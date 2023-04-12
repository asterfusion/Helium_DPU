/*
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is provided "as is" without any warranty of any kind, and is
 * distributed under the applicable Marvell proprietary limited use license
 * agreement.
 */

#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#include <rte_cfgfile.h>
#include <rte_cycles.h>
#include <rte_ethdev_vdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_prefetch.h>
#include <rte_string_fns.h>

#include "rte_eth_lport_private.h"

static
const char *pmd_lport_valid_args[] = {
	LPORT_CFG_KVARG,
	LPORT_IFACE_KVARG,
	NULL
};

/* global argument vars */
static int tx_ring_size = 256;
static int socket_id = SOCKET_ID_ANY;

static int
lport_probe(struct rte_vdev_device *dev);
static int
lport_remove(struct rte_vdev_device *dev);

static
struct rte_vdev_driver pmd_lport_drv = {
	.probe	= lport_probe,
	.remove = lport_remove,
};

RTE_PMD_REGISTER_VDEV(net_lport, pmd_lport_drv);
RTE_PMD_REGISTER_ALIAS(net_lport, eth_lport);

RTE_PMD_REGISTER_PARAM_STRING(net_lport, "cfg=fname iface=<ifc>");

static
struct {
	struct ldomain ldomains[LPORT_MAX_DOMAIN];
	struct lport     lports[LPORT_MAX_PORT];
	struct ldata_per_core lcore_data[RTE_MAX_LCORE];

	struct rte_eth_dev_owner owner;
	uint8_t initialized;
	uint8_t config_read;	/* configuration file has been read */
	uint8_t using_shq;	/* at least one shared queue is used */
} lport_data;

#define BURST_SIZE	32	/* TODO - make this configurable */
#define DSA_FWD_TAG	0xC0
#define DSA_FCPU_TAG	0x40

#define MACS_LEN	(2 * RTE_ETHER_ADDR_LEN)

/* fwd decl of tagging functions */
static void
dispatch_by_dsa_port(const struct ldomain *ld,
		     struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
static int
retag_with_dsa_port(const struct lport *lport,
		    struct rte_mbuf **tx_pkts, int nb_pkts);
static inline struct lport*
match_by_dsa_port(const struct ldomain *ld, uint8_t *data);

static void
dispatch_by_dsa_vid(const struct ldomain *ld,
		    struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
static int
retag_with_dsa_vid(const struct lport *lport,
		   struct rte_mbuf **tx_pkts, int nb_pkts);
static inline struct lport*
match_by_dsa_vid(const struct ldomain *ld, uint8_t *data);

static void
dispatch_by_vlan(const struct ldomain *ld,
		 struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
static int
retag_with_vlan(const struct lport *lport,
		struct rte_mbuf **tx_pkts, int nb_pkts);
static inline struct lport*
match_by_vlan(const struct ldomain *ld, uint8_t *data);

static
struct lport_tag_set {
	const char *name;
	lport_tag_type_t tag_type;
	lport_dispatch_cb_t dispatch_cb;
	lport_retag_cb_t retag_cb;
	lport_match_cb_t match_cb;
} lport_valid_tags[] = {
	{ "dsa",     DSA_PORT_TAG, dispatch_by_dsa_port,
				   retag_with_dsa_port,
				   match_by_dsa_port},
	{ "dsa-vid", DSA_VID_TAG,  dispatch_by_dsa_vid,
				   retag_with_dsa_vid,
				   match_by_dsa_vid },
	{ "vlan",    VLAN_TAG,     dispatch_by_vlan,
				   retag_with_vlan,
				   match_by_vlan },
};

static inline void lport_drain_tx_ring(uint16_t tx_qid, struct ldomain *ld,
				       struct lport_lcstats *stats);

static
const struct lport_tag_set *match_tag_by_name(const char *name)
{
	size_t nlen = strlen(name);
	uint32_t i;

	for (i = 0; i < RTE_DIM(lport_valid_tags); ++i)
		if (strncmp(lport_valid_tags[i].name, name, nlen) == 0)
			return &lport_valid_tags[i];
	return NULL;
}

static
const struct lport_tag_set *match_tag_by_type(lport_tag_type_t type)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(lport_valid_tags); ++i)
		if (lport_valid_tags[i].tag_type == type)
			return &lport_valid_tags[i];
	return NULL;
}

static inline
struct lport *match_by_dsa_port(const struct ldomain *ld, uint8_t *data)
{
	struct lport_mapping *map;
	uint16_t dsa_port_id;

	dsa_port_id = (data[13] >> 3);
	map = ld->tag_map;
	do {
		if (map->tag.value == dsa_port_id)
			break;
	} while ((++map)->port);

	return map->port;
}

static inline
bool drop_packet(const struct lport *lp, struct rte_mbuf *pkt, uint8_t *data)
{
	if (!lp || !lp->active)
		return true;

	if (!lp->promisc_mode) {
		struct rte_ether_addr *ea = (struct rte_ether_addr *)data;

		/* drop unicast traffic if not directed to us */
		if (rte_is_unicast_ether_addr(ea) &&
		    !rte_is_same_ether_addr(&lp->mac, ea))
			return true;
		/* drop multicast traffic if not turned on */
		if (!lp->allmulticast_on && rte_is_multicast_ether_addr(ea))
			return true;
	}
	if (unlikely(lp->mtu_configured && (rte_pktmbuf_pkt_len(pkt) >
		      (uint32_t)(lp->mtu + RTE_ETHER_HDR_LEN))))
		return true;
	return false;
}

static
void dispatch_by_dsa_port(const struct ldomain *ld,
			  struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint8_t *data;
	struct lport *lp;
	struct ldata_per_core *lpcd = &lport_data.lcore_data[rte_lcore_id()];
	struct rte_mbuf *pkt;
	uint32_t i;

	for (i = 0; i < nb_pkts; ++i) {
		pkt = rx_pkts[i];
		data = rte_pktmbuf_mtod(pkt, uint8_t*);
		/* Check byte after MACs.
		 * TODO - for now we handle only Forward tag - should we handle
		 * also To_CPU?
		 */
		if (unlikely((data[12] & DSA_FWD_TAG) != DSA_FWD_TAG)) {
			/* TODO - do not count these at the moment, just drop.
			 * Introduce proper counter for it later (either 'xstat'
			 * or 'lport' specific with its own API).
			 */
			goto drop_packet;
		}
		/* This +2 prefetch is experimental - it seems to give
		 *  better performance than +1
		 */
		if (likely(i + 2 < nb_pkts))
			rte_prefetch0(rte_pktmbuf_mtod(rx_pkts[i + 2], void*));

		lp = match_by_dsa_port(ld, data);
		if (unlikely(drop_packet(lp, pkt, data)))
			/* TODO - same as above, for now just drop it */
			goto drop_packet;

		/* bump the "local" stats and every # packets update globals */
		struct lport_lcstats *stats = &lpcd->stats[lp->id];

		stats->rx_bytes += rte_pktmbuf_pkt_len(pkt);
		++stats->rx_pkts;

		if (data[12] & 0x20) {
			/* original packet had VLAN tag so just replace DSA tag
			 * with VLAN one
			 */
			data[12] = 0x81;
			if (data[13] & 1)
				data[14] |= 0x10;
			else
				data[14] &= ~0x10;
			data[13] = 0x00;
		} else {
			memmove(data + 4, data, 12);
			rte_pktmbuf_adj(pkt, 4);
			pkt->l2_len -= 4;
		}
		if (unlikely(rte_ring_enqueue(lp->rx_ring, pkt) != 0)) {
			++stats->rx_dropped;
			goto drop_packet;
		}
		continue;
drop_packet:
		rte_pktmbuf_free(pkt);
	}
}

static inline
struct lport *match_by_dsa_vid(const struct ldomain *ld, uint8_t *data)
{
	struct lport_mapping *map;
	uint16_t vlan_id;

	vlan_id = data[14] & 0xF;
	vlan_id = vlan_id << 8 | data[15];
	map = ld->tag_map;
	do {
		if (map->tag.value == vlan_id)
			break;
	} while ((++map)->port);

	return map->port;
}

static
void dispatch_by_dsa_vid(const struct ldomain *ld,
			 struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint8_t *data;
	struct lport *lp;
	struct ldata_per_core *lpcd = &lport_data.lcore_data[rte_lcore_id()];
	struct rte_mbuf *pkt;
	uint32_t i;

	for (i = 0; i < nb_pkts; ++i) {
		pkt = rx_pkts[i];
		data = rte_pktmbuf_mtod(pkt, uint8_t*);
		/* Check byte after MACs.  It should be Forward tag. */
		if (unlikely((data[12] & DSA_FWD_TAG) != DSA_FWD_TAG)) {
			/* TODO - do not count these at the moment, just drop.
			 * Introduce proper counter for it later (either 'xstat'
			 * or 'lport' specific with its own API).
			 */
			goto drop_packet;
		}
		/* This +2 prefetch is experimental - it seems to give
		 * better performance than +1
		 */
		if (likely(i + 2 < nb_pkts))
			rte_prefetch0(rte_pktmbuf_mtod(rx_pkts[i + 2], void*));

		lp = match_by_dsa_vid(ld, data);
		if (unlikely(drop_packet(lp, pkt, data)))
			/* TODO - same as above, for now just drop it */
			goto drop_packet;

		/* bump the "local" stats and every # packets update globals */
		struct lport_lcstats *stats = &lpcd->stats[lp->id];

		stats->rx_bytes += rte_pktmbuf_pkt_len(pkt);
		++stats->rx_pkts;

		/* remove DSA tag */
		memmove(data + 4, data, 12);
		rte_pktmbuf_adj(pkt, 4);
		pkt->l2_len -= 4;

		if (unlikely(rte_ring_enqueue(lp->rx_ring, pkt) != 0)) {
			++stats->rx_dropped;
			goto drop_packet;
		}
		continue;
drop_packet:
		rte_pktmbuf_free(pkt);
	}
}

static inline
struct lport *match_by_vlan(const struct ldomain *ld, uint8_t *data)
{
	struct lport_mapping *map;
	uint16_t vlan_id;

	vlan_id = data[14] & 0xF;
	vlan_id = vlan_id << 8 | data[15];
	map = ld->tag_map;
	do {
		if (map->tag.value == vlan_id)
			break;
	} while ((++map)->port);

	return map->port;
}

static
void dispatch_by_vlan(const struct ldomain *ld,
		      struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	uint8_t *data;
	struct lport *lp;
	struct ldata_per_core *lpcd = &lport_data.lcore_data[rte_lcore_id()];
	struct rte_mbuf *pkt;
	uint32_t i;

	for (i = 0; i < nb_pkts; ++i) {
		pkt = rx_pkts[i];
		data = rte_pktmbuf_mtod(pkt, uint8_t*);
		/* packet should be of VLAN type */
		if (unlikely(!(pkt->packet_type &
			       RTE_PTYPE_L2_ETHER_VLAN))) {
			/* TODO - do not count these at the moment, just drop.
			 * Introduce proper counter for it later (either 'xstat'
			 * or 'lport' specific with its own API).
			 */
			goto drop_packet;
		}
		/* This +2 prefetch is experimental - it seems to give
		 * better performance than +1
		 */
		if (likely(i + 2 < nb_pkts))
			rte_prefetch0(rte_pktmbuf_mtod(rx_pkts[i + 2], void*));

		lp = match_by_vlan(ld, data);
		if (unlikely(drop_packet(lp, pkt, data)))
			/* TODO - same as above, for now just drop it */
			goto drop_packet;

		/* bump the "local" stats and every # packets update globals */
		struct lport_lcstats *stats = &lpcd->stats[lp->id];

		stats->rx_bytes += rte_pktmbuf_pkt_len(pkt);
		++stats->rx_pkts;

		/* remove VLAN tag */
		memmove(data + 4, data, 12);
		rte_pktmbuf_adj(pkt, 4);
		pkt->packet_type &= ~RTE_PTYPE_L2_ETHER_VLAN;
		pkt->l2_len -= 4;

		if (unlikely(rte_ring_enqueue(lp->rx_ring, pkt) != 0)) {
			++stats->rx_dropped;
			goto drop_packet;
		}
		continue;
drop_packet:
		rte_pktmbuf_free(pkt);
	}
}

static
uint16_t lport_rx_burst(void *l_port,
			struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct lport *lp = l_port;
	struct ldomain *ld = lp->ldomain;
	uint32_t d;

	nb_pkts = rte_ring_dequeue_burst(lp->rx_ring, (void **)rx_pkts, nb_pkts,
					 NULL/* not interested in available */);
	if (rte_spinlock_trylock(&ld->rx_lock)) {
		struct rte_mbuf *bufs[BURST_SIZE];
		uint16_t new_pkts;

		new_pkts = rte_eth_rx_burst(ld->eth_id, 0, bufs, BURST_SIZE);
		rte_spinlock_unlock(&ld->rx_lock);
		if (new_pkts != 0)
			ld->dispatch_cb(ld, bufs, new_pkts);
	}

	/* This check is for the (unlikely) case when shared queue is used and
	 * some core has put in there packets waiting to be transmitted on the
	 * next tx_burst call but for some reason it is not called any more.
	 * Unfortunately we have to check not only this p-port but all of them,
	 * since it might happen that two p-ports are used in uni-directional
	 * way (one always for RX and one always for TX) so we can't rely on
	 * having some core calling rx_burst for the port meant for TX only.
	 */
	if (lport_data.using_shq) {
		uint64_t curr = rte_rdtsc();
		struct ldata_per_core *lpcd =
				&lport_data.lcore_data[rte_lcore_id()];

		/* do not check more then once per second */
		if (likely(curr < lpcd->next_tsc))
			goto exit;
		lpcd->next_tsc = curr + rte_get_tsc_hz();
		for (d = 0; d < RTE_DIM(lport_data.ldomains); ++d) {
			struct ldomain *ld = &lport_data.ldomains[d];

			if (!ld->tx_ring || rte_ring_empty(ld->tx_ring))
				continue;
			if (rte_spinlock_trylock(&ld->tx_lock)) {
				/* the shared queue is the last one */
				lport_drain_tx_ring(ld->max_tx_queues - 1, ld,
						    lpcd->stats);
				rte_spinlock_unlock(&ld->tx_lock);
			}
		}
	}

exit:
	return nb_pkts;
}


/* During retagging tag is inserted in front of the packet so we depend on the
 * headroom being large enough to accommodate for it - current max tag size is 4
 */
static_assert(RTE_PKTMBUF_HEADROOM >= 4, "Not enough headroom configured");

static inline
bool insert_bytes(uint16_t nb_bytes, uint16_t offset, struct rte_mbuf *pkt)
{
	char *data;

	data = rte_pktmbuf_prepend(pkt, nb_bytes);
	if (unlikely(!data)) {
		RTE_LPORT_LOG(WARNING, "Not enough headroom in packet\n");
		return false;
	}
	memmove(data, data + nb_bytes, offset);

	return true;
}

static
int retag_with_dsa_port(const struct lport *lp,
			struct rte_mbuf **tx_pkts, int nb_pkts)
{
	struct rte_mbuf *pkt;
	uint8_t *tag;
	int i, f = -1; /* index of last valid packet */

	/* fill tag with correct port id and check MTU if configured */
	for (i = 0; i < nb_pkts; ++i) {
		pkt = tx_pkts[i];
		tag = rte_pktmbuf_mtod_offset(pkt, uint8_t*, MACS_LEN);
		if (tag[0] == 0x81 && tag[1] == 0x00) {
			/* replace VLAN tag with DSA tag */
			tag[0] = DSA_FCPU_TAG | 0x20;
			tag[1] = (uint8_t)(lp->tag.value << 3);
			if (tag[2] & 0x10) {
				tag[1] |= 1;
				tag[2] &= ~0x10;
			}
		} else {
			/* insert DSA tag */
			if (unlikely(!insert_bytes(4, MACS_LEN, pkt)))
				continue;
			pkt->l2_len += 4;
			tag = rte_pktmbuf_mtod_offset(pkt, uint8_t*, MACS_LEN);
			tag[0] = DSA_FCPU_TAG;
			tag[1] = (uint8_t)(lp->tag.value << 3);
			/* zero VLAN id - maybe this is not needed? */
			tag[2] = 0;
			tag[3] = 0;
		}

		if (likely(++f == i)) /* all packets so far are good */
			continue;
		tx_pkts[i] = tx_pkts[f];
		tx_pkts[f] = pkt;
	}

	return f + 1;
}

static
int retag_with_dsa_vid(const struct lport *lp,
		       struct rte_mbuf **tx_pkts, int nb_pkts)
{
	struct rte_mbuf *pkt;
	uint8_t *tag;
	int i, f = -1; /* index of last valid packet */

	/* fill tag with correct port id and check MTU if configured */
	for (i = 0; i < nb_pkts; ++i) {
		pkt = tx_pkts[i];
		/* insert DSA tag */
		if (unlikely(!insert_bytes(4, MACS_LEN, pkt)))
			continue;
		pkt->l2_len += 4;
		tag = rte_pktmbuf_mtod_offset(pkt, uint8_t*, MACS_LEN);
		tag[0] = DSA_FWD_TAG;
		tag[1] = 0;
		tag[2] = (uint8_t)(lp->tag.value >> 8 & 0xF);
		tag[3] = (uint8_t)(lp->tag.value      & 0xFF);

		if (likely(++f == i)) /* all packets so far are good */
			continue;
		tx_pkts[i] = tx_pkts[f];
		tx_pkts[f] = pkt;
	}

	return f + 1;
}

static
int retag_with_vlan(const struct lport *lp,
		    struct rte_mbuf **tx_pkts, int nb_pkts)
{
	struct rte_mbuf *pkt;
	uint8_t *tag;
	int i, f = -1; /* index of last valid packet */

	/* fill tag with correct port id and check MTU if configured */
	for (i = 0; i < nb_pkts; ++i) {
		pkt = tx_pkts[i];
		/* insert VLAN tag */
		if (unlikely(!insert_bytes(4, MACS_LEN, pkt)))
			continue;
		pkt->packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		pkt->l2_len += 4;
		tag = rte_pktmbuf_mtod_offset(pkt, uint8_t*, MACS_LEN);
		tag[0] = 0x81;
		tag[1] = 0x00;
		tag[2] = (uint8_t)(lp->tag.value >> 8 & 0xF);
		tag[3] = (uint8_t)(lp->tag.value      & 0xFF);

		if (likely(++f == i)) /* all packets so far are good */
			continue;
		tx_pkts[i] = tx_pkts[f];
		tx_pkts[f] = pkt;
	}

	return f + 1;
}

static inline void
lport_drain_tx_ring(uint16_t tx_qid, struct ldomain *ld,
		    struct lport_lcstats *stats)
{
	struct rte_mbuf *bufs[BURST_SIZE];
	uint16_t avail_pkts;
	uint16_t tx;

	while (true) {
		avail_pkts = rte_ring_dequeue_burst(ld->tx_ring, (void **)bufs,
						    BURST_SIZE, NULL);
		if (!avail_pkts)
			break;
		tx = rte_eth_tx_burst(ld->eth_id, tx_qid, bufs, avail_pkts);
		/* In order to count drops properly per port we need to parse
		 * the tag again.
		 */
		if (unlikely(tx < avail_pkts)) {
			struct lport *lp;
			struct lport_lcstats *s;

			for (; tx < avail_pkts; ++tx) {
				lp = ld->match_cb(ld,
						  rte_pktmbuf_mtod(bufs[tx],
								   uint8_t*));
				s = stats + lp->id;

				--s->tx_pkts;
				s->tx_bytes -= rte_pktmbuf_pkt_len(bufs[tx]);
				++s->tx_dropped;
				rte_pktmbuf_free(bufs[tx]);
			}
		}
	}
}

static
uint16_t lport_tx_burst(void *l_port,
			struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct lport *lp = l_port;
	uint16_t nb_tx;
	uint32_t i;

	if (unlikely(!lp->active)) {
		RTE_LPORT_LOG(WARNING, "Port %s not started\n", lp->name);
		return 0;
	}

	nb_tx = lp->retag_cb(lp, tx_pkts, nb_pkts);

	struct ldomain *ld = lp->ldomain;
	struct ldata_per_core *lpcd = &lport_data.lcore_data[rte_lcore_id()];
	uint16_t tx_qid = lpcd->q_ids[ld->id].tx_id;

	if (tx_qid & 1) {
		/* This lcore has to use shared queue so lets try to take a
		 * lock.  If we fail then some other lcore is "draining" the TX
		 * ring so just append to it and quit, if we succeed then
		 * "drain" the ring and then transmit our packets directly
		 * without going through the ring.
		 */
		if (rte_spinlock_trylock(&ld->tx_lock)) {
			tx_qid >>= 1;
			lport_drain_tx_ring(tx_qid, ld, lpcd->stats);
			nb_tx = rte_eth_tx_burst(ld->eth_id, tx_qid,
						 tx_pkts, nb_tx);
			rte_spinlock_unlock(&ld->tx_lock);
		} else {
			nb_tx = rte_ring_enqueue_burst(ld->tx_ring,
						       (void **)tx_pkts,
						       nb_tx,
						       NULL/* space left */);
		}
	} else {
		nb_tx = rte_eth_tx_burst(ld->eth_id, tx_qid >> 1,
					 tx_pkts, nb_tx);
	}

	/* bump the "local" stats */
	struct lport_lcstats *stats = &lpcd->stats[lp->id];

	for (i = 0; i < nb_tx; ++i) {
		if (likely(i + 2 < nb_tx))
			rte_prefetch0(rte_pktmbuf_mtod(tx_pkts[i + 2], void*));
		stats->tx_bytes += rte_pktmbuf_pkt_len(tx_pkts[i]);
		++stats->tx_pkts;
	}

	if (unlikely(nb_tx < nb_pkts)) {
		/* TODO:
		 * In case the packets were taked from lport_drain_tx_ring()
		 * we need to check to which lports the not sent packets are
		 * belong and update stats accordingly.
		 */
		stats->tx_dropped += nb_pkts - nb_tx;
	}

	return nb_tx;
}

static int
lport_ethdev_info(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	struct lport *lp = dev->data->dev_private;
	struct ldomain *ld = lp->ldomain;

	rte_eth_dev_info_get(ld->eth_id, dev_info);

	dev_info->max_mac_addrs = 1;
	dev_info->max_rx_queues = 1;
	dev_info->max_tx_queues = 1;
	/* TODO - any other info needs to be overwritten? */
	return 0;
}

static int
lport_ethdev_start(struct rte_eth_dev *eth_dev)
{
	/* physical port should not be started explicitly, but indirectly via
	 * l-ports so here we check for that.
	 */
	if (eth_dev->device->driver->name != pmd_lport_drv.driver.name) {
		RTE_LPORT_LOG(ERR, "LPORT can only start l- and/or p-ports\n");
		return -EINVAL;
	}

	struct lport *lp = eth_dev->data->dev_private;
	struct ldomain *ld = lp->ldomain;
	int ret;

	/* mark port as active - even if the p-port might not be active yet */
	lp->active = true;
	++ld->active_lports;

	if (!ld->active) {
		ret = rte_eth_dev_start(ld->eth_id);
		if (ret)
			return ret;
		ld->active = true;
	}

	/* the status of link is copied from the p-port */
	rte_eth_link_get(ld->eth_id, &eth_dev->data->dev_link);

	return 0;
}

static void
lport_ethdev_stop(struct rte_eth_dev *eth_dev)
{
	struct lport *lp = eth_dev->data->dev_private;
	struct ldomain *ld = lp->ldomain;

	if (--ld->active_lports == 0) {
		RTE_LOG(INFO, EAL, "Stopping p-port %d\n",
			(int)(lp->ldomain - lport_data.ldomains));
		rte_eth_dev_stop(ld->eth_id);
		ld->active = false;
	}

	eth_dev->data->dev_link.link_status = ETH_LINK_DOWN;
	lp->active = false;
}

static int
lport_ethdev_configure(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;
	struct ldomain *ld = lp->ldomain;
	int ret;

	if (ld->configured)
		return 0;

	/* Configure 1 RX queue and enough TX queues to service configured
	 * lcores (but no more than it is available).
	 */
	unsigned int nb_tx_q = rte_lcore_count();

	if (nb_tx_q > ld->max_tx_queues) {
		/* There is not enough TX queues to have dedicated one for each
		 * lcore.  So configure the last queue as a shared one which
		 * will be used indirectly via TX ring and draining of this ring
		 * synchronized via ldomain->tx_lock.  Let's fist create TX
		 * ring ...
		 */
		char r_name[RTE_MEMZONE_NAMESIZE];
		int16_t shared_q;
		uint32_t i;

		snprintf(r_name, sizeof(r_name), "lport_tx_ring%d", ld->id);
		ld->tx_ring = rte_ring_create(r_name, tx_ring_size,
					      ld->socket_id, RING_F_SC_DEQ);
		if (!ld->tx_ring) {
			RTE_LPORT_LOG(ERR,
				      "Failed to create TX ring (p-port %d)\n",
				      ld->id);
			return -ENOMEM;
		}
		lport_data.using_shq = true;
		/* ... and now fix the queue id for those lcores that should
		 * share the same TX queue (lowest bit marks queue as shared)
		 */
		shared_q = ld->max_tx_queues - 1;
		for (i = 0; i < RTE_MAX_LCORE; ++i) {
			if (rte_eal_lcore_role(i) != ROLE_RTE)
				continue;
			if (rte_lcore_index(i) >= shared_q)
				lport_data.lcore_data[i].q_ids[ld->id].tx_id =
						shared_q << 1 | 1;
		}

		nb_tx_q = ld->max_tx_queues;
	} else {
		ld->max_tx_queues = nb_tx_q;
	}
	ret = rte_eth_dev_configure(ld->eth_id, 1, nb_tx_q,
				    &dev->data->dev_conf);
	if (ret == 0) {
		ld->configured = true;
	} else {
		rte_ring_free(ld->tx_ring);
		ld->tx_ring = NULL;
	}
	return ret;
}

static int
lport_ethdev_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
			    uint16_t nb_rx_desc,
			    unsigned int socket_id __rte_unused,
			    const struct rte_eth_rxconf *rx_conf,
			    struct rte_mempool *mb_pool)
{
	if (rx_queue_id > 0)
		return -EINVAL;

	int err;
	struct lport *lp = dev->data->dev_private;

	if (lp->rxq_configured) /* nothing to reconfigure */
		return 0;

	struct ldomain *ld = lp->ldomain;
	char r_name[RTE_MEMZONE_NAMESIZE];

	snprintf(r_name, sizeof(r_name), "lport_rx_ring%d",
		 (unsigned int)lp->tag.value);

	if (!rte_is_power_of_2(nb_rx_desc))
		nb_rx_desc = rte_align32pow2(nb_rx_desc);

	lp->rx_ring = rte_ring_create(r_name, nb_rx_desc, ld->socket_id,
				      RING_F_SC_DEQ);
	if (!lp->rx_ring) {
		RTE_LPORT_LOG(ERR, "Failed to allocate RX ring\n");
		return -ENOMEM;
	}

	if (ld->rxq_configured == 0) { /* this is the 1st l-port RX queue cfg */
		/* FIXME - p-port RX queue params should come from config file!
		 * and not from arguments of first l-port
		 */
		err = rte_eth_rx_queue_setup(ld->eth_id, rx_queue_id,
					     nb_rx_desc, ld->socket_id,
					     rx_conf, mb_pool);
		if (err) {
			RTE_LPORT_LOG(ERR,
				"Failed to configure RX queue on p-port\n");
			goto err_no_queue;
		}
	}
	lp->rxq_configured = true;
	++ld->rxq_configured;

	dev->data->rx_queues[rx_queue_id] = lp;

	return 0;

err_no_queue:
	rte_ring_free(lp->rx_ring);
	lp->rx_ring = NULL;

	return err;
}

static void
lport_ethdev_rx_queue_release(void *l_port)
{
	struct lport *lp = l_port;

	if (!lp)
		return;

	/* Nothing to release on eth_id - there is no public API to release
	 * the queues, release callback is used internally in DPDK.  So here
	 * we just mark the RX queue is not configured so that on next call
	 * to queue setup we will call rte_eth_rx_queue_setup() on eth_id and
	 * it will reconfigure the queue (free and allocate new one)
	 */
	lp->rxq_configured = false;
	--lp->ldomain->rxq_configured;

	rte_ring_free(lp->rx_ring);
	lp->rx_ring = NULL;
}

static int
lport_ethdev_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
			    uint16_t nb_tx_desc,
			    unsigned int socket_id __rte_unused,
			    const struct rte_eth_txconf *tx_conf)
{
	struct lport *lp = dev->data->dev_private;
	uint16_t q;
	int ret;

	if (lp->txq_configured) /* nothing to reconfigure */
		return 0;

	struct ldomain *ld = lp->ldomain;

	if (ld->txq_configured == 0) { /* this is the 1st l-port TX queue cfg */
		for (q = 0; q < ld->max_tx_queues; ++q) {
			/* FIXME - p-port TX queue params should come from
			 * config file and not from arguments of first l-port
			 */
			ret =  rte_eth_tx_queue_setup(ld->eth_id, q, nb_tx_desc,
						      ld->socket_id, tx_conf);
			if (ret)
				return ret;
		}
	}
	lp->txq_configured = true;
	++ld->txq_configured;

	dev->data->tx_queues[tx_queue_id] = lp;

	return 0;
}

static void
lport_ethdev_tx_queue_release(void *l_port)
{
	struct lport *lp = l_port;
	struct ldomain *ld;

	if (!lp)
		return;

	ld = lp->ldomain;

	/* See comment in lport_ethdev_rx_queue_release() */
	lp->txq_configured = false;
	--ld->txq_configured;
}

static void
lport_ethdev_close(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;
	uint32_t i;

	if (lp->active)
		lport_ethdev_stop(dev);

	RTE_LOG(INFO, EAL, "Closing l-port device %s\n", lp->name);
	for (i = 0; i < dev->data->nb_rx_queues; ++i)
		lport_ethdev_rx_queue_release(dev->data->rx_queues[i]);
	for (i = 0; i < dev->data->nb_tx_queues; ++i)
		lport_ethdev_tx_queue_release(dev->data->tx_queues[i]);
}

static int
lport_ethdev_link_update(struct rte_eth_dev *ethdev, int wait_to_complete)
{
	struct lport *lp = ethdev->data->dev_private;

	if (wait_to_complete)
		rte_eth_link_get(lp->ldomain->eth_id,
				 &lp->eth_dev->data->dev_link);
	else
		rte_eth_link_get_nowait(lp->ldomain->eth_id,
					&lp->eth_dev->data->dev_link);
	return 0;
}

static int
lport_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct lport *lp = dev->data->dev_private;
	uint32_t l;

	for (l = 0; l < RTE_DIM(lport_data.lcore_data); ++l) {
		if (!rte_lcore_is_enabled(l))
			continue;

		struct lport_lcstats *curr =
				&lport_data.lcore_data[l].stats[lp->id];
		struct lport_lcstats *base =
				&lport_data.lcore_data[l].bstats[lp->id];

		stats->ipackets += curr->rx_pkts - base->rx_bytes;
		stats->ibytes   += curr->rx_bytes - base->rx_bytes;
		stats->imissed  += curr->rx_dropped - base->rx_dropped;

		stats->opackets += curr->tx_pkts - base->tx_pkts;
		stats->obytes   += curr->tx_bytes - base->tx_bytes;
		stats->oerrors  += curr->tx_dropped - base->tx_dropped;
	}

	return 0;
}

static int
lport_stats_reset(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;
	uint32_t l;

	for (l = 0; l < RTE_DIM(lport_data.lcore_data); ++l) {
		if (!rte_lcore_is_enabled(l))
			continue;

		lport_data.lcore_data[l].bstats[lp->id] =
				lport_data.lcore_data[l].stats[lp->id];
	}

	return 0;
}

static
int lport_mac_addr_set(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr)
{
	struct lport *lp = dev->data->dev_private;

	if (!rte_is_valid_assigned_ether_addr(mac_addr))
		return -EINVAL;

	rte_ether_addr_copy(mac_addr, &lp->mac);
	return 0;
}

static
int lport_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct lport *lp = dev->data->dev_private;
	uint16_t port_id = lp->ldomain->eth_id;
	uint16_t p_mtu;
	int ret;

	if (mtu != 0) { /* setting MTU to 0 clears MTU filtering */
		ret = rte_eth_dev_get_mtu(port_id, &p_mtu);
		if (ret)
			return ret;

		if (p_mtu < mtu) {
			ret = rte_eth_dev_set_mtu(port_id, mtu);
			if (ret)
				return ret;
		}
	}

	lp->mtu = mtu;
	lp->mtu_configured = mtu;
	return 0;
}

static int lport_promisc_enable(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;

	lp->promisc_mode = true;
	return 0;
}

static int lport_promisc_disable(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;

	lp->promisc_mode = false;
	return 0;
}

static int lport_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;

	lp->allmulticast_on = true;
	return 0;
}

static int lport_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct lport *lp = dev->data->dev_private;

	lp->allmulticast_on = false;
	return 0;
}

static
const struct eth_dev_ops lport_dev_ops = {
	.dev_start	   = lport_ethdev_start,
	.dev_stop	   = lport_ethdev_stop,
	.dev_close	   = lport_ethdev_close,
	.dev_configure	   = lport_ethdev_configure,
	.dev_infos_get	   = lport_ethdev_info,
	.rx_queue_setup    = lport_ethdev_rx_queue_setup,
	.tx_queue_setup    = lport_ethdev_tx_queue_setup,
	.rx_queue_release  = lport_ethdev_rx_queue_release,
	.tx_queue_release  = lport_ethdev_tx_queue_release,
	.link_update	   = lport_ethdev_link_update,
	.stats_get         = lport_stats_get,
	.stats_reset       = lport_stats_reset,
	.mac_addr_set      = lport_mac_addr_set,
	.mtu_set           = lport_mtu_set,
	.promiscuous_enable   = lport_promisc_enable,
	.promiscuous_disable  = lport_promisc_disable,
	.allmulticast_enable  = lport_allmulticast_enable,
	.allmulticast_disable = lport_allmulticast_disable,
};

static struct rte_eth_dev*
lport_ethdev_alloc(struct rte_vdev_device *dev, struct lport *port, int socket)
{
	struct rte_eth_dev *eth_dev;

	eth_dev = rte_eth_dev_allocate(port->name);
	if (!eth_dev) {
		RTE_LPORT_LOG(ERR, "Unable to allocate rte_eth_dev\n");
		goto err;
	}

	eth_dev->device = &dev->device;
	eth_dev->intr_handle = NULL;

	eth_dev->data->kdrv = RTE_KDRV_NONE;
	eth_dev->data->numa_node = socket;

	eth_dev->rx_pkt_burst = lport_rx_burst;
	eth_dev->tx_pkt_burst = lport_tx_burst;
	eth_dev->dev_ops = &lport_dev_ops;

	eth_dev->data->mac_addrs = rte_zmalloc_socket(rte_vdev_device_name(dev),
						      RTE_ETHER_ADDR_LEN, 0,
						      socket);
	if (!eth_dev->data->mac_addrs) {
		RTE_LPORT_LOG(ERR, "Unable to allocate mac_addrs\n");
		goto err;
	}
	/* copy MAC from p-port to both generic eth data and our local struct */
	rte_eth_macaddr_get(port->ldomain->eth_id, eth_dev->data->mac_addrs);
	rte_ether_addr_copy(eth_dev->data->mac_addrs, &port->mac);
	eth_dev->data->dev_private = port;

	rte_eth_dev_probing_finish(eth_dev);

	return eth_dev;

err:
	if (eth_dev)
		rte_eth_dev_release_port(eth_dev);
	return NULL;
}

static int
lport_parse_int_arg(const char *string, int *ptr)
{
	char *end;
	long value;

	if (!string)
		return -1;

	value = strtol(string, &end, 0);

	if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN)) ||
	    (errno != 0 && value == 0))
		return -errno;

	*ptr = (int)value;

	return 0;
}

static
struct lport_mapping *tag_map_alloc(int len)
{
	/* (len+1) since the last element is used as "sentinel" */
	struct lport_mapping *map =
		rte_malloc(NULL, (len + 1) * sizeof(struct lport_mapping), 0);

	if (!map) {
		RTE_LPORT_LOG(ERR, "Failed to allocate tag mapping");
		return NULL;
	}

	return map;
}

static
int parse_tag(lport_tag_type_t type, const char *str, lport_tag_t *tag)
{
	uintptr_t value;

	switch (type) {
	case DSA_PORT_TAG:
	case DSA_VID_TAG:
	case VLAN_TAG:
		errno = 0;
		value = strtoul(str, NULL, 10);
		if (errno)
			return -EINVAL;
		tag->value = value;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct rte_cfgfile_entry*
cfg_find_entry(const struct rte_cfgfile_entry *entries,
	       int len, const char *name)
{
	size_t nlen = strlen(name);
	int i;

	for (i = 0; i < len; ++i)
		if (strncmp(entries[i].name, name, nlen) == 0)
			return entries + i;
	return NULL;
}

static
int cfg_count_entries(const struct rte_cfgfile_entry *entries,
		      int len, const char *name)
{
	const struct rte_cfgfile_entry *entry = entries;
	int num = 0;

	entries += len;

	while ((entry = cfg_find_entry(entry, entries - entry, name))) {
		++entry;
		++num;
	}
	return num;
}

static
int tag_cmp(const void *a, const void *b)
{
	const struct lport_mapping *left  = a;
	const struct lport_mapping *right = b;

	return left->tag.value - right->tag.value;
}

static
void parse_lports(struct ldomain *ld,
		  const struct rte_cfgfile_entry *entry,
		  const struct rte_cfgfile_entry *end_entry, int *lp_idx)
{
	char buf[CFG_NAME_LEN];
	const char *vname = NULL;
	struct lport_mapping *map = ld->tag_map;
	lport_tag_t tag;
	struct lport *lp;

	while ((entry = cfg_find_entry(entry, end_entry - entry, "lport"))) {
		if (sscanf(entry->name, "lport:%s", buf) == 1) {
			if (strlen(buf) >= LPORT_PNAME_MAX_LEN)
				RTE_LPORT_LOG(WARNING,
					      "Port name too long: %s\n",
					      vname);
		} else {
			sprintf(buf, "lport%d", *lp_idx);
		}
		vname = buf;
		if (parse_tag(ld->tag_type, entry->value, &tag) != 0) {
			RTE_LPORT_LOG(WARNING, "Could not parse tag: %s\n",
				      entry->value);
			continue;
		}
		/* initialize the l-port */
		lp = lport_data.lports + *lp_idx;
		lp->ldomain = ld;
		/* rx_ring is initialized later during port config */
		lp->tag = tag;
		lp->retag_cb = match_tag_by_type(ld->tag_type)->retag_cb;
                strlcpy(lp->name, vname, LPORT_PNAME_MAX_LEN);
		/* update the tag mapping */
		map->tag  = tag;
		map->port = lp;
		RTE_LPORT_LOG(DEBUG, "l-port %s tag=%lu\n", vname, tag.value);
		++map;

		++entry;
		++(*lp_idx);
	}
	/* mark last tag as "sentinel" */
	map->tag.value = -1;
	map->port = NULL;
	/* now sort the tag map */
	qsort(ld->tag_map, map - ld->tag_map, sizeof(*ld->tag_map),
	      tag_cmp);
}

/* exemplary config file
 *  [l-domain]
 *  classify = dsa
 *  p-port = net_mvneta,iface=eth0
 *  # l-ports  rule
 *  lport:wan  = 1
 *  lport:lan0 = 2
 *  lport:lan1 = 3
 */

static int
lport_parse_config(struct rte_cfgfile *cfg)
{
	const char *value;
	int num_sect;
	int has_global = 0;
	int curr_domain = 0;

	/* First handle global arguments ("socket" and "tx_ring_size") */
	if (rte_cfgfile_has_section(cfg, "GLOBAL")) {
		has_global = 1;
		value = rte_cfgfile_get_entry(cfg, "GLOBAL", "socket");
		if (!value && lport_parse_int_arg(value, &socket_id) != 0)
			RTE_LPORT_LOG(ERR, "Invalid 'socket' argument\n");
		value = rte_cfgfile_get_entry(cfg, "GLOBAL", "tx_ring_size");
		if (value && (lport_parse_int_arg(value, &tx_ring_size) != 0 ||
			      tx_ring_size < 0)) {
			RTE_LPORT_LOG(ERR, "Invalid 'tx_ring_size' argument\n");
			tx_ring_size = 256;
		}
	}

	num_sect = rte_cfgfile_num_sections(cfg, "", 0);
	if (num_sect <= has_global) {
		RTE_LPORT_LOG(ERR,
			      "Invalid configuration file - no l-domains\n");
		return -EINVAL;
	}

	struct ldomain *ld;
	struct rte_cfgfile_entry entries[LPORT_CFG_MAX_ENT];
	const struct rte_cfgfile_entry *entry;
	const struct rte_cfgfile_entry *end_entry; /* "eoe" mark */
	int num_ent;
	char sect_name[CFG_NAME_LEN];
	const struct lport_tag_set *tset;
	int i, lp_idx = 0;

	for (i = has_global; i < num_sect; ++i) {
		ld = &lport_data.ldomains[curr_domain];
		RTE_ASSERT(!ld->initialized);
		num_ent = rte_cfgfile_section_num_entries_by_index(cfg,
								   sect_name,
								   i);
		if (num_ent <= 0) {
			RTE_LPORT_LOG(WARNING, "Empty configuration section\n");
			continue;
		}
		if (num_ent > LPORT_CFG_MAX_ENT)
			RTE_LPORT_LOG(WARNING, "Too many entries in section\n");
		if (strncmp(LPORT_CFG_SECTION, sect_name, CFG_NAME_LEN) != 0) {
			RTE_LPORT_LOG(WARNING, "Unrecognized section: %s\n",
				      sect_name);
			continue;
		}
		end_entry = entries + num_ent;
		rte_cfgfile_section_entries_by_index(cfg, i, sect_name, entries,
						     LPORT_CFG_MAX_ENT);

		entry = cfg_find_entry(entries, LPORT_CFG_MAX_ENT, "classify");
		if (!entry) {
			RTE_LPORT_LOG(WARNING,
				      "Missing classification scheme\n");
			continue;
		}
		tset = match_tag_by_name(entry->value);
		if (!tset) {
			RTE_LPORT_LOG(WARNING, "Wrong classification scheme\n");
			continue;
		}
		RTE_LPORT_LOG(DEBUG, "Classification scheme: %s\n", tset->name);
		ld->tag_type    = tset->tag_type;
		ld->dispatch_cb = tset->dispatch_cb;
		ld->match_cb    = tset->match_cb;

		num_ent = cfg_count_entries(entries, num_ent, "lport");
		if (num_ent <= 0) {
			RTE_LPORT_LOG(ERR, "Missing l-port specification\n");
			continue;
		}
		ld->tag_map = tag_map_alloc(num_ent);
		if (ld->tag_map == NULL)
			return -1;
		entry = cfg_find_entry(entries, LPORT_CFG_MAX_ENT, "p-port");
		if (!entry) {
			RTE_LPORT_LOG(ERR, "Missing p-port configuration\n");
			continue;
		}
		/* NOTE - the tag_map and port_arg are allocated "forever" */
		ld->port_arg = strdup(entry->value);

		/* initialize the l-domain */
		ld->socket_id = socket_id;
		rte_spinlock_init(&ld->tx_lock);
		rte_spinlock_init(&ld->rx_lock);
		ld->initialized = true;

		parse_lports(ld, entries, end_entry, &lp_idx);

		/* domain configured so move to next one */
		++curr_domain;
	}

	return 0;
}

static int
lport_enable_port(const char *key __rte_unused, const char *ifname,
		  void *vdev)
{
	struct lport *lp;
	struct ldomain *ld;
	uint16_t eth_id;
	struct rte_eth_dev_info dinfo;
	struct rte_dev_iterator iter;
	uint32_t i;

	for (i = 0; i < RTE_DIM(lport_data.lports); ++i) {
		lp = lport_data.lports + i;
		if (ifname && strncmp(ifname, lp->name, RTE_DIM(lp->name)) != 0)
			continue;
		if (lp->eth_dev)  /* if enabled continue here instead of   */
			continue; /* return just in case of repeated iface */
		ld = lp->ldomain;
		if (ld->eth_id == RTE_MAX_ETHPORTS) {
			/* initialize p-port */
			if (rte_dev_probe(ld->port_arg)) {
				RTE_LPORT_LOG(ERR,
					      "Could not probe p-port\n");
				return -EINVAL;
			}
			RTE_ETH_FOREACH_MATCHING_DEV(eth_id, ld->port_arg,
						     &iter) {
				rte_eth_iterator_cleanup(&iter);
				break;
			}
			if (eth_id == RTE_MAX_ETHPORTS) {
				RTE_LPORT_LOG(ERR,
					      "Could not find p-port\n");
				return -EINVAL;
			}
			/* mark every p-port as owned by us */
			rte_eth_dev_owner_set(eth_id, &lport_data.owner);
			/* since p-port is our main transport pipe for different
			 * l-ports set it in promiscuous mode
			 */
			rte_eth_promiscuous_enable(eth_id);
			ld->eth_id = eth_id;

			rte_eth_dev_info_get(eth_id, &dinfo);
			ld->max_tx_queues = dinfo.max_tx_queues;
		}
		lp->eth_dev = lport_ethdev_alloc(vdev, lp, ld->socket_id);
		if (!lp->eth_dev)
			/* XXX - I guess EINVAL (e.g. duplicated name) is more
			 * likely, but since this is "failure to 'alloc'" let's
			 * use ENOMEM
			 */
			return -ENOMEM;
		++ld->lports_cnt;
	}
	return 0;
}

static void
lport_init(void)
{
	struct ldomain *ldomain;
	unsigned int d, l, v;
	struct rte_eth_dev_owner *owner;

	RTE_LOG(INFO, EAL, "Initializing pmd_lport data\n");

	memset(&lport_data, 0, sizeof(lport_data));
	for (d = 0; d < RTE_DIM(lport_data.ldomains); ++d) {
		ldomain = &lport_data.ldomains[d];
		ldomain->id = d;
		ldomain->eth_id = RTE_MAX_ETHPORTS;
		ldomain->socket_id = SOCKET_ID_ANY;
		for (l = 0; l < RTE_DIM(lport_data.lcore_data); ++l) {
			struct lport_qids *qid =
					&lport_data.lcore_data[l].q_ids[d];

			if (rte_lcore_is_enabled(l)) {
				qid->rx_id = 0;
				/* lowest bit is reserved for "shared" flag */
				qid->tx_id = rte_lcore_index(l) << 1;
			} else {
				qid->rx_id = -1;
				qid->tx_id = -1;
			}
		}
	}
	for (v = 0; v < RTE_DIM(lport_data.lports); ++v) {
		struct lport *lp = lport_data.lports + v;

		lp->tag.value = -1;
		lp->id = v;
		lp->promisc_mode = true; /* by default l-ports are promisc */
	}

	/* allocate owner id to be used for all p-ports */
	owner = &lport_data.owner;
	rte_eth_dev_owner_new(&owner->id);
	strncpy(owner->name, "net_lport", sizeof(owner->name));
}

static int
lport_probe(struct rte_vdev_device *dev)
{
	struct rte_kvargs *kvlist;
	struct rte_cfgfile *cfg = NULL;
	int ret = 0;
	unsigned int ifaces;

	if (!dev)
		return -EINVAL;

	socket_id = dev->device.numa_node;

	if (!lport_data.initialized) {
		lport_init();
		lport_data.initialized = true;
	}

	kvlist = rte_kvargs_parse(rte_vdev_device_args(dev),
				  pmd_lport_valid_args);
	if (!kvlist)
		return -EINVAL;

	if (!lport_data.config_read) {
		const char *fname = "lport.cfg";
		const struct rte_kvargs_pair *pair;
		uint32_t i;

		for (i = 0; i < kvlist->count; i++) {
			pair = &kvlist->pairs[i];
			if (strcmp(pair->key, LPORT_CFG_KVARG) == 0) {
				fname = pair->value;
				break;
			}
		}
		cfg = rte_cfgfile_load(fname, CFG_FLAG_GLOBAL_SECTION);
		if (!cfg) {
			RTE_LPORT_LOG(ERR, "Failed to load configuration: %s\n",
				      fname);
			ret = -EINVAL;
			goto exit;
		}

		ret = lport_parse_config(cfg);
		if (ret != 0)
			goto exit;
		lport_data.config_read = true;
	}

	ifaces = rte_kvargs_count(kvlist, LPORT_IFACE_KVARG);
	if (!ifaces)
		lport_enable_port(NULL, NULL, dev);
	else
		ret = rte_kvargs_process(kvlist, LPORT_IFACE_KVARG,
					 lport_enable_port, dev);

exit:
	if (cfg)
		rte_cfgfile_close(cfg);
	rte_kvargs_free(kvlist);
	return ret;
}

static int
lport_remove(struct rte_vdev_device *dev)
{
	if (!dev || dev->device.driver != &pmd_lport_drv.driver)
		return -EINVAL;

	struct lport *lp;
	struct rte_eth_dev *eth_dev;
	struct ldomain *ld;
	uint32_t i;

	for (i = 0; i < RTE_DIM(lport_data.lports); ++i) {
		lp = lport_data.lports + i;
		if (!lp->eth_dev || lp->eth_dev->device != &dev->device)
			continue;
		if (lp->active) /* user has to stop the port first */
			return -EBUSY;
		eth_dev = lp->eth_dev;
		rte_free(eth_dev->data->mac_addrs);
		eth_dev->dev_ops = NULL;
		eth_dev->rx_pkt_burst = NULL;
		eth_dev->tx_pkt_burst = NULL;
		rte_eth_dev_release_port(eth_dev);
		lp->eth_dev = NULL;
		--lp->ldomain->lports_cnt;
	}
	for (i = 0; i < RTE_DIM(lport_data.ldomains); ++i) {
		ld = lport_data.ldomains + i;
		if (ld->eth_id == RTE_MAX_ETHPORTS || ld->lports_cnt != 0)
			continue;

		free(ld->port_arg);
		rte_free(ld->tag_map);
		/* detach p-port and mark it so in lport_data */
		rte_dev_remove(&dev->device);
		ld->eth_id = RTE_MAX_ETHPORTS;
	}

	return 0;
}
