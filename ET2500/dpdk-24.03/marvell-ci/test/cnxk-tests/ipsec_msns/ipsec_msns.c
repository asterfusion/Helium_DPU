/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_bitmap.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_hexdump.h>
#include <rte_ipsec.h>
#include <rte_malloc.h>
#include <rte_pmd_cnxk.h>
#include <rte_security.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>

#include "ipsec_msns.h"

#define NB_ETHPORTS_USED	 1
#define MEMPOOL_CACHE_SIZE	 32
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define RTE_PORT_ALL		 (~(uint16_t)0x0)

#define RX_PTHRESH 8  /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8  /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 0  /**< Default values of RX write-back threshold reg. */

#define TX_PTHRESH 32 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define NB_MBUF 10240U

static struct rte_mempool *mbufpool[RTE_MAX_ETHPORTS];
static struct rte_mempool *sess_pool;
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SECURITY,
		},
	.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
			.offloads = RTE_ETH_TX_OFFLOAD_SECURITY | RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE,
		},
	.lpbk_mode = 0,
};

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
			.pthresh = RX_PTHRESH,
			.hthresh = RX_HTHRESH,
			.wthresh = RX_WTHRESH,
		},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
			.pthresh = TX_PTHRESH,
			.hthresh = TX_HTHRESH,
			.wthresh = TX_WTHRESH,
		},
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32,   /* Use PMD default values */
};

struct lcore_cfg {
	uint8_t socketid;
	uint16_t nb_ports;
	uint16_t portid;
	int eventdev_id;
	int event_port_id;
	int eventq_id;

	/* Stats */
	uint64_t rx_pkts;
	uint64_t rx_ipsec_pkts;
	uint64_t tx_pkts;
};

static struct lcore_cfg lcore_cfg[RTE_MAX_LCORE];

static struct rte_flow *default_flow[RTE_MAX_ETHPORTS][RTE_PMD_CNXK_SEC_ACTION_ALG4 + 1];

struct sa_index_map {
	struct rte_bitmap *map;
	uint32_t size;
};

static struct sa_index_map bmap[RTE_MAX_ETHPORTS][2];

/* Example usage, max entries 4K */
#define MAX_SA_SIZE (4 * 1024)

static uint32_t ethdev_port_mask = RTE_PORT_ALL;
static volatile bool force_quit;
static uint32_t nb_bufs = 0;
static bool perf_mode;
static bool pfc;
static int eventdev_id;
static int rx_adapter_id;
static int tx_adapter_id;
static int nb_event_queues;
static int nb_event_ports;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

static int
cnxk_sa_index_init(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	uint32_t bmap_sz;
	uint32_t i;
	void *mem;

	if (bmap[port_id][dir].map == NULL) {
		bmap_sz = rte_bitmap_get_memory_footprint(size);
		mem = rte_zmalloc("ut_sa_index_bmap", bmap_sz, RTE_CACHE_LINE_SIZE);
		if (mem == NULL)
			return -1;
		bmap[port_id][dir].map = rte_bitmap_init(size, mem, bmap_sz);
		if (bmap[port_id][dir].map == NULL)
			return -1;
		for (i = 0; i < size; i++)
			rte_bitmap_set(bmap[port_id][dir].map, i);
		bmap[port_id][dir].size = size;
	}
	return 0;
}

static void
cnxk_sa_index_fini(int port_id, enum rte_security_ipsec_sa_direction dir)
{
	rte_free(bmap[port_id][dir].map);
	bmap[port_id][dir].map = NULL;
}

static int
cnxk_sa_index_alloc(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t size)
{
	bool update_idx;
	int index, bit;
	uint32_t count;
	uint32_t i, j;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if (size > bmap[port_id][dir].size)
		return -1;

	__rte_bitmap_scan_init(bmap[port_id][dir].map);
	i = 0;
retry:
	update_idx = 1;
	count = 0;
	index = -1;
	for (; i < bmap[port_id][dir].size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (bit) {
			if (update_idx) {
				if ((i + size) > bmap[port_id][dir].size)
					return -1;
				index = i;
				update_idx = 0;
			}
			count++;
			if (count >= size) {
				for (j = index; j < (index + size); j++)
					rte_bitmap_clear(bmap[port_id][dir].map, j);
				return index;
			}
		} else {
			i++;
			goto retry;
		}
	}
	return -1;
}

static int
cnxk_sa_index_free(int port_id, enum rte_security_ipsec_sa_direction dir, uint32_t sa_index,
		   uint32_t size)
{
	uint32_t i;
	int bit;

	if (bmap[port_id][dir].map == NULL)
		return -1;

	if ((sa_index + size) > bmap[port_id][dir].size)
		return -1;

	for (i = sa_index; i < sa_index + size; i++) {
		bit = rte_bitmap_get(bmap[port_id][dir].map, i);
		if (!bit)
			rte_bitmap_set(bmap[port_id][dir].map, i);
	}
	return 0;
}

static int
compare_pkt_data(struct rte_mbuf *m, uint8_t *ref, unsigned int tot_len)
{
	unsigned int nb_segs = m->nb_segs;
	struct rte_mbuf *save = m;
	unsigned int matched = 0;
	unsigned int len;

	while (m && nb_segs != 0) {
		len = tot_len;
		if (len > m->data_len)
			len = m->data_len;
		if (len != 0) {
			if (memcmp(rte_pktmbuf_mtod(m, char *), ref + matched, len)) {
				printf("\n====Test case failed: Data Mismatch");
				rte_hexdump(stdout, "Data", rte_pktmbuf_mtod(m, char *), len);
				rte_hexdump(stdout, "Reference", ref + matched, len);
				return -1;
			}
		}
		tot_len -= len;
		matched += len;
		m = m->next;
		nb_segs--;
	}

	if (tot_len) {
		printf("\n====Test casecase failed: Data Missing %u", tot_len);
		printf("\n====nb_segs %u, tot_len %u", nb_segs, tot_len);
		rte_pktmbuf_dump(stderr, save, -1);
		return -1;
	}
	return 0;
}

/* Create Inline IPsec session */
static int
create_inline_ipsec_session(struct ipsec_session_data *sa, uint16_t portid,
			    struct rte_security_session **ses,
			    enum rte_security_ipsec_sa_direction dir,
			    enum rte_security_ipsec_tunnel_type tun_type)
{
	uint32_t src_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 2));
	uint32_t dst_v4 = rte_cpu_to_be_32(RTE_IPV4(192, 168, 1, 1));
	uint16_t src_v6[8] = {0x2607, 0xf8b0, 0x400c, 0x0c03, 0x0000, 0x0000, 0x0000, 0x001a};
	uint16_t dst_v6[8] = {0x2001, 0x0470, 0xe5bf, 0xdead, 0x4957, 0x2174, 0xe82c, 0x4887};
	struct rte_security_session_conf sess_conf = {
		.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL,
		.protocol = RTE_SECURITY_PROTOCOL_IPSEC,
		.ipsec = sa->ipsec_xform,
		.crypto_xform = &sa->xform.aead,
		.userdata = NULL,
	};
	const struct rte_security_capability *sec_cap;
	struct rte_security_ctx *sec_ctx;

	sess_conf.ipsec.direction = dir;
	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	if (sec_ctx == NULL) {
		printf("Ethernet device doesn't support security features.\n");
		return -1;
	}

	sec_cap = rte_security_capabilities_get(sec_ctx);
	if (sec_cap == NULL) {
		printf("No capabilities registered\n");
		return -1;
	}

	/* iterate until ESP tunnel*/
	while (sec_cap->action != RTE_SECURITY_ACTION_TYPE_NONE) {
		if (sec_cap->action == sess_conf.action_type &&
		    sec_cap->protocol == RTE_SECURITY_PROTOCOL_IPSEC &&
		    sec_cap->ipsec.mode == sess_conf.ipsec.mode && sec_cap->ipsec.direction == dir)
			break;
		sec_cap++;
	}

	if (sec_cap->action == RTE_SECURITY_ACTION_TYPE_NONE) {
		printf("No suitable security capability found\n");
		return -1;
	}

	sess_conf.crypto_xform->aead.key.data = sa->key.data;

	/* Save SA as userdata for the security session. When
	 * the packet is received, this userdata will be
	 * retrieved using the metadata from the packet.
	 *
	 * The PMD is expected to set similar metadata for other
	 * operations, like rte_eth_event, which are tied to
	 * security session. In such cases, the userdata could
	 * be obtained to uniquely identify the security
	 * parameters denoted.
	 */

	sess_conf.userdata = (void *)sa;
	sess_conf.ipsec.tunnel.type = tun_type;
	if (tun_type == RTE_SECURITY_IPSEC_TUNNEL_IPV4) {
		memcpy(&sess_conf.ipsec.tunnel.ipv4.src_ip, &src_v4, sizeof(src_v4));
		memcpy(&sess_conf.ipsec.tunnel.ipv4.dst_ip, &dst_v4, sizeof(dst_v4));
	} else {
		memcpy(&sess_conf.ipsec.tunnel.ipv6.src_addr, &src_v6, sizeof(src_v6));
		memcpy(&sess_conf.ipsec.tunnel.ipv6.dst_addr, &dst_v6, sizeof(dst_v6));
	}

	*ses = rte_security_session_create(sec_ctx, &sess_conf, sess_pool);
	if (*ses == NULL) {
		printf("SEC Session init failed\n");
		return -1;
	}

	return 0;
}

/* Check the link status of all ports in up to 3s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30  /* 3s (30 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	char link_status[RTE_ETH_LINK_MAX_STR_LEN];
	struct rte_eth_link link;
	uint16_t portid;
	int ret;

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & RTE_BIT64(portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n", portid,
					       rte_strerror(-ret));
				continue;
			}

			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status, sizeof(link_status), &link);
				printf("Port %d %s\n", portid, link_status);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
			print_flag = 1;
	}
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static void
copy_buf_to_pkt_segs(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	unsigned int copy_len;
	struct rte_mbuf *seg;
	void *seg_buf;

	seg = pkt;
	while (offset >= seg->data_len) {
		offset -= seg->data_len;
		seg = seg->next;
	}
	copy_len = seg->data_len - offset;
	seg_buf = rte_pktmbuf_mtod_offset(seg, char *, offset);
	while (len > copy_len) {
		rte_memcpy(seg_buf, buf, (size_t)copy_len);
		len -= copy_len;
		buf = ((char *)buf + copy_len);
		seg = seg->next;
		seg_buf = rte_pktmbuf_mtod(seg, void *);
	}
	rte_memcpy(seg_buf, buf, (size_t)len);
}

static inline void
copy_buf_to_pkt(void *buf, unsigned int len, struct rte_mbuf *pkt, unsigned int offset)
{
	if (offset + len <= pkt->data_len) {
		rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf, (size_t)len);
		return;
	}
	copy_buf_to_pkt_segs(buf, len, pkt, offset);
}

static inline int
init_traffic(struct rte_mempool *mp, struct rte_mbuf **pkts_burst,
	     struct ipsec_test_packet *vectors)
{
	struct rte_mbuf *pkt;

	pkt = rte_pktmbuf_alloc(mp);
	if (pkt == NULL)
		return -1;

	pkt->data_len = vectors->len;
	pkt->pkt_len = vectors->len;
	copy_buf_to_pkt(vectors->data, vectors->len, pkt, 0);
	pkts_burst[0] = pkt;
	return 0;
}

static void
init_lcore(void)
{
	uint16_t ev_port_id = 0;
	unsigned int lcore_id;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_cfg[lcore_id].socketid = rte_lcore_to_socket_id(lcore_id);
		if (rte_lcore_is_enabled(lcore_id) != 0) {
			if (perf_mode) {
				/* Assign event port id */
				lcore_cfg[lcore_id].eventdev_id = 0;
				lcore_cfg[lcore_id].event_port_id = -1;
				if (ev_port_id >= nb_event_ports)
					continue;
				lcore_cfg[lcore_id].event_port_id = ev_port_id++;
			} else {
				lcore_cfg[lcore_id].portid = 0;
			}
		}
	}
}

static int
init_sess_mempool(void)
{
	struct rte_security_ctx *sec_ctx;
	uint16_t nb_sess = 512;
	uint32_t sess_sz;
	int socketid = 0;
	char s[64];

	sec_ctx = rte_eth_dev_get_sec_ctx(0);
	if (sec_ctx == NULL)
		return -ENOENT;

	sess_sz = rte_security_session_get_size(sec_ctx);
	if (sess_pool == NULL) {
		snprintf(s, sizeof(s), "sess_pool_%d", socketid);
		sess_pool = rte_mempool_create(s, nb_sess, sess_sz, MEMPOOL_CACHE_SIZE, 0,
					       NULL, NULL, NULL, NULL, socketid, 0);
		if (sess_pool == NULL) {
			printf("Cannot init sess pool on socket %d\n", socketid);
			return -1;
		}
		printf("Allocated sess pool on socket %d\n", socketid);
	}
	return 0;
}

static int
init_pktmbuf_pool(uint32_t portid, unsigned int nb_mbuf)
{
	int socketid = 0;
	char s[64];

	if (mbufpool[portid] == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool_%d", portid);
		mbufpool[portid] = rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
							   RTE_MBUF_DEFAULT_BUF_SIZE, socketid);
		if (mbufpool[portid] == NULL)
			printf("Cannot init mbuf pool on socket %d\n", socketid);
		printf("Allocated mbuf pool for port %d\n", portid);
	}
	return 0;
}

static int
create_default_flow(uint16_t port_id, enum rte_pmd_cnxk_sec_action_alg alg, uint32_t spi,
		    uint16_t sa_lo, uint16_t sa_hi, uint32_t sa_index)
{
	struct rte_pmd_cnxk_sec_action sec = {0};
	struct rte_flow_action_mark mark = {0};
	struct rte_flow_item_esp mesp = {0};
	struct rte_flow_item_esp esp = {0};
	struct rte_flow_action action[3];
	struct rte_flow_item pattern[2];
	struct rte_flow_attr attr = {0};
	struct rte_flow_error err;
	struct rte_flow *flow;
	int act_count = 0;
	int ret;

	/* Add the default rte_flow to enable SECURITY for all ESP packets */
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ESP;
	pattern[0].spec = &esp;
	pattern[0].mask = &mesp;
	pattern[0].last = NULL;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	action[act_count].type = RTE_FLOW_ACTION_TYPE_SECURITY;
	action[act_count].conf = &sec;
	act_count++;

	esp.hdr.spi = RTE_BE32(spi);
	mesp.hdr.spi = RTE_BE32(0xffffffff);
	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* SPI = 0x10000001, sa_index = 0 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG0;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* SPI = 0x10000001, sa_index = 1 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG1;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG2;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* SPI = 0x04000001, sa_index = 2 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG3;
		sec.sa_xor = 1;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* SPI = 0x100, sa_index = 3 */
		sec.alg = RTE_PMD_CNXK_SEC_ACTION_ALG4;
		sec.sa_xor = 0;
		sec.sa_hi = sa_hi;
		sec.sa_lo = sa_lo;
		sec.sa_index = sa_index;
		esp.hdr.spi = RTE_BE32(0x100);
		mesp.hdr.spi = RTE_BE32(0xffffffff);
		mark.id = 0x200;
		action[act_count].type = RTE_FLOW_ACTION_TYPE_MARK;
		action[act_count].conf = &mark;
		act_count++;
		break;
	}

	action[act_count].type = RTE_FLOW_ACTION_TYPE_END;
	action[act_count].conf = NULL;
	attr.ingress = 1;

	ret = rte_flow_validate(port_id, &attr, pattern, action, &err);
	if (ret)
		return ret;

	flow = rte_flow_create(port_id, &attr, pattern, action, &err);
	if (flow == NULL) {
		printf("\nDefault flow rule create failed\n");
		return -1;
	}

	default_flow[port_id][alg] = flow;
	return 0;
}

static void
destroy_default_flow(uint16_t port_id)
{
	struct rte_flow_error err;
	uint8_t alg;
	int ret;

	for (alg = RTE_PMD_CNXK_SEC_ACTION_ALG0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG4; alg++) {
		if (!default_flow[port_id][alg])
			continue;
		ret = rte_flow_destroy(port_id, default_flow[port_id][alg], &err);
		if (ret) {
			printf("\nDefault flow rule destroy failed for port=%d alg=%d, rc=%d\n",
			       port_id, alg, ret);
			return;
		}
		default_flow[port_id][alg] = NULL;
	}
}

static int
ut_eventdev_setup(void)
{
	struct rte_event_eth_rx_adapter_queue_conf queue_conf;
	struct rte_event_dev_info evdev_default_conf = {0};
	struct rte_event_dev_config eventdev_conf = {0};
	struct rte_event_queue_conf eventq_conf = {0};
	struct rte_event_port_conf ev_port_conf = {0};
	const int all_queues = -1;
	uint8_t ev_queue_id = 0;
	int portid, ev_port_id;
	uint32_t caps = 0;
	int ret;

	/* Setup eventdev */
	eventdev_id = 0;
	rx_adapter_id = 0;
	tx_adapter_id = 0;

	/* Get default conf of eventdev */
	ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
	if (ret < 0) {
		printf("Error in getting event device info[devID:%d]\n",
		       eventdev_id);
		return ret;
	}
	nb_event_ports = rte_lcore_count();
	nb_event_queues = evdev_default_conf.max_event_queues;

	/* Get Tx adapter capabilities */
	ret = rte_event_eth_tx_adapter_caps_get(eventdev_id, tx_adapter_id, &caps);
	if (ret < 0) {
		printf("Failed to get event device %d eth tx adapter"
		       " capabilities\n",
		       eventdev_id);
		return ret;
	}

	eventdev_conf.nb_events_limit =
		evdev_default_conf.max_num_events;
	eventdev_conf.nb_event_queue_flows =
		evdev_default_conf.max_event_queue_flows;
	eventdev_conf.nb_event_port_dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	eventdev_conf.nb_event_port_enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	eventdev_conf.nb_event_queues = nb_event_queues;
	eventdev_conf.nb_event_ports = nb_event_ports;

	/* Configure event device */

	ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
	if (ret < 0) {
		printf("Error in configuring event device\n");
		return ret;
	}

	/* Configure event queue */
	eventq_conf.schedule_type = RTE_SCHED_TYPE_PARALLEL;
	eventq_conf.nb_atomic_flows = 1024;
	eventq_conf.nb_atomic_order_sequences = 1024;

	/* Setup the queue */
	for (ev_queue_id = 0; ev_queue_id < nb_event_queues; ev_queue_id++) {
		ret = rte_event_queue_setup(eventdev_id, ev_queue_id, &eventq_conf);
		if (ret < 0) {
			printf("Failed to setup event queue %d, rc=%d\n", ev_queue_id, ret);
			return ret;
		}
	}

	/* Configure event port */
	for (ev_port_id = 0; ev_port_id < nb_event_ports; ev_port_id++) {
		ret = rte_event_port_setup(eventdev_id, ev_port_id, NULL);
		if (ret < 0) {
			printf("Failed to setup event port %d\n", ret);
			return ret;
		}

		/* Make event queue - event port link */
		ret = rte_event_port_link(eventdev_id, ev_port_id, NULL, NULL, 1);
		if (ret < 0) {
			printf("Failed to link event port %d\n", ret);
			return ret;
		}
	}

	/* Setup port conf */
	ev_port_conf.new_event_threshold = 1200;
	ev_port_conf.dequeue_depth =
		evdev_default_conf.max_event_port_dequeue_depth;
	ev_port_conf.enqueue_depth =
		evdev_default_conf.max_event_port_enqueue_depth;

	/* Create Rx adapter */
	ret = rte_event_eth_rx_adapter_create(rx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create rx adapter %d\n", ret);
		return ret;
	}

	/* Create tx adapter */
	ret = rte_event_eth_tx_adapter_create(tx_adapter_id, eventdev_id,
					      &ev_port_conf);
	if (ret < 0) {
		printf("Failed to create tx adapter %d\n", ret);
		return ret;
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		/* Setup queue conf */
		memset(&queue_conf, 0, sizeof(queue_conf));
		queue_conf.ev.queue_id = portid % nb_event_queues;
		queue_conf.ev.sched_type = RTE_SCHED_TYPE_PARALLEL;
		queue_conf.ev.event_type = RTE_EVENT_TYPE_ETHDEV;

		/* Add queue to the adapter */
		ret = rte_event_eth_rx_adapter_queue_add(rx_adapter_id, portid,
							 all_queues, &queue_conf);
		if (ret < 0) {
			printf("Failed to add eth queue to rx adapter %d\n", ret);
			return ret;
		}

		/* Add queue to the adapter */
		ret = rte_event_eth_tx_adapter_queue_add(tx_adapter_id, portid,
							 all_queues);
		if (ret < 0) {
			printf("Failed to add eth queue to tx adapter %d\n", ret);
			return ret;
		}

	}
	/* Start rx adapter */
	ret = rte_event_eth_rx_adapter_start(rx_adapter_id);
	if (ret < 0) {
		printf("Failed to start rx adapter %d\n", ret);
		return ret;
	}

	/* Start tx adapter */
	ret = rte_event_eth_tx_adapter_start(tx_adapter_id);
	if (ret < 0) {
		printf("Failed to start tx adapter %d\n", ret);
		return ret;
	}

	/* Start eventdev */
	ret = rte_event_dev_start(eventdev_id);
	if (ret < 0) {
		printf("Failed to start event device %d\n", ret);
		return ret;
	}

	return 0;
}

static void
ut_eventdev_teardown(void)
{
	int ret;
	int portid;

	/* Stop rx adapter */
	ret = rte_event_eth_rx_adapter_stop(rx_adapter_id);
	if (ret < 0)
		printf("Failed to stop rx adapter %d\n", ret);

	/* Stop tx adapter */
	ret = rte_event_eth_tx_adapter_stop(tx_adapter_id);
	if (ret < 0)
		printf("Failed to stop tx adapter %d\n", ret);

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_event_eth_rx_adapter_queue_del(rx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove rx adapter queues %d\n", ret);
		ret = rte_event_eth_tx_adapter_queue_del(tx_adapter_id, portid, -1);
		if (ret < 0)
			printf("Failed to remove tx adapter queues %d\n", ret);
	}

	/* Release rx adapter */
	ret = rte_event_eth_rx_adapter_free(rx_adapter_id);
	if (ret < 0)
		printf("Failed to free rx adapter %d\n", ret);

	/* Release tx adapter */
	ret = rte_event_eth_tx_adapter_free(tx_adapter_id);
	if (ret < 0)
		printf("Failed to free tx adapter %d\n", ret);

	/* Stop and release event devices */
	rte_event_dev_stop(eventdev_id);
	ret = rte_event_dev_close(eventdev_id);
	if (ret < 0)
		printf("Failed to close event dev %d, %d\n", eventdev_id, ret);
}

static void
print_usage(const char *name)
{
	printf("Invalid arguments\n");
	printf("usage: %s [--perf] [--pfc] [--portmask] [--nb-mbufs <count >]\n", name);
}

static int
parse_args(int argc, char **argv)
{
	char *name = argv[0];

	argc--;
	argv++;
	while (argc) {
		if (!strcmp(argv[0], "--perf")) {
			perf_mode = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--pfc")) {
			pfc = true;
			argc--;
			argv++;
			continue;
		}

		if (!strcmp(argv[0], "--portmask") && (argc > 1)) {
			ethdev_port_mask = strtoul(argv[1], NULL, 0);
			argc -= 2;
			argv += 2;
			continue;
		}

		if (!strcmp(argv[0], "--nb-mbufs") && (argc > 1)) {
			nb_bufs = atoi(argv[1]);
			argc-=2;
			argv+=2;
			continue;
		}

		/* Unknown args */
		print_usage(name);
		return -1;
	}

	return 0;
}

static int
ut_setup(int argc, char **argv)
{
	uint16_t nb_rx_queue = 1, nb_tx_queue = 1;
	int socketid = 0, ret;
	uint32_t nb_lcores;
	uint32_t nb_mbufs;
	uint16_t nb_ports;
	uint16_t nb_rxd;
	uint16_t nb_txd;
	uint16_t portid;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		printf("Invalid EAL arguments\n");
		return -1;
	}
	argc -= ret;
	argv += ret;

	ret = parse_args(argc, argv);
	if (ret < 0)
		return ret;

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED || ethdev_port_mask == 0) {
		printf("At least %u port(s) used for test\n", NB_ETHPORTS_USED);
		return -1;
	}

	ret = init_sess_mempool();
	if (ret) {
		printf("Unable to initialize session mempool: ret = %d\n", ret);
		return -1;
	}

	nb_lcores = rte_lcore_count();

	nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	nb_txd = RTE_TEST_TX_DESC_DEFAULT;

	nb_mbufs = nb_bufs ? nb_bufs : RTE_MAX(nb_ports * (nb_rxd + nb_txd +
							   nb_lcores * MEMPOOL_CACHE_SIZE),
					       NB_MBUF);

	/* Setup all available ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;

		ret = init_pktmbuf_pool(portid, nb_mbufs);
		if (ret) {
			printf("Failed to setup pktmbuf pool for port=%d, ret=%d", portid, ret);
			return ret;
		}

		/* Enable loopback mode for non perf test */
		port_conf.lpbk_mode = perf_mode ? 0 : 1;

		/* port configure */
		ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
		if (ret < 0) {
			printf("Cannot configure device: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		ret = rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		if (ret < 0) {
			printf("Cannot get mac address: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		printf("Port %u ", portid);
		print_ethaddr("Address:", &ports_eth_addr[portid]);
		printf("\n");

		/* tx queue setup */
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, socketid, &tx_conf);
		if (ret < 0) {
			printf("rte_eth_tx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		/* rx queue steup */
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, socketid, &rx_conf,
					     mbufpool[portid]);
		if (ret < 0) {
			printf("rte_eth_rx_queue_setup: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		/* Init sa_index map with 4K size*/
		ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, MAX_SA_SIZE);
		if (ret) {
			printf("egress sa index init failed: err=%d, port=%d\n", ret, portid);
			return ret;
		}

		ret = cnxk_sa_index_init(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, MAX_SA_SIZE);
		if (ret) {
			printf("egress sa index init failed: err=%d, port=%d\n", ret, portid);
			return ret;
		}
	}

	if (perf_mode) {
		/* Setup event device */
		ret = ut_eventdev_setup();
		if (ret < 0) {
			printf("Failed to setup eventdev, err=%d\n", ret);
			return ret;
		}
	}

	init_lcore();

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		/* Enable PFC if requested */
		if (pfc) {
			struct rte_eth_pfc_queue_conf pfc_conf;
			struct rte_eth_fc_conf fc_conf;

			/* Disable flow control */
			memset(&fc_conf, 0, sizeof(fc_conf));
			fc_conf.mode = RTE_ETH_FC_NONE;
			ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
			if (ret) {
				printf("Failed to disable flow control on port=%u, ret=%d\n",
				       portid, ret);
				return ret;
			}

			/* Enable PFC */
			memset(&pfc_conf, 0, sizeof(pfc_conf));
			pfc_conf.mode = RTE_ETH_FC_FULL;
			pfc_conf.rx_pause.tx_qid = 0;
			pfc_conf.rx_pause.tc = (portid + 3) % 8;
			pfc_conf.tx_pause.rx_qid = 0;
			pfc_conf.tx_pause.tc = (portid + 3) % 8;
			ret = rte_eth_dev_priority_flow_ctrl_queue_configure(portid, &pfc_conf);
			if (ret) {
				printf("Failed to enable PFC %u on port=%u, ret=%d\n",
				       pfc_conf.rx_pause.tc, portid, ret);
				return ret;
			}

			printf("Enabled PFC class %u on port %d RX/TX\n", pfc_conf.rx_pause.tc,
			       portid);
		}

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			printf("rte_eth_dev_start: err=%d, port=%d\n", ret, portid);
			return ret;
		}
		/* always enable promiscuous */
		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0) {
			printf("rte_eth_promiscuous_enable: err=%s, port=%d\n", rte_strerror(-ret),
			       portid);
			return ret;
		}
	}

	check_all_ports_link_status(ethdev_port_mask);
	return 0;
}

static void
ut_teardown(void)
{
	int ret;
	int portid;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%s, port=%u\n", rte_strerror(-ret), portid);
	}

	/* Event device cleanup */
	if (perf_mode)
		ut_eventdev_teardown();

	/* port tear down */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		ret = rte_eth_dev_reset(portid);
		if (ret != 0)
			printf("rte_eth_dev_reset: err=%s, port=%u\n", rte_strerror(-ret), portid);

		cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS);
		cnxk_sa_index_fini(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS);
	}
}

static int
ut_ipsec_encap_decap(struct test_ipsec_vector *vector, enum rte_security_ipsec_tunnel_type tun_type,
		     uint8_t alg)
{
	struct rte_security_session *out_ses = NULL, *in_ses = NULL;
	uint32_t in_sa_index = 0, out_sa_index = 0, spi = 0;
	struct rte_security_session_conf conf = {0};
	struct rte_security_ctx *sec_ctx = NULL;
	uint32_t index_count = 0, sa_index = 0;
	uint16_t lcore_id = rte_lcore_id();
	struct ipsec_session_data sa_data;
	unsigned int portid, nb_rx = 0, j;
	unsigned int nb_sent = 0, nb_tx;
	struct rte_mbuf *tx_pkts = NULL;
	struct rte_mbuf *rx_pkts = NULL;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint64_t userdata;
	int ret = 0;

	nb_tx = 1;
	portid = lcore_cfg[lcore_id].portid;
	ret = init_traffic(mbufpool[portid], &tx_pkts, vector->frags);
	if (ret != 0) {
		ret = -1;
		goto out;
	}

	switch (alg) {
	case RTE_PMD_CNXK_SEC_ACTION_ALG0:
		/* Allocate 1 index and use it */
		index_count = 1;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index;
		spi = (0x1 << 28 | in_sa_index);
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG1:
		/* Allocate 2 index and use higher index */
		index_count = 2;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 1;
		spi = (sa_index << 28) | 0x0000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG2:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG3:
		/* Allocate 3 index and use higher index */
		index_count = 3;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 2;
		spi = (sa_index << 25) | 0x00000001;
		sa_hi = (spi >> 16) & 0xffff;
		sa_lo = 0x0001;
		break;
	case RTE_PMD_CNXK_SEC_ACTION_ALG4:
		/* Allocate 4 index and use higher index */
		index_count = 4;
		out_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, index_count);
		in_sa_index =
			cnxk_sa_index_alloc(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, index_count);
		sa_index = in_sa_index + 3;
		spi = 0x100;
		sa_hi = 0;
		sa_lo = 0;
		break;
	default:
		ret = -1;
		goto out;
	}

	sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = out_sa_index;
	/* Create Inline IPsec outbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &out_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_EGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Outbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	/* Update the real spi value */
	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	ret = rte_security_session_update(sec_ctx, out_ses, &conf);
	if (ret) {
		printf("Security session update failed outbound\n");
		goto out;
	}
	printf("Updated Outbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	rte_security_set_pkt_metadata(sec_ctx, out_ses, tx_pkts, NULL);
	tx_pkts->ol_flags |= RTE_MBUF_F_TX_SEC_OFFLOAD;
	tx_pkts->l2_len = RTE_ETHER_HDR_LEN;

	memcpy(&sa_data, vector->sa_data, sizeof(sa_data));
	sa_data.ipsec_xform.spi = sa_index;
	/* Create Inline IPsec inbound session. */
	ret = create_inline_ipsec_session(&sa_data, portid, &in_ses,
					  RTE_SECURITY_IPSEC_SA_DIR_INGRESS, tun_type);
	if (ret)
		goto out;
	printf("Created Inbound session with sa_index = 0x%x\n", sa_data.ipsec_xform.spi);

	sa_data.ipsec_xform.spi = spi;
	sa_data.ipsec_xform.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	memcpy(&conf.ipsec, &sa_data.ipsec_xform, sizeof(struct rte_security_ipsec_xform));
	conf.crypto_xform = &sa_data.xform.aead;
	conf.userdata = (void *)(uint64_t)(alg);
	ret = rte_security_session_update(sec_ctx, in_ses, &conf);
	if (ret) {
		printf("Security session update failed inbound\n");
		goto out;
	}
	printf("Updated Inbound session with SPI = 0x%x\n", sa_data.ipsec_xform.spi);

	ret = create_default_flow(portid, alg, spi, sa_lo, sa_hi, sa_index);
	if (ret) {
		printf("Flow creation failed\n");
		goto out;
	}

	nb_sent = rte_eth_tx_burst(portid, 0, &tx_pkts, nb_tx);
	if (nb_sent != nb_tx) {
		ret = -1;
		printf("\nFailed to tx %u pkts", nb_tx);
		goto out;
	}

	printf("Sent %u pkts\n", nb_sent);
	rte_delay_ms(100);

	/* Retry few times before giving up */
	nb_rx = 0;
	j = 0;
	do {
		nb_rx += rte_eth_rx_burst(portid, 0, &rx_pkts, nb_tx - nb_rx);
		j++;
		if (nb_rx >= nb_tx)
			break;
		rte_delay_ms(100);
	} while (j < 10);

	printf("Recv %u pkts\n", nb_rx);
	/* Check for minimum number of Rx packets expected */
	if (nb_rx != nb_tx) {
		printf("\nReceived less Rx pkts(%u) pkts\n", nb_rx);
		ret = -1;
		goto out;
	}

	if (rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED ||
	    !(rx_pkts->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD)) {
		printf("\nSecurity offload failed\n");
		ret = -1;
		goto out;
	}

	/* Check for userdata match */
	userdata = *rte_security_dynfield(rx_pkts);
	if (userdata != alg) {
		printf("\nDecrypted packet userdata mismatch %lx != %x\n",
		       userdata, alg);
		ret = -1;
		goto out;
	}

	if (vector->full_pkt->len != rx_pkts->pkt_len) {
		printf("\nDecrypted packet length mismatch\n");
		ret = -1;
		goto out;
	}
	ret = compare_pkt_data(rx_pkts, vector->full_pkt->data, vector->full_pkt->len);
out:
	destroy_default_flow(portid);

	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_EGRESS, out_sa_index, index_count);
	cnxk_sa_index_free(portid, RTE_SECURITY_IPSEC_SA_DIR_INGRESS, in_sa_index, index_count);

	/* Clear session data. */
	if (out_ses)
		rte_security_session_destroy(sec_ctx, out_ses);
	if (in_ses)
		rte_security_session_destroy(sec_ctx, in_ses);

	rte_pktmbuf_free(tx_pkts);
	rte_pktmbuf_free(rx_pkts);
	return ret;
}

static int
ut_ipsec_ipv4_burst_encap_decap(void)
{
	struct test_ipsec_vector ipv4_nofrag_case = {
		.sa_data = &conf_aes_128_gcm,
		.full_pkt = &pkt_ipv4_plain,
		.frags = &pkt_ipv4_plain,
	};
	int rc;

	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG0);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG0: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG1);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG1: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG2);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG2: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG3);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG3: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	rc = ut_ipsec_encap_decap(&ipv4_nofrag_case, RTE_SECURITY_IPSEC_TUNNEL_IPV4,
				  RTE_PMD_CNXK_SEC_ACTION_ALG4);
	printf("Test RTE_PMD_CNXK_SEC_ACTION_ALG4: %s\n", rc ? "FAILED" : "PASS");
	if (rc)
		return rc;
	return 0;
}

static void
print_stats(void)
{
	uint64_t last_rx = 0, last_tx = 0;
	uint64_t curr_rx = 0, curr_tx = 0;
	uint64_t curr_rx_ipsec = 0;
	uint64_t timeout = 5;
	uint16_t lcore_id;

	while (!force_quit) {
		curr_rx = 0;
		curr_tx = 0;
		curr_rx_ipsec = 0;
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			curr_rx += lcore_cfg[lcore_id].rx_pkts;
			curr_tx += lcore_cfg[lcore_id].tx_pkts;
			curr_rx_ipsec += lcore_cfg[lcore_id].rx_ipsec_pkts;
		}

		printf("%" PRIu64 " Rx pps(%" PRIu64 " ipsec pkts), %" PRIu64 " Tx pps, "
		       "%" PRIu64 " drops\n",
		       (curr_rx - last_rx) / timeout, curr_rx_ipsec, (curr_tx - last_tx) / timeout,
		       curr_rx - curr_tx);

		sleep(timeout);
		last_rx = curr_rx;
		last_tx = curr_tx;
	}
}

/*
 * Event mode exposes various operating modes depending on the
 * capabilities of the event device and the operating mode
 * selected.
 */

static void
ipsec_event_port_flush(uint8_t eventdev_id __rte_unused, struct rte_event ev,
		       void *args __rte_unused)
{
	rte_pktmbuf_free(ev.mbuf);
}

static int
event_worker(void *args)
{
	uint32_t lcore_id = rte_lcore_id();
	struct lcore_cfg *info = &lcore_cfg[lcore_id];
	unsigned int nb_rx = 0, nb_tx;
	struct rte_mbuf *pkt;
	struct rte_event ev;

	(void)args;

	printf("Launching event mode worker on lcore=%u, event_port_id=%u\n", lcore_id,
	       info->event_port_id);

	while (!force_quit) {
		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(info->eventdev_id, info->event_port_id,
						&ev, 1, 0);
		if (nb_rx == 0)
			continue;

		switch (ev.event_type) {
		case RTE_EVENT_TYPE_ETHDEV:
			break;
		default:
			printf("Invalid event type %u",	ev.event_type);
			continue;
		}

		pkt = ev.mbuf;

		info->rx_pkts += nb_rx;
		info->rx_ipsec_pkts += !!(pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD);

		rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));
		/* Drop packets received with offload failure */
		if (pkt->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED) {
			rte_pktmbuf_free(ev.mbuf);
			continue;
		}

		/* Save eth queue for Tx */
		rte_event_eth_tx_adapter_txq_set(pkt, 0);

		/*
		 * Since tx internal port is available, events can be
		 * directly enqueued to the adapter and it would be
		 * internally submitted to the eth device.
		 */
		nb_tx = rte_event_eth_tx_adapter_enqueue(info->eventdev_id,
							 info->event_port_id,
							 &ev, /* events */
							 1,   /* nb_events */
							 0 /* flags */);
		if (!nb_tx)
			rte_pktmbuf_free(ev.mbuf);
		info->tx_pkts += nb_tx;
	}

	if (ev.u64) {
		ev.op = RTE_EVENT_OP_RELEASE;
		rte_event_enqueue_burst(info->eventdev_id,
					info->event_port_id, &ev, 1);
	}

	rte_event_port_quiesce(info->eventdev_id, info->event_port_id,
			       ipsec_event_port_flush, NULL);
	return 0;
}

static int
ut_ipsec_ipv4_perf(void)
{
	struct rte_security_session *in_ses[RTE_MAX_ETHPORTS][RTE_PMD_CNXK_SEC_ACTION_ALG3 + 1];
	enum rte_security_ipsec_tunnel_type tun_type = RTE_SECURITY_IPSEC_TUNNEL_IPV4;
	struct rte_security_session_conf conf = {0};
	enum rte_security_ipsec_sa_direction dir;
	struct rte_security_ctx *sec_ctx = NULL;
	uint32_t sa_indices[RTE_MAX_ETHPORTS];
	uint32_t sa_index = 0;
	struct ipsec_session_data sa_data;
	unsigned int portid;
	uint16_t sa_hi = 0, sa_lo = 0;
	uint16_t lcore_id;
	uint32_t spi = 0;
	int ret = 0, i;
	uint8_t alg;

	memset(&in_ses, 0, sizeof(in_ses));
	memset(sa_indices, 0xFF, sizeof(sa_indices));
	/* Create one ESP rule per alg on port 0 and it would apply on all ports
	 * due to custom_act
	 */
	printf("\nCrypto Alg: AES-GCM-128\n");
	printf("Crypto Key: ");
	for (i = 0; i < 15; i++)
		printf("%02x:", conf_aes_128_gcm.key.data[i]);
	printf("%02x\n", conf_aes_128_gcm.key.data[i]);

	printf("Crypto Salt: %02x:%02x:%02x:%02x\n",
	       conf_aes_128_gcm.ipsec_xform.salt >> 24,
	       (conf_aes_128_gcm.ipsec_xform.salt >> 16) & 0xFF,
	       (conf_aes_128_gcm.ipsec_xform.salt >> 8) & 0xFF,
	       conf_aes_128_gcm.ipsec_xform.salt & 0xFF);

	dir = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		sec_ctx = (struct rte_security_ctx *)rte_eth_dev_get_sec_ctx(portid);

		sa_index = cnxk_sa_index_alloc(0, dir, 16);
		for (alg = RTE_PMD_CNXK_SEC_ACTION_ALG0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG3;
		     alg++) {

			switch (alg) {
			case RTE_PMD_CNXK_SEC_ACTION_ALG0:
				spi = (0x2 << 28 | sa_index);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG1:
				/* Only SPI[31:28] are considered as SA[3:0] hence use.
				 * rest from SPI[15:4].
				 */
				spi = ((sa_index & 0xF) << 28) | ((sa_index >> 4) << 4);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG2:
				/* Only SPI[27:25] are considered as SA[2:0] hence use.
				 * rest from SPI[15:3].
				 */
				spi = ((sa_index & 0x7) << 25) | ((sa_index >> 3) << 3);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			case RTE_PMD_CNXK_SEC_ACTION_ALG3:
				/* Only SPI[28:25] are considered as SA[3:0] hence use.
				 * rest from SPI[15:4].
				 */
				spi = ((sa_index & 0xF) << 25) | ((sa_index >> 4) << 4);
				sa_hi = (spi >> 16) & 0xffff;
				sa_lo = 0x0000;
				break;
			default:
				break;
			}

			memcpy(&sa_data, &conf_aes_128_gcm, sizeof(sa_data));
			sa_data.ipsec_xform.spi = sa_index;
			/* Create Inline IPsec inbound session. */
			ret = create_inline_ipsec_session(&sa_data, portid, &in_ses[portid][alg],
							  dir, tun_type);
			if (ret)
				goto out;
			printf("Port %d: Created alg %d Inbound session with sa_index = 0x%x\n",
			       portid, alg, sa_data.ipsec_xform.spi);

			sa_data.ipsec_xform.spi = spi;
			sa_data.ipsec_xform.direction = dir;
			conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_PROTOCOL;
			conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
			memcpy(&conf.ipsec, &sa_data.ipsec_xform,
			       sizeof(struct rte_security_ipsec_xform));
			conf.crypto_xform = &sa_data.xform.aead;
			ret = rte_security_session_update(sec_ctx, in_ses[portid][alg], &conf);
			if (ret) {
				printf("Security session update failed inbound\n");
				goto out;
			}
			printf("Port %d: Updated alg %d Inbound session with SPI = 0x%x\n",
			       portid, alg, sa_data.ipsec_xform.spi);

			/* Create all flow rules on port 0 and it would get applied on all ports due
			 * to channel mask.
			 */
			ret = create_default_flow(portid, alg, sa_data.ipsec_xform.spi,
						  sa_lo, sa_hi, sa_index);
			if (ret) {
				printf("Flow creation failed\n");
				goto out;
			}
			sa_index++;
		}
	}

	printf("\n");

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(event_worker, NULL, SKIP_MAIN);

	/* Print stats */
	print_stats();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
out:
	RTE_ETH_FOREACH_DEV(portid) {
		if ((ethdev_port_mask & RTE_BIT64(portid)) == 0)
			continue;
		destroy_default_flow(portid);

		if (sa_indices[portid] != UINT32_MAX)
			cnxk_sa_index_free(portid, dir, sa_indices[portid], 16);
		sa_indices[portid] = UINT32_MAX;

		/* Clear session data. */
		for (alg = 0; alg <= RTE_PMD_CNXK_SEC_ACTION_ALG3; alg++) {
			if (in_ses[portid][alg])
				rte_security_session_destroy(sec_ctx, in_ses[portid][alg]);
		}
	}
	return ret;
}

int
main(int argc, char **argv)
{
	int rc;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	rc = ut_setup(argc, argv);
	if (rc) {
		printf("TEST FAILED: ut_setup\n");
		return rc;
	}

	if (perf_mode) {
		printf("Running in perf mode\n");
		rc = ut_ipsec_ipv4_perf();
		if (rc) {
			printf("Failed to run perf mode\n");
			return rc;
		}

	} else {
		rc = ut_ipsec_ipv4_burst_encap_decap();
		if (rc) {
			printf("TEST FAILED: ut_ipsec_ipv4_burst_encap_decap\n");
			return rc;
		}
	}
	ut_teardown();
	return 0;
}
