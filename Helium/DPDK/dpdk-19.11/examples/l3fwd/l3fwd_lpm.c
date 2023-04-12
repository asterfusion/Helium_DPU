/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>

#include "l3fwd.h"
#include "l3fwd_event.h"

struct ipv4_l3fwd_lpm_route {
	uint32_t ip;
	uint8_t  depth;
	uint8_t  if_out;
};

struct ipv6_l3fwd_lpm_route {
	uint8_t ip[16];
	uint8_t  depth;
	uint8_t  if_out;
};

/* 198.18.0.0/16 are set aside for RFC2544 benchmarking (RFC5735). */
static struct ipv4_l3fwd_lpm_route ipv4_l3fwd_lpm_route_array[] = {
	{RTE_IPV4(198, 18, 0, 0), 24, 0},
	{RTE_IPV4(198, 18, 1, 0), 24, 1},
	{RTE_IPV4(198, 18, 2, 0), 24, 2},
	{RTE_IPV4(198, 18, 3, 0), 24, 3},
	{RTE_IPV4(198, 18, 4, 0), 24, 4},
	{RTE_IPV4(198, 18, 5, 0), 24, 5},
	{RTE_IPV4(198, 18, 6, 0), 24, 6},
	{RTE_IPV4(198, 18, 7, 0), 24, 7},
};

/* 2001:0200::/48 is IANA reserved range for IPv6 benchmarking (RFC5180) */
static struct ipv6_l3fwd_lpm_route ipv6_l3fwd_lpm_route_array[] = {
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 48, 0},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 48, 1},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0}, 48, 2},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0}, 48, 3},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0}, 48, 4},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0}, 48, 5},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0}, 48, 6},
	{{32, 1, 2, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0}, 48, 7},
};

#define IPV4_L3FWD_LPM_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_lpm_route_array) / sizeof(ipv4_l3fwd_lpm_route_array[0]))
#define IPV6_L3FWD_LPM_NUM_ROUTES \
	(sizeof(ipv6_l3fwd_lpm_route_array) / sizeof(ipv6_l3fwd_lpm_route_array[0]))

#define IPV4_L3FWD_LPM_MAX_RULES         1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 8)
#define IPV6_L3FWD_LPM_MAX_RULES         1024
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[NB_SOCKETS];
struct rte_lpm6 *ipv6_l3fwd_lpm_lookup_struct[NB_SOCKETS];

static inline uint16_t
lpm_get_ipv4_dst_port(void *ipv4_hdr, uint16_t portid, void *lookup_struct)
{
	uint32_t next_hop;
	struct rte_lpm *ipv4_l3fwd_lookup_struct =
		(struct rte_lpm *)lookup_struct;

	return (uint16_t) ((rte_lpm_lookup(ipv4_l3fwd_lookup_struct,
		rte_be_to_cpu_32(((struct rte_ipv4_hdr *)ipv4_hdr)->dst_addr),
		&next_hop) == 0) ? next_hop : portid);
}

static inline uint16_t
lpm_get_ipv6_dst_port(void *ipv6_hdr, uint16_t portid, void *lookup_struct)
{
	uint32_t next_hop;
	struct rte_lpm6 *ipv6_l3fwd_lookup_struct =
		(struct rte_lpm6 *)lookup_struct;

	return (uint16_t) ((rte_lpm6_lookup(ipv6_l3fwd_lookup_struct,
			((struct rte_ipv6_hdr *)ipv6_hdr)->dst_addr,
			&next_hop) == 0) ?  next_hop : portid);
}

static __rte_always_inline uint16_t
lpm_get_dst_port(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
		uint16_t portid)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		return lpm_get_ipv4_dst_port(ipv4_hdr, portid,
					     qconf->ipv4_lookup_struct);
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					     qconf->ipv6_lookup_struct);
	}

	return portid;
}

/*
 * lpm_get_dst_port optimized routine for packets where dst_ipv4 is already
 * precalculated. If packet is ipv6 dst_addr is taken directly from packet
 * header and dst_ipv4 value is not used.
 */
static __rte_always_inline uint16_t
lpm_get_dst_port_with_ipv4(const struct lcore_conf *qconf, struct rte_mbuf *pkt,
	uint32_t dst_ipv4, uint16_t portid)
{
	uint32_t next_hop;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		return (uint16_t) ((rte_lpm_lookup(qconf->ipv4_lookup_struct,
						   dst_ipv4, &next_hop) == 0)
				   ? next_hop : portid);

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {

		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
		ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);

		return (uint16_t) ((rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				ipv6_hdr->dst_addr, &next_hop) == 0)
				? next_hop : portid);

	}

	return portid;
}

#if defined(RTE_ARCH_X86)
#include "l3fwd_lpm_sse.h"
#elif defined RTE_MACHINE_CPUFLAG_NEON
#include "l3fwd_lpm_neon.h"
#elif defined(RTE_ARCH_PPC_64)
#include "l3fwd_lpm_altivec.h"
#else
#include "l3fwd_lpm.h"
#endif

/* main processing loop */
int
lpm_main_loop(__attribute__((unused)) void *dummy)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	int i, nb_rx;
	uint16_t portid;
	uint8_t queueid;
	struct lcore_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
		US_PER_S * BURST_TX_DRAIN_US;

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, L3FWD, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, L3FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {

		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, L3FWD,
			" -- lcoreid=%u portid=%u rxqueueid=%hhu\n",
			lcore_id, portid, queueid);
	}

	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_tx_port; ++i) {
				portid = qconf->tx_port_id[i];
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf,
					qconf->tx_mbufs[portid].len,
					portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
				MAX_PKT_BURST);
			if (nb_rx == 0)
				continue;

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON \
			 || defined RTE_ARCH_PPC_64
			l3fwd_lpm_send_packets(nb_rx, pkts_burst,
						portid, qconf);
#else
			l3fwd_lpm_no_opt_send_packets(nb_rx, pkts_burst,
							portid, qconf);
#endif /* X86 */
		}
	}

	return 0;
}

static __rte_always_inline void
lpm_event_loop_single(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	struct rte_event ev;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();
	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);
	while (!force_quit) {
		if (!rte_event_dequeue_burst(event_d_id, event_p_id, &ev, 1, 0))
			continue;

		struct rte_mbuf *mbuf = ev.mbuf;
		mbuf->port = lpm_get_dst_port(lconf, mbuf, mbuf->port);

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON \
				|| defined RTE_ARCH_PPC_64
		process_packet(mbuf, &mbuf->port);
#else

		struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf,
							struct rte_ether_hdr *);
#ifdef DO_RFC_1812_CHECKS
		struct rte_ipv4_hdr *ipv4_hdr;
		if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type)) {
			/* Handle IPv4 headers.*/
			ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
					struct rte_ipv4_hdr *,
					sizeof(struct rte_ether_hdr));

			if (is_valid_ipv4_pkt(ipv4_hdr, mbuf->pkt_len)
					< 0) {
				mbuf->port = BAD_PORT;
				continue;
			}
			/* Update time to live and header checksum */
			--(ipv4_hdr->time_to_live);
			++(ipv4_hdr->hdr_checksum);
		}
#endif
		/* dst addr */
		*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[mbuf->port];

		/* src addr */
		rte_ether_addr_copy(&ports_eth_addr[mbuf->port],
				&eth_hdr->s_addr);
#endif
		if (mbuf->port == BAD_PORT) {
			rte_pktmbuf_free(mbuf);
			continue;
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			ev.queue_id = tx_q_id;
			ev.op = RTE_EVENT_OP_FORWARD;
			while (rte_event_enqueue_burst(event_d_id, event_p_id,
						&ev, 1) && !force_quit)
				;
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			rte_event_eth_tx_adapter_txq_set(mbuf, 0);
			while (!rte_event_eth_tx_adapter_enqueue(event_d_id,
						event_p_id, &ev, 1, 0) &&
					!force_quit)
				;
		}
	}
}

static __rte_always_inline void
lpm_event_loop_burst(struct l3fwd_event_resources *evt_rsrc,
		const uint8_t flags)
{
	const int event_p_id = l3fwd_get_free_event_port(evt_rsrc);
	const uint8_t tx_q_id = evt_rsrc->evq.event_q_id[
		evt_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	const uint16_t deq_len = evt_rsrc->deq_depth;
	struct rte_event events[MAX_PKT_BURST];
	struct lcore_conf *lconf;
	unsigned int lcore_id;
	int i, nb_enq, nb_deq;

	if (event_p_id < 0)
		return;

	lcore_id = rte_lcore_id();

	lconf = &lcore_conf[lcore_id];

	RTE_LOG(INFO, L3FWD, "entering %s on lcore %u\n", __func__, lcore_id);

	while (!force_quit) {
		/* Read events from RX queues */
		nb_deq = rte_event_dequeue_burst(event_d_id, event_p_id,
				events, deq_len, 0);
		if (nb_deq == 0) {
			rte_pause();
			continue;
		}

		for (i = 0; i < nb_deq; i++) {
			struct rte_mbuf *mbuf = events[i].mbuf;

			mbuf->port = lpm_get_dst_port(lconf, mbuf, mbuf->port);

#if defined RTE_ARCH_X86 || defined RTE_MACHINE_CPUFLAG_NEON \
					|| defined RTE_ARCH_PPC_64
			process_packet(mbuf, &mbuf->port);
#else
			struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf,
						struct rte_ether_hdr *);

#ifdef DO_RFC_1812_CHECKS
			struct rte_ipv4_hdr *ipv4_hdr;
			if (RTE_ETH_IS_IPV4_HDR(mbuf->packet_type)) {
				/* Handle IPv4 headers.*/
				ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf,
						struct rte_ipv4_hdr *,
						sizeof(struct rte_ether_hdr));

				if (is_valid_ipv4_pkt(ipv4_hdr, mbuf->pkt_len)
						< 0) {
					mbuf->port = BAD_PORT;
					continue;
				}
				/* Update time to live and header checksum */
				--(ipv4_hdr->time_to_live);
				++(ipv4_hdr->hdr_checksum);
			}
#endif
			/* dst addr */
			*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[
								mbuf->port];
			/* src addr */
			rte_ether_addr_copy(&ports_eth_addr[mbuf->port],
					&eth_hdr->s_addr);
#endif
			if (flags & L3FWD_EVENT_TX_ENQ) {
				events[i].queue_id = tx_q_id;
				events[i].op = RTE_EVENT_OP_FORWARD;
			}

			if (flags & L3FWD_EVENT_TX_DIRECT)
				rte_event_eth_tx_adapter_txq_set(mbuf, 0);
		}

		if (flags & L3FWD_EVENT_TX_ENQ) {
			nb_enq = rte_event_enqueue_burst(event_d_id, event_p_id,
					events, nb_deq);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_enqueue_burst(event_d_id,
						event_p_id, events + nb_enq,
						nb_deq - nb_enq);
		}

		if (flags & L3FWD_EVENT_TX_DIRECT) {
			nb_enq = rte_event_eth_tx_adapter_enqueue(event_d_id,
					event_p_id, events, nb_deq, 0);
			while (nb_enq < nb_deq && !force_quit)
				nb_enq += rte_event_eth_tx_adapter_enqueue(
						event_d_id, event_p_id,
						events + nb_enq,
						nb_deq - nb_enq, 0);
		}
	}
}

static __rte_always_inline void
lpm_event_loop(struct l3fwd_event_resources *evt_rsrc,
		 const uint8_t flags)
{
	if (flags & L3FWD_EVENT_SINGLE)
		lpm_event_loop_single(evt_rsrc, flags);
	if (flags & L3FWD_EVENT_BURST)
		lpm_event_loop_burst(evt_rsrc, flags);
}

int __rte_noinline
lpm_event_main_loop_tx_d(__attribute__((unused)) void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_d_burst(__attribute__((unused)) void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_DIRECT | L3FWD_EVENT_BURST);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q(__attribute__((unused)) void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_SINGLE);
	return 0;
}

int __rte_noinline
lpm_event_main_loop_tx_q_burst(__attribute__((unused)) void *dummy)
{
	struct l3fwd_event_resources *evt_rsrc =
					l3fwd_get_eventdev_rsrc();

	lpm_event_loop(evt_rsrc, L3FWD_EVENT_TX_ENQ | L3FWD_EVENT_BURST);
	return 0;
}

void
setup_lpm(const int socketid)
{
	struct rte_lpm6_config config;
	struct rte_lpm_config config_ipv4;
	unsigned i;
	int ret;
	char s[64];
	char abuf[INET6_ADDRSTRLEN];

	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {
		struct in_addr in;

		/* skip unused ports */
		if ((1 << ipv4_l3fwd_lpm_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid],
			ipv4_l3fwd_lpm_route_array[i].ip,
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		in.s_addr = htonl(ipv4_l3fwd_lpm_route_array[i].ip);
		printf("LPM: Adding route %s / %d (%d)\n",
		       inet_ntop(AF_INET, &in, abuf, sizeof(abuf)),
			ipv4_l3fwd_lpm_route_array[i].depth,
			ipv4_l3fwd_lpm_route_array[i].if_out);
	}

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config.flags = 0;
	ipv6_l3fwd_lpm_lookup_struct[socketid] = rte_lpm6_create(s, socketid,
				&config);
	if (ipv6_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);

	/* populate the LPM table */
	for (i = 0; i < IPV6_L3FWD_LPM_NUM_ROUTES; i++) {

		/* skip unused ports */
		if ((1 << ipv6_l3fwd_lpm_route_array[i].if_out &
				enabled_port_mask) == 0)
			continue;

		ret = rte_lpm6_add(ipv6_l3fwd_lpm_lookup_struct[socketid],
			ipv6_l3fwd_lpm_route_array[i].ip,
			ipv6_l3fwd_lpm_route_array[i].depth,
			ipv6_l3fwd_lpm_route_array[i].if_out);

		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
				i, socketid);
		}

		printf("LPM: Adding route %s / %d (%d)\n",
		       inet_ntop(AF_INET6, ipv6_l3fwd_lpm_route_array[i].ip,
				 abuf, sizeof(abuf)),
		       ipv6_l3fwd_lpm_route_array[i].depth,
		       ipv6_l3fwd_lpm_route_array[i].if_out);
	}
}

int
lpm_check_ptype(int portid)
{
	int i, ret;
	int ptype_l3_ipv4 = 0, ptype_l3_ipv6 = 0;
	uint32_t ptype_mask = RTE_PTYPE_L3_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return 0;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		if (ptypes[i] & RTE_PTYPE_L3_IPV4)
			ptype_l3_ipv4 = 1;
		if (ptypes[i] & RTE_PTYPE_L3_IPV6)
			ptype_l3_ipv6 = 1;
	}

	if (ptype_l3_ipv4 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV4\n", portid);

	if (ptype_l3_ipv6 == 0)
		printf("port %d cannot parse RTE_PTYPE_L3_IPV6\n", portid);

	if (ptype_l3_ipv4 && ptype_l3_ipv6)
		return 1;

	return 0;

}

static inline void
lpm_parse_ptype(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;
	uint32_t packet_type = RTE_PTYPE_UNKNOWN;
	uint16_t ether_type;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = eth_hdr->ether_type;
	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
	else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6))
		packet_type |= RTE_PTYPE_L3_IPV6_EXT_UNKNOWN;

	m->packet_type = packet_type;
}

uint16_t
lpm_cb_parse_ptype(uint16_t port __rte_unused, uint16_t queue __rte_unused,
		   struct rte_mbuf *pkts[], uint16_t nb_pkts,
		   uint16_t max_pkts __rte_unused,
		   void *user_param __rte_unused)
{
	unsigned int i;

	if (unlikely(nb_pkts == 0))
		return nb_pkts;
	rte_prefetch0(rte_pktmbuf_mtod(pkts[0], struct ether_hdr *));
	for (i = 0; i < (unsigned int) (nb_pkts - 1); ++i) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i+1],
			struct ether_hdr *));
		lpm_parse_ptype(pkts[i]);
	}
	lpm_parse_ptype(pkts[i]);

	return nb_pkts;
}

/* Return ipv4/ipv6 lpm fwd lookup struct. */
void *
lpm_get_ipv4_l3fwd_lookup_struct(const int socketid)
{
	return ipv4_l3fwd_lpm_lookup_struct[socketid];
}

void *
lpm_get_ipv6_l3fwd_lookup_struct(const int socketid)
{
	return ipv6_l3fwd_lpm_lookup_struct[socketid];
}
