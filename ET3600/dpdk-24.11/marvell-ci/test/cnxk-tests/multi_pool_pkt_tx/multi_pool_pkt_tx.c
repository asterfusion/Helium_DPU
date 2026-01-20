/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_log.h>

#define SRC_IP_ADDR	     ((198U << 24) | (18 << 16) | (0 << 8) | 1)
#define DST_IP_ADDR	     ((198U << 24) | (18 << 16) | (0 << 8) | 2)
#define SRC_UDP_PORT	     9
#define DST_UDP_PORT	     9
#define MAX_NUM_LCORE	     24
#define SEG_LEN		     64
#define MAX_PKT_BURST	     32
#define MEMPOOL_CACHE_SIZE   256
#define PRINT_DELAY_MS	     1000
#define MTU		     8192
#define MAX_TX_BURST_RETRIES 64
#define NUM_FLOWS	     100
#define NUM_SEGS	     6

#define ERROR(...)                                                             \
	do {                                                                   \
		keep_running = false;                                          \
		rte_mb();                                                      \
		rte_log(RTE_LOG_ERR, RTE_LOGTYPE_USER1, __VA_ARGS__);          \
	} while (0)

#define NOTICE(...) rte_log(RTE_LOG_NOTICE, RTE_LOGTYPE_USER1, __VA_ARGS__)
#define EXIT(...)   rte_exit(EXIT_FAILURE, __VA_ARGS__)

static bool keep_running = true;

struct app_arg {
	bool tx_mode;
	unsigned int n_queue;
	unsigned int n_desc;
	unsigned int max_pkts;
	unsigned int num_segs;
	unsigned int multi_pool;
};

struct queue_info {
	unsigned int lcore;
	uint64_t pkts;
	uint64_t last_count;
	uint64_t dropped;
	unsigned int num_segs;
} __rte_cache_aligned;

struct packet_header {
	struct rte_ether_hdr ether;
	struct rte_ipv4_hdr ipv4;
	struct rte_udp_hdr udp;
} __rte_packed;

struct port_info {
	struct queue_info qinfo[MAX_NUM_LCORE];
	unsigned int portid;
	unsigned int n_queue;
	unsigned int nb_mbufs_per_pool;
	struct rte_mempool *pool[NUM_SEGS];
	uint64_t last_count;
	uint64_t max_pps;
} __rte_cache_aligned;

struct thread_info {
	struct port_info *pinfo;
	unsigned int qid;
	bool *keep_runnig;
	struct app_arg *arg;
	unsigned int lcore;
	bool launched;
} __rte_cache_aligned;

static void
print_stats(struct port_info *pinfo, unsigned int n_port, struct app_arg *arg,
	    bool show_pps)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	uint64_t pps, pkts, dropped;
	unsigned int p, q;

	NOTICE("%s%s", clr, topLeft);
	NOTICE("\n==============================================");
	NOTICE("\nStatistics");
	if (arg->tx_mode)
		NOTICE("\n(Nqueues = %u, Multipool=%u)", arg->n_queue,
		       arg->multi_pool);
	else
		NOTICE("\n(Nqueues = %u)", arg->n_queue);
	NOTICE("\n==============================================");
	for (p = 0; p < n_port; p++) {
		struct port_info *ptr = &pinfo[p];

		pkts = 0;
		dropped = 0;
		NOTICE("\nPort %u", p);
		NOTICE("\n----------------------------------------------");
		for (q = 0; q < arg->n_queue; q++) {
			pkts += ptr->qinfo[q].pkts;
			dropped += ptr->qinfo[q].dropped;
			pps = (ptr->qinfo[q].pkts - ptr->qinfo[q].last_count);
			pps = (pps * 1000) / PRINT_DELAY_MS;
			if (show_pps) {
				if (arg->tx_mode)
					NOTICE("\nQueue %02u PPS (nseg=%u)         %16"PRIu64,
					       q, ptr->qinfo[q].num_segs, pps);
				else
					NOTICE("\nQueue %02u PPS                  %16"PRIu64,
					       q, pps);
			}
			ptr->qinfo[q].last_count = ptr->qinfo[q].pkts;
		}

		pps = ((pkts - ptr->last_count) * 1000) / PRINT_DELAY_MS;
		ptr->last_count = pkts;
		if (pps > ptr->max_pps)
			ptr->max_pps = pps;

		if (show_pps) {
			NOTICE("\nCombined PPS                  %16"PRIu64, pps);
			NOTICE("\n----------------------------------------------");
		}
		NOTICE("\nMaximum PPS                   %16"PRIu64
		       "\nTotal %s Pkts                 %16"PRIu64
		       "\nTotal Dropped Pkts            %16"PRIu64,
		       ptr->max_pps, arg->tx_mode ? "TX" : "RX", pkts, dropped);
	}
	NOTICE("\n==============================================\n");
	fflush(stdout);
}

static void
setup_packet(struct packet_header *hdr, uint32_t pkt_len, unsigned int portid,
	     unsigned int flow)
{
	uint16_t len;

	memset(hdr, 0, sizeof(struct packet_header));

	len = (uint16_t)(pkt_len -
			 sizeof(struct rte_ether_hdr) -
			 sizeof(struct rte_ipv4_hdr));
	hdr->udp.dgram_len = rte_cpu_to_be_16(len);
	hdr->udp.src_port = rte_cpu_to_be_16(SRC_UDP_PORT + flow);
	hdr->udp.dst_port = rte_cpu_to_be_16(DST_UDP_PORT);

	len = (uint16_t)(len + sizeof(struct rte_ipv4_hdr));
	hdr->ipv4.version_ihl = RTE_IPV4_VHL_DEF;
	hdr->ipv4.time_to_live = 64;
	hdr->ipv4.next_proto_id = IPPROTO_UDP;
	hdr->ipv4.dst_addr = rte_cpu_to_be_32(DST_IP_ADDR);
	hdr->ipv4.src_addr = rte_cpu_to_be_32(SRC_IP_ADDR);
	hdr->ipv4.total_length = rte_cpu_to_be_16(len);
	hdr->ipv4.hdr_checksum = rte_ipv4_cksum(&hdr->ipv4);

	rte_eth_macaddr_get(portid, &hdr->ether.src_addr);
	hdr->ether.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
}

static void
initialize(struct port_info *pinfo, struct app_arg *arg)
{
	unsigned int q, portid, pool_id, npools;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_lconf;
	struct rte_eth_fc_conf fc_conf;
	uint16_t nb_txd, nb_rxd;
	char name[16];
	int ret;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = RTE_ETH_MQ_RX_NONE,
		},
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP,
			},
		},
	};

	portid = pinfo->portid;
	pinfo->n_queue = arg->n_queue;

	pinfo->nb_mbufs_per_pool = ((unsigned int)arg->n_desc + MAX_PKT_BURST +
				    MEMPOOL_CACHE_SIZE) * MAX_NUM_LCORE;

	/* Create the mbuf pools */
	npools = arg->multi_pool ? NUM_SEGS : 1;
	for (pool_id = 0; pool_id < npools; pool_id++) {
		snprintf(name, sizeof(name), "mbuf_pool_%u_%u", portid, pool_id);
		pinfo->pool[pool_id] =
			rte_pktmbuf_pool_create(name, pinfo->nb_mbufs_per_pool,
						MEMPOOL_CACHE_SIZE, 0, MTU,
						rte_socket_id());
		if (pinfo->pool[pool_id] == NULL)
			EXIT("Cannot init mbuf pool portid=%u poolid=%u\n",
			     portid, pool_id);

		/* Only one pool required in RX mode */
		if (!arg->tx_mode)
			break;
	}

	NOTICE("Initializing port %u... ", portid);

	ret = rte_eth_dev_info_get(portid, &dev_info);
	if (ret != 0)
		EXIT("Error during getting device (port %u) info: %s\n", portid,
		     strerror(-ret));

	port_lconf = port_conf;
	/* Enable Multi Seg */
	if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS))
		EXIT("Device doesn't support multi seg\n");
	port_lconf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	/* Disable Fast Free */
	port_lconf.txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the number of queues */
	ret = rte_eth_dev_configure(portid, arg->tx_mode ? 0 : pinfo->n_queue,
				    arg->tx_mode ? pinfo->n_queue : 0,
				    &port_lconf);
	if (ret < 0)
		EXIT("Cannot configure device: err=%d, port=%u\n", ret, portid);

	/* Turn off flow control */
	ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
	if (!ret) {
		fc_conf.mode = RTE_ETH_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
	}
	if (ret < 0)
		EXIT("Failed to turn off flow control\n");

	nb_txd = arg->tx_mode ? arg->n_desc : 0;
	nb_rxd = arg->tx_mode ? 0 : arg->n_desc;
	ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
	if (ret < 0)
		EXIT("Cannot adjust number of descs: err=%d, port=%u\n", ret,
		     portid);

	if (arg->tx_mode) {
		/* Initialize TX queue */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = port_lconf.txmode.offloads;
		for (q = 0; q < pinfo->n_queue; q++) {
			ret = rte_eth_tx_queue_setup(
				portid, q, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
			if (ret < 0)
				EXIT("Tx queue setup err=%d, port=%u\n", ret,
				     portid);
		}
	} else {
		/* Initialize RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_lconf.rxmode.offloads;
		for (q = 0; q < pinfo->n_queue; q++) {
			ret = rte_eth_rx_queue_setup(
				portid, q, nb_rxd,
				rte_eth_dev_socket_id(portid),
				&rxq_conf, pinfo->pool[0]);
			if (ret < 0)
				EXIT("Rx queue setup err=%d, port=%u\n", ret,
				     portid);
		}
	}

	/* Set MTU */
	ret = rte_eth_dev_set_mtu(portid, MTU);
	if (ret < 0)
		EXIT("Failed to set MTU\n");

	/* Start device */
	rte_eth_promiscuous_enable(portid);
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		EXIT("rte_eth_dev_start:err=%d, port=%u\n", ret, portid);

	NOTICE("done:\n");
	fflush(stdout);
}

static void
finalize(struct port_info *pinfo, struct app_arg *arg)
{
	unsigned int pool_id, npools;
	unsigned int portid;
	int ret;

	portid = pinfo->portid;

	/* Close port */
	NOTICE("Closing port %d...", portid);
	ret = rte_eth_dev_stop(portid);
	if (ret != 0)
		EXIT("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
	rte_eth_dev_close(portid);

	/* Free mempool */
	npools = arg->multi_pool ? NUM_SEGS : 1;
	for (pool_id = 0; pool_id < npools; pool_id++) {
		rte_mempool_free(pinfo->pool[pool_id]);
		if (!arg->tx_mode)
			break;
	}
}

static int
launch_lcore_rx(void *args)
{
	unsigned int lcore, portid, recd, qid;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct thread_info *tinfo = args;
	struct queue_info *qinfo;
	struct port_info *pinfo;

	rte_mb();
	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];
	NOTICE("Entering RX main loop on lcore %u portid=%u qid=%u\n", lcore,
	       portid, qid);
	fflush(stdout);

	while (keep_running) {
		recd = rte_eth_rx_burst(portid, qid, pkts_burst, MAX_PKT_BURST);
		qinfo->pkts += recd;

		rte_pktmbuf_free_bulk(pkts_burst, recd);
		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts)
			ERROR("Max Packets Reached\n");
	}

	return 0;
}

static int
launch_lcore_tx(void *args)
{
	struct rte_mempool *rand_pool[NUM_SEGS];
	struct rte_mbuf **m, **m_arr, **m_nxt;
	struct thread_info *tinfo = args;
	unsigned int lcore, portid, qid;
	unsigned int i, j, flow_id = 0;
	struct queue_info *qinfo;
	struct port_info *pinfo;
	unsigned int num_segs;
	int sent;

	rte_mb();

	lcore = rte_lcore_id();
	pinfo = tinfo->pinfo;
	portid = pinfo->portid;
	qid = tinfo->qid;
	qinfo = &pinfo->qinfo[qid];

	srand(time(NULL) * lcore);
	if (tinfo->arg->num_segs) {
		num_segs = tinfo->arg->num_segs;
	} else {
		/* Pick a random number of segments between 2 and NUM_SEGS */
		num_segs = ((unsigned int)rand() % (NUM_SEGS - 2));
		num_segs += 2;
	}
	qinfo->num_segs = num_segs;
	for (i = 0; i < num_segs; i++) {
		j = tinfo->arg->multi_pool ? (unsigned int)rand() % num_segs : 0;
		rand_pool[i] = pinfo->pool[j];
	}

	m_arr = malloc(num_segs * MAX_PKT_BURST * sizeof(struct rte_mbuf *));
	if (!m_arr) {
		ERROR("failed to allocate memory for mbuf pointers\n");
		return 0;
	}

	NOTICE("LCORE %u: Entering TX main loop on portid=%u qid=%u num_segs=%u\n", lcore,
	       portid, qid, num_segs);
	for (i = 0; i < num_segs; i++)
		NOTICE("LCORE %u: Segment %u Pool: %p\n", lcore, i, rand_pool[i]);
	fflush(stdout);

	while (keep_running) {

		for (i = 0; i < num_segs; i++) {
			m = &m_arr[i * MAX_PKT_BURST];
			if (rte_pktmbuf_alloc_bulk(rand_pool[i], m,
						   MAX_PKT_BURST)) {
				ERROR("Failed to alloc mbufs for seg %u\n", i);
				break;
			}
		}
		for (j = 0; j < MAX_PKT_BURST; j++) {
			m = &m_arr[0];
			m[j]->pkt_len = SEG_LEN * num_segs;
			m[j]->nb_segs = num_segs;
			/* Setup the mbuf chain */
			m_nxt = m;
			flow_id = (flow_id + 1) % NUM_FLOWS;
			setup_packet(
				RTE_PTR_ADD(m[j]->buf_addr, m[j]->data_off),
				SEG_LEN * num_segs, portid, flow_id);
			for (i = 0; i < num_segs; i++) {
				m = m_nxt;
				m[j]->data_len = SEG_LEN;
				m[j]->data_off = 0;
				if (i < num_segs - 1) {
					m_nxt = &m_arr[(i + 1) * MAX_PKT_BURST];
					m[j]->next = m_nxt[j];
				}
			}
			m[j]->next = NULL;
		}

		sent = rte_eth_tx_burst(portid, qid, &m_arr[0], MAX_PKT_BURST);
		if (unlikely(sent != MAX_PKT_BURST)) {
			int retry = 0;

			while (sent < MAX_PKT_BURST &&
			       retry < MAX_TX_BURST_RETRIES) {
				sent += rte_eth_tx_burst(portid, qid,
							 &m_arr[0] + sent,
							 MAX_PKT_BURST - sent);
				retry++;
			}
			if (sent != MAX_PKT_BURST) {
				rte_pktmbuf_free_bulk(&m_arr[0] + sent,
						      MAX_PKT_BURST - sent);
				qinfo->dropped += MAX_PKT_BURST - sent;
			}
		}
		qinfo->pkts += sent;
		if (tinfo->arg->max_pkts &&
		    qinfo->pkts >= tinfo->arg->max_pkts) {
			ERROR("Max packets reached\n");
			break;
		}
	}

	free(m_arr);
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
		ERROR("\n\nSignal %d received, preparing to exit..\n", signum);
}

static int
parse_args(int argc, char **argv, struct app_arg *arg)
{
	arg->tx_mode = true;
	arg->n_queue = 1;
	arg->n_desc = 1024;
	arg->max_pkts = 0;
	arg->num_segs = 0;
	arg->multi_pool = true;

	/* Parse Arguments */
	while (argc > 1) {
		if (strncmp(argv[1], "--rx", 4) == 0) {
			arg->tx_mode = false;
		} else if (strncmp(argv[1], "--nqueue", 8) == 0) {
			if (argc < 3)
				return -1;
			arg->n_queue = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else if (strncmp(argv[1], "--ndesc", 7) == 0) {
			if (argc < 3)
				return -1;
			arg->n_desc = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else if (strncmp(argv[1], "--max-pkts", 10) == 0) {
			if (argc < 3)
				return -1;
			arg->max_pkts = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
		} else if (strncmp(argv[1], "--num-segs", 10) == 0) {
			if (argc < 3)
				return -1;
			arg->num_segs = strtoul(argv[2], 0, 0);
			argv++;
			argc--;
			if (arg->num_segs > 6)
				return -1;
		} else if (strncmp(argv[1], "--no-multi-pool", 15) == 0) {
			arg->multi_pool = false;
		} else {
			return -1;
		}
		argv++;
		argc--;
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct port_info pinfo[RTE_MAX_ETHPORTS];
	struct thread_info tinfo[RTE_MAX_LCORE];
	struct queue_info qinfo[RTE_MAX_LCORE];
	unsigned int n_port, n_lcore, p, q, c;
	struct app_arg arg;
	int ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		EXIT("Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	memset(&tinfo, 0, sizeof(tinfo));
	memset(&qinfo, 0, sizeof(qinfo));
	memset(&pinfo, 0, sizeof(pinfo));
	memset(&arg, 0, sizeof(arg));

	if (parse_args(argc, argv, &arg))
		EXIT("Argument parsing failed\n");

	n_port = rte_eth_dev_count_avail();
	if (n_port == 0)
		EXIT("No Ethernet ports - bye\n");

	/* Check lcores */
	n_lcore = 0;
	RTE_LCORE_FOREACH_WORKER(c) {
		if (!rte_lcore_is_enabled(c))
			continue;
		tinfo[n_lcore].arg = &arg;
		tinfo[n_lcore].lcore = c;
		n_lcore++;
	}
	if (n_lcore < n_port * arg.n_queue)
		EXIT("Need at least %u lcores\n", n_port * arg.n_queue);

	/* Initialize the ports */
	n_port = 0;
	RTE_ETH_FOREACH_DEV(p) {
		pinfo[n_port].portid = p;
		initialize(&pinfo[n_port], &arg);
		n_port++;
	}

	/* Launch rx/tx threads per queue */
	for (p = 0; p < n_port; p++) {
		for (q = 0; q < arg.n_queue; q++) {
			lcore_function_t *f;

			if (arg.tx_mode)
				f = launch_lcore_tx;
			else
				f = launch_lcore_rx;

			c = p * arg.n_queue + q;
			tinfo[c].pinfo = &pinfo[p];
			tinfo[c].qid = q;
			ret = rte_eal_remote_launch(f, &tinfo[c],
						    tinfo[c].lcore);
			if (ret) {
				ERROR("Failed to launch thread\n");
				goto cleanup;
			}
			tinfo[c].launched = true;
		}
	}

	/* Periodically print the stats */
	while (keep_running) {
		rte_delay_ms(PRINT_DELAY_MS);
		rte_mb();
		print_stats(pinfo, n_port, &arg, true);
	}

cleanup:
	/* Wait for threads to exit out */
	for (p = 0; p < n_port; p++) {
		for (q = 0; q < arg.n_queue; q++) {
			c = p * arg.n_queue + q;
			if (!tinfo[c].launched)
				continue;
			if (rte_eal_wait_lcore(tinfo[c].lcore) < 0)
				EXIT("Failed waiting for completion\n");
		}
	}

	/* Finalize the ports */
	for (p = 0; p < n_port; p++)
		finalize(&pinfo[p], &arg);

	/* Print final stats */
	rte_mb();
	rte_eal_cleanup();
	print_stats(pinfo, n_port, &arg, false);

	return ret;
}
