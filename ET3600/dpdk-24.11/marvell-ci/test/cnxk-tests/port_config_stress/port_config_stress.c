/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025, Marvell
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <stdatomic.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_cycles.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_log.h>

#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE		512
#define TX_RING_SIZE		512
#define NUM_MBUFS		8191
#define MBUF_CACHE_SIZE		250
#define MAX_CONFIG_LOOPS	100
#define PKT_BURST_SIZE		32
#define NUM_QUEUES_PER_PORT	1
#define MAX_OFFLOAD		1024

struct lcore_params {
	uint16_t port_id;
	uint16_t queue_id;
};

static struct lcore_params lparams[RTE_MAX_LCORE];

static unsigned int lcore_id;
static uint16_t next_port;

static atomic_bool force_quit;
static atomic_bool control_stop;

static struct rte_mempool *mbuf_pool;

static uint16_t nb_ports;
static uint16_t portid;

static uint64_t current_rx_offload;
static uint64_t current_tx_offload;

static uint64_t rx_offloads[MAX_OFFLOAD];
static uint64_t tx_offloads[MAX_OFFLOAD];

volatile bool test_failed;

uint64_t rx_count;
uint64_t tx_count;

uint64_t common_rx_offloads[] = {
	RTE_ETH_RX_OFFLOAD_VLAN_STRIP,
	RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
	RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
	RTE_ETH_RX_OFFLOAD_TCP_CKSUM,
	RTE_ETH_RX_OFFLOAD_CHECKSUM,
	RTE_ETH_RX_OFFLOAD_KEEP_CRC,
	RTE_ETH_RX_OFFLOAD_RSS_HASH
};

uint64_t common_tx_offloads[] = {
	RTE_ETH_TX_OFFLOAD_VLAN_INSERT,
	RTE_ETH_TX_OFFLOAD_IPV4_CKSUM,
	RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
	RTE_ETH_TX_OFFLOAD_TCP_CKSUM,
	RTE_ETH_TX_OFFLOAD_MULTI_SEGS
};

static inline void
print_offloads(uint64_t rx, uint64_t tx)
{
	printf("  RX Offloads: ");
	if (rx == 0) {
		printf("None");
	} else {
		if (rx & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
			printf("VLAN_STRIP ");
		if (rx & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
			printf("IPV4_CKSUM ");
		if (rx & RTE_ETH_RX_OFFLOAD_UDP_CKSUM)
			printf("UDP_CKSUM ");
		if (rx & RTE_ETH_RX_OFFLOAD_TCP_CKSUM)
			printf("TCP_CKSUM ");
		if (rx & RTE_ETH_RX_OFFLOAD_CHECKSUM)
			printf("CHECKSUM ");
		if (rx & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
			printf("KEEP_CRC ");
		if (rx & RTE_ETH_RX_OFFLOAD_RSS_HASH)
			printf("RSS_HASH ");
	}

	printf("\n  TX Offloads: ");
	if (tx == 0) {
		printf("None");
	} else {
		if (tx & RTE_ETH_TX_OFFLOAD_VLAN_INSERT)
			printf("VLAN_INSERT ");
		if (tx & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
			printf("IPV4_CKSUM ");
		if (tx & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
			printf("UDP_CKSUM ");
		if (tx & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
			printf("TCP_CKSUM ");
		if (tx & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
			printf("MULTI_SEGS ");
	}
	printf("\n");
}

static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	const uint16_t rx_rings = NUM_QUEUES_PER_PORT;
	const uint16_t tx_rings = NUM_QUEUES_PER_PORT;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_conf port_conf;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));
	port_conf.lpbk_mode = 1;
	port_conf.rxmode.offloads = current_rx_offload;
	port_conf.txmode.offloads = current_tx_offload;

	if (current_rx_offload & RTE_ETH_RX_OFFLOAD_RSS_HASH)
		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/*
	 * port_conf is passed to rte_eth_dev_configure() → applies offloads at device level
	 * txconf is passed to rte_eth_tx_queue_setup() → applies offloads at queue level
	 */

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;

	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;

	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
			":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
			addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM || signum == SIGABRT) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		atomic_store(&control_stop, true);
	}
}

static void
cleanup_port(uint16_t portid)
{
	printf("Stopping port %u...\n", portid);
	rte_eth_dev_stop(portid);
}

static void
cleanup_resources(void)
{
	atomic_store(&force_quit, true);
	rte_eal_mp_wait_lcore();

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
	}

	if (mbuf_pool != NULL) {
		rte_mempool_free(mbuf_pool);
		mbuf_pool = NULL;
	}

	rte_eal_cleanup();
}

static int
lcore_main_loop(void *arg)
{
	struct lcore_params *params = (struct lcore_params *)arg;
	const uint16_t port = params->port_id;
	const uint16_t queue = params->queue_id;
	struct rte_mbuf *bufs[PKT_BURST_SIZE];

	if (port_init(port, mbuf_pool) != 0) {
		printf("lcore %u failed to init port %u\n", rte_lcore_id(), port);
		test_failed = 1;
		return -1;
	}

	printf("lcore %u started (port=%u, queue=%u)\n", rte_lcore_id(), port, queue);

	while (!atomic_load(&force_quit)) {

		struct rte_mbuf *tx_buf = rte_pktmbuf_alloc(mbuf_pool);

		if (tx_buf) {
			char *pkt_data = rte_pktmbuf_mtod(tx_buf, char *);
			memset(pkt_data, 0xAB, 64);

			tx_buf->data_len = 64;
			tx_buf->pkt_len = 64;

			uint16_t nb_tx = rte_eth_tx_burst(port, queue, &tx_buf, 1);
			if (nb_tx == 0)
				rte_pktmbuf_free(tx_buf);
		}

		uint16_t nb_rx = rte_eth_rx_burst(port, queue, bufs, PKT_BURST_SIZE);

		if (nb_rx > 0) {
			uint16_t nb_tx = rte_eth_tx_burst(port, queue, bufs, nb_rx);

			if (nb_tx < nb_rx) {
				for (uint16_t i = nb_tx; i < nb_rx; i++)
					rte_pktmbuf_free(bufs[i]);
			}
		}
	}

	cleanup_port(port);
	printf("lcore %u exiting...\n", rte_lcore_id());
	return 0;
}

int
main(int argc, char **argv)
{
	struct timespec start_time, end_time;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_stats stats;
	uint64_t rx_capa, tx_capa;
	int ret;
	setvbuf(stdout, NULL, _IONBF, 0);
	clock_gettime(CLOCK_MONOTONIC, &start_time);

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	nb_ports = rte_eth_dev_count_avail();

	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No available Ethernet ports.\n");

	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
			NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Offloads are features that the NIC can do in hardware to reduce CPU work */
	/* They are represented as bitmasks (each feature is a single bit) */
	/* assume port 0 for capabilities */

	ret = rte_eth_dev_info_get(0, &dev_info);

	if (ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to get device info\n");
	rx_capa = dev_info.rx_offload_capa;
	tx_capa = dev_info.tx_offload_capa;

	/* Extract RX offload capabilities */
	for (size_t i = 0; i < RTE_DIM(common_rx_offloads); i++) {
		if ((rx_capa & common_rx_offloads[i]) && rx_count < MAX_OFFLOAD)
			rx_offloads[rx_count++] = common_rx_offloads[i];
	}

	/*  Filter supported TX offloads */
	for (size_t i = 0; i < RTE_DIM(common_tx_offloads); i++) {
		if ((tx_capa & common_tx_offloads[i]) && tx_count < MAX_OFFLOAD)
			tx_offloads[tx_count++] = common_tx_offloads[i];
	}

	for (int i = 0; i < MAX_CONFIG_LOOPS; i++) {
		if (atomic_load(&control_stop)) {
			printf("End signal received. Exiting early at loop %d...\n", i + 1);
			cleanup_resources();
			break;
		}

		if (test_failed) {
			printf("Error in previous iteration. Exiting at loop %d...\n", i + 1);
			cleanup_resources();
			break;
		}

		printf("\n=== Configuration loop %d ===\n", i + 1);

		if (rx_count > 0)
			current_rx_offload = rx_offloads[(i + 1) % rx_count];
		else {
			current_rx_offload = 0;
			printf("Warning: No RX offloads available, defaulting to 0\n");
		}

		if (tx_count > 0)
			current_tx_offload = tx_offloads[(i + 1) % tx_count];
		else {
			current_tx_offload = 0;
			printf("Warning: No TX offloads available, defaulting to 0\n");
		}

		print_offloads(current_rx_offload, current_tx_offload);

		next_port = 0;
		RTE_LCORE_FOREACH_WORKER(lcore_id) {
			if (next_port >= nb_ports)
				break;
			lparams[lcore_id].port_id = next_port;
			lparams[lcore_id].queue_id = 0;
			int rc = rte_eal_remote_launch(lcore_main_loop,
					&lparams[lcore_id], lcore_id);
			if (rc != 0) {
				printf("Failed to launch lcore %u (ret=%d)\n", lcore_id, rc);
				test_failed = 1;

			} else {
				printf("Launched lcore %u for port %u\n", lcore_id, next_port);
			}
			next_port++;
		}

		printf("Running traffic...\n");
		rte_delay_ms(500);

		atomic_store(&force_quit, true);
		rte_eal_mp_wait_lcore();
		atomic_store(&force_quit, false);

		RTE_ETH_FOREACH_DEV(portid) {
			if (rte_eth_stats_get(portid, &stats) == 0) {
				printf("Port %u stats:\n", portid);
				printf("  RX-packets: %" PRIu64 "\n", stats.ipackets);
				printf("  TX-packets: %" PRIu64 "\n", stats.opackets);
				printf("  RX-dropped: %" PRIu64 "\n", stats.imissed);
				printf("  TX-dropped: %" PRIu64 "\n", stats.oerrors);
				if (stats.ipackets == 0 || stats.opackets == 0) {
					printf("ERROR: No RX or TX packets on port %u\n", portid);
					test_failed = 1;
				}
			} else {
				printf("Failed to get stats for port %u\n", portid);
				test_failed = 1;
			}
			rte_eth_stats_reset(portid);
		}
	}

	printf("Bye...\n");
	cleanup_resources();

	clock_gettime(CLOCK_MONOTONIC, &end_time);
	double elapsed = (end_time.tv_sec - start_time.tv_sec) +
		(end_time.tv_nsec - start_time.tv_nsec) / 1e9;

	printf("Total execution time: %.3f seconds\n", elapsed);

	if (atomic_load(&control_stop))
		return 1;
	else if (test_failed) {
		printf("Test FAILED.\n");
		return 1;
	}

	printf("Test PASSED.\n");
	return 0;
}
