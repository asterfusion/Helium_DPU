/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_graph_worker.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_rcu_qsbr.h>
#include <rte_string_fns.h>
#include <rte_vect.h>
#include <rte_rawdev.h>
#include <rte_pmd_cnxk_emdev.h>
#include <spec/virtio.h>
#include <spec/virtio_net.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l2_node.h"

/* Log type */
#define RTE_LOGTYPE_VIRTIO_L2FWD RTE_LOGTYPE_USER1

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024

#define DEFAULT_QUEUES_PER_PORT 1

#define MAX_ETHDEV_RX_PER_LCORE 128
#define MAX_VIRTIO_RX_PER_LCORE 128

#define MAX_LCORE_PARAMS 1024

#define NB_SOCKETS 8

#define MAX_VFS_PER_EPF 3

#define APP_INFO(fmt, args...) RTE_LOG(INFO, VIRTIO_L2FWD, fmt, ##args)

#define APP_INFO_NH(fmt, args...) rte_log(RTE_LOG_INFO, RTE_LOGTYPE_VIRTIO_L2FWD, fmt, ##args)

#define APP_ERR(fmt, args...) RTE_LOG(ERR, VIRTIO_L2FWD, fmt, ##args)

#define DRV_NAME_LEN 14

#define CQ_NOTIF_QID 0ul

struct lcore_ethdev_rx {
	uint16_t portid;
	char node_name[RTE_NODE_NAMESIZE];
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	/* Tx can either be ethdev or virtio */
	struct l2_ethdev_tx_node_ctx *ethdev_tx;
	struct l2_emdev_enq_node_ctx *emdev_enq;
	uint16_t emdev_qid;
};

struct lcore_emdev_deq {
	uint16_t emdev_id;
	char node_name[RTE_NODE_NAMESIZE];
	struct l2_emdev_deq_node_ctx *emdev_deq;
	uint16_t emdev_qid;
};

/* Lcore conf */
struct lcore_conf {
	/* Fast path accessed */
	uint16_t nb_emdev_deq;
	struct lcore_emdev_deq emdev_deq[MAX_VIRTIO_RX_PER_LCORE];
	uint16_t nb_ethdev_rx;
	struct lcore_ethdev_rx ethdev_rx[MAX_ETHDEV_RX_PER_LCORE];
	uint32_t weight;

	struct rte_graph *graph;
	char name[RTE_GRAPH_NAMESIZE];
	rte_graph_t graph_id;
	struct rte_rcu_qsbr *qs_v;
} __rte_cache_aligned;

static uint64_t lcore_eth_mask[RTE_MAX_ETHPORTS];
static uint64_t lcore_emdev_mask[RTE_RAWDEV_MAX_DEVS];

/* virtio_devid->eth_port */
struct l2fwd_map {
	uint16_t id;
	uint16_t emdev_id;
#define ETHDEV_NEXT 1
#define VIRTIO_NEXT 2
	uint8_t type;
};

/* Static global variables used within this file. */
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static uint16_t lcore_list_wt_sorted[RTE_MAX_LCORE];

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

static bool enable_l4_csum; /**< Enable IPv4 checksum offload feature */
static int disable_tx_mseg; /**< disable default ethdev Tx multi-seg offload */
static int per_port_pool; /**< Use separate buffer pools per port; disabled */
			  /**< by default */

static volatile bool force_quit;

static struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* Mask of enabled ports */
static uint64_t port_mask_ena;
static uint16_t nb_ethdevs;
static uint64_t emdev_mask_ena = 0x1; /**< Mask of enabled emdevs */
static uint16_t nb_emdevs = 1;
static uint16_t nb_epfvfs = 1;
static uint16_t num_outb_queues = 17;
static uint16_t emdev_q_count[RTE_RAWDEV_MAX_DEVS];
static uint16_t nb_desc = 4096;
static uint16_t virtio_q_count[RTE_RAWDEV_MAX_DEVS][RTE_PMD_EMDEV_FUNCS_MAX];

/* Pcap trace */
static char pcap_filename[RTE_GRAPH_PCAP_FILE_SZ];
static uint64_t packet_to_capture = 1024;
static int pcap_trace_enable;
static uint32_t pktmbuf_count = 16 * 1024;

static struct l2fwd_map virtio_map[RTE_RAWDEV_MAX_DEVS][RTE_PMD_EMDEV_FUNCS_MAX];
static struct l2fwd_map eth_map[RTE_MAX_ETHPORTS];

static struct rte_eth_dev_info eth_dev_info[RTE_MAX_ETHPORTS];
static struct rte_eth_conf eth_dev_conf[RTE_MAX_ETHPORTS];
static uint16_t eth_dev_q_count[RTE_MAX_ETHPORTS];

static rte_node_t ethdev_rx_nodes[RTE_MAX_ETHPORTS];
static rte_node_t ethdev_tx_nodes[RTE_MAX_ETHPORTS];
static rte_node_t emdev_deq_nodes[RTE_RAWDEV_MAX_DEVS];
static rte_node_t emdev_enq_nodes[RTE_RAWDEV_MAX_DEVS];
static const char *emdev_deq_edge_names[RTE_RAWDEV_MAX_DEVS + RTE_MAX_ETHPORTS];
static uint16_t nb_emdev_deq_edges;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
		.offloads = RTE_ETH_TX_OFFLOAD_MULTI_SEGS,
	},
};

static int stats_enable;
static int verbose_stats;

static uint32_t max_pkt_len;
static int pool_buf_len = RTE_MBUF_DEFAULT_BUF_SIZE;

static struct rte_mempool *e_pktmbuf_pool[RTE_MAX_ETHPORTS];
static struct rte_mempool *v_pktmbuf_pool[RTE_RAWDEV_MAX_DEVS];

static uint16_t vnet_reta_sz[RTE_RAWDEV_MAX_DEVS][RTE_PMD_EMDEV_FUNCS_MAX];

static bool ethdev_cgx_loopback;

/* RCU QSBR variable */
static struct rte_rcu_qsbr *qs_v;

static const char **node_patterns;
static struct rte_graph_cluster_stats *graph_stats[RTE_MAX_LCORE];

static bool
is_ethdev_enabled(uint16_t portid)
{
	return port_mask_ena & RTE_BIT64(portid);
}

static bool
is_emdev_enabled(uint16_t devid)
{
	return emdev_mask_ena & RTE_BIT64(devid);
}

static bool
is_rawdev_emdev(uint16_t devid)
{
	struct rte_rawdev_info devinfo;
	uint8_t priv_info[512];

	memset(&devinfo, 0, sizeof(devinfo));
	devinfo.dev_private = priv_info;
	if (rte_rawdev_info_get(devid, &devinfo, sizeof(priv_info)) < 0)
		return false;

	if (strcmp(devinfo.driver_name, "raw_cnxk_emdev"))
		return false;

	return true;
}

static int
check_lcore_params(void)
{
	uint8_t lcore;
	uint16_t i;

	for (i = 0; i < RTE_MAX_ETHPORTS; ++i) {
		if (!is_ethdev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_eth_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}

	for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++) {
		if (!is_emdev_enabled(i))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_emdev_mask[i]))
				continue;

			if (!rte_lcore_is_enabled(lcore)) {
				APP_ERR("Error: lcore %hhu is not enabled in lcore mask\n", lcore);
				return -1;
			}

			if (lcore == rte_get_main_lcore()) {
				APP_ERR("Error: lcore %u is main lcore\n", lcore);
				return -1;
			}
		}
	}
	return 0;
}

static int
check_port_config(void)
{
	uint16_t portid;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; ++portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		if (!rte_eth_dev_is_valid_port(portid)) {
			APP_INFO("Port %u is not present on the board\n", portid);
			return -1;
		}
	}

	return 0;
}

static int
check_emdev_config(void)
{
	struct rte_rawdev_info devinfo;
	uint8_t priv_info[512];
	uint16_t devid;

	for (devid = 0; devid < RTE_RAWDEV_MAX_DEVS; ++devid) {
		if (!is_emdev_enabled(devid))
			continue;

		memset(&devinfo, 0, sizeof(devinfo));
		devinfo.dev_private = priv_info;
		if (rte_rawdev_info_get(devid, &devinfo, sizeof(priv_info)) < 0) {
			APP_INFO("rawdev %u is not present on the board\n", devid);
			return -1;
		}

		if (strcmp(devinfo.driver_name, "raw_cnxk_emdev")) {
			APP_INFO("rawdev %u is not a valid emdev\n", devid);
			return -1;
		}
	}
	return 0;
}

static const char *
virtio_dev_status_to_str(uint8_t status)
{
	switch (status) {
	case VIRTIO_DEV_RESET:
		return "VIRTIO_DEV_RESET";
	case VIRTIO_DEV_ACKNOWLEDGE:
		return "VIRTIO_DEV_ACKNOWLEDGE";
	case VIRTIO_DEV_DRIVER:
		return "VIRTIO_DEV_DRIVER";
	case VIRTIO_DEV_DRIVER_OK:
		return "VIRTIO_DEV_DRIVER_OK";
	case VIRTIO_DEV_FEATURES_OK:
		return "VIRTIO_DEV_FEATURES_OK";
	case VIRTIO_DEV_NEEDS_RESET:
		return "VIRTIO_DEV_NEEDS_RESET";
	case VIRTIO_DEV_FAILED:
		return "VIRTIO_DEV_FAILED";
	default:
		return "UNKNOWN_STATUS";
	};
	return NULL;
}

static int
init_lcore_ethdev_rx(void)
{
	uint16_t portid, nb_ethdev_rx;
	uint8_t lcore;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; ++portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_eth_mask[portid]))
				continue;

			nb_ethdev_rx = lcore_conf[lcore].nb_ethdev_rx;
			if (nb_ethdev_rx >= MAX_ETHDEV_RX_PER_LCORE) {
				APP_ERR("Error: too many ethdev rx (%u) for lcore: %u\n",
					(unsigned int)nb_ethdev_rx + 1, (unsigned int)lcore);
				return -1;
			}

			lcore_conf[lcore].ethdev_rx[nb_ethdev_rx].portid = portid;
			snprintf(lcore_conf[lcore].ethdev_rx[nb_ethdev_rx].node_name,
				 RTE_NODE_NAMESIZE, "l2_ethdev_rx-%u", portid);
			lcore_conf[lcore].nb_ethdev_rx++;
		}
	}

	/* Initialize lcore list */
	for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++)
		lcore_list_wt_sorted[lcore] = lcore;

	return 0;
}

static int
init_lcore_emdev_deq(void)
{
	uint16_t lcore, nb_emdev_deq, emdev_id, i, edge_id;
	struct lcore_conf *qconf;
	char node_name[RTE_NODE_NAMESIZE];

	/* Initialize emdev deq edges */
	snprintf(node_name, RTE_NODE_NAMESIZE, "%s", "pkt_drop");
	emdev_deq_edge_names[0] = strdup(node_name);
	if (!emdev_deq_edge_names[0]) {
		APP_ERR("Error: failed to allocate memory for emdev deq edge name\n");
		return -1;
	}
	nb_emdev_deq_edges++;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!is_ethdev_enabled(i))
			continue;

		edge_id = nb_emdev_deq_edges++;
		snprintf(node_name, RTE_NODE_NAMESIZE, "l2_ethdev_tx-%u", i);
		emdev_deq_edge_names[edge_id] = strdup(node_name);
		if (!emdev_deq_edge_names[edge_id]) {
			APP_ERR("Error: failed to allocate memory for emdev deq edge name\n");
			return -1;
		}
	}

	/* Equally distribute emdev queues among all the subscribed lcores */
	for (emdev_id = 0; emdev_id < RTE_RAWDEV_MAX_DEVS; emdev_id++) {
		if (!is_emdev_enabled(emdev_id))
			continue;

		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_emdev_mask[emdev_id]))
				continue;
			qconf = &lcore_conf[lcore];
			nb_emdev_deq = qconf->nb_emdev_deq;
			if (nb_emdev_deq >= MAX_VIRTIO_RX_PER_LCORE) {
				APP_ERR("Error: too many emdev deq (%u) for lcore: %u\n",
					(unsigned int)nb_emdev_deq + 1, (unsigned int)lcore);
				return -1;
			}
			qconf->emdev_deq[nb_emdev_deq].emdev_id = emdev_id;
			snprintf(qconf->emdev_deq[nb_emdev_deq].node_name, RTE_NODE_NAMESIZE,
				 "l2_emdev_deq-%d", emdev_id);
			qconf->nb_emdev_deq++;
		}

		edge_id = nb_emdev_deq_edges++;
		snprintf(node_name, RTE_NODE_NAMESIZE, "l2_emdev_enq-%d", emdev_id);
		emdev_deq_edge_names[edge_id] = strdup(node_name);
		if (!emdev_deq_edge_names[edge_id]) {
			APP_ERR("Error: failed to allocate memory for emdev deq edge name\n");
			return -1;
		}

	}

	return 0;
}

static int
assign_lcore_emdev_queues(void)
{
	uint16_t emdev_id, i, lcore;
	struct lcore_conf *qconf;
	bool need_emdev_q;

	for (emdev_id = 0; emdev_id < RTE_RAWDEV_MAX_DEVS; emdev_id++) {
		if (!is_emdev_enabled(emdev_id))
			continue;

		/* Assign emdev queue id to each lcore with first one for control core */
		emdev_q_count[emdev_id] = 1;
		for (lcore = 0; lcore < RTE_MAX_LCORE; lcore++) {
			if (!(RTE_BIT64(lcore) & lcore_emdev_mask[emdev_id]))
				continue;
			qconf = &lcore_conf[lcore];
			need_emdev_q = false;

			for (i = 0; i < qconf->nb_emdev_deq; i++) {
				if (qconf->emdev_deq[i].emdev_id != emdev_id)
					continue;
				qconf->emdev_deq[i].emdev_qid = emdev_q_count[emdev_id];
				need_emdev_q = true;
			}
			for (i = 0; i < qconf->nb_ethdev_rx; i++) {
				if (eth_map[qconf->ethdev_rx[i].portid].type != VIRTIO_NEXT)
					continue;
				if (eth_map[qconf->ethdev_rx[i].portid].emdev_id != emdev_id)
					continue;
				qconf->ethdev_rx[i].emdev_qid = emdev_q_count[emdev_id];
				need_emdev_q = true;
			}
			if (need_emdev_q)
				emdev_q_count[emdev_id]++;
		}
		if (emdev_q_count[emdev_id] > 8) {
			APP_ERR("Error: too many emdev queues (%u) for emdev: %u\n",
				(unsigned int)emdev_q_count[emdev_id], (unsigned int)emdev_id);
			return -1;
		}
	}

	return 0;
}

/* Display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] --"
		" -p PORTMASK"
		" -e EMDEV_MASK"
		" [-P]"
		" [-s]"
		" [-l]"
		" [--l2fwd-map (port,dev)[,(port,dev)]]"
		" [--max-pkt-len PKTLEN]"
		" [--pool-buf-len PKTLEN]"
		" [--per-port-pool]"
		" [--disable-tx-mseg]"
		" [--num-pkt-cap]"
		" [--enable-l4-csum]"
		" [--num-outb-queues]\n\n"

		"  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
		"  -e EMDEVMASK: Hexadecimal bitmask of emdevs to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -s : Enable stats. Giving it multiple times makes stats verbose.\n"
		"  -l : Enable CGX loopback\n"
		"  --eth-config (port,lcore_mask): Ethdev rx lcore mapping\n"
		"           Default is half of the found lcores would be mapped to all ethdevs\n"
		"  --emdev-config (dev,lcore_mask)[,(dev,lcore_mask)] : emdev deq lcore mapping\n"
		"           Default is half of the found lcores would be mapped to all emdev devs\n"
		"  --l2fwd-map (eX,VY.Z)[,(A,B.C)] : Ethdev Virtio map\n"
		"           X is ethdev port, Y is emdev id, Z is emdev func id\n"
		"           Default is (e0,v0.0),(e1,v0.1)... i.e ethdev 0 is mapped to virtio emdev 0 pf\n"
		"           ethdev 1 is mapped to virtio emdev 0 vf 0, etc\n"
		"  --max-pkt-len PKTLEN: maximum packet length in decimal (64-9600)\n"
		"  --pool-buf-len PKTLEN: maximum pool buffer length in decimal (64-9600)\n"
		"  --per-port-pool: Use separate buffer pool per port\n"
		"  --disable-tx-mseg: Disable ethdev Tx multi-seg offload capability\n"
		"  --pcap-enable: Enables pcap capture\n"
		"  --pcap-num-cap NUMPKT: Number of packets to capture\n"
		"  --pcap-file-name NAME: Pcap file name\n"
		"  --enable-l4-csum: Enable IPv4 L4 checksum offload capability\n"
		"  --num-outb-queues: Number of emdev outbound queues\n",
		prgname);
}

static uint64_t
parse_num_pkt_cap(const char *num_pkt_cap)
{
	uint64_t num_pkt;
	char *end = NULL;

	/* Parse decimal string */
	num_pkt = strtoull(num_pkt_cap, &end, 10);
	if ((num_pkt_cap[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	if (num_pkt == 0)
		return 0;

	return num_pkt;
}

static int
parse_max_pkt_len(const char *pktlen)
{
	unsigned long len;
	char *end = NULL;

	/* Parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static uint64_t
parse_uint(const char *str)
{
	char *end = NULL;
	unsigned long val;

	/* Parse hexadecimal string */
	val = strtoul(str, &end, 0);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return val;
}

static int
parse_eth_config(const char *q_arg)
{
	enum fieldnames { FLD_PORT = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_PORT] >= RTE_MAX_ETHPORTS ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid port/lcore mask\n");
			return -1;
		}

		lcore_eth_mask[int_fld[FLD_PORT]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

static int
parse_emdev_config(const char *q_arg)
{
	enum fieldnames { FLD_DEV = 0, FLD_LCORE_MASK, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	uint32_t size;
	char s[256];
	char *end;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i])
				return -1;
		}

		if (int_fld[FLD_DEV] >= RTE_RAWDEV_MAX_DEVS ||
		    int_fld[FLD_LCORE_MASK] >= RTE_BIT64(RTE_MAX_LCORE)) {
			APP_ERR("Invalid emdev/lcore mask\n");
			return -1;
		}

		lcore_emdev_mask[int_fld[FLD_DEV]] = int_fld[FLD_LCORE_MASK];
	}

	return 0;
}

static int
parse_l2fwd_map_config(const char *q_arg)
{
	enum fieldnames { FLD_PORTA = 0, FLD_PORTB, _NUM_FLD };
	uint16_t emdev_id = 0, func_id = 0;
	uint16_t emdev_id2 = 0, func_id2 = 0;
	unsigned long int_fld[_NUM_FLD][2];
	uint16_t portid, portid2;
	const char *p, *p0 = q_arg;
	char *str_fld[_NUM_FLD];
	char *end;
	char s[256];
	char *p2;
	uint32_t size;
	int i;

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		p0 = strchr(p, ')');
		if (p0 == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		memset(int_fld, 0, sizeof(int_fld));
		memcpy(s, p, size);
		s[size] = '\0';
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			p2 = strchr(str_fld[i], '.');
			if (p2 != NULL) {
				*p2 = '\0';
				int_fld[i][0] = strtoul(str_fld[i] + 1, &end, 0);
				int_fld[i][1] = strtoul(p2 + 1, &end, 0);
			} else {
				int_fld[i][0] = strtoul(str_fld[i] + 1, &end, 0);
			}
			if (errno != 0 || end == str_fld[i])
				return -1;
		}


		if (*str_fld[FLD_PORTA] == 'v') {
			emdev_id = int_fld[FLD_PORTA][0];
			func_id = int_fld[FLD_PORTA][1];
			if (*str_fld[FLD_PORTB] == 'v') {
				emdev_id2 = int_fld[FLD_PORTB][0];
				func_id2 = int_fld[FLD_PORTB][1];

				virtio_map[emdev_id][func_id].id = func_id2;
				virtio_map[emdev_id][func_id].emdev_id = emdev_id2;
				virtio_map[emdev_id][func_id].type = VIRTIO_NEXT;

				virtio_map[emdev_id2][func_id2].id = func_id;
				virtio_map[emdev_id2][func_id2].emdev_id = emdev_id;
				virtio_map[emdev_id2][func_id2].type = VIRTIO_NEXT;
			} else if (*str_fld[FLD_PORTB] == 'e') {
				portid = int_fld[FLD_PORTB][0];
				virtio_map[emdev_id][func_id].id = int_fld[FLD_PORTB][0];
				virtio_map[emdev_id][func_id].type = ETHDEV_NEXT;

				eth_map[portid].id = func_id;
				eth_map[portid].emdev_id = emdev_id;
				eth_map[portid].type = VIRTIO_NEXT;
			} else {
				APP_ERR("Invalid port type, not 'v' or 'e'\n");
				return -1;
			}
		} else if (*str_fld[FLD_PORTA] == 'e') {
			portid = int_fld[FLD_PORTA][0];
			if (*str_fld[FLD_PORTB] == 'v') {
				emdev_id = int_fld[FLD_PORTB][0];
				func_id = int_fld[FLD_PORTB][1];
				eth_map[portid].id = func_id;
				eth_map[portid].emdev_id = emdev_id;
				eth_map[portid].type = VIRTIO_NEXT;

				virtio_map[emdev_id][func_id].id = portid;
				virtio_map[emdev_id][func_id].type = ETHDEV_NEXT;
			} else if (*str_fld[FLD_PORTB] == 'e') {
				portid2 = int_fld[FLD_PORTB][0];
				eth_map[portid].id = portid2;
				eth_map[portid].type = ETHDEV_NEXT;

				eth_map[portid2].id = portid;
				eth_map[portid2].type = ETHDEV_NEXT;
			} else {
				APP_ERR("Invalid port type, not 'v' or 'e'\n");
				return -1;
			}
		} else {
			APP_ERR("Invalid port type, not 'v' or 'e'\n");
			return -1;
		}
	}

	return 0;
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 512

static const char short_options[] = "p:" /* portmask */
				    "e:" /* virt dev mask */
				    "d:" /* DMA flush threshold */
				    "P"  /* promiscuous */
				    "f"  /* Disable auto free */
				    "s"  /* stats enable */
				    "y:" /* Override DMA vfid */
				    "l"  /* Enable CGX loopback */
	;

#define CMD_LINE_OPT_ETH_CONFIG    "eth-config"
#define CMD_LINE_OPT_EMDEV_CONFIG "emdev-config"
#define CMD_LINE_OPT_L2FWD_MAP     "l2fwd-map"
#define CMD_LINE_OPT_MAX_PKT_LEN   "max-pkt-len"
#define CMD_LINE_OPT_MAX_BUF_LEN   "pool-buf-len"
#define CMD_LINE_OPT_PER_PORT_POOL "per-port-pool"
#define CMD_LINE_OPT_DIS_TX_MSEG   "disable-tx-mseg"
#define CMD_LINE_OPT_PCAP_ENABLE   "pcap-enable"
#define CMD_LINE_OPT_NUM_PKT_CAP   "pcap-num-cap"
#define CMD_LINE_OPT_PCAP_FILENAME "pcap-file-name"
#define CMD_LINE_OPT_ENA_L4_CSUM   "enable-l4-csum"
#define CMD_LINE_OPT_NUM_QUEUES    "num-outb-queues"
#define CMD_LINE_OPT_NUM_VFS       "num-emdev-vfs"
enum {
	/* Long options mapped to a short option */

	/* First long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ETH_CONFIG_NUM,
	CMD_LINE_OPT_EMDEV_CONFIG_NUM,
	CMD_LINE_OPT_L2FWD_MAP_NUM,
	CMD_LINE_OPT_MAX_PKT_LEN_NUM,
	CMD_LINE_OPT_MAX_BUF_LEN_NUM,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
	CMD_LINE_OPT_PARSE_DIS_TX_MSEG,
	CMD_LINE_OPT_PARSE_PCAP_ENABLE,
	CMD_LINE_OPT_PARSE_NUM_PKT_CAP,
	CMD_LINE_OPT_PCAP_FILENAME_CAP,
	CMD_LINE_OPT_PARSE_ENA_L4_CSUM,
	CMD_LINE_OPT_PARSE_NUM_QUEUES,
	CMD_LINE_OPT_PARSE_NUM_VFS,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ETH_CONFIG, 1, 0, CMD_LINE_OPT_ETH_CONFIG_NUM},
	{CMD_LINE_OPT_EMDEV_CONFIG, 1, 0, CMD_LINE_OPT_EMDEV_CONFIG_NUM},
	{CMD_LINE_OPT_L2FWD_MAP, 1, 0, CMD_LINE_OPT_L2FWD_MAP_NUM},
	{CMD_LINE_OPT_MAX_PKT_LEN, 1, 0, CMD_LINE_OPT_MAX_PKT_LEN_NUM},
	{CMD_LINE_OPT_MAX_BUF_LEN, 1, 0, CMD_LINE_OPT_MAX_BUF_LEN_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{CMD_LINE_OPT_DIS_TX_MSEG, 0, 0, CMD_LINE_OPT_PARSE_DIS_TX_MSEG},
	{CMD_LINE_OPT_PCAP_ENABLE, 0, 0, CMD_LINE_OPT_PARSE_PCAP_ENABLE},
	{CMD_LINE_OPT_NUM_PKT_CAP, 1, 0, CMD_LINE_OPT_PARSE_NUM_PKT_CAP},
	{CMD_LINE_OPT_PCAP_FILENAME, 1, 0, CMD_LINE_OPT_PCAP_FILENAME_CAP},
	{CMD_LINE_OPT_ENA_L4_CSUM, 0, 0, CMD_LINE_OPT_PARSE_ENA_L4_CSUM},
	{CMD_LINE_OPT_NUM_QUEUES, 1, 0, CMD_LINE_OPT_PARSE_NUM_QUEUES},
	{CMD_LINE_OPT_NUM_VFS, 1, 0, CMD_LINE_OPT_PARSE_NUM_VFS},
	{NULL, 0, 0, 0},
};

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	uint16_t portid, j, func_id, emdev_id;
	uint64_t emdev_mask_dflt = 0;
	uint64_t eth_mask_dflt = 0;
	char *prgname = argv[0];
	char *str;
	int option_index;
	char **argvopt;
	uint8_t lcore;
	int opt, rc;
	int i;

	/* Setup l2fwd map to defaults */
	emdev_id = 0;
	func_id = 0;
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		eth_map[portid].type = VIRTIO_NEXT;
		eth_map[portid].id = func_id;
		eth_map[portid].emdev_id = emdev_id;

		virtio_map[emdev_id][func_id].type = ETHDEV_NEXT;
		virtio_map[emdev_id][func_id].id = func_id;

		func_id++;
		if (func_id > MAX_VFS_PER_EPF) {
			func_id = 0;
			emdev_id++;
		}
	}

	/* Setup lcore mask of ethdev and virtio dev to default
	 * One for main lcore and rest divided
	 * among ethdev and virtio.
	 */

	j = 0;
	lcore = 0;
	for (; lcore < RTE_MAX_LCORE; lcore++) {
		if ((j == (rte_lcore_count() - 1) / 2) && rte_lcore_count() > 2)
			break;
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()))
			continue;

		eth_mask_dflt |= RTE_BIT64(lcore);
		j++;
	}

	j = 0;
	if (rte_lcore_count() <= 2)
		lcore = 0;

	for (; lcore < RTE_MAX_LCORE; lcore++) {
		if ((j == (rte_lcore_count() - 1) / 2) && rte_lcore_count() > 2)
			break;
		if (!rte_lcore_is_enabled(lcore) || (lcore == rte_get_main_lcore()))
			continue;

		emdev_mask_dflt |= RTE_BIT64(lcore);
		j++;
	}

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {
		switch (opt) {
		/* Portmask */
		case 'p':
			str = optarg;
			port_mask_ena = parse_uint(str);
			nb_ethdevs = __builtin_popcountl(port_mask_ena);
			if (nb_ethdevs < 1 || nb_ethdevs > RTE_MAX_ETHPORTS) {
				APP_ERR("Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'e':
			str = optarg;
			emdev_mask_ena = parse_uint(str);
			nb_emdevs = __builtin_popcountl(emdev_mask_ena);
			if (nb_emdevs < 1 || nb_emdevs > RTE_RAWDEV_MAX_DEVS) {
				APP_ERR("Invalid emdev mask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			promiscuous_on = 1;
			break;
		case 's':
			if (stats_enable)
				verbose_stats++;
			else
				stats_enable = 1;
			break;
		case 'l':
			ethdev_cgx_loopback = true;
			APP_INFO("Ethdev CGX loopback enabled\n");
			break;

		/* Long options */
		case CMD_LINE_OPT_ETH_CONFIG_NUM:
			rc = parse_eth_config(optarg);
			if (rc) {
				APP_ERR("Invalid eth config\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_EMDEV_CONFIG_NUM:
			rc = parse_emdev_config(optarg);
			if (rc) {
				APP_ERR("Invalid virt config\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_L2FWD_MAP_NUM:
			rc = parse_l2fwd_map_config(optarg);
			if (rc) {
				APP_ERR("Invalid eth config\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_MAX_PKT_LEN_NUM:
			max_pkt_len = parse_max_pkt_len(optarg);
			break;

		case CMD_LINE_OPT_MAX_BUF_LEN_NUM:
			pool_buf_len = parse_max_pkt_len(optarg);
			if (pool_buf_len == -1)
				pool_buf_len = RTE_MBUF_DEFAULT_BUF_SIZE;
			break;

		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			APP_INFO("Per port buffer pool is enabled\n");
			per_port_pool = 1;
			break;

		case CMD_LINE_OPT_PARSE_DIS_TX_MSEG:
			APP_INFO("Ethdev Tx multi-seg offload is disabled\n");
			disable_tx_mseg = 1;
			break;

		case CMD_LINE_OPT_PARSE_PCAP_ENABLE:
			APP_INFO("Packet capture enabled\n");
			pcap_trace_enable = 1;
			break;

		case CMD_LINE_OPT_PARSE_NUM_PKT_CAP:
			packet_to_capture = parse_num_pkt_cap(optarg);
			APP_INFO("Number of packets to capture: %" PRIu64 "\n", packet_to_capture);
			break;

		case CMD_LINE_OPT_PCAP_FILENAME_CAP:
			rte_strlcpy(pcap_filename, optarg, sizeof(pcap_filename));
			APP_INFO("Pcap file name: %s\n", pcap_filename);
			break;

		case CMD_LINE_OPT_PARSE_ENA_L4_CSUM:
			APP_INFO("IPv4 Checksum offload feature is enabled\n");
			enable_l4_csum = true;
			break;

		case CMD_LINE_OPT_PARSE_NUM_QUEUES:
			num_outb_queues = parse_uint(optarg);
			APP_INFO("Number of maximum outbound queues: %d\n", num_outb_queues);
			break;

		case CMD_LINE_OPT_PARSE_NUM_VFS:
			nb_epfvfs = parse_uint(optarg);
			APP_INFO("Number of vfs of a emdev: %d\n", nb_epfvfs);
			/* Include PF device also for virtio functioning */
			nb_epfvfs += 1;
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	rc = optind - 1;
	optind = 1; /* Reset getopt lib */

	if (!nb_ethdevs || !nb_emdevs) {
		APP_ERR("Need at least one port and emdev\n");
		return -1;
	}
	for (i = 0; i < RTE_MAX_ETHPORTS; i++)
		lcore_eth_mask[i] = eth_mask_dflt;

	for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++)
		lcore_emdev_mask[i] = emdev_mask_dflt;

	return rc;
}

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	APP_INFO_NH("%s%s", name, buf);
}

static int
init_eth_mempool(uint16_t portid, uint32_t nb_mbuf)
{
	char s[64];

	if (e_pktmbuf_pool[portid] == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool_e%d", portid);
		/* Create a pool with priv size of a cacheline */
		e_pktmbuf_pool[portid] =
			rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
						RTE_CACHE_LINE_SIZE, pool_buf_len, 0);
		if (e_pktmbuf_pool[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
		else
			APP_INFO("Allocated ethdev mbuf pool for portid=%d\n", portid);
	}

	return 0;
}

static int
init_emdev_mempool(uint16_t devid, uint32_t nb_mbuf)
{
	char s[64];

	if (v_pktmbuf_pool[devid] == NULL) {
		snprintf(s, sizeof(s), "mbuf_pool_v%d", devid);
		/* Create a pool with priv size of a cacheline */
		v_pktmbuf_pool[devid] =
			rte_pktmbuf_pool_create(s, nb_mbuf, MEMPOOL_CACHE_SIZE,
						RTE_CACHE_LINE_SIZE, pool_buf_len, 0);
		if (v_pktmbuf_pool[devid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
		else
			APP_INFO("Allocated virtio_dev mbuf pool for devid=%d\n", devid);
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;
	int rc;

	APP_INFO("\n");
	APP_INFO("Checking link status\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if (!is_ethdev_enabled(portid))
				continue;
			memset(&link, 0, sizeof(link));
			rc = rte_eth_link_get_nowait(portid, &link);
			if (rc < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					APP_ERR("Port %u link get failed: %s\n", portid,
						rte_strerror(-rc));
				continue;
			}
			/* Print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text, sizeof(link_status_text),
						    &link);
				APP_INFO("Port %d %s\n", portid, link_status_text);
				continue;
			}
			/* Clear all_ports_up flag if any link down */
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* After finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* Set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			APP_INFO("Done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	APP_INFO("\n");
	if (signum == SIGINT || signum == SIGTERM) {
		APP_INFO("Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void
sig_user1_handler(int signum)
{
	int i;

	APP_INFO("\n");
	if (signum == SIGUSR1) {
		APP_INFO("Signal %d received, dumping debug data...\n", signum);

		for (i = 0; i < RTE_RAWDEV_MAX_DEVS; i++) {
			if (!is_emdev_enabled(i))
				continue;
			rte_rawdev_dump(i, NULL);
		}

	}
}

static int
dump_emdev_queue_mapping(uint16_t emdev_id, uint16_t emdev_qid)
{
	struct rte_pmd_cnxk_func_q_map_attr q_map;
	uint16_t func_id, qid;

	for (func_id = 0; func_id < nb_epfvfs; func_id++) {
		for (qid = 0; qid < virtio_q_count[emdev_id][func_id]; qid++) {
			q_map.func_id = func_id;
			q_map.outb_qid = qid;
			if (rte_rawdev_get_attr(emdev_id, CNXK_EMDEV_ATTR_FUNC_Q_MAP,
						(uint64_t *)&q_map) < 0)
				return -1;
			if (emdev_qid != q_map.qid)
				continue;
			APP_INFO_NH("PFVF=%d VQ=%d ", func_id, qid);
		}
	}

	return 0;
}

static void
dump_lcore_info(void)
{
	struct l2_emdev_deq_node_ctx *emdev_deq;
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i, q_id;
	uint64_t map;

	APP_INFO("\n");
	APP_INFO("Lcore info...\n");
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0 || lcore_id == rte_get_main_lcore())
			continue;

		qconf = &lcore_conf[lcore_id];
		if (!qconf->nb_ethdev_rx && !qconf->nb_emdev_deq)
			continue;

		APP_INFO("\tVirtio queues on lcore %u ... ", lcore_id);
		for (i = 0; i < qconf->nb_emdev_deq; i++) {
			emdev_deq = qconf->emdev_deq[i].emdev_deq;
			APP_INFO_NH("emdev(%u, %u): ", emdev_deq->emdev_id, emdev_deq->emdev_qid);
			dump_emdev_queue_mapping(emdev_deq->emdev_id, emdev_deq->emdev_qid);
		}

		APP_INFO_NH("\n");
		APP_INFO("\tRx queues on lcore %u ... ", lcore_id);
		fflush(stdout);

		fflush(stdout);

		map = 0;
		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
			map = ethdev_rx->rx_q_map;
			q_id = 0;
			while (map) {
				if (map & 0x1)
					APP_INFO_NH("eth_rxq=%d,%d ", ethdev_rx->eth_port, q_id);
				q_id++;
				map = map >> 1;
			}
		}
		APP_INFO_NH("\n");
	}
	APP_INFO("\n");
}

static int
lcore_wt_cmp(const void *a, const void *b)
{
	uint16_t lcore_a = *(const uint16_t *)a;
	uint16_t lcore_b = *(const uint16_t *)b;

	if (lcore_conf[lcore_a].weight < lcore_conf[lcore_b].weight)
		return -1;

	if (lcore_conf[lcore_a].weight == lcore_conf[lcore_b].weight)
		return 0;

	return 1;
}

static int
setup_lcore_queue_mapping(uint16_t emdev_id, uint16_t func_id, uint16_t virt_q_count)
{
	struct rte_pmd_cnxk_func_q_map_attr q_map;
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	uint16_t i, outb_qid, emdev_qid, q_id;
	uint16_t nb_virtqs_per_notify_q;
	uint16_t virt_rx_q, eth_rx_q;
	struct lcore_conf *qconf;
	uint32_t lcore_id, idx;
	uint16_t nb_qs;

	virtio_q_count[emdev_id][func_id] = virt_q_count;
	/* One emdev queue is dedicated for Control queue */
	nb_qs = emdev_q_count[emdev_id] - 1;
	nb_virtqs_per_notify_q = (virt_q_count > nb_qs) ? virt_q_count / nb_qs : 1;
	outb_qid = 0;
	emdev_qid = 1;
	while (outb_qid < virt_q_count) {
		q_map.func_id = func_id;
		q_map.qid = emdev_qid;
		q_map.outb_qid = outb_qid;
		rte_rawdev_set_attr(emdev_id, CNXK_EMDEV_ATTR_FUNC_Q_MAP, (uint64_t)&q_map);
		outb_qid++;
		if (!(outb_qid % nb_virtqs_per_notify_q))
			emdev_qid++;
		if (emdev_qid > nb_qs)
			emdev_qid = 1;
	}

	virt_rx_q = virt_q_count / 2;
	eth_rx_q = (virtio_map[emdev_id][func_id].type == ETHDEV_NEXT) ? virt_rx_q : 0;

	/* Create a sorted lcore list based on its weight */
	qsort(lcore_list_wt_sorted, RTE_MAX_LCORE, sizeof(lcore_list_wt_sorted[0]), lcore_wt_cmp);
	/* Equally distribute ethdev rx queues among all the subscribed lcores */
	q_id = 0;
	while (q_id < eth_rx_q) {
		for (idx = 0; idx < RTE_MAX_LCORE && q_id < eth_rx_q; idx++) {
			lcore_id = lcore_list_wt_sorted[idx];
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			qconf = &lcore_conf[lcore_id];

			/* Skip Lcore if not needed */
			if (!qconf->nb_ethdev_rx)
				continue;

			for (i = 0; i < qconf->nb_ethdev_rx; i++) {
				/* Check for matching virtio devid */
				if (!qconf->ethdev_rx[i].emdev_enq ||
				    qconf->ethdev_rx[i].ethdev_rx->func_id != func_id)
					continue;

				ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
				/* Add queue to valid ethdev queue map */
				ethdev_rx->rx_q_map |= RTE_BIT64(q_id);
				ethdev_rx->rx_q_count++;
				/* Update lcore weight */
				qconf->weight++;
				q_id++;
				break;
			}
		}
		if (!q_id) {
			APP_INFO("Skipping ethdev rx for virtio (%u,%u), no lcore mapping found\n",
				 emdev_id, func_id);
			break;
		}
	}

	dump_lcore_info();
	return 0;
}

static void
clear_lcore_queue_mapping(uint16_t emdev_id, uint16_t func_id)
{
	struct l2_ethdev_rx_node_ctx *ethdev_rx;
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t i;

	RTE_SET_USED(emdev_id);
	RTE_SET_USED(func_id);

	virtio_q_count[emdev_id][func_id] = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_ethdev_rx)
			continue;

		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			/* Check for matching virtio devid */
			if (!qconf->ethdev_rx[i].emdev_enq ||
			    qconf->ethdev_rx[i].ethdev_rx->func_id != func_id)
				continue;

			/* Clear valid ethdev queue map */
			ethdev_rx = qconf->ethdev_rx[i].ethdev_rx;
			/* Update lcore weight */
			qconf->weight -= ethdev_rx->rx_q_count;
			ethdev_rx->rx_q_map = 0;
			ethdev_rx->rx_q_count = 0;
		}
	}
	rte_io_wmb();
	dump_lcore_info();
}

static int
reconfig_ethdev(uint16_t portid, uint16_t q_count)
{
	struct rte_eth_conf *local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t nb_rx_queue;
	uint32_t nb_tx_queue;
	uint16_t queueid;
	int rc;

	APP_INFO("Reconfiguring ethdev portid=%d with q_count=%u\n", portid, q_count);

	local_port_conf = &eth_dev_conf[portid];
	nb_rx_queue = q_count;
	nb_tx_queue = nb_rx_queue;
	rc = rte_eth_dev_stop(portid);
	if (rc != 0) {
		APP_ERR("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		return rc;
	}

	/* FIXME: Reset ethdev on every reconfigure to avoid corrupt rule */
	rc = rte_eth_dev_reset(portid);
	if (rc != 0) {
		APP_ERR("Failed to reset port %u: %s\n", portid, rte_strerror(-rc));
		return rc;
	}

	rc = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, local_port_conf);
	if (rc < 0) {
		APP_ERR("Cannot configure device: err=%d, port=%d\n", rc, portid);
		return rc;
	}

	rc = rte_eth_dev_info_get(portid, &dev_info);
	if (rc) {
		APP_ERR("Cannot get device info: port=%d\n", portid);
		return rc;
	}

	/* Setup Tx queues */
	for (queueid = 0; queueid < nb_tx_queue; queueid++) {
		txconf = &dev_info.default_txconf;
		txconf->offloads = local_port_conf->txmode.offloads;

		rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, 0, txconf);
		if (rc < 0) {
			APP_ERR("rte_eth_tx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	/* Setup RX queues */
	for (queueid = 0; queueid < nb_rx_queue; queueid++) {
		struct rte_eth_rxconf rxq_conf;

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		if (!per_port_pool)
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
						    e_pktmbuf_pool[0]);
		else
			rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
						    e_pktmbuf_pool[portid]);
		if (rc < 0) {
			APP_ERR("rte_eth_rx_queue_setup: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	eth_dev_q_count[portid] = q_count;

	rc = rte_eth_dev_start(portid);
	if (rc < 0) {
		APP_ERR("rte_eth_dev_start: err=%d, port=%d\n", rc, portid);
		return rc;
	}
	return 0;
}

#define VNET_RSS_RETA_SIZE 128
static int
rss_reta_configure(uint16_t emdev_id, uint16_t func_id, struct virtio_net_ctrl_rss *rss)
{
	struct rte_eth_rss_reta_entry64 reta_conf[VNET_RSS_RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE];
	struct rte_eth_conf *local_port_conf;
	uint16_t virt_q_count, portid;
	uint16_t reta_size;
	uint16_t next_q;
	uint32_t i;
	int rc;

	clear_lcore_queue_mapping(emdev_id, func_id);
	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);

	/* Get active virt queue count */
	virt_q_count = rss->max_tx_vq * 2;

	if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	    virt_q_count > (num_outb_queues - 1)) {
		APP_ERR("virtio_dev(%u,%u): invalid virt_q_count=%d\n", emdev_id, func_id,
			virt_q_count);
		return -EIO;
	}

	if (virtio_map[emdev_id][func_id].type != ETHDEV_NEXT)
		goto skip_eth_reconfig;

	portid = virtio_map[emdev_id][func_id].id;
	local_port_conf = &eth_dev_conf[portid];

	/* Reconfigure ethdev with required number of queues */
	rc = reconfig_ethdev(portid, virt_q_count / 2);
	if (rc)
		return rc;

	local_port_conf->rx_adv_conf.rss_conf.rss_key = NULL;
	memset(reta_conf, 0, sizeof(reta_conf));
	reta_size = vnet_reta_sz[emdev_id][func_id];

	for (i = 0; i < reta_size; i++)
		reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

	next_q = rss->indirection_table[0];
	for (i = 0; i < reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		if (eth_dev_info[portid].reta_size != reta_size &&
		    rss->indirection_table[i] != next_q) {
			APP_ERR("Found a non sequential RETA table, cannot work with"
				" mismatched reta table size (ethdev=%u, virtio=%u)\n",
				eth_dev_info[portid].reta_size, reta_size);
			APP_ERR("Please relaunch application with ethdev '%s' reta_size devarg"
			       " as %u.", rte_dev_name(eth_dev_info[portid].device),
			       vnet_reta_sz[emdev_id][func_id]);
			return -ENOTSUP;
		}
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	for (i = reta_size; i < eth_dev_info[portid].reta_size; i++) {
		uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
		uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

		reta_conf[reta_id].reta[reta_pos] = rss->indirection_table[i];
		next_q = rss->indirection_table[i] + 1;
		if (next_q >= virt_q_count / 2)
			next_q = 0;
	}

	rc = rte_eth_dev_rss_reta_update(portid, reta_conf, eth_dev_info[portid].reta_size);
	if (rc) {
		APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n",
			portid, rc);
		return rc;
	}

skip_eth_reconfig:
	rc = setup_lcore_queue_mapping(emdev_id, func_id, virt_q_count);
	if (rc)
		APP_ERR("virtio_dev(%u, %u): failed to setup lcore queue mapping, rc=%d\n",
			emdev_id, func_id, rc);
	return rc;
}

static int
mq_configure(uint16_t emdev_id, uint16_t func_id, uint16_t virt_q_count)
{
	struct rte_eth_rss_reta_entry64
		reta_conf[VIRTIO_NET_RSS_RETA_SIZE / RTE_ETH_RETA_GROUP_SIZE];
	uint16_t reta_size, i;
	uint16_t portid;
	int rc;

	clear_lcore_queue_mapping(emdev_id, func_id);
	/* Synchronize RCU */
	rte_rcu_qsbr_synchronize(qs_v, RTE_QSBR_THRID_INVALID);

	if (virt_q_count <= 0 || virt_q_count & 0x1 ||
	    virt_q_count >= num_outb_queues) {
		APP_ERR("virtio_dev(%u,%u): invalid virt_q_count=%d\n", emdev_id, func_id,
			virt_q_count);
		return -EIO;
	}
	/* Reconfigure ethdev with required number of queues */
	if (virtio_map[emdev_id][func_id].type == ETHDEV_NEXT) {
		portid = virtio_map[emdev_id][func_id].id;
		rc = reconfig_ethdev(virtio_map[emdev_id][func_id].id, virt_q_count / 2);
		if (rc)
			return rc;
		memset(reta_conf, 0, sizeof(reta_conf));
		reta_size = eth_dev_info[portid].reta_size;

		if (reta_size) {
			for (i = 0; i < reta_size; i++)
				reta_conf[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

			for (i = 0; i < reta_size; i++) {
				uint32_t reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
				uint32_t reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;

				reta_conf[reta_id].reta[reta_pos] = i % (virt_q_count / 2);
			}

			rc = rte_eth_dev_rss_reta_update(portid, reta_conf, reta_size);
			if (rc) {
				APP_ERR("Failed to update RSS reta table for portid=%d, rc=%d\n",
					portid, rc);
				return rc;
			}
		}
	}

	rc = setup_lcore_queue_mapping(emdev_id, func_id, virt_q_count);
	if (rc)
		APP_ERR("virtio_dev(%u,%u): failed to setup lcore queue mapping, rc=%d\n", emdev_id,
			func_id, rc);

	return rc;
}

static int
promisc_configure(uint16_t emdev_id, uint16_t func_id, uint8_t enable)
{
	if (enable)
		return rte_eth_promiscuous_enable(virtio_map[emdev_id][func_id].id);
	return rte_eth_promiscuous_disable(virtio_map[emdev_id][func_id].id);
}

static int
allmulti_configure(uint16_t emdev_id, uint16_t func_id, uint8_t enable)
{
	if (enable)
		return rte_eth_allmulticast_enable(virtio_map[emdev_id][func_id].id);
	return rte_eth_allmulticast_disable(virtio_map[emdev_id][func_id].id);
}

static int
virtio_ctrl_cmd_process(uint16_t emdev_id, struct rte_pmd_cnxk_emdev_event *event)
{
	struct virtio_net_ctrl *ctrl_cmd = (struct virtio_net_ctrl *)event->data;
	uint16_t nb_qps;
	int status = 0;

	APP_INFO("[dev %u] cq class: %u command: %u\n", event->func_id, ctrl_cmd->class,
		 ctrl_cmd->command);
	if (ctrl_cmd->class == VIRTIO_NET_CTRL_MQ) {
		switch (ctrl_cmd->command) {
		case VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET:
			nb_qps = *(uint16_t *)ctrl_cmd->data;
			status = mq_configure(emdev_id, event->func_id, nb_qps * 2);
			break;
		case VIRTIO_NET_CTRL_MQ_RSS_CONFIG:
			status = rss_reta_configure(emdev_id, event->func_id,
						    (void *)ctrl_cmd->data);
			break;
		default:
			APP_INFO("[dev %u] class:command=%u:%u  is not supported", event->func_id,
				 ctrl_cmd->class, ctrl_cmd->command);
			break;
		}
		return status;
	} else if (ctrl_cmd->class == VIRTIO_NET_CTRL_RX) {
		switch (ctrl_cmd->command) {
		case VIRTIO_NET_CTRL_RX_PROMISC:
			status = promisc_configure(emdev_id, event->func_id,
						   *(uint8_t *)ctrl_cmd->data);
			break;
		case VIRTIO_NET_CTRL_RX_ALLMULTI:
			status = allmulti_configure(emdev_id, event->func_id,
						    *(uint8_t *)ctrl_cmd->data);
			break;
		default:
			APP_INFO("[dev %u] class:command=%u:%u  is not supported", event->func_id,
				 ctrl_cmd->class, ctrl_cmd->command);
			break;
		}
		return status;
	}
	APP_INFO("[dev %u] class:command=%u:%u  is not supported\n", event->func_id,
		 ctrl_cmd->class, ctrl_cmd->command);

	return status;
}

static void
ctrl_cmd_dequeue(void)
{
	struct rte_pmd_cnxk_emdev_event *event;
	struct rte_rawdev_buf *buf;
	uint16_t emdev_id = 0;
	uint64_t context;
	uint16_t count;
	int status;

	/* Process control commands from all emdevs queue 0 */
	for (emdev_id = 0; emdev_id < rte_rawdev_count(); emdev_id++) {
		if (!is_emdev_enabled(emdev_id))
			continue;

		context = CQ_NOTIF_QID;
		/* Dequeue Control commands */
		count = rte_rawdev_dequeue_buffers(emdev_id, &buf, 1, (void *)context);
		if (!count)
			goto next;

		event = rte_pktmbuf_mtod((struct rte_mbuf *)buf, struct rte_pmd_cnxk_emdev_event *);

		status = virtio_ctrl_cmd_process(emdev_id, event);

		*((uint8_t *)event->data) = (status) ? VIRTIO_NET_ERR : VIRTIO_NET_OK;
		event->data_len = sizeof(uint8_t);

		context = (uint64_t)event->func_id << 8 | (uint64_t)event->qid << 16;
		count = rte_rawdev_enqueue_buffers(emdev_id, &buf, 1, (void *)context);
		if (count != 1)
			APP_ERR("Ctrl cmd ACK enqueue failed\n");
next:
		/* Call empty enqueue to flush Tx queues */
		context = CQ_NOTIF_QID;
		rte_rawdev_enqueue_buffers(emdev_id, NULL, 0, (void *)context);
	}
}

static void
print_stats(void)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	uint16_t lcore_id;
	int gstats_en;

	gstats_en = rte_graph_has_stats_feature();
	while (!force_quit) {
		if (gstats_en && stats_enable) {
			/* Clear screen and move to top left */
			printf("%s%s", clr, topLeft);
			if (verbose_stats != 2)
				rte_graph_cluster_stats_get(graph_stats[0], 0);
			for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
				/* Dump lcore graph stats */
				if (verbose_stats == 2 && graph_stats[lcore_id])
					rte_graph_cluster_stats_get(graph_stats[lcore_id], 0);
			}
		}
		ctrl_cmd_dequeue();
		rte_delay_ms(1E3);
	}
}

static int
graph_main_loop(void *conf)
{
	RTE_SET_USED(conf);
	struct rte_rcu_qsbr *qs_v;
	struct lcore_conf *qconf;
	struct rte_graph *graph;
	uint32_t lcore_id;

	RTE_SET_USED(conf);

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];
	qs_v = qconf->qs_v;
	graph = qconf->graph;

	if (!graph) {
		APP_INFO("Lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	/* Register this thread to rdaort quiescent state */
	rte_rcu_qsbr_thread_register(qs_v, lcore_id);
	rte_rcu_qsbr_thread_online(qs_v, lcore_id);

	APP_INFO("Entering graph main loop on lcore %u, %s(%p)\n", lcore_id, qconf->name, graph);

	while (likely(!force_quit)) {

		/* Walk through graph */
		rte_graph_walk(graph);

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(qs_v, lcore_id);
	}

	rte_rcu_qsbr_thread_offline(qs_v, lcore_id);
	rte_rcu_qsbr_thread_unregister(qs_v, lcore_id);
	return 0;
}

static uint32_t
eth_dev_get_overhead_len(uint32_t max_rx_pktlen, uint16_t max_mtu)
{
	uint32_t overhead_len;

	if (max_mtu != UINT16_MAX && max_rx_pktlen > max_mtu)
		overhead_len = max_rx_pktlen - max_mtu;
	else
		overhead_len = RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;

	return overhead_len;
}

static int
config_port_max_pkt_len(struct rte_eth_conf *conf, struct rte_eth_dev_info *dev_info)
{
	uint32_t overhead_len;

	if (max_pkt_len == 0)
		return 0;

	if (max_pkt_len < RTE_ETHER_MIN_LEN || max_pkt_len > MAX_JUMBO_PKT_LEN)
		return -1;

	overhead_len = eth_dev_get_overhead_len(dev_info->max_rx_pktlen, dev_info->max_mtu);
	conf->rxmode.mtu = max_pkt_len - overhead_len;

	if (conf->rxmode.mtu > RTE_ETHER_MTU)
		conf->txmode.offloads |= RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

	return 0;
}

static int
ethdev_reset(uint16_t portid)
{
	int rc = 0;

	rc = rte_eth_dev_stop(portid);
	if (rc != 0) {
		APP_ERR("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		return rc;
	}

	rc = rte_eth_dev_reset(portid);
	if (rc != 0)
		APP_ERR("Failed to reset port %u: %s\n", portid, rte_strerror(-rc));

	eth_dev_q_count[portid] = 0;

	return rc;
}

static int
virtio_dev_status_cb(uint16_t emdev_id, uint16_t func_id, uint8_t status)
{
	bool reset_ethdev = false;
	uint16_t virt_q_count = 2;
	int rc;

	APP_INFO("virtio_dev(%u,%u): status=%s\n", emdev_id, func_id,
		 virtio_dev_status_to_str(status));

	switch (status) {
	case VIRTIO_DEV_RESET:
	case VIRTIO_DEV_NEEDS_RESET:
		clear_lcore_queue_mapping(emdev_id, func_id);
		reset_ethdev = true;
		break;
	case VIRTIO_DEV_DRIVER_OK:

		rc = setup_lcore_queue_mapping(emdev_id, func_id, virt_q_count);
		if (rc)
			APP_ERR("virtio(%u,%u): failed to setup lcore queue mapping, rc=%d\n",
				emdev_id, func_id, rc);
		break;
	default:
		break;
	};

	/* After this point, all the core's see updated queue mapping */

	if (reset_ethdev && virtio_map[emdev_id][func_id].type == ETHDEV_NEXT) {
		/* First reset device */
		ethdev_reset(virtio_map[emdev_id][func_id].id);
		/* dump packet pool available count */
		if (per_port_pool)
			APP_ERR("Packet pool avial buff_cnt=%d\n",
				rte_mempool_avail_count(
					e_pktmbuf_pool[virtio_map[emdev_id][func_id].id]));
		else
			APP_ERR("Packet pool avial buff_cnt=%d\n",
				rte_mempool_avail_count(e_pktmbuf_pool[0]));
		/* Reconfigure ethdev with 1 queue */
		reconfig_ethdev(virtio_map[emdev_id][func_id].id, 1);
	}
	return 0;
}

static int
lsc_event_callback(uint16_t port_id, enum rte_eth_event_type type __rte_unused, void *param,
		   void *ret_param __rte_unused)
{
	struct rte_pmd_cnxk_vnet_link_info link_info;
	uint16_t emdev_id = (uint64_t)param >> 16;
	uint16_t func_id = (uint64_t)param & 0xFFFF;
	struct rte_eth_link eth_link;

	if (rte_eth_link_get(port_id, &eth_link))
		return -1;
	link_info.status = eth_link.link_status;
	link_info.speed = eth_link.link_speed;
	link_info.duplex = eth_link.link_duplex;
	link_info.func_id = func_id;

	rte_rawdev_set_attr(emdev_id, CNXK_EMDEV_ATTR_LINK_STATUS, (uint64_t)&link_info);

	return 0;
}

static void
setup_mempools(void)
{
	uint32_t emdev_id;
	uint16_t portid;
	int rc;

	/* Initialize all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid) {
		/* Skip ports that are not enabled */
		if (!is_ethdev_enabled(portid))
			continue;

		/* Init memory */
		if (!per_port_pool) {
			/* portid = 0; this is *not* signifying the first port,
			 * rather, it signifies that portid is ignored.
			 */
			rc = init_eth_mempool(0, pktmbuf_count);
		} else {
			rc = init_eth_mempool(portid, pktmbuf_count);
		}
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "init_eth_mempool() failed\n");
	}

	for (emdev_id = 0; emdev_id < RTE_RAWDEV_MAX_DEVS; emdev_id++) {
		if (!is_emdev_enabled(emdev_id))
			continue;

		if (!per_port_pool) {
			/* portid = 0; this is *not* signifying the first port,
			 * rather, it signifies that portid is ignored.
			 */
			rc = init_emdev_mempool(0, pktmbuf_count);
		} else {
			rc = init_emdev_mempool(emdev_id, pktmbuf_count);
		}
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "init_virtio_mempool() failed\n");
	}
}

static void
setup_eth_devices(void)
{
	struct rte_eth_rss_reta_entry64 reta_conf[4];
	struct rte_eth_conf local_port_conf;
	struct rte_node_register *node_reg;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint16_t queueid, i, portid;
	uint16_t nb_rx_queue;
	uint32_t nb_tx_queue;
	char name[32];
	int rc;

	APP_INFO("\n");

	RTE_ETH_FOREACH_DEV(portid) {
		const char *edge_name = name;

		local_port_conf = port_conf;

		/* Skip ports that are not enabled */
		if (!is_ethdev_enabled(portid)) {
			APP_INFO("Skipping disabled port %d\n", portid);
			continue;
		}

		/* Init port */
		APP_INFO("Initializing port %d ...", portid);
		fflush(stdout);

		if (rte_eth_dev_info_get(portid, &dev_info))
			rte_exit(EXIT_FAILURE, "rte_eth_dev_info_get() failed for port %d\n",
				 portid);
		eth_dev_info[portid] = dev_info;

		/* Setup ethdev with max Rx, Tx queues */
		if (eth_map[portid].type == VIRTIO_NEXT)
			nb_rx_queue = DEFAULT_QUEUES_PER_PORT;
		else
			nb_rx_queue = num_outb_queues / 2;

		nb_tx_queue = nb_rx_queue;
		eth_dev_q_count[portid] = nb_rx_queue;

		APP_INFO_NH("Creating queues: nb_rxq=%d nb_txq=%u... ", nb_rx_queue, nb_tx_queue);

		rc = config_port_max_pkt_len(&local_port_conf, &dev_info);
		if (rc != 0)
			rte_exit(EXIT_FAILURE, "Invalid max packet length: %u (port %u)\n",
				 max_pkt_len, portid);

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		if (disable_tx_mseg)
			local_port_conf.txmode.offloads &= ~RTE_ETH_TX_OFFLOAD_MULTI_SEGS;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
		    port_conf.rx_adv_conf.rss_conf.rss_hf) {
			APP_INFO("Port %u modified RSS hash function based on "
				 "hardware support,"
				 "requested:%#" PRIx64 " configured:%#" PRIx64 "\n",
				 portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
				 local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		/* Enable CGX loopback mode if needed */
		local_port_conf.lpbk_mode = !!ethdev_cgx_loopback;

		rc = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%d\n", rc,
				 portid);
		eth_dev_conf[portid] = local_port_conf;

		rc = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (rc < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n",
				 rc, portid);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		APP_INFO_NH("\n");

		/* Setup Tx queues */
		for (queueid = 0; queueid < nb_tx_queue; queueid++) {
			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;

			rc = rte_eth_tx_queue_setup(portid, queueid, nb_txd, 0, txconf);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_tx_queue_setup: err=%d, "
					 "port=%d\n",
					 rc, portid);
		}

		/* Setup RX queues */
		for (queueid = 0; queueid < nb_rx_queue; queueid++) {
			struct rte_eth_rxconf rxq_conf;

			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port_conf.rxmode.offloads;
			if (!per_port_pool)
				rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
							    e_pktmbuf_pool[0]);
			else
				rc = rte_eth_rx_queue_setup(portid, queueid, nb_rxd, 0, &rxq_conf,
							    e_pktmbuf_pool[portid]);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: err=%d, "
					 "port=%d\n",
					 rc, portid);
		}

		/* Setup all entries in RETA table to point to RQ 0.
		 * RETA table will get updated when number of queue count
		 * is available.
		 */
		if (dev_info.reta_size) {
			memset(reta_conf, 0, sizeof(reta_conf));
			for (i = 0; i < 4; i++)
				reta_conf[i].mask = UINT64_MAX;

			rc = rte_eth_dev_rss_reta_update(portid, reta_conf, dev_info.reta_size);
			if (rc < 0)
				rte_exit(EXIT_FAILURE,
					 "Failed to update reta table to RQ 0, rc=%d\n", rc);
		}

		/* Disable ptype extraction */
		rc = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "Failed to disable ptype parsing\n");

		/* Clone ethdev rx and tx nodes for this ethdev */
		snprintf(name, sizeof(name), "%u", portid);
		node_reg = l2_ethdev_rx_node_get();
		ethdev_rx_nodes[portid] = rte_node_clone(node_reg->id, name);

		node_reg = l2_ethdev_tx_node_get();
		ethdev_tx_nodes[portid] = rte_node_clone(node_reg->id, name);

		/* Update graph edge info */
		if (eth_map[portid].type == ETHDEV_NEXT) {
			snprintf(name, sizeof(name), "l2_ethdev_tx-%u", eth_map[portid].id);
			rte_node_edge_update(ethdev_rx_nodes[portid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		} else {
			snprintf(name, sizeof(name), "l2_emdev_enq-%u", eth_map[portid].emdev_id);
			rte_node_edge_update(ethdev_rx_nodes[portid], RTE_EDGE_ID_INVALID,
					     &edge_name, 1);
		}
	}

	APP_INFO("\n");
	/* Dump L2FWD map */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;
		if (eth_map[portid].type == ETHDEV_NEXT)
			APP_INFO("L2FWD_MAP: ethdev_rx[%u] =====> ethdev_tx[%u] (lcores 0x%lX)\n",
				 portid, eth_map[portid].id, lcore_eth_mask[portid]);
		else
			APP_INFO(
				"L2FWD_MAP: ethdev_rx[%u] ======> virtiodev_tx[%u] (lcores 0x%lX)\n",
				portid, eth_map[portid].id, lcore_eth_mask[portid]);
	}
}

static int
setup_em_devices(void)
{
	struct rte_pmd_cnxk_func_q_map_attr q_map;
	struct rte_pmd_cnxk_vnet_conf *vnet_conf;
	struct rte_pmd_cnxk_emdev_q_conf q_conf;
	struct rte_pmd_cnxk_emdev_conf conf;
	struct rte_rawdev_info rawdev_conf;
	struct rte_node_register *node_reg;
	uint16_t portid;
	uint64_t data;
	char name[32];
	int rc, i, j, func_id;
	int emdev_id = 0;

	for (emdev_id = 0; emdev_id < rte_rawdev_count(); emdev_id++) {
		if (is_rawdev_emdev(emdev_id) == false)
			continue;

		/* Skip emdevs that are not enabled */
		if (!is_emdev_enabled(emdev_id)) {
			APP_INFO("Skipping disabled emdev %d\n", emdev_id);
			continue;
		}

		APP_INFO("Initializing emdev %d ... qs=%u", emdev_id, emdev_q_count[emdev_id]);

		memset(&conf, 0, sizeof(struct rte_pmd_cnxk_emdev_conf));
		conf.num_emdev_queues = emdev_q_count[emdev_id];
		conf.max_outb_queues = num_outb_queues;
		conf.num_funcs = nb_epfvfs;
		conf.emdev_type = EMDEV_TYPE_VIRTIO_NET;
		conf.status_cb = virtio_dev_status_cb;
		if (!per_port_pool)
			conf.default_mp = v_pktmbuf_pool[0];
		else
			conf.default_mp = v_pktmbuf_pool[emdev_id];

		for (func_id = 0; func_id < nb_epfvfs; func_id++) {
			struct rte_eth_link eth_link;

			vnet_conf = &conf.vnet_conf[func_id];
			portid = virtio_map[emdev_id][func_id].id;

			if (!eth_dev_info[portid].reta_size)
				vnet_conf->reta_size = 0;
			else
				vnet_conf->reta_size = RTE_MAX(VIRTIO_NET_RSS_RETA_SIZE,
							       eth_dev_info[portid].reta_size);

			vnet_conf->hash_key_size = eth_dev_info[portid].hash_key_size;

			if (rte_eth_link_get(portid, &eth_link))
				rte_exit(EXIT_FAILURE,
					 "Error during getting device (port %u) link\n", portid);
			vnet_conf->link_info.status = eth_link.link_status;
			vnet_conf->link_info.speed = eth_link.link_speed;
			vnet_conf->link_info.duplex = eth_link.link_duplex;
			data = (uint64_t)func_id | (uint64_t)emdev_id << 16;
			/* Register link status change interrupt callback */
			rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_LSC,
						      lsc_event_callback,
						      (void *)data);
			/* Populate default mac address */
			rte_eth_macaddr_get(portid, (struct rte_ether_addr *)vnet_conf->mac);

			/* Save reta size for future use */
			vnet_reta_sz[emdev_id][func_id] = vnet_conf->reta_size;
		}

		rawdev_conf.dev_private = (rte_rawdev_obj_t)(&conf);
		rc = rte_rawdev_configure(emdev_id, &rawdev_conf, sizeof(conf));
		if (rc)
			rte_exit(EXIT_FAILURE, "Can't config cnxk emdev: err=%d, "
				 "dev=%u\n", rc, emdev_id);

		for (i = 0; i < nb_epfvfs; i++) {
			/* Initially set for 2 queues at least */
			for (j = 0; j < 2; j++) {
				q_map.func_id = i;
				q_map.qid = 1;
				q_map.outb_qid = j;
				rte_rawdev_set_attr(emdev_id, CNXK_EMDEV_ATTR_FUNC_Q_MAP,
						    (uint64_t)&q_map);
			}
		}
		q_conf.nb_desc = nb_desc;
		for (i = 0; i < emdev_q_count[emdev_id]; i++) {
			rc = rte_rawdev_queue_setup(emdev_id, i, &q_conf, sizeof(q_conf));
			if (rc < 0) {
				APP_ERR("Failed to setup queue %u.\n", i);
				goto exit;
			}
		}
		/* Clone rx and tx nodes for this emdev */
		snprintf(name, sizeof(name), "%u", emdev_id);
		node_reg = l2_emdev_deq_node_get();
		emdev_deq_nodes[emdev_id] = rte_node_clone(node_reg->id, name);

		node_reg = l2_emdev_enq_node_get();
		emdev_enq_nodes[emdev_id] = rte_node_clone(node_reg->id, name);

		/* Add all ethdev tx nodes to every emdev deq node */
		rte_node_edge_update(emdev_deq_nodes[emdev_id], 0, emdev_deq_edge_names,
				     nb_emdev_deq_edges);

		rc = rte_rawdev_start(emdev_id);
		if (rc) {
			APP_ERR("rte_rawdev_start: err=%d, dev=%u\n", rc, emdev_id);
			return rc;
		}
		APP_INFO_NH("done\n");

	}
	return 0;
exit:
	for (; emdev_id >= 0; emdev_id--) {
		if (!is_emdev_enabled(emdev_id))
			continue;
		rte_rawdev_stop(emdev_id);
		rte_rawdev_close(emdev_id);
	}
	return rc;
}

static int
setup_graph_workers(void)
{
	static const char *const default_patterns[] = {
		"pkt_drop",
	};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_param graph_conf;
	struct lcore_conf *qconf;
	struct rte_node *node;
	uint32_t emdev_id;
	uint16_t nb_patterns;
	rte_node_t node_id;
	uint32_t lcore_id;
	uint16_t portid;

	nb_patterns = RTE_DIM(default_patterns);
	node_patterns = malloc((MAX_ETHDEV_RX_PER_LCORE + MAX_VIRTIO_RX_PER_LCORE + nb_patterns) *
			       sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
	graph_conf.node_patterns = node_patterns;

	/* Pcap config */
	graph_conf.pcap_enable = pcap_trace_enable;
	graph_conf.num_pkt_to_capture = packet_to_capture;
	graph_conf.pcap_filename = pcap_filename;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		rte_graph_t graph_id;
		rte_edge_t i;

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		qconf = &lcore_conf[lcore_id];

		/* Skip Lcore if not needed */
		if (!qconf->nb_ethdev_rx && !qconf->nb_emdev_deq)
			continue;

		qconf->qs_v = qs_v;

		nb_patterns = RTE_DIM(default_patterns);
		snprintf(qconf->name, sizeof(qconf->name), "worker_%u", lcore_id);

		/* Add ethdev and emdev rx node patterns of this lcore */
		for (i = 0; i < qconf->nb_ethdev_rx; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->ethdev_rx[i].node_name;
		nb_patterns += i;

		for (i = 0; i < qconf->nb_emdev_deq; i++)
			graph_conf.node_patterns[nb_patterns + i] = qconf->emdev_deq[i].node_name;

		nb_patterns += i;

		graph_conf.nb_node_patterns = nb_patterns;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		graph_id = rte_graph_create(qconf->name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID) {
			APP_ERR("rte_graph_create(): graph_id invalid for lcore %u\n",
				 lcore_id);
			goto exit;
		}

		qconf->graph_id = graph_id;
		qconf->graph = rte_graph_lookup(qconf->name);
		if (!qconf->graph)
			rte_exit(EXIT_FAILURE, "rte_graph_lookup(): graph %s not found\n",
				 qconf->name);

		/* Update context data of ethdev rx and emdev tx nodes of this graph */
		for (i = 0; i < qconf->nb_ethdev_rx; i++) {
			portid = qconf->ethdev_rx[i].portid;

			/* ethdev rx ctx */
			node_id = ethdev_rx_nodes[portid];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->ethdev_rx[i].ethdev_rx = (struct l2_ethdev_rx_node_ctx *)node->ctx;
			qconf->ethdev_rx[i].ethdev_rx->eth_port = portid;
			qconf->ethdev_rx[i].ethdev_rx->virtio_next = 1;
			qconf->ethdev_rx[i].ethdev_rx->emdev_id = eth_map[portid].emdev_id;
			qconf->ethdev_rx[i].ethdev_rx->func_id = eth_map[portid].id;

			/* Mapped virtio tx ctx */
			node_id = emdev_enq_nodes[eth_map[portid].emdev_id];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->ethdev_rx[i].emdev_enq = (struct l2_emdev_enq_node_ctx *)node->ctx;
			qconf->ethdev_rx[i].emdev_enq->emdev_id = eth_map[portid].emdev_id;
			qconf->ethdev_rx[i].emdev_enq->emdev_qid = qconf->ethdev_rx[i].emdev_qid;
		}

		/* Update context data of emdev rx and ethdev tx nodes of this graph */
		for (i = 0; i < qconf->nb_emdev_deq; i++) {
			emdev_id = qconf->emdev_deq[i].emdev_id;

			/* virtio rx ctx */
			node_id = emdev_deq_nodes[i];
			node = rte_graph_node_get(graph_id, node_id);
			qconf->emdev_deq[i].emdev_deq = (struct l2_emdev_deq_node_ctx *)node->ctx;
			qconf->emdev_deq[i].emdev_deq->emdev_id = emdev_id;
			qconf->emdev_deq[i].emdev_deq->emdev_qid = qconf->emdev_deq[i].emdev_qid;
			qconf->emdev_deq[i].emdev_deq->eth_next = 1;
		}

		/* Assign portid to respective tx node context */
		for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
			node_id = ethdev_tx_nodes[portid];
			node = rte_graph_node_get(graph_id, node_id);
			if (node) {
				struct l2_ethdev_tx_node_ctx *ethdev_tx_ctx;

				ethdev_tx_ctx = (struct l2_ethdev_tx_node_ctx *)node->ctx;
				ethdev_tx_ctx->eth_port = portid;
			}
		}

		/* Assign emdevid to respective enq node context */
		for (emdev_id = 0; emdev_id < RTE_RAWDEV_MAX_DEVS; emdev_id++) {
			node_id = emdev_enq_nodes[emdev_id];
			node = rte_graph_node_get(graph_id, node_id);
			if (node) {
				struct l2_emdev_enq_node_ctx *emdev_enq_ctx;

				emdev_enq_ctx = (struct l2_emdev_enq_node_ctx *)node->ctx;
				emdev_enq_ctx->emdev_id = emdev_id;
			}
		}

		if (rte_graph_has_stats_feature() && stats_enable && verbose_stats == 2) {
			const char *pattern = qconf->name;
			/* Prepare per-lcore stats object */
			memset(&s_param, 0, sizeof(s_param));
			s_param.f = stdout;
			s_param.socket_id = SOCKET_ID_ANY;
			s_param.graph_patterns = &pattern;
			s_param.nb_graph_patterns = 1;

			graph_stats[lcore_id] = rte_graph_cluster_stats_create(&s_param);
			if (graph_stats[lcore_id] == NULL) {
				APP_ERR("Unable to create stats object\n");
				goto exit;
			}
		}
	}

	if (rte_graph_has_stats_feature() && stats_enable && verbose_stats != 2) {
		const char *pattern = "worker_*";
		/* Prepare stats object */
		memset(&s_param, 0, sizeof(s_param));
		s_param.f = stdout;
		s_param.socket_id = SOCKET_ID_ANY;
		s_param.graph_patterns = &pattern;
		s_param.nb_graph_patterns = 1;

		graph_stats[0] = rte_graph_cluster_stats_create(&s_param);
		if (graph_stats[0] == NULL)
			rte_exit(EXIT_FAILURE, "Unable to create stats object\n");
	}

	return 0;
exit:
	return -EINVAL;
}

static void
release_graph_workers(void)
{
	uint32_t lcore_id;
	int rc;

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (graph_stats[lcore_id])
			rte_graph_cluster_stats_destroy(graph_stats[lcore_id]);
	}

	/* Wait for worker cores to exit */
	rc = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rc = rte_eal_wait_lcore(lcore_id);
		/* Destroy graph */
		if (rc < 0 || rte_graph_destroy(rte_graph_from_name(lcore_conf[lcore_id].name))) {
			rc = -1;
			break;
		}
	}
	free(node_patterns);
}

static void
release_em_device(void)
{
	int emdev_id;

	for (emdev_id = 0; emdev_id < RTE_RAWDEV_MAX_DEVS; emdev_id++) {
		/* Skip emdevs that are not enabled */
		if (!is_emdev_enabled(emdev_id))
			continue;
		rte_rawdev_stop(emdev_id);
		rte_rawdev_close(emdev_id);
	}
}

static void
release_eth_devices(void)
{
	uint16_t portid;
	int rc;

	/* Stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;
		APP_INFO("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			APP_ERR("Failed to stop port %u: %s\n", portid, rte_strerror(-rc));
		rte_eth_dev_close(portid);
		APP_INFO_NH(" Done\n");
	}
}

int
main(int argc, char **argv)
{
	struct lcore_conf *qconf;
	uint32_t lcore_id;
	uint16_t portid;
	size_t sz;
	int rc;

	/* Init EAL */
	rc = rte_eal_init(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= rc;
	argv += rc;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, sig_user1_handler);

	/* Parse application arguments (after the EAL ones) */
	rc = parse_args(argc, argv);
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "Invalid VIRTIO_L2FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params() failed\n");

	rc = init_lcore_ethdev_rx();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues() failed\n");

	rc = init_lcore_emdev_deq();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_virtio_dev() failed\n");

	rc = assign_lcore_emdev_queues();
	if (rc < 0)
		rte_exit(EXIT_FAILURE, "assign_lcore_emdev_queues() failed\n");

	if (check_port_config() < 0)
		APP_ERR("check_port_config() failed\n");

	if (check_emdev_config() < 0)
		rte_exit(EXIT_FAILURE, "check_emdev_config() failed\n");

	/* Alloc mempools */
	setup_mempools();

	/* Initialize all ethdev ports. 8< */
	setup_eth_devices();

	/* Setup RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qs_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
							 SOCKET_ID_ANY);
	if (!qs_v)
		rte_exit(EXIT_FAILURE, "Failed to alloc rcu_qsbr variable\n");

	rc = rte_rcu_qsbr_init(qs_v, RTE_MAX_LCORE);
	if (rc)
		rte_exit(EXIT_FAILURE, "rte_rcu_qsbr_init(): failed to init, rc=%d\n", rc);

	/* Start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (!is_ethdev_enabled(portid))
			continue;

		/* Start device */
		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", rc, portid);

		if (promiscuous_on)
			rte_eth_promiscuous_enable(portid);
	}

	check_all_ports_link_status();

	/* Initialize virtio devices */
	rc = setup_em_devices();
	if (rc) {
		APP_ERR("setup_em_device: err=%d\n", rc);
		goto cleanup_ethdev;
	}

	/* Graph Initialization */
	rc = setup_graph_workers();
	if (rc) {
		APP_ERR("setup_graph_workers: err=%d\n", rc);
		goto cleanup_emdev;
	}

	APP_INFO("\n");

	if (per_port_pool) {
		RTE_ETH_FOREACH_DEV(portid) {
			if (!is_ethdev_enabled(portid))
				continue;

			APP_ERR("Initial Packet pool avail buff_cnt=%d\n",
				rte_mempool_avail_count(e_pktmbuf_pool[portid]));
		}
	} else {
		APP_ERR("Initial Packet pool avail buff_cnt=%d\n",
			rte_mempool_avail_count(e_pktmbuf_pool[0]));
	}

	/* Launch per-lcore init on every worker lcore */
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];
		if (qconf->graph)
			rte_eal_remote_launch(graph_main_loop, NULL, lcore_id);
	}

	dump_lcore_info();

	/* Accumulate and print stats on main until exit */
	print_stats();

	/* Wait for all worker cores to finish and destroy their graphs */
	release_graph_workers();

cleanup_emdev:
	/* Close pem device */
	release_em_device();

cleanup_ethdev:
	/* Close eth devices */
	release_eth_devices();

	/* clean up the EAL */
	rte_eal_cleanup();
	APP_INFO("Bye...\n");

	return rc;
}
