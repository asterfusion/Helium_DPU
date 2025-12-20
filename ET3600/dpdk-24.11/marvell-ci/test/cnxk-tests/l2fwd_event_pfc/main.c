/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <rte_string_fns.h>

#include "l2fwd_event.h"
#include "l2fwd_poll.h"

/* display usage */
static void
l2fwd_event_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
	       "  -T PERIOD: statistics will be refreshed each PERIOD seconds "
	       "		(0 to disable, 10 default, 86400 maximum)\n"
	       "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
	       "      When enabled:\n"
	       "       - The source MAC address is replaced by the TX port MAC address\n"
	       "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n"
	       "  --rxq: Number of Rx queues created on each port. Default is 1\n"
	       "  --txq: Number of Tx queues created on each port. Default is 1\n"
	       "  --pfc: <port>:<rx_pfc>:<on/off>:<txq>:<tc>:<tx_pfc>:<on/off>:<rxq>:<tc>:<pause quanta>\n"
	       "    - <port> : Port id on which PFC is to be enabled.\n"
	       "    - <rx_pfc>:<on/off> : Enable reception of 802.1qbb flow control PFC frames.\n"
	       "    - <txq> : Tx queue on which TC is to be mapped and will be paused if PFC is received with corresponding TC.\n"
	       "    - <tc> : Traffic class which is used to pause mapped txq.\n"
	       "    - <tx_pfc>:<on/off> : Enable xmit of 802.1qbb flow control PFC frames.\n"
	       "    - <rxq> : Rx queue on which TC is to be mapped.\n"
	       "    - <tc> : Traffic class which is mapped with rxq and used in PFC frame if threshold reaches.\n"
	       "    - <pause quanta> : Pause quanta which is mapped with rxq and used in PFC frame if threshold reaches.\n"
	       "  --short-pool: Enable use of short mbuf pool (disabled by default)\n"
	       "  --mode: Packet transfer mode for I/O, poll or eventdev\n"
	       "          Default mode = eventdev\n"
	       "  --eventq-sched: Event queue schedule type, ordered, atomic or parallel.\n"
	       "                  Default: atomic\n"
	       "                  Valid only if --mode=eventdev\n"
	       "  --event-vector:  Enable event vectorization.\n"
	       "  --event-vector-size: Max vector size if event vectorization is enabled.\n"
	       "  --event-vector-tmo: Max timeout to form vector in nanoseconds if event vectorization is enabled\n"
	       "  --config: Configure forwarding port pair mapping\n"
	       "	    Default: alternate port pairs\n\n",
	       prgname);
}

static int
l2fwd_event_parse_pfc(char *optarg, struct l2fwd_resources *rsrc)
{
	char *pfc_str, *token;
	uint16_t portid;
	uint16_t index;
	size_t len;
	int rc = 0;

	len = strlen(optarg);
	len++;
	pfc_str = malloc(len);
	if (pfc_str == NULL) {
		printf("Memory allocation failed\n");
		rc = -1;
		goto error;
	}
	strcpy(pfc_str, optarg);

	/* <portid>:<rx_pfc>:<on/off>:<txq>:<tc>:<tx_pfc>:<on/off>:<rxq>:<tc>:<pause quanta> */
	token = strtok(pfc_str, ":");
	if (token == NULL) {
		printf("port ID is expected\n");
		rc = -1;
		goto error;
	}
	portid = atoi(token);
	if (portid >= RTE_MAX_ETHPORTS) {
		printf("port ID is invalid\n");
		rc = -1;
		goto error;
	}
	if ((rsrc->enabled_port_mask & (1 << portid)) == 0) {
		printf("port is not enabled\n");
		rc = -1;
		goto error;
	}
	index = rsrc->pfc_config_cnt[portid];

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("rx_pfc is expected\n");
		rc = -1;
		goto error;
	}
	if (strncmp(token, "rx_pfc", 6)) {
		printf("Invalid string\n");
		rc = -1;
		goto error;
	}

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("either on or off is expected\n");
		rc = -1;
		goto error;
	}
	if (!strncmp(token, "on", 2)) {
		rsrc->pfc_config[portid][index].rx_pfc = true;
	} else if (!strncmp(token, "off", 3)) {
		rsrc->pfc_config[portid][index].rx_pfc = false;
	} else {
		printf("Invalid rx_pfc option\n");
		rc = -1;
		goto error;
	}

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("txq is expected\n");
		rc = -1;
		goto error;
	}
	rsrc->pfc_config[portid][index].txq = atoi(token);

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("tx_tc is expected\n");
		rc = -1;
		goto error;
	}
	rsrc->pfc_config[portid][index].tx_tc = atoi(token);

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("tx_pfc is expected\n");
		rc = -1;
		goto error;
	}
	if (strncmp(token, "tx_pfc", 6)) {
		printf("Invalid string\n");
		rc = -1;
		goto error;
	}

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("either on or off is expected\n");
		rc = -1;
		goto error;
	}
	if (!strncmp(token, "on", 2)) {
		rsrc->pfc_config[portid][index].tx_pfc = true;
	} else if (!strncmp(token, "off", 3)) {
		rsrc->pfc_config[portid][index].tx_pfc = false;
	} else {
		printf("Invalid tx_pfc option\n");
		rc = -1;
		goto error;
	}

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("rxq is expected\n");
		rc = -1;
		goto error;
	}
	rsrc->pfc_config[portid][index].rxq = atoi(token);

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("rx_tc is expected\n");
		rc = -1;
		goto error;
	}
	rsrc->pfc_config[portid][index].rx_tc = atoi(token);

	token = strtok(NULL, ":");
	if (token == NULL) {
		printf("pause quanta is expected\n");
		rc = -1;
		goto error;
	}
	rsrc->pfc_config[portid][index].pause = atoi(token);
	rsrc->pfc_config_cnt[portid]++;

error:
	free(pfc_str);
	return rc;
}

static int
l2fwd_event_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static unsigned int
l2fwd_event_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_event_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static void
l2fwd_event_parse_mode(const char *optarg,
		       struct l2fwd_resources *rsrc)
{
	if (!strncmp(optarg, "poll", 4))
		rsrc->event_mode = false;
	else if (!strncmp(optarg, "eventdev", 8))
		rsrc->event_mode = true;
}

static void
l2fwd_event_parse_eventq_sched(const char *optarg,
			       struct l2fwd_resources *rsrc)
{
	if (!strncmp(optarg, "ordered", 7))
		rsrc->sched_type = RTE_SCHED_TYPE_ORDERED;
	else if (!strncmp(optarg, "atomic", 6))
		rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
	else if (!strncmp(optarg, "parallel", 8))
		rsrc->sched_type = RTE_SCHED_TYPE_PARALLEL;
}

static int
l2fwd_parse_port_pair_config(const char *q_arg, struct l2fwd_resources *rsrc)
{
	enum fieldnames {
		FLD_PORT1 = 0,
		FLD_PORT2,
		_NUM_FLD
	};
	const char *p, *p0 = q_arg;
	uint16_t int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	uint16_t port_pair = 0;
	unsigned int size;
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
		if (rte_strsplit(s, sizeof(s), str_fld,
					_NUM_FLD, ',') != _NUM_FLD)
			return -1;

		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] >= RTE_MAX_ETHPORTS)
				return -1;
		}

		if (port_pair >= RTE_MAX_ETHPORTS / 2) {
			printf("exceeded max number of port pair params: Current %d Max = %d\n",
			       port_pair, RTE_MAX_ETHPORTS / 2);
			return -1;
		}

		if ((rsrc->dst_ports[int_fld[FLD_PORT1]] != UINT32_MAX) ||
			(rsrc->dst_ports[int_fld[FLD_PORT2]] != UINT32_MAX)) {
			printf("Duplicate port pair (%d,%d) config\n",
					int_fld[FLD_PORT1], int_fld[FLD_PORT2]);
			return -1;
		}

		rsrc->dst_ports[int_fld[FLD_PORT1]] = int_fld[FLD_PORT2];
		rsrc->dst_ports[int_fld[FLD_PORT2]] = int_fld[FLD_PORT1];

		port_pair++;
	}

	rsrc->port_pairs = true;

	return 0;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"
#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_RXQ "rxq"
#define CMD_LINE_OPT_TXQ "txq"
#define CMD_LINE_OPT_PFC "pfc"
#define CMD_LINE_OPT_SHORT_POOL "short-pool"
#define CMD_LINE_OPT_EVENTQ_SCHED "eventq-sched"
#define CMD_LINE_OPT_PORT_PAIR_CONF "config"
#define CMD_LINE_OPT_ENABLE_VECTOR "event-vector"
#define CMD_LINE_OPT_VECTOR_SIZE "event-vector-size"
#define CMD_LINE_OPT_VECTOR_TMO_NS "event-vector-tmo"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_MODE_NUM,
	CMD_LINE_OPT_RXQ_NUM,
	CMD_LINE_OPT_TXQ_NUM,
	CMD_LINE_OPT_PFC_NUM,
	CMD_LINE_OPT_PFC_SHORT_POOL_NUM,
	CMD_LINE_OPT_EVENTQ_SCHED_NUM,
	CMD_LINE_OPT_PORT_PAIR_CONF_NUM,
	CMD_LINE_OPT_ENABLE_VECTOR_NUM,
	CMD_LINE_OPT_VECTOR_SIZE_NUM,
	CMD_LINE_OPT_VECTOR_TMO_NS_NUM
};

/* Parse the argument given in the command line of the application */
static int
l2fwd_event_parse_args(int argc, char **argv, struct l2fwd_resources *rsrc)
{
	int mac_updating = 1;
	struct option lgopts[] = {
		{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
		{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
		{ CMD_LINE_OPT_MODE, required_argument, NULL, CMD_LINE_OPT_MODE_NUM},
		{ CMD_LINE_OPT_RXQ, required_argument, NULL, CMD_LINE_OPT_RXQ_NUM},
		{ CMD_LINE_OPT_TXQ, required_argument, NULL, CMD_LINE_OPT_TXQ_NUM},
		{ CMD_LINE_OPT_PFC, required_argument, NULL, CMD_LINE_OPT_PFC_NUM},
		{ CMD_LINE_OPT_SHORT_POOL, no_argument, NULL, CMD_LINE_OPT_PFC_SHORT_POOL_NUM},
		{ CMD_LINE_OPT_EVENTQ_SCHED, required_argument, NULL,
						CMD_LINE_OPT_EVENTQ_SCHED_NUM},
		{ CMD_LINE_OPT_PORT_PAIR_CONF, required_argument, NULL,
					CMD_LINE_OPT_PORT_PAIR_CONF_NUM},
		{CMD_LINE_OPT_ENABLE_VECTOR, no_argument, NULL,
					CMD_LINE_OPT_ENABLE_VECTOR_NUM},
		{CMD_LINE_OPT_VECTOR_SIZE, required_argument, NULL,
					CMD_LINE_OPT_VECTOR_SIZE_NUM},
		{CMD_LINE_OPT_VECTOR_TMO_NS, required_argument, NULL,
					CMD_LINE_OPT_VECTOR_TMO_NS_NUM},
		{NULL, 0, 0, 0}
	};
	int opt, ret, timer_secs;
	char *prgname = argv[0];
	uint16_t port_id;
	int option_index;
	char **argvopt;

	/* Reset l2fwd_dst_ports. 8< */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++)
		rsrc->dst_ports[port_id] = UINT32_MAX;

	argvopt = argv;
	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			rsrc->enabled_port_mask =
					l2fwd_event_parse_portmask(optarg);
			if (rsrc->enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q':
			rsrc->rx_queue_per_lcore =
					l2fwd_event_parse_nqueue(optarg);
			if (rsrc->rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_event_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			rsrc->timer_period = timer_secs;
			/* convert to number of cycles */
			rsrc->timer_period *= rte_get_timer_hz();
			break;

		case CMD_LINE_OPT_MODE_NUM:
			l2fwd_event_parse_mode(optarg, rsrc);
			break;

		case CMD_LINE_OPT_RXQ_NUM:
			rsrc->num_rxq = l2fwd_event_parse_nqueue(optarg);
			if (rsrc->num_rxq == 0) {
				printf("invalid number of Rx queues\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_TXQ_NUM:
			rsrc->num_txq = l2fwd_event_parse_nqueue(optarg);
			if (rsrc->num_txq == 0) {
				printf("invalid number of Tx queues\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PFC_NUM:
			ret = l2fwd_event_parse_pfc(optarg, rsrc);
			if (ret) {
				printf("invalid PFC configuration\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PFC_SHORT_POOL_NUM:
			rsrc->use_short_pool = 1;
			break;

		case CMD_LINE_OPT_EVENTQ_SCHED_NUM:
			l2fwd_event_parse_eventq_sched(optarg, rsrc);
			break;

		case CMD_LINE_OPT_PORT_PAIR_CONF_NUM:
			ret = l2fwd_parse_port_pair_config(optarg, rsrc);
			if (ret) {
				printf("Invalid port pair config\n");
				l2fwd_event_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_ENABLE_VECTOR_NUM:
			printf("event vectorization is enabled\n");
			rsrc->evt_vec.enabled = 1;
			break;
		case CMD_LINE_OPT_VECTOR_SIZE_NUM:
			rsrc->evt_vec.size = strtol(optarg, NULL, 10);
			break;
		case CMD_LINE_OPT_VECTOR_TMO_NS_NUM:
			rsrc->evt_vec.timeout_ns = strtoull(optarg, NULL, 10);
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_event_usage(prgname);
			return -1;
		}
	}

	rsrc->mac_updating = mac_updating;

	if (rsrc->evt_vec.enabled && !rsrc->evt_vec.size) {
		rsrc->evt_vec.size = VECTOR_SIZE_DEFAULT;
		printf("vector size set to default (%" PRIu16 ")\n",
		       rsrc->evt_vec.size);
	}

	if (rsrc->evt_vec.enabled && !rsrc->evt_vec.timeout_ns) {
		rsrc->evt_vec.timeout_ns = VECTOR_TMO_NS_DEFAULT;
		printf("vector timeout set to default (%" PRIu64 " ns)\n",
		       rsrc->evt_vec.timeout_ns);
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
	/* >8 End of reset l2fwd_dst_ports. */
}

/*
 * Check port pair config with enabled port mask,
 * and for valid port pair combinations.
 */
static int
check_port_pair_config(struct l2fwd_resources *rsrc)
{
	uint32_t port_pair_mask = 0;
	uint32_t portid;
	uint16_t index;

	for (index = 0; index < rte_eth_dev_count_avail(); index++) {
		if ((rsrc->enabled_port_mask & (1 << index)) == 0 ||
		    (port_pair_mask & (1 << index)))
			continue;

		portid = rsrc->dst_ports[index];
		if (portid == UINT32_MAX) {
			printf("port %u is enabled in but no valid port pair\n",
			       index);
			return -1;
		}

		if (!rte_eth_dev_is_valid_port(index)) {
			printf("port %u is not valid\n", index);
			return -1;
		}

		if (!rte_eth_dev_is_valid_port(portid)) {
			printf("port %u is not valid\n", portid);
			return -1;
		}

		if (port_pair_mask & (1 << portid) &&
				rsrc->dst_ports[portid] != index) {
			printf("port %u is used in other port pairs\n", portid);
			return -1;
		}

		port_pair_mask |= (1 << portid);
		port_pair_mask |= (1 << index);
	}

	return 0;
}

static int
l2fwd_launch_one_lcore(void *args)
{
	struct l2fwd_resources *rsrc = args;
	struct l2fwd_poll_resources *poll_rsrc = rsrc->poll_rsrc;
	struct l2fwd_event_resources *evt_rsrc = rsrc->evt_rsrc;

	if (rsrc->event_mode)
		evt_rsrc->ops.l2fwd_event_loop(rsrc);
	else
		poll_rsrc->poll_main_loop(rsrc);

	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(struct l2fwd_resources *rsrc, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t port_id;
	int ret;

	printf("\nChecking link status...");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (rsrc->force_quit)
			return;

		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(port_id) {
			if (rsrc->force_quit)
				return;

			if ((port_mask & (1 << port_id)) == 0)
				continue;

			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(port_id, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						port_id, rte_strerror(-ret));
				continue;
			}

			/* print link status if flag set */
			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
						    sizeof(link_status_text), &link);
				printf("Port %d %s\n", port_id, link_status_text);
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
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Print out statistics on packets dropped */
static void
print_stats(struct l2fwd_resources *rsrc)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint32_t port_id;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = {27, '[', '2', 'J', '\0' };
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		/* skip disabled ports */
		if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %29"PRIu64
			   "\nPackets received: %25"PRIu64
			   "\nPackets dropped: %26"PRIu64,
			   port_id,
			   rsrc->port_stats[port_id].tx,
			   rsrc->port_stats[port_id].rx,
			   rsrc->port_stats[port_id].dropped);

		total_packets_dropped +=
					rsrc->port_stats[port_id].dropped;
		total_packets_tx += rsrc->port_stats[port_id].tx;
		total_packets_rx += rsrc->port_stats[port_id].rx;
	}

	if (rsrc->event_mode) {
		struct l2fwd_event_resources *evt_rsrc = rsrc->evt_rsrc;
		struct rte_event_eth_rx_adapter_stats rx_adptr_stats;
		struct rte_event_eth_tx_adapter_stats tx_adptr_stats;
		int ret, i;

		for (i = 0; i < evt_rsrc->rx_adptr.nb_rx_adptr; i++) {
			ret = rte_event_eth_rx_adapter_stats_get(
					evt_rsrc->rx_adptr.rx_adptr[i],
					&rx_adptr_stats);
			if (ret < 0)
				continue;
			printf("\nRx adapter[%d] statistics===================="
				   "\nReceive queue poll count: %17"PRIu64
				   "\nReceived packet count: %20"PRIu64
				   "\nEventdev enqueue count: %19"PRIu64
				   "\nEventdev enqueue retry count: %13"PRIu64
				   "\nReceived packet dropped count: %12"PRIu64
				   "\nRx enqueue start timestamp: %15"PRIu64
				   "\nRx enqueue block cycles: %18"PRIu64
				   "\nRx enqueue unblock timestamp: %13"PRIu64,
				   evt_rsrc->rx_adptr.rx_adptr[i],
				   rx_adptr_stats.rx_poll_count,
				   rx_adptr_stats.rx_packets,
				   rx_adptr_stats.rx_enq_count,
				   rx_adptr_stats.rx_enq_retry,
				   rx_adptr_stats.rx_dropped,
				   rx_adptr_stats.rx_enq_start_ts,
				   rx_adptr_stats.rx_enq_block_cycles,
				   rx_adptr_stats.rx_enq_end_ts);
		}
		for (i = 0; i <  evt_rsrc->tx_adptr.nb_tx_adptr; i++) {
			ret = rte_event_eth_tx_adapter_stats_get(
					evt_rsrc->tx_adptr.tx_adptr[i],
					&tx_adptr_stats);
			if (ret < 0)
				continue;
			printf("\nTx adapter[%d] statistics===================="
				   "\n Number of transmit retries: %15"PRIu64
				   "\n Number of packets transmitted: %12"PRIu64
				   "\n Number of packets dropped: %16"PRIu64,
				   evt_rsrc->tx_adptr.tx_adptr[i],
				   tx_adptr_stats.tx_retry,
				   tx_adptr_stats.tx_packets,
				   tx_adptr_stats.tx_dropped);
		}
	}
	printf("\nAggregate lcore statistics ========================="
		   "\nTotal packets sent: %23"PRIu64
		   "\nTotal packets received: %19"PRIu64
		   "\nTotal packets dropped: %20"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

static void
l2fwd_event_print_stats(struct l2fwd_resources *rsrc)
{
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	const uint64_t timer_period = rsrc->timer_period;

	while (!rsrc->force_quit) {
		/* if timer is enabled */
		if (timer_period > 0) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {
				print_stats(rsrc);
				/* reset the timer */
				timer_tsc = 0;
			}
			prev_tsc = cur_tsc;
		}
	}
}

static void
signal_handler(int signum)
{
	struct l2fwd_resources *rsrc = l2fwd_get_rsrc();

	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		rsrc->force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	struct rte_eth_pfc_queue_conf pfc_conf;
	struct rte_flow_item_vlan vlan, mask;
	struct rte_flow_action_queue conf;
	struct rte_flow_action actions[4];
	struct rte_flow_item pattern[4];
	uint16_t nb_ports_available = 0;
	struct rte_eth_fc_conf fc_conf;
	uint32_t nb_ports_in_mask = 0;
	struct l2fwd_resources *rsrc;
	uint16_t port_id, last_port;
	struct rte_flow_attr attr;
	struct rte_flow *flow;
	uint32_t nb_mbufs;
	uint16_t nb_ports;
	int i, ret, j = 7;
	char name[32];

	/* Init EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	rsrc = l2fwd_get_rsrc();

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = l2fwd_event_parse_args(argc, argv, rsrc);
	if (ret < 0)
		rte_panic("Invalid L2FWD arguments\n");
	/* >8 End of init EAL. */

	printf("MAC updating %s\n", rsrc->mac_updating ? "enabled" : "disabled");
	printf("Use short pool %s\n", rsrc->use_short_pool ? "enabled" : "disabled");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_panic("No Ethernet ports - bye\n");

	/* check port mask to possible port mask */
	if (rsrc->enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_panic("Invalid portmask; possible (0x%x)\n", (1 << nb_ports) - 1);

	if (!rsrc->port_pairs) {
		last_port = 0;
		/*
		 * Each logical core is assigned a dedicated TX queue on each port.
		 */
		RTE_ETH_FOREACH_DEV(port_id) {
			/* skip ports that are not enabled */
			if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
				continue;

			if (nb_ports_in_mask % 2) {
				rsrc->dst_ports[port_id] = last_port;
				rsrc->dst_ports[last_port] = port_id;
			} else {
				last_port = port_id;
			}

			nb_ports_in_mask++;
		}
		if (nb_ports_in_mask % 2) {
			printf("Notice: odd number of ports in portmask.\n");
			rsrc->dst_ports[last_port] = last_port;
		}
	} else {
		if (check_port_pair_config(rsrc) < 0)
			rte_panic("Invalid port pair config\n");
	}

	nb_mbufs = RTE_MAX(nb_ports * (RX_DESC_DEFAULT + TX_DESC_DEFAULT + MAX_PKT_BURST +
				       rte_lcore_count() * MEMPOOL_CACHE_SIZE), 8192U);

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;

		/* Create the mbuf pool. 8< */
		for (i = 0; i < rsrc->num_rxq; i++) {
			snprintf(name, 32, "port%d_rxq%d_pool", port_id, i);
			rsrc->pktmbuf_pool[port_id][i] = rte_pktmbuf_pool_create(name, nb_mbufs,
					MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id());
			if (rsrc->pktmbuf_pool[port_id][i] == NULL)
				rte_panic("Cannot init mbuf pool\n");

			if (rsrc->use_short_pool) {
				snprintf(name, 32, "port%d_rxq%d_spool", port_id, i);
				rsrc->pktmbuf_short_pool[port_id][i] = rte_pktmbuf_pool_create(name,
						nb_mbufs, MEMPOOL_CACHE_SIZE, 0, 256,
						rte_socket_id());
				if (rsrc->pktmbuf_short_pool[port_id][i] == NULL)
					rte_panic("Cannot init mbuf short pool\n");
				}
		}
		/* >8 End of creation of mbuf pool. */
	}

	if (rsrc->evt_vec.enabled) {
		unsigned int nb_vec, vec_size;

		vec_size = rsrc->evt_vec.size;
		nb_vec = (nb_mbufs + vec_size - 1) / vec_size;
		nb_vec = RTE_MAX(512U, nb_vec);
		nb_vec += rte_lcore_count() * 32;
		rsrc->evt_vec_pool = rte_event_vector_pool_create(
			"vector_pool", nb_vec, 32, vec_size, rte_socket_id());
		if (rsrc->evt_vec_pool == NULL)
			rte_panic("Cannot init event vector pool\n");
	}

	nb_ports_available = l2fwd_event_init_ports(rsrc);
	if (!nb_ports_available)
		rte_panic("All available ports are disabled. Please set portmask.\n");

	/* Configure eventdev parameters if required */
	if (rsrc->event_mode)
		l2fwd_event_resource_setup(rsrc);
	else
		l2fwd_poll_resource_setup(rsrc);

	/* initialize port stats */
	memset(&rsrc->port_stats, 0, sizeof(struct l2fwd_port_statistics));

	if (rsrc->event_mode)
		l2fwd_event_service_setup(rsrc);

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;

		for (i = 0; i < rsrc->num_rxq; i++, j--) {
			/* Attributes */
			attr.group = 0;
			attr.priority = j;
			attr.ingress = 1;

			/* Pattern */
			memset(&vlan, 0, sizeof(struct rte_flow_item_vlan));
			vlan.hdr.vlan_tci = RTE_BE16(i << 13);
			vlan.has_more_vlan = 0;

			memset(&mask, 0, sizeof(struct rte_flow_item_vlan));
			mask.hdr.vlan_tci = RTE_BE16(0xe000);

			pattern[0].type = RTE_FLOW_ITEM_TYPE_VLAN;
			pattern[0].spec = &vlan;
			pattern[0].last = NULL;
			pattern[0].mask = &mask;
			pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

			/* Actions */
			memset(&conf, 0, sizeof(struct rte_flow_action_queue));
			conf.index = i;
			actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
			actions[0].conf = &conf;
			actions[1].type = RTE_FLOW_ACTION_TYPE_END;
			flow = rte_flow_create(port_id, &attr, pattern, actions, NULL);
			if (flow == NULL)
				printf("Flow Error\n");
		}
	}

	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;

		memset(&fc_conf, 0, sizeof(struct rte_eth_fc_conf));
		fc_conf.mode = RTE_ETH_FC_NONE;
		ret = rte_eth_dev_flow_ctrl_set(port_id, &fc_conf);
		if (ret) {
			printf("Error in configuring pause frame. Err = %d\n", ret);
			return ret;
		}

		/* Enable Ethernet device for PFC */
		for (i = 0; i < rsrc->pfc_config_cnt[port_id]; i++) {
			if (rsrc->pfc_config[port_id][i].rx_pfc &&
			    rsrc->pfc_config[port_id][i].tx_pfc)
				pfc_conf.mode = RTE_ETH_FC_FULL;
			else if (rsrc->pfc_config[port_id][i].rx_pfc)
				pfc_conf.mode = RTE_ETH_FC_RX_PAUSE;
			else if (rsrc->pfc_config[port_id][i].tx_pfc)
				pfc_conf.mode = RTE_ETH_FC_TX_PAUSE;
			else
				pfc_conf.mode = RTE_ETH_FC_NONE;

			pfc_conf.rx_pause.tx_qid = rsrc->pfc_config[port_id][i].txq;
			pfc_conf.rx_pause.tc = rsrc->pfc_config[port_id][i].tx_tc;
			pfc_conf.tx_pause.pause_time = rsrc->pfc_config[port_id][i].pause;
			pfc_conf.tx_pause.rx_qid = rsrc->pfc_config[port_id][i].rxq;
			pfc_conf.tx_pause.tc = rsrc->pfc_config[port_id][i].rx_tc;

			ret = rte_eth_dev_priority_flow_ctrl_queue_configure(port_id,
						&pfc_conf);
			if (ret) {
				printf("Error in setting PFC for port %u\n", port_id);
				return ret;
			}
		}
	}

	/* All settings are done. Now enable eth devices */
	RTE_ETH_FOREACH_DEV(port_id) {
		/* skip ports that are not enabled */
		if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;

		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_panic("rte_eth_dev_start:err=%d, port=%u\n", ret, port_id);

		rte_eth_dev_priv_dump(port_id, stdout);
	}

	check_all_ports_link_status(rsrc, rsrc->enabled_port_mask);

	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, rsrc,
				 SKIP_MAIN);
	l2fwd_event_print_stats(rsrc);
	if (rsrc->event_mode) {
		struct l2fwd_event_resources *evt_rsrc = rsrc->evt_rsrc;

		for (i = 0; i < evt_rsrc->rx_adptr.nb_rx_adptr; i++)
			rte_event_eth_rx_adapter_stop(evt_rsrc->rx_adptr.rx_adptr[i]);

		for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++)
			rte_event_eth_tx_adapter_stop(evt_rsrc->tx_adptr.tx_adptr[i]);

		RTE_ETH_FOREACH_DEV(port_id) {
			if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
				continue;
			ret = rte_eth_dev_stop(port_id);
			if (ret < 0)
				printf("rte_eth_dev_stop:err=%d, port=%u\n", ret, port_id);
		}

		rte_eal_mp_wait_lcore();
		RTE_ETH_FOREACH_DEV(port_id) {
			if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
				continue;

			printf("Closing port %d...", port_id);
			rte_eth_dev_close(port_id);
		}

		rte_event_dev_stop(evt_rsrc->event_d_id);
		rte_event_dev_close(evt_rsrc->event_d_id);
		printf(" Done\n");
	} else {
		rte_eal_mp_wait_lcore();

		RTE_ETH_FOREACH_DEV(port_id) {
			if ((rsrc->enabled_port_mask & (1 << port_id)) == 0)
				continue;

			printf("Closing port %d...", port_id);
			ret = rte_eth_dev_stop(port_id);
			if (ret < 0)
				printf("rte_eth_dev_stop:err=%d, port=%u\n", ret, port_id);

			rte_eth_dev_close(port_id);
			printf(" Done\n");
		}
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return 0;
}
