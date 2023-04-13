/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Mellanox Technologies, Ltd
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
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>
#include <rte_flow_block.h>


#define COMMENT_LEAD_CHAR   ('#')
#define OPTION_RULE_IPV4    "rule_ipv4"
#define RTE_FLOW_MAX_RULE_NUM  100
#define MAX_PKT_BURST 256
#define MEMPOOL_CACHE_SIZE 256
#define MAX_CORE_NUM 24
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 4096
#define CHECK_INTERVAL 100  /* 100ms */
#define MAX_REPEAT_TIMES 90  /* 9s (90 * 100ms) in total */

static volatile bool force_quit;

uint16_t g_port_id[8];
static uint16_t port_count = 0;
struct rte_mempool *mbuf_pool;
struct rte_flow *flow;
static int core_queue[RTE_MAX_LCORE] = {0};
static uint64_t flow_pkt_count[RTE_MAX_LCORE] = {0};
static uint64_t non_flow_pkt_count[RTE_MAX_LCORE] = {0};
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static uint64_t timer_period = 200000000;
static uint64_t flow_pkts = 0;
static uint64_t non_flow_pkts = 0;

#define uint32_t_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_MASK,
	CB_FLD_DST_PORT,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_MASK,
	CB_FLD_PROTO,
	CB_FLD_PORT_ID,
	CB_FLD_NUM,
};

const char cb_port_delim[] = ":";

/* ACL field definitions for IPv4 5 tuple rule */
enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

enum {
	PROTO_INPUT_IPV4,
	SRC_INPUT_IPV4,
	DST_INPUT_IPV4,
	SRCP_DESTP_INPUT_IPV4
};


#define SRC_IP ((0<<24) + (0<<16) + (0<<8) + 0) /* src ip = 0.0.0.0 */
#define DEST_IP ((192<<24) + (168<<16) + (1<<8) + 1) /* dest ip = 192.168.1.1 */
#define DEST_IP_A ((192<<24) + (168<<16) + (1<<8) + 11)
#define FULL_MASK 0xffffffff /* full mask */
#define EMPTY_MASK 0x0 /* empty mask */


static inline void
print_ether_addr(const char *what, struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", what, buf);
}

static void print_stats(void)
{
    printf("===========================================\n");

    for (int i = 0; i < RTE_MAX_LCORE; i++)
    {
        flow_pkts += flow_pkt_count[i];
        non_flow_pkts += non_flow_pkt_count[i];
    }
    printf("    rte_flow pkts: %lu\n", flow_pkts);
    printf("    non_rte_flow pkts: %lu\n\n", non_flow_pkts);

    flow_pkts = 0;
    non_flow_pkts = 0;
}

static int
rte_flow_main_loop(void)
{
	struct rte_mbuf *mbufs[32];
	//struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
	int ret = 0;
    uint16_t lcore_id;
    uint16_t queue_id;
    uint64_t prev_tsc = 0;
    uint64_t diff_tsc = 0;
    uint64_t cur_tsc = 0;
    uint64_t timer_tsc = 0;

    lcore_id = rte_lcore_id();
    queue_id = core_queue[lcore_id];

	while (!force_quit) 
    {
		if (lcore_id == rte_get_main_lcore()) 
        {
            cur_tsc = rte_rdtsc();
            diff_tsc = cur_tsc - prev_tsc;
            timer_tsc += diff_tsc;
            if (unlikely(timer_tsc >= timer_period))
            {
                print_stats();
                timer_tsc = 0;
            }
            prev_tsc = cur_tsc;
            continue;
        }

        else
        {
            for (i = 0; i < port_count; i++)
            {
			    nb_rx = rte_eth_rx_burst(g_port_id[i], queue_id, mbufs, 32);
		    	if (nb_rx)
                {
	    			for (j = 0; j < nb_rx; j++)
                    {
    					struct rte_mbuf *m = mbufs[j];

    					//printf(" - queue=0x%x - core=%u, hi = %u, rss = %u\n",
						//    	(unsigned int)queue_id, rte_lcore_id(), m->hash.fdir.hi, m->hash.rss);

					    //rte_pktmbuf_free(m);
                        if (m->hash.fdir.hi > 0)
                        {
                            ret = rte_eth_tx_burst(g_port_id[m->hash.fdir.hi - 1] , queue_id , &(m) , 1);
                            flow_pkt_count[lcore_id]++;
                        }
                        else
                        {
                            ret = rte_eth_tx_burst(0, 0, &(m) , 1);
                            non_flow_pkt_count[lcore_id]++;
                        }
				    }
			    }
		    }
        }
	}

	return ret;
}

static int
rte_flow_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	rte_flow_main_loop();
	return 0;
}

static void
init_port(uint16_t port_id, uint16_t nr_queues)
{
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
		.rxmode = {
            .mq_mode = RTE_ETH_MQ_RX_RSS,
			.split_hdr_size = 0,
            .offloads = DEV_RX_OFFLOAD_RSS_HASH,
            .reserved_64s[0] = 1,
		},
        .rx_adv_conf = {
		    .rss_conf = {
			    .rss_key = NULL,
			    .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP,
		    },
	    },
		.txmode = {
			.offloads =
				RTE_ETH_TX_OFFLOAD_VLAN_INSERT |
				RTE_ETH_TX_OFFLOAD_IPV4_CKSUM  |
				RTE_ETH_TX_OFFLOAD_UDP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_TCP_CKSUM   |
				RTE_ETH_TX_OFFLOAD_SCTP_CKSUM  |
				RTE_ETH_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;
    uint64_t rx_metadata = 0;

    rx_metadata |= RTE_ETH_RX_METADATA_USER_FLAG;
    rx_metadata |= RTE_ETH_RX_METADATA_USER_MARK;

    ret = rte_eth_rx_metadata_negotiate(port_id, &rx_metadata);
    if (ret == 0)
    {
        if (!(rx_metadata & RTE_ETH_RX_METADATA_USER_FLAG))
        {
            printf(":: flow action FLAG will not affect Rx mbufs on port=%u\n", port_id);
        }

        if (!(rx_metadata & RTE_ETH_RX_METADATA_USER_MARK))
        {
            printf(":: flow action MARK will not affect Rx mbufs on port=%u\n", port_id);
        }
    }
    else if (ret != -ENOTSUP)
    {
        rte_exit(EXIT_FAILURE, "Error when negotiating Rx meta features on port=%u: %s\n", port_id, rte_strerror(-ret));
    }
    else
    {
        printf("negotiating Rx meta features on port=%u, ret = %u\n", port_id, ret);
    }

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	printf(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			":: promiscuous mode enable failed: err=%s, port=%u\n",
			rte_strerror(-ret), port_id);

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}

    for (int i = 0; i < RTE_MAX_LCORE; i++)
    {
        flow_pkts += flow_pkt_count[i];
        non_flow_pkts += non_flow_pkt_count[i];
    }
    printf("    The count of packets matched rte flow: %lu\n", flow_pkts);
    printf("    The count of packets not matched rte flow: %lu\n", non_flow_pkts);
}

/*
 * Parse IPv4 5 tuple rules file, ipv4_rules_file.txt.
 * Expected format:
 * <src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port> <space> ":" <src_port_mask> <space> \
 * <dst_port> <space> ":" <dst_port_mask> <space> \
 * <proto>'/'<proto_mask> <space> \
 * <priority>
 */

static int
get_cb_field(char **in, uint32_t *fd, int base, unsigned long lim,
		char dlm)
{
	unsigned long val;
	char *end;

	errno = 0;
	val = strtoul(*in, &end, base);
	if (errno != 0 || end[0] != dlm || val > lim)
		return -EINVAL;
	*fd = (uint32_t)val;
	*in = end + 1;
	return 0;
}

static uint32_t
convert_depth_to_bitmask(uint32_t depth_val)
{
	uint32_t bitmask = 0;
	int i, j;

	for (i = depth_val, j = 0; i > 0; i--, j++)
		bitmask |= (1 << (31 - j));
	return bitmask;
}

static int
parse_ipv4_net(char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint32_t a, b, c, d, m;

	if (get_cb_field(&in, &a, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &b, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &c, 0, UINT8_MAX, '.'))
		return -EINVAL;
	if (get_cb_field(&in, &d, 0, UINT8_MAX, '/'))
		return -EINVAL;
	if (get_cb_field(&in, &m, 0, sizeof(uint32_t) * CHAR_BIT, 0))
		return -EINVAL;

	addr[0] = RTE_IPV4(a, b, c, d);
	mask_len[0] = convert_depth_to_bitmask(m);
	return 0;
}

static int
parse_ipv4_5tuple_rule(char *str, rte_flow_ntuple_filter_t *ntuple_filter)
{
	int i, ret;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = CB_FLD_NUM;
	uint32_t temp;
    uint16_t nr_ports = 0;

	s = str;
	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	ret = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&ntuple_filter->src_ip,
			&ntuple_filter->src_ip_mask);
	if (ret != 0) {
		printf("failed to read source address/mask: %s\n",
			in[CB_FLD_SRC_ADDR]);
		return ret;
	}

	ret = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&ntuple_filter->dst_ip,
			&ntuple_filter->dst_ip_mask);
	if (ret != 0) {
		printf("failed to read destination address/mask: %s\n",
			in[CB_FLD_DST_ADDR]);
		return ret;
	}

	if (get_cb_field(&in[CB_FLD_SRC_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_SRC_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->src_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_DST_PORT], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port = (uint16_t)temp;

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
			sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (get_cb_field(&in[CB_FLD_DST_PORT_MASK], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->dst_port_mask = (uint16_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, '/'))
		return -EINVAL;
	ntuple_filter->proto = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PROTO], &temp, 0, UINT8_MAX, 0))
		return -EINVAL;
	ntuple_filter->proto_mask = (uint8_t)temp;

	if (get_cb_field(&in[CB_FLD_PORT_ID], &temp, 0, UINT16_MAX, 0))
		return -EINVAL;
	ntuple_filter->port_id = (uint16_t)temp;
    nr_ports = rte_eth_dev_count_avail();
    if ((ntuple_filter->port_id > nr_ports) && (ntuple_filter->port_id != 127))
    {
        return -EINVAL;
    }
	return ret;
}

/* Bypass comment and empty lines */
static inline int
is_bypass_line(char *buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

/* Reads file and calls the add_classify_rule function. 8< */
static int
parse_rules(const char *rule_path, rte_flow_ntuple_filter_t *ntuple_filter, uint16_t *rule_num)
{
	FILE *fh;
	char buff[LINE_MAX];
	unsigned int i = 0;
	unsigned int total_num = 0;
	int ret;

	fh = fopen(rule_path, "rb");
	if (fh == NULL)
		rte_exit(EXIT_FAILURE, "%s: fopen %s failed\n", __func__,
			rule_path);

	ret = fseek(fh, 0, SEEK_SET);
	if (ret)
		rte_exit(EXIT_FAILURE, "%s: fseek %d failed\n", __func__,
			ret);

	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))
			continue;

		if (total_num >= RTE_FLOW_MAX_RULE_NUM) {
			printf("\nINFO: classify rule capacity %d reached\n",
				total_num);
			break;
		}

		if (parse_ipv4_5tuple_rule(buff, ntuple_filter) != 0)
			rte_exit(EXIT_FAILURE,
				"%s Line %u: parse rules error\n",
				rule_path, i);

		total_num++;
		ntuple_filter += 1;
	}

	fclose(fh);
	*rule_num = total_num;
	return 0;
}
/* >8 End of add_rules. */

/* display usage */
static void
print_usage(const char *prgname)
{
	printf("%s usage:\n", prgname);
	printf("[EAL options] --  --"OPTION_RULE_IPV4"=FILE: ");
	printf("specify the ipv4 rules file.\n");
	printf("Each rule occupies one line in the file.\n");
}

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv, rte_flow_ntuple_filter_t *ntuple_filter, uint16_t *rule_num)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = {
		{OPTION_RULE_IPV4, 1, 0, 0},
		{NULL, 0, 0, 0}
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			if (!strncmp(lgopts[option_index].name,
					OPTION_RULE_IPV4,
					sizeof(OPTION_RULE_IPV4)))

			    parse_rules(optarg, ntuple_filter, rule_num);
			break;
		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
check_all_ports_link_status(void)
{
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_REPEAT_TIMES; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;

			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
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
		if (all_ports_up == 1 || count == (MAX_REPEAT_TIMES - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

int
main(int argc, char **argv)
{
	int ret;
    uint16_t port_id = 0;
	uint16_t nr_ports;
	struct rte_flow_error error;
	uint16_t rule_num = 0;
    uint16_t rx_tx_queue_cnt = 0;
    unsigned int nb_lcores = 0;
    unsigned int nb_mbufs;
    uint32_t lcore_id;
	rte_flow_ntuple_filter_t ntuple_filter[128];

	/* Initialize EAL. 8< */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");
	/* >8 End of Initialization of EAL. */
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = parse_args(argc, argv, ntuple_filter, &rule_num);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid rte_flow parameters\n");

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");

    nb_lcores = rte_lcore_count();
    for (unsigned int i = 0; i < RTE_MAX_LCORE; i++)
	{
	    if (rte_lcore_is_enabled(i) && i != rte_get_main_lcore())
	    {
		    core_queue[i] = rx_tx_queue_cnt;
		    rx_tx_queue_cnt++;
	    }

        else
	    {
		    core_queue[i] = 65535;
	    }
	}

    nb_mbufs = RTE_MAX(nr_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 600000U);    
	/* Allocates a mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
				    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	/* >8 End of allocating a mempool to hold the mbufs. */
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    RTE_ETH_FOREACH_DEV(port_id) {
	    init_port(port_id, rx_tx_queue_cnt);
    	for (int i = 0; i < rule_num; i++)
        {
	        flow = generate_ipv4_flow(port_id, &ntuple_filter[i], &error);
	        if (!flow) 
		    {
	    	    printf("Flow can't be created %d message: %s\n",
    			    error.type,
			        error.message ? error.message : "(no stated reason)");
		        rte_exit(EXIT_FAILURE, "error in creating flow");
	        }

	    }

        g_port_id[port_count++] = port_id;
    }

    check_all_ports_link_status();
	//ret = main_loop();

    rte_eal_mp_remote_launch(rte_flow_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
	/* clean up the EAL */
	rte_eal_cleanup();

	return ret;
}

