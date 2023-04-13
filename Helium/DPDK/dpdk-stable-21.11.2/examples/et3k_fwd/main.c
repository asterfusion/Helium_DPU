
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

int no_stats_print = 0;

static volatile bool force_quit;
static int core_queue[RTE_MAX_LCORE] = {0};

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 256
#define MEMPOOL_CACHE_SIZE 256
#define MAX_CORE_NUM 24
// 2*100G + 12*10G
#define MAX_PORT_NUM 14 

char et3k_portname[MAX_PORT_NUM][8];

int et3k_port_fwd_port[MAX_PORT_NUM];

uint16_t et3k_port_vlan[MAX_PORT_NUM];
#define et3k_port_to_vlan(a) ((a))
#define et3k_vlan_to_port(a) ((a))


/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 2048
#define RTE_TEST_TX_DESC_DEFAULT 4096
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;


static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.mtu = RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - RTE_ETHER_CRC_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * global_pktmbuf_pool = NULL;


/********************** stats ***************************/
static uint64_t timer_period = 1; /* default period is 1 seconds */


struct rte_eth_stats hardware_stats[3]; // only 3 dpdk ports


typedef struct et3k_soft_stats{
	uint64_t rx;
	uint64_t tx;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t drop;
}et3k_soft_stats_lcore_t;

et3k_soft_stats_lcore_t et3k_soft_stats[MAX_CORE_NUM][MAX_PORT_NUM];
et3k_soft_stats_lcore_t et3k_total_stats[MAX_PORT_NUM];

static void
collect_lcore_stats(void)
{
	int lcore;
	int port;

	memset(et3k_total_stats , 0 , sizeof(et3k_soft_stats_lcore_t) * MAX_PORT_NUM);

	for( lcore=0 ; lcore<MAX_CORE_NUM ; lcore ++ )
	{
		for( port=0; port<MAX_PORT_NUM ; port ++ )
		{
			et3k_total_stats[port].rx += et3k_soft_stats[lcore][port].rx;
			et3k_total_stats[port].tx += et3k_soft_stats[lcore][port].tx;
			et3k_total_stats[port].rx_bytes += et3k_soft_stats[lcore][port].rx_bytes;
			et3k_total_stats[port].tx_bytes += et3k_soft_stats[lcore][port].tx_bytes;
			et3k_total_stats[port].drop += et3k_soft_stats[lcore][port].drop;

		}
	}

}
/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	int ret_code;

    uint16_t portid;

	if(no_stats_print)
	{
		return ;
	}

    RTE_ETH_FOREACH_DEV(portid) {
		if(portid >= 3)
		{
			rte_exit(EXIT_FAILURE, "dpdk port num is greater than 3 !!!!!\n" );
		}
        ret_code = rte_eth_stats_get(portid, &(hardware_stats[portid]));
        if (ret_code != 0)
        {
            rte_exit(EXIT_FAILURE, "rte_eth_stats_get : %d\n" , ret_code);
        }
    }

#define COLUMN_HEAD "%10s"
#define COLUMN_NUM  "%8lu"	


	printf("===========================================\n");

	printf(COLUMN_HEAD""COLUMN_NUM""COLUMN_NUM""COLUMN_NUM"\n" , "port" , 0UL , 1UL , 2UL);

#define foreach_stats \
FUNC(ipackets) \
FUNC(opackets) \
FUNC(ibytes) \
FUNC(obytes) \
FUNC(imissed) \
FUNC(ierrors) \
FUNC(oerrors) \

#define FUNC(a) printf(COLUMN_HEAD""COLUMN_NUM""COLUMN_NUM""COLUMN_NUM"\n" , #a , \
	hardware_stats[0].a , hardware_stats[1].a , hardware_stats[2].a);

foreach_stats
#undef FUNC

	printf("-------------------------------------------\n");

	collect_lcore_stats();

#define SOFT_PORT_COLUMN_HEAD "%6s"
#define SOFT_PORT_COLUMN_NUM  "%10lu"		
#define SOFT_PORT_COLUMN_NUM_HEAD  "%10s"		

	printf(SOFT_PORT_COLUMN_HEAD""SOFT_PORT_COLUMN_NUM_HEAD""
			SOFT_PORT_COLUMN_NUM_HEAD""SOFT_PORT_COLUMN_NUM_HEAD
			""SOFT_PORT_COLUMN_NUM_HEAD""SOFT_PORT_COLUMN_NUM_HEAD"\n" , 
		"port" , "rx" , "tx" , "rx_bytes" , "tx_bytes" , "drop");


	for(portid=0; portid<MAX_PORT_NUM; portid++)
	{
		printf(SOFT_PORT_COLUMN_HEAD""SOFT_PORT_COLUMN_NUM""
				SOFT_PORT_COLUMN_NUM""SOFT_PORT_COLUMN_NUM
				""SOFT_PORT_COLUMN_NUM""SOFT_PORT_COLUMN_NUM"\n" , 
			et3k_portname[portid] , 
			et3k_total_stats[portid].rx , 
			et3k_total_stats[portid].tx ,
			et3k_total_stats[portid].rx_bytes ,
			et3k_total_stats[portid].tx_bytes  , 
			et3k_total_stats[portid].drop 

			);
	}

}

/********************** rx tx ***************************/

static void dump_no_vlan_pkt(struct rte_mbuf *mbuf)
{
	uint32_t pkt_len;
	uint32_t i;
	uint8_t *data;

	data = rte_pktmbuf_mtod(mbuf, uint8_t *);

	pkt_len = rte_pktmbuf_pkt_len(mbuf);

	for(i=0;i<pkt_len ; i++)
	{
		printf("%02x " , data[i]);

		if(i % 32 == 31)
		{
			printf("\n");
		}
	}

	printf("\n");

}
// return pannel port 
static int 
et3k_rx_pkt_handler(int dpdkport , struct rte_mbuf *mbuf )
{

	uint16_t vlan_id;
	int port_id;

	int ret;

	if(dpdkport == 0)
	{
		ret = rte_vlan_strip(mbuf);

		if(ret != 0)
		{
			dump_no_vlan_pkt(mbuf);
			rte_exit(EXIT_FAILURE , "DPDK PORT 0 receive a pkt without vlan\n");
		}

		vlan_id  = mbuf->vlan_tci;

		vlan_id &= 0xFFF;

		port_id = et3k_vlan_to_port(vlan_id);

		if(port_id <=0 || port_id >= 13)
		{
			rte_exit(EXIT_FAILURE , "DPDK PORT 0 receive a pkt with invalid vlan %d\n" , vlan_id);
		}

		return port_id;

	}
	else
	{
		if(dpdkport == 1)
		{
			//C1
			port_id = 13;
		}
		else
		{
			//C2
			port_id = 14;
		}
	}

	return port_id;
}

// return DPDK port 
static void 
et3k_tx_pkt_handler(uint16_t tx_queue , int tx_port , struct rte_mbuf *mbuf )
{
	int ret;
	uint16_t dpdkport;

	uint16_t vlan_id = et3k_port_to_vlan(tx_port);


	if(tx_port < 13)
	{
		mbuf->vlan_tci = vlan_id;

		ret = rte_vlan_insert(&mbuf);

		if(ret != 0)
		{
			rte_exit(EXIT_FAILURE , "call rte_vlan_insert failed (%d)\n" , ret);
		}

		dpdkport = 0;
	}
	else if(tx_port == 13)
	{
		dpdkport = 1;
	}
	else
	{
		dpdkport = 2;
	}

	ret = rte_eth_tx_burst(dpdkport , tx_queue , &(mbuf) , 1);

	if(ret != 1)
	{
		rte_exit(EXIT_FAILURE , "call rte_eth_tx_burst failed\n");
	}

}

/******************* main processing loop ***************/
static void
et3k_fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *mb;
	uint16_t lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;

	uint16_t dpdkport;
	int pannel_port;
	int tx_port;

	uint16_t queue_id;;
	uint16_t nb_rx;
	uint16_t pkt_i;


	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();

    queue_id = core_queue[lcore_id];

    RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u, queue_id %u, master = %u\n", lcore_id, queue_id, rte_get_main_lcore());

	while (!force_quit) {

        if (lcore_id == rte_get_main_lcore()) {
            cur_tsc = rte_rdtsc();
            diff_tsc = cur_tsc - prev_tsc;


            /* advance the timer */
            timer_tsc += diff_tsc;

            /* if timer has reached its timeout */
            if (unlikely(timer_tsc >= timer_period)) {

                /* do this only on master core */
                    print_stats();
                    /* reset the timer */
                    timer_tsc = 0;
            }

            prev_tsc = cur_tsc;


            continue;

        }

		for(dpdkport=0 ; dpdkport<3 ; dpdkport ++)
		{
			nb_rx = rte_eth_rx_burst(dpdkport , queue_id  , pkts_burst , MAX_PKT_BURST);

			for( pkt_i=0 ; pkt_i<nb_rx ; pkt_i ++)
			{
				mb = pkts_burst[pkt_i];
				pannel_port = et3k_rx_pkt_handler(dpdkport , mb);

				et3k_soft_stats[lcore_id][pannel_port - 1].rx ++;
				et3k_soft_stats[lcore_id][pannel_port - 1].rx_bytes += rte_pktmbuf_pkt_len(mb);

				tx_port = et3k_port_fwd_port[pannel_port - 1];

				if( tx_port <= 0 || tx_port > MAX_PORT_NUM )
				{
					et3k_soft_stats[lcore_id][pannel_port - 1].drop ++;
					rte_pktmbuf_free(mb);
				}
				else
				{
					et3k_soft_stats[lcore_id][tx_port - 1].tx ++;
					et3k_soft_stats[lcore_id][tx_port - 1].tx_bytes += rte_pktmbuf_pkt_len(mb);

					et3k_tx_pkt_handler(queue_id , tx_port , mb);
				}
			}
		}

        
	}
}

static int
et3k_fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	et3k_fwd_main_loop();
	return 0;
}


/******************* global init ***************/

static void
et3k_setup_portname(void)
{
	int i;
	for(i=0 ;i<MAX_PORT_NUM ; i++)
	{
		if(i<=11)
		{
			sprintf(et3k_portname[i] , "X%d" , i+1);
		}
		else
		{
			sprintf(et3k_portname[i] , "C%d" , i-12 + 1);
		}
	}
}


// 1-1 2-2 ....
static void
et3k_setup_port_fwd_default(void)
{
	int i;
	for(i=0 ;i<MAX_PORT_NUM ; i++)
	{
		et3k_port_fwd_port[i] = i+1;
	}

	printf("FWD Config : X1->X1 . X2->X2 ....\n" );

}

// "1-2;2-1;" or "1-2;2-1"
static void
et3k_setup_port_fwd_subconfig(char *config)
{
	int rx_port;
	int tx_port;
	int ret;

	ret = sscanf(config , "%d-%d" , &rx_port , &tx_port);

	if(ret != 2)
	{
		rte_exit(EXIT_FAILURE , "Invalid sub config : %s\n" , config);
	}

	if(rx_port <= 0 || rx_port > MAX_PORT_NUM)
	{
		rte_exit(EXIT_FAILURE , "Invalid rx port : %d\n" , rx_port);
	}

	if(tx_port <= 0 || tx_port > MAX_PORT_NUM)
	{
		rte_exit(EXIT_FAILURE , "Invalid tx port : %d\n" , tx_port);
	}

	et3k_port_fwd_port[rx_port - 1] = tx_port;

	printf("FWD Config : %s -> %s\n" , et3k_portname[rx_port-1] , et3k_portname[tx_port-1]);

}

static void
et3k_setup_port_fwd(char *config)
{
#define TEMP_STR_MAX_LEN 16
	char temp[TEMP_STR_MAX_LEN];

	int temp_i;
	int config_i;
	int config_len;

	temp_i = 0;

	if(config == NULL)
	{
		et3k_setup_port_fwd_default();
		return;
	}

	config_len = strlen(config);

	for(config_i=0; config_i < config_len ; config_i ++)
	{
		if(config[config_i] == ';')
		{
			temp[temp_i] = '\0';
			et3k_setup_port_fwd_subconfig(temp);
			temp_i = 0;
		}
		else
		{
			temp[temp_i] = config[config_i];
			temp_i ++;
			if(temp_i >= (TEMP_STR_MAX_LEN))
			{
				rte_exit(EXIT_FAILURE , "Invalid config : %s\n" , config);
			}
		}
	}

	if(temp_i != 0)
	{
		temp[temp_i] = '\0';
		et3k_setup_port_fwd_subconfig(temp);
	}
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(void)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
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
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
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
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t portid;
	unsigned int nb_lcores = 0;
	unsigned int nb_mbufs;
    uint32_t rx_tx_queue_cnt = 0;
	uint32_t lcore_id;
    uint8_t  queue_index = 0;

	et3k_setup_portname();

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if(argc == 1)
	{
		et3k_setup_port_fwd(NULL);
	}
	else
	{
		et3k_setup_port_fwd(argv[1]);
	}


	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	if(nb_ports != 3)
	{
		rte_exit(EXIT_FAILURE, "DPDK ports num is not 3. (num is %d)- bye\n" , nb_ports);
	}

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

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 600000U);

	/* create the mbuf pool */
	global_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (global_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, rx_tx_queue_cnt, rx_tx_queue_cnt, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);




        for(queue_index = 0 ; queue_index < rx_tx_queue_cnt ; queue_index ++ )
        {
            /* init one RX queue */
            fflush(stdout);
            rxq_conf = dev_info.default_rxconf;
            rxq_conf.offloads = local_port_conf.rxmode.offloads;
            ret = rte_eth_rx_queue_setup(portid, queue_index , nb_rxd,
                            rte_eth_dev_socket_id(portid),
                            &rxq_conf,
                            global_pktmbuf_pool);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
                    ret, portid);

            /* init one TX queue on each port */
            fflush(stdout);
            txq_conf = dev_info.default_txconf;
            txq_conf.offloads = local_port_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(portid, queue_index , nb_txd,
                    rte_eth_dev_socket_id(portid),
                    &txq_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
                    ret, portid);

        }
		
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		ret = rte_eth_promiscuous_enable(portid);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_promiscuous_enable:err=%s, port=%u\n",
				 rte_strerror(-ret), portid);
	}


	check_all_ports_link_status();

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(et3k_fwd_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {

		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}
