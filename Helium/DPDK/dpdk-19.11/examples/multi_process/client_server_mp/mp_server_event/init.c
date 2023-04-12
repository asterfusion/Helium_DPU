/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/queue.h>
#include <errno.h>
#include <stdarg.h>
#include <inttypes.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_byteorder.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>

#include "common.h"
#include "args.h"
#include "init.h"
#include "l3fwd_event.h"

#define MBUF_CACHE_SIZE 512

#define RTE_MP_RX_DESC_DEFAULT 1024
#define RTE_MP_TX_DESC_DEFAULT 1024
#define CLIENT_QUEUE_RINGSIZE 128

#define NO_FLAGS 0

/* The mbuf pool for packet rx */
struct rte_mempool *pktmbuf_pool;

uint32_t enabled_port_mask;

/* array of info/queues for clients */
struct client *clients = NULL;

/* the port details */
struct port_info *ports;

/**
 * Initialise the mbuf pool for packet reception for the NIC, and any other
 * buffer pools needed by the app - currently none.
 */
static int
init_mbuf_pools(void)
{
	const unsigned int num_mbufs_server =
		RTE_MP_RX_DESC_DEFAULT * ports->num_ports;
	const unsigned int num_mbufs_client =
		num_clients * (CLIENT_QUEUE_RINGSIZE +
			       RTE_MP_TX_DESC_DEFAULT * ports->num_ports);
	const unsigned int num_mbufs_mp_cache =
		(num_clients + 1) * MBUF_CACHE_SIZE;
	const unsigned int num_mbufs =
		num_mbufs_server + num_mbufs_client + num_mbufs_mp_cache;

	/* don't pass single-producer/single-consumer flags to mbuf create as it
	 * seems faster to use a cache instead */
	printf("Creating mbuf pool '%s' [%u mbufs] ...\n",
			PKTMBUF_POOL_NAME, num_mbufs);
	pktmbuf_pool = rte_pktmbuf_pool_create(PKTMBUF_POOL_NAME, num_mbufs,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	return pktmbuf_pool == NULL; /* 0  on success */
}



/**
 * Initialise an individual port:
 * - configure number of rx and tx rings
 * - set up each rx ring, to pull from the main mbuf pool
 * - set up each tx ring
 * - start the port and report its status to stdout
 */
int init_port_event()
{
	int retval;
	/* for port configuration all features are off by default */
	const struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS
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
	_event_resource_setup(&port_conf);
}

static int
init_port(uint16_t port_num)
{
	/* for port configuration all features are off by default */
	const struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS
		}
	};
	const uint16_t rx_rings = 1, tx_rings = num_clients;
	uint16_t rx_ring_size = RTE_MP_RX_DESC_DEFAULT;
	uint16_t tx_ring_size = RTE_MP_TX_DESC_DEFAULT;

	uint16_t q;
	int retval;

	printf("Port %u init ... ", port_num);
	fflush(stdout);


#if 0
	/* Standard DPDK port initialisation - config port, then set up
	 * rx and tx rings */
	if ((retval = rte_eth_dev_configure(port_num, rx_rings, tx_rings,
		&port_conf)) != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port_num, &rx_ring_size,
			&tx_ring_size);
	if (retval != 0)
		return retval;

	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port_num, q, rx_ring_size,
				rte_eth_dev_socket_id(port_num),
				NULL, pktmbuf_pool);
		if (retval < 0) return retval;
	}

	for ( q = 0; q < tx_rings; q ++ ) {
		retval = rte_eth_tx_queue_setup(port_num, q, tx_ring_size,
				rte_eth_dev_socket_id(port_num),
				NULL);
		if (retval < 0) return retval;
	}

#endif

	retval = rte_eth_promiscuous_enable(port_num);
	if (retval < 0)
		return retval;

	retval  = rte_eth_dev_start(port_num);
	if (retval < 0) return retval;

	printf( "done: \n");

	return 0;
}

/**
 * Set up the DPDK rings which will be used to pass packets, via
 * pointers, between the multi-process server and client processes.
 * Each client needs one RX queue.
 */
static int
init_shm_rings(void)
{
	unsigned i;
	unsigned socket_id;
	const char * q_name;
	const unsigned ringsize = CLIENT_QUEUE_RINGSIZE;

	clients = rte_malloc("client details",
		sizeof(*clients) * num_clients, 0);
	if (clients == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate memory for client program details\n");

	for (i = 0; i < num_clients; i++) {
		/* Create an RX queue for each client */
		socket_id = rte_socket_id();
		q_name = get_rx_queue_name(i);
		clients[i].rx_q = rte_ring_create(q_name,
				ringsize, socket_id,
				RING_F_SP_ENQ | RING_F_SC_DEQ ); /* single prod, single cons */
		if (clients[i].rx_q == NULL)
			rte_exit(EXIT_FAILURE, "Cannot create rx ring queue for client %u\n", i);
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
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
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << ports->id[portid])) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(ports->id[portid], &link);
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
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", ports->id[portid],
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)ports->id[portid]);
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

static inline int
l3fwd_service_enable(uint32_t service_id)
{
	uint8_t min_service_count = UINT8_MAX;
	uint32_t slcore_array[RTE_MAX_LCORE];
	unsigned int slcore = 0;
	uint8_t service_count;
	int32_t slcore_count;

	if (!rte_service_lcore_count())
    {
		return -ENOENT;
    }

	slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
	if (slcore_count < 0)
    {
		return -ENOENT;
    }
	/* Get the core which has least number of services running. */
	while (slcore_count--) {
		/* Reset default mapping */
		rte_service_map_lcore_set(service_id,
				slcore_array[slcore_count], 0);
		service_count = rte_service_lcore_count_services(
				slcore_array[slcore_count]);
		if (service_count < min_service_count) {
			slcore = slcore_array[slcore_count];
			min_service_count = service_count;
		}
	}
	if (rte_service_map_lcore_set(service_id, slcore, 1))
		return -ENOENT;
	rte_service_lcore_start(slcore);

	return 0;
}
static void
l3fwd_event_service_setup(void)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();
	struct rte_event_dev_info evdev_info;
	uint32_t service_id, caps;
	int ret, i;

	rte_event_dev_info_get(evt_rsrc->event_d_id, &evdev_info);
	if (evdev_info.event_dev_cap  & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED) {
        printf("event distributed sched!\n");
		ret = rte_event_dev_service_id_get(evt_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
				 "Error in starting eventdev service\n");
		l3fwd_service_enable(service_id);
	}

	for (i = 0; i < evt_rsrc->rx_adptr.nb_rx_adptr; i++) {
        printf("rx adptr %d\n", evt_rsrc->rx_adptr.nb_rx_adptr);
		ret = rte_event_eth_rx_adapter_caps_get(evt_rsrc->event_d_id,
				evt_rsrc->rx_adptr.rx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Failed to get Rx adapter[%d] caps\n",
				 evt_rsrc->rx_adptr.rx_adptr[i]);
		ret = rte_event_eth_rx_adapter_service_id_get(
				evt_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
				 "Error in starting Rx adapter[%d] service\n",
				 evt_rsrc->rx_adptr.rx_adptr[i]);
		l3fwd_service_enable(service_id);
	}

	for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++) {
        printf("tx adptr %d\n", evt_rsrc->tx_adptr.nb_tx_adptr);
		ret = rte_event_eth_tx_adapter_caps_get(evt_rsrc->event_d_id,
				evt_rsrc->tx_adptr.tx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Failed to get Rx adapter[%d] caps\n",
				 evt_rsrc->tx_adptr.tx_adptr[i]);
		ret = rte_event_eth_tx_adapter_service_id_get(
				evt_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
				 "Error in starting Rx adapter[%d] service\n",
				 evt_rsrc->tx_adptr.tx_adptr[i]);
		l3fwd_service_enable(service_id);
	}
}
/**
 * Main init function for the multi-process server app,
 * calls subfunctions to do each stage of the initialisation.
 */
int
init(int argc, char *argv[])
{
	int retval;
	const struct rte_memzone *mz;
	uint16_t i;

	/* init EAL, parsing EAL args */
	retval = rte_eal_init(argc, argv);
	if (retval < 0)
		return -1;
	argc -= retval;
	argv += retval;

	/* set up array for port data */
	mz = rte_memzone_reserve(MZ_PORT_INFO, sizeof(*ports),
				rte_socket_id(), NO_FLAGS);
	if (mz == NULL)
		rte_exit(EXIT_FAILURE, "Cannot reserve memory zone for port information\n");
	memset(mz->addr, 0, sizeof(*ports));
	ports = mz->addr;

	/* parse additional, application arguments */
	retval = parse_app_args(argc, argv);
	if (retval != 0)
		return -1;

	/* initialise mbuf pools */
	retval = init_mbuf_pools();
	if (retval != 0)
		rte_exit(EXIT_FAILURE, "Cannot create needed mbuf pools\n");

    init_port_event();
	/* now initialise the ports we will use */
	for (i = 0; i < ports->num_ports; i++) {
		retval = init_port(ports->id[i]);
		if (retval != 0)
			rte_exit(EXIT_FAILURE, "Cannot initialise port %u\n",
					(unsigned)i);
	}

    l3fwd_event_service_setup();

	check_all_ports_link_status(ports->num_ports, (~0x0));

	/* initialise the client queues/rings for inter-eu comms */
	init_shm_rings();

	return 0;
}
