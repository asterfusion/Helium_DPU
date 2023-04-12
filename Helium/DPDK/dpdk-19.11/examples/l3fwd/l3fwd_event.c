/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include "l3fwd.h"
#include "l3fwd_event.h"

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static void
parse_mode(const char *optarg)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "poll", 4))
		evt_rsrc->enabled = false;
	else if (!strncmp(optarg, "eventdev", 8))
		evt_rsrc->enabled = true;
}

static void
parse_eventq_sync(const char *optarg)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "ordered", 7))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_ORDERED;
	if (!strncmp(optarg, "atomic", 6))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
	if (!strncmp(optarg, "parallel", 8))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_PARALLEL;
}

static void
l3fwd_parse_eventdev_args(char **argv, int argc)
{
	const struct option eventdev_lgopts[] = {
		{CMD_LINE_OPT_MODE, 1, 0, CMD_LINE_OPT_MODE_NUM},
		{CMD_LINE_OPT_EVENTQ_SYNC, 1, 0, CMD_LINE_OPT_EVENTQ_SYNC_NUM},
		{NULL, 0, 0, 0}
	};
	char *prgname = argv[0];
	char **argvopt = argv;
	int32_t option_index;
	int32_t opt;

	while ((opt = getopt_long(argc, argvopt, "", eventdev_lgopts,
					&option_index)) != EOF) {
		switch (opt) {
		case CMD_LINE_OPT_MODE_NUM:
			parse_mode(optarg);
			break;

		case CMD_LINE_OPT_EVENTQ_SYNC_NUM:
			parse_eventq_sync(optarg);
			break;

		default:
			print_usage(prgname);
			exit(1);
		}
	}
}

static void
l3fwd_eth_dev_port_setup(struct rte_eth_conf *port_conf)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();
	uint16_t nb_ports = rte_eth_dev_count_avail();
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	unsigned int nb_lcores = rte_lcore_count();
	struct rte_eth_conf local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	unsigned int nb_mbuf;
	uint16_t port_id;
	int32_t ret;

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		local_port_conf = *port_conf;
		/* skip ports that are not enabled */
		if ((evt_rsrc->port_mask & (1 << port_id)) == 0) {
			printf("\nSkipping disabled port %d\n", port_id);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", port_id);
		fflush(stdout);
		printf("Creating queues: nb_rxq=1 nb_txq=1...\n");

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_panic("Error during getting device (port %u) info:"
				  "%s\n", port_id, strerror(-ret));

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
						DEV_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
						dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf->rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function "
			       "based on hardware support,"
			       "requested:%#"PRIx64" configured:%#"PRIx64"\n",
			       port_id,
			       port_conf->rx_adv_conf.rss_conf.rss_hf,
			       local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%d\n",
				 ret, port_id);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n", ret, port_id);

		rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
		print_ethaddr(" Address:", &ports_eth_addr[port_id]);
		printf(", ");
		print_ethaddr("Destination:",
			(const struct rte_ether_addr *)&dest_eth_addr[port_id]);
		printf(", ");

		/* prepare source MAC for each port. */
		rte_ether_addr_copy(&ports_eth_addr[port_id],
			(struct rte_ether_addr *)(val_eth + port_id) + 1);

		/* init memory */
		if (!evt_rsrc->per_port_pool) {
			/* port_id = 0; this is *not* signifying the first port,
			 * rather, it signifies that port_id is ignored.
			 */
			nb_mbuf = RTE_MAX(nb_ports * nb_rxd +
					  nb_ports * nb_txd +
					  nb_ports * nb_lcores *
							MAX_PKT_BURST +
					  nb_lcores * MEMPOOL_CACHE_SIZE,
					  8192u);
			ret = init_mem(0, nb_mbuf);
		} else {
			nb_mbuf = RTE_MAX(nb_rxd + nb_rxd +
					  nb_lcores * MAX_PKT_BURST +
					  nb_lcores * MEMPOOL_CACHE_SIZE,
					  8192u);
			ret = init_mem(port_id, nb_mbuf);
		}
		/* init one Rx queue per port */
		rxconf = dev_info.default_rxconf;
		rxconf.offloads = local_port_conf.rxmode.offloads;
		if (!evt_rsrc->per_port_pool)
			ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, 0,
					&rxconf, evt_rsrc->pkt_pool[0][0]);
		else
			ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, 0,
					&rxconf,
					evt_rsrc->pkt_pool[port_id][0]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup: err=%d, "
				 "port=%d\n", ret, port_id);

		/* init one Tx queue per port */
		txconf = dev_info.default_txconf;
		txconf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, 0, &txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, "
				 "port=%d\n", ret, port_id);
	}
}

static void
l3fwd_event_capability_setup(void)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Invalid capability for Tx adptr port %d\n",
				 i);

		evt_rsrc->tx_mode_q |= !(caps &
				   RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (evt_rsrc->tx_mode_q)
		l3fwd_event_set_generic_ops(&evt_rsrc->ops);
	else
		l3fwd_event_set_internal_port_ops(&evt_rsrc->ops);
}

int
l3fwd_get_free_event_port(struct l3fwd_event_resources *evt_rsrc)
{
	static int index;
	int port_id;

	rte_spinlock_lock(&evt_rsrc->evp.lock);
	if (index >= evt_rsrc->evp.nb_ports) {
		printf("No free event port is available\n");
		return -1;
	}

	port_id = evt_rsrc->evp.event_p_id[index];
	index++;
	rte_spinlock_unlock(&evt_rsrc->evp.lock);

	return port_id;
}

void
l3fwd_event_resource_setup(struct rte_eth_conf *port_conf)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();
	const event_loop_cb lpm_event_loop[2][2] = {
		[0][0] = lpm_event_main_loop_tx_d,
		[0][1] = lpm_event_main_loop_tx_d_burst,
		[1][0] = lpm_event_main_loop_tx_q,
		[1][1] = lpm_event_main_loop_tx_q_burst,
	};
	const event_loop_cb em_event_loop[2][2] = {
		[0][0] = em_event_main_loop_tx_d,
		[0][1] = em_event_main_loop_tx_d_burst,
		[1][0] = em_event_main_loop_tx_q,
		[1][1] = em_event_main_loop_tx_q_burst,
	};
	uint32_t event_queue_cfg;
	int ret;

	/* Parse eventdev command line options */
	l3fwd_parse_eventdev_args(evt_rsrc->args, evt_rsrc->nb_args);
	if (!evt_rsrc->enabled)
		return;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found");

	/* Setup eventdev capability callbacks */
	l3fwd_event_capability_setup();

	/* Ethernet device configuration */
	l3fwd_eth_dev_port_setup(port_conf);

	/* Event device configuration */
	event_queue_cfg = evt_rsrc->ops.event_device_setup();

	/* Event queue configuration */
	evt_rsrc->ops.event_queue_setup(event_queue_cfg);

	/* Event port configuration */
	evt_rsrc->ops.event_port_setup();

	/* Rx/Tx adapters configuration */
	evt_rsrc->ops.adapter_setup();

	/* Start event device */
	ret = rte_event_dev_start(evt_rsrc->event_d_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	evt_rsrc->ops.lpm_event_loop = lpm_event_loop[evt_rsrc->tx_mode_q]
						       [evt_rsrc->has_burst];

	evt_rsrc->ops.em_event_loop = em_event_loop[evt_rsrc->tx_mode_q]
						       [evt_rsrc->has_burst];
}
