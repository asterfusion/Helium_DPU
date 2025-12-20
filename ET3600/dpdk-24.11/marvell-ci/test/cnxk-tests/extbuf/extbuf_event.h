/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "event.h"

static __rte_always_inline struct global_event_resources *
glb_event_get_rsrc(void)
{
	static const char name[RTE_MEMZONE_NAMESIZE] = "rsrc";
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(name);
	if (mz != NULL)
		return mz->addr;

	mz = rte_memzone_reserve(name,
			sizeof(struct global_event_resources), 0, 0);
	if (mz != NULL) {
		struct global_event_resources *rsrc = mz->addr;

		memset(rsrc, 0, sizeof(struct global_event_resources));
		rsrc->event_mode = true;
		rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
		return mz->addr;
	}

	rte_panic("Unable to allocate memory for event resources\n");

	return NULL;
}

static void
mempool_initialize(struct global_event_resources *rsrc, uint32_t nb_ports)
{
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
#define MAX_PKT_BURST_T 64
#define MEMPOOL_CACHE_SIZE_T 256
	uint32_t nb_mbufs;

	nb_mbufs = RTE_MAX(nb_ports * (RTE_TEST_RX_DESC_DEFAULT +
				RTE_TEST_TX_DESC_DEFAULT +
				MAX_PKT_BURST_T + rte_lcore_count() *
				MEMPOOL_CACHE_SIZE_T), rte_lcore_count()*8192U);

	rsrc->x_pktmbuf_pool = rte_pktmbuf_pool_create("x_mbuf_pool",
			nb_mbufs, MEMPOOL_CACHE_SIZE_T, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (rsrc->x_pktmbuf_pool == NULL)
		rte_panic("Cannot init x_mbuf pool\n");

	rsrc->p_pktmbuf_pool = rte_pktmbuf_pool_create("p_mbuf_pool",
			nb_mbufs, MEMPOOL_CACHE_SIZE_T, 0,
			RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (rsrc->p_pktmbuf_pool == NULL)
		rte_panic("Cannot init x_mbuf pool\n");
}

static void
event_capability_setup(void)
{
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_panic("Invalid capability for Tx adptr port %d\n",
					i);
	}
}

static uint32_t
event_device_setup_internal_port(struct global_event_resources *rsrc)
{
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;
	struct rte_event_dev_config event_d_conf = {
		.nb_events_limit  = 4096,
		.nb_event_queue_flows = 1024,
		.nb_event_port_dequeue_depth = 128,
		.nb_event_port_enqueue_depth = 128
	};
	struct rte_event_dev_info dev_info;
	const uint8_t event_d_id = 0; /* Always use first event device only */
	uint32_t event_queue_cfg = 0;
	uint16_t ethdev_count = 0;
	uint16_t num_workers = 0;
	uint16_t port_id;
	int ret;

	RTE_ETH_FOREACH_DEV(port_id) {
		ethdev_count++;
	}

	rte_event_dev_info_get(event_d_id, &dev_info);

	/* Enable implicit release */
	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE)
		evt_rsrc->disable_implicit_release = 0;

	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
		event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

	event_d_conf.nb_event_queues = ethdev_count;
	if (dev_info.max_event_queues < event_d_conf.nb_event_queues)
		event_d_conf.nb_event_queues = dev_info.max_event_queues;

	if (dev_info.max_num_events < event_d_conf.nb_events_limit)
		event_d_conf.nb_events_limit = dev_info.max_num_events;

	if (dev_info.max_event_queue_flows < event_d_conf.nb_event_queue_flows)
		event_d_conf.nb_event_queue_flows =
			dev_info.max_event_queue_flows;

	if (dev_info.max_event_port_dequeue_depth <
			event_d_conf.nb_event_port_dequeue_depth)
		event_d_conf.nb_event_port_dequeue_depth =
			dev_info.max_event_port_dequeue_depth;
	if (dev_info.max_event_port_enqueue_depth <
			event_d_conf.nb_event_port_enqueue_depth)
		event_d_conf.nb_event_port_enqueue_depth =
			dev_info.max_event_port_enqueue_depth;

	/* Ignore Main core. */
	num_workers = rte_lcore_count() - 1;
	if (dev_info.max_event_ports < num_workers)
		num_workers = dev_info.max_event_ports;

	event_d_conf.nb_event_ports = num_workers;
	evt_rsrc->evp.nb_ports = num_workers;
	evt_rsrc->evq.nb_queues = event_d_conf.nb_event_queues;
	evt_rsrc->has_burst = !!(dev_info.event_dev_cap &
			RTE_EVENT_DEV_CAP_BURST_MODE);

	ret = rte_event_dev_configure(event_d_id, &event_d_conf);
	if (ret < 0)
		rte_panic("Error in configuring event device\n");

	evt_rsrc->event_d_id = event_d_id;
	return event_queue_cfg;
}

static void
event_queue_setup_internal_port(struct global_event_resources *rsrc,
				uint32_t event_queue_cfg)
{
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;
	uint8_t event_d_id = evt_rsrc->event_d_id;
	struct rte_event_queue_conf event_q_conf = {
		.nb_atomic_flows = 1024,
		.nb_atomic_order_sequences = 1024,
		.event_queue_cfg = event_queue_cfg,
		.priority = RTE_EVENT_DEV_PRIORITY_NORMAL
	};
	struct rte_event_queue_conf def_q_conf;
	uint8_t event_q_id = 0;
	int32_t ret;

	ret = rte_event_queue_default_conf_get(event_d_id, event_q_id,
			&def_q_conf);
	if (ret < 0)
		rte_panic("Error to get default config of event queue\n");

	if (def_q_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
		event_q_conf.nb_atomic_flows = def_q_conf.nb_atomic_flows;

	if (def_q_conf.nb_atomic_order_sequences <
			event_q_conf.nb_atomic_order_sequences)
		event_q_conf.nb_atomic_order_sequences =
			def_q_conf.nb_atomic_order_sequences;

	event_q_conf.event_queue_cfg = event_queue_cfg;
	event_q_conf.schedule_type = rsrc->sched_type;
	evt_rsrc->evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
			evt_rsrc->evq.nb_queues);
	if (!evt_rsrc->evq.event_q_id)
		rte_panic("Memory allocation failure\n");

	for (event_q_id = 0; event_q_id < evt_rsrc->evq.nb_queues;
			event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
				&event_q_conf);
		if (ret < 0)
			rte_panic("Error in configuring event queue\n");
		evt_rsrc->evq.event_q_id[event_q_id] = event_q_id;
	}
}


static void
event_port_setup_internal_port(struct global_event_resources *rsrc)
{
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;
	uint8_t event_d_id = evt_rsrc->event_d_id;
	struct rte_event_port_conf event_p_conf = {
		.dequeue_depth = 32,
		.enqueue_depth = 32,
		.new_event_threshold = 4096
	};
	struct rte_event_port_conf def_p_conf;
	uint8_t event_p_id;
	int32_t ret;

	evt_rsrc->evp.event_p_id = (uint8_t *)malloc(sizeof(uint8_t) *
			evt_rsrc->evp.nb_ports);

	if (!evt_rsrc->evp.event_p_id)
		rte_panic("Failed to allocate memory for Event Ports\n");

	ret = rte_event_port_default_conf_get(event_d_id, 0, &def_p_conf);
	if (ret < 0)
		rte_panic("Error to get default configuration of event port\n");

	if (def_p_conf.new_event_threshold < event_p_conf.new_event_threshold)
		event_p_conf.new_event_threshold =
			def_p_conf.new_event_threshold;

	if (def_p_conf.dequeue_depth < event_p_conf.dequeue_depth)
		event_p_conf.dequeue_depth = def_p_conf.dequeue_depth;

	if (def_p_conf.enqueue_depth < event_p_conf.enqueue_depth)
		event_p_conf.enqueue_depth = def_p_conf.enqueue_depth;

	event_p_conf.event_port_cfg = 0;
	if (evt_rsrc->disable_implicit_release)
		event_p_conf.event_port_cfg |=
			RTE_EVENT_PORT_CFG_DISABLE_IMPL_REL;

	for (event_p_id = 0; event_p_id < evt_rsrc->evp.nb_ports;
			event_p_id++) {
		ret = rte_event_port_setup(event_d_id, event_p_id,
				&event_p_conf);
		if (ret < 0)
			rte_panic("Error in configuring event port %d\n",
					event_p_id);

		ret = rte_event_port_link(event_d_id, event_p_id, NULL,
				NULL, 0);
		if (ret < 0)
			rte_panic("Error in linking event port %d to queue\n",
					event_p_id);
		evt_rsrc->evp.event_p_id[event_p_id] = event_p_id;

		/* init spinlock */
		rte_spinlock_init(&evt_rsrc->evp.lock);
	}
	evt_rsrc->def_p_conf = event_p_conf;
}


static void
tx_adapter_setup_internal_port(struct global_event_resources *rsrc)
{
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;
	uint8_t event_d_id = evt_rsrc->event_d_id;
	uint16_t adapter_id = 0;
	uint16_t nb_adapter = 0;
	uint16_t port_id;
	int ret;

	RTE_ETH_FOREACH_DEV(port_id) {
		nb_adapter++;
	}

	evt_rsrc->tx_adptr.nb_tx_adptr = nb_adapter;
	evt_rsrc->tx_adptr.tx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
			evt_rsrc->tx_adptr.nb_tx_adptr);

	if (!evt_rsrc->tx_adptr.tx_adptr) {
		free(evt_rsrc->rx_adptr.rx_adptr);
		free(evt_rsrc->evp.event_p_id);
		free(evt_rsrc->evq.event_q_id);
		rte_panic("Failed to allocate memory for Rx adapter\n");
	}

	adapter_id = 0;
	RTE_ETH_FOREACH_DEV(port_id) {
		ret = rte_event_eth_tx_adapter_create(adapter_id, event_d_id,
				&evt_rsrc->def_p_conf);
		if (ret)
			rte_panic("Failed to create tx adapter[%d]\n",
					adapter_id);

		ret = rte_event_eth_tx_adapter_queue_add(adapter_id, port_id,
				-1);
		if (ret)
			rte_panic("Failed to add queues to Tx adapter\n");

		ret = rte_event_eth_tx_adapter_start(adapter_id);
		if (ret)
			rte_panic("Tx adapter[%d] start Failed\n", adapter_id);

		evt_rsrc->tx_adptr.tx_adptr[adapter_id] = adapter_id;
		adapter_id++;
	}
}

static void
event_resource_setup(struct global_event_resources *rsrc)
{
	struct event_resources *evt_rsrc;
	uint32_t event_queue_cfg;
	int ret;

	if (!rte_event_dev_count())
		rte_panic("No Eventdev found\n");

	evt_rsrc = rte_zmalloc("event",
			sizeof(struct event_resources), 0);
	if (evt_rsrc == NULL)
		rte_panic("Failed to allocate memory\n");

	rsrc->evt_rsrc = evt_rsrc;

	event_capability_setup();
	event_queue_cfg = event_device_setup_internal_port(rsrc);
	event_queue_setup_internal_port(rsrc, event_queue_cfg);
	event_port_setup_internal_port(rsrc);
	tx_adapter_setup_internal_port(rsrc);

	ret = rte_event_dev_start(evt_rsrc->event_d_id);

	if (ret < 0)
		rte_panic("Error in starting eventdev\n");
}

static inline int
event_service_enable(uint32_t service_id)
{
	uint8_t min_service_count = UINT8_MAX;
	uint32_t slcore_array[RTE_MAX_LCORE];
	unsigned int slcore = 0;
	uint8_t service_count;
	int32_t slcore_count;

	if (!rte_service_lcore_count())
		return -ENOENT;

	slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
	if (slcore_count < 0)
		return -ENOENT;
	/* Get the core which has least number of services running. */
	while (slcore_count--) {
		/* Reset default mapping */
		if (rte_service_map_lcore_set(service_id,
					slcore_array[slcore_count], 0) != 0)
			return -ENOENT;
		service_count = rte_service_lcore_count_services(
				slcore_array[slcore_count]);
		if (service_count < min_service_count) {
			slcore = slcore_array[slcore_count];
			min_service_count = service_count;
		}
	}
	if (rte_service_map_lcore_set(service_id, slcore, 1) != 0)
		return -ENOENT;
	rte_service_lcore_start(slcore);

	return 0;
}

static __rte_noinline int
get_free_event_port(struct event_resources *evt_rsrc)
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

static void
setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr,
			struct rte_udp_hdr *udp_hdr, uint16_t pkt_data_len,
			uint8_t port, uint8_t flow)
{
#define IP_DEFTTL  64
	uint16_t tx_udp_src_port = 9;
	uint16_t tx_udp_dst_port = 9;
	uint32_t tx_ip_src_addr = (198U << 24) | (18 << 16) | (0 << 8) | 1;
	uint32_t tx_ip_dst_addr = (198U << 24) | (18 << 16) | (0 << 8) | 2;


	uint16_t *ptr16;
	uint32_t ip_cksum;
	uint16_t pkt_len;

	RTE_SET_USED(port);
	RTE_SET_USED(flow);

	/*
	 * Initialize UDP header.
	 */
	pkt_len = (uint16_t) (pkt_data_len + sizeof(struct rte_udp_hdr));
	udp_hdr->src_port = rte_cpu_to_be_16(tx_udp_src_port);
	udp_hdr->dst_port = rte_cpu_to_be_16(tx_udp_dst_port);
	/*udp_hdr->dgram_len      = RTE_CPU_TO_BE_16(pkt_len);*/
	udp_hdr->dgram_len      = pkt_len;
	udp_hdr->dgram_cksum    = 0; /* No UDP checksum. */

	/*
	 * Initialize IP header.
	 */
	pkt_len = (uint16_t) (pkt_len + sizeof(struct rte_ipv4_hdr));
	ip_hdr->version_ihl   = RTE_IPV4_VHL_DEF;
	ip_hdr->type_of_service   = 0;
	ip_hdr->fragment_offset = 0;
	ip_hdr->time_to_live   = IP_DEFTTL;
	ip_hdr->next_proto_id = IPPROTO_UDP;
	ip_hdr->packet_id = 0;
	/*ip_hdr->total_length   = RTE_CPU_TO_BE_16(pkt_len);*/
	ip_hdr->total_length   = pkt_len;
	ip_hdr->src_addr = rte_cpu_to_be_32(tx_ip_src_addr);
	ip_hdr->dst_addr = rte_cpu_to_be_32(tx_ip_dst_addr);

	/*
	 * Compute IP header checksum.
	 */
	ptr16 = (unaligned_uint16_t *) ip_hdr;
	ip_cksum = 0;
	ip_cksum += ptr16[0]; ip_cksum += ptr16[1];
	ip_cksum += ptr16[2]; ip_cksum += ptr16[3];
	ip_cksum += ptr16[4];
	ip_cksum += ptr16[6]; ip_cksum += ptr16[7];
	ip_cksum += ptr16[8]; ip_cksum += ptr16[9];
	/*
	 * Reduce 32 bit checksum to 16 bits and complement it.
	 */
	ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) +
		(ip_cksum & 0x0000FFFF);
	if (ip_cksum > 65535)
		ip_cksum -= 65535;
	ip_cksum = (~ip_cksum) & 0x0000FFFF;
	if (ip_cksum == 0)
		ip_cksum = 0xFFFF;
	ip_hdr->hdr_checksum = (uint16_t) ip_cksum;
}

static void
fill_event(struct global_event_resources *rsrc,
		struct rte_mbuf *mbuf, struct rte_event *ev)
{
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;

	ev->event = 0;
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->queue_id =
		evt_rsrc->evq.event_q_id[evt_rsrc->evq.nb_queues - 1];
	ev->sched_type = RTE_SCHED_TYPE_ATOMIC;
	ev->priority = RTE_EVENT_DEV_PRIORITY_NORMAL;
	ev->event_type =  RTE_EVENT_TYPE_CPU;
	ev->sub_event_type = 0; /* stage 0 */

	ev->mbuf = mbuf;
}

static void
free_cb_event_compl(void *addr, void *opaque)
{
	struct rte_mbuf *m = (struct rte_mbuf *)addr;
	rte_mbuf_refcnt_set(m, 1);
	rte_pktmbuf_free_seg(m);
	RTE_SET_USED(opaque);
}


static void
init_shinfo_event_compl(struct rte_mbuf_ext_shared_info *s)
{
	s->free_cb = free_cb_event_compl;
	s->fcb_opaque = NULL;
	rte_mbuf_ext_refcnt_set(s, 1);
}

static int
initialize_pkts(struct global_event_resources *rsrc, struct rte_event *ev)
{

#define TX_DEF_PACKET_LEN 64
#define UDP_SRC_PORT 9
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
	struct rte_ether_hdr eth_hdr;
	struct rte_ipv4_hdr ip_hdr;
	struct rte_udp_hdr udp_hdr;
	struct rte_udp_hdr *pkt_udp_hdr;
	uint16_t pkt_sz = TX_DEF_PACKET_LEN;
	uint16_t eth_port_id = 0;

	struct rte_mbuf *mbuf, *ext_mbuf;
	struct rte_mbuf_ext_shared_info s;

	mbuf = rte_pktmbuf_alloc(rsrc->x_pktmbuf_pool);
	if (mbuf == NULL)
		return -1;

	ext_mbuf = rte_pktmbuf_alloc(rsrc->p_pktmbuf_pool);
	if (ext_mbuf == NULL)
		return -1;
	ext_mbuf->next = NULL;
	ext_mbuf->data_off = 64;
	ext_mbuf->data_len = sizeof(struct rte_mbuf);
	ext_mbuf->pkt_len = sizeof(struct rte_mbuf);
	init_shinfo_event_compl(&s);
	rte_pktmbuf_attach_extbuf(
			mbuf, ext_mbuf, (uint64_t)ext_mbuf,
			sizeof(struct rte_mbuf), &s);

	RTE_ETH_FOREACH_DEV(eth_port_id) {

		rte_eth_macaddr_get(eth_port_id, &dst_mac);
		rte_eth_random_addr((uint8_t *)&src_mac);
		rte_ether_addr_copy(&dst_mac, &eth_hdr.dst_addr);
		rte_ether_addr_copy(&src_mac, &eth_hdr.src_addr);
		eth_hdr.ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

		setup_pkt_udp_ip_headers(
				&ip_hdr, &udp_hdr,
				pkt_sz - sizeof(struct rte_ether_hdr) -
				sizeof(struct rte_ipv4_hdr) -
				sizeof(struct rte_udp_hdr),
				eth_port_id, 1);

		mbuf->port = eth_port_id;
		mbuf->data_len = pkt_sz;
		mbuf->pkt_len = pkt_sz;


		/* Copy Ethernet header */
		rte_memcpy(rte_pktmbuf_mtod_offset(mbuf, char *, 0),
				&eth_hdr, sizeof(struct rte_ether_hdr));

		/* Copy Ipv4 header */
		rte_memcpy(rte_pktmbuf_mtod_offset(
					mbuf, char *,
					sizeof(struct rte_ether_hdr)),
				&ip_hdr, sizeof(struct rte_ipv4_hdr));

		/* Copy UDP header */
		rte_memcpy(rte_pktmbuf_mtod_offset(
					mbuf, char *,
					sizeof(struct rte_ipv4_hdr) +
					sizeof(struct rte_ether_hdr)),
				&udp_hdr, sizeof(struct rte_udp_hdr));

		pkt_udp_hdr = rte_pktmbuf_mtod_offset(
				mbuf, struct rte_udp_hdr *,
				sizeof(struct rte_ipv4_hdr) +
				sizeof(struct rte_ether_hdr));
		pkt_udp_hdr->src_port =
			rte_cpu_to_be_16(UDP_SRC_PORT + 0);
		pkt_udp_hdr->dst_port =
			rte_cpu_to_be_16(UDP_SRC_PORT + 0);
	}

	fill_event(rsrc, mbuf, ev);
	return 0;
}


static int
event_loop_single(void *args)
{
	struct global_event_resources *rsrc = args;
	struct event_resources *evt_rsrc = rsrc->evt_rsrc;
	const int port_id = get_free_event_port(evt_rsrc);
	const uint8_t event_d_id = evt_rsrc->event_d_id;
	uint8_t enq = 0;
	struct rte_event ev;

	if (port_id < 0)
		return -1;

	while (*(rsrc->keep_running)) {
		if (initialize_pkts(rsrc, &ev) < 0)
			continue;
		enq = rte_event_eth_tx_adapter_enqueue(
				event_d_id, port_id, &ev, 1, 0);
		__atomic_fetch_add(&rsrc->tx_pkts, enq, __ATOMIC_RELAXED);
		rte_delay_ms(1);
	}
	return 0;
}

static void
finalize_event(struct global_event_resources *rsrc)
{
	int i;
	struct global_event_resources *rsrcs = rsrc;
	struct event_resources *evt_rsrc =
		rsrcs->evt_rsrc;

	for (i = 0; i < evt_rsrc->tx_adptr.nb_tx_adptr; i++)
		rte_event_eth_tx_adapter_stop(
				evt_rsrc->tx_adptr.tx_adptr[i]);

	rte_event_dev_stop(evt_rsrc->event_d_id);
	rte_event_dev_close(evt_rsrc->event_d_id);
	rte_mempool_free(rsrcs->x_pktmbuf_pool);
	rte_mempool_free(rsrcs->p_pktmbuf_pool);
}

static struct global_event_resources *
initialize_event(uint8_t nb_ports)
{
	struct global_event_resources *rsrc;

	rsrc = glb_event_get_rsrc();
	mempool_initialize(rsrc, nb_ports);
	event_resource_setup(rsrc);

	return rsrc;
}



