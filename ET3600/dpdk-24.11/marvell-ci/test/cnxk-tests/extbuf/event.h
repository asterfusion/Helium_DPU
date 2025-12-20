/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include <rte_eventdev.h>
#include <errno.h>
#include <rte_event_timer_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_event_eth_rx_adapter.h>

struct global_event_resources {
	volatile uint8_t force_quit;
	uint8_t event_mode;
	uint8_t sched_type;
	void *evt_rsrc;
	uint8_t *keep_running;
	struct rte_mempool *x_pktmbuf_pool;
	struct rte_mempool *p_pktmbuf_pool;
	uint64_t tx_pkts;
	uint64_t pps;
	uint64_t lst_count;
	uint64_t lst_pps;
} __rte_cache_aligned;


struct event_queues {
	uint8_t *event_q_id;
	uint8_t nb_queues;
};

struct event_ports {
	uint8_t *event_p_id;
	uint8_t nb_ports;
	rte_spinlock_t lock;
};

struct event_rx_adptr {
	uint32_t service_id;
	uint8_t nb_rx_adptr;
	uint8_t *rx_adptr;
};

struct event_tx_adptr {
	uint32_t service_id;
	uint8_t nb_tx_adptr;
	uint8_t *tx_adptr;
};

struct event_resources {
	uint8_t tx_mode_q;
	uint8_t deq_depth;
	uint8_t has_burst;
	uint8_t event_d_id;
	uint8_t disable_implicit_release;
	struct event_ports evp;
	struct event_queues evq;
	struct event_rx_adptr rx_adptr;
	struct event_tx_adptr tx_adptr;
	struct rte_event_port_conf def_p_conf;
};

