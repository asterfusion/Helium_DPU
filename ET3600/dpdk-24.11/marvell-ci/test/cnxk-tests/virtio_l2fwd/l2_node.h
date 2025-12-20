/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_L2_NODE_H__
#define __INCLUDE_L2_NODE_H__

#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#define STATIC_ASSERT(s) _Static_assert(s, #s)

typedef struct l2_ethdev_rx_node_ctx {
	uint64_t rx_q_map;
	uint16_t eth_port;
	uint16_t rx_q_count;
	uint8_t virtio_next;
	uint8_t next_q;
	uint8_t emdev_id;
	uint8_t func_id;
} l2_ethdev_rx_node_ctx_t;

typedef struct l2_ethdev_tx_node_ctx {
	uint64_t eth_port;
} l2_ethdev_tx_node_ctx_t;

typedef struct l2_emdev_deq_node_ctx {
	uint16_t eth_next;
	uint16_t emdev_id;
	uint16_t emdev_qid;
} l2_emdev_deq_node_ctx_t;

typedef struct l2_emdev_enq_node_ctx {
	uint16_t emdev_id;
	uint16_t emdev_qid;
} l2_emdev_enq_node_ctx_t;

STATIC_ASSERT(sizeof(l2_emdev_deq_node_ctx_t) <= RTE_NODE_CTX_SZ);
STATIC_ASSERT(sizeof(l2_emdev_enq_node_ctx_t) <= RTE_NODE_CTX_SZ);
STATIC_ASSERT(sizeof(l2_ethdev_rx_node_ctx_t) <= RTE_NODE_CTX_SZ);
STATIC_ASSERT(sizeof(l2_ethdev_tx_node_ctx_t) <= RTE_NODE_CTX_SZ);

/**
 * Node mbuf private data to store dest queue.
 */
struct l2_mbuf_tx_priv1 {
	union {
		struct {
			uint16_t tx_queue;
			uint16_t nb_pkts;
		};
		uint32_t u;
	};
};

#define L2_ETHDEV_RX_BURST_PER_Q 64
#define L2_ETHDEV_RX_Q_MAX       64
#define L2_ETHDEV_RX_BURST_MAX   128

#define L2_EMDEV_DEQ_BURST_MAX   128

/**
 * Get mbuf_priv1 pointer from rte_mbuf.
 *
 * @param
 *   Pointer to the rte_mbuf.
 *
 * @return
 *   Pointer to the mbuf_priv1.
 */
static __rte_always_inline struct l2_mbuf_tx_priv1 *
l2_mbuf_tx_priv1(struct rte_mbuf *m)
{
	return (struct l2_mbuf_tx_priv1 *)&m->hash.txadapter.reserved2;
}

/* Space in mbuf txadapter area post rss reserved only 32B */
STATIC_ASSERT(sizeof(struct l2_mbuf_tx_priv1) <= 4);

struct rte_node_register *l2_emdev_deq_node_get(void);
struct rte_node_register *l2_emdev_enq_node_get(void);
struct rte_node_register *l2_ethdev_rx_node_get(void);
struct rte_node_register *l2_ethdev_tx_node_get(void);

#endif /* __INCLUDE_L2_NODE_H__ */
