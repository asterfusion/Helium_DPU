/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include "l2_node.h"

static __rte_always_inline uint16_t
l2_ethdev_dequeue_inline(struct rte_graph *graph, struct rte_node *node,
			 l2_ethdev_rx_node_ctx_t *ctx)
{
	uint16_t nb_pkts = 0, next_index, count;
	uint16_t max_pkts, max_que_per_ethdev;
	uint16_t rxq_map_count, max_q;
	struct rte_mbuf **mbufs;
	uint16_t port, queue;
	uint64_t rx_q_map;
	uint16_t q_count;

	next_index = ctx->virtio_next;
	rx_q_map = ctx->rx_q_map;
	rxq_map_count = rte_clz64(rx_q_map);
	port = ctx->eth_port;
	max_pkts = L2_ETHDEV_RX_BURST_MAX;
	max_que_per_ethdev = L2_ETHDEV_RX_Q_MAX - 1;
	max_q = max_que_per_ethdev - rxq_map_count;

	/* Get stream for pkts */
	mbufs = (struct rte_mbuf **)rte_node_next_stream_get(graph, node, next_index, max_pkts);

	q_count = __builtin_popcountl(rx_q_map);
	queue = ctx->next_q;
	while (q_count && (nb_pkts < max_pkts)) {
		if (!(rx_q_map & RTE_BIT64(queue))) {
			queue = queue > max_q ? 0 : queue + 1;
			continue;
		}

		count = RTE_MIN(L2_ETHDEV_RX_BURST_PER_Q, max_pkts - nb_pkts);
		count = rte_eth_rx_burst(port, queue, &mbufs[nb_pkts], count);
		if (likely(count)) {
			/* Update destination Tx queue and pkt count in first pkt */
			l2_mbuf_tx_priv1(mbufs[nb_pkts])->tx_queue = queue;
			l2_mbuf_tx_priv1(mbufs[nb_pkts])->nb_pkts = count;
		}

		nb_pkts += count;
		queue = queue > max_q ? 0 : queue + 1;
		q_count--;
	}
	ctx->next_q = queue;

	if (unlikely(nb_pkts == 0))
		return 0;

	/* Put pkts to next node */
	rte_node_next_stream_put(graph, node, next_index, nb_pkts);

	return nb_pkts;
}

static __rte_always_inline uint16_t
l2_ethdev_dequeue(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	l2_ethdev_rx_node_ctx_t *ctx = (l2_ethdev_rx_node_ctx_t *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = l2_ethdev_dequeue_inline(graph, node, ctx);
	return n_pkts;
}

static int
l2_ethdev_rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);
	return 0;
}

static struct rte_node_register l2_ethdev_rx_node_base = {
	.process = l2_ethdev_dequeue,
	.flags = RTE_NODE_SOURCE_F,
	.name = "l2_ethdev_rx",

	.init = l2_ethdev_rx_node_init,

	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
l2_ethdev_rx_node_get(void)
{
	return &l2_ethdev_rx_node_base;
}

RTE_NODE_REGISTER(l2_ethdev_rx_node_base);
