/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include <rte_rawdev.h>

#include "l2_node.h"

static __rte_always_inline uint16_t
l2_emdev_dequeue_inline(struct rte_graph *graph, struct rte_node *node,
			l2_emdev_deq_node_ctx_t *ctx)
{
	struct rte_mbuf *mbufs[L2_EMDEV_DEQ_BURST_MAX];
	uint16_t nb_pkts = 0, count;
	uint16_t idx = 0, i, curr_q, next_q;
	uint16_t emdev_qid = ctx->emdev_qid;
	uint16_t emdev_id = ctx->emdev_id;
	uint16_t next_func, curr_func;
	uint16_t max_pkts;

	/* Do an enqueue flush to push previous pkts out.
	 * Do we need separate enqueue flush node ?
	 */
	rte_rawdev_enqueue_buffers(emdev_id, NULL, 0, (void *)(uintptr_t)emdev_qid);

	max_pkts = L2_EMDEV_DEQ_BURST_MAX;

	/* Dequeue packets from a given emdev queue */
	nb_pkts = rte_rawdev_dequeue_buffers(emdev_id, (void *)mbufs, max_pkts,
					     (void *)(uintptr_t)emdev_qid);
	if (unlikely(nb_pkts == 0))
		return 0;

	count = 1;
	curr_q = (mbufs[idx])->hash.fdir.id / 2;
	curr_func = (mbufs[idx])->port & 0xFF;
	for (i = 1; i < nb_pkts; i++) {
		next_func = (mbufs[i])->port & 0xFF;
		next_q = (mbufs[i])->hash.fdir.id / 2;
		if (next_func != curr_func || next_q != curr_q) {
			/* Update destination Tx queue and pkt count in first pkt */
			l2_mbuf_tx_priv1(mbufs[idx])->nb_pkts = count;
			l2_mbuf_tx_priv1(mbufs[idx])->tx_queue = curr_q;
			if (next_func != curr_func) {
				rte_node_enqueue(graph, node, ctx->eth_next + curr_func,
						 (void **)&mbufs[idx], count);
				curr_func = next_func;
			}
			curr_q = next_q;
			idx = i;
			count = 0;
		}
		count++;
	}

	l2_mbuf_tx_priv1(mbufs[idx])->nb_pkts = count;
	l2_mbuf_tx_priv1(mbufs[idx])->tx_queue = curr_q;

	rte_node_enqueue(graph, node, ctx->eth_next + curr_func, (void **)&mbufs[idx], count);

	return nb_pkts;
}

static __rte_always_inline uint16_t
l2_emdev_dequeue(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t cnt)
{
	l2_emdev_deq_node_ctx_t *ctx = (l2_emdev_deq_node_ctx_t *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = l2_emdev_dequeue_inline(graph, node, ctx);
	return n_pkts;
}

static int
l2_emdev_deq_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	return 0;
}

static struct rte_node_register l2_emdev_deq_node_base = {
	.process = l2_emdev_dequeue,
	.flags = RTE_NODE_SOURCE_F,
	.name = "l2_emdev_deq",

	.init = l2_emdev_deq_node_init,

	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
l2_emdev_deq_node_get(void)
{
	return &l2_emdev_deq_node_base;
}

RTE_NODE_REGISTER(l2_emdev_deq_node_base);
