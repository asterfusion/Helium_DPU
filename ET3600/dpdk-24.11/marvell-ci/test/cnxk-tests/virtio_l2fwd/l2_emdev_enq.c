/* SPDX-License-Identifier: Marvell-Proprietary
 * Copyright(C) 2025 Marvell.
 */

#include <rte_rawdev.h>
#include <rte_pmd_cnxk_emdev.h>

#include "l2_node.h"

static uint16_t
l2_emdev_enqueue(struct rte_graph *graph, struct rte_node *node, void **objs,
		 uint16_t nb_objs)
{
	l2_emdev_enq_node_ctx_t *ctx = (l2_emdev_enq_node_ctx_t *)node->ctx;
	uint16_t emdev_id = ctx->emdev_id;
	uint16_t emdev_qid = ctx->emdev_qid;
	uint16_t count, nb_pkts, i, queue;
	struct rte_mbuf *mbuf;
	uint64_t context;

	i = 0;
	while (i < nb_objs) {
		mbuf = (struct rte_mbuf *)objs[i];
		nb_pkts = l2_mbuf_tx_priv1(mbuf)->nb_pkts;
		/* Even number queue in pair for Enqueue */
		queue = l2_mbuf_tx_priv1(mbuf)->tx_queue * 2;
		context = (uint64_t)emdev_qid;
		context |= (uint64_t)mbuf->port << 8;
		context |= (uint64_t)queue << 16;
		/* Enqueue to host */
		count = rte_rawdev_enqueue_buffers(emdev_id, (struct rte_rawdev_buf **)&objs[i],
						   nb_pkts, (void *)context);
		/* Redirect unsent pkts to drop node */
		if (count != nb_pkts)
			rte_node_enqueue(graph, node, 0, &objs[i + count], nb_pkts - count);
		i += nb_pkts;
	}

	return nb_objs;
}

static struct rte_node_register l2_emdev_enq_node_base = {
	.process = l2_emdev_enqueue,
	.name = "l2_emdev_enq",

	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
l2_emdev_enq_node_get(void)
{
	return &l2_emdev_enq_node_base;
}

RTE_NODE_REGISTER(l2_emdev_enq_node_base);
