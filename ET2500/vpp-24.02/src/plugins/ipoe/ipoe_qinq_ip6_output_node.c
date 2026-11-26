/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

typedef enum
{
  IPOE_QINQ_IP6_ERROR_INVALID_DPO,
  IPOE_QINQ_IP6_ERROR_NO_BINDING,
  IPOE_QINQ_IP6_ERROR_SESSION_MISMATCH,
  IPOE_QINQ_IP6_ERROR_SESSION_INACTIVE,
  IPOE_QINQ_IP6_ERROR_SESSION_EXPIRED,
  IPOE_QINQ_IP6_ERROR_NO_QINQ,
  IPOE_QINQ_IP6_ERROR_NO_HEADROOM,
  IPOE_QINQ_IP6_ERROR_POLICER_DROP,
  IPOE_QINQ_IP6_N_ERROR,
} ipoe_qinq_ip6_error_t;

static char *ipoe_qinq_ip6_error_strings[] = {
  "invalid IPoE QinQ IPv6 DPO", "IPoE IPv6 binding not found",
  "IPoE QinQ IPv6 session mismatch", "inactive IPoE QinQ IPv6 session",
  "expired IPoE QinQ IPv6 session", "IPoE session has no QinQ",
  "IPoE QinQ IPv6 packet has insufficient headroom",
  "IPoE QinQ IPv6 policer drop",
};

VLIB_NODE_FN (ipoe_qinq_ip6_output_node) (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  while (n_left--)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      u32 dpo_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
      const ipoe_qinq_dpo_t *context = ipoe_qinq_dpo_get (dpo_index);
      ipoe_session_t *session = 0;
      ipoe_qinq_ip6_error_t error = IPOE_QINQ_IP6_ERROR_INVALID_DPO;
      u32 next = 1;
      u32 bytes = vlib_buffer_length_in_chain (vm, b);

      if (!context)
	goto enqueue;
      session = ipoe_ip6_binding_lookup (context->qinq_sw_if_index,
					 &ip6->dst_address, 0);
      if (!session)
	{
	  error = IPOE_QINQ_IP6_ERROR_NO_BINDING;
	  goto enqueue;
	}
      if (session->external_index != context->external_index)
	error = IPOE_QINQ_IP6_ERROR_SESSION_MISMATCH;
      else if (!session->admin_state)
	error = IPOE_QINQ_IP6_ERROR_SESSION_INACTIVE;
      else if (vlib_time_now (vm) >= session->expires_at)
	error = IPOE_QINQ_IP6_ERROR_SESSION_EXPIRED;
      else if (!session->qinq.enabled)
	error = IPOE_QINQ_IP6_ERROR_NO_QINQ;
      else if (!qinq_rewrite_two_tags (
		 b, &session->user_mac, &session->qinq.local_mac,
		 session->qinq.outer_tpid, session->qinq.outer_vlan,
		 session->qinq.inner_tpid, session->qinq.inner_vlan,
		 ETHERNET_TYPE_IP6))
	error = IPOE_QINQ_IP6_ERROR_NO_HEADROOM;
      else
	{
	  vnet_buffer (b)->sw_if_index[VLIB_TX] =
	    session->qinq.parent_sw_if_index;
	  ipoe_mark_hqos (b, session);
	  if (ipoe_session_police (vm, b, session, VLIB_TX))
	    {
	      error = IPOE_QINQ_IP6_ERROR_POLICER_DROP;
	      goto enqueue;
	    }
	  next = 0;
	  ipoe_session_counter_add (session->counter_index,
	    IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD, bytes);
	}
enqueue:
      if (next == 1)
	{
	  b->error = node->errors[error];
	  if (session && error != IPOE_QINQ_IP6_ERROR_POLICER_DROP)
	    ipoe_session_counter_add (session->counter_index,
	      IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP, bytes);
	}
      vlib_set_next_frame_buffer (vm, node, next, from[0]);
      from++;
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_qinq_ip6_output_node) = {
  .name = "ipoe-qinq-ip6-output", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPOE_QINQ_IP6_N_ERROR,
  .error_strings = ipoe_qinq_ip6_error_strings,
  .n_next_nodes = 2,
  .next_nodes = { [0] = "interface-output", [1] = "error-drop" },
};
