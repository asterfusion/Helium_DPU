/* SPDX-License-Identifier: Apache-2.0 */

#include <ipoe/ipoe.h>

typedef enum
{
  IPOE_QINQ_OUTPUT_NEXT_INTERFACE_OUTPUT,
  IPOE_QINQ_OUTPUT_NEXT_DROP,
  IPOE_QINQ_OUTPUT_N_NEXT,
} ipoe_qinq_output_next_t;

typedef enum
{
  IPOE_QINQ_OUTPUT_ERROR_NO_SESSION,
  IPOE_QINQ_OUTPUT_ERROR_SESSION_INACTIVE,
  IPOE_QINQ_OUTPUT_ERROR_NO_QINQ,
  IPOE_QINQ_OUTPUT_ERROR_INVALID_DPO,
  IPOE_QINQ_OUTPUT_ERROR_SESSION_MISMATCH,
  IPOE_QINQ_OUTPUT_ERROR_ACCESS_MISMATCH,
  IPOE_QINQ_OUTPUT_ERROR_NO_HEADROOM,
  IPOE_QINQ_OUTPUT_N_ERROR,
} ipoe_qinq_output_error_t;

static char *ipoe_qinq_output_error_strings[] = {
  "IPoE QinQ session not found",
  "IPoE QinQ session is inactive",
  "IPoE session has no QinQ encapsulation",
  "IPoE QinQ DPO context is invalid",
  "IPoE QinQ DPO session mismatch",
  "IPoE QinQ session access mismatch",
  "IPoE QinQ packet has insufficient headroom",
};

typedef struct
{
  u32 dpo_index;
  u32 fib_index;
  u32 qinq_sw_if_index;
  u32 parent_sw_if_index;
  ip4_address_t dst_ip;
  u64 dpo_external_index;
  u64 session_external_index;
  u16 outer_vlan;
  u16 inner_vlan;
  u8 error;
} ipoe_qinq_output_trace_t;

static u8 *
format_ipoe_qinq_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  ipoe_qinq_output_trace_t *trace =
    va_arg (*args, ipoe_qinq_output_trace_t *);
  const char *result = trace->error == (u8) ~0 ?
		       "forward" : ipoe_qinq_output_error_strings[trace->error];

  return format (s, "ipoe-qinq-output: dpo %u fib %u dpo-session %llu "
		 "interface %u parent %u dst %U session %llu vlan %u/%u "
		 "result %s",
		 trace->dpo_index, trace->fib_index,
		 trace->dpo_external_index,
		 trace->qinq_sw_if_index, trace->parent_sw_if_index,
		 format_ip4_address, &trace->dst_ip,
		 trace->session_external_index,
		 trace->outer_vlan, trace->inner_vlan, result);
}

VLIB_NODE_FN (ipoe_qinq_output_node) (vlib_main_t *vm,
			      vlib_node_runtime_t *node,
			      vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left)
    {
      u32 *to_next;
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left && n_left_to_next)
	{
	  u32 bi = from[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);
	  u32 dpo_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
	  const ipoe_qinq_dpo_t *context = ipoe_qinq_dpo_get (dpo_index);
	  u32 qinq_sw_if_index = context ? context->qinq_sw_if_index : ~0;
	  ipoe_qinq_output_next_t next = IPOE_QINQ_OUTPUT_NEXT_DROP;
	  ipoe_qinq_output_error_t error = context ?
	    IPOE_QINQ_OUTPUT_ERROR_NO_SESSION :
	    IPOE_QINQ_OUTPUT_ERROR_INVALID_DPO;
	  ipoe_downstream_lookup_result_t lookup_result;
	  ipoe_session_t *session = 0;
	  u32 packet_bytes = vlib_buffer_length_in_chain (vm, b);

	  if (context)
	    {
	      session = ipoe_session_lookup_downstream (
		qinq_sw_if_index, &ip4->dst_address, context->external_index, 1,
		&lookup_result);
	      if (lookup_result == IPOE_DOWNSTREAM_LOOKUP_NO_SESSION)
		error = IPOE_QINQ_OUTPUT_ERROR_NO_SESSION;
	      else if (lookup_result == IPOE_DOWNSTREAM_LOOKUP_SESSION_INACTIVE)
		error = IPOE_QINQ_OUTPUT_ERROR_SESSION_INACTIVE;
	      else if (lookup_result ==
		       IPOE_DOWNSTREAM_LOOKUP_SESSION_MISMATCH)
		error = IPOE_QINQ_OUTPUT_ERROR_SESSION_MISMATCH;
	      else if (lookup_result == IPOE_DOWNSTREAM_LOOKUP_ACCESS_MISMATCH)
		error = IPOE_QINQ_OUTPUT_ERROR_ACCESS_MISMATCH;
	      else if (!session->qinq.enabled)
		error = IPOE_QINQ_OUTPUT_ERROR_NO_QINQ;
	      else
		{
		  if (!qinq_rewrite_two_tags (
			b, &session->user_mac, &session->qinq.local_mac,
			session->qinq.outer_tpid, session->qinq.outer_vlan,
			session->qinq.inner_tpid, session->qinq.inner_vlan,
			ETHERNET_TYPE_IP4))
		    {
		      error = IPOE_QINQ_OUTPUT_ERROR_NO_HEADROOM;
		      goto trace_and_enqueue;
		    }
		  vnet_buffer (b)->sw_if_index[VLIB_TX] =
		    session->qinq.parent_sw_if_index;
		  next = IPOE_QINQ_OUTPUT_NEXT_INTERFACE_OUTPUT;
		  ipoe_session_counter_add (
		    session->counter_index,
		    IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD, packet_bytes);
		}
	    }

	trace_and_enqueue:
	  if (next == IPOE_QINQ_OUTPUT_NEXT_DROP)
	    {
	      b->error = node->errors[error];
	      if (session)
		ipoe_session_counter_add (
		  session->counter_index,
		  IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP, packet_bytes);
	    }

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipoe_qinq_output_trace_t *trace =
		vlib_add_trace (vm, node, b, sizeof (*trace));
	      trace->dpo_index = dpo_index;
	      trace->fib_index = context ? context->fib_index : ~0;
	      trace->dpo_external_index = context ? context->external_index : 0;
	      trace->qinq_sw_if_index = qinq_sw_if_index;
	      trace->parent_sw_if_index =
		session ? session->qinq.parent_sw_if_index : ~0;
	      trace->dst_ip = ip4->dst_address;
	      trace->session_external_index =
		session ? session->external_index : 0;
	      trace->outer_vlan = session ? session->qinq.outer_vlan : 0;
	      trace->inner_vlan = session ? session->qinq.inner_vlan : 0;
	      trace->error = next == IPOE_QINQ_OUTPUT_NEXT_DROP ? error : ~0;
	    }

	  to_next[0] = bi;
	  from++;
	  to_next++;
	  n_left--;
	  n_left_to_next--;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi, next);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_qinq_output_node) = {
  .name = "ipoe-qinq-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ipoe_qinq_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ipoe_qinq_output_error_strings),
  .error_strings = ipoe_qinq_output_error_strings,
  .n_next_nodes = IPOE_QINQ_OUTPUT_N_NEXT,
  .next_nodes = {
    [IPOE_QINQ_OUTPUT_NEXT_INTERFACE_OUTPUT] = "interface-output",
    [IPOE_QINQ_OUTPUT_NEXT_DROP] = "error-drop",
  },
};
