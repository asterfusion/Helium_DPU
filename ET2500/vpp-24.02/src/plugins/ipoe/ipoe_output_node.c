/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <ipoe/ipoe_packet.h>

#include <vnet/feature/feature.h>

typedef enum
{
  IPOE_OUTPUT_RESULT_PASS,
  IPOE_OUTPUT_RESULT_DHCP_WHITELIST,
  IPOE_OUTPUT_RESULT_NON_IP4_BYPASS,
  IPOE_OUTPUT_RESULT_MALFORMED,
  IPOE_OUTPUT_RESULT_UNSUPPORTED_VLAN_DEPTH,
  IPOE_OUTPUT_RESULT_INTERFACE_DISABLED,
  IPOE_OUTPUT_RESULT_NO_SESSION,
  IPOE_OUTPUT_RESULT_SESSION_INACTIVE,
  IPOE_OUTPUT_RESULT_ACCESS_MISMATCH,
} ipoe_output_result_t;

typedef enum
{
  IPOE_OUTPUT_NEXT_DROP,
  IPOE_OUTPUT_N_NEXT,
} ipoe_output_next_t;

#define foreach_ipoe_output_error                                           \
  _ (MALFORMED, "malformed IPv4 output packets")                           \
  _ (UNSUPPORTED_VLAN_DEPTH, "unsupported output VLAN depth packets")      \
  _ (INTERFACE_DISABLED, "IPoE interface disabled output packets")         \
  _ (NO_SESSION, "IPoE output session not found packets")                  \
  _ (SESSION_INACTIVE, "inactive IPoE output session packets")             \
  _ (ACCESS_MISMATCH, "IPoE output session access mismatch packets")

typedef enum
{
#define _(sym, str) IPOE_OUTPUT_ERROR_##sym,
  foreach_ipoe_output_error
#undef _
    IPOE_OUTPUT_N_ERROR,
} ipoe_output_error_t;

static char *ipoe_output_error_strings[] = {
#define _(sym, str) str,
  foreach_ipoe_output_error
#undef _
};

typedef struct
{
  u64 external_index;
  ip4_address_t dst_ip;
  u32 sw_if_index;
  u8 vlan_depth;
  u8 result;
} ipoe_output_trace_t;

static const char *
ipoe_output_result_name (u8 result)
{
  switch (result)
    {
    case IPOE_OUTPUT_RESULT_PASS: return "pass";
    case IPOE_OUTPUT_RESULT_DHCP_WHITELIST: return "dhcp-whitelist";
    case IPOE_OUTPUT_RESULT_NON_IP4_BYPASS: return "non-ip4-bypass";
    case IPOE_OUTPUT_RESULT_MALFORMED: return "malformed";
    case IPOE_OUTPUT_RESULT_UNSUPPORTED_VLAN_DEPTH:
      return "unsupported-vlan-depth";
    case IPOE_OUTPUT_RESULT_INTERFACE_DISABLED: return "interface-disabled";
    case IPOE_OUTPUT_RESULT_NO_SESSION: return "no-session";
    case IPOE_OUTPUT_RESULT_SESSION_INACTIVE: return "session-inactive";
    case IPOE_OUTPUT_RESULT_ACCESS_MISMATCH: return "access-mismatch";
    default: return "unknown";
    }
}

static u8 *
format_ipoe_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  ipoe_output_trace_t *t = va_arg (*args, ipoe_output_trace_t *);

  return format (s, "ipoe-output: sw_if_index=%u dst_ip=%U index=%llu "
		 "vlan_depth=%u result=%s",
		 t->sw_if_index, format_ip4_address, &t->dst_ip,
		 t->external_index, t->vlan_depth,
		 ipoe_output_result_name (t->result));
}

static_always_inline ipoe_output_result_t
ipoe_output_check_packet (vlib_main_t *vm, vlib_buffer_t *b,
			  u64 *external_index, u32 *counter_index,
			  u32 *packet_bytes, ip4_address_t *dst_ip,
			  u8 *vlan_depth, ipoe_output_error_t *error)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_ip4_view_t view;
  ipoe_session_t *session;
  ipoe_packet_result_t parse_result;
  ip4_header_t *ip4;
  uword *p;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];

  *external_index = 0;
  *counter_index = ~0;
  *packet_bytes = 0;
  dst_ip->as_u32 = 0;
  *vlan_depth = 0;
  if (sw_if_index >= vec_len (im->interfaces) ||
      !im->interfaces[sw_if_index].enabled)
    {
      *error = IPOE_OUTPUT_ERROR_INTERFACE_DISABLED;
      return IPOE_OUTPUT_RESULT_INTERFACE_DISABLED;
    }

  parse_result = ipoe_ip4_from_ethernet (vm, b, &view);
  *vlan_depth = view.vlan_depth;
  if (parse_result == IPOE_PACKET_NON_IP4)
    return IPOE_OUTPUT_RESULT_NON_IP4_BYPASS;
  if (parse_result == IPOE_PACKET_UNSUPPORTED_VLAN_DEPTH)
    {
      *error = IPOE_OUTPUT_ERROR_UNSUPPORTED_VLAN_DEPTH;
      return IPOE_OUTPUT_RESULT_UNSUPPORTED_VLAN_DEPTH;
    }
  if (parse_result != IPOE_PACKET_IP4_OK)
    {
      *error = IPOE_OUTPUT_ERROR_MALFORMED;
      return IPOE_OUTPUT_RESULT_MALFORMED;
    }

  ip4 = view.ip4;
  *dst_ip = ip4->dst_address;
  *packet_bytes = vlib_buffer_length_in_chain (vm, b);
  if (ipoe_ip4_is_dhcp_downstream (&view))
    return IPOE_OUTPUT_RESULT_DHCP_WHITELIST;

  p = hash_get (im->session_by_user,
		(uword) ipoe_user_key (sw_if_index, &ip4->dst_address));
  if (!p || pool_is_free_index (im->sessions, p[0]))
    {
      *error = IPOE_OUTPUT_ERROR_NO_SESSION;
      return IPOE_OUTPUT_RESULT_NO_SESSION;
    }
  session = pool_elt_at_index (im->sessions, p[0]);
  *external_index = session->external_index;
  *counter_index = session->counter_index;
  if (!session->admin_state)
    {
      *error = IPOE_OUTPUT_ERROR_SESSION_INACTIVE;
      return IPOE_OUTPUT_RESULT_SESSION_INACTIVE;
    }
  if (session->sw_if_index != sw_if_index)
    {
      *error = IPOE_OUTPUT_ERROR_ACCESS_MISMATCH;
      return IPOE_OUTPUT_RESULT_ACCESS_MISMATCH;
    }
  return IPOE_OUTPUT_RESULT_PASS;
}

VLIB_NODE_FN (ipoe_output_node) (vlib_main_t *vm,
				  vlib_node_runtime_t *node,
				  vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 *to_next;
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  ipoe_output_error_t error0 = IPOE_OUTPUT_ERROR_NO_SESSION;
	  ipoe_output_result_t result0;
	  ip4_address_t dst_ip;
	  u64 external_index;
	  u32 counter_index;
	  u32 packet_bytes;
	  u8 vlan_depth;
	  u32 next0;

	  from++;
	  n_left_from--;
	  to_next[0] = bi0;
	  to_next++;
	  n_left_to_next--;

	  vnet_feature_next (&next0, b0);
	  result0 = ipoe_output_check_packet (vm, b0, &external_index,
					&counter_index, &packet_bytes,
					&dst_ip, &vlan_depth, &error0);
	  if (result0 == IPOE_OUTPUT_RESULT_PASS)
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD,
				      packet_bytes);
	  else if (external_index &&
		   (result0 == IPOE_OUTPUT_RESULT_SESSION_INACTIVE ||
		    result0 == IPOE_OUTPUT_RESULT_ACCESS_MISMATCH))
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP,
				      packet_bytes);
	  if (result0 != IPOE_OUTPUT_RESULT_PASS &&
	      result0 != IPOE_OUTPUT_RESULT_DHCP_WHITELIST &&
	      result0 != IPOE_OUTPUT_RESULT_NON_IP4_BYPASS)
	    {
	      next0 = IPOE_OUTPUT_NEXT_DROP;
	      b0->error = node->errors[error0];
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipoe_output_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->dst_ip = dst_ip;
	      t->external_index = external_index;
	      t->vlan_depth = vlan_depth;
	      t->result = result0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_output_node) = {
  .name = "ipoe-output",
  .vector_size = sizeof (u32),
  .format_trace = format_ipoe_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ipoe_output_error_strings),
  .error_strings = ipoe_output_error_strings,
  .n_next_nodes = IPOE_OUTPUT_N_NEXT,
  .next_nodes = {
    [IPOE_OUTPUT_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (ipoe_output, static) = {
  .arc_name = "interface-output",
  .node_name = "ipoe-output",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};
