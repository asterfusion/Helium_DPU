/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <vnet/feature/feature.h>
#include <vnet/udp/udp_packet.h>

typedef enum
{
  IPOE_IP6_OUTPUT_ERROR_MALFORMED,
  IPOE_IP6_OUTPUT_ERROR_NO_BINDING,
  IPOE_IP6_OUTPUT_ERROR_SESSION_INACTIVE,
  IPOE_IP6_OUTPUT_ERROR_SESSION_EXPIRED,
  IPOE_IP6_OUTPUT_ERROR_ACCESS_MISMATCH,
  IPOE_IP6_OUTPUT_N_ERROR,
} ipoe_ip6_output_error_t;

static char *ipoe_ip6_output_error_strings[] = {
  "malformed IPv6 output packets", "IPoE IPv6 binding not found packets",
  "inactive IPoE IPv6 session packets", "expired IPoE IPv6 session packets",
  "IPoE IPv6 session access mismatch packets",
};

static_always_inline ip6_header_t *
ipoe_ip6_output_header (vlib_buffer_t *b)
{
  u8 *current = vlib_buffer_get_current (b);
  u32 offset = 0;
  u16 type;

  if (b->current_length >= sizeof (ip6_header_t) &&
      (current[0] >> 4) == 6)
    return (ip6_header_t *) current;
  if (b->current_length < sizeof (ethernet_header_t))
    return 0;
  type = ((ethernet_header_t *) current)->type;
  offset = sizeof (ethernet_header_t);
  while (type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN) ||
	 type == clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD))
    {
      ethernet_vlan_header_t *vlan;
      if (b->current_length < offset + sizeof (*vlan))
	return 0;
      vlan = (ethernet_vlan_header_t *) (current + offset);
      type = vlan->type;
      offset += sizeof (*vlan);
    }
  if (type != clib_host_to_net_u16 (ETHERNET_TYPE_IP6) ||
      b->current_length < offset + sizeof (ip6_header_t))
    return 0;
  return (ip6_header_t *) (current + offset);
}

static_always_inline u8
ipoe_ip6_output_control_whitelist (vlib_buffer_t *b, const ip6_header_t *ip6)
{
  const u8 *next = (const u8 *) (ip6 + 1);
  const u8 *end = (const u8 *) vlib_buffer_get_current (b) + b->current_length;

  if (ip6->protocol == IP_PROTOCOL_UDP && next + sizeof (udp_header_t) <= end)
    {
      const udp_header_t *udp = (const udp_header_t *) next;
      return clib_net_to_host_u16 (udp->src_port) == 547 &&
	clib_net_to_host_u16 (udp->dst_port) == 546;
    }
  return ip6->protocol == IP_PROTOCOL_ICMP6 && next < end &&
    (next[0] == 134 || next[0] == 135 || next[0] == 136);
}

VLIB_NODE_FN (ipoe_ip6_output_node) (vlib_main_t *vm,
				     vlib_node_runtime_t *node,
				     vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  while (n_left--)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);
      ip6_header_t *ip6;
      ipoe_session_t *session = 0;
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
      u32 next;
      u32 bytes = vlib_buffer_length_in_chain (vm, b);
      ipoe_ip6_output_error_t error = IPOE_IP6_OUTPUT_ERROR_NO_BINDING;

      vnet_feature_next (&next, b);
      ip6 = ipoe_ip6_output_header (b);
      if (!ip6)
	{
	  error = IPOE_IP6_OUTPUT_ERROR_MALFORMED;
	  goto drop;
	}
      if (ipoe_ip6_output_control_whitelist (b, ip6))
	goto enqueue;
      session = ipoe_ip6_binding_lookup (sw_if_index, &ip6->dst_address, 0);
      if (!session)
	goto drop;
      if (!session->admin_state)
	error = IPOE_IP6_OUTPUT_ERROR_SESSION_INACTIVE;
      else if (vlib_time_now (vm) >= session->expires_at)
	error = IPOE_IP6_OUTPUT_ERROR_SESSION_EXPIRED;
      else if (session->sw_if_index != sw_if_index)
	error = IPOE_IP6_OUTPUT_ERROR_ACCESS_MISMATCH;
      else
	{
	  ipoe_session_counter_add (session->counter_index,
	    IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD, bytes);
	  goto enqueue;
	}
      ipoe_session_counter_add (session->counter_index,
	IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP, bytes);
drop:
      next = 0;
      b->error = node->errors[error];
enqueue:
      vlib_set_next_frame_buffer (vm, node, next, from[0]);
      from++;
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_ip6_output_node) = {
  .name = "ipoe-ip6-output", .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = IPOE_IP6_OUTPUT_N_ERROR,
  .error_strings = ipoe_ip6_output_error_strings,
  .n_next_nodes = 1, .next_nodes = { [0] = "error-drop" },
};

VNET_FEATURE_INIT (ipoe_l2_ip6_output, static) = {
  .arc_name = "l2-output-ip6", .node_name = "ipoe-ip6-output",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};
VNET_FEATURE_INIT (ipoe_ip6_output, static) = {
  .arc_name = "ip6-output", .node_name = "ipoe-ip6-output",
  .runs_before = VNET_FEATURES ("interface-output"),
};
