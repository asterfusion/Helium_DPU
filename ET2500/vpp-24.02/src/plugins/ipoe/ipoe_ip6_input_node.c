/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <vnet/feature/feature.h>
#include <vnet/udp/udp_packet.h>

typedef enum
{
  IPOE_IP6_INPUT_ERROR_MALFORMED,
  IPOE_IP6_INPUT_ERROR_INTERFACE_DISABLED,
  IPOE_IP6_INPUT_ERROR_NO_BINDING,
  IPOE_IP6_INPUT_ERROR_SESSION_INACTIVE,
  IPOE_IP6_INPUT_ERROR_SESSION_EXPIRED,
  IPOE_IP6_INPUT_ERROR_ACCESS_MISMATCH,
  IPOE_IP6_INPUT_ERROR_MAC_MISMATCH,
  IPOE_IP6_INPUT_N_ERROR,
} ipoe_ip6_input_error_t;

static char *ipoe_ip6_input_error_strings[] = {
  "malformed IPv6 packets",
  "IPoE interface disabled IPv6 packets",
  "IPoE IPv6 binding not found packets",
  "inactive IPoE IPv6 session packets",
  "expired IPoE IPv6 session packets",
  "IPoE IPv6 session access mismatch packets",
  "IPoE IPv6 session MAC mismatch packets",
};

typedef enum
{
  IPOE_IP6_INPUT_NEXT_DROP,
  IPOE_IP6_INPUT_N_NEXT,
} ipoe_ip6_input_next_t;

static_always_inline ip6_header_t *
ipoe_ip6_input_header (vlib_buffer_t *b, u8 l2, ethernet_header_t **eth)
{
  u8 *current = vlib_buffer_get_current (b);
  u32 offset = 0;
  u16 type;

  *eth = 0;
  if (!l2)
    return b->current_length >= sizeof (ip6_header_t) ?
      (ip6_header_t *) current : 0;
  if (b->current_length < sizeof (ethernet_header_t))
    return 0;
  *eth = (ethernet_header_t *) current;
  type = (*eth)->type;
  offset = sizeof (**eth);
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
ipoe_ip6_control_whitelist (vlib_buffer_t *b, const ip6_header_t *ip6)
{
  const u8 *next = (const u8 *) (ip6 + 1);
  const u8 *end = (const u8 *) vlib_buffer_get_current (b) + b->current_length;

  if (ip6->protocol == IP_PROTOCOL_UDP && next + sizeof (udp_header_t) <= end)
    {
      const udp_header_t *udp = (const udp_header_t *) next;
      return clib_net_to_host_u16 (udp->src_port) == 546 &&
	clib_net_to_host_u16 (udp->dst_port) == 547;
    }
  return ip6->protocol == IP_PROTOCOL_ICMP6 && next < end &&
    (next[0] == 133 || next[0] == 135 || next[0] == 136);
}

static uword
ipoe_ip6_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vlib_frame_t *frame, u8 l2)
{
  ipoe_main_t *im = &ipoe_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  while (n_left--)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, from[0]);
      u32 next;
      u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
      ethernet_header_t *eth;
      ip6_header_t *ip6;
      ipoe_session_t *session = 0;
      ipoe_ip6_input_error_t error = IPOE_IP6_INPUT_ERROR_NO_BINDING;
      u32 bytes = vlib_buffer_length_in_chain (vm, b);

      vnet_feature_next (&next, b);

      if (sw_if_index >= vec_len (im->interfaces) ||
	  !im->interfaces[sw_if_index].enabled)
	{
	  error = IPOE_IP6_INPUT_ERROR_INTERFACE_DISABLED;
	  goto drop;
	}
      ip6 = ipoe_ip6_input_header (b, l2, &eth);
      if (!ip6 || (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label) >> 28) != 6)
	{
	  error = IPOE_IP6_INPUT_ERROR_MALFORMED;
	  goto drop;
	}
      if (ipoe_ip6_control_whitelist (b, ip6))
	goto enqueue;
      session = ipoe_ip6_binding_lookup (sw_if_index, &ip6->src_address, 0);
      if (!session)
	goto drop;
      if (!session->admin_state)
	error = IPOE_IP6_INPUT_ERROR_SESSION_INACTIVE;
      else if (vlib_time_now (vm) >= session->expires_at)
	error = IPOE_IP6_INPUT_ERROR_SESSION_EXPIRED;
      else if (session->sw_if_index != sw_if_index)
	error = IPOE_IP6_INPUT_ERROR_ACCESS_MISMATCH;
      else if (l2 && memcmp (session->user_mac.bytes, eth->src_address, 6))
	error = IPOE_IP6_INPUT_ERROR_MAC_MISMATCH;
      else
	{
	  ipoe_session_counter_add (session->counter_index,
	    IPOE_SESSION_COUNTER_UPSTREAM_FORWARD, bytes);
	  goto enqueue;
	}
      ipoe_session_counter_add (session->counter_index,
	IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP, bytes);
drop:
      next = IPOE_IP6_INPUT_NEXT_DROP;
      b->error = node->errors[error];
enqueue:
      vlib_set_next_frame_buffer (vm, node, next, from[0]);
      from++;
    }
  return frame->n_vectors;
}

VLIB_NODE_FN (ipoe_l2_ip6_input_node) (vlib_main_t *vm,
				       vlib_node_runtime_t *node,
				       vlib_frame_t *frame)
{ return ipoe_ip6_input_inline (vm, node, frame, 1); }

VLIB_NODE_FN (ipoe_ip6_input_node) (vlib_main_t *vm,
				    vlib_node_runtime_t *node,
				    vlib_frame_t *frame)
{ return ipoe_ip6_input_inline (vm, node, frame, 0); }

#define IPOE_IP6_NODE(_name)                                                \
{ .name = _name, .vector_size = sizeof (u32),                              \
  .type = VLIB_NODE_TYPE_INTERNAL, .n_errors = IPOE_IP6_INPUT_N_ERROR,      \
  .error_strings = ipoe_ip6_input_error_strings,                            \
  .n_next_nodes = IPOE_IP6_INPUT_N_NEXT,                                    \
  .next_nodes = { [IPOE_IP6_INPUT_NEXT_DROP] = "error-drop" } }

VLIB_REGISTER_NODE (ipoe_l2_ip6_input_node) =
  IPOE_IP6_NODE ("ipoe-l2-ip6-input");
VLIB_REGISTER_NODE (ipoe_ip6_input_node) =
  IPOE_IP6_NODE ("ipoe-ip6-input");

VNET_FEATURE_INIT (ipoe_l2_ip6_input, static) = {
  .arc_name = "l2-input-ip6", .node_name = "ipoe-l2-ip6-input",
};
VNET_FEATURE_INIT (ipoe_ip6_input, static) = {
  .arc_name = "ip6-unicast", .node_name = "ipoe-ip6-input",
};
