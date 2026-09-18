/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

#include <vnet/feature/feature.h>
#include <vnet/ip/ip4.h>
#include <vnet/l2/l2_input.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>

typedef enum
{
  IPOE_L2_RESULT_PASS,
  IPOE_L2_RESULT_DHCP_WHITELIST,
  IPOE_L2_RESULT_MALFORMED,
  IPOE_L2_RESULT_INTERFACE_DISABLED,
  IPOE_L2_RESULT_NO_SESSION,
  IPOE_L2_RESULT_SESSION_INACTIVE,
  IPOE_L2_RESULT_ACCESS_MISMATCH,
  IPOE_L2_RESULT_MAC_MISMATCH,
} ipoe_l2_result_t;

typedef enum
{
  IPOE_L2_NEXT_DROP,
  IPOE_L2_N_NEXT,
} ipoe_l2_next_t;

#define foreach_ipoe_l2_error                                                \
  _ (MALFORMED, "malformed IPv4 packets")                                   \
  _ (INTERFACE_DISABLED, "IPoE interface disabled packets")                 \
  _ (NO_SESSION, "IPoE session not found packets")                          \
  _ (SESSION_INACTIVE, "inactive IPoE session packets")                     \
  _ (ACCESS_MISMATCH, "IPoE session access mismatch packets")               \
  _ (MAC_MISMATCH, "IPoE session MAC mismatch packets")

typedef enum
{
#define _(sym, str) IPOE_L2_ERROR_##sym,
  foreach_ipoe_l2_error
#undef _
    IPOE_L2_N_ERROR,
} ipoe_l2_error_t;

static char *ipoe_l2_error_strings[] = {
#define _(sym, str) str,
  foreach_ipoe_l2_error
#undef _
};

typedef struct
{
  u64 external_index;
  ip4_address_t src_ip;
  mac_address_t src_mac;
  u32 sw_if_index;
  u8 result;
} ipoe_l2_trace_t;

static const char *
ipoe_l2_result_name (u8 result)
{
  switch (result)
    {
    case IPOE_L2_RESULT_PASS: return "pass";
    case IPOE_L2_RESULT_DHCP_WHITELIST: return "dhcp-whitelist";
    case IPOE_L2_RESULT_MALFORMED: return "malformed";
    case IPOE_L2_RESULT_INTERFACE_DISABLED: return "interface-disabled";
    case IPOE_L2_RESULT_NO_SESSION: return "no-session";
    case IPOE_L2_RESULT_SESSION_INACTIVE: return "session-inactive";
    case IPOE_L2_RESULT_ACCESS_MISMATCH: return "access-mismatch";
    case IPOE_L2_RESULT_MAC_MISMATCH: return "mac-mismatch";
    default: return "unknown";
    }
}

static u8 *
format_ipoe_l2_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  ipoe_l2_trace_t *t = va_arg (*args, ipoe_l2_trace_t *);

  return format (s, "ipoe-l2-input: sw_if_index=%u src_ip=%U src_mac=%U "
		 "index=%llu result=%s",
		 t->sw_if_index, format_ip4_address, &t->src_ip,
		 format_ethernet_address, t->src_mac.bytes,
		 t->external_index, ipoe_l2_result_name (t->result));
}

static_always_inline u8
ipoe_l2_is_dhcp_client (vlib_buffer_t *b, const ip4_header_t *ip4,
			u32 packet_bytes)
{
  const udp_header_t *udp;
  u32 ip4_bytes = ip4_header_bytes (ip4);

  if (ip4->protocol != IP_PROTOCOL_UDP || ip4_is_fragment (ip4) ||
      ip4_bytes < sizeof (*ip4) ||
      packet_bytes < vnet_buffer (b)->l2.l2_len + ip4_bytes + sizeof (*udp))
    return 0;

  udp = (const udp_header_t *) ((const u8 *) ip4 + ip4_bytes);
  return (clib_net_to_host_u16 (udp->src_port) == UDP_DST_PORT_dhcp_to_client &&
	  clib_net_to_host_u16 (udp->dst_port) == UDP_DST_PORT_dhcp_to_server);
}

static_always_inline ipoe_l2_result_t
ipoe_l2_check_packet (vlib_main_t *vm, vlib_buffer_t *b,
		      u64 *external_index, u32 *counter_index,
		      u32 *packet_bytes, ipoe_l2_error_t *error)
{
  ipoe_main_t *im = &ipoe_main;
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  ipoe_interface_t *intf;
  ipoe_session_t *session;
  ip4_header_t *ip4;
  uword *p;
  u32 frame_bytes = vlib_buffer_length_in_chain (vm, b);
  u32 ip4_bytes;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 l2_len = vnet_buffer (b)->l2.l2_len;

  *external_index = 0;
  *counter_index = ~0;
  *packet_bytes = 0;
  if (l2_len < sizeof (*eth) || frame_bytes < l2_len + sizeof (*ip4))
    {
      *error = IPOE_L2_ERROR_MALFORMED;
      return IPOE_L2_RESULT_MALFORMED;
    }

  ip4 = (ip4_header_t *) ((u8 *) eth + l2_len);
  if (ip4->ip_version_and_header_length >> 4 != 4 ||
      ip4_header_bytes (ip4) < sizeof (*ip4) ||
      frame_bytes < l2_len + ip4_header_bytes (ip4))
    {
      *error = IPOE_L2_ERROR_MALFORMED;
      return IPOE_L2_RESULT_MALFORMED;
    }
  ip4_bytes = clib_net_to_host_u16 (ip4->length);
  if (ip4_bytes < ip4_header_bytes (ip4) ||
      frame_bytes < l2_len + ip4_bytes)
    {
      *error = IPOE_L2_ERROR_MALFORMED;
      return IPOE_L2_RESULT_MALFORMED;
    }

  if (sw_if_index >= vec_len (im->interfaces) ||
      !im->interfaces[sw_if_index].enabled)
    {
      *error = IPOE_L2_ERROR_INTERFACE_DISABLED;
      return IPOE_L2_RESULT_INTERFACE_DISABLED;
    }
  intf = vec_elt_at_index (im->interfaces, sw_if_index);
  *packet_bytes = frame_bytes;
  if (ipoe_l2_is_dhcp_client (b, ip4, frame_bytes))
    return IPOE_L2_RESULT_DHCP_WHITELIST;

  p = hash_get (im->session_by_user,
		(uword) ipoe_user_key (sw_if_index, &ip4->src_address));
  if (!p || pool_is_free_index (im->sessions, p[0]))
    {
      *error = IPOE_L2_ERROR_NO_SESSION;
      return IPOE_L2_RESULT_NO_SESSION;
    }

  session = pool_elt_at_index (im->sessions, p[0]);
  *external_index = session->external_index;
  *counter_index = session->counter_index;
  if (!session->admin_state)
    {
      *error = IPOE_L2_ERROR_SESSION_INACTIVE;
      return IPOE_L2_RESULT_SESSION_INACTIVE;
    }
  if (session->sw_if_index != sw_if_index)
    {
      *error = IPOE_L2_ERROR_ACCESS_MISMATCH;
      return IPOE_L2_RESULT_ACCESS_MISMATCH;
    }
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L2 &&
      memcmp (session->user_mac.bytes, eth->src_address,
	      sizeof (eth->src_address)))
    {
      *error = IPOE_L2_ERROR_MAC_MISMATCH;
      return IPOE_L2_RESULT_MAC_MISMATCH;
    }
  return IPOE_L2_RESULT_PASS;
}

VLIB_NODE_FN (ipoe_l2_input_node) (vlib_main_t *vm,
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
	  u32 next0;
	  u64 external_index;
	  u32 counter_index;
	  u32 packet_bytes;
	  ipoe_l2_error_t error0 = IPOE_L2_ERROR_NO_SESSION;
	  ipoe_l2_result_t result0;

	  from++;
	  n_left_from--;
	  to_next[0] = bi0;
	  to_next++;
	  n_left_to_next--;

	  vnet_feature_next (&next0, b0);
	  result0 = ipoe_l2_check_packet (vm, b0, &external_index,
					    &counter_index, &packet_bytes,
					    &error0);
	  if (result0 == IPOE_L2_RESULT_PASS)
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_UPSTREAM_FORWARD,
				      packet_bytes);
	  else if (external_index &&
		   (result0 == IPOE_L2_RESULT_SESSION_INACTIVE ||
		    result0 == IPOE_L2_RESULT_ACCESS_MISMATCH ||
		    result0 == IPOE_L2_RESULT_MAC_MISMATCH))
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP,
				      packet_bytes);
	  if (result0 != IPOE_L2_RESULT_PASS &&
	      result0 != IPOE_L2_RESULT_DHCP_WHITELIST)
	    {
	      next0 = IPOE_L2_NEXT_DROP;
	      b0->error = node->errors[error0];
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ethernet_header_t *eth = vlib_buffer_get_current (b0);
	      ipoe_l2_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->external_index = external_index;
	      t->result = result0;
	      t->src_mac = ZERO_MAC_ADDRESS;
	      t->src_ip.as_u32 = 0;
	      if (vlib_buffer_length_in_chain (vm, b0) >= sizeof (*eth))
		mac_address_from_bytes (&t->src_mac, eth->src_address);
	      if (vnet_buffer (b0)->l2.l2_len >= sizeof (*eth) &&
		  vlib_buffer_length_in_chain (vm, b0) >=
		    vnet_buffer (b0)->l2.l2_len + sizeof (ip4_header_t))
		{
		  ip4_header_t *ip4 =
		    (ip4_header_t *) ((u8 *) eth +
				  vnet_buffer (b0)->l2.l2_len);
		  t->src_ip = ip4->src_address;
		}
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_l2_input_node) = {
  .name = "ipoe-l2-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipoe_l2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ipoe_l2_error_strings),
  .error_strings = ipoe_l2_error_strings,
  .n_next_nodes = IPOE_L2_N_NEXT,
  .next_nodes = {
    [IPOE_L2_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (ipoe_l2_input, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "ipoe-l2-input",
  .runs_before = VNET_FEATURES ("linux-cp-l2-igmp", "linux-cp-l2-vrrp",
				"l2-input-feat-arc-end"),
};
