/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <ipoe/ipoe_packet.h>

#include <vnet/feature/feature.h>

typedef enum
{
  IPOE_IP4_RESULT_PASS,
  IPOE_IP4_RESULT_DHCP_WHITELIST,
  IPOE_IP4_RESULT_MALFORMED,
  IPOE_IP4_RESULT_INTERFACE_DISABLED,
  IPOE_IP4_RESULT_L2_HEADER_INVALID,
  IPOE_IP4_RESULT_NO_SESSION,
  IPOE_IP4_RESULT_SESSION_INACTIVE,
  IPOE_IP4_RESULT_ACCESS_MISMATCH,
  IPOE_IP4_RESULT_MAC_MISMATCH,
} ipoe_ip4_result_t;

typedef enum
{
  IPOE_IP4_NEXT_DROP,
  IPOE_IP4_N_NEXT,
} ipoe_ip4_next_t;

#define foreach_ipoe_ip4_error                                              \
  _ (MALFORMED, "malformed IPv4 packets")                                  \
  _ (INTERFACE_DISABLED, "IPoE interface disabled packets")                \
  _ (L2_HEADER_INVALID, "IPoE L2 identity without valid Ethernet header")  \
  _ (NO_SESSION, "IPoE session not found packets")                         \
  _ (SESSION_INACTIVE, "inactive IPoE session packets")                    \
  _ (ACCESS_MISMATCH, "IPoE session access mismatch packets")              \
  _ (MAC_MISMATCH, "IPoE session MAC mismatch packets")

typedef enum
{
#define _(sym, str) IPOE_IP4_ERROR_##sym,
  foreach_ipoe_ip4_error
#undef _
    IPOE_IP4_N_ERROR,
} ipoe_ip4_error_t;

static char *ipoe_ip4_error_strings[] = {
#define _(sym, str) str,
  foreach_ipoe_ip4_error
#undef _
};

typedef struct
{
  u64 external_index;
  ip4_address_t src_ip;
  mac_address_t src_mac;
  u32 sw_if_index;
  u8 result;
} ipoe_ip4_trace_t;

static const char *
ipoe_ip4_result_name (u8 result)
{
  switch (result)
    {
    case IPOE_IP4_RESULT_PASS: return "pass";
    case IPOE_IP4_RESULT_DHCP_WHITELIST: return "dhcp-whitelist";
    case IPOE_IP4_RESULT_MALFORMED: return "malformed";
    case IPOE_IP4_RESULT_INTERFACE_DISABLED: return "interface-disabled";
    case IPOE_IP4_RESULT_L2_HEADER_INVALID: return "l2-header-invalid";
    case IPOE_IP4_RESULT_NO_SESSION: return "no-session";
    case IPOE_IP4_RESULT_SESSION_INACTIVE: return "session-inactive";
    case IPOE_IP4_RESULT_ACCESS_MISMATCH: return "access-mismatch";
    case IPOE_IP4_RESULT_MAC_MISMATCH: return "mac-mismatch";
    default: return "unknown";
    }
}

static u8 *
format_ipoe_ip4_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  ipoe_ip4_trace_t *t = va_arg (*args, ipoe_ip4_trace_t *);

  return format (s, "ipoe-ip4-input: sw_if_index=%u src_ip=%U src_mac=%U "
		 "index=%llu result=%s",
		 t->sw_if_index, format_ip4_address, &t->src_ip,
		 format_ethernet_address, t->src_mac.bytes,
		 t->external_index, ipoe_ip4_result_name (t->result));
}

static_always_inline ethernet_header_t *
ipoe_ip4_get_l2_header (vlib_buffer_t *b)
{
  i32 l2_offset = vnet_buffer (b)->l2_hdr_offset;

  if (!(b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID) ||
      l2_offset < -(i32) VLIB_BUFFER_PRE_DATA_SIZE ||
      l2_offset + (i32) sizeof (ethernet_header_t) > b->current_data)
    return 0;
  return (ethernet_header_t *) (b->data + l2_offset);
}

static_always_inline u32
ipoe_ip4_get_l2_header_bytes (vlib_buffer_t *b)
{
  i32 l2_offset = vnet_buffer (b)->l2_hdr_offset;

  if (!(b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID) ||
      l2_offset < -(i32) VLIB_BUFFER_PRE_DATA_SIZE ||
      l2_offset + (i32) sizeof (ethernet_header_t) > b->current_data)
    return 0;
  return b->current_data - l2_offset;
}

static_always_inline ipoe_ip4_result_t
ipoe_ip4_check_packet (vlib_main_t *vm, vlib_buffer_t *b,
		       u64 *external_index, u32 *counter_index,
		       u32 *packet_bytes, ip4_address_t *src_ip,
		       mac_address_t *src_mac, ipoe_ip4_error_t *error)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_ip4_view_t view;
  ipoe_interface_t *intf;
  ipoe_session_t *session;
  ethernet_header_t *eth;
  ip4_header_t *ip4;
  uword *p;
  u32 l2_header_bytes;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  *external_index = 0;
  *counter_index = ~0;
  *packet_bytes = 0;
  src_ip->as_u32 = 0;
  *src_mac = ZERO_MAC_ADDRESS;
  if (ipoe_ip4_from_current (vm, b, &view) != IPOE_PACKET_IP4_OK)
    {
      *error = IPOE_IP4_ERROR_MALFORMED;
      return IPOE_IP4_RESULT_MALFORMED;
    }
  ip4 = view.ip4;
  *src_ip = ip4->src_address;
  l2_header_bytes = ipoe_ip4_get_l2_header_bytes (b);
  if (!l2_header_bytes)
    {
      *error = IPOE_IP4_ERROR_L2_HEADER_INVALID;
      return IPOE_IP4_RESULT_L2_HEADER_INVALID;
    }
  *packet_bytes = l2_header_bytes + view.packet_ip4_bytes;

  if (sw_if_index >= vec_len (im->interfaces) ||
      !im->interfaces[sw_if_index].enabled)
    {
      *error = IPOE_IP4_ERROR_INTERFACE_DISABLED;
      return IPOE_IP4_RESULT_INTERFACE_DISABLED;
    }
  intf = vec_elt_at_index (im->interfaces, sw_if_index);
  if (ipoe_ip4_is_dhcp_client (&view))
    return IPOE_IP4_RESULT_DHCP_WHITELIST;

  p = hash_get (im->session_by_user,
		(uword) ipoe_user_key (sw_if_index, &ip4->src_address));
  if (!p || pool_is_free_index (im->sessions, p[0]))
    {
      *error = IPOE_IP4_ERROR_NO_SESSION;
      return IPOE_IP4_RESULT_NO_SESSION;
    }
  session = pool_elt_at_index (im->sessions, p[0]);
  *external_index = session->external_index;
  *counter_index = session->counter_index;
  if (!session->admin_state)
    {
      *error = IPOE_IP4_ERROR_SESSION_INACTIVE;
      return IPOE_IP4_RESULT_SESSION_INACTIVE;
    }
  if (session->sw_if_index != sw_if_index)
    {
      *error = IPOE_IP4_ERROR_ACCESS_MISMATCH;
      return IPOE_IP4_RESULT_ACCESS_MISMATCH;
    }
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L2)
    {
      eth = ipoe_ip4_get_l2_header (b);
      if (!eth)
        {
          *error = IPOE_IP4_ERROR_L2_HEADER_INVALID;
          return IPOE_IP4_RESULT_L2_HEADER_INVALID;
        }
      mac_address_from_bytes (src_mac, eth->src_address);
      if (memcmp (session->user_mac.bytes, eth->src_address,
                  sizeof (eth->src_address)))
        {
          *error = IPOE_IP4_ERROR_MAC_MISMATCH;
          return IPOE_IP4_RESULT_MAC_MISMATCH;
        }
    }
  return IPOE_IP4_RESULT_PASS;
}

VLIB_NODE_FN (ipoe_ip4_input_node) (vlib_main_t *vm,
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
	  ipoe_ip4_error_t error0 = IPOE_IP4_ERROR_NO_SESSION;
	  ipoe_ip4_result_t result0;
	  ip4_address_t src_ip;
	  mac_address_t src_mac;
	  u64 external_index;
	  u32 counter_index;
	  u32 packet_bytes;
	  u32 next0;

	  from++;
	  n_left_from--;
	  to_next[0] = bi0;
	  to_next++;
	  n_left_to_next--;

	  vnet_feature_next (&next0, b0);
	  result0 = ipoe_ip4_check_packet (vm, b0, &external_index,
					     &counter_index, &packet_bytes,
					     &src_ip, &src_mac, &error0);
	  if (result0 == IPOE_IP4_RESULT_PASS)
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_UPSTREAM_FORWARD,
				      packet_bytes);
	  else if (external_index &&
		   (result0 == IPOE_IP4_RESULT_SESSION_INACTIVE ||
		    result0 == IPOE_IP4_RESULT_ACCESS_MISMATCH ||
		    result0 == IPOE_IP4_RESULT_MAC_MISMATCH))
	    ipoe_session_counter_add (counter_index,
				      IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP,
				      packet_bytes);
	  if (result0 != IPOE_IP4_RESULT_PASS &&
	      result0 != IPOE_IP4_RESULT_DHCP_WHITELIST)
	    {
	      next0 = IPOE_IP4_NEXT_DROP;
	      b0->error = node->errors[error0];
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ipoe_ip4_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->src_ip = src_ip;
	      t->src_mac = src_mac;
	      t->external_index = external_index;
	      t->result = result0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (ipoe_ip4_input_node) = {
  .name = "ipoe-ip4-input",
  .vector_size = sizeof (u32),
  .format_trace = format_ipoe_ip4_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (ipoe_ip4_error_strings),
  .error_strings = ipoe_ip4_error_strings,
  .n_next_nodes = IPOE_IP4_N_NEXT,
  .next_nodes = {
    [IPOE_IP4_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (ipoe_ip4_input, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "ipoe-ip4-input",
};
