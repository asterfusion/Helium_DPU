/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/llc/llc.h>
#include <vnet/osi/osi.h>

#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp_match.h>
#include <linux-cp/lcp_punt.h>
#include <linux-cp/lcp_stats.h>

u16 *bpdu_drop;

#define foreach_lcp_ip4_producer_next                                    \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-copp-punt")

typedef enum
{
#define _(sym, node) LCP_IP4_PRODUCER_NEXT_##sym,
  foreach_lcp_ip4_producer_next
#undef _
  LCP_IP4_PRODUCER_N_NEXT,
} lcp_ip4_producer_next_t;

#define foreach_lcp_ip6_producer_next                                    \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-copp-punt")

typedef enum
{
#define _(sym, node) LCP_IP6_PRODUCER_NEXT_##sym,
  foreach_lcp_ip6_producer_next
#undef _
  LCP_IP6_PRODUCER_N_NEXT,
} lcp_ip6_producer_next_t;

#define foreach_lcp_local_producer_next                                  \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-copp-punt")

typedef enum
{
#define _(sym, node) LCP_LOCAL_PRODUCER_NEXT_##sym,
  foreach_lcp_local_producer_next
#undef _
  LCP_LOCAL_PRODUCER_N_NEXT,
} lcp_local_producer_next_t;

#define foreach_lcp_l2_feature_next                                      \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-l2-delivery")

typedef enum
{
#define _(sym, node) LCP_L2_FEATURE_NEXT_##sym,
  foreach_lcp_l2_feature_next
#undef _
  LCP_L2_FEATURE_N_NEXT,
} lcp_l2_feature_next_t;

#define foreach_lcp_l2_direct_next                                       \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-l2-delivery")                                     \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, node) LCP_L2_DIRECT_NEXT_##sym,
  foreach_lcp_l2_direct_next
#undef _
  LCP_L2_DIRECT_N_NEXT,
} lcp_l2_direct_next_t;

#define foreach_lcp_l2_delivery_next                                     \
  _ (DROP, "error-drop")                                                \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, node) LCP_L2_DELIVERY_NEXT_##sym,
  foreach_lcp_l2_delivery_next
#undef _
  LCP_L2_DELIVERY_N_NEXT,
} lcp_l2_delivery_next_t;

typedef struct
{
  u32 sw_if_index;
  u16 rule_id;
  u8 trap_id;
  u8 context;
  u8 llc_dsap;
  u8 llc_ssap;
  u8 llc_control;
  u8 osi_protocol;
  u8 isis_pdu_type;
  u32 valid_fields;
} lcp_producer_trace_t;

static u8 *
format_lcp_producer_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  lcp_producer_trace_t *t = va_arg (*args, lcp_producer_trace_t *);
  const lcp_match_rule_t *rule = lcp_match_rule_find (t->rule_id);

  return format (s, "linux-cp context 0x%x sw_if_index %u trap %u "
		 "matched-rule %s (%u) fields 0x%x llc %02x/%02x/%02x "
		 "osi %02x pdu %u",
		 t->context, t->sw_if_index, t->trap_id,
		 rule ? rule->name : "unknown", t->rule_id, t->valid_fields,
		 t->llc_dsap, t->llc_ssap, t->llc_control, t->osi_protocol,
		 t->isis_pdu_type);
}

static_always_inline uword
lcp_ip_producer_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, u32 context, u32 drop_next,
			u32 punt_next)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0;

  while (n_left)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left && n_left_to_next)
	{
	  u32 bi = from[0], next, original_next;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  lcp_action_result_t action_result;
	  lcp_packet_view_t view;
	  lcp_match_result_t result = { 0 };
	  u32 packet_context = context;

	  bool copp_processed = lcp_buffer_copp_processed (b);

	  /*
	   * The trap id is stored in buffer opaque metadata and buffers are
	   * recycled by VPP.  L2 classification initializes it explicitly, but
	   * the IP producers used to inspect a stale value and skip classification
	   * for most subsequent packets.  L3 packets enter this producer before
	   * any LCP decision, so start each packet with a clean marker.
	   */
	  if (copp_processed)
	    {
	      lcp_buffer_clear_copp_processed (b);
	      vnet_buffer2 (b)->trap_id = LCP_TRAP_INVALID;
	    }
	  else
	    vnet_buffer2 (b)->trap_id = LCP_TRAP_INVALID;

	  vnet_feature_next (&original_next, b);
	  next = original_next;
	  if (context == LCP_MATCH_CTX_LOCAL_IP46)
	    packet_context =
	      b->current_length &&
		(*(u8 *) vlib_buffer_get_current (b) >> 4) == 6 ?
		LCP_MATCH_CTX_LOCAL6 : LCP_MATCH_CTX_LOCAL4;
	  if (!copp_processed && vnet_buffer2 (b)->trap_id == LCP_TRAP_INVALID &&
	      lcp_packet_parse (vm, b, packet_context, &view) &&
	      lcp_match_select (&view, &result))
	    {
	      if (!lcp_buffer_set_trap_id (b, result.trap_type))
		next = drop_next;
	      else
		{
		  action_result = lcp_punt_process_with_default (
		    vm, b, lcp_legacy_action (result.trap_type));
		  switch (action_result.disposition)
		    {
		    case LCP_DISPOSITION_DROP:
		      next = drop_next;
		      break;
		    case LCP_DISPOSITION_FORWARD:
		    case LCP_DISPOSITION_COPY:
		      next = original_next;
		      /* The CPU copy carries the trap id; the original must continue
		       * through the feature arc without a stale punt marker. */
		      lcp_buffer_mark_copp_processed (b);
		      break;
		    case LCP_DISPOSITION_TRAP:
		      next = punt_next;
		      break;
		    }
		  if (action_result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
		    copies[n_copies++] = action_result.cpu_bi;
		}
	    }

	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lcp_producer_trace_t *t =
		vlib_add_trace (vm, node, b, sizeof (*t));

	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      t->trap_id = result.trap_type;
	      t->rule_id = result.evidence_rule_id;
	      t->context = packet_context;
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

  if (n_copies)
    vlib_buffer_enqueue_to_single_next (vm, node, copies,
					punt_next, n_copies);
  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_ip4_producer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_ip_producer_inline (vm, node, frame, LCP_MATCH_CTX_IP4,
				 LCP_IP4_PRODUCER_NEXT_DROP,
				 LCP_IP4_PRODUCER_NEXT_PUNT);
}

VLIB_NODE_FN (lcp_ip6_producer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_ip_producer_inline (vm, node, frame, LCP_MATCH_CTX_IP6,
				 LCP_IP6_PRODUCER_NEXT_DROP,
				 LCP_IP6_PRODUCER_NEXT_PUNT);
}

VLIB_NODE_FN (lcp_local_producer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_ip_producer_inline (vm, node, frame, LCP_MATCH_CTX_LOCAL_IP46,
				 LCP_LOCAL_PRODUCER_NEXT_DROP,
				 LCP_LOCAL_PRODUCER_NEXT_PUNT);
}

VLIB_REGISTER_NODE (lcp_ip4_producer_node) = {
  .name = "linux-cp-ip4-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_IP4_PRODUCER_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_IP4_PRODUCER_NEXT_##sym] = node,
    foreach_lcp_ip4_producer_next
#undef _
  },
};

VLIB_REGISTER_NODE (lcp_ip6_producer_node) = {
  .name = "linux-cp-ip6-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_IP6_PRODUCER_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_IP6_PRODUCER_NEXT_##sym] = node,
    foreach_lcp_ip6_producer_next
#undef _
  },
};

VLIB_REGISTER_NODE (lcp_local_producer_node) = {
  .name = "linux-cp-local-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_LOCAL_PRODUCER_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_LOCAL_PRODUCER_NEXT_##sym] = node,
    foreach_lcp_local_producer_next
#undef _
  },
};

VNET_FEATURE_INIT (lcp_ip4_producer_uc, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-ip4-punt",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};
VNET_FEATURE_INIT (lcp_ip4_producer_mc, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-ip4-punt",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};
VNET_FEATURE_INIT (lcp_ip6_producer_uc, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-ip6-punt",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};
VNET_FEATURE_INIT (lcp_ip6_producer_mc, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-ip6-punt",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};
VNET_FEATURE_INIT (lcp_local_ip4_feature, static) = {
  .arc_name = "ip4-punt",
  .node_name = "linux-cp-local-punt",
  .runs_before = VNET_FEATURES ("linux-cp-punt-l3", "ip4-punt-redirect"),
};
VNET_FEATURE_INIT (lcp_local_ip6_feature, static) = {
  .arc_name = "ip6-punt",
  .node_name = "linux-cp-local-punt",
  .runs_before = VNET_FEATURES ("linux-cp-punt-l3", "ip6-punt-redirect"),
};

static_always_inline u32
lcp_l2_direct_rx_sw_if_index (vlib_buffer_t *b)
{
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  if ((b->flags & VLIB_BUFFER_NOT_PHY_INTF) &&
      vnet_buffer2 (b)->l2_rx_sw_if_index != 0 &&
      vnet_buffer2 (b)->l2_rx_sw_if_index != ~0)
    {
      sw_if_index = vnet_buffer2 (b)->l2_rx_sw_if_index;
      vnet_buffer2 (b)->l2_rx_sw_if_index = ~0;
      vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
    }
  return sw_if_index;
}

VLIB_NODE_FN (lcp_l2_delivery_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left && n_left_to_next)
	{
	  u32 bi = from[0], next = LCP_L2_DELIVERY_NEXT_DROP;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  index_t lipi = lcp_itf_pair_find_by_phy (
	    lcp_l2_direct_rx_sw_if_index (b));
	  lcp_itf_pair_t *lip = lcp_itf_pair_get (lipi);

	  if (lip)
	    {
	      word len = (u8 *) vlib_buffer_get_current (b) -
			 (u8 *) ethernet_buffer_get_header (b);
	      vnet_buffer (b)->sw_if_index[VLIB_TX] = lip->lip_host_sw_if_index;
	      vlib_buffer_advance (b, -len);
	      if (lcp_cpu_branch_pass (vm, b) ||
		  vnet_buffer2 (b)->trap_id == LCP_TRAP_INVALID)
		next = LCP_L2_DELIVERY_NEXT_IO;
	    }
	  else if (vnet_buffer2 (b)->trap_id != 0)
	    lcp_stats_increment (vm, vnet_buffer2 (b)->trap_id,
				 LCP_STATS_DELIVERY_DROP);

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

VLIB_REGISTER_NODE (lcp_l2_delivery_node) = {
  .name = "linux-cp-l2-delivery",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_L2_DELIVERY_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_L2_DELIVERY_NEXT_##sym] = node,
    foreach_lcp_l2_delivery_next
#undef _
  },
};

static_always_inline uword
lcp_l2_producer_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, bool is_feature, bool fail_closed)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0;
  u32 drop_next = is_feature ? LCP_L2_FEATURE_NEXT_DROP :
			       LCP_L2_DIRECT_NEXT_DROP;
  u32 punt_next = is_feature ? LCP_L2_FEATURE_NEXT_PUNT :
			       LCP_L2_DIRECT_NEXT_PUNT;

  while (n_left)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left && n_left_to_next)
	{
	  u32 bi = from[0], next = drop_next, original_next = drop_next;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  lcp_action_result_t action_result;
	  u32 context = LCP_MATCH_CTX_L2_DIRECT;
	  lcp_packet_view_t view;
	  lcp_match_result_t result = { 0 };

	  if (is_feature)
	    {
	      u32 l2_len = vnet_buffer (b)->l2.l2_len;
	      u8 *ip;

	      vnet_feature_next (&original_next, b);
	      next = original_next;
	      if (l2_len >= b->current_length)
		goto enqueue;
	      ip = (u8 *) vlib_buffer_get_current (b) + l2_len;
	      context = (*ip >> 4) == 6 ? LCP_MATCH_CTX_L2_IP6 :
					 LCP_MATCH_CTX_L2_IP4;
	    }
	  else
	    {
	      u32 rx_sw_if_index = lcp_l2_direct_rx_sw_if_index (b);
	      index_t lipi = lcp_itf_pair_find_by_host (rx_sw_if_index);
	      lcp_itf_pair_t *lip = lcp_itf_pair_get (lipi);

	      context = LCP_MATCH_CTX_L2_DIRECT;
	      if (lip)
		{
		  word len = (u8 *) vlib_buffer_get_current (b) -
			     (u8 *) ethernet_buffer_get_header (b);
		  lcp_set_max_tc (b);
		  vnet_buffer (b)->sw_if_index[VLIB_TX] =
		    lip->lip_phy_sw_if_index;
		  vlib_buffer_advance (b, -len);
		  next = LCP_L2_DIRECT_NEXT_IO;
		  goto enqueue;
		}
	    }

	  vnet_buffer2 (b)->trap_id = LCP_TRAP_INVALID;
	  if (lcp_packet_parse (vm, b, context, &view) &&
	      lcp_match_select (&view, &result))
	    {
	      if (!is_feature && result.trap_type == LCP_TRAP_STP &&
		  view.rx_sw_if_index < vec_len (bpdu_drop) &&
		  bpdu_drop[view.rx_sw_if_index])
		goto enqueue;
	      if (!lcp_buffer_set_trap_id (b, result.trap_type))
		next = drop_next;
	      else
		{
		  action_result = lcp_punt_process_with_default (
		    vm, b, lcp_legacy_action (result.trap_type));
		  switch (action_result.disposition)
		    {
		    case LCP_DISPOSITION_DROP:
		      next = drop_next;
		      break;
		    case LCP_DISPOSITION_FORWARD:
		    case LCP_DISPOSITION_COPY:
		      next = original_next;
		      /* The CPU copy carries the trap id; the original must continue
		       * through the L2 feature arc without a stale punt marker. */
		      lcp_buffer_mark_copp_processed (b);
		      break;
		    case LCP_DISPOSITION_TRAP:
		      next = punt_next;
		      break;
		    }
		  if (action_result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
		    copies[n_copies++] = action_result.cpu_bi;
		}
	    }
	  else if (!is_feature && !fail_closed)
	    next = punt_next;

	enqueue:
	  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lcp_producer_trace_t *t =
		vlib_add_trace (vm, node, b, sizeof (*t));

	      t->sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
	      t->trap_id = result.trap_type;
	  t->rule_id = result.evidence_rule_id;
	      t->context = context;
	      t->llc_dsap = view.llc_dsap;
	      t->llc_ssap = view.llc_ssap;
	      t->llc_control = view.llc_control;
	      t->osi_protocol = view.osi_protocol;
	      t->isis_pdu_type = view.isis_pdu_type;
	      t->valid_fields = view.valid_fields;
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

  if (n_copies)
    vlib_buffer_enqueue_to_single_next (vm, node, copies, punt_next,
					n_copies);
  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_l2_producer_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_l2_producer_inline (vm, node, frame, true, false);
}

VLIB_NODE_FN (lcp_l2_direct_adapter_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_l2_producer_inline (vm, node, frame, false, false);
}

VLIB_NODE_FN (lcp_isis_direct_adapter_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_l2_producer_inline (vm, node, frame, false, true);
}

VLIB_REGISTER_NODE (lcp_l2_producer_node) = {
  .name = "linux-cp-l2-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_L2_FEATURE_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_L2_FEATURE_NEXT_##sym] = node,
    foreach_lcp_l2_feature_next
#undef _
  },
};

VLIB_REGISTER_NODE (lcp_l2_direct_adapter_node) = {
  .name = "linux-cp-l2-direct-adapter",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_L2_DIRECT_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_L2_DIRECT_NEXT_##sym] = node,
    foreach_lcp_l2_direct_next
#undef _
  },
};

VLIB_REGISTER_NODE (lcp_isis_direct_adapter_node) = {
  .name = "linux-cp-isis-adapter",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_producer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_L2_DIRECT_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_L2_DIRECT_NEXT_##sym] = node,
    foreach_lcp_l2_direct_next
#undef _
  },
};

VNET_FEATURE_INIT (lcp_l2_ip4_feature, static) = {
  .arc_name = "l2-input-ip4",
  .node_name = "linux-cp-l2-punt",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};
VNET_FEATURE_INIT (lcp_l2_ip6_feature, static) = {
  .arc_name = "l2-input-ip6",
  .node_name = "linux-cp-l2-punt",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

static clib_error_t *
lcp_producer_init (vlib_main_t *vm)
{
  ethernet_register_input_type (vm, ETHERNET_TYPE_802_1_LLDP,
				lcp_l2_direct_adapter_node.index);
  ethernet_register_input_type (vm, ETHERNET_TYPE_SLOW_PROTOCOLS,
				lcp_l2_direct_adapter_node.index);
  ethernet_register_input_type (vm, ETHERNET_TYPE_PTP,
				lcp_l2_direct_adapter_node.index);
  llc_register_input_protocol (vm, LLC_PROTOCOL_bpdu,
			       lcp_l2_direct_adapter_node.index);
  osi_register_input_protocol (OSI_PROTOCOL_isis,
			       lcp_isis_direct_adapter_node.index);
  return 0;
}

VLIB_INIT_FUNCTION (lcp_producer_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init"),
};

VLIB_NODE_FN (lcp_igmp_xc_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left && n_left_to_next)
	{
	  u32 bi = from[0], next;
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  ip4_header_t *ip4 = vlib_buffer_get_current (b);

	  vnet_feature_next (&next, b);
	  if (ip4->protocol == IP_PROTOCOL_IGMP)
	    {
	      index_t lipi = lcp_itf_pair_find_by_host (
		vnet_buffer (b)->sw_if_index[VLIB_RX]);
	      lcp_itf_pair_t *lip = lcp_itf_pair_get (lipi);

	      if (lip)
		{
		  word len = (u8 *) vlib_buffer_get_current (b) -
			     (u8 *) ethernet_buffer_get_header (b);
		  vnet_buffer (b)->sw_if_index[VLIB_TX] =
		    lip->lip_phy_sw_if_index;
		  vlib_buffer_advance (b, -len);
		  next = 0;
		}
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

VLIB_REGISTER_NODE (lcp_igmp_xc_node) = {
  .name = "linux-cp-igmp-xc",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = { [0] = "interface-output" },
};
VNET_FEATURE_INIT (lcp_igmp_xc_feature, static) = {
  .arc_name = "ip4-local",
  .node_name = "linux-cp-igmp-xc",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
