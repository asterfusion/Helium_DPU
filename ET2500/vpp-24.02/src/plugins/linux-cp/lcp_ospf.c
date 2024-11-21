/*
 * lcp_ospf.c - ospf packet punt handling node definitions
 *
 * Copyright 2024-2027 Asterfusion Network
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/fib/fib_sas.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>

#define foreach_lcp_ospf                                                       \
  _ (PUNT, "linux-cp-punt")                                                   \

typedef enum
{
#define _(sym, str) LCP_OSPF_NEXT_##sym,
  foreach_lcp_ospf
#undef _
    LCP_OSPF_N_NEXT,
} lcp_ospf_next_t;

typedef struct lcp_ospf_trace_t_
{
  u32 sw_if_index;
  u8 is_ipv6;
} lcp_ospf_trace_t;

/* packet trace format function */
static u8 *
format_lcp_ospf_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_ospf_trace_t *t = va_arg (*args, lcp_ospf_trace_t *);

  s = format (s, "OSPF: sw_if_index %d IPv%d\n",
	      t->sw_if_index, (t->is_ipv6) ? 6 : 4);

  return s;
}

static_always_inline uword
lcp_ospf_phy_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
				vlib_frame_t * frame, u8 is_ipv6)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;
	  ip4_header_t *ip40, *ip41;
	  ip6_header_t *ip60, *ip61;
	  u32 sw_if_index0, sw_if_index1;

	  bi0 = from[0];
	  bi1 = from[1];

	  to_next[0] = bi0;
	  to_next[1] = bi1;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);

	  /* most packets will follow feature arc */
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	  sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

      if (is_ipv6)
      {
          ip60 = vlib_buffer_get_current (b0);
          ip61 = vlib_buffer_get_current (b1);

          if (PREDICT_FALSE (ip60->protocol == IP_PROTOCOL_OSPF))
          {
              next0 = LCP_OSPF_NEXT_PUNT;
          }
          if (PREDICT_FALSE (ip61->protocol == IP_PROTOCOL_OSPF))
          {
              next1 = LCP_OSPF_NEXT_PUNT;
          }
      }
	  else
      {
          ip40 = vlib_buffer_get_current (b0);
          ip41 = vlib_buffer_get_current (b1);

          if (PREDICT_FALSE (ip40->protocol == IP_PROTOCOL_OSPF))
          {
              next0 = LCP_OSPF_NEXT_PUNT;
          }
          if (PREDICT_FALSE (ip41->protocol == IP_PROTOCOL_OSPF))
          {
              next1 = LCP_OSPF_NEXT_PUNT;
          }
      }


      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ospf_trace_t *t =
              vlib_add_trace (vm, node, b0, sizeof (*t));

          t->sw_if_index = sw_if_index0;
          t->is_ipv6 = is_ipv6;
      }

      if (b1->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ospf_trace_t *t =
              vlib_add_trace (vm, node, b1, sizeof (*t));

          t->sw_if_index = sw_if_index1;
          t->is_ipv6 = is_ipv6;
      }

	  from += 2;
	  n_left_from -= 2;
	  to_next += 2;
	  n_left_to_next -= 2;

	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  ip4_header_t *ip4;
	  ip6_header_t *ip6;
	  u32 sw_if_index0;

	  bi0 = from[0];
	  to_next[0] = bi0;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* most packets will follow feature arc */
	  vnet_feature_next (&next0, b0);

	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	  if (is_ipv6)
      {
          ip6 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_OSPF))
          {
              next0 = LCP_OSPF_NEXT_PUNT;
          }
      }
      else
      {
          ip4 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE (ip4->protocol == IP_PROTOCOL_OSPF))
          {
              next0 = LCP_OSPF_NEXT_PUNT;
          }
      }


      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ospf_trace_t *t =
              vlib_add_trace (vm, node, b0, sizeof (*t));

          t->sw_if_index = sw_if_index0;
          t->is_ipv6 = is_ipv6;
      }

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_ospfv2_phy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_ospf_phy_node_inline (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (lcp_ospfv2_phy_node) =
{
  .name = "linux-cp-ospfv2-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_ospf_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_OSPF_N_NEXT,

  .next_nodes = {
    [LCP_OSPF_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_ospfv2_phy_feat, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-ospfv2-phy",
  .runs_before = VNET_FEATURES ("ip4-mfib-forward-lookup"),
};

VLIB_NODE_FN (lcp_ospfv3_phy_node) (vlib_main_t * vm,
					   vlib_node_runtime_t * node,
					   vlib_frame_t * frame)
{
  return lcp_ospf_phy_node_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (lcp_ospfv3_phy_node) =
{
  .name = "linux-cp-ospfv3-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_ospf_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_OSPF_N_NEXT,

  .next_nodes = {
    [LCP_OSPF_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_ospfv3_phy_feat, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-ospfv3-phy",
  .runs_before = VNET_FEATURES ("ip6-mfib-forward-lookup"),
};

