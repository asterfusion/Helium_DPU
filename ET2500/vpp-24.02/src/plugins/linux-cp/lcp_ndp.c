/*
 * lcp_ndp.c - ndp packet punt handling node definitions
 *
 * Copyright 2024-2027 Asterfusion Network
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ip/format.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/icmp46_packet.h>

#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>

#define foreach_lcp_ndp                                                       \
  _ (PUNT, "linux-cp-punt")                                                   \

typedef enum
{
#define _(sym, str) LCP_NDP_NEXT_##sym,
    foreach_lcp_ndp
#undef _
    LCP_NDP_N_NEXT,
} lcp_ndp_next_t;

#define LCP_NDP_TRACE_DATA_SIZE 64
typedef struct lcp_ndp_trace_t_
{
  u32 sw_if_index;
  u8 packet_data[LCP_NDP_TRACE_DATA_SIZE];
} lcp_ndp_trace_t;

u8 *
format_lcp_ndp_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  lcp_ndp_trace_t *t = va_arg (*va, lcp_ndp_trace_t *);

  s = format (s, "ndp: sw_if_index %d %U", t->sw_if_index,
	      format_ip6_header, t->packet_data, sizeof (t->packet_data));

  return s;
}

VLIB_NODE_FN (lcp_ndp_phy_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0;

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
	  ip6_header_t *ip60, *ip61;
	  icmp46_header_t *icmp0, *icmp1;
	  vlib_buffer_t *c0, *c1;
	  word len0, len1;
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

          ip60 = vlib_buffer_get_current (b0);
          ip61 = vlib_buffer_get_current (b1);

          icmp0 = ip6_ext_header_find(vm, b0, ip60, IP_PROTOCOL_ICMP6, NULL);
          if(icmp0)
          {
              if(PREDICT_FALSE(
                 ICMP6_neighbor_solicitation == icmp0->type ||
                 ICMP6_neighbor_advertisement == icmp0->type ||
                 ICMP6_router_solicitation == icmp0->type ||
                 ICMP6_router_advertisement == icmp0->type ||
                 ICMP6_redirect == icmp0->type
                 ))
              {
		  len0 = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
		  vlib_buffer_advance (b0, -len0);
		  c0 = vlib_buffer_copy (vm, b0);
		  vlib_buffer_advance (b0, len0);
		  if (c0)
		  {
		      copies[n_copies++] = vlib_get_buffer_index (vm, c0);
		  }
              }
          }

          icmp1 = ip6_ext_header_find(vm, b1, ip61, IP_PROTOCOL_ICMP6, NULL);
          if (icmp1)
          {
              if(PREDICT_FALSE(
                 ICMP6_neighbor_solicitation == icmp1->type ||
                 ICMP6_neighbor_advertisement == icmp1->type ||
                 ICMP6_router_solicitation == icmp1->type ||
                 ICMP6_router_advertisement == icmp1->type ||
                 ICMP6_redirect == icmp1->type
                ))
              {
		  len1 = ((u8 *) vlib_buffer_get_current (b1) - (u8 *) ethernet_buffer_get_header (b1));
		  vlib_buffer_advance (b1, -len1);
		  c1 = vlib_buffer_copy (vm, b1);
		  vlib_buffer_advance (b1, len1);
		  if (c1)
		  {
		      copies[n_copies++] = vlib_get_buffer_index (vm, c1);
		  }
              }
          }

      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ndp_trace_t *t0 =
              vlib_add_trace (vm, node, b0, sizeof (*t0));

          t0->sw_if_index = sw_if_index0;
	  clib_memcpy_fast (t0, b0->data + b0->current_data, LCP_NDP_TRACE_DATA_SIZE);
      }

      if (b1->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ndp_trace_t *t1 =
              vlib_add_trace (vm, node, b1, sizeof (*t1));

          t1->sw_if_index = sw_if_index1;
	  clib_memcpy_fast (t1, b1->data + b1->current_data, LCP_NDP_TRACE_DATA_SIZE);
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
	  ip6_header_t *ip6;
	  icmp46_header_t *icmp;
	  u32 sw_if_index0;

	  vlib_buffer_t *c;
	  word len;

	  bi0 = from[0];
	  to_next[0] = bi0;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* most packets will follow feature arc */
	  vnet_feature_next (&next0, b0);

	  sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          ip6 = vlib_buffer_get_current (b0);
          icmp = ip6_ext_header_find(vm, b0, ip6, IP_PROTOCOL_ICMP6, NULL);
          if(icmp)
          {
              if(PREDICT_FALSE(
                 ICMP6_neighbor_solicitation == icmp->type ||
                 ICMP6_neighbor_advertisement == icmp->type ||
                 ICMP6_router_solicitation == icmp->type ||
                 ICMP6_router_advertisement == icmp->type ||
                 ICMP6_redirect == icmp->type
                 ))
              {
		  len = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
		  vlib_buffer_advance (b0, -len);
		  c = vlib_buffer_copy (vm, b0);
		  vlib_buffer_advance (b0, len);
		  if (c)
		  {
		      copies[n_copies++] = vlib_get_buffer_index (vm, c);
		  }
              }
          }


      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
          lcp_ndp_trace_t *t =
              vlib_add_trace (vm, node, b0, sizeof (*t));

          t->sw_if_index = sw_if_index0;
	  clib_memcpy_fast (t, b0->data + b0->current_data, LCP_NDP_TRACE_DATA_SIZE);
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

  if (PREDICT_FALSE(n_copies))
  {
    vlib_buffer_enqueue_to_single_next (vm, node, copies,
					LCP_NDP_NEXT_PUNT, n_copies);
  }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_ndp_phy_node) =
{
  .name = "linux-cp-ndp-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_ndp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_NDP_N_NEXT,

  .next_nodes = {
    [LCP_NDP_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_ndp_phy_uc, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-ndp-phy",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

VNET_FEATURE_INIT (lcp_ndp_phy_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-ndp-phy",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

