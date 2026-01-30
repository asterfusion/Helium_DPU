/*
 * lcp_igmp.c - igmp and mld packet punt handling node definitions
 *
 * Copyright 2024-2027 Asterfusion Network
 *G
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp_adj.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

#define foreach_lcp_pim                                                      \
  _ (PUNT, "linux-cp-punt")                                                   \

typedef enum
{
#define _(sym, str) LCP_PIM_NEXT_##sym,
    foreach_lcp_pim
#undef _
    LCP_PIM_N_NEXT,
} lcp_pim_next_t;

typedef struct lcp_pim_trace_t_
{
  u32 sw_if_index;
} lcp_pim_trace_t;

/* packet trace format function */
static u8 *
format_lcp_pim_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_pim_trace_t *t = va_arg (*args, lcp_pim_trace_t *);

  s = format (s, "pim: sw_if_index %d\n", t->sw_if_index);
  return s;
}

always_inline uword 
pim_ip4_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, int is_l2_path)
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
          ip4_header_t *ip40, *ip41;
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

          if (is_l2_path)
          {
              ip40 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
              ip41 = vlib_buffer_get_current (b1) + vnet_buffer (b1)->l2.l2_len;
              len0 = 0;
              len1 = 0;
          }
          else
          {
              ip40 = vlib_buffer_get_current (b0);
              ip41 = vlib_buffer_get_current (b1);
              len0 = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
              len1 = ((u8 *) vlib_buffer_get_current (b1) - (u8 *) ethernet_buffer_get_header (b1));
          }

          /* Check if IP protocol is PIM (103) */
          if (PREDICT_FALSE(ip40->protocol == IP_PROTOCOL_PIM))
          {
              if (is_l2_path) {
                  c0 = vlib_buffer_copy (vm, b0);
              } else {
                  vlib_buffer_advance (b0, -len0);
                  c0 = vlib_buffer_copy (vm, b0);
                  vlib_buffer_advance (b0, len0);
              }
              if (c0)
              {
                  copies[n_copies++] = vlib_get_buffer_index (vm, c0);
              }
          }

          if (PREDICT_FALSE(ip41->protocol == IP_PROTOCOL_PIM))
          {
              if (is_l2_path) {
                  c1 = vlib_buffer_copy (vm, b1);
              } else {
                  vlib_buffer_advance (b1, -len1);
                  c1 = vlib_buffer_copy (vm, b1);
                  vlib_buffer_advance (b1, len1);
              }
              if (c1)
              {
                  copies[n_copies++] = vlib_get_buffer_index (vm, c1);
              }
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
              t0->sw_if_index = sw_if_index0;
          }
    
          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
              t1->sw_if_index = sw_if_index1;
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
          u32 sw_if_index0;
          vlib_buffer_t *c;
          word len;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);

          /* most packets will follow feature arc */
          vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (is_l2_path)
          {
              ip4 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
              len = 0;
          }
          else
          {
              ip4 = vlib_buffer_get_current (b0);
              len = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
          }

          /* Check if IP protocol is PIM (103) */
          if (PREDICT_FALSE(ip4->protocol == IP_PROTOCOL_PIM))
          {
              if (is_l2_path) {
                  c = vlib_buffer_copy (vm, b0);
              } else {
                  vlib_buffer_advance (b0, -len);
                  c = vlib_buffer_copy (vm, b0);
                  vlib_buffer_advance (b0, len);
              }
              if (c)
              {
                  copies[n_copies++] = vlib_get_buffer_index (vm, c);
              }
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
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
                                        LCP_PIM_NEXT_PUNT, n_copies);
  }

  return frame->n_vectors;
}

always_inline uword 
pim_ip6_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, int is_l2_path)
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
          u8 *pim0, *pim1;
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

          if (is_l2_path)
          {
              ip60 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
              ip61 = vlib_buffer_get_current (b1) + vnet_buffer (b1)->l2.l2_len;
              len0 = 0;
              len1 = 0;
          }
          else
          {
              ip60 = vlib_buffer_get_current (b0);
              ip61 = vlib_buffer_get_current (b1);
              len0 = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
              len1 = ((u8 *) vlib_buffer_get_current (b1) - (u8 *) ethernet_buffer_get_header (b1));
          }

          /* Find PIM header in IPv6 extension headers */
          pim0 = ip6_ext_header_find(vm, b0, ip60, IP_PROTOCOL_PIM, NULL);
          if (PREDICT_FALSE(pim0 != NULL))
          {
              if (is_l2_path) 
              {
                c0 = vlib_buffer_copy (vm, b0);
              } 
              else 
              {
                vlib_buffer_advance (b0, -len0);
                c0 = vlib_buffer_copy (vm, b0);
                vlib_buffer_advance (b0, len0);
              }
              if (c0)
              {
                copies[n_copies++] = vlib_get_buffer_index (vm, c0);
              }
          }
          
          pim1 = ip6_ext_header_find(vm, b1, ip61, IP_PROTOCOL_PIM, NULL);
          if (PREDICT_FALSE(pim1 != NULL))
          {
              if (is_l2_path) 
              {
                c1 = vlib_buffer_copy (vm, b1);
              } 
              else 
              {
                vlib_buffer_advance (b1, -len1);
                c1 = vlib_buffer_copy (vm, b1);
                vlib_buffer_advance (b1, len1);
              }
              if (c1)
              {
                copies[n_copies++] = vlib_get_buffer_index (vm, c1);
              }
          }
        
          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
              t0->sw_if_index = sw_if_index0;
          }
    
          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
              t1->sw_if_index = sw_if_index1;
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
          u8 *pim;
          u32 sw_if_index0;
          vlib_buffer_t *c;
          word len;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);

          /* most packets will follow feature arc */
          vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (is_l2_path)
          {
              ip6 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
              len = 0;
          }
          else
          {
              ip6 = vlib_buffer_get_current (b0);
              len = ((u8 *) vlib_buffer_get_current (b0) - (u8 *) ethernet_buffer_get_header (b0));
          }

          pim = ip6_ext_header_find(vm, b0, ip6, IP_PROTOCOL_PIM, NULL);
          if (PREDICT_FALSE(pim != NULL))
          {
              if (is_l2_path) 
              {
                c = vlib_buffer_copy (vm, b0);
              } 
              else 
              {
                vlib_buffer_advance (b0, -len);
                c = vlib_buffer_copy (vm, b0);
                vlib_buffer_advance (b0, len);
              }
              if (c)
              {
                copies[n_copies++] = vlib_get_buffer_index (vm, c);
              }
          }
          
          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pim_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
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
                                        LCP_PIM_NEXT_PUNT, n_copies);
  }

  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_pim4_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return pim_ip4_node_fn(vm, node, frame, 0);
}

VLIB_NODE_FN (lcp_pim6_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return pim_ip6_node_fn(vm, node, frame, 0);
}

VLIB_REGISTER_NODE (lcp_pim4_node) =
{
  .name = "linux-cp-pim",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_pim_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_PIM_N_NEXT,

  .next_nodes = {
    [LCP_PIM_NEXT_PUNT] = "linux-cp-punt",
  },
};

VLIB_REGISTER_NODE (lcp_pim6_node) =
{
  .name = "linux-cp-pim6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_pim_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_PIM_N_NEXT,

  .next_nodes = {
    [LCP_PIM_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_pim4_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-pim",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (lcp_pim6_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-pim6",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};
