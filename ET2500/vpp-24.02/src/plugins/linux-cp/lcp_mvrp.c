/*
 * lcp_mvrp.c - MVRP packet punt handling node definitions
 *
 * Copyright 2024-2027 Asterfusion Network
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>
#include <plugins/linux-cp/lcp_interface.h>


#define foreach_lcp_mvrp                                                       \
  _ (DROP, "error-drop")                                                      \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) LCP_MVRP_NEXT_##sym,
  foreach_lcp_mvrp
#undef _
    LCP_MVRP_N_NEXT,
} lcp_mvrp_next_t;

typedef struct lcp_mvrp_trace_t_
{
  u32 sw_if_index;
} lcp_mvrp_trace_t;

/* packet trace format function */
static u8 *
format_lcp_mvrp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_mvrp_trace_t *t = va_arg (*args, lcp_mvrp_trace_t *);

  s = format (s, "mvrp: sw_if_index %d\n", t->sw_if_index);

  return s;
}

VLIB_NODE_FN (lcp_mvrp_punt_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
  {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 4 && n_left_to_next >= 4)
      {
          u32 bi0, bi1, bi2, bi3;
          vlib_buffer_t *b0, *b1, *b2, *b3;
          u32 next0, next1, next2, next3;
          u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
          lcp_itf_pair_t *lip0 = NULL, *lip1 = NULL, *lip2 = NULL, *lip3 = NULL;
          u32 lipi0 = 0, lipi1 = 0, lipi2 = 0, lipi3 = 0;
          u32 is_host0 = 0, is_host1 = 0, is_host2 = 0, is_host3 = 0;
          u8 len0, len1, len2, len3;

          bi0 = from[0];
          bi1 = from[1];
          bi2 = from[2];
          bi3 = from[3];

          to_next[0] = bi0;
          to_next[1] = bi1;
          to_next[2] = bi2;
          to_next[3] = bi3;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);

          next0 = next1 = next2 = next3 = LCP_MVRP_NEXT_DROP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_RX];
          sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_RX];

          /* Handle L2 RX interface if present */
          if ((b0->flags & VLIB_BUFFER_NOT_PHY_INTF) && (vnet_buffer2(b0)->l2_rx_sw_if_index > 0))
          {
                sw_if_index0 = vnet_buffer2(b0)->l2_rx_sw_if_index;
                vnet_buffer2(b0)->l2_rx_sw_if_index = ~0;
          }
          if ((b1->flags & VLIB_BUFFER_NOT_PHY_INTF) && (vnet_buffer2(b1)->l2_rx_sw_if_index > 0))
          {
                sw_if_index1 = vnet_buffer2(b1)->l2_rx_sw_if_index;
                vnet_buffer2(b1)->l2_rx_sw_if_index = ~0;
          }
          if ((b2->flags & VLIB_BUFFER_NOT_PHY_INTF) && (vnet_buffer2(b2)->l2_rx_sw_if_index > 0))
          {
                sw_if_index2 = vnet_buffer2(b2)->l2_rx_sw_if_index;
                vnet_buffer2(b2)->l2_rx_sw_if_index = ~0;
          }
          if ((b3->flags & VLIB_BUFFER_NOT_PHY_INTF) && (vnet_buffer2(b3)->l2_rx_sw_if_index > 0))
          {
                sw_if_index3 = vnet_buffer2(b3)->l2_rx_sw_if_index;
                vnet_buffer2(b3)->l2_rx_sw_if_index = ~0;
          }

          /* Find interface pair for each packet */
          lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID) is_host0 = 1;
          }
          lip0 = lcp_itf_pair_get (lipi0);

          lipi1 = lcp_itf_pair_find_by_phy (sw_if_index1); 
          if (lipi1 == INDEX_INVALID)
          {
              lipi1 = lcp_itf_pair_find_by_host (sw_if_index1);
              if (lipi1 != INDEX_INVALID) is_host1 = 1;
          }
          lip1 = lcp_itf_pair_get (lipi1);

          lipi2 = lcp_itf_pair_find_by_phy (sw_if_index2); 
          if (lipi2 == INDEX_INVALID)
          {
              lipi2 = lcp_itf_pair_find_by_host (sw_if_index2);
              if (lipi2 != INDEX_INVALID) is_host2 = 1;
          }
          lip2 = lcp_itf_pair_get (lipi2);

          lipi3 = lcp_itf_pair_find_by_phy (sw_if_index3); 
          if (lipi3 == INDEX_INVALID)
          {
              lipi3 = lcp_itf_pair_find_by_host (sw_if_index3);
              if (lipi3 != INDEX_INVALID) is_host3 = 1;
          }
          lip3 = lcp_itf_pair_get (lipi3);

          /* Configure next node and output interface */
          if (lip0)
          {
              next0 = LCP_MVRP_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = 
                  is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }

          if (lip1)
          {
              next1 = LCP_MVRP_NEXT_IO;
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = 
                  is_host1 ? lip1->lip_phy_sw_if_index : lip1->lip_host_sw_if_index;
              len1 = ((u8 *) vlib_buffer_get_current (b1) -
                      (u8 *) ethernet_buffer_get_header (b1));
              vlib_buffer_advance (b1, -len1);
          }

          if (lip2)
          {
              next2 = LCP_MVRP_NEXT_IO;
              vnet_buffer (b2)->sw_if_index[VLIB_TX] = 
                  is_host2 ? lip2->lip_phy_sw_if_index : lip2->lip_host_sw_if_index;
              len2 = ((u8 *) vlib_buffer_get_current (b2) -
                      (u8 *) ethernet_buffer_get_header (b2));
              vlib_buffer_advance (b2, -len2);
          }

          if (lip3)
          {
              next3 = LCP_MVRP_NEXT_IO;
              vnet_buffer (b3)->sw_if_index[VLIB_TX] = 
                  is_host3 ? lip3->lip_phy_sw_if_index : lip3->lip_host_sw_if_index;
              len3 = ((u8 *) vlib_buffer_get_current (b3) -
                      (u8 *) ethernet_buffer_get_header (b3));
              vlib_buffer_advance (b3, -len3);
          }

          /* Tracing */
          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              lcp_mvrp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
          }
          if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
          {
              lcp_mvrp_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
              t->sw_if_index = sw_if_index1;
          }
          if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
          {
              lcp_mvrp_trace_t *t = vlib_add_trace (vm, node, b2, sizeof (*t));
              t->sw_if_index = sw_if_index2;
          }
          if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
          {
              lcp_mvrp_trace_t *t = vlib_add_trace (vm, node, b3, sizeof (*t));
              t->sw_if_index = sw_if_index3;
          }

          from += 4;
          n_left_from -= 4;
          to_next += 4;
          n_left_to_next -= 4;

          vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                  to_next, n_left_to_next,
                  bi0, bi1, bi2, bi3,
                  next0, next1, next2, next3);
      }

      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          u32 sw_if_index0;
          lcp_itf_pair_t *lip0 = NULL;
          u32 lipi0 = 0;
          u32 is_host0 = 0;
          u8 len0;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);
          next0 = LCP_MVRP_NEXT_DROP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          if ((b0->flags & VLIB_BUFFER_NOT_PHY_INTF) && (vnet_buffer2(b0)->l2_rx_sw_if_index > 0))
          {
                sw_if_index0 = vnet_buffer2(b0)->l2_rx_sw_if_index;
                vnet_buffer2(b0)->l2_rx_sw_if_index = ~0;
          }

          lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID) is_host0 = 1;
          }
          lip0 = lcp_itf_pair_get (lipi0);

          if (lip0)
          {
              next0 = LCP_MVRP_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = 
                  is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              lcp_mvrp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
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

  return frame->n_vectors;
}

/*
 * MVRP punt node declaration
 */
VLIB_REGISTER_NODE(lcp_mvrp_punt_node) = {
  .name = "lcp-mvrp-punt",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .format_trace = format_lcp_mvrp_trace,

  .n_next_nodes = LCP_MVRP_N_NEXT,
  .next_nodes = {
    [LCP_MVRP_NEXT_DROP] = "error-drop",
    [LCP_MVRP_NEXT_IO] = "interface-output",
  },
};

static clib_error_t *
lcp_mvrp_init (vlib_main_t *vm)
{
  /* Register MVRP punt node for Ethernet type 0x88F5 */
  ethernet_register_input_type (vm, ETHERNET_TYPE_MVRP, lcp_mvrp_punt_node.index);
  return NULL;
}

VLIB_INIT_FUNCTION (lcp_mvrp_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init"),
};