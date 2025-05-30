/*
 * lcp_lldp.c - lldp packet punt handling node definitions
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
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_sas.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>
#include <plugins/linux-cp/lcp_interface.h>

#define foreach_lcp_lldp                                                       \
  _ (DROP, "error-drop")                                                      \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) LCP_LLDP_NEXT_##sym,
  foreach_lcp_lldp
#undef _
    LCP_LLDP_N_NEXT,
} lcp_lldp_next_t;

typedef struct lcp_lldp_trace_t_
{
  u32 sw_if_index;
  u8 is_ipv6;
} lcp_lldp_trace_t;

/* packet trace format function */
static u8 *
format_lcp_lldp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_lldp_trace_t *t = va_arg (*args, lcp_lldp_trace_t *);

  s = format (s, "lldp: sw_if_index %d IPv%d\n",
	      t->sw_if_index, (t->is_ipv6) ? 6 : 4);

  return s;
}
VLIB_NODE_FN (lcp_lldp_punt_node) (vlib_main_t * vm,
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

      while (n_left_from >= 2 && n_left_to_next >= 2)
      {
          u32 bi0, bi1;
          vlib_buffer_t *b0, *b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
	      lcp_itf_pair_t *lip0 = NULL;
	      lcp_itf_pair_t *lip1 = NULL;
	      u32 lipi0 = 0;
	      u32 lipi1 = 0;
          u32 is_host0 = 0;
          u32 is_host1 = 0;
	  u8 len0, len1;

          bi0 = from[0];
          bi1 = from[1];

          to_next[0] = bi0;
          to_next[1] = bi1;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          next0 = next1 = LCP_LLDP_NEXT_DROP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          //vnet_feature_next (&next0, b0);
          //vnet_feature_next (&next1, b1);
        if (vnet_buffer2(b0)->l2_rx_sw_if_index > 0)
          {
                sw_if_index0 = vnet_buffer2(b0)->l2_rx_sw_if_index;
          }
          if (vnet_buffer2(b1)->l2_rx_sw_if_index > 0)
          {
                sw_if_index1 = vnet_buffer2(b1)->l2_rx_sw_if_index;
          }

	      lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID)
              {
                  is_host0 = 1;
              }
          }
          lip0 = lcp_itf_pair_get (lipi0);

          if (lip0)
          {
              next0 = LCP_LLDP_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }

	      lipi1 = lcp_itf_pair_find_by_phy ( sw_if_index1);
          if (lipi1 == INDEX_INVALID)
          {
              lipi1 = lcp_itf_pair_find_by_host (sw_if_index1);
              if (lipi1 != INDEX_INVALID)
              {
                  is_host1 = 1;
              }
          }
          lip1 = lcp_itf_pair_get (lipi1);

          if (lip1)
          {
              next1 = LCP_LLDP_NEXT_IO;
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = is_host1 ? lip1->lip_phy_sw_if_index : lip1->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len1 = ((u8 *) vlib_buffer_get_current (b1) -
                      (u8 *) ethernet_buffer_get_header (b1));
              vlib_buffer_advance (b1, -len1);
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_lldp_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));

              t->sw_if_index = sw_if_index0;
          }

          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_lldp_trace_t *t =
                  vlib_add_trace (vm, node, b1, sizeof (*t));

              t->sw_if_index = sw_if_index1;
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
          u32 sw_if_index0;
	      lcp_itf_pair_t *lip0 = NULL;
	      u32 lipi0 = 0;
          u32 is_host0 = 0;
	  u8 len0;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);

          next0 = LCP_LLDP_NEXT_DROP;

          /* most packets will follow feature arc */
          //vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          if (vnet_buffer2(b0)->l2_rx_sw_if_index > 0)
          {
                sw_if_index0 = vnet_buffer2(b0)->l2_rx_sw_if_index;
          }
     

	      lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID)
              {
                  is_host0 = 1;
              }
          }
          lip0 = lcp_itf_pair_get (lipi0);

          if (lip0)
          {
              next0 = LCP_LLDP_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }


          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_lldp_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));

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
 * lldp input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(lcp_lldp_punt_node) = {
  .name = "lcp-lldp-punt",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .format_trace = format_lcp_lldp_trace,

  .n_next_nodes = LCP_LLDP_N_NEXT,
  .next_nodes =
  {
    [LCP_LLDP_NEXT_DROP] = "error-drop",
    [LCP_LLDP_NEXT_IO] = "interface-output",
  },
};

static clib_error_t *
lcp_lldp_init (vlib_main_t *vm)
{
  /* register lldp punt node */
  ethernet_register_input_type (vm, ETHERNET_TYPE_802_1_LLDP /* LLDP */ ,
				lcp_lldp_punt_node.index);
  ethernet_register_input_type (vm, ETHERNET_TYPE_802_1X_AUTHENTICATION/* dot1x */ ,
				lcp_lldp_punt_node.index);
  return NULL;
}

VLIB_INIT_FUNCTION (lcp_lldp_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init"),
};
