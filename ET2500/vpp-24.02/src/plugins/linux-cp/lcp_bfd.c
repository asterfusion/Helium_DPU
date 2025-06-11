/*
 * lcp_bfd.c - bfd packet punt handling node definitions
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
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>
#include <plugins/linux-cp/lcp_interface.h>

// 定义 BFD 相关的 UDP 端口号
#define UDP_DST_PORT_BFD_CONTROL 3784
#define UDP_DST_PORT_BFD_ECHO 3785
#define UDP6_DST_PORT_BFD_CONTROL 3784
#define UDP6_DST_PORT_BFD_ECHO 3785

#define foreach_lcp_bfd                                                       \
  _ (PUNT, "linux-cp-punt")                                                   \

typedef enum
{
#define _(sym, str) LCP_BFD_NEXT_##sym,
    foreach_lcp_bfd
#undef _
    LCP_BFD_N_NEXT,
} lcp_bfd_next_t;

typedef struct lcp_bfd_trace_t_
{
  u32 sw_if_index;
  u8 is_ipv6;
} lcp_bfd_trace_t;

/* packet trace format function */
static u8 *
format_lcp_bfd_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_bfd_trace_t *t = va_arg (*args, lcp_bfd_trace_t *);

  s = format (s, "bfd: sw_if_index %d IPv%d\n",
              t->sw_if_index, (t->is_ipv6) ? 6 : 4);

  return s;
}

static_always_inline uword
lcp_bfd_phy_node_inline (vlib_main_t * vm,
                          vlib_node_runtime_t * node,
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
      udp_header_t *udph0, *udph1;
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

      //set max tc priority
      lcp_set_max_tc(b0);
      lcp_set_max_tc(b1);

      if (is_ipv6)
      {
        ip60 = vlib_buffer_get_current (b0);
        ip61 = vlib_buffer_get_current (b1);

        udph0 = ip6_ext_header_find(vm, b0, ip60, IP_PROTOCOL_UDP, NULL);
        if(udph0)
        {
          if(PREDICT_FALSE(
             UDP6_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph0->dst_port) ||
             UDP6_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph0->dst_port)
             ))
          {
            next0 = LCP_BFD_NEXT_PUNT;
          }
        }

        udph1 = ip6_ext_header_find(vm, b1, ip61, IP_PROTOCOL_UDP, NULL);
        if (udph1)
        {
          if(PREDICT_FALSE(
             UDP6_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph1->dst_port) ||
             UDP6_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph1->dst_port)
            ))
          {
            next1 = LCP_BFD_NEXT_PUNT;
          }
        }
      }
      else
      {
        ip40 = vlib_buffer_get_current (b0);
        ip41 = vlib_buffer_get_current (b1);

        if (ip40->protocol == IP_PROTOCOL_UDP)
        {
          udph0 = ip4_next_header(ip40);
          if(PREDICT_FALSE(
             UDP_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph0->dst_port) ||
             UDP_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph0->dst_port)
            ))
          {
            next0 = LCP_BFD_NEXT_PUNT;
          }
        }
        if (ip41->protocol == IP_PROTOCOL_UDP)
        {
          udph1 = ip4_next_header(ip41);
          if(PREDICT_FALSE(
             UDP_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph1->dst_port) ||
             UDP_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph1->dst_port)
             ))
          {
            next1 = LCP_BFD_NEXT_PUNT;
          }
        }
      }


      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
        lcp_bfd_trace_t *t =
            vlib_add_trace (vm, node, b0, sizeof (*t));

        t->sw_if_index = sw_if_index0;
        t->is_ipv6 = is_ipv6;
      }

      if (b1->flags & VLIB_BUFFER_IS_TRACED)
      {
        lcp_bfd_trace_t *t =
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
      udp_header_t *udph;
      u32 sw_if_index0;

      bi0 = from[0];
      to_next[0] = bi0;

      b0 = vlib_get_buffer (vm, bi0);

      /* most packets will follow feature arc */
      vnet_feature_next (&next0, b0);

      sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

      //set max tc priority
      lcp_set_max_tc(b0);

      if (is_ipv6)
      {
        ip6 = vlib_buffer_get_current (b0);
        udph = ip6_ext_header_find(vm, b0, ip6, IP_PROTOCOL_UDP, NULL);
        if(udph)
        {
          if(PREDICT_FALSE(
             UDP6_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph->dst_port) ||
             UDP6_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph->dst_port)
             ))
          {
            next0 = LCP_BFD_NEXT_PUNT;
          }
        }
      }
      else
      {
        ip4 = vlib_buffer_get_current (b0);
        udph = ip4_next_header(ip4);
        if(PREDICT_FALSE(
              UDP_DST_PORT_BFD_CONTROL == clib_net_to_host_u16(udph->dst_port) ||
              UDP_DST_PORT_BFD_ECHO == clib_net_to_host_u16(udph->dst_port)
              ))
        {
          next0 = LCP_BFD_NEXT_PUNT;
        }
      }


      if (b0->flags & VLIB_BUFFER_IS_TRACED)
      {
        lcp_bfd_trace_t *t =
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

VLIB_NODE_FN (lcp_bfd_phy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lcp_bfd_phy_node_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (lcp_bfdv6_phy_node) (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lcp_bfd_phy_node_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (lcp_bfd_phy_node) =
{
  .name = "linux-cp-bfd-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_bfd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_BFD_N_NEXT,

  .next_nodes = {
    [LCP_BFD_NEXT_PUNT] = "linux-cp-punt",
  },
};

VLIB_REGISTER_NODE (lcp_bfdv6_phy_node) =
{
  .name = "linux-cp-bfdv6-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_bfd_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_BFD_N_NEXT,

  .next_nodes = {
    [LCP_BFD_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_bfd_phy_uc, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-bfd-phy",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (lcp_bfd_phy_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-bfd-phy",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (lcp_bfdv6_phy_uc, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-bfdv6-phy",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

VNET_FEATURE_INIT (lcp_bfdv6_phy_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-bfdv6-phy",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};