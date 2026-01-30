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
#include <vnet/ip/icmp46_packet.h>
#include <vnet/feature/feature.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp_interface.h>
#include <linux-cp/lcp_adj.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>

/* MLD ICMPv6 types */
#define ICMP6_MLD_LISTENER_QUERY    130
#define ICMP6_MLD_LISTENER_REPORT   131
#define ICMP6_MLD_LISTENER_DONE     132
#define ICMP6_MLD2_LISTENER_REPORT  143

#define foreach_lcp_igmp                                                      \
  _ (PUNT, "linux-cp-punt")                                                   \

typedef enum
{
#define _(sym, str) LCP_IGMP_NEXT_##sym,
    foreach_lcp_igmp
#undef _
    LCP_IGMP_N_NEXT,
} lcp_igmp_next_t;

typedef struct lcp_igmp_trace_t_
{
  u32 sw_if_index;
} lcp_igmp_trace_t;

/* packet trace format function */
static u8 *
format_lcp_igmp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_igmp_trace_t *t = va_arg (*args, lcp_igmp_trace_t *);

  s = format (s, "igmp/mld: sw_if_index %d\n", t->sw_if_index);
  return s;
}

always_inline uword 
igmp_ip4_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, int is_l2_path)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 punt_indices[VLIB_FRAME_SIZE];
  u32 n_punts = 0;

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
          u32 sw_if_index0, sw_if_index1;
          u32 is_igmp0 = 0, is_igmp1 = 0;

          bi0 = from[0];
          bi1 = from[1];

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
          }
          else
          {
              ip40 = vlib_buffer_get_current (b0);
              ip41 = vlib_buffer_get_current (b1);
          }

          /* Check if IP protocol is IGMP (2) */
          if (PREDICT_FALSE(ip40->protocol == IP_PROTOCOL_IGMP))
          {
              /* Mark as IGMP packet to punt */
              is_igmp0 = 1;
              next0 = LCP_IGMP_NEXT_PUNT;
          }
          else
          {
              /* Non-IGMP packet, enqueue normally */
              to_next[0] = bi0;
              to_next += 1;
              n_left_to_next -= 1;
          }

          if (PREDICT_FALSE(ip41->protocol == IP_PROTOCOL_IGMP))
          {
              /* Mark as IGMP packet to punt */
              is_igmp1 = 1;
              next1 = LCP_IGMP_NEXT_PUNT;
          }
          else
          {
              /* Non-IGMP packet, enqueue normally */
              to_next[0] = bi1;
              to_next += 1;
              n_left_to_next -= 1;
          }

          /* Enqueue IGMP packets to punt */
          if (is_igmp0)
          {
              punt_indices[n_punts++] = bi0;
          }
          
          if (is_igmp1)
          {
              punt_indices[n_punts++] = bi1;
          }

          /* Add trace for non-IGMP packets (or all packets if needed) */
          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
              t0->sw_if_index = sw_if_index0;
          }
    
          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
              t1->sw_if_index = sw_if_index1;
          }

          from += 2;
          n_left_from -= 2;

          /* Only validate enqueue for non-IGMP packets */
          if (!is_igmp0 && !is_igmp1)
          {
              vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, bi1, next0, next1);
          }
          else if (!is_igmp0)
          {
              /* Only b0 is non-IGMP */
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, next0);
          }
          else if (!is_igmp1)
          {
              /* Only b1 is non-IGMP */
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi1, next1);
          }
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          ip4_header_t *ip4;
          u32 sw_if_index0;
          u32 is_igmp = 0;

          bi0 = from[0];
          b0 = vlib_get_buffer (vm, bi0);

          /* most packets will follow feature arc */
          vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (is_l2_path)
          {
              ip4 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
          }
          else
          {
              ip4 = vlib_buffer_get_current (b0);
          }

          /* Check if IP protocol is IGMP (2) */
          if (PREDICT_FALSE(ip4->protocol == IP_PROTOCOL_IGMP))
          {
              /* Mark as IGMP packet to punt */
              is_igmp = 1;
              next0 = LCP_IGMP_NEXT_PUNT;
              punt_indices[n_punts++] = bi0;
          }
          else
          {
              /* Non-IGMP packet, enqueue normally */
              to_next[0] = bi0;
              to_next += 1;
              n_left_to_next -= 1;
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
          }

          from += 1;
          n_left_from -= 1;

          /* Only validate enqueue for non-IGMP packets */
          if (!is_igmp)
          {
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, next0);
          }
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Punt IGMP packets to LCP_IGMP_NEXT_PUNT */
  if (PREDICT_FALSE(n_punts > 0))
  {
    vlib_buffer_enqueue_to_single_next (vm, node, punt_indices,
                                        LCP_IGMP_NEXT_PUNT, n_punts);
  }

  return frame->n_vectors;
}

always_inline uword 
mld_ip6_node_fn(vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame, int is_l2_path)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  u32 punt_indices[VLIB_FRAME_SIZE];
  u32 n_punts = 0;

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
          icmp46_header_t *icmp0 = NULL, *icmp1 = NULL;
          u32 sw_if_index0, sw_if_index1;
          u32 is_mld0 = 0, is_mld1 = 0;

          bi0 = from[0];
          bi1 = from[1];

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
          }
          else
          {
              ip60 = vlib_buffer_get_current (b0);
              ip61 = vlib_buffer_get_current (b1);
          }

          /* Check for MLD packets */
          icmp0 = ip6_ext_header_find(vm, b0, ip60, IP_PROTOCOL_ICMP6, NULL);
          if (icmp0)
          {
            if (PREDICT_FALSE(
                 ICMP6_multicast_listener_request == icmp0->type ||
                 ICMP6_multicast_listener_report == icmp0->type ||
                 ICMP6_multicast_listener_done == icmp0->type ||
                 ICMP6_multicast_listener_report_v2 == icmp0->type
                 ))
            {
              /* MLD packet - mark for punt */
              is_mld0 = 1;
              next0 = LCP_IGMP_NEXT_PUNT;
              punt_indices[n_punts++] = bi0;
            }
          }
          
          icmp1 = ip6_ext_header_find(vm, b1, ip61, IP_PROTOCOL_ICMP6, NULL);
          if (icmp1)
          {
            if (PREDICT_FALSE(
                 ICMP6_multicast_listener_request == icmp1->type ||
                 ICMP6_multicast_listener_report == icmp1->type ||
                 ICMP6_multicast_listener_done == icmp1->type ||
                 ICMP6_multicast_listener_report_v2 == icmp1->type
                 ))
            {
              /* MLD packet - mark for punt */
              is_mld1 = 1;
              next1 = LCP_IGMP_NEXT_PUNT;
              punt_indices[n_punts++] = bi1;
            }
          }
        
          /* Enqueue non-MLD packets normally */
          if (!is_mld0)
          {
              to_next[0] = bi0;
              to_next += 1;
              n_left_to_next -= 1;
          }
          
          if (!is_mld1)
          {
              to_next[0] = bi1;
              to_next += 1;
              n_left_to_next -= 1;
          }

          /* Add trace for all packets */
          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
              t0->sw_if_index = sw_if_index0;
          }
    
          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
              t1->sw_if_index = sw_if_index1;
          }

          from += 2;
          n_left_from -= 2;

          /* Only validate enqueue for non-MLD packets */
          if (!is_mld0 && !is_mld1)
          {
              vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, bi1, next0, next1);
          }
          else if (!is_mld0)
          {
              /* Only b0 is non-MLD */
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, next0);
          }
          else if (!is_mld1)
          {
              /* Only b1 is non-MLD */
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi1, next1);
          }
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          ip6_header_t *ip6;
          icmp46_header_t *icmp = NULL;
          u32 sw_if_index0;
          u32 is_mld = 0;

          bi0 = from[0];
          b0 = vlib_get_buffer (vm, bi0);

          /* most packets will follow feature arc */
          vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (is_l2_path)
          {
              ip6 = vlib_buffer_get_current (b0) + vnet_buffer (b0)->l2.l2_len;
          }
          else
          {
              ip6 = vlib_buffer_get_current (b0);
          }

          icmp = ip6_ext_header_find(vm, b0, ip6, IP_PROTOCOL_ICMP6, NULL);
          if (icmp)
          {
            if (PREDICT_FALSE(
                 ICMP6_multicast_listener_request == icmp->type ||
                 ICMP6_multicast_listener_report == icmp->type ||
                 ICMP6_multicast_listener_done == icmp->type ||
                 ICMP6_multicast_listener_report_v2 == icmp->type
                 ))
            {
              /* MLD packet - mark for punt */
              is_mld = 1;
              next0 = LCP_IGMP_NEXT_PUNT;
              punt_indices[n_punts++] = bi0;
            }
          }
          
          /* Enqueue non-MLD packets normally */
          if (!is_mld)
          {
              to_next[0] = bi0;
              to_next += 1;
              n_left_to_next -= 1;
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_igmp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->sw_if_index = sw_if_index0;
          }

          from += 1;
          n_left_from -= 1;

          /* Only validate enqueue for non-MLD packets */
          if (!is_mld)
          {
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                               to_next, n_left_to_next,
                                               bi0, next0);
          }
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  /* Punt MLD packets to LCP_IGMP_NEXT_PUNT */
  if (PREDICT_FALSE(n_punts > 0))
  {
    vlib_buffer_enqueue_to_single_next (vm, node, punt_indices,
                                        LCP_IGMP_NEXT_PUNT, n_punts);
  }

  return frame->n_vectors;
}

typedef struct lcp_igmp_xc_trace_t_
{
  u32 host_sw_if_index;
  u32 phy_sw_if_index;
  // u32 adj_index;
} lcp_igmp_xc_trace_t;

static u8 *
format_lcp_igmp_xc_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_igmp_xc_trace_t *t = va_arg (*args, lcp_igmp_xc_trace_t *);

  s = format (s, "igmp-xc: host-sw-if-index %d -> phy-sw-if-index %d",
              t->host_sw_if_index, t->phy_sw_if_index);
  return s;
}

typedef enum
{
  IGMP_NEXT_INTERFACE_OUTPUT,
  IGMP_N_NEXT,
} igmp_next_t;

static_always_inline u32
lcp_igmp_xc_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  u32 next_index = 0;
  u32 n_copied = 0;

  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          const lcp_itf_pair_t *lip;
          u32 next0, bi0, lipi;
          vlib_buffer_t *b0;
          ip4_header_t *ip4;
          u8 len0;

          bi0 = to_next[0] = from[0];

          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          ip4 = vlib_buffer_get_current (b0);

          if (PREDICT_TRUE(ip4->protocol != IP_PROTOCOL_IGMP))
            {
              vnet_feature_next (&next0, b0);
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                             n_left_to_next, bi0, next0);
              continue;
            }

          lipi = lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
          
          if (PREDICT_FALSE(lipi == ~0))
            {
              vnet_feature_next (&next0, b0);
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                             n_left_to_next, bi0, next0);
              continue;
            }

          lip = lcp_itf_pair_get (lipi);

          vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;

          len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
          vlib_buffer_advance (b0, -len0);

          next0 = IGMP_NEXT_INTERFACE_OUTPUT;
          if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lcp_igmp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
              t->host_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
              t->phy_sw_if_index = lip->lip_phy_sw_if_index;
              // t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
            }

          n_copied++;
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                                         n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return n_copied;
}

VLIB_REGISTER_NODE (lcp_igmp_xc_node) =
{
  .name = "linux-cp-igmp-xc",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_igmp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = IGMP_N_NEXT,

  .next_nodes = {
    [IGMP_NEXT_INTERFACE_OUTPUT] = "interface-output",
  },
};

VNET_FEATURE_INIT (lcp_igmp_xc_feature, static) =
{
  .arc_name = "ip4-local",
  .node_name = "linux-cp-igmp-xc",
  .runs_before = VNET_FEATURES (0),
};

VLIB_NODE_FN (lcp_igmp_xc_node) (vlib_main_t *vm, vlib_node_runtime_t *node, 
                                vlib_frame_t *frame)
{
  return lcp_igmp_xc_inline (vm, node, frame);
}

VLIB_NODE_FN (lcp_igmp4_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return igmp_ip4_node_fn(vm, node, frame, 0);
}

VLIB_NODE_FN (lcp_igmp6_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return mld_ip6_node_fn(vm, node, frame, 0);
}

VLIB_NODE_FN (lcp_l2_igmp4_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return igmp_ip4_node_fn(vm, node, frame, 1);
}

VLIB_NODE_FN (lcp_l2_igmp6_node) (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    return mld_ip6_node_fn(vm, node, frame, 1);
}

VLIB_REGISTER_NODE (lcp_igmp4_node) =
{
  .name = "linux-cp-igmp",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_igmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_IGMP_N_NEXT,

  .next_nodes = {
    [LCP_IGMP_NEXT_PUNT] = "linux-cp-punt",
  },
};

VLIB_REGISTER_NODE (lcp_igmp6_node) =
{
  .name = "linux-cp-igmp6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_igmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_IGMP_N_NEXT,

  .next_nodes = {
    [LCP_IGMP_NEXT_PUNT] = "linux-cp-punt",
  },
};

VLIB_REGISTER_NODE (lcp_l2_igmp4_node) =
{
  .name = "linux-cp-l2-igmp",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_igmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_IGMP_N_NEXT,

  .next_nodes = {
    [LCP_IGMP_NEXT_PUNT] = "linux-cp-punt",
  },
};

VLIB_REGISTER_NODE (lcp_l2_igmp6_node) =
{
  .name = "linux-cp-l2-igmp6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_igmp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_IGMP_N_NEXT,

  .next_nodes = {
    [LCP_IGMP_NEXT_PUNT] = "linux-cp-punt",
  },
};

VNET_FEATURE_INIT (lcp_igmp4_mc, static) =
{
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-igmp",
  .runs_before = VNET_FEATURES ("ip4-not-enabled"),
};

VNET_FEATURE_INIT (lcp_igmp6_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-igmp6",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

VNET_FEATURE_INIT (lcp_l2_igmp4_feature, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "linux-cp-l2-igmp",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VNET_FEATURE_INIT (lcp_l2_igmp6_feature, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "linux-cp-l2-igmp6",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};