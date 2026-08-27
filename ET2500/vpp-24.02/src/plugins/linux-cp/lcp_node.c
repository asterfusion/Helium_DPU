/*
 * lcp_enthernet_node.c : linux control plane ethernet node
 *
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/socket.h>
#include <linux/if.h>

#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/linux-cp/lcp_adj.h>
#include <linux-cp/lcp.api_enum.h>
#include <linux-cp/lcp_match.h>
#include <linux-cp/lcp_punt.h>
#include <linux-cp/lcp_stats.h>

#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/l2/l2_input.h>
#include <vnet/mpls/mpls.h>

#define foreach_lip_punt                                                      \
  _ (IO, "punt to host")                                                      \
  _ (DROP, "unknown input interface")

typedef enum
{
#define _(sym, str) LIP_PUNT_NEXT_##sym,
  foreach_lip_punt
#undef _
    LIP_PUNT_N_NEXT,
} lip_punt_next_t;

typedef struct lip_punt_trace_t_
{
  u32 phy_sw_if_index;
  u32 host_sw_if_index;
} lip_punt_trace_t;

/* packet trace format function */
static u8 *
format_lip_punt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lip_punt_trace_t *t = va_arg (*args, lip_punt_trace_t *);

  s =
    format (s, "lip-punt: %u -> %u", t->phy_sw_if_index, t->host_sw_if_index);

  return s;
}

#ifdef SUPPORT_LCP_VLAN_TAG_ACT
static_always_inline void lip_punt_vlan_tag_proc(const lcp_itf_pair_t *lip, vlib_buffer_t *b)
{
    u8 *data = (u8 *) ethernet_buffer_get_header (b);

    if (lip->lip_host_vlan_tag == LCP_ITF_HOST_VLAN_TAG_STRIP)
    {
        if ((data[12] == 0x81 && data[13] == 0x00) ||
            (data[12] == 0x88 && data[13] == 0xa8) ||
            (data[12] == 0x91 && data[13] == 0x00) ||
            (data[12] == 0x92 && data[13] == 0x00))
        {
            //vlan packet
            clib_memmove(data + 4, data, 12);
            vlib_buffer_advance (b, 4);
        }
    }
    else if (lip->lip_host_vlan_tag == LCP_ITF_HOST_VLAN_TAG_KEEP)
    {
        if ((data[12] == 0x81 && data[13] == 0x00) ||
            (data[12] == 0x88 && data[13] == 0xa8) ||
            (data[12] == 0x91 && data[13] == 0x00) ||
            (data[12] == 0x92 && data[13] == 0x00))
        {
            //keep vlan, do nothing
        }
        else
        {
            //add pvlan
            if (lip->lip_host_pvlan < 4096)
            {
                clib_memmove(data - 4, data, 12);
                data[8] = 0x81;
                data[9] = 0x00;
                data[10] = lip->lip_host_pvlan >> 8;
                data[11] = lip->lip_host_pvlan & 0xFF;
                vlib_buffer_advance (b, -4);
            }
        }
    }
}
#endif

typedef enum
{
  LCP_DELIVERY_CONTEXT_LEGACY,
  LCP_DELIVERY_CONTEXT_COPP,
} lcp_delivery_context_t;

/*
 * Prepare a CPU-bound buffer for LCP delivery.
 *
 * This function mutates buffer metadata and packet offset. It MUST NOT be
 * called for the original buffer of a COPY action; only a TRAP original or a
 * COPY clone may reach this boundary.
 */
static_always_inline u32
lcp_prepare_cpu_branch (vlib_main_t *vm, vlib_buffer_t *b,
			lcp_delivery_context_t context, u32 *sw_if_index,
			const lcp_itf_pair_t **lip)
{
  u32 lipi;

  *sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  if ((b->flags & VNET_BUFFER_F_TCP_ORIG_RX_SAVED) &&
      vnet_buffer2 (b)->l2_rx_sw_if_index != ~0)
    {
      u32 l2_rx_sw_if_index = vnet_buffer2 (b)->l2_rx_sw_if_index;

      lipi = lcp_itf_pair_find_by_phy (l2_rx_sw_if_index);
      b->flags &= ~VNET_BUFFER_F_TCP_ORIG_RX_SAVED;
      vnet_buffer2 (b)->l2_rx_sw_if_index = ~0;
    }
  else
    lipi = lcp_itf_pair_find_by_phy (*sw_if_index);

  if (PREDICT_FALSE (lipi == INDEX_INVALID))
    {
      if ((b->flags & VLIB_BUFFER_NOT_PHY_INTF) &&
	  vnet_buffer2 (b)->l2_rx_sw_if_index != ~0)
	{
	  u32 l2_rx_sw_if_index = vnet_buffer2 (b)->l2_rx_sw_if_index;
	  vnet_sw_interface_t *si =
	    vnet_get_sw_interface (vnet_get_main (), l2_rx_sw_if_index);

	  if (si && si->type == VNET_SW_INTERFACE_TYPE_SUB)
	    l2_rx_sw_if_index = si->sup_sw_if_index;
	  lipi = lcp_itf_pair_find_by_phy (l2_rx_sw_if_index);
	  vnet_buffer2 (b)->l2_rx_sw_if_index = ~0;
	}
      if (lipi == INDEX_INVALID)
	goto delivery_drop;
    }

  *lip = lcp_itf_pair_get (lipi);
  if (PREDICT_FALSE (*lip == 0))
    {
      lipi = INDEX_INVALID;
      goto delivery_drop;
    }

  vnet_buffer (b)->sw_if_index[VLIB_TX] = (*lip)->lip_host_sw_if_index;
  if (PREDICT_TRUE ((*lip)->lip_host_type == LCP_ITF_HOST_TAP))
    {
      word len = (u8 *) vlib_buffer_get_current (b) -
		 (u8 *) ethernet_buffer_get_header (b);

      if (PREDICT_FALSE (!(b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)))
	{
	  vnet_main_t *vnm = vnet_get_main ();
	  vnet_hw_interface_t *hw =
	    vnet_get_sup_hw_interface (vnm, (*lip)->lip_phy_sw_if_index);
	  ethernet_header_t *eh;

	  vlib_buffer_advance (b, -sizeof (ethernet_header_t));
	  eh = vlib_buffer_get_current (b);
	  clib_memcpy (eh->src_address, hw->hw_address,
		       sizeof (eh->src_address));
	  clib_memcpy (eh->dst_address, hw->hw_address,
		       sizeof (eh->dst_address));
	  eh->type = (b->flags & VNET_BUFFER_F_IS_IP4) ?
		       clib_host_to_net_u16 (ETHERNET_TYPE_IP4) :
		       clib_host_to_net_u16 (ETHERNET_TYPE_IP6);
	}
      else
	vlib_buffer_advance (b, -len);
    }

#ifdef SUPPORT_LCP_VLAN_TAG_ACT
  lip_punt_vlan_tag_proc (*lip, b);
#endif
  return lipi;

delivery_drop:
  if (context == LCP_DELIVERY_CONTEXT_COPP)
    lcp_stats_increment (vm, vnet_buffer2 (b)->trap_id,
			 LCP_STATS_DELIVERY_DROP);
  return INDEX_INVALID;
}

/**
 * Pass punted packets from the PHY to the HOST.
 */
static_always_inline uword
lip_punt_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, u8 is_copp)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_punt_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  const lcp_itf_pair_t *lip0 = NULL;
	  u32 next0 = ~0;
	  u32 bi0, lipi0;
	  u32 sw_if_index0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  next0 = LIP_PUNT_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  lipi0 = INDEX_INVALID;
	  /* Account policy/policer success before attempting Linux delivery. */
	  if (!is_copp || lcp_cpu_branch_pass (vm, b0))
	    {
	      lipi0 = lcp_prepare_cpu_branch (
		vm, b0, is_copp ? LCP_DELIVERY_CONTEXT_COPP :
			    LCP_DELIVERY_CONTEXT_LEGACY,
		&sw_if_index0, &lip0);
	      if (lipi0 != INDEX_INVALID)
		next0 = LIP_PUNT_NEXT_IO;
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lip_punt_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = sw_if_index0;
	      t->host_sw_if_index =
		(lipi0 == INDEX_INVALID) ? ~0 : lip0->lip_host_sw_if_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (lip_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lip_punt_node_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (lip_copp_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return lip_punt_node_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (lip_punt_node) = {
  .name = "linux-cp-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lip_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LIP_PUNT_N_NEXT,
  .next_nodes = {
    [LIP_PUNT_NEXT_DROP] = "error-drop",
    [LIP_PUNT_NEXT_IO] = "interface-output",
  },
};

VLIB_REGISTER_NODE (lip_copp_punt_node) = {
  .name = "linux-cp-copp-punt",
  .vector_size = sizeof (u32),
  .format_trace = format_lip_punt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LIP_PUNT_N_NEXT,
  .next_nodes = {
    [LIP_PUNT_NEXT_DROP] = "error-drop",
    [LIP_PUNT_NEXT_IO] = "interface-output",
  },
};

#define LCP_ACL_PUNT_CONTINUE ((u32) ~0)

static u32 lcp_acl_producer_by_arc[256];

#define foreach_lcp_acl_punt_next                                       \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-copp-punt")

typedef enum
{
#define _(sym, node) LCP_ACL_PUNT_NEXT_##sym,
  foreach_lcp_acl_punt_next
#undef _
  LCP_ACL_PUNT_N_NEXT,
} lcp_acl_punt_next_t;

/**
 * Apply CoPP to packets punted by the ACL plugin.
 */
VLIB_NODE_FN (lcp_acl_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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
	  u32 bi = from[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u32 next = LCP_ACL_PUNT_CONTINUE;
	  lcp_action_result_t action_result;

	  if (!lcp_buffer_set_trap_id (b, LCP_TRAP_ACL))
	    next = LCP_ACL_PUNT_NEXT_DROP;
	  else
	    {
	      action_result = lcp_punt_process_with_default (
		vm, b, LCP_COPP_ACTION_TRAP);
	      switch (action_result.disposition)
		{
		case LCP_DISPOSITION_DROP:
		  next = LCP_ACL_PUNT_NEXT_DROP;
		  break;
		case LCP_DISPOSITION_FORWARD:
		case LCP_DISPOSITION_COPY:
		  /* Consume the ACL feature continuation exactly once below. */
		  next = LCP_ACL_PUNT_CONTINUE;
		  break;
		case LCP_DISPOSITION_TRAP:
		  next = LCP_ACL_PUNT_NEXT_PUNT;
		  break;
		}
	      if (action_result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
		copies[n_copies++] = action_result.cpu_bi;
	    }

	  from++;
	  n_left--;
	  if (next == LCP_ACL_PUNT_CONTINUE)
	    {
	      u8 arc = vnet_buffer (b)->feature_arc_index;
	      u32 producer_index = lcp_acl_producer_by_arc[arc];
	      vlib_node_t *producer =
		producer_index == ~0 ? 0 : vlib_get_node (vm, producer_index);
	      u32 producer_next;

	      if (PREDICT_FALSE (producer == 0))
		next = LCP_ACL_PUNT_NEXT_DROP;
	      else
		{
		  vnet_feature_next (&producer_next, b);
		  if (PREDICT_FALSE (producer_next >=
				     vec_len (producer->next_nodes)))
		    next = LCP_ACL_PUNT_NEXT_DROP;
		  else
		    {
		      u32 continuation = producer->next_nodes[producer_next];
		      vlib_frame_t *continuation_frame =
			vlib_get_frame_to_node (vm, continuation);
		      u32 *continuation_buffers =
			vlib_frame_vector_args (continuation_frame);

		      continuation_buffers[0] = bi;
		      continuation_frame->n_vectors = 1;
		      vlib_put_frame_to_node (vm, continuation,
					  continuation_frame);
		    }
		}
	    }
	  if (next != LCP_ACL_PUNT_CONTINUE)
	    {
	      to_next[0] = bi;
	      to_next++;
	      n_left_to_next--;
	      vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					       n_left_to_next, bi, next);
	    }
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (n_copies)
    vlib_buffer_enqueue_to_single_next (vm, node, copies,
					LCP_ACL_PUNT_NEXT_PUNT, n_copies);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_acl_punt_node) = {
  .name = "linux-cp-acl-punt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_ACL_PUNT_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_ACL_PUNT_NEXT_##sym] = node,
    foreach_lcp_acl_punt_next
#undef _
  },
};

static clib_error_t *
lcp_acl_punt_redirect_init (vlib_main_t *vm)
{
  static const struct
  {
    const char *arc_name;
    const char *node_name;
  } acl_producers[] = {
    { "l2-input-ip6", "acl-plugin-in-ip6-l2" },
    { "l2-input-ip4", "acl-plugin-in-ip4-l2" },
    { "l2-output-ip6", "acl-plugin-out-ip6-l2" },
    { "l2-output-ip4", "acl-plugin-out-ip4-l2" },
    { "ip6-unicast", "acl-plugin-in-ip6-fa" },
    { "ip4-unicast", "acl-plugin-in-ip4-fa" },
    { "ip6-output", "acl-plugin-out-ip6-fa" },
    { "ip4-output", "acl-plugin-out-ip4-fa" },
    { "l2-input-nonip", "acl-plugin-in-sai-nonip-l2" },
    { "l2-output-nonip", "acl-plugin-out-sai-nonip-l2" },
  };

  clib_memset (lcp_acl_producer_by_arc, 0xff,
	       sizeof (lcp_acl_producer_by_arc));
  for (u32 i = 0; i < ARRAY_LEN (acl_producers); i++)
    {
      vlib_node_t *acl_node = vlib_get_node_by_name (
	vm, (u8 *) acl_producers[i].node_name);
      u8 arc = vnet_get_feature_arc_index (acl_producers[i].arc_name);

      if (acl_node && arc != (u8) ~0)
	{
	  lcp_acl_producer_by_arc[arc] = acl_node->index;
	  vlib_node_add_next_with_slot (vm, acl_node->index,
					lcp_acl_punt_node.index, 1);
	}
    }
  return 0;
}

VLIB_INIT_FUNCTION (lcp_acl_punt_redirect_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init", "acl_init"),
};

/**
 * Adapter for NAT44-ED miss / hairpin events.
 * The NAT plugin sets vnet_buffer2()->trap_id and sends the packet here;
 * we apply the CoPP policy and either drop, forward, copy, or punt to the
 * host via linux-cp-copp-punt.
 */
#define foreach_lcp_nat_miss_next                                       \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-copp-punt")

typedef enum
{
#define _(sym, node) LCP_NAT_MISS_NEXT_##sym,
  foreach_lcp_nat_miss_next
#undef _
  LCP_NAT_MISS_N_NEXT,
} lcp_nat_miss_next_t;

VLIB_NODE_FN (lcp_nat_miss_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
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
	  u32 bi = from[0];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  u32 original_next = LCP_NAT_MISS_NEXT_DROP;
	  u32 next;
	  lcp_action_result_t action_result;

	  action_result = lcp_punt_process_with_default (
	    vm, b, LCP_COPP_ACTION_TRAP);
	  switch (action_result.disposition)
	    {
	    case LCP_DISPOSITION_DROP:
	      next = LCP_NAT_MISS_NEXT_DROP;
	      break;
	    case LCP_DISPOSITION_FORWARD:
	    case LCP_DISPOSITION_COPY:
	      next = original_next;
	      break;
	    case LCP_DISPOSITION_TRAP:
	      next = LCP_NAT_MISS_NEXT_PUNT;
	      break;
	    }
	  if (action_result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
	    copies[n_copies++] = action_result.cpu_bi;

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
					LCP_NAT_MISS_NEXT_PUNT, n_copies);
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_nat_miss_node) = {
  .name = "linux-cp-nat-miss",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_NAT_MISS_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_NAT_MISS_NEXT_##sym] = node,
    foreach_lcp_nat_miss_next
#undef _
  },
};

#define foreach_lcp_punt_l3 _ (DROP, "unknown error")

typedef enum
{
#define _(sym, str) LCP_LOCAL_NEXT_##sym,
  foreach_lcp_punt_l3
#undef _
    LCP_LOCAL_N_NEXT,
} lcp_punt_l3_next_t;

typedef struct lcp_punt_l3_trace_t_
{
  u32 phy_sw_if_index;
} lcp_punt_l3_trace_t;

/* packet trace format function */
static u8 *
format_lcp_punt_l3_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_punt_l3_trace_t *t = va_arg (*args, lcp_punt_l3_trace_t *);

  s = format (s, "linux-cp-punt-l3: %u", t->phy_sw_if_index);

  return s;
}

VLIB_NODE_FN (lcp_punt_l3_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lip_punt_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  u32 next0 = LCP_LOCAL_NEXT_DROP;
	  u32 bi0;
	  index_t lipi0;
	  lcp_itf_pair_t *lip0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (&next0, b0);

	  lipi0 =
	    lcp_itf_pair_find_by_phy (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  if (lipi0 != INDEX_INVALID)
	    {
	      /*
	       * Avoid TTL check for packets which arrived on a tunnel and
	       * are being punted to the local host.
	       */
	      lip0 = lcp_itf_pair_get (lipi0);
	      if (lip0->lip_host_type == LCP_ITF_HOST_TUN)
		b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_punt_l3_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_punt_l3_node) = {
  .name = "linux-cp-punt-l3",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_punt_l3_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = 1,
  .next_nodes = {
    [LCP_LOCAL_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (lcp_punt_l3_ip4, static) = {
  .arc_name = "ip4-punt",
  .node_name = "linux-cp-punt-l3",
  .runs_before = VNET_FEATURES ("ip4-punt-redirect"),
};

VNET_FEATURE_INIT (lip_punt_l3_ip6, static) = {
  .arc_name = "ip6-punt",
  .node_name = "linux-cp-punt-l3",
  .runs_before = VNET_FEATURES ("ip6-punt-redirect"),
};

#define foreach_lcp_xc                                                        \
  _ (DROP, "drop")                                                            \
  _ (XC_IP4, "x-connnect-ip4")                                                \
  _ (XC_IP6, "x-connnect-ip6")

typedef enum
{
#define _(sym, str) LCP_XC_NEXT_##sym,
  foreach_lcp_xc
#undef _
    LCP_XC_N_NEXT,
} lcp_xc_next_t;

typedef struct lcp_xc_trace_t_
{
  u32 phy_sw_if_index;
  adj_index_t adj_index;
} lcp_xc_trace_t;

/* packet trace format function */
static u8 *
format_lcp_xc_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_xc_trace_t *t = va_arg (*args, lcp_xc_trace_t *);

  s = format (s, "lcp-xc: itf:%d adj:%d", t->phy_sw_if_index, t->adj_index);

  return s;
}

/**
 * X-connect all packets from the HOST to the PHY.
 *
 * This runs in either the IP4 or IP6 path. The MAC rewrite on the received
 * packet from the host is used as a key to find the adjacency used on the phy.
 * This allows this code to start the feature arc on that adjacency.
 * Consequently, all packet sent from the host are also subject to output
 * features, which is symmetric w.r.t. to input features.
 */
static_always_inline u32
lcp_xc_inline (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame,
	       ip_address_family_t af)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_xc_next_t next_index;
  ip_lookup_main_t *lm;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  if (AF_IP4 == af)
    lm = &ip4_main.lookup_main;
  else
    lm = &ip6_main.lookup_main;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const ethernet_header_t *eth;
	  const lcp_itf_pair_t *lip;
	  u32 next0, bi0, lipi, ai;
	  vlib_buffer_t *b0;
	  const ip_adjacency_t *adj;
	  u8 len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi =
	    lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;

	  //add by asterfusion for tap trunk port, when use tun/p2p/pipe maybe need to fix it
	  if (PREDICT_TRUE (lip->lip_host_type == LCP_ITF_HOST_TAP))
      {
          /*
           * rewind to ethernet header
           */
          len0 = ((u8 *) vlib_buffer_get_current (b0) -
                  (u8 *) ethernet_buffer_get_header (b0));
      }
      else
      {
          len0 = lip->lip_rewrite_len;
      }

	  vlib_buffer_advance (b0, -len0);
	  eth = vlib_buffer_get_current (b0);

	  ai = ADJ_INDEX_INVALID;
	  if (!ethernet_address_cast (eth->dst_address))
	    ai = lcp_adj_lkup ((u8 *) eth, lip->lip_rewrite_len,
			       vnet_buffer (b0)->sw_if_index[VLIB_TX]);
	  if (ai == ADJ_INDEX_INVALID)
	    ai = lip->lip_phy_adjs.adj_index[af];

	  adj = adj_get (ai);
	  vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ai;
	  next0 = adj->rewrite_header.next_index;
	  vnet_buffer (b0)->ip.save_rewrite_length = len0;

	  if (PREDICT_FALSE (adj->rewrite_header.flags &
			     VNET_REWRITE_HAS_FEATURES))
	    vnet_feature_arc_start_w_cfg_index (
	      lm->output_feature_arc_index,
	      vnet_buffer (b0)->sw_if_index[VLIB_TX], &next0, b0,
	      adj->ia_cfg_index);

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
	      t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_xc_ip4)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (lcp_xc_inline (vm, node, frame, AF_IP4));
}

VLIB_NODE_FN (lcp_xc_ip6)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (lcp_xc_inline (vm, node, frame, AF_IP6));
}

VLIB_REGISTER_NODE (lcp_xc_ip4) = { .name = "linux-cp-xc-ip4",
				    .vector_size = sizeof (u32),
				    .format_trace = format_lcp_xc_trace,
				    .type = VLIB_NODE_TYPE_INTERNAL,
				    .sibling_of = "ip4-rewrite" };

VNET_FEATURE_INIT (lcp_xc_ip4_ucast_node, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-xc-ip4",
};
VNET_FEATURE_INIT (lcp_xc_ip4_mcast_node, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-xc-ip4",
};

VLIB_REGISTER_NODE (lcp_xc_ip6) = { .name = "linux-cp-xc-ip6",
				    .vector_size = sizeof (u32),
				    .format_trace = format_lcp_xc_trace,
				    .type = VLIB_NODE_TYPE_INTERNAL,
				    .sibling_of = "ip6-rewrite" };

VNET_FEATURE_INIT (lcp_xc_ip6_ucast_node, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-xc-ip6",
};
VNET_FEATURE_INIT (lcp_xc_ip6_mcast_node, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-xc-ip6",
};

typedef enum
{
  LCP_XC_MPLS_NEXT_DROP,
  LCP_XC_MPLS_NEXT_IO,
  LCP_XC_MPLS_N_NEXT,
} lcp_xc_mpls_next_t;

static_always_inline uword
lcp_xc_mpls_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_xc_next_t next_index;

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const ethernet_header_t *eth;
	  const lcp_itf_pair_t *lip;
	  u32 next0, bi0, lipi, ai;
	  vlib_buffer_t *b0;
	  // const ip_adjacency_t *adj;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi =
	    lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip->lip_phy_sw_if_index;
	  vlib_buffer_advance (b0, -lip->lip_rewrite_len);
	  eth = vlib_buffer_get_current (b0);

	  ai = ADJ_INDEX_INVALID;
	  next0 = LCP_XC_MPLS_NEXT_DROP;
	  if (!ethernet_address_cast (eth->dst_address))
	    ai = lcp_adj_lkup ((u8 *) eth, lip->lip_rewrite_len,
			       vnet_buffer (b0)->sw_if_index[VLIB_TX]);
	  if (ai != ADJ_INDEX_INVALID)
	    {
	      vnet_buffer (b0)->ip.adj_index[VLIB_TX] = ai;
	      next0 = LCP_XC_MPLS_NEXT_IO;
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
	      t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (lcp_xc_mpls)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (lcp_xc_mpls_inline (vm, node, frame));
}

VLIB_REGISTER_NODE (
  lcp_xc_mpls) = { .name = "linux-cp-xc-mpls",
		   .vector_size = sizeof (u32),
		   .format_trace = format_lcp_xc_trace,
		   .type = VLIB_NODE_TYPE_INTERNAL,
		   .n_next_nodes = LCP_XC_MPLS_N_NEXT,
		   .next_nodes = {
		     [LCP_XC_MPLS_NEXT_DROP] = "error-drop",
		     [LCP_XC_MPLS_NEXT_IO] = "interface-output",
		   } };

VNET_FEATURE_INIT (lcp_xc_mpls_node, static) = {
  .arc_name = "mpls-input",
  .node_name = "linux-cp-xc-mpls",
};

typedef enum
{
  LCP_XC_L3_NEXT_XC,
  LCP_XC_L3_NEXT_LOOKUP,
  LCP_XC_L3_N_NEXT,
} lcp_xc_l3_next_t;

/**
 * X-connect all packets from the HOST to the PHY on L3 interfaces
 *
 * There's only one adjacency that can be used on these links.
 */
static_always_inline u32
lcp_xc_l3_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, ip_address_family_t af)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_xc_next_t next_index;
  vnet_main_t *vnm = vnet_get_main ();

  next_index = 0;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  vlib_buffer_t *b0;
	  const lcp_itf_pair_t *lip;
	  u32 next0 = ~0;
	  u32 bi0, lipi;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);

	  /* Flag buffers as locally originated. Otherwise their TTL will
	   * be checked & decremented. That would break services like BGP
	   * which set a TTL of 1 by default.
	   */
	  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

	  lipi =
	    lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip = lcp_itf_pair_get (lipi);

	  /* P2P tunnels can use generic adjacency */
	  if (PREDICT_TRUE (
		vnet_sw_interface_is_p2p (vnm, lip->lip_phy_sw_if_index)))
	    {
	      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
		lip->lip_phy_sw_if_index;
	      vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
		lip->lip_phy_adjs.adj_index[af];
	      next0 = LCP_XC_L3_NEXT_XC;
	    }
	  /* P2MP tunnels require a fib lookup to find the right adjacency */
	  else
	    {
	      /* lookup should use FIB table associated with phy interface */
	      vnet_buffer (b0)->sw_if_index[VLIB_RX] =
		lip->lip_phy_sw_if_index;
	      next0 = LCP_XC_L3_NEXT_LOOKUP;
	    }

	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_xc_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->phy_sw_if_index = lip->lip_phy_sw_if_index;
	      t->adj_index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

/**
 * X-connect all packets from the HOST to the PHY.
 */
VLIB_NODE_FN (lcp_xc_l3_ip4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (lcp_xc_l3_inline (vm, node, frame, AF_IP4));
}

VLIB_NODE_FN (lcp_xc_l3_ip6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return (lcp_xc_l3_inline (vm, node, frame, AF_IP6));
}

VLIB_REGISTER_NODE (lcp_xc_l3_ip4_node) = {
  .name = "linux-cp-xc-l3-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_XC_L3_N_NEXT,
  .next_nodes = {
    [LCP_XC_L3_NEXT_XC] = "ip4-midchain",
    [LCP_XC_L3_NEXT_LOOKUP] = "ip4-lookup",
  },
};

VNET_FEATURE_INIT (lcp_xc_node_l3_ip4_unicast, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "linux-cp-xc-l3-ip4",
};

VNET_FEATURE_INIT (lcp_xc_node_l3_ip4_multicaast, static) = {
  .arc_name = "ip4-multicast",
  .node_name = "linux-cp-xc-l3-ip4",
};

VLIB_REGISTER_NODE (lcp_xc_l3_ip6_node) = {
  .name = "linux-cp-xc-l3-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_xc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_next_nodes = LCP_XC_L3_N_NEXT,
  .next_nodes = {
    [LCP_XC_L3_NEXT_XC] = "ip6-midchain",
    [LCP_XC_L3_NEXT_LOOKUP] = "ip6-lookup",
  },
};

VNET_FEATURE_INIT (lcp_xc_node_l3_ip6_unicast, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "linux-cp-xc-l3-ip6",
};

VNET_FEATURE_INIT (lcp_xc_node_l3_ip6_multicast, static) = {
  .arc_name = "ip6-multicast",
  .node_name = "linux-cp-xc-l3-ip6",
};

#define foreach_lcp_arp_delivery_next                                   \
  _ (DROP, "error-drop")                                                \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, node) LCP_ARP_DELIVERY_NEXT_##sym,
  foreach_lcp_arp_delivery_next
#undef _
  LCP_ARP_DELIVERY_N_NEXT,
} lcp_arp_delivery_next_t;

#define foreach_lcp_arp_phy_next                                        \
  _ (DROP, "error-drop")                                                \
  _ (PUNT, "linux-cp-arp-copp-delivery")

typedef enum
{
#define _(sym, node) LCP_ARP_PHY_NEXT_##sym,
  foreach_lcp_arp_phy_next
#undef _
  LCP_ARP_PHY_N_NEXT,
} lcp_arp_phy_next_t;

typedef enum
{
  LCP_ARP_HOST_NEXT_DROP,
  LCP_ARP_HOST_NEXT_IO,
  LCP_ARP_HOST_N_NEXT,
} lcp_arp_host_next_t;

typedef struct lcp_arp_trace_t_
{
  u32 rx_sw_if_index;
  u16 arp_opcode;
} lcp_arp_trace_t;

/* packet trace format function */
static u8 *
format_lcp_arp_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_arp_trace_t *t = va_arg (*args, lcp_arp_trace_t *);

  s = format (s, "rx-sw-if-index: %u opcode: %u", t->rx_sw_if_index,
	      t->arp_opcode);

  return s;
}

static_always_inline const lcp_itf_pair_t *
lcp_arp_phy_pair (vlib_buffer_t *b)
{
  u32 lipi = lcp_itf_pair_find_by_phy (
    vnet_buffer (b)->sw_if_index[VLIB_RX]);

  if (lipi == INDEX_INVALID && (b->flags & VLIB_BUFFER_NOT_PHY_INTF) &&
      vnet_buffer2 (b)->l2_rx_sw_if_index != ~0)
    {
      u32 sw_if_index = vnet_buffer2 (b)->l2_rx_sw_if_index;
      vnet_sw_interface_t *si =
	vnet_get_sw_interface (vnet_get_main (), sw_if_index);

      if (si != NULL && si->type == VNET_SW_INTERFACE_TYPE_SUB)
	sw_if_index = si->sup_sw_if_index;

      lipi = lcp_itf_pair_find_by_phy (sw_if_index);
      vnet_buffer2 (b)->l2_rx_sw_if_index = ~0;
    }

  return lcp_itf_pair_get (lipi);
}

VLIB_NODE_FN (lcp_arp_copp_delivery_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  const lcp_itf_pair_t *lip0 = lcp_arp_phy_pair (b0);
	  u32 next0 = LCP_ARP_DELIVERY_NEXT_DROP;

	  if (PREDICT_TRUE (lip0 != NULL))
	    {
	      word len0 = (u8 *) vlib_buffer_get_current (b0) -
			  (u8 *) ethernet_buffer_get_header (b0);

	      vnet_buffer (b0)->sw_if_index[VLIB_TX] =
		lip0->lip_host_sw_if_index;
	      vlib_buffer_advance (b0, -len0);
#ifdef SUPPORT_LCP_VLAN_TAG_ACT
	      lip_punt_vlan_tag_proc (lip0, b0);
#endif
	      if (lcp_cpu_branch_pass (vm, b0))
		next0 = LCP_ARP_DELIVERY_NEXT_IO;
	    }
	  else
	    lcp_stats_increment (vm, vnet_buffer2 (b0)->trap_id,
				 LCP_STATS_DELIVERY_DROP);

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_arp_copp_delivery_node) = {
  .name = "linux-cp-arp-copp-delivery",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = LCP_ARP_DELIVERY_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_ARP_DELIVERY_NEXT_##sym] = node,
    foreach_lcp_arp_delivery_next
#undef _
  },
};

/**
 * Apply CoPP to ARP requests and replies received from the PHY.
 */
VLIB_NODE_FN (lcp_arp_phy_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;
  u32 next_index = node->cached_next_index;
  u32 copies[VLIB_FRAME_SIZE];
  u32 n_copies = 0;

  while (n_left_from > 0)
    {
      u32 *to_next, n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  u32 next0, original_next;
	  lcp_action_result_t action_result;
	  lcp_packet_view_t view = { 0 };
	  lcp_match_result_t result = { 0 };

	  vnet_feature_next (&original_next, b0);
	  next0 = original_next;
	  if (lcp_packet_parse (vm, b0, LCP_MATCH_CTX_ARP, &view) &&
	      lcp_match_select (&view, &result))
	    {
	      if (!lcp_buffer_set_trap_id (b0, result.trap_type))
		next0 = LCP_ARP_PHY_NEXT_DROP;
	      else
		{
		  action_result = lcp_punt_process_with_default (
		    vm, b0, LCP_COPP_ACTION_COPY);
		  switch (action_result.disposition)
		    {
		    case LCP_DISPOSITION_DROP:
		      next0 = LCP_ARP_PHY_NEXT_DROP;
		      break;
		    case LCP_DISPOSITION_FORWARD:
		    case LCP_DISPOSITION_COPY:
		      next0 = original_next;
		      /* The CPU copy carries the trap id; the original must continue
		       * through the ARP feature arc without a stale punt marker. */
		      vnet_buffer2 (b0)->trap_id = LCP_TRAP_INVALID;
		      break;
		    case LCP_DISPOSITION_TRAP:
		      next0 = LCP_ARP_PHY_NEXT_PUNT;
		      break;
		    }
		  if (action_result.cpu_bi != LCP_PUNT_BUFFER_INVALID)
		    copies[n_copies++] = action_result.cpu_bi;
		}
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      lcp_arp_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->arp_opcode = view.arp_opcode;
	    }

	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (PREDICT_FALSE (n_copies != 0))
    vlib_buffer_enqueue_to_single_next (vm, node, copies,
					LCP_ARP_PHY_NEXT_PUNT, n_copies);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_arp_phy_node) = {
  .name = "linux-cp-arp-phy",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_ARP_PHY_N_NEXT,
  .next_nodes = {
#define _(sym, node) [LCP_ARP_PHY_NEXT_##sym] = node,
    foreach_lcp_arp_phy_next
#undef _
  },
};

VNET_FEATURE_INIT (lcp_arp_phy_arp_feat, static) = {
  .arc_name = "arp",
  .node_name = "linux-cp-arp-phy",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

/**
 * x-connect ARP packets from the host to the phy
 */
VLIB_NODE_FN (lcp_arp_host_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, *from, *to_next, n_left_to_next;
  lcp_arp_host_next_t next_index;

  next_index = node->cached_next_index;
  n_left_from = frame->n_vectors;
  from = vlib_frame_vector_args (frame);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const lcp_itf_pair_t *lip0;
	  lcp_arp_host_next_t next0;
	  vlib_buffer_t *b0;
	  u32 bi0, lipi0;
	  u8 len0;

	  bi0 = to_next[0] = from[0];

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = LCP_ARP_HOST_NEXT_DROP;

	  b0 = vlib_get_buffer (vm, bi0);

	  lipi0 =
	    lcp_itf_pair_find_by_host (vnet_buffer (b0)->sw_if_index[VLIB_RX]);
	  lip0 = lcp_itf_pair_get (lipi0);
	  if (PREDICT_FALSE (lip0 == NULL))
	    goto trace0;

	  /* Send to the phy */
	  next0 = LCP_ARP_HOST_NEXT_IO;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = lip0->lip_phy_sw_if_index;

	  //set max tc priority
	  lcp_set_max_tc(b0);

	  len0 = ((u8 *) vlib_buffer_get_current (b0) -
		  (u8 *) ethernet_buffer_get_header (b0));
	  vlib_buffer_advance (b0, -len0);

	trace0:
	  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lcp_arp_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->arp_opcode = 0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_arp_host_node) = {
  .name = "linux-cp-arp-host",
  .vector_size = sizeof (u32),
  .format_trace = format_lcp_arp_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .n_next_nodes = LCP_ARP_HOST_N_NEXT,
  .next_nodes = {
    [LCP_ARP_HOST_NEXT_DROP] = "error-drop",
    [LCP_ARP_HOST_NEXT_IO] = "interface-output",
  },
};

VNET_FEATURE_INIT (lcp_arp_host_arp_feat, static) = {
  .arc_name = "arp",
  .node_name = "linux-cp-arp-host",
  .runs_before = VNET_FEATURES ("arp-reply"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
