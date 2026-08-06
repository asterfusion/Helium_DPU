/*
 * l2_cast_policer_node.c: L2 multicast/broadcast policer nodes
 *
 * Copyright 2024-2027 Asterfusion Network
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

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vppinfra/error.h>

#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

#include <l2_cast_policer/l2_cast_policer.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 policer_index;
  u8 is_mcast;
  u8 is_bcast;
} l2_cast_policer_trace_t;

static u8 *
format_l2_cast_policer_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2_cast_policer_trace_t *t = va_arg (*args, l2_cast_policer_trace_t *);

  s = format (s,
	      "l2-cast-policer: mcast:%s bcast:%s sw_if_index %u policer_index %u next_index %x",
	      t->is_mcast ? "true" : "false",
	      t->is_bcast ? "true" : "false", t->sw_if_index,
	      t->policer_index, t->next_index);
  return s;
}

#define foreach_l2_cast_policer_error \
_(DROP, "policer dropped packets")

typedef enum
{
#define _(sym,str) L2_CAST_POLICER_ERROR_##sym,
  foreach_l2_cast_policer_error
#undef _
  L2_CAST_POLICER_N_ERROR,
} l2_cast_policer_error_t;

static char *l2_cast_policer_error_strings[] = {
#define _(sym,string) string,
  foreach_l2_cast_policer_error
#undef _
};

static_always_inline int
is_broadcast_mac (const u8 *dst)
{
  return (dst[0] == 0xff && dst[1] == 0xff && dst[2] == 0xff &&
	  dst[3] == 0xff && dst[4] == 0xff && dst[5] == 0xff);
}

static_always_inline int
is_multicast_mac_only (const u8 *dst)
{
  return ((dst[0] & 0x1) != 0 && !is_broadcast_mac (dst));
}

static_always_inline uword
l2_cast_policer_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			vlib_frame_t *frame, u32 feature_bit, u32 *feat_next,
			uword *enable_bitmap, u32 *policer_index_by_sw_if_index,
			int is_mcast_node)
{
  u32 n_left_from, *from, *to_next;
  vlib_node_runtime_t *error_node;
  u32 next_index = node->cached_next_index;
  u64 time_in_policer_periods;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  error_node = vlib_node_get_runtime (vm, node->node_index);
  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0, next0, sw_if_index0, policer_index0 = UINT32_MAX;
	  vlib_buffer_t *b0;
	  ethernet_header_t *eth0;
	  u8 act0 = QOS_ACTION_TRANSMIT;
	  u8 is_mcast0 = 0, is_bcast0 = 0;
	  int should_police0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  b0 = vlib_get_buffer (vm, bi0);

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  eth0 = vlib_buffer_get_current (b0);

	  next0 = vnet_l2_feature_next (b0, feat_next, feature_bit);

	  is_bcast0 = is_broadcast_mac (eth0->dst_address);
	  is_mcast0 = is_multicast_mac_only (eth0->dst_address);
	  should_police0 = is_mcast_node ? is_mcast0 : is_bcast0;

	  if (PREDICT_TRUE (should_police0) &&
	      clib_bitmap_get_no_check (enable_bitmap, sw_if_index0))
	    {
	      policer_index0 = policer_index_by_sw_if_index[sw_if_index0];
	      act0 = vnet_policer_police (vm, b0, policer_index0,
					  time_in_policer_periods,
					  POLICE_CONFORM, false);
	      if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
		{
		  next0 = L2_CAST_POLICER_NEXT_DROP;
		  b0->error =
		    error_node->errors[L2_CAST_POLICER_ERROR_DROP];
		}
	    }

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			     (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      l2_cast_policer_trace_t *t0 =
		vlib_add_trace (vm, node, b0, sizeof (*t0));
	      t0->sw_if_index = sw_if_index0;
	      t0->next_index = next0;
	      t0->policer_index = policer_index0;
	      t0->is_mcast = is_mcast0;
	      t0->is_bcast = is_bcast0;
	    }

	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_NODE_FN (l2_mcast_policer_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame)
{
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;

  return l2_cast_policer_inline (
    vm, node, frame, L2INPUT_FEAT_MCAST_POLICER,
    lcpm->mcast_l2_input_feat_next, lcpm->mcast_enable_by_sw_if_index,
    lcpm->mcast_policer_index_by_sw_if_index, 1);
}

VLIB_REGISTER_NODE (l2_mcast_policer_node) = {
  .name = "l2-mcast-policer",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_cast_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (l2_cast_policer_error_strings),
  .error_strings = l2_cast_policer_error_strings,
  .n_next_nodes = L2_CAST_POLICER_N_NEXT,
  .next_nodes =
    {
      [L2_CAST_POLICER_NEXT_DROP] = "error-drop",
    },
};

VLIB_NODE_FN (l2_bcast_policer_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame)
{
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;

  return l2_cast_policer_inline (
    vm, node, frame, L2INPUT_FEAT_BCAST_POLICER,
    lcpm->bcast_l2_input_feat_next, lcpm->bcast_enable_by_sw_if_index,
    lcpm->bcast_policer_index_by_sw_if_index, 0);
}

VLIB_REGISTER_NODE (l2_bcast_policer_node) = {
  .name = "l2-bcast-policer",
  .vector_size = sizeof (u32),
  .format_trace = format_l2_cast_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (l2_cast_policer_error_strings),
  .error_strings = l2_cast_policer_error_strings,
  .n_next_nodes = L2_CAST_POLICER_N_NEXT,
  .next_nodes =
    {
      [L2_CAST_POLICER_NEXT_DROP] = "error-drop",
    },
};
