/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/vnet.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

#include "pppoe.h"

typedef enum
{
  LCP_PPPOE_QOS_NEXT_DROP,
  LCP_PPPOE_QOS_N_NEXT,
} lcp_pppoe_qos_next_t;

typedef enum
{
  LCP_PPPOE_QOS_ERROR_POLICER_DROP,
  LCP_PPPOE_QOS_N_ERROR,
} lcp_pppoe_qos_error_t;

static char *lcp_pppoe_qos_error_strings[] = {
  [LCP_PPPOE_QOS_ERROR_POLICER_DROP] = "subscriber policer drop",
};

VLIB_NODE_FN (lcp_pppoe_qos_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_policer_main_t *pm = &vnet_policer_main;
  u32 next_index = node->cached_next_index;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left_from = frame->n_vectors;

  while (n_left_from)
    {
      u32 *to_next;
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from && n_left_to_next)
	{
	  u32 bi0 = from[0];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	  u32 next0 = LCP_PPPOE_QOS_NEXT_DROP;
	  bool policer_drop = false;
	  u32 policer_index = ~0u;
	  u64 now = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

	  if (sw_if_index < vec_len (pm->policer_index_by_sw_if_index[VLIB_TX]))
	    policer_index = pm->policer_index_by_sw_if_index[VLIB_TX][sw_if_index];
	  if (policer_index != ~0u)
	    {
	      u8 rewrite_len = vnet_buffer (b0)->ip.save_rewrite_length;
	      vlib_buffer_advance (b0, rewrite_len);
	      u8 action = vnet_policer_police (vm, b0, policer_index, now,
					       POLICE_CONFORM, false);
	      vlib_buffer_advance (b0, -(word) rewrite_len);
	      if (action == QOS_ACTION_DROP)
		{
		  policer_drop = true;
		  b0->error = node->errors[LCP_PPPOE_QOS_ERROR_POLICER_DROP];
		}
	    }

	  if (!policer_drop)
	    vnet_feature_next (&next0, b0);

	  from++;
	  n_left_from--;
	  to_next[0] = bi0;
	  to_next++;
	  n_left_to_next--;
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_pppoe_qos_output_node) = {
  .name = "lcp-pppoe-qos-output",
  .vector_size = sizeof (u32),
  .n_errors = LCP_PPPOE_QOS_N_ERROR,
  .error_strings = lcp_pppoe_qos_error_strings,
  .n_next_nodes = LCP_PPPOE_QOS_N_NEXT,
  .next_nodes = {
    [LCP_PPPOE_QOS_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (lcp_pppoe_qos_output_ip4, static) = {
  .arc_name = "ip4-output",
  .node_name = "lcp-pppoe-qos-output",
  .runs_before = VNET_FEATURES ("interface-output"),
};

VNET_FEATURE_INIT (lcp_pppoe_qos_output_ip6, static) = {
  .arc_name = "ip6-output",
  .node_name = "lcp-pppoe-qos-output",
  .runs_before = VNET_FEATURES ("interface-output"),
};

static int
lcp_pppoe_policer_bind (u32 sw_if_index, u32 policer_index, vlib_dir_t dir,
			bool apply)
{
  vnet_policer_main_t *pm = &vnet_policer_main;

  if (apply && pool_is_free_index (pm->policers, policer_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  vec_validate (pm->policer_index_by_sw_if_index[dir], sw_if_index);
  pm->policer_index_by_sw_if_index[dir][sw_if_index] =
    apply ? policer_index : ~0u;
  return 0;
}

int
lcp_pppoe_policer_input_set (u32 sw_if_index, u32 policer_index, bool apply)
{
  return lcp_pppoe_policer_bind (sw_if_index, policer_index, VLIB_RX, apply);
}

static int
lcp_pppoe_qos_output_feature_set (const char *arc_name, u32 sw_if_index,
				  bool apply)
{
  int enabled = vnet_feature_is_enabled (
    arc_name, "lcp-pppoe-qos-output", sw_if_index);

  if ((apply && enabled == 1) || (!apply && enabled == 0))
    return 0;
  return vnet_feature_enable_disable (arc_name, "lcp-pppoe-qos-output",
				      sw_if_index, apply, 0, 0);
}

int
lcp_pppoe_policer_output_set (u32 sw_if_index, u32 policer_index, bool apply)
{
  int rv;

  if (!apply)
    {
      rv = lcp_pppoe_qos_output_feature_set ("ip4-output", sw_if_index, false);
      if (rv)
	return rv;
      rv = lcp_pppoe_qos_output_feature_set ("ip6-output", sw_if_index, false);
      if (rv)
	return rv;
      return lcp_pppoe_policer_bind (sw_if_index, ~0u, VLIB_TX, false);
    }

  rv = lcp_pppoe_policer_bind (sw_if_index, policer_index, VLIB_TX, true);
  if (rv)
    return rv;
  rv = lcp_pppoe_qos_output_feature_set ("ip4-output", sw_if_index, true);
  if (rv)
    return rv;
  return lcp_pppoe_qos_output_feature_set ("ip6-output", sw_if_index, true);
}
