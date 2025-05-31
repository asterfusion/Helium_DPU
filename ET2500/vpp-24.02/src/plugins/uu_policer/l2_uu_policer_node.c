/*
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

#include <plugins/uu_policer/l2_uu_policer.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 policer_index;
  u8 is_uu;
} uu_polier_trace_t;

/* packet trace format function */
static u8 *
format_uu_policer_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  uu_polier_trace_t *t = va_arg (*args, uu_polier_trace_t *);

  s = format (s, "l2-uu-policer: is_uu: %s sw_if_index %u policer_index %u next_index %x",
              t->is_uu ? "true" : "false",
              t->sw_if_index, 
              t->policer_index, 
              t->next_index);
  return s;
}
#define foreach_uu_policer_error                    \
_(DROP, "policer dropped packets")               

typedef enum
{
#define _(sym,str) UU_POLICER_ERROR_##sym,
  foreach_uu_policer_error
#undef _
    UU_POLICER_N_ERROR,
} uu_policer_error_t;

static char *uu_policer_error_strings[] = {
#define _(sym,string) string,
    foreach_uu_policer_error
#undef _
};


VLIB_NODE_FN (l2_uu_policer_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
                                   vlib_frame_t * frame)
{
    l2_uu_policer_main_t *uupm = &l2_uu_policer_main;

    u32 n_left_from, *from, *to_next;
    vlib_node_runtime_t *error_node;
    u32 next_index = node->cached_next_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    error_node = vlib_node_get_runtime (vm, node->node_index);

    u64 time_in_policer_periods;
    time_in_policer_periods = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;

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
            ethernet_header_t *eth0, *eth1;
            u32 policer_index0, policer_index1;
            u8 act0, act1;
            u8 is_uu0 = 0, is_uu1 = 0;

            bi0 = from[0];
            bi1 = from[1];

            to_next[0] = bi0;
            to_next[1] = bi1;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
            sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

            eth0 = vlib_buffer_get_current (b0);
            eth1 = vlib_buffer_get_current (b1);

            /* most packets will follow feature arc */
            next0 = vnet_l2_feature_next (b0, uupm->l2_input_feat_next,
                                          L2INPUT_FEAT_UU_POLICER);
            next1 = vnet_l2_feature_next (b1, uupm->l2_input_feat_next,
                                          L2INPUT_FEAT_UU_POLICER);

            if (PREDICT_TRUE((eth0->dst_address[0] & 0x1) == 0) && 
                clib_bitmap_get_no_check(uupm->enable_by_sw_if_index, sw_if_index0))
            {
                is_uu0 = 1;
                policer_index0 = uupm->policer_index_by_sw_if_index[sw_if_index0];
                act0 = vnet_policer_police (vm, b0, policer_index0, time_in_policer_periods,
                                            POLICE_CONFORM, false);
                if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
                {
                    next0 = L2_UU_POLICER_ERROR_DROP;
                    b0->error = error_node->errors[UU_POLICER_ERROR_DROP];
                }
            }
            if (PREDICT_TRUE((eth1->dst_address[0] & 0x1) == 0) && 
                clib_bitmap_get_no_check(uupm->enable_by_sw_if_index, sw_if_index1))
            {
                is_uu1 = 1;
                policer_index1 = uupm->policer_index_by_sw_if_index[sw_if_index1];
                act1 = vnet_policer_police (vm, b1, policer_index1, time_in_policer_periods,
                                        POLICE_CONFORM, false);
                if (PREDICT_FALSE (act1 == QOS_ACTION_DROP))
                {
                    next1 = L2_UU_POLICER_ERROR_DROP;
                    b1->error = error_node->errors[UU_POLICER_ERROR_DROP];
                }
            }

            if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
            {
                if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    uu_polier_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                    t0->sw_if_index = sw_if_index0;
                    t0->next_index = next0;
                    t0->policer_index = policer_index0;
                    t0->is_uu = is_uu0;

                }
                if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
                {
                    uu_polier_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
                    t1->sw_if_index = sw_if_index1;
                    t1->next_index = next1;
                    t1->policer_index = policer_index1;
                    t1->is_uu = is_uu1;
                }
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
            ethernet_header_t *eth0;
            u32 policer_index0;
            u8 act0;
            u8 is_uu0 = 0;

            bi0 = from[0];

            to_next[0] = bi0;

            b0 = vlib_get_buffer (vm, bi0);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            eth0 = vlib_buffer_get_current (b0);

            /* most packets will follow feature arc */
            next0 = vnet_l2_feature_next (b0, uupm->l2_input_feat_next,
                                          L2INPUT_FEAT_UU_POLICER);

            if (PREDICT_TRUE((eth0->dst_address[0] & 0x1) == 0) && 
                clib_bitmap_get_no_check(uupm->enable_by_sw_if_index, sw_if_index0))
            {
                is_uu0 = 1;
                policer_index0 = uupm->policer_index_by_sw_if_index[sw_if_index0];
                act0 = vnet_policer_police (vm, b0, policer_index0, time_in_policer_periods,
                                            POLICE_CONFORM, false);
                if (PREDICT_FALSE (act0 == QOS_ACTION_DROP))
                {
                    next0 = L2_UU_POLICER_ERROR_DROP;
                    b0->error = error_node->errors[UU_POLICER_ERROR_DROP];
                }
            }


            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && 
                                (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                uu_polier_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                t0->sw_if_index = sw_if_index0;
                t0->next_index = next0;
                t0->policer_index = policer_index0;
                t0->is_uu = is_uu0;
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

VLIB_REGISTER_NODE (l2_uu_policer_node) =
{
  .name = "l2-uu-policer",
  .vector_size = sizeof (u32),
  .format_trace = format_uu_policer_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN (uu_policer_error_strings),
  .error_strings = uu_policer_error_strings,
  .n_next_nodes = L2_UU_POLICER_N_NEXT,

  .next_nodes =
  {
    [L2_UU_POLICER_ERROR_DROP] = "error-drop",
  }
};
