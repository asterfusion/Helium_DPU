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
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_input.h>

#include <plugins/security_check/security.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} raguard_check_trace_t;

/* packet trace format function */
static u8 *
format_raguard_check_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  raguard_check_trace_t *t = va_arg (*args, raguard_check_trace_t *);

  s = format (s, "raguard_check: sw_if_index %d next_index %x", t->sw_if_index, t->next_index);
  return s;
}
#define foreach_raguard_check_error                    \
_(DROP, "dropped raguard check packets")               \
_(PUNT, "punt raguard check packets")                  

typedef enum
{
#define _(sym,str) RAGUARD_CHECK_ERROR_##sym,
  foreach_raguard_check_error
#undef _
    RAGUARD_CHECK_N_ERROR,
} raguard_check_error_t;

static char *raguard_check_error_strings[] = {
#define _(sym,string) string,
    foreach_raguard_check_error
#undef _
};


always_inline void process_raguard_check(security_check_main_t *secm, 
                                      u32 sw_if_index, 
                                      vlib_buffer_t *b,
                                      u32 *next,
                                      u32 thread_index, 
                                      int is_l2_path)
{
    vnet_sw_interface_t *sw = NULL;
    u32 sup_sw_if_index;

    ip6_header_t *ip6;
    icmp46_header_t *icmp;

    raguard_role_e role, sup_role;


    if (is_l2_path)
    {
        ip6 = vlib_buffer_get_current (b) + vnet_buffer (b)->l2.l2_len;
    }
    else 
    {
        ip6 = vlib_buffer_get_current (b);
    }

    icmp = ip6_ext_header_find(secm->vlib_main, b, ip6, IP_PROTOCOL_ICMP6, NULL);

    if (!icmp || ICMP6_router_advertisement != icmp->type)
    {
        return;
    }

    //get sup sw_if_index
    sw = vnet_get_sw_interface (secm->vnet_main, sw_if_index);
    sup_sw_if_index = sw->sup_sw_if_index;

    if (is_l2_path)
    {
        //get vlan
#if 0
        l2_bridge_domain_t *bd_config;
        u16 vlan = ~0;

        bd_config = vec_elt_at_index (l2input_main.bd_configs, vnet_buffer (b)->l2.bd_index);
        vlan = bd_config->bd_id;

        /*
         * TODO if raguard policy need to apply in VPP:
         *   Need use vlan to lookup ragurad policy, 
         *   and currently not supported and will be punt to the CPU for processing
         */
#endif
    }

    //get raguard role 
    role = secm->raguard_config.role_by_sw_if_index[sw_if_index];
    sup_role = secm->raguard_config.role_by_sw_if_index[sup_sw_if_index];

    /*
     * when sup_role != role
     * sup_role priority is high
     * role priority is low
     */
    if(role != sup_role) role = sup_role;

    switch(role)
    {
    case RAGUARD_ROLE_NONE:
    case RAGUARD_ROLE_ROUTER:
        //do noting
        break;
    case RAGUARD_ROLE_USER:
        *next = SECURITY_CHECK_ERROR_DROP;
        break;
    case RAGUARD_ROLE_HYBRID:
        *next = SECURITY_CHECK_PUNT;
        break;
    }
    return;
}

always_inline uword
raguard_check_node (vlib_main_t * vm,
                    vlib_node_runtime_t * node,
                    vlib_frame_t * frame, 
                    int is_l2_path)
{
    security_check_main_t *secm = &security_check_main;
    u32 thread_index = vm->thread_index;

    u32 n_left_from, *from, *to_next;
    vlib_node_runtime_t *error_node;

    u32 next_index = node->cached_next_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;

    error_node = vlib_node_get_runtime (vm, node->node_index);

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

            bi0 = from[0];
            bi1 = from[1];

            to_next[0] = bi0;
            to_next[1] = bi1;

            b0 = vlib_get_buffer (vm, bi0);
            b1 = vlib_get_buffer (vm, bi1);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
            sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

            /* most packets will follow feature arc */
            vnet_feature_next (&next0, b0);
            vnet_feature_next (&next1, b1);

            process_raguard_check(secm, sw_if_index0, b0, &next0, thread_index, is_l2_path);
            if (PREDICT_FALSE(next0 == SECURITY_CHECK_ERROR_DROP))
            {
                b0->error = error_node->errors[RAGUARD_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next0 == SECURITY_CHECK_PUNT))
            {
                b0->error = error_node->errors[RAGUARD_CHECK_ERROR_PUNT];
            }

            process_raguard_check(secm, sw_if_index1, b1, &next1, thread_index, is_l2_path);
            if (PREDICT_FALSE(next1 == SECURITY_CHECK_ERROR_DROP))
            {
                b1->error = error_node->errors[RAGUARD_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next1 == SECURITY_CHECK_PUNT))
            {
                b1->error = error_node->errors[RAGUARD_CHECK_ERROR_PUNT];
            }

            if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
            {
                if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    raguard_check_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                    t0->sw_if_index = sw_if_index0;
                    t0->next_index = next0;

                }
                if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
                {
                    raguard_check_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
                    t1->sw_if_index = sw_if_index1;
                    t1->next_index = next1;
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

            bi0 = from[0];

            to_next[0] = bi0;

            b0 = vlib_get_buffer (vm, bi0);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            /* most packets will follow feature arc */
            vnet_feature_next (&next0, b0);

            process_raguard_check(secm, sw_if_index0, b0, &next0, thread_index, is_l2_path);
            if (PREDICT_FALSE(next0 == SECURITY_CHECK_ERROR_DROP))
            {
                b0->error = error_node->errors[RAGUARD_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next0 == SECURITY_CHECK_PUNT))
            {
                b0->error = error_node->errors[RAGUARD_CHECK_ERROR_PUNT];
            }

            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && 
                                (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                raguard_check_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                t0->sw_if_index = sw_if_index0;
                t0->next_index = next0;
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

VLIB_NODE_FN (raguard_check_l2_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return raguard_check_node (vm, node, frame, 1);
}

VLIB_NODE_FN (raguard_check_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return raguard_check_node (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (raguard_check_l2_node) =
{
  .name = "raguard-check-node-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_raguard_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (raguard_check_error_strings),
  .error_strings = raguard_check_error_strings,
  .n_next_nodes = SECURITY_CHECK_N_NEXT,
  .next_nodes =
  {
    [SECURITY_CHECK_ERROR_DROP] = "error-drop",
    [SECURITY_CHECK_PUNT] = "linux-cp-punt",
  }
};

/* *INDENT-OFF* */
VNET_FEATURE_INIT (raguard_check_l2, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "raguard-check-node-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (raguard_check_ip6_node) =
{
  .name = "raguard-check-node-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_raguard_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (raguard_check_error_strings),
  .error_strings = raguard_check_error_strings,
  .n_next_nodes = SECURITY_CHECK_N_NEXT,
  .next_nodes =
  {
    [SECURITY_CHECK_ERROR_DROP] = "error-drop",
    [SECURITY_CHECK_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (raguard_check_ip6_uc, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "raguard-check-node-ip6",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

VNET_FEATURE_INIT (raguard_check_ip6_mc, static) =
{
  .arc_name = "ip6-multicast",
  .node_name = "raguard-check-node-ip6",
  .runs_before = VNET_FEATURES ("ip6-not-enabled"),
};

/* *INDENT-ON* */
