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
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/l2/l2_input.h>

#include <plugins/security_check/security.h>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} savi_check_trace_t;

/* packet trace format function */
static u8 *
format_savi_check_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  savi_check_trace_t *t = va_arg (*args, savi_check_trace_t *);

  s = format (s, "savi_check: sw_if_index %d next_index %x", t->sw_if_index, t->next_index);
  return s;
}
#define foreach_savi_check_error                    \
_(DROP, "dropped savi check packets")               \
_(PUNT, "punt savi check packets")                  

typedef enum
{
#define _(sym,str) SAVI_CHECK_ERROR_##sym,
  foreach_savi_check_error
#undef _
    SAVI_CHECK_N_ERROR,
} savi_check_error_t;

static char *savi_check_error_strings[] = {
#define _(sym,string) string,
    foreach_savi_check_error
#undef _
};


always_inline void process_savi_check(security_check_main_t *secm, 
                                      u32 sw_if_index, 
                                      vlib_buffer_t *b,
                                      u32 *next,
                                      u32 thread_index)
{
    clib_bihash_kv_24_8_t k, v;
    l2_bridge_domain_t *bd_config;
    u8 pass_flag = 0;

    vnet_sw_interface_t *sw = NULL;
    u32 sup_sw_if_index;

    ethernet_header_t *eth;
    ip6_header_t *ip6;
    icmp46_header_t *icmp;
    udp_header_t *udph;

    u16 vlan;
    snp_entry_t *entry = NULL;

    u32 buf_len = vlib_buffer_length_in_chain (secm->vlib_main, b);

    eth = vlib_buffer_get_current (b);
    ip6 = vlib_buffer_get_current (b) + vnet_buffer (b)->l2.l2_len;

    icmp = ip6_ext_header_find(secm->vlib_main, b, ip6, IP_PROTOCOL_ICMP6, NULL);
    udph = ip6_ext_header_find(secm->vlib_main, b, ip6, IP_PROTOCOL_UDP, NULL);

    if (!icmp && !udph)
    {
        return;
    }

    //get sup sw_if_index
    sw = vnet_get_sw_interface (secm->vnet_main, sw_if_index);
    sup_sw_if_index = sw->sup_sw_if_index;

    //get vlan
    bd_config = vec_elt_at_index (l2input_main.bd_configs, vnet_buffer (b)->l2.bd_index);
    vlan = bd_config->bd_id;

    /*
     * For packets with a (::, ff02::1:xxxxx) (eg NDP-NS)
     *     skip check
     * For packets with a (::, ff02::2) (eg NDP-RS)
     *     skip check
     */
    if (ip6->src_address.as_u64[0] == 0 && ip6->src_address.as_u64[1] == 0 &&
        icmp && (ICMP6_neighbor_solicitation == icmp->type ||
                 ICMP6_router_solicitation == icmp->type))
    {
        return;
    }

    //ndp and dhcpv6 ; ra check for raguard
    if (PREDICT_FALSE(
          (icmp && (ICMP6_neighbor_solicitation == icmp->type ||
                   ICMP6_neighbor_advertisement == icmp->type ||
                   ICMP6_router_solicitation == icmp->type ||
                   ICMP6_redirect == icmp->type)) || 
          (udph && (UDP6_DST_PORT_dhcpv6_to_server == clib_net_to_host_u16(udph->dst_port) ||
                    UDP6_DST_PORT_dhcpv6_to_client == clib_net_to_host_u16(udph->dst_port)))))
    {
        //fill bihash key
        k.key[0] = (u64)eth->src_address[0] << 56 | 
                    (u64)eth->src_address[1] << 48 | 
                    (u64)eth->src_address[2] << 40 | 
                    (u64)eth->src_address[3] << 32 | 
                    (u64)eth->src_address[4] << 24 | 
                    (u64)eth->src_address[5] << 16 | 
                    vlan;
        k.key[1] = ip6->src_address.as_u64[0];
        k.key[2] = ip6->src_address.as_u64[1];

        /* 
         * first proc port savi check
         */
        if (clib_bitmap_get_no_check(secm->savi_config.enable_by_sw_if_index, sw_if_index) ||
            clib_bitmap_get_no_check(secm->savi_config.enable_by_sw_if_index, sup_sw_if_index))
        {
            if (clib_bihash_search_24_8 (&secm->snp_table, &k, &v))
            {
                //not found, packet will drop
                *next = SECURITY_CHECK_ERROR_DROP;
                ASSERT (vec_len(secm->savi_config.counter) >= thread_index);
                secm->savi_config.counter[thread_index].if_counter[sw_if_index].pkt += 1;
                secm->savi_config.counter[thread_index].if_counter[sw_if_index].bytes += buf_len;
                return;
            }
            else 
            {
                //found need compare interfaces
                entry = (snp_entry_t *)v.value;
                if (entry->interface != sw_if_index &&
                        entry->sup_interface != sup_sw_if_index)
                {
                    *next = SECURITY_CHECK_ERROR_DROP;
                    ASSERT (vec_len(secm->savi_config.counter) >= thread_index);
                    secm->savi_config.counter[thread_index].if_counter[sw_if_index].pkt += 1;
                    secm->savi_config.counter[thread_index].if_counter[sw_if_index].bytes += buf_len;
                    return;
                }
                pass_flag = 1;
            }
        }
        if (clib_bitmap_get_no_check(secm->savi_config.enable_by_vlan, vlan))
        {
            if (clib_bitmap_get_no_check(secm->savi_config.trust_sw_if_index_by_vlan[vlan], sw_if_index) || 
                clib_bitmap_get_no_check(secm->savi_config.trust_sw_if_index_by_vlan[vlan], sup_sw_if_index))
            {
                return;
            }

            if (pass_flag)
            {
                return;
            }

            if (clib_bihash_search_24_8 (&secm->snp_table, &k, &v))
            {
                //not found, packet will drop
                *next = SECURITY_CHECK_ERROR_DROP;
                ASSERT (vec_len(secm->savi_config.counter) >= thread_index);
                secm->savi_config.counter[thread_index].vlan_counter[vlan].pkt += 1;
                secm->savi_config.counter[thread_index].vlan_counter[vlan].bytes += buf_len;
                return;
            }
            else 
            {
                //found need compare interfaces
                entry = (snp_entry_t *)v.value;
                if (entry->interface != sw_if_index &&
                    entry->sup_interface != sup_sw_if_index)
                {
                    *next = SECURITY_CHECK_ERROR_DROP;
                    ASSERT (vec_len(secm->savi_config.counter) >= thread_index);
                    secm->savi_config.counter[thread_index].vlan_counter[vlan].pkt += 1;
                    secm->savi_config.counter[thread_index].vlan_counter[vlan].bytes += buf_len;
                    return;
                }
            }
        }
    }
    return;
}

VLIB_NODE_FN (savi_check_node) (vlib_main_t * vm,
                               vlib_node_runtime_t * node,
                               vlib_frame_t * frame)
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

            process_savi_check(secm, sw_if_index0, b0, &next0, thread_index);
            if (PREDICT_FALSE(next0 == SECURITY_CHECK_ERROR_DROP))
            {
                b0->error = error_node->errors[SAVI_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next0 == SECURITY_CHECK_PUNT))
            {
                b0->error = error_node->errors[SAVI_CHECK_ERROR_PUNT];
            }

            process_savi_check(secm, sw_if_index1, b1, &next1, thread_index);
            if (PREDICT_FALSE(next1 == SECURITY_CHECK_ERROR_DROP))
            {
                b1->error = error_node->errors[SAVI_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next1 == SECURITY_CHECK_PUNT))
            {
                b1->error = error_node->errors[SAVI_CHECK_ERROR_PUNT];
            }

            if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
            {
                if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
                {
                    savi_check_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
                    t0->sw_if_index = sw_if_index0;
                    t0->next_index = next0;

                }
                if (PREDICT_FALSE (b1->flags & VLIB_BUFFER_IS_TRACED))
                {
                    savi_check_trace_t *t1 = vlib_add_trace (vm, node, b1, sizeof (*t1));
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

            process_savi_check(secm, sw_if_index0, b0, &next0, thread_index);
            if (PREDICT_FALSE(next0 == SECURITY_CHECK_ERROR_DROP))
            {
                b0->error = error_node->errors[SAVI_CHECK_ERROR_DROP];
            }
            else if (PREDICT_FALSE(next0 == SECURITY_CHECK_PUNT))
            {
                b0->error = error_node->errors[SAVI_CHECK_ERROR_PUNT];
            }

            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) && 
                                (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                savi_check_trace_t *t0 = vlib_add_trace (vm, node, b0, sizeof (*t0));
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

VLIB_REGISTER_NODE (savi_check_node) =
{
  .name = "savi-check-node",
  .vector_size = sizeof (u32),
  .format_trace = format_savi_check_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (savi_check_error_strings),
  .error_strings = savi_check_error_strings,
  .n_next_nodes = SECURITY_CHECK_N_NEXT,
  .next_nodes =
  {
    [SECURITY_CHECK_ERROR_DROP] = "error-drop",
    [SECURITY_CHECK_PUNT] = "linux-cp-punt",
  }
};

/* *INDENT-OFF* */
VNET_FEATURE_INIT (savi_check, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "savi-check-node",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};
/* *INDENT-ON* */
