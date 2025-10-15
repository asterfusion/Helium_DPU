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

#include "map_ce.h"

enum map_ce_ip4_classify_next_e
{
    MAP_CE_IP4_CLASSIFY_NEXT_DROP,
    MAP_CE_IP4_CLASSIFY_NEXT_NAT_IN2OUT,
    MAP_CE_IP4_CLASSIFY_NEXT_MAP_E,
    MAP_CE_IP4_CLASSIFY_NEXT_MAP_T,
    MAP_CE_IP4_CLASSIFY_NEXT_ICMP_ERROR,
    MAP_CE_IP4_CLASSIFY_N_NEXT,
};

enum map_ce_ip6_classify_next_e
{
    MAP_CE_IP6_CLASSIFY_NEXT_DROP,
    MAP_CE_IP6_CLASSIFY_NEXT_NAT_OUT2IN,
    MAP_CE_IP6_CLASSIFY_NEXT_MAP_E,
    MAP_CE_IP6_CLASSIFY_NEXT_MAP_T,
    MAP_CE_IP6_CLASSIFY_NEXT_ICMP_ERROR,
    MAP_CE_IP6_CLASSIFY_N_NEXT,
};

static uword
ip4_map_ce_classify (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, map_ce_ip4_classify_node.index);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    map_ce_main_t *mm = &map_ce_main;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;
            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAP_CE_IP4_CLASSIFY_NEXT_DROP;

            map_ce_domain_t *d0;
            ip4_header_t *ip40;
            u32 map_domain_index0 = ~0;
            bool df0 = false;
            bool frag_ignore_df = false;
            u16 mtu0 = ~0; 
            u32 ext_map_len = 0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);

            /* check src_address local lpm domain */
            d0 = ip4_local_map_get_domain (&ip40->src_address, &map_domain_index0, &error0);
            if (!d0)
            {			
                vnet_feature_next (&next0, p0);
                goto trace;
            }

            /* check ttl */
            if (PREDICT_FALSE (ip40->ttl == 1))
            {
                icmp4_error_set_vnet_buffer (p0, ICMP4_time_exceeded,
                        ICMP4_time_exceeded_ttl_exceeded_in_transit, 0);
                error0 = MAP_CE_ERROR_TIME_EXCEEDED;
                next0 = MAP_CE_IP4_CLASSIFY_NEXT_ICMP_ERROR;
                goto trace;
            }

            /* check mtu and fragment */
            mtu0 = d0->mtu ? d0->mtu : ~0;
            df0 = ip40->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);
            frag_ignore_df = d0->frag_valid ? d0->frag_ignore_df : mm->frag_ignore_df;

            ext_map_len =  + sizeof(ip6_header_t);
            if (d0->flags & MAP_CE_DOMAIN_TRANSLATION)
            {
                ext_map_len -= sizeof(ip4_header_t);
            }

            if (PREDICT_FALSE(df0 && !frag_ignore_df &&
                              (clib_host_to_net_u16 (ip40->length) + ext_map_len) > mtu0))
            {
                icmp4_error_set_vnet_buffer (p0, ICMP4_destination_unreachable,
                                             ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
                                             mtu0 - ext_map_len);
                error0 = MAP_CE_ERROR_DF_SET;
                next0 = MAP_CE_IP4_CLASSIFY_NEXT_ICMP_ERROR;
                goto trace;
            }

            vnet_buffer (p0)->map_ce.map_domain_index = map_domain_index0;
            if (d0->flags & MAP_CE_DOMAIN_TRANSLATION)
                vnet_buffer (p0)->map_ce.is_translation = true;
            else
                vnet_buffer (p0)->map_ce.is_translation = false;

            next0 = MAP_CE_IP4_CLASSIFY_NEXT_NAT_IN2OUT;

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_add_trace (vm, node, p0, map_domain_index0);
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next, pi0,
                                             next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

static uword
ip6_map_ce_classify (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, map_ce_ip6_classify_node.index);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;
            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAP_CE_IP6_CLASSIFY_NEXT_DROP;

            map_ce_domain_t *d0;
            ip6_header_t *ip60;
            u32 map_domain_index0 = ~0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip60 = vlib_buffer_get_current (p0);

            /* check dst_address lpm domain */
            d0 = ip6_map_get_domain (&ip60->dst_address, &map_domain_index0, &error0);
            if (!d0)
            {			
                vnet_feature_next (&next0, p0);
                goto trace;
            }

            if (PREDICT_FALSE (ip60->hop_limit == 1))
            {
                icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
                        ICMP6_time_exceeded_ttl_exceeded_in_transit,
                        0);
                error0 = MAP_CE_ERROR_TIME_EXCEEDED;
                next0 = MAP_CE_IP6_CLASSIFY_NEXT_ICMP_ERROR;
                goto trace;
            }

            vnet_buffer (p0)->map_ce.map_domain_index = map_domain_index0;
            if (d0->flags & MAP_CE_DOMAIN_TRANSLATION)
            {
                vnet_buffer (p0)->map_ce.is_translation = true;
                next0 = MAP_CE_IP6_CLASSIFY_NEXT_MAP_T;
            }
            else
            {
                vnet_buffer (p0)->map_ce.is_translation = false;
                next0 = MAP_CE_IP6_CLASSIFY_NEXT_MAP_E;
            }

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_add_trace (vm, node, p0, map_domain_index0);
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next, pi0,
                                             next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

/* *INDENT-OFF* */
VNET_FEATURE_INIT (map_ce_ip4_classify_feature, static) =
{
    .arc_name = "ip4-unicast",
    .node_name = "map-ce-ip4-classify",
    .runs_before = VNET_FEATURES ("nat44-ed-out2in", "nat44-ed-in2out",
                                  "nat44-out2in-worker-handoff", "nat44-in2out-worker-handoff",
                                  "nat44-handoff-classify", "nat44-ed-classify",
                                  "nat-pre-out2in", "nat-pre-in2out",
                                  "ipsec4-input-feature"),
    .runs_after = VNET_FEATURES("ip4-sv-reassembly-feature", "spi-ip4-input-node"),
};

VLIB_REGISTER_NODE(map_ce_ip4_classify_node) = {
    .function = ip4_map_ce_classify,
    .name = "map-ce-ip4-classify",
    .vector_size = sizeof(u32),
    .format_trace = format_map_ce_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = MAP_CE_N_ERROR,
    .error_counters = map_ce_error_counters,

    .n_next_nodes = MAP_CE_IP4_CLASSIFY_N_NEXT,
    .next_nodes = {
        [MAP_CE_IP4_CLASSIFY_NEXT_DROP] = "error-drop",
        [MAP_CE_IP4_CLASSIFY_NEXT_NAT_IN2OUT] = "map-ce-nat44-ei-in2out",
        [MAP_CE_IP4_CLASSIFY_NEXT_MAP_E] = "ip4-map-e-ce",
        [MAP_CE_IP4_CLASSIFY_NEXT_MAP_T] = "ip4-map-t-ce",
        [MAP_CE_IP4_CLASSIFY_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    },
};

VNET_FEATURE_INIT (map_ce_ip6_classify_feature, static) =
{
    .arc_name = "ip6-unicast",
    .node_name = "map-ce-ip6-classify",
    .runs_before = VNET_FEATURES ("nat64-in2out", "nat64-in2out-handoff", "ipsec6-input-feature"),
    .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature", "ip6-full-reassembly-feature", "spi-ip6-input-node"),
};

VLIB_REGISTER_NODE(map_ce_ip6_classify_node) = {
    .function = ip6_map_ce_classify,
    .name = "map-ce-ip6-classify",
    .vector_size = sizeof(u32),
    .format_trace = format_map_ce_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = MAP_CE_N_ERROR,
    .error_counters = map_ce_error_counters,

    .n_next_nodes = MAP_CE_IP6_CLASSIFY_N_NEXT,
    .next_nodes = {
        [MAP_CE_IP6_CLASSIFY_NEXT_DROP] = "error-drop",
        [MAP_CE_IP6_CLASSIFY_NEXT_NAT_OUT2IN] = "map-ce-nat44-ei-out2in",
        [MAP_CE_IP6_CLASSIFY_NEXT_MAP_E] = "ip6-map-e-ce",
        [MAP_CE_IP6_CLASSIFY_NEXT_MAP_T] = "ip6-map-t-ce",
        [MAP_CE_IP6_CLASSIFY_NEXT_ICMP_ERROR] = "ip6-icmp-error",
    },
};
/* *INDENT-ON* */
