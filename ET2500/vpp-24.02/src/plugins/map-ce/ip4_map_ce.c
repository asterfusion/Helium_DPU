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
#include <vnet/ip/ip_frag.h>
#include <vnet/ip/ip4_to_ip6.h>
enum mape_ce_ip4_next_e
{
    MAPE_CE_IP4_NEXT_IP6_LOOKUP,
    MAPE_CE_IP4_NEXT_DROP,
    MAPE_CE_IP4_N_NEXT,
};

static_always_inline void
ip4_map_e_ce_decrement_ttl (ip4_header_t * ip)
{
  i32 ttl = ip->ttl;

  /* Input node should have reject packets with ttl 0. */
  ASSERT (ip->ttl > 0);

  u32 checksum = ip->checksum + clib_host_to_net_u16 (0x0100);
  checksum += checksum >= 0xffff;
  ip->checksum = checksum;
  ttl -= 1;
  ip->ttl = ttl;

  /* Verify checksum. */
  ASSERT (ip4_header_checksum_is_valid (ip));
}

static_always_inline u32
ip4_map_e_ce_vtcfl (map_ce_domain_t *d, ip4_header_t * ip4, vlib_buffer_t * p)
{
  map_ce_main_t *mm = &map_ce_main;
  u8 tc = 0;
  if (d->tc_valid)
      tc = d->tc_copy ? ip4->tos : d->tc;
  else
      tc = mm->tc_copy ? ip4->tos : mm->tc;

  u32 vtcfl = 0x6 << 28;
  vtcfl |= tc << 20;
  vtcfl |= vnet_buffer (p)->ip.flow_hash & 0x000fffff;

  return (clib_host_to_net_u32 (vtcfl));
}

static u32
ip4_map_e_ce_fragment (vlib_main_t * vm, vlib_combined_counter_main_t *cm,
                       u32 bi, 
                       map_ce_domain_t *d, 
                       bool df,
                       u32 ** buffers, u8 * error)
{
    map_ce_main_t *mm = &map_ce_main;
    vlib_buffer_t *b = vlib_get_buffer (vm, bi);
    u32 *i;

    bool frag_inner = d->frag_valid ? d->frag_inner : mm->frag_inner;

    if (frag_inner)
    {
        if (df) ip4_header_clear_df((ip4_header_t *)(vlib_buffer_get_current(b) + sizeof(ip6_header_t)));

        /* IPv4 fragmented packets inside of IPv6 */
        ip4_frag_do_fragment (vm, bi, d->mtu, sizeof (ip6_header_t), buffers);

        /* Fixup */
        vec_foreach (i, *buffers)
        {
            vlib_buffer_t *p = vlib_get_buffer (vm, *i);
            ip6_header_t *ip6 = vlib_buffer_get_current (p);
            ip6->payload_length =
                clib_host_to_net_u16 (p->current_length - sizeof (ip6_header_t));

            vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_TX,
                    vm->thread_index,
                    d - mm->domains, 1,
                    clib_net_to_host_u16(ip6->payload_length) + 40);
        }
    }
    else
    {
        /* Create IPv6 fragments here */
        ip6_frag_do_fragment (vm, bi, d->mtu, 0, buffers);

        vec_foreach (i, *buffers)
        {
            vlib_buffer_t *p = vlib_get_buffer (vm, *i);
            vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_TX,
                    vm->thread_index,
                    d - mm->domains, 1,
                    p->current_length);
        }
    }
    return (MAPE_CE_IP4_NEXT_IP6_LOOKUP);
}

/*
 * ip4_map_ce
 */
static uword
ip4_map_e_ce (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip4_map_e_ce_node.index);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    map_ce_main_t *mm = &map_ce_main;
    vlib_combined_counter_main_t *cm = mm->domain_counters;
    u32 thread_index = vm->thread_index;
    u32 *buffer0 = 0;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;
            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAPE_CE_IP4_NEXT_IP6_LOOKUP;

            map_ce_domain_t *d0;
            ip4_header_t *ip40;
            ip6_header_t *ip6h0;
            u32 map_domain_index0 = ~0;
            bool free_original_buffer0 = false;
            u32 *frag_from0, frag_left0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);

            u16 l4_src_port0 = vnet_buffer (p0)->ip.reass.l4_src_port;

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            /*
             * Clamp TCP MSS value.
             */
            if (ip40->protocol == IP_PROTOCOL_TCP)
            {
                tcp_header_t *tcp = ip4_next_header (ip40);

                if (d0->tcp_mss_valid)
                {
                    if (d0->tcp_mss > 0 && tcp_syn (tcp))
                    {
                        ip_csum_t csum = tcp->checksum;
                        map_mss_clamping (tcp, &csum, d0->tcp_mss);
                        tcp->checksum = ip_csum_fold (csum);
                    }

                }
                else
                {
                    if (mm->tcp_mss > 0 && tcp_syn (tcp))
                    {
                        ip_csum_t csum = tcp->checksum;
                        map_mss_clamping (tcp, &csum, mm->tcp_mss);
                        tcp->checksum = ip_csum_fold (csum);
                    }
                }
            }

            bool df0 = ip40->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT);

            /* ttl */
            ip4_map_e_ce_decrement_ttl (ip40);

            /* MAP calc */
            u32 sa40 = clib_net_to_host_u32 (ip40->src_address.as_u32);
            u16 sp40 = clib_net_to_host_u16 (l4_src_port0);
            u64 sal60 = map_ce_get_pfx (d0, sa40, sp40);
            u64 sar60 = map_ce_get_sfx (d0, sa40, sp40);
            if (sal60 == 0 && sar60 == 0 && error0 == MAP_CE_ERROR_NONE)
                error0 = MAP_CE_ERROR_NO_BINDING;

            /* construct ipv6 header */
            vlib_buffer_advance (p0, -(sizeof (ip6_header_t)));
            ip6h0 = vlib_buffer_get_current (p0);
            vnet_buffer (p0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

            ip6h0->payload_length = ip40->length;
            ip6h0->protocol = IP_PROTOCOL_IP_IN_IP;
            ip6h0->hop_limit = 0x40;
            ip6h0->src_address.as_u64[0] = clib_host_to_net_u64 (sal60);
            ip6h0->src_address.as_u64[1] = clib_host_to_net_u64 (sar60);
            
            if (ip4_map_check_dst_ip_type(d0, &ip40->dst_address))
            {
                ip6h0->dst_address.as_u64[0] = map_ce_get_pfx_fmr_net(d0, ip40->dst_address.as_u32, vnet_buffer (p0)->ip.reass.l4_dst_port);
                ip6h0->dst_address.as_u64[1] = map_ce_get_sfx_fmr_net(d0, ip40->dst_address.as_u32, vnet_buffer (p0)->ip.reass.l4_dst_port);
            }
            else
                ip6h0->dst_address = d0->ip6_dst;

            /* tc */
            ip6h0->ip_version_traffic_class_and_flow_label = ip4_map_e_ce_vtcfl (d0, ip40, p0);

            /*
             * Determine next node. Can be one of:
             * ip6-lookup, ip6-rewrite, error-drop
             */
            if (PREDICT_TRUE (error0 == MAP_CE_ERROR_NONE))
            {
                if (PREDICT_FALSE(d0->mtu && 
                                 (clib_net_to_host_u16 (ip6h0->payload_length) + sizeof (*ip6h0) > d0->mtu)))
                {
                    next0 = ip4_map_e_ce_fragment (vm, cm, pi0, d0, df0, &buffer0, &error0);

                    if (error0 == MAP_CE_ERROR_NONE)
                    {
                        free_original_buffer0 = true;
                    }
                }
                else
                {
                    vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_TX,
                            thread_index,
                            map_domain_index0, 1,
                            clib_net_to_host_u16(ip6h0->payload_length) + 40);
                }
            }
            else
            {
                next0 = MAPE_CE_IP4_NEXT_DROP;
            }

            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_add_trace (vm, node, p0, map_domain_index0);
            }

            p0->error = error_node->errors[error0];

            /* Send fragments that were added in the frame */
            if (free_original_buffer0)
            {
                vlib_buffer_free_one (vm, pi0);	/* Free original packet */
            }
            else
            {
                vec_add1 (buffer0, pi0);
            }

            frag_from0 = buffer0;
            frag_left0 = vec_len (buffer0);

            while (frag_left0 > 0)
            {
                while (frag_left0 > 0 && n_left_to_next > 0)
                {
                    u32 i0;
                    i0 = to_next[0] = frag_from0[0];
                    frag_from0 += 1;
                    frag_left0 -= 1;
                    to_next += 1;
                    n_left_to_next -= 1;

                    vlib_get_buffer (vm, i0)->error = error_node->errors[error0];
                    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                            to_next, n_left_to_next,
                            i0, next0);
                }
                vlib_put_next_frame (vm, node, next_index, n_left_to_next);
                vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
            }
            vec_reset_length (buffer0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }

    vec_free (buffer0);
    return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_map_e_ce_node) = {
    .function = ip4_map_e_ce,
    .name = "ip4-map-e-ce",
    .vector_size = sizeof(u32),
    .format_trace = format_map_ce_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = MAP_CE_N_ERROR,
    .error_counters = map_ce_error_counters,

    .n_next_nodes = MAPE_CE_IP4_N_NEXT,
    .next_nodes = {
        [MAPE_CE_IP4_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [MAPE_CE_IP4_NEXT_DROP] = "error-drop",
    },
};

/* *INDENT-ON* */
