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

#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/ip_frag.h>

enum mapt_ce_ip6_next_e
{
    MAPT_CE_IP6_NEXT_NAT_OUT2IN,
    MAPT_CE_IP6_NEXT_ICMP_ERROR,
    MAPT_CE_IP6_NEXT_DROP,
    MAPT_CE_IP6_N_NEXT,
};

typedef struct
{
  map_ce_domain_t *d;
  u16 dst_port;
} mapt_ce_icmp6_to_icmp_ctx_t;

static int
mapt_ce_ip6_to_ip4_set_icmp_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
    mapt_ce_icmp6_to_icmp_ctx_t *ctx = arg;
    u32 ip4_dadr;

    // Security check
    // Note that this prevents an intermediate IPv6 router from answering
    // the request.
    ip4_dadr = map_ce_get_ip4 (ctx->d, &ip6->dst_address);
    if (ip6->dst_address.as_u64[0] != map_ce_get_pfx_net (ctx->d, ip4_dadr, ctx->dst_port) || 
        ip6->src_address.as_u64[1] != map_ce_get_sfx_net (ctx->d, ip4_dadr, ctx->dst_port))
        return -1;

    ip4->src_address.as_u32 = ip6_map_t_ce_embedded_address (ctx->d, &ip6->src_address);
    ip4->dst_address.as_u32 = ip4_dadr;
  return 0;
}

static int
mapt_ce_ip6_to_ip4_set_inner_icmp_cb (ip6_header_t *ip6, ip4_header_t *ip4, void *arg)
{
  mapt_ce_icmp6_to_icmp_ctx_t *ctx = arg;
  u32 inner_ip4_dadr;

  //Security check of inner packet
  inner_ip4_dadr = map_ce_get_ip4 (ctx->d, &ip6->dst_address);
  if (ip6->dst_address.as_u64[0] !=
      map_ce_get_pfx_net (ctx->d, inner_ip4_dadr, ctx->dst_port)
      || ip6->dst_address.as_u64[1] != map_ce_get_sfx_net (ctx->d,
							inner_ip4_dadr,
							ctx->dst_port))
    return -1;

  ip4->dst_address.as_u32 = inner_ip4_dadr;
  ip4->src_address.as_u32 =
    ip6_map_t_ce_embedded_address (ctx->d, &ip6->src_address);

  return 0;
}

static void
mapt_ce_ip6_to_ip4_fragmented(map_ce_domain_t *d, 
                              vlib_buffer_t *p,
                              ip6_header_t *ip6, 
                              ip6_frag_hdr_t *frag, 
                              u32 saddr, 
                              u32 daddr,
                              u8 tos,
                              u8 l4_protocol, 
                              u16 l4_offset)
{
    u16 frag_id;
    u8 frag_more;
    u16 frag_offset;
    ip4_header_t *ip4;

    ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));
    vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

    frag_id = frag_id_6to4 (frag->identification);
    frag_more = ip6_frag_hdr_more (frag);
    frag_offset = ip6_frag_hdr_offset (frag);

    ip4->src_address.as_u32 = saddr;
    ip4->dst_address.as_u32 = daddr;

    ip4->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
    ip4->tos = tos;

    ip4->length = u16_net_add (ip6->payload_length, sizeof (*ip4) - l4_offset + sizeof (*ip6));
    ip4->fragment_id = frag_id;
    ip4->flags_and_fragment_offset = clib_host_to_net_u16 (frag_offset | (frag_more ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0));
    ip4->ttl = ip6->hop_limit;
    ip4->protocol = (l4_protocol == IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : l4_protocol;
    ip4->checksum = ip4_header_checksum (ip4);
}

static void
mapt_ce_ip6_to_ip4_tcp(map_ce_domain_t *d, 
                              vlib_buffer_t *p,
                              ip6_header_t *ip6, 
                              u32 saddr, 
                              u32 daddr,
                              u8 tos,
                              u16 l4_offset, 
                              u16 frag_hdr_offset)
{
    map_ce_main_t *mm = &map_ce_main;

    ip4_header_t *ip4;
    ip_csum_t csum = 0;
    u16 *checksum;
    ip6_address_t old_src, old_dst;
    u16 fragment_id;
    u16 flags;

    tcp_header_t *tcp = (tcp_header_t *) u8_ptr_add (ip6, l4_offset);

    u16 tcp_mss = d->tcp_mss ? d->tcp_mss : mm->tcp_mss;
    if (tcp_mss > 0)
    {
        csum = tcp->checksum;
        map_mss_clamping (tcp, &csum, tcp_mss);
        tcp->checksum = ip_csum_fold (csum);
    }
    checksum = &tcp->checksum;

    old_src.as_u64[0] = ip6->src_address.as_u64[0];
    old_src.as_u64[1] = ip6->src_address.as_u64[1];
    old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
    old_dst.as_u64[1] = ip6->dst_address.as_u64[1];

    ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));
    vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

    if (frag_hdr_offset)
    {
        // Only the first fragment
        ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_hdr_offset);
        fragment_id = frag_id_6to4 (hdr->identification);
        flags = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
    }
    else
    {
        fragment_id = 0;
        flags = 0;
    }

    ip4->src_address.as_u32 = saddr;
    ip4->dst_address.as_u32 = daddr;

    ip4->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
    ip4->tos = tos;
    ip4->length = u16_net_add (ip6->payload_length, sizeof (*ip4) + sizeof (*ip6) - l4_offset);

    ip4->fragment_id = fragment_id;
    ip4->flags_and_fragment_offset = flags;
    ip4->ttl = ip6->hop_limit;
    ip4->protocol = IP_PROTOCOL_TCP;
    ip4->checksum = ip4_header_checksum (ip4);

    csum = ip_csum_sub_even (*checksum, old_src.as_u64[0]);
    csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
    csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
    csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
    csum = ip_csum_add_even (csum, ip4->dst_address.as_u32);
    csum = ip_csum_add_even (csum, ip4->src_address.as_u32);
    *checksum = ip_csum_fold (csum);
}

static void
mapt_ce_ip6_to_ip4_udp(map_ce_domain_t *d, 
                              vlib_buffer_t *p,
                              ip6_header_t *ip6, 
                              u32 saddr, 
                              u32 daddr,
                              u8 tos,
                              u16 l4_offset, 
                              u16 frag_hdr_offset)
{
    ip4_header_t *ip4;
    ip_csum_t csum = 0;
    u16 *checksum;
    ip6_address_t old_src, old_dst;
    u16 fragment_id;
    u16 flags;

    udp_header_t *udp = (udp_header_t *) u8_ptr_add (ip6, l4_offset);

    checksum = &udp->checksum;

    old_src.as_u64[0] = ip6->src_address.as_u64[0];
    old_src.as_u64[1] = ip6->src_address.as_u64[1];
    old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
    old_dst.as_u64[1] = ip6->dst_address.as_u64[1];

    ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));
    vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

    if (frag_hdr_offset)
    {
        // Only the first fragment
        ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_hdr_offset);
        fragment_id = frag_id_6to4 (hdr->identification);
        flags = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
    }
    else
    {
        fragment_id = 0;
        flags = 0;
    }

    ip4->src_address.as_u32 = saddr;
    ip4->dst_address.as_u32 = daddr;

    ip4->ip_version_and_header_length = IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
    ip4->tos = tos;
    ip4->length = u16_net_add (ip6->payload_length, sizeof (*ip4) + sizeof (*ip6) - l4_offset);

    ip4->fragment_id = fragment_id;
    ip4->flags_and_fragment_offset = flags;
    ip4->ttl = ip6->hop_limit;
    ip4->protocol = IP_PROTOCOL_UDP;
    ip4->checksum = ip4_header_checksum (ip4);

    csum = ip_csum_sub_even (*checksum, old_src.as_u64[0]);
    csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
    csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
    csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
    csum = ip_csum_add_even (csum, ip4->dst_address.as_u32);
    csum = ip_csum_add_even (csum, ip4->src_address.as_u32);
    *checksum = ip_csum_fold (csum);
}

static u8
mapt_ce_ip6_to_ip4_icmp(map_ce_domain_t *d, 
                              vlib_buffer_t *p,
                              ip6_header_t *ip6, 
                              u32 saddr, 
                              u32 daddr,
                              u8 tos,
                              u16 l4_offset, 
                              u16 l4_dst_port)
{
    vlib_main_t *vm = vlib_get_main ();

    mapt_ce_icmp6_to_icmp_ctx_t ctx;

    ctx.d = d;
    ctx.dst_port = l4_dst_port;

    if (icmp6_to_icmp (vm, p, mapt_ce_ip6_to_ip4_set_icmp_cb, &ctx,
                mapt_ce_ip6_to_ip4_set_inner_icmp_cb, &ctx))
    {
        return MAP_CE_ERROR_ICMP;
    }

    return MAP_CE_ERROR_NONE;
}

static uword
ip6_map_t_ce (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip6_map_t_ce_node.index);
    map_ce_main_t *mm = &map_ce_main;
    vlib_combined_counter_main_t *cm = map_ce_main.domain_counters;
    u32 thread_index = vm->thread_index;

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

            map_ce_domain_t *d0;
            u32 map_domain_index0 = ~0;

            ip6_header_t *ip60;
            ip6_frag_hdr_t *frag0;
            u16 l4_dst_port0;
            u8 tos0;
            u8 l4_protocol0;
            u16 l4_offset0, frag_hdr_offset0;

            i32 map_port0 = -1;
            u32 saddr0;
            u32 daddr0;
            u32 l4_len0;


            u32 next0 = MAPT_CE_IP6_NEXT_NAT_OUT2IN;
            u8 error0 = MAP_CE_ERROR_NONE;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;
            to_next += 1;
            n_left_to_next -= 1;

            p0 = vlib_get_buffer (vm, pi0);

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            l4_dst_port0 = vnet_buffer (p0)->ip.reass.l4_dst_port;

            ip60 = vlib_buffer_get_current (p0);

            saddr0 = ip6_map_t_ce_embedded_address (d0, &ip60->src_address);
            daddr0 = map_ce_get_ip4 (d0, &ip60->dst_address);

            if (PREDICT_FALSE (ip6_parse (vm, p0, ip60, p0->current_length,
                                &l4_protocol0,
                                &l4_offset0,
                                &frag_hdr_offset0)))
            {
                error0 = MAP_CE_ERROR_MALFORMED;
                next0 = MAPT_CE_IP6_NEXT_DROP;
                goto trace;
            }

            l4_len0 = (u32) clib_net_to_host_u16 (ip60->payload_length) + sizeof (*ip60) - l4_offset0;

            //calc tos
            tos0 = d0->tos_valid ? 
                    (d0->tos_copy ? ip6_translate_tos (ip60->ip_version_traffic_class_and_flow_label) : d0->tos): 
                    (mm->tos_copy ? ip6_translate_tos (ip60->ip_version_traffic_class_and_flow_label) : mm->tos);

            frag0 = (ip6_frag_hdr_t *) u8_ptr_add (ip60, frag_hdr_offset0);
            if (PREDICT_FALSE(frag_hdr_offset0 && ip6_frag_hdr_offset (frag0)))
            {
                map_port0 = l4_dst_port0;
                mapt_ce_ip6_to_ip4_fragmented(d0, p0, ip60, frag0, 
                                              saddr0, daddr0, tos0, 
                                              l4_protocol0, l4_offset0);

            }
            else if (PREDICT_TRUE (l4_protocol0 == IP_PROTOCOL_TCP))
            {
                if (l4_len0 < sizeof (tcp_header_t))
                {
                    error0 = MAP_CE_ERROR_MALFORMED;
                    next0 = MAPT_CE_IP6_NEXT_DROP;
                    goto trace;
                }
                map_port0 = l4_dst_port0;
                mapt_ce_ip6_to_ip4_tcp(d0, p0, ip60, 
                                       saddr0, daddr0, tos0, l4_offset0, frag_hdr_offset0);
            }
            else if (PREDICT_TRUE (l4_protocol0 == IP_PROTOCOL_UDP))
            {
                if (l4_len0 < sizeof (udp_header_t))
                {
                    error0 = MAP_CE_ERROR_MALFORMED;
                    next0 = MAPT_CE_IP6_NEXT_DROP;
                    goto trace;
                }
                map_port0 = l4_dst_port0;
                mapt_ce_ip6_to_ip4_udp(d0, p0, ip60, 
                                       saddr0, daddr0, tos0, l4_offset0, frag_hdr_offset0);
            }
            else if (l4_protocol0 == IP_PROTOCOL_ICMP6)
            {
                if (l4_len0 < sizeof (icmp46_header_t))
                {
                    error0 = MAP_CE_ERROR_MALFORMED;
                    next0 = MAPT_CE_IP6_NEXT_DROP;
                    goto trace;
                }

                error0 = mapt_ce_ip6_to_ip4_icmp(d0, p0, ip60, 
                                       saddr0, daddr0, tos0, l4_offset0, l4_dst_port0);
                if (error0 != MAP_CE_ERROR_NONE)
                {
                    next0 = MAPT_CE_IP6_NEXT_ICMP_ERROR;
                    goto trace;
                }
                if (((icmp46_header_t *) u8_ptr_add (ip60, l4_offset0))->type == ICMP6_echo_reply || 
                    ((icmp46_header_t *) u8_ptr_add (ip60, l4_offset0))-> type == ICMP6_echo_request)
                {
                    map_port0 = l4_dst_port0;
                }
            }
            else
            {
                error0 = MAP_CE_ERROR_BAD_PROTOCOL;
                next0 = MAPT_CE_IP6_NEXT_DROP;
                goto trace;
            }

            if (PREDICT_FALSE (map_port0 != -1) && 
                              (d0->sec_check_valid ? d0->sec_check : mm->sec_check) &&
                              (ip60->dst_address.as_u64[0] != map_ce_get_pfx_net (d0, daddr0, map_port0) || 
                               ip60->dst_address.as_u64[1] != map_ce_get_sfx_net (d0, daddr0, map_port0)))
            {
                // Security check when map_port0 is not zero (non-first fragment, UDP or TCP)
                error0 = MAP_CE_ERROR_SEC_CHECK;
                if (d0->icmp6_enabled_valid ? d0->icmp6_enabled : mm->icmp6_enabled)
                {
                    icmp6_error_set_vnet_buffer (p0, ICMP6_destination_unreachable,
                            ICMP6_destination_unreachable_source_address_failed_policy,
                            0);
                    next0 = MAPT_CE_IP6_NEXT_ICMP_ERROR;
                }
                else
                {
                    next0 = MAPT_CE_IP6_NEXT_DROP;
                }
                goto trace;
            }

            vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_RX,
                                            thread_index,
                                            map_domain_index0, 1,
                                            clib_net_to_host_u16 (ip60->payload_length));

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_add_trace (vm, node, p0, map_domain_index0);
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                    to_next, n_left_to_next, pi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(ip6_map_t_ce_node) = {
  .function = ip6_map_t_ce,
  .name = "ip6-map-t-ce",
  .vector_size = sizeof(u32),
  .format_trace = format_map_ce_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_CE_N_ERROR,
  .error_counters = map_ce_error_counters,

  .n_next_nodes = MAPT_CE_IP6_N_NEXT,
  .next_nodes =
  {
    [MAPT_CE_IP6_NEXT_NAT_OUT2IN] = "map-ce-nat44-ei-out2in",
    [MAPT_CE_IP6_NEXT_ICMP_ERROR] = "ip6-icmp-error",
    [MAPT_CE_IP6_NEXT_DROP] = "error-drop",
  },
};
