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

enum mapt_ce_ip4_next_e
{
    MAPT_CE_IP4_NEXT_IP6_LOOKUP,
    MAPT_CE_IP4_NEXT_IP6_FRAG,
    MAPT_CE_IP4_NEXT_DROP,
    MAPT_CE_IP4_N_NEXT,
};

typedef struct
{
  map_ce_domain_t *d;
  u16 src_port;
  u16 dst_port;
} mapt_ce_icmp_to_icmp6_ctx_t;

static int
mapt_ce_ip4_to_ip6_set_icmp_cb (vlib_buffer_t * b, ip4_header_t * ip4,
			ip6_header_t * ip6, void *arg)
{
  mapt_ce_icmp_to_icmp6_ctx_t *ctx = arg;
  ip4_address_t old_src, old_dst;

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  ip6->src_address.as_u64[0] = map_ce_get_pfx_net (ctx->d, old_src.as_u32, ctx->src_port);
  ip6->src_address.as_u64[1] = map_ce_get_sfx_net (ctx->d, old_src.as_u32, ctx->src_port);

  if (ip4_map_check_dst_ip_type(ctx->d, &old_dst))
  {
      ip6->dst_address.as_u64[0] = map_ce_get_pfx_fmr_net (ctx->d, old_dst.as_u32, ctx->dst_port);
      ip6->dst_address.as_u64[1] = map_ce_get_sfx_fmr_net (ctx->d, old_dst.as_u32, ctx->dst_port);
  }
  else
      ip4_map_t_ce_embedded_address (ctx->d, &ip6->dst_address, &old_dst);
  return 0;
}

static int
mapt_ce_ip4_to_ip6_set_inner_icmp_cb (vlib_buffer_t * b, ip4_header_t * ip4,
			      ip6_header_t * ip6, void *arg)
{
  mapt_ce_icmp_to_icmp6_ctx_t *ctx = arg;
  ip4_address_t old_src, old_dst;

  old_src.as_u32 = ip4->src_address.as_u32;
  old_dst.as_u32 = ip4->dst_address.as_u32;

  //Note that the destination address is within the domain
  //while the source address is the one outside the domain
  ip6->dst_address.as_u64[0] = map_ce_get_pfx_net (ctx->d, old_dst.as_u32, ctx->dst_port);
  ip6->dst_address.as_u64[1] = map_ce_get_sfx_net (ctx->d, old_dst.as_u32, ctx->dst_port);

  if (ip4_map_check_dst_ip_type(ctx->d, &old_src))
  {
      ip6->src_address.as_u64[0] = map_ce_get_pfx_fmr_net (ctx->d, old_src.as_u32, ctx->src_port);
      ip6->src_address.as_u64[1] = map_ce_get_sfx_fmr_net (ctx->d, old_src.as_u32, ctx->src_port);
  }
  else
      ip4_map_t_ce_embedded_address (ctx->d, &ip6->src_address, &old_src);

  return 0;
}

/*
 * Translate fragmented IPv4 UDP/TCP packet to IPv6.
 */
static_always_inline int
mapt_ce_ip4_to_ip6_fragmented (vlib_buffer_t * p, map_ce_domain_t *d, ip4_header_t *ip4, u16 src_port, u16 dst_port)
{
    map_ce_main_t *mm = &map_ce_main;

    ip6_header_t *ip6;
    ip6_frag_hdr_t *frag;

    ip4_address_t old_src, old_dst;

    frag = (ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
    ip6 = (ip6_header_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag) - sizeof (*ip6));
    vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));

    old_src.as_u32 = ip4->src_address.as_u32;
    old_dst.as_u32 = ip4->dst_address.as_u32;

    //We know that the protocol was one of ICMP, TCP or UDP
    //because the first fragment was found and cached
    frag->next_hdr = (ip4->protocol == IP_PROTOCOL_ICMP) ? IP_PROTOCOL_ICMP6 : ip4->protocol;
    frag->identification = frag_id_4to6 (ip4->fragment_id);
    frag->rsv = 0;
    frag->fragment_offset_and_more = 
        ip6_frag_hdr_offset_and_more (ip4_get_fragment_offset (ip4),
                                      clib_net_to_host_u16(ip4->flags_and_fragment_offset) & IP4_HEADER_FLAG_MORE_FRAGMENTS);

    //vtcfl
    if (d->tc_valid)
    {
        if (d->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (d->tc << 20));
    }
    else
    {
        if (mm->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (mm->tc << 20));
    }

    ip6->payload_length = clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) - sizeof (*ip4) + sizeof (*frag));
    ip6->hop_limit = ip4->ttl;
    ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;

    ip6->src_address.as_u64[0] = map_ce_get_pfx_net (d, old_src.as_u32, src_port);
    ip6->src_address.as_u64[1] = map_ce_get_sfx_net (d, old_src.as_u32, src_port);
    if (ip4_map_check_dst_ip_type(d, &old_dst))
    {
        ip6->dst_address.as_u64[0] = map_ce_get_pfx_fmr_net (d, old_dst.as_u32, dst_port);
        ip6->dst_address.as_u64[1] = map_ce_get_sfx_fmr_net (d, old_dst.as_u32, dst_port);
    }
    else
        ip4_map_t_ce_embedded_address (d, &ip6->dst_address, &old_dst);

    return 0;
}

/*
 * Translate IPv4 TCP packet to IPv6.
 */
static_always_inline int
mapt_ce_ip4_to_ip6_tcp (vlib_buffer_t * p, map_ce_domain_t *d, ip4_header_t *ip4, u16 src_port, u16 dst_port)
{
    map_ce_main_t *mm = &map_ce_main;

    ip_csum_t csum;
    ip6_header_t *ip6;
    u16 *checksum;
    ip6_frag_hdr_t *frag;

    u32 frag_id;
    ip4_address_t old_src, old_dst;

    tcp_header_t *tcp = ip4_next_header (ip4);

    checksum = &tcp->checksum;

    if (d->tcp_mss_valid)
    {
        if (d->tcp_mss > 0 && tcp_syn (tcp))
        {
            csum = tcp->checksum;
            map_mss_clamping (tcp, &csum, d->tcp_mss);
            tcp->checksum = ip_csum_fold (csum);
        }
    }
    else
    {
        if (mm->tcp_mss > 0 && tcp_syn (tcp))
        {
            csum = tcp->checksum;
            map_mss_clamping (tcp, &csum, mm->tcp_mss);
            tcp->checksum = ip_csum_fold (csum);
        }
    }

    old_src.as_u32 = ip4->src_address.as_u32;
    old_dst.as_u32 = ip4->dst_address.as_u32;

    //frag
    if (PREDICT_FALSE (ip4->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
    {
        ip6 = (ip6_header_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
        frag = (ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
        frag_id = frag_id_4to6 (ip4->fragment_id); 

        vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
    }
    else
    {
        ip6 = (ip6_header_t *) (((u8 *) ip4) + sizeof (*ip4) - sizeof (*ip6));
        vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
        frag = NULL;
    }

    //vtcfl
    if (d->tc_valid)
    {
        if (d->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (d->tc << 20));
    }
    else
    {
        if (mm->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (mm->tc << 20));
    }

    ip6->payload_length = u16_net_add (ip4->length, -sizeof (*ip4));
    ip6->hop_limit = ip4->ttl;
    ip6->protocol = ip4->protocol;

    if (PREDICT_FALSE (frag != NULL))
    {
        frag->next_hdr = ip6->protocol;
        frag->identification = frag_id;
        frag->rsv = 0;
        frag->fragment_offset_and_more = ip6_frag_hdr_offset_and_more (0, 1);
        ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
        ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

    ip6->src_address.as_u64[0] = map_ce_get_pfx_net (d, old_src.as_u32, src_port);
    ip6->src_address.as_u64[1] = map_ce_get_sfx_net (d, old_src.as_u32, src_port);
    if (ip4_map_check_dst_ip_type(d, &old_dst))
    {
        ip6->dst_address.as_u64[0] = map_ce_get_pfx_fmr_net (d, old_dst.as_u32, dst_port);
        ip6->dst_address.as_u64[1] = map_ce_get_sfx_fmr_net (d, old_dst.as_u32, dst_port);
    }
    else
        ip4_map_t_ce_embedded_address (d, &ip6->dst_address, &old_dst);

    csum = ip_csum_sub_even (*checksum, old_src.as_u32);
    csum = ip_csum_sub_even (csum, old_dst.as_u32);
    csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
    csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
    csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
    csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
    *checksum = ip_csum_fold (csum);

    return 0;
}

/*
 * Translate IPv4 UDP packet to IPv6.
 */
static_always_inline int
mapt_ce_ip4_to_ip6_udp (vlib_buffer_t * p, map_ce_domain_t *d, ip4_header_t *ip4, u16 src_port, u16 dst_port)
{
    map_ce_main_t *mm = &map_ce_main;

    ip_csum_t csum;
    ip6_header_t *ip6;
    u16 *checksum;
    ip6_frag_hdr_t *frag;

    u32 frag_id;
    ip4_address_t old_src, old_dst;

    udp_header_t *udp = ip4_next_header (ip4);

    /*
     * UDP checksum is optional over IPv4 but mandatory for IPv6 We
     * do not check udp->length sanity but use our safe computed
     * value instead
     */

    checksum = &udp->checksum;

    if (PREDICT_FALSE (!*checksum))
    {
        u16 udp_len = clib_host_to_net_u16 (ip4->length) - sizeof (*ip4);
        csum = ip_incremental_checksum (0, udp, udp_len);
        csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
        csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (IP_PROTOCOL_UDP));
        csum = ip_csum_with_carry (csum, *((u64 *) (&ip4->src_address)));
        *checksum = ~ip_csum_fold (csum);
	}

    old_src.as_u32 = ip4->src_address.as_u32;
    old_dst.as_u32 = ip4->dst_address.as_u32;

    //frag
    if (PREDICT_FALSE (ip4->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
    {
        ip6 = (ip6_header_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
        frag = (ip6_frag_hdr_t *) u8_ptr_add (ip4, sizeof (*ip4) - sizeof (*frag));
        frag_id = frag_id_4to6 (ip4->fragment_id); 

        vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6) - sizeof (*frag));
    }
    else
    {
        ip6 = (ip6_header_t *) (((u8 *) ip4) + sizeof (*ip4) - sizeof (*ip6));
        vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
        frag = NULL;
    }

    //vtcfl
    if (d->tc_valid)
    {
        if (d->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (d->tc << 20));
    }
    else
    {
        if (mm->tc_copy)
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));
        else
            ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 ((6 << 28) + (mm->tc << 20));
    }

    ip6->payload_length = u16_net_add (ip4->length, -sizeof (*ip4));
    ip6->hop_limit = ip4->ttl;
    ip6->protocol = ip4->protocol;

    if (PREDICT_FALSE (frag != NULL))
    {
        frag->next_hdr = ip6->protocol;
        frag->identification = frag_id;
        frag->rsv = 0;
        frag->fragment_offset_and_more = ip6_frag_hdr_offset_and_more (0, 1);
        ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
        ip6->payload_length = u16_net_add (ip6->payload_length, sizeof (*frag));
    }

    ip6->src_address.as_u64[0] = map_ce_get_pfx_net (d, old_src.as_u32, src_port);
    ip6->src_address.as_u64[1] = map_ce_get_sfx_net (d, old_src.as_u32, src_port);
    if (ip4_map_check_dst_ip_type(d, &old_dst))
    {
        ip6->dst_address.as_u64[0] = map_ce_get_pfx_fmr_net (d, old_dst.as_u32, dst_port);
        ip6->dst_address.as_u64[1] = map_ce_get_sfx_fmr_net (d, old_dst.as_u32, dst_port);
    }
    else
        ip4_map_t_ce_embedded_address (d, &ip6->dst_address, &old_dst);

    csum = ip_csum_sub_even (*checksum, old_src.as_u32);
    csum = ip_csum_sub_even (csum, old_dst.as_u32);
    csum = ip_csum_add_even (csum, ip6->src_address.as_u64[0]);
    csum = ip_csum_add_even (csum, ip6->src_address.as_u64[1]);
    csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[0]);
    csum = ip_csum_add_even (csum, ip6->dst_address.as_u64[1]);
    *checksum = ip_csum_fold (csum);

    return 0;
}

static_always_inline int
mapt_ce_ip4_to_ip6_icmp (vlib_buffer_t * p, map_ce_domain_t *d, ip4_header_t *ip4, u16 src_port, u16 dst_port)
{
    mapt_ce_icmp_to_icmp6_ctx_t ctx;

    ctx.src_port = src_port;
    ctx.dst_port = dst_port;
    ctx.d = d;

    if (icmp_to_icmp6(p, mapt_ce_ip4_to_ip6_set_icmp_cb, &ctx, mapt_ce_ip4_to_ip6_set_inner_icmp_cb, &ctx))
    {
        return MAP_CE_ERROR_ICMP;
    }
    return MAP_CE_ERROR_NONE;
}

/*
 * ip4_map_t_ce
 */
static uword
ip4_map_t_ce (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip4_map_e_ce_node.index);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    map_ce_main_t *mm = &map_ce_main;
    vlib_combined_counter_main_t *cm = mm->domain_counters;
    u32 thread_index = vm->thread_index;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;
            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAPT_CE_IP4_NEXT_IP6_LOOKUP;

            map_ce_domain_t *d0;
            ip4_header_t *ip40;
            u16 ip4_len0;
            u16 l4_src_port0 = UINT16_MAX;
            u16 l4_dst_port0 = UINT16_MAX;
            u32 map_domain_index0 = ~0;
            u16 mtu0 = ~0; 

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;
            to_next += 1;
            n_left_to_next -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);


            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, vnet_buffer (p0)->map_ce.map_domain_index);


            l4_src_port0 = vnet_buffer (p0)->ip.reass.l4_src_port;
            l4_dst_port0 = vnet_buffer (p0)->ip.reass.l4_dst_port;
            ip4_len0 = clib_host_to_net_u16 (ip40->length);

            if (PREDICT_FALSE (p0->current_length < ip4_len0 || ip40->ip_version_and_header_length != 0x45))
            {
                error0 = MAP_CE_ERROR_UNKNOWN;
                next0 = MAPT_CE_IP4_NEXT_DROP;
                goto trace;
            }

            if (PREDICT_FALSE (ip4_get_fragment_offset (ip40)))
            {
                if (l4_src_port0 == UINT16_MAX)
                {
                    error0 = MAP_CE_ERROR_FRAGMENT_MEMORY;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
                if (mapt_ce_ip4_to_ip6_fragmented(p0, d0, ip40, l4_src_port0, l4_dst_port0))
                {
                    error0 = MAP_CE_ERROR_UNKNOWN;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
            }
            else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP))
            {
                if (ip4_len0 < 40)
                {
                    error0 = MAP_CE_ERROR_MALFORMED;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
                if (mapt_ce_ip4_to_ip6_tcp(p0, d0, ip40, l4_src_port0, l4_dst_port0))
                {
                    error0 = MAP_CE_ERROR_UNKNOWN;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
            }
            else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_UDP))
            {
                if (ip4_len0 < 40)
                {
                    error0 = MAP_CE_ERROR_MALFORMED;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }

                if (mapt_ce_ip4_to_ip6_udp(p0, d0, ip40, l4_src_port0, l4_dst_port0))
                {
                    error0 = MAP_CE_ERROR_UNKNOWN;
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
            }
            else if (ip40->protocol == IP_PROTOCOL_ICMP)
            {
                error0 = mapt_ce_ip4_to_ip6_icmp(p0, d0, ip40, l4_src_port0, l4_dst_port0);
                if (error0 != MAP_CE_ERROR_NONE)
                {
                    next0 = MAPT_CE_IP4_NEXT_DROP;
                    goto trace;
                }
            }
            else
            {
                error0 = MAP_CE_ERROR_BAD_PROTOCOL;
                goto trace;
            }

            mtu0 = d0->mtu ? d0->mtu : ~0;
            if (mtu0 < p0->current_length)
            {
                //Send to fragmentation node if necessary
                vnet_buffer (p0)->ip_frag.mtu = mtu0;
                vnet_buffer (p0)->ip_frag.next_index = IP_FRAG_NEXT_IP6_LOOKUP;
                next0 = MAPT_CE_IP4_NEXT_IP6_FRAG;
            }

            vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_TX,
                                             thread_index,
                                             map_domain_index0, 1,
                                             ip4_len0 + 20);
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
VLIB_REGISTER_NODE(ip4_map_t_ce_node) = {
  .function = ip4_map_t_ce,
  .name = "ip4-map-t-ce",
  .vector_size = sizeof(u32),
  .format_trace = format_map_ce_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_CE_N_ERROR,
  .error_counters = map_ce_error_counters,

  .n_next_nodes = MAPT_CE_IP4_N_NEXT,
  .next_nodes = {
      [MAPT_CE_IP4_NEXT_IP6_LOOKUP] = "ip6-lookup",
      [MAPT_CE_IP4_NEXT_IP6_FRAG] = IP6_FRAG_NODE_NAME,
      [MAPT_CE_IP4_NEXT_DROP] = "error-drop",
  },
};
