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
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

enum mape_ce_ip6_next_e
{
    MAPE_CE_IP6_NEXT_NAT_OUT2IN,
    MAPE_CE_IP6_NEXT_IP4_REASS,
    MAPE_CE_IP6_NEXT_IP4_FRAGMENT,
    MAPE_CE_IP6_NEXT_IP6_LOCAL,
    MAPE_CE_IP6_NEXT_ICMP_ERROR,
    MAPE_CE_IP6_NEXT_DROP,
    MAPE_CE_IP6_N_NEXT,
};

enum mape_ce_ip6_post_ip4_reass_next_e
{
    MAPE_CE_IP6_MAP_POST_IP4_REASS_NEXT_NAT_OUT2IN,
    MAPE_CE_IP6_MAP_POST_IP4_REASS_NEXT_DROP,
    MAPE_CE_IP6_MAP_POST_IP4_REASS_N_NEXT,
};

typedef struct
{
  u32 map_domain_index;
  u16 port;
} map_ce_ip6_map_ip4_reass_trace_t;

u8 *
format_ip6_map_ce_post_ip4_reass_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  map_ce_ip6_map_ip4_reass_trace_t *t =
    va_arg (*args, map_ce_ip6_map_ip4_reass_trace_t *);
  return format (s, "MAP domain index: %d L4 port: %u",
		 t->map_domain_index, clib_net_to_host_u16 (t->port));
}

static_always_inline bool
ip6_map_ce_sec_check (map_ce_domain_t * d, u16 port, ip4_header_t * ip4, ip6_header_t * ip6)
{
    u16 sp4 = clib_net_to_host_u16 (port);
    u32 sa4 = clib_net_to_host_u32 (ip4->src_address.as_u32);
    u64 sal6 = map_ce_get_pfx (d, sa4, sp4);
    u64 sar6 = map_ce_get_sfx (d, sa4, sp4);

    if (PREDICT_FALSE(
            sal6 != clib_net_to_host_u64 (ip6->src_address.as_u64[0]) || 
            sar6 != clib_net_to_host_u64 (ip6->src_address.as_u64[1])
            ))
        return (false);
    return (true);
}

static_always_inline void
mape_ce_ip6_map_security_check (map_ce_domain_t * d, vlib_buffer_t * b,
                                ip4_header_t * ip4, ip6_header_t * ip6, 
                                u32 * next, u8 * error)
{
    map_ce_main_t *mm = &map_ce_main;

    if (d->psid_length > 0)
    {
        if (!ip4_is_fragment (ip4))
        {
            u16 port = ip4_get_port (ip4, 1);
            if (port)
            {
                if (d->sec_check_valid)
                {
                    if (d->sec_check)
                        *error = ip6_map_ce_sec_check (d, port, ip4, ip6) ? 
                            MAP_CE_ERROR_NONE : MAP_CE_ERROR_DECAP_SEC_CHECK;
                }
                else
                {
                    if (mm->sec_check)
                        *error = ip6_map_ce_sec_check (d, port, ip4, ip6) ? 
                            MAP_CE_ERROR_NONE : MAP_CE_ERROR_DECAP_SEC_CHECK;
                }
            }
            else
            {
                *error = MAP_CE_ERROR_BAD_PROTOCOL;
            }
        }
        else
        {
            if (d->sec_check_valid)
            {
                if (d->sec_check_frag)
                {
                    vnet_buffer (b)->ip.reass.next_index = mm->ip4_sv_reass_custom_next_index;
                    *next = MAPE_CE_IP6_NEXT_IP4_REASS;
                }
            }
            else
            {
                if (mm->sec_check_frag)
                {
                    vnet_buffer (b)->ip.reass.next_index = mm->ip4_sv_reass_custom_next_index;
                    *next = MAPE_CE_IP6_NEXT_IP4_REASS;
                }
            }
        }
    }
}

static_always_inline int
mape_ce_ip6_map_icmp_relay (vlib_main_t * vm, map_ce_domain_t *d, vlib_buffer_t *p, ip6_header_t *ip6)
{
    /*
     * In:
     *  IPv6 header           (40)
     *  ICMPv6 header          (8)
     *  IPv6 header           (40)
     *  Original IPv4 header / packet
     *
     * Out:
     *  New IPv4 header
     *  New ICMP header
     *  Original IPv4 header / packet
     *
     * Need at least ICMP(8) + IPv6(40) + IPv4(20) + L4 header(8)
     *
     */
    map_ce_main_t *mm = &map_ce_main;

    u32 mtu;
    u16 *fragment_ids;
    u16 tlen = clib_net_to_host_u16 (ip6->payload_length);

    fragment_ids = clib_random_buffer_get_data (&vm->random_buffer, sizeof (fragment_ids[0]));

    if (tlen < 76)
    {
        return MAP_CE_ERROR_ICMP_RELAY;
    }

    icmp46_header_t *icmp6 = (icmp46_header_t *) (ip6 + 1);
    ip6_header_t *inner_ip6 = (ip6_header_t *) (icmp6 + 2);
    if (inner_ip6->protocol != IP_PROTOCOL_IP_IN_IP)
    {
        return MAP_CE_ERROR_ICMP_RELAY;
    }

    ip4_header_t *inner_ip4 = (ip4_header_t *) (inner_ip6 + 1);
    vlib_buffer_advance (p, 60);	/* sizeof ( IPv6 + ICMP + IPv6 - IPv4 - ICMP ) */
    ip4_header_t *new_ip4 = vlib_buffer_get_current (p);
    icmp46_header_t *new_icmp4 = (icmp46_header_t *) (new_ip4 + 1);

    /*
     * Relay according to RFC2473, section 8.3
     */
    switch (icmp6->type)
    {
    case ICMP6_destination_unreachable:
    case ICMP6_time_exceeded:
    case ICMP6_parameter_problem:
        /* Type 3 - destination unreachable, Code 1 - host unreachable */
        new_icmp4->type = ICMP4_destination_unreachable;
        new_icmp4->code = ICMP4_destination_unreachable_destination_unreachable_host;
        break;

    case ICMP6_packet_too_big:
        /* Type 3 - destination unreachable, Code 4 - packet too big */
        /* Potential TODO: Adjust domain tunnel MTU based on the value received here */
        mtu = clib_net_to_host_u32 (*((u32 *) (icmp6 + 1)));
        /* Check DF flag */
        if (!(inner_ip4->flags_and_fragment_offset & clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT)))
        {
            return MAP_CE_ERROR_ICMP_RELAY;
        }

        new_icmp4->type = ICMP4_destination_unreachable;
        new_icmp4->code = ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set;
        *((u32 *) (new_icmp4 + 1)) = clib_host_to_net_u32 (mtu < 1280 ? 1280 : mtu);
        break;

    default:
        return MAP_CE_ERROR_ICMP_RELAY;
    }

    /*
     * Ensure the total ICMP packet is no longer than 576 bytes (RFC1812)
     */
    new_ip4->ip_version_and_header_length = 0x45;
    new_ip4->tos = 0;
    u16 nlen = (tlen - 20) > 576 ? 576 : tlen - 20;
    new_ip4->length = clib_host_to_net_u16 (nlen);
    new_ip4->fragment_id = fragment_ids[0];
    new_ip4->ttl = 64;
    new_ip4->protocol = IP_PROTOCOL_ICMP;
    new_ip4->src_address = d->icmp4_src_address_valid ? d->icmp4_src_address : mm->icmp4_src_address;
    new_ip4->dst_address = inner_ip4->src_address;
    new_ip4->checksum = ip4_header_checksum (new_ip4);

    new_icmp4->checksum = 0;
    ip_csum_t sum = ip_incremental_checksum (0, new_icmp4, nlen - 20);
    new_icmp4->checksum = ~ip_csum_fold (sum);

    return MAP_CE_ERROR_NONE;
}

/*
 * ip6_map_e_ce
 */
static uword
ip6_map_e_ce (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip6_map_e_ce_node.index);
    map_ce_main_t *mm = &map_ce_main;
    vlib_combined_counter_main_t *cm = mm->domain_counters;
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

            map_ce_domain_t *d0 = 0;
            u32 map_domain_index0 = ~0;

            ip4_header_t *ip40;
            ip6_header_t *ip60;

            u32 next0 = MAPE_CE_IP6_NEXT_NAT_OUT2IN;
            u8 error0 = MAP_CE_ERROR_NONE;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;
            to_next += 1;
            n_left_to_next -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip60 = vlib_buffer_get_current (p0);

            vlib_buffer_advance (p0, sizeof (ip6_header_t));
            ip40 = vlib_buffer_get_current (p0);

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_IP_IN_IP && 
                             clib_net_to_host_u16 (ip60->payload_length) > 20))
            {
                /* MAP inbound security check */
                mape_ce_ip6_map_security_check (d0, p0, ip40, ip60, &next0, &error0);

                if (PREDICT_TRUE (error0 == MAP_CE_ERROR_NONE && 
                                  next0 == MAPE_CE_IP6_NEXT_NAT_OUT2IN))
                {
                    vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_RX,
                                                     thread_index,
                                                     map_domain_index0, 1,
                                                     clib_net_to_host_u16
                                                     (ip40->length));
                }
            }
            else if (ip60->protocol == IP_PROTOCOL_ICMP6 &&
                    clib_net_to_host_u16 (ip60->payload_length) > sizeof (icmp46_header_t))
            {
                icmp46_header_t *icmp60 = (void *) (ip60 + 1);
                if (icmp60->type == ICMP6_echo_request ||
                    icmp60->type == ICMP6_echo_reply)
                {
                    next0 = MAPE_CE_IP6_NEXT_IP6_LOCAL;
                    vlib_buffer_advance (p0, -sizeof (ip6_header_t));
                    goto trace;
                }

                error0 = mape_ce_ip6_map_icmp_relay(vm, d0, p0, ip60);
                if (error0 != MAP_CE_ERROR_NONE)
                {
                    next0 = MAPE_CE_IP6_NEXT_DROP;
                    goto trace;
                }    

                vlib_increment_simple_counter (&mm->icmp_relayed, thread_index, 0, 1);

            }
            else if (ip60->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION &&
                    (((ip6_frag_hdr_t *) (ip60 + 1))->next_hdr == IP_PROTOCOL_IP_IN_IP))
            {
                error0 = MAP_CE_ERROR_FRAGMENTED;
                next0 = MAPE_CE_IP6_NEXT_DROP;
                goto trace;
            }
            else
            {
                error0 = MAP_CE_ERROR_BAD_PROTOCOL;
                next0 = MAPE_CE_IP6_NEXT_DROP;
                goto trace;
            }

            if (error0 == MAP_CE_ERROR_DECAP_SEC_CHECK &&
                ((d0 && d0->icmp6_enabled_valid) ? d0->icmp6_enabled : mm->icmp6_enabled))
            {
                /* Set ICMP parameters */
                vlib_buffer_advance (p0, -sizeof (ip6_header_t));
                icmp6_error_set_vnet_buffer (p0, ICMP6_destination_unreachable,
                        ICMP6_destination_unreachable_source_address_failed_policy,
                        0);
                next0 = MAPE_CE_IP6_NEXT_ICMP_ERROR;
            }
            else
            {
                next0 = (error0 == MAP_CE_ERROR_NONE) ? next0 : MAPE_CE_IP6_NEXT_DROP;
            }

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_add_trace (vm, node, p0, map_domain_index0);
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                    n_left_to_next, pi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

static uword
ip6_map_ce_post_ip4_reass (vlib_main_t * vm,
                           vlib_node_runtime_t * node, 
                           vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip6_map_ce_post_ip4_reass_node.index);
    map_ce_main_t *mm = &map_ce_main;
    vlib_combined_counter_main_t *cm = mm->domain_counters;
    u32 thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        /* Single loop */
        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;

            map_ce_domain_t *d0;
            u32 map_domain_index0 = ~0;

            ip4_header_t *ip40;
            ip6_header_t *ip60;
            i32 port0 = 0;

            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAPE_CE_IP6_MAP_POST_IP4_REASS_NEXT_NAT_OUT2IN;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;
            to_next += 1;
            n_left_to_next -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);
            ip60 = ((ip6_header_t *) ip40) - 1;

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            port0 = vnet_buffer (p0)->ip.reass.l4_src_port;

            error0 = ip6_map_ce_sec_check (d0, port0, ip40, ip60) ? 
                        MAP_CE_ERROR_NONE : MAP_CE_ERROR_DECAP_SEC_CHECK;

            if (error0 != MAP_CE_ERROR_NONE)
                goto trace;

            vlib_increment_combined_counter (cm + MAP_CE_DOMAIN_COUNTER_RX,
                                                 thread_index,
                                                 map_domain_index0, 1,
                                                 clib_net_to_host_u16(ip40->length));

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                map_ce_ip6_map_ip4_reass_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof (*tr));
                tr->map_domain_index = map_domain_index0;
                tr->port = port0;
            }

            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next, 
                    n_left_to_next, pi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return frame->n_vectors;
}


VLIB_REGISTER_NODE(ip6_map_e_ce_node) = {
  .function = ip6_map_e_ce,
  .name = "ip6-map-e-ce",
  .vector_size = sizeof(u32),
  .format_trace = format_map_ce_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_CE_N_ERROR,
  .error_counters = map_ce_error_counters,

  .n_next_nodes = MAPE_CE_IP6_N_NEXT,
  .next_nodes = {
    [MAPE_CE_IP6_NEXT_NAT_OUT2IN] = "map-ce-nat44-ei-out2in",
    [MAPE_CE_IP6_NEXT_IP4_REASS] = "ip4-sv-reassembly-custom-next",
    [MAPE_CE_IP6_NEXT_IP4_FRAGMENT] = "ip4-frag",
    [MAPE_CE_IP6_NEXT_IP6_LOCAL] = "ip6-local",
    [MAPE_CE_IP6_NEXT_ICMP_ERROR] = "ip6-icmp-error",
    [MAPE_CE_IP6_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip6_map_ce_post_ip4_reass_node) = {
  .function = ip6_map_ce_post_ip4_reass,
  .name = "ip6-map-ce-post-ip4-reass",
  .vector_size = sizeof(u32),
  .format_trace = format_ip6_map_ce_post_ip4_reass_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = MAP_CE_N_ERROR,
  .error_counters = map_ce_error_counters,
  .n_next_nodes = MAPE_CE_IP6_MAP_POST_IP4_REASS_N_NEXT,
  .next_nodes = {
    [MAPE_CE_IP6_MAP_POST_IP4_REASS_NEXT_NAT_OUT2IN] = "map-ce-nat44-ei-out2in",
    [MAPE_CE_IP6_MAP_POST_IP4_REASS_NEXT_DROP] = "error-drop",
  },
};

clib_error_t *
mape_ce_ip6_init (vlib_main_t * vm)
{
    map_ce_main.ip4_sv_reass_custom_next_index =
        ip4_sv_reass_custom_register_next_node(ip6_map_ce_post_ip4_reass_node.index);
    return 0;
}

VLIB_INIT_FUNCTION (mape_ce_ip6_init) =
{
    .runs_after = VLIB_INITS ("map_ce_init"),
};
