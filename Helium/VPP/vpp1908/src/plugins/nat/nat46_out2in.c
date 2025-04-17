/**
 * @file
 * @brief NAT46 IPv4 to IPv6 translation (otside to inside network)
 */

#include <nat/nat46.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/udp/udp.h>

typedef struct
{
    u32 sw_if_index;
    u32 next_index;
} nat46_out2in_trace_t;

static u8 *
format_nat46_out2in_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    nat46_out2in_trace_t *t = va_arg (*args, nat46_out2in_trace_t *);

    s = format (s, "NAT46-out2in: sw_if_index %d, next index %d", t->sw_if_index, t->next_index);
    return s;
}

typedef struct
{
    u32 sw_if_index;
    u32 next_index;
    u8 cached;
} nat46_out2in_reass_trace_t;

static u8 *
format_nat46_out2in_reass_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    nat46_out2in_reass_trace_t *t = va_arg (*args, nat46_out2in_reass_trace_t *);

    s = format (s, "NAT46-out2in-reass: sw_if_index %d, next index %d, status %s",
                t->sw_if_index, t->next_index,
                t->cached ? "cached" : "translated");

    return s;
}

static inline u8
nat46_out2in_not_translate (u32 sw_if_index, ip6_address_t ip6_addr)
{
  nat46_main_t *nm = &nat46_main;
  ip6_address_t *addr;
  ip6_main_t *im6 = &ip6_main;
  ip_lookup_main_t *lm6 = &im6->lookup_main;
  ip_interface_address_t *ia = 0;
  int i;

  for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
  {
      if (nm->auto_add_sw_if_indices[i] == sw_if_index)
          return 0;
  }
  /* *INDENT-OFF* */
  foreach_ip_interface_address (lm6, ia, sw_if_index, 0,
  ({
	addr = ip_interface_address_get_address (lm6, ia);
	if (0 == ip6_address_compare (addr, &ip6_addr))
		return 1;
  }));
  /* *INDENT-ON* */
  return 0;
}


#define foreach_nat46_out2in_error                       \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol")          \
_(OUT2IN_PACKETS, "good out2in packets processed")       \
_(NO_TRANSLATION, "no translation")                      \
_(UNKNOWN, "unknown")                                    \
_(DROP_FRAGMENT, "drop fragment")                        \
_(MAX_REASS, "maximum reassemblies exceeded")            \
_(MAX_FRAG, "maximum fragments per reassembly exceeded") \
_(TCP_PACKETS, "TCP packets")                            \
_(UDP_PACKETS, "UDP packets")                            \
_(ICMP_PACKETS, "ICMP packets")                          \
_(OTHER_PACKETS, "other protocol packets")               \
_(FRAGMENTS, "fragments")                                \
_(CACHED_FRAGMENTS, "cached fragments")                  \
_(PROCESSED_FRAGMENTS, "processed fragments")


typedef enum
{
#define _(sym,str) NAT46_OUT2IN_ERROR_##sym,
    foreach_nat46_out2in_error
#undef _
    NAT46_OUT2IN_N_ERROR,
} nat46_out2in_error_t;

static char *nat46_out2in_error_strings[] = {
#define _(sym,string) string,
    foreach_nat46_out2in_error
#undef _
};

typedef enum
{
    NAT46_OUT2IN_NEXT_IP6_LOOKUP,
    NAT46_OUT2IN_NEXT_IP4_LOOKUP,
    NAT46_OUT2IN_NEXT_DROP,
    NAT46_OUT2IN_NEXT_REASS,
    NAT46_OUT2IN_N_NEXT,
} nat46_out2in_next_t;

typedef struct nat46_out2in_set_ctx_t_
{
    vlib_buffer_t *b;
    vlib_main_t *vm;
    u32 thread_index;
} nat46_out2in_set_ctx_t;

static int
nat46_out2in_tcp_udp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
    nat46_main_t *nm = &nat46_main;
    nat46_out2in_set_ctx_t *ctx = arg;
    nat46_db_bib_entry_t *bibe;
    nat46_db_st_entry_t *ste;
    ip46_address_t saddr, daddr;
    ip4_address_t ip4_saddr;
    udp_header_t *udp = ip6_next_header (ip6);
    tcp_header_t *tcp = ip6_next_header (ip6);
    u8 proto = ip6->protocol;
    u16 dport = udp->dst_port;
    u16 sport = udp->src_port;
    u32 sw_if_index, fib_index;
    u16 *checksum;
    ip_csum_t csum;
    nat46_db_t *db = &nm->db[ctx->thread_index];

    sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
    fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

    saddr.ip6.as_u64[0] = ip6->src_address.as_u64[0];
    saddr.ip6.as_u64[1] = ip6->src_address.as_u64[1];
    daddr.ip6.as_u64[0] = ip6->dst_address.as_u64[0];
    daddr.ip6.as_u64[1] = ip6->dst_address.as_u64[1];

    ste = nat46_db_st_entry_find (db, &daddr, &saddr, dport, sport, proto, fib_index, 1);
    if (ste)
    {
        bibe = nat46_db_bib_entry_by_index (db, proto, ste->bibe_index);
        if (!bibe)
            return -1;
    }
    else
    {
        bibe = nat46_db_bib_entry_find (db, &daddr, dport, proto, fib_index, 1);

        if (!bibe)
            return -1;

        if(nat46_db_remote_mapping_find_and_map64(fib_index, &ip6->src_address, &ip4_saddr, proto))
            return -1;

        ste = nat46_db_st_entry_create (ctx->thread_index, db, bibe, &ip4_saddr, &saddr.ip6, sport);

        if (!ste)
            return -1;

        vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0, db->st.st_entries_num);
    }

    ip4->src_address.as_u32 = ste->in_r_addr.as_u32;
    ip4->dst_address.as_u32 = bibe->in_addr.as_u32;
    udp->dst_port = bibe->in_port;

    if (proto == IP_PROTOCOL_UDP)
        checksum = &udp->checksum;
    else
    {
        checksum = &tcp->checksum;
        nat46_tcp_session_set_state (ste, tcp, 1);
    }

    csum = ip_csum_sub_even (*checksum, dport);
    csum = ip_csum_add_even (csum, udp->dst_port);
    *checksum = ip_csum_fold (csum);

    vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

    nat46_session_reset_timeout (ste, ctx->vm);

    return 0;
}

static int
nat46_out2in_icmp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
    nat46_main_t *nm = &nat46_main;
    nat46_out2in_set_ctx_t *ctx = arg;
    nat46_db_bib_entry_t *bibe;
    nat46_db_st_entry_t *ste;
    ip46_address_t saddr, daddr;
    ip4_address_t ip4_saddr;
    u32 sw_if_index, fib_index;
    icmp46_header_t *icmp = (icmp46_header_t *)(ip4 + 1);
    nat46_db_t *db = &nm->db[ctx->thread_index];

    sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
    fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

    saddr.ip6.as_u64[0] = ip6->src_address.as_u64[0];
    saddr.ip6.as_u64[1] = ip6->src_address.as_u64[1];
    daddr.ip6.as_u64[0] = ip6->dst_address.as_u64[0];
    daddr.ip6.as_u64[1] = ip6->dst_address.as_u64[1];

    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
    {
        u16 out_id = ((u16 *) (icmp))[2];
        ste = nat46_db_st_entry_find (db, &daddr, &saddr, out_id, 0, IP_PROTOCOL_ICMP, fib_index, 1);

        if (ste)
        {
            bibe = nat46_db_bib_entry_by_index (db, IP_PROTOCOL_ICMP, ste->bibe_index);
            if (!bibe)
                return -1;
        }
        else
        {
            bibe = nat46_db_bib_entry_find (db, &daddr, out_id, IP_PROTOCOL_ICMP, fib_index, 1);
            if (!bibe)
                return -1;

            if(nat46_db_remote_mapping_find_and_map64(fib_index, &ip6->src_address, &ip4_saddr, IP_PROTOCOL_ICMP))
                return -1;

            ste = nat46_db_st_entry_create (ctx->thread_index, db, bibe, &ip4_saddr, &saddr.ip6, 0);

            if (!ste)
                return -1;

            vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0,
                    db->st.st_entries_num);
        }

        nat46_session_reset_timeout (ste, ctx->vm);

        ip4->src_address.as_u32 = ste->in_r_addr.as_u32;
        ip4->dst_address.as_u32 = bibe->in_addr.as_u32;
        ((u16 *) (icmp))[2] = bibe->in_port;

        vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }
    else
    {
        ip4_header_t *inner_ip4 = (ip4_header_t *) u8_ptr_add (icmp, 8);
        if(nat46_db_remote_mapping_find_and_map64(fib_index, &ip6->src_address, &ip4_saddr, IP_PROTOCOL_ICMP))
            return -1;
        ip4->src_address.as_u32 = ip4_saddr.as_u32;
        ip4->dst_address.as_u32 = inner_ip4->src_address.as_u32;
    }
  return 0;
}

static int
nat46_out2in_inner_icmp_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
    nat46_main_t *nm = &nat46_main;
    nat46_out2in_set_ctx_t *ctx = arg;
    nat46_db_bib_entry_t *bibe;
    nat46_db_st_entry_t *ste;
    ip46_address_t saddr, daddr;
    u32 sw_if_index, fib_index;
    u8 proto = ip6->protocol;
    nat46_db_t *db = &nm->db[ctx->thread_index];

    sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
    fib_index = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

    clib_memset (&saddr, 0, sizeof (saddr));
    saddr.ip6.as_u64[0] = ip6->src_address.as_u64[0];
    saddr.ip6.as_u64[1] = ip6->src_address.as_u64[1];
    clib_memset (&daddr, 0, sizeof (daddr));
    daddr.ip6.as_u64[0] = ip6->dst_address.as_u64[0];
    daddr.ip6.as_u64[1] = ip6->dst_address.as_u64[1];

    if (proto == IP_PROTOCOL_ICMP6)
    {
        icmp46_header_t *icmp = ip6_next_header (ip6);
        u16 out_id = ((u16 *) (icmp))[2];
        proto = IP_PROTOCOL_ICMP;

        if (!(icmp->type == ICMP6_echo_request || icmp->type == ICMP6_echo_reply))
            return -1;

        ste = nat46_db_st_entry_find (db, &saddr, &daddr, out_id, 0, proto, fib_index, 1);
        if (!ste)
            return -1;

        bibe = nat46_db_bib_entry_by_index (db, proto, ste->bibe_index);
        if (!bibe)
            return -1;

        ip4->dst_address.as_u32 = ste->in_r_addr.as_u32;
        ip4->src_address.as_u32 = bibe->in_addr.as_u32;
        ((u16 *) (icmp))[2] = bibe->in_port;

        vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }
    else
    {
        udp_header_t *udp = ip6_next_header (ip6);
        tcp_header_t *tcp = ip6_next_header (ip6);
        u16 dport = udp->dst_port;
        u16 sport = udp->src_port;
        u16 *checksum;
        ip_csum_t csum;

        ste = nat46_db_st_entry_find (db, &saddr, &daddr, sport, dport, proto, fib_index, 1);
        if (!ste)
            return -1;

        bibe = nat46_db_bib_entry_by_index (db, proto, ste->bibe_index);
        if (!bibe)
            return -1;

        if(nat46_db_remote_mapping_find_and_map64(fib_index, &daddr.ip6, &ip4->dst_address, proto))
            return -1;

        ip4->src_address.as_u32 = bibe->in_addr.as_u32;
        udp->src_port = bibe->in_port;

        if (proto == IP_PROTOCOL_UDP)
            checksum = &udp->checksum;
        else
            checksum = &tcp->checksum;
        if (*checksum)
        {
            csum = ip_csum_sub_even (*checksum, sport);
            csum = ip_csum_add_even (csum, udp->src_port);
            *checksum = ip_csum_fold (csum);
        }
        vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;
    }

    return 0;
}

static int
nat46_out2in_unk_proto_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
    nat46_main_t *nm = &nat46_main;
    nat46_out2in_set_ctx_t *ctx = arg;
    nat46_db_bib_entry_t *bibe;
    nat46_db_st_entry_t *ste;
    ip46_address_t saddr, daddr;
    ip4_address_t ip4_saddr;
    u32 sw_if_index, fib_index;
    u8 proto = ip6->protocol;
    nat46_db_t *db = &nm->db[ctx->thread_index];

    sw_if_index = vnet_buffer (ctx->b)->sw_if_index[VLIB_RX];
    fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

    clib_memset (&saddr, 0, sizeof (saddr));
    saddr.ip6.as_u64[0] = ip6->src_address.as_u64[0];
    saddr.ip6.as_u64[1] = ip6->src_address.as_u64[1];
    clib_memset (&daddr, 0, sizeof (daddr));
    saddr.ip6.as_u64[0] = ip6->dst_address.as_u64[0];
    saddr.ip6.as_u64[1] = ip6->dst_address.as_u64[1];

    ste = nat46_db_st_entry_find (db, &daddr, &saddr, 0, 0, proto, fib_index, 1);
    if (ste)
    {
        bibe = nat46_db_bib_entry_by_index (db, proto, ste->bibe_index);
        if (!bibe)
            return -1;
    }
    else
    {
        bibe = nat46_db_bib_entry_find (db, &daddr, 0, proto, fib_index, 1);

        if (!bibe)
            return -1;

        if(nat46_db_remote_mapping_find_and_map64(fib_index, &ip6->src_address, &ip4_saddr, proto))
            return -1;

        ste = nat46_db_st_entry_create (ctx->thread_index, db, bibe, &ip4_saddr, &saddr.ip6, 0);

        if (!ste)
            return -1;

        vlib_set_simple_counter (&nm->total_sessions, ctx->thread_index, 0, db->st.st_entries_num);
    }

    nat46_session_reset_timeout (ste, ctx->vm);

    ip4->src_address.as_u32 = ste->in_r_addr.as_u32;
    ip4->dst_address.as_u32 = bibe->in_addr.as_u32;

    vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

    return 0;
}

VLIB_NODE_FN (nat46_out2in_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    nat46_out2in_next_t next_index;
    nat46_main_t *nm = &nat46_main;
    u32 pkts_processed = 0;
    u32 thread_index = vm->thread_index;
    u32 tcp_packets = 0, udp_packets = 0, icmp_packets = 0, other_packets = 0, fragments = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;
    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0;
            ip6_header_t *ip60;
            u32 proto0;
            nat46_out2in_set_ctx_t ctx0;
            udp_header_t *udp0;
            u32 sw_if_index0;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            ip60 = vlib_buffer_get_current (b0);

            ctx0.b = b0;
            ctx0.vm = vm;
            ctx0.thread_index = thread_index;

            next0 = NAT46_OUT2IN_NEXT_IP4_LOOKUP;

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            if (nat46_out2in_not_translate (sw_if_index0, ip60->dst_address))
            {
                next0 = NAT46_OUT2IN_NEXT_IP6_LOOKUP;
                goto trace0;
            }

            if (PREDICT_FALSE (ip60->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION))
            {
                next0 = NAT46_OUT2IN_NEXT_REASS;
                fragments++;
                goto trace0;
            }

            proto0 = ip_proto_to_snat_proto (ip60->protocol);

            if (PREDICT_FALSE (proto0 == ~0))
            {
                if (ip6_to_ip4 (b0, nat46_out2in_unk_proto_set_cb, &ctx0))
                {
                    next0 = NAT46_OUT2IN_NEXT_DROP;
                    b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                }
                other_packets++;
                goto trace0;
            }

            if (proto0 == SNAT_PROTOCOL_ICMP)
            {
                icmp_packets++;
                if (icmp6_to_icmp (b0, 
                         nat46_out2in_icmp_set_cb, &ctx0,
                         nat46_out2in_inner_icmp_set_cb, &ctx0))
                {
                    next0 = NAT46_OUT2IN_NEXT_IP6_LOOKUP;
                    b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                    goto trace0;
                }
            }
            else
            {
                if (proto0 == SNAT_PROTOCOL_TCP)
                    tcp_packets++;
                else
                    udp_packets++;

                if (ip6_to_ip4_tcp_udp (b0, nat46_out2in_tcp_udp_set_cb, &ctx0, 0))
                {
                    udp0 = ip6_next_header (ip60);
                    /*
                     * Send DHCP packets to the ipv6 stack, or we won't
                     * be able to use dhcp client on the outside interface
                     */
                    if ((proto0 == SNAT_PROTOCOL_UDP) && 
                        (udp0->dst_port == clib_host_to_net_u16 (UDP_DST_PORT_dhcp_to_client)))
                    {
                        next0 = NAT46_OUT2IN_NEXT_IP6_LOOKUP;
                        goto trace0;
                    }
                    next0 = NAT46_OUT2IN_NEXT_DROP;
                    b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                    goto trace0;
                }
            }

trace0:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                nat46_out2in_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
                t->next_index = next0;
            }

            pkts_processed += next0 == NAT46_OUT2IN_NEXT_IP4_LOOKUP;

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
                    n_left_to_next, bi0, next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_OUT2IN_PACKETS, pkts_processed);
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_TCP_PACKETS, tcp_packets);
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_UDP_PACKETS, udp_packets);
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_ICMP_PACKETS, icmp_packets);
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_OTHER_PACKETS, other_packets);
    vlib_node_increment_counter (vm, nm->out2in_node_index,
            NAT46_OUT2IN_ERROR_FRAGMENTS, fragments);

    return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_out2in_node) = {
    .name = "nat46-out2in",
    .vector_size = sizeof (u32),
    .format_trace = format_nat46_out2in_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (nat46_out2in_error_strings),
    .error_strings = nat46_out2in_error_strings,
    .n_next_nodes = NAT46_OUT2IN_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes = {
        [NAT46_OUT2IN_NEXT_DROP] = "error-drop",
        [NAT46_OUT2IN_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [NAT46_OUT2IN_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [NAT46_OUT2IN_NEXT_REASS] = "nat46-out2in-reass",
    },
};
/* *INDENT-ON* */

typedef struct nat46_out2in_frag_set_ctx_t_
{
    vlib_main_t *vm;
    vlib_buffer_t *b;
    u32 sess_index;
    u32 thread_index;
    u16 l4_offset;
    u16 payload_length;
    u8 proto;
    u8 first_frag;
} nat46_out2in_frag_set_ctx_t;

static int
nat46_out2in_frag_set_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
    nat46_main_t *nm = &nat46_main;
    nat46_out2in_frag_set_ctx_t *ctx = arg;
    nat46_db_st_entry_t *ste;
    nat46_db_bib_entry_t *bibe;
    udp_header_t *udp;
    ip_csum_t csum;
    u16 *checksum;
    nat46_db_t *db = &nm->db[ctx->thread_index];

    ste = nat46_db_st_entry_by_index (db, ctx->proto, ctx->sess_index);
    if (!ste)
        return -1;

    bibe = nat46_db_bib_entry_by_index (db, ctx->proto, ste->bibe_index);
    if (!bibe)
        return -1;

    if (ctx->first_frag)
    {
        udp = (udp_header_t *) u8_ptr_add (ip6, ctx->l4_offset);

        udp->dst_port = bibe->in_port;

        if (ctx->proto == IP_PROTOCOL_UDP)
        {
            checksum = &udp->checksum;

            //ipv6 udp checksum must fill
            if (!checksum)
                return -1;
            else
            {
                csum = ip_csum_sub_even (*checksum, bibe->out_addr.as_u64[0]);
                csum = ip_csum_sub_even (csum, bibe->out_addr.as_u64[1]);
                csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u64[0]);
                csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u64[1]);
                csum = ip_csum_sub_even (csum, bibe->out_port);
                csum = ip_csum_add_even (csum, ste->in_r_addr.as_u32);
                csum = ip_csum_add_even (csum, bibe->in_addr.as_u32);
                csum = ip_csum_add_even (csum, bibe->in_port);
                *checksum = ip_csum_fold (csum);
            }
        }
        else
        {
            tcp_header_t *tcp = (tcp_header_t *) udp;
            nat46_tcp_session_set_state (ste, tcp, 1);
            checksum = &tcp->checksum;
            csum = ip_csum_sub_even (*checksum, bibe->out_addr.as_u64[0]);
            csum = ip_csum_sub_even (csum, bibe->out_addr.as_u64[1]);
            csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u64[0]);
            csum = ip_csum_sub_even (csum, ste->out_r_addr.as_u64[1]);
            csum = ip_csum_sub_even (csum, bibe->out_port);
            csum = ip_csum_add_even (csum, ste->in_r_addr.as_u32);
            csum = ip_csum_add_even (csum, bibe->in_addr.as_u32);
            csum = ip_csum_add_even (csum, bibe->in_port);
            *checksum = ip_csum_fold (csum);
        }
    }

    ip4->src_address.as_u32 = ste->in_r_addr.as_u32;
    ip4->dst_address.as_u32 = bibe->in_addr.as_u32;

    vnet_buffer (ctx->b)->sw_if_index[VLIB_TX] = bibe->fib_index;

    nat46_session_reset_timeout (ste, ctx->vm);

    return 0;
}

VLIB_NODE_FN (nat46_out2in_reass_node) (vlib_main_t * vm,
					vlib_node_runtime_t * node,
					vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    nat46_out2in_next_t next_index;
    u32 pkts_processed = 0, cached_fragments = 0;
    u32 *fragments_to_drop = 0;
    u32 *fragments_to_loopback = 0;
    nat46_main_t *nm = &nat46_main;
    u32 thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
        u32 n_left_to_next;

        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 bi0;
            vlib_buffer_t *b0;
            u32 next0;
            u8 cached0 = 0;
            u32 sw_if_index0, fib_index0;
            nat46_db_st_entry_t *ste0;
            nat46_db_bib_entry_t *bibe0;
            nat46_out2in_frag_set_ctx_t ctx0;
            nat46_db_t *db = &nm->db[thread_index];

            ip46_address_t saddr0, daddr0;
            ip4_address_t ip4_saddr0;

            ip6_header_t *ip60;
            ip6_frag_hdr_t *frag0;
            u16 l4_offset0, frag_offset0;
            u8 l4_protocol0;

            udp_header_t *udp0;

            nat_reass_ip6_t *reass0;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            next0 = NAT46_OUT2IN_NEXT_IP4_LOOKUP;

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
            fib_index0 = fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index0);

            ctx0.thread_index = thread_index;

            if (PREDICT_FALSE (nat_reass_is_drop_frag (1)))
            {
                next0 = NAT46_OUT2IN_NEXT_DROP;
                b0->error = node->errors[NAT46_OUT2IN_ERROR_DROP_FRAGMENT];
                goto trace0;
            }

            ip60 = vlib_buffer_get_current (b0);

            if (PREDICT_FALSE (ip6_parse(ip60, b0->current_length, &l4_protocol0, &l4_offset0,
                      &frag_offset0)))
            {
                next0 = NAT46_OUT2IN_NEXT_DROP;
                b0->error = node->errors[NAT46_OUT2IN_ERROR_UNKNOWN];
                goto trace0;
            }

            if (PREDICT_FALSE (!(l4_protocol0 == IP_PROTOCOL_TCP || l4_protocol0 == IP_PROTOCOL_UDP)))
            {
                next0 = NAT46_OUT2IN_NEXT_DROP;
                b0->error = node->errors[NAT46_OUT2IN_ERROR_DROP_FRAGMENT];
                goto trace0;
            }

            udp0 = (udp_header_t *) u8_ptr_add (ip60, l4_offset0);
            frag0 = (ip6_frag_hdr_t *) u8_ptr_add (ip60, frag_offset0);

            reass0 = nat_ip6_reass_find_or_create (ip60->src_address,
                    ip60->dst_address,
                    frag0->identification,
                    l4_protocol0,
                    1, &fragments_to_drop);

            if (PREDICT_FALSE (!reass0))
            {
                next0 = NAT46_OUT2IN_NEXT_DROP;
                b0->error = node->errors[NAT46_OUT2IN_ERROR_MAX_REASS];
                goto trace0;
            }

            if (PREDICT_TRUE (ip6_frag_hdr_offset (frag0)))
            {
                ctx0.first_frag = 0;

                if (PREDICT_FALSE (reass0->sess_index == (u32) ~ 0))
                {
                    if (nat_ip6_reass_add_fragment
                            (thread_index, reass0, bi0, &fragments_to_drop))
                    {
                        b0->error = node->errors[NAT46_OUT2IN_ERROR_MAX_FRAG];
                        next0 = NAT46_OUT2IN_NEXT_DROP;
                        goto trace0;
                    }
                    cached0 = 1;
                    goto trace0;
                }
            }
            else
            {
                ctx0.first_frag = 1;

                saddr0.as_u64[0] = ip60->src_address.as_u64[0];
                saddr0.as_u64[1] = ip60->src_address.as_u64[1];
                daddr0.as_u64[0] = ip60->dst_address.as_u64[0];
                daddr0.as_u64[1] = ip60->dst_address.as_u64[1];

                ste0 = nat46_db_st_entry_find (db, 
                            &daddr0, &saddr0, 
                            udp0->dst_port, udp0->src_port,
                            l4_protocol0, fib_index0, 1);
                if (!ste0)
                {
                    bibe0 = nat46_db_bib_entry_find (db, &daddr0, udp0->dst_port, l4_protocol0, fib_index0, 1);
                    if (!bibe0)
                    {
                        next0 = NAT46_OUT2IN_NEXT_DROP;
                        b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                        goto trace0;
                    }


                    if(nat46_db_remote_mapping_find_and_map64(fib_index0, &ip60->src_address, &ip4_saddr0, ip60->protocol))
                    {
                        next0 = NAT46_OUT2IN_NEXT_DROP;
                        b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                        goto trace0;
                    }

                    ste0 = nat46_db_st_entry_create (thread_index, db, bibe0, &ip4_saddr0, &saddr0.ip6, udp0->src_port);

                    if (!ste0)
                    {
                        next0 = NAT46_OUT2IN_NEXT_DROP;
                        b0->error = node->errors[NAT46_OUT2IN_ERROR_NO_TRANSLATION];
                        goto trace0;
                    }

                    vlib_set_simple_counter (&nm->total_sessions, thread_index, 0, db->st.st_entries_num);
                }
                reass0->sess_index = nat46_db_st_entry_get_index (db, ste0);
                reass0->thread_index = thread_index;

                nat_ip6_reass_get_frags (reass0, &fragments_to_loopback);
            }

            ctx0.sess_index = reass0->sess_index;
            ctx0.proto = l4_protocol0;
            ctx0.vm = vm;
            ctx0.b = b0;
            ctx0.l4_offset = l4_offset0;
            ctx0.payload_length = ip60->payload_length;

            if (ip6_to_ip4_fragmented (b0, nat46_out2in_frag_set_cb, &ctx0))
            {
                next0 = NAT46_OUT2IN_NEXT_DROP;
                b0->error = node->errors[NAT46_OUT2IN_ERROR_UNKNOWN];
                goto trace0;
            }

trace0:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                nat46_out2in_reass_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
                t->cached = cached0;
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
            }

            if (cached0)
            {
                n_left_to_next++;
                to_next--;
                cached_fragments++;
            }
            else
            {
                pkts_processed += next0 != NAT46_OUT2IN_NEXT_DROP;

                /* verify speculative enqueue, maybe switch current next frame */
                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                        to_next, n_left_to_next,
                        bi0, next0);
            }

            if (n_left_from == 0 && vec_len (fragments_to_loopback))
            {
                from = vlib_frame_vector_args (frame);
                u32 len = vec_len (fragments_to_loopback);
                if (len <= VLIB_FRAME_SIZE)
                {
                    clib_memcpy_fast (from, fragments_to_loopback, sizeof (u32) * len);
                    n_left_from = len;
                    vec_reset_length (fragments_to_loopback);
                }
                else
                {
                    clib_memcpy_fast (from, fragments_to_loopback + (len - VLIB_FRAME_SIZE), sizeof (u32) * VLIB_FRAME_SIZE);
                    n_left_from = VLIB_FRAME_SIZE;
                    _vec_len (fragments_to_loopback) = len - VLIB_FRAME_SIZE;
                }
            }
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, nm->out2in_reass_node_index,
            NAT46_OUT2IN_ERROR_PROCESSED_FRAGMENTS, pkts_processed);
    vlib_node_increment_counter (vm, nm->out2in_reass_node_index,
            NAT46_OUT2IN_ERROR_CACHED_FRAGMENTS, cached_fragments);

    nat_send_all_to_node (vm, fragments_to_drop, node,
            &node->errors[NAT46_OUT2IN_ERROR_DROP_FRAGMENT],
            NAT46_OUT2IN_NEXT_DROP);

    vec_free (fragments_to_drop);
    vec_free (fragments_to_loopback);
    return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_out2in_reass_node) = {
    .name = "nat46-out2in-reass",
    .vector_size = sizeof (u32),
    .format_trace = format_nat46_out2in_reass_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN (nat46_out2in_error_strings),
    .error_strings = nat46_out2in_error_strings,
    .n_next_nodes = NAT46_OUT2IN_N_NEXT,
    /* edit / add dispositions here */
    .next_nodes = {
        [NAT46_OUT2IN_NEXT_DROP] = "error-drop",
        [NAT46_OUT2IN_NEXT_IP6_LOOKUP] = "ip6-lookup",
        [NAT46_OUT2IN_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [NAT46_OUT2IN_NEXT_REASS] = "nat46-out2in-reass",
    },
};
/* *INDENT-ON* */

#define foreach_nat46_out2in_handoff_error                       \
_(CONGESTION_DROP, "congestion drop")                            \
_(SAME_WORKER, "same worker")                                    \
_(DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym,str) NAT46_OUT2IN_HANDOFF_ERROR_##sym,
    foreach_nat46_out2in_handoff_error
#undef _
        NAT46_OUT2IN_HANDOFF_N_ERROR,
} nat46_out2in_handoff_error_t;

static char *nat46_out2in_handoff_error_strings[] = {
#define _(sym,string) string,
    foreach_nat46_out2in_handoff_error
#undef _
};

typedef struct
{
    u32 next_worker_index;
} nat46_out2in_handoff_trace_t;

static u8 *
format_nat46_out2in_handoff_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    nat46_out2in_handoff_trace_t *t = va_arg (*args, nat46_out2in_handoff_trace_t *);

    s =
        format (s, "NAT46-OUT2IN-HANDOFF: next-worker %d", t->next_worker_index);

    return s;
}

VLIB_NODE_FN (nat46_out2in_handoff_node) (vlib_main_t * vm,
					  vlib_node_runtime_t * node,
					  vlib_frame_t * frame)
{
    nat46_main_t *nm = &nat46_main;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u32 n_enq, n_left_from, *from;
    u16 thread_indices[VLIB_FRAME_SIZE], *ti;
    u32 fq_index;
    u32 thread_index = vm->thread_index;
    u32 do_handoff = 0, same_worker = 0;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    vlib_get_buffers (vm, from, bufs, n_left_from);

    b = bufs;
    ti = thread_indices;

    fq_index = nm->fq_out2in_index;

    while (n_left_from > 0)
    {
        ip6_header_t *ip0;
        u32 sw_if_index, fib_index;

        ip0 = vlib_buffer_get_current (b[0]);

        sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
        fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);
        ti[0] = nat46_get_worker_out2in (ip0, fib_index);

        if (ti[0] != thread_index)
            do_handoff++;
        else
            same_worker++;

        if (PREDICT_FALSE
                ((node->flags & VLIB_NODE_FLAG_TRACE)
                 && (b[0]->flags & VLIB_BUFFER_IS_TRACED)))
        {
            nat46_out2in_handoff_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
            t->next_worker_index = ti[0];
        }

        n_left_from -= 1;
        ti += 1;
        b += 1;
    }

    n_enq =
        vlib_buffer_enqueue_to_thread (vm, fq_index, from, thread_indices,
                frame->n_vectors, 1);

    if (n_enq < frame->n_vectors)
        vlib_node_increment_counter (vm, node->node_index, NAT46_OUT2IN_HANDOFF_ERROR_CONGESTION_DROP, frame->n_vectors - n_enq);
    vlib_node_increment_counter (vm, node->node_index, NAT46_OUT2IN_HANDOFF_ERROR_SAME_WORKER, same_worker);
    vlib_node_increment_counter (vm, node->node_index, NAT46_OUT2IN_HANDOFF_ERROR_DO_HANDOFF, do_handoff);

    return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_out2in_handoff_node) = {
    .name = "nat46-out2in-handoff",
    .vector_size = sizeof (u32),
    .format_trace = format_nat46_out2in_handoff_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
    .n_errors = ARRAY_LEN(nat46_out2in_handoff_error_strings),
    .error_strings = nat46_out2in_handoff_error_strings,

    .n_next_nodes = 1,

    .next_nodes = {
        [0] = "error-drop",
    },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
