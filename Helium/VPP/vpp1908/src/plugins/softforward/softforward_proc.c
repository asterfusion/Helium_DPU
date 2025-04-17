#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <softforward/softforward.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

typedef struct
{
    u32 sw_if_index;
    u32 next_index;
    ip4_address_t dst_ip;
    u8 is_match;
} softforward_trace_t;

/* packet trace format function */
static u8 *
format_softforward_node_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    softforward_trace_t *t = va_arg (*args, softforward_trace_t *);
    char *tag;

    tag = t->is_match ? "matched" : "not matched";

    s = format (s, "%s: sw_if_index %d, next index %d, dst_ip %U", tag,
            t->sw_if_index, t->next_index, format_ip4_address, &t->dst_ip);

    return s;
}

#define foreach_softforward_error                       \
    _(UNSUPPORTED_PROTOCOL_IPV6, "unsupported IP6 protocol")         \
    _(FIND_MAPPING_PACKET, "match mapping table")      \
    _(NOT_FIND_MAPPING_PACKET, "not match mapping table")

typedef enum
{
#define _(sym,str) SOFTFORWARD_ERROR_##sym,
    foreach_softforward_error
#undef _
    SOFTFORWARD_N_ERROR,
} softforward_error_t;

static char *softforward_error_strings[] = {
#define _(sym,string) string,
    foreach_softforward_error
#undef _
};

typedef enum
{
    SOFTFORWARD_NEXT_DROP,
    SOFTFORWARD_NEXT_LOOKUP,
    SOFTFORWARD_NEXT_OUTPUT,
    SOFTFORWARD_N_NEXT,
} softforward_next_t;


static_always_inline void softforward_modify_ip(
        softforward_map_entry_t *e,
        ip4_header_t *ip)
{
    u32 old_saddr, old_daddr;
    u32 new_saddr, new_daddr;
    ip_csum_t sum;
    udp_header_t *udp;
    tcp_header_t *tcp;

    //Check whether saddr needs to be modified
    if (e->map_saddr.as_u32 != 0)
    {
        old_saddr = ip->src_address.as_u32;
        ip->src_address.as_u32 = e->map_saddr.as_u32;
        new_saddr = ip->src_address.as_u32;
    }
    else
    {
        old_saddr = ip->src_address.as_u32;
        new_saddr = ip->src_address.as_u32;
    }

    old_daddr = ip->dst_address.as_u32;
    ip->dst_address.as_u32 = e->map_daddr.as_u32;
    new_daddr = ip->dst_address.as_u32;

    sum = ip->checksum;
    sum = ip_csum_update (sum, old_saddr, new_saddr,
            ip4_header_t,
            src_address /* changed member */ );
    sum = ip_csum_update (sum, old_daddr, new_daddr,
            ip4_header_t,
            dst_address /* changed member */ );
    ip->checksum = ip_csum_fold (sum);

    /*if protocol is tcp or udp */
    /*now only suuport tcp and udp */
    switch(ip->protocol)
    {
    case IP_PROTOCOL_UDP:
        udp = ip4_next_header (ip);
        if (PREDICT_FALSE (udp->checksum))
        {
            sum = udp->checksum;
            sum = ip_csum_update (sum, old_saddr, new_saddr,
                    ip4_header_t,
                    src_address /* changed member */ );
            sum = ip_csum_update (sum, old_daddr, new_daddr,
                    ip4_header_t,
                    dst_address /* changed member */ );
            udp->checksum = ip_csum_fold (sum);
        }
        break;
    case IP_PROTOCOL_TCP:
        tcp = ip4_next_header (ip);
        sum = tcp->checksum;
        sum = ip_csum_update (sum, old_saddr, new_saddr,
                ip4_header_t,
                src_address /* changed member */ );
        sum = ip_csum_update (sum, old_daddr, new_daddr,
                ip4_header_t,
                dst_address /* changed member */ );
        tcp->checksum = ip_csum_fold (sum);
        break;
    default:
        break;
    }
}

/* *INDENT-ON* */
VLIB_NODE_FN (softforward_node) (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    softforward_next_t next_index;
    u32 find_mapping = 0;
    u32 not_find_mapping = 0;
    softforward_main_t *sf = &sf_main;
    u32 stats_node_index;
    u32 thread_index = vm->thread_index;

    stats_node_index = sf->softforward_node_index;

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
            u32 sw_if_index0;
            ip4_header_t *ip0;
            softforward_mapping_key_t key0;
            softforward_map_entry_t *e0;
            u8  is_match0 = 0;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            next0 = SOFTFORWARD_NEXT_DROP;

            ip0 = vlib_buffer_get_current (b0);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            key0.daddr = ip0->dst_address;
            key0.reserved = 0;

            e0 = softforward_mapping_match (sf, sw_if_index0, &key0, thread_index);
            if(e0 == NULL)
            {
                not_find_mapping++;
                goto trace0;
            }

            softforward_modify_ip(e0, ip0);

#if 0
            next0 = SOFTFORWARD_NEXT_LOOKUP;
#else
            vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index0;
            
            vlib_buffer_reset (b0);

            next0 = SOFTFORWARD_NEXT_OUTPUT;
#endif

trace0:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                softforward_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->dst_ip = ip0->dst_address;
                t->is_match = is_match0;
            }
            find_mapping += next0 != SOFTFORWARD_NEXT_DROP;

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                    to_next, n_left_to_next,
                    bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, stats_node_index, SOFTFORWARD_ERROR_FIND_MAPPING_PACKET, find_mapping);
    vlib_node_increment_counter (vm, stats_node_index, SOFTFORWARD_ERROR_NOT_FIND_MAPPING_PACKET, not_find_mapping);
    return frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (softforward_node) = {
    .name = "softforward",
    .vector_size = sizeof (u32),
    .format_trace = format_softforward_node_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(softforward_error_strings),
    .error_strings = softforward_error_strings,

    .n_next_nodes = SOFTFORWARD_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes = {
        [SOFTFORWARD_NEXT_DROP] = "error-drop",
        [SOFTFORWARD_NEXT_LOOKUP] = "ip4-lookup",
        [SOFTFORWARD_NEXT_OUTPUT] = "interface-output",
    },
};
/* *INDENT-ON* */
