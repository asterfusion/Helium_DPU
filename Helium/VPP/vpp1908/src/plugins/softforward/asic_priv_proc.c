#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <softforward/asic_priv.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#define foreach_asic_private_error                       \
    _(NOT_ASIC_PRIVATE_PACKET, "not has asic private header")      \
    _(ENPCAP_ASIC_PRIVATE_PACKET, "encap asic private header")      \
    _(DEPCAP_ASIC_PRIVATE_PACKET, "decap asic private header")

typedef enum
{
#define _(sym,str) ASIC_PRIVATE_ERROR_##sym,
    foreach_asic_private_error
#undef _
    ASIC_PRIVATE_N_ERROR,
} asic_private_error_t;

static char *asic_private_error_strings[] = {
#define _(sym,string) string,
    foreach_asic_private_error
#undef _
};

typedef enum
{
    ASIC_PRIVATE_NEXT_DROP,
    ASIC_PRIVATE_NEXT_ETHERNET_INPUT,
    ASIC_PRIVATE_N_NEXT,
} asic_private_next_t;

typedef struct
{
    u32 sw_if_index;
    u32 next_index;
    u16 asic_ether_type;
    u16 raw_ether_type;
    u16 ghc_ingress_port;
    u16 ghc_ingress_vrf;
    u16 ghc_ingress_rmac_group;

} asic_private_trace_t;

/* packet trace format function */
static u8 *
format_asic_private_node_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    asic_private_trace_t *t = va_arg (*args, asic_private_trace_t *);

    s = format (s, "asic private: sw_if_index %d, next index %d, \
                    asic_ether_type %x ether_type %x  \
                    ingress_port %d ingress_vrf %x ingress_rmac_group %d", 
            t->sw_if_index, t->next_index, t->asic_ether_type, t->raw_ether_type, 
            t->ghc_ingress_port, t->ghc_ingress_vrf, t->ghc_ingress_rmac_group);

    return s;
}

/* *INDENT-ON* */
VLIB_NODE_FN (pre_asic_private_node) (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    asic_private_next_t next_index;
    asic_private_main_t *apm = &ap_main;
    vnet_main_t *vnm = vnet_get_main ();

    u32 depcap_asic_private_packet = 0;
    u32 not_asic_private_packet = 0;
    u32 stats_node_index;

    stats_node_index = apm->pre_asic_private_node;

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
            ethernet_asic_header_t *eah0;
            u32 *opaque0;
            asic_private_opaque2_t *ap_opaque0;

            vnet_hw_interface_t *hi0 = NULL;

            u16 asic_ether_type0 = 0;

            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);
            next0 = ASIC_PRIVATE_NEXT_ETHERNET_INPUT;

            eah0 = vlib_buffer_get_current (b0);

            sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

            hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

            asic_ether_type0 = eah0->eth.type;

            //record
            opaque0 = asic_private_buffer_opaque2(b0);
            ap_opaque0 = (asic_private_opaque2_t *)opaque0;

            clib_memcpy(ap_opaque0->dst_address, eah0->eth.dst_address, 6);
            ap_opaque0->ether_type = eah0->ghc.ether_type;

            ap_opaque0->ingress_port = eah0->ghc.ingress_port;
            ap_opaque0->ingress_vrf = eah0->ghc.ingress_vrf;
            ap_opaque0->ingress_rmac_group = eah0->ghc.ingress_rmac_group;

            //check eth_type 
            if(eah0->eth.type != ASIC_PRIVATE_ETHER_TYPE)
            {
                not_asic_private_packet++;
                next0 = ASIC_PRIVATE_NEXT_DROP;
                goto trace0;
            }

            //decap private
            eah0->eth.type = eah0->ghc.ether_type;
            clib_memcpy(eah0->eth.dst_address, hi0->hw_address, 6);

            /* because ethernet_header_t size == ghc_header_t size so.. */
            //clib_memcpy(&eah0->eth, &eah0->ghc, sizeof(ghc_header_t)); //Simple
            memmove((u8 *)(eah0+1) - sizeof(ethernet_header_t), &eah0->eth, sizeof(ethernet_header_t));  //More specific compatibility

            vlib_buffer_advance(b0, sizeof(ghc_header_t));

            depcap_asic_private_packet++;

trace0:
            if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
                        && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
                asic_private_trace_t *t =
                    vlib_add_trace (vm, node, b0, sizeof (*t));
                t->sw_if_index = sw_if_index0;
                t->next_index = next0;
                t->asic_ether_type = asic_ether_type0;
                t->raw_ether_type = ap_opaque0->ether_type;
                t->ghc_ingress_port = ap_opaque0->ingress_port;
                t->ghc_ingress_vrf = ap_opaque0->ingress_vrf;
                t->ghc_ingress_rmac_group = ap_opaque0->ingress_rmac_group;
            }

            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                    to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, stats_node_index, ASIC_PRIVATE_ERROR_DEPCAP_ASIC_PRIVATE_PACKET, depcap_asic_private_packet);
    vlib_node_increment_counter (vm, stats_node_index, ASIC_PRIVATE_ERROR_NOT_ASIC_PRIVATE_PACKET, not_asic_private_packet);
    return frame->n_vectors;
}

VLIB_NODE_FN (post_asic_private_node) (vlib_main_t * vm,
        vlib_node_runtime_t * node,
        vlib_frame_t * frame)
{
    u32 n_left_from, *from, *to_next;
    asic_private_next_t next_index;
    asic_private_main_t *apm = &ap_main;
    u32 enpcap_asic_private_packet = 0;
    u32 stats_node_index;

    stats_node_index = apm->pre_asic_private_node;

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
            ethernet_asic_header_t *eah0;
            u32 *opaque0;
            asic_private_opaque2_t *ap_opaque0;
            /* speculatively enqueue b0 to the current next frame */
            bi0 = from[0];
            to_next[0] = bi0;
            from += 1;
            to_next += 1;
            n_left_from -= 1;
            n_left_to_next -= 1;

            b0 = vlib_get_buffer (vm, bi0);

            vnet_feature_next(&next0, b0);

            eah0 = vlib_buffer_get_current (b0);
            opaque0 = asic_private_buffer_opaque2(b0);
            ap_opaque0 = (asic_private_opaque2_t *)opaque0;

            //decap private
            clib_memcpy(eah0->eth.dst_address, ap_opaque0->dst_address, 6);
            eah0->eth.type = ASIC_PRIVATE_ETHER_TYPE;

            eah0->ghc.ether_type = ap_opaque0->ether_type;
            eah0->ghc.ingress_port = ap_opaque0->ingress_port;
            eah0->ghc.ingress_vrf = ap_opaque0->ingress_vrf;
            eah0->ghc.ingress_rmac_group = ap_opaque0->ingress_rmac_group;

            enpcap_asic_private_packet++;
            /* verify speculative enqueue, maybe switch current next frame */
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                    to_next, n_left_to_next, bi0, next0);
        }

        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    vlib_node_increment_counter (vm, stats_node_index, ASIC_PRIVATE_ERROR_ENPCAP_ASIC_PRIVATE_PACKET, enpcap_asic_private_packet);
    return frame->n_vectors;
}


/* *INDENT-OFF* */
VLIB_REGISTER_NODE (pre_asic_private_node) = {
    .name = "pre-asic-private",
    .vector_size = sizeof (u32),
    .format_trace = format_asic_private_node_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(asic_private_error_strings),
    .error_strings = asic_private_error_strings,

    .n_next_nodes = ASIC_PRIVATE_N_NEXT,

    /* edit / add dispositions here */
    .next_nodes = {
        [ASIC_PRIVATE_NEXT_DROP] = "error-drop",
        [ASIC_PRIVATE_NEXT_ETHERNET_INPUT] = "ethernet-input",
    },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (post_asic_private_node) = {
    .name = "post-asic-private",
    .vector_size = sizeof (u32),
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = ARRAY_LEN(asic_private_error_strings),
    .error_strings = asic_private_error_strings,

    .n_next_nodes = 0,

    /* edit / add dispositions here */
    .next_nodes = {
        [0] = "error-drop",
    },
};
/* *INDENT-ON* */
