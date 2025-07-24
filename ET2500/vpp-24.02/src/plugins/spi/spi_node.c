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
/**
 * @file
 * @brief SPI session and check node
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/error.h>

#include <spi/spi.h>
#include <spi/spi_inline.h>

static char *spi_node_error_strings[] = {
#define _(sym,string) string,
    foreach_spi_node_error
#undef _
};

static u8 *
format_spi_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    spi_trace_t *t = va_arg (*args, spi_trace_t *);

    s = format (s, "SPI: thread_index %d, in_sw_if_index %d out_sw_if_index, next index %d", 
            t->thread_index, t->in_sw_if_index, t->out_sw_if_index, t->next_index);

    s = format (s, "\n\t skip_spi %d", t->skip_spi);
    s = format (s, "\n\t icmp_o_tcp_flags %d", t->icmp_o_tcp_flags);

    if (~0 != t->session_index)
    {
        s = format (s, "\n\t session %d", t->session_index);
    }
    return s;
}

static_always_inline uword
spi_session_trace_node_fn (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame,
					  int is_output, 
                      int is_ip6)
{
    u32 n_left;
    u32 *from;

    vlib_buffer_t **b;
    u32 *in_sw_if_index;
    u32 *out_sw_if_index;
    spi_pkt_info_t *spi_pkt;
    u64 *hash;
    u16 *nexts;

    spi_main_t *spim = &spi_main;
    spi_runtime_t *rt = (spi_runtime_t *) node->runtime_data;

    n_left = frame->n_vectors;
    from = vlib_frame_vector_args (frame);
    vlib_get_buffers (vm, from, rt->bufs, frame->n_vectors);

    spi_node_common_prepare_fn (vm, rt, n_left, from, is_ip6, is_output);

    b = rt->bufs;
    in_sw_if_index = rt->in_sw_if_indices;
    out_sw_if_index = rt->out_sw_if_indices;
    spi_pkt = rt->pkts;
    hash = rt->hashes;
    nexts = rt->nexts;

    while (n_left > 8)
    {
        spi_trace_t *t0 = NULL, *t1 = NULL, *t2 = NULL, *t3 = NULL;
        u32 arc_next0, arc_next1, arc_next2, arc_next3;

        CLIB_PREFETCH (b[4], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[5], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[6], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[7], CLIB_CACHE_LINE_BYTES * 2, LOAD);

        CLIB_PREFETCH (&spi_pkt[4], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[5], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[6], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[7], CLIB_CACHE_LINE_BYTES, LOAD);

        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[4]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[5]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[6]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[7]);

        vnet_feature_next (&arc_next0, b[0]);
        vnet_feature_next (&arc_next1, b[1]);
        vnet_feature_next (&arc_next2, b[2]);
        vnet_feature_next (&arc_next3, b[3]);
        nexts[0] = arc_next0;
        nexts[1] = arc_next1;
        nexts[2] = arc_next2;
        nexts[3] = arc_next3;

        if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
            t0 = vlib_add_trace (vm, node, b[0], sizeof (spi_trace_t));

        if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
            t1 = vlib_add_trace (vm, node, b[1], sizeof (spi_trace_t));

        if (PREDICT_FALSE (b[2]->flags & VLIB_BUFFER_IS_TRACED))
            t2 = vlib_add_trace (vm, node, b[2], sizeof (spi_trace_t));

        if (PREDICT_FALSE (b[3]->flags & VLIB_BUFFER_IS_TRACED))
            t3 = vlib_add_trace (vm, node, b[3], sizeof (spi_trace_t));

        spi_proc_session_fn(vm, node, rt, b[0], &spi_pkt[0], &nexts[0], 
                         hash[0], in_sw_if_index[0], out_sw_if_index[0], is_output, t0);

        spi_proc_session_fn(vm, node, rt, b[1], &spi_pkt[1], &nexts[1], 
                         hash[1], in_sw_if_index[1], out_sw_if_index[1], is_output, t1);

        spi_proc_session_fn(vm, node, rt, b[2], &spi_pkt[2], &nexts[2], 
                         hash[2], in_sw_if_index[2], out_sw_if_index[2], is_output, t2);

        spi_proc_session_fn(vm, node, rt, b[3], &spi_pkt[3], &nexts[3], 
                         hash[3], in_sw_if_index[3], out_sw_if_index[3], is_output, t3);

        t0 = NULL;
        t1 = NULL;
        t2 = NULL;
        t3 = NULL;
          
        n_left -= 4;
        b += 4;
        in_sw_if_index += 4;
        out_sw_if_index += 4;
        spi_pkt += 4;
        hash += 4;
        nexts += 4;
    }

    while (n_left > 0)
    {
        spi_trace_t *t0 = NULL;

        u32 arc_next0;
        vnet_feature_next (&arc_next0, b[0]);
        nexts[0] = arc_next0;

        if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
            t0 = vlib_add_trace (vm, node, b[0], sizeof (spi_trace_t));

        spi_proc_session_fn(vm, node, rt, b[0], &spi_pkt[0], &nexts[0], 
                         hash[0], in_sw_if_index[0], out_sw_if_index[0], is_output, t0);
        t0 = NULL;

        n_left -= 1;
        b += 1;
        in_sw_if_index += 1;
        out_sw_if_index += 1;
        spi_pkt += 1;
        hash += 1;
        nexts += 1;
    }

    vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) rt->nexts , frame->n_vectors);
    return frame->n_vectors;
}

always_inline uword
spi_session_node_fn (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame,
					  int is_output,
					  int is_ip6)
{
    u32 n_left;
    u32 *from;

    vlib_buffer_t **b;
    u32 *in_sw_if_index;
    u32 *out_sw_if_index;
    spi_pkt_info_t *spi_pkt;
    u64 *hash;
    u16 *nexts;

    spi_main_t *spim = &spi_main;
    spi_runtime_t *rt = (spi_runtime_t *) node->runtime_data;

    n_left = frame->n_vectors;
    from = vlib_frame_vector_args (frame);
    vlib_get_buffers (vm, from, rt->bufs, frame->n_vectors);

    spi_node_common_prepare_fn (vm, rt, n_left, from, is_ip6, is_output);

    b = rt->bufs;
    in_sw_if_index = rt->in_sw_if_indices;
    out_sw_if_index = rt->out_sw_if_indices;
    spi_pkt = rt->pkts;
    hash = rt->hashes;
    nexts = rt->nexts;

    while (n_left > 8)
    {
        u32 arc_next0, arc_next1, arc_next2, arc_next3;

        CLIB_PREFETCH (b[4], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[5], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[6], CLIB_CACHE_LINE_BYTES * 2, LOAD);
        CLIB_PREFETCH (b[7], CLIB_CACHE_LINE_BYTES * 2, LOAD);

        CLIB_PREFETCH (&spi_pkt[4], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[5], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[6], CLIB_CACHE_LINE_BYTES, LOAD);
        CLIB_PREFETCH (&spi_pkt[7], CLIB_CACHE_LINE_BYTES, LOAD);

        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[4]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[5]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[6]);
        clib_bihash_prefetch_bucket_48_8 (&spim->session_table, hash[7]);

        vnet_feature_next (&arc_next0, b[0]);
        vnet_feature_next (&arc_next1, b[1]);
        vnet_feature_next (&arc_next2, b[2]);
        vnet_feature_next (&arc_next3, b[3]);
        nexts[0] = arc_next0;
        nexts[1] = arc_next1;
        nexts[2] = arc_next2;
        nexts[3] = arc_next3;

        spi_proc_session_fn(vm, node, rt, b[0], &spi_pkt[0], &nexts[0], 
                         hash[0], in_sw_if_index[0], out_sw_if_index[0], is_output, NULL);

        spi_proc_session_fn(vm, node, rt, b[1], &spi_pkt[1], &nexts[1], 
                         hash[1], in_sw_if_index[1], out_sw_if_index[1], is_output, NULL);

        spi_proc_session_fn(vm, node, rt, b[2], &spi_pkt[2], &nexts[2], 
                         hash[2], in_sw_if_index[2], out_sw_if_index[2], is_output, NULL);

        spi_proc_session_fn(vm, node, rt, b[3], &spi_pkt[3], &nexts[3], 
                         hash[3], in_sw_if_index[3], out_sw_if_index[3], is_output, NULL);
          
        n_left -= 4;
        b += 4;
        in_sw_if_index += 4;
        out_sw_if_index += 4;
        spi_pkt += 4;
        hash += 4;
        nexts += 4;
    }

    while (n_left > 0)
    {
        u32 arc_next0;
        vnet_feature_next (&arc_next0, b[0]);
        nexts[0] = arc_next0;

        spi_proc_session_fn(vm, node, rt, b[0], &spi_pkt[0], &nexts[0], 
                         hash[0], in_sw_if_index[0], out_sw_if_index[0], is_output, NULL);

        n_left -= 1;
        b += 1;
        in_sw_if_index += 1;
        out_sw_if_index += 1;
        spi_pkt += 1;
        hash += 1;
        nexts += 1;
    }

    vlib_buffer_enqueue_to_next (vm, node, from, (u16 *) rt->nexts , frame->n_vectors);
    return frame->n_vectors;
}

always_inline uword
spi_node_fn_inline (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame,
					  int is_output,
                      int is_ip6)
{
    if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
        return spi_session_trace_node_fn (vm, node, frame, is_output, is_ip6);
    else
        return spi_session_node_fn (vm, node, frame, is_output, is_ip6);
    return frame->n_vectors;
}

VLIB_NODE_FN (spi_ip4_input_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
    return spi_node_fn_inline (vm, node, frame, 0, 0);
}

VLIB_NODE_FN (spi_ip6_input_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
    return spi_node_fn_inline (vm, node, frame, 0, 1);
}

VLIB_NODE_FN (spi_ip4_output_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
    return spi_node_fn_inline (vm, node, frame, 1, 0);
}

VLIB_NODE_FN (spi_ip6_output_node) (vlib_main_t * vm,
						     vlib_node_runtime_t
						     * node,
						     vlib_frame_t * frame)
{
    return spi_node_fn_inline (vm, node, frame, 1, 1);
}

VLIB_REGISTER_NODE (spi_ip4_input_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip4-input-node",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (spi_node_error_strings),
  .error_strings = spi_node_error_strings,
  .runtime_data_bytes = sizeof (spi_runtime_t),
};

VLIB_REGISTER_NODE (spi_ip4_output_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip4-output-node",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (spi_node_error_strings),
  .error_strings = spi_node_error_strings,
  .runtime_data_bytes = sizeof (spi_runtime_t),
};


VLIB_REGISTER_NODE (spi_ip6_input_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip6-input-node",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (spi_node_error_strings),
  .error_strings = spi_node_error_strings,
  .runtime_data_bytes = sizeof (spi_runtime_t),
};

VLIB_REGISTER_NODE (spi_ip6_output_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip6-output-node",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (spi_node_error_strings),
  .error_strings = spi_node_error_strings,
  .runtime_data_bytes = sizeof (spi_runtime_t),
};

VNET_FEATURE_INIT (spi_ip4_input_feature) = {
  .arc_name = "ip4-unicast",
  .node_name = "spi-ip4-input-node",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa", "ip4-inacl", "ip4-sv-reassembly-feature",
                               "spi-ip4-input-worker-handoff"),
  .runs_before = VNET_FEATURES ("nat44-ed-out2in", "nat44-ed-in2out", 
                                "nat44-out2in-worker-handoff", "nat44-in2out-worker-handoff", 
                                "nat44-handoff-classify", "nat44-ed-classify", 
                                "nat-pre-out2in", "nat-pre-in2out",
                                "ipsec4-input-feature"),
};

VNET_FEATURE_INIT (spi_ip6_input_feature) = {
  .arc_name = "ip6-unicast",
  .node_name = "spi-ip6-input-node",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa", "ip6-inacl", "ip6-sv-reassembly-feature",
                               "spi-ip6-input-worker-handoff"),
  .runs_before = VNET_FEATURES ("nat64-in2out", "nat64-in2out-handoff", "ipsec6-input-feature"),
};

VNET_FEATURE_INIT (spi_ip4_output_feature) = {
  .arc_name = "ip4-output",
  .node_name = "spi-ip4-output-node",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa", "ip4-outacl", 
                               "ipsec4-output-feature", "ip4-sv-reassembly-output-feature",
                               "nat44-ed-in2out-output", "nat44-in2out-output-worker-handoff", "nat-pre-in2out-output", 
                               "spi-ip4-output-worker-handoff"),
};

VNET_FEATURE_INIT (spi_ip6_output_feature) = {
  .arc_name = "ip6-output",
  .node_name = "spi-ip6-output-node",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip6-fa", "ip6-outacl", 
                               "ipsec6-output-feature",
                               "spi-ip6-output-worker-handoff"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
