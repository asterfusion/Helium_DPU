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
 * @brief SPI worker handoff
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>

#include <spi/spi.h>
#include <spi/spi_inline.h>

static char *spi_handoff_error_strings[] = {
#define _(sym,string) string,
  foreach_spi_handoff_error
#undef _
};

static u8 *
format_spi_handoff_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    spi_handoff_trace_t *t = va_arg (*args, spi_handoff_trace_t *);
    char *tag;

    tag = t->is_output ? "OUTPUT" : "INPUT";
    s = format (s, "SPI_%s_WORKER_HANDOFF: next-worker %d trace index %d",
            tag, t->next_worker_index, t->trace_index);
    return s;
}

static inline uword
spi_worker_handoff_fn_inline (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame, u8 is_ip6, u8 is_output)
{
    u32 n_enq, n_left_from, *from, do_handoff = 0, same_worker = 0;

    vlib_buffer_t **b;
    u16 *ti;
    u64 *hash;

    spi_main_t *spim = &spi_main;
    spi_handoff_runtime_t *rt = (spi_handoff_runtime_t *) node->runtime_data;

    u32 fq_index, thread_index = vm->thread_index;

    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    vlib_get_buffers (vm, from, rt->bufs, n_left_from);

    if (is_ip6)
        fq_index = is_output ? spim->fq_ip6_output_index : spim->fq_ip6_input_index;
    else
        fq_index = is_output ? spim->fq_ip4_output_index : spim->fq_ip4_input_index;

    spi_handoff_node_common_prepare_fn (vm, rt, n_left_from, from, is_ip6, is_output);

    b = rt->bufs;
    hash = rt->hashes;
    ti = rt->thread_indices;

    while (n_left_from >= 8)
    {
        vlib_prefetch_buffer_header (hash, LOAD);

        ti[0] = spim->first_worker_index + hash[0] % spim->num_workers;
        ti[1] = spim->first_worker_index + hash[1] % spim->num_workers;
        ti[2] = spim->first_worker_index + hash[2] % spim->num_workers;
        ti[3] = spim->first_worker_index + hash[3] % spim->num_workers;

        if (ti[0] == thread_index) same_worker++;
        else do_handoff++;

        if (ti[1] == thread_index) same_worker++;
        else do_handoff++;

        if (ti[2] == thread_index) same_worker++;
        else do_handoff++;

        if (ti[3] == thread_index) same_worker++;
        else do_handoff++;

        b += 4;
        ti += 4;
        hash += 4;
        n_left_from -= 4;
    }

    while (n_left_from > 0)
    {

        ti[0] = spim->first_worker_index + hash[0] % spim->num_workers;

        if (ti[0] == thread_index) same_worker++;
        else do_handoff++;

        b += 1;
        ti += 1;
        hash += 1;
        n_left_from -= 1;
    }

    if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)))
    {
        u32 i;
        b = rt->bufs;
        ti = rt->thread_indices;

        for (i = 0; i < frame->n_vectors; i++)
        {
            if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
            {
                spi_handoff_trace_t *t = vlib_add_trace (vm, node, b[0], sizeof (*t));
                t->next_worker_index = ti[0];
                t->trace_index = vlib_buffer_get_trace_index (b[0]);
                t->is_output = is_output;
                b += 1;
                ti += 1;
            }
            else
                break;
        }
    }

    n_enq = vlib_buffer_enqueue_to_thread (vm, node, fq_index, 
                                          from, rt->thread_indices, 
                                          frame->n_vectors, 1);

    if (n_enq < frame->n_vectors)
    {
        vlib_node_increment_counter (vm, node->node_index,
                                     SPI_HANDOFF_ERROR_CONGESTION_DROP,
                                     frame->n_vectors - n_enq);
    }

    vlib_node_increment_counter (vm, node->node_index,
                                 SPI_HANDOFF_ERROR_SAME_WORKER, 
                                 same_worker);

    vlib_node_increment_counter (vm, node->node_index,
                                SPI_HANDOFF_ERROR_DO_HANDOFF, 
                                do_handoff);

    return frame->n_vectors;
}

VLIB_NODE_FN (spi_ip4_input_worker_handoff_node) (vlib_main_t * vm,
						vlib_node_runtime_t * node,
						vlib_frame_t * frame)
{
    return spi_worker_handoff_fn_inline (vm, node, frame, 0, 0);
}

VLIB_NODE_FN (spi_ip4_output_worker_handoff_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
    return spi_worker_handoff_fn_inline (vm, node, frame, 0, 1);
}

VLIB_NODE_FN (spi_ip6_input_worker_handoff_node) (vlib_main_t * vm,
						vlib_node_runtime_t * node,
						vlib_frame_t * frame)
{
    return spi_worker_handoff_fn_inline (vm, node, frame, 1, 0);
}

VLIB_NODE_FN (spi_ip6_output_worker_handoff_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
    return spi_worker_handoff_fn_inline (vm, node, frame, 1, 1);
}


VLIB_REGISTER_NODE (spi_ip4_input_worker_handoff_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip4-input-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(spi_handoff_error_strings),
  .error_strings = spi_handoff_error_strings,
  .runtime_data_bytes = sizeof (spi_handoff_runtime_t),
};

VLIB_REGISTER_NODE (spi_ip4_output_worker_handoff_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip4-output-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(spi_handoff_error_strings),
  .error_strings = spi_handoff_error_strings,
  .runtime_data_bytes = sizeof (spi_handoff_runtime_t),
};

VLIB_REGISTER_NODE (spi_ip6_input_worker_handoff_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip6-input-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(spi_handoff_error_strings),
  .error_strings = spi_handoff_error_strings,
  .runtime_data_bytes = sizeof (spi_handoff_runtime_t),
};

VLIB_REGISTER_NODE (spi_ip6_output_worker_handoff_node) = {
  .sibling_of = "spi-default",
  .name = "spi-ip6-output-worker-handoff",
  .vector_size = sizeof (u32),
  .format_trace = format_spi_handoff_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN(spi_handoff_error_strings),
  .error_strings = spi_handoff_error_strings,
  .runtime_data_bytes = sizeof (spi_handoff_runtime_t),
};

VNET_FEATURE_INIT (spi_ip4_input_worker_handoff_feature) = {
  .arc_name = "ip4-unicast",
  .node_name = "spi-ip4-input-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa", "ip4-inacl", "ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("nat44-ed-out2in", "nat44-ed-in2out", 
                                "nat44-out2in-worker-handoff", "nat44-in2out-worker-handoff", 
                                "nat44-handoff-classify", "nat44-ed-classify", 
                                "nat-pre-out2in", "nat-pre-in2out",
                                "ipsec4-input-feature"),
};

VNET_FEATURE_INIT (spi_ip6_input_worker_handoff_feature) = {
  .arc_name = "ip6-unicast",
  .node_name = "spi-ip6-input-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa", "ip6-inacl", "ip6-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("nat64-in2out", "nat64-in2out-handoff", "ipsec6-input-feature"),
};

VNET_FEATURE_INIT (spi_ip4_output_worker_handoff_feature) = {
  .arc_name = "ip4-output",
  .node_name = "spi-ip4-output-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip4-fa", "ip4-outacl", 
                               "ipsec4-output-feature", "ip4-sv-reassembly-output-feature", 
                               "nat44-ed-in2out-output", "nat44-in2out-output-worker-handoff", "nat-pre-in2out-output"),
};

VNET_FEATURE_INIT (spi_ip6_output_worker_handoff_feature) = {
  .arc_name = "ip6-output",
  .node_name = "spi-ip6-output-worker-handoff",
  .runs_after = VNET_FEATURES ("acl-plugin-out-ip6-fa", "ip6-outacl", 
                               "ipsec6-output-feature"),
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
