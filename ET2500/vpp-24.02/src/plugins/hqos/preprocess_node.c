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
 * @brief hqos preprocess node
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>

#include <hqos/hqos.h>

enum hqos_preprocess_next_e
{
    HQOS_PREPROCESS_NEXT_ERROR_DROP,
    HQOS_PREPROCESS_N_NEXT,
};

static_always_inline void
hqos_classification_proc(vlib_main_t *vm,
                         vlib_node_runtime_t *node,
                         vlib_buffer_t *p,
                         u32 *throught_num,
                         u32 *throught_from,
                         u16 *throught_nexts)
{
    int rv_len;
    vnet_main_t *vnm = vnet_get_main ();
    hqos_main_t *hm = &hqos_main;
    u32 arc_next;
    u32 sw_if_index;
    vnet_hw_interface_t *hi = NULL;

    u32 state = HQOS_ERROR_INTO_HQOS;

    hqos_interface_hqos_mapping_t *hqos_mapping = NULL;
    u32 hqos_port_id = ~0;

    uword *user_group_id_ptr = NULL;
    u32 user_group_id = ~0;

    hqos_user_t *user = NULL;
    u32 user_id = ~0;

    u32 tc = 0;

    hqos_sched_port *hqos_port = NULL;
    uword *hqos_subport_id_ptr = NULL;
    uword *hqos_pipe_id_ptr = NULL;
    u32 hqos_subport_id = ~0;
    u32 hqos_pipe_id = ~0;
    u32 hqos_queue_id = ~0;

    hqos_port_fifo_t *hqos_port_fifo = NULL;

    hqos_preprocess_trace_t *t = NULL;

    sw_if_index = vnet_buffer (p)->sw_if_index[VLIB_TX];
    hi = vnet_get_sup_hw_interface (vnm, sw_if_index);

    tc = vnet_buffer2(p)->tc_index;

    if (!hi)
    {
        //throught to interface-output feature
        vnet_feature_next (&arc_next, p);
        throught_from[*throught_num] = vlib_get_buffer_index(vm, p);
        throught_nexts[*throught_num] = arc_next;
        (*throught_num)++;
        p->error = node->errors[HQOS_ERROR_CUT_THROUGTH];
        state = HQOS_ERROR_CUT_THROUGTH;
        goto trace;
    }

    hqos_mapping = vec_elt_at_index(hm->interface_mapping_vec, sw_if_index);
    hqos_port_id = hqos_mapping->hqos_port_id;
    if (hqos_port_id == UINT32_MAX || 
        !clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        vnet_feature_next (&arc_next, p);
        throught_from[*throught_num] = vlib_get_buffer_index(vm, p);
        throught_nexts[*throught_num] = arc_next;
        (*throught_num)++;
        p->error = node->errors[HQOS_ERROR_NOT_HQOS_PORT];
        state = HQOS_ERROR_NOT_HQOS_PORT;
        goto trace;
    }

    user_id = vlib_buffer_hqos_user_get(p);
    if (pool_is_free_index(hm->user_pool, user_id))
    {
        //user to default user
        user_id = 0;
    }

    user_group_id_ptr = hash_get(hi->user_to_ugroup, user_id);
    if (user_group_id_ptr)
        user_group_id = (*user_group_id_ptr) & (HQOS_MAX_USER_GROUP - 1);
    else
        user_group_id = 0;

    hqos_subport_id_ptr = hash_get(hqos_mapping->user_group_id_to_hqos_subport_id, user_group_id);
    if (hqos_subport_id_ptr)
        hqos_subport_id = (*hqos_subport_id_ptr) & (HQOS_NODE_MAX_SUBPORT_PER_PORT - 1);
    else
        hqos_subport_id = 0;

    hqos_pipe_id_ptr = hash_get(hqos_mapping->user_id_to_hqos_pipe_id, user_id);
    if (hqos_pipe_id_ptr)
        hqos_pipe_id = (*hqos_pipe_id_ptr) & (HQOS_NODE_MAX_PIPE_PER_SUBPORT - 1);
    else
        hqos_pipe_id = 0;

    user = pool_elt_at_index(hm->user_pool, user_id);
    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];
    hqos_port_fifo = vec_elt_at_index(hm->hqos_port_fifo_vec, hqos_port_id);

    hqos_queue_id = hqos_get_queue_id(hqos_port, hqos_subport_id, hqos_pipe_id, 
                                      user->tc_queue_mode[tc] == HQOS_TC_QUEUE_MODE_DWRR ? 
                                           tc : HQOS_SCHED_TRAFFIC_CLASS_BE + tc);

    vlib_buffer_hqos_tc_set(p, tc);
    vlib_buffer_hqos_color_set(p, HQOS_COLOR_GREEN);
    vlib_buffer_hqos_queue_set(p, hqos_queue_id);

    rv_len = hqos_fifo_enqueue_mp(hqos_port_fifo->in_fifo, 1, (void *)&p);
    if (rv_len != 8)
    {
        clib_warning("hqos port id %u hqos_port_fifo enqueue failed(%d)\n", hqos_mapping->hqos_port_id, rv_len);
    }

    p->error = node->errors[HQOS_ERROR_INTO_HQOS];

trace:
    if (PREDICT_FALSE (p->flags & VLIB_BUFFER_IS_TRACED))
    {
        t = vlib_add_trace (vm, node, p, sizeof (hqos_preprocess_trace_t));
        t->state = state;
        t->pkt_len = vlib_buffer_length_in_chain(vm, p);
        t->tc = tc;
        t->user_id = user_id;
        t->user_group_id = user_group_id;
        t->color = HQOS_COLOR_GREEN;
        t->hqos_port_id = hqos_port_id;
        t->hqos_subport_id = hqos_subport_id;
        t->hqos_pipe_id = hqos_pipe_id;
        t->hqos_queue_id = hqos_queue_id;
    }
    return;
}

VLIB_NODE_FN (hqos_preprocess_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 n_left;
    u32 *from;
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

    u32 throught_num = 0;
    u32 throught_from[VLIB_FRAME_SIZE];
    u16 throught_nexts[VLIB_FRAME_SIZE];

    n_left = frame->n_vectors;
    from = vlib_frame_vector_args (frame);
    vlib_get_buffers (vm, from, bufs, frame->n_vectors);

    b = bufs;

    while (n_left > 8)
    {
        vlib_prefetch_buffer_header (b[4], STORE);
        vlib_prefetch_buffer_header (b[5], STORE);
        vlib_prefetch_buffer_header (b[6], STORE);
        vlib_prefetch_buffer_header (b[7], STORE);

        hqos_classification_proc(vm, node, b[0], &throught_num, throught_from, throught_nexts);
        hqos_classification_proc(vm, node, b[1], &throught_num, throught_from, throught_nexts);
        hqos_classification_proc(vm, node, b[2], &throught_num, throught_from, throught_nexts);
        hqos_classification_proc(vm, node, b[3], &throught_num, throught_from, throught_nexts);

        n_left -= 4;
        b += 4;
    }

    while (n_left > 4)
    {
        vlib_prefetch_buffer_header (b[2], STORE);
        vlib_prefetch_buffer_header (b[3], STORE);

        hqos_classification_proc(vm, node, b[0], &throught_num, throught_from, throught_nexts);
        hqos_classification_proc(vm, node, b[1], &throught_num, throught_from, throught_nexts);

        n_left -= 2;
        b += 2;
    }

    while (n_left > 0)
    {

        hqos_classification_proc(vm, node, b[0], &throught_num, throught_from, throught_nexts);

        n_left -= 1;
        b += 1;
    }

    vlib_buffer_enqueue_to_next (vm, node, throught_from, throught_nexts , throught_num);

    return throught_num;
}

VLIB_REGISTER_NODE (hqos_preprocess_node) = {
  .name = "hqos-preprocess",
  .vector_size = sizeof (u32),
  .format_trace = format_hqos_preprocess_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = HQOS_N_ERROR,
  .error_counters = hqos_error_counters,

  .n_next_nodes = HQOS_PREPROCESS_N_NEXT,
  .next_nodes = {
      [HQOS_PREPROCESS_NEXT_ERROR_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (hqos_preprocess_feature, static) = {
  .arc_name = "interface-output",
  .node_name = "hqos-preprocess",
  .runs_after = VNET_FEATURES ("nsim-output-feature", "mactime-tx", "isolation_group",
                               "flowprobe-output-l2", "ct6-in2out", "policer-output",
                               "stats-collect-tx", "ipsec-if-output", "span-output"),
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};
