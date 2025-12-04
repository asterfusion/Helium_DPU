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
#include <vppinfra/vector/mask_compare.h>
#include <vppinfra/vector/compress.h>
#include <vppinfra/vector/count_equal.h>
#include <vppinfra/vector/array_mask.h>

#include <hqos/hqos.h>

enum hqos_postprocess_next_e
{
    HQOS_POSTPROCESS_NEXT_ERROR_DROP,
    HQOS_POSTPROCESS_N_NEXT,
};

static_always_inline void
hqos_store_tx_frame_scalar_data (vnet_hw_if_tx_frame_t *copy_frame,
			    vnet_hw_if_tx_frame_t *tf)
{
  if (copy_frame)
    clib_memcpy_fast (tf, copy_frame, sizeof (vnet_hw_if_tx_frame_t));
}

static_always_inline u32
hqos_postprocess_hqos_port(vlib_main_t * vm, hqos_main_t *hm, 
                           u32 hqos_port_id, vlib_buffer_t **buffers)
{
    uint32_t to_output_num = 0;

    hqos_port_fifo_t *hqos_port_fifo = &hm->hqos_port_fifo_vec[hqos_port_id];

    to_output_num = hqos_fifo_dequeue_sc (hqos_port_fifo->out_fifo,
                                          VLIB_FRAME_SIZE,
                                          (void *)buffers);

    return to_output_num;
}

static_always_inline void
hqos_hash_func_with_mask (void **p, u32 *hash, u32 n_packets, u32 *lookup_table,
		     u32 mask, vnet_hash_fn_t hf)
{
  u32 n_left_from = n_packets;

  hf (p, hash, n_packets);

  clib_array_mask_u32 (hash, mask, n_packets);

  while (n_left_from >= 4)
    {
      hash[0] = lookup_table[hash[0]];
      hash[1] = lookup_table[hash[1]];
      hash[2] = lookup_table[hash[2]];
      hash[3] = lookup_table[hash[3]];

      hash += 4;
      n_left_from -= 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = lookup_table[hash[0]];

      hash += 1;
      n_left_from -= 1;
    }
}

static_always_inline void
hqos_tc_func(void** p, u32* qids, u32 n_packets, u32 n_queues, vnet_hw_interface_t* hi) 
{
    u32 n_left_from = n_packets;

    while (n_left_from >= 4) {
        uword* q0, * q1, * q2, * q3;
        u32 tc0 = *(u32 *)p[0];
        u32 tc1 = *(u32 *)p[1];
        u32 tc2 = *(u32 *)p[2];
        u32 tc3 = *(u32 *)p[3];

        *(u32 *)p[0] = 0;
        *(u32 *)p[1] = 0;
        *(u32 *)p[2] = 0;
        *(u32 *)p[3] = 0;

        q0 = hi->tc_to_queue ? hash_get(hi->tc_to_queue, tc0) : NULL;
        q1 = hi->tc_to_queue ? hash_get(hi->tc_to_queue, tc1) : NULL;
        q2 = hi->tc_to_queue ? hash_get(hi->tc_to_queue, tc2) : NULL;
        q3 = hi->tc_to_queue ? hash_get(hi->tc_to_queue, tc3) : NULL;

        qids[0] = (q0 ? q0[0] : tc0) % n_queues;
        qids[1] = (q1 ? q1[0] : tc1) % n_queues;
        qids[2] = (q2 ? q2[0] : tc2) % n_queues;
        qids[3] = (q3 ? q3[0] : tc3) % n_queues;

        qids += 4;
        n_left_from -= 4;
        p += 4;
    }

    while (n_left_from > 0) {
        uword* q0;
        u32 tc0 = *(u32 *)p[0];

        *(u32 *)p[0] = 0;

        q0 = hi->tc_to_queue ? hash_get(hi->tc_to_queue, tc0) : NULL;
        qids[0] = (q0 ? q0[0] : tc0) % n_queues;

        qids += 1;
        n_left_from -= 1;
        p += 1;
    }
}

static_always_inline u32
hqos_enqueue_one_to_tx (vlib_main_t *vm, vlib_node_runtime_t *node, u32 *ppqi,
                       u32 *from, vnet_hw_if_tx_frame_t *copy_frame,
                       u32 n_vectors, u32 n_left, u32 next_index)
{
    u32 tmp[VLIB_FRAME_SIZE];
    vlib_frame_bitmap_t mask = {};
    vlib_frame_t *f;
    vnet_hw_if_tx_frame_t *tf;
    u32 *to;
    u32 n_copy = 0, n_free = 0;

    f = vlib_get_next_frame_internal (vm, node, next_index, 0);
    tf = vlib_frame_scalar_args (f);

    if (f->n_vectors > 0 &&
        (!copy_frame || (tf->queue_id == copy_frame->queue_id)))
    {
        /* append current next frame */
        n_free = VLIB_FRAME_SIZE - f->n_vectors;
        /*
         * if frame contains enough space for worst case scenario,
         * we can avoid use of tmp
         */
        if (n_free >= n_left)
            to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
        else
            to = tmp;
    }
    else
    {
        if (f->n_vectors > 0)
        {
            /* current frame doesn't fit - grab empty one */
            f = vlib_get_next_frame_internal (vm, node, next_index, 1);
            tf = vlib_frame_scalar_args (f);
        }

        /* empty frame - store scalar data */
        hqos_store_tx_frame_scalar_data (copy_frame, tf);
        to = vlib_frame_vector_args (f);
        n_free = VLIB_FRAME_SIZE;
    }

    /*
     * per packet queue id array
     * compare with given queue_id, if match, copy respective buffer index from -> to
     */
    if (ppqi)
    {
        clib_mask_compare_u32 (copy_frame->queue_id, ppqi, mask, n_vectors);
        n_copy = clib_compress_u32 (to, from, mask, n_vectors);

        if (n_copy == 0)
            return n_left;
    }
    else
    {
        /*
         * no work required, just copy all buffer indices from -> to
         */
        n_copy = n_left;
        vlib_buffer_copy_indices (to, from, n_copy);
    }

    if (to != tmp)
    {
        /* indices already written to frame, just close it */
        vlib_put_next_frame (vm, node, next_index, n_free - n_copy);
    }
    else if (n_free >= n_copy)
    {
        /* enough space in the existing frame */
        to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
        vlib_buffer_copy_indices (to, tmp, n_copy);
        vlib_put_next_frame (vm, node, next_index, n_free - n_copy);
    }
    else
    {
        /* full frame */
        to = (u32 *) vlib_frame_vector_args (f) + f->n_vectors;
        vlib_buffer_copy_indices (to, tmp, n_free);
        vlib_put_next_frame (vm, node, next_index, 0);

        /* second frame */
        u32 n_2nd_frame = n_copy - n_free;
        f = vlib_get_next_frame_internal (vm, node, next_index, 1);
        tf = vlib_frame_scalar_args (f);
        /* empty frame - store scalar data */
        hqos_store_tx_frame_scalar_data (copy_frame, tf);
        to = vlib_frame_vector_args (f);
        vlib_buffer_copy_indices (to, tmp + n_free, n_2nd_frame);
        vlib_put_next_frame (vm, node, next_index, VLIB_FRAME_SIZE - n_2nd_frame);
    }
    return n_left - n_copy;
}

static_always_inline void
hqos_enqueue_to_tx (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vnet_hw_interface_t *hi, u32 next_index,
		    vnet_hw_if_output_node_runtime_t *r, u32 *from, void **p,
		    u32 n_vectors)
{
    u32 n_left = n_vectors;

    /*
     * backward compatible for drivers not integrated with new tx infra.
     */
    if (r == 0)
    {
        n_left = hqos_enqueue_one_to_tx (vm, node, NULL, from, NULL, n_vectors, n_left, next_index);
    }
    /*
     * only 1 tx queue of given interface is available on given thread
     */
    else if (r->n_queues == 1)
    {
        n_left = hqos_enqueue_one_to_tx (vm, node, NULL, from, r->frame, n_vectors, n_left, next_index);
    }
    /*
     * multi tx-queues use case
     */
    else if (r->n_queues > 1)
    {
        u32 qids[VLIB_FRAME_SIZE];

        if (hi->flags & VNET_HW_INTERFACE_FLAG_USE_TC)
            hqos_tc_func(p, qids, n_vectors, r->n_queues, hi);
        else
            hqos_hash_func_with_mask (p, qids, n_vectors, r->lookup_table,
                    vec_len (r->lookup_table) - 1, hi->hf);

        for (u32 i = 0; i < r->n_queues; i++)
        {
            n_left = hqos_enqueue_one_to_tx (vm, node, qids, from, &r->frame[i], n_vectors, n_left, next_index);
            if (n_left == 0)
                break;
        }
    }
    else
        ASSERT (0);
}

static_always_inline void
hqos_enqueue_to_tx_node(vlib_main_t * vm, vlib_node_runtime_t * node, 
                        vlib_buffer_t **buffers, u32 pkt_count)
{
    vnet_main_t *vnm = vnet_get_main ();
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hi;

    vlib_frame_bitmap_t used_elts = {}, mask = {};

    u32 n_left = pkt_count;

    u32 buffer_indexs[VLIB_FRAME_SIZE];
    u32 sw_if_indices[VLIB_FRAME_SIZE], *sw_if_index = sw_if_indices;
    void *ptr[VLIB_FRAME_SIZE], **p = ptr;
    u32 tmp[VLIB_FRAME_SIZE];

    u32 n_comp, n_p_comp, swif, off;

    u16 next_index;

    u16 *tx_node_next_index = hm->sw_if_tx_node_next_index;

    vlib_get_buffer_indices(vm, buffers, buffer_indexs, pkt_count);

    while (n_left >= 8)
    {
        vnet_hw_interface_t *hi0, *hi1, *hi2, *hi3;
        hqos_postprocess_trace_t *t0, *t1, *t2, *t3;

        vlib_prefetch_buffer_header (buffers[4], LOAD);
        vlib_prefetch_buffer_header (buffers[5], LOAD);
        vlib_prefetch_buffer_header (buffers[6], LOAD);
        vlib_prefetch_buffer_header (buffers[7], LOAD);

        sw_if_index[0] = vnet_buffer (buffers[0])->sw_if_index[VLIB_TX];
        sw_if_index[1] = vnet_buffer (buffers[1])->sw_if_index[VLIB_TX];
        sw_if_index[2] = vnet_buffer (buffers[2])->sw_if_index[VLIB_TX];
        sw_if_index[3] = vnet_buffer (buffers[3])->sw_if_index[VLIB_TX];

        hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index[0]);
        hi1 = vnet_get_sup_hw_interface (vnm, sw_if_index[1]);
        hi2 = vnet_get_sup_hw_interface (vnm, sw_if_index[2]);
        hi3 = vnet_get_sup_hw_interface (vnm, sw_if_index[3]);

        p[0] = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[0])->tc_index : vlib_buffer_get_current (buffers[0]);
        p[1] = hi1->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[1])->tc_index : vlib_buffer_get_current (buffers[1]);
        p[2] = hi2->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[2])->tc_index : vlib_buffer_get_current (buffers[2]);
        p[3] = hi3->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[3])->tc_index : vlib_buffer_get_current (buffers[3]);

        if (PREDICT_FALSE (buffers[0]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t0 = vlib_add_trace (vm, node, buffers[0], sizeof (hqos_postprocess_trace_t));
            t0->sw_if_index = sw_if_index[0];
            t0->use_tc = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t0->tc = vnet_buffer2(buffers[0])->tc_index;
        }
        if (PREDICT_FALSE (buffers[1]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t1 = vlib_add_trace (vm, node, buffers[1], sizeof (hqos_postprocess_trace_t));
            t1->sw_if_index = sw_if_index[1];
            t1->use_tc = hi1->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t1->tc = vnet_buffer2(buffers[1])->tc_index;
        }
        if (PREDICT_FALSE (buffers[2]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t2 = vlib_add_trace (vm, node, buffers[2], sizeof (hqos_postprocess_trace_t));
            t2->sw_if_index = sw_if_index[2];
            t2->use_tc = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t2->tc = vnet_buffer2(buffers[2])->tc_index;
        }
        if (PREDICT_FALSE (buffers[3]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t3 = vlib_add_trace (vm, node, buffers[3], sizeof (hqos_postprocess_trace_t));
            t3->sw_if_index = sw_if_index[3];
            t3->use_tc = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t3->tc = vnet_buffer2(buffers[3])->tc_index;
        }

        p += 4;
        buffers += 4;
        sw_if_index += 4;
        n_left -= 4;
    }

    while (n_left >= 4)
    {
        vnet_hw_interface_t *hi0, *hi1;
        hqos_postprocess_trace_t *t0, *t1;

        vlib_prefetch_buffer_header (buffers[2], LOAD);
        vlib_prefetch_buffer_header (buffers[3], LOAD);

        sw_if_index[0] = vnet_buffer (buffers[0])->sw_if_index[VLIB_TX];
        sw_if_index[1] = vnet_buffer (buffers[1])->sw_if_index[VLIB_TX];

        hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index[0]);
        hi1 = vnet_get_sup_hw_interface (vnm, sw_if_index[1]);

        p[0] = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[0])->tc_index : vlib_buffer_get_current (buffers[0]);
        p[1] = hi1->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[1])->tc_index : vlib_buffer_get_current (buffers[1]);

        if (PREDICT_FALSE (buffers[0]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t0 = vlib_add_trace (vm, node, buffers[0], sizeof (hqos_postprocess_trace_t));
            t0->sw_if_index = sw_if_index[0];
            t0->use_tc = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t0->tc = vnet_buffer2(buffers[0])->tc_index;
        }
        if (PREDICT_FALSE (buffers[1]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t1 = vlib_add_trace (vm, node, buffers[1], sizeof (hqos_postprocess_trace_t));
            t1->sw_if_index = sw_if_index[1];
            t1->use_tc = hi1->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t1->tc = vnet_buffer2(buffers[1])->tc_index;
        }

        p += 2;
        buffers += 2;
        sw_if_index += 2;
        n_left -= 2;
    }

    while (n_left)
    {
        vnet_hw_interface_t *hi0;
        hqos_postprocess_trace_t *t0;

        sw_if_index[0] = vnet_buffer (buffers[0])->sw_if_index[VLIB_TX];

        hi0 = vnet_get_sup_hw_interface (vnm, sw_if_index[0]);

        p[0] = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC ? 
                    &vnet_buffer2(buffers[0])->tc_index : vlib_buffer_get_current (buffers[0]);

        if (PREDICT_FALSE (buffers[0]->flags & VLIB_BUFFER_IS_TRACED))
        {
            t0 = vlib_add_trace (vm, node, buffers[0], sizeof (hqos_postprocess_trace_t));
            t0->sw_if_index = sw_if_index[0];
            t0->use_tc = hi0->flags & VNET_HW_INTERFACE_FLAG_USE_TC;
            t0->tc = vnet_buffer2(buffers[0])->tc_index;
        }

        p++;
        buffers++;
        sw_if_index++;
        n_left--;
    }

    n_left = pkt_count;
    swif = sw_if_indices[0];
    off = 0;

more:
    next_index = vec_elt (tx_node_next_index, swif);
    hi = vnet_get_sup_hw_interface (vnm, swif);
    vnet_hw_if_output_node_runtime_t *r = 0;
    void *ptr_tmp[VLIB_FRAME_SIZE], **p_tmp = ptr_tmp;
    if (hi->output_node_thread_runtimes)
        r = vec_elt_at_index (hi->output_node_thread_runtimes, vm->thread_index);

    /* compare and compress based on comparison mask */
    clib_mask_compare_u32 (swif, sw_if_indices, mask, pkt_count);
    n_comp = clib_compress_u32 (tmp, buffer_indexs, mask, pkt_count);

    /*
     * tx queue of given interface is not available on given thread
     */
    if (r)
    {
        if (r->n_queues == 0)
        {
            vlib_error_drop_buffers (vm, node, tmp, /* buffer stride */ 1, n_comp, 
                                    VNET_INTERFACE_OUTPUT_NEXT_DROP, node->node_index, 
                                    VNET_INTERFACE_OUTPUT_ERROR_NO_TX_QUEUE);
            goto drop;
        }
        else if (r->n_queues > 1)
        {
            n_p_comp = clib_compress_u64 ((u64 *) p_tmp, (u64 *) ptr, mask, pkt_count);
            ASSERT (n_p_comp == n_comp);
        }
    }

    hqos_enqueue_to_tx (vm, node, hi, next_index, r, tmp, ptr_tmp, n_comp);

drop:
    n_left -= n_comp;
    if (n_left)
    {
        /* store comparison mask so we can find next unused element */
        vlib_frame_bitmap_or (used_elts, mask);

        /* fine first unused sw_if_index by scanning trough used_elts bitmap */
        while (PREDICT_FALSE (used_elts[off] == ~0))
            off++;

        swif = sw_if_indices[(off << 6) + count_trailing_zeros (~used_elts[off])];
        goto more;
    }
    return;
}

static uword
hqos_postprocess_input (vlib_main_t * vm,
                        vlib_node_runtime_t * node,
                        vlib_frame_t * f)
{
    u32 thread_index = vm->thread_index;
    hqos_main_t *hm = &hqos_main;
    uword hqos_port_id;

    u32 pkt_count = 0;
    u32 pkt_total = 0;
    vlib_buffer_t *buffers[VLIB_FRAME_SIZE];

    if (clib_bitmap_is_zero(hm->hqos_enabled_by_sw_if))
        return 0;

    //foreach all hqos_port
    hqos_port_id = clib_bitmap_first_set(hm->hqos_port_bitmap);
    while(hqos_port_id != ~0)
    {
        //Check if the current hqos_port_id is attached to the current thread
        if (hm->hqos_port_sched_mapping_worker[hqos_port_id] == (~0) || 
            hm->hqos_port_sched_mapping_worker[hqos_port_id] != thread_index)
        {
            hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
            continue;
        }

        pkt_count = hqos_postprocess_hqos_port(vm, hm, hqos_port_id, buffers);

        hqos_enqueue_to_tx_node (vm, node, buffers, pkt_count);

        pkt_total += pkt_count;

        hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
    }

    return pkt_total;
}

VLIB_REGISTER_NODE (hqos_postprocess_node) = {
  .function = hqos_postprocess_input,
  .name = "hqos-postprocess-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,

  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .format_trace = format_hqos_postprocess_trace,

  .n_next_nodes = HQOS_POSTPROCESS_N_NEXT,
  .next_nodes = {
      [HQOS_POSTPROCESS_NEXT_ERROR_DROP] = "error-drop",
  },
};
