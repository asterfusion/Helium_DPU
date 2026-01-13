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
 * @brief hqos process thread
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/feature/feature.h>

#include <hqos/hqos.h>

#ifndef CLIB_MARCH_VARIANT

static_always_inline void
hqos_sched_thread_hqos_port(hqos_main_t *hm, u32 hqos_port_id, u32 thread_index)
{
    u32 to_hqos_num = 0;
    u32 to_hqos_success = 0;
    u32 to_output_num = 0;
    u32 to_output_success = 0;


    hqos_port_fifo_t *hqos_port_fifo = &hm->hqos_port_fifo_vec[hqos_port_id];
    hqos_sched_port  *hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    vlib_buffer_t *enqueue_pkts[hqos_port->n_queue_size];
    vlib_buffer_t *dequeue_pkts[hqos_port->n_queue_size];
    u32 free_buffer_indices[hqos_port->n_queue_size];

    /*
     * First get vlib_buffer_t ptr from port_fifo and
     * enqueue to hqos sched port
     */
    to_hqos_num = hqos_fifo_dequeue_sc (hqos_port_fifo->in_fifo,
                                        hqos_port->n_queue_size,
                                         (void *)enqueue_pkts);

    if (to_hqos_num > 0)
    {
        to_hqos_success = hqos_sched_port_enqueue(hqos_port,
                                                  enqueue_pkts,
                                                  to_hqos_num);

        if (to_hqos_num != to_hqos_success)
        {
#if 0
            clib_warning("Hqos -> to_hqos_num %u, to_hqos_success %u : Hqos Queue full, pkt drop %u!",
                         to_hqos_num, to_hqos_success, to_hqos_num - to_hqos_success);
#endif
            /*
             * No need to free the buffer, as hQoS will free it after the enqueue fails
             * only counter
             */
            hm->hqos_port_enqueue_drop[hqos_port_id].counters[thread_index] += (to_hqos_num - to_hqos_success);
        }
    }

    /*
     * Second dequeue fome hoqs shced port and
     * enqueue to port_fifo out_fifo
     */

    to_output_num = hqos_sched_port_dequeue(hqos_port, dequeue_pkts, hqos_port->n_queue_size);

    if (to_output_num > 0)
    {
        to_output_success = hqos_fifo_enqueue_sp (hqos_port_fifo->out_fifo,
                                                  to_output_num,
                                                  (void *)dequeue_pkts);

        if (to_output_num != to_output_success)
        {
#if 0
            clib_warning("Hqos -> to_output_num %u, to_output_success %u : Hqos Port fifo full, pkt drop %u!",
                         to_output_num, to_output_success, to_output_num - to_output_success);
#endif
            hm->hqos_port_dequeue_drop[hqos_port_id].counters[thread_index] += (to_output_num - to_output_success);

            vlib_get_buffer_indices(hm->vlib_main,
                                    dequeue_pkts + to_output_success,
                                    free_buffer_indices,
                                    (to_output_num - to_output_success));

            vlib_buffer_free(hm->vlib_main, free_buffer_indices, (to_output_num - to_output_success));
        }
    }
}

static_always_inline void
hqos_sched_thread_internal ()
{
    u32 thread_index = vlib_get_thread_index ();
    hqos_main_t *hm = &hqos_main;
    uword hqos_port_id;

    while (1)
    {
        //check hqos enabled by sw_if_index
        if (clib_bitmap_is_zero(hm->hqos_enabled_by_sw_if))
            continue;

        //foreach all hqos_port
        hqos_port_id = clib_bitmap_first_set(hm->hqos_port_bitmap);
        while(hqos_port_id != ~0)
        {
            //Check if the current hqos_port_id is attached to the current thread
            if (hm->hqos_port_sched_mapping_thread[hqos_port_id] == (~0) ||
                hm->hqos_port_sched_mapping_thread[hqos_port_id] != thread_index)
            {
                hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
                continue;
            }

            hqos_sched_thread_hqos_port(hm, hqos_port_id, thread_index);

            hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
        }
    }
}

static void
hqos_sched_thread_fn (void *arg)
{
    vlib_worker_thread_t *w = (vlib_worker_thread_t *) arg;
    vlib_worker_thread_init (w);

    hqos_sched_thread_internal ();
}

VLIB_REGISTER_THREAD (hqos_sched_reg, static) =
{
    .name = "hqos-sched",
    .short_name = "hqos-sched",
    .function = hqos_sched_thread_fn,
    .no_data_structure_clone = 1,
};
#endif

static_always_inline u32
hqos_sched_worker_hqos_port(hqos_main_t *hm, u32 hqos_port_id, u32 thread_index)
{
    u32 to_hqos_num = 0;
    u32 to_hqos_success = 0;
    u32 to_output_num = 0;
    u32 to_output_success = 0;

    hqos_port_fifo_t *hqos_port_fifo = &hm->hqos_port_fifo_vec[hqos_port_id];
    hqos_sched_port  *hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    vlib_buffer_t *enqueue_pkts[hqos_port->n_queue_size];
    vlib_buffer_t *dequeue_pkts[hqos_port->n_queue_size];
    u32 free_buffer_indices[hqos_port->n_queue_size];

    /*
     * First get vlib_buffer_t ptr from port_fifo and
     * enqueue to hqos sched port
     */
    to_hqos_num = hqos_fifo_dequeue_sc (hqos_port_fifo->in_fifo,
                                         hqos_port->n_queue_size,
                                         (void *)enqueue_pkts);

    if (to_hqos_num > 0)
    {

        to_hqos_success = hqos_sched_port_enqueue(hqos_port,
                                                  enqueue_pkts,
                                                  to_hqos_num);

        if (to_hqos_num != to_hqos_success)
        {
#if 0
            clib_warning("Hqos -> to_hqos_num %u, to_hqos_success %u : Hqos Queue full, pkt drop %u!",
                         to_hqos_num, to_hqos_success, to_hqos_num - to_hqos_success);
#endif
            /*
             * No need to free the buffer, as hQoS will free it after the enqueue fails
             * only counter
             */
            hm->hqos_port_enqueue_drop[hqos_port_id].counters[thread_index] += (to_hqos_num - to_hqos_success);
        }
    }

    /*
     * Second dequeue fome hoqs shced port and
     * enqueue to port_fifo out_fifo
     */

    to_output_num = hqos_sched_port_dequeue(hqos_port, dequeue_pkts, hqos_port->n_queue_size);

    if (to_output_num > 0)
    {

        to_output_success = hqos_fifo_enqueue_sp (hqos_port_fifo->out_fifo,
                                                  to_output_num,
                                                  (void *)dequeue_pkts);

        if (to_output_num != to_output_success)
        {
#if 0
            clib_warning("Hqos -> to_output_num %u, to_output_success %u : Hqos Port fifo full, pkt drop %u!",
                         to_output_num, to_output_success, to_output_num - to_output_success);
#endif
            hm->hqos_port_dequeue_drop[hqos_port_id].counters[thread_index] += (to_output_num - to_output_success);

            vlib_get_buffer_indices(hm->vlib_main,
                                    dequeue_pkts + to_output_success,
                                    free_buffer_indices,
                                    (to_output_num - to_output_success));

            vlib_buffer_free(hm->vlib_main, free_buffer_indices, (to_output_num - to_output_success));
        }
    }

    return to_output_success;
}

static uword
hqos_sched_worker_fn (vlib_main_t * vm,
                      vlib_node_runtime_t * node,
                      vlib_frame_t * f)
{
    hqos_main_t *hm = &hqos_main;
    u32 thread_index = vlib_get_thread_index ();
    uword hqos_port_id;

    u32 output_pkt = 0;

    //check hqos enabled by sw_if_index
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

        output_pkt += hqos_sched_worker_hqos_port(hm, hqos_port_id, thread_index);

        hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
    }
    return output_pkt;
}

VLIB_REGISTER_NODE(hqos_sched_node) = {
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_DISABLED,
    .name = "hqos-sched",
    .vector_size = sizeof(u32),
    .n_errors = HQOS_N_ERROR,
    .error_counters = hqos_error_counters,
    .function = hqos_sched_worker_fn,
};
