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

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vlib/threads.h>

#include <hqos/hqos.h>

hqos_main_t hqos_main;

static void 
hqos_attach_sched_core(hqos_main_t *hm, u32 hqos_port_id)
{
    vlib_global_main_t *vgm = vlib_get_global_main ();
    u32 thread_worker_index = 0;

    thread_worker_index = hm->hqos_sched_worker_first + hqos_port_id %  hm->hqos_sched_worker_num;
    hm->hqos_port_sched_mapping_worker[hqos_port_id] = thread_worker_index;
    hm->hqos_thread_worker_refcnt[thread_worker_index]++;
    if (hm->hqos_thread_worker_refcnt[thread_worker_index] == 1)
    {
        //If there is no separate thread
        if (hm->hqos_sched_thread_num == 0)
        {
            //enable hqos input node 
            if (VLIB_NODE_STATE_POLLING != 
                    vlib_node_get_state (vgm->vlib_mains[thread_worker_index], hqos_sched_node.index))
                vlib_node_set_state (vgm->vlib_mains[thread_worker_index], hqos_sched_node.index, VLIB_NODE_STATE_POLLING);
        }

        //hqos postprocess output node
        if (VLIB_NODE_STATE_POLLING != 
                vlib_node_get_state (vgm->vlib_mains[thread_worker_index], hqos_postprocess_node.index))
            vlib_node_set_state (vgm->vlib_mains[thread_worker_index], hqos_postprocess_node.index, VLIB_NODE_STATE_POLLING);
    }

    if (hm->hqos_sched_thread_num != 0)
    {
        thread_worker_index = hm->hqos_sched_thread_first + hqos_port_id %  hm->hqos_sched_thread_num;
        hm->hqos_port_sched_mapping_thread[hqos_port_id] = thread_worker_index;
        hm->hqos_thread_worker_refcnt[thread_worker_index]++;
    }
}

static void 
hqos_detach_sched_core(hqos_main_t *hm, u32 hqos_port_id)
{
    vlib_global_main_t *vgm = vlib_get_global_main ();
    u32 thread_worker_index = 0;

    thread_worker_index = hm->hqos_port_sched_mapping_worker[hqos_port_id];
    hm->hqos_thread_worker_refcnt[thread_worker_index]--;
    hm->hqos_port_sched_mapping_worker[hqos_port_id] = (~0);

    if (hm->hqos_thread_worker_refcnt[thread_worker_index] == 0)
    {
        //If there is no separate thread
        if (hm->hqos_sched_thread_num == 0)
        {
            //disable hqos input node 
            if (VLIB_NODE_STATE_POLLING == 
                    vlib_node_get_state (vgm->vlib_mains[thread_worker_index], hqos_sched_node.index))
                vlib_node_set_state (vgm->vlib_mains[thread_worker_index], hqos_sched_node.index, VLIB_NODE_STATE_DISABLED);
        }

        //hqos postprocess output node
        if (VLIB_NODE_STATE_POLLING == 
                vlib_node_get_state (vgm->vlib_mains[thread_worker_index], hqos_postprocess_node.index))
            vlib_node_set_state (vgm->vlib_mains[thread_worker_index], hqos_postprocess_node.index, VLIB_NODE_STATE_DISABLED);
    }

    if (hm->hqos_sched_thread_num != 0)
    {
        thread_worker_index = hm->hqos_port_sched_mapping_thread[hqos_port_id];
        hm->hqos_thread_worker_refcnt[thread_worker_index]--;
        hm->hqos_port_sched_mapping_thread[hqos_port_id] = (~0);
    }
}

static int 
hqos_port_fifo_init(hqos_port_fifo_t *hqos_port_fifo, u32 queue_size)
{
    int ret = 0;
    hqos_port_fifo->in_fifo = hqos_fifo_alloc(queue_size, sizeof(void *));
    hqos_port_fifo->out_fifo = hqos_fifo_alloc(queue_size, sizeof(void *));

    if (!hqos_port_fifo->in_fifo || !hqos_port_fifo->in_fifo)
    {
        ret = -1;
        goto free;
    }

free:
    if (ret != 0)
    {
        if (hqos_port_fifo->in_fifo)
        {
            hqos_fifo_free(hqos_port_fifo->in_fifo);
            hqos_port_fifo->in_fifo = NULL;
        }
        if (hqos_port_fifo->out_fifo)
        {
            hqos_fifo_free(hqos_port_fifo->out_fifo);
            hqos_port_fifo->out_fifo = NULL;
        }
    }
    return ret;
}

static void 
hqos_port_fifo_deinit(hqos_port_fifo_t *hqos_port_fifo)
{
    vlib_main_t *vm = vlib_get_main();
    u32 fifo_count = 0;
    u32 dequeue_count = 0;
    vlib_buffer_t **pkts = vec_new(vlib_buffer_t *, HQOS_PER_PORT_FIFO_LENGTH);
    u32 *free_buffer_indices = vec_new(u32, HQOS_PER_PORT_FIFO_LENGTH);

    if (hqos_port_fifo->in_fifo)
    {
        fifo_count = hqos_fifo_count(hqos_port_fifo->in_fifo);
        if (fifo_count > 0)
        {
            dequeue_count = hqos_fifo_dequeue_sc (hqos_port_fifo->in_fifo,
                                                fifo_count,
                                                (void *)pkts);

            if (dequeue_count != fifo_count)
            {
                clib_warning("Hqos in-fifo has not been dequeue fully completed yet!!");
            }

            vlib_get_buffer_indices(vm, pkts, free_buffer_indices, dequeue_count);
            vlib_buffer_free(vm, free_buffer_indices, dequeue_count);
        }

        hqos_fifo_free(hqos_port_fifo->in_fifo);
        hqos_port_fifo->in_fifo = NULL;
    }
    if (hqos_port_fifo->out_fifo)
    {
        if (hqos_fifo_count(hqos_port_fifo->out_fifo))
        {
            dequeue_count = hqos_fifo_dequeue_sc (hqos_port_fifo->out_fifo,
                                                fifo_count,
                                                (void *)pkts);

            if (dequeue_count != fifo_count)
            {
                clib_warning("Hqos out-fifo has not been dequeue fully completed yet!!");
            }

            vlib_get_buffer_indices(vm, pkts, free_buffer_indices, dequeue_count);
            vlib_buffer_free(vm, free_buffer_indices, dequeue_count);
        }

        hqos_fifo_free(hqos_port_fifo->out_fifo);
        hqos_port_fifo->out_fifo = NULL;
    }
}

int hqos_user_add (u8 * tag, u32 *user_id)
{
    hqos_main_t *hm = &hqos_main;

    hqos_user_t *user = NULL;

    if (pool_elts(hm->user_pool) > hm->hqos_max_user)
    {
        clib_warning ("%s: Maximum number of hqos users(No resources)", __FUNCTION__);
        return VNET_API_ERROR_UNSPECIFIED;
    }

    pool_get_zero (hm->user_pool, user);

    user->user_id = user - hm->user_pool;

    if (tag)
        clib_memcpy(user->tag, tag, sizeof(user->tag));

    *user_id = user->user_id;
    return 0;
}

int hqos_user_del (u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->dscp_to_tc);
    hash_free(user->dscp_to_color);
    hash_free(user->dot1p_to_tc);
    hash_free(user->dot1p_to_color);
    hash_free(user->mpls_exp_to_tc);
    hash_free(user->mpls_exp_to_color);

    pool_put_index (hm->user_pool, user_id);
    return 0;
}

int hqos_user_update_queue_mode(u32 user_id, u32 tc_queue_id, bool is_dwrr, u8 weight)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    if (tc_queue_id >= HQOS_SCHED_BE_QUEUES_PER_PIPE)
    {
        clib_warning ("%s :current hqos tc_queue_id must be les than %u", __FUNCTION__, HQOS_SCHED_BE_QUEUES_PER_PIPE);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    if (is_dwrr)
    {
        user->tc_queue_mode[tc_queue_id] = HQOS_TC_QUEUE_MODE_DWRR;
        user->tc_queue_weight[tc_queue_id] = weight;
    }
    else
    {
        user->tc_queue_mode[tc_queue_id] = HQOS_TC_QUEUE_MODE_SP;
        user->tc_queue_weight[tc_queue_id] = 1;
    }

    return 0;
}

int hqos_user_group_add (u8 * tag, u32 *user_group_id)
{
    hqos_main_t *hm = &hqos_main;

    hqos_user_group_t *user_group = NULL;

    if (pool_elts(hm->user_group_pool) > hm->hqos_max_user_group)
    {
        clib_warning ("%s: Maximum number of hqos user groups(No resources)", __FUNCTION__);
        return VNET_API_ERROR_UNSPECIFIED;
    }

    pool_get_zero (hm->user_group_pool, user_group);

    user_group->user_group_id = user_group - hm->user_group_pool;

    if (tag)
        clib_memcpy(user_group->tag, tag, sizeof(user_group->tag));

    *user_group_id = user_group->user_group_id;
    return 0;
}

int hqos_user_group_del (u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    pool_put_index (hm->user_group_pool, user_group_id);
    return 0;
}

int hqos_interface_update_user_group_user(u32 sw_if_index, u32 user_id, u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hw;
    uword *result = NULL;

    hw = vnet_get_hw_interface_or_null (hm->vnet_main, sw_if_index);

    if (!hw)
    {
        clib_warning ("%s :current sw_if_index not have hw-interfaces", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current user not create", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (user_group_id == UINT32_MAX)
    {
        result = hash_get(hw->user_to_ugroup, user_id);
        if (result)
            hash_unset(hw->user_to_ugroup, user_id);

        return 0;
    }

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current user group not create", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hash_set(hw->user_to_ugroup, user_id, user_group_id);

    return 0;
}

int hqos_interface_mapping_hqos_port(u32 sw_if_index, u32 hqos_port_id)
{
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hw;
    hqos_interface_hqos_mapping_t *interface_hqos_mapping;

    hw = vnet_get_hw_interface_or_null (hm->vnet_main, sw_if_index);

    if (!hw)
    {
        clib_warning ("%s :current sw_if_index not have hw-interfaces", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    vec_validate(hm->interface_mapping_vec, sw_if_index);

    interface_hqos_mapping = vec_elt_at_index(hm->interface_mapping_vec, sw_if_index);

    //reset
    if (hqos_port_id == (~0))
    {
        if (interface_hqos_mapping->hqos_port_id != (~0))
            hm->hqos_port_refcnt[interface_hqos_mapping->hqos_port_id]--;

        interface_hqos_mapping->hqos_port_id = hqos_port_id;
        return 0;
    }

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port not create", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    interface_hqos_mapping->hqos_port_id = hqos_port_id;

    hm->hqos_port_refcnt[hqos_port_id]++;

    return 0;
}

int hqos_interface_mapping_user_group_to_hqos_subport(u32 sw_if_index, u32 user_group_id, u32 hqos_subport_id)
{
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hw;
    hqos_interface_hqos_mapping_t *interface_hqos_mapping;
    uword *result = NULL;

    hw = vnet_get_hw_interface_or_null (hm->vnet_main, sw_if_index);

    if (!hw)
    {
        clib_warning ("%s :current sw_if_index not have hw-interfaces", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    vec_validate(hm->interface_mapping_vec, sw_if_index);

    interface_hqos_mapping = vec_elt_at_index(hm->interface_mapping_vec, sw_if_index);

    if (hqos_subport_id == UINT32_MAX)
    {
        result = hash_get(interface_hqos_mapping->user_group_id_to_hqos_subport_id, user_group_id);
        if (result)
            hash_unset(interface_hqos_mapping->user_group_id_to_hqos_subport_id, user_group_id);

        return 0;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hash_set(interface_hqos_mapping->user_group_id_to_hqos_subport_id,  user_group_id, hqos_subport_id);
    return 0;
}

int hqos_interface_mapping_user_to_hqos_pipe(u32 sw_if_index, u32 user_id, u32 hqos_pipe_id)
{
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hw;
    hqos_interface_hqos_mapping_t *interface_hqos_mapping;
    uword *result = NULL;

    hw = vnet_get_hw_interface_or_null (hm->vnet_main, sw_if_index);

    if (!hw)
    {
        clib_warning ("%s :current sw_if_index not have hw-interfaces", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    vec_validate(hm->interface_mapping_vec, sw_if_index);

    interface_hqos_mapping = vec_elt_at_index(hm->interface_mapping_vec, sw_if_index);

    if (hqos_pipe_id == UINT32_MAX)
    {
        result = hash_get(interface_hqos_mapping->user_id_to_hqos_pipe_id, user_id);
        if (result)
            hash_unset(interface_hqos_mapping->user_id_to_hqos_pipe_id, user_id);

        return 0;
    }

    if (hqos_pipe_id >= hm->hqos_node_max_pipe_per_subport)
    {
        clib_warning ("%s :current hqos_pipe_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hash_set(interface_hqos_mapping->user_id_to_hqos_pipe_id,  user_id, hqos_pipe_id);

    return 0;
}

int hqos_interface_enable_disable(u32 sw_if_index, bool is_enable)
{
    hqos_main_t *hm = &hqos_main;

    if (pool_is_free_index (hm->vnet_main->interface_main.sw_interfaces,
                sw_if_index))
        return VNET_API_ERROR_INVALID_SW_IF_INDEX;

    is_enable = ! !is_enable;

    if (clib_bitmap_get (hm->hqos_enabled_by_sw_if, sw_if_index) == is_enable)
        return 0;

    vnet_feature_enable_disable ("interface-output", "hqos-preprocess", sw_if_index, is_enable ? 1 : 0, 0, 0);
    hm->hqos_enabled_by_sw_if = clib_bitmap_set (hm->hqos_enabled_by_sw_if, sw_if_index, is_enable);

    return 0;
}

int hqos_port_add(u64 port_rate, 
                  u32 n_subports_per_port, 
                  u32 n_max_subport_profiles, 
                  u32 n_pipes_per_subport,
                  u32 n_queue_size,
                  u32 mtu, u32 frame_overhead, 
                  u32 *hqos_port_id)
{
    int rv;
    hqos_main_t *hm = &hqos_main;

    hqos_sched_port *hqos_port = NULL;

    u32 tmp_port_id = (~0);

    if (clib_bitmap_count_set_bits(hm->hqos_port_bitmap) > hm->hqos_node_port_max)
    {
        clib_warning ("%s: Maximum number of hqos port(No resources)", __FUNCTION__);
        return VNET_API_ERROR_UNSPECIFIED;
    }

    if (n_subports_per_port > hm->hqos_node_max_subport_per_port)
    {
        n_subports_per_port = hm->hqos_node_max_subport_per_port;
    }

    if (n_pipes_per_subport > hm->hqos_node_max_pipe_per_subport)
    {
        n_pipes_per_subport = hm->hqos_node_max_pipe_per_subport;
    }

    tmp_port_id = clib_bitmap_first_clear(hm->hqos_port_bitmap);

    //default subport profile params
    hqos_sched_subport_profile_params default_subport_profile_params = {
        .tb_rate = port_rate,
        .tb_size = HQOS_DEFAULT_BUCKET_SIZE,
        .tc_rate = { port_rate, port_rate, port_rate, 
                     port_rate, port_rate, port_rate, 
                     port_rate, port_rate, port_rate },
        .tc_period = HQOS_DEFAULT_TC_PERIOD,
    };

    hqos_sched_port_params port_params = {
        .rate = port_rate,
        .mtu = mtu,
        .frame_overhead = frame_overhead,
        .n_subports_per_port = n_subports_per_port,
        .n_max_subport_profiles = n_max_subport_profiles,
        .n_pipes_per_subport = n_pipes_per_subport,
        .n_queue_size = n_queue_size,
        .n_subport_profiles = 1,
        .subport_profiles = &default_subport_profile_params,
    };

    //create and config port
    hqos_port = hqos_sched_port_config(&port_params);

    if (!hqos_port)
    {
        clib_warning ("hqos_sched_port_config failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    //default pipe profile params
    hqos_sched_pipe_params default_pipe_params = {
        .tb_rate = port_rate,
        .tb_size = HQOS_DEFAULT_BUCKET_SIZE,
        .tc_rate = { port_rate, port_rate, port_rate, 
                     port_rate, port_rate, port_rate, 
                     port_rate, port_rate, port_rate },
        .tc_period = HQOS_DEFAULT_TC_PERIOD,
        .tc_ov_weight = HQOS_DEFAULT_BE_TC_OV_WEIGHT,
        .wrr_weights = {1, 1, 1, 1, 1, 1, 1, 1},
    };

    hqos_sched_subport_params default_subport_params = {
        .n_pipes_per_subport_enabled = n_pipes_per_subport,
        .qsize = { n_queue_size, n_queue_size, n_queue_size,
                   n_queue_size, n_queue_size, n_queue_size,
                   n_queue_size, n_queue_size, n_queue_size},
        .n_max_pipe_profiles = n_pipes_per_subport,
        .n_pipe_profiles = 1,
        .pipe_profiles = &default_pipe_params,
        .cman_params = NULL,
    };

    //config default subport 
    rv = hqos_sched_subport_config(hqos_port, 
                                   HQOS_DEFAULT_SUBPORT_ID, 
                                   &default_subport_params, 
                                   HQOS_DEFAULT_SUBPORT_PROFILE_ID);
    
    if (rv)
    {
        clib_warning ("hqos_sched_subport_config default failed", __FUNCTION__);
        hqos_sched_port_free(hqos_port);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }


    //config default pipe
    rv = hqos_sched_pipe_config(hqos_port, 
                                HQOS_DEFAULT_SUBPORT_ID, 
                                HQOS_DEFAULT_PIPE_ID,
                                HQOS_DEFAULT_PIPE_PROFILE_ID);
    if (rv)
    {
        clib_warning ("hqos_sched_pipe_config default failed", __FUNCTION__);
        hqos_sched_port_free(hqos_port);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    //Reset Counter
    vec_zero(hm->hqos_port_enqueue_drop[tmp_port_id].counters);
    vec_zero(hm->hqos_port_dequeue_drop[tmp_port_id].counters);

    //port fifo init
    rv = hqos_port_fifo_init(&hm->hqos_port_fifo_vec[tmp_port_id], HQOS_PER_PORT_FIFO_LENGTH);
    if (rv)
    {
        clib_warning ("hqos port fifo init failed", __FUNCTION__);
        hqos_sched_port_free(hqos_port);
        return VNET_API_ERROR_UNSPECIFIED;
    }

    hm->hqos_port_ptr_vec[tmp_port_id] = hqos_port;

    *hqos_port_id = tmp_port_id;

    clib_bitmap_set_no_check(hm->hqos_port_bitmap, tmp_port_id, 1);

    //Configure hqos sched core
    hqos_attach_sched_core(hm, tmp_port_id);

    return 0;
}

int hqos_port_del(u32 hqos_port_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        //stop preprocess
        clib_bitmap_set_no_check(hm->hqos_port_bitmap, hqos_port_id, 0);

        //Remove hoqs sched core
        hqos_detach_sched_core(hm, hqos_port_id);

        hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

        //port fifo deinit
        hqos_port_fifo_deinit(&hm->hqos_port_fifo_vec[hqos_port_id]);

        hqos_sched_port_free(hqos_port);

        hqos_port = NULL;
    }
    return 0;
}

int hqos_port_subport_profile_add(u32 hqos_port_id,
                                  u64 tb_rate,
                                  u64 tb_size,
                                  u64 *tc_rate,
                                  u64 tc_period,
                                  u32 *hqos_port_subport_profile_id)
{
    int rv, i;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    u32 tmp_port_subport_profile_id = (~0);

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    hqos_sched_subport_profile_params subport_profile_params = {
        .tb_rate = tb_rate,
        .tb_size = tb_size,
        .tc_period = tc_period,
    };

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        subport_profile_params.tc_rate[i] = tc_rate[i];
    }

    rv = hqos_sched_port_subport_profile_add(hqos_port,
                                             &subport_profile_params,
                                             &tmp_port_subport_profile_id);
    if (rv)
    {
        clib_warning ("hqos_sched_port_subport_profile_add add failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    *hqos_port_subport_profile_id = tmp_port_subport_profile_id;
    return 0;
}

int hqos_port_subport_profile_update(u32 hqos_port_id, 
                                     u32 hqos_port_subport_profile_id,
                                     u64 tb_rate,
                                     u64 tb_size,
                                     u64 *tc_rate,
                                     u64 tc_period)
{
    int rv, i;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    hqos_sched_subport_profile_params subport_profile_params = {
        .tb_rate = tb_rate,
        .tb_size = tb_size,
        .tc_period = tc_period,
    };

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        subport_profile_params.tc_rate[i] = tc_rate[i];
    }

    rv = hqos_sched_port_subport_profile_update(hqos_port,
                                             &subport_profile_params,
                                             hqos_port_subport_profile_id);
    if (rv)
    {
        clib_warning ("hqos_sched_port_subport_profile_update update failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    return 0;
}

int hqos_port_subport_config(u32 hqos_port_id,
                           u32 hqos_subport_id,
                           u32 hqos_port_subport_profile_id,
                           u32 n_pipes_per_subport_enabled,
                           u32 n_max_pipe_profiles,
                           u16 *qsize)
{
    int rv, i;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (hqos_port_subport_profile_id >= hqos_port->n_subport_profiles)
    {
        clib_warning ("%s :current hqos_port_subport_profile_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_sched_subport_params subport_params = {
        .n_pipes_per_subport_enabled = n_pipes_per_subport_enabled,
        .n_max_pipe_profiles = n_max_pipe_profiles,
        .n_pipe_profiles = 0,
        .pipe_profiles = NULL,
        .cman_params = NULL,
    };

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        subport_params.qsize[i] = qsize[i];
    }

    rv = hqos_sched_subport_config(hqos_port,
                                   hqos_subport_id,
                                   &subport_params,
                                   hqos_port_subport_profile_id);

    if (rv)
    {
        clib_warning ("hqos_sched_subport_config add failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    return 0;
}

int hqos_port_subport_update_profile(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_port_subport_profile_id)
{
    int rv;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (hqos_port_subport_profile_id >= hqos_port->n_subport_profiles)
    {
        clib_warning ("%s :current hqos_port_subport_profile_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    rv = hqos_sched_subport_config(hqos_port,
                                   hqos_subport_id,
                                   NULL,
                                   hqos_port_subport_profile_id);

    if (rv)
    {
        clib_warning ("hqos_sched_subport_config update failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    return 0;
}

int hqos_subport_pipe_profile_add(u32 hqos_port_id,
                                  u32 hqos_subport_id,
                                  u64 tb_rate,
                                  u64 tb_size, 
                                  u64 *tc_rate,
                                  u64 tc_period,
                                  u8 tc_ov_weight,
                                  u8 *wrr_weights,
                                  u32 *hqos_pipe_profile_id)
{
    int rv, i;

    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    u32 tmp_pipe_profile_id = (~0);

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    hqos_sched_pipe_params pipe_params = {
        .tb_rate = tb_rate,
        .tb_size = tb_size,
        .tc_period = tc_period,
        .tc_ov_weight = tc_ov_weight,
    };

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        pipe_params.tc_rate[i] = tc_rate[i];
    }

    for (i = 0; i < HQOS_SCHED_BE_QUEUES_PER_PIPE; i++)
    {
        pipe_params.wrr_weights[i] = wrr_weights[i];
    }

    rv = hqos_sched_subport_pipe_profile_add(hqos_port,
                                             hqos_subport_id,
                                             &pipe_params,
                                             &tmp_pipe_profile_id);
    if (rv)
    {
        clib_warning ("hqos_sched_subport_pipe_profile_add add failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    *hqos_pipe_profile_id = tmp_pipe_profile_id;
    return 0;
}

int hqos_subport_pipe_profile_update(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_pipe_profile_id,
                                     u64 tb_rate,
                                     u64 tb_size, 
                                     u64 *tc_rate,
                                     u64 tc_period,
                                     u8 tc_ov_weight,
                                     u8 *wrr_weights)
{
    int rv, i;

    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    hqos_sched_pipe_params pipe_params = {
        .tb_rate = tb_rate,
        .tb_size = tb_size,
        .tc_period = tc_period,
        .tc_ov_weight = tc_ov_weight,
    };

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        pipe_params.tc_rate[i] = tc_rate[i];
    }

    for (i = 0; i < HQOS_SCHED_BE_QUEUES_PER_PIPE; i++)
    {
        pipe_params.wrr_weights[i] = wrr_weights[i];
    }

    rv = hqos_sched_subport_pipe_profile_update(hqos_port,
                                             hqos_subport_id,
                                             &pipe_params,
                                             hqos_pipe_profile_id);
    if (rv)
    {
        clib_warning ("hqos_sched_subport_pipe_profile_update update failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }
    return 0;
}

int hqos_subport_pipe_update_profile(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_pipe_id,
                                     u32 hqos_pipe_profile_id)
{
    int rv;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return VNET_API_ERROR_INVALID_VALUE;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    rv = hqos_sched_pipe_config(hqos_port,
                                hqos_subport_id,
                                hqos_pipe_id,
                                hqos_pipe_profile_id);

    if (rv)
    {
        clib_warning ("hqos_sched_pipe_config update failed", __FUNCTION__);
        return VNET_API_ERROR_INVALID_ARGUMENT;
    }

    return 0;
}

void hqos_subport_stat_get(u32 hqos_port_id, u32 hqos_subport_id, hqos_sched_subport_stats *stat)
{
    u32 tc_ov = 0;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    hqos_sched_subport_read_stats(hqos_port, hqos_subport_id, stat, &tc_ov);

    return;
}

void hqos_queue_stat_get(u32 hqos_port_id, u32 hqos_subport_id, u32 hqos_pipe_id, u32 hqos_queue_id, hqos_sched_queue_stats *stat)
{
    u16 qlen = 0;
    u32 queue_id;
    hqos_main_t *hm = &hqos_main;
    hqos_sched_port *hqos_port = NULL;

    if (hqos_port_id >= hm->hqos_node_port_max)
    {
        clib_warning ("%s :current hqos port id invalid", __FUNCTION__);
        return;
    }

    if (!clib_bitmap_get_no_check(hm->hqos_port_bitmap, hqos_port_id))
    {
        clib_warning ("%s :current hqos port id not created", __FUNCTION__);
        return;
    }

    if (hqos_subport_id >= hm->hqos_node_max_subport_per_port)
    {
        clib_warning ("%s :current hqos_subport_id invalid", __FUNCTION__);
        return;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    queue_id = (hqos_subport_id << (hqos_port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2)) |
               (hqos_pipe_id  << (hqos_port->n_pipes_per_subport_log2) ) |
                hqos_queue_id;

    hqos_sched_queue_read_stats(hqos_port, queue_id, stat, &qlen);

    return;
}

int hqos_user_set_dscp_tc_map(u32 user_id, u8 dscp, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->dscp_to_tc, dscp, tc);
    return 0;
}

int hqos_user_set_dscp_color_map(u32 user_id, u8 dscp, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->dscp_to_color, dscp, color);
    return 0;
}

int hqos_user_set_dot1p_tc_map(u32 user_id, u8 dot1p, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->dot1p_to_tc, dot1p, tc);
    return 0;
}

int hqos_user_set_dot1p_color_map(u32 user_id, u8 dot1p, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->dot1p_to_color, dot1p, color);
    return 0;
}

int hqos_user_set_mpls_exp_tc_map(u32 user_id, u8 mpls_exp, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->mpls_exp_to_tc, mpls_exp, tc);
    return 0;
}

int hqos_user_set_mpls_exp_color_map(u32 user_id, u8 mpls_exp, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_set(user->mpls_exp_to_color, mpls_exp, color);
    return 0;
}

int hqos_user_remove_dscp_tc_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->dscp_to_tc);
    user->dscp_to_tc = NULL;
    return 0;
}

int hqos_user_remove_dscp_color_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->dscp_to_color);
    user->dscp_to_color = NULL;
    return 0;
}

int hqos_user_remove_dot1p_tc_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->dot1p_to_tc);
    user->dot1p_to_tc = NULL;
    return 0;
}

int hqos_user_remove_dot1p_color_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->dot1p_to_color);
    user->dot1p_to_color = NULL;
    return 0;
}

int hqos_user_remove_mpls_exp_tc_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->mpls_exp_to_tc);
    user->mpls_exp_to_tc = NULL;
    return 0;
}

int hqos_user_remove_mpls_exp_color_map(u32 user_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_t *user = NULL;

    if (pool_is_free_index(hm->user_pool, user_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user = pool_elt_at_index(hm->user_pool, user_id);

    hash_free(user->mpls_exp_to_color);
    user->mpls_exp_to_color = NULL;
    return 0;
}

int hqos_user_group_set_dscp_tc_map(u32 user_group_id, u8 dscp, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->dscp_to_tc, dscp, tc);
    return 0;
}

int hqos_user_group_set_dscp_color_map(u32 user_group_id, u8 dscp, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->dscp_to_color, dscp, color);
    return 0;
}

int hqos_user_group_set_dot1p_tc_map(u32 user_group_id, u8 dot1p, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->dot1p_to_tc, dot1p, tc);
    return 0;
}

int hqos_user_group_set_dot1p_color_map(u32 user_group_id, u8 dot1p, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->dot1p_to_color, dot1p, color);
    return 0;
}

int hqos_user_group_set_mpls_exp_tc_map(u32 user_group_id, u8 mpls_exp, u8 tc)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->mpls_exp_to_tc, mpls_exp, tc);
    return 0;
}

int hqos_user_group_set_mpls_exp_color_map(u32 user_group_id, u8 mpls_exp, u8 color)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user group id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_set(user_group->mpls_exp_to_color, mpls_exp, color);
    return 0;
}

int hqos_user_group_remove_dscp_tc_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->dscp_to_tc);
    user_group->dscp_to_tc = NULL;
    return 0;
}

int hqos_user_group_remove_dscp_color_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->dscp_to_color);
    user_group->dscp_to_color = NULL;
    return 0;
}

int hqos_user_group_remove_dot1p_tc_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->dot1p_to_tc);
    user_group->dot1p_to_tc = NULL;
    return 0;
}

int hqos_user_group_remove_dot1p_color_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->dot1p_to_color);
    user_group->dot1p_to_color = NULL;
    return 0;
}

int hqos_user_group_remove_mpls_exp_tc_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->mpls_exp_to_tc);
    user_group->mpls_exp_to_tc = NULL;
    return 0;
}

int hqos_user_group_remove_mpls_exp_color_map(u32 user_group_id)
{
    hqos_main_t *hm = &hqos_main;
    hqos_user_group_t *user_group = NULL;

    if (pool_is_free_index(hm->user_group_pool, user_group_id))
    {
        clib_warning ("%s :current hqos user id is free", __FUNCTION__);
        return 0;
    }

    user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

    hash_free(user_group->mpls_exp_to_color);
    user_group->mpls_exp_to_color = NULL;
    return 0;
}

/*
 * HW Interface Add/Del callback
 */

static clib_error_t *
hqos_hw_interface_add_del (vnet_main_t * vnm, u32 hw_if_index, u32 is_add)
{
    hqos_main_t *hm = &hqos_main;
    hqos_interface_hqos_mapping_t *intf_hqos_map;

    vnet_hw_interface_t *hw = NULL;

    u32 next_index;
    vlib_node_t *tx_node;

    if (is_add)
    {
        vec_validate(hm->interface_mapping_vec, hw_if_index);
        intf_hqos_map = vec_elt_at_index(hm->interface_mapping_vec, hw_if_index);
        memset(intf_hqos_map, 0, sizeof(hqos_interface_hqos_mapping_t));
        intf_hqos_map->hqos_port_id = (~0);

        /* Register the tx node of hw into the post-processing node */ 
        hw = vnet_get_hw_interface(vnm, hw_if_index);

        char *tx_node_name = (char *)format(0, "%v-tx", hw->name);
        tx_node = vlib_get_node_by_name(vnm->vlib_main, (u8 *)tx_node_name);

        if (tx_node != NULL)
        {
            next_index = vlib_node_add_next(vnm->vlib_main, hqos_postprocess_node.index, tx_node->index);
            vec_validate(hm->sw_if_tx_node_next_index, hw->sw_if_index);
            hm->sw_if_tx_node_next_index[hw->sw_if_index] = next_index;
        }
    }
    else
    {
        intf_hqos_map = vec_elt_at_index(hm->interface_mapping_vec, hw_if_index);
        hash_free(intf_hqos_map->user_group_id_to_hqos_subport_id);
        hash_free(intf_hqos_map->user_id_to_hqos_pipe_id);

        /* Reset Register the tx node of hw into the post-processing node */
        hm->sw_if_tx_node_next_index[hw->sw_if_index] = 0;
    }

    return 0;
}
VNET_HW_INTERFACE_ADD_DEL_FUNCTION (hqos_hw_interface_add_del);

/*
 * hqos_init
 */
static void hqos_default_user(hqos_main_t *hm)
{
    hqos_user_t *user = NULL;
    pool_get_zero (hm->user_pool, user);

    user->user_id = user - hm->user_pool;

    sprintf((char *)user->tag, "%s", "default_user");
}

static void hqos_default_user_group(hqos_main_t *hm)
{
    hqos_user_group_t *user_group = NULL;
    pool_get_zero (hm->user_group_pool, user_group);

    user_group->user_group_id = user_group - hm->user_group_pool;

    sprintf((char *)user_group->tag, "%s", "default_user_group");
}

clib_error_t *
hqos_init (vlib_main_t * vm)
{
    hqos_main_t *hm = &hqos_main;
    clib_error_t *error = 0;
    uword *thread_worker, *thread_hqos;
    vlib_thread_registration_t *tr_worker, *tr_hqos;

    vlib_thread_main_t *tm = vlib_get_thread_main ();

    hqos_combined_counter_t *hcc;

    memset (hm, 0, sizeof (*hm));

    hm->hqos_enabled_by_sw_if = 0;
    hm->hqos_node_port_max = HQOS_NODE_PORT_MAX;
    hm->hqos_node_max_subport_per_port = HQOS_NODE_MAX_SUBPORT_PER_PORT;
    hm->hqos_node_max_pipe_per_subport = HQOS_NODE_MAX_PIPE_PER_SUBPORT;

    hm->hqos_max_user = HQOS_MAX_USER;
    hm->hqos_max_user_group = HQOS_MAX_USER_GROUP;
    hm->hqos_max_user_group_per_port = HQOS_MAX_USER_GROUP_PER_PORT;
    hm->hqos_max_user_per_user_group = HQOS_MAX_USER_PER_USER_GROUP;

    pool_alloc_aligned(hm->user_pool, hm->hqos_max_user, CLIB_CACHE_LINE_BYTES);
    pool_alloc_aligned(hm->user_group_pool, hm->hqos_max_user_group, CLIB_CACHE_LINE_BYTES);

    clib_bitmap_alloc(hm->hqos_port_bitmap, hm->hqos_node_port_max);

    hm->hqos_port_ptr_vec = vec_new(hqos_sched_port *, hm->hqos_node_port_max);
    vec_zero(hm->hqos_port_ptr_vec);

    //port fifo
    hm->hqos_port_fifo_vec = vec_new(hqos_fifo_t *, hm->hqos_node_port_max);
    vec_zero(hm->hqos_port_fifo_vec);

    //hqos_node_port refcnt
    vec_validate(hm->hqos_port_refcnt, hm->hqos_node_port_max);

    /*
     * core mapping
     */
    vec_validate(hm->hqos_thread_worker_refcnt, tm->n_vlib_mains);
    /* 
     * find out which dedicated cpus will be used for hqos sched thread 
     */
    vec_validate(hm->hqos_port_sched_mapping_thread, hm->hqos_node_port_max);
    vec_set(hm->hqos_port_sched_mapping_thread, (~0));
    thread_hqos = hash_get_mem (tm->thread_registrations_by_name, "hqos-sched");
    tr_hqos = thread_hqos ? (vlib_thread_registration_t *) thread_hqos[0] : 0;
    if (tr_hqos && tr_hqos->count > 0)
    {
        hm->hqos_sched_thread_first = tr_hqos->first_index;
        hm->hqos_sched_thread_num = tr_hqos->count;
    }

    /* 
     * find out which share cpus will be used for hqos sched thread 
     */
    vec_validate(hm->hqos_port_sched_mapping_worker, hm->hqos_node_port_max);
    vec_set(hm->hqos_port_sched_mapping_worker, (~0));
    thread_worker = hash_get_mem (tm->thread_registrations_by_name, "workers");
    tr_worker = thread_worker ? (vlib_thread_registration_t *) thread_worker[0] : 0;
    if (tr_worker && tr_worker->count > 0)
    {
        hm->hqos_sched_worker_num = tr_worker->count;
        hm->hqos_sched_worker_first = tr_worker->first_index;
    }

    /* Counter */

    vec_validate (hm->hqos_port_enqueue_drop, hm->hqos_node_port_max);
    vec_foreach (hcc, hm->hqos_port_enqueue_drop)
    {
        vec_validate(hcc->counters, tm->n_thread_stacks);
        vec_zero(hcc->counters);
    }
    vec_validate (hm->hqos_port_dequeue_drop, hm->hqos_node_port_max);
    vec_foreach (hcc, hm->hqos_port_dequeue_drop)
    {
        vec_validate(hcc->counters, tm->n_thread_stacks);
        vec_zero(hcc->counters);
    }

    /* prealloc default user and default user group*/
    hqos_default_user(hm);
    hqos_default_user_group(hm);

    hm->vnet_main = vnet_get_main ();
    hm->vlib_main = vm;

    hqos_vlib_main = vm;
    error = hqos_plugin_api_hookup (vm);

    return error;
}

VLIB_INIT_FUNCTION (hqos_init);

VLIB_PLUGIN_REGISTER() = {
  .version = VPP_BUILD_VER,
  .description = "Hierarchical Quality of Service",
};
