/*
 * hqos.h: types/functions for HQOS.
 *
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

#ifndef included_hqos_h
#define included_hqos_h

#include <vnet/vnet.h>
#include <vppinfra/pool.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/sparse_vec.h>
#include <vppinfra/hash.h>

#include <hqos/hqos.api_enum.h>
#include "hqos/sched/sched.h"

#include <hqos/fifo/fifo.h>

//#define HQOS_DEBUG

#define HQOS_NODE_PORT_MAX                (128)
#define HQOS_NODE_MAX_SUBPORT_PER_PORT    (8)
#define HQOS_NODE_MAX_PIPE_PER_SUBPORT    (4096)

#define HQOS_MAX_USER                     (1 << 16) //64k
#define HQOS_MAX_USER_GROUP               (128)
#define HQOS_MAX_USER_GROUP_PER_PORT      (HQOS_NODE_MAX_SUBPORT_PER_PORT)
#define HQOS_MAX_USER_PER_USER_GROUP      (HQOS_NODE_MAX_PIPE_PER_SUBPORT)

#define HQOS_DEFAULT_BUCKET_SIZE          (16 * 1000 * 1000) //16MB
#define HQOS_DEFAULT_TC_PERIOD            (10) //10ms
#define HQOS_DEFAULT_SUBPORT_TC_QSIZE     (512)
#define HQOS_DEFAULT_BE_TC_OV_WEIGHT      (1)

#define HQOS_DEFAULT_SUBPORT_ID           (0)
#define HQOS_DEFAULT_SUBPORT_PROFILE_ID   (0)
#define HQOS_DEFAULT_PIPE_ID              (0)
#define HQOS_DEFAULT_PIPE_PROFILE_ID      (0)

#define HQOS_PER_PORT_FIFO_LENGTH     (16384)

typedef enum _hqos_tc_queue_mode
{
    HQOS_TC_QUEUE_MODE_SP,
    HQOS_TC_QUEUE_MODE_DWRR,
    HQOS_TC_QUEUE_MODE_CNT,
}__attribute__ ((__packed__)) hqos_tc_queue_mode_e;

typedef struct _hqos_user
{
    u32 user_id;

    /* 
     * tc to hqos queue 
     * in hqos sched. 
     * Preset each pipe to have 16 queues and 9 TCs.
     * The queue with TC as BE is the last 8 queues.
     *
     * A design:
     *  These 16 queues are mapped externally to 8 queues.
     * When the queue mode is SP, use the first 8 queues for mapping. 
     * When the queue mode is DWRR, use the last 8 queues for mapping
     *
     * default is SP
     */
    hqos_tc_queue_mode_e tc_queue_mode[HQOS_SCHED_BE_QUEUES_PER_PIPE];
    u8 tc_queue_weight[HQOS_SCHED_BE_QUEUES_PER_PIPE];

    u8 tag[32];

} hqos_user_t;

STATIC_ASSERT ((sizeof (hqos_user_t) <= CLIB_CACHE_LINE_BYTES),
	       "hqos user fits in one cacheline");

typedef struct _hqos_user_group
{
    u32 user_group_id;
    u8 tag[32];
} hqos_user_group_t;

STATIC_ASSERT ((sizeof (hqos_user_group_t) <= CLIB_CACHE_LINE_BYTES),
	       "hqos user group fits in one cacheline");

typedef struct _hqos_interface_hqos_mapping
{
    u32 hqos_port_id;

    /* hash by user mapping*/
    uword *user_group_id_to_hqos_subport_id;
    uword *user_id_to_hqos_pipe_id;

} hqos_interface_hqos_mapping_t;

typedef struct _hqos_port_fifo
{
    hqos_fifo_t *in_fifo;
    hqos_fifo_t *out_fifo;

} hqos_port_fifo_t;

typedef struct
{
    u64 *counters;
} hqos_combined_counter_t;

typedef struct _hqos_main
{
    u32 hqos_node_port_max;
    u32 hqos_node_max_subport_per_port;
    u32 hqos_node_max_pipe_per_subport;

    u32 hqos_max_user;
    u32 hqos_max_user_group;
    u32 hqos_max_user_group_per_port;
    u32 hqos_max_user_per_user_group;

    /* Graph node state */
    uword *hqos_enabled_by_sw_if;

    /* Hqos user pool */
    hqos_user_t *user_pool;
    hqos_user_group_t *user_group_pool;

    /* Hqos Scheduler Node */
    uword *hqos_port_bitmap; //ID allocator
    hqos_sched_port **hqos_port_ptr_vec;

    hqos_port_fifo_t *hqos_port_fifo_vec;

    /* Interface hqos scheduler node mapping */
    u32 *hqos_port_refcnt;
    hqos_interface_hqos_mapping_t  *interface_mapping_vec;

    u8 *hqos_thread_worker_refcnt;
    /* Hqos sched private thread bind info */
    u32 hqos_sched_thread_first;
    u32 hqos_sched_thread_num;
    u32 *hqos_port_sched_mapping_thread;

    /* Hqos sched worker bind info */
    u32 hqos_sched_worker_first;
    u32 hqos_sched_worker_num;
    u32 *hqos_port_sched_mapping_worker;

    /* Hqos PostProcess next_index recored */
    u16 *sw_if_tx_node_next_index;

    /* Hqos port drop counter */
    hqos_combined_counter_t *hqos_port_enqueue_drop;
    hqos_combined_counter_t *hqos_port_dequeue_drop;

    /* convenience */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    /* API message id base */
    u16 msg_id_base;

} hqos_main_t;
extern hqos_main_t hqos_main;


typedef vl_counter_hqos_enum_t hqos_error_t;

/* Format or trace*/
typedef struct _hqos_preprocess_trace
{
    u32 state;

    u32 pkt_len;
    u32 user_id;
    u32 user_group_id;
    u32 tc;
    u32 color;
    u32 hqos_port_id;
    u32 hqos_subport_id;
    u32 hqos_pipe_id;
    u32 hqos_queue_id;
} hqos_preprocess_trace_t;

typedef struct _hqos_postprocess_trace
{
    u32 sw_if_index;
    u32 tc;
    u8  use_tc;
} hqos_postprocess_trace_t;


/* Format */
u8 * format_hqos_preprocess_trace(u8 *s, va_list *args);
u8 * format_hqos_postprocess_trace(u8 *s, va_list *args);
u8 * format_hqos_tc_queue_mode(u8 *s, va_list *args);
u8 * format_hqos_port(u8 *s, va_list *args);
u8 * format_hqos_port_detail(u8 *s, va_list *args);

/* API */
clib_error_t *hqos_plugin_api_hookup (vlib_main_t * vm);

/* Control Function */
//hqos interface feature Contorl
int hqos_interface_enable_disable(u32 sw_if_index, bool is_enable);

//hqos user Control
int hqos_user_add (u8 * tag, u32 * user_id);
int hqos_user_del (u32 user_id);
int hqos_user_group_add (u8 * tag, u32 *user_group_id);
int hqos_user_group_del (u32 user_group_id);
int hqos_interface_update_user_group_user(u32 sw_if_index, u32 user_id, u32 user_group_id);

//hqos scheduler node Control

int hqos_interface_mapping_hqos_port(u32 sw_if_index, u32 hqos_port_id);
int hqos_interface_mapping_user_group_to_hqos_subport(u32 sw_if_index, u32 user_group_id, u32 hqos_subport_id);
int hqos_interface_mapping_user_to_hqos_pipe(u32 sw_if_index, u32 user_id, u32 hqos_pipe_id);

int hqos_port_add(u64 port_rate,
                  u32 n_subports_per_port, 
                  u32 n_max_subport_profiles, 
                  u32 n_pipes_per_subport,
                  u32 mtu, u32 frame_overhead, 
                  u32 *hqos_port_id);
int hqos_port_del(u32 hqos_port_id);
int hqos_user_update_queue_mode(u32 user_id, u32 tc_queue_id, bool is_dwrr, u8 weight);

int hqos_port_subport_profile_add(u32 hqos_port_id, 
                                  u64 tb_rate, 
                                  u64 tb_size, 
                                  u64 *tc_rate, 
                                  u64 tc_period,
                                  u32 *hqos_port_subport_profile_id);
int hqos_port_subport_profile_update(u32 hqos_port_id, 
                                     u32 hqos_port_subport_profile_id,
                                     u64 tb_rate,
                                     u64 tb_size,
                                     u64 *tc_rate,
                                     u64 tc_period);
int hqos_port_subport_config(u32 hqos_port_id,
                             u32 hqos_subport_id,
                             u32 hqos_port_subport_profile_id,
                             u32 n_pipes_per_subport_enabled,
                             u32 n_max_pipe_profiles,
                             u16 *qsize);
int hqos_port_subport_update_profile(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_port_subport_profile_id);

int hqos_subport_pipe_profile_add(u32 hqos_port_id,
                                  u32 hqos_subport_id,
                                  u64 tb_rate,
                                  u64 tb_size, 
                                  u64 *tc_rate,
                                  u64 tc_period,
                                  u8 tc_ov_weight,
                                  u8 *wrr_weights,
                                  u32 *hqos_pipe_profile_id);
int hqos_subport_pipe_profile_update(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_pipe_profile_id,
                                     u64 tb_rate,
                                     u64 tb_size, 
                                     u64 *tc_rate,
                                     u64 tc_period,
                                     u8 tc_ov_weight,
                                     u8 *wrr_weights);
int hqos_subport_pipe_update_profile(u32 hqos_port_id,
                                     u32 hqos_subport_id,
                                     u32 hqos_pipe_id,
                                     u32 hqos_pipe_profile_id);

void hqos_subport_stat_get(u32 hqos_port_id, 
                           u32 hqos_subport_id, 
                           hqos_sched_subport_stats *stat);
void hqos_queue_stat_get(u32 hqos_port_id, 
                         u32 hqos_subport_id, 
                         u32 hqos_pipe_id, 
                         u32 hqos_queue_id, 
                         hqos_sched_queue_stats *stat);

/* inline func */

static_always_inline u32 
hqos_get_queue_id(hqos_sched_port *hqos_port, u32 hqos_subport_id, u32 hqos_pipe_id, u32 hqos_queue_id)
{
    return (hqos_subport_id << (hqos_port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2)) |
           (hqos_pipe_id  << (hqos_port->n_pipes_per_subport_log2) ) | 
           hqos_queue_id;
}


/* node */
extern vlib_node_registration_t hqos_sched_node;
extern vlib_node_registration_t hqos_postprocess_node;
#endif /* included_hqos_h */
