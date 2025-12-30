/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#ifndef included_hqos_sched_priv_h
#define included_hqos_sched_priv_h

#ifdef __cplusplus
extern "C" {
#endif

#include "hqos/sched/sched.h"

//#define HQOS_SCHED_DEBUG

#ifdef HQOS_SCHED_DEBUG

static_always_inline int
hqos_sched_port_queue_is_empty(hqos_sched_subport *subport, u32 qindex)
{
    hqos_sched_queue *queue = subport->queue + qindex;

    return queue->qr == queue->qw;
}

static_always_inline void
hqos_debug_check_queue_slab(hqos_sched_subport *subport, u32 bmp_pos, u64 bmp_slab)
{
    u64 mask;
    u32 i, panic;

    if (bmp_slab == 0)
        clib_panic("Empty slab at position %u\n", bmp_pos);

    panic = 0;
    for (i = 0, mask = 1; i < 64; i++, mask <<= 1) 
    {
        if (mask & bmp_slab) {
            if (hqos_sched_port_queue_is_empty(subport, bmp_pos + i)) {
                clib_warning("Queue %u (slab offset %u) is empty\n", bmp_pos + i, i);
                panic = 1;
            }
        }
    }

    if (panic)
        clib_panic("Empty queues in slab 0x%" PRIx64 "starting at position %u\n", bmp_slab, bmp_pos);
}

#endif /* HQOS_SCHED_DEBUG */


/*
 * inline function
 */

static_always_inline u32 
hqos_sched_subport_pipe_queues(hqos_sched_subport *subport)
{
    return HQOS_SCHED_QUEUES_PER_PIPE * subport->n_pipes_per_subport_enabled;
}

static_always_inline vlib_buffer_t **
hqos_sched_subport_pipe_qbase(hqos_sched_subport *subport, u32 qindex)
{
    u32 pindex = qindex >> HQOS_SCHED_QUEUES_PER_PIPE_LOG2;
    u32 qpos = qindex & (HQOS_SCHED_QUEUES_PER_PIPE - 1);

    return (subport->queue_array + pindex *
        subport->qsize_sum + subport->qsize_add[qpos]);
}

static_always_inline u16 
hqos_sched_subport_pipe_qsize(hqos_sched_port *port, hqos_sched_subport *subport, u32 qindex)
{
    uint32_t tc = port->pipe_tc[qindex & (HQOS_SCHED_QUEUES_PER_PIPE - 1)];

    return subport->qsize[tc];
}

static_always_inline u32 
hqos_sched_port_queues_per_port(hqos_sched_port *port)
{
    u32 n_queues = 0, i;

    for (i = 0; i < port->n_subports_per_port; i++)
    {
        if (port->subports[i])
            n_queues += hqos_sched_subport_pipe_queues(port->subports[i]);
    }

    return n_queues;
}

static_always_inline u16 
hqos_sched_port_pipe_queue(hqos_sched_port *port, u32 traffic_class)
{
    u16 pipe_queue = port->pipe_queue[traffic_class];

    return pipe_queue;
}

static_always_inline u8 
hqos_sched_port_pipe_tc(hqos_sched_port *port, u32 qindex)
{
    u8 pipe_tc = port->pipe_tc[qindex & (HQOS_SCHED_QUEUES_PER_PIPE - 1)];

    return pipe_tc;
}

static_always_inline u8
hqos_sched_port_tc_queue(hqos_sched_port *port, u32 qindex)
{
    u8 tc_queue = port->tc_queue[qindex & (HQOS_SCHED_QUEUES_PER_PIPE - 1)];

    return tc_queue;
}

static_always_inline u64
hqos_sched_time_ms_to_bytes(u64 time_ms, u64 rate)
{
    u64 time = time_ms;

    time = (time * rate) / 1000;

    return time;
}

static_always_inline void
hqos_sched_subport_free(hqos_sched_port *port, hqos_sched_subport *subport)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    u32 n_subport_pipe_queues;
    u32 qindex;

    if (subport == NULL)
        return;

    n_subport_pipe_queues = hqos_sched_subport_pipe_queues(subport);

    /* Free enqueued vlib_buffer */
    for (qindex = 0; qindex < n_subport_pipe_queues; qindex++) 
    {
        vlib_buffer_t **bufs = hqos_sched_subport_pipe_qbase(subport, qindex);
        u16 qsize = hqos_sched_subport_pipe_qsize(port, subport, qindex);
        if (qsize != 0) {
            hqos_sched_queue *queue = subport->queue + qindex;
            u16 qr = queue->qr & (qsize - 1);
            u16 qw = queue->qw & (qsize - 1);

            for (; qr != qw; qr = (qr + 1) & (qsize - 1))
                vlib_buffer_free_one(vm, vlib_get_buffer_index(vm, bufs[qr]));
        }
    }

    clib_mem_free(subport);
}

static_always_inline u32 
hqos_sched_port_qindex(hqos_sched_port *port, 
                       u32 subport, u32 pipe, u32 traffic_class, u32 queue)
{
    return ((subport & (port->n_subports_per_port - 1)) <<
        (port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2)) |
        ((pipe &
        (port->subports[subport]->n_pipes_per_subport_enabled - 1)) << HQOS_SCHED_QUEUES_PER_PIPE_LOG2) |
        ((hqos_sched_port_pipe_queue(port, traffic_class) + queue) &
        (HQOS_SCHED_QUEUES_PER_PIPE - 1));
}

static_always_inline void
hqos_sched_port_update_subport_stats(hqos_sched_port *port,
                                     hqos_sched_subport *subport,
                                     u32 qindex,
                                     vlib_buffer_t *pkt)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    u32 tc_index = hqos_sched_port_pipe_tc(port, qindex);
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt);

    subport->stats.n_pkts_tc[tc_index] += 1;
    subport->stats.n_bytes_tc[tc_index] += pkt_len;
}

static_always_inline void
hqos_sched_port_update_subport_stats_on_drop(hqos_sched_port *port,
                                             hqos_sched_subport *subport,
                                             u32 qindex,
                                             vlib_buffer_t *pkt,
                                             u32 n_pkts_cman_dropped)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    u32 tc_index = hqos_sched_port_pipe_tc(port, qindex);
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt);

    subport->stats.n_pkts_tc_dropped[tc_index] += 1;
    subport->stats.n_bytes_tc_dropped[tc_index] += pkt_len;
    subport->stats.n_pkts_cman_dropped[tc_index] += n_pkts_cman_dropped;
}

static_always_inline void
hqos_sched_port_update_queue_stats(hqos_sched_subport *subport,
                                   u32 qindex,
                                   vlib_buffer_t *pkt)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    hqos_sched_queue_extra *qe = subport->queue_extra + qindex;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt);

    qe->stats.n_pkts += 1;
    qe->stats.n_bytes += pkt_len;
}

static_always_inline void
hqos_sched_port_update_queue_stats_on_drop(hqos_sched_subport *subport,
                                           u32 qindex,
                                           vlib_buffer_t *pkt,
                                           u32 n_pkts_cman_dropped)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    hqos_sched_queue_extra *qe = subport->queue_extra + qindex;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt);

    qe->stats.n_pkts_dropped += 1;
    qe->stats.n_bytes_dropped += pkt_len;
    if (subport->cman_enabled)
        qe->stats.n_pkts_cman_dropped += n_pkts_cman_dropped;
}

static_always_inline int
hqos_sched_port_cman_drop(hqos_sched_port *port,
                          hqos_sched_subport *subport,
                          vlib_buffer_t *pkt,
                          u32 qindex,
                          u16 qlen)
{
    if (!subport->cman_enabled)
        return 0;

    vlib_main_t *vm = hqos_vlib_get_main ();

    hqos_sched_queue_extra *qe;
    u32 tc_index;

    tc_index = hqos_sched_port_pipe_tc(port, qindex);
    qe = subport->queue_extra + qindex;

    /* RED */
    if (subport->cman == HQOS_SCHED_CMAN_RED) {
        hqos_red_config *red_cfg;
        hqos_red *red;
        hqos_color color;

        color = vlib_buffer_hqos_color_get(pkt);
        red_cfg = &subport->red_config[tc_index][color];

        if ((red_cfg->min_th | red_cfg->max_th) == 0)
            return 0;

        red = &qe->red;

        return hqos_red_enqueue(red_cfg, red, qlen, port->time);
    }

    /* PIE */
    hqos_pie_config *pie_cfg = &subport->pie_config[tc_index];
    hqos_pie *pie = &qe->pie;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt);

    return hqos_pie_enqueue(pie_cfg, pie, qlen, pkt_len, port->time_cpu_cycles);
}

static_always_inline void
hqos_sched_port_red_set_queue_empty_timestamp(hqos_sched_port *port,
                                              hqos_sched_subport *subport, 
                                              u32 qindex)
{
    if (subport->cman_enabled && subport->cman == HQOS_SCHED_CMAN_RED) {
        hqos_sched_queue_extra *qe = subport->queue_extra + qindex;
        hqos_red *red = &qe->red;

        hqos_red_mark_queue_empty(red, port->time);
    }
}

static_always_inline void
hqos_sched_port_pie_dequeue(hqos_sched_subport *subport,
                            u32 qindex, u32 pkt_len, u32 time) 
{
    if (subport->cman_enabled && subport->cman == HQOS_SCHED_CMAN_PIE) {
        hqos_sched_queue_extra *qe = subport->queue_extra + qindex;
        hqos_pie *pie = &qe->pie;

        /* Update queue length */
        pie->qlen -= 1;
        pie->qlen_bytes -= pkt_len;

        hqos_pie_dequeue(pie, pkt_len, time);
    }
}

static_always_inline hqos_sched_subport *
hqos_sched_port_subport(hqos_sched_port *port,
                        vlib_buffer_t *pkt)
{
    u32 queue_id = vlib_buffer_hqos_queue_get(pkt);
    u32 subport_id = queue_id >> (port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2);

    return port->subports[subport_id];
}

static_always_inline u32 
hqos_sched_port_enqueue_qptrs_prefetch0(hqos_sched_subport *subport,
                                        vlib_buffer_t *pkt, 
                                        u32 subport_qmask)
{
    hqos_sched_queue *q;
    hqos_sched_queue_extra *qe;
    u32 qindex = vlib_buffer_hqos_queue_get(pkt);
    u32 subport_queue_id = subport_qmask & qindex;

    q = subport->queue + subport_queue_id;
    clib_prefetch_load(q);
    qe = subport->queue_extra + subport_queue_id;
    clib_prefetch_load(qe);

    return subport_queue_id;
}

static_always_inline void
hqos_sched_port_enqueue_qwa_prefetch0(hqos_sched_port *port,
                                      hqos_sched_subport *subport,
                                      u32 qindex,
                                      vlib_buffer_t **qbase)
{
    hqos_sched_queue *q;
    vlib_buffer_t **q_qw;
    u16 qsize;

    q = subport->queue + qindex;
    qsize = hqos_sched_subport_pipe_qsize(port, subport, qindex);
    q_qw = qbase + (q->qw & (qsize - 1));

    clib_prefetch_load(q_qw);

    hqos_bitmap_prefetch0(subport->bmp, qindex);
}

static_always_inline int
hqos_sched_port_enqueue_qwa(hqos_sched_port *port,
                            hqos_sched_subport *subport,
                            u32 qindex,
                            vlib_buffer_t **qbase,
                            vlib_buffer_t *pkt)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    hqos_sched_queue *q;
    u16 qsize;
    u16 qlen;

    q = subport->queue + qindex;
    qsize = hqos_sched_subport_pipe_qsize(port, subport, qindex);
    qlen = q->qw - q->qr;

    /* Drop the packet (and update drop stats) when queue is full */
    if (PREDICT_FALSE(hqos_sched_port_cman_drop(port, subport, pkt, qindex, qlen) ||
             (qlen >= qsize))) 
    {
        vlib_buffer_free_one (vm, vlib_get_buffer_index(vm, pkt));
        hqos_sched_port_update_subport_stats_on_drop(port, subport, qindex, pkt, qlen < qsize);
        hqos_sched_port_update_queue_stats_on_drop(subport, qindex, pkt, qlen < qsize);
        return 0;
    }

    /* Enqueue packet */
    qbase[q->qw & (qsize - 1)] = pkt;
    q->qw++;

    /* Activate queue in the subport bitmap */
    hqos_bitmap_set(subport->bmp, qindex);

    /* Statistics */
    hqos_sched_port_update_subport_stats(port, subport, qindex, pkt);
    hqos_sched_port_update_queue_stats(subport, qindex, pkt);

    return 1;
}

static_always_inline u64 
hqos_grinder_tc_ov_credits_update(hqos_sched_port *port,
                             hqos_sched_subport *subport, 
                             u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_subport_profile *sp = grinder->subport_params;
    u64 tc_ov_consumption[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u64 tc_consumption = 0, tc_ov_consumption_max;
    u64 tc_ov_wm = subport->tc_ov_wm;
    u32 i;

    if (subport->tc_ov == 0)
        return subport->tc_ov_wm_max;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASS_BE; i++) {
        tc_ov_consumption[i] = sp->tc_credits_per_period[i]
                    -  subport->tc_credits[i];
        tc_consumption += tc_ov_consumption[i];
    }

    tc_ov_consumption[HQOS_SCHED_TRAFFIC_CLASS_BE] = sp->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] -
                                                     subport->tc_credits[HQOS_SCHED_TRAFFIC_CLASS_BE];

    tc_ov_consumption_max = sp->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] - tc_consumption;

    if (tc_ov_consumption[HQOS_SCHED_TRAFFIC_CLASS_BE] > (tc_ov_consumption_max - port->mtu)) 
    {
        tc_ov_wm  -= tc_ov_wm >> 7;
        if (tc_ov_wm < subport->tc_ov_wm_min)
            tc_ov_wm = subport->tc_ov_wm_min;

        return tc_ov_wm;
    }

    tc_ov_wm += (tc_ov_wm >> 7) + 1;
    if (tc_ov_wm > subport->tc_ov_wm_max)
        tc_ov_wm = subport->tc_ov_wm_max;

    return tc_ov_wm;
}

static_always_inline void
hqos_grinder_credits_update(hqos_sched_port *port,
                       hqos_sched_subport *subport, 
                       u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;
    hqos_sched_pipe_profile *params = grinder->pipe_params;
    hqos_sched_subport_profile *sp = grinder->subport_params;
    u64 n_periods;
    u32 i;

    /* Subport TB */
    n_periods = (port->time - subport->tb_time) / sp->tb_period;
    subport->tb_credits += n_periods * sp->tb_credits_per_period;
    subport->tb_credits = HQOS_MIN(subport->tb_credits, sp->tb_size);
    subport->tb_time += n_periods * sp->tb_period;

    /* Pipe TB */
    n_periods = (port->time - pipe->tb_time) / params->tb_period;
    pipe->tb_credits += n_periods * params->tb_credits_per_period;
    pipe->tb_credits = HQOS_MIN(pipe->tb_credits, params->tb_size);
    pipe->tb_time += n_periods * params->tb_period;

    /* Subport TCs */
    if (PREDICT_FALSE(port->time >= subport->tc_time)) {
        for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
            subport->tc_credits[i] = sp->tc_credits_per_period[i];

        subport->tc_time = port->time + sp->tc_period;
    }

    /* Pipe TCs */
    if (PREDICT_FALSE(port->time >= pipe->tc_time)) {
        for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
            pipe->tc_credits[i] = params->tc_credits_per_period[i];
        pipe->tc_time = port->time + params->tc_period;
    }
}

static_always_inline void
hqos_grinder_credits_update_with_tc_ov(hqos_sched_port *port,
                                  hqos_sched_subport *subport, 
                                  u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;
    hqos_sched_pipe_profile *params = grinder->pipe_params;
    hqos_sched_subport_profile *sp = grinder->subport_params;
    u64 n_periods;
    u32 i;

    /* Subport TB */
    n_periods = (port->time - subport->tb_time) / sp->tb_period;
    subport->tb_credits += n_periods * sp->tb_credits_per_period;
    subport->tb_credits = HQOS_MIN(subport->tb_credits, sp->tb_size);
    subport->tb_time += n_periods * sp->tb_period;

    /* Pipe TB */
    n_periods = (port->time - pipe->tb_time) / params->tb_period;
    pipe->tb_credits += n_periods * params->tb_credits_per_period;
    pipe->tb_credits = HQOS_MIN(pipe->tb_credits, params->tb_size);
    pipe->tb_time += n_periods * params->tb_period;

    /* Subport TCs */
    if (PREDICT_FALSE(port->time >= subport->tc_time)) {
        subport->tc_ov_wm = hqos_grinder_tc_ov_credits_update(port, subport, pos);

        for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
            subport->tc_credits[i] = sp->tc_credits_per_period[i];

        subport->tc_time = port->time + sp->tc_period;
        subport->tc_ov_period_id++;
    }

    /* Pipe TCs */
    if (PREDICT_FALSE(port->time >= pipe->tc_time)) {
        for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
            pipe->tc_credits[i] = params->tc_credits_per_period[i];
        pipe->tc_time = port->time + params->tc_period;
    }

    /* Pipe TCs - Oversubscription */
    if (PREDICT_FALSE(pipe->tc_ov_period_id != subport->tc_ov_period_id)) {
        pipe->tc_ov_credits = subport->tc_ov_wm * params->tc_ov_weight;

        pipe->tc_ov_period_id = subport->tc_ov_period_id;
    }
}

static_always_inline int
hqos_grinder_credits_check(hqos_sched_port *port,
                           hqos_sched_subport *subport, 
                           u32 pos)
{
    vlib_main_t *vm = hqos_vlib_get_main ();

    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;
    u32 tc_index = grinder->tc_index;

    vlib_buffer_t *pkt = grinder->pkt;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt) + port->frame_overhead;

    u64 subport_tb_credits = subport->tb_credits;
    u64 subport_tc_credits = subport->tc_credits[tc_index];
    u64 pipe_tb_credits = pipe->tb_credits;
    u64 pipe_tc_credits = pipe->tc_credits[tc_index];
    int enough_credits;

    /* Check pipe and subport credits */
    enough_credits = (pkt_len <= subport_tb_credits) &&
        (pkt_len <= subport_tc_credits) &&
        (pkt_len <= pipe_tb_credits) &&
        (pkt_len <= pipe_tc_credits);

    if (!enough_credits)
        return 0;

    /* Update pipe and subport credits */
    subport->tb_credits -= pkt_len;
    subport->tc_credits[tc_index] -= pkt_len;
    pipe->tb_credits -= pkt_len;
    pipe->tc_credits[tc_index] -= pkt_len;

    return 1;
}

static_always_inline int
hqos_grinder_credits_check_with_tc_ov(hqos_sched_port *port,
                                      hqos_sched_subport *subport, 
                                      u32 pos)
{
    vlib_main_t *vm = hqos_vlib_get_main ();

    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;
    u32 tc_index = grinder->tc_index;

    vlib_buffer_t *pkt = grinder->pkt;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt) + port->frame_overhead;

    u64 subport_tb_credits = subport->tb_credits;
    u64 subport_tc_credits = subport->tc_credits[tc_index];
    u64 pipe_tb_credits = pipe->tb_credits;
    u64 pipe_tc_credits = pipe->tc_credits[tc_index];
    u64 pipe_tc_ov_mask1[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE];
    u64 pipe_tc_ov_mask2[HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE] = {0};
    u64 pipe_tc_ov_credits;

    u32 i;
    int enough_credits;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
        pipe_tc_ov_mask1[i] = ~0LLU;

    pipe_tc_ov_mask1[HQOS_SCHED_TRAFFIC_CLASS_BE] = pipe->tc_ov_credits;
    pipe_tc_ov_mask2[HQOS_SCHED_TRAFFIC_CLASS_BE] = ~0LLU;
    pipe_tc_ov_credits = pipe_tc_ov_mask1[tc_index];

    /* Check pipe and subport credits */
    enough_credits = (pkt_len <= subport_tb_credits) &&
        (pkt_len <= subport_tc_credits) &&
        (pkt_len <= pipe_tb_credits) &&
        (pkt_len <= pipe_tc_credits) &&
        (pkt_len <= pipe_tc_ov_credits);

    if (!enough_credits)
        return 0;

    /* Update pipe and subport credits */
    subport->tb_credits -= pkt_len;
    subport->tc_credits[tc_index] -= pkt_len;
    pipe->tb_credits -= pkt_len;
    pipe->tc_credits[tc_index] -= pkt_len;
    pipe->tc_ov_credits -= pipe_tc_ov_mask2[tc_index] & pkt_len;

    return 1;
}

static_always_inline int
hqos_grinder_schedule(hqos_sched_port *port,
                 hqos_sched_subport *subport, 
                 u32 pos)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_queue *queue = grinder->queue[grinder->qpos];
    u32 qindex = grinder->qindex[grinder->qpos];

    vlib_buffer_t *pkt = grinder->pkt;
    u32 pkt_len = vlib_buffer_length_in_chain(vm, pkt) + port->frame_overhead;

    u32 be_tc_active;

    if (subport->tc_ov_enabled) {
        if (!hqos_grinder_credits_check_with_tc_ov(port, subport, pos))
            return 0;
    } else {
        if (!hqos_grinder_credits_check(port, subport, pos))
            return 0;
    }

#if 0
    /* Advance port time */
    port->time += pkt_len;
#endif

    /* Send packet */
    port->pkts_out[port->n_pkts_out++] = pkt;
    queue->qr++;

    be_tc_active = (grinder->tc_index == HQOS_SCHED_TRAFFIC_CLASS_BE) ? ~0x0 : 0x0;
    grinder->wrr_tokens[grinder->qpos] +=
        (pkt_len * grinder->wrr_cost[grinder->qpos]) & be_tc_active;

    if (queue->qr == queue->qw) {
        hqos_bitmap_clear(subport->bmp, qindex);
        grinder->qmask &= ~(1 << grinder->qpos);
        if (be_tc_active)
            grinder->wrr_mask[grinder->qpos] = 0;

        hqos_sched_port_red_set_queue_empty_timestamp(port, subport, qindex);
    }

    hqos_sched_port_pie_dequeue(subport, qindex, pkt_len, port->time_cpu_cycles);

    /* Reset pipe loop detection */
    subport->pipe_loop = HQOS_SCHED_PIPE_INVALID;
    grinder->productive = 1;

    return 1;
}

static_always_inline int
hqos_grinder_pipe_exists(hqos_sched_subport *subport, u32 base_pipe)
{
    u32 i;

    for (i = 0; i < HQOS_SCHED_PORT_N_GRINDERS; i++) {
        if (subport->grinder_base_bmp_pos[i] == base_pipe)
            return 1;
    }

    return 0;
}

static_always_inline void
hqos_grinder_pcache_populate(hqos_sched_subport *subport,
                             u32 pos, u32 bmp_pos, u64 bmp_slab)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u16 w[4];

    grinder->pcache_w = 0;
    grinder->pcache_r = 0;

    w[0] = (u16) bmp_slab;
    w[1] = (u16) (bmp_slab >> 16);
    w[2] = (u16) (bmp_slab >> 32);
    w[3] = (u16) (bmp_slab >> 48);

    grinder->pcache_qmask[grinder->pcache_w] = w[0];
    grinder->pcache_qindex[grinder->pcache_w] = bmp_pos;
    grinder->pcache_w += (w[0] != 0);

    grinder->pcache_qmask[grinder->pcache_w] = w[1];
    grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 16;
    grinder->pcache_w += (w[1] != 0);

    grinder->pcache_qmask[grinder->pcache_w] = w[2];
    grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 32;
    grinder->pcache_w += (w[2] != 0);

    grinder->pcache_qmask[grinder->pcache_w] = w[3];
    grinder->pcache_qindex[grinder->pcache_w] = bmp_pos + 48;
    grinder->pcache_w += (w[3] != 0);
}

static_always_inline void
hqos_grinder_tccache_populate(hqos_sched_subport *subport,
                              u32 pos, u32 qindex, u32 qmask)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u8 b, i;

    grinder->tccache_w = 0;
    grinder->tccache_r = 0;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASS_BE; i++) {
        b = (u8) ((qmask >> i) & 0x1);
        grinder->tccache_qmask[grinder->tccache_w] = b;
        grinder->tccache_qindex[grinder->tccache_w] = qindex + i;
        grinder->tccache_w += (b != 0);
    }

    b = (uint8_t) (qmask >> (HQOS_SCHED_TRAFFIC_CLASS_BE));
    grinder->tccache_qmask[grinder->tccache_w] = b;
    grinder->tccache_qindex[grinder->tccache_w] = qindex + HQOS_SCHED_TRAFFIC_CLASS_BE;
    grinder->tccache_w += (b != 0);
}

static_always_inline int
hqos_grinder_next_tc(hqos_sched_port *port,
                     hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    vlib_buffer_t **qbase;
    u32 qindex;
    u16 qsize;

    if (grinder->tccache_r == grinder->tccache_w)
        return 0;

    qindex = grinder->tccache_qindex[grinder->tccache_r];
    qbase = hqos_sched_subport_pipe_qbase(subport, qindex);
    qsize = hqos_sched_subport_pipe_qsize(port, subport, qindex);

    grinder->tc_index = hqos_sched_port_pipe_tc(port, qindex);
    grinder->qmask = grinder->tccache_qmask[grinder->tccache_r];
    grinder->qsize = qsize;

    if (grinder->tc_index < HQOS_SCHED_TRAFFIC_CLASS_BE) {
        grinder->queue[0] = subport->queue + qindex;
        grinder->qbase[0] = qbase;
        grinder->qindex[0] = qindex;
        grinder->tccache_r++;

        return 1;
    }

    grinder->queue[0] = subport->queue + qindex;
    grinder->queue[1] = subport->queue + qindex + 1;
    grinder->queue[2] = subport->queue + qindex + 2;
    grinder->queue[3] = subport->queue + qindex + 3;
    grinder->queue[4] = subport->queue + qindex + 4;
    grinder->queue[5] = subport->queue + qindex + 5;
    grinder->queue[6] = subport->queue + qindex + 6;
    grinder->queue[7] = subport->queue + qindex + 7;

    grinder->qbase[0] = qbase;
    grinder->qbase[1] = qbase + qsize;
    grinder->qbase[2] = qbase + 2 * qsize;
    grinder->qbase[3] = qbase + 3 * qsize;
    grinder->qbase[4] = qbase + 4 * qsize;
    grinder->qbase[5] = qbase + 5 * qsize;
    grinder->qbase[6] = qbase + 6 * qsize;
    grinder->qbase[7] = qbase + 7 * qsize;

    grinder->qindex[0] = qindex;
    grinder->qindex[1] = qindex + 1;
    grinder->qindex[2] = qindex + 2;
    grinder->qindex[3] = qindex + 3;
    grinder->qindex[4] = qindex + 4;
    grinder->qindex[5] = qindex + 5;
    grinder->qindex[6] = qindex + 6;
    grinder->qindex[7] = qindex + 7;

    grinder->tccache_r++;
    return 1;
}

static_always_inline int
hqos_grinder_next_pipe(hqos_sched_port *port,
                       hqos_sched_subport *subport, 
                       u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u32 pipe_qindex;
    u16 pipe_qmask;

    if (grinder->pcache_r < grinder->pcache_w) 
    {
        pipe_qmask = grinder->pcache_qmask[grinder->pcache_r];
        pipe_qindex = grinder->pcache_qindex[grinder->pcache_r];
        grinder->pcache_r++;
    } 
    else
    {
        uint64_t bmp_slab = 0;
        uint32_t bmp_pos = 0;

        /* Get another non-empty pipe group */
        if (PREDICT_FALSE(hqos_bitmap_scan(subport->bmp, &bmp_pos, &bmp_slab) <= 0))
            return 0;

#ifdef HQOS_SCHED_DEBUG
        hqos_debug_check_queue_slab(subport, bmp_pos, bmp_slab);
#endif

        /* Return if pipe group already in one of the other grinders */
        subport->grinder_base_bmp_pos[pos] = HQOS_SCHED_BMP_POS_INVALID;
        if (PREDICT_FALSE(hqos_grinder_pipe_exists(subport, bmp_pos)))
            return 0;

        subport->grinder_base_bmp_pos[pos] = bmp_pos;

        /* Install new pipe group into grinder's pipe cache */
        hqos_grinder_pcache_populate(subport, pos, bmp_pos, bmp_slab);

        pipe_qmask = grinder->pcache_qmask[0];
        pipe_qindex = grinder->pcache_qindex[0];
        grinder->pcache_r = 1;
    }

    /* Install new pipe in the grinder */
    grinder->pindex = pipe_qindex >> HQOS_SCHED_QUEUES_PER_PIPE_LOG2;
    grinder->subport = subport;
    grinder->pipe = subport->pipe + grinder->pindex;
    grinder->pipe_params = NULL; /* to be set after the pipe structure is prefetched */
    grinder->productive = 0;

    hqos_grinder_tccache_populate(subport, pos, pipe_qindex, pipe_qmask);
    hqos_grinder_next_tc(port, subport, pos);

    /* Check for pipe exhaustion */
    if (grinder->pindex == subport->pipe_loop) {
        subport->pipe_exhaustion = 1;
        subport->pipe_loop = HQOS_SCHED_PIPE_INVALID;
    }

    return 1;
}

static_always_inline void
hqos_grinder_wrr_load(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;
    hqos_sched_pipe_profile *pipe_params = grinder->pipe_params;
    u32 qmask = grinder->qmask;

    grinder->wrr_tokens[0] = ((u16) pipe->wrr_tokens[0]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[1] = ((u16) pipe->wrr_tokens[1]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[2] = ((u16) pipe->wrr_tokens[2]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[3] = ((u16) pipe->wrr_tokens[3]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[4] = ((u16) pipe->wrr_tokens[4]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[5] = ((u16) pipe->wrr_tokens[5]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[6] = ((u16) pipe->wrr_tokens[6]) << HQOS_SCHED_WRR_SHIFT;
    grinder->wrr_tokens[7] = ((u16) pipe->wrr_tokens[7]) << HQOS_SCHED_WRR_SHIFT;

    grinder->wrr_mask[0] = (qmask & 0x1) * 0xFFFF;
    grinder->wrr_mask[1] = ((qmask >> 1) & 0x1) * 0xFFFF;
    grinder->wrr_mask[2] = ((qmask >> 2) & 0x1) * 0xFFFF;
    grinder->wrr_mask[3] = ((qmask >> 3) & 0x1) * 0xFFFF;
    grinder->wrr_mask[4] = ((qmask >> 4) & 0x1) * 0xFFFF;
    grinder->wrr_mask[5] = ((qmask >> 5) & 0x1) * 0xFFFF;
    grinder->wrr_mask[6] = ((qmask >> 6) & 0x1) * 0xFFFF;
    grinder->wrr_mask[7] = ((qmask >> 7) & 0x1) * 0xFFFF;

    grinder->wrr_cost[0] = pipe_params->wrr_cost[0];
    grinder->wrr_cost[1] = pipe_params->wrr_cost[1];
    grinder->wrr_cost[2] = pipe_params->wrr_cost[2];
    grinder->wrr_cost[3] = pipe_params->wrr_cost[3];
    grinder->wrr_cost[4] = pipe_params->wrr_cost[4];
    grinder->wrr_cost[5] = pipe_params->wrr_cost[5];
    grinder->wrr_cost[6] = pipe_params->wrr_cost[6];
    grinder->wrr_cost[7] = pipe_params->wrr_cost[7];
}

static_always_inline void
hqos_grinder_wrr_store(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    hqos_sched_pipe *pipe = grinder->pipe;

    pipe->wrr_tokens[0] = (grinder->wrr_tokens[0] & grinder->wrr_mask[0]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[1] = (grinder->wrr_tokens[1] & grinder->wrr_mask[1]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[2] = (grinder->wrr_tokens[2] & grinder->wrr_mask[2]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[3] = (grinder->wrr_tokens[3] & grinder->wrr_mask[3]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[4] = (grinder->wrr_tokens[4] & grinder->wrr_mask[4]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[5] = (grinder->wrr_tokens[5] & grinder->wrr_mask[5]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[6] = (grinder->wrr_tokens[6] & grinder->wrr_mask[6]) >> HQOS_SCHED_WRR_SHIFT;
    pipe->wrr_tokens[7] = (grinder->wrr_tokens[7] & grinder->wrr_mask[7]) >> HQOS_SCHED_WRR_SHIFT;
}

static_always_inline void
hqos_grinder_wrr(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u16 wrr_tokens_min;

    grinder->wrr_tokens[0] |= ~grinder->wrr_mask[0];
    grinder->wrr_tokens[1] |= ~grinder->wrr_mask[1];
    grinder->wrr_tokens[2] |= ~grinder->wrr_mask[2];
    grinder->wrr_tokens[3] |= ~grinder->wrr_mask[3];
    grinder->wrr_tokens[4] |= ~grinder->wrr_mask[4];
    grinder->wrr_tokens[5] |= ~grinder->wrr_mask[5];
    grinder->wrr_tokens[6] |= ~grinder->wrr_mask[6];
    grinder->wrr_tokens[7] |= ~grinder->wrr_mask[7];

    grinder->qpos = hqos_min_pos_8_u16(grinder->wrr_tokens);
    wrr_tokens_min = grinder->wrr_tokens[grinder->qpos];

    grinder->wrr_tokens[0] -= wrr_tokens_min;
    grinder->wrr_tokens[1] -= wrr_tokens_min;
    grinder->wrr_tokens[2] -= wrr_tokens_min;
    grinder->wrr_tokens[3] -= wrr_tokens_min;
    grinder->wrr_tokens[4] -= wrr_tokens_min;
    grinder->wrr_tokens[5] -= wrr_tokens_min;
    grinder->wrr_tokens[6] -= wrr_tokens_min;
    grinder->wrr_tokens[7] -= wrr_tokens_min;
}

static_always_inline void
hqos_grinder_prefetch_pipe(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;

    clib_prefetch_load(grinder->pipe);
    clib_prefetch_load(grinder->queue[0]);
}

static_always_inline void
hqos_grinder_prefetch_tc_queue_arrays(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u16 qsize, qr[HQOS_SCHED_MAX_QUEUES_PER_TC];

    qsize = grinder->qsize;
    grinder->qpos = 0;

    if (grinder->tc_index < HQOS_SCHED_TRAFFIC_CLASS_BE) {
        qr[0] = grinder->queue[0]->qr & (qsize - 1);

        clib_prefetch_load(grinder->qbase[0] + qr[0]);
        return;
    }

    qr[0] = grinder->queue[0]->qr & (qsize - 1);
    qr[1] = grinder->queue[1]->qr & (qsize - 1);
    qr[2] = grinder->queue[2]->qr & (qsize - 1);
    qr[3] = grinder->queue[3]->qr & (qsize - 1);

    clib_prefetch_load(grinder->qbase[0] + qr[0]);
    clib_prefetch_load(grinder->qbase[1] + qr[1]);

    hqos_grinder_wrr_load(subport, pos);
    hqos_grinder_wrr(subport, pos);

    clib_prefetch_load(grinder->qbase[2] + qr[2]);
    clib_prefetch_load(grinder->qbase[3] + qr[3]);
}

static_always_inline void
hqos_grinder_prefetch_vlib_buffer(hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;
    u32 qpos = grinder->qpos;
    vlib_buffer_t **qbase = grinder->qbase[qpos];
    u16 qsize = grinder->qsize;
    u16 qr = grinder->queue[qpos]->qr & (qsize - 1);

    grinder->pkt = qbase[qr];
    vlib_prefetch_buffer_header (grinder->pkt, LOAD);

    if (PREDICT_FALSE((qr & 0x7) == 7)) {
        u16 qr_next = (grinder->queue[qpos]->qr + 1) & (qsize - 1);
        vlib_prefetch_buffer_header(qbase + qr_next, LOAD);
    }
}

static_always_inline u32 
hqos_grinder_handle(hqos_sched_port *port, hqos_sched_subport *subport, u32 pos)
{
    hqos_sched_grinder *grinder = subport->grinder + pos;

    switch (grinder->state) 
    {
    case e_GRINDER_PREFETCH_PIPE:
    {
        if (hqos_grinder_next_pipe(port, subport, pos)) {
            hqos_grinder_prefetch_pipe(subport, pos);
            subport->busy_grinders++;

            grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
            return 0;
        }

        return 0;
    }

    case e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS:
    {
        hqos_sched_pipe *pipe = grinder->pipe;

        grinder->pipe_params = subport->pipe_profiles + pipe->profile;
        grinder->subport_params = port->subport_profiles + subport->profile;

        hqos_grinder_prefetch_tc_queue_arrays(subport, pos);

        if (subport->tc_ov_enabled)
            hqos_grinder_credits_update_with_tc_ov(port, subport, pos);
        else
            hqos_grinder_credits_update(port, subport, pos);

        grinder->state = e_GRINDER_PREFETCH_VLIB_BUF;
        return 0;
    }

    case e_GRINDER_PREFETCH_VLIB_BUF:
    {
        hqos_grinder_prefetch_vlib_buffer(subport, pos);

        grinder->state = e_GRINDER_READ_VLIB_BUF;
        return 0;
    }

    case e_GRINDER_READ_VLIB_BUF:
    {
        u32 wrr_active, result = 0;

        result = hqos_grinder_schedule(port, subport, pos);

        wrr_active = (grinder->tc_index == HQOS_SCHED_TRAFFIC_CLASS_BE);

        /* Look for next packet within the same TC */
        if (result && grinder->qmask) {
            if (wrr_active)
                hqos_grinder_wrr(subport, pos);

            hqos_grinder_prefetch_vlib_buffer(subport, pos);

            return 1;
        }

        if (wrr_active)
            hqos_grinder_wrr_store(subport, pos);

        /* Look for another active TC within same pipe */
        if (hqos_grinder_next_tc(port, subport, pos)) {
            hqos_grinder_prefetch_tc_queue_arrays(subport, pos);

            grinder->state = e_GRINDER_PREFETCH_VLIB_BUF;
            return result;
        }

        if (grinder->productive == 0 &&
            subport->pipe_loop == HQOS_SCHED_PIPE_INVALID)
            subport->pipe_loop = grinder->pindex;

        /* Look for another active pipe */
        if (hqos_grinder_next_pipe(port, subport, pos)) {
            hqos_grinder_prefetch_pipe(subport, pos);

            grinder->state = e_GRINDER_PREFETCH_TC_QUEUE_ARRAYS;
            return result;
        }

        /* No active pipe found */
        subport->busy_grinders--;

        grinder->state = e_GRINDER_PREFETCH_PIPE;
        return result;
    }

    default:
        clib_panic("Algorithmic error (invalid state)\n");
        return 0;
    }
}

static_always_inline void
hqos_sched_port_time_resync(hqos_sched_port *port)
{
    u64 cycles = clib_cpu_time_now();
    u64 cycles_diff;
    u64 bytes_diff;
    u32 i;

    if (cycles < port->time_cpu_cycles)
        port->time_cpu_cycles = 0;

    cycles_diff = cycles - port->time_cpu_cycles;
    /* Compute elapsed time in bytes */
    bytes_diff = hqos_reciprocal_divide_u64(cycles_diff << HQOS_SCHED_TIME_SHIFT, &port->inv_cycles_per_byte);

    /* Advance port time */
    port->time_cpu_cycles += (bytes_diff * port->cycles_per_byte) >> HQOS_SCHED_TIME_SHIFT;
    port->time_cpu_bytes += bytes_diff;
    if (port->time < port->time_cpu_bytes)
        port->time = port->time_cpu_bytes;

    /* Reset pipe loop detection */
    for (i = 0; i < port->n_subports_per_port; i++)
    {
        if (port->subports[i])
            port->subports[i]->pipe_loop = HQOS_SCHED_PIPE_INVALID;
    }
}

static_always_inline int
hqos_sched_port_exceptions(hqos_sched_subport *subport, int second_pass)
{
    int exceptions;

    /* Check if any exception flag is set */
    exceptions = (second_pass && subport->busy_grinders == 0) ||
        (subport->pipe_exhaustion == 1);

    /* Clear exception flags */
    subport->pipe_exhaustion = 0;

    return exceptions;
}


#ifdef __cplusplus
}
#endif

#endif //included_hqos_sched_priv_h
