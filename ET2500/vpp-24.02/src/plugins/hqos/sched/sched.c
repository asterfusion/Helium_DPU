/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#include <inttypes.h>
#include "hqos/sched/sched_common.h"
#include "hqos/sched/sched.h"
#include "hqos/sched/sched_priv.h"

vlib_main_t *hqos_vlib_main;

static int
hqos_pipe_profile_check(hqos_sched_pipe_params *params,
                        u64 rate, u16 *qsize)
{
    u32 i;

    /* Pipe parameters */
    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter params", __func__);
        return -EINVAL;
    }

    /* TB rate: non-zero, not greater than port rate */
    if (params->tb_rate == 0)
        params->tb_rate = rate;

    if (params->tb_rate > rate) {
        clib_warning("%s: Incorrect value for tb rate", __func__);
        return -EINVAL;
    }

    /* TB size: non-zero */
    if (params->tb_size == 0) {
        clib_warning("%s: Incorrect value for tb size", __func__);
        return -EINVAL;
    }

    /* TC rate: non-zero if qsize non-zero, less than pipe rate */
    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
        if (params->tc_rate[i] == 0)
        {
            params->tc_rate[i] = params->tb_rate;
        }

        if ((qsize[i] == 0 && params->tc_rate[i] != 0) ||
            (qsize[i] != 0 && (params->tc_rate[i] > params->tb_rate))) {
            clib_warning("%s: Incorrect value for qsize or tc_rate", __func__);
            return -EINVAL;
        }
    }

    if (qsize[HQOS_SCHED_TRAFFIC_CLASS_BE] == 0) {
        clib_warning("%s: Incorrect value for be traffic class rate", __func__);
        return -EINVAL;
    }

    /* TC period: non-zero */
    if (params->tc_period == 0) {
        clib_warning("%s: Incorrect value for tc period", __func__);
        return -EINVAL;
    }

    /*  Best effort tc oversubscription weight: non-zero */
    if (params->tc_ov_weight == 0) {
        clib_warning("%s: Incorrect value for tc ov weight", __func__);
        return -EINVAL;
    }

    /* Queue WRR weights: non-zero */
    for (i = 0; i < HQOS_SCHED_BE_QUEUES_PER_PIPE; i++) {
        if (params->wrr_weights[i] == 0) {
            clib_warning("%s: Incorrect value for wrr weight", __func__);
            return -EINVAL;
        }
    }

    return 0;
}

static int
hqos_subport_profile_check(hqos_sched_subport_profile_params *params, u64 rate)
{
    u32 i;

    /* Check user parameters */
    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter params", __func__);
        return -EINVAL;
    }

    if (params->tb_rate == 0)
    {
        params->tb_rate = rate;
    }

    if (params->tb_rate > rate) {
        clib_warning("%s: Incorrect value for tb rate", __func__);
        return -EINVAL;
    }

    if (params->tb_size == 0) {
        clib_warning("%s: Incorrect value for tb size", __func__);
        return -EINVAL;
    }

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
        if (params->tc_rate[i] == 0)
        {
            params->tc_rate[i] = params->tb_rate;
        }

        if (params->tc_rate[i] > params->tb_rate) {
            clib_warning("%s: Incorrect value for tc rate", __func__);
            return -EINVAL;
        }
    }

    if (params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE] == 0) {
        params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE] = params->tb_rate;
    }

    if (params->tc_period == 0) {
        clib_warning("%s: Incorrect value for tc period", __func__);
        return -EINVAL;
    }

    return 0;
}

static int
hqos_sched_port_check_params(hqos_sched_port_params *params)
{
    u32 i;

    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter params", __func__);
        return -EINVAL;
    }

    /* rate */
    if (params->rate == 0) {
        clib_warning("%s: Incorrect value for rate", __func__);
        return -EINVAL;
    }

    /* mtu */
    if (params->mtu == 0) {
        clib_warning("%s: Incorrect value for mtu", __func__);
        return -EINVAL;
    }

    /* n_subports_per_port: non-zero, limited to 16 bits, power of 2 */
    if (params->n_subports_per_port == 0 ||
        params->n_subports_per_port > 1u << 16 ||
        !is_pow2(params->n_subports_per_port)) {
        clib_warning("%s: Incorrect value for number of subports", __func__);
        return -EINVAL;
    }

    if (params->subport_profiles == NULL ||
        params->n_subport_profiles == 0 ||
        params->n_max_subport_profiles == 0 ||
        params->n_subport_profiles > params->n_max_subport_profiles) {
        clib_warning("%s: Incorrect value for subport profiles", __func__);
        return -EINVAL;
    }

    for (i = 0; i < params->n_subport_profiles; i++) {
        hqos_sched_subport_profile_params *p = params->subport_profiles + i;
        int status;

        status = hqos_subport_profile_check(p, params->rate);
        if (status != 0) {
            clib_warning("%s: subport profile check failed(%d)", __func__, status);
            return -EINVAL;
        }
    }

    /* n_pipes_per_subport: non-zero, power of 2 */
    if (params->n_pipes_per_subport == 0 ||
        !is_pow2(params->n_pipes_per_subport)) {
        clib_warning("%s: Incorrect value for maximum pipes number", __func__);
        return -EINVAL;
    }

    return 0;
}

static int
hqos_sched_subport_check_params(hqos_sched_subport_params *params,
                                u32 n_max_pipes_per_subport,
                                u64 rate)
{
    u32 i;

    /* Check user parameters */
    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter params", __func__);
        return -EINVAL;
    }

    /* qsize: if non-zero, power of 2,
     * no bigger than 32K (due to 16-bit read/write pointers)
     */
    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
        uint16_t qsize = params->qsize[i];

        if (qsize != 0 && !is_pow2(qsize)) {
            clib_warning("%s: Incorrect value for qsize", __func__);
            return -EINVAL;
        }
    }

    if (params->qsize[HQOS_SCHED_TRAFFIC_CLASS_BE] == 0) {
        clib_warning("%s: Incorrect qsize", __func__);
        return -EINVAL;
    }

    /* n_pipes_per_subport: non-zero, power of 2 */
    if (params->n_pipes_per_subport_enabled == 0 ||
        params->n_pipes_per_subport_enabled > n_max_pipes_per_subport ||
        !is_pow2(params->n_pipes_per_subport_enabled)) {
        clib_warning("%s: Incorrect value for pipes number", __func__);
        return -EINVAL;
    }

    /* pipe_profiles and n_pipe_profiles */
    if (params->pipe_profiles == NULL ||
        params->n_pipe_profiles == 0 ||
        params->n_max_pipe_profiles == 0 ||
        params->n_pipe_profiles > params->n_max_pipe_profiles) {
        return 0;
    }

    for (i = 0; i < params->n_pipe_profiles; i++) {
        hqos_sched_pipe_params *p = params->pipe_profiles + i;
        int status;

        status = hqos_pipe_profile_check(p, rate, &params->qsize[0]);
        if (status != 0) {
            clib_warning("%s: Pipe profile check failed(%d)", __func__, status);
            return -EINVAL;
        }
    }

    return 0;
}

static u32 
hqos_sched_subport_get_array_base(hqos_sched_subport_params *params,
                                  hqos_sched_subport_array array)
{
    u32 n_pipes_per_subport = params->n_pipes_per_subport_enabled;
    u32 n_subport_pipe_queues = HQOS_SCHED_QUEUES_PER_PIPE * n_pipes_per_subport;

    u32 size_pipe = n_pipes_per_subport * sizeof(hqos_sched_pipe);
    u32 size_queue = n_subport_pipe_queues * sizeof(hqos_sched_queue);
    u32 size_queue_extra = n_subport_pipe_queues * sizeof(hqos_sched_queue_extra);
    u32 size_pipe_profiles = params->n_max_pipe_profiles * sizeof(hqos_sched_pipe_profile);
    u32 size_bmp_array = hqos_bitmap_get_memory_footprint(n_subport_pipe_queues); 

    u32 size_per_pipe_queue_array, size_queue_array;
    u32 base, i;

    size_per_pipe_queue_array = 0;
    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
        if (i < HQOS_SCHED_TRAFFIC_CLASS_BE)
            size_per_pipe_queue_array += params->qsize[i] * sizeof(struct vlib_buffer_t *);
        else
            size_per_pipe_queue_array += HQOS_SCHED_MAX_QUEUES_PER_TC * params->qsize[i] * sizeof(struct vlib_buffer_t *);
    }
    size_queue_array = n_pipes_per_subport * size_per_pipe_queue_array;

    base = 0;

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_PIPE) return base;

    base += CLIB_CACHE_LINE_ROUND(size_pipe);

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE) return base;

    base += CLIB_CACHE_LINE_ROUND(size_queue);

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA) return base;

    base += CLIB_CACHE_LINE_ROUND(size_queue_extra);

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_PIPE_PROFILES) return base;

    base += CLIB_CACHE_LINE_ROUND(size_pipe_profiles);

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_BMP_ARRAY) return base;

    base += CLIB_CACHE_LINE_ROUND(size_bmp_array);

    if (array == e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY) return base;

    base += CLIB_CACHE_LINE_ROUND(size_queue_array);

    return base;
}

static void
hqos_sched_subport_config_qsize(hqos_sched_subport *subport)
{
    u32 i;

    subport->qsize_add[0] = 0;

    /* Strict priority traffic class */
    for (i = 1; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
        subport->qsize_add[i] = subport->qsize_add[i-1] + subport->qsize[i-1];

    /* Best-effort traffic class */
    for (i = HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i < HQOS_SCHED_QUEUES_PER_PIPE; i++)
    {
        subport->qsize_add[i] = subport->qsize_add[i - 1] + subport->qsize[HQOS_SCHED_TRAFFIC_CLASS_BE];
    }

    subport->qsize_sum = subport->qsize_add[i - 1] + subport->qsize[HQOS_SCHED_TRAFFIC_CLASS_BE];
}

static void
hqos_sched_port_log_pipe_profile(hqos_sched_subport *subport, u32 i)
{
    hqos_sched_pipe_profile *p = subport->pipe_profiles + i;

    clib_warning("Low level config for pipe profile %u:\n"
                 "   Token bucket: period = %"PRIu64", credits per period = %"PRIu64", size = %"PRIu64"\n"
                 "   Traffic classes: period = %"PRIu64"\n"
                 "   credits per period ="
                 " [%"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64
                 ", %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64
                 ", %"PRIu64"]\n"
                 "   Best-effort traffic class oversubscription: weight = %u\n"
                 "   WRR cost: [%u, %u, %u, %u, %u, %u, %u, %u]\n",
                 i,
                 /* Token bucket */
                 p->tb_period, p->tb_credits_per_period, p->tb_size,
                 /* Traffic classes */
                 p->tc_period,
                 p->tc_credits_per_period[0], p->tc_credits_per_period[1], p->tc_credits_per_period[2], p->tc_credits_per_period[3],
                 p->tc_credits_per_period[4], p->tc_credits_per_period[5], p->tc_credits_per_period[6], p->tc_credits_per_period[7],
                 p->tc_credits_per_period[8],
                 /* Best-effort traffic class oversubscription */
                 p->tc_ov_weight,
                 /* WRR */
                 p->wrr_cost[0], p->wrr_cost[1], p->wrr_cost[2], p->wrr_cost[3],
                 p->wrr_cost[4], p->wrr_cost[5], p->wrr_cost[6], p->wrr_cost[7]);
}

static void
hqos_sched_port_log_subport_profile(hqos_sched_port *port, u32 i)
{
    hqos_sched_subport_profile *p = port->subport_profiles + i;

    clib_warning("Low level config for subport profile %u:\n"
                 "Token bucket: period = %"PRIu64", credits per period = %"PRIu64", size = %"PRIu64"\n"
                 "Traffic classes: period = %"PRIu64"\n"
                 "credits per period ="
                 " [%"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64
                 ", %"PRIu64", %"PRIu64", %"PRIu64", %"PRIu64
                 ", %"PRIu64"]\n",
                 i,
                 /* Token bucket */
                 p->tb_period, p->tb_credits_per_period, p->tb_size,
                 /* Traffic classes */
                 p->tc_period,
                 p->tc_credits_per_period[0], p->tc_credits_per_period[1], p->tc_credits_per_period[2], p->tc_credits_per_period[3],
                 p->tc_credits_per_period[4], p->tc_credits_per_period[5], p->tc_credits_per_period[6], p->tc_credits_per_period[7],
                 p->tc_credits_per_period[8]);
}

static void
hqos_sched_pipe_profile_convert(hqos_sched_subport *subport,
                                hqos_sched_pipe_params *src,
                                hqos_sched_pipe_profile *dst,
                                u64 rate)
{
    u32 wrr_cost[HQOS_SCHED_BE_QUEUES_PER_PIPE];
    u32 lcd1, lcd2, lcd3, lcd4, lcd12, lcd34, lcd;
    u32 i;

    /* Token Bucket */
    if (src->tb_rate == rate) {
        dst->tb_credits_per_period = 1;
        dst->tb_period = 1;
    } else {
        f64 tb_rate = (f64) src->tb_rate / (f64) rate;
        f64 d = HQOS_SCHED_TB_RATE_CONFIG_ERR;

        hqos_approx_64(tb_rate, d, &dst->tb_credits_per_period,
            &dst->tb_period);
    }

    dst->orig_tb_rate = src->tb_rate;

    dst->tb_size = src->tb_size;

    /* Traffic Classes */
    dst->orig_tc_period = src->tc_period;
    dst->tc_period = hqos_sched_time_ms_to_bytes(src->tc_period, rate);

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
        if (subport->qsize[i])
            dst->tc_credits_per_period[i] = hqos_sched_time_ms_to_bytes(src->tc_period, src->tc_rate[i]);

    dst->tc_ov_weight = src->tc_ov_weight;

    /* WRR queues */
    wrr_cost[0] = src->wrr_weights[0];
    wrr_cost[1] = src->wrr_weights[1];
    wrr_cost[2] = src->wrr_weights[2];
    wrr_cost[3] = src->wrr_weights[3];
    wrr_cost[4] = src->wrr_weights[4];
    wrr_cost[5] = src->wrr_weights[5];
    wrr_cost[6] = src->wrr_weights[6];
    wrr_cost[7] = src->wrr_weights[7];
    dst->wrr_weights[0] = src->wrr_weights[0];
    dst->wrr_weights[1] = src->wrr_weights[1];
    dst->wrr_weights[2] = src->wrr_weights[2];
    dst->wrr_weights[3] = src->wrr_weights[3];
    dst->wrr_weights[4] = src->wrr_weights[4];
    dst->wrr_weights[5] = src->wrr_weights[5];
    dst->wrr_weights[6] = src->wrr_weights[6];
    dst->wrr_weights[7] = src->wrr_weights[7];

    lcd1 = hqos_get_lcd(wrr_cost[0], wrr_cost[1]);
    lcd2 = hqos_get_lcd(wrr_cost[2], wrr_cost[3]);
    lcd3 = hqos_get_lcd(wrr_cost[4], wrr_cost[5]);
    lcd4 = hqos_get_lcd(wrr_cost[6], wrr_cost[7]);
    lcd12 = hqos_get_lcd(lcd1, lcd2);
    lcd34 = hqos_get_lcd(lcd3, lcd4);
    lcd = hqos_get_lcd(lcd12, lcd34);

    wrr_cost[0] = lcd / wrr_cost[0];
    wrr_cost[1] = lcd / wrr_cost[1];
    wrr_cost[2] = lcd / wrr_cost[2];
    wrr_cost[3] = lcd / wrr_cost[3];
    wrr_cost[4] = lcd / wrr_cost[4];
    wrr_cost[5] = lcd / wrr_cost[5];
    wrr_cost[6] = lcd / wrr_cost[6];
    wrr_cost[7] = lcd / wrr_cost[7];

    dst->wrr_cost[0] = (u8) wrr_cost[0];
    dst->wrr_cost[1] = (u8) wrr_cost[1];
    dst->wrr_cost[2] = (u8) wrr_cost[2];
    dst->wrr_cost[3] = (u8) wrr_cost[3];
    dst->wrr_cost[4] = (u8) wrr_cost[4];
    dst->wrr_cost[5] = (u8) wrr_cost[5];
    dst->wrr_cost[6] = (u8) wrr_cost[6];
    dst->wrr_cost[7] = (u8) wrr_cost[7];
}

static void
hqos_sched_subport_profile_convert(hqos_sched_subport_profile_params *src,
                                   hqos_sched_subport_profile *dst,
                                   u64 rate)
{
    u32 i;

    /* Token Bucket */
    if (src->tb_rate == rate) {
        dst->tb_credits_per_period = 1;
        dst->tb_period = 1;
    } else {
        f64 tb_rate = (f64) src->tb_rate / (double) rate;
        f64 d = HQOS_SCHED_TB_RATE_CONFIG_ERR;

        hqos_approx_64(tb_rate, d, &dst->tb_credits_per_period, &dst->tb_period);
    }
    dst->orig_tb_rate = src->tb_rate;

    dst->tb_size = src->tb_size;

    /* Traffic Classes */
    dst->orig_tc_period = src->tc_period;
    dst->tc_period = hqos_sched_time_ms_to_bytes(src->tc_period, rate);

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
        dst->tc_credits_per_period[i] = hqos_sched_time_ms_to_bytes(src->tc_period, src->tc_rate[i]);
}

static void
hqos_sched_subport_config_pipe_profile_table(hqos_sched_subport *subport,
                                             hqos_sched_subport_params *params, 
                                             u64 rate)
{
    u32 i;

    for (i = 0; i < subport->n_pipe_profiles; i++) {
        hqos_sched_pipe_params *src = params->pipe_profiles + i;
        hqos_sched_pipe_profile *dst = subport->pipe_profiles + i;

        hqos_sched_pipe_profile_convert(subport, src, dst, rate);
        hqos_sched_port_log_pipe_profile(subport, i);
    }

    subport->pipe_tc_be_rate_max = 0;
    for (i = 0; i < subport->n_pipe_profiles; i++) {
        hqos_sched_pipe_params *src = params->pipe_profiles + i;
        u64 pipe_tc_be_rate = src->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE];

        if (subport->pipe_tc_be_rate_max < pipe_tc_be_rate)
            subport->pipe_tc_be_rate_max = pipe_tc_be_rate;
    }
}

static void
hqos_sched_port_config_subport_profile_table(hqos_sched_port *port,
                                             hqos_sched_port_params *params,
                                             u64 rate)
{
    u32 i;

    for (i = 0; i < port->n_subport_profiles; i++) {
        hqos_sched_subport_profile_params *src = params->subport_profiles + i;
        hqos_sched_subport_profile *dst = port->subport_profiles + i;

        hqos_sched_subport_profile_convert(src, dst, rate);
        hqos_sched_port_log_subport_profile(port, i);
    }
}

static void
hqos_sched_free_memory(hqos_sched_port *port, u32 n_subports)
{
    u32 i;

    for (i = 0; i < n_subports; i++) {
        hqos_sched_subport *subport = port->subports[i];

        hqos_sched_subport_free(port, subport);
    }

    clib_mem_free(port->subport_profiles);
    clib_mem_free(port);
}

static int
hqos_sched_red_config(hqos_sched_port *port,
                      hqos_sched_subport *s,
                      hqos_sched_subport_params *params,
                      u32 n_subports)
{
    u32 i;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {

        u32 j;

        for (j = 0; j < HQOS_COLORS; j++) {
            /* if min/max are both zero, then RED is disabled */
            if ((params->cman_params->red_params[i][j].min_th |
                 params->cman_params->red_params[i][j].max_th) == 0) {
                continue;
            }

            if (hqos_red_config_init(&s->red_config[i][j],
                params->cman_params->red_params[i][j].wq_log2,
                params->cman_params->red_params[i][j].min_th,
                params->cman_params->red_params[i][j].max_th,
                params->cman_params->red_params[i][j].maxp_inv) != 0) {
                hqos_sched_free_memory(port, n_subports);

                clib_warning("%s: RED configuration init fails", __func__);
                return -EINVAL;
            }
        }
    }
    s->cman = HQOS_SCHED_CMAN_RED;
    return 0;
}

static int
hqos_sched_pie_config(hqos_sched_port *port,
                      hqos_sched_subport *s,
                      hqos_sched_subport_params *params,
                      u32 n_subports)
{
    u32 i;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
        if (params->cman_params->pie_params[i].tailq_th > params->qsize[i]) {
            clib_warning("%s: PIE tailq threshold incorrect", __func__);
            return -EINVAL;
        }

        if (hqos_pie_config_init(&s->pie_config[i],
            params->cman_params->pie_params[i].qdelay_ref,
            params->cman_params->pie_params[i].dp_update_interval,
            params->cman_params->pie_params[i].max_burst,
            params->cman_params->pie_params[i].tailq_th) != 0) {
            hqos_sched_free_memory(port, n_subports);

            clib_warning("%s: PIE configuration init fails", __func__);
            return -EINVAL;
        }
    }
    s->cman = HQOS_SCHED_CMAN_PIE;
    return 0;
}

static int
hqos_sched_cman_config(hqos_sched_port *port,
                       hqos_sched_subport *s,
                       hqos_sched_subport_params *params,
                       u32 n_subports)
{
    if (params->cman_params->cman_mode == HQOS_SCHED_CMAN_RED)
        return hqos_sched_red_config(port, s, params, n_subports);

    else if (params->cman_params->cman_mode == HQOS_SCHED_CMAN_PIE)
        return hqos_sched_pie_config(port, s, params, n_subports);

    return -EINVAL;
}



/********************* 
 * Function 
 *********************/

uint32_t
hqos_sched_port_get_memory_footprint(hqos_sched_port_params *port_params,
    hqos_sched_subport_params **subport_params)
{
    uint32_t size0 = 0, size1 = 0, i;
    int status;

    status = hqos_sched_port_check_params(port_params);
    if (status != 0) {
        clib_warning("%s: Port scheduler port params check failed (%d)", __func__, status);
        return 0;
    }

    for (i = 0; i < port_params->n_subports_per_port; i++) {
        hqos_sched_subport_params *sp = subport_params[i];

        status = hqos_sched_subport_check_params(sp,
                                                 port_params->n_pipes_per_subport,
                                                 port_params->rate);
        if (status != 0) {
            clib_warning("%s: Port scheduler subport params check failed (%d)", __func__, status);
            return 0;
        }
    }

    size0 = sizeof(hqos_sched_port);

    for (i = 0; i < port_params->n_subports_per_port; i++) {
        hqos_sched_subport_params *sp = subport_params[i];

        size1 += hqos_sched_subport_get_array_base(sp, e_HQOS_SCHED_SUBPORT_ARRAY_TOTAL);
    }

    return size0 + size1;
}

hqos_sched_port *
hqos_sched_port_config(hqos_sched_port_params *params)
{
    vlib_main_t *vm = hqos_vlib_get_main ();
    hqos_sched_port *port = NULL;
    u32 size0, size1, size2;
    u64 cycles_per_byte;
    u32 i, j;
    int status;

    status = hqos_sched_port_check_params(params);
    if (status != 0) {
        clib_warning("%s: Port scheduler params check failed (%d)", __func__, status);
        return NULL;
    }

    size0 = sizeof(hqos_sched_port);
    size1 = params->n_subports_per_port * sizeof(hqos_sched_subport *);
    size2 = params->n_max_subport_profiles * sizeof(hqos_sched_subport_profile);

    /* Allocate memory to store the data structures */
    port = clib_mem_alloc_aligned(size0 + size1, CLIB_CACHE_LINE_BYTES);
    if (port == NULL) {
        clib_warning("%s: Memory allocation fails", __func__);
        return NULL;
    }
    clib_memset(port, 0, clib_mem_size(port));

    /* Allocate memory to store the subport profile */
    port->subport_profiles  = clib_mem_alloc_aligned(size2, CLIB_CACHE_LINE_BYTES);
    if (port->subport_profiles == NULL) {
        clib_warning("%s: Memory allocation fails", __func__);
        clib_mem_free(port);
        return NULL;
    }
    clib_memset(port->subport_profiles, 0, clib_mem_size(port->subport_profiles));

    /* User parameters */
    port->n_subports_per_port = params->n_subports_per_port;
    port->n_subport_profiles = params->n_subport_profiles;
    port->n_max_subport_profiles = params->n_max_subport_profiles;
    port->n_pipes_per_subport = params->n_pipes_per_subport;
    port->n_pipes_per_subport_log2 = hqos_count_trailing_zeros_32(params->n_pipes_per_subport);
    port->n_queue_size = params->n_queue_size;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
        port->pipe_queue[i] = i;

    for (i = 0, j = 0; i < HQOS_SCHED_QUEUES_PER_PIPE; i++) {
        port->pipe_tc[i] = j;

        if (j < HQOS_SCHED_TRAFFIC_CLASS_BE)
            j++;
    }

    for (i = 0, j = 0; i < HQOS_SCHED_QUEUES_PER_PIPE; i++) {
        port->tc_queue[i] = j;

        if (i >= HQOS_SCHED_TRAFFIC_CLASS_BE)
            j++;
    }

    port->rate = params->rate;
    port->mtu = params->mtu + params->frame_overhead;
    port->frame_overhead = params->frame_overhead;

    /* Timing */
    port->time_cpu_cycles = clib_cpu_time_now();
    port->time_cpu_bytes = 0;
    port->time = 0;

    /* Subport profile table */
    hqos_sched_port_config_subport_profile_table(port, params, port->rate);

    cycles_per_byte = ((u64)vm->clib_time.clocks_per_second << HQOS_SCHED_TIME_SHIFT) / params->rate;
    port->inv_cycles_per_byte = hqos_reciprocal_value_u64(cycles_per_byte);
    port->cycles_per_byte = cycles_per_byte;

    /* Grinders */
    port->pkts_out = NULL;
    port->n_pkts_out = 0;
    port->subport_id = 0;

    return port;
}

void
hqos_sched_port_free(hqos_sched_port *port)
{
    u32 i;

    /* Check user parameters */
    if (port == NULL)
        return;

    for (i = 0; i < port->n_subports_per_port; i++)
        hqos_sched_subport_free(port, port->subports[i]);

    clib_mem_free(port->subport_profiles);
    clib_mem_free(port);
}

int
hqos_sched_port_subport_profile_add(hqos_sched_port *port,
                                    hqos_sched_subport_profile_params *params,
                                    u32 *subport_profile_id)
{
    int status;
    hqos_sched_subport_profile *dst;

    /* Port */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter profile", __func__);
        return -EINVAL;
    }

    if (subport_profile_id == NULL) {
        clib_warning("%s: Incorrect value for parameter subport_profile_id", __func__);
        return -EINVAL;
    }

    dst = port->subport_profiles + port->n_subport_profiles;

    /* Subport profiles exceeds the max limit */
    if (port->n_subport_profiles >= port->n_max_subport_profiles) {
        clib_warning("%s: Number of subport profiles exceeds the max limit", __func__);
        return -EINVAL;
    }

    status = hqos_subport_profile_check(params, port->rate);
    if (status != 0) {
        clib_warning("%s: subport profile check failed(%d)", __func__, status);
        return -EINVAL;
    }

    hqos_sched_subport_profile_convert(params, dst, port->rate);

    /* Subport profile commit */
    *subport_profile_id = port->n_subport_profiles;
    port->n_subport_profiles++;

    hqos_sched_port_log_subport_profile(port, *subport_profile_id);

    return 0;
}

int
hqos_sched_port_subport_profile_update(hqos_sched_port *port,
                                    hqos_sched_subport_profile_params *params,
                                    u32 subport_profile_id)
{
    int status;
    hqos_sched_subport_profile *dst;

    /* Port */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (params == NULL) {
        clib_warning("%s: Incorrect value for parameter profile", __func__);
        return -EINVAL;
    }

    if (subport_profile_id >= port->n_subport_profiles)
    {
        clib_warning("%s: subport profile id is invalid", __func__);
        return -EINVAL;
    }

    dst = port->subport_profiles + subport_profile_id;

    /* Subport profiles exceeds the max limit */
    if (port->n_subport_profiles >= port->n_max_subport_profiles) {
        clib_warning("%s: Number of subport profiles exceeds the max limit", __func__);
        return -EINVAL;
    }

    status = hqos_subport_profile_check(params, port->rate);
    if (status != 0) {
        clib_warning("%s: subport profile check failed(%d)", __func__, status);
        return -EINVAL;
    }

    hqos_sched_subport_profile_convert(params, dst, port->rate);

    hqos_sched_port_log_subport_profile(port, subport_profile_id);

    return 0;
}

int
hqos_sched_subport_pipe_profile_add(hqos_sched_port *port,
                                    uint32_t subport_id,
                                    hqos_sched_pipe_params *params,
                                    uint32_t *pipe_profile_id)
{
    hqos_sched_subport *s;
    hqos_sched_pipe_profile *pp;
    hqos_sched_subport_profile *sp;
    int status;

    /* Port */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    /* Subport id not exceeds the max limit */
    if (subport_id > port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for subport id", __func__);
        return -EINVAL;
    }

    s = port->subports[subport_id];

    /* Pipe profiles exceeds the max limit */
    if (s->n_pipe_profiles >= s->n_max_pipe_profiles) {
        clib_warning("%s: Number of pipe profiles exceeds the max limit", __func__);
        return -EINVAL;
    }

    sp = port->subport_profiles + s->profile;

    /* Pipe params */
    status = hqos_pipe_profile_check(params, sp->orig_tb_rate, &s->qsize[0]);
    if (status != 0) {
        clib_warning("%s: Pipe profile check failed(%d)", __func__, status);
        return -EINVAL;
    }

    pp = &s->pipe_profiles[s->n_pipe_profiles];
    hqos_sched_pipe_profile_convert(s, params, pp, sp->orig_tb_rate);

    /* Pipe profile commit */
    *pipe_profile_id = s->n_pipe_profiles;
    s->n_pipe_profiles++;

    if (s->pipe_tc_be_rate_max < params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE])
        s->pipe_tc_be_rate_max = params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE];

    hqos_sched_port_log_pipe_profile(s, *pipe_profile_id);

    return 0;
}

int
hqos_sched_subport_pipe_profile_update(hqos_sched_port *port,
                                    uint32_t subport_id,
                                    hqos_sched_pipe_params *params,
                                    uint32_t pipe_profile_id)
{
    hqos_sched_subport *s;
    hqos_sched_pipe_profile *pp;
    hqos_sched_subport_profile *sp;
    int status;

    /* Port */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    /* Subport id not exceeds the max limit */
    if (subport_id > port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for subport id", __func__);
        return -EINVAL;
    }

    s = port->subports[subport_id];

    /* Pipe profiles exceeds the max limit */
    if (s->n_pipe_profiles >= s->n_max_pipe_profiles) {
        clib_warning("%s: Number of pipe profiles exceeds the max limit", __func__);
        return -EINVAL;
    }

    sp = port->subport_profiles + s->profile;

    /* Pipe profile id valid */
    if (pipe_profile_id >= s->n_pipe_profiles)
    {
        clib_warning("%s: pipe profiles id invalid", __func__);
        return -EINVAL;
    }

    /* Pipe params */
    status = hqos_pipe_profile_check(params, sp->orig_tb_rate, &s->qsize[0]);
    if (status != 0) {
        clib_warning("%s: Pipe profile check failed(%d)", __func__, status);
        return -EINVAL;
    }

    pp = &s->pipe_profiles[pipe_profile_id];
    hqos_sched_pipe_profile_convert(s, params, pp, sp->orig_tb_rate);

    if (s->pipe_tc_be_rate_max < params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE])
        s->pipe_tc_be_rate_max = params->tc_rate[HQOS_SCHED_TRAFFIC_CLASS_BE];

    hqos_sched_port_log_pipe_profile(s, pipe_profile_id);

    return 0;
}

int
hqos_sched_subport_tc_ov_config(hqos_sched_port *port,
                                u32 subport_id,
                                bool tc_ov_enable)
{
    hqos_sched_subport *s;

    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (subport_id >= port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for parameter subport id", __func__);
        return  -EINVAL;
    }

    s = port->subports[subport_id];
    s->tc_ov_enabled = tc_ov_enable ? 1 : 0;

    return 0;
}

int
hqos_sched_subport_config(hqos_sched_port *port,
                          u32 subport_id,
                          hqos_sched_subport_params *params,
                          u32 subport_profile_id)
{
    hqos_sched_subport *s = NULL;
    hqos_sched_subport_profile *profile;

    u32 n_subports = subport_id;
    u32 n_subport_pipe_queues, i;
    u32 size0, size1, bmp_mem_size;
    int status;
    int ret;

    /* Check user parameters */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return 0;
    }

    if (subport_id >= port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for subport id", __func__);
        ret = -EINVAL;
        goto out;
    }

    if (subport_profile_id >= port->n_max_subport_profiles) {
        clib_warning("%s: Number of subport profile exceeds the max limit", __func__);
        ret = -EINVAL;
        goto out;
    }

    /** Memory is allocated only on first invocation of the api for a
     * given subport. Subsequent invocation on same subport will just
     * update subport bandwidth parameter.
     */
    if (port->subports[subport_id] == NULL) {

        status = hqos_sched_subport_check_params(params, port->n_pipes_per_subport, port->rate);
        if (status != 0) {
            clib_warning( "%s: Port scheduler params check failed (%d)", __func__, status);
            ret = -EINVAL;
            goto out;
        }

        /* Determine the amount of memory to allocate */
        size0 = sizeof(hqos_sched_subport);
        size1 = hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_TOTAL);

        /* Allocate memory to store the data structures */
        s = clib_mem_alloc_aligned(size0 + size1, CLIB_CACHE_LINE_BYTES);
        if (s == NULL) {
            clib_warning("%s: Memory allocation fails", __func__);
            ret = -ENOMEM;
            goto out;
        }

        clib_memset(s, 0, clib_mem_size(s));

        n_subports++;

        s->tb_time = port->time;

        /* User parameters */
        s->n_pipes_per_subport_enabled = params->n_pipes_per_subport_enabled;
        memcpy(s->qsize, params->qsize, sizeof(params->qsize));
        s->n_pipe_profiles = params->n_pipe_profiles;
        s->n_max_pipe_profiles = params->n_max_pipe_profiles;

        /* TC oversubscription is enabled by default */
        s->tc_ov_enabled = 1;

        if (params->cman_params != NULL) 
        {
            s->cman_enabled = true;
            status = hqos_sched_cman_config(port, s, params, n_subports);
            if (status) {
                clib_warning("%s: CMAN configuration fails", __func__);
                return status;
            }
        } 
        else 
        {
            s->cman_enabled = false;
        }

        /* Scheduling loop detection */
        s->pipe_loop = HQOS_SCHED_PIPE_INVALID;
        s->pipe_exhaustion = 0;

        /* Grinders */
        s->busy_grinders = 0;

        /* Queue base calculation */
        hqos_sched_subport_config_qsize(s);

        /* Large data structures */
        s->pipe = (hqos_sched_pipe *) (s->memory + hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_PIPE));
        s->queue = (hqos_sched_queue *) (s->memory + hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE));
        s->queue_extra = (hqos_sched_queue_extra *) (s->memory + hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_EXTRA));
        s->pipe_profiles = (hqos_sched_pipe_profile *) (s->memory + hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_PIPE_PROFILES));
        s->bmp_array =  s->memory + hqos_sched_subport_get_array_base( params, e_HQOS_SCHED_SUBPORT_ARRAY_BMP_ARRAY); 
        s->queue_array = (vlib_buffer_t **) (s->memory + hqos_sched_subport_get_array_base(params, e_HQOS_SCHED_SUBPORT_ARRAY_QUEUE_ARRAY));

        /* Pipe profile table */
        hqos_sched_subport_config_pipe_profile_table(s, params, port->rate);

        /* Bitmap */
        n_subport_pipe_queues = hqos_sched_subport_pipe_queues(s);
        bmp_mem_size = hqos_bitmap_get_memory_footprint(n_subport_pipe_queues);
        s->bmp = hqos_bitmap_init(n_subport_pipe_queues, s->bmp_array, bmp_mem_size);
        if (s->bmp == NULL) {
            clib_warning("%s: Subport bitmap init error", __func__);
            ret = -EINVAL;
            goto out;
        }

        for (i = 0; i < HQOS_SCHED_PORT_N_GRINDERS; i++)
            s->grinder_base_bmp_pos[i] = HQOS_SCHED_PIPE_INVALID;

        /* TC oversubscription */
        s->tc_ov_period_id = 0;
        s->tc_ov = 0;
        s->tc_ov_n = 0;
        s->tc_ov_rate = 0;

        /* Port */
        port->subports[subport_id] = s;
        port->n_active_subports++;
    }
    {
        /* update subport parameters from subport profile table*/
        profile = port->subport_profiles + subport_profile_id;

        s = port->subports[subport_id];

        s->tb_credits = profile->tb_size / 2;

        s->tb_time = port->time;

        s->tc_time = port->time + profile->tc_period;

        for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
            if (s->qsize[i])
                s->tc_credits[i] = profile->tc_credits_per_period[i];
            else
                profile->tc_credits_per_period[i] = 0;

        s->tc_ov_wm_min = hqos_sched_time_ms_to_bytes(profile->tc_period, port->mtu);
        s->tc_ov_wm_max = hqos_sched_time_ms_to_bytes(profile->tc_period, s->pipe_tc_be_rate_max);
        s->tc_ov_wm = s->tc_ov_wm_max;
        s->profile = subport_profile_id;

    }

    hqos_sched_port_log_subport_profile(port, subport_profile_id);

    return 0;

out:
    hqos_sched_free_memory(port, n_subports);

    return ret;
}

int
hqos_sched_pipe_config(hqos_sched_port *port,
                       u32 subport_id,
                       u32 pipe_id,
                       int pipe_profile)
{
    hqos_sched_subport *s;
    hqos_sched_subport_profile *sp;
    hqos_sched_pipe *p;
    hqos_sched_pipe_profile *params;
    u32 n_subports = subport_id + 1;
    u32 deactivate, profile, i;
    int ret;

    /* Check user parameters */
    profile = (u32) pipe_profile;
    deactivate = (pipe_profile < 0);

    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (subport_id >= port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for parameter subport id", __func__);
        ret = -EINVAL;
        goto out;
    }

    s = port->subports[subport_id];
    if (pipe_id >= s->n_pipes_per_subport_enabled) {
        clib_warning("%s: Incorrect value for parameter pipe id", __func__);
        ret = -EINVAL;
        goto out;
    }

    if (!deactivate && profile >= s->n_pipe_profiles) {
        clib_warning("%s: Incorrect value for parameter pipe profile", __func__);
        ret = -EINVAL;
        goto out;
    }

    sp = port->subport_profiles + s->profile;
    /* Handle the case when pipe already has a valid configuration */
    p = s->pipe + pipe_id;
    if (p->tb_time) 
    {
        params = s->pipe_profiles + p->profile;

        f64 subport_tc_be_rate = (f64)sp->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] / (f64) sp->tc_period;
        f64 pipe_tc_be_rate = (f64) params->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] / (f64) params->tc_period;
        u32 tc_be_ov = s->tc_ov;

        /* Unplug pipe from its subport */
        s->tc_ov_n -= params->tc_ov_weight;
        s->tc_ov_rate -= pipe_tc_be_rate;
        s->tc_ov = s->tc_ov_rate > subport_tc_be_rate;

        if (s->tc_ov != tc_be_ov) {
            clib_warning("Subport %u Best-effort TC oversubscription is OFF (%.4lf >= %.4lf)",
                    subport_id, subport_tc_be_rate, s->tc_ov_rate);
        }

        /* Reset the pipe */
        memset(p, 0, sizeof(hqos_sched_pipe));
    }

    if (deactivate)
        return 0;

    /* Apply the new pipe configuration */
    p->profile = profile;
    params = s->pipe_profiles + p->profile;

    /* Token Bucket (TB) */
    p->tb_time = port->time;
    p->tb_credits = params->tb_size / 2;

    /* Traffic Classes (TCs) */
    p->tc_time = port->time + params->tc_period;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        if (s->qsize[i])
            p->tc_credits[i] = params->tc_credits_per_period[i];
    }

    {
        /* Subport best effort tc oversubscription */
        f64 subport_tc_be_rate = (f64)sp->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] / (f64) sp->tc_period;
        f64 pipe_tc_be_rate = (f64) params->tc_credits_per_period[HQOS_SCHED_TRAFFIC_CLASS_BE] / (f64) params->tc_period;
        u32 tc_be_ov = s->tc_ov;

        s->tc_ov_n += params->tc_ov_weight;
        s->tc_ov_rate += pipe_tc_be_rate;
        s->tc_ov = s->tc_ov_rate > subport_tc_be_rate;

        if (s->tc_ov != tc_be_ov) {
            clib_warning("Subport %u Best effort TC oversubscription is ON (%.4lf < %.4lf)",
                    subport_id, subport_tc_be_rate, s->tc_ov_rate);
        }
        p->tc_ov_period_id = s->tc_ov_period_id;
        p->tc_ov_credits = s->tc_ov_wm;
    }

    return 0;

out:
    hqos_sched_free_memory(port, n_subports);

    return ret;
}


/*
 * The enqueue function implements a 4-level pipeline with each stage
 * processing two different packets. The purpose of using a pipeline
 * is to hide the latency of prefetching the data structures. The
 * naming convention is presented in the diagram below:
 *
 *   p00  _______   p10  _______   p20  _______   p30  _______
 * ----->|       |----->|       |----->|       |----->|       |----->
 *       |   0   |      |   1   |      |   2   |      |   3   |
 * ----->|_______|----->|_______|----->|_______|----->|_______|----->
 *   p01            p11            p21            p31
 */
int
hqos_sched_port_enqueue(hqos_sched_port *port, vlib_buffer_t **pkts, u32 n_pkts)
{
    vlib_buffer_t *pkt00, *pkt01, 
                  *pkt10, *pkt11, 
                  *pkt20, *pkt21, 
                  *pkt30, *pkt31, 
                  *pkt_last;

    vlib_buffer_t **q00_base, **q01_base, 
                  **q10_base, **q11_base, 
                  **q20_base, **q21_base, 
                  **q30_base, **q31_base, 
                  **q_last_base;

    hqos_sched_subport *subport00, *subport01, 
                       *subport10, *subport11, 
                       *subport20, *subport21, 
                       *subport30, *subport31, 
                       *subport_last;
    u32 q00, q01, 
        q10, q11, 
        q20, q21, 
        q30, q31, 
        q_last;
    u32 r00, r01, 
        r10, r11, 
        r20, r21, 
        r30, r31, 
        r_last;

    u32 subport_qmask;
    u32 result, i;

    result = 0;
    subport_qmask = (1 << (port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2)) - 1;

    /*
     * Less then 6 input packets available, which is not enough to
     * feed the pipeline
     */
    if (PREDICT_FALSE(n_pkts < 6)) {
        hqos_sched_subport *subports[5];
        vlib_buffer_t **q_base[5];
        uint32_t q[5];

        /* Prefetch the mbuf structure of each packet */
        for (i = 0; i < n_pkts; i++)
            vlib_prefetch_buffer_header(pkts[i], LOAD);

        /* Prefetch the subport structure for each packet */
        for (i = 0; i < n_pkts; i++)
            subports[i] = hqos_sched_port_subport(port, pkts[i]);

        /* Prefetch the queue structure for each queue */
        for (i = 0; i < n_pkts; i++)
            q[i] = hqos_sched_port_enqueue_qptrs_prefetch0(subports[i], pkts[i], subport_qmask);

        /* Prefetch the write pointer location of each queue */
        for (i = 0; i < n_pkts; i++) {
            q_base[i] = hqos_sched_subport_pipe_qbase(subports[i], q[i]);
            hqos_sched_port_enqueue_qwa_prefetch0(port, subports[i], q[i], q_base[i]);
        }

        /* Write each packet to its queue */
        for (i = 0; i < n_pkts; i++)
            result += hqos_sched_port_enqueue_qwa(port, subports[i], q[i], q_base[i], pkts[i]);

        return result;
    }

    /* Feed the first 3 stages of the pipeline (6 packets needed) */
    pkt20 = pkts[0];
    pkt21 = pkts[1];
    vlib_prefetch_buffer_header(pkt20, LOAD);
    vlib_prefetch_buffer_header(pkt21, LOAD);

    pkt10 = pkts[2];
    pkt11 = pkts[3];
    vlib_prefetch_buffer_header(pkt10, LOAD);
    vlib_prefetch_buffer_header(pkt11, LOAD);

    subport20 = hqos_sched_port_subport(port, pkt20);
    subport21 = hqos_sched_port_subport(port, pkt21);

    q20 = hqos_sched_port_enqueue_qptrs_prefetch0(subport20, pkt20, subport_qmask);
    q21 = hqos_sched_port_enqueue_qptrs_prefetch0(subport21, pkt21, subport_qmask);

    pkt00 = pkts[4];
    pkt01 = pkts[5];
    vlib_prefetch_buffer_header(pkt00, LOAD);
    vlib_prefetch_buffer_header(pkt01, LOAD);

    subport10 = hqos_sched_port_subport(port, pkt10);
    subport11 = hqos_sched_port_subport(port, pkt11);

    q10 = hqos_sched_port_enqueue_qptrs_prefetch0(subport10, pkt10, subport_qmask);
    q11 = hqos_sched_port_enqueue_qptrs_prefetch0(subport11, pkt11, subport_qmask);

    q20_base = hqos_sched_subport_pipe_qbase(subport20, q20);
    q21_base = hqos_sched_subport_pipe_qbase(subport21, q21);

    hqos_sched_port_enqueue_qwa_prefetch0(port, subport20, q20, q20_base);
    hqos_sched_port_enqueue_qwa_prefetch0(port, subport21, q21, q21_base);

    /* Run the pipeline */
    for (i = 6; i < (n_pkts & (~1)); i += 2) {
        /* Propagate stage inputs */
        pkt30 = pkt20;
        pkt31 = pkt21;
        pkt20 = pkt10;
        pkt21 = pkt11;
        pkt10 = pkt00;
        pkt11 = pkt01;
        q30 = q20;
        q31 = q21;
        q20 = q10;
        q21 = q11;
        subport30 = subport20;
        subport31 = subport21;
        subport20 = subport10;
        subport21 = subport11;
        q30_base = q20_base;
        q31_base = q21_base;

        /* Stage 0: Get packets in */
        pkt00 = pkts[i];
        pkt01 = pkts[i + 1];
        vlib_prefetch_buffer_header(pkt00, LOAD);
        vlib_prefetch_buffer_header(pkt01, LOAD);

        /* Stage 1: Prefetch subport and queue structure storing queue pointers */
        subport10 = hqos_sched_port_subport(port, pkt10);
        subport11 = hqos_sched_port_subport(port, pkt11);

        q10 = hqos_sched_port_enqueue_qptrs_prefetch0(subport10, pkt10, subport_qmask);
        q11 = hqos_sched_port_enqueue_qptrs_prefetch0(subport11, pkt11, subport_qmask);

        /* Stage 2: Prefetch queue write location */
        q20_base = hqos_sched_subport_pipe_qbase(subport20, q20);
        q21_base = hqos_sched_subport_pipe_qbase(subport21, q21);

        hqos_sched_port_enqueue_qwa_prefetch0(port, subport20, q20, q20_base);
        hqos_sched_port_enqueue_qwa_prefetch0(port, subport21, q21, q21_base);

        /* Stage 3: Write packet to queue and activate queue */
        r30 = hqos_sched_port_enqueue_qwa(port, subport30, q30, q30_base, pkt30);
        r31 = hqos_sched_port_enqueue_qwa(port, subport31, q31, q31_base, pkt31);
        result += r30 + r31;
    }

    /*
     * Drain the pipeline (exactly 6 packets).
     * Handle the last packet in the case
     * of an odd number of input packets.
     */

    pkt_last = pkts[n_pkts - 1];
    vlib_prefetch_buffer_header(pkt_last, LOAD);

    subport00 = hqos_sched_port_subport(port, pkt00);
    subport01 = hqos_sched_port_subport(port, pkt01);

    q00 = hqos_sched_port_enqueue_qptrs_prefetch0(subport00, pkt00, subport_qmask);
    q01 = hqos_sched_port_enqueue_qptrs_prefetch0(subport01, pkt01, subport_qmask);

    q10_base = hqos_sched_subport_pipe_qbase(subport10, q10);
    q11_base = hqos_sched_subport_pipe_qbase(subport11, q11);

    hqos_sched_port_enqueue_qwa_prefetch0(port, subport10, q10, q10_base);
    hqos_sched_port_enqueue_qwa_prefetch0(port, subport11, q11, q11_base);

    r20 = hqos_sched_port_enqueue_qwa(port, subport20, q20, q20_base, pkt20);
    r21 = hqos_sched_port_enqueue_qwa(port, subport21, q21, q21_base, pkt21);
    result += r20 + r21;

    subport_last = hqos_sched_port_subport(port, pkt_last);
    q_last = hqos_sched_port_enqueue_qptrs_prefetch0(subport_last, pkt_last, subport_qmask);                                                       

    q00_base = hqos_sched_subport_pipe_qbase(subport00, q00);                                    
    q01_base = hqos_sched_subport_pipe_qbase(subport01, q01);                                    

    hqos_sched_port_enqueue_qwa_prefetch0(port, subport00, q00, q00_base);                       
    hqos_sched_port_enqueue_qwa_prefetch0(port, subport01, q01, q01_base);                       

    r10 = hqos_sched_port_enqueue_qwa(port, subport10, q10, q10_base, pkt10);
    r11 = hqos_sched_port_enqueue_qwa(port, subport11, q11, q11_base, pkt11);
    result += r10 + r11;                                                                        

    q_last_base = hqos_sched_subport_pipe_qbase(subport_last, q_last);
    hqos_sched_port_enqueue_qwa_prefetch0(port, subport_last, q_last, q_last_base);

    r00 = hqos_sched_port_enqueue_qwa(port, subport00, q00, q00_base, pkt00);
    r01 = hqos_sched_port_enqueue_qwa(port, subport01, q01, q01_base, pkt01);
    result += r00 + r01;

    if (n_pkts & 1) {
        r_last = hqos_sched_port_enqueue_qwa(port, subport_last, q_last, q_last_base, pkt_last);
        result += r_last; 
    }

    return result;
}

int
hqos_sched_port_dequeue(hqos_sched_port *port, vlib_buffer_t **pkts, u32 n_pkts)
{
    hqos_sched_subport *subport;
    u32 subport_id = port->subport_id;
    u32 i, n_subports = 0, count;

    port->pkts_out = pkts;
    port->n_pkts_out = 0;

    hqos_sched_port_time_resync(port);

    /* Take each queue in the grinder one step further */
    for (i = 0, count = 0; ; i++)  {
        subport = port->subports[subport_id];

        count += hqos_grinder_handle(port, subport, i & (HQOS_SCHED_PORT_N_GRINDERS - 1));

        if (count == n_pkts) {
            subport_id++;

            if (subport_id == port->n_active_subports)
                subport_id = 0;

            port->subport_id = subport_id;
            break;
        }

        if (hqos_sched_port_exceptions(subport, i >= HQOS_SCHED_PORT_N_GRINDERS)) {
            i = 0;
            subport_id++;
            n_subports++;
        }

        if (subport_id == port->n_active_subports)
            subport_id = 0;

        if (n_subports == port->n_active_subports) {
            port->subport_id = subport_id;
            break;
        }
    }

    return count;
}


/*************************** 
 * Statistics Function 
 ***************************/

int
hqos_sched_subport_read_stats(hqos_sched_port *port,
                              u32 subport_id,
                              hqos_sched_subport_stats *stats,
                              u32 *tc_ov)
{
    hqos_sched_subport *s;

    /* Check user parameters */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (subport_id >= port->n_subports_per_port) {
        clib_warning("%s: Incorrect value for subport id", __func__);
        return -EINVAL;
    }

    if (stats == NULL) {
        clib_warning("%s: Incorrect value for parameter stats", __func__);
        return -EINVAL;
    }

    if (tc_ov == NULL) {
        clib_warning("%s: Incorrect value for tc_ov", __func__);
        return -EINVAL;
    }

    s = port->subports[subport_id];

    /* Copy subport stats and clear */
    memcpy(stats, &s->stats, sizeof(hqos_sched_subport_stats));
    memset(&s->stats, 0, sizeof(hqos_sched_subport_stats));

    /* Subport TC oversubscription status */
    *tc_ov = s->tc_ov;

    return 0;
}

int
hqos_sched_queue_read_stats(hqos_sched_port *port,
                            u32 queue_id,
                            hqos_sched_queue_stats *stats,
                            u16 *qlen)
{
    hqos_sched_subport *s;
    hqos_sched_queue *q;
    hqos_sched_queue_extra *qe;
    u32 subport_id, subport_qmask, subport_qindex;

    /* Check user parameters */
    if (port == NULL) {
        clib_warning("%s: Incorrect value for parameter port", __func__);
        return -EINVAL;
    }

    if (queue_id >= hqos_sched_port_queues_per_port(port)) {
        clib_warning("%s: Incorrect value for queue id", __func__);
        return -EINVAL;
    }

    if (stats == NULL) {
        clib_warning("%s: Incorrect value for parameter stats", __func__);
        return -EINVAL;
    }

    if (qlen == NULL) {
        clib_warning("%s: Incorrect value for parameter qlen", __func__);
        return -EINVAL;
    }

    subport_qmask = port->n_pipes_per_subport_log2 + HQOS_SCHED_QUEUES_PER_PIPE_LOG2; //4 is queue log2
    subport_id = (queue_id >> subport_qmask) & (port->n_subports_per_port - 1);

    s = port->subports[subport_id];
    subport_qindex = ((1 << subport_qmask) - 1) & queue_id;
    q = s->queue + subport_qindex;
    qe = s->queue_extra + subport_qindex;

    /* Copy queue stats and clear */
    memcpy(stats, &qe->stats, sizeof(hqos_sched_queue_stats));
    memset(&qe->stats, 0, sizeof(hqos_sched_queue_stats));

    /* Queue length */
    *qlen = q->qw - q->qr;

    return 0;
}
