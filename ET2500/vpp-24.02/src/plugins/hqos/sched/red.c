/*                                                                                   
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#include <math.h>
#include "hqos/sched/red.h"
#include "hqos/sched/sched_common.h"


static int hqos_red_init_done = 0;     /**< Flag to indicate that global initialisation is done */
u32 hqos_red_rand_val = 0;        /**< Random value cache */
u32 hqos_red_rand_seed = 0;       /**< Seed for random number generation */

/**
 * table[i] = log2(1-Wq) * Scale * -1
 *       Wq = 1/(2^i)
 */
uint16_t hqos_red_log2_1_minus_Wq[HQOS_RED_WQ_LOG2_NUM];

/**
 * table[i] = 2^(i/16) * Scale
 */
uint16_t hqos_red_pow2_frac_inv[16];

/**
 * @brief Initialize tables used to compute average
 *        queue size when queue is empty.
 */
static void
__hqos_red_init_tables(void)
{
    u32 i = 0;
    f64 scale = 0.0;
    f64 table_size = 0.0;

    scale = (f64)(1 << HQOS_RED_SCALING);
    table_size = (f64)(ARRAY_LEN(hqos_red_pow2_frac_inv));

    for (i = 0; i < ARRAY_LEN(hqos_red_pow2_frac_inv); i++) {
        f64 m = (f64)i;

        hqos_red_pow2_frac_inv[i] = (f64) round(scale / pow(2, m / table_size));
    }

    scale = 1024.0;

    ASSERT(HQOS_RED_WQ_LOG2_NUM == ARRAY_LEN(hqos_red_log2_1_minus_Wq));

    for (i = HQOS_RED_WQ_LOG2_MIN; i <= HQOS_RED_WQ_LOG2_MAX; i++) {
        f64 n = (f64)i;
        f64 Wq = pow(2, -n);
        u32 index = i - HQOS_RED_WQ_LOG2_MIN;

        hqos_red_log2_1_minus_Wq[index] = (u16) round(-1.0 * scale * log2(1.0 - Wq));
        /**
         * Table entry of zero, corresponds to a Wq of zero
         * which is not valid (avg would remain constant no
         * matter how long the queue is empty). So we have
         * to check for zero and round up to one.
         */
        if (hqos_red_log2_1_minus_Wq[index] == 0) {
            hqos_red_log2_1_minus_Wq[index] = 1;
        }
    }
}

int
hqos_red_config_init(hqos_red_config *red_cfg,
                     const u16 wq_log2,
                     const u16 min_th,
                     const u16 max_th,
                     const u16 maxp_inv)
{

    if (red_cfg == NULL) {
        return -1;
    }
    if (max_th > HQOS_RED_MAX_TH_MAX) {
        return -2;
    }
    if (min_th >= max_th) {
        return -3;
    }
    if (wq_log2 > HQOS_RED_WQ_LOG2_MAX) {
        return -4;
    }
    if (wq_log2 < HQOS_RED_WQ_LOG2_MIN) {
        return -5;
    }
    if (maxp_inv < HQOS_RED_MAXP_INV_MIN) {
        return -6;
    }
    if (maxp_inv > HQOS_RED_MAXP_INV_MAX) {
        return -7;
    }

    /**
     *  Initialize the RED module if not already done
     */
    if (!hqos_red_init_done) {
        hqos_red_rand_seed = random_default_seed();
        hqos_red_rand_val = hqos_fast_rand();
        __hqos_red_init_tables();
        hqos_red_init_done = 1;
    }

    red_cfg->min_th = ((uint32_t) min_th) << (wq_log2 + HQOS_RED_SCALING);
    red_cfg->max_th = ((uint32_t) max_th) << (wq_log2 + HQOS_RED_SCALING);
    red_cfg->pa_const = (2 * (max_th - min_th) * maxp_inv) << HQOS_RED_SCALING;
    red_cfg->maxp_inv = maxp_inv;
    red_cfg->wq_log2 = wq_log2;

    return 0;
}
