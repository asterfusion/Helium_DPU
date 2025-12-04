/*                                                                                   
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#include <math.h>
#include "hqos/sched/pie.h"
#include "hqos/sched/sched_common.h"

int hqos_pie_config_init(hqos_pie_config *pie_cfg,
                                const u16 qdelay_ref,
                                const u16 dp_update_interval,
                                const u16 max_burst,
                                const u16 tailq_th)
{
    u64 cpu_hz = hqos_get_cpu_hz();

    if (pie_cfg == NULL)
        return -1;

    if (qdelay_ref <= 0) {
        clib_warning("%s: Incorrect value for qdelay_ref", __func__);
        return -EINVAL;
    }

    if (dp_update_interval <= 0) {
        clib_warning("%s: Incorrect value for dp_update_interval", __func__);
        return -EINVAL;
    }

    if (max_burst <= 0) {
        clib_warning("%s: Incorrect value for max_burst", __func__);
        return -EINVAL;
    }

    if (tailq_th <= 0) {
        clib_warning("%s: Incorrect value for tailq_th", __func__);
        return -EINVAL;
    }

    pie_cfg->qdelay_ref = (cpu_hz * qdelay_ref) / 1000;
    pie_cfg->dp_update_interval = (cpu_hz * dp_update_interval) / 1000;
    pie_cfg->max_burst = (cpu_hz * max_burst) / 1000;
    pie_cfg->tailq_th = tailq_th;

    return 0;
}
