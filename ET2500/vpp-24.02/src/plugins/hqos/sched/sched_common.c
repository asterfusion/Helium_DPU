/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#include "hqos/sched/sched_common.h"

clib_time_t hqos_clib_time;

void hqos_clib_time_init()
{
    clib_time_init(&hqos_clib_time);
}
