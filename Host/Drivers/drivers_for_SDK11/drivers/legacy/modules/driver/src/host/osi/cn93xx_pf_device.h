/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cn93xx_pf_device.h
    \brief Host Driver: Routines that perform CN93XX specific PF domain operations.
*/

#ifndef  __CN93XX_PF_DEVICE_H__
#define  __CN93XX_PF_DEVICE_H__

#include "cn93xx_pf_regs.h"

/* Register address and configuration for a CN93XX devices.
 * If device specific changes need to be made then add a struct to include
 * device specific fields as shown in the commented section
 */
typedef struct {

	cn93xx_pf_config_t *conf;

	octeon_device_t *oct;

} octeon_cn93xx_pf_t;

void cn93xx_pf_setup_global_output_regs(octeon_device_t * oct);

void cn93xx_check_config_space_error_regs(octeon_device_t * oct);

int setup_cn93xx_octeon_pf_device(octeon_device_t * oct);
int setup_cn98xx_octeon_pf_device(octeon_device_t * oct);

void cn93xx_get_pf_num(octeon_device_t * oct);

int validate_cn93xx_pf_config_info(cn93xx_pf_config_t * conf93xx);

uint32_t cn93xx_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us);

uint32_t cn93xx_core_clock(octeon_device_t * oct);

void cn93xx_dump_pf_initialized_regs(octeon_device_t * oct);
#endif

/* $Id$ */
