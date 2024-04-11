/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cnxk_pf_device.h
    \brief Host Driver: Routines that perform CNXK specific PF domain operations.
*/

#ifndef  __CNXK_PF_DEVICE_H__
#define  __CNXK_PF_DEVICE_H__

#include "cnxk_pf_regs.h"

/* Register address and configuration for a CNXK devices.
 * If device specific changes need to be made then add a struct to include
 * device specific fields as shown in the commented section
 */
typedef struct {

	octeon_config_t *conf;

	octeon_device_t *oct;

} octeon_cnxk_pf_t;

void cnxk_pf_setup_global_output_regs(octeon_device_t * oct);

void cnxk_check_config_space_error_regs(octeon_device_t * oct);

int setup_cnxk_octeon_pf_device(octeon_device_t * oct);

void cnxk_get_pf_num(octeon_device_t * oct);

int validate_cnxk_pf_config_info(cnxk_pf_config_t * conf_cnxk);

uint32_t cnxk_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us);

uint32_t cnxk_core_clock(octeon_device_t * oct);

void cnxk_dump_pf_initialized_regs(octeon_device_t * oct);
#endif

/* $Id$ */
