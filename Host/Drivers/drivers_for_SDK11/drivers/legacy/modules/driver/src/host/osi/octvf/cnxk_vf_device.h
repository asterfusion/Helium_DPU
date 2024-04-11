/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cnxk_vf_device.h
    \brief Host Driver: Routines that perform CNXK specific VF domain operations.
*/

#ifndef  __CNXK_VF_DEVICE_H__
#define  __CNXK_VF_DEVICE_H__

#include "cnxk_vf_regs.h"

/* Register address and configuration for a CNXK devices.
 * If device specific changes need to be made then add a struct to include
 * device specific fields as shown in the commented section
 */
typedef struct {

	octeon_config_t *conf;

	octeon_device_t *oct;

} octeon_cnxk_vf_t;

void cnxk_vf_setup_global_output_regs(octeon_device_t * oct);

void cnxk_check_config_space_error_regs(octeon_device_t * oct);

int setup_cnxk_octeon_vf_device(octeon_device_t * oct);

int validate_cnxk_vf_config_info(cnxk_vf_config_t * conf_cnxk);

uint32_t cnxk_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us);

uint32_t cnxk_core_clock(octeon_device_t * oct);

void cnxk_dump_vf_initialized_regs(octeon_device_t * oct);
#endif

/* $Id$ */
