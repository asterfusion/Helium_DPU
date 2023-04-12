/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

/*! \file  cn83xx_pf_device.h
    \brief Host Driver: Routines that perform CN83XX specific PF domain operations.
*/

#ifndef  __CN83XX_PF_DEVICE_H__
#define  __CN83XX_PF_DEVICE_H__

#include "cn83xx_pf_regs.h"

/* Register address and configuration for a CN83XX devices.
 * If device specific changes need to be made then add a struct to include
 * device specific fields as shown in the commented section
 */
typedef struct {
	/** The PCI interrupt mask used by interrupt handler */
	uint64_t intr_mask64;

	cn83xx_pf_config_t *conf;

	octeon_device_t *oct;

} octeon_cn83xx_pf_t;

void cn83xx_pf_setup_global_output_regs(octeon_device_t * oct);

void cn83xx_check_config_space_error_regs(octeon_device_t * oct);

enum setup_stage setup_cn83xx_octeon_pf_device(octeon_device_t * oct);

void cn83xx_get_pf_num(octeon_device_t * oct);

int validate_cn83xx_pf_config_info(cn83xx_pf_config_t * conf83xx);

uint32_t cn83xx_get_oq_ticks(octeon_device_t * oct, uint32_t time_intr_in_us);

uint32_t cn83xx_core_clock(octeon_device_t * oct);

void cn83xx_dump_pf_initialized_regs(octeon_device_t * oct);
#endif

/* $Id$ */
