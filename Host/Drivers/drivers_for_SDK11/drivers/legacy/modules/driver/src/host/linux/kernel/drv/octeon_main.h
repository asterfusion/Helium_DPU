/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_main.h
    \brief Host Driver: This file is included by all host driver source files
                        to include common definitions.
*/

#ifndef  _OCTEON_MAIN_H_
#define  _OCTEON_MAIN_H_

#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "cavium_kernel_defs.h"
#include "cavium-list.h"
#include "octeon_device.h"
#include "octeon-opcodes.h"
#include "octeon-common.h"


/** Driver's State.
 */
typedef enum {

	OCT_DRV_DEVICE_INIT_START,
	OCT_DRV_DEVICE_INIT_DONE,
	OCT_DRV_REGISTER_DONE,
	OCT_DRV_POLL_INIT_DONE,
	OCT_DRV_ACTIVE
} OCTEON_DRIVER_STATUS;

void octeon_unmap_pci_barx(octeon_device_t * oct, int baridx);

int octeon_map_pci_barx(octeon_device_t * oct, int baridx, int max_map_len);

void octeon_destroy_resources(octeon_device_t * oct_dev);

void octeon_stop_device(octeon_device_t * oct);

void octeon_oei_irq_handler(octeon_device_t *oct, u64 reg_val);
#endif
/* $Id: octeon_main.h 141410 2016-06-30 14:37:41Z mchalla $ */
