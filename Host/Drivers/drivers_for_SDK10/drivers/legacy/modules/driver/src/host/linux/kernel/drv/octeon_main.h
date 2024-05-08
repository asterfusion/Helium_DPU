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

#ifdef USE_BUFFER_POOL
#include "buffer_pool.h"
#endif

/** Driver's State.
 */
typedef enum {

	OCT_DRV_DEVICE_INIT_START,
	OCT_DRV_DEVICE_INIT_DONE,
	OCT_DRV_REGISTER_DONE,
	OCT_DRV_POLL_INIT_DONE,
	OCT_DRV_ACTIVE
} OCTEON_DRIVER_STATUS;

enum setup_stage {
	SETUP_SUCCESS,
	SETUP_FAIL,
	SETUP_IN_PROGRESS
};

void octeon_unmap_pci_barx(octeon_device_t * oct, int baridx);

int octeon_map_pci_barx(octeon_device_t * oct, int baridx, int max_map_len);

void octeon_destroy_resources(octeon_device_t * oct_dev);

void octeon_stop_device(octeon_device_t * oct);

#endif
/* $Id: octeon_main.h 141410 2016-06-30 14:37:41Z mchalla $ */
