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
#ifndef __OCTEON_MAILBOX_H__
#define __OCTEON_MAILBOX_H__

#include "octeon_main.h"

//Mail Box Commands
#define OCTEON_VF_ACTIVE	  (0x1 << 16)
#define OCTEON_CORE_CONFIG	  (0x2 << 16)

//Macro for Read acknowldgement
#define OCTEON_PFVFACK			0xffffffffffffffffULL
#define OCTEON_PFVFSIG			0x1122334455667788ULL

typedef enum {
	OCT_MBOX_STATE_IDLE = 0,
	OCT_MBOX_STATE_BUSY = 1,
} oct_mbox_state_t;

typedef enum {
	OCT_MBOX_CMD_DONE = 0,
	OCT_MBOX_CMD_BUSY = 1
} oct_mbox_cmd_state_t;

typedef enum {
	MBOX_QIDX_UNUSED = 0,
	MBOX_QIDX_USED = 1
} oct_mbox_qidx_state_t;

typedef enum {
	MBOX_DATA_NONE = 0,
	MBOX_DATA_SEND = 1,
	MBOX_DATA_GET = 2
} oct_mbox_dir_t;

typedef int (*octeon_mbox_callback_t) (void *, unsigned long);

typedef struct {
	oct_mbox_qidx_state_t state;

	oct_mbox_dir_t dir;

	oct_mbox_cmd_state_t cmd_state;

	octeon_mbox_callback_t fn;

	unsigned long fn_arg;

	uint32_t cmd;

	uint32_t qno;

	uint32_t total_len;

	uint32_t recv_len;

	uint64_t *data;
} oct_mbox_cmd_t;

int octeon_mbox_add_to_queue(int oct_id, oct_mbox_cmd_t * cmd);

int octeon_mbox_send_cmd(octeon_device_t * oct, oct_mbox_cmd_t * cmd);
#endif
