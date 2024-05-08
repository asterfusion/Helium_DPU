// SPDX-License-Identifier: (GPL-2.0)
/* Mgmt ethernet driver
 *
 * Copyright (C) 2015-2019 Marvell, Inc.
 */

#ifndef _BAR_SPACE_MGMT_NET_H_
#define _BAR_SPACE_MGMT_NET_H_

#define OTXMN_DEV_TYPE_MGMT_NET	1

#define OTXMN_GLOBAL_REG_OFFSET	0
#define OTXMN_VERSION_REG	(OTXMN_GLOBAL_REG_OFFSET + 0)
#define	OTXMN_DEV_TYPE_REG	(OTXMN_GLOBAL_REG_OFFSET + 8)

#define OTXMN_HOST_DOWN			0
#define OTXMN_HOST_READY		1
#define OTXMN_HOST_RUNNING		2
#define OTXMN_HOST_GOING_DOWN		3
#define OTXMN_HOST_FATAL		4

#define OTXMN_HOST_RW_OFFSET		128
#define OTXMN_HOST_STATUS_REG		(OTXMN_HOST_RW_OFFSET + 0)
#define OTXMN_HOST_INTR_REG		(OTXMN_HOST_RW_OFFSET + 8)
#define OTXMN_HOST_MBOX_ACK_REG         (OTXMN_HOST_RW_OFFSET + 16)
#define OTXMN_HOST_MBOX_OFFSET		(OTXMN_HOST_RW_OFFSET + 24)

#define OTXMN_TARGET_DOWN		0
#define OTXMN_TARGET_READY		1
#define OTXMN_TARGET_RUNNING		2
#define OTXMN_TARGET_GOING_DOWN		3
#define OTXMN_TARGET_FATAL		4

#define OTXMN_TARGET_RW_OFFSET			256
#define OTXMN_TARGET_STATUS_REG			(OTXMN_TARGET_RW_OFFSET + 0)
#define OTXMN_TARGET_INTR_REG			(OTXMN_TARGET_RW_OFFSET + 8)
#define OTXMN_TARGET_MBOX_ACK_REG		(OTXMN_TARGET_RW_OFFSET + 16)
#define OTXMN_TARGET_MBOX_OFFSET		(OTXMN_TARGET_RW_OFFSET + 24)

#define OTXMN_TX_DESCQ_OFFSET	1024
#define OTXMN_RX_DESCQ_OFFSET	65536

#define OTXMN_BAR_SIZE 131072

#define OTXMN_MBOX_SIZE_WORDS 8
#define OTXMN_MBOX_HOST_STATUS_CHANGE 1
#define OTXMN_MBOX_TARGET_STATUS_CHANGE 2

#define	OTXMN_MBOX_TIMEOUT_MS 100
#define	OTXMN_MBOX_WAIT_MS 10
#define OTXMN_MBOX_DBELL_ID 0

struct otxmn_mbox_hdr {
	uint64_t opcode  :8;
	uint64_t id      :8;
	uint64_t req_ack :1;
	uint64_t sizew   :3; /* size in words excluding hdr */
	uint64_t rsvd    :44;
} _packed;

union otxmn_mbox_msg {
	uint64_t words[OTXMN_MBOX_SIZE_WORDS];
	struct {
		struct otxmn_mbox_hdr hdr;
		uint64_t data[7];
	} s;
} __packed;

#endif /* _BAR_SPACE_MGMT_NET_H_ */
