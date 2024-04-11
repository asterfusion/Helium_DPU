/* Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __OCTEON_MBOX_H__
#define __OCTEON_MBOX_H__

#include "octeon_main.h"

#define OTX_PF_MBOX_VERSION 1
#define OTX_VF_FLAG_PF_SET_MAC  (1 << 0) /* PF has set MAC address */
#define OTX_SDP_16K_HW_FRS  16380UL
#define OTX_SDP_64K_HW_FRS  65531UL

#define OTX_VF_LINK_SPEED_1000   1000
#define OTX_VF_LINK_SPEED_10000  10000
#define OTX_VF_LINK_SPEED_25000  25000
#define OTX_VF_LINK_SPEED_40000  40000
#define OTX_VF_LINK_SPEED_50000  50000
#define OTX_VF_LINK_SPEED_100000 100000

typedef enum {
	OTX_VF_MBOX_CMD_VERSION,
	OTX_VF_MBOX_CMD_SET_MTU,
	OTX_VF_MBOX_CMD_SET_MAC_ADDR,
	OTX_VF_MBOX_CMD_GET_MAC_ADDR,
	OTX_VF_MBOX_CMD_GET_LINK_INFO,
	OTX_VF_MBOX_CMD_GET_STATS,
	OTX_VF_MBOX_CMD_SET_RX_STATE,
	OTX_VF_MBOX_CMD_SET_LINK_STATUS,
	OTX_VF_MBOX_CMD_GET_LINK_STATUS,
	OTX_VF_MBOX_CMD_GET_MTU,
	OTX_VF_MBOX_CMD_LAST,
} otx_vf_mbox_opcode_t;

typedef enum {
	OTX_VF_MBOX_TYPE_CMD,
	OTX_VF_MBOX_TYPE_RSP_ACK,
	OTX_VF_MBOX_TYPE_RSP_NACK,
} otx_vf_mbox_word_type_t;

typedef enum {
	OTX_VF_LINK_STATUS_DOWN,
	OTX_VF_LINK_STATUS_UP,
} otx_vf_link_status_t;

typedef enum {
	OTX_VF_LINK_HALF_DUPLEX,
	OTX_VF_LINK_FULL_DUPLEX,
} otx_vf_link_duplex_t;

typedef enum {
	OTX_VF_LINK_FIXED,
	OTX_VF_LINK_AUTONEG,
} otx_vf_link_autoneg_t;

/* Hardware interface link state information. */
struct octeon_iface_link_info {
	/* Bitmap of Supported link speeds/modes. */
	uint64_t supported_modes;

	/* Bitmap of Advertised link speeds/modes. */
	uint64_t advertised_modes;

	/* Negotiated link speed in Mbps. */
	uint32_t speed;

	/* MTU */
	uint16_t mtu;

	/* Autonegotiation state. */
#define OTX_VF_LINK_MODE_AUTONEG_SUPPORTED   BIT(0)
#define OTX_VF_LINK_MODE_AUTONEG_ADVERTISED  BIT(1)
	uint8_t autoneg;

	/* Pause frames setting. */
#define OTX_VF_LINK_MODE_PAUSE_SUPPORTED   BIT(0)
#define OTX_VF_LINK_MODE_PAUSE_ADVERTISED  BIT(1)
	uint8_t pause;

	/* Admin state of the link (ifconfig <iface> up/down */
	uint8_t  admin_up;

	/* Operational state of the link: physical link is up down */
	uint8_t  oper_up;
};

#define OTX_VF_MBOX_TIMEOUT_MS 1000
#define OTX_VF_MBOX_VERSION     0
#define MBOX_MAX_DATA_SIZE      6
#define MBOX_MORE_FRAG_FLAG     1
#define MBOX_MAX_DATA_BUF_SIZE 256

#define OTX_VF_MBOX_WRITE_WAIT_TIME        msecs_to_jiffies(1)

enum otx_mbox_cmd_status {
	OTX_VF_MBOX_STATUS_SUCCESS = 0,
	OTX_VF_MBOX_STATUS_FAILED = 1,
	OTX_VF_MBOX_STATUS_BUSY = 2,
};

enum otx_vf_mbox_state {
	OTX_VF_MBOX_STATE_IDLE = 0,
	OTX_VF_MBOX_STATE_BUSY = 1,
};

union otx_vf_mbox_word {
	u64 u64;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 rsvd:6;
		u64 data:48;
	} s;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 frag:1;
		u64 rsvd:5;
		u8 data[6];
	} s_data;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 rsvd:6;
		u64 version:48;
	} s_version;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 rsvd:6;
		u8 mac_addr[6];
	} s_set_mac;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 rsvd:6;
		u64 mtu:48;
	} s_set_mtu;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 rsvd:6;
		u64 mtu:48;
	} s_get_mtu;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 state:1;
		u64 rsvd:53;
	} s_link_state;
	struct {
		u64 opcode:8;
		u64 type:2;
		u64 status:1;
		u64 rsvd:53;
	} s_link_status;
} __packed;

void handle_mbox_work(struct work_struct *work);
#endif
