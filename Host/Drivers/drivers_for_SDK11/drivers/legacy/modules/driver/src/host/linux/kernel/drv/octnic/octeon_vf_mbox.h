/* Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __OCTEON_VF_MBOX_H__
#define __OCTEON_VF_MBOX_H__

#include "octeon_mbox.h"

#define ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define ETHER_HDR_LEN (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define ETH_OVERHEAD (ETHER_HDR_LEN + ETHER_CRC_LEN + 8)
#define ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */
#define FRAME_SIZE_MAX       9000
int octnet_vf_mbox_send_cmd(octeon_device_t *oct_dev, union otx_vf_mbox_word cmd,
			    union otx_vf_mbox_word *rsp);
int octnet_vf_mbox_send_cmd_nolock(octeon_device_t *oct_dev, union otx_vf_mbox_word cmd,
				   union otx_vf_mbox_word *rsp);
int octnet_vf_mbox_send_mtu_set(octeon_device_t *oct_dev, int32_t mtu);
int octnet_vf_mbox_send_vf_pf_config_data(octeon_device_t *oct_dev, otx_vf_mbox_opcode_t opcode,
					  uint8_t *data, int32_t size);
int octnet_vf_mbox_get_pf_vf_data(octeon_device_t *oct_dev, otx_vf_mbox_opcode_t opcode,
				  uint8_t *data, int32_t *size);
int octnet_vf_mbox_set_mac_addr(octeon_device_t *oct_dev, char *mac_addr);
int octnet_vf_mbox_get_mac_addr(octeon_device_t *oct_dev, char *mac_addr);
#endif
