/* Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_hw.h"
#include "octeon_mbox.h"
#include "octeon_config.h"
#include "octeon_macros.h"
#include "octeon_model.h"

static int
get_max_pkt_len(octeon_device_t *oct)
{
	octeon_model_info(&octeon_model, oct);
	if (octeon_errata_sdp_mtu_size_16k())
		return OTX_SDP_16K_HW_FRS;
	return OTX_SDP_64K_HW_FRS;
}

static void handle_vf_validate_version(octeon_device_t *oct,  int vf_id,
					union otx_vf_mbox_word cmd,
					union otx_vf_mbox_word *rsp)
{
	uint32_t vf_version = (uint32_t)cmd.s_version.version;

	if (vf_version <= OTX_PF_MBOX_VERSION)
		rsp->s_version.type = OTX_VF_MBOX_TYPE_RSP_ACK;
	else
		rsp->s_version.type = OTX_VF_MBOX_TYPE_RSP_NACK;
}

static void
handle_vf_set_mtu(octeon_device_t *oct, int vf_id, union otx_vf_mbox_word cmd,
		 union otx_vf_mbox_word *rsp)
{
	rsp->s_set_mtu.type = OTX_VF_MBOX_TYPE_RSP_ACK;
	cavium_print_msg("mbox handle set mtu cmd vf %d mtu is %d\n",
			 vf_id, (int)cmd.s_set_mtu.mtu);
}

static void
handle_vf_get_mtu(octeon_device_t *oct, int vf_id, union otx_vf_mbox_word cmd,
		 union otx_vf_mbox_word *rsp)
{
	rsp->s_get_mtu.type = OTX_VF_MBOX_TYPE_RSP_ACK;
	rsp->s_get_mtu.mtu = get_max_pkt_len(oct);
	cavium_print_msg("mbox handle get mtu cmd vf %d mtu is %d\n",
			 vf_id, get_max_pkt_len(oct));
}

static void
handle_vf_set_mac_addr(octeon_device_t *oct,  int vf_id, union otx_vf_mbox_word cmd,
		      union otx_vf_mbox_word *rsp)
{
	int i;

	if (oct->vf_info[vf_id].flags & OTX_VF_FLAG_PF_SET_MAC) {
		cavium_print_msg("%s VF%d attempted to override administratively set MAC address\n",
				  __func__, vf_id);
		rsp->s_set_mac.type = OTX_VF_MBOX_TYPE_RSP_NACK;
		return;
	}

	for (i = 0; i < MBOX_MAX_DATA_SIZE; i++)
		oct->vf_info[vf_id].mac_addr[i] = cmd.s_set_mac.mac_addr[i];

	rsp->s_set_mac.type = OTX_VF_MBOX_TYPE_RSP_ACK;
	cavium_print_msg("%s vf:%d Mac %pM\n",  __func__, vf_id, oct->vf_info[vf_id].mac_addr);
}

static void
handle_vf_get_mac_addr(octeon_device_t *oct,  int vf_id, union otx_vf_mbox_word cmd,
		      union otx_vf_mbox_word *rsp)
{
	int i;

	rsp->s_set_mac.type = OTX_VF_MBOX_TYPE_RSP_ACK;
	for (i = 0; i < MBOX_MAX_DATA_SIZE; i++)
		rsp->s_set_mac.mac_addr[i] = oct->vf_info[vf_id].mac_addr[i];
	cavium_print_msg("%s vf:%d Mac: %pM\n",  __func__, vf_id, oct->vf_info[vf_id].mac_addr);
}

static void handle_vf_pf_get_data(octeon_device_t *oct,
				   octeon_mbox_t *mbox, int vf_id,
				   union otx_vf_mbox_word cmd,
				   union otx_vf_mbox_word *rsp)
{
	int length = 0;
	int i = 0;
	struct octeon_iface_link_info link_info;

	rsp->s_data.type = OTX_VF_MBOX_TYPE_RSP_ACK;

	if (cmd.s_data.frag != MBOX_MORE_FRAG_FLAG) {
		mbox->config_data_index = 0;
		memset(mbox->config_data, 0, MBOX_MAX_DATA_BUF_SIZE);
		/* Based on the OPCODE CMD the PF driver
		 * specific API should be called to fetch
		 * the requested data
		 */
		switch (cmd.s.opcode) {
		case OTX_VF_MBOX_CMD_GET_LINK_INFO:
			memset(&link_info, 0, sizeof(link_info));
			link_info.supported_modes = 0;
			link_info.advertised_modes = 0;
			link_info.autoneg = OTX_VF_LINK_AUTONEG;
			link_info.pause = 0;
			link_info.speed = OTX_VF_LINK_SPEED_10000;
			link_info.admin_up = OTX_VF_LINK_STATUS_UP;
			link_info.oper_up = OTX_VF_LINK_STATUS_UP;
			link_info.mtu = get_max_pkt_len(oct);
			mbox->message_len = sizeof(link_info);
			*((int32_t *)rsp->s_data.data) = mbox->message_len;
			memcpy(mbox->config_data, (uint8_t *)&link_info, sizeof(link_info));
			break;
		default:
			cavium_print_msg("handle_vf_pf_get_data invalid opcode:%d\n",cmd.s.opcode);
			rsp->s_data.type = OTX_VF_MBOX_TYPE_RSP_NACK;
			return;
		}
		*((int32_t *)rsp->s_data.data) = mbox->message_len;
		return;
	}
	if (mbox->message_len > MBOX_MAX_DATA_SIZE)
		length = MBOX_MAX_DATA_SIZE;
	else
		length = mbox->message_len;

	mbox->message_len -= length;

	for (i = 0; i < length; i++) {
		rsp->s_data.data[i] =
			mbox->config_data[mbox->config_data_index];
		mbox->config_data_index++;
	}
}

void handle_mbox_work(struct work_struct *work)
{
	struct cavium_wk *wk = container_of(work, struct cavium_wk, work);
	octeon_mbox_t *mbox = NULL;
	octeon_device_t *oct = NULL;
	union otx_vf_mbox_word cmd = { 0 };
	union otx_vf_mbox_word rsp = { 0 };
	int vf_id;

	mbox = (octeon_mbox_t *)wk->ctxptr;
	oct = (octeon_device_t *)mbox->oct;
	vf_id = mbox->vf_id;

	cavium_mutex_lock(&mbox->lock);
	cmd.u64 = OCTEON_READ64(mbox->vf_pf_data_reg);
	rsp.u64 = 0;

	cavium_print_msg("handle_mbox_work is called vf_id %d\n",vf_id);
	switch(cmd.s.opcode) {
	case OTX_VF_MBOX_CMD_VERSION:
		handle_vf_validate_version(oct, vf_id, cmd, &rsp);
		break;
	case OTX_VF_MBOX_CMD_GET_LINK_INFO:
		handle_vf_pf_get_data(oct, mbox, vf_id, cmd, &rsp);
		break;
	case OTX_VF_MBOX_CMD_SET_MTU:
		handle_vf_set_mtu(oct, vf_id, cmd, &rsp);
		break;
	case OTX_VF_MBOX_CMD_SET_MAC_ADDR:
		handle_vf_set_mac_addr(oct, vf_id, cmd, &rsp);
		break;
	case OTX_VF_MBOX_CMD_GET_MAC_ADDR:
		handle_vf_get_mac_addr(oct, vf_id, cmd, &rsp);
		break;
	case OTX_VF_MBOX_CMD_GET_MTU:
		handle_vf_get_mtu(oct, vf_id, cmd, &rsp);
		break;
	default:
		cavium_print_msg("handle_mbox_work is called OTX_VF_MBOX_TYPE_RSP_NACK\n");
		rsp.s.type = OTX_VF_MBOX_TYPE_RSP_NACK;
		break;
	}
	OCTEON_WRITE64(mbox->vf_pf_data_reg, rsp.u64);
	cavium_mutex_unlock(&mbox->lock);
}
