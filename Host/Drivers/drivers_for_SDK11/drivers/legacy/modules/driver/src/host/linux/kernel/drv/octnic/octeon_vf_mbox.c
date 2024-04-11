/* Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "octeon_network.h"
#include "octeon_macros.h"
#include "octeon_nic.h"
#include "octeon_vf_mbox.h"

int
octnet_vf_mbox_send_cmd(octeon_device_t *oct_dev, union otx_vf_mbox_word cmd,
		     union otx_vf_mbox_word *rsp)
{
	return oct_dev->fn_list.send_mbox_cmd(oct_dev, cmd, rsp);
}

int
octnet_vf_mbox_send_cmd_nolock(octeon_device_t *oct_dev,
			    union otx_vf_mbox_word cmd,
			    union otx_vf_mbox_word *rsp)
{
	return oct_dev->fn_list.send_mbox_cmd_nolock(oct_dev, cmd, rsp);
}

int
octnet_vf_mbox_send_mtu_set(octeon_device_t *oct_dev, int32_t mtu)
{
	uint32_t frame_size = mtu + ETH_OVERHEAD;
	union otx_vf_mbox_word cmd;
	union otx_vf_mbox_word rsp;
	int ret = 0;

	if (mtu < ETHER_MIN_MTU || frame_size > FRAME_SIZE_MAX)
		return -EINVAL;

	cmd.u64 = 0;
	cmd.s_set_mtu.opcode = OTX_VF_MBOX_CMD_SET_MTU;
	cmd.s_set_mtu.mtu = mtu;

	ret = octnet_vf_mbox_send_cmd(oct_dev, cmd, &rsp);
	if (ret)
		return ret;
	if (rsp.s_set_mtu.type != OTX_VF_MBOX_TYPE_RSP_ACK)
		return -EINVAL;

	cavium_print_msg("mtu set  success mtu %u\n", mtu);

	return 0;
}

int
octnet_vf_mbox_send_vf_pf_config_data(octeon_device_t *oct_dev,
				otx_vf_mbox_opcode_t opcode,
				uint8_t *data, int32_t size)
{
	unsigned long flags;
	union otx_vf_mbox_word cmd;
	union otx_vf_mbox_word rsp;
	int32_t read_cnt, num_bytes_written = 0, ret;
	octeon_mbox_t *mbox = oct_dev->mbox[0];

	cmd.u64 = 0;
	cmd.s_data.opcode = opcode;
	cmd.s_data.frag = 0;

	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	if (mbox->state == OTX_VF_MBOX_STATE_BUSY) {
		spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		cavium_error("%s VF Mbox is in Busy state\n", __func__);
		return OTX_VF_MBOX_STATUS_BUSY;
	}
	mbox->state = OTX_VF_MBOX_STATE_BUSY;
	cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);

	cmd.s_data.frag = MBOX_MORE_FRAG_FLAG;
	*((int32_t *)cmd.s_data.data) = size;
	ret = octnet_vf_mbox_send_cmd_nolock(oct_dev, cmd, &rsp);
	if (ret) {
		cavium_error("%s send mbox cmd fail for length\n", __func__);
		cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
		mbox->state = OTX_VF_MBOX_STATE_IDLE;
		cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		return ret;
	}
	if (rsp.s_data.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
		cavium_error("%s send mbox cmd ACK receive fail for length\n", __func__);
		cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
		mbox->state = OTX_VF_MBOX_STATE_IDLE;
		cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		return -EINVAL;
	}
	cmd.u64 = 0;
	cmd.s_data.opcode = opcode;
	cmd.s_data.frag = 0;

	for (read_cnt = 0; read_cnt < size; read_cnt++) {
		cmd.s_data.data[num_bytes_written] = data[read_cnt];
		num_bytes_written++;
		if (num_bytes_written == MBOX_MAX_DATA_SIZE ||
				(read_cnt == (size - 1))) {
			if (num_bytes_written == MBOX_MAX_DATA_SIZE &&
					(read_cnt != (size - 1))) {
				cmd.s_data.frag = MBOX_MORE_FRAG_FLAG;
				num_bytes_written = 0;
			}
			ret = octnet_vf_mbox_send_cmd_nolock(oct_dev, cmd, &rsp);
			if (ret) {
				cavium_error("%s send mbox cmd nolock fail\n", __func__);
				cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
				mbox->state = OTX_VF_MBOX_STATE_IDLE;
				cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
				return ret;
			}
			if (rsp.s_set_mac.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
				cavium_error("%s send mbox cmd nolock ACK fail\n", __func__);
				cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
				mbox->state = OTX_VF_MBOX_STATE_IDLE;
				cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
				return -EINVAL;
			}
			cmd.u64 = 0;
			cmd.s_data.opcode = opcode;
			cmd.s_data.frag = 0;
		}
	}
	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	mbox->state = OTX_VF_MBOX_STATE_IDLE;
	cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
	return 0;
}

int
octnet_vf_mbox_get_pf_vf_data(octeon_device_t *oct_dev,
			otx_vf_mbox_opcode_t opcode,
			uint8_t *data, int32_t *size)
{
	unsigned long flags;
	union otx_vf_mbox_word cmd;
	union otx_vf_mbox_word rsp;
	int32_t read_cnt, i = 0, ret;
	int32_t data_len = 0, tmp_len = 0;
	octeon_mbox_t *mbox = oct_dev->mbox[0];

	cmd.u64 = 0;
	cmd.s_data.opcode = opcode;
	cmd.s_data.frag = 0;

	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	if (mbox->state == OTX_VF_MBOX_STATE_BUSY) {
		spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		cavium_error("%s VF Mbox is in Busy state\n", __func__);
		return OTX_VF_MBOX_STATUS_BUSY;
	}
	mbox->state = OTX_VF_MBOX_STATE_BUSY;
	cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);

	/* Send cmd to read data from PF */
	ret = octnet_vf_mbox_send_cmd_nolock(oct_dev, cmd, &rsp);
	if (ret) {
		cavium_error("%s send mbox cmd fail for data request\n", __func__);
		cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
		mbox->state = OTX_VF_MBOX_STATE_IDLE;
		cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		return ret;
	}
	if (rsp.s_data.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
		cavium_error("%s send mbox cmd ACK receive fail for data request\n", __func__);
		cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
		mbox->state = OTX_VF_MBOX_STATE_IDLE;
		cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
		return -EINVAL;
	}
	/*  PF sends the data length of requested CMD
	 *  in  ACK
	 */
	data_len = *((int32_t *)rsp.s_data.data);
	tmp_len = data_len;
	cavium_print_msg("data length %d:\n", data_len);
	cmd.u64 = 0;
	rsp.u64 = 0;
	cmd.s_data.opcode = opcode;
	cmd.s_data.frag = 1;
	while (data_len) {
		ret = octnet_vf_mbox_send_cmd_nolock(oct_dev, cmd, &rsp);
		if (ret) {
			cavium_error("%s send mbox cmd fail for data request\n", __func__);
			cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
			mbox->state = OTX_VF_MBOX_STATE_IDLE;
			cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
			oct_dev->mbox_data_index = 0;
			memset(oct_dev->mbox_data_buf, 0, MBOX_MAX_DATA_BUF_SIZE);
			return ret;
		}
		if (rsp.s_set_mac.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
			cavium_error("%s send mbox ACK receive fail for data request\n", __func__);
			cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
			mbox->state = OTX_VF_MBOX_STATE_IDLE;
			cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
			oct_dev->mbox_data_index = 0;
			memset(oct_dev->mbox_data_buf, 0, MBOX_MAX_DATA_BUF_SIZE);
			return -EINVAL;
		}
		if (data_len > MBOX_MAX_DATA_SIZE) {
			data_len -= MBOX_MAX_DATA_SIZE;
			read_cnt = MBOX_MAX_DATA_SIZE;
		} else {
			read_cnt = data_len;
			data_len = 0;
		}
		for (i = 0; i < read_cnt; i++) {
			oct_dev->mbox_data_buf[oct_dev->mbox_data_index] =
				rsp.s_data.data[i];
			oct_dev->mbox_data_index++;
		}
		cmd.u64 = 0;
		rsp.u64 = 0;
		cmd.s_data.opcode = opcode;
		cmd.s_data.frag = 1;
	}
	memcpy(data, oct_dev->mbox_data_buf, tmp_len);
	*size = tmp_len;
	oct_dev->mbox_data_index = 0;
	memset(oct_dev->mbox_data_buf, 0, MBOX_MAX_DATA_BUF_SIZE);
	cavium_spin_lock_irqsave(&oct_dev->vf_mbox_lock, flags);
	mbox->state = OTX_VF_MBOX_STATE_IDLE;
	cavium_spin_unlock_irqrestore(&oct_dev->vf_mbox_lock, flags);
	return 0;
}

int
octnet_vf_mbox_set_mac_addr(octeon_device_t *oct_dev,
				char  *mac_addr)
{
	union otx_vf_mbox_word cmd;
	union otx_vf_mbox_word rsp;
	int i, ret;

	cmd.u64 = 0;
	cmd.s_set_mac.opcode = OTX_VF_MBOX_CMD_SET_MAC_ADDR;
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		cmd.s_set_mac.mac_addr[i] = mac_addr[i];
	ret = octnet_vf_mbox_send_cmd(oct_dev, cmd, &rsp);
	if (ret) {
		cavium_error("%s fail ret:%d\n", __func__, ret);
		return ret;
	}
	if (rsp.s_set_mac.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
		cavium_error("%s received NACK\n", __func__);
		return -EINVAL;
	}
	cavium_print_msg("%s MAC Addr %pM\n", __func__, mac_addr);
	return 0;
}

int
octnet_vf_mbox_get_mac_addr(octeon_device_t *oct_dev,
				char  *mac_addr)
{
	union otx_vf_mbox_word cmd;
	union otx_vf_mbox_word rsp;
	int i, ret;

	cmd.u64 = 0;
	cmd.s_set_mac.opcode = OTX_VF_MBOX_CMD_GET_MAC_ADDR;
	ret = octnet_vf_mbox_send_cmd(oct_dev, cmd, &rsp);
	if (ret) {
		cavium_error("%s fail ret:%d\n", __func__, ret);
		return ret;
	}
	if (rsp.s_set_mac.type != OTX_VF_MBOX_TYPE_RSP_ACK) {
		cavium_error("%s received NACK\n", __func__);
		return -EINVAL;
	}
	for (i = 0; i < ETHER_ADDR_LEN; i++)
		mac_addr[i] = rsp.s_set_mac.mac_addr[i];
	cavium_print_msg("%s MAC Addr %pM\n", __func__, mac_addr);
	return 0;
}
