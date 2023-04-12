/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <rte_atomic.h>
#include <rte_bus_pci.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_interrupts.h>
#include <rte_io.h>
#include <rte_log.h>
#include <rte_pci.h>

#include "hns3_ethdev.h"
#include "hns3_logs.h"
#include "hns3_rxtx.h"
#include "hns3_intr.h"
#include "hns3_regs.h"
#include "hns3_dcb.h"
#include "hns3_mp.h"

#define HNS3_DEFAULT_PORT_CONF_BURST_SIZE	32
#define HNS3_DEFAULT_PORT_CONF_QUEUES_NUM	1

#define HNS3_SERVICE_INTERVAL		1000000 /* us */
#define HNS3_PORT_BASE_VLAN_DISABLE	0
#define HNS3_PORT_BASE_VLAN_ENABLE	1
#define HNS3_INVLID_PVID		0xFFFF

#define HNS3_FILTER_TYPE_VF		0
#define HNS3_FILTER_TYPE_PORT		1
#define HNS3_FILTER_FE_EGRESS_V1_B	BIT(0)
#define HNS3_FILTER_FE_NIC_INGRESS_B	BIT(0)
#define HNS3_FILTER_FE_NIC_EGRESS_B	BIT(1)
#define HNS3_FILTER_FE_ROCE_INGRESS_B	BIT(2)
#define HNS3_FILTER_FE_ROCE_EGRESS_B	BIT(3)
#define HNS3_FILTER_FE_EGRESS		(HNS3_FILTER_FE_NIC_EGRESS_B \
					| HNS3_FILTER_FE_ROCE_EGRESS_B)
#define HNS3_FILTER_FE_INGRESS		(HNS3_FILTER_FE_NIC_INGRESS_B \
					| HNS3_FILTER_FE_ROCE_INGRESS_B)

/* Reset related Registers */
#define HNS3_GLOBAL_RESET_BIT		0
#define HNS3_CORE_RESET_BIT		1
#define HNS3_IMP_RESET_BIT		2
#define HNS3_FUN_RST_ING_B		0

#define HNS3_VECTOR0_IMP_RESET_INT_B	1

#define HNS3_RESET_WAIT_MS	100
#define HNS3_RESET_WAIT_CNT	200

int hns3_logtype_init;
int hns3_logtype_driver;

enum hns3_evt_cause {
	HNS3_VECTOR0_EVENT_RST,
	HNS3_VECTOR0_EVENT_MBX,
	HNS3_VECTOR0_EVENT_ERR,
	HNS3_VECTOR0_EVENT_OTHER,
};

static enum hns3_reset_level hns3_get_reset_level(struct hns3_adapter *hns,
						 uint64_t *levels);
static int hns3_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int hns3_vlan_pvid_configure(struct hns3_adapter *hns, uint16_t pvid,
				    int on);

static void
hns3_pf_disable_irq0(struct hns3_hw *hw)
{
	hns3_write_dev(hw, HNS3_MISC_VECTOR_REG_BASE, 0);
}

static void
hns3_pf_enable_irq0(struct hns3_hw *hw)
{
	hns3_write_dev(hw, HNS3_MISC_VECTOR_REG_BASE, 1);
}

static enum hns3_evt_cause
hns3_check_event_cause(struct hns3_adapter *hns, uint32_t *clearval)
{
	struct hns3_hw *hw = &hns->hw;
	uint32_t vector0_int_stats;
	uint32_t cmdq_src_val;
	uint32_t val;
	enum hns3_evt_cause ret;

	/* fetch the events from their corresponding regs */
	vector0_int_stats = hns3_read_dev(hw, HNS3_VECTOR0_OTHER_INT_STS_REG);
	cmdq_src_val = hns3_read_dev(hw, HNS3_VECTOR0_CMDQ_SRC_REG);

	/*
	 * Assumption: If by any chance reset and mailbox events are reported
	 * together then we will only process reset event and defer the
	 * processing of the mailbox events. Since, we would have not cleared
	 * RX CMDQ event this time we would receive again another interrupt
	 * from H/W just for the mailbox.
	 */
	if (BIT(HNS3_VECTOR0_IMPRESET_INT_B) & vector0_int_stats) { /* IMP */
		rte_atomic16_set(&hw->reset.disable_cmd, 1);
		hns3_atomic_set_bit(HNS3_IMP_RESET, &hw->reset.pending);
		val = BIT(HNS3_VECTOR0_IMPRESET_INT_B);
		if (clearval) {
			hw->reset.stats.imp_cnt++;
			hns3_warn(hw, "IMP reset detected, clear reset status");
		} else {
			hns3_schedule_delayed_reset(hns);
			hns3_warn(hw, "IMP reset detected, don't clear reset status");
		}

		ret = HNS3_VECTOR0_EVENT_RST;
		goto out;
	}

	/* Global reset */
	if (BIT(HNS3_VECTOR0_GLOBALRESET_INT_B) & vector0_int_stats) {
		rte_atomic16_set(&hw->reset.disable_cmd, 1);
		hns3_atomic_set_bit(HNS3_GLOBAL_RESET, &hw->reset.pending);
		val = BIT(HNS3_VECTOR0_GLOBALRESET_INT_B);
		if (clearval) {
			hw->reset.stats.global_cnt++;
			hns3_warn(hw, "Global reset detected, clear reset status");
		} else {
			hns3_schedule_delayed_reset(hns);
			hns3_warn(hw, "Global reset detected, don't clear reset status");
		}

		ret = HNS3_VECTOR0_EVENT_RST;
		goto out;
	}

	/* check for vector0 msix event source */
	if (vector0_int_stats & HNS3_VECTOR0_REG_MSIX_MASK) {
		val = vector0_int_stats;
		ret = HNS3_VECTOR0_EVENT_ERR;
		goto out;
	}

	/* check for vector0 mailbox(=CMDQ RX) event source */
	if (BIT(HNS3_VECTOR0_RX_CMDQ_INT_B) & cmdq_src_val) {
		cmdq_src_val &= ~BIT(HNS3_VECTOR0_RX_CMDQ_INT_B);
		val = cmdq_src_val;
		ret = HNS3_VECTOR0_EVENT_MBX;
		goto out;
	}

	if (clearval && (vector0_int_stats || cmdq_src_val))
		hns3_warn(hw, "surprise irq ector0_int_stats:0x%x cmdq_src_val:0x%x",
			  vector0_int_stats, cmdq_src_val);
	val = vector0_int_stats;
	ret = HNS3_VECTOR0_EVENT_OTHER;
out:

	if (clearval)
		*clearval = val;
	return ret;
}

static void
hns3_clear_event_cause(struct hns3_hw *hw, uint32_t event_type, uint32_t regclr)
{
	if (event_type == HNS3_VECTOR0_EVENT_RST)
		hns3_write_dev(hw, HNS3_MISC_RESET_STS_REG, regclr);
	else if (event_type == HNS3_VECTOR0_EVENT_MBX)
		hns3_write_dev(hw, HNS3_VECTOR0_CMDQ_SRC_REG, regclr);
}

static void
hns3_clear_all_event_cause(struct hns3_hw *hw)
{
	uint32_t vector0_int_stats;
	vector0_int_stats = hns3_read_dev(hw, HNS3_VECTOR0_OTHER_INT_STS_REG);

	if (BIT(HNS3_VECTOR0_IMPRESET_INT_B) & vector0_int_stats)
		hns3_warn(hw, "Probe during IMP reset interrupt");

	if (BIT(HNS3_VECTOR0_GLOBALRESET_INT_B) & vector0_int_stats)
		hns3_warn(hw, "Probe during Global reset interrupt");

	hns3_clear_event_cause(hw, HNS3_VECTOR0_EVENT_RST,
			       BIT(HNS3_VECTOR0_IMPRESET_INT_B) |
			       BIT(HNS3_VECTOR0_GLOBALRESET_INT_B) |
			       BIT(HNS3_VECTOR0_CORERESET_INT_B));
	hns3_clear_event_cause(hw, HNS3_VECTOR0_EVENT_MBX, 0);
}

static void
hns3_interrupt_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	enum hns3_evt_cause event_cause;
	uint32_t clearval = 0;

	/* Disable interrupt */
	hns3_pf_disable_irq0(hw);

	event_cause = hns3_check_event_cause(hns, &clearval);

	/* vector 0 interrupt is shared with reset and mailbox source events. */
	if (event_cause == HNS3_VECTOR0_EVENT_ERR) {
		hns3_handle_msix_error(hns, &hw->reset.request);
		hns3_schedule_reset(hns);
	} else if (event_cause == HNS3_VECTOR0_EVENT_RST)
		hns3_schedule_reset(hns);
	else
		hns3_err(hw, "Received unknown event");

	hns3_clear_event_cause(hw, event_cause, clearval);
	/* Enable interrupt if it is not cause by reset */
	hns3_pf_enable_irq0(hw);
}

static int
hns3_set_port_vlan_filter(struct hns3_adapter *hns, uint16_t vlan_id, int on)
{
#define HNS3_VLAN_OFFSET_160		160
	struct hns3_vlan_filter_pf_cfg_cmd *req;
	struct hns3_hw *hw = &hns->hw;
	uint8_t vlan_offset_byte_val;
	struct hns3_cmd_desc desc;
	uint8_t vlan_offset_byte;
	uint8_t vlan_offset_160;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_VLAN_FILTER_PF_CFG, false);

	vlan_offset_160 = vlan_id / HNS3_VLAN_OFFSET_160;
	vlan_offset_byte = (vlan_id % HNS3_VLAN_OFFSET_160) / 8;
	vlan_offset_byte_val = 1 << (vlan_id % 8);

	req = (struct hns3_vlan_filter_pf_cfg_cmd *)desc.data;
	req->vlan_offset = vlan_offset_160;
	req->vlan_cfg = on ? 0 : 1;
	req->vlan_offset_bitmap[vlan_offset_byte] = vlan_offset_byte_val;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "set port vlan id failed, vlan_id =%u, ret =%d",
			 vlan_id, ret);

	return ret;
}

static void
hns3_rm_dev_vlan_table(struct hns3_adapter *hns, uint16_t vlan_id)
{
	struct hns3_user_vlan_table *vlan_entry;
	struct hns3_pf *pf = &hns->pf;

	LIST_FOREACH(vlan_entry, &pf->vlan_list, next) {
		if (vlan_entry->vlan_id == vlan_id) {
			if (vlan_entry->hd_tbl_status)
				hns3_set_port_vlan_filter(hns, vlan_id, 0);
			LIST_REMOVE(vlan_entry, next);
			rte_free(vlan_entry);
			break;
		}
	}
}

static void
hns3_add_dev_vlan_table(struct hns3_adapter *hns, uint16_t vlan_id,
			bool writen_to_tbl)
{
	struct hns3_user_vlan_table *vlan_entry;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_pf *pf = &hns->pf;

	LIST_FOREACH(vlan_entry, &pf->vlan_list, next) {
		if (vlan_entry->vlan_id == vlan_id)
			return;
	}

	vlan_entry = rte_zmalloc("hns3_vlan_tbl", sizeof(*vlan_entry), 0);
	if (vlan_entry == NULL) {
		hns3_err(hw, "Failed to malloc hns3 vlan table");
		return;
	}

	vlan_entry->hd_tbl_status = writen_to_tbl;
	vlan_entry->vlan_id = vlan_id;

	LIST_INSERT_HEAD(&pf->vlan_list, vlan_entry, next);
}

static int
hns3_restore_vlan_table(struct hns3_adapter *hns)
{
	struct hns3_user_vlan_table *vlan_entry;
	struct hns3_pf *pf = &hns->pf;
	uint16_t vlan_id;
	int ret = 0;

	if (pf->port_base_vlan_cfg.state == HNS3_PORT_BASE_VLAN_ENABLE) {
		ret = hns3_vlan_pvid_configure(hns, pf->port_base_vlan_cfg.pvid,
					       1);
		return ret;
	}

	LIST_FOREACH(vlan_entry, &pf->vlan_list, next) {
		if (vlan_entry->hd_tbl_status) {
			vlan_id = vlan_entry->vlan_id;
			ret = hns3_set_port_vlan_filter(hns, vlan_id, 1);
			if (ret)
				break;
		}
	}

	return ret;
}

static int
hns3_vlan_filter_configure(struct hns3_adapter *hns, uint16_t vlan_id, int on)
{
	struct hns3_pf *pf = &hns->pf;
	bool writen_to_tbl = false;
	int ret = 0;

	/*
	 * When vlan filter is enabled, hardware regards vlan id 0 as the entry
	 * for normal packet, deleting vlan id 0 is not allowed.
	 */
	if (on == 0 && vlan_id == 0)
		return 0;

	/*
	 * When port base vlan enabled, we use port base vlan as the vlan
	 * filter condition. In this case, we don't update vlan filter table
	 * when user add new vlan or remove exist vlan, just update the
	 * vlan list. The vlan id in vlan list will be writen in vlan filter
	 * table until port base vlan disabled
	 */
	if (pf->port_base_vlan_cfg.state == HNS3_PORT_BASE_VLAN_DISABLE) {
		ret = hns3_set_port_vlan_filter(hns, vlan_id, on);
		writen_to_tbl = true;
	}

	if (ret == 0 && vlan_id) {
		if (on)
			hns3_add_dev_vlan_table(hns, vlan_id, writen_to_tbl);
		else
			hns3_rm_dev_vlan_table(hns, vlan_id);
	}
	return ret;
}

static int
hns3_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_vlan_filter_configure(hns, vlan_id, on);
	rte_spinlock_unlock(&hw->lock);
	return ret;
}

static int
hns3_vlan_tpid_configure(struct hns3_adapter *hns, enum rte_vlan_type vlan_type,
			 uint16_t tpid)
{
	struct hns3_rx_vlan_type_cfg_cmd *rx_req;
	struct hns3_tx_vlan_type_cfg_cmd *tx_req;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_cmd_desc desc;
	int ret;

	if ((vlan_type != ETH_VLAN_TYPE_INNER &&
	     vlan_type != ETH_VLAN_TYPE_OUTER)) {
		hns3_err(hw, "Unsupported vlan type, vlan_type =%d", vlan_type);
		return -EINVAL;
	}

	if (tpid != RTE_ETHER_TYPE_VLAN) {
		hns3_err(hw, "Unsupported vlan tpid, vlan_type =%d", vlan_type);
		return -EINVAL;
	}

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_VLAN_TYPE_ID, false);
	rx_req = (struct hns3_rx_vlan_type_cfg_cmd *)desc.data;

	if (vlan_type == ETH_VLAN_TYPE_OUTER) {
		rx_req->ot_fst_vlan_type = rte_cpu_to_le_16(tpid);
		rx_req->ot_sec_vlan_type = rte_cpu_to_le_16(tpid);
	} else if (vlan_type == ETH_VLAN_TYPE_INNER) {
		rx_req->ot_fst_vlan_type = rte_cpu_to_le_16(tpid);
		rx_req->ot_sec_vlan_type = rte_cpu_to_le_16(tpid);
		rx_req->in_fst_vlan_type = rte_cpu_to_le_16(tpid);
		rx_req->in_sec_vlan_type = rte_cpu_to_le_16(tpid);
	}

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "Send rxvlan protocol type command fail, ret =%d",
			 ret);
		return ret;
	}

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_VLAN_INSERT, false);

	tx_req = (struct hns3_tx_vlan_type_cfg_cmd *)desc.data;
	tx_req->ot_vlan_type = rte_cpu_to_le_16(tpid);
	tx_req->in_vlan_type = rte_cpu_to_le_16(tpid);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Send txvlan protocol type command fail, ret =%d",
			 ret);
	return ret;
}

static int
hns3_vlan_tpid_set(struct rte_eth_dev *dev, enum rte_vlan_type vlan_type,
		   uint16_t tpid)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_vlan_tpid_configure(hns, vlan_type, tpid);
	rte_spinlock_unlock(&hw->lock);
	return ret;
}

static int
hns3_set_vlan_rx_offload_cfg(struct hns3_adapter *hns,
			     struct hns3_rx_vtag_cfg *vcfg)
{
	struct hns3_vport_vtag_rx_cfg_cmd *req;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_cmd_desc desc;
	uint16_t vport_id;
	uint8_t bitmap;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_VLAN_PORT_RX_CFG, false);

	req = (struct hns3_vport_vtag_rx_cfg_cmd *)desc.data;
	hns3_set_bit(req->vport_vlan_cfg, HNS3_REM_TAG1_EN_B,
		     vcfg->strip_tag1_en ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_REM_TAG2_EN_B,
		     vcfg->strip_tag2_en ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_SHOW_TAG1_EN_B,
		     vcfg->vlan1_vlan_prionly ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_SHOW_TAG2_EN_B,
		     vcfg->vlan2_vlan_prionly ? 1 : 0);

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, the PF-related vf_id is 0, just need to configure parameters
	 * for vport_id 0.
	 */
	vport_id = 0;
	req->vf_offset = vport_id / HNS3_VF_NUM_PER_CMD;
	bitmap = 1 << (vport_id % HNS3_VF_NUM_PER_BYTE);
	req->vf_bitmap[req->vf_offset] = bitmap;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Send port rxvlan cfg command fail, ret =%d", ret);
	return ret;
}

static void
hns3_update_rx_offload_cfg(struct hns3_adapter *hns,
			   struct hns3_rx_vtag_cfg *vcfg)
{
	struct hns3_pf *pf = &hns->pf;
	memcpy(&pf->vtag_config.rx_vcfg, vcfg, sizeof(pf->vtag_config.rx_vcfg));
}

static void
hns3_update_tx_offload_cfg(struct hns3_adapter *hns,
			   struct hns3_tx_vtag_cfg *vcfg)
{
	struct hns3_pf *pf = &hns->pf;
	memcpy(&pf->vtag_config.tx_vcfg, vcfg, sizeof(pf->vtag_config.tx_vcfg));
}

static int
hns3_en_hw_strip_rxvtag(struct hns3_adapter *hns, bool enable)
{
	struct hns3_rx_vtag_cfg rxvlan_cfg;
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	if (pf->port_base_vlan_cfg.state == HNS3_PORT_BASE_VLAN_DISABLE) {
		rxvlan_cfg.strip_tag1_en = false;
		rxvlan_cfg.strip_tag2_en = enable;
	} else {
		rxvlan_cfg.strip_tag1_en = enable;
		rxvlan_cfg.strip_tag2_en = true;
	}

	rxvlan_cfg.vlan1_vlan_prionly = false;
	rxvlan_cfg.vlan2_vlan_prionly = false;
	rxvlan_cfg.rx_vlan_offload_en = enable;

	ret = hns3_set_vlan_rx_offload_cfg(hns, &rxvlan_cfg);
	if (ret) {
		hns3_err(hw, "enable strip rx vtag failed, ret =%d", ret);
		return ret;
	}

	hns3_update_rx_offload_cfg(hns, &rxvlan_cfg);

	return ret;
}

static int
hns3_set_vlan_filter_ctrl(struct hns3_hw *hw, uint8_t vlan_type,
			  uint8_t fe_type, bool filter_en, uint8_t vf_id)
{
	struct hns3_vlan_filter_ctrl_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_VLAN_FILTER_CTRL, false);

	req = (struct hns3_vlan_filter_ctrl_cmd *)desc.data;
	req->vlan_type = vlan_type;
	req->vlan_fe = filter_en ? fe_type : 0;
	req->vf_id = vf_id;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "set vlan filter fail, ret =%d", ret);

	return ret;
}

static int
hns3_enable_vlan_filter(struct hns3_adapter *hns, bool enable)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_set_vlan_filter_ctrl(hw, HNS3_FILTER_TYPE_VF,
					HNS3_FILTER_FE_EGRESS, false, 0);
	if (ret) {
		hns3_err(hw, "hns3 enable filter fail, ret =%d", ret);
		return ret;
	}

	ret = hns3_set_vlan_filter_ctrl(hw, HNS3_FILTER_TYPE_PORT,
					HNS3_FILTER_FE_INGRESS, enable, 0);
	if (ret)
		hns3_err(hw, "hns3 enable filter fail, ret =%d", ret);

	return ret;
}

static int
hns3_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_rxmode *rxmode;
	unsigned int tmp_mask;
	bool enable;
	int ret = 0;

	rte_spinlock_lock(&hw->lock);
	rxmode = &dev->data->dev_conf.rxmode;
	tmp_mask = (unsigned int)mask;
	if (tmp_mask & ETH_VLAN_STRIP_MASK) {
		/* Enable or disable VLAN stripping */
		enable = rxmode->offloads & DEV_RX_OFFLOAD_VLAN_STRIP ?
		    true : false;

		ret = hns3_en_hw_strip_rxvtag(hns, enable);
		if (ret) {
			rte_spinlock_unlock(&hw->lock);
			hns3_err(hw, "failed to enable rx strip, ret =%d", ret);
			return ret;
		}
	}

	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3_set_vlan_tx_offload_cfg(struct hns3_adapter *hns,
			     struct hns3_tx_vtag_cfg *vcfg)
{
	struct hns3_vport_vtag_tx_cfg_cmd *req;
	struct hns3_cmd_desc desc;
	struct hns3_hw *hw = &hns->hw;
	uint16_t vport_id;
	uint8_t bitmap;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_VLAN_PORT_TX_CFG, false);

	req = (struct hns3_vport_vtag_tx_cfg_cmd *)desc.data;
	req->def_vlan_tag1 = vcfg->default_tag1;
	req->def_vlan_tag2 = vcfg->default_tag2;
	hns3_set_bit(req->vport_vlan_cfg, HNS3_ACCEPT_TAG1_B,
		     vcfg->accept_tag1 ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_ACCEPT_UNTAG1_B,
		     vcfg->accept_untag1 ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_ACCEPT_TAG2_B,
		     vcfg->accept_tag2 ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_ACCEPT_UNTAG2_B,
		     vcfg->accept_untag2 ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_PORT_INS_TAG1_EN_B,
		     vcfg->insert_tag1_en ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_PORT_INS_TAG2_EN_B,
		     vcfg->insert_tag2_en ? 1 : 0);
	hns3_set_bit(req->vport_vlan_cfg, HNS3_CFG_NIC_ROCE_SEL_B, 0);

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, the PF-related vf_id is 0, just need to configure parameters
	 * for vport_id 0.
	 */
	vport_id = 0;
	req->vf_offset = vport_id / HNS3_VF_NUM_PER_CMD;
	bitmap = 1 << (vport_id % HNS3_VF_NUM_PER_BYTE);
	req->vf_bitmap[req->vf_offset] = bitmap;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Send port txvlan cfg command fail, ret =%d", ret);

	return ret;
}

static int
hns3_vlan_txvlan_cfg(struct hns3_adapter *hns, uint16_t port_base_vlan_state,
		     uint16_t pvid)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tx_vtag_cfg txvlan_cfg;
	int ret;

	if (port_base_vlan_state == HNS3_PORT_BASE_VLAN_DISABLE) {
		txvlan_cfg.accept_tag1 = true;
		txvlan_cfg.insert_tag1_en = false;
		txvlan_cfg.default_tag1 = 0;
	} else {
		txvlan_cfg.accept_tag1 = false;
		txvlan_cfg.insert_tag1_en = true;
		txvlan_cfg.default_tag1 = pvid;
	}

	txvlan_cfg.accept_untag1 = true;
	txvlan_cfg.accept_tag2 = true;
	txvlan_cfg.accept_untag2 = true;
	txvlan_cfg.insert_tag2_en = false;
	txvlan_cfg.default_tag2 = 0;

	ret = hns3_set_vlan_tx_offload_cfg(hns, &txvlan_cfg);
	if (ret) {
		hns3_err(hw, "pf vlan set pvid failed, pvid =%u ,ret =%d", pvid,
			 ret);
		return ret;
	}

	hns3_update_tx_offload_cfg(hns, &txvlan_cfg);
	return ret;
}

static void
hns3_store_port_base_vlan_info(struct hns3_adapter *hns, uint16_t pvid, int on)
{
	struct hns3_pf *pf = &hns->pf;

	pf->port_base_vlan_cfg.state = on ?
	    HNS3_PORT_BASE_VLAN_ENABLE : HNS3_PORT_BASE_VLAN_DISABLE;

	pf->port_base_vlan_cfg.pvid = pvid;
}

static void
hns3_rm_all_vlan_table(struct hns3_adapter *hns, bool is_del_list)
{
	struct hns3_user_vlan_table *vlan_entry;
	struct hns3_pf *pf = &hns->pf;

	LIST_FOREACH(vlan_entry, &pf->vlan_list, next) {
		if (vlan_entry->hd_tbl_status)
			hns3_set_port_vlan_filter(hns, vlan_entry->vlan_id, 0);

		vlan_entry->hd_tbl_status = false;
	}

	if (is_del_list) {
		vlan_entry = LIST_FIRST(&pf->vlan_list);
		while (vlan_entry) {
			LIST_REMOVE(vlan_entry, next);
			rte_free(vlan_entry);
			vlan_entry = LIST_FIRST(&pf->vlan_list);
		}
	}
}

static void
hns3_add_all_vlan_table(struct hns3_adapter *hns)
{
	struct hns3_user_vlan_table *vlan_entry;
	struct hns3_pf *pf = &hns->pf;

	LIST_FOREACH(vlan_entry, &pf->vlan_list, next) {
		if (!vlan_entry->hd_tbl_status)
			hns3_set_port_vlan_filter(hns, vlan_entry->vlan_id, 1);

		vlan_entry->hd_tbl_status = true;
	}
}

static void
hns3_remove_all_vlan_table(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_pf *pf = &hns->pf;
	int ret;

	hns3_rm_all_vlan_table(hns, true);
	if (pf->port_base_vlan_cfg.pvid != HNS3_INVLID_PVID) {
		ret = hns3_set_port_vlan_filter(hns,
						pf->port_base_vlan_cfg.pvid, 0);
		if (ret) {
			hns3_err(hw, "Failed to remove all vlan table, ret =%d",
				 ret);
			return;
		}
	}
}

static int
hns3_update_vlan_filter_entries(struct hns3_adapter *hns,
				uint16_t port_base_vlan_state,
				uint16_t new_pvid, uint16_t old_pvid)
{
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	int ret = 0;

	if (port_base_vlan_state == HNS3_PORT_BASE_VLAN_ENABLE) {
		if (old_pvid != HNS3_INVLID_PVID && old_pvid != 0) {
			ret = hns3_set_port_vlan_filter(hns, old_pvid, 0);
			if (ret) {
				hns3_err(hw,
					 "Failed to clear clear old pvid filter, ret =%d",
					 ret);
				return ret;
			}
		}

		hns3_rm_all_vlan_table(hns, false);
		return hns3_set_port_vlan_filter(hns, new_pvid, 1);
	}

	if (new_pvid != 0) {
		ret = hns3_set_port_vlan_filter(hns, new_pvid, 0);
		if (ret) {
			hns3_err(hw, "Failed to set port vlan filter, ret =%d",
				 ret);
			return ret;
		}
	}

	if (new_pvid == pf->port_base_vlan_cfg.pvid)
		hns3_add_all_vlan_table(hns);

	return ret;
}

static int
hns3_en_rx_strip_all(struct hns3_adapter *hns, int on)
{
	struct hns3_rx_vtag_cfg rx_vlan_cfg;
	struct hns3_hw *hw = &hns->hw;
	bool rx_strip_en;
	int ret;

	rx_strip_en = on ? true : false;
	rx_vlan_cfg.strip_tag1_en = rx_strip_en;
	rx_vlan_cfg.strip_tag2_en = rx_strip_en;
	rx_vlan_cfg.vlan1_vlan_prionly = false;
	rx_vlan_cfg.vlan2_vlan_prionly = false;
	rx_vlan_cfg.rx_vlan_offload_en = rx_strip_en;

	ret = hns3_set_vlan_rx_offload_cfg(hns, &rx_vlan_cfg);
	if (ret) {
		hns3_err(hw, "enable strip rx failed, ret =%d", ret);
		return ret;
	}

	hns3_update_rx_offload_cfg(hns, &rx_vlan_cfg);
	return ret;
}

static int
hns3_vlan_pvid_configure(struct hns3_adapter *hns, uint16_t pvid, int on)
{
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	uint16_t port_base_vlan_state;
	uint16_t old_pvid;
	int ret;

	if (on == 0 && pvid != pf->port_base_vlan_cfg.pvid) {
		if (pf->port_base_vlan_cfg.pvid != HNS3_INVLID_PVID)
			hns3_warn(hw, "Invalid operation! As current pvid set "
				  "is %u, disable pvid %u is invalid",
				  pf->port_base_vlan_cfg.pvid, pvid);
		return 0;
	}

	port_base_vlan_state = on ? HNS3_PORT_BASE_VLAN_ENABLE :
				    HNS3_PORT_BASE_VLAN_DISABLE;
	ret = hns3_vlan_txvlan_cfg(hns, port_base_vlan_state, pvid);
	if (ret) {
		hns3_err(hw, "Failed to config tx vlan, ret =%d", ret);
		return ret;
	}

	ret = hns3_en_rx_strip_all(hns, on);
	if (ret) {
		hns3_err(hw, "Failed to config rx vlan strip, ret =%d", ret);
		return ret;
	}

	if (pvid == HNS3_INVLID_PVID)
		goto out;
	old_pvid = pf->port_base_vlan_cfg.pvid;
	ret = hns3_update_vlan_filter_entries(hns, port_base_vlan_state, pvid,
					      old_pvid);
	if (ret) {
		hns3_err(hw, "Failed to update vlan filter entries, ret =%d",
			 ret);
		return ret;
	}

out:
	hns3_store_port_base_vlan_info(hns, pvid, on);
	return ret;
}

static int
hns3_vlan_pvid_set(struct rte_eth_dev *dev, uint16_t pvid, int on)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_vlan_pvid_configure(hns, pvid, on);
	rte_spinlock_unlock(&hw->lock);
	return ret;
}

static void
init_port_base_vlan_info(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;

	pf->port_base_vlan_cfg.state = HNS3_PORT_BASE_VLAN_DISABLE;
	pf->port_base_vlan_cfg.pvid = HNS3_INVLID_PVID;
}

static int
hns3_default_vlan_config(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_set_port_vlan_filter(hns, 0, 1);
	if (ret)
		hns3_err(hw, "default vlan 0 config failed, ret =%d", ret);
	return ret;
}

static int
hns3_init_vlan_config(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	/*
	 * This function can be called in the initialization and reset process,
	 * when in reset process, it means that hardware had been reseted
	 * successfully and we need to restore the hardware configuration to
	 * ensure that the hardware configuration remains unchanged before and
	 * after reset.
	 */
	if (rte_atomic16_read(&hw->reset.resetting) == 0)
		init_port_base_vlan_info(hw);

	ret = hns3_enable_vlan_filter(hns, true);
	if (ret) {
		hns3_err(hw, "vlan init fail in pf, ret =%d", ret);
		return ret;
	}

	ret = hns3_vlan_tpid_configure(hns, ETH_VLAN_TYPE_INNER,
				       RTE_ETHER_TYPE_VLAN);
	if (ret) {
		hns3_err(hw, "tpid set fail in pf, ret =%d", ret);
		return ret;
	}

	/*
	 * When in the reinit dev stage of the reset process, the following
	 * vlan-related configurations may differ from those at initialization,
	 * we will restore configurations to hardware in hns3_restore_vlan_table
	 * and hns3_restore_vlan_conf later.
	 */
	if (rte_atomic16_read(&hw->reset.resetting) == 0) {
		ret = hns3_vlan_pvid_configure(hns, HNS3_INVLID_PVID, 0);
		if (ret) {
			hns3_err(hw, "pvid set fail in pf, ret =%d", ret);
			return ret;
		}

		ret = hns3_en_hw_strip_rxvtag(hns, false);
		if (ret) {
			hns3_err(hw, "rx strip configure fail in pf, ret =%d",
				 ret);
			return ret;
		}
	}

	return hns3_default_vlan_config(hns);
}

static int
hns3_restore_vlan_conf(struct hns3_adapter *hns)
{
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_set_vlan_rx_offload_cfg(hns, &pf->vtag_config.rx_vcfg);
	if (ret) {
		hns3_err(hw, "hns3 restore vlan rx conf fail, ret =%d", ret);
		return ret;
	}

	ret = hns3_set_vlan_tx_offload_cfg(hns, &pf->vtag_config.tx_vcfg);
	if (ret)
		hns3_err(hw, "hns3 restore vlan tx conf fail, ret =%d", ret);

	return ret;
}

static int
hns3_dev_configure_vlan(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct rte_eth_dev_data *data = dev->data;
	struct rte_eth_txmode *txmode;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	txmode = &data->dev_conf.txmode;
	if (txmode->hw_vlan_reject_tagged || txmode->hw_vlan_reject_untagged)
		hns3_warn(hw,
			  "hw_vlan_reject_tagged or hw_vlan_reject_untagged "
			  "configuration is not supported! Ignore these two "
			  "parameters: hw_vlan_reject_tagged(%d), "
			  "hw_vlan_reject_untagged(%d)",
			  txmode->hw_vlan_reject_tagged,
			  txmode->hw_vlan_reject_untagged);

	/* Apply vlan offload setting */
	ret = hns3_vlan_offload_set(dev, ETH_VLAN_STRIP_MASK);
	if (ret) {
		hns3_err(hw, "dev config vlan Strip failed, ret =%d", ret);
		return ret;
	}

	/* Apply pvid setting */
	ret = hns3_vlan_pvid_set(dev, txmode->pvid,
				 txmode->hw_vlan_insert_pvid);
	if (ret)
		hns3_err(hw, "dev config vlan pvid(%d) failed, ret =%d",
			 txmode->pvid, ret);

	return ret;
}

static int
hns3_config_tso(struct hns3_hw *hw, unsigned int tso_mss_min,
		unsigned int tso_mss_max)
{
	struct hns3_cfg_tso_status_cmd *req;
	struct hns3_cmd_desc desc;
	uint16_t tso_mss;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_TSO_GENERIC_CONFIG, false);

	req = (struct hns3_cfg_tso_status_cmd *)desc.data;

	tso_mss = 0;
	hns3_set_field(tso_mss, HNS3_TSO_MSS_MIN_M, HNS3_TSO_MSS_MIN_S,
		       tso_mss_min);
	req->tso_mss_min = rte_cpu_to_le_16(tso_mss);

	tso_mss = 0;
	hns3_set_field(tso_mss, HNS3_TSO_MSS_MIN_M, HNS3_TSO_MSS_MIN_S,
		       tso_mss_max);
	req->tso_mss_max = rte_cpu_to_le_16(tso_mss);

	return hns3_cmd_send(hw, &desc, 1);
}

int
hns3_config_gro(struct hns3_hw *hw, bool en)
{
	struct hns3_cfg_gro_status_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_GRO_GENERIC_CONFIG, false);
	req = (struct hns3_cfg_gro_status_cmd *)desc.data;

	req->gro_en = rte_cpu_to_le_16(en ? 1 : 0);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "GRO hardware config cmd failed, ret = %d", ret);

	return ret;
}

static int
hns3_set_umv_space(struct hns3_hw *hw, uint16_t space_size,
		   uint16_t *allocated_size, bool is_alloc)
{
	struct hns3_umv_spc_alc_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	req = (struct hns3_umv_spc_alc_cmd *)desc.data;
	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_VLAN_ALLOCATE, false);
	hns3_set_bit(req->allocate, HNS3_UMV_SPC_ALC_B, is_alloc ? 0 : 1);
	req->space_size = rte_cpu_to_le_32(space_size);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		PMD_INIT_LOG(ERR, "%s umv space failed for cmd_send, ret =%d",
			     is_alloc ? "allocate" : "free", ret);
		return ret;
	}

	if (is_alloc && allocated_size)
		*allocated_size = rte_le_to_cpu_32(desc.data[1]);

	return 0;
}

static int
hns3_init_umv_space(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	uint16_t allocated_size = 0;
	int ret;

	ret = hns3_set_umv_space(hw, pf->wanted_umv_size, &allocated_size,
				 true);
	if (ret)
		return ret;

	if (allocated_size < pf->wanted_umv_size)
		PMD_INIT_LOG(WARNING, "Alloc umv space failed, want %u, get %u",
			     pf->wanted_umv_size, allocated_size);

	pf->max_umv_size = (!!allocated_size) ? allocated_size :
						pf->wanted_umv_size;
	pf->used_umv_size = 0;
	return 0;
}

static int
hns3_uninit_umv_space(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	int ret;

	if (pf->max_umv_size == 0)
		return 0;

	ret = hns3_set_umv_space(hw, pf->max_umv_size, NULL, false);
	if (ret)
		return ret;

	pf->max_umv_size = 0;

	return 0;
}

static bool
hns3_is_umv_space_full(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	bool is_full;

	is_full = (pf->used_umv_size >= pf->max_umv_size);

	return is_full;
}

static void
hns3_update_umv_space(struct hns3_hw *hw, bool is_free)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;

	if (is_free) {
		if (pf->used_umv_size > 0)
			pf->used_umv_size--;
	} else
		pf->used_umv_size++;
}

static void
hns3_prepare_mac_addr(struct hns3_mac_vlan_tbl_entry_cmd *new_req,
		      const uint8_t *addr, bool is_mc)
{
	const unsigned char *mac_addr = addr;
	uint32_t high_val = ((uint32_t)mac_addr[3] << 24) |
			    ((uint32_t)mac_addr[2] << 16) |
			    ((uint32_t)mac_addr[1] << 8) |
			    (uint32_t)mac_addr[0];
	uint32_t low_val = ((uint32_t)mac_addr[5] << 8) | (uint32_t)mac_addr[4];

	hns3_set_bit(new_req->flags, HNS3_MAC_VLAN_BIT0_EN_B, 1);
	if (is_mc) {
		hns3_set_bit(new_req->entry_type, HNS3_MAC_VLAN_BIT0_EN_B, 0);
		hns3_set_bit(new_req->entry_type, HNS3_MAC_VLAN_BIT1_EN_B, 1);
		hns3_set_bit(new_req->mc_mac_en, HNS3_MAC_VLAN_BIT0_EN_B, 1);
	}

	new_req->mac_addr_hi32 = rte_cpu_to_le_32(high_val);
	new_req->mac_addr_lo16 = rte_cpu_to_le_16(low_val & 0xffff);
}

static int
hns3_get_mac_vlan_cmd_status(struct hns3_hw *hw, uint16_t cmdq_resp,
			     uint8_t resp_code,
			     enum hns3_mac_vlan_tbl_opcode op)
{
	if (cmdq_resp) {
		hns3_err(hw, "cmdq execute failed for get_mac_vlan_cmd_status,status=%u",
			 cmdq_resp);
		return -EIO;
	}

	if (op == HNS3_MAC_VLAN_ADD) {
		if (resp_code == 0 || resp_code == 1) {
			return 0;
		} else if (resp_code == HNS3_ADD_UC_OVERFLOW) {
			hns3_err(hw, "add mac addr failed for uc_overflow");
			return -ENOSPC;
		} else if (resp_code == HNS3_ADD_MC_OVERFLOW) {
			hns3_err(hw, "add mac addr failed for mc_overflow");
			return -ENOSPC;
		}

		hns3_err(hw, "add mac addr failed for undefined, code=%u",
			 resp_code);
		return -EIO;
	} else if (op == HNS3_MAC_VLAN_REMOVE) {
		if (resp_code == 0) {
			return 0;
		} else if (resp_code == 1) {
			hns3_dbg(hw, "remove mac addr failed for miss");
			return -ENOENT;
		}

		hns3_err(hw, "remove mac addr failed for undefined, code=%u",
			 resp_code);
		return -EIO;
	} else if (op == HNS3_MAC_VLAN_LKUP) {
		if (resp_code == 0) {
			return 0;
		} else if (resp_code == 1) {
			hns3_dbg(hw, "lookup mac addr failed for miss");
			return -ENOENT;
		}

		hns3_err(hw, "lookup mac addr failed for undefined, code=%u",
			 resp_code);
		return -EIO;
	}

	hns3_err(hw, "unknown opcode for get_mac_vlan_cmd_status, opcode=%u",
		 op);

	return -EINVAL;
}

static int
hns3_lookup_mac_vlan_tbl(struct hns3_hw *hw,
			 struct hns3_mac_vlan_tbl_entry_cmd *req,
			 struct hns3_cmd_desc *desc, bool is_mc)
{
	uint8_t resp_code;
	uint16_t retval;
	int ret;

	hns3_cmd_setup_basic_desc(&desc[0], HNS3_OPC_MAC_VLAN_ADD, true);
	if (is_mc) {
		desc[0].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		memcpy(desc[0].data, req,
			   sizeof(struct hns3_mac_vlan_tbl_entry_cmd));
		hns3_cmd_setup_basic_desc(&desc[1], HNS3_OPC_MAC_VLAN_ADD,
					  true);
		desc[1].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		hns3_cmd_setup_basic_desc(&desc[2], HNS3_OPC_MAC_VLAN_ADD,
					  true);
		ret = hns3_cmd_send(hw, desc, HNS3_MC_MAC_VLAN_ADD_DESC_NUM);
	} else {
		memcpy(desc[0].data, req,
		       sizeof(struct hns3_mac_vlan_tbl_entry_cmd));
		ret = hns3_cmd_send(hw, desc, 1);
	}
	if (ret) {
		hns3_err(hw, "lookup mac addr failed for cmd_send, ret =%d.",
			 ret);
		return ret;
	}
	resp_code = (rte_le_to_cpu_32(desc[0].data[0]) >> 8) & 0xff;
	retval = rte_le_to_cpu_16(desc[0].retval);

	return hns3_get_mac_vlan_cmd_status(hw, retval, resp_code,
					    HNS3_MAC_VLAN_LKUP);
}

static int
hns3_add_mac_vlan_tbl(struct hns3_hw *hw,
		      struct hns3_mac_vlan_tbl_entry_cmd *req,
		      struct hns3_cmd_desc *mc_desc)
{
	uint8_t resp_code;
	uint16_t retval;
	int cfg_status;
	int ret;

	if (mc_desc == NULL) {
		struct hns3_cmd_desc desc;

		hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_VLAN_ADD, false);
		memcpy(desc.data, req,
		       sizeof(struct hns3_mac_vlan_tbl_entry_cmd));
		ret = hns3_cmd_send(hw, &desc, 1);
		resp_code = (rte_le_to_cpu_32(desc.data[0]) >> 8) & 0xff;
		retval = rte_le_to_cpu_16(desc.retval);

		cfg_status = hns3_get_mac_vlan_cmd_status(hw, retval, resp_code,
							  HNS3_MAC_VLAN_ADD);
	} else {
		hns3_cmd_reuse_desc(&mc_desc[0], false);
		mc_desc[0].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		hns3_cmd_reuse_desc(&mc_desc[1], false);
		mc_desc[1].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		hns3_cmd_reuse_desc(&mc_desc[2], false);
		mc_desc[2].flag &= rte_cpu_to_le_16(~HNS3_CMD_FLAG_NEXT);
		memcpy(mc_desc[0].data, req,
		       sizeof(struct hns3_mac_vlan_tbl_entry_cmd));
		mc_desc[0].retval = 0;
		ret = hns3_cmd_send(hw, mc_desc, HNS3_MC_MAC_VLAN_ADD_DESC_NUM);
		resp_code = (rte_le_to_cpu_32(mc_desc[0].data[0]) >> 8) & 0xff;
		retval = rte_le_to_cpu_16(mc_desc[0].retval);

		cfg_status = hns3_get_mac_vlan_cmd_status(hw, retval, resp_code,
							  HNS3_MAC_VLAN_ADD);
	}

	if (ret) {
		hns3_err(hw, "add mac addr failed for cmd_send, ret =%d", ret);
		return ret;
	}

	return cfg_status;
}

static int
hns3_remove_mac_vlan_tbl(struct hns3_hw *hw,
			 struct hns3_mac_vlan_tbl_entry_cmd *req)
{
	struct hns3_cmd_desc desc;
	uint8_t resp_code;
	uint16_t retval;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_VLAN_REMOVE, false);

	memcpy(desc.data, req, sizeof(struct hns3_mac_vlan_tbl_entry_cmd));

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "del mac addr failed for cmd_send, ret =%d", ret);
		return ret;
	}
	resp_code = (rte_le_to_cpu_32(desc.data[0]) >> 8) & 0xff;
	retval = rte_le_to_cpu_16(desc.retval);

	return hns3_get_mac_vlan_cmd_status(hw, retval, resp_code,
					    HNS3_MAC_VLAN_REMOVE);
}

static int
hns3_add_uc_addr_common(struct hns3_hw *hw, struct rte_ether_addr *mac_addr)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_mac_vlan_tbl_entry_cmd req;
	struct hns3_pf *pf = &hns->pf;
	struct hns3_cmd_desc desc;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	uint16_t egress_port = 0;
	uint8_t vf_id;
	int ret;

	/* check if mac addr is valid */
	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Add unicast mac addr err! addr(%s) invalid",
			 mac_str);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, the PF-related vf_id is 0, just need to configure parameters
	 * for vf_id 0.
	 */
	vf_id = 0;
	hns3_set_field(egress_port, HNS3_MAC_EPORT_VFID_M,
		       HNS3_MAC_EPORT_VFID_S, vf_id);

	req.egress_port = rte_cpu_to_le_16(egress_port);

	hns3_prepare_mac_addr(&req, mac_addr->addr_bytes, false);

	/*
	 * Lookup the mac address in the mac_vlan table, and add
	 * it if the entry is inexistent. Repeated unicast entry
	 * is not allowed in the mac vlan table.
	 */
	ret = hns3_lookup_mac_vlan_tbl(hw, &req, &desc, false);
	if (ret == -ENOENT) {
		if (!hns3_is_umv_space_full(hw)) {
			ret = hns3_add_mac_vlan_tbl(hw, &req, NULL);
			if (!ret)
				hns3_update_umv_space(hw, false);
			return ret;
		}

		hns3_err(hw, "UC MAC table full(%u)", pf->used_umv_size);

		return -ENOSPC;
	}

	rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);

	/* check if we just hit the duplicate */
	if (ret == 0) {
		hns3_dbg(hw, "mac addr(%s) has been in the MAC table", mac_str);
		return 0;
	}

	hns3_err(hw, "PF failed to add unicast entry(%s) in the MAC table",
		 mac_str);

	return ret;
}

static int
hns3_add_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr,
		  uint32_t idx, __attribute__ ((unused)) uint32_t pool)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_add_uc_addr_common(hw, mac_addr);
	if (ret) {
		rte_spinlock_unlock(&hw->lock);
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to add mac addr(%s): %d", mac_str, ret);
		return ret;
	}

	if (idx == 0)
		hw->mac.default_addr_setted = true;
	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3_remove_uc_addr_common(struct hns3_hw *hw, struct rte_ether_addr *mac_addr)
{
	struct hns3_mac_vlan_tbl_entry_cmd req;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	/* check if mac addr is valid */
	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Remove unicast mac addr err! addr(%s) invalid",
			 mac_str);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	hns3_set_bit(req.entry_type, HNS3_MAC_VLAN_BIT0_EN_B, 0);
	hns3_prepare_mac_addr(&req, mac_addr->addr_bytes, false);
	ret = hns3_remove_mac_vlan_tbl(hw, &req);
	if (ret == -ENOENT) /* mac addr isn't existent in the mac vlan table. */
		return 0;
	else if (ret == 0)
		hns3_update_umv_space(hw, true);

	return ret;
}

static void
hns3_remove_mac_addr(struct rte_eth_dev *dev, uint32_t idx)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	/* index will be checked by upper level rte interface */
	struct rte_ether_addr *mac_addr = &dev->data->mac_addrs[idx];
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_remove_uc_addr_common(hw, mac_addr);
	if (ret) {
		rte_spinlock_unlock(&hw->lock);
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to remove mac addr(%s): %d", mac_str, ret);
		return;
	}

	if (idx == 0)
		hw->mac.default_addr_setted = false;
	rte_spinlock_unlock(&hw->lock);
}

static int
hns3_set_default_mac_addr(struct rte_eth_dev *dev,
			  struct rte_ether_addr *mac_addr)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_ether_addr *oaddr;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	bool default_addr_setted;
	bool rm_succes = false;
	int ret, ret_val;

	/* check if mac addr is valid */
	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to set mac addr, addr(%s) invalid",
			 mac_str);
		return -EINVAL;
	}

	oaddr = (struct rte_ether_addr *)hw->mac.mac_addr;
	default_addr_setted = hw->mac.default_addr_setted;
	if (default_addr_setted && !!rte_is_same_ether_addr(mac_addr, oaddr))
		return 0;

	rte_spinlock_lock(&hw->lock);
	if (default_addr_setted) {
		ret = hns3_remove_uc_addr_common(hw, oaddr);
		if (ret) {
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      oaddr);
			hns3_warn(hw, "Remove old uc mac address(%s) fail: %d",
				  mac_str, ret);
			rm_succes = false;
		} else
			rm_succes = true;
	}

	ret = hns3_add_uc_addr_common(hw, mac_addr);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to set mac addr(%s): %d", mac_str, ret);
		goto err_add_uc_addr;
	}

	ret = hns3_pause_addr_cfg(hw, mac_addr->addr_bytes);
	if (ret) {
		hns3_err(hw, "Failed to configure mac pause address: %d", ret);
		goto err_pause_addr_cfg;
	}

	rte_ether_addr_copy(mac_addr,
			    (struct rte_ether_addr *)hw->mac.mac_addr);
	hw->mac.default_addr_setted = true;
	rte_spinlock_unlock(&hw->lock);

	return 0;

err_pause_addr_cfg:
	ret_val = hns3_remove_uc_addr_common(hw, mac_addr);
	if (ret_val) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_warn(hw,
			  "Failed to roll back to del setted mac addr(%s): %d",
			  mac_str, ret_val);
	}

err_add_uc_addr:
	if (rm_succes) {
		ret_val = hns3_add_uc_addr_common(hw, oaddr);
		if (ret_val) {
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      oaddr);
			hns3_warn(hw,
				  "Failed to restore old uc mac addr(%s): %d",
				  mac_str, ret_val);
			hw->mac.default_addr_setted = false;
		}
	}
	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3_configure_all_mac_addr(struct hns3_adapter *hns, bool del)
{
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	struct hns3_hw *hw = &hns->hw;
	struct rte_ether_addr *addr;
	int err = 0;
	int ret;
	int i;

	for (i = 0; i < HNS3_UC_MACADDR_NUM; i++) {
		addr = &hw->data->mac_addrs[i];
		if (!rte_is_valid_assigned_ether_addr(addr))
			continue;
		if (del)
			ret = hns3_remove_uc_addr_common(hw, addr);
		else
			ret = hns3_add_uc_addr_common(hw, addr);
		if (ret) {
			err = ret;
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      addr);
			hns3_dbg(hw,
				 "Failed to %s mac addr(%s). ret:%d i:%d",
				 del ? "remove" : "restore", mac_str, ret, i);
		}
	}
	return err;
}

static void
hns3_update_desc_vfid(struct hns3_cmd_desc *desc, uint8_t vfid, bool clr)
{
#define HNS3_VF_NUM_IN_FIRST_DESC 192
	uint8_t word_num;
	uint8_t bit_num;

	if (vfid < HNS3_VF_NUM_IN_FIRST_DESC) {
		word_num = vfid / 32;
		bit_num = vfid % 32;
		if (clr)
			desc[1].data[word_num] &=
			    rte_cpu_to_le_32(~(1UL << bit_num));
		else
			desc[1].data[word_num] |=
			    rte_cpu_to_le_32(1UL << bit_num);
	} else {
		word_num = (vfid - HNS3_VF_NUM_IN_FIRST_DESC) / 32;
		bit_num = vfid % 32;
		if (clr)
			desc[2].data[word_num] &=
			    rte_cpu_to_le_32(~(1UL << bit_num));
		else
			desc[2].data[word_num] |=
			    rte_cpu_to_le_32(1UL << bit_num);
	}
}

static int
hns3_add_mc_addr(struct hns3_hw *hw, struct rte_ether_addr *mac_addr)
{
	struct hns3_mac_vlan_tbl_entry_cmd req;
	struct hns3_cmd_desc desc[3];
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	uint8_t vf_id;
	int ret;

	/* Check if mac addr is valid */
	if (!rte_is_multicast_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to add mc mac addr, addr(%s) invalid",
			 mac_str);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	hns3_set_bit(req.entry_type, HNS3_MAC_VLAN_BIT0_EN_B, 0);
	hns3_prepare_mac_addr(&req, mac_addr->addr_bytes, true);
	ret = hns3_lookup_mac_vlan_tbl(hw, &req, desc, true);
	if (ret) {
		/* This mac addr do not exist, add new entry for it */
		memset(desc[0].data, 0, sizeof(desc[0].data));
		memset(desc[1].data, 0, sizeof(desc[0].data));
		memset(desc[2].data, 0, sizeof(desc[0].data));
	}

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, the PF-related vf_id is 0, just need to configure parameters
	 * for vf_id 0.
	 */
	vf_id = 0;
	hns3_update_desc_vfid(desc, vf_id, false);
	ret = hns3_add_mac_vlan_tbl(hw, &req, desc);
	if (ret) {
		if (ret == -ENOSPC)
			hns3_err(hw, "mc mac vlan table is full");
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to add mc mac addr(%s): %d", mac_str, ret);
	}

	return ret;
}

static int
hns3_remove_mc_addr(struct hns3_hw *hw, struct rte_ether_addr *mac_addr)
{
	struct hns3_mac_vlan_tbl_entry_cmd req;
	struct hns3_cmd_desc desc[3];
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	uint8_t vf_id;
	int ret;

	/* Check if mac addr is valid */
	if (!rte_is_multicast_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to rm mc mac addr, addr(%s) invalid",
			 mac_str);
		return -EINVAL;
	}

	memset(&req, 0, sizeof(req));
	hns3_set_bit(req.entry_type, HNS3_MAC_VLAN_BIT0_EN_B, 0);
	hns3_prepare_mac_addr(&req, mac_addr->addr_bytes, true);
	ret = hns3_lookup_mac_vlan_tbl(hw, &req, desc, true);
	if (ret == 0) {
		/*
		 * This mac addr exist, remove this handle's VFID for it.
		 * In current version VF is not supported when PF is driven by
		 * DPDK driver, the PF-related vf_id is 0, just need to
		 * configure parameters for vf_id 0.
		 */
		vf_id = 0;
		hns3_update_desc_vfid(desc, vf_id, true);

		/* All the vfid is zero, so need to delete this entry */
		ret = hns3_remove_mac_vlan_tbl(hw, &req);
	} else if (ret == -ENOENT) {
		/* This mac addr doesn't exist. */
		return 0;
	}

	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to rm mc mac addr(%s): %d", mac_str, ret);
	}

	return ret;
}

static int
hns3_set_mc_addr_chk_param(struct hns3_hw *hw,
			   struct rte_ether_addr *mc_addr_set,
			   uint32_t nb_mc_addr)
{
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	struct rte_ether_addr *addr;
	uint32_t i;
	uint32_t j;

	if (nb_mc_addr > HNS3_MC_MACADDR_NUM) {
		hns3_err(hw, "Failed to set mc mac addr, nb_mc_addr(%d) "
			 "invalid. valid range: 0~%d",
			 nb_mc_addr, HNS3_MC_MACADDR_NUM);
		return -EINVAL;
	}

	/* Check if input mac addresses are valid */
	for (i = 0; i < nb_mc_addr; i++) {
		addr = &mc_addr_set[i];
		if (!rte_is_multicast_ether_addr(addr)) {
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      addr);
			hns3_err(hw,
				 "Failed to set mc mac addr, addr(%s) invalid.",
				 mac_str);
			return -EINVAL;
		}

		/* Check if there are duplicate addresses */
		for (j = i + 1; j < nb_mc_addr; j++) {
			if (rte_is_same_ether_addr(addr, &mc_addr_set[j])) {
				rte_ether_format_addr(mac_str,
						      RTE_ETHER_ADDR_FMT_SIZE,
						      addr);
				hns3_err(hw, "Failed to set mc mac addr, "
					 "addrs invalid. two same addrs(%s).",
					 mac_str);
				return -EINVAL;
			}
		}
	}

	return 0;
}

static void
hns3_set_mc_addr_calc_addr(struct hns3_hw *hw,
			   struct rte_ether_addr *mc_addr_set,
			   int mc_addr_num,
			   struct rte_ether_addr *reserved_addr_list,
			   int *reserved_addr_num,
			   struct rte_ether_addr *add_addr_list,
			   int *add_addr_num,
			   struct rte_ether_addr *rm_addr_list,
			   int *rm_addr_num)
{
	struct rte_ether_addr *addr;
	int current_addr_num;
	int reserved_num = 0;
	int add_num = 0;
	int rm_num = 0;
	int num;
	int i;
	int j;
	bool same_addr;

	/* Calculate the mc mac address list that should be removed */
	current_addr_num = hw->mc_addrs_num;
	for (i = 0; i < current_addr_num; i++) {
		addr = &hw->mc_addrs[i];
		same_addr = false;
		for (j = 0; j < mc_addr_num; j++) {
			if (rte_is_same_ether_addr(addr, &mc_addr_set[j])) {
				same_addr = true;
				break;
			}
		}

		if (!same_addr) {
			rte_ether_addr_copy(addr, &rm_addr_list[rm_num]);
			rm_num++;
		} else {
			rte_ether_addr_copy(addr,
					    &reserved_addr_list[reserved_num]);
			reserved_num++;
		}
	}

	/* Calculate the mc mac address list that should be added */
	for (i = 0; i < mc_addr_num; i++) {
		addr = &mc_addr_set[i];
		same_addr = false;
		for (j = 0; j < current_addr_num; j++) {
			if (rte_is_same_ether_addr(addr, &hw->mc_addrs[j])) {
				same_addr = true;
				break;
			}
		}

		if (!same_addr) {
			rte_ether_addr_copy(addr, &add_addr_list[add_num]);
			add_num++;
		}
	}

	/* Reorder the mc mac address list maintained by driver */
	for (i = 0; i < reserved_num; i++)
		rte_ether_addr_copy(&reserved_addr_list[i], &hw->mc_addrs[i]);

	for (i = 0; i < rm_num; i++) {
		num = reserved_num + i;
		rte_ether_addr_copy(&rm_addr_list[i], &hw->mc_addrs[num]);
	}

	*reserved_addr_num = reserved_num;
	*add_addr_num = add_num;
	*rm_addr_num = rm_num;
}

static int
hns3_set_mc_mac_addr_list(struct rte_eth_dev *dev,
			  struct rte_ether_addr *mc_addr_set,
			  uint32_t nb_mc_addr)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_ether_addr reserved_addr_list[HNS3_MC_MACADDR_NUM];
	struct rte_ether_addr add_addr_list[HNS3_MC_MACADDR_NUM];
	struct rte_ether_addr rm_addr_list[HNS3_MC_MACADDR_NUM];
	struct rte_ether_addr *addr;
	int reserved_addr_num;
	int add_addr_num;
	int rm_addr_num;
	int mc_addr_num;
	int num;
	int ret;
	int i;

	/* Check if input parameters are valid */
	ret = hns3_set_mc_addr_chk_param(hw, mc_addr_set, nb_mc_addr);
	if (ret)
		return ret;

	rte_spinlock_lock(&hw->lock);

	/*
	 * Calculate the mc mac address lists those should be removed and be
	 * added, Reorder the mc mac address list maintained by driver.
	 */
	mc_addr_num = (int)nb_mc_addr;
	hns3_set_mc_addr_calc_addr(hw, mc_addr_set, mc_addr_num,
				   reserved_addr_list, &reserved_addr_num,
				   add_addr_list, &add_addr_num,
				   rm_addr_list, &rm_addr_num);

	/* Remove mc mac addresses */
	for (i = 0; i < rm_addr_num; i++) {
		num = rm_addr_num - i - 1;
		addr = &rm_addr_list[num];
		ret = hns3_remove_mc_addr(hw, addr);
		if (ret) {
			rte_spinlock_unlock(&hw->lock);
			return ret;
		}
		hw->mc_addrs_num--;
	}

	/* Add mc mac addresses */
	for (i = 0; i < add_addr_num; i++) {
		addr = &add_addr_list[i];
		ret = hns3_add_mc_addr(hw, addr);
		if (ret) {
			rte_spinlock_unlock(&hw->lock);
			return ret;
		}

		num = reserved_addr_num + i;
		rte_ether_addr_copy(addr, &hw->mc_addrs[num]);
		hw->mc_addrs_num++;
	}
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3_configure_all_mc_mac_addr(struct hns3_adapter *hns, bool del)
{
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	struct hns3_hw *hw = &hns->hw;
	struct rte_ether_addr *addr;
	int err = 0;
	int ret;
	int i;

	for (i = 0; i < hw->mc_addrs_num; i++) {
		addr = &hw->mc_addrs[i];
		if (!rte_is_multicast_ether_addr(addr))
			continue;
		if (del)
			ret = hns3_remove_mc_addr(hw, addr);
		else
			ret = hns3_add_mc_addr(hw, addr);
		if (ret) {
			err = ret;
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      addr);
			hns3_dbg(hw, "%s mc mac addr: %s failed",
				 del ? "Remove" : "Restore", mac_str);
		}
	}
	return err;
}

static int
hns3_check_mq_mode(struct rte_eth_dev *dev)
{
	enum rte_eth_rx_mq_mode rx_mq_mode = dev->data->dev_conf.rxmode.mq_mode;
	enum rte_eth_tx_mq_mode tx_mq_mode = dev->data->dev_conf.txmode.mq_mode;
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_pf *pf = HNS3_DEV_PRIVATE_TO_PF(dev->data->dev_private);
	struct rte_eth_dcb_rx_conf *dcb_rx_conf;
	struct rte_eth_dcb_tx_conf *dcb_tx_conf;
	uint8_t num_tc;
	int max_tc = 0;
	int i;

	dcb_rx_conf = &dev->data->dev_conf.rx_adv_conf.dcb_rx_conf;
	dcb_tx_conf = &dev->data->dev_conf.tx_adv_conf.dcb_tx_conf;

	if (rx_mq_mode == ETH_MQ_RX_VMDQ_DCB_RSS) {
		hns3_err(hw, "ETH_MQ_RX_VMDQ_DCB_RSS is not supported. "
			 "rx_mq_mode = %d", rx_mq_mode);
		return -EINVAL;
	}

	if (rx_mq_mode == ETH_MQ_RX_VMDQ_DCB ||
	    tx_mq_mode == ETH_MQ_TX_VMDQ_DCB) {
		hns3_err(hw, "ETH_MQ_RX_VMDQ_DCB and ETH_MQ_TX_VMDQ_DCB "
			 "is not supported. rx_mq_mode = %d, tx_mq_mode = %d",
			 rx_mq_mode, tx_mq_mode);
		return -EINVAL;
	}

	if (rx_mq_mode == ETH_MQ_RX_DCB_RSS) {
		if (dcb_rx_conf->nb_tcs > pf->tc_max) {
			hns3_err(hw, "nb_tcs(%u) > max_tc(%u) driver supported.",
				 dcb_rx_conf->nb_tcs, pf->tc_max);
			return -EINVAL;
		}

		if (!(dcb_rx_conf->nb_tcs == HNS3_4_TCS ||
		      dcb_rx_conf->nb_tcs == HNS3_8_TCS)) {
			hns3_err(hw, "on ETH_MQ_RX_DCB_RSS mode, "
				 "nb_tcs(%d) != %d or %d in rx direction.",
				 dcb_rx_conf->nb_tcs, HNS3_4_TCS, HNS3_8_TCS);
			return -EINVAL;
		}

		if (dcb_rx_conf->nb_tcs != dcb_tx_conf->nb_tcs) {
			hns3_err(hw, "num_tcs(%d) of tx is not equal to rx(%d)",
				 dcb_tx_conf->nb_tcs, dcb_rx_conf->nb_tcs);
			return -EINVAL;
		}

		for (i = 0; i < HNS3_MAX_USER_PRIO; i++) {
			if (dcb_rx_conf->dcb_tc[i] != dcb_tx_conf->dcb_tc[i]) {
				hns3_err(hw, "dcb_tc[%d] = %d in rx direction, "
					 "is not equal to one in tx direction.",
					 i, dcb_rx_conf->dcb_tc[i]);
				return -EINVAL;
			}
			if (dcb_rx_conf->dcb_tc[i] > max_tc)
				max_tc = dcb_rx_conf->dcb_tc[i];
		}

		num_tc = max_tc + 1;
		if (num_tc > dcb_rx_conf->nb_tcs) {
			hns3_err(hw, "max num_tc(%u) mapped > nb_tcs(%u)",
				 num_tc, dcb_rx_conf->nb_tcs);
			return -EINVAL;
		}
	}

	return 0;
}

static int
hns3_check_dcb_cfg(struct rte_eth_dev *dev)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	if (!hns3_dev_dcb_supported(hw)) {
		hns3_err(hw, "this port does not support dcb configurations.");
		return -EOPNOTSUPP;
	}

	if (hw->current_fc_status == HNS3_FC_STATUS_MAC_PAUSE) {
		hns3_err(hw, "MAC pause enabled, cannot config dcb info.");
		return -EOPNOTSUPP;
	}

	/* Check multiple queue mode */
	return hns3_check_mq_mode(dev);
}

static int
hns3_dev_configure(struct rte_eth_dev *dev)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	enum rte_eth_rx_mq_mode mq_mode = conf->rxmode.mq_mode;
	uint16_t nb_rx_q = dev->data->nb_rx_queues;
	uint16_t nb_tx_q = dev->data->nb_tx_queues;
	struct rte_eth_rss_conf rss_conf;
	uint16_t mtu;
	int ret;

	/*
	 * Hardware does not support where the number of rx and tx queues is
	 * not equal in hip08.
	 */
	if (nb_rx_q != nb_tx_q) {
		hns3_err(hw,
			 "nb_rx_queues(%u) not equal with nb_tx_queues(%u)! "
			 "Hardware does not support this configuration!",
			 nb_rx_q, nb_tx_q);
		return -EINVAL;
	}

	if (conf->link_speeds & ETH_LINK_SPEED_FIXED) {
		hns3_err(hw, "setting link speed/duplex not supported");
		return -EINVAL;
	}

	hw->adapter_state = HNS3_NIC_CONFIGURING;
	if ((uint32_t)mq_mode & ETH_MQ_RX_DCB_FLAG) {
		ret = hns3_check_dcb_cfg(dev);
		if (ret)
			goto cfg_err;
	}

	/* When RSS is not configured, redirect the packet queue 0 */
	if ((uint32_t)mq_mode & ETH_MQ_RX_RSS_FLAG) {
		rss_conf = conf->rx_adv_conf.rss_conf;
		if (rss_conf.rss_key == NULL) {
			rss_conf.rss_key = rss_cfg->key;
			rss_conf.rss_key_len = HNS3_RSS_KEY_SIZE;
		}

		ret = hns3_dev_rss_hash_update(dev, &rss_conf);
		if (ret)
			goto cfg_err;
	}

	/*
	 * If jumbo frames are enabled, MTU needs to be refreshed
	 * according to the maximum RX packet length.
	 */
	if (conf->rxmode.offloads & DEV_RX_OFFLOAD_JUMBO_FRAME) {
		/*
		 * Security of max_rx_pkt_len is guaranteed in dpdk frame.
		 * Maximum value of max_rx_pkt_len is HNS3_MAX_FRAME_LEN, so it
		 * can safely assign to "uint16_t" type variable.
		 */
		mtu = (uint16_t)HNS3_PKTLEN_TO_MTU(conf->rxmode.max_rx_pkt_len);
		ret = hns3_dev_mtu_set(dev, mtu);
		if (ret)
			goto cfg_err;
		dev->data->mtu = mtu;
	}

	ret = hns3_dev_configure_vlan(dev);
	if (ret)
		goto cfg_err;

	hw->adapter_state = HNS3_NIC_CONFIGURED;

	return 0;

cfg_err:
	hw->adapter_state = HNS3_NIC_INITIALIZED;
	return ret;
}

static int
hns3_set_mac_mtu(struct hns3_hw *hw, uint16_t new_mps)
{
	struct hns3_config_max_frm_size_cmd *req;
	struct hns3_cmd_desc desc;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CONFIG_MAX_FRM_SIZE, false);

	req = (struct hns3_config_max_frm_size_cmd *)desc.data;
	req->max_frm_size = rte_cpu_to_le_16(new_mps);
	req->min_frm_size = HNS3_MIN_FRAME_LEN;

	return hns3_cmd_send(hw, &desc, 1);
}

static int
hns3_config_mtu(struct hns3_hw *hw, uint16_t mps)
{
	int ret;

	ret = hns3_set_mac_mtu(hw, mps);
	if (ret) {
		hns3_err(hw, "Failed to set mtu, ret = %d", ret);
		return ret;
	}

	ret = hns3_buffer_alloc(hw);
	if (ret) {
		hns3_err(hw, "Failed to allocate buffer, ret = %d", ret);
		return ret;
	}

	return 0;
}

static int
hns3_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	uint32_t frame_size = mtu + HNS3_ETH_OVERHEAD;
	struct hns3_hw *hw = &hns->hw;
	bool is_jumbo_frame;
	int ret;

	if (dev->data->dev_started) {
		hns3_err(hw, "Failed to set mtu, port %u must be stopped "
			 "before configuration", dev->data->port_id);
		return -EBUSY;
	}

	rte_spinlock_lock(&hw->lock);
	is_jumbo_frame = frame_size > RTE_ETHER_MAX_LEN ? true : false;
	frame_size = RTE_MAX(frame_size, HNS3_DEFAULT_FRAME_LEN);

	/*
	 * Maximum value of frame_size is HNS3_MAX_FRAME_LEN, so it can safely
	 * assign to "uint16_t" type variable.
	 */
	ret = hns3_config_mtu(hw, (uint16_t)frame_size);
	if (ret) {
		rte_spinlock_unlock(&hw->lock);
		hns3_err(hw, "Failed to set mtu, port %u mtu %u: %d",
			 dev->data->port_id, mtu, ret);
		return ret;
	}
	hns->pf.mps = (uint16_t)frame_size;
	if (is_jumbo_frame)
		dev->data->dev_conf.rxmode.offloads |=
						DEV_RX_OFFLOAD_JUMBO_FRAME;
	else
		dev->data->dev_conf.rxmode.offloads &=
						~DEV_RX_OFFLOAD_JUMBO_FRAME;
	dev->data->dev_conf.rxmode.max_rx_pkt_len = frame_size;
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3_dev_infos_get(struct rte_eth_dev *eth_dev, struct rte_eth_dev_info *info)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	info->max_rx_queues = hw->tqps_num;
	info->max_tx_queues = hw->tqps_num;
	info->max_rx_pktlen = HNS3_MAX_FRAME_LEN; /* CRC included */
	info->min_rx_bufsize = hw->rx_buf_len;
	info->max_mac_addrs = HNS3_UC_MACADDR_NUM;
	info->max_mtu = info->max_rx_pktlen - HNS3_ETH_OVERHEAD;
	info->rx_offload_capa = (DEV_RX_OFFLOAD_IPV4_CKSUM |
				 DEV_RX_OFFLOAD_TCP_CKSUM |
				 DEV_RX_OFFLOAD_UDP_CKSUM |
				 DEV_RX_OFFLOAD_SCTP_CKSUM |
				 DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
				 DEV_RX_OFFLOAD_OUTER_UDP_CKSUM |
				 DEV_RX_OFFLOAD_KEEP_CRC |
				 DEV_RX_OFFLOAD_SCATTER |
				 DEV_RX_OFFLOAD_VLAN_STRIP |
				 DEV_RX_OFFLOAD_QINQ_STRIP |
				 DEV_RX_OFFLOAD_VLAN_FILTER |
				 DEV_RX_OFFLOAD_VLAN_EXTEND |
				 DEV_RX_OFFLOAD_JUMBO_FRAME);
	info->tx_queue_offload_capa = DEV_TX_OFFLOAD_MBUF_FAST_FREE;
	info->tx_offload_capa = (DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM |
				 DEV_TX_OFFLOAD_IPV4_CKSUM |
				 DEV_TX_OFFLOAD_TCP_CKSUM |
				 DEV_TX_OFFLOAD_UDP_CKSUM |
				 DEV_TX_OFFLOAD_SCTP_CKSUM |
				 DEV_TX_OFFLOAD_VLAN_INSERT |
				 DEV_TX_OFFLOAD_QINQ_INSERT |
				 DEV_TX_OFFLOAD_MULTI_SEGS |
				 info->tx_queue_offload_capa);

	info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = HNS3_MAX_RING_DESC,
		.nb_min = HNS3_MIN_RING_DESC,
		.nb_align = HNS3_ALIGN_RING_DESC,
	};

	info->tx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = HNS3_MAX_RING_DESC,
		.nb_min = HNS3_MIN_RING_DESC,
		.nb_align = HNS3_ALIGN_RING_DESC,
	};

	info->vmdq_queue_num = 0;

	info->reta_size = HNS3_RSS_IND_TBL_SIZE;
	info->hash_key_size = HNS3_RSS_KEY_SIZE;
	info->flow_type_rss_offloads = HNS3_ETH_RSS_SUPPORT;

	info->default_rxportconf.burst_size = HNS3_DEFAULT_PORT_CONF_BURST_SIZE;
	info->default_txportconf.burst_size = HNS3_DEFAULT_PORT_CONF_BURST_SIZE;
	info->default_rxportconf.nb_queues = HNS3_DEFAULT_PORT_CONF_QUEUES_NUM;
	info->default_txportconf.nb_queues = HNS3_DEFAULT_PORT_CONF_QUEUES_NUM;
	info->default_rxportconf.ring_size = HNS3_DEFAULT_RING_DESC;
	info->default_txportconf.ring_size = HNS3_DEFAULT_RING_DESC;

	return 0;
}

static int
hns3_fw_version_get(struct rte_eth_dev *eth_dev, char *fw_version,
		    size_t fw_size)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = snprintf(fw_version, fw_size, "0x%08x", hw->fw_version);
	ret += 1; /* add the size of '\0' */
	if (fw_size < (uint32_t)ret)
		return ret;
	else
		return 0;
}

static int
hns3_dev_link_update(struct rte_eth_dev *eth_dev,
		     __rte_unused int wait_to_complete)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_mac *mac = &hw->mac;
	struct rte_eth_link new_link;

	memset(&new_link, 0, sizeof(new_link));
	switch (mac->link_speed) {
	case ETH_SPEED_NUM_10M:
	case ETH_SPEED_NUM_100M:
	case ETH_SPEED_NUM_1G:
	case ETH_SPEED_NUM_10G:
	case ETH_SPEED_NUM_25G:
	case ETH_SPEED_NUM_40G:
	case ETH_SPEED_NUM_50G:
	case ETH_SPEED_NUM_100G:
		new_link.link_speed = mac->link_speed;
		break;
	default:
		new_link.link_speed = ETH_SPEED_NUM_100M;
		break;
	}

	new_link.link_duplex = mac->link_duplex;
	new_link.link_status = mac->link_status ? ETH_LINK_UP : ETH_LINK_DOWN;
	new_link.link_autoneg =
	    !(eth_dev->data->dev_conf.link_speeds & ETH_LINK_SPEED_FIXED);

	return rte_eth_linkstatus_set(eth_dev, &new_link);
}

static int
hns3_parse_func_status(struct hns3_hw *hw, struct hns3_func_status_cmd *status)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;

	if (!(status->pf_state & HNS3_PF_STATE_DONE))
		return -EINVAL;

	pf->is_main_pf = (status->pf_state & HNS3_PF_STATE_MAIN) ? true : false;

	return 0;
}

static int
hns3_query_function_status(struct hns3_hw *hw)
{
#define HNS3_QUERY_MAX_CNT		10
#define HNS3_QUERY_SLEEP_MSCOEND	1
	struct hns3_func_status_cmd *req;
	struct hns3_cmd_desc desc;
	int timeout = 0;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_FUNC_STATUS, true);
	req = (struct hns3_func_status_cmd *)desc.data;

	do {
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			PMD_INIT_LOG(ERR, "query function status failed %d",
				     ret);
			return ret;
		}

		/* Check pf reset is done */
		if (req->pf_state)
			break;

		rte_delay_ms(HNS3_QUERY_SLEEP_MSCOEND);
	} while (timeout++ < HNS3_QUERY_MAX_CNT);

	return hns3_parse_func_status(hw, req);
}

static int
hns3_query_pf_resource(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_pf_res_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_PF_RSRC, true);
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		PMD_INIT_LOG(ERR, "query pf resource failed %d", ret);
		return ret;
	}

	req = (struct hns3_pf_res_cmd *)desc.data;
	hw->total_tqps_num = rte_le_to_cpu_16(req->tqp_num);
	pf->pkt_buf_size = rte_le_to_cpu_16(req->buf_size) << HNS3_BUF_UNIT_S;
	hw->tqps_num = RTE_MIN(hw->total_tqps_num, HNS3_MAX_TQP_NUM_PER_FUNC);

	if (req->tx_buf_size)
		pf->tx_buf_size =
		    rte_le_to_cpu_16(req->tx_buf_size) << HNS3_BUF_UNIT_S;
	else
		pf->tx_buf_size = HNS3_DEFAULT_TX_BUF;

	pf->tx_buf_size = roundup(pf->tx_buf_size, HNS3_BUF_SIZE_UNIT);

	if (req->dv_buf_size)
		pf->dv_buf_size =
		    rte_le_to_cpu_16(req->dv_buf_size) << HNS3_BUF_UNIT_S;
	else
		pf->dv_buf_size = HNS3_DEFAULT_DV;

	pf->dv_buf_size = roundup(pf->dv_buf_size, HNS3_BUF_SIZE_UNIT);

	hw->num_msi =
	    hns3_get_field(rte_le_to_cpu_16(req->pf_intr_vector_number),
			   HNS3_PF_VEC_NUM_M, HNS3_PF_VEC_NUM_S);

	return 0;
}

static void
hns3_parse_cfg(struct hns3_cfg *cfg, struct hns3_cmd_desc *desc)
{
	struct hns3_cfg_param_cmd *req;
	uint64_t mac_addr_tmp_high;
	uint64_t mac_addr_tmp;
	uint32_t i;

	req = (struct hns3_cfg_param_cmd *)desc[0].data;

	/* get the configuration */
	cfg->vmdq_vport_num = hns3_get_field(rte_le_to_cpu_32(req->param[0]),
					     HNS3_CFG_VMDQ_M, HNS3_CFG_VMDQ_S);
	cfg->tc_num = hns3_get_field(rte_le_to_cpu_32(req->param[0]),
				     HNS3_CFG_TC_NUM_M, HNS3_CFG_TC_NUM_S);
	cfg->tqp_desc_num = hns3_get_field(rte_le_to_cpu_32(req->param[0]),
					   HNS3_CFG_TQP_DESC_N_M,
					   HNS3_CFG_TQP_DESC_N_S);

	cfg->phy_addr = hns3_get_field(rte_le_to_cpu_32(req->param[1]),
				       HNS3_CFG_PHY_ADDR_M,
				       HNS3_CFG_PHY_ADDR_S);
	cfg->media_type = hns3_get_field(rte_le_to_cpu_32(req->param[1]),
					 HNS3_CFG_MEDIA_TP_M,
					 HNS3_CFG_MEDIA_TP_S);
	cfg->rx_buf_len = hns3_get_field(rte_le_to_cpu_32(req->param[1]),
					 HNS3_CFG_RX_BUF_LEN_M,
					 HNS3_CFG_RX_BUF_LEN_S);
	/* get mac address */
	mac_addr_tmp = rte_le_to_cpu_32(req->param[2]);
	mac_addr_tmp_high = hns3_get_field(rte_le_to_cpu_32(req->param[3]),
					   HNS3_CFG_MAC_ADDR_H_M,
					   HNS3_CFG_MAC_ADDR_H_S);

	mac_addr_tmp |= (mac_addr_tmp_high << 31) << 1;

	cfg->default_speed = hns3_get_field(rte_le_to_cpu_32(req->param[3]),
					    HNS3_CFG_DEFAULT_SPEED_M,
					    HNS3_CFG_DEFAULT_SPEED_S);
	cfg->rss_size_max = hns3_get_field(rte_le_to_cpu_32(req->param[3]),
					   HNS3_CFG_RSS_SIZE_M,
					   HNS3_CFG_RSS_SIZE_S);

	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
		cfg->mac_addr[i] = (mac_addr_tmp >> (8 * i)) & 0xff;

	req = (struct hns3_cfg_param_cmd *)desc[1].data;
	cfg->numa_node_map = rte_le_to_cpu_32(req->param[0]);

	cfg->speed_ability = hns3_get_field(rte_le_to_cpu_32(req->param[1]),
					    HNS3_CFG_SPEED_ABILITY_M,
					    HNS3_CFG_SPEED_ABILITY_S);
	cfg->umv_space = hns3_get_field(rte_le_to_cpu_32(req->param[1]),
					HNS3_CFG_UMV_TBL_SPACE_M,
					HNS3_CFG_UMV_TBL_SPACE_S);
	if (!cfg->umv_space)
		cfg->umv_space = HNS3_DEFAULT_UMV_SPACE_PER_PF;
}

/* hns3_get_board_cfg: query the static parameter from NCL_config file in flash
 * @hw: pointer to struct hns3_hw
 * @hcfg: the config structure to be getted
 */
static int
hns3_get_board_cfg(struct hns3_hw *hw, struct hns3_cfg *hcfg)
{
	struct hns3_cmd_desc desc[HNS3_PF_CFG_DESC_NUM];
	struct hns3_cfg_param_cmd *req;
	uint32_t offset;
	uint32_t i;
	int ret;

	for (i = 0; i < HNS3_PF_CFG_DESC_NUM; i++) {
		offset = 0;
		req = (struct hns3_cfg_param_cmd *)desc[i].data;
		hns3_cmd_setup_basic_desc(&desc[i], HNS3_OPC_GET_CFG_PARAM,
					  true);
		hns3_set_field(offset, HNS3_CFG_OFFSET_M, HNS3_CFG_OFFSET_S,
			       i * HNS3_CFG_RD_LEN_BYTES);
		/* Len should be divided by 4 when send to hardware */
		hns3_set_field(offset, HNS3_CFG_RD_LEN_M, HNS3_CFG_RD_LEN_S,
			       HNS3_CFG_RD_LEN_BYTES / HNS3_CFG_RD_LEN_UNIT);
		req->offset = rte_cpu_to_le_32(offset);
	}

	ret = hns3_cmd_send(hw, desc, HNS3_PF_CFG_DESC_NUM);
	if (ret) {
		PMD_INIT_LOG(ERR, "get config failed %d.", ret);
		return ret;
	}

	hns3_parse_cfg(hcfg, desc);

	return 0;
}

static int
hns3_parse_speed(int speed_cmd, uint32_t *speed)
{
	switch (speed_cmd) {
	case HNS3_CFG_SPEED_10M:
		*speed = ETH_SPEED_NUM_10M;
		break;
	case HNS3_CFG_SPEED_100M:
		*speed = ETH_SPEED_NUM_100M;
		break;
	case HNS3_CFG_SPEED_1G:
		*speed = ETH_SPEED_NUM_1G;
		break;
	case HNS3_CFG_SPEED_10G:
		*speed = ETH_SPEED_NUM_10G;
		break;
	case HNS3_CFG_SPEED_25G:
		*speed = ETH_SPEED_NUM_25G;
		break;
	case HNS3_CFG_SPEED_40G:
		*speed = ETH_SPEED_NUM_40G;
		break;
	case HNS3_CFG_SPEED_50G:
		*speed = ETH_SPEED_NUM_50G;
		break;
	case HNS3_CFG_SPEED_100G:
		*speed = ETH_SPEED_NUM_100G;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
hns3_get_board_configuration(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_cfg cfg;
	int ret;

	ret = hns3_get_board_cfg(hw, &cfg);
	if (ret) {
		PMD_INIT_LOG(ERR, "get board config failed %d", ret);
		return ret;
	}

	if (cfg.media_type == HNS3_MEDIA_TYPE_COPPER) {
		PMD_INIT_LOG(ERR, "media type is copper, not supported.");
		return -EOPNOTSUPP;
	}

	hw->mac.media_type = cfg.media_type;
	hw->rss_size_max = cfg.rss_size_max;
	hw->rx_buf_len = cfg.rx_buf_len;
	memcpy(hw->mac.mac_addr, cfg.mac_addr, RTE_ETHER_ADDR_LEN);
	hw->mac.phy_addr = cfg.phy_addr;
	hw->mac.default_addr_setted = false;
	hw->num_tx_desc = cfg.tqp_desc_num;
	hw->num_rx_desc = cfg.tqp_desc_num;
	hw->dcb_info.num_pg = 1;
	hw->dcb_info.hw_pfc_map = 0;

	ret = hns3_parse_speed(cfg.default_speed, &hw->mac.link_speed);
	if (ret) {
		PMD_INIT_LOG(ERR, "Get wrong speed %d, ret = %d",
			     cfg.default_speed, ret);
		return ret;
	}

	pf->tc_max = cfg.tc_num;
	if (pf->tc_max > HNS3_MAX_TC_NUM || pf->tc_max < 1) {
		PMD_INIT_LOG(WARNING,
			     "Get TC num(%u) from flash, set TC num to 1",
			     pf->tc_max);
		pf->tc_max = 1;
	}

	/* Dev does not support DCB */
	if (!hns3_dev_dcb_supported(hw)) {
		pf->tc_max = 1;
		pf->pfc_max = 0;
	} else
		pf->pfc_max = pf->tc_max;

	hw->dcb_info.num_tc = 1;
	hw->alloc_rss_size = RTE_MIN(hw->rss_size_max,
				     hw->tqps_num / hw->dcb_info.num_tc);
	hns3_set_bit(hw->hw_tc_map, 0, 1);
	pf->tx_sch_mode = HNS3_FLAG_TC_BASE_SCH_MODE;

	pf->wanted_umv_size = cfg.umv_space;

	return ret;
}

static int
hns3_get_configuration(struct hns3_hw *hw)
{
	int ret;

	ret = hns3_query_function_status(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to query function status: %d.", ret);
		return ret;
	}

	/* Get pf resource */
	ret = hns3_query_pf_resource(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to query pf resource: %d", ret);
		return ret;
	}

	ret = hns3_get_board_configuration(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to get board configuration: %d", ret);
		return ret;
	}

	return 0;
}

static int
hns3_map_tqps_to_func(struct hns3_hw *hw, uint16_t func_id, uint16_t tqp_pid,
		      uint16_t tqp_vid, bool is_pf)
{
	struct hns3_tqp_map_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_SET_TQP_MAP, false);

	req = (struct hns3_tqp_map_cmd *)desc.data;
	req->tqp_id = rte_cpu_to_le_16(tqp_pid);
	req->tqp_vf = func_id;
	req->tqp_flag = 1 << HNS3_TQP_MAP_EN_B;
	if (!is_pf)
		req->tqp_flag |= (1 << HNS3_TQP_MAP_TYPE_B);
	req->tqp_vid = rte_cpu_to_le_16(tqp_vid);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "TQP map failed %d", ret);

	return ret;
}

static int
hns3_map_tqp(struct hns3_hw *hw)
{
	uint16_t tqps_num = hw->total_tqps_num;
	uint16_t func_id;
	uint16_t tqp_id;
	int num;
	int ret;
	int i;

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, so we allocate tqps to PF as much as possible.
	 */
	tqp_id = 0;
	num = DIV_ROUND_UP(hw->total_tqps_num, HNS3_MAX_TQP_NUM_PER_FUNC);
	for (func_id = 0; func_id < num; func_id++) {
		for (i = 0;
		     i < HNS3_MAX_TQP_NUM_PER_FUNC && tqp_id < tqps_num; i++) {
			ret = hns3_map_tqps_to_func(hw, func_id, tqp_id++, i,
						    true);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int
hns3_cfg_mac_speed_dup_hw(struct hns3_hw *hw, uint32_t speed, uint8_t duplex)
{
	struct hns3_config_mac_speed_dup_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	req = (struct hns3_config_mac_speed_dup_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CONFIG_SPEED_DUP, false);

	hns3_set_bit(req->speed_dup, HNS3_CFG_DUPLEX_B, !!duplex ? 1 : 0);

	switch (speed) {
	case ETH_SPEED_NUM_10M:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_10M);
		break;
	case ETH_SPEED_NUM_100M:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_100M);
		break;
	case ETH_SPEED_NUM_1G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_1G);
		break;
	case ETH_SPEED_NUM_10G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_10G);
		break;
	case ETH_SPEED_NUM_25G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_25G);
		break;
	case ETH_SPEED_NUM_40G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_40G);
		break;
	case ETH_SPEED_NUM_50G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_50G);
		break;
	case ETH_SPEED_NUM_100G:
		hns3_set_field(req->speed_dup, HNS3_CFG_SPEED_M,
			       HNS3_CFG_SPEED_S, HNS3_CFG_SPEED_100G);
		break;
	default:
		PMD_INIT_LOG(ERR, "invalid speed (%u)", speed);
		return -EINVAL;
	}

	hns3_set_bit(req->mac_change_fec_en, HNS3_CFG_MAC_SPEED_CHANGE_EN_B, 1);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "mac speed/duplex config cmd failed %d", ret);

	return ret;
}

static int
hns3_tx_buffer_calc(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_priv_buf *priv;
	uint32_t i, total_size;

	total_size = pf->pkt_buf_size;

	/* alloc tx buffer for all enabled tc */
	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];

		if (hw->hw_tc_map & BIT(i)) {
			if (total_size < pf->tx_buf_size)
				return -ENOMEM;

			priv->tx_buf_size = pf->tx_buf_size;
		} else
			priv->tx_buf_size = 0;

		total_size -= priv->tx_buf_size;
	}

	return 0;
}

static int
hns3_tx_buffer_alloc(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
/* TX buffer size is unit by 128 byte */
#define HNS3_BUF_SIZE_UNIT_SHIFT	7
#define HNS3_BUF_SIZE_UPDATE_EN_MSK	BIT(15)
	struct hns3_tx_buff_alloc_cmd *req;
	struct hns3_cmd_desc desc;
	uint32_t buf_size;
	uint32_t i;
	int ret;

	req = (struct hns3_tx_buff_alloc_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_TX_BUFF_ALLOC, 0);
	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		buf_size = buf_alloc->priv_buf[i].tx_buf_size;

		buf_size = buf_size >> HNS3_BUF_SIZE_UNIT_SHIFT;
		req->tx_pkt_buff[i] = rte_cpu_to_le_16(buf_size |
						HNS3_BUF_SIZE_UPDATE_EN_MSK);
	}

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "tx buffer alloc cmd failed %d", ret);

	return ret;
}

static int
hns3_get_tc_num(struct hns3_hw *hw)
{
	int cnt = 0;
	uint8_t i;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++)
		if (hw->hw_tc_map & BIT(i))
			cnt++;
	return cnt;
}

static uint32_t
hns3_get_rx_priv_buff_alloced(struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_priv_buf *priv;
	uint32_t rx_priv = 0;
	int i;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];
		if (priv->enable)
			rx_priv += priv->buf_size;
	}
	return rx_priv;
}

static uint32_t
hns3_get_tx_buff_alloced(struct hns3_pkt_buf_alloc *buf_alloc)
{
	uint32_t total_tx_size = 0;
	uint32_t i;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++)
		total_tx_size += buf_alloc->priv_buf[i].tx_buf_size;

	return total_tx_size;
}

/* Get the number of pfc enabled TCs, which have private buffer */
static int
hns3_get_pfc_priv_num(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_priv_buf *priv;
	int cnt = 0;
	uint8_t i;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];
		if ((hw->dcb_info.hw_pfc_map & BIT(i)) && priv->enable)
			cnt++;
	}

	return cnt;
}

/* Get the number of pfc disabled TCs, which have private buffer */
static int
hns3_get_no_pfc_priv_num(struct hns3_hw *hw,
			 struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_priv_buf *priv;
	int cnt = 0;
	uint8_t i;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];
		if (hw->hw_tc_map & BIT(i) &&
		    !(hw->dcb_info.hw_pfc_map & BIT(i)) && priv->enable)
			cnt++;
	}

	return cnt;
}

static bool
hns3_is_rx_buf_ok(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc,
		  uint32_t rx_all)
{
	uint32_t shared_buf_min, shared_buf_tc, shared_std, hi_thrd, lo_thrd;
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	uint32_t shared_buf, aligned_mps;
	uint32_t rx_priv;
	uint8_t tc_num;
	uint8_t i;

	tc_num = hns3_get_tc_num(hw);
	aligned_mps = roundup(pf->mps, HNS3_BUF_SIZE_UNIT);

	if (hns3_dev_dcb_supported(hw))
		shared_buf_min = HNS3_BUF_MUL_BY * aligned_mps +
					pf->dv_buf_size;
	else
		shared_buf_min = aligned_mps + HNS3_NON_DCB_ADDITIONAL_BUF
					+ pf->dv_buf_size;

	shared_buf_tc = tc_num * aligned_mps + aligned_mps;
	shared_std = roundup(max_t(uint32_t, shared_buf_min, shared_buf_tc),
			     HNS3_BUF_SIZE_UNIT);

	rx_priv = hns3_get_rx_priv_buff_alloced(buf_alloc);
	if (rx_all < rx_priv + shared_std)
		return false;

	shared_buf = rounddown(rx_all - rx_priv, HNS3_BUF_SIZE_UNIT);
	buf_alloc->s_buf.buf_size = shared_buf;
	if (hns3_dev_dcb_supported(hw)) {
		buf_alloc->s_buf.self.high = shared_buf - pf->dv_buf_size;
		buf_alloc->s_buf.self.low = buf_alloc->s_buf.self.high
			- roundup(aligned_mps / HNS3_BUF_DIV_BY,
				  HNS3_BUF_SIZE_UNIT);
	} else {
		buf_alloc->s_buf.self.high =
			aligned_mps + HNS3_NON_DCB_ADDITIONAL_BUF;
		buf_alloc->s_buf.self.low = aligned_mps;
	}

	if (hns3_dev_dcb_supported(hw)) {
		hi_thrd = shared_buf - pf->dv_buf_size;

		if (tc_num <= NEED_RESERVE_TC_NUM)
			hi_thrd = hi_thrd * BUF_RESERVE_PERCENT
					/ BUF_MAX_PERCENT;

		if (tc_num)
			hi_thrd = hi_thrd / tc_num;

		hi_thrd = max_t(uint32_t, hi_thrd,
				HNS3_BUF_MUL_BY * aligned_mps);
		hi_thrd = rounddown(hi_thrd, HNS3_BUF_SIZE_UNIT);
		lo_thrd = hi_thrd - aligned_mps / HNS3_BUF_DIV_BY;
	} else {
		hi_thrd = aligned_mps + HNS3_NON_DCB_ADDITIONAL_BUF;
		lo_thrd = aligned_mps;
	}

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		buf_alloc->s_buf.tc_thrd[i].low = lo_thrd;
		buf_alloc->s_buf.tc_thrd[i].high = hi_thrd;
	}

	return true;
}

static bool
hns3_rx_buf_calc_all(struct hns3_hw *hw, bool max,
		     struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_priv_buf *priv;
	uint32_t aligned_mps;
	uint32_t rx_all;
	uint8_t i;

	rx_all = pf->pkt_buf_size - hns3_get_tx_buff_alloced(buf_alloc);
	aligned_mps = roundup(pf->mps, HNS3_BUF_SIZE_UNIT);

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];

		priv->enable = 0;
		priv->wl.low = 0;
		priv->wl.high = 0;
		priv->buf_size = 0;

		if (!(hw->hw_tc_map & BIT(i)))
			continue;

		priv->enable = 1;
		if (hw->dcb_info.hw_pfc_map & BIT(i)) {
			priv->wl.low = max ? aligned_mps : HNS3_BUF_SIZE_UNIT;
			priv->wl.high = roundup(priv->wl.low + aligned_mps,
						HNS3_BUF_SIZE_UNIT);
		} else {
			priv->wl.low = 0;
			priv->wl.high = max ? (aligned_mps * HNS3_BUF_MUL_BY) :
					aligned_mps;
		}

		priv->buf_size = priv->wl.high + pf->dv_buf_size;
	}

	return hns3_is_rx_buf_ok(hw, buf_alloc, rx_all);
}

static bool
hns3_drop_nopfc_buf_till_fit(struct hns3_hw *hw,
			     struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_priv_buf *priv;
	int no_pfc_priv_num;
	uint32_t rx_all;
	uint8_t mask;
	int i;

	rx_all = pf->pkt_buf_size - hns3_get_tx_buff_alloced(buf_alloc);
	no_pfc_priv_num = hns3_get_no_pfc_priv_num(hw, buf_alloc);

	/* let the last to be cleared first */
	for (i = HNS3_MAX_TC_NUM - 1; i >= 0; i--) {
		priv = &buf_alloc->priv_buf[i];
		mask = BIT((uint8_t)i);

		if (hw->hw_tc_map & mask &&
		    !(hw->dcb_info.hw_pfc_map & mask)) {
			/* Clear the no pfc TC private buffer */
			priv->wl.low = 0;
			priv->wl.high = 0;
			priv->buf_size = 0;
			priv->enable = 0;
			no_pfc_priv_num--;
		}

		if (hns3_is_rx_buf_ok(hw, buf_alloc, rx_all) ||
		    no_pfc_priv_num == 0)
			break;
	}

	return hns3_is_rx_buf_ok(hw, buf_alloc, rx_all);
}

static bool
hns3_drop_pfc_buf_till_fit(struct hns3_hw *hw,
			   struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	struct hns3_priv_buf *priv;
	uint32_t rx_all;
	int pfc_priv_num;
	uint8_t mask;
	int i;

	rx_all = pf->pkt_buf_size - hns3_get_tx_buff_alloced(buf_alloc);
	pfc_priv_num = hns3_get_pfc_priv_num(hw, buf_alloc);

	/* let the last to be cleared first */
	for (i = HNS3_MAX_TC_NUM - 1; i >= 0; i--) {
		priv = &buf_alloc->priv_buf[i];
		mask = BIT((uint8_t)i);

		if (hw->hw_tc_map & mask &&
		    hw->dcb_info.hw_pfc_map & mask) {
			/* Reduce the number of pfc TC with private buffer */
			priv->wl.low = 0;
			priv->enable = 0;
			priv->wl.high = 0;
			priv->buf_size = 0;
			pfc_priv_num--;
		}
		if (hns3_is_rx_buf_ok(hw, buf_alloc, rx_all) ||
		    pfc_priv_num == 0)
			break;
	}

	return hns3_is_rx_buf_ok(hw, buf_alloc, rx_all);
}

static bool
hns3_only_alloc_priv_buff(struct hns3_hw *hw,
			  struct hns3_pkt_buf_alloc *buf_alloc)
{
#define COMPENSATE_BUFFER	0x3C00
#define COMPENSATE_HALF_MPS_NUM	5
#define PRIV_WL_GAP		0x1800
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_pf *pf = &hns->pf;
	uint32_t tc_num = hns3_get_tc_num(hw);
	uint32_t half_mps = pf->mps >> 1;
	struct hns3_priv_buf *priv;
	uint32_t min_rx_priv;
	uint32_t rx_priv;
	uint8_t i;

	rx_priv = pf->pkt_buf_size - hns3_get_tx_buff_alloced(buf_alloc);
	if (tc_num)
		rx_priv = rx_priv / tc_num;

	if (tc_num <= NEED_RESERVE_TC_NUM)
		rx_priv = rx_priv * BUF_RESERVE_PERCENT / BUF_MAX_PERCENT;

	/*
	 * Minimum value of private buffer in rx direction (min_rx_priv) is
	 * equal to "DV + 2.5 * MPS + 15KB". Driver only allocates rx private
	 * buffer if rx_priv is greater than min_rx_priv.
	 */
	min_rx_priv = pf->dv_buf_size + COMPENSATE_BUFFER +
			COMPENSATE_HALF_MPS_NUM * half_mps;
	min_rx_priv = roundup(min_rx_priv, HNS3_BUF_SIZE_UNIT);
	rx_priv = rounddown(rx_priv, HNS3_BUF_SIZE_UNIT);

	if (rx_priv < min_rx_priv)
		return false;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		priv = &buf_alloc->priv_buf[i];

		priv->enable = 0;
		priv->wl.low = 0;
		priv->wl.high = 0;
		priv->buf_size = 0;

		if (!(hw->hw_tc_map & BIT(i)))
			continue;

		priv->enable = 1;
		priv->buf_size = rx_priv;
		priv->wl.high = rx_priv - pf->dv_buf_size;
		priv->wl.low = priv->wl.high - PRIV_WL_GAP;
	}

	buf_alloc->s_buf.buf_size = 0;

	return true;
}

/*
 * hns3_rx_buffer_calc: calculate the rx private buffer size for all TCs
 * @hw: pointer to struct hns3_hw
 * @buf_alloc: pointer to buffer calculation data
 * @return: 0: calculate sucessful, negative: fail
 */
static int
hns3_rx_buffer_calc(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
	/* When DCB is not supported, rx private buffer is not allocated. */
	if (!hns3_dev_dcb_supported(hw)) {
		struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
		struct hns3_pf *pf = &hns->pf;
		uint32_t rx_all = pf->pkt_buf_size;

		rx_all -= hns3_get_tx_buff_alloced(buf_alloc);
		if (!hns3_is_rx_buf_ok(hw, buf_alloc, rx_all))
			return -ENOMEM;

		return 0;
	}

	/*
	 * Try to allocate privated packet buffer for all TCs without share
	 * buffer.
	 */
	if (hns3_only_alloc_priv_buff(hw, buf_alloc))
		return 0;

	/*
	 * Try to allocate privated packet buffer for all TCs with share
	 * buffer.
	 */
	if (hns3_rx_buf_calc_all(hw, true, buf_alloc))
		return 0;

	/*
	 * For different application scenes, the enabled port number, TC number
	 * and no_drop TC number are different. In order to obtain the better
	 * performance, software could allocate the buffer size and configure
	 * the waterline by tring to decrease the private buffer size according
	 * to the order, namely, waterline of valided tc, pfc disabled tc, pfc
	 * enabled tc.
	 */
	if (hns3_rx_buf_calc_all(hw, false, buf_alloc))
		return 0;

	if (hns3_drop_nopfc_buf_till_fit(hw, buf_alloc))
		return 0;

	if (hns3_drop_pfc_buf_till_fit(hw, buf_alloc))
		return 0;

	return -ENOMEM;
}

static int
hns3_rx_priv_buf_alloc(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_rx_priv_buff_cmd *req;
	struct hns3_cmd_desc desc;
	uint32_t buf_size;
	int ret;
	int i;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RX_PRIV_BUFF_ALLOC, false);
	req = (struct hns3_rx_priv_buff_cmd *)desc.data;

	/* Alloc private buffer TCs */
	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		struct hns3_priv_buf *priv = &buf_alloc->priv_buf[i];

		req->buf_num[i] =
			rte_cpu_to_le_16(priv->buf_size >> HNS3_BUF_UNIT_S);
		req->buf_num[i] |= rte_cpu_to_le_16(1 << HNS3_TC0_PRI_BUF_EN_B);
	}

	buf_size = buf_alloc->s_buf.buf_size;
	req->shared_buf = rte_cpu_to_le_16((buf_size >> HNS3_BUF_UNIT_S) |
					   (1 << HNS3_TC0_PRI_BUF_EN_B));

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "rx private buffer alloc cmd failed %d", ret);

	return ret;
}

static int
hns3_rx_priv_wl_config(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
#define HNS3_RX_PRIV_WL_ALLOC_DESC_NUM 2
	struct hns3_rx_priv_wl_buf *req;
	struct hns3_priv_buf *priv;
	struct hns3_cmd_desc desc[HNS3_RX_PRIV_WL_ALLOC_DESC_NUM];
	int i, j;
	int ret;

	for (i = 0; i < HNS3_RX_PRIV_WL_ALLOC_DESC_NUM; i++) {
		hns3_cmd_setup_basic_desc(&desc[i], HNS3_OPC_RX_PRIV_WL_ALLOC,
					  false);
		req = (struct hns3_rx_priv_wl_buf *)desc[i].data;

		/* The first descriptor set the NEXT bit to 1 */
		if (i == 0)
			desc[i].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);

		for (j = 0; j < HNS3_TC_NUM_ONE_DESC; j++) {
			uint32_t idx = i * HNS3_TC_NUM_ONE_DESC + j;

			priv = &buf_alloc->priv_buf[idx];
			req->tc_wl[j].high = rte_cpu_to_le_16(priv->wl.high >>
							HNS3_BUF_UNIT_S);
			req->tc_wl[j].high |=
				rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));
			req->tc_wl[j].low = rte_cpu_to_le_16(priv->wl.low >>
							HNS3_BUF_UNIT_S);
			req->tc_wl[j].low |=
				rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));
		}
	}

	/* Send 2 descriptor at one time */
	ret = hns3_cmd_send(hw, desc, HNS3_RX_PRIV_WL_ALLOC_DESC_NUM);
	if (ret)
		PMD_INIT_LOG(ERR, "rx private waterline config cmd failed %d",
			     ret);
	return ret;
}

static int
hns3_common_thrd_config(struct hns3_hw *hw,
			struct hns3_pkt_buf_alloc *buf_alloc)
{
#define HNS3_RX_COM_THRD_ALLOC_DESC_NUM 2
	struct hns3_shared_buf *s_buf = &buf_alloc->s_buf;
	struct hns3_rx_com_thrd *req;
	struct hns3_cmd_desc desc[HNS3_RX_COM_THRD_ALLOC_DESC_NUM];
	struct hns3_tc_thrd *tc;
	int tc_idx;
	int i, j;
	int ret;

	for (i = 0; i < HNS3_RX_COM_THRD_ALLOC_DESC_NUM; i++) {
		hns3_cmd_setup_basic_desc(&desc[i], HNS3_OPC_RX_COM_THRD_ALLOC,
					  false);
		req = (struct hns3_rx_com_thrd *)&desc[i].data;

		/* The first descriptor set the NEXT bit to 1 */
		if (i == 0)
			desc[i].flag |= rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);
		else
			desc[i].flag &= ~rte_cpu_to_le_16(HNS3_CMD_FLAG_NEXT);

		for (j = 0; j < HNS3_TC_NUM_ONE_DESC; j++) {
			tc_idx = i * HNS3_TC_NUM_ONE_DESC + j;
			tc = &s_buf->tc_thrd[tc_idx];

			req->com_thrd[j].high =
				rte_cpu_to_le_16(tc->high >> HNS3_BUF_UNIT_S);
			req->com_thrd[j].high |=
				 rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));
			req->com_thrd[j].low =
				rte_cpu_to_le_16(tc->low >> HNS3_BUF_UNIT_S);
			req->com_thrd[j].low |=
				 rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));
		}
	}

	/* Send 2 descriptors at one time */
	ret = hns3_cmd_send(hw, desc, HNS3_RX_COM_THRD_ALLOC_DESC_NUM);
	if (ret)
		PMD_INIT_LOG(ERR, "common threshold config cmd failed %d", ret);

	return ret;
}

static int
hns3_common_wl_config(struct hns3_hw *hw, struct hns3_pkt_buf_alloc *buf_alloc)
{
	struct hns3_shared_buf *buf = &buf_alloc->s_buf;
	struct hns3_rx_com_wl *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RX_COM_WL_ALLOC, false);

	req = (struct hns3_rx_com_wl *)desc.data;
	req->com_wl.high = rte_cpu_to_le_16(buf->self.high >> HNS3_BUF_UNIT_S);
	req->com_wl.high |= rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));

	req->com_wl.low = rte_cpu_to_le_16(buf->self.low >> HNS3_BUF_UNIT_S);
	req->com_wl.low |= rte_cpu_to_le_16(BIT(HNS3_RX_PRIV_EN_B));

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "common waterline config cmd failed %d", ret);

	return ret;
}

int
hns3_buffer_alloc(struct hns3_hw *hw)
{
	struct hns3_pkt_buf_alloc pkt_buf;
	int ret;

	memset(&pkt_buf, 0, sizeof(pkt_buf));
	ret = hns3_tx_buffer_calc(hw, &pkt_buf);
	if (ret) {
		PMD_INIT_LOG(ERR,
			     "could not calc tx buffer size for all TCs %d",
			     ret);
		return ret;
	}

	ret = hns3_tx_buffer_alloc(hw, &pkt_buf);
	if (ret) {
		PMD_INIT_LOG(ERR, "could not alloc tx buffers %d", ret);
		return ret;
	}

	ret = hns3_rx_buffer_calc(hw, &pkt_buf);
	if (ret) {
		PMD_INIT_LOG(ERR,
			     "could not calc rx priv buffer size for all TCs %d",
			     ret);
		return ret;
	}

	ret = hns3_rx_priv_buf_alloc(hw, &pkt_buf);
	if (ret) {
		PMD_INIT_LOG(ERR, "could not alloc rx priv buffer %d", ret);
		return ret;
	}

	if (hns3_dev_dcb_supported(hw)) {
		ret = hns3_rx_priv_wl_config(hw, &pkt_buf);
		if (ret) {
			PMD_INIT_LOG(ERR,
				     "could not configure rx private waterline %d",
				     ret);
			return ret;
		}

		ret = hns3_common_thrd_config(hw, &pkt_buf);
		if (ret) {
			PMD_INIT_LOG(ERR,
				     "could not configure common threshold %d",
				     ret);
			return ret;
		}
	}

	ret = hns3_common_wl_config(hw, &pkt_buf);
	if (ret)
		PMD_INIT_LOG(ERR, "could not configure common waterline %d",
			     ret);

	return ret;
}

static int
hns3_mac_init(struct hns3_hw *hw)
{
	struct hns3_adapter *hns = HNS3_DEV_HW_TO_ADAPTER(hw);
	struct hns3_mac *mac = &hw->mac;
	struct hns3_pf *pf = &hns->pf;
	int ret;

	pf->support_sfp_query = true;
	mac->link_duplex = ETH_LINK_FULL_DUPLEX;
	ret = hns3_cfg_mac_speed_dup_hw(hw, mac->link_speed, mac->link_duplex);
	if (ret) {
		PMD_INIT_LOG(ERR, "Config mac speed dup fail ret = %d", ret);
		return ret;
	}

	mac->link_status = ETH_LINK_DOWN;

	return hns3_config_mtu(hw, pf->mps);
}

static int
hns3_get_mac_ethertype_cmd_status(uint16_t cmdq_resp, uint8_t resp_code)
{
#define HNS3_ETHERTYPE_SUCCESS_ADD		0
#define HNS3_ETHERTYPE_ALREADY_ADD		1
#define HNS3_ETHERTYPE_MGR_TBL_OVERFLOW		2
#define HNS3_ETHERTYPE_KEY_CONFLICT		3
	int return_status;

	if (cmdq_resp) {
		PMD_INIT_LOG(ERR,
			     "cmdq execute failed for get_mac_ethertype_cmd_status, status=%d.\n",
			     cmdq_resp);
		return -EIO;
	}

	switch (resp_code) {
	case HNS3_ETHERTYPE_SUCCESS_ADD:
	case HNS3_ETHERTYPE_ALREADY_ADD:
		return_status = 0;
		break;
	case HNS3_ETHERTYPE_MGR_TBL_OVERFLOW:
		PMD_INIT_LOG(ERR,
			     "add mac ethertype failed for manager table overflow.");
		return_status = -EIO;
		break;
	case HNS3_ETHERTYPE_KEY_CONFLICT:
		PMD_INIT_LOG(ERR, "add mac ethertype failed for key conflict.");
		return_status = -EIO;
		break;
	default:
		PMD_INIT_LOG(ERR,
			     "add mac ethertype failed for undefined, code=%d.",
			     resp_code);
		return_status = -EIO;
	}

	return return_status;
}

static int
hns3_add_mgr_tbl(struct hns3_hw *hw,
		 const struct hns3_mac_mgr_tbl_entry_cmd *req)
{
	struct hns3_cmd_desc desc;
	uint8_t resp_code;
	uint16_t retval;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MAC_ETHTYPE_ADD, false);
	memcpy(desc.data, req, sizeof(struct hns3_mac_mgr_tbl_entry_cmd));

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		PMD_INIT_LOG(ERR,
			     "add mac ethertype failed for cmd_send, ret =%d.",
			     ret);
		return ret;
	}

	resp_code = (rte_le_to_cpu_32(desc.data[0]) >> 8) & 0xff;
	retval = rte_le_to_cpu_16(desc.retval);

	return hns3_get_mac_ethertype_cmd_status(retval, resp_code);
}

static void
hns3_prepare_mgr_tbl(struct hns3_mac_mgr_tbl_entry_cmd *mgr_table,
		     int *table_item_num)
{
	struct hns3_mac_mgr_tbl_entry_cmd *tbl;

	/*
	 * In current version, we add one item in management table as below:
	 * 0x0180C200000E -- LLDP MC address
	 */
	tbl = mgr_table;
	tbl->flags = HNS3_MAC_MGR_MASK_VLAN_B;
	tbl->ethter_type = rte_cpu_to_le_16(HNS3_MAC_ETHERTYPE_LLDP);
	tbl->mac_addr_hi32 = rte_cpu_to_le_32(htonl(0x0180C200));
	tbl->mac_addr_lo16 = rte_cpu_to_le_16(htons(0x000E));
	tbl->i_port_bitmap = 0x1;
	*table_item_num = 1;
}

static int
hns3_init_mgr_tbl(struct hns3_hw *hw)
{
#define HNS_MAC_MGR_TBL_MAX_SIZE	16
	struct hns3_mac_mgr_tbl_entry_cmd mgr_table[HNS_MAC_MGR_TBL_MAX_SIZE];
	int table_item_num;
	int ret;
	int i;

	memset(mgr_table, 0, sizeof(mgr_table));
	hns3_prepare_mgr_tbl(mgr_table, &table_item_num);
	for (i = 0; i < table_item_num; i++) {
		ret = hns3_add_mgr_tbl(hw, &mgr_table[i]);
		if (ret) {
			PMD_INIT_LOG(ERR, "add mac ethertype failed, ret =%d",
				     ret);
			return ret;
		}
	}

	return 0;
}

static void
hns3_promisc_param_init(struct hns3_promisc_param *param, bool en_uc,
			bool en_mc, bool en_bc, int vport_id)
{
	if (!param)
		return;

	memset(param, 0, sizeof(struct hns3_promisc_param));
	if (en_uc)
		param->enable = HNS3_PROMISC_EN_UC;
	if (en_mc)
		param->enable |= HNS3_PROMISC_EN_MC;
	if (en_bc)
		param->enable |= HNS3_PROMISC_EN_BC;
	param->vf_id = vport_id;
}

static int
hns3_cmd_set_promisc_mode(struct hns3_hw *hw, struct hns3_promisc_param *param)
{
	struct hns3_promisc_cfg_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CFG_PROMISC_MODE, false);

	req = (struct hns3_promisc_cfg_cmd *)desc.data;
	req->vf_id = param->vf_id;
	req->flag = (param->enable << HNS3_PROMISC_EN_B) |
	    HNS3_PROMISC_TX_EN_B | HNS3_PROMISC_RX_EN_B;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "Set promisc mode fail, status is %d", ret);

	return ret;
}

static int
hns3_set_promisc_mode(struct hns3_hw *hw, bool en_uc_pmc, bool en_mc_pmc)
{
	struct hns3_promisc_param param;
	bool en_bc_pmc = true;
	uint8_t vf_id;
	int ret;

	/*
	 * In current version VF is not supported when PF is driven by DPDK
	 * driver, the PF-related vf_id is 0, just need to configure parameters
	 * for vf_id 0.
	 */
	vf_id = 0;

	hns3_promisc_param_init(&param, en_uc_pmc, en_mc_pmc, en_bc_pmc, vf_id);
	ret = hns3_cmd_set_promisc_mode(hw, &param);
	if (ret)
		return ret;

	return 0;
}

static int
hns3_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	bool en_mc_pmc = (dev->data->all_multicast == 1) ? true : false;
	int ret = 0;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_set_promisc_mode(hw, true, en_mc_pmc);
	rte_spinlock_unlock(&hw->lock);
	if (ret)
		hns3_err(hw, "Failed to enable promiscuous mode: %d", ret);

	return ret;
}

static int
hns3_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	bool en_mc_pmc = (dev->data->all_multicast == 1) ? true : false;
	int ret = 0;

	/* If now in all_multicast mode, must remain in all_multicast mode. */
	rte_spinlock_lock(&hw->lock);
	ret = hns3_set_promisc_mode(hw, false, en_mc_pmc);
	rte_spinlock_unlock(&hw->lock);
	if (ret)
		hns3_err(hw, "Failed to disable promiscuous mode: %d", ret);

	return ret;
}

static int
hns3_dev_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	bool en_uc_pmc = (dev->data->promiscuous == 1) ? true : false;
	int ret = 0;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_set_promisc_mode(hw, en_uc_pmc, true);
	rte_spinlock_unlock(&hw->lock);
	if (ret)
		hns3_err(hw, "Failed to enable allmulticast mode: %d", ret);

	return ret;
}

static int
hns3_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	bool en_uc_pmc = (dev->data->promiscuous == 1) ? true : false;
	int ret = 0;

	/* If now in promiscuous mode, must remain in all_multicast mode. */
	if (dev->data->promiscuous == 1)
		return 0;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_set_promisc_mode(hw, en_uc_pmc, false);
	rte_spinlock_unlock(&hw->lock);
	if (ret)
		hns3_err(hw, "Failed to disable allmulticast mode: %d", ret);

	return ret;
}

static int
hns3_dev_promisc_restore(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	bool en_mc_pmc;
	bool en_uc_pmc;

	en_uc_pmc = (hw->data->promiscuous == 1) ? true : false;
	en_mc_pmc = (hw->data->all_multicast == 1) ? true : false;

	return hns3_set_promisc_mode(hw, en_uc_pmc, en_mc_pmc);
}

static int
hns3_get_sfp_speed(struct hns3_hw *hw, uint32_t *speed)
{
	struct hns3_sfp_speed_cmd *resp;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_SFP_GET_SPEED, true);
	resp = (struct hns3_sfp_speed_cmd *)desc.data;
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret == -EOPNOTSUPP) {
		hns3_err(hw, "IMP do not support get SFP speed %d", ret);
		return ret;
	} else if (ret) {
		hns3_err(hw, "get sfp speed failed %d", ret);
		return ret;
	}

	*speed = resp->sfp_speed;

	return 0;
}

static uint8_t
hns3_check_speed_dup(uint8_t duplex, uint32_t speed)
{
	if (!(speed == ETH_SPEED_NUM_10M || speed == ETH_SPEED_NUM_100M))
		duplex = ETH_LINK_FULL_DUPLEX;

	return duplex;
}

static int
hns3_cfg_mac_speed_dup(struct hns3_hw *hw, uint32_t speed, uint8_t duplex)
{
	struct hns3_mac *mac = &hw->mac;
	int ret;

	duplex = hns3_check_speed_dup(duplex, speed);
	if (mac->link_speed == speed && mac->link_duplex == duplex)
		return 0;

	ret = hns3_cfg_mac_speed_dup_hw(hw, speed, duplex);
	if (ret)
		return ret;

	mac->link_speed = speed;
	mac->link_duplex = duplex;

	return 0;
}

static int
hns3_update_speed_duplex(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_pf *pf = &hns->pf;
	uint32_t speed;
	int ret;

	/* If IMP do not support get SFP/qSFP speed, return directly */
	if (!pf->support_sfp_query)
		return 0;

	ret = hns3_get_sfp_speed(hw, &speed);
	if (ret == -EOPNOTSUPP) {
		pf->support_sfp_query = false;
		return ret;
	} else if (ret)
		return ret;

	if (speed == ETH_SPEED_NUM_NONE)
		return 0; /* do nothing if no SFP */

	/* Config full duplex for SFP */
	return hns3_cfg_mac_speed_dup(hw, speed, ETH_LINK_FULL_DUPLEX);
}

static int
hns3_cfg_mac_mode(struct hns3_hw *hw, bool enable)
{
	struct hns3_config_mac_mode_cmd *req;
	struct hns3_cmd_desc desc;
	uint32_t loop_en = 0;
	uint8_t val = 0;
	int ret;

	req = (struct hns3_config_mac_mode_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CONFIG_MAC_MODE, false);
	if (enable)
		val = 1;
	hns3_set_bit(loop_en, HNS3_MAC_TX_EN_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_RX_EN_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_PAD_TX_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_PAD_RX_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_1588_TX_B, 0);
	hns3_set_bit(loop_en, HNS3_MAC_1588_RX_B, 0);
	hns3_set_bit(loop_en, HNS3_MAC_APP_LP_B, 0);
	hns3_set_bit(loop_en, HNS3_MAC_LINE_LP_B, 0);
	hns3_set_bit(loop_en, HNS3_MAC_FCS_TX_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_RX_FCS_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_RX_FCS_STRIP_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_TX_OVERSIZE_TRUNCATE_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_RX_OVERSIZE_TRUNCATE_B, val);
	hns3_set_bit(loop_en, HNS3_MAC_TX_UNDER_MIN_ERR_B, val);
	req->txrx_pad_fcs_loop_en = rte_cpu_to_le_32(loop_en);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		PMD_INIT_LOG(ERR, "mac enable fail, ret =%d.", ret);

	return ret;
}

static int
hns3_get_mac_link_status(struct hns3_hw *hw)
{
	struct hns3_link_status_cmd *req;
	struct hns3_cmd_desc desc;
	int link_status;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_LINK_STATUS, true);
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "get link status cmd failed %d", ret);
		return ret;
	}

	req = (struct hns3_link_status_cmd *)desc.data;
	link_status = req->status & HNS3_LINK_STATUS_UP_M;

	return !!link_status;
}

static void
hns3_update_link_status(struct hns3_hw *hw)
{
	int state;

	state = hns3_get_mac_link_status(hw);
	if (state != hw->mac.link_status)
		hw->mac.link_status = state;
}

static void
hns3_service_handler(void *param)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)param;
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	if (!hns3_is_reset_pending(hns)) {
		hns3_update_speed_duplex(eth_dev);
		hns3_update_link_status(hw);
	} else
		hns3_warn(hw, "Cancel the query when reset is pending");

	rte_eal_alarm_set(HNS3_SERVICE_INTERVAL, hns3_service_handler, eth_dev);
}

static int
hns3_init_hardware(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_map_tqp(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to map tqp: %d", ret);
		return ret;
	}

	ret = hns3_init_umv_space(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init umv space: %d", ret);
		return ret;
	}

	ret = hns3_mac_init(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init MAC: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_init_mgr_tbl(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init manager table: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_set_promisc_mode(hw, false, false);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to set promisc mode: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_init_vlan_config(hns);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vlan: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_dcb_init(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init dcb: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_init_fd_config(hns);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init flow director: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_config_tso(hw, HNS3_TSO_MSS_MIN, HNS3_TSO_MSS_MAX);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to config tso: %d", ret);
		goto err_mac_init;
	}

	ret = hns3_config_gro(hw, false);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to config gro: %d", ret);
		goto err_mac_init;
	}
	return 0;

err_mac_init:
	hns3_uninit_umv_space(hw);
	return ret;
}

static int
hns3_init_pf(struct rte_eth_dev *eth_dev)
{
	struct rte_device *dev = eth_dev->device;
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev);
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* Get hardware io base address from pcie BAR2 IO space */
	hw->io_base = pci_dev->mem_resource[2].addr;

	/* Firmware command queue initialize */
	ret = hns3_cmd_init_queue(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init cmd queue: %d", ret);
		goto err_cmd_init_queue;
	}

	hns3_clear_all_event_cause(hw);

	/* Firmware command initialize */
	ret = hns3_cmd_init(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init cmd: %d", ret);
		goto err_cmd_init;
	}

	ret = rte_intr_callback_register(&pci_dev->intr_handle,
					 hns3_interrupt_handler,
					 eth_dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to register intr: %d", ret);
		goto err_intr_callback_register;
	}

	/* Enable interrupt */
	rte_intr_enable(&pci_dev->intr_handle);
	hns3_pf_enable_irq0(hw);

	/* Get configuration */
	ret = hns3_get_configuration(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to fetch configuration: %d", ret);
		goto err_get_config;
	}

	ret = hns3_init_hardware(hns);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init hardware: %d", ret);
		goto err_get_config;
	}

	/* Initialize flow director filter list & hash */
	ret = hns3_fdir_filter_init(hns);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to alloc hashmap for fdir: %d", ret);
		goto err_hw_init;
	}

	hns3_set_default_rss_args(hw);

	ret = hns3_enable_hw_error_intr(hns, true);
	if (ret) {
		PMD_INIT_LOG(ERR, "fail to enable hw error interrupts: %d",
			     ret);
		goto err_fdir;
	}

	return 0;

err_fdir:
	hns3_fdir_filter_uninit(hns);
err_hw_init:
	hns3_uninit_umv_space(hw);

err_get_config:
	hns3_pf_disable_irq0(hw);
	rte_intr_disable(&pci_dev->intr_handle);
	hns3_intr_unregister(&pci_dev->intr_handle, hns3_interrupt_handler,
			     eth_dev);

err_intr_callback_register:
	hns3_cmd_uninit(hw);

err_cmd_init:
	hns3_cmd_destroy_queue(hw);

err_cmd_init_queue:
	hw->io_base = NULL;

	return ret;
}

static void
hns3_uninit_pf(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct rte_device *dev = eth_dev->device;
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev);
	struct hns3_hw *hw = &hns->hw;

	PMD_INIT_FUNC_TRACE();

	hns3_enable_hw_error_intr(hns, false);
	hns3_rss_uninit(hns);
	hns3_fdir_filter_uninit(hns);
	hns3_uninit_umv_space(hw);
	hns3_pf_disable_irq0(hw);
	rte_intr_disable(&pci_dev->intr_handle);
	hns3_intr_unregister(&pci_dev->intr_handle, hns3_interrupt_handler,
			     eth_dev);
	hns3_cmd_uninit(hw);
	hns3_cmd_destroy_queue(hw);
	hw->io_base = NULL;
}

static int
hns3_do_start(struct hns3_adapter *hns, bool reset_queue)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_dcb_cfg_update(hns);
	if (ret)
		return ret;

	/* Enable queues */
	ret = hns3_start_queues(hns, reset_queue);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to start queues: %d", ret);
		return ret;
	}

	/* Enable MAC */
	ret = hns3_cfg_mac_mode(hw, true);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to enable MAC: %d", ret);
		goto err_config_mac_mode;
	}
	return 0;

err_config_mac_mode:
	hns3_stop_queues(hns, true);
	return ret;
}

static int
hns3_dev_start(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	PMD_INIT_FUNC_TRACE();
	if (rte_atomic16_read(&hw->reset.resetting))
		return -EBUSY;
	rte_spinlock_lock(&hw->lock);
	hw->adapter_state = HNS3_NIC_STARTING;

	ret = hns3_do_start(hns, true);
	if (ret) {
		hw->adapter_state = HNS3_NIC_CONFIGURED;
		rte_spinlock_unlock(&hw->lock);
		return ret;
	}

	hw->adapter_state = HNS3_NIC_STARTED;
	rte_spinlock_unlock(&hw->lock);
	hns3_set_rxtx_function(eth_dev);
	hns3_mp_req_start_rxtx(eth_dev);

	hns3_info(hw, "hns3 dev start successful!");
	return 0;
}

static int
hns3_do_stop(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	bool reset_queue;
	int ret;

	ret = hns3_cfg_mac_mode(hw, false);
	if (ret)
		return ret;
	hw->mac.link_status = ETH_LINK_DOWN;

	if (rte_atomic16_read(&hw->reset.disable_cmd) == 0) {
		hns3_configure_all_mac_addr(hns, true);
		reset_queue = true;
	} else
		reset_queue = false;
	hw->mac.default_addr_setted = false;
	return hns3_stop_queues(hns, reset_queue);
}

static void
hns3_dev_stop(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	PMD_INIT_FUNC_TRACE();

	hw->adapter_state = HNS3_NIC_STOPPING;
	hns3_set_rxtx_function(eth_dev);
	rte_wmb();
	/* Disable datapath on secondary process. */
	hns3_mp_req_stop_rxtx(eth_dev);
	/* Prevent crashes when queues are still in use. */
	rte_delay_ms(hw->tqps_num);

	rte_spinlock_lock(&hw->lock);
	if (rte_atomic16_read(&hw->reset.resetting) == 0) {
		hns3_do_stop(hns);
		hns3_dev_release_mbufs(hns);
		hw->adapter_state = HNS3_NIC_CONFIGURED;
	}
	rte_spinlock_unlock(&hw->lock);
}

static void
hns3_dev_close(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		rte_free(eth_dev->process_private);
		eth_dev->process_private = NULL;
		return;
	}

	if (hw->adapter_state == HNS3_NIC_STARTED)
		hns3_dev_stop(eth_dev);

	hw->adapter_state = HNS3_NIC_CLOSING;
	hns3_reset_abort(hns);
	hw->adapter_state = HNS3_NIC_CLOSED;
	rte_eal_alarm_cancel(hns3_service_handler, eth_dev);

	hns3_configure_all_mc_mac_addr(hns, true);
	hns3_remove_all_vlan_table(hns);
	hns3_vlan_txvlan_cfg(hns, HNS3_PORT_BASE_VLAN_DISABLE, 0);
	hns3_uninit_pf(eth_dev);
	hns3_free_all_queues(eth_dev);
	rte_free(hw->reset.wait_data);
	rte_free(eth_dev->process_private);
	eth_dev->process_private = NULL;
	hns3_mp_uninit_primary();
	hns3_warn(hw, "Close port %d finished", hw->data->port_id);
}

static int
hns3_flow_ctrl_get(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_pf *pf = HNS3_DEV_PRIVATE_TO_PF(dev->data->dev_private);

	fc_conf->pause_time = pf->pause_time;

	/* return fc current mode */
	switch (hw->current_mode) {
	case HNS3_FC_FULL:
		fc_conf->mode = RTE_FC_FULL;
		break;
	case HNS3_FC_TX_PAUSE:
		fc_conf->mode = RTE_FC_TX_PAUSE;
		break;
	case HNS3_FC_RX_PAUSE:
		fc_conf->mode = RTE_FC_RX_PAUSE;
		break;
	case HNS3_FC_NONE:
	default:
		fc_conf->mode = RTE_FC_NONE;
		break;
	}

	return 0;
}

static void
hns3_get_fc_mode(struct hns3_hw *hw, enum rte_eth_fc_mode mode)
{
	switch (mode) {
	case RTE_FC_NONE:
		hw->requested_mode = HNS3_FC_NONE;
		break;
	case RTE_FC_RX_PAUSE:
		hw->requested_mode = HNS3_FC_RX_PAUSE;
		break;
	case RTE_FC_TX_PAUSE:
		hw->requested_mode = HNS3_FC_TX_PAUSE;
		break;
	case RTE_FC_FULL:
		hw->requested_mode = HNS3_FC_FULL;
		break;
	default:
		hw->requested_mode = HNS3_FC_NONE;
		hns3_warn(hw, "fc_mode(%u) exceeds member scope and is "
			  "configured to RTE_FC_NONE", mode);
		break;
	}
}

static int
hns3_flow_ctrl_set(struct rte_eth_dev *dev, struct rte_eth_fc_conf *fc_conf)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_pf *pf = HNS3_DEV_PRIVATE_TO_PF(dev->data->dev_private);
	int ret;

	if (fc_conf->high_water || fc_conf->low_water ||
	    fc_conf->send_xon || fc_conf->mac_ctrl_frame_fwd) {
		hns3_err(hw, "Unsupported flow control settings specified, "
			 "high_water(%u), low_water(%u), send_xon(%u) and "
			 "mac_ctrl_frame_fwd(%u) must be set to '0'",
			 fc_conf->high_water, fc_conf->low_water,
			 fc_conf->send_xon, fc_conf->mac_ctrl_frame_fwd);
		return -EINVAL;
	}
	if (fc_conf->autoneg) {
		hns3_err(hw, "Unsupported fc auto-negotiation setting.");
		return -EINVAL;
	}
	if (!fc_conf->pause_time) {
		hns3_err(hw, "Invalid pause time %d setting.",
			 fc_conf->pause_time);
		return -EINVAL;
	}

	if (!(hw->current_fc_status == HNS3_FC_STATUS_NONE ||
	    hw->current_fc_status == HNS3_FC_STATUS_MAC_PAUSE)) {
		hns3_err(hw, "PFC is enabled. Cannot set MAC pause. "
			 "current_fc_status = %d", hw->current_fc_status);
		return -EOPNOTSUPP;
	}

	hns3_get_fc_mode(hw, fc_conf->mode);
	if (hw->requested_mode == hw->current_mode &&
	    pf->pause_time == fc_conf->pause_time)
		return 0;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_fc_enable(dev, fc_conf);
	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3_priority_flow_ctrl_set(struct rte_eth_dev *dev,
			    struct rte_eth_pfc_conf *pfc_conf)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_pf *pf = HNS3_DEV_PRIVATE_TO_PF(dev->data->dev_private);
	uint8_t priority;
	int ret;

	if (!hns3_dev_dcb_supported(hw)) {
		hns3_err(hw, "This port does not support dcb configurations.");
		return -EOPNOTSUPP;
	}

	if (pfc_conf->fc.high_water || pfc_conf->fc.low_water ||
	    pfc_conf->fc.send_xon || pfc_conf->fc.mac_ctrl_frame_fwd) {
		hns3_err(hw, "Unsupported flow control settings specified, "
			 "high_water(%u), low_water(%u), send_xon(%u) and "
			 "mac_ctrl_frame_fwd(%u) must be set to '0'",
			 pfc_conf->fc.high_water, pfc_conf->fc.low_water,
			 pfc_conf->fc.send_xon,
			 pfc_conf->fc.mac_ctrl_frame_fwd);
		return -EINVAL;
	}
	if (pfc_conf->fc.autoneg) {
		hns3_err(hw, "Unsupported fc auto-negotiation setting.");
		return -EINVAL;
	}
	if (pfc_conf->fc.pause_time == 0) {
		hns3_err(hw, "Invalid pause time %d setting.",
			 pfc_conf->fc.pause_time);
		return -EINVAL;
	}

	if (!(hw->current_fc_status == HNS3_FC_STATUS_NONE ||
	    hw->current_fc_status == HNS3_FC_STATUS_PFC)) {
		hns3_err(hw, "MAC pause is enabled. Cannot set PFC."
			     "current_fc_status = %d", hw->current_fc_status);
		return -EOPNOTSUPP;
	}

	priority = pfc_conf->priority;
	hns3_get_fc_mode(hw, pfc_conf->fc.mode);
	if (hw->dcb_info.pfc_en & BIT(priority) &&
	    hw->requested_mode == hw->current_mode &&
	    pfc_conf->fc.pause_time == pf->pause_time)
		return 0;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_dcb_pfc_enable(dev, pfc_conf);
	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3_get_dcb_info(struct rte_eth_dev *dev, struct rte_eth_dcb_info *dcb_info)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct hns3_pf *pf = HNS3_DEV_PRIVATE_TO_PF(dev->data->dev_private);
	enum rte_eth_rx_mq_mode mq_mode = dev->data->dev_conf.rxmode.mq_mode;
	int i;

	rte_spinlock_lock(&hw->lock);
	if ((uint32_t)mq_mode & ETH_MQ_RX_DCB_FLAG)
		dcb_info->nb_tcs = pf->local_max_tc;
	else
		dcb_info->nb_tcs = 1;

	for (i = 0; i < HNS3_MAX_USER_PRIO; i++)
		dcb_info->prio_tc[i] = hw->dcb_info.prio_tc[i];
	for (i = 0; i < dcb_info->nb_tcs; i++)
		dcb_info->tc_bws[i] = hw->dcb_info.pg_info[0].tc_dwrr[i];

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		dcb_info->tc_queue.tc_rxq[0][i].base =
					hw->tc_queue[i].tqp_offset;
		dcb_info->tc_queue.tc_txq[0][i].base =
					hw->tc_queue[i].tqp_offset;
		dcb_info->tc_queue.tc_rxq[0][i].nb_queue =
					hw->tc_queue[i].tqp_count;
		dcb_info->tc_queue.tc_txq[0][i].nb_queue =
					hw->tc_queue[i].tqp_count;
	}
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3_reinit_dev(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_cmd_init(hw);
	if (ret) {
		hns3_err(hw, "Failed to init cmd: %d", ret);
		return ret;
	}

	ret = hns3_reset_all_queues(hns);
	if (ret) {
		hns3_err(hw, "Failed to reset all queues: %d", ret);
		goto err_init;
	}

	ret = hns3_init_hardware(hns);
	if (ret) {
		hns3_err(hw, "Failed to init hardware: %d", ret);
		goto err_init;
	}

	ret = hns3_enable_hw_error_intr(hns, true);
	if (ret) {
		hns3_err(hw, "fail to enable hw error interrupts: %d",
			     ret);
		goto err_mac_init;
	}
	hns3_info(hw, "Reset done, driver initialization finished.");

	return 0;

err_mac_init:
	hns3_uninit_umv_space(hw);
err_init:
	hns3_cmd_uninit(hw);

	return ret;
}

static bool
is_pf_reset_done(struct hns3_hw *hw)
{
	uint32_t val, reg, reg_bit;

	switch (hw->reset.level) {
	case HNS3_IMP_RESET:
		reg = HNS3_GLOBAL_RESET_REG;
		reg_bit = HNS3_IMP_RESET_BIT;
		break;
	case HNS3_GLOBAL_RESET:
		reg = HNS3_GLOBAL_RESET_REG;
		reg_bit = HNS3_GLOBAL_RESET_BIT;
		break;
	case HNS3_FUNC_RESET:
		reg = HNS3_FUN_RST_ING;
		reg_bit = HNS3_FUN_RST_ING_B;
		break;
	case HNS3_FLR_RESET:
	default:
		hns3_err(hw, "Wait for unsupported reset level: %d",
			 hw->reset.level);
		return true;
	}
	val = hns3_read_dev(hw, reg);
	if (hns3_get_bit(val, reg_bit))
		return false;
	else
		return true;
}

bool
hns3_is_reset_pending(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	enum hns3_reset_level reset;

	hns3_check_event_cause(hns, NULL);
	reset = hns3_get_reset_level(hns, &hw->reset.pending);
	if (hw->reset.level != HNS3_NONE_RESET && hw->reset.level < reset) {
		hns3_warn(hw, "High level reset %d is pending", reset);
		return true;
	}
	reset = hns3_get_reset_level(hns, &hw->reset.request);
	if (hw->reset.level != HNS3_NONE_RESET && hw->reset.level < reset) {
		hns3_warn(hw, "High level reset %d is request", reset);
		return true;
	}
	return false;
}

static int
hns3_wait_hardware_ready(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_wait_data *wait_data = hw->reset.wait_data;
	struct timeval tv;

	if (wait_data->result == HNS3_WAIT_SUCCESS)
		return 0;
	else if (wait_data->result == HNS3_WAIT_TIMEOUT) {
		gettimeofday(&tv, NULL);
		hns3_warn(hw, "Reset step4 hardware not ready after reset time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		return -ETIME;
	} else if (wait_data->result == HNS3_WAIT_REQUEST)
		return -EAGAIN;

	wait_data->hns = hns;
	wait_data->check_completion = is_pf_reset_done;
	wait_data->end_ms = (uint64_t)HNS3_RESET_WAIT_CNT *
				      HNS3_RESET_WAIT_MS + get_timeofday_ms();
	wait_data->interval = HNS3_RESET_WAIT_MS * USEC_PER_MSEC;
	wait_data->count = HNS3_RESET_WAIT_CNT;
	wait_data->result = HNS3_WAIT_REQUEST;
	rte_eal_alarm_set(wait_data->interval, hns3_wait_callback, wait_data);
	return -EAGAIN;
}

static int
hns3_func_reset_cmd(struct hns3_hw *hw, int func_id)
{
	struct hns3_cmd_desc desc;
	struct hns3_reset_cmd *req = (struct hns3_reset_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CFG_RST_TRIGGER, false);
	hns3_set_bit(req->mac_func_reset, HNS3_CFG_RESET_FUNC_B, 1);
	req->fun_reset_vfid = func_id;

	return hns3_cmd_send(hw, &desc, 1);
}

static int
hns3_imp_reset_cmd(struct hns3_hw *hw)
{
	struct hns3_cmd_desc desc;

	hns3_cmd_setup_basic_desc(&desc, 0xFFFE, false);
	desc.data[0] = 0xeedd;

	return hns3_cmd_send(hw, &desc, 1);
}

static void
hns3_msix_process(struct hns3_adapter *hns, enum hns3_reset_level reset_level)
{
	struct hns3_hw *hw = &hns->hw;
	struct timeval tv;
	uint32_t val;

	gettimeofday(&tv, NULL);
	if (hns3_read_dev(hw, HNS3_GLOBAL_RESET_REG) ||
	    hns3_read_dev(hw, HNS3_FUN_RST_ING)) {
		hns3_warn(hw, "Don't process msix during resetting time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		return;
	}

	switch (reset_level) {
	case HNS3_IMP_RESET:
		hns3_imp_reset_cmd(hw);
		hns3_warn(hw, "IMP Reset requested time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		break;
	case HNS3_GLOBAL_RESET:
		val = hns3_read_dev(hw, HNS3_GLOBAL_RESET_REG);
		hns3_set_bit(val, HNS3_GLOBAL_RESET_BIT, 1);
		hns3_write_dev(hw, HNS3_GLOBAL_RESET_REG, val);
		hns3_warn(hw, "Global Reset requested time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		break;
	case HNS3_FUNC_RESET:
		hns3_warn(hw, "PF Reset requested time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		/* schedule again to check later */
		hns3_atomic_set_bit(HNS3_FUNC_RESET, &hw->reset.pending);
		hns3_schedule_reset(hns);
		break;
	default:
		hns3_warn(hw, "Unsupported reset level: %d", reset_level);
		return;
	}
	hns3_atomic_clear_bit(reset_level, &hw->reset.request);
}

static enum hns3_reset_level
hns3_get_reset_level(struct hns3_adapter *hns, uint64_t *levels)
{
	struct hns3_hw *hw = &hns->hw;
	enum hns3_reset_level reset_level = HNS3_NONE_RESET;

	/* Return the highest priority reset level amongst all */
	if (hns3_atomic_test_bit(HNS3_IMP_RESET, levels))
		reset_level = HNS3_IMP_RESET;
	else if (hns3_atomic_test_bit(HNS3_GLOBAL_RESET, levels))
		reset_level = HNS3_GLOBAL_RESET;
	else if (hns3_atomic_test_bit(HNS3_FUNC_RESET, levels))
		reset_level = HNS3_FUNC_RESET;
	else if (hns3_atomic_test_bit(HNS3_FLR_RESET, levels))
		reset_level = HNS3_FLR_RESET;

	if (hw->reset.level != HNS3_NONE_RESET && reset_level < hw->reset.level)
		return HNS3_NONE_RESET;

	return reset_level;
}

static int
hns3_prepare_reset(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	uint32_t reg_val;
	int ret;

	switch (hw->reset.level) {
	case HNS3_FUNC_RESET:
		ret = hns3_func_reset_cmd(hw, 0);
		if (ret)
			return ret;

		/*
		 * After performaning pf reset, it is not necessary to do the
		 * mailbox handling or send any command to firmware, because
		 * any mailbox handling or command to firmware is only valid
		 * after hns3_cmd_init is called.
		 */
		rte_atomic16_set(&hw->reset.disable_cmd, 1);
		hw->reset.stats.request_cnt++;
		break;
	case HNS3_IMP_RESET:
		reg_val = hns3_read_dev(hw, HNS3_VECTOR0_OTER_EN_REG);
		hns3_write_dev(hw, HNS3_VECTOR0_OTER_EN_REG, reg_val |
			       BIT(HNS3_VECTOR0_IMP_RESET_INT_B));
		break;
	default:
		break;
	}
	return 0;
}

static int
hns3_set_rst_done(struct hns3_hw *hw)
{
	struct hns3_pf_rst_done_cmd *req;
	struct hns3_cmd_desc desc;

	req = (struct hns3_pf_rst_done_cmd *)desc.data;
	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_PF_RST_DONE, false);
	req->pf_rst_done |= HNS3_PF_RESET_DONE_BIT;
	return hns3_cmd_send(hw, &desc, 1);
}

static int
hns3_stop_service(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_dev *eth_dev;

	eth_dev = &rte_eth_devices[hw->data->port_id];
	rte_eal_alarm_cancel(hns3_service_handler, eth_dev);
	hw->mac.link_status = ETH_LINK_DOWN;

	hns3_set_rxtx_function(eth_dev);
	rte_wmb();
	/* Disable datapath on secondary process. */
	hns3_mp_req_stop_rxtx(eth_dev);
	rte_delay_ms(hw->tqps_num);

	rte_spinlock_lock(&hw->lock);
	if (hns->hw.adapter_state == HNS3_NIC_STARTED ||
	    hw->adapter_state == HNS3_NIC_STOPPING) {
		hns3_do_stop(hns);
		hw->reset.mbuf_deferred_free = true;
	} else
		hw->reset.mbuf_deferred_free = false;

	/*
	 * It is cumbersome for hardware to pick-and-choose entries for deletion
	 * from table space. Hence, for function reset software intervention is
	 * required to delete the entries
	 */
	if (rte_atomic16_read(&hw->reset.disable_cmd) == 0)
		hns3_configure_all_mc_mac_addr(hns, true);
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3_start_service(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_dev *eth_dev;

	if (hw->reset.level == HNS3_IMP_RESET ||
	    hw->reset.level == HNS3_GLOBAL_RESET)
		hns3_set_rst_done(hw);
	eth_dev = &rte_eth_devices[hw->data->port_id];
	hns3_set_rxtx_function(eth_dev);
	hns3_mp_req_start_rxtx(eth_dev);
	hns3_service_handler(eth_dev);
	return 0;
}

static int
hns3_restore_conf(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_configure_all_mac_addr(hns, false);
	if (ret)
		return ret;

	ret = hns3_configure_all_mc_mac_addr(hns, false);
	if (ret)
		goto err_mc_mac;

	ret = hns3_dev_promisc_restore(hns);
	if (ret)
		goto err_promisc;

	ret = hns3_restore_vlan_table(hns);
	if (ret)
		goto err_promisc;

	ret = hns3_restore_vlan_conf(hns);
	if (ret)
		goto err_promisc;

	ret = hns3_restore_all_fdir_filter(hns);
	if (ret)
		goto err_promisc;

	if (hns->hw.adapter_state == HNS3_NIC_STARTED) {
		ret = hns3_do_start(hns, false);
		if (ret)
			goto err_promisc;
		hns3_info(hw, "hns3 dev restart successful!");
	} else if (hw->adapter_state == HNS3_NIC_STOPPING)
		hw->adapter_state = HNS3_NIC_CONFIGURED;
	return 0;

err_promisc:
	hns3_configure_all_mc_mac_addr(hns, true);
err_mc_mac:
	hns3_configure_all_mac_addr(hns, true);
	return ret;
}

static void
hns3_reset_service(void *param)
{
	struct hns3_adapter *hns = (struct hns3_adapter *)param;
	struct hns3_hw *hw = &hns->hw;
	enum hns3_reset_level reset_level;
	struct timeval tv_delta;
	struct timeval tv_start;
	struct timeval tv;
	uint64_t msec;
	int ret;

	/*
	 * The interrupt is not triggered within the delay time.
	 * The interrupt may have been lost. It is necessary to handle
	 * the interrupt to recover from the error.
	 */
	if (rte_atomic16_read(&hns->hw.reset.schedule) == SCHEDULE_DEFERRED) {
		rte_atomic16_set(&hns->hw.reset.schedule, SCHEDULE_REQUESTED);
		hns3_err(hw, "Handling interrupts in delayed tasks");
		hns3_interrupt_handler(&rte_eth_devices[hw->data->port_id]);
		reset_level = hns3_get_reset_level(hns, &hw->reset.pending);
		if (reset_level == HNS3_NONE_RESET) {
			hns3_err(hw, "No reset level is set, try IMP reset");
			hns3_atomic_set_bit(HNS3_IMP_RESET, &hw->reset.pending);
		}
	}
	rte_atomic16_set(&hns->hw.reset.schedule, SCHEDULE_NONE);

	/*
	 * Check if there is any ongoing reset in the hardware. This status can
	 * be checked from reset_pending. If there is then, we need to wait for
	 * hardware to complete reset.
	 *    a. If we are able to figure out in reasonable time that hardware
	 *       has fully resetted then, we can proceed with driver, client
	 *       reset.
	 *    b. else, we can come back later to check this status so re-sched
	 *       now.
	 */
	reset_level = hns3_get_reset_level(hns, &hw->reset.pending);
	if (reset_level != HNS3_NONE_RESET) {
		gettimeofday(&tv_start, NULL);
		ret = hns3_reset_process(hns, reset_level);
		gettimeofday(&tv, NULL);
		timersub(&tv, &tv_start, &tv_delta);
		msec = tv_delta.tv_sec * MSEC_PER_SEC +
		       tv_delta.tv_usec / USEC_PER_MSEC;
		if (msec > HNS3_RESET_PROCESS_MS)
			hns3_err(hw, "%d handle long time delta %" PRIx64
				     " ms time=%ld.%.6ld",
				 hw->reset.level, msec,
				 tv.tv_sec, tv.tv_usec);
		if (ret == -EAGAIN)
			return;
	}

	/* Check if we got any *new* reset requests to be honored */
	reset_level = hns3_get_reset_level(hns, &hw->reset.request);
	if (reset_level != HNS3_NONE_RESET)
		hns3_msix_process(hns, reset_level);
}

static const struct eth_dev_ops hns3_eth_dev_ops = {
	.dev_start          = hns3_dev_start,
	.dev_stop           = hns3_dev_stop,
	.dev_close          = hns3_dev_close,
	.promiscuous_enable = hns3_dev_promiscuous_enable,
	.promiscuous_disable = hns3_dev_promiscuous_disable,
	.allmulticast_enable  = hns3_dev_allmulticast_enable,
	.allmulticast_disable = hns3_dev_allmulticast_disable,
	.mtu_set            = hns3_dev_mtu_set,
	.stats_get          = hns3_stats_get,
	.stats_reset        = hns3_stats_reset,
	.xstats_get         = hns3_dev_xstats_get,
	.xstats_get_names   = hns3_dev_xstats_get_names,
	.xstats_reset       = hns3_dev_xstats_reset,
	.xstats_get_by_id   = hns3_dev_xstats_get_by_id,
	.xstats_get_names_by_id = hns3_dev_xstats_get_names_by_id,
	.dev_infos_get          = hns3_dev_infos_get,
	.fw_version_get         = hns3_fw_version_get,
	.rx_queue_setup         = hns3_rx_queue_setup,
	.tx_queue_setup         = hns3_tx_queue_setup,
	.rx_queue_release       = hns3_dev_rx_queue_release,
	.tx_queue_release       = hns3_dev_tx_queue_release,
	.dev_configure          = hns3_dev_configure,
	.flow_ctrl_get          = hns3_flow_ctrl_get,
	.flow_ctrl_set          = hns3_flow_ctrl_set,
	.priority_flow_ctrl_set = hns3_priority_flow_ctrl_set,
	.mac_addr_add           = hns3_add_mac_addr,
	.mac_addr_remove        = hns3_remove_mac_addr,
	.mac_addr_set           = hns3_set_default_mac_addr,
	.set_mc_addr_list       = hns3_set_mc_mac_addr_list,
	.link_update            = hns3_dev_link_update,
	.rss_hash_update        = hns3_dev_rss_hash_update,
	.rss_hash_conf_get      = hns3_dev_rss_hash_conf_get,
	.reta_update            = hns3_dev_rss_reta_update,
	.reta_query             = hns3_dev_rss_reta_query,
	.filter_ctrl            = hns3_dev_filter_ctrl,
	.vlan_filter_set        = hns3_vlan_filter_set,
	.vlan_tpid_set          = hns3_vlan_tpid_set,
	.vlan_offload_set       = hns3_vlan_offload_set,
	.vlan_pvid_set          = hns3_vlan_pvid_set,
	.get_reg                = hns3_get_regs,
	.get_dcb_info           = hns3_get_dcb_info,
	.dev_supported_ptypes_get = hns3_dev_supported_ptypes_get,
};

static const struct hns3_reset_ops hns3_reset_ops = {
	.reset_service       = hns3_reset_service,
	.stop_service        = hns3_stop_service,
	.prepare_reset       = hns3_prepare_reset,
	.wait_hardware_ready = hns3_wait_hardware_ready,
	.reinit_dev          = hns3_reinit_dev,
	.restore_conf	     = hns3_restore_conf,
	.start_service       = hns3_start_service,
};

static int
hns3_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_device *dev = eth_dev->device;
	struct rte_pci_device *pci_dev = RTE_DEV_TO_PCI(dev);
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	uint16_t device_id = pci_dev->id.device_id;
	int ret;

	PMD_INIT_FUNC_TRACE();
	eth_dev->process_private = (struct hns3_process_private *)
	    rte_zmalloc_socket("hns3_filter_list",
			       sizeof(struct hns3_process_private),
			       RTE_CACHE_LINE_SIZE, eth_dev->device->numa_node);
	if (eth_dev->process_private == NULL) {
		PMD_INIT_LOG(ERR, "Failed to alloc memory for process private");
		return -ENOMEM;
	}
	/* initialize flow filter lists */
	hns3_filterlist_init(eth_dev);

	hns3_set_rxtx_function(eth_dev);
	eth_dev->dev_ops = &hns3_eth_dev_ops;
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		hns3_mp_init_secondary();
		hw->secondary_cnt++;
		return 0;
	}

	hns3_mp_init_primary();
	hw->adapter_state = HNS3_NIC_UNINITIALIZED;

	if (device_id == HNS3_DEV_ID_25GE_RDMA ||
	    device_id == HNS3_DEV_ID_50GE_RDMA ||
	    device_id == HNS3_DEV_ID_100G_RDMA_MACSEC)
		hns3_set_bit(hw->flag, HNS3_DEV_SUPPORT_DCB_B, 1);

	hns->is_vf = false;
	hw->data = eth_dev->data;

	/*
	 * Set default max packet size according to the mtu
	 * default vale in DPDK frame.
	 */
	hns->pf.mps = hw->data->mtu + HNS3_ETH_OVERHEAD;

	ret = hns3_reset_init(hw);
	if (ret)
		goto err_init_reset;
	hw->reset.ops = &hns3_reset_ops;

	ret = hns3_init_pf(eth_dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init pf: %d", ret);
		goto err_init_pf;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("hns3-mac",
					       sizeof(struct rte_ether_addr) *
					       HNS3_UC_MACADDR_NUM, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %zx bytes needed "
			     "to store MAC addresses",
			     sizeof(struct rte_ether_addr) *
			     HNS3_UC_MACADDR_NUM);
		ret = -ENOMEM;
		goto err_rte_zmalloc;
	}

	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.mac_addr,
			    &eth_dev->data->mac_addrs[0]);

	hw->adapter_state = HNS3_NIC_INITIALIZED;
	/*
	 * Pass the information to the rte_eth_dev_close() that it should also
	 * release the private port resources.
	 */
	eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;

	if (rte_atomic16_read(&hns->hw.reset.schedule) == SCHEDULE_PENDING) {
		hns3_err(hw, "Reschedule reset service after dev_init");
		hns3_schedule_reset(hns);
	} else {
		/* IMP will wait ready flag before reset */
		hns3_notify_reset_ready(hw, false);
	}

	rte_eal_alarm_set(HNS3_SERVICE_INTERVAL, hns3_service_handler, eth_dev);
	hns3_info(hw, "hns3 dev initialization successful!");
	return 0;

err_rte_zmalloc:
	hns3_uninit_pf(eth_dev);

err_init_pf:
	rte_free(hw->reset.wait_data);
err_init_reset:
	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;
	eth_dev->tx_pkt_prepare = NULL;
	rte_free(eth_dev->process_private);
	eth_dev->process_private = NULL;
	return ret;
}

static int
hns3_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;
	eth_dev->tx_pkt_prepare = NULL;
	if (hw->adapter_state < HNS3_NIC_CLOSING)
		hns3_dev_close(eth_dev);

	hw->adapter_state = HNS3_NIC_REMOVED;
	return 0;
}

static int
eth_hns3_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct hns3_adapter),
					     hns3_dev_init);
}

static int
eth_hns3_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, hns3_dev_uninit);
}

static const struct rte_pci_id pci_id_hns3_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_GE) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_25GE) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_25GE_RDMA) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_50GE_RDMA) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_100G_RDMA_MACSEC) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver rte_hns3_pmd = {
	.id_table = pci_id_hns3_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_hns3_pci_probe,
	.remove = eth_hns3_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_hns3, rte_hns3_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_hns3, pci_id_hns3_map);
RTE_PMD_REGISTER_KMOD_DEP(net_hns3, "* igb_uio | vfio-pci");

RTE_INIT(hns3_init_log)
{
	hns3_logtype_init = rte_log_register("pmd.net.hns3.init");
	if (hns3_logtype_init >= 0)
		rte_log_set_level(hns3_logtype_init, RTE_LOG_NOTICE);
	hns3_logtype_driver = rte_log_register("pmd.net.hns3.driver");
	if (hns3_logtype_driver >= 0)
		rte_log_set_level(hns3_logtype_driver, RTE_LOG_NOTICE);
}
