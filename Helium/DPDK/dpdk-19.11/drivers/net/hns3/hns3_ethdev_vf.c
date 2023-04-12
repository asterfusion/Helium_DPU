/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/pci_regs.h>

#include <rte_alarm.h>
#include <rte_atomic.h>
#include <rte_bus_pci.h>
#include <rte_byteorder.h>
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
#include <rte_vfio.h>

#include "hns3_ethdev.h"
#include "hns3_logs.h"
#include "hns3_rxtx.h"
#include "hns3_regs.h"
#include "hns3_intr.h"
#include "hns3_dcb.h"
#include "hns3_mp.h"

#define HNS3VF_KEEP_ALIVE_INTERVAL	2000000 /* us */
#define HNS3VF_SERVICE_INTERVAL		1000000 /* us */

#define HNS3VF_RESET_WAIT_MS	20
#define HNS3VF_RESET_WAIT_CNT	2000

/* Reset related Registers */
#define HNS3_GLOBAL_RESET_BIT		0
#define HNS3_CORE_RESET_BIT		1
#define HNS3_IMP_RESET_BIT		2
#define HNS3_FUN_RST_ING_B		0

enum hns3vf_evt_cause {
	HNS3VF_VECTOR0_EVENT_RST,
	HNS3VF_VECTOR0_EVENT_MBX,
	HNS3VF_VECTOR0_EVENT_OTHER,
};

static enum hns3_reset_level hns3vf_get_reset_level(struct hns3_hw *hw,
						    uint64_t *levels);
static int hns3vf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
static int hns3vf_dev_configure_vlan(struct rte_eth_dev *dev);

/* set PCI bus mastering */
static void
hns3vf_set_bus_master(const struct rte_pci_device *device, bool op)
{
	uint16_t reg;

	rte_pci_read_config(device, &reg, sizeof(reg), PCI_COMMAND);

	if (op)
		/* set the master bit */
		reg |= PCI_COMMAND_MASTER;
	else
		reg &= ~(PCI_COMMAND_MASTER);

	rte_pci_write_config(device, &reg, sizeof(reg), PCI_COMMAND);
}

/**
 * hns3vf_find_pci_capability - lookup a capability in the PCI capability list
 * @cap: the capability
 *
 * Return the address of the given capability within the PCI capability list.
 */
static int
hns3vf_find_pci_capability(const struct rte_pci_device *device, int cap)
{
#define MAX_PCIE_CAPABILITY 48
	uint16_t status;
	uint8_t pos;
	uint8_t id;
	int ttl;

	rte_pci_read_config(device, &status, sizeof(status), PCI_STATUS);
	if (!(status & PCI_STATUS_CAP_LIST))
		return 0;

	ttl = MAX_PCIE_CAPABILITY;
	rte_pci_read_config(device, &pos, sizeof(pos), PCI_CAPABILITY_LIST);
	while (ttl-- && pos >= PCI_STD_HEADER_SIZEOF) {
		rte_pci_read_config(device, &id, sizeof(id),
				    (pos + PCI_CAP_LIST_ID));

		if (id == 0xFF)
			break;

		if (id == cap)
			return (int)pos;

		rte_pci_read_config(device, &pos, sizeof(pos),
				    (pos + PCI_CAP_LIST_NEXT));
	}
	return 0;
}

static int
hns3vf_enable_msix(const struct rte_pci_device *device, bool op)
{
	uint16_t control;
	int pos;

	pos = hns3vf_find_pci_capability(device, PCI_CAP_ID_MSIX);
	if (pos) {
		rte_pci_read_config(device, &control, sizeof(control),
				    (pos + PCI_MSIX_FLAGS));
		if (op)
			control |= PCI_MSIX_FLAGS_ENABLE;
		else
			control &= ~PCI_MSIX_FLAGS_ENABLE;
		rte_pci_write_config(device, &control, sizeof(control),
				     (pos + PCI_MSIX_FLAGS));
		return 0;
	}
	return -1;
}

static int
hns3vf_add_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr,
		    __attribute__ ((unused)) uint32_t idx,
		    __attribute__ ((unused)) uint32_t pool)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_UNICAST,
				HNS3_MBX_MAC_VLAN_UC_ADD, mac_addr->addr_bytes,
				RTE_ETHER_ADDR_LEN, false, NULL, 0);
	rte_spinlock_unlock(&hw->lock);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to add mac addr(%s) for vf: %d", mac_str,
			 ret);
	}

	return ret;
}

static void
hns3vf_remove_mac_addr(struct rte_eth_dev *dev, uint32_t idx)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	/* index will be checked by upper level rte interface */
	struct rte_ether_addr *mac_addr = &dev->data->mac_addrs[idx];
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_UNICAST,
				HNS3_MBX_MAC_VLAN_UC_REMOVE,
				mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN, false,
				NULL, 0);
	rte_spinlock_unlock(&hw->lock);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to remove mac addr(%s) for vf: %d",
			 mac_str, ret);
	}
}

static int
hns3vf_set_default_mac_addr(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mac_addr)
{
#define HNS3_TWO_ETHER_ADDR_LEN (RTE_ETHER_ADDR_LEN * 2)
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_ether_addr *old_addr;
	uint8_t addr_bytes[HNS3_TWO_ETHER_ADDR_LEN]; /* for 2 MAC addresses */
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret;

	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to set mac addr, addr(%s) invalid.",
			 mac_str);
		return -EINVAL;
	}

	old_addr = (struct rte_ether_addr *)hw->mac.mac_addr;
	rte_spinlock_lock(&hw->lock);
	memcpy(addr_bytes, mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN);
	memcpy(&addr_bytes[RTE_ETHER_ADDR_LEN], old_addr->addr_bytes,
	       RTE_ETHER_ADDR_LEN);

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_UNICAST,
				HNS3_MBX_MAC_VLAN_UC_MODIFY, addr_bytes,
				HNS3_TWO_ETHER_ADDR_LEN, false, NULL, 0);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to set mac addr(%s) for vf: %d", mac_str,
			 ret);
	}

	rte_ether_addr_copy(mac_addr,
			    (struct rte_ether_addr *)hw->mac.mac_addr);
	rte_spinlock_unlock(&hw->lock);

	return ret;
}

static int
hns3vf_configure_mac_addr(struct hns3_adapter *hns, bool del)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_ether_addr *addr;
	enum hns3_mbx_mac_vlan_subcode opcode;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int ret = 0;
	int i;

	if (del)
		opcode = HNS3_MBX_MAC_VLAN_UC_REMOVE;
	else
		opcode = HNS3_MBX_MAC_VLAN_UC_ADD;
	for (i = 0; i < HNS3_VF_UC_MACADDR_NUM; i++) {
		addr = &hw->data->mac_addrs[i];
		if (!rte_is_valid_assigned_ether_addr(addr))
			continue;
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, addr);
		hns3_dbg(hw, "rm mac addr: %s", mac_str);
		ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_UNICAST, opcode,
					addr->addr_bytes, RTE_ETHER_ADDR_LEN,
					false, NULL, 0);
		if (ret) {
			hns3_err(hw, "Failed to remove mac addr for vf: %d",
				 ret);
			break;
		}
	}
	return ret;
}

static int
hns3vf_add_mc_mac_addr(struct hns3_adapter *hns,
		       struct rte_ether_addr *mac_addr)
{
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_MULTICAST,
				HNS3_MBX_MAC_VLAN_MC_ADD,
				mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN, false,
				NULL, 0);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to add mc mac addr(%s) for vf: %d",
			 mac_str, ret);
		return ret;
	}

	return 0;
}

static int
hns3vf_remove_mc_mac_addr(struct hns3_adapter *hns,
			  struct rte_ether_addr *mac_addr)
{
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_MULTICAST,
				HNS3_MBX_MAC_VLAN_MC_REMOVE,
				mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN, false,
				NULL, 0);
	if (ret) {
		rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
				      mac_addr);
		hns3_err(hw, "Failed to remove mc mac addr(%s) for vf: %d",
			 mac_str, ret);
		return ret;
	}

	return 0;
}

static int
hns3vf_set_mc_mac_addr_list(struct rte_eth_dev *dev,
			    struct rte_ether_addr *mc_addr_set,
			    uint32_t nb_mc_addr)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct rte_ether_addr *addr;
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
	int cur_addr_num;
	int set_addr_num;
	int num;
	int ret;
	int i;

	if (nb_mc_addr > HNS3_MC_MACADDR_NUM) {
		hns3_err(hw, "Failed to set mc mac addr, nb_mc_addr(%d) "
			 "invalid. valid range: 0~%d",
			 nb_mc_addr, HNS3_MC_MACADDR_NUM);
		return -EINVAL;
	}

	set_addr_num = (int)nb_mc_addr;
	for (i = 0; i < set_addr_num; i++) {
		addr = &mc_addr_set[i];
		if (!rte_is_multicast_ether_addr(addr)) {
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      addr);
			hns3_err(hw,
				 "Failed to set mc mac addr, addr(%s) invalid.",
				 mac_str);
			return -EINVAL;
		}
	}
	rte_spinlock_lock(&hw->lock);
	cur_addr_num = hw->mc_addrs_num;
	for (i = 0; i < cur_addr_num; i++) {
		num = cur_addr_num - i - 1;
		addr = &hw->mc_addrs[num];
		ret = hns3vf_remove_mc_mac_addr(hns, addr);
		if (ret) {
			rte_spinlock_unlock(&hw->lock);
			return ret;
		}

		hw->mc_addrs_num--;
	}

	for (i = 0; i < set_addr_num; i++) {
		addr = &mc_addr_set[i];
		ret = hns3vf_add_mc_mac_addr(hns, addr);
		if (ret) {
			rte_spinlock_unlock(&hw->lock);
			return ret;
		}

		rte_ether_addr_copy(addr, &hw->mc_addrs[hw->mc_addrs_num]);
		hw->mc_addrs_num++;
	}
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3vf_configure_all_mc_mac_addr(struct hns3_adapter *hns, bool del)
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
			ret = hns3vf_remove_mc_mac_addr(hns, addr);
		else
			ret = hns3vf_add_mc_mac_addr(hns, addr);
		if (ret) {
			err = ret;
			rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE,
					      addr);
			hns3_err(hw, "Failed to %s mc mac addr: %s for vf: %d",
				 del ? "Remove" : "Restore", mac_str, ret);
		}
	}
	return err;
}

static int
hns3vf_set_promisc_mode(struct hns3_hw *hw, bool en_bc_pmc)
{
	struct hns3_mbx_vf_to_pf_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	req = (struct hns3_mbx_vf_to_pf_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_MBX_VF_TO_PF, false);
	req->msg[0] = HNS3_MBX_SET_PROMISC_MODE;
	req->msg[1] = en_bc_pmc ? 1 : 0;

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Set promisc mode fail, status is %d", ret);

	return ret;
}

static int
hns3vf_dev_configure(struct rte_eth_dev *dev)
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
		ret = hns3vf_dev_mtu_set(dev, mtu);
		if (ret)
			goto cfg_err;
		dev->data->mtu = mtu;
	}

	ret = hns3vf_dev_configure_vlan(dev);
	if (ret)
		goto cfg_err;

	hw->adapter_state = HNS3_NIC_CONFIGURED;
	return 0;

cfg_err:
	hw->adapter_state = HNS3_NIC_INITIALIZED;
	return ret;
}

static int
hns3vf_config_mtu(struct hns3_hw *hw, uint16_t mtu)
{
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_MTU, 0, (const uint8_t *)&mtu,
				sizeof(mtu), true, NULL, 0);
	if (ret)
		hns3_err(hw, "Failed to set mtu (%u) for vf: %d", mtu, ret);

	return ret;
}

static int
hns3vf_dev_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	uint32_t frame_size = mtu + HNS3_ETH_OVERHEAD;
	int ret;

	if (dev->data->dev_started) {
		hns3_err(hw, "Failed to set mtu, port %u must be stopped "
			 "before configuration", dev->data->port_id);
		return -EBUSY;
	}

	if (rte_atomic16_read(&hw->reset.resetting)) {
		hns3_err(hw, "Failed to set mtu during resetting");
		return -EIO;
	}

	rte_spinlock_lock(&hw->lock);
	ret = hns3vf_config_mtu(hw, mtu);
	if (ret) {
		rte_spinlock_unlock(&hw->lock);
		return ret;
	}
	if (frame_size > RTE_ETHER_MAX_LEN)
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
hns3vf_dev_infos_get(struct rte_eth_dev *eth_dev, struct rte_eth_dev_info *info)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	info->max_rx_queues = hw->tqps_num;
	info->max_tx_queues = hw->tqps_num;
	info->max_rx_pktlen = HNS3_MAX_FRAME_LEN; /* CRC included */
	info->min_rx_bufsize = hw->rx_buf_len;
	info->max_mac_addrs = HNS3_VF_UC_MACADDR_NUM;
	info->max_mtu = info->max_rx_pktlen - HNS3_ETH_OVERHEAD;

	info->rx_offload_capa = (DEV_RX_OFFLOAD_IPV4_CKSUM |
				 DEV_RX_OFFLOAD_UDP_CKSUM |
				 DEV_RX_OFFLOAD_TCP_CKSUM |
				 DEV_RX_OFFLOAD_SCTP_CKSUM |
				 DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM |
				 DEV_RX_OFFLOAD_OUTER_UDP_CKSUM |
				 DEV_RX_OFFLOAD_KEEP_CRC |
				 DEV_RX_OFFLOAD_SCATTER |
				 DEV_RX_OFFLOAD_VLAN_STRIP |
				 DEV_RX_OFFLOAD_QINQ_STRIP |
				 DEV_RX_OFFLOAD_VLAN_FILTER |
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
	info->default_rxportconf.ring_size = HNS3_DEFAULT_RING_DESC;
	info->default_txportconf.ring_size = HNS3_DEFAULT_RING_DESC;

	return 0;
}

static void
hns3vf_clear_event_cause(struct hns3_hw *hw, uint32_t regclr)
{
	hns3_write_dev(hw, HNS3_VECTOR0_CMDQ_SRC_REG, regclr);
}

static void
hns3vf_disable_irq0(struct hns3_hw *hw)
{
	hns3_write_dev(hw, HNS3_MISC_VECTOR_REG_BASE, 0);
}

static void
hns3vf_enable_irq0(struct hns3_hw *hw)
{
	hns3_write_dev(hw, HNS3_MISC_VECTOR_REG_BASE, 1);
}

static enum hns3vf_evt_cause
hns3vf_check_event_cause(struct hns3_adapter *hns, uint32_t *clearval)
{
	struct hns3_hw *hw = &hns->hw;
	enum hns3vf_evt_cause ret;
	uint32_t cmdq_stat_reg;
	uint32_t rst_ing_reg;
	uint32_t val;

	/* Fetch the events from their corresponding regs */
	cmdq_stat_reg = hns3_read_dev(hw, HNS3_VECTOR0_CMDQ_STAT_REG);

	if (BIT(HNS3_VECTOR0_RST_INT_B) & cmdq_stat_reg) {
		rst_ing_reg = hns3_read_dev(hw, HNS3_FUN_RST_ING);
		hns3_warn(hw, "resetting reg: 0x%x", rst_ing_reg);
		hns3_atomic_set_bit(HNS3_VF_RESET, &hw->reset.pending);
		rte_atomic16_set(&hw->reset.disable_cmd, 1);
		val = hns3_read_dev(hw, HNS3_VF_RST_ING);
		hns3_write_dev(hw, HNS3_VF_RST_ING, val | HNS3_VF_RST_ING_BIT);
		val = cmdq_stat_reg & ~BIT(HNS3_VECTOR0_RST_INT_B);
		if (clearval) {
			hw->reset.stats.global_cnt++;
			hns3_warn(hw, "Global reset detected, clear reset status");
		} else {
			hns3_schedule_delayed_reset(hns);
			hns3_warn(hw, "Global reset detected, don't clear reset status");
		}

		ret = HNS3VF_VECTOR0_EVENT_RST;
		goto out;
	}

	/* Check for vector0 mailbox(=CMDQ RX) event source */
	if (BIT(HNS3_VECTOR0_RX_CMDQ_INT_B) & cmdq_stat_reg) {
		val = cmdq_stat_reg & ~BIT(HNS3_VECTOR0_RX_CMDQ_INT_B);
		ret = HNS3VF_VECTOR0_EVENT_MBX;
		goto out;
	}

	val = 0;
	ret = HNS3VF_VECTOR0_EVENT_OTHER;
out:
	if (clearval)
		*clearval = val;
	return ret;
}

static void
hns3vf_interrupt_handler(void *param)
{
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	enum hns3vf_evt_cause event_cause;
	uint32_t clearval;

	if (hw->irq_thread_id == 0)
		hw->irq_thread_id = pthread_self();

	/* Disable interrupt */
	hns3vf_disable_irq0(hw);

	/* Read out interrupt causes */
	event_cause = hns3vf_check_event_cause(hns, &clearval);

	switch (event_cause) {
	case HNS3VF_VECTOR0_EVENT_RST:
		hns3_schedule_reset(hns);
		break;
	case HNS3VF_VECTOR0_EVENT_MBX:
		hns3_dev_handle_mbx_msg(hw);
		break;
	default:
		break;
	}

	/* Clear interrupt causes */
	hns3vf_clear_event_cause(hw, clearval);

	/* Enable interrupt */
	hns3vf_enable_irq0(hw);
}

static int
hns3vf_check_tqp_info(struct hns3_hw *hw)
{
	uint16_t tqps_num;

	tqps_num = hw->tqps_num;
	if (tqps_num > HNS3_MAX_TQP_NUM_PER_FUNC || tqps_num == 0) {
		PMD_INIT_LOG(ERR, "Get invalid tqps_num(%u) from PF. valid "
				  "range: 1~%d",
			     tqps_num, HNS3_MAX_TQP_NUM_PER_FUNC);
		return -EINVAL;
	}

	if (hw->rx_buf_len == 0)
		hw->rx_buf_len = HNS3_DEFAULT_RX_BUF_LEN;
	hw->alloc_rss_size = RTE_MIN(hw->rss_size_max, hw->tqps_num);

	return 0;
}

static int
hns3vf_get_queue_info(struct hns3_hw *hw)
{
#define HNS3VF_TQPS_RSS_INFO_LEN	6
	uint8_t resp_msg[HNS3VF_TQPS_RSS_INFO_LEN];
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_GET_QINFO, 0, NULL, 0, true,
				resp_msg, HNS3VF_TQPS_RSS_INFO_LEN);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to get tqp info from PF: %d", ret);
		return ret;
	}

	memcpy(&hw->tqps_num, &resp_msg[0], sizeof(uint16_t));
	memcpy(&hw->rss_size_max, &resp_msg[2], sizeof(uint16_t));
	memcpy(&hw->rx_buf_len, &resp_msg[4], sizeof(uint16_t));

	return hns3vf_check_tqp_info(hw);
}

static int
hns3vf_get_queue_depth(struct hns3_hw *hw)
{
#define HNS3VF_TQPS_DEPTH_INFO_LEN	4
	uint8_t resp_msg[HNS3VF_TQPS_DEPTH_INFO_LEN];
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_GET_QDEPTH, 0, NULL, 0, true,
				resp_msg, HNS3VF_TQPS_DEPTH_INFO_LEN);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to get tqp depth info from PF: %d",
			     ret);
		return ret;
	}

	memcpy(&hw->num_tx_desc, &resp_msg[0], sizeof(uint16_t));
	memcpy(&hw->num_rx_desc, &resp_msg[2], sizeof(uint16_t));

	return 0;
}

static int
hns3vf_get_tc_info(struct hns3_hw *hw)
{
	uint8_t resp_msg;
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_GET_TCINFO, 0, NULL, 0,
				true, &resp_msg, sizeof(resp_msg));
	if (ret) {
		hns3_err(hw, "VF request to get TC info from PF failed %d",
			 ret);
		return ret;
	}

	hw->hw_tc_map = resp_msg;

	return 0;
}

static int
hns3vf_get_configuration(struct hns3_hw *hw)
{
	int ret;

	hw->mac.media_type = HNS3_MEDIA_TYPE_NONE;

	/* Get queue configuration from PF */
	ret = hns3vf_get_queue_info(hw);
	if (ret)
		return ret;

	/* Get queue depth info from PF */
	ret = hns3vf_get_queue_depth(hw);
	if (ret)
		return ret;

	/* Get tc configuration from PF */
	return hns3vf_get_tc_info(hw);
}

static void
hns3vf_set_tc_info(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	uint16_t nb_rx_q = hw->data->nb_rx_queues;
	uint16_t new_tqps;
	uint8_t i;

	hw->num_tc = 0;
	for (i = 0; i < HNS3_MAX_TC_NUM; i++)
		if (hw->hw_tc_map & BIT(i))
			hw->num_tc++;

	new_tqps = RTE_MIN(hw->tqps_num, nb_rx_q);
	hw->alloc_rss_size = RTE_MIN(hw->rss_size_max, new_tqps / hw->num_tc);
	hw->alloc_tqps = hw->alloc_rss_size * hw->num_tc;

	hns3_tc_queue_mapping_cfg(hw);
}

static void
hns3vf_request_link_info(struct hns3_hw *hw)
{
	uint8_t resp_msg;
	int ret;

	if (rte_atomic16_read(&hw->reset.resetting))
		return;
	ret = hns3_send_mbx_msg(hw, HNS3_MBX_GET_LINK_STATUS, 0, NULL, 0, false,
				&resp_msg, sizeof(resp_msg));
	if (ret)
		hns3_err(hw, "Failed to fetch link status from PF: %d", ret);
}

static int
hns3vf_vlan_filter_configure(struct hns3_adapter *hns, uint16_t vlan_id, int on)
{
#define HNS3VF_VLAN_MBX_MSG_LEN 5
	struct hns3_hw *hw = &hns->hw;
	uint8_t msg_data[HNS3VF_VLAN_MBX_MSG_LEN];
	uint16_t proto = htons(RTE_ETHER_TYPE_VLAN);
	uint8_t is_kill = on ? 0 : 1;

	msg_data[0] = is_kill;
	memcpy(&msg_data[1], &vlan_id, sizeof(vlan_id));
	memcpy(&msg_data[3], &proto, sizeof(proto));

	return hns3_send_mbx_msg(hw, HNS3_MBX_SET_VLAN, HNS3_MBX_VLAN_FILTER,
				 msg_data, HNS3VF_VLAN_MBX_MSG_LEN, true, NULL,
				 0);
}

static int
hns3vf_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	if (rte_atomic16_read(&hw->reset.resetting)) {
		hns3_err(hw,
			 "vf set vlan id failed during resetting, vlan_id =%u",
			 vlan_id);
		return -EIO;
	}
	rte_spinlock_lock(&hw->lock);
	ret = hns3vf_vlan_filter_configure(hns, vlan_id, on);
	rte_spinlock_unlock(&hw->lock);
	if (ret)
		hns3_err(hw, "vf set vlan id failed, vlan_id =%u, ret =%d",
			 vlan_id, ret);

	return ret;
}

static int
hns3vf_en_hw_strip_rxvtag(struct hns3_hw *hw, bool enable)
{
	uint8_t msg_data;
	int ret;

	msg_data = enable ? 1 : 0;
	ret = hns3_send_mbx_msg(hw, HNS3_MBX_SET_VLAN, HNS3_MBX_VLAN_RX_OFF_CFG,
				&msg_data, sizeof(msg_data), false, NULL, 0);
	if (ret)
		hns3_err(hw, "vf enable strip failed, ret =%d", ret);

	return ret;
}

static int
hns3vf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	struct hns3_hw *hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;
	unsigned int tmp_mask;

	tmp_mask = (unsigned int)mask;
	/* Vlan stripping setting */
	if (tmp_mask & ETH_VLAN_STRIP_MASK) {
		rte_spinlock_lock(&hw->lock);
		/* Enable or disable VLAN stripping */
		if (dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_VLAN_STRIP)
			hns3vf_en_hw_strip_rxvtag(hw, true);
		else
			hns3vf_en_hw_strip_rxvtag(hw, false);
		rte_spinlock_unlock(&hw->lock);
	}

	return 0;
}

static int
hns3vf_handle_all_vlan_table(struct hns3_adapter *hns, int on)
{
	struct rte_vlan_filter_conf *vfc;
	struct hns3_hw *hw = &hns->hw;
	uint16_t vlan_id;
	uint64_t vbit;
	uint64_t ids;
	int ret = 0;
	uint32_t i;

	vfc = &hw->data->vlan_filter_conf;
	for (i = 0; i < RTE_DIM(vfc->ids); i++) {
		if (vfc->ids[i] == 0)
			continue;
		ids = vfc->ids[i];
		while (ids) {
			/*
			 * 64 means the num bits of ids, one bit corresponds to
			 * one vlan id
			 */
			vlan_id = 64 * i;
			/* count trailing zeroes */
			vbit = ~ids & (ids - 1);
			/* clear least significant bit set */
			ids ^= (ids ^ (ids - 1)) ^ vbit;
			for (; vbit;) {
				vbit >>= 1;
				vlan_id++;
			}
			ret = hns3vf_vlan_filter_configure(hns, vlan_id, on);
			if (ret) {
				hns3_err(hw,
					 "VF handle vlan table failed, ret =%d, on = %d",
					 ret, on);
				return ret;
			}
		}
	}

	return ret;
}

static int
hns3vf_remove_all_vlan_table(struct hns3_adapter *hns)
{
	return hns3vf_handle_all_vlan_table(hns, 0);
}

static int
hns3vf_restore_vlan_conf(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_conf *dev_conf;
	bool en;
	int ret;

	dev_conf = &hw->data->dev_conf;
	en = dev_conf->rxmode.offloads & DEV_RX_OFFLOAD_VLAN_STRIP ? true
								   : false;
	ret = hns3vf_en_hw_strip_rxvtag(hw, en);
	if (ret)
		hns3_err(hw, "VF restore vlan conf fail, en =%d, ret =%d", en,
			 ret);
	return ret;
}

static int
hns3vf_dev_configure_vlan(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct rte_eth_dev_data *data = dev->data;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	if (data->dev_conf.txmode.hw_vlan_reject_tagged ||
	    data->dev_conf.txmode.hw_vlan_reject_untagged ||
	    data->dev_conf.txmode.hw_vlan_insert_pvid) {
		hns3_warn(hw, "hw_vlan_reject_tagged, hw_vlan_reject_untagged "
			      "or hw_vlan_insert_pvid is not support!");
	}

	/* Apply vlan offload setting */
	ret = hns3vf_vlan_offload_set(dev, ETH_VLAN_STRIP_MASK);
	if (ret)
		hns3_err(hw, "dev config vlan offload failed, ret =%d", ret);

	return ret;
}

static int
hns3vf_set_alive(struct hns3_hw *hw, bool alive)
{
	uint8_t msg_data;

	msg_data = alive ? 1 : 0;
	return hns3_send_mbx_msg(hw, HNS3_MBX_SET_ALIVE, 0, &msg_data,
				 sizeof(msg_data), false, NULL, 0);
}

static void
hns3vf_keep_alive_handler(void *param)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)param;
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	uint8_t respmsg;
	int ret;

	ret = hns3_send_mbx_msg(hw, HNS3_MBX_KEEP_ALIVE, 0, NULL, 0,
				false, &respmsg, sizeof(uint8_t));
	if (ret)
		hns3_err(hw, "VF sends keeping alive cmd failed(=%d)",
			 ret);

	rte_eal_alarm_set(HNS3VF_KEEP_ALIVE_INTERVAL, hns3vf_keep_alive_handler,
			  eth_dev);
}

static void
hns3vf_service_handler(void *param)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)param;
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	/*
	 * The query link status and reset processing are executed in the
	 * interrupt thread.When the IMP reset occurs, IMP will not respond,
	 * and the query operation will time out after 30ms. In the case of
	 * multiple PF/VFs, each query failure timeout causes the IMP reset
	 * interrupt to fail to respond within 100ms.
	 * Before querying the link status, check whether there is a reset
	 * pending, and if so, abandon the query.
	 */
	if (!hns3vf_is_reset_pending(hns))
		hns3vf_request_link_info(hw);
	else
		hns3_warn(hw, "Cancel the query when reset is pending");

	rte_eal_alarm_set(HNS3VF_SERVICE_INTERVAL, hns3vf_service_handler,
			  eth_dev);
}

static int
hns3vf_init_hardware(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	uint16_t mtu = hw->data->mtu;
	int ret;

	ret = hns3vf_set_promisc_mode(hw, true);
	if (ret)
		return ret;

	ret = hns3vf_config_mtu(hw, mtu);
	if (ret)
		goto err_init_hardware;

	ret = hns3vf_vlan_filter_configure(hns, 0, 1);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to initialize VLAN config: %d", ret);
		goto err_init_hardware;
	}

	ret = hns3_config_gro(hw, false);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to config gro: %d", ret);
		goto err_init_hardware;
	}

	ret = hns3vf_set_alive(hw, true);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to VF send alive to PF: %d", ret);
		goto err_init_hardware;
	}

	hns3vf_request_link_info(hw);
	return 0;

err_init_hardware:
	(void)hns3vf_set_promisc_mode(hw, false);
	return ret;
}

static int
hns3vf_clear_vport_list(struct hns3_hw *hw)
{
	return hns3_send_mbx_msg(hw, HNS3_MBX_HANDLE_VF_TBL,
				 HNS3_MBX_VPORT_LIST_CLEAR, NULL, 0, false,
				 NULL, 0);
}

static int
hns3vf_init_vf(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
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

	/* Firmware command initialize */
	ret = hns3_cmd_init(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init cmd: %d", ret);
		goto err_cmd_init;
	}

	rte_spinlock_init(&hw->mbx_resp.lock);

	hns3vf_clear_event_cause(hw, 0);

	ret = rte_intr_callback_register(&pci_dev->intr_handle,
					 hns3vf_interrupt_handler, eth_dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to register intr: %d", ret);
		goto err_intr_callback_register;
	}

	/* Enable interrupt */
	rte_intr_enable(&pci_dev->intr_handle);
	hns3vf_enable_irq0(hw);

	/* Get configuration from PF */
	ret = hns3vf_get_configuration(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to fetch configuration: %d", ret);
		goto err_get_config;
	}

	rte_eth_random_addr(hw->mac.mac_addr); /* Generate a random mac addr */

	ret = hns3vf_clear_vport_list(hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to clear tbl list: %d", ret);
		goto err_get_config;
	}

	ret = hns3vf_init_hardware(hns);
	if (ret)
		goto err_get_config;

	hns3_set_default_rss_args(hw);

	(void)hns3_stats_reset(eth_dev);
	return 0;

err_get_config:
	hns3vf_disable_irq0(hw);
	rte_intr_disable(&pci_dev->intr_handle);
	hns3_intr_unregister(&pci_dev->intr_handle, hns3vf_interrupt_handler,
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
hns3vf_uninit_vf(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	PMD_INIT_FUNC_TRACE();

	hns3_rss_uninit(hns);
	(void)hns3vf_set_alive(hw, false);
	(void)hns3vf_set_promisc_mode(hw, false);
	hns3vf_disable_irq0(hw);
	rte_intr_disable(&pci_dev->intr_handle);
	hns3_intr_unregister(&pci_dev->intr_handle, hns3vf_interrupt_handler,
			     eth_dev);
	hns3_cmd_uninit(hw);
	hns3_cmd_destroy_queue(hw);
	hw->io_base = NULL;
}

static int
hns3vf_do_stop(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	bool reset_queue;

	hw->mac.link_status = ETH_LINK_DOWN;

	if (rte_atomic16_read(&hw->reset.disable_cmd) == 0) {
		hns3vf_configure_mac_addr(hns, true);
		reset_queue = true;
	} else
		reset_queue = false;
	return hns3_stop_queues(hns, reset_queue);
}

static void
hns3vf_dev_stop(struct rte_eth_dev *eth_dev)
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
		hns3vf_do_stop(hns);
		hns3_dev_release_mbufs(hns);
		hw->adapter_state = HNS3_NIC_CONFIGURED;
	}
	rte_eal_alarm_cancel(hns3vf_service_handler, eth_dev);
	rte_spinlock_unlock(&hw->lock);
}

static void
hns3vf_dev_close(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return;

	if (hw->adapter_state == HNS3_NIC_STARTED)
		hns3vf_dev_stop(eth_dev);

	hw->adapter_state = HNS3_NIC_CLOSING;
	hns3_reset_abort(hns);
	hw->adapter_state = HNS3_NIC_CLOSED;
	rte_eal_alarm_cancel(hns3vf_keep_alive_handler, eth_dev);
	hns3vf_configure_all_mc_mac_addr(hns, true);
	hns3vf_remove_all_vlan_table(hns);
	hns3vf_uninit_vf(eth_dev);
	hns3_free_all_queues(eth_dev);
	rte_free(hw->reset.wait_data);
	rte_free(eth_dev->process_private);
	eth_dev->process_private = NULL;
	hns3_mp_uninit_primary();
	hns3_warn(hw, "Close port %d finished", hw->data->port_id);
}

static int
hns3vf_dev_link_update(struct rte_eth_dev *eth_dev,
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
hns3vf_do_start(struct hns3_adapter *hns, bool reset_queue)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	hns3vf_set_tc_info(hns);

	ret = hns3_start_queues(hns, reset_queue);
	if (ret) {
		hns3_err(hw, "Failed to start queues: %d", ret);
		return ret;
	}

	return 0;
}

static int
hns3vf_dev_start(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	int ret;

	PMD_INIT_FUNC_TRACE();
	if (rte_atomic16_read(&hw->reset.resetting))
		return -EBUSY;
	rte_spinlock_lock(&hw->lock);
	hw->adapter_state = HNS3_NIC_STARTING;
	ret = hns3vf_do_start(hns, true);
	if (ret) {
		hw->adapter_state = HNS3_NIC_CONFIGURED;
		rte_spinlock_unlock(&hw->lock);
		return ret;
	}
	hw->adapter_state = HNS3_NIC_STARTED;
	rte_spinlock_unlock(&hw->lock);
	hns3_set_rxtx_function(eth_dev);
	hns3_mp_req_start_rxtx(eth_dev);
	rte_eal_alarm_set(HNS3VF_SERVICE_INTERVAL, hns3vf_service_handler,
			  eth_dev);
	return 0;
}

static bool
is_vf_reset_done(struct hns3_hw *hw)
{
#define HNS3_FUN_RST_ING_BITS \
	(BIT(HNS3_VECTOR0_GLOBALRESET_INT_B) | \
	 BIT(HNS3_VECTOR0_CORERESET_INT_B) | \
	 BIT(HNS3_VECTOR0_IMPRESET_INT_B) | \
	 BIT(HNS3_VECTOR0_FUNCRESET_INT_B))

	uint32_t val;

	if (hw->reset.level == HNS3_VF_RESET) {
		val = hns3_read_dev(hw, HNS3_VF_RST_ING);
		if (val & HNS3_VF_RST_ING_BIT)
			return false;
	} else {
		val = hns3_read_dev(hw, HNS3_FUN_RST_ING);
		if (val & HNS3_FUN_RST_ING_BITS)
			return false;
	}
	return true;
}

bool
hns3vf_is_reset_pending(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	enum hns3_reset_level reset;

	hns3vf_check_event_cause(hns, NULL);
	reset = hns3vf_get_reset_level(hw, &hw->reset.pending);
	if (hw->reset.level != HNS3_NONE_RESET && hw->reset.level < reset) {
		hns3_warn(hw, "High level reset %d is pending", reset);
		return true;
	}
	return false;
}

static int
hns3vf_wait_hardware_ready(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_wait_data *wait_data = hw->reset.wait_data;
	struct timeval tv;

	if (wait_data->result == HNS3_WAIT_SUCCESS) {
		/*
		 * After vf reset is ready, the PF may not have completed
		 * the reset processing. The vf sending mbox to PF may fail
		 * during the pf reset, so it is better to add extra delay.
		 */
		if (hw->reset.level == HNS3_VF_FUNC_RESET ||
		    hw->reset.level == HNS3_FLR_RESET)
			return 0;
		/* Reset retry process, no need to add extra delay. */
		if (hw->reset.attempts)
			return 0;
		if (wait_data->check_completion == NULL)
			return 0;

		wait_data->check_completion = NULL;
		wait_data->interval = 1 * MSEC_PER_SEC * USEC_PER_MSEC;
		wait_data->count = 1;
		wait_data->result = HNS3_WAIT_REQUEST;
		rte_eal_alarm_set(wait_data->interval, hns3_wait_callback,
				  wait_data);
		hns3_warn(hw, "hardware is ready, delay 1 sec for PF reset complete");
		return -EAGAIN;
	} else if (wait_data->result == HNS3_WAIT_TIMEOUT) {
		gettimeofday(&tv, NULL);
		hns3_warn(hw, "Reset step4 hardware not ready after reset time=%ld.%.6ld",
			  tv.tv_sec, tv.tv_usec);
		return -ETIME;
	} else if (wait_data->result == HNS3_WAIT_REQUEST)
		return -EAGAIN;

	wait_data->hns = hns;
	wait_data->check_completion = is_vf_reset_done;
	wait_data->end_ms = (uint64_t)HNS3VF_RESET_WAIT_CNT *
				      HNS3VF_RESET_WAIT_MS + get_timeofday_ms();
	wait_data->interval = HNS3VF_RESET_WAIT_MS * USEC_PER_MSEC;
	wait_data->count = HNS3VF_RESET_WAIT_CNT;
	wait_data->result = HNS3_WAIT_REQUEST;
	rte_eal_alarm_set(wait_data->interval, hns3_wait_callback, wait_data);
	return -EAGAIN;
}

static int
hns3vf_prepare_reset(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret = 0;

	if (hw->reset.level == HNS3_VF_FUNC_RESET) {
		ret = hns3_send_mbx_msg(hw, HNS3_MBX_RESET, 0, NULL,
					0, true, NULL, 0);
	}
	rte_atomic16_set(&hw->reset.disable_cmd, 1);

	return ret;
}

static int
hns3vf_stop_service(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_dev *eth_dev;

	eth_dev = &rte_eth_devices[hw->data->port_id];
	rte_eal_alarm_cancel(hns3vf_service_handler, eth_dev);
	hw->mac.link_status = ETH_LINK_DOWN;

	hns3_set_rxtx_function(eth_dev);
	rte_wmb();
	/* Disable datapath on secondary process. */
	hns3_mp_req_stop_rxtx(eth_dev);
	rte_delay_ms(hw->tqps_num);

	rte_spinlock_lock(&hw->lock);
	if (hw->adapter_state == HNS3_NIC_STARTED ||
	    hw->adapter_state == HNS3_NIC_STOPPING) {
		hns3vf_do_stop(hns);
		hw->reset.mbuf_deferred_free = true;
	} else
		hw->reset.mbuf_deferred_free = false;

	/*
	 * It is cumbersome for hardware to pick-and-choose entries for deletion
	 * from table space. Hence, for function reset software intervention is
	 * required to delete the entries.
	 */
	if (rte_atomic16_read(&hw->reset.disable_cmd) == 0)
		hns3vf_configure_all_mc_mac_addr(hns, true);
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static int
hns3vf_start_service(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_dev *eth_dev;

	eth_dev = &rte_eth_devices[hw->data->port_id];
	hns3_set_rxtx_function(eth_dev);
	hns3_mp_req_start_rxtx(eth_dev);

	hns3vf_service_handler(eth_dev);
	return 0;
}

static int
hns3vf_restore_conf(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	ret = hns3vf_configure_mac_addr(hns, false);
	if (ret)
		return ret;

	ret = hns3vf_configure_all_mc_mac_addr(hns, false);
	if (ret)
		goto err_mc_mac;

	ret = hns3vf_restore_vlan_conf(hns);
	if (ret)
		goto err_vlan_table;

	if (hw->adapter_state == HNS3_NIC_STARTED) {
		ret = hns3vf_do_start(hns, false);
		if (ret)
			goto err_vlan_table;
		hns3_info(hw, "hns3vf dev restart successful!");
	} else if (hw->adapter_state == HNS3_NIC_STOPPING)
		hw->adapter_state = HNS3_NIC_CONFIGURED;
	return 0;

err_vlan_table:
	hns3vf_configure_all_mc_mac_addr(hns, true);
err_mc_mac:
	hns3vf_configure_mac_addr(hns, true);
	return ret;
}

static enum hns3_reset_level
hns3vf_get_reset_level(struct hns3_hw *hw, uint64_t *levels)
{
	enum hns3_reset_level reset_level;

	/* return the highest priority reset level amongst all */
	if (hns3_atomic_test_bit(HNS3_VF_RESET, levels))
		reset_level = HNS3_VF_RESET;
	else if (hns3_atomic_test_bit(HNS3_VF_FULL_RESET, levels))
		reset_level = HNS3_VF_FULL_RESET;
	else if (hns3_atomic_test_bit(HNS3_VF_PF_FUNC_RESET, levels))
		reset_level = HNS3_VF_PF_FUNC_RESET;
	else if (hns3_atomic_test_bit(HNS3_VF_FUNC_RESET, levels))
		reset_level = HNS3_VF_FUNC_RESET;
	else if (hns3_atomic_test_bit(HNS3_FLR_RESET, levels))
		reset_level = HNS3_FLR_RESET;
	else
		reset_level = HNS3_NONE_RESET;

	if (hw->reset.level != HNS3_NONE_RESET && reset_level < hw->reset.level)
		return HNS3_NONE_RESET;

	return reset_level;
}

static void
hns3vf_reset_service(void *param)
{
	struct hns3_adapter *hns = (struct hns3_adapter *)param;
	struct hns3_hw *hw = &hns->hw;
	enum hns3_reset_level reset_level;
	struct timeval tv_delta;
	struct timeval tv_start;
	struct timeval tv;
	uint64_t msec;

	/*
	 * The interrupt is not triggered within the delay time.
	 * The interrupt may have been lost. It is necessary to handle
	 * the interrupt to recover from the error.
	 */
	if (rte_atomic16_read(&hns->hw.reset.schedule) == SCHEDULE_DEFERRED) {
		rte_atomic16_set(&hns->hw.reset.schedule, SCHEDULE_REQUESTED);
		hns3_err(hw, "Handling interrupts in delayed tasks");
		hns3vf_interrupt_handler(&rte_eth_devices[hw->data->port_id]);
		reset_level = hns3vf_get_reset_level(hw, &hw->reset.pending);
		if (reset_level == HNS3_NONE_RESET) {
			hns3_err(hw, "No reset level is set, try global reset");
			hns3_atomic_set_bit(HNS3_VF_RESET, &hw->reset.pending);
		}
	}
	rte_atomic16_set(&hns->hw.reset.schedule, SCHEDULE_NONE);

	/*
	 * Hardware reset has been notified, we now have to poll & check if
	 * hardware has actually completed the reset sequence.
	 */
	reset_level = hns3vf_get_reset_level(hw, &hw->reset.pending);
	if (reset_level != HNS3_NONE_RESET) {
		gettimeofday(&tv_start, NULL);
		hns3_reset_process(hns, reset_level);
		gettimeofday(&tv, NULL);
		timersub(&tv, &tv_start, &tv_delta);
		msec = tv_delta.tv_sec * MSEC_PER_SEC +
		       tv_delta.tv_usec / USEC_PER_MSEC;
		if (msec > HNS3_RESET_PROCESS_MS)
			hns3_err(hw, "%d handle long time delta %" PRIx64
				 " ms time=%ld.%.6ld",
				 hw->reset.level, msec, tv.tv_sec, tv.tv_usec);
	}
}

static int
hns3vf_reinit_dev(struct hns3_adapter *hns)
{
	struct rte_eth_dev *eth_dev = &rte_eth_devices[hns->hw.data->port_id];
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct hns3_hw *hw = &hns->hw;
	int ret;

	if (hw->reset.level == HNS3_VF_FULL_RESET) {
		rte_intr_disable(&pci_dev->intr_handle);
		hns3vf_set_bus_master(pci_dev, true);
	}

	/* Firmware command initialize */
	ret = hns3_cmd_init(hw);
	if (ret) {
		hns3_err(hw, "Failed to init cmd: %d", ret);
		goto err_cmd_init;
	}

	if (hw->reset.level == HNS3_VF_FULL_RESET) {
		/*
		 * UIO enables msix by writing the pcie configuration space
		 * vfio_pci enables msix in rte_intr_enable.
		 */
		if (pci_dev->kdrv == RTE_KDRV_IGB_UIO ||
		    pci_dev->kdrv == RTE_KDRV_UIO_GENERIC) {
			if (hns3vf_enable_msix(pci_dev, true))
				hns3_err(hw, "Failed to enable msix");
		}

		rte_intr_enable(&pci_dev->intr_handle);
	}

	ret = hns3_reset_all_queues(hns);
	if (ret) {
		hns3_err(hw, "Failed to reset all queues: %d", ret);
		goto err_init;
	}

	ret = hns3vf_init_hardware(hns);
	if (ret) {
		hns3_err(hw, "Failed to init hardware: %d", ret);
		goto err_init;
	}

	return 0;

err_cmd_init:
	hns3vf_set_bus_master(pci_dev, false);
err_init:
	hns3_cmd_uninit(hw);
	return ret;
}

static const struct eth_dev_ops hns3vf_eth_dev_ops = {
	.dev_start          = hns3vf_dev_start,
	.dev_stop           = hns3vf_dev_stop,
	.dev_close          = hns3vf_dev_close,
	.mtu_set            = hns3vf_dev_mtu_set,
	.stats_get          = hns3_stats_get,
	.stats_reset        = hns3_stats_reset,
	.xstats_get         = hns3_dev_xstats_get,
	.xstats_get_names   = hns3_dev_xstats_get_names,
	.xstats_reset       = hns3_dev_xstats_reset,
	.xstats_get_by_id   = hns3_dev_xstats_get_by_id,
	.xstats_get_names_by_id = hns3_dev_xstats_get_names_by_id,
	.dev_infos_get      = hns3vf_dev_infos_get,
	.rx_queue_setup     = hns3_rx_queue_setup,
	.tx_queue_setup     = hns3_tx_queue_setup,
	.rx_queue_release   = hns3_dev_rx_queue_release,
	.tx_queue_release   = hns3_dev_tx_queue_release,
	.dev_configure      = hns3vf_dev_configure,
	.mac_addr_add       = hns3vf_add_mac_addr,
	.mac_addr_remove    = hns3vf_remove_mac_addr,
	.mac_addr_set       = hns3vf_set_default_mac_addr,
	.set_mc_addr_list   = hns3vf_set_mc_mac_addr_list,
	.link_update        = hns3vf_dev_link_update,
	.rss_hash_update    = hns3_dev_rss_hash_update,
	.rss_hash_conf_get  = hns3_dev_rss_hash_conf_get,
	.reta_update        = hns3_dev_rss_reta_update,
	.reta_query         = hns3_dev_rss_reta_query,
	.filter_ctrl        = hns3_dev_filter_ctrl,
	.vlan_filter_set    = hns3vf_vlan_filter_set,
	.vlan_offload_set   = hns3vf_vlan_offload_set,
	.get_reg            = hns3_get_regs,
	.dev_supported_ptypes_get = hns3_dev_supported_ptypes_get,
};

static const struct hns3_reset_ops hns3vf_reset_ops = {
	.reset_service       = hns3vf_reset_service,
	.stop_service        = hns3vf_stop_service,
	.prepare_reset       = hns3vf_prepare_reset,
	.wait_hardware_ready = hns3vf_wait_hardware_ready,
	.reinit_dev          = hns3vf_reinit_dev,
	.restore_conf        = hns3vf_restore_conf,
	.start_service       = hns3vf_start_service,
};

static int
hns3vf_dev_init(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
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
	eth_dev->dev_ops = &hns3vf_eth_dev_ops;
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		hns3_mp_init_secondary();
		hw->secondary_cnt++;
		return 0;
	}

	hns3_mp_init_primary();

	hw->adapter_state = HNS3_NIC_UNINITIALIZED;
	hns->is_vf = true;
	hw->data = eth_dev->data;

	ret = hns3_reset_init(hw);
	if (ret)
		goto err_init_reset;
	hw->reset.ops = &hns3vf_reset_ops;

	ret = hns3vf_init_vf(eth_dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to init vf: %d", ret);
		goto err_init_vf;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("hns3vf-mac",
					       sizeof(struct rte_ether_addr) *
					       HNS3_VF_UC_MACADDR_NUM, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %zx bytes needed "
			     "to store MAC addresses",
			     sizeof(struct rte_ether_addr) *
			     HNS3_VF_UC_MACADDR_NUM);
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
	rte_eal_alarm_set(HNS3VF_KEEP_ALIVE_INTERVAL, hns3vf_keep_alive_handler,
			  eth_dev);
	return 0;

err_rte_zmalloc:
	hns3vf_uninit_vf(eth_dev);

err_init_vf:
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
hns3vf_dev_uninit(struct rte_eth_dev *eth_dev)
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
		hns3vf_dev_close(eth_dev);

	hw->adapter_state = HNS3_NIC_REMOVED;
	return 0;
}

static int
eth_hns3vf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		     struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct hns3_adapter),
					     hns3vf_dev_init);
}

static int
eth_hns3vf_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, hns3vf_dev_uninit);
}

static const struct rte_pci_id pci_id_hns3vf_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_100G_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_HUAWEI, HNS3_DEV_ID_100G_RDMA_PFC_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver rte_hns3vf_pmd = {
	.id_table = pci_id_hns3vf_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_hns3vf_pci_probe,
	.remove = eth_hns3vf_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_hns3_vf, rte_hns3vf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_hns3_vf, pci_id_hns3vf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_hns3_vf, "* igb_uio | vfio-pci");
