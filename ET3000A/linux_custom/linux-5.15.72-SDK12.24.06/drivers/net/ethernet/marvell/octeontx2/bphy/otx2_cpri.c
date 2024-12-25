// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_cpri.h"
#include "otx2_bphy_debugfs.h"

/*	Theory of Operation
 *
 *	I.   General
 *
 *	The BPHY CPRI netdev processes ethernet packets which are received
 *	and transmitted by CPRI MHAB. The ODP BPHY application shares the
 *	CPRI ETH UL/DL configuration information using ioctl. The Rx
 *	notification is sent to netdev using PSM GPINT.
 *
 *	II.  Driver Operation
 *
 *	This driver register's a character device and provides ioctl for
 *	ODP application to initialize the netdev(s) to process CPRI Ethernet
 *	packets. Each netdev instance created by the driver corresponds to
 *	a unique CPRI MHAB id and Lane id. The ODP application shares the
 *	information such as CPRI ETH UL/DL circular buffers and Rx GPINT
 *	number per CPRI MHAB. The CPRI ETH UL/DL circular buffers are shared
 *	per each CPRI MHAB id. The Rx/Tx packet memory(DDR) is also allocated
 *	by ODP application. The GPINT is setup using CPRI_ETH_UL_INT_PSM_MSG_W0
 *	and CPRI_ETH_UL_INT_PSM_MSG_W1 registers.
 *
 *	III. Transmit
 *
 *	The driver xmit routine selects DL circular buffer ring based on MHAB
 *	id and if there is a free entry available, the driver updates the WQE
 *	header and packet data to the DL entry and updates the DL_WR_DOORBELL
 *	with number of packets written for the hardware to process.
 *
 *	IV.  Receive
 *
 *	The driver receives GPINT interrupt notification per each MHAB and
 *	invokes NAPI handler. The NAPI handler reads the UL circular buffer
 *	ring parameters UL_SW_RD_PTR and UL_NXT_WR_PTR to get the count of
 *	packets to be processed. For each packet received, the driver allocates
 *	skb and copies the packet data to skb. The driver updates
 *	UL_RD_DOORBELL register with count of packets processed by the driver.
 *
 *	V.   Miscellaneous
 *
 *	Ethtool:
 *	The ethtool stats shows packet stats for each netdev instance.
 *
 */

/* global driver ctx */
struct otx2_cpri_drv_ctx cpri_drv_ctx[OTX2_BPHY_CPRI_MAX_INTF];

/* debugfs */
static void otx2_cpri_debugfs_reader(char *buffer, size_t count, void *priv);
static const char *otx2_cpri_debugfs_get_formatter(void);
static size_t otx2_cpri_debugfs_get_buffer_size(void);
static void otx2_cpri_debugfs_create(struct otx2_cpri_drv_ctx *ctx);
static void otx2_cpri_debugfs_remove(struct otx2_cpri_drv_ctx *ctx);

/* enable rx for the interface */
static void otx2_cpri_enable_rx(struct otx2_cpri_ndev_priv *priv);

static struct net_device *otx2_cpri_get_netdev(int mhab_id, int lmac_id)
{
	struct net_device *netdev = NULL;
	int idx;

	for (idx = 0; idx < OTX2_BPHY_CPRI_MAX_INTF; idx++) {
		if (cpri_drv_ctx[idx].cpri_num == mhab_id &&
		    cpri_drv_ctx[idx].lmac_id == lmac_id &&
		    cpri_drv_ctx[idx].valid) {
			netdev = cpri_drv_ctx[idx].netdev;
			break;
		}
	}

	return netdev;
}

static void otx2_cpri_set_rx_state(struct otx2_cpri_ndev_priv *priv,
				   bool enabled)
{
	u64 value;

	value = readq(priv->cpri_reg_base +
		      CPRIX_RXD_GMII_UL_CBUF_CFG1(priv->cpri_num));

	if (enabled)
		value |= BIT_ULL(63);
	else
		value &= ~BIT_ULL(63);

	netdev_printk(KERN_INFO, priv->netdev,
		      "%s RX for CPRI %u LMAC %u 0x%llx\n",
		      (enabled ? "Enabling" : "Disabling"),
		      priv->cpri_num, priv->lmac_id, value);

	writeq(value,
	       priv->cpri_reg_base +
	       CPRIX_RXD_GMII_UL_CBUF_CFG1(priv->cpri_num));
}

void otx2_cpri_enable_intf(int cpri_num)
{
	struct otx2_cpri_drv_ctx *drv_ctx;
	struct otx2_cpri_ndev_priv *priv;
	struct net_device *netdev;
	int idx;

	for (idx = 0; idx < OTX2_BPHY_CPRI_MAX_INTF; idx++) {
		drv_ctx = &cpri_drv_ctx[idx];
		if (drv_ctx->cpri_num == cpri_num && drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			priv->if_type = IF_TYPE_CPRI;
		}
	}
}

void otx2_bphy_cpri_cleanup(void)
{
	struct otx2_cpri_drv_ctx *drv_ctx = NULL;
	struct otx2_cpri_ndev_priv *priv;
	struct net_device *netdev;
	int i;

	for (i = 0; i < OTX2_BPHY_CPRI_MAX_INTF; i++) {
		drv_ctx = &cpri_drv_ctx[i];
		if (drv_ctx->valid) {
			otx2_cpri_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			otx2_cpri_set_rx_state(priv, false);
			cancel_work_sync(&priv->tx_burst_work);
			unregister_netdev(netdev);
			netif_napi_del(&priv->napi);
			--(priv->cpri_common->refcnt);
			if (priv->cpri_common->refcnt == 0)
				kfree(priv->cpri_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}

	/* Disable CPRI ETH UL INT */
	for (i = 0; i < OTX2_BPHY_CPRI_MAX_MHAB; i++)
		writeq(0x1, cpri_reg_base +
		       CPRIX_ETH_UL_INT_ENA_W1C(i));
}

static int otx2_cpri_process_rx_pkts(struct otx2_cpri_ndev_priv *priv,
				     int budget)
{
	int count, head, processed_pkts = 0;
	struct otx2_cpri_ndev_priv *priv2;
	struct cpri_pkt_ul_wqe_hdr *wqe;
	struct ul_cbuf_cfg *ul_cfg;
	struct net_device *netdev;
	u16 nxt_wr_ptr, len;
	struct sk_buff *skb;
	u8 *pkt_buf;

	ul_cfg = &priv->cpri_common->ul_cfg;

	nxt_wr_ptr = readq(priv->cpri_reg_base +
			   CPRIX_RXD_GMII_UL_NXT_WR_PTR(priv->cpri_num)) &
			0xFFFF;
	/* get the HW head */
	head = CIRC_BUF_ENTRY(nxt_wr_ptr);

	if (ul_cfg->sw_rd_ptr > head) {
		count = ul_cfg->num_entries - ul_cfg->sw_rd_ptr;
		count += head;
	} else {
		count = head - ul_cfg->sw_rd_ptr;
	}

	while (likely((processed_pkts < budget) && (processed_pkts < count))) {
		pkt_buf = (u8 __force *)ul_cfg->cbuf_virt_addr +
			  (OTX2_BPHY_CPRI_PKT_BUF_SIZE * ul_cfg->sw_rd_ptr);
		wqe = (struct cpri_pkt_ul_wqe_hdr *)pkt_buf;
		netdev = otx2_cpri_get_netdev(wqe->mhab_id, wqe->lane_id);
		if (unlikely(!netdev)) {
			net_err_ratelimited("CPRI Rx netdev not found, cpri%d lmac%d\n",
					    wqe->mhab_id, wqe->lane_id);
			priv->stats.rx_dropped++;
			priv->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}
		priv2 = netdev_priv(netdev);
		if (wqe->fcserr || wqe->rsp_ferr || wqe->rsp_nferr) {
			net_err_ratelimited("%s: CPRI Rx err,cpri%d lmac%d sw_rd_ptr=%d\n",
					    netdev->name,
					    wqe->mhab_id, wqe->lane_id,
					    ul_cfg->sw_rd_ptr);
			priv2->stats.rx_dropped++;
			priv2->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}
		if (unlikely(!netif_carrier_ok(netdev))) {
			net_err_ratelimited("%s {cpri%d lmac%d} link down, drop pkt\n",
					    netdev->name, priv2->cpri_num,
					    priv2->lmac_id);
			priv2->stats.rx_dropped++;
			priv2->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}

		len = wqe->pkt_length;

		if (unlikely(netif_msg_pktdata(priv2))) {
			netdev_printk(KERN_DEBUG, priv2->netdev, "RX DATA:");
			print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16,
				       4, pkt_buf,
				       len + OTX2_BPHY_CPRI_WQE_SIZE, true);
		}

		pkt_buf += OTX2_BPHY_CPRI_WQE_SIZE;

		skb = netdev_alloc_skb_ip_align(netdev, len);
		if (!skb) {
			net_err_ratelimited("%s:CPRI Rx: alloc skb failed\n",
					    netdev->name);
			priv->stats.rx_dropped++;
			priv->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}

		memcpy(skb->data, pkt_buf, len);
		skb_put(skb, len);
		skb->protocol = eth_type_trans(skb, netdev);

		netif_receive_skb(skb);

		priv2->last_rx_jiffies = jiffies;

update_processed_pkts:
		processed_pkts++;
		ul_cfg->sw_rd_ptr++;
		if (ul_cfg->sw_rd_ptr == ul_cfg->num_entries)
			ul_cfg->sw_rd_ptr = 0;

	}

	if (processed_pkts)
		writeq(processed_pkts, priv->cpri_reg_base +
		       CPRIX_RXD_GMII_UL_RD_DOORBELL(priv->cpri_num));

	return processed_pkts;
}

/* napi poll routine */
static int otx2_cpri_napi_poll(struct napi_struct *napi, int budget)
{
	struct otx2_cpri_ndev_priv *priv;
	int workdone = 0;

	priv = container_of(napi, struct otx2_cpri_ndev_priv, napi);

	/* pkt processing loop */
	workdone += otx2_cpri_process_rx_pkts(priv, budget);

	if (workdone < budget) {
		napi_complete_done(napi, workdone);

		/* Re enable the Rx interrupts */
		otx2_cpri_enable_rx(priv);
	}

	return workdone;
}

bool otx2_cpri_rx_napi_schedule(int cpri_num, u32 status)
{
	struct otx2_cpri_drv_ctx *drv_ctx;
	struct otx2_cpri_ndev_priv *priv;
	u64 regval;
	int idx;

	for (idx = 0; idx < OTX2_BPHY_CPRI_MAX_INTF; idx++) {
		drv_ctx = &cpri_drv_ctx[idx];
		/* ignore lmac, one UL interrupt/cpri */
		if (!(drv_ctx->valid && drv_ctx->cpri_num == cpri_num))
			continue;
		/* check if i/f down, napi disabled */
		priv = netdev_priv(drv_ctx->netdev);
		if (test_bit(CPRI_INTF_DOWN, &priv->state))
			continue;
		/* clear intr enable bit, re-enable in napi handler */
		regval = 1 << CPRI_RX_INTR_SHIFT(cpri_num);
		writeq(regval, priv->bphy_reg_base + PSM_INT_GP_ENA_W1C(1));
		priv->gp_int_disabled = 1;
		/* schedule napi */
		napi_schedule(&priv->napi);
		/* napi scheduled per MHAB, return */
		return true;
	}

	return false;
}

void otx2_cpri_update_stats(struct otx2_cpri_ndev_priv *priv)
{
	struct otx2_cpri_stats *dev_stats = &priv->stats;

	dev_stats->rx_frames += readq(priv->cpri_reg_base +
				      CPRIX_ETH_UL_GPKTS_CNT(priv->cpri_num,
							     priv->lmac_id));
	dev_stats->rx_octets += readq(priv->cpri_reg_base +
				      CPRIX_ETH_UL_GOCT_CNT(priv->cpri_num,
							    priv->lmac_id));
	dev_stats->rx_err += readq(priv->cpri_reg_base +
				      CPRIX_ETH_UL_ERR_CNT(priv->cpri_num,
							   priv->lmac_id));
	dev_stats->bad_crc += readq(priv->cpri_reg_base +
				    CPRIX_ETH_BAD_CRC_CNT(priv->cpri_num,
							  priv->lmac_id));
	dev_stats->oversize += readq(priv->cpri_reg_base +
				     CPRIX_ETH_UL_OSIZE_CNT(priv->cpri_num,
							    priv->lmac_id));
	dev_stats->undersize += readq(priv->cpri_reg_base +
				      CPRIX_ETH_UL_USIZE_CNT(priv->cpri_num,
							     priv->lmac_id));
	dev_stats->fifo_ovr += readq(priv->cpri_reg_base +
				     CPRIX_ETH_UL_FIFO_ORUN_CNT(priv->cpri_num,
								priv->lmac_id));
	dev_stats->rx_bad_octets += readq(priv->cpri_reg_base +
					  CPRIX_ETH_UL_BOCT_CNT(priv->cpri_num,
								priv->lmac_id));
	dev_stats->tx_frames += readq(priv->cpri_reg_base +
				      CPRIX_ETH_DL_GPKTS_CNT(priv->cpri_num,
							     priv->lmac_id));
	dev_stats->tx_octets += readq(priv->cpri_reg_base +
				      CPRIX_ETH_DL_GOCTETS_CNT(priv->cpri_num,
							       priv->lmac_id));
}

static void otx2_cpri_get_stats64(struct net_device *netdev,
				  struct rtnl_link_stats64 *stats)
{
	struct otx2_cpri_ndev_priv *priv = netdev_priv(netdev);
	struct otx2_cpri_stats *dev_stats = &priv->stats;

	otx2_cpri_update_stats(priv);

	stats->rx_bytes = dev_stats->rx_octets;
	stats->rx_packets = dev_stats->rx_frames;
	stats->rx_dropped = dev_stats->rx_dropped;
	stats->rx_errors = dev_stats->rx_err;
	stats->rx_crc_errors = dev_stats->bad_crc;
	stats->rx_fifo_errors = dev_stats->fifo_ovr;
	stats->rx_length_errors = dev_stats->oversize + dev_stats->undersize;

	stats->tx_bytes = dev_stats->tx_octets;
	stats->tx_packets = dev_stats->tx_frames;
}

/* netdev ioctl */
static int otx2_cpri_ioctl(struct net_device *netdev, struct ifreq *req,
			   int cmd)
{
	return -EOPNOTSUPP;
}

static void otx2_cpri_tx_burst_work(struct work_struct *work)
{
	struct otx2_cpri_ndev_priv *priv =
			container_of(work, struct otx2_cpri_ndev_priv, tx_burst_work);
	struct dl_cbuf_cfg *dl_cfg = &priv->cpri_common->dl_cfg;
	unsigned long flags;

	spin_lock_irqsave(&dl_cfg->lock, flags);
	if (priv->tx_burst_pkts >= 1) {
		udelay(25);
		priv->tx_burst_pkts = 0;
		if (netif_queue_stopped(priv->netdev))
			netif_wake_queue(priv->netdev);
	}
	spin_unlock_irqrestore(&dl_cfg->lock, flags);
}

/* netdev xmit */
static netdev_tx_t otx2_cpri_eth_start_xmit(struct sk_buff *skb,
					    struct net_device *netdev)
{
	struct otx2_cpri_ndev_priv *priv = netdev_priv(netdev);
	struct cpri_pkt_dl_wqe_hdr *wqe;
	struct dl_cbuf_cfg *dl_cfg;
	unsigned long flags;
	u8 *buf_ptr;
	int tail, count;
	u16 nxt_rd_ptr;

	dl_cfg = &priv->cpri_common->dl_cfg;

	spin_lock_irqsave(&dl_cfg->lock, flags);

	if (unlikely(priv->if_type != IF_TYPE_CPRI)) {
		netif_err(priv, tx_queued, netdev,
			  "%s {cpri%d lmac%d} invalid intf mode, drop pkt\n",
			  netdev->name, priv->cpri_num, priv->lmac_id);
		/* update stats */
		priv->stats.tx_dropped++;
		priv->last_tx_dropped_jiffies = jiffies;
		goto exit;
	}

	if (unlikely(!netif_carrier_ok(netdev))) {
		/* update stats */
		priv->stats.tx_dropped++;
		priv->last_tx_dropped_jiffies = jiffies;
		goto exit;
	}

	if (priv->tx_burst_pkts >= 1) {
		spin_unlock_irqrestore(&dl_cfg->lock, flags);
		netif_stop_queue(priv->netdev);
		schedule_work(&priv->tx_burst_work);
		return NETDEV_TX_BUSY;
	}

	/* Read CPRI(0..2)_TXD_GMII_DL_WR_DOORBELL to become 0 */
	while ((readq(priv->cpri_reg_base +
		      CPRIX_TXD_GMII_DL_WR_DOORBELL(priv->cpri_num)) & 0xFF))
		cpu_relax();

	nxt_rd_ptr = readq(priv->cpri_reg_base +
			   CPRIX_TXD_GMII_DL_NXT_RD_PTR(priv->cpri_num)) &
			0xFFFF;
	/* get the HW tail */
	tail = CIRC_BUF_ENTRY(nxt_rd_ptr);
	if (dl_cfg->sw_wr_ptr >= tail)
		count = dl_cfg->num_entries - dl_cfg->sw_wr_ptr + tail;
	else
		count = tail - dl_cfg->sw_wr_ptr;

	if (count == 0) {
		spin_unlock_irqrestore(&dl_cfg->lock, flags);
		return NETDEV_TX_BUSY;
	}

	if (unlikely(netif_msg_pktdata(priv))) {
		netdev_printk(KERN_DEBUG, priv->netdev, "Tx: skb %pS len=%d\n",
			      skb, skb->len);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       skb->data, skb->len, true);
	}

	buf_ptr = (u8 __force *)dl_cfg->cbuf_virt_addr +
		  (OTX2_BPHY_CPRI_PKT_BUF_SIZE * dl_cfg->sw_wr_ptr);
	wqe = (struct cpri_pkt_dl_wqe_hdr *)buf_ptr;
	wqe->mhab_id = priv->cpri_num;
	wqe->lane_id = priv->lmac_id;
	buf_ptr += OTX2_BPHY_CPRI_WQE_SIZE;
	/* zero pad for short pkts, since there is no HW support */
	if (skb->len < 64)
		memset(buf_ptr, 0, 64);
	memcpy(buf_ptr, skb->data, skb->len);
	wqe->pkt_length = skb->len > 64 ? skb->len : 64;

	/* ensure the memory is updated before ringing doorbell */
	dma_wmb();
	writeq(1, priv->cpri_reg_base +
	       CPRIX_TXD_GMII_DL_WR_DOORBELL(priv->cpri_num));

	/* increment queue index */
	dl_cfg->sw_wr_ptr++;
	if (dl_cfg->sw_wr_ptr == dl_cfg->num_entries)
		dl_cfg->sw_wr_ptr = 0;

	/* increment burst pkt count */
	priv->tx_burst_pkts++;

	priv->last_tx_jiffies = jiffies;
exit:
	dev_kfree_skb_any(skb);
	spin_unlock_irqrestore(&dl_cfg->lock, flags);

	return NETDEV_TX_OK;
}

/* netdev open */
static int otx2_cpri_eth_open(struct net_device *netdev)
{
	struct otx2_cpri_ndev_priv *priv = netdev_priv(netdev);

	napi_enable(&priv->napi);

	spin_lock(&priv->lock);
	clear_bit(CPRI_INTF_DOWN, &priv->state);
	if (priv->link_state == LINK_STATE_UP) {
		netif_carrier_on(netdev);
		netif_start_queue(netdev);
	}
	spin_unlock(&priv->lock);

	return 0;
}

/* netdev close */
static int otx2_cpri_eth_stop(struct net_device *netdev)
{
	struct otx2_cpri_ndev_priv *priv = netdev_priv(netdev);

	spin_lock(&priv->lock);
	set_bit(CPRI_INTF_DOWN, &priv->state);

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);
	spin_unlock(&priv->lock);

	napi_disable(&priv->napi);

	otx2_cpri_enable_rx(priv);

	return 0;
}

static const struct net_device_ops otx2_cpri_netdev_ops = {
	.ndo_open		= otx2_cpri_eth_open,
	.ndo_stop		= otx2_cpri_eth_stop,
	.ndo_start_xmit		= otx2_cpri_eth_start_xmit,
	.ndo_eth_ioctl		= otx2_cpri_ioctl,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64	= otx2_cpri_get_stats64,
};

static void otx2_cpri_dump_ul_cbuf(struct otx2_cpri_ndev_priv *priv)
{
	struct ul_cbuf_cfg *ul_cfg = &priv->cpri_common->ul_cfg;

	pr_debug("%s: num_entries=%d iova=0x%llx\n",
		 __func__, ul_cfg->num_entries, ul_cfg->cbuf_iova_addr);
}

static void otx2_cpri_dump_dl_cbuf(struct otx2_cpri_ndev_priv *priv)
{
	struct dl_cbuf_cfg *dl_cfg = &priv->cpri_common->dl_cfg;

	pr_debug("%s: num_entries=%d iova=0x%llx\n",
		 __func__, dl_cfg->num_entries, dl_cfg->cbuf_iova_addr);
}

static void otx2_cpri_fill_dl_ul_cfg(struct otx2_cpri_ndev_priv *priv,
				     struct bphy_netdev_cpri_if *cpri_cfg)
{
	struct dl_cbuf_cfg *dl_cfg;
	struct ul_cbuf_cfg *ul_cfg;
	u64 iova;

	dl_cfg = &priv->cpri_common->dl_cfg;
	dl_cfg->num_entries = cpri_cfg->num_dl_buf;
	iova = cpri_cfg->dl_buf_iova_addr;
	dl_cfg->cbuf_iova_addr = iova;
	dl_cfg->cbuf_virt_addr = otx2_iova_to_virt(priv->iommu_domain, iova);
	dl_cfg->sw_wr_ptr = 0;
	spin_lock_init(&dl_cfg->lock);
	otx2_cpri_dump_dl_cbuf(priv);

	ul_cfg = &priv->cpri_common->ul_cfg;
	ul_cfg->num_entries = cpri_cfg->num_ul_buf;
	iova = cpri_cfg->ul_buf_iova_addr;
	ul_cfg->cbuf_iova_addr = iova;
	ul_cfg->cbuf_virt_addr = otx2_iova_to_virt(priv->iommu_domain, iova);
	ul_cfg->sw_rd_ptr = 0;
	spin_lock_init(&ul_cfg->lock);
	otx2_cpri_dump_ul_cbuf(priv);
}

int otx2_cpri_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				  struct bphy_netdev_comm_intf_cfg *cfg)
{
	struct otx2_cpri_drv_ctx *drv_ctx = NULL;
	struct otx2_cpri_ndev_priv *priv, *priv2;
	struct bphy_netdev_cpri_if *cpri_cfg;
	int i, intf_idx = 0, lmac, ret;
	struct net_device *netdev;

	for (i = 0; i < OTX2_BPHY_CPRI_MAX_MHAB; i++) {
		priv2 = NULL;
		cpri_cfg = &cfg[i].cpri_if_cfg;
		for (lmac = 0; lmac < OTX2_BPHY_CPRI_MAX_LMAC; lmac++) {
			intf_idx = (i * 4) + lmac;
			if (intf_idx >= OTX2_BPHY_CPRI_MAX_INTF) {
				dev_dbg(cdev->dev,
					"cpri%d lmac%d doesn't exist, skipping intf cfg\n",
					i, lmac);
				continue;
			}
			if (!(cpri_cfg->active_lane_mask & (1 << lmac)))
				continue;
			netdev =
			    alloc_etherdev(sizeof(struct otx2_cpri_ndev_priv));
			if (!netdev) {
				dev_err(cdev->dev,
					"error allocating net device\n");
				ret = -ENOMEM;
				goto err_exit;
			}
			priv = netdev_priv(netdev);
			memset(priv, 0, sizeof(*priv));
			if (!priv2) {
				priv->cpri_common =
					kzalloc(sizeof(struct cpri_common_cfg),
						GFP_KERNEL);
				if (!priv->cpri_common) {
					dev_err(cdev->dev, "kzalloc failed\n");
					free_netdev(netdev);
					ret = -ENOMEM;
					goto err_exit;
				}
				priv->cpri_common->refcnt = 1;
			}
			spin_lock_init(&priv->lock);
			priv->netdev = netdev;
			priv->cdev_priv = cdev;
			priv->msg_enable = netif_msg_init(-1, 0);
			spin_lock_init(&priv->stats.lock);
			priv->cpri_num = cpri_cfg->id;
			priv->lmac_id = lmac;
			priv->if_type = cfg[i].if_type;
			memcpy(priv->mac_addr, &cpri_cfg->eth_addr[lmac],
			       ETH_ALEN);
			if (is_valid_ether_addr(priv->mac_addr))
				ether_addr_copy(netdev->dev_addr,
						priv->mac_addr);
			else
				random_ether_addr(netdev->dev_addr);
			priv->pdev = pci_get_device(OTX2_BPHY_PCI_VENDOR_ID,
						    OTX2_BPHY_PCI_DEVICE_ID,
						    NULL);
			priv->iommu_domain =
				iommu_get_domain_for_dev(&priv->pdev->dev);
			priv->bphy_reg_base = bphy_reg_base;
			priv->cpri_reg_base = cpri_reg_base;

			if (!priv2) {
				otx2_cpri_fill_dl_ul_cfg(priv, cpri_cfg);
			} else {
				/* share cpri_common data */
				priv->cpri_common = priv2->cpri_common;
				++(priv->cpri_common->refcnt);
			}

			netif_napi_add(priv->netdev, &priv->napi,
				       otx2_cpri_napi_poll, NAPI_POLL_WEIGHT);
			INIT_WORK(&priv->tx_burst_work, otx2_cpri_tx_burst_work);

			/* keep last (cpri + lmac) priv structure */
			if (!priv2)
				priv2 = priv;

			snprintf(netdev->name, sizeof(netdev->name),
				 "cpri%d", intf_idx);
			netdev->netdev_ops = &otx2_cpri_netdev_ops;
			otx2_cpri_set_ethtool_ops(netdev);
			netdev->mtu = 1500U;
			netdev->min_mtu = ETH_MIN_MTU;
			netdev->max_mtu = 1500U;
			ret = register_netdev(netdev);
			if (ret < 0) {
				dev_err(cdev->dev,
					"failed to register net device %s\n",
					netdev->name);
				free_netdev(netdev);
				ret = -ENODEV;
				goto err_exit;
			}
			dev_dbg(cdev->dev, "net device %s registered\n",
				netdev->name);

			netif_carrier_off(netdev);
			netif_stop_queue(netdev);
			set_bit(CPRI_INTF_DOWN, &priv->state);
			priv->link_state = LINK_STATE_UP;

			/* initialize global ctx */
			drv_ctx = &cpri_drv_ctx[intf_idx];
			drv_ctx->cpri_num = priv->cpri_num;
			drv_ctx->lmac_id = priv->lmac_id;
			drv_ctx->valid = 1;
			drv_ctx->netdev = netdev;

			/* create debugfs entry */
			otx2_cpri_debugfs_create(drv_ctx);
		}
	}

	return 0;

err_exit:
	for (i = 0; i < OTX2_BPHY_CPRI_MAX_INTF; i++) {
		drv_ctx = &cpri_drv_ctx[i];
		if (drv_ctx->valid) {
			otx2_cpri_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			cancel_work_sync(&priv->tx_burst_work);
			unregister_netdev(netdev);
			netif_napi_del(&priv->napi);
			--(priv->cpri_common->refcnt);
			if (priv->cpri_common->refcnt == 0)
				kfree(priv->cpri_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}
	return ret;
}

static void otx2_cpri_debugfs_reader(char *buffer, size_t count, void *priv)
{
	struct otx2_cpri_drv_ctx *ctx;
	struct otx2_cpri_ndev_priv *netdev;
	u8 queue_stopped, state_up;
	const char *formatter;

	ctx = priv;
	netdev = netdev_priv(ctx->netdev);
	queue_stopped = netif_queue_stopped(ctx->netdev);
	state_up = netdev->link_state;
	formatter = otx2_cpri_debugfs_get_formatter();

	snprintf(buffer, count, formatter,
		 queue_stopped,
		 state_up,
		 netdev->last_tx_jiffies,
		 netdev->last_tx_dropped_jiffies,
		 netdev->last_rx_jiffies,
		 netdev->last_rx_dropped_jiffies,
		 netdev->gp_int_disabled,
		 jiffies);
}

static const char *otx2_cpri_debugfs_get_formatter(void)
{
	static const char *buffer_format = "queue-stopped: %u\n"
					   "state-up: %u\n"
					   "last-tx-jiffies: %lu\n"
					   "last-tx-dropped-jiffies: %lu\n"
					   "last-rx-jiffies: %lu\n"
					   "last-rx-dropped-jiffies: %lu\n"
					   "gp-int-disabled: %u\n"
					   "current-jiffies: %lu\n";

	return buffer_format;
}

static size_t otx2_cpri_debugfs_get_buffer_size(void)
{
	static size_t buffer_size;

	if (!buffer_size) {
		const char *formatter = otx2_cpri_debugfs_get_formatter();
		u8 max_boolean = 1;
		unsigned long max_jiffies = (unsigned long)-1;

		buffer_size = snprintf(NULL, 0, formatter,
				       max_boolean,
				       max_boolean,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_boolean,
				       max_jiffies);
		++buffer_size;
	}

	return buffer_size;
}

static void otx2_cpri_debugfs_create(struct otx2_cpri_drv_ctx *ctx)
{
	size_t buffer_size = otx2_cpri_debugfs_get_buffer_size();

	ctx->debugfs = otx2_bphy_debugfs_add_file(ctx->netdev->name,
						  buffer_size, ctx,
						  otx2_cpri_debugfs_reader);
}

static void otx2_cpri_debugfs_remove(struct otx2_cpri_drv_ctx *ctx)
{
	if (ctx->debugfs)
		otx2_bphy_debugfs_remove_file(ctx->debugfs);
}

void otx2_cpri_set_link_state(struct net_device *netdev, u8 state)
{
	struct otx2_cpri_ndev_priv *priv;

	priv = netdev_priv(netdev);

	spin_lock(&priv->lock);
	if (priv->link_state != state) {
		priv->link_state = state;
		if (state == LINK_STATE_DOWN) {
			netdev_info(netdev, "Link DOWN\n");
			if (netif_running(netdev)) {
				netif_carrier_off(netdev);
				netif_stop_queue(netdev);
			}
		} else {
			netdev_info(netdev, "Link UP\n");
			if (netif_running(netdev)) {
				netif_carrier_on(netdev);
				netif_start_queue(netdev);
			}
		}
	}
	spin_unlock(&priv->lock);
}

static void otx2_cpri_enable_rx(struct otx2_cpri_ndev_priv *priv)
{
	struct otx2_bphy_cdev_priv *cdev_priv;
	u64 intr_en, regval;

	cdev_priv = priv->cdev_priv;

	/* Re enable the Rx interrupts if needed */
	intr_en = 1 << CPRI_RX_INTR_SHIFT(priv->cpri_num);
	spin_lock(&cdev_priv->lock);
	if (priv->gp_int_disabled) {
		regval = readq(priv->bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		regval |= intr_en;
		writeq(regval, priv->bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		priv->gp_int_disabled = 0;
		writeq(0x1, priv->cpri_reg_base +
		       CPRIX_ETH_UL_INT(priv->cpri_num));
	}
	spin_unlock(&cdev_priv->lock);
}
