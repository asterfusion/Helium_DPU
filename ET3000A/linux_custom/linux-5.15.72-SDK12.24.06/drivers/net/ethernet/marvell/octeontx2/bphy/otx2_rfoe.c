// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_rfoe.h"
#include "otx2_bphy_hw.h"
#include "otx2_bphy_debugfs.h"

/*	                      Theory of Operation
 *
 *	I.   General
 *
 *	The BPHY RFOE netdev driver handles packets such as eCPRI control,
 *	PTP and other ethernet packets received from/sent to BPHY RFOE MHAB
 *	in Linux kernel. All other packets such as ROE and eCPRI non-control
 *	are handled by ODP application in user space. The ODP application
 *	initializes the JDT/MBT/PSM-queues to process the Rx/Tx packets in
 *	netdev and shares the information through driver ioctl. The Rx/TX
 *	notification will be sent to netdev using one of the PSM GPINT.
 *
 *	II.  Driver Operation
 *
 *	This driver register's a character device and provides ioctl for
 *	ODP application to initialize the netdev(s) to process eCPRI and
 *	other Ethernet packets. Each netdev corresponds to a unique RFOE
 *	index and LMAC id. The ODP application initializes the flow tables,
 *	Rx JDT and RX MBT to process Rx packets. There will be a unique
 *	Flow Table, JDT, MBT for processing eCPRI, PTP and other Ethernet
 *	packets separately. The Rx packet memory (DDR) is also allocated
 *	by ODP and configured in MBT. All LMAC's in a single RFOE MHAB share
 *	the Rx configuration tuple {Flow Id, JDT and MBT}. The Rx event is
 *	notified to the netdev via PSM GPINT1. Each PSM GPINT supports 32-bits
 *	and can be used as interrupt status bits. For each Rx packet type
 *	per RFOE, one PSM GPINT bit is reserved to notify the Rx event for
 *	that packet type. The ODP application configures PSM_CMD_GPINT_S
 *	in the JCE section of JD for each packet. There are total 32 JDT
 *	and MBT entries per packet type. These entries will be reused when
 *	the JDT/MBT circular entries wraps around.
 *
 *	On Tx side, the ODP application creates preconfigured job commands
 *	for the driver use. Each job command contains information such as
 *	PSM cmd (ADDJOB) info, JD iova address. The packet memory is also
 *	allocated by ODP app. The JD rd dma cfg section contains the memory
 *	addr for packet DMA. There are two PSM queues/RFOE reserved for Tx
 *	puropose. One queue handles PTP traffic and other queue is used for
 *	eCPRI and regular Ethernet traffic. The PTP job descriptor's (JD) are
 *	configured to generate Tx completion event through GPINT mechanism.
 *	For each LMAC/RFOE there will be one GPINT bit reserved for this
 *	purpose. For eCPRI and other Ethernet traffic there is no GPINT	event
 *	to signal Tx completion to the driver. The driver Tx interrupt handler
 *	reads RFOE(0..2)_TX_PTP_TSTMP_W0 and RFOE(0..2)_TX_PTP_TSTMP_W1
 *	registers for PTP timestamp and fills the time stamp in PTP skb. The
 *	number of preconfigured job commands are 64 for non-ptp shared by all
 *	LMAC's in RFOE and 4 for PTP per each LMAC in RFOE. The PTP job cmds
 *	are not shared because the timestamp registers are unique per LMAC.
 *
 *	III. Transmit
 *
 *	The driver xmit routine selects the PSM queue based on whether the
 *	packet needs to be timestamped in HW by checking SKBTX_HW_TSTAMP flag.
 *	In case of PTP packet, if there is pending PTP packet in progress then
 *	the drivers adds this skb to a list and returns success. This list
 *	is processed after the previous PTP packet is sent and timestamp is
 *	copied to the skb successfully in the Tx interrupt handler.
 *
 *	Once the PSM queue is selected, the driver checks whether there is
 *	enough space in that PSM queue by reading PSM_QUEUE(0..127)_SPACE
 *	reister. If the PSM queue is not full, then the driver get's the
 *	corresponding job entries associated with that queue and updates the
 *	length in JD DMA cfg word0 and copied the packet data to JD DMA
 *	cfg word1. For eCPRI/non-PTP packets, the driver also updates JD CFG
 *	RFOE_MODE.
 *
 *	IV.  Receive
 *
 *	The driver receives an interrupt per pkt_type and invokes NAPI handler.
 *	The NAPI handler reads the corresponding MBT cfg (nxt_buf) to see the
 *	number of packets to be processed. For each successful mbt_entry, the
 *	packet handler get's corresponding mbt entry buffer address and based
 *	on packet type, the PSW0/ECPRI_PSW0 is read to get the JD iova addr
 *	corresponding to that MBT entry. The DMA block size is read from the
 *	JDT entry to know the number of bytes DMA'd including PSW bytes. The
 *	MBT entry buffer address is moved by pkt_offset bytes and length is
 *	decremented by pkt_offset to get actual pkt data and length. For each
 *	pkt, skb is allocated and packet data is copied to skb->data. In case
 *	of PTP packets, the PSW1 contains the PTP timestamp value and will be
 *	copied to the skb.
 *
 *	V.   Miscellaneous
 *
 *	Ethtool:
 *	The ethtool stats shows packet stats for each packet type.
 *
 */

/* global driver ctx */
struct otx2_rfoe_drv_ctx rfoe_drv_ctx[RFOE_MAX_INTF];

/* debugfs */
static void otx2_rfoe_debugfs_reader(char *buffer, size_t count, void *priv);
static const char *otx2_rfoe_debugfs_get_formatter(void);
static size_t otx2_rfoe_debugfs_get_buffer_size(void);
static void otx2_rfoe_debugfs_create(struct otx2_rfoe_drv_ctx *ctx);
static void otx2_rfoe_debugfs_remove(struct otx2_rfoe_drv_ctx *ctx);

static void otx2_rfoe_set_rx_state(struct otx2_rfoe_ndev_priv *priv,
				   bool enabled)
{
	struct rfoex_rx_ctrl *rx_ctrl;
	u64 value;

	value = readq(priv->rfoe_reg_base + RFOEX_RX_CTL(priv->rfoe_num));

	rx_ctrl = (struct rfoex_rx_ctrl *)&value;

	if (rx_ctrl->data_pkt_rx_en == enabled)
		return;

	rx_ctrl->data_pkt_rx_en = enabled;

	netdev_printk(KERN_INFO, priv->netdev,
		      "%s RX for RFOE %u LMAC %u data_pkt_rx_en 0x%x\n",
		      (enabled ? "Enabling" : "Disabling"),
		      priv->rfoe_num, priv->lmac_id, rx_ctrl->data_pkt_rx_en);

	writeq(value,
	       priv->rfoe_reg_base + RFOEX_RX_CTL(priv->rfoe_num));
}

void otx2_rfoe_disable_intf(int rfoe_num)
{
	struct otx2_rfoe_drv_ctx *drv_ctx;
	struct otx2_rfoe_ndev_priv *priv;
	struct net_device *netdev;
	int idx;

	for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
		drv_ctx = &rfoe_drv_ctx[idx];
		if (drv_ctx->rfoe_num == rfoe_num && drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			priv->if_type = IF_TYPE_NONE;
		}
	}
}

void otx2_bphy_rfoe_cleanup(void)
{
	struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
	struct otx2_rfoe_ndev_priv *priv;
	struct net_device *netdev;
	struct rx_ft_cfg *ft_cfg;
	int i, idx;

	for (i = 0; i < RFOE_MAX_INTF; i++) {
		drv_ctx = &rfoe_drv_ctx[i];
		if (drv_ctx->valid) {
			otx2_rfoe_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			netif_stop_queue(netdev);
			priv = netdev_priv(netdev);
			otx2_rfoe_set_rx_state(priv, false);
			--(priv->ptp_cfg->refcnt);
			if (!priv->ptp_cfg->refcnt) {
				del_timer_sync(&priv->ptp_cfg->ptp_timer);
				kfree(priv->ptp_cfg);
			}
			otx2_rfoe_ptp_destroy(priv);
			for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
				if (!(priv->pkt_type_mask & (1U << idx)))
					continue;
				ft_cfg = &priv->rx_ft_cfg[idx];
				netif_napi_del(&ft_cfg->napi);
			}
			unregister_netdev(netdev);
			--(priv->rfoe_common->refcnt);
			if (priv->rfoe_common->refcnt == 0)
				kfree(priv->rfoe_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}
}

void otx2_rfoe_calc_ptp_ts(struct otx2_rfoe_ndev_priv *priv, u64 *ts)
{
	u64 ptp_diff_nsec, ptp_diff_psec;
	struct ptp_bcn_off_cfg *ptp_cfg;
	struct ptp_clk_cfg *clk_cfg;
	struct ptp_bcn_ref *ref;
	unsigned long flags;
	u64 timestamp = *ts;

	ptp_cfg = priv->ptp_cfg;
	if (!ptp_cfg->use_ptp_alg)
		return;
	clk_cfg = &ptp_cfg->clk_cfg;

	spin_lock_irqsave(&ptp_cfg->lock, flags);

	if (likely(timestamp > ptp_cfg->new_ref.ptp0_ns))
		ref = &ptp_cfg->new_ref;
	else
		ref = &ptp_cfg->old_ref;

	/* calculate ptp timestamp diff in pico sec */
	ptp_diff_psec = ((timestamp - ref->ptp0_ns) * PICO_SEC_PER_NSEC *
			 clk_cfg->clk_freq_div) / clk_cfg->clk_freq_ghz;
	ptp_diff_nsec = (ptp_diff_psec + ref->bcn0_n2_ps + 500) /
			PICO_SEC_PER_NSEC;
	timestamp = ref->bcn0_n1_ns - priv->sec_bcn_offset + ptp_diff_nsec;

	spin_unlock_irqrestore(&ptp_cfg->lock, flags);

	*ts = timestamp;
}

static void otx2_rfoe_ptp_offset_timer(struct timer_list *t)
{
	struct ptp_bcn_off_cfg *ptp_cfg = from_timer(ptp_cfg, t, ptp_timer);
	u64 mio_ptp_ts, ptp_ts_diff, ptp_diff_nsec, ptp_diff_psec;
	struct ptp_clk_cfg *clk_cfg = &ptp_cfg->clk_cfg;
	unsigned long expires, flags;

	spin_lock_irqsave(&ptp_cfg->lock, flags);

	memcpy(&ptp_cfg->old_ref, &ptp_cfg->new_ref,
	       sizeof(struct ptp_bcn_ref));

	mio_ptp_ts = readq(ptp_reg_base + MIO_PTP_CLOCK_HI);
	ptp_ts_diff = mio_ptp_ts - ptp_cfg->new_ref.ptp0_ns;
	ptp_diff_psec = (ptp_ts_diff * PICO_SEC_PER_NSEC *
			 clk_cfg->clk_freq_div) / clk_cfg->clk_freq_ghz;
	ptp_diff_nsec = ptp_diff_psec / PICO_SEC_PER_NSEC;
	ptp_cfg->new_ref.ptp0_ns += ptp_ts_diff;
	ptp_cfg->new_ref.bcn0_n1_ns += ptp_diff_nsec;
	ptp_cfg->new_ref.bcn0_n2_ps += ptp_diff_psec -
				       (ptp_diff_nsec * PICO_SEC_PER_NSEC);

	spin_unlock_irqrestore(&ptp_cfg->lock, flags);

	expires = jiffies + PTP_OFF_RESAMPLE_THRESH * HZ;
	mod_timer(&ptp_cfg->ptp_timer, expires);
}

/* submit pending ptp tx requests */
static void otx2_rfoe_ptp_submit_work(struct work_struct *work)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(work,
						struct otx2_rfoe_ndev_priv,
						ptp_queue_work);
	struct mhbw_jd_dma_cfg_word_0_s *jd_dma_cfg_word_0;
	struct mhbw_jd_dma_cfg_word_1_s *jd_dma_cfg_word_1;
	struct mhab_job_desc_cfg *jd_cfg_ptr;
	struct psm_cmd_addjob_s *psm_cmd_lo;
	struct tx_job_queue_cfg *job_cfg;
	struct tx_job_entry *job_entry;
	struct ptp_tstamp_skb *ts_skb;
	u16 psm_queue_id, queue_space;
	struct sk_buff *skb = NULL;
	struct list_head *head;
	u64 jd_cfg_ptr_iova;
	unsigned long flags;
	u64 regval;

	job_cfg = &priv->tx_ptp_job_cfg;

	spin_lock_irqsave(&job_cfg->lock, flags);

	/* check pending ptp requests */
	if (list_empty(&priv->ptp_skb_list.list)) {
		netif_dbg(priv, tx_queued, priv->netdev, "no pending ptp tx requests\n");
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return;
	}

	/* check psm queue space available */
	psm_queue_id = job_cfg->psm_queue_id;
	regval = readq(priv->psm_reg_base + PSM_QUEUE_SPACE(psm_queue_id));
	queue_space = regval & 0x7FFF;
	if (queue_space < 1) {
		netif_dbg(priv, tx_queued, priv->netdev, "ptp tx psm queue %d full\n",
			  psm_queue_id);
		/* reschedule to check later */
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		schedule_work(&priv->ptp_queue_work);
		return;
	}

	if (test_and_set_bit_lock(PTP_TX_IN_PROGRESS, &priv->state)) {
		netif_dbg(priv, tx_queued, priv->netdev, "ptp tx ongoing\n");
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return;
	}

	head = &priv->ptp_skb_list.list;
	ts_skb = list_entry(head->next, struct ptp_tstamp_skb, list);
	skb = ts_skb->skb;
	list_del(&ts_skb->list);
	kfree(ts_skb);
	priv->ptp_skb_list.count--;

	netif_dbg(priv, tx_queued, priv->netdev,
		  "submitting ptp tx skb %pS\n", skb);

	priv->last_tx_ptp_jiffies = jiffies;

	/* get the tx job entry */
	job_entry = (struct tx_job_entry *)
				&job_cfg->job_entries[job_cfg->q_idx];

	netif_dbg(priv, tx_queued, priv->netdev,
		  "rfoe=%d lmac=%d psm_queue=%d tx_job_entry %d job_cmd_lo=0x%llx job_cmd_high=0x%llx jd_iova_addr=0x%llx\n",
		  priv->rfoe_num, priv->lmac_id, psm_queue_id, job_cfg->q_idx,
		  job_entry->job_cmd_lo, job_entry->job_cmd_hi,
		  job_entry->jd_iova_addr);

	priv->ptp_tx_skb = skb;
	psm_cmd_lo = (struct psm_cmd_addjob_s *)&job_entry->job_cmd_lo;
	priv->ptp_job_tag = psm_cmd_lo->jobtag;

	/* update length and block size in jd dma cfg word */
	jd_cfg_ptr_iova = *(u64 *)((u8 __force *)job_entry->jd_ptr + 8);
	jd_cfg_ptr = (struct mhab_job_desc_cfg __force *)
		     otx2_iova_to_virt(priv->iommu_domain, jd_cfg_ptr_iova);
	jd_cfg_ptr->cfg1.pkt_len = skb->len;
	jd_dma_cfg_word_0 = (struct mhbw_jd_dma_cfg_word_0_s __force *)
				job_entry->rd_dma_ptr;
	jd_dma_cfg_word_0->block_size = (((skb->len + 15) >> 4) * 4);

	/* copy packet data to rd_dma_ptr start addr */
	jd_dma_cfg_word_1 = (struct mhbw_jd_dma_cfg_word_1_s *)
				((u8 __force *)job_entry->rd_dma_ptr + 8);
	memcpy((void __force *)otx2_iova_to_virt(priv->iommu_domain,
						 jd_dma_cfg_word_1->start_addr),
	       skb->data, skb->len);

	/* make sure that all memory writes are completed */
	dma_wmb();

	/* submit PSM job */
	writeq(job_entry->job_cmd_lo,
	       priv->psm_reg_base + PSM_QUEUE_CMD_LO(psm_queue_id));
	writeq(job_entry->job_cmd_hi,
	       priv->psm_reg_base + PSM_QUEUE_CMD_HI(psm_queue_id));

	/* increment queue index */
	job_cfg->q_idx++;
	if (job_cfg->q_idx == job_cfg->num_entries)
		job_cfg->q_idx = 0;

	spin_unlock_irqrestore(&job_cfg->lock, flags);
}

#define OTX2_RFOE_PTP_TSTMP_POLL_CNT	100

/* ptp interrupt processing bottom half */
static void otx2_rfoe_ptp_tx_work(struct work_struct *work)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(work,
						struct otx2_rfoe_ndev_priv,
						ptp_tx_work);
	struct skb_shared_hwtstamps ts;
	u64 timestamp, tstmp_w1;
	u16 jobid;
	int cnt;

	if (!priv->ptp_tx_skb) {
		netif_err(priv, tx_done, priv->netdev,
			  "ptp tx skb not found, something wrong!\n");
		goto submit_next_req;
	}

	/* poll for timestamp valid bit to go high */
	for (cnt = 0; cnt < OTX2_RFOE_PTP_TSTMP_POLL_CNT; cnt++) {
		/* read RFOE(0..2)_TX_PTP_TSTMP_W1(0..3) */
		tstmp_w1 = readq(priv->rfoe_reg_base +
				 RFOEX_TX_PTP_TSTMP_W1(priv->rfoe_num,
						       priv->lmac_id));
		/* check valid bit */
		if (tstmp_w1 & (1ULL << 63))
			break;
		usleep_range(5, 10);
	}

	if (cnt >= OTX2_RFOE_PTP_TSTMP_POLL_CNT) {
		netif_err(priv, tx_err, priv->netdev,
			  "ptp tx timestamp polling timeout, skb=%pS\n",
			  priv->ptp_tx_skb);
		priv->stats.tx_hwtstamp_failures++;
		goto submit_next_req;
	}

	/* check err or drop condition */
	if ((tstmp_w1 & (1ULL << 21)) || (tstmp_w1 & (1ULL << 20))) {
		netif_err(priv, tx_done, priv->netdev,
			  "ptp timestamp error tstmp_w1=0x%llx\n",
			  tstmp_w1);
		goto submit_next_req;
	}
	/* match job id */
	jobid = (tstmp_w1 >> 4) & 0xffff;
	if (jobid != priv->ptp_job_tag) {
		netif_err(priv, tx_done, priv->netdev,
			  "ptp job id doesn't match, tstmp_w1->job_id=0x%x skb->job_tag=0x%x\n",
			  jobid, priv->ptp_job_tag);
		goto submit_next_req;
	}
	/* update timestamp value in skb */
	timestamp = readq(priv->rfoe_reg_base +
			  RFOEX_TX_PTP_TSTMP_W0(priv->rfoe_num,
						priv->lmac_id));
	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN &&
	    priv->ptp_cfg->use_ptp_alg)
		otx2_rfoe_calc_ptp_ts(priv, &timestamp);
	else
		timestamp = timecounter_cyc2time(&priv->time_counter, timestamp);

	memset(&ts, 0, sizeof(ts));
	ts.hwtstamp = ns_to_ktime(timestamp);
	skb_tstamp_tx(priv->ptp_tx_skb, &ts);

submit_next_req:
	if (priv->ptp_tx_skb)
		dev_kfree_skb_any(priv->ptp_tx_skb);
	priv->ptp_tx_skb = NULL;
	clear_bit_unlock(PTP_TX_IN_PROGRESS, &priv->state);
	schedule_work(&priv->ptp_queue_work);
}

/* psm queue timer callback to check queue space */
static void otx2_rfoe_tx_timer_cb(struct timer_list *t)
{
	struct otx2_rfoe_ndev_priv *priv =
			container_of(t, struct otx2_rfoe_ndev_priv, tx_timer);
	int reschedule = 0, psm_qidx, psm_qpos;
	u16 psm_queue_id, queue_space;
	bool psm_queue_ena;
	u64 regval;

	/* check psm queue space for both ptp and oth packets */
	if (netif_queue_stopped(priv->netdev)) {
		psm_queue_id = priv->tx_ptp_job_cfg.psm_queue_id;
		/* check if psm queue is disabled */
		psm_qidx = psm_queue_id / 64;
		psm_qpos = psm_queue_id % 64;
		regval = readq(priv->psm_reg_base + PSM_QUEUE_ENA_W1S(psm_qidx));
		psm_queue_ena = (regval >> psm_qpos) & 0x1;
		if (unlikely(!psm_queue_ena)) {
			reschedule = 1;
			goto out;
		}
		// check queue space
		regval = readq(priv->psm_reg_base +
						PSM_QUEUE_SPACE(psm_queue_id));
		queue_space = regval & 0x7FFF;
		if (queue_space < 1) {
			reschedule = 1;
			goto out;
		}

		psm_queue_id = priv->rfoe_common->tx_oth_job_cfg.psm_queue_id;
		/* check if psm queue is disabled */
		psm_qidx = psm_queue_id / 64;
		psm_qpos = psm_queue_id % 64;
		regval = readq(priv->psm_reg_base + PSM_QUEUE_ENA_W1S(psm_qidx));
		psm_queue_ena = (regval >> psm_qpos) & 0x1;
		if (unlikely(!psm_queue_ena)) {
			reschedule = 1;
			goto out;
		}
		// check queue space
		regval = readq(priv->psm_reg_base +
						PSM_QUEUE_SPACE(psm_queue_id));
		queue_space = regval & 0x7FFF;
		if (queue_space < 1) {
			reschedule = 1;
			goto out;
		}
		netif_wake_queue(priv->netdev);
	}
out:
	if (reschedule)
		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
}

static void otx2_rfoe_dump_psw(struct otx2_rfoe_ndev_priv *priv, u8 *buf_ptr)
{
	netdev_err(priv->netdev,
		   "psw0(w0)=0x%llx psw0(w1)=0x%llx psw1(w0)=0x%llx psw1(w1)=0x%llx\n",
		   *(u64 *)buf_ptr, *((u64 *)buf_ptr + 1),
		   *((u64 *)buf_ptr + 2), *((u64 *)buf_ptr + 3));
}

static void otx2_rfoe_process_rx_pkt(struct otx2_rfoe_ndev_priv *priv,
				     struct rx_ft_cfg *ft_cfg, int mbt_buf_idx)
{
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	struct mhbw_jd_dma_cfg_word_0_s *jd_dma_cfg_word_0;
	struct rfoe_ecpri_psw0_s *ecpri_psw0 = NULL;
	struct rfoe_ecpri_psw1_s *ecpri_psw1 = NULL;
	u64 tstamp = 0, mbt_state, jdt_iova_addr;
	int found = 0, idx, len, pkt_type;
	struct otx2_rfoe_ndev_priv *priv2;
	struct otx2_rfoe_drv_ctx *drv_ctx;
	unsigned int ptp_message_len = 0;
	struct rfoe_psw0_s *psw0 = NULL;
	struct rfoe_psw1_s *psw1 = NULL;
	struct net_device *netdev;
	u8 *buf_ptr, *jdt_ptr;
	struct sk_buff *skb;
	u8 lmac_id;

	/* read mbt state */
	spin_lock(&cdev_priv->mbt_lock);
	writeq(mbt_buf_idx, (priv->rfoe_reg_base +
			 RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
	mbt_state = readq(priv->rfoe_reg_base +
			  RFOEX_RX_IND_MBT_SEG_STATE(priv->rfoe_num));
	spin_unlock(&cdev_priv->mbt_lock);

	buf_ptr = (u8 __force *)ft_cfg->mbt_virt_addr +
				(ft_cfg->buf_size * mbt_buf_idx);

	dma_rmb();

	pkt_type = ft_cfg->pkt_type;
#ifdef ASIM
	// ASIM issue, all rx packets will hit eCPRI flow table
	pkt_type = PACKET_TYPE_ECPRI;
#endif
	if (pkt_type != PACKET_TYPE_ECPRI) {
		psw0 = (struct rfoe_psw0_s *)buf_ptr;
		if (psw0->pkt_err_sts || psw0->dma_error) {
			net_warn_ratelimited("%s: psw0 pkt_err_sts = 0x%x, dma_err=0x%x\n",
					     priv->netdev->name,
					     psw0->pkt_err_sts,
					     psw0->dma_error);
			return;
		}
		/* check that the psw type is correct: */
		if (unlikely(psw0->pswt == ECPRI_TYPE)) {
			net_warn_ratelimited("%s: pswt is eCPRI for pkt_type = %d\n",
					     priv->netdev->name, pkt_type);
			return;
		}
		lmac_id = psw0->lmac_id;
		jdt_iova_addr = (u64)psw0->jd_ptr;
		psw1 = (struct rfoe_psw1_s *)(buf_ptr + 16);
		tstamp = psw1->ptp_timestamp;
	} else {
		ecpri_psw0 = (struct rfoe_ecpri_psw0_s *)buf_ptr;
		if (ecpri_psw0->err_sts & 0x1F) {
			net_warn_ratelimited("%s: ecpri_psw0 err_sts = 0x%x\n",
					     priv->netdev->name,
					     ecpri_psw0->err_sts);
			return;
		}
		/* check that the psw type is correct: */
		if (unlikely(ecpri_psw0->pswt != ECPRI_TYPE)) {
			net_warn_ratelimited("%s: pswt is not eCPRI for pkt_type = %d\n",
					     priv->netdev->name, pkt_type);
			return;
		}
		lmac_id = ecpri_psw0->src_id & 0x3;
		jdt_iova_addr = (u64)ecpri_psw0->jd_ptr;
		ecpri_psw1 = (struct rfoe_ecpri_psw1_s *)(buf_ptr + 16);
		tstamp = ecpri_psw1->ptp_timestamp;
	}

	if (unlikely(!jdt_iova_addr)) {
		netdev_err(priv->netdev, "JD_PTR was null at mbt_buf_idx %d\n", mbt_buf_idx);
		otx2_rfoe_dump_psw(priv, buf_ptr);
		return;
	}

	/* read jd ptr from psw */
	jdt_ptr = (u8 __force *)otx2_iova_to_virt(priv->iommu_domain, jdt_iova_addr);
	jd_dma_cfg_word_0 = (struct mhbw_jd_dma_cfg_word_0_s *)
			((u8 *)jdt_ptr + ft_cfg->jd_rd_offset);
	len = (jd_dma_cfg_word_0->block_size) << 2;
	netif_dbg(priv, rx_status, priv->netdev, "jd rd_dma len = %d\n", len);

	for (idx = 0; idx < RFOE_MAX_INTF; idx++) {
		drv_ctx = &rfoe_drv_ctx[idx];
		if (drv_ctx->valid && drv_ctx->rfoe_num == priv->rfoe_num &&
		    drv_ctx->lmac_id == lmac_id) {
			found = 1;
			break;
		}
	}
	if (found) {
		netdev = rfoe_drv_ctx[idx].netdev;
		priv2 = netdev_priv(netdev);
	} else {
		pr_err("netdev not found, something went wrong!\n");
		return;
	}

	if ((mbt_state >> 16 & 0xf) != 0) {
		pr_err("rx pkt error: mbt_buf_idx=%d, err=%d\n",
		       mbt_buf_idx, (u8)(mbt_state >> 16 & 0xf));
		goto drop_pkt;
	}

	if (mbt_state >> 20 & 0x1) {
		pr_err("rx dma error: mbt_buf_idx=%d\n", mbt_buf_idx);
		goto drop_pkt;
	}

	/* drop the packet if interface is down */
	if (unlikely(!netif_carrier_ok(netdev))) {
		netif_err(priv2, rx_err, netdev,
			  "%s {rfoe%d lmac%d} link down, drop pkt\n",
			  netdev->name, priv2->rfoe_num,
			  priv2->lmac_id);
		goto drop_pkt;
	}

	netif_dbg(priv2, rx_status, priv2->netdev,
		  "Rx: rfoe=%d lmac=%d mbt_buf_idx=%d psw0(w0)=0x%llx psw0(w1)=0x%llx psw1(w0)=0x%llx psw1(w1)=0x%llx jd:iova=0x%llx\n",
		  priv2->rfoe_num, lmac_id, mbt_buf_idx,
		  *(u64 *)buf_ptr, *((u64 *)buf_ptr + 1),
		  *((u64 *)buf_ptr + 2), *((u64 *)buf_ptr + 3),
		  jdt_iova_addr);

	if (unlikely(netif_msg_pktdata(priv2))) {
		netdev_printk(KERN_DEBUG, priv2->netdev, "RX MBUF DATA:");
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       buf_ptr, len, true);
	}

	buf_ptr += (ft_cfg->pkt_offset * 16);
	len -= (ft_cfg->pkt_offset * 16);

	skb = netdev_alloc_skb_ip_align(netdev, len);
	if (!skb) {
		netif_err(priv2, rx_err, netdev, "Rx: alloc skb failed\n");
		goto drop_pkt;
	}

	memcpy(skb->data, buf_ptr, len);
	skb_put(skb, len);
	skb->protocol = eth_type_trans(skb, netdev);

	/* remove trailing padding for ptp packets */
	if (skb->protocol == htons(ETH_P_1588)) {
		ptp_message_len = skb->data[2] << 8 | skb->data[3];
		skb_trim(skb, ptp_message_len);
	}

	if (priv2->rx_hw_tstamp_en) {
		if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN &&
		    priv->ptp_cfg->use_ptp_alg)
			otx2_rfoe_calc_ptp_ts(priv2, &tstamp);
		else
			tstamp = timecounter_cyc2time(&priv2->time_counter, tstamp);
		skb_hwtstamps(skb)->hwtstamp = ns_to_ktime(tstamp);
	}

	/* update stats */
	if (pkt_type == PACKET_TYPE_PTP) {
		priv2->stats.ptp_rx_packets++;
		priv2->last_rx_ptp_jiffies = jiffies;
	} else if (pkt_type == PACKET_TYPE_ECPRI) {
		priv2->stats.ecpri_rx_packets++;
		priv2->last_rx_jiffies = jiffies;
	} else {
		priv2->stats.rx_packets++;
		priv2->last_rx_jiffies = jiffies;
	}
	priv2->stats.rx_bytes += skb->len;

	netif_receive_skb(skb);
	return;

drop_pkt:
	/* update stats */
	if (pkt_type == PACKET_TYPE_PTP) {
		priv2->stats.ptp_rx_dropped++;
		priv2->last_rx_ptp_dropped_jiffies = jiffies;
	} else if (pkt_type == PACKET_TYPE_ECPRI) {
		priv2->stats.ecpri_rx_dropped++;
		priv2->last_rx_dropped_jiffies = jiffies;
	} else {
		priv2->stats.rx_dropped++;
		priv2->last_rx_dropped_jiffies = jiffies;
	}
}

static int otx2_rfoe_process_rx_flow(struct otx2_rfoe_ndev_priv *priv,
				     int pkt_type, int budget)
{
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	int count = 0, processed_pkts = 0;
	struct rx_ft_cfg *ft_cfg;
	u64 mbt_cfg;
	u16 nxt_buf;
	int *mbt_last_idx = &priv->rfoe_common->rx_mbt_last_idx[pkt_type];
	u16 *prv_nxt_buf = &priv->rfoe_common->nxt_buf[pkt_type];

	ft_cfg = &priv->rx_ft_cfg[pkt_type];

	spin_lock(&cdev_priv->mbt_lock);
	/* read mbt nxt_buf */
	writeq(ft_cfg->mbt_idx,
	       priv->rfoe_reg_base +
	       RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num));
	mbt_cfg = readq(priv->rfoe_reg_base +
			RFOEX_RX_IND_MBT_CFG(priv->rfoe_num));
	spin_unlock(&cdev_priv->mbt_lock);

	nxt_buf = (mbt_cfg >> 32) & 0xffff;

	/* no mbt entries to process */
	if (nxt_buf == *prv_nxt_buf) {
		netif_dbg(priv, rx_status, priv->netdev,
			  "no rx packets to process, rfoe=%d pkt_type=%d mbt_idx=%d nxt_buf=%d mbt_buf_sw_head=%d\n",
			  priv->rfoe_num, pkt_type, ft_cfg->mbt_idx, nxt_buf,
			  *mbt_last_idx);
		return 0;
	}

	*prv_nxt_buf = nxt_buf;

	/* get count of pkts to process, check ring wrap condition */
	if (*mbt_last_idx > nxt_buf) {
		count = ft_cfg->num_bufs - *mbt_last_idx;
		count += nxt_buf;
	} else {
		count = nxt_buf - *mbt_last_idx;
	}

	netif_dbg(priv, rx_status, priv->netdev,
		  "rfoe=%d pkt_type=%d mbt_idx=%d nxt_buf=%d mbt_buf_sw_head=%d count=%d\n",
		  priv->rfoe_num, pkt_type, ft_cfg->mbt_idx, nxt_buf,
		  *mbt_last_idx, count);

	while (likely((processed_pkts < budget) && (processed_pkts < count))) {
		otx2_rfoe_process_rx_pkt(priv, ft_cfg, *mbt_last_idx);

		(*mbt_last_idx)++;
		if (*mbt_last_idx == ft_cfg->num_bufs)
			*mbt_last_idx = 0;

		processed_pkts++;
	}

	return processed_pkts;
}

/* napi poll routine */
static int otx2_rfoe_napi_poll(struct napi_struct *napi, int budget)
{
	struct otx2_bphy_cdev_priv *cdev_priv;
	struct otx2_rfoe_ndev_priv *priv;
	int workdone = 0, pkt_type;
	struct rx_ft_cfg *ft_cfg;
	u64 intr_en, regval;

	ft_cfg = container_of(napi, struct rx_ft_cfg, napi);
	priv = ft_cfg->priv;
	cdev_priv = priv->cdev_priv;
	pkt_type = ft_cfg->pkt_type;

	/* pkt processing loop */
	workdone += otx2_rfoe_process_rx_flow(priv, pkt_type, budget);

	if (workdone < budget) {
		napi_complete_done(napi, workdone);

		/* Re enable the Rx interrupts */
		intr_en = PKT_TYPE_TO_INTR(pkt_type) <<
				RFOE_RX_INTR_SHIFT(priv->rfoe_num);
		spin_lock(&cdev_priv->lock);
		regval = readq(bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		regval |= intr_en;
		writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		spin_unlock(&cdev_priv->lock);
	}

	return workdone;
}

/* Rx GPINT napi schedule api */
void otx2_rfoe_rx_napi_schedule(int rfoe_num, u32 status)
{
	enum bphy_netdev_packet_type pkt_type;
	struct otx2_rfoe_drv_ctx *drv_ctx;
	struct otx2_rfoe_ndev_priv *priv;
	struct rx_ft_cfg *ft_cfg;
	int intf, bit_idx;
	u32 intr_sts;
	u64 regval;

	for (intf = 0; intf < RFOE_MAX_INTF; intf++) {
		drv_ctx = &rfoe_drv_ctx[intf];
		/* ignore lmac, one interrupt/pkt_type/rfoe */
		if (!(drv_ctx->valid && drv_ctx->rfoe_num == rfoe_num))
			continue;
		/* check if i/f down, napi disabled */
		priv = netdev_priv(drv_ctx->netdev);
		if (test_bit(RFOE_INTF_DOWN, &priv->state))
			continue;
		/* check rx pkt type */
		intr_sts = ((status >> RFOE_RX_INTR_SHIFT(rfoe_num)) &
			    RFOE_RX_INTR_EN);
		for (bit_idx = 0; bit_idx < PACKET_TYPE_MAX; bit_idx++) {
			if (!(intr_sts & BIT(bit_idx)))
				continue;
			pkt_type = INTR_TO_PKT_TYPE(bit_idx);
			if (unlikely(!(priv->pkt_type_mask & (1U << pkt_type))))
				continue;
			/* clear intr enable bit, re-enable in napi handler */
			regval = PKT_TYPE_TO_INTR(pkt_type) <<
				 RFOE_RX_INTR_SHIFT(rfoe_num);
			writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1C(1));
			/* schedule napi */
			ft_cfg = &drv_ctx->ft_cfg[pkt_type];
			napi_schedule(&ft_cfg->napi);
		}
		/* napi scheduled per pkt_type, return */
		return;
	}
}

static void otx2_rfoe_get_stats64(struct net_device *netdev,
				  struct rtnl_link_stats64 *stats)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct otx2_rfoe_stats *dev_stats = &priv->stats;

	stats->rx_bytes = dev_stats->rx_bytes;
	stats->rx_packets = dev_stats->rx_packets +
			    dev_stats->ptp_rx_packets +
			    dev_stats->ecpri_rx_packets;
	stats->rx_dropped = dev_stats->rx_dropped +
			    dev_stats->ptp_rx_dropped +
			    dev_stats->ecpri_rx_dropped;

	stats->tx_bytes = dev_stats->tx_bytes;
	stats->tx_packets = dev_stats->tx_packets +
			    dev_stats->ptp_tx_packets +
			    dev_stats->ecpri_tx_packets;
	stats->tx_dropped = dev_stats->tx_dropped +
			    dev_stats->ptp_tx_dropped +
			    dev_stats->ecpri_tx_dropped;
}

static int otx2_rfoe_config_hwtstamp(struct net_device *netdev,
				     struct ifreq *ifr)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct hwtstamp_config config;

	if (copy_from_user(&config, ifr->ifr_data, sizeof(config)))
		return -EFAULT;

	/* reserved for future extensions */
	if (config.flags)
		return -EINVAL;

	/* ptp hw timestamp is always enabled, mark the sw flags
	 * so that tx ptp requests are submitted to ptp psm queue
	 * and rx timestamp is copied to skb
	 */

	switch (config.tx_type) {
	case HWTSTAMP_TX_OFF:
		priv->tx_hw_tstamp_en = 0;
		break;
	case HWTSTAMP_TX_ON:
		priv->tx_hw_tstamp_en = 1;
		break;
	default:
		return -ERANGE;
	}

	switch (config.rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		priv->rx_hw_tstamp_en = 0;
		break;
	case HWTSTAMP_FILTER_ALL:
	case HWTSTAMP_FILTER_SOME:
	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		priv->rx_hw_tstamp_en = 1;
		break;
	default:
		return -ERANGE;
	}

	if (copy_to_user(ifr->ifr_data, &config, sizeof(config)))
		return -EFAULT;

	return 0;
}

/* netdev ioctl */
static int otx2_rfoe_ioctl(struct net_device *netdev, struct ifreq *req,
			   int cmd)
{
	switch (cmd) {
	case SIOCSHWTSTAMP:
		return otx2_rfoe_config_hwtstamp(netdev, req);
	default:
		return -EOPNOTSUPP;
	}
}

/* netdev xmit */
static netdev_tx_t otx2_rfoe_eth_start_xmit(struct sk_buff *skb,
					    struct net_device *netdev)
{
	int psm_queue_id, queue_space, psm_qidx, psm_qpos, pkt_type = 0;
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct mhbw_jd_dma_cfg_word_0_s *jd_dma_cfg_word_0;
	struct mhbw_jd_dma_cfg_word_1_s *jd_dma_cfg_word_1;
	struct mhab_job_desc_cfg *jd_cfg_ptr;
	struct psm_cmd_addjob_s *psm_cmd_lo;
	struct tx_job_queue_cfg *job_cfg;
	struct tx_job_entry *job_entry;
	struct ptp_tstamp_skb *ts_skb;
	u64 jd_cfg_ptr_iova, regval;
	unsigned long flags;
	struct ethhdr *eth;
	bool psm_queue_ena;

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) {
		if (!priv->tx_hw_tstamp_en) {
			netif_dbg(priv, tx_queued, priv->netdev,
				  "skb HW timestamp requested but not enabled, this packet will not be timestamped\n");
			job_cfg = &priv->rfoe_common->tx_oth_job_cfg;
			pkt_type = PACKET_TYPE_OTHER;
		} else {
			job_cfg = &priv->tx_ptp_job_cfg;
			pkt_type = PACKET_TYPE_PTP;
		}
	} else {
		job_cfg = &priv->rfoe_common->tx_oth_job_cfg;
		eth = (struct ethhdr *)skb->data;
		if (ntohs(eth->h_proto) == ETH_P_ECPRI)
			pkt_type = PACKET_TYPE_ECPRI;
		else
			pkt_type = PACKET_TYPE_OTHER;
	}

	spin_lock_irqsave(&job_cfg->lock, flags);

	if (unlikely(priv->if_type != IF_TYPE_ETHERNET)) {
		netif_err(priv, tx_queued, netdev,
			  "%s {rfoe%d lmac%d} invalid intf mode, drop pkt\n",
			  netdev->name, priv->rfoe_num, priv->lmac_id);
		/* update stats */
		priv->stats.tx_dropped++;
		priv->last_tx_dropped_jiffies = jiffies;
		goto exit;
	}

	if (unlikely(!netif_carrier_ok(netdev))) {
		netif_err(priv, tx_err, netdev,
			  "%s {rfoe%d lmac%d} link down, drop pkt\n",
			  netdev->name, priv->rfoe_num,
			  priv->lmac_id);
		/* update stats */
		if (pkt_type == PACKET_TYPE_ECPRI) {
			priv->stats.ecpri_tx_dropped++;
			priv->last_tx_dropped_jiffies = jiffies;
		} else if (pkt_type == PACKET_TYPE_PTP) {
			priv->stats.ptp_tx_dropped++;
			priv->last_tx_ptp_dropped_jiffies = jiffies;
		} else {
			priv->stats.tx_dropped++;
			priv->last_tx_dropped_jiffies = jiffies;
		}

		goto exit;
	}

	if (unlikely(!(priv->pkt_type_mask & (1U << pkt_type)))) {
		netif_err(priv, tx_queued, netdev,
			  "%s {rfoe%d lmac%d} pkt not supported, drop pkt\n",
			  netdev->name, priv->rfoe_num,
			  priv->lmac_id);
		/* update stats */
		if (pkt_type == PACKET_TYPE_ECPRI) {
			priv->stats.ecpri_tx_dropped++;
			priv->last_tx_dropped_jiffies = jiffies;
		} else if (pkt_type == PACKET_TYPE_PTP) {
			priv->stats.ptp_tx_dropped++;
			priv->last_tx_ptp_dropped_jiffies = jiffies;
		} else {
			priv->stats.tx_dropped++;
			priv->last_tx_dropped_jiffies = jiffies;
		}

		goto exit;
	}

	/* get psm queue number */
	psm_queue_id = job_cfg->psm_queue_id;
	netif_dbg(priv, tx_queued, priv->netdev,
		  "psm: queue(%d): cfg=0x%llx ptr=0x%llx space=0x%llx\n",
		  psm_queue_id,
		  readq(priv->psm_reg_base + PSM_QUEUE_CFG(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_PTR(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_SPACE(psm_queue_id)));

	/* check if psm queue is disabled */
	psm_qidx = psm_queue_id / 64;
	psm_qpos = psm_queue_id % 64;
	regval = readq(priv->psm_reg_base + PSM_QUEUE_ENA_W1S(psm_qidx));
	psm_queue_ena = (regval >> psm_qpos) & 0x1;
	if (unlikely(!psm_queue_ena)) {
		dev_err_ratelimited(&netdev->dev,
				    "psm queue %d is disabled, dropping pkt\n",
				    psm_queue_id);
		netif_stop_queue(netdev);
		dev_kfree_skb_any(skb);
		/* update stats */
		if (pkt_type == PACKET_TYPE_ECPRI)
			priv->stats.ecpri_tx_dropped++;
		else
			priv->stats.tx_dropped++;

		priv->last_tx_dropped_jiffies = jiffies;

		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return NETDEV_TX_OK;
	}

	/* check psm queue space available */
	regval = readq(priv->psm_reg_base + PSM_QUEUE_SPACE(psm_queue_id));
	queue_space = regval & 0x7FFF;
	if (queue_space < 1 && pkt_type != PACKET_TYPE_PTP) {
		netif_err(priv, tx_err, netdev,
			  "no space in psm queue %d, dropping pkt\n",
			   psm_queue_id);
		netif_stop_queue(netdev);
		dev_kfree_skb_any(skb);
		/* update stats */
		if (pkt_type == PACKET_TYPE_ECPRI)
			priv->stats.ecpri_tx_dropped++;
		else
			priv->stats.tx_dropped++;

		priv->last_tx_dropped_jiffies = jiffies;

		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return NETDEV_TX_OK;
	}

	/* get the tx job entry */
	job_entry = (struct tx_job_entry *)
				&job_cfg->job_entries[job_cfg->q_idx];

	netif_dbg(priv, tx_queued, priv->netdev,
		  "rfoe=%d lmac=%d psm_queue=%d tx_job_entry %d job_cmd_lo=0x%llx job_cmd_high=0x%llx jd_iova_addr=0x%llx\n",
		  priv->rfoe_num, priv->lmac_id, psm_queue_id, job_cfg->q_idx,
		  job_entry->job_cmd_lo, job_entry->job_cmd_hi,
		  job_entry->jd_iova_addr);

	/* hw timestamp */
	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) &&
	    priv->tx_hw_tstamp_en) {
		if (list_empty(&priv->ptp_skb_list.list) &&
		    !test_and_set_bit_lock(PTP_TX_IN_PROGRESS, &priv->state)) {
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
			priv->ptp_tx_skb = skb;
			psm_cmd_lo = (struct psm_cmd_addjob_s *)
						&job_entry->job_cmd_lo;
			priv->ptp_job_tag = psm_cmd_lo->jobtag;
		} else {
			/* check ptp queue count */
			if (priv->ptp_skb_list.count >= max_ptp_req) {
				netif_err(priv, tx_err, netdev,
					  "ptp list full, dropping pkt\n");
				priv->stats.ptp_tx_dropped++;
				priv->last_tx_ptp_dropped_jiffies = jiffies;
				goto exit;
			}
			/* allocate and add ptp req to queue */
			ts_skb = kmalloc(sizeof(*ts_skb), GFP_ATOMIC);
			if (!ts_skb) {
				priv->stats.ptp_tx_dropped++;
				priv->last_tx_ptp_dropped_jiffies = jiffies;
				goto exit;
			}
			ts_skb->skb = skb;
			list_add_tail(&ts_skb->list, &priv->ptp_skb_list.list);
			priv->ptp_skb_list.count++;
			skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
			priv->stats.ptp_tx_packets++;
			priv->stats.tx_bytes += skb->len;
			/* sw timestamp */
			skb_tx_timestamp(skb);
			goto exit;	/* submit the packet later */
		}
	}

	/* sw timestamp */
	skb_tx_timestamp(skb);

	if (unlikely(netif_msg_pktdata(priv))) {
		netdev_printk(KERN_DEBUG, priv->netdev, "Tx: skb %pS len=%d\n",
			      skb, skb->len);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       skb->data, skb->len, true);
	}

	/* update length and block size in jd dma cfg word */
	jd_cfg_ptr_iova = *(u64 *)((u8 __force *)job_entry->jd_ptr + 8);
	jd_cfg_ptr = (struct mhab_job_desc_cfg __force *)
		     otx2_iova_to_virt(priv->iommu_domain, jd_cfg_ptr_iova);
	jd_cfg_ptr->cfg1.pkt_len = skb->len;
	jd_dma_cfg_word_0 = (struct mhbw_jd_dma_cfg_word_0_s __force *)
						job_entry->rd_dma_ptr;
	jd_dma_cfg_word_0->block_size = (((skb->len + 15) >> 4) * 4);

	/* update rfoe_mode and lmac id for non-ptp (shared) psm job entry */
	if (pkt_type != PACKET_TYPE_PTP) {
		jd_cfg_ptr->cfg.lmacid = priv->lmac_id & 0x3;
		if (pkt_type == PACKET_TYPE_ECPRI)
			jd_cfg_ptr->cfg.rfoe_mode = 1;
		else
			jd_cfg_ptr->cfg.rfoe_mode = 0;
	}

	/* copy packet data to rd_dma_ptr start addr */
	jd_dma_cfg_word_1 = (struct mhbw_jd_dma_cfg_word_1_s *)
					((u8 __force *)job_entry->rd_dma_ptr + 8);
	memcpy((void __force *)otx2_iova_to_virt(priv->iommu_domain,
						 jd_dma_cfg_word_1->start_addr),
	       skb->data, skb->len);

	/* make sure that all memory writes are completed */
	dma_wmb();

	/* submit PSM job */
	writeq(job_entry->job_cmd_lo,
	       priv->psm_reg_base + PSM_QUEUE_CMD_LO(psm_queue_id));
	writeq(job_entry->job_cmd_hi,
	       priv->psm_reg_base + PSM_QUEUE_CMD_HI(psm_queue_id));

	/* update stats */
	if (pkt_type == PACKET_TYPE_ECPRI) {
		priv->stats.ecpri_tx_packets++;
		priv->last_tx_jiffies = jiffies;
	} else if (pkt_type == PACKET_TYPE_PTP) {
		priv->stats.ptp_tx_packets++;
		priv->last_tx_ptp_jiffies = jiffies;
	} else {
		priv->stats.tx_packets++;
		priv->last_tx_jiffies = jiffies;
	}
	priv->stats.tx_bytes += skb->len;

	/* increment queue index */
	job_cfg->q_idx++;
	if (job_cfg->q_idx == job_cfg->num_entries)
		job_cfg->q_idx = 0;
exit:
	if (!(skb_shinfo(skb)->tx_flags & SKBTX_IN_PROGRESS))
		dev_kfree_skb_any(skb);

	spin_unlock_irqrestore(&job_cfg->lock, flags);

	return NETDEV_TX_OK;
}

static int otx2_rfoe_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;

	netdev_info(netdev, "changed MTU to %d\n", new_mtu);
	return 0;
}

/* netdev open */
static int otx2_rfoe_eth_open(struct net_device *netdev)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	int idx;

	for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
		if (!(priv->pkt_type_mask & (1U << idx)))
			continue;
		napi_enable(&priv->rx_ft_cfg[idx].napi);
	}

	priv->ptp_tx_skb = NULL;

	spin_lock(&priv->lock);
	clear_bit(RFOE_INTF_DOWN, &priv->state);

	if (priv->link_state == LINK_STATE_UP) {
		netif_carrier_on(netdev);
		netif_start_queue(netdev);
	}
	spin_unlock(&priv->lock);

	return 0;
}

/* netdev close */
static int otx2_rfoe_eth_stop(struct net_device *netdev)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct ptp_tstamp_skb *ts_skb, *ts_skb2;
	int idx;

	spin_lock(&priv->lock);
	set_bit(RFOE_INTF_DOWN, &priv->state);

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	spin_unlock(&priv->lock);

	for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
		if (!(priv->pkt_type_mask & (1U << idx)))
			continue;
		napi_disable(&priv->rx_ft_cfg[idx].napi);
	}

	del_timer_sync(&priv->tx_timer);

	/* cancel any pending ptp work item in progress */
	cancel_work_sync(&priv->ptp_tx_work);
	if (priv->ptp_tx_skb) {
		dev_kfree_skb_any(priv->ptp_tx_skb);
		priv->ptp_tx_skb = NULL;
		clear_bit_unlock(PTP_TX_IN_PROGRESS, &priv->state);
	}

	/* clear ptp skb list */
	cancel_work_sync(&priv->ptp_queue_work);
	list_for_each_entry_safe(ts_skb, ts_skb2,
				 &priv->ptp_skb_list.list, list) {
		list_del(&ts_skb->list);
		kfree(ts_skb);
	}
	priv->ptp_skb_list.count = 0;

	return 0;
}

static int otx2_rfoe_init(struct net_device *netdev)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	/* Enable VLAN TPID match */
	writeq(0x18100, (priv->rfoe_reg_base +
			 RFOEX_RX_VLANX_CFG(priv->rfoe_num, 0)));
	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;

	return 0;
}

static int otx2_rfoe_vlan_rx_configure(struct net_device *netdev, u16 vid,
				       bool forward)
{
	struct rfoe_rx_ind_vlanx_fwd fwd;
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	u64 index = (vid >> 6) & 0x3F;
	u64 mask = (0x1ll << (vid & 0x3F));
	unsigned long flags;

	if (vid >= VLAN_N_VID) {
		netdev_err(netdev, "Invalid VLAN ID %d\n", vid);
		return -EINVAL;
	}

	spin_lock_irqsave(&cdev_priv->mbt_lock, flags);

	if (forward && priv->rfoe_common->rx_vlan_fwd_refcnt[vid]++)
		goto out;

	if (!forward && --priv->rfoe_common->rx_vlan_fwd_refcnt[vid])
		goto out;

	/* read current fwd mask */
	writeq(index, (priv->rfoe_reg_base +
		       RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
	fwd.fwd = readq(priv->rfoe_reg_base +
			RFOEX_RX_IND_VLANX_FWD(priv->rfoe_num, 0));

	if (forward)
		fwd.fwd |= mask;
	else
		fwd.fwd &= ~mask;

	/* write the new fwd mask */
	writeq(index, (priv->rfoe_reg_base +
		       RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
	writeq(fwd.fwd, (priv->rfoe_reg_base +
			 RFOEX_RX_IND_VLANX_FWD(priv->rfoe_num, 0)));

out:
	spin_unlock_irqrestore(&cdev_priv->mbt_lock, flags);

	return 0;
}

static int otx2_rfoe_vlan_rx_add(struct net_device *netdev, __be16 proto,
				 u16 vid)
{
	return otx2_rfoe_vlan_rx_configure(netdev, vid, true);
}

static int otx2_rfoe_vlan_rx_kill(struct net_device *netdev, __be16 proto,
				  u16 vid)
{
	return otx2_rfoe_vlan_rx_configure(netdev, vid, false);
}

static const struct net_device_ops otx2_rfoe_netdev_ops = {
	.ndo_init		= otx2_rfoe_init,
	.ndo_open		= otx2_rfoe_eth_open,
	.ndo_stop		= otx2_rfoe_eth_stop,
	.ndo_start_xmit		= otx2_rfoe_eth_start_xmit,
	.ndo_change_mtu		= otx2_rfoe_change_mtu,
	.ndo_eth_ioctl		= otx2_rfoe_ioctl,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64	= otx2_rfoe_get_stats64,
	.ndo_vlan_rx_add_vid	= otx2_rfoe_vlan_rx_add,
	.ndo_vlan_rx_kill_vid	= otx2_rfoe_vlan_rx_kill,
};

static void otx2_rfoe_dump_rx_ft_cfg(struct otx2_rfoe_ndev_priv *priv)
{
	struct rx_ft_cfg *ft_cfg;
	int idx;

	for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
		if (!(priv->pkt_type_mask & (1U << idx)))
			continue;
		ft_cfg = &priv->rx_ft_cfg[idx];
		pr_debug("rfoe=%d lmac=%d pkttype=%d flowid=%d mbt: idx=%d size=%d nbufs=%d iova=0x%llx jdt: idx=%d size=%d num_jd=%d iova=0x%llx\n",
			 priv->rfoe_num, priv->lmac_id, ft_cfg->pkt_type,
			 ft_cfg->flow_id, ft_cfg->mbt_idx, ft_cfg->buf_size,
			 ft_cfg->num_bufs, ft_cfg->mbt_iova_addr,
			 ft_cfg->jdt_idx, ft_cfg->jd_size, ft_cfg->num_jd,
			 ft_cfg->jdt_iova_addr);
	}
}

static inline void otx2_rfoe_fill_rx_ft_cfg(struct otx2_rfoe_ndev_priv *priv,
					    struct bphy_netdev_comm_if *if_cfg)
{
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	struct bphy_netdev_rbuf_info *rbuf_info;
	struct rx_ft_cfg *ft_cfg;
	u64 jdt_cfg0, iova;
	int idx;

	/* RX flow table configuration */
	for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
		if (!(priv->pkt_type_mask & (1U << idx)))
			continue;
		ft_cfg = &priv->rx_ft_cfg[idx];
		rbuf_info = &if_cfg->rbuf_info[idx];
		ft_cfg->pkt_type = rbuf_info->pkt_type;
		ft_cfg->gp_int_num = rbuf_info->gp_int_num;
		ft_cfg->flow_id = rbuf_info->flow_id;
		ft_cfg->mbt_idx = rbuf_info->mbt_index;
		ft_cfg->buf_size = rbuf_info->buf_size * 16;
		ft_cfg->num_bufs = rbuf_info->num_bufs;
		ft_cfg->mbt_iova_addr = rbuf_info->mbt_iova_addr;
		iova = ft_cfg->mbt_iova_addr;
		ft_cfg->mbt_virt_addr = otx2_iova_to_virt(priv->iommu_domain,
							  iova);
		ft_cfg->jdt_idx = rbuf_info->jdt_index;
		ft_cfg->jd_size = rbuf_info->jd_size * 8;
		ft_cfg->num_jd = rbuf_info->num_jd;
		ft_cfg->jdt_iova_addr = rbuf_info->jdt_iova_addr;
		iova = ft_cfg->jdt_iova_addr;
		ft_cfg->jdt_virt_addr = otx2_iova_to_virt(priv->iommu_domain,
							  iova);
		spin_lock(&cdev_priv->mbt_lock);
		writeq(ft_cfg->jdt_idx,
		       (priv->rfoe_reg_base +
			RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
		jdt_cfg0 = readq(priv->rfoe_reg_base +
				 RFOEX_RX_IND_JDT_CFG0(priv->rfoe_num));
		spin_unlock(&cdev_priv->mbt_lock);
		ft_cfg->jd_rd_offset = ((jdt_cfg0 >> 28) & 0xf) * 8;
		ft_cfg->pkt_offset = (u8)((jdt_cfg0 >> 52) & 0x7);
		ft_cfg->priv = priv;
		netif_napi_add(priv->netdev, &ft_cfg->napi,
			       otx2_rfoe_napi_poll,
			       NAPI_POLL_WEIGHT);
	}
}

static void otx2_rfoe_fill_tx_job_entries(struct otx2_rfoe_ndev_priv *priv,
					  struct tx_job_queue_cfg *job_cfg,
				struct bphy_netdev_tx_psm_cmd_info *tx_job,
					  int num_entries)
{
	struct tx_job_entry *job_entry;
	u64 jd_cfg_iova, iova;
	int i;

	for (i = 0; i < num_entries; i++) {
		job_entry = &job_cfg->job_entries[i];
		job_entry->job_cmd_lo = tx_job->low_cmd;
		job_entry->job_cmd_hi = tx_job->high_cmd;
		job_entry->jd_iova_addr = tx_job->jd_iova_addr;
		iova = job_entry->jd_iova_addr;
		job_entry->jd_ptr = otx2_iova_to_virt(priv->iommu_domain, iova);
		jd_cfg_iova = *(u64 *)((u8 __force *)job_entry->jd_ptr + 8);
		job_entry->jd_cfg_ptr = otx2_iova_to_virt(priv->iommu_domain,
							  jd_cfg_iova);
		job_entry->rd_dma_iova_addr = tx_job->rd_dma_iova_addr;
		iova = job_entry->rd_dma_iova_addr;
		job_entry->rd_dma_ptr = otx2_iova_to_virt(priv->iommu_domain,
							  iova);
		pr_debug("job_cmd_lo=0x%llx job_cmd_hi=0x%llx jd_iova_addr=0x%llx rd_dma_iova_addr=%llx\n",
			 tx_job->low_cmd, tx_job->high_cmd,
			 tx_job->jd_iova_addr, tx_job->rd_dma_iova_addr);
		tx_job++;
	}
	/* get psm queue id */
	job_entry = &job_cfg->job_entries[0];
	job_cfg->psm_queue_id = (job_entry->job_cmd_lo >> 8) & 0xff;
	job_cfg->q_idx = 0;
	job_cfg->num_entries = num_entries;
	spin_lock_init(&job_cfg->lock);
}

int otx2_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				  struct bphy_netdev_comm_intf_cfg *cfg)
{
	int i, intf_idx = 0, num_entries, lmac, idx, ret;
	struct bphy_netdev_tx_psm_cmd_info *tx_info;
	struct otx2_rfoe_drv_ctx *drv_ctx = NULL;
	struct otx2_rfoe_ndev_priv *priv, *priv2;
	struct bphy_netdev_rfoe_if *rfoe_cfg;
	struct bphy_netdev_comm_if *if_cfg;
	struct tx_job_queue_cfg *tx_cfg;
	struct ptp_bcn_off_cfg *ptp_cfg;
	struct net_device *netdev;
	struct rx_ft_cfg *ft_cfg;
	u8 pkt_type_mask;

	cdev->num_rfoe_mhab = 3;
	cdev->num_rfoe_lmac = 4;
	cdev->tot_rfoe_intf = 10; /* 2 rfoe x 4 lmac + 1 rfoe x 2 lmac */

	ptp_cfg = kzalloc(sizeof(*ptp_cfg), GFP_KERNEL);
	if (!ptp_cfg)
		return -ENOMEM;
	timer_setup(&ptp_cfg->ptp_timer, otx2_rfoe_ptp_offset_timer, 0);
	ptp_cfg->clk_cfg.clk_freq_ghz = PTP_CLK_FREQ_GHZ;
	ptp_cfg->clk_cfg.clk_freq_div = PTP_CLK_FREQ_DIV;
	spin_lock_init(&ptp_cfg->lock);

	for (i = 0; i < cdev->num_rfoe_mhab; i++) {
		priv2 = NULL;
		rfoe_cfg = &cfg[i].rfoe_if_cfg;
		pkt_type_mask = rfoe_cfg->pkt_type_mask;
		for (lmac = 0; lmac < cdev->num_rfoe_lmac; lmac++) {
			intf_idx = (i * cdev->num_rfoe_lmac) + lmac;
			if (intf_idx >= cdev->tot_rfoe_intf) {
				dev_dbg(cdev->dev,
					"rfoe%d lmac%d doesn't exist, skipping intf cfg\n",
					i, lmac);
				continue;
			}
			if_cfg = &rfoe_cfg->if_cfg[lmac];
			/* check if lmac is valid */
			if (!if_cfg->lmac_info.is_valid) {
				dev_dbg(cdev->dev,
					"rfoe%d lmac%d invalid intf cfg, skipping\n", i, lmac);
				continue;
			}
			netdev =
			    alloc_etherdev(sizeof(struct otx2_rfoe_ndev_priv));
			if (!netdev) {
				dev_err(cdev->dev,
					"error allocating net device\n");
				ret = -ENOMEM;
				goto err_exit;
			}
			priv = netdev_priv(netdev);
			memset(priv, 0, sizeof(*priv));
			if (!priv2) {
				priv->rfoe_common =
					kzalloc(sizeof(struct rfoe_common_cfg),
						GFP_KERNEL);
				if (!priv->rfoe_common) {
					dev_err(cdev->dev, "kzalloc failed\n");
					free_netdev(netdev);
					ret = -ENOMEM;
					goto err_exit;
				}
				priv->rfoe_common->refcnt = 1;
			}
			spin_lock_init(&priv->lock);
			priv->netdev = netdev;
			priv->cdev_priv = cdev;
			priv->msg_enable = netif_msg_init(-1, 0);
			spin_lock_init(&priv->stats.lock);
			priv->rfoe_num = if_cfg->lmac_info.rfoe_num;
			priv->lmac_id = if_cfg->lmac_info.lane_num;
			priv->if_type = cfg[i].if_type;
			memcpy(priv->mac_addr, if_cfg->lmac_info.eth_addr,
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
			priv->psm_reg_base = psm_reg_base;
			priv->rfoe_reg_base = rfoe_reg_base;
			priv->bcn_reg_base = bcn_reg_base;
			priv->ptp_reg_base = ptp_reg_base;
			priv->ptp_cfg = ptp_cfg;
			++(priv->ptp_cfg->refcnt);

			/* Initialise PTP TX work queue */
			INIT_WORK(&priv->ptp_tx_work, otx2_rfoe_ptp_tx_work);
			INIT_WORK(&priv->ptp_queue_work,
				  otx2_rfoe_ptp_submit_work);

			/* Initialise PTP skb list */
			INIT_LIST_HEAD(&priv->ptp_skb_list.list);
			priv->ptp_skb_list.count = 0;
			timer_setup(&priv->tx_timer, otx2_rfoe_tx_timer_cb, 0);

			priv->pkt_type_mask = pkt_type_mask;
			otx2_rfoe_fill_rx_ft_cfg(priv, if_cfg);
			otx2_rfoe_dump_rx_ft_cfg(priv);

			/* TX PTP job configuration */
			if (priv->pkt_type_mask & (1U << PACKET_TYPE_PTP)) {
				tx_cfg = &priv->tx_ptp_job_cfg;
				tx_info = &if_cfg->ptp_pkt_info[0];
				num_entries = MAX_PTP_MSG_PER_LMAC;
				otx2_rfoe_fill_tx_job_entries(priv, tx_cfg,
							      tx_info,
							      num_entries);
			}

			/* TX ECPRI/OTH(PTP) job configuration */
			if (!priv2 &&
			    ((priv->pkt_type_mask &
			      (1U << PACKET_TYPE_OTHER)) ||
			     (priv->pkt_type_mask &
			      (1U << PACKET_TYPE_ECPRI)))) {
				/* RFOE 2 will have 2 LMAC's */
				num_entries = (priv->rfoe_num < 2) ?
						MAX_OTH_MSG_PER_RFOE : 32;
				tx_cfg = &priv->rfoe_common->tx_oth_job_cfg;
				tx_info = &rfoe_cfg->oth_pkt_info[0];
				otx2_rfoe_fill_tx_job_entries(priv, tx_cfg,
							      tx_info,
							      num_entries);
			} else if (priv2) {
				/* share rfoe_common data */
				priv->rfoe_common = priv2->rfoe_common;
				++(priv->rfoe_common->refcnt);
			}

			/* keep last (rfoe + lmac) priv structure */
			if (!priv2)
				priv2 = priv;

			snprintf(netdev->name, sizeof(netdev->name),
				 "rfoe%d", intf_idx);
			netdev->netdev_ops = &otx2_rfoe_netdev_ops;
			otx2_rfoe_set_ethtool_ops(netdev);
			otx2_rfoe_ptp_init(priv);
			netdev->watchdog_timeo = (15 * HZ);
			netdev->mtu = 1500U;
			netdev->min_mtu = ETH_MIN_MTU;
			netdev->max_mtu = OTX2_RFOE_MAX_MTU;
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
			set_bit(RFOE_INTF_DOWN, &priv->state);
			priv->link_state = LINK_STATE_UP;

			/* initialize global ctx */
			drv_ctx = &rfoe_drv_ctx[intf_idx];
			drv_ctx->rfoe_num = priv->rfoe_num;
			drv_ctx->lmac_id = priv->lmac_id;
			drv_ctx->valid = 1;
			drv_ctx->netdev = netdev;
			drv_ctx->ft_cfg = &priv->rx_ft_cfg[0];

			/* create debugfs entry */
			otx2_rfoe_debugfs_create(drv_ctx);
		}
	}

	return 0;

err_exit:
	for (i = 0; i < RFOE_MAX_INTF; i++) {
		drv_ctx = &rfoe_drv_ctx[i];
		if (drv_ctx->valid) {
			otx2_rfoe_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			otx2_rfoe_ptp_destroy(priv);
			unregister_netdev(netdev);
			for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
				if (!(priv->pkt_type_mask & (1U << idx)))
					continue;
				ft_cfg = &priv->rx_ft_cfg[idx];
				netif_napi_del(&ft_cfg->napi);
			}
			--(priv->rfoe_common->refcnt);
			if (priv->rfoe_common->refcnt == 0)
				kfree(priv->rfoe_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}
	del_timer_sync(&ptp_cfg->ptp_timer);
	kfree(ptp_cfg);

	return ret;
}

static void otx2_rfoe_debugfs_reader(char *buffer, size_t count, void *priv)
{
	struct otx2_rfoe_drv_ctx *ctx;
	struct otx2_rfoe_ndev_priv *netdev;
	u8 ptp_tx_in_progress;
	unsigned int queued_ptp_reqs;
	u8 queue_stopped, state_up;
	u16 other_tx_psm_space, ptp_tx_psm_space, queue_id;
	u64 regval;
	const char *formatter;

	ctx = priv;
	netdev = netdev_priv(ctx->netdev);
	ptp_tx_in_progress = test_bit(PTP_TX_IN_PROGRESS, &netdev->state);
	queued_ptp_reqs = netdev->ptp_skb_list.count;
	queue_stopped = netif_queue_stopped(ctx->netdev);
	state_up = netdev->link_state;
	formatter = otx2_rfoe_debugfs_get_formatter();

	/* other tx psm space */
	queue_id = netdev->rfoe_common->tx_oth_job_cfg.psm_queue_id;
	regval = readq(netdev->psm_reg_base + PSM_QUEUE_SPACE(queue_id));
	other_tx_psm_space = regval & 0x7FFF;

	/* ptp tx psm space */
	queue_id = netdev->tx_ptp_job_cfg.psm_queue_id;
	regval = readq(netdev->psm_reg_base + PSM_QUEUE_SPACE(queue_id));
	ptp_tx_psm_space = regval & 0x7FFF;

	snprintf(buffer, count, formatter,
		 ptp_tx_in_progress,
		 queued_ptp_reqs,
		 queue_stopped,
		 state_up,
		 netdev->last_tx_jiffies,
		 netdev->last_tx_dropped_jiffies,
		 netdev->last_tx_ptp_jiffies,
		 netdev->last_tx_ptp_dropped_jiffies,
		 netdev->last_rx_jiffies,
		 netdev->last_rx_dropped_jiffies,
		 netdev->last_rx_ptp_jiffies,
		 netdev->last_rx_ptp_dropped_jiffies,
		 jiffies,
		 other_tx_psm_space,
		 ptp_tx_psm_space);
}

static const char *otx2_rfoe_debugfs_get_formatter(void)
{
	static const char *buffer_format = "ptp-tx-in-progress: %u\n"
					   "queued-ptp-reqs: %u\n"
					   "queue-stopped: %u\n"
					   "state-up: %u\n"
					   "last-tx-jiffies: %lu\n"
					   "last-tx-dropped-jiffies: %lu\n"
					   "last-tx-ptp-jiffies: %lu\n"
					   "last-tx-ptp-dropped-jiffies: %lu\n"
					   "last-rx-jiffies: %lu\n"
					   "last-rx-dropped-jiffies: %lu\n"
					   "last-rx-ptp-jiffies: %lu\n"
					   "last-rx-ptp-dropped-jiffies: %lu\n"
					   "current-jiffies: %lu\n"
					   "other-tx-psm-space: %u\n"
					   "ptp-tx-psm-space: %u\n";

	return buffer_format;
}

static size_t otx2_rfoe_debugfs_get_buffer_size(void)
{
	static size_t buffer_size;

	if (!buffer_size) {
		const char *formatter = otx2_rfoe_debugfs_get_formatter();
		u8 max_boolean = 1;
		int max_ptp_req_count = max_ptp_req;
		unsigned long max_jiffies = (unsigned long)-1;
		u16 max_psm_space = (u16)-1;

		buffer_size = snprintf(NULL, 0, formatter,
				       max_boolean,
				       max_ptp_req_count,
				       max_boolean,
				       max_boolean,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_psm_space,
				       max_psm_space);
		++buffer_size;
	}

	return buffer_size;
}

static void otx2_rfoe_debugfs_create(struct otx2_rfoe_drv_ctx *ctx)
{
	size_t buffer_size = otx2_rfoe_debugfs_get_buffer_size();

	ctx->root = otx2_bphy_debugfs_add_dir(ctx->netdev->name);
	if (!ctx->root)
		return;

	ctx->debugfs = otx2_bphy_debugfs_add_file("ptp_jiffies_counter",
						  buffer_size, ctx,
						  otx2_rfoe_debugfs_reader);
	otx2_debugfs_add_jdt_ring_file(ctx);
	otx2_debugfs_add_tstamp_ring_file(ctx);
	otx2_debugfs_add_rpm_stats_file(ctx);
}

static void otx2_rfoe_debugfs_remove(struct otx2_rfoe_drv_ctx *ctx)
{
	if (ctx->debugfs)
		otx2_bphy_debugfs_remove_file(ctx->debugfs);

	debugfs_remove_recursive(ctx->root);
}

void otx2_rfoe_set_link_state(struct net_device *netdev, u8 state)
{
	struct otx2_rfoe_ndev_priv *priv;

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
