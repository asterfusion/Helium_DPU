// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include "cnf10k_rfoe.h"
#include "otx2_bphy_debugfs.h"
#include "cnf10k_bphy_hw.h"
#include <net/checksum.h>
#include <net/ip6_checksum.h>

#define PTP_PORT               0x13F
/* Original timestamp offset starts at 34 byte in PTP Sync packet and its
 * divided as 6 byte seconds field and 4 byte nano seconds field.
 * Silicon supports only 4 byte seconds field so adjust seconds field
 * offset with 2
 */
#define PTP_SYNC_SEC_OFFSET    34
#define PTP_SYNC_NSEC_OFFSET   40
#define ECPRI_REQ_SEC_OFFSET    2
#define PACKET_ECPRI5_NO_TS  0xff

#define BPHY_NDEV_NUM_TXQ	2
#define BPHY_NDEV_NUM_RXQ	1

#define PTP_QUEUE_ID		0
#define OTH_QUEUE_ID		1

/* global driver ctx */
struct cnf10k_rfoe_drv_ctx cnf10k_rfoe_drv_ctx[CNF10K_RFOE_MAX_INTF];

static inline bool is_mcs_err(struct rfoe_psw_s *psw)
{
	u8 err = psw->mcs_err_sts >> 2 & 0x1f;

	return err != 0x0 && err != 0x1 && err != 0x6;
}

static uint8_t cnf10k_rfoe_get_ptp_ts_index(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct rfoe_link_tx_ptp_ring_ctl *ctrl;
	u64 value;

	value = readq(priv->rfoe_reg_base +
		      CNF10K_RFOEX_LINK_TX_PTP_RING_CTL(priv->rfoe_num,
							priv->lmac_id));
	ctrl = (struct rfoe_link_tx_ptp_ring_ctl *)(&value);
	return ctrl->tail_idx0;
}

static void cnf10k_rfoe_update_tx_drop_stats(struct cnf10k_rfoe_ndev_priv *priv,
					     int pkt_type)
{
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
}

static void cnf10k_rfoe_update_tx_stats(struct cnf10k_rfoe_ndev_priv *priv,
					int pkt_type, int len)
{
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
	priv->stats.tx_bytes += len;
}

static void cnf10k_rfoe_update_rx_drop_stats(struct cnf10k_rfoe_ndev_priv *priv,
					     int pkt_type)
{
	if (pkt_type == PACKET_TYPE_ECPRI) {
		priv->stats.ecpri_rx_dropped++;
		priv->last_rx_dropped_jiffies = jiffies;
	} else if (pkt_type == PACKET_TYPE_PTP) {
		priv->stats.ptp_rx_dropped++;
		priv->last_rx_ptp_dropped_jiffies = jiffies;
	} else {
		priv->stats.rx_dropped++;
		priv->last_rx_dropped_jiffies = jiffies;
	}
}

static void cnf10k_rfoe_update_rx_stats(struct cnf10k_rfoe_ndev_priv *priv,
					int pkt_type, int len)
{
	if (pkt_type == PACKET_TYPE_PTP) {
		priv->stats.ptp_rx_packets++;
		priv->last_rx_ptp_jiffies = jiffies;
	} else if (pkt_type == PACKET_TYPE_ECPRI) {
		priv->stats.ecpri_rx_packets++;
		priv->last_rx_jiffies = jiffies;
	} else {
		priv->stats.rx_packets++;
		priv->last_rx_jiffies = jiffies;
	}
	priv->stats.rx_bytes += len;
}

static void cnf10k_rfoe_set_rx_state(struct cnf10k_rfoe_ndev_priv *priv,
				     bool enabled)
{
	struct rfoe_rx_ctrl *rx_ctrl;
	u64 value;

	value = readq(priv->rfoe_reg_base +
		      CNF10K_RFOEX_RX_CTL(priv->rfoe_num));

	rx_ctrl = (struct rfoe_rx_ctrl *)&value;

	if (enabled)
		rx_ctrl->data_pkt_rx_en |= (1 << priv->lmac_id);
	else
		rx_ctrl->data_pkt_rx_en &= ~(1 << priv->lmac_id);

	netdev_printk(KERN_INFO, priv->netdev,
		      "%s RX for RFOE %u LMAC %u data_pkt_rx_en 0x%x\n",
		      (enabled ? "Enabling" : "Disabling"),
		      priv->rfoe_num, priv->lmac_id, rx_ctrl->data_pkt_rx_en);

	writeq(value,
	       priv->rfoe_reg_base + CNF10K_RFOEX_RX_CTL(priv->rfoe_num));
}

void cnf10k_bphy_intr_handler(struct otx2_bphy_cdev_priv *cdev_priv, u32 status)
{
	struct cnf10k_rfoe_drv_ctx *cnf10k_drv_ctx;
	struct cnf10k_rfoe_ndev_priv *priv;
	struct net_device *netdev;
	int rfoe_num, i;
	u32 intr_mask;

	/* rx intr processing */
	for (rfoe_num = 0; rfoe_num < cdev_priv->num_rfoe_mhab; rfoe_num++) {
		intr_mask = CNF10K_RFOE_RX_INTR_MASK(rfoe_num);
		if (status & intr_mask)
			cnf10k_rfoe_rx_napi_schedule(rfoe_num, status);
	}

	/* tx intr processing */
	for (i = 0; i < CNF10K_RFOE_MAX_INTF; i++) {
		cnf10k_drv_ctx = &cnf10k_rfoe_drv_ctx[i];
		if (cnf10k_drv_ctx->valid) {
			netdev = cnf10k_drv_ctx->netdev;
			priv = netdev_priv(netdev);
			intr_mask = CNF10K_RFOE_TX_PTP_INTR_MASK(priv->rfoe_num,
								 priv->lmac_id,
						cdev_priv->num_rfoe_lmac);
			if (status & intr_mask)
				schedule_work(&priv->ptp_tx_work);
		}
	}
}

void cnf10k_rfoe_disable_intf(int rfoe_num)
{
	struct cnf10k_rfoe_drv_ctx *drv_ctx;
	struct cnf10k_rfoe_ndev_priv *priv;
	struct net_device *netdev;
	int idx;

	for (idx = 0; idx < CNF10K_RFOE_MAX_INTF; idx++) {
		drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
		if (drv_ctx->rfoe_num == rfoe_num && drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			priv->if_type = IF_TYPE_NONE;
		}
	}
}

void cnf10k_bphy_rfoe_cleanup(void)
{
	struct cnf10k_rfoe_drv_ctx *drv_ctx = NULL;
	struct cnf10k_rfoe_ndev_priv *priv;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	struct net_device *netdev;
	int i, idx;

	for (i = 0; i < CNF10K_RFOE_MAX_INTF; i++) {
		drv_ctx = &cnf10k_rfoe_drv_ctx[i];
		if (drv_ctx->valid) {
			cnf10k_rfoe_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			netif_tx_stop_all_queues(netdev);
			priv = netdev_priv(netdev);
			cnf10k_rfoe_set_rx_state(priv, false);
			--(priv->ptp_cfg->refcnt);
			if (!priv->ptp_cfg->refcnt) {
				del_timer_sync(&priv->ptp_cfg->ptp_timer);
				kfree(priv->ptp_cfg);
			}
			cnf10k_rfoe_ptp_destroy(priv);
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

void cnf10k_rfoe_calc_ptp_ts(struct cnf10k_rfoe_ndev_priv *priv, u64 *ts)
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

static void cnf10k_rfoe_ptp_offset_timer(struct timer_list *t)
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

static bool cnf10k_validate_network_transport(struct sk_buff *skb)
{
	if ((ip_hdr(skb)->protocol == IPPROTO_UDP) ||
	    (ipv6_hdr(skb)->nexthdr == IPPROTO_UDP)) {
		struct udphdr *udph = udp_hdr(skb);

		if (udph->source == htons(PTP_PORT) &&
		    udph->dest == htons(PTP_PORT))
			return true;
	}

	return false;
}

static bool cnf10k_is_ptp_sync_ecpri_req(struct sk_buff *skb, int *offset,
					 int *udp_csum, int *pkt_type)
{
	struct ethhdr *eth = (struct ethhdr *)(skb->data);
	struct roe_ecpri_msg_5_hdr_s *ecpri_t5_hdr;
	struct roe_ecpri_cmn_hdr_s *ecpri_hdr;
	u8 *data = skb->data, *msgtype;
	__be16 proto = eth->h_proto;
	int network_depth = 0;

	if (eth_type_vlan(eth->h_proto))
		proto = __vlan_get_protocol(skb, eth->h_proto, &network_depth);

	switch (ntohs(proto)) {
	case ETH_P_1588:
	case ETH_P_ECPRI:
		if (network_depth)
			*offset = network_depth;
		else
			*offset = ETH_HLEN;
		break;
	case ETH_P_IP:
	case ETH_P_IPV6:
		if (!cnf10k_validate_network_transport(skb))
			return false;

		*udp_csum = 1;
		*offset = skb_transport_offset(skb) + sizeof(struct udphdr);
	}

	if (ntohs(proto) == ETH_P_ECPRI) {
		ecpri_hdr = (struct roe_ecpri_cmn_hdr_s *)(skb->data + sizeof(*eth));
		ecpri_t5_hdr = (struct roe_ecpri_msg_5_hdr_s *)(skb->data + sizeof(*eth) +
				sizeof(*ecpri_hdr));
		if (ecpri_hdr->msg_type == ECPRI_MSG_TYPE_5) {
			*pkt_type = PACKET_TYPE_ECPRI;
			switch (ecpri_t5_hdr->action_type) {
			case ACTION_REQ:
			case ACTION_RESP:
				*offset = *offset + sizeof(*ecpri_hdr);
				return true;
			case ACTION_REQ_WITH_FOLLOWUP:
			case ACTION_REMOTE_REQ:
			case ACTION_REMOTE_REQ_WITH_FOLLOWUP:
			default:
				/* eCPRI action types which dont need timestamping,
				 * compensation fields.
				 */
				*pkt_type = PACKET_ECPRI5_NO_TS;
				return false;
			}
		} else {
			pr_err("Unsupported eCPRI msg type %x\n", ecpri_hdr->msg_type);
			return false;
		}
	} else {
		msgtype = data + *offset;
	}

	*pkt_type = PACKET_TYPE_PTP;
	/* Check PTP messageId is SYNC or not */
	return (*msgtype & 0xf) == 0;
}

static void cnf10k_rfoe_prepare_onestep_ptp_header(struct cnf10k_rfoe_ndev_priv *priv,
						   struct cnf10k_tx_action_s *tx_mem,
						   struct sk_buff *skb,
						   int proto_data_offset, int udp_csum,
						   int pkt_type)
{
	struct ecpri_t5_tstamp *ecpri_tstamp;
	struct ptpv2_tstamp *origin_tstamp;
	struct timespec64 ts;
	u64 tstamp, tsns;

	tstamp = cnf10k_rfoe_read_ptp_clock(priv);
	tsns = tstamp;
	if (priv->use_sw_timecounter)
		cnf10k_rfoe_ptp_tstamp2time(priv, tstamp, &tsns);
	else if (priv->ptp_cfg->use_ptp_alg)
		cnf10k_rfoe_calc_ptp_ts(priv, &tsns);

	ts = ns_to_timespec64(tsns);

	if (pkt_type == PACKET_TYPE_PTP) {
		origin_tstamp = (struct ptpv2_tstamp *)((u8 *)skb->data + proto_data_offset +
							PTP_SYNC_SEC_OFFSET);
		origin_tstamp->seconds_msb = htons((ts.tv_sec >> 32) & 0xffff);
		origin_tstamp->seconds_lsb = htonl(ts.tv_sec & 0xffffffff);
		origin_tstamp->nanoseconds = htonl(ts.tv_nsec);

		/* Point to correction field in PTP packet */
		tx_mem->start_offset = proto_data_offset + 8;
	} else if (pkt_type == PACKET_TYPE_ECPRI) {
		ecpri_tstamp = (struct ecpri_t5_tstamp *)((u8 *)skb->data + proto_data_offset +
						ECPRI_REQ_SEC_OFFSET);
		ecpri_tstamp->seconds_msb = htons((ts.tv_sec >> 32) & 0xffff);
		ecpri_tstamp->seconds_lsb = htonl(ts.tv_sec & 0xffffffff);
		ecpri_tstamp->nanoseconds = htonl(ts.tv_nsec);

		/* Point to correction field in ecpri packet */
		tx_mem->start_offset = proto_data_offset + 12;
	}
	tx_mem->udp_csum_crt = udp_csum;
	tx_mem->base_ns  = tstamp % NSEC_PER_SEC;
	tx_mem->step_type = 1;
}

#define OTX2_RFOE_PTP_TSTMP_POLL_CNT	20

static void cnf10k_rfoe_dump_ts_ring(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct rfoe_tx_ptp_tstmp_s *tx_tstmp;
	u64 *ptp_tstamp;
	u8 i;

	pr_info("PTP ring entries dump:\n");

	for (i = 0; i < priv->ptp_ring_cfg.ptp_ring_size; i++) {
		tx_tstmp = (struct rfoe_tx_ptp_tstmp_s *)
			   ((u8 __force *)priv->ptp_ring_cfg.ptp_ring_base +
			    (16 * i));
		ptp_tstamp = (u64 *)tx_tstmp;
		pr_info("entry = %u, tx_tstmp_w0 = 0x%llx tx_tstmp_w1 = 0x%llx\n",
			i, *ptp_tstamp, *(ptp_tstamp + 1));
	}
}

/* ptp interrupt processing bottom half */
static void cnf10k_rfoe_ptp_tx_work(struct work_struct *work)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(work,
						 struct cnf10k_rfoe_ndev_priv,
						 ptp_tx_work);
	struct rfoe_tx_ptp_tstmp_s *tx_tstmp;
	struct skb_shared_hwtstamps ts;
	struct netdev_queue *txq;
	u64 timestamp, tsns;
	u64 *ptp_tstamp;
	int cnt;

	txq = netdev_get_tx_queue(priv->netdev, PTP_QUEUE_ID);

	if (!priv->ptp_tx_skb) {
		netif_err(priv, tx_done, priv->netdev,
			  "ptp tx skb not found, something wrong!\n");
		return;
	}

	if (!(skb_shinfo(priv->ptp_tx_skb)->tx_flags & SKBTX_IN_PROGRESS)) {
		netif_err(priv, tx_done, priv->netdev,
			  "ptp tx skb SKBTX_IN_PROGRESS not set\n");
		goto submit_next_req;
	}

	/* ptp timestamp entry is 128-bit in size */
	tx_tstmp = (struct rfoe_tx_ptp_tstmp_s *)
		   ((u8 __force *)priv->ptp_ring_cfg.ptp_ring_base +
		    (16 * priv->ptp_ring_cfg.ptp_ring_idx));

	/* poll for match job id */
	for (cnt = 0; cnt < OTX2_RFOE_PTP_TSTMP_POLL_CNT; cnt++) {
		/* make sure that all memory writes by rfoe are completed */
		dma_rmb();
		if (tx_tstmp->jobid == priv->ptp_job_tag)
			break;
		usleep_range(5, 10);
	}

	if (cnt >= OTX2_RFOE_PTP_TSTMP_POLL_CNT) {
		netdev_err(priv->netdev,
			   "ptp job id doesn't match @ idx=%d: job_id=0x%x skb->job_tag=0x%x\n",
			   priv->ptp_ring_cfg.ptp_ring_idx, tx_tstmp->jobid, priv->ptp_job_tag);
		if (netif_msg_tx_queued(priv))
			cnf10k_rfoe_dump_ts_ring(priv);
		goto tx_tstmp_error;
	}

	if (tx_tstmp->drop || tx_tstmp->tx_err) {
		ptp_tstamp = (u64 *)tx_tstmp;
		netdev_err(priv->netdev,
			   "ptp timstamp error @ idx=%d: tstmp_w0=0x%llx tstmp_w1=0x%llx\n",
			   priv->ptp_ring_cfg.ptp_ring_idx, *ptp_tstamp, *(ptp_tstamp + 1));
		goto tx_tstmp_error;
	}

	/* update timestamp value in skb */
	timestamp = cnf10k_ptp_convert_timestamp(tx_tstmp->ptp_timestamp);
	tsns = timestamp;
	if (priv->use_sw_timecounter)
		cnf10k_rfoe_ptp_tstamp2time(priv, timestamp, &tsns);
	else if (priv->ptp_cfg->use_ptp_alg)
		cnf10k_rfoe_calc_ptp_ts(priv, &tsns);

	memset(&ts, 0, sizeof(ts));
	ts.hwtstamp = ns_to_ktime(tsns);
	skb_tstamp_tx(priv->ptp_tx_skb, &ts);

	goto submit_next_req;

tx_tstmp_error:
	priv->stats.tx_hwtstamp_failures++;
submit_next_req:
	if (priv->ptp_tx_skb)
		dev_kfree_skb_any(priv->ptp_tx_skb);
	priv->ptp_tx_skb = NULL;

	if (txq && netif_tx_queue_stopped(txq))
		netif_tx_wake_queue(txq);
}

/* psm queue timer callback to check queue space */
static void cnf10k_rfoe_tx_timer_cb(struct timer_list *t)
{
	struct cnf10k_rfoe_ndev_priv *priv =
			container_of(t, struct cnf10k_rfoe_ndev_priv, tx_timer);
	u16 psm_queue_id, queue_space;
	struct netdev_queue *txq;
	u8 schedule_mask = 0;
	u64 regval;

	txq = netdev_get_tx_queue(priv->netdev, PTP_QUEUE_ID);
	if (txq && netif_tx_queue_stopped(txq)) {
		/* check ptp psm queue space */
		psm_queue_id = priv->tx_ptp_job_cfg.psm_queue_id;
		regval = readq(priv->psm_reg_base +
			       PSM_QUEUE_SPACE(psm_queue_id));
		queue_space = regval & 0xFFFF;
		if (queue_space > 1)
			netif_tx_wake_queue(txq);
		else
			schedule_mask = 1 << PTP_QUEUE_ID;
	}

	txq = netdev_get_tx_queue(priv->netdev, OTH_QUEUE_ID);
	if (txq && netif_tx_queue_stopped(txq)) {
		/* check other psm queue space */
		psm_queue_id = priv->rfoe_common->tx_oth_job_cfg.psm_queue_id;
		regval = readq(priv->psm_reg_base +
			       PSM_QUEUE_SPACE(psm_queue_id));
		queue_space = regval & 0xFFFF;
		if (queue_space > 1)
			netif_tx_wake_queue(txq);
		else
			schedule_mask |= (1 << OTH_QUEUE_ID);
	}

	if (schedule_mask)
		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
}

static void cnf10k_rfoe_dump_psw(struct cnf10k_rfoe_ndev_priv *priv, u8 *buf_ptr)
{
	int i;

	for (i = 0; i < 8; i++)
		netdev_err(priv->netdev, "psw(w%d)=0x%llx\n", i, *((u64 *)buf_ptr + i));
}

static void cnf10k_rfoe_process_rx_pkt(struct cnf10k_rfoe_ndev_priv *priv,
				       struct cnf10k_rx_ft_cfg *ft_cfg,
				       int mbt_buf_idx)
{
	struct cnf10k_mhbw_jd_dma_cfg_word_0_s *jd_dma_cfg_word_0;
	struct rfoe_psw_w2_ecpri_s *ecpri_psw_w2;
	struct rfoe_psw_w2_roe_s *rfoe_psw_w2;
	struct cnf10k_rfoe_ndev_priv *priv2;
	struct cnf10k_rfoe_drv_ctx *drv_ctx;
	u64 tstamp = 0, jdt_iova_addr, tsns;
	int found = 0, idx, len, pkt_type;
	struct rfoe_psw_s *psw = NULL;
	struct net_device *netdev;
	u8 *buf_ptr, *jdt_ptr;
	struct sk_buff *skb;
	u8 lmac_id;

	buf_ptr = (u8 __force *)ft_cfg->mbt_virt_addr +
				(ft_cfg->buf_size * mbt_buf_idx);
	dma_rmb();

	pkt_type = ft_cfg->pkt_type;

	psw = (struct rfoe_psw_s *)buf_ptr;
	if (psw->pkt_type == CNF10K_ECPRI) {
		jdt_iova_addr = (u64)psw->jd_ptr;
		if (unlikely(!jdt_iova_addr)) {
			netdev_err(priv->netdev, "JD_PTR was null at mbt_buf_idx %d\n",
				   mbt_buf_idx);
			cnf10k_rfoe_dump_psw(priv, buf_ptr);
			return;
		}
		ecpri_psw_w2 = (struct rfoe_psw_w2_ecpri_s *)
					&psw->proto_sts_word;
		lmac_id = ecpri_psw_w2->lmac_id;

		/* Only ecpri payload size is captured in psw->pkt_len, so
		 * get full packet length from JDT.
		 */
		jdt_ptr = (u8 __force *)otx2_iova_to_virt(priv->iommu_domain, jdt_iova_addr);
		jd_dma_cfg_word_0 = (struct cnf10k_mhbw_jd_dma_cfg_word_0_s *)
				((u8 __force *)jdt_ptr + ft_cfg->jd_rd_offset);
		len = (jd_dma_cfg_word_0->block_size) << 2;
		len -= (ft_cfg->pkt_offset * 16);
	} else {
		rfoe_psw_w2 = (struct rfoe_psw_w2_roe_s *)&psw->proto_sts_word;
		lmac_id = rfoe_psw_w2->lmac_id;
		len = psw->pkt_len;
		if (unlikely(!len)) {
			netdev_err(priv->netdev, "packet length was zero at mbt_buf_idx %d\n",
				   mbt_buf_idx);
			cnf10k_rfoe_dump_psw(priv, buf_ptr);
			return;
		}
	}

	for (idx = 0; idx < CNF10K_RFOE_MAX_INTF; idx++) {
		drv_ctx = &cnf10k_rfoe_drv_ctx[idx];
		if (drv_ctx->valid && drv_ctx->rfoe_num == priv->rfoe_num &&
		    drv_ctx->lmac_id == lmac_id) {
			found = 1;
			break;
		}
	}
	if (found) {
		netdev = cnf10k_rfoe_drv_ctx[idx].netdev;
		priv2 = netdev_priv(netdev);
	} else {
		pr_err("netdev not found, something went wrong!\n");
		return;
	}

	if (unlikely(psw->mac_err_sts || is_mcs_err(psw))) {
		if (netif_msg_rx_err(priv2))
			net_warn_ratelimited("%s: psw mac_err_sts = 0x%x, mcs_err_sts=0x%x\n",
					     priv2->netdev->name,
					     psw->mac_err_sts,
					     psw->mcs_err_sts);
		if (psw->mac_err_sts) {
			cnf10k_rfoe_update_rx_drop_stats(priv2, pkt_type);
			return;
		}
	}

	/* drop the packet if interface is down */
	if (unlikely(!netif_carrier_ok(netdev))) {
		netif_err(priv2, rx_err, netdev,
			  "%s {rfoe%d lmac%d} link down, drop pkt\n",
			  netdev->name, priv2->rfoe_num,
			  priv2->lmac_id);
		cnf10k_rfoe_update_rx_drop_stats(priv2, pkt_type);
		return;
	}

	buf_ptr += (ft_cfg->pkt_offset * 16);
	if (unlikely(netif_msg_pktdata(priv2))) {
		net_info_ratelimited("%s: %s: Rx: rfoe=%d lmac=%d mbt_buf_idx=%d\n",
				     priv2->netdev->name, __func__, priv2->rfoe_num,
				     lmac_id, mbt_buf_idx);
		netdev_printk(KERN_DEBUG, priv2->netdev, "RX MBUF DATA:");
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       buf_ptr, len, true);
	}

	skb = netdev_alloc_skb_ip_align(netdev, len);
	if (!skb) {
		netif_err(priv2, rx_err, netdev, "Rx: alloc skb failed\n");
		cnf10k_rfoe_update_rx_drop_stats(priv2, pkt_type);
		return;
	}

	memcpy(skb->data, buf_ptr, len);
	skb_put(skb, len);
	skb->protocol = eth_type_trans(skb, netdev);

	if (priv2->rx_hw_tstamp_en) {
		tstamp = be64_to_cpu(*(__be64 *)&psw->ptp_timestamp);
		tstamp = cnf10k_ptp_convert_timestamp(tstamp);
		tsns = tstamp;
		if (priv2->use_sw_timecounter)
			cnf10k_rfoe_ptp_tstamp2time(priv2, tstamp, &tsns);
		else if (priv2->ptp_cfg->use_ptp_alg)
			cnf10k_rfoe_calc_ptp_ts(priv2, &tsns);

		skb_hwtstamps(skb)->hwtstamp = ns_to_ktime(tsns);
	}

	cnf10k_rfoe_update_rx_stats(priv2, pkt_type, skb->len);

	netif_receive_skb(skb);
}

static int cnf10k_rfoe_process_rx_flow(struct cnf10k_rfoe_ndev_priv *priv,
				       int pkt_type, int budget)
{
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	int count = 0, processed_pkts = 0;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	u64 mbt_cfg;
	u16 nxt_buf;
	int *mbt_last_idx = &priv->rfoe_common->rx_mbt_last_idx[pkt_type];
	u16 *prv_nxt_buf = &priv->rfoe_common->nxt_buf[pkt_type];

	ft_cfg = &priv->rx_ft_cfg[pkt_type];

	spin_lock(&cdev_priv->mbt_lock);
	/* read mbt nxt_buf */
	writeq(ft_cfg->mbt_idx,
	       priv->rfoe_reg_base +
	       CNF10K_RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num));
	mbt_cfg = readq(priv->rfoe_reg_base +
			CNF10K_RFOEX_RX_IND_MBT_CFG(priv->rfoe_num));
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
		cnf10k_rfoe_process_rx_pkt(priv, ft_cfg, *mbt_last_idx);

		(*mbt_last_idx)++;
		if (*mbt_last_idx == ft_cfg->num_bufs)
			*mbt_last_idx = 0;

		processed_pkts++;
	}

	return processed_pkts;
}

/* napi poll routine */
static int cnf10k_rfoe_napi_poll(struct napi_struct *napi, int budget)
{
	struct cnf10k_rfoe_ndev_priv *priv;
	struct otx2_bphy_cdev_priv *cdev_priv;
	int workdone = 0, pkt_type;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	u64 intr_en, regval;

	ft_cfg = container_of(napi, struct cnf10k_rx_ft_cfg, napi);
	priv = ft_cfg->priv;
	cdev_priv = priv->cdev_priv;
	pkt_type = ft_cfg->pkt_type;

	/* pkt processing loop */
	workdone += cnf10k_rfoe_process_rx_flow(priv, pkt_type, budget);

	if (workdone < budget) {
		napi_complete_done(napi, workdone);

		/* Re enable the Rx interrupts */
		intr_en = PKT_TYPE_TO_INTR(pkt_type) <<
				CNF10K_RFOE_RX_INTR_SHIFT(priv->rfoe_num);
		spin_lock(&cdev_priv->lock);
		if (priv->rfoe_num < 6) {
			regval = readq(bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
			regval |= intr_en;
			writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1S(1));
		} else {
			regval = readq(bphy_reg_base + PSM_INT_GP_ENA_W1S(2));
			regval |= intr_en;
			writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1S(2));
		}
		spin_unlock(&cdev_priv->lock);
	}

	return workdone;
}

/* Rx GPINT napi schedule api */
void cnf10k_rfoe_rx_napi_schedule(int rfoe_num, u32 status)
{
	enum bphy_netdev_packet_type pkt_type;
	struct cnf10k_rfoe_drv_ctx *drv_ctx;
	struct cnf10k_rfoe_ndev_priv *priv;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	int intf, bit_idx;
	u32 intr_sts;
	u64 regval;

	for (intf = 0; intf < CNF10K_RFOE_MAX_INTF; intf++) {
		drv_ctx = &cnf10k_rfoe_drv_ctx[intf];
		/* ignore lmac, one interrupt/pkt_type/rfoe */
		if (!(drv_ctx->valid && drv_ctx->rfoe_num == rfoe_num))
			continue;
		/* check if i/f down, napi disabled */
		priv = netdev_priv(drv_ctx->netdev);
		if (test_bit(RFOE_INTF_DOWN, &priv->state))
			continue;
		/* check rx pkt type */
		intr_sts = ((status >> CNF10K_RFOE_RX_INTR_SHIFT(rfoe_num)) &
			    RFOE_RX_INTR_EN);
		for (bit_idx = 0; bit_idx < PACKET_TYPE_MAX; bit_idx++) {
			if (!(intr_sts & BIT(bit_idx)))
				continue;
			pkt_type = INTR_TO_PKT_TYPE(bit_idx);
			if (unlikely(!(priv->pkt_type_mask & (1U << pkt_type))))
				continue;
			/* clear intr enable bit, re-enable in napi handler */
			regval = PKT_TYPE_TO_INTR(pkt_type) <<
				 CNF10K_RFOE_RX_INTR_SHIFT(rfoe_num);
			if (rfoe_num < 6)
				writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1C(1));
			else
				writeq(regval, bphy_reg_base + PSM_INT_GP_ENA_W1C(2));
			/* schedule napi */
			ft_cfg = &drv_ctx->ft_cfg[pkt_type];
			napi_schedule(&ft_cfg->napi);
		}
		/* napi scheduled per pkt_type, return */
		return;
	}
}

static void cnf10k_rfoe_get_stats64(struct net_device *netdev,
				    struct rtnl_link_stats64 *stats)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
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

static int cnf10k_rfoe_config_hwtstamp(struct net_device *netdev,
				       struct ifreq *ifr)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
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
		if (priv->ptp_onestep_sync)
			priv->ptp_onestep_sync = 0;
		priv->tx_hw_tstamp_en = 0;
		break;
	case HWTSTAMP_TX_ONESTEP_SYNC:
		priv->ptp_onestep_sync = 1;
		fallthrough;
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
static int cnf10k_rfoe_ioctl(struct net_device *netdev, struct ifreq *req,
			     int cmd)
{
	switch (cmd) {
	case SIOCSHWTSTAMP:
		return cnf10k_rfoe_config_hwtstamp(netdev, req);
	default:
		return -EOPNOTSUPP;
	}
}

static void cnf10k_rfoe_compute_udp_csum(struct sk_buff *skb)
{
	struct ipv6hdr *iph6;
	__wsum udp_csum = 0;
	struct iphdr *iph;
	int offset;

	udp_hdr(skb)->check = 0;
	offset = skb_transport_offset(skb);
	udp_csum = skb_checksum(skb, offset, skb->len - offset, 0);
	if (eth_hdr(skb)->h_proto == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		udp_hdr(skb)->check = csum_tcpudp_magic(iph->saddr,
							iph->daddr,
							skb->len - offset,
							iph->protocol,
							udp_csum);
	} else if (eth_hdr(skb)->h_proto == htons(ETH_P_IPV6)) {
		iph6 = ipv6_hdr(skb);
		udp_hdr(skb)->check = csum_ipv6_magic(&iph6->saddr,
						      &iph6->daddr,
						      skb->len - offset,
						      iph6->nexthdr,
						      udp_csum);
	}
}

static int cnf10k_rfoe_check_psm_queue_space(struct cnf10k_rfoe_ndev_priv *priv,
					     int psm_queue_id)
{
	int queue_space;

	queue_space = readq(priv->psm_reg_base +
			    PSM_QUEUE_SPACE(psm_queue_id)) & 0xFFFF;

	if (queue_space < 1)
		return 1;

	return 0;
}

static int cnf10k_rfoe_check_update_tx_stats(struct cnf10k_rfoe_ndev_priv *priv,
					     int pkt_type)
{
	struct net_device *netdev = priv->netdev;

	if (unlikely(priv->if_type != IF_TYPE_ETHERNET)) {
		netif_err(priv, tx_queued, netdev,
			  "%s {rfoe%d lmac%d} invalid intf mode, drop pkt\n",
			  netdev->name, priv->rfoe_num, priv->lmac_id);
		goto err;
	}

	if (unlikely(!netif_carrier_ok(netdev))) {
		netif_err(priv, tx_err, netdev,
			  "%s {rfoe%d lmac%d} link down, drop pkt\n",
			  netdev->name, priv->rfoe_num,
			  priv->lmac_id);
		goto err;
	}

	if (unlikely(!(priv->pkt_type_mask & (1U << pkt_type)))) {
		netif_err(priv, tx_queued, netdev,
			  "%s {rfoe%d lmac%d} pkt not supported, drop pkt\n",
			  netdev->name, priv->rfoe_num,
			  priv->lmac_id);
		goto err;
	}

	return 0;

err:
	cnf10k_rfoe_update_tx_drop_stats(priv, pkt_type);
	return -EINVAL;
}

static void cnf10k_rfoe_submit_job(struct cnf10k_rfoe_ndev_priv *priv,
				   struct tx_job_entry *job_entry, int job_index,
				   int psm_queue_id, unsigned int pkt_len,
				   bool update_lmac, u8 rfoe_mode)
{
	struct cnf10k_mhbw_jd_dma_cfg_word_0_s *jd_dma_cfg_word_0;
	struct cnf10k_mhab_job_desc_cfg *jd_cfg_ptr;

	netif_dbg(priv, tx_queued, priv->netdev,
		  "rfoe=%d lmac=%d psm_queue=%d tx_job_entry %d job_cmd_lo=0x%llx job_cmd_high=0x%llx jd_iova_addr=0x%llx\n",
		  priv->rfoe_num, priv->lmac_id, psm_queue_id, job_index,
		  job_entry->job_cmd_lo, job_entry->job_cmd_hi,
		  job_entry->jd_iova_addr);

	/* update length and block size in jd dma cfg word */
	jd_cfg_ptr = (struct cnf10k_mhab_job_desc_cfg __force *)job_entry->jd_cfg_ptr;
	jd_dma_cfg_word_0 = (struct cnf10k_mhbw_jd_dma_cfg_word_0_s __force *)
						job_entry->rd_dma_ptr;

	if (update_lmac) {
		jd_cfg_ptr->cfg3.lmacid = priv->lmac_id & 0x3;
		jd_cfg_ptr->cfg.rfoe_mode = rfoe_mode;
	}

	jd_cfg_ptr->cfg3.pkt_len = pkt_len;
	jd_dma_cfg_word_0->block_size = (((pkt_len + 15) >> 4) * 4);

	/* make sure that all memory writes are completed */
	dma_wmb();

	/* submit PSM job */
	writeq(job_entry->job_cmd_lo,
	       priv->psm_reg_base + PSM_QUEUE_CMD_LO(psm_queue_id));
	writeq(job_entry->job_cmd_hi,
	       priv->psm_reg_base + PSM_QUEUE_CMD_HI(psm_queue_id));
}

static netdev_tx_t cnf10k_rfoe_ptp_xmit(struct sk_buff *skb,
					struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct cnf10k_psm_cmd_addjob_s *psm_cmd_lo;
	struct rfoe_tx_ptp_tstmp_s *tx_tstmp;
	struct cnf10k_tx_action_s tx_mem;
	struct tx_job_queue_cfg *job_cfg;
	int proto_data_offset = 0, udp_csum = 0;
	struct tx_job_entry *job_entry;
	int pkt_type = PACKET_TYPE_PTP;
	int pkt_stats_type = PACKET_TYPE_PTP;
	struct netdev_queue *txq;
	unsigned int pkt_len = 0;
	unsigned long flags;
	struct ethhdr *eth;
	int psm_queue_id;

	job_cfg = &priv->tx_ptp_job_cfg;
	memset(&tx_mem, 0, sizeof(tx_mem));

	txq = netdev_get_tx_queue(netdev, skb_get_queue_mapping(skb));

	eth = (struct ethhdr *)skb->data;
	if (htons(eth->h_proto) == ETH_P_ECPRI)
		pkt_stats_type = PACKET_TYPE_ECPRI;

	spin_lock_irqsave(&job_cfg->lock, flags);

	if (cnf10k_rfoe_check_update_tx_stats(priv, pkt_stats_type))
		goto exit;

	/* get psm queue number */
	psm_queue_id = job_cfg->psm_queue_id;
	netif_dbg(priv, tx_queued, priv->netdev,
		  "psm: queue(%d): cfg=0x%llx ptr=0x%llx space=0x%llx\n",
		  psm_queue_id,
		  readq(priv->psm_reg_base + PSM_QUEUE_CFG(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_PTR(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_SPACE(psm_queue_id)));

	/* check psm queue space available */
	if (cnf10k_rfoe_check_psm_queue_space(priv, psm_queue_id)) {
		netif_err(priv, tx_err, netdev,
			  "no space in psm queue %d, dropping pkt\n",
			   psm_queue_id);
		netif_tx_stop_queue(txq);
		cnf10k_rfoe_update_tx_drop_stats(priv, pkt_stats_type);
		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return NETDEV_TX_BUSY;
	}

	/* PTP packets are xmited one by one */
	if (priv->ptp_tx_skb) {
		netif_tx_stop_queue(txq);
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return NETDEV_TX_BUSY;
	}

	priv->ptp_tx_skb = skb;

	/* get the tx job entry */
	job_entry = (struct tx_job_entry *)
				&job_cfg->job_entries[job_cfg->q_idx];

	if (unlikely(netif_msg_pktdata(priv))) {
		netdev_printk(KERN_DEBUG, priv->netdev, "Tx: skb %pS len=%d\n",
			      skb, skb->len);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       skb->data, skb->len, true);
	}

	/* check if one-step is enabled */
	if (priv->ptp_onestep_sync) {
		if (cnf10k_is_ptp_sync_ecpri_req(skb, &proto_data_offset, &udp_csum, &pkt_type)) {
			cnf10k_rfoe_prepare_onestep_ptp_header(priv,
							       &tx_mem, skb,
							       proto_data_offset,
							       udp_csum, pkt_type);
			/* recalculate UDP hdr checksum as RFOE block has no checksum
			 * offload support and checksum field is left with stale data
			 */
			if (udp_csum)
				cnf10k_rfoe_compute_udp_csum(skb);
		}

		if ((pkt_type == PACKET_TYPE_PTP && ((*(skb->data + proto_data_offset) & 0xF) !=
				    DELAY_REQUEST_MSG_ID)) || pkt_type == PACKET_TYPE_ECPRI)

			goto ptp_one_step_out;
	}

	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

	psm_cmd_lo = (struct cnf10k_psm_cmd_addjob_s *)&job_entry->job_cmd_lo;
	priv->ptp_job_tag = psm_cmd_lo->jobtag;
	priv->ptp_ring_cfg.ptp_ring_idx = cnf10k_rfoe_get_ptp_ts_index(priv);

	/* ptp timestamp entry is 128-bit in size */
	tx_tstmp = (struct rfoe_tx_ptp_tstmp_s *)
		   ((u8 __force *)priv->ptp_ring_cfg.ptp_ring_base +
		    (16 * priv->ptp_ring_cfg.ptp_ring_idx));
	memset(tx_tstmp, 0, sizeof(struct rfoe_tx_ptp_tstmp_s));

ptp_one_step_out:
	/* sw timestamp */
	skb_tx_timestamp(skb);

	pkt_len = skb->len;

	/* Copy packet data to dma buffer */
	if (priv->ndev_flags & BPHY_NDEV_TX_1S_PTP_EN_FLAG) {
		memcpy((void __force *)job_entry->pkt_dma_addr, &tx_mem, sizeof(tx_mem));
		memcpy((void __force *)job_entry->pkt_dma_addr + sizeof(tx_mem),
		       skb->data, skb->len);
		pkt_len += sizeof(tx_mem);
	} else {
		memcpy((void __force *)job_entry->pkt_dma_addr, skb->data, pkt_len);
	}

	cnf10k_rfoe_submit_job(priv, job_entry, job_cfg->q_idx, psm_queue_id,
			       pkt_len, false, 0);

	cnf10k_rfoe_update_tx_stats(priv, pkt_stats_type, skb->len);

	/* increment queue index */
	job_cfg->q_idx++;
	if (job_cfg->q_idx == job_cfg->num_entries)
		job_cfg->q_idx = 0;
exit:
	spin_unlock_irqrestore(&job_cfg->lock, flags);

	return NETDEV_TX_OK;
}

/* netdev xmit */
static netdev_tx_t cnf10k_rfoe_eth_start_xmit(struct sk_buff *skb,
					      struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
	int qidx = skb_get_queue_mapping(skb);
	struct tx_job_queue_cfg *job_cfg;
	struct tx_job_entry *job_entry;
	int psm_queue_id, pkt_type = 0;
	struct netdev_queue *txq;
	unsigned int pkt_len = 0;
	unsigned long flags;
	struct ethhdr *eth;

	if (skb_get_queue_mapping(skb) == PTP_QUEUE_ID)
		return cnf10k_rfoe_ptp_xmit(skb, netdev);

	eth = (struct ethhdr *)skb->data;
	job_cfg = &priv->rfoe_common->tx_oth_job_cfg;
	pkt_type = PACKET_TYPE_OTHER;
	if (htons(eth->h_proto) == ETH_P_ECPRI)
		pkt_type = PACKET_TYPE_ECPRI;

	txq = netdev_get_tx_queue(netdev, qidx);

	spin_lock_irqsave(&job_cfg->lock, flags);

	if (cnf10k_rfoe_check_update_tx_stats(priv, pkt_type))
		goto exit;

	/* get psm queue number */
	psm_queue_id = job_cfg->psm_queue_id;
	netif_dbg(priv, tx_queued, priv->netdev,
		  "psm: queue(%d): cfg=0x%llx ptr=0x%llx space=0x%llx\n",
		  psm_queue_id,
		  readq(priv->psm_reg_base + PSM_QUEUE_CFG(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_PTR(psm_queue_id)),
		  readq(priv->psm_reg_base + PSM_QUEUE_SPACE(psm_queue_id)));

	/* check psm queue space available */
	if (cnf10k_rfoe_check_psm_queue_space(priv, psm_queue_id)) {
		netif_err(priv, tx_err, netdev,
			  "no space in psm queue %d, dropping pkt\n",
			   psm_queue_id);
		netif_tx_stop_queue(txq);
		cnf10k_rfoe_update_tx_drop_stats(priv, pkt_type);
		mod_timer(&priv->tx_timer, jiffies + msecs_to_jiffies(100));
		spin_unlock_irqrestore(&job_cfg->lock, flags);
		return NETDEV_TX_BUSY;
	}

	/* get the tx job entry */
	job_entry = (struct tx_job_entry *)
				&job_cfg->job_entries[job_cfg->q_idx];

	if (unlikely(netif_msg_pktdata(priv))) {
		netdev_printk(KERN_DEBUG, priv->netdev, "Tx: skb %pS len=%d\n",
			      skb, skb->len);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       skb->data, skb->len, true);
	}

	pkt_len = skb->len;

	if (skb->len < 64)
		memset((void __force *)job_entry->pkt_dma_addr, 0, 64);

	/* Copy packet data to dma buffer */
	memcpy((void __force *)job_entry->pkt_dma_addr, skb->data, skb->len);

	cnf10k_rfoe_submit_job(priv, job_entry, job_cfg->q_idx, psm_queue_id,
			       pkt_len, true,
			       pkt_type == PACKET_TYPE_ECPRI ? 1 : 0);

	cnf10k_rfoe_update_tx_stats(priv, pkt_type, skb->len);

	/* increment queue index */
	job_cfg->q_idx++;
	if (job_cfg->q_idx == job_cfg->num_entries)
		job_cfg->q_idx = 0;
exit:
	dev_kfree_skb_any(skb);

	spin_unlock_irqrestore(&job_cfg->lock, flags);

	return NETDEV_TX_OK;
}

static int cnf10k_change_mtu(struct net_device *netdev, int new_mtu)
{
	netdev->mtu = new_mtu;

	return 0;
}

/* netdev open */
static int cnf10k_rfoe_eth_open(struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
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
		netif_tx_start_all_queues(netdev);
	}
	spin_unlock(&priv->lock);

	return 0;
}

/* netdev close */
static int cnf10k_rfoe_eth_stop(struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
	int idx;

	spin_lock(&priv->lock);
	set_bit(RFOE_INTF_DOWN, &priv->state);

	netif_tx_stop_all_queues(netdev);
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
	}

	return 0;
}

static int cnf10k_rfoe_init(struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	/* Enable VLAN TPID match */
	writeq(0x18100, (priv->rfoe_reg_base +
			 CNF10K_RFOEX_RX_VLANX_CFG(priv->rfoe_num, 0)));
	netdev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;

	return 0;
}

static int cnf10k_rfoe_vlan_rx_configure(struct net_device *netdev, u16 vid,
					 bool forward)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	struct rfoe_rx_ind_vlanx_fwd fwd;
	unsigned long flags;
	u64 mask, index;

	if (vid >= VLAN_N_VID) {
		netdev_err(netdev, "Invalid VLAN ID %d\n", vid);
		return -EINVAL;
	}

	mask = (0x1ll << (vid & 0x3F));
	index = (vid >> 6) & 0x3F;

	spin_lock_irqsave(&cdev_priv->mbt_lock, flags);

	if (forward && priv->rfoe_common->rx_vlan_fwd_refcnt[vid]++)
		goto out;

	if (!forward && --priv->rfoe_common->rx_vlan_fwd_refcnt[vid])
		goto out;

	/* read current fwd mask */
	writeq(index, (priv->rfoe_reg_base +
		       CNF10K_RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
	fwd.fwd = readq(priv->rfoe_reg_base +
			CNF10K_RFOEX_RX_IND_VLANX_FWD(priv->rfoe_num, 0));

	if (forward)
		fwd.fwd |= mask;
	else
		fwd.fwd &= ~mask;

	/* write the new fwd mask */
	writeq(index, (priv->rfoe_reg_base +
		       CNF10K_RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
	writeq(fwd.fwd, (priv->rfoe_reg_base +
			 CNF10K_RFOEX_RX_IND_VLANX_FWD(priv->rfoe_num, 0)));

out:
	spin_unlock_irqrestore(&cdev_priv->mbt_lock, flags);

	return 0;
}

static int cnf10k_rfoe_vlan_rx_add(struct net_device *netdev, __be16 proto,
				   u16 vid)
{
	return cnf10k_rfoe_vlan_rx_configure(netdev, vid, true);
}

static int cnf10k_rfoe_vlan_rx_kill(struct net_device *netdev, __be16 proto,
				    u16 vid)
{
	return cnf10k_rfoe_vlan_rx_configure(netdev, vid, false);
}

static u16 cnf10k_rfoe_select_queue(struct net_device *netdev,
				    struct sk_buff *skb,
				    struct net_device *sb_dev)
{
	/* Pick queue 0 for PTP packets and 1 for other packets.
	 * Out of two hardware PSM queues used by an RFOE, PTP packets
	 * are submitted to one queue and others are submitted to another queue.
	 * Without this netdev queue selection, stopping one netdev queue by
	 * netif_stop_queue stops both ptp and other packet jobs.
	 * Hence use separate netdev queues.
	 */
	if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)
		return PTP_QUEUE_ID;
	else
		return OTH_QUEUE_ID;
}

static const struct net_device_ops cnf10k_rfoe_netdev_ops = {
	.ndo_init		= cnf10k_rfoe_init,
	.ndo_open		= cnf10k_rfoe_eth_open,
	.ndo_stop		= cnf10k_rfoe_eth_stop,
	.ndo_start_xmit		= cnf10k_rfoe_eth_start_xmit,
	.ndo_change_mtu		= cnf10k_change_mtu,
	.ndo_eth_ioctl		= cnf10k_rfoe_ioctl,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats64	= cnf10k_rfoe_get_stats64,
	.ndo_vlan_rx_add_vid	= cnf10k_rfoe_vlan_rx_add,
	.ndo_vlan_rx_kill_vid	= cnf10k_rfoe_vlan_rx_kill,
	.ndo_select_queue	= cnf10k_rfoe_select_queue,
};

static void cnf10k_rfoe_dump_rx_ft_cfg(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct cnf10k_rx_ft_cfg *ft_cfg;
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

static void cnf10k_rfoe_fill_rx_ft_cfg(struct cnf10k_rfoe_ndev_priv *priv,
				       struct cnf10k_bphy_ndev_comm_if *if_cfg)
{
	struct otx2_bphy_cdev_priv *cdev_priv = priv->cdev_priv;
	struct cnf10k_bphy_ndev_rbuf_info *rbuf_info;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	u64 jdt_cfg0, iova;
	int idx;

	/* RX flow table configuration */
	for (idx = 0; idx < PACKET_TYPE_MAX; idx++) {
		if (!(priv->pkt_type_mask & (1U << idx)))
			continue;
		ft_cfg = &priv->rx_ft_cfg[idx];
		rbuf_info = &if_cfg->rbuf_info[idx];
		ft_cfg->pkt_type = rbuf_info->pkt_type;
		ft_cfg->gp_int_num = (enum bphy_netdev_rx_gpint)rbuf_info->gp_int_num;
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
			CNF10K_RFOEX_RX_INDIRECT_INDEX_OFFSET(priv->rfoe_num)));
		jdt_cfg0 = readq(priv->rfoe_reg_base +
				 CNF10K_RFOEX_RX_IND_JDT_CFG0(priv->rfoe_num));
		spin_unlock(&cdev_priv->mbt_lock);
		ft_cfg->jd_rd_offset = ((jdt_cfg0 >> 27) & 0x3f) * 8;
		ft_cfg->pkt_offset = (u8)((jdt_cfg0 >> 52) & 0x1f);
		ft_cfg->priv = priv;
		netif_napi_add(priv->netdev, &ft_cfg->napi,
			       cnf10k_rfoe_napi_poll,
			       NAPI_POLL_WEIGHT);
	}
}

static void cnf10k_rfoe_fill_tx_job_entries(struct cnf10k_rfoe_ndev_priv *priv,
					    struct tx_job_queue_cfg *job_cfg,
				struct cnf10k_bphy_ndev_tx_psm_cmd_info *tx_job,
					    int num_entries)
{
	struct cnf10k_mhbw_jd_dma_cfg_word_1_s *jd_dma_cfg_word_1;
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
		jd_dma_cfg_word_1 = (struct cnf10k_mhbw_jd_dma_cfg_word_1_s *)
						((u8 __force *)job_entry->rd_dma_ptr + 8);
		job_entry->pkt_dma_addr = otx2_iova_to_virt(priv->iommu_domain,
							    jd_dma_cfg_word_1->start_addr);

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

int cnf10k_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				    struct cnf10k_rfoe_ndev_comm_intf_cfg *cfg)
{
	int i, intf_idx = 0, num_entries, lmac, idx, ret;
	struct cnf10k_bphy_ndev_tx_psm_cmd_info *tx_info;
	struct cnf10k_bphy_ndev_tx_ptp_ring_info *info;
	struct cnf10k_rfoe_drv_ctx *drv_ctx = NULL;
	struct cnf10k_rfoe_ndev_priv *priv, *priv2;
	struct cnf10k_bphy_ndev_rfoe_if *rfoe_cfg;
	struct cnf10k_bphy_ndev_comm_if *if_cfg;
	struct tx_ptp_ring_cfg *ptp_ring_cfg;
	struct tx_job_queue_cfg *tx_cfg;
	struct cnf10k_rx_ft_cfg *ft_cfg;
	struct ptp_bcn_off_cfg *ptp_cfg;
	struct net_device *netdev;
	u8 ptp_errata = false;
	u8 pkt_type_mask;

	cdev->hw_version = cfg->hw_params.chip_ver;
	dev_dbg(cdev->dev, "hw_version = 0x%x\n", cfg->hw_params.chip_ver);

	if (CHIP_CNF10KB(cdev->hw_version)) {
		cdev->num_rfoe_mhab = 7;
		cdev->num_rfoe_lmac = 2;
		cdev->tot_rfoe_intf = 14;
	} else if (CHIP_CNF10KA(cdev->hw_version)) {
		cdev->num_rfoe_mhab = 2;
		cdev->num_rfoe_lmac = 4;
		cdev->tot_rfoe_intf = 8;
		ptp_errata = true;
	} else {
		dev_err(cdev->dev, "unsupported chip version\n");
		return -EINVAL;
	}

	ptp_cfg = kzalloc(sizeof(*ptp_cfg), GFP_KERNEL);
	if (!ptp_cfg)
		return -ENOMEM;
	timer_setup(&ptp_cfg->ptp_timer, cnf10k_rfoe_ptp_offset_timer, 0);
	ptp_cfg->clk_cfg.clk_freq_ghz = PTP_CLK_FREQ_GHZ;
	ptp_cfg->clk_cfg.clk_freq_div = PTP_CLK_FREQ_DIV;
	spin_lock_init(&ptp_cfg->lock);

	for (i = 0; i < cdev->num_rfoe_mhab; i++) {
		priv2 = NULL;
		rfoe_cfg = &cfg->rfoe_if_cfg[i];
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
					"rfoe%d lmac%d invalid intf cfg, skipping\n",
					i, lmac);
				continue;
			}
			netdev = alloc_etherdev_mqs(sizeof(*priv), BPHY_NDEV_NUM_TXQ,
						    BPHY_NDEV_NUM_RXQ);
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
			priv->ndev_flags = if_cfg->ndev_flags;
			priv->if_type = IF_TYPE_ETHERNET;
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
			if (!priv->iommu_domain) {
				ret = -ENODEV;
				goto err_exit;
			}

			priv->bphy_reg_base = bphy_reg_base;
			priv->psm_reg_base = psm_reg_base;
			priv->rfoe_reg_base = rfoe_reg_base;
			priv->bcn_reg_base = bcn_reg_base;
			priv->ptp_reg_base = ptp_reg_base;
			priv->ptp_cfg = ptp_cfg;
			priv->ptp_errata = ptp_errata;
			++(priv->ptp_cfg->refcnt);

			/* Initialise PTP TX work queue */
			INIT_WORK(&priv->ptp_tx_work, cnf10k_rfoe_ptp_tx_work);

			timer_setup(&priv->tx_timer,
				    cnf10k_rfoe_tx_timer_cb, 0);

			priv->pkt_type_mask = pkt_type_mask;
			cnf10k_rfoe_fill_rx_ft_cfg(priv, if_cfg);
			cnf10k_rfoe_dump_rx_ft_cfg(priv);

			/* TX PTP job configuration */
			if (priv->pkt_type_mask & (1U << PACKET_TYPE_PTP)) {
				tx_cfg = &priv->tx_ptp_job_cfg;
				tx_info = &if_cfg->ptp_pkt_info[0];
				num_entries = MAX_PTP_MSG_PER_LMAC;
				cnf10k_rfoe_fill_tx_job_entries(priv, tx_cfg,
								tx_info,
								num_entries);
				/* fill ptp ring info */
				ptp_ring_cfg = &priv->ptp_ring_cfg;
				info = &if_cfg->ptp_ts_ring_info[0];
				ptp_ring_cfg->ptp_ring_base =
					otx2_iova_to_virt(priv->iommu_domain,
							  info->ring_iova_addr);
				ptp_ring_cfg->ptp_ring_id = info->ring_idx;
				ptp_ring_cfg->ptp_ring_size = info->ring_size;
				ptp_ring_cfg->ptp_ring_idx = 0;
			}

			/* TX ECPRI/OTH(PTP) job configuration */
			if (!priv2 &&
			    ((priv->pkt_type_mask &
			      (1U << PACKET_TYPE_OTHER)) ||
			     (priv->pkt_type_mask &
			      (1U << PACKET_TYPE_ECPRI)))) {
				num_entries = cdev->num_rfoe_lmac *
						MAX_OTH_MSG_PER_LMAC;
				tx_cfg = &priv->rfoe_common->tx_oth_job_cfg;
				tx_info = &rfoe_cfg->oth_pkt_info[0];
				cnf10k_rfoe_fill_tx_job_entries(priv, tx_cfg,
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
			netdev->netdev_ops = &cnf10k_rfoe_netdev_ops;
			cnf10k_rfoe_set_ethtool_ops(netdev);
			cnf10k_rfoe_ptp_init(priv);
			netdev->watchdog_timeo = (15 * HZ);
			netdev->mtu = 1500U;
			netdev->min_mtu = ETH_MIN_MTU;
			netdev->max_mtu = CNF10K_RFOE_MAX_MTU;
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
			netif_tx_stop_all_queues(netdev);
			set_bit(RFOE_INTF_DOWN, &priv->state);
			priv->link_state = LINK_STATE_UP;

			/* initialize global ctx */
			drv_ctx = &cnf10k_rfoe_drv_ctx[intf_idx];
			drv_ctx->rfoe_num = priv->rfoe_num;
			drv_ctx->lmac_id = priv->lmac_id;
			drv_ctx->valid = 1;
			drv_ctx->netdev = netdev;
			drv_ctx->ft_cfg = &priv->rx_ft_cfg[0];

			/* create debugfs entry */
			cnf10k_rfoe_debugfs_create(drv_ctx);
		}
	}

	return 0;

err_exit:
	for (i = 0; i < CNF10K_RFOE_MAX_INTF; i++) {
		drv_ctx = &cnf10k_rfoe_drv_ctx[i];
		if (drv_ctx->valid) {
			cnf10k_rfoe_debugfs_remove(drv_ctx);
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			cnf10k_rfoe_ptp_destroy(priv);
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

void cnf10k_rfoe_set_link_state(struct net_device *netdev, u8 state)
{
	struct cnf10k_rfoe_ndev_priv *priv;

	priv = netdev_priv(netdev);

	spin_lock(&priv->lock);
	if (priv->link_state != state) {
		priv->link_state = state;
		if (state == LINK_STATE_DOWN) {
			netdev_info(netdev, "Link DOWN\n");
			if (netif_running(netdev)) {
				netif_carrier_off(netdev);
				netif_tx_stop_all_queues(netdev);
			}
		} else {
			netdev_info(netdev, "Link UP\n");
			if (netif_running(netdev)) {
				netif_carrier_on(netdev);
				netif_tx_start_all_queues(netdev);
			}
		}
	}
	spin_unlock(&priv->lock);
}
