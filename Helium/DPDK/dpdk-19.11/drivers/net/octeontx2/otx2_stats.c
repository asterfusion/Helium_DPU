/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <inttypes.h>

#include "otx2_ethdev.h"

struct otx2_nix_xstats_name {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
};

static const struct otx2_nix_xstats_name nix_tx_xstats[] = {
	{"tx_ucast", NIX_STAT_LF_TX_TX_UCAST},
	{"tx_bcast", NIX_STAT_LF_TX_TX_BCAST},
	{"tx_mcast", NIX_STAT_LF_TX_TX_MCAST},
	{"tx_drop", NIX_STAT_LF_TX_TX_DROP},
	{"tx_octs", NIX_STAT_LF_TX_TX_OCTS},
};

static const struct otx2_nix_xstats_name nix_rx_xstats[] = {
	{"rx_octs", NIX_STAT_LF_RX_RX_OCTS},
	{"rx_ucast", NIX_STAT_LF_RX_RX_UCAST},
	{"rx_bcast", NIX_STAT_LF_RX_RX_BCAST},
	{"rx_mcast", NIX_STAT_LF_RX_RX_MCAST},
	{"rx_drop", NIX_STAT_LF_RX_RX_DROP},
	{"rx_drop_octs", NIX_STAT_LF_RX_RX_DROP_OCTS},
	{"rx_fcs", NIX_STAT_LF_RX_RX_FCS},
	{"rx_err", NIX_STAT_LF_RX_RX_ERR},
	{"rx_drp_bcast", NIX_STAT_LF_RX_RX_DRP_BCAST},
	{"rx_drp_mcast", NIX_STAT_LF_RX_RX_DRP_MCAST},
	{"rx_drp_l3bcast", NIX_STAT_LF_RX_RX_DRP_L3BCAST},
	{"rx_drp_l3mcast", NIX_STAT_LF_RX_RX_DRP_L3MCAST},
};

static const struct otx2_nix_xstats_name nix_q_xstats[] = {
	{"rq_op_re_pkts", NIX_LF_RQ_OP_RE_PKTS},
};

static const struct otx2_nix_xstats_name nix_rx_xstats_cgx[] = {
	{"cgx_rx_pkts",             NIX_CGX_RX_PKT_CNT},
	{"cgx_rx_octs",             NIX_CGX_RX_OCT_CNT},
	{"cgx_rx_pause_pkts",       NIX_CGX_RX_PAUSE_PKT_CNT},
	{"cgx_rx_pause_octs",       NIX_CGX_RX_PAUSE_OCT_CNT},
	{"cgx_rx_fifo_drop_pkts",   NIX_CGX_RX_FIFO_DROP_PKT_CNT},
	{"cgx_rx_fifo_drop_octs",   NIX_CGX_RX_FIFO_DROP_OCT_CNT},
	{"cgx_rx_errors",           NIX_CGX_RX_ERR_CNT},
};

static const struct otx2_nix_xstats_name nix_tx_xstats_cgx[] = {
	{"cgx_tx_collision_drop",        NIX_CGX_TX_COLLISION_DROP},
	{"cgx_tx_multiple_collision",    NIX_CGX_TX_MULTIPLE_COLLISION},
	{"cgx_tx_single_collision",      NIX_CGX_TX_SINGLE_COLLISION},
	{"cgx_tx_octs",                  NIX_CGX_TX_OCT_CNT},
	{"cgx_tx_pkts",                  NIX_CGX_TX_PKT_CNT},
	{"cgx_tx_1_to_63_oct_frames",      NIX_CGX_TX_1_63_PKT_CNT},
	{"cgx_tx_64_oct_frames",           NIX_CGX_TX_64_PKT_CNT},
	{"cgx_tx_65_to_127_oct_frames",    NIX_CGX_TX_65_127_PKT_CNT},
	{"cgx_tx_128_to_255_oct_frames",   NIX_CGX_TX_128_255_PKT_CNT},
	{"cgx_tx_256_to_511_oct_frames",   NIX_CGX_TX_256_511_PKT_CNT},
	{"cgx_tx_512_to_1023_oct_frames",  NIX_CGX_TX_512_1023_PKT_CNT},
	{"cgx_tx_1024_to_1518_oct_frames", NIX_CGX_TX_1024_1518_PKT_CNT},
	{"cgx_tx_1519_to_max_oct_frames",  NIX_CGX_TX_1519_MAX_PKT_CNT},
	{"cgx_tx_broadcast_packets",       NIX_CGX_TX_BCAST_PKTS},
	{"cgx_tx_multicast_packets",       NIX_CGX_TX_MCAST_PKTS},
	{"cgx_tx_underflow_packets",       NIX_CGX_TX_UFLOW_PKTS},
	{"cgx_tx_pause_packets",           NIX_CGX_TX_PAUSE_PKTS},
};

#define OTX2_NIX_NUM_RX_XSTATS RTE_DIM(nix_rx_xstats)
#define OTX2_NIX_NUM_TX_XSTATS RTE_DIM(nix_tx_xstats)
#define OTX2_NIX_NUM_QUEUE_XSTATS RTE_DIM(nix_q_xstats)
#define OTX2_NIX_NUM_RX_XSTATS_CGX RTE_DIM(nix_rx_xstats_cgx)
#define OTX2_NIX_NUM_TX_XSTATS_CGX RTE_DIM(nix_tx_xstats_cgx)

#define OTX2_NIX_NUM_XSTATS_REG (OTX2_NIX_NUM_RX_XSTATS + \
		OTX2_NIX_NUM_TX_XSTATS + OTX2_NIX_NUM_QUEUE_XSTATS)
#define OTX2_NIX_NUM_XSTATS_CGX (OTX2_NIX_NUM_XSTATS_REG + \
		OTX2_NIX_NUM_RX_XSTATS_CGX + OTX2_NIX_NUM_TX_XSTATS_CGX)

static inline unsigned int num_xstats(struct otx2_eth_dev *dev)
{
	if (otx2_dev_is_sdp(dev))
		return OTX2_NIX_NUM_XSTATS_REG;
	else
		return OTX2_NIX_NUM_XSTATS_CGX;
}

int
otx2_nix_dev_stats_get(struct rte_eth_dev *eth_dev,
		       struct rte_eth_stats *stats)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	uint64_t reg, val;
	uint32_t qidx, i;
	int64_t *addr;

	stats->opackets = otx2_read64(dev->base +
			NIX_LF_TX_STATX(NIX_STAT_LF_TX_TX_UCAST));
	stats->opackets += otx2_read64(dev->base +
			NIX_LF_TX_STATX(NIX_STAT_LF_TX_TX_MCAST));
	stats->opackets += otx2_read64(dev->base +
			NIX_LF_TX_STATX(NIX_STAT_LF_TX_TX_BCAST));
	stats->oerrors = otx2_read64(dev->base +
			NIX_LF_TX_STATX(NIX_STAT_LF_TX_TX_DROP));
	stats->obytes = otx2_read64(dev->base +
			NIX_LF_TX_STATX(NIX_STAT_LF_TX_TX_OCTS));

	stats->ipackets = otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_UCAST));
	stats->ipackets += otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_MCAST));
	stats->ipackets += otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_BCAST));
	stats->imissed = otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_DROP));
	stats->ibytes = otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_OCTS));
	stats->ierrors = otx2_read64(dev->base +
			NIX_LF_RX_STATX(NIX_STAT_LF_RX_RX_ERR));

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		if (dev->txmap[i] & (1U << 31)) {
			qidx = dev->txmap[i] & 0xFFFF;
			reg = (((uint64_t)qidx) << 32);

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_opackets[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_OCTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_obytes[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_DROP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] = val;
		}
        else if(i < dev->configured_nb_tx_qs) {
			qidx = i;
			reg = (((uint64_t)qidx) << 32);

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_opackets[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_OCTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_obytes[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_SQ_OP_DROP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] = val;
        }
	}

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		if (dev->rxmap[i] & (1U << 31)) {
			qidx = dev->rxmap[i] & 0xFFFF;
			reg = (((uint64_t)qidx) << 32);

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_ipackets[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_OCTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_ibytes[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_DROP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_RE_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] += val;
		}
        else if(i < dev->configured_nb_rx_qs) {
			qidx = i;
			reg = (((uint64_t)qidx) << 32);

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_ipackets[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_OCTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_ibytes[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_DROP_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] = val;

			addr = (int64_t *)(dev->base + NIX_LF_RQ_OP_RE_PKTS);
			val = otx2_atomic64_add_nosync(reg, addr);
			if (val & OP_ERR)
				val = 0;
			stats->q_errors[i] += val;
        }
	}

	return 0;
}

int
otx2_nix_dev_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	struct otx2_mbox *mbox = dev->mbox;

	if (otx2_mbox_alloc_msg_nix_stats_rst(mbox) == NULL)
		return -ENOMEM;

	return otx2_mbox_process(mbox);
}

int
otx2_nix_queue_stats_mapping(struct rte_eth_dev *eth_dev, uint16_t queue_id,
			     uint8_t stat_idx, uint8_t is_rx)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);

	if (is_rx)
		dev->rxmap[stat_idx] = ((1U << 31) | queue_id);
	else
		dev->txmap[stat_idx] = ((1U << 31) | queue_id);

	return 0;
}

int
otx2_nix_xstats_get(struct rte_eth_dev *eth_dev,
		    struct rte_eth_xstat *xstats,
		    unsigned int n)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	struct otx2_mbox *mbox = dev->mbox;
	struct msg_req *req;
	struct cgx_stats_rsp *stat_resp;
	unsigned int i, count = 0, xstat_cnt;
	//uint64_t reg, val;
	int rc;

	xstat_cnt = num_xstats(dev);
	if (n < xstat_cnt) {
		return xstat_cnt;
	}

	if (xstats == NULL)
		return 0;

	if (!otx2_dev_is_sdp(dev)) {
	  req = otx2_mbox_alloc_msg_cgx_stats(mbox);
	  req->hdr.pcifunc = dev->pf_func;
	  rc = otx2_mbox_process_msg(mbox, (void *)&stat_resp);
	  if (rc)
	      return rc;
    }

	for (i = 0; i < OTX2_NIX_NUM_TX_XSTATS; i++) {
		xstats[count].value = otx2_read64(dev->base +
		NIX_LF_TX_STATX(nix_tx_xstats[i].offset));
		xstats[count].id = count;
		count++;
	}

	for (i = 0; i < OTX2_NIX_NUM_RX_XSTATS; i++) {
		xstats[count].value = otx2_read64(dev->base +
		NIX_LF_RX_STATX(nix_rx_xstats[i].offset));
		xstats[count].id = count;
		count++;
	}

        /* this value is not valid, you can see the q_errors to see re_pkts by marvin */
#if 0
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		reg = (((uint64_t)i) << 32);
		val = otx2_atomic64_add_nosync(reg, (int64_t *)(dev->base +
					       nix_q_xstats[0].offset));
		if (val & OP_ERR)
			val = 0;
		xstats[count].value += val;
	}
#else
    xstats[count].value = 0;
#endif
	xstats[count].id = count;
	count++;

	if (otx2_dev_is_sdp(dev))
		return count;

	for (i = 0; i < OTX2_NIX_NUM_RX_XSTATS_CGX; i++) {
		xstats[count].value =
			stat_resp->rx_stats[nix_rx_xstats_cgx[i].offset];
		xstats[count].id = count;
		count++;
	}

	for (i = 0; i < OTX2_NIX_NUM_TX_XSTATS_CGX; i++) {
		xstats[count].value =
			stat_resp->tx_stats[nix_tx_xstats_cgx[i].offset];
		xstats[count].id = count;
		count++;
	}
	return count;
}

int
otx2_nix_xstats_get_names(struct rte_eth_dev *eth_dev,
			  struct rte_eth_xstat_name *xstats_names,
			  unsigned int limit)
{
	unsigned int i, count = 0;
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	unsigned int xstat_cnt;

	RTE_SET_USED(eth_dev);

	xstat_cnt = num_xstats(dev);
	if (limit < xstat_cnt && xstats_names != NULL)
		return -ENOMEM;

	if (xstats_names) {
		for (i = 0; i < OTX2_NIX_NUM_TX_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", nix_tx_xstats[i].name);
			count++;
		}

		for (i = 0; i < OTX2_NIX_NUM_RX_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", nix_rx_xstats[i].name);
			count++;
		}

		for (i = 0; i < OTX2_NIX_NUM_QUEUE_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", nix_q_xstats[i].name);
			count++;
		}

		if (otx2_dev_is_sdp(dev))
			return count;

		for (i = 0; i < OTX2_NIX_NUM_RX_XSTATS_CGX; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", nix_rx_xstats_cgx[i].name);
			count++;
		}

		for (i = 0; i < OTX2_NIX_NUM_TX_XSTATS_CGX; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", nix_tx_xstats_cgx[i].name);
			count++;
		}
	}

	return xstat_cnt;
}

int
otx2_nix_xstats_get_names_by_id(struct rte_eth_dev *eth_dev,
				struct rte_eth_xstat_name *xstats_names,
				const uint64_t *ids, unsigned int limit)
{
	struct rte_eth_xstat_name xstats_names_copy[OTX2_NIX_NUM_XSTATS_CGX];
	uint16_t i;
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	unsigned int xstat_cnt;

	xstat_cnt = num_xstats(dev);

	if (limit < xstat_cnt && ids == NULL)
		return xstat_cnt;

	if (limit > xstat_cnt)
		return -EINVAL;

	if (xstats_names == NULL)
		return -ENOMEM;

	otx2_nix_xstats_get_names(eth_dev, xstats_names_copy, limit);

	for (i = 0; i < xstat_cnt; i++) {
		if (ids[i] >= xstat_cnt) {
			otx2_err("Invalid id value");
			return -EINVAL;
		}
		strncpy(xstats_names[i].name, xstats_names_copy[ids[i]].name,
			sizeof(xstats_names[i].name));
	}

	return limit;
}

int
otx2_nix_xstats_get_by_id(struct rte_eth_dev *eth_dev, const uint64_t *ids,
			  uint64_t *values, unsigned int n)
{
	struct rte_eth_xstat xstats[OTX2_NIX_NUM_XSTATS_CGX];
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	unsigned int xstat_cnt;
	uint16_t i;

	xstat_cnt = num_xstats(dev);
	if (n < xstat_cnt && ids == NULL)
		return xstat_cnt;

	if (n > xstat_cnt)
		return -EINVAL;

	if (values == NULL)
		return -ENOMEM;

	otx2_nix_xstats_get(eth_dev, xstats, n);

	for (i = 0; i < xstat_cnt; i++) {
		if (ids[i] >= xstat_cnt) {
			otx2_err("Invalid id value");
			return -EINVAL;
		}
		values[i] = xstats[ids[i]].value;
	}

	return n;
}

static int
nix_queue_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	struct otx2_mbox *mbox = dev->mbox;
	struct nix_aq_enq_rsp *rsp;
	struct nix_aq_enq_req *aq;
	uint32_t i;
	int rc;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		aq = otx2_mbox_alloc_msg_nix_aq_enq(mbox);
		aq->qidx = i;
		aq->ctype = NIX_AQ_CTYPE_RQ;
		aq->op = NIX_AQ_INSTOP_READ;
		rc = otx2_mbox_process_msg(mbox, (void *)&rsp);
		if (rc) {
			otx2_err("Failed to read rq context");
			return rc;
		}
		aq = otx2_mbox_alloc_msg_nix_aq_enq(mbox);
		aq->qidx = i;
		aq->ctype = NIX_AQ_CTYPE_RQ;
		aq->op = NIX_AQ_INSTOP_WRITE;
		otx2_mbox_memcpy(&aq->rq, &rsp->rq, sizeof(rsp->rq));
		otx2_mbox_memset(&aq->rq_mask, 0, sizeof(aq->rq_mask));
		aq->rq.octs = 0;
		aq->rq.pkts = 0;
		aq->rq.drop_octs = 0;
		aq->rq.drop_pkts = 0;
		aq->rq.re_pkts = 0;

		aq->rq_mask.octs = ~(aq->rq_mask.octs);
		aq->rq_mask.pkts = ~(aq->rq_mask.pkts);
		aq->rq_mask.drop_octs = ~(aq->rq_mask.drop_octs);
		aq->rq_mask.drop_pkts = ~(aq->rq_mask.drop_pkts);
		aq->rq_mask.re_pkts = ~(aq->rq_mask.re_pkts);
		rc = otx2_mbox_process(mbox);
		if (rc) {
			otx2_err("Failed to write rq context");
			return rc;
		}
	}

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		aq = otx2_mbox_alloc_msg_nix_aq_enq(mbox);
		aq->qidx = i;
		aq->ctype = NIX_AQ_CTYPE_SQ;
		aq->op = NIX_AQ_INSTOP_READ;
		rc = otx2_mbox_process_msg(mbox, (void *)&rsp);
		if (rc) {
			otx2_err("Failed to read sq context");
			return rc;
		}
		aq = otx2_mbox_alloc_msg_nix_aq_enq(mbox);
		aq->qidx = i;
		aq->ctype = NIX_AQ_CTYPE_SQ;
		aq->op = NIX_AQ_INSTOP_WRITE;
		otx2_mbox_memcpy(&aq->sq, &rsp->sq, sizeof(rsp->sq));
		otx2_mbox_memset(&aq->sq_mask, 0, sizeof(aq->sq_mask));
		aq->sq.octs = 0;
		aq->sq.pkts = 0;
		aq->sq.drop_octs = 0;
		aq->sq.drop_pkts = 0;

		aq->sq_mask.octs = ~(aq->sq_mask.octs);
		aq->sq_mask.pkts = ~(aq->sq_mask.pkts);
		aq->sq_mask.drop_octs = ~(aq->sq_mask.drop_octs);
		aq->sq_mask.drop_pkts = ~(aq->sq_mask.drop_pkts);
		rc = otx2_mbox_process(mbox);
		if (rc) {
			otx2_err("Failed to write sq context");
			return rc;
		}
	}

	return 0;
}

int
otx2_nix_xstats_reset(struct rte_eth_dev *eth_dev)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);
	struct otx2_mbox *mbox = dev->mbox;
	int ret;

	if (otx2_mbox_alloc_msg_nix_stats_rst(mbox) == NULL)
		return -ENOMEM;

	ret = otx2_mbox_process(mbox);
	if (ret != 0)
		return ret;

    /* Reset cgx stats */
    if (!otx2_dev_is_sdp(dev)) {
        if (otx2_mbox_alloc_msg_cgx_stats_rst(mbox) == NULL)
            return -ENOMEM;

        ret = otx2_mbox_process(mbox);
        if (ret != 0)
            return ret;
    }

	/* Reset queue stats */
	return nix_queue_stats_reset(eth_dev);
}
