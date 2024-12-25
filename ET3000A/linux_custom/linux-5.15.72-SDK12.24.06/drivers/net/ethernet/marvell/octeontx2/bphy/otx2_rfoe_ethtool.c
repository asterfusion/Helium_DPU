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

static const char ethtool_stat_strings[][ETH_GSTRING_LEN] = {
	"oth_rx_packets",
	"ptp_rx_packets",
	"ecpri_rx_packets",
	"rx_bytes",
	"oth_tx_packets",
	"ptp_tx_packets",
	"ecpri_tx_packets",
	"tx_bytes",
	"oth_rx_dropped",
	"ptp_rx_dropped",
	"ecpri_rx_dropped",
	"oth_tx_dropped",
	"ptp_tx_dropped",
	"ecpri_tx_dropped",
	"ptp_tx_hwtstamp_failures",
	"EthIfInFrames",
	"EthIfInOctets",
	"EthIfInErrDropFrames",
	"EthIfInFullDropFrames",
	"EthIfInEcpriErrDropFrames",
	"EthIfInFtDropFrames",
	"EthIfInFdSosDropFrames",
	"EthIfInOrderinfoFail",
	"EthIfInDmaFrames",
	"EthIfInDmaOctets",
	"EthIfInDmaComplete",
	"EthIfInRxVlanFwd",
	"EthIfOutFrames",
	"EthIfOutOctets",
	"EthIfOutDropFrames",
	"EthIfInUnknownVlan",
};

static void otx2_rfoe_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		memcpy(data, *ethtool_stat_strings,
		       sizeof(ethtool_stat_strings));
		break;
	}
}

static int otx2_rfoe_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stat_strings);
	default:
		return -EOPNOTSUPP;
	}
}

static void otx2_rfoe_update_lmac_stats(struct otx2_rfoe_ndev_priv *priv)
{
	struct otx2_rfoe_stats *stats = &priv->stats;

	stats->EthIfInFrames = readq(priv->rfoe_reg_base +
				     RFOEX_RX_CGX_PKT_STAT(priv->rfoe_num,
							   priv->lmac_id));
	stats->EthIfInOctets = readq(priv->rfoe_reg_base +
				     RFOEX_RX_CGX_OCTS_STAT(priv->rfoe_num,
							    priv->lmac_id));
	stats->ethifinerrdropframes = readq(priv->rfoe_reg_base +
					    RFOEX_RX_PKT_ERR_DROP_STAT(priv->rfoe_num));
	stats->ethifinecprierrdropframes = readq(priv->rfoe_reg_base +
						 RFOEX_RX_ECPRI_ERR_DROP_STATX(priv->rfoe_num,
									       priv->lmac_id));
	stats->ethifinftdropframes = readq(priv->rfoe_reg_base +
					   RFOEX_RX_FT_ENABLE_DROP_STAT(priv->rfoe_num));
	stats->ethifinfdsosdropframes = readq(priv->rfoe_reg_base +
					      RFOEX_RX_FD_SOS_DROP_STAT(priv->rfoe_num));
	stats->ethifinorderinfofail = readq(priv->rfoe_reg_base +
					    RFOEX_RX_ORDERINFO_FAIL_STAT(priv->rfoe_num));
	stats->ethifindmaframes = readq(priv->rfoe_reg_base +
					RFOEX_RX_DMA_PKT_STATX(priv->rfoe_num, priv->lmac_id));
	stats->ethifindmaoctets = readq(priv->rfoe_reg_base +
					RFOEX_RX_DMA_OCTS_STATX(priv->rfoe_num, priv->lmac_id));
	stats->ethifindmacomplete = readq(priv->rfoe_reg_base +
					  RFOEX_RX_DMA_COMPLETE_STATX(priv->rfoe_num,
								      priv->lmac_id));
	stats->ethifinrxvlanfwd = readq(priv->rfoe_reg_base +
					RFOEX_RX_VLAN_FWD_STATX(priv->rfoe_num, priv->lmac_id));
	stats->EthIfOutFrames = readq(priv->rfoe_reg_base +
				      RFOEX_TX_PKT_STAT(priv->rfoe_num,
							priv->lmac_id));
	stats->EthIfOutOctets = readq(priv->rfoe_reg_base +
				      RFOEX_TX_OCTS_STAT(priv->rfoe_num,
							 priv->lmac_id));
	stats->ethifoutdropframes = readq(priv->rfoe_reg_base +
					  RFOEX_TX_PKT_DROP_STATX(priv->rfoe_num, priv->lmac_id));
	stats->EthIfInUnknownVlan =
				readq(priv->rfoe_reg_base +
				      RFOEX_RX_VLAN_DROP_STAT(priv->rfoe_num,
							      priv->lmac_id));
}

static void otx2_rfoe_get_ethtool_stats(struct net_device *netdev,
					struct ethtool_stats *stats,
					u64 *data)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	otx2_rfoe_update_lmac_stats(priv);
	spin_lock(&priv->stats.lock);
	memcpy(data, &priv->stats,
	       ARRAY_SIZE(ethtool_stat_strings) * sizeof(u64));
	spin_unlock(&priv->stats.lock);
}

static void otx2_rfoe_get_drvinfo(struct net_device *netdev,
				  struct ethtool_drvinfo *p)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	snprintf(p->driver, sizeof(p->driver), "otx2_rfoe {rfoe%d lmac%d}",
		 priv->rfoe_num, priv->lmac_id);
	strlcpy(p->bus_info, "platform", sizeof(p->bus_info));
}

static int otx2_rfoe_get_ts_info(struct net_device *netdev,
				 struct ethtool_ts_info *info)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->phc_index =  ptp_clock_index(priv->ptp_clock);

	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
			   (1 << HWTSTAMP_FILTER_ALL);

	return 0;
}

static u32 otx2_rfoe_get_msglevel(struct net_device *netdev)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	return priv->msg_enable;
}

static void otx2_rfoe_set_msglevel(struct net_device *netdev, u32 level)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	priv->msg_enable = level;
}

static const struct ethtool_ops otx2_rfoe_ethtool_ops = {
	.get_drvinfo		= otx2_rfoe_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= otx2_rfoe_get_ts_info,
	.get_strings		= otx2_rfoe_get_strings,
	.get_sset_count		= otx2_rfoe_get_sset_count,
	.get_ethtool_stats	= otx2_rfoe_get_ethtool_stats,
	.get_msglevel		= otx2_rfoe_get_msglevel,
	.set_msglevel		= otx2_rfoe_set_msglevel,
};

void otx2_rfoe_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &otx2_rfoe_ethtool_ops;
}
