/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include "octeontx_ethdev.h"
#include "octeontx_rxtx.h"
#include "octeontx_logs.h"

int
octeontx_dev_flow_ctrl_get(struct rte_eth_dev *dev,
			   struct rte_eth_fc_conf *fc_conf)
{
	struct octeontx_nic *nic = octeontx_pmd_priv(dev);
	octeontx_mbox_bgx_port_fc_cfg_t conf;
	int rc;

	memset(&conf, 0, sizeof(octeontx_mbox_bgx_port_fc_cfg_t));

	rc = octeontx_bgx_port_flow_ctrl_cfg(nic->ptbl_id, &conf);
	if (rc)
		return rc;

	if (conf.rx_pause && conf.tx_pause)
		fc_conf->mode = RTE_FC_FULL;
	else if (conf.rx_pause)
		fc_conf->mode = RTE_FC_RX_PAUSE;
	else if (conf.tx_pause)
		fc_conf->mode = RTE_FC_TX_PAUSE;
	else
		fc_conf->mode = RTE_FC_NONE;

	/* low_water & high_water values are in Bytes */
	fc_conf->low_water = conf.low_water;
	fc_conf->high_water = conf.high_water;

	return rc;
}

int
octeontx_dev_flow_ctrl_set(struct rte_eth_dev *dev,
			   struct rte_eth_fc_conf *fc_conf)
{
	struct octeontx_nic *nic = octeontx_pmd_priv(dev);
	struct octeontx_fc_info *fc = &nic->fc;
	octeontx_mbox_bgx_port_fc_cfg_t conf;
	uint8_t tx_pause, rx_pause;
	uint16_t max_high_water;
	int rc;

	if (fc_conf->pause_time || fc_conf->mac_ctrl_frame_fwd ||
	    fc_conf->autoneg) {
		octeontx_log_err("Below flowctrl parameters are not supported "
				 "pause_time, mac_ctrl_frame_fwd and autoneg");
		return -EINVAL;
	}

	if (fc_conf->high_water == fc->high_water &&
	    fc_conf->low_water == fc->low_water &&
	    fc_conf->mode == fc->mode)
		return 0;

	max_high_water = fc->rx_fifosz - OCTEONTX_BGX_RSVD_RX_FIFOBYTES;

	if (fc_conf->high_water > max_high_water ||
	    fc_conf->high_water < fc_conf->low_water) {
		octeontx_log_err("Invalid high/low water values "
				 "High_water(in Bytes) must <= 0x%x ",
				 max_high_water);
		return -EINVAL;
	}

	if (fc_conf->high_water % BIT(4) || fc_conf->low_water % BIT(4)) {
		octeontx_log_err("High/low water value must be multiple of 16");
		return -EINVAL;
	}

	rx_pause = (fc_conf->mode == RTE_FC_FULL) ||
			(fc_conf->mode == RTE_FC_RX_PAUSE);
	tx_pause = (fc_conf->mode == RTE_FC_FULL) ||
			(fc_conf->mode == RTE_FC_TX_PAUSE);

	conf.high_water = fc_conf->high_water;
	conf.low_water = fc_conf->low_water;
	conf.fc_cfg = BGX_PORT_FC_CFG_SET;
	conf.rx_pause = rx_pause;
	conf.tx_pause = tx_pause;

	rc = octeontx_bgx_port_flow_ctrl_cfg(nic->ptbl_id, &conf);
	if (rc)
		return rc;

	fc->high_water = fc_conf->high_water;
	fc->low_water = fc_conf->low_water;
	fc->mode = fc_conf->mode;

	return rc;
}

int
octeontx_dev_flow_ctrl_init(struct rte_eth_dev *dev)
{
	struct octeontx_nic *nic = octeontx_pmd_priv(dev);
	struct octeontx_fc_info *fc = &nic->fc;
	struct rte_eth_fc_conf fc_conf;
	int rc;

	rc = octeontx_dev_flow_ctrl_get(dev, &fc_conf);
	if (rc) {
		octeontx_log_err("Failed to get flow control info");
		return rc;
	}

	fc->def_highmark = fc_conf.high_water;
	fc->def_lowmark = fc_conf.low_water;
	fc->def_mode = fc_conf.mode;

	return rc;
}

int
octeontx_dev_flow_ctrl_fini(struct rte_eth_dev *dev)
{
	struct octeontx_nic *nic = octeontx_pmd_priv(dev);
	struct octeontx_fc_info *fc = &nic->fc;
	struct rte_eth_fc_conf fc_conf;

	memset(&fc_conf, 0, sizeof(struct rte_eth_fc_conf));

	/* Restore flow control parameters with default values */
	fc_conf.high_water = fc->def_highmark;
	fc_conf.low_water = fc->def_lowmark;
	fc_conf.mode = fc->def_mode;

	return octeontx_dev_flow_ctrl_set(dev, &fc_conf);
}
