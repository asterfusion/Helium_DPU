// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU PF/VF Netdev Devlink
 *
 * Copyright (C) 2021 Marvell.
 */

#include "otx2_common.h"

/* Devlink Params APIs */
static int otx2_dl_mcam_count_validate(struct devlink *devlink, u32 id,
				       union devlink_param_value val,
				       struct netlink_ext_ack *extack)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	struct otx2_flow_config *flow_cfg;

	if (!pfvf->flow_cfg) {
		NL_SET_ERR_MSG_MOD(extack,
				   "pfvf->flow_cfg not initialized");
		return -EINVAL;
	}

	flow_cfg = pfvf->flow_cfg;
	if (flow_cfg && flow_cfg->nr_flows) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot modify count when there are active rules");
		return -EINVAL;
	}

	return 0;
}

static int otx2_dl_mcam_count_set(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	if (!pfvf->flow_cfg)
		return 0;

	otx2_alloc_mcam_entries(pfvf, ctx->val.vu16);

	return 0;
}

static int otx2_dl_mcam_count_get(struct devlink *devlink, u32 id,
				  struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	struct otx2_flow_config *flow_cfg;

	if (!pfvf->flow_cfg) {
		ctx->val.vu16 = 0;
		return 0;
	}

	flow_cfg = pfvf->flow_cfg;
	ctx->val.vu16 = flow_cfg->max_flows;

	return 0;
}

static int otx2_dl_tl1_rr_prio_validate(struct devlink *devlink, u32 id,
					union devlink_param_value val,
					struct netlink_ext_ack *extack)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pf = otx2_dl->pfvf;

	if (is_otx2_vf(pf->pcifunc)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TL1RR PRIORITY setting not allowed on VFs");
		return -EOPNOTSUPP;
	}

	if (otx2_is_qos_configured(pf)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TL1RR PRIORITY setting not allowed after QOS config");
		return -EOPNOTSUPP;
	}

	if (pci_num_vf(pf->pdev)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "TL1RR PRIORITY setting not allowed as VFs are already attached");
		return -EOPNOTSUPP;
	}

	if (val.vu8 > 7) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Valid priority range 0 - 7");
		return -EINVAL;
	}

	return 0;
}

static int otx2_dl_tl1_rr_prio_get(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	ctx->val.vu8 = pfvf->hw.txschq_aggr_lvl_rr_prio;

	return 0;
}

static int otx2_dl_tl1_rr_prio_set(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	struct nix_tl1_rr_prio_req *req;
	bool if_up;
	int err;

	if_up = netif_running(pfvf->netdev);

	/* send mailbox to AF */
	mutex_lock(&pfvf->mbox.lock);

	req = otx2_mbox_alloc_msg_nix_tl1_rr_prio(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}

	req->tl1_rr_prio = ctx->val.vu8;
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	mutex_unlock(&pfvf->mbox.lock);

	/* Reconfigure TL1/TL2 DWRR PRIORITY */
	if (!err && if_up) {
		otx2_stop(pfvf->netdev);
		otx2_open(pfvf->netdev);
	}

	return err;
}

static int otx2_dl_rbuf_size_validate(struct devlink *devlink, u32 id,
				      union devlink_param_value val,
				      struct netlink_ext_ack *extack)
{
	/* Hardware supports max size of 32k for a receive buffer
	 * and 1536 is typical ethernet frame size.
	 */
	if (val.vu16 < 1536 || val.vu16 > 32768) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Receive buffer range is 1536 - 32768");
		return -EINVAL;
	}

	return 0;
}

static int otx2_dl_rbuf_size_set(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	struct net_device *netdev;
	int err = 0;
	bool if_up;

	rtnl_lock();

	netdev = pfvf->netdev;
	if_up = netif_running(netdev);
	if (if_up)
		netdev->netdev_ops->ndo_stop(netdev);

	pfvf->hw.rbuf_len = ctx->val.vu16;

	if (if_up)
		err = netdev->netdev_ops->ndo_open(netdev);

	rtnl_unlock();

	return err;
}

static int otx2_dl_rbuf_size_get(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	ctx->val.vu16 = pfvf->hw.rbuf_len;

	return 0;
}

static int otx2_dl_cqe_size_validate(struct devlink *devlink, u32 id,
				     union devlink_param_value val,
				     struct netlink_ext_ack *extack)
{
	if (val.vu16 != 128 && val.vu16 != 512) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Only 128 or 512 byte descriptor allowed");
		return -EINVAL;
	}

	return 0;
}

static int otx2_dl_cqe_size_set(struct devlink *devlink, u32 id,
				struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	struct net_device *netdev;
	int err = 0;
	bool if_up;

	rtnl_lock();

	netdev = pfvf->netdev;
	if_up = netif_running(netdev);
	if (if_up)
		netdev->netdev_ops->ndo_stop(netdev);

	pfvf->hw.xqe_size = ctx->val.vu16;

	if (if_up)
		err = netdev->netdev_ops->ndo_open(netdev);

	rtnl_unlock();

	return err;
}

static int otx2_dl_cqe_size_get(struct devlink *devlink, u32 id,
				struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	ctx->val.vu16 = pfvf->hw.xqe_size;

	return 0;
}

static int otx2_dl_serdes_link_set(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	if (!is_otx2_vf(pfvf->pcifunc))
		return otx2_config_serdes_link_state(pfvf, ctx->val.vbool);

	return -EOPNOTSUPP;
}

static int otx2_dl_serdes_link_get(struct devlink *devlink, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	ctx->val.vbool = (pfvf->linfo.link_up) ? true : false;

	return 0;
}

static int otx2_dl_ucast_flt_cnt_set(struct devlink *devlink, u32 id,
				     struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	int err;

	pfvf->flow_cfg->ucast_flt_cnt = ctx->val.vu8;

	otx2_mcam_flow_del(pfvf);
	err = otx2_mcam_entry_init(pfvf);
	if (err)
		return err;

	return 0;
}

static int otx2_dl_ucast_flt_cnt_get(struct devlink *devlink, u32 id,
				     struct devlink_param_gset_ctx *ctx)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	if (!pfvf->flow_cfg) {
		ctx->val.vu8 = 0;
		return 0;
	}

	ctx->val.vu8 = pfvf->flow_cfg->ucast_flt_cnt;

	return 0;
}

static int otx2_dl_ucast_flt_cnt_validate(struct devlink *devlink, u32 id,
					  union devlink_param_value val,
					  struct netlink_ext_ack *extack)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	/* Check for UNICAST filter support*/
	if (!(pfvf->flags & OTX2_FLAG_UCAST_FLTR_SUPPORT)) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Unicast filter not enabled");
		return -EINVAL;
	}

	if (!pfvf->flow_cfg) {
		NL_SET_ERR_MSG_MOD(extack,
				   "pfvf->flow_cfg not initialized");
		return -EINVAL;
	}

	if (pfvf->flow_cfg->nr_flows) {
		NL_SET_ERR_MSG_MOD(extack,
				   "Cannot modify count when there are active rules");
		return -EINVAL;
	}

	return 0;
}

enum otx2_dl_param_id {
	OTX2_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	OTX2_DEVLINK_PARAM_ID_MCAM_COUNT,
	OTX2_DEVLINK_PARAM_ID_TL1_RR_PRIO,
	OTX2_DEVLINK_PARAM_ID_CQE_SIZE,
	OTX2_DEVLINK_PARAM_ID_RBUF_SIZE,
	OTX2_DEVLINK_PARAM_ID_UCAST_FLT_CNT,
	OTX2_DEVLINK_PARAM_ID_SERDES_LINK,
};

static const struct devlink_param otx2_dl_params[] = {
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_MCAM_COUNT,
			     "mcam_count", DEVLINK_PARAM_TYPE_U16,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_mcam_count_get, otx2_dl_mcam_count_set,
			     otx2_dl_mcam_count_validate),
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_TL1_RR_PRIO,
			     "tl1_rr_prio", DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_tl1_rr_prio_get, otx2_dl_tl1_rr_prio_set,
			     otx2_dl_tl1_rr_prio_validate),
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_CQE_SIZE,
			     "completion_descriptor_size", DEVLINK_PARAM_TYPE_U16,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_cqe_size_get, otx2_dl_cqe_size_set,
			     otx2_dl_cqe_size_validate),
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_RBUF_SIZE,
			     "receive_buffer_size", DEVLINK_PARAM_TYPE_U16,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_rbuf_size_get, otx2_dl_rbuf_size_set,
			     otx2_dl_rbuf_size_validate),
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_SERDES_LINK,
			     "serdes_link", DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_serdes_link_get, otx2_dl_serdes_link_set,
			     NULL),
	DEVLINK_PARAM_DRIVER(OTX2_DEVLINK_PARAM_ID_UCAST_FLT_CNT,
			     "unicast_filter_count", DEVLINK_PARAM_TYPE_U8,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_dl_ucast_flt_cnt_get, otx2_dl_ucast_flt_cnt_set,
			     otx2_dl_ucast_flt_cnt_validate),
};

/* Devlink OPs */
static int otx2_devlink_info_get(struct devlink *devlink,
				 struct devlink_info_req *req,
				 struct netlink_ext_ack *extack)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	if (is_otx2_vf(pfvf->pcifunc))
		return devlink_info_driver_name_put(req, "rvu_nicvf");

	return devlink_info_driver_name_put(req, "rvu_nicpf");
}

static const struct devlink_ops otx2_devlink_ops = {
	.info_get = otx2_devlink_info_get,
};

int otx2_register_dl(struct otx2_nic *pfvf)
{
	struct otx2_devlink *otx2_dl;
	struct devlink *dl;
	int err;

	dl = devlink_alloc(&otx2_devlink_ops,
			   sizeof(struct otx2_devlink), pfvf->dev);
	if (!dl) {
		dev_warn(pfvf->dev, "devlink_alloc failed\n");
		return -ENOMEM;
	}

	otx2_dl = devlink_priv(dl);
	otx2_dl->dl = dl;
	otx2_dl->pfvf = pfvf;
	pfvf->dl = otx2_dl;

	err = devlink_params_register(dl, otx2_dl_params,
				      ARRAY_SIZE(otx2_dl_params));
	if (err) {
		dev_err(pfvf->dev,
			"devlink params register failed with error %d", err);
		goto err_dl;
	}

	devlink_params_publish(dl);
	devlink_register(dl);
	return 0;

err_dl:
	devlink_free(dl);
	return err;
}

void otx2_unregister_dl(struct otx2_nic *pfvf)
{
	struct otx2_devlink *otx2_dl = pfvf->dl;
	struct devlink *dl = otx2_dl->dl;

	devlink_unregister(dl);
	devlink_params_unregister(dl, otx2_dl_params,
				  ARRAY_SIZE(otx2_dl_params));
	devlink_free(dl);
}
