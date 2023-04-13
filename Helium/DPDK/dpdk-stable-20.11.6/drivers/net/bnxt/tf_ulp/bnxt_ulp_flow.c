/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2020 Broadcom
 * All rights reserved.
 */

#include "bnxt.h"
#include "bnxt_tf_common.h"
#include "ulp_rte_parser.h"
#include "ulp_matcher.h"
#include "ulp_flow_db.h"
#include "ulp_mapper.h"
#include "ulp_fc_mgr.h"
#include "ulp_port_db.h"
#include <rte_malloc.h>

static int32_t
bnxt_ulp_flow_validate_args(const struct rte_flow_attr *attr,
			    const struct rte_flow_item pattern[],
			    const struct rte_flow_action actions[],
			    struct rte_flow_error *error)
{
	/* Perform the validation of the arguments for null */
	if (!error)
		return BNXT_TF_RC_ERROR;

	if (!pattern) {
		rte_flow_error_set(error,
				   EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM_NUM,
				   NULL,
				   "NULL pattern.");
		return BNXT_TF_RC_ERROR;
	}

	if (!actions) {
		rte_flow_error_set(error,
				   EINVAL,
				   RTE_FLOW_ERROR_TYPE_ACTION_NUM,
				   NULL,
				   "NULL action.");
		return BNXT_TF_RC_ERROR;
	}

	if (!attr) {
		rte_flow_error_set(error,
				   EINVAL,
				   RTE_FLOW_ERROR_TYPE_ATTR,
				   NULL,
				   "NULL attribute.");
		return BNXT_TF_RC_ERROR;
	}

	if (attr->egress && attr->ingress) {
		rte_flow_error_set(error,
				   EINVAL,
				   RTE_FLOW_ERROR_TYPE_ATTR,
				   attr,
				   "EGRESS AND INGRESS UNSUPPORTED");
		return BNXT_TF_RC_ERROR;
	}
	return BNXT_TF_RC_SUCCESS;
}

static inline void
bnxt_ulp_set_dir_attributes(struct ulp_rte_parser_params *params,
			    const struct rte_flow_attr *attr)
{
	/* Set the flow attributes */
	if (attr->egress)
		params->dir_attr |= BNXT_ULP_FLOW_ATTR_EGRESS;
	if (attr->ingress)
		params->dir_attr |= BNXT_ULP_FLOW_ATTR_INGRESS;
	if (attr->transfer)
		params->dir_attr |= BNXT_ULP_FLOW_ATTR_TRANSFER;
}

void
bnxt_ulp_init_mapper_params(struct bnxt_ulp_mapper_create_parms *mapper_cparms,
			    struct ulp_rte_parser_params *params,
			    enum bnxt_ulp_fdb_type flow_type)
{
	mapper_cparms->flow_type	= flow_type;
	mapper_cparms->app_priority	= params->priority;
	mapper_cparms->dir_attr		= params->dir_attr;
	mapper_cparms->class_tid	= params->class_id;
	mapper_cparms->act_tid		= params->act_tmpl;
	mapper_cparms->func_id		= params->func_id;
	mapper_cparms->hdr_bitmap	= &params->hdr_bitmap;
	mapper_cparms->hdr_field	= params->hdr_field;
	mapper_cparms->comp_fld		= params->comp_fld;
	mapper_cparms->act		= &params->act_bitmap;
	mapper_cparms->act_prop		= &params->act_prop;
	mapper_cparms->flow_id		= params->fid;
	mapper_cparms->parent_flow	= params->parent_flow;
	mapper_cparms->parent_fid	= params->parent_fid;
}

/* Function to create the rte flow. */
static struct rte_flow *
bnxt_ulp_flow_create(struct rte_eth_dev *dev,
		     const struct rte_flow_attr *attr,
		     const struct rte_flow_item pattern[],
		     const struct rte_flow_action actions[],
		     struct rte_flow_error *error)
{
	struct bnxt_ulp_mapper_create_parms mapper_cparms = { 0 };
	struct ulp_rte_parser_params params;
	struct bnxt_ulp_context *ulp_ctx;
	int rc, ret = BNXT_TF_RC_ERROR;
	struct rte_flow *flow_id;
	uint16_t func_id;
	uint32_t fid;

	if (bnxt_ulp_flow_validate_args(attr,
					pattern, actions,
					error) == BNXT_TF_RC_ERROR) {
		BNXT_TF_DBG(ERR, "Invalid arguments being passed\n");
		goto flow_error;
	}

	ulp_ctx = bnxt_ulp_eth_dev_ptr2_cntxt_get(dev);
	if (!ulp_ctx) {
		BNXT_TF_DBG(ERR, "ULP context is not initialized\n");
		goto flow_error;
	}

	/* Initialize the parser params */
	memset(&params, 0, sizeof(struct ulp_rte_parser_params));
	params.ulp_ctx = ulp_ctx;

	/* Set the flow attributes */
	bnxt_ulp_set_dir_attributes(&params, attr);

	/* copy the device port id and direction for further processing */
	ULP_COMP_FLD_IDX_WR(&params, BNXT_ULP_CF_IDX_INCOMING_IF,
			    dev->data->port_id);
	ULP_COMP_FLD_IDX_WR(&params, BNXT_ULP_CF_IDX_SVIF_FLAG,
			    BNXT_ULP_INVALID_SVIF_VAL);

	/* Get the function id */
	if (ulp_port_db_port_func_id_get(ulp_ctx,
					 dev->data->port_id,
					 &func_id)) {
		BNXT_TF_DBG(ERR, "conversion of port to func id failed\n");
		goto flow_error;
	}

	/* Protect flow creation */
	if (bnxt_ulp_cntxt_acquire_fdb_lock(ulp_ctx)) {
		BNXT_TF_DBG(ERR, "Flow db lock acquire failed\n");
		goto flow_error;
	}

	/* Allocate a Flow ID for attaching all resources for the flow to.
	 * Once allocated, all errors have to walk the list of resources and
	 * free each of them.
	 */
	rc = ulp_flow_db_fid_alloc(ulp_ctx, BNXT_ULP_FDB_TYPE_REGULAR,
				   func_id, &fid);
	if (rc) {
		BNXT_TF_DBG(ERR, "Unable to allocate flow table entry\n");
		goto release_lock;
	}

	/* Parse the rte flow pattern */
	ret = bnxt_ulp_rte_parser_hdr_parse(pattern, &params);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto free_fid;

	/* Parse the rte flow action */
	ret = bnxt_ulp_rte_parser_act_parse(actions, &params);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto free_fid;

	params.fid = fid;
	params.func_id = func_id;
	params.priority = attr->priority;
	params.port_id = bnxt_get_phy_port_id(dev->data->port_id);
	/* Perform the rte flow post process */
	ret = bnxt_ulp_rte_parser_post_process(&params);
	if (ret == BNXT_TF_RC_ERROR)
		goto free_fid;
	else if (ret == BNXT_TF_RC_FID)
		goto return_fid;

	ret = ulp_matcher_pattern_match(&params, &params.class_id);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto free_fid;

	ret = ulp_matcher_action_match(&params, &params.act_tmpl);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto free_fid;

	bnxt_ulp_init_mapper_params(&mapper_cparms, &params,
				    BNXT_ULP_FDB_TYPE_REGULAR);
	/* Call the ulp mapper to create the flow in the hardware. */
	ret = ulp_mapper_flow_create(ulp_ctx, &mapper_cparms);
	if (ret)
		goto free_fid;

return_fid:
	bnxt_ulp_cntxt_release_fdb_lock(ulp_ctx);

	flow_id = (struct rte_flow *)((uintptr_t)fid);
	return flow_id;

free_fid:
	ulp_flow_db_fid_free(ulp_ctx, BNXT_ULP_FDB_TYPE_REGULAR, fid);
release_lock:
	bnxt_ulp_cntxt_release_fdb_lock(ulp_ctx);
flow_error:
	rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			   "Failed to create flow.");
	return NULL;
}

/* Function to validate the rte flow. */
static int
bnxt_ulp_flow_validate(struct rte_eth_dev *dev,
		       const struct rte_flow_attr *attr,
		       const struct rte_flow_item pattern[],
		       const struct rte_flow_action actions[],
		       struct rte_flow_error *error)
{
	struct ulp_rte_parser_params params;
	struct bnxt_ulp_context *ulp_ctx;
	uint32_t class_id, act_tmpl;
	int ret = BNXT_TF_RC_ERROR;

	if (bnxt_ulp_flow_validate_args(attr,
					pattern, actions,
					error) == BNXT_TF_RC_ERROR) {
		BNXT_TF_DBG(ERR, "Invalid arguments being passed\n");
		goto parse_error;
	}

	ulp_ctx = bnxt_ulp_eth_dev_ptr2_cntxt_get(dev);
	if (!ulp_ctx) {
		BNXT_TF_DBG(ERR, "ULP context is not initialized\n");
		goto parse_error;
	}

	/* Initialize the parser params */
	memset(&params, 0, sizeof(struct ulp_rte_parser_params));
	params.ulp_ctx = ulp_ctx;

	/* Set the flow attributes */
	bnxt_ulp_set_dir_attributes(&params, attr);

	/* Parse the rte flow pattern */
	ret = bnxt_ulp_rte_parser_hdr_parse(pattern, &params);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto parse_error;

	/* Parse the rte flow action */
	ret = bnxt_ulp_rte_parser_act_parse(actions, &params);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto parse_error;

	/* Perform the rte flow post process */
	ret = bnxt_ulp_rte_parser_post_process(&params);
	if (ret == BNXT_TF_RC_ERROR)
		goto parse_error;
	else if (ret == BNXT_TF_RC_FID)
		return 0;

	ret = ulp_matcher_pattern_match(&params, &class_id);

	if (ret != BNXT_TF_RC_SUCCESS)
		goto parse_error;

	ret = ulp_matcher_action_match(&params, &act_tmpl);
	if (ret != BNXT_TF_RC_SUCCESS)
		goto parse_error;

	/* all good return success */
	return ret;

parse_error:
	rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			   "Failed to validate flow.");
	return -EINVAL;
}

/* Function to destroy the rte flow. */
int
bnxt_ulp_flow_destroy(struct rte_eth_dev *dev,
		      struct rte_flow *flow,
		      struct rte_flow_error *error)
{
	struct bnxt_ulp_context *ulp_ctx;
	uint32_t flow_id;
	uint16_t func_id;
	int ret;

	ulp_ctx = bnxt_ulp_eth_dev_ptr2_cntxt_get(dev);
	if (!ulp_ctx) {
		BNXT_TF_DBG(ERR, "ULP context is not initialized\n");
		if (error)
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					   "Failed to destroy flow.");
		return -EINVAL;
	}

	flow_id = (uint32_t)(uintptr_t)flow;

	if (ulp_port_db_port_func_id_get(ulp_ctx,
					 dev->data->port_id,
					 &func_id)) {
		BNXT_TF_DBG(ERR, "conversion of port to func id failed\n");
		if (error)
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					   "Failed to destroy flow.");
		return -EINVAL;
	}

	if (ulp_flow_db_validate_flow_func(ulp_ctx, flow_id, func_id) ==
	    false) {
		BNXT_TF_DBG(ERR, "Incorrect device params\n");
		if (error)
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					   "Failed to destroy flow.");
		return -EINVAL;
	}

	if (bnxt_ulp_cntxt_acquire_fdb_lock(ulp_ctx)) {
		BNXT_TF_DBG(ERR, "Flow db lock acquire failed\n");
		return -EINVAL;
	}
	ret = ulp_mapper_flow_destroy(ulp_ctx, BNXT_ULP_FDB_TYPE_REGULAR,
				      flow_id);
	if (ret) {
		BNXT_TF_DBG(ERR, "Failed to destroy flow.\n");
		if (error)
			rte_flow_error_set(error, -ret,
					   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					   "Failed to destroy flow.");
	}
	bnxt_ulp_cntxt_release_fdb_lock(ulp_ctx);

	return ret;
}

/* Function to destroy the rte flows. */
static int32_t
bnxt_ulp_flow_flush(struct rte_eth_dev *eth_dev,
		    struct rte_flow_error *error)
{
	struct bnxt_ulp_context *ulp_ctx;
	int32_t ret = 0;
	uint16_t func_id;

	ulp_ctx = bnxt_ulp_eth_dev_ptr2_cntxt_get(eth_dev);
	if (!ulp_ctx) {
		return ret;
	}

	/* Free the resources for the last device */
	if (ulp_ctx_deinit_allowed(ulp_ctx)) {
		ret = ulp_flow_db_session_flow_flush(ulp_ctx);
	} else if (bnxt_ulp_cntxt_ptr2_flow_db_get(ulp_ctx)) {
		ret = ulp_port_db_port_func_id_get(ulp_ctx,
						   eth_dev->data->port_id,
						   &func_id);
		if (!ret)
			ret = ulp_flow_db_function_flow_flush(ulp_ctx, func_id);
		else
			BNXT_TF_DBG(ERR, "convert port to func id failed\n");
	}
	if (ret)
		rte_flow_error_set(error, ret,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Failed to flush flow.");
	return ret;
}

/* Function to query the rte flows. */
static int32_t
bnxt_ulp_flow_query(struct rte_eth_dev *eth_dev,
		    struct rte_flow *flow,
		    const struct rte_flow_action *action,
		    void *data,
		    struct rte_flow_error *error)
{
	int rc = 0;
	struct bnxt_ulp_context *ulp_ctx;
	struct rte_flow_query_count *count;
	uint32_t flow_id;

	ulp_ctx = bnxt_ulp_eth_dev_ptr2_cntxt_get(eth_dev);
	if (!ulp_ctx) {
		BNXT_TF_DBG(ERR, "ULP context is not initialized\n");
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Failed to query flow.");
		return -EINVAL;
	}

	flow_id = (uint32_t)(uintptr_t)flow;

	switch (action->type) {
	case RTE_FLOW_ACTION_TYPE_COUNT:
		count = data;
		rc = ulp_fc_mgr_query_count_get(ulp_ctx, flow_id, count);
		if (rc) {
			rte_flow_error_set(error, EINVAL,
					   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					   "Failed to query flow.");
		}
		break;
	default:
		rte_flow_error_set(error, -rc, RTE_FLOW_ERROR_TYPE_ACTION_NUM,
				   NULL, "Unsupported action item");
	}

	return rc;
}

const struct rte_flow_ops bnxt_ulp_rte_flow_ops = {
	.validate = bnxt_ulp_flow_validate,
	.create = bnxt_ulp_flow_create,
	.destroy = bnxt_ulp_flow_destroy,
	.flush = bnxt_ulp_flow_flush,
	.query = bnxt_ulp_flow_query,
	.isolate = NULL
};
