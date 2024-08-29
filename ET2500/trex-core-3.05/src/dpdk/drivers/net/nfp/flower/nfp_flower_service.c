/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Corigine, Inc.
 * All rights reserved.
 */

#include "nfp_flower_service.h"

#include <rte_spinlock.h>

#include "nfp_flower_ctrl.h"
#include "../nfpcore/nfp_cpp.h"
#include "../nfpcore/nfp_sync.h"
#include "../nfp_logs.h"
#include "../nfp_service.h"

/* Driver limitation, PMD can enlarge it if need. */
#define MAX_FLOWER_SERVICE_SLOT 8

struct nfp_flower_service {
	/** Flower service is enabled */
	bool enabled;
	/** Flower service info */
	struct nfp_service_info info;
	/** Store flower cards' information */
	struct nfp_app_fw_flower *slots[MAX_FLOWER_SERVICE_SLOT];
	/** Spinlock for sync slots when add/remove card */
	rte_spinlock_t spinlock;
};

static struct nfp_flower_service *
nfp_flower_service_handle_get(struct nfp_app_fw_flower *app)
{
	return app->pf_hw->pf_dev->process_share.fl_service;
}

static int
nfp_flower_service_loop(void *arg)
{
	uint16_t slot;
	struct nfp_app_fw_flower *app;
	struct nfp_flower_service *service_handle;

	service_handle = arg;
	/* Waiting for enabling service */
	while (!service_handle->enabled)
		rte_delay_ms(1);

	while (rte_service_runstate_get(service_handle->info.id) != 0) {
		rte_spinlock_lock(&service_handle->spinlock);
		for (slot = 0; slot < MAX_FLOWER_SERVICE_SLOT; slot++) {
			app = service_handle->slots[slot];
			if (app == NULL)
				continue;

			nfp_flower_ctrl_vnic_process(app);
		}
		rte_spinlock_unlock(&service_handle->spinlock);
	}

	return 0;
}

static int
nfp_flower_service_enable(struct nfp_flower_service *service_handle)
{
	int ret;

	const struct rte_service_spec flower_service = {
		.name              = "flower_ctrl_vnic_service",
		.callback          = nfp_flower_service_loop,
		.callback_userdata = (void *)service_handle,
	};

	ret = nfp_service_enable(&flower_service, &service_handle->info);
	if (ret != 0)
		return ret;

	rte_spinlock_init(&service_handle->spinlock);
	service_handle->enabled = true;

	return 0;
}

static uint16_t
nfp_flower_service_insert(struct nfp_app_fw_flower *app,
		struct nfp_flower_service *service_handle)
{
	uint16_t slot;

	rte_spinlock_lock(&service_handle->spinlock);
	for (slot = 0; slot < MAX_FLOWER_SERVICE_SLOT; slot++) {
		if (service_handle->slots[slot] == NULL) {
			service_handle->slots[slot] = app;
			break;
		}
	}
	rte_spinlock_unlock(&service_handle->spinlock);

	return slot;
}

int
nfp_flower_service_start(void *app_fw_flower)
{
	int ret;
	struct nfp_flower_service *service_handle;
	struct nfp_app_fw_flower *app = app_fw_flower;

	service_handle = nfp_flower_service_handle_get(app);
	if (service_handle == NULL) {
		PMD_DRV_LOG(ERR, "Can not get service handle");
		return -EINVAL;
	}

	/* Enable flower service when driver initializes the first NIC */
	if (!service_handle->enabled) {
		ret = nfp_flower_service_enable(service_handle);
		if (ret != 0) {
			PMD_DRV_LOG(ERR, "Could not enable flower service");
			return -ESRCH;
		}
	}

	/* Insert the NIC to flower service slot */
	ret = nfp_flower_service_insert(app, service_handle);
	if (ret == MAX_FLOWER_SERVICE_SLOT) {
		PMD_DRV_LOG(ERR, "Flower ctrl vnic service slot over %u",
				MAX_FLOWER_SERVICE_SLOT);
		return -ENOSPC;
	}

	return 0;
}

void
nfp_flower_service_stop(void *app_fw_flower)
{
	uint16_t slot;
	uint16_t count;
	struct nfp_flower_service *service_handle;
	struct nfp_app_fw_flower *app = app_fw_flower;

	service_handle = nfp_flower_service_handle_get(app);
	if (service_handle == NULL) {
		PMD_DRV_LOG(ERR, "Can not get service handle");
		return;
	}

	rte_spinlock_lock(&service_handle->spinlock);
	for (slot = 0; slot < MAX_FLOWER_SERVICE_SLOT; slot++) {
		/* The app only in one slot */
		if (service_handle->slots[slot] != app)
			continue;

		service_handle->slots[slot] = NULL;
	}
	rte_spinlock_unlock(&service_handle->spinlock);

	/* Determine whether to disable service */
	count = nfp_sync_handle_count_get(app->pf_hw->pf_dev->sync, NULL,
			service_handle);
	if (count > 1)
		return;

	if (nfp_service_disable(&service_handle->info) != 0)
		PMD_DRV_LOG(ERR, "Could not disable service");
}

int
nfp_flower_service_sync_alloc(void *app_fw_flower)
{
	struct nfp_flower_service *service_handle;
	struct nfp_app_fw_flower *app = app_fw_flower;
	struct nfp_pf_dev *pf_dev = app->pf_hw->pf_dev;

	service_handle = nfp_sync_handle_alloc(pf_dev->sync, NULL,
			NFP_SYNC_MAGIC_FL_SERVICE,
			sizeof(struct nfp_flower_service));
	if (service_handle == NULL)
		return -ENOMEM;

	pf_dev->process_share.fl_service = service_handle;

	return 0;
}

void
nfp_flower_service_sync_free(void *app_fw_flower)
{
	struct nfp_app_fw_flower *app = app_fw_flower;
	struct nfp_pf_dev *pf_dev = app->pf_hw->pf_dev;

	nfp_sync_handle_free(pf_dev->sync, NULL, pf_dev->process_share.fl_service);

	pf_dev->process_share.fl_service = NULL;
}
