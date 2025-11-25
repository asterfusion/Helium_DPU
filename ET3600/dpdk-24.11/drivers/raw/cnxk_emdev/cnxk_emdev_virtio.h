/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#ifndef _CNXK_EMDEV_VIRTIO_H_
#define _CNXK_EMDEV_VIRTIO_H_

#include "rte_pmd_cnxk_emdev.h"

#include "spec/virtio.h"
#include "spec/virtio_net.h"

struct cnxk_emdev_virtio_pfvf;

typedef uint16_t (*virtio_cq_id_get_cb_t)(struct cnxk_emdev_virtio_pfvf *pfvf,
					  uint64_t feature_bits);
typedef int (*virtio_dev_cfg_read_cb_t)(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t offset,
					void *data, uint8_t len);

struct cnxk_emdev_virtio_cbs {
	virtio_cq_id_get_cb_t cq_id_get;
	virtio_dev_cfg_read_cb_t dev_cfg_read;
};

struct cnxk_emdev_virtio_net_conf {
	struct virtio_net_config dev_cfg;
};

struct cnxk_emdev_virtio_queue_conf {
	uint16_t queue_select;	    /* read-write */
	uint16_t queue_size;	    /* read-write */
	uint16_t queue_msix_vector; /* read-write */
	uint16_t queue_enable;	    /* read-write */
	uint16_t queue_notify_off;  /* read-only for driver */
	uint32_t queue_desc_lo;	    /* read-write */
	uint32_t queue_desc_hi;	    /* read-write */
	uint32_t queue_avail_lo;    /* read-write */
	uint32_t queue_avail_hi;    /* read-write */
	uint32_t queue_used_lo;	    /* read-write */
	uint32_t queue_used_hi;	    /* read-write */
	uint16_t queue_notify_data; /* read-only for driver */
	uint16_t queue_reset;	    /* read-write */

	struct roc_emdev_psw_inb_q inbq;
	struct roc_emdev_psw_outb_q outbq;
};

struct cnxk_emdev_virtio_pfvf {
	enum rte_pmd_emdev_type emdev_type;

	uint16_t vf_id;
	uint16_t epf_func;
	uint16_t queue_select;
	uint32_t drv_feature_bits_lo;
	uint32_t drv_feature_bits_hi;
	uint32_t device_feature_select;
	uint32_t guest_feature_select;
	uint8_t config_generation;
	uint8_t device_status;
	uint64_t dev_feature_bits;
	uint64_t feature_bits;

	/* Virtio per-queue configuration */
	struct cnxk_emdev_virtio_queue_conf *queue_conf;
	/* Virtio per-queue fast path data */
	struct cnxk_emdev_vnet_queue *vnet_qs;
	uint16_t max_queues;
	uint16_t config_msix_vector;

	/* Status callback */
	rte_pmd_cnxk_emdev_status_cb_t status_cb;

	struct cnxk_emdev_virtio_net_conf net_conf;

	/* Back pointer to the device */
	struct cnxk_emdev *dev;
};

extern struct cnxk_emdev_virtio_cbs emdev_virtio_cbs[];

#endif /* _CNXK_EMDEV_VIRTIO_H_ */
