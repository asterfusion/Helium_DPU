/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef _VHOST_BLK_H_
#define _VHOST_BLK_H_

#include <stdio.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdbool.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>

#include <rte_vhost.h>

#ifndef VIRTIO_F_RING_PACKED
#define VIRTIO_F_RING_PACKED 34

struct vring_packed_desc {
	/* Buffer Address. */
	__le64 addr;
	/* Buffer Length. */
	__le32 len;
	/* Buffer ID. */
	__le16 id;
	/* The flags depending on descriptor type. */
	__le16 flags;
};
#endif

struct vhost_blk_queue {
	struct rte_vhost_vring vq;
	struct rte_vhost_ring_inflight inflight_vq;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
	bool avail_wrap_counter;
	bool used_wrap_counter;
};

#define NUM_OF_BLK_QUEUES 1

#define min(a, b) (((a) < (b)) ? (a) : (b))

struct vhost_block_dev {
	/** ID for vhost library. */
	int vid;
	/** Queues for the block device */
	struct vhost_blk_queue queues[NUM_OF_BLK_QUEUES];
	/** Unique name for this block device. */
	char name[64];

	/** Unique product name for this kind of block device. */
	char product_name[256];

	/** Size in bytes of a logical block for the backend */
	uint32_t blocklen;

	/** Number of blocks */
	uint64_t blockcnt;

	/** write cache enabled, not used at the moment */
	int write_cache;

	/** use memory as disk storage space */
	uint8_t *data;
};

struct vhost_blk_ctrlr {
	uint8_t started;
	uint8_t packed_ring;
	uint8_t need_restart;
	/** Only support 1 LUN for the example */
	struct vhost_block_dev *bdev;
	/** VM memory region */
	struct rte_vhost_memory *mem;
} __rte_cache_aligned;

#define VHOST_BLK_MAX_IOVS 128

enum blk_data_dir {
	BLK_DIR_NONE = 0,
	BLK_DIR_TO_DEV = 1,
	BLK_DIR_FROM_DEV = 2,
};

struct vhost_blk_task {
	uint8_t readtype;
	uint8_t req_idx;
	uint16_t head_idx;
	uint16_t last_idx;
	uint16_t inflight_idx;
	uint16_t buffer_id;
	uint32_t dxfer_dir;
	uint32_t data_len;
	struct virtio_blk_outhdr *req;

	volatile uint8_t *status;

	struct iovec iovs[VHOST_BLK_MAX_IOVS];
	uint32_t iovs_cnt;
	struct vring_packed_desc *desc_packed;
	struct vring_desc *desc_split;
	struct rte_vhost_vring *vq;
	struct vhost_block_dev *bdev;
	struct vhost_blk_ctrlr *ctrlr;
};

struct inflight_blk_task {
	struct vhost_blk_task blk_task;
	struct rte_vhost_inflight_desc_packed *inflight_desc;
	struct rte_vhost_inflight_info_packed *inflight_packed;
};

struct vhost_blk_ctrlr *g_vhost_ctrlr;
struct vhost_device_ops vhost_blk_device_ops;

int vhost_bdev_process_blk_commands(struct vhost_block_dev *bdev,
				     struct vhost_blk_task *task);

void vhost_session_install_rte_compat_hooks(uint32_t vid);

void vhost_dev_install_rte_compat_hooks(const char *path);

struct vhost_blk_ctrlr *vhost_blk_ctrlr_find(const char *ctrlr_name);

#endif /* _VHOST_blk_H_ */
