/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include <bus_pci_driver.h>
#include <dev_driver.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_pci.h>
#include <rte_rawdev.h>
#include <rte_rawdev_pmd.h>

#include "cnxk_emdev.h"
#include "cnxk_emdev_virtio.h"
#include "cnxk_emdev_vnet.h"
#include "spec/virtio.h"
#include <roc_api.h>

#define BIT_MASK32		   (0xFFFFFFFFU)
#define VIRTIO_INVALID_QUEUE_INDEX 0xFFFF
#define VIRTIO_DESC_SZ		   16
#define VIRTIO_DFLT_QUEUE_SZ	   4096

struct cnxk_emdev_virtio_cbs emdev_virtio_cbs[EMDEV_TYPE_MAX];

static const char *
cnxk_emdev_virtio_dev_status_to_str(uint8_t status)
{
	switch (status) {
	case VIRTIO_DEV_RESET:
		return "VIRTIO_DEV_RESET";
	case VIRTIO_DEV_ACKNOWLEDGE:
		return "VIRTIO_DEV_ACKNOWLEDGE";
	case VIRTIO_DEV_DRIVER:
		return "VIRTIO_DEV_DRIVER";
	case VIRTIO_DEV_DRIVER_OK:
		return "VIRTIO_DEV_DRIVER_OK";
	case VIRTIO_DEV_FEATURES_OK:
		return "VIRTIO_DEV_FEATURES_OK";
	case VIRTIO_DEV_NEEDS_RESET:
		return "VIRTIO_DEV_NEEDS_RESET";
	case VIRTIO_DEV_FAILED:
		return "VIRTIO_DEV_FAILED";
	default:
		return "UNKNOWN_STATUS";
	};
	return NULL;
}

static uint8_t
virtio_netdev_hdr_size(struct cnxk_emdev_virtio_pfvf *pfvf)
{
	struct virtio_net_hdr *vnet_hdr;
	uint8_t virtio_hdr_sz;

	if (!(pfvf->device_status & VIRTIO_DEV_FEATURES_OK))
		return 0;

	if (pfvf->feature_bits & RTE_BIT64(VIRTIO_NET_F_HASH_REPORT))
		virtio_hdr_sz = offsetof(struct virtio_net_hdr, padding_reserved) +
				sizeof(vnet_hdr->padding_reserved);
	else
		virtio_hdr_sz = offsetof(struct virtio_net_hdr, num_buffers) +
				sizeof(vnet_hdr->num_buffers);
	return virtio_hdr_sz;
}

static void
emdev_vnet_set_functions(struct cnxk_emdev_virtio_pfvf *pfvf, struct cnxk_emdev_vnet_queue *vnet_q,
			 uint16_t qid, uint16_t cq_id)
{
	bool no_inorder = false;
	bool mseg = false;

	/* Extend functions w.r.t. negotiated features */
	no_inorder = (pfvf->feature_bits & RTE_BIT64(VIRTIO_F_IN_ORDER)) ? false : true;
	mseg = (pfvf->feature_bits & RTE_BIT64(VIRTIO_NET_F_MRG_RXBUF)) ? true : false;

	if (qid == cq_id) {
		vnet_q->dbl_fn_id = EMDEV_VNET_PSW_DBL_OFFLOAD_CTRL_DEQ;
		vnet_q->enq_fn_id = EMDEV_VNET_ENQ_OFFLOAD_CTRL;
		vnet_q->dpi_compl_fn_id = 0;
	} else if ((qid % 2) == 0) {
		vnet_q->dbl_fn_id = EMDEV_VNET_PSW_DBL_OFFLOAD_ENQ;
		vnet_q->dpi_compl_fn_id = EMDEV_VNET_DPI_COMPL_OFFLOAD_ENQ;
		vnet_q->enq_fn_id = EMDEV_VNET_ENQ_OFFLOAD_FF;
		if (mseg)
			vnet_q->enq_fn_id |= EMDEV_VNET_ENQ_OFFLOAD_MSEG;
	} else {
		vnet_q->dbl_fn_id = EMDEV_VNET_PSW_DBL_OFFLOAD_DEQ;
		vnet_q->dpi_compl_fn_id = EMDEV_VNET_DPI_COMPL_OFFLOAD_DEQ;
		vnet_q->enq_fn_id = EMDEV_VNET_ENQ_OFFLOAD_NONE;
		if (no_inorder) {
			vnet_q->dpi_compl_fn_id |= DPI_DEQ_NOINORDER_F;
			vnet_q->dbl_fn_id |= DBL_DEQ_NOINORDER_F;
		}
	}
}

static void
emdev_vnet_reset_functions(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t qid)
{
	struct cnxk_emdev_vnet_queue *vnet_q;

	vnet_q = &pfvf->vnet_qs[qid];
	vnet_q->dpi_compl_fn_id = EMDEV_VNET_DPI_COMPL_OFFLOAD_NONE;
	vnet_q->dbl_fn_id = EMDEV_VNET_PSW_DBL_OFFLOAD_NONE;
	vnet_q->enq_fn_id = EMDEV_VNET_ENQ_OFFLOAD_NONE;
}

static inline void
virtio_queues_fini(struct cnxk_emdev_virtio_pfvf *pfvf)
{
	struct cnxk_emdev_virtio_queue_conf *qconf;
	uint16_t qid;

	for (qid = 0; qid < pfvf->max_queues; qid++) {
		qconf = &pfvf->queue_conf[qid];
		if (qconf->queue_enable) {
			roc_emdev_psw_inb_q_fini(&qconf->inbq);
			roc_emdev_psw_outb_q_fini(&qconf->outbq);
			plt_free((void *)qconf->inbq.shib.real_q_base_addr);
		}
		memset(qconf, 0, sizeof(*qconf));
		/* Reset the queue size */
		qconf->queue_select = VIRTIO_INVALID_QUEUE_INDEX;
		qconf->queue_size = VIRTIO_DFLT_QUEUE_SZ;
		qconf->queue_msix_vector = CNXK_EMDEV_MSIX_VECTOR_INVALID;

		/* Reset functions */
		emdev_vnet_reset_functions(pfvf, qid);
	}
}

static inline int
virtio_queue_init(struct cnxk_emdev_virtio_pfvf *pfvf, struct cnxk_emdev_virtio_queue_conf *qconf,
		  uint16_t qid)
{
	struct roc_emdev_psw_outb_q *outbq = &qconf->outbq;
	struct roc_emdev_psw_inb_q *inbq = &qconf->inbq;
	struct cnxk_emdev *dev = pfvf->dev;
	struct cnxk_emdev_vnet_queue *vnet_q;
	uint16_t vf_id = pfvf->vf_id;
	struct roc_emdev *roc_emdev;
	uint16_t cq_id;
	size_t sz;
	int rc;

	inbq->qid = qid;
	inbq->evf_id = vf_id;
	inbq->hib.q_base_addr = (((uint64_t)qconf->queue_desc_hi << 32) | (qconf->queue_desc_lo));
	/* Return failure if queue address is not 64 byte aligned as HW requires minimum of
	 * 64 byte alignment.
	 */
	if (inbq->hib.q_base_addr & 0x3F)
		return -EINVAL;
	inbq->hib.msix_vec_num = CNXK_EMDEV_MSIX_VECTOR_INVALID;
	if (qconf->queue_msix_vector != CNXK_EMDEV_MSIX_VECTOR_INVALID) {
		inbq->hib.msix_vec_num = qconf->queue_msix_vector;
		inbq->hib.msix_en = true;
	}
	inbq->hib.pround = 1;
	inbq->ci_init = BIT_ULL(15);
	inbq->pi_init = BIT_ULL(15);
	if (!rte_is_power_of_2(qconf->queue_size))
		return -EINVAL;
	inbq->nb_desc = qconf->queue_size;
	inbq->desc_sz = VIRTIO_DESC_SZ;
	/* Allocate 256 bytes more to make host queue address and shadow queue address have
	 * same lsb 8 bits.
	 */
	sz = (inbq->nb_desc * VIRTIO_DESC_SZ) + 256;
	inbq->shib.real_q_base_addr = (uintptr_t)plt_zmalloc(sz, 256);
	if (!inbq->shib.real_q_base_addr)
		return -ENOMEM;

	inbq->shib.q_base_addr = (inbq->shib.real_q_base_addr & ~(0xFF)) +
				 (inbq->hib.q_base_addr & 0xFF);
	rc = roc_emdev_psw_inb_q_init(&dev->roc_emdev, inbq);
	if (rc)
		goto q_base_addr_free;

	outbq->qid = qid;
	outbq->evf_id = vf_id;
	outbq->hob.q_base_addr = inbq->hib.q_base_addr;
	outbq->hob.notify_qid = dev->func_q_map[vf_id][qid];
	outbq->shob.q_base_addr = inbq->shib.q_base_addr;
	outbq->nb_desc = qconf->queue_size;
	outbq->desc_sz = VIRTIO_DESC_SZ;
	outbq->hob.pround = 1;
	outbq->ci_init = BIT_ULL(15);
	outbq->pi_init = BIT_ULL(15);

	/* For virtio CQ, always use notify qid 0 */
	cq_id = emdev_virtio_cbs[pfvf->emdev_type].cq_id_get(pfvf, pfvf->feature_bits);
	if (qid == cq_id) {
		outbq->qp_type = ROC_EMDEV_QP_TYPE_CTRL;
		outbq->hob.notify_qid = 0;
	}

	/* Initialize the outb queue */
	rc = roc_emdev_psw_outb_q_init(&dev->roc_emdev, outbq);
	if (rc)
		goto inb_q_fini;

	roc_emdev = &dev->roc_emdev;
	vnet_q = &pfvf->vnet_qs[qid];
	vnet_q->q_sz = qconf->queue_size;
	vnet_q->qid = qid;
	vnet_q->epf_func = roc_emdev_epf_func_get(roc_emdev, vf_id);
	vnet_q->sd_base = inbq->shib.q_base_addr;
	vnet_q->pi_desc = BIT_ULL(15);
	vnet_q->ci_desc = BIT_ULL(15);
	vnet_q->ci = BIT_ULL(15);

	emdev_vnet_set_functions(pfvf, vnet_q, qid, cq_id);

	/* Use default mempool for now */
	vnet_q->mp = dev->default_mp;
	vnet_q->virtio_hdr_sz = virtio_netdev_hdr_size(pfvf);

	/* Calculate the buffer length */
	vnet_q->data_off = roc_emdev->first_skip * 8;
	vnet_q->buf_len = vnet_q->mp->elt_size - vnet_q->data_off;
	return 0;

inb_q_fini:
	roc_emdev_psw_inb_q_fini(inbq);
q_base_addr_free:
	plt_free((void *)inbq->shib.real_q_base_addr);
	return rc;
}

int
cnxk_emdev_virtio_queue_init(struct cnxk_emdev *dev, uint16_t func_id, uint16_t outb_qid)
{
	struct cnxk_emdev_virtio_pfvf *pfvfs = dev->pfvf;
	struct cnxk_emdev_virtio_pfvf *pfvf = &pfvfs[func_id];
	struct cnxk_emdev_virtio_queue_conf *qconf;
	struct roc_emdev_psw_outb_q *outbq;

	qconf = &pfvf->queue_conf[outb_qid];
	outbq = &qconf->outbq;
	if (!outbq->hob.q_base_addr)
		return 0;
	return virtio_queue_init(pfvf, qconf, outb_qid);
}

void
cnxk_emdev_virtio_queue_fini(struct cnxk_emdev *dev, uint16_t func_id, uint16_t outb_qid)
{
	struct cnxk_emdev_virtio_pfvf *pfvfs = dev->pfvf;
	struct cnxk_emdev_virtio_pfvf *pfvf = &pfvfs[func_id];
	struct cnxk_emdev_virtio_queue_conf *qconf;

	qconf = &pfvf->queue_conf[outb_qid];
	if (qconf->queue_enable) {
		roc_emdev_psw_inb_q_fini(&qconf->inbq);
		roc_emdev_psw_outb_q_fini(&qconf->outbq);
		plt_free((void *)qconf->inbq.shib.real_q_base_addr);
	}

	/* Reset mapping to qid 1 */
	dev->func_q_map[pfvf->vf_id][outb_qid] = CNXK_EMDEV_DFLT_QID;
}

static void
dma_compl_wait(struct cnxk_emdev_virtio_pfvf *pfvf)
{
	struct cnxk_emdev *dev = pfvf->dev;
	struct cnxk_emdev_queue *emdev_q;
	uint16_t nq_id;

	for (nq_id = 0; nq_id < dev->nb_emdev_qs; nq_id++) {
		emdev_q = &dev->emdev_qs[nq_id];
		if (emdev_q->roc_nq_qp) {
			if (cnxk_emdev_dma_compl_wait(&emdev_q->dpi_q_inb, CNXK_EMDEV_DMA_TMO_MS))
				plt_err("[0x%x][Q%d] DMA Completion Timeout", pfvf->epf_func,
					nq_id);
			if (cnxk_emdev_dma_compl_wait(&emdev_q->dpi_q_outb, CNXK_EMDEV_DMA_TMO_MS))
				plt_err("[0x%x][Q%d] DMA Completion Timeout", pfvf->epf_func,
					nq_id);
		}
	}
}

static inline int
device_status_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint8_t device_status)
{
	plt_emdev_dbg("[dev %u] device_status: 0x%x", pfvf->vf_id, device_status);

	if (device_status == VIRTIO_DEV_RESET) {
		plt_emdev_dbg("[dev %u] %s", pfvf->vf_id,
			      cnxk_emdev_virtio_dev_status_to_str(VIRTIO_DEV_RESET));

		/* Call callback before starting reset */
		pfvf->status_cb(pfvf->dev->dev_id, pfvf->vf_id, device_status);

		dma_compl_wait(pfvf);

		/* Cleanup virtio queues */
		virtio_queues_fini(pfvf);

		pfvf->device_status = 0;
	}

	if (device_status & VIRTIO_DEV_FEATURES_OK) {
		plt_emdev_dbg("[dev %u] %s", pfvf->vf_id,
			      cnxk_emdev_virtio_dev_status_to_str(VIRTIO_DEV_FEATURES_OK));

		pfvf->feature_bits = pfvf->drv_feature_bits_lo | (uint64_t)pfvf->drv_feature_bits_hi
									 << 32;
		pfvf->device_status |= VIRTIO_DEV_FEATURES_OK;

		plt_info("[dev %u] Feature bits negotiated : %" PRIx64, pfvf->vf_id,
			 pfvf->feature_bits);
		if ((pfvf->feature_bits & RTE_BIT64(VIRTIO_F_ORDER_PLATFORM)) == 0) {
			plt_warn("[dev %u] !!! VIRTIO_F_ORDER_PLATFORM not negotiated !!!",
				 pfvf->vf_id);
			plt_warn("[dev %u] !!! Can lead to out-of-sync descriptor data !!!",
				 pfvf->vf_id);
		}
	}

	if (device_status & VIRTIO_DEV_DRIVER_OK) {

		plt_emdev_dbg("[dev %u] %s", pfvf->vf_id,
			      cnxk_emdev_virtio_dev_status_to_str(VIRTIO_DEV_DRIVER_OK));

		pfvf->device_status |= VIRTIO_DEV_DRIVER_OK;

		/* Call callback*/
		pfvf->status_cb(pfvf->dev->dev_id, pfvf->vf_id, VIRTIO_DEV_DRIVER_OK);
	}

	if (device_status & VIRTIO_DEV_ACKNOWLEDGE) {
		pfvf->device_status |= VIRTIO_DEV_ACKNOWLEDGE;
		plt_emdev_dbg("[dev %u] %s", pfvf->vf_id,
			      cnxk_emdev_virtio_dev_status_to_str(VIRTIO_DEV_ACKNOWLEDGE));
	}

	if (device_status & VIRTIO_DEV_DRIVER) {
		pfvf->device_status |= VIRTIO_DEV_DRIVER;
		plt_emdev_dbg("[dev %u] %s", pfvf->vf_id,
			      cnxk_emdev_virtio_dev_status_to_str(VIRTIO_DEV_DRIVER));
	}

	return 0;
}

static inline int
queue_select_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t queue_id)
{
	plt_emdev_dbg("[dev %u] queue_id: %u", pfvf->vf_id, queue_id);
	if (queue_id >= pfvf->max_queues)
		return -EINVAL;

	pfvf->queue_select = queue_id;
	pfvf->queue_conf[queue_id].queue_select = queue_id;

	return 0;
}

static inline int
queue_size_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t queue_size)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	pfvf->queue_conf[queue_id].queue_size = queue_size;

	plt_emdev_dbg("[dev %u] queue[%u]_size: 0x%04x", pfvf->vf_id, queue_id, queue_size);
	return 0;
}

static inline int
queue_msix_vector_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t queue_msix_vector)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	pfvf->queue_conf[queue_id].queue_msix_vector = queue_msix_vector;
	plt_emdev_dbg("[dev %u] queue[%u]_msix_vector: 0x%04x", pfvf->vf_id, queue_id,
		      queue_msix_vector);
	return 0;
}

static inline int
queue_enable_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t queue_enable)
{
	uint16_t queue_id = pfvf->queue_select;
	struct cnxk_emdev_virtio_queue_conf *qconf = &pfvf->queue_conf[queue_id];
	int rc;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	plt_emdev_dbg("[dev %u] queue[%u]_enable: 0x%04x", pfvf->vf_id, queue_id, queue_enable);

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}
	if (qconf->queue_enable == queue_enable)
		return 0;

	/* Setup datapath queue info */
	if (queue_enable) {
		rc = virtio_queue_init(pfvf, qconf, queue_id);
		if (rc) {
			plt_err("Failed to initialize the emdev queue");
			return rc;
		}
	} else {
		plt_free((void *)qconf->inbq.shib.real_q_base_addr);
		roc_emdev_psw_inb_q_fini(&qconf->inbq);
		roc_emdev_psw_outb_q_fini(&qconf->outbq);
	}

	qconf->queue_enable = queue_enable;
	return 0;
}

static inline int
queue_desc_lo_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_desc_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_desc_lo: 0x%x", pfvf->vf_id, queue_id, queue_desc_lo);
	pfvf->queue_conf[queue_id].queue_desc_lo = queue_desc_lo;

	return 0;
}

static inline int
queue_desc_hi_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_desc_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_desc_lo: 0x%x", pfvf->vf_id, queue_id, queue_desc_hi);
	pfvf->queue_conf[queue_id].queue_desc_hi = queue_desc_hi;

	return 0;
}

static inline int
queue_avail_lo_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_avail_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_avail_lo: 0x%x", pfvf->vf_id, queue_id, queue_avail_lo);
	pfvf->queue_conf[queue_id].queue_avail_lo = queue_avail_lo;

	return 0;
}

static int
queue_avail_hi_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_avail_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_avail_hi: 0x%x", pfvf->vf_id, queue_id, queue_avail_hi);
	pfvf->queue_conf[queue_id].queue_avail_hi = queue_avail_hi;

	return 0;
}

static inline int
queue_used_lo_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_used_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_used_lo: 0x%x", pfvf->vf_id, queue_id, queue_used_lo);
	pfvf->queue_conf[queue_id].queue_used_lo = queue_used_lo;

	return 0;
}

static inline int
queue_used_hi_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t queue_used_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	plt_emdev_dbg("[dev %u] queue[%u]_used_hi: 0x%x", pfvf->vf_id, queue_id, queue_used_hi);
	pfvf->queue_conf[queue_id].queue_used_hi = queue_used_hi;

	return 0;
}

static inline int
config_msix_vector_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *msix_vector)
{
	*msix_vector = pfvf->config_msix_vector;

	plt_emdev_dbg("[dev %u] read config_msix_vector: 0x%04x", pfvf->vf_id, *msix_vector);
	return 0;
}

static inline int
config_msix_vector_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t msix_vector)
{
	pfvf->config_msix_vector = msix_vector;
	plt_emdev_dbg("[dev %u] config_msix_vector: 0x%04x", pfvf->vf_id, msix_vector);

	return roc_emdev_mbox_msix_cfg(&pfvf->dev->roc_emdev, pfvf->vf_id, msix_vector);
}

static inline int
device_feature_select_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t device_feature_select)
{
	pfvf->device_feature_select = device_feature_select;

	plt_emdev_dbg("[dev %u] device_feature_select: %u", pfvf->vf_id, device_feature_select);

	return 0;
}

static inline int
guest_feature_select_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t driver_feature_select)
{
	pfvf->guest_feature_select = driver_feature_select;

	plt_emdev_dbg("[dev %u] driver_feature_select: %u", pfvf->vf_id, driver_feature_select);
	return 0;
}

static inline int
guest_feature_write(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t driver_feature)
{
	uint32_t feature_select = pfvf->guest_feature_select;

	if (feature_select == 0)
		pfvf->drv_feature_bits_lo = driver_feature;
	else if (feature_select == 1)
		pfvf->drv_feature_bits_hi = driver_feature;

	plt_emdev_dbg("[dev %u] driver_feature[%u]: 0x%08x", pfvf->vf_id, feature_select,
		      driver_feature);

	return 0;
}

static inline int
apinotif_write_handle(struct cnxk_emdev_virtio_pfvf *pfvf, struct roc_emdev_apinotif_handle *desc,
		      void *args)
{
	uint32_t offset = desc->addr >> 3;
	uint64_t data = desc->data;
	int rc = 0;

	RTE_SET_USED(args);
	offset = offset - ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF;
	switch (offset) {
	case 0:
		/* device_feature_select */
		rc = device_feature_select_write(pfvf, (uint32_t)data);
		break;
	case 4:
		/* device_feature */
		rc = -EINVAL;
		break;
	case 8:
		/* Guest feature select */
		rc = guest_feature_select_write(pfvf, (uint32_t)data);
		break;
	case 12:
		/* Guest feature */
		rc = guest_feature_write(pfvf, (uint32_t)data);
		break;
	case 16:
		rc = config_msix_vector_write(pfvf, (uint16_t)data);
		break;
	case 18:
		rc = -EINVAL;
		break;
	case 20:
		rc = device_status_write(pfvf, (uint8_t)data);
		break;
	case 21:
		rc = -EINVAL;
		break;
	case 22:
		rc = queue_select_write(pfvf, (uint16_t)data);
		break;
	case 24:
		rc = queue_size_write(pfvf, (uint16_t)data);
		break;
	case 26:
		rc = queue_msix_vector_write(pfvf, (uint16_t)data);
		break;
	case 28:
		rc = queue_enable_write(pfvf, (uint16_t)data);
		break;
	case 30:
		rc = -EINVAL;
		break;
	case 32:
		rc = queue_desc_lo_write(pfvf, (uint32_t)data);
		break;
	case 36:
		rc = queue_desc_hi_write(pfvf, (uint32_t)data);
		break;
	case 40:
		rc = queue_avail_lo_write(pfvf, (uint32_t)data);
		break;
	case 44:
		rc = queue_avail_hi_write(pfvf, (uint32_t)data);
		break;
	case 48:
		rc = queue_used_lo_write(pfvf, (uint32_t)data);
		break;
	case 52:
		rc = queue_used_hi_write(pfvf, (uint32_t)data);
		break;
	default:
		break;
	}

	return rc;
}

static inline int
num_queues_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *num_queues)
{
	*num_queues = pfvf->max_queues;

	plt_emdev_dbg("R:[dev %u] num_queues: 0x%x", pfvf->vf_id, *num_queues);

	return 0;
}

static inline int
device_status_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint8_t *device_status)
{
	*device_status = pfvf->device_status;

	plt_emdev_dbg("R:[dev %u] device_status: 0x%x", pfvf->vf_id, *device_status);

	return 0;
}

static inline int
config_generation_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint8_t *cfg_gen)
{
	*cfg_gen = pfvf->config_generation;

	plt_emdev_dbg("R:[dev %u] device_status: 0x%x", pfvf->vf_id, *cfg_gen);

	return 0;
}

static inline int
queue_select_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *queue_id)
{
	*queue_id = pfvf->queue_select;

	plt_emdev_dbg("R:[dev %u] queue_id: %u", pfvf->vf_id, *queue_id);
	return 0;
}

static inline int
queue_size_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *queue_size)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_size = pfvf->queue_conf[queue_id].queue_size;

	plt_emdev_dbg("R:[dev %u] queue[%u]_size: 0x%04x", pfvf->vf_id, queue_id, *queue_size);
	return 0;
}

static inline int
queue_msix_vector_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *queue_msix_vector)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_msix_vector = pfvf->queue_conf[queue_id].queue_msix_vector;
	plt_emdev_dbg("R:[dev %u] R:queue[%u]_msix_vector: 0x%04x", pfvf->vf_id, queue_id,
		      *queue_msix_vector);
	return 0;
}

static inline int
queue_enable_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *queue_enable)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_enable = pfvf->queue_conf[queue_id].queue_enable;

	plt_emdev_dbg("R:[dev %u] R:queue[%u]_enable: 0x%04x", pfvf->vf_id, queue_id,
		      *queue_enable);

	return 0;
}

static inline int
queue_notify_off_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint16_t *queue_notif_off)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_notif_off = queue_id;

	plt_emdev_dbg("R:[dev %u] queue[%u]_enable: 0x%04x", pfvf->vf_id, queue_id,
		      *queue_notif_off);

	return 0;
}

static inline int
queue_desc_lo_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_desc_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_desc_lo = pfvf->queue_conf[queue_id].queue_desc_lo;
	plt_emdev_dbg("R:[dev %u] queue[%u]_desc_lo: 0x%x", pfvf->vf_id, queue_id, *queue_desc_lo);

	return 0;
}

static inline int
queue_desc_hi_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_desc_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_desc_hi = pfvf->queue_conf[queue_id].queue_desc_hi;
	plt_emdev_dbg("R:[dev %u] queue[%u]_desc_lo: 0x%x", pfvf->vf_id, queue_id, *queue_desc_hi);

	return 0;
}

static inline int
queue_avail_lo_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_avail_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_avail_lo = pfvf->queue_conf[queue_id].queue_avail_lo;
	plt_emdev_dbg("R:[dev %u] queue[%u]_avail_lo: 0x%x", pfvf->vf_id, queue_id,
		      *queue_avail_lo);

	return 0;
}

static inline int
queue_avail_hi_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_avail_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_avail_hi = pfvf->queue_conf[queue_id].queue_avail_hi;
	plt_emdev_dbg("R:[dev %u] queue[%u]_avail_hi: 0x%x", pfvf->vf_id, queue_id,
		      *queue_avail_hi);

	return 0;
}

static inline int
queue_used_lo_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_used_lo)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_used_lo = pfvf->queue_conf[queue_id].queue_used_lo;
	plt_emdev_dbg("R:[dev %u] queue[%u]_used_lo: 0x%x", pfvf->vf_id, queue_id, *queue_used_lo);

	return 0;
}

static int
queue_used_hi_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *queue_used_hi)
{
	uint16_t queue_id = pfvf->queue_select;

	if (queue_id == VIRTIO_INVALID_QUEUE_INDEX)
		return -EINVAL;

	if (queue_id >= pfvf->max_queues) {
		plt_err("[dev %u] Invalid queue [%u]", pfvf->vf_id, queue_id);
		return -EINVAL;
	}

	*queue_used_hi = pfvf->queue_conf[queue_id].queue_used_hi;

	plt_emdev_dbg("R:[dev %u] queue[%u]_used_hi: 0x%x", pfvf->vf_id, queue_id, *queue_used_hi);
	return 0;
}

static inline int
device_feature_select_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *device_feature_select)
{
	*device_feature_select = pfvf->device_feature_select;

	plt_emdev_dbg("R:[dev %u] device_feature_select: %u", pfvf->vf_id, *device_feature_select);

	return 0;
}

static inline int
device_feature_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *device_feature)
{
	uint32_t feature_select = pfvf->device_feature_select;

	if (feature_select == 0)
		*device_feature = (uint32_t)pfvf->dev_feature_bits & BIT_MASK32;
	else if (feature_select == 1)
		*device_feature = (uint32_t)(pfvf->dev_feature_bits >> 32) & BIT_MASK32;

	plt_emdev_dbg("R:[dev %u] device_feature[%u]: 0x%08x", pfvf->vf_id, feature_select,
		      *device_feature);

	return 0;
}

static inline int
guest_feature_select_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *driver_feature_select)
{
	*driver_feature_select = pfvf->guest_feature_select;

	plt_emdev_dbg("R:[dev %u] driver_feature_select: %u", pfvf->vf_id, *driver_feature_select);
	return 0;
}

static inline int
guest_feature_read(struct cnxk_emdev_virtio_pfvf *pfvf, uint32_t *driver_feature)
{
	uint32_t feature_select = pfvf->guest_feature_select;

	if (feature_select == 0)
		*driver_feature = pfvf->drv_feature_bits_lo;
	else if (feature_select == 1)
		*driver_feature = pfvf->drv_feature_bits_hi;

	plt_emdev_dbg("R:[dev %u] driver_feature[%u]: 0x%08x", pfvf->vf_id, feature_select,
		      *driver_feature);

	return 0;
}

static inline int
apinotif_read_handle(struct cnxk_emdev_virtio_pfvf *pfvf, struct roc_emdev_apinotif_handle *desc,
		     void *args)
{
	uint32_t offset = desc->addr >> 3;
	void *data = &desc->data;
	uint8_t len;
	int rc = 0;

	RTE_SET_USED(args);
	offset = offset - ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF;
	len = (uint8_t)rte_popcount32((uint32_t)desc->be);

	switch (offset) {
	case 0:
		/* device_feature_select */
		rc = device_feature_select_read(pfvf, (uint32_t *)data);
		break;
	case 4:
		/* device_feature */
		rc = device_feature_read(pfvf, (uint32_t *)data);
		break;
	case 8:
		/* Guest feature select */
		rc = guest_feature_select_read(pfvf, (uint32_t *)data);
		break;
	case 12:
		/* Guest feature */
		rc = guest_feature_read(pfvf, (uint32_t *)data);
		break;
	case 16:
		rc = config_msix_vector_read(pfvf, (uint16_t *)data);
		break;
	case 18:
		rc = num_queues_read(pfvf, (uint16_t *)data);
		break;
	case 20:
		rc = device_status_read(pfvf, (uint8_t *)data);
		break;
	case 21:
		rc = config_generation_read(pfvf, (uint8_t *)data);
		break;
	case 22:
		rc = queue_select_read(pfvf, (uint16_t *)data);
		break;
	case 24:
		rc = queue_size_read(pfvf, (uint16_t *)data);
		break;
	case 26:
		rc = queue_msix_vector_read(pfvf, (uint16_t *)data);
		break;
	case 28:
		rc = queue_enable_read(pfvf, (uint16_t *)data);
		break;
	case 30:
		rc = queue_notify_off_read(pfvf, (uint16_t *)data);
		break;
	case 32:
		rc = queue_desc_lo_read(pfvf, (uint32_t *)data);
		break;
	case 36:
		rc = queue_desc_hi_read(pfvf, (uint32_t *)data);
		break;
	case 40:
		rc = queue_avail_lo_read(pfvf, (uint32_t *)data);
		break;
	case 44:
		rc = queue_avail_hi_read(pfvf, (uint32_t *)data);
		break;
	case 48:
		rc = queue_used_lo_read(pfvf, (uint32_t *)data);
		break;
	case 52:
		rc = queue_used_hi_read(pfvf, (uint32_t *)data);
		break;
	default:
		rc = emdev_virtio_cbs[pfvf->emdev_type].dev_cfg_read(pfvf, offset, data, len);
		break;
	}

	return rc;
}

static int
cnxk_emdev_virtio_apinotif_handle(uint16_t epf_func, struct roc_emdev_apinotif_handle *desc,
				  void *args)
{
	uint16_t vf_id = (epf_func >> PSW_EPF_FUNC_VF_SHIFT) & PSW_EPF_FUNC_VF_MASK;
	struct cnxk_emdev *dev = args;
	struct cnxk_emdev_virtio_pfvf *pfvf, *pfvfs = dev->pfvf;
	int rc;

	pfvf = &pfvfs[vf_id];
	if (desc->is_read)
		rc = apinotif_read_handle(pfvf, desc, args);
	else
		rc = apinotif_write_handle(pfvf, desc, args);

	return rc;
}

static int
cnxk_emdev_virtio_pfvf_init(struct cnxk_emdev *dev, uint16_t nb_pfvfs,
			    struct rte_pmd_cnxk_emdev_conf *conf)
{
	struct cnxk_emdev_virtio_pfvf *pfvf, *pfvfs;
	uint16_t max_queues;
	int i, rc;

	max_queues = dev->roc_emdev.nb_outb_qs;

	pfvfs = plt_zmalloc(nb_pfvfs * sizeof(struct cnxk_emdev_virtio_pfvf), 0);
	if (!pfvfs) {
		plt_err("Couldn't allocate memory for emdev VFs");
		return -ENOMEM;
	}
	for (i = 0; i < (int)nb_pfvfs; i++) {
		pfvf = &pfvfs[i];
		pfvf->dev = dev;
		pfvf->vf_id = i;
		pfvf->max_queues = max_queues;

		/* Allocate per virtio queue control path/fast path */
		pfvf->queue_conf =
			plt_zmalloc(max_queues * sizeof(struct cnxk_emdev_virtio_queue_conf), 0);
		if (!pfvf->queue_conf) {
			plt_err("Failed to allocate memory for queue config");
			i--;
			rc = -ENOMEM;
			goto exit;
		}
		for (int j = 0; j < (int)max_queues; j++) {
			pfvf->queue_conf[j].queue_select = VIRTIO_INVALID_QUEUE_INDEX;
			pfvf->queue_conf[j].queue_size = VIRTIO_DFLT_QUEUE_SZ;
			pfvf->queue_conf[j].queue_msix_vector = CNXK_EMDEV_MSIX_VECTOR_INVALID;
		}
		pfvf->vnet_qs = plt_zmalloc(max_queues * sizeof(struct cnxk_emdev_vnet_queue), 64);
		if (!pfvf->vnet_qs) {
			plt_err("Failed to allocate memory for vnet queue config");
			plt_free(pfvf->queue_conf);
			i--;
			rc = -ENOMEM;
			goto exit;
		}
		/* Set default device feature bits */
		pfvf->dev_feature_bits =
			RTE_BIT64(VIRTIO_F_RING_PACKED) | RTE_BIT64(VIRTIO_F_VERSION_1) |
			RTE_BIT64(VIRTIO_F_ANY_LAYOUT) | RTE_BIT64(VIRTIO_F_IN_ORDER) |
			RTE_BIT64(VIRTIO_F_ORDER_PLATFORM) | RTE_BIT64(VIRTIO_F_SR_IOV) |
			RTE_BIT64(VIRTIO_F_IOMMU_PLATFORM) | RTE_BIT64(VIRTIO_F_NOTIFICATION_DATA);
		pfvf->emdev_type = conf->emdev_type;
		pfvf->status_cb = conf->status_cb;
		switch (conf->emdev_type) {
		case EMDEV_TYPE_VIRTIO_NET:
			cnxk_emdev_vnet_init(pfvf, &conf->vnet_conf[i]);
			break;
		default:
			break;
		}
	}
	dev->pfvf = pfvfs;

	return 0;
exit:
	for (; i >= 0; i--) {
		plt_free(pfvfs[i].vnet_qs);
		plt_free(pfvfs[i].queue_conf);
	}
	plt_free(pfvfs);

	return rc;
}

static void
cnxk_emdev_virtio_pfvf_fini(struct cnxk_emdev *dev, uint16_t nb_pfvfs)
{
	struct cnxk_emdev_virtio_pfvf *pfvf, *pfvfs = dev->pfvf;
	int i;

	for (i = 0; i < (int)nb_pfvfs; i++) {
		pfvf = &pfvfs[i];
		plt_free(pfvf->queue_conf);
		plt_free(pfvf->vnet_qs);
	}
	plt_free(dev->pfvf);
}

int
cnxk_emdev_virtio_setup(struct cnxk_emdev *dev, struct rte_pmd_cnxk_emdev_conf *conf)
{
	struct roc_emdev *roc_emdev = &dev->roc_emdev;
	int rc;

	rc = cnxk_emdev_virtio_pfvf_init(dev, roc_emdev->nb_epfvfs, conf);
	if (rc)
		return rc;

	roc_emdev_apinotif_cb_register(roc_emdev, cnxk_emdev_virtio_apinotif_handle, dev);

	return 0;
}

void
cnxk_emdev_virtio_close(struct cnxk_emdev *dev)
{
	struct roc_emdev *roc_emdev = &dev->roc_emdev;

	cnxk_emdev_virtio_pfvf_fini(dev, roc_emdev->nb_epfvfs);
	roc_emdev_apinotif_cb_unregister(roc_emdev);
}
