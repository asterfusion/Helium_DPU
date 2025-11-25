/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#ifndef _CNXK_EMDEV_H_
#define _CNXK_EMDEV_H_

#include "rte_pmd_cnxk_emdev.h"
#include <roc_api.h>

#define PCI_DEVID_CNXK_EMDEV_VIRTIO_NET	   0x1041
#define PCI_DEVID_CNXK_EMDEV_VIRTIO_CRYPTO 0x1054

#define CNXK_EMDEV_Q_MBUF_RING_SZ 4096u

#define CNXK_EMDEV_DFLT_QID 1
#define CNXK_EMDEV_MSIX_VECTOR_INVALID 0xFFFF

#define CNXK_EMDEV_DMA_TMO_MS 5000

/* Transport specific device object */
typedef void *cnxk_emdev_pfvf_obj_t;
struct cnxk_emdev;

typedef void (*cnxk_emdev_cls_queue_setup_t)(struct cnxk_emdev *dev, uint16_t queue_id);
typedef void (*cnxk_emdev_cls_dump_t)(struct cnxk_emdev *dev, FILE *file);

/* Class specific operations function pointer table */
struct cnxk_emdev_cls_ops {
	cnxk_emdev_cls_queue_setup_t cls_queue_setup;
	cnxk_emdev_cls_dump_t cls_dump;
};

struct cnxk_emdev_vnet_queue;

/* PSW queue */
struct cnxk_emdev_psw_q {
	uint64_t *q_base;
	uint32_t q_sz;
	uintptr_t pi_dbl;
	uintptr_t ci_dbl;
	uint16_t ci;
};

/* DPI queue */
struct cnxk_emdev_dpi_q {
	uint64_t *inst_base;
	uint64_t *compl_base;
	uint64_t *ridx_r;
	uint64_t *widx_r;
	uint16_t avail;
	uint16_t compl_idx;
	uint8_t qid;
	struct rte_mempool *mp;
};

/* Notify queue and ack queue */
struct cnxk_emdev_queue {
	/* Fast path */
	struct cnxk_emdev_psw_q nq;
	struct cnxk_emdev_psw_q aq;
	struct cnxk_emdev_dpi_q dpi_q_inb;
	struct cnxk_emdev_dpi_q dpi_q_outb;

	/* VF bitmap */
	uint64_t vf_bitmap[2];

	/* Array of vnet queues per VF */
	struct cnxk_emdev_vnet_queue *vnet_q_base[ROC_PSW_VFS_MAX];

	/* Mbuf array */
	struct rte_mbuf *mbuf_arr[CNXK_EMDEV_Q_MBUF_RING_SZ];
	uint16_t mbuf_pi;
	uint16_t mbuf_ci;

	/* Slow path */
	struct roc_emdev_psw_nq_qp *roc_nq_qp;
	struct roc_dpi_lf_que *roc_dpi_q_inb;
	struct roc_dpi_lf_que *roc_dpi_q_outb;
	struct cnxk_emdev *dev;
};

struct cnxk_emdev {
	/* Base ROC EM device */
	struct roc_emdev roc_emdev;

	/* EMDEV device type */
	enum rte_pmd_emdev_type emdev_type;

	const struct cnxk_emdev_cls_ops *cls_ops;

	/* PSW Notify Ack queue pairs */
	struct roc_emdev_psw_nq_qp *notify_qs;
	uint16_t nb_notify_qs;

	/* DPI LF's */
	struct roc_dpi_lf *dpi_lfs;
	uint16_t nb_dpi_lfs;

	/* EMDEV fast path queue objects */
	struct cnxk_emdev_queue *emdev_qs;
	uint16_t nb_emdev_qs;

	cnxk_emdev_pfvf_obj_t pfvf;
	uint16_t nb_epfvfs;
	uint16_t func_q_map[ROC_PSW_VFS_MAX][ROC_PSW_OUTB_QUEUES_MAX];
	struct rte_mempool *default_mp;
	struct rte_rawdev *rawdev;
	uint16_t dev_id;
};

#define WRAP_OFF(i) ((uint16_t)(i) & ~RTE_BIT64(15))

#define NQ_DESC_SZ(x)		 (WRAP_OFF(x) * PSW_NQ_DESC_SZ)
#define NQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + NQ_DESC_SZ(i) + (o))

#define AQ_DESC_SZ(x)		 (WRAP_OFF(x) * PSW_AQ_DESC_SZ)
#define AQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + AQ_DESC_SZ(i) + (o))

#define DESC_DIFF(a, b, q_sz) ((a - b + q_sz) & (q_sz - 1))
#define DESC_ADD(a, b, q_sz)  ((a + b) & (q_sz - 1))
#define DESC_SUB(a, b, q_sz)  ((a - b + q_sz) & (q_sz - 1))

static __rte_always_inline uint16_t
wrap_off_add(uint16_t a, uint16_t b, uint16_t q_sz)
{
	uint16_t sum = a + b;
	uint16_t mask = (~(q_sz - 1) & ~RTE_BIT64(15));

	sum += mask;
	sum = sum & ~mask;

	return sum;
}

static __rte_always_inline uint16_t
wrap_off_m1(uint16_t a, uint16_t q_sz)
{
	uint16_t sum = a - 1;
	uint16_t mask = (~(q_sz - 1) & ~RTE_BIT64(15));

	sum = sum & ~mask;
	return sum;
}

static __rte_always_inline uint16_t
wrap_off_diff(uint16_t a, uint16_t b, uint16_t q_sz)
{
	return (a & RTE_BIT64(15)) == (b & RTE_BIT64(15)) ?
		       ((uint16_t)(WRAP_OFF(a) - WRAP_OFF(b))) :
		       (q_sz - (b & (RTE_BIT64(15) - 1)) + WRAP_OFF(a));
}

static __rte_always_inline uint16_t
wrap_off_diff_no_wrap(uint16_t a, uint16_t b, uint16_t q_sz)
{
	return (a & RTE_BIT64(15)) == (b & RTE_BIT64(15)) ? (uint16_t)(a - b) :
							    (q_sz - (b & (RTE_BIT64(15) - 1)));
}

static inline struct cnxk_emdev *
cnxk_rawdev_priv(const struct rte_rawdev *rawdev)
{
	return rawdev->dev_private;
}

static inline uint16_t
cnxk_emdev_qid_from_ctx(rte_rawdev_obj_t context)
{
	return (uintptr_t)context & 0xFF;
}

static inline uint16_t
cnxk_emdev_vf_from_ctx(rte_rawdev_obj_t context)
{
	return ((uintptr_t)context >> 8) & 0xFF;
}

static inline uint16_t
cnxk_emdev_rid_from_ctx(rte_rawdev_obj_t context)
{
	return ((uintptr_t)context >> 16) & 0xFF;
}

int cnxk_emdev_virtio_setup(struct cnxk_emdev *dev, struct rte_pmd_cnxk_emdev_conf *conf);
void cnxk_emdev_virtio_close(struct cnxk_emdev *dev);
int cnxk_emdev_virtio_queue_init(struct cnxk_emdev *dev, uint16_t func_id, uint16_t outb_qid);
void cnxk_emdev_virtio_queue_fini(struct cnxk_emdev *dev, uint16_t func_id, uint16_t outb_qid);

int cnxk_emdev_info_get(struct rte_rawdev *rawdev, rte_rawdev_obj_t dev_info, size_t dev_info_size);
int cnxk_emdev_configure(const struct rte_rawdev *rawdev, rte_rawdev_obj_t config,
			 size_t config_size);
int cnxk_emdev_close(struct rte_rawdev *rawdev);
int cnxk_emdev_start(struct rte_rawdev *rawdev);
void cnxk_emdev_stop(struct rte_rawdev *rawdev);
int cnxk_emdev_dump(struct rte_rawdev *rawdev, FILE *f);
uint16_t cnxk_emdev_queue_count(struct rte_rawdev *rawdev);
int cnxk_emdev_queue_setup(struct rte_rawdev *rawdev, uint16_t queue_id,
			   rte_rawdev_obj_t queue_conf, size_t conf_size);
int cnxk_emdev_queue_release(struct rte_rawdev *rawdev, uint16_t queue_id);
int cnxk_emdev_attr_get(struct rte_rawdev *rawdev, const char *attr_name, uint64_t *attr_value);
int cnxk_emdev_attr_set(struct rte_rawdev *rawdev, const char *attr_name, uint64_t attr_value);
#endif /* _CNXK_EMDEV_H_ */
