/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_ROC_EMDEV_H__
#define __INCLUDE_ROC_EMDEV_H__

enum roc_emdev_type { ROC_EMDEV_TYPE_VIRTIO = 1, ROC_EMDEV_TYPE_NVME, ROC_EMDEV_TYPE_MAX };

enum roc_emdev_qp_type {
	ROC_EMDEV_QP_TYPE_CTRL = 1,
	ROC_EMDEV_QP_TYPE_DATA = 2,
};

enum roc_emdev_dpi_lf_ring_type {
	ROC_EMDEV_DPI_LF_RING_INB = 0,
	ROC_EMDEV_DPI_LF_RING_OUTB = 1,
	ROC_EMDEV_DPI_LF_RING_MAX,
};

struct roc_emdev {
	struct plt_pci_device *pci_dev;
	uint16_t nb_epfvfs;
	uint16_t nb_inb_qs;
	uint16_t nb_outb_qs;
	uint16_t nb_notify_qs;
	uint16_t nb_dpi_lfs;
	uint8_t first_skip;
	uint8_t later_skip;
	/* End of input params */
	enum roc_emdev_type emul_type;
#define ROC_EMDEV_MEM_SZ (6 * 1070)
	uint8_t reserved[ROC_EMDEV_MEM_SZ] __plt_cache_aligned;
};

struct roc_emdev_psw_aq_qp {
	uint32_t qid;
	uint32_t nb_desc;
	/* End of input params */
	uint64_t *notify_q_base;
	uint64_t *ack_q_base;
	uint32_t qmask;
	uint32_t q_sz;
	uintptr_t notify_q_pi_dbell;
	uintptr_t notify_q_ci_dbell;
	uintptr_t ack_q_pi_dbell;
	uintptr_t ack_q_ci_dbell;
	struct roc_emdev *roc_emdev;
};

struct roc_emdev_psw_nq_qp {
	uint32_t qid;
	uint32_t nb_desc;
	/* End of input params */
	uint64_t *notify_q_base;
	uint64_t *ack_q_base;
	uint32_t qmask;
	uint32_t q_sz;
	uintptr_t notify_q_pi_dbell;
	uintptr_t notify_q_ci_dbell;
	uintptr_t ack_q_pi_dbell;
	uintptr_t ack_q_ci_dbell;
	struct roc_emdev *roc_emdev;
	bool enable;
};

struct roc_emdev_psw_inb_q {
	uint32_t qid;
	uint16_t evf_id;
	uint16_t pasid;
	uint16_t pasid_en;
	struct roc_emdev_psw_hib_q {
		uintptr_t q_base_addr; /* Base address of the queue in Host */
		uint64_t pround;
		uint16_t msix_vec_num;
		bool msix_en;
	} hib;

	struct roc_emdev_psw_shib_q {
		uintptr_t q_base_addr;	    /* Aligned address of the shadow queue in Octeon */
		uintptr_t real_q_base_addr; /* Base address of the shadow queue */
	} shib;

	uint16_t desc_sz;
	uint32_t nb_desc;
	uint16_t pi_init;
	uint16_t ci_init;
	/* End of input params */
	struct roc_emdev *roc_emdev;
	/* Write data for LDADD/CASP ops for HIQ, SHIQ */
	uint64_t wdata;
	/* Shadow queue doorbells */
	uintptr_t pi_dbell;
	uintptr_t ci_dbell;
};

struct roc_emdev_psw_outb_q {
	uint32_t qid;
	uint16_t evf_id;
	uint16_t pasid;
	uint16_t pasid_en;
	/* Control Queue or Data Queue */
	enum roc_emdev_qp_type qp_type;
	struct roc_emdev_psw_hob_q {
		uintptr_t q_base_addr; /* Base address of the queue in Host */
		uint64_t pround;
		uint16_t notify_qid; /* Notify queue id with associated PSW LF */
	} hob;

	struct roc_emdev_psw_shob_q {
		uintptr_t q_base_addr;	    /* Aligned address of the shadow queue in Octeon */
		uintptr_t real_q_base_addr; /* Base address of the shadow queue */
	} shob;

	uint16_t desc_sz;
	uint32_t nb_desc;
	uint16_t pi_init;
	uint16_t ci_init;
	/* End of input params */
	struct roc_emdev *roc_emdev;
	/* Write data for LDADD/CASP ops for HoQ, SHoQ */
	uint64_t wdata;
	/* Shadow queue doorbells */
	uintptr_t pi_dbell;
	uintptr_t ci_dbell;
};

struct roc_emdev_psw_dbl_desc {
	uint16_t epffunc;
	uint16_t index;
	uint8_t hoqid;
};

struct roc_emdev_psw_ack_dbl_desc {
	uint16_t write_cnt;
	uint16_t index;
	uint16_t epffunc;
	uint8_t hiqid;
	uint8_t msgovrd;
	uint8_t intrpt;
};

struct roc_emdev_apinotif_handle {
	uint32_t addr;
	uint64_t data;
	uint8_t be;
	bool is_read;
};

#define ROC_PSW_VFS_MAX		 128
#define ROC_PSW_OUTB_QUEUES_MAX	 4096
#define ROC_PSW_NOTIF_QUEUES_MAX 64
#define ROC_EMDEV_DPI_Q_SZ	 4096u

#define ROC_EMDEV_PSW_BURST_SZ 64

/**
 * Virtio defines
 */
/* Use BAR 0 */
#define ROC_EMDEV_VIRTIO_BAR 0

/* VIRTIO PCI config area */
#define ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF 0

/* VIRTIO PCI common config area ``struct virtio_pci_common_cfg`` */
#define ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_LEN 64

/* VIRTIO PCI NET/CRYPTO device config area */
#define ROC_EMDEV_VIRTIO_PCI_DEV_CFG_LEN 64

typedef int (*roc_emdev_apinotif_cb_t)(uint16_t epf_func, struct roc_emdev_apinotif_handle *desc,
				       void *args);

typedef int (*roc_emdev_flrnotif_cb_t)(uint16_t epf_func, void *args);

int __roc_api roc_emdev_init(struct roc_emdev *roc_emdev);
int __roc_api roc_emdev_fini(struct roc_emdev *roc_emdev);

int __roc_api roc_emdev_setup(struct roc_emdev *roc_emdev);
int __roc_api roc_emdev_release(struct roc_emdev *roc_emdev);

int __roc_api roc_emdev_psw_epfvf_config(struct roc_emdev *roc_emdev, uint16_t evf_id,
					 uint16_t notify_qbase, bool enable);
void __roc_api roc_emdev_flrnotif_cb_register(struct roc_emdev *roc_emdev,
					      roc_emdev_flrnotif_cb_t cb, void *cb_args);
void __roc_api roc_emdev_flrnotif_cb_unregister(struct roc_emdev *roc_emdev);
struct roc_dpi_lf *__roc_api roc_emdev_dpi_lf_base_get(struct roc_emdev *roc_emdev);

int __roc_api roc_emdev_psw_aq_qp_init(struct roc_emdev *roc_emdev,
				       struct roc_emdev_psw_aq_qp *anq);
int __roc_api roc_emdev_psw_aq_qp_fini(struct roc_emdev_psw_aq_qp *anq);

int __roc_api roc_emdev_psw_nq_qp_init(struct roc_emdev *roc_emdev, struct roc_emdev_psw_nq_qp *nq);
int __roc_api roc_emdev_psw_nq_qp_fini(struct roc_emdev_psw_nq_qp *nq);

int __roc_api roc_emdev_psw_inb_q_init(struct roc_emdev *roc_emdev,
				       struct roc_emdev_psw_inb_q *inbq);
int __roc_api roc_emdev_psw_inb_q_fini(struct roc_emdev_psw_inb_q *inbq);

int __roc_api roc_emdev_psw_outb_q_init(struct roc_emdev *roc_emdev,
					struct roc_emdev_psw_outb_q *outbq);
int __roc_api roc_emdev_psw_outb_q_fini(struct roc_emdev_psw_outb_q *outbq);

int __roc_api roc_emdev_apinotif_cb_register(struct roc_emdev *roc_emdev,
					     roc_emdev_apinotif_cb_t cb, void *cb_args);
int __roc_api roc_emdev_apinotif_cb_unregister(struct roc_emdev *roc_emdev);
int __roc_api roc_emdev_irqs_register(struct roc_emdev *roc_emdev);
void __roc_api roc_emdev_irqs_unregister(struct roc_emdev *roc_emdev);
int __roc_api roc_emdev_mbox_msix_cfg(struct roc_emdev *roc_emdev, uint16_t evf_id,
				      uint16_t mbox_msix);
void __roc_api roc_emdev_psw_mbox_int_trigger(struct roc_emdev *roc_emdev, uint16_t evf_id);
uint16_t __roc_api roc_emdev_epf_func_get(struct roc_emdev *roc_emdev, uint16_t vf_id);

/* Debug APIs */
int __roc_api roc_emdev_psw_anq_desc_dump(FILE *file, void *data);
int __roc_api roc_emdev_psw_nq_desc_dump(FILE *file, void *data);
int __roc_api roc_emdev_psw_aq_qp_dump(struct roc_emdev_psw_aq_qp *anq, FILE *file);
int __roc_api roc_emdev_psw_nq_qp_dump(struct roc_emdev_psw_nq_qp *nq, FILE *file);
int __roc_api roc_emdev_psw_inb_q_dump(struct roc_emdev_psw_inb_q *inbq, FILE *file);
int __roc_api roc_emdev_psw_outb_q_dump(struct roc_emdev_psw_outb_q *outbq, FILE *file);

#endif /* __INCLUDE_ROC_EMDEV_H__ */
