/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_ROC_EMDEV_PRIV_H__
#define __INCLUDE_ROC_EMDEV_PRIV_H__

#define PSW_FID_ENTRY_MAX 12

struct psw_fid_entry {
	uint16_t bar;
	uint32_t offset;
	uint32_t size;
	uint8_t psw_type;
	uint8_t stride;
	uint8_t read_en;
	uint8_t write_en;
	uint8_t read_mask;
	uint8_t valid;
	uint16_t fid_idx;
	uint16_t isepf;
};

enum psw_virtio_fid_entry {
	PSW_VIRTIO_FID_CFG = 0,
	PSW_VIRTIO_FID_NOTIFY,
	PSW_VIRTIO_FID_MSIX,
	PSW_VIRTIO_FID_PBA,
	PSW_EVF_VIRTIO_FID_CFG,
	PSW_EVF_VIRTIO_FID_NOTIFY,
	PSW_EVF_VIRTIO_FID_MSIX,
	PSW_EVF_VIRTIO_FID_PBA,
	PSW_VIRTIO_FID_ENTRY_MAX,
};

struct psw_lf {
	uint16_t lf_id;
	uintptr_t rbase;
	uint16_t msixoff;
	struct emdev *emdev;
};

struct psw_hw_caps {
	/* PSW_AF_CONST0 includes, mevf, mdbl, mmsix and nepf */
	uint64_t const0;
	/* PSW_AF_CONST1 includes, mqueues, fidentrynum, gidbucketnum
	 * and gidentrynum
	 */
	uint64_t const1;
	/* PSW_AF_CONST2 includes, shared_size, TPT entries, PST and TST
	 * entries and number of LFs.
	 */
	uint64_t const2;
#define PSW_TYPE_COUNT 9
	/* PSW_AF_FID_TYPE(0..8)_CONST, includes pfoffset and vfoffset
	 * for each psw type
	 */
	uint64_t fid_type_const[PSW_TYPE_COUNT];
};

struct emdev_epfvf {
	/* Host EPFFUNC */
	uint16_t evf_id;
	uint16_t epf_func;

	/* Host-Shadow Inbound queues */
	struct roc_emdev_psw_inb_q **inb_qs;
	uint16_t nb_inb_qs;

	/* Host-Shadow Outbound queues */
	struct roc_emdev_psw_outb_q **outb_qs;
	uint16_t nb_outb_qs;

	/* Mapped PSW LF slot id */
	uint16_t psw_lfid;
	/* Number allocated GID resources for this function */
	uint16_t nb_rids;
};

struct emdev {
	/* Base device class */
	struct dev dev;

	/* PCI device */
	struct plt_pci_device *pci_dev;

	/* Emulation device type */
	enum roc_emdev_type emul_type;

	/* API notification queues */
	struct roc_emdev_psw_aq_qp *aq_qps;

	/* Notification queues */
	struct roc_emdev_psw_nq_qp **nq_qps;
	uint16_t nb_notify_qs;

	/* PSW LFs attached to emulation device */
	struct psw_lf *psw_lfs;
	uint16_t nb_psw_lfs;

	/* EPFVFs attached to emulation device */
	struct emdev_epfvf *epfvfs;
	uint16_t nb_epfvfs;
	uint16_t nb_inb_qs;
	uint16_t nb_outb_qs;
	uint8_t first_skip;
	uint8_t later_skip;

	/* EPF func and mask covering all EPFVF's */
	uint16_t epf_func;
	uint16_t epf_func_mask;

	/* Associated EPF id */
	uint16_t epf_id;
	uint16_t port;

	/* DPI LFs */
	uint8_t dpi_blkaddr;
	struct roc_dpi_lf *dpi_lfs;
	uint16_t nb_dpi_lfs;
	uint16_t dpi_chan_tbl;
	uint16_t dpi_chan_tbl_sz;

	/* PSW FID entries */
	struct psw_fid_entry fid_entries[PSW_VIRTIO_FID_ENTRY_MAX];
	uint16_t nb_fid_entries;

	/* API notify callback and args */
	roc_emdev_apinotif_cb_t apinotif_cb;
	void *apinotif_cb_args;

	roc_emdev_flrnotif_cb_t flrnotif_cb;
	void *flrnotif_cb_args;
	/* PSW HW capabilities */
	struct psw_hw_caps caps;
};

static inline struct emdev *
roc_emdev_to_emdev_priv(struct roc_emdev *roc_emdev)
{
	return (struct emdev *)&roc_emdev->reserved[0];
}

int emdev_lf_register_irqs(struct emdev *emdev);
int emdev_lf_unregister_irqs(struct emdev *emdev);

#endif /* __INCLUDE_ROC_EMDEV_PRIV_H__ */
