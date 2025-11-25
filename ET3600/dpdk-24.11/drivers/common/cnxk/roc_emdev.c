/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#include "roc_api.h"
#include "roc_priv.h"

#define ROC_EMDEV_API_Q_SZ 4096

/* VIRTIO PCI NOTIFY area BAR offset */
#define ROC_EMDEV_VIRTIO_NOTIFY_AREA_OFF    256
#define ROC_EMDEV_VIRTIO_NOTIFY_AREA_STRIDE 8
#define ROC_EMDEV_VIRTIO_MSIX_OFFSET	    4096
#define ROC_EMDEV_VIRTIO_PBA_OFFSET	    8192

#define MBOX_MSIX_VECS 4
#define MSIX_VEC_SZ    16

#define PEM_MAX_PFS 8

#define PSW_EPFFUNC(port, epf, vf_id) \
	((((port) & 0x1) << 14) | (((epf) & 0x7) << 9) | ((vf_id) & 0xFF))

const struct psw_fid_entry psw_fid_base[ROC_EMDEV_TYPE_MAX][PSW_FID_ENTRY_MAX] = {
	[ROC_EMDEV_TYPE_VIRTIO] = {
		/* VIRTIO PCI common config + VIRTIO DEV config area for EPF*/
		[PSW_VIRTIO_FID_CFG] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF,
			.size = (ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_LEN +
				 ROC_EMDEV_VIRTIO_PCI_DEV_CFG_LEN),
			.psw_type = PSW_TYPES_API,
			.read_en = 1,
			.write_en = 1,
			.read_mask = 0x0,
			.isepf = 1,
			.valid = 1,
		},
		/* VIRTIO PCI notify area for EPF */
		[PSW_VIRTIO_FID_NOTIFY] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_NOTIFY_AREA_OFF,
			.psw_type = PSW_TYPES_PIDBL,
			.size = 0,
			.write_en = 1,
			.read_mask = 0x1,
			.stride = ROC_EMDEV_VIRTIO_NOTIFY_AREA_STRIDE,
			.isepf = 1,
			.valid = 1,
		},
		/* VIRTIO PCI MSI-X area for EPF */
		[PSW_VIRTIO_FID_MSIX] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_MSIX_OFFSET,
			.psw_type = PSW_TYPES_MSIX,
			.size = 0,
			.write_en = 1,
			.read_en = 1,
			.read_mask = 0x0,
			.isepf = 1,
			.valid = 1,
		},
		/* VIRTIO PCI PBA area for EPF */
		[PSW_VIRTIO_FID_PBA] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_PBA_OFFSET,
			.psw_type = PSW_TYPES_PBA,
			.size = 0,
			.write_en = 1,
			.read_en = 1,
			.read_mask = 0x0,
			.isepf = 1,
			.valid = 1,
		},
		/* VIRTIO PCI common config + VIRTIO DEV config area for all EVFs of a EPF */
		[PSW_EVF_VIRTIO_FID_CFG] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_OFF,
			.size = (ROC_EMDEV_VIRTIO_PCI_COMMON_CFG_LEN +
				 ROC_EMDEV_VIRTIO_PCI_DEV_CFG_LEN),
			.psw_type = PSW_TYPES_API,
			.read_en = 1,
			.write_en = 1,
			.read_mask = 0x0,
			.isepf = 0,
			.valid = 1,
		},
		/* VIRTIO PCI notify area for all EVFs of a EPF */
		[PSW_EVF_VIRTIO_FID_NOTIFY] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_NOTIFY_AREA_OFF,
			.psw_type = PSW_TYPES_PIDBL,
			.size = 0,
			.write_en = 1,
			.read_mask = 0x1,
			.stride = ROC_EMDEV_VIRTIO_NOTIFY_AREA_STRIDE,
			.isepf = 0,
			.valid = 1,
		},
		/* VIRTIO PCI MSI-X area for all EPFs of a EPF */
		[PSW_EVF_VIRTIO_FID_MSIX] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_MSIX_OFFSET,
			.psw_type = PSW_TYPES_MSIX,
			.size = 0,
			.write_en = 1,
			.read_en = 1,
			.read_mask = 0x0,
			.isepf = 0,
			.valid = 1,
		},
		/* VIRTIO PCI PBA area for all EPFs of a EPF */
		[PSW_EVF_VIRTIO_FID_PBA] = {
			.bar = ROC_EMDEV_VIRTIO_BAR,
			.offset = ROC_EMDEV_VIRTIO_PBA_OFFSET,
			.psw_type = PSW_TYPES_PBA,
			.size = 0,
			.write_en = 1,
			.read_en = 1,
			.read_mask = 0x0,
			.isepf = 0,
			.valid = 1,
		},
	},
};

static int
psw_lf_attach(struct dev *dev, uint8_t nb_psw_lfs)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct psw_rsrc_attach_req *req;
	int rc = -ENOMEM;

	/* Attach PSW LF */
	req = mbox_alloc_msg_psw_attach_resources(mbox);
	if (req == NULL)
		goto exit;

	req->modify = true;
	req->pswlfs = nb_psw_lfs;

	rc = mbox_process(mbox);
	if (rc)
		plt_err("Failed to attach PSW/DPI LF, rc=%d", rc);

exit:
	mbox_put(mbox);
	return rc;
}

static int
psw_lf_detach(struct dev *dev)
{
	struct mbox *mbox = mbox_get(dev->mbox);
	struct psw_rsrc_detach_req *req;
	int rc = -ENOMEM;

	/* Detach PSW LF */
	req = mbox_alloc_msg_psw_detach_resources(mbox);
	if (req == NULL)
		goto exit;

	req->partial = 1;
	req->pswlfs = 1;

	rc = mbox_process(mbox);
	if (rc)
		plt_err("Failed to detach PSW/DPI LF, rc=%d", rc);

exit:
	mbox_put(mbox);
	return rc;
}

static int
emdev_lf_attach(struct emdev *emdev)
{
	uint8_t dpi_blkaddr = RVU_BLOCK_ADDR_DPI0;
	struct psw_msix_offset_rsp *msix_rsp;
	struct msg_req *msix_req;
	struct psw_lf *psw_lf;
	struct mbox *mbox;
	int rc, i;

	emdev->dpi_blkaddr = dpi_blkaddr;

	/* Attach PSW LF */
	rc = psw_lf_attach(&emdev->dev, emdev->nb_psw_lfs);
	if (rc)
		return rc;

	/* Attach DPI LF */
	rc = dpi_lf_attach(&emdev->dev, dpi_blkaddr, true, emdev->nb_dpi_lfs);
	if (rc)
		goto psw_detach;

	mbox = mbox_get(emdev->dev.mbox);
	/* Get MSIX offsets */
	msix_req = mbox_alloc_msg_psw_msix_offset(mbox);
	if (msix_req == NULL) {
		mbox_put(mbox);
		goto dpi_detach;
	}

	rc = mbox_process_msg(mbox, (void **)&msix_rsp);
	if (rc) {
		plt_err("Failed to get msix offsets for PSW/DPI LF, rc=%d", rc);
		mbox_put(mbox);
		goto dpi_detach;
	}
	mbox_put(mbox);

	/* Populate PSW LF's */
	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		psw_lf->lf_id = i;
		psw_lf->rbase = emdev->dev.bar2 + ((RVU_BLOCK_ADDR_PSW << 20) | (i << 12));
		psw_lf->msixoff = msix_rsp->pswlf_msixoff[i];
		psw_lf->emdev = emdev;
	}

	/* Init DPI LF's */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		rc = dpi_lf_init(&emdev->dpi_lfs[i], &emdev->dev, i);
		if (rc)
			goto dpi_detach;

		/* Update DPI LF's SSO/NPA PF_FUNC's */
		rc = roc_dpi_lf_pffunc_cfg(&emdev->dpi_lfs[i]);
		if (rc) {
			plt_err("Failed to configure SSO/NPA PF_FUNC for DPI LF, rc=%d", rc);
			goto dpi_detach;
		}

		/* Populate DPI queue size and first skip/later skip */
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].qsize = ROC_EMDEV_DPI_Q_SZ;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].cmd_len = DPI_CMD_SIZE_64B;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].first_skip = emdev->first_skip;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_INB].later_skip = emdev->later_skip;

		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_OUTB].qsize = ROC_EMDEV_DPI_Q_SZ;
		emdev->dpi_lfs[i].queue[ROC_EMDEV_DPI_LF_RING_OUTB].cmd_len = DPI_CMD_SIZE_64B;
	}

	return 0;
dpi_detach:
	rc |= dpi_lf_detach(&emdev->dev);
psw_detach:
	rc |= psw_lf_detach(&emdev->dev);
	return rc;
}

static int
emdev_lf_detach(struct emdev *emdev)
{
	int rc = 0;

	/* Detach DPI LF */
	rc |= dpi_lf_detach(&emdev->dev);

	/* Detach PSW LF */
	rc |= psw_lf_detach(&emdev->dev);

	return rc;
}

static int
psw_virtio_fid_table_setup(struct emdev *emdev)
{
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_fid_free_entry_req *free_req;
	struct psw_fid_alloc_entry_req *req;
	struct psw_fid_alloc_entry_rsp *rsp;
	struct psw_epf_dbl_cfg_req *dbl_req;
	const struct psw_fid_entry *entry;
	size_t size;
	int rc, i;

	for (i = 0; i < (int)PSW_FID_ENTRY_MAX; i++) {
		entry = &psw_fid_base[ROC_EMDEV_TYPE_VIRTIO][i];
		if (!entry->valid)
			continue;
		/* Allocate entry for common config and device config */
		req = mbox_alloc_msg_psw_fid_alloc_entry(mbox);
		if (!req)
			return -ENOMEM;

		/* Matches this EPF and all its VF's */
		req->evf_id = 0;
		req->evfm1_mask = 0x0;
		req->bar = entry->bar;
		req->base_addr = entry->offset >> 3;

		switch (entry->psw_type) {
		/* For VIRTIO notify area, size would be calculated based on stride and number of
		 * queues allocated.
		 */
		case PSW_TYPES_PIDBL:
			size = PLT_ALIGN(emdev->nb_inb_qs * entry->stride, 2);
			break;
		case PSW_TYPES_MSIX:
			size = (emdev->nb_inb_qs + MBOX_MSIX_VECS) * MSIX_VEC_SZ;
			break;
		case PSW_TYPES_PBA:
			size = ((emdev->nb_inb_qs + MBOX_MSIX_VECS) / 8) + 1;
			break;
		default:
			size = entry->size;
			break;
		}
		size = plt_align32pow2(size);
		/* Check if size and base conflicts with previous entry */
		if (i >= 1) {
			if (emdev->fid_entries[i - 1].isepf == entry->isepf &&
			    emdev->fid_entries[i - 1].offset + emdev->fid_entries[i - 1].size >
			    entry->offset) {
				plt_err("FID entry[%d] conflicts with previous entry", i);
				rc = -EINVAL;
				goto error;
			}
		}

		req->base_mask = (~(size - 1)) >> 3;
		req->log2size = plt_log2_u32(size);
		/* Stride is in multiple of 8 bytes */
		req->log2stride = plt_log2_u32(entry->stride / 8);
		req->psw_type = entry->psw_type;
		req->read_mask = entry->read_mask;
		req->read_en = entry->read_en;
		req->isepf = entry->isepf;

		plt_emdev_dbg("fid[%u]: Base_addr=%x base_mask=%x", i, req->base_addr,
			      req->base_mask);

		rc = mbox_process_msg(mbox, (void **)&rsp);
		if (rc) {
			plt_err("Failed to allocate PSW FID entry, rc=%d", rc);
			goto error;
		}

		/* Store fid entry for future use */
		emdev->fid_entries[i] = *entry;
		emdev->fid_entries[i].size = size;
		emdev->fid_entries[i].fid_idx = rsp->fid_idx;
		emdev->nb_fid_entries++;
	}
	dbl_req = mbox_alloc_msg_psw_epf_dbl_cfg(mbox);
	if (!dbl_req)
		goto error;
	dbl_req->pi.mask = 0xffff;
	dbl_req->pi.les = 0;
	dbl_req->pi.rotate = 16;
	dbl_req->pi.tglen = 1;

	dbl_req->ci.mask = 0xffff;
	dbl_req->ci.les = 0;
	dbl_req->ci.tglen = 0;
	rc = mbox_process(mbox);
	if (rc) {
		plt_err("Failed to configure epf doorbell, rc=%d", rc);
		goto error;
	}

	mbox_put(mbox);
	return 0;
error:
	/* Release allocated FID entries */
	for (i = 0; i < emdev->nb_fid_entries; i++) {
		free_req = mbox_alloc_msg_psw_fid_free_entry(mbox);
		if (!free_req)
			break;
		free_req->fid_idx = emdev->fid_entries[i].fid_idx;
		rc |= mbox_process(mbox);
	}
	emdev->nb_fid_entries = 0;
	mbox_put(mbox);
	return rc;
}

static int
psw_virtio_fid_table_release(struct emdev *emdev)
{
	int rc = 0;
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_fid_free_entry_req *req;
	int i;

	for (i = 0; i < emdev->nb_fid_entries; i++) {
		req = mbox_alloc_msg_psw_fid_free_entry(mbox);
		if (!req)
			break;
		req->fid_idx = emdev->fid_entries[i].fid_idx;
		rc |= mbox_process(mbox);
	}

	emdev->nb_fid_entries = 0;
	mbox_put(mbox);

	return rc;
}

int
roc_emdev_init(struct roc_emdev *roc_emdev)
{
	struct plt_pci_device *pci_dev;
	struct idev_cfg *idev;
	struct emdev *emdev;
	int rc;

	idev = idev_get_cfg();
	if (idev == NULL)
		return -ENOTSUP;

	emdev = roc_emdev_to_emdev_priv(roc_emdev);
	pci_dev = roc_emdev->pci_dev;

	/* Initialize base device */
	rc = dev_init(&emdev->dev, pci_dev);
	if (rc)
		return rc;

	emdev->pci_dev = pci_dev;
	idev->emdev = emdev;

	return 0;
}

int
roc_emdev_fini(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	/* Finalize base device */
	return dev_fini(&emdev->dev, emdev->pci_dev);
}

static int
emdev_psw_rsrc_alloc(struct emdev *emdev, uint16_t nb_inb_qs, uint16_t nb_outb_qs)
{
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_gid_free_req *free_req;
	struct psw_gid_alloc_req *req;
	struct emdev_epfvf *epfvf;
	uint16_t nb_epfvfs;
	int rc, i;

	nb_epfvfs = emdev->nb_epfvfs;
	/* Allocate memory for EPFVF */
	emdev->epfvfs = plt_zmalloc(sizeof(struct emdev_epfvf) * nb_epfvfs, 0);
	if (!emdev->epfvfs)
		return -ENOMEM;

	/* Allocate queue resources per EPFVF */
	for (i = 0; i < nb_epfvfs; i++) {
		epfvf = &emdev->epfvfs[i];
		epfvf->evf_id = i;
		epfvf->epf_func = PSW_EPFFUNC(0, emdev->epf_id, i);

		/* Allocate inbound and outbound queue holders */
		rc = -ENOMEM;
		epfvf->inb_qs = plt_zmalloc(sizeof(struct roc_emdev_psw_inb_q *) * nb_inb_qs, 0);
		if (!epfvf->inb_qs)
			goto error_q_alloc;

		epfvf->outb_qs = plt_zmalloc(sizeof(struct roc_emdev_psw_outb_q *) * nb_outb_qs, 0);
		if (!epfvf->outb_qs)
			goto error_q_alloc;

		/* Allocate PSW inbound and outbound queues */
		req = mbox_alloc_msg_psw_gid_alloc(mbox);
		if (!req)
			return -ENOMEM;

		req->evf_id = epfvf->evf_id;
		req->nb_inb_qs = nb_inb_qs;
		req->nb_outb_qs = nb_outb_qs;
		req->nb_mid = PLT_MAX(nb_inb_qs, nb_outb_qs);
		req->rid_base = 0;

		rc = mbox_process(mbox);
		if (rc) {
			plt_err("Failed to allocate PSW queues, rc=%d", rc);
			goto error_q_alloc;
		}

		plt_emdev_dbg("GID alloc done, nb_inb_qs : %u nb_outb_qs: %u", nb_inb_qs,
			      nb_outb_qs);

		epfvf->nb_inb_qs = nb_inb_qs;
		epfvf->nb_outb_qs = nb_outb_qs;
		epfvf->nb_rids = req->nb_mid;
	}

	mbox_put(mbox);
	return 0;
error_q_alloc:
	/* Clean up allocated resources */
	for (i = 0; i < nb_epfvfs; i++) {
		free_req = mbox_alloc_msg_psw_gid_free(mbox);
		if (!free_req)
			break;
		free_req->evf_id = emdev->epfvfs[i].evf_id;
		free_req->nb_rids = epfvf->nb_rids;
		free_req->rid_base = 0;
		rc |= mbox_process(mbox);

		plt_free(emdev->epfvfs[i].inb_qs);
		plt_free(emdev->epfvfs[i].outb_qs);
	}
	plt_free(emdev->epfvfs);
	emdev->epfvfs = NULL;
	mbox_put(mbox);
	return rc;
}

static int
emdev_psw_rsrc_free(struct emdev *emdev)
{
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_gid_free_req *req;
	struct emdev_epfvf *epfvf;
	uint16_t nb_epfvfs;
	int rc = 0, i;

	nb_epfvfs = emdev->nb_epfvfs;

	/* Free queue resources per EPFVF */
	for (i = 0; i < nb_epfvfs; i++) {
		epfvf = &emdev->epfvfs[i];

		req = mbox_alloc_msg_psw_gid_free(mbox);
		if (!req)
			return -ENOMEM;

		req->evf_id = epfvf->evf_id;
		req->nb_rids = epfvf->nb_rids;
		req->rid_base = 0;
		rc |= mbox_process(mbox);
		if (rc)
			plt_err("Failed to free PSW queues for epfvf %d, rc=%d", i, rc);
	}

	plt_free(emdev->epfvfs);
	emdev->epfvfs = NULL;

	mbox_put(mbox);
	return rc;
}

static int
emdev_aq_qp_init(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	struct roc_emdev_psw_aq_qp *aq_qp;
	int rc, i;

	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		aq_qp = &emdev->aq_qps[i];
		aq_qp->qid = 0;
		aq_qp->nb_desc = ROC_EMDEV_API_Q_SZ;

		rc = roc_emdev_psw_aq_qp_init(roc_emdev, aq_qp);
		if (rc) {
			plt_err("Failed to setup PSW AQ QP, rc=%d", rc);
			return rc;
		}
	}

	return 0;
}

static int
emdev_aq_qp_fini(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	struct roc_emdev_psw_aq_qp *aq_qp;
	int rc = 0, i;

	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		aq_qp = &emdev->aq_qps[i];

		rc |= roc_emdev_psw_aq_qp_fini(aq_qp);
		if (rc)
			plt_err("Failed to cleanup PSW AQ QP, rc=%d", rc);
	}

	return rc;
}

static int
emdev_dpi_chan_tbl_config(struct emdev *emdev)
{
	struct roc_dpi_lf *lf;
	uint64_t tbl_entries[64], epf_id;
	uint16_t nb_entries, tbl_sz;
	int rc, i = 0, chan_tbl;

	/* Use default channel table if there is no one PF */
	if (emdev->nb_epfvfs == 1) {
		union roc_dpi_lf_ccfg ccfg;
		ccfg.u = BIT_ULL(63) | emdev->epf_id << 12 | 0;

		for (i = 0; i < emdev->nb_dpi_lfs; i++) {
			lf = &emdev->dpi_lfs[i];
			/* Setup default chan config */
			rc = roc_dpi_lf_ring_chan_cfg(&lf->queue[ROC_EMDEV_DPI_LF_RING_INB], &ccfg);
			rc |= roc_dpi_lf_ring_chan_cfg(&lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB],
						       &ccfg);
			if (rc) {
				plt_err("Failed to configure DPI ring default chan, rc=%d", rc);
				return rc;
			}
		}
		return 0;
	}

	/* Alloc one DPI Channel Table */
	tbl_sz = emdev->nb_epfvfs * 2;
	chan_tbl = dpi_chan_tbl_alloc(&emdev->dev, emdev->dpi_blkaddr, tbl_sz);
	if (chan_tbl < 0) {
		plt_err("Failed to allocate DPI Channel Table, rc=%d", chan_tbl);
		return chan_tbl;
	}

	emdev->dpi_chan_tbl = chan_tbl;
	emdev->dpi_chan_tbl_sz = tbl_sz;
	epf_id = emdev->epf_id;

	/* Fill DPI Channel Table entries */
	i = 0;
	while (i < emdev->nb_epfvfs) {
		/* One entry per EPF_FUNC */
		tbl_entries[i % 64] = BIT_ULL(63) | epf_id << 12 | i;
		i++;

		/* Write 64 entries at a time */
		if (i % 64 == 0) {
			nb_entries = 64;
			rc = dpi_chan_tbl_update(&emdev->dev, emdev->dpi_blkaddr, chan_tbl,
						 tbl_entries, i - nb_entries, nb_entries);
			if (rc) {
				plt_err("Failed to write DPI Channel Table, rc=%d", rc);
				return rc;
			}
		}
	}

	/* Write remaining entries */
	nb_entries = i % 64;
	if (nb_entries) {
		rc = dpi_chan_tbl_update(&emdev->dev, emdev->dpi_blkaddr, chan_tbl, tbl_entries,
					 i - nb_entries, nb_entries);
		if (rc) {
			plt_err("Failed to write DPI Channel Table, rc=%d", rc);
			rc |= dpi_chan_tbl_free(&emdev->dev, emdev->dpi_blkaddr, chan_tbl);
			return rc;
		}
	}
	return 0;
}

static void
emdev_dpi_lf_ring_ena_dis(struct roc_dpi_lf *lf, uint8_t ring_idx, uint8_t enb)
{
	uint64_t reg;

	reg = plt_read64(lf->rbase + DPI_LF_RINGX_CFG(ring_idx));
	if (enb)
		reg |= DPI_LF_QCFG_QEN;
	else
		reg &= ~DPI_LF_QCFG_QEN;
	plt_write64(reg, lf->rbase + DPI_LF_RINGX_CFG(ring_idx));
}

static int
emdev_dpi_setup(struct emdev *emdev)
{
	struct roc_dpi_lf_ring_cfg rcfg;
	struct roc_dpi_lf_que *lf_q;
	struct roc_dpi_lf *lf;
	int i, rc = 0;

	rc = emdev_dpi_chan_tbl_config(emdev);
	if (rc)
		return rc;

	/* Setup DPI rings */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		lf = &emdev->dpi_lfs[i];

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];

		if (emdev->nb_epfvfs > 1) {
			/* Associate LF to channel table */
			rc = dpi_chan_tbl_ena_dis(&emdev->dev, emdev->dpi_blkaddr, lf->slot,
						  emdev->dpi_chan_tbl, true);
			if (rc) {
				plt_err("Failed to associate DPI LF:%d to channel table, rc=%d",
					lf->slot, rc);
				goto cleanup_ring;
			}
		}

		/* Setup DPI ring for ROC_EMDEV_DPI_LF_RING_INB */
		memset(&rcfg, 0, sizeof(rcfg));
		rcfg.xtype = DPI_XTYPE_INBOUND;
		rcfg.rport = emdev->epf_id < PEM_MAX_PFS ? 0 : 1;
		rcfg.isize = lf_q->cmd_len / DPI_CMD_SIZE_128B;
		rcfg.ring_idx = ROC_EMDEV_DPI_LF_RING_INB;

		rc = roc_dpi_lf_ring_init(lf_q, &rcfg);
		if (rc) {
			plt_err("Failed to setup DPI ring for DEV2MEM, rc=%d", rc);
			goto cleanup_ring;
		}

		/* enable dpi lf inbound ring */
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 1);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		/* Setup DPI ring for ROC_EMDEV_DPI_LF_RING_OUTB */
		memset(&rcfg, 0, sizeof(rcfg));
		rcfg.xtype = DPI_XTYPE_OUTBOUND;
		rcfg.wport = emdev->epf_id < PEM_MAX_PFS ? 0 : 1;
		rcfg.isize = lf_q->cmd_len / DPI_CMD_SIZE_128B;
		rcfg.ring_idx = ROC_EMDEV_DPI_LF_RING_OUTB;

		rc = roc_dpi_lf_ring_init(lf_q, &rcfg);
		if (rc) {
			plt_err("Failed to setup DPI ring for MEM2DEV, rc=%d", rc);
			goto cleanup_ring;
		}

		/* enable dpi lf outbound ring */
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 1);
	}

	return 0;
cleanup_ring:
	for (; i > 0; i--) {
		lf = &emdev->dpi_lfs[i - 1];
		/* Disable rings */
		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		if (emdev->nb_epfvfs > 1)
			rc |= dpi_chan_tbl_ena_dis(&emdev->dev, emdev->dpi_blkaddr, lf->slot,
						   emdev->dpi_chan_tbl, false);
	}
	if (emdev->nb_epfvfs > 1)
		rc |= dpi_chan_tbl_free(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl);

	return rc;
}

static int
emdev_dpi_release(struct emdev *emdev)
{
	struct roc_dpi_lf_que *lf_q;
	struct roc_dpi_lf *lf;
	int i, rc = 0;

	/* Disable DPI rings */
	for (i = 0; i < emdev->nb_dpi_lfs; i++) {
		lf = &emdev->dpi_lfs[i];
		/* Disable rings */
		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_INB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_INB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		lf_q = &lf->queue[ROC_EMDEV_DPI_LF_RING_OUTB];
		emdev_dpi_lf_ring_ena_dis(lf, ROC_EMDEV_DPI_LF_RING_OUTB, 0);
		roc_dpi_lf_ring_fini(lf_q);

		if (emdev->nb_epfvfs > 1)
			/* Disable DPI LF from channel table */
			rc |= dpi_chan_tbl_ena_dis(&emdev->dev, emdev->dpi_blkaddr, lf->slot,
						   emdev->dpi_chan_tbl, false);
	}

	if (emdev->nb_epfvfs > 1)
		rc = dpi_chan_tbl_free(&emdev->dev, emdev->dpi_blkaddr, emdev->dpi_chan_tbl);

	return rc;
}

static int
emdev_psw_caps_get(struct emdev *emdev)
{
	struct mbox *mbox = mbox_get(emdev->dev.mbox);
	struct psw_caps_get_rsp *caps;
	int rc;

	mbox_alloc_msg_psw_caps_get(mbox);

	rc = mbox_process_msg(mbox, (void *)&caps);
	if (rc) {
		plt_err("Failed to get PSW caps, rc=%d", rc);
		goto exit;
	}
	emdev->epf_id = caps->epf_id;
	emdev->caps.const0 = caps->const0;
	emdev->caps.const1 = caps->const1;
	emdev->caps.const2 = caps->const2;
	mbox_memcpy(emdev->caps.fid_type_const, caps->fid_type_const,
		    sizeof(emdev->caps.fid_type_const));
exit:
	mbox_put(mbox);
	return rc;
}

int
roc_emdev_setup(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	uint16_t nb_inb_qs, nb_outb_qs, nb_notify_qs;
	uint16_t nb_psw_lfs;
	int rc;

	nb_inb_qs = roc_emdev->nb_inb_qs;
	nb_outb_qs = roc_emdev->nb_outb_qs;
	nb_notify_qs = roc_emdev->nb_notify_qs;

	/* Each PSW LFs have 8 notify queues */
	nb_psw_lfs = nb_notify_qs / 8;
	if (nb_notify_qs % 8)
		nb_psw_lfs++;

	emdev->nb_inb_qs = nb_inb_qs;
	emdev->nb_outb_qs = nb_outb_qs;
	emdev->nb_psw_lfs = nb_psw_lfs;
	emdev->nb_notify_qs = nb_notify_qs;
	emdev->nb_epfvfs = roc_emdev->nb_epfvfs;
	emdev->nb_dpi_lfs = nb_notify_qs;
	emdev->first_skip = roc_emdev->first_skip;
	emdev->later_skip = roc_emdev->later_skip;

	rc = -ENOMEM;
	/* Allocate memory to hold AQs */
	emdev->aq_qps = plt_zmalloc(sizeof(struct roc_emdev_psw_aq_qp) * nb_psw_lfs, 0);
	if (!emdev->aq_qps)
		return rc;

	/* Allocate memory to hold pointers to NQ QP's */
	emdev->nq_qps = plt_zmalloc(sizeof(struct roc_emdev_psw_nq_qp *) * nb_notify_qs, 0);
	if (!emdev->nq_qps)
		goto free_mem;

	/* Allocate memory to hold PSW LFs and its notification queues */
	emdev->psw_lfs = plt_zmalloc(sizeof(struct psw_lf) * nb_psw_lfs, 0);
	if (!emdev->psw_lfs)
		goto free_mem;

	/* Allocate memory to hold DPI LFs */
	emdev->dpi_lfs = plt_zmalloc(sizeof(struct roc_dpi_lf) * emdev->nb_dpi_lfs, 0);
	if (!emdev->dpi_lfs)
		goto free_mem;

	emdev->emul_type = roc_emdev->emul_type;

	rc = emdev_psw_caps_get(emdev);
	if (rc)
		goto free_mem;

	/* Attach PSW, DPI LF */
	rc = emdev_lf_attach(emdev);
	if (rc)
		goto free_mem;

	/* Setup DPI rings */
	rc = emdev_dpi_setup(emdev);
	if (rc)
		goto detach_lf;

	/* Allocate PSW HIB, SHIB, HOB, SHOB queues per EPF_FUNC */
	rc = emdev_psw_rsrc_alloc(emdev, nb_inb_qs, nb_outb_qs);
	if (rc)
		goto dpi_lf_release;

	/* Setup PSW FID table based on device type */
	rc = -ENOTSUP;
	if (emdev->emul_type == ROC_EMDEV_TYPE_VIRTIO)
		rc = psw_virtio_fid_table_setup(emdev);

	if (rc)
		goto free_psw_rsrc;

	/* Setup PSW AQ QP */
	rc = emdev_aq_qp_init(roc_emdev);
	if (rc)
		goto cleanup_fid;

	return 0;
cleanup_fid:
	rc |= psw_virtio_fid_table_release(emdev);
free_psw_rsrc:
	/* Free PSW HIB, SHIB, HOB, SHOB queues per EPF_FUNC */
	rc |= emdev_psw_rsrc_free(emdev);
dpi_lf_release:
	rc |= emdev_dpi_release(emdev);
detach_lf:
	rc |= emdev_lf_detach(emdev);
free_mem:
	plt_free(emdev->dpi_lfs);
	plt_free(emdev->psw_lfs);
	plt_free(emdev->nq_qps);
	plt_free(emdev->aq_qps);

	return rc;
}

int
roc_emdev_release(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	int rc;

	/* Cleanup PSW AQ QP */
	rc = emdev_aq_qp_fini(roc_emdev);
	if (rc)
		return rc;

	/* Remove FID entries */
	rc = psw_virtio_fid_table_release(emdev);
	if (rc)
		return rc;

	/* Free PSW HIB, SHIB, HOB, SHOB queues per EPF_FUNC */
	rc = emdev_psw_rsrc_free(emdev);
	if (rc)
		return rc;

	/* DPI LF cleanup */
	rc = emdev_dpi_release(emdev);
	if (rc)
		return rc;

	/* Detach PSW, DPI LF */
	rc = emdev_lf_detach(emdev);
	if (rc)
		return rc;

	plt_free(emdev->aq_qps);
	plt_free(emdev->nq_qps);
	plt_free(emdev->psw_lfs);
	plt_free(emdev->dpi_lfs);
	emdev->aq_qps = NULL;
	emdev->nq_qps = NULL;
	emdev->psw_lfs = NULL;
	emdev->dpi_lfs = NULL;

	return 0;
}

int
roc_emdev_apinotif_cb_register(struct roc_emdev *roc_emdev, roc_emdev_apinotif_cb_t cb,
			       void *cb_args)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->apinotif_cb = cb;
	emdev->apinotif_cb_args = cb_args;
	return 0;
}

int
roc_emdev_apinotif_cb_unregister(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->apinotif_cb = NULL;
	emdev->apinotif_cb_args = NULL;
	return 0;
}

struct roc_dpi_lf *
roc_emdev_dpi_lf_base_get(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	return emdev->dpi_lfs;
}

uint16_t
roc_emdev_epf_func_get(struct roc_emdev *roc_emdev, uint16_t vf_id)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	uint16_t port;

	port = emdev->epf_id < PEM_MAX_PFS ? 0 : 1;
	return PSW_EPFFUNC(port, emdev->epf_id, vf_id);
}

void
roc_emdev_flrnotif_cb_register(struct roc_emdev *roc_emdev, roc_emdev_flrnotif_cb_t cb,
			       void *cb_args)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->flrnotif_cb = cb;
	emdev->flrnotif_cb_args = cb_args;
}

void
roc_emdev_flrnotif_cb_unregister(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev->flrnotif_cb = NULL;
	emdev->flrnotif_cb_args = NULL;
}

int
roc_emdev_mbox_msix_cfg(struct roc_emdev *roc_emdev, uint16_t evf_id, uint16_t mbox_msix)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	struct dev *dev = &emdev->dev;
	struct mbox *mbox = mbox_get(dev->mbox);
	struct psw_mbox_msix_cfg_req *req;
	int rc = -ENOMEM;

	req = mbox_alloc_msg_psw_mbox_msix_cfg(mbox);
	if (req == NULL)
		goto exit;

	req->evf_id = evf_id;
	req->mbox_msix = mbox_msix;

	rc = mbox_process(mbox);
	if (rc)
		plt_err("Failed to set mbox msix, rc=%d", rc);

exit:
	mbox_put(mbox);
	return rc;
}

void
roc_emdev_psw_mbox_int_trigger(struct roc_emdev *roc_emdev, uint16_t evf_id)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	struct emdev_epfvf *epfvf;
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	uint64_t wdata;

	epfvf = &emdev->epfvfs[evf_id];
	psw_lf = &emdev->psw_lfs[0];
	rbase = psw_lf->rbase;

	wdata = epfvf->epf_func;

	roc_atomic64_cas(wdata, 1, PLT_PTR_CAST(rbase + PSW_LF_OP_MBOXX(1)));
}
