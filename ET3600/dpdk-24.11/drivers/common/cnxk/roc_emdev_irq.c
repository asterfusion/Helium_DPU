/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

#define ANQ_DESC_SZ(x)		  (x * PSW_ANQ_DESC_SZ)
#define ANQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + ANQ_DESC_SZ(i) + (o))

#define AAQ_DESC_SZ(x)		  (x * PSW_AAQ_DESC_SZ)
#define AAQ_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + AAQ_DESC_SZ(i) + (o))

static inline int
emdev_lf_aq_ack_desc_enqueue(struct psw_lf *lf, uint64_t data, uint8_t be, uint16_t etag,
			     uint16_t epffunc, bool rd_err)
{
	struct emdev *emdev = lf->emdev;
	struct roc_emdev_psw_aq_qp *aq_qp;
	uint64_t desc_data;
	void *ack_q_base;
	uint16_t pi, ci;

	aq_qp = &emdev->aq_qps[lf->lf_id];
	ack_q_base = aq_qp->ack_q_base;
	pi = plt_read64(aq_qp->ack_q_pi_dbell);
	ci = plt_read64(aq_qp->ack_q_ci_dbell);
	if (((pi + 1) & aq_qp->qmask) == ci)
		return -ENOSPC;

	desc_data = PSW_ACK_DESC_TYPE_DATA << 1;
	desc_data |= 1 << 8;
	desc_data |= epffunc << 16;
	desc_data |= (uint64_t)etag << 32;
	desc_data |= be << 8;
	desc_data |= rd_err << 5;

	*AAQ_DESC_PTR_OFF(ack_q_base, pi, 0) = desc_data;
	*AAQ_DESC_PTR_OFF(ack_q_base, pi, 8) = data;

	pi = (pi + 1) & aq_qp->qmask;
	plt_write64(pi, aq_qp->ack_q_pi_dbell);

	return 0;
}

static int
emdev_lf_apinotif_process_desc(struct psw_lf *lf)
{
	struct roc_emdev_apinotif_handle handle;
	struct roc_emdev_psw_aq_qp *aq_qp;
	struct emdev *emdev = lf->emdev;
	uint64_t desc_data, data;
	uint16_t epf_func, etag;
	void *notify_q_base;
	uint8_t dtype, be;
	bool rd_err = 0;
	uint16_t ci, pi;
	uint32_t addr;
	int rc = 0;

	aq_qp = &emdev->aq_qps[lf->lf_id];

	notify_q_base = aq_qp->notify_q_base;
	ci = plt_read64(aq_qp->notify_q_ci_dbell);
	pi = plt_read64(aq_qp->notify_q_pi_dbell);

	/* Check if there is no descriptor to process */
	if (ci == pi)
		return 0;

	while (ci != pi) {
#ifdef CNXK_EMDEV_DEBUG
		roc_emdev_psw_anq_desc_dump(NULL, ANQ_DESC_PTR_OFF(notify_q_base, ci, 0));
#endif
		desc_data = *ANQ_DESC_PTR_OFF(notify_q_base, ci, 0);
		addr = desc_data >> 32;
		epf_func = (desc_data >> 16) & 0xffff;
		data = (desc_data >> 4) & 0xf;
		dtype = (desc_data >> 1) & 0x7;
		be = (desc_data >> 8) & 0xff;
		ci = (ci + 1) & aq_qp->qmask;

		handle.addr = addr;
		handle.be = be;
		switch (dtype) {
		case PSW_NOTIF_DESC_TYPE_WRITE:
			/* Next descriptor should be DATA descriptor */
			desc_data = *ANQ_DESC_PTR_OFF(notify_q_base, ci, 0);
			if (((desc_data >> 1) & 0x7) != PSW_NOTIF_DESC_TYPE_DATA) {
				plt_err("Unexpected descriptor type: 0x%" PRIx64 " at ci=0x%x",
					((desc_data >> 1) & 0x7), ci);
				rc |= -EIO;
				break;
			}

			data |= (desc_data & ~0xF);

			handle.data = data;
			handle.is_read = false;
			if (emdev->apinotif_cb != NULL)
				emdev->apinotif_cb(epf_func, &handle, emdev->apinotif_cb_args);

			ci = (ci + 1) & aq_qp->qmask;
			break;
		case PSW_NOTIF_DESC_TYPE_READ:
			/* Next descriptor should be TAG descriptor */
			desc_data = *ANQ_DESC_PTR_OFF(notify_q_base, ci, 0);
			if (((desc_data >> 1) & 0x7) != PSW_NOTIF_DESC_TYPE_TAG) {
				plt_err("Unexpected descriptor type: 0x%" PRIx64 " at ci=0x%x",
					((desc_data >> 1) & 0x7), ci);
				rc |= -EIO;
				break;
			}

			handle.is_read = true;
			handle.data = 0x0ULL;
			if (emdev->apinotif_cb != NULL)
				rd_err = emdev->apinotif_cb(epf_func, &handle,
							    emdev->apinotif_cb_args);

			etag = (desc_data >> 4) & 0x3ff;
			rc = emdev_lf_aq_ack_desc_enqueue(lf, handle.data, handle.be, etag,
							  epf_func, !!rd_err);
			if (rc) {
				ci = (ci - 1) & aq_qp->qmask;
				goto dbell_update;
			}
			ci = (ci + 1) & aq_qp->qmask;
			break;
		default:
			plt_err("Unknown descriptor type : 0x%x at ci 0x%x", dtype, ci);
			rc |= -EINVAL;
			ci = (ci + 1) & aq_qp->qmask;
			break;
		}
	}

dbell_update:
	plt_write64(ci, aq_qp->notify_q_ci_dbell);
	return rc;
}

static void
emdev_lf_apinotif_intr_enb_dis(struct psw_lf *lf, bool enb)
{
	if (enb)
		plt_write64(1, lf->rbase + PSW_LF_APINOTIF_INT_ENA_W1S);
	else
		plt_write64(1, lf->rbase + PSW_LF_APINOTIF_INT_ENA_W1C);
}

static void
emdev_lf_apinotif_irq(void *param)
{
	struct psw_lf *lf = (struct psw_lf *)param;
	uint64_t intr;

	intr = plt_read64(lf->rbase + PSW_LF_APINOTIF_INT);
	if (intr == 0)
		return;

	/* Clear interrupt */
	plt_write64(intr, lf->rbase + PSW_LF_APINOTIF_INT);

	emdev_lf_apinotif_process_desc(lf);
}

static int
emdev_lf_register_apinotif_irq(struct psw_lf *lf)
{
	struct emdev *emdev = lf->emdev;
	struct plt_pci_device *pci_dev = emdev->pci_dev;
	struct plt_intr_handle *handle;
	int rc, vec;

	if (lf->msixoff == MSIX_VECTOR_INVALID) {
		plt_err("Invalid PSWLF MSIX vector offset vector: 0x%x", lf->msixoff);
		return -EINVAL;
	}

	vec = lf->msixoff + PSW_LF_APINOTIF_INT_VEC;
	handle = pci_dev->intr_handle;

	/* Clear API notification interrupt */
	emdev_lf_apinotif_intr_enb_dis(lf, false);
	/* Register handler for API notification interrupt */
	rc = dev_irq_register(handle, emdev_lf_apinotif_irq, lf, vec);
	/* Enable API notification interrupt */
	emdev_lf_apinotif_intr_enb_dis(lf, true);

	return rc;
}

static int
emdev_lf_irqs_register(struct emdev *emdev)
{
	struct psw_lf *psw_lf;
	int rc, i;

	/* Register psw api notification interrupt  */
	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		rc = emdev_lf_register_apinotif_irq(psw_lf);
		if (rc) {
			plt_err("Error registering PSWLF APINOTIF irq for lf=%d, rc=%d", i, rc);
			break;
		}
	}

	return rc;
}

int
roc_emdev_irqs_register(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	return emdev_lf_irqs_register(emdev);
}

static void
emdev_lf_unregister_apinotif_irq(struct psw_lf *lf)
{
	struct plt_pci_device *pci_dev = lf->emdev->pci_dev;
	struct plt_intr_handle *handle;
	int vec;

	handle = pci_dev->intr_handle;

	vec = lf->msixoff + PSW_LF_APINOTIF_INT_VEC;
	emdev_lf_apinotif_intr_enb_dis(lf, false);
	dev_irq_unregister(handle, emdev_lf_apinotif_irq, lf, vec);
}

static void
emdev_lf_irqs_unregister(struct emdev *emdev)
{
	struct psw_lf *psw_lf;
	int i;

	for (i = 0; i < emdev->nb_psw_lfs; i++) {
		psw_lf = &emdev->psw_lfs[i];
		emdev_lf_unregister_apinotif_irq(psw_lf);
	}
}

void
roc_emdev_irqs_unregister(struct roc_emdev *roc_emdev)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);

	emdev_lf_irqs_unregister(emdev);
}
