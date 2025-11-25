/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

#define emdev_dump(file, fmt, ...)                                                                 \
	do {                                                                                       \
		if ((file) == NULL)                                                                \
			plt_dump(fmt, ##__VA_ARGS__);                                              \
		else                                                                               \
			fprintf(file, fmt "\n", ##__VA_ARGS__);                                    \
	} while (0)

int
roc_emdev_psw_anq_desc_dump(FILE *file, void *desc)
{
	uint64_t dtype = (*(uint64_t *)desc >> 1) & 0x7;
	struct psw_notif_write_read_desc_s *wr_rd;
	struct psw_notif_data_desc_s *data;
	struct psw_notif_tag_desc_s *tag;

	emdev_dump(file, "ANQ desc_addr: 0x%" PRIx64, PLT_U64_CAST((uint64_t)desc));
	wr_rd = (struct psw_notif_write_read_desc_s *)desc;
	switch (dtype) {
	case PSW_NOTIF_DESC_TYPE_WRITE:
		data = (struct psw_notif_data_desc_s *)((uintptr_t)desc + 8);
		emdev_dump(file, "\tWR W0: dtype 0x%x epffunc 0x%x", wr_rd->dtype, wr_rd->epffunc);
		emdev_dump(file, "\tWR W0: addr 0x%x data[3:0] 0x%x", wr_rd->addr, wr_rd->data);
		emdev_dump(file, "\tWR W0: be 0x%x phase 0x%x", wr_rd->be, wr_rd->phase);
		emdev_dump(file, "\tWR W1: data[63:4] 0x%" PRIx64 "(%" PRIx64 ")",
			   PLT_U64_CAST(data->data), PLT_U64_CAST(data->data << 4 | wr_rd->data));
		emdev_dump(file, "\tWR W1: dtype 0x%x phase 0x%x", data->dtype, data->phase);
		break;
	case PSW_NOTIF_DESC_TYPE_READ:
		tag = (struct psw_notif_tag_desc_s *)((uintptr_t)desc + 8);
		emdev_dump(file, "\tRD W0: dtype 0x%x epffunc 0x%x", wr_rd->dtype, wr_rd->epffunc);
		emdev_dump(file, "\tRD W0: addr 0x%x data[3:0] 0x%x", wr_rd->addr, wr_rd->data);
		emdev_dump(file, "\tRD W0: be 0x%x phase 0x%x", wr_rd->be, wr_rd->phase);
		emdev_dump(file, "\tRD W1: etag 0x%x", tag->etag);
		emdev_dump(file, "\tRD W1: dtype 0x%x phase 0x%x", tag->dtype, tag->phase);
		break;
	default:
		emdev_dump(file, "\tUnknown descriptor type 0x%" PRIx64, dtype);
		emdev_dump(file, "\tW0: 0x%" PRIx64, *(uint64_t *)desc);
		break;
	};
	return 0;
}

int
roc_emdev_psw_nq_desc_dump(FILE *file, void *desc)
{
	uint64_t dtype = (*(uint64_t *)desc >> 1) & 0x7;
	struct psw_notif_doorbell_desc_s *dbl_desc;

	emdev_dump(file, "NQ desc_addr: 0x%" PRIx64, PLT_U64_CAST((uint64_t)desc));
	dbl_desc = (struct psw_notif_doorbell_desc_s *)desc;
	switch (dtype) {
	case PSW_NOTIF_DESC_TYPE_PI_DBL:
		emdev_dump(file, "\tPIDBL dtype 0x%x epffunc 0x%x", dbl_desc->dtype,
			   dbl_desc->epffunc);
		emdev_dump(file, "\tPIDBL phase 0x%x hoqid 0x%x", dbl_desc->phase, dbl_desc->hoqid);
		emdev_dump(file, "\tPIDBL index 0x%x", dbl_desc->index);
		break;
	default:
		emdev_dump(file, "\tDBL: Unknown descriptor type 0x%" PRIx64, dtype);
		emdev_dump(file, "\tDBL: 0x%" PRIx64, *(uint64_t *)desc);
		break;
	};
	return 0;
}

int
roc_emdev_psw_aq_qp_dump(struct roc_emdev_psw_aq_qp *aq, FILE *file)
{
	struct roc_emdev *roc_emdev = aq->roc_emdev;
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	union psw_apinotif_queue_config_u apinotif_q_cfg;
	union psw_apiack_queue_config_u apiack_q_cfg;
	union psw_queue_config_u q_cfg_base;
	struct psw_lf *psw_lf;
	uintptr_t rbase;

	psw_lf = &emdev->psw_lfs[aq->qid];
	rbase = psw_lf->rbase;
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&apinotif_q_cfg, 0, sizeof(apinotif_q_cfg));
	memset(&apiack_q_cfg, 0, sizeof(apiack_q_cfg));

	/* Read API NQ Q config */
	q_cfg_base.u[0] = plt_read64(rbase + PSW_LF_ANQCX(0));
	q_cfg_base.u[1] = plt_read64(rbase + PSW_LF_ANQCX(1));
	q_cfg_base.u[2] = plt_read64(rbase + PSW_LF_ANQCX(2));
	q_cfg_base.u[3] = plt_read64(rbase + PSW_LF_ANQCX(3));
	apinotif_q_cfg.u[0] = plt_read64(rbase + PSW_LF_ANQCX(4));
	apinotif_q_cfg.u[1] = plt_read64(rbase + PSW_LF_ANQCX(5));
	apinotif_q_cfg.u[2] = plt_read64(rbase + PSW_LF_ANQCX(6));
	apinotif_q_cfg.u[3] = plt_read64(rbase + PSW_LF_ANQCX(7));

	emdev_dump(file, "API NQ Q%u: 0x%" PRIx64, aq->qid, PLT_U64_CAST((uint64_t)aq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW7: qerror 0x%x apifulldrop 0x%x idle 0x%x ii 0x%x",
		   apinotif_q_cfg.s.qerror, apinotif_q_cfg.s.apifulldrop, apinotif_q_cfg.s.idle,
		   apinotif_q_cfg.s.ii);

	/* Read API ACK Q config */
	q_cfg_base.u[0] = plt_read64(rbase + PSW_LF_AAQCX(0));
	q_cfg_base.u[1] = plt_read64(rbase + PSW_LF_AAQCX(1));
	q_cfg_base.u[2] = plt_read64(rbase + PSW_LF_AAQCX(2));
	q_cfg_base.u[3] = plt_read64(rbase + PSW_LF_AAQCX(3));
	apiack_q_cfg.u[0] = plt_read64(rbase + PSW_LF_AAQCX(4));
	apiack_q_cfg.u[1] = plt_read64(rbase + PSW_LF_AAQCX(5));
	apiack_q_cfg.u[2] = plt_read64(rbase + PSW_LF_AAQCX(6));
	apiack_q_cfg.u[3] = plt_read64(rbase + PSW_LF_AAQCX(7));

	emdev_dump(file, "API ACK Q%u: 0x%" PRIx64, aq->qid, PLT_U64_CAST((uint64_t)aq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", apiack_q_cfg.s.qerror,
		   apiack_q_cfg.s.idle, apiack_q_cfg.s.ii);
	return 0;
}

int
roc_emdev_psw_nq_qp_dump(struct roc_emdev_psw_nq_qp *nq, FILE *file)
{
	struct roc_emdev *roc_emdev = nq->roc_emdev;
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	union psw_notif_queue_config_u notif_q_cfg;
	union psw_ack_queue_config_u ack_q_cfg;
	union psw_queue_config_u q_cfg_base;
	uint16_t nq_qid = nq->qid % 8;
	uint16_t nq_lf = nq->qid / 8;
	struct psw_lf *psw_lf;
	uintptr_t rbase;

	psw_lf = &emdev->psw_lfs[nq_lf];
	rbase = psw_lf->rbase;
	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&notif_q_cfg, 0, sizeof(notif_q_cfg));
	memset(&ack_q_cfg, 0, sizeof(ack_q_cfg));

	/* Read NQ Q config */
	q_cfg_base.u[0] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 0));
	q_cfg_base.u[1] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 1));
	q_cfg_base.u[2] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 2));
	q_cfg_base.u[3] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 3));
	notif_q_cfg.u[0] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 4));
	notif_q_cfg.u[1] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 5));
	notif_q_cfg.u[2] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 6));
	notif_q_cfg.u[3] = plt_read64(rbase + PSW_LF_NX_QCX(nq_qid, 7));

	emdev_dump(file, "NQ Q%u: 0x%" PRIx64, nq_qid, PLT_U64_CAST((uint64_t)nq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround %" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", notif_q_cfg.s.qerror,
		   notif_q_cfg.s.idle, notif_q_cfg.s.ii);

	/* Read ACK Q config */
	q_cfg_base.u[0] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 0));
	q_cfg_base.u[1] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 1));
	q_cfg_base.u[2] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 2));
	q_cfg_base.u[3] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 3));
	ack_q_cfg.u[0] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 4));
	ack_q_cfg.u[1] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 5));
	ack_q_cfg.u[2] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 6));
	ack_q_cfg.u[3] = plt_read64(rbase + PSW_LF_AX_QCX(nq_qid, 7));

	emdev_dump(file, "ACK Q%u: 0x%" PRIx64, nq_qid, PLT_U64_CAST((uint64_t)nq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);

	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", ack_q_cfg.s.qerror,
		   ack_q_cfg.s.idle, ack_q_cfg.s.ii);

	return 0;
}

int
roc_emdev_psw_inb_q_dump(struct roc_emdev_psw_inb_q *inbq, FILE *file)
{
	struct roc_emdev *roc_emdev = inbq->roc_emdev;
	struct emdev *emdev = roc_emdev_to_emdev_priv(roc_emdev);
	union psw_hib_queue_config_u hib_q_cfg;
	union psw_shib_queue_config_u shib_q_cfg;
	union psw_queue_config_u q_cfg_base;
	struct emdev_epfvf *epfvf;
	struct psw_lf *psw_lf;
	uint16_t evf_id;
	uintptr_t rbase;
	uint64_t wdata;

	/* Check if EVF id is within range of EPF/VFs attached */
	evf_id = inbq->evf_id;
	if (evf_id > emdev->nb_epfvfs)
		return -EINVAL;

	epfvf = &emdev->epfvfs[evf_id];
	psw_lf = &emdev->psw_lfs[0];
	rbase = psw_lf->rbase;
	wdata = epfvf->epf_func | inbq->qid << 16;

	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&hib_q_cfg, 0, sizeof(hib_q_cfg));
	memset(&shib_q_cfg, 0, sizeof(shib_q_cfg));

	/* Read SHIB Q config */
	q_cfg_base.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(0)));
	q_cfg_base.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(1)));
	q_cfg_base.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(2)));
	q_cfg_base.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(3)));
	shib_q_cfg.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(4)));
	shib_q_cfg.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(5)));
	shib_q_cfg.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(6)));
	shib_q_cfg.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHIQCX(7)));

	emdev_dump(file, "Shadow INB Q%u: 0x%" PRIx64, inbq->qid, PLT_U64_CAST((uint64_t)inbq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", shib_q_cfg.s.qerror,
		   shib_q_cfg.s.idle, shib_q_cfg.s.ii);

	/* Read HIB Q config */
	q_cfg_base.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(0)));
	q_cfg_base.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(1)));
	q_cfg_base.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(2)));
	q_cfg_base.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(3)));
	hib_q_cfg.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(4)));
	hib_q_cfg.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(5)));
	hib_q_cfg.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(6)));
	hib_q_cfg.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HIQCX(7)));

	emdev_dump(file, "HIB Q%u: 0x%" PRIx64, inbq->qid, PLT_U64_CAST((uint64_t)inbq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW4: pcie_attr 0x%" PRIx64, hib_q_cfg.s.pcie_attr);
	emdev_dump(file, "\tW5: cimode 0x%x log2bs 0x%x inplace 0x%x", hib_q_cfg.s.cimode,
		   hib_q_cfg.s.log2bs, hib_q_cfg.s.inplace);
	emdev_dump(file, "\tW5: msg_type 0x%x msix_vec_num 0x%x", hib_q_cfg.s.msg_type,
		   hib_q_cfg.s.msix_vec_num);
	emdev_dump(file, "\tW6: pi_addr 0x%" PRIx64, hib_q_cfg.s.pi_addr);
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", hib_q_cfg.s.qerror,
		   hib_q_cfg.s.idle, hib_q_cfg.s.ii);

	return 0;
}

int
roc_emdev_psw_outb_q_dump(struct roc_emdev_psw_outb_q *outbq, FILE *file)
{
	struct emdev *emdev = roc_emdev_to_emdev_priv(outbq->roc_emdev);
	union psw_hob_queue_config_u hob_q_cfg;
	union psw_shob_queue_config_u shob_q_cfg;
	union psw_queue_config_u q_cfg_base;
	struct emdev_epfvf *epfvf;
	struct psw_lf *psw_lf;
	uintptr_t rbase;
	uint16_t evf_id;
	uint64_t wdata;

	/* Check if EVF id is within range of EPF/VFs attached */
	evf_id = outbq->evf_id;
	if (evf_id > emdev->nb_epfvfs)
		return -EINVAL;

	epfvf = &emdev->epfvfs[evf_id];
	psw_lf = &emdev->psw_lfs[0];
	rbase = psw_lf->rbase;
	wdata = epfvf->epf_func | outbq->qid << 16;

	memset(&q_cfg_base, 0, sizeof(q_cfg_base));
	memset(&hob_q_cfg, 0, sizeof(hob_q_cfg));
	memset(&shob_q_cfg, 0, sizeof(shob_q_cfg));

	/* Read SHOB Q config */
	q_cfg_base.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(0)));
	q_cfg_base.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(1)));
	q_cfg_base.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(2)));
	q_cfg_base.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(3)));
	shob_q_cfg.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(4)));
	shob_q_cfg.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(5)));
	shob_q_cfg.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(6)));
	shob_q_cfg.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_SHOQCX(7)));

	emdev_dump(file, "Shadow OUTB Q%u: 0x%" PRIx64, outbq->qid, PLT_U64_CAST((uint64_t)outbq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW5: ci_msg_en 0x%x ci_addr 0x%" PRIx64, shob_q_cfg.s.ci_msg_en,
		   PLT_U64_CAST(shob_q_cfg.s.ci_addr));
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", shob_q_cfg.s.qerror,
		   shob_q_cfg.s.idle, shob_q_cfg.s.ii);

	/* Read HOB Q config */
	q_cfg_base.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(0)));
	q_cfg_base.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(1)));
	q_cfg_base.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(2)));
	q_cfg_base.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(3)));
	hob_q_cfg.u[0] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(4)));
	hob_q_cfg.u[1] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(5)));
	hob_q_cfg.u[2] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(6)));
	hob_q_cfg.u[3] = roc_atomic64_add_nosync(wdata, PLT_PTR_CAST(rbase + PSW_LF_OP_HOQCX(7)));

	emdev_dump(file, "HOB Q%u: 0x%" PRIx64, outbq->qid, PLT_U64_CAST((uint64_t)outbq));
	emdev_dump(file, "\tW0: enable 0x%x log2ds 0x%x log2qs 0x%x", q_cfg_base.s.enable,
		   q_cfg_base.s.log2ds, q_cfg_base.s.log2qs);
	emdev_dump(file, "\tW1: base_addr 0x%" PRIx64, PLT_U64_CAST(q_cfg_base.s.base_addr));
	emdev_dump(file, "\tW2: pi 0x%x pround 0x%" PRIx64, q_cfg_base.s.pi,
		   PLT_U64_CAST(q_cfg_base.s.pround));
	emdev_dump(file, "\tW3: ci 0x%x", q_cfg_base.s.ci);
	emdev_dump(file, "\tW4: pcie_attr 0x%" PRIx64, hob_q_cfg.s.pcie_attr);
	emdev_dump(file, "\tW5: notif_qnum 0x%x log2bs 0x%x inplace 0x%x", hob_q_cfg.s.notif_qnum,
		   hob_q_cfg.s.log2bs, hob_q_cfg.s.inplace);
	emdev_dump(file, "\tW5: anp_qos 0x%x incr_pi 0x%x", hob_q_cfg.s.anp_qos,
		   hob_q_cfg.s.incr_pi);
	emdev_dump(file, "\tW7: qerror 0x%x idle 0x%x ii 0x%x", hob_q_cfg.s.qerror,
		   hob_q_cfg.s.idle, hob_q_cfg.s.ii);
	return 0;
}
