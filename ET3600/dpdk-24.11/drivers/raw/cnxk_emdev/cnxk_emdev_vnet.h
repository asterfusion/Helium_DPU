/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#ifndef _CNXK_EMDEV_VIRTIO_NET_H_
#define _CNXK_EMDEV_VIRTIO_NET_H_

#include "cnxk_emdev.h"
#include "cnxk_emdev_dma.h"
#include "cnxk_emdev_virtio.h"
#include "roc_api.h"
#include "rte_pmd_cnxk_emdev.h"

#include "spec/virtio.h"
#include "spec/virtio_net.h"

#define VNET_DESC_ENTRY_SZ	   16UL
#define VNET_DESC_SZ(x)		   (WRAP_OFF(x) * VNET_DESC_ENTRY_SZ)
#define VNET_DESC_PTR_OFF(b, i, o) (uint64_t *)(((uintptr_t)b) + VNET_DESC_SZ(i) + (o))

typedef int (*cnxk_emdev_vnet_psw_dbl_fn_t)(void *queue, void *vnet_q, uint16_t index);
typedef int (*cnxk_emdev_vnet_dpi_compl_fn_t)(void *queue, void *vnet_q, uint16_t index);
typedef int (*cnxk_emdev_vnet_enq_fn_t)(void *queue, void *vnet_q, struct rte_mbuf **mbufs,
					uint16_t count);

extern cnxk_emdev_vnet_psw_dbl_fn_t cnxk_emdev_vnet_psw_dbl_fn[];
extern cnxk_emdev_vnet_dpi_compl_fn_t cnxk_emdev_vnet_dpi_compl_fn[];
extern cnxk_emdev_vnet_enq_fn_t cnxk_emdev_vnet_enq_fn[];

/* Emdev Vnet PSW doorbell Offloads */
#define EMDEV_VNET_PSW_DBL_OFFLOAD_NONE		 (0)
#define EMDEV_VNET_PSW_DBL_OFFLOAD_ENQ		 RTE_BIT64(0)
#define EMDEV_VNET_PSW_DBL_OFFLOAD_CTRL_DEQ	 RTE_BIT64(1)
#define EMDEV_VNET_PSW_DBL_OFFLOAD_DEQ		 RTE_BIT64(2)
#define EMDEV_VNET_PSW_DBL_OFFLOAD_DEQ_NOINORDER RTE_BIT64(3)
#define EMDEV_VNET_PSW_DBL_OFFLOAD_LAST		 RTE_BIT64(3)

#define DBL_ENQ_F	    EMDEV_VNET_PSW_DBL_OFFLOAD_ENQ
#define DBL_CTRL_F	    EMDEV_VNET_PSW_DBL_OFFLOAD_CTRL_DEQ
#define DBL_DEQ_F	    EMDEV_VNET_PSW_DBL_OFFLOAD_DEQ
#define DBL_DEQ_NOINORDER_F EMDEV_VNET_PSW_DBL_OFFLOAD_DEQ_NOINORDER

#define EMDEV_VNET_PSW_DBL_FASTPATH_MODES                                                          \
	D(none, EMDEV_VNET_PSW_DBL_OFFLOAD_NONE)                                                   \
	D(enq, DBL_ENQ_F)                                                                          \
	D(ctrl, DBL_CTRL_F)                                                                        \
	D(deq, DBL_DEQ_F)                                                                          \
	D(deq_noinorder, DBL_DEQ_F | DBL_DEQ_NOINORDER_F)

#define D(name, flags) int cnxk_emdev_vnet_psw_dbl_##name(void *q, void *vnet_q, uint16_t idx);

EMDEV_VNET_PSW_DBL_FASTPATH_MODES
#undef D

/* Emdev Vnet DPI Completion Offloads */
#define EMDEV_VNET_DPI_COMPL_OFFLOAD_NONE	   (0)
#define EMDEV_VNET_DPI_COMPL_OFFLOAD_ENQ	   RTE_BIT64(0)
#define EMDEV_VNET_DPI_COMPL_OFFLOAD_DEQ	   RTE_BIT64(1)
#define EMDEV_VNET_DPI_COMPL_OFFLOAD_DEQ_NOINORDER RTE_BIT64(2)
#define EMDEV_VNET_DPI_COMPL_OFFLOAD_LAST	   RTE_BIT64(2)

#define DPI_ENQ_F	    EMDEV_VNET_DPI_COMPL_OFFLOAD_ENQ
#define DPI_DEQ_F	    EMDEV_VNET_DPI_COMPL_OFFLOAD_DEQ
#define DPI_DEQ_NOINORDER_F EMDEV_VNET_DPI_COMPL_OFFLOAD_DEQ_NOINORDER

#define EMDEV_VNET_DPI_COMPL_FASTPATH_MODES                                                        \
	C(none, EMDEV_VNET_DPI_COMPL_OFFLOAD_NONE)                                                 \
	C(enq, DPI_ENQ_F)                                                                          \
	C(deq, DPI_DEQ_F)                                                                          \
	C(deq_noinorder, DPI_DEQ_F | DPI_DEQ_NOINORDER_F)

#define C(name, flags) int cnxk_emdev_vnet_dpi_compl_##name(void *q, void *vnet_q, uint16_t idx);

EMDEV_VNET_DPI_COMPL_FASTPATH_MODES
#undef C

/* Emdev Vnet Enqueue Offloads */
#define EMDEV_VNET_ENQ_OFFLOAD_NONE (0)
#define EMDEV_VNET_ENQ_OFFLOAD_CTRL RTE_BIT64(0)
#define EMDEV_VNET_ENQ_OFFLOAD_FF   RTE_BIT64(1)
#define EMDEV_VNET_ENQ_OFFLOAD_MSEG RTE_BIT64(2)
#define EMDEV_VNET_ENQ_OFFLOAD_LAST RTE_BIT64(2)

#define E_CTRL_F EMDEV_VNET_ENQ_OFFLOAD_CTRL
#define E_FF_F	 EMDEV_VNET_ENQ_OFFLOAD_FF
#define E_MSEG_F EMDEV_VNET_ENQ_OFFLOAD_MSEG

#define EMDEV_VNET_ENQ_FASTPATH_MODES                                                              \
	E(none, EMDEV_VNET_ENQ_OFFLOAD_NONE)                                                       \
	E(ctrl, E_CTRL_F)                                                                          \
	E(ff, E_FF_F)                                                                              \
	E(ctrl_ff, (E_CTRL_F | E_FF_F))                                                            \
	E(ff_mseg, (E_FF_F | E_MSEG_F))

#define E(name, flags)                                                                             \
	int cnxk_emdev_vnet_enq_##name(void *q, void *vnet_q, struct rte_mbuf **pkts, uint16_t num);

EMDEV_VNET_ENQ_FASTPATH_MODES
#undef E

struct cnxk_emdev_vnet_queue {
	uint16_t epf_func;
	uint16_t qid;
	uint16_t dbl_fn_id;
	uint16_t dpi_compl_fn_id;
	uint16_t enq_fn_id;
	uint16_t q_sz;
	uint8_t virtio_hdr_sz;
	uintptr_t sd_base;
	uint16_t pi_desc;
	uint16_t ci_desc;
	uint16_t ci;
	uint16_t buf_len;
	uint16_t data_off;
	uint16_t chan_flags;
	uint64_t aura_handle;
	struct rte_mempool *mp;

	/* Slow path */
	struct cnxk_emdev_virtio_pfvf *pfvf;
};

static __rte_always_inline void
cnxk_emdev_vnet_update_fn_ptrs(void)
{
	uint64_t i = 0;
	for (; i < (EMDEV_VNET_PSW_DBL_OFFLOAD_LAST << 1); i++)
		if (cnxk_emdev_vnet_psw_dbl_fn[i] == NULL)
			cnxk_emdev_vnet_psw_dbl_fn[i] = cnxk_emdev_vnet_psw_dbl_fn[0];

	for (i = 0; i < (EMDEV_VNET_DPI_COMPL_OFFLOAD_LAST << 1); i++)
		if (cnxk_emdev_vnet_dpi_compl_fn[i] == NULL)
			cnxk_emdev_vnet_dpi_compl_fn[i] = cnxk_emdev_vnet_dpi_compl_fn[0];

	for (i = 0; i < (EMDEV_VNET_ENQ_OFFLOAD_LAST << 1); i++)
		if (cnxk_emdev_vnet_enq_fn[i] == NULL)
			cnxk_emdev_vnet_enq_fn[i] = cnxk_emdev_vnet_enq_fn[0];
}

static __rte_always_inline uint16_t
emdev_dbl_desc_process(struct cnxk_emdev_queue *queue)
{
	struct cnxk_emdev_psw_q *nq = &queue->nq;
	struct cnxk_emdev_vnet_queue *vnet_q;
	void *q_base = nq->q_base;
	uintptr_t ci_dbl = nq->ci_dbl;
	uintptr_t pi_dbl = nq->pi_dbl;
	uint64_t desc_data, index;
	uint16_t q_sz = nq->q_sz;
	uint16_t pi, ci, rid;
	uint8_t vf;

	pi = plt_read64(pi_dbl);
	ci = nq->ci;

	if (DESC_DIFF(pi, ci, q_sz) == 0)
		return 0;

	while (ci != pi) {
#ifdef CNXK_EMDEV_DEBUG
		roc_emdev_psw_nq_desc_dump(NULL, NQ_DESC_PTR_OFF(q_base, ci, 0));
		uint8_t dtype;
		desc_data = *NQ_DESC_PTR_OFF(q_base, ci, 0);
		dtype = (desc_data >> 1) & 0x7;
		if (dtype != PSW_NOTIF_DESC_TYPE_PI_DBL) {
			plt_err("Invalid Descriptor found");
			return 0;
		}
#endif
		desc_data = *NQ_DESC_PTR_OFF(q_base, ci, 0);
		vf = (desc_data >> 16) & 0xff;
		rid = (desc_data >> 8) & 0xff;
		/* Include phase bit as BIT 15 in index */
		index = ((desc_data >> 32) & 0xffff);
		vnet_q = queue->vnet_q_base[vf] ? queue->vnet_q_base[vf] + rid : NULL;
		/* Jump to queue specific callback for processing dbell.
		 * Stall processing if the descriptor is not consumed
		 */
#ifdef CNXK_EMDEV_DEBUG
		plt_info("Processing VNET DBL VF %d RID %d to dbl %u", vf, rid, vnet_q->dbl_fn_id);
#endif
		if ((*cnxk_emdev_vnet_psw_dbl_fn[vnet_q->dbl_fn_id])(queue, vnet_q, index))
			break;

		ci = DESC_ADD(ci, 1, q_sz);
	}

	nq->ci = ci;

	/* update CI doorbell */
	ci &= (q_sz - 1);
	plt_write64(ci, ci_dbl);
	return 0;
}

static __rte_always_inline uint16_t
emdev_dpi_compl_process(struct cnxk_emdev_queue *queue, struct cnxk_emdev_dpi_q *dpi_q)
{
	uint64_t *compl_base = dpi_q->compl_base;
	uint64_t *widx_r = dpi_q->widx_r;
	struct cnxk_emdev_vnet_queue *vnet_q;
	uint16_t widx, compl_idx;
	uint64_t *compl_ptr;
	uint8_t cs, fn_id;

	widx = plt_read64(widx_r) & 0xFFF;
	compl_idx = dpi_q->compl_idx;
	while (compl_idx != widx) {
		/* Process the completion */
		compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, compl_idx);

		cs = __atomic_load_n((uint8_t *)compl_ptr, __ATOMIC_ACQUIRE);
		if (cs == 0xFF)
			break;

		vnet_q = (struct cnxk_emdev_vnet_queue *)compl_ptr[1];
		if (vnet_q) {
			fn_id = vnet_q->dpi_compl_fn_id;
			/* Jump to queue specific callback for processing completion
			 * Donot continue if the completion is not consumed.
			 */
			if ((*cnxk_emdev_vnet_dpi_compl_fn[fn_id])(queue, vnet_q, compl_idx))
				break;
		}
		compl_idx = cnxk_emdev_dma_next_idx(compl_idx);
	}
	dpi_q->compl_idx = compl_idx;
	return 0;
}

int cnxk_emdev_vnet_init(struct cnxk_emdev_virtio_pfvf *pfvf, struct rte_pmd_cnxk_vnet_conf *conf);
int cnxk_emdev_vnet_enqueue(struct rte_rawdev *rawdev, struct rte_rawdev_buf **bufs, uint32_t count,
			    rte_rawdev_obj_t ctx);
int cnxk_emdev_vnet_dequeue(struct rte_rawdev *rawdev, struct rte_rawdev_buf **bufs, uint32_t count,
			    rte_rawdev_obj_t ctx);

/* Process functions */
int cnxk_emdev_vnet_enq_psw_dbl(struct cnxk_emdev_queue *queue,
				struct cnxk_emdev_vnet_queue *vnet_q, uint16_t index,
				const uint16_t flags);
int cnxk_emdev_vnet_enq_dpi_compl(struct cnxk_emdev_queue *queue,
				  struct cnxk_emdev_vnet_queue *vnet_q, uint16_t index,
				  const uint16_t flags);
int cnxk_emdev_vnet_enq(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
			struct rte_mbuf **mbufs, uint16_t count);

int cnxk_emdev_vnet_deq_psw_dbl(struct cnxk_emdev_queue *queue,
				struct cnxk_emdev_vnet_queue *vnet_q, uint16_t index,
				const uint16_t flags);
int cnxk_emdev_vnet_deq_dpi_compl(struct cnxk_emdev_queue *queue,
				  struct cnxk_emdev_vnet_queue *vnet_q, uint16_t index,
				  const uint16_t flags);

int cnxk_emdev_vnet_ctrl_deq_psw_dbl(struct cnxk_emdev_queue *queue,
				     struct cnxk_emdev_vnet_queue *vnet_q, uint16_t index,
				     const uint16_t flags);
int cnxk_emdev_vnet_ctrl_enq(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
			     struct rte_mbuf **mbufs, uint16_t count);

#endif /* _CNXK_EMDEV_VIRTIO_NET_H_ */
