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

#include <roc_api.h>

#include "cnxk_emdev_dma.h"
#include "cnxk_emdev_vnet.h"

cnxk_emdev_vnet_enq_fn_t cnxk_emdev_vnet_enq_fn[EMDEV_VNET_ENQ_OFFLOAD_LAST << 1] = {
#define E(name, flags) [flags] = cnxk_emdev_vnet_enq_##name,
	EMDEV_VNET_ENQ_FASTPATH_MODES
#undef E
};

static __rte_always_inline uint32_t
calculate_nb_enq(uintptr_t sd_base, uint16_t off, uint32_t slen, uint16_t q_sz, uint16_t avail_sd)
{
	uint16_t nb_enq = 0;
	uint32_t dlen = 0;
	uint64_t d_flags;

	while (dlen < slen && avail_sd) {
		d_flags = *VNET_DESC_PTR_OFF(sd_base, off, 8);
		dlen += d_flags & (RTE_BIT64(32) - 1);
		off = DESC_ADD(off, 1, q_sz);
		nb_enq += 1;
		avail_sd--;
	}
	return dlen >= slen ? nb_enq : UINT16_MAX;
}

static __rte_always_inline uint16_t
process_mseg_pkts_enq(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
		      struct rte_mbuf *mbuf, uint16_t *ci_desc, uint16_t *qdma_idx)
{
	uint32_t dlens[DPI_DMA_64B_MAX_NLST], slen, xlen = 0, buf_len;
	struct cnxk_emdev_dpi_q *outb_q = &queue->dpi_q_outb;
	uintptr_t dsts[DPI_DMA_64B_MAX_NLST], src;
	uint64_t *compl_base = outb_q->compl_base;
	uint16_t hdr_sz = vnet_q->virtio_hdr_sz;
	uint64_t *dma_base = outb_q->inst_base;
	uint32_t pend_dlen = 0, pend, pkt_len;
	uintptr_t sd_base = vnet_q->sd_base;
	uint64_t *dma_ptr, *compl_ptr;
	uint16_t q_sz = vnet_q->q_sz;
	uint16_t dma_idx = *qdma_idx;
	struct rte_mbuf *m_next;
	uint64_t d_flags, avail;
	uint8_t num, d_idx = 0;
	uint16_t off = *ci_desc;
	uint64_t mdata, aura;
	uint16_t dma_cnt = 0;
	uintptr_t hdr;

	aura = roc_npa_aura_handle_to_aura(mbuf->pool->pool_id) << 32;
	pkt_len = mbuf->pkt_len + hdr_sz;

	/* Src:Dest 1:N per DMA instructions */
	do {
		hdr = rte_pktmbuf_mtod_offset(mbuf, uintptr_t, -hdr_sz);
		src = (uintptr_t)hdr;
		slen = mbuf->data_len + hdr_sz;
		m_next = mbuf->next;
		mbuf->nb_segs = 1;
		mbuf->next = NULL;
		mbuf = m_next;
		hdr_sz = 0;

		dma_ptr = cnxk_emdev_dma_inst_addr(dma_base, dma_idx);
		compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, dma_idx);
		mdata = vnet_q->chan_flags | aura;

		pend = slen > pend_dlen ? slen - pend_dlen : 0;
		if (unlikely(!pend)) {
			/* Continue with previous descriptor space */
			dlens[d_idx - 1] = slen;
			goto submit;
		}

again:
		d_flags = *VNET_DESC_PTR_OFF(sd_base, off, 8);
		buf_len = d_flags & (RTE_BIT64(32) - 1);

		d_flags = d_flags & 0xFFFFFFFF00000000UL;
		avail = !!(d_flags & VIRT_PACKED_RING_DESC_F_AVAIL);
		d_flags &= ~VIRT_PACKED_RING_DESC_F_AVAIL_USED;

		xlen = RTE_MIN(pend, buf_len);
		pend = pend - xlen;

		dsts[d_idx] = *VNET_DESC_PTR_OFF(sd_base, off, 0);
		dlens[d_idx++] = xlen;
		pend_dlen = buf_len;

		xlen = RTE_MIN(buf_len, pkt_len);
		pkt_len -= xlen;

		/* Set both AVAIL and USED bit same and fillup length in Tx desc */
		*VNET_DESC_PTR_OFF(sd_base, off, 8) =
			avail << 55 | avail << 63 | d_flags | (xlen & (RTE_BIT64(32) - 1));

		off = DESC_ADD(off, 1, q_sz);

		if (unlikely(pend)) {
			if (d_idx == DPI_DMA_64B_MAX_NLST) {
				num = (d_idx << 4) | 1;
				xlen = slen - pend;
				cnxk_emdev_dma_enq_xn(dma_ptr, compl_ptr, mdata, &src, dsts, num,
						      &xlen, dlens);
				compl_ptr[1] = 0;
				dma_idx = cnxk_emdev_dma_next_idx(dma_idx);
				dma_ptr = cnxk_emdev_dma_inst_addr(dma_base, dma_idx);
				compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, dma_idx);

				dma_cnt++;
				src += xlen;
				slen -= xlen;
				d_idx = 0;
			}
			goto again;
		}

submit:
		num = (d_idx << 4) | 1;
		mdata |= (1 << 13); /* set FP_L, to be free from HW */
		cnxk_emdev_dma_enq_xn(dma_ptr, compl_ptr, mdata, &src, dsts, num, &slen, dlens);
		compl_ptr[1] = 0;
		dma_idx = cnxk_emdev_dma_next_idx(dma_idx);
		dma_cnt++;

		/* Space left in previous descriptor ? */
		xlen = dlens[d_idx - 1];
		pend_dlen -= xlen;
		dsts[0] = pend_dlen > 0 ? dsts[d_idx - 1] + xlen : 0;
		dlens[0] = pend_dlen > 0 ? pend_dlen : 0;
		d_idx = !!pend_dlen;

	} while (mbuf);

	*ci_desc = off;
	*qdma_idx = dma_idx;
	return dma_cnt;
}

static __rte_always_inline int
emdev_vnet_ctrl_enq(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
		    struct rte_mbuf **mbufs, uint16_t count, const uint16_t flags)
{
	struct cnxk_emdev_dpi_q *outb_q = &queue->dpi_q_outb;
	uint64_t *compl_base = outb_q->compl_base, *compl_ptr;
	uint64_t *dma_base = outb_q->inst_base, *dma_ptr;
	struct cnxk_emdev_psw_q *aq = &queue->aq;
	struct rte_pmd_cnxk_emdev_event *event;
	uintptr_t sd_base = vnet_q->sd_base;
	uint16_t ci_end, avail, dma_idx;
	uint16_t q_sz = vnet_q->q_sz;
	uint64_t val, ack_desc;
	uint16_t a_pi, a_ci;
	uint16_t tmo_ms;
	uint64_t mdata;

	PLT_SET_USED(flags);

	/* Doesn't support enqueue of multiple event completions */
	if (count > 1)
		return -ENOTSUP;

	/* DMA avail check */
	avail = cnxk_emdev_dma_avail(outb_q, &dma_idx);
	if (avail < 1)
		return -ENOSPC;

	event = rte_pktmbuf_mtod(mbufs[0], struct rte_pmd_cnxk_emdev_event *);
	ci_end = event->ci_end;
	ci_end = wrap_off_m1(ci_end, q_sz);

	/* DMA status to last descriptor */
	dma_ptr = cnxk_emdev_dma_inst_addr(dma_base, dma_idx);
	compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, dma_idx);
	mdata = (1 << 13) | roc_npa_aura_handle_to_aura(mbufs[0]->pool->pool_id) << 32;

	/* Submit a DMA instruction */
	cnxk_emdev_dma_enq_x1(dma_ptr, compl_ptr, mdata, (uintptr_t)&event->status,
			      *VNET_DESC_PTR_OFF(sd_base, ci_end, 0), 1);

	/* Trigger DMA */
	plt_io_wmb();
	plt_write64(1, outb_q->widx_r);

	/* Wait for DMA completion */
	tmo_ms = CNXK_EMDEV_DMA_TMO_MS;
	do {
		rte_delay_us_sleep(1000);
		__atomic_load(&compl_ptr[0], &val, __ATOMIC_ACQUIRE);
		tmo_ms--;
		if (!tmo_ms) {
			plt_err("[dev 0x%x] ctrl enq DMA timeout", vnet_q->epf_func);
			return -EFAULT;
		}
	} while (val == 0xFF);

	a_pi = plt_read64((uint64_t *)aq->pi_dbl);
	a_ci = plt_read64((uint64_t *)aq->ci_dbl);

	/* Check if Ack queue is full */
	if (((a_pi + 1) & (aq->q_sz - 1)) == a_ci)
		return -ENOSPC;

	/* Prepare PSW_ACK_DOORBELL_DESC_S */
	ack_desc = (uint64_t)event->ci_end << 32;
	ack_desc |= (uint64_t)vnet_q->qid << 8;
	ack_desc |= (uint64_t)vnet_q->epf_func << 16;
	ack_desc |= (uint64_t)wrap_off_diff(event->ci_end, event->ci_start, vnet_q->q_sz) << 48;

	/* Add instruction to ack queue to trigger descriptor store */
	*AQ_DESC_PTR_OFF(aq->q_base, a_pi, 0) = ack_desc;
	a_pi = DESC_ADD(a_pi, 1, aq->q_sz);
	plt_io_wmb();
	plt_write64(a_pi, aq->pi_dbl);

	vnet_q->ci = event->ci_end;
	return count;
}

static __rte_always_inline uint16_t
emdev_vnet_enq(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
	       struct rte_mbuf **mbufs, uint16_t count, const uint16_t flags)
{
	struct cnxk_emdev_dpi_q *outb_q = &queue->dpi_q_outb;
	uint64_t *compl_base = outb_q->compl_base;
	uint64_t *dma_base = outb_q->inst_base;
	uint16_t hdr_sz = vnet_q->virtio_hdr_sz;
	uintptr_t sd_base = vnet_q->sd_base;
	uint16_t pi_desc, nb_desc, i;
	uint64_t *dma_ptr, *compl_ptr;
	uint16_t q_sz = vnet_q->q_sz;
	uint16_t dma_avail, ci_desc;
	uint16_t dma_idx, ci_start;
	struct virtio_net_hdr *hdr;
	uint16_t avail_sd, nb_enq;
	uint64_t d_flags, avail;
	uint32_t buf_len, len;
	uint16_t dma_cnt = 0;
	uint64_t mdata = 0; /* set ZBW_CA */
	uint64_t *mbuf0;

	PLT_SET_USED(flags);

	/* Check space in DPI ring and skip consuming the desc if DPI queue is full */
	dma_avail = cnxk_emdev_dma_avail(outb_q, &dma_idx);
	if (!dma_avail)
		return 0;

	/* Break if there is no descriptor avail */
	pi_desc = vnet_q->pi_desc;
	ci_desc = vnet_q->ci_desc;
	nb_desc = wrap_off_diff(pi_desc, ci_desc, q_sz);
	if (!nb_desc)
		return 0;

	/* Limit the count to available descriptors and available DMA instructions */
	avail_sd = RTE_MIN(nb_desc, dma_avail << 1);
	count = RTE_MIN(count, avail_sd);
	/* Process the mbufs */
	i = 0;

	/* Assuming all mbufs for this queue are from same pool */
	mdata = vnet_q->chan_flags;
	mdata |= (1 << 13) | roc_npa_aura_handle_to_aura(mbufs[0]->pool->pool_id) << 32;
	dma_ptr = cnxk_emdev_dma_inst_addr(dma_base, dma_idx);
	compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, dma_idx);

	ci_start = ci_desc;
	while (i < count) {
		mbuf0 = (uint64_t *)mbufs[i];

		dma_ptr = cnxk_emdev_dma_inst_addr(dma_base, dma_idx);
		compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, dma_idx);

		/* Add Virtio header */
		hdr = rte_pktmbuf_mtod_offset((struct rte_mbuf *)mbuf0, struct virtio_net_hdr *,
					      -(hdr_sz));
		hdr->flags = 0;
		hdr->gso_type = 0;
		hdr->gso_size = 0;
		hdr->csum_start = 0;
		hdr->csum_offset = 0;
		hdr->flags = 0;

		d_flags = *VNET_DESC_PTR_OFF(sd_base, ci_desc, 8);
		buf_len = d_flags & (RTE_BIT64(32) - 1);
		len = ((struct rte_mbuf *)mbuf0)->pkt_len + hdr_sz;

		if ((flags & EMDEV_VNET_ENQ_OFFLOAD_MSEG) &&
		    ((((struct rte_mbuf *)mbuf0)->nb_segs > 1) || (buf_len < len))) {
			nb_enq = 1;

			if (unlikely(buf_len < len)) {
				nb_enq = calculate_nb_enq(sd_base, ci_desc, len, q_sz, avail_sd);

				/* Check for available descriptors and mbuf space */
				if (nb_enq == UINT16_MAX)
					goto exit;
			}

			hdr->num_buffers = nb_enq;
			avail_sd -= nb_enq;
			dma_cnt += process_mseg_pkts_enq(queue, vnet_q, (struct rte_mbuf *)mbuf0,
							 &ci_desc, &dma_idx);
		} else {
			hdr->num_buffers = 1;
			d_flags = d_flags & 0xFFFFFFFF00000000UL;

			/* Limit length to buf len */
			len = len > buf_len ? buf_len : len;

			avail = !!(d_flags & VIRT_PACKED_RING_DESC_F_AVAIL);
			d_flags &= ~VIRT_PACKED_RING_DESC_F_AVAIL_USED;

			/* Set both AVAIL and USED bit same and fillup length in Tx desc */
			*VNET_DESC_PTR_OFF(sd_base, ci_desc, 8) =
				avail << 55 | avail << 63 | d_flags | (len & (RTE_BIT64(32) - 1));

			/* Prepare DMA src/dst of mbuf transfer */
			cnxk_emdev_dma_enq_x1(dma_ptr, compl_ptr, mdata, (uintptr_t)hdr,
					      *VNET_DESC_PTR_OFF(sd_base, ci_desc, 0), len);
			ci_desc = wrap_off_add(ci_desc, 1, q_sz);
			compl_ptr[1] = 0;
			dma_idx = cnxk_emdev_dma_next_idx(dma_idx);
			dma_cnt++;
		}

#ifdef RTE_LIBRTE_MEMPOOL_DEBUG
		/* When fast free is enabled, all the buffers would be freed by DPI to NPA
		 * Mark them as put since SW didnot not be freeing them.
		 */
		RTE_MEMPOOL_CHECK_COOKIES(mbufs[i]->pool, (void **)&mbufs[i], 1, 0);
#endif
		i++;
	}

exit:
	if (likely(i)) {
		/* Store vnet_q in the last completion to get callback after that */
		compl_ptr[1] = (uintptr_t)vnet_q;
		compl_ptr[2] = ci_start << 16 | ci_desc;
		/* Issue a doorbell to trigger DMA */
		plt_io_wmb();
		plt_write64(dma_cnt, outb_q->widx_r);
	}

	vnet_q->ci_desc = ci_desc;
	return i;
}

int
cnxk_emdev_vnet_enq_psw_dbl(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
			    uint16_t pi, const uint16_t flags)

{
#ifdef CNXK_EMDEV_DEBUG
	rte_hexdump(stdout, "CQ descriptors",
		    VNET_DESC_PTR_OFF(vnet_q->sd_base, vnet_q->pi_desc, 0),
		    wrap_off_diff(pi, vnet_q->pi_desc, vnet_q->q_sz) * 16);
#endif
	PLT_SET_USED(queue);
	PLT_SET_USED(flags);
	vnet_q->pi_desc = pi;
	return 0;
}

int
cnxk_emdev_vnet_enq_dpi_compl(struct cnxk_emdev_queue *queue, struct cnxk_emdev_vnet_queue *vnet_q,
			      uint16_t comp_idx, const uint16_t flags)
{
	struct cnxk_emdev_dpi_q *outb_q = &queue->dpi_q_outb;
	uint64_t *compl_base = outb_q->compl_base;
	struct cnxk_emdev_psw_q *aq = &queue->aq;
	uint16_t ci_start, ci_desc, pi, ci;
	uint16_t q_sz = vnet_q->q_sz;
	uint64_t *compl_ptr, ci_data;
	uint64_t *pi_dbl, *ci_dbl;
	uint64_t ack_desc;

	PLT_SET_USED(flags);
	pi_dbl = (uint64_t *)aq->pi_dbl;
	ci_dbl = (uint64_t *)aq->ci_dbl;
	pi = plt_read64(pi_dbl);
	ci = plt_read64(ci_dbl);

	/* Check if Ack queue is full */
	if (DESC_ADD(pi, 1, aq->q_sz) == ci)
		return -ENOSPC;

	compl_ptr = cnxk_emdev_dma_compl_addr(compl_base, comp_idx);
	ci_data = compl_ptr[2];
	ci_start = ci_data >> 16;
	ci_desc = ci_data & 0xFFFF;

	/* Prepare PSW_ACK_DOORBELL_DESC_S */
	ack_desc = (uint64_t)ci_desc << 32;
	ack_desc |= (uint64_t)vnet_q->qid << 8;
	ack_desc |= (uint64_t)vnet_q->epf_func << 16;
	ack_desc |= (uint64_t)wrap_off_diff(ci_desc, ci_start, vnet_q->q_sz) << 48;

	/* Add instruction to ack queue to trigger descriptor store */
	*AQ_DESC_PTR_OFF(aq->q_base, pi, 0) = ack_desc;
	pi = DESC_ADD(pi, 1, q_sz);
	plt_io_wmb();
	plt_write64(pi, pi_dbl);
	return 0;
}

int
cnxk_emdev_vnet_enqueue(struct rte_rawdev *rawdev, struct rte_rawdev_buf **bufs, uint32_t count,
			rte_rawdev_obj_t ctx)
{
	struct cnxk_emdev *dev = cnxk_rawdev_priv(rawdev);
	struct cnxk_emdev_vnet_queue *vnet_q;
	struct cnxk_emdev_queue *queue;
	struct cnxk_emdev_dpi_q *dpi_q;
	uint16_t qid, vf_id, vf_qid;
	uint8_t fn_id;

	/* Extract enq destination vf, qid from meta */
	qid = cnxk_emdev_qid_from_ctx(ctx);
	vf_id = cnxk_emdev_vf_from_ctx(ctx);
	vf_qid = cnxk_emdev_rid_from_ctx(ctx);
	queue = &dev->emdev_qs[qid];

	/* Process doorbell descriptors */
	emdev_dbl_desc_process(queue);

	/* Process DPI outbound completions */
	dpi_q = &queue->dpi_q_outb;
	emdev_dpi_compl_process(queue, dpi_q);

	/* Skip if nothing to enqueue */
	if (!count)
		return 0;

	/* Enqueue the mbufs to vnet queue */
	vnet_q = queue->vnet_q_base[vf_id] ? queue->vnet_q_base[vf_id] + vf_qid : NULL;
	fn_id = vnet_q ? vnet_q->enq_fn_id : 0;
	return cnxk_emdev_vnet_enq_fn[fn_id](queue, vnet_q, (struct rte_mbuf **)bufs, count);
}

#define E(name, flags)                                                                             \
	int cnxk_emdev_vnet_enq_##name(void *q, void *vnet_q, struct rte_mbuf **mbufs,             \
				       uint16_t nb_mbufs)                                          \
	{                                                                                          \
		if (flags == EMDEV_VNET_ENQ_OFFLOAD_NONE)                                          \
			return 0;                                                                  \
												   \
		if (flags & EMDEV_VNET_ENQ_OFFLOAD_CTRL)                                           \
			return emdev_vnet_ctrl_enq(q, vnet_q, mbufs, nb_mbufs, flags);             \
		else                                                                               \
			return emdev_vnet_enq(q, vnet_q, mbufs, nb_mbufs, flags);                  \
	}

EMDEV_VNET_ENQ_FASTPATH_MODES
#undef E
