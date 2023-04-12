/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __OTX2_WORKER_H__
#define __OTX2_WORKER_H__

#include <rte_common.h>
#include <rte_branch_prediction.h>

#include <otx2_common.h>
#include "otx2_evdev.h"
#include "otx2_vlib_buffer.h"
#include "otx2_ethdev_sec_tx.h"

/* SSO Operations */

static __rte_always_inline uint16_t
otx2_ssogws_get_work(struct otx2_ssogws *ws, struct rte_event *ev,
		     const uint32_t flags, const void * const lookup_mem)
{
	union otx2_sso_event event;
	uint64_t tstamp_ptr;
	uint64_t get_work1;
	uint64_t mbuf;

	otx2_write64(BIT_ULL(16) | /* wait for work. */
		     1, /* Use Mask set 0. */
		     ws->getwrk_op);

	if (flags & NIX_RX_OFFLOAD_PTYPE_F)
		rte_prefetch_non_temporal(lookup_mem);
#ifdef RTE_ARCH_ARM64
	asm volatile(
			"		ldr %[tag], [%[tag_loc]]	\n"
			"		ldr %[wqp], [%[wqp_loc]]	\n"
			"		tbz %[tag], 63, done%=		\n"
			"		sevl				\n"
			"rty%=:		wfe				\n"
			"		ldr %[tag], [%[tag_loc]]	\n"
			"		ldr %[wqp], [%[wqp_loc]]	\n"
			"		tbnz %[tag], 63, rty%=		\n"
			"done%=:	dmb ld				\n"
			"		prfm pldl1keep, [%[wqp], #8]	\n"
			"		sub %[mbuf], %[wqp], #0x80	\n"
			"		prfm pldl1keep, [%[mbuf]]	\n"
			: [tag] "=&r" (event.get_work0),
			  [wqp] "=&r" (get_work1),
			  [mbuf] "=&r" (mbuf)
			: [tag_loc] "r" (ws->tag_op),
			  [wqp_loc] "r" (ws->wqp_op)
			);
#else
	event.get_work0 = otx2_read64(ws->tag_op);
	while ((BIT_ULL(63)) & event.get_work0)
		event.get_work0 = otx2_read64(ws->tag_op);

	get_work1 = otx2_read64(ws->wqp_op);
	rte_prefetch0((const void *)get_work1);
	mbuf = (uint64_t)((char *)get_work1 - sizeof(struct rte_mbuf));
	rte_prefetch0((const void *)mbuf);
#endif

	event.get_work0 = (event.get_work0 & (0x3ull << 32)) << 6 |
		(event.get_work0 & (0x3FFull << 36)) << 4 |
		(event.get_work0 & 0xffffffff);
	ws->cur_tt = event.sched_type;
	ws->cur_grp = event.queue_id;

	if (event.sched_type != SSO_TT_EMPTY &&
	    event.event_type == RTE_EVENT_TYPE_ETHDEV) {
		otx2_wqe_to_mbuf(get_work1, mbuf, event.sub_event_type,
				 (uint32_t) event.get_work0, flags, lookup_mem);
		/* Extracting tstamp, if PTP enabled*/
		tstamp_ptr = *(uint64_t *)(((struct nix_wqe_hdr_s *)get_work1)
					     + OTX2_SSO_WQE_SG_PTR);
		otx2_nix_mbuf_to_tstamp((struct rte_mbuf *)mbuf, ws->tstamp,
					flags, (uint64_t *)tstamp_ptr);
		get_work1 = mbuf;
	}

	ev->event = event.get_work0;
	ev->u64 = get_work1;

	return !!get_work1;
}

static __rte_always_inline uint16_t
otx2_ssogws_get_work_vwqe(struct otx2_ssogws *ws, struct rte_event *ev,
		     const uint32_t flags, const void * const lookup_mem)
{
	union otx2_sso_event event;
	uint64_t tstamp_ptr;
	uint64_t get_work1;
	uint64_t mbuf;

	otx2_write64(BIT_ULL(16) | /* wait for work. */
		     1, /* Use Mask set 0. */
		     ws->getwrk_op);

	if (flags & NIX_RX_OFFLOAD_PTYPE_F)
		rte_prefetch_non_temporal(lookup_mem);
#ifdef RTE_ARCH_ARM64
	asm volatile(
			"		ldr %[tag], [%[tag_loc]]\n"
			"		ldr %[wqp], [%[wqp_loc]]\n"
			"		tbz %[tag], 63, done%=\n"
			"		sevl\n"
			"rty%=:		wfe\n"
			"		ldr %[tag], [%[tag_loc]]\n"
			"		ldr %[wqp], [%[wqp_loc]]\n"
			"		tbnz %[tag], 63, rty%=\n"
			"done%=:	dmb ld\n"
			"		prfm pldl1keep, [%[wqp], #8]\n"
			"		sub %[mbuf], %[wqp], #0x80\n"
			"		prfm pldl1keep, [%[mbuf]]\n"
			: [tag] "=&r" (event.get_work0),
			  [wqp] "=&r" (get_work1),
			  [mbuf] "=&r" (mbuf)
			: [tag_loc] "r" (ws->tag_op),
			  [wqp_loc] "r" (ws->wqp_op)
			);
#else
	event.get_work0 = otx2_read64(ws->tag_op);
	while ((BIT_ULL(63)) & event.get_work0)
		event.get_work0 = otx2_read64(ws->tag_op);

	get_work1 = otx2_read64(ws->wqp_op);
	rte_prefetch0((const void *)get_work1);
	mbuf = (uint64_t)((char *)get_work1 - sizeof(struct rte_mbuf));
	rte_prefetch0((const void *)mbuf);
#endif

	event.get_work0 = (event.get_work0 & (0x3ull << 32)) << 6 |
		(event.get_work0 & (0x3FFull << 36)) << 4 |
		(event.get_work0 & 0xffffffff);
	ws->cur_tt = event.sched_type;
	ws->cur_grp = event.queue_id;

	if (event.sched_type != SSO_TT_EMPTY &&
	    event.event_type == RTE_EVENT_TYPE_ETHDEV) {
		otx2_wqe_to_mbuf(get_work1, mbuf, event.sub_event_type,
				 (uint32_t) event.get_work0, flags, lookup_mem);
		/* Extracting tstamp, if PTP enabled*/
		tstamp_ptr = *(uint64_t *)(((struct nix_wqe_hdr_s *)get_work1)
					     + OTX2_SSO_WQE_SG_PTR);
		otx2_nix_mbuf_to_tstamp((struct rte_mbuf *)mbuf, ws->tstamp,
					flags, (uint64_t *)tstamp_ptr);
		get_work1 = mbuf;
	}

	ev->event = event.get_work0;
	ev->u64 = get_work1;

	return !!get_work1;
}

/* Used in cleaning up workslot. */
static __rte_always_inline uint16_t
otx2_ssogws_get_work_empty(struct otx2_ssogws *ws, struct rte_event *ev,
			   const uint32_t flags)
{
	union otx2_sso_event event;
	uint64_t tstamp_ptr;
	uint64_t get_work1;
	uint64_t mbuf;

#ifdef RTE_ARCH_ARM64
	asm volatile(
			"		ldr %[tag], [%[tag_loc]]	\n"
			"		ldr %[wqp], [%[wqp_loc]]	\n"
			"		tbz %[tag], 63, done%=		\n"
			"		sevl				\n"
			"rty%=:		wfe				\n"
			"		ldr %[tag], [%[tag_loc]]	\n"
			"		ldr %[wqp], [%[wqp_loc]]	\n"
			"		tbnz %[tag], 63, rty%=		\n"
			"done%=:	dmb ld				\n"
			"		prfm pldl1keep, [%[wqp], #8]	\n"
			"		sub %[mbuf], %[wqp], #0x80	\n"
			"		prfm pldl1keep, [%[mbuf]]	\n"
			: [tag] "=&r" (event.get_work0),
			  [wqp] "=&r" (get_work1),
			  [mbuf] "=&r" (mbuf)
			: [tag_loc] "r" (ws->tag_op),
			  [wqp_loc] "r" (ws->wqp_op)
			);
#else
	event.get_work0 = otx2_read64(ws->tag_op);
	while ((BIT_ULL(63)) & event.get_work0)
		event.get_work0 = otx2_read64(ws->tag_op);

	get_work1 = otx2_read64(ws->wqp_op);
	rte_prefetch_non_temporal((const void *)get_work1);
	mbuf = (uint64_t)((char *)get_work1 - sizeof(struct rte_mbuf));
	rte_prefetch_non_temporal((const void *)mbuf);
#endif

	event.get_work0 = (event.get_work0 & (0x3ull << 32)) << 6 |
		(event.get_work0 & (0x3FFull << 36)) << 4 |
		(event.get_work0 & 0xffffffff);
	ws->cur_tt = event.sched_type;
	ws->cur_grp = event.queue_id;

	if (event.sched_type != SSO_TT_EMPTY &&
	    event.event_type == RTE_EVENT_TYPE_ETHDEV) {
		otx2_wqe_to_mbuf(get_work1, mbuf, event.sub_event_type,
				 (uint32_t) event.get_work0, flags, NULL);
		/* Extracting tstamp, if PTP enabled*/
		tstamp_ptr = *(uint64_t *)(((struct nix_wqe_hdr_s *)get_work1)
					     + OTX2_SSO_WQE_SG_PTR);
		otx2_nix_mbuf_to_tstamp((struct rte_mbuf *)mbuf, ws->tstamp,
					flags, (uint64_t *)tstamp_ptr);
		get_work1 = mbuf;
	}

	ev->event = event.get_work0;
	ev->u64 = get_work1;

	return !!get_work1;
}

static __rte_always_inline void
otx2_ssogws_add_work(struct otx2_ssogws *ws, const uint64_t event_ptr,
		     const uint32_t tag, const uint8_t new_tt,
		     const uint16_t grp)
{
	uint64_t add_work0;

	add_work0 = tag | ((uint64_t)(new_tt) << 32);
	otx2_store_pair(add_work0, event_ptr, ws->grps_base[grp]);
}

static __rte_always_inline void
otx2_ssogws_swtag_desched(struct otx2_ssogws *ws, uint32_t tag, uint8_t new_tt,
			  uint16_t grp)
{
	uint64_t val;

	val = tag | ((uint64_t)(new_tt & 0x3) << 32) | ((uint64_t)grp << 34);
	otx2_write64(val, ws->swtag_desched_op);
}

static __rte_always_inline void
otx2_ssogws_swtag_norm(struct otx2_ssogws *ws, uint32_t tag, uint8_t new_tt)
{
	uint64_t val;

	val = tag | ((uint64_t)(new_tt & 0x3) << 32);
	otx2_write64(val, ws->swtag_norm_op);
}

static __rte_always_inline void
otx2_ssogws_swtag_untag(struct otx2_ssogws *ws)
{
	otx2_write64(0, OTX2_SSOW_GET_BASE_ADDR(ws->getwrk_op) +
		     SSOW_LF_GWS_OP_SWTAG_UNTAG);
	ws->cur_tt = SSO_SYNC_UNTAGGED;
}

static __rte_always_inline void
otx2_ssogws_swtag_flush(struct otx2_ssogws *ws)
{
	otx2_write64(0, OTX2_SSOW_GET_BASE_ADDR(ws->getwrk_op) +
		     SSOW_LF_GWS_OP_SWTAG_FLUSH);
	ws->cur_tt = SSO_SYNC_EMPTY;
}

static __rte_always_inline void
otx2_ssogws_desched(struct otx2_ssogws *ws)
{
	otx2_write64(0, OTX2_SSOW_GET_BASE_ADDR(ws->getwrk_op) +
		     SSOW_LF_GWS_OP_DESCHED);
}

static __rte_always_inline void
otx2_ssogws_swtag_wait(struct otx2_ssogws *ws)
{
#ifdef RTE_ARCH_ARM64
	uint64_t swtp;

	asm volatile("		ldr %[swtb], [%[swtp_loc]]	\n"
		     "		tbz %[swtb], 62, done%=		\n"
		     "		sevl				\n"
		     "rty%=:	wfe				\n"
		     "		ldr %[swtb], [%[swtp_loc]]	\n"
		     "		tbnz %[swtb], 62, rty%=		\n"
		     "done%=:					\n"
		     : [ swtb ] "=&r"(swtp)
		     : [ swtp_loc ] "r"(ws->tag_op));
#else
	/* Wait for the SWTAG/SWTAG_FULL operation */
	while (otx2_read64(ws->tag_op) & BIT_ULL(62))
		;
#endif
}

static __rte_always_inline void
otx2_ssogws_head_wait(struct otx2_ssogws *ws)
{
#ifdef RTE_ARCH_ARM64
	uint64_t tag;

	asm volatile (
			"	ldr %[tag], [%[tag_op]]		\n"
			"	tbnz %[tag], 35, done%=		\n"
			"	sevl				\n"
			"rty%=:	wfe				\n"
			"	ldr %[tag], [%[tag_op]]		\n"
			"	tbz %[tag], 35, rty%=		\n"
			"done%=:				\n"
			: [tag] "=&r" (tag)
			: [tag_op] "r" (ws->tag_op)
			);
#else
	/* Wait for the HEAD to be set */
	while (!(otx2_read64(ws->tag_op) & BIT_ULL(35)))
		;
#endif
}
static __rte_always_inline void
otx2_ssogws_order(struct otx2_ssogws *ws, const uint8_t wait_flag)
{
	if (wait_flag)
		otx2_ssogws_head_wait(ws);

	rte_cio_wmb();
}

static __rte_always_inline struct otx2_eth_txq *
otx2_ssogws_xtract_meta(struct rte_mbuf *m,
			const uint64_t txq_data[][RTE_MAX_QUEUES_PER_PORT])
{
	return (struct otx2_eth_txq *)txq_data[m->port][
					rte_event_eth_tx_adapter_txq_get(m)];
}

static __rte_always_inline void
otx2_ssogws_prepare_pkt(const struct otx2_eth_txq *txq, struct rte_mbuf *m,
			uint64_t *cmd, const uint32_t flags)
{
	otx2_lmt_mov(cmd, txq->cmd, otx2_nix_tx_ext_subs(flags));
	otx2_nix_xmit_prepare(m, cmd, flags);
}

static __rte_always_inline struct otx2_eth_txq *
otx2_ssogws_xtract_meta_vlib(uint16_t q, uint16_t port)
{

	return rte_eth_devices[port].data->tx_queues[q];
}

static __rte_always_inline uint16_t
otx2_nix_xmit_pkts_vlib(void *tx_queue, struct rte_mbuf **tx_pkts,
			uint16_t pkts, uint64_t *cmd, const uint16_t flags)
{
	dpdk_otx2_per_thread_data_t *ptd =
				(dpdk_otx2_per_thread_data_t *)((tx_pkts));
	struct otx2_eth_txq *txq = tx_queue; uint16_t i;
	const rte_iova_t io_addr = txq->io_addr;
	void *lmt_addr = txq->lmt_addr;
	uint16_t prefetch;

	/* Inline NIX_XMIT_FC_OR_RETURN(txq, pkts) */
	/* Cached value is low, Update the fc_cache_pkts */
	if (unlikely((txq)->fc_cache_pkts < (pkts))) {
		/* Multiply with sqe_per_sqb to express in pkts */
		(txq)->fc_cache_pkts =
			((txq)->nb_sqb_bufs_adj - *(txq)->fc_mem) <<
				(txq)->sqes_per_sqb_log2;
		/* Check it again for the room */
		if (unlikely((txq)->fc_cache_pkts < (pkts)))
			return 0;
	}

	otx2_lmt_mov(cmd, &txq->cmd[0], otx2_nix_tx_ext_subs(flags));

	/* Lets commit any changes in the packet */
	rte_cio_wmb();

	for (i = 0; i < pkts; i++) {
		prefetch = i+3;
		if (likely(prefetch < pkts))
			rte_prefetch_non_temporal((void *)(tx_pkts[prefetch]));
		otx2_nix_xmit_prepare_from_vlib(tx_pkts[i], cmd, flags, ptd);
		    /* Passing no of segdw as 4: HDR + EXT + SG + SMEM */
		otx2_nix_xmit_prepare_tstamp(cmd, &txq->cmd[0],
			tx_pkts[i]->ol_flags, 4, flags);
		otx2_nix_xmit_one(cmd, lmt_addr, io_addr, flags);
	}

	/* Reduce the cached count */
	txq->fc_cache_pkts -= pkts;

	return pkts;
}

static __rte_always_inline uint16_t
otx2_ssogws_event_tx(struct otx2_ssogws *ws, struct rte_event ev[],
		     uint64_t *cmd, const uint64_t
		     txq_data[][RTE_MAX_QUEUES_PER_PORT],
		     const uint32_t flags)
{
	struct rte_mbuf *m = ev[0].mbuf;
	struct otx2_eth_txq *txq;
//	int64_t ret;

	if ((flags & NIX_TX_OFFLOAD_SECURITY_F) &&
	    (m->ol_flags & PKT_TX_SEC_OFFLOAD)) {
		txq = otx2_ssogws_xtract_meta(m, txq_data);
		return otx2_sec_event_tx(ws, ev, m, txq, flags);
	}

	/* Perform header writes before barrier for TSO */
	otx2_nix_xmit_prepare_tso(m, flags);
	/* Lets commit any changes in the packet here in case of single seg as
	 * no further changes to mbuf will be done.
	 * While for multi seg all mbufs used are set to NULL in
	 * otx2_nix_prepare_mseg() after preparing the sg list and these changes
	 * should be committed before LMTST.
	 * Also in no fast free case some mbuf fields are updated in
	 * otx2_nix_prefree_seg
	 * Hence otx2_nix_xmit_submit_lmt_release/otx2_nix_xmit_mseg_one_release
	 * has store barrier for multiseg.
	 */
	if (!(flags & NIX_TX_MULTI_SEG_F) &&
	    !(flags & NIX_TX_OFFLOAD_MBUF_NOFF_F))
		rte_cio_wmb();
	txq = otx2_ssogws_xtract_meta(m, txq_data);
#if 0
    if ((ret = rte_atomic64_sub_return(&txq->fc_cache_pkts_at, 1)) < 0) {
		if (ret == -1) {
			/* Only one core enters here */
                        rte_atomic64_set(&txq->fc_cache_pkts_at,
					(txq->nb_sqb_bufs_adj - *txq->fc_mem)
					<< txq->sqes_per_sqb_log2);
			if (rte_atomic64_sub_return
					(&txq->fc_cache_pkts_at, 1) < 0) {
				/* Gives chance to set fc_cache_pakets again*/
				rte_atomic64_set(&txq->fc_cache_pkts_at, 0);
				return 0;
			}
		} else {
			/* Remaining cores return 0 */
			return 0;
		}
	}
#endif
	otx2_ssogws_prepare_pkt(txq, m, cmd, flags);

	if (flags & NIX_TX_MULTI_SEG_F) {
		const uint16_t segdw = otx2_nix_prepare_mseg(m, cmd, flags);
		otx2_nix_xmit_prepare_tstamp(cmd, &txq->cmd[0],
					     m->ol_flags, segdw, flags);
		if (!ev->sched_type) {
			otx2_nix_xmit_mseg_prep_lmt(cmd, txq->lmt_addr, segdw);
			otx2_ssogws_head_wait(ws);
			if (otx2_nix_xmit_submit_lmt_release(txq->io_addr) == 0)
				otx2_nix_xmit_mseg_one(cmd, txq->lmt_addr,
						       txq->io_addr, segdw);
		} else {
			otx2_nix_xmit_mseg_one_release(cmd, txq->lmt_addr,
						       txq->io_addr, segdw);
		}
	} else {
		/* Passing no of segdw as 4: HDR + EXT + SG + SMEM */
		otx2_nix_xmit_prepare_tstamp(cmd, &txq->cmd[0],
					     m->ol_flags, 4, flags);

		if (!ev->sched_type) {
			otx2_nix_xmit_prep_lmt(cmd, txq->lmt_addr, flags);
			otx2_ssogws_head_wait(ws);
			if (otx2_nix_xmit_submit_lmt(txq->io_addr) == 0)
				otx2_nix_xmit_one(cmd, txq->lmt_addr,
						  txq->io_addr, flags);
		} else {
			otx2_nix_xmit_one(cmd, txq->lmt_addr, txq->io_addr,
					  flags);
		}
	}

	otx2_write64(0, ws->swtag_flush_op);

	return 1;
}
static __rte_always_inline uint16_t
otx2_ssogws_event_tx_vlib(struct otx2_ssogws *ws, struct rte_event ev[],
		     uint64_t *cmd, const uint32_t flags,
		     const uint32_t num_pkts)
{
	struct otx2_eth_txq *txq = NULL;
	dpdk_vlib_buffer_t **vbuf = (dpdk_vlib_buffer_t **) ev;
	uint16_t sent_pkts = 0;
	dpdk_otx2_per_thread_data_t *ptd =
			(dpdk_otx2_per_thread_data_t *)((vbuf));
	uint16_t wait_flag = ptd->holding_cq_tag;

	struct rte_event *tmp_ev = (struct rte_event *)
					(&(vbuf[0]->custom_ptr));
	switch (tmp_ev->sched_type) {
	case SSO_SYNC_ORDERED:
		while (wait_flag && !((otx2_read64(ws->tag_op)) & BIT_ULL(35)))
			;
		 /* Fall-through */
	case SSO_SYNC_ATOMIC:
		txq = otx2_ssogws_xtract_meta_vlib(
					OTX2_EVENT_QUEUE(tmp_ev->u64),
					OTX2_EVENT_PORT(tmp_ev->u64)
					);
		sent_pkts = otx2_nix_xmit_pkts_vlib((void *)txq,
			(struct rte_mbuf **)vbuf, num_pkts, cmd, flags);
		return sent_pkts;
	default:
		RTE_ASSERT(0);
	}
	/*We haven't enqueued any events*/
	return 0;
}

#endif
