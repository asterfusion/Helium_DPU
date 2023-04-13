/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

#include <rte_bus.h>
#include <rte_bus_pci.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mempool.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <rte_io.h>
#include <rte_net.h>
#include <rte_common.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>

#include "otx_ep_common.h"
#include "otx_ep_vf.h"
#include "otx2_ep_vf.h"
#include "otx_ep_rxtx.h"

/* SDP_LENGTH_S specifies packet length and is of 8-byte size */
#define INFO_SIZE 8
static void
otx_ep_dmazone_free(const struct rte_memzone *mz)
{
	const struct rte_memzone *mz_tmp;
	int ret = 0;

	if (mz == NULL) {
		otx_ep_err("Memzone %s : NULL\n", mz->name);
		return;
	}

	mz_tmp = rte_memzone_lookup(mz->name);
	if (mz_tmp == NULL) {
		otx_ep_err("Memzone %s Not Found\n", mz->name);
		return;
	}

	ret = rte_memzone_free(mz);
	if (ret)
		otx_ep_err("Memzone free failed : ret = %d\n", ret);

}

/* Free IQ resources */
int
otx_ep_delete_iqs(struct otx_ep_device *otx_ep, uint32_t iq_no)
{
	struct otx_ep_instr_queue *iq;

	iq = otx_ep->instr_queue[iq_no];
	if (iq == NULL) {
		otx_ep_err("Invalid IQ[%d]\n", iq_no);
		return -ENOMEM;
	}

	rte_free(iq->req_list);
	iq->req_list = NULL;

	if (iq->iq_mz) {
		otx_ep_dmazone_free(iq->iq_mz);
		iq->iq_mz = NULL;
	}

	rte_free(otx_ep->instr_queue[iq_no]);
	otx_ep->instr_queue[iq_no] = NULL;

	otx_ep->nb_tx_queues--;

	otx_ep_info("IQ[%d] is deleted\n", iq_no);

	return 0;
}

/* IQ initialization */
static int
otx_ep_init_instr_queue(struct otx_ep_device *otx_ep, int iq_no, int num_descs,
		     unsigned int socket_id)
{
	const struct otx_ep_config *conf;
	struct otx_ep_instr_queue *iq;
	uint32_t q_size;

	conf = otx_ep->conf;
	iq = otx_ep->instr_queue[iq_no];
	q_size = conf->iq.instr_type * num_descs;

	/* IQ memory creation for Instruction submission to OCTEON TX2 */
	iq->iq_mz = rte_eth_dma_zone_reserve(otx_ep->eth_dev,
					     "instr_queue", iq_no, q_size,
					     OTX_EP_PCI_RING_ALIGN,
					     socket_id);
	if (iq->iq_mz == NULL) {
		otx_ep_err("IQ[%d] memzone alloc failed\n", iq_no);
		goto iq_init_fail;
	}

	iq->base_addr_dma = iq->iq_mz->iova;
	iq->base_addr = (uint8_t *)iq->iq_mz->addr;

	if (num_descs & (num_descs - 1)) {
		otx_ep_err("IQ[%d] descs not in power of 2\n", iq_no);
		goto iq_init_fail;
	}

	iq->nb_desc = num_descs;

	/* Create a IQ request list to hold requests that have been
	 * posted to OCTEON TX2. This list will be used for freeing the IQ
	 * data buffer(s) later once the OCTEON TX2 fetched the requests.
	 */
	iq->req_list = rte_zmalloc_socket("request_list",
			(iq->nb_desc * OTX_EP_IQREQ_LIST_SIZE),
			RTE_CACHE_LINE_SIZE,
			rte_socket_id());
	if (iq->req_list == NULL) {
		otx_ep_err("IQ[%d] req_list alloc failed\n", iq_no);
		goto iq_init_fail;
	}

	otx_ep_info("IQ[%d]: base: %p basedma: %lx count: %d\n",
		     iq_no, iq->base_addr, (unsigned long)iq->base_addr_dma,
		     iq->nb_desc);

	iq->otx_ep_dev = otx_ep;
	iq->q_no = iq_no;
	iq->fill_cnt = 0;
	iq->host_write_index = 0;
	iq->otx_read_index = 0;
	iq->flush_index = 0;

	/* Initialize the spinlock for this instruction queue */
	rte_spinlock_init(&iq->lock);
	rte_spinlock_init(&iq->post_lock);

	rte_atomic64_clear(&iq->iq_flush_running);

	otx_ep->io_qmask.iq |= (1ull << iq_no);

	/* Set 32B/64B mode for each input queue */
	if (conf->iq.instr_type == 64)
		otx_ep->io_qmask.iq64B |= (1ull << iq_no);

	iq->iqcmd_64B = (conf->iq.instr_type == 64);

	/* Set up IQ registers */
	otx_ep->fn_list.setup_iq_regs(otx_ep, iq_no);

	return 0;

iq_init_fail:
	return -ENOMEM;

}

int
otx_ep_setup_iqs(struct otx_ep_device *otx_ep, uint32_t iq_no, int num_descs, unsigned
	      int socket_id)
{
	struct otx_ep_instr_queue *iq;

	iq = (struct otx_ep_instr_queue *)rte_zmalloc("otx_ep_IQ", sizeof(*iq),
						RTE_CACHE_LINE_SIZE);
	if (iq == NULL)
		return -ENOMEM;

	otx_ep->instr_queue[iq_no] = iq;

	if (otx_ep_init_instr_queue(otx_ep, iq_no, num_descs, socket_id)) {
		otx_ep_err("IQ init is failed\n");
		goto delete_IQ;
	}
	otx_ep->nb_tx_queues++;

	otx_ep_info("IQ[%d] is created.\n", iq_no);

	return 0;

delete_IQ:
	otx_ep_delete_iqs(otx_ep, iq_no);
	return -ENOMEM;
}

static void
otx_ep_droq_reset_indices(struct otx_ep_droq *droq)
{
	droq->read_idx  = 0;
	droq->write_idx = 0;
	droq->refill_idx = 0;
	droq->refill_count = 0;
	droq->last_pkt_count = 0;
	rte_atomic64_set(&droq->pkts_pending, 0);
}

static void
otx_ep_droq_destroy_ring_buffers(struct otx_ep_droq *droq)
{
	uint32_t idx;

	for (idx = 0; idx < droq->nb_desc; idx++) {
		if (droq->recv_buf_list[idx]) {
			rte_pktmbuf_free(droq->recv_buf_list[idx]);
			droq->recv_buf_list[idx] = NULL;
		}
	}

	otx_ep_droq_reset_indices(droq);
}

/* Free OQs resources */
int
otx_ep_delete_oqs(struct otx_ep_device *otx_ep, uint32_t oq_no)
{
	struct otx_ep_droq *droq;

	droq = otx_ep->droq[oq_no];
	if (droq == NULL) {
		otx_ep_err("Invalid droq[%d]\n", oq_no);
		return -ENOMEM;
	}

	otx_ep_droq_destroy_ring_buffers(droq);
	rte_free(droq->recv_buf_list);
	droq->recv_buf_list = NULL;

#ifndef BUFPTR_ONLY_MODE
	if (droq->info_mz) {
		otx_ep_dmazone_free(droq->info_mz);
		droq->info_mz = NULL;
	}
#endif

	if (droq->desc_ring_mz) {
		otx_ep_dmazone_free(droq->desc_ring_mz);
		droq->desc_ring_mz = NULL;
	}

	memset(droq, 0, OTX_EP_DROQ_SIZE);

	rte_free(otx_ep->droq[oq_no]);
	otx_ep->droq[oq_no] = NULL;

	otx_ep->nb_rx_queues--;

	otx_ep_info("OQ[%d] is deleted\n", oq_no);
	return 0;
}

static int
otx_ep_droq_setup_ring_buffers(struct otx_ep_droq *droq)
{
	struct otx_ep_droq_desc *desc_ring = droq->desc_ring;
	uint32_t idx;
	struct rte_mbuf *buf;
	struct otx_ep_droq_info *info;

	for (idx = 0; idx < droq->nb_desc; idx++) {
		buf = rte_pktmbuf_alloc(droq->mpool);
		if (buf == NULL) {
			otx_ep_err("OQ buffer alloc failed\n");
			droq->stats.rx_alloc_failure++;
			/* otx_ep_droq_destroy_ring_buffers(droq);*/
			return -ENOMEM;
		}

		droq->recv_buf_list[idx] = buf;
#ifndef BUFPTR_ONLY_MODE
		droq->info_list[idx].length = 0;

		/* Map ring buffers into memory */
		desc_ring[idx].info_ptr = (uint64_t)(droq->info_list_dma +
			(idx * OTX_EP_DROQ_INFO_SIZE));

#endif
		info = rte_pktmbuf_mtod(buf, struct otx_ep_droq_info *);
		memset(info, 0, sizeof(*info));
		desc_ring[idx].buffer_ptr = rte_mbuf_data_iova_default(buf);
	}

	otx_ep_droq_reset_indices(droq);

	return 0;
}

#ifndef BUFPTR_ONLY_MODE
static void *
otx_ep_alloc_info_buffer(struct otx_ep_device *otx_ep __rte_unused,
	struct otx_ep_droq *droq, unsigned int socket_id)
{
    otx_ep_info("sdp_ep_alloc_info_buffer: droq->nb_desc = %u, size = %lu\n", droq->nb_desc, OTX_EP_DROQ_INFO_SIZE);
	droq->info_mz = rte_memzone_reserve_aligned("OQ_info_list",
				(droq->nb_desc * OTX_EP_DROQ_INFO_SIZE),
				socket_id,
				RTE_MEMZONE_IOVA_CONTIG,
				OTX_EP_PCI_RING_ALIGN);

	if (droq->info_mz == NULL)
		return NULL;

	droq->info_list_dma = droq->info_mz->iova;
	droq->info_alloc_size = droq->info_mz->len;
	droq->info_base_addr = (size_t)droq->info_mz->addr;

	return droq->info_mz->addr;
}
#endif

/* OQ initialization */
static int
otx_ep_init_droq(struct otx_ep_device *otx_ep, uint32_t q_no,
	      uint32_t num_descs, uint32_t desc_size,
	      struct rte_mempool *mpool, unsigned int socket_id)
{
	const struct otx_ep_config *conf = otx_ep->conf;
	uint32_t c_refill_threshold;
	uint32_t desc_ring_size;
	struct otx_ep_droq *droq;

	otx_ep_info("OQ[%d] Init start\n", q_no);

	droq = otx_ep->droq[q_no];
	droq->otx_ep_dev = otx_ep;
	droq->q_no = q_no;
	droq->mpool = mpool;

	droq->nb_desc      = num_descs;
	droq->buffer_size  = desc_size;
	c_refill_threshold = RTE_MAX(conf->oq.refill_threshold, droq->nb_desc/2);

	/* OQ desc_ring set up */
	desc_ring_size = droq->nb_desc * OTX_EP_DROQ_DESC_SIZE;
	droq->desc_ring_mz = rte_eth_dma_zone_reserve(otx_ep->eth_dev,
						"droq", q_no, desc_ring_size,
						OTX_EP_PCI_RING_ALIGN, socket_id);

	if (droq->desc_ring_mz == NULL) {
		otx_ep_err("OQ:%d desc_ring allocation failed\n", q_no);
		goto init_droq_fail;
	}

	droq->desc_ring_dma = droq->desc_ring_mz->iova;
	droq->desc_ring = (struct otx_ep_droq_desc *)droq->desc_ring_mz->addr;

	otx_ep_dbg("OQ[%d]: desc_ring: virt: 0x%p, dma: %lx\n",
		    q_no, droq->desc_ring, (unsigned long)droq->desc_ring_dma);
	otx_ep_dbg("OQ[%d]: num_desc: %d\n", q_no, droq->nb_desc);


#ifndef BUFPTR_ONLY_MODE
	/* OQ info_list set up */
	droq->info_list = otx_ep_alloc_info_buffer(otx_ep, droq, socket_id);
	if (droq->info_list == NULL) {
		otx_ep_err("memory allocation failed for OQ[%d] info_list\n", q_no);
		goto init_droq_fail;
	}

#endif
	/* OQ buf_list set up */
	droq->recv_buf_list = rte_zmalloc_socket("recv_buf_list",
				(droq->nb_desc * sizeof(struct rte_mbuf *)),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (droq->recv_buf_list == NULL) {
		otx_ep_err("OQ recv_buf_list alloc failed\n");
		goto init_droq_fail;
	}

	if (otx_ep_droq_setup_ring_buffers(droq))
		goto init_droq_fail;

	droq->refill_threshold = c_refill_threshold;
	rte_spinlock_init(&droq->lock);


	/* Set up OQ registers */
	otx_ep->fn_list.setup_oq_regs(otx_ep, q_no);

	otx_ep->io_qmask.oq |= (1ull << q_no);

	return 0;

init_droq_fail:
	return -ENOMEM;
}

/* OQ configuration and setup */
int
otx_ep_setup_oqs(struct otx_ep_device *otx_ep, int oq_no, int num_descs,
	       int desc_size, struct rte_mempool *mpool, unsigned int socket_id)
{
	struct otx_ep_droq *droq;

	/* Allocate new droq. */
	droq = (struct otx_ep_droq *)rte_zmalloc("otx_ep_OQ",
				sizeof(*droq), RTE_CACHE_LINE_SIZE);
	if (droq == NULL) {
		otx_ep_err("Droq[%d] Creation Failed\n", oq_no);
		return -ENOMEM;
	}
	otx_ep->droq[oq_no] = droq;

	if (otx_ep_init_droq(otx_ep, oq_no, num_descs, desc_size, mpool, socket_id)) {
		otx_ep_err("Droq[%d] Initialization failed\n", oq_no);
		goto delete_OQ;
	}
	otx_ep_info("OQ[%d] is created.\n", oq_no);

	otx_ep->nb_rx_queues++;

	return 0;

delete_OQ:
	otx_ep_delete_oqs(otx_ep, oq_no);
	return -ENOMEM;
}

static inline void
otx_ep_iqreq_delete(struct otx_ep_instr_queue *iq, uint32_t idx)
{
	uint32_t reqtype;
	void *buf;
	struct otx_ep_buf_free_info *finfo;

	buf     = iq->req_list[idx].buf;
	reqtype = iq->req_list[idx].reqtype;

	switch (reqtype) {
	case OTX_EP_REQTYPE_NORESP_NET:
		rte_pktmbuf_free((struct rte_mbuf *)buf);
		otx_ep_dbg("IQ buffer freed at idx[%d]\n", idx);
		break;

	case OTX_EP_REQTYPE_NORESP_GATHER:
		finfo = (struct  otx_ep_buf_free_info *)buf;
		/* This will take care of multiple segments also */
		rte_pktmbuf_free(finfo->mbuf);
		rte_free(finfo->g.sg);
		rte_free(finfo);
		break;

	case OTX_EP_REQTYPE_NONE:
	default:
		otx_ep_info("This iqreq mode is not supported:%d\n", reqtype);

	}

	/* Reset the request list at this index */
	iq->req_list[idx].buf = NULL;
	iq->req_list[idx].reqtype = 0;
}

static inline void
otx_ep_iqreq_add(struct otx_ep_instr_queue *iq, void *buf,
		uint32_t reqtype)
{
	iq->req_list[iq->host_write_index].buf = buf;
	iq->req_list[iq->host_write_index].reqtype = reqtype;

	//otx_ep_dbg("IQ buffer added at idx[%d]\n", iq->host_write_index);

}

static void
otx_ep_flush_iq(struct otx_ep_device *otx_ep,
		struct otx_ep_instr_queue *iq)
{
	uint32_t instr_processed = 0;

	rte_spinlock_lock(&iq->lock);

	iq->otx_read_index = otx_ep->fn_list.update_iq_read_idx(iq);
	while (iq->flush_index != iq->otx_read_index) {
		/* Free the IQ data buffer to the pool */
		otx_ep_iqreq_delete(iq, iq->flush_index);
		iq->flush_index =
			otx_ep_incr_index(iq->flush_index, 1, iq->nb_desc);

		instr_processed++;
	}

	iq->stats.instr_processed = instr_processed;
	rte_atomic64_sub(&iq->instr_pending, instr_processed);

	rte_spinlock_unlock(&iq->lock);
}

static inline void
otx_ep_ring_doorbell(struct otx_ep_device *otx_ep __rte_unused,
		struct otx_ep_instr_queue *iq)
{
	rte_write64(iq->fill_cnt, iq->doorbell_reg);

	/* Make sure doorbell write goes through */
	rte_wmb();
	iq->fill_cnt = 0;

}

static inline int
post_iqcmd(struct otx_ep_instr_queue *iq, uint8_t *iqcmd)
{
	uint8_t *iqptr, cmdsize;

	/* This ensures that the read index does not wrap around to
	 * the same position if queue gets full before OCTEON TX2 could
	 * fetch any instr.
	 */
	if (rte_atomic64_read(&iq->instr_pending) >=
			      (int32_t)(iq->nb_desc - 1)) {
		//otx_ep_dbg("IQ is full, pending:%ld\n",
		//	 (long)rte_atomic64_read(&iq->instr_pending));

		return OTX_EP_IQ_SEND_FAILED;
	}

	/* Copy cmd into iq */
	cmdsize = ((iq->iqcmd_64B) ? 64 : 32);
	iqptr   = iq->base_addr + (cmdsize * iq->host_write_index);

      /* Dump iQ cmd */
	rte_memcpy(iqptr, iqcmd, cmdsize);
#if 0
        {
                int i = 0;
                uint64_t *tmp = (uint64_t *) iqptr;
                otx_ep_dbg("IQ DUMP: iq no: %d dma addr: 0x%016lx, offset: %d\n",
                       iq->q_no, iq->base_addr_dma,  iq->host_write_index);
                for (i = 0; i < cmdsize / 8; i++)
                        otx_ep_dbg("word[%d]: 0x%016lx\n", i, *(tmp + i));
        }
	otx_ep_dbg("IQ cmd posted @ index:%d\n", iq->host_write_index);
#endif
	/* Increment the host write index */
	iq->host_write_index =
		otx_ep_incr_index(iq->host_write_index, 1, iq->nb_desc);

	iq->fill_cnt++;

	/* Flush the command into memory. We need to be sure the data
	 * is in memory before indicating that the instruction is
	 * pending.
	 */
	rte_wmb();
	rte_atomic64_inc(&iq->instr_pending);

	/* OTX_EP_IQ_SEND_SUCCESS */
	return 0;
}


static int
otx_ep_send_data(struct otx_ep_device *otx_ep,
	      struct otx_ep_instr_queue *iq, void *cmd, int dbell)
{
	uint32_t ret;

	/* Lock this IQ command queue before posting instruction */
	rte_spinlock_lock(&iq->post_lock);

	/* Submit IQ command */
	ret = post_iqcmd(iq, cmd);

	if (ret == OTX_EP_IQ_SEND_SUCCESS) {
		if (dbell)
			otx_ep_ring_doorbell(otx_ep, iq);

		iq->stats.instr_posted++;
		//otx_ep_dbg("Instr submit success posted: %ld\n",
		//	     (long)iq->stats.instr_posted);

	} else {
		iq->stats.instr_dropped++;
		if (iq->fill_cnt)
			otx_ep_ring_doorbell(otx_ep, iq);
		otx_ep_dbg("Instr submit failled, dropped: %ld\n",
			 (long)iq->stats.instr_dropped);

	}

	rte_spinlock_unlock(&iq->post_lock);

	return ret;
}

static inline void
set_sg_size(struct otx_ep_sg_entry *sg_entry,
		uint16_t size, uint32_t pos)
{
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	sg_entry->u.size[pos] = size;
#elif RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	sg_entry->u.size[3 - pos] = size;
#endif
}

/* Enqueue requests/packets to OTX_EP IQ queue.
 * returns number of requests enqueued successfully
 */
uint16_t
otx_ep_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct otx_ep_instr_64B iqcmd;
	struct otx_ep_instr_queue *iq;
	struct otx_ep_device *otx_ep;
	uint64_t dptr;
	int count = 0;
	unsigned int i;
	struct rte_mbuf *m;
	unsigned int pkt_len;
	void *iqreq_buf;
	uint32_t iqreq_type;
	int gather, gsz;
	int dbell;

	iq = (struct otx_ep_instr_queue *)tx_queue;
	otx_ep = iq->otx_ep_dev;

	if (!otx_ep->started || !otx_ep->linkup) {
		goto xmit_fail;
	}

	iqcmd.ih.u64 = 0;
	iqcmd.pki_ih3.u64 = 0;
	iqcmd.irh.u64 = 0;

	/* ih invars */
	iqcmd.ih.s.fsz = 32;
	iqcmd.ih.s.pkind = otx_ep->pkind; /* The SDK decided PKIND value */

	/* pki ih3 invars */
	iqcmd.pki_ih3.s.w = 1;
	iqcmd.pki_ih3.s.utt = 1;
	iqcmd.pki_ih3.s.tagtype = ORDERED_TAG;
	iqcmd.pki_ih3.s.sl = 32 + OTX_CUST_DATA_LEN;        /* sl will be sizeof(pki_ih3) */

	/* irh invars */
	iqcmd.irh.s.opcode = OTX_EP_NW_PKT_OP;

	for (i = 0; i < nb_pkts; i++) {
		m = pkts[i];
		if (m->nb_segs == 1) {
			/* dptr */
			dptr = rte_mbuf_data_iova(m);
			pkt_len = rte_pktmbuf_data_len(m);
			iqreq_buf = m;
			iqreq_type = OTX_EP_REQTYPE_NORESP_NET;
			gather = 0;
			gsz = 0;
		} else {
			struct otx_ep_buf_free_info *finfo;
			int j, frags, num_sg;

			if (!(otx_ep->tx_offloads & DEV_TX_OFFLOAD_MULTI_SEGS))
				goto xmit_fail;

			finfo = (struct otx_ep_buf_free_info *)rte_malloc(NULL,
									  sizeof(*finfo),
										  0);
			if (finfo == NULL) {
				otx_ep_err("free buffer alloc failed\n");
				goto xmit_fail;
			}
			num_sg = (m->nb_segs + 3)/4;
			finfo->g.sg = rte_zmalloc(NULL, (sizeof(struct otx_ep_sg_entry)
					   * num_sg), OTX_EP_SG_ALIGN);
			if (finfo->g.sg == NULL) {
				rte_free(finfo);
				otx_ep_err("sg entry alloc failed\n");
				goto xmit_fail;
			}
			gather = 1;
			gsz = m->nb_segs;
			finfo->g.num_sg = num_sg;
			finfo->g.sg[0].ptr[0] = rte_mbuf_data_iova(m);
			set_sg_size(&finfo->g.sg[0], m->data_len, 0);
			pkt_len = m->data_len;
			finfo->mbuf = m;

			frags = m->nb_segs - 1;
			j = 1;
			m = m->next;
			while (frags--) {
				finfo->g.sg[(j >> 2)].ptr[(j & 3)] =
						rte_mbuf_data_iova(m);
				set_sg_size(&finfo->g.sg[(j >> 2)],
						m->data_len, (j & 3));
				pkt_len += m->data_len;
				j++;
				m = m->next;
			}
			dptr = rte_mem_virt2iova(finfo->g.sg);
			iqreq_buf = finfo;
			iqreq_type = OTX_EP_REQTYPE_NORESP_GATHER;
			if (pkt_len > OTX_EP_MAX_PKT_SZ) {
				rte_free(finfo->g.sg);
				rte_free(finfo);
				otx_ep_err("failed\n");
				goto xmit_fail;
			}
		}
		/* ih vars */
		iqcmd.ih.s.tlen = pkt_len + iqcmd.ih.s.fsz;
		iqcmd.ih.s.gather = gather;
		iqcmd.ih.s.gsz = gsz;
		/* PKI_IH3 vars */
		/* irh vars */
		//irh.rlenssz = ;

		iqcmd.dptr = dptr;
		/* Swap FSZ(front data) here, to avoid swapping on OCTEON TX side */
		/* rprt is not used so not swapping */
		//otx_ep_swap_8B_data(&iqcmd.rptr, 1);
		otx_ep_swap_8B_data(&iqcmd.irh.u64, 1);

		/*otx_ep_dbg("After swapping\n");
		otx_ep_dbg("Word0 [dptr]: 0x%016lx\n", (unsigned long)iqcmd.dptr);
		otx_ep_dbg("Word1 [ihtx]: 0x%016lx\n", (unsigned long)iqcmd.ih);
		otx_ep_dbg("Word2 [pki_ih3]: 0x%016lx\n", (unsigned long)iqcmd.pki_ih3);
		otx_ep_dbg("Word3 [rptr]: 0x%016lx\n", (unsigned long)iqcmd.rptr);
		otx_ep_dbg("Word4 [irh]: 0x%016lx\n", (unsigned long)iqcmd.irh);
		otx_ep_dbg("Word5 [exhdr[0]]: 0x%016lx\n",
				(unsigned long)iqcmd.exhdr[0]);
		*/
		//rte_pktmbuf_dump(stdout, m, rte_pktmbuf_pkt_len(m));
		otx_ep_iqreq_add(iq, iqreq_buf, iqreq_type);
		dbell = (i == (unsigned)(nb_pkts - 1)) ? 1:0;
		if (otx_ep_send_data(otx_ep, iq, &iqcmd, dbell)) {
			otx_ep_dbg("Data send failled :");
			iq->req_list[iq->host_write_index].buf = NULL;
			iq->req_list[iq->host_write_index].reqtype = 0;
			goto xmit_fail;
		}
		iq->stats.tx_pkts++;
		iq->stats.tx_bytes += pkt_len;
		count++;
	}

xmit_fail:
	if (rte_atomic64_read(&iq->instr_pending) >= (iq->nb_desc / 2))
		otx_ep_flush_iq(otx_ep, iq);

	/* Return no# of instructions posted successfully. */
	return count;

}
/* Enqueue requests/packets to OTX_EP IQ queue.
 * returns number of requests enqueued successfully
 */
uint16_t
otx2_ep_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts)
{
	struct otx2_ep_instr_64B iqcmd2;
	struct otx_ep_instr_queue *iq;
	struct otx_ep_device *otx_ep;
	uint64_t dptr;
	int count = 0;
	unsigned int i;
	struct rte_mbuf *m;
	unsigned int pkt_len;
	void *iqreq_buf;
	uint32_t iqreq_type;
	int gather, gsz;
	int dbell;

	iq = (struct otx_ep_instr_queue *)tx_queue;
	otx_ep = iq->otx_ep_dev;

	if (!otx_ep->started || !otx_ep->linkup) {
		goto xmit_fail;
	}

	iqcmd2.ih.u64 = 0;
	iqcmd2.irh.u64 = 0;

	/* ih invars */
	iqcmd2.ih.s.fsz = 24;
	iqcmd2.ih.s.pkind = otx_ep->pkind; /* The SDK decided PKIND value */
	/* irh invars */
	iqcmd2.irh.s.opcode = OTX_EP_NW_PKT_OP;

    //EC96:
    uint64_t mtu_limit;


	for (i = 0; i < nb_pkts; i++) {
		m = pkts[i];

        //TSO offload ? use max pkt len : use mtu len
        mtu_limit = (m->ol_flags & PKT_TX_TCP_SEG) ? OTX_EP_MAX_PKT_SZ :
                   (uint64_t)(OTX2_EP_MTU2PKT_SIZE(otx_ep->eth_dev->data->mtu));

        if (rte_pktmbuf_pkt_len(m) > mtu_limit) {
      //      otx_ep_err("failed pkt_len[%u] over max_pkt_len[%lu]\n",
       //                  rte_pktmbuf_pkt_len(m), mtu_limit);
            goto xmit_fail;
        }

	
		if (m->nb_segs == 1) {
			/* dptr */
			dptr = rte_mbuf_data_iova(m);
			pkt_len = rte_pktmbuf_data_len(m);
			iqreq_buf = m;
			iqreq_type = OTX_EP_REQTYPE_NORESP_NET;
			gather = 0;
			gsz = 0;
		} else {
			struct otx_ep_buf_free_info *finfo;
			int j, frags, num_sg;

			if (!(otx_ep->tx_offloads & DEV_TX_OFFLOAD_MULTI_SEGS))
				goto xmit_fail;

			finfo = (struct otx_ep_buf_free_info *)rte_malloc(NULL,
									  sizeof(*finfo),
										  0);
			if (finfo == NULL) {
				otx_ep_err("free buffer alloc failed\n");
				goto xmit_fail;
			}
			num_sg = (m->nb_segs + 3)/4;
			finfo->g.sg = rte_zmalloc(NULL, (sizeof(struct otx_ep_sg_entry)
					   * num_sg), OTX_EP_SG_ALIGN);
			if (finfo->g.sg == NULL) {
				rte_free(finfo);
				otx_ep_err("sg entry alloc failed\n");
				goto xmit_fail;
			}
			gather = 1;
			gsz = m->nb_segs;
			finfo->g.num_sg = num_sg;
			finfo->g.sg[0].ptr[0] = rte_mbuf_data_iova(m);
			set_sg_size(&finfo->g.sg[0], m->data_len, 0);
			pkt_len = m->data_len;
			finfo->mbuf = m;

			frags = m->nb_segs - 1;
			j = 1;
			m = m->next;
			while (frags--) {
				finfo->g.sg[(j >> 2)].ptr[(j & 3)] =
						rte_mbuf_data_iova(m);
				set_sg_size(&finfo->g.sg[(j >> 2)],
						m->data_len, (j & 3));
				pkt_len += m->data_len;
				j++;
				m = m->next;
			}
			dptr = rte_mem_virt2iova(finfo->g.sg);
			iqreq_buf = finfo;
			iqreq_type = OTX_EP_REQTYPE_NORESP_GATHER;
		}
		/* ih vars */
		iqcmd2.ih.s.tlen = pkt_len + iqcmd2.ih.s.fsz;
		iqcmd2.ih.s.gather = gather;
		iqcmd2.ih.s.gsz = gsz;
		/* irh vars */
		//irh.rlenssz = ;
		iqcmd2.dptr = dptr;
		/* Swap FSZ(front data) here, to avoid swapping on OCTEON TX side */
		// rptr is not used so not swapping.
		//otx_ep_swap_8B_data(&iqcmd2.rptr, 1);
		otx_ep_swap_8B_data(&iqcmd2.irh.u64, 1);

		/*otx_ep_dbg("After swapping\n");
		otx_ep_dbg("Word0 [dptr]: 0x%016lx\n", (unsigned long)iqcmd.dptr);
		otx_ep_dbg("Word1 [ihtx]: 0x%016lx\n", (unsigned long)iqcmd.ih);
		otx_ep_dbg("Word2 [pki_ih3]: 0x%016lx\n", (unsigned long)iqcmd.pki_ih3);
		otx_ep_dbg("Word3 [rptr]: 0x%016lx\n", (unsigned long)iqcmd.rptr);
		otx_ep_dbg("Word4 [irh]: 0x%016lx\n", (unsigned long)iqcmd.irh);
		otx_ep_dbg("Word5 [exhdr[0]]: 0x%016lx\n",
				(unsigned long)iqcmd.exhdr[0]);
		*/
		//rte_pktmbuf_dump(stdout, m, rte_pktmbuf_pkt_len(m));
		otx_ep_iqreq_add(iq, iqreq_buf, iqreq_type);
		dbell = (i == (unsigned)(nb_pkts - 1)) ? 1:0;
		if (otx_ep_send_data(otx_ep, iq, &iqcmd2, dbell)) {
			otx_ep_dbg("Data send failled :");
			iq->req_list[iq->host_write_index].buf = NULL;
			iq->req_list[iq->host_write_index].reqtype = 0;
			goto xmit_fail;
		}
		iq->stats.tx_pkts++;
		iq->stats.tx_bytes += pkt_len;
		count++;
	}

xmit_fail:
	if (rte_atomic64_read(&iq->instr_pending) >= (iq->nb_desc / 2))
		otx_ep_flush_iq(otx_ep, iq);

	/* Return no# of instructions posted successfully. */
	return count;

}

static uint32_t
otx_ep_droq_refill(struct otx_ep_droq *droq)
{
	struct otx_ep_droq_desc *desc_ring;
	uint32_t desc_refilled = 0;
	struct rte_mbuf *buf = NULL;
	struct otx_ep_droq_info *info;

	desc_ring = droq->desc_ring;

	while (droq->refill_count && (desc_refilled < droq->nb_desc)) {
		/* If a valid buffer exists (happens if there is no dispatch),
		 * reuse the buffer, else allocate.
		 */
		if (droq->recv_buf_list[droq->refill_idx] != NULL)
			break;

		buf = rte_pktmbuf_alloc(droq->mpool);
		/* If a buffer could not be allocated, no point in
		 * continuing
		 */
		if (buf == NULL) {
			droq->stats.rx_alloc_failure++;
			break;
		}
		info = rte_pktmbuf_mtod(buf, struct otx_ep_droq_info *);
		memset(info, 0, sizeof(*info));

		droq->recv_buf_list[droq->refill_idx] = buf;
		desc_ring[droq->refill_idx].buffer_ptr = rte_mbuf_data_iova_default(buf);

#ifndef BUFPTR_ONLY_MODE
		/* Reset any previous values in the length field. */
		droq->info_list[droq->refill_idx].length = 0;
#endif

		droq->refill_idx = otx_ep_incr_index(droq->refill_idx, 1,
				droq->nb_desc);

		desc_refilled++;
		droq->refill_count--;

	}

	return desc_refilled;
}

static struct rte_mbuf *
otx_ep_droq_read_packet(struct otx_ep_device *otx_ep,
			struct otx_ep_droq *droq, int next_fetch)
{
	struct rte_net_hdr_lens hdr_lens;
	struct otx_ep_droq_info *info;
	struct otx_ep_droq_info *info2;
	uint32_t pkt_len = 0;
	uint64_t total_pkt_len;
	struct rte_mbuf *droq_pkt = NULL;
	struct rte_mbuf *droq_pkt2 = NULL;
	int next_idx;

	droq_pkt  = droq->recv_buf_list[droq->read_idx];
	droq_pkt2  = droq->recv_buf_list[droq->read_idx];
#ifndef BUFPTR_ONLY_MODE
	info = &droq->info_list[droq->read_idx];
#else
	info = rte_pktmbuf_mtod(droq_pkt, struct otx_ep_droq_info *);
	rte_rmb();
	if(unlikely(!((volatile struct otx_ep_droq_info *)info->length))) {
		int retry = 10;

		otx_ep_dbg("OCTEON DROQ[%d]: read_idx: %d; Data not ready yet, "
			   "Retry; pending=%lu\n", droq->q_no, droq->read_idx,
			   rte_atomic64_read(&droq->pkts_pending));
		droq->stats.pkts_delayed_data++;
		while (retry-- && unlikely(
			!(volatile struct otx_ep_droq_info *)info->length));
		if (!retry && unlikely(!info->length)) {
			otx_ep_err("OCTEON DROQ[%d]: read_idx: %d; Retry failed !!\n",
				   droq->q_no, droq->read_idx);
			/* May be zero length packet; drop it */
			rte_pktmbuf_free(droq_pkt);
			droq->recv_buf_list[droq->read_idx] = NULL;
			droq->read_idx = otx_ep_incr_index(droq->read_idx, 1,/* count */
						droq->nb_desc /* max rd idx */);
			droq->stats.dropped_zlp++;
			droq->refill_count++;
			goto oq_read_fail;
		}
	}
	if (next_fetch) {
		next_idx = otx_ep_incr_index(droq->read_idx, 1, droq->nb_desc);
		droq_pkt2  = droq->recv_buf_list[next_idx];
		info2 = rte_pktmbuf_mtod(droq_pkt2, struct otx_ep_droq_info *);
		rte_prefetch_non_temporal((const void *)info2);
	}
#endif

	otx_ep_swap_8B_data((uint64_t *)&info->length, 1);
	if (!info->length) {
		otx_ep_err("OQ info_list->length[%ld]", (long)info->length);
		goto oq_read_fail;
	}

	/* Deduce the actual data size */
	total_pkt_len = info->length + INFO_SIZE;
	if (total_pkt_len <= droq->buffer_size) {
		info->length -= OTX_EP_RH_SIZE;
		droq_pkt  = droq->recv_buf_list[droq->read_idx];
		if (likely(droq_pkt != NULL)) {
			droq_pkt->data_off += OTX_EP_DROQ_INFO_SIZE;
			otx_ep_dbg("OQ: pkt_len[%ld], buffer_size %d\n",
				(long)info->length, droq->buffer_size);
			pkt_len = (uint32_t)info->length;
			droq_pkt->pkt_len  = pkt_len;
			droq_pkt->data_len  = pkt_len;
			droq_pkt->port = otx_ep->port_id;
			droq->recv_buf_list[droq->read_idx] = NULL;
			droq->read_idx = otx_ep_incr_index(droq->read_idx, 1,/* count */
						droq->nb_desc /* max rd idx */);
			droq->refill_count++;
		}
	} else {
		struct rte_mbuf *first_buf = NULL;
		struct rte_mbuf *last_buf = NULL;

		while (pkt_len < total_pkt_len) {
			int cpy_len = 0;

			cpy_len = ((pkt_len + droq->buffer_size) >
					total_pkt_len)
					? ((uint32_t)total_pkt_len -
						pkt_len)
					: droq->buffer_size;

			droq_pkt = droq->recv_buf_list[droq->read_idx];
			droq->recv_buf_list[droq->read_idx] = NULL;

			if (likely(droq_pkt != NULL)) {
				/* Note the first seg */
				if (!pkt_len)
					first_buf = droq_pkt;

				droq_pkt->port = otx_ep->port_id;
				if (!pkt_len) {
					droq_pkt->data_off += OTX_EP_DROQ_INFO_SIZE;
					droq_pkt->pkt_len = cpy_len - OTX_EP_DROQ_INFO_SIZE;
					droq_pkt->data_len = cpy_len - OTX_EP_DROQ_INFO_SIZE;
				} else {
					droq_pkt->pkt_len = cpy_len;
					droq_pkt->data_len = cpy_len;
				}

				if (pkt_len) {
					first_buf->nb_segs++;
					first_buf->pkt_len += droq_pkt->pkt_len;
				}

				if (last_buf)
					last_buf->next = droq_pkt;

				last_buf = droq_pkt;
			} else {
				otx_ep_err("no buf\n");
			}

			pkt_len += cpy_len;
			droq->read_idx = otx_ep_incr_index(droq->read_idx, 1,/* count */
						droq->nb_desc /* max rd idx */);
			droq->refill_count++;
		}
		droq_pkt = first_buf;
	}
	droq_pkt->packet_type = rte_net_get_ptype(droq_pkt, &hdr_lens,
					RTE_PTYPE_ALL_MASK);
	droq_pkt->l2_len = hdr_lens.l2_len;
	droq_pkt->l3_len = hdr_lens.l3_len;
	droq_pkt->l4_len = hdr_lens.l4_len;


    //EC96
    uint64_t mtu_limit;
    
    mtu_limit = OTX2_EP_MTU2PKT_SIZE(otx_ep->eth_dev->data->mtu);

	if ((droq_pkt->pkt_len > mtu_limit) &&
	    !(otx_ep->rx_offloads & DEV_RX_OFFLOAD_JUMBO_FRAME)) {

       // otx_ep_err("OQ: pkt_len[%u] over max_pkt_len[%lu]\n", 
         //            droq_pkt->pkt_len, mtu_limit);
		rte_pktmbuf_free(droq_pkt);
		goto oq_read_fail;
	}

	if ((droq_pkt->nb_segs > 1) &&
	    !(otx_ep->rx_offloads & DEV_RX_OFFLOAD_SCATTER)) {
		rte_pktmbuf_free(droq_pkt);
		goto oq_read_fail;
	}

	return droq_pkt;

oq_read_fail:
	return NULL;
}

static inline uint32_t
otx_ep_check_droq_pkts(struct otx_ep_droq *droq, uint32_t burst_size)
{
	uint32_t min_pkts = 0;
	uint32_t new_pkts;
	uint32_t pkt_count;

	/* Latest available OQ packets */
	pkt_count = rte_read32(droq->pkts_sent_reg);

	/* Newly arrived packets */
	new_pkts = pkt_count - droq->last_pkt_count;
	//otx_ep_dbg("Recvd [%d] new OQ pkts\n", new_pkts);

	min_pkts = (new_pkts > burst_size) ? burst_size : new_pkts;
	if (min_pkts) {
		rte_atomic64_add(&droq->pkts_pending, min_pkts);
		/* Back up the aggregated packet count so far */
		droq->last_pkt_count += min_pkts;
	}

	return min_pkts;
}

/* Check for response arrival from OCTEON TX2
 * returns number of requests completed
 */
uint16_t
otx_ep_recv_pkts(void *rx_queue,
		  struct rte_mbuf **rx_pkts,
		  uint16_t budget)
{
	struct rte_mbuf *oq_pkt;
	struct otx_ep_device *otx_ep;
	struct otx_ep_droq *droq = rx_queue;

	uint32_t q_no = 0, pkts = 0;
	uint32_t new_pkts = 0;
	int next_fetch;

	otx_ep = droq->otx_ep_dev;

	if (!otx_ep->started || !otx_ep->linkup) {
		return 0;
	}

	droq = otx_ep->droq[q_no];
	if (!droq) {
		otx_ep_err("Invalid droq[%d]\n", q_no);
		goto finish;
	}

	/* Grab the lock */
	rte_spinlock_lock(&droq->lock);

	new_pkts = otx_ep_check_droq_pkts(droq, budget);
	if (!new_pkts) {
		//otx_ep_dbg("Zero new_pkts:%d\n", new_pkts);
		goto update_credit; /* No pkts at this moment */
	}

	//otx_ep_dbg("Received new_pkts = %d\n", new_pkts);

	for (pkts = 0; pkts < new_pkts; pkts++) {

		/* Push the received pkt to application */
		next_fetch = (pkts == new_pkts - 1) ? 0 : 1;
		oq_pkt = otx_ep_droq_read_packet(otx_ep, droq, next_fetch);
		if (!oq_pkt) {
			otx_ep_err("DROQ read pkt failed.\n");
			droq->stats.rx_err++;
			goto finish;
		}
		//rte_pktmbuf_dump(stdout, oq_pkt, rte_pktmbuf_pkt_len(oq_pkt));
		rx_pkts[pkts] = oq_pkt;
		/* Stats */
		droq->stats.pkts_received++;
		droq->stats.bytes_received += oq_pkt->pkt_len;
	}

	/* Ack the h/w with no# of pkts read by Host */
	rte_wmb();
	rte_write32(pkts, droq->pkts_sent_reg);

	droq->last_pkt_count -= pkts;

	//otx_ep_dbg("DROQ pkts[%d] pushed to application\n", pkts);

	/* Refill DROQ buffers */
	//if (droq->refill_count >= 2 /* droq->refill_threshold */) {
update_credit:
	if (droq->refill_count >= droq->refill_threshold) {
		int desc_refilled = otx_ep_droq_refill(droq);

		/* Flush the droq descriptor data to memory to be sure
		 * that when we update the credits the data in memory is
		 * accurate.
		 */
		rte_wmb();
		rte_write32(desc_refilled, droq->pkts_credit_reg);
		//otx_ep_dbg("Refilled count = %d\n", desc_refilled);
	} else {
		/*
		 * SDP output goes into DROP state when output doorbell count
		 * goes below drop count. When door bell count is written with
		 * a value greater than drop count SDP output should come out
		 * of DROP state. Due to a race condition this is not happening.
		 * Writing doorbell register with 0 again may make SDP output
		 * come out of this state.
		 */

		rte_write32(0, droq->pkts_credit_reg);
	}
finish:
	/* Release the spin lock */
	rte_spinlock_unlock(&droq->lock);

	return pkts;

}
