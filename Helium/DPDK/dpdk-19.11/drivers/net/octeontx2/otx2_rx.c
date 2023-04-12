/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <rte_vect.h>

#include "otx2_ethdev.h"
#include "otx2_rx.h"

#define NIX_DESCS_PER_LOOP	4
#define CQE_CAST(x)		((struct nix_cqe_hdr_s *)(x))
#define CQE_SZ(x)		((x) * NIX_CQ_ENTRY_SZ)

/**
 * add for sdp device
 */
static bool
otx2_eth_dev_is_sdp(struct rte_pci_device *pci_dev)
{
    if (pci_dev->id.device_id == PCI_DEVID_OCTEONTX2_RVU_SDP_PF ||
        pci_dev->id.device_id == PCI_DEVID_OCTEONTX2_RVU_SDP_VF)
        return true;
    return false;
}

static __rte_always_inline void
neon_memcpy64(void *dst, void *src)
{
#if defined(RTE_ARCH_ARM64)
	__asm__ volatile ("ldp q1,q2,[%0]      "::"r"(src));
	__asm__ volatile ("ldp q3,q4,[%0 , #32]"::"r"(src));
	__asm__ volatile ("stp q1,q2,[%0]      "::"r"(dst));
	__asm__ volatile ("stp q3,q4,[%0 , #32]"::"r"(dst));
#else
	RTE_SET_USED(dst);
	RTE_SET_USED(src);
#endif
}

static inline uint16_t
nix_rx_nb_pkts_vwqe(struct otx2_eth_rxq *rxq, const uint64_t wdata,
	       const uint16_t pkts, const uint32_t qmask)
{
	uint32_t available = rxq->available;

	/* Update the available count if cached value is not enough */
	if (unlikely(available < pkts)) {
		uint64_t reg, tail;
		/* Use LDADDA version to avoid reorder */
		reg = otx2_atomic64_add_sync(wdata, rxq->cq_status);
		/* CQ_OP_STATUS operation error */
		if (reg & BIT_ULL(CQ_OP_STAT_OP_ERR) ||
		    reg & BIT_ULL(CQ_OP_STAT_CQ_ERR))
			return 0;

		tail = reg & 0xFFFFF;
		if (tail < rxq->head)
			available = tail - (rxq->head) + qmask + 1;
		else
			available = tail - (rxq->head);

		rxq->available = available;
	}

	return RTE_MIN(pkts, available);
}

static inline uint16_t
nix_rx_nb_pkts(struct otx2_eth_rxq *rxq, const uint64_t wdata,
	       const uint16_t pkts, const uint32_t qmask)
{
	uint32_t available = rxq->available;

	/* Update the available count if cached value is not enough */
	if (unlikely(available < pkts)) {
		uint64_t reg, head, tail;

		/* Use LDADDA version to avoid reorder */
		reg = otx2_atomic64_add_sync(wdata, rxq->cq_status);
		/* CQ_OP_STATUS operation error */
        if (reg & BIT_ULL(CQ_OP_STAT_OP_ERR) ||
            reg & BIT_ULL(CQ_OP_STAT_CQ_ERR))
            return 0;

		tail = reg & 0xFFFFF;
		head = (reg >> 20) & 0xFFFFF;
		if (tail < head)
			available = tail - head + qmask + 1;
		else
			available = tail - head;

		rxq->available = available;
	}

	return RTE_MIN(pkts, available);
}

static __rte_always_inline uint16_t
nix_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	      uint16_t pkts, const uint16_t flags)
{
	struct otx2_eth_rxq *rxq = rx_queue;
	const uint64_t mbuf_init = rxq->mbuf_initializer;
	const void *lookup_mem = rxq->lookup_mem;
	const uint64_t data_off = rxq->data_off;
	const uintptr_t desc = rxq->desc;
	const uint64_t wdata = rxq->wdata;
	const uint32_t qmask = rxq->qmask;
	uint16_t packets = 0, nb_pkts;
	uint32_t head = rxq->head;
	struct nix_cqe_hdr_s *cq;
	struct rte_mbuf *mbuf;
	uint8_t sdp_device = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(rxq->eth_dev);

	if(otx2_eth_dev_is_sdp(pci_dev))
	{
		sdp_device = 1;
	}

	nb_pkts = nix_rx_nb_pkts(rxq, wdata, pkts, qmask);

	while (packets < nb_pkts) {
		/* Prefetch N desc ahead */
		rte_prefetch_non_temporal((void *)(desc +
					(CQE_SZ((head + 2) & qmask))));
		cq = (struct nix_cqe_hdr_s *)(desc + CQE_SZ(head));

		mbuf = nix_get_mbuf_from_cqe(cq, data_off);

		otx2_nix_cqe_to_mbuf(cq, cq->tag, mbuf, lookup_mem, mbuf_init,
				     flags);
		otx2_nix_mbuf_to_tstamp(mbuf, rxq->tstamp, flags,
				(uint64_t *)((uint8_t *)mbuf + data_off));
		//printf("###mbuf len %d, data_len %d, nb_segs %d\n", mbuf->pkt_len, mbuf->data_len, mbuf->nb_segs);
		//rte_pktmbuf_dump(stdout, mbuf, mbuf->pkt_len);

		rx_pkts[packets++] = mbuf;
		if(sdp_device)
		{
			rte_pktmbuf_adj(rx_pkts[packets-1], CVM_RAW_FRONT_SIZE);
			rx_pkts[packets-1]->l2_len -= CVM_RAW_FRONT_SIZE;
		}
		//otx2_prefetch_store_keep(mbuf);
		otx2_prefetch_store_keep(rx_pkts[packets-1]);
		head++;
		head &= qmask;
	}

	rxq->head = head;
	rxq->available -= nb_pkts;

	/* Free all the CQs that we've processed */
	otx2_write64((wdata | nb_pkts), rxq->cq_door);

	return nb_pkts;
}

static __rte_always_inline uint16_t
nix_recv_pkts_vlib(void *rx_queue, struct rte_mbuf **rx_pkts,
                   uint16_t pkts, const uint16_t flags)
{
    dpdk_otx2_per_thread_data_t *ptd =
                 (dpdk_otx2_per_thread_data_t *)((rx_pkts) - (256 - pkts));
    struct otx2_eth_rxq *rxq = rx_queue;
    const uint64_t mbuf_init = rxq->mbuf_initializer;
    const uint64_t data_off = rxq->data_off;
    const uint16_t *lookup_mem = rxq->lookup_mem;
    const uintptr_t desc = rxq->desc;
    const uint64_t wdata = rxq->wdata;
    const uint32_t qmask = rxq->qmask;
    uint16_t packets = 0, nb_pkts;
    uint32_t head = rxq->head;
    struct nix_cqe_hdr_s *cq;
    const struct nix_rx_parse_s *rx;
    const int64_t curr_data = ((mbuf_init) & 0XFFFF) - RTE_PKTMBUF_HEADROOM;
    dpdk_vlib_buffer_t *vbuf;
    uint8_t sdp_device = 0;
    struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(rxq->eth_dev);
    struct rte_mbuf *v2d_buf = 0;

    if (otx2_eth_dev_is_sdp(pci_dev)) {
        sdp_device = 1;
    }

    nb_pkts = nix_rx_nb_pkts(rxq, wdata, pkts, qmask);

    while (packets < nb_pkts) {
        /* Prefetch N desc ahead */
        rte_prefetch_non_temporal((void *)(desc + (CQE_SZ(head + 2))));
        cq = (struct nix_cqe_hdr_s *)(desc + CQE_SZ(head));
        vbuf = nix_get_vlib_from_cqe(cq, data_off);
        v2d_buf = nix_get_mbuf_from_cqe(cq, data_off);

        otx2_nix_cqe_to_mbuf(cq, cq->tag, v2d_buf, lookup_mem, mbuf_init,
                             flags);
        rx = (const struct nix_rx_parse_s *)((const uint64_t *)cq + 1);
        vlib_update_ol_flags(*(const uint64_t *)rx, &ptd->rx_or_flags,
                              lookup_mem, flags);
        neon_memcpy64(vbuf, &ptd->buffer_template);
        ptd->rx_n_bytes += vbuf->current_length = rx->pkt_lenm1 + 1;
        vbuf->current_data = curr_data;
        rx_pkts[packets++] = (struct rte_mbuf *)vbuf;

        if(sdp_device) {
            vbuf->current_data += CVM_RAW_FRONT_SIZE;
            vbuf->current_length -= CVM_RAW_FRONT_SIZE;
            ptd->rx_n_bytes -= CVM_RAW_FRONT_SIZE;
            // NIX_DESC_SZ ?->  nix_get_vlib_from_cqe
            v2d_buf =(struct rte_mbuf *)(
                          ((char*)(rx_pkts[packets-1] - 1)) - NIX_DESC_SZ);
            rte_pktmbuf_adj(v2d_buf, CVM_RAW_FRONT_SIZE);
            v2d_buf->l2_len -= CVM_RAW_FRONT_SIZE;
        }

        head++;
        head &= qmask;
    }

    rxq->head = head;
    rxq->available -= nb_pkts;

    /* Free all the CQs that we've processed */
    otx2_write64((wdata | nb_pkts), rxq->cq_door);

    return nb_pkts;
}

static __rte_always_inline uint16_t
nix_recv_pkts_vwqe(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t pkts, const uint16_t flags)
{
	struct otx2_eth_rxq *rxq = rx_queue;
	const uint64_t wdata = rxq->wdata;
	const uint32_t qmask = rxq->qmask;
	uint16_t nb_pkts = 0;

	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(flags);

	nb_pkts = nix_rx_nb_pkts_vwqe(rxq, wdata, pkts, qmask);

	return nb_pkts;
}
#if defined(RTE_ARCH_ARM64)

static __rte_always_inline uint64_t
nix_vlan_update(const uint64_t w2, uint64_t ol_flags, uint8x16_t *f)
{
	if (w2 & BIT_ULL(21) /* vtag0_gone */) {
		ol_flags |= PKT_RX_VLAN | PKT_RX_VLAN_STRIPPED;
		*f = vsetq_lane_u16((uint16_t)(w2 >> 32), *f, 5);
	}

	return ol_flags;
}

static __rte_always_inline uint64_t
nix_qinq_update(const uint64_t w2, uint64_t ol_flags, struct rte_mbuf *mbuf)
{
	if (w2 & BIT_ULL(23) /* vtag1_gone */) {
		ol_flags |= PKT_RX_QINQ | PKT_RX_QINQ_STRIPPED;
		mbuf->vlan_tci_outer = (uint16_t)(w2 >> 48);
	}

	return ol_flags;
}

static __rte_always_inline uint16_t
nix_recv_pkts_vector(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t pkts, const uint16_t flags)
{
	struct otx2_eth_rxq *rxq = rx_queue; uint16_t packets = 0;
	uint64x2_t cq0_w8, cq1_w8, cq2_w8, cq3_w8, mbuf01, mbuf23;
	const uint64_t mbuf_initializer = rxq->mbuf_initializer;
	const uint64x2_t data_off = vdupq_n_u64(rxq->data_off);
	uint64_t ol_flags0, ol_flags1, ol_flags2, ol_flags3;
	uint64x2_t rearm0 = vdupq_n_u64(mbuf_initializer);
	uint64x2_t rearm1 = vdupq_n_u64(mbuf_initializer);
	uint64x2_t rearm2 = vdupq_n_u64(mbuf_initializer);
	uint64x2_t rearm3 = vdupq_n_u64(mbuf_initializer);
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3;
	const uint16_t *lookup_mem = rxq->lookup_mem;
	const uint32_t qmask = rxq->qmask;
	const uint64_t wdata = rxq->wdata;
	const uintptr_t desc = rxq->desc;
	uint8x16_t f0, f1, f2, f3;
	uint32_t head = rxq->head;
	uint16_t pkts_left;
	uint8_t sdp_device = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(rxq->eth_dev);

	if(otx2_eth_dev_is_sdp(pci_dev))
	{
		sdp_device = 1;
	}

	pkts = nix_rx_nb_pkts(rxq, wdata, pkts, qmask);
	pkts_left = pkts & (NIX_DESCS_PER_LOOP - 1);

	/* Packets has to be floor-aligned to NIX_DESCS_PER_LOOP */
	pkts = RTE_ALIGN_FLOOR(pkts, NIX_DESCS_PER_LOOP);

	while (packets < pkts) {
		/* Exit loop if head is about to wrap */
		if (((head + NIX_DESCS_PER_LOOP - 1) & qmask) <
				NIX_DESCS_PER_LOOP) {
			pkts_left += (pkts - packets);
			break;
		}

		const uintptr_t cq0 = desc + CQE_SZ(head);

		/* Prefetch N desc ahead */
		rte_prefetch_non_temporal((void *)(cq0 + CQE_SZ(8)));
		rte_prefetch_non_temporal((void *)(cq0 + CQE_SZ(9)));
		rte_prefetch_non_temporal((void *)(cq0 + CQE_SZ(10)));
		rte_prefetch_non_temporal((void *)(cq0 + CQE_SZ(11)));

		/* Get NIX_RX_SG_S for size and buffer pointer */
		cq0_w8 = vld1q_u64((uint64_t *)(cq0 + CQE_SZ(0) + 64));
		cq1_w8 = vld1q_u64((uint64_t *)(cq0 + CQE_SZ(1) + 64));
		cq2_w8 = vld1q_u64((uint64_t *)(cq0 + CQE_SZ(2) + 64));
		cq3_w8 = vld1q_u64((uint64_t *)(cq0 + CQE_SZ(3) + 64));

		/* Extract mbuf from NIX_RX_SG_S */
		mbuf01 = vzip2q_u64(cq0_w8, cq1_w8);
		mbuf23 = vzip2q_u64(cq2_w8, cq3_w8);
		mbuf01 = vqsubq_u64(mbuf01, data_off);
		mbuf23 = vqsubq_u64(mbuf23, data_off);

		/* Move mbufs to scalar registers for future use */
		mbuf0 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 0);
		mbuf1 = (struct rte_mbuf *)vgetq_lane_u64(mbuf01, 1);
		mbuf2 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 0);
		mbuf3 = (struct rte_mbuf *)vgetq_lane_u64(mbuf23, 1);

		/* Mask to get packet len from NIX_RX_SG_S */
		const uint8x16_t shuf_msk = {
			0xFF, 0xFF,   /* pkt_type set as unknown */
			0xFF, 0xFF,   /* pkt_type set as unknown */
			0, 1,         /* octet 1~0, low 16 bits pkt_len */
			0xFF, 0xFF,   /* skip high 16 bits pkt_len, zero out */
			0, 1,         /* octet 1~0, 16 bits data_len */
			0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF
			};

		/* Form the rx_descriptor_fields1 with pkt_len and data_len */
		f0 = vqtbl1q_u8(cq0_w8, shuf_msk);
		f1 = vqtbl1q_u8(cq1_w8, shuf_msk);
		f2 = vqtbl1q_u8(cq2_w8, shuf_msk);
		f3 = vqtbl1q_u8(cq3_w8, shuf_msk);

		/* Load CQE word0 and word 1 */
		uint64_t cq0_w0 = ((uint64_t *)(cq0 + CQE_SZ(0)))[0];
		uint64_t cq0_w1 = ((uint64_t *)(cq0 + CQE_SZ(0)))[1];
		uint64_t cq1_w0 = ((uint64_t *)(cq0 + CQE_SZ(1)))[0];
		uint64_t cq1_w1 = ((uint64_t *)(cq0 + CQE_SZ(1)))[1];
		uint64_t cq2_w0 = ((uint64_t *)(cq0 + CQE_SZ(2)))[0];
		uint64_t cq2_w1 = ((uint64_t *)(cq0 + CQE_SZ(2)))[1];
		uint64_t cq3_w0 = ((uint64_t *)(cq0 + CQE_SZ(3)))[0];
		uint64_t cq3_w1 = ((uint64_t *)(cq0 + CQE_SZ(3)))[1];

		if (flags & NIX_RX_OFFLOAD_RSS_F) {
			/* Fill rss in the rx_descriptor_fields1 */
			f0 = vsetq_lane_u32(cq0_w0, f0, 3);
			f1 = vsetq_lane_u32(cq1_w0, f1, 3);
			f2 = vsetq_lane_u32(cq2_w0, f2, 3);
			f3 = vsetq_lane_u32(cq3_w0, f3, 3);
			ol_flags0 = PKT_RX_RSS_HASH;
			ol_flags1 = PKT_RX_RSS_HASH;
			ol_flags2 = PKT_RX_RSS_HASH;
			ol_flags3 = PKT_RX_RSS_HASH;
		} else {
			ol_flags0 = 0; ol_flags1 = 0;
			ol_flags2 = 0; ol_flags3 = 0;
		}

		if (flags & NIX_RX_OFFLOAD_PTYPE_F) {
			/* Fill packet_type in the rx_descriptor_fields1 */
			f0 = vsetq_lane_u32(nix_ptype_get(lookup_mem, cq0_w1),
					    f0, 0);
			f1 = vsetq_lane_u32(nix_ptype_get(lookup_mem, cq1_w1),
					    f1, 0);
			f2 = vsetq_lane_u32(nix_ptype_get(lookup_mem, cq2_w1),
					    f2, 0);
			f3 = vsetq_lane_u32(nix_ptype_get(lookup_mem, cq3_w1),
					    f3, 0);
		}

		if (flags & NIX_RX_OFFLOAD_CHECKSUM_F) {
			ol_flags0 |= nix_rx_olflags_get(lookup_mem, cq0_w1);
			ol_flags1 |= nix_rx_olflags_get(lookup_mem, cq1_w1);
			ol_flags2 |= nix_rx_olflags_get(lookup_mem, cq2_w1);
			ol_flags3 |= nix_rx_olflags_get(lookup_mem, cq3_w1);
		}

		if (flags & NIX_RX_OFFLOAD_VLAN_STRIP_F) {
			uint64_t cq0_w2 = *(uint64_t *)(cq0 + CQE_SZ(0) + 16);
			uint64_t cq1_w2 = *(uint64_t *)(cq0 + CQE_SZ(1) + 16);
			uint64_t cq2_w2 = *(uint64_t *)(cq0 + CQE_SZ(2) + 16);
			uint64_t cq3_w2 = *(uint64_t *)(cq0 + CQE_SZ(3) + 16);

			ol_flags0 = nix_vlan_update(cq0_w2, ol_flags0, &f0);
			ol_flags1 = nix_vlan_update(cq1_w2, ol_flags1, &f1);
			ol_flags2 = nix_vlan_update(cq2_w2, ol_flags2, &f2);
			ol_flags3 = nix_vlan_update(cq3_w2, ol_flags3, &f3);

			ol_flags0 = nix_qinq_update(cq0_w2, ol_flags0, mbuf0);
			ol_flags1 = nix_qinq_update(cq1_w2, ol_flags1, mbuf1);
			ol_flags2 = nix_qinq_update(cq2_w2, ol_flags2, mbuf2);
			ol_flags3 = nix_qinq_update(cq3_w2, ol_flags3, mbuf3);
		}

		if (flags & NIX_RX_OFFLOAD_MARK_UPDATE_F) {
			ol_flags0 = nix_update_match_id(*(uint16_t *)
				    (cq0 + CQE_SZ(0) + 38), ol_flags0, mbuf0);
			ol_flags1 = nix_update_match_id(*(uint16_t *)
				    (cq0 + CQE_SZ(1) + 38), ol_flags1, mbuf1);
			ol_flags2 = nix_update_match_id(*(uint16_t *)
				    (cq0 + CQE_SZ(2) + 38), ol_flags2, mbuf2);
			ol_flags3 = nix_update_match_id(*(uint16_t *)
				    (cq0 + CQE_SZ(3) + 38), ol_flags3, mbuf3);
		}

		/* Form rearm_data with ol_flags */
		rearm0 = vsetq_lane_u64(ol_flags0, rearm0, 1);
		rearm1 = vsetq_lane_u64(ol_flags1, rearm1, 1);
		rearm2 = vsetq_lane_u64(ol_flags2, rearm2, 1);
		rearm3 = vsetq_lane_u64(ol_flags3, rearm3, 1);

		/* Update rx_descriptor_fields1 */
		vst1q_u64((uint64_t *)mbuf0->rx_descriptor_fields1, f0);
		vst1q_u64((uint64_t *)mbuf1->rx_descriptor_fields1, f1);
		vst1q_u64((uint64_t *)mbuf2->rx_descriptor_fields1, f2);
		vst1q_u64((uint64_t *)mbuf3->rx_descriptor_fields1, f3);

		/* Update rearm_data */
		vst1q_u64((uint64_t *)mbuf0->rearm_data, rearm0);
		vst1q_u64((uint64_t *)mbuf1->rearm_data, rearm1);
		vst1q_u64((uint64_t *)mbuf2->rearm_data, rearm2);
		vst1q_u64((uint64_t *)mbuf3->rearm_data, rearm3);

		/* Store the mbufs to rx_pkts */
		vst1q_u64((uint64_t *)&rx_pkts[packets], mbuf01);
		vst1q_u64((uint64_t *)&rx_pkts[packets + 2], mbuf23);

		if(sdp_device)
		{
			rte_pktmbuf_adj(rx_pkts[packets], CVM_RAW_FRONT_SIZE);
			rte_pktmbuf_adj(rx_pkts[packets+1], CVM_RAW_FRONT_SIZE);
			rte_pktmbuf_adj(rx_pkts[packets+2], CVM_RAW_FRONT_SIZE);
			rte_pktmbuf_adj(rx_pkts[packets+3], CVM_RAW_FRONT_SIZE);
			rx_pkts[packets]->l2_len -= CVM_RAW_FRONT_SIZE;
			rx_pkts[packets+1]->l2_len -= CVM_RAW_FRONT_SIZE;
			rx_pkts[packets+2]->l2_len -= CVM_RAW_FRONT_SIZE;
			rx_pkts[packets+3]->l2_len -= CVM_RAW_FRONT_SIZE;
		}

		/* Prefetch mbufs */
		//otx2_prefetch_store_keep(mbuf0);
		//otx2_prefetch_store_keep(mbuf1);
		//otx2_prefetch_store_keep(mbuf2);
		//otx2_prefetch_store_keep(mbuf3);
		otx2_prefetch_store_keep(rx_pkts[packets]);
		otx2_prefetch_store_keep(rx_pkts[packets+1]);
		otx2_prefetch_store_keep(rx_pkts[packets+2]);
		otx2_prefetch_store_keep(rx_pkts[packets+3]);

		/* Mark mempool obj as "get" as it is alloc'ed by NIX */
		__mempool_check_cookies(mbuf0->pool, (void **)&mbuf0, 1, 1);
		__mempool_check_cookies(mbuf1->pool, (void **)&mbuf1, 1, 1);
		__mempool_check_cookies(mbuf2->pool, (void **)&mbuf2, 1, 1);
		__mempool_check_cookies(mbuf3->pool, (void **)&mbuf3, 1, 1);

		/* Advance head pointer and packets */
		head += NIX_DESCS_PER_LOOP; head &= qmask;
		packets += NIX_DESCS_PER_LOOP;
	}

	rxq->head = head;
	rxq->available -= packets;

	rte_cio_wmb();
	/* Free all the CQs that we've processed */
	otx2_write64((rxq->wdata | packets), rxq->cq_door);

	if (unlikely(pkts_left))
		packets += nix_recv_pkts(rx_queue, &rx_pkts[packets],
					 pkts_left, flags);

	return packets;
}



static __rte_always_inline uint16_t
nix_recv_pkts_vlib_vector(void *rx_queue, struct rte_mbuf **rx_pkts,
			uint16_t pkts, const uint16_t flags)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(pkts);
	RTE_SET_USED(flags);

	return 0;
}

#else

static inline uint16_t
nix_recv_pkts_vector(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t pkts, const uint16_t flags)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(pkts);
	RTE_SET_USED(flags);

	return 0;
}

static inline uint16_t
nix_recv_pkts_vlib_vector(void *rx_queue, struct rte_mbuf **rx_pkts,
			uint16_t pkts, const uint16_t flags)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(pkts);
	RTE_SET_USED(flags);

	return 0;
}
#endif

#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			       \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_ ## name(void *rx_queue,				       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	return nix_recv_pkts(rx_queue, rx_pkts, pkts, (flags));		       \
}									       \
									       \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_mseg_ ## name(void *rx_queue,			       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	return nix_recv_pkts(rx_queue, rx_pkts, pkts,			       \
			     (flags) | NIX_RX_MULTI_SEG_F);		       \
}									       \
									       \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_vec_ ## name(void *rx_queue,				       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	/* TSTMP is not supported by vector */				       \
	if ((flags) & NIX_RX_OFFLOAD_TSTAMP_F)				       \
		return 0;						       \
	return nix_recv_pkts_vector(rx_queue, rx_pkts, pkts, (flags));	       \
}									       \
									       \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_vlib_ ## name(void *rx_queue,			       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	return nix_recv_pkts_vlib(rx_queue, rx_pkts, pkts, (flags));    \
}									       \
									       \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_vlib_vec_ ## name(void *rx_queue,			       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	/* TSTMP is not supported by vector */				       \
	if ((flags) & NIX_RX_OFFLOAD_TSTAMP_F)				       \
		return 0;						       \
	return nix_recv_pkts_vlib_vector(rx_queue, rx_pkts, pkts, (flags));    \
}									       \
                                            \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_vlib_msg_ ## name(void *rx_queue,			       \
			struct rte_mbuf **rx_pkts, uint16_t pkts)	       \
{									       \
	return nix_recv_pkts_vlib(rx_queue, rx_pkts, pkts, \
                          (flags) | NIX_RX_MULTI_SEG_F);	       \
}                                                  \
                                                    \
static uint16_t __rte_noinline	__hot					       \
otx2_nix_recv_pkts_vwqe_ ## name(void *rx_queue,			       \
			struct rte_mbuf **rx_pkts,			       \
			uint16_t pkts)					       \
{									       \
	return nix_recv_pkts_vwqe(rx_queue, rx_pkts, pkts, (flags));	       \
}
NIX_RX_FASTPATH_MODES
#undef R

static inline void
pick_rx_func(struct rte_eth_dev *eth_dev,
	     const eth_rx_burst_t rx_burst[2][2][2][2][2][2][2])
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);

	/* [SEC] [TSTMP] [MARK] [VLAN] [CKSUM] [PTYPE] [RSS] */
	eth_dev->rx_pkt_burst = rx_burst
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_SECURITY_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_TSTAMP_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_MARK_UPDATE_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_VLAN_STRIP_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_CHECKSUM_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_PTYPE_F)]
		[!!(dev->rx_offload_flags & NIX_RX_OFFLOAD_RSS_F)];
}

void
otx2_eth_set_rx_function(struct rte_eth_dev *eth_dev)
{
	struct otx2_eth_dev *dev = otx2_eth_pmd_priv(eth_dev);

	const eth_rx_burst_t nix_eth_rx_burst[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_burst_mseg[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_mseg_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_vec_burst[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_vec_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_vlib[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_vlib_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_vlib_vec[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_vlib_vec_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_vlib_msg[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_vlib_msg_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	const eth_rx_burst_t nix_eth_rx_vwqe[2][2][2][2][2][2][2] = {
#define R(name, f6, f5, f4, f3, f2, f1, f0, flags)			\
	[f6][f5][f4][f3][f2][f1][f0] =  otx2_nix_recv_pkts_vwqe_ ## name,

NIX_RX_FASTPATH_MODES
#undef R
	};

	if (dev->vwqe_sim_enable) {
		pick_rx_func(eth_dev, nix_eth_rx_vwqe);
	} else if (dev->vlib_enable) {
		if (dev->scalar_ena) {
			pick_rx_func(eth_dev, nix_eth_rx_vlib);
		} else {
			pick_rx_func(eth_dev, nix_eth_rx_vlib_vec);
		}
        if (dev->rx_offloads & DEV_RX_OFFLOAD_SCATTER) {
            pick_rx_func(eth_dev, nix_eth_rx_vlib_msg);
        }
	} else {
	/* For PTP enabled, scalar rx function should be chosen as most of the
	 * PTP apps are implemented to rx burst 1 pkt.
	 */
	if (dev->scalar_ena || dev->rx_offloads & DEV_RX_OFFLOAD_TIMESTAMP)
	{
		//otx2_err("nix_eth_rx_burst\n");
		pick_rx_func(eth_dev, nix_eth_rx_burst);
	}
	else
	{
		//otx2_err("nix_eth_rx_vec_burst\n");
		pick_rx_func(eth_dev, nix_eth_rx_vec_burst);
	}

	if (dev->rx_offloads & DEV_RX_OFFLOAD_SCATTER)
	{
		//otx2_err("nix_eth_rx_burst_mseg\n");
		pick_rx_func(eth_dev, nix_eth_rx_burst_mseg);
	}

	/* Copy multi seg version with no offload for tear down sequence */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
	{
		//otx2_err("no offload nix_eth_rx_burst_mseg\n");
		dev->rx_pkt_burst_no_offload =
			nix_eth_rx_burst_mseg[0][0][0][0][0][0][0];
	}
	}

	rte_mb();
}
