/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_CNXK_EMDEV_DMA_H__
#define __INCLUDE_CNXK_EMDEV_DMA_H__

#include <rte_mempool.h>
#include <rte_vect.h>

#include "cnxk_emdev.h"

#define DPI_DMA_64B_MAX_POINTERS 4
#define DPI_DMA_64B_MAX_NFST	 (DPI_DMA_64B_MAX_POINTERS - 1)
#define DPI_DMA_64B_MAX_NLST	 (DPI_DMA_64B_MAX_POINTERS - 1)

/**
 * Wait till all DMA instructions are completed
 * Called from non-data path core
 */
static __rte_always_inline int
cnxk_emdev_dma_compl_wait(struct cnxk_emdev_dpi_q *q, uint16_t tmo_ms)
{
	uint16_t wr_idx = plt_read64(q->widx_r) & 0xFFF;

	/* No pending in-flight instructions */
	while (!((plt_read64(q->ridx_r) >> 63) && (q->compl_idx == wr_idx))) {
		tmo_ms--;
		if (!tmo_ms)
			return -EFAULT;
		rte_delay_us_sleep(1000);
	}

	return 0;
}

/**
 * Get available space in DMA vchan state
 */
static __rte_always_inline uint16_t
cnxk_emdev_dma_avail(struct cnxk_emdev_dpi_q *q, uint16_t *idx)
{
	uint16_t widx = plt_read64(q->widx_r) & 0xFFF;
	uint16_t compl_idx = q->compl_idx;
	uint16_t q_sz = ROC_EMDEV_DPI_Q_SZ;
	uint16_t used;

	used = widx >= compl_idx ? widx - compl_idx : widx + q_sz - compl_idx;
	*idx = widx & 0xFFF;
	return q_sz - used;
}

static __rte_always_inline uint16_t
cnxk_emdev_dma_inst_idx(struct cnxk_emdev_dpi_q *q)
{
	uint64_t widx = plt_read64(q->widx_r);

	return widx & 0xFFF;
}

static __rte_always_inline uint64_t *
cnxk_emdev_dma_inst_addr(uint64_t *base, uint16_t idx)
{
	/* Assuming 64B instruction size */
	return base + (idx << 3);
}

static __rte_always_inline uint64_t *
cnxk_emdev_dma_compl_addr(uint64_t *base, uint16_t idx)
{
	/* Assuming 128B completion addr */
	return base + (idx << 4);
}

static __rte_always_inline uint64_t *
cnxk_emdev_dma_ptr_addr(uint64_t *base, uint16_t idx)
{
	/* Assuming 64B instruction size, return pointer to DPI_DMA_PTR_S */
	return cnxk_emdev_dma_inst_addr(base, idx) + 2;
}

static __rte_always_inline uint16_t
cnxk_emdev_dma_next_idx(uint16_t idx)
{
	return (idx + 1) & (ROC_EMDEV_DPI_Q_SZ - 1);
}

/**
 * Enqueue one DMA pointer pair.
 *
 */
static __rte_always_inline void
cnxk_emdev_dma_enq_x1(uint64_t *inst_base, uint64_t *compl_base, uint64_t mdata, rte_iova_t src,
		      rte_iova_t dst, uint16_t len)
{
	uint64_t w0 = (1ULL << 63 | (mdata & 0x1FFFUL) << 12 | ((mdata >> 32) << 30));
	uint64_t fp_l = (mdata >> 13) & 0x1UL;
	uint64_t fp_h = (mdata >> 14) & 0x1UL;

	/* DPI_DMA_64B_INSTR_HDR_S */
	inst_base[0] = w0 | 0x11UL;
	inst_base[1] = (uintptr_t)compl_base;
	inst_base[2] = (uint64_t)len << 32 | len | (fp_h << 63) | (fp_l << 31);
	inst_base[3] = src;
	inst_base[4] = dst;

	*(uint8_t *)compl_base = 0xFF;
}

/**
 * Enqueue DMA M:N src:dest pointers
 */
static __rte_always_inline void
cnxk_emdev_dma_enq_xn(uint64_t *inst_base, uint64_t *compl_base, uint64_t mdata, rte_iova_t *src,
		      rte_iova_t *dst, uint8_t num, uint32_t *slen, uint32_t *dlen)
{
	uint64_t w0 = (1ULL << 63 | (mdata & 0x1FFFUL) << 12 | ((mdata >> 32) << 30));
	uint8_t idx = 3, sidx = 0, didx = 0, lidx = 0;
	uint64_t fp_l = (mdata >> 13) & 0x1UL;
	uint64_t fp_h = (mdata >> 14) & 0x1UL;
	uint8_t nb_src = num & 0xF;
	uint8_t nb_dst = num >> 4;
	uint16_t lens[4] = {0};

	if (unlikely(((nb_src + nb_dst) > 4) || (nb_src > 3) || (nb_dst > 3)))
		return;

	/* DPI_DMA_64B_INSTR_HDR_S */
	inst_base[0] = w0 | ((nb_dst & 0x3) << 4) | (nb_src & 0x3);
	inst_base[1] = (uintptr_t)compl_base;

	while (nb_src) {
		lens[lidx++] = slen[sidx];
		inst_base[idx] = src[sidx++];
		idx = (idx == 4) ? 6 : idx + 1; /* Ensure we don't overflow */
		nb_src--;
	}

	while (nb_dst) {
		lens[lidx++] = dlen[didx];
		inst_base[idx] = dst[didx++];
		idx = (idx == 4) ? 6 : idx + 1; /* Ensure we don't overflow */
		nb_dst--;
	}

	inst_base[2] = (uint64_t)lens[1] << 32 | lens[0] | (fp_h << 63) | (fp_l << 31);
	fp_l = (mdata >> 15) & 0x1UL;
	fp_h = (mdata >> 16) & 0x1UL;
	inst_base[5] = (uint64_t)lens[3] << 32 | lens[2] | (fp_h << 63) | (fp_l << 31);

	*(uint8_t *)compl_base = 0xFF;
}

#if defined(RTE_ARCH_ARM64)
/**
 * Enqueue multiple DMA pointers in src-dest single seg pairs.
 */
static __rte_always_inline void
cnxk_emdev_dma_enq_x2(uint64_t *inst_base, uint64_t *compl_base, uint64_t mdata, uint64x2_t *vsrc,
		      uint64x2_t *vdst, uint8_t nsrc, uint8_t ndst)
{
	PLT_SET_USED(inst_base);
	PLT_SET_USED(compl_base);
	PLT_SET_USED(mdata);
	PLT_SET_USED(vsrc);
	PLT_SET_USED(vdst);
	PLT_SET_USED(nsrc);
	PLT_SET_USED(ndst);
}
#endif

#endif /* __INCLUDE_CNXK_EMDEV_DMA_H__ */
