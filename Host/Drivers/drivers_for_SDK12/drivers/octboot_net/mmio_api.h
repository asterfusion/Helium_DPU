/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/* Mgmt ethernet driver
 */

#ifndef __MMIO_API_H_
#define __MMIO_API_H_

static inline void mmio_memset(void __iomem *mmio_addr, int val, int size)
{
	uint8_t __iomem *baddr;

	baddr = (uint8_t *)mmio_addr;
	while (size--) {
		writeb_relaxed(val, baddr);
		baddr++;
	}
	wmb();
}

static inline void mmio_memread(void *laddr, void const  __iomem *mmio_addr,
				int size)
{
	uint64_t __iomem *qaddr;
	uint8_t __iomem *baddr;
	int alignl, alignr;
	uint64_t *lqaddr;
	uint8_t *lbaddr;

	alignl = (uint64_t)laddr % 8;
	alignr = (uint64_t)mmio_addr % 8;
	qaddr = (uint64_t *)mmio_addr;
	lqaddr = (uint64_t *)laddr;
	if (alignl == 0 && alignr == 0) {
		while (size >= 8) {
			*lqaddr = readq_relaxed(qaddr);
			size -= 8;
			lqaddr++;
			qaddr++;
		}
	}
	baddr = (uint8_t *)qaddr;
	lbaddr = (uint8_t *)lqaddr;
	while (size--) {
		*lbaddr = readb_relaxed(baddr);
		baddr++;
		lbaddr++;
	}
	rmb();
}

static inline void mmio_memwrite(void __iomem *mmio_addr, void const *laddr,
				 int size)
{
	uint64_t __iomem *qaddr;
	uint8_t __iomem *baddr;
	int alignl, alignr;
	uint64_t *lqaddr;
	uint8_t *lbaddr;

	alignl = (uint64_t)laddr % 8;
	alignr = (uint64_t)mmio_addr % 8;
	qaddr = (uint64_t *)mmio_addr;
	lqaddr = (uint64_t *)laddr;
	if (alignl == 0 && alignr == 0) {
		while (size >= 8) {
			writeq_relaxed(*lqaddr, qaddr);
			size -= 8;
			lqaddr++;
			qaddr++;
		}
	}
	baddr = (uint8_t *)qaddr;
	lbaddr = (uint8_t *)lqaddr;
	while (size--) {
		writeb_relaxed(*lbaddr, baddr);
		baddr++;
		lbaddr++;
	}
	wmb();
}

#endif /* _MMIO_API_ */
