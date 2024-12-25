// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "common.h"
#include "mbox.h"
#include "rvu.h"
#include "cgx.h"

int rvu_tim_lookup_rsrc(struct rvu *rvu, struct rvu_block *block,
			u16 pcifunc, int slot)
{
	int lf, blkaddr;
	u64 val;

	/* Due to a HW issue LF_CFG_DEBUG register cannot be used to
	 * find PF_FUNC <=> LF mapping, hence scan through LFX_CFG
	 * registers to find mapped LF for a given PF_FUNC.
	 */
	if (is_rvu_96xx_B0(rvu)) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
		if (blkaddr < 0)
			return TIM_AF_LF_INVALID;

		for (lf = 0; lf < block->lf.max; lf++) {
			val = rvu_read64(rvu, block->addr, block->lfcfg_reg |
					 (lf << block->lfshift));
			if ((((val >> 8) & 0xffff) == pcifunc) &&
			    (val & 0xff) == slot)
				return lf;
		}
		return -1;
	}

	val = ((u64)pcifunc << 24) | (slot << 16) | (1ULL << 13);
	rvu_write64(rvu, block->addr, block->lookup_reg, val);

	/* Wait for the lookup to finish */
	while (rvu_read64(rvu, block->addr, block->lookup_reg) & (1ULL << 13))
		;

	val = rvu_read64(rvu, block->addr, block->lookup_reg);

	/* Check LF valid bit */
	if (!(val & (1ULL << 12)))
		return -1;

	return (val & 0xFFF);
}

void rvu_tim_hw_fixes(struct rvu *rvu, int blkaddr)
{
	u64 cfg;
	/* Due wrong clock gating, TIM expire counter is updated wrongly.
	 * Workaround is to enable force clock (FORCE_CSCLK_ENA = 1).
	 */
	cfg = rvu_read64(rvu, blkaddr, TIM_AF_FLAGS_REG);
	cfg |= BIT_ULL(1);
	rvu_write64(rvu, blkaddr, TIM_AF_FLAGS_REG, cfg);
}

bool rvu_tim_ptp_has_errata(struct pci_dev *pdev)
{
	if (pdev->subsystem_device == PCI_SUBSYS_DEVID_CN10K_A ||
	    pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_A ||
	    pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B)
		return true;
	return false;
}

u64 rvu_tim_ptp_rollover_errata_fix(struct rvu *rvu, u64 time)
{
	long offset = rvu_read64(rvu, BLKADDR_TIM, TIM_AF_ADJUST_PTP);
	u32 sec, nsec, max_nsec = NSEC_PER_SEC;

	sec = (u32)(time >> 32);
	nsec = (u32)time;

	if (!offset || nsec < max_nsec)
		return time;

	if (offset < 0) {
		nsec += max_nsec;
		sec -= 1;
	} else {
		nsec -= max_nsec;
		sec += 1;
	}

	return (u64)sec << 32 | nsec;
}

/* Due to an Hardware errata, in some corner cases, AQ context lock
 * operations can result in a NDC way getting into an illegal state
 * of not valid but locked.
 *
 * This API solves the problem by clearing the lock bit of the NDC block.
 * The operation needs to be done for each line of all the NDC banks.
 */
int rvu_ndc_fix_locked_cacheline(struct rvu *rvu, int blkaddr)
{
	int bank, max_bank, line, max_line, err;
	u64 reg;

	/* Set the ENABLE bit(63) to '0' */
	reg = rvu_read64(rvu, blkaddr, NDC_AF_CAMS_RD_INTERVAL);
	rvu_write64(rvu, blkaddr, NDC_AF_CAMS_RD_INTERVAL, reg & GENMASK_ULL(62, 0));

	/* Poll until the BUSY bits(47:32) are set to '0' */
	err = rvu_poll_reg(rvu, blkaddr, NDC_AF_CAMS_RD_INTERVAL, GENMASK_ULL(47, 32), true);
	if (err) {
		dev_err(rvu->dev, "Timed out while polling for NDC CAM busy bits.\n");
		return err;
	}

	max_bank = NDC_MAX_BANK(rvu, blkaddr);
	max_line = NDC_MAX_LINE_PER_BANK(rvu, blkaddr);
	for (bank = 0; bank < max_bank; bank++) {
		for (line = 0; line < max_line; line++) {
			/* Check if 'cache line valid bit(63)' is not set
			 * but 'cache line lock bit(60)' is set and on
			 * success, reset the lock bit(60).
			 */
			reg = rvu_read64(rvu, blkaddr,
					 NDC_AF_BANKX_LINEX_METADATA(bank, line));
			if (!(reg & BIT_ULL(63)) && (reg & BIT_ULL(60))) {
				rvu_write64(rvu, blkaddr,
					    NDC_AF_BANKX_LINEX_METADATA(bank, line),
					    reg & ~BIT_ULL(60));
			}
		}
	}

	return 0;
}
