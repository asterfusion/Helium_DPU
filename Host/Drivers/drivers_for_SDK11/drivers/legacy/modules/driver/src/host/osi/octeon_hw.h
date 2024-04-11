/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  octeon_hw.h
    \brief Host Driver: PCI read/write routines and default register values.
*/

#ifndef __OCTEON_HW_H__
#define __OCTEON_HW_H__

#include "octeon_main.h"
#include "octeon_device.h"
#include "octeon_reg_defs.h"

static inline uint16_t OCTEON_MAJOR_REV(octeon_device_t * oct)
{
	uint16_t rev = (oct->rev_id & 0xC) >> 2;

	return (rev == 0) ? 1 : rev;
}

static inline uint16_t OCTEON_MINOR_REV(octeon_device_t * oct)
{
	return (oct->rev_id & 0x3);
}

#define   octeon_write_csr(oct_dev, reg_off, value) \
		{ \
			cavium_print(PRINT_REGS, "octeon_write_csr: reg: 0x%08lx val: 0x%08lx\n", (unsigned long)reg_off, (unsigned long)value); \
			OCTEON_WRITE32((uint8_t*)oct_dev->mmio[0].hw_addr + reg_off, value); \
		}

#define   octeon_write_csr64(oct_dev, reg_off, val64) \
		{ \
			cavium_print(PRINT_REGS, "octeon_write_csr64: reg: 0x%08lx val: 0x%016llx\n", (unsigned long)reg_off, (uint64_t)val64); \
			OCTEON_WRITE64((uint8_t*)oct_dev->mmio[0].hw_addr + reg_off, val64); \
		}

#define   octeon_read_csr(oct_dev, reg_off)         \
		({ \
			uint32_t  val=OCTEON_READ32((uint8_t*)oct_dev->mmio[0].hw_addr + reg_off);\
			cavium_print(PRINT_REGS, "octeon_read_csr: reg: 0x%08lx val: 0x%08lx\n",(unsigned long) reg_off, (unsigned long)val); \
			val;\
		})

#define   octeon_read_csr64(oct_dev, reg_off)         \
		({ \
			uint64_t  val64 = OCTEON_READ64((uint8_t*)oct_dev->mmio[0].hw_addr + reg_off);\
			cavium_print(PRINT_REGS, "octeon_read_csr64: reg: 0x%08lx val: 0x%016llx\n", (unsigned long)reg_off, (uint64_t)val64); \
		  val64;\
		})

/** Read windowed register.
 *  @param  oct   -  pointer to the Octeon device.
 *  @param  addr  -  Address of the register to read.
 * 
 *  This routine is called to read from the indirectly accessed
 *  Octeon registers that are visible through a PCI BAR0 mapped window
 *  register.
 *  @return  - 64 bit value read from the register.
 */

static inline uint64_t OCTEON_PCI_WIN_READ(octeon_device_t * oct, uint64_t addr)
{
	uint64_t val64;

	if (OCTEON_CN83XX_PF_OR_VF(oct->chip_id))
		addr |= 1ull << 49; /* read 8 bytes */
	else
		addr |= 1ull << 53; /* read 8 bytes */

	OCTEON_WRITE64(oct->reg_list.pci_win_rd_addr, addr);
	val64 = OCTEON_READ64(oct->reg_list.pci_win_rd_data);

	cavium_print(PRINT_REGS,
		     "OCTEON_PCI_WIN_READ: reg: 0x%016llx val: 0x%016llx\n",
		     addr, val64);

	return val64;
}

/** Write windowed register.
 *  @param  oct  -  pointer to the Octeon device.
 *  @param  addr -  Address of the register to write
 *  @param  val  -  Value to write 
 * 
 *  This routine is called to write to the indirectly accessed
 *  Octeon registers that are visible through a PCI BAR0 mapped window
 *  register.
 *  @return   Nothing.
 */
static inline void
OCTEON_PCI_WIN_WRITE(octeon_device_t * oct, uint64_t addr, uint64_t val)
{
	OCTEON_WRITE64(oct->reg_list.pci_win_wr_addr, addr);

	OCTEON_WRITE64(oct->reg_list.pci_win_wr_data, val);

	cavium_print(PRINT_REGS,
		     "OCTEON_PCI_WIN_WRITE: reg: 0x%016llx val: 0x%016llx\n",
		     addr, val);
}

#define   CN3XXX_DEVICE_IN_PCIX_MODE(oct_dev)       \
      (octeon_read_csr(oct_dev, PCI_CTL_STATUS_2) & PCI_CTL_STATUS_2_PCIX_MODE)

#endif /* __OCTEON_HW_H__ */
/* $Id: octeon_hw.h 162991 2017-07-20 10:18:44Z mchalla $ */
