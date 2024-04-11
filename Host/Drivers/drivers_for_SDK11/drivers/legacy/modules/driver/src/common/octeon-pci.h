/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __OCTEON_PCI_H__
#define __OCTEON_PCI_H__

enum octeon_pcie_mps {
	PCIE_MPS_DEFAULT = -1,	/* Use the default setup by BIOS */
	PCIE_MPS_128B = 0,
	PCIE_MPS_256B = 1
};

enum octeon_pcie_mrrs {
	PCIE_MRRS_DEFAULT = -1,	/* Use the default setup by BIOS */
	PCIE_MRRS_128B = 0,
	PCIE_MRRS_256B = 1,
	PCIE_MRRS_512B = 2,
	PCIE_MRRS_1024B = 3,
	PCIE_MRRS_2048B = 4,
	PCIE_MRRS_4096B = 5
};

#define FW_STATUS_READY         1ULL
#define FW_STATUS_RUNNING	2ULL
#endif
