/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
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

#endif
