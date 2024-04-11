/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef  __CVM_LINUX_TYPES_H__
#define  __CVM_LINUX_TYPES_H__
#include "octeon_compat.h"


#define   OCTEON_READ32(addr)            readl(addr)
#define   OCTEON_WRITE32(addr, val)      writel((val),(addr))
#define   OCTEON_READ16(addr)            readw(addr)
#define   OCTEON_WRITE16(addr, val)      writew((val),(addr))
#define   OCTEON_READ8(addr)             readb(addr)
#define   OCTEON_WRITE8(addr, val)       writeb((val),(addr))
#ifdef    readq
#define   OCTEON_READ64(addr)            readq(addr)
#endif
#ifdef    writeq
#define   OCTEON_WRITE64(addr, val)      writeq((val),(addr))
#endif

#define OCTEON_READ_PCI_CONFIG(dev, offset, pvalue)      \
          pci_read_config_dword((dev)->pci_dev, (offset),(pvalue))

#define OCTEON_WRITE_PCI_CONFIG(dev, offset, value)      \
          pci_write_config_dword((dev)->pci_dev, (offset),(value))

#endif
