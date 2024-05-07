/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell Octeon EP (EndPoint) Ethernet Driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#ifndef _OCTEP_COMPAT_H_
#define _OCTEP_COMPAT_H_

#include <linux/version.h>

#if defined(RHEL_RELEASE_CODE)
#if (RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(8,4))
#define TX_TIMEOUT_HAS_TXQ_ARG 1
#if (RHEL_RELEASE_VERSION(8, 9) <= RHEL_RELEASE_CODE)
#define NO_SET_GSO_API
#endif
#if (RHEL_RELEASE_VERSION(8, 9) <= RHEL_RELEASE_CODE)
#define NAPI_ADD_HAS_BUDGET_ARG 0
#else
#define NAPI_ADD_HAS_BUDGET_ARG 1
#endif
#define USE_ETHER_ADDR_COPY
#define NO_SKB_XMIT_MORE
#else
#error "RHEL versions before rhel-8.4 not supported !!!"
#endif
#if (RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(8, 4))
#ifdef CONFIG_PCIE_PTM
int pci_enable_ptm(struct pci_dev *dev, u8 *granularity);
#endif
#endif

#else
#if KERNEL_VERSION(5, 2, 0) <= LINUX_VERSION_CODE
#define NO_SKB_XMIT_MORE
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#define TX_TIMEOUT_HAS_TXQ_ARG 1
#else
#define TX_TIMEOUT_HAS_TXQ_ARG 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,1,0)
#define NAPI_ADD_HAS_BUDGET_ARG 1
#else
#define NAPI_ADD_HAS_BUDGET_ARG 0
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,15,0)
#define USE_ETHER_ADDR_COPY
#else
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)) && \
	(LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0))
#ifdef CONFIG_PCIE_PTM
int pci_enable_ptm(struct pci_dev *dev, u8 *granularity);
#endif
#endif
#if KERNEL_VERSION(5, 19, 0) <= LINUX_VERSION_CODE
#define NO_SET_GSO_API
#endif
#endif

#endif /* _OCTEP_COMPAT_H_ */
