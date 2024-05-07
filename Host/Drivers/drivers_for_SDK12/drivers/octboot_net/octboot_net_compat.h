/* SPDX-License-Identifier: GPL-2.0 */
/*
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
#define NAPI_ADD_HAS_BUDGET_ARG 0
#else
#define NAPI_ADD_HAS_BUDGET_ARG 1
#endif
#define USE_ETHER_ADDR_COPY
#define NO_SKB_XMIT_MORE
#else
#error "RHEL versions before rhel-8.4 not supported !!!"
#endif

#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
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
#endif

#endif /* _OCTEP_COMPAT_H_ */
