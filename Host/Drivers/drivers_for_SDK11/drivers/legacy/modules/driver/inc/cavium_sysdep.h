/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cavium_sysdep.h
    \brief Host Driver: This file pulls in the OS-dependent header files.
*/

#ifndef _CAVIUM_SYSDEP_H
#define _CAVIUM_SYSDEP_H

#ifndef __CAVIUM_LITTLE_ENDIAN
#define __CAVIUM_LITTLE_ENDIAN 1234
#endif

#ifndef __CAVIUM_BIG_ENDIAN
#define __CAVIUM_BIG_ENDIAN	4321
#endif

#ifdef CUSTOM_OS
#include "custom_sysdep.h"
#else /* CUSTOM_OS */
#ifdef linux
#ifdef USER_DRV
#include "linux_user_sysdep.h"
#else
#include "linux_sysdep.h"
#endif /* USER_DRV */
#elif defined(__FreeBSD__)
#include "../freebsd/freebsd_sysdep.h"
#elif defined (_WIN32)
#include "..\windows\windows_sysdep.h"
#endif /* linux */
#endif /* !CUSTOM_OS */

#endif /* _CAVIUM_SYSDEP_H */

/* $Id: cavium_sysdep.h 141410 2016-06-30 14:37:41Z mchalla $ */
