/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file linux_sysdep.h
    \brief Host Driver: This file has linux-specific definitions for macros and
                        inline routines used in the Octeon driver.
 */

#ifndef _LINUX_SYSDEP_H
#define _LINUX_SYSDEP_H

#define UNUSED  __attribute__((unused))

#define __NO_VERSION__
#include <linux/version.h>


#ifndef MODULE
#define MODULE
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cpumask.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <asm/byteorder.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <linux/pci.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/ipv6.h>
#include <asm/div64.h>
#include <linux/kthread.h>
#include <linux/sched/signal.h>

#include "cvm_linux_types.h"

#define     OCTEON_VENDOR_ID               0x177D
#define     OCTEON_DEVICE_MAJOR            127
#define     DRIVER_NAME                    "Octeon"

#ifdef __LITTLE_ENDIAN
#define  ENDIAN_MESG  "Little endian"
#else
#define  ENDIAN_MESG  "Big endian"
#endif

/* Gives up the CPU for a timeout period.  */
#define   cavium_sleep_timeout(timeout)     \
    {                                           \
        set_current_state(TASK_INTERRUPTIBLE);  \
        schedule_timeout(timeout);              \
        set_current_state(TASK_RUNNING);        \
    }

static inline int
atomic_check_and_sub(int val, atomic_t *ptr, char *file,
			    int line)
{
	if ((atomic_read((ptr)) - val) < 0) {
		printk(KERN_ERR "OCTEON: %s:%d Underflow in atomic value (%d) (attempt to subtract %d)\n",
		     file, line, atomic_read((ptr)), val);
		return 1;
	}
	atomic_sub((val), (ptr));
	return 0;
}

static inline int
atomic_check_and_dec(atomic_t *ptr, char *file, int line)
{
	if ((atomic_read((ptr)) - 1) < 0) {
		printk(KERN_ERR "OCTEON: %s:%d Underflow in atomic value (%d)\n",
			     file, line, atomic_read((ptr)));
		return 1;
	}
	atomic_dec((ptr));
	return 0;
}

static inline int
atomic_check_and_inc(atomic_t *ptr, int check_val, char *file,
			    int line)
{
	if ((atomic_read((ptr)) + 1) > check_val) {
		printk(KERN_ERR "OCTEON: %s:%d Overflow in atomic value (%d) (max: %d)\n",
		     file, line, atomic_read((ptr)), check_val);
		return 1;
	}
	atomic_inc((ptr));
	return 0;
}

static inline int
atomic_check_and_add(int val, atomic_t *ptr, int check_val,
			    char *file, int line)
{
	if ((atomic_read((ptr)) + val) > check_val) {
		printk(KERN_ERR "OCTEON: %s:%d Overflow in atomic value (%d) (attempt to add %d, max: %d)\n",
		     file, line, atomic_read((ptr)), val, check_val);
		return 1;
	}
	atomic_add((val), (ptr));
	return 0;
}

static inline unsigned long
cavium_div64(unsigned long long x, unsigned long long y, unsigned long *r)
{
	unsigned long mod;

	/* do_div puts result of x/y in x and remainder is returned. */
	mod = do_div(x, y);
	*r = x;
	return mod;
}


#if !defined(readq)
static inline uint64_t OCTEON_READ64(void *addr)
{
	uint64_t val64;
	val64 = readl(addr + 4);
	val64 = (val64 << 32) | readl(addr);
	return val64;
}
#endif

#if !defined(writeq)
static inline void OCTEON_WRITE64(void *addr, uint64_t val)
{
	writel((uint32_t) (val & 0xffffffff), addr);
	writel((val >> 32), ((uint8_t *) addr + 4));
}
#endif

#define   spin_lock_destroy(lock)          do { } while (0)

#define octeon_assign_dev_name(oct)         \
    sprintf( ((oct)->device_name), "Octeon%d", ((oct)->octeon_id))

#endif /* _LINUX_SYSDEP_H */
