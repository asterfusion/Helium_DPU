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

#ifdef __KERNEL__

#define __NO_VERSION__
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#include <linux/config.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#define NO_MQ_SUPPORT
#ifndef CONFIG_64BIT
#define atomic64_t atomic_t
#define atomic64_inc atomic_inc
#endif
#endif

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
#ifdef PCIE_AER
#include <linux/aer.h>
#endif
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/vmalloc.h>
#include <linux/ipv6.h>
#include <asm/div64.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/kthread.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif

#include "cvm_linux_types.h"

#define     OCTEON_VENDOR_ID               0x177D
#define     OCTEON_DEVICE_MAJOR            127
#define     DRIVER_NAME                    "Octeon"

#define     OCTEON_VF_DEVICE_MAJOR         126
#define     VF_DRIVER_NAME                 "Octeon_vf"

#define     OCTEON_REQ_INFO_CB             1
#define     MAX_OCTEON_LINKS               12

#ifdef __LITTLE_ENDIAN
#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
#else
#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
#endif

#if BITS_PER_LONG == 32
#define CVM_CAST64(v) ((long long)(v))
#elif BITS_PER_LONG == 64
#define CVM_CAST64(v) ((long long)(long)(v))
#else
#error "Unknown system architecture"
#endif

#if  __CAVIUM_BYTE_ORDER == __CAVIUM_LITTLE_ENDIAN
#define  ENDIAN_MESG  "Little endian"
#else
#define  ENDIAN_MESG  "Big endian"
#endif

/* Different buffer allocation types. */
#define  OCT_BUFFER_TYPE_1    1	/* Allocated using malloc etc */
#define  OCT_BUFFER_TYPE_2    2	/* Of type skb etc.. */
#define  OCT_BUFFER_TYPE_3    3	/* Allocated from the buffer pool */
#define  OCT_BUFFER_TYPE_4    4	/* Allocated using virtual memory calls */

/*cavium string fuction */
#define cavium_strcpy(dest,max_len,src) strcpy(dest,src)
#define cavium_strncpy(dest,max_len,src,n) strncpy(dest,src,n)
#define cavium_strcat(dest,max_len,src) strcat(dest,src)
#define cavium_strchr strchr
#define cavium_snprintf snprintf

#define   cavium_print_msg(format, ...)    printk( format, ## __VA_ARGS__)

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,9)
#define   cavium_error(format, ...)         \
    do {                                         \
        if(printk_ratelimit())                  \
            printk( format, ## __VA_ARGS__);    \
    } while(0)
#else
#define   cavium_error(format, ...) printk( format, ## __VA_ARGS__)

#endif

#define   CAVIUM_INTERNAL_TIME(tmsecs)            ((tmsecs * HZ)/1000)

/* Gives up the CPU for a timeout period.  */
#define   cavium_sleep_timeout(timeout)     \
    {                                           \
        set_current_state(TASK_INTERRUPTIBLE);  \
        schedule_timeout(timeout);              \
        set_current_state(TASK_RUNNING);        \
    }

/** Host: The different levels of debugging print messages available.
 * Enable debugging by compiling with CAVIUM_DEBUG set to one of these
 * values.
 */
typedef enum {
	PRINT_ERROR = 0,
	PRINT_MSG = 0,
	PRINT_REGS = 1,
	PRINT_DEBUG = 2,
	PRINT_FLOW = 3,
	PRINT_ALL = 4,
} OCTEON_DEBUG_LEVEL;

#ifdef CAVIUM_DEBUG

extern OCTEON_DEBUG_LEVEL octeon_debug_level;

#define  cavium_print(level, format, ...)         \
    {     if(level <= octeon_debug_level) printk( format, ## __VA_ARGS__); }
#else
#define  cavium_print(level, format, ...)       do { } while(0);
#endif

typedef enum {
	OCTEON_PROC_READ = 1,
	OCTEON_PROC_WRITE = 2,
} octeon_proc_type_t;

typedef int (proc_show_t) (struct seq_file * s, void *v);

typedef ssize_t(proc_write_new_t) (struct file * filp, const char __user * buf,
			       size_t count, loff_t * offp);

typedef struct {
	char name[20];
	mode_t attributes;
	proc_show_t *proc_show;
	proc_write_new_t *proc_write;
	octeon_proc_type_t type;
} octeon_proc_entry_t;

typedef struct {

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
	cavium_pid_t id;
#else
	cavium_ostask_t *id;
#endif

	int (*fn) (void *);

	void *fn_arg;

	char fn_string[80];

	int exec_on_create;

} cvm_kthread_t;

#define INIT_CVM_KTHREAD(pcvmthread)                     \
    (memset((pcvmthread), 0, sizeof(cvm_kthread_t)))

#define SET_CVM_KTHREAD_FN(pcvmthread, fn)               \
    ((pcvmthread)->fn = fn)

#define SET_CVM_KTHREAD_FN_ARG(pcvmthread, fn_arg)       \
    ((pcvmthread)->fn_arg = fn_arg)

#define SET_CVM_KTHREAD_FN_STRING(pcvmthread, fn_string) \
    do {                                                 \
        if(fn_string) {                                  \
            strcpy((pcvmthread)->fn_string,fn_string);   \
        }                                                \
    } while(0)

#define SET_CVM_KTHREAD_EXEC_ON_CREATE(pcvmthread)       \
    ((pcvmthread)->exec_on_create = 1)

static inline int
cavium_kthread_setup(cvm_kthread_t * t,
		     int (*fn) (void *),
		     void *fn_arg, char *fn_string, int exec_flag)
{
	SET_CVM_KTHREAD_FN(t, fn);
	SET_CVM_KTHREAD_FN_ARG(t, fn_arg);
	SET_CVM_KTHREAD_FN_STRING(t, fn_string);
	t->exec_on_create = exec_flag;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)

#define CVM_KTHREAD_EXISTS(pcvmthread)   ((pcvmthread)->id >= 0)

static inline int cavium_kthread_create(cvm_kthread_t * t)
{
	t->id =
	    kernel_thread(t->fn, t->fn_arg,
			  CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	return (t->id < 0);
}

static inline int cavium_kthread_signalled(void)
{
	return signal_pending(current);
}

static inline void cavium_kthread_destroy(cvm_kthread_t * t)
{
	if (t->id >= 0) {
		kill_proc(t->id, SIGTERM, 1);
	}
	t->id = -1;
}

static inline void cavium_kthread_set_cpu_affinity(cvm_kthread_t * t, int cpu)
{
	cavium_error("%s: Nothing implemented\n", __CVM_FUNCTION__);
}

static inline void cavium_kthread_run(cvm_kthread_t * t)
{
	cavium_error("%s: Nothing implemented\n", __CVM_FUNCTION__);
}

#else

#define CVM_KTHREAD_EXISTS(pcvmthread)   ((pcvmthread)->id)

static inline int cavium_kthread_create(cvm_kthread_t * t)
{

	t->id = kthread_create(t->fn, t->fn_arg, t->fn_string);
	if (t->id == NULL)
		return 1;

	if (t->exec_on_create)
		wake_up_process(t->id);

	return 0;
}

static inline int cavium_kthread_signalled(void)
{
	return kthread_should_stop();
}

static inline void cavium_kthread_destroy(cvm_kthread_t * t)
{
	if (t->id) {
		kthread_stop(t->id);
	}
	t->id = NULL;
}

static inline void cavium_kthread_set_cpu_affinity(cvm_kthread_t * t, int cpu)
{
	if (t->id) {
		kthread_bind(t->id, cpu);
	}
}

static inline void cavium_kthread_run(cvm_kthread_t * t)
{
	if (t->id) {
		wake_up_process(t->id);
	}
}

#endif

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
static inline void cavium_thread_daemonize(char *name)
{
	daemonize(name);
	allow_signal(SIGTERM);
}
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,15,0)
#define CVM_SET_ETHTOOL_OPS(netdev, ops)  (netdev->ethtool_ops = ops)
#else
#define CVM_SET_ETHTOOL_OPS(netdev, ops)  SET_ETHTOOL_OPS(netdev, ops)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,16,0)
#define cvm_alloc_netdev_mq(size, name, funptr, nq) \
	alloc_netdev_mq(size, name, NET_NAME_ENUM, funptr, nq)

#define cvm_alloc_netdev(size, name, funptr)  alloc_netdev(size, name, NET_NAME_ENUM, funptr)
#else
#define cvm_alloc_netdev_mq(size, name, funptr, nq) \
        alloc_netdev_mq(size, name, funptr, nq)

#define cvm_alloc_netdev(size, name, funptr)  alloc_netdev(size, name, funptr)
#endif

static inline int
cavium_atomic_check_and_sub(int val, cavium_atomic_t * ptr, char *file,
			    int line)
{
	if ((cavium_atomic_read((ptr)) - val) < 0) {
		cavium_error
		    ("OCTEON: %s:%d Underflow in atomic value (%d) (attempt to subtract %d)\n",
		     file, line, cavium_atomic_read((ptr)), val);
		return 1;
	}
	atomic_sub((val), (ptr));
	return 0;
}

static inline int
cavium_atomic_check_and_dec(cavium_atomic_t * ptr, char *file, int line)
{
	if ((cavium_atomic_read((ptr)) - 1) < 0) {
		cavium_error("OCTEON: %s:%d Underflow in atomic value (%d)\n",
			     file, line, cavium_atomic_read((ptr)));
		return 1;
	}
	atomic_dec((ptr));
	return 0;
}

static inline int
cavium_atomic_check_and_inc(cavium_atomic_t * ptr, int check_val, char *file,
			    int line)
{
	if ((cavium_atomic_read((ptr)) + 1) > check_val) {
		cavium_error
		    ("OCTEON: %s:%d Overflow in atomic value (%d) (max: %d)\n",
		     file, line, cavium_atomic_read((ptr)), check_val);
		return 1;
	}
	atomic_inc((ptr));
	return 0;
}

static inline int
cavium_atomic_check_and_add(int val, cavium_atomic_t * ptr, int check_val,
			    char *file, int line)
{
	if ((cavium_atomic_read((ptr)) + val) > check_val) {
		cavium_error
		    ("OCTEON: %s:%d Overflow in atomic value (%d) (attempt to add %d, max: %d)\n",
		     file, line, cavium_atomic_read((ptr)), val, check_val);
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

static inline void
cavium_sleep_cond(cavium_wait_channel * wait_queue, int *condition)
{
	cavium_wait_entry we;

	cavium_init_wait_entry(&we, current);
	cavium_add_to_waitq(wait_queue, &we);
	set_current_state(TASK_INTERRUPTIBLE);
	while (!(*condition))
		schedule();
	set_current_state(TASK_RUNNING);
	cavium_remove_from_waitq(wait_queue, &we);
}

static inline void
cavium_sleep_atomic_cond(cavium_wait_channel * waitq, cavium_atomic_t * pcond)
{
	cavium_wait_entry we;

	cavium_init_wait_entry(&we, current);
	cavium_add_to_waitq(waitq, &we);
	set_current_state(TASK_INTERRUPTIBLE);
	while (!cavium_atomic_read(pcond))
		schedule();
	set_current_state(TASK_RUNNING);
	cavium_remove_from_waitq(waitq, &we);
}

/* Gives up the CPU for a timeout period.
   Check that the condition is not true before we go to sleep for a
   timeout period.  */
static inline void
cavium_sleep_timeout_cond(cavium_wait_channel * wait_queue, int *condition,
			  int timeout)
{
	cavium_wait_entry we;

	cavium_init_wait_entry(&we, current);
	cavium_add_to_waitq(wait_queue, &we);
	set_current_state(TASK_INTERRUPTIBLE);
	if (!(*condition))
		schedule_timeout(timeout);
	set_current_state(TASK_RUNNING);
	cavium_remove_from_waitq(wait_queue, &we);
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

static inline void *octeon_pci_alloc_consistent(cavium_pci_device_t * pci_dev,
						uint32_t size,
						unsigned long *dma_addr_ptr,
						void *ctx UNUSED)
{
	return pci_alloc_consistent(pci_dev, size, (dma_addr_t *) dma_addr_ptr);
}

static inline void
octeon_pci_free_consistent(cavium_pci_device_t * pci_dev, uint32_t size,
			   void *virt_addr, unsigned long dma_addr,
			   void *ctx UNUSED)
{
	pci_free_consistent(pci_dev, size, virt_addr, dma_addr);
}

#define USE_PCIMAP_CALLS

#define cnnic_pci_map_single(oct, vaddr, size, dir, ctx) \
    octeon_pci_map_single(oct, vaddr, size, dir)
static inline unsigned long
octeon_pci_map_single(cavium_pci_device_t * pci_dev, void *virt_addr,
		      uint32_t size, int direction)
{
	unsigned long physaddr;
#if defined(USE_PCIMAP_CALLS)
	physaddr = pci_map_single(pci_dev, virt_addr, size, direction);
#else
	physaddr = virt_to_phys(virt_addr);
#endif
//      printk("physaddr: %lx\n", physaddr);
	return physaddr;
}

static inline void
octeon_pci_unmap_single(cavium_pci_device_t * pci_dev, unsigned long dma_addr,
			uint32_t size, int direction)
{
#if defined(USE_PCIMAP_CALLS)
	pci_unmap_single(pci_dev, (dma_addr_t) dma_addr, size, direction);
#endif
}

static inline unsigned long
octeon_pci_map_page(cavium_pci_device_t * pci_dev, cavium_page_t * page,
		    unsigned long offset, uint32_t size, int direction)
{
	return pci_map_page(pci_dev, page, offset, size, direction);
}

static inline int
octeon_pci_mapping_error(cavium_pci_device_t *pci_dev, unsigned long dma_addr)
{
	return pci_dma_mapping_error(pci_dev, dma_addr);
}

static inline void
octeon_pci_unmap_page(cavium_pci_device_t * pci_dev, unsigned long dma_addr,
		      uint32_t size, int direction)
{
	return pci_unmap_page(pci_dev, dma_addr, size, direction);
}

static inline void
cnnic_pci_dma_sync_single_for_cpu(cavium_pci_device_t * pci_dev,
				  unsigned long dma_addr, uint32_t size,
				  int direction)
{
	pci_dma_sync_single_for_cpu(pci_dev, dma_addr, size, direction);
}

static inline void
cnnic_pci_dma_sync_single_for_device(cavium_pci_device_t * pci_dev,
				     unsigned long dma_addr, uint32_t size,
				     int direction)
{
	pci_dma_sync_single_for_device(pci_dev, dma_addr, size, direction);
}


static inline void *cav_net_buff_rx_alloc(uint32_t size, void *ctx UNUSED)
{
#if 1
#define SKB_ADJUST_MASK  0x3F
#define SKB_ADJUST       (SKB_ADJUST_MASK + 1)

	struct sk_buff *skb = dev_alloc_skb(size + SKB_ADJUST);
	if(skb) {
			if ((unsigned long)skb->data & SKB_ADJUST_MASK) {
				uint32_t r =
					SKB_ADJUST - ((unsigned long)skb->data & SKB_ADJUST_MASK);
				skb_reserve(skb, r);
			}
			/* clear info structure at the head of data */
			memset(skb->data, 0, 16);
	}
	/*if( (unsigned long)skb->data & SKB_ADJUST_MASK) {
	   printk("skb->data @ %p\n", skb->data);
	   } */
#else
	struct sk_buff *skb = dev_alloc_skb(size + 2);
	if (skb)
		skb_reserve(skb, 2);
#endif

	return ((void *)skb);
}

#define   get_recv_buffer_data(ptr, app_ctx)      (((struct sk_buff *)(ptr))->data)
#define   get_recv_buffer_cb(ptr)                 (((struct sk_buff *)(ptr))->cb)

/** Copy contents of one Output Queue buffer to another.
 *  @param d_buf    - Output Queue buffer to copy to.
 *  @param s_buf    - Output queue buffer to copy from.
 *  @param d_offset - Offset in data pointer of dest buffer to start copy.
 *  @param length   - NUmber of bytes to copy.
 *
 *  Copies length bytes from s_buf's data buffer at address d_offset bytes from
 *  d_buf's data buffer. The control data from s_buf is copied as it is to d_buf.
 */
static inline void
copy_recv_buffer(void *d_buf, void *s_buf, uint32_t d_offset, uint32_t length)
{
	struct sk_buff *d_skb = (struct sk_buff *)d_buf;
	struct sk_buff *s_skb = (struct sk_buff *)s_buf;

	memcpy(d_skb->data + d_offset, s_skb->data, length);
}

/** Call this routine to free the recv_info packet buffers.
 * Depending on the buffer type the packet buffers need to be
 * freed using different calls.
 * @param buf      - the buffer to be freed.
 * @param buf_type - the buffer type for the recv_pkt.
 */
static __inline void cavium_free_recv_pkt_buf(void *buf, uint32_t buf_type)
{
	if (buf_type == OCT_BUFFER_TYPE_1) {
		cavium_free_dma(buf);
	} else {
		if (buf_type == OCT_BUFFER_TYPE_2)
			free_recv_buffer(buf);
		else
			cavium_error
			    ("OCTEON: Unknown recv buf type. Buffer not freed\n");
	}
}

/** Prints contents of a memory location when an error occurs.
 * The message is always printed and is not dependent on the debug level.
 * @param data - the address where data is located.
 * @param size - size of data to be printed at "data".
 */
static inline void cavium_error_print(uint8_t * data, uint32_t size)
{
	uint32_t i;

	printk("Printing %d bytes @ 0x%p\n", size, data);
	for (i = 0; i < size; i++) {
		if (!(i & 0x7))
			printk("\n");
		printk(" %02x", data[i]);
	}
	printk("\n");
}

static inline void cavium_error_print_8B_data(uint64_t * data, uint32_t size)
{
	uint32_t i, blocks;

	blocks = (size >> 3) + ((size & 0x07) ? 1 : 0);
	printk("Printing %d 8B blocks @ 0x%p\n", blocks, data);
	for (i = 0; i < blocks; i++)
		printk(" %016llx\n", CVM_CAST64(data[i]));
	printk("\n");
}

#define   cavium_spin_lock_destroy(lock)          do { } while(0)

int octeon_add_proc_entry(int octeon_id, octeon_proc_entry_t * entry);

int octeon_delete_proc_entry(int octeon_id, char *name);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define  SET_PROC_OWNER(proc_entry)  ((proc_entry)->owner = THIS_MODULE)
#else
#define  SET_PROC_OWNER(proc_entry)  do { } while(0)
#endif

#define octeon_assign_dev_name(oct)         \
    sprintf( ((oct)->device_name), "Octeon%d", ((oct)->octeon_id))

#define octeon_assign_vf_dev_name(oct)         \
    sprintf( ((oct)->device_name), "Octeon_vf%d", ((oct)->octeon_id))

#define OCTEON_MAX_SG  (ROUNDUP4(MAX_SKB_FRAGS) >> 2)

#else /* __KERNEL__ */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <endian.h>
#include <ctype.h>
#include <time.h>

#ifdef __BYTE_ORDER
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __CAVIUM_BYTE_ORDER __CAVIUM_LITTLE_ENDIAN
#else /* presumably Big Endian :-) */
#define __CAVIUM_BYTE_ORDER __CAVIUM_BIG_ENDIAN
#endif
#else /* __BYTE_ORDER */
#error __BYTE_ORDER undefined
#endif /* __BYTE_ORDER */

#define CVM_CAST64(v) ((long long)(v))

#define uint64  unsigned long long
#define uint32  unsigned int
#define uint16  unsigned short
#define uint8   unsigned char

/*cavium string fuction for kernel driver*/
#define cavium_strcpy(dest,max_len,src) strcpy(dest,src)
#define cavium_strncpy(dest,max_len,src,n) strncpy(dest,src,n)
#define cavium_strcat(dest,max_len,src) strcat(dest,src)
#define cavium_strchr strchr
#define cavium_snprintf snprintf

#endif /* __KERNEL__ */

#endif /* _LINUX_SYSDEP_H */

/* $Id: linux_sysdep.h 170606 2018-03-20 15:42:45Z vvelumuri $ */
