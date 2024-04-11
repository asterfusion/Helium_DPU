/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef  __CVM_LINUX_TYPES_H__
#define  __CVM_LINUX_TYPES_H__
#include "octeon_compat.h"

#define   __CVM_FILE__                   __FILE__
#define   __CVM_FUNCTION__               __FUNCTION__
#define   __CVM_LINE__                   __LINE__
#define   __CAVIUM_MEM_ATOMIC            GFP_ATOMIC
#define   __CAVIUM_MEM_GENERAL           GFP_KERNEL
#define   CAVIUM_PAGE_SIZE               PAGE_SIZE
#define   CAVIUM_MAX_CONTIG_PAGES        512
#define   OCTEON_MAX_ALLOC_RETRIES       1

#define   cavium_flush_write()           wmb()
#define   cavium_get_cpu_count()         num_online_cpus()

#define   cavium_likely(x)                likely(x) 
#define   cavium_unlikely(x)              unlikely(x) 

#define   cavium_get_cpu_counter()       get_cycles()
#define   cavium_jiffies                 jiffies
#define   CAVIUM_TICKS_PER_SEC           HZ
#define   cavium_mdelay(tmsecs)          mdelay(tmsecs)
#define   cavium_udelay(tusecs)          udelay(tusecs)
#define   cavium_timeout(tjiffies)       schedule_timeout(tjiffies)

#define   cavium_malloc_dma(size, flags) kmalloc((size),(flags))
#define   cavium_free_dma(pbuf)	         kfree((pbuf))
#define   cnnic_malloc_irq(size, flags)  cavium_malloc_dma(size, flags)
#define   cnnic_free_irq(buf)            cavium_free_dma(buf)
#define   octeon_free_recv_info(buf)     cnnic_free_irq(buf)
#define   octeon_dma_rmb()               dma_rmb()

#define   cavium_alloc_virt(size)        vmalloc((size))
#define   cavium_free_virt(ptr)          vfree((ptr))

#define   cavium_memcpy(dest, src, size) memcpy((dest), (src), (size))
#define   cavium_memset(buf, val, size)  memset((buf), (val), (size))
#define   cavium_memcmp(buf1,buf2,size)  memcmp((buf1), (buf2), (size))

#define   cavium_sleep(wc)               interruptible_sleep_on(wc)
#define   cavium_wakeup(wc)              wake_up_interruptible((wc))
#define   cavium_schedule()              schedule()
#define   cavium_disable_irq_nosync(irq) disable_irq_nosync(irq)
#define   cavium_enable_irq(irq)         enable_irq(irq)

#define   cavium_atomic_set(ptr, val)    atomic_set((ptr), (val))
#define   cavium_atomic_read(ptr)        atomic_read((ptr))
#define   cavium_atomic_inc(ptr)         atomic_inc((ptr))
#define   cavium_atomic_add(val, ptr)    atomic_add((val), (ptr))
#define   cavium_atomic_dec(ptr)         atomic_dec((ptr))
#define   cavium_atomic_sub(val, ptr)    atomic_sub((val), (ptr))

#define   cavium_sema_init(sema, count)  sema_init((sema),(count))
#define   cavium_sema_down(sema)         down((sema))
#define   cavium_sema_up(sema)           up((sema))

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

#define   CAVIUM_PCI_DMA_FROMDEVICE      PCI_DMA_FROMDEVICE
#define   CAVIUM_PCI_DMA_TODEVICE        PCI_DMA_TODEVICE
#define   CAVIUM_PCI_DMA_BIDIRECTIONAL   PCI_DMA_BIDIRECTIONAL

#define   free_recv_buffer(skb)          dev_kfree_skb_any((skb))
#define   recv_buf_put(skb, len)         skb_put((skb), (len))
#define   recv_buf_reserve(skb, len)     skb_reserve((ptr), len)
#define   recv_buffer_push(skb, len)     skb_push((skb), (len))
#define   recv_buffer_pull(skb, len)     skb_pull((skb), (len))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
#define   cvm_ip_hdr(skb)                (ip_hdr((skb)))
#define   cvm_ip6_hdr(skb)               (ipv6_hdr((skb)))
#else
#define   cvm_ip_hdr(skb)                ((skb)->nh.iph)
#define   cvm_ip6_hdr(skb)               ((skb)->nh.ipv6h)
#endif

#define   cavium_spin_lock_init(lock)               spin_lock_init((lock))
#define   cavium_spin_lock(lock)                    spin_lock((lock))
#define   cavium_spin_unlock(lock)                  spin_unlock((lock))
#define   cavium_spin_lock_softirqsave(lock)        spin_lock_bh(lock)
#define   cavium_spin_unlock_softirqrestore(lock)   spin_unlock_bh(lock)
#define   cavium_spin_lock_irqsave(lock, flags)     spin_lock_irqsave(lock, flags)
#define   cavium_spin_unlock_irqrestore(lock,flags) spin_unlock_irqrestore(lock, flags)

#define   cavium_mutex_init(lock)                    mutex_init((lock))
#define   cavium_mutex_lock(lock)                    mutex_lock((lock))
#define   cavium_mutex_unlock(lock)                  mutex_unlock((lock))
#define   cavium_mutex_destroy(lock)                 mutex_destroy((lock))

#define   cavium_init_wait_channel(wc_ptr)          init_waitqueue_head(wc_ptr)
#define   cavium_init_wait_entry(we_ptr, task)      init_waitqueue_entry(we_ptr, task)
#define   cavium_add_to_waitq(wq_ptr, we_ptr)       add_wait_queue(wq_ptr, we_ptr)
#define   cavium_remove_from_waitq(wq_ptr, we_ptr)  remove_wait_queue(wq_ptr, we_ptr)

#define   cavium_copy_in(dest, src, size)           copy_from_user((dest), (src), (size))
#define   cavium_copy_out(dest, src, size)          copy_to_user((dest), (src), (size))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || defined(HAS_2PARAM_ACCESS_OK)
#define   cavium_access_ok(flag, addr, size)        access_ok((addr), (size))
#else
#define   cavium_access_ok(flag, addr, size)        access_ok((flag), (addr), (size))
#endif

#define   cavium_get_random_bytes(ptr, len)         get_random_bytes((ptr), (len))

#define   cavium_check_timeout(kerntime, chk_time)  time_after((kerntime), (unsigned long)(chk_time))

#define   cavium_tasklet_init(ptask, pfn, parg)     tasklet_init((ptask), (pfn), (parg))
#define   cavium_tasklet_schedule(ptask)            tasklet_schedule((ptask))
#define   cavium_tasklet_kill(ptask)                tasklet_kill((ptask))

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#define   cavium_smpcall_func_single(cpu, func, info, wait) \
                smp_call_function_single(cpu, func, info, wait)	/* smp support: for per core invocation */
#else
#define   cavium_smpcall_func_single(cpu, func, info, wait) \
                smp_call_function_single(cpu, func, info, wait, 0)	/* smp support: for per core invocation */
#endif

#define   cavium_schedule_tasklet                   tasklet_schedule	/* smp support: tasklet schedule for function pointer passing */

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#define cavium_proc_create_data(name, mode, parent, fops, data)    proc_create_data(name, mode, parent, fops, data)
#else
#define cavium_proc_create_data(name, mode, parent, fops, data)    create_proc_entry(name, mode, parent);
#endif

#define cavium_getpid()                             current->pid

#define OCTEON_READ_PCI_CONFIG(dev, offset, pvalue)      \
          pci_read_config_dword((dev)->pci_dev, (offset),(pvalue))

#define OCTEON_WRITE_PCI_CONFIG(dev, offset, value)      \
          pci_write_config_dword((dev)->pci_dev, (offset),(value))

#define cavium_iomem            __iomem

#define    cvm_intr_return_t             irqreturn_t
#define    CVM_INTR_HANDLED              IRQ_HANDLED
#define    CVM_INTR_NONE                 IRQ_NONE

#define    CVM_MOD_INC_USE_COUNT         try_module_get(THIS_MODULE)
#define    CVM_MOD_DEC_USE_COUNT         module_put(THIS_MODULE)
#define    CVM_MOD_IN_USE                module_refcount(THIS_MODULE)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define    CVM_SHARED_INTR         SA_SHIRQ
#else
#define    CVM_SHARED_INTR         IRQF_SHARED
#endif

typedef pid_t cavium_pid_t;
typedef struct task_struct cavium_ostask_t;
typedef spinlock_t cavium_spinlock_t;
typedef struct mutex cavium_mutex_t;
typedef struct semaphore cavium_semaphore_t;
typedef struct tasklet cavium_tasklet_t;
typedef struct tasklet_struct cavium_tasklet_struct_t;	/* added for OS transparency */
typedef atomic_t cavium_atomic_t;
typedef wait_queue_head_t cavium_wait_channel;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,13,0)
typedef wait_queue_t cavium_wait_entry;
#else
typedef wait_queue_entry_t cavium_wait_entry;
#endif
typedef struct sk_buff cavium_netbuf_t;
typedef struct pci_dev cavium_pci_device_t;
typedef struct msix_entry cavium_msix_entry_t;
typedef struct page cavium_page_t;
typedef struct seq_file cavium_seq_file_t;

static inline void *cnnic_alloc_aligned_dma(uint32_t size,
					    uint32_t * alloc_size UNUSED,
					    unsigned long *orig_ptr UNUSED,
					    void *ctx UNUSED)
{
	int retries = 0;
	void *ptr = NULL;

#define OCTEON_MAX_ALLOC_RETRIES     1
	do {
		ptr =
		    (void *)__get_free_pages(__CAVIUM_MEM_GENERAL,
					     get_order(size));
		if ((unsigned long)ptr & 0x07) {
			free_pages((unsigned long)ptr, get_order(size));
			ptr = NULL;
			/* Increment the size required if the first attempt failed. */
			if (!retries)
				size += 7;
		}
		retries++;
	} while ((retries <= OCTEON_MAX_ALLOC_RETRIES) && !ptr);

	*alloc_size = size;
	*orig_ptr = (unsigned long)ptr;
	if ((unsigned long)ptr & 0x07)
		ptr = (void *)(((unsigned long)ptr + 7) & ~(7UL));
	return ptr;
}

#define cnnic_free_aligned_dma(ptr, size, ctx) \
            free_pages(ptr, get_order(size))
#endif

/* $Id: cvm_linux_types.h 48846 2010-04-30 19:53:17Z panicker $ */
