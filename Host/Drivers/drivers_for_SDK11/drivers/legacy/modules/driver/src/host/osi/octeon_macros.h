/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_macros.h 
    \brief Host driver: Inline macros for memory allocation/free and dispatch
           list handling. 
 */

#ifndef __OCTEON_MACROS_H__
#define __OCTEON_MACROS_H__

#define     PTR_TO_ULL(x)             ((unsigned long long)(unsigned long)(x))
#define     CVM_MIN(d1, d2)           (((d1) < (d2)) ? (d1) : (d2))
#define     CVM_MAX(d1, d2)           (((d1) > (d2))?(d1):(d2))

#define     CVM_CHECK_BIT(var, pos)   ((var) & ((1UL) <<(pos)))
#define     CVM_SET_BIT(var, pos)     ((var) |= ((1UL) << (pos)))
#define     CVM_CLEAR_BIT(var, pos)   ((var) &= ( ~(1UL) << (pos)))

#define INCR_INSTRQUEUE_PKT_COUNT(octeon_dev_ptr, iq_no, field, count)  \
                     octeon_dev_ptr->instr_queue[iq_no]->stats.field += count

/*
 *  Macros that switch between using the buffer pool and the system-dependent
 *  routines based on compilation flags used.
 */
#define cavium_alloc_buffer(octeon_dev, size)   cavium_malloc_dma(size, __CAVIUM_MEM_ATOMIC)
#define cavium_free_buffer(octeon_dev, buf)     cavium_free_dma(buf)

/** Allocates with page size granularity.
 *  @param size        - size of memory to allocate.
 *  @param alloc_size  - pointer to 32-bit location where actual allocated
 *                       size is returned.
 *  @param orig_ptr    - If the ptr was moved to make the memory buffer
 *                       8-byte aligned, the start address of allocated
 *                       memory is returned here.
 *  @param ctx         - currently unsed
 *  @return If allocation is successful, the start of the 8-byte aligned
 *          buffer is returned, else NULL.
 */
static inline void *cavium_alloc_aligned_memory(uint32_t size,
						uint32_t * alloc_size,
						unsigned long *orig_ptr,
						void *ctx)
{
	return cnnic_alloc_aligned_dma(size, alloc_size, orig_ptr, ctx);
}

/** Allocate a recv_info structure. The recv_pkt pointer in the recv_info
  * structure is filled in before this call returns.
  * @param extra_bytes - extra bytes to be allocated at the end of the recv info
  *                      structure.
  * @return - pointer to a newly allocated recv_info structure.
  */
static inline octeon_recv_info_t *octeon_alloc_recv_info(int extra_bytes)
{
	octeon_recv_info_t *recv_info;
	uint8_t *buf;

	buf =
	    cnnic_malloc_irq(OCT_RECV_PKT_SIZE + OCT_RECV_INFO_SIZE +
			     extra_bytes, __CAVIUM_MEM_ATOMIC);
	if (buf == NULL)
		return NULL;

	recv_info = (octeon_recv_info_t *) buf;
	recv_info->recv_pkt = (octeon_recv_pkt_t *) (buf + OCT_RECV_INFO_SIZE);
	recv_info->rsvd = NULL;
	if (extra_bytes)
		recv_info->rsvd = buf + OCT_RECV_INFO_SIZE + OCT_RECV_PKT_SIZE;

	return recv_info;
}

/** Free the buffers from a recv_pkt structure. The buffer type determines the
  * function to call to free the buffers.
  * @param recv_pkt       - pointer to a recv_pkt structure.
  */
static inline void cavium_free_recv_pkt_buffers(octeon_recv_pkt_t * recv_pkt)
{
	int i;

	for (i = 0; i < recv_pkt->buffer_count; i++) {
		switch (recv_pkt->buf_type) {
		case OCT_BUFFER_TYPE_1:
			cavium_free_dma(recv_pkt->buffer_ptr[i]);
			break;
		case OCT_BUFFER_TYPE_2:
			free_recv_buffer(recv_pkt->buffer_ptr[i]);
			break;
		default:
			cavium_error("OCTEON: %s: Unknown buf type \n",
				     __CVM_FUNCTION__);
		}
	}
}

/*---------------------- Dispatch list handlers  --------------------------*/
  /** Gets the dispatch function registered to receive packets with a
 *  given opcode.
 *  @param  octeon_dev  - the octeon device pointer.
 *  @param  opcode      - the opcode for which the dispatch function
 *                        is to checked.
 *
 *  @return Success: octeon_dispatch_fn_t (dispatch function pointer)
 *  @return Failure: NULL
 *
 *  Looks up the dispatch list to get the dispatch function for a
 *  given opcode.
 */
static inline octeon_dispatch_fn_t
octeon_get_dispatch(octeon_device_t * octeon_dev, uint16_t opcode)
{
	int idx;
	cavium_list_t *dispatch;
	octeon_dispatch_fn_t fn = NULL;

	idx = opcode & OCTEON_OPCODE_MASK;

	cavium_spin_lock_softirqsave(&octeon_dev->dispatch.lock);

	if (octeon_dev->dispatch.count == 0) {
		cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
		return NULL;
	}

	if (!(octeon_dev->dispatch.dlist[idx].opcode)) {
		cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
		return NULL;
	}

	if (octeon_dev->dispatch.dlist[idx].opcode == opcode) {
		cavium_print(PRINT_DEBUG, " found dispatch in main\n");
		fn = octeon_dev->dispatch.dlist[idx].dispatch_fn;
	} else {
		cavium_list_for_each(dispatch,
				     &(octeon_dev->dispatch.dlist[idx].list)) {
			if (((octeon_dispatch_t *) dispatch)->opcode == opcode) {
				cavium_print(PRINT_DEBUG,
					     " found dispatch in list\n");
				fn = ((octeon_dispatch_t *)
				      dispatch)->dispatch_fn;
				break;
			}
		}
	}
	cavium_print(PRINT_DEBUG, " No dispatch found \n");

	cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
	return fn;
}

/** Get the argument that the user set when registering dispatch
 *  function for a given opcode.
 *  @param  octeon_dev - the octeon device pointer.
 *  @param  opcode     - the opcode for which the dispatch argument
 *                       is to be checked.
 *  @return  Success: void * (argument to the dispatch function)
 *  @return  Failure: NULL
 *
 */
static inline void *octeon_get_dispatch_arg(octeon_device_t * octeon_dev,
					    uint16_t opcode)
{
	int idx;
	cavium_list_t *dispatch;
	void *fn_arg = NULL;

	idx = opcode & OCTEON_OPCODE_MASK;

	cavium_spin_lock_softirqsave(&octeon_dev->dispatch.lock);

	if (octeon_dev->dispatch.count == 0) {
		cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
		return NULL;
	}

	if (octeon_dev->dispatch.dlist[idx].opcode == opcode) {
		fn_arg = octeon_dev->dispatch.dlist[idx].arg;
	} else {
		cavium_list_for_each(dispatch,
				     &(octeon_dev->dispatch.dlist[idx].list)) {
			if (((octeon_dispatch_t *) dispatch)->opcode == opcode) {
				fn_arg = ((octeon_dispatch_t *) dispatch)->arg;
				break;
			}
		}
	}

	cavium_spin_unlock_softirqrestore(&octeon_dev->dispatch.lock);
	return fn_arg;
}

static inline int
cvm_is_val_in_range(uint32_t index, uint32_t minVal, uint32_t maxVal)
{
	if (minVal < maxVal)
		return (index >= minVal) && (index < maxVal);
	else
		return (index < maxVal) || (index >= minVal);
}

/*
  off   - offset in dst where data will be copied.
  len   - bytes to be copied
  size  - size of dst buffer
  If (off+len) <= size, copy len bytes from src to (dst + off).
  Return the new offset
 */
static inline int
cvm_copy_cond(char *dst, char *src, int off, int len, int size)
{
	if ((off + len) <= size) {
		cavium_memcpy((dst + off), src, len);
		off += len;
	}

	return off;
}

#endif

/* $Id: octeon_macros.h 141410 2016-06-30 14:37:41Z mchalla $ */
