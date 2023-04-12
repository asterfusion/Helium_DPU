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

/*!  \file  octeon_droq.h
     \brief Host Driver: Implemantation of Octeon Output queues.
*/

#ifndef __OCTEON_DROQ_H__
#define __OCTEON_DROQ_H__

#include "octeon_main.h"

#ifdef APP_DROQ_POLL
/* Application will poll DROQ for Rx processing */
#undef USE_DROQ_THREADS
#else /* !APP_DROQ_POLL */
/** DROQ Implementation.
 *  "USE_DROQ_THREADS" and "USE_DROQ_TASKLETS" are mutually exclusive features.
 *  Either of these can be used for multi Rx processing.
 **/

/* By default DROQ Threads are enabled */
#ifndef OCT_NIC_USE_NAPI
#define USE_DROQ_THREADS
#endif

#if !defined(USE_DROQ_THREADS) && !defined(USE_DROQ_TASKLETS)
//#define USE_DROQ_TASKLETS
#endif

#if defined(USE_DROQ_THREADS) && defined(USE_DROQ_TASKLETS)
#error "Please enable only one of USE_DROQ_THREADS or USE_DROQ_TASKLETS"
#endif
#endif

/** Octeon descriptor format.
    The descriptor ring is made of descriptors which have 2 64-bit values:
    -# Physical (bus) address of the data buffer.
    -# Physical (bus) address of a octeon_droq_info_t structure.
    The Octeon device DMA's incoming packets and its information at the address
    given by these descriptor fields.
 */
typedef struct {

  /** The buffer pointer */
	uint64_t buffer_ptr;

  /** The Info pointer */
	uint64_t info_ptr;

} octeon_droq_desc_t;

#define OCT_DROQ_DESC_SIZE    (sizeof(octeon_droq_desc_t))

/** Information about packet DMA'ed by Octeon.
    The format of the information available at Info Pointer after Octeon 
    has posted a packet. Not all descriptors have valid information. Only
    the Info field of the first descriptor for a packet has information
    about the packet. */
#ifndef BUFPTR_ONLY_MODE
typedef struct {

  /** The Output Response Header. */
	octeon_resp_hdr_t resp_hdr;

  /** The Length of the packet. */
	uint64_t length;

} octeon_droq_info_t;
#else
typedef struct {

  /** The Length of the packet. */
	uint64_t length;
#ifndef ETHERPCI
  /** The Output Response Header. */
	octeon_resp_hdr_t resp_hdr;
#endif
} octeon_droq_info_t;
#endif

#define OCT_DROQ_INFO_SIZE   (sizeof(octeon_droq_info_t))

/** Pointer to data buffer.
    Driver keeps a pointer to the data buffer that it made available to 
    the Octeon device. Since the descriptor ring keeps physical (bus)
    addresses, this field is required for the driver to keep track of
    the virtual address pointers. The fields are operated by
    OS-dependent routines.
*/
typedef struct {

  /** Pointer to the packet buffer. Hidden by void * to make it OS independent.
         */
	void *buffer;

  /** Pointer to the data in the packet buffer.
      This could be different or same as the buffer pointer depending
      on the OS for which the code is compiled. */
	uint8_t *data;

#ifdef OCT_REUSE_RX_BUFS
  /** Pointer to the skb buffer when reusing DMA buffers.
   *  This is needed to retrive skb users and reference count to
   *  free or reuse DMA buffer */
	void *skbptr;
#endif
} octeon_recv_buffer_t;
	
typedef struct octeon_droq_ism {
	void *pkt_cnt_addr;
	unsigned long pkt_cnt_dma;
} octeon_droq_ism_t;

#define OCT_DROQ_RECVBUF_SIZE    (sizeof(octeon_recv_buffer_t))

/** The Descriptor Ring Output Queue structure.
    This structure has all the information required to implement a 
    Octeon DROQ.
*/
typedef struct {

  /** A spinlock to protect access to this ring. */
	cavium_spinlock_t lock;

	uint32_t q_no;

	uint32_t fastpath_on;

	octeon_droq_ops_t ops;

	octeon_device_t *oct_dev;

#ifdef  USE_DROQ_THREADS

	cvm_kthread_t thread;

	cavium_wait_channel wc;

	int stop_thread;

	cavium_atomic_t thread_active;

#endif

  /** The 8B aligned descriptor ring starts at this address. */
	octeon_droq_desc_t *desc_ring;

  /** Index in the ring where the driver should read the next packet */
	uint32_t host_read_index;

  /** Index in the ring where Octeon will write the next packet */
	uint32_t octeon_write_index;

  /** Index in the ring where the driver will refill the descriptor's buffer */
	uint32_t host_refill_index;

  /** Packets pending to be processed - tasklet implementation */
	cavium_atomic_t pkts_pending;

  /** Number of  descriptors in this ring. */
	uint32_t max_count;

  /** The number of descriptors pending refill. */
	uint32_t refill_count;

	uint32_t pkts_per_intr;
	uint32_t refill_threshold;

  /** The max number of descriptors in DROQ without a buffer.
      This field is used to keep track of empty space threshold. If the
      refill_count reaches this value, the DROQ cannot accept a max-sized
      (64K) packet. */
	uint32_t max_empty_descs;

   /** The 8B aligned info ptrs begin from this address. */
	octeon_droq_info_t *info_list;

  /** The receive buffer list. This list has the virtual addresses of the
      buffers.  */
	octeon_recv_buffer_t *recv_buf_list;

  /** The size of each buffer pointed by the buffer pointer. */
	uint32_t buffer_size;

  /** Pointer to the mapped packet credit register.
       Host writes number of info/buffer ptrs available to this register */
	void *pkts_credit_reg;

  /** Pointer to the mapped packet sent register.
      Octeon writes the number of packets DMA'ed to host memory
      in this register. */
	void *pkts_sent_reg;

	cavium_list_t dispatch_list;

  /** Statistics for this DROQ. */
	oct_droq_stats_t stats;

  /** DMA mapped address of the DROQ descriptor ring. */
	unsigned long desc_ring_dma;

  /** Info ptr list are allocated at this virtual address. */
	unsigned long info_base_addr;

  /** Allocated size of info list. */
	uint32_t info_alloc_size;

  /* irq number associated with this queue */
    uint32_t irq_num;

  /** application context */
	void *app_ctx;

	struct napi_struct napi;

	octeon_droq_ism_t ism;

} octeon_droq_t;

#define OCT_DROQ_SIZE   (sizeof(octeon_droq_t))

/**
 *  Allocates space for the descriptor ring for the droq and sets the
 *   base addr, num desc etc in Octeon registers.
 *
 * @param  oct_dev    - pointer to the octeon device structure
 * @param  q_no       - droq no. ranges from 0 - 3.
 * @param app_ctx     - pointer to application context
 * @return Success: 0    Failure: 1
*/
int octeon_init_droq(octeon_device_t * oct_dev, uint32_t q_no, void *app_ctx);

/**
 *  Frees the space for descriptor ring for the droq.
 *
 *  @param oct_dev - pointer to the octeon device structure
 *  @param q_no    - droq no. ranges from 0 - 3.
 *  @return:    Success: 0    Failure: 1
*/
int octeon_delete_droq(octeon_device_t * oct_dev, uint32_t q_no);

uint32_t octeon_droq_refill(octeon_device_t * octeon_dev, octeon_droq_t * droq);

int wait_for_oq_pkts(octeon_device_t * oct);

int wait_for_output_queue_pkts(octeon_device_t * oct, int q_no);

void octeon_droq_bh(unsigned long);

void octeon_droq_print_stats(void);

int octeon_droq_check_hw_for_pkts(octeon_device_t * oct, octeon_droq_t * droq);

int octeon_setup_droq(int oct_id, int q_no, void *app_ctx);

int32_t octeon_create_droq(octeon_device_t * oct, int q_no, void *app_ctx);

#endif	/*__OCTEON_DROQ_H__ */

/* $Id: octeon_droq.h 168306 2017-11-30 05:14:45Z vattunuru $ */
