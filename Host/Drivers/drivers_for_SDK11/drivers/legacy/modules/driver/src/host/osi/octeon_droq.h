/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file  octeon_droq.h
     \brief Host Driver: Implemantation of Octeon Output queues.
*/

#ifndef __OCTEON_DROQ_H__
#define __OCTEON_DROQ_H__

#include "octeon_main.h"

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
typedef struct {

  /** The Length of the packet. */
	uint64_t length;
  /** The Output Response Header. */
	octeon_resp_hdr_t resp_hdr;
} octeon_droq_info_t;

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

} octeon_recv_buffer_t;
	
#define OCTEON_ISM_OQ_MEM_SIZE	8	/* size in bytes of ISM DMA allocs */
typedef struct octeon_droq_ism {
	/*
	 * The DMA (pkt_cnt_dma) and virtual (pkt_cnt_addr) are both base
	 * addresses for 2 double buffered values.  The index alternates
	 * between 0 and 1, and is updated whenever the SDPX_RX_OUT_CNTS[cnt]
	 * field is adjusted.  This is required to ensure that only ISM writes
	 * after that adjustment takes effect are used by software after the
	 * adjustment has been initiated by a CSR write.
	 */
	int index;
	uint32_t *pkt_cnt_addr;
	unsigned long pkt_cnt_dma;
} octeon_droq_ism_t;

#define OCT_DROQ_RECVBUF_SIZE    (sizeof(octeon_recv_buffer_t))

/** The Descriptor Ring Output Queue structure.
    This structure has all the information required to implement a 
    Octeon DROQ.
*/
typedef struct octeon_droq_struct {
	uint32_t q_no;

	struct napi_struct napi;
	struct net_device *pndev;

  /** Function pointer for HW queue checking function.  This
      call is on the fast path, and we want to have ISM and
      non-ISM version selected at runtime. */
	int (*check_hw_for_pkts) (struct _OCTEON_DEVICE *, struct octeon_droq_struct *droq);

  /** The receive buffer list. This list has the virtual addresses of the
      buffers.  */
	octeon_recv_buffer_t *recv_buf_list;

  /** Pointer to the mapped packet credit register.
       Host writes number of info/buffer ptrs available to this register */
	void *pkts_credit_reg;

  /** Pointer to the mapped packet sent register.
      Octeon writes the number of packets DMA'ed to host memory
      in this register. */
	void *pkts_sent_reg;

  /** Pointer to the ISM configuration regiser.
      This is used for controlling the ISM writes to hos
      memory */
	void *out_cnts_ism;

  /** Fix for DMA incompletion during pkt reads.
      This variable is used to initiate a sent_reg_read
      that completes pending dma
      this variable is used as lvalue so compiler cannot optimize
      the reads */
	uint32_t sent_reg_val;



  /** Statistics for this DROQ. */
	oct_droq_stats_t stats;

  /** Packets pending to be processed - tasklet implementation */
	uint32_t pkts_pending;
	uint32_t last_pkt_count;

  /** Index in the ring where the driver should read the next packet */
	uint32_t host_read_index;

  /** Index in the ring where Octeon will write the next packet */
	uint32_t octeon_write_index;

  /** Number of  descriptors in this ring. */
	uint32_t max_count;
	uint32_t ring_size_mask;

  /** The number of descriptors pending refill. */
	uint32_t refill_count;

  /** Index in the ring where the driver will refill the descriptor's buffer */
	uint32_t host_refill_index;
	uint32_t pkts_per_intr;
	uint32_t refill_threshold;

  /** The size of each buffer pointed by the buffer pointer. */
	uint32_t buffer_size;
	uint32_t max_single_buffer_size;

	octeon_device_t *oct_dev;
  /** A spinlock to protect access to this ring. */
	cavium_spinlock_t lock;


	uint32_t fastpath_on;

	octeon_droq_ops_t ops;

  /** The 8B aligned descriptor ring starts at this address. */
	octeon_droq_desc_t *desc_ring;


  /** The max number of descriptors in DROQ without a buffer.
      This field is used to keep track of empty space threshold. If the
      refill_count reaches this value, the DROQ cannot accept a max-sized
      (64K) packet. */
	uint32_t max_empty_descs;

   /** The 8B aligned info ptrs begin from this address. */
	octeon_droq_info_t *info_list;


	cavium_list_t dispatch_list;


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


	octeon_droq_ism_t ism;

} ____cacheline_aligned_in_smp octeon_droq_t;

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

void octeon_droq_bh(unsigned long);

void octeon_droq_print_stats(void);

int octeon_droq_check_hw_for_pkts(octeon_device_t * oct, octeon_droq_t * droq);

int octeon_setup_droq(int oct_id, int q_no, void *app_ctx);

int32_t octeon_create_droq(octeon_device_t * oct, int q_no, void *app_ctx);
int32_t octeon_droq_set_netdev(octeon_device_t *oct, int q_no, int q_cnt,
			       struct net_device *pndev);
int octeon_droq_process_poll_pkts(octeon_droq_t *droq, uint32_t budget);

#endif	/*__OCTEON_DROQ_H__ */

/* $Id: octeon_droq.h 168306 2017-11-30 05:14:45Z vattunuru $ */
