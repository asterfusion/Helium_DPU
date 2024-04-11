/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file buffer_pool.h
     \brief Host Driver: A driver-generated pool of buffers that it can use for 
                         dynamic memory allocation.
*/

#ifndef __BUFFER_POOL_H__
#define __BUFFER_POOL_H__

#include "octeon_main.h"

/*----------------------------   BUFFER POOL  -------------------------------*/

/**  The 6 pools in the driver's buffer pool */
typedef enum { huge = 0,
	large,
	medium,
	small,
	tiny,
	ex_tiny,
	os
} OCTEON_BUFPOOL;

/*
 * buffer pool management
 */

typedef struct {
	unsigned long pool;
	unsigned long index;
} buffer_tag;

/** Configuration for the driver's buffer pool.
 *  Indicates the numbers of buffers to allocate at init time
 *  for each pool.
 */
typedef struct {

	uint32_t huge_buffer_max;
			      /**< number in huge 32K buffer pool */
	uint32_t large_buffer_max;
			      /**< number in large 16K buffer pool */
	uint32_t medium_buffer_max;
			      /**< number in medium 8K buffer pool */
	uint32_t small_buffer_max;
			      /**< number in small 4K buffer pool */
	uint32_t tiny_buffer_max;
			      /**< number in tiny 2K buffer pool */
	uint32_t ex_tiny_buffer_max;
			       /**< number in ex tiny 1K buffer pool */

} octeon_bufpool_config_t;

/** List to keep track of fragmented buffers in the buffer pool. */
typedef struct {
	cavium_list_t list;
	cavium_list_t alloc_list;
	uint8_t *big_buf;
	int frags_count;
	int index;
	OCTEON_BUFPOOL p;
	uint16_t free_list[MAX_FRAGMENTS];
	uint8_t *address[MAX_FRAGMENTS];
	int free_list_index;
	int not_allocated;
} cavium_frag_buf_t;

/** Each buffer pool is represented by this structure.
 */
typedef struct {
  /** Lock for this pool. */
	cavium_spinlock_t buffer_lock;

  /** Number of chunks in this pool. */
	int chunks;

  /** Size of each chunk available for use after allocation. */
	int chunk_size;

  /** Actual size of each chunk. (includes size of buffer tag)*/
	int real_size;

	uint8_t *base;

  /** Address of each chunk. */
	uint8_t *address[MAX_BUFFER_CHUNKS];

  /** Address of usable space in chunk ( chunk - buffer tag) */
	uint8_t *address_trans[MAX_BUFFER_CHUNKS];

  /** Free list for this pool. */
	uint16_t free_list[MAX_BUFFER_CHUNKS];

  /** The next location in free list where a buffer is available. */
	int free_list_index;

  /** Start of head for this pool's fragment list.  */
	cavium_list_t frags_list;

} cavium_buffer_t;

/** Initialize the buffer pool.
 *   @param  octeon_dev   -  pointer to the octeon device.
 *   @param  bufpool_conf -  Configuration to be used to initialize 
 *
 *   The buffer pool is allocated according to chunk size and chunk count
 *   mentioned in bufpool_conf for each pool. There is a separate buffer
 *   pool for each device.
 *   
 *   @return Success: 0; Failure: 1.
 */
uint32_t octeon_init_buffer_pool(octeon_device_t * octeon_dev,
				 octeon_bufpool_config_t * bufpool_conf);

/** Delete the buffer pool.
 *  @param  octeon_dev - pointer to the octeon device.
 *
 *  Delete the buffers in the buffer pool at module unload time.
 */
void octeon_delete_buffer_pool(octeon_device_t * octeon_dev);

/** Get a buffer from the pool.
 *  @param  pdev  -  pointer to the octeon device.
 *  @param  size  -  size of buffer to be allocated.
 *
 *  The buffer pool  thats a best fit for the buffer size is checked for
 *  an available buffer. If not, then the next higher size buffer pool
 *  is checked. If no buffers are available, a buffer is dynamically 
 *  allocated and if that fails, no buffer is returned.
 *
 *  @return Success: buffer pointer; Failure: NULL
 */
uint8_t *get_buffer_from_pool(void *pdev, int size);

/** Put a buffer back into the buffer pool.
 *  @param  dev - pointer to the octeon device.
 *  @param  b   - the buffer to be released to the pool.
 *
 */
void put_buffer_in_pool(void *dev, uint8_t * b);

/* Get the buffer pool statistics */
void oct_get_buffer_pool_stats(oct_stats_t * stats);

#endif

/* $Id: buffer_pool.h 141410 2016-06-30 14:37:41Z mchalla $ */
