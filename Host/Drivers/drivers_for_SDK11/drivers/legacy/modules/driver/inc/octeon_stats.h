/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file   octeon_stats.h
     \brief  Host Driver: Statistics provided by the driver for different queues and
             buffer pool.
*/

#ifndef  __OCTEON_STATS_H__
#define  __OCTEON_STATS_H__

#include "octeon_config.h"

#define   OCTEON_BUFFER_POOL_STATS_ON      0x01

#define MAX_IQS  MAX_OCTEON_INSTR_QUEUES
#define MAX_OQS  MAX_OCTEON_OUTPUT_QUEUES

/** Statistics table for octeon device. */
typedef struct {

	/** Number of interrupts received. */
	uint64_t interrupts;

	/** Poll thread ran these many times. */
	uint64_t poll_count;

	/** Request completion tasklet ran these many times */
	uint64_t comp_tasklet_count;

	/** DROQ tasklet ran these many times */
	uint64_t droq_tasklet_count;

} oct_dev_stats_t;

/** Buffer pool statistics. Each of the buffer pool has four stats fields.*/
typedef struct {

	/** Buffer created in this pool at init time. */
	uint32_t max_count;

	/** Buffers allocated from this pool by driver. */
	uint32_t alloc_count;

	/** Fragmented buffer count. */
	uint32_t frag_count;

	/** Buffers moved to other pools. */
	uint32_t other_pool_count;

} oct_bufpool_stats_t;

#define OCT_BUFPOOL_STATS_SIZE  (sizeof(oct_bufpool_stats_t))

/** Input Queue statistics. Each input queue has four stats fields. */
typedef struct {

	uint64_t instr_posted;
			   /**< Instructions posted to this queue. */
	uint64_t instr_processed;
			      /**< Instructions processed in this queue. */
	uint64_t instr_dropped;
			      /**< Instructions that could not be processed. */
	uint64_t bytes_sent;  /**< Bytes sent through this queue. */
	uint64_t sgentry_sent;/**< Gather entries sent through this queue. */
	uint64_t lastbytes_sent;
			     /**< Bytes sent through this queue at last proc stats display */
	uint64_t tx_busy_retransmit; /* TX is busy, re-queue packet to re-transmit */
} ____cacheline_aligned_in_smp oct_iq_stats_t;

#define OCT_IQ_STATS_SIZE   (sizeof(oct_iq_stats_t))

/** Output Queue statistics. Each output queue has four stats fields. */
typedef struct {

	uint64_t pkts_received;
			    /**< Number of packets received in this queue. */
	uint64_t bytes_received;
			    /**< Bytes received by this queue submitted to stack */
	uint64_t pkts_st_received;
			    /**< Number of packets received in this queue submitted to stack. */
	uint64_t bytes_st_received;
			    /**< Bytes received by this queue. */
	uint64_t dropped_nodispatch;
				 /**< Packets dropped due to no dispatch function. */
	uint64_t dropped_nomem;
			    /**< Packets dropped due to no memory available. */
	uint64_t dropped_toomany;
			      /**< Packets dropped due to large number of pkts to process. */
	uint64_t lastbytes_received;
				 /**< packets received through this queue at last proc display */
	uint64_t pkts_delayed_data;
				 /**< packets with data got ready after interrupt arrived */
	uint64_t dropped_zlp;
				 /**< packets dropped due to zero length */
} ____cacheline_aligned_in_smp oct_droq_stats_t;

#define OCT_DROQ_STATS_SIZE   (sizeof(oct_droq_stats_t))

/** Octeon device statistics */
typedef struct {

	uint64_t magic;		     /**< Magic word to verify correctness of structure. */
	uint8_t oct_id;
	uint8_t debug_level;		   /**< The current debug level. */
	uint16_t components;		  /**< Indicates what components are present. */
	uint16_t reserved;
	char dev_state[32];		     /** < Current state of the octeon device. */
	oct_bufpool_stats_t bufpool[BUF_POOLS];	  /**< The buffer pool statistics. */
	oct_iq_stats_t iq[OCTEON3_MAX_IOQS];	   /**< The input queue statistics. */
	oct_droq_stats_t droq[OCTEON3_MAX_IOQS];	     /**< The output queue statistics. */
} oct_stats_t;

#define  OCT_STATS_SIZE   (sizeof(oct_stats_t))

#define CAVIUM_STATS_MAGIC  0x1111222233334444ULL

#endif /* __OCTEON_STATS_H__ */

/* $Id: octeon_stats.h 162999 2017-07-20 10:34:40Z mchalla $ */
