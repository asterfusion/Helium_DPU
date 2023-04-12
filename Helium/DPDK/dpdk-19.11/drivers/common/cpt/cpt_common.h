/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium, Inc
 */

#ifndef _CPT_COMMON_H_
#define _CPT_COMMON_H_

#include <rte_mempool.h>

/*
 * This file defines common macros and structs
 */

#define TIME_IN_RESET_COUNT	5

/* Default command timeout in seconds */
#define DEFAULT_COMMAND_TIMEOUT	4

#define CPT_COUNT_THOLD		32
#define CPT_TIMER_THOLD		0x3F

#ifndef ROUNDUP4
#define ROUNDUP4(val)	(((val) + 3) & 0xfffffffc)
#endif

#ifndef ROUNDUP8
#define ROUNDUP8(val)	(((val) + 7) & 0xfffffff8)
#endif

#ifndef ROUNDUP16
#define ROUNDUP16(val)	(((val) + 15) & 0xfffffff0)
#endif

#ifndef __hot
#define __hot __attribute__((hot))
#endif

#define MOD_INC(i, l)   ((i) == (l - 1) ? (i) = 0 : (i)++)

struct cpt_qp_meta_info {
	struct rte_mempool *pool;
	int sg_mlen;
	int lb_mlen;
};

struct rid {
	/** Request id of a crypto operation */
	uintptr_t rid;
};

/*
 * Pending queue structure
 *
 */
struct pending_queue {
	/** Pending requests count */
	uint64_t pending_count;
	/** Array of pending requests */
	struct rid *rid_queue;
	/** Tail of queue to be used for enqueue */
	uint16_t enq_tail;
	/** Head of queue to be used for dequeue */
	uint16_t deq_head;
};

struct cpt_request_info {
	/** Data path fields */
	uint64_t comp_baddr;
	volatile uint64_t *completion_addr;
	volatile uint64_t *alternate_caddr;
	void *op;
	struct {
		uint64_t ei0;
		uint64_t ei1;
		uint64_t ei2;
		uint64_t ei3;
	} ist;
	uint8_t *rptr;

	/** Control path fields */
	uint64_t time_out;
	uint8_t extra_time;
} __rte_cache_aligned;

#endif /* _CPT_COMMON_H_ */
