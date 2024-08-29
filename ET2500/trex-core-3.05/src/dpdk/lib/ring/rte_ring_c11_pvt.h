/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2017,2018 HXT-semitech Corporation.
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * Copyright (c) 2021 Arm Limited
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_C11_PVT_H_
#define _RTE_RING_C11_PVT_H_

static __rte_always_inline void
__rte_ring_update_tail(struct rte_ring_headtail *ht, uint32_t old_val,
		uint32_t new_val, uint32_t single, uint32_t enqueue)
{
	RTE_SET_USED(enqueue);

	/*
	 * If there are other enqueues/dequeues in progress that preceded us,
	 * we need to wait for them to complete
	 */
	if (!single)
		rte_wait_until_equal_32((uint32_t *)(uintptr_t)&ht->tail, old_val,
			rte_memory_order_relaxed);

	rte_atomic_store_explicit(&ht->tail, new_val, rte_memory_order_release);
}

/**
 * @internal This function updates the producer head for enqueue
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sp
 *   Indicates whether multi-producer path is needed or not
 * @param n
 *   The number of elements we will want to enqueue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where enqueue starts
 * @param new_head
 *   Returns the current/new head value i.e. where enqueue finishes
 * @param free_entries
 *   Returns the amount of free space in the ring BEFORE head was moved
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_move_prod_head(struct rte_ring *r, unsigned int is_sp,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *free_entries)
{
	const uint32_t capacity = r->capacity;
	uint32_t cons_tail;
	unsigned int max = n;
	int success;

	*old_head = rte_atomic_load_explicit(&r->prod.head, rte_memory_order_relaxed);
	do {
		/* Reset n to the initial burst count */
		n = max;

		/* Ensure the head is read before tail */
		rte_atomic_thread_fence(rte_memory_order_acquire);

		/* load-acquire synchronize with store-release of ht->tail
		 * in update_tail.
		 */
		cons_tail = rte_atomic_load_explicit(&r->cons.tail,
					rte_memory_order_acquire);

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > cons_tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*free_entries = (capacity + cons_tail - *old_head);

		/* check that we have enough room in ring */
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			return 0;

		*new_head = *old_head + n;
		if (is_sp) {
			r->prod.head = *new_head;
			success = 1;
		} else
			/* on failure, *old_head is updated */
			success = rte_atomic_compare_exchange_strong_explicit(&r->prod.head,
					old_head, *new_head,
					rte_memory_order_relaxed,
					rte_memory_order_relaxed);
	} while (unlikely(success == 0));
	return n;
}

/**
 * @internal This function updates the consumer head for dequeue
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sc
 *   Indicates whether multi-consumer path is needed or not
 * @param n
 *   The number of elements we will want to dequeue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where dequeue starts
 * @param new_head
 *   Returns the current/new head value i.e. where dequeue finishes
 * @param entries
 *   Returns the number of entries in the ring BEFORE head was moved
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_move_cons_head(struct rte_ring *r, int is_sc,
		unsigned int n, enum rte_ring_queue_behavior behavior,
		uint32_t *old_head, uint32_t *new_head,
		uint32_t *entries)
{
	unsigned int max = n;
	uint32_t prod_tail;
	int success;

	/* move cons.head atomically */
	*old_head = rte_atomic_load_explicit(&r->cons.head, rte_memory_order_relaxed);
	do {
		/* Restore n as it may change every loop */
		n = max;

		/* Ensure the head is read before tail */
		rte_atomic_thread_fence(rte_memory_order_acquire);

		/* this load-acquire synchronize with store-release of ht->tail
		 * in update_tail.
		 */
		prod_tail = rte_atomic_load_explicit(&r->prod.tail,
					rte_memory_order_acquire);

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1.
		 */
		*entries = (prod_tail - *old_head);

		/* Set the actual entries for dequeue */
		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (unlikely(n == 0))
			return 0;

		*new_head = *old_head + n;
		if (is_sc) {
			r->cons.head = *new_head;
			success = 1;
		} else
			/* on failure, *old_head will be updated */
			success = rte_atomic_compare_exchange_strong_explicit(&r->cons.head,
							old_head, *new_head,
							rte_memory_order_relaxed,
							rte_memory_order_relaxed);
	} while (unlikely(success == 0));
	return n;
}

#endif /* _RTE_RING_C11_PVT_H_ */
