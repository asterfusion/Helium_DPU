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

/*! \file   oct_test_list.h
    \brief  Common: A linked list implementation used for test programs.
*/

#ifndef  __OCT_TEST_LIST_H__
#define  __OCT_TEST_LIST_H__

//#define   TEST_LIST_DEBUG

#ifdef  __KERNEL__

#include "cavium_sysdep.h"
#include "cavium_defs.h"

typedef spinlock_t oct_test_lock_t;

#define  oct_test_list_lock_init(plock)    cavium_spin_lock_init((plock))
#define  oct_test_list_lock(plock)         cavium_spin_lock_softirqsave((plock))
#define  oct_test_list_unlock(plock)       cavium_spin_unlock_softirqrestore((plock))

#define  oct_test_alloc(size)              kmalloc((size), GFP_ATOMIC)
#define  oct_test_free(ptr)                kfree((ptr))

#define  oct_test_memset(ptr, val, size)   memset((ptr), (val), (size))
#define  oct_test_strcpy(dest, src)        strcpy((dest), (src))

#define  PRINT_ERR(format, ...)            printk( format, ## __VA_ARGS__)
#define  PRINT_MSG                         PRINT_ERR

#ifdef   TEST_LIST_DEBUG
#define  PRINT_DBG(format, ...)      printk( format, ## __VA_ARGS__)
#else
#define  PRINT_DBG(format, ...)      do {  } while(0)
#endif

#else

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

typedef int oct_test_lock_t;

#define  oct_test_list_lock_init(plock)    do { } while(0)
#define  oct_test_list_lock(plock)         do { } while(0)
#define  oct_test_list_unlock(plock)       do { } while(0)

#define  oct_test_alloc(size)              malloc((size))
#define  oct_test_free(ptr)                free((ptr))

#define  oct_test_memset(ptr, val, size)   memset((ptr), (val), (size))
#define  oct_test_strcpy(dest, src)        strcpy((dest), (src))

#define  PRINT_ERR(format, ...)      printf( format, ## __VA_ARGS__)
#define  PRINT_MSG                   PRINT_ERR

#ifdef   TEST_LIST_DEBUG
#define  PRINT_DBG(format, ...)      printf( format, ## __VA_ARGS__)
#else
#define  PRINT_DBG(format, ...)      do {  } while(0)
#endif

#endif

#define   NODE_IN_USE   1
#define   NODE_IS_FREE  0

struct test_node {

	void *next;		/* Next item in linked list. */
	void *tptr;		/* Pointer to test specific data structure */

	int node_status;

#ifdef  TEST_LIST_DEBUG
	char dbg_func[80];	/* Debug - Function that made last call. */
	int dbg_line;		/* Debug - Line number of last call */
#endif
};

struct test_list {

	oct_test_lock_t lock;

	struct test_node *head, *tail;	/* Pointer to start and end of list. */

	int node_count;		/* Total number of nodes initialized */

	int avail_count;	/* Total available nodes. */

};

struct test_list *initialize_test_list(int count, int extra_bytes);

int cleanup_test_list(struct test_list *tl, int count);

void print_test_list(struct test_list *tl);

extern struct test_node *__get_next_node(struct test_list *tl);

extern int __put_free_node(struct test_list *tl, struct test_node *tn);

#define        peek_node(tl)          (tl->head)

#ifdef TEST_LIST_DEBUG
#define  get_next_node(tl)                                 \
	({                                                     \
		struct test_node *n = __get_next_node((tl));       \
		if(n) {                                            \
			oct_test_strcpy(n->dbg_func, __FUNCTION__);    \
			n->dbg_line  = __LINE__;                       \
		}                                                  \
		n;                                                 \
	})

#define  put_free_node(tl, tn)                             \
	({                                                     \
		int ret = __put_free_node((tl), (tn));             \
		if((tl) && (tn)) {                                 \
			oct_test_strcpy((tn)->dbg_func, __FUNCTION__); \
			(tn)->dbg_line  = __LINE__;                    \
		}                                                  \
		ret;                                               \
	})

#else

#define  get_next_node(tl)           __get_next_node((tl))
#define  put_free_node(tl, tn)       __put_free_node((tl), (tn))

#endif

#endif

/* $Id: oct_test_list.h 141410 2016-06-30 14:37:41Z mchalla $ */
