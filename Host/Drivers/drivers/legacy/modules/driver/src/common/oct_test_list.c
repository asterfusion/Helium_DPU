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

#include  "oct_test_list.h"

struct test_list *initialize_test_list(int count, int extra_bytes)
{
	int i, size;
	struct test_list *tl;
	struct test_node *tn;

	tl = oct_test_alloc(sizeof(struct test_list));
	if (tl == NULL)
		return NULL;

	oct_test_memset(tl, 0, sizeof(struct test_list));
	oct_test_list_lock_init(&tl->lock);
	tl->head = tl->tail = NULL;

	size = sizeof(struct test_node) + extra_bytes;

	for (i = 0; i < count; i++) {

		tn = oct_test_alloc(size);
		PRINT_DBG("%s Node[%d] alloc @ %p\n", __FUNCTION__, i, tn);

		if (tn == NULL) {
			cleanup_test_list(tl, i);
			oct_test_free(tl);
			return NULL;
		}
		memset(tn, 0, size);

		tn->node_status = NODE_IN_USE;
		__put_free_node(tl, tn);
		tl->node_count++;
	}

	PRINT_DBG("Test list initialized at %p\n", tl);
	return tl;
}

int cleanup_test_list(struct test_list *tl, int count)
{
	int empty = 0, i = 0;
	struct test_node *tn, *tnext;

	if (tl == NULL) {
		PRINT_ERR("%s  Test List Pointer is NULL\n", __FUNCTION__);
		return -EINVAL;
	}

	oct_test_list_lock(&tl->lock);

	if (count > tl->avail_count) {
		PRINT_ERR
		    ("%s test list (%p) called with count: %d available: %d\n",
		     __FUNCTION__, tl, count, tl->avail_count);
		oct_test_list_unlock(&tl->lock);
		return -EINVAL;
	}

	tn = tl->head;
	while (tn != NULL) {
		tnext = tn->next;
		PRINT_DBG(" %s freeing node @ %p\n", __FUNCTION__, tn);
		oct_test_free(tn);
		i++;
		tl->node_count--;
		tl->avail_count--;
		if ((i != count)
		    && ((tl->node_count == 0) || (tl->avail_count == 0))) {
			PRINT_ERR
			    (" %s Error! Node Count: %d Available Count: %d after %d operations\n",
			     __FUNCTION__, tl->node_count, tl->avail_count, i);
			oct_test_list_unlock(&tl->lock);
			return -EINVAL;
		}
		tn = tnext;
	}

	if (tl->node_count == 0) {
		empty = 1;
		tl->head = tl->tail = NULL;
	}

	oct_test_list_unlock(&tl->lock);

	if (i != count) {
		PRINT_ERR(" %s Expected to free %d nodes, found %d\n",
			  __FUNCTION__, count, i);
	}

	if (empty) {
		//PRINT_MSG("%s List @ %p is empty. freeing it now!\n", __FUNCTION__, tl);
		oct_test_free(tl);
	}

	return 0;
}

void print_test_list(struct test_list *tl)
{
	int i = 0;
	struct test_node *tn;

	if (tl == NULL) {
		PRINT_ERR("%s  Test List Pointer is NULL\n", __FUNCTION__);
		return;
	}

	PRINT_MSG
	    ("\n\nPrinting List @ %p head: %p tail: %p (avail: %d node: %d)\n",
	     tl, tl->head, tl->tail, tl->avail_count, tl->node_count);

	oct_test_list_lock(&tl->lock);
	tn = tl->head;
	while (tn != NULL) {
		PRINT_MSG("Node[%d] tn @ %p next @ %p\n", i, tn, tn->next);
		tn = tn->next;
	}

	oct_test_list_unlock(&tl->lock);
	return;
}

struct test_node *__get_next_node(struct test_list *tl)
{
	struct test_node *tn = NULL;

	PRINT_DBG("%s head: %p tail: %p\n", __FUNCTION__, tl->head, tl->tail);

	oct_test_list_lock(&tl->lock);

	if (tl->tail != NULL) {

		tn = tl->head;
		if (tn->node_status != NODE_IS_FREE) {
			PRINT_DBG
			    (" %s Error: Node in test list (%p) has status %d\n",
			     __FUNCTION__, tl, tn->node_status);
#ifdef TEST_LIST_DEBUG
			PRINT_DBG("%s  Node %p: Last reference from %s:%d\n",
				  __FUNCTION__, tn, tn->dbg_func, tn->dbg_line);
#endif
			oct_test_list_unlock(&tl->lock);
			return NULL;
		}

		tl->head = tl->head->next;
		if (tl->head == NULL)
			tl->tail = NULL;

		tn->next = NULL;
		tn->node_status = NODE_IN_USE;

		tl->avail_count--;
	}

	oct_test_list_unlock(&tl->lock);

	return tn;
}

int __put_free_node(struct test_list *tl, struct test_node *tn)
{
	if (tn->node_status == NODE_IS_FREE) {
		PRINT_ERR("%s Error: Node (%p) has status %d\n",
			  __FUNCTION__, tn, tn->node_status);
#ifdef TEST_LIST_DEBUG
		PRINT_DBG("%s  Node %p: Last reference from %s:%d\n",
			  __FUNCTION__, tn, tn->dbg_func, tn->dbg_line);
#endif
		return -EINVAL;
	}

	oct_test_list_lock(&tl->lock);

	tn->next = NULL;
	tn->node_status = NODE_IS_FREE;

	if (tl->tail == NULL) {
		tl->head = tl->tail = tn;
	} else {
		tl->tail->next = tn;
		tl->tail = tn;
	}

	tl->avail_count++;
	PRINT_DBG("%s node: %p  tl: %p head: %p tail: %p\n",
		  __FUNCTION__, tn, tl, tl->head, tl->tail);

	oct_test_list_unlock(&tl->lock);

	return 0;
}

/* $Id: oct_test_list.c 141410 2016-06-30 14:37:41Z mchalla $ */
