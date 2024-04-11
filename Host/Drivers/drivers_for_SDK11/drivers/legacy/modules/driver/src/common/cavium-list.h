/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file   cavium-list.h
    \brief  Common: A linked list implementation used to manipulate internal
                    driver lists.
*/

#ifndef _CAVIUM_LIST_H
#define _CAVIUM_LIST_H

struct __cavium_list_node {
	struct __cavium_list_node *le_next;
	struct __cavium_list_node *le_prev;
};

typedef struct __cavium_list_node cavium_list_t;

static inline void CAVIUM_INIT_LIST_HEAD(cavium_list_t * ptr)
{
	ptr->le_next = ptr;
	ptr->le_prev = ptr;
}

static inline
    void cavium_list_add_head(cavium_list_t * node, cavium_list_t * head)
{
	head->le_next->le_prev = node;
	node->le_next = head->le_next;
	head->le_next = node;
	node->le_prev = head;
}

static inline
    void cavium_list_add_tail(cavium_list_t * node, cavium_list_t * head)
{
	head->le_prev->le_next = node;
	node->le_prev = head->le_prev;
	head->le_prev = node;
	node->le_next = head;
}

/* Move nodes from list2 to list1. list1 must be empty. list2 will be empty
   when this call returns. */
static inline
    void cavium_list_move(cavium_list_t * list1, cavium_list_t * list2)
{
	if (list2->le_next != list2) {
		list1->le_next = list2->le_next;
		list1->le_next->le_prev = list1;
		list1->le_prev = list2->le_prev;
		list1->le_prev->le_next = list1;
	}

	list2->le_next = list2->le_prev = list2;
}

/* Get the node at the head of a list. The node is not removed from the list. */
static inline cavium_list_t *cavium_list_get_head(cavium_list_t * root)
{
	if ((root->le_prev == root) && (root->le_next == root))
		return NULL;

	return root->le_next;
}

/* Get the node at the tail of a list. The node is not removed from the list. */
static inline cavium_list_t *cavium_list_get_tail(cavium_list_t * root)
{
	if ((root->le_prev == root) && (root->le_next == root))
		return NULL;

	return root->le_prev;
}

/* Remove the node passed as argument from its list. */
static inline void cavium_list_del(cavium_list_t * node)
{
	node->le_next->le_prev = node->le_prev;
	node->le_prev->le_next = node->le_next;
}

/* Remove the node at the head of the list. The list would be empty at
   the end of this call if there are no more nodes in the list. */
static inline cavium_list_t *cavium_list_delete_head(cavium_list_t * root)
{
	cavium_list_t *node = cavium_list_get_head(root);
	if (node)
		cavium_list_del(node);

	return node;
}

#define cavium_list_for_each(tmp, head)  \
	for (tmp = (head)->le_next; tmp != (head); tmp = tmp->le_next)

#define cavium_list_for_each_safe(tmp, tmp2, head)  \
	for (tmp = (head)->le_next, tmp2 = tmp->le_next; tmp != (head); tmp = tmp2, tmp2 = tmp->le_next)

#endif

/* $Id: cavium-list.h 141410 2016-06-30 14:37:41Z mchalla $ */
