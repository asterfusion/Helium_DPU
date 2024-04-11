/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file pending_list.h
    \brief  Host Driver: Pending list for host instructions. 
*/

#ifndef __PENDING_LIST_H__
#define __PENDING_LIST_H__

#include "octeon_instr.h"

/** Status of an entry in the pending list.
 */
typedef enum {
	OCTEON_PENDING_ENTRY_FREE = 0,
	OCTEON_PENDING_ENTRY_USED,
	OCTEON_PENDING_ENTRY_TIMEOUT,
	OCTEON_PENDING_ENTRY_REMOVE
} OCTEON_PENDING_ENTRY_STATUS;

/** Structure of an entry in pending list.
 */
typedef struct {

  /** Used to add/delete this entry to one of the 3 response lists. */
	cavium_list_t list;

  /** Index in the input queue where this request was posted */
	uint16_t queue_index;

  /** Queue into which request was posted. */
	uint16_t iq_no;

  /** Index into pending_list that is returned to the user (for polling) */
	uint32_t request_id;

  /** Status of this entry */
	OCTEON_PENDING_ENTRY_STATUS status;

  /** The instruction itself (not in the format that Octeon sees it)*/
	octeon_soft_instruction_t *instr;

} octeon_pending_entry_t;

#define OCT_PENDING_ENTRY_SIZE  (sizeof(octeon_pending_entry_t))

#define PEND_ENTRY_CALLBACK(pend_entry_ptr)                        \
           (pend_entry_ptr->instr->req_info.callback)

#define PEND_ENTRY_CALLBACK_ARG(pend_entry_ptr)                    \
         (pend_entry_ptr->instr->req_info.callback_arg)

/** Pending list implementation for each Octeon device. */

typedef struct {

   /** Pending list for input instructions */
	octeon_pending_entry_t *list;

   /** A list which indicates which entry in the pending_list above is free */
	uint32_t *free_list;

   /** The next location in pending_free_list where an index into pending_list
      can be saved */
	uint32_t free_index;

   /** Number of pending list entries. */
	uint32_t entries;

   /** Count of pending instructions */
	cavium_atomic_t instr_count;

   /** A lock to control access to the pending list */
	cavium_spinlock_t lock;

} octeon_pending_list_t;

/** Allocate and initialize a pending list for the number of entries
  * given by "count".
  * @param oct - pointer to the octeon device structure.
  * @return 0 if the allocation was successful, 1 otherwise.
  */
int octeon_init_pending_list(octeon_device_t * oct);

int octeon_init_iq_pending_list(octeon_device_t * oct, int iq_no,
				uint32_t count);

/** Free the pending list resources.
  *  @param octeon_dev - pointer to the octeon device structure.
  */
int octeon_delete_pending_list(octeon_device_t * octeon_dev);

int octeon_delete_iq_pending_list(octeon_device_t * oct,
				  octeon_pending_list_t * plist);

int wait_for_pending_requests(octeon_device_t * oct, int q_no);

int wait_for_all_pending_requests(octeon_device_t * oct);

/** Adds a instruction waiting for response from octeon to the
  * pending list.
  * @param octeon_dev - pointer to the octeon device structure.
  * @param  soft_instr  -  the instruction to add to pending list.
  * @return NULL if the instruction could not be added, else a 
  *         pointer to the entry in pending list is returned.
  */
octeon_pending_entry_t *add_to_pending_list(octeon_device_t * octeon_dev,
					    octeon_soft_instruction_t *
					    soft_instr);

/**  Release an instruction from the pending list.
  *  @param octeon_dev - pointer to the octeon device structure.
  *  @param pending_entry - the pending entry which holds the instr to be freed.
  */
void release_from_pending_list(octeon_device_t * octeon_dev,
			       octeon_pending_entry_t * pending_entry);

#endif

/* $Id: pending_list.h 141410 2016-06-30 14:37:41Z mchalla $ */
