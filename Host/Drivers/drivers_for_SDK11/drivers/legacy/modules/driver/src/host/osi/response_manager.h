/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file response_manager.h
    \brief Host Driver:  Response queues for host instructions.
*/

#ifndef __RESPONSE_MANAGER_H__
#define __RESPONSE_MANAGER_H__

#include "octeon_instr.h"
#include "octeon_iq.h"
#include "pending_list.h"

/* Maximum ordered requests to process in every invocation of
   process_ordered_list(). The function will continue to process requests as
   long as it can find one that has finished processing. If it keeps finding
   requests that have completed, the function can run for ever. The value
   defined here sets an upper limit on the number of requests it can process
   before it returns control to the poll thread.
*/
#define  MAX_ORD_REQS_TO_PROCESS   4096

/** Head of a response list. There are 6 response lists in the
 *  system. One for each response order- Unordered, ordered
 *  and 1 for noresponse entries on each instruction queue.
 */
typedef struct {

  /** List structure to add delete pending entries to */
	cavium_list_t head;

  /** A lock for this response list */
	cavium_spinlock_t lock;

} octeon_response_list_t;

/** The type of response list.
 */
typedef enum {
	OCTEON_ORDERED_LIST = 0,
	OCTEON_UNORDERED_NONBLOCKING_LIST = 1,
	OCTEON_UNORDERED_BLOCKING_LIST = 2
} OCTEON_RESPONSE_LIST;

/** Gets the response list index given the response order
 *  and instruction queue number.
 */
#define GET_RESPONSE_LIST(resp_order, resp_mode, resp_list)  \
           if(resp_order == OCTEON_RESP_ORDERED)                   \
               resp_list = OCTEON_ORDERED_LIST;                    \
           else                                                    \
               if(resp_mode == OCTEON_RESP_BLOCKING)               \
                   resp_list = OCTEON_UNORDERED_BLOCKING_LIST;     \
               else                                                \
                   resp_list = OCTEON_UNORDERED_NONBLOCKING_LIST;

/** Initialize the response lists. The number of response lists to create is
  * given by count.
  * @param octeon_dev      - the octeon device structure.
  */
int octeon_setup_response_list(octeon_device_t * octeon_dev);

void octeon_delete_response_list(octeon_device_t * octeon_dev);

/** Adds a instruction waitinng for a response from octeon to a response list.
  * @param resp_list - the response list to which the entry is added.
  * @param entry     - the pending entry that tracks the instruction.
  */
void push_response_list(octeon_response_list_t * resp_list,
			octeon_pending_entry_t * entry);

/** Checks the noresponse list associated with one of four instr queues.
  * The new read index tells the driver that last entry in the instr queue
  * where octeon has read an instr. The routine cleans up all entries from 
  * the previously marked (old) read index to the current (new) read index.
  * @param oct		   - the octeon device structure.
  * @param iq		   - the instruction queue structure.
  */
void process_noresponse_list(octeon_device_t * oct, octeon_instr_queue_t * iq);

/** Check the unordered response queue for the entry in "query".
  * Checks if an entry exists and if it does returns the current status
  * of that entry. If the instruction at that entry finished processing or
  * has timed-out, the entry is cleaned.
  * @param octeon_dev   -  the octeon device structure.
  * @param query        -  the query holds the request id of the entry to check
  * @return 0 if the entry existed, its status is returned in query->status.
  *         1 otherwise.
  */
int process_unordered_poll(octeon_device_t * octeon_dev,
			   octeon_query_request_t * query);

/** Check the status of first entry in the ordered list. If the instruction at
  * that entry finished processing or has timed-out, the entry is cleaned.
  * @param octeon_dev  - the octeon device structure.
  * @param force_quit - the request is forced to timeout if this is 1
  * @return 1 if the ordered list is empty, 0 otherwise.  
  */
int process_ordered_list(octeon_device_t * octeon_dev, int force_quit);

/** Routine executed as a tasklet for request completion processing in
  * interrupt context. It gets scheduled by the interrupt handler whenever
  * a FORCEINT interrupt is received on DMA Counter 1. It checks upto 16
  * UNORDERED BLOCKING mode requests for completion and calls their callback
  * function if the request is completed (or has timedout).
  */
void octeon_request_completion_bh(unsigned long pdev);

/**  Delete all allocation made for a soft instruction. The alloc flags for the
  *  instruction are checked to determine what buffers are to be deleted.
  *  @param  octeon_dev  -  the octeon device structure.
  *  @param  soft_instr  -  the soft instruction to deallocate.
  */
void delete_soft_instr(octeon_device_t * octeon_dev,
		       octeon_soft_instruction_t * soft_instr);

/**  Free the pending instruction from the pending list and from response list.
  *  @param  octeon_dev    -  the octeon device structure.
  *  @param pending_entry  -  the entry to be freed.
  *  @param iq_no          -  the instr queue on which the instruction
  *                           was posted.
  */
void free_instr_from_lists(octeon_device_t * octeon_dev,
			   octeon_pending_entry_t * pending_entry,
			   uint32_t iq_no);

#endif

/* $Id: response_manager.h 141410 2016-06-30 14:37:41Z mchalla $ */
