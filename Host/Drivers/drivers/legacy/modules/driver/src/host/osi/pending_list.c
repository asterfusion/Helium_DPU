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

#include "octeon_main.h"
#include "octeon_debug.h"
#include "octeon_macros.h"

int octeon_init_iq_pending_list(octeon_device_t * oct, int iq_no,
				uint32_t count)
{
	int i;
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];
	octeon_pending_list_t *plist;

	iq->pend_list_size = count;

	iq->plist = cavium_alloc_virt(sizeof(octeon_pending_list_t));
	plist = (octeon_pending_list_t *) iq->plist;

	if (!plist) {
		cavium_error("OCTEON: Allocation failed for iq pending list\n");
		return 1;
	}
	cavium_memset(plist, 0, sizeof(octeon_pending_list_t));

	plist->list =
	    (octeon_pending_entry_t *) cavium_alloc_virt(OCT_PENDING_ENTRY_SIZE
							 * count);
	if (!plist->list) {
		cavium_error("OCTEON: Allocation failed for pending list\n");
		cavium_free_virt(iq->plist);
		return 1;
	}
	cavium_memset((void *)plist->list, 0, OCT_PENDING_ENTRY_SIZE * count);

	plist->free_list =
	    (uint32_t *) cavium_alloc_virt(sizeof(uint32_t) * count);

	if (!plist->free_list) {
		cavium_error
		    ("OCTEON: Allocation failed for pending free_list\n");
		cavium_free_virt(plist->list);
		cavium_free_virt(plist);
		return 1;
	}

	plist->entries = count;

	for (i = 0; i < count; i++) {
		plist->free_list[i] = i;
		plist->list[i].status = OCTEON_PENDING_ENTRY_FREE;
	}

	cavium_spin_lock_init(&plist->lock);
	plist->free_index = 0;
	cavium_atomic_set(&plist->instr_count, 0);

	return 0;
}

int octeon_delete_iq_pending_list(octeon_device_t * oct,
				  octeon_pending_list_t * plist)
{
	uint32_t i, pl_index;
	octeon_soft_instruction_t *pend_instr;

	cavium_spin_lock(&plist->lock);

	for (i = 0; i < plist->free_index; i++) {
		pl_index = plist->free_list[i];
		if (plist->list[pl_index].status != OCTEON_PENDING_ENTRY_FREE) {
			cavium_print(PRINT_DEBUG,
				     "pending list index: %d is used \n",
				     pl_index);
			pend_instr = plist->list[pl_index].instr;
			delete_soft_instr(oct, pend_instr);
			plist->list[pl_index].status =
			    OCTEON_PENDING_ENTRY_FREE;
		}
	}

	if (plist->list)
		cavium_free_virt(plist->list);

	if (plist->free_list)
		cavium_free_virt(plist->free_list);

	cavium_spin_unlock(&plist->lock);
	cavium_free_virt(plist);

	return 0;
}

int wait_for_pending_requests(octeon_device_t * oct, int q_no)
{
	int pcount = 0, loop_count = 100;
	octeon_pending_list_t *plist;

	plist = (octeon_pending_list_t *) oct->instr_queue[q_no]->plist;
	/* Wait for pending requests to finish. */
	do {
		pcount = (int)cavium_atomic_read(&plist->instr_count);
		if (pcount)
			cavium_sleep_timeout(CAVIUM_TICKS_PER_SEC / 10);

	} while (pcount && (loop_count--));

	if (pcount) {
		cavium_error("OCTEON: There are %d outstanding requests\n",
			     pcount);
#ifdef CAVIUM_DEBUG
		{
			int lvl = octeon_debug_level;
			octeon_debug_level = PRINT_DEBUG;
			print_pending_list(oct);
			octeon_debug_level = lvl;
		}
#endif
		return 1;
	}

	return 0;
}

int wait_for_all_pending_requests(octeon_device_t * oct)
{
	int q_no, ret_val = 0;

	for (q_no = 0; q_no < oct->num_iqs; q_no++) {
		if (wait_for_pending_requests(oct, q_no)) {
			cavium_error
			    ("OCTEON: There are pending requests in IQ:%d\n",
			     q_no);
			ret_val = 1;
		}
	}

	return ret_val;
}

octeon_pending_entry_t *add_to_pending_list(octeon_device_t * oct,
					    octeon_soft_instruction_t * si)
{
	uint32_t pl_index, iq_num, plist_size;
	octeon_pending_list_t *plist;

	iq_num = SOFT_INSTR_IQ_NO(si);
	plist = (octeon_pending_list_t *) oct->instr_queue[iq_num]->plist;
	plist_size = oct->instr_queue[iq_num]->pend_list_size;

	/* Grab the lock for pending list now */
	cavium_spin_lock_softirqsave(&plist->lock);

	if (plist->free_index == plist_size) {
		cavium_error
		    ("OCTEON: No space in pending list; free_index: %d\n",
		     plist->free_index);
		/* Release the lock for pending list now */
		cavium_spin_unlock_softirqrestore(&plist->lock);
		return NULL;
	}

	pl_index = plist->free_list[plist->free_index];
	if (plist->list[pl_index].status != OCTEON_PENDING_ENTRY_FREE) {
		cavium_error("OCTEON: Pending list entry at %d is occupied\n",
			     pl_index);
		/* Release the lock for pending list now */
		cavium_spin_unlock_softirqrestore(&plist->lock);
		return NULL;
	}

	plist->free_index++;

	plist->list[pl_index].instr = si;
	plist->list[pl_index].request_id =
	    ((0x0000003F & iq_num) | (pl_index << 6));
	plist->list[pl_index].status = OCTEON_PENDING_ENTRY_USED;
	plist->list[pl_index].iq_no = SOFT_INSTR_IQ_NO(si);

	/* Increment the count of pending instructions. */
#ifdef CAVIUM_DEBUG
	cavium_atomic_check_and_inc(&plist->instr_count, plist->entries,
				    __CVM_FILE__, __CVM_LINE__);
#else
	cavium_atomic_inc(&plist->instr_count);
#endif

	/* Release the lock for pending list now */
	cavium_spin_unlock_softirqrestore(&plist->lock);

	si->req_info.status = OCTEON_REQUEST_PENDING;
	si->irh.rid = pl_index;
	si->req_info.request_id = ((0x0000003F & iq_num) | (pl_index << 6));

	/* The timeout is specified in millisecs. We need to convert to the
	 * internal clock tick representation. 05.10.05
	 */
	si->req_info.timeout = CAVIUM_INTERNAL_TIME(si->req_info.timeout);
	cavium_print(PRINT_DEBUG,
		     "Instr timeout is %u; timeout calculated is %lu\n",
		     si->req_info.timeout, si->timeout);

	return (&plist->list[pl_index]);
}

void
release_from_pending_list(octeon_device_t * oct, octeon_pending_entry_t * pe)
{
	octeon_pending_list_t *plist =
	    (octeon_pending_list_t *) oct->instr_queue[pe->iq_no]->plist;

	cavium_spin_lock_softirqsave(&plist->lock);
	plist->free_index--;
	plist->free_list[plist->free_index] = (pe->request_id) >> 6;
	pe->status = OCTEON_PENDING_ENTRY_FREE;

	/* Decrement the count of pending instructions. */
	cavium_atomic_dec(&plist->instr_count);

	cavium_spin_unlock_softirqrestore(&plist->lock);
	return;
}

/* $Id: pending_list.c 162991 2017-07-20 10:18:44Z mchalla $ */
