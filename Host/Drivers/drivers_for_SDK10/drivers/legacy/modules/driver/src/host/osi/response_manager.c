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
#include "octeon_reg_defs.h"

oct_poll_fn_status_t
oct_poll_check_unordered_list(void *octptr, unsigned long arg);

void (*noresp_buf_free_fn[MAX_OCTEON_DEVICES][NORESP_TYPES + 1]) (void *);

int octeon_setup_response_list(octeon_device_t * oct)
{
	int i, ret = 0;
#ifdef OCT_NIC_IQ_USE_NAPI
	struct cavium_wq *cwq;
#else	
	octeon_poll_ops_t poll_ops;
#endif	

	for (i = 0; i < MAX_RESPONSE_LISTS; i++) {
		CAVIUM_INIT_LIST_HEAD(&oct->response_list[i].head);
		cavium_spin_lock_init(&oct->response_list[i].lock);
	}

	for (i = 0; i <= NORESP_TYPES; i++) {
		noresp_buf_free_fn[oct->octeon_id][i] = NULL;
	}

#ifdef OCT_NIC_IQ_USE_NAPI

	spin_lock_init(&oct->cmd_resp_wqlock);

	oct->req_comp_wq.wq = alloc_workqueue("req-comp", WQ_MEM_RECLAIM, 0);
	if (!oct->req_comp_wq.wq) {
		dev_err(&oct->pci_dev->dev, "failed to create wq thread\n");
		return -ENOMEM;
	}

	cwq = &oct->req_comp_wq;
	INIT_DELAYED_WORK(&cwq->wk.work, oct_poll_req_completion);
	cwq->wk.ctxptr = oct;
	oct->cmd_resp_state = OCT_DRV_ONLINE;
	queue_delayed_work(cwq->wq, &cwq->wk.work, msecs_to_jiffies(50));

#else
	cavium_memset(&poll_ops, 0, sizeof(octeon_poll_ops_t));

	poll_ops.fn = oct_poll_req_completion;
	poll_ops.fn_arg = 0UL;
	poll_ops.ticks = 1;
	poll_ops.rsvd = 0xff;
	ret = octeon_register_poll_fn(oct->octeon_id, &poll_ops);
#endif

/*	poll_ops.fn     = oct_poll_check_unordered_list;
	poll_ops.ticks  = CAVIUM_TICKS_PER_SEC/10;
	ret = octeon_register_poll_fn(oct->octeon_id, &poll_ops);*/

	return ret;
}

void octeon_delete_response_list(octeon_device_t * oct)
{
#ifdef OCT_NIC_IQ_USE_NAPI
	cancel_delayed_work_sync(&oct->req_comp_wq.wk.work);
	destroy_workqueue(oct->req_comp_wq.wq);
#else	
	octeon_unregister_poll_fn(oct->octeon_id, oct_poll_req_completion, 0);
//      octeon_unregister_poll_fn(oct->octeon_id, oct_poll_check_unordered_list, 0);
#endif
}

/*
   API to query unordered request status 
*/
uint32_t
octeon_query_request_status(uint32_t octeon_id UNUSED,
			    octeon_query_request_t * query)
{
	octeon_device_t *octeon_dev = get_octeon_device(query->octeon_id);
	if (octeon_dev == NULL) {
		cavium_error
		    ("OCTEON: Request query for invalid octeon device: %d\n",
		     query->octeon_id);
		return 1;
	}
	if (process_unordered_poll(octeon_dev, query)) {
		return 1;
	}
	return 0;
}

static inline void
octeon_pci_unmap_sg_list(octeon_device_t * oct,
			 octeon_sg_entry_t * sg,
			 uint64_t hw_addr, uint32_t sg_cnt, uint32_t type)
{
	uint32_t i, dir;
	uint16_t size;

	dir =
	    (type ==
	     OCTEON_DMA_GATHER) ? CAVIUM_PCI_DMA_TODEVICE :
	    CAVIUM_PCI_DMA_FROMDEVICE;

	for (i = 0; i < sg_cnt; i++) {
		if (sg[i / 4].ptr[i % 4]) {

			size = CAVIUM_GET_SG_SIZE(&sg[i / 4], (i % 4));

			octeon_pci_unmap_single(oct->pci_dev,
						sg[i / 4].ptr[i % 4], size,
						dir);
		}
	}

	if (type == OCTEON_DMA_SCATTER)
		dir = CAVIUM_PCI_DMA_TODEVICE;

	octeon_pci_unmap_single(oct->pci_dev, hw_addr,
				((ROUNDUP4(sg_cnt) >> 2) * OCT_SG_ENTRY_SIZE),
				dir);
}

// *INDENT-OFF*
void
delete_soft_instr_buffers(octeon_device_t             *octeon_dev UNUSED,
                          octeon_soft_instruction_t   *soft_instr)
{
	cavium_print(PRINT_DEBUG,"delete_soft_instr: alloc flags is 0x%x\n",
	             SOFT_INSTR_ALLOCFLAGS(soft_instr));
	if(SOFT_INSTR_ALLOCFLAGS(soft_instr) & OCTEON_RPTR_HEADER)
		cavium_free_buffer(octeon_dev,(uint8_t *)((uint64_t *)soft_instr->status_word - 1));

	if(SOFT_INSTR_ALLOCFLAGS(soft_instr) & OCTEON_RPTR_SCATTER)
		cavium_free_buffer(octeon_dev, (uint8_t*)soft_instr->scatter_ptr);

	/* If a gather list was created, its time to free it */
	if(SOFT_INSTR_ALLOCFLAGS(soft_instr) & OCTEON_DPTR_GATHER)
		cavium_free_buffer(octeon_dev, (uint8_t*)soft_instr->gather_ptr);

	/* If the input buffers were coalesced in direct dma mode, we
		should free that too.
	*/
	if(SOFT_INSTR_ALLOCFLAGS(soft_instr) & OCTEON_DPTR_COALESCED)
		cavium_free_buffer(octeon_dev, (uint8_t*)soft_instr->dptr);


	if(SOFT_INSTR_ALLOCFLAGS(soft_instr) & OCTEON_SOFT_INSTR_ALLOCATED)
		cavium_free_buffer(octeon_dev, (uint8_t*)soft_instr);

}
// *INDENT-ON*

static __inline void
release_soft_instr(octeon_device_t * octeon_dev,
		   octeon_soft_instruction_t * soft_instr,
		   octeon_req_status_t status)
{
	instr_callback_t softinstr_callback = SOFT_INSTR_CALLBACK(soft_instr);
	void *softinstr_callarg = SOFT_INSTR_CALLBACK_ARG(soft_instr);
	octeon_instr3_64B_t o3_cmd;

	cavium_print(PRINT_FLOW, "release soft Instr...\n");

	if ((octeon_dev->chip_id == OCTEON_CN83XX_PF)
	    || (octeon_dev->chip_id == OCTEON_CN83XX_VF)) {

		memcpy(&o3_cmd, &soft_instr->command, 64);
#ifndef IOQ_PERF_MODE_O3
		soft_instr->command.rptr = o3_cmd.rptr;
#endif
	}

	if (soft_instr->dptr) {
		if (!soft_instr->ih.gather) {
			octeon_pci_unmap_single(octeon_dev->pci_dev,
						soft_instr->command.dptr,
						soft_instr->ih.dlengsz,
						CAVIUM_PCI_DMA_TODEVICE);
		} else {
			octeon_pci_unmap_sg_list(octeon_dev,
						 (octeon_sg_entry_t *)
						 soft_instr->dptr,
						 soft_instr->command.dptr,
						 soft_instr->ih.dlengsz,
						 OCTEON_DMA_GATHER);
		}
	}

	if (soft_instr->rptr) {

		/* rptr is being swapped in __do_instruction_processing() in 
		request_manager.c along with irh. Before unmapping the rptr ,
		swap to get the original iova.  */
		if ((octeon_dev->chip_id == OCTEON_CN83XX_PF)
			|| (octeon_dev->chip_id == OCTEON_CN83XX_VF))
			octeon_swap_8B_data(&soft_instr->command.rptr, 1);

		if (!soft_instr->irh.scatter) {
			octeon_pci_unmap_single(octeon_dev->pci_dev,
						soft_instr->command.rptr,
						soft_instr->irh.rlenssz,
						CAVIUM_PCI_DMA_FROMDEVICE);
		} else {
			octeon_pci_unmap_sg_list(octeon_dev,
						 (octeon_sg_entry_t *)
						 soft_instr->rptr,
						 soft_instr->command.rptr,
						 soft_instr->irh.rlenssz,
						 OCTEON_DMA_SCATTER);
		}
	}

	if (SOFT_INSTR_ALLOCFLAGS(soft_instr))
		delete_soft_instr_buffers(octeon_dev, soft_instr);

	if (softinstr_callback) {	/* invoke callback: after delete buffers */
		(*softinstr_callback) (status, softinstr_callarg);
	}

	return;
}

static __inline octeon_pending_entry_t *get_list_head(octeon_device_t *
						      octeon_dev UNUSED,
						      octeon_response_list_t *
						      response_list)
{
	if (response_list->head.le_next != &response_list->head)
		return (octeon_pending_entry_t *) response_list->head.le_next;
	else
		return NULL;
}

static __inline void
release_from_response_list(octeon_device_t * octeon_dev UNUSED,
			   octeon_pending_entry_t * pending_entry)
{
	cavium_list_del(&pending_entry->list);
}

void
push_response_list(octeon_response_list_t * response_list,
		   octeon_pending_entry_t * entry)
{
	cavium_spin_lock_softirqsave(&response_list->lock);
	cavium_list_add_tail(&entry->list, &response_list->head);
	cavium_spin_unlock_softirqrestore(&response_list->lock);
}

int process_ordered_list(octeon_device_t * octeon_dev, int force_quit)
{
	octeon_response_list_t *response_list;
	octeon_pending_entry_t *pending_entry;
	octeon_soft_instruction_t *soft_instr;
	octeon_req_status_t status;
	uint32_t request_complete = 0;
	uint32_t resp_to_process = MAX_ORD_REQS_TO_PROCESS;

	response_list = &octeon_dev->response_list[OCTEON_ORDERED_LIST];

	/* Keep checking for all completed requests. */
	do {
		/* Grab the lock for ordered response list. */
		cavium_spin_lock_softirqsave(&response_list->lock);

		pending_entry = get_list_head(octeon_dev, response_list);
		if (!pending_entry) {
			/* There are no pending ORDERED entries */
			cavium_spin_unlock_softirqrestore(&response_list->lock);
			return 1;
		}

		soft_instr = pending_entry->instr;
		/* Reset the status value everytime to OCTEON_REQUEST_PENDING */
		status = OCTEON_REQUEST_PENDING;
		if ((*(soft_instr->status_word) != COMPLETION_WORD_INIT)) {
			uint64_t status64 = *(soft_instr->status_word);
			if (((status64 & 0xff) != 0xff)) {

				octeon_swap_8B_data(&status64, 1);
				/* Do not copy to status if byte[0] is set. This can happen when
				   the status word has not been DMA'ed in completely when the check
				   above is made, thereby reading an incorrect status value.
				   Bug # 513. Error code of 0x00ff from core is illegal. */
				if (((status64 & 0xff) != 0xff))
					status =
					    (octeon_req_status_t) (status64 &
								   0xffffffffULL);
			}
		} else {
			/* this instruction has completed execution */

			/* response for this instruction is request-timed-out if force_quit is set */
			if (force_quit
			    || cavium_check_timeout(cavium_jiffies,
						    soft_instr->timeout)) {

				status = OCTEON_REQUEST_TIMEOUT;
			}
		}

		if (status != OCTEON_REQUEST_PENDING) {
			soft_instr->req_info.status = status;
			cavium_print(PRINT_REGS,
				     "process_ordered_list: releasing entry with status: %x\n",
				     status);
			release_from_response_list(octeon_dev, pending_entry);
			cavium_spin_unlock_softirqrestore(&response_list->lock);

			release_soft_instr(octeon_dev, soft_instr, status);
			release_from_pending_list(octeon_dev, pending_entry);
			request_complete++;
		} else {
			request_complete = 0;
			cavium_spin_unlock_softirqrestore(&response_list->lock);
		}

		/* If we hit the Max Ordered requests to process every loop, we quit
		   and let this function be invoked the next time the poll thread runs
		   to process the remaining requests. This function can take up the
		   entire CPU if there is no upper limit to the requests processed. */
		if (request_complete >= resp_to_process) {
			break;
		}
	} while (request_complete);
	return 0;
}

int
process_unordered_poll(octeon_device_t * octeon_dev,
		       octeon_query_request_t * query)
{
	octeon_pending_entry_t *pending_entry;
	octeon_soft_instruction_t *soft_instr;
	octeon_req_status_t status = OCTEON_REQUEST_PENDING;
	uint32_t iq_num = ((query->request_id) & 0x0000003F);
	octeon_instr_queue_t *instr_queue;
	octeon_pending_list_t *plist;

	instr_queue = octeon_dev->instr_queue[iq_num];
	plist = (octeon_pending_list_t *) instr_queue->plist;

	if (((query->request_id) >> 6) > instr_queue->pend_list_size) {
		cavium_error
		    ("OCTEON: process_unordered_list: No request with id: %d\n",
		     query->request_id);
		query->status = OCTEON_REQUEST_TIMEOUT;
		return 1;
	}

	pending_entry = &plist->list[query->request_id >> 6];

	if (pending_entry->status == OCTEON_PENDING_ENTRY_FREE) {
		cavium_error
		    ("OCTEON: process_unordered_list: No request with id: %d\n",
		     query->request_id);
		query->status = OCTEON_REQUEST_TIMEOUT;
		return 1;
	}

	if (pending_entry->request_id != query->request_id) {
		cavium_error
		    ("OCTEON: process_unordered_list: pending entry req_id (%d) does not match query req_id: %d\n",
		     pending_entry->request_id, query->request_id);
		query->status = OCTEON_REQUEST_TIMEOUT;
		return 1;
	}

	soft_instr = pending_entry->instr;
	if (SOFT_INSTR_RESP_ORDER(soft_instr) != OCTEON_RESP_UNORDERED) {
		cavium_error
		    ("OCTEON: process_unordered_list: request not unordered\n");
		query->status = OCTEON_REQUEST_TIMEOUT;
		return 1;
	}

	cavium_print(PRINT_DEBUG, "process_unordered_list: status @ 0x%p\n",
		     soft_instr->status_word);

	if (query->status == OCTEON_REQUEST_INTERRUPTED) {
		status = query->status;
		goto unordered_finish;
	}

	if (*(soft_instr->status_word) != COMPLETION_WORD_INIT) {
		uint64_t status64 = *(soft_instr->status_word);
		octeon_swap_8B_data(&status64, 1);
		/* Do not copy to status if byte[0] is 0xff. This can happen when the status word
		   has not been DMA'ed in completely when the check above is made, thereby reading an
		   incorrect status value. Bug # 513. Error code of 0x00ff from core is illegal. */
		if (!((status64 & 0xff) == 0xff))
			status =
			    (octeon_req_status_t) (status64 &
						   0x00000000ffffffffULL);
	} else {
		if (cavium_check_timeout(cavium_jiffies, soft_instr->timeout)) {
			status = OCTEON_REQUEST_TIMEOUT;
		}
	}
	cavium_print(PRINT_DEBUG, "Req Id: %d @ %p Status : %d\n",
		     query->request_id, soft_instr->status_word, status);

unordered_finish:
	if (status != OCTEON_REQUEST_PENDING) {
		octeon_response_list_t *response_list;
		if (SOFT_INSTR_RESP_MODE(soft_instr) == OCTEON_RESP_BLOCKING)
			response_list =
			    &octeon_dev->response_list
			    [OCTEON_UNORDERED_BLOCKING_LIST];
		else
			response_list =
			    &octeon_dev->response_list
			    [OCTEON_UNORDERED_NONBLOCKING_LIST];
		cavium_print(PRINT_DEBUG,
			     "process_unordered_list: release entry with status: %x\n",
			     status);

		cavium_spin_lock_softirqsave(&response_list->lock);
		release_from_response_list(octeon_dev, pending_entry);
		cavium_spin_unlock_softirqrestore(&response_list->lock);

		release_from_pending_list(octeon_dev, pending_entry);
		release_soft_instr(octeon_dev, soft_instr, status);
	}
	query->status = status;
	return status;
}

void process_noresponse_list(octeon_device_t * oct, octeon_instr_queue_t * iq)
{
	cavium_list_t instr_list, *tmp, *tmp2;
	octeon_soft_instruction_t *instr;
	uint32_t get_idx;

	CAVIUM_INIT_LIST_HEAD(&instr_list);

	cavium_spin_lock_softirqsave(&iq->lock);

	get_idx = iq->nr_free.get_idx;

	while (get_idx != iq->nr_free.put_idx) {
		cavium_print(PRINT_DEBUG,
			     "Removing buf @ %p type %d from idx %d\n",
			     iq->nr_free.q[get_idx].buf,
			     iq->nr_free.q[get_idx].buftype, get_idx);

// *INDENT-OFF*
		switch(iq->nr_free.q[get_idx].buftype) {
			case NORESP_BUFTYPE_INSTR:
				instr = (octeon_soft_instruction_t *)iq->nr_free.q[get_idx].buf;
				cavium_list_add_tail(&instr->list, &instr_list);
				break;
			case NORESP_BUFTYPE_NET:
			case NORESP_BUFTYPE_NET_SG:
			case NORESP_BUFTYPE_OHSM_SEND:
				noresp_buf_free_fn[oct->octeon_id][iq->nr_free.q[get_idx].buftype](iq->nr_free.q[get_idx].buf);
				break;
			default:
				cavium_error("%s Unknown buftype: %d buf: %p at idx %d\n", 
				             __CVM_FUNCTION__, iq->nr_free.q[get_idx].buftype,
				             iq->nr_free.q[get_idx].buf, get_idx);
		}
// *INDENT-ON*
		iq->nr_free.q[get_idx].buftype = 0;
		iq->nr_free.q[get_idx].buf = 0;
		INCR_INDEX_BY1(get_idx, iq->max_count);
	}

	iq->nr_free.get_idx = get_idx;

	cavium_spin_unlock_softirqrestore(&iq->lock);

	cavium_list_for_each_safe(tmp, tmp2, &instr_list) {
		octeon_soft_instruction_t *instr =
		    (octeon_soft_instruction_t *) tmp;
		cavium_list_del(tmp);
		release_soft_instr(oct, instr, instr->req_info.status);
	}

	return;
}

void
free_instr_from_lists(octeon_device_t * oct,
		      octeon_pending_entry_t * pe, uint32_t iq_no UNUSED)
{
	OCTEON_RESPONSE_LIST resp_list;
	octeon_soft_instruction_t *soft_instr;

	GET_RESPONSE_LIST(SOFT_INSTR_RESP_ORDER(pe->instr),
			  SOFT_INSTR_RESP_MODE(pe->instr), resp_list);

	cavium_spin_lock_softirqsave(&(oct->response_list[resp_list].lock));
	release_from_response_list(oct, pe);
	cavium_spin_unlock_softirqrestore(&
					  (oct->response_list[resp_list].lock));

	soft_instr = pe->instr;
	release_from_pending_list(oct, pe);
	delete_soft_instr_buffers(oct, soft_instr);
}

/* Called from delete_pending_list()  */
void
delete_soft_instr(octeon_device_t * octeon_dev,
		  octeon_soft_instruction_t * soft_instr)
{
	if (SOFT_INSTR_ALLOCFLAGS(soft_instr))
		delete_soft_instr_buffers(octeon_dev, soft_instr);
}

/* This routine is called to check the unordered blocking responses. The ioctl
   would be sleeping on a channel waiting for response. This routine is called
   from the request completion tasklet, thereby speeding up response time for
   unordered-blocking requests.
*/
void check_unordered_blocking_list(octeon_device_t * oct)
{
	cavium_list_t *curr = NULL, *tmp = NULL;
	octeon_pending_entry_t *pending_entry = NULL;
	octeon_response_list_t *response_list = NULL;
	octeon_soft_instruction_t *soft_instr = NULL;
	octeon_req_status_t status = OCTEON_REQUEST_PENDING;
	int count = 0;

	response_list =
	    (octeon_response_list_t *) & (oct->response_list
					  [OCTEON_UNORDERED_BLOCKING_LIST]);
	cavium_spin_lock_softirqsave(&response_list->lock);
	cavium_list_for_each_safe(curr, tmp, &response_list->head) {
		status = OCTEON_REQUEST_PENDING;
		if (count++ > 16)
			break;
		pending_entry = (octeon_pending_entry_t *) curr;
		soft_instr = pending_entry->instr;
		if (*(soft_instr->status_word) != COMPLETION_WORD_INIT) {
			uint64_t status64 = *(soft_instr->status_word);
			octeon_swap_8B_data(&status64, 1);
			/* Do not copy to status if byte[0] is 0xff. This can happen when
			   the status word has not been DMA'ed in completely when the check
			   above is made, thereby reading an incorrect status value.
			   Bug # 513. Error code of 0x00ff from core is illegal. */
			if (!((status64 & 0xff) == 0xff))
				status =
				    (octeon_req_status_t) (status64 &
							   0x00000000ffffffffULL);
		} else {
			if (cavium_check_timeout
			    (cavium_jiffies, soft_instr->timeout)) {
				status = OCTEON_REQUEST_TIMEOUT;
			}
		}

		if (status != OCTEON_REQUEST_PENDING) {
			soft_instr->req_info.status = status;
			cavium_print(PRINT_DEBUG,
				     "process_unordered_list: release entry with status: %x\n",
				     status);
			if (SOFT_INSTR_CALLBACK(soft_instr)) {
				SOFT_INSTR_CALLBACK(soft_instr) (status,
								 SOFT_INSTR_CALLBACK_ARG
								 (soft_instr));
				/* Else callback will be called again during query. */
				SET_SOFT_INSTR_CALLBACK(soft_instr, NULL);
			}
		}
	}
	cavium_spin_unlock_softirqrestore(&response_list->lock);

}

void octeon_request_completion_bh(unsigned long pdev)
{
	octeon_device_t *octeon_dev = (octeon_device_t *) pdev;

	octeon_dev->stats.comp_tasklet_count++;

	/* process_ordered_list returns 1 if list is empty. */
	if (!process_ordered_list(octeon_dev, 0))
		cavium_tasklet_schedule(&octeon_dev->comp_tasklet);
	check_unordered_blocking_list(octeon_dev);
}

/* Free any zombie entries in the UNORDERED NONBLOCKING LIST. These type of
   requests require the user app to query for completion. If the user app
   exits without a query, the pending entry would never be checked if not
   for this poll function.
   An alternative would have been to scan this response list when close() is
   called for the process. But that runs into problems when the device is
   opened by one process and the requests are sent by another (probably child)
   process. */
oct_poll_fn_status_t
oct_poll_check_unordered_list(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;
	cavium_list_t list, *curr, *tmp = NULL;
	octeon_pending_entry_t *pe;
	octeon_response_list_t *response_list;
	octeon_soft_instruction_t *si;

	response_list = (octeon_response_list_t *)
	    & (oct->response_list[OCTEON_UNORDERED_NONBLOCKING_LIST]);

	CAVIUM_INIT_LIST_HEAD(&list);

	cavium_spin_lock_softirqsave(&response_list->lock);

	cavium_list_for_each_safe(curr, tmp, &response_list->head) {
		pe = (octeon_pending_entry_t *) curr;
		si = pe->instr;
		if (pe->status == OCTEON_PENDING_ENTRY_TIMEOUT) {
			cavium_print(PRINT_DEBUG,
				     "Removing pending entry req_id:%d, opcode: %x\n",
				     pe->request_id, si->irh.opcode);
			release_from_response_list(oct, pe);
			pe->status = OCTEON_PENDING_ENTRY_REMOVE;
			cavium_list_add_tail(curr, &list);
		}
		if (pe->status == OCTEON_PENDING_ENTRY_USED) {
			if (cavium_check_timeout(cavium_jiffies, si->timeout)) {
				cavium_print(PRINT_DEBUG,
					     "Found pending entry @ %p, opcode: %x\n",
					     pe, si->irh.opcode);
				pe->status = OCTEON_PENDING_ENTRY_TIMEOUT;
			}
		}
	}			/* cavium list for each */
	cavium_spin_unlock_softirqrestore(&response_list->lock);

	cavium_list_for_each_safe(curr, tmp, &list) {
		pe = (octeon_pending_entry_t *) curr;
		si = pe->instr;
		cavium_print(PRINT_DEBUG, "Freeing pending list entry at %d\n",
			     pe->request_id);
		release_from_pending_list(oct, pe);
		SET_SOFT_INSTR_CALLBACK(si, NULL);
		release_soft_instr(oct, si, OCTEON_REQUEST_TIMEOUT);
		cavium_sleep_timeout(1);
	}

	return OCT_POLL_FN_CONTINUE;
}

#ifdef OCT_NIC_IQ_USE_NAPI
void oct_poll_req_completion(struct work_struct *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	octeon_device_t *oct = (octeon_device_t *)wk->ctxptr;
	struct cavium_wq *cwq = &oct->req_comp_wq;

	process_ordered_list(oct, 0);

	check_unordered_blocking_list(oct);

	queue_delayed_work(cwq->wq, &cwq->wk.work, msecs_to_jiffies(50));
}

#else
oct_poll_fn_status_t
oct_poll_req_completion(void *octptr, unsigned long arg UNUSED)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;

	process_ordered_list(oct, 0);

	check_unordered_blocking_list(oct);
	return OCT_POLL_FN_CONTINUE;
}
#endif

int
octeon_register_noresp_buf_free_fn(int oct_id, int buftype, void (*fn) (void *))
{
	octeon_device_t *oct = get_octeon_device(oct_id);

	if (oct == NULL) {
		cavium_error("%s: Invalid Octeon Id: %d\n", __CVM_FUNCTION__,
			     oct_id);
		return -ENODEV;
	}

	if (buftype > NORESP_TYPES) {
		cavium_error("%s: Invalid buftype: %d\n", __CVM_FUNCTION__,
			     buftype);
		return -EINVAL;
	}

	noresp_buf_free_fn[oct_id][buftype] = fn;

	return 0;
}

/* $Id: response_manager.c 163569 2017-07-25 15:58:46Z mchalla $ */
