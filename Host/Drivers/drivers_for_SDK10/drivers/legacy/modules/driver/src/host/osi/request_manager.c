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
#include "octeon_mem_ops.h"

typedef struct {
	int status;
	int index;
} iq_post_status_t;

#ifdef OCT_NIC_IQ_USE_NAPI
void __check_db_timeout(octeon_device_t *oct, u64 iq_no);
void check_db_timeout(struct work_struct *work);
#else
oct_poll_fn_status_t check_db_timeout(void *octptr, unsigned long iq_no);
#endif

extern void cn83xx_dump_regs(octeon_device_t *, int iq_no);
static inline int IQ_INSTR_MODE_64B(octeon_device_t * oct, int iq_no)
{
	octeon_instr_queue_t *iq =
	    (octeon_instr_queue_t *) oct->instr_queue[iq_no];
	return (iq->iqcmd_64B);
}

#define IQ_INSTR_MODE_32B(oct, iq_no)  (!IQ_INSTR_MODE_64B(oct, iq_no))

/* Define this to return the request status comaptible to old code */
//#define OCTEON_USE_OLD_REQ_STATUS

int octeon_init_nr_free_list(octeon_instr_queue_t * iq, int count)
{
	int size;

	size = (sizeof(octeon_noresponse_list_t) * count);

	/* Initialize a list to holds NORESPONSE requests that have been fetched
	   by Octeon but has yet to be freed by driver. */
	iq->nrlist = cavium_alloc_virt(size);
	if (iq->nrlist == NULL) {
		cavium_error("OCTEON: Noresponse list allocation failed\n");
		return 1;
	}
	cavium_memset(iq->nrlist, 0, size);

	iq->nr_free.q = cavium_alloc_virt(size);
	if (iq->nr_free.q == NULL) {
		cavium_error
		    ("OCTEON: NoResponse Free list allocation failed\n");
		cavium_free_virt(iq->nrlist);
		iq->nrlist = NULL;
		return 1;
	}

	cavium_atomic_set(&iq->nr_free.count, 0);

	return 0;
}

/* Return 0 on success, 1 on failure */
int octeon_setup_iq(octeon_device_t * oct, int iq_no, void *app_ctx)
{
	if (oct->instr_queue[iq_no]) {
		cavium_error("IQ is in use. Cannot create the IQ: %d again\n",
			     iq_no);
		return 1;
	}
	oct->instr_queue[iq_no] =
	    cavium_alloc_virt(sizeof(octeon_instr_queue_t));

	if (oct->instr_queue[iq_no] == NULL)
		return 1;

	cavium_memset(oct->instr_queue[iq_no], 0, sizeof(octeon_instr_queue_t));

	oct->instr_queue[iq_no]->app_ctx = app_ctx;
	if (octeon_init_instr_queue(oct, iq_no)) {
		cavium_free_virt(oct->instr_queue[iq_no]);
		oct->instr_queue[iq_no] = NULL;
		return 1;
	}

	oct->num_iqs++;
	/* Enabling IQs in octnet_enable_io_queues() */
	//oct->fn_list.enable_io_queues(oct);
	return 0;
}

int wait_for_iq_instr_fetch(octeon_device_t * oct, int q_no)
{
	int retry = 1000, pending, instr_cnt = 0;
	octeon_instr_queue_t *instr_queue = oct->instr_queue[q_no];

	do {

		instr_cnt = 0;

		pending = cavium_atomic_read(&instr_queue->instr_pending);
		if (pending)
#ifdef OCT_NIC_IQ_USE_NAPI
			__check_db_timeout(oct, q_no);
#else			
			check_db_timeout(oct, q_no);
#endif			
		instr_cnt += pending;

		if (instr_cnt == 0)
			break;

		cavium_sleep_timeout(1);

	} while (retry-- && instr_cnt);

	return instr_cnt;
}

int wait_for_instr_fetch(octeon_device_t * oct)
{
	int i, retry = 1000, pending, instr_cnt = 0;

	do {

		instr_cnt = 0;

		for (i = 0; i < oct->num_iqs; i++) {
// *INDENT-OFF*
			pending = cavium_atomic_read(&oct->instr_queue[i]->instr_pending);
// *INDENT-ON*
			if (pending)
#ifdef OCT_NIC_IQ_USE_NAPI
				__check_db_timeout(oct, i);
#else			
				check_db_timeout(oct, i);
#endif				
			instr_cnt += pending;
		}

		if (instr_cnt == 0)
			break;

		cavium_sleep_timeout(1);

	} while (retry-- && instr_cnt);

	return instr_cnt;
}

static inline void
ring_doorbell(octeon_device_t * oct, octeon_instr_queue_t * iq)
{
	if (cavium_atomic_read(&oct->status) == OCT_DEV_RUNNING) {
		OCTEON_WRITE32(iq->doorbell_reg, iq->fill_cnt);
		iq->fill_cnt = 0;
		iq->last_db_time = cavium_jiffies;
		return;
	}
}

static inline void __copy_cmd_into_iq(octeon_instr_queue_t * iq, uint8_t * cmd)
{
	uint8_t *iqptr, cmdsize;

	cmdsize = ((iq->iqcmd_64B) ? 64 : 32);
	iqptr = iq->base_addr + (cmdsize * iq->host_write_index);

	cavium_memcpy(iqptr, cmd, cmdsize);

	/* Dump iQ cmd */
#if 0
	{
		int i = 0;
		uint64_t *tmp = (uint64_t *) iqptr;
		printk("IQ DUMP: iq no: %d dma addr: 0x%016lx, offset: %d\n",
		       iq->iq_no, iq->base_addr_dma, iq->host_write_index);
		for (i = 0; i < cmdsize / 8; i++)
			printk("word[%d]: 0x%016llx\n", i, *(tmp + i));
	}
#endif
}

static inline int
__post_command(octeon_device_t * octeon_dev UNUSED,
	       octeon_instr_queue_t * iq,
	       uint32_t force_db UNUSED, uint8_t * cmd)
{
	uint32_t index = -1;

	/* This ensures that the read index does not wrap around to the same 
	   position if queue gets full before Octeon could fetch any instr. */
	if (cavium_atomic_read(&iq->instr_pending) >= (iq->max_count - 1)) {
		cavium_error(
			     "OCTEON[%d]: IQ[%d] is full (%d entries)\n",
			     octeon_dev->octeon_id, iq->iq_no,
			     cavium_atomic_read(&iq->instr_pending));
		cavium_error("%s write_idx: %d flush: %d new: %d\n",
			     __CVM_FUNCTION__, iq->host_write_index,
			     iq->flush_index, iq->octeon_read_index);

		return -1;
	}

	__copy_cmd_into_iq(iq, cmd);

	/* "index" is returned, host_write_index is modified. */
	index = iq->host_write_index;
	INCR_INDEX_BY1(iq->host_write_index, iq->max_count);
	iq->fill_cnt++;

	/* Flush the command into memory. */
	cavium_flush_write();

#ifdef CAVIUM_DEBUG
	cavium_atomic_check_and_inc(&iq->instr_pending, iq->max_count,
				    __CVM_FILE__, __CVM_LINE__);
#else
	cavium_atomic_inc(&iq->instr_pending);
#endif

	cavium_print(PRINT_FLOW, "post_comm: index returned is %d\n", index);
	return index;
}

static inline iq_post_status_t
__post_command2(octeon_device_t * octeon_dev UNUSED,
		octeon_instr_queue_t * iq,
		uint32_t force_db UNUSED, uint8_t * cmd)
{
	iq_post_status_t st;

	st.status = IQ_SEND_OK;

	/* This ensures that the read index does not wrap around to the same 
	   position if queue gets full before Octeon could fetch any instr. */
	if (cavium_atomic_read(&iq->instr_pending) >= (iq->max_count - 1)) {
		cavium_print(PRINT_FLOW,
			     "OCTEON[%d]: IQ[%d] is full (%d entries)\n",
			     octeon_dev->octeon_id, iq->iq_no,
			     cavium_atomic_read(&iq->instr_pending));
		cavium_print(PRINT_FLOW, "%s write_idx: %d flush: %d new: %d\n",
			     __CVM_FUNCTION__, iq->host_write_index,
			     iq->flush_index, iq->octeon_read_index);

		st.status = IQ_SEND_FAILED;
		st.index = -1;
		return st;
	}

	if (cavium_atomic_read(&iq->instr_pending) >= (iq->max_count - 2))
		st.status = IQ_SEND_STOP;

	__copy_cmd_into_iq(iq, cmd);

	/* "index" is returned, host_write_index is modified. */
	st.index = iq->host_write_index;
	INCR_INDEX_BY1(iq->host_write_index, iq->max_count);
	iq->fill_cnt++;

	/* Flush the command into memory. */
	cavium_flush_write();

#ifdef CAVIUM_DEBUG
	cavium_atomic_check_and_inc(&iq->instr_pending, iq->max_count,
				    __CVM_FILE__, __CVM_LINE__);
#else
	cavium_atomic_inc(&iq->instr_pending);
#endif

	cavium_print(PRINT_FLOW, "post_comm: index returned is %d\n", st.index);

	return st;
}

static int
post_command32B(octeon_device_t * oct,
		octeon_instr_queue_t * iq,
		uint32_t force_db, octeon_instr_32B_t * cmd32)
{
#ifdef CAVIUM_DEBUG
	if (iq->iqcmd_64B) {
		cavium_error
		    ("Cannot post 32 byte command in IQ[%d] (64-Byte IQ)\n",
		     iq->iq_no);
		return -1;
	}
#endif

	return __post_command(oct, iq, force_db, (uint8_t *) cmd32);
}

static int
post_command64B(octeon_device_t * oct,
		octeon_instr_queue_t * iq,
		uint32_t force_db, octeon_instr_64B_t * cmd64)
{
#ifdef CAVIUM_DEBUG
	if (!iq->iqcmd_64B) {
		cavium_error
		    ("Cannot post 64 byte command in IQ[%d] (32-Byte IQ)\n",
		     iq->iq_no);
		return -1;
	}
#endif

	return __post_command(oct, iq, force_db, (uint8_t *) cmd64);
}

static inline void
__add_to_nrlist(octeon_instr_queue_t * iq, int idx, void *buf, int buftype)
{
#ifdef CAVIUM_DEBUG
	if (iq->nrlist[idx].buftype != NORESP_BUFTYPE_NONE) {
		cavium_error("NRLIST[%d] buftype: %d\n", idx,
			     iq->nrlist[idx].buftype);
	}
#endif
	iq->nrlist[idx].buf = buf;
	iq->nrlist[idx].buftype = buftype;
}

static int
__process_iq_noresponse_list(octeon_device_t * oct UNUSED,
			     octeon_instr_queue_t * iq)
{
	uint32_t old = iq->flush_index;
	uint32_t inst_count = 0, put_idx;

	put_idx = iq->nr_free.put_idx;

	while (old != iq->octeon_read_index) {
		if (iq->nrlist[old].buftype == NORESP_BUFTYPE_NONE)
			goto skip_this;

		cavium_print(PRINT_DEBUG,
			     "Adding instr @ %p type %d to freelist @ idx %d\n",
			     iq->nrlist[old].buf, iq->nrlist[old].buftype,
			     put_idx);

		iq->nr_free.q[put_idx].buf = iq->nrlist[old].buf;
		iq->nr_free.q[put_idx].buftype = iq->nrlist[old].buftype;
		iq->nrlist[old].buf = 0;
		iq->nrlist[old].buftype = 0;
		INCR_INDEX_BY1(put_idx, iq->max_count);

skip_this:
		inst_count++;
		INCR_INDEX_BY1(old, iq->max_count);
	}

	iq->nr_free.put_idx = put_idx;

	iq->flush_index = old;

	return inst_count;
}

static inline void
update_iq_indices(octeon_device_t * oct, octeon_instr_queue_t * iq)
{
	uint32_t inst_processed = 0;

	/* Calculate how many commands Octeon has read and move the read index
	   accordingly. */
	iq->octeon_read_index = oct->fn_list.update_iq_read_idx(iq);

	/* Move the NORESPONSE requests to the per-device completion list. */
	if (iq->flush_index != iq->octeon_read_index) {
		inst_processed = __process_iq_noresponse_list(oct, iq);
	}

	if (inst_processed) {
		cavium_atomic_sub(inst_processed, &iq->instr_pending);
		iq->stats.instr_processed += inst_processed;
	}
}

/** Check for commands that were fetched by Octeon. If they were NORESPONSE
  * requests, move the requests from the per-queue pending list to the
  * per-device noresponse completion list.
  */
static inline void
flush_instr_queue(octeon_device_t * oct, octeon_instr_queue_t * iq)
{
	cavium_spin_lock_softirqsave(&iq->lock);
	update_iq_indices(oct, iq);
	cavium_spin_unlock_softirqrestore(&iq->lock);

	process_noresponse_list(oct, iq);
}

#ifdef OCT_NIC_IQ_USE_NAPI
/* Process instruction queue after timeout.
 *  * This routine gets called from a workqueue or when removing the module.
 *   */
void __check_db_timeout(octeon_device_t *oct, u64 iq_no)
{
	octeon_instr_queue_t *iq;
	u64 next_time;

	if (!oct)
		return;

	iq = oct->instr_queue[iq_no];
	if (!iq)
		return;

	/* return immediately, if no work pending */
	if (!atomic_read(&iq->instr_pending))
		return;
	/* If jiffies - last_db_time < db_timeout do nothing  */
	next_time = iq->last_db_time + iq->db_timeout;
	if (!time_after(jiffies, (unsigned long)next_time))
		return;
	iq->last_db_time = jiffies;

	/* Flush the instruction queue */
	octeon_flush_iq(oct, iq, 0);

	//lio_enable_irq(NULL, iq); //TODO
}

void check_db_timeout(struct work_struct *work)
{
	struct cavium_wk *wk = (struct cavium_wk *)work;
	octeon_device_t *oct = (octeon_device_t *)wk->ctxptr;
	u64 iq_no = wk->ctxul;
	struct cavium_wq *db_wq = &oct->check_db_wq[iq_no];
	u32 delay = 10;

	__check_db_timeout(oct, iq_no);
	queue_delayed_work(db_wq->wq, &db_wq->wk.work, msecs_to_jiffies(delay));
}

#else
/* Called by the Poll thread at regular intervals to check the instruction
 * queue for commands to be posted and for commands that were fetched by Octeon.
 */
oct_poll_fn_status_t check_db_timeout(void *octptr, unsigned long iq_no)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;
	octeon_instr_queue_t *iq;

	iq = oct->instr_queue[iq_no];

	/* If cavium_jiffies - last_db_time < db_timeout do nothing  */
	if (!cavium_check_timeout
	    (cavium_jiffies, (iq->last_db_time + iq->db_timeout))) {
		return OCT_POLL_FN_CONTINUE;
	}
	iq->last_db_time = cavium_jiffies;

	/* Get the lock and prevent tasklets. This routine gets called from
	   the poll thread. Instructions can now be posted in tasklet context */
	cavium_spin_lock_softirqsave(&iq->lock);
	if (iq->fill_cnt != 0)
		ring_doorbell(oct, iq);

	cavium_spin_unlock_softirqrestore(&iq->lock);

	/* Flush the instruction queue */
	if (iq->do_auto_flush)
		octeon_flush_iq(oct, iq, 1);

	return OCT_POLL_FN_CONTINUE;
}
#endif

extern void
delete_soft_instr_buffers(octeon_device_t *, octeon_soft_instruction_t *);

void cn93xx_dump_regs(octeon_device_t * oct, int qno);

static octeon_instr_status_t
__do_instruction_processing(octeon_device_t * oct,
			    octeon_soft_instruction_t * si,
			    octeon_soft_request_t * sr)
{
	int q_index, resp_mode, resp_order;
	uint32_t iq_no;
	octeon_instr_64B_t *cmd;
	octeon_instr_queue_t *iq;
	uint64_t *irh, *ih;
	octeon_pending_entry_t *pending_entry = NULL;
	octeon_instr_status_t retval;
	OCTEON_DMA_MODE dma_mode;

	//octeon_instr_ih3_t ih3;
	octeon_instr_pki_ih3_t pki_ih3;
	octeon_instr3_64B_t o3_cmd;

	octeon_instr_ihx_t ihx;

	retval.u64 = OCTEON_REQUEST_FAILED;
	cavium_print(PRINT_FLOW,
		     "\n\n----#  octeon_process_instruction  #----\n");

#ifdef CAVIUM_DEBUG
	print_soft_instr(oct, si);
#endif

	if((si->alloc_flags & OCTEON_DIRECT_GATHER) &&
		(oct->chip_id == OCTEON_CN93XX_PF || oct->chip_id == OCTEON_CN93XX_VF ||
		 oct->chip_id == OCTEON_CN98XX_PF || oct->chip_id == OCTEON_CN98XX_VF)) {
		cavium_error("OCTEONTX2 dont support direct gather mode\n");
		return retval;
	}
	/* Add the PCIe port to be used for sending responses back. */
	if (SOFT_INSTR_RESP_ORDER(si) != OCTEON_RESP_NORESPONSE)
		si->irh.pcie_port = oct->pcie_port;

	irh = (uint64_t *) & si->irh;
	ih = (uint64_t *) & si->ih;
	resp_order = SOFT_INSTR_RESP_ORDER(si);
	resp_mode = SOFT_INSTR_RESP_MODE(si);
	dma_mode = SOFT_INSTR_DMA_MODE(si);
	iq_no = SOFT_INSTR_IQ_NO(si);

	iq = oct->instr_queue[iq_no];

	/* The first 32 bytes are always used by the driver. The last 32 bytes
	   may contain direct gather information in CN63XX. */
	if ( (oct->chip_id == OCTEON_CN83XX_PF) ||
	   (oct->chip_id == OCTEON_CN83XX_VF) ||
		(oct->chip_id == OCTEON_CN93XX_PF) || (oct->chip_id == OCTEON_CN93XX_VF) ||
		oct->chip_id == OCTEON_CN98XX_PF || oct->chip_id == OCTEON_CN98XX_VF) {
		memset(&ihx, 0, sizeof(octeon_instr_ihx_t));
		memset(&pki_ih3, 0, sizeof(octeon_instr_pki_ih3_t));
		memset(&o3_cmd, 0, sizeof(octeon_instr3_64B_t));
		cmd = &si->command;

		/* clear the space for the first five 8B words(dptr,ih3,pki_ih3,rptr and irh) */
		memset(cmd, 0, sizeof(octeon_instr_64B_t));

	} else {
		/* point the O2 cmd to actual 64B command */
		cmd = &si->command;

		/* clear the space for the first four 8B words(dptr,ih,rptr and irh) */
		memset(cmd, 0, sizeof(octeon_instr_32B_t));
	}

// *INDENT-OFF*
   if(si->dptr) {
      if(!si->ih.gather) {
         cmd->dptr = (uint64_t)octeon_pci_map_single(oct->pci_dev,
                     (void *)si->dptr, si->ih.dlengsz, CAVIUM_PCI_DMA_TODEVICE);
      } else {
         if(si->alloc_flags & OCTEON_DIRECT_GATHER) {
            cmd->dptr = (uint64_t)octeon_pci_map_single(oct->pci_dev,
                        (void *)si->dptr,
                        CAVIUM_GET_SG_SIZE((octeon_sg_entry_t *)cmd->exhdr, 0),
                        CAVIUM_PCI_DMA_TODEVICE);
         } else {
            cmd->dptr = (uint64_t)octeon_pci_map_single(oct->pci_dev,
                        (void *)si->dptr,
                        ((ROUNDUP4(si->ih.dlengsz) >> 2) * OCT_SG_ENTRY_SIZE),
                        CAVIUM_PCI_DMA_TODEVICE);
         }
      }
   }
// *INDENT-ON*

	if (si->rptr) {
		if (!si->irh.scatter) {
			cmd->rptr =
			    (uint64_t) octeon_pci_map_single(oct->pci_dev,
							     (void *)si->rptr,
							     si->irh.rlenssz,
							     CAVIUM_PCI_DMA_FROMDEVICE);
		} else {
			cmd->rptr = (uint64_t) octeon_pci_map_single(oct->pci_dev, (void *)si->rptr, ((ROUNDUP4(si->irh.rlenssz) >> 2) * OCT_SG_ENTRY_SIZE), CAVIUM_PCI_DMA_TODEVICE);	/* scatterlist PCI is TODEVICE */
		}
	}

	if (iq->iqcmd_64B && !(si->alloc_flags & OCTEON_DIRECT_GATHER) &&
	    SOFT_INSTR_EXHDR_COUNT(si)) {
		cavium_memcpy(cmd->exhdr, si->exhdr,
			      (SOFT_INSTR_EXHDR_COUNT(si) * 8));
	}

	/* Set the timeout value for the instruction */
	si->timeout = cavium_jiffies + SOFT_INSTR_TIMEOUT(si);

	if (resp_order != OCTEON_RESP_NORESPONSE) {
		pending_entry = add_to_pending_list(oct, si);
		if (!pending_entry) {
			iq->stats.instr_dropped++;
			delete_soft_instr_buffers(oct, si);
#ifndef OCTEON_USE_OLD_REQ_STATUS
			retval.s.status = OCTEON_REQUEST_NO_PENDING_ENTRY;
#endif
			return retval;
		}
	}

	cavium_print(PRINT_DEBUG, "Request id from pending list is %d\n",
		     si->req_info.request_id);

	/* Sending the FD pid info in each request request_id to the OCTEON 
	 * for the SE applications which require FD pid info.
	 */
	si->irh.rid = cavium_getpid();

	/* There is are changs for 83XX, cann't fit with O3 case */
	if ((oct->chip_id == OCTEON_CN83XX_PF) ||
		(oct->chip_id == OCTEON_CN83XX_VF) ||
		(oct->chip_id == OCTEON_CN93XX_PF) ||
		(oct->chip_id == OCTEON_CN93XX_VF) ||
		oct->chip_id == OCTEON_CN98XX_PF || oct->chip_id == OCTEON_CN98XX_VF) {
		/* Fill up SDD IHX */
		ihx.pkind = oct->pkind;

		if ((oct->chip_id == OCTEON_CN83XX_PF) ||
		    (oct->chip_id == OCTEON_CN83XX_VF))
			ihx.fsz = si->ih.fsz + 8;	/* extra 8B for PKI IH */
		ihx.fsz = si->ih.fsz + 8;	/* extra 8 bytes for EXHDR */

		ihx.gather = si->ih.gather;

		if (ihx.gather) {
			ihx.gsz = si->ih.dlengsz;
        	ihx.tlen = si->gather_bytes+ ihx.fsz;
        } else {
        	ihx.tlen = si->ih.dlengsz + ihx.fsz;
	}
	if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF)) {
		/* Fill up PKI IH3 */
		pki_ih3.w = 1;
		pki_ih3.raw = si->ih.raw;
		//pki_ih3.utag = 1;
		//pki_ih3.uqpg = 1;
		pki_ih3.utt = 1;

		//pki_ih3.tag = si->ih.tag;
		pki_ih3.tagtype = si->ih.tagtype;

		/** 
		 * QPG entry is allocated by the pkipf driver in the octeontx
		 * Currently it is allocated statically with each pkind having 32 qpg entries
		 */
		//pki_ih3.qpg = oct->pkind * 32;
		pki_ih3.pm = 0x7;
		pki_ih3.sl = 8;
	}
	/* Now fill up the CN78xx 64B command */
	/* copy dptr */
	o3_cmd.dptr = cmd->dptr;

	/* copy ih3 */
	o3_cmd.ih3 = *((uint64_t *) & ihx);

	if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF)) {
		/* copy pki_ih3 */
		o3_cmd.pki_ih3 = *((uint64_t *) & pki_ih3);
	}
#ifndef IOQ_PERF_MODE_O3
	/* copy rptr */
	o3_cmd.rptr = cmd->rptr;
#endif
	/* copy irh */
	o3_cmd.irh = *irh;

#if 0
        printk("Before swapping\n");
        printk("word0 [dptr]: 0x%016llx\n", *((uint64_t *)&o3_cmd.dptr));
        printk("word1 [ihtx]: 0x%016llx\n", *((uint64_t *)&o3_cmd.ih3));
        printk("word2 [pki_ih]: 0x%016llx\n", *((uint64_t *)&o3_cmd.pki_ih3));
        printk("word3 [rptr]: 0x%016llx\n", *((uint64_t *)&o3_cmd.rptr));
        printk("word4 [irh]: 0x%016llx\n", *((uint64_t *)&o3_cmd.irh));
#endif
        /* Swap the FSZ in here, to avoid swapping on Octeon side */
#ifndef IOQ_PERF_MODE_O3
        octeon_swap_8B_data(&o3_cmd.rptr, 1);
#endif
        octeon_swap_8B_data(&o3_cmd.irh, 1);
		/* copy the 64B CN78xx cmd to actual 64B command */
		memcpy(cmd, &o3_cmd, 64);

        /* Dump the instr cmd */
#if 0
        printk("After swapping\n");
        printk("word0 [dptr]: 0x%016llx\n", cmd->dptr);
        printk("word1 [ihtx]: 0x%016llx\n", cmd->ih );
        printk("word2 [pki_ih]: 0x%016llx\n", cmd->rptr);
        printk("word3 [rptr]: 0x%016llx\n", cmd->irh);
        printk("word4 [irh]: 0x%016llx\n", cmd->exhdr[0]);
#endif        
	} else {
		/* copy the IH to cmd#64 */
		cmd->ih = *ih;

		/* copy the IRH to cmd#64 */
		cmd->irh = *irh;
	}

	cavium_spin_lock_softirqsave(&iq->lock);

	if (!iq->iqcmd_64B) {
		q_index = post_command32B(oct, iq,
					  (si->alloc_flags &
					   OCTEON_SOFT_INSTR_DB_NOW),
					  (octeon_instr_32B_t *) cmd);
	} else {
		q_index = post_command64B(oct, iq,
					  (si->alloc_flags &
					   OCTEON_SOFT_INSTR_DB_NOW), cmd);
	}

	if (q_index >= 0) {

		if (resp_order == OCTEON_RESP_NORESPONSE) {
			__add_to_nrlist(iq, q_index, si, NORESP_BUFTYPE_INSTR);
		} else {
			pending_entry->queue_index = q_index;
		}

		cavium_print(PRINT_FLOW, "The command was posted at %d\n",
			     q_index);
		if (SOFT_INSTR_HAS_GATHER(si)) {
			iq->stats.sgentry_sent += SOFT_INSTR_DLEN(si);
			iq->stats.bytes_sent += si->gather_bytes;
		} else {
			iq->stats.bytes_sent += SOFT_INSTR_DLEN(si);
		}
		iq->stats.instr_posted++;

		retval.s.request_id = si->req_info.request_id;
		retval.s.error = 0;
		retval.s.status = si->req_info.status;

		if (sr) {
			SOFT_REQ_INFO(sr)->request_id = retval.s.request_id;
			SOFT_REQ_INFO(sr)->status = retval.s.status;
		}

		if (iq->fill_cnt >= iq->fill_threshold
		    || (si->alloc_flags & OCTEON_SOFT_INSTR_DB_NOW))
			ring_doorbell(oct, iq);

		cavium_spin_unlock_softirqrestore(&iq->lock);

		if (resp_order != OCTEON_RESP_NORESPONSE) {
			uint32_t resp_list;

			GET_RESPONSE_LIST(resp_order, resp_mode, resp_list);

			push_response_list(&oct->response_list[resp_list],
					   pending_entry);
		}

	} else {

		iq->stats.instr_dropped++;

		cavium_spin_unlock_softirqrestore(&iq->lock);

		cavium_error(
			     "OCTEON[%d]: No space in IQ[%d] to post instruction\n",
			     oct->octeon_id, iq_no);
        cn83xx_dump_regs(oct, iq_no);
		if (resp_order != OCTEON_RESP_NORESPONSE) {
			release_from_pending_list(oct, pending_entry);
			delete_soft_instr_buffers(oct, si);
		}

	}

#ifndef OCT_NIC_IQ_USE_NAPI
	if (iq->do_auto_flush) {
		octeon_flush_iq(oct, iq, (iq->max_count / 2));
	}
#endif

	return retval;
}

/** Allocate a sglist components based on the number of scatter or gather 
  * buffer count (given by sg_count).
  */
static inline octeon_sg_entry_t *octeon_alloc_sglist(octeon_device_t *
						     octeon_dev UNUSED,
						     octeon_soft_instruction_t *
						     soft_instr,
						     uint32_t sg_count,
						     uint32_t flags)
{
	uint8_t *sg_list = NULL;

	sg_list =
	    cavium_alloc_buffer(octeon_dev, (sg_count * OCT_SG_ENTRY_SIZE) + 7);
	if (sg_list) {
		cavium_print(PRINT_DEBUG,
			     "alloc_sg_list:sg_count: %d sg_list at 0x%p\n",
			     sg_count, sg_list);
		if (flags & OCTEON_DPTR_GATHER)
			soft_instr->gather_ptr = (void *)sg_list;
		else
			soft_instr->scatter_ptr = (void *)sg_list;
		/* scatter/gather list needs to be 8B aligned  */
		if ((unsigned long)sg_list & 0x07)
			sg_list =
			    (uint8_t *) (((unsigned long)sg_list + 7) & ~(7UL));
		cavium_memset(sg_list, 0, sg_count * OCT_SG_ENTRY_SIZE);
		SET_SOFT_INSTR_ALLOCFLAGS(soft_instr, flags);
	}
	return (octeon_sg_entry_t *) sg_list;
}

#if 0
static void *octeon_create_direct_gather(octeon_device_t * oct,
					 octeon_buffer_t * buf,
					 octeon_soft_instruction_t * si)
{
	octeon_sg_entry_t *sg = (octeon_sg_entry_t *) si->command.exhdr;
	int i;

	si->ih.dlengsz = 0;
	memset(sg, 0, sizeof(octeon_sg_entry_t));

	CAVIUM_ADD_SG_SIZE(sg, buf->size[0], 0);

	for (i = 1; i < buf->cnt; i++) {
		CAVIUM_ADD_SG_SIZE(sg, buf->size[i], i);
		sg->ptr[i - 1] =
		    octeon_pci_map_single(oct->pci_dev,
					  OCT_SOFT_REQ_BUFPTR(buf, i),
					  buf->size[i],
					  CAVIUM_PCI_DMA_TODEVICE);
	}

	si->alloc_flags |= OCTEON_DIRECT_GATHER;

	return OCT_SOFT_REQ_BUFPTR(buf, 0);
}
#endif

/* Setup a gather (for GATHER or SCATTER_GATHER DMA)
 * or scatter list (for SCATTER 0r SCATTER_GATHER DMA)
 */
static octeon_sg_entry_t *octeon_create_sg_list(octeon_device_t * oct,
						octeon_buffer_t * buf,
						octeon_soft_instruction_t *
						soft_instr, uint32_t flags)
{
	octeon_sg_entry_t *sg_list;
	uint32_t iq_no, i, j, k, sg_count = 0, cnt = buf->cnt, total_size = 0;
	uint16_t exhdr_size = 0, size;
	int tmpcnt = 0;

	cavium_print(PRINT_FLOW, "\n\n----#octeon_create_sg_list (%s)#----\n",
		     (flags == OCTEON_RPTR_SCATTER) ? "scatter" : "gather");

	iq_no = SOFT_INSTR_IQ_NO(soft_instr);

	if (cnt == 0) {
		cavium_error("OCTEON: %s buffer count cannot be 0\n",
			     (flags ==
			      OCTEON_DPTR_GATHER) ? "Gather" : "Scatter");
		return NULL;
	}

	if (flags == OCTEON_DPTR_GATHER) {	/* If its a gather list. */

		exhdr_size = (uint16_t) SOFT_INSTR_EXHDR_COUNT(soft_instr) * 8;
		cavium_print(PRINT_DEBUG,
			     "iq_no: %d instr_mode: %d exhdr_size: %d\n", iq_no,
			     IQ_INSTR_MODE_32B(oct, iq_no) ? 32 : 64,
			     exhdr_size);

		/* CN38XX Errata PCI-500: Component length should <= 65528.
		   No check is made here currently since the max size for total gather
		   bytes is 65511. */
		for (i = 0; i < cnt; i++) {
			if (buf->size[i] == 0) {
				cavium_error
				    ("OCTEON: Gather buffer size cannot be 0\n");
				return NULL;
			}
			total_size += buf->size[i];
		}

		if (IQ_INSTR_MODE_32B(oct, iq_no) && exhdr_size) {
			cavium_print(PRINT_DEBUG,
				     "create gather: exhdr to be added\n");
			total_size += exhdr_size;
			cnt++;
		}

		if (total_size > OCT_MAX_GATHER_DATA_SIZE) {
			cavium_error
			    ("OCTEON: Total Size (%d) exceeds max (%d) for Gather\n",
			     total_size, OCT_MAX_GATHER_DATA_SIZE);
			return NULL;
		}

		soft_instr->gather_bytes = total_size;

		/* We can use direct gather mode in CN63xx, if there are <= 4 gather
		   ptrs for a IQ in 64-byte mode and there are no extra header bytes. */
		/*if( (oct->chip_id >= OCTEON_CN63XX_PASS1) && (cnt <= 4) &&
		   IQ_INSTR_MODE_64B(oct, iq_no) && (exhdr_size == 0) ) {
		   return octeon_create_direct_gather(oct, buf, soft_instr);
		   } else */  {
			soft_instr->ih.dlengsz = cnt;
		}

	} else {		/* Else its a scatter list */

		if (cnt > MAX_SCATTER_PTRS) {
			cavium_error
			    ("Found %d scatter ptrs; Max supported is %d\n",
			     cnt, MAX_SCATTER_PTRS);
			return NULL;
		}

		for (i = 0, total_size = 0; i < cnt; i++) {
			if (buf->size[i] == 0) {
				cavium_error
				    ("OCTEON: Scatter buffer size cannot be 0\n");
				return NULL;
			}
			/* CN38XX Errata PCI-500: Component length should <= 65528 */
			if (buf->size[i] > OCT_MAX_COMP_BUF_LEN) {
				cavium_error
				    ("Scatter buffer size (%d) exceeds max (%d)\n",
				     buf->size[i], OCT_MAX_COMP_BUF_LEN);
				return NULL;
			}
			total_size += buf->size[i];
		}

		/* Note: We check here for OCT_MAX_SCATTER_DMA_SIZE since if this
		   was a user-request, the ioctl would have already checked
		   the data size for OCT_MAX_SCATTER_DATA_SIZE and then
		   added space for ORH and status. If this is a kernel-request
		   then the output buffer has space reserved for ORH and
		   status.
		 */
		if (total_size > OCT_MAX_SCATTER_DMA_SIZE) {
			cavium_error
			    ("Buffer Size (%d) exceeds max (%d) for Scatter\n",
			     total_size, OCT_MAX_SCATTER_DMA_SIZE);
			return NULL;
		}
		soft_instr->irh.rlenssz = cnt;
		soft_instr->scatter_bytes = total_size;
	}

	sg_count = ROUNDUP4(cnt) >> 2;

	sg_list = octeon_alloc_sglist(oct, soft_instr, sg_count, flags);
	if (!sg_list)
		return NULL;

	/* If IQ instruction mode is 32-byte and there are extra header bytes,
	   use the first gather pointer to trasnmit the header bytes. */
	if (IQ_INSTR_MODE_32B(oct, iq_no) &&
	    ((flags == OCTEON_DPTR_GATHER) && (exhdr_size))) {
		CAVIUM_ADD_SG_SIZE(&sg_list[0], exhdr_size, 0);
		sg_list[0].ptr[0] =
		    octeon_pci_map_single(oct->pci_dev, soft_instr->exhdr,
					  exhdr_size, CAVIUM_PCI_DMA_TODEVICE);
		tmpcnt = 1;
		cnt--;
	}

	for (i = 0, j = 0; i < sg_count; i++) {
		for (k = tmpcnt; ((k < 4) && (j < cnt)); j++, k++) {

			size = buf->size[j];

			/* Gather list data is swapped and interpreted in Hardware.
			   Scatter data is interpreted by core software. We need to do
			   swapping of scatter list manually. */
			if (flags == OCTEON_RPTR_SCATTER) {
				sg_list[i].u.size[3 - k] = size;
			} else {
				CAVIUM_ADD_SG_SIZE(&sg_list[i], size, k);
			}

			if (flags == OCTEON_DPTR_GATHER) {
				sg_list[i].ptr[k] =
				    octeon_pci_map_single(oct->pci_dev,
							  OCT_SOFT_REQ_BUFPTR
							  (buf, j),
							  buf->size[j],
							  CAVIUM_PCI_DMA_TODEVICE);
			} else {
				sg_list[i].ptr[k] =
				    octeon_pci_map_single(oct->pci_dev,
							  OCT_SOFT_REQ_BUFPTR
							  (buf, j),
							  buf->size[j],
							  CAVIUM_PCI_DMA_FROMDEVICE);
			}
		}
		tmpcnt = 0;
	}

	return sg_list;
}

/* Setup the Input buffers for a DIRECT DMA request. Multiple Input buffers are
 * coalesced. */
static inline uint8_t *octeon_process_request_inbuf(octeon_device_t *
						    octeon_dev,
						    octeon_soft_instruction_t *
						    soft_instr,
						    octeon_soft_request_t *
						    soft_req)
{
	uint8_t i, iq_no, exhdr_size = 0, *buf = NULL, *tmpbuf = NULL;
	uint32_t total_size = 0;

	iq_no = SOFT_INSTR_IQ_NO(soft_instr);
	exhdr_size = SOFT_INSTR_EXHDR_COUNT(soft_instr) * 8;

	/* If there is more than one input buffer or there are extra header bytes
	   for a 32-byte IQ, we need to coalesce the input buffers.
	 */
	if ((soft_req->inbuf.cnt > 1)
	    || ((IQ_INSTR_MODE_32B(octeon_dev, iq_no) && exhdr_size))) {

		for (i = 0, total_size = 0; i < soft_req->inbuf.cnt; i++)
			total_size += soft_req->inbuf.size[i];

		total_size += exhdr_size;	/* Add any extra header bytes present */

		/* Input buffer should not exceed OCT_MAX_DIRECT_INPUT_DATA_SIZE */
		if (total_size == 0) {
			cavium_error
			    ("OCTEON: Input Size cannot be 0 when bufcnt is %d\n",
			     soft_req->inbuf.cnt);
			return NULL;
		}

		/* Input buffer should not exceed OCT_MAX_DIRECT_INPUT_DATA_SIZE */
		if (total_size > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
			cavium_error
			    ("Input Size (%d) exceeds max (%d) for DIRECT mode\n",
			     total_size, OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			return NULL;
		}

		buf = cavium_alloc_buffer(octeon_dev, total_size);
		if (buf == NULL)
			return NULL;

		tmpbuf = buf;
		if (exhdr_size) {
			cavium_memcpy(tmpbuf, soft_instr->exhdr, exhdr_size);
			tmpbuf += exhdr_size;
		}

		for (i = 0; i < soft_req->inbuf.cnt; i++) {
			cavium_memcpy(tmpbuf, SOFT_REQ_INBUF(soft_req, i),
				      soft_req->inbuf.size[i]);
			tmpbuf += soft_req->inbuf.size[i];
		}

		soft_instr->dptr = buf;
		soft_instr->ih.dlengsz = total_size;
		SET_SOFT_INSTR_ALLOCFLAGS(soft_instr, OCTEON_DPTR_COALESCED);

	} else {

		if (soft_req->inbuf.size[0] == 0) {
			cavium_error
			    ("OCTEON: Input Size cannot be 0 when bufcnt is %d\n",
			     soft_req->inbuf.cnt);
			return NULL;
		}

		if (soft_req->inbuf.size[0] > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
			cavium_error
			    ("Input Size (%d) exceeds max (%d) for DIRECT mode\n",
			     soft_req->inbuf.size[0],
			     OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			return NULL;
		}
		soft_instr->dptr = SOFT_REQ_INBUF(soft_req, 0);
		soft_instr->ih.dlengsz = soft_req->inbuf.size[0];
	}

	return (soft_instr->dptr);
}

static uint32_t
octeon_create_data_buf(octeon_device_t * oct,
		       octeon_soft_instruction_t * soft_instr,
		       octeon_soft_request_t * soft_req)
{
	OCTEON_DMA_MODE dma_mode;
	OCTEON_RESPONSE_ORDER resp_order;

	dma_mode = GET_SOFT_REQ_DMA_MODE(soft_req);
	resp_order = GET_SOFT_REQ_RESP_ORDER(soft_req);

	cavium_print(PRINT_FLOW, "\n\n----# octeon_create_data_buf #----\n");

	/*
	   Input & Output buffer count must be in range {0, MAX_BUFCNT).
	 */
	if ((soft_req->inbuf.cnt > MAX_BUFCNT)
	    || (soft_req->outbuf.cnt > MAX_BUFCNT)) {
		cavium_error("OCTEON: (%s) Invalid buffer count in request\n",
			     __CVM_FUNCTION__);
		return OCTEON_REQUEST_INVALID_BUFCNT;
	}

	/* 
	   For all response order other than NORESPONSE, the output buffer 
	   count cannot be 0, nor can the output.ptr0 be NULL.
	 */
	if (resp_order == OCTEON_RESP_NORESPONSE) {
		if (dma_mode != OCTEON_DMA_DIRECT
		    && dma_mode != OCTEON_DMA_GATHER) {
			cavium_error
			    ("OCTEON: NoResponse request don't support %s dma mode\n",
			     OCTEON_DMA_MODE_STRING(dma_mode));
		}
		if (soft_req->outbuf.cnt != 0) {
			cavium_error
			    ("OCTEON: Outbuf count should be 0 for resp_order: %s\n",
			     OCTEON_RESP_ORDER_STRING(resp_order));
		}
	} else {
		if ((soft_req->outbuf.cnt == 0)
		    || (SOFT_REQ_OUTBUF(soft_req, 0) == NULL)) {
			cavium_error
			    ("OCTEON: Invalid buffer count for resp_order: %s\n",
			     OCTEON_RESP_ORDER_STRING(resp_order));
			cavium_error
			    ("OCTEON: outbuf.cnt = %d outbuf.ptr0 = %p\n",
			     soft_req->outbuf.cnt, SOFT_REQ_OUTBUF(soft_req,
								   0));
			return OCTEON_REQUEST_INVALID_BUFCNT;
		}
	}

	if ((dma_mode == OCTEON_DMA_DIRECT || dma_mode == OCTEON_DMA_GATHER) &&
	    (soft_req->outbuf.cnt > 1)) {
		cavium_error
		    ("OCTEON: Invalid outbuf.cnt (%d) for dma_mode %s\n",
		     soft_req->outbuf.cnt, OCTEON_DMA_MODE_STRING(dma_mode));
		return OCTEON_REQUEST_INVALID_BUFCNT;
	}

	if (dma_mode == OCTEON_DMA_DIRECT) {
		soft_instr->ih.gather = 0;
		soft_instr->irh.scatter = 0;

		/* For direct DMA mode, the output buffer size should not exceed
		   OCT_MAX_DIRECT_DMA_SIZE. 
		   Note: We check the output size here for OCT_MAX_DIRECT_DMA_SIZE &
		   since if this was a user-request, the ioctl would have made
		   the check for OCT_MAX_DIRECT_OUTPUT_DATA_SIZE and then added
		   space for ORH and status, and if this was a kernel-request,
		   the output buffer already has space for the ORH and status
		   bytes.
		 */
		if ((resp_order != OCTEON_RESP_NORESPONSE)
		    && (soft_req->outbuf.size[0] > OCT_MAX_DIRECT_DMA_SIZE)) {
			cavium_error
			    ("Output Size (%d) exceeds max (%d) for DIRECT mode\n",
			     soft_req->outbuf.size[0], OCT_MAX_DIRECT_DMA_SIZE);
			return OCTEON_REQUEST_INVALID_BUFSIZE;
		}

		/* Its legal to have no input in DIRECT DMA, but the driver will
		   have to allocate space if extra header bytes are present for
		   a request queued to a IQ in 32-byte mode. */
		if ((soft_req->inbuf.cnt) ||
		    ((IQ_INSTR_MODE_32B(oct, SOFT_INSTR_IQ_NO(soft_instr))
		      && (SOFT_INSTR_EXHDR_COUNT(soft_instr))))) {
			soft_instr->dptr = octeon_process_request_inbuf(oct,
									soft_instr,
									soft_req);
			if (!soft_instr->dptr) {
				cavium_error
				    ("OCTEON: (%s) Input buffer creation failed\n",
				     __CVM_FUNCTION__);
				return OCTEON_REQUEST_NO_MEMORY;
			}
		}

		if ((soft_instr->ih.raw)
		    && (resp_order != OCTEON_RESP_NORESPONSE)) {

			soft_instr->rptr = SOFT_REQ_OUTBUF(soft_req, 0);

			/* The caller would have allocated 16 bytes for ORH and status
			   word. The expected length should be total - 16 bytes */
			soft_instr->irh.rlenssz = soft_req->outbuf.size[0];
// *INDENT-OFF*
            soft_instr->status_word =
                    (uint64_t *)((uint8_t *)SOFT_REQ_OUTBUF(soft_req, 0)
                                        + soft_req->outbuf.size[0] - 8);
// *INDENT-ON*
		}

	} else {		/* If not Direct DMA */

		soft_instr->ih.gather = 0;
		soft_instr->irh.scatter = 0;

		/* Prepare the buffers first. Check for Gather mode. Create gather
		   list and a single output buffer (for GATHER DMA). */
		if ((dma_mode == OCTEON_DMA_GATHER)
		    || (dma_mode == OCTEON_DMA_SCATTER_GATHER)) {

			soft_instr->ih.gather = 1;

			if ((soft_instr->ih.raw)
			    && (dma_mode == OCTEON_DMA_GATHER)
			    && (resp_order != OCTEON_RESP_NORESPONSE)) {

				if (soft_req->outbuf.size[0] == 0) {
					cavium_error
					    ("OCTEON: Output Size must be non-zero for %s response\n",
					     OCTEON_RESP_ORDER_STRING
					     (resp_order));
					return OCTEON_REQUEST_INVALID_BUFSIZE;
				}

				/* GATHER DMA uses a single Output buffer. */
				if (soft_req->outbuf.size[0] >
				    OCT_MAX_DIRECT_DMA_SIZE) {
					cavium_error
					    ("OCTEON: Output Size (%d) exceeds max (%d) for GATHER mode\n",
					     soft_req->outbuf.size[0],
					     OCT_MAX_DIRECT_DMA_SIZE);
					return OCTEON_REQUEST_INVALID_BUFSIZE;
				}
				soft_instr->rptr = SOFT_REQ_OUTBUF(soft_req, 0);
				soft_instr->irh.rlenssz =
				    soft_req->outbuf.size[0];
				soft_instr->status_word =
				    (uint64_t *) ((uint8_t *)
						  SOFT_REQ_OUTBUF(soft_req, 0)
						  + soft_req->outbuf.size[0] -
						  8);
			}

			soft_instr->dptr =
			    octeon_create_sg_list(oct, &soft_req->inbuf,
						  soft_instr,
						  OCTEON_DPTR_GATHER);
			if (!soft_instr->dptr) {
				cavium_error
				    ("OCTEON: Gather list for request failed\n");
				return OCTEON_REQUEST_NO_MEMORY;
			}

		}

		/* Prepare the output buffers. Check for Scatter mode. Create scatter
		   list and a single input buffer (for SCATTER DMA). */
// *INDENT-OFF*
      if( (dma_mode == OCTEON_DMA_SCATTER)
          || (dma_mode == OCTEON_DMA_SCATTER_GATHER)) {

         soft_instr->irh.scatter = 1;

         if( (soft_instr->ih.raw) && (dma_mode == OCTEON_DMA_SCATTER)) {

            if(soft_req->inbuf.cnt > 1) {
                cavium_error("Inbuf cnt (%d) > 1 not allowed for SCATTER DMA\n",
                             soft_req->inbuf.cnt);
                return OCTEON_REQUEST_INVALID_BUFCNT;
            }

            /* SCATTER DMA uses a single Output buffer. */ 
            if(soft_req->inbuf.cnt) { /* Should be 1 buffer. We checked. */

               if(soft_req->inbuf.size[0] == 0) {
                  cavium_error("OCTEON: Inbuf size cannot be 0 for bufcnt %d\n",
                               soft_req->inbuf.cnt);
                  return OCTEON_REQUEST_INVALID_BUFSIZE;
               }

               if(soft_req->inbuf.size[0] > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
                  cavium_error("Input Size (%d) exceeds max (%d) for SCATTER mode\n", soft_req->inbuf.size[0], OCT_MAX_DIRECT_INPUT_DATA_SIZE);
                  return OCTEON_REQUEST_INVALID_BUFSIZE;
               }
               soft_instr->dptr        = SOFT_REQ_INBUF(soft_req, 0);
               soft_instr->ih.dlengsz  = soft_req->inbuf.size[0];
            }

         }

         soft_instr->rptr = octeon_create_sg_list(oct, &soft_req->outbuf,
                                              soft_instr, OCTEON_RPTR_SCATTER);
         if(!soft_instr->rptr)  {
             cavium_error("OCTEON: Scatter list for request failed\n");
             return OCTEON_REQUEST_NO_MEMORY;
         }

         if(resp_order != OCTEON_RESP_NORESPONSE) {
            soft_instr->status_word = (uint64_t *)
                  ((uint8_t *)SOFT_REQ_OUTBUF(soft_req, (soft_req->outbuf.cnt-1))
                   + soft_req->outbuf.size[soft_req->outbuf.cnt-1] - 8);
         }
      }  /* SCATTER DMA MODE */
// *INDENT-ON*

	}			/* ! DIRECT DMA MODE */

	if (soft_instr->ih.raw) {

		if (IQ_INSTR_MODE_32B(oct, SOFT_INSTR_IQ_NO(soft_instr))) {
			soft_instr->ih.fsz = 16;
		} else {
			soft_instr->ih.fsz =
			    16 + (SOFT_INSTR_EXHDR_COUNT(soft_instr) * 8);
		}

		if (soft_instr->status_word) {
			*(soft_instr->status_word) = COMPLETION_WORD_INIT;
		}
	}

	return 0;
}

octeon_instr_status_t
__do_request_processing(octeon_device_t * oct, octeon_soft_request_t * sr)
{
	octeon_soft_instruction_t *si;
	OCTEON_EXHDR_FMT hdr_info;
	uint32_t i, hdr_cnt;
	octeon_instr_status_t retval;

	retval.u64 = OCTEON_REQUEST_FAILED;

	si = (octeon_soft_instruction_t *)
	    cavium_alloc_buffer(oct, OCT_SOFT_INSTR_SIZE);
	if (si == NULL) {
		cavium_error
		    ("OCTEON[%d]: Allocation failed in processing request\n",
		     oct->octeon_id);
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_NO_MEMORY;
#endif
		return retval;
	}
	cavium_memset(si, 0, OCT_SOFT_INSTR_SIZE);

	/* Set a flag so that this instruction is freed when execution is 
	   completed  */
	SET_SOFT_INSTR_ALLOCFLAGS(si, OCTEON_SOFT_INSTR_ALLOCATED);

	cavium_memcpy(&si->exhdr_info, &sr->exhdr_info, OCT_EXHDR_INFO_SIZE);

	/* Copy the request info from soft_request to soft_instr */
	cavium_memcpy(&si->req_info, SOFT_REQ_INFO(sr), OCT_REQ_INFO_SIZE);

	/* The IH and IRH are partially filled in soft_req. Copy them. */
	si->ih = sr->ih;
	si->irh = sr->irh;

	/* Take care of the extra headers if required for a 64 byte op */
	hdr_cnt = SOFT_INSTR_EXHDR_COUNT(si);
	for (i = 0; i < hdr_cnt; i++) {
		hdr_info = GET_SOFT_REQ_EXHDR_INFO(sr, i);

		switch (hdr_info) {
		case OCTEON_EXHDR_PASS_THRU:
			si->exhdr[i] = sr->exhdr[i];
			break;
		case OCTEON_EXHDR_ENDIAN_SWAP:
			si->exhdr[i] = ENDIAN_SWAP_8_BYTE(sr->exhdr[i]);
			break;
		default:
			cavium_error
			    ("OCTEON: Invalid extra header info in request\n");
			break;
		}
	}

	/* This routine will take care of the remaining fields in IH & IRH and
	   setup the soft_instr->dptr and rptr addresses. */
	if ((retval.s.status = octeon_create_data_buf(oct, si, sr))) {
		delete_soft_instr(oct, si);
		cavium_error
		    ("OCTEON: Data buffer creation failed in request\n");
#ifdef OCTEON_USE_OLD_REQ_STATUS
		retval.u64 = OCTEON_REQUEST_FAILED;
#endif
		return retval;
	}

	retval = __do_instruction_processing(oct, si, sr);
	if (retval.s.error) {
		cavium_error(
			     "OCTEON[%d]: Instruction send failed to process request status: %x\n",
			     oct->octeon_id, retval.s.status);
		/*### No more releasing memory for instr here. process_instruction would
		   have done that ### */
	}
	/* The instruction was posted successfully */
	return retval;
}

/** (This routine is exported as an API)
  * Process a soft instruction. Called directly by the BASE driver and other
  * modules with a soft_instr pointer.
  */
octeon_instr_status_t
octeon_process_instruction(octeon_device_t * oct,
			   octeon_soft_instruction_t * soft_instr,
			   octeon_soft_request_t * soft_req)
{
	octeon_instr_status_t retval;

	retval.u64 = OCTEON_REQUEST_FAILED;

	if (cavium_atomic_read(&oct->status) != OCT_DEV_RUNNING) {
		print_octeon_state_errormsg(oct);
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_NOT_RUNNING;
#endif
		return retval;
	}

	return __do_instruction_processing(oct, soft_instr, soft_req);
}

octeon_instr_status_t
octeon_process_request(uint32_t octeon_id, octeon_soft_request_t * soft_req)
{
	octeon_instr_status_t retval;
	octeon_device_t *oct;
	OCTEON_RESPONSE_ORDER resp_order;
	OCTEON_RESPONSE_MODE resp_mode;

	retval.u64 = OCTEON_REQUEST_FAILED;

	cavium_print(PRINT_FLOW, "\n\n----#  octeon_process_request #----\n");

	oct = get_octeon_device(octeon_id);
	if (oct == NULL) {
		cavium_error("OCTEON: Request for unknown device: %d\n",
			     octeon_id);
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_NO_DEVICE;
#endif
		return retval;
	}

	/* Requests will be processed by the driver only in the RUNNING state. */
	if (cavium_atomic_read(&oct->status) != OCT_DEV_RUNNING) {
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_NOT_RUNNING;
#endif
		return retval;
	}

	if (GET_REQ_INFO_IQ_NO(SOFT_REQ_INFO(soft_req)) >= oct->num_iqs) {
		cavium_error("OCTEON: Invalid IQ (%d)\n",
			     GET_REQ_INFO_IQ_NO(SOFT_REQ_INFO(soft_req)));
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_INVALID_IQ;
#endif
		return retval;
	}

	if (soft_req->inbuf.cnt > MAX_BUFCNT
	    || soft_req->outbuf.cnt > MAX_BUFCNT) {
		cavium_error("OCTEON: Max buffers allowed is %d\n", MAX_BUFCNT);
#ifndef OCTEON_USE_OLD_REQ_STATUS
		retval.s.status = OCTEON_REQUEST_INVALID_BUFCNT;
#endif
		return retval;
	}

	resp_order = GET_SOFT_REQ_RESP_ORDER(soft_req);
	resp_mode = GET_SOFT_REQ_RESP_MODE(soft_req);

	if (!SOFT_REQ_IS_RAW(soft_req)) {
		/* Non-RAW mode data (Packet mode) should not expect a RESPONSE */
		if (resp_order != OCTEON_RESP_NORESPONSE) {
			cavium_error
			    ("%s: Error! Packet Mode request must be NORESPONSE\n",
			     __CVM_FUNCTION__);
#ifndef OCTEON_USE_OLD_REQ_STATUS
			retval.s.status = OCTEON_REQUEST_INVALID_RESP_ORDER;
#endif
			return retval;
		}
	}

	SOFT_REQ_INFO(soft_req)->octeon_id = octeon_id;

	return __do_request_processing(oct, soft_req);
}

/** This API will be used for octnic driver Tx */
int
octeon_send_noresponse_command(octeon_device_t * oct,
			       int iq_no,
			       int force_db,
			       void *cmd, void *buf, int datasize, int buftype)
{
	iq_post_status_t st;
	octeon_instr_queue_t *iq = oct->instr_queue[iq_no];

	cavium_spin_lock_softirqsave(&iq->lock);

	st = __post_command2(oct, iq, force_db, cmd);

	if (cavium_likely(st.status != IQ_SEND_FAILED)) {
		__add_to_nrlist(iq, st.index, buf, buftype);
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, bytes_sent, datasize);
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, instr_posted, 1);

		if (iq->fill_cnt >= iq->fill_threshold || force_db)
			ring_doorbell(oct, iq);

	} else {
		INCR_INSTRQUEUE_PKT_COUNT(oct, iq_no, instr_dropped, 1);
	}

	cavium_spin_unlock_softirqrestore(&iq->lock);

#ifndef OCT_NIC_IQ_USE_NAPI
	if (iq->do_auto_flush)
		octeon_flush_iq(oct, iq, 8);
#endif		

	return st.status;
}

int
octeon_send_short_command(octeon_device_t * oct,
			  uint16_t opcode, uint8_t param, void *rptr, int rsize)
{
	octeon_soft_instruction_t *instr;
	octeon_instr_status_t retval;

	instr = cavium_alloc_buffer(oct, OCT_SOFT_INSTR_SIZE);
	if (instr == NULL) {
		cavium_error("OCTEON: send_short_cmd: instr alloc failed\n");
		return 1;
	}
	cavium_memset(instr, 0, OCT_SOFT_INSTR_SIZE);
	instr->ih.raw = 1;
	instr->ih.fsz = 16;
	instr->ih.rs = 1;
	instr->ih.tagtype = 1;
	instr->irh.opcode = opcode;
	instr->irh.param = param;

	/* Sending FD pid info during FD close() call in irh->rid to OCTEON,
	 *  so that SE applications will clean up the resources for this FD.    
	 */
	if (rptr == NULL && rsize != 0) {
		instr->irh.rid = rsize;
	}

	/* If an rptr and rsize is given, pass it along in the PCI command.
	   The driver will still issue a NORESPONSE type instruction. It is
	   the caller's responsibility to track the rptr for the arrival of
	   response. */
	if (rptr != NULL && rsize != 0) {
		/* Add the PCIe port to be used for response. */
		instr->irh.pcie_port = oct->pcie_port;

		instr->irh.rlenssz = rsize;
		instr->rptr = rptr;
	}

	SET_REQ_INFO_IQ_NO(&instr->req_info, 0);

	SET_REQ_INFO_RESP_ORDER(&instr->req_info, OCTEON_RESP_NORESPONSE);
	SET_REQ_INFO_DMA_MODE(&instr->req_info, OCTEON_DMA_DIRECT);
	SET_REQ_INFO_OCTEON_ID(&instr->req_info, oct->octeon_id);
	SET_REQ_INFO_TIMEOUT(&instr->req_info, 100);
	SET_REQ_INFO_CALLBACK(&instr->req_info, NULL, NULL);

	SET_SOFT_INSTR_ALLOCFLAGS(instr, OCTEON_SOFT_INSTR_ALLOCATED);

	if ((cavium_atomic_read(&oct->status) != OCT_DEV_RUNNING) &&
	    (cavium_atomic_read(&oct->status) != OCT_DEV_IN_RESET)) {
		return 1;
	}

	retval = __do_instruction_processing(oct, instr, NULL);
	if (retval.s.error)
		return 1;
	return 0;
}

/*--- Wrappers for local functions exported to other modules ---*/

/** API exported to other modules that want to post a command directly
  * into the Input queue. This way of sending a command to Octeon does not
  * provide for notification of completion or for a callback. Most modules
  * will not use this.
  */
int
octeon_iq_post_command(octeon_device_t * oct,
		       octeon_instr_queue_t * iq, uint32_t force_db, void *cmd)
{
	int q_index;
	if (!iq->iqcmd_64B)
		q_index = post_command32B(oct, iq, force_db, cmd);
	else
		q_index = post_command64B(oct, iq, force_db, cmd);

	if ((q_index >= 0) && (iq->fill_cnt >= iq->fill_threshold || force_db))
		ring_doorbell(oct, iq);

	return q_index;
}

/** API exported so that modules like octeon NIC module can flush the input
  * queue to which they had posted a command before.
  */

#if 0 //def 0 //OCT_NIC_IQ_USE_NAPI
/* Can only run in process context */
int
lio_process_iq_request_list(octeon_device_t *oct,
	octeon_instr_queue_t *iq, u32 napi_budget)
{
	int reqtype;
	void *buf;
	u32 old = iq->flush_index;
	u32 inst_count = 0;
	unsigned int pkts_compl = 0, bytes_compl = 0;
	struct octeon_soft_command *sc;
	struct octeon_instr_irh *irh;
	unsigned long flags;

    while (old != iq->octeon_read_index) {
		reqtype = iq->nrlist[old].reqtype;
		buf     = iq->nrlist[old].buf;

		if (reqtype == REQTYPE_NONE)
			goto skip_this;

		octeon_update_tx_completion_counters(buf, reqtype, &pkts_compl,
				&bytes_compl);

		switch (reqtype) {
			case REQTYPE_NORESP_NET:
			case REQTYPE_NORESP_NET_SG:
			case REQTYPE_RESP_NET_SG:
				reqtype_free_fn[oct->octeon_id][reqtype](buf);
				break;
	        case REQTYPE_RESP_NET:
	        case REQTYPE_SOFT_COMMAND:
	            sc = buf;

            if (OCTEON_CN23XX_PF(oct) || OCTEON_CN23XX_VF(oct))
				irh = (struct octeon_instr_irh *)
				                  &sc->cmd.cmd3.irh;
			else
			    irh = (struct octeon_instr_irh *)
			                    &sc->cmd.cmd2.irh;
			if (irh->rflag) {
				/* We're expecting a response from Octeon.
				 * It's up to lio_process_ordered_list() to
				 * process  sc. Add sc to the ordered soft
				 * command response list because we expect
				 * a response from Octeon.
			     */
               spin_lock_irqsave
                   (&oct->response_list
	                     [OCTEON_ORDERED_SC_LIST].lock,
	                      flags);
	           atomic_inc(&oct->response_list
	                   [OCTEON_ORDERED_SC_LIST].
	                    pending_req_count);
	           list_add_tail(&sc->node, &oct->response_list
	                   [OCTEON_ORDERED_SC_LIST].head);
	           spin_unlock_irqrestore
	                   (&oct->response_list
	                     [OCTEON_ORDERED_SC_LIST].lock,
	                     flags);

            } else {
                if (sc->callback) {
                   /* This callback must not sleep */
                   sc->callback(oct, OCTEON_REQUEST_DONE,
                            sc->callback_arg);
                }
            }
            break;
		        default:
	            dev_err(&oct->pci_dev->dev,
	                "%s Unknown reqtype: %d buf: %p at idx %d\n",
	                __func__, reqtype, buf, old);
        }

        iq->request_list[old].buf = NULL;
        iq->request_list[old].reqtype = 0;

 skip_this:
		inst_count++;
		old = incr_index(old, 1, iq->max_count);
				 
		if ((napi_budget) && (inst_count >= napi_budget))
			break;
	 }
	 if (bytes_compl)
	      octeon_report_tx_completion_to_bql(iq->app_ctx, pkts_compl,
	                           bytes_compl);
	 iq->flush_index = old;
																 
	 return inst_count;
}
#endif


#ifdef OCT_NIC_IQ_USE_NAPI
/* Can only be called from process context */
int
octeon_flush_iq(octeon_device_t *oct, octeon_instr_queue_t *iq,
        uint32_t napi_budget)
{
    uint32_t inst_processed = 0;
    uint32_t tot_inst_processed = 0;
    int tx_done = 1;

    if (!spin_trylock(&iq->iq_flush_running_lock))
		return tx_done;

	spin_lock_bh(&iq->lock);
									    
	iq->octeon_read_index = oct->fn_list.update_iq_read_idx(iq);

    do {
		/* Process any outstanding IQ packets. */
		if (iq->flush_index == iq->octeon_read_index)
			break;

		if (napi_budget)
			inst_processed =
				lio_process_iq_request_list(oct, iq,
										napi_budget -
										tot_inst_processed);
		else
			inst_processed =
				lio_process_iq_request_list(oct, iq, 0);

		if (inst_processed) {
			atomic_sub(inst_processed, &iq->instr_pending);
			iq->stats.instr_processed += inst_processed;
		}

		tot_inst_processed += inst_processed;
		inst_processed = 0;

	} while (tot_inst_processed < napi_budget);

	if (napi_budget && (tot_inst_processed >= napi_budget))
		tx_done = 0;

	iq->last_db_time = jiffies;

	spin_unlock_bh(&iq->lock);

	spin_unlock(&iq->iq_flush_running_lock);

	return tx_done;
}
#else
void
octeon_flush_iq(octeon_device_t * oct, octeon_instr_queue_t * iq,
		uint32_t pending_thresh)
{

	if (cavium_atomic_read(&iq->instr_pending) >= pending_thresh) {
		flush_instr_queue(oct, iq);
	}
}
#endif

void octeon_perf_flush_iq(octeon_device_t * oct, octeon_instr_queue_t * iq)
{
	uint32_t inst_processed = 0;

	cavium_spin_lock_softirqsave(&iq->lock);

	iq->octeon_read_index = oct->fn_list.update_iq_read_idx(iq);

	if (iq->flush_index != iq->octeon_read_index) {
		uint32_t old = iq->flush_index;

		inst_processed = 0;
		while (old != iq->octeon_read_index) {
			inst_processed++;
			INCR_INDEX_BY1(old, iq->max_count);
		}
		iq->flush_index = old;
	}

	if (inst_processed) {
		cavium_atomic_sub(inst_processed, &iq->instr_pending);
		iq->stats.instr_processed += inst_processed;
	}
	cavium_spin_unlock_softirqrestore(&iq->lock);

	return;
}

/* $Id: request_manager.c 170607 2018-03-20 15:52:25Z vvelumuri $ */
