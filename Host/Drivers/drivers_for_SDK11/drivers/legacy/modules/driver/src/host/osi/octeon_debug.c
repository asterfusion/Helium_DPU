/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifdef CAVIUM_DEBUG

#include "octeon_main.h"
#include "octeon_hw.h"

#define MAX_OCTEON_STAMP_CNT 256

OCTEON_DEBUG_LEVEL octeon_debug_level = CAVIUM_DEBUG;

static uint64_t oct_stamps[MAX_OCTEON_STAMP_CNT];
static uint8_t oct_stamp_index[MAX_OCTEON_STAMP_CNT];
static int oct_stamp_cnt = 0;

void print_data(uint8_t * data, uint32_t size)
{
	uint32_t i;

	cavium_print(PRINT_DEBUG, "Printing %d bytes @ 0x%p\n", size, data);
	for (i = 0; i < size; i++) {
		if (!(i & 0x7))
			cavium_print(PRINT_DEBUG, "\n");
		cavium_print(PRINT_DEBUG, " %02x", data[i]);
	}
	cavium_print(PRINT_DEBUG, "\n");
}

/*
   print_config_regs
   Parameters:
     1. octeon_dev  - Pointer to the octeon device.
   Description: 
     Prints select registers of Octeon from
     Config Space, Mapped to BAR0 (CSR), Windowed Registers.
   Returns:
     Nothing
   Locks:
     No locks are held.
*/
void print_octeon_regs(octeon_device_t * octeon_dev)
{
	int i;
	uint32_t val;
	uint64_t startaddr = 0x00011F0000000000ULL;

	cavium_print(PRINT_REGS, "\n----config regs----\n");
	for (i = 0; i < 0x64; i += 4) {
		OCTEON_READ_PCI_CONFIG(octeon_dev, i, &val);
		cavium_print(PRINT_REGS, "config[0x%x]: 0x%08x\n", i, val);
	}

	cavium_print(PRINT_REGS, "\n----CSR regs----\n");
// *INDENT-OFF*
   for(i = 0; i < 0x28; i+= 4)
       cavium_print(PRINT_REGS,"Reg[0x%x]: 0x%08x\n", i, OCTEON_READ32((uint8_t*)octeon_dev->mmio[0].hw_addr + i));
   for(i = 0x30; i < 0xB8; i+= 4)
     cavium_print(PRINT_REGS,"Reg[0x%x]: 0x%08x\n", i, OCTEON_READ32((uint8_t*)octeon_dev->mmio[0].hw_addr + i));
// *INDENT-ON*
	cavium_print(PRINT_REGS, "n----NPI  regs----\n");

	cavium_print(PRINT_REGS, "NPI[%016llx]: 0x%016llx\n",
		     CVM_CAST64(startaddr + 0x10),
		     CVM_CAST64(OCTEON_PCI_WIN_READ
				(octeon_dev, startaddr + 0x10)));
	for (i = 0x50; i < 0x1FF; i += 8)
		cavium_print(PRINT_REGS, "NPI[%016llx]: 0x%016llx\n",
			     CVM_CAST64(startaddr + i),
			     CVM_CAST64(OCTEON_PCI_WIN_READ
					(octeon_dev, startaddr + i)));
	cavium_print(PRINT_REGS, "n\n");
}

void print_queue(octeon_device_t * oct_dev, int iq_no)
{

	if (octeon_debug_level >= PRINT_DEBUG) {
		octeon_instr_queue_t *iq;
		octeon_instr_32B_t *queue32;
		octeon_instr_64B_t *queue64;
		uint32_t i;

		cavium_print(PRINT_DEBUG, "\n---Instruction Queue No. %d---\n",
			     iq_no);
		iq = (octeon_instr_queue_t *) & oct_dev->instr_queue[iq_no];

		if (iq->iqcmd_64B) {
			queue64 = (octeon_instr_64B_t *) iq->base_addr;
			for (i = 0; i < iq->max_count; i++)
				cavium_print(PRINT_DEBUG,
					     "Queue[%d] dptr:0x%llx ih:0x%llx irh:0x%llx rptr:0x%llx \n",
					     i, CVM_CAST64(queue64[i].dptr),
					     CVM_CAST64(*
							((uint64_t *) &
							 queue64[i].ih)),
					     CVM_CAST64(queue64[i].rptr),
					     CVM_CAST64(*
							((uint64_t *) &
							 queue64[i].irh)));
		} else {
			queue32 = (octeon_instr_32B_t *) iq->base_addr;

			for (i = 0; i < iq->max_count; i++)
				cavium_print(PRINT_DEBUG,
					     "Queue[%d] dptr:0x%llx ih:0x%llx irh:0x%llx  rptr:0x%llx\n",
					     i, CVM_CAST64(queue32[i].dptr),
					     CVM_CAST64(*
							((uint64_t *) &
							 queue32[i].ih)),
					     CVM_CAST64(queue32[i].rptr),
					     CVM_CAST64(*
							((uint64_t *) &
							 queue32[i].irh)));
		}
	}
}

void octeon_print_command(OCTEON_IQ_INSTRUCTION_MODE iq_mode, void *arg)
{

	if (octeon_debug_level >= PRINT_DEBUG) {
		octeon_instr_32B_t *cmd;
		octeon_instr_64B_t *command64;
		octeon_instr_ih_t *ih;
		int i;

		cavium_print(PRINT_DEBUG, "\n\n----#  print_command  #----\n");
		cmd = (octeon_instr_32B_t *) arg;
		cavium_print_msg("DPTR: 0x%016llx\n", CVM_CAST64(cmd->dptr));
		cavium_print_msg("IH  : 0x%016llx\n", CVM_CAST64(cmd->ih));
		ih = (octeon_instr_ih_t *) & (cmd->ih);
		cavium_print_msg
		    ("Mode: %s %s %s dlengsz: %d fsz: %d grp: %d qos: %d tag: 0x%08x tagtype: %d\n",
		     (ih->raw ? "RAW" : "Packet"),
		     (ih->gather ? (ih->dlengsz ? "InDirect" : "Direct") : ""),
		     (ih->gather ? "Gather" : "Direct"), ih->dlengsz, ih->fsz,
		     ih->grp, ih->qos, ih->tag, ih->tagtype);
		cavium_print_msg("RPTR: 0x%016llx\n", CVM_CAST64(cmd->rptr));
		cavium_print_msg("IRH : 0x%016llx\n", CVM_CAST64(cmd->irh));
		switch (iq_mode) {
		case IQ_MODE_64:
			command64 = (octeon_instr_64B_t *) arg;
			cavium_print_msg("---Exhdr--\n");
			for (i = 0; i < 4; i++)
				cavium_print_msg("gh[%d]: 0x%016llx\n",
						 i,
						 CVM_CAST64(command64->exhdr
							    [i]));
			break;
		case IQ_MODE_32:
			break;
		}
	}
}

void print_pending_list(octeon_device_t * octeon_dev)
{
	octeon_pending_list_t *plist;

	if (octeon_debug_level >= PRINT_DEBUG) {
		uint32_t i, j;
		uint32_t pl_index;
		uint64_t *ptr = NULL;

		cavium_print(PRINT_DEBUG, "\n\n----#  Pending List  #----\n");
// *INDENT-OFF*
		for(j=0;j< octeon_dev->num_iqs ; j++){
	
			plist = (octeon_pending_list_t *)octeon_dev->instr_queue[j]->plist;

			cavium_print(PRINT_DEBUG,"Instr_queue : %u Total used entries: %d\n",j,
					(plist->free_index));

			for (i = 0; i < plist->free_index; i++)  {
				pl_index = plist->free_list[i];
				cavium_print(PRINT_DEBUG," pending entry at index %d in pending_list\n",
						pl_index);
				cavium_print(PRINT_DEBUG," request id: %d\n",
						plist->list[pl_index].request_id);
				cavium_print(PRINT_DEBUG," queue_index: %d\n",
						plist->list[pl_index].queue_index);
				ptr = (uint64_t*)&plist->list[pl_index].instr->ih;
				cavium_print(PRINT_DEBUG," ih in the instr: 0x%llx\n", CVM_CAST64(*ptr));
				ptr = (uint64_t*)&plist->list[pl_index].instr->irh;
				cavium_print(PRINT_DEBUG," irh in the instr: 0x%llx\n", CVM_CAST64(*ptr));
			}
		}
// *INDENT-ON*
	}
}

void print_response_list(octeon_device_t * octeon_dev, uint32_t list_number)
{

	if (octeon_debug_level >= PRINT_DEBUG) {
		cavium_list_t *curr;
		octeon_pending_entry_t *pending_entry;
// *INDENT-OFF*

    cavium_print(PRINT_DEBUG,"\n--Response List %d---\n", list_number);

    cavium_list_for_each(curr, &octeon_dev->response_list[list_number].head) {
      pending_entry = (octeon_pending_entry_t *)curr;
     
      cavium_print(PRINT_DEBUG,"  request id: %d\n", pending_entry->request_id);
      cavium_print(PRINT_DEBUG,"  queue idx: %d\n", pending_entry->queue_index);
      cavium_print(PRINT_DEBUG,"  -----------------\n");
    }
// *INDENT-ON*
	}
}

void print_sg_list(octeon_sg_entry_t * sg, uint32_t count)
{

	if (octeon_debug_level >= PRINT_DEBUG) {
		uint32_t i, sg_count;
		uint64_t *data = (uint64_t *) sg;

		sg_count = count + (ROUNDUP4(count) >> 2);

		cavium_print(PRINT_DEBUG, "Scatter/Gather List @ %p\n", sg);
		for (i = 0; i < sg_count; i++) {
			cavium_print(PRINT_DEBUG, "Word[%d]: 0x%016llx\n",
				     i, CVM_CAST64(data[i]));
		}
	}
}

void print_req_info(octeon_request_info_t * req_info)
{
	uint32_t *ptr = NULL;
// *INDENT-OFF*
	cavium_print(PRINT_DEBUG,"Request Info Data\n");
	cavium_print(PRINT_DEBUG,"  octeon_id: 0x%x\n", req_info->octeon_id);
	ptr = (uint32_t *)&req_info->req_mask;
	cavium_print(PRINT_DEBUG,"  req_mask : 0x%08x\n %s %s %s qno:%d\n",
                *ptr,
	  	        (req_info->req_mask.resp_mode)?"Non-Blocking ":"Blocking ",
	            (req_info->req_mask.resp_order == 0)?"Ordered ":
                (req_info->req_mask.resp_order == 1)?"Unordered ":"NoResponse ",
                (req_info->req_mask.dma_mode == 0)?"Direct ":
                (req_info->req_mask.dma_mode == 1)?"Scatter ": 
                (req_info->req_mask.dma_mode == 2)?"Gather ":" Scatter-Gather ",
                req_info->req_mask.iq_no);

	cavium_print(PRINT_DEBUG,"timeout  : %u\n",req_info->timeout);
	cavium_print(PRINT_DEBUG,"callback:0x%p\n", req_info->callback);
	cavium_print(PRINT_DEBUG,"callback_arg: 0x%p\n", req_info->callback_arg);
	cavium_print(PRINT_DEBUG,"status   : 0x%08x\n", req_info->status);
	cavium_print(PRINT_DEBUG,"request_id: 0x%08x\n", req_info->request_id);
// *INDENT-ON*
}

void
print_soft_instr(octeon_device_t * octeon_dev UNUSED,
		 octeon_soft_instruction_t * soft_instr)
{

	if (octeon_debug_level >= PRINT_DEBUG) {
		int i;
		octeon_instr_ih_t *ih;
		octeon_instr_irh_t *irh;
		octeon_request_info_t *req_info = &soft_instr->req_info;

		cavium_print(PRINT_DEBUG, "Print SOFT_INSTRUCTION\n");
		cavium_print(PRINT_DEBUG, "dptr: 0x%p  rptr: 0x%p\n",
			     soft_instr->dptr, soft_instr->rptr);
		ih = &soft_instr->ih;
		irh = &soft_instr->irh;

		cavium_print(PRINT_DEBUG, "ih: 0x%016llx  irh: 0x%016llx\n",
			     CVM_CAST64(*((volatile uint64_t *)ih)),
			     CVM_CAST64(*((volatile uint64_t *)irh)));
		cavium_print(PRINT_DEBUG,
			     " %s %s dlen:%d fsz:%d qos:%d grp:%d %s\n",
			     (ih->raw) ? "Raw" : " ",
			     (ih->gather) ? " Gather " : " ", ih->dlengsz,
			     ih->fsz, ih->qos, ih->grp,
			     (ih->rs) ? " raw short " : " ");
		cavium_print(PRINT_DEBUG,
			     "opcode:0x%x param:%d dport:%d rlen:%d rid:%d %s\n",
			     irh->opcode, irh->param, irh->dport, irh->rlenssz,
			     irh->rid, (irh->scatter) ? " scatter " : " ");

		for (i = 0; i < 4; i++)
			cavium_print(PRINT_DEBUG, "exhdr[%d]:0x%016llx\n", i,
				     CVM_CAST64(soft_instr->exhdr[i]));
		cavium_print(PRINT_DEBUG, "status_word: 0x%p\n",
			     (soft_instr->status_word));
		cavium_print(PRINT_DEBUG, "timeout: %lu\n",
			     soft_instr->timeout);

		print_req_info(req_info);

		cavium_print(PRINT_DEBUG, "\nAlloc flags: %x\n",
			     soft_instr->alloc_flags);

		if (soft_instr->ih.gather) {
			cavium_print(PRINT_DEBUG,
				     "\ndptr is gather list with %d entries\n",
				     soft_instr->ih.dlengsz);
			print_sg_list((octeon_sg_entry_t *) soft_instr->dptr,
				      (uint32_t) soft_instr->ih.dlengsz);
		}
		if (soft_instr->irh.scatter) {
			cavium_print(PRINT_DEBUG,
				     "\nrptr is scatter list with %d entries\n",
				     soft_instr->irh.rlenssz);
			print_sg_list((octeon_sg_entry_t *) soft_instr->rptr,
				      (uint32_t) soft_instr->irh.rlenssz);
		}
	}
}

void octeon_print_stamp(void)
{
	int i;
	for (i = 0; i < oct_stamp_cnt; i++) {
		octeon_swap_8B_data(&oct_stamps[i], 1);
		cavium_print_msg("stamp[%d]: 0x%016llx index: %d\n", i,
				 CVM_CAST64(oct_stamps[i]), oct_stamp_index[i]);
	}
}

void octeon_add_stamp(uint64_t * dptr, uint32_t q_index)
{
	oct_stamps[oct_stamp_cnt] = *dptr;
	oct_stamp_index[oct_stamp_cnt] = q_index;
	oct_stamp_cnt++;
	if (oct_stamp_cnt == MAX_OCTEON_STAMP_CNT)
		oct_stamp_cnt = 0;
}

#endif

/* $Id: octeon_debug.c 141410 2016-06-30 14:37:41Z mchalla $ */
