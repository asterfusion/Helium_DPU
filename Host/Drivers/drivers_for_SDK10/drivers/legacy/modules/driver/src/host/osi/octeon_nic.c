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

#include "cavium_sysdep.h"
#include "octeon_device.h"
#include "octeon_macros.h"
#include "octeon_nic.h"

int octnet_send_nic_data_pkt(octeon_device_t * oct, octnic_data_pkt_t * ndata)
{
#if  defined(FLOW_BASED_DISTRIBUTION)
	return octeon_send_noresponse_command(oct, ndata->q_no, 0, &ndata->cmd,
					      ndata->buf, ndata->datasize,
					      ndata->buftype);
#else
	return octeon_send_noresponse_command(oct, ndata->q_no, 1, &ndata->cmd,
					      ndata->buf, ndata->datasize,
					      ndata->buftype);
#endif
}

void octnet_link_ctrl_callback(octeon_req_status_t status, void *sif_ptr)
{
	octeon_soft_instruction_t *si = (octeon_soft_instruction_t *) sif_ptr;
	octnic_ctrl_pkt_t *nctrl;

	nctrl = (octnic_ctrl_pkt_t *) ((uint8_t *) si + OCT_SOFT_INSTR_SIZE);

	/* Call the callback function if status is OK.
	   Status is OK only if a response was expected and core returned success.
	   If no response was expected, status is OK if the command was posted
	   successfully. */
	if (!status && nctrl->cb_fn)
		nctrl->cb_fn(nctrl);

	cavium_free_dma(si);
}

#if !defined(ETHERPCI)
void
octnet_prepare_ls_soft_instr(octeon_device_t * oct,
			     octeon_soft_instruction_t * si)
{

	octeon_config_t *oct_cfg = octeon_get_conf(oct);
	cavium_memset(si, 0, OCT_SOFT_INSTR_SIZE);

	si->ih.fsz = 16;
	si->ih.tagtype = ORDERED_TAG;
	si->ih.tag = 0x11111111;
	si->ih.raw = 1;

	si->irh.opcode = HOST_NW_INFO_OP;
	si->irh.param = 32;

	SET_SOFT_INSTR_DMA_MODE(si, OCTEON_DMA_DIRECT);
	SET_SOFT_INSTR_RESP_ORDER(si, OCTEON_RESP_ORDERED);
	SET_SOFT_INSTR_RESP_MODE(si, OCTEON_RESP_NON_BLOCKING);
	SET_SOFT_INSTR_IQ_NO(si, CFG_GET_CTRL_Q_NO(oct_cfg));
	SET_SOFT_INSTR_TIMEOUT(si, 1000);

	/* Since this instruction is sent in the poll thread context, if the
	   doorbell coalescing is > 1, the doorbell will never be rung for
	   this instruction (this call has to return for poll thread to hit
	   the doorbell). So enforce the doorbell ring. */
	SET_SOFT_INSTR_ALLOCFLAGS(si, OCTEON_SOFT_INSTR_DB_NOW);
	si->dptr = NULL;
	si->ih.dlengsz = 0;
}

#endif

static inline octeon_soft_instruction_t
    * octnic_alloc_ctrl_pkt_si(octeon_device_t * oct, octnic_ctrl_pkt_t * nctrl,
			       octnic_ctrl_params_t nparams)
{
	octeon_soft_instruction_t *si = NULL;
	uint8_t *data;
	uint32_t uddsize = 0, datasize = 0;
	octeon_config_t *oct_cfg = octeon_get_conf(oct);

	uddsize = (nctrl->ncmd.s.more * 8);

	datasize = OCTNET_CMD_SIZE + uddsize + (nctrl->wait_time ? 16 : 0);

	/* Additional 8 bytes to align rptr to a 8 byte boundary. */
	datasize += sizeof(octnic_ctrl_pkt_t) + 8;

	si = cavium_malloc_dma((OCT_SOFT_INSTR_SIZE + datasize),
			       __CAVIUM_MEM_ATOMIC);
	if (si == NULL)
		return NULL;

	cavium_memset(si, 0, (OCT_SOFT_INSTR_SIZE + datasize));

	cavium_memcpy(((uint8_t *) si + OCT_SOFT_INSTR_SIZE), nctrl,
		      sizeof(octnic_ctrl_pkt_t));

	si->ih.fsz = 16;
	si->ih.tagtype = ORDERED_TAG;
	si->ih.tag = 0x11111111;
	si->ih.raw = 1;
	si->ih.grp = CFG_GET_CTRL_Q_GRP(oct_cfg);
	si->ih.rs = 1;
	si->irh.opcode = OCT_NW_CMD_OP;
	SET_SOFT_INSTR_DMA_MODE(si, OCTEON_DMA_DIRECT);
	SET_SOFT_INSTR_OCTEONID(si, oct->octeon_id);
	SET_SOFT_INSTR_IQ_NO(si, CFG_GET_CTRL_Q_NO(oct_cfg));
	SET_SOFT_INSTR_CALLBACK(si, octnet_link_ctrl_callback);
	SET_SOFT_INSTR_CALLBACK_ARG(si, (void *)si);

	data = (uint8_t *) si + OCT_SOFT_INSTR_SIZE + sizeof(octnic_ctrl_pkt_t);
	si->dptr = data;
	si->ih.dlengsz = OCTNET_CMD_SIZE + uddsize;

	cavium_memcpy(data, &nctrl->ncmd, OCTNET_CMD_SIZE);
	//octeon_swap_8B_data((uint64_t *) data, (OCTNET_CMD_SIZE >> 3));

	if (uddsize) {
		/* Endian-Swap for UDD should have been done by caller. */
		cavium_memcpy(data + OCTNET_CMD_SIZE, nctrl->udd, uddsize);
	}

	if (nctrl->wait_time) {
		si->rptr = ((uint8_t *) si->dptr + si->ih.dlengsz);
		if ((unsigned long)si->rptr & 0x7) {
			si->rptr =
			    (void *)(((unsigned long)si->rptr + 8) & ~0x7);
		}
		si->irh.rlenssz = 16;
		si->status_word = (uint64_t *) ((uint8_t *) si->rptr + 8);
		*(si->status_word) = COMPLETION_WORD_INIT;

		SET_SOFT_INSTR_RESP_ORDER(si, nparams.resp_order);
		SET_SOFT_INSTR_RESP_MODE(si, OCTEON_RESP_NON_BLOCKING);
		SET_SOFT_INSTR_TIMEOUT(si, nctrl->wait_time);
	} else {
		SET_SOFT_INSTR_RESP_ORDER(si, OCTEON_RESP_NORESPONSE);
	}

	SET_SOFT_INSTR_ALLOCFLAGS(si, OCTEON_SOFT_INSTR_DB_NOW);

	cavium_print(PRINT_FLOW,
		     "%s si @ %p uddsize: %d datasize: %d dptr: %p rptr: %p\n",
		     __CVM_FUNCTION__, si, uddsize, datasize, si->dptr,
		     si->rptr);

	return si;
}

int
octnet_send_nic_ctrl_pkt(octeon_device_t * oct, octnic_ctrl_pkt_t * nctrl,
			 octnic_ctrl_params_t nparams)
{
	octeon_instr_status_t retval;
	octeon_soft_instruction_t *si = NULL;

	si = octnic_alloc_ctrl_pkt_si(oct, nctrl, nparams);
	if (si == NULL) {
		cavium_error("OCTNIC: %s soft instr alloc failed\n",
			     __CVM_FUNCTION__);
		return -1;
	}

	retval = octeon_process_instruction(oct, si, NULL);
	if (retval.s.error) {
		cavium_error("OCTNIC: %s soft instr send failed status: %x\n",
			     __CVM_FUNCTION__, retval.s.status);
		return -1;
	}

	return retval.s.request_id;
}

/* $Id: octeon_nic.c 151774 2017-01-05 09:09:50Z mchalla $ */
