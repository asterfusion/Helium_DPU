/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_instr.h
    \brief  Host Driver: Octeon soft instruction format and macros to operate on it.
*/

#ifndef  __OCTEON_INSTR_H__
#define  __OCTEON_INSTR_H__

/*------------------------------  SOFT INSTRUCTION  -------------------------*/

/* alloc flags settings  */
#define OCTEON_DPTR_COALESCED         1
#define OCTEON_DPTR_GATHER            2
#define OCTEON_RPTR_HEADER            4
#define OCTEON_RPTR_SCATTER           8
#define OCTEON_SOFT_INSTR_ALLOCATED   16
#define OCTEON_SOFT_INSTR_DB_NOW      32
#define OCTEON_DIRECT_GATHER          64

/** Format of a instruction presented to the driver. This structure has the
    values that get posted to Octeon in addition to other fields that are
    used by the driver to keep track of the instruction's progress.
*/
typedef struct {

	cavium_list_t list;

#define COMPLETION_WORD_INIT    0xffffffffffffffffULL
	/** Pointer to the completion status word */
	volatile uint64_t *status_word;

	/** The timestamp (in ticks) till we wait for a response for this
        instruction. */
	unsigned long timeout;

	/**How the response for the instruction should be handled.*/
	octeon_request_info_t req_info;

	/** Input data pointer. It is either pointing directly to input data
	    or to a gather list which is a list of addresses where data is present. */
	void *dptr;

	/** Response from Octeon comes at this address. It is either pointing to 
	    output data buffer directly or to a scatter list which in turn points 
	    to output data buffers. */
	void *rptr;

	/** The instruction header. All input commands have this field. */
	octeon_instr_ih_t ih;

	/** Input request header. */
	octeon_instr_irh_t irh;

	/** The PCI instruction to be sent to Octeon. This is stored in the instr
	    to retrieve the physical address of buffers when instr is freed. */
	octeon_instr_64B_t command;

	/** These headers are used to create a 64-byte instruction  */
	uint64_t exhdr[4];

	/** Information about the extra headers. */
	octeon_exhdr_info_t exhdr_info;

	/** Flags to indicate memory allocated for this instruction. Used by driver
	    when freeing the soft instruction.  */
	uint32_t alloc_flags;

	/** If a gather list was allocated, this ptr points to the buffer used for
	    the gather list. The gather list has to be 8B aligned, so this value
	    may be different from dptr.
	*/
	void *gather_ptr;

	/** Total data bytes transferred in the gather mode request. */
	uint32_t gather_bytes;

	/** If a scatter list was allocated, this ptr points to the buffer used for
	    the scatter list. The scatter list has to be 8B aligned, so this value
	    may be different from rptr.
	*/
	void *scatter_ptr;

	/** Total data bytes to be received in the scatter mode request. */
	uint32_t scatter_bytes;

} octeon_soft_instruction_t;

#define OCT_SOFT_INSTR_SIZE   (sizeof(octeon_soft_instruction_t))

#define SOFT_INSTR_IRH(pinstr)         ((pinstr)->irh)
#define SOFT_INSTR_OPCODE(pinstr)      ((pinstr)->irh.opcode)
#define SOFT_INSTR_DPTR(pinstr)        ((pinstr)->dptr)
#define SOFT_INSTR_IH(pinstr)          ((pinstr)->ih)
#define SOFT_INSTR_CALLBACK(pinstr)    ((pinstr)->req_info.callback)
#define SOFT_INSTR_CALLBACK_ARG(pinstr) ((pinstr)->req_info.callback_arg)
#define SOFT_INSTR_STATUS(pinstr)      ((pinstr)->req_info.status)
#define SOFT_INSTR_REQUESTID(pinstr)   ((pinstr)->req_info.request_id)
#define SOFT_INSTR_RESP_ORDER(pinstr)  ((pinstr)->req_info.req_mask.resp_order)
#define SOFT_INSTR_RESP_MODE(pinstr)   ((pinstr)->req_info.req_mask.resp_mode)
#define SOFT_INSTR_DMA_MODE(pinstr)    ((pinstr)->req_info.req_mask.dma_mode)
#define SOFT_INSTR_IQ_NO(pinstr)       ((pinstr)->req_info.req_mask.iq_no)
#define SOFT_INSTR_EXHDR_COUNT(pinstr) ((pinstr)->exhdr_info.exhdr_count)
#define SOFT_INSTR_ALLOCFLAGS(pinstr)  ((pinstr)->alloc_flags)
#define SOFT_INSTR_DLEN(pinstr)        ((pinstr)->ih.dlengsz)
#define SOFT_INSTR_HAS_GATHER(pinstr)  ((pinstr)->ih.gather)
#define SOFT_INSTR_RLEN(pinstr)        ((pinstr)->irh.rlenssz)
#define SOFT_INSTR_HAS_SCATTER(pinstr) ((pinstr)->irh.scatter)
#define SOFT_INSTR_RPTR(pinstr)        ((pinstr)->rptr)
#define SOFT_INSTR_TIMEOUT(pinstr)     ((pinstr)->req_info.timeout)
#define SET_SOFT_INSTR_OPCODE(pinstr, val)  ((pinstr)->irh.opcode = (val))
#define SET_SOFT_INSTR_IQ_NO(pinstr,  val)  ((pinstr)->req_info.req_mask.iq_no = (val))
#define SET_SOFT_INSTR_TIMEOUT(pinstr, val) ((pinstr)->req_info.timeout=(val))
#define SET_SOFT_INSTR_RESP_ORDER(pinstr, vresp_order) \
   ((pinstr)->req_info.req_mask.resp_order = vresp_order)
#define SET_SOFT_INSTR_RESP_MODE(pinstr, vresp_mode)   \
   ((pinstr)->req_info.req_mask.resp_mode = (vresp_mode))
#define SET_SOFT_INSTR_DMA_MODE(pinstr, vdma_mode)     \
   ((pinstr)->req_info.req_mask.dma_mode = (vdma_mode))
#define SET_SOFT_INSTR_CALLBACK(pinstr, vcallback)     \
   ((pinstr)->req_info.callback = (vcallback))
#define SET_SOFT_INSTR_CALLBACK_ARG(pinstr, arg)      \
   ((pinstr)->req_info.callback_arg = (arg))
#define SET_SOFT_INSTR_STATUS(pinstr, val)            \
   ((pinstr)->req_info.status = (val))
#define SET_SOFT_INSTR_REQUESTID(pinstr, val)         \
   ((pinstr)->req_info.request_id = (val))
#define SET_SOFT_INSTR_OCTEONID(pinstr, oct_id)       \
   ((pinstr)->req_info.octeon_id = (oct_id))
#define SET_SOFT_INSTR_ALLOCFLAGS(pinstr, val)        \
   ((pinstr)->alloc_flags |= (val))
#define INIT_SOFT_INSTR_ALLOCFLAGS(pinstr)            \
   ((pinstr)->alloc_flags = 0)

/*----------------------Function prototypes----------------------*/

/**
 *  octeon_process_instruction.
 *  NOTE: Starting with release 0.9.6, this routine requires a 3rd parameter
 *        which can be NULL in most cases. The 3rd parameter is only set by
 *        the driver's octeon_process_request() routine currently.
 *  This routine is called by different components of the driver when 
 *  an instruction (raw packet) or data packet needs to sent to the
 *  Octeon device. All requests from external applications or kernel
 *  modules also get routed via this routine.
 *
 * @param  oct        - pointer to octeon device structure.
 * @param  soft_instr - pointer to the soft instruction structure
 *                       which has the input commnand to be posted.
 * @param  soft_req   - an optional pointer to a soft_request structure.
 *                      If present and the instruction is posted successfully,
 *                      the status and request id is copied from soft_instr
 *                      into the soft_request before returning.
 *
 * @return: Returns octeon_instr_status_t type value.
 *          Set to OCTEON_SOFT_INSTR_FAILED on failure.
 *          Else s.status has current status.
 */
octeon_instr_status_t
octeon_process_instruction(octeon_device_t * oct,
			   octeon_soft_instruction_t * soft_instr,
			   octeon_soft_request_t * soft_req);

#endif /* __OCTEON_INSTR_H__ */

/* $Id: octeon_instr.h 160211 2017-06-13 12:57:09Z gpatchikolla $ */
