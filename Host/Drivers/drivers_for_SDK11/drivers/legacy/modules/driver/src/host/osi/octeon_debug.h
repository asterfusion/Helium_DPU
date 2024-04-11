/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_debug.h
    \brief  Host Driver: Debug routines to print Octeon driver structures and data.
*/

#ifndef __OCTEON_DEBUG_H__
#define __OCTEON_DEBUG_H__

#ifdef CAVIUM_DEBUG
#include "octeon-common.h"

/** Print buffer contents.
 *  @param data   - buffer to print
 *  @param size   - number of bytes to print from buffer.
 */
void print_data(uint8_t * data, uint32_t size);

/**  Print the input queue contents. 
 *   @param  oct_dev  - pointer to the octeon device.
 *   @param  iq_no    - instruction queue whose contents are printed.
 *
 *   Prints the commands in the instruction queue.
 */
void print_queue(octeon_device_t * oct_dev, int iq_no);

/**  Print the pending list contents.
 *   @param  oct_dev  - pointer to the octeon device.
 *
 *   Prints certain fields of the soft instruction in each entry.
 */
void print_pending_list(octeon_device_t * oct_dev);

/**  Print the response list contents.
 *   @param octeon_dev   - pointer to the octeon device.
 *   @param list_number  - response list to be printed.
 *
 *   Prints some fields of the pending list entries attached to the
 *   response list.
 */
void print_response_list(octeon_device_t * octeon_dev, uint32_t list_number);

/**  Print contents of Octeon registers.
 *   @param octeon_dev  - pointer to the octeon device.
 *   
 *   Prints the contents of the config space registers, the
 *   CSR and the windowed registers.
 */
void print_octeon_regs(octeon_device_t * octeon_dev);

/** Print contents of request info structure. 
 *  @param req_info - pointer to request info structure.
 */
void print_req_info(octeon_request_info_t * req_info);

/**   Prints contents of a soft instruction.
 *    @param octeon_dev  - pointer to the octeon device.
 *    @param soft_instr  - pointer the soft instruction structure.
 *
 *    Prints all the fields of a soft instruction; decoding the type
 *    of request that created the instruction and also scatter/gather
 *    list contents.
 */
void print_soft_instr(octeon_device_t * octeon_dev,
		      octeon_soft_instruction_t * soft_instr);

/** Print the command posted to a instruction queue.
 *  @param iq_mode  -  the mode of the instruction (32-byte/64-byte)
 *  @param  arg      -  the command to be printed.
 *
 *  The command is printed in the format hinted by the iq_mode.
 */
void octeon_print_command(OCTEON_IQ_INSTRUCTION_MODE iq_mode, void *arg);

/**  Print the contents of a scatter/gather list.
 *   @param  sg     - pointer to the scatter/gather list.
 *   @param  count  - the number of entries in the list.
 *
 *   Prints the contents of the list for the number of entries
 *   hinted by the count.
 */
void print_sg_list(octeon_sg_entry_t * sg, uint32_t count);

/* Print first 8 bytes of each instruction posted to Octeon. */
/* The list may wrap around if more instructions than the size of stamp list
   is posted. */
void octeon_print_stamps(void);

/* Add the first 8 bytes of data at dptr to the next index in the stamp list
   The list may wrap around if more instructions than the size of stamp list
   is posted. */
void octeon_add_stamp(uint64_t * dptr, uint32_t q_index);

#else /* CAVIUM_DEBUG is not defined. */

#define print_data(arg1, arg2)              do { } while(0);
#define print_queue(arg1, arg2 )            do { } while(0);
#define print_pending_list(arg1)            do { } while(0);
#define print_response_list(arg1, arg2 )    do { } while(0);
#define print_octeon_regs(arg1)             do { } while(0);

#define print_octeon_regs(arg1)    do { } while(0);

#define print_req_info(arg1, arg2)      do { } while(0);
#define print_soft_instr(arg1, arg2)      do { } while(0);
#define octeon_print_command(arg1, arg2)  do { } while(0);
#define print_sg_list(arg1, arg2)         do { } while(0);

#define oct_push_profile()      do{ }while(0);
#define oct_pop_profile()       do{ }while(0);
#define oct_print_profile(msg)  do{ }while(0);

#define octeon_print_stamps()   do{ }while(0);
#define octeon_add_stamps()     do{ }while(0);

#endif /* CAVIUM_DEBUG */

static inline void cavium_error_print_data(uint8_t * data, int size)
{
	int i;

	if (data == NULL) {
		cavium_print_msg("%s: NULL Pointer found\n", __CVM_FUNCTION__);
		return;
	}

	cavium_print_msg("Printing %d bytes @ 0x%p\n", size, data);
	for (i = 0; i < size; i++) {
		if (!(i & 0x7))
			cavium_print_msg("\n");
		cavium_print_msg(" %02x", data[i]);
	}
	cavium_print_msg("\n");
}

#endif /*__OCTEON_DEBUG_H__*/

/* $Id: octeon_debug.h 141712 2016-07-08 06:55:10Z mchalla $ */
