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

/*!  \file  octeon_user.h
     \brief Host Driver: Octeon user API provided by liboctapi.a
*/

#ifndef    __OCTEON_USER_H__
#define    __OCTEON_USER_H__

#if defined(_WIN32)

#include <windows.h>
#include <winioctl.h>
#include <cavium_sysdep.h>
#include <cavium_defs.h>
#include <octeon_ioctl.h>
#include <stdio.h>

#define STATUS_INVALID_PARAMETER         (0xC000000DL)
#define STATUS_UNSUCCESSFUL                 (0xC0000001L)

extern int errno;

int open(const char *filename, int mode);
void close(int fd);
int ioctl(int fd, int request, void *ptr);

#endif
#include <cavium_sysdep.h>
#include <octeon_ioctl.h>
#include <cavium_defs.h>

/* common user mode apis */

extern int oct_dev_handle;

typedef enum {
	DATA8 = 1,
	DATA16 = 2,
	DATA32 = 4,
/*    DATA64  =  8 */
} octeon_user_datatype_t;

/** Opens the octeon device file and sets the handle.
 *  This needs to be done only once to communicate with all Octeon devices.
 *  @return  Success: 0; Failure: errno returned by open
 */
int octeon_initialize();

/** Closes the octeon device file. The user app cannot communicate with any
 * Octeon device after this step.
 *  @return 0
 */
int octeon_shutdown();

/** Do a Hot Reset of the octeon device. After a Hot reset, a new
 * application can be loaded on the octeon cores without having to
 * restart the octeon driver module.
 * @return 0 if the reset was successful.
 * @return errno has the reason if the reset failed.
 */
int octeon_hot_reset(int oct_id);

/** Get the number of octeon devices currently managed by the driver.
 *  @return Success: Count of Octeon devices.
 *  @return Failure: 0.
 */
int octeon_get_dev_count();

/** Send a request to Octeon. The request can be in UNORDERED or NORESPONSE
  * mode. For UNORDERED mode, both blocking (the function call blocks till
  * it gets a response from octeon) or non-blocking (the function returns
  * immediately). 
  * @param oct_id   - the octeon device to which the request is sent.
  * @param soft_req - the request in octeon_soft_request_t format.
  * @return  Success: 0; Failure: errno returned by ioctl
  */
int octeon_send_request(int oct_id, octeon_soft_request_t * soft_req);

/** Query the status of a previously posted UNORDERED Non-blocking request.
  * @param oct_id - the octeon device to which the request is sent.
  * @param query  - query structure which holds the request id and in which
  *                 the status of the request is returned.
  * @return  Success: 0; Failure: errno returned by ioctl
  */
int octeon_query_request(int oct_id, octeon_query_request_t * query);

int octeon_get_stats(int oct_id, oct_stats_t * stats);

/** Get the number of IOQs initialized by the device given by octeon_id.
 *  @param oct_id - id of octeon device whose number of queues are required.
 *  @return  Success: Number of IOQs; Failure: negative of errno returned by ioctl
 */
int octeon_get_num_ioqs(int oct_id);

/**  Read the Octeon PCI config register.
 *   @param oct_id - id of octeon device.
 *   @param offset - offset into the config space (register address).
 *   @param data   - address where the register contents (32-bit) are to copied.
 *   @return  Success: 0; Failure: errno returned by ioctl
 */
int octeon_read_pcicfg_register(int oct_id, uint32_t offset, uint32_t * data);

/**  Write to a Octeon PCI config register.
 *   @param oct_id  - id of octeon device.
 *   @param offset  - offset into the config space (register address).
 *   @param data    - 32-bit value to be written.
 *   @return  Success: 0; Failure: errno returned by ioctl
 */
int octeon_write_pcicfg_register(int oct_id, uint32_t offset, uint32_t data);

/**  Get the physical mapped address for different PCI address spaces.
 *   @param oct_id - the octeon device to get the mapping for.
 *   @param type   - the type of mapping ((BAR0, BAR1, BAR2)
 *   @param mapped_address - the mapped physical address is expected here.
 *   @param mapped_size    - size of the mapped region is expected here.
 *   @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_get_mapping_info(int oct_id, octeon_reg_type_t type,
			    unsigned long *mapped_address,
			    uint32_t * mapped_size);

/** Read a 32-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to read.
 *  @param address - the address to read from.
 *  @param data    - Address where the 32-bit value should be read into.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_read32(int oct_id, unsigned long address, uint32_t * data);

/** Write a 32-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to write.
 *  @param address - the address to write to.
 *  @param data    - 32-bit value to write.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_write32(int oct_id, unsigned long address, uint32_t data);

/** Read a 16-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to read.
 *  @param address - the address to read from.
 *  @param data    - Address where the 16-bit value should be read into.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_read16(int oct_id, unsigned long address, uint16_t * data);

/** Write a 16-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to write.
 *  @param address - the address to write to.
 *  @param data    - 16-bit value to write.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_write16(int oct_id, unsigned long address, uint16_t data);

/** Read a 8-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to read.
 *  @param address - the address to read from.
 *  @param data    - Address where the 8-bit value should be read into.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_read8(int oct_id, unsigned long address, uint8_t * data);

/** Write a 8-bit value from a Octeon PCI mapped address.
 *  @param oct_id  - the octeon device to write.
 *  @param address - the address to write to.
 *  @param data    - 8-bit value to write.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_write8(int oct_id, unsigned long address, uint8_t data);

/** Write a 64-bit value to a 64-bit address in the Octeon PCI
 *  windowed access region.
 *  @param oct_id  - the octeon device to write.
 *  @param address - the address in the window to write to.
 *  @param data    - 64-bit value to write.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_win_write(int oct_id, uint64_t address, uint64_t data);

/** Read a 64-bit value from a 64-bit address in the Octeon PCI
 *  windowed access region.
 *  @param oct_id  - the octeon device to read.
 *  @param address - the address in the window to read.
 *  @param data    - The 64-bit value read should be copied here.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_win_read(int oct_id, uint64_t address, uint64_t * data);

/** Read "len" bytes from Octeon memory at address "core addr" and copy it into
 *  user-space memory at address "data". Use the byte-swap mode specified by
 *  "swap_mode".
 *  @param oct_id    - the octeon device to read.
 *  @param core_addr - the address in the Octeon memory to read.
 *  @param len       - number of bytes to read.
 *  @param data      - driver returns the data read from Octeon into user-space
 *                     starting at this address.
 *  @param swap_mode - byte-swap mode to use. Usually is 0 (no-swap)
 *                      or 1 (64-bit swap).
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_read_core_direct(int oct_id, uint64_t core_addr, uint32_t len,
			    void *data, uint32_t swap_mode);

/** Copy "len" bytes from user-space memory at address "data" into Octeon
 *  memory at address "core addr". Use the byte-swap mode specified by
 *  "swap_mode".
 *  @param oct_id    - the octeon device to write.
 *  @param core_addr - the address in the Octeon memory to write.
 *  @param len       - number of bytes to write.
 *  @param data      - driver copies data from this user-space address.
 *  @param swap_mode - byte-swap mode to use. Usually is 0 (no-swap)
 *                      or 1 (64-bit swap).
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_write_core_direct(int oct_id, uint64_t core_addr, uint32_t len,
			     void *data, uint32_t swap_mode);

/** Read 1/2/4 bytes from Octeon memory at address "address" and copy it into
 *  user-space memory at address "data". "datatype" specifies whether the
 *  read is 1/2/4 bytes wide.
 *  @param oct_id    - the octeon device to read.
 *  @param datatype  - specifies the number of bytes to read.
 *  @param address   - the address in the Octeon memory to read.
 *  @param data      - driver returns the data read from Octeon into user-space
 *                     starting at this address.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_read_core(int oct_id, octeon_user_datatype_t datatype,
		     uint64_t address, void *data);

/** Copy 1/2/4 bytes from user-space memory at address "data" into Octeon
 *  memory at address "address". "datatype" specifies whether the
 *  read is 1/2/4 bytes wide.
 *  @param oct_id    - the octeon device to write.
 *  @param datatype  - specifies the number of bytes to write.
 *  @param address   - the address in the Octeon memory to write.
 *  @param data      - driver copies the data from this user-space address
 *                     into Octeon.
 *  @return Success: 0; Failure: errno if ioctl fails.
 */
int octeon_write_core(int oct_id, octeon_user_datatype_t datatype,
		      uint64_t address, void *data);

#endif /* __OCTEON_USER_H__ */

/* $Id: octeon_user.h 141410 2016-06-30 14:37:41Z mchalla $ */
