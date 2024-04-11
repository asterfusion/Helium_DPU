/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file octeon_mem_ops.h
     \brief Host Driver: Routines used to read/write Octeon memory.
*/

#ifndef __OCTEON_MEM_OPS_H__
#define __OCTEON_MEM_OPS_H__

#include  "octeon_hw.h"

#define    OCT_CORE_BAR1_MAPS       MAX_BAR1_MAP_INDEX
#define    OCT_CORE_MEM_BEGIN       0x00000000
#define    OCT_CORE_MEM_END         (OCT_CORE_MEM_BEGIN + (MAX_BAR1_MAP_INDEX * (1 << 22)))

/** Map the Octeon memory into host virtual memory using BAR1 index registers.
  * The routine checks that the range given by (end - start) will fit in the
  * available BAR1 index registers. If it does, it creates the mapping and
  * stores the PCI mapped address for the range (end - start) in an internal
  * structure.
  */
uint32_t
octeon_map_device_range(octeon_device_t * oct, uint64_t start, uint64_t end);

/** Get the PCI address by looking up the core_addr to the device's internal
 *  mapping table. If the region of core_addr is mapped, return the PCI address,
 *  else return NULL.
 */
void *octeon_get_mapped_addr(octeon_device_t * oct, uint64_t core_addr);

/**  Read a 64-bit value from a BAR1 mapped core memory address.
 *   @param  oct        -  pointer to the octeon device.
 *   @param  core_addr  -  the address to read from.
 *
 *   The range_idx gives the BAR1 index register for the range of address
 *   in which core_addr is mapped.
 *
 *   @return  64-bit value read from Core memory
 */
uint64_t octeon_read_device_mem64(octeon_device_t * oct, uint64_t core_addr);

/**  Read a 32-bit value from a BAR1 mapped core memory address.
 *   @param  oct        -  pointer to the octeon device.
 *   @param  core_addr  -  the address to read from.
 *
 *   @return  32-bit value read from Core memory
 */
uint32_t octeon_read_device_mem32(octeon_device_t * oct, uint64_t core_addr);

/**  Read a 16-bit value from a BAR1 mapped core memory address.
 *   @param  oct       -  pointer to the octeon device.
 *   @param  core_addr -  the address to read from.
 *
 *   @return  16-bit value read from Core memory
 */
uint16_t octeon_read_device_mem16(octeon_device_t * oct, uint64_t core_addr);

/**  Read a 8-bit value from a BAR1 mapped core memory address.
 *   @param  oct        -  pointer to the octeon device.
 *   @param  core_addr  -  the address to read from.
 *
 *   @return  8-bit value read from Core memory
 */
uint8_t octeon_read_device_mem8(octeon_device_t * oct, uint64_t core_addr);

/**  Write a 64-bit value to a BAR1 mapped core memory address.
 *   @param  oct         -  pointer to the octeon device.
 *   @param  core_addr   -  the address to write to.
 *   @param  val         -  64-bit value to write.
 *
 *   The range_idx gives the BAR1 index register for the range of address
 *   in which core_addr is mapped. 
 *
 *   @return  Nothing.
 */
int
octeon_write_device_mem64(octeon_device_t * oct, uint64_t core_addr,
			  uint64_t val);

/**  Write a 32-bit value to a BAR1 mapped core memory address.
 *   @param  oct        -  pointer to the octeon device.
 *   @param  core_addr  -  the address to write to.
 *   @param  val        -  32-bit value to write.
 *
 *   @return  Nothing.
 */
int
octeon_write_device_mem32(octeon_device_t * oct, uint64_t core_addr,
			  uint32_t val);

/**  Write a 16-bit value to a BAR1 mapped core memory address.
 *   @param  oct         -  pointer to the octeon device.
 *   @param  core_addr   -  the address to write to.
 *   @param  val         -  16-bit value to write.
 *
 *   @return  Nothing.
 */
int
octeon_write_device_mem16(octeon_device_t * oct, uint64_t core_addr,
			  uint16_t val);

/**  Write a 8-bit value to a BAR1 mapped core memory address.
 *   @param  oct         -  pointer to the octeon device.
 *   @param  core_addr   -  the address to write to.
 *   @param  val         -  8-bit value to write.
 *
 *   @return  Nothing.
 */
int
octeon_write_device_mem8(octeon_device_t * oct, uint64_t core_addr,
			 uint8_t val);

/** Read multiple bytes from Octeon memory using the defined SWAP type. Also
  * check the octeon_read_core_memory() function, that reads Octeon memory with
  * an assumed swap of 64-bit.
  */
void
octeon_pci_read_core_mem(octeon_device_t * oct,
			 uint64_t coreaddr,
			 uint8_t * buf, uint32_t len, int swap);

/** Write multiple bytes into Octeon memory using the defined SWAP type. Also
  * check the octeon_write_core_memory() function, that writes Octeon memory
  * with an assumed swap of 64-bit.
  */
void
octeon_pci_write_core_mem(octeon_device_t * oct,
			  uint64_t coreaddr,
			  uint8_t * buf, uint32_t len, int swap);

#endif

/* $Id: octeon_mem_ops.h 141410 2016-06-30 14:37:41Z mchalla $ */
