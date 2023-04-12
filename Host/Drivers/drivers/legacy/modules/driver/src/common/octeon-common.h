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

/*!  \file  octeon-common.h
     \brief Common: Structures and macros used by both core and host driver.
*/

#ifndef  __OCTEON_COMMON_H__
#define  __OCTEON_COMMON_H__

#if defined(linux) &&  defined(__KERNEL__)
#include <linux/types.h>
#endif

/** Macro to increment index.
    Index is incremented by count; if the sum exceeds
    max, index is wrapped-around to the start.
*/
#define INCR_INDEX(index, count, max)             \
        if(((index)+(count)) >= (max))            \
            index = ((index)+(count))-(max);      \
        else                                      \
            index += (count);

#define INCR_INDEX_BY1(index, max)                \
        if((++(index)) == (max))  index=0;        \


#define DECR_INDEX(index, count, max)             \
        if( (count) > (index) )                   \
           index = ( (max) - ((count - index)) ); \
        else                                      \
           index -=count;

/** Structure used by core driver to send indication that the Octeon
	application is ready.*/
typedef struct {

	uint64_t corefreq;

} octeon_core_setup_t;

/*---------------------------  SCATTER GATHER ENTRY  -----------------------*/

/** Enum differentiates whether a given scatter-gather component should
    be used as a gather or a scatter list. */
typedef enum {
	OCTEON_SCATTER_LIST = 0,
	OCTEON_GATHER_LIST = 1
} OCTEON_SG_LIST_TYPE;

#define SCATTER_HEADER_BYTES   16

/** The Scatter-Gather List Entry. The scatter or gather component used with
    a Octeon input instruction has this format. */
typedef struct {

	/** The first 64 bit gives the size of data in each dptr.*/
	union {
		uint16_t size[4];
		uint64_t size64;
	} u;

	/** The 4 dptr pointers for this entry. */
	uint64_t ptr[4];

} octeon_sg_entry_t;

#define OCT_SG_ENTRY_SIZE    (sizeof(octeon_sg_entry_t))

static inline void
CAVIUM_ADD_SG_SIZE(octeon_sg_entry_t * sg_entry, uint16_t size, int pos)
{
#if  __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
	sg_entry->u.size[pos] = size;
#else
	sg_entry->u.size[3 - pos] = size;
#endif
}

static inline uint16_t CAVIUM_GET_SG_SIZE(octeon_sg_entry_t * sg_entry, int pos)
{
#if  __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
	return sg_entry->u.size[pos];
#else
	return sg_entry->u.size[3 - pos];
#endif
}

/*------------------------- End Scatter/Gather ---------------------------*/

/** Octeon core address range summary. */
typedef struct {
	uint64_t start;
		      /**< Range starts at this address. */
	uint64_t end; /**< Range ends at this address. */
} oct_range_val_t;

#define OCT_RANGE_VAL_SIZE     (sizeof(oct_range_val_t))

/** Response format for a CORE_MEM_MAP instruction.
    The core presents the address ranges to be mapped to PCI
    BAR1 in this structure. */
typedef struct {

	uint64_t range_count;
			    /**< Number of distinct Core addr ranges to map */
	union {
		oct_range_val_t *ranges;
				 /**< Address ranges. */
		uint64_t u64;
	} u;
} oct_dev_range_t;

#define  OCT_DEV_RANGE_SIZE    (sizeof(oct_dev_range_t))

/** Structure used by host driver to pass PCI address map of all Octeon
	devices. For each octeon device, one instance of this structure is used. */
typedef struct {

	/** Device Id of Octeon device to which this map belongs. */
	uint64_t octeon_id;

	/** BAR0 PCI mapped address for this Octeon device. */
	uint64_t bar0_pci_addr;

	/** BAR1 PCI mapped address for this Octeon device. */
	uint64_t bar1_pci_addr;

} cn56xx_pci_map_t;

/** Structure used by host driver to send identifying information to each Octeon
	device. used in endpoint-communication. */
typedef struct {

	/** This Octeon's device id. */
	uint8_t my_device_id;

	/** Total number of Octeon devices in the system. */
	uint8_t dev_count;

	/** Swap mode to be used when sending instruction to another endpoint. */
	uint8_t swap_mode;

	uint8_t reserved[5];

} cn56xx_pci_map_hdr_t;

/** Structure used when host driver sets up endpoint-to-endpoint communication
	between multiple CN56XX devices. */
typedef struct {

	cn56xx_pci_map_hdr_t hdr;
	cn56xx_pci_map_t map;

} cn56xx_map_data_t;

#endif

/* $Id: octeon-common.h 141410 2016-06-30 14:37:41Z mchalla $ */
