/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "octeon_device.h"
#include "octeon_macros.h"
#include "octeon_mem_ops.h"

#define MEMOPS_IDX   MAX_BAR1_MAP_INDEX

uint32_t
octeon_map_device_range(octeon_device_t * oct, uint64_t start, uint64_t end)
{
	uint32_t i, maps_reqrd = 0, old_map_count;

	cavium_print(PRINT_FLOW, "--------octeon_map_device_range-------\n");
	if (oct->map_count == MAX_OCTEON_MAPS) {
		cavium_error("OCTEON: No space available, map count: %d\n",
			     oct->map_count);
		return INVALID_MAP;
	}

	cavium_print(PRINT_DEBUG, "Size required is 0x%016llx\n",
		     CVM_CAST64(end - start));
	if (start > end) {
		cavium_error
		    ("OCTEON: Invalid address range, start: 0x%llx end: 0x%llx\n",
		     CVM_CAST64(start), CVM_CAST64(end));
		return INVALID_MAP;
	}

	/* start -1 otherwise Ranges with exact 4M multiples end up
	   using 2 maps */
	maps_reqrd = (uint32_t) (((end - start) - 1) >> 22) + 1;
	cavium_print(PRINT_DEBUG, "Maps required is %d\n", maps_reqrd);

	if ((oct->map_count + maps_reqrd) > MAX_OCTEON_MAPS) {
		cavium_error
		    ("OCTEON: current map count: %d, new maps_reqrd: %d will exceed max allowed: %d\n",
		     oct->map_count, maps_reqrd, MAX_OCTEON_MAPS);
		return INVALID_MAP;
	}

	old_map_count = oct->map_count;

	for (i = old_map_count; i < (old_map_count + maps_reqrd); i++) {
		oct->fn_list.bar1_idx_setup(oct, start, i, 1);
		oct->range_table[i].mapped_addr =
		    (uint8_t *) oct->mmio[1].hw_addr +
		    ((old_map_count + i) << 22);
		oct->range_table[i].core_addr = start;
		cavium_print(PRINT_DEBUG,
			     "map_table[%d] mapped_addr: 0x%p core_addr: 0x%016llx\n",
			     i, oct->range_table[i].mapped_addr,
			     CVM_CAST64(oct->range_table[i].core_addr));

		start += (1 << 22);
	}
	oct->map_count += maps_reqrd;

	return old_map_count;
}

uint32_t octeon_get_mapped_idx(octeon_device_t * oct, uint64_t core_addr)
{
	uint32_t i;

	for (i = 0; i < oct->map_count; i++) {
		if ((oct->range_table[i].core_addr <= core_addr)
		    && (core_addr <
			(oct->range_table[i].core_addr + (1 << 22))))
			return i;
	}

	return INVALID_MAP;
}

void *octeon_get_mapped_addr(octeon_device_t * oct, uint64_t core_addr)
{
	uint32_t range_idx;

	range_idx = octeon_get_mapped_idx(oct, core_addr);
// *INDENT-OFF*
	if(range_idx == INVALID_MAP) {
		cavium_error(" %s Core address 0x%llx is unmapped\n",
		              __CVM_FUNCTION__, CVM_CAST64(core_addr));
		return NULL;
	}

	return  (void *) ((unsigned long)oct->range_table[range_idx].mapped_addr
          + (unsigned long)(core_addr - oct->range_table[range_idx].core_addr));
// *INDENT-ON*
}

#if 0

uint64_t octeon_read_device_mem64(octeon_device_t * oct, uint64_t core_addr)
{
	uint64_t *pciaddr = (uint64_t *) octeon_get_mapped_addr(oct, core_addr);
	if (pciaddr)
		return ENDIAN_SWAP_8_BYTE(OCTEON_READ64(pciaddr));

	return -EFAULT;
}

int
octeon_write_device_mem64(octeon_device_t * oct,
			  uint64_t core_addr, uint64_t val)
{
	uint64_t *pciaddr = (uint64_t *) octeon_get_mapped_addr(oct, core_addr);
	if (pciaddr) {
		OCTEON_WRITE64(pciaddr, ENDIAN_SWAP_8_BYTE(val));
		return 0;
	}

	return -EFAULT;
}

#endif

static inline void
octeon_toggle_bar1_swapmode(octeon_device_t * oct UNUSED, int idx UNUSED)
{
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
	uint32_t mask;

	mask = oct->fn_list.bar1_idx_read(oct, idx);
	mask = (mask & 0x2) ? (mask & ~2) : (mask | 2);
	oct->fn_list.bar1_idx_write(oct, idx, mask);
#endif
}

static void
octeon_pci_fastwrite(octeon_device_t * oct, uint8_t * mapped_addr,
		     uint8_t * hostbuf, int len)
{
	while (((unsigned long)mapped_addr) & 7) {
		OCTEON_WRITE8(mapped_addr++, *(hostbuf++));
		len--;
	}

	octeon_toggle_bar1_swapmode(oct, MEMOPS_IDX);

	while (len >= 8) {
		OCTEON_WRITE64(mapped_addr, *((uint64_t *) hostbuf));
		mapped_addr += 8;
		hostbuf += 8;
		len -= 8;
	}

	octeon_toggle_bar1_swapmode(oct, MEMOPS_IDX);

	while (len--) {
		OCTEON_WRITE8(mapped_addr++, *(hostbuf++));
	}
}

static void
octeon_pci_fastread(octeon_device_t * oct, uint8_t * mapped_addr,
		    uint8_t * hostbuf, int len)
{
	while (((unsigned long)mapped_addr) & 7) {
		*(hostbuf++) = OCTEON_READ8(mapped_addr++);
		len--;
	}

	octeon_toggle_bar1_swapmode(oct, MEMOPS_IDX);

	while (len >= 8) {
		*((uint64_t *) hostbuf) = OCTEON_READ64(mapped_addr);
		mapped_addr += 8;
		hostbuf += 8;
		len -= 8;
	}

	octeon_toggle_bar1_swapmode(oct, MEMOPS_IDX);

	while (len--) {
		*(hostbuf++) = OCTEON_READ8(mapped_addr++);
	}
}

/* Core mem read/write with temporary bar1 settings. */
/* op = 1 to read, op = 0 to write. */
static void
__octeon_pci_rw_core_mem(octeon_device_t * oct,
			 uint64_t addr,
			 uint8_t * hostbuf, uint32_t len, uint32_t op)
{
	uint32_t copy_len = 0, index_reg_val = 0;
	unsigned long flags;
	uint8_t *mapped_addr;

	cavium_spin_lock_irqsave(&oct->oct_lock, flags);

	/* Save the original index reg value. */
	index_reg_val = oct->fn_list.bar1_idx_read(oct, MEMOPS_IDX);

	cavium_print(PRINT_DEBUG,
		     "%s Transfer %llu bytes %s core addr %llx %s host buffer @ %p\n",
		     __CVM_FUNCTION__, CVM_CAST64(len), (op) ? "from" : "to",
		     CVM_CAST64(addr), (op) ? "to" : "from", hostbuf);

	do {
		oct->fn_list.bar1_idx_setup(oct, addr, MEMOPS_IDX, 1);
		mapped_addr = (uint8_t *) oct->mmio[1].hw_addr
		    + (MEMOPS_IDX << 22) + (addr & 0x3fffff);

		/* If operation crosses a 4MB boundary, split the transfer at the 4MB
		   boundary. */
		if (((addr + len - 1) & ~(0x3fffff)) != (addr & ~(0x3fffff))) {
			copy_len = ((addr & ~(0x3fffff)) + (1 << 22)) - addr;
		} else {
			copy_len = len;
		}

		cavium_print(PRINT_DEBUG,
			     "hostbuf: %p corebuf: %llx copy_len: %d\n",
			     hostbuf, CVM_CAST64(addr), copy_len);

		if (op) {	/* read from core */
			octeon_pci_fastread(oct, mapped_addr, hostbuf,
					    copy_len);
		} else {
			octeon_pci_fastwrite(oct, mapped_addr, hostbuf,
					     copy_len);
		}

		len -= copy_len;
		addr += copy_len;
		hostbuf += copy_len;

	} while (len);

	oct->fn_list.bar1_idx_write(oct, MEMOPS_IDX, index_reg_val);

	cavium_spin_unlock_irqrestore(&oct->oct_lock, flags);
}

void
octeon_pci_read_core_mem(octeon_device_t * oct,
			 uint64_t coreaddr,
			 uint8_t * buf, uint32_t len, int swap UNUSED)
{
	/* swap is a relic and is ignored. */
	__octeon_pci_rw_core_mem(oct, coreaddr, buf, len, 1);
}

void
octeon_pci_write_core_mem(octeon_device_t * oct,
			  uint64_t coreaddr,
			  uint8_t * buf, uint32_t len, int swap UNUSED)
{
	/* swap is a relic and is ignored. */
	__octeon_pci_rw_core_mem(oct, coreaddr, buf, len, 0);
}

/* The following are API's exported to other modules. */

void
octeon_write_core_memory(uint32_t octeon_id,
			 uint64_t addr, void *buf, uint32_t len)
{
	octeon_device_t *oct = get_octeon_device(octeon_id);
	if (oct)
		__octeon_pci_rw_core_mem(oct, addr, buf, len, 0);
}

void
octeon_read_core_memory(uint32_t octeon_id,
			uint64_t addr, void *buf, uint32_t len)
{
	octeon_device_t *oct = get_octeon_device(octeon_id);
	if (oct)
		__octeon_pci_rw_core_mem(oct, addr, buf, len, 1);
}

/* $Id: octeon_mem_ops.c 143739 2016-08-18 12:24:33Z mchalla $ */
