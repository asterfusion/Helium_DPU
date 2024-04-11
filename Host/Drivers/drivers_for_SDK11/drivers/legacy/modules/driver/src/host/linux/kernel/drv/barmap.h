/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef _BARMAP_H_
#define _BARMAP_H_

#include "facility.h"

#define NPU_BARMAP_VERSION_MAJOR 0
#define NPU_BARMAP_VERSION_MINOR 2

#define NPU_BARMAP_VERSION \
	((NPU_BARMAP_VERSION_MAJOR << 16) | NPU_BARMAP_VERSION_MINOR)

/* Facility mapping in BAR1 */
struct facility_bar_map
{
	/* Offset of facility memory region in BAR1 */
        uint32_t offset;

	/* Size of faciltiy memory region in BAR1 */
        uint32_t size;

	/* First SPI interrupt assigned to facility on host to
	 * send interrupt to target
	 */
        uint32_t h2t_dbell_start;

	/* Number of SPI interrupts assigned for facility
	 * starting from h2t_dbell_start
	 */
        uint32_t h2t_dbell_count;
};


struct npu_bar_map {
	uint32_t version;		// version of the memory map structure

	struct facility_bar_map facility_map[MV_FACILITY_COUNT];
	/* offset in BAR1 where GICD CSR space is mapped */
	uint32_t gicd_offset;
	uint8_t pem_num;
};

/* BAR1 provides 64MB of OcteonTX memory for Host access in EndPoint mode.
 * Use second half of this 64MB for various rings used to facilitate
 * communication between modules/entities on NPU and Host.
 *
 * First 32MB can be used for pci-console and other purposes.
 */
#define MB (1024 * 1024)
#define NPU_BARMAP_FIREWALL_OFFSET (32 * MB)

#define NPU_BARMAP_CTRL_OFFSET (NPU_BARMAP_FIREWALL_OFFSET)
#define NPU_BARMAP_CTRL_SIZE   (1 * MB)

#define NPU_BARMAP_MGMT_NETDEV_OFFSET \
	(NPU_BARMAP_CTRL_OFFSET + NPU_BARMAP_CTRL_SIZE)
#define NPU_BARMAP_MGMT_NETDEV_SIZE   (1 * MB)

#define NPU_BARMAP_NW_AGENT_OFFSET \
	(NPU_BARMAP_MGMT_NETDEV_OFFSET + NPU_BARMAP_MGMT_NETDEV_SIZE)
#define NPU_BARMAP_NW_AGENT_SIZE (1 * MB)

#define NPU_BARMAP_RPC_OFFSET \
	(NPU_BARMAP_NW_AGENT_OFFSET + NPU_BARMAP_NW_AGENT_SIZE)
#define NPU_BARMAP_RPC_SIZE (1 * MB)

#define NPU_BARMAP_FIREWALL_SIZE \
	(NPU_BARMAP_CTRL_SIZE + NPU_BARMAP_MGMT_NETDEV_SIZE + \
	 NPU_BARMAP_NW_AGENT_SIZE + NPU_BARMAP_RPC_SIZE)

#define NPU_BARMAP_FIREWALL_FIRST_ENTRY 8
/* entry 8 to entry 14; entry-15 is reserved to map GICD space 
 * for host to interrupt NPU
 */
#define NPU_BARMAP_FIREWALL_MAX_ENTRY 7
#define CN83XX_PEM_BAR1_INDEX_MAX_ENTRIES 16
#define NPU_BARMAP_ENTRY_SIZE (4 * MB)
#define NPU_BARMAP_MAX_SIZE \
	(NPU_BARMAP_ENTRY_SIZE * NPU_BARMAP_FIREWALL_MAX_ENTRY)

/* Use last entry of BAR1_INDEX for host to trigger interrupt to NPU */
#define GICD_SETSPI_NSR  0x40
#define NPU_BARMAP_SPI_ENTRY  15
#define NPU_BARMAP_SPI_OFFSET \
	((NPU_BARMAP_SPI_ENTRY * NPU_BARMAP_ENTRY_SIZE) + \
	 GICD_SETSPI_NSR)
#define NPU_GICD_BASE          0x801000000000

#define NPU_FACILITY_CONTROL_IRQ_IDX 0
#define NPU_FACILITY_MGMT_NETDEV_IRQ_IDX \
	(NPU_FACILITY_CONTROL_IRQ_IDX + MV_FACILITY_CONTROL_IRQ_CNT)
#define NPU_FACILITY_NW_AGENT_IRQ_IDX \
	(NPU_FACILITY_MGMT_NETDEV_IRQ_IDX + MV_FACILITY_MGMT_NETDEV_IRQ_CNT)
#define NPU_FACILITY_RPC_IRQ_IDX \
	(NPU_FACILITY_NW_AGENT_IRQ_IDX + MV_FACILITY_NW_AGENT_IRQ_CNT)
#define NPU_FACILITY_IRQ_CNT \
	(NPU_FACILITY_RPC_IRQ_IDX + MV_FACILITY_RPC_IRQ_CNT)

#define NPU_SPI_IRQ_START 32

static inline int npu_bar_map_init(struct npu_bar_map *map,
				   int first_irq, int irq_count)
{
	struct facility_bar_map *facility_map;

	/* Translate SPI IRQ index to global IRQ index */
	first_irq = NPU_SPI_IRQ_START + first_irq;
	if (map == NULL) {
		printk("%s: Error; NULL pointer\n", __func__);
		return -1;
	}

	/* Validate sufficient IRQ's are provided by FDT */
	if (irq_count < NPU_FACILITY_IRQ_CNT) {
		printk("Error: Insufficient number of IRQs in FDT\n");
		printk("Required IRQ count=%d; IRQs provided by FDT=%d\n",
		       NPU_FACILITY_IRQ_CNT, irq_count);
		return -1;
	}
	map->version =  NPU_BARMAP_VERSION;

	facility_map = &map->facility_map[MV_FACILITY_CONTROL];
	facility_map->offset = NPU_BARMAP_CTRL_OFFSET;
	facility_map->size = NPU_BARMAP_CTRL_SIZE;
	facility_map->h2t_dbell_start =
		first_irq + NPU_FACILITY_CONTROL_IRQ_IDX;
	facility_map->h2t_dbell_count = MV_FACILITY_CONTROL_IRQ_CNT;

	facility_map = &map->facility_map[MV_FACILITY_MGMT_NETDEV];
	facility_map->offset = NPU_BARMAP_MGMT_NETDEV_OFFSET;
	facility_map->size = NPU_BARMAP_MGMT_NETDEV_SIZE;
	facility_map->h2t_dbell_start =
		first_irq + NPU_FACILITY_MGMT_NETDEV_IRQ_IDX;
	facility_map->h2t_dbell_count = MV_FACILITY_MGMT_NETDEV_IRQ_CNT;

	facility_map = &map->facility_map[MV_FACILITY_NW_AGENT];
	facility_map->offset = NPU_BARMAP_NW_AGENT_OFFSET;
	facility_map->size = NPU_BARMAP_NW_AGENT_SIZE;
	facility_map->h2t_dbell_start =
		first_irq + NPU_FACILITY_NW_AGENT_IRQ_IDX;
	facility_map->h2t_dbell_count = MV_FACILITY_NW_AGENT_IRQ_CNT;

	facility_map = &map->facility_map[MV_FACILITY_RPC];
	facility_map->offset = NPU_BARMAP_RPC_OFFSET;
	facility_map->size = NPU_BARMAP_RPC_SIZE;
	facility_map->h2t_dbell_start =
		first_irq + NPU_FACILITY_RPC_IRQ_IDX;
	facility_map->h2t_dbell_count = MV_FACILITY_RPC_IRQ_CNT;

	map->gicd_offset = NPU_BARMAP_SPI_OFFSET;
	return 0;
}

static inline void npu_barmap_dump(struct npu_bar_map *map)
{
	struct facility_bar_map *facility_map;

	if (map == NULL) {
		printk("%s: Error; NULL pointer\n", __func__);
		return;
	}

	printk("Version: major=%d minor=%d\n",
	       map->version >> 16, map->version & 0xffff);

	facility_map = &map->facility_map[MV_FACILITY_CONTROL];
	printk("Control: Offset=%x, size=%x, first_db=%d db_count=%d\n",
	       facility_map->offset, facility_map->size,
	       facility_map->h2t_dbell_start, facility_map->h2t_dbell_count);

	facility_map = &map->facility_map[MV_FACILITY_MGMT_NETDEV];
	printk("Mgmt-netdev: Offset=%x, size=%x, first_db=%d db_count=%d\n",
	       facility_map->offset, facility_map->size,
	       facility_map->h2t_dbell_start, facility_map->h2t_dbell_count);

	facility_map = &map->facility_map[MV_FACILITY_NW_AGENT];
	printk("Network-Agent: Offset=%x, size=%x, first_db=%d db_count=%d\n",
	       facility_map->offset, facility_map->size,
	       facility_map->h2t_dbell_start, facility_map->h2t_dbell_count);

	facility_map = &map->facility_map[MV_FACILITY_RPC];
	printk("RPC: Offset=%x, size=%x, first_db=%d db_count=%d\n",
	       facility_map->offset, facility_map->size,
	       facility_map->h2t_dbell_start, facility_map->h2t_dbell_count);

	printk("GICD offset in BAR = %x\n", map->gicd_offset);
	printk("PEM number: %u\n", map->pem_num);
}
#endif /* _BARMAP_H_ */
