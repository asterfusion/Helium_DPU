/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

//#include <string.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "barmap.h"
#include "facility.h"
#include "octeon_device.h"

extern octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];

static int facility_conf_init_done[MAX_OCTEON_DEVICES];

void mv_facility_conf_init(octeon_device_t *oct)
{
	void *bar1_addr;
	struct device *dev = &oct->pci_dev->dev;
	struct facility_bar_map *facility_map;

	memset(&oct->facility_conf, 0,
	       sizeof(mv_facility_conf_t) * MV_FACILITY_COUNT);

	if (OCTEON_CN9PLUS_PF(oct->chip_id))
		bar1_addr = oct->mmio[2].hw_addr;
	else
		bar1_addr = oct->mmio[1].hw_addr;
	/* TODO: set name for all facility names */
	facility_map = &oct->npu_memmap_info.facility_map[MV_FACILITY_CONTROL];
	oct->facility_conf[MV_FACILITY_CONTROL].type = MV_FACILITY_CONTROL;
	oct->facility_conf[MV_FACILITY_CONTROL].dma_dev.host_ep_dev = dev;
	oct->facility_conf[MV_FACILITY_CONTROL].memmap.host_addr =
				bar1_addr + facility_map->offset;
	oct->facility_conf[MV_FACILITY_CONTROL].memsize = facility_map->size;
	oct->facility_conf[MV_FACILITY_CONTROL].num_h2t_dbells =
				facility_map->h2t_dbell_count;
	oct->facility_conf[MV_FACILITY_CONTROL].num_t2h_dbells = 0;
	strncpy(oct->facility_conf[MV_FACILITY_CONTROL].name,
		MV_FACILITY_NAME_CONTROL, FACILITY_NAME_LEN-1);

	facility_map = &oct->npu_memmap_info.facility_map[MV_FACILITY_MGMT_NETDEV];
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].type = MV_FACILITY_MGMT_NETDEV;
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].dma_dev.host_ep_dev = dev;
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].memmap.host_addr =
				bar1_addr + facility_map->offset;
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].memsize = facility_map->size;
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].num_h2t_dbells =
				facility_map->h2t_dbell_count;
	oct->facility_conf[MV_FACILITY_MGMT_NETDEV].num_t2h_dbells = 0;
	strncpy(oct->facility_conf[MV_FACILITY_MGMT_NETDEV].name,
		MV_FACILITY_NAME_MGMT_NETDEV, FACILITY_NAME_LEN-1);

	facility_map = &oct->npu_memmap_info.facility_map[MV_FACILITY_NW_AGENT];
	oct->facility_conf[MV_FACILITY_NW_AGENT].type = MV_FACILITY_NW_AGENT;
	oct->facility_conf[MV_FACILITY_NW_AGENT].dma_dev.host_ep_dev = dev;
	oct->facility_conf[MV_FACILITY_NW_AGENT].memmap.host_addr =
				bar1_addr + facility_map->offset;
	oct->facility_conf[MV_FACILITY_NW_AGENT].memsize = facility_map->size;
	oct->facility_conf[MV_FACILITY_NW_AGENT].num_h2t_dbells =
				facility_map->h2t_dbell_count;
	oct->facility_conf[MV_FACILITY_NW_AGENT].num_t2h_dbells = 0;
	strncpy(oct->facility_conf[MV_FACILITY_NW_AGENT].name,
		MV_FACILITY_NAME_NETWORK_AGENT, FACILITY_NAME_LEN-1);

	facility_map = &oct->npu_memmap_info.facility_map[MV_FACILITY_RPC];
	oct->facility_conf[MV_FACILITY_RPC].type = MV_FACILITY_RPC;
	oct->facility_conf[MV_FACILITY_RPC].dma_dev.host_ep_dev = dev;
	oct->facility_conf[MV_FACILITY_RPC].memmap.host_addr =
				bar1_addr + facility_map->offset;
	oct->facility_conf[MV_FACILITY_RPC].memsize = facility_map->size;
	oct->facility_conf[MV_FACILITY_RPC].num_h2t_dbells =
				facility_map->h2t_dbell_count;
	oct->facility_conf[MV_FACILITY_RPC].num_t2h_dbells = 0;
	strncpy(oct->facility_conf[MV_FACILITY_RPC].name,
		MV_FACILITY_NAME_RPC, FACILITY_NAME_LEN-1);

	facility_conf_init_done[oct->octeon_id] = 1;
}

/* returns facility configuration structure filled up */
int mv_get_facility_conf(int handle, mv_facility_conf_t *conf)
{
	int inst, type;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (!is_facility_valid(type)) {
		printk("%s: Invalid facility type %d\n", __func__, type);
		return -ENOENT;
	}

	/* Inform caller to try again, if facility conf is not initialized */
	if (!facility_conf_init_done[inst])
		return -EAGAIN;

	memcpy(conf, &octeon_device[inst]->facility_conf[type], sizeof(mv_facility_conf_t));
	return 0;
}
EXPORT_SYMBOL_GPL(mv_get_facility_conf);

int mv_facility_request_dbell_irq(int type, int dbell,
				  irq_handler_t handler, void *arg)
{
	printk("%s: IRQ's not supported\n", __func__);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(mv_facility_request_dbell_irq);

void mv_facility_free_dbell_irq(int type, int dbell, void *arg)
{
	printk("%s: IRQ's not supported\n", __func__);
}
EXPORT_SYMBOL_GPL(mv_facility_free_dbell_irq);

int mv_facility_register_event_callback(int handle,
					mv_facility_event_cb handler,
					void *cb_arg)
{
	int inst, type;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (!is_facility_valid(type)) {
		printk("%s: Invalid facility type %d\n", __func__, type);
		return -EINVAL;
	}

	octeon_device[inst]->facility_handler[type].cb = handler;
	octeon_device[inst]->facility_handler[type].cb_arg = cb_arg;
	printk("Registered event handler for facility type %d\n", type);

	return 0;
}
EXPORT_SYMBOL_GPL(mv_facility_register_event_callback);

void mv_facility_unregister_event_callback(int handle)
{
	int inst, type;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (!is_facility_valid(type)) {
		printk("%s: Invalid facility type %d\n", __func__, type);
		return;
	}

	octeon_device[inst]->facility_handler[type].cb = NULL;
	octeon_device[inst]->facility_handler[type].cb_arg = NULL;
	printk("Unregistered event handler for facility type %d\n", type);
}
EXPORT_SYMBOL_GPL(mv_facility_unregister_event_callback);

int mv_send_facility_dbell(int handle, int dbell)
{
	struct facility_bar_map *facility_map;
	int irq;
	int inst, type;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (!is_facility_valid(type)) {
		printk("%s: Invalid facility type %d\n", __func__, type);
		return -EINVAL;
	}

	facility_map = &octeon_device[inst]->npu_memmap_info.facility_map[type];

	irq = dbell + facility_map->h2t_dbell_start;

	/* check if dbell falls in range */
	if (irq >= facility_map->h2t_dbell_start &&
	    irq < (facility_map->h2t_dbell_start +
		     facility_map->h2t_dbell_count)) {

		if (OCTEON_CN9PLUS_PF(octeon_device[0]->chip_id))
			*(volatile uint32_t *)(octeon_device[inst]->mmio[2].hw_addr +
			 	octeon_device[inst]->npu_memmap_info.gicd_offset) = irq;
		else
			*(volatile uint32_t *)(octeon_device[inst]->mmio[1].hw_addr +
			 	octeon_device[inst]->npu_memmap_info.gicd_offset) = irq;
	} else {
		return -EINVAL;
	}

	/* printk("%s: invoked for type-%d, dbell-%d\n", __func__, type, dbell); */
	return 0;
}
EXPORT_SYMBOL_GPL(mv_send_facility_dbell);

int mv_send_facility_event(int type)
{
	printk("%s: invoked for type-%d\n", __func__, type);
	return 0;
}
EXPORT_SYMBOL_GPL(mv_send_facility_event);

void mv_facility_irq_handler(octeon_device_t *oct, uint64_t event_word)
{
	int i;

	for (i = 0; i < MV_FACILITY_COUNT; i++) {
		if ((event_word & (1UL << i)) && oct->facility_handler[i].cb)
			oct->facility_handler[i].cb(oct->facility_handler[i].cb_arg);
	}
}
