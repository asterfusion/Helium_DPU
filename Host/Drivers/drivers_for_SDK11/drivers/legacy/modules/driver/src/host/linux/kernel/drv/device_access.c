/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/string.h>

#include "facility.h"
#include "device_access.h"
#include "octeon_device.h"

//mv_facility_conf_t rpc_facility_conf;
//mv_facility_conf_t nwa_facility_conf;
extern octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];
static bool init_done = false;
static int facility_instance_cnt;

#define UNUSED  __attribute__((unused))

int mv_get_facility_instance_count(char *name)
{
	/* For now return the instance count for any name */
	return facility_instance_cnt;
};
EXPORT_SYMBOL(mv_get_facility_instance_count);

int mv_get_multi_facility_handle(int instance, char *name)
{
	int type, handle;

	if (instance >= facility_instance_cnt)
		return -ENOENT;

	if (strcmp(name, MV_FACILITY_NAME_RPC) &&
	    strcmp(name, MV_FACILITY_NAME_NETWORK_AGENT))
		return -ENOENT;

	if (!init_done)
		return -EAGAIN;

	if (!strcmp(name, MV_FACILITY_NAME_RPC))
		type = MV_FACILITY_RPC;
	else
		type = MV_FACILITY_NW_AGENT;

	handle = (uint8_t)(octeon_device[instance]->facility_conf[type].type) & 0xf;
	handle |= (uint8_t)(octeon_device[instance]->octeon_id) << 4;

	return handle;
}
EXPORT_SYMBOL(mv_get_multi_facility_handle);

int mv_get_facility_handle(char *name)
{
	int type;

	if (strcmp(name, MV_FACILITY_NAME_RPC) &&
	    strcmp(name, MV_FACILITY_NAME_NETWORK_AGENT))
		return -ENOENT;

	if (!init_done)
		return -EAGAIN;

	if (!strcmp(name, MV_FACILITY_NAME_RPC))
		type = MV_FACILITY_RPC;
	else
		type = MV_FACILITY_NW_AGENT;

	return (octeon_device[0]->facility_conf[type].type);
}
EXPORT_SYMBOL(mv_get_facility_handle);

int mv_get_bar_mem_map(int handle, mv_bar_map_t *bar_map)
{
	int inst, type;
	mv_facility_conf_t *conf;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);
	if (type >= MV_FACILITY_COUNT)
		return -ENOENT;

	conf = &octeon_device[inst]->facility_conf[type];

	bar_map->addr.host_addr = conf->memmap.host_addr;
	bar_map->memsize = conf->memsize;

	return 0;
}
EXPORT_SYMBOL(mv_get_bar_mem_map);

int mv_pci_get_dma_dev_count(int handle)
{
	return 1;
}

int mv_pci_get_dma_dev(int handle, int index, struct device **dev)
{
	int inst, type;
	mv_facility_conf_t *conf;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (type == MV_FACILITY_RPC) {
		conf = &octeon_device[inst]->facility_conf[type];
		*dev = conf->dma_dev.host_ep_dev;
	} else {
		return -ENOENT;
	}

	return 0;
}
EXPORT_SYMBOL(mv_pci_get_dma_dev);

int mv_get_num_dbell(int handle, enum mv_target target, uint32_t *num_dbells)
{
	int inst, type;
	mv_facility_conf_t *conf;

	inst = FACILITY_INSTANCE(handle);
	type = FACILITY_TYPE(handle);

	if (type == MV_FACILITY_RPC && target == MV_TARGET_EP) {
		conf = &octeon_device[inst]->facility_conf[type];
		*num_dbells = conf->num_h2t_dbells;
	} else {
		return -ENOENT;
	}

	return 0;
}
EXPORT_SYMBOL(mv_get_num_dbell);

int mv_request_dbell_irq(
	int handle UNUSED,
	uint32_t dbell UNUSED,
	irq_handler_t handler UNUSED,
	void *arg UNUSED,
	const struct cpumask *cpumask UNUSED)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL(mv_request_dbell_irq);

int mv_dbell_enable(
	int handle UNUSED,
	uint32_t dbell UNUSED)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL(mv_dbell_enable);

int mv_dbell_disable(
	int handle UNUSED,
	uint32_t dbell UNUSED)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL(mv_dbell_disable);

int mv_dbell_disable_nosync(
	int handle UNUSED,
	uint32_t dbell UNUSED)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL(mv_dbell_disable_nosync);

int mv_free_dbell_irq(
	int handle UNUSED,
	uint32_t dbell UNUSED,
	void *arg UNUSED)
{
	return -ENOTSUPP;
}
EXPORT_SYMBOL(mv_free_dbell_irq);

int mv_send_dbell(int handle, uint32_t dbell)
{
	return mv_send_facility_dbell(handle, dbell);
}
EXPORT_SYMBOL(mv_send_dbell);

int host_device_access_init(int id)
{
	mv_facility_conf_t *conf;

	conf = &octeon_device[id]->facility_conf[MV_FACILITY_RPC];
	printk("	%s configuration\n"
		"Type = %d, Host Addr = 0x%llx Memsize = 0x%x\n"
		 "Doorbell_count = %d\n",
		 conf->name,
		 conf->type,
		 (u64)conf->memmap.host_addr,
		 conf->memsize,
		 conf->num_h2t_dbells);

	conf = &octeon_device[id]->facility_conf[MV_FACILITY_NW_AGENT];
	printk("	%s configuration\n"
		"Type = %d, Host Addr = 0x%llx Memsize = 0x%x\n"
		 "Doorbell_count = %d\n",
		 conf->name,
		 conf->type,
		 (u64)conf->memmap.host_addr,
		 conf->memsize,
		 conf->num_h2t_dbells);
	init_done = true;
	facility_instance_cnt++;

	return 0;
}
