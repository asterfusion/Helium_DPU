// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 PCIe host controller
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/bitfield.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/of_address.h>
#include <linux/of_pci.h>
#include <linux/pci.h>
#include <linux/pci-acpi.h>
#include <linux/pci-ecam.h>
#include <linux/platform_device.h>

#if defined(CONFIG_PCI_HOST_OCTEONTX2_PEM)

/* Bridge config space reads/writes done using
 * these registers.
 */
#define PEM_CFG_WR	0x18
#define PEM_CFG_RD	0x20

struct octeontx2_pem_pci {
	u32		ea_entry[3];
	void __iomem	*pem_reg_base;
};

static int octeontx2_pem_bridge_read(struct pci_bus *bus, unsigned int devfn,
				     int where, int size, u32 *val)
{
	struct pci_config_window *cfg = bus->sysdata;
	struct octeontx2_pem_pci *pem_pci;
	u64 read_val;

	if (devfn != 0 || where >= 2048) {
		*val = ~0;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	pem_pci = (struct octeontx2_pem_pci *)cfg->priv;

	/*
	 * 32-bit accesses only.  Write the address to the low order
	 * bits of PEM_CFG_RD, then trigger the read by reading back.
	 * The config data lands in the upper 32-bits of PEM_CFG_RD.
	 */
	read_val = where & ~3ull;
	writeq(read_val, pem_pci->pem_reg_base + PEM_CFG_RD);
	read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
	read_val >>= 32;

	/* HW reset value at few config space locations are
	 * garbage, fix them.
	 */
	switch (where & ~3) {
	case 0x00: /* DevID & VenID */
		read_val = 0xA02D177D;
		break;
	case 0x04:
		read_val = 0x00100006;
		break;
	case 0x08:
		read_val = 0x06040100;
		break;
	case 0x0c:
		read_val = 0x00010000;
		break;
	case 0x18:
		read_val = 0x00010100;
		break;
	case 0x40:
		read_val &= 0xffff00ff;
		read_val |= 0x00005000; /* In RC mode, point to EA capability */
		break;
	case 0x5c: /* EA_ENTRY2 */
		read_val = pem_pci->ea_entry[0];
		break;
	case 0x60: /* EA_ENTRY3 */
		read_val = pem_pci->ea_entry[1];
		break;
	case 0x64: /* EA_ENTRY4 */
		read_val = pem_pci->ea_entry[2];
		break;
	case 0x70: /* Express Cap */
		/* HW reset value is '0', set PME interrupt vector to 1 */
		if (!(read_val & (0x1f << 25)))
			read_val |= (1u << 25);
		break;
	default:
		break;
	}
	read_val >>= (8 * (where & 3));
	switch (size) {
	case 1:
		read_val &= 0xff;
		break;
	case 2:
		read_val &= 0xffff;
		break;
	default:
		break;
	}
	*val = read_val;
	return PCIBIOS_SUCCESSFUL;
}

static int octeontx2_pem_config_read(struct pci_bus *bus, unsigned int devfn,
				   int where, int size, u32 *val)
{
	struct pci_config_window *cfg = bus->sysdata;

	if (bus->number < cfg->busr.start ||
	    bus->number > cfg->busr.end)
		return PCIBIOS_DEVICE_NOT_FOUND;

	/*
	 * The first device on the bus is the PEM PCIe bridge.
	 * Special case its config access.
	 */
	if (bus->number == cfg->busr.start)
		return octeontx2_pem_bridge_read(bus, devfn, where, size, val);

	return pci_generic_config_read(bus, devfn, where, size, val);
}

/*
 * Some of the w1c_bits below also include read-only or non-writable
 * reserved bits, this makes the code simpler and is OK as the bits
 * are not affected by writing zeros to them.
 */
static u32 octeontx2_pem_bridge_w1c_bits(u64 where_aligned)
{
	u32 w1c_bits = 0;

	switch (where_aligned) {
	case 0x04: /* Command/Status */
	case 0x1c: /* Base and I/O Limit/Secondary Status */
		w1c_bits = 0xff000000;
		break;
	case 0x44: /* Power Management Control and Status */
		w1c_bits = 0xfffffe00;
		break;
	case 0x78: /* Device Control/Device Status */
	case 0x80: /* Link Control/Link Status */
	case 0x88: /* Slot Control/Slot Status */
	case 0x90: /* Root Status */
	case 0xa0: /* Link Control 2 Registers/Link Status 2 */
		w1c_bits = 0xffff0000;
		break;
	case 0x104: /* Uncorrectable Error Status */
	case 0x110: /* Correctable Error Status */
	case 0x130: /* Error Status */
	case 0x180: /* Lane error status */
		w1c_bits = 0xffffffff;
		break;
	default:
		break;
	}
	return w1c_bits;
}

/* Some bits must be written to one so they appear to be read-only. */
static u32 octeontx2_pem_bridge_w1_bits(u64 where_aligned)
{
	u32 w1_bits;

	switch (where_aligned) {
	case 0x1c: /* I/O Base / I/O Limit, Secondary Status */
		/* Force 32-bit I/O addressing. */
		w1_bits = 0x0101;
		break;
	case 0x24: /* Prefetchable Memory Base / Prefetchable Memory Limit */
		/* Force 64-bit addressing */
		w1_bits = 0x00010001;
		break;
	default:
		w1_bits = 0;
		break;
	}
	return w1_bits;
}

static int octeontx2_pem_bridge_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 val)
{
	struct pci_config_window *cfg = bus->sysdata;
	struct octeontx2_pem_pci *pem_pci;
	u64 where_aligned = where & ~3ull;
	u64 write_val, read_val;
	u32 mask = 0;


	if (devfn != 0 || where >= 2048)
		return PCIBIOS_DEVICE_NOT_FOUND;

	pem_pci = (struct octeontx2_pem_pci *)cfg->priv;

	/*
	 * 32-bit accesses only.  If the write is for a size smaller
	 * than 32-bits, we must first read the 32-bit value and merge
	 * in the desired bits and then write the whole 32-bits back
	 * out.
	 */
	switch (size) {
	case 1:
		writeq(where_aligned, pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val >>= 32;
		mask = ~(0xff << (8 * (where & 3)));
		read_val &= mask;
		val = (val & 0xff) << (8 * (where & 3));
		val |= (u32)read_val;
		break;
	case 2:
		writeq(where_aligned, pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val = readq(pem_pci->pem_reg_base + PEM_CFG_RD);
		read_val >>= 32;
		mask = ~(0xffff << (8 * (where & 3)));
		read_val &= mask;
		val = (val & 0xffff) << (8 * (where & 3));
		val |= (u32)read_val;
		break;
	default:
		break;
	}

	/*
	 * By expanding the write width to 32 bits, we may
	 * inadvertently hit some W1C bits that were not intended to
	 * be written.  Calculate the mask that must be applied to the
	 * data to be written to avoid these cases.
	 */
	if (mask) {
		u32 w1c_bits = octeontx2_pem_bridge_w1c_bits(where);

		if (w1c_bits) {
			mask &= w1c_bits;
			val &= ~mask;
		}
	}

	/*
	 * Some bits must be read-only with value of one.  Since the
	 * access method allows these to be cleared if a zero is
	 * written, force them to one before writing.
	 */
	val |= octeontx2_pem_bridge_w1_bits(where_aligned);

	/*
	 * Low order bits are the config address, the high order 32
	 * bits are the data to be written.
	 */
	write_val = (((u64)val) << 32) | where_aligned;
	writeq(write_val, pem_pci->pem_reg_base + PEM_CFG_WR);
	return PCIBIOS_SUCCESSFUL;
}

static int octeontx2_pem_config_write(struct pci_bus *bus, unsigned int devfn,
				    int where, int size, u32 val)
{
	struct pci_config_window *cfg = bus->sysdata;

	if (bus->number < cfg->busr.start ||
	    bus->number > cfg->busr.end)
		return PCIBIOS_DEVICE_NOT_FOUND;
	/*
	 * The first device on the bus is the PEM PCIe bridge.
	 * Special case its config access.
	 */
	if (bus->number == cfg->busr.start)
		return octeontx2_pem_bridge_write(bus, devfn, where, size, val);

	return pci_generic_config_write(bus, devfn, where, size, val);
}

static int octeontx2_pem_init(struct device *dev, struct pci_config_window *cfg,
			    struct resource *res_pem)
{
	struct octeontx2_pem_pci *pem_pci;
	resource_size_t bar4_start;

	pem_pci = devm_kzalloc(dev, sizeof(*pem_pci), GFP_KERNEL);
	if (!pem_pci)
		return -ENOMEM;

	pem_pci->pem_reg_base = devm_ioremap(dev, res_pem->start, 0x10000);
	if (!pem_pci->pem_reg_base)
		return -ENOMEM;

	/*
	 * The MSI-X BAR for the PEM and AER interrupts is located at
	 * a fixed offset from the PEM register base.  Generate a
	 * fragment of the synthesized Enhanced Allocation capability
	 * structure here for the BAR.
	 */
	bar4_start = res_pem->start + 0xf00000000;
	pem_pci->ea_entry[0] = (u32)bar4_start | 2;
	pem_pci->ea_entry[1] = (u32)(res_pem->end - bar4_start) & ~3u;
	pem_pci->ea_entry[2] = (u32)(bar4_start >> 32);

	cfg->priv = pem_pci;
	return 0;
}

static int octeontx2_pem_platform_init(struct pci_config_window *cfg)
{
	struct device *dev = cfg->parent;
	struct platform_device *pdev;
	struct resource *res_pem;

	if (!dev->of_node)
		return -EINVAL;

	pdev = to_platform_device(dev);

	/*
	 * The second register range is the PEM bridge to the PCIe
	 * bus.  It has a different config access method than those
	 * devices behind the bridge.
	 */
	res_pem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res_pem) {
		dev_err(dev, "missing \"reg[1]\"property\n");
		return -EINVAL;
	}

	return octeontx2_pem_init(dev, cfg, res_pem);
}

static struct pci_ecam_ops pci_octeontx2_pem_ops = {
	.bus_shift	= 20,
	.init		= octeontx2_pem_platform_init,
	.pci_ops	= {
		.map_bus	= pci_ecam_map_bus,
		.read		= octeontx2_pem_config_read,
		.write		= octeontx2_pem_config_write,
	}
};

static const struct of_device_id octeontx2_pem_of_match[] = {
	{ 
        .compatible = "marvell,pci-host-octeontx2-pem", 
        .data = &pci_octeontx2_pem_ops,
    },
	{ },
};

static int octeontx2_pem_probe(struct platform_device *pdev)
{
	return pci_host_common_probe(pdev);
}

static struct platform_driver octeontx2_pem_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.of_match_table = octeontx2_pem_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = octeontx2_pem_probe,
};
builtin_platform_driver(octeontx2_pem_driver);

#endif
