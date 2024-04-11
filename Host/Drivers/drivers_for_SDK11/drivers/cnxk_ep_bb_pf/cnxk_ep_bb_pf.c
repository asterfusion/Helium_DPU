// SPDX-License-Identifier: GPL-2.0-only
/* Marvell CNXK EP (EndPoint) bbdev PF stub driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>

#define DRV_NAME "cnxk_ep_bb_pf"

#ifndef PCI_VENDOR_ID_CAVIUM
#define PCI_VENDOR_ID_CAVIUM 0x177d
#endif

#define CNXK_EP_BB_PF_DEVICE_ID 0xEF04

static struct pci_device_id cnxk_epbb_pf_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, CNXK_EP_BB_PF_DEVICE_ID) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, cnxk_epbb_pf_table);
MODULE_AUTHOR("Marvell Inc");
MODULE_DESCRIPTION("Marvell CNXK EP bbdev driver");
MODULE_LICENSE("GPL");

static int cnxk_epbb_pf_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct device *dev = &pdev->dev;
	int ret = 0;

	if (num_vfs > 0) {
		ret = pci_enable_sriov(pdev, num_vfs);
		if (!ret)
			ret = num_vfs;
		else
			dev_err(dev, "Failed to enable sriov :0x%x\n", ret);
	} else {
		pci_disable_sriov(pdev);
	}

	return ret;
}

static int cnxk_epbb_pf_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	int ret;

	dev_info(dev, "Found device %x:%x\n", pdev->vendor, pdev->device);

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable otx2 device:0x%x\n", ret);
		goto probe_exit;
	}

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (ret) {
		dev_err(dev, "Failed to set DMA mask on otx2 device:0x%x\n",
			ret);
		goto disable_device;
	}

	pci_set_master(pdev);

	return 0;

disable_device:
	pci_disable_device(pdev);

probe_exit:
	return ret;
}

static void cnxk_epbb_pf_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;

	dev_info(dev, "Removing device %x:%x\n", pdev->vendor, pdev->device);

	pci_disable_sriov(pdev);
	pci_disable_device(pdev);
}

static struct pci_driver cnxk_epbb_pf_driver = {
	.name            = DRV_NAME,
	.id_table        = cnxk_epbb_pf_table,
	.probe           = cnxk_epbb_pf_probe,
	.remove          = cnxk_epbb_pf_remove,
	.sriov_configure = cnxk_epbb_pf_sriov_configure
};

static int __init cnxk_epbb_pf_init(void)
{
	int ret;

	pr_info("%s: Loading module\n", __func__);

	ret = pci_register_driver(&cnxk_epbb_pf_driver);

	if (ret < 0)
		pr_err("%s: Failed to register pci driver\n", __func__);

	return ret;
}

static void __exit cnxk_epbb_pf_exit(void)
{
	pci_unregister_driver(&cnxk_epbb_pf_driver);
	pr_info("%s: Removed module\n", __func__);
}

module_init(cnxk_epbb_pf_init);
module_exit(cnxk_epbb_pf_exit);
