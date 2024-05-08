
/*  
 *  hello-1.c - The simplest kernel module.
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/mod_devicetable.h>
#include <linux/pci.h>
#include <linux/version.h>



uint32_t pcidev = 0;
MODULE_LICENSE("GPL");
module_param(pcidev, int, 0);
MODULE_PARM_DESC(pcidev, "Probe the pci device, others will ignore, format: bus<<8|devfn");
#define     OCTEON_VENDOR_ID               0x177D
#define  DEFINE_PCI_DEVICE_TABLE(octeon_pci_table) struct pci_device_id octeon_pci_tbl[]
static DEFINE_PCI_DEVICE_TABLE(octeon_pci_tbl) = {
	{OCTEON_VENDOR_ID, 0xA300, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},	//83xx PF
	{OCTEON_VENDOR_ID, 0xB200, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},	//96xx PF
	{OCTEON_VENDOR_ID, 0xB100, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},	//98xx PF
	{0, 0, 0, 0, 0, 0, 0}
};

int octeon_probe(struct pci_dev *pdev, const struct pci_device_id *ent)

{
	
    uint32_t cur_pcidev = 0;

			

    cur_pcidev = (pdev->bus->number << 8)|pdev->devfn;
    printk("OCTEON: ordering_octeon bus:dev.fun bus=%x:%x.%x\n", pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	
    return 0;


	
	

	printk("OCTEON: Octeon device is ready bus:dev.fun %x:%x.%x\n",
			 pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	
}





void octeon_remove(struct pci_dev *pdev)
{
	

	printk("OCTEON: Octeon device  removed\n");
}



static struct pci_driver octeon_pci_driver = {
	.name = "Octeon",
	.id_table = octeon_pci_tbl,
	.probe = octeon_probe,
#if  LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
	.remove = __devexit_p(octeon_remove),
#else
	.remove = octeon_remove,
#endif
#ifdef PCIE_AER
	/* For AER */
	.err_handler = &octeon_err_handler,
#endif
};




int init_module(void)
{
    int ret;
	
	printk(KERN_INFO "insmod octeon_drv_pre.\n");
    ret = pci_register_driver(&octeon_pci_driver);
	
	return 0;
}

void cleanup_module(void)
{
	printk(KERN_INFO "rmmod octeon_drv_pre 1.\n");
    pci_unregister_driver(&octeon_pci_driver);
}