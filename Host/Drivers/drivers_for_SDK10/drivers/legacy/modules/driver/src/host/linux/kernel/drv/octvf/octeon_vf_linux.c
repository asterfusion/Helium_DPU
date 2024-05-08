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

#include "octeon_main.h"
#include "cavium_release.h"

MODULE_AUTHOR("Cavium Networks");
MODULE_DESCRIPTION("Octeon Host PCI Driver");
MODULE_LICENSE("GPL");

void cleanup_module(void);

extern int octeon_open(struct inode *, struct file *);
extern int octeon_release(struct inode *, struct file *);
extern int octeon_ioctl(struct inode *, struct file *, unsigned int,
			unsigned long);
extern long octeon_compat_ioctl(struct file *, unsigned int, unsigned long);
extern long octeon_unlocked_ioctl(struct file *, unsigned int, unsigned long);

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
extern int __devinit
octeon_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
#else
extern int octeon_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
#endif

extern void octeon_remove(struct pci_dev *pdev);

extern OCTEON_DRIVER_STATUS octeon_state;

extern void octeon_init_device_list(void);
extern int octeon_init_poll_thread(void);
extern int octeon_delete_poll_thread(void);
extern void octeon_reset_ioq(octeon_device_t * octeon_dev, int ioq);

#ifdef PCIE_AER
extern pci_ers_result_t octeon_pcie_error_detected(struct pci_dev *pdev,
						   pci_channel_state_t state);
extern pci_ers_result_t octeon_pcie_mmio_enabled(struct pci_dev *pdev);
extern pci_ers_result_t octeon_pcie_slot_reset(struct pci_dev *pdev);
extern void octeon_pcie_resume(struct pci_dev *pdev);

/* For PCI-E Advanced Error Recovery (AER) Interface */
static struct pci_error_handlers octeon_err_handler = {
	.error_detected = octeon_pcie_error_detected,
	.mmio_enabled = octeon_pcie_mmio_enabled,
	.slot_reset = octeon_pcie_slot_reset,
	.resume = octeon_pcie_resume,
};
#endif

static struct file_operations octeon_fops = {
open:	octeon_open,
release:octeon_release,
read:	NULL,
write:	NULL,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
ioctl:	octeon_ioctl,
#else
unlocked_ioctl:octeon_unlocked_ioctl,
compat_ioctl:octeon_compat_ioctl,
#endif
mmap:	NULL
};

#ifndef  DEFINE_PCI_DEVICE_TABLE
#define  DEFINE_PCI_DEVICE_TABLE(octeon_pci_table) struct pci_device_id octeon_pci_tbl[]
#endif

static DEFINE_PCI_DEVICE_TABLE(octeon_pci_tbl) = {
	{
	OCTEON_VENDOR_ID, OCTEON_CN83XX_VF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},	//83xx VF
	{
	OCTEON_VENDOR_ID, OCTEON_CN93XX_VF, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},	//93xx VF
	{
	0, 0, 0, 0, 0, 0, 0}
};

static struct pci_driver octeon_pci_driver = {
	.name = "Octeon_vf",
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

void get_base_compile_options(char *copts UNUSED)
{
#ifdef CAVIUM_DEBUG
	strcat(copts, " DEBUG ");
#endif

#ifdef USE_BUFFER_POOL
	strcat(copts, " BUFPOOL ");
#endif

#ifdef ETHERPCI
	strcat(copts, " ETHERPCI");
#endif

#ifdef   CVM_SUPPORT_DEPRECATED_API
	strcat(copts, " SUPPORT_DEPRECATED_API ");
#endif
}

int octeon_base_init_module(void)
{
	int ret;

#if !defined(OCTEON_EXCLUDE_BASE_LOAD)
	const char *oct_cvs_tag = CNNIC_VERSION;
	char copts[160], oct_version[sizeof(CNNIC_VERSION) + 100];

	cavium_print_msg
	    ("-- OCTEON: Loading Octeon PCI driver (base module)\n");
	cavium_parse_cvs_string(oct_cvs_tag, oct_version, sizeof(oct_version));
	cavium_print_msg("OCTEON: Driver Version: %s\n", oct_version);
	cavium_print_msg("OCTEON: System is %s (%d ticks/sec)\n", ENDIAN_MESG,
			 CAVIUM_TICKS_PER_SEC);

	copts[0] = '\0';

	get_base_compile_options(copts);
	if (strlen(copts))
		cavium_print_msg("OCTEON: PCI Driver compile options: %s\n",
				 copts);
	else
		cavium_print_msg("OCTEON: PCI Driver compile options: NONE\n");
#endif

	octeon_state = OCT_DRV_DEVICE_INIT_START;

	octeon_init_device_list();
	octeon_init_module_handler_list();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
	ret = pci_module_init(&octeon_pci_driver);
#else
	ret = pci_register_driver(&octeon_pci_driver);
#endif
	if (ret < 0) {
		cavium_error("OCTEON: pci_module_init() returned %d\n", ret);
		cavium_error
		    ("OCTEON: Your kernel may not be configured for hotplug\n");
		cavium_error("        and no Octeon devices were detected\n");
		return ret;
	}

	octeon_state = OCT_DRV_DEVICE_INIT_DONE;

	if (octeon_init_poll_thread()) {
		cavium_error("OCTEON: Poll thread creation failed\n");
		return -ENODEV;
	}

	octeon_state = OCT_DRV_POLL_INIT_DONE;

	ret =
	    register_chrdev(OCTEON_VF_DEVICE_MAJOR, VF_DRIVER_NAME,
			    &octeon_fops);
	if (ret < 0) {
		cavium_error("OCTEON: Device Registration failed, error:%d\n",
			     ret);
		/* This is the error value returned by register_chrdev() */
		return ret;
	}

	octeon_state = OCT_DRV_REGISTER_DONE;

#if !defined(OCTEON_EXCLUDE_BASE_LOAD)
	cavium_print_msg
	    ("-- OCTEON: Octeon PCI driver (base module) is ready!\n");
#endif

	return ret;
}

void octeon_base_exit_module(void)
{
#if !defined(OCTEON_EXCLUDE_BASE_LOAD)
	cavium_print_msg
	    ("-- OCTEON: Preparing to unload Octeon PCI driver (base module)\n");
	cavium_print(PRINT_FLOW, "cleanup_module(): state is %d\n",
		     octeon_state);
#endif

	switch (octeon_state) {
	case OCT_DRV_ACTIVE:
	case OCT_DRV_REGISTER_DONE:
		unregister_chrdev(OCTEON_VF_DEVICE_MAJOR, VF_DRIVER_NAME);
		cavium_print(PRINT_FLOW, "Device unregister done\n");
	case OCT_DRV_POLL_INIT_DONE:
		/* The poll thread is not enabled for a continuous mode pci test */
		octeon_delete_poll_thread();
		cavium_print(PRINT_FLOW, "Octeon poll thread stopped\n");
	case OCT_DRV_DEVICE_INIT_DONE:
	case OCT_DRV_DEVICE_INIT_START:
		break;
	}

	pci_unregister_driver(&octeon_pci_driver);

#if !defined(OCTEON_EXCLUDE_BASE_LOAD)
	cavium_print_msg
	    ("-- OCTEON: Stopped Octeon PCI driver (base module)\n");
#endif
}

#if !defined(OCTEON_EXCLUDE_BASE_LOAD)
module_init(octeon_base_init_module);
module_exit(octeon_base_exit_module);
#endif

/* All symbols exported by the BASE driver are listed below. */

#ifdef USE_BUFFER_POOL
EXPORT_SYMBOL(put_buffer_in_pool);
EXPORT_SYMBOL(get_buffer_from_pool);
#endif
EXPORT_SYMBOL(octeon_map_single_buffer);
EXPORT_SYMBOL(octeon_unmap_single_buffer);
EXPORT_SYMBOL(octeon_map_page);
EXPORT_SYMBOL(octeon_unmap_page);

EXPORT_SYMBOL(get_octeon_count);
EXPORT_SYMBOL(get_octeon_device_id);
EXPORT_SYMBOL(get_octeon_device_ptr);
EXPORT_SYMBOL(octeon_get_tx_qsize);
EXPORT_SYMBOL(octeon_get_rx_qsize);

EXPORT_SYMBOL(octeon_register_module_handler);
EXPORT_SYMBOL(octeon_unregister_module_handler);
EXPORT_SYMBOL(octeon_register_dispatch_fn);
EXPORT_SYMBOL(octeon_unregister_dispatch_fn);
EXPORT_SYMBOL(octeon_register_poll_fn);
EXPORT_SYMBOL(octeon_unregister_poll_fn);
EXPORT_SYMBOL(octeon_register_noresp_buf_free_fn);
EXPORT_SYMBOL(octeon_add_proc_entry);
EXPORT_SYMBOL(octeon_delete_proc_entry);

EXPORT_SYMBOL(octeon_process_request);
EXPORT_SYMBOL(octeon_process_instruction);
EXPORT_SYMBOL(octeon_query_request_status);
EXPORT_SYMBOL(process_ordered_list);
EXPORT_SYMBOL(octeon_send_noresponse_command);

EXPORT_SYMBOL(octeon_write_core_memory);
EXPORT_SYMBOL(octeon_read_core_memory);

EXPORT_SYMBOL(octeon_get_cycles_per_usec);

#ifdef CAVIUM_DEBUG
EXPORT_SYMBOL(octeon_debug_level);
#endif

EXPORT_SYMBOL(octeon_reset_oq_bufsize);
EXPORT_SYMBOL(octeon_register_droq_ops);
EXPORT_SYMBOL(octeon_unregister_droq_ops);
EXPORT_SYMBOL(octeon_process_droq_poll_cmd);
EXPORT_SYMBOL(octeon_send_short_command);
EXPORT_SYMBOL(octeon_reset_ioq);

EXPORT_SYMBOL(octeon_iq_post_command);
EXPORT_SYMBOL(octeon_flush_iq);
EXPORT_SYMBOL(print_octeon_state_errormsg);
EXPORT_SYMBOL(octeon_perf_flush_iq);
EXPORT_SYMBOL(octeon_get_conf);
EXPORT_SYMBOL(octeon_setup_droq);
EXPORT_SYMBOL(octeon_setup_iq);
EXPORT_SYMBOL(octeon_delete_droq);
EXPORT_SYMBOL(octeon_delete_instr_queue);
EXPORT_SYMBOL(octeon_enable_msix_interrupts);
EXPORT_SYMBOL(octeon_allocate_ioq_vector);
EXPORT_SYMBOL(octeon_delete_ioq_vector);
EXPORT_SYMBOL(octeon_disable_msix_interrupts);
EXPORT_SYMBOL(octeon_setup_irq_affinity);
EXPORT_SYMBOL(octeon_clear_irq_affinity);
EXPORT_SYMBOL(wait_for_instr_fetch);
EXPORT_SYMBOL(wait_for_iq_instr_fetch);
EXPORT_SYMBOL(wait_for_pending_requests);
EXPORT_SYMBOL(wait_for_oq_pkts);
EXPORT_SYMBOL(wait_for_output_queue_pkts);
