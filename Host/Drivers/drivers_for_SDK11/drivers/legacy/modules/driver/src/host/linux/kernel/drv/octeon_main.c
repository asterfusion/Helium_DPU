/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include <linux/aer.h>
#include "octeon_main.h"
#include "cavium_proc.h"
#include "octeon_mem_ops.h"
#include "octeon_macros.h"
#include "barmap.h"

void __iomem *nwa_bar0_internal_addr;
EXPORT_SYMBOL(nwa_bar0_internal_addr);

/* By default MSIX interrupts are enabled.
 * OCTEONTX supports only MSI-X interrupts.
 */
int octeon_msix = 1;

module_param(octeon_msix, int, 0);
MODULE_PARM_DESC(octeon_msix, "Flag for enabling MSI-X interrupts");

uint32_t num_vfs = 0;

char sdp_packet_mode[5];
module_param_string(sdp_packet_mode, sdp_packet_mode, sizeof(sdp_packet_mode), 0);
MODULE_PARM_DESC(sdp_packet_mode, "Mode of SDP operation: <loop|nic>");

int octeon_device_init(octeon_device_t *);
void octeon_remove(struct pci_dev *pdev);

extern int octeon_setup_poll_fn_list(octeon_device_t * oct);
extern void octeon_delete_poll_fn_list(octeon_device_t * oct);

/*  State of the Octeon host driver.
    The Octeon device status is set after each sub-system of Octeon driver
    gets initialized. If failure occurs the status value indicates the cleanup
    routine which resources need to be freed.
*/
OCTEON_DRIVER_STATUS octeon_state;

extern octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];

#ifdef PCIE_AER
/* PCIe AER interface routines */
pci_ers_result_t octeon_pcie_slot_reset(struct pci_dev *pdev);
pci_ers_result_t octeon_pcie_error_detected(struct pci_dev *pdev,
					    pci_channel_state_t state);
pci_ers_result_t octeon_pcie_mmio_enabled(struct pci_dev *pdev);

void octeon_pcie_resume(struct pci_dev *pdev);
void octeon_cleanup_aer_uncorrect_error_status(struct pci_dev *);
void octeon_stop_io(octeon_device_t * oct);

void octeon_pcierror_quiesce_device(octeon_device_t * oct)
{
	int i;

	/* Disable the input and output queues now. No more packets will
	   arrive from Octeon, but we should wait for all packet processing
	   to finish. */
	if(oct->fn_list.force_io_queues_off)	   
		oct->fn_list.force_io_queues_off(oct)

	/* To allow for in-flight requests */
	cavium_sleep_timeout(100);

	if (wait_for_all_pending_requests(oct)) {
		cavium_error("OCTEON[%d]: There were pending requests\n",
			     oct->octeon_id);
	}

	/* Force all requests waiting to be fetched by OCTEON to complete. */
	for (i = 0; i < oct->num_iqs; i++) {
		octeon_instr_queue_t *iq = oct->instr_queue[i];

		if (cavium_atomic_read(&iq->instr_pending)) {
			iq->fill_cnt = 0;
			iq->octeon_read_index = iq->host_write_index;
			iq->stats.instr_processed +=
			    cavium_atomic_read(&iq->instr_pending);

			process_noresponse_list(oct, iq);
		}
	}

	/* Force all pending ordered list requests to time out. */
	process_ordered_list(oct, 1);

	/* We do not need to wait for output queue packets to be processed. */
}

void octeon_cleanup_aer_uncorrect_error_status(struct pci_dev *dev)
{
	int pos = 0x100;
	u32 status, mask;

	pci_read_config_dword(dev, pos + PCI_ERR_UNCOR_STATUS, &status);
	pci_read_config_dword(dev, pos + PCI_ERR_UNCOR_SEVER, &mask);
	if (dev->error_state == pci_channel_io_normal)
		status &= ~mask;	/* Clear corresponding nonfatal bits */
	else
		status &= mask;	/* Clear corresponding fatal bits */
	pci_write_config_dword(dev, pos + PCI_ERR_UNCOR_STATUS, status);

}

void octeon_stop_io(octeon_device_t * oct)
{

	/* No more instructions will be forwarded. */
	cavium_atomic_set(&oct->status, OCT_DEV_IN_RESET);

	/* Disable interrupts  */
	oct->fn_list.disable_interrupt(oct->chip, OCTEON_ALL_INTR);

	octeon_pcierror_quiesce_device(oct);

	if (oct->app_mode == CVM_DRV_BASE_APP) {

		if (oct->msix_on) {
			octeon_clear_irq_affinity(oct);
			octeon_disable_msix_interrupts(oct);
			octeon_delete_ioq_vector(oct);
		}

		oct_stop_base_module(oct->octeon_id, oct);
	}

	cavium_print_msg("OCTEON: Device state is now %s\n",
			 get_oct_state_string(&oct->status));

	if (oct->sriov_info.num_vfs)
		cavium_print_msg
		    (" Before unloading octeon_drv.ko, ensure that VMs attached to the VFs are shut down.\n");

	/* making it a common function for all OCTEON models */
	octeon_cleanup_aer_uncorrect_error_status(oct->pci_dev);
}

/**
 * octeon_pcie_error_detected - called when PCI error is detected
 * @pdev: Pointer to PCI device
 * @state: The current pci connection state
 *
 * This function is called after a PCI bus error affecting
 * this device has been detected.
 */
pci_ers_result_t
octeon_pcie_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	octeon_device_t *oct = pci_get_drvdata(pdev);

	/* Non-correctable Non-fatal errors */
	if (state == pci_channel_io_normal) {
		cavium_error
		    ("OCTEON: Non-correctable non-fatal error reported.\n");
		octeon_cleanup_aer_uncorrect_error_status(oct->pci_dev);
		return PCI_ERS_RESULT_CAN_RECOVER;
	}

	/* Non-correctable Fatal errors */
	cavium_error
	    ("OCTEON: PCIe error Non-correctable FATAL reported by AER driver\n");
	octeon_stop_io(oct);

	/* Always return a DISCONNECT. There is no support for recovery but only
	   for a clean shutdown. */
	return PCI_ERS_RESULT_DISCONNECT;
}

pci_ers_result_t octeon_pcie_mmio_enabled(struct pci_dev * pdev)
{
	/* We should never hit this since we never ask for a reset for a Fatal
	   Error. We always return DISCONNECT in io_error above. */
	/* But play safe and return RECOVERED for now. */
	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * octeon_pcie_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the octeon_resume routine.
 */
pci_ers_result_t octeon_pcie_slot_reset(struct pci_dev * pdev)
{
	/* We should never hit this since we never ask for a reset for a Fatal
	   Error. We always return DISCONNECT in io_error above. */
	/* But play safe and return RECOVERED for now. */
	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * octeon_pcie_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the octeon_resume routine.
 */
void octeon_pcie_resume(struct pci_dev *pdev)
{
	/* Nothing to be done here. */
}

/* PCIe AER - end */
#endif

void octeon_unmap_pci_barx(octeon_device_t * oct, int baridx)
{
	cavium_print(PRINT_DEBUG,
		     "OCTEON[%d]: Freeing PCI mapped regions for Bar%d\n",
		     oct->octeon_id, baridx);

	if (oct->mmio[baridx].done)
		iounmap((void *)oct->mmio[baridx].hw_addr);

	if (oct->mmio[baridx].start)
		pci_release_region(oct->pci_dev, baridx * 2);
}

int octeon_map_pci_barx(octeon_device_t * oct, int baridx, int max_map_len)
{
	unsigned long mapped_len = 0;

	if (pci_request_region(oct->pci_dev, baridx * 2, DRIVER_NAME)) {
		cavium_error
		    ("OCTEON[%d]: pci_request_region failed for bar %d\n",
		     oct->octeon_id, baridx);
		return 1;
	}

	oct->mmio[baridx].start = pci_resource_start(oct->pci_dev, baridx * 2);
	oct->mmio[baridx].len = pci_resource_len(oct->pci_dev, baridx * 2);

	mapped_len = oct->mmio[baridx].len;
	if (!mapped_len)
		return 1;

	if (max_map_len && (mapped_len > max_map_len)) {
		mapped_len = max_map_len;
	}

	oct->mmio[baridx].hw_addr =
	    ioremap(oct->mmio[baridx].start, mapped_len);
	oct->mmio[baridx].mapped_len = mapped_len;

	cavium_print(PRINT_DEBUG,
		     "OCTEON[%d]: BAR%d start: 0x%lx mapped %lu of %lu bytes\n",
		     oct->octeon_id, baridx, oct->mmio[baridx].start,
		     mapped_len, oct->mmio[baridx].len);

	/* VSR: delete below print; only for dev debug */
	printk("OCTEON[%d]: BAR%d start: 0x%lx mapped %lu of %lu bytes; hw_addr=0x%llx\n",
	       oct->octeon_id, baridx, oct->mmio[baridx].start,
	       mapped_len, oct->mmio[baridx].len, (unsigned long long)oct->mmio[baridx].hw_addr);

	if (!oct->mmio[baridx].hw_addr) {
		cavium_error("OCTEON[%d]: error ioremap for bar %d\n",
			     oct->octeon_id, baridx);
		return 1;
	}
	oct->mmio[baridx].done = 1;

	nwa_bar0_internal_addr = oct->mmio[baridx].hw_addr + NPU_BARMAP_NW_AGENT_OFFSET;

	return 0;
}

/* Linux wrapper for our interrupt handlers. */
cvm_intr_return_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
octeon_intr_handler(int irq, void *dev, struct pt_regs * regs)
#else
octeon_intr_handler(int irq UNUSED, void *dev)
#endif
{
	octeon_device_t *oct = (octeon_device_t *) dev;
	return oct->fn_list.interrupt_handler(oct);
}

/* Linux wrapper for our interrupt handlers. */
cvm_intr_return_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
octeon_msix_intr_handler(int irq, void *dev, struct pt_regs * regs)
#else
octeon_msix_intr_handler(int irq UNUSED, void *dev)
#endif
{
	unsigned long flags;
	cvm_intr_return_t ret;
	octeon_ioq_vector_t *ioq_vector = (octeon_ioq_vector_t *) dev;
	octeon_device_t *oct = ioq_vector->oct_dev;

	local_irq_save(flags);
	ret = oct->fn_list.msix_interrupt_handler(ioq_vector);
	local_irq_restore(flags);

	return ret;
}

void octeon_disable_msix_interrupts(octeon_device_t * oct_dev)
{
	int i = 0;
	int non_ioq_intrs = 0;

	if (OCTEON_CN83XX_PF(oct_dev->chip_id))
		non_ioq_intrs = OCTEON_NUM_NON_IOQ_INTR;
	else if (OCTEON_CN9XXX_PF(oct_dev->chip_id))
		non_ioq_intrs = OCTEONTX2_NUM_NON_IOQ_INTR;
	else if (OCTEON_CNXK_PF(oct_dev->chip_id))
		non_ioq_intrs = CNXK_NUM_NON_IOQ_INTR;

	if (oct_dev->num_irqs) {
		if (OCTEON_CN8PLUS_PF(oct_dev->chip_id)) {
			for (i = 0; i < non_ioq_intrs; i++) {
				/* Free non ioq MSI-X vector */
				free_irq(oct_dev->msix_entries[i].vector,
					 oct_dev);
			}
			/* Free ioq MSI-X vector */
			for (i = 0; i < oct_dev->num_irqs-non_ioq_intrs; i++) {
				free_irq(oct_dev->msix_entries[i+non_ioq_intrs].vector,
					 oct_dev->ioq_vector[i]);
			}
		} else {
			for (i = 0; i < (oct_dev->num_irqs - 1); i++) {
				/* free MSI-X vector */
				free_irq(oct_dev->msix_entries[i].vector,
					 oct_dev->ioq_vector[i]);
			}
			/* non-iov vector's argument is octeon_dev struct */
			free_irq(oct_dev->msix_entries[oct_dev->num_irqs -1].vector,
				 oct_dev);
		}
		pci_disable_msix(oct_dev->pci_dev);
		cavium_free_virt(oct_dev->msix_entries);
		oct_dev->msix_entries = NULL;
	}
}

static char octtx_intr_names[][INTRNAMSIZ] = {
	"octeontx_epf_irerr_rint",
	"octeontx_epf_orerr_rint",
	"octeontx_epf_mbox_rint",
	"octeontx_epf_oei_rint",
	"octeontx_epf_dma_rint",
	"octeontx_epf_misc_rint",
	"octeontx_epf_pp_vf_rint",
	"octeontx_epf_dma_vf_rint",
	"octeontx_epf_rsvd_int0",
	"octeontx_epf_rsvd_int1",
	"octeontx_epf_rsvd_int2",
	"octeontx_epf_rsvd_int3",
	"octeontx_epf_rsvd_int4",
	"octeontx_epf_rsvd_int5",
	"octeontx_epf_rsvd_int6",
	"octeontx_epf_rsvd_int7",
	/* IOQ interrupt */
	"octeontx"
};

/* VSR: these interrupts changed for 96xx to 98xx to 10k */
static char octtx2_intr_names[][INTRNAMSIZ] = {
	"octeontx2_epf_ire_rint",
	"octeontx2_epf_ore_rint",
	"octeontx2_epf_vfire_rint0",
	"octeontx2_epf_vfire_rint1",
	"octeontx2_epf_vfore_rint0",
	"octeontx2_epf_vfore_rint1",
	"octeontx2_epf_mbox_rint0",
	"octeontx2_epf_mbox_rint1",
	"octeontx2_epf_oei_rint",
	"octeontx2_epf_dma_rint",
	"octeontx2_epf_dma_vf_rint0",
	"octeontx2_epf_dma_vf_rint1",
	"octeontx2_epf_pp_vf_rint0",
	"octeontx2_epf_pp_vf_rint1",
	"octeontx2_epf_misc_rint",
	"octeontx2_epf_rsvd",
	/* IOQ interrupt */
	"octeontx2"
};
static char octtx2_cnxk_intr_names[][INTRNAMSIZ] = {
	"octeontx2_epf_ire_rint",
	"octeontx2_epf_ore_rint",
	"octeontx2_epf_vfire_rint",
	"octeontx2_epf_rsvd0",
	"octeontx2_epf_vfore_rint",
	"octeontx2_epf_rsvd1",
	"octeontx2_epf_mbox_rint",
	"octeontx2_epf_rsvd2_0",
	"octeontx2_epf_rsvd2_1",
	"octeontx2_epf_dma_rint",
	"octeontx2_epf_dma_vf_rint",
	"octeontx2_epf_rsvd3",
	"octeontx2_epf_pp_vf_rint",
	"octeontx2_epf_rsvd3",
	"octeontx2_epf_misc_rint",
	"octeontx2_epf_rsvd5",
	/* Next 16 are for OEI_RINT */
	"octeontx2_epf_oei_rint0",
	"octeontx2_epf_oei_rint1",
	"octeontx2_epf_oei_rint2",
	"octeontx2_epf_oei_rint3",
	"octeontx2_epf_oei_rint4",
	"octeontx2_epf_oei_rint5",
	"octeontx2_epf_oei_rint6",
	"octeontx2_epf_oei_rint7",
	"octeontx2_epf_oei_rint8",
	"octeontx2_epf_oei_rint9",
	"octeontx2_epf_oei_rint10",
	"octeontx2_epf_oei_rint11",
	"octeontx2_epf_oei_rint12",
	"octeontx2_epf_oei_rint13",
	"octeontx2_epf_oei_rint14",
	"octeontx2_epf_oei_rint15",
	/* IOQ interrupt */
	"octeontx2"
};

int octeon_tx_enable_msix_interrupts(octeon_device_t * oct)
{
	int irqret, num_ioq_vectors, i = 0, srn = 0, ret = 0;
	int failed_non_irq_index = 0, failed_irq_index = 0;
	int non_ioq_intrs = 0;
	char *oct_irq_names = NULL, *irq_names, *ioq_irq_name;

	num_ioq_vectors = oct->num_oqs;

	if (OCTEON_CN83XX_PF(oct->chip_id)) {
		non_ioq_intrs = OCTEON_NUM_NON_IOQ_INTR;
		oct_irq_names = octtx_intr_names[0];
	} else if (OCTEON_CN9XXX_PF(oct->chip_id)) {
		non_ioq_intrs = OCTEONTX2_NUM_NON_IOQ_INTR;
		oct_irq_names = octtx2_intr_names[0];
	} else if (OCTEON_CNXK_PF(oct->chip_id)) {
		non_ioq_intrs = CNXK_NUM_NON_IOQ_INTR;
		oct_irq_names = octtx2_cnxk_intr_names[0];
	}

	oct->num_irqs = num_ioq_vectors + non_ioq_intrs;
	/* allocate storage for the names assigned to each irq */
	oct->irq_name_storage =
		devm_kzalloc(&oct->pci_dev->dev,
			     (oct->num_irqs * INTRNAMSIZ), GFP_KERNEL);
	if (!oct->irq_name_storage) {
		cavium_error("Irq name storage alloc failed...\n");
		return 1;
	}
	irq_names = oct->irq_name_storage;
	memcpy(irq_names, oct_irq_names, (non_ioq_intrs * INTRNAMSIZ));

	oct->msix_entries =
	    cavium_alloc_virt(oct->num_irqs * sizeof(cavium_msix_entry_t));

	if (oct->msix_entries == NULL) {
		cavium_error("Memory Alloc failed.\n");
		return 1;
	}

	//srn = oct->sriov_info.pf_srn;

	for (i = 0; i < non_ioq_intrs; i++) {
		oct->msix_entries[i].entry = i;
	}

	for (i = non_ioq_intrs; i < oct->num_irqs; i++) {
		oct->msix_entries[i].entry = srn + i;
	}

	cavium_error("%s: OCTEON[%d]: num_irqs = %d, srn = %d\n", __func__, oct->octeon_id, oct->num_irqs, srn);
	ret = pci_enable_msix_range(oct->pci_dev, oct->msix_entries,
				    oct->num_irqs, oct->num_irqs);
	if(ret < 0) {
		cavium_error("Unable to Allocate MSI-X interrupts. returned err: %d \n", ret);
		cavium_free_virt(oct->msix_entries);
		oct->msix_entries = NULL;
		return 1;
	}
	cavium_print_msg
	    ("OCTEON: %d MSI-X interrupts are allocated.\n", oct->num_irqs);

	/** For 83XX/93XX, there is OCTEON_NUM_NON_IOQ_INTR non-ioq interrupts */
	for (i = 0; i < non_ioq_intrs; i++) {
		irqret = request_irq(oct->msix_entries[i].vector,
				     octeon_intr_handler, 0,
				     &irq_names[IRQ_NAME_OFF(i)], oct);
		if (irqret) {
			failed_non_irq_index = i;
			cavium_error
			    ("OCTEON: Request_irq failed for MSIX interrupt "
			     "Error: %d\n", irqret);

			goto free_non_irq_entries;
		}
	}
	failed_non_irq_index = non_ioq_intrs;

	for (i = 0; i < num_ioq_vectors; i++) {
		ioq_irq_name = &irq_names[IRQ_NAME_OFF(i + non_ioq_intrs)];
		snprintf(ioq_irq_name, INTRNAMSIZ,
				"%s-pf%u-ioq%d",
				&oct_irq_names[IRQ_NAME_OFF(non_ioq_intrs)],
				oct->pf_num, i);

		irqret = request_irq(oct->msix_entries[i + non_ioq_intrs].vector,
				     octeon_msix_intr_handler, 0,
				     ioq_irq_name,
				     oct->ioq_vector[i]);
		if (irqret) {
			failed_irq_index = i;
			cavium_error
			    ("OCTEON: Request_irq failed for MSIX interrupt "
			     "Error: %d\n", irqret);

			goto free_irq_entries;
		}
		oct->droq[i]->irq_num =
			oct->msix_entries[i + non_ioq_intrs].vector;
	}

	oct->msix_on = 1;
	cavium_print_msg("OCTEON[%d]: MSI-X enabled\n", oct->octeon_id);
	return 0;

free_irq_entries:
	for (i = 0; i < failed_irq_index; i++) {
		free_irq(oct->msix_entries[i].vector, oct->ioq_vector[i]);
	}
free_non_irq_entries:
	for (i = 0; i < failed_non_irq_index; i++) {
		free_irq(oct->msix_entries[i].vector, oct);
	}
	pci_disable_msix(oct->pci_dev);
	cavium_free_virt(oct->msix_entries);
	oct->msix_entries = NULL;
	return 1;
}

/*  Enable interrupt in Octeon device as given in the PCI interrupt mask.
*/
int octeon_enable_msix_interrupts(octeon_device_t * oct)
{
	cavium_atomic_set(&oct->in_interrupt, 0);
	cavium_atomic_set(&oct->interrupts, 0);

	return octeon_tx_enable_msix_interrupts(oct);
}

int octeon_disable_sriov(octeon_device_t * oct)
{
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	/* If the device VFs are assigned,we cannot disable SR-IOV */
	if (pci_vfs_assigned(oct->pci_dev)) {
		cavium_error
		    ("Unloading the PF driver while VFs are assigned\n");
		return -1;
	}
#endif
	/* disable iov and allow time for transactions to clear */
	pci_disable_sriov(oct->pci_dev);
	oct->sriov_info.sriov_enabled = 0;
	msleep(100);

	return 0;
}

int octeon_enable_sriov(octeon_device_t * oct)
{
	int err;
	unsigned int num_vfs = oct->sriov_info.num_vfs;

	if (oct->drv_flags & OCTEON_SRIOV_MODE) {

		if (!num_vfs)
			cavium_error
			    ("OCTEON: num_vfs should be non-zero value.\n");

		err = pci_enable_sriov(oct->pci_dev, oct->sriov_info.num_vfs);
		if (err) {
			cavium_error
			    ("OCTEON: Failed to enable PCI sriov: %d\n", err);
			return err;
		}
		oct->sriov_info.sriov_enabled = 1;
	}
	return 0;
}

int octeon_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	octeon_device_t *oct_dev = pci_get_drvdata(pdev);
	int vf_srn, rpvf;

	oct_dev->sriov_info.num_vfs = num_vfs;
	if(num_vfs == 0)
		return octeon_disable_sriov(oct_dev);

	vf_srn = oct_dev->sriov_info.vf_srn;
	rpvf = oct_dev->sriov_info.rings_per_vf;

	if (num_vfs > oct_dev->sriov_info.max_vfs) {
		cavium_error("Invalid VF count; Max supported VFs = %d\n",
			     oct_dev->sriov_info.max_vfs);
		return -EINVAL;
	}

	oct_dev->fn_list.configure_sriov_vfs(oct_dev);

	return octeon_enable_sriov(oct_dev);
}

#define FW_STATUS_VSEC_ID 0xA3
#define FW_STATUS_READY 1
static u8 oct_get_fw_ready_status(octeon_device_t * oct)
{
	u32 pos = 0;
	u16 vsec_id;
	u8 status = 0;

	while ((pos = pci_find_next_ext_capability(oct->pci_dev, pos,
						   PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(oct->pci_dev, pos + 4, &vsec_id);
		if (vsec_id == FW_STATUS_VSEC_ID) {
			pci_read_config_byte(oct->pci_dev, (pos + 8), &status);
			cavium_print_msg("OCTEON[%d]:fw ready status %u\n",
					 oct->octeon_id, status);
			return status;
		}
	}
	return 0;
}

static int pf_has_link_dependency(octeon_device_t *oct)
{
	int pos;
	u8 link;

	pos = pci_find_ext_capability(oct->pci_dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos) {
		printk("failed to find SRIOV capability in device\n");
		return -ENODEV;
	}

	pci_read_config_byte(oct->pci_dev, pos + PCI_SRIOV_FUNC_LINK, &link);

	return link;
}

static void octeon_device_init_work(struct work_struct *work)
{
	octeon_device_t *oct_dev;
	struct cavium_delayed_wq *wq;
	u8 status;

	wq = container_of(work, struct cavium_delayed_wq, wk.work.work);
	oct_dev = (octeon_device_t *)wq->wk.ctxptr;

	cavium_atomic_set(&oct_dev->status, OCT_DEV_CHECK_FW);

	if (pf_has_link_dependency(oct_dev))
		goto skip_fw_status_check;

	while (true) {
		status = oct_get_fw_ready_status(oct_dev);
		if (status == FW_STATUS_READY)
			break;

		schedule_timeout_interruptible(HZ * 1);
		if (cavium_atomic_read(&oct_dev->status) > OCT_DEV_RUNNING) {
			cavium_atomic_set(&oct_dev->status, OCT_DEV_STATE_INVALID);
			cavium_print_msg("OCTEON: Stopping firmware ready work.\n");
			return;
		}
	}

skip_fw_status_check:
	if (octeon_device_init(oct_dev)) {
		cavium_print_msg("OCTEON[%d]: ERROR: Octeon driver failed to load.\n",
				 oct_dev->octeon_id);
		return;
	}

	octeon_state = OCT_DRV_ACTIVE;

	cavium_print_msg("OCTEON: Octeon device %d is ready\n",
			 oct_dev->octeon_id);
}

#if  LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0)
int __devinit
octeon_probe(struct pci_dev *pdev, const struct pci_device_id *ent UNUSED)
#else
int octeon_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
#endif
{
	octeon_device_t *oct_dev = NULL;

	cavium_print_msg("OCTEON: Found device %x:%x\n",
			 (uint32_t) pdev->vendor, (uint32_t) pdev->device);

	oct_dev = octeon_allocate_device(pdev->device);
	if (oct_dev == NULL)
		return -ENOMEM;

	cavium_print_msg("OCTEON: Setting up Octeon device %d \n",
			 oct_dev->octeon_id);

	/* Assign octeon_device for this device to the private data area. */
	pci_set_drvdata(pdev, oct_dev);

	/* set linux specific device pointer */
	oct_dev->pci_dev = (void *)pdev;

	oct_dev->dev_init_wq.wq = alloc_workqueue("dev_init_wq", WQ_MEM_RECLAIM, 0);
	oct_dev->dev_init_wq.wk.ctxptr = oct_dev;
	INIT_DELAYED_WORK(&oct_dev->dev_init_wq.wk.work, octeon_device_init_work);
	queue_delayed_work(oct_dev->dev_init_wq.wq, &oct_dev->dev_init_wq.wk.work, 0);

	return 0;
}

void octeon_destroy_resources(octeon_device_t * oct_dev)
{
	/* call the App handler to clear and destroy the queues created by the application. */

	switch (cavium_atomic_read(&oct_dev->status)) {
	case OCT_DEV_RUNNING:
	case OCT_DEV_DROQ_INIT_DONE:
	case OCT_DEV_INSTR_QUEUE_INIT_DONE:
		if ((oct_dev->app_mode == CVM_DRV_BASE_APP) ||
		    (oct_dev->app_mode == CVM_DRV_ZLIB_APP))
			octeon_unregister_module_handler(CVM_DRV_BASE_APP);

#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

	case OCT_DEV_CORE_OK:
		cavium_atomic_set(&oct_dev->status, OCT_DEV_IN_RESET);

		oct_dev->app_mode = CVM_DRV_INVALID_APP;
		cavium_print_msg("OCTEON[%d]: Device state is now %s\n",
				 oct_dev->octeon_id,
				 get_oct_state_string(&oct_dev->status));

		cavium_sleep_timeout(CAVIUM_TICKS_PER_SEC / 10);
#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

	case OCT_DEV_STOPPING:
#ifndef PCIE_AER
	case OCT_DEV_IN_RESET:
#endif
	case OCT_DEV_HOST_OK:

		/* Soft reset the octeon device before exiting */
		oct_dev->fn_list.soft_reset(oct_dev);

#ifndef PCIE_AER
		/* Delete the /proc device entries */
		cavium_delete_proc(oct_dev);
#endif
#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

#ifdef PCIE_AER
	case OCT_DEV_IN_RESET:
#endif

	case OCT_DEV_RESP_LIST_INIT_DONE:
		octeon_delete_response_list(oct_dev);

		cavium_print_msg("OCTEON[%d]: Response list deleted.\n",
				 oct_dev->octeon_id);

		/* Disable the device */
		pci_disable_device(oct_dev->pci_dev);
		octeon_delete_mbox(oct_dev);
		cavium_print_msg("OCTEON[%d]: MBOX deleted.\n",
					 oct_dev->octeon_id);
#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

	case OCT_DEV_DISPATCH_INIT_DONE:
		octeon_delete_dispatch_list(oct_dev);
		octeon_delete_poll_fn_list(oct_dev);

		cavium_print_msg("OCTEON[%d]: Deleted poll functions list.\n",
				 oct_dev->octeon_id);
#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

	case OCT_DEV_PCI_MAP_DONE:
		octeon_unmap_pci_barx(oct_dev, 0);
		octeon_unmap_pci_barx(oct_dev, 1);
		if (OCTEON_CN9PLUS_PF(oct_dev->chip_id)) {
			octeon_unmap_pci_barx(oct_dev, 2);
		}

		cavium_print_msg("OCTEON[%d]: BAR unmapped.\n",
				 oct_dev->octeon_id);
#if __GNUC__ > 6
		__attribute__((__fallthrough__));
#endif

	case OCT_DEV_RESET_CLEANUP_DONE:
	case OCT_DEV_BEGIN_STATE:
		/* Nothing to be done here either */
		break;
	}			/* end switch(oct_dev->status) */

	cavium_tasklet_kill(&oct_dev->comp_tasklet);
}

/* This routine is called for each octeon device during driver
    unload time. */
void octeon_remove(struct pci_dev *pdev)
{
	octeon_device_t *oct_dev = pci_get_drvdata(pdev);
	int oct_idx;

	oct_idx = oct_dev->octeon_id;
	cavium_print_msg("OCTEON: Stopping octeon device %d\n", oct_idx);

	if (cavium_atomic_read(&oct_dev->status) == OCT_DEV_CHECK_FW) {
		cavium_atomic_set(&oct_dev->status, OCT_DEV_STOPPING);
		while (true) {
			if (cavium_atomic_read(&oct_dev->status) == OCT_DEV_STATE_INVALID)
				return;

			cavium_error("OCTEON: Waiting for firmware ready work to end.\n");
			schedule_timeout_interruptible(HZ * 1);
		}
		goto before_exit;
	}

	if (oct_dev->sriov_info.sriov_enabled) {
		octeon_disable_sriov(oct_dev);
		cavium_print_msg("OCTEON[%d]: SRIOV disabled.\n",
				 oct_dev->octeon_id);
	}

	/* Call the module handler for each module attached to the
	   base driver. */
	if (oct_dev->app_mode && (oct_dev->app_mode != CVM_DRV_INVALID_APP)
	    && (oct_dev->app_mode != CVM_DRV_BASE_APP)
	    && (oct_dev->app_mode != CVM_DRV_ZLIB_APP)) {
		octeon_stop_module(oct_dev->app_mode, oct_dev->octeon_id);
	}
#ifdef PCIE_AER
	/* Delete the /proc device entries */
	cavium_delete_proc(oct_dev);
#endif

	/* Reset the octeon device and cleanup all memory allocated for
	   the octeon device by driver. */
	octeon_destroy_resources(oct_dev);

	/* This octeon device has been removed. Update the global
	   data structure to reflect this. Free the device structure. */
	octeon_free_device_mem(oct_dev);

before_exit:
	cavium_print_msg("OCTEON: Octeon device %d removed\n", oct_idx);
}

/* The open() entry point for the octeon driver. This routine is called
   every time the /dev/octeon_device file is opened. */
int octeon_open(struct inode *inode UNUSED, struct file *file UNUSED)
{
	CVM_MOD_INC_USE_COUNT;
	return 0;
}

/* The close() entry point for the octeon driver. This routine is called
   every time the /dev/octeon_device file is closed. */
int octeon_release(struct inode *inode UNUSED, struct file *file UNUSED)
{
	/* Send the FD pid info to the OCTEON on FD close() call */
	int i;

	for (i = 0; i < MAX_OCTEON_DEVICES; i++) {
		if (octeon_device[i]) {
			if (cavium_atomic_read(&octeon_device[i]->status) ==
			    OCT_DEV_RUNNING) {
				cavium_print(PRINT_DEBUG, " %s : fd pid = %d\n",
					     __FUNCTION__, current->pid);
			} else {
				cavium_error
				    ("OCTEON[%d] Device is Not in Running State  \n",
				     octeon_device[i]->octeon_id);
				cavium_error
				    (" SE Application is Not Loaded & Running. \n");
			}

		}
	}

	CVM_MOD_DEC_USE_COUNT;
	return 0;
}

/* Routine to identify the Octeon device and to map the BAR address space */
int octeon_chip_specific_setup(octeon_device_t * oct)
{
	uint32_t dev_id, rev_id;

	OCTEON_READ_PCI_CONFIG(oct, 0, &dev_id);
	OCTEON_READ_PCI_CONFIG(oct, 8, &rev_id);
	oct->rev_id = rev_id & 0xff;

	switch (dev_id) {

		case OCTEON_CN83XX_PCIID_PF:
			cavium_print_msg("OCTEON[%d]: CN83XX PASS%d.%d\n",
					 oct->octeon_id, OCTEON_MAJOR_REV(oct),
					 OCTEON_MINOR_REV(oct));

			/* Enable it to stop loading the driver for PF1 */
			oct->sriov_info.num_vfs = num_vfs;
			oct->chip_id = OCTEON_CN83XX_ID_PF;

			return setup_cn83xx_octeon_pf_device(oct);
		case OCTEON_CN93XX_PCIID_PF:
		case OCTEON_CN95N_PCIID_PF:
		case OCTEON_CN95O_PCIID_PF:
		case OCTEON_CN3380_PCIID_PF:
			cavium_print_msg("OCTEON[%d]: CN93XX PASS%d.%d\n",
					 oct->octeon_id, OCTEON_MAJOR_REV(oct),
					 OCTEON_MINOR_REV(oct));
			if (dev_id == OCTEON_CN3380_PCIID_PF)
				cavium_print_msg("OCTEON[%d]: LIO3 CN93XX PASS%d.%d\n",
					 oct->octeon_id, OCTEON_MAJOR_REV(oct),
					 OCTEON_MINOR_REV(oct));

			oct->pf_num = oct->octeon_id;
			/* Enable it to stop loading the driver for PF1 */
			oct->sriov_info.num_vfs = num_vfs;
			oct->chip_id = OCTEON_CN93XX_ID_PF;
			return setup_cn93xx_octeon_pf_device(oct);
		case OCTEON_CN98XX_PCIID_PF:
			cavium_print_msg("OCTEON[%d]: CN98XX PASS%d.%d on %02x:%02x:%x\n",
					 oct->octeon_id, OCTEON_MAJOR_REV(oct),
					 OCTEON_MINOR_REV(oct), oct->pci_dev->bus->number,
					 PCI_SLOT(oct->pci_dev->devfn),
					 PCI_FUNC(oct->pci_dev->devfn));

			oct->pf_num = oct->octeon_id;
			/* Enable it to stop loading the driver for PF1 */
			oct->sriov_info.num_vfs = num_vfs;
			oct->chip_id = OCTEON_CN98XX_ID_PF;
			return setup_cn98xx_octeon_pf_device(oct); //use 93xx PF setup for now

		case OCTEON_CN10KA_PCIID_PF:
		case OCTEON_CNF10KA_PCIID_PF:
		case OCTEON_CN10KB_PCIID_PF:
		case OCTEON_CNF10KB_PCIID_PF:
			cavium_print_msg("OCTEON[%d]: CNXK PASS%d.%d on %02x:%02x:%x\n",
					 oct->octeon_id, OCTEON_MAJOR_REV(oct),
					 OCTEON_MINOR_REV(oct), oct->pci_dev->bus->number,
					 PCI_SLOT(oct->pci_dev->devfn),
					 PCI_FUNC(oct->pci_dev->devfn));

			oct->pf_num = oct->octeon_id;
			oct->sriov_info.num_vfs = num_vfs;
			oct->chip_id = OCTEON_CN10KA_ID_PF;
			return setup_cnxk_octeon_pf_device(oct);
	default:
		cavium_error("OCTEON: Unknown device found (dev_id: %x)\n",
			     dev_id);
	}

	return -1;
}

/* OS-specific initialization for each Octeon device. */
static int octeon_pci_os_setup(octeon_device_t * octeon_dev)
{

	/* setup PCI stuff first */
	if (pci_enable_device(octeon_dev->pci_dev)) {
		cavium_error("OCTEON: pci_enable_device failed\n");
		return 1;
	}

	/* Octeon device supports DMA into a 64-bit space */
#if  LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	if (pci_set_dma_mask(octeon_dev->pci_dev, PCI_DMA_64BIT)) {
		cavium_error("OCTEON: pci_set_dma_mask(64bit) failed\n");
		return 1;
	}
#else
	if (dma_set_mask_and_coherent(&octeon_dev->pci_dev->dev, DMA_BIT_MASK(64))) {
		cavium_error("OCTEON: Unexpected DMA device capability\n");
		return 1;
	}
#endif

	pci_enable_pcie_error_reporting(octeon_dev->pci_dev);
	/* Enable PCI DMA Master. */
	pci_set_master(octeon_dev->pci_dev);

	return 0;
}

extern oct_poll_fn_status_t
oct_poll_module_starter(void *octptr, unsigned long arg);

extern oct_poll_fn_status_t
octeon_hostfw_handshake(void *octptr, unsigned long arg);

extern oct_poll_fn_status_t
octeon_get_app_mode(void *octptr, unsigned long arg);

extern oct_poll_fn_status_t
octeon_wait_for_npu_base(void *octptr, unsigned long arg);

extern int oct_stop_base_module(int oct_id, void *oct_dev);

int octeon_setup_droq(int oct_id, int q_no, void *app_ctx)
{
	octeon_device_t *octeon_dev =
	    (octeon_device_t *) get_octeon_device(oct_id);
	int ret_val = 0;

	if (octeon_dev == NULL)
		return -1;

	cavium_print(PRINT_DEBUG, "OCTEON[%d]: Creating Droq: %d\n",
			 octeon_dev->octeon_id, q_no);
	/* droq creation and local register settings. */
	ret_val = octeon_create_droq(octeon_dev, q_no, app_ctx);
	if (ret_val == -1)
		return ret_val;

	return ret_val;
}

/* Device initialization for each Octeon device. */
int octeon_device_init(octeon_device_t * octeon_dev)
{
	int ret;
	octeon_poll_ops_t poll_ops;

	cavium_atomic_set(&octeon_dev->status, OCT_DEV_BEGIN_STATE);

	/* Enable access to the octeon device and make its DMA capability
	   known to the OS. */
	if (octeon_pci_os_setup(octeon_dev))
		return 1;

	/* Initialize the poll list mechanism used that allows modules to
	   register functions with the driver for each Octeon device. */
	octeon_setup_poll_fn_list(octeon_dev);

	ret  = octeon_chip_specific_setup(octeon_dev);
	/* Identify the Octeon type and map the BAR address space. */
	if (ret == -1) {
		cavium_error("OCTEON: Chip specific setup failed\n");
		return 1;
	}

	cavium_print_msg(" Chip specific setup completed\n");

	if (octeon_msix)
		octeon_dev->drv_flags |= OCTEON_MSIX_CAPABLE;

	cavium_atomic_set(&octeon_dev->status, OCT_DEV_PCI_MAP_DONE);

	cavium_spin_lock_init(&octeon_dev->oct_lock);

	/* Initialize the dispatch mechanism used to push packets arriving on
	   Octeon Output queues. */
	if (octeon_init_dispatch_list(octeon_dev))
		return 1;

	cavium_memset(&poll_ops, 0, sizeof(octeon_poll_ops_t));

	/* The driver has its own set of functions that it registers for
	   each octeon device. */
	poll_ops.fn = oct_poll_module_starter;
	poll_ops.fn_arg = 0UL;
	poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
	strcpy(poll_ops.name, "Module Starter");
	octeon_register_poll_fn(octeon_dev->octeon_id, &poll_ops);

	cavium_atomic_set(&octeon_dev->status, OCT_DEV_DISPATCH_INIT_DONE);

	/* If the use of buffer pool is enabled in the Makefile, allocate
	   memory and initialize the pools. */

	octeon_set_io_queues_off(octeon_dev);

	ret = octeon_dev->fn_list.setup_device_regs(octeon_dev);
	cavium_print_msg(" Setup device regs completed\n");
	if (ret) {
		cavium_error("OCTEON: Failed to configure device registers\n");
		return ret;
	}

	/* Initialize lists to manage the requests of different types that arrive
	   from user & kernel applications for this octeon device. */
	if (octeon_setup_response_list(octeon_dev)) {
		cavium_error("OCTEON: Response list allocation failed\n");
		return 1;
	}
	cavium_atomic_set(&octeon_dev->status, OCT_DEV_RESP_LIST_INIT_DONE);

	if (octeon_setup_mbox(octeon_dev)) {
		cavium_error("OCTEON: Mailbox setup failed\n");
		return 1;
	}

	/* Setup the /proc entries for this octeon device. */
	cavium_init_proc(octeon_dev);

	octeon_dev->app_mode = CVM_DRV_INVALID_APP;

	cavium_atomic_set(&octeon_dev->status, OCT_DEV_HOST_OK);

	cavium_atomic_set(&octeon_dev->hostfw_hs_state, HOSTFW_HS_INIT);

#ifdef BUILD_FOR_EMULATOR
	if (OCTEON_CN93XX_PF(octeon_dev->chip_id)) {
		/* init_ioqs proc entry is used for starting base module in
		 * case of emulator. Driver can sucessfully return from here. */
		return 0;
	}
#else

	if (OCTEON_CN8PLUS_PF(octeon_dev->chip_id)) {
#define SDP_HOST_LOADED                 0xDEADBEEFULL
		if (OCTEON_CN83XX_PF(octeon_dev->chip_id))
			octeon_write_csr64(octeon_dev,
					   CN83XX_SLI_EPF_SCRATCH(0),
					   SDP_HOST_LOADED);
    	/* Register a Host - Firmware (OCTEON) handshake poll function */
	    poll_ops.fn = octeon_get_app_mode;
    	poll_ops.fn_arg = 0UL;
	    poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
    	strcpy(poll_ops.name, "Host Firmware Handshake Thread");
        octeon_register_poll_fn(octeon_dev->octeon_id, &poll_ops);

		/* Register a Host eth_mux - NPU base driver handshake poll function */
	poll_ops.fn = octeon_wait_for_npu_base;
    	poll_ops.fn_arg = 0UL;
	poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
    	strcpy(poll_ops.name, "Host-NPU Handshake Thread");
        octeon_register_poll_fn(octeon_dev->octeon_id, &poll_ops);
    }else {
    	/* Register a Host - Firmware (OCTEON) handshake poll function */
	    poll_ops.fn = octeon_hostfw_handshake;
    	poll_ops.fn_arg = 0UL;
	    poll_ops.ticks = CAVIUM_TICKS_PER_SEC;
    	strcpy(poll_ops.name, "Host Firmware Handshake Thread");
        octeon_register_poll_fn(octeon_dev->octeon_id, &poll_ops);
    }
#endif
	return 0;
}

/* $Id: octeon_main.c 170599 2018-03-20 13:42:25Z vvelumuri $ */
