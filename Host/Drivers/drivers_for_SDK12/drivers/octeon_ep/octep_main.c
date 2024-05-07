// SPDX-License-Identifier: GPL-2.0
/* Marvell Octeon EP (EndPoint) Ethernet Driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#include <linux/types.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/aer.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/vmalloc.h>

#include "octep_compat.h"
#include "octep_config.h"
#include "octep_main.h"
#include "octep_ctrl_net.h"
#include "octep_pfvf_mbox.h"

#define OCTEP_INTR_POLL_TIME_MSECS		100

#define OCTEP_PTM_REQ_VSEC_ID		0x3
#define OCTEP_PTM_REQ_CTL		0x8
#define OCTEP_PTM_REQ_CTL_RAUEN		0x1
#define OCTEP_PTM_REQ_CTL_RSD		0x2

struct workqueue_struct *octep_wq;

/* Supported Devices */
static const struct pci_device_id octep_pci_id_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CN98_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CN93_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CNF95O_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CNF95N_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CN10KA_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CNF10KA_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CNF10KB_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, OCTEP_PCI_DEVICE_ID_CN10KB_PF)},
	{0, },
};
MODULE_DEVICE_TABLE(pci, octep_pci_id_tbl);

MODULE_AUTHOR("Veerasenareddy Burru <vburru@marvell.com>");
MODULE_DESCRIPTION(OCTEP_DRV_STRING);
MODULE_LICENSE("GPL");

static int octep_sriov_disable(struct octep_device *oct);

/**
 * octep_alloc_ioq_vectors() - Allocate Tx/Rx Queue interrupt info.
 *
 * @oct: Octeon device private data structure.
 *
 * Allocate resources to hold per Tx/Rx queue interrupt info.
 * This is the information passed to interrupt handler, from which napi poll
 * is scheduled and includes quick access to private data of Tx/Rx queue
 * corresponding to the interrupt being handled.
 *
 * Return: 0, on successful allocation of resources for all queue interrupts.
 *         -1, if failed to allocate any resource.
 */
static int octep_alloc_ioq_vectors(struct octep_device *oct)
{
	int i;
	struct octep_ioq_vector *ioq_vector;

	for (i = 0; i < oct->num_oqs; i++) {
		oct->ioq_vector[i] = vzalloc(sizeof(*oct->ioq_vector[i]));
		if (!oct->ioq_vector[i])
			goto free_ioq_vector;

		ioq_vector = oct->ioq_vector[i];
		ioq_vector->iq = oct->iq[i];
		ioq_vector->oq = oct->oq[i];
		ioq_vector->octep_dev = oct;
	}

	dev_info(&oct->pdev->dev, "Allocated %d IOQ vectors\n", oct->num_oqs);
	return 0;

free_ioq_vector:
	while (i) {
		i--;
		vfree(oct->ioq_vector[i]);
		oct->ioq_vector[i] = NULL;
	}
	return -1;
}

/**
 * octep_free_ioq_vectors() - Free Tx/Rx Queue interrupt vector info.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_free_ioq_vectors(struct octep_device *oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		if (oct->ioq_vector[i]) {
			vfree(oct->ioq_vector[i]);
			oct->ioq_vector[i] = NULL;
		}
	}
	netdev_info(oct->netdev, "Freed IOQ Vectors\n");
}

/**
 * octep_enable_msix_range() - enable MSI-x interrupts.
 *
 * @oct: Octeon device private data structure.
 *
 * Allocate and enable all MSI-x interrupts (queue and non-queue interrupts)
 * for the Octeon device.
 *
 * Return: 0, on successfully enabling all MSI-x interrupts.
 *         -1, if failed to enable any MSI-x interrupt.
 */
static int octep_enable_msix_range(struct octep_device *oct)
{
	int num_msix, msix_allocated;
	int i;

	/* Generic interrupts apart from input/output queues */
	num_msix = oct->num_oqs + CFG_GET_NON_IOQ_MSIX(oct->conf);
	oct->msix_entries = kcalloc(num_msix,
				    sizeof(struct msix_entry), GFP_KERNEL);
	if (!oct->msix_entries)
		goto msix_alloc_err;

	for (i = 0; i < num_msix; i++)
		oct->msix_entries[i].entry = i;

	msix_allocated = pci_enable_msix_range(oct->pdev, oct->msix_entries,
					       num_msix, num_msix);
	if (msix_allocated != num_msix) {
		dev_err(&oct->pdev->dev,
			"Failed to enable %d msix irqs; got only %d\n",
			num_msix, msix_allocated);
		goto enable_msix_err;
	}
	oct->num_irqs = msix_allocated;
	dev_info(&oct->pdev->dev, "MSI-X enabled successfully\n");

	return 0;

enable_msix_err:
	if (msix_allocated > 0)
		pci_disable_msix(oct->pdev);
	kfree(oct->msix_entries);
	oct->msix_entries = NULL;
msix_alloc_err:
	return -1;
}

/**
 * octep_disable_msix() - disable MSI-x interrupts.
 *
 * @oct: Octeon device private data structure.
 *
 * Disable MSI-x on the Octeon device.
 */
static void octep_disable_msix(struct octep_device *oct)
{
	pci_disable_msix(oct->pdev);
	kfree(oct->msix_entries);
	oct->msix_entries = NULL;
	dev_info(&oct->pdev->dev, "Disabled MSI-X\n");
}

/**
 * octep_mbox_intr_handler() - common handler for pfvf mbox interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for pfvf mbox interrupts.
 */
static irqreturn_t octep_mbox_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.mbox_intr_handler(oct);
}

/**
 * octep_oei_intr_handler() - common handler for output endpoint interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for all output endpoint interrupts.
 */
static irqreturn_t octep_oei_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.oei_intr_handler(oct);
}

/**
 * octep_ire_intr_handler() - common handler for input ring error interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for input ring error interrupts.
 */
static irqreturn_t octep_ire_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.ire_intr_handler(oct);
}

/**
 * octep_ore_intr_handler() - common handler for output ring error interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for output ring error interrupts.
 */
static irqreturn_t octep_ore_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.ore_intr_handler(oct);
}

/**
 * octep_vfire_intr_handler() - common handler for vf input ring error interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for vf input ring error interrupts.
 */
static irqreturn_t octep_vfire_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	pr_info("DBG: %s", __func__);
	return oct->hw_ops.vfire_intr_handler(oct);
}

/**
 * octep_vfore_intr_handler() - common handler for vf output ring error interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for vf output ring error interrupts.
 */
static irqreturn_t octep_vfore_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.vfore_intr_handler(oct);
}

/**
 * octep_dma_intr_handler() - common handler for dpi dma related interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for dpi dma related interrupts.
 */
static irqreturn_t octep_dma_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.dma_intr_handler(oct);
}

/**
 * octep_dma_vf_intr_handler() - common handler for dpi dma transaction error interrupts for VFs.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for dpi dma transaction error interrupts for VFs.
 */
static irqreturn_t octep_dma_vf_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.dma_vf_intr_handler(oct);
}

/**
 * octep_pp_vf_intr_handler() - common handler for pp transaction error interrupts for VFs.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for pp transaction error interrupts for VFs.
 */
static irqreturn_t octep_pp_vf_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.pp_vf_intr_handler(oct);
}

/**
 * octep_misc_intr_handler() - common handler for mac related interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for mac related interrupts.
 */
static irqreturn_t octep_misc_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.misc_intr_handler(oct);
}

/**
 * octep_rsvd_intr_handler() - common handler for reserved interrupts (future use).
 *
 * @irq: Interrupt number.
 * @data: interrupt data.
 *
 * this is common handler for all reserved interrupts.
 */
static irqreturn_t octep_rsvd_intr_handler(int irq, void *data)
{
	struct octep_device *oct = data;

	return oct->hw_ops.rsvd_intr_handler(oct);
}

/**
 * octep_ioq_intr_handler() - handler for all Tx/Rx queue interrupts.
 *
 * @irq: Interrupt number.
 * @data: interrupt data contains pointers to Tx/Rx queue private data
 *         and correspong NAPI context.
 *
 * this is common handler for all non-queue (generic) interrupts.
 */
static irqreturn_t octep_ioq_intr_handler(int irq, void *data)
{
	struct octep_ioq_vector *ioq_vector = data;
	struct octep_device *oct = ioq_vector->octep_dev;

	return oct->hw_ops.ioq_intr_handler(ioq_vector);
}

/**
 * octep_request_irqs() - Register interrupt handlers.
 *
 * @oct: Octeon device private data structure.
 *
 * Register handlers for all queue and non-queue interrupts.
 *
 * Return: 0, on successful registration of all interrupt handlers.
 *         -1, on any error.
 */
static int octep_request_irqs(struct octep_device *oct)
{
	struct net_device *netdev = oct->netdev;
	struct octep_ioq_vector *ioq_vector;
	struct msix_entry *msix_entry;
	char **non_ioq_msix_names;
	int num_non_ioq_msix;
	int ret, i, j;

	num_non_ioq_msix = CFG_GET_NON_IOQ_MSIX(oct->conf);
	non_ioq_msix_names = CFG_GET_NON_IOQ_MSIX_NAMES(oct->conf);

	oct->non_ioq_irq_names = kcalloc(num_non_ioq_msix,
					 OCTEP_MSIX_NAME_SIZE, GFP_KERNEL);
	if (!oct->non_ioq_irq_names)
		goto alloc_err;

	/* First few MSI-X interrupts are non-queue interrupts */
	for (i = 0; i < num_non_ioq_msix; i++) {
		char *irq_name;

		irq_name = &oct->non_ioq_irq_names[i * OCTEP_MSIX_NAME_SIZE];
		msix_entry = &oct->msix_entries[i];

		snprintf(irq_name, OCTEP_MSIX_NAME_SIZE,
			 "%s-%s", netdev->name, non_ioq_msix_names[i]);
		if (!strncmp(non_ioq_msix_names[i], "epf_mbox_rint", strlen("epf_mbox_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_mbox_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_oei_rint",
			   strlen("epf_oei_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_oei_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_ire_rint",
			   strlen("epf_ire_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_ire_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_ore_rint",
			   strlen("epf_ore_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_ore_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_vfire_rint",
			   strlen("epf_vfire_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_vfire_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_vfore_rint",
			   strlen("epf_vfore_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_vfore_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_dma_rint",
			   strlen("epf_dma_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_dma_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_dma_vf_rint",
			   strlen("epf_dma_vf_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_dma_vf_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_pp_vf_rint",
			   strlen("epf_pp_vf_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_pp_vf_intr_handler, 0,
					  irq_name, oct);
		} else if (!strncmp(non_ioq_msix_names[i], "epf_misc_rint",
			   strlen("epf_misc_rint"))) {
			ret = request_irq(msix_entry->vector,
					  octep_misc_intr_handler, 0,
					  irq_name, oct);
		} else {
			ret = request_irq(msix_entry->vector,
					  octep_rsvd_intr_handler, 0,
					  irq_name, oct);
		}

		if (ret) {
			netdev_err(netdev,
				   "request_irq failed for %s; err=%d",
				   irq_name, ret);
			goto non_ioq_irq_err;
		}
	}

	/* Request IRQs for Tx/Rx queues */
	for (j = 0; j < oct->num_oqs; j++) {
		ioq_vector = oct->ioq_vector[j];
		msix_entry = &oct->msix_entries[j + num_non_ioq_msix];

		snprintf(ioq_vector->name, sizeof(ioq_vector->name),
			 "%s-q%d", netdev->name, j);
		ret = request_irq(msix_entry->vector,
				  octep_ioq_intr_handler, 0,
				  ioq_vector->name, ioq_vector);
		if (ret) {
			netdev_err(netdev,
				   "request_irq failed for Q-%d; err=%d",
				   j, ret);
			goto ioq_irq_err;
		}

		cpumask_set_cpu(j % num_online_cpus(),
				&ioq_vector->affinity_mask);
		irq_set_affinity_hint(msix_entry->vector,
				      &ioq_vector->affinity_mask);
	}

	return 0;
ioq_irq_err:
	while (j) {
		--j;
		ioq_vector = oct->ioq_vector[j];
		msix_entry = &oct->msix_entries[j + num_non_ioq_msix];

		irq_set_affinity_hint(msix_entry->vector, NULL);
		free_irq(msix_entry->vector, ioq_vector);
	}
non_ioq_irq_err:
	while (i) {
		--i;
		free_irq(oct->msix_entries[i].vector, oct);
	}
	kfree(oct->non_ioq_irq_names);
	oct->non_ioq_irq_names = NULL;
alloc_err:
	return -1;
}

/**
 * octep_free_irqs() - free all registered interrupts.
 *
 * @oct: Octeon device private data structure.
 *
 * Free all queue and non-queue interrupts of the Octeon device.
 */
static void octep_free_irqs(struct octep_device *oct)
{
	int i;

	/* First few MSI-X interrupts are non queue interrupts; free them */
	for (i = 0; i < CFG_GET_NON_IOQ_MSIX(oct->conf); i++)
		free_irq(oct->msix_entries[i].vector, oct);
	kfree(oct->non_ioq_irq_names);

	/* Free IRQs for Input/Output (Tx/Rx) queues */
	for (i = CFG_GET_NON_IOQ_MSIX(oct->conf); i < oct->num_irqs; i++) {
		irq_set_affinity_hint(oct->msix_entries[i].vector, NULL);
		free_irq(oct->msix_entries[i].vector,
			 oct->ioq_vector[i - CFG_GET_NON_IOQ_MSIX(oct->conf)]);
	}
	netdev_info(oct->netdev, "IRQs freed\n");
}

/**
 * octep_setup_irqs() - setup interrupts for the Octeon device.
 *
 * @oct: Octeon device private data structure.
 *
 * Allocate data structures to hold per interrupt information, allocate/enable
 * MSI-x interrupt and register interrupt handlers.
 *
 * Return: 0, on successful allocation and registration of all interrupts.
 *         -1, on any error.
 */
static int octep_setup_irqs(struct octep_device *oct)
{
	if (octep_alloc_ioq_vectors(oct))
		goto ioq_vector_err;

	if (octep_enable_msix_range(oct))
		goto enable_msix_err;

	if (octep_request_irqs(oct))
		goto request_irq_err;

	return 0;

request_irq_err:
	octep_disable_msix(oct);
enable_msix_err:
	octep_free_ioq_vectors(oct);
ioq_vector_err:
	return -1;
}

/**
 * octep_clean_irqs() - free all interrupts and its resources.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_clean_irqs(struct octep_device *oct)
{
	octep_free_irqs(oct);
	octep_disable_msix(oct);
	octep_free_ioq_vectors(oct);
}

/**
 * octep_update_pkt() - Update IQ/OQ IN/OUT_CNT registers.
 *
 * @iq: Octeon Tx queue data structure.
 * @oq: Octeon Rx queue data structure.
 */
static void octep_update_pkt(struct octep_iq *iq, struct octep_oq *oq)
{
	u32 pkts_pend = READ_ONCE(oq->pkts_pending);
	u32 last_pkt_count = READ_ONCE(oq->last_pkt_count);
	u32 pkts_processed = READ_ONCE(iq->pkts_processed);
	u32 pkt_in_done = READ_ONCE(iq->pkt_in_done);

	if (oq->suspend == true)
		return;

	netdev_dbg(iq->netdev, "enabling intr for Q-%u\n", iq->q_no);
	if (pkts_processed) {
		writel(pkts_processed, iq->inst_cnt_reg);
		readl(iq->inst_cnt_reg);
		WRITE_ONCE(iq->pkt_in_done, (pkt_in_done - pkts_processed));
		WRITE_ONCE(iq->pkts_processed, 0);
	}
	if (last_pkt_count - pkts_pend) {
		writel(last_pkt_count - pkts_pend, oq->pkts_sent_reg);
		readl(oq->pkts_sent_reg);
		WRITE_ONCE(oq->last_pkt_count, pkts_pend);
	}
	/* Flush the previous wrties before writing to RESEND bit */
	smp_wmb();
}

/**
 * octep_enable_ioq_irq() - Enable MSI-x interrupt of a Tx/Rx queue.
 *
 * @iq: Octeon Tx queue data structure.
 * @oq: Octeon Rx queue data structure.
 */
static void octep_enable_ioq_irq(struct octep_iq *iq, struct octep_oq *oq)
{
	writeq(1UL << OCTEP_OQ_INTR_RESEND_BIT, oq->pkts_sent_reg);
	writeq(1UL << OCTEP_IQ_INTR_RESEND_BIT, iq->inst_cnt_reg);
}

/**
 * octep_napi_poll() - NAPI poll function for Tx/Rx.
 *
 * @napi: pointer to napi context.
 * @budget: max number of packets to be processed in single invocation.
 */
static int octep_napi_poll(struct napi_struct *napi, int budget)
{
	struct octep_ioq_vector *ioq_vector =
		container_of(napi, struct octep_ioq_vector, napi);
	struct octep_oq *oq = ioq_vector->oq;
	u32 tx_pending, rx_done;

	if (oq->suspend == true) {
		napi_complete(napi);
		return (budget - 1);
	}

	tx_pending = octep_iq_process_completions(ioq_vector->iq, budget);
	rx_done = octep_oq_process_rx(ioq_vector->oq, budget);

	if (oq->suspend == true) {
		napi_complete(napi);
		return (budget - 1);
	}

	/* need more polling if tx completion processing is still pending or
	 * processed at least 'budget' number of rx packets.
	 */
	if (tx_pending || rx_done >= budget)
		return budget;

	octep_update_pkt(ioq_vector->iq, ioq_vector->oq);
	napi_complete_done(napi, rx_done);
	octep_enable_ioq_irq(ioq_vector->iq, ioq_vector->oq);
	return rx_done;
}

/**
 * octep_napi_add() - Add NAPI poll for all Tx/Rx queues.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_napi_add(struct octep_device *oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		netdev_dbg(oct->netdev, "Adding NAPI on Q-%d\n", i);
#if NAPI_ADD_HAS_BUDGET_ARG
		netif_napi_add(oct->netdev, &oct->ioq_vector[i]->napi, octep_napi_poll, 64);
#else
		netif_napi_add(oct->netdev, &oct->ioq_vector[i]->napi, octep_napi_poll);
#endif
		oct->oq[i]->napi = &oct->ioq_vector[i]->napi;
	}
}

/**
 * octep_napi_delete() - delete NAPI poll callback for all Tx/Rx queues.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_napi_delete(struct octep_device *oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		netdev_dbg(oct->netdev, "Deleting NAPI on Q-%d\n", i);
		netif_napi_del(&oct->ioq_vector[i]->napi);
		oct->oq[i]->napi = NULL;
	}
}

/**
 * octep_napi_enable() - enable NAPI for all Tx/Rx queues.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_napi_enable(struct octep_device *oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		netdev_dbg(oct->netdev, "Enabling NAPI on Q-%d\n", i);
		napi_enable(&oct->ioq_vector[i]->napi);
	}
}

/**
 * octep_napi_disable() - disable NAPI for all Tx/Rx queues.
 *
 * @oct: Octeon device private data structure.
 */
static void octep_napi_disable(struct octep_device *oct)
{
	int i;

	for (i = 0; i < oct->num_oqs; i++) {
		netdev_dbg(oct->netdev, "Disabling NAPI on Q-%d\n", i);
		napi_disable(&oct->ioq_vector[i]->napi);
	}
}

static void octep_link_up(struct net_device *netdev)
{
	netif_carrier_on(netdev);
	netif_tx_start_all_queues(netdev);
}

static bool octep_drv_down_in_progress(struct octep_device *oct)
{
	return test_bit(OCTEP_DEV_STATE_DOWN_IN_PROGRESS, &oct->state);
}

/**
 * octep_open() - start the octeon network device.
 *
 * @netdev: pointer to kernel network device.
 *
 * setup Tx/Rx queues, interrupts and enable hardware operation of Tx/Rx queues
 * and interrupts..
 *
 * Return: 0, on successfully setting up device and bring it up.
 *         -1, on any error.
 */
static int octep_open(struct net_device *netdev)
{
	struct octep_device *oct = netdev_priv(netdev);
	int err, ret;

	netdev_info(netdev, "Starting netdev ...\n");

	while (octep_drv_down_in_progress(oct))
		msleep(20);

	netif_carrier_off(netdev);

	oct->hw_ops.reset_io_queues(oct);

	if (octep_setup_iqs(oct))
		goto setup_iq_err;
	if (octep_setup_oqs(oct))
		goto setup_oq_err;
	if (octep_setup_irqs(oct))
		goto setup_irq_err;

	err = netif_set_real_num_tx_queues(netdev, oct->num_oqs);
	if (err)
		goto set_queues_err;
	err = netif_set_real_num_rx_queues(netdev, oct->num_iqs);
	if (err)
		goto set_queues_err;

	octep_napi_add(oct);
	octep_napi_enable(oct);

	oct->link_info.admin_up = 1;
	octep_ctrl_net_set_rx_state(oct, OCTEP_CTRL_NET_INVALID_VFID, true,
				    false);
	octep_ctrl_net_set_link_status(oct, OCTEP_CTRL_NET_INVALID_VFID, true,
				       false);
	oct->poll_non_ioq_intr = false;

	/* Enable Octeon device interrupts */
	oct->hw_ops.enable_interrupts(oct);

	/* Enable the input and output queues for this Octeon device */
	oct->hw_ops.enable_io_queues(oct);

	octep_oq_dbell_init(oct);

	ret = octep_ctrl_net_get_link_status(oct, OCTEP_CTRL_NET_INVALID_VFID);
	if (ret)
		octep_link_up(netdev);

	set_bit(OCTEP_DEV_STATE_OPEN, &oct->state);

	netdev_info(netdev, "Started netdev ...\n");

	return 0;

set_queues_err:
	octep_napi_disable(oct);
	octep_napi_delete(oct);
	octep_clean_irqs(oct);
setup_irq_err:
	octep_free_oqs(oct);
setup_oq_err:
	octep_free_iqs(oct);
setup_iq_err:
	return -1;
}

static bool octep_drv_busy(struct octep_device *oct)
{
	return test_bit(OCTEP_DEV_STATE_READ_STATS, &oct->state);
}

/**
 * octep_stop() - stop the octeon network device.
 *
 * @netdev: pointer to kernel network device.
 *
 * stop the device Tx/Rx operations, bring down the link and
 * free up all resources allocated for Tx/Rx queues and interrupts.
 */
static int octep_stop(struct net_device *netdev)
{
	struct octep_device *oct = netdev_priv(netdev);

	netdev_info(netdev, "Stopping the device ...\n");

	clear_bit(OCTEP_DEV_STATE_OPEN, &oct->state);
	smp_mb__after_atomic();
	while (octep_drv_busy(oct))
		msleep(20);

	set_bit(OCTEP_DEV_STATE_DOWN_IN_PROGRESS, &oct->state);
	smp_mb__after_atomic();

	octep_ctrl_net_set_link_status(oct, OCTEP_CTRL_NET_INVALID_VFID, false,
				       false);
	octep_ctrl_net_set_rx_state(oct, OCTEP_CTRL_NET_INVALID_VFID, false,
				    false);

	/* Stop Tx from stack */
	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	oct->link_info.admin_up = 0;
	oct->link_info.oper_up = 0;

	oct->hw_ops.disable_interrupts(oct);
	octep_napi_disable(oct);
	octep_napi_delete(oct);

	octep_clean_irqs(oct);
	octep_clean_iqs(oct);

	oct->hw_ops.disable_io_queues(oct);
	oct->hw_ops.reset_io_queues(oct);
	octep_free_oqs(oct);
	octep_free_iqs(oct);

	oct->poll_non_ioq_intr = true;
	queue_delayed_work(octep_wq, &oct->intr_poll_task,
			   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));

	clear_bit(OCTEP_DEV_STATE_DOWN_IN_PROGRESS, &oct->state);
	smp_mb__after_atomic();

	netdev_info(netdev, "Device stopped !!\n");
	return 0;
}

/**
 * octep_iq_full_check() - check if a Tx queue is full.
 *
 * @iq: Octeon Tx queue data structure.
 *
 * Return: 0, if the Tx queue is not full.
 *         1, if the Tx queue is full.
 */
static int octep_iq_full_check(struct octep_iq *iq)
{
	if (likely((IQ_INSTR_SPACE(iq)) >
		   OCTEP_WAKE_QUEUE_THRESHOLD))
		return 0;

	/* Stop the queue if unable to send */
	netif_stop_subqueue(iq->netdev, iq->q_no);

	/* check again and restart the queue, in case NAPI has just freed
	 * enough Tx ring entries.
	 */
	if (unlikely(IQ_INSTR_SPACE(iq) >
		     OCTEP_WAKE_QUEUE_THRESHOLD)) {
		netif_start_subqueue(iq->netdev, iq->q_no);
		iq->stats.restart_cnt++;
		return 0;
	}

	return 1;
}

/**
 * octep_start_xmit() - Enqueue packet to Octoen hardware Tx Queue.
 *
 * @skb: packet skbuff pointer.
 * @netdev: kernel network device.
 *
 * Return: NETDEV_TX_BUSY, if Tx Queue is full.
 *         NETDEV_TX_OK, if successfully enqueued to hardware Tx queue.
 */
static netdev_tx_t octep_start_xmit(struct sk_buff *skb,
				    struct net_device *netdev)
{
	struct octep_device *oct = netdev_priv(netdev);
	netdev_features_t feat  = netdev->features;
	struct octep_tx_sglist_desc *sglist;
	struct octep_tx_buffer *tx_buffer;
	struct octep_tx_desc_hw *hw_desc;
	struct skb_shared_info *shinfo;
	struct octep_instr_hdr *ih;
	struct octep_iq *iq;
	skb_frag_t *frag;
	u16 nr_frags, si;
	int xmit_more;
	u16 q_no, wi;

	if (skb_put_padto(skb, ETH_ZLEN))
		return NETDEV_TX_OK;

	q_no = skb_get_queue_mapping(skb);
	if (q_no >= oct->num_iqs) {
		netdev_err(netdev, "Invalid Tx skb->queue_mapping=%d\n", q_no);
		q_no = q_no % oct->num_iqs;
	}

	iq = oct->iq[q_no];
	if (octep_iq_full_check(iq)) {
		iq->stats.tx_busy++;
		return NETDEV_TX_BUSY;
	}

	shinfo = skb_shinfo(skb);
	nr_frags = shinfo->nr_frags;

	wi = iq->host_write_index;
	hw_desc = &iq->desc_ring[wi];
	hw_desc->ih64 = 0;

	tx_buffer = iq->buff_info + wi;
	tx_buffer->skb = skb;

	ih = &hw_desc->ih;
	/* TODO prefill */
	ih->pkind = oct->conf->fw_info.pkind;
	ih->fsz = oct->conf->fw_info.fsz;
	ih->tlen = skb->len + ih->fsz;

	if (!nr_frags) {
		tx_buffer->gather = 0;
		tx_buffer->dma = dma_map_single(iq->dev, skb->data,
						skb->len, DMA_TO_DEVICE);
		if (dma_mapping_error(iq->dev, tx_buffer->dma))
			goto dma_map_err;
		hw_desc->dptr = tx_buffer->dma;
	} else {
		/* Scatter/Gather */
		dma_addr_t dma;
		u16 len;

		sglist = tx_buffer->sglist;

		ih->gsz = nr_frags + 1;
		ih->gather = 1;
		tx_buffer->gather = 1;

		len = skb_headlen(skb);
		dma = dma_map_single(iq->dev, skb->data, len, DMA_TO_DEVICE);
		if (dma_mapping_error(iq->dev, dma))
			goto dma_map_err;

		memset(sglist, 0, OCTEP_SGLIST_SIZE_PER_PKT);
		sglist[0].len[3] = len;
		sglist[0].dma_ptr[0] = dma;

		si = 1; /* entry 0 is main skb, mapped above */
		frag = &shinfo->frags[0];
		while (nr_frags--) {
			len = skb_frag_size(frag);
			dma = skb_frag_dma_map(iq->dev, frag, 0,
					       len, DMA_TO_DEVICE);
			if (dma_mapping_error(iq->dev, dma))
				goto dma_map_sg_err;

			sglist[si >> 2].len[3 - (si & 3)] = len;
			sglist[si >> 2].dma_ptr[si & 3] = dma;

			frag++;
			si++;
		}
		hw_desc->dptr = tx_buffer->sglist_dma;
	}

	if (oct->conf->fw_info.tx_ol_flags) {
		if ((feat & (NETIF_F_TSO)) && (skb_is_gso(skb))) {
			hw_desc->txm.ol_flags = OCTEP_TX_OFFLOAD_CKSUM;
			hw_desc->txm.ol_flags |= OCTEP_TX_OFFLOAD_TSO;
			hw_desc->txm.gso_size =  skb_shinfo(skb)->gso_size;
			hw_desc->txm.gso_segs =  skb_shinfo(skb)->gso_segs;
		} else if (feat & (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM)) {
			hw_desc->txm.ol_flags = OCTEP_TX_OFFLOAD_CKSUM;
		}
		/* due to ESR txm will be swapped by hw */
		hw_desc->txm64[0] = cpu_to_be64(hw_desc->txm64[0]);
	}

	netdev_tx_sent_queue(iq->netdev_q, skb->len);

#if defined(NO_SKB_XMIT_MORE)
	xmit_more = netdev_xmit_more();
#else
	xmit_more = skb->xmit_more;
#endif

	skb_tx_timestamp(skb);
	iq->fill_cnt++;
	wi++;
	iq->host_write_index = wi & iq->ring_size_mask;
	if (xmit_more &&
	    (IQ_INSTR_PENDING(iq) <
	     (iq->max_count - OCTEP_WAKE_QUEUE_THRESHOLD)) &&
	    iq->fill_cnt < iq->fill_threshold)
		return NETDEV_TX_OK;

	/* Flush the hw descriptors before writing to doorbell */
	smp_wmb();
	writel(iq->fill_cnt, iq->doorbell_reg);
	iq->stats.instr_posted += iq->fill_cnt;
	iq->fill_cnt = 0;
	return NETDEV_TX_OK;

dma_map_sg_err:
	if (si > 0) {
		dma_unmap_single(iq->dev, sglist[0].dma_ptr[0],
				 sglist[0].len[0], DMA_TO_DEVICE);
		sglist[0].len[0] = 0;
	}
	while (si > 1) {
		dma_unmap_page(iq->dev, sglist[si >> 2].dma_ptr[si & 3],
			       sglist[si >> 2].len[si & 3], DMA_TO_DEVICE);
		sglist[si >> 2].len[si & 3] = 0;
		si--;
	}
	tx_buffer->gather = 0;
dma_map_err:
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

/**
 * octep_get_stats64() - Get Octeon network device statistics.
 *
 * @netdev: kernel network device.
 * @stats: pointer to stats structure to be filled in.
 */
static void octep_get_stats64(struct net_device *netdev,
			      struct rtnl_link_stats64 *stats)
{
	u64 tx_packets, tx_bytes, rx_packets, rx_bytes;
	struct octep_device *oct = netdev_priv(netdev);
	int q;

	set_bit(OCTEP_DEV_STATE_READ_STATS, &oct->state);
	smp_mb__after_atomic();
	if (!test_bit(OCTEP_DEV_STATE_OPEN, &oct->state)) {
		clear_bit(OCTEP_DEV_STATE_READ_STATS, &oct->state);
		return;
	}

	tx_packets = 0;
	tx_bytes = 0;
	rx_packets = 0;
	rx_bytes = 0;
	for (q = 0; q < oct->num_oqs; q++) {
		struct octep_iq *iq = oct->iq[q];
		struct octep_oq *oq = oct->oq[q];

		tx_packets += iq->stats.instr_completed;
		tx_bytes += iq->stats.bytes_sent;
		rx_packets += oq->stats.packets;
		rx_bytes += oq->stats.bytes;
	}
	stats->tx_packets = tx_packets;
	stats->tx_bytes = tx_bytes;
	stats->rx_packets = rx_packets;
	stats->rx_bytes = rx_bytes;
	clear_bit(OCTEP_DEV_STATE_READ_STATS, &oct->state);
}

/**
 * octep_tx_timeout_task - work queue task to Handle Tx queue timeout.
 *
 * @work: pointer to Tx queue timeout work_struct
 *
 * Stop and start the device so that it frees up all queue resources
 * and restarts the queues, that potentially clears a Tx queue timeout
 * condition.
 **/
static void octep_tx_timeout_task(struct work_struct *work)
{
	struct octep_device *oct = container_of(work, struct octep_device,
						tx_timeout_task);
	struct net_device *netdev = oct->netdev;

	rtnl_lock();
	if (netif_running(netdev)) {
		octep_stop(netdev);
		octep_open(netdev);
	}
	rtnl_unlock();
}

/**
 * octep_tx_timeout() - Handle Tx Queue timeout.
 *
 * @netdev: pointer to kernel network device.
 * @txqueue: Timed out Tx queue number.
 *
 * Schedule a work to handle Tx queue timeout.
 */
#if TX_TIMEOUT_HAS_TXQ_ARG
static void octep_tx_timeout(struct net_device *netdev, unsigned int txqueue)
#else
static void octep_tx_timeout(struct net_device *netdev)
#endif
{
	struct octep_device *oct = netdev_priv(netdev);

	queue_work(octep_wq, &oct->tx_timeout_task);
}

static int octep_set_mac(struct net_device *netdev, void *p)
{
	struct octep_device *oct = netdev_priv(netdev);
	struct sockaddr *addr = (struct sockaddr *)p;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	err = octep_ctrl_net_set_mac_addr(oct, OCTEP_CTRL_NET_INVALID_VFID,
					  addr->sa_data, true);
	if (err)
		return err;

	memcpy(oct->mac_addr, addr->sa_data, ETH_ALEN);
#if defined(USE_ETHER_ADDR_COPY)
	ether_addr_copy(netdev->dev_addr, addr->sa_data);
#else
	eth_hw_addr_set(netdev, addr->sa_data);
#endif

	return 0;
}

static int octep_change_mtu(struct net_device *netdev, int new_mtu)
{
	struct octep_device *oct = netdev_priv(netdev);
	struct octep_iface_link_info *link_info;
	int err = 0;

	link_info = &oct->link_info;
	if (link_info->mtu == new_mtu)
		return 0;

	err = octep_ctrl_net_set_mtu(oct, OCTEP_CTRL_NET_INVALID_VFID, new_mtu,
				     true);
	if (!err) {
		oct->link_info.mtu = new_mtu;
		netdev->mtu = new_mtu;
	}

	return err;
}

static int octep_get_vf_config(struct net_device *dev, int vf, struct ifla_vf_info *ivi)
{
	struct octep_device *oct = netdev_priv(dev);

	ivi->vf = vf;
	ether_addr_copy(ivi->mac, oct->vf_info[vf].mac_addr);
	ivi->vlan = 0;
	ivi->qos = 0;
	ivi->spoofchk = 0;
	ivi->linkstate = IFLA_VF_LINK_STATE_ENABLE;
	ivi->trusted = true;
	ivi->max_tx_rate = 10000;
	ivi->min_tx_rate = 0;

	return 0;
}

static int octep_set_vf_mac(struct net_device *dev, int vf, u8 *mac)
{
	struct octep_device *oct = netdev_priv(dev);
	int i;

	if (!is_valid_ether_addr(mac)) {
		dev_err(&oct->pdev->dev, "Invalid  MAC Address %pM\n", mac);
		return -EADDRNOTAVAIL;
	}

	dev_dbg(&oct->pdev->dev, "set vf-%d mac to %pM\n", vf, mac);
	for (i = 0; i < ETH_ALEN; i++)
		oct->vf_info[vf].mac_addr[i] = mac[i];
	oct->vf_info[vf].flags |=  OCTEON_PFVF_FLAG_MAC_SET_BY_PF;
	return 0;
}

static int octep_set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos, __be16 vlan_proto)
{
	struct octep_device *oct = netdev_priv(dev);

	dev_err(&oct->pdev->dev, "Setting VF VLAN not supported\n");
	return 0;
}

static int octep_set_vf_spoofchk(struct net_device *dev, int vf, bool setting)
{
	struct octep_device *oct = netdev_priv(dev);

	dev_err(&oct->pdev->dev, "Setting VF spoof check not supported\n");
	return 0;
}

static int octep_set_vf_trust(struct net_device *dev, int vf, bool setting)
{
	struct octep_device *oct = netdev_priv(dev);

	dev_err(&oct->pdev->dev, "Setting VF trust not supported\n");
	return 0;
}

static int octep_set_vf_rate(struct net_device *dev, int vf, int min_tx_rate, int max_tx_rate)
{
	struct octep_device *oct = netdev_priv(dev);

	dev_err(&oct->pdev->dev, "Setting VF rate not supported\n");
	return 0;
}

static int octep_set_vf_link_state(struct net_device *dev, int vf, int link_state)
{
	struct octep_device *oct = netdev_priv(dev);

	dev_err(&oct->pdev->dev, "Setting VF link state not supported\n");
	return 0;
}

static int octep_get_vf_stats(struct net_device *dev, int vf, struct ifla_vf_stats *vf_stats)
{
	printk_once("Octeon: Getting VF stats not supported\n");
	return 0;
}

static netdev_features_t octep_fix_features(struct net_device *dev,
					    netdev_features_t features)
{
	return (dev->hw_features & features);
}

static int octep_set_features(struct net_device *dev, netdev_features_t features)
{
	struct octep_ctrl_net_offloads offloads = { 0 };
	struct octep_device *oct = netdev_priv(dev);
	int err;

	/* We only support features received from firmware */
	if ((features & dev->hw_features) != features)
		return -EINVAL;

	if (features & NETIF_F_TSO)
		offloads.tx_offloads |= OCTEP_TX_OFFLOAD_TSO;

	if (features & NETIF_F_TSO6)
		offloads.tx_offloads |= OCTEP_TX_OFFLOAD_TSO;

	if (features & NETIF_F_IP_CSUM)
		offloads.tx_offloads |= OCTEP_TX_OFFLOAD_CKSUM;

	if (features & NETIF_F_IPV6_CSUM)
		offloads.tx_offloads |= OCTEP_TX_OFFLOAD_CKSUM;

	if (features & NETIF_F_RXCSUM)
		offloads.rx_offloads |= OCTEP_RX_OFFLOAD_CKSUM;

	err = octep_ctrl_net_set_offloads(oct,
					  OCTEP_CTRL_NET_INVALID_VFID,
					  &offloads,
					  true);
	if (!err)
		dev->features = features;

	return err;
}

static const struct net_device_ops octep_netdev_ops = {
	.ndo_open                = octep_open,
	.ndo_stop                = octep_stop,
	.ndo_start_xmit          = octep_start_xmit,
	.ndo_get_stats64         = octep_get_stats64,
	.ndo_tx_timeout          = octep_tx_timeout,
	.ndo_set_mac_address     = octep_set_mac,
	.ndo_change_mtu          = octep_change_mtu,
	.ndo_fix_features        = octep_fix_features,
	.ndo_set_features        = octep_set_features,
	/* for VFs */
	.ndo_get_vf_config       = octep_get_vf_config,
	.ndo_set_vf_mac          = octep_set_vf_mac,
	.ndo_set_vf_vlan         = octep_set_vf_vlan,
	.ndo_set_vf_spoofchk     = octep_set_vf_spoofchk,
	.ndo_set_vf_trust        = octep_set_vf_trust,
	.ndo_set_vf_rate         = octep_set_vf_rate,
	.ndo_set_vf_link_state   = octep_set_vf_link_state,
	.ndo_get_vf_stats        = octep_get_vf_stats,
};

/* Cancel all tasks except hb task */
static void cancel_all_tasks(struct octep_device *oct)
{
	cancel_work_sync(&oct->tx_timeout_task);
	cancel_work_sync(&oct->ctrl_mbox_task);
	oct->poll_non_ioq_intr = false;
	cancel_delayed_work_sync(&oct->intr_poll_task);
	octep_delete_pfvf_mbox(oct);
	octep_ctrl_net_uninit(oct);
}

/**
 * octep_hb_timeout_task - work queue task to check firmware heartbeat.
 *
 * @work: pointer to hb work_struct
 *
 * Check for heartbeat miss count. Uninitialize oct device if miss count
 * exceeds configured max heartbeat miss count.
 *
 **/
static void octep_hb_timeout_task(struct work_struct *work)
{
	struct octep_device *oct = container_of(work, struct octep_device,
						hb_task.work);

	int status, miss_cnt;

	status = atomic_read(&oct->status);
	if (status != OCTEP_DEV_STATUS_INIT &&
	    status != OCTEP_DEV_STATUS_READY)
		return;

	miss_cnt = atomic_inc_return(&oct->hb_miss_cnt);
	if (miss_cnt < oct->conf->fw_info.hb_miss_count) {
		queue_delayed_work(octep_wq, &oct->hb_task,
				   msecs_to_jiffies(oct->conf->fw_info.hb_interval));
		return;
	}

	dev_err(&oct->pdev->dev, "Missed %u heartbeats. carrier off\n",
		miss_cnt);
	netif_carrier_off(oct->netdev);
}

/**
 * octep_intr_poll_task - work queue task to process non-ioq interrupts.
 *
 * @work: pointer to mbox work_struct
 *
 * Process non-ioq interrupts to handle control mailbox, pfvf mailbox.
 **/
static void octep_intr_poll_task(struct work_struct *work)
{
	struct octep_device *oct = container_of(work, struct octep_device,
						intr_poll_task.work);
	int status;

	status = atomic_read(&oct->status);
	if ((status != OCTEP_DEV_STATUS_INIT &&
	     status != OCTEP_DEV_STATUS_READY) ||
	    !oct->poll_non_ioq_intr) {
		dev_info(&oct->pdev->dev, "Interrupt poll task stopped.\n");
		return;
	}

	oct->hw_ops.poll_non_ioq_interrupts(oct);
	queue_delayed_work(octep_wq, &oct->intr_poll_task,
			   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));
}

/**
 * octep_ctrl_mbox_task - work queue task to process ctrl mbox messages.
 *
 * @work: pointer to mbox work_struct
 *
 * Poll ctrl mailbox and process messages.
 **/
static void octep_ctrl_mbox_task(struct work_struct *work)
{
	struct octep_device *oct = container_of(work, struct octep_device,
						ctrl_mbox_task);
	int status;

	status = atomic_read(&oct->status);
	if (status != OCTEP_DEV_STATUS_INIT &&
	    status != OCTEP_DEV_STATUS_READY)
		return;

	octep_ctrl_net_recv_fw_messages(oct);
}

static const char *octep_devid_to_str(struct octep_device *oct)
{
	switch (oct->chip_id) {
	case OCTEP_PCI_DEVICE_ID_CN98_PF:
		return "CN98XX";
	case OCTEP_PCI_DEVICE_ID_CN93_PF:
		return "CN93XX";
	case OCTEP_PCI_DEVICE_ID_CNF95O_PF:
		return "CNF95O";
	case OCTEP_PCI_DEVICE_ID_CNF95N_PF:
		return "CNF95N";
	case OCTEP_PCI_DEVICE_ID_CN10KA_PF:
		return "CN10KA";
	case OCTEP_PCI_DEVICE_ID_CNF10KA_PF:
		return "CNF10KA";
	case OCTEP_PCI_DEVICE_ID_CNF10KB_PF:
		return "CNF10KB";
	case OCTEP_PCI_DEVICE_ID_CN10KB_PF:
		return "CN10KB";
	default:
		return "Unsupported";
	}
}

/**
 * octep_device_setup() - Setup Octeon Device.
 *
 * @oct: Octeon device private data structure.
 *
 * Setup Octeon device hardware operations, configuration, etc ...
 */
int octep_device_setup(struct octep_device *oct)
{
	struct pci_dev *pdev = oct->pdev;
	int i, err;

	/* allocate memory for oct->conf */
	oct->conf = kzalloc(sizeof(*oct->conf), GFP_KERNEL);
	if (!oct->conf)
		return -ENOMEM;

	/* Map BAR regions */
	for (i = 0; i < OCTEP_MMIO_REGIONS; i++) {
		oct->mmio[i].hw_addr =
			ioremap(pci_resource_start(oct->pdev, i * 2),
				pci_resource_len(oct->pdev, i * 2));
		if (!oct->mmio[i].hw_addr) {
			dev_err(&pdev->dev,
				"Failed to remap BAR-%d; start=0x%llx len=0x%llx\n",
				i, pci_resource_start(oct->pdev, i * 2),
				pci_resource_len(oct->pdev, i * 2));
			goto ioremap_err;
		}
		oct->mmio[i].mapped = 1;
	}

	oct->chip_id = pdev->device;
	oct->rev_id = pdev->revision;
	dev_info(&pdev->dev, "chip_id = 0x%x\n", pdev->device);

	switch (oct->chip_id) {
	case OCTEP_PCI_DEVICE_ID_CN98_PF:
	case OCTEP_PCI_DEVICE_ID_CN93_PF:
	case OCTEP_PCI_DEVICE_ID_CNF95O_PF:
	case OCTEP_PCI_DEVICE_ID_CNF95N_PF:
		dev_info(&pdev->dev, "Setting up OCTEON %s PF PASS%d.%d\n",
			 octep_devid_to_str(oct), OCTEP_MAJOR_REV(oct), OCTEP_MINOR_REV(oct));
		octep_device_setup_cn93_pf(oct);
		break;
	case OCTEP_PCI_DEVICE_ID_CNF10KA_PF:
	case OCTEP_PCI_DEVICE_ID_CN10KA_PF:
	case OCTEP_PCI_DEVICE_ID_CNF10KB_PF:
	case OCTEP_PCI_DEVICE_ID_CN10KB_PF:
		dev_info(&pdev->dev, "Setting up OCTEON %s PF PASS%d.%d\n",
			 octep_devid_to_str(oct), OCTEP_MAJOR_REV(oct), OCTEP_MINOR_REV(oct));
		octep_device_setup_cnxk_pf(oct);
		break;
	default:
		dev_err(&pdev->dev,
			"%s: unsupported device\n", __func__);
		goto unsupported_dev;
	}

	err = octep_ctrl_net_init(oct);
	if (err)
		return err;

	err = octep_setup_pfvf_mbox(oct);
	if (err) {
		dev_err(&pdev->dev, " pfvf mailbox setup failed\n");
		octep_ctrl_net_uninit(oct);
		return err;
	}

	INIT_WORK(&oct->tx_timeout_task, octep_tx_timeout_task);
	INIT_WORK(&oct->ctrl_mbox_task, octep_ctrl_mbox_task);
	INIT_DELAYED_WORK(&oct->intr_poll_task, octep_intr_poll_task);
	oct->poll_non_ioq_intr = true;
	queue_delayed_work(octep_wq, &oct->intr_poll_task,
			   msecs_to_jiffies(OCTEP_INTR_POLL_TIME_MSECS));

	atomic_set(&oct->hb_miss_cnt, 0);
	INIT_DELAYED_WORK(&oct->hb_task, octep_hb_timeout_task);

	return 0;

ioremap_err:
	while (i) {
		i--;
		iounmap(oct->mmio[i].hw_addr);
		oct->mmio[i].mapped = 0;
	}
	kfree(oct->conf);
	oct->conf = NULL;
unsupported_dev:
	return -1;
}

/**
 * octep_device_cleanup() - Cleanup Octeon Device.
 *
 * @oct: Octeon device private data structure.
 *
 * Cleanup Octeon device allocated resources.
 */
static void octep_device_cleanup(struct octep_device *oct)
{
	int i;

	dev_info(&oct->pdev->dev, "Cleaning up Octeon Device ...\n");
	cancel_all_tasks(oct);
	cancel_delayed_work_sync(&oct->hb_task);

	oct->hw_ops.soft_reset(oct);
	for (i = 0; i < OCTEP_MMIO_REGIONS; i++) {
		if (oct->mmio[i].mapped)
			iounmap(oct->mmio[i].hw_addr);
	}

	kfree(oct->conf);
	oct->conf = NULL;
}

static bool get_fw_ready_status(struct octep_device *oct)
{
	u32 pos = 0;
	u16 vsec_id;
	u8 status = 0;

	while ((pos = pci_find_next_ext_capability(oct->pdev, pos,
						   PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(oct->pdev, pos + 4, &vsec_id);
#define FW_STATUS_VSEC_ID  0xA3
		if (vsec_id != FW_STATUS_VSEC_ID)
			continue;

		pci_read_config_byte(oct->pdev, (pos + 8), &status);
		dev_info(&oct->pdev->dev, "Firmware ready status = %u\n", status);
#define FW_STATUS_READY 1ULL
		return (status == FW_STATUS_READY) ? true : false;
	}
	return false;
}

/**
 * octep_dev_setup_task - work queue task to setup octep device.
 *
 * @work: pointer to dev setup work_struct
 *
 * Wait for firmware to be ready, then continue with device setup.
 * Check for module exit while waiting for firmware.
 *
 **/
static void octep_dev_setup_task(struct work_struct *work)
{
	struct octep_device *oct = container_of(work, struct octep_device,
						dev_setup_task);
	struct net_device *netdev = oct->netdev;
	int max_rx_pktlen;
	int err;

	atomic_set(&oct->status, OCTEP_DEV_STATUS_WAIT_FOR_FW);
	while (true) {
		if (get_fw_ready_status(oct))
			break;

		schedule_timeout_interruptible(HZ * 1);

		if (atomic_read(&oct->status) >= OCTEP_DEV_STATUS_READY) {
			dev_info(&oct->pdev->dev,
				 "Stopping firmware ready work.\n");
			return;
		}
		if (atomic_read(&oct->status) == OCTEP_DEV_STATUS_ALLOC) {
			dev_info(&oct->pdev->dev,
				 "Quitting scheduled work.\n");
			return;
		}
	}

	/* Do not free resources on failure. driver unload will
	 * lead to freeing resources.
	 */
	atomic_set(&oct->status, OCTEP_DEV_STATUS_INIT);
	err = octep_device_setup(oct);
	if (err) {
		dev_err(&oct->pdev->dev, "Device setup failed\n");
		atomic_set(&oct->status, OCTEP_DEV_STATUS_ALLOC);
		return;
	}

	octep_ctrl_net_get_info(oct, OCTEP_CTRL_NET_INVALID_VFID,
				&oct->conf->fw_info);
	dev_info(&oct->pdev->dev, "Heartbeat interval %u msecs Heartbeat miss count %u\n",
		 oct->conf->fw_info.hb_interval,
		 oct->conf->fw_info.hb_miss_count);
	queue_delayed_work(octep_wq, &oct->hb_task,
			   msecs_to_jiffies(oct->conf->fw_info.hb_interval));

	netdev->netdev_ops = &octep_netdev_ops;
	octep_set_ethtool_ops(netdev);
	netif_carrier_off(netdev);

	netdev->hw_features = NETIF_F_SG;
	if (OCTEP_TX_IP_CSUM(oct->conf->fw_info.tx_ol_flags))
		netdev->hw_features |= (NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM);

	if (OCTEP_RX_IP_CSUM(oct->conf->fw_info.rx_ol_flags))
		netdev->hw_features |= NETIF_F_RXCSUM;

	max_rx_pktlen = octep_ctrl_net_get_mtu(oct, OCTEP_CTRL_NET_INVALID_VFID);
	if (max_rx_pktlen < 0) {
		dev_err(&oct->pdev->dev,
			"Failed to get max receive packet size; err = %d\n", max_rx_pktlen);
		atomic_set(&oct->status, OCTEP_DEV_STATUS_INIT);
		return;
	}
	netdev->min_mtu = OCTEP_MIN_MTU;
	netdev->max_mtu = max_rx_pktlen - (ETH_HLEN + ETH_FCS_LEN);
	netdev->mtu = OCTEP_DEFAULT_MTU;

	if (OCTEP_TX_TSO(oct->conf->fw_info.tx_ol_flags)) {
		netdev->hw_features |= NETIF_F_TSO;
#if defined(NO_SET_GSO_API)
		netif_set_tso_max_size(netdev, netdev->max_mtu);
#else
		netif_set_gso_max_size(netdev, netdev->max_mtu);
#endif
	}

	netdev->features |= netdev->hw_features;

	octep_ctrl_net_get_mac_addr(oct, OCTEP_CTRL_NET_INVALID_VFID,
				    oct->mac_addr);
#if defined(USE_ETHER_ADDR_COPY)
	ether_addr_copy(netdev->dev_addr, oct->mac_addr);
	ether_addr_copy(netdev->perm_addr, oct->mac_addr);
#else
	eth_hw_addr_set(netdev, oct->mac_addr);
#endif

	err = register_netdev(netdev);
	if (err) {
		dev_err(&oct->pdev->dev, "Failed to register netdev\n");
		atomic_set(&oct->status, OCTEP_DEV_STATUS_INIT);
		return;
	}
	atomic_set(&oct->status, OCTEP_DEV_STATUS_READY);
	dev_info(&oct->pdev->dev, "Device setup successful\n");
}

#ifdef CONFIG_PCIE_PTM
static int find_ptm_req_vsec(struct pci_dev *pdev)
{
	int vsec = 0;
	u16 val;

	while ((vsec = pci_find_next_ext_capability(pdev, vsec, PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(pdev, vsec + PCI_VNDR_HEADER, &val);
		if (val == OCTEP_PTM_REQ_VSEC_ID)
			return vsec;
	}

	return 0;
}

static void octep_enable_ptm(struct pci_dev *pdev)
{
	int vsec = 0;
	u32 val;
	int err;

	err = pci_enable_ptm(pdev, NULL);
	if (err < 0)
		dev_info(&pdev->dev, "PCIe PTM not supported by PCIe bus/controller\n");
	else {
		/* Vendor Specific PTM Configuration */
		vsec = find_ptm_req_vsec(pdev);
		if (!vsec)
			dev_info(&pdev->dev, "No vendor specific PTM Requester capability found\n");
		else {
			pci_read_config_dword(pdev, vsec + OCTEP_PTM_REQ_CTL, &val);
			/* enable PTM requester auto update and requester start update */
			val |= (OCTEP_PTM_REQ_CTL_RAUEN | OCTEP_PTM_REQ_CTL_RSD);
			pci_write_config_dword(pdev, vsec + OCTEP_PTM_REQ_CTL, val);
		}
	}
}
#else
static inline void octep_enable_ptm(struct pci_dev *pdev) { }
#endif

/**
 * octep_probe() - Octeon PCI device probe handler.
 *
 * @pdev: PCI device structure.
 * @ent: entry in Octeon PCI device ID table.
 *
 * Initializes and enables the Octeon PCI device for network operations.
 * Initializes Octeon private data structure and registers a network device.
 */
static int octep_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct octep_device *octep_dev = NULL;
	struct net_device *netdev;
	int err;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Failed to enable PCI device\n");
		return  err;
	}

	err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (err) {
		dev_err(&pdev->dev, "Failed to set DMA mask !!\n");
		goto err_dma_mask;
	}

	err = pci_request_mem_regions(pdev, OCTEP_DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Failed to map PCI memory regions\n");
		goto err_pci_regions;
	}

	pci_enable_pcie_error_reporting(pdev);
	octep_enable_ptm(pdev);
	pci_set_master(pdev);

	netdev = alloc_etherdev_mq(sizeof(struct octep_device),
				   OCTEP_MAX_QUEUES);
	if (!netdev) {
		dev_err(&pdev->dev, "Failed to allocate netdev\n");
		err = -ENOMEM;
		goto err_alloc_netdev;
	}
	SET_NETDEV_DEV(netdev, &pdev->dev);

	octep_dev = netdev_priv(netdev);
	octep_dev->netdev = netdev;
	octep_dev->pdev = pdev;
	octep_dev->dev = &pdev->dev;
	pci_set_drvdata(pdev, octep_dev);

	atomic_set(&octep_dev->status, OCTEP_DEV_STATUS_ALLOC);
	INIT_WORK(&octep_dev->dev_setup_task, octep_dev_setup_task);
	schedule_work(&octep_dev->dev_setup_task);
	dev_info(&pdev->dev, "Device setup task queued\n");

	clear_bit(OCTEP_DEV_STATE_OPEN, &octep_dev->state);

	return 0;

err_alloc_netdev:
	pci_disable_pcie_error_reporting(pdev);
	pci_release_mem_regions(pdev);
err_pci_regions:
err_dma_mask:
	pci_disable_device(pdev);
	return err;
}

/**
 * octep_remove() - Remove Octeon PCI device from driver control.
 *
 * @pdev: PCI device structure of the Octeon device.
 *
 * Cleanup all resources allocated for the Octeon device.
 * Unregister from network device and disable the PCI device.
 */
static void octep_remove(struct pci_dev *pdev)
{
	struct octep_device *oct = pci_get_drvdata(pdev);
	int status;

	if (!oct)
		return;

	dev_info(&pdev->dev, "Removing device.\n");
	status = atomic_read(&oct->status);
	if (status <= OCTEP_DEV_STATUS_ALLOC)
		goto free_resources;

	if (status == OCTEP_DEV_STATUS_READY)
		octep_sriov_disable(oct);
	if (status == OCTEP_DEV_STATUS_WAIT_FOR_FW) {
		atomic_set(&oct->status, OCTEP_DEV_STATUS_UNINIT);
		cancel_work_sync(&oct->dev_setup_task);
		goto free_resources;
	}
	/* Wait for the device setup task to complete
	 * in case it has proceeded to setup device
	 * after detecting fw ready
	 */
	flush_work(&oct->dev_setup_task);
	atomic_set(&oct->status, OCTEP_DEV_STATUS_UNINIT);

	if (oct->netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(oct->netdev);

	octep_device_cleanup(oct);

free_resources:
	pci_release_mem_regions(pdev);
	free_netdev(oct->netdev);
	pci_disable_pcie_error_reporting(pdev);
	pci_disable_device(pdev);
}

static int octep_sriov_disable(struct octep_device *oct)
{
	struct pci_dev *pdev = oct->pdev;

	if (pci_vfs_assigned(oct->pdev)) {
		dev_warn(&pdev->dev, "Can't disable SRIOV while VFs are assigned\n");
		return -EPERM;
	}

	pci_disable_sriov(pdev);
	CFG_GET_ACTIVE_VFS(oct->conf) = 0;

	return 0;
}

static int octep_sriov_enable(struct octep_device *oct, int num_vfs)
{
	struct pci_dev *pdev = oct->pdev;
	int err;

	CFG_GET_ACTIVE_VFS(oct->conf) = num_vfs;
	err = pci_enable_sriov(pdev, num_vfs);
	if (err) {
		dev_warn(&pdev->dev, "Failed to enable SRIOV err=%d\n", err);
		CFG_GET_ACTIVE_VFS(oct->conf) = 0;
		return err;
	}

	return num_vfs;
}

static int octep_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	struct octep_device *oct = pci_get_drvdata(pdev);
	int max_nvfs, status;

	status = atomic_read(&oct->status);
	if (status != OCTEP_DEV_STATUS_READY)
		return -EAGAIN;

	if (num_vfs == 0)
		return octep_sriov_disable(oct);

	max_nvfs = CFG_GET_MAX_VFS(oct->conf);

	if (num_vfs > max_nvfs) {
		dev_err(&pdev->dev, "Invalid VF count Max supported VFs = %d\n",
			max_nvfs);
		return -EINVAL;
	}

	return octep_sriov_enable(oct, num_vfs);
}

static int octep_reset_prepare(struct pci_dev *pdev)
{
	struct octep_device *oct = pci_get_drvdata(pdev);
	struct net_device *netdev = oct->netdev;

	dev_info(&pdev->dev, "A Start octep_reset_prepare ...\n");

	oct->poll_non_ioq_intr = false;
	clear_bit(OCTEP_DEV_STATE_OPEN, &oct->state);
	smp_mb__after_atomic();
	while (octep_drv_busy(oct))
		msleep(20);
	dev_info(&pdev->dev, "B Start octep_reset_prepare ...\n");

	/* Stop Tx from stack */
	netif_tx_stop_all_queues(netdev);
	netif_carrier_off(netdev);
	netif_tx_disable(netdev);

	oct->hw_ops.disable_interrupts(oct);
	oct->hw_ops.disable_io_queues(oct);
	cancel_delayed_work_sync(&oct->intr_poll_task);
	dev_info(&pdev->dev, "Done octep_reset_prepare ...\n");
	return 0;
}

static int octep_reset_done(struct pci_dev *pdev)
{
	struct octep_device *oct = pci_get_drvdata(pdev);

	dev_info(&pdev->dev, "Start octep_reset_done ...\n");

	set_bit(OCTEP_DEV_STATE_OPEN, &oct->state);
	dev_info(&pdev->dev, "Done octep_reset_done ...\n");
	return 0;
}

void octep_cleanup_aer_uncorrect_error_status(struct pci_dev *pdev)
{
	int pos = 0x100;
	u32 status, mask;

	pci_read_config_dword(pdev, pos + PCI_ERR_UNCOR_STATUS, &status);
	pci_read_config_dword(pdev, pos + PCI_ERR_UNCOR_SEVER, &mask);
	if (pdev->error_state == pci_channel_io_normal)
		status &= ~mask;        /* Clear corresponding nonfatal bits */
	else
		status &= mask; /* Clear corresponding fatal bits */
	pci_write_config_dword(pdev, pos + PCI_ERR_UNCOR_STATUS, status);
	dev_info(&pdev->dev, "octeon_cleanup_aer_uncorrect_error_status");

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
octep_pcie_error_detected(struct pci_dev *pdev, pci_channel_state_t state)
{
	struct octep_device *oct = pci_get_drvdata(pdev);

	/* Non-correctable Non-fatal errors */
	if (state == pci_channel_io_normal) {
		dev_err(&pdev->dev, "Non-correctable non-fatal error reported.\n");
		octep_cleanup_aer_uncorrect_error_status(oct->pdev);
		return PCI_ERS_RESULT_CAN_RECOVER;
	}
	/* Non-correctable Fatal errors */
	dev_err(&pdev->dev, "PCIe error Non-correctable FATAL reported by AER driver\n");
	/* Always return a DISCONNECT. There is no support for recovery but only
	 * for a clean shutdown. */
	return PCI_ERS_RESULT_DISCONNECT;
}

pci_ers_result_t octep_pcie_mmio_enabled(struct pci_dev *pdev)
{
	/* We should never hit this since we never ask for a reset for a Fatal
	 * Error. We always return DISCONNECT in io_error above. */
	/* But play safe and return RECOVERED for now. */
	dev_err(&pdev->dev, "octep_pcie_mmio_enabled\n");
	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * octep_pcie_slot_reset - called after the pci bus has been reset.
 * @pdev: Pointer to PCI device
 *
 * Restart the card from scratch, as if from a cold-boot. Implementation
 * resembles the first-half of the octeon_resume routine.
 */
pci_ers_result_t octep_pcie_slot_reset(struct pci_dev * pdev)
{
	/* We should never hit this since we never ask for a reset for a Fatal
	 * Error. We always return DISCONNECT in io_error above. */
	/* But play safe and return RECOVERED for now. */
	dev_err(&pdev->dev, "octep_pcie_slot_reset\n");
	return PCI_ERS_RESULT_RECOVERED;
}

/**
 * octep_pcie_resume - called when traffic can start flowing again.
 * @pdev: Pointer to PCI device
 *
 * This callback is called when the error recovery driver tells us that
 * its OK to resume normal operation. Implementation resembles the
 * second-half of the octeon_resume routine.
 */
void octep_pcie_resume(struct pci_dev *pdev)
{
	dev_err(&pdev->dev, "octep_pcie_resume\n");
	/* Nothing to be done here. */
}

/**
 * octep_pci_error_reset_prepare - prepare device driver for pci reset
 * @pdev: PCI device information struct
 */
static void octep_pci_error_reset_prepare(struct pci_dev *pdev)
{
	struct octep_device *oct = pci_get_drvdata(pdev);
	int num_vfs = 0, vf_idx = 0;
	union octep_pfvf_mbox_word notif = { 0 };

	dev_info(&pdev->dev, "Reset prepare state:%ld status:%d\n",
		 oct->state, atomic_read(&oct->status));

	if (oct->state && (atomic_read(&oct->status) == OCTEP_DEV_STATUS_READY)) {
		num_vfs = CFG_GET_ACTIVE_VFS(oct->conf);
		dev_info(&pdev->dev, "Reset prepare num Vfs:%d\n", num_vfs);

		/* Broadcast to all VF's about PF is going to initiate reset */
		for (vf_idx = 0; vf_idx < num_vfs; vf_idx++) {
			notif.s_link_status.opcode = OCTEP_PFVF_MBOX_NOTIF_PF_FLR;
			notif.s_link_status.status = 0;
			notif.s.type = OCTEP_PFVF_MBOX_TYPE_CMD;
			octep_send_notification(oct, vf_idx, notif);
			dev_info(&pdev->dev, "Reset prepare sent RESET to Vf:%d\n",
				 vf_idx);
		}
		msleep(5);
		octep_reset_prepare(pdev);
	} else if (atomic_read(&oct->status) == OCTEP_DEV_STATUS_WAIT_FOR_FW) {
		dev_info(&pdev->dev, "Reset prepare OCTEP STATUS WAIT FOR FW Started\n");
		atomic_set(&oct->status, OCTEP_DEV_STATUS_ALLOC);
		msleep(2);
		cancel_work_sync(&oct->dev_setup_task);
		dev_info(&pdev->dev, "Reset prepare OCTEP STATUS WAIT FOR FW Done\n");
	}
}

/**
 * octep_pci_error_reset_done - pci reset done, device driver reset can begin
 * @pdev: PCI device information struct
 */
static void octep_pci_error_reset_done(struct pci_dev *pdev)
{
	struct octep_device *oct = pci_get_drvdata(pdev);

	dev_info(&pdev->dev, "Reset done state:%ld status:%d\n",
		 oct->state, atomic_read(&oct->status));

	if (!oct->state && (atomic_read(&oct->status) == OCTEP_DEV_STATUS_READY)) {
		octep_reset_done(pdev);
		dev_info(&pdev->dev, "After reset done state:%ld status:%d\n",
			 oct->state, atomic_read(&oct->status));
	}
}

/* For PCI-E Advanced Error Recovery (AER) Interface */
static struct pci_error_handlers octeon_err_handler = {
	.error_detected = octep_pcie_error_detected,
	.mmio_enabled = octep_pcie_mmio_enabled,
	.slot_reset = octep_pcie_slot_reset,
	.reset_prepare = octep_pci_error_reset_prepare,
	.reset_done = octep_pci_error_reset_done,
	.resume = octep_pcie_resume,
};

static struct pci_driver octep_driver = {
	.name = OCTEP_DRV_NAME,
	.id_table = octep_pci_id_tbl,
	.probe = octep_probe,
	.remove = octep_remove,
	.sriov_configure = octep_sriov_configure,
	.err_handler = &octeon_err_handler,
};

/**
 * octep_init_module() - Module initialiation.
 *
 * create common resource for the driver and register PCI driver.
 */
static int __init octep_init_module(void)
{
	int ret;

	pr_info("%s: Loading %s ...\n", OCTEP_DRV_NAME, OCTEP_DRV_STRING);

	/* work queue for all deferred tasks */
	octep_wq = create_singlethread_workqueue(OCTEP_DRV_NAME);
	if (!octep_wq) {
		pr_err("%s: Failed to create common workqueue\n",
		       OCTEP_DRV_NAME);
		return -ENOMEM;
	}

	ret = pci_register_driver(&octep_driver);
	if (ret < 0) {
		pr_err("%s: Failed to register PCI driver; err=%d\n",
		       OCTEP_DRV_NAME, ret);
		destroy_workqueue(octep_wq);
		return ret;
	}

	pr_info("%s: Loaded successfully !\n", OCTEP_DRV_NAME);

	return ret;
}

/**
 * octep_exit_module() - Module exit routine.
 *
 * unregister the driver with PCI subsystem and cleanup common resources.
 */
static void __exit octep_exit_module(void)
{
	pr_info("%s: Unloading ...\n", OCTEP_DRV_NAME);

	pci_unregister_driver(&octep_driver);
	destroy_workqueue(octep_wq);

	pr_info("%s: Unloading complete\n", OCTEP_DRV_NAME);
}

module_init(octep_init_module);
module_exit(octep_exit_module);
