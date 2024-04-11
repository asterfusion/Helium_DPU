/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/* Host PHC driver using PTP timer on Octeon EP device
 */

#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/circ_buf.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/ptp_clock_kernel.h>

#include "linux_sysdep.h"
#include "octeon_device.h"
#include "octeon_hw.h"


#ifdef PHC_DEBUG
static void octeon_device_poll(struct work_struct *work);
#endif

int startup_set_ptp = 0;
module_param(startup_set_ptp, int, 0);
MODULE_PARM_DESC(startup_set_ptp, "Flag to set PTP clock to host clock at startup for testing");

void __iomem *nwa_bar0_internal_addr;

uint64_t octeon_pci_bar4_read64(octeon_device_t *oct_dev, int baridx, uint64_t bar_offset);
void octeon_pci_bar4_write64(octeon_device_t *oct_dev, int baridx, uint64_t bar_offset, uint64_t val);

int octeon_chip_specific_setup(octeon_device_t *oct_dev);

#ifndef  DEFINE_PCI_DEVICE_TABLE
#define  DEFINE_PCI_DEVICE_TABLE(octeon_ep_phc_pci_tbl) struct pci_device_id octeon_ep_phc_pci_tbl[]
#endif

static DEFINE_PCI_DEVICE_TABLE(octeon_ep_phc_pci_tbl) = {
	/* Same devid for all PHC PFs, both cn9xxx and cn10k */
	{OCTEON_VENDOR_ID, 0xEF00, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0, 0, 0, 0, 0, 0, 0}
};

extern int octeon_ep_phc_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
extern void octeon_ep_phc_remove(struct pci_dev *pdev);
extern int octeon_ep_phc_sriov_configure(struct pci_dev *dev, int num_vfs);
static struct pci_driver octeon_ep_phc_pci_driver = {
	.name = "Octeon EP PHC",
	.id_table = octeon_ep_phc_pci_tbl,
	.probe = octeon_ep_phc_probe,
	.remove = octeon_ep_phc_remove,
};
static ssize_t octeon_ep_phc_sysfs_device_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf);

static struct kobj_attribute phc_ptp_attribute = {
	.attr = {
		.name = "ptp_device",
		.mode = S_IWUSR | S_IRUGO,
	},
	.show = octeon_ep_phc_sysfs_device_show,
	.store = NULL,
};
static struct kobj_attribute phc_pcie_attribute = {
	.attr = {
		.name = "pcie_device",
		.mode = S_IWUSR | S_IRUGO,
	},
	.show = octeon_ep_phc_sysfs_device_show,
	.store = NULL,
};

/*
 * We need our own kobj type, as we want to use container_of() to get
 * the owning octeon_device_t, but that doesn't work with pointers.
 * We manage the kobj lifetime along with the octeon_device_t lifetime, so
 * phc_kobj_release() does nothing.
 */
static void phc_kobj_release(struct kobject *kobj)
{
}
static struct kobj_type phc_kobj_type = {
	.release = &phc_kobj_release,
	.sysfs_ops = &kobj_sysfs_ops,
};


/*
 * PTP clock operations
 * This driver only supports read-only operations on a PTP hardware clock
 * source that is owned and managed by software running on the Octeon
 * PCIe EP device.
 */
#ifdef PHC_DEBUG
static u64 prev_offset;
#endif
static int oct_ep_ptp_gettime_cn9xxx(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct oct_ep_ptp_clock *ep_clk;
	struct timespec64 tspec;
	uint64_t ns = 0;

	ep_clk = container_of(ptp, struct oct_ep_ptp_clock, caps);
	preempt_disable_notrace();
	ns = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CKOUT_THRESH_HI_OFFSET);
#ifdef PHC_DEBUG
	if (prev_offset && prev_offset != ns) {
		printk("OCT_PHC[%d]: offset changed, prev: 0x%llx, current: 0x%llx\n",
		       ep_clk->oct_dev->octeon_id, (unsigned long long)prev_offset,
		       (unsigned long long)ns);

		prev_offset = ns;
	}
	if (!prev_offset)
		prev_offset = ns;
#endif

	ns += octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);

	preempt_enable_notrace();
	tspec = ns_to_timespec64(ns);

	memcpy(ts, &tspec, sizeof(struct timespec64));
	return 0;
}

static int oct_ep_ptp_gettime_cn10k(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct oct_ep_ptp_clock *ep_clk;
	struct timespec64 tspec;
	u64 offset_ns = 0;
	u64 sec, sec1;
	u64 ns;

	ep_clk = container_of(ptp, struct oct_ep_ptp_clock, caps);
	preempt_disable_notrace();

	/*
	 * The CLOCK_SEC and CLOCK_HI represent the PTP time in seconds and
	 * nanosecond fraction.  When CLOCK_HI reaches 10^9, it rolls over
	 * to 0, and CLOCK_SEC is incremented.  These two registers are read
	 * separately, and we need to ensure that we only use values that
	 * are read in a consistent state.  If there is a second rollover
	 * event between the two register reads then the two reads do not
	 * represent the correc time.
	 * Here we read the CLOCK_SEC register before and after reading the
	 * CLOCK_HI register, and re-read the nsec counter if a rollover
	 * just occurred.
	 */
	sec = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_SEC_OFFSET);
	ns = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);
	sec1 = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_SEC_OFFSET);

	/* check nsec rollover */
	if (sec1 > sec) {
		u64 ns1;
		/*
		 * Note: we may want to do something clever here, as phc2sys
		 * will use the mid-point of the time take to get the time
		 * as the 'actual' time of the read, but hitting this case
		 * will cause the read to take longer and for the ns to be
		 * read at a different point during that time.
		 * We may be able to use the 2 ns readings to time the
		 * reads, and then use that to adjust.
		 * This will likely be hard to test, as this case will
		 * likely be difficult to hit.
		 * We may not need to deal with this if we required phc2sys
		 * to do multiple readings per period, as readings that hit
		 * this case will be longer than others, so will be ignored
		 * due to that.
		 */
		ns1 = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);
		printk("OCT_PHC[%d]: POLL ROLLOVER ns: %lld, ns1: %lld\n",
		       ep_clk->oct_dev->octeon_id,
		       (unsigned long long)ns,
		       (unsigned long long)ns1);
		ns = ns1;
		sec = sec1;
	}
	offset_ns = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CKOUT_THRESH_HI_OFFSET);
	preempt_enable_notrace();

#ifdef PHC_DEBUG
	if (prev_offset && prev_offset != offset_ns) {
		printk("OCT_PHC[%d]: offset changed, prev: 0x%llx, current: 0x%llx\n",
		       ep_clk->oct_dev->octeon_id, (unsigned long long)prev_offset,
		       (unsigned long long)ns);

		prev_offset = offset_ns;
	}
	if (!prev_offset)
		prev_offset = offset_ns;
#endif
	tspec = ns_to_timespec64(ns + sec * NSEC_PER_SEC + offset_ns);
	memcpy(ts, &tspec, sizeof(struct timespec64));
	return 0;
}

static int oct_ep_ptp_gettime_cnf10kb(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct oct_ep_ptp_clock *ep_clk;
	struct timespec64 tspec;
	u64 ns;

	ep_clk = container_of(ptp, struct oct_ep_ptp_clock, caps);
	preempt_disable_notrace();

	/* The CLOCK_HI represent the PTP time in nanoseconds */
	ns = octeon_pci_bar4_read64(ep_clk->oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
			       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);

	preempt_enable_notrace();

	tspec = ns_to_timespec64(ns);
	memcpy(ts, &tspec, sizeof(struct timespec64));
	return 0;
}

static int oct_ep_ptp_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *rq, int on)
{
	/* Nothing to do here, PTP hardware is enabled by EP */
	return 0;
}
static int oct_ep_ptp_adjfreq(struct ptp_clock_info *ptp, s32 ppb)
{
	return -ENOTSUPP;
}

static int oct_ep_ptp_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	return -ENOTSUPP;
}

static int oct_ep_ptp_settime(struct ptp_clock_info *ptp,
			   const struct timespec64 *ts)
{
	return -ENOTSUPP;
}


static struct ptp_clock_info oct_ep_ptp_caps = {
	.owner		= THIS_MODULE,
	.name		= "Octeon EP PHC",
	.max_adj	= 1,
	.n_ext_ts	= 0,
	.n_pins		= 0,
	.pps		= 0,
	.adjfreq	= oct_ep_ptp_adjfreq,
	.adjtime	= oct_ep_ptp_adjtime,
	.gettime64	= oct_ep_ptp_gettime_cn9xxx,
	.settime64	= oct_ep_ptp_settime,
	.enable		= oct_ep_ptp_enable,
};

static int __init phc_init(void)
{
	int ret;
	ret = pci_register_driver(&octeon_ep_phc_pci_driver);
	if (ret < 0) {
		printk(KERN_ERR "OCT_PHC: pci_register_driver() returned %d\n", ret);
		printk(KERN_ERR "OCT_PHC: Your kernel may not be configured for hotplug\n");
		printk(KERN_ERR "        and no Octeon devices were detected\n");
		return ret;
	}
	return 0;
}

static void __exit phc_exit(void)
{
	pci_unregister_driver(&octeon_ep_phc_pci_driver);
}

#define FW_STATUS_VSEC_ID 0xA3
#define FW_STATUS_READY 1
#define FW_STATUS_RUNNING 2
static u8 oct_get_fw_ready_status(octeon_device_t *oct_dev)
{
	u32 pos = 0;
	u16 vsec_id;
	u8 status = 0;

	while ((pos = pci_find_next_ext_capability(oct_dev->pci_dev, pos,
						   PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(oct_dev->pci_dev, pos + 4, &vsec_id);
		if (vsec_id == FW_STATUS_VSEC_ID) {
			pci_read_config_byte(oct_dev->pci_dev, (pos + 8), &status);
			dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]:fw ready status %u\n",
					 oct_dev->octeon_id, status);
			return status;
		}
	}
	return 0;
}

/* OS-specific initialization for each Octeon device. */
static int octeon_pci_os_setup(octeon_device_t *oct_dev)
{

	/* setup PCI stuff first */
	if (pci_enable_device(oct_dev->pci_dev)) {
		dev_err(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: pci_enable_device failed\n",
			     oct_dev->octeon_id);
		return 1;
	}

	/* Octeon device supports DMA into a 64-bit space */
	if (dma_set_mask_and_coherent(&oct_dev->pci_dev->dev, DMA_BIT_MASK(64))) {
		dev_err(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Unexpected DMA device capability\n",
			     oct_dev->octeon_id);
		return 1;
	}

	/* Enable PCI DMA Master. */
	pci_set_master(oct_dev->pci_dev);

	return 0;
}


static ssize_t octeon_ep_phc_sysfs_device_show(struct kobject *kobj,
					       struct kobj_attribute *attr,
					       char *buf)
{
	octeon_device_t *oct_dev;

	oct_dev = container_of(kobj, struct _OCTEON_DEVICE, phc_sysfs_kobject);

	if (!strcmp(attr->attr.name, "ptp_device")) {
		return sprintf(buf, "ptp%d\n",
			       ptp_clock_index(oct_dev->oct_ep_ptp_clock->ptp_clock));
	}
	else {
		return sprintf(buf, "%x:%x:%x\n",
			       oct_dev->pci_dev->bus->number,
			       PCI_SLOT(oct_dev->pci_dev->devfn),
			       PCI_FUNC(oct_dev->pci_dev->devfn));
	}
}

/* Device initialization for each Octeon device. */
int octeon_device_init(octeon_device_t *oct_dev)
{
	int ret;

	atomic_set(&oct_dev->status, OCT_DEV_BEGIN_STATE);

	/* Enable access to the octeon device and make its DMA capability
	   known to the OS. */
	if (octeon_pci_os_setup(oct_dev))
		return 1;

	ret  = octeon_chip_specific_setup(oct_dev);
	/* Identify the Octeon type and map the BAR address space. */
	if (ret == -1) {
		dev_err(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Chip specific setup failed\n",
			 oct_dev->octeon_id);
		return 1;
	}

	dev_info(&oct_dev->pci_dev->dev, "Chip specific setup completed\n");
	atomic_set(&oct_dev->status, OCT_DEV_PCI_MAP_DONE);

	spin_lock_init(&oct_dev->oct_lock);

	atomic_set(&oct_dev->status, OCT_DEV_DISPATCH_INIT_DONE);

	atomic_set(&oct_dev->status, OCT_DEV_HOST_OK);

	return 0;
}
static void octeon_device_init_work(struct work_struct *work)
{
	octeon_device_t *oct_dev;
	struct cavium_delayed_wq *wq;
	u8 status;
	int retval;

	wq = container_of(work, struct cavium_delayed_wq, wk.work.work);
	oct_dev = (octeon_device_t *)wq->wk.ctxptr;

	atomic_set(&oct_dev->status, OCT_DEV_CHECK_FW);
	while (true) {
		status = oct_get_fw_ready_status(oct_dev);
		if (status == FW_STATUS_READY || status == FW_STATUS_RUNNING)
			break;

		schedule_timeout_interruptible(HZ * 1);
		if (atomic_read(&oct_dev->status) > OCT_DEV_RUNNING) {
			atomic_set(&oct_dev->status, OCT_DEV_STATE_INVALID);
			dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Stopping firmware ready work.\n",
					 oct_dev->octeon_id);
			return;
		}
	}

	if (octeon_device_init(oct_dev)) {
		dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: ERROR: Octeon driver failed to load.\n",
				 oct_dev->octeon_id);
		return;
	}

	if (OCTEON_CNXK_PF(oct_dev->chip_id) || OCTEON_CNFXK_PF(oct_dev->chip_id)) {
		if (oct_dev->chip_id == OCTEON_CNF10KB_ID_PF)
			oct_ep_ptp_caps.gettime64 = oct_ep_ptp_gettime_cnf10kb;
		else
			oct_ep_ptp_caps.gettime64 = oct_ep_ptp_gettime_cn10k;
	}

	oct_dev->oct_ep_ptp_clock->caps = oct_ep_ptp_caps;
	oct_dev->oct_ep_ptp_clock->oct_dev = oct_dev;

	oct_dev->oct_ep_ptp_clock->ptp_clock = ptp_clock_register(&oct_dev->oct_ep_ptp_clock->caps, NULL);
	if (!oct_dev->oct_ep_ptp_clock->ptp_clock) {
	    dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: ERROR: Octeon PHC driver failed to load.\n",
			     oct_dev->octeon_id);
	    return;
	}
	if (startup_set_ptp) {
	    /*
	     * For cases where the PTP clock is not set to an external
	     * reference, we want to set it to match the host clock at
	     * startup.  Without this the PTP clock will be off by decades,
	     * and phc2sys will not handle this.
	     * Note that this write may need an additional PCIe stream ID to
	     * be allowed in the EBF menu.
	     */
	    uint64_t kt = ktime_get_real_ns();
	    if (OCTEON_CNXK_PF(oct_dev->chip_id) || OCTEON_CNFXK_PF(oct_dev->chip_id)) {
		    octeon_pci_bar4_write64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION, CN93XX_MIO_PTP_CLOCK_HI_OFFSET, kt%1000000000);
		    octeon_pci_bar4_write64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION, CN93XX_MIO_PTP_CLOCK_SEC_OFFSET, kt/1000000000);
	    } else {
		octeon_pci_bar4_write64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION, CN93XX_MIO_PTP_CLOCK_HI_OFFSET, kt);
	    }
	    dev_info(&oct_dev->pci_dev->dev,
		     "OCT_PHC[%d]: Setting PTP_CLOCK_HI based on host time: %lld\n",
		     oct_dev->octeon_id, (unsigned long long)kt);
	}

	dev_info(&oct_dev->pci_dev->dev,
		 "OCT_PHC[%d]: Octeon PHC using PCI device %02x:%02x:%x, PTP device ptp%d is ready\n",
		 oct_dev->octeon_id,
		 oct_dev->pci_dev->bus->number,
		 PCI_SLOT(oct_dev->pci_dev->devfn),
		 PCI_FUNC(oct_dev->pci_dev->devfn),
		 ptp_clock_index(oct_dev->oct_ep_ptp_clock->ptp_clock));

	retval = kobject_init_and_add(&oct_dev->phc_sysfs_kobject, &phc_kobj_type, kernel_kobj, "oct_phc%d", oct_dev->octeon_id);
	if (retval < 0) {
		dev_info(&oct_dev->pci_dev->dev,
			 "OCT_PHC[%d]: Error allocating kobject for sysfs\n",
			 oct_dev->octeon_id);
		kobject_put(&oct_dev->phc_sysfs_kobject);
	}
	else
	{
		retval = sysfs_create_file(&oct_dev->phc_sysfs_kobject, &phc_ptp_attribute.attr);
		if (retval) {
			dev_info(&oct_dev->pci_dev->dev,
				 "OCT_PHC[%d]: Error creating sysfs file\n",
				 oct_dev->octeon_id);
		}
		retval = sysfs_create_file(&oct_dev->phc_sysfs_kobject, &phc_pcie_attribute.attr);
		if (retval) {
			dev_info(&oct_dev->pci_dev->dev,
				 "OCT_PHC[%d]: Error creating sysfs file\n",
				 oct_dev->octeon_id);
		}
	}


#ifdef PHC_DEBUG
	oct_dev->dev_poll_wq.wq = alloc_workqueue("dev_poll_wq", WQ_MEM_RECLAIM, 0);
	oct_dev->dev_poll_wq.wk.ctxptr = oct_dev;
	INIT_DELAYED_WORK(&oct_dev->dev_poll_wq.wk.work, octeon_device_poll);
	queue_delayed_work(oct_dev->dev_poll_wq.wq, &oct_dev->dev_poll_wq.wk.work, 0);
#endif

}

#ifdef PHC_DEBUG
static void octeon_device_poll(struct work_struct *work)
{
	octeon_device_t *oct_dev;
	struct cavium_delayed_wq *wq;
	uint64_t ptp;
	uint64_t kt;
	uint64_t kt1;
	uint64_t p_kt = 0;
	uint64_t p_ptp = 0;

	wq = container_of(work, struct cavium_delayed_wq, wk.work.work);
	oct_dev = (octeon_device_t *)wq->wk.ctxptr;

	if (OCTEON_CNXK_PF(oct_dev->chip_id) || OCTEON_CNFXK_PF(oct_dev->chip_id)) {
		u64 offset_ns = 0;
		u64 sec, sec1;
		u64 ns;
		dev_info(&oct_dev->pci_dev->dev,
			 "OCT_PHC[%d]: Octeon CN10K PHC debug poll loop started, chip ID: 0x%x\n",
			 oct_dev->octeon_id, oct_dev->chip_id);
		while (1) {
			schedule_timeout_interruptible(HZ * 1);
			preempt_disable_notrace();
			kt1 = ktime_get_real_ns();
			sec = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
					       CN93XX_MIO_PTP_CLOCK_SEC_OFFSET);
			ns = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
					       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);
			sec1 = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
					       CN93XX_MIO_PTP_CLOCK_SEC_OFFSET);
			offset_ns = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
					       CN93XX_MIO_PTP_CKOUT_THRESH_HI_OFFSET);

			/* check nsec rollover */
			if (sec1 > sec) {
				u64 ns1;
				ns1 = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION,
					       CN93XX_MIO_PTP_CLOCK_HI_OFFSET);
				dev_info(&oct_dev->pci_dev->dev,
					 "OCT_PHC[%d]: POLL ROLLOVER ns: %lld, ns1: %lld\n",
					 oct_dev->octeon_id,
					 (unsigned long long)ns,
					 (unsigned long long)ns1);
				ns = ns1;
				sec = sec1;
			}
			ptp = ns + sec * NSEC_PER_SEC + offset_ns;
			kt = ktime_get_real_ns();
			preempt_enable_notrace();
			dev_info(&oct_dev->pci_dev->dev,
				 "OCT_PHC[%d]: PTP_CLOCK_HI: %lld, kt/ptp diff: %lld, ptp int: %lld, kt int: %lld, int diff: %lld, lat: %lld\n",
				 oct_dev->octeon_id,
				 (unsigned long long)ptp, (long long)(ptp - kt),
				 (long long)(ptp - p_ptp),
				 (long long)(kt - p_kt),
				 (long long)(ptp - p_ptp) - (long long)(kt - p_kt),
				 (long long)(kt - kt1));
			p_ptp = ptp;
			p_kt = kt;
			if (atomic_read(&oct_dev->status) > OCT_DEV_RUNNING)
				return;
		}
	} else {
		dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Octeon CN9XXX PHC debug poll loop started, chip ID: 0x%x\n",
				 oct_dev->octeon_id, oct_dev->chip_id);
		while (1) {
			schedule_timeout_interruptible(HZ * 1);
			preempt_disable_notrace();
			kt1 = ktime_get_real_ns();
			ptp = octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION, CN93XX_MIO_PTP_CKOUT_THRESH_HI_OFFSET);
			ptp += octeon_pci_bar4_read64(oct_dev, CN93XX_MIO_PTP_BAR4_REGION, CN93XX_MIO_PTP_CLOCK_HI_OFFSET);
			kt = ktime_get_real_ns();
			preempt_enable_notrace();
			dev_info(&oct_dev->pci_dev->dev,
				 "OCT_PHC[%d]: PTP_CLOCK_HI: %lld, kt/ptp diff: %lld, ptp int: %lld, kt int: %lld, int diff: %lld, lat: %lld\n",
				 oct_dev->octeon_id,
				 (unsigned long long)ptp, (long long)(ptp - kt),
				 (long long)(ptp - p_ptp),
				 (long long)(kt - p_kt),
				 (long long)(ptp - p_ptp) - (long long)(kt - p_kt),
				 (long long)(kt - kt1));
			p_ptp = ptp;
			p_kt = kt;
			if (atomic_read(&oct_dev->status) > OCT_DEV_RUNNING)
				return;
		}
	}
}
#endif

int octeon_ep_phc_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	octeon_device_t *oct_dev = NULL;

	oct_dev = octeon_allocate_device(pdev->device);
	if (oct_dev == NULL)
		return(-ENOMEM);

	oct_dev->oct_ep_ptp_clock = kmalloc(sizeof(struct oct_ep_ptp_clock), GFP_KERNEL);
	if (oct_dev->oct_ep_ptp_clock == NULL)
		return(-ENOMEM);


	/* Assign octeon_device for this device to the private data area. */
	pci_set_drvdata(pdev, oct_dev);

	/* set linux specific device pointer */
	oct_dev->pci_dev = (void *)pdev;


	dev_info(&oct_dev->pci_dev->dev, "OCT_PHC: Loading PHC driver\n");

	oct_dev->dev_init_wq.wq = alloc_workqueue("dev_init_wq", WQ_MEM_RECLAIM, 0);
	oct_dev->dev_init_wq.wk.ctxptr = oct_dev;
	INIT_DELAYED_WORK(&oct_dev->dev_init_wq.wk.work, octeon_device_init_work);
	queue_delayed_work(oct_dev->dev_init_wq.wq, &oct_dev->dev_init_wq.wk.work, 0);

	return 0;

}
void octeon_ep_phc_remove(struct pci_dev *pdev)
{
	octeon_device_t *oct_dev = pci_get_drvdata(pdev);
	int oct_idx;

	oct_idx = oct_dev->octeon_id;

	dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Stopping octeon device\n", oct_idx);
	if (atomic_read(&oct_dev->status) == OCT_DEV_CHECK_FW) {
		atomic_set(&oct_dev->status, OCT_DEV_STOPPING);
		while (true) {
			if (atomic_read(&oct_dev->status) == OCT_DEV_STATE_INVALID)
				return;

			dev_err(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Waiting for firmware ready work to end.\n",
				oct_idx);
			schedule_timeout_interruptible(HZ * 1);
		}
		goto before_exit;
	}

	atomic_set(&oct_dev->status, OCT_DEV_STOPPING);

#ifdef PHC_DEBUG
	cancel_delayed_work_sync(&oct_dev->dev_poll_wq.wk.work);
	flush_workqueue(oct_dev->dev_poll_wq.wq);
	destroy_workqueue(oct_dev->dev_poll_wq.wq);
	oct_dev->dev_poll_wq.wq = NULL;
#endif
	cancel_delayed_work_sync(&oct_dev->dev_init_wq.wk.work);
	flush_workqueue(oct_dev->dev_init_wq.wq);
	destroy_workqueue(oct_dev->dev_init_wq.wq);
	oct_dev->dev_init_wq.wq = NULL;


	ptp_clock_unregister(oct_dev->oct_ep_ptp_clock->ptp_clock);
	kfree(oct_dev->oct_ep_ptp_clock);

	sysfs_remove_file(&oct_dev->phc_sysfs_kobject, &phc_ptp_attribute.attr);
	sysfs_remove_file(&oct_dev->phc_sysfs_kobject, &phc_pcie_attribute.attr);
	kobject_put(&oct_dev->phc_sysfs_kobject);

	/* Reset the octeon device and cleanup all memory allocated for
	 * the octeon device by driver.*
	 */
	octeon_destroy_resources(oct_dev);

	/* This octeon device has been removed. Update the global
	 * data structure to reflect this. Free the device structure.
	 */
	octeon_free_device_mem(oct_dev);

before_exit:
	dev_info(&oct_dev->pci_dev->dev, "OCT_PHC[%d]: Octeon device removed\n", oct_idx);
}



module_init(phc_init);
module_exit(phc_exit);
MODULE_AUTHOR("Marvell Inc.");
MODULE_DESCRIPTION("OTX PCIe EP PHC");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
