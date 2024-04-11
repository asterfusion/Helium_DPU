/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <linux/etherdevice.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/circ_buf.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/sched/signal.h>
#endif

#include "desc_queue.h"
#include "octboot_net.h"
#include "mmio_api.h"
#include "octboot_net_compat.h"

#define OCTBOOT_NET_VERSION "1.0"
#define OCTBOOT_NET_VERSION_MAJOR 1
#define OCTBOOT_NET_VERSION_MINOR 0

struct octboot_net_struct {
	struct octboot_net_dev *gmdev;
	struct pci_dev *octnet_pci_dev_arr;
	int pci_bus;
	int pci_device;
	int pci_fn;
	int octboot_net_init_done;
	int initialized;
};

static struct octboot_net_struct octboot_struct[8];

static struct workqueue_struct *octboot_net_init_wq;
static struct delayed_work octboot_net_init_task;
static struct octboot_net_dev *gmdev[8];
static int octnet_num_device;
static int octboot_net_init_done[8];

static void mgmt_init_work(void *bar4_addr, int index);
static int mdev_reinit_rings(struct octboot_net_dev *mdev);
static void change_host_status(struct octboot_net_dev *mdev, uint64_t status,
			bool ack_wait);
static int mgmt_init_start[8];
#define OCTBOOT_NET_INIT_WQ_DELAY (1 * HZ)
#define DEVICE_COUNT_RESOURCE 3

#define OCTBOOT_NET_MBOX_SIZE_WORDS 8
#define OCTBOOT_NET_MBOX_HOST_STATUS_CHANGE 1
#define OCTBOOT_NET_MBOX_TARGET_STATUS_CHANGE 2
#define OCTBOOT_NET_MBOX_OPCODE_INVALID 0xFF

#define OCTBOOT_NET_MBOX_TIMEOUT_MS 100
#define OCTBOOT_NET_MBOX_WAIT_MS 10
#define OCTBOOT_NET_MBOX_DBELL_ID 0

struct octboot_net_mbox_hdr {
	uint64_t opcode  :8;
	uint64_t id      :8;
	uint64_t req_ack :1;
	uint64_t sizew   :3; /* size in words excluding hdr */
	uint64_t rsvd    :44;
} _packed;

union octboot_net_mbox_msg {
	uint64_t words[OCTBOOT_NET_MBOX_SIZE_WORDS];
	struct {
		 struct octboot_net_mbox_hdr hdr;
		 uint64_t data[7];
	} s;
} __packed;

static void octboot_net_poll(void);

struct uboot_pcinet_barmap {
	uint64_t signature;
	uint64_t host_version;
	uint64_t host_status_reg;
	uint64_t host_mailbox_ack;
	uint64_t host_mailbox[8];
	uint64_t target_version;
	uint64_t target_status_reg;
	uint64_t target_mailbox_ack;
	uint64_t target_mailbox[8];
	uint64_t rx_descriptor_offset;
	uint64_t tx_descriptor_offset;
};

#define OCTBOOT_NET_MAXQ 1
#define OCTBOOT_NET_DESCQ_CLEAN 0
#define OCTBOOT_NET_DESCQ_READY 1
#define OCTBOOT_IFACE_NAME "octboot_net%d"
#define OCTBOOT_NET_NUM_ELEMENTS 256
#define OCTBOOT_NET_SERVICE_TASK_US 1000


struct octboot_net_dev {
	struct device *dev;
	struct net_device *ndev;
	struct pci_dev *pdev;
	struct octboot_net_sw_descq rxq[OCTBOOT_NET_MAXQ];
	struct octboot_net_sw_descq txq[OCTBOOT_NET_MAXQ];
	bool  admin_up;
	uint8_t  __iomem *bar_map;
	uint32_t bar_map_size;
	uint32_t max_rxq;
	uint32_t num_rxq;
	uint32_t max_txq;
	uint32_t num_txq;
	uint32_t element_count;
	struct workqueue_struct *mgmt_wq;
	struct delayed_work service_task;
	uint32_t *tq_cons_shdw_vaddr;
	uint64_t tq_cons_shdw_dma;
	uint32_t *rq_cons_shdw_vaddr;
	uint64_t rq_cons_shdw_dma;
	struct mutex mbox_lock;
	uint32_t send_mbox_id;
	uint32_t recv_mbox_id;
	int      octboot_net_restart;
	uint8_t hw_addr[ETH_ALEN];
};

#define NPU_HANDSHAKE_SIGNATURE 0xABCDABCD
#define SIGNATURE_OFFSET 0x2000000 /* BAR4 index 8 is at this offset */
#define HOST_VERSION_OFFSET 0x2000008
#define HOST_STATUS_REG_OFFSET 0x2000080

#define OCTNET_HOST_DOWN                 0
#define OCTNET_HOST_READY                1
#define OCTNET_HOST_RUNNING              2
#define OCTNET_HOST_GOING_DOWN           3
#define OCTNET_HOST_FATAL                4

#define HOST_RESET_STATUS_REG_OFFSET 0x2000088
#define OCTNET_HOST_RESET_STATUS_BIT     0

#define HOST_MBOX_ACK_OFFSET 0x2000090
#define HOST_MBOX_OFFSET 0x2000098    /* Eight words at this offset */
#define TARGET_VERSION_OFFSET 0x2000060
#define TARGET_STATUS_REG_OFFSET 0x2000100


#define HOST_STATUS_REG(mdev)      (mdev->bar_map + HOST_STATUS_REG_OFFSET)
#define HOST_RESET_STATUS_REG(mdev) (mdev->bar_map + HOST_RESET_STATUS_REG_OFFSET)
#define HOST_VERSION_REG(mdev)      (mdev->bar_map + HOST_VERSION_OFFSET)
#define HOST_MBOX_ACK_REG(mdev)    (mdev->bar_map + HOST_MBOX_ACK_OFFSET)
#define HOST_MBOX_MSG_REG(mdev, i)    \
	(mdev->bar_map + HOST_MBOX_OFFSET + (i * 8))


#define OCTNET_TARGET_DOWN               0
#define OCTNET_TARGET_READY              1
#define OCTNET_TARGET_RUNNING            2
#define OCTNET_TARGET_GOING_DOWN         3
#define OCTNET_TARGET_FATAL              4


#define TARGET_MBOX_OFFSET 0x2000118
#define TARGET_MBOX_ACK_OFFSET 0x2000110
#define OCTNET_RX_DESC_OFFSET 0x20000B8
#define OCTNET_TX_DESC_OFFSET 0x20000c0

#define OCTNET_TX_DESCQ_OFFSET   0x2000400
#define OCTNET_RX_DESCQ_OFFSET   0x2010000

#define TX_DESCQ_OFFSET(mdev)     (mdev->bar_map + OCTNET_TX_DESCQ_OFFSET)
#define RX_DESCQ_OFFSET(mdev)     (mdev->bar_map + OCTNET_RX_DESCQ_OFFSET)

#define TARGET_STATUS_REG(mdev)        (mdev->bar_map + TARGET_STATUS_REG_OFFSET)
#define TARGET_VERSION_REG(mdev)        (mdev->bar_map + TARGET_VERSION_OFFSET)
#define TARGET_MBOX_MSG_REG(mdev, i)  \
	(mdev->bar_map + TARGET_MBOX_OFFSET + (i * 8))
#define TARGET_MBOX_ACK_REG(mdev)    \
	(mdev->bar_map + TARGET_MBOX_ACK_OFFSET)

typedef struct {
	/** PCI address to which the BAR is mapped. */
	unsigned long start;
	/** Length of this PCI address space. */
	unsigned long len;
	/** Length that has been mapped to phys. address space. */
	unsigned long mapped_len;
	/** The physical address to which the PCI address space is mapped. */
	void *hw_addr;
	/** Flag indicating the mapping was successful. */
	int done;
} octeon_mmio;

typedef struct {
	octeon_mmio mmio[3];
	/* struct npu_bar_map npu_memmap_info; */
	struct uboot_pcinet_barmap npu_memmap_info;
	void *bar4_addr;
	int signature_found;
	bool unavailable;
	bool enabled;
	struct pci_dev *pdev;
} octboot_net_device_t;

octboot_net_device_t octboot_net_device[8];

static unsigned int vendor_id = 0x177d;
static unsigned int device_id_f95n = 0xb400;
static unsigned int device_id_f105n = 0xbc00;

static uint64_t get_host_status(struct octboot_net_dev *mdev)
{
	return readq(HOST_STATUS_REG(mdev));
}

static void set_host_reset_status(struct octboot_net_dev *mdev, bool set)
{
	uint64_t val;

	dev_info(&mdev->pdev->dev, "reset host status to %s", set ? "true" : "false");
	val = readq(HOST_RESET_STATUS_REG(mdev));
	val &= ~(1 << OCTNET_HOST_RESET_STATUS_BIT);
	if (set)
		val |= (set << OCTNET_HOST_RESET_STATUS_BIT);
	dev_info(&mdev->pdev->dev,
		 "reset host status reg 0x%llx to val 0x%llx",
		 (uint64_t)HOST_RESET_STATUS_REG(mdev), val);
	writeq(val, HOST_RESET_STATUS_REG(mdev));
}

static uint64_t get_target_status(struct octboot_net_dev *mdev)
{
	return readq(TARGET_STATUS_REG(mdev));
}

static uint64_t get_target_version(struct octboot_net_dev *mdev)
{
	return readq(TARGET_VERSION_REG(mdev));
}

static uint64_t get_target_mbox_ack(struct octboot_net_dev *mdev)
{
	return readq(TARGET_MBOX_ACK_REG(mdev));
}

static void set_host_mbox_ack_reg(struct octboot_net_dev *mdev, uint32_t id)
{
	writeq(id, HOST_MBOX_ACK_REG(mdev));
}

static void mbox_send_msg(struct octboot_net_dev *mdev,
		union octboot_net_mbox_msg *msg)
{
	unsigned long timeout = msecs_to_jiffies(OCTBOOT_NET_MBOX_TIMEOUT_MS);
	unsigned long period = msecs_to_jiffies(OCTBOOT_NET_MBOX_WAIT_MS);
	unsigned long expire;
	int i, id;

	mutex_lock(&mdev->mbox_lock);
	mdev->send_mbox_id++;
	msg->s.hdr.id = mdev->send_mbox_id;
	id = msg->s.hdr.id;
	for (i = 1; i <= msg->s.hdr.sizew; i++)
		writeq(msg->words[i], HOST_MBOX_MSG_REG(mdev, i));
	/* write header at the end */
	/* printk(KERN_DEBUG "send mbox msg id:%d opcode:%d sizew: %d\n",
	       msg->s.hdr.id, msg->s.hdr.opcode, msg->s.hdr.sizew); */
	writeq(msg->words[0], HOST_MBOX_MSG_REG(mdev, 0));
	/* more than 1 word mbox messages need explicit ack */
	if (msg->s.hdr.req_ack || msg->s.hdr.sizew) {
		/* printk(KERN_DEBUG "mbox send wait for ack\n"); */
		expire = jiffies + timeout;
		while (get_target_mbox_ack(mdev) != id) {
			schedule_timeout_interruptible(period);
			if ((signal_pending(current)) ||
				(time_after(jiffies, expire))) {
				netdev_err(mdev->ndev, "octboot_net:mbox ack wait failed\n");
				break;
			}
		}
	}
	mutex_unlock(&mdev->mbox_lock);
}

static void octboot_net_restart(void)
{
	cancel_delayed_work(&octboot_net_init_task);
	queue_delayed_work(octboot_net_init_wq, &octboot_net_init_task,
			OCTBOOT_NET_INIT_WQ_DELAY);
}


static int mbox_check_msg_rcvd(struct octboot_net_dev *mdev,
			union octboot_net_mbox_msg *msg)
{
	unsigned int flags;
	int i, ret;

	flags = READ_ONCE(mdev->ndev->flags);

	if (!(flags | IFF_RUNNING))
		return 0;

	mutex_lock(&mdev->mbox_lock);
	msg->words[0] = readq(TARGET_MBOX_MSG_REG(mdev, 0));
	if (msg->s.hdr.opcode == OCTBOOT_NET_MBOX_OPCODE_INVALID) {
		ret = 0;

		/* If restart was already set, do not repeat process */
		if (mdev->octboot_net_restart)
			return ret;

		netdev_err(mdev->ndev, "Async or Sync reset of Octeon device\n");
		mutex_unlock(&mdev->mbox_lock);
		mdev->octboot_net_restart = true;
		/* set netdevice down */
		mdev->ndev->flags &= ~(IFF_RUNNING);
		change_host_status(mdev, OCTNET_HOST_GOING_DOWN, false);
		netif_carrier_off(mdev->ndev);
		cancel_delayed_work(&mdev->service_task);
		octboot_net_restart();
		/* Perform cleanup and return to looking for signature */
		return ret;

	}
	if (mdev->recv_mbox_id != msg->s.hdr.id) {
		/* new msg */
		netdev_err(mdev->ndev, "new mbox msg id:%d opcode:%d sizew: %d\n",
			msg->s.hdr.id, msg->s.hdr.opcode, msg->s.hdr.sizew);

		mdev->recv_mbox_id = msg->s.hdr.id;
		for (i = 1; i <= msg->s.hdr.sizew; i++)
			msg->words[i] = readq(TARGET_MBOX_MSG_REG(mdev, i));
		ret = 0;
	} else {
		ret = -ENOENT;
	}
	mutex_unlock(&mdev->mbox_lock);
	return ret;
}

static void change_host_status(struct octboot_net_dev *mdev, uint64_t status,
			bool ack_wait)
{
	union octboot_net_mbox_msg msg;

	netdev_err(mdev->ndev, "change host status from %lld to %lld\n",
		   readq(HOST_STATUS_REG(mdev)), status);

	writeq(status, HOST_STATUS_REG(mdev));
	memset(&msg, 0, sizeof(union octboot_net_mbox_msg));
	msg.s.hdr.opcode = OCTBOOT_NET_MBOX_HOST_STATUS_CHANGE;
	if (ack_wait)
		msg.s.hdr.req_ack = 1;
	mbox_send_msg(mdev, &msg);
}

static int find_octboot_net_entry(struct pci_dev *octnet_pci_dev)
{
	int i;
	int pci_bus, pci_device, pci_fn;

	pci_bus = octnet_pci_dev->bus->number;
	pci_device = PCI_SLOT(octnet_pci_dev->devfn);
	pci_fn = PCI_FUNC(octnet_pci_dev->devfn);

	for (i = 0; i < 8; i++) {
		if (octboot_struct[i].initialized &&
			octboot_struct[i].pci_bus == pci_bus &&
			octboot_struct[i].pci_device == pci_device &&
			octboot_struct[i].pci_fn == pci_fn) {
			dev_dbg(&octnet_pci_dev->dev, "Found octboot device at idx %d\n", i);
			return i;
		}
	}
	return -1;
}

static int add_octboot_net_entry(struct pci_dev *octnet_pci_dev)
{
	int i;
	int pci_bus, pci_device, pci_fn;

	pci_bus = octnet_pci_dev->bus->number;
	pci_device = PCI_SLOT(octnet_pci_dev->devfn);
	pci_fn = PCI_FUNC(octnet_pci_dev->devfn);

	for (i = 0; i < 8; i++) {
		if (!octboot_struct[i].initialized) {
			octboot_struct[i].octnet_pci_dev_arr = octnet_pci_dev;
			octboot_struct[i].pci_bus = pci_bus;
			octboot_struct[i].pci_device = pci_device;
			octboot_struct[i].pci_fn = pci_fn;
			octboot_struct[i].initialized = true;
			return i;
		}
	}
	dev_err(&octnet_pci_dev->dev, "Error: exceeded max devices supported\n");
	return -ENOSPC;
}

static bool octboot_is_pci_bar_addr_reset(struct pci_dev *pdev)
{
	uint32_t bar0_base, bar1_base;

	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_0, &bar0_base);
	pci_read_config_dword(pdev, PCI_BASE_ADDRESS_1, &bar1_base);
	if (!(bar0_base >> 16) && !bar1_base)
		return true;

	return false;
}

static bool octboot_is_pci_bar_accessible(octboot_net_device_t *octboot_dev)
{
	struct pci_dev *pdev = octboot_dev->pdev;
	uint64_t addr, signature;

	addr = (uint64_t)(octboot_dev->bar4_addr + SIGNATURE_OFFSET);
	signature = *(uint64_t *)addr;
	dev_info(&pdev->dev, "signature offset=0x%llx signature=0x%llx\n", addr, signature);
	/* all F's means BAR not accessible */
	return (*(uint64_t *)addr != -1ULL);
}

static int octboot_enable_device(octboot_net_device_t *octboot_dev)
{
	struct pci_dev *pdev;
	int i, ret = 0;

	pdev = octboot_dev->pdev;

	if (octboot_is_pci_bar_addr_reset(pdev)) {
		/* device was earlier not available; might be going through reset.
		 * now available; restore the config.
		 */
		dev_info(&pdev->dev, "Device available but BAR addr is reset; restore config\n");
		pci_restore_state(pdev);
		octboot_dev->unavailable = false;
	}

	if (!pci_device_is_present(pdev) ||
	    (octboot_dev->bar4_addr && !octboot_is_pci_bar_accessible(octboot_dev))) {
		/* Device unavailable; may be going through reset */
		if (octboot_dev->enabled && !octboot_dev->unavailable) {
			dev_info(&pdev->dev, "Device became unavailable\n");
			octboot_dev->unavailable = true;
		}
		return -EAGAIN;
	}

	/* Enable the device only once; later just call restore state */
	if (octboot_dev->enabled)
		return 0;

	dev_info(&pdev->dev, "enabling device ...\n");
	ret = pci_enable_device(pdev);
	if (ret) {
		pr_err("Failed to enable PCI device 0x%x\n", ret);
		return ret;
	}

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64));
	if (ret) {
		pr_err("Failed to set DMA mask on PCI device 0x%x\n", ret);
		return ret;
	}
	pci_set_master(pdev);

	for (i = 0; i < DEVICE_COUNT_RESOURCE; i++) {
		octboot_dev->mmio[i].start = pci_resource_start(pdev, i * 2);
		octboot_dev->mmio[i].len = pci_resource_len(pdev, i * 2);
		octboot_dev->mmio[i].hw_addr = ioremap(octboot_dev->mmio[i].start,
						       octboot_dev->mmio[i].len);
		octboot_dev->mmio[i].done = 1;

		if (i == 2)
			octboot_dev->bar4_addr = octboot_dev->mmio[i].hw_addr;
	}
	octboot_dev->enabled = true;
	octboot_dev->signature_found = false;

	return 0;
}

static void octboot_net_init_work(struct work_struct *work)
{
	struct pci_dev *octnet_pci_dev = NULL;
	int entry_idx, ret;

	octnet_num_device = 0;
	while ((octnet_pci_dev = pci_get_device(vendor_id, PCI_ANY_ID, octnet_pci_dev))) {
		if ((octnet_pci_dev->device != device_id_f95n) &&
		    (octnet_pci_dev->device != device_id_f105n))
			continue;

		/* Found supported Octeon device */
		dev_dbg(&octnet_pci_dev->dev,
			"Initializing device (devid=0x%x)\n", octnet_pci_dev->device);
		entry_idx = find_octboot_net_entry(octnet_pci_dev);

		if (entry_idx == -1) {
			entry_idx = add_octboot_net_entry(octnet_pci_dev);

			if (entry_idx == -ENOSPC) {
				dev_info(&octnet_pci_dev->dev, "Ignoring this device\n");
				continue;
			}

			dev_info(&octnet_pci_dev->dev, "Device added at entry %d\n", entry_idx);
		}

		octboot_net_device[entry_idx].pdev = octnet_pci_dev;
		octnet_num_device++;

		ret = octboot_enable_device(&octboot_net_device[entry_idx]);
		if (ret)
			dev_dbg(&octnet_pci_dev->dev, "Failed to enable device; ret=%d\n", ret);
	}

	octboot_net_poll();
	return;
}

static void octboot_net_poll(void)
{
	struct pci_dev *octnet_pci_device;
	int offset = SIGNATURE_OFFSET; /* BAR4 index 8 is at this offset */
	uint64_t signature;
	void *bar4_addr;
	void *src;
	int i;

	for (i = 0; i < octnet_num_device; i++) {
		if (!octboot_net_device[i].bar4_addr ||
		    !octboot_net_device[i].pdev ||
		    octboot_net_device[i].unavailable)
			continue;

		bar4_addr = octboot_net_device[i].bar4_addr;
		src = bar4_addr + offset;

		octnet_pci_device = octboot_struct[i].octnet_pci_dev_arr;
		memcpy(&octboot_net_device[i].npu_memmap_info, src,
			sizeof(struct uboot_pcinet_barmap));

		/* Check for signature */
		signature = octboot_net_device[i].npu_memmap_info.signature;
		if (signature == NPU_HANDSHAKE_SIGNATURE) {
			if (!octboot_net_device[i].signature_found) {
				/* Uboot is booting and requires a netdevice for tftp */
				dev_info(&octnet_pci_device->dev,
					 "[Device-%d] Found valid signature 0x%llx\n",
					 i, signature);
				octboot_net_device[i].signature_found = true;
				octboot_net_device[i].unavailable = false;

				/* Save state for future restoration */
				dev_info(&octnet_pci_device->dev, "saving pci state ...\n");
				pci_save_state(octnet_pci_device);
			}
		} else if (octboot_net_device[i].signature_found) {
			dev_info(&octnet_pci_device->dev,
				 "[Device-%d] Found invalid signature 0x%llx\n", i, signature);
			octboot_net_device[i].signature_found = false;
			octboot_net_device[i].unavailable = true;
		}
	}

	/* Now that we have the signature, the next step is to create a
	 * netdevice
	 */
	for (i = 0; i < octnet_num_device; i++) {
		if ((octboot_net_device[i].signature_found == true) &&
						!mgmt_init_start[i]) {
			bar4_addr = octboot_net_device[i].bar4_addr;
			mgmt_init_work(bar4_addr, i);
			mgmt_init_start[i] = 1;
		}
		if ((octboot_net_device[i].signature_found == true) &&
				(mgmt_init_start[i]) &&
				octboot_net_init_done[i]) {
			struct octboot_net_dev *mdev = gmdev[i];
			int ret;

			/* This is restart */
			if (mdev->octboot_net_restart == true) {
				unsigned int flags;

				netdev_err(mdev->ndev, "This is restart of mgmt service task\n");
				change_host_status(mdev, OCTNET_HOST_GOING_DOWN, false);
				netif_carrier_off(mdev->ndev);
				napi_synchronize(&mdev->rxq[0].napi);
				ret = mdev_reinit_rings(mdev);
				if (ret) {
					netdev_err(mdev->ndev,
						   "restart of mgmt service task failed\n");
					netdev_err(mdev->ndev,
						   "Please unload and load octboot_net module\n");
					change_host_status(mdev, OCTNET_HOST_FATAL, false);
					return;
				}
				change_host_status(mdev, OCTNET_HOST_READY, false);
				/* barrier to ensure the octboot_net_task thread  reads the
				 * updated flag
				 */
				flags = READ_ONCE(mdev->ndev->flags);
				flags |= IFF_RUNNING;
				WRITE_ONCE(mdev->ndev->flags, flags);
				mdev->octboot_net_restart = false;
				queue_delayed_work(mdev->mgmt_wq, &mdev->service_task,
						usecs_to_jiffies(OCTBOOT_NET_SERVICE_TASK_US));
			}
		}
	}

	for (i = 0; i < octnet_num_device; i++) {
		if (octboot_net_device[i].signature_found == false) {
			queue_delayed_work(octboot_net_init_wq, &octboot_net_init_task,
				OCTBOOT_NET_INIT_WQ_DELAY);
			return;
		}
	}
}

static int octboot_net_open(struct net_device *dev)
{
	struct octboot_net_dev *mdev = netdev_priv(dev);

	mdev->admin_up = true;
	__module_get(THIS_MODULE);
	return 0;
}

static int octboot_net_close(struct net_device *dev)
{
	struct octboot_net_dev *mdev = netdev_priv(dev);

	mdev->admin_up = false;
	module_put(THIS_MODULE);
	return 0;
}

static void octboot_net_get_stats64(struct net_device *dev,
		struct rtnl_link_stats64 *s)
{
	struct octboot_net_dev *mdev = netdev_priv(dev);
	int i;

	for (i = 0; i < mdev->num_rxq; i++) {
		s->rx_packets += mdev->rxq[i].pkts;
		s->rx_bytes   += mdev->rxq[i].bytes;
		s->rx_errors  += mdev->rxq[i].errors;
	}
	for (i = 0; i < mdev->num_txq; i++) {
		s->tx_packets += mdev->txq[i].pkts;
		s->tx_bytes   += mdev->txq[i].bytes;
		s->tx_errors  += mdev->txq[i].errors;
	}
}

netdev_tx_t octboot_net_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct octboot_net_dev *mdev =
		(struct octboot_net_dev *)netdev_priv(dev);
	struct octboot_net_hw_desc_ptr ptr;
	struct octboot_net_sw_descq  *tq;
	uint32_t cur_cons_idx, cur_prod_idx;
	uint8_t *hw_desc_ptr;
	dma_addr_t dma;
	/* hard code */
	int idx = 0;
	int xmit_more;
	int bytes;

	tq = &mdev->txq[idx];
	/* should not get packets without IFF_UP */
	if (!mdev->admin_up)
		goto err;
	if (get_host_status(mdev) != OCTNET_HOST_RUNNING)
		goto err;
	/* dont handle non linear skb, did not set NETIF_F_SG */
	if (skb_is_nonlinear(skb))
		goto err;
	if (skb_put_padto(skb, ETH_ZLEN)) {
		tq->errors++;
		return NETDEV_TX_OK;
	}
	bytes = skb->len;

#if defined(NO_SKB_XMIT_MORE)
	xmit_more = netdev_xmit_more();
#else
	xmit_more = skb->xmit_more;
#endif
	cur_cons_idx = READ_ONCE(*tq->cons_idx_shadow);
	cur_prod_idx = READ_ONCE(tq->local_prod_idx);
	if (!octboot_net_circq_space(cur_prod_idx, cur_cons_idx, tq->mask)) {
		tq->errors++;
		/* if we have accumulated skbs send them */
		if (tq->pending) {
			writel(tq->local_prod_idx, tq->hw_prod_idx);
			tq->pending = 0;
		}
		return NETDEV_TX_BUSY;
	}
	memset(&ptr, 0, sizeof(struct octboot_net_hw_desc_ptr));
	ptr.hdr.s_mgmt_net.ptr_type = OCTBOOT_NET_DESC_PTR_DIRECT;
	ptr.hdr.s_mgmt_net.ptr_len = skb->len;
	ptr.hdr.s_mgmt_net.total_len = skb->len;
	dma = dma_map_single(mdev->dev, skb->data, skb->len,
			     DMA_TO_DEVICE);
	if (dma_mapping_error(mdev->dev, dma)) {
		netdev_err(mdev->ndev, "dma mapping err in xmit\n");
		goto err;
	}
	ptr.ptr = dma;
	hw_desc_ptr = tq->hw_descq +
		OCTBOOT_NET_DESC_ARR_ENTRY_OFFSET(cur_prod_idx);
	/* printk(KERN_DEBUG "tx is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n",
		 ptr.hdr.s_mgmt_net.is_frag,
		 ptr.hdr.s_mgmt_net.total_len,
		 ptr.hdr.s_mgmt_net.ptr_type,
		 ptr.hdr.s_mgmt_net.ptr_len,
		 ptr.ptr);
	*/
	mmio_memwrite(hw_desc_ptr, &ptr, sizeof(struct octboot_net_hw_desc_ptr));
	tq->skb_list[cur_prod_idx] = skb;
	tq->dma_list[cur_prod_idx] = dma;
	/* lists need to be updated before going forward */
	wmb();
	cur_prod_idx = octboot_net_circq_inc(cur_prod_idx, tq->mask);
	WRITE_ONCE(tq->local_prod_idx, cur_prod_idx);
	tq->pkts  += 1;
	tq->bytes += bytes;
	wmb();
	if (xmit_more && tq->pending < DPIX_MAX_PTR) {
		tq->pending++;
		return NETDEV_TX_OK;
	}
	writel(tq->local_prod_idx, tq->hw_prod_idx);
	tq->pending = 0;
	return NETDEV_TX_OK;
err:
	tq->errors++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static const struct net_device_ops octboot_netdev_ops = {
	.ndo_open            = octboot_net_open,
	.ndo_stop            = octboot_net_close,
	.ndo_start_xmit      = octboot_net_tx,
	.ndo_get_stats64     = octboot_net_get_stats64,
};

static bool __handle_txq_completion(struct octboot_net_dev *mdev, int q_idx, int budget)
{
	struct octboot_net_sw_descq *tq = &mdev->txq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct sk_buff *skb;
	int count, start, i;
	dma_addr_t dma;
	bool resched = false;

	if (!mdev->admin_up)
		return false;
	if (get_host_status(mdev) != OCTNET_HOST_RUNNING)
		return false;

	cons_idx = READ_ONCE(tq->local_cons_idx);
	prod_idx =  READ_ONCE(*tq->cons_idx_shadow);
	count = octboot_net_circq_depth(prod_idx, cons_idx, tq->mask);
	if (budget && count > budget) {
		resched = true;
		count = budget;
	}
	start = cons_idx;
	for (i = 0; i < count; i++) {
		skb = tq->skb_list[start];
		dma = tq->dma_list[start];
		dma_unmap_single(mdev->dev, dma, skb->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(skb);
		tq->skb_list[start] = NULL;
		tq->dma_list[start] = 0;
		start = octboot_net_circq_inc(start, tq->mask);
	}
	/* update lists before updating cons idx */
	wmb();
	cons_idx = octboot_net_circq_add(cons_idx, count, tq->mask);
	WRITE_ONCE(tq->local_cons_idx, cons_idx);
	wmb();
	if (resched == false) {
		/* check again */
		cons_idx = READ_ONCE(tq->local_cons_idx);
		prod_idx =  READ_ONCE(*tq->cons_idx_shadow);
		count = octboot_net_circq_depth(prod_idx, cons_idx, tq->mask);
		if (count)
			resched = true;
	}
	return resched;
}

static int rxq_refill(struct octboot_net_dev *mdev, int q_idx, int count)
{
	struct octboot_net_sw_descq *rq = &mdev->rxq[q_idx];
	int cur_prod_idx, start;
	struct octboot_net_hw_desc_ptr ptr;
	uint8_t *hw_desc_ptr;
	struct sk_buff *skb;
	dma_addr_t dma;
	int i;

	cur_prod_idx = READ_ONCE(rq->local_prod_idx);
	start = cur_prod_idx;
	for (i = 0; i < count; i++) {
		memset(&ptr, 0, sizeof(struct octboot_net_hw_desc_ptr));
		skb = dev_alloc_skb(OCTBOOT_NET_RX_BUF_SIZE);
		if (!skb) {
			netdev_err(mdev->ndev, "mgmt_net: skb alloc fail\n");
			break;
		}
		skb->dev = mdev->ndev;
		dma = dma_map_single(mdev->dev, skb->data, 
				OCTBOOT_NET_RX_BUF_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(mdev->dev, dma)) {
			dev_kfree_skb_any(skb);
			netdev_err(mdev->ndev, "mgmt_net: dma mapping fail\n");
			break;
		}
		ptr.hdr.s_mgmt_net.ptr_type = OCTBOOT_NET_DESC_PTR_DIRECT;
		ptr.ptr = dma;
		if (rq->skb_list[start] != NULL || rq->dma_list[start] != 0) {
			dev_kfree_skb_any(skb);
			netdev_err(mdev->ndev, "mgmt_net:refill err entry !empty\n");
			break;
		}
		rq->skb_list[start] = skb;
		rq->dma_list[start] = dma;
		hw_desc_ptr = rq->hw_descq +
				OCTBOOT_NET_DESC_ARR_ENTRY_OFFSET(start);
		mmio_memwrite(hw_desc_ptr, &ptr,
			      sizeof(struct octboot_net_hw_desc_ptr));
		start = octboot_net_circq_inc(start, rq->mask);
	}
	/* the lists need to be updated before updating hwprod idx */
	wmb();
	cur_prod_idx = octboot_net_circq_add(cur_prod_idx, i, rq->mask);
	WRITE_ONCE(rq->local_prod_idx, cur_prod_idx);
	writel(rq->local_prod_idx, rq->hw_prod_idx);
	wmb();
	return i;
}

static void dump_hw_descq(struct octboot_net_hw_descq *descq)
{
	struct  octboot_net_hw_desc_ptr *ptr;
	int i, count;

	pr_info("prod_idx %u\n", descq->prod_idx);
	pr_info("cons_idx %u\n", descq->cons_idx);
	pr_info("num_entries %u\n", descq->num_entries);
	pr_info("shadow_cons_idx_addr 0x%llx\n",
		descq->shadow_cons_idx_addr);
	count = octboot_net_circq_depth(descq->prod_idx, descq->cons_idx, descq->num_entries - 1);
	for (i = 0; i < count; i++) {
		ptr = &descq->desc_arr[i];
		pr_info("idx:%d is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n", i,
			ptr->hdr.s_mgmt_net.is_frag,
			ptr->hdr.s_mgmt_net.total_len,
			ptr->hdr.s_mgmt_net.ptr_type,
			ptr->hdr.s_mgmt_net.ptr_len,
			ptr->ptr);
	}
}

static bool __handle_rxq(struct octboot_net_dev *mdev, int q_idx, int budget, int from_wq)
{
	struct octboot_net_sw_descq *rq = &mdev->rxq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct octboot_net_hw_desc_ptr ptr;
	uint8_t *hw_desc_ptr;
	int count, start, i;
	struct sk_buff *skb;
	struct octboot_net_hw_descq *tmp_descq;
	int descq_tot_size;
	bool resched = false;
	struct napi_struct *napi = &rq->napi;

	if (!mdev->admin_up)
		return false;
	if (get_host_status(mdev) != OCTNET_HOST_RUNNING)
		return false;

	cons_idx = READ_ONCE(rq->local_cons_idx);
	prod_idx =  READ_ONCE(*rq->cons_idx_shadow);
	count = octboot_net_circq_depth(prod_idx,  cons_idx, rq->mask);
	if (!count)
		return false;
	if (budget && count > budget) {
		resched = true;
		count = budget;
	}
	start = cons_idx;
	for (i = 0; i < count; i++) {
		skb = rq->skb_list[start];
		dma_unmap_single(mdev->dev, rq->dma_list[start],
				 OCTBOOT_NET_RX_BUF_SIZE,
				 DMA_FROM_DEVICE);
		hw_desc_ptr = rq->hw_descq +
				OCTBOOT_NET_DESC_ARR_ENTRY_OFFSET(start);
		/* this is not optimal metadata should probaly be in the packet */
		mmio_memread(&ptr, hw_desc_ptr,
			     sizeof(struct octboot_net_hw_desc_ptr));

		if (unlikely(ptr.hdr.s_mgmt_net.total_len < ETH_ZLEN ||
		    ptr.hdr.s_mgmt_net.is_frag ||
		    ptr.hdr.s_mgmt_net.ptr_len != ptr.hdr.s_mgmt_net.ptr_len)) {
			/* dont handle frags now */
			rq->errors++;
			descq_tot_size = sizeof(struct octboot_net_hw_descq) +
					 (rq->element_count *
					  sizeof(struct octboot_net_hw_desc_ptr));
			tmp_descq = kmalloc(descq_tot_size, GFP_KERNEL);
			if (!tmp_descq) {
				netdev_err(mdev->ndev, "rx error kmalloc\n");
			} else {
				mmio_memread(tmp_descq, rq->hw_descq,
					     descq_tot_size);
				dump_hw_descq(tmp_descq);
				kfree(tmp_descq);
			}
			dev_kfree_skb_any(skb);
		} else {
			skb_put(skb, ptr.hdr.s_mgmt_net.total_len);
			skb->protocol = eth_type_trans(skb, mdev->ndev);
			rq->pkts += 1;
			rq->bytes += ptr.hdr.s_mgmt_net.total_len;
			if (from_wq)
				netif_receive_skb(skb);
			else
				napi_gro_receive(napi, skb);
		}
		rq->skb_list[start] = NULL;
		rq->dma_list[start] = 0;
		start = octboot_net_circq_inc(start, rq->mask);
	}
	/* lists need to be updated before updating cons idx */
	wmb();
	cons_idx = octboot_net_circq_add(cons_idx, count, rq->mask);
	WRITE_ONCE(rq->local_cons_idx, cons_idx);
	wmb();
	rxq_refill(mdev, q_idx, count);
	/* check again */
	if (resched == false) {
		cons_idx = READ_ONCE(rq->local_cons_idx);
		prod_idx = READ_ONCE(*rq->cons_idx_shadow);
		count = octboot_net_circq_depth(prod_idx,  cons_idx, rq->mask);
		if (count)
			resched = true;
	}
	return resched;
}

static int octboot_net_napi_poll(struct napi_struct *napi, int budget)
{
	struct octboot_net_sw_descq *rq;
	struct octboot_net_sw_descq *tq;
	struct octboot_net_dev *mdev;
	int q_num;
	bool need_resched = false;

	rq = container_of(napi, struct octboot_net_sw_descq, napi);
	mdev = (struct octboot_net_dev *)rq->priv;
	q_num = rq->q_num;
	tq = &mdev->txq[q_num];

	spin_lock_bh(&tq->lock);
	need_resched |= __handle_txq_completion(mdev, q_num, budget);
	spin_unlock_bh(&tq->lock);

	spin_lock_bh(&rq->lock);
	need_resched |= __handle_rxq(mdev, q_num, budget, 0);
	spin_unlock_bh(&rq->lock);

	if (need_resched)
		return budget;
	napi_complete(napi);
	wmb();
	return 0;
}

static int mdev_clean_tx_ring(struct octboot_net_dev *mdev, int q_idx)
{
	struct octboot_net_sw_descq *tq = &mdev->txq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct sk_buff *skb;
	int i, count, start;
	int descq_tot_size;
	dma_addr_t  dma;

	if (tq->status == OCTBOOT_NET_DESCQ_CLEAN)
		return 0;
	cons_idx = tq->local_cons_idx;
	prod_idx = tq->local_prod_idx;
	count = octboot_net_circq_depth(prod_idx, cons_idx, tq->mask);
	descq_tot_size = sizeof(struct octboot_net_hw_descq) +
		(tq->element_count * sizeof(struct octboot_net_hw_desc_ptr));
	start = cons_idx;
	for (i = 0; i < count; i++) {
		skb = tq->skb_list[start];
		dma = tq->dma_list[start];
		dma_unmap_single(mdev->dev, dma, skb->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(skb);
		tq->skb_list[start] = NULL;
		tq->dma_list[start] = 0;
		start = octboot_net_circq_inc(start, tq->mask);
	}
	tq->local_cons_idx = tq->local_prod_idx = 0;
	*tq->cons_idx_shadow = 0;
	tq->status = OCTBOOT_NET_DESCQ_CLEAN;
	vfree(tq->skb_list);
	vfree(tq->dma_list);
	/* tq status need to be updated before memset */
	wmb();
	mmio_memset(tq->hw_descq, 0, descq_tot_size);
	return count;
}

static void mdev_clean_tx_rings(struct octboot_net_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->num_txq && i < OCTBOOT_NET_MAXQ; i++)
		mdev_clean_tx_ring(mdev, i);
}

static int mdev_setup_tx_ring(struct octboot_net_dev *mdev, int q_idx)
{
	int element_count = mdev->element_count;
	struct octboot_net_hw_descq *descq;
	struct octboot_net_sw_descq *tq;
	int descq_tot_size;

	descq_tot_size = sizeof(struct octboot_net_hw_descq) + (element_count *
		sizeof(struct octboot_net_hw_desc_ptr));
	descq = kzalloc(descq_tot_size, GFP_KERNEL);
	if (!descq) {
		netdev_err(mdev->ndev, "octboot_net: tq descq alloc failed\n");
		return -ENOMEM;
	}
	tq = &mdev->txq[q_idx];
	tq->priv = mdev;
	tq->q_num = q_idx;
	tq->local_prod_idx = 0;
	tq->local_cons_idx = 0;
	tq->pending = 0;
	tq->element_count = element_count;
	tq->mask = element_count - 1;
	descq->num_entries = element_count;
	tq->cons_idx_shadow = mdev->tq_cons_shdw_vaddr + q_idx;
	descq->shadow_cons_idx_addr = mdev->tq_cons_shdw_dma +
	(q_idx * sizeof(*mdev->tq_cons_shdw_vaddr));
	*tq->cons_idx_shadow = 0;
	tq->hw_descq = TX_DESCQ_OFFSET(mdev) + (q_idx * descq_tot_size);
	tq->hw_prod_idx = (uint32_t *)(tq->hw_descq +
		offsetof(struct octboot_net_hw_descq, prod_idx));
	tq->skb_list = vzalloc(sizeof(struct sk_buff *) * element_count);
	if (!tq->skb_list) {
		kfree(descq);
		netdev_err(mdev->ndev, "octboot_net: tq skb_list alloc  failed\n");
		return -ENOMEM;
	}
	tq->dma_list = vzalloc(sizeof(dma_addr_t) * element_count);
	if (!tq->dma_list) {
		kfree(descq);
		vfree(tq->skb_list);
		netdev_err(mdev->ndev, "octboot_net: tq dma_list malloc failed\n");
		return -ENOMEM;
	}
	spin_lock_init(&tq->lock);
	wmb();
	tq->status = OCTBOOT_NET_DESCQ_READY;
	/* tq status needs to be updated before memwrite */
	wmb();
	mmio_memwrite(tq->hw_descq, descq, descq_tot_size);
	kfree(descq);
	return 0;
}

static int mdev_setup_tx_rings(struct octboot_net_dev *mdev)
{
	int i, j, ret;

	for  (i = 0; i < mdev->num_txq && i < OCTBOOT_NET_MAXQ; i++) {
		ret = mdev_setup_tx_ring(mdev, i);
		if (ret)
		goto error;
	}
	return 0;
error:
	for (j = 0; j < i; j++)
	mdev_clean_tx_ring(mdev, j);
	return ret;
}

static void mdev_clean_rx_ring(struct octboot_net_dev *mdev, int q_idx)
{
	struct octboot_net_sw_descq *rq = &mdev->rxq[q_idx];
	int cons_idx, prod_idx;
	struct sk_buff *skb;
	int descq_tot_size;
	int start, count;
	int i;

	if (rq->status == OCTBOOT_NET_DESCQ_CLEAN)
		return;
	napi_disable(&rq->napi);
	netif_napi_del(&rq->napi);
	cons_idx = rq->local_cons_idx;
	prod_idx = rq->local_prod_idx;
	count = octboot_net_circq_depth(prod_idx, cons_idx, rq->mask);
	descq_tot_size = sizeof(struct octboot_net_hw_descq) +
		(rq->element_count * sizeof(struct octboot_net_hw_desc_ptr));
	start = cons_idx;
	for (i = 0; i < count; i++) {
		skb = rq->skb_list[start];
		if (skb) {
			dma_unmap_single(mdev->dev, rq->dma_list[start],
					 OCTBOOT_NET_RX_BUF_SIZE,
					 DMA_FROM_DEVICE);
			dev_kfree_skb_any(skb);
			rq->skb_list[start] = NULL;
			rq->dma_list[start] = 0;
			start = octboot_net_circq_inc(start, rq->mask);
		}
	}
	rq->local_prod_idx = rq->local_cons_idx = 0;
	*rq->cons_idx_shadow = 0;
	vfree(rq->skb_list);
	vfree(rq->dma_list);
	rq->status = OCTBOOT_NET_DESCQ_CLEAN;
	/* rq needs to be updated before memset */
	wmb();
	mmio_memset(rq->hw_descq, 0, descq_tot_size);
}

static void mdev_clean_rx_rings(struct octboot_net_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->num_rxq && i < OCTBOOT_NET_MAXQ; i++)
		mdev_clean_rx_ring(mdev, i);
}

static int mdev_setup_rx_ring(struct octboot_net_dev *mdev, int q_idx)
{
	int element_count = mdev->element_count;
	struct octboot_net_hw_desc_ptr *ptr;
	struct octboot_net_hw_descq *descq;
	struct octboot_net_sw_descq *rq;
	int i, j, ret, count;
	struct sk_buff *skb;
	int descq_tot_size;
	dma_addr_t  dma;

	rq = &mdev->rxq[q_idx];
	rq->priv = mdev;
	descq_tot_size = sizeof(struct octboot_net_hw_descq) + (element_count *
		      sizeof(struct octboot_net_hw_desc_ptr));
	descq = kzalloc(descq_tot_size, GFP_KERNEL);
	if (!descq) {
		netdev_err(mdev->ndev, "octboot_net: rq descq alloc failed\n");
		return -ENOMEM;
	}
	rq->local_prod_idx = 0;
	rq->local_cons_idx = 0;
	rq->element_count = element_count;
	rq->mask = element_count - 1;
	rq->q_num = q_idx;
	rq->skb_list = vzalloc(sizeof(struct sk_buff *) * element_count);
	if (!rq->skb_list) {
		kfree(descq);
		netdev_err(mdev->ndev, "octboot_net: rq skb_list  alloc failed\n");
		return -ENOMEM;
	}

	rq->dma_list = vzalloc(sizeof(dma_addr_t) * element_count);
	if (!rq->dma_list) {
		kfree(descq);
		vfree(rq->skb_list);
		netdev_err(mdev->ndev, "octboot_net: rq dma_list  alloc failed\n");
		return -ENOMEM;
	}
	descq->num_entries = element_count;
	descq->buf_size = OCTBOOT_NET_RX_BUF_SIZE;
	rq->cons_idx_shadow = mdev->rq_cons_shdw_vaddr + q_idx;
	descq->shadow_cons_idx_addr = mdev->rq_cons_shdw_dma +
		(q_idx * sizeof(*rq->cons_idx_shadow));
	*rq->cons_idx_shadow = 0;
	count = octboot_net_circq_space(rq->local_prod_idx, rq->local_cons_idx,
		  rq->mask);
	for (i = 0; i < count; i++) {
		skb = alloc_skb(OCTBOOT_NET_RX_BUF_SIZE, GFP_KERNEL);
		if (!skb) {
		netdev_err(mdev->ndev, "octboot_net: skb alloc failed\n");
		ret = -ENOMEM;
		goto error;
	}
	skb->dev = mdev->ndev;
	dma = dma_map_single(mdev->dev, skb->data, OCTBOOT_NET_RX_BUF_SIZE,
		     DMA_FROM_DEVICE);
	if (dma_mapping_error(mdev->dev, dma)) {
		netdev_err(mdev->ndev, "octboot_net: dma mapping failed\n");
		dev_kfree_skb_any(skb);
		ret = -ENOENT;
		goto error;
	}
	ptr = &descq->desc_arr[rq->local_prod_idx];
	memset(ptr, 0, sizeof(struct octboot_net_hw_desc_ptr));
	ptr->hdr.s_mgmt_net.ptr_type = OCTBOOT_NET_DESC_PTR_DIRECT;
	ptr->ptr = dma;
	rq->skb_list[rq->local_prod_idx] = skb;
	rq->dma_list[rq->local_prod_idx] = dma;
	rq->local_prod_idx = octboot_net_circq_inc(rq->local_prod_idx,
		     rq->mask);
	descq->prod_idx = octboot_net_circq_inc(descq->prod_idx, rq->mask);
	}

	rq->hw_descq = RX_DESCQ_OFFSET(mdev) + (q_idx * descq_tot_size);
	rq->hw_prod_idx = (uint32_t *)(rq->hw_descq +
		       offsetof(struct octboot_net_hw_descq, prod_idx));
#if NAPI_ADD_HAS_BUDGET_ARG
	netif_napi_add(mdev->ndev, &rq->napi, octboot_net_napi_poll,
			NAPI_POLL_WEIGHT);
#else
	netif_napi_add(mdev->ndev, &rq->napi, octboot_net_napi_poll);
#endif
	napi_enable(&mdev->rxq[0].napi);
	rq->status = OCTBOOT_NET_DESCQ_READY;
	/* rq needs to be updated before memwrite */
	spin_lock_init(&rq->lock);
	wmb();
	mmio_memwrite(rq->hw_descq, descq, descq_tot_size);
	kfree(descq);
	return 0;
error:
	for (j = 0; j < i; j++) {
		skb = rq->skb_list[j];
		dma = rq->dma_list[j];
		if (skb) {
			dev_kfree_skb_any(skb);
			dma_unmap_single(mdev->dev, dma, OCTBOOT_NET_RX_BUF_SIZE,
			DMA_FROM_DEVICE);
		}
		rq->skb_list[j] = NULL;
		rq->dma_list[j] = 0;
	}
	rq->local_prod_idx = 0;
	rq->local_cons_idx = 0;
	kfree(descq);
	vfree(rq->skb_list);
	vfree(rq->dma_list);
	return ret;
}

static int mdev_setup_rx_rings(struct octboot_net_dev *mdev)
{
	int i, j, ret;

	for  (i = 0; i < mdev->num_rxq && i < OCTBOOT_NET_MAXQ; i++) {
		ret = mdev_setup_rx_ring(mdev, i);
		if (ret)
			goto error;
	}
	return 0;
error:
	for (j = 0; j < i; j++)
		mdev_clean_rx_ring(mdev, j);
	return ret;
}

static int mdev_reinit_rings(struct octboot_net_dev *mdev)
{
	int ret;

	mdev_clean_tx_rings(mdev);
	mdev_clean_rx_rings(mdev);
	ret = mdev_setup_tx_rings(mdev);
	if (ret)
		return ret;
	ret = mdev_setup_rx_rings(mdev);
	if (ret)
		mdev_clean_tx_rings(mdev);
	return ret;
}

static int handle_target_status(struct octboot_net_dev *mdev)
{
	uint64_t target_status;
	uint64_t cur_status;
	int ret = 0;

	cur_status = get_host_status(mdev);
	target_status = get_target_status(mdev);
	netdev_err(mdev->ndev, "host status %llu\n", cur_status);
	netdev_err(mdev->ndev, "target status %llu\n", target_status);

	switch (cur_status) {
	case OCTNET_HOST_READY:
		if (target_status == OCTNET_TARGET_RUNNING) {
			netdev_err(mdev->ndev, "octboot_net: target running\n");
			change_host_status(mdev, OCTNET_HOST_RUNNING, false);
			netif_carrier_on(mdev->ndev);
		}
		break;
	case OCTNET_HOST_RUNNING:
		target_status = get_target_status(mdev);
		if (target_status != OCTNET_TARGET_RUNNING) {
			netdev_err(mdev->ndev, "octboot_net: target stopped\n");
			change_host_status(mdev, OCTNET_HOST_GOING_DOWN,
						   false);
			netif_carrier_off(mdev->ndev);
			napi_synchronize(&mdev->rxq[0].napi);
			ret = mdev_reinit_rings(mdev);
			if (ret) {
				change_host_status(mdev, OCTNET_HOST_FATAL,
						   false);
				return ret;
			}
			change_host_status(mdev, OCTNET_HOST_READY, false);
		}
		break;
	default:
		netdev_err(mdev->ndev, "octboot_net: unhandled state transition host_status:%llu target_status %llu\n",
		       cur_status, target_status);
		break;
	}
	return ret;
}

static void octboot_net_task(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	union octboot_net_mbox_msg msg;
	struct octboot_net_dev *mdev;
	int ret;
	int q_num = 0;

	mdev = (struct octboot_net_dev *)container_of(delayed_work,
			struct octboot_net_dev, service_task);
	ret = mbox_check_msg_rcvd(mdev, &msg);
	if (!ret) {
		switch (msg.s.hdr.opcode) {
		case OCTBOOT_NET_MBOX_TARGET_STATUS_CHANGE:
			handle_target_status(mdev);
			if (msg.s.hdr.req_ack)
				set_host_mbox_ack_reg(mdev, msg.s.hdr.id);
			break;
		case OCTBOOT_NET_MBOX_OPCODE_INVALID:
			/* Return from octboot_net_task */
			return;
		default:
			break;
		}
	}

	if (spin_trylock_bh(&mdev->txq[q_num].lock)) {
		__handle_txq_completion(mdev, q_num, 0);
		spin_unlock_bh(&mdev->txq[q_num].lock);
	}
	if (spin_trylock_bh(&mdev->rxq[q_num].lock)) {

		__handle_rxq(mdev, q_num, 0, 1);
		spin_unlock_bh(&mdev->rxq[q_num].lock);
	}
	queue_delayed_work(mdev->mgmt_wq, &mdev->service_task,
		usecs_to_jiffies(OCTBOOT_NET_SERVICE_TASK_US));
}

static void octboot_net_get_drvinfo(struct net_device *dev,
			struct ethtool_drvinfo *info)
{
	struct octboot_net_dev *mdev =
		(struct octboot_net_dev *)netdev_priv(dev);

	strscpy(info->driver, "OCTBOOT_NET", sizeof(info->driver));
	strscpy(info->bus_info, pci_name(mdev->pdev), sizeof(info->bus_info));
}

static const struct ethtool_ops octboot_net_ethtool_ops = {
	.get_drvinfo = octboot_net_get_drvinfo,
	.get_link = ethtool_op_get_link,
};

void octboot_net_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &octboot_net_ethtool_ops;
}

static void mgmt_init_work(void *bar4_addr, int index)
{
	uint32_t *tq_cons_shdw_vaddr, *rq_cons_shdw_vaddr;
	dma_addr_t tq_cons_shdw_dma, rq_cons_shdw_dma;
	int num_txq, num_rxq, max_rxq, max_txq, ret;
	struct net_device *ndev;
	struct octboot_net_dev *mdev;
	struct pci_dev *octnet_pci_device;
	uint32_t host_version;
	uint32_t target_version;

	octnet_pci_device = octboot_struct[index].octnet_pci_dev_arr;

	max_txq = num_txq = OCTBOOT_NET_MAXQ;
	max_rxq = num_rxq = OCTBOOT_NET_MAXQ;
	tq_cons_shdw_vaddr = dma_alloc_coherent(&octnet_pci_device->dev,
		(sizeof(uint32_t) * num_txq),
		&tq_cons_shdw_dma, GFP_KERNEL);
	if (tq_cons_shdw_vaddr == NULL) {
		pr_err("octboot_net: dma_alloc_coherent tq failed\n");
		ret = -ENOMEM;
		goto conf_err;
	}

	rq_cons_shdw_vaddr = dma_alloc_coherent(&octnet_pci_device->dev,
		(sizeof(uint32_t) * num_rxq), &rq_cons_shdw_dma, GFP_KERNEL);
	if (rq_cons_shdw_vaddr == NULL) {
		ret = -ENOMEM;
		pr_err("octboot_net: dma_alloc_coherent rq failed\n");
		goto tq_dma_free;
	}
	/* we support only single queue at this time */
	ndev = alloc_netdev(sizeof(struct octboot_net_dev),
			    OCTBOOT_IFACE_NAME, NET_NAME_UNKNOWN, ether_setup);


	if (!ndev) {
		ret = -ENOMEM;
		pr_err("octboot_net: alloc_netdev failed\n");
		goto rq_dma_free;
	}
	ndev->netdev_ops = &octboot_netdev_ops;
	octboot_net_set_ethtool_ops(ndev);
	ndev->hw_features = NETIF_F_HIGHDMA;
	ndev->features = ndev->hw_features;
	ndev->mtu = OCTBOOT_NET_MAX_MTU;
	netif_carrier_off(ndev);
	eth_hw_addr_random(ndev);
	mdev = netdev_priv(ndev);
	memset(mdev, 0, sizeof(struct octboot_net_dev));
	mdev->admin_up = false;
	mdev->ndev = ndev;
	mdev->pdev = octnet_pci_device;
	mdev->bar_map = bar4_addr;
	mdev->dev = &octnet_pci_device->dev;
	mdev->max_txq = max_txq;
	mdev->max_rxq = max_rxq;
	mdev->num_txq = num_txq;
	mdev->num_rxq = num_rxq;
	mdev->element_count = OCTBOOT_NET_NUM_ELEMENTS;
	mdev->tq_cons_shdw_vaddr = tq_cons_shdw_vaddr;
	mdev->tq_cons_shdw_dma   = tq_cons_shdw_dma;
	mdev->rq_cons_shdw_vaddr = rq_cons_shdw_vaddr;
	mdev->rq_cons_shdw_dma   = rq_cons_shdw_dma;
	ret = mdev_setup_tx_rings(mdev);
	if (ret) {
		netdev_err(mdev->ndev, "octboot_net setup tx rings failed\n");
		goto free_net;
	}
	ret = mdev_setup_rx_rings(mdev);
	if (ret) {
		netdev_err(mdev->ndev, "octboot_net: setup rx rings failed\n");
		goto clean_tx_ring;
	}

	mdev->mgmt_wq = alloc_ordered_workqueue("octboot_net_task", 0);
	if (!mdev->mgmt_wq) {
		ret = -ENOMEM;
		netdev_err(mdev->ndev, "octboot_net_task: alloc_ordered_workqueue failed\n");
		goto clean_rx_ring;
	}
	mdev->send_mbox_id = 0;
	mdev->recv_mbox_id = 0;
	mutex_init(&mdev->mbox_lock);
	ret = register_netdev(ndev);
	if (ret) {
		netdev_err(mdev->ndev, "octboot_net: register_netdev failed\n");
		goto destroy_mutex;
	}
	change_host_status(mdev, OCTNET_HOST_READY, false);
	INIT_DELAYED_WORK(&mdev->service_task, octboot_net_task);
	queue_delayed_work(mdev->mgmt_wq, &mdev->service_task,
		   usecs_to_jiffies(OCTBOOT_NET_SERVICE_TASK_US));
	gmdev[index] = mdev;
	octboot_net_init_done[index] = 1;
	host_version = ((OCTBOOT_NET_VERSION_MAJOR << 8)|OCTBOOT_NET_VERSION_MINOR);
	writeq(host_version, HOST_VERSION_REG(mdev));
	target_version = get_target_version(mdev);
	if ((host_version >> 8) == (target_version >> 8))
		netdev_info(mdev->ndev, "octboot_net driver compatible with uboot\n");
	else
		netdev_err(mdev->ndev, "octboot_net driver Incompatible with uboot\n");

	return;
destroy_mutex:
	mutex_destroy(&mdev->mbox_lock);
	destroy_workqueue(mdev->mgmt_wq);
clean_rx_ring:
	mdev_clean_rx_rings(mdev);
clean_tx_ring:
	mdev_clean_tx_rings(mdev);
free_net:
	free_netdev(ndev);

rq_dma_free:
	dma_free_coherent(&octnet_pci_device->dev,
		  (sizeof(uint32_t) * num_rxq),
		  rq_cons_shdw_vaddr,
		  rq_cons_shdw_dma);
tq_dma_free:
	dma_free_coherent(&octnet_pci_device->dev,
		  (sizeof(uint32_t) * num_txq),
		  tq_cons_shdw_vaddr,
		  tq_cons_shdw_dma);
conf_err:
	pr_err("octboot_net: init failed; error = %d\n", ret);
	return;
}

static int __init octboot_net_init(void)
{
	octboot_net_init_wq = create_singlethread_workqueue("octboot_net_poll");
	if (!octboot_net_init_wq)
		return -ENOMEM;

	INIT_DELAYED_WORK(&octboot_net_init_task, octboot_net_init_work);
	queue_delayed_work(octboot_net_init_wq, &octboot_net_init_task, 0);
	return 0;
}

static void teardown_mdev_resources(struct octboot_net_dev *mdev)
{
	dma_free_coherent(mdev->dev,
			  (sizeof(uint32_t) * mdev->num_rxq),
			  mdev->rq_cons_shdw_vaddr,
			  mdev->rq_cons_shdw_dma);
	dma_free_coherent(mdev->dev,
			  (sizeof(uint32_t) * mdev->num_txq),
			  mdev->tq_cons_shdw_vaddr,
			  mdev->tq_cons_shdw_dma);
}

static void __exit octboot_net_exit(void)
{
	struct octboot_net_dev *mdev;
	int i;

	cancel_delayed_work_sync(&octboot_net_init_task);
	flush_workqueue(octboot_net_init_wq);
	destroy_workqueue(octboot_net_init_wq);

	for (i = 0; i < octnet_num_device; i++) {
		if (!gmdev[i])
			continue;
	mdev = gmdev[i];
	netif_carrier_off(mdev->ndev);
	change_host_status(mdev, OCTNET_HOST_GOING_DOWN, false);
	napi_synchronize(&mdev->rxq[0].napi);
	cancel_delayed_work_sync(&mdev->service_task);
	mdev_clean_rx_rings(mdev);
	mdev_clean_tx_rings(mdev);
	change_host_status(mdev, OCTNET_HOST_GOING_DOWN, false);
	mutex_destroy(&mdev->mbox_lock);
	destroy_workqueue(mdev->mgmt_wq);
	set_host_reset_status(mdev, true);
	unregister_netdev(mdev->ndev);
	teardown_mdev_resources(mdev);
	free_netdev(mdev->ndev);
	pci_disable_device(mdev->pdev);
	gmdev[i] = NULL;
	}
}

module_init(octboot_net_init);
module_exit(octboot_net_exit);
MODULE_AUTHOR("Marvell Inc.");
MODULE_DESCRIPTION("x86 octboot host driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(OCTBOOT_NET_VERSION);
