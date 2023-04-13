/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#include <rte_string_fns.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_alarm.h>
#include <rte_ether.h>
#include <rte_io.h>

#include "otx2_common.h"
#include "otx_ep_common.h"
#include "otx_ep_vf.h"
#include "otx2_ep_vf.h"
#include "otx_ep_rxtx.h"

#include <inttypes.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define MAX_INTR_VEC_ID RTE_MAX_RXTX_INTR_VEC_ID
#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
		sizeof(int) * (MAX_INTR_VEC_ID))
#define OTX_EP_DEV(_eth_dev)		((_eth_dev)->data->dev_private)

static const struct rte_eth_desc_lim otx_ep_rx_desc_lim = {
	.nb_max		= OTX_EP_MAX_OQ_DESCRIPTORS,
	.nb_min		= OTX_EP_MIN_OQ_DESCRIPTORS,
	.nb_align	= 1,
};

static const struct rte_eth_desc_lim otx_ep_tx_desc_lim = {
	.nb_max		= OTX_EP_MAX_IQ_DESCRIPTORS,
	.nb_min		= OTX_EP_MIN_IQ_DESCRIPTORS,
	.nb_align	= 1,
};

static int
otx_ep_dev_info_get(struct rte_eth_dev *eth_dev,
		 struct rte_eth_dev_info *devinfo)
{

	struct otx_ep_device *otx_epvf = (struct otx_ep_device *)OTX_EP_DEV(eth_dev);
	struct rte_pci_device *pdev = otx_epvf->pdev;
	uint32_t dev_id = pdev->id.device_id;

    devinfo->min_mtu = OTX2_EP_PKT2MTU_SIZE(NIX_MIN_FRS);
    devinfo->max_mtu = OTX2_EP_PKT2MTU_SIZE(NIX_MAX_FRS);

	devinfo->speed_capa = ETH_LINK_SPEED_10G;
	devinfo->max_rx_queues = otx_epvf->max_rx_queues;
	devinfo->max_tx_queues = otx_epvf->max_tx_queues;

	devinfo->min_rx_bufsize = OTX_EP_MIN_RX_BUF_SIZE;
	if (dev_id == PCI_DEVID_OCTEONTX_EP_VF) {
		devinfo->max_rx_pktlen = OTX_EP_OQ_BUF_SIZE- OTX_EP_RH_SIZE;
		devinfo->rx_offload_capa = DEV_RX_OFFLOAD_JUMBO_FRAME;
		devinfo->rx_offload_capa |= DEV_RX_OFFLOAD_SCATTER;
		devinfo->tx_offload_capa = DEV_TX_OFFLOAD_MULTI_SEGS;
	} else if (dev_id == PCI_DEVID_OCTEONTX2_EP_NET_VF) {
		devinfo->max_rx_pktlen = NIX_MAX_FRS;
		devinfo->rx_offload_capa = DEV_RX_OFFLOAD_JUMBO_FRAME;
		devinfo->rx_offload_capa |= DEV_RX_OFFLOAD_SCATTER;
		devinfo->tx_offload_capa = DEV_TX_OFFLOAD_MULTI_SEGS;
	}

	devinfo->max_mac_addrs = 1;

	devinfo->rx_desc_lim = otx_ep_rx_desc_lim;
	devinfo->tx_desc_lim = otx_ep_tx_desc_lim;

	return 0;
}

static int
otx_ep_dev_link_update(struct rte_eth_dev *eth_dev,
		    int wait_to_complete __rte_unused)
{
	struct otx_ep_device *otx_epvf = (struct otx_ep_device *)OTX_EP_DEV(eth_dev);
	struct rte_eth_link link;

	memset(&link, 0, sizeof(link));
	link.link_status = ETH_LINK_DOWN;
	link.link_speed = ETH_SPEED_NUM_NONE;
	link.link_duplex = ETH_LINK_HALF_DUPLEX;
	link.link_autoneg = ETH_LINK_AUTONEG;
	if (otx_epvf->linkup) {
		link.link_status = ETH_LINK_UP;
		link.link_speed = ETH_SPEED_NUM_100G;
		link.link_duplex = ETH_LINK_FULL_DUPLEX;
	}
	return rte_eth_linkstatus_set(eth_dev, &link);
}

static int
otx_ep_promisc_enable(struct rte_eth_dev *eth_dev)
{
    return 0;
}
static int
otx_ep_promisc_disable(struct rte_eth_dev *eth_dev)
{
    return 0;
}

static int
otx_ep_dev_mtu_set(struct rte_eth_dev *eth_dev, uint16_t mtu)
{
    uint32_t frame_size = OTX2_EP_MTU2PKT_SIZE(mtu);

    // check if mtu is valid
    if ((frame_size < NIX_MIN_FRS) || (frame_size > NIX_MAX_FRS)) {
        return -EINVAL;
    }

    eth_dev->data->mtu = mtu;
    return 0;

}


/**
 * Api to check link state.
 */


static int
otx_ep_dev_start(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf = (struct otx_ep_device *)OTX_EP_DEV(eth_dev);
	unsigned int q;

	/* Enable IQ/OQ for this device */
	otx_epvf->fn_list.enable_io_queues(otx_epvf);

	for (q = 0; q < otx_epvf->nb_rx_queues; q++) {
		rte_write32(otx_epvf->droq[q]->nb_desc,
			    otx_epvf->droq[q]->pkts_credit_reg);

		rte_wmb();
		otx_ep_info("OQ[%d] dbells [%d]\n", q,
		rte_read32(otx_epvf->droq[q]->pkts_credit_reg));
	}

	otx_epvf->started = 1;
	otx_epvf->linkup = 1;

	rte_wmb();
	otx_ep_info("dev started\n");

	return 0;
}

/* Stop device and disable input/output functions */
static void
otx_ep_dev_stop(struct rte_eth_dev *eth_dev)
{
    struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);

    otx_epvf->started = 0;
    otx_epvf->linkup = 0;
    otx_epvf->fn_list.disable_io_queues(otx_epvf);
    struct otx_ep_droq *droq = otx_epvf->droq[0];
    rte_write32(0, droq->pkts_credit_reg);
//otx_ep_err("stop . set FFFFF\n");

//  while ((rte_read32(droq->pkts_credit_reg) != 0ull)) {
//      rte_write32(0xFFFFFFFF, droq->pkts_credit_reg);
//      rte_delay_ms(1);
//  }

}

static int
otx_ep_chip_specific_setup(struct otx_ep_device *otx_epvf)
{
	struct rte_pci_device *pdev = otx_epvf->pdev;
	uint32_t dev_id = pdev->id.device_id;
	int ret;

	switch (dev_id) {
	case PCI_DEVID_OCTEONTX_EP_VF:
		otx_epvf->chip_id = PCI_DEVID_OCTEONTX_EP_VF;
		ret = otx_ep_vf_setup_device(otx_epvf);
		otx_epvf->fn_list.disable_io_queues(otx_epvf);
		break;
	case PCI_DEVID_OCTEONTX2_EP_NET_VF:
		otx_epvf->chip_id = PCI_DEVID_OCTEONTX2_EP_NET_VF;
		ret = otx2_ep_vf_setup_device(otx_epvf);
		otx_epvf->fn_list.disable_io_queues(otx_epvf);
		break;
	default:
		otx_ep_err("Unsupported device\n");
		ret = -EINVAL;
	}

	if (!ret)
		otx_ep_info("OTX_EP dev_id[%d]\n", dev_id);

	return ret;
}

/* OTX_EP VF device initialization */
static int
otx_epdev_init(struct otx_ep_device *otx_epvf)
{
	uint32_t ethdev_queues;

	if (otx_ep_chip_specific_setup(otx_epvf)) {
		otx_ep_err("Chip specific setup failed\n");
		goto setup_fail;
	}

	if (otx_epvf->fn_list.setup_device_regs(otx_epvf)) {
		otx_ep_err("Failed to configure device registers\n");
		goto setup_fail;
	}

	otx_epvf->eth_dev->rx_pkt_burst = &otx_ep_recv_pkts;
	if (otx_epvf->chip_id == PCI_DEVID_OCTEONTX_EP_VF)
		otx_epvf->eth_dev->tx_pkt_burst = &otx_ep_xmit_pkts;
	else if (otx_epvf->chip_id == PCI_DEVID_OCTEONTX2_EP_NET_VF)
		otx_epvf->eth_dev->tx_pkt_burst = &otx2_ep_xmit_pkts;
	ethdev_queues = (uint32_t)(otx_epvf->sriov_info.rings_per_vf);
	otx_epvf->max_rx_queues = otx_epvf->max_tx_queues = ethdev_queues;

	otx_ep_info("OTX_EP Device is Ready\n");

	return 0;

setup_fail:
	return -ENOMEM;
}

static int otx_epvf_setup_rxq_intr(struct otx_ep_device *otx_epvf,
				   uint16_t q_no)
{
	struct rte_eth_dev *eth_dev = otx_epvf->eth_dev;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = &pci_dev->intr_handle;
	int rc, vec;

	vec = SDP_VF_R_MSIX(q_no);

	rc = otx_ep_register_irq(handle, vec);
	if (rc) {
		otx_ep_err("Fail to register Rx irq, rc=%d", rc);
		return rc;
	}

	if (!handle->intr_vec) {
		handle->intr_vec = rte_zmalloc("intr_vec",
				    otx_epvf->max_rx_queues *
				    sizeof(int), 0);
		if (!handle->intr_vec) {
			otx_ep_err("Failed to allocate %d rx intr_vec",
				 otx_epvf->max_rx_queues);
			return -ENOMEM;
		}
	}

	/* VFIO vector zero is resereved for misc interrupt so
	 * doing required adjustment.
	 */
	handle->intr_vec[q_no] = RTE_INTR_VEC_RXTX_OFFSET + vec;

	return rc;
}

static void otx_epvf_unset_rxq_intr(struct otx_ep_device *otx_epvf,
				    uint16_t q_no)
{
	/* Not yet implemented */
	struct rte_eth_dev *eth_dev = otx_epvf->eth_dev;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = &pci_dev->intr_handle;
	int vec;

	vec = SDP_VF_R_MSIX(q_no);
	otx_epvf->fn_list.disable_rxq_intr(otx_epvf, q_no);
	otx_ep_unregister_irq(handle, vec);
}

static int
otx_ep_dev_configure(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	struct rte_eth_dev_data *data = eth_dev->data;
	struct rte_eth_conf *conf = &data->dev_conf;
	struct rte_eth_rxmode *rxmode = &conf->rxmode;
	struct rte_eth_txmode *txmode = &conf->txmode;
	uint32_t ethdev_queues;
	uint16_t q;

	ethdev_queues = (uint32_t)(otx_epvf->sriov_info.rings_per_vf);
	if ((eth_dev->data->nb_rx_queues > ethdev_queues) ||
	    (eth_dev->data->nb_tx_queues > ethdev_queues)) {
		otx_ep_err("invalid num queues\n");
		return -ENOMEM;
	}
	otx_ep_info("OTX_EP Device is configured with num_txq %d num_rxq %d\n", eth_dev->data->nb_rx_queues, eth_dev->data->nb_tx_queues);

	otx_epvf->port_configured = 1;
	otx_epvf->rx_offloads = rxmode->offloads;
	otx_epvf->tx_offloads = txmode->offloads;

	if (eth_dev->data->dev_conf.intr_conf.rxq) {
		for (q = 0; q < eth_dev->data->nb_rx_queues; q++)
			otx_epvf_setup_rxq_intr(otx_epvf, q);
	}
	return 0;
}

static int
irq_get_info(struct rte_intr_handle *intr_handle)
{
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };
	int rc;

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;

	rc = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
	if (rc < 0) {
		otx_ep_err("Failed to get IRQ info rc=%d errno=%d", rc, errno);
		return rc;
	}

	otx_ep_dbg("Flags=0x%x index=0x%x count=0x%x max_intr_vec_id=0x%x",
		   irq.flags, irq.index, irq.count, MAX_INTR_VEC_ID);

	if (irq.count > MAX_INTR_VEC_ID) {
		otx_ep_err("HW max=%d > MAX_INTR_VEC_ID: %d",
			   intr_handle->max_intr, MAX_INTR_VEC_ID);
		intr_handle->max_intr = MAX_INTR_VEC_ID;
	} else {
		intr_handle->max_intr = irq.count;
	}

	return 0;
}

static int
irq_init(struct rte_intr_handle *intr_handle)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, rc;
	uint32_t i;

	if (intr_handle->max_intr > MAX_INTR_VEC_ID) {
		otx_ep_err("Max_intr=%d greater than MAX_INTR_VEC_ID=%d",
			   intr_handle->max_intr, MAX_INTR_VEC_ID);
		return -ERANGE;
	}

	len = sizeof(struct vfio_irq_set) +
		sizeof(int32_t) * intr_handle->max_intr;

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->start = 0;
	irq_set->count = intr_handle->max_intr;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			 VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	fd_ptr = (int32_t *)&irq_set->data[0];
	for (i = 0; i < irq_set->count; i++)
		fd_ptr[i] = -1;

	rc = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		otx_ep_err("Failed to set irqs vector rc=%d", rc);

	return rc;
}

static int
irq_config(struct rte_intr_handle *intr_handle, unsigned int vec)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, rc;

	if (vec > intr_handle->max_intr) {
		otx_ep_err("vector=%d greater than max_intr=%d", vec,
			   intr_handle->max_intr);
		return -EINVAL;
	}

	len = sizeof(struct vfio_irq_set) + sizeof(int32_t);
	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;
	irq_set->start = vec;
	irq_set->count = 1;
	irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD |
			 VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	/* Use vec fd to set interrupt vectors */
	fd_ptr = (int32_t *)&irq_set->data[0];
	fd_ptr[0] = intr_handle->efds[vec];

	rc = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (rc)
		otx_ep_err("Failed to set_irqs vector=0x%x rc=%d", vec, rc);

	return rc;
}

int
otx_ep_register_irq(struct rte_intr_handle *intr_handle, unsigned int vec)
{
	struct rte_intr_handle tmp_handle;

	/* If no max_intr read from VFIO */
	if (intr_handle->max_intr == 0) {
		irq_get_info(intr_handle);
		irq_init(intr_handle);
	}

	if (vec > intr_handle->max_intr) {
		otx_ep_err("Vector=%d greater than max_intr=%d", vec,
			   intr_handle->max_intr);
		return -EINVAL;
	}

	tmp_handle = *intr_handle;
	/* Create new eventfd for interrupt vector */
	tmp_handle.fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	if (tmp_handle.fd == -1)
		return -ENODEV;

	intr_handle->efds[vec] = tmp_handle.fd;
	intr_handle->nb_efd = ((vec + 1) > intr_handle->nb_efd) ?
			       (vec + 1) : intr_handle->nb_efd;
	intr_handle->max_intr = RTE_MAX(intr_handle->nb_efd + 1,
					intr_handle->max_intr);

	otx_ep_dbg("Enable vector:0x%x for vfio (efds: %d, max:%d)",
		   vec, intr_handle->nb_efd, intr_handle->max_intr);

	/* Enable MSIX vectors to VFIO */
	return irq_config(intr_handle, vec);
}

/**
 * @internal
 * Unregister IRQ
 */
void
otx_ep_unregister_irq(struct rte_intr_handle *intr_handle, unsigned int vec)
{
	struct rte_intr_handle tmp_handle;

	if (vec > intr_handle->max_intr) {
		otx_ep_err("Error unregistering MSI-X interrupts vec:%d > %d",
			vec, intr_handle->max_intr);
		return;
	}

	tmp_handle = *intr_handle;
	tmp_handle.fd = intr_handle->efds[vec];
	if (tmp_handle.fd == -1)
		return;

	otx_ep_dbg("Disable vector:0x%x for vfio (efds: %d, max:%d)",
			vec, intr_handle->nb_efd, intr_handle->max_intr);

	if (intr_handle->efds[vec] != -1)
		close(intr_handle->efds[vec]);
	/* Disable MSIX vectors from VFIO */
	intr_handle->efds[vec] = -1;
	irq_config(intr_handle, vec);
}
/**
 * Setup our receive queue/ringbuffer. This is the
 * queue the Octeon uses to send us packets and
 * responses. We are given a memory pool for our
 * packet buffers that are used to populate the receive
 * queue.
 *
 * @param eth_dev
 *    Pointer to the structure rte_eth_dev
 * @param q_no
 *    Queue number
 * @param num_rx_descs
 *    Number of entries in the queue
 * @param socket_id
 *    Where to allocate memory
 * @param rx_conf
 *    Pointer to the struction rte_eth_rxconf
 * @param mp
 *    Pointer to the packet pool
 *
 * @return
 *    - On success, return 0
 *    - On failure, return -1
 */
static int
otx_ep_rx_queue_setup(struct rte_eth_dev *eth_dev, uint16_t q_no,
		       uint16_t num_rx_descs, unsigned int socket_id,
		       const struct rte_eth_rxconf *rx_conf __rte_unused,
		       struct rte_mempool *mp)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	struct rte_pktmbuf_pool_private *mbp_priv;
	uint16_t buf_size;

	if (q_no >= otx_epvf->max_rx_queues) {
		otx_ep_err("Invalid rx queue number %u\n", q_no);
		return -EINVAL;
	}

	if (num_rx_descs & (num_rx_descs - 1)) {
		otx_ep_err("Invalid rx desc number should be pow 2  %u\n", num_rx_descs);
		return -EINVAL;
	}
	if (num_rx_descs > (SDP_GBL_WMARK * 4)) {
        //num_rx_descs = 2048;
        //otx_ep_err("Invalid rx desc number should at least be greater than 8 * wmark  %u use default 2048\n", num_rx_descs);
		num_rx_descs = 2048;
        //return -EINVAL;
	}

	otx_ep_dbg("setting up rx queue %u\n", q_no);

	mbp_priv = rte_mempool_get_priv(mp);
	buf_size = mbp_priv->mbuf_data_room_size - RTE_PKTMBUF_HEADROOM;

	if (otx_ep_setup_oqs(otx_epvf, q_no, num_rx_descs, buf_size, mp, socket_id)) {
		otx_ep_err("droq allocation failed\n");
		return -1;
	}

	eth_dev->data->rx_queues[q_no] = otx_epvf->droq[q_no];

	return 0;
}

/**
 * Release the receive queue/ringbuffer. Called by
 * the upper layers.
 *
 * @param rxq
 *    Opaque pointer to the receive queue to release
 *
 * @return
 *    - nothing
 */
static void
otx_ep_rx_queue_release(void *rxq)
{
	struct otx_ep_droq *rq = (struct otx_ep_droq *)rxq;
	int q_id = rq->q_no;
	struct otx_ep_device *otx_epvf = rq->otx_ep_dev;

	if (otx_ep_delete_oqs(otx_epvf, q_id)) {
			otx_ep_err("Failed to delete OQ:%d\n", q_id);
	}
}

/**
 * Allocate and initialize SW ring. Initialize associated HW registers.
 *
 * @param eth_dev
 *   Pointer to structure rte_eth_dev
 *
 * @param q_no
 *   Queue number
 *
 * @param num_tx_descs
 *   Number of ringbuffer descriptors
 *
 * @param socket_id
 *   NUMA socket id, used for memory allocations
 *
 * @param tx_conf
 *   Pointer to the structure rte_eth_txconf
 *
 * @return
 *   - On success, return 0
 *   - On failure, return -errno value
 */
static int
otx_ep_tx_queue_setup(struct rte_eth_dev *eth_dev, uint16_t q_no,
		       uint16_t num_tx_descs, unsigned int socket_id,
		       const struct rte_eth_txconf *tx_conf __rte_unused)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	int retval;

	if (q_no >= otx_epvf->max_tx_queues) {
		otx_ep_err("Invalid tx queue number %u\n", q_no);
		return -EINVAL;
	}
	if (num_tx_descs & (num_tx_descs - 1)) {
		otx_ep_err("Invalid tx desc number should be pow 2  %u\n", num_tx_descs);
		return -EINVAL;
	}

	retval = otx_ep_setup_iqs(otx_epvf, q_no, num_tx_descs, socket_id);

	if (retval) {
		otx_ep_err("IQ(TxQ) creation failed.\n");
		return retval;
	}

	eth_dev->data->tx_queues[q_no] = otx_epvf->instr_queue[q_no];
	otx_ep_dbg("tx queue[%d] setup\n", q_no);
	return 0;
}

/**
 * Release the transmit queue/ringbuffer. Called by
 * the upper layers.
 *
 * @param txq
 *    Opaque pointer to the transmit queue to release
 *
 * @return
 *    - nothing
 */
static void
otx_ep_tx_queue_release(void *txq)
{
	struct otx_ep_instr_queue *tq = (struct otx_ep_instr_queue *)txq;

	otx_ep_delete_iqs(tq->otx_ep_dev, tq->q_no);
}

static int
otx_ep_dev_stats_get(struct rte_eth_dev *eth_dev,
		  struct rte_eth_stats *stats)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	struct otx_ep_instr_queue *iq;
	struct otx_ep_droq *droq;
	int i;
	uint64_t bytes = 0;
	uint64_t pkts = 0;
	uint64_t drop = 0;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		iq = otx_epvf->instr_queue[i];
		pkts += iq->stats.tx_pkts;
		bytes += iq->stats.tx_bytes;
		drop +=  iq->stats.instr_dropped;
	}
	stats->opackets = pkts;
	stats->obytes = bytes;
	stats->oerrors = drop;

	pkts = 0;
	drop = 0;
	bytes = 0;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		droq = otx_epvf->droq[i];
		pkts += droq->stats.pkts_received;
		bytes += droq->stats.bytes_received;
		drop +=  droq->stats.rx_alloc_failure + droq->stats.rx_err;
	}
	stats->ibytes = bytes;
	stats->ipackets = pkts;
	stats->ierrors = drop;

	return 0;
}

static int
otx_ep_dev_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	struct otx_ep_instr_queue *iq;
	struct otx_ep_droq *droq;
	int i;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		iq = otx_epvf->instr_queue[i];
		iq->stats.tx_pkts = 0;
		iq->stats.tx_bytes = 0;
	}
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		droq = otx_epvf->droq[i];
		droq->stats.pkts_received = 0;
		droq->stats.bytes_received = 0;
	}
	return 0;
}

static int otx_ep_dev_rxq_irq_enable(struct rte_eth_dev *dev,
				     uint16_t rx_queue_id)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(dev);
	int rc;

	rc = otx_epvf->fn_list.enable_rxq_intr(otx_epvf, rx_queue_id);
	return rc;
}

static int otx_ep_dev_rxq_irq_disable(struct rte_eth_dev *dev,
				      uint16_t rx_queue_id)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(dev);
	int rc;

	rc = otx_epvf->fn_list.disable_rxq_intr(otx_epvf, rx_queue_id);
	return rc;
}

/* Define our ethernet definitions */
static const struct eth_dev_ops otx_ep_eth_dev_ops = {
	.dev_configure		= otx_ep_dev_configure,
	.dev_start		= otx_ep_dev_start,
	.dev_stop		= otx_ep_dev_stop,
	.rx_queue_setup	        = otx_ep_rx_queue_setup,
	.rx_queue_release	= otx_ep_rx_queue_release,
	.tx_queue_setup	        = otx_ep_tx_queue_setup,
	.tx_queue_release	= otx_ep_tx_queue_release,
	.link_update		= otx_ep_dev_link_update,
	.stats_get		= otx_ep_dev_stats_get,
	.stats_reset		= otx_ep_dev_stats_reset,
	.dev_infos_get		= otx_ep_dev_info_get,
	.rx_queue_intr_enable   = otx_ep_dev_rxq_irq_enable,
	.rx_queue_intr_disable  = otx_ep_dev_rxq_irq_disable,
	.mtu_set                  = otx_ep_dev_mtu_set,
	.promiscuous_enable       = otx_ep_promisc_enable,
	.promiscuous_disable      = otx_ep_promisc_disable,
};



static int
otx_epdev_exit(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf;
	uint32_t num_queues, q;

	otx_ep_info("%s:\n", __func__);

	otx_epvf = OTX_EP_DEV(eth_dev);

	otx_epvf->fn_list.disable_io_queues(otx_epvf);

	num_queues = otx_epvf->nb_rx_queues;
	for (q = 0; q < num_queues; q++) {
		if (otx_ep_delete_oqs(otx_epvf, q)) {
			otx_ep_err("Failed to delete OQ:%d\n", q);
			return -ENOMEM;
		}
	}
	otx_ep_info("Num OQs:%d freed\n", otx_epvf->nb_rx_queues);

	num_queues = otx_epvf->nb_tx_queues;
	for (q = 0; q < num_queues; q++) {
		if (otx_ep_delete_iqs(otx_epvf, q)) {
			otx_ep_err("Failed to delete IQ:%d\n", q);
			return -ENOMEM;
		}
	}
	otx_ep_dbg("Num IQs:%d freed\n", otx_epvf->nb_tx_queues);

	return 0;
}

static int
otx_ep_eth_dev_uninit(struct rte_eth_dev *eth_dev)
{
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	uint16_t q;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;
	otx_epdev_exit(eth_dev);

	if (eth_dev->data->dev_conf.intr_conf.rxq) {
		for (q = 0; q < eth_dev->data->nb_rx_queues; q++)
			otx_epvf_unset_rxq_intr(otx_epvf, q);
	}

	otx_epvf->port_configured = 0;

	eth_dev->dev_ops = NULL;
	eth_dev->rx_pkt_burst = NULL;
	eth_dev->tx_pkt_burst = NULL;

	return 0;
}



static int
otx_ep_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pdev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct otx_ep_device *otx_epvf = OTX_EP_DEV(eth_dev);
	int vf_id;
	unsigned char vf_mac_addr[RTE_ETHER_ADDR_LEN];

	/* Single process support */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	rte_eth_copy_pci_info(eth_dev, pdev);

	if (pdev->mem_resource[0].addr)
		otx_ep_info("OTX_EP_EP BAR0 is mapped:\n");
	else {
		otx_ep_err("OTX_EP_EP: Failed to map device BARs\n");
		otx_ep_err("BAR0 %p\n BAR2 %p",
			pdev->mem_resource[0].addr,
			pdev->mem_resource[2].addr);
		return -ENODEV;
	}
	otx_epvf->eth_dev = eth_dev;
	otx_epvf->port_id = eth_dev->data->port_id;
	eth_dev->dev_ops = &otx_ep_eth_dev_ops;
	eth_dev->data->mac_addrs = rte_zmalloc("otx_ep", RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		otx_ep_err("MAC addresses memory allocation failed\n");
		eth_dev->dev_ops = NULL;
		return -ENOMEM;
	}
	rte_eth_random_addr(vf_mac_addr);
	memcpy(eth_dev->data->mac_addrs, vf_mac_addr, RTE_ETHER_ADDR_LEN);
	otx_epvf->hw_addr = pdev->mem_resource[0].addr;
	otx_epvf->pdev = pdev;

	/* Discover the VF number being probed */
	vf_id = ((pdev->addr.devid & 0x1F) << 3) |
		 (pdev->addr.function & 0x7);

	vf_id -= 1;
	otx_epvf->vf_num = vf_id;
	otx_epdev_init(otx_epvf);
	if (pdev->id.device_id == PCI_DEVID_OCTEONTX2_EP_NET_VF)
		otx_epvf->pkind = SDP_OTX2_PKIND;
	else
		otx_epvf->pkind = SDP_PKIND +
				  (vf_id * otx_epvf->sriov_info.rings_per_vf);
	otx_ep_info("vfid %d using pkind %d\n", vf_id, otx_epvf->pkind);

	otx_epvf->port_configured = 0;

	return 0;
}

static int
otx_ep_eth_dev_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		      struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev, sizeof(struct otx_ep_device),
			otx_ep_eth_dev_init);
}

static int
otx_ep_eth_dev_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev,
					      otx_ep_eth_dev_uninit);
}


/* Set of PCI devices this driver supports */
static const struct rte_pci_id pci_id_otx_ep_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX_EP_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_EP_NET_VF) },
	{ .vendor_id = 0, /* sentinel */ }
};



static struct rte_pci_driver rte_otx_ep_pmd = {
	.id_table	= pci_id_otx_ep_map,
	.drv_flags      = RTE_PCI_DRV_NEED_MAPPING,
	.probe		= otx_ep_eth_dev_pci_probe,
	.remove		= otx_ep_eth_dev_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_otx_ep, rte_otx_ep_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_otx_ep, pci_id_otx_ep_map);
RTE_PMD_REGISTER_KMOD_DEP(net_otx_ep, "* igb_uio | vfio-pci");
