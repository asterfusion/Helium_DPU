/*****************************************************************************
 *  Copyright (C) 2018 Marvell International Ltd.
 *
 *  This program is provided "as is" without any warranty of any kind, and is
 *  distributed under the applicable Marvell limited use license agreement.
 *****************************************************************************/

#include <rte_interrupts.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>

#ifdef RTE_EAL_VFIO

#include <rte_malloc.h>
#include <linux/vfio.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>

#include "armada_ep_ethdev.h"

static int armada_ep_irq_config(struct rte_intr_handle *intr_handle,
				unsigned int vec, uint32_t vfio_irq_set_flag);

#define MSIX_IRQ_SET_BUF_LEN (sizeof(struct vfio_irq_set) + \
			      sizeof(int) * (RTE_MAX_RXTX_INTR_VEC_ID))

int
armada_ep_rx_queue_intr_enable(struct rte_eth_dev *eth_dev,
			      uint16_t rx_queue_id)
{
	struct		armada_ep_priv *priv = eth_dev->data->dev_private;
	struct		armada_ep_queue *q = priv->rx_queue[rx_queue_id];
	uint32_t	arr_idx;
	uint32_t	*msi_x_mask_p;

	arr_idx = ARMADA_EP_MSIX_GET_MASK_ARR_INDEX(q->intr_vec);
	msi_x_mask_p = &priv->nic_cfg->msi_x_mask[arr_idx];

	writel(ARMADA_EP_MSIX_GET_MASK(q->intr_vec) | readl(msi_x_mask_p),
		msi_x_mask_p);
	return 0;
}

int
armada_ep_rx_queue_intr_disable(struct rte_eth_dev *eth_dev,
			       uint16_t rx_queue_id)
{
	struct		armada_ep_priv *priv = eth_dev->data->dev_private;
	struct		armada_ep_queue *q = priv->rx_queue[rx_queue_id];
	uint32_t	arr_idx;
	uint32_t	*msi_x_mask_p;

	arr_idx = ARMADA_EP_MSIX_GET_MASK_ARR_INDEX(q->intr_vec);
	msi_x_mask_p = &priv->nic_cfg->msi_x_mask[arr_idx];

	writel(~ARMADA_EP_MSIX_GET_MASK(q->intr_vec) & readl(msi_x_mask_p),
		msi_x_mask_p);
	return 0;
}

static int
armada_ep_irq_get_info(struct rte_intr_handle *intr_handle)
{
	struct vfio_irq_info irq = { .argsz = sizeof(irq) };
	int ret;

	irq.index = VFIO_PCI_MSIX_IRQ_INDEX;

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq);
	if (ret < 0) {
		ARMADA_EP_LOG(ERR, "Failed to get IRQ info ret=%d", ret);
		return ret;
	}

	ARMADA_EP_LOG(DEBUG, "Flags=0x%x index=0x%x count=0x%x "
		      "max_intr_vec_id=0x%x", irq.flags, irq.index, irq.count,
		      RTE_MAX_RXTX_INTR_VEC_ID);

	if (irq.count > RTE_MAX_RXTX_INTR_VEC_ID) {
		ARMADA_EP_LOG(ERR, "HW max=%d > MAX_INTR_VEC_ID: %d",
			      intr_handle->max_intr, RTE_MAX_RXTX_INTR_VEC_ID);
		intr_handle->max_intr = RTE_MAX_RXTX_INTR_VEC_ID;
	} else {
		intr_handle->max_intr = irq.count;
	}

	return 0;
}

static int
armada_ep_irq_init(struct rte_intr_handle *intr_handle)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, ret;
	uint32_t i;

	if (intr_handle->max_intr > RTE_MAX_RXTX_INTR_VEC_ID) {
		ARMADA_EP_LOG(ERR, "Max_intr=%d greater than "
			      "MAX_INTR_VEC_ID=%d", intr_handle->max_intr,
			      RTE_MAX_RXTX_INTR_VEC_ID);
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

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret)
		ARMADA_EP_LOG(ERR, "Failed to set irqs vector rc=%d", ret);

	return ret;
}

static int
armada_ep_irq_config(struct rte_intr_handle *intr_handle, unsigned int vec,
		     uint32_t vfio_irq_set_flag)
{
	char irq_set_buf[MSIX_IRQ_SET_BUF_LEN];
	struct vfio_irq_set *irq_set;
	int32_t *fd_ptr;
	int len, ret;

	if (vec > intr_handle->max_intr) {
		ARMADA_EP_LOG(ERR, "vector=%d greater than max_intr=%d", vec,
				intr_handle->max_intr);
		return -EINVAL;
	}

	/* If no max_intr read from VFIO */
	if (intr_handle->max_intr == 0) {
		armada_ep_irq_get_info(intr_handle);
		armada_ep_irq_init(intr_handle);
	}

	len = sizeof(struct vfio_irq_set) + sizeof(int32_t);

	irq_set = (struct vfio_irq_set *)irq_set_buf;
	irq_set->argsz = len;

	irq_set->start = vec;
	irq_set->count = 1;
	irq_set->flags = vfio_irq_set_flag | VFIO_IRQ_SET_ACTION_TRIGGER;
	irq_set->index = VFIO_PCI_MSIX_IRQ_INDEX;

	/* Use vec fd to set interrupt vectors */
	if (vfio_irq_set_flag & VFIO_IRQ_SET_DATA_EVENTFD) {
		fd_ptr = (int32_t *)&irq_set->data[0];
		fd_ptr[0] = intr_handle->efds[vec];
	}

	ret = ioctl(intr_handle->vfio_dev_fd, VFIO_DEVICE_SET_IRQS, irq_set);
	if (ret)
		ARMADA_EP_LOG(ERR, "Failed to set_irqs vector=0x%x ret=%d", vec,
			      ret);

	return ret;
}

int
armada_ep_register_queue_irqs(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *intr_handle = &pci_dev->intr_handle;
	struct armada_ep_priv *priv = eth_dev->data->dev_private;
	uint32_t vec, irqs_nb;
	int local_fd, ret = 0;

	irqs_nb  = eth_dev->data->nb_rx_queues;

	if (!intr_handle->intr_vec) {
		intr_handle->intr_vec = rte_zmalloc("intr_vec",
						    irqs_nb * sizeof(int), 0);
		if (!intr_handle->intr_vec) {
			ARMADA_EP_LOG(ERR, "Failed to allocate %d rx intr_vec",
				      irqs_nb);
			return -ENOMEM;
		}
	}

	for (vec = 0; vec < irqs_nb; vec++) {
		priv->rx_queue[vec]->intr_vec = vec;

		/* Create new eventfd for interrupt vector */
		local_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (local_fd == -1)
			return -ENODEV;

		intr_handle->efds[vec] = local_fd;

		/* Enable MSIX vectors to VFIO */
		ret = armada_ep_irq_config(intr_handle, vec,
					   VFIO_IRQ_SET_DATA_EVENTFD);
		if (ret)
			break;

		intr_handle->intr_vec[vec] = RTE_INTR_VEC_RXTX_OFFSET + vec;
	}

	intr_handle->nb_efd = vec;
	intr_handle->max_intr = RTE_MAX(intr_handle->nb_efd + 1,
					intr_handle->max_intr);

	return ret;
}
#endif /* RTE_EAL_VFIO */

