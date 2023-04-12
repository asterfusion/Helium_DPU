// SPDX-License-Identifier: (GPL-2.0)
/* Mgmt ethernet driver
 *
 * Copyright (C) 2015-2019 Marvell, Inc.
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h>
#endif

#include <facility.h>

#include <desc_queue.h>
#include <bar_space_mgmt_net.h>
#include <mmio_api.h>
#include <host_ethdev.h>
#include "octeon_device.h"

extern octeon_device_t *octeon_device[MAX_OCTEON_DEVICES];

#define MGMT_IFACE_NAME "mvmgmt%d"

#define TX_DESCQ_OFFSET(mdev) (mdev->bar_map + OTXMN_TX_DESCQ_OFFSET)
#define RX_DESCQ_OFFSET(mdev) (mdev->bar_map + OTXMN_RX_DESCQ_OFFSET)

#define TARGET_STATUS_REG(mdev) (mdev->bar_map + OTXMN_TARGET_STATUS_REG)
#define TARGET_INTR_REG(mdev) (mdev->bar_map + OTXMN_TARGET_INTR_REG)
#define TARGET_MBOX_MSG_REG(mdev, i) \
	(mdev->bar_map + OTXMN_TARGET_MBOX_OFFSET + (i * 8))
#define TARGET_MBOX_ACK_REG(mdev) \
	(mdev->bar_map + OTXMN_TARGET_MBOX_ACK_REG)

#define HOST_STATUS_REG(mdev) (mdev->bar_map + OTXMN_HOST_STATUS_REG)
#define HOST_INTR_REG(mdev) (mdev->bar_map + OTXMN_HOST_INTR_REG)
#define HOST_MBOX_ACK_REG(mdev) (mdev->bar_map + OTXMN_HOST_MBOX_ACK_REG)
#define HOST_MBOX_MSG_REG(mdev, i) \
	(mdev->bar_map + OTXMN_HOST_MBOX_OFFSET + (i * 8))

static struct workqueue_struct *mgmt_init_wq;
static struct workqueue_struct *heartbeat_wq;
static struct workqueue_struct *first_insmod_wq;
static struct delayed_work mgmt_init_task;
static struct delayed_work heartbeat_task;
#define MGMT_INIT_WQ_DELAY (1 * HZ)
int had_remove = 0;
static struct otxmn_dev *gmdev[MAX_OCTEON_DEVICES];
static int mgmt_net_napi_poll(struct napi_struct *napi, int budget);
static int mgmt_net_intr_hndlr(void *arg);

static uint64_t get_host_status(struct otxmn_dev *mdev)
{
	return readq(HOST_STATUS_REG(mdev));
}

static uint64_t get_target_status(struct otxmn_dev *mdev)
{
	return readq(TARGET_STATUS_REG(mdev));
}

static uint64_t get_target_mbox_ack(struct otxmn_dev *mdev)
{
	return readq(TARGET_MBOX_ACK_REG(mdev));
}

static void heartbeat_mvmgmt(struct work_struct *work);

static void set_host_mbox_ack_reg(struct otxmn_dev *mdev, uint32_t id)
{
	writeq(id, HOST_MBOX_ACK_REG(mdev));
}

static void mbox_send_msg(struct otxmn_dev *mdev, union otxmn_mbox_msg *msg)
{
	unsigned long timeout = msecs_to_jiffies(OTXMN_MBOX_TIMEOUT_MS);
	unsigned long period = msecs_to_jiffies(OTXMN_MBOX_WAIT_MS);
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
	if (msg->s.hdr.req_ack || msg->s.hdr.sizew)
	{
		/* printk(KERN_DEBUG "mbox send wait for ack\n"); */
		expire = jiffies + timeout;
		while (get_target_mbox_ack(mdev) != id)
		{
			schedule_timeout_interruptible(period);
			if ((signal_pending(current)) ||
				(time_after(jiffies, expire)))
			{
				printk(KERN_ERR "mgmt_net:mbox ack wait failed\n");
				break;
			}
		}
	}
	mutex_unlock(&mdev->mbox_lock);
}

static int mbox_check_msg_rcvd(struct otxmn_dev *mdev,
							   union otxmn_mbox_msg *msg)
{
	int i, ret;

	mutex_lock(&mdev->mbox_lock);
	msg->words[0] = readq(TARGET_MBOX_MSG_REG(mdev, 0));
	if (mdev->recv_mbox_id != msg->s.hdr.id)
	{
		/* new msg */
		/*printk(KERN_DEBUG "new mbox msg id:%d opcode:%d sizew: %d\n",
			   msg->s.hdr.id, msg->s.hdr.opcode, msg->s.hdr.sizew);
		*/
		mdev->recv_mbox_id = msg->s.hdr.id;
		for (i = 1; i <= msg->s.hdr.sizew; i++)
			msg->words[i] = readq(TARGET_MBOX_MSG_REG(mdev, i));
		ret = 0;
	}
	else
	{
		ret = -ENOENT;
	}
	mutex_unlock(&mdev->mbox_lock);
	return ret;
}

static void change_host_status(struct otxmn_dev *mdev, uint64_t status,
							   bool ack_wait)
{
	union otxmn_mbox_msg msg;

	/*printk(KERN_DEBUG "change host status from %lu to %llu \n",
		   readq(HOST_STATUS_REG(mdev)), status);
	*/
	writeq(status, HOST_STATUS_REG(mdev));
	memset(&msg, 0, sizeof(union otxmn_mbox_msg));
	msg.s.hdr.opcode = OTXMN_MBOX_HOST_STATUS_CHANGE;
	if (ack_wait)
		msg.s.hdr.req_ack = 1;
	mbox_send_msg(mdev, &msg);
}

netdev_tx_t mgmt_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct otxmn_dev *mdev = (struct otxmn_dev *)netdev_priv(dev);
	struct otxcn_hw_desc_ptr ptr;
	struct otxmn_sw_descq *tq;
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
	if (get_host_status(mdev) != OTXMN_HOST_RUNNING)
		goto err;
	/* dont handle non linear skb, did not set NETIF_F_SG */
	if (skb_is_nonlinear(skb))
		goto err;
	if (skb_put_padto(skb, ETH_ZLEN))
	{
		tq->errors++;
		return NETDEV_TX_OK;
	}
	bytes = skb->len;
#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 0, 0) || defined(P_SKBUFF_XMIT_MORE_2)
	xmit_more = 0;
#else
	xmit_more = skb->xmit_more;
#endif
	cur_cons_idx = READ_ONCE(*tq->cons_idx_shadow);
	cur_prod_idx = READ_ONCE(tq->local_prod_idx);
	if (!otxmn_circq_space(cur_prod_idx, cur_cons_idx, tq->mask))
	{
		tq->errors++;
		/* if we have accumulated skbs send them */
		if (tq->pending)
		{
			writel(tq->local_prod_idx, tq->hw_prod_idx);
			/* todo use shadow val */
			if (readq(TARGET_INTR_REG(mdev)) != 0)
				mv_send_facility_dbell(MV_FACILITY_MGMT_NETDEV, 0, mdev->oct_dev);
			tq->pending = 0;
		}
		return NETDEV_TX_BUSY;
	}
	memset(&ptr, 0, sizeof(struct otxcn_hw_desc_ptr));
	ptr.hdr.s_mgmt_net.ptr_type = OTXCN_DESC_PTR_DIRECT;
	ptr.hdr.s_mgmt_net.ptr_len = skb->len;
	ptr.hdr.s_mgmt_net.total_len = skb->len;
	dma = dma_map_single(mdev->dev, skb->data, skb->len,
						 DMA_TO_DEVICE);
	if (dma_mapping_error(mdev->dev, dma))
	{
		printk(KERN_ERR "dma mapping err in xmit\n");
		goto err;
	}
	ptr.ptr = dma;
	hw_desc_ptr = tq->hw_descq +
				  OTXCN_DESC_ARR_ENTRY_OFFSET(cur_prod_idx);
	/* printk(KERN_DEBUG "tx is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n",
		 ptr.hdr.s_mgmt_net.is_frag,
		 ptr.hdr.s_mgmt_net.total_len,
		 ptr.hdr.s_mgmt_net.ptr_type,
		 ptr.hdr.s_mgmt_net.ptr_len,
		 ptr.ptr);
	*/
	mmio_memwrite(hw_desc_ptr, &ptr, sizeof(struct otxcn_hw_desc_ptr));
	tq->skb_list[cur_prod_idx] = skb;
	tq->dma_list[cur_prod_idx] = dma;
	/* lists need to be updated before going forward */
	wmb();
	cur_prod_idx = otxmn_circq_inc(cur_prod_idx, tq->mask);
	WRITE_ONCE(tq->local_prod_idx, cur_prod_idx);
	tq->pkts += 1;
	tq->bytes += bytes;
	wmb();
	if (xmit_more && tq->pending < DPIX_MAX_PTR)
	{
		tq->pending++;
		return NETDEV_TX_OK;
	}
	writel(tq->local_prod_idx, tq->hw_prod_idx);
	if (readq(TARGET_INTR_REG(mdev)) != 0)
		mv_send_facility_dbell(MV_FACILITY_MGMT_NETDEV, 0, mdev->oct_dev);
	tq->pending = 0;
	return NETDEV_TX_OK;
err:
	tq->errors++;
	dev_kfree_skb_any(skb);
	return NETDEV_TX_OK;
}

static int mgmt_open(struct net_device *dev)
{
	struct otxmn_dev *mdev = netdev_priv(dev);

	mdev->admin_up = true;
	__module_get(THIS_MODULE);
	return 0;
}

static int mgmt_close(struct net_device *dev)
{
	struct otxmn_dev *mdev = netdev_priv(dev);

	mdev->admin_up = false;
	module_put(THIS_MODULE);
	return 0;
}

static void mgmt_get_stats64(struct net_device *dev,
							 struct rtnl_link_stats64 *s)
{
	struct otxmn_dev *mdev = netdev_priv(dev);
	int i;

	for (i = 0; i < mdev->num_rxq; i++)
	{
		s->rx_packets += mdev->rxq[i].pkts;
		s->rx_bytes += mdev->rxq[i].bytes;
		s->rx_errors += mdev->rxq[i].errors;
	}
	for (i = 0; i < mdev->num_txq; i++)
	{
		s->tx_packets += mdev->txq[i].pkts;
		s->tx_bytes += mdev->txq[i].bytes;
		s->tx_errors += mdev->txq[i].errors;
	}
}

static int mgmt_set_mac(struct net_device *netdev, void *p)
{
	struct otxmn_dev *mdev = netdev_priv(netdev);
	struct sockaddr *addr = (struct sockaddr *)p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(netdev->dev_addr, addr->sa_data, netdev->addr_len);
	memcpy(mdev->hw_addr, addr->sa_data, ETH_ALEN);

	return 0;
}

static const struct net_device_ops mgmt_netdev_ops = {
	.ndo_open = mgmt_open,
	.ndo_stop = mgmt_close,
	.ndo_start_xmit = mgmt_tx,
	.ndo_get_stats64 = mgmt_get_stats64,
	.ndo_set_mac_address = mgmt_set_mac,
};

static void dump_hw_descq(struct otxcn_hw_descq *descq)
{
	struct otxcn_hw_desc_ptr *ptr;
	int i, count;

	printk(KERN_DEBUG "prod_idx %u\n", descq->prod_idx);
	printk(KERN_DEBUG "cons_idx %u\n", descq->cons_idx);
	printk(KERN_DEBUG "num_entries %u\n", descq->num_entries);
	printk(KERN_DEBUG "shadow_cons_idx_addr 0x%llx\n",
		   descq->shadow_cons_idx_addr);
	count = otxmn_circq_depth(descq->prod_idx, descq->cons_idx, descq->num_entries - 1);
	for (i = 0; i < count; i++)
	{
		ptr = &descq->desc_arr[i];
		printk(KERN_DEBUG "idx:%d is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n",
			   i,
			   ptr->hdr.s_mgmt_net.is_frag,
			   ptr->hdr.s_mgmt_net.total_len,
			   ptr->hdr.s_mgmt_net.ptr_type,
			   ptr->hdr.s_mgmt_net.ptr_len,
			   ptr->ptr);
	}
}

static int mdev_clean_tx_ring(struct otxmn_dev *mdev, int q_idx)
{
	struct otxmn_sw_descq *tq = &mdev->txq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct sk_buff *skb;
	int i, count, start;
	int descq_tot_size;
	dma_addr_t dma;

	if (tq->status == OTXMN_DESCQ_CLEAN)
		return 0;
	cons_idx = tq->local_cons_idx;
	prod_idx = tq->local_prod_idx;
	count = otxmn_circq_depth(prod_idx, cons_idx, tq->mask);
	descq_tot_size = sizeof(struct otxcn_hw_descq) +
					 (tq->element_count * sizeof(struct otxcn_hw_desc_ptr));
	start = cons_idx;
	for (i = 0; i < count; i++)
	{
		skb = tq->skb_list[start];
		dma = tq->dma_list[start];
		dma_unmap_single(mdev->dev, dma, skb->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(skb);
		tq->skb_list[start] = NULL;
		tq->dma_list[start] = 0;
		start = otxmn_circq_inc(start, tq->mask);
	}
	tq->local_cons_idx = tq->local_prod_idx = 0;
	*tq->cons_idx_shadow = 0;
	tq->status = OTXMN_DESCQ_CLEAN;
	vfree(tq->skb_list);
	vfree(tq->dma_list);
	/* tq status need to be updated before memset */
	wmb();
	mmio_memset(tq->hw_descq, 0, descq_tot_size);
	return count;
}

static void mdev_clean_tx_rings(struct otxmn_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->num_txq; i++)
		mdev_clean_tx_ring(mdev, i);
}

/* tx rings are memset to 0. they dont have anything unless
 * there is something to send
 */
static int mdev_setup_tx_ring(struct otxmn_dev *mdev, int q_idx)
{
	int element_count = mdev->element_count;
	struct otxcn_hw_descq *descq;
	struct otxmn_sw_descq *tq;
	int descq_tot_size;

	descq_tot_size = sizeof(struct otxcn_hw_descq) + (element_count *
													  sizeof(struct otxcn_hw_desc_ptr));
	descq = kzalloc(descq_tot_size, GFP_KERNEL);
	if (!descq)
	{
		printk(KERN_ERR "mgmt_net: tq descq alloc failed\n");
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
								   offsetof(struct otxcn_hw_descq,
											prod_idx));
	tq->skb_list = vzalloc(sizeof(struct sk_buff *) * element_count);
	if (!tq->skb_list)
	{
		kfree(descq);
		printk(KERN_ERR "mgmt_net: tq skb_list alloc  failed\n");
		return -ENOMEM;
	}
	tq->dma_list = vzalloc(sizeof(dma_addr_t) * element_count);
	if (!tq->dma_list)
	{
		kfree(descq);
		vfree(tq->skb_list);
		printk(KERN_ERR "mgmt_net: tq dma_list malloc failed\n");
		return -ENOMEM;
	}
	spin_lock_init(&tq->lock);
	wmb();
	/* printk(KERN_DEBUG "tx hw descq\n");
	 * dump_hw_descq(descq); */
	tq->status = OTXMN_DESCQ_READY;
	/* tq status needs to be updated before memwrite */
	wmb();
	mmio_memwrite(tq->hw_descq, descq, descq_tot_size);
	kfree(descq);
	return 0;
}

static int mdev_setup_tx_rings(struct otxmn_dev *mdev)
{
	int i, j, ret;

	for (i = 0; i < mdev->num_txq; i++)
	{
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

static void mdev_clean_rx_ring(struct otxmn_dev *mdev, int q_idx)
{
	struct otxmn_sw_descq *rq = &mdev->rxq[q_idx];
	int cons_idx, prod_idx;
	struct sk_buff *skb;
	int descq_tot_size;
	int start, count;
	int i;

	if (rq->status == OTXMN_DESCQ_CLEAN)
		return;
	writeq(0, HOST_INTR_REG(mdev));
	napi_disable(&rq->napi);
	mv_facility_unregister_event_callback(MV_FACILITY_MGMT_NETDEV, mdev->oct_dev);
	netif_napi_del(&rq->napi);
	cons_idx = rq->local_cons_idx;
	prod_idx = rq->local_prod_idx;
	count = otxmn_circq_depth(prod_idx, cons_idx, rq->mask);
	descq_tot_size = sizeof(struct otxcn_hw_descq) +
					 (rq->element_count * sizeof(struct otxcn_hw_desc_ptr));
	start = cons_idx;
	for (i = 0; i < count; i++)
	{
		skb = rq->skb_list[start];
		if (skb)
		{
			dma_unmap_single(mdev->dev, rq->dma_list[start],
							 OTXMN_RX_BUF_SIZE,
							 DMA_FROM_DEVICE);
			dev_kfree_skb_any(skb);
			rq->skb_list[start] = NULL;
			rq->dma_list[start] = 0;
			start = otxmn_circq_inc(start, rq->mask);
		}
	}
	rq->local_prod_idx = rq->local_cons_idx = 0;
	*rq->cons_idx_shadow = 0;
	vfree(rq->skb_list);
	vfree(rq->dma_list);
	rq->status = OTXMN_DESCQ_CLEAN;
	/* rq needs to be updated before memset */
	wmb();
	mmio_memset(rq->hw_descq, 0, descq_tot_size);
}

static void mdev_clean_rx_rings(struct otxmn_dev *mdev)
{
	int i;

	for (i = 0; i < mdev->num_rxq; i++)
		mdev_clean_rx_ring(mdev, i);
}

static int mdev_setup_rx_ring(struct otxmn_dev *mdev, int q_idx)
{
	int element_count = mdev->element_count;
	struct otxcn_hw_desc_ptr *ptr;
	struct otxcn_hw_descq *descq;
	struct otxmn_sw_descq *rq;
	int i, j, ret, count;
	struct sk_buff *skb;
	int descq_tot_size;
	dma_addr_t dma;

	rq = &mdev->rxq[q_idx];
	rq->priv = mdev;
	descq_tot_size = sizeof(struct otxcn_hw_descq) + (element_count *
													  sizeof(struct otxcn_hw_desc_ptr));
	descq = kzalloc(descq_tot_size, GFP_KERNEL);
	if (!descq)
	{
		printk(KERN_ERR "mgmt_net: rq descq alloc failed\n");
		return -ENOMEM;
	}
	rq->local_prod_idx = 0;
	rq->local_cons_idx = 0;
	rq->element_count = element_count;
	rq->mask = element_count - 1;
	rq->q_num = q_idx;
	rq->skb_list = vzalloc(sizeof(struct sk_buff *) * element_count);
	if (!rq->skb_list)
	{
		kfree(descq);
		printk(KERN_ERR "mgmt_net: rq skb_list  alloc failed\n");
		return -ENOMEM;
	}
	rq->dma_list = vzalloc(sizeof(dma_addr_t) * element_count);
	if (!rq->dma_list)
	{
		kfree(descq);
		vfree(rq->skb_list);
		printk(KERN_ERR "mgmt_net: rq dma_list  alloc failed\n");
		return -ENOMEM;
	}
	descq->num_entries = element_count;
	descq->buf_size = OTXMN_RX_BUF_SIZE;
	rq->cons_idx_shadow = mdev->rq_cons_shdw_vaddr + q_idx;
	/* TODO split the shadow add per cache line for each queue
	 */
	descq->shadow_cons_idx_addr = mdev->rq_cons_shdw_dma +
								  (q_idx * sizeof(*rq->cons_idx_shadow));
	*rq->cons_idx_shadow = 0;
	count = otxmn_circq_space(rq->local_prod_idx, rq->local_cons_idx,
							  rq->mask);
	for (i = 0; i < count; i++)
	{
		skb = alloc_skb(OTXMN_RX_BUF_SIZE, GFP_KERNEL);
		if (!skb)
		{
			printk(KERN_ERR "mgmt_net: skb alloc failed\n");
			ret = -ENOMEM;
			goto error;
		}
		skb->dev = mdev->ndev;
		dma = dma_map_single(mdev->dev, skb->data, OTXMN_RX_BUF_SIZE,
							 DMA_FROM_DEVICE);
		if (dma_mapping_error(mdev->dev, dma))
		{
			printk(KERN_ERR "mgmt_net: dma mapping failed\n");
			dev_kfree_skb_any(skb);
			ret = -ENOENT;
			goto error;
		}
		ptr = &descq->desc_arr[rq->local_prod_idx];
		memset(ptr, 0, sizeof(struct otxcn_hw_desc_ptr));
		ptr->hdr.s_mgmt_net.ptr_type = OTXCN_DESC_PTR_DIRECT;
		ptr->ptr = dma;
		rq->skb_list[rq->local_prod_idx] = skb;
		rq->dma_list[rq->local_prod_idx] = dma;
		rq->local_prod_idx = otxmn_circq_inc(rq->local_prod_idx,
											 rq->mask);
		descq->prod_idx = otxmn_circq_inc(descq->prod_idx, rq->mask);
	}
	rq->hw_descq = RX_DESCQ_OFFSET(mdev) + (q_idx * descq_tot_size);
	rq->hw_prod_idx = (uint32_t *)(rq->hw_descq +
								   offsetof(struct otxcn_hw_descq,
											prod_idx));
	/* printk(KERN_DEBUG "rx hw descq\n");
	 * dump_hw_descq(descq);
	printk(KERN_DEBUG "dma list\n");
	for (i = 0; i < count; i++)
		printk(KERN_DEBUG "idx:%d skb->data %p  dma 0x%llx\n",
			   i, rq->skb_list[i]->data, rq->dma_list[i]);
	*/
	ret = mv_facility_register_event_callback(MV_FACILITY_MGMT_NETDEV,
					  	  mgmt_net_intr_hndlr,
                                       	  	  (void *)mdev, mdev->oct_dev);
	if (ret) {
		printk("register event callback failed\n");
		ret = -ENOENT;
		goto error;
	}
	netif_napi_add(mdev->ndev, &rq->napi, mgmt_net_napi_poll,
				   NAPI_POLL_WEIGHT);
	napi_enable(&mdev->rxq[0].napi);
	writeq(1, HOST_INTR_REG(mdev));
	rq->status = OTXMN_DESCQ_READY;
	/* rq needs to be updated before memwrite */
	spin_lock_init(&rq->lock);
	wmb();
	mmio_memwrite(rq->hw_descq, descq, descq_tot_size);
	kfree(descq);
	return 0;
error:
	for (j = 0; j < i; j++)
	{
		skb = rq->skb_list[j];
		dma = rq->dma_list[j];
		if (skb)
		{
			dev_kfree_skb_any(skb);
			dma_unmap_single(mdev->dev, dma, OTXMN_RX_BUF_SIZE,
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

static int mdev_setup_rx_rings(struct otxmn_dev *mdev)
{
	int i, j, ret;

	for (i = 0; i < mdev->num_rxq; i++)
	{
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

static int mdev_reinit_rings(struct otxmn_dev *mdev)
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

static int handle_target_status(struct otxmn_dev *mdev)
{
	uint64_t target_status;
	uint64_t cur_status;
	int ret = 0;

	cur_status = get_host_status(mdev);
	target_status = get_target_status(mdev);
	/* printk(KERN_DEBUG "host status %llu\n", cur_status);
	printk(KERN_DEBUG "target status %llu\n", target_status);
	*/
	printk(KERN_DEBUG "oct %d host status %llu, target_status %llu\n", ((octeon_device_t *)mdev->oct_dev)->octeon_id, cur_status, target_status);
	switch (cur_status)
	{
	case OTXMN_HOST_READY:
		if (target_status == OTXMN_TARGET_RUNNING)
		{
			printk(KERN_DEBUG "mgmt_net: target running\n");
			change_host_status(mdev, OTXMN_HOST_RUNNING, false);
			netif_carrier_on(mdev->ndev);
		}
		break;
	case OTXMN_HOST_RUNNING:
		target_status = get_target_status(mdev);
		if (target_status != OTXMN_TARGET_RUNNING)
		{
			printk(KERN_DEBUG "mgmt_net: target stopped\n");
			change_host_status(mdev, OTXMN_HOST_GOING_DOWN,
							   false);
			netif_carrier_off(mdev->ndev);
			napi_synchronize(&mdev->rxq[0].napi);
			ret = mdev_reinit_rings(mdev);
			if (ret)
			{
				change_host_status(mdev, OTXMN_HOST_FATAL,
								   false);
				return ret;
			}
			change_host_status(mdev, OTXMN_HOST_READY, false);
		}
		break;
	default:
		printk(KERN_DEBUG "mgmt_net: unhandled state transition host_status:%llu target_status %llu\n",
			   cur_status, target_status);
		break;
	}
	return ret;
}

static bool __handle_txq_completion(struct otxmn_dev *mdev, int q_idx, int budget)
{
	struct otxmn_sw_descq *tq = &mdev->txq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct sk_buff *skb;
	int count, start, i;
	dma_addr_t dma;
	bool resched = false;

	if (!mdev->admin_up)
		return false;
	if (get_host_status(mdev) != OTXMN_HOST_RUNNING)
		return false;

	cons_idx = READ_ONCE(tq->local_cons_idx);
	prod_idx = READ_ONCE(*tq->cons_idx_shadow);
	count = otxmn_circq_depth(prod_idx, cons_idx, tq->mask);
	if (budget && count > budget)
	{
		resched = true;
		count = budget;
	}
	start = cons_idx;
	for (i = 0; i < count; i++)
	{
		skb = tq->skb_list[start];
		dma = tq->dma_list[start];
		dma_unmap_single(mdev->dev, dma, skb->len, DMA_TO_DEVICE);
		dev_kfree_skb_any(skb);
		tq->skb_list[start] = NULL;
		tq->dma_list[start] = 0;
		start = otxmn_circq_inc(start, tq->mask);
	}
	/* update lists before updating cons idx */
	wmb();
	cons_idx = otxmn_circq_add(cons_idx, count, tq->mask);
	WRITE_ONCE(tq->local_cons_idx, cons_idx);
	wmb();
	if (resched == false)
	{
		/* check again */
		cons_idx = READ_ONCE(tq->local_cons_idx);
		prod_idx = READ_ONCE(*tq->cons_idx_shadow);
		count = otxmn_circq_depth(prod_idx, cons_idx, tq->mask);
		if (count)
			resched = true;
	}
	return resched;
}

static int rxq_refill(struct otxmn_dev *mdev, int q_idx, int count)
{
	struct otxmn_sw_descq *rq = &mdev->rxq[q_idx];
	int cur_prod_idx, start;
	struct otxcn_hw_desc_ptr ptr;
	uint8_t *hw_desc_ptr;
	struct sk_buff *skb;
	dma_addr_t dma;
	int i;

	cur_prod_idx = READ_ONCE(rq->local_prod_idx);
	start = cur_prod_idx;
	for (i = 0; i < count; i++)
	{
		memset(&ptr, 0, sizeof(struct otxcn_hw_desc_ptr));
		skb = dev_alloc_skb(OTXMN_RX_BUF_SIZE);
		if (!skb)
		{
			printk(KERN_ERR "mgmt_net: skb alloc fail\n");
			break;
		}
		skb->dev = mdev->ndev;
		dma = dma_map_single(mdev->dev, skb->data, OTXMN_RX_BUF_SIZE,
							 DMA_FROM_DEVICE);
		if (dma_mapping_error(mdev->dev, dma))
		{
			dev_kfree_skb_any(skb);
			printk(KERN_ERR "mgmt_net: dma mapping fail\n");
			break;
		}
		ptr.hdr.s_mgmt_net.ptr_type = OTXCN_DESC_PTR_DIRECT;
		ptr.ptr = dma;
		if (rq->skb_list[start] != NULL || rq->dma_list[start] != 0)
		{
			dev_kfree_skb_any(skb);
			printk(KERN_ERR "mgmt_net:refill err entry !empty\n");
			break;
		}
		rq->skb_list[start] = skb;
		rq->dma_list[start] = dma;
		hw_desc_ptr = rq->hw_descq +
					  OTXCN_DESC_ARR_ENTRY_OFFSET(start);
		mmio_memwrite(hw_desc_ptr, &ptr,
					  sizeof(struct otxcn_hw_desc_ptr));
		start = otxmn_circq_inc(start, rq->mask);
	}
	/* the lists need to be updated before updating hwprod idx */
	wmb();
	cur_prod_idx = otxmn_circq_add(cur_prod_idx, i, rq->mask);
	WRITE_ONCE(rq->local_prod_idx, cur_prod_idx);
	writel(rq->local_prod_idx, rq->hw_prod_idx);
	wmb();
	/* tx complete intr to target */
	if (readq(TARGET_INTR_REG(mdev)) != 0)
		mv_send_facility_dbell(MV_FACILITY_MGMT_NETDEV, 0, mdev->oct_dev);
	return i;
}

/* static void pkt_hex_dump(struct sk_buff *skb)
{
	int i, l, linelen, remaining;
	uint8_t *data, ch;
	int rowsize = 16;
	size_t len;
	int li = 0;

	printk("Packet hex dump:\n");
	data = (uint8_t *) skb->data;
	len = skb->len;
	remaining = len;
	for (i = 0; i < len; i += rowsize) {
		printk("%06d\t", li);
		linelen = min(remaining, rowsize);
		remaining -= rowsize;
		for (l = 0; l < linelen; l++) {
			ch = data[l];
			printk(KERN_CONT "%02X ", (uint32_t) ch);
		}
		data += linelen;
		li += 10;
		printk(KERN_CONT "\n");
	}
} */

static bool __handle_rxq(struct otxmn_dev *mdev, int q_idx, int budget, int from_wq)
{
	struct otxmn_sw_descq *rq = &mdev->rxq[q_idx];
	uint32_t cons_idx, prod_idx;
	struct otxcn_hw_desc_ptr ptr;
	uint8_t *hw_desc_ptr;
	int count, start, i;
	struct sk_buff *skb;
	struct otxcn_hw_descq *tmp_descq;
	int descq_tot_size;
	bool resched = false;
	struct napi_struct *napi = &rq->napi;

	if (!mdev->admin_up)
		return false;
	if (get_host_status(mdev) != OTXMN_HOST_RUNNING)
		return false;

	cons_idx = READ_ONCE(rq->local_cons_idx);
	prod_idx = READ_ONCE(*rq->cons_idx_shadow);
	count = otxmn_circq_depth(prod_idx, cons_idx, rq->mask);
	if (!count)
		return false;
	if (budget && count > budget)
	{
		resched = true;
		count = budget;
	}
	start = cons_idx;
	for (i = 0; i < count; i++)
	{
		skb = rq->skb_list[start];
		dma_unmap_single(mdev->dev, rq->dma_list[start],
						 OTXMN_RX_BUF_SIZE,
						 DMA_FROM_DEVICE);
		hw_desc_ptr = rq->hw_descq +
					  OTXCN_DESC_ARR_ENTRY_OFFSET(start);
		/* this is not optimal metatadata should probaly be in the packet */
		mmio_memread(&ptr, hw_desc_ptr,
					 sizeof(struct otxcn_hw_desc_ptr));
		/*printk(KERN_DEBUG "is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n",
			 ptr.hdr.s_mgmt_net.is_frag,
			 ptr.hdr.s_mgmt_net.total_len,
			 ptr.hdr.s_mgmt_net.ptr_type,
			 ptr.hdr.s_mgmt_net.ptr_len,
			 ptr.ptr);
		*/
		if (unlikely(ptr.hdr.s_mgmt_net.total_len < ETH_ZLEN ||
					 ptr.hdr.s_mgmt_net.is_frag ||
					 ptr.hdr.s_mgmt_net.ptr_len != ptr.hdr.s_mgmt_net.ptr_len))
		{
			/* dont handle frags now */
			printk(KERN_ERR "mgmt_net: bad rx pkt\n");
			printk(KERN_ERR "is_frag:%d total_len:%d ptr_type:%d ptr_len:%d ptr:0x%llx\n",
				   ptr.hdr.s_mgmt_net.is_frag,
				   ptr.hdr.s_mgmt_net.total_len,
				   ptr.hdr.s_mgmt_net.ptr_type,
				   ptr.hdr.s_mgmt_net.ptr_len,
				   ptr.ptr);
			rq->errors++;
			descq_tot_size = sizeof(struct otxcn_hw_descq) +
							 (rq->element_count *
							  sizeof(struct otxcn_hw_desc_ptr));
			printk(KERN_ERR "rq->element count %d\n, descq_tot_size %d\n", rq->element_count, descq_tot_size);
			tmp_descq = kmalloc(descq_tot_size, GFP_KERNEL);
			if (!tmp_descq)
			{
				printk(KERN_ERR "rx error kmalloc\n");
			}
			else
			{
				mmio_memread(tmp_descq, rq->hw_descq,
							 descq_tot_size);
				dump_hw_descq(tmp_descq);
				kfree(tmp_descq);
			}
			dev_kfree_skb_any(skb);
		}
		else
		{
			skb_put(skb, ptr.hdr.s_mgmt_net.total_len);
			/* pkt_hex_dump(skb); */
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
		start = otxmn_circq_inc(start, rq->mask);
	}
	/* lists need to be updated before updating cons idx */
	wmb();
	cons_idx = otxmn_circq_add(cons_idx, count, rq->mask);
	WRITE_ONCE(rq->local_cons_idx, cons_idx);
	wmb();
	rxq_refill(mdev, q_idx, count);
	/* check again */
	if (resched == false)
	{
		cons_idx = READ_ONCE(rq->local_cons_idx);
		prod_idx = READ_ONCE(*rq->cons_idx_shadow);
		count = otxmn_circq_depth(prod_idx, cons_idx, rq->mask);
		if (count)
			resched = true;
	}
	return resched;
}

static int mgmt_net_napi_poll(struct napi_struct *napi, int budget)
{
	struct otxmn_sw_descq *rq;
	struct otxmn_sw_descq *tq;
	struct otxmn_dev *mdev;
	int q_num;
	bool need_resched = false;

	rq = container_of(napi, struct otxmn_sw_descq, napi);
	mdev = (struct otxmn_dev *)rq->priv;
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
	writeq(1, HOST_INTR_REG(mdev));
	wmb();
	return 0;
}

static int mgmt_net_intr_hndlr(void *arg)
{
	struct otxmn_dev *mdev;

	mdev = (struct otxmn_dev *)arg;
	writeq(0, HOST_INTR_REG(mdev));
	wmb();
	/* hard coded queue num */
	napi_schedule_irqoff(&mdev->rxq[0].napi);
	return 0;
}

static void mgmt_net_task(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	union otxmn_mbox_msg msg;
	struct otxmn_dev *mdev;
	int ret;
	int q_num = 0;

	mdev = (struct otxmn_dev *)container_of(delayed_work, struct otxmn_dev,
											service_task);
	ret = mbox_check_msg_rcvd(mdev, &msg);
	if (!ret)
	{
		switch (msg.s.hdr.opcode)
		{
		case OTXMN_MBOX_TARGET_STATUS_CHANGE:
			handle_target_status(mdev);
			if (msg.s.hdr.req_ack)
				set_host_mbox_ack_reg(mdev, msg.s.hdr.id);
			break;

		default:
			break;
		}
	}
	if (spin_trylock_bh(&mdev->txq[q_num].lock))
	{
		__handle_txq_completion(mdev, q_num, 0);
		spin_unlock_bh(&mdev->txq[q_num].lock);
	}
	if (spin_trylock_bh(&mdev->rxq[q_num].lock))
	{
		__handle_rxq(mdev, q_num, 0, 1);
		spin_unlock_bh(&mdev->rxq[q_num].lock);
	}
	queue_delayed_work(mdev->mgmt_wq, &mdev->service_task,
					   usecs_to_jiffies(OTXMN_SERVICE_TASK_US));
}

static void mgmt_init_work_oct(struct work_struct *work, octeon_device_t *oct_dev)
{
	uint32_t *tq_cons_shdw_vaddr, *rq_cons_shdw_vaddr;
	dma_addr_t tq_cons_shdw_dma, rq_cons_shdw_dma;
	int num_txq, num_rxq, max_rxq, max_txq, ret;
	mv_facility_conf_t conf;
	struct net_device *ndev;
	struct otxmn_dev *mdev;
	char mvm_name[20]="";
	// if the octeon_id have register mdev, return
	if (gmdev[oct_dev->octeon_id])
	{
		return;
	}

	ret = mv_get_facility_conf(MV_FACILITY_MGMT_NETDEV, &conf, oct_dev);
	if (ret == -ENOENT)
	{
		printk(KERN_ERR
			   "mgmt_net[%d]: failed to get facility config; Error: Unsupported facility\n",
			   oct_dev->octeon_id);
		ret = -ENODEV;
		goto conf_err;
	}
	if (ret == -ENODEV)
	{
		printk(KERN_ERR
			   "mgmt_net[%d]: facility conf Error\n",
			   oct_dev->octeon_id);
		goto conf_err;
	}
	if (ret == -EAGAIN)
	{
		printk_once(KERN_INFO
					"mgmt_net[%d]: Waiting for facility config availability\n",
					oct_dev->octeon_id);
		queue_delayed_work(mgmt_init_wq, &mgmt_init_task,
						   MGMT_INIT_WQ_DELAY);
		return;
	}
	printk(KERN_INFO "mgmt_net[%d]: Got the facility config\n", oct_dev->octeon_id);

	if (conf.memsize < OTXMN_BAR_SIZE)
	{
		printk(KERN_ERR "mgmt_net:bar size less %d\n", conf.memsize);
		ret = -ENODEV;
		goto conf_err;
	}
	if (conf.num_h2t_dbells < 1)
	{
		printk(KERN_ERR "mgmt_net:need at least 1 h2t dbell %d\n", conf.num_h2t_dbells);
		ret = -ENODEV;
		goto conf_err;
	}
	printk(KERN_DEBUG "mgmt_net[%d]:conf.map_addr.bar_map %p\n", oct_dev->octeon_id,
		   conf.memmap.host_addr);
	printk(KERN_DEBUG "mgmt_net[%d]:conf.map_size %d\n", oct_dev->octeon_id, conf.memsize);
	/* irrespective of resources, we support single queue only */
	max_txq = num_txq = OTXMN_MAXQ;
	max_rxq = num_rxq = OTXMN_MAXQ;
	tq_cons_shdw_vaddr = dma_alloc_coherent(conf.dma_dev.host_ep_dev,
											(sizeof(uint32_t) * num_txq),
											&tq_cons_shdw_dma,
											GFP_KERNEL);
	if (tq_cons_shdw_vaddr == NULL)
	{
		printk(KERN_ERR "mgmt_net: dma_alloc_coherent tq failed\n");
		ret = -ENOMEM;
		goto conf_err;
	}
	rq_cons_shdw_vaddr = dma_alloc_coherent(conf.dma_dev.host_ep_dev,
											(sizeof(uint32_t) * num_rxq),
											&rq_cons_shdw_dma,
											GFP_KERNEL);
	if (rq_cons_shdw_vaddr == NULL)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "mgmt_net: dma_alloc_coherent rq failed\n");
		goto tq_dma_free;
	}
	sprintf(mvm_name,"mvmgmt%d",oct_dev->octeon_id);
	/* we support only single queue at this time */
#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 16, 0)
	ndev = alloc_netdev(sizeof(struct otxmn_dev), mvm_name,
						NET_NAME_UNKNOWN, ether_setup);
#else
	ndev = alloc_netdev(sizeof(struct otxmn_dev), mvm_name,
						ether_setup);
	memset(mvm_name,0,sizeof(mvm_name));
#endif
	if (!ndev)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "mgmt_net: alloc_netdev failed\n");
		goto rq_dma_free;
	}
	ndev->netdev_ops = &mgmt_netdev_ops;
	ndev->hw_features = NETIF_F_HIGHDMA;
	ndev->features = ndev->hw_features;
	ndev->mtu = OTXMN_MAX_MTU;
	netif_carrier_off(ndev);
	eth_hw_addr_random(ndev);
	mdev = netdev_priv(ndev);
	memset(mdev, 0, sizeof(struct otxmn_dev));
	mdev->admin_up = false;
	mdev->ndev = ndev;
	mdev->dev = conf.dma_dev.host_ep_dev;
	mdev->bar_map = conf.memmap.host_addr;
	mdev->bar_map_size = conf.memsize;
	mdev->max_txq = max_txq;
	mdev->max_rxq = max_rxq;
	mdev->num_txq = num_txq;
	mdev->num_rxq = num_rxq;
	mdev->element_count = OTXMN_NUM_ELEMENTS;
	mdev->tq_cons_shdw_vaddr = tq_cons_shdw_vaddr;
	mdev->tq_cons_shdw_dma = tq_cons_shdw_dma;
	mdev->rq_cons_shdw_vaddr = rq_cons_shdw_vaddr;
	mdev->rq_cons_shdw_dma = rq_cons_shdw_dma;
	mdev->oct_dev = oct_dev;
	oct_dev->mgmt_dev = mdev;
	/*
	printk(KERN_DEBUG "rq_cons_shdw_vaddr %p rq_cons_shdw_dma %llx phys: 0x%llx\n",
		   mdev->rq_cons_shdw_vaddr, mdev->rq_cons_shdw_dma,
		   virt_to_phys(mdev->rq_cons_shdw_vaddr));
	printk(KERN_DEBUG "tq_cons_shdw_vaddr %p tq_cons_shdw_dma %llx phys: 0x%llx\n",
		   mdev->tq_cons_shdw_vaddr, mdev->tq_cons_shdw_dma,
		   virt_to_phys(mdev->tq_cons_shdw_vaddr));
	*/
	ret = mdev_setup_tx_rings(mdev);
	if (ret)
	{
		printk(KERN_ERR "mgmt_net setup tx rings failed\n");
		goto free_net;
	}
	ret = mdev_setup_rx_rings(mdev);
	if (ret)
	{
		printk(KERN_ERR "mgmt_net: setup rx rings failed\n");
		goto clean_tx_ring;
	}
	mdev->mgmt_wq = alloc_ordered_workqueue("mgmt_net", 0);
	if (!mdev->mgmt_wq)
	{
		ret = -ENOMEM;
		printk(KERN_ERR "mgmt_net: alloc_ordered_workqueue failed\n");
		goto clean_rx_ring;
	}
	mdev->send_mbox_id = 0;
	mdev->recv_mbox_id = 0;
	mutex_init(&mdev->mbox_lock);
	ret = register_netdev(ndev);
	if (ret)
	{
		printk(KERN_ERR "mgmt_net: register_netdev failed\n");
		goto destroy_mutex;
	}
	change_host_status(mdev, OTXMN_HOST_READY, false);
	INIT_DELAYED_WORK(&mdev->service_task, mgmt_net_task);
	queue_delayed_work(mdev->mgmt_wq, &mdev->service_task,
					   usecs_to_jiffies(OTXMN_SERVICE_TASK_US));
	gmdev[oct_dev->octeon_id] = mdev;
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
	dma_free_coherent(conf.dma_dev.host_ep_dev,
					  (sizeof(uint32_t) * num_rxq),
					  rq_cons_shdw_vaddr,
					  rq_cons_shdw_dma);
tq_dma_free:
	dma_free_coherent(conf.dma_dev.host_ep_dev,
					  (sizeof(uint32_t) * num_txq),
					  tq_cons_shdw_vaddr,
					  tq_cons_shdw_dma);
conf_err:
	printk(KERN_ERR "mgmt_net[%d]: init failed; error = %d\n", oct_dev->octeon_id, ret);
	return;
}

static void first_insmod(struct work_struct *work)
{

	octeon_device_t *oct;

	oct = container_of(work, struct _OCTEON_DEVICE, first_insmod_task.work);

	if (oct->is_set == 1)
	{

		cavium_print_msg("OCTEON[%d]: waiting for mgmt mode; ", oct->octeon_id);

		mgmt_init_work_oct(work, oct);
		return;
	}

	if (had_remove != 1)
	{

		queue_delayed_work(first_insmod_wq, &oct->first_insmod_task, usecs_to_jiffies(10000 * 100));
	}
}

static void mgmt_init_work(struct work_struct *work)
{
	int octidx;
	octeon_device_t *oct_dev;

	first_insmod_wq = alloc_workqueue("first_insmod_wq", 0, 0);
	for (octidx = 0; octidx < MAX_OCTEON_DEVICES; octidx++)
	{
		oct_dev = (octeon_device_t *)get_octeon_device_ptr(octidx);

		if (oct_dev == NULL)
			continue;
		printk("begin insmod [mgmt_net %d]", oct_dev->octeon_id);

		INIT_DELAYED_WORK(&oct_dev->first_insmod_task, first_insmod);

		queue_delayed_work(first_insmod_wq, &oct_dev->first_insmod_task, 0);
		msleep(500);
	}
}

static void teardown_mdev_resources(struct otxmn_dev *mdev)
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

static void heartbeat_mvmgmt(struct work_struct *work)
{

	int octidx;
	octeon_device_t *oct_dev;
	struct otxmn_dev *mdev;

	// char cmd[128];
	for (octidx = 0; octidx < MAX_OCTEON_DEVICES; octidx++)
	{
		oct_dev = (octeon_device_t *)get_octeon_device_ptr(octidx);

		if (oct_dev == NULL)
			continue;

		if (oct_dev->is_reset == 1)
		{
			cavium_print_msg("mgm %d is resetting\n", oct_dev->octeon_id);
			if (!gmdev[octidx])
				continue;
			mdev = gmdev[octidx];
			netif_carrier_off(mdev->ndev);

			change_host_status(mdev, OTXMN_HOST_GOING_DOWN, true);

			napi_synchronize(&mdev->rxq[0].napi);

			cancel_delayed_work_sync(&mdev->service_task);

			mdev_clean_rx_rings(mdev);

			mdev_clean_tx_rings(mdev);

			change_host_status(mdev, OTXMN_HOST_GOING_DOWN, true);

			mutex_destroy(&mdev->mbox_lock);

			destroy_workqueue(mdev->mgmt_wq);

			unregister_netdev(mdev->ndev);

			teardown_mdev_resources(mdev);

			free_netdev(mdev->ndev);

			gmdev[octidx] = NULL;

			mgmt_init_work_oct(work, oct_dev);
			oct_dev->is_reset = 0;

			printk("mvmgmt_had_rest");
		}
	}
	if (had_remove != 1)
	{
		queue_delayed_work(heartbeat_wq, &heartbeat_task, usecs_to_jiffies(10000 * 100));
	}
}

static int __init mgmt_init(void)
{
	mgmt_init_wq = create_singlethread_workqueue("mv_mgmt");
	if (!mgmt_init_wq)
		return -ENOMEM;

	INIT_DELAYED_WORK(&mgmt_init_task, mgmt_init_work);
	queue_delayed_work(mgmt_init_wq, &mgmt_init_task, 0);

	heartbeat_wq = alloc_workqueue("mvm_heartbeat", 0, 0);

	INIT_DELAYED_WORK(&heartbeat_task, heartbeat_mvmgmt);
	queue_delayed_work(heartbeat_wq, &heartbeat_task, usecs_to_jiffies(10000 * 1000));
	return 0;
}

static void __exit mgmt_exit(void)
{
	struct otxmn_dev *mdev;
	int i;

	had_remove = 1;
	msleep(2000);
	cancel_delayed_work_sync(&mgmt_init_task);
	flush_workqueue(mgmt_init_wq);
	destroy_workqueue(mgmt_init_wq);

	cancel_delayed_work_sync(&heartbeat_task);
	flush_workqueue(heartbeat_wq);
	destroy_workqueue(heartbeat_wq);

	flush_workqueue(first_insmod_wq);
	destroy_workqueue(first_insmod_wq);

	for (i = 0; i < MAX_OCTEON_DEVICES; i++)
	{
		if (!gmdev[i])
			continue;
		mdev = gmdev[i];
		netif_carrier_off(mdev->ndev);
		change_host_status(mdev, OTXMN_HOST_GOING_DOWN, true);
		napi_synchronize(&mdev->rxq[0].napi);
		cancel_delayed_work_sync(&mdev->service_task);
		mdev_clean_rx_rings(mdev);
		mdev_clean_tx_rings(mdev);
		change_host_status(mdev, OTXMN_HOST_GOING_DOWN, true);
		mutex_destroy(&mdev->mbox_lock);
		destroy_workqueue(mdev->mgmt_wq);
		unregister_netdev(mdev->ndev);
		teardown_mdev_resources(mdev);
		free_netdev(mdev->ndev);
		gmdev[i] = NULL;
	}
}

module_init(mgmt_init);
module_exit(mgmt_exit);
MODULE_AUTHOR("Marvell Inc.");
MODULE_DESCRIPTION("OTX Management Net driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(OTXMN_VERSION);
