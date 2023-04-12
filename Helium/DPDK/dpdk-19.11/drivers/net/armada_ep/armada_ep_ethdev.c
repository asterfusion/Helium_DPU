/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <rte_kvargs.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_mbuf_ptype.h>
#include <rte_spinlock.h>
#include <rte_net.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_memzone.h>

#include <net/if.h>
#include <sys/socket.h>

#include "armada_ep_ethdev.h"
#include "armada_ep_mng.h"
#include "armada_ep_errno.h"

#include <inttypes.h>
#include <stdio.h>

#if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE
#include <rte_bus_vdev.h>
#else /* PCI mode */
#include <rte_ethdev_pci.h>
#endif /* end of if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE */

#if ARMADA_EP_VDEV_MODE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#endif /* end of if ARMADA_EP_VDEV_MODE */


/*
 * PHASE1
 */
#if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE
static int rte_pmd_armada_ep_vdev_probe(struct rte_vdev_device *vdev);
static int rte_pmd_armada_ep_vdev_remove(struct rte_vdev_device *dev);

#else /* PCI mode */
static int rte_pmd_armada_ep_pci_probe(struct rte_pci_driver *pci_drv,
				       struct rte_pci_device *pci_dev);
static int rte_pmd_armada_ep_pci_remove(struct rte_pci_device *dev);

#endif /* end of if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE */

static int armada_ep_dev_infos_get(struct rte_eth_dev *dev __rte_unused,
				   struct rte_eth_dev_info *dev_info);
static int armada_ep_dev_configure(struct rte_eth_dev *dev);
static int armada_ep_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx,
				    uint16_t desc, unsigned int socket,
				    const struct rte_eth_rxconf *conf,
				    struct rte_mempool *mp);
static int armada_ep_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx,
				    uint16_t desc, unsigned int socket,
				    const struct rte_eth_txconf *conf);
static inline void armada_ep_mgmt_qs_destroy(struct armada_ep_priv *priv);
static inline void armada_ep_queue_destroy(struct armada_ep_queue *hw_q);

static int armada_ep_dev_start(struct rte_eth_dev *dev);
static void armada_ep_dev_stop(struct rte_eth_dev *dev);
static void armada_ep_dev_close(struct rte_eth_dev *dev);
static int armada_ep_dev_set_link_up(struct rte_eth_dev *dev);
static int armada_ep_dev_set_link_down(struct rte_eth_dev *dev);
static int armada_ep_link_update(struct rte_eth_dev *dev, int wait_to_complete);
static int armada_ep_stats_get(struct rte_eth_dev *dev,
			       struct rte_eth_stats *rte_stats);

static uint16_t armada_ep_tx_pkt_burst(void *txq, struct rte_mbuf **tx_pkts,
				       uint16_t nb_pkts);
static uint16_t armada_ep_rx_pkt_burst(void *rxq, struct rte_mbuf **rx_pkts,
				       uint16_t nb_pkts);

/*
 * static void armada_ep_rx_queue_release(void *rxq);
 * static void armada_ep_tx_queue_release(void *txq);
 * static int armada_ep_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
 * static int armada_ep_stats_reset(struct rte_eth_dev *dev);
 * static int armada_ep_xstats_get(struct rte_eth_dev *dev,
 *	struct rte_eth_xstat *stats, unsigned int n);
 * static int armada_ep_xstats_reset(struct rte_eth_dev *dev);
 * static int armada_ep_xstats_get_names(struct rte_eth_dev *dev __rte_unused,
 *	struct rte_eth_xstat_name *xstats_names,
 *	unsigned int size);
 * static void armada_ep_rxq_info_get(struct rte_eth_dev *dev,
 *	uint16_t rx_queue_id,
 *	struct rte_eth_rxq_info *qinfo);
 * static void armada_ep_txq_info_get(struct rte_eth_dev *dev,
 *	uint16_t tx_queue_id,
 *	struct rte_eth_txq_info *qinfo);
 * static int armada_ep_rx_queue_start(struct rte_eth_dev *dev,
 *	uint16_t queue_id);
 * static int armada_ep_rx_queue_stop(struct rte_eth_dev *dev,
 *	uint16_t queue_id);
 * static int armada_ep_tx_queue_start(struct rte_eth_dev *dev,
 *	uint16_t queue_id);
 * static int armada_ep_tx_queue_stop(struct rte_eth_dev *dev,
 *	uint16_t queue_id);
 */

#if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE
static struct rte_vdev_driver vdev_armada_ep_drv = {
	.probe = rte_pmd_armada_ep_vdev_probe,
	.remove = rte_pmd_armada_ep_vdev_remove,
};

#else

#define PCI_VENDOR_ID_MARVELL		0x11ab
#define PCI_DEVID_MARVELL_ARMADA_EP	0x7081

static const struct rte_pci_id pci_mrvl_armada_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MARVELL,
			PCI_DEVID_MARVELL_ARMADA_EP)
	},
	{
		.vendor_id = 0,
	},
};

static struct rte_pci_driver pci_armada_ep_drv = {
	.id_table = pci_mrvl_armada_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING |
			RTE_PCI_DRV_INTR_LSC,
	.probe = rte_pmd_armada_ep_pci_probe,
	.remove = rte_pmd_armada_ep_pci_remove,
};
#endif

/* NOTE: update all assignments according to our implementations */
static const struct eth_dev_ops armada_ep_ops = {
	.dev_configure = armada_ep_dev_configure,
	.dev_start = armada_ep_dev_start,
	.dev_stop = armada_ep_dev_stop,
	.dev_set_link_up = armada_ep_dev_set_link_up,
	.dev_set_link_down = armada_ep_dev_set_link_down,
	.dev_close = armada_ep_dev_close,
	.link_update = armada_ep_link_update,
	.mtu_set = NULL,
	.stats_get = armada_ep_stats_get,
	.stats_reset = NULL,
	.xstats_get = NULL,
	.xstats_reset = NULL,
	.xstats_get_names = NULL,
	.dev_infos_get = armada_ep_dev_infos_get,
	.rxq_info_get = NULL,
	.txq_info_get = NULL,
	.tx_queue_start = NULL,
	.tx_queue_stop = NULL,
	.rx_queue_start = NULL,
	.rx_queue_stop = NULL,
	.rx_queue_setup = armada_ep_rx_queue_setup,
	.rx_queue_release = NULL,
	.tx_queue_setup = armada_ep_tx_queue_setup,
	.tx_queue_release = NULL,
	.flow_ctrl_get = NULL,
	.flow_ctrl_set = NULL,
#ifdef RTE_EAL_VFIO
	.rx_queue_intr_enable = armada_ep_rx_queue_intr_enable,
	.rx_queue_intr_disable = armada_ep_rx_queue_intr_disable
#endif /* RTE_EAL_VFIO */
};

/*
 * Get the user defined cookie from an inq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure.
 *
 * @retval	cookie
 */
static inline uint64_t
armada_ep_inq_desc_get_cookie(struct armada_ep_desc *desc)
{
	/* cmd[6] and cmd[7] holds the cookie (Low and High parts) */
	return((uint64_t)(((uint64_t)desc->cmds[7]) << 32) |
		(uint64_t)desc->cmds[6]);
}

/*
 * Get the packet length from an inq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure.
 *
 * @retval	packet length
 */
static inline uint16_t
armada_ep_inq_desc_get_pkt_len(struct armada_ep_desc *desc)
{
	return ((desc->cmds[1] & ARMADA_EP_RXD_BYTE_COUNT_MASK) >> 16);
}

/*
 * Get the number of buffers in the buffer pool.
 * @param[in] *bp_queue
 *	A pointer to buffer pull queueu
 *
 * @return num_buffer
 *		Amount of the available buffer pull buffers.
 */
static inline uint32_t
armada_ep_inq_bpool_get_num_buffs(struct armada_ep_queue *bp_queue)
{
	return armada_ep_q_num_occupied(readl_relaxed(bp_queue->prod_p),
		readl_relaxed(bp_queue->cons_p), bp_queue->count);
}

/*
 *Service func for copy bulk of descs from hw rxq to local memory
 * @param[in] *priv
 *	Pointer to the priv (rqx).
 * @param[in] tc
 *	Specific Trafic Class.
 * @param[in] qid
 *	Specific Queue id.
 * @param[out] *descs
 *	Pointer to the target local memory.
 * @ *num
 *	[in]  Amount of descs that should be copied.
 *	[out] Amount of descs that actually copied.
 * @return
 *	0 on success
 */
static int
armada_ep_inq_hw_recv(struct armada_ep_priv *priv, uint8_t tc, uint8_t qid,
		      struct armada_ep_desc *descs, uint16_t *num)
{
	struct armada_ep_queue *rxq;
	struct armada_ep_desc *rxq_desc;
	uint16_t recv_req = *num;
	uint16_t desc_received = 0;
	uint16_t desc_remain = 0;
	uint16_t block_size, index;
	uint32_t prod_val, cons_val;

	rxq = priv->in_tcs[tc].queues[qid];
	rxq_desc = (struct armada_ep_desc *)(rxq->desc);

	/* Read producer and consumer index */
	prod_val = readl(rxq->prod_p);
	cons_val = readl(rxq->cons_p);

	/* Get the number of received descriptors in the queue. */
	desc_received = armada_ep_q_num_occupied(prod_val, cons_val,
						 rxq->count);
	if (desc_received == 0) {
		*num = 0;
		return 0;
	}

	/* Update the num of requested descs based on the available descs
	 * in the rx queue.
	 */
	recv_req = RTE_MIN(recv_req, desc_received);

	/* In case there is a wrap around the descriptors are be stored to the
	 * end of the ring AND from the beginning of the desc ring.
	 * So the size of the first block is the number of descriptor till the
	 * end of the ring.
	 */
	if (unlikely((cons_val + recv_req) > rxq->count)) {
		block_size = rxq->count - cons_val;
	} else {
		/* No wrap around */
		block_size = recv_req;
	}

	desc_remain = recv_req;

	index = 0;
	/* Copy descriptors from the rxq to local memory
	 * Since we handle wrap-around, could be up to two iterations
	 */
	do {
		memcpy(&descs[index], &rxq_desc[cons_val],
		       block_size * sizeof(*descs));

		cons_val = armada_ep_q_index_inc(cons_val, block_size,
						 rxq->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;

	} while (desc_remain);


	/* Update the consumer index, after the writing was done */
	writel(cons_val, rxq->cons_p);

	/* Update the actual number of the descriptors that were copied */
	*num = recv_req;

	return 0;
};

/*
 * Copy bulk of descriptors to the buffer pool.
 *@param *bp_queue
 *		pointer to the buffer pool queue
 *@param buff_entry[]
 *		array of new buffer pool descriptors(address and cookies)
 *@ *num
 *	[in]	Amount of decriptors that should be refill
 *	[out]	Amount of decriptors that were refill
 */
static int
armada_ep_inq_bpool_put_buffs(struct armada_ep_queue *bp_queue,
			      struct armada_ep_bpool_desc buff_entry[],
			      uint16_t *num)
{
	struct armada_ep_bpool_desc *buf_desc;
	uint16_t num_bpds = *num;
	uint16_t block_size, index, desc_remain;
	uint32_t free_count, cons_val, prod_val;

	/* Read consumer and producer index */
	cons_val = readl(bp_queue->cons_p);
	prod_val = readl(bp_queue->prod_p);

	/* Get the amount of descriptores that available for refill in the
	 * hw buffr pool
	 */
	free_count = armada_ep_q_space(prod_val, cons_val, bp_queue->count);

	if (unlikely(free_count < num_bpds)) {
		ARMADA_EP_LOG(DEBUG,
			      "The num of required refill BP is more than "
			      "the free BP.\n\t\tnum_bpds (%d)\n\t\t not "
			      "available (%d)\n\t\tBPool tc: (%d) q: (%d)\n",
			      num_bpds, free_count, bp_queue->tc,
			      bp_queue->queue_idx);

		num_bpds = free_count;
	}

	if (unlikely(!num_bpds)) {
		ARMADA_EP_LOG(DEBUG, "BPool full\n");
		*num = 0;
		return 0;
	}

	block_size = RTE_MIN(num_bpds, (uint16_t)(bp_queue->count - prod_val));
	desc_remain = num_bpds;
	index = 0;

	buf_desc = (struct armada_ep_bpool_desc *)bp_queue->desc;

	/* In case there is a wrap-around, the first iteration will handle the
	 * descriptors till the end of queue. The rest will be handled at the
	 * following iteration.
	 * Note that there should be no more than 2 iterations.
	 **/
	do {
		/* Copy bulk of BP descriptors to the BP queue */
		memcpy(&buf_desc[prod_val], &buff_entry[index],
		       sizeof(struct armada_ep_bpool_desc) * block_size);

		prod_val = armada_ep_q_index_inc(prod_val, block_size,
						 bp_queue->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;
	} while (desc_remain > 0);

	/* Update the producer index, after the writing was done */
	writel(prod_val, bp_queue->prod_p);

	/* Update the amount of decriptors that were refill */
	*num = num_bpds;

	return 0;
}

/*
 * Release buffers to hardware bpool (buffer-pool)
 *
 *@param[in] rxq
 *   Pointer to the receive queue.
 * @param[in] num
 *   Number of buffers to release.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_inq_fill_bpool(struct armada_ep_rxq *rxq, int num)
{
	struct armada_ep_bpool_desc entries[num];
	struct rte_mbuf *mbufs[num];
	uint32_t core_id;
	int i, ret = 0;

	core_id = rte_lcore_id();
	if (core_id == LCORE_ID_ANY)
		core_id = 0;

	/* Allocate a bulk of mbufs */
	ret = rte_pktmbuf_alloc_bulk(rxq->mp, mbufs, num);
	if (ret)
		return ret;

	for (i = 0; i < num; i++) {
		/* Set the IO address of the beginning of the mbuf data */
		entries[i].buff_addr_phys =
			rte_mbuf_data_iova_default(mbufs[i]);
		entries[i].buff_cookie = (uintptr_t)mbufs[i];
	}

	armada_ep_inq_bpool_put_buffs(&rxq->priv->bp_queue[rxq->queue_id],
				      entries, (uint16_t *)&i);

	/* Release mbufs that didn't used in the bpool refill */
	if (i < num) {
		for (; i < num; i++) {
			rte_pktmbuf_free((struct rte_mbuf *)
					  entries[i].buff_cookie);
		}
	}
	return ret;
}

/*
 * Get the Layer 3 information from an inq packet descriptor.
 *
 * @param[in]	desc		A pointer to a packet descriptor structure.
 * @param[out]	l3_type		A pointer to l3 type.
 * @param[out]	l3_offset	A pointer to l3 offset, relative to start of
 *
 */
static inline void armada_ep_inq_desc_get_l3_info(struct armada_ep_desc *desc,
						  enum armada_ep_inq_l3_type
						  *l3_type, uint8_t *l3_offset)
{
	*l3_type = ((desc->cmds[0] & ARMADA_EP_RXD_L3_INFO_MASK) >> 28);
	*l3_offset = ((desc->cmds[0] & ARMADA_EP_RXD_L3_OFF_MASK) >> 0);
}

/*
 * Get the Layer 4 information from an inq packet descriptor.
 *
 * @param[in]	desc		A pointer to a packet descriptor structure.
 * @param[out]	l4_type		A pointer to l4 type.
 * @param[out]	l4_offset	A pointer to l4 offset.
 *
 */
static inline void armada_ep_inq_desc_get_l4_info(struct armada_ep_desc *desc,
						  enum armada_ep_inq_l4_type
						  *l4_type, uint8_t *l4_offset)
{
	*l4_type = ((desc->cmds[0] & ARMADA_EP_RXD_L4_INFO_MASK) >> 25);
	*l4_offset = (((desc->cmds[0] & ARMADA_EP_RXD_L3_OFF_MASK) >> 0) +
		sizeof(u32) * ((desc->cmds[0] & ARMADA_EP_RXD_IPHDR_LEN_MASK)
		>> 8));
}

/*
 * Get the VLAN tag information from an inq packet descriptor.
 *
 * @param[in]	desc		A pointer to a packet descriptor structure.
 * @param[out]	vlan_tag	A pointer to vlan tag.
 *
 */
static inline void armada_ep_inq_desc_get_vlan_tag(struct armada_ep_desc *desc,
						   enum armada_ep_inq_vlan_tag
						   *vlan_tag)
{
	*vlan_tag = ((desc->cmds[1] & ARMADA_EP_RXD_VLAN_INFO_MASK) >> 14);
}

/*
 * Get the packet format from an inq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure.
 *
 * @retval	enum packet format (None, Indirect s/g , Direct s/g, single)
 */
static inline enum armada_ep_format
armada_ep_inq_desc_get_format(struct armada_ep_desc *desc)
{
	return ((desc->cmds[0] & ARMADA_EP_RXD_FORMAT_MASK) >> 19);
}

/*
 * Return packet type information and l3/l4 offsets.
 *
 * @param[in] desc
 *   Pointer to the received packet descriptor.
 * @param[out] l3_offset
 *   l3 packet offset.
 * @param[out] l4_offset
 *   l4 packet offset.
 *
 * @return
 *   Packet type information.
 */
static inline uint64_t
armada_ep_inq_desc_to_packet_type_and_offset(struct armada_ep_desc *desc,
					     uint8_t *l3_offset,
					     uint8_t *l4_offset)
{
	enum armada_ep_inq_l3_type l3_type;
	enum armada_ep_inq_l4_type l4_type;
	enum armada_ep_inq_vlan_tag vlan_tag;
	uint64_t packet_type;

	armada_ep_inq_desc_get_l3_info(desc, &l3_type, l3_offset);
	armada_ep_inq_desc_get_l4_info(desc, &l4_type, l4_offset);
	armada_ep_inq_desc_get_vlan_tag(desc, &vlan_tag);

	packet_type = RTE_PTYPE_L2_ETHER;

	switch (vlan_tag) {
	case ARMADA_EP_INQ_VLAN_TAG_SINGLE:
		packet_type |= RTE_PTYPE_L2_ETHER_VLAN;
		break;
	case ARMADA_EP_INQ_VLAN_TAG_DOUBLE:
		packet_type |= RTE_PTYPE_L2_ETHER_QINQ;
		break;
	default:
		break;
	}

	switch (l3_type) {
	case ARMADA_EP_INQ_L3_TYPE_IPV4_NO_OPTS:
		packet_type |= RTE_PTYPE_L3_IPV4;
		break;
	case ARMADA_EP_INQ_L3_TYPE_IPV4_OK:
		packet_type |= RTE_PTYPE_L3_IPV4_EXT;
		break;
	case ARMADA_EP_INQ_L3_TYPE_IPV4_TTL_ZERO:
		packet_type |= RTE_PTYPE_L3_IPV4_EXT_UNKNOWN;
		break;
	case ARMADA_EP_INQ_L3_TYPE_IPV6_NO_EXT:
		packet_type |= RTE_PTYPE_L3_IPV6;
		break;
	case ARMADA_EP_INQ_L3_TYPE_IPV6_EXT:
		packet_type |= RTE_PTYPE_L3_IPV6_EXT;
		break;
	case ARMADA_EP_INQ_L3_TYPE_ARP:
		packet_type |= RTE_PTYPE_L2_ETHER_ARP;
		/*
		 * In case of ARP l4_offset is set to wrong value.
		 * Set it to proper one so that later on mbuf->l3_len can be
		 * calculated subtracting l4_offset and l3_offset.
		 */
		*l4_offset = *l3_offset + ARMADA_EP_ARP_LENGTH;
		break;
	default:
		ARMADA_EP_LOG(DEBUG, "Failed to recognise l3 packet type");
		break;
	}

	switch (l4_type) {
	case ARMADA_EP_INQ_L4_TYPE_TCP:
		packet_type |= RTE_PTYPE_L4_TCP;
		break;
	case ARMADA_EP_INQ_L4_TYPE_UDP:
		packet_type |= RTE_PTYPE_L4_UDP;
		break;
	default:
		ARMADA_EP_LOG(DEBUG, "Failed to recognise l4 packet type");
		break;
	}

	return packet_type;
}

/*
 * Get offload information from the received packet descriptor and set it to the
 * mbuf ol flags.
 *
 * @param[in] desc
 *   Pointer to the received packet descriptor.
 *
 * @return
 *   Mbuf offload flags.
 */
static inline uint64_t
armada_ep_inq_desc_to_ol_flags(struct armada_ep_desc *desc,
			       uint64_t packet_type)
{
	uint64_t flags = 0;
	enum armada_ep_inq_ipv4_status ipv4_status;
	enum armada_ep_inq_l4_status l4_status;

	if (RTE_ETH_IS_IPV4_HDR(packet_type)) {
		ipv4_status = ((desc->cmds[0] & ARMADA_EP_RXD_IPV4_STATUS_MASK)
			>> 23);
		if (ipv4_status == ARMADA_EP_INQ_IPV4_CSUM_OK)
			flags |= PKT_RX_IP_CKSUM_GOOD;
		else if (ipv4_status == ARMADA_EP_INQ_IPV4_CSUM_ERR)
			flags |= PKT_RX_IP_CKSUM_BAD;
		else if (ipv4_status == ARMADA_EP_INQ_IPV4_CSUM_UNKNOWN)
			flags |= PKT_RX_IP_CKSUM_UNKNOWN;
	}

	if (((packet_type & RTE_PTYPE_L4_UDP) == RTE_PTYPE_L4_UDP) ||
	    ((packet_type & RTE_PTYPE_L4_TCP) == RTE_PTYPE_L4_TCP)) {
		l4_status = ((desc->cmds[0] & ARMADA_EP_RXD_L4_STATUS_MASK)
			>> 13);
		if (l4_status == ARMADA_EP_INQ_L4_CSUM_OK)
			flags |= PKT_RX_L4_CKSUM_GOOD;
		else if (l4_status == ARMADA_EP_INQ_L4_CSUM_ERR)
			flags |= PKT_RX_L4_CKSUM_BAD;
		else if (l4_status == ARMADA_EP_INQ_L4_CSUM_UNKNOWN)
			flags |= PKT_RX_L4_CKSUM_UNKNOWN;
	}

	return flags;
}

/*
 * Get S/G num entries.
 * There is 2 numbers shift between the hw desc s/g entries and the real s/g
 * segments number in the mbuf.
 *
 * @param[in]	desc		Apointer to the S/G first segment.
 *
 * @Return	sg_num_entries	The number of S/G entries in the jambo packet.
 */
static inline uint8_t
armada_ep_inq_desc_get_sg_num_entries(struct armada_ep_desc *desc)
{
	return (((desc->cmds[2] & ARMADA_EP_RXD_NUM_SG_ENT_MASK) >> 16) + 2);
}

/* Set S/G mbuf pkt length.
 *
 * @param[in]	desc		A pointer to the S/G first segment.
 * @param[in]	idx		The first S/G segment desc index in the descs.
 *				array
 * @param[in]	num_sg_entries	Number of S/G entries in the jambo packet.
 */
static inline void
armada_ep_inq_sg_mbuf_set(struct armada_ep_desc *descs,
			  uint8_t num_sg_entries)
{
	struct rte_mbuf *first_seg = NULL, *prev_seg = NULL, *cur_seg = NULL;
	uint8_t i = 0;

	first_seg =
		(struct rte_mbuf *)(armada_ep_inq_desc_get_cookie(&descs[i]));
	first_seg->pkt_len = armada_ep_inq_desc_get_pkt_len(&descs[i]);
	first_seg->data_len = first_seg->pkt_len;
	rte_mbuf_refcnt_set(first_seg, 1);
	first_seg->nb_segs = 1;
	prev_seg = first_seg;
	while (--num_sg_entries) {
		i++;
		cur_seg =
		(struct rte_mbuf *)(armada_ep_inq_desc_get_cookie(&descs[i]));
		rte_pktmbuf_reset(cur_seg);
		cur_seg->data_len = armada_ep_inq_desc_get_pkt_len(&descs[i]);
		first_seg->pkt_len += cur_seg->data_len;
		rte_mbuf_refcnt_set(cur_seg, 1);
		first_seg->nb_segs++;
		prev_seg->next = cur_seg;
		prev_seg = cur_seg;
	}

	if (cur_seg != NULL)
		cur_seg->next = NULL;
}

/*
 * S/G desc handling
 * Validate that all the S/G enries are in the rxq, set the S/G info to the mbuf
 *
 * @param[in]  descs	A pointer to a packet descriptor structure array.
 * @param[in]  idx	A pointer to the current desc in the descs array, will
 *			be used for verified that all the S/G entries already
 *			exsist in the descs array.
 * @param[in]  nb_descs The numbers of descs that currently handled by the
 *			Rx burst func.
 * @param[out] idx	A pointer to the last s/g desc in the descs array.
 *
 * @Return		Status 0 on success
 */
static inline int
armada_ep_inq_sg_handling(struct armada_ep_desc *descs, uint32_t *idx,
			   struct armada_ep_rxq *sw_rxq, uint16_t nb_descs)
{
	uint16_t num_sg_entries, num_descs, new_desc_idx;
	int additional_descs;
	struct armada_ep_priv *priv = sw_rxq->priv;
	struct armada_ep_desc new_descs[ARMADA_EP_MAX_SG_SEGMENTS];

	num_sg_entries = armada_ep_inq_desc_get_sg_num_entries(&descs[*idx]);

	/* Validate that all the s/g enties are in the descs queue */

	additional_descs = num_sg_entries - (nb_descs - *idx);

	if (additional_descs > 0) {
		num_descs = additional_descs;

		/* Copy the old s/g descs to the new descs array */
		memcpy(&new_descs[0], &descs[*idx],
		       (num_sg_entries - additional_descs) * sizeof(*descs));

		/* new_desc_idx it's the idx of the first new desc in the new
		 * descs array that stored the the old and new descs.
		 */
		new_desc_idx = num_sg_entries - additional_descs;

		/* Get additional descs from the hw rxq */
		armada_ep_inq_hw_recv(priv, priv->rx_queue[sw_rxq->queue_id]->tc
			, priv->rx_queue[sw_rxq->queue_id]->queue_idx,
			&new_descs[new_desc_idx],
			&num_descs);

		if (num_descs == additional_descs) {
			/* Set S/G mbufs infos */
			armada_ep_inq_sg_mbuf_set(&new_descs[0],
						  num_sg_entries);
			/*
			 * Descs index update, the return idx in this case equal
			 * to the count of the old descs array minus one.
			 */
			*idx = nb_descs - 1;
			return 0;
		}
		/* If part of the s/g entries are missing in the rxq */
		uint16_t i, actual_sg_descs;
		struct rte_mbuf *mbuf;

		actual_sg_descs = num_sg_entries - additional_descs +
				  num_descs;
		ARMADA_EP_LOG(ERR, "Not all the S/G descs exist in "
		"the HW RXQ, expected: %d descs, actual: %d descs\n",
		num_sg_entries, actual_sg_descs);
		for (i = 0; i < actual_sg_descs; i++) {
			mbuf = (struct rte_mbuf *)
				(armada_ep_inq_desc_get_cookie(&new_descs[i]));
			rte_pktmbuf_free(mbuf);
			}
		/*
		 * Descs index update, the return idx in this case equal
		 * to the size of the old descs array minus one
		 */
		*idx = nb_descs - 1;
		return -1;
	}
	/* Set S/G mbufs infos */
	armada_ep_inq_sg_mbuf_set(&descs[*idx], num_sg_entries);
	/*
	 * Descs index update, the return idx in this case equal to the index of
	 * the first s/g entrie plus the num of the total s/g entries minus one
	 */
	*idx = *idx + num_sg_entries - 1;
	return 0;
}

/*
 * Reset an outq packet descriptor to default value.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 */
static inline void
armada_ep_outq_desc_reset(struct armada_ep_desc *desc)
{
	int i;
	for (i = 0; i < ARMADA_EP_DESC_NUM_WORDS; i++)
		desc->cmds[i] = 0;
}

/*
 * Set the physical address in an outq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 * @param[in]	addr	Physical DMA address containing the packet to be sent.
 */
static inline void
armada_ep_outq_desc_set_phys_addr(struct armada_ep_desc *desc, uint64_t addr)
{
	/*
	 * cmd[4] and cmd[5] holds the buffer physical address
	 * (Low and High parts)
	 */
	desc->cmds[4] = (uint32_t)addr;
	desc->cmds[5] = (uint32_t)((uint64_t)addr >> 32);
}

/*
 * Set the packet offset in an outq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 * @param[in]	offset	The packet offset.
 */
static inline void
armada_ep_outq_desc_set_pkt_offset(struct armada_ep_desc *desc, uint32_t offset)
{
	desc->cmds[1] = (desc->cmds[1] & ~ARMADA_EP_TXD_PKT_OFF_MASK) |
		(offset << 0 & ARMADA_EP_TXD_PKT_OFF_MASK);
}

/*
 * Set the packet length in an outq packet descriptor.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 * @param[in]	len	The packet length, not including CRC.
 */
static inline void
armada_ep_outq_desc_set_pkt_len(struct armada_ep_desc *desc, uint16_t len)
{
	desc->cmds[1] = (desc->cmds[1] & ~ARMADA_EP_TXD_BYTE_COUNT_MASK) |
		(len << 16 & ARMADA_EP_TXD_BYTE_COUNT_MASK);
}

/*
 * Prepare protocol information.
 *
 * @param[in] ol_flags
 *	Offload flags.
 * @param[in] packet_type
 *	Packet type bitfield.
 * @param[out] l3_type
 *	Pointer to the l3_type structure.
 * @param[out] l4_type
 *	Pointer to the l4_type structure.
 * @param[out] vlan_tag
 *	Pointer to the vlan_tag type structure.
 *
 * @return
 *   0 on success.
 */
static inline int
armada_ep_outq_prepare_proto_info(uint64_t ol_flags, uint32_t packet_type,
				  enum armada_ep_outq_l3_type *l3_type,
				  enum armada_ep_outq_l4_type *l4_type,
				  enum armada_ep_outq_vlan_tag *vlan_tag,
				  enum armada_ep_outq_gipchk_disable *gipchk,
				  enum armada_ep_outq_gl4chk_disable *gl4chk)
{
	if ((ol_flags & PKT_TX_IPV4) || RTE_ETH_IS_IPV4_HDR(packet_type))
		*l3_type = ARMADA_EP_OUTQ_L3_TYPE_IPV4;
	else if ((ol_flags & PKT_TX_IPV6) || RTE_ETH_IS_IPV6_HDR(packet_type))
		*l3_type = ARMADA_EP_OUTQ_L3_TYPE_IPV6;
	else
		*l3_type = ARMADA_EP_OUTQ_L3_TYPE_OTHER;

	if (packet_type & RTE_PTYPE_L4_TCP)
		*l4_type = ARMADA_EP_OUTQ_L4_TYPE_TCP;
	else if (packet_type & RTE_PTYPE_L4_UDP)
		*l4_type = ARMADA_EP_OUTQ_L4_TYPE_UDP;
	else
		*l4_type = ARMADA_EP_OUTQ_L4_TYPE_RESERVED;

	if (packet_type & RTE_PTYPE_L2_ETHER_VLAN)
		*vlan_tag = ARMADA_EP_OUTQ_VLAN_TAG_SINGLE;
	else if (packet_type & RTE_PTYPE_L2_ETHER_QINQ)
		*vlan_tag = ARMADA_EP_OUTQ_VLAN_TAG_DOUBLE;
	else
		*vlan_tag = ARMADA_EP_OUTQ_VLAN_TAG_NONE;

	if (ol_flags & PKT_TX_IP_CKSUM)
		*gipchk = ARMADA_EP_OUTQ_GIPCHK_ENABLE;
	else
		*gipchk = ARMADA_EP_OUTQ_GIPCHK_DISABLE;

	if (ol_flags & PKT_TX_L4_MASK)
		*gl4chk = ARMADA_EP_OUTQ_GL4CHK_ENABLE;
	else
		*gl4chk = ARMADA_EP_OUTQ_GL4CHK_DISABLE;

	return 0;
}

/*
 * Set the protocol info in an outq packet descriptor.
 *
 * @param[in]	desc		A pointer to a packet descriptor structure to be
 *				set.
 * @param[in]	vlan_type	The vlan tag.
 * @param[in]	l3_info		The l3 type of the packet.
 * @param[in]	l3_offset	The l3 offset of the packet.
 * @param[in]	l4_info		The l4 type of the packet.
 * @param[in]	l4_offset	The l4 offset of the packet.
 */
static inline void
armada_ep_outq_desc_set_proto_info(struct armada_ep_desc *desc,
				   enum armada_ep_outq_vlan_tag vlan_info,
				   enum armada_ep_outq_l3_type l3_type,
				   uint8_t l3_offset,
				   enum armada_ep_outq_l4_type l4_type,
				   uint8_t l4_offset)
{
	uint8_t ip_hdr_length;

	/* L2 info */
	/* Set Vlan info */
	desc->cmds[1] = (desc->cmds[1] & ~ARMADA_EP_TXD_VLAN_INFO_MASK) |
		(vlan_info << 14 & ARMADA_EP_TXD_VLAN_INFO_MASK);

	/* L3 info */

	/* Set L3 offset*/
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_L3_OFF_MASK) |
		(l3_offset << 0 & ARMADA_EP_TXD_L3_OFF_MASK);

	/* Set L3 info*/
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_L3_INFO_MASK) |
		(l3_type << 26 & ARMADA_EP_TXD_L3_INFO_MASK);

	/* Set IP checksum*/
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_GIPCHK_DISABLE_MASK) |
		(ARMADA_EP_OUTQ_GIPCHK_DISABLE << 15 &
			~ARMADA_EP_TXD_GIPCHK_DISABLE_MASK);

	/* L4 info */

	/* Set IP header len*/
	ip_hdr_length = (l4_offset - l3_offset) / sizeof(uint32_t);

	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_IPHDR_LEN_MASK) |
		(ip_hdr_length << 8 & ARMADA_EP_TXD_IPHDR_LEN_MASK);

	/* Set L4 info */
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_L4_INFO_MASK) |
		(l4_type << 24 & ARMADA_EP_TXD_L4_INFO_MASK);

	/* Set L4 checksum */
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_GL4CHK_DISABLE_MASK) |
		(ARMADA_EP_OUTQ_GL4CHK_DISABLE << 13 &
		 ARMADA_EP_TXD_GL4CHK_DISABLE_MASK);
}

/*
 * Set S/G (Scatter/Gather) format info
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 * @param[in]	format	S/G desc format enum.
 */
static inline void
armada_ep_outq_desc_set_format(struct armada_ep_desc *desc,
				 enum armada_ep_format format)
{
	desc->cmds[0] = (desc->cmds[0] & ~ARMADA_EP_TXD_FORMAT_MASK) |
		(format << 28 & ARMADA_EP_TXD_FORMAT_MASK);
}

/*
 * Set S/G (Scatter/Gather) number of entries.
 * There is 2 numbers shift between the hw desc s/g entries and the real s/g
 * segments number in the mbuf
 *
 * @param[in]	desc	A pointer to a descriptor structure to be set.
 * @param[in]	num	Total Number of s/g entries.
 */
static inline void
armada_ep_outq_desc_set_num_sg_entries(struct armada_ep_desc *desc,
				 uint16_t num_sg_entries)
{
	desc->cmds[2] = (desc->cmds[2] & ~ARMADA_EP_TXD_NUM_SG_ENT_MASK) |
		((num_sg_entries - 2) << 16 & ARMADA_EP_TXD_NUM_SG_ENT_MASK);
}

/*
 * Add bulk of buffers to a armada_ep tx queue
 *@param[in] *tx_queue
 *		pointer to the tx queue
 *@param[in] buff_entry[]
 *		array of new descriptors
 *@ *num[out]
 *	pointer to the number amount of transmited descriptors
 */
static int
armada_ep_outq_hw_send(struct armada_ep_queue *tx_queue,
		       struct armada_ep_desc buff_entry[], uint16_t *num)
{
	struct armada_ep_desc *buf_desc;
	uint16_t num_txds;
	uint16_t block_size, index, desc_remain;
	uint32_t free_count, cons_val, prod_val;
	num_txds = *num;

	if (unlikely(!num_txds)) {
		ARMADA_EP_LOG(DEBUG, "Number tx descs for transmission is 0\n");
		return 0;
	}

	/* Read consumer and producer index */
	cons_val = readl(tx_queue->cons_p);
	prod_val = readl(tx_queue->prod_p);

	/* Calculate number of the available tx descriptors */
	free_count = armada_ep_q_space(prod_val, cons_val, tx_queue->count);

	if (unlikely(free_count < num_txds)) {
		ARMADA_EP_LOG(DEBUG,
			"The num of required descs in tx_queue is more than "
			"the available descs.  num_txds (%d), free_count "
			"(%d((tx_queue tc: %d q: %d)\n",
			num_txds, free_count, tx_queue->tc,
			tx_queue->queue_idx);
		num_txds = free_count;
	}

	if (unlikely(!num_txds)) {
		ARMADA_EP_LOG(DEBUG, "Tx queue full\n");
		*num = 0;
		return 0;
	}

	/* In case there is a wrap-around, the first iteration will handle the
	 * descriptors till the end of queue. The rest will be handled at the
	 * following iteration.
	 * Note that there should be no more than 2 iterations.
	 **/

	/* In wrap-around, handle the number of desc till the end of queue */
	block_size = RTE_MIN(num_txds, (uint16_t)(tx_queue->count - prod_val));

	desc_remain = num_txds;
	index = 0; /* index in source descriptor array */

	buf_desc = (struct armada_ep_desc *)tx_queue->desc;

	/* Copy bulk of tx descriptors to the tx queue */
	do {
		memcpy(&buf_desc[prod_val], &buff_entry[index],
		       sizeof(struct armada_ep_desc) * block_size);

		/* Increment prod idx, update remaining desc count and bk sz */
		prod_val = armada_ep_q_index_inc(prod_val, block_size,
						 tx_queue->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;
	} while (desc_remain > 0);

	/* Update Producer index */
	/* make sure all writes are done (i.e. the descriptors were copied
	 * before incrementing the producer index)
	 */
	writel(prod_val, tx_queue->prod_p);

	/* Update the number of the transmited descriptors */
	*num = num_txds;

	return 0;
}

/*
 * Check the amount of pkts that already transmitted
 *
 * @param[in] *hw_txq
 *	Piointer to the tx hw queue
 *
 * @return tx_num
 * the amount of buffers that already transmitted
 */
static uint16_t
armada_ep_outq_get_num_outq_done(struct armada_ep_queue *hw_txq)
{
	uint32_t cons_val;
	uint32_t tx_num = 0;

	cons_val = readl_relaxed(hw_txq->cons_p);
	/* Check the amount pkts that already transmitted,
	 * the gap between the current cons val and the last tx cons val
	 */
	tx_num = armada_ep_q_num_occupied(cons_val, hw_txq->last_tx_cons_val,
					  hw_txq->count);
	hw_txq->last_tx_cons_val = cons_val;

	return tx_num;
}

/*
 * Release mbufs of pkts that already sent.
 *
 * @param[in] sq
 *   Pointer to the shadow queue.
 */
static inline void
armada_ep_outq_free_sent_buffers(struct armada_ep_shadow_txq *sq)
{
	struct armada_ep_bpool_desc *entry;
	struct rte_mbuf *mbuf;
	uint16_t nb_done = 0;
	int i;
	int tail = sq->tail;

	nb_done = sq->num_to_release;
	sq->num_to_release = 0;

	for (i = 0; i < nb_done; i++) {
		entry = &sq->ent[tail];
		if (unlikely(!entry->buff_addr_phys)) {
			ARMADA_EP_LOG(ERR, "Shadow memory @%d. buff_addr_phys "
				      "is NULL!\n", tail);
			tail = (tail + 1) & (sq->total_size - 1);
			continue;
		}
		mbuf = (struct rte_mbuf *)entry->buff_cookie;
		/*
		 * In case of S/G, only the first mbuf freed, the other segments
		 * skipped
		 */
		tail = (tail + mbuf->nb_segs) & (sq->total_size - 1);
		i += (mbuf->nb_segs - 1); /* +1 will be done by the 'for' */
		/* Need to retrieve nb_segs, so free afterwards */
		rte_pktmbuf_free(mbuf);
		entry->buff_cookie = 0;
		entry->buff_addr_phys = 0;
	}
	sq->tail = tail;
	sq->size -= nb_done;
}

/*
 * Check and free sent pkt mbufs
 *
 * @param[in] *hw_txq
 *	pointer to the hw_txq
 * @param[in] *sq
 *	pointer to the shadow tx queueu
 *
 * @return 0 on success
 */
static int
armada_ep_outq_check_n_free_sent_buffers(struct armada_ep_queue *hw_txq,
					struct armada_ep_shadow_txq *shadow_txq)
{
	uint16_t num_conf = 0;

	/* get the amount of tx buffers that can be released  */
	num_conf = armada_ep_outq_get_num_outq_done(hw_txq);

	shadow_txq->num_to_release += num_conf;

	if (likely(shadow_txq->num_to_release <
			ARMADA_EP_BUF_RELEASE_BURST_SIZE))
		return 0;

	/* free sent buffers */
	armada_ep_outq_free_sent_buffers(shadow_txq);

	return 0;
}

/*
 * Scatter/Gather Tx handling
 * @param[in]	desc	A pointer to the s/g first target tx descriptor.
 * @param[in]	mbuf	A Pointer to the first s/g mbuf.
 *
 */
static inline void
armada_ep_outq_sg_handling(struct armada_ep_desc *descs, struct rte_mbuf *mbuf)
{
	struct rte_mbuf *cur_seg = mbuf;
	uint16_t i = 0;

	/* First s/g segment setting */
	armada_ep_outq_desc_set_format(&descs[i], ARMADA_EP_DIRECT_SG);

	/* Set num of sg entries */
	armada_ep_outq_desc_set_num_sg_entries(&descs[i], cur_seg->nb_segs);
	armada_ep_outq_desc_set_pkt_len(&descs[i],
					rte_pktmbuf_data_len(cur_seg));
	/* Rest of segments setting */
	while (cur_seg->next != NULL) {
		i++;
		cur_seg = cur_seg->next;
		armada_ep_outq_desc_reset(&descs[i]);
		armada_ep_outq_desc_set_format(&descs[i],
					       ARMADA_EP_NONE_FORMAT);
		/* Set the physical address in an outq packet descriptor */
		armada_ep_outq_desc_set_phys_addr(&descs[i],
						  rte_pktmbuf_iova(cur_seg));
		/* Set the packet offset in an outq packet descriptor */
		armada_ep_outq_desc_set_pkt_offset(&descs[i], 0);

		armada_ep_outq_desc_set_pkt_len(&descs[i],
					rte_pktmbuf_data_len(cur_seg));
		}
}

/*
 * DPDK callback for receive.
 *
 * @param[in] rxq
 *   Generic pointer to the receive queue.
 * @param[out] rx_pkts
 *   Pointer to the received mbuf array.
 * @param[in] nb_descs
 *    Number of descriptors in the receive queue.
 *
 * @return
 *   Number of descriptors that successfully received.
 */
static uint16_t
armada_ep_rx_pkt_burst(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_descs)
{
	struct armada_ep_rxq *sw_rxq = rxq;
	struct armada_ep_priv *priv = sw_rxq->priv;
	struct armada_ep_desc descs[nb_descs];
	uint32_t i = 0;
	uint32_t rx_done = 0;
	uint8_t l3_offset, l4_offset;
	int ret = 0;

	/* Copy rxq descriptors to local array */
	armada_ep_inq_hw_recv(priv, priv->rx_queue[sw_rxq->queue_id]->tc,
			      priv->rx_queue[sw_rxq->queue_id]->queue_idx,
			      descs, &nb_descs);

	/* Update DPDK mbuf */
	for (i = 0; i < nb_descs; i++) {
		struct rte_mbuf *mbuf;
		uint64_t addr;

		/* Rx descriptors prefetch */
		if (likely(nb_descs - i > ARMADA_EP_PREFETCH_SHIFT)) {
			struct armada_ep_desc *pref_desc;
			uint64_t pref_addr;

			pref_desc = &descs[i + ARMADA_EP_PREFETCH_SHIFT];

			pref_addr = armada_ep_inq_desc_get_cookie(pref_desc);
			rte_mbuf_prefetch_part1((struct rte_mbuf *)(pref_addr));
			rte_mbuf_prefetch_part2((struct rte_mbuf *)(pref_addr));
		}

		/* Mbuf address assignmet, taken from the desc cookie */
		addr = armada_ep_inq_desc_get_cookie(&descs[i]);
		mbuf = (struct rte_mbuf *)addr;

		/* Reset the mbuf to default values */
		rte_pktmbuf_reset(mbuf);

		/* Update mbuf variables */
		mbuf->data_off += sw_rxq->data_offset;
		mbuf->pkt_len = armada_ep_inq_desc_get_pkt_len(&descs[i]);
		mbuf->data_len = mbuf->pkt_len;
		mbuf->port = sw_rxq->port_id;

		mbuf->packet_type =
			armada_ep_inq_desc_to_packet_type_and_offset(&descs[i],
							    &l3_offset,
							    &l4_offset);
		mbuf->l2_len = l3_offset;
		mbuf->l3_len = l4_offset - l3_offset;

		if (sw_rxq->cksum_enabled)
			mbuf->ol_flags =
				armada_ep_inq_desc_to_ol_flags(&descs[i],
							mbuf->packet_type);

		/* Scatter Gather handling */
		if (ARMADA_EP_DIRECT_SG ==
			armada_ep_inq_desc_get_format(&descs[i])) {
			if (armada_ep_inq_sg_handling(descs, &i, sw_rxq,
						     nb_descs)) {
				/* Missing s/g entries in the RXQ case,
				 * the used mbufs already freed in
				 * armada_ep_inq_sg_handling func
				 */
				continue;
			}
		}

		rx_pkts[rx_done++] = mbuf;

		sw_rxq->bytes_recv += mbuf->pkt_len;
	}

	/* Buffer pool refill */
	if (rte_spinlock_trylock(&priv->bp_lock) == 1) {
		uint32_t num, refill_num;

		/*Get the current available buffers in the buffer pool*/
		num = armada_ep_inq_bpool_get_num_buffs
					(&priv->bp_queue[sw_rxq->queue_id]);

		if (unlikely(num <= (uint32_t)priv->bp_min_size)) {
			refill_num = priv->bp_init_size - num - 1;
			/* Buffer pool refill */
			ret = armada_ep_inq_fill_bpool(sw_rxq, refill_num);
			if (ret)
				ARMADA_EP_LOG(ERR, "Failed to fill bpool, "
					      "refill_num: %d ", refill_num);
		}
		rte_spinlock_unlock(&priv->bp_lock);
	}
	sw_rxq->packets_recv += rx_done;

	return rx_done;
}

/*
 * DPDK callback for transmit.
 *
 * @param[out] txq
 *	Generic pointer to sw txq
 * @param[in] tx_pkts
 *	Pointer to the tx mbufs.
 * @param[in] nb_pkts
 *	Amount of packets to transmit.
 *
 * @return
 *   Amount of packets that actually were transmitted.
 */
static uint16_t
armada_ep_tx_pkt_burst(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct armada_ep_txq *sw_txq = txq;
	struct armada_ep_priv *priv = sw_txq->priv;
	struct armada_ep_queue *hw_txq;
	struct armada_ep_shadow_txq *shadow_txq;
	struct armada_ep_desc descs[nb_pkts];
	int i, bytes_sent = 0;
	uint16_t sq_free_size;

	shadow_txq = &sw_txq->shadow_txq;

	hw_txq = priv->tx_queue[sw_txq->queue_id];

	/* Release trasmitted pkts mbufs */
	if (shadow_txq->size)
		armada_ep_outq_check_n_free_sent_buffers(hw_txq, shadow_txq);

	/*
	 *Reduce the num of pkt that will be transmitted in case of limited
	 *free desc in the shedow queue
	 */
	sq_free_size = shadow_txq->total_size - shadow_txq->size - 1;
	if (unlikely(nb_pkts > sq_free_size)) {
		ARMADA_EP_LOG(DEBUG, "No room in shadow queue for %d packets %d"
			      " packets will be sent.\n", nb_pkts,
			      sq_free_size);

		nb_pkts = sq_free_size;
	}
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *mbuf = tx_pkts[i];
		enum armada_ep_outq_l3_type l3_type;
		enum armada_ep_outq_l4_type l4_type;
		enum armada_ep_outq_vlan_tag vlan_tag;
		enum armada_ep_outq_gipchk_disable gipchk;
		enum armada_ep_outq_gl4chk_disable gl4chk;

		/* mbuf prefetch*/
		if (likely(nb_pkts - i > ARMADA_EP_PREFETCH_SHIFT)) {
			struct rte_mbuf *pref_pkt_hdr;

			pref_pkt_hdr = tx_pkts[i + ARMADA_EP_PREFETCH_SHIFT];
			rte_mbuf_prefetch_part1(pref_pkt_hdr);
			rte_mbuf_prefetch_part2(pref_pkt_hdr);
		}

		/* assign the mbuf cookie address to the shadow queue coockie */
		shadow_txq->ent[shadow_txq->head].buff_cookie = (uint64_t)mbuf;

		/* assign the mbuf data address to the shadow queue data */
		shadow_txq->ent[shadow_txq->head].buff_addr_phys =
			rte_mbuf_data_iova_default(mbuf);

		/* Increase the shadow ring queue write index */
		shadow_txq->head = (shadow_txq->head + 1) &
			(shadow_txq->total_size - 1);

		shadow_txq->size++;

		/* Reset an outq packet descriptor to default value */
		armada_ep_outq_desc_reset(&descs[i]);

		/* Set the physical address in an outq packet descriptor */
		armada_ep_outq_desc_set_phys_addr(&descs[i],
						  rte_pktmbuf_iova(mbuf));

		/* Set the packet offset in an outq packet descriptor */
		armada_ep_outq_desc_set_pkt_offset(&descs[i], 0);

		/* Set the Byte count in an outq packet descriptor */
		armada_ep_outq_desc_set_pkt_len(&descs[i],
						rte_pktmbuf_pkt_len(mbuf));

		/* Prepara and set protocol info   */
		armada_ep_outq_prepare_proto_info(mbuf->ol_flags,
						  mbuf->packet_type, &l3_type,
						  &l4_type, &vlan_tag, &gipchk,
						  &gl4chk);

		armada_ep_outq_desc_set_proto_info(&descs[i], vlan_tag, l3_type,
						   mbuf->l2_len, l4_type,
						   mbuf->l2_len + mbuf->l3_len);
		armada_ep_outq_desc_set_format(&descs[i], ARMADA_EP_NON_SG);

		/* Increment the byte sent, used for statistics  */
		bytes_sent += rte_pktmbuf_pkt_len(mbuf);
	}

	/* Copy the tx descriptors to the tx hw queue */
	armada_ep_outq_hw_send(hw_txq, descs, &nb_pkts);

	/*
	 * Since it was already checked that there is headroom in the shadow q
	 * for all the descs, no need to verify that the requested nb_descs were
	 * actually coppied.
	 */

	sw_txq->bytes_sent += bytes_sent;
	sw_txq->packets_sent += nb_pkts;

	return nb_pkts;
}

/*
 * DPDK callback for scatter/gather transmit.
 *
 * @param[out] txq
 *	Generic pointer to sw txq.
 * @param[in] tx_pkts
 *	Pointer to the tx mbufs.
 * @param[in] nb_pkts
 *	Amount of packets to transmit.
 *
 * @return
 *   Amount of packets that actually were transmitted.
 */
static uint16_t
armada_ep_sg_tx_pkt_burst(void *txq, struct rte_mbuf **tx_pkts,
			  uint16_t nb_pkts)
{
	struct armada_ep_txq *sw_txq = txq;
	struct armada_ep_priv *priv = sw_txq->priv;
	struct armada_ep_queue *hw_txq;
	struct armada_ep_shadow_txq *shadow_txq;
	struct armada_ep_desc *descs;
	int i, bytes_sent = 0;
	uint16_t sq_free_size, nb_descs = 0;

	shadow_txq = &sw_txq->shadow_txq;
	descs = shadow_txq->descs;

	hw_txq = priv->tx_queue[sw_txq->queue_id];

	/* Release trasmitted pkts mbufs */
	if (shadow_txq->size)
		armada_ep_outq_check_n_free_sent_buffers(hw_txq, shadow_txq);

	/* Check what is the descs headroom in the shadow txq */
	sq_free_size = shadow_txq->total_size - shadow_txq->size - 1;

	for (i = 0; (i < nb_pkts) && sq_free_size; i++) {
		struct rte_mbuf *mbuf;
		enum armada_ep_outq_l3_type l3_type;
		enum armada_ep_outq_l4_type l4_type;
		enum armada_ep_outq_vlan_tag vlan_tag;
		enum armada_ep_outq_gipchk_disable gipchk;
		enum armada_ep_outq_gl4chk_disable gl4chk;

		/* mbuf prefetch*/
		if (likely(nb_pkts - i > ARMADA_EP_PREFETCH_SHIFT)) {
			struct rte_mbuf *pref_pkt_hdr;

			pref_pkt_hdr = tx_pkts[i + ARMADA_EP_PREFETCH_SHIFT];
			rte_mbuf_prefetch_part1(pref_pkt_hdr);
			rte_mbuf_prefetch_part2(pref_pkt_hdr);
		}

		mbuf = tx_pkts[i];

		/* Reset an outq packet descriptor to default value */
		armada_ep_outq_desc_reset(&descs[nb_descs]);

		/* Set the physical address in an outq packet descriptor */
		armada_ep_outq_desc_set_phys_addr(&descs[nb_descs],
						  rte_pktmbuf_iova(mbuf));

		/* Set the packet offset in an outq packet descriptor */
		armada_ep_outq_desc_set_pkt_offset(&descs[nb_descs], 0);

		/* Set the Byte count in an outq packet descriptor */
		armada_ep_outq_desc_set_pkt_len(&descs[nb_descs],
						rte_pktmbuf_pkt_len(mbuf));

		/* Prepara and set protocol info   */
		armada_ep_outq_prepare_proto_info(mbuf->ol_flags,
						  mbuf->packet_type, &l3_type,
						  &l4_type, &vlan_tag, &gipchk,
						  &gl4chk);

		armada_ep_outq_desc_set_proto_info(&descs[nb_descs], vlan_tag,
						   l3_type, mbuf->l2_len,
						   l4_type, mbuf->l2_len +
						   mbuf->l3_len);

		armada_ep_outq_desc_set_format(&descs[nb_descs],
					       ARMADA_EP_NON_SG);

		/* Check and set Scatter/Gather info */
		if (mbuf->nb_segs > 1) {
			if (mbuf->nb_segs > ARMADA_EP_MAX_SG_SEGMENTS) {
				ARMADA_EP_LOG(ERR, "Pkt with more than %d "
					"scatter/gather segments not supported "
					"and will not be sent\n",
					ARMADA_EP_MAX_SG_SEGMENTS);
				goto pkts_send;
			}
			/*
			 * Check if there is free descs in the shedow queue for
			 * all the s/g segments.
			 */
			if (mbuf->nb_segs > sq_free_size) {
				ARMADA_EP_LOG(DEBUG, "No room in hw shadow "
					"queue for %d s/g segments, the pkt "
					"will not be sent\n", mbuf->nb_segs -
					sq_free_size);
				goto pkts_send;
			}

			armada_ep_outq_sg_handling(&descs[nb_descs], mbuf);
		}

		/* Increment the byte sent, used for statistics  */
		bytes_sent += rte_pktmbuf_pkt_len(mbuf);

		/* assign the mbuf cookie address to the shadow queue coockie */
		shadow_txq->ent[shadow_txq->head].buff_cookie = (uint64_t)mbuf;

		/* assign the mbuf data address to the shadow queue data */
		shadow_txq->ent[shadow_txq->head].buff_addr_phys =
			rte_mbuf_data_iova_default(mbuf);

		/* Increase the shadow ring queue write index */
		shadow_txq->head = (shadow_txq->head + mbuf->nb_segs) &
			(shadow_txq->total_size - 1);

		shadow_txq->size += mbuf->nb_segs;

		sq_free_size -= mbuf->nb_segs;
		nb_descs += mbuf->nb_segs;
	}
pkts_send:
	 /* Copy the tx descriptors to the tx hw queue */
	armada_ep_outq_hw_send(hw_txq, descs, &nb_descs);

	/*
	 * since it was already checked that there is headroom in the shadow q
	 * for all the descs, no need to verify that the requested nb_descs were
	 * actually coppied.
	 */

	sw_txq->bytes_sent += bytes_sent;
	sw_txq->packets_sent += i;

	return i;
}

#if ARMADA_EP_LOOPBACK_MODE
/* #############################
 * #      Loopback funcs       #
 * #############################
 */
/*
 * armada_ep_loopback_get_rxq_free_space - Verify the Rx queue status and return
 * the amount of free space in the queue.
 */
static inline int
armada_ep_loopback_get_rxq_free_space(struct armada_ep_queue *hw_rxq,
				      uint16_t nb_pkts, uint32_t *rxq_prod_val)
{
	uint16_t free_count = 0;
	uint32_t cons_val;

	*rxq_prod_val = readl(hw_rxq->prod_p);
	cons_val = readl(hw_rxq->cons_p);

	free_count = armada_ep_q_space(*rxq_prod_val, cons_val, hw_rxq->count);

	if (unlikely(free_count < nb_pkts)) {
		ARMADA_EP_LOG(DEBUG,
			      "The num of required descs is more than the free "
			      "descs in rx_queue . nb_pkts (%d), free_count "
			      "(%d((rx_queue tc: %d q: %d)\n", nb_pkts,
			      free_count, hw_rxq->tc, hw_rxq->queue_idx);

		nb_pkts = free_count;
	}

	if (unlikely(!nb_pkts)) {
		ARMADA_EP_LOG(DEBUG, "Rx queue full\n");
		nb_pkts = 0;
	}
	return nb_pkts;
}

/* Callback - will be called by armada_ep_descs_processing() */
static inline int __rte_unused
armada_ep_loopback_cpy_bpq_descs_to_local_mem(struct armada_ep_queue *hw_bpq,
					      uint32_t *prod_val __rte_unused,
					      uint32_t *cons_val,
					      uint16_t block_size,
					      uint16_t index, void *descs)
{
	struct armada_ep_bpool_desc *ret_descs =
		(struct armada_ep_bpool_desc *)descs;
	struct armada_ep_bpool_desc *hw_bp_descs = hw_bpq->desc;

	memcpy(&ret_descs[index], &hw_bp_descs[*cons_val],
		block_size * sizeof(*ret_descs));
	*cons_val = armada_ep_q_index_inc(*cons_val, block_size, hw_bpq->count);

	return 0;
}

/*
 * armada_ep_loopback_get_bpool_descs - get bpool descs to forward the
 * transmitted mbufs to rx queue
 */
static inline int
armada_ep_loopback_get_bpool_descs(struct armada_ep_queue *hw_bpq,
				   uint16_t nb_pkts,
				   struct armada_ep_bpool_desc *descs)
{
	uint32_t cons_val, prod_val;
	uint16_t available_bps = 0, desc_remain = 0;
	uint16_t block_size, index;

	prod_val = readl(hw_bpq->prod_p);
	cons_val = readl(hw_bpq->cons_p);

	/* Calculate number of available descriptors in the queue.
	 * Since queue size is a power of 2, we can use the below formula.
	 */
	available_bps = armada_ep_q_num_occupied(prod_val, cons_val,
						 hw_bpq->count);
	if (available_bps == 0)
		return 0;

	nb_pkts = RTE_MIN(nb_pkts,
			  available_bps);

	/* In case there is a wrap around the descriptors are be stored to the
	 * end of the ring AND from the beginning of the desc ring.
	 * So the size of the first block is the number of descriptor till the
	 * end of the ring.
	 */
	if (unlikely((cons_val + nb_pkts) > hw_bpq->count)) {
		block_size = hw_bpq->count - cons_val;
	} else {
		/* No wrap around */
		block_size = nb_pkts;
	}

	desc_remain = nb_pkts;
	index = 0;

	/* Since we handle wrap-around, could be up to two iterations */
	do {
		/* Copy descriptors from the bpq to local memory */
		struct armada_ep_bpool_desc *hw_bp_descs = hw_bpq->desc;
		memcpy(&descs[index],
		       &hw_bp_descs[cons_val],
		       block_size * sizeof(*descs));

		cons_val = armada_ep_q_index_inc(cons_val, block_size,
						 hw_bpq->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;
	} while (desc_remain);

	writel(cons_val, hw_bpq->cons_p);

	return nb_pkts;
}

/*
 * armada_ep_loopback_update_new_mbufs_members - update new mbuf from the pool
 * with the data and info of the transmitted mbufs.
 */
static inline void
armada_ep_loopback_update_new_mbufs_members(struct rte_mbuf **old_mbufs,
					    struct armada_ep_bpool_desc
					    *new_bp_descs, uint16_t nb_pkts)
{
	int i;

	/* Copy buffer to new bpool address and update new mbuf*/
	for (i = 0; i < nb_pkts; i++) {
		if (likely(nb_pkts - i > ARMADA_EP_PREFETCH_SHIFT)) {
			struct armada_ep_bpool_desc *pref_desc;
			uint64_t pref_addr;

			pref_desc = &new_bp_descs[i + ARMADA_EP_PREFETCH_SHIFT];

			/* Get the mbuf address from the descriptor cookie */
			pref_addr = pref_desc->buff_cookie;
			rte_mbuf_prefetch_part1((struct rte_mbuf *)(pref_addr));
			rte_mbuf_prefetch_part2((struct rte_mbuf *)(pref_addr));
		}

		struct rte_mbuf *old_mbuf = old_mbufs[i];
		struct rte_mbuf *new_mbuf =
				(struct rte_mbuf *)new_bp_descs[i].buff_cookie;
		rte_pktmbuf_reset(new_mbuf);

		/* copy pkt data */
		memcpy((char *)new_mbuf->buf_addr + old_mbuf->data_off,
			(void *)((char *)old_mbuf->buf_addr +
			old_mbuf->data_off), old_mbuf->pkt_len);

		/* update mbuf info and pkt parsing */
		new_mbuf->data_off = old_mbuf->data_off;
		new_mbuf->ol_flags = old_mbuf->ol_flags;
		new_mbuf->packet_type = old_mbuf->packet_type;
		new_mbuf->tx_offload = old_mbuf->tx_offload;
		new_mbuf->pkt_len = old_mbuf->pkt_len;
		new_mbuf->data_len = old_mbuf->data_len;
		new_mbuf->port = old_mbuf->port;
		}
}

/* Callback - will be called by armada_ep_descs_processing() */
static inline int __rte_unused
armada_ep_loopback_cpy_txq_descs_to_local_mem(struct armada_ep_queue *hw_txq,
					      uint32_t *prod_val __rte_unused,
					      uint32_t *cons_val,
					      uint16_t block_size,
					      uint16_t index, void *descs)
{
	struct armada_ep_desc *ret_descs = (struct armada_ep_desc *)descs;
	struct armada_ep_desc *txq_descs =
			(struct armada_ep_desc *)hw_txq->desc;

	memcpy(&ret_descs[index], &txq_descs[*cons_val],
		block_size * sizeof(*txq_descs));

	*cons_val = armada_ep_q_index_inc(*cons_val, block_size, hw_txq->count);

	return 0;
}

/*
 * armada_ep_loopback_free_txq_descs - free the transmitted mbufs after saving
 * the relevant data and info.
 */
static inline void
armada_ep_loopback_free_txq_descs(struct armada_ep_queue *hw_txq,
				  struct armada_ep_desc *local_tx_descs,
				  uint16_t nb_pkts)
{
	struct armada_ep_desc *txq_descs =
			(struct armada_ep_desc *)hw_txq->desc;

	uint32_t cons_val, prod_val;
	uint16_t desc_transmit = 0, desc_remain = 0;
	uint16_t num_txds, block_size, index;

	prod_val = readl(hw_txq->prod_p);
	cons_val = readl(hw_txq->cons_p);

	/* Calculate number of available descriptors in the queue.
	 * Since queue size is a power of 2, we can use the below formula.
	 */
	desc_transmit = armada_ep_q_num_occupied(prod_val, cons_val,
						 hw_txq->count);

	num_txds = RTE_MIN(nb_pkts, desc_transmit);

	/* In case there is a wrap around the descriptors are be stored to the
	 * end of the ring AND from the beginning of the desc ring.
	 * So the size of the first block is the number of descriptor till the
	 * end of the ring.
	 */
	if (unlikely((cons_val + num_txds) > hw_txq->count)) {
		block_size = hw_txq->count - cons_val;
	} else {
		/* No wrap around */
		block_size = num_txds;
	}

	desc_remain = nb_pkts;

	index = 0;

	/* Since we handle wrap-around, could be up to two iterations */
	do {
		/* Copy descriptors from the txq to local mem */
		memcpy(&local_tx_descs[index], &txq_descs[cons_val],
		       block_size * sizeof(*txq_descs));

		cons_val = armada_ep_q_index_inc(cons_val, block_size,
						 hw_txq->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;
	} while (desc_remain);

	writel(cons_val, hw_txq->cons_p);
}

/*
 * Set the virtual address in an outq packet descriptor.
 *
 * This routine should be used by upper layer in cases where the buffer
 * is being allocated outside of MUSDK-dmamem allocator. The virtual-address
 * is used localy by the ARMADA_EP driver in order to calculate RSS.
 *
 * @param[in]	desc	A pointer to a packet descriptor structure to be set.
 * @param[in]	addr	Virtual address containing the packet to be sent.
 */
static inline void
armada_ep_loopback_desc_set_virt_addr(struct armada_ep_desc *desc,
					   void *addr)
{
	/* cmd[6] and cmd[7] holds the buffer virtual address
	 *(Low and High parts)
	 */
	desc->cmds[6] = (uint32_t)(uintptr_t)addr;
	desc->cmds[7] = (uint32_t)((uint64_t)(uintptr_t)addr >> 32);
}

/*
 * armada_ep_loopback_insert_rxq_descs - fill the Rx queue with the new mbufs
 * (already contained the transmitted data and info)
 */
static inline void
armada_ep_loopback_insert_rxq_descs(struct armada_ep_queue *hw_rxq,
				    struct armada_ep_desc *local_tx_descs,
				    struct armada_ep_bpool_desc *descs,
				    uint16_t nb_pkts, uint32_t rxq_prod_val)
{
	struct armada_ep_desc *rxq_descs =
		(struct armada_ep_desc *)hw_rxq->desc;

	uint16_t block_size, index;
	uint16_t desc_remain = 0;

	/* In wrap-around, handle the number of desc till the end of queue */
	block_size = RTE_MIN(nb_pkts,
			     (uint16_t)(hw_rxq->count - rxq_prod_val));

	desc_remain = nb_pkts;
	index = 0;
	int i;

	do {
		/* Copy Tx desc to Rx hwq
		 * This copy is relevant for the following info
		 * parameters:
		 * md_mod
		 * IP_HdLen[6:2]
		 * L3_offset[6:0]
		 * Byte Count[15:0]
		 * VLAN_info
		 * Packet_offset[7:0]
		 * L4Chk[15:0]
		 * Propriatary MV FW

		 * TODO: need to convert the following parameters from
		 * txd info to rxd info:
		 * L3_Info[2:0]
		 * L4_Info[2:0]
		 */
		memcpy(&rxq_descs[rxq_prod_val], &local_tx_descs[index],
		       block_size * sizeof(*rxq_descs));

		for (i = 0; i < block_size; i++) {
			armada_ep_outq_desc_set_phys_addr
				(&rxq_descs[rxq_prod_val + i],
				descs[i + index].buff_addr_phys);

			armada_ep_loopback_desc_set_virt_addr
				(&rxq_descs[rxq_prod_val + i],
				(uint64_t *)descs[i + index].buff_cookie);
		}
		rxq_prod_val = armada_ep_q_index_inc(rxq_prod_val, block_size,
						     hw_rxq->count);
		desc_remain -= block_size;
		index = block_size;
		block_size = desc_remain;
	} while (desc_remain);

	writel(rxq_prod_val, hw_rxq->prod_p);
}

/*
 * armada_ep_loopback_update_descs - initiate loopback flow.
 */
static inline int
armada_ep_loopback_update_descs(struct armada_ep_txq *sw_txq,
				struct rte_mbuf **mbufs, uint16_t nb_pkts)
{
	struct armada_ep_priv *priv = sw_txq->priv;

	//TODO: Question: is sw_txq->queue_id == sw_rxq->queue_id ?
	//can we assume that tx queues amount will always be the same as rx
	//queues when loopback is set?
	struct armada_ep_queue *hw_txq = priv->tx_queue[sw_txq->queue_id];
	struct armada_ep_queue *hw_rxq = priv->rx_queue[sw_txq->queue_id];
	struct armada_ep_queue *hw_bpq = &priv->bp_queue[sw_txq->queue_id];

	struct armada_ep_bpool_desc descs[nb_pkts];
	struct armada_ep_desc local_tx_descs[nb_pkts];

	uint32_t rxq_prod_val;

	nb_pkts = armada_ep_loopback_get_rxq_free_space(hw_rxq, nb_pkts,
							&rxq_prod_val);
	if (unlikely(!nb_pkts))
		return 0;

	nb_pkts = armada_ep_loopback_get_bpool_descs(hw_bpq, nb_pkts, descs);
	if (unlikely(!nb_pkts))
		return 0;

	armada_ep_loopback_update_new_mbufs_members(mbufs, descs, nb_pkts);
	armada_ep_loopback_free_txq_descs(hw_txq, local_tx_descs, nb_pkts);

	armada_ep_loopback_insert_rxq_descs(hw_rxq, local_tx_descs, descs,
					    nb_pkts, rxq_prod_val);
	return 0;
}

/*
 * DPDK callback for transmit in case of loopback.
 * If loopback is set, at the end of tx flow the rx queue and bpool queue
 * will be updated.
 *
 * @param txq
 *   Generic pointer transmit queue.
 * @param tx_pkts
 *   Packets to transmit.
 * @param nb_pkts
 *   Number of packets in array.
 *
 * @return
 *   Number of packets successfully transmitted.
 */
static uint16_t
armada_ep_loopback_tx_pkt_burst(void *txq, struct rte_mbuf **tx_pkts,
				uint16_t nb_pkts)
{
	nb_pkts = armada_ep_sg_tx_pkt_burst(txq, tx_pkts, nb_pkts);
	armada_ep_loopback_update_descs(txq, tx_pkts, nb_pkts);

	return nb_pkts;
}

#endif

/*
 * armada_ep_put_queue_idx - Free a previous allocated entry for queue
 * control pointers.
 */
static inline void
armada_ep_put_queue_idx(struct armada_ep_priv *priv, uint32_t index)
{
	priv->q_indices_arr[index] = 0xFFFFFFFF;
}

/*
 * armada_ep_get_queue_idx - allocate a free entry for queue control pointers.
 */
static inline int
armada_ep_get_queue_idx(struct armada_ep_priv *priv)
{
	uint32_t i;

	for (i = 0; i < priv->q_indices_arr_len; i++) {
		if (priv->q_indices_arr[i] == 0xFFFFFFFF) {
			priv->q_indices_arr[i] = 0;
			return i;
		}
	}

	/* All entries are occupied, not likely to happen. */
	ARMADA_EP_LOG(ERR, "All Ring indeces are occupied (%d entries).\n",
		      priv->q_indices_arr_len);

	return -ENODEV;
}

/*
 * armada_ep_alloc_queue_cookies - allocate cmd/Notif rings cookie list.
 *
 * @param queue
 *   Pointer to HW queue structure.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static inline int
armada_ep_alloc_queue_cookies(struct armada_ep_queue *queue)
{
	/* For cmd queues, the cookie holds data regarding the command.
	 * Hence, it should contain enough entries so it can serve all commands.
	 */
	if (queue->queue_type == ARMADA_EP_CMD_QUEUE) {
		queue->cookie_count = RTE_MAX(queue->count * 2,
			(uint32_t)ARMADA_EP_CMD_QUEUE_MAX_COOKIE_LEN);
	} else {
		queue->cookie_count = queue->count;
	}

	queue->mgmt_cookie_list = NULL;

	queue->mgmt_cookie_list = rte_zmalloc("cookie_list",
		sizeof(struct armada_ep_mgmt_cookie) *
		queue->cookie_count, 0);
	if (queue->mgmt_cookie_list == NULL) {
		ARMADA_EP_LOG(ERR, "Failed allocate %d Bytes for"
			      " cookie_list.\n",
			      (int)(sizeof(struct armada_ep_mgmt_cookie)
			      * queue->cookie_count));
		return -ENOMEM;
	}
	return 0;
}

/*
 * armada_ep_alloc_queue_resources - allocate Rx/Tx/cmd/Notif/... ring resources
 * (Descriptors)
 *
 * @param queue
 *   Pointer to HW queue structure.
 * @param desc_size
 *   Descriptor structure size.
 * @param queue_len
 *   The queue length (amount ofsescriptors that required).
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static inline int
armada_ep_alloc_queue_resources(struct rte_eth_dev *dev,
				struct armada_ep_queue *queue, int desc_size,
				int queue_len)
{
	int ret = -ENOMEM;
	char queue_name[30];

	queue->count = queue_len;
	queue->desc_size = desc_size;

	switch (queue->queue_type) {
	case ARMADA_EP_RX_QUEUE:
		sprintf(queue_name, "hw_rxq_tc%d", queue->tc);
		break;
	case ARMADA_EP_TX_QUEUE:
		sprintf(queue_name, "hw_txq_tc%d", queue->tc);
		break;
	case ARMADA_EP_BPOOL_QUEUE:
		sprintf(queue_name, "hw_bpq_tc%d", queue->tc);
		break;
	case ARMADA_EP_CMD_QUEUE:
		sprintf(queue_name, "hw_cmdq_tc%d", queue->tc);
		break;
	case ARMADA_EP_NOTIF_QUEUE:
		sprintf(queue_name, "hw_notifq_tc%d", queue->tc);
		break;
	}

	queue->q_memzone = rte_eth_dma_zone_reserve(dev, queue_name,
					queue->queue_idx,
					queue->count * queue->desc_size,
					0, SOCKET_ID_ANY);
	if (queue->q_memzone == NULL) {
		ARMADA_EP_LOG(ERR, "Failed to allocate mem for hw ring");
		ret = -ENOMEM;
		goto err;
	}
	memset(queue->q_memzone->addr, 0, queue->q_memzone->len);
	queue->desc = queue->q_memzone->addr;
	queue->dma = queue->q_memzone->iova;

	/* Get an entry in the queue indeces memory, to be pointed to by the
	 * consumer / producer pointer.
	 */
	ret = armada_ep_get_queue_idx(queue->priv);
	if (ret < 0) {
		ARMADA_EP_LOG(ERR, "Unable to allocate entry for queue producer"
			      " index");
		goto err;
	}
	queue->prod_idx = (uint16_t)ret;
	queue->prod_p = queue->priv->q_indices_arr + queue->prod_idx;
	ret = armada_ep_get_queue_idx(queue->priv);
	if (ret < 0) {
		ARMADA_EP_LOG(ERR, "Unable to allocate entry for queue consumer"
			      " index");
		goto err;
	}
	queue->cons_idx = (uint16_t)ret;
	queue->cons_p = queue->priv->q_indices_arr + queue->cons_idx;

	return 0;
err:
	queue->prod_p = NULL;
	queue->cons_p = NULL;
	if (queue->cons_idx)
		armada_ep_put_queue_idx(queue->priv, queue->cons_idx);
	if (queue->prod_idx)
		armada_ep_put_queue_idx(queue->priv, queue->prod_idx);
	if (queue->q_memzone) {
		rte_memzone_free(queue->q_memzone);
		queue->q_memzone = NULL;
		queue->desc = NULL;
		queue->dma = 0;
	}
	if (queue->mgmt_cookie_list)
		rte_free(queue->mgmt_cookie_list);
	queue->mgmt_cookie_list = NULL;
	return ret;
}

/*
 * armada_ep_ring_resources - Free Rx/Tx/cmd/Notif/... ring resources
 * (Descriptors)
 */
static inline int
armada_ep_free_queue_resources(struct armada_ep_queue *hw_queue)
{
	if (!hw_queue)
		return 0;

	if (hw_queue->mgmt_cookie_list) {
		rte_free(hw_queue->mgmt_cookie_list);
		hw_queue->mgmt_cookie_list = NULL;
	};

	if (hw_queue->q_memzone) {
		rte_memzone_free(hw_queue->q_memzone);
		hw_queue->q_memzone = NULL;
		hw_queue->desc = NULL;
		hw_queue->dma = 0;
	};

	armada_ep_put_queue_idx(hw_queue->priv, hw_queue->prod_idx);
	armada_ep_put_queue_idx(hw_queue->priv, hw_queue->cons_idx);
	return 0;
}

/*
 * Flush hardware bpool (buffer-pool).
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_drain_bpool(struct armada_ep_priv *priv __rte_unused,
		      uint32_t num __rte_unused)
{
	ARMADA_EP_LOG(DEBUG, "Need to implement");
	/* TODO - there is no API to get buffers from the pool, so we need to
	 * record all buffers in a local queue
	 */
}

/*
 * Flush hardware bpool (buffer-pool).
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_flush_bpool(struct rte_eth_dev *dev)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	uint32_t num, i;

	/* bpool amount is equal to num_rx_queues*/
	for (i = 0; i < priv->num_rx_queues; i++) {
		struct armada_ep_queue *bpq = &priv->bp_queue[i];
		num = armada_ep_q_num_occupied(readl(bpq->prod_p),
					       readl(bpq->cons_p), bpq->count);
		armada_ep_drain_bpool(priv, num);
	}
}

/*
 * Flush transmit shadow queues.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_flush_tx_shadow_queues(struct rte_eth_dev *dev)
{
	struct armada_ep_txq *txq;
	struct armada_ep_shadow_txq *sq;
	struct armada_ep_bpool_desc *entry;
	struct rte_mbuf *mbuf;
	int i;

	ARMADA_EP_LOG(DEBUG,
		      "Flushing tx shadow queues");
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = (struct armada_ep_txq *)dev->data->tx_queues[i];
		sq = &txq->shadow_txq;
		sq->num_to_release = sq->size;
		armada_ep_outq_free_sent_buffers(sq);
		while (sq->tail != sq->head) {
			entry = &sq->ent[sq->tail];
			if (unlikely(!entry->buff_addr_phys)) {
				sq->tail = (sq->tail + 1) &
					(sq->total_size - 1);
				continue;
			}

			mbuf = (struct rte_mbuf *)entry->buff_cookie;
			rte_pktmbuf_free(mbuf);
			sq->tail = (sq->tail + 1) &
				    (sq->total_size - 1);
		}
		memset(sq, 0, sizeof(*sq));
	}
}

/*
 * Flush receive queues.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_flush_rx_queues(struct rte_eth_dev *dev)
{
	int i, j, ret;
	struct rte_mbuf *mbuf;
	uint64_t addr;

	ARMADA_EP_LOG(DEBUG, "Flushing rx queues");
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		uint16_t num;
		do {
			struct armada_ep_rxq *q = dev->data->rx_queues[i];
			struct armada_ep_desc descs[ARMADA_EP_BURST_SIZE];

			num = ARMADA_EP_BURST_SIZE;
			ret = armada_ep_inq_hw_recv(q->priv,
			    q->priv->rx_queue[q->queue_id]->tc,
			    q->priv->rx_queue[q->queue_id]->queue_idx, descs,
			    &num);

			for (j = 0; j < num; j++) {
				addr = armada_ep_inq_desc_get_cookie(&descs[i]);
				mbuf = (struct rte_mbuf *)addr;
				rte_pktmbuf_free(mbuf);
			}
		} while (ret == 0 && num);
	}
}

/*
 * Flush all rx, tx and bpool queues before stop/close device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_flush_queues_process(struct rte_eth_dev *dev)
{
	armada_ep_flush_rx_queues(dev);
	armada_ep_flush_tx_shadow_queues(dev);
	armada_ep_flush_bpool(dev);
}

/*
 * DPDK callback to close the device.
 * The driver support RTE_ETH_DEV_CLOSE_REMOVE flag to support free sw queues.
 * The func rte_eth_dev_release_port() will free the following:
 *	1. sw_rxq (eth_dev->data->rx_queues)
 *	2. sw_txq (eth_dev->data->tx_queues)
 *	3. priv mac_addrs (eth_dev->data->mac_addrs)
 *	4. priv hash_mac_addrs (eth_dev->data->hash_mac_addrs)
 *	5. priv structure (eth_dev->data->dev_private)
 * Note: MUST call dev_close beore calling dev_close
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_dev_close(struct rte_eth_dev *dev)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	int i;

	/* free of all the queues resources*/
#if !ARMADA_EP_STANDALONE_VDEV_MODE
	armada_ep_deinit_io(priv);
	armada_ep_mgmt_qs_destroy(priv);
#endif

	for (i = 0; i < priv->num_rx_queues; i++) {
		armada_ep_queue_destroy(&priv->bp_queue[i]);
		armada_ep_queue_destroy(priv->rx_queue[i]);
	}

	for (i = 0; i < priv->num_tx_queues; i++) {
		struct armada_ep_txq *sw_txq = dev->data->tx_queues[i];

		rte_free(sw_txq->shadow_txq.ent);
		rte_free(sw_txq->shadow_txq.descs);
		armada_ep_queue_destroy(priv->tx_queue[i]);
	}

#if ARMADA_EP_STANDALONE_VDEV_MODE
	rte_free(priv->q_indices_arr);
#endif
}

/*
 * DPDK callback to get device statistics.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param stats
 *   Stats structure output buffer.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	unsigned int i, idx;

	if (!priv)
		return -EPERM;

	for (i = 0; i < priv->num_rx_queues; i++) {
		struct armada_ep_rxq *rxq = dev->data->rx_queues[i];

		if (!rxq)
			continue;

		idx = rxq->queue_id;
		if (unlikely(idx >= RTE_ETHDEV_QUEUE_STAT_CNTRS)) {
			RTE_LOG(ERR, PMD,
				"rx queue %d stats out of range (0 - %d)\n",
				idx, RTE_ETHDEV_QUEUE_STAT_CNTRS - 1);
			continue;
		}

		stats->q_ibytes[idx] = rxq->bytes_recv;
		stats->q_ipackets[idx] = rxq->packets_recv;
		stats->q_errors[idx] = 0;
		stats->ibytes += stats->q_ibytes[idx];
		stats->ipackets += stats->q_ipackets[idx];
	}

	for (i = 0; i < priv->num_tx_queues; i++) {
		struct armada_ep_txq *txq = dev->data->tx_queues[i];

		if (!txq)
			continue;

		idx = txq->queue_id;
		if (unlikely(idx >= RTE_ETHDEV_QUEUE_STAT_CNTRS)) {
			RTE_LOG(ERR, PMD,
				"tx queue %d stats out of range (0 - %d)\n",
				idx, RTE_ETHDEV_QUEUE_STAT_CNTRS - 1);
		}

		stats->q_obytes[idx] = txq->bytes_sent;
		stats->q_opackets[idx] = txq->packets_sent;
		stats->obytes += stats->q_obytes[idx];
		stats->opackets += stats->q_opackets[idx];
	}

	/* driver not support imissed, ierrors, rx_nombuf */
	stats->imissed = 0;
	stats->ierrors = 0;
	stats->rx_nombuf = 0;

	return 0;
}

/*
 * DPDK callback to retrieve physical link information.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param wait_to_complete
 *   Wait for request completion (ignored).
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_link_update(struct rte_eth_dev *dev,
		      int wait_to_complete __rte_unused)
{
	int ret = 0;

	dev->data->dev_link.link_speed = ETH_SPEED_NUM_10G;
	dev->data->dev_link.link_duplex = ETH_LINK_FULL_DUPLEX;
	dev->data->dev_link.link_autoneg = ETH_LINK_FIXED;

#if ARMADA_EP_STANDALONE_VDEV_MODE
	dev->data->dev_link.link_status = ETH_LINK_UP;
#else
	uint32_t link_status = 0;

	ret = armada_ep_pf_vf_link_status(dev->data->dev_private,
		&link_status);

	if (ret) {
		ARMADA_EP_LOG(ERR, "Error during device link update.\n");
		return ret;
	}

	if (link_status == 1) {
		dev->data->dev_link.link_status = ETH_LINK_UP;
	} else if (link_status == 0) {
		dev->data->dev_link.link_status = ETH_LINK_DOWN;
	} else {
		ARMADA_EP_LOG(ERR, "Unrecognized dev status (%d)", link_status);
		ret = -EINVAL;
	}
#endif
	ARMADA_EP_LOG(INFO,
		      "link_update finish successfully");

	return ret;
}

/*
 * DPDK callback to bring the link down.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_dev_set_link_down(struct rte_eth_dev *dev)
{
	int ret = 0;

#if !ARMADA_EP_STANDALONE_VDEV_MODE
	ret = armada_ep_pf_vf_disable(dev->data->dev_private);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Error during device set link down.\n");
		return ret;
	}
#else
	dev->data->dev_link.link_status = ETH_LINK_DOWN;
#endif
	ARMADA_EP_LOG(INFO, "dev_set_link_down finish successfully");

	return ret;

}

/*
 * DPDK callback to bring the link up.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_dev_set_link_up(struct rte_eth_dev *dev)
{
	int ret = 0;

#if !ARMADA_EP_STANDALONE_VDEV_MODE
	uint8_t resp_status;

	ret = armada_ep_pf_vf_enable(dev->data->dev_private,
		&resp_status);

	if (ret) {
		ARMADA_EP_LOG(ERR, "Error during device set link up.\n");
		return ret;
	}
#else
	dev->data->dev_link.link_status = ETH_LINK_UP;
#endif

	ARMADA_EP_LOG(INFO, "dev_set_link_up finish successfully");
	return ret;
}

/*
 * DPDK callback to stop the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 */
static void
armada_ep_dev_stop(struct rte_eth_dev *dev)
{
	armada_ep_flush_queues_process(dev);
	armada_ep_dev_set_link_down(dev);
	/*
	 * TODO: known issue - need to verify we cleen queues when "stop" cmd
	 * NOTE: OTX2 driver Stop rx queues and free up pkts pending and
	 *       Stop tx queues
	 */
}

/*
 * DPDK callback to start the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative errno value on failure.
 */
static int
armada_ep_dev_start(struct rte_eth_dev *dev)
{
#if !ARMADA_EP_STANDALONE_VDEV_MODE
	int ret = 0;
	struct armada_ep_priv *priv = dev->data->dev_private;

	if (priv->dev_initialized == 0) {
#ifdef RTE_EAL_VFIO
		if (dev->data->dev_conf.intr_conf.rxq != 0) {
			if (armada_ep_register_queue_irqs(dev))
				return -1;
		}
#endif /* RTE_EAL_VFIO */
		ret = armada_ep_init_io(priv);

		if (ret) {
			ARMADA_EP_LOG(ERR,
				"Error during device start process.\n");
			return ret;
		}
		priv->dev_initialized = 1;
	}
#endif

	ARMADA_EP_LOG(INFO, "dev_start finish successfully");
	return armada_ep_dev_set_link_up(dev);
}

/*
 * armada_ep_init_tcs - Initialize members of in_tc and out_tc arrays.
 *
 * @param priv
 *   Pointer to the private device structure.
 * @retval
 *   0 for sucessful init.
 */
static inline int
armada_ep_init_tcs(struct armada_ep_priv *priv)
{
	uint8_t i;
	for (i = 0; i < priv->num_in_tcs; i++) {
		priv->in_tcs[i].num_queues = priv->num_qs_per_tc;
		priv->in_tcs[i].buff_size = priv->buff_size;
		priv->in_tcs[i].pkt_offset = priv->pkt_offset;
	}

	for (i = 0; i < priv->num_out_tcs; i++)
		priv->out_tcs[i].num_queues = priv->num_qs_per_tc;
	return 0;
}

/*
 * DPDK callback to perform ethernet device configuration.
 *
 * Prepare the driver for a given number of TX and RX queues.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_dev_configure(struct rte_eth_dev *dev)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	uint32_t max_rx_pkt_len;

	if (dev->data->dev_conf.rxmode.mq_mode != ETH_MQ_RX_NONE) {
		ARMADA_EP_LOG(ERR, "Unsupported rx multi queue mode %d\n",
			      dev->data->dev_conf.rxmode.mq_mode);
		return -EINVAL;
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC) {
		ARMADA_EP_LOG(ERR, "L2 CRC keeping not supported\n");
		return -EINVAL;
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_VLAN_STRIP) {
		ARMADA_EP_LOG(ERR, "VLAN stripping not supported\n");
		return -EINVAL;
	}

	if (dev->data->dev_conf.rxmode.split_hdr_size) {
		ARMADA_EP_LOG(ERR, "Split headers not supported\n");
		return -EINVAL;
	}

	if ((priv->pf_vf_capabilities.flags & CAPABILITIES_SG) &&
	    !(dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_SCATTER)) {
		ARMADA_EP_LOG(ERR, "RX Scatter MUST be set\n");
		return -EINVAL;
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_TCP_LRO) {
		ARMADA_EP_LOG(ERR, "LRO not supported\n");
		return -EINVAL;
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_JUMBO_FRAME) {
		max_rx_pkt_len = dev->data->dev_conf.rxmode.max_rx_pkt_len;
		dev->data->mtu = max_rx_pkt_len - RTE_ETHER_HDR_LEN -
			RTE_ETHER_CRC_LEN;
	}

	/* init rte_eth_dev struct with callback functions*/
	dev->rx_pkt_burst = armada_ep_rx_pkt_burst;
	dev->tx_pkt_burst = armada_ep_tx_pkt_burst;
	if (dev->data->dev_conf.txmode.offloads & DEV_TX_OFFLOAD_MULTI_SEGS)
		dev->tx_pkt_burst = armada_ep_sg_tx_pkt_burst;

#if ARMADA_EP_LOOPBACK_MODE
	dev->tx_pkt_burst = armada_ep_loopback_tx_pkt_burst;
#endif
	priv->num_rx_queues = dev->data->nb_rx_queues;
	priv->num_tx_queues = dev->data->nb_tx_queues;
	priv->num_rx_pools = dev->data->nb_rx_queues;

	armada_ep_init_tcs(priv);

	/*
	 * Calculate the minimum bpool size for refill feature as follows:
	 * 2 default burst sizes (for each rx queue).
	 * If the bpool size will be below this value, new buffers will
	 * be added to the pool.
	 */
	priv->bp_min_size = ARMADA_EP_BURST_SIZE * 2;

	/* interface is always in promiscuous mode */
	dev->data->promiscuous = 1;

	ARMADA_EP_LOG(INFO, "dev_configure finish successfully");
	return 0;
}

/*
 * DPDK callback to get information about the device.
 *
 * @param dev
 *   Pointer to Ethernet device structure (unused).
 * @param info
 *   Info structure output buffer.
 */
static int
armada_ep_dev_infos_get(struct rte_eth_dev *dev,
			struct rte_eth_dev_info *dev_info)
{
	struct armada_ep_priv *priv = dev->data->dev_private;

	dev_info->speed_capa = ETH_LINK_SPEED_10M |
				ETH_LINK_SPEED_100M |
				ETH_LINK_SPEED_1G |
				ETH_LINK_SPEED_10G;
	dev_info->max_rx_queues = ARMADA_EP_MAX_QUEUES;
	dev_info->max_tx_queues = ARMADA_EP_MAX_QUEUES;
	dev_info->max_mac_addrs = ARMADA_EP_MAC_ADDRS_MAX;
	dev_info->rx_desc_lim.nb_max = ARMADA_EP_RXD_MAX;
	dev_info->rx_desc_lim.nb_min = ARMADA_EP_RXD_MIN;
	dev_info->rx_desc_lim.nb_seg_max = 1;
	if (priv->pf_vf_capabilities.flags & CAPABILITIES_SG)
		dev_info->rx_desc_lim.nb_seg_max = ARMADA_EP_MAX_SG_SEGMENTS;
	dev_info->rx_desc_lim.nb_mtu_seg_max = dev_info->rx_desc_lim.nb_seg_max;

	dev_info->rx_desc_lim.nb_align = ARMADA_EP_RXD_ALIGN;
	dev_info->tx_desc_lim.nb_max = ARMADA_EP_TXD_MAX;
	dev_info->tx_desc_lim.nb_min = ARMADA_EP_TXD_MIN;
	dev_info->tx_desc_lim.nb_align = ARMADA_EP_TXD_ALIGN;
	dev_info->tx_desc_lim.nb_seg_max = 1;
	if (priv->pf_vf_capabilities.flags & CAPABILITIES_SG)
		dev_info->tx_desc_lim.nb_seg_max = ARMADA_EP_MAX_SG_SEGMENTS;
	dev_info->tx_desc_lim.nb_mtu_seg_max = dev_info->tx_desc_lim.nb_seg_max;

	dev_info->rx_offload_capa = ARMADA_EP_RX_OFFLOADS;
	dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_JUMBO_FRAME;
	if (priv->pf_vf_capabilities.flags & CAPABILITIES_SG)
		dev_info->rx_offload_capa |= DEV_RX_OFFLOAD_SCATTER;
	dev_info->rx_queue_offload_capa = dev_info->rx_offload_capa;

	dev_info->tx_offload_capa = ARMADA_EP_TX_OFFLOADS;
	if (priv->pf_vf_capabilities.flags & CAPABILITIES_SG)
		dev_info->tx_offload_capa |= DEV_TX_OFFLOAD_MULTI_SEGS;
	dev_info->tx_queue_offload_capa = dev_info->tx_offload_capa;

	//TODO: We soppurt ARMADA_EP_HASH_T_2_TUPLE, ARMADA_EP_HASH_T_5_TUPLE
	dev_info->flow_type_rss_offloads = ARMADA_EP_HASH_T_NONE;

	/* By default packets are dropped if no descriptors are available */
	dev_info->default_rxconf.rx_drop_en = 1;

	/* one buffer size */
	dev_info->max_rx_pktlen = priv->pf_vf_capabilities.max_buf_size;
	if (priv->pf_vf_capabilities.flags & CAPABILITIES_SG) {
		/* maximum number of s/g entries multiple by buf-size */
		dev_info->max_rx_pktlen = ARMADA_EP_MAX_SG_SEGMENTS *
			priv->pf_vf_capabilities.max_buf_size;
	}

	dev_info->max_mtu = dev_info->max_rx_pktlen;

	/* mempool buffer size MUST be at least as the hw bpool buffer size */
	dev_info->min_rx_bufsize = priv->pf_vf_capabilities.max_buf_size;
	return 0;
}

/*
 * Initialize armada_ep_queue structure according given idx and ring size (desc)
 * Update private device structure with the initialized hw queue.
 *
 * @param hw_q
 *   Pointer to HW queue structure.
 * @param priv
 *   Pointer to the private device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 */
static inline void
armada_ep_init_hw_queue(struct armada_ep_queue *hw_q,
			struct armada_ep_priv *priv,
			uint16_t idx, uint16_t desc)
{
	hw_q->priv = priv;
	hw_q->queue_idx = idx % ARMADA_EP_MAX_NUM_QS_PER_TC;
	hw_q->tc = idx / ARMADA_EP_MAX_NUM_QS_PER_TC;
	hw_q->count = desc;
	hw_q->intr_vec = ARMADA_EP_MGMT_MSIX_ID_INVALID;

	/* arrange queue in intc/outtc array and rx/tx_queue array in private
	 * device structure.
	 */
	switch (hw_q->queue_type) {
	case ARMADA_EP_RX_QUEUE:
		priv->rx_queue[idx] = hw_q;
		priv->in_tcs[hw_q->tc].queues[hw_q->queue_idx] = hw_q;
		break;
	case ARMADA_EP_TX_QUEUE:
		hw_q->last_tx_cons_val = 0;
		priv->tx_queue[idx] = hw_q;
		priv->out_tcs[hw_q->tc].queues[hw_q->queue_idx] = hw_q;
		break;
	case ARMADA_EP_BPOOL_QUEUE:
		hw_q->bp_frag_size = priv->buff_size;
		priv->in_tcs[hw_q->tc].bp_qs[hw_q->queue_idx] = hw_q;
		break;
	case ARMADA_EP_CMD_QUEUE:
	case ARMADA_EP_NOTIF_QUEUE:
		break;
	}
}

/*
 * Configure the buffer pool queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param priv
 *   Pointer to the private device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static inline int
armada_ep_bp_queue_setup(struct rte_eth_dev *dev,
			    struct armada_ep_priv *priv,
			    uint16_t idx, uint16_t desc)
{
	struct armada_ep_queue *hw_bpq = &priv->bp_queue[idx];
	uint32_t desc_size;
	int ret;

	priv->bp_init_size = desc;

	hw_bpq->queue_type = ARMADA_EP_BPOOL_QUEUE;
	armada_ep_init_hw_queue(hw_bpq, priv, idx, desc);

	desc_size = sizeof(struct armada_ep_bpool_desc);
	ret = armada_ep_alloc_queue_resources(dev, hw_bpq, desc_size,
					      priv->rx_queue_size);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate buffers pool %d.\n",
			      idx);
		goto err_hw_bp_queue_setup;
	}
	return 0;
err_hw_bp_queue_setup:
	if (hw_bpq)
		armada_ep_queue_destroy(hw_bpq);
	return ret;
}

/*
 * DPDK callback to configure the receive queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   RX queue index.
 * @param desc
 *   Number of descriptors to configure in queue.
 * @param socket
 *   NUMA socket on which memory must be allocated.
 * @param conf
 *   Thresholds parameters.
 * @param mp
 *   Memory pool for buffer allocations.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			 unsigned int socket,
			 const struct rte_eth_rxconf *conf,
			 struct rte_mempool *mp)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	struct armada_ep_rxq *sw_rxq = NULL;
	struct armada_ep_queue *hw_rxq = NULL;
	uint32_t min_size;
	uint32_t max_rx_pkt_len = dev->data->dev_conf.rxmode.max_rx_pkt_len;
	uint32_t desc_size;
	int ret;
	uint32_t buff_size = rte_pktmbuf_data_room_size(mp) -
		RTE_PKTMBUF_HEADROOM;
	uint64_t offloads;

	/* Update priv queue parameters */
	if (!RTE_IS_POWER_OF_2(desc)) {
		ARMADA_EP_LOG(ERR, "Invalid queue size. Must be power of 2.\n");
		return -EINVAL;
	}
	priv->rx_queue_size = desc;
	priv->buff_size = buff_size;

	min_size = priv->buff_size - ARMADA_EP_PKT_EFFEC_OFFS;
	if (min_size < max_rx_pkt_len) {
		ARMADA_EP_LOG(ERR, "Mbuf size must be increased to %u bytes to"
			      " hold up to %u bytes of data.\n",
			       max_rx_pkt_len + RTE_PKTMBUF_HEADROOM +
			       ARMADA_EP_PKT_EFFEC_OFFS, max_rx_pkt_len);
		return -EINVAL;
	}

	/* Allocate and initiate HW RX queue for max possible number of
	 * hardware descriptors.
	 */
	hw_rxq = rte_zmalloc_socket("rx_ring", sizeof(*hw_rxq), 0, socket);
	if (!hw_rxq) {
		ret = -ENOMEM;
		goto err_hw_rx_queue_setup;
	}

	/* init hw queue */
	hw_rxq->queue_type = ARMADA_EP_RX_QUEUE;
	armada_ep_init_hw_queue(hw_rxq, priv, idx, desc);

	desc_size = sizeof(struct armada_ep_desc);
	ret = armada_ep_alloc_queue_resources(dev, hw_rxq, desc_size,
					      priv->rx_queue_size);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate rx ring %d.\n", idx);
		goto err_hw_rx_queue_setup;
		}

	armada_ep_bp_queue_setup(dev, priv, idx, desc);

	/* Allocate and initiate software queue. */
	if (dev->data->rx_queues[idx]) {
		rte_free(dev->data->rx_queues[idx]);
		dev->data->rx_queues[idx] = NULL;
	}

	offloads = conf->offloads | dev->data->dev_conf.rxmode.offloads;

	sw_rxq = rte_zmalloc_socket("rxq", sizeof(*sw_rxq), 0, socket);
	if (!sw_rxq) {
		ret = -ENOMEM;
		goto err_sw_rx_queue_setup;
	}

	sw_rxq->priv = priv;
	sw_rxq->mp = mp;
	sw_rxq->queue_id = idx;
	sw_rxq->port_id = dev->data->port_id;
	sw_rxq->size = desc;
	sw_rxq->cksum_enabled = offloads & DEV_RX_OFFLOAD_CHECKSUM;

	ret = armada_ep_inq_fill_bpool(sw_rxq, desc - 1);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to fill buffers pool %d.\n", idx);
		goto err_sw_rx_queue_setup;
	}

	dev->data->rx_queues[idx] = sw_rxq;
	ARMADA_EP_LOG(INFO, "Rx queue %d setup successfully", idx);

	return 0;

err_sw_rx_queue_setup:
	rte_free(sw_rxq);

err_hw_rx_queue_setup:
	if (hw_rxq) {
		armada_ep_queue_destroy(&priv->bp_queue[idx]);
		armada_ep_queue_destroy(hw_rxq);
	}
	return ret;
}

/*
 * DPDK callback to configure the transmit queue.
 *
 * @param dev
 *   Pointer to Ethernet device structure.
 * @param idx
 *   Transmit queue index.
 * @param desc
 *   Number of descriptors to configure in the queue.
 * @param socket
 *   NUMA socket on which memory must be allocated.
 * @param conf
 *   Tx queue configuration parameters.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
armada_ep_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t desc,
			 unsigned int socket, const struct rte_eth_txconf *conf)
{
	struct armada_ep_priv *priv = dev->data->dev_private;
	struct armada_ep_txq *sw_txq = NULL;
	struct armada_ep_queue *hw_txq = NULL;
	uint32_t desc_size;
	int ret;

	/* Update priv queue parameters */

	if (!RTE_IS_POWER_OF_2(desc)) {
		ARMADA_EP_LOG(ERR, "Invalid queue size. Must be power of 2.\n");
		return -EINVAL;
	}
	priv->tx_queue_size = desc;

	/* Allocate and initiate HW TX queue for max possible number of
	 * hardware descriptors.
	 */
	hw_txq = rte_zmalloc_socket("tx_ring", sizeof(*hw_txq), 0, socket);
	if (!hw_txq) {
		ret = -ENOMEM;
		goto err_hw_tx_queue_setup;
	}

	/* init hw queue */
	hw_txq->queue_type = ARMADA_EP_TX_QUEUE;
	armada_ep_init_hw_queue(hw_txq, priv, idx, desc);

	desc_size = sizeof(struct armada_ep_desc);
	ret = armada_ep_alloc_queue_resources(dev, hw_txq, desc_size,
					      priv->tx_queue_size);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate tx ring %d.\n", idx);
		goto err_hw_tx_queue_setup;
	}

	/* Allocate and initiate software queue. */
	if (dev->data->tx_queues[idx]) {
		rte_free(dev->data->tx_queues[idx]);
		dev->data->tx_queues[idx] = NULL;
	}

	sw_txq = rte_zmalloc_socket("txq", sizeof(*sw_txq), 0, socket);
	if (!sw_txq) {
		ret =  -ENOMEM;
		goto err_sw_tx_queue_setup;
	}

	sw_txq->priv = priv;
	sw_txq->queue_id = idx;
	sw_txq->port_id = dev->data->port_id;
	sw_txq->tx_deferred_start = conf->tx_deferred_start;
	sw_txq->size = desc;

	sw_txq->shadow_txq.total_size = desc;
	sw_txq->shadow_txq.ent =
		rte_zmalloc_socket("txq-shadow-ents",
				sizeof(struct armada_ep_bpool_desc) *
				sw_txq->shadow_txq.total_size, 0,
				socket);
	if (sw_txq->shadow_txq.ent == NULL) {
		ret = -ENOMEM;
		ARMADA_EP_LOG(ERR, "Tx shadow ents allocation failed");
		goto err_sw_tx_queue_setup;
	}
	sw_txq->shadow_txq.descs =
		rte_zmalloc_socket("txq-shadow-descs",
				sizeof(struct armada_ep_desc) * desc, 0,
				socket);
	if (sw_txq->shadow_txq.descs == NULL) {
		ret = -ENOMEM;
		ARMADA_EP_LOG(ERR, "Tx shadow descs allocation failed");
		goto err_sw_tx_queue_setup;
	}

	dev->data->tx_queues[idx] = sw_txq;
	ARMADA_EP_LOG(INFO, "Tx queue %d setup successfully", idx);
	return 0;

err_sw_tx_queue_setup:
	if (sw_txq) {
		rte_free(sw_txq->shadow_txq.ent);
		rte_free(sw_txq->shadow_txq.descs);
	}
	rte_free(sw_txq);
err_hw_tx_queue_setup:
	armada_ep_queue_destroy(hw_txq);
	return ret;
}

/*
 * armada_ep_queue_destroy - free and zero all queue resource, and queue itself
 */
static inline void
armada_ep_queue_destroy(struct armada_ep_queue *hw_q)
{
	armada_ep_free_queue_resources(hw_q);
	switch (hw_q->queue_type) {
	case ARMADA_EP_RX_QUEUE:
	case ARMADA_EP_TX_QUEUE:
		rte_free(hw_q);
		hw_q = NULL;
		break;
	case ARMADA_EP_BPOOL_QUEUE:
	case ARMADA_EP_CMD_QUEUE:
	case ARMADA_EP_NOTIF_QUEUE:
		break;
	}
}

/* armada_ep_request_device - write a request on the shared host-target memory.
 * In case answer from target will not be rcieved -1 will be return.
 */
static inline int
armada_ep_request_device(struct armada_ep_priv *priv, int request,
			 int required_response)
{
	int timeout = TIMEOUT_INIT;
	int ret = 0;

	/* Request device */
	writel(request, &priv->nic_cfg->status);

	/* Wait until the device firmware sets up the BARs */
	do {
		if (readl(&priv->nic_cfg->status) & required_response)
			break;
		rte_delay_us(1000);
		timeout--;
	} while (timeout);

	if (timeout == 0) {
		ARMADA_EP_LOG(ERR, "Timeout while waiting for device "
			      "response.\n");
		ret = -1;
	}

	return ret;
}

/*
 * armada_ep_mgmt_qs_destroy - free and zero mgmt queues resource
 */
static inline void
armada_ep_mgmt_qs_destroy(struct armada_ep_priv *priv)
{
	armada_ep_request_device(priv, ARMADA_CFG_STATUS_HOST_MGMT_CLOSE_REQ,
				 ARMADA_CFG_STATUS_HOST_MGMT_CLOSE_DONE);

	armada_ep_queue_destroy(&priv->notif_queue);
	armada_ep_queue_destroy(&priv->cmd_queue);
}

/*
 * armada_ep_init_queue_indeces - Initialize Q pointers page.
 *
 * @param priv
 *   Pointer to the private device structure.
 *
 */
static inline int
armada_ep_init_queue_indeces(struct armada_ep_priv *priv)
{
	uint32_t array_size;

	/* q_indices_arr contain two elements for each queue: prod idx and cons
	 * idx. Need to allocate for each queue type: Rx, Tx, BPool, Notif, cmd
	 */
	priv->q_indices_arr_len = (ARMADA_EP_MAX_RXQ_COUNT +
				   ARMADA_EP_MAX_TXQ_COUNT +
				   ARMADA_EP_MAX_BPOOLS_COUNT +
				   ARMADA_EP_MAX_NOTIFQ_COUNT +
				   ARMADA_EP_MAX_CMDQ_COUNT) * 2;
	array_size = priv->q_indices_arr_len * sizeof(uint32_t);

#if !ARMADA_EP_STANDALONE_VDEV_MODE
	if ((priv->nic_cfg->msi_x_tbl_offset - priv->nic_cfg->dev_use_size) <
		array_size) {
		ARMADA_EP_LOG(ERR, "not enough memory on BAR for rings indicex "
			      "ptrs!");
		return -ENOMEM;
	}

	priv->q_indices_arr = (void *)((uint64_t)priv->nic_cfg +
			priv->nic_cfg->dev_use_size);

	/* in case the indices are allocated on the BAR, we would like to send
	 * only the offset from the bar base address
	 */
	priv->q_indices_arr_phys = priv->nic_cfg->dev_use_size;
#else
	priv->q_indices_arr = rte_zmalloc("indices_arr", array_size, 0);
	if (!priv->q_indices_arr) {
		ARMADA_EP_LOG(ERR, "No memory for indices_arr.\n");
		return -ENOMEM;
	};

	priv->q_indices_arr_phys = (dma_addr_t)&priv->q_indices_arr;
#endif

	/* Set all entries to "free" state. */
	memset(priv->q_indices_arr,
	       0xFF,
	       array_size);

	return 0;
}

#if !ARMADA_EP_STANDALONE_VDEV_MODE
/*
 * Communicate management queues information with device side.
 * In case command / notification queue index is located on PCI BARs
 * set queue producer / consumer to PCI BARs
 * else set queue producer / consumer to notification area
 */
static int
armada_ep_mgmt_set_mgmt_queues(struct armada_ep_priv *priv)
{
	struct armada_ep_q_hw_info *cmd_q_info, *notif_q_info;

	/* Set CMD queue base address & length. */
	cmd_q_info = &priv->nic_cfg->cmd_q;
	cmd_q_info->q_addr = priv->cmd_queue.dma;
	cmd_q_info->len  = priv->cmd_queue.count;
	cmd_q_info->q_prod_offs =
		armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
					    priv->cmd_queue.prod_idx);
	cmd_q_info->q_cons_offs =
		armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
					    priv->cmd_queue.cons_idx);

	/* Set Notification queue base address & length. */
	notif_q_info = &priv->nic_cfg->notif_q;
	notif_q_info->q_addr = priv->notif_queue.dma;
	notif_q_info->len  = priv->notif_queue.count;
	notif_q_info->q_prod_offs =
		armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
					    priv->notif_queue.prod_idx);
	notif_q_info->q_cons_offs =
		armada_ep_q_indx_local_phys(priv->q_indices_arr_phys,
					    priv->notif_queue.cons_idx);

	/* Make sure that upper writes are executed before notifying the
	 * end-point.
	 */
	/* Notify the AGNIC */
	armada_ep_request_device(priv, readl(&priv->nic_cfg->status) |
				 ARMADA_EP_CFG_STATUS_HOST_MGMT_READY,
				 ARMADA_EP_CFG_STATUS_DEV_MGMT_READY);
	return 0;
}

/*
 * armada_ep_setup_mgmt_qs - Allocate cmd and notif queues.
 */
static int armada_ep_setup_mgmt_qs(struct rte_eth_dev *dev,
				   struct armada_ep_priv *priv)
{
	struct armada_ep_queue *queue;
	int ret;

	/* Command Ring. */
	queue = &priv->cmd_queue;
	queue->priv = priv;
	queue->queue_type = ARMADA_EP_CMD_QUEUE;

	ret = armada_ep_alloc_queue_resources(dev, queue,
					      sizeof(struct armada_ep_cmd_desc),
					      ARMADA_EP_CMD_QUEUE_LEN);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate command Queue.");
		goto cmd_err;
	}
	ret = armada_ep_alloc_queue_cookies(queue);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate cookies for CMD Queue.");
		goto cmd_err;
	}

	/* Notification Queue. */
	queue = &priv->notif_queue;
	queue->priv = priv;
	queue->queue_type = ARMADA_EP_NOTIF_QUEUE;

	ret = armada_ep_alloc_queue_resources(dev, queue,
					      sizeof(struct armada_ep_cmd_desc),
					      ARMADA_EP_NOTIF_QUEUE_LEN);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate NOTIF Queue.");
		goto notif_err;
	}
	ret = armada_ep_alloc_queue_cookies(queue);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Failed to allocate cookies for Notif"
			      " Queue.");
		goto notif_err;
	}

	/* Now set the MGMT queues pointers in HW. */
	ret = armada_ep_mgmt_set_mgmt_queues(priv);
	if (ret)
		goto q_setup_err;

	rte_spinlock_init(&priv->mgmt_lock);

	return 0;
q_setup_err:
	armada_ep_queue_destroy(&priv->notif_queue);
notif_err:
	armada_ep_queue_destroy(&priv->cmd_queue);
cmd_err:
	return ret;
}
#endif

/*
 * Initialize ARMADA EP private device structure members.
 *
 * @param priv
 *   Pointer to the private device structure (this structure will be assign to
 *   rte_eth_dev structure.
 *
 * @return
 *   0 if successful, else negative number.
 */
static inline int
armada_ep_priv_init(struct rte_eth_dev *eth_dev, struct armada_ep_priv *priv,
		    int device_id, void *nic_va)
{
	int ret;

	priv->id = device_id;
	priv->num_in_tcs = ARMADA_EP_MAX_NUM_TCS;
	priv->num_out_tcs = ARMADA_EP_MAX_NUM_TCS;
	priv->num_qs_per_tc = ARMADA_EP_MAX_NUM_QS_PER_TC;

	priv->pkt_offset = ARMADA_EP_PKT_EFFEC_OFFS;
	if (priv->num_qs_per_tc > 1)
		priv->hash_type = ARMADA_EP_HASH_T_2_TUPLE;

	priv->nic_cfg = nic_va;
	priv->dev_initialized = 0;

#if !ARMADA_EP_STANDALONE_VDEV_MODE
	ret = armada_ep_request_device(priv, ARMADA_EP_CFG_STATUS_HOST_RESET,
				       ARMADA_EP_CFG_STATUS_DEV_READY);
	if (ret)
		goto err_priv_init;
#endif

	/* set indeces */
	ret = armada_ep_init_queue_indeces(priv);
	if (ret)
		goto err_priv_init;

#if !ARMADA_EP_STANDALONE_VDEV_MODE
	ret = armada_ep_setup_mgmt_qs(eth_dev, priv);
	if (ret)
		goto err_priv_init;

	/* Read "HW" capabilities */
	ret = armada_ep_pf_vf_get_capabilities(priv);
	if (ret)
		goto err_priv_init;
#endif

	return 0;

err_priv_init:
	rte_free(priv->q_indices_arr);
	return ret;
}

/*
 * Create private device structure.
 *
 * @param dev_name
 *   Pointer to the port name passed in the initialization parameters.
 *
 * @return
 *   Pointer to the newly allocated private device structure, Null in case of
 *   of a failure.
 */
static inline struct armada_ep_priv*
armada_ep_priv_create(void)
{
	struct armada_ep_priv *priv = NULL;

	priv = rte_zmalloc_socket("armada_ap_priv", sizeof(*priv), 0,
				  rte_socket_id());
	if (priv == NULL)
		ARMADA_EP_LOG(ERR, "Error allocating memory to armada_ep_priv");
	return priv;
}

/*
 * Config device representing Ethernet port.
 *
 * @param vdev
 *   Pointer to the virtual device.
 * @param name
 *   Pointer to the port's name.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static inline int
armada_ep_eth_dev_config(struct rte_eth_dev *eth_dev, int device_id,
			 void *nic_va)
{
	int ret = 0;
	struct armada_ep_priv *priv = NULL;

	/* Flag to call rte_eth_dev_release_port() in rte_eth_dev_close(). */
	eth_dev->data->dev_flags |= RTE_ETH_DEV_CLOSE_REMOVE;

	priv = armada_ep_priv_create();
	if (priv == NULL) {
		ret = -ENOMEM;
		goto out_free_priv;
	}

	/* Initialize private data */
	ret = armada_ep_priv_init(eth_dev, priv, device_id, nic_va);
	if (ret) {
		ARMADA_EP_LOG(ERR, "Error during init priv");
		goto out_free_priv;
	}

	eth_dev->data->mac_addrs = rte_zmalloc("mac_addrs", RTE_ETHER_ADDR_LEN *
					       ARMADA_EP_MAC_ADDRS_MAX, 0);
	if (!eth_dev->data->mac_addrs) {
		ARMADA_EP_LOG(ERR, "Failed to allocate space for eth addrs\n");
		ret = -ENOMEM;
		goto out_free_priv;
	}

	/* init rte_eth_dev struct */
	eth_dev->data->kdrv = RTE_KDRV_NONE;
	eth_dev->data->dev_private = priv;
	eth_dev->dev_ops = &armada_ep_ops;
	return 0;

out_free_priv:
	rte_free(priv);

	return ret;
}

#if ARMADA_EP_VDEV_MODE && !ARMADA_EP_STANDALONE_VDEV_MODE
static void *remap(uint64_t phys_addr)
{
	int fd;
	void *virt;

	fd = open("/dev/mem", O_RDWR);
	if (fd == -1) {
		ARMADA_EP_LOG(ERR, "can't open /dev/mem");
		goto remap_err;
	}

	/* Map one page */

	virt = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		    phys_addr & ~MAP_MASK);
	if (virt == (void *)-1) {
		ARMADA_EP_LOG(ERR, "mmap failed for physical address");
		goto remap_err;
	}
	close(fd);
	return virt;

remap_err:
	close(fd);
	return NULL;
}
#endif

#if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE
/*
 * Callback used by rte_kvargs_process() during argument parsing.
 *
 * @param key
 *   Pointer to the parsed key (unused).
 * @param value
 *   Pointer to the parsed value.
 * @param extra_args
 *   Pointer to the extra arguments which contains address of the
 *   table of pointers to parsed interface names.
 *
 * @return
 *   Always 0.
 */
static inline int
armada_ep_get_ifnames(const char *key __rte_unused, const char *value,
		      void *extra_args)
{
	struct armada_ep_ifnames *ifnames = extra_args;
	ifnames->names[ifnames->idx++] = value;

	return 0;
}

/*
 * DPDK callback to register the virtual device.
 *
 * @param vdev
 *   Pointer to the virtual device.
 *
 * @return
 *   0 on success, negative error value otherwise.
 */
static int
rte_pmd_armada_ep_vdev_probe(struct rte_vdev_device *vdev)
{
	struct rte_kvargs *kvlist = NULL;
	struct armada_ep_ifnames ifnames;
	int ret = -EINVAL;
	uint32_t i, ifnum;
	const char *params;
	struct rte_eth_dev *eth_dev = NULL;
	void *nic_va = NULL;

	/* get device arguments and parse them */
	params = rte_vdev_device_args(vdev);
	if (!params)
		return -EINVAL;

	kvlist = rte_kvargs_parse(params, valid_args);
	if (kvlist == NULL) {
		ARMADA_EP_LOG(ERR, "Invalid arguments");
		return -EINVAL;
	}

	ifnum = rte_kvargs_count(kvlist, ARMADA_EP_IFACE_NAME_ARG);
	if (ifnum > RTE_DIM(ifnames.names)) {
		ARMADA_EP_LOG(ERR, "More interfaces than maximum allow");
		goto out_free_kvlist;
	}

	ifnames.idx = 0;
	rte_kvargs_process(kvlist, ARMADA_EP_IFACE_NAME_ARG,
			   armada_ep_get_ifnames, &ifnames);

	/* For each given interface create device representing ethernet port */
	for (i = 0; i < ifnum; i++) {
		ARMADA_EP_LOG(DEBUG, "Creating %s", ifnames.names[i]);

		eth_dev = rte_eth_dev_allocate(ifnames.names[i]);
		if (eth_dev == NULL) {
			ret = -ENOMEM;
			goto out_free_kvlist;
		}

#if !ARMADA_EP_STANDALONE_VDEV_MODE
		nic_va = remap(PCI_EP_VF_BAR_ADDR(i));
		if (nic_va == NULL) {
			ARMADA_EP_LOG(ERR, "mmap failed for physical address ");
			ret = -EINVAL;
			goto out_cleanup;
		}
#endif

		ret = armada_ep_eth_dev_config(eth_dev, i, nic_va);
		if (ret)
			goto out_cleanup;

		eth_dev->device = &vdev->device;

		rte_eth_dev_probing_finish(eth_dev);
		ARMADA_EP_LOG(INFO, "Probe finish successfully - %s",
			      ifnames.names[i]);
	}

	rte_kvargs_free(kvlist);

	return 0;

out_cleanup:
	rte_pmd_armada_ep_vdev_remove(vdev);
#if !ARMADA_EP_STANDALONE_VDEV_MODE
	if (nic_va)
		munmap(nic_va, MAP_SIZE);
#endif

out_free_kvlist:
	rte_kvargs_free(kvlist);

	return ret;
}

static int
rte_pmd_armada_ep_vdev_remove(struct rte_vdev_device *eth_dev)
{
	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		if (rte_eth_devices[port_id].device != &eth_dev->device)
			continue;
		rte_eth_dev_close(port_id);
	}
	return 0;
}

#else  /* ARMADA_EP_PCI_MODE is defined */

/* PCI Mode */

static int
armada_ep_eth_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;
	int ret = 0;
	uint32_t pci_bar_idx = 2;
	struct rte_mem_resource *pci_bar;
	int device_id;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	rte_eth_copy_pci_info(eth_dev, pci_dev);
	pci_bar = &pci_dev->mem_resource[pci_bar_idx];

	ARMADA_EP_LOG(DEBUG, "pci_dev->mem_resource[0] phys(0x%" PRIx64
		      ") virt(%p) len (0x%" PRIx64 ")",
		      pci_bar->phys_addr, pci_bar->addr, pci_bar->len);

	device_id = pci_dev->addr.function - ARMADA_EP_BASE_FUNCTION_ID;
	ret = armada_ep_eth_dev_config(eth_dev, device_id, pci_bar->addr);
	if (ret)
		goto out_cleanup;

	return ret;
out_cleanup:
	ARMADA_EP_LOG(ERR, "Failed to init eth_dev ret=%d", ret);

	return ret;
}

static int
rte_pmd_armada_ep_pci_probe(struct rte_pci_driver *pci_drv,
			    struct rte_pci_device *pci_dev)
{
	int ret = 0;

	RTE_SET_USED(pci_drv);

	ret = rte_eth_dev_pci_generic_probe(pci_dev,
					    sizeof(struct armada_ep_priv),
					    armada_ep_eth_dev_init);
	if (ret)
		goto out_cleanup;

	return ret;
out_cleanup:
	rte_pmd_armada_ep_pci_remove(pci_dev);
	return ret;
}

static int
rte_pmd_armada_ep_pci_remove(struct rte_pci_device *eth_dev)
{
	/* Low Priority TODO: Dana Add PCI remove */

	uint16_t port_id;

	RTE_ETH_FOREACH_DEV(port_id) {
		if (rte_eth_devices[port_id].device != &eth_dev->device)
			continue;
		rte_eth_dev_close(port_id);
	}
	return 0;
}
#endif  /* end of ifndef ARMADA_EP_PCI_MODE */


#if ARMADA_EP_VDEV_MODE || ARMADA_EP_STANDALONE_VDEV_MODE
RTE_PMD_REGISTER_VDEV(net_armada_ep, vdev_armada_ep_drv);
RTE_PMD_REGISTER_ALIAS(net_armada_ep, eth_armada_ep);
#else
RTE_PMD_REGISTER_PCI(net_armada_ep, pci_armada_ep_drv);
RTE_PMD_REGISTER_PCI_TABLE(net_armada_ep, pci_mrvl_armada_map);
RTE_PMD_REGISTER_KMOD_DEP(net_armada_ep, "vfio-pci");
#endif
