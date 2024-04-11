/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/* Mgmt ethernet driver
 */

#ifndef _OCTBOOT_NET_ETHDEV_H_
#define _OCTBOOT_NET_ETHDEV_H_

//#define MTU_1500_SETTINGS
#define MTU_9600_SETTINGS

#define DPI_MAX_PTR_1500_MTU 15
#define DPI_MAX_PTR_9600_MTU 4

#define RECV_BUF_SIZE_1500_MTU 2048
#define RECV_BUF_SIZE_9600_MTU 12288

#ifdef MTU_1500_SETTINGS
#define OCTBOOT_NET_MAX_MTU 1500
#define DPIX_MAX_PTR DPI_MAX_PTR_1500_MTU
#define OCTBOOT_NET_RX_BUF_SIZE RECV_BUF_SIZE_1500_MTU
#endif

#ifdef MTU_9600_SETTINGS
#define OCTBOOT_NET_MAX_MTU 9600
#define DPIX_MAX_PTR DPI_MAX_PTR_9600_MTU
#define OCTBOOT_NET_RX_BUF_SIZE RECV_BUF_SIZE_9600_MTU
#endif

#define OTXMN_NUM_ELEMENTS 2048
#define OTXMN_VERSION  "1.0.0"
#define	OTXMN_SERVICE_TASK_US 1000
/* max number of tx/rx queues we support */
#define OTXMN_MAXQ 1
#define OTXMN_DESCQ_CLEAN 0
#define OTXMN_DESCQ_READY 1

static inline uint32_t octboot_net_circq_add(uint32_t index, uint32_t add,
				       uint32_t mask)
{
	return (index + add) & mask;
}

static inline uint32_t octboot_net_circq_inc(uint32_t index, uint32_t mask)
{
	return octboot_net_circq_add(index, 1, mask);
}

static inline uint32_t octboot_net_circq_depth(uint32_t pi, uint32_t ci,
					 uint32_t mask)
{
	return (pi - ci) & mask;
}

static inline uint32_t octboot_net_circq_space(uint32_t pi, uint32_t ci,
					 uint32_t mask)
{
	return mask - octboot_net_circq_depth(pi, ci, mask);
}

struct octboot_net_sw_descq {
	uint32_t local_prod_idx;
	uint32_t local_cons_idx;
	void *priv;
	spinlock_t lock;
	struct napi_struct napi;
	uint32_t q_num;
	uint32_t pending;
	uint32_t element_count;
	uint32_t mask;
	uint32_t * __iomem hw_prod_idx;
	uint32_t *cons_idx_shadow;
	struct sk_buff **skb_list;
	dma_addr_t *dma_list;
	uint8_t * __iomem hw_descq;
	uint32_t status;
	uint64_t pkts;
	uint64_t bytes;
	uint64_t errors;
};

#endif /* _OCTBOOT_NET_ETHDEV_H_ */
