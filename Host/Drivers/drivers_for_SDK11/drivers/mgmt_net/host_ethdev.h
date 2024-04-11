/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/* Mgmt ethernet driver
 */

#ifndef _HOST_ETHDEV_H_
#define _HOST_ETHDEV_H_

//#define MTU_1500_SETTINGS
#define MTU_9600_SETTINGS

#define DPI_MAX_PTR_1500_MTU 15
#define DPI_MAX_PTR_9600_MTU 4

#define RECV_BUF_SIZE_1500_MTU 2048
#define RECV_BUF_SIZE_9600_MTU 12288

#ifdef MTU_1500_SETTINGS
#define OTXMN_MAX_MTU 1500
#define DPIX_MAX_PTR DPI_MAX_PTR_1500_MTU
#define OTXMN_RX_BUF_SIZE RECV_BUF_SIZE_1500_MTU
#endif

#ifdef MTU_9600_SETTINGS
#define OTXMN_MAX_MTU 9600
#define DPIX_MAX_PTR DPI_MAX_PTR_9600_MTU
#define OTXMN_RX_BUF_SIZE RECV_BUF_SIZE_9600_MTU
#endif

#define OTXMN_NUM_ELEMENTS 2048
#define OTXMN_VERSION  "1.0.0"
#define	OTXMN_SERVICE_TASK_US 1000
/* max number of tx/rx queues we support */
#define OTXMN_MAXQ 1
#define OTXMN_DESCQ_CLEAN 0
#define OTXMN_DESCQ_READY 1

static inline uint32_t otxmn_circq_add(uint32_t index, uint32_t add,
				       uint32_t mask)
{
        return (index + add) & mask;
}

static inline uint32_t otxmn_circq_inc(uint32_t index, uint32_t mask)
{
        return otxmn_circq_add(index, 1, mask);
}

static inline uint32_t otxmn_circq_depth(uint32_t pi, uint32_t ci,
					 uint32_t mask)
{
        return (pi - ci) & mask;
}

static inline uint32_t otxmn_circq_space(uint32_t pi, uint32_t ci,
					 uint32_t mask)
{
        return mask - otxmn_circq_depth(pi, ci, mask);
}

struct otxmn_sw_descq {
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

struct otxmn_dev {
	struct device *dev;
	struct net_device *ndev;
	struct otxmn_sw_descq rxq[OTXMN_MAXQ];
	struct otxmn_sw_descq txq[OTXMN_MAXQ];
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
	uint8_t hw_addr[ETH_ALEN];
};

#endif /* _HOST_ETHDEV_H_ */
