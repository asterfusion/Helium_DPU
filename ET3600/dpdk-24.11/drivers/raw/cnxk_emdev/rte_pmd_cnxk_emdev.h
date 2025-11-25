/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#ifndef _RTE_PMD_CNXK_EMDEV_H_
#define _RTE_PMD_CNXK_EMDEV_H_

#include <rte_ether.h>

#define CNXK_EMDEV_ATTR_FUNC_Q_MAP   "func_q_map:"
#define CNXK_EMDEV_ATTR_VIRT_Q_COUNT "vnet_q_count:"
#define CNXK_EMDEV_ATTR_LINK_STATUS  "vnet_link_status:"
#define CNXK_EMDEV_ATTR_NAME_LEN     20

#define RTE_PMD_EMDEV_MAX	16
#define RTE_PMD_EMDEV_FUNCS_MAX 128

/** Device status callback */
typedef int (*rte_pmd_cnxk_emdev_status_cb_t)(uint16_t emdev_id, uint16_t func_id, uint8_t status);

enum rte_pmd_emdev_type {
	EMDEV_TYPE_VIRTIO_NET = 1,
	EMDEV_TYPE_VIRTIO_CRYPTO = 2,
	EMDEV_TYPE_MAX,
};

struct rte_pmd_cnxk_func_q_map_attr {
	uint16_t func_id;
	uint16_t outb_qid;
	uint16_t qid;
};

/** Virtio net device link info */
struct rte_pmd_cnxk_vnet_link_info {
	/** Function ID */
	uint16_t func_id;

	/** Link status */
	uint16_t status;
	/**
	 * Link speed.
	 *
	 * Speed contains the device speed, in units of 1 MBit per second,
	 * 0 to 0x7fffffff, or 0xffffffff for unknown speed.
	 */
	uint32_t speed;
	/**
	 * Link mode.
	 *
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	uint8_t duplex;
};

struct rte_pmd_cnxk_vnet_conf {
	/** RETA size supported */
	uint16_t reta_size;
	/** HASH key size supported */
	uint16_t hash_key_size;
	/** Default MTU */
	uint16_t mtu;
	/** Default MAC address */
	uint8_t mac[RTE_ETHER_ADDR_LEN];
	/** Link info */
	struct rte_pmd_cnxk_vnet_link_info link_info;
};

struct rte_pmd_cnxk_emdev_info {
	uint16_t num_dev_funcs;
};

struct rte_pmd_cnxk_emdev_conf {
	uint16_t num_emdev_queues;
	uint16_t max_outb_queues;
	uint16_t num_funcs;
	enum rte_pmd_emdev_type emdev_type;

	rte_pmd_cnxk_emdev_status_cb_t status_cb;

	/* Default mempool */
	struct rte_mempool *default_mp;

	struct rte_pmd_cnxk_vnet_conf vnet_conf[RTE_PMD_EMDEV_FUNCS_MAX];
};

struct rte_pmd_cnxk_emdev_q_conf {
	uint16_t nb_desc;
};

struct rte_pmd_cnxk_emdev_event {
	/* Dequeued hoqid and index to be shared between dequeue and
	 * enqueue operations.
	 */
	uint16_t qid;
	uint16_t ci_start;
	uint16_t ci_end;
	uint16_t status;
	uint8_t func_id;
#define RTE_PMD_CNXK_EMDEV_EVENT_TYPE_CTRL 0x1
	uint8_t type;
	uint16_t data_len;
	uint8_t data[];
};

#endif /* _RTE_PMD_CNXK_EMDEV_H_ */
