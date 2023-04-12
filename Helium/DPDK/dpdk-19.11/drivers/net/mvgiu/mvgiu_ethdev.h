/*  SPDX-License-Identifier: BSD-3-Clause
 *  Copyright(c) 2018 Marvell International Ltd.
 */

#ifndef _MVGIU_ETHDEV_H_
#define _MVGIU_ETHDEV_H_

#include <rte_spinlock.h>
#include <rte_flow_driver.h>
#include <rte_ethdev.h>
#include <env/mv_autogen_comp_flags.h>
#include <drivers/mv_giu.h>
#include <drivers/mv_giu_bpool.h>
#include <drivers/mv_giu_gpio.h>
#include <mng/mv_nmp_guest.h>

#define MVGIU_MAX_NUM_TCS_PER_PORT	GIU_GPIO_MAX_NUM_TCS
#define MVGIU_MAX_NUM_QS_PER_TC		GIU_GPIO_TC_MAX_NUM_QS

/** Maximum number of rx queues per port */
#define MVGIU_RXQ_MAX (GIU_GPIO_MAX_NUM_TCS * GIU_GPIO_TC_MAX_NUM_QS)

/** Maximum number of tx queues per port */
#define MVGIU_TXQ_MAX (GIU_GPIO_MAX_NUM_TCS * GIU_GPIO_TC_MAX_NUM_QS)

/** Tx queue descriptors alignment */
#define MVGIU_TXD_ALIGN 16

/** Rx queue descriptors alignment */
#define MVGIU_RXD_ALIGN 16

/** Minimum number of sent buffers to release from shadow queue to BM */
#define MVGIU_BUF_RELEASE_BURST_SIZE	64

#define MVGIU_MAC_ADDRS_MAX 1

#define MVGIU_PKT_EFFEC_OFFS (0)

struct mvgiu_priv {
	/* Hot fields, used in fast path. */
	struct giu_bpool *bpool;  /**< BPool pointer */
	struct giu_gpio	*gpio;    /**< Port handler pointer */
	rte_spinlock_t lock;	  /**< Spinlock for checking bpool status */
	uint16_t bpool_init_size; /**< Configured BPool size  */

	/** Mapping for DPDK rx queue->(TC, MRVL relative inq) */
	struct {
		uint8_t tc;  /**< Traffic Class */
		uint8_t inq; /**< Relative in-queue number */
	} rxq_map[MVGIU_RXQ_MAX] __rte_cache_aligned;

	uint16_t nb_rx_queues;

	struct giu_bpool_capabilities bpool_capa;
	struct giu_gpio_capabilities gpio_capa;
};

#endif /* _MVGIU_ETHDEV_H_ */
