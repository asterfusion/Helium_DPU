/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/**
 * @file facility.h
 * @brief defines facility interface data structures and APIs
 *
 * Facility is a mechanism provided through which host and target
 * modules (implementing the functionality of facilities) communicate
 * via OcteonTX memory made accessible to Host through OcteonTX BAR1
 */
 
#ifndef _FACILITY_H_
#define _FACILITY_H_
#include <linux/interrupt.h>

#include "mv_facility.h"

/**
 * @brief Facility type
 *
 * Facility type; Each facility is assigned a unique ID
 */

enum mv_facility_type {
	MV_FACILITY_CONTROL,       /* Control module */
	MV_FACILITY_MGMT_NETDEV,   /* Management Netdev */
	MV_FACILITY_NW_AGENT,      /* Network Agent */
	MV_FACILITY_RPC,           /* RPC */
	MV_FACILITY_RAW,           /* RAW; to use in raw mode */
	/* Add new Facilities here */
	MV_FACILITY_COUNT          /* Number of facilities */
};

#define MV_FACILITY_FLAG(flag) (1 << flag)

/**
 * @brief Facility flags
 *
 * Facility flags, may include capabilities exchanged between facility
 * modules on host and target
 */
enum mv_facility_flag {
        /* Add new flags here */
	MV_FACILITY_FLAG_MAX /* Number of facilities */
};

#define FACILITY_NAME_LEN 32
#define MV_FACILITY_NAME_CONTROL "control"
#define MV_FACILITY_NAME_MGMT_NETDEV "mgmt-netdev"
#define MV_FACILITY_NAME_NETWORK_AGENT "nwa"
#define MV_FACILITY_NAME_RPC "rpc"

#define MV_FACILITY_CONTROL_IRQ_CNT 1
#define MV_FACILITY_MGMT_NETDEV_IRQ_CNT 1
#define MV_FACILITY_NW_AGENT_IRQ_CNT 1
#define MV_FACILITY_RPC_IRQ_CNT 5

#define MV_FACILITY_MAX_DBELLS 16

#define FACILITY_INSTANCE(x)	((x >> 4) & 0xf)
#define FACILITY_TYPE(x)	(x & 0xf)
/**
 * @brief Facility DMA device
 *
 * Underlying device to be used for DMA mapping by facility module
 */
typedef union {
	/* Host Endpoint device */
	struct device *host_ep_dev;

	/* Target DMA device */
	struct device *target_dma_dev;
} mv_facility_dev_t;

/**
 * @brief Facility Configuration
 *
 * Facility Configuration
 */
typedef struct {
        /* device to be used for DMA mapping */
        mv_facility_dev_t dma_dev;

        char name[FACILITY_NAME_LEN];

        /* Facility type */
        int type;

        /* Flags include capabilities */
        uint64_t flags;

        /* address of OcteonTX BAR1 memory assigned to the facility */
        mv_bar_map_addr_t memmap;
        uint32_t memsize;

        /* Number of doorbells assigned to facility for host to
         * interrupt its counterpart on target
         */
        unsigned int num_h2t_dbells;

        /* Number of doorbells assigned to facility for target to
         * interrupt its counterpart on host
         */
        unsigned int num_t2h_dbells;
} mv_facility_conf_t;

/* Facility event callback function pointer */
typedef int (*mv_facility_event_cb)(void *);

typedef struct {
        mv_facility_event_cb cb;
        void *cb_arg;
} mv_facility_event_cb_t;

/**
 * @brief Get Facility configuration
 *
 * Fills conf with facility configuration or throws error for
 * invalid facility type
 * @param type Facility type.
 * @param conf pointer to facility configuration.
 * @return 0 on success, -1 on error.
 */
int mv_get_facility_conf(int type, mv_facility_conf_t *conf);

/**
 * @brief Request Facility IRQ
 *
 * Register Facility handler for a doorbell interrupt
 * This API implemented by pcie_host driver and facility module
 * invokes this API to register its API to handle a doorbell interrupt
 * For each doorbell interrupt, facility can register different API.
 * pcie_host (eth_mux) driver maps the facility doorbell to hardware
 * irq and registers it (request_irq())
 * @param type Facility type.
 * @param dbell index within doorbells assigned to facility
 *              for example: 0 to num_t2h_dbells-1.
 * @param handler function be invoked upon doorbell interrupt.
 * @param arg this is passed as “dev” parameter to request_irq().
 *            so this argument is passed to the handler
 *            upon invocation.
 *
 * @return 0, on success and standard error numbers on failure
 */
int mv_facility_request_dbell_irq(int type,
                                  int dbell, irq_handler_t handler,
                                  void *arg);

/**
 * @brief Free facility IRQ
 *
 * Unregister Facility handler for a doorbell interrupt
 * pcie_host will free corresponding hardware irq (free_irq()).
 * @param dbell index within doorbells assigned to facility
 * @param arg   argument passed to mv_facility_request_dbell_irq().
 *              This is passed as dev_id parameter to free_irq().
 */
void mv_facility_free_dbell_irq(int type, int dbell, void *arg);

/**
 * @brief Register Facility Event callback
 *
 * If a facility does not have dedicated IRQs, it’s driver should call
 * this API to register common callback for all events to the facility
 * The callback handler is invoked in process context.
 * @param type Facility type.
 * @param handler callback function.
 * @param cb_arg argument to be passed to the callback handler.
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_facility_register_event_callback(int type,
                                        mv_facility_event_cb handler,
                                        void *cb_arg);

/**
 * @brief Unregister Facility Event Callback
 *
 * Unregister event handler for the facility
 * @param type Facility type.
 */
void mv_facility_unregister_event_callback(int type);

/**
 * @brief: Send Doorbell Interrupt to Remote Facility
 *
 * Send doorbell to counterpart of the facility; host calls this to
 * interrupt facility on target and vice-versa.
 * @param type Facility Type.
 * @param dbell Index within doorbells assigned to facility
 *              for example: 0 to num_t2h_dbells-1.
 *
 * @return 0 on success, standard error code on failure.
 */
int mv_send_facility_dbell(int type, int dbell);

/**
 * @brief: Send Event notification to Remote Facility
 *
 * Send event notification to counterpart of the facility; host calls
 * this to notify facility on target and vice-versa.
 * @param type Facility Type.
 *
 * @return 0 on success, standard error code on failure.
 */
int mv_send_facility_event(int type);

static inline int is_facility_valid(int type)
{
	return (type < MV_FACILITY_COUNT);
}
#endif /* _FACILITY_H_ */
