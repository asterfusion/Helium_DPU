/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 */

#ifndef RTE_FLOW_DRIVER_H_
#define RTE_FLOW_DRIVER_H_

/**
 * @file
 * RTE generic flow API (driver side)
 *
 * This file provides implementation helpers for internal use by PMDs, they
 * are not intended to be exposed to applications and are not subject to ABI
 * versioning.
 */

#include <stdint.h>

#include "rte_ethdev.h"
#include "rte_ethdev_driver.h"
#include "rte_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Generic flow operations structure implemented and returned by PMDs.
 *
 * To implement this API, PMDs must handle the RTE_ETH_FILTER_GENERIC filter
 * type in their .filter_ctrl callback function (struct eth_dev_ops) as well
 * as the RTE_ETH_FILTER_GET filter operation.
 *
 * If successful, this operation must result in a pointer to a PMD-specific
 * struct rte_flow_ops written to the argument address as described below:
 *
 * \code
 *
 * // PMD filter_ctrl callback
 *
 * static const struct rte_flow_ops pmd_flow_ops = { ... };
 *
 * switch (filter_type) {
 * case RTE_ETH_FILTER_GENERIC:
 *     if (filter_op != RTE_ETH_FILTER_GET)
 *         return -EINVAL;
 *     *(const void **)arg = &pmd_flow_ops;
 *     return 0;
 * }
 *
 * \endcode
 *
 * See also rte_flow_ops_get().
 *
 * These callback functions are not supposed to be used by applications
 * directly, which must rely on the API defined in rte_flow.h.
 *
 * Public-facing wrapper functions perform a few consistency checks so that
 * unimplemented (i.e. NULL) callbacks simply return -ENOTSUP. These
 * callbacks otherwise only differ by their first argument (with port ID
 * already resolved to a pointer to struct rte_eth_dev).
 */
struct rte_flow_ops {
	/** See rte_flow_validate(). */
	int (*validate)
		(struct rte_eth_dev *,
		 const struct rte_flow_attr *,
		 const struct rte_flow_item [],
		 const struct rte_flow_action [],
		 struct rte_flow_error *);
	/** See rte_flow_create(). */
	struct rte_flow *(*create)
		(struct rte_eth_dev *,
		 const struct rte_flow_attr *,
		 const struct rte_flow_item [],
		 const struct rte_flow_action [],
		 struct rte_flow_error *);
	/** See rte_flow_destroy(). */
	int (*destroy)
		(struct rte_eth_dev *,
		 struct rte_flow *,
		 struct rte_flow_error *);
	/** See rte_flow_flush(). */
	int (*flush)
		(struct rte_eth_dev *,
		 struct rte_flow_error *);
	/** See rte_flow_query(). */
	int (*query)
		(struct rte_eth_dev *,
		 struct rte_flow *,
		 const struct rte_flow_action *,
		 void *,
		 struct rte_flow_error *);
	/** See rte_flow_isolate(). */
	int (*isolate)
		(struct rte_eth_dev *,
		 int,
		 struct rte_flow_error *);
	/** See rte_flow_dev_dump(). */
	int (*dev_dump)
		(struct rte_eth_dev *dev,
		 FILE *file,
		 struct rte_flow_error *error);
	/** See rte_flow_get_aged_flows() */
	int (*get_aged_flows)
		(struct rte_eth_dev *dev,
		 void **context,
		 uint32_t nb_contexts,
		 struct rte_flow_error *err);
	/** See rte_flow_shared_action_create() */
	struct rte_flow_shared_action *(*shared_action_create)
		(struct rte_eth_dev *dev,
		 const struct rte_flow_shared_action_conf *conf,
		 const struct rte_flow_action *action,
		 struct rte_flow_error *error);
	/** See rte_flow_shared_action_destroy() */
	int (*shared_action_destroy)
		(struct rte_eth_dev *dev,
		 struct rte_flow_shared_action *shared_action,
		 struct rte_flow_error *error);
	/** See rte_flow_shared_action_update() */
	int (*shared_action_update)
		(struct rte_eth_dev *dev,
		 struct rte_flow_shared_action *shared_action,
		 const struct rte_flow_action *update,
		 struct rte_flow_error *error);
	/** See rte_flow_shared_action_query() */
	int (*shared_action_query)
		(struct rte_eth_dev *dev,
		 const struct rte_flow_shared_action *shared_action,
		 void *data,
		 struct rte_flow_error *error);
	/** See rte_flow_tunnel_decap_set() */
	int (*tunnel_decap_set)
		(struct rte_eth_dev *dev,
		 struct rte_flow_tunnel *tunnel,
		 struct rte_flow_action **pmd_actions,
		 uint32_t *num_of_actions,
		 struct rte_flow_error *err);
	/** See rte_flow_tunnel_match() */
	int (*tunnel_match)
		(struct rte_eth_dev *dev,
		 struct rte_flow_tunnel *tunnel,
		 struct rte_flow_item **pmd_items,
		 uint32_t *num_of_items,
		 struct rte_flow_error *err);
	/** See rte_flow_get_rte_flow_restore_info() */
	int (*get_restore_info)
		(struct rte_eth_dev *dev,
		 struct rte_mbuf *m,
		 struct rte_flow_restore_info *info,
		 struct rte_flow_error *err);
	/** See rte_flow_action_tunnel_decap_release() */
	int (*tunnel_action_decap_release)
		(struct rte_eth_dev *dev,
		 struct rte_flow_action *pmd_actions,
		 uint32_t num_of_actions,
		 struct rte_flow_error *err);
	/** See rte_flow_item_release() */
	int (*tunnel_item_release)
		(struct rte_eth_dev *dev,
		 struct rte_flow_item *pmd_items,
		 uint32_t num_of_items,
		 struct rte_flow_error *err);
};

/**
 * Get generic flow operations structure from a port.
 *
 * @param port_id
 *   Port identifier to query.
 * @param[out] error
 *   Pointer to flow error structure.
 *
 * @return
 *   The flow operations structure associated with port_id, NULL in case of
 *   error, in which case rte_errno is set and the error structure contains
 *   additional details.
 */
const struct rte_flow_ops *
rte_flow_ops_get(uint16_t port_id, struct rte_flow_error *error);

#ifdef __cplusplus
}
#endif

#endif /* RTE_FLOW_DRIVER_H_ */
