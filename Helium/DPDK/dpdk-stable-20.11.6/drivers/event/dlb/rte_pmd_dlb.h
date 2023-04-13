/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2020 Intel Corporation
 */

/*!
 *  @file      rte_pmd_dlb.h
 *
 *  @brief     DLB PMD-specific functions
 *
 */

#ifndef _RTE_PMD_DLB_H_
#define _RTE_PMD_DLB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Selects the token pop mode for an DLB port.
 */
enum dlb_token_pop_mode {
	/* Pop the CQ tokens immediately after dequeueing. */
	AUTO_POP,
	/* Pop CQ tokens after (dequeue_depth - 1) events are released.
	 * Supported on load-balanced ports only.
	 */
	DELAYED_POP,
	/* Pop the CQ tokens during next dequeue operation. */
	DEFERRED_POP,

	/* NUM_TOKEN_POP_MODES must be last */
	NUM_TOKEN_POP_MODES
};

/*!
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Configure the token pop mode for an DLB port. By default, all ports use
 * AUTO_POP. This function must be called before calling rte_event_port_setup()
 * for the port, but after calling rte_event_dev_configure().
 *
 * @note
 *    The defer_sched vdev arg, which configures all load-balanced ports with
 *    dequeue_depth == 1 for DEFERRED_POP mode, takes precedence over this
 *    function.
 *
 * @param dev_id
 *    The identifier of the event device.
 * @param port_id
 *    The identifier of the event port.
 * @param mode
 *    The token pop mode.
 *
 * @return
 * - 0: Success
 * - EINVAL: Invalid dev_id, port_id, or mode
 * - EINVAL: The DLB is not configured, is already running, or the port is
 *   already setup
 */

__rte_experimental
int
rte_pmd_dlb_set_token_pop_mode(uint8_t dev_id,
			       uint8_t port_id,
			       enum dlb_token_pop_mode mode);
#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMD_DLB_H_ */
