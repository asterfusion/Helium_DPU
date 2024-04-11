/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/**
 * @file mv_facility.h
 * @brief defines facility interface data structures and APIs
 *
 * Facility is a mechanism provided through which host and target
 * modules (implementing the functionality of facilities) communicate
 * via platform memory made accessible to Host through platform BAR0
 */

#ifndef _MV_FACILITY_H_
#define _MV_FACILITY_H_
#include <linux/interrupt.h>

#define MAX_FACILITY_INSTANCES	2

/**
 * @brief facility memory address
 *
 * address of memory assigned to facility
 */
typedef union {
	uint64_t u64;

	/* Host IO remapped address of mapped memory */
	void __iomem *host_addr;

	/* Target virtual address of mapped memory */
	void *target_addr;
} mv_bar_map_addr_t;

/**
 * @brief facility bar mapped memory
 *
 * facility retrieves the bar memory and size using this structure
 */
typedef struct {
	mv_bar_map_addr_t addr;
	uint32_t memsize;
} mv_bar_map_t;

typedef u64 host_dma_addr_t;

enum mv_dma_dir {
	MV_DMA_TO_HOST = 0,
	MV_DMA_FROM_HOST = 1,
};

enum mv_target {
	MV_TARGET_HOST = 0,
	MV_TARGET_EP = 1,
};

/**
 * @brief Get number of facility instances
 *
 * Returns the number of facility configurations for the given facility type.
 * @param name          facility name
 * @return count of facility instances and standard error for failure.
 */
int mv_get_facility_instance_count(char *name);

/**
 * @brief Get facility handle of an instance
 *
 * Returns the facility handle based on the instance number and the
 facility
 * name passed. this handle should be used for all facility based APIs.
 *
 * @param instance      instance number
 * @param name          facility name
 * @return              handle on success, error on failure.
 */
int mv_get_multi_facility_handle(int instance, char *name);

/**
 * @brief Get Facility handle
 *
 * Returns the facility handle based on the passed facility name, this handle
 * should be used for all Facility based API below
 * @param name		the Facility name.
 * @return handle >= 0 on success, on error returns errno.
 */
int mv_get_facility_handle(char *name);

/**
 * @brief Get the Facility device count
 *
 * Returns the number of facility device's used for dma
 * @param handle	Facility handle
 *
 * @return >= 0, on success and standard error numbers on failure.
 */
int mv_pci_get_dma_dev_count(
	int			handle);

/**
 * @brief Get the Facility device
 *
 * Returns the facility device used for dma
 * @param handle	Facility handle
 * @param index 	index of dma device.
 * @param dev		the device used by the facility
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_pci_get_dma_dev(
	int			handle,
	int 			index,
	struct device		**dev);

/**
 * @brief Perform DMA operation
 *
 * Performs a DMA operation on a DMA assigned to a facility
 * @param handle	Facility handle
 * @param dev 		dma device
 * @param host_addr	dma address in host system
 * @param ep_addr	virtual address in target system
 * @param dma_ep_addr	dma address in target system
 * @param dir		direction of dma transaction
 * @param size		transaction size in bytes
 *
 * @return 0, on success and standard error numbers on failure.
 */
#ifdef CONFIG_MV_FACILITY_DMA_API
int mv_pci_sync_dma(
	int			handle,
	struct device 		*dev,
	host_dma_addr_t		host_addr,
	void			*ep_addr,
	dma_addr_t		dma_ep_addr,
	enum mv_dma_dir		dir,
	u32			size);
#endif

/**
 * @brief Return the facility doorbells number
 *
 * Returns the number of doorbells configured for the facility
 * @param handle	Facility handle
 * @param target	the doorbell direction
 * @param num_dbells	the number of doorbells
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_get_num_dbell(
	int			handle,
	enum mv_target		target,
	uint32_t		*num_dbells);

/**
 * @brief Request Facility IRQ
 *
 * Register Facility handler for a doorbell interrupt
 * doorbell interrupts start disabled.
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 * @param handler	function be invoked upon doorbell interrupt
 * @param arg		this is passed as "dev" parameter to request_irq().
 *			so this argument is passed to the handler
 *			upon invocation.
 * @param cpumask	cpu's that will handle irq for this doorbell.
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_request_dbell_irq(
	int			handle,
	uint32_t		dbell,
	irq_handler_t		handler,
	void			*arg,
	const struct cpumask 	*cpumask);

/**
 * @brief Free Facility IRQ
 *
 * Unregister Facility handler for a doorbell interrupt
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 * @param arg		argument passed to mv_request_dbell_irq().
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_free_dbell_irq(
	int			handle,
	uint32_t		dbell,
	void			*arg);

/**
 * @brief Enable doorbell IRQ
 *
 * Enables the Facility doorbell IRQ
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_dbell_enable(
	int			handle,
	uint32_t		dbell);

/**
 * @brief Disable doorbell IRQ
 *
 * Disables the Facility doorbell IRQ
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_dbell_disable(
	int			handle,
	uint32_t		dbell);

/**
 * @brief Disable doorbell IRQ without waiting
 *
 * Disables the Facility doorbell IRQ, does not ensure existing instances
 * of the IRQ handler have completed before returning
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_dbell_disable_nosync(
	int			handle,
	uint32_t		dbell);

/**
 * @brief Send doorbell interrupt to remote Facility
 *
 * Send doorbell to counterpart of the Facility, host calls this to
 * interrupt Facility on target and vice-versa.
 * @param handle	Facility handle
 * @param dbell		the doorbell to use
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_send_dbell(
	int			handle,
	uint32_t		dbell);

/**
 * @brief Returns the Facility bar map
 *
 * Returns the Facility bar map structure that includes the host or target
 * address and memory size of this mapped memory
 * @param handle	Facility handle
 * @param bar_map	the returned bar map structure filled in by Facility
 *
 * @return 0, on success and standard error numbers on failure.
 */
int mv_get_bar_mem_map(
	int			handle,
	mv_bar_map_t		*bar_map);

#endif /* _MV_FACILITY_H_ */
