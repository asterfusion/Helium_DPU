/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef _OTX2_EP_PERF_H_
#define _OTX2_EP_PERF_H_

#define PCI_EP_HOST_PKT_FRONT_SIZE    0

#define PCI_EP_LOG_MODE  0
#define PCI_EP_ERR_LOG   0
#define PCI_EP_INFO_LOG  1
#define PCI_EP_DBG_LOG   2

#define PCI_EP_SUCCESS  0
#define PCI_EP_FAILURE -1

enum pci_ep_conn {
	conn_rx_only = 0,
	conn_tx_only,
	conn_rxtx
};

struct pci_ep_stats {
	size_t tx_events;
	size_t tx_bytes;
	size_t rx_events;
	size_t rx_bytes;
};

struct pci_ep_core_info {
	struct rte_mempool *mempool;
	struct pci_ep_stats stats;
	uint64_t pktnum;
	int queue_id;
	int pktlen;
	int mode;
	int burst_size;
	char *rawdev_name;
	uint16_t rawdev_id;
} __rte_cache_aligned;

#define pciep_err(fmt, args...)					\
	do {							\
		if (PCI_EP_LOG_MODE >= PCI_EP_ERR_LOG)		\
			printf("ERR: %s():%u " fmt "\n",	\
				__func__, __LINE__, ## args);	\
	} while (0)

#define pciep_info(fmt, args...)				\
	do {							\
		if (PCI_EP_LOG_MODE >= PCI_EP_INFO_LOG)		\
			printf("INFO: %s():%u " fmt "\n",	\
				__func__, __LINE__, ##args);	\
	} while (0)

#define pciep_dbg(fmt, args...)					\
	do {							\
		if (PCI_EP_LOG_MODE >= PCI_EP_DBG_LOG)		\
			printf("DEBUG: %s():%u " fmt "\n",	\
				__func__, __LINE__, ##args);	\
	} while (0)


typedef void (*pci_ep_signal_handler_t)(int);
typedef int (*pci_ep_hw_init_t)(struct pci_ep_core_info *, int);
typedef int (*pci_ep_data_loop_t)(void *);
typedef int (*pci_ep_get_stats_t)(struct pci_ep_core_info *, int,
				  struct pci_ep_stats *);

struct pci_ep_mode_specific_methods {
	pci_ep_signal_handler_t signal_handler;
	pci_ep_hw_init_t hw_init;
	pci_ep_data_loop_t data_loop;
	pci_ep_get_stats_t get_stats;
} __rte_cache_aligned;

extern volatile bool force_quit;

int pci_ep_setup_methods(struct pci_ep_mode_specific_methods *methods,
			 int mode);

#endif  /* _OTX2_EP_PERF_H_ */
