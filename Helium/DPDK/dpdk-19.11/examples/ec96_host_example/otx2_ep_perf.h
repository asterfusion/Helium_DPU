/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef _OTX2_EP_PERF_H_
#define _OTX2_EP_PERF_H_

#define PCI_EP_HOST_PKT_FRONT_SIZE   0

#define PCI_EP_LOG_MODE  0
#define PCI_EP_ERR_LOG   0
#define PCI_EP_INFO_LOG  1
#define PCI_EP_DBG_LOG   2

#define PCI_EP_SUCCESS  0
#define PCI_EP_FAILURE -1

#include <rte_rawdev.h>

enum pci_ep_conn {
    conn_rx_only = 0,
    conn_tx_only = 1,
    conn_rxtx    = 2,
    conn_ec96    = 3,
};

struct pci_ep_stats {
	size_t tx_events;
	size_t tx_bytes;
	size_t rx_events;
	size_t rx_bytes;
};

struct pci_ep_core_info {
	struct rte_mempool *mempool;
	uint64_t pktnum;
	int queues;
	int pktlen;
	int mode;
	int burst_size;
	char *rawdev_name;
	uint16_t rawdev_id;
    uint8_t dump;
} __rte_cache_aligned;


struct pci_ep_core_run_info {
    uint8_t rawdev_id;
    uint8_t queue_id;
	char *config;
	struct pci_ep_stats stats;
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


extern volatile bool force_quit;

void pci_ep_host_exit_rawdev(uint16_t dev_id);
int pci_ep_host_hw_config(struct pci_ep_core_info *core_info, int num_rawdev);
void pci_ep_host_signal_handler(int signum);
int pci_ep_host_data_loop(void *arg_ptr);
int pci_ep_host_get_stats(struct pci_ep_core_run_info *run_info, int num_rawdev,
                      struct pci_ep_stats *delta_stats);

void pci_ep_rx_pkts(struct pci_ep_core_info *core_info, uint8_t q_no,
                    struct rte_rawdev_buf **buffers, uint64_t pkg_num, 
                    struct pci_ep_stats *stats);
void pci_ep_tx_pkts(struct pci_ep_core_info *core_info, uint8_t q_no, 
                     uint64_t pkg_num, uint8_t *mbuf, struct pci_ep_stats *stats);
void pci_ep_ec96_pkts(struct pci_ep_core_info *core_info, uint8_t q_no,
                    struct rte_rawdev_buf **buffers, struct pci_ep_stats *stats);

#endif  /* _OTX2_EP_PERF_H_ */
