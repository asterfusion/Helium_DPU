/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <signal.h>
#include <stdbool.h>

#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_rawdev.h>

#include "otx2_common.h"
#include "otx2_ep_perf.h"
#include "otx2_ep_rawdev.h"

static void
pci_ep_host_exit_rawdev(uint16_t dev_id)
{
	rte_rawdev_stop(dev_id);
	rte_rawdev_close(dev_id);
}

static void
pci_ep_host_signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		pciep_info("Signal %d received", signum);
		pciep_info("Preparing to exit...\n");
		force_quit = true;
	}
}

static int
pci_ep_host_hw_init(struct pci_ep_core_info *core_info, int num_rawdev)
{
	struct rte_rawdev_info dev_info = { 0 };
	struct sdp_rawdev_info config;
	struct rte_mempool *mpool;
	uint16_t dev_id;
	int index;
	int ret;

	mpool = rte_mempool_create("pciep_pool",
			num_rawdev * 16384 /* Num elt */,
			RTE_MBUF_DEFAULT_BUF_SIZE /* Elt size */,
			0 /* Cache_size */,
			0 /* Private_data_size */,
			NULL /* MP_init */,
			NULL /* MP_init arg */,
			NULL /* Obj_init */,
			NULL /* Obj_init arg */,
			rte_socket_id() /* Socket id */,
			0 /* Flags */);

	if (!mpool) {
		pciep_err("Failed to create mempool");
		return PCI_EP_FAILURE;
	}

	memset(&config, 0x00, sizeof(config));
	config.enqdeq_mpool = mpool;
	config.app_conf = NULL;

	for (index = 0; index < num_rawdev; index++) {
		dev_id = rte_rawdev_get_dev_id(core_info[index].rawdev_name);
		if ((int16_t)dev_id < 0) {
			pciep_err("Provided BDF %s is not a rawdev",
				core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}

		core_info[index].mempool = mpool;
		core_info[index].rawdev_id = dev_id;
		/* Allowed queues per VF are 1, due to driver restriction */
		core_info[index].queue_id = 0;

		dev_info.dev_private = &config;
		ret = rte_rawdev_configure(core_info[index].rawdev_id,
					   &dev_info);
		if (ret) {
			pciep_err("Couldn't able to configure PCI_EP %s",
				core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}

		ret = rte_rawdev_start(core_info[index].rawdev_id);
		if (ret) {
			pciep_err("Couldn't able to start PCI_EP %s",
					core_info[index].rawdev_name);
			return PCI_EP_FAILURE;
		}
	}

	return PCI_EP_SUCCESS;
}

static int
pci_ep_host_get_stats(struct pci_ep_core_info *core_info,
		      int num_rawdev,
		      struct pci_ep_stats *delta_stats)
{
	struct pci_ep_stats ioq_tot_stats = { 0 };
	static struct pci_ep_stats ioq_last_stats;
	int core_id;

	for (core_id = 0; core_id < num_rawdev; core_id++) {
		ioq_tot_stats.tx_events +=
			core_info[core_id].stats.tx_events;
		ioq_tot_stats.tx_bytes  +=
			core_info[core_id].stats.tx_bytes;
		ioq_tot_stats.rx_events +=
			core_info[core_id].stats.rx_events;
		ioq_tot_stats.rx_bytes  +=
			core_info[core_id].stats.rx_bytes;
	}

	delta_stats->tx_events =
		ioq_tot_stats.tx_events - ioq_last_stats.tx_events;
	delta_stats->tx_bytes  =
		ioq_tot_stats.tx_bytes - ioq_last_stats.tx_bytes;
	delta_stats->rx_events =
		ioq_tot_stats.rx_events - ioq_last_stats.rx_events;
	delta_stats->rx_bytes  =
		ioq_tot_stats.rx_bytes - ioq_last_stats.rx_bytes;

	memcpy(&ioq_last_stats, &ioq_tot_stats, sizeof(ioq_last_stats));

	return PCI_EP_SUCCESS;
}

static int
pci_ep_host_rx_data_loop(void *arg)
{
	struct pci_ep_core_info *core_info = (struct pci_ep_core_info *)arg;
	struct sdp_droq_pkt oq_pkt_obj[core_info->burst_size];
	struct rte_rawdev_buf *d_buf[core_info->burst_size];
	struct pci_ep_stats *stats = &core_info->stats;
	struct sdp_droq_pkt *oq_pkt;
	struct sdp_soft_instr si;
	uint64_t pkt_count = 0;
	int count;
	int idx;

	/* Filling out queue buffer */
	for (idx = 0; idx < core_info->burst_size; idx++) {
		memset(&oq_pkt_obj[idx], 0x00, sizeof(struct sdp_droq_pkt));
		d_buf[idx] = (struct rte_rawdev_buf *)&oq_pkt_obj[idx];
	}

	while (!force_quit && pkt_count < core_info->pktnum) {
		count = rte_rawdev_dequeue_buffers(core_info->rawdev_id,
						   d_buf,
						   core_info->burst_size,
						   &si);

		for (idx = 0; idx < count; idx++) {
			oq_pkt = (struct sdp_droq_pkt *)d_buf[idx];
			rte_mempool_put(core_info->mempool, oq_pkt->data);
			stats->rx_events++;
			stats->rx_bytes += oq_pkt->len;
		}
		pkt_count += count;
	}

	pci_ep_host_exit_rawdev(core_info->rawdev_id);
	force_quit = true;

	return PCI_EP_SUCCESS;
}

static int
pci_ep_host_tx_data_loop(void *arg)
{
	struct pci_ep_core_info *core_info = (struct pci_ep_core_info *)arg;
	struct pci_ep_stats *stats = &core_info->stats;
	struct sdp_soft_instr si;
	struct sdp_device sdpvf;
	uint64_t pkt_count = 0;
	void *buf;

	memset(&si, 0x00, sizeof(si));
	memset(&sdpvf, 0x00, sizeof(sdpvf));

	si.q_no = core_info->queue_id;
	si.rptr = NULL;

	si.ih.fsz = PCI_EP_HOST_PKT_FRONT_SIZE;
	si.ih.tlen = core_info->pktlen;
	si.ih.gather = 0;

	si.reqtype = SDP_REQTYPE_NORESP;

	while (!force_quit && pkt_count < core_info->pktnum) {
		rte_mempool_get(core_info->mempool, &buf);
		if (!buf) {
			pciep_dbg("Buffer allocation failed");
			continue;
		}
		si.dptr = (uint8_t *)buf;

		while (!rte_rawdev_enqueue_buffers(core_info->rawdev_id,
						   NULL, 1, &si))
			rte_pause();
		stats->tx_events++;
		stats->tx_bytes += core_info->pktlen;
		pkt_count++;
	}

	pci_ep_host_exit_rawdev(core_info->rawdev_id);
	force_quit = true;

	return PCI_EP_SUCCESS;
}

static int
pci_ep_host_rxtx_data_loop(void *arg_ptr)
{
	struct pci_ep_core_info *core_info = (struct pci_ep_core_info *)arg_ptr;
	struct sdp_droq_pkt oq_pkt_obj[core_info->burst_size];
	struct rte_rawdev_buf *d_buf[core_info->burst_size];
	struct pci_ep_stats *stats = &core_info->stats;
	struct sdp_droq_pkt *oq_pkt;
	struct sdp_device sdpvf;
	struct sdp_soft_instr si;
	uint64_t pkt_count = 0;
	void *buf;
	int count;
	int idx;

	/* Filling out queue buffer */
	for (idx = 0; idx < core_info->burst_size; idx++) {
		memset(&oq_pkt_obj[idx], 0x00, sizeof(struct sdp_droq_pkt));
		d_buf[idx] = (struct rte_rawdev_buf *)&oq_pkt_obj[idx];
	}

	memset(&si, 0x00, sizeof(si));
	memset(&sdpvf, 0x00, sizeof(sdpvf));

	si.q_no = core_info->queue_id;
	si.rptr = NULL;

	si.ih.fsz = PCI_EP_HOST_PKT_FRONT_SIZE;
	si.ih.tlen = core_info->pktlen;
	si.ih.gather = 0;

	si.reqtype = SDP_REQTYPE_NORESP;

	while (!force_quit && pkt_count < core_info->pktnum) {
		/* Dequeue */
		count = rte_rawdev_dequeue_buffers(core_info->rawdev_id,
						   d_buf,
						   core_info->burst_size,
						   &si);
		for (idx = 0; idx < count; idx++) {
			oq_pkt = (struct sdp_droq_pkt *)d_buf[idx];
			rte_mempool_put(core_info->mempool, oq_pkt->data);
			stats->rx_events++;
			stats->rx_bytes += oq_pkt->len;
		}
		pkt_count += count;

		/* Enqueue */
		for (idx = 0; idx < core_info->burst_size; idx++) {
			rte_mempool_get(core_info->mempool, &buf);
			if (!buf) {
				pciep_dbg("Buffer allocation failed");
				break;
			}
			si.dptr = (uint8_t *)buf;

			while (!rte_rawdev_enqueue_buffers(core_info->rawdev_id,
							   NULL, 1, &si))
				rte_pause();
			stats->tx_events++;
			stats->tx_bytes += core_info->pktlen;
		}
		pkt_count += idx;
	}

	pci_ep_host_exit_rawdev(core_info->rawdev_id);
	force_quit = true;

	return PCI_EP_SUCCESS;
}

int
pci_ep_setup_methods(struct pci_ep_mode_specific_methods *io_methods, int mode)
{
	io_methods->signal_handler = pci_ep_host_signal_handler;
	io_methods->get_stats = pci_ep_host_get_stats;
	io_methods->hw_init = pci_ep_host_hw_init;

	switch (mode) {
	case conn_rxtx:
		io_methods->data_loop = pci_ep_host_rxtx_data_loop;
		break;

	case conn_rx_only:
		io_methods->data_loop = pci_ep_host_rx_data_loop;
		break;

	case conn_tx_only:
		io_methods->data_loop = pci_ep_host_tx_data_loop;
		break;

	default:
		pciep_err("Invalid Mode");
		return PCI_EP_FAILURE;
	}
	return PCI_EP_SUCCESS;
}

