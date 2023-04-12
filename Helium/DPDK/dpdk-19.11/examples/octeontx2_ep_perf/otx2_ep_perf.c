/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_pci.h>

#include "otx2_ep_perf.h"

volatile bool force_quit;

static const struct option long_options[] = {
	{"whitelist", required_argument, 0, 'w'},
	{"pktnum", required_argument, 0, 'n'},
	{"pktlen", required_argument, 0, 'l'},
	{"mode", required_argument, 0, 'm'},
	{"burst", required_argument, 0, 'b'},
	{0, 0, 0, 0}
};

static void
pci_ep_app_usage(const char *app_name)
{
	char usage_str[2048];

	snprintf(usage_str, sizeof(usage_str),
		"  Usage: %s [options]\n"
		"  Options:\n"
		"  -n, --packets=N       Send/Receive N packets(default ~32M)\n"
		"                             0 implies no limit\n"
		"  -l, --pktlen=N        Send packets with size N\n"
		"                             (default 1024)\n"
		"  -w, --whitelist=BDF   Rawdev white listing\n"
		"                             it is for host application only;\n"
		"  -m, --mode=N          Transmission mode is RX/TX/Both\n"
		"                             with values 0/1/2 (default 2)\n"
		"  -b, --burst=N         Dequeue burst size(default 1).\n"
		"                             should be between [1-256]\n"
		"\n", app_name);

	fprintf(stderr, "%s", usage_str);
	exit(1);
}

static int
pci_ep_has_valid_number(char *str)
{
	if (!str)
		return PCI_EP_FAILURE;

	for (; *str != 0; str++) {
		if (isdigit(*str) == 0)
			return PCI_EP_FAILURE;
	}

	return PCI_EP_SUCCESS;
}

static int
pci_ep_has_valid_mode(char *str)
{
	int num;

	if (pci_ep_has_valid_number(str) != PCI_EP_SUCCESS)
		return PCI_EP_FAILURE;

	num = atoi(str);
	if ((num != conn_rx_only) &&
	    (num != conn_tx_only) &&
	    (num != conn_rxtx))
		return PCI_EP_FAILURE;

	return PCI_EP_SUCCESS;
}

static int
pci_ep_app_validate_cores(int num_cores)
{
	int enabled_core_count;
	int avail_cores;
	int core_id;

	avail_cores = rte_lcore_count();
	if (num_cores > avail_cores) {
		pciep_err("Available cores are %d only", avail_cores);
		pciep_err("But number of white listing rawdevs are %d",
				num_cores);
		return PCI_EP_FAILURE;
	}

	enabled_core_count = 0;
	RTE_LCORE_FOREACH_SLAVE(core_id) {
		if (rte_lcore_is_enabled(core_id))
			enabled_core_count++;
	}

	if (num_cores > enabled_core_count) {
		pciep_err("Available cores are %d", avail_cores);
		pciep_err("But enabled cores %d", enabled_core_count);
		pciep_err("Number of white listing rawdevs are %d",
				num_cores);
		return PCI_EP_FAILURE;
	}

	return PCI_EP_SUCCESS;
}

static int
pci_ep_parse_app_args(int argc, char *argv[],
			  struct pci_ep_core_info *core_info,
			  int *num_rawdev, uint64_t *pktnum,
			  int *pktlen, int *mode, int *burst)
{
	struct rte_pci_addr pci_addr;
	char sdpep_rawdev_name[128];
	int index;
	int opt;

	/* Default values */
	*num_rawdev = 0;
	*pktnum = 1ULL << 25;
	*pktlen = 1024;
	*mode = conn_rxtx;
	*burst = 1;

	while ((opt = getopt_long(argc, argv, "in:l:w:m:b:",
				  long_options, &index)) != -1) {

		switch (opt) {

		case 'n':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Packets value is not in format");
				return PCI_EP_FAILURE;
			}
			*pktnum = atol(optarg);
			if (!(*pktnum))
				*pktnum = UINT64_MAX;
			break;

		case 'l':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Packet length is not in format");
				return PCI_EP_FAILURE;
			}
			*pktlen = atoi(optarg);
			if (!(*pktlen))
				*pktlen = 1024;
			break;

		case 'w':
			if (rte_pci_addr_parse(optarg, &pci_addr)
						!= PCI_EP_SUCCESS) {
				pciep_err("rawdev is not in BDF format");
				return PCI_EP_FAILURE;
			}

			if (*num_rawdev >= RTE_MAX_LCORE) {
				pciep_err("provided rawdevs > max cores %d",
					RTE_MAX_LCORE);
				return PCI_EP_FAILURE;
			}

			sprintf(sdpep_rawdev_name, "SDPEP:%x:%02x.%d",
					pci_addr.bus,
					pci_addr.devid,
					pci_addr.function);

			core_info[*num_rawdev].rawdev_name =
				rte_zmalloc("IOQ_TESTAPP",
					    strlen(sdpep_rawdev_name) + 1,
					    0);

			if (core_info[*num_rawdev].rawdev_name == NULL) {
				pciep_err("Couldn't able to create memory");
				return PCI_EP_FAILURE;
			}
			strcpy(core_info[*num_rawdev].rawdev_name,
			       sdpep_rawdev_name);

			*num_rawdev += 1;
			break;

		case 'm':
			if (pci_ep_has_valid_mode(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Mode value is not in format");
				return PCI_EP_FAILURE;
			}
			*mode = atoi(optarg);
			break;

		case 'b':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Burst value is not in format");
				return PCI_EP_FAILURE;
			}
			*burst = atoi(optarg);

			if (*burst < 1 || *burst > 256) {
				pciep_err("Burst should be in [1-256]");
				return PCI_EP_FAILURE;
			}
			break;

		default:
			pciep_err("Invalid option");
			return PCI_EP_FAILURE;
		}
	}

	if (*num_rawdev == 0) {
		pciep_err("Rawdevs are not provided");
		return PCI_EP_FAILURE;
	}

	if (pci_ep_app_validate_cores(*num_rawdev) != PCI_EP_SUCCESS)
		return PCI_EP_FAILURE;

	return PCI_EP_SUCCESS;
}

static int
pci_ep_parse_args(int argc, char *argv[],
		  struct pci_ep_core_info *core_info,
		  int *num_cores, uint64_t *pktnum,
		  int *pktlen, int *mode, int *burst)
{
	int ret_argc;
	int ret;

	ret_argc = rte_eal_init(argc, argv);
	if (ret_argc < 0) {
		pciep_err("Invalid EAL arguments");
		return PCI_EP_FAILURE;
	}

	ret = pci_ep_parse_app_args(argc - ret_argc, argv + ret_argc,
				    core_info, num_cores,
				    pktnum, pktlen, mode, burst);
	if (ret) {
		pci_ep_app_usage(argv[0]);
		return PCI_EP_FAILURE;
	}

	return ret_argc;
}

static void
pci_ep_display_stats(struct pci_ep_stats *stats)
{
	double rx_gbps = ((double)stats->rx_bytes * 8)/1000000000;
	double tx_gbps = ((double)stats->tx_bytes * 8)/1000000000;
	double rx_mpps = ((double)stats->rx_events)/1000000;
	double tx_mpps = ((double)stats->tx_events)/1000000;
	double mpps = rx_mpps + tx_mpps;
	double gbps = rx_gbps + tx_gbps;
	static uint64_t samples;
	static double tot_mpps;
	static double tot_gbps;

	tot_mpps += mpps;
	tot_gbps += gbps;
	samples++;

	printf("\x1b[32m");
	printf("avg: %.4lf mpps, %.4lf gbps; time = %ld seconds\n",
		tot_mpps/samples, tot_gbps/samples, samples);
	printf("\trx: %.4lf mpps, %.4lf gbps\n", rx_mpps, rx_gbps);
	printf("\ttx: %.4lf mpps, %.4lf gbps\n", tx_mpps, tx_gbps);
	printf("\trxtx: %.4lf mpps, %.4lf gbps\n", mpps, gbps);
	printf("\x1b[0m");
	fflush(stdout);
}

int
main(int argc, char *argv[])
{
	struct pci_ep_core_info core_info[RTE_MAX_LCORE];
	struct pci_ep_mode_specific_methods methods;
	struct pci_ep_stats stats;
	uint64_t pktnum;
	int num_cores;
	int burst_size;
	int eal_args;
	int lcore_id;
	int pktlen;
	int index;
	int mode;
	int ret;
	int err;

	force_quit = false;

	eal_args = pci_ep_parse_args(argc, argv, core_info, &num_cores,
					 &pktnum, &pktlen, &mode, &burst_size);
	if (eal_args < 0)
		return PCI_EP_FAILURE;

	for (index = 0; index < num_cores; index++) {
		core_info[index].pktnum = pktnum;
		core_info[index].pktlen = pktlen;
		/* Burst-size used for host app only */
		core_info[index].burst_size = burst_size;
	}

	if (pci_ep_setup_methods(&methods, mode) != PCI_EP_SUCCESS)
		return PCI_EP_FAILURE;

	ret = methods.hw_init(core_info, num_cores);
	if (ret)
		return PCI_EP_FAILURE;

	signal(SIGINT, methods.signal_handler);
	signal(SIGTERM, methods.signal_handler);

	index = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		err = rte_eal_remote_launch(methods.data_loop,
					    (void *)&core_info[index],
					    lcore_id);
		if (err) {
			pciep_dbg("Failed to launch core %d", lcore_id);
			continue;
		}

		if (++index == num_cores)
			break;
	}

	while (!force_quit) {
		usleep(1000000);
		ret = methods.get_stats(core_info, num_cores, &stats);
		if (ret)
			return PCI_EP_FAILURE;
		pci_ep_display_stats(&stats);
	}

	rte_eal_mp_wait_lcore();

	return PCI_EP_SUCCESS;
}

