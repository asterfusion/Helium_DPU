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
	{"concurrent", required_argument, 0, 'c'},
	{"dump", required_argument, 0, 'd'},
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
		"  -c, --concurrent=N    Enqueue/Dequeue burst size(default 1).\n"
		"                             should be between [1-256]\n"
		"  -d, --dump=N          Print pkg context.\n"
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
        (num != conn_rxtx) && 
        (num != conn_ec96))
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
pci_ep_parse_app_args(int argc, char *argv[], struct pci_ep_core_info *core_info,
                       int *num_rawdev)
{
	struct rte_pci_addr pci_addr;
	char sdpep_rawdev_name[128];
	int index;
	int opt;

	*num_rawdev = 0;
	int concurrent = 1;
    core_info->burst_size = concurrent;
    core_info->pktnum = UINT64_MAX;
    core_info->pktlen = 1024;
    core_info->dump = 0;

	while ((opt = getopt_long(argc, argv, "n:l:w:m:c:d:",
				  long_options, &index)) != -1) {

		switch (opt) {

		case 'n':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Packets value is not in format");
				return PCI_EP_FAILURE;
			}
            
            core_info->pktnum = (atoi(optarg) <= 0) ? UINT64_MAX : atoi(optarg);
			break;

		case 'l':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Packet length is not in format");
				return PCI_EP_FAILURE;
			}

            core_info->pktlen = (atoi(optarg) == 0) ? 1024 : atoi(optarg);
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
			core_info->mode = atoi(optarg);
			break;

		case 'c':
			if (pci_ep_has_valid_number(optarg) != PCI_EP_SUCCESS) {
				pciep_err("Burst value is not in format");
				return PCI_EP_FAILURE;
			}
			concurrent = atoi(optarg);

			if (concurrent < 1 || concurrent > 256) {
				pciep_err("PKGS concurrent should be in [1-256]");
				return PCI_EP_FAILURE;
			}

            core_info->burst_size = concurrent;
			break;

        case 'd':
            core_info->dump = atoi(optarg);
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

    printf("num_rawdev %d\n", *num_rawdev);

	if (pci_ep_app_validate_cores(*num_rawdev) != PCI_EP_SUCCESS)
		return PCI_EP_FAILURE;

	return PCI_EP_SUCCESS;
}



static void
pci_ep_display_stats(struct pci_ep_stats *stats, useconds_t time)
{
	double rx_gbps = ((double)stats->rx_bytes * 8)/(1000*time);
	double tx_gbps = ((double)stats->tx_bytes * 8)/(1000*time);
	double rx_mpps = ((double)stats->rx_events)/time;
	double tx_mpps = ((double)stats->tx_events)/time;
	double mpps = rx_mpps + tx_mpps;
	double gbps = rx_gbps + tx_gbps;
	static uint64_t samples;
	static double tot_mpps;
	static double tot_gbps;

	tot_mpps += mpps;
	tot_gbps += gbps;
	samples++;

	printf("\x1b[32m");
	printf("avg: %.4lf mpps, %.4lf gbps; epoch %ld \n",
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
    struct pci_ep_core_run_info core_run[RTE_MAX_LCORE];
	struct pci_ep_stats stats;
    int cnt = 0;
    int start = 0;	
	int raw_devs;
	int lcore_id;
	int index;
	int ret;
	int err;
    int ret_argc;

	force_quit = false;

    //EAL init	
	ret_argc = rte_eal_init(argc, argv);
	if (ret_argc < 0) {
        pciep_err("Invalid EAL arguments");
        return PCI_EP_FAILURE;
    }
   
    //Parse input params	
	ret = pci_ep_parse_app_args(argc - ret_argc, argv + ret_argc, core_info, 
                                &raw_devs);
	if (ret) {
		pci_ep_app_usage(argv[0]);
		return PCI_EP_FAILURE;
	}

    //Set pkt configs for each rawdev (each rawdev a core)
    for (index = 1; index < raw_devs; index++) {
        core_info[index].pktnum = core_info[0].pktnum;
        core_info[index].pktlen = core_info[0].pktlen;
        core_info[index].burst_size = core_info[0].burst_size;
        core_info[index].mode = core_info[0].mode;
        core_info[index].dump = core_info[0].dump;
    }

    //config each raw_device 	
    ret = pci_ep_host_hw_config(core_info, raw_devs);
	if (ret)
		return PCI_EP_FAILURE;

    //take over  SIGINT SIGTERM
    signal(SIGINT, pci_ep_host_signal_handler);
    signal(SIGTERM, pci_ep_host_signal_handler);

    // one queue per cpu cores
    for (index = 0; index < raw_devs; index++) {
        for (cnt = 0; cnt < core_info[index].queues; cnt++) {
            core_run[start+cnt].config = (char *)(core_info+index);
            core_run[start+cnt].rawdev_id = core_info[index].rawdev_id;
            core_run[start+cnt].queue_id = cnt;
            memset(&(core_run[start+cnt].stats), 0, sizeof(struct pci_ep_stats));
        }
		start += cnt;
    }

    index = 0;
    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        err = rte_eal_remote_launch(pci_ep_host_data_loop,
					    (void *)&core_run[index],
					    lcore_id);
        if (err) {
            pciep_dbg("Failed to launch core %d", lcore_id);
            continue;
        }

        if (++index == start) {
            printf("\n[cores] cores total use %d\n", start);
			break;
		}
    }

	while (!force_quit) {
        useconds_t disp_time = 5 * 1000000;
		usleep(disp_time);
        ret = pci_ep_host_get_stats(core_info, start, &stats);
        if (ret) {
            printf("\nERRORs  ret %d\n",ret);
			return PCI_EP_FAILURE;
        }
	//	pci_ep_display_stats(&stats, disp_time);
    }

    rte_eal_mp_wait_lcore();
    for (index = 0; index < raw_devs; index++) {
        pci_ep_host_exit_rawdev(core_info[index].rawdev_id);
    }


    return PCI_EP_SUCCESS;
}

