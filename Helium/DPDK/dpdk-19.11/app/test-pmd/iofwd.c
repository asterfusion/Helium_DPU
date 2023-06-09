/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
//	uint64_t tx_offloads = ports[fs->tx_port].dev_conf.txmode.offloads;
//	uint64_t ol_flags = 0;

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_tsc;
	uint64_t end_tsc;
	uint64_t core_cycles;
#endif

#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	start_tsc = rte_rdtsc();
#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return;
	fs->rx_packets += nb_rx;

#if 0
        //add by marvin, to suuport checksum offload and tso
        if (tx_offloads & DEV_TX_OFFLOAD_IPV4_CKSUM)
        {
                int i;
                uint32_t ptype;
                for(i=0; i< nb_rx; i++)
                {
                        ptype = pkts_burst[i]->packet_type;
                        ol_flags = 0;
                        if((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4 ||
                                        (ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV4_EXT )
                        {
                                ol_flags |= PKT_TX_IP_CKSUM;
                                ol_flags |= PKT_TX_IPV4;
                                ol_flags |= PKT_TX_OUTER_IPV4;
                                ol_flags |= PKT_TX_OUTER_IP_CKSUM;
                        }
                        else if((ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6 ||
                                        (ptype & RTE_PTYPE_L3_MASK) == RTE_PTYPE_L3_IPV6_EXT )
                        {
                                ol_flags |= PKT_TX_IP_CKSUM;
                                ol_flags |= PKT_TX_IPV6;
                                ol_flags |= PKT_TX_OUTER_IPV6;
                                ol_flags |= PKT_TX_OUTER_IP_CKSUM;
                        }

			if((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
			{
				ol_flags |= PKT_TX_TCP_CKSUM;
				
				if(tx_offloads & DEV_TX_OFFLOAD_TCP_TSO)
				{
					ol_flags |= PKT_TX_TCP_SEG;
					pkts_burst[i]->tso_segsz = 9000;
					struct rte_tcp_hdr * tcp_hdr = (struct rte_tcp_hdr *)((uint8_t *)rte_pktmbuf_mtod(pkts_burst[i], struct rte_ether_hdr *) + pkts_burst[i]->l2_len + pkts_burst[i]->l3_len);
					pkts_burst[i]->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
					//printf("l4_len %d, l2 %d, l3 %d\n", pkts_burst[i]->l4_len, pkts_burst[i]->l2_len, pkts_burst[i]->l3_len);
				}
			}
			else if((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
			{
                                ol_flags |= PKT_TX_UDP_CKSUM;
                        }

			if(ol_flags)
			{
                                pkts_burst[i]->ol_flags |= ol_flags;
                                //printf("ol_flags 0x%x == 0x%x\n", ol_flags, pkts_burst[i]->ol_flags);
                        }
		}
	}
#endif

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
			pkts_burst, nb_rx);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
		}
	}
	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	end_tsc = rte_rdtsc();
	core_cycles = (end_tsc - start_tsc);
	fs->core_cycles = (uint64_t) (fs->core_cycles + core_cycles);
#endif
}

struct fwd_engine io_fwd_engine = {
	.fwd_mode_name  = "io",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_io_forward,
};
