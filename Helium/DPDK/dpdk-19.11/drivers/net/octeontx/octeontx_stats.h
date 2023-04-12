/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */
#define BGX_XSTAT(stat) \
	{#stat, offsetof(octeontx_mbox_bgx_port_stats_t, stat)}
struct octeontx_xstats {
	char sname[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t soffset;
};

struct octeontx_xstats octeontx_bgx_xstats[] = {
	BGX_XSTAT(rx_packets),
	BGX_XSTAT(tx_packets),
	//BGX_XSTAT(rx_bytes),
	//BGX_XSTAT(tx_bytes),
	BGX_XSTAT(rx_broadcast_packets),
	BGX_XSTAT(multicast),
	BGX_XSTAT(rx_1_to_64_packets),
	BGX_XSTAT(rx_65_to_127_packets),
	BGX_XSTAT(rx_128_to_255_packets),
	BGX_XSTAT(rx_256_to_511_packets),
	BGX_XSTAT(rx_512_to_1023_packets),
	BGX_XSTAT(rx_1024_to_1522_packets),
	BGX_XSTAT(rx_1523_to_max_packets),
	BGX_XSTAT(tx_multicast_packets),
	BGX_XSTAT(tx_broadcast_packets),
	BGX_XSTAT(rx_undersized_errors),
	BGX_XSTAT(rx_oversize_errors),
	BGX_XSTAT(rx_jabber_errors),
	BGX_XSTAT(rx_crc_errors),
	BGX_XSTAT(collisions),
	//BGX_XSTAT(rx_errors),
	//BGX_XSTAT(tx_errors),
	//BGX_XSTAT(rx_dropped),
	//BGX_XSTAT(tx_dropped),
	//BGX_XSTAT(rx_length_errors),
	//BGX_XSTAT(rx_over_errors),
	//BGX_XSTAT(rx_frame_errors),
	//BGX_XSTAT(rx_fifo_errors),
	//BGX_XSTAT(rx_missed_errors),
	//BGX_XSTAT(tx_aborted_errors),
	//BGX_XSTAT(tx_carrier_errors),
	//BGX_XSTAT(tx_fifo_errors),
	//BGX_XSTAT(tx_heartbeat_errors),
	//BGX_XSTAT(tx_window_errors),
	BGX_XSTAT(tx_1_to_64_packets),
	BGX_XSTAT(tx_65_to_127_packets),
	BGX_XSTAT(tx_128_to_255_packets),
	BGX_XSTAT(tx_256_to_511_packets),
	BGX_XSTAT(tx_512_to_1023_packets),
	BGX_XSTAT(tx_1024_to_1522_packets),
	BGX_XSTAT(tx_1523_to_max_packets),
	BGX_XSTAT(rx_fragmented_errors),
	BGX_XSTAT(rx_pause_packets),
	BGX_XSTAT(tx_pause_packets),
};

#define NUM_BGX_XSTAT \
	(sizeof(octeontx_bgx_xstats) / sizeof(struct octeontx_xstats))
