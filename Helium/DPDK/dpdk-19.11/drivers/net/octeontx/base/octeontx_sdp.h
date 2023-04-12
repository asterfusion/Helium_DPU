/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef __OCTEONTX_SDP_H__
#define __OCTEONTX_SDP_H__

#include <stddef.h>
#include <stdint.h>

#include <octeontx_mbox.h>

#define OCTEONTX_SDP_COPROC		11

/* SDP messages */
#define MBOX_SDP_PORT_OPEN		0
#define MBOX_SDP_PORT_CLOSE		1
#define MBOX_SDP_PORT_START		2
#define MBOX_SDP_PORT_STOP		3
#define MBOX_SDP_PORT_GET_CONFIG	4
#define MBOX_SDP_PORT_GET_STATUS	5
#define MBOX_SDP_PORT_GET_STATS		6
#define MBOX_SDP_PORT_CLR_STATS		7
#define MBOX_SDP_PORT_GET_LINK_STATUS	8
#define MBOX_SDP_REG_READ		9
#define MBOX_SDP_REG_WRITE		10

/* SDP port configuration parameters: */
typedef struct octeontx_mbox_sdp_port_conf {
	/* 1 = port activated, 0 = port is idle.*/
	uint8_t enable;
	/* 1 = backpressure enabled, 0 = disabled.*/
	uint8_t bpen;
	/* CPU node */
	uint8_t node;
	/* Base channel (PKI_CHAN_E) */
	uint16_t base_chan;
	/* Number of channels */
	uint16_t num_chans;
	/* Diagnostics support: */
	/* BGX number */
	uint8_t sdp;
	/* LMAC number */
	uint8_t lmac;
	/* PF value of PKIND (PKI port: BGX[]_CMR[]_RX_ID_MAP[pknd]).*/
	uint8_t pkind;
} octeontx_mbox_sdp_port_conf_t;

/* SDP port status: */
typedef struct octeontx_mbox_sdp_port_status {
	/* 1 = link is up, 0 = link is down. */
	uint8_t link_up;
	/* 1 = LMAC is backpressured, 0 = no backpressure. */
	uint8_t bp;
} octeontx_mbox_sdp_port_status_t;

/* SDP port statistics: */
typedef struct octeontx_mbox_SDP_port_stats {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
	uint64_t rx_errors;
	uint64_t tx_errors;
	uint64_t rx_dropped;
	uint64_t tx_dropped;
	uint64_t multicast;
	uint64_t collisions;

	/* Detailed receive errors. */
	uint64_t rx_length_errors;
	uint64_t rx_over_errors;
	uint64_t rx_crc_errors;
	uint64_t rx_frame_errors;
	uint64_t rx_fifo_errors;
	uint64_t rx_missed_errors;

	/* Detailed transmit errors. */
	uint64_t tx_aborted_errors;
	uint64_t tx_carrier_errors;
	uint64_t tx_fifo_errors;
	uint64_t tx_heartbeat_errors;
	uint64_t tx_window_errors;

	/* Extended statistics based on RFC2819. */
	uint64_t rx_1_to_64_packets;
	uint64_t rx_65_to_127_packets;
	uint64_t rx_128_to_255_packets;
	uint64_t rx_256_to_511_packets;
	uint64_t rx_512_to_1023_packets;
	uint64_t rx_1024_to_1522_packets;
	uint64_t rx_1523_to_max_packets;

	uint64_t tx_1_to_64_packets;
	uint64_t tx_65_to_127_packets;
	uint64_t tx_128_to_255_packets;
	uint64_t tx_256_to_511_packets;
	uint64_t tx_512_to_1023_packets;
	uint64_t tx_1024_to_1522_packets;
	uint64_t tx_1523_to_max_packets;
} octeontx_mbox_sdp_port_stats_t;

typedef struct octeontx_mbox_sdp_reg {
	uint64_t addr;
	uint64_t val;
} octeontx_mbox_sdp_reg_t;
int octeontx_sdp_port_open(int port, octeontx_mbox_sdp_port_conf_t *conf);
int octeontx_sdp_port_close(int port);
int octeontx_sdp_port_start(int port);
int octeontx_sdp_port_stop(int port);
int octeontx_sdp_port_config(int port, octeontx_mbox_sdp_port_conf_t *conf);
int octeontx_sdp_port_status(int port, octeontx_mbox_sdp_port_status_t *stat);
int octeontx_sdp_port_stats(int port, octeontx_mbox_sdp_port_stats_t *stats);
int octeontx_sdp_port_stats_clr(int port);
int octeontx_sdp_port_link_status(int port);
int octeontx_sdp_reg_read(uint64_t addr, uint64_t *val);
int octeontx_sdp_reg_write(uint64_t addr, uint64_t val);
#endif	/* __OCTEONTX_SDP_H__ */
