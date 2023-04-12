/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

/*!  \file  octeon-nic-common.h
     \brief Common: Structures and macros used in PCI-NIC package by core and
                    host driver.
 */

#ifndef __OCTEON_NIC_COMMON_H__
#define __OCTEON_NIC_COMMON_H__

#include "octeon-common.h"
#include "octeon_config.h"

#ifdef ETHERPCI
/* EtherPCI supports 4 virtual OCTEON Ethernet interfaces */
#undef    MAX_OCTEON_LINKS
#define   MAX_OCTEON_LINKS    4
#define   ETHERPCI_QUEUES_PER_LINK   1
#define   OCTNET_POW_GRP      15
#else
#define   OCTNET_POW_GRP      0
#endif

#define   OCTNET_MIN_FRM_SIZE        64
#define   OCTNET_MAX_FRM_SIZE        16018
#define   OCTNET_DEFAULT_FRM_SIZE    1518

/** NIC Commands are sent using this Octeon Input Queue */
#define   OCTNET_CMD_Q                0

/* NIC Command types */
#define   OCTNET_CMD_CHANGE_MTU       0x1
#define   OCTNET_CMD_CHANGE_MACADDR   0x2
#define   OCTNET_CMD_CHANGE_DEVFLAGS  0x3
#define   OCTNET_CMD_RX_CTL           0x4

#define   OCTNET_CMD_SET_MAC_TBL      0x5
#define   OCTNET_CMD_CLEAR_STATS      0x6

/* command for setting the speed, duplex & autoneg */
#define   OCTNET_CMD_SET_SETTINGS     0x7
#define   OCTNET_CMD_SET_FLOW_CTL     0x8

#define   OCTNET_CMD_MDIO_READ_WRITE  0x9

/* RX(packets coming from wire) Checksum verification flags */
/* TCP/UDP csum */
#define   CNNIC_L4SUM_VERIFIED             0x1
#define   CNNIC_IPSUM_VERIFIED             0x2
#define   CNNIC_CSUM_VERIFIED              (CNNIC_IPSUM_VERIFIED | CNNIC_L4SUM_VERIFIED)

/* Interface flags communicated between host driver and core app. */
typedef enum {
	OCTNET_IFFLAG_PROMISC = 0x1,
	OCTNET_IFFLAG_ALLMULTI = 0x2,
	OCTNET_IFFLAG_MULTICAST = 0x4
} octnet_ifflags_t;

/*
   wqe
   ---------------  0
 |  wqe  word0-3 |
   ---------------  32
 |    PCI IH     |
   ---------------  40
 |     RPTR      |
   ---------------  48
 |    PCI IRH     |
   ---------------  56
 |  OCT_NET_CMD  |
   ---------------  64
 | Addtl 8-BData |
 |               |
   ---------------
 */

typedef union {

	uint64_t u64;

	struct {

#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
		uint64_t cmd:5;

		uint64_t more:3;

		uint64_t param1:32;

		uint64_t param2:16;

		uint64_t param3:8;

#else

		uint64_t param3:8;

		uint64_t param2:16;

		uint64_t param1:32;

		uint64_t more:3;

		uint64_t cmd:5;

#endif
	} s;

} octnet_cmd_t;

#define   OCTNET_CMD_SIZE     (sizeof(octnet_cmd_t))

/** Status of a RGMII Link on Octeon as seen by core driver. */
typedef union {

	uint64_t u64;

	struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
		uint64_t reserved:6;
		uint64_t pause:1;
		uint64_t interface:4;
		uint64_t autoneg:1;
		uint64_t speed:20;
		uint64_t mtu:16;
		uint64_t status:8;
		uint64_t duplex:8;
#else
		uint64_t duplex:8;
		uint64_t status:8;
		uint64_t mtu:16;
		uint64_t speed:20;
		uint64_t autoneg:1;
		uint64_t interface:4;
		uint64_t pause:1;
		uint64_t reserved:4;
#endif
	} s;
} oct_link_status_t;

/** Information for a OCTEON ethernet interface shared between core & host. */
typedef struct {

	oct_link_status_t link;

	uint64_t hw_addr;

#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	uint8_t ifidx;
	/* the starting ioq index in rx/txpciq[ ] that host octnic driver starts creating IOQs for each octX link */
	uint8_t num_rxpciq;
	uint8_t num_txpciq;
	uint8_t rsvd[3];
	uint16_t gmxport;
#else
	uint16_t gmxport;
	uint8_t rsvd[3];
	uint8_t num_txpciq;
	uint8_t num_rxpciq;
	uint8_t ifidx;
#endif

	uint8_t txpciq[MAX_IOQS_PER_NICIF];
	uint8_t rxpciq[MAX_IOQS_PER_NICIF];
} oct_link_info_t;

#define OCT_LINK_INFO_SIZE   (sizeof(oct_link_info_t))
typedef struct {
	uint64_t pcieport;

	uint64_t status_len;

	uint64_t stats_len;

	uint64_t status_addr;

	uint64_t stats_addr;
} oct_stats_dma_info_t;

/** Stats for each NIC port in RX direction. */
struct nic_rx_stats_t {
	/* link-level stats */
	uint64_t total_rcvd;
	uint64_t bytes_rcvd;
	uint64_t ctl_rcvd;
	uint64_t fifo_err;	/* Accounts for over/under-run of buffers */
	uint64_t dmac_drop;
	uint64_t fcs_err;
	uint64_t jabber_err;
	uint64_t l2_err;
	uint64_t frame_err;
	uint64_t total_bcst;
	uint64_t runts;

	/* firmware stats */
	uint64_t fw_total_rcvd;
	uint64_t fw_total_fwd;
	uint64_t fw_err_pko;
	uint64_t fw_err_link;
	uint64_t fw_err_drop;
	uint64_t fw_total_drop;
};

/** Stats for each NIC port in RX direction. */
struct nic_tx_stats_t {
	/* link-level stats */
	uint64_t total_rcvd;
	uint64_t bytes_rcvd;
	uint64_t ctl_rcvd;
	uint64_t fifo_err;	/* Accounts for over/under-run of buffers */
	uint64_t runts;
	uint64_t collision;

	/* firmware stats */
	uint64_t fw_total_rcvd;
	uint64_t fw_total_fwd;
	uint64_t fw_err_pko;
	uint64_t fw_err_link;
	uint64_t fw_err_drop;
};

typedef struct {

	struct nic_rx_stats_t fromwire;
	struct nic_tx_stats_t fromhost;

} oct_link_stats_t;

#define OCT_LINK_STATS_SIZE   (sizeof(oct_link_stats_t))

#endif

/* $Id: octeon-nic-common.h 170605 2018-03-20 15:19:22Z vvelumuri $ */
