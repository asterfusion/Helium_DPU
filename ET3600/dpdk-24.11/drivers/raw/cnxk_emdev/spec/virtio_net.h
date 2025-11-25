/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell
 */

#ifndef __INCLUDE_VIRTIO_NET_H__
#define __INCLUDE_VIRTIO_NET_H__

/** The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM	    0  /** Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM	    1  /** Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MTU	    3  /** Initial MTU advice. */
#define VIRTIO_NET_F_MAC	    5  /** Host has given MAC address. */
#define VIRTIO_NET_F_GUEST_TSO4	    7  /** Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6	    8  /** Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN	    9  /** Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO	    10 /** Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4	    11 /** Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6	    12 /** Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN	    13 /** Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO	    14 /** Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF	    15 /** Host can merge receive buffers. */
#define VIRTIO_NET_F_STATUS	    16 /** virtio_net_config.status available */
#define VIRTIO_NET_F_CTRL_VQ	    17 /** Control channel available */
#define VIRTIO_NET_F_CTRL_RX	    18 /** Control channel RX mode support */
#define VIRTIO_NET_F_CTRL_VLAN	    19 /** Control channel VLAN filtering */
#define VIRTIO_NET_F_CTRL_RX_EXTRA  20 /** Extra RX mode control support */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21 /** Guest can announce device on the network */
#define VIRTIO_NET_F_MQ		    22 /** Device supports Receive Flow Steering */
#define VIRTIO_NET_F_CTRL_MAC_ADDR  23 /** Set MAC address */
#define VIRTIO_NET_F_HASH_REPORT    57 /** Set HASH REPORT */
#define VIRTIO_NET_F_GUEST_HDRLEN   59 /** Guest provides the exact hdr_len value .*/
#define VIRTIO_NET_F_RSS	    60 /** RSS supported */
#define VIRTIO_NET_F_SPEED_DUPLEX   63 /** Device set linkspeed and duplex */

/**  Virtio RSS hash types */
#define VIRTIO_NET_HASH_TYPE_IPV4   RTE_BIT32(0)
#define VIRTIO_NET_HASH_TYPE_TCPV4  RTE_BIT32(1)
#define VIRTIO_NET_HASH_TYPE_UDPV4  RTE_BIT32(2)
#define VIRTIO_NET_HASH_TYPE_IPV6   RTE_BIT32(3)
#define VIRTIO_NET_HASH_TYPE_TCPV6  RTE_BIT32(4)
#define VIRTIO_NET_HASH_TYPE_UDPV6  RTE_BIT32(5)
#define VIRTIO_NET_HASH_TYPE_IP_EX  RTE_BIT32(6)
#define VIRTIO_NET_HASH_TYPE_TCP_EX RTE_BIT32(7)
#define VIRTIO_NET_HASH_TYPE_UDP_EX RTE_BIT32(8)

#define VIRTIO_NET_HASH_TYPE_MASK                                                                  \
	(VIRTIO_NET_HASH_TYPE_IPV4 | VIRTIO_NET_HASH_TYPE_TCPV4 | VIRTIO_NET_HASH_TYPE_UDPV4 |     \
	 VIRTIO_NET_HASH_TYPE_IPV6 | VIRTIO_NET_HASH_TYPE_TCPV6 | VIRTIO_NET_HASH_TYPE_UDPV6 |     \
	 VIRTIO_NET_HASH_TYPE_IP_EX | VIRTIO_NET_HASH_TYPE_TCP_EX | VIRTIO_NET_HASH_TYPE_UDP_EX)

#define VIRTIO_NET_ETHER_ADDR_LEN 6
struct virtio_net_ctrl_rss;

struct virtio_net_config {
#define VIRTIO_NET_ETHER_ADDR_LEN 6
	/** The config defining mac address (if VIRTIO_NET_F_MAC) */
	uint8_t mac[VIRTIO_NET_ETHER_ADDR_LEN];
	/** See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
#define VIRTIO_NET_S_LINK_UP  1
#define VIRTIO_NET_S_ANNOUNCE 2
	uint16_t status;
	/** Max virtio queue pairs */
	uint16_t max_virtqueue_pairs;
	/** MTU supported */
	uint16_t mtu;
	/**
	 * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
	 * Any other value stands for unknown.
	 */
	uint32_t speed;
	/**
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	uint8_t duplex;
	/** RSS key size max */
	uint8_t rss_max_key_size;
	/** RSS table size max */
	uint16_t rss_max_indirection_table_length;
	/** Supported hash types */
	uint32_t supported_hash_types;
} __rte_packed;

struct virtio_net_hdr {
#define VIRTIO_NET_HDR_F_NEEDS_CSUM 1
#define VIRTIO_NET_HDR_F_DATA_VALID 2
#define VIRTIO_NET_HDR_F_RSC_INFO   4
	/** Packet flags */
	uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE	  0
#define VIRTIO_NET_HDR_GSO_TCPV4  1
#define VIRTIO_NET_HDR_GSO_UDP	  3
#define VIRTIO_NET_HDR_GSO_TCPV6  4
#define VIRTIO_NET_HDR_GSO_UDP_L4 5
#define VIRTIO_NET_HDR_GSO_ECN	  0x80
	/** Packet GSO type */
	uint8_t gso_type;
	/** Packet header length */
	rte_le16_t hdr_len;
	/** Packet GSO size */
	rte_le16_t gso_size;
	/** Packet csum start offset */
	rte_le16_t csum_start;
	/** Packet csum update offset */
	rte_le16_t csum_offset;
	/** Number of buffers of packet */
	rte_le16_t num_buffers;
	/** hash value of packet */
	rte_le32_t hash_value;
#define VIRTIO_NET_HASH_REPORT_NONE	0
#define VIRTIO_NET_HASH_REPORT_IPv4	1
#define VIRTIO_NET_HASH_REPORT_TCPv4	2
#define VIRTIO_NET_HASH_REPORT_UDPv4	3
#define VIRTIO_NET_HASH_REPORT_IPv6	4
#define VIRTIO_NET_HASH_REPORT_TCPv6	5
#define VIRTIO_NET_HASH_REPORT_UDPv6	6
#define VIRTIO_NET_HASH_REPORT_IPv6_EX	7
#define VIRTIO_NET_HASH_REPORT_TCPv6_EX 8
#define VIRTIO_NET_HASH_REPORT_UDPv6_EX 9
	/** hash report of packet */
	rte_le16_t hash_report;
	/** padding reserved of packet */
	rte_le16_t padding_reserved;
} __rte_packed;

#define VIRTIO_NET_CTRL_MQ 4
/** For automatic receive steering */
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET 0
/** For configurable receive steering */
#define VIRTIO_NET_CTRL_MQ_RSS_CONFIG 1
/** For configurable hash calculation */
#define VIRTIO_NET_CTRL_MQ_HASH_CONFIG 2

#define VIRTIO_NET_RSS_RETA_SIZE 128
#define VIRTIO_NET_RSS_KEY_SIZE	 40

/** RSS control command */
struct virtio_net_ctrl_rss {
	/** Hash types */
	uint32_t hash_types;
	/** Indirection table mask */
	uint16_t indirection_table_mask;
	/** Unclassified queue */
	uint16_t unclassified_queue;
	/** Indirection table */
	uint16_t indirection_table[VIRTIO_NET_RSS_RETA_SIZE];
	/** Max Tx VQ */
	uint16_t max_tx_vq;
	/** Hash key length */
	uint8_t hash_key_length;
	/** Hash key data */
	uint8_t hash_key_data[VIRTIO_NET_RSS_KEY_SIZE];
};

/** Virito NET Rx control command */
#define VIRTIO_NET_CTRL_RX	    0
#define VIRTIO_NET_CTRL_RX_PROMISC  0
#define VIRTIO_NET_CTRL_RX_ALLMULTI 1

/** MAC control command */
struct virtio_net_ctrl_mac {
	/** MAC address entries */
	uint32_t entries;
	/** Array of MAC addresses */
	uint8_t macs[][VIRTIO_NET_ETHER_ADDR_LEN];
};

/** Virtio NET MAC control command */
#define VIRTIO_NET_CTRL_MAC	      1
#define VIRTIO_NET_CTRL_MAC_TABLE_SET 0
#define VIRTIO_NET_CTRL_MAC_ADDR_SET  1

/** VLAN control command */
struct virtio_net_ctrl_vlan {
	/** PCP(3) + DEI(1) + VLAN ID(12) */
	uint16_t tci;
};

/** Virtio NET VLAN control command */
#define VIRTIO_NET_CTRL_VLAN	 2
#define VIRTIO_NET_CTRL_VLAN_ADD 0
#define VIRTIO_NET_CTRL_VLAN_DEL 1

/** Virtio control command ack value */
#define VIRTIO_NET_OK  0
#define VIRTIO_NET_ERR 1
typedef uint8_t virtio_net_ctrl_ack;

/** CTRL_VQ command */
struct virtio_net_ctrl {
	/** Control command class */
	uint8_t class;
	/** Control command */
	uint8_t command;
	/** Control command data */
	uint8_t data[];
};
#endif /* __INCLUDE_VIRTIO_NET_H__ */
