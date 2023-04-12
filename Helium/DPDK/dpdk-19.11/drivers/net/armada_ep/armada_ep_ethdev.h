/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Marvell International Ltd.
 * Copyright(c) 2017 Semihalf.
 * All rights reserved.
 */

#ifndef _ARMADA_EP_ETHDEV_H_
#define _ARMADA_EP_ETHDEV_H_

#include <rte_ethdev.h>
#include <rte_atomic.h>
#include <rte_io.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <rte_ether.h>
#include <rte_common.h>

#include "armada_ep_hw.h"

typedef uint64_t dma_addr_t;

/* Config */
#define MRVL_COOKIE_ADDR_INVALID ~0ULL

/* Armada EP driver configuration modes:
 * Armada EP driver run on PCIe device. Define the below modes for other usage:
 *
 * ARMADA_EP_VDEV_MODE - will be run with virtual device, and virtual PCI BAR
 *			 (PCI BAR will be virtually mapped).
 * ARMADA_EP_STANDALONE_VDEV_MODE - will be run with with virtual device,
 *				    without PCI bar and without management
 *				    queues and commands.
 * ARMADA_EP_LOOPBACK_MODE - if define, the tx descs will virtually transmite
 *			     to rx descs. Can be define with PCI mode,
 *			     ARMADA_EP_VDEV_MODE, ARMADA_EP_STANDALONE_VDEV_MODE
 */
#define ARMADA_EP_VDEV_MODE 0
#define ARMADA_EP_STANDALONE_VDEV_MODE 0
#define ARMADA_EP_LOOPBACK_MODE 0

/* Log */
#define ARMADA_EP_LOG(level, fmt, args...) (rte_log(RTE_LOG_##level, \
				RTE_LOGTYPE_PMD, "%s(): " fmt "\n", \
				__func__, ##args))

//TODO: Add prints for debug - log level debug
//TODO: Maybe need to remove ARMADA_EP_DEBUG_SESSION from this h and add it to
//      armada_ep_debug.h
#define ARMADA_EP_DEBUG_SESSION(fmt, args...) ARMADA_EP_LOG(ERR, \
				"\t\tAEP_DEBUG\t\t" fmt, ##args)

/* valid arguments */
#define ARMADA_EP_IFACE_NAME_ARG "iface"
static const char *const valid_args[] = {ARMADA_EP_IFACE_NAME_ARG, NULL};

/*
 * memory access primitives. Reads are ordered relative to any
 * following Normal memory access. Writes are ordered relative to any prior
 * Normal memory access.
 */
#define readl(c) (rte_read32(c))
#define readl_relaxed(c) (rte_read32_relaxed(c))

#define writel(v, c) (rte_write32((v), (c)))
#define writel_relaxed(v, c) (rte_write32_relaxed((v), (c)))

/* PCIe BAR */

#if ARMADA_EP_VDEV_MODE
#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

//TODO: need to verify that this PCI_EP_VF_BAR_ADDR_BASE const or we need to
//      ask for it in run time
#define PCI_EP_VF_BAR_ADDR_BASE		0x138d80000
#define PCI_EP_VF_BAR_SIZE		0x1000
#define PCI_EP_VF_BAR_ADDR(id)		(PCI_EP_VF_BAR_ADDR_BASE + (id) * \
					PCI_EP_VF_BAR_SIZE)
#endif

#define ARMADA_EP_BASE_FUNCTION_ID 2

#define TIMEOUT_INIT 1000 /* ~1 second. */

/* capabilities */
#define ARMADA_EP_RX_OFFLOADS	(DEV_RX_OFFLOAD_CHECKSUM) /* Rx cksum offload */
#define ARMADA_EP_TX_OFFLOADS	0			  /* Tx cksum offload */
#define ARMADA_EP_BURST_SIZE	64
#define ARMADA_EP_PKT_EFFEC_OFFS 0
#define ARMADA_EP_MAC_ADDRS_MAX	1

/* Scatter/Gather*/
#define ARMADA_EP_MAX_SG_SEGMENTS	33

/* descriptors amount and alignment */
#define ARMADA_EP_RXD_MAX	16384	/** Max number of descs in rx queue */
#define ARMADA_EP_RXD_MIN	64	/** Min number of descs in rx queue */
#define ARMADA_EP_RXD_ALIGN	16	/** Rx queue descs alignment */
#define ARMADA_EP_TXD_MAX	16384	/** Max number of descs in tx queue */
#define ARMADA_EP_TXD_MIN	64	/** Min number of descs in tx queue */
#define ARMADA_EP_TXD_ALIGN	16	/** Tx queue descs alignment */

/** Minimum number of sent buffers to release from shadow queue to BM */
#define ARMADA_EP_BUF_RELEASE_BURST_SIZE	64

/* Trafic classes capabilities */
#define ARMADA_EP_MAX_NUM_TCS		1 /**< Max. number of TCs per vf. */
#define ARMADA_EP_MAX_NUM_QS_PER_TC	1 /**< Max. number of Qs per TC. */

#define ARMADA_EP_MAX_QUEUES	\
	(ARMADA_EP_MAX_NUM_QS_PER_TC * ARMADA_EP_MAX_NUM_TCS)
#define ARMADA_EP_MAX_RXQ_COUNT		(ARMADA_EP_MAX_QUEUES)
#define ARMADA_EP_MAX_TXQ_COUNT		(ARMADA_EP_MAX_QUEUES)
#define ARMADA_EP_MAX_BPOOLS_COUNT	(ARMADA_EP_MAX_RXQ_COUNT)
#define ARMADA_EP_MAX_NOTIFQ_COUNT	(1)
#define ARMADA_EP_MAX_CMDQ_COUNT	(1)

/* prefetch shift */
#define ARMADA_EP_PREFETCH_SHIFT 2

/* Queue index increment */

static inline uint32_t
armada_ep_q_index_inc(uint32_t index_val, uint16_t inc_val, uint32_t q_sz)
{
	return ((index_val + inc_val) & (q_sz - 1));
}

/* Calc the queue oocupied descriptors num - cons to prod gap
 * Since queue size is a power of 2, we can use the below formula.
 */
static inline uint32_t
armada_ep_q_num_occupied(uint32_t prod, uint32_t cons, uint32_t q_sz)
{
	return ((prod - cons + q_sz) & (q_sz - 1));
}

/* Calc the queue space  - prod to cons gap */
static inline uint32_t
armada_ep_q_space(uint32_t prod, uint32_t cons, uint32_t q_sz)
{
	return (q_sz - armada_ep_q_num_occupied(prod, cons, q_sz) - 1);
}

/* Calc physical address of a local producer / consumer pointer. */
static inline int
armada_ep_q_indx_local_phys(dma_addr_t q_indices_arr_phys, uint8_t indx)
{
	return (q_indices_arr_phys + (indx * sizeof(uint32_t)));
}

#ifdef RTE_EAL_VFIO
/* Rx interrupts functions */
int armada_ep_rx_queue_intr_enable(struct rte_eth_dev *eth_dev,
				   uint16_t rx_queue_id);

int armada_ep_rx_queue_intr_disable(struct rte_eth_dev *eth_dev,
				    uint16_t rx_queue_id);

int armada_ep_register_queue_irqs(struct rte_eth_dev *eth_dev);
#endif /* RTE_EAL_VFIO */


/*
 * ############################
 * #       HW Descriptor      #
 * ############################
 */


#define ARMADA_EP_DESC_NUM_WORDS 8

struct armada_ep_desc {
	uint32_t cmds[ARMADA_EP_DESC_NUM_WORDS];
};


/******** RXQ-Desc ********/
/* cmd 0 */
#define ARMADA_EP_RXD_L3_OFF_MASK		(0x0000007F)
#define ARMADA_EP_RXD_DP_MASK			(0x00000080)
#define ARMADA_EP_RXD_IPHDR_LEN_MASK		(0x00001F00)
#define ARMADA_EP_RXD_L4_STATUS_MASK		(0x00006000)
#define ARMADA_EP_RXD_FORMAT_MASK		(0x00180000)
#define ARMADA_EP_RXD_MD_MODE_MASK		(0x00400000)
#define ARMADA_EP_RXD_IPV4_STATUS_MASK		(0x01800000)
#define ARMADA_EP_RXD_L4_INFO_MASK		(0x0E000000)
#define ARMADA_EP_RXD_L3_INFO_MASK		(0x70000000)
/* cmd 1 */
#define ARMADA_EP_RXD_PKT_OFF_MASK		(0x000000FF)
#define ARMADA_EP_RXD_L3_CAST_INFO_MASK		(0x00000C00)
#define ARMADA_EP_RXD_L2_CAST_INFO_MASK		(0x00003000)
#define ARMADA_EP_RXD_VLAN_INFO_MASK		(0x0000C000)
#define ARMADA_EP_RXD_BYTE_COUNT_MASK		(0xFFFF0000)
/* cmd 2 */
#define ARMADA_EP_RXD_PORT_NUM_MASK		(0x0000E000)
#define ARMADA_EP_RXD_NUM_SG_ENT_MASK		(0x001F0000)
/* cmd 4 */
#define ARMADA_EP_RXD_BUF_PHYS_LO_MASK		(0xFFFFFFFF)
/* cmd 5 */
#define ARMADA_EP_RXD_BUF_PHYS_HI_MASK		(0xFFFFFFFF)
/* cmd 6 */
#define ARMADA_EP_RXD_BUF_COOKIE_LO_MASK	(0xFFFFFFFF)
/* cmd 7 */
#define ARMADA_EP_RXD_BUF_COOKIE_HI_MASK	(0xFFFFFFFF)


/******** TXQ-Desc ********/
/* cmd 0 */
#define ARMADA_EP_TXD_L3_OFF_MASK		(0x0000007F)
#define ARMADA_EP_TXD_IPHDR_LEN_MASK		(0x00001F00)
#define ARMADA_EP_TXD_GL4CHK_DISABLE_MASK	(0x00004000)
#define ARMADA_EP_TXD_GIPCHK_DISABLE_MASK	(0x00008000)
#define ARMADA_EP_TXD_MD_MODE_MASK		(0x00400000)
#define ARMADA_EP_TXD_L4_INFO_MASK		(0x03000000)
#define ARMADA_EP_TXD_L3_INFO_MASK		(0x0C000000)
#define ARMADA_EP_TXD_FORMAT_MASK		(0x30000000)
/* cmd 1 */
#define ARMADA_EP_TXD_PKT_OFF_MASK		(0x000000FF)
#define ARMADA_EP_TXD_VLAN_INFO_MASK		(0x0000C000)
#define ARMADA_EP_TXD_BYTE_COUNT_MASK		(0xFFFF0000)
/* cmd 2*/
#define ARMADA_EP_TXD_NUM_SG_ENT_MASK		(0x001F0000)
/* cmd 4 */
#define ARMADA_EP_TXD_BUF_PHYS_LO_MASK		(0xFFFFFFFF)
/* cmd 5 */
#define ARMADA_EP_TXD_BUF_PHYS_HI_MASK		(0xFFFFFFFF)
/* cmd 6 */
#define ARMADA_EP_TXD_BUF_VIRT_LO_MASK		(0xFFFFFFFF)
/* cmd 7 */
#define ARMADA_EP_TXD_BUF_VIRT_HI_MASK		(0xFFFFFFFF)

/* Descriptor position, used for Scatter/Gather */
enum armada_ep_format {
	ARMADA_EP_NONE_FORMAT = 0,	/* S/G segment that is not first */
	ARMADA_EP_INDIRECT_SG,		/* S/G first segment, indirect method */
	ARMADA_EP_DIRECT_SG,		/* S/G first segment, direct method */
	ARMADA_EP_NON_SG		/* Single entry - not S/G desc */
};

/* Rx - INQ */
#define ARMADA_EP_ARP_LENGTH 28 /* used for calculate l4 offset in ARP case */

enum armada_ep_inq_l3_type {
	ARMADA_EP_INQ_L3_TYPE_NA = 0,
	ARMADA_EP_INQ_L3_TYPE_IPV4_NO_OPTS,	/* IPv4 with IHL=5, TTL>0 */
	ARMADA_EP_INQ_L3_TYPE_IPV4_OK,		/* IPv4 with IHL>5, TTL>0 */
	ARMADA_EP_INQ_L3_TYPE_IPV4_TTL_ZERO,	/* Other IPV4 packets */
	ARMADA_EP_INQ_L3_TYPE_IPV6_NO_EXT,	/* IPV6 without extensions */
	ARMADA_EP_INQ_L3_TYPE_IPV6_EXT,	/* IPV6 with extensions */
	ARMADA_EP_INQ_L3_TYPE_ARP,		/* ARP */
	ARMADA_EP_INQ_L3_TYPE_USER_DEFINED	/* User defined */
};

enum armada_ep_inq_l4_type {
	ARMADA_EP_INQ_L4_TYPE_NA = 0,		/* N/A */
	ARMADA_EP_INQ_L4_TYPE_TCP,		/* L4 TCP*/
	ARMADA_EP_INQ_L4_TYPE_UDP,		/* L4 UDP*/
	ARMADA_EP_INQ_L4_TYPE_USER_DEFINED	/* User defined*/
};

enum armada_ep_inq_l2_cast_type {
	ARMADA_EP_INQ_L2_UNICAST = 0,		/* L2 Unicast */
	ARMADA_EP_INQ_L2_MULTICAST,		/* L2 Multicast */
	ARMADA_EP_INQ_L2_BROADCAST,		/* L2 Broadcast */
	ARMADA_EP_INQ_L2_RESERVED		/* Reserved */
};

enum armada_ep_inq_l3_cast_type {
	ARMADA_EP_INQ_L3_UNICAST = 0,		/* L3 Unicast */
	ARMADA_EP_INQ_L3_MULTICAST,		/* L3 Multicast */
	ARMADA_EP_INQ_L3_ANYCAST,		/* L3 Anycast */
	ARMADA_EP_INQ_L3_BROADCAST,		/* L3 Broadcast */
};

enum armada_ep_inq_vlan_tag {
	ARMADA_EP_INQ_VLAN_TAG_NONE = 0,	/* No VLANs */
	ARMADA_EP_INQ_VLAN_TAG_SINGLE,		/* Single VLAN */
	ARMADA_EP_INQ_VLAN_TAG_DOUBLE,		/* Double VLANs */
	ARMADA_EP_INQ_VLAN_TAG_RESERVED,	/* Reserved */
};

enum armada_ep_inq_l4_status {
	ARMADA_EP_INQ_L4_CSUM_OK = 0,		/* Ok (good) */
	ARMADA_EP_INQ_L4_CSUM_ERR,		/* L4 checksum Err (bad) */
	ARMADA_EP_INQ_L4_CSUM_UNKNOWN,		/* L4 checksum Unknown */
	ARMADA_EP_INQ_L4_CSUM_RESERVED		/* Reserved*/
};

enum armada_ep_inq_ipv4_status {
	ARMADA_EP_INQ_IPV4_CSUM_OK = 0,		/* Ok (good)*/
	ARMADA_EP_INQ_IPV4_CSUM_ERR,		/* IPv4 checksum Err (bad) */
	ARMADA_EP_INQ_IPV4_CSUM_UNKNOWN,	/* IPv4 checksum Unknown */
	ARMADA_EP_INQ_IPV4_CSUM_RESERVED,	/* Reserved */
};


/* Tx - OUTQ */
enum armada_ep_outq_l3_type {
	ARMADA_EP_OUTQ_L3_TYPE_IPV4 = 0,	/* IPv4 */
	ARMADA_EP_OUTQ_L3_TYPE_IPV6,		/* IPv6 */
	ARMADA_EP_OUTQ_L3_TYPE_OTHER		/* Other */
};

enum armada_ep_outq_l4_type {
	ARMADA_EP_OUTQ_L4_TYPE_TCP = 0,		/* L4 TCP*/
	ARMADA_EP_OUTQ_L4_TYPE_UDP,		/* L4 UDP*/
	ARMADA_EP_OUTQ_L4_TYPE_RESERVED		/* Reserved*/
};

enum armada_ep_outq_vlan_tag {
	ARMADA_EP_OUTQ_VLAN_TAG_NONE = 0,	/* No VLANs */
	ARMADA_EP_OUTQ_VLAN_TAG_SINGLE,		/* Single VLAN */
	ARMADA_EP_OUTQ_VLAN_TAG_DOUBLE,		/* Double VLANs */
	ARMADA_EP_OUTQ_VLAN_TAG_RESERVED	/* Reserved */
};

/* Generate IPv4 header checksum options */
enum armada_ep_outq_gipchk_disable {
	ARMADA_EP_OUTQ_GIPCHK_ENABLE = 0,	/* Generate checksum */
	ARMADA_EP_OUTQ_GIPCHK_DISABLE		/* Don't generate checksum */
};

/* Generate TCP/UDP checksum option*/
enum armada_ep_outq_gl4chk_disable {
	ARMADA_EP_OUTQ_GL4CHK_ENABLE = 0,	/* Generate Checksum */
	ARMADA_EP_OUTQ_GL4CHK_DISABLE,		/* Don't generate checksum */
};

//TODO: in the future: add rss support
enum armada_ep_hash_type {
	ARMADA_EP_HASH_T_NONE = 0, /* Invalid hash type */
	ARMADA_EP_HASH_T_2_TUPLE,  /* IP-src, IP-dst */
	ARMADA_EP_HASH_T_5_TUPLE,  /* IP-src, IP-dst, IP-Prot, L4-src, L4-dst */
	ARMADA_EP_HASH_T_OUT_OF_RANGE
};

/*
 * ############################
 * #         HW structs       #
 * ############################
 */

/* queue type */
enum armada_ep_queue_type {
	ARMADA_EP_RX_QUEUE = 0, /* Invalid hash type */
	ARMADA_EP_TX_QUEUE, /* IP-src, IP-dst */
	ARMADA_EP_CMD_QUEUE, /* IP-src, IP-dst, IP-Prot, L4-src, L4-dst */
	ARMADA_EP_NOTIF_QUEUE,
	ARMADA_EP_BPOOL_QUEUE,
};

struct armada_ep_queue {
	uint32_t *prod_p;
	uint32_t *cons_p;
	uint32_t last_tx_cons_val; /* last tx consumer val */

	const struct rte_memzone *q_memzone;
	void *desc;
	uint64_t dma;
	uint32_t count; /*queue len - amount of descriptors in the ring*/

	struct armada_ep_priv *priv;

	enum armada_ep_queue_type queue_type;
	uint32_t desc_size;

	uint8_t prod_idx; /* IDX for MNP update*/
	uint8_t cons_idx; /* IDX for MNP update*/
	uint8_t tc;
	uint8_t queue_idx;

	uint32_t intr_vec; /* ARMADA_EP_MGMT_MSIX_ID_INVALID disable MSI-X */

	uint32_t bp_frag_size;

	/* Cookie list for management queues only */
	struct armada_ep_mgmt_cookie *mgmt_cookie_list;
	uint32_t cookie_count;
};

/*
 * ############################
 * #         SW structs       #
 * ############################
 */


/*
 * To use buffer harvesting based on loopback port shadow queue structure
 * was introduced for buffers information bookkeeping.
 *
 * Before sending the packet, related buffer information (armada_ep_bpool_desc)
 * is stored in shadow queue. After packet is transmitted no longer used
 * packet buffer is released back to it's original hardware pool,
 * on condition it originated from interface.
 * In case it  was generated by application itself i.e: mbuf->port field is
 * 0xff then its released to software mempool.
 */
struct armada_ep_shadow_txq {
	uint16_t head;           /* write index - used when sending buffers */
	uint16_t tail;           /* read index - used when releasing buffers */
	uint16_t size;           /* queue occupied size */
	uint16_t num_to_release; /* num of buffers sent, that can be released */
	uint16_t total_size;     /* the shadow-q total size */
	uint16_t res;
	/* the queue-entries MUST be of type 'giu_buff_inf' as there is an
	 * assumption it is continuous when it is used in 'giu_bpool_put_buffs'
	 */
	struct armada_ep_bpool_desc *ent;
	struct armada_ep_desc *descs;
};


struct armada_ep_rxq {
	struct armada_ep_priv *priv;
	struct rte_mempool *mp;
	uint32_t size;
	int queue_id;
	int port_id;
	int cksum_enabled;
	uint64_t bytes_recv;
	uint64_t packets_recv;
	uint16_t data_offset; /* Offset of the data within the buffer */
};

struct armada_ep_txq {
	struct armada_ep_priv *priv;
	int queue_id;
	int port_id;
	uint64_t bytes_sent;
	uint64_t packets_sent;
	struct armada_ep_shadow_txq shadow_txq;
	int tx_deferred_start;
	uint32_t size;
};

#define ARMADA_EP_IFACE_NUM 7 /**< Maximum number of interfaces */

struct armada_ep_ifnames {
	const char *names[ARMADA_EP_IFACE_NUM];
	int idx;
};

struct armada_ep_intc {
	uint8_t num_queues;
	uint16_t buff_size;
	uint16_t pkt_offset;

	struct armada_ep_queue *queues[ARMADA_EP_MAX_NUM_QS_PER_TC];
	struct armada_ep_queue *bp_qs[ARMADA_EP_MAX_NUM_QS_PER_TC];
};

struct armada_ep_outtc {
	uint8_t num_queues;

	struct armada_ep_queue *queues[ARMADA_EP_MAX_NUM_QS_PER_TC];
};


struct armada_ep_priv {
	int id;
	struct armada_ep_intc in_tcs[ARMADA_EP_MAX_NUM_TCS];
	struct armada_ep_outtc out_tcs[ARMADA_EP_MAX_NUM_TCS];

	/* Tx - one ring per active queue */
	uint16_t num_tx_queues;
	uint16_t tx_queue_size;
	struct armada_ep_queue *tx_queue[ARMADA_EP_MAX_TXQ_COUNT];

	/* Rx */
	uint16_t num_rx_queues;
	uint16_t rx_queue_size;
	struct armada_ep_queue *rx_queue[ARMADA_EP_MAX_RXQ_COUNT];

	/* BP */
	uint16_t num_rx_pools;
	uint16_t buff_size;
	uint16_t pkt_offset;
	rte_spinlock_t bp_lock;
	uint16_t bp_min_size;  /**< BPool minimum size  */
	uint16_t bp_init_size; /**< Configured BPool size  */
	struct armada_ep_queue bp_queue[ARMADA_EP_MAX_BPOOLS_COUNT];

	uint8_t num_in_tcs;
	uint8_t num_out_tcs;
	uint8_t num_qs_per_tc;

	/* rings indices array */
	uint32_t *q_indices_arr;
	dma_addr_t q_indices_arr_phys;
	uint32_t q_indices_arr_len;

	struct armada_ep_config_mem	*nic_cfg;

	uint8_t mac[RTE_ETHER_ADDR_LEN];

	/* Management command & notification Rings. */
	struct armada_ep_queue cmd_queue;
	struct armada_ep_queue notif_queue;
	rte_spinlock_t mgmt_lock;

	int32_t link;
	uint8_t dev_initialized;

	/* rss */
	enum armada_ep_hash_type hash_type;

	/* capabilities */
	struct armada_ep_mgmt_capabilities pf_vf_capabilities;
};



#endif /* _ARMADA_EP_ETHDEV_H_ */
