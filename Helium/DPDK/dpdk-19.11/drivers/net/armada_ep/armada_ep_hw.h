/******************************************************************************
 *  Copyright (C) 2018 Marvell International Ltd.
 *
 *  This program is provided "as is" without any warranty of any kind, and is
 *  distributed under the applicable Marvell limited use license agreement.
 ******************************************************************************/

#ifndef __ARMADA_EP_HW_H__
#define __ARMADA_EP_HW_H__

#include "armada_ep_common.h"

/*
 * Configuration space definition
 */

/*
 * Configuration structure defined by the device, and used for
 * initial communication between the host driver (armada_ep) and the NPU.
 * The below is still preliminary, till we finalize the interface between
 * the host and the NIC.
 * - q_addr: Physical address of the queue in host's memory.
 * - q_prod_offs: Producer offset from BAR.
 * - q_cons_offs: Consumer offset from BAR.
 * - len: Number of elements in the queue.
 */
struct armada_ep_q_hw_info {
	u64	q_addr;
	u32	q_prod_offs;
	u32	q_cons_offs;
	u32	len;
	u32	res;
} __attribute__((packed));

#define ARMADA_EP_MSIX_NUM		128
#define ARMADA_EP_MSIX_MASK_SIZE	32
#define ARMADA_EP_MSIX_GET_MASK_ARR_INDEX(msix_id) \
	((msix_id) / ARMADA_EP_MSIX_MASK_SIZE)
#define ARMADA_EP_MSIX_GET_MASK(msix_id) \
	(BIT((msix_id) % ARMADA_EP_MSIX_MASK_SIZE))

struct armada_ep_config_mem {
#define ARMADA_EP_CFG_STATUS_DEV_READY		(1 << 0)
#define ARMADA_EP_CFG_STATUS_HOST_MGMT_READY	(1 << 1)
#define ARMADA_EP_CFG_STATUS_DEV_MGMT_READY	(1 << 2)
#define ARMADA_CFG_STATUS_HOST_MGMT_CLOSE_REQ	(1 << 29)
#define ARMADA_CFG_STATUS_HOST_MGMT_CLOSE_DONE	(1 << 30)
#define ARMADA_EP_CFG_STATUS_HOST_RESET		(1 << 31)

	u32	status;
	u8	mac_addr[6];
	u8	res1[6];
	struct armada_ep_q_hw_info cmd_q;
	struct armada_ep_q_hw_info notif_q;
	u8	res2[24];

	u32	dev_use_size;
	/* MSI-X table offset at BAR0 */
	u32     msi_x_tbl_offset;
	u32	msi_x_mask[ceil(ARMADA_EP_MSIX_NUM, ARMADA_EP_MSIX_MASK_SIZE)];

	u8	res3[896]; /* complete to 1KB */
} __attribute__((packed));

/*
 * Management descriptors definitions.
 */

#define ARMADA_EP_MGMT_DESC_DATA_LEN		(56)

enum armada_ep_cmd_dest_type {
	CDT_INVALID = 0,
	CDT_PF,
	CDT_VF,
	CDT_CUSTOM
};

/*
 * armada_ep_app_code - Define the list of the different command receivers at
 * the NIC side, or the notification receive at the host side.
 */
enum armada_ep_app_codes {
	//TODO: need to verify if need to change the below commands
	AC_HOST_AGNIC_NETDEV	= 0X1,
	AC_PF_MANAGER,

	APP_CODE_LAST		= 0XFFFF,
};

/*
 * agnic_cmd_codes - Define the list of commands that can be set from the host
 * to the NIC.
 */
enum armada_ep_cmd_codes {
	//TODO: need to verify if need to change the below commands
	CC_PF_VF_INIT = 0x1,
	CC_PF_VF_INIT_DONE,
	CC_PF_VF_EGRESS_TC_ADD,
	CC_PF_VF_EGRESS_DATA_Q_ADD,
	CC_PF_VF_INGRESS_TC_ADD,
	CC_PF_VF_INGRESS_DATA_Q_ADD,
	CC_PF_VF_ENABLE,
	CC_PF_VF_DISABLE,

	CC_PF_MGMT_ECHO,
	CC_PF_VF_LINK_STATUS,
	CC_PF_GET_STATISTICS,
	CC_PF_VF_CLOSE,
	CC_PF_MAC_ADDR,
	CC_PF_PROMISC,
	CC_PF_MC_PROMISC,
	CC_PF_MTU,
	CC_PF_SET_LOOPBACK,
	CC_PF_ADD_VLAN,
	CC_PF_REMOVE_VLAN,
	CC_PF_GET_GP_STATS,
	CC_PF_GET_GP_QUEUE_STATS,
	CC_PF_MC_ADD_ADDR,
	CC_PF_MC_REMOVE_ADDR,
	CC_PF_MAC_FLUSH,
	CC_PF_LINK_INFO,
	CC_PF_PAUSE_SET,
	CC_PF_PAUSE_GET,
	CC_PF_PORT_RATE_LIMIT,
	CC_PF_QUEUE_RATE_LIMIT,
	CC_PF_VF_GET_CAPABILITIES,
	CMD_CODE_LAST = 0XFF,
};

enum armada_ep_notif_codes {
	NC_PF_LINK_CHANGE = 0x1,
	NC_PF_KEEP_ALIVE  = 0x2,

	NOTIF_CODE_LAST = 0XFF,
};

/* Relevant only for pf_vf_init command. */
enum armada_ep_egress_sched {
	ES_STRICT_SCHED = 0x1,
	ES_WRR_SCHED
};

/* Relevant only for ingress_tc_add command. */
enum armada_ep_ingress_hash_type {
	ING_HASH_TYPE_NONE = 0x0,
	ING_HASH_TYPE_2_TUPLE,
	ING_HASH_TYPE_5_TUPLE,
	ING_HASH_LAST
};

#define SET_MGMT_CMD_FIELD(_word, val, _off, _msk)	\
	({typeof(_word) word = _word; \
	typeof(_off) off = _off; \
	typeof(_msk) msk = _msk; \
	word = ((word & ~(msk << off)) | (((val) & msk) << off)); })
#define GET_MGMT_CMD_FIELD(word, off, msk) \
	(((word) >> (off)) & (msk))

#define ARMADA_EP_MAC_ADDR_LEN	6
#define ARMADA_EP_MGMT_MSIX_ID_INVALID	(-1)

struct rate_limit_params {
	/* committed_burst_size, in kilobytes. Min: 64kB */
	u32 cbs;
	/* committed_information_rate, in kilobits per second. Min: 100kbps */
	u32 cir;
};
/*
 * armada_ep_mgmt_cmd - Encapsulates all management control commands parameters.
 */
/* Make sure structure is portable along different systems. */
struct armada_ep_mgmt_cmd_params {
	union {
		struct {
			u32	num_host_egress_tc;
			u32	num_host_ingress_tc;
			u16	mtu_override;
				/*TODO: need to remove, not used*/
			u16	mru_override;
				/*TODO: need to remove, not used*/
			u8	egress_sched; /* enum agnic_egress_sched */
		} __attribute__((packed)) pf_vf_init;

		struct {
			u32	tc;
			u32	num_queues;
		} __attribute__((packed)) pf_vf_egress_tc_add;

		/* Used for BP & Tx queues. */
		struct {
			u64	q_phys_addr;
			u32	q_prod_offs;
			u32	q_cons_offs;
			u32	q_len;
			u32	q_wrr_weight;
			u32	tc; /* irrelevant for BP. */
			u32	msix_id;
		} __attribute__((packed)) pf_vf_egress_q_add;

		struct {
			u32	tc;
			u32	num_queues;
			u32	pkt_offset;
			u8	hash_type; /* enum agnic_ingress_hash_type */
		} __attribute__((packed)) pf_vf_ingress_tc_add;

		struct {
			u64	q_phys_addr;
			u32	q_prod_offs;
			u32	q_cons_offs;
			u64	bpool_q_phys_addr;
			u32	bpool_q_prod_offs;
			u32	bpool_q_cons_offs;
			u32	q_len;
			u32	msix_id;
			u32	tc;
			u32	q_buf_size;
		} __attribute__((packed)) pf_vf_ingress_data_q_add;

		struct {
			u8	reset;
		} __attribute__((packed)) pf_get_statistics;

		struct {
			u32	mtu;
		} __attribute__((packed)) pf_set_mtu;

		struct {
			u8 loopback;
		} __attribute__((packed)) pf_set_loopback;

		struct {
			u16 vlan;
		} __attribute__((packed)) pf_vlan;

		struct {
			u8 uc;
			u8 mc;
		} __attribute__((packed)) pf_flush_addr;

		struct {
			u8	out;
			u8	tc;
			u8	qid;
			u8	reset;
		} __attribute__((packed)) pf_q_get_statistics;

		struct {
			u8 enable;
			u8 tc;
			u8 qid;
			struct rate_limit_params rate_limit;
		} __attribute__((packed)) pf_queue_rate_limit;

		struct {
			u8 enable;
			struct rate_limit_params rate_limit;
		} __attribute__((packed)) pf_port_rate_limit;

		/* CC_PF_MAC_ADDR */
		u8 mac_addr[ARMADA_EP_MAC_ADDR_LEN];

		/* CC_PF_PROMISC */
#define ARMADA_EP_PROMISC_ENABLE	(1)
#define ARMADA_EP_PROMISC_DISABLE	(0)
		u8 promisc;

		/* CC_PF_MC_PROMISC */
#define ARMADA_EP_MC_PROMISC_ENABLE	(1)
#define ARMADA_EP_MC_PROMISC_DISABLE	(0)
		u8 mc_promisc;
		/* CC_PF_PAUSE_SET */
		struct {
			u8 rx;
			u8 tx;
		} __attribute__((packed)) pf_pause_params;
	};
} __attribute__((packed));

struct armada_ep_mgmt_capabilities {
#define CAPABILITIES_SG		(1 << 0)
	u32 flags;
	u32 max_buf_size;
} __attribute__((packed));

/*
 * armada_ep_mgmt_cmd_resp - Encapsulates the different responses that can be
 * received from the NIC as a result of a management command.
 * status - Command execution status (0 - Ok, 1 - Fail, 0xFF - Notification).
 */
/* Make sure structure is portable along different systems. */
struct armada_ep_mgmt_cmd_resp {
#define ARMADA_EP_NOTIF_STATUS_OK	(0)
#define ARMADA_EP_NOTIF_STATUS_FAIL	(1)
	u8 status;
	union {
		/* Use same response structure for all Q add operations. */
		struct {
#define ARMADA_EP_Q_INF_STATUS_OK	(0)
#define ARMADA_EP_Q_INF_STATUS_ERR	(1)
			u64	q_inf;
			u64	bpool_q_inf;
		} __attribute__((packed)) q_add_resp;

		/* CC_PF_LINK_STATUS */
		u32 link_status;

		/* CC_PF_PP2_STATISTICS */
		struct {
			u64 rx_bytes;
			u64 rx_packets;
			u64 rx_unicast_packets;
			u64 rx_errors;
			u64 rx_fullq_dropped;
			u64 rx_bm_dropped;
			u64 rx_early_dropped;
			u64 rx_fifo_dropped;
			u64 rx_cls_dropped;
			u64 tx_bytes;
			u64 tx_packets;
			u64 tx_unicast_packets;
			u64 tx_errors;
		} __attribute__((packed)) armada_ep_stats;

		struct {
			u64 gp_rx_packets;
			u64 gp_rx_fullq_dropped;
			u64 gp_tx_packets;
		} __attribute__((packed)) gp_stats;

		struct {
			u64 packets;
		} __attribute__((packed)) gp_queue_stats;

		/* CC_PF_LINK_INFO */
		struct {
			u8  link_up;
			u32 speed;
			u32 duplex;
			u32 phy_mode;
		} __attribute__((packed)) pf_link_info;

		/* CC_PF_PAUSE_GET */
		struct {
			u8 rx;
			u8 tx;
		} __attribute__((packed)) pf_pause_params;
		/* CC_PF_VF_GET_CAPABILITIES */
		struct armada_ep_mgmt_capabilities pf_vf_capabilities;
	};
} __attribute__((packed));

/*
 * armada_ep_mgmt_notification - Encapsulates the different notifications that
 * can be received from the SNIC.
 */
/* Make sure structure is portable along different systems. */
struct armada_ep_mgmt_notification {
	union {
		/* NC_PF_LINK_CHANGE */
		u32 link_status;
	};
} __attribute__((packed));

/* Command Descriptor
 * cmd_idx - Command Identifier, this field will be copied to the response
 *   descriptor by the agnic, in order to correlate the response with the
 *	command.
 *	value 0xFFFF indicate a notification message.
 * app_code - Target application Id (out of enum agnic_app_codes)
 * cmd_code - Command to be executed (out of enum agnic_cmd_codes)
 * client_id - Destination ID – PF / VF Id
 * client_type - Destination type – PF / VF
 * flags - Bitmask of CMD_FLAGS_XX.
 * cmd_params/resp_data
 *	Array of bytes, holding the serialized parameters/response list for a
 *	specific command.
 */
/* Make sure structure is portable along different systems. */
struct armada_ep_cmd_desc {
#define CMD_ID_ILLEGAL			0
#define CMD_ID_NOTIFICATION		0xFFFF
	u16 cmd_idx;
	u16 app_code;
	u8 cmd_code;
	u8 client_id;
	u8 client_type;
	u8 flags;

	u8 data[ARMADA_EP_MGMT_DESC_DATA_LEN];
} __attribute__((packed));

/* indicates whether the descriptor is consturcted from multiple ones */
#define CMD_FLAGS_NUM_EXT_DESC_MASK		0x1F
#define CMD_FLAGS_NUM_EXT_DESC_SHIFT		0

#define CMD_FLAGS_NUM_EXT_DESC_SET(flags, val)	\
	SET_MGMT_CMD_FIELD(flags, val, CMD_FLAGS_NUM_EXT_DESC_SHIFT, \
	CMD_FLAGS_NUM_EXT_DESC_MASK)
#define CMD_FLAGS_NUM_EXT_DESC_GET(flags)	\
	GET_MGMT_CMD_FIELD(flags, CMD_FLAGS_NUM_EXT_DESC_SHIFT, \
	CMD_FLAGS_NUM_EXT_DESC_MASK)

/* No response is required for this cmd */
#define CMD_FLAGS_NO_RESP_MASK			0x1
#define CMD_FLAGS_NO_RESP_SHIFT			5
#define CMD_FLAGS_NO_RESP_SET(flags, val)	\
	SET_MGMT_CMD_FIELD(flags, val, CMD_FLAGS_NO_RESP_SHIFT, \
	CMD_FLAGS_NO_RESP_MASK)
#define CMD_FLAGS_NO_RESP_GET(flags)		\
	GET_MGMT_CMD_FIELD(flags, CMD_FLAGS_NO_RESP_SHIFT, \
	CMD_FLAGS_NO_RESP_MASK)

/* Indicates position of the command buffer- inline first, last or external
 * buffer.
 */
#define CMD_FLAGS_BUF_POS_MASK			0x3
#define CMD_FLAGS_BUF_POS_SHIFT			6
#define CMD_FLAGS_BUF_POS_SET(flags, val)	\
	SET_MGMT_CMD_FIELD(flags, val, CMD_FLAGS_BUF_POS_SHIFT, \
	CMD_FLAGS_BUF_POS_MASK)
#define CMD_FLAGS_BUF_POS_GET(flags)		\
	GET_MGMT_CMD_FIELD(flags, CMD_FLAGS_BUF_POS_SHIFT, \
	CMD_FLAGS_BUF_POS_MASK)

#define CMD_FLAG_BUF_POS_SINGLE		0 /* CMD_params is inline and this is
					   * a single buffer descriptor;
					   * i.e. the parameters for this
					   * command are inline.
					   */
#define CMD_FLAG_BUF_POS_FIRST_MID	1 /* CMD_params is inline and this is
					   * the first or a middle buffer out of
					   * a sequence of buffers to come.
					   */
#define CMD_FLAG_BUF_POS_LAST		2 /* CMD_params is inline and this is
					   * the last buffer out of a sequence
					   * thatpreviously arrived.
					   */
#define CMD_FLAG_BUF_POS_EXT_BUF	3 /* CMD_params is a pointer to an
					   * external buffer; i.e. the
					   * parameters for this command reside
					   * in external buffer.
					   */

/* Buffers Pool Descriptor */
struct armada_ep_bpool_desc {
	u64 buff_addr_phys;
	u64 buff_cookie;
} __attribute__((packed));

#endif /* __AGNIC_PFIO_HW_H__ */
