/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2013 - 2015 Intel Corporation
 */

#ifndef _IAVF_LAN_HMC_H_
#define _IAVF_LAN_HMC_H_

/* forward-declare the HW struct for the compiler */
struct iavf_hw;

/* HMC element context information */

/* Rx queue context data
 *
 * The sizes of the variables may be larger than needed due to crossing byte
 * boundaries. If we do not have the width of the variable set to the correct
 * size then we could end up shifting bits off the top of the variable when the
 * variable is at the top of a byte and crosses over into the next byte.
 */
struct iavf_hmc_obj_rxq {
	u16 head;
	u16 cpuid; /* bigger than needed, see above for reason */
	u64 base;
	u16 qlen;
#define IAVF_RXQ_CTX_DBUFF_SHIFT 7
	u16 dbuff; /* bigger than needed, see above for reason */
#define IAVF_RXQ_CTX_HBUFF_SHIFT 6
	u16 hbuff; /* bigger than needed, see above for reason */
	u8  dtype;
	u8  dsize;
	u8  crcstrip;
	u8  fc_ena;
	u8  l2tsel;
	u8  hsplit_0;
	u8  hsplit_1;
	u8  showiv;
	u32 rxmax; /* bigger than needed, see above for reason */
	u8  tphrdesc_ena;
	u8  tphwdesc_ena;
	u8  tphdata_ena;
	u8  tphhead_ena;
	u16 lrxqthresh; /* bigger than needed, see above for reason */
	u8  prefena;	/* NOTE: normally must be set to 1 at init */
};

/* Tx queue context data
*
* The sizes of the variables may be larger than needed due to crossing byte
* boundaries. If we do not have the width of the variable set to the correct
* size then we could end up shifting bits off the top of the variable when the
* variable is at the top of a byte and crosses over into the next byte.
*/
struct iavf_hmc_obj_txq {
	u16 head;
	u8  new_context;
	u64 base;
	u8  fc_ena;
	u8  timesync_ena;
	u8  fd_ena;
	u8  alt_vlan_ena;
	u16 thead_wb;
	u8  cpuid;
	u8  head_wb_ena;
	u16 qlen;
	u8  tphrdesc_ena;
	u8  tphrpacket_ena;
	u8  tphwdesc_ena;
	u64 head_wb_addr;
	u32 crc;
	u16 rdylist;
	u8  rdylist_act;
};

/* for hsplit_0 field of Rx HMC context */
enum iavf_hmc_obj_rx_hsplit_0 {
	IAVF_HMC_OBJ_RX_HSPLIT_0_NO_SPLIT      = 0,
	IAVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_L2      = 1,
	IAVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_IP      = 2,
	IAVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_TCP_UDP = 4,
	IAVF_HMC_OBJ_RX_HSPLIT_0_SPLIT_SCTP    = 8,
};

/* fcoe_cntx and fcoe_filt are for debugging purpose only */
struct iavf_hmc_obj_fcoe_cntx {
	u32 rsv[32];
};

struct iavf_hmc_obj_fcoe_filt {
	u32 rsv[8];
};

/* Context sizes for LAN objects */
enum iavf_hmc_lan_object_size {
	IAVF_HMC_LAN_OBJ_SZ_8   = 0x3,
	IAVF_HMC_LAN_OBJ_SZ_16  = 0x4,
	IAVF_HMC_LAN_OBJ_SZ_32  = 0x5,
	IAVF_HMC_LAN_OBJ_SZ_64  = 0x6,
	IAVF_HMC_LAN_OBJ_SZ_128 = 0x7,
	IAVF_HMC_LAN_OBJ_SZ_256 = 0x8,
	IAVF_HMC_LAN_OBJ_SZ_512 = 0x9,
};

#define IAVF_HMC_L2OBJ_BASE_ALIGNMENT 512
#define IAVF_HMC_OBJ_SIZE_TXQ         128
#define IAVF_HMC_OBJ_SIZE_RXQ         32
#define IAVF_HMC_OBJ_SIZE_FCOE_CNTX   64
#define IAVF_HMC_OBJ_SIZE_FCOE_FILT   64

enum iavf_hmc_lan_rsrc_type {
	IAVF_HMC_LAN_FULL  = 0,
	IAVF_HMC_LAN_TX    = 1,
	IAVF_HMC_LAN_RX    = 2,
	IAVF_HMC_FCOE_CTX  = 3,
	IAVF_HMC_FCOE_FILT = 4,
	IAVF_HMC_LAN_MAX   = 5
};

enum iavf_hmc_model {
	IAVF_HMC_MODEL_DIRECT_PREFERRED = 0,
	IAVF_HMC_MODEL_DIRECT_ONLY      = 1,
	IAVF_HMC_MODEL_PAGED_ONLY       = 2,
	IAVF_HMC_MODEL_UNKNOWN,
};

struct iavf_hmc_lan_create_obj_info {
	struct iavf_hmc_info *hmc_info;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
	enum iavf_sd_entry_type entry_type;
	u64 direct_mode_sz;
};

struct iavf_hmc_lan_delete_obj_info {
	struct iavf_hmc_info *hmc_info;
	u32 rsrc_type;
	u32 start_idx;
	u32 count;
};

enum iavf_status_code iavf_init_lan_hmc(struct iavf_hw *hw, u32 txq_num,
					u32 rxq_num, u32 fcoe_cntx_num,
					u32 fcoe_filt_num);
enum iavf_status_code iavf_configure_lan_hmc(struct iavf_hw *hw,
					     enum iavf_hmc_model model);
enum iavf_status_code iavf_shutdown_lan_hmc(struct iavf_hw *hw);

u64 iavf_calculate_l2fpm_size(u32 txq_num, u32 rxq_num,
			      u32 fcoe_cntx_num, u32 fcoe_filt_num);
enum iavf_status_code iavf_get_lan_tx_queue_context(struct iavf_hw *hw,
						    u16 queue,
						    struct iavf_hmc_obj_txq *s);
enum iavf_status_code iavf_clear_lan_tx_queue_context(struct iavf_hw *hw,
						      u16 queue);
enum iavf_status_code iavf_set_lan_tx_queue_context(struct iavf_hw *hw,
						    u16 queue,
						    struct iavf_hmc_obj_txq *s);
enum iavf_status_code iavf_get_lan_rx_queue_context(struct iavf_hw *hw,
						    u16 queue,
						    struct iavf_hmc_obj_rxq *s);
enum iavf_status_code iavf_clear_lan_rx_queue_context(struct iavf_hw *hw,
						      u16 queue);
enum iavf_status_code iavf_set_lan_rx_queue_context(struct iavf_hw *hw,
						    u16 queue,
						    struct iavf_hmc_obj_rxq *s);
enum iavf_status_code iavf_create_lan_hmc_object(struct iavf_hw *hw,
				struct iavf_hmc_lan_create_obj_info *info);
enum iavf_status_code iavf_delete_lan_hmc_object(struct iavf_hw *hw,
				struct iavf_hmc_lan_delete_obj_info *info);

#endif /* _IAVF_LAN_HMC_H_ */
