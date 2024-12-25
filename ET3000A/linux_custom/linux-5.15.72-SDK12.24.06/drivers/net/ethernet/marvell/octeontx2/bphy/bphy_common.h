/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell BPHY Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _BPHY_COMMON_H_
#define _BPHY_COMMON_H_

/* BPHY definitions */
#define OTX2_BPHY_PCI_VENDOR_ID		0x177D
#define OTX2_BPHY_PCI_DEVICE_ID		0xA089

/* PSM register offsets */
#define PSM_QUEUE_CMD_LO(a)		(0x0 + (a) * 0x10)
#define PSM_QUEUE_CMD_HI(a)		(0x8 + (a) * 0x10)
#define PSM_QUEUE_CFG(a)		(0x1000 + (a) * 0x10)
#define PSM_QUEUE_PTR(a)		(0x2000 + (a) * 0x10)
#define PSM_QUEUE_SPACE(a)		(0x3000 + (a) * 0x10)
#define PSM_QUEUE_TIMEOUT_CFG(a)	(0x4000 + (a) * 0x10)
#define PSM_QUEUE_INFO(a)		(0x5000 + (a) * 0x10)
#define PSM_QUEUE_ENA_W1S(a)		(0x10000 + (a) * 0x8)
#define PSM_QUEUE_ENA_W1C(a)		(0x10100 + (a) * 0x8)
#define PSM_QUEUE_FULL_STS(a)		(0x10200 + (a) * 0x8)
#define PSM_QUEUE_BUSY_STS(a)		(0x10300 + (a) * 0x8)

/* BPHY PSM GPINT register offsets */
#define PSM_INT_GP_SUM_W1C(a)		(0x10E0000 + (a) * 0x100)
#define PSM_INT_GP_SUM_W1S(a)		(0x10E0040 + (a) * 0x100)
#define PSM_INT_GP_ENA_W1C(a)		(0x10E0080 + (a) * 0x100)
#define PSM_INT_GP_ENA_W1S(a)		(0x10E00C0 + (a) * 0x100)

/* eCPRI ethertype */
#define ETH_P_ECPRI			0xAEFE
#define ECPRI_MSG_TYPE_5		0x5

/* max ptp tx requests */
extern int max_ptp_req;

/* reg base address */
extern void __iomem *bphy_reg_base;
extern void __iomem *psm_reg_base;
extern void __iomem *rfoe_reg_base;
extern void __iomem *bcn_reg_base;
extern void __iomem *ptp_reg_base;
extern void __iomem *cpri_reg_base;

enum port_link_state {
	LINK_STATE_DOWN,
	LINK_STATE_UP,
};

/* CPRI definitions */
struct cpri_pkt_dl_wqe_hdr {
	u64 lane_id		: 2;
	u64 reserved1		: 2;
	u64 mhab_id		: 2;
	u64 reserved2		: 2;
	u64 pkt_length		: 11;
	u64 reserved3		: 45;
	u64 w1;
};

struct cpri_pkt_ul_wqe_hdr {
	u64 lane_id		: 2;
	u64 reserved1		: 2;
	u64 mhab_id		: 2;
	u64 reserved2		: 2;
	u64 pkt_length		: 11;
	u64 reserved3		: 5;
	u64 fcserr		: 1;
	u64 rsp_ferr		: 1;
	u64 rsp_nferr		: 1;
	u64 reserved4		: 37;
	u64 w1;
};

struct psm_queue_info {
	u64 new_cmd_vld         : 1;
	u64 new_cmdlo_vld       : 1;
	u64 cur_cmd_vld         : 1;
	u64 in_cont_seq         : 1;
	u64 rdy_for_followup    : 1;
	u64 cont_job_wait_done  : 1;
	u64 cont_job_wait_cdt   : 1;
	u64 queue_jobreq        : 1;
	u64 state               : 4;
	u64 queue_njreq         : 3;
	u64 queue_mabq          : 1;
	u64 runjob_ctr          : 8;
	u64 badcmd_opc          : 6;
	u64 reserved_30_31      : 2;
	u64 cont_mab_id         : 6;
	u64 reserved_38_39      : 2;
	u64 cur_cmd_opcode      : 6;
	u64 cur_cmd_subopcode   : 2;
	u64 cur_cmd_wait_cond   : 8;
	u64 cur_cmd_jobtype     : 8;
};

struct psm_rst {
	u64 queue_reset_qid     : 8;
	u64 reserved_8_15       : 8;
	u64 queue_reset         : 1;
	u64 reserved_17_62      : 46;
	u64 psm_reset           : 1;
};

/* iova to kernel virtual addr */
static inline void __iomem *otx2_iova_to_virt(struct iommu_domain *domain, u64 iova)
{
	return (void __iomem *)phys_to_virt(iommu_iova_to_phys(domain, iova));
}

#endif
