/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */
#ifndef __INCLUDE_PSW_H__
#define __INCLUDE_PSW_H__

/* Register offsets */

#define PSW_AF_CONST0			    (0x8ull)
#define PSW_AF_CONST1			    (0x10ull)
#define PSW_AF_CONST2			    (0x18ull)
#define PSW_AF_MISC_CTRL		    (0x30ull)
#define PSW_AF_SCRATCH_ARRAYX(a)	    (0x60ull | (uint64_t)(a) << 3)
#define PSW_AF_CCLK_PART0_ACTIVE_PCX(a)	    (0x100ull | (uint64_t)(a) << 3)
#define PSW_AF_CLK_EN_PART0		    (0x150ull)
#define PSW_AF_CSR_REQ_CNT		    (0x200ull)
#define PSW_AF_ATOMIC_REQ_CNT		    (0x208ull)
#define PSW_AF_ATOMIC_LCAPTURE		    (0x210ull)
#define PSW_PRIV_AF_INT_CFG		    (0x1000000ull)
#define PSW_PRIV_AF_CFG			    (0x1000008ull)
#define PSW_PRIV_GEN_CFG		    (0x1000010ull)
#define PSW_AF_BLK_RST			    (0x1000018ull)
#define PSW_AF_LF_RST			    (0x1000020ull)
#define PSW_AF_RVU_LF_CFG_DEBUG		    (0x1000028ull)
#define PSW_PRIV_CONST			    (0x1000030ull)
#define PSW_AF_RVU_CLK_CTRL		    (0x1000040ull)
#define PSW_PRIV_LFX_INT_CFG(a)		    (0x1000200ull | (uint64_t)(a) << 3)
#define PSW_PRIV_LFX_CFG(a)		    (0x1000400ull | (uint64_t)(a) << 3)
#define PSW_AF_EPF_FLR_DONE_INT		    (0x1800000ull)
#define PSW_AF_EPF_FLR_DONE_INT_W1S	    (0x1800008ull)
#define PSW_AF_EPF_FLR_DONE_INT_ENA_W1C	    (0x1800010ull)
#define PSW_AF_EPF_FLR_DONE_INT_ENA_W1S	    (0x1800018ull)
#define PSW_AF_RAS_INT			    (0x1800020ull)
#define PSW_AF_RAS_INT_W1S		    (0x1800028ull)
#define PSW_AF_RAS_INT_ENA_W1C		    (0x1800030ull)
#define PSW_AF_RAS_INT_ENA_W1S		    (0x1800038ull)
#define PSW_AF_RVU_INT			    (0x1800040ull)
#define PSW_AF_RVU_INT_W1S		    (0x1800048ull)
#define PSW_AF_RVU_INT_ENA_W1C		    (0x1800050ull)
#define PSW_AF_RVU_INT_ENA_W1S		    (0x1800058ull)
#define PSW_AF_APINOTIF_INT		    (0x1800100ull)
#define PSW_AF_APINOTIF_INT_W1S		    (0x1800108ull)
#define PSW_AF_APINOTIF_INT_ENA_W1C	    (0x1800110ull)
#define PSW_AF_APINOTIF_INT_ENA_W1S	    (0x1800118ull)
#define PSW_AF_GEN_INT			    (0x1800200ull)
#define PSW_AF_GEN_INT_W1S		    (0x1800208ull)
#define PSW_AF_GEN_INT_ENA_W1C		    (0x1800210ull)
#define PSW_AF_GEN_INT_ENA_W1S		    (0x1800218ull)
#define PSW_AF_ECC_INT			    (0x1800300ull)
#define PSW_AF_ECC_INT_W1S		    (0x1800308ull)
#define PSW_AF_ECC_INT_ENA_W1C		    (0x1800310ull)
#define PSW_AF_ECC_INT_ENA_W1S		    (0x1800318ull)
#define PSW_AF_EVFX_FLR_DONE_INT(a)	    (0x1800400ull | (uint64_t)(a) << 3)
#define PSW_AF_EVFX_FLR_DONE_INT_W1S(a)	    (0x1800800ull | (uint64_t)(a) << 3)
#define PSW_AF_EVFX_FLR_DONE_INT_ENA_W1C(a) (0x1800c00ull | (uint64_t)(a) << 3)
#define PSW_AF_EVFX_FLR_DONE_INT_ENA_W1S(a) (0x1801000ull | (uint64_t)(a) << 3)
#define PSW_AF_EPFX_LF_SHARED_BASE(a)	    (0x2000000ull | (uint64_t)(a) << 3)
#define PSW_AF_EVF_EPFX_SHARED_BASE(a)	    (0x2000100ull | (uint64_t)(a) << 3)
#define PSW_AF_SHARED_CLK_CTRL		    (0x2001000ull)
#define PSW_AF_EPFX_EVFX_LF_SHARED_BASE(a, b)                                                      \
	(0x2008000ull | (uint64_t)(a) << 10 | (uint64_t)(b) << 3)
#define PSW_AF_SHARED_REQ_CNT		(0x2010000ull)
#define PSW_AF_SHARED_REQ_LCAPTURE	(0x2010010ull)
#define PSW_AF_SHARED_REQ_LCAPTURE2	(0x2010020ull)
#define PSW_AF_FID_TYPEX_CONST(a)	(0x3000000ull | (uint64_t)(a) << 3)
#define PSW_AF_FID_CLK_CTRL		(0x3000050ull)
#define PSW_AF_FID_RSP_WRR		(0x3000060ull)
#define PSW_AF_FID_NOMATCH_CAPTURE	(0x3000070ull)
#define PSW_AF_MAP_CAPTURE		(0x3000080ull)
#define PSW_AF_HNON_VAL			(0x3000088ull)
#define PSW_AF_INJECT_REQ		(0x3000090ull)
#define PSW_AF_INJECT_RW_DATA		(0x3000098ull)
#define PSW_AF_FID_ATTRX(a)		(0x3004000ull | (uint64_t)(a) << 3)
#define PSW_AF_FID_BASEX(a)		(0x3008000ull | (uint64_t)(a) << 3)
#define PSW_AF_FID_INDX(a)		(0x300c000ull | (uint64_t)(a) << 3)
#define PSW_AF_EPFX_MAP(a)		(0x3020000ull | (uint64_t)(a) << 3)
#define PSW_AF_EPFX_EVFX_MAP(a, b)	(0x3030000ull | (uint64_t)(a) << 10 | (uint64_t)(b) << 3)
#define PSW_AF_HCI_REQ_CNT		(0x3040000ull)
#define PSW_AF_HCI_REQ_LCAPTURE		(0x3040008ull)
#define PSW_AF_HCI_REQ_LCAPTURE2	(0x3040010ull)
#define PSW_AF_FID_LAST_MATCH_IDX	(0x3040018ull)
#define PSW_AF_GID_CLK_CTRL		(0x4000000ull)
#define PSW_AF_GID_PARAM		(0x4000008ull)
#define PSW_AF_GID_ERR_CAPTURE		(0x4000020ull)
#define PSW_AF_GID_CLEAR_STAT		(0x4000040ull)
#define PSW_AF_GID_DBG_COUNT1		(0x4000048ull)
#define PSW_AF_GID_DBG_COUNT2		(0x4000050ull)
#define PSW_AF_GID_DBG_COUNT3		(0x4000058ull)
#define PSW_AF_GID_DBG_FIND_MAX		(0x4000060ull)
#define PSW_AF_GID_DBG_REFLECTION1	(0x4000068ull)
#define PSW_AF_GID_DBG_REFLECTION2	(0x4000070ull)
#define PSW_AF_GID_BUCKETX(a)		(0x4080000ull | (uint64_t)(a) << 3)
#define PSW_AF_GID_ENTRY0X(a)		(0x4100000ull | (uint64_t)(a) << 4)
#define PSW_AF_GID_ENTRY1X(a)		(0x4100008ull | (uint64_t)(a) << 4)
#define PSW_AF_GID_ENTRY0_W		(0x4200000ull)
#define PSW_AF_GID_ENTRY1_W		(0x4200008ull)
#define PSW_AF_GID_BUCKET_RESULT	(0x4200010ull)
#define PSW_AF_GID_ENTRY_RESULT0	(0x4200018ull)
#define PSW_AF_GID_ENTRY_RESULT1	(0x4200020ull)
#define PSW_AF_GID_LU			(0x4200028ull)
#define PSW_AF_HOX_QCX(a, b)		(0x5000000ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_AF_SHOX_QCX(a, b)		(0x5100000ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_AF_PF_PIDBL_CFGX(a)		(0x5200000ull | (uint64_t)(a) << 3)
#define PSW_AF_PF_CIDBL_CFGX(a)		(0x5200100ull | (uint64_t)(a) << 3)
#define PSW_AF_DBL_TO_THX(a)		(0x5200200ull | (uint64_t)(a) << 3)
#define PSW_AF_DBL_WINX(a)		(0x5200400ull | (uint64_t)(a) << 3)
#define PSW_AF_H2AP_CLK_CTRL		(0x5200500ull)
#define PSW_AF_HO_QE_CAPTURE		(0x5200610ull)
#define PSW_AF_SHO_QE_CAPTURE		(0x5200620ull)
#define PSW_AF_NQE_CAPTURE		(0x5200630ull)
#define PSW_AF_HOQ_QOS_WRR		(0x5200640ull)
#define PSW_AF_HOQ_PENDX(a)		(0x5200680ull | (uint64_t)(a) << 3)
#define PSW_AF_HOQ_ANP_GRPX(a)		(0x52006a0ull | (uint64_t)(a) << 3)
#define PSW_AF_HOQ_ANP_GRP_INDEXX(a)	(0x52006c0ull | (uint64_t)(a) << 3)
#define PSW_AF_HOQ_ERR_ACCESS		(0x5200700ull)
#define PSW_AF_HO_DMA_STAT		(0x5200708ull)
#define PSW_AF_HO_DMA_TRANSX(a)		(0x5200720ull | (uint64_t)(a) << 3)
#define PSW_AF_HO_DMA_SKIPX(a)		(0x5200760ull | (uint64_t)(a) << 3)
#define PSW_AF_HO_DMA_CNT_CFGX(a)	(0x5200780ull | (uint64_t)(a) << 3)
#define PSW_AF_HOQ_ANPX_PENDX(a, b)	(0x5210000ull | (uint64_t)(a) << 10 | (uint64_t)(b) << 3)
#define PSW_AF_HIX_QCX(a, b)		(0x6000000ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_AF_SHIX_QCX(a, b)		(0x6100000ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_AF_HI_QE_CAPTURE		(0x6200000ull)
#define PSW_AF_SHI_QE_CAPTURE		(0x6200010ull)
#define PSW_AF_AQE_CAPTURE		(0x6200020ull)
#define PSW_AF_ACKQ_TH			(0x6200030ull)
#define PSW_AF_ACKQ_WRR			(0x6200040ull)
#define PSW_AF_AP2H_CLK_CTRL		(0x6200080ull)
#define PSW_AF_MSIX_VECX_ADDR(a)	(0x7000000ull | (uint64_t)(a) << 4)
#define PSW_AF_MSIX_VECX_CTL(a)		(0x7000008ull | (uint64_t)(a) << 4)
#define PSW_AF_MSIX_PBAX(a)		(0x7080000ull | (uint64_t)(a) << 3)
#define PSW_AF_MSIX_ATTRX(a)		(0x7090000ull | (uint64_t)(a) << 3)
#define PSW_AF_EPFX_PCIE_CFG(a)		(0x70c0000ull | (uint64_t)(a) << 3)
#define PSW_AF_EPFX_EVFX_PCIE_CFG(a, b) (0x70d0000ull | (uint64_t)(a) << 10 | (uint64_t)(b) << 3)
#define PSW_AF_MSIX_VECX_STAT(a)	(0x7400000ull | (uint64_t)(a) << 3)
#define PSW_AF_MSIX_VECX_EPF_FUNC(a)	(0x7800000ull | (uint64_t)(a) << 3)
#define PSW_AF_MSIX_CLK_CTRL		(0x7900000ull)
#define PSW_AF_API_NOTIF_QCX(a)		(0x8000000ull | (uint64_t)(a) << 3)
#define PSW_AF_API_TO_TH		(0x8000100ull)
#define PSW_AF_API_NQE_CAPTURE		(0x8000110ull)
#define PSW_AF_API_AQE_CAPTURE		(0x8000120ull)
#define PSW_AF_API_CLK_CTRL		(0x8000200ull)
#define PSW_AF_BAR2_SEL			(0x9000000ull)
#define PSW_AF_BAR2_ALIASX(a)		(0x9100000ull | (uint64_t)(a) << 3)
#define PSW_AF_TIMER_TICK_CFG		(0xa000000ull)
#define PSW_AF_TICK_CNT			(0xa000008ull)
#define PSW_AF_TPS_PAUSE		(0xa000010ull)
#define PSW_AF_TPD_CLK_CTRL		(0xa000100ull)
#define PSW_AF_TIMER_PROFILE_TBLX(a)	(0xa000200ull | (uint64_t)(a) << 3)
#define PSW_AF_PST_BASE_ADDR		(0xa000400ull)
#define PSW_AF_TIMED_POLLING_DRIFT	(0xa000408ull)
#define PSW_AF_TIMED_POLLING_CFG	(0xa000410ull)
#define PSW_AF_TIMED_ERR_CAPTURE	(0xa000420ull)
#define PSW_AF_TIMER_SEL_TBLX(a)	(0xa010000ull | (uint64_t)(a) << 3)
#define PSW_AF_LF_MBOX_EPFX_DATAX(a, b) (0xb000000ull | (uint64_t)(a) << 4 | (uint64_t)(b) << 3)
#define PSW_AF_LF_MBOX_EPFX_EVFX_DATAX(a, b, c)                                                    \
	(0xb100000ull | (uint64_t)(a) << 11 | (uint64_t)(b) << 4 | (uint64_t)(c) << 3)
#define PSW_AF_LF_EPFX_MBOX_MSIX(a) (0xb200000ull | (uint64_t)(a) << 3)
#define PSW_AF_LF_EPFX_EVFX_MBOX_MSIX(a, b)                                                        \
	(0xb300000ull | (uint64_t)(b) << 10 | (uint64_t)(a) << 3)
#define PSW_AF_MBOX_CLK_CTRL		(0xb400000ull)
#define PSW_AF_NCB_ATTR			(0xc000000ull)
#define PSW_AF_LFX_NCB_ATTR(a)		(0xc000200ull | (uint64_t)(a) << 3)
#define PSW_AF_CCLK_PART1_ACTIVE_PCX(a) (0xc000400ull | (uint64_t)(a) << 3)
#define PSW_AF_CLK_EN_PART1		(0xc000450ull)
#define PSW_AF_NCB_CLK_CTRL		(0xc000460ull)
#define PSW_AF_SCRATCH_DBG		(0xc000480ull)
#define PSW_AF_NCB_OUTSTAND		(0xc000600ull)
#define PSW_AF_HPI_OUTSTAND		(0xc000610ull)
#define PSW_AF_HPIX_REQ_CNT(a)		(0xc000620ull | (uint64_t)(a) << 3)
#define PSW_AF_HPIX_DATA_REQ_CNT(a)	(0xc000630ull | (uint64_t)(a) << 3)
#define PSW_AF_HPIX_RD_ADDR_LCAPTURE(a) (0xc000640ull | (uint64_t)(a) << 3)
#define PSW_AF_HPIX_RD_REQ_LCAPTURE(a)	(0xc000650ull | (uint64_t)(a) << 3)
#define PSW_AF_HPIX_WR_ADDR_LCAPTURE(a) (0xc000660ull | (uint64_t)(a) << 3)
#define PSW_AF_HPIX_WR_REQ_LCAPTURE(a)	(0xc000670ull | (uint64_t)(a) << 3)

#define PSW_LF_ERR_CAPTURE	    (0x8ull)
#define PSW_LF_ACK_ERR_CAPTURE	    (0x10ull)
#define PSW_LF_ANQCX(a)		    (0x40ull | (uint64_t)(a) << 3)
#define PSW_LF_AAQCX(a)		    (0x80ull | (uint64_t)(a) << 3)
#define PSW_LF_NX_QCX(a, b)	    (0x200ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_LF_AX_QCX(a, b)	    (0x400ull | (uint64_t)(a) << 6 | (uint64_t)(b) << 3)
#define PSW_LF_OP_HOQCX(a)	    (0x640ull | (uint64_t)(a) << 3)
#define PSW_LF_OP_SHOQCX(a)	    (0x680ull | (uint64_t)(a) << 3)
#define PSW_LF_OP_HIQCX(a)	    (0x6c0ull | (uint64_t)(a) << 3)
#define PSW_LF_OP_SHIQCX(a)	    (0x700ull | (uint64_t)(a) << 3)
#define PSW_LF_OP_MBOXX(a)	    (0x760ull | (uint64_t)(a) << 3)
#define PSW_LF_OP_SHARED_BASE	    (0x780ull)
#define PSW_LF_RAS_INT		    (0x790ull)
#define PSW_LF_RAS_INT_W1S	    (0x798ull)
#define PSW_LF_RAS_INT_ENA_W1C	    (0x7a0ull)
#define PSW_LF_RAS_INT_ENA_W1S	    (0x7a8ull)
#define PSW_LF_NOTIF_INT	    (0x7b0ull)
#define PSW_LF_NOTIF_INT_W1S	    (0x7b8ull)
#define PSW_LF_NOTIF_INT_ENA_W1C    (0x7c0ull)
#define PSW_LF_NOTIF_INT_ENA_W1S    (0x7c8ull)
#define PSW_LF_ACK_INT		    (0x7d0ull)
#define PSW_LF_ACK_INT_W1S	    (0x7d8ull)
#define PSW_LF_ACK_INT_ENA_W1C	    (0x7e0ull)
#define PSW_LF_ACK_INT_ENA_W1S	    (0x7e8ull)
#define PSW_LF_APINOTIF_INT	    (0x7f0ull)
#define PSW_LF_APINOTIF_INT_W1S	    (0x7f8ull)
#define PSW_LF_APINOTIF_INT_ENA_W1C (0x800ull)
#define PSW_LF_APINOTIF_INT_ENA_W1S (0x808ull)
#define PSW_LF_APIACK_INT	    (0x810ull)
#define PSW_LF_APIACK_INT_W1S	    (0x818ull)
#define PSW_LF_APIACK_INT_ENA_W1C   (0x820ull)
#define PSW_LF_APIACK_INT_ENA_W1S   (0x828ull)

/* Enum offsets */

#define PSW_LF_INT_VEC_NOTIF_INT    (0x0ull)
#define PSW_LF_INT_VEC_ACK_INT	    (0x1ull)
#define PSW_LF_INT_VEC_APINOTIF_INT (0x2ull)
#define PSW_LF_INT_VEC_APIACK_INT   (0x3ull)
#define PSW_LF_INT_VEC_RAS_INT	    (0x4ull)

#define PSW_QTYPE_HOQ	 (0x0ull)
#define PSW_QTYPE_SHOQ	 (0x1ull)
#define PSW_QTYPE_HIQ	 (0x2ull)
#define PSW_QTYPE_SHIQ	 (0x3ull)
#define PSW_QTYPE_NOTIFQ (0x4ull)
#define PSW_QTYPE_AQ	 (0x5ull)
#define PSW_QTYPE_APINQ	 (0x6ull)
#define PSW_QTYPE_APIAQ	 (0x7ull)

#define PSW_ACK_DESC_TYPE_DOORBELL (0x0ull)
#define PSW_ACK_DESC_TYPE_DATA	   (0x1ull)

#define PSW_NOTIF_DESC_TYPE_PI_DBL    (0x0ull)
#define PSW_NOTIF_DESC_TYPE_WRITE     (0x1ull)
#define PSW_NOTIF_DESC_TYPE_WRITE_CFG (0x2ull)
#define PSW_NOTIF_DESC_TYPE_MBOX      (0x3ull)
#define PSW_NOTIF_DESC_TYPE_READ      (0x4ull)
#define PSW_NOTIF_DESC_TYPE_DATA      (0x5ull)
#define PSW_NOTIF_DESC_TYPE_TAG	      (0x6ull)
#define PSW_NOTIF_DESC_TYPE_PR	      (0x7ull)

#define PSW_AF_INT_VEC_EPF_FLR_DONE_INT	      (0x80ull)
#define PSW_AF_INT_VEC_API_NOTIF_INT	      (0x81ull)
#define PSW_AF_INT_VEC_GEN_INT		      (0x82ull)
#define PSW_AF_INT_VEC_RAS_INT		      (0x83ull)
#define PSW_AF_INT_VEC_RVU_INT		      (0x84ull)
#define PSW_AF_INT_VEC_ECC_INT		      (0x85ull)
#define PSW_AF_INT_VEC_EVF_START_FLR_DONE_INT (0x0ull)
#define PSW_AF_INT_VEC_EVF_END_FLR_DONE_INT   (0x7full)

#define PSW_QETYPE_QDIS (0x0ull)
#define PSW_QETYPE_DDRP (0x1ull)
#define PSW_QETYPE_RFLT (0x2ull)
#define PSW_QETYPE_WFLT (0x3ull)
#define PSW_QETYPE_RPSN (0x4ull)
#define PSW_QETYPE_DBLD (0x5ull)
#define PSW_QETYPE_BMD	(0x6ull)
#define PSW_QETYPE_CTV	(0x7ull)

#define PSW_TYPES_API	   (0x0ull)
#define PSW_TYPES_LFSHARED (0x1ull)
#define PSW_TYPES_ESHARED  (0x2ull)
#define PSW_TYPES_LFMBOX   (0x3ull)
#define PSW_TYPES_EMBOX	   (0x4ull)
#define PSW_TYPES_MSIX	   (0x5ull)
#define PSW_TYPES_PBA	   (0x6ull)
#define PSW_TYPES_PIDBL	   (0x7ull)
#define PSW_TYPES_CIDBL	   (0x8ull)

#define PSW_SETYPE_HOQ	 (0x0ull)
#define PSW_SETYPE_SHOQ	 (0x1ull)
#define PSW_SETYPE_HIQ	 (0x2ull)
#define PSW_SETYPE_SHIQ	 (0x3ull)
#define PSW_SETYPE_MBOX	 (0x4ull)
#define PSW_SETYPE_SBASE (0x5ull)
#define PSW_SETYPE_ACK	 (0x6ull)

/* Structures definitions */

/* Read/Write descriptor structure */
struct psw_ack_api_data_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t intrpt : 1;
	uint64_t rderr : 1;
	uint64_t rsvd_7_6 : 2;
	uint64_t be : 8;
	uint64_t epffunc : 16;
	uint64_t etag : 11;
	uint64_t rsvd_63_43 : 21;
	uint64_t data : 64; /* W1 */
};

/* Acknowledge queue doorbell descriptor structure */
struct psw_ack_doorbell_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t intrpt : 1;
	uint64_t rsvd_5 : 1;
	uint64_t msgovrd : 2;
	uint64_t iqid : 8;
	uint64_t epffunc : 16;
	uint64_t index : 16;
	uint64_t write_cnt : 8;
	uint64_t reserved : 8;
};

/* Acknowledge queue config structure */
struct psw_ack_queue_config_s {
	uint64_t rsvd_63_0 : 64;    /* W0 */
	uint64_t rsvd_127_64 : 64;  /* W1 */
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* API acknowledge queue config structure */
struct psw_apiack_queue_config_s {
	uint64_t rsvd_63_0 : 64;    /* W0 */
	uint64_t rsvd_127_64 : 64;  /* W1 */
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* API notification queue config structure */
struct psw_apinotif_queue_config_s {
	uint64_t rsvd_63_0 : 64;    /* W0 */
	uint64_t rsvd_127_64 : 64;  /* W1 */
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_193 : 1;
	uint64_t apifulldrop : 1;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* PSW epf func structure */
struct psw_epf_func_s {
	uint16_t vf : 8;
	uint16_t rsvd_8 : 1;
	uint16_t pf : 3;
	uint16_t rsvd_13_12 : 2;
	uint16_t port : 1;
	uint16_t rsvd_15 : 1;
};

/* PCIe host inbound queue config structure */
struct psw_hib_queue_config_s {
	uint64_t pcie_attr : 64; /* W0 */
	uint64_t cimode : 1;
	uint64_t rsvd_67_65 : 3;
	uint64_t log2bs : 2;
	uint64_t inplace : 1;
	uint64_t rsvd_71 : 1;
	uint64_t msg_type : 2;
	uint64_t rsvd_79_74 : 6;
	uint64_t msix_vec_num : 9;
	uint64_t rsvd_127_89 : 39;
	uint64_t pi_addr : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* PCIe host outbound queue config structure */
struct psw_hob_queue_config_s {
	uint64_t pcie_attr : 64; /* W0 */
	uint64_t notif_qnum : 3;
	uint64_t rsvd_67 : 1;
	uint64_t log2bs : 2;
	uint64_t inplace : 1;
	uint64_t rsvd_71 : 1;
	uint64_t anp_qos : 2;
	uint64_t rsvd_87_74 : 14;
	uint64_t incr_pi : 1;
	uint64_t rsvd_127_89 : 39;
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t twin : 4;
	uint64_t rsvd_207_200 : 8;
	uint64_t ii : 16;
	uint64_t lf : 8;
	uint64_t qid : 8;
	uint64_t epffunc : 16;
};

/* Data descriptor structure */
struct psw_notif_data_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t data : 60;
};

/* Notification queue doorbell structure */
struct psw_notif_doorbell_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t rsvd_7_4 : 4;
	uint64_t hoqid : 8;
	uint64_t epffunc : 16;
	uint64_t index : 16;
	uint64_t rsvd_63_48 : 16;
};

/* Port reset descriptor structure */
struct psw_notif_pr_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t p0r : 1;
	uint64_t p1r : 1;
	uint64_t rsvd_63_6 : 58;
};

/* Notification queue config structure */
struct psw_notif_queue_config_s {
	uint64_t rsvd_63_0 : 64;    /* W0 */
	uint64_t rsvd_127_64 : 64;  /* W1 */
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* Read tag descriptor structure */
struct psw_notif_tag_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t etag : 11;
	uint64_t rsvd_63_15 : 49;
};

/* Read/Write notification queue descriptor structure */
struct psw_notif_write_read_desc_s {
	uint64_t phase : 1;
	uint64_t dtype : 3;
	uint64_t data : 4;
	uint64_t be : 8;
	uint64_t epffunc : 16;
	uint64_t addr : 32;
};

/* PSW pcie attributes structure */
struct psw_pcie_attr_s {
	uint64_t pasid : 20;
	uint64_t ph : 2;
	uint64_t ro : 1;
	uint64_t no_snp : 1;
	uint64_t pasid_ctrl : 2;
	uint64_t es : 1;
	uint64_t th : 1;
	uint64_t rsvd_31_28 : 4;
	uint64_t tlp_st : 16;
	uint64_t rsvd_63_48 : 16;
};

/* Queue config base structure */
struct psw_queue_config_s {
	uint64_t enable : 1;
	uint64_t rsvd_3_1 : 3;
	uint64_t log2ds : 3;
	uint64_t rsvd_7 : 1;
	uint64_t log2qs : 4;
	uint64_t rsvd_63_12 : 52;
	uint64_t rsvd_69_64 : 6;
	uint64_t base_addr : 58;
	uint64_t pi : 16;
	uint64_t pround : 48;
	uint64_t ci : 16;
	uint64_t rsvd_255_208 : 48;
	uint64_t rsvd_319_256 : 64; /* W4 */
	uint64_t rsvd_383_320 : 64; /* W5 */
	uint64_t rsvd_447_384 : 64; /* W6 */
	uint64_t rsvd_511_448 : 64; /* W7 */
};

/* PCIe shadow host inbound queue config structure */
struct psw_shib_queue_config_s {
	uint64_t rsvd_63_0 : 64;    /* W0 */
	uint64_t rsvd_127_64 : 64;  /* W1 */
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* PCIe shadow host outbound queue config structure */
struct psw_shob_queue_config_s {
	uint64_t rsvd_63_0 : 64; /* W0 */
	uint64_t ci_msg_en : 1;
	uint64_t rsvd_65 : 1;
	uint64_t ci_addr : 62;
	uint64_t rsvd_191_128 : 64; /* W2 */
	uint64_t qerror : 1;
	uint64_t rsvd_194_193 : 2;
	uint64_t idle : 1;
	uint64_t rsvd_207_196 : 12;
	uint64_t ii : 16;
	uint64_t rsvd_255_224 : 32;
};

/* PSW timed polling structure */
struct psw_timed_polling_s {
	uint64_t epffunc : 16;
	uint64_t rsvd_19_16 : 4;
	uint64_t size : 2;
	uint64_t rsvd_23_22 : 2;
	uint64_t dir : 1;
	uint64_t rsvd_63_25 : 39;
	uint64_t pcie_addr : 64; /* W1 */
	uint64_t ddr_addr : 64;	 /* W2 */
	uint64_t pcie_attr : 64; /* W3 */
};

/* PSW Queue config union */
union psw_queue_config_u {
	struct psw_queue_config_s s;
	uint64_t u[8];
};

/* PSW API notification queue config union */
union psw_apinotif_queue_config_u {
	struct psw_apinotif_queue_config_s s;
	uint64_t u[4];
};

/* PSW API ack queue config union */
union psw_apiack_queue_config_u {
	struct psw_apiack_queue_config_s s;
	uint64_t u[4];
};

/* PSW notification queue config union */
union psw_notif_queue_config_u {
	struct psw_notif_queue_config_s s;
	uint64_t u[4];
};

/* PSW ack queue config union */
union psw_ack_queue_config_u {
	struct psw_ack_queue_config_s s;
	uint64_t u[4];
};

/* PSW Host Inbound Queue config union */
union psw_hib_queue_config_u {
	struct psw_hib_queue_config_s s;
	uint64_t u[4];
};

/* PSW Host Outbound Queue config union */
union psw_hob_queue_config_u {
	struct psw_hob_queue_config_s s;
	uint64_t u[4];
};

/* PSW Shadow Inbound Queue config union */
union psw_shib_queue_config_u {
	struct psw_shib_queue_config_s s;
	uint64_t u[4];
};

/* PSW Shadow Outbound Queue config union */
union psw_shob_queue_config_u {
	struct psw_shob_queue_config_s s;
	uint64_t u[4];
};

/* PSW PCI attributes union */
union psw_pcie_attr_u {
	struct psw_pcie_attr_s s;
	uint64_t u;
};

enum psw_lf_int_vec_e {
	PSW_LF_NOTIF_INT_VEC = 0,
	PSW_LF_ACK_INT_VEC,
	PSW_LF_APINOTIF_INT_VEC,
	PSW_LF_APIACK_INT_VEC,
	PSW_LF_RAS_INT_VEC,
};

#define PSW_ANQ_DESC_SZ 8
#define PSW_NQ_DESC_SZ	8
#define PSW_AQ_DESC_SZ	8
#define PSW_AAQ_DESC_SZ 16

#define PSW_EPF_FUNC_PF_MASK  (BIT_ULL(3) - 1)
#define PSW_EPF_FUNC_PF_SHIFT 9
#define PSW_EPF_FUNC_VF_MASK  (BIT_ULL(8) - 1)
#define PSW_EPF_FUNC_VF_SHIFT 0

#endif /* __INCLUDE_PSW_H__ */
