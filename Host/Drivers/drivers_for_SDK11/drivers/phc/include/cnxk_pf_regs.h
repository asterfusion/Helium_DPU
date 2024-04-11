/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cnxk_pf_regs.h
    \brief Host Driver: Register Address and Register Mask values for
                        Octeon CNXK devices.
*/

#ifndef __CNXK_PF_REGS_H__
#define __CNXK_PF_REGS_H__
/*############################ RST #########################*/
#define    CNXK_RST_BOOT               0x000087E006001600ULL
#define    CNXK_RST_CHIP_DOMAIN_W1S    0x000087E006001810ULL
#define    CNXK_RST_CORE_DOMAIN_W1S    0x000087E006001820ULL
#define    CNXK_RST_CORE_DOMAIN_W1C    0x000087E006001828ULL

#define     CNXK_CONFIG_XPANSION_BAR             0x38

#define     CNXK_CONFIG_PCIE_CAP                 0x70
#define     CNXK_CONFIG_PCIE_DEVCAP              0x74
#define     CNXK_CONFIG_PCIE_DEVCTL              0x78
#define     CNXK_CONFIG_PCIE_LINKCAP             0x7C
#define     CNXK_CONFIG_PCIE_LINKCTL             0x80
#define     CNXK_CONFIG_PCIE_SLOTCAP             0x84
#define     CNXK_CONFIG_PCIE_SLOTCTL             0x88

#define     CNXK_PCIE_SRIOV_FDL                  0x188      /* 0x98 */
#define     CNXK_PCIE_SRIOV_FDL_BIT_POS          0x10
#define     CNXK_PCIE_SRIOV_FDL_MASK             0xFF

#define     CNXK_CONFIG_PCIE_FLTMSK              0x720

/*
  ##############  BAR0 Registers ################
*/

/* NOTE: Below registers are not accessible from host
 *
 * SDP_OUT_WMARK
 * SDP_GBL_CONTROL
 * SDP_PKIND_VALID
 * SDP_OUT_BP_ENX_W1C
 * SDP_OUT_BP_ENX_W1S
 * SDP_CONST
 * SDP_ECCX_CTL
 * SDP_ECCX_FLIP
 * SDP_BISTX_STATUS
 * SDP_DIAG
 *
 * SDP_S2M_REGX_ACC
 * SDP_S2M_CTL
 * SDP_SCTL
 * SDP_S2M_MACX_CTL
 * SDP_M2S_MACX_CTL
 * SDP_BIST_STATUS
 * SDP_MEM_CTL
 * SDP_MEM_FLIP
 * SDP_END_MERGE
 * SDP_BAR3_ADDR
 * SDP_LMAC_CONSTX
 * SDP_LMAC_CONST1X
 * SDP_S2M_REGX_ACC2
 *
 * Interrupt registers: [/W1S/ENA_W1C/ENA_W1S]

 * SDP_MAC_INT_SUM          Interrupt bit summary for one mac
 * SDP_EPFX_DMA_VF_LINT     error int for a VF DMA read transaction
 * SDP_EPFX_MISC_LINT       Different int summary bits for a MAC
 * SDP_EPFX_PP_VF_LINT      error int for a VF PP read transaction
 * SDP_ECCX_LINT            ECC int summary for the SDP
 * SDP_EPFX_IERR_LINT       Error has been detected on input ring-i
 * SDP_EPFX_OERR_LINT       Error has been detected on output ring-i
 * SDP_EPFX_FLR_VF_LINT     When a VF causes an FLR. 
 * SDP_MBE_INT              ECC int summary bits of sli.
 *
 */

/* ################# Offsets of RING, EPF, MAC ######################### */
#define    CNXK_RING_OFFSET                      (0x1ULL << 17)
#define    CNXK_EPF_OFFSET                       (0x1ULL << 25)
#define    CNXK_MAC_OFFSET                       (0x1ULL << 4)
#define    CNXK_EPVF_RING_OFFSET                 (0x1ULL << 4)

/* ################# Scratch Registers ######################### */
/* TODO: VSR: add support for multi EPF */
#define    CNXK_SDP_EPF_SCRATCH                  0x209E0

/* ################# Window Registers ######################### */
#define    CNXK_SDP_WIN_WR_ADDR_LO               0x20000
#define    CNXK_SDP_WIN_WR_ADDR_HI               0x20004
#define    CNXK_SDP_WIN_WR_ADDR64                CNXK_SDP_WIN_WR_ADDR_LO
#define    CNXK_SDP_WIN_RD_ADDR_LO               0x20010
#define    CNXK_SDP_WIN_RD_ADDR_HI               0x20014
#define    CNXK_SDP_WIN_RD_ADDR64                CNXK_SDP_WIN_RD_ADDR_LO
#define    CNXK_SDP_WIN_WR_DATA_LO               0x20020
#define    CNXK_SDP_WIN_WR_DATA_HI               0x20024
#define    CNXK_SDP_WIN_WR_DATA64                CNXK_SDP_WIN_WR_DATA_LO
#define    CNXK_SDP_WIN_WR_MASK_LO               0x20030
#define    CNXK_SDP_WIN_WR_MASK_HI               0x20034
#define    CNXK_SDP_WIN_WR_MASK_REG              CNXK_SDP_WIN_WR_MASK_LO
#define    CNXK_SDP_WIN_RD_DATA_LO               0x20040
#define    CNXK_SDP_WIN_RD_DATA_HI               0x20044
#define    CNXK_SDP_WIN_RD_DATA64                CNXK_SDP_WIN_RD_DATA_LO

#define    CNXK_SDP_MAC_NUMBER                   0x2C100

/* ################# Global Previliged registers ######################### */
#define    CNXK_SDP_EPF_RINFO                   0x209F0

/* ------------------  Masks Prviliged Registers ----------------------------------- */
#define    CNXK_SDP_EPF_RINFO_SRN                (0x7FULL)
#define    CNXK_SDP_EPF_RINFO_RPVF               (0xFULL << 32)
#define    CNXK_SDP_EPF_RINFO_NVFS               (0x7FULL << 48)

/* Starting bit of SRN field in CNXK_SDP_PKT_MAC_RINFO64 register */
#define    CNXK_SDP_EPF_RINFO_SRN_BIT_POS        0
/* Starting bit of RPVF field in CNXK_SDP_PKT_MAC_RINFO64 register */
#define    CNXK_SDP_EPF_RINFO_RPVF_BIT_POS       32
/* Starting bit of NVFS field in CNXK_SDP_PKT_MAC_RINFO64 register */
#define    CNXK_SDP_EPF_RINFO_NVFS_BIT_POS       48

/* SDP Function select */
/* SDP_FUNC_SEL_S[7:8]: Physical Function */
#define    CNXK_SDP_FUNC_SEL_EPF_BIT_POS         7
/* SDP_FUNC_SEL_S[6:0]: Function within Physical Function */
#define    CNXK_SDP_FUNC_SEL_FUNC_BIT_POS        0

/*###################### RING IN REGISTERS #########################*/

#define    CNXK_SDP_R_IN_CONTROL_START           0x10000
#define    CNXK_SDP_R_IN_ENABLE_START            0x10010
#define    CNXK_SDP_R_IN_INSTR_BADDR_START       0x10020
#define    CNXK_SDP_R_IN_INSTR_RSIZE_START       0x10030
#define    CNXK_SDP_R_IN_INSTR_DBELL_START       0x10040
#define    CNXK_SDP_R_IN_CNTS_START              0x10050
#define    CNXK_SDP_R_IN_INT_LEVELS_START        0x10060
#define    CNXK_SDP_R_IN_PKT_CNT_START           0x10080
#define    CNXK_SDP_R_IN_BYTE_CNT_START          0x10090

#define    CNXK_SDP_R_IN_CONTROL(ring)          \
       (CNXK_SDP_R_IN_CONTROL_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_ENABLE(ring)          \
       (CNXK_SDP_R_IN_ENABLE_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INSTR_BADDR(ring)          \
       (CNXK_SDP_R_IN_INSTR_BADDR_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INSTR_RSIZE(ring)          \
       (CNXK_SDP_R_IN_INSTR_RSIZE_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INSTR_DBELL(ring)          \
       (CNXK_SDP_R_IN_INSTR_DBELL_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_CNTS(ring)          \
       (CNXK_SDP_R_IN_CNTS_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INT_LEVELS(ring)          \
       (CNXK_SDP_R_IN_INT_LEVELS_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_PKT_CNT(ring)          \
       (CNXK_SDP_R_IN_PKT_CNT_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_BYTE_CNT(ring)          \
       (CNXK_SDP_R_IN_BYTE_CNT_START + ((ring) * CNXK_RING_OFFSET))


/*------------------ R_IN Masks ----------------*/

/** Rings per Virtual Function **/
#define    CNXK_R_IN_CTL_RPVF_MASK       	(0xF)
#define	   CNXK_R_IN_CTL_RPVF_POS		(48)

/* Number of instructions to be read in one MAC read request. 
 * setting to Max value(4)
 **/
#define    CNXK_R_IN_CTL_IDLE                    (0x1ULL << 28)
#define    CNXK_R_IN_CTL_RDSIZE                  (0x3ULL << 25)
#define    CNXK_R_IN_CTL_IS_64B                  (0x1ULL << 24)
#define    CNXK_R_IN_CTL_D_NSR                   (0x1ULL << 8)
#define    CNXK_R_IN_CTL_D_ROR                   (0x1ULL << 5)
#define    CNXK_R_IN_CTL_NSR                     (0x1ULL << 3)
#define    CNXK_R_IN_CTL_ROR                     (0x1ULL << 0)

#define    CNXK_R_IN_CTL_MASK                    \
            ( CNXK_R_IN_CTL_RDSIZE                \
            | CNXK_R_IN_CTL_IS_64B)

/*###################### RING OUT REGISTERS #########################*/
#define    CNXK_SDP_R_OUT_CNTS_START              0x10100
#define    CNXK_SDP_R_OUT_INT_LEVELS_START        0x10110
#define    CNXK_SDP_R_OUT_SLIST_BADDR_START       0x10120
#define    CNXK_SDP_R_OUT_SLIST_RSIZE_START       0x10130
#define    CNXK_SDP_R_OUT_SLIST_DBELL_START       0x10140
#define    CNXK_SDP_R_OUT_CONTROL_START           0x10150
/* VSR: TODO: WMARK need to be set; New in CN10K */
#define    CNXK_SDP_R_OUT_WMARK_START             0x10160
#define    CNXK_SDP_R_OUT_ENABLE_START            0x10170
#define    CNXK_SDP_R_OUT_PKT_CNT_START           0x10180
#define    CNXK_SDP_R_OUT_BYTE_CNT_START          0x10190

#define    CNXK_SDP_R_OUT_CNTS(ring)          \
       (CNXK_SDP_R_OUT_CNTS_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_INT_LEVELS(ring)          \
       (CNXK_SDP_R_OUT_INT_LEVELS_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_SLIST_BADDR(ring)          \
       (CNXK_SDP_R_OUT_SLIST_BADDR_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_SLIST_RSIZE(ring)          \
       (CNXK_SDP_R_OUT_SLIST_RSIZE_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_SLIST_DBELL(ring)          \
       (CNXK_SDP_R_OUT_SLIST_DBELL_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_CONTROL(ring)          \
       (CNXK_SDP_R_OUT_CONTROL_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_WMARK(ring)          \
       (CNXK_SDP_R_OUT_WMARK_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_ENABLE(ring)          \
       (CNXK_SDP_R_OUT_ENABLE_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_PKT_CNT(ring)          \
       (CNXK_SDP_R_OUT_PKT_CNT_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_BYTE_CNT(ring)          \
       (CNXK_SDP_R_OUT_BYTE_CNT_START + ((ring) * CNXK_RING_OFFSET))

/*------------------ R_OUT Masks ----------------*/
#define    CNXK_R_OUT_INT_LEVELS_BMODE            (1ULL << 63)
#define    CNXK_R_OUT_INT_LEVELS_TIMET            (32)

#define    CNXK_R_OUT_CTL_IDLE                    (1ULL << 40)
#define    CNXK_R_OUT_CTL_NSR_I                   (1ULL << 33)
#define    CNXK_R_OUT_CTL_ROR_I                   (1ULL << 32)
#define    CNXK_R_OUT_CTL_NSR_D                   (1ULL << 29)
#define    CNXK_R_OUT_CTL_ROR_D                   (1ULL << 28)
#define    CNXK_R_OUT_CTL_NSR_P                   (1ULL << 25)
#define    CNXK_R_OUT_CTL_ROR_P                   (1ULL << 24)
#define    CNXK_R_OUT_CTL_IMODE                   (1ULL << 23)


/* ############### Interrupt Moderate Registers ###################### */

#define CNXK_SDP_R_IN_INT_MDRT_CTL0_START         0x10280
#define CNXK_SDP_R_IN_INT_MDRT_CTL1_START         0x102A0
#define CNXK_SDP_R_IN_INT_MDRT_DBG_START          0x102C0

#define CNXK_SDP_R_OUT_INT_MDRT_CTL0_START        0x10380
#define CNXK_SDP_R_OUT_INT_MDRT_CTL1_START        0x103A0
#define CNXK_SDP_R_OUT_INT_MDRT_DBG_START         0x103C0


#define CNXK_SDP_R_MBOX_ISM_START                 0x10500
#define CNXK_SDP_R_OUT_CNTS_ISM_START             0x10510
#define CNXK_SDP_R_IN_CNTS_ISM_START              0x10520


#define    CNXK_SDP_R_IN_INT_MDRT_CTL0(ring)          \
       (CNXK_SDP_R_IN_INT_MDRT_CTL0_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INT_MDRT_CTL1(ring)          \
       (CNXK_SDP_R_IN_INT_MDRT_CTL1_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_INT_MDRT_DBG(ring)          \
       (CNXK_SDP_R_IN_INT_MDRT_DBG_START + ((ring) * CNXK_RING_OFFSET))


#define    CNXK_SDP_R_OUT_INT_MDRT_CTL0(ring)          \
       (CNXK_SDP_R_OUT_INT_MDRT_CTL0_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_INT_MDRT_CTL1(ring)          \
       (CNXK_SDP_R_OUT_INT_MDRT_CTL1_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_INT_MDRT_DBG(ring)          \
       (CNXK_SDP_R_OUT_INT_MDRT_DBG_START + ((ring) * CNXK_RING_OFFSET))


#define    CNXK_SDP_R_MBOX_ISM(ring)          \
       (CNXK_SDP_R_MBOX_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_OUT_CNTS_ISM(ring)          \
       (CNXK_SDP_R_OUT_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_IN_CNTS_ISM(ring)          \
       (CNXK_SDP_R_IN_CNTS_ISM_START + ((ring) * CNXK_RING_OFFSET))


/* ##################### Mail Box Registers ########################## */
/* INT register for VF. when a MBOX write from PF happed to a VF, 
 * corresponding bit will be set in this register as well as in PF_VF_INT register. 
 * This is a RO register, the int can be cleared by writing 1 to PF_VF_INT */
/* Basically first 3 are from PF to VF. The last one is data from VF to PF */
/* VSR: check if any difference in mbox hanlding in CN10K */
#define    CNXK_SDP_R_MBOX_PF_VF_DATA_START       0x10210
#define    CNXK_SDP_R_MBOX_PF_VF_INT_START        0x10220
#define    CNXK_SDP_R_MBOX_VF_PF_DATA_START       0x10230

#define    CNXK_SDP_R_MBOX_PF_VF_DATA(ring)          \
       (CNXK_SDP_R_MBOX_PF_VF_DATA_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_MBOX_PF_VF_INT(ring)          \
       (CNXK_SDP_R_MBOX_PF_VF_INT_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_R_MBOX_VF_PF_DATA(ring)          \
       (CNXK_SDP_R_MBOX_VF_PF_DATA_START + ((ring) * CNXK_RING_OFFSET))

#define    CNXK_SDP_MBOX_VF_PF_DATA_START       0x24000
#define    CNXK_SDP_MBOX_PF_VF_DATA_START       0x22000

#define    CNXK_SDP_MBOX_VF_PF_DATA(ring)          \
       (CNXK_SDP_MBOX_VF_PF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET ))
#define    CNXK_SDP_MBOX_PF_VF_DATA(ring)      \
       (CNXK_SDP_MBOX_PF_VF_DATA_START + ((ring) * CNXK_EPVF_RING_OFFSET ))

/* ##################### Interrupt Registers ########################## */

/* In PF: Each bit indicates a ring that is signalling interrupt. 
 * In VF: 
 *           7 - 0: indicates input ring that is signalling interrupts. 
 *          15 - 8: indicates output ring that is signalling interrupts. 
 *          23 - 16: indicates mailbox interrupt. 
 */

#define	   CNXK_SDP_R_ERR_TYPE_START		0x10400

#define	   CNXK_SDP_EPF_MBOX_RINT		0x20100
#define	   CNXK_SDP_EPF_MBOX_RINT_W1S		0x20120
#define	   CNXK_SDP_EPF_MBOX_RINT_ENA_W1C	0x20140
#define	   CNXK_SDP_EPF_MBOX_RINT_ENA_W1S	0x20160

#define	   CNXK_SDP_EPF_VFIRE_RINT		0x20180
#define	   CNXK_SDP_EPF_VFIRE_RINT_W1S		0x201A0
#define	   CNXK_SDP_EPF_VFIRE_RINT_ENA_W1C	0x201C0
#define	   CNXK_SDP_EPF_VFIRE_RINT_ENA_W1S	0x201E0

#define	   CNXK_SDP_EPF_IRERR_RINT		0x20200
#define	   CNXK_SDP_EPF_IRERR_RINT_W1S		0x20210
#define	   CNXK_SDP_EPF_IRERR_RINT_ENA_W1C	0x20220
#define	   CNXK_SDP_EPF_IRERR_RINT_ENA_W1S	0x20230

#define	   CNXK_SDP_EPF_VFORE_RINT		0x20240
#define	   CNXK_SDP_EPF_VFORE_RINT_W1S		0x20260
#define	   CNXK_SDP_EPF_VFORE_RINT_ENA_W1C	0x20280
#define	   CNXK_SDP_EPF_VFORE_RINT_ENA_W1S	0x202A0

#define	   CNXK_SDP_EPF_ORERR_RINT		0x20320
#define	   CNXK_SDP_EPF_ORERR_RINT_W1S		0x20330
#define	   CNXK_SDP_EPF_ORERR_RINT_ENA_W1C	0x20340
#define	   CNXK_SDP_EPF_ORERR_RINT_ENA_W1S	0x20350

#define	   CNXK_SDP_EPF_OEI_RINT		0x20400
#define	   CNXK_SDP_EPF_OEI_RINT_W1S		0x20500
#define	   CNXK_SDP_EPF_OEI_RINT_ENA_W1C	0x20600
#define	   CNXK_SDP_EPF_OEI_RINT_ENA_W1S	0x20700

#define	   CNXK_SDP_EPF_DMA_RINT		0x20800
#define	   CNXK_SDP_EPF_DMA_RINT_W1S		0x20810
#define	   CNXK_SDP_EPF_DMA_RINT_ENA_W1C	0x20820
#define	   CNXK_SDP_EPF_DMA_RINT_ENA_W1S	0x20830

#define	   CNXK_SDP_EPF_DMA_INT_LEVEL		0x20840
#define	   CNXK_SDP_EPF_DMA_CNT			0x20860
#define	   CNXK_SDP_EPF_DMA_TIM			0x20880

#define	   CNXK_SDP_EPF_MISC_RINT		0x208A0
#define	   CNXK_SDP_EPF_MISC_RINT_W1S		0x208B0
#define	   CNXK_SDP_EPF_MISC_RINT_ENA_W1C	0x208C0
#define	   CNXK_SDP_EPF_MISC_RINT_ENA_W1S	0x208D0

#define	   CNXK_SDP_EPF_DMA_VF_RINT		0x208E0
#define	   CNXK_SDP_EPF_DMA_VF_RINT_W1S		0x20900
#define	   CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1C	0x20920
#define	   CNXK_SDP_EPF_DMA_VF_RINT_ENA_W1S	0x20940

#define	   CNXK_SDP_EPF_PP_VF_RINT		0x20960
#define	   CNXK_SDP_EPF_PP_VF_RINT_W1S		0x20980
#define	   CNXK_SDP_EPF_PP_VF_RINT_ENA_W1C	0x209A0
#define	   CNXK_SDP_EPF_PP_VF_RINT_ENA_W1S	0x209C0

#define    CNXK_SDP_R_ERR_TYPE(ring)          \
       (CNXK_SDP_R_ERR_TYPE_START + ((ring) * CNXK_RING_OFFSET))

/* VSR: TODO: single OEI_TRIG CSR replaced with 16 in cn10k; handle it in NPU */
//SDP(0)_EPF(0..3)_OEI_TRIG(0..15) (old: SDPX_EPFX_OEI_TRIG(0..1)(0..15))

/*------------------ Interrupt Masks ----------------*/

#define	   CNXK_INTR_R_SEND_ISM		(1ULL << 63)
#define	   CNXK_INTR_R_OUT_INT		(1ULL << 62)
#define    CNXK_INTR_R_IN_INT		(1ULL << 61)
#define    CNXK_INTR_R_MBOX_INT		(1ULL << 60)
#define    CNXK_INTR_R_RESEND		(1ULL << 59)

/* ####################### Ring Mapping Registers ################################## */

#define    CNXK_SDP_EPVF_RING_START      	0x26000 
#define    CNXK_SDP_IN_RING_TB_MAP_START 	0x28000 
#define    CNXK_SDP_IN_RATE_LIMIT_START  	0x2A000 
#define    CNXK_SDP_MAC_PF_RING_CTL_START	0x2C000 


#define	   CNXK_SDP_EPVF_RING(ring)	            \
                (CNXK_SDP_EPVF_RING_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define	   CNXK_SDP_IN_RING_TB_MAP(ring)	            \
                (CNXK_SDP_N_RING_TB_MAP_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define	   CNXK_SDP_IN_RATE_LIMIT(ring)	            \
                (CNXK_SDP_IN_RATE_LIMIT_START + ((ring) * CNXK_EPVF_RING_OFFSET))
#define	   CNXK_SDP_MAC_PF_RING_CTL(mac)	            \
                (CNXK_SDP_MAC_PF_RING_CTL_START + ((mac) * CNXK_MAC_OFFSET))

/* Starting bit of NPFS field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_NPFS_BIT_POS	0
/* Width of NPFS field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_NPFS		0x3
/* Starting bit of SRN field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_SRN_BIT_POS		8
/* Width of SRN field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_SRN			0x7F
/* Starting bit of RPPF field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_RPPF_BIT_POS	16
/* Width of RPPF field in CNXK_SDP_MAC_PF_RING_CTL register */
#define    CNXK_SDP_MAC_PF_RING_CTL_RPPF		0x3F

/* ######################## PEM Specific Registers ######################## */
/** PEM(0..5)_BAR4_INDEX(0..15)address is defined as
 *  addr = (0x8E0000000700 | port << 36 | idx << 3 )
 *  Here, port is PEM(0..5) & idx is INDEX(0..15)
 **/

#define    CNXK_PEM_BAR4_INDEX_START             0x8E0000000700ULL
#define    CNXK_PEM_OFFSET                       36
#define    CNXK_BAR4_INDEX_OFFSET                3

#define    CNXK_PEM_BAR4_INDEX_REG(port, idx)              \
           (CNXK_PEM_BAR4_INDEX_START + ((port * 1ULL) << CNXK_PEM_OFFSET) + \
			((idx) << CNXK_BAR4_INDEX_OFFSET) )
/*
 * This register is only supported on CNXK.
 * This register only supports 32 bit accesses.
 * Address generation is not well documented, and this has been tested
 * with 0x418, but is expected to work 4 byte aligned addresses as well.
 */

#define CNXK_PEMX_PFX_CSX_PFCFGX(pem,pf,offset)      ((0x8e0000008000 | (uint64_t)pem << 36 \
						| pf << 18 \
						| ((offset >> 16) & 1) << 16 \
						| (offset >> 3) << 3) \
						+ (((offset >> 2) & 1) << 2))

/* Register defines for use with CNXK_PEMX_PFX_CSX_PFCFGX */
#define CNXK_PCIEEP_VSECST_CTL	0x418

/*---------------   PCI BAR4 index registers -------------*/

/* BAR4 Mask */
#define    PCI_BAR4_ENABLE_CA            1
#define    PCI_BAR4_ENTRY_VALID          1
#define    PCI_BAR4_MASK                 ((PCI_BAR4_ENABLE_CA << 3)   \
                                          | PCI_BAR4_ENTRY_VALID )


#define    INVALID_MAP    0xffff
		   
#endif

/* $Id:$ */
