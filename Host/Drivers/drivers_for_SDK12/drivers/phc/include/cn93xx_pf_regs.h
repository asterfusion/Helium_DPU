/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cn93xx_pf_regs.h
    \brief Host Driver: Register Address and Register Mask values for
                        Octeon CN93XX devices.
*/

#ifndef __CN93XX_PF_REGS_H__
#define __CN93XX_PF_REGS_H__
/*############################ RST #########################*/
#define    CN93XX_RST_SOFT_RST        0x000087E006001680ULL   //TODO: not defined these address in HRM.
#define    CN93XX_RST_BOOT            0x000087E006001600ULL

#define    CN93XX_RST_CORE_DOMAIN_W1S    0x000087E006001820ULL
#define    CN93XX_RST_CORE_DOMAIN_W1C    0x000087E006001828ULL

/*
 * PTP register offsets from base of PTP block.  These are used
 * along with a BAR4 region mapping to read them.  The BAR4
 * mapping must be set up by Octeon, as the some BAR4 configuration
 * registers are not accessible from the host.
 */
#define    CN93XX_MIO_PTP_BAR4_REGION               14
#define    CN93XX_MIO_PTP_CLOCK_CFG_OFFSET          0xf00
#define    CN93XX_MIO_PTP_CLOCK_HI_OFFSET           0xf10
#define    CN93XX_MIO_PTP_CKOUT_THRESH_HI_OFFSET    0xf38
#define    CN93XX_MIO_PTP_CLOCK_SEC_OFFSET          0xfd0

#define     CN93XX_CONFIG_XPANSION_BAR             0x38

#define     CN93XX_CONFIG_PCIE_CAP                 0x70
#define     CN93XX_CONFIG_PCIE_DEVCAP              0x74
#define     CN93XX_CONFIG_PCIE_DEVCTL              0x78
#define     CN93XX_CONFIG_PCIE_LINKCAP             0x7C
#define     CN93XX_CONFIG_PCIE_LINKCTL             0x80
#define     CN93XX_CONFIG_PCIE_SLOTCAP             0x84
#define     CN93XX_CONFIG_PCIE_SLOTCTL             0x88

#define     CN93XX_PCIE_SRIOV_FDL                  0x188      /* 0x98 */
#define     CN93XX_PCIE_SRIOV_FDL_BIT_POS          0x10
#define     CN93XX_PCIE_SRIOV_FDL_MASK             0xFF

#define     CN93XX_CONFIG_PCIE_FLTMSK              0x720

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
#define    CN93XX_RING_OFFSET                      (0x1ULL << 17)
#define    CN93XX_EPF_OFFSET                       (0x1ULL << 25)
#define    CN93XX_MAC_OFFSET                       (0x1ULL << 4)
#define    CN93XX_BIT_ARRAY_OFFSET                 (0x1ULL << 4)
#define    CN93XX_EPVF_RING_OFFSET                 (0x1ULL << 4)

/* ################# Scratch Registers ######################### */
#define    CN93XX_SDP_EPF_SCRATCH                  0x205E0

/* ################# Window Registers ######################### */
#define    CN93XX_SDP_WIN_WR_ADDR_LO               0x20000
#define    CN93XX_SDP_WIN_WR_ADDR_HI               0x20004
#define    CN93XX_SDP_WIN_WR_ADDR64                CN93XX_SDP_WIN_WR_ADDR_LO
#define    CN93XX_SDP_WIN_RD_ADDR_LO               0x20010
#define    CN93XX_SDP_WIN_RD_ADDR_HI               0x20014
#define    CN93XX_SDP_WIN_RD_ADDR64                CN93XX_SDP_WIN_RD_ADDR_LO
#define    CN93XX_SDP_WIN_WR_DATA_LO               0x20020
#define    CN93XX_SDP_WIN_WR_DATA_HI               0x20024
#define    CN93XX_SDP_WIN_WR_DATA64                CN93XX_SDP_WIN_WR_DATA_LO
#define    CN93XX_SDP_WIN_WR_MASK_LO               0x20030
#define    CN93XX_SDP_WIN_WR_MASK_HI               0x20034
#define    CN93XX_SDP_WIN_WR_MASK_REG              CN93XX_SDP_WIN_WR_MASK_LO
#define    CN93XX_SDP_WIN_RD_DATA_LO               0x20040
#define    CN93XX_SDP_WIN_RD_DATA_HI               0x20044
#define    CN93XX_SDP_WIN_RD_DATA64                CN93XX_SDP_WIN_RD_DATA_LO

#define    CN93XX_SDP_MAC_NUMBER                   0x2C100

/* ################# Global Previliged registers ######################### */
#define    CN93XX_SDP_EPF_RINFO                    0x205F0

/* ------------------  Masks Prviliged Registers ----------------------------------- */
#define    CN93XX_SDP_EPF_RINFO_SRN                (0xFFULL)
#define    CN93XX_SDP_EPF_RINFO_RPVF               (0xFULL << 32)
#define    CN93XX_SDP_EPF_RINFO_NVFS               (0xFFULL << 48)

/* Starting bit of SRN field in CN93XX_SDP_PKT_MAC_RINFO64 register */
#define    CN93XX_SDP_EPF_RINFO_SRN_BIT_POS        0
/* Starting bit of RPVF field in CN93XX_SDP_PKT_MAC_RINFO64 register */
#define    CN93XX_SDP_EPF_RINFO_RPVF_BIT_POS       32
/* Starting bit of NVFS field in CN93XX_SDP_PKT_MAC_RINFO64 register */
#define    CN93XX_SDP_EPF_RINFO_NVFS_BIT_POS       48

/* SDP Function select */
#define    CN93XX_SDP_FUNC_SEL_EPF_BIT_POS         8
#define    CN93XX_SDP_FUNC_SEL_FUNC_BIT_POS        0

/*###################### RING IN REGISTERS #########################*/

#define    CN93XX_SDP_R_IN_CONTROL_START           0x10000

#define    CN93XX_SDP_R_IN_ENABLE_START            0x10010

#define    CN93XX_SDP_R_IN_INSTR_BADDR_START       0x10020

#define    CN93XX_SDP_R_IN_INSTR_RSIZE_START       0x10030

#define    CN93XX_SDP_R_IN_INSTR_DBELL_START       0x10040

#define    CN93XX_SDP_R_IN_CNTS_START              0x10050

#define    CN93XX_SDP_R_IN_INT_LEVELS_START        0x10060

//#define    CN93XX_SDP_R_IN_INT_STATUS_START      0x10070  //TODO not mentioned in HRM

#define    CN93XX_SDP_R_IN_PKT_CNT_START           0x10080

#define    CN93XX_SDP_R_IN_BYTE_CNT_START          0x10090

#define    CN93XX_SDP_R_IN_CONTROL(ring)          \
       (CN93XX_SDP_R_IN_CONTROL_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_ENABLE(ring)          \
       (CN93XX_SDP_R_IN_ENABLE_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INSTR_BADDR(ring)          \
       (CN93XX_SDP_R_IN_INSTR_BADDR_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INSTR_RSIZE(ring)          \
       (CN93XX_SDP_R_IN_INSTR_RSIZE_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INSTR_DBELL(ring)          \
       (CN93XX_SDP_R_IN_INSTR_DBELL_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_CNTS(ring)          \
       (CN93XX_SDP_R_IN_CNTS_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INT_LEVELS(ring)          \
       (CN93XX_SDP_R_IN_INT_LEVELS_START + ((ring) * CN93XX_RING_OFFSET))
#if 0
#define    CN93XX_SDP_R_IN_INT_STATUS(ring)          \
       (CN93XX_SDP_R_IN_INT_STATUS_START + ((ring) * CN93XX_RING_OFFSET))
#endif
#define    CN93XX_SDP_R_IN_PKT_CNT(ring)          \
       (CN93XX_SDP_R_IN_PKT_CNT_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_BYTE_CNT(ring)          \
       (CN93XX_SDP_R_IN_BYTE_CNT_START + ((ring) * CN93XX_RING_OFFSET))


/*------------------ R_IN Masks ----------------*/

/** Rings per Virtual Function **/
#define    CN93XX_R_IN_CTL_RPVF_MASK       	(0xF)
#define	   CN93XX_R_IN_CTL_RPVF_POS		    (48)

/* Number of instructions to be read in one MAC read request. 
 * setting to Max value(4)
 **/
#define    CN93XX_R_IN_CTL_IDLE                    (0x1ULL << 28)
#define    CN93XX_R_IN_CTL_RDSIZE                  (0x3ULL << 25)
#define    CN93XX_R_IN_CTL_IS_64B                  (0x1ULL << 24)
#define    CN93XX_R_IN_CTL_D_NSR                   (0x1ULL << 8)
#define    CN93XX_R_IN_CTL_D_ESR                   (0x1ULL << 6)
#define    CN93XX_R_IN_CTL_D_ROR                   (0x1ULL << 5)
#define    CN93XX_R_IN_CTL_NSR                     (0x1ULL << 3)
#define    CN93XX_R_IN_CTL_ESR                     (0x1ULL << 1)
#define    CN93XX_R_IN_CTL_ROR                     (0x1ULL << 0)

#define    CN93XX_R_IN_CTL_MASK                    \
            ( CN93XX_R_IN_CTL_RDSIZE                \
            | CN93XX_R_IN_CTL_IS_64B)

/*###################### RING OUT REGISTERS #########################*/
#define    CN93XX_SDP_R_OUT_CNTS_START              0x10100

#define    CN93XX_SDP_R_OUT_INT_LEVELS_START        0x10110

#define    CN93XX_SDP_R_OUT_SLIST_BADDR_START       0x10120

#define    CN93XX_SDP_R_OUT_SLIST_RSIZE_START       0x10130

#define    CN93XX_SDP_R_OUT_SLIST_DBELL_START       0x10140

#define    CN93XX_SDP_R_OUT_CONTROL_START           0x10150

#define    CN93XX_SDP_R_OUT_ENABLE_START            0x10160

//#define    CN93XX_SDP_R_OUT_INT_STATUS_START        0x10170  //TODO, not provided in HRM

#define    CN93XX_SDP_R_OUT_PKT_CNT_START           0x10180

#define    CN93XX_SDP_R_OUT_BYTE_CNT_START          0x10190

#define    CN93XX_SDP_R_OUT_CONTROL(ring)          \
       (CN93XX_SDP_R_OUT_CONTROL_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_ENABLE(ring)          \
       (CN93XX_SDP_R_OUT_ENABLE_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_SLIST_BADDR(ring)          \
       (CN93XX_SDP_R_OUT_SLIST_BADDR_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_SLIST_RSIZE(ring)          \
       (CN93XX_SDP_R_OUT_SLIST_RSIZE_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_SLIST_DBELL(ring)          \
       (CN93XX_SDP_R_OUT_SLIST_DBELL_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_CNTS(ring)          \
       (CN93XX_SDP_R_OUT_CNTS_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_INT_LEVELS(ring)          \
       (CN93XX_SDP_R_OUT_INT_LEVELS_START + ((ring) * CN93XX_RING_OFFSET))
#if 0
#define    CN93XX_SDP_R_OUT_INT_STATUS(ring)          \
       (CN93XX_SDP_R_OUT_INT_STATUS_START + ((ring) * CN93XX_RING_OFFSET))
#endif
#define    CN93XX_SDP_R_OUT_PKT_CNT(ring)          \
       (CN93XX_SDP_R_OUT_PKT_CNT_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_BYTE_CNT(ring)          \
       (CN93XX_SDP_R_OUT_BYTE_CNT_START + ((ring) * CN93XX_RING_OFFSET))

/*------------------ R_OUT Masks ----------------*/
#define    CN93XX_R_OUT_INT_LEVELS_BMODE            (1ULL << 63)
#define    CN93XX_R_OUT_INT_LEVELS_TIMET            (32)

#define    CN93XX_R_OUT_CTL_IDLE                    (1ULL << 40)
#define    CN93XX_R_OUT_CTL_ES_I                    (1ULL << 34)
#define    CN93XX_R_OUT_CTL_NSR_I                   (1ULL << 33)
#define    CN93XX_R_OUT_CTL_ROR_I                   (1ULL << 32)
#define    CN93XX_R_OUT_CTL_ES_D                    (1ULL << 30)
#define    CN93XX_R_OUT_CTL_NSR_D                   (1ULL << 29)
#define    CN93XX_R_OUT_CTL_ROR_D                   (1ULL << 28)
#define    CN93XX_R_OUT_CTL_ES_P                    (1ULL << 26)
#define    CN93XX_R_OUT_CTL_NSR_P                   (1ULL << 25)
#define    CN93XX_R_OUT_CTL_ROR_P                   (1ULL << 24)
#define    CN93XX_R_OUT_CTL_IMODE                   (1ULL << 23)


/* ############### Interrupt Moderate Registers ###################### */

#define CN93XX_SDP_R_IN_INT_MDRT_CTL0_START         0x10280
#define CN93XX_SDP_R_IN_INT_MDRT_CTL1_START         0x102A0
#define CN93XX_SDP_R_IN_INT_MDRT_DBG_START          0x102C0

#define CN93XX_SDP_R_OUT_INT_MDRT_CTL0_START        0x10380
#define CN93XX_SDP_R_OUT_INT_MDRT_CTL1_START        0x103A0
#define CN93XX_SDP_R_OUT_INT_MDRT_DBG_START         0x103C0


#define CN93XX_SDP_R_MBOX_ISM_START                 0x10500
#define CN93XX_SDP_R_OUT_CNTS_ISM_START             0x10510
#define CN93XX_SDP_R_IN_CNTS_ISM_START              0x10520


#define    CN93XX_SDP_R_IN_INT_MDRT_CTL0(ring)          \
       (CN93XX_SDP_R_IN_INT_MDRT_CTL0_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INT_MDRT_CTL1(ring)          \
       (CN93XX_SDP_R_IN_INT_MDRT_CTL1_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_INT_MDRT_DBG(ring)          \
       (CN93XX_SDP_R_IN_INT_MDRT_DBG_START + ((ring) * CN93XX_RING_OFFSET))


#define    CN93XX_SDP_R_OUT_INT_MDRT_CTL0(ring)          \
       (CN93XX_SDP_R_OUT_INT_MDRT_CTL0_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_INT_MDRT_CTL1(ring)          \
       (CN93XX_SDP_R_OUT_INT_MDRT_CTL1_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_INT_MDRT_DBG(ring)          \
       (CN93XX_SDP_R_OUT_INT_MDRT_DBG_START + ((ring) * CN93XX_RING_OFFSET))


#define    CN93XX_SDP_R_MBOX_ISM(ring)          \
       (CN93XX_SDP_R_MBOX_ISM_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_OUT_CNTS_ISM(ring)          \
       (CN93XX_SDP_R_OUT_CNTS_ISM_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_IN_CNTS_ISM(ring)          \
       (CN93XX_SDP_R_IN_CNTS_ISM_START + ((ring) * CN93XX_RING_OFFSET))


/* ##################### Mail Box Registers ########################## */
//TODO: clean up the comment bfefore submission
/* INT register for VF. when a MBOX write from PF happed to a VF, 
 * corresponding bit will be set in this register as well as in PF_VF_INT register. 
 * This is a RO register, the int can be cleared by writing 1 to PF_VF_INT */
/* Basically first 3 are from PF to VF. The last one is data from VF to PF */

//#define	   CN93XX_SDP_R_MBOX_RINT_STATUS_START	     0x10200  //TODO , not provided in HRM

#define    CN93XX_SDP_R_MBOX_PF_VF_DATA_START       0x10210

#define    CN93XX_SDP_R_MBOX_PF_VF_INT_START        0x10220

#define    CN93XX_SDP_R_MBOX_VF_PF_DATA_START       0x10230

#define    CN93XX_SDP_MBOX_VF_PF_DATA_START       0x24000
#define    CN93XX_SDP_MBOX_PF_VF_DATA_START       0x22000

#if 0
#define    CN93XX_SDP_R_MBOX_RINT_STATUS(epf, ring)          \
       (CN93XX_SDP_R_MBOX_RINT_STATUS_START + ((ring) * CN93XX_RING_OFFSET))
#endif

#define    CN93XX_SDP_R_MBOX_PF_VF_DATA(ring)          \
       (CN93XX_SDP_R_MBOX_PF_VF_DATA_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_MBOX_PF_VF_INT(ring)          \
       (CN93XX_SDP_R_MBOX_PF_VF_INT_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_R_MBOX_VF_PF_DATA(ring)          \
       (CN93XX_SDP_R_MBOX_VF_PF_DATA_START + ((ring) * CN93XX_RING_OFFSET))

#define    CN93XX_SDP_MBOX_VF_PF_DATA(ring)          \
       (CN93XX_SDP_MBOX_VF_PF_DATA_START + ((ring) * CN93XX_EPVF_RING_OFFSET ))
#define    CN93XX_SDP_MBOX_PF_VF_DATA(ring)      \
       (CN93XX_SDP_MBOX_PF_VF_DATA_START + ((ring) * CN93XX_EPVF_RING_OFFSET ))

/* ##################### Interrupt Registers ########################## */

/* In PF: Each bit indicates a ring that is signalling interrupt. 
 * In VF: 
 *           7 - 0: indicates input ring that is signalling interrupts. 
 *          15 - 8: indicates output ring that is signalling interrupts. 
 *          23 - 16: indicates mailbox interrupt. 
 */

//#define	   CN93XX_SDP_EPF_R_ALL_IN_STATUS_START	        0x10300
#define	   CN93XX_SDP_R_ERR_TYPE_START	    0x10400

#define	   CN93XX_SDP_EPF_MBOX_RINT_START	    0x20100
#define	   CN93XX_SDP_EPF_MBOX_RINT_W1S_START	    0x20120
#define	   CN93XX_SDP_EPF_MBOX_RINT_ENA_W1C_START   0x20140
#define	   CN93XX_SDP_EPF_MBOX_RINT_ENA_W1S_START   0x20160

#define	   CN93XX_SDP_EPF_VFIRE_RINT_START          0x20180
#define	   CN93XX_SDP_EPF_VFIRE_RINT_W1S_START      0x201A0
#define	   CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1C_START  0x201C0
#define	   CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1S_START  0x201E0

#define	   CN93XX_SDP_EPF_IRERR_RINT                0x20200
#define	   CN93XX_SDP_EPF_IRERR_RINT_W1S            0x20210
#define	   CN93XX_SDP_EPF_IRERR_RINT_ENA_W1C        0x20220
#define	   CN93XX_SDP_EPF_IRERR_RINT_ENA_W1S        0x20230

#define	   CN93XX_SDP_EPF_VFORE_RINT_START          0x20240
#define	   CN93XX_SDP_EPF_VFORE_RINT_W1S_START      0x20260
#define	   CN93XX_SDP_EPF_VFORE_RINT_ENA_W1C_START  0x20280
#define	   CN93XX_SDP_EPF_VFORE_RINT_ENA_W1S_START  0x202A0

#define	   CN93XX_SDP_EPF_ORERR_RINT                0x20320
#define	   CN93XX_SDP_EPF_ORERR_RINT_W1S            0x20330
#define	   CN93XX_SDP_EPF_ORERR_RINT_ENA_W1C        0x20340
#define	   CN93XX_SDP_EPF_ORERR_RINT_ENA_W1S        0x20350

#define	   CN93XX_SDP_EPF_OEI_RINT                  0x20360
#define	   CN93XX_SDP_EPF_OEI_RINT_W1S              0x20370
#define	   CN93XX_SDP_EPF_OEI_RINT_ENA_W1C          0x20380
#define	   CN93XX_SDP_EPF_OEI_RINT_ENA_W1S          0x20390

#define	   CN93XX_SDP_EPF_DMA_RINT                  0x20400
#define	   CN93XX_SDP_EPF_DMA_RINT_W1S              0x20410
#define	   CN93XX_SDP_EPF_DMA_RINT_ENA_W1C          0x20420
#define	   CN93XX_SDP_EPF_DMA_RINT_ENA_W1S          0x20430

#define	   CN93XX_SDP_EPF_DMA_INT_LEVEL_START	    0x20440
#define	   CN93XX_SDP_EPF_DMA_CNT_START	            0x20460
#define	   CN93XX_SDP_EPF_DMA_TIM_START	            0x20480

#define	   CN93XX_SDP_EPF_MISC_RINT                 0x204A0
#define	   CN93XX_SDP_EPF_MISC_RINT_W1S	            0x204B0
#define	   CN93XX_SDP_EPF_MISC_RINT_ENA_W1C         0x204C0
#define	   CN93XX_SDP_EPF_MISC_RINT_ENA_W1S         0x204D0

#define	   CN93XX_SDP_EPF_DMA_VF_RINT_START           0x204E0
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_W1S_START       0x20500
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1C_START   0x20520
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1S_START   0x20540

#define	   CN93XX_SDP_EPF_PP_VF_RINT_START            0x20560
#define	   CN93XX_SDP_EPF_PP_VF_RINT_W1S_START        0x20580
#define	   CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1C_START    0x205A0
#define	   CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1S_START    0x205C0

#define    CN93XX_SDP_R_ERR_TYPE(ring)          \
       (CN93XX_SDP_R_ERR_TYPE_START + ((ring) * CN93XX_RING_OFFSET))

#define	   CN93XX_SDP_EPF_MBOX_RINT(index)	            \
                (CN93XX_SDP_EPF_MBOX_RINT_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_MBOX_RINT_W1S(index)	            \
                (CN93XX_SDP_EPF_MBOX_RINT_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_MBOX_RINT_ENA_W1C(index)	            \
                (CN93XX_SDP_EPF_MBOX_RINT_ENA_W1C_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_MBOX_RINT_ENA_W1S(index)	            \
                (CN93XX_SDP_EPF_MBOX_RINT_ENA_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))

#define	   CN93XX_SDP_EPF_VFIRE_RINT(index)	            \
                (CN93XX_SDP_EPF_VFIRE_RINT_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFIRE_RINT_W1S(index)	            \
                (CN93XX_SDP_EPF_VFIRE_RINT_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1C(index)	            \
                (CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1C_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1S(index)	            \
                (CN93XX_SDP_EPF_VFIRE_RINT_ENA_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))

#define	   CN93XX_SDP_EPF_VFORE_RINT(index)	            \
                (CN93XX_SDP_EPF_VFORE_RINT_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFORE_RINT_W1S(index)	            \
                (CN93XX_SDP_EPF_VFORE_RINT_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFORE_RINT_ENA_W1C(index)	            \
                (CN93XX_SDP_EPF_VFORE_RINT_ENA_W1C_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_VFORE_RINT_ENA_W1S(index)	            \
                (CN93XX_SDP_EPF_VFORE_RINT_ENA_W1S_START + ((index) * CN93XX_BIT_ARRAY_OFFSET))

#define	   CN93XX_SDP_EPF_DMA_VF_RINT(index)	            \
                (CN93XX_SDP_EPF_DMA_VF_RINT_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_W1S(index)	            \
                (CN93XX_SDP_EPF_DMA_VF_RINT_W1S_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1C(index)	            \
                (CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1C_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1S(index)	            \
                (CN93XX_SDP_EPF_DMA_VF_RINT_ENA_W1S_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))

#define	   CN93XX_SDP_EPF_PP_VF_RINT(index)	            \
                (CN93XX_SDP_EPF_PP_VF_RINT_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_PP_VF_RINT_W1S(index)	            \
                (CN93XX_SDP_EPF_PP_VF_RINT_W1S_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1C(index)	            \
                (CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1C_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))
#define	   CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1S(index)	            \
                (CN93XX_SDP_EPF_PP_VF_RINT_ENA_W1S_START + ((index) + CN93XX_BIT_ARRAY_OFFSET))


/*------------------ Interrupt Masks ----------------*/

#define	   CN93XX_INTR_R_SEND_ISM       (1ULL << 63)
#define	   CN93XX_INTR_R_OUT_INT        (1ULL << 62)
#define    CN93XX_INTR_R_IN_INT			(1ULL << 61)
#define    CN93XX_INTR_R_MBOX_INT		(1ULL << 60)
#define    CN93XX_INTR_R_RESEND			(1ULL << 59)
#define    CN93XX_INTR_R_CLR_TIM		(1ULL << 58)

/* ####################### Ring Mapping Registers ################################## */

#define    CN93XX_SDP_EPVF_RING_START      	            0x26000 
#define    CN93XX_SDP_IN_RING_TB_MAP_START 	            0x28000 
#define    CN93XX_SDP_IN_RATE_LIMIT_START  	            0x2A000 
#define    CN93XX_SDP_MAC_PF_RING_CTL_START	            0x2C000 


#define	   CN93XX_SDP_EPVF_RING(ring)	            \
                (CN93XX_SDP_EPVF_RING_START + ((ring) * CN93XX_EPVF_RING_OFFSET))
#define	   CN93XX_SDP_IN_RING_TB_MAP(ring)	            \
                (CN93XX_SDP_N_RING_TB_MAP_START + ((ring) * CN93XX_EPVF_RING_OFFSET))
#define	   CN93XX_SDP_IN_RATE_LIMIT(ring)	            \
                (CN93XX_SDP_IN_RATE_LIMIT_START + ((ring) * CN93XX_EPVF_RING_OFFSET))
#define	   CN93XX_SDP_MAC_PF_RING_CTL(mac)	            \
                (CN93XX_SDP_MAC_PF_RING_CTL_START + ((mac) * CN93XX_MAC_OFFSET))

/* Starting bit of NPFS field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_NPFS_BIT_POS	    0
/* Width of NPFS field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_NPFS		    0xF
/* Starting bit of SRN field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_SRN_BIT_POS	    8
/* Width of SRN field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_SRN		    0xFF
/* Starting bit of RPPF field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_RPPF_BIT_POS	    16
/* Width of RPPF field in CN93XX_SDP_MAC_PF_RING_CTL register */
#define    CN93XX_SDP_MAC_PF_RING_CTL_RPPF		    0x3F


#define    CN98XX_SDP_MAC_PF_RING_CTL_NPFS_BIT_POS	    48
#define    CN98XX_SDP_MAC_PF_RING_CTL_NPFS		    0xF
#define    CN98XX_SDP_MAC_PF_RING_CTL_RPPF_BIT_POS	    32
#define    CN98XX_SDP_MAC_PF_RING_CTL_RPPF		    0x3F
#define    CN98XX_SDP_MAC_PF_RING_CTL_SRN_BIT_POS	    0
#define    CN98XX_SDP_MAC_PF_RING_CTL_SRN		    0xFF
/* ############################# PEM Specific Registers ############################ */
/** PEM(0..3)_BAR1_INDEX(0..15)address is defined as
 *  addr = (0x00011800C0000100  |port <<24 |idx <<3 )
 *  Here, port is PEM(0..3) & idx is INDEX(0..15)
 **/

#define    CN93XX_PEM_BAR1_INDEX_START             0x000087E0C0000100ULL
#define    CN93XX_PEM_OFFSET                       24
#define    CN93XX_BAR1_INDEX_OFFSET                3

#define    CN93XX_PEM_BAR1_INDEX_REG(port, idx)              \
           (CN93XX_PEM_BAR1_INDEX_START + ((port) << CN93XX_PEM_OFFSET) +  \
			((idx) << CN93XX_BAR1_INDEX_OFFSET) )

#define CN93XX_PEMX_CFG_WR(a)		  (0x8E0000000018ULL | (a << 36))
/*---------------   PCI BAR1 index registers -------------*/

/* BAR1 Mask */
#define    PCI_BAR1_ENABLE_CA            1
#define    PCI_BAR1_ENDIAN_MODE          OCTEON_PCI_64BIT_SWAP
#define    PCI_BAR1_ENTRY_VALID          1
#define    PCI_BAR1_MASK                 (  (PCI_BAR1_ENABLE_CA << 3)   \
                                          | (PCI_BAR1_ENDIAN_MODE << 1) \
                                          | PCI_BAR1_ENTRY_VALID )


#define    INVALID_MAP    0xffff
/* For BAR4 mappings    */
#define PEMX_BASE(a)			(0x8E0000000000ull | \
					 (unsigned long long)a<<36)
#define BAR4_IDX_OFFSET(i)		(0x700ull | i<<3)
		   
#endif

/* $Id:$ */
