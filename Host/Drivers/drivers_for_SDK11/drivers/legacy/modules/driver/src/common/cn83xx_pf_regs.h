/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cn83xx_pf_regs.h
    \brief Host Driver: Register Address and Register Mask values for
                        Octeon CN83XX devices.
*/

#ifndef __CN83XX_PF_REGS_H__
#define __CN83XX_PF_REGS_H__
/*############################ RST #########################*/
#define    CN83XX_RST_SOFT_RST        0x000087E006001680ULL
#define    CN83XX_RST_BOOT            0x000087E006001600ULL

#define     CN83XX_CONFIG_XPANSION_BAR             0x38

#define     CN83XX_CONFIG_PCIE_CAP                 0x70
#define     CN83XX_CONFIG_PCIE_DEVCAP              0x74
#define     CN83XX_CONFIG_PCIE_DEVCTL              0x78
#define     CN83XX_CONFIG_PCIE_LINKCAP             0x7C
#define     CN83XX_CONFIG_PCIE_LINKCTL             0x80
#define     CN83XX_CONFIG_PCIE_SLOTCAP             0x84
#define     CN83XX_CONFIG_PCIE_SLOTCTL             0x88

//#define     CN83XX_PCIE_SRIOV_FDL                  0x188      /* 0x98 */
#define     CN83XX_PCIE_SRIOV_FDL_BIT_POS          0x10
#define     CN83XX_PCIE_SRIOV_FDL_MASK             0xFF

#define     CN83XX_CONFIG_PCIE_FLTMSK              0x720

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
 * SLI_S2M_REGX_ACC
 * SLI_S2M_CTL
 * SLI_SCTL
 * SLI_S2M_MACX_CTL
 * SLI_M2S_MACX_CTL
 * SLI_BIST_STATUS
 * SLI_MEM_CTL
 * SLI_MEM_FLIP
 * SLI_END_MERGE
 * SLI_BAR3_ADDR
 * SLI_LMAC_CONSTX
 * SLI_LMAC_CONST1X
 * SLI_S2M_REGX_ACC2
 *
 * Interrupt registers: [/W1S/ENA_W1C/ENA_W1S]

 * SLI_MAC_INT_SUM          Interrupt bit summary for one mac
 * SLI_EPFX_DMA_VF_LINT     error int for a VF DMA read transaction
 * SLI_EPFX_MISC_LINT       Different int summary bits for a MAC
 * SLI_EPFX_PP_VF_LINT      error int for a VF PP read transaction
 * SDP_ECCX_LINT            ECC int summary for the SDP
 * SDP_EPFX_IERR_LINT       Error has been detected on input ring-i
 * SDP_EPFX_OERR_LINT       Error has been detected on output ring-i
 * SDP_EPFX_FLR_VF_LINT     When a VF causes an FLR. 
 * SLI_MBE_INT              ECC int summary bits of sli.
 *
 */

/* ################# Offsets of RING and EPF ######################### */
#define    CN83XX_RING_OFFSET                       (0x1ULL << 17)
#define    CN83XX_EPF_OFFSET                        (0x0)

/* ################# Scratch Registers ######################### */
#define    CN83XX_SDP_SCRATCH_START                0x20180
#define    CN83XX_SDP_SCRATCH(index)                \
                ( CN83XX_SDP_SCRATCH_START  + ( (index) * CN83XX_EPF_OFFSET))

#define    CN83XX_SLI_EPF_SCRATCH_START            0x28100
#define    CN83XX_SLI_EPF_SCRATCH(index)                \
                ( CN83XX_SLI_EPF_SCRATCH_START  + ( (index) * CN83XX_EPF_OFFSET))

/* ################# Window Registers ######################### */
#define    CN83XX_SLI_WIN_WR_ADDR_LO_START                   0x2C000
#define    CN83XX_SLI_WIN_WR_ADDR_HI_START                   0x2C004
#define    CN83XX_SLI_WIN_WR_ADDR64_START                    CN83XX_SLI_WIN_WR_ADDR_LO_START
#define    CN83XX_SLI_WIN_RD_ADDR_LO_START                   0x2C010
#define    CN83XX_SLI_WIN_RD_ADDR_HI_START                   0x2C014
#define    CN83XX_SLI_WIN_RD_ADDR64_START                    CN83XX_SLI_WIN_RD_ADDR_LO_START
#define    CN83XX_SLI_WIN_WR_DATA_LO_START                   0x2C020
#define    CN83XX_SLI_WIN_WR_DATA_HI_START                   0x2C024
#define    CN83XX_SLI_WIN_WR_DATA64_START                    CN83XX_SLI_WIN_WR_DATA_LO_START
#define    CN83XX_SLI_WIN_WR_MASK_LO_START                   0x2C030
#define    CN83XX_SLI_WIN_WR_MASK_HI_START                   0x2C034
#define    CN83XX_SLI_WIN_WR_MASK_REG_START                  CN83XX_SLI_WIN_WR_MASK_LO_START
#define    CN83XX_SLI_WIN_RD_DATA_LO_START                   0x2C040
#define    CN83XX_SLI_WIN_RD_DATA_HI_START                   0x2C044
#define    CN83XX_SLI_WIN_RD_DATA64_START                    CN83XX_SLI_WIN_RD_DATA_LO_START
#define    CN83XX_SLI_MAC_NUMBER_START                       0x2C050

#define    CN83XX_SLI_WIN_WR_ADDR_LO(epf_num)                \
                ( CN83XX_SLI_WIN_WR_ADDR_LO_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_ADDR_HI(epf_num)                \
                ( CN83XX_SLI_WIN_WR_ADDR_HI_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_ADDR64(epf_num)                \
                ( CN83XX_SLI_WIN_WR_ADDR64_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_ADDR_LO(epf_num)                \
                ( CN83XX_SLI_WIN_RD_ADDR_LO_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_ADDR_HI(epf_num)                \
                ( CN83XX_SLI_WIN_RD_ADDR_HI_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_ADDR64(epf_num)                \
                ( CN83XX_SLI_WIN_RD_ADDR64_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_DATA_LO(epf_num)                \
                ( CN83XX_SLI_WIN_WR_DATA_LO_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_DATA_HI(epf_num)                \
                ( CN83XX_SLI_WIN_WR_DATA_HI_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_DATA64(epf_num)                \
                ( CN83XX_SLI_WIN_WR_DATA64_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_DATA_LO(epf_num)                \
                ( CN83XX_SLI_WIN_RD_DATA_LO_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_DATA_HI(epf_num)                \
                ( CN83XX_SLI_WIN_RD_DATA_HI_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_RD_DATA64(epf_num)                \
                ( CN83XX_SLI_WIN_RD_DATA64_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_MASK_LO(epf_num)                \
                ( CN83XX_SLI_WIN_WR_MASK_LO_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_MASK_HI(epf_num)                \
                ( CN83XX_SLI_WIN_WR_MASK_HI_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_WIN_WR_MASK_REG(epf_num)                \
                ( CN83XX_SLI_WIN_WR_MASK_REG_START  + ((epf_num) * CN83XX_EPF_OFFSET) )
#define    CN83XX_SLI_MAC_NUMBER(index)                \
                ( CN83XX_SLI_MAC_NUMBER_START  + ( (index) * CN83XX_EPF_OFFSET))

/* ################# Global Previliged registers ######################### */
#define    CN83XX_SDP_EPF_RINFO_START              0x20190

#define    CN83XX_SDP_EPF_R_VF_NUM_START           0x10500

#define    CN83XX_SDP_EPF_RINFO(epf)                \
            (CN83XX_SDP_EPF_RINFO_START + ( (epf) * CN83XX_EPF_OFFSET))

#define    CN83XX_SDP_EPF_R_VF_NUM(epf, ring)                \
            (CN83XX_SDP_EPF_R_VF_NUM_START + ( (epf) * CN83XX_EPF_OFFSET) + ( (ring * CN83XX_RING_OFFSET)))

/* ------------------  Masks Prviliged Registers ----------------------------------- */
#define    CN83XX_SDP_EPF_RINFO_SRN               (0x7FULL)
#define    CN83XX_SDP_EPF_RINFO_TRS               (0xFFULL << 16)
#define    CN83XX_SDP_EPF_RINFO_RPVF              (0x1FULL << 32)
#define    CN83XX_SDP_EPF_RINFO_NVFS              (0x7FULL << 48)

/* Starting bit of SRN field in CN83XX_SLI_PKT_MAC_RINFO64 register */
#define    CN83XX_SDP_EPF_RINFO_SRN_BIT_POS     0
/* Starting bit of the TRS field in CN83XX_SLI_PKT_MAC_RINFO64 register */
#define    CN83XX_SDP_EPF_RINFO_TRS_BIT_POS     16
/* Starting bit of RPVF field in CN83XX_SLI_PKT_MAC_RINFO64 register */
#define    CN83XX_SDP_EPF_RINFO_RPVF_BIT_POS     32
/* Starting bit of NVFS field in CN83XX_SLI_PKT_MAC_RINFO64 register */
#define    CN83XX_SDP_EPF_RINFO_NVFS_BIT_POS     48

/*###################### RING IN REGISTERS #########################*/

#define    CN83XX_SDP_EPF_R_IN_CONTROL_START    0x10000

#define    CN83XX_SDP_EPF_R_IN_ENABLE_START     0x10010

#define    CN83XX_SDP_EPF_R_IN_INSTR_BADDR_START      0x10020

#define    CN83XX_SDP_EPF_R_IN_INSTR_RSIZE_START      0x10030

#define    CN83XX_SDP_EPF_R_IN_INSTR_DBELL_START      0x10040

#define    CN83XX_SDP_EPF_R_IN_CNTS_START      0x10050

#define    CN83XX_SDP_EPF_R_IN_INT_LEVELS_START      0x10060

#define    CN83XX_SDP_EPF_R_IN_INT_STATUS_START      0x10070

#define    CN83XX_SDP_EPF_R_IN_PKT_CNT_START      0x10080

#define    CN83XX_SDP_EPF_R_IN_BYTE_CNT_START      0x10090

#define    CN83XX_SDP_EPF_R_IN_CONTROL(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_CONTROL_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_ENABLE(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_ENABLE_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_INSTR_BADDR(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_INSTR_BADDR_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_INSTR_RSIZE(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_INSTR_RSIZE_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_INSTR_DBELL(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_INSTR_DBELL_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_CNTS(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_CNTS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_INT_LEVELS(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_INT_LEVELS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_INT_STATUS(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_INT_STATUS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_PKT_CNT(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_PKT_CNT_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_IN_BYTE_CNT(epf, ring)          \
       (CN83XX_SDP_EPF_R_IN_BYTE_CNT_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

/*------------------ R_IN Masks ----------------*/

/** Rings per Virtual Function **/
#define    CN83XX_R_IN_CTL_RPVF_MASK       	(0xF)
#define	   CN83XX_R_IN_CTL_RPVF_POS		    (48)

/* Number of instructions to be read in one MAC read request. 
 * setting to Max value(4)
 **/
#define    CN83XX_R_IN_CTL_IDLE                    (0x1ULL << 28)
#define    CN83XX_R_IN_CTL_RDSIZE                  (0x3ULL << 25)
#define    CN83XX_R_IN_CTL_IS_64B                  (0x1ULL << 24)
#define    CN83XX_R_IN_CTL_D_NSR                   (0x1ULL << 8)
#define    CN83XX_R_IN_CTL_D_ESR                   (0x1ULL << 6)
#define    CN83XX_R_IN_CTL_D_ROR                   (0x1ULL << 5)
#define    CN83XX_R_IN_CTL_NSR                     (0x1ULL << 3)
#define    CN83XX_R_IN_CTL_ESR                     (0x1ULL << 1)
#define    CN83XX_R_IN_CTL_ROR                     (0x1ULL << 0)

#define    CN83XX_R_IN_CTL_MASK                    \
            ( CN83XX_R_IN_CTL_RDSIZE                \
            | CN83XX_R_IN_CTL_IS_64B)

/*###################### RING OUT REGISTERS #########################*/
#define    CN83XX_SDP_EPF_R_OUT_CNTS_START              0x10100

#define    CN83XX_SDP_EPF_R_OUT_INT_LEVELS_START        0x10110

#define    CN83XX_SDP_EPF_R_OUT_SLIST_BADDR_START       0x10120

#define    CN83XX_SDP_EPF_R_OUT_SLIST_RSIZE_START       0x10130

#define    CN83XX_SDP_EPF_R_OUT_SLIST_DBELL_START       0x10140

#define    CN83XX_SDP_EPF_R_OUT_CONTROL_START           0x10150

#define    CN83XX_SDP_EPF_R_OUT_ENABLE_START            0x10160

#define    CN83XX_SDP_EPF_R_OUT_INT_STATUS_START        0x10170

#define    CN83XX_SDP_EPF_R_OUT_PKT_CNT_START           0x10180

#define    CN83XX_SDP_EPF_R_OUT_BYTE_CNT_START          0x10190

#define    CN83XX_SDP_EPF_R_OUT_CONTROL(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_CONTROL_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_ENABLE(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_ENABLE_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_SLIST_BADDR(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_SLIST_BADDR_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_SLIST_RSIZE(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_SLIST_RSIZE_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_SLIST_DBELL(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_SLIST_DBELL_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_CNTS(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_CNTS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_INT_LEVELS(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_INT_LEVELS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_INT_STATUS(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_INT_STATUS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_PKT_CNT(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_PKT_CNT_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_OUT_BYTE_CNT(epf, ring)          \
       (CN83XX_SDP_EPF_R_OUT_BYTE_CNT_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

/*------------------ R_OUT Masks ----------------*/
#define    CN83XX_R_OUT_INT_LEVELS_BMODE            (1ULL << 63)
#define    CN83XX_R_OUT_INT_LEVELS_TIMET            (32)

#define    CN83XX_R_OUT_CTL_IDLE                     (1ULL << 36)
#define    CN83XX_R_OUT_CTL_ES_I                    (1ULL << 34)
#define    CN83XX_R_OUT_CTL_NSR_I                   (1ULL << 33)
#define    CN83XX_R_OUT_CTL_ROR_I                   (1ULL << 32)
#define    CN83XX_R_OUT_CTL_ES_D                    (1ULL << 30)
#define    CN83XX_R_OUT_CTL_NSR_D                   (1ULL << 29)
#define    CN83XX_R_OUT_CTL_ROR_D                   (1ULL << 28)
#define    CN83XX_R_OUT_CTL_ES_P                    (1ULL << 26)
#define    CN83XX_R_OUT_CTL_NSR_P                   (1ULL << 25)
#define    CN83XX_R_OUT_CTL_ROR_P                   (1ULL << 24)
#define    CN83XX_R_OUT_CTL_IMODE                   (1ULL << 23)

/* ##################### Mail Box Registers ########################## */
//TODO: clean up the comment bfefore submission
/* INT register for VF. when a MBOX write from PF happed to a VF, 
 * corresponding bit will be set in this register as well as in PF_VF_INT register. 
 * This is a RO register, the int can be cleared by writing 1 to PF_VF_INT */
/* Basically first 3 are from PF to VF. The last one is data from VF to PF */

#define	   CN83XX_SDP_EPF_R_MBOX_RINT_STATUS_START	     0x10200

#define    CN83XX_SDP_EPF_R_MBOX_PF_VF_DATA_START        0x10210

#define    CN83XX_SDP_EPF_R_MBOX_PF_VF_INT_START         0x10220

#define    CN83XX_SDP_EPF_R_MBOX_VF_PF_DATA_START        0x10230

#define    CN83XX_SDP_EPF_R_MBOX_RINT_STATUS(epf, ring)          \
       (CN83XX_SDP_EPF_R_MBOX_RINT_STATUS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_MBOX_PF_VF_DATA(epf, ring)          \
       (CN83XX_SDP_EPF_R_MBOX_PF_VF_DATA_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_MBOX_PF_VF_INT(epf, ring)          \
       (CN83XX_SDP_EPF_R_MBOX_PF_VF_INT_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define    CN83XX_SDP_EPF_R_MBOX_VF_PF_DATA(epf, ring)          \
       (CN83XX_SDP_EPF_R_MBOX_VF_PF_DATA_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

/* ##################### Interrupt Registers ########################## */

/* In PF: Each bit indicates a ring that is signalling interrupt. 
 * In VF: 
 *           7 - 0: indicates input ring that is signalling interrupts. 
 *          15 - 8: indicates output ring that is signalling interrupts. 
 *          23 - 16: indicates mailbox interrupt. 
 */
#define	   CN83XX_SDP_EPF_R_ALL_IN_STATUS_START	        0x10300
#define	   CN83XX_SDP_EPF_R_ERR_TYPE_START	            0x10400

#define	   CN83XX_SDP_EPF_MBOX_RINT_START	            0x20000
#define	   CN83XX_SDP_EPF_MBOX_RINT_W1S_START	        0x20010
#define	   CN83XX_SDP_EPF_MBOX_RINT_ENA_W1C_START	    0x20020
#define	   CN83XX_SDP_EPF_MBOX_RINT_ENA_W1S_START	    0x20030

#define	   CN83XX_SDP_EPF_IRERR_RINT_START	            0x20080
#define	   CN83XX_SDP_EPF_IRERR_RINT_W1S_START	        0x20090
#define	   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1C_START	    0x200A0
#define	   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1S_START	    0x200B0

#define	   CN83XX_SDP_EPF_ORERR_RINT_START	            0x20100
#define	   CN83XX_SDP_EPF_ORERR_RINT_W1S_START	        0x20110
#define	   CN83XX_SDP_EPF_ORERR_RINT_ENA_W1C_START	    0x20120
#define	   CN83XX_SDP_EPF_ORERR_RINT_ENA_W1S_START	    0x20130

#define	   CN83XX_SDP_EPF_OEI_RINT_START	            0x20140
#define	   CN83XX_SDP_EPF_OEI_RINT_W1S_START	        0x20150
#define	   CN83XX_SDP_EPF_OEI_RINT_ENA_W1C_START	    0x20160
#define	   CN83XX_SDP_EPF_OEI_RINT_ENA_W1S_START	    0x20170

#define	   CN83XX_SLI_EPF_MISC_RINT_START	            0x28240
#define	   CN83XX_SLI_EPF_MISC_RINT_W1S_START	        0x28250
#define	   CN83XX_SLI_EPF_MISC_RINT_ENA_W1C_START	    0x28260
#define	   CN83XX_SLI_EPF_MISC_RINT_ENA_W1S_START	    0x28270

#define	   CN83XX_SLI_EPF_PP_VF_RINT_START	            0x282C0
#define	   CN83XX_SLI_EPF_PP_VF_RINT_W1S_START	        0x282D0
#define	   CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1C_START	    0x282E0
#define	   CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1S_START	    0x282F0

#define	   CN83XX_SLI_EPF_DMA_VF_RINT_START	            0x28400
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_W1S_START	        0x28410
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1C_START	    0x28420
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1S_START	    0x28430

#define	   CN83XX_SLI_EPF_DMA_RINT_START	            0x28500
#define	   CN83XX_SLI_EPF_DMA_RINT_W1S_START	        0x28510
#define	   CN83XX_SLI_EPF_DMA_RINT_ENA_W1C_START	    0x28540
#define	   CN83XX_SLI_EPF_DMA_RINT_ENA_W1S_START	    0x28550

#define    CN83XX_SDP_EPF_R_ALL_IN_STATUS(epf, ring)          \
       (CN83XX_SDP_EPF_R_ALL_IN_STATUS_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))
#define    CN83XX_SDP_EPF_R_ERR_TYPE(epf, ring)          \
       (CN83XX_SDP_EPF_R_ERR_TYPE_START + ( (epf) * CN83XX_EPF_OFFSET) +  ( (ring) * CN83XX_RING_OFFSET))

#define	   CN83XX_SDP_EPF_MBOX_RINT(epf)	            \
                (CN83XX_SDP_EPF_MBOX_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_MBOX_RINT_W1S(epf)	            \
                (CN83XX_SDP_EPF_MBOX_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_MBOX_RINT_ENA_W1C(epf)	            \
                (CN83XX_SDP_EPF_MBOX_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_MBOX_RINT_ENA_W1S(epf)	            \
                (CN83XX_SDP_EPF_MBOX_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SDP_EPF_IRERR_RINT(epf)	            \
                (CN83XX_SDP_EPF_IRERR_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_IRERR_RINT_W1S(epf)	            \
                (CN83XX_SDP_EPF_IRERR_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1C(epf)	            \
                (CN83XX_SDP_EPF_IRERR_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_IRERR_RINT_ENA_W1S(epf)	            \
                (CN83XX_SDP_EPF_IRERR_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SDP_EPF_ORERR_RINT(epf)	            \
                (CN83XX_SDP_EPF_ORERR_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_ORERR_RINT_W1S(epf)	            \
                (CN83XX_SDP_EPF_ORERR_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_ORERR_RINT_ENA_W1C(epf)	            \
                (CN83XX_SDP_EPF_ORERR_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_ORERR_RINT_ENA_W1S(epf)	            \
                (CN83XX_SDP_EPF_ORERR_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SDP_EPF_OEI_RINT(epf)	            \
                (CN83XX_SDP_EPF_OEI_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_OEI_RINT_W1S(epf)	            \
                (CN83XX_SDP_EPF_OEI_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_OEI_RINT_ENA_W1C(epf)	            \
                (CN83XX_SDP_EPF_OEI_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SDP_EPF_OEI_RINT_ENA_W1S(epf)	            \
                (CN83XX_SDP_EPF_OEI_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SLI_EPF_MISC_RINT(epf)	            \
                (CN83XX_SLI_EPF_MISC_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_MISC_RINT_W1S(epf)	            \
                (CN83XX_SLI_EPF_MISC_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_MISC_RINT_ENA_W1C(epf)	            \
                (CN83XX_SLI_EPF_MISC_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_MISC_RINT_ENA_W1S(epf)	            \
                (CN83XX_SLI_EPF_MISC_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SLI_EPF_PP_VF_RINT(epf)	            \
                (CN83XX_SLI_EPF_PP_VF_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_PP_VF_RINT_W1S(epf)	            \
                (CN83XX_SLI_EPF_PP_VF_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1C(epf)	            \
                (CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1S(epf)	            \
                (CN83XX_SLI_EPF_PP_VF_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SLI_EPF_DMA_VF_RINT(epf)	            \
                (CN83XX_SLI_EPF_DMA_VF_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_W1S(epf)	            \
                (CN83XX_SLI_EPF_DMA_VF_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1C(epf)	            \
                (CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1S(epf)	            \
                (CN83XX_SLI_EPF_DMA_VF_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

#define	   CN83XX_SLI_EPF_DMA_RINT(epf)	            \
                (CN83XX_SLI_EPF_DMA_RINT_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_RINT_W1S(epf)	            \
                (CN83XX_SLI_EPF_DMA_RINT_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_RINT_ENA_W1C(epf)	            \
                (CN83XX_SLI_EPF_DMA_RINT_ENA_W1C_START + ( (epf) * CN83XX_EPF_OFFSET))
#define	   CN83XX_SLI_EPF_DMA_RINT_ENA_W1S(epf)	            \
                (CN83XX_SLI_EPF_DMA_RINT_ENA_W1S_START + ( (epf) * CN83XX_EPF_OFFSET))

/*------------------ Interrupt Masks ----------------*/

#define	   CN83XX_INTR_R_OUT_INT        (1ULL << 62)
#define    CN83XX_INTR_R_IN_INT			(1ULL << 61)
#define    CN83XX_INTR_R_MBOX_INT		(1ULL << 60)
#define    CN83XX_INTR_R_RESEND			(1ULL << 59)

/* ############################# PEM Specific Registers ############################ */
/** PEM(0..3)_BAR1_INDEX(0..15)address is defined as
 *  addr = (0x00011800C0000100  |port <<24 |idx <<3 )
 *  Here, port is PEM(0..3) & idx is INDEX(0..15)
 **/

#define    CN83XX_PEM_BAR1_INDEX_START             0x000087E0C0000100ULL
#define    CN83XX_PEM_OFFSET                       24
#define    CN83XX_BAR1_INDEX_OFFSET                3

#define    CN83XX_PEM_BAR1_INDEX_REG(port, idx)              \
           (CN83XX_PEM_BAR1_INDEX_START + ((port) << CN83XX_PEM_OFFSET) +  \
			((idx) << CN83XX_BAR1_INDEX_OFFSET) )

/*---------------   PCI BAR1 index registers -------------*/

/* BAR1 Mask */
#define    PCI_BAR1_ENABLE_CA            1
#define    PCI_BAR1_ENDIAN_MODE          OCTEON_PCI_64BIT_SWAP
#define    PCI_BAR1_ENTRY_VALID          1
#define    PCI_BAR1_MASK                 (  (PCI_BAR1_ENABLE_CA << 3)   \
                                          | (PCI_BAR1_ENDIAN_MODE << 1) \
                                          | PCI_BAR1_ENTRY_VALID )


#define    INVALID_MAP    0xffff
		   
#endif

/* $Id:$ */
