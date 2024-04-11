/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cn83xx_vf_regs.h
    \brief Host Driver: Register Address and Register Mask values for
                        Octeon CN83XX devices.
*/

#ifndef __CN83XX_VF_REGS_H__
#define __CN83XX_VF_REGS_H__
/*############################ RST #########################*/
#define     CN83XX_CONFIG_XPANSION_BAR             0x38

#define     CN83XX_CONFIG_PCIE_CAP                 0x70
#define     CN83XX_CONFIG_PCIE_DEVCAP              0x74
#define     CN83XX_CONFIG_PCIE_DEVCTL              0x78
#define     CN83XX_CONFIG_PCIE_LINKCAP             0x7C
#define     CN83XX_CONFIG_PCIE_LINKCTL             0x80
#define     CN83XX_CONFIG_PCIE_SLOTCAP             0x84
#define     CN83XX_CONFIG_PCIE_SLOTCTL             0x88

#define     CN83XX_CONFIG_PCIE_FLTMSK              0x720

#define  CN83XX_VF_RING_OFFSET                    (0x1ULL << 17)
#define  CN83XX_VF_EPF_OFFSET                     (0x0)
/*###################### RING IN REGISTERS #########################*/

#define    CN83XX_VF_SDP_EPF_R_IN_CONTROL_START    0x10000

#define    CN83XX_VF_SDP_EPF_R_IN_ENABLE_START     0x10010

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_BADDR_START      0x10020

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_RSIZE_START      0x10030

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL_START      0x10040

#define    CN83XX_VF_SDP_EPF_R_IN_CNTS_START      0x10050

#define    CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS_START      0x10060

#define    CN83XX_VF_SDP_EPF_R_IN_INT_STATUS_START      0x10070

#define    CN83XX_VF_SDP_EPF_R_IN_PKT_CNT_START      0x10080

#define    CN83XX_VF_SDP_EPF_R_IN_BYTE_CNT_START      0x10090

#define    CN83XX_VF_SDP_EPF_R_IN_CONTROL(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_CONTROL_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_ENABLE(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_ENABLE_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_BADDR(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_INSTR_BADDR_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_RSIZE(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_INSTR_RSIZE_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_INSTR_DBELL_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_CNTS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_CNTS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_INT_LEVELS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_INT_STATUS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_INT_STATUS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_PKT_CNT(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_PKT_CNT_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_IN_BYTE_CNT(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_IN_BYTE_CNT_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

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
#define    CN83XX_VF_SDP_EPF_R_OUT_CNTS_START              0x10100

#define    CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS_START        0x10110

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_BADDR_START       0x10120

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_RSIZE_START       0x10130

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL_START       0x10140

#define    CN83XX_VF_SDP_EPF_R_OUT_CONTROL_START           0x10150

#define    CN83XX_VF_SDP_EPF_R_OUT_ENABLE_START            0x10160

#define    CN83XX_VF_SDP_EPF_R_OUT_INT_STATUS_START        0x10170

#define    CN83XX_VF_SDP_EPF_R_OUT_PKT_CNT_START           0x10180

#define    CN83XX_VF_SDP_EPF_R_OUT_BYTE_CNT_START          0x10190

#define    CN83XX_VF_SDP_EPF_R_OUT_CONTROL(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_CONTROL_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_ENABLE(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_ENABLE_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_BADDR(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_SLIST_BADDR_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_RSIZE(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_SLIST_RSIZE_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_SLIST_DBELL_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_CNTS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_CNTS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_INT_LEVELS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_INT_STATUS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_INT_STATUS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_PKT_CNT(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_PKT_CNT_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_OUT_BYTE_CNT(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_OUT_BYTE_CNT_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

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

#define	   CN83XX_VF_SDP_EPF_R_MBOX_RINT_STATUS_START	     0x10200

#define    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_DATA_START        0x10210

#define    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT_START         0x10220

#define    CN83XX_VF_SDP_EPF_R_MBOX_VF_PF_DATA_START        0x10230

#define    CN83XX_VF_SDP_EPF_R_MBOX_RINT_STATUS(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_MBOX_RINT_STATUS_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_DATA(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_DATA_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_MBOX_PF_VF_INT_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#define    CN83XX_VF_SDP_EPF_R_MBOX_VF_PF_DATA(epf, ring)          \
       (CN83XX_VF_SDP_EPF_R_MBOX_VF_PF_DATA_START + ( (epf) * CN83XX_VF_EPF_OFFSET) +  ( (ring) * CN83XX_VF_RING_OFFSET))

#endif

/* $Id:$ */
