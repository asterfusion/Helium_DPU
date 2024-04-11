/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file  octeon-drv-opcodes.h
     \brief Common: Opcodes used by host and core PCI driver. 
*/

#ifndef __OCTEON_DRV_OPCODES_H__
#define __OCTEON_DRV_OPCODES_H__

/* Opcodes used by host driver/apps to perform operations on the core */
/* Opcodes in the ranges
   -  0x1000 to 0x1FFF
   -  0x7000 to 0x7FFF are reserved by the host driver */

/* Note: The core driver uses the lower 16 bits as an index into a 
         table of function pointers that is MAX_DRV_OPCODES in length.
         See that the lower 16-bits are unique for each driver opcode
         and does not exceed MAX_DRV_OPCODES in value. */
#define DRIVER_OP_START             0x1001

/* Opcodes 0x1000-0x10FF reserved for base driver. */
#define CORE_MEM_MAP_OP             0x1001
#define HOT_RESET_OP                0x1002
#define DEVICE_STOP_OP              0x1003
#define DEVICE_START_OP             0x1004
#define OCT_PCI_FLR_HANDLER_OP      0x1005

/* Exclusive Control Queue for both host and core */
#define CTRL_QUEUE_NUM              0

/* Values in param field for DEVICE_START/STOP_OP */
#define  DEVICE_IPD                 0x1
#define  DEVICE_PKO                 0x2

#define PCIE_MAP_OP                 0x111C

#define CVM_DRV_RESP_COMP_OP        0x111D

/* Used by PCI TOE */
#define PCI_TOE_GETLINK_OP          0x111E

#define DRIVER_OP_END               0x111F

/* Opcodes 0x1200-0x12FF reserved for the NIC module. */
#define OCT_NW_PKT_OP               0x1220
#define OCT_NW_CMD_OP               0x1221
#define HOST_NW_INFO_OP             0x1222
#define HOST_PORT_STATS_OP          0x1223
#define OCT_NIC_MBCAST_COMPLETION_OP 0x1224
#define HOST_NW_STOP_OP             0x1225

#define MBCAST_TIMER_TICKS              2

#define MAX_DRV_OPCODES             64

/* Opcodes 0x1300-0x13FF reserved for driver test applications. */

	/* These opcodes are used in test packets sent to the core application
	   in base module. */
#define CVMCS_REQRESP_OP            0x1301
#define CVMCS_DMA_OP                0x1302
#define CVMCS_REQRESP_COMP_OP       0x1303

#define PKO_OQ_MASK_INDICATION      0x1304

#define  PKO_OQ_MASK_SET            0x1
#define  PKO_OQ_MASK_CLEAR          0x2

    /* These opcodes are used in the octeon_pcitest application */
#define HOST_TO_CORE_PKT            0x1305

    /* For CN56XX Peer to Peer test packet */
#define EP_TO_EP_OP                 0x1306

       /* These opcodes are used by the validation test application. */
#define OPV_OPCODE_BEGIN            0x1310

#define OPV_INIT_OP                 0x1311
#define OPV_START_OP                0x1312
#define OPV_STOP_OP                 0x1313
#define OPV_REPORT_OP               0x1314
#define OPV_TEST_OP                 0x1315
#define OPV_CORE_INFO_OP            0x1316
#define OPV_DMA_PKT_OP              0x1317
#define OPV_DMA_INTR_OP             0x131F

#define OPV_OPCODE_END              0x131F

/* Fd Open() - Close() indication opcodes  to OCTEON */
#define FD_OPEN_INDICATION         0x1340
#define FD_CLOSE_INDICATION        0x1341

/* Host Firmware Handshake Opcodes */
#define HOSTFW_HS_ACK		0x1401

#define HOSTFW_HS_APP_INDICATION            0xA001
#define HOSTFW_HS_SUPPORT_INDICATION        0xA002
#define HOSTFW_HS_NB_BLOCK_INDICATION	    0xA003
#define HOSTFW_HS_READ_DONE_INDICATION	    0xA004
#define HOSTFW_HS_NUM_INTF_INDICATION	    0xA005
#define HOSTFW_HS_CORE_ACTIVE_INDICATION    0xA006

#define HOSTFW_HS_SCRATCH_FREE_INDICATION   0xA007

#define HOST_HS_OCT_IDX_INDICATION	    0xA008

/* Opcodes used by core driver/apps to perform operations on the host */
/* Opcodes in the ranges
   - 0x8000 to 0x8FFF
   - 0xF001 to 0xFFFF are reserved by the core driver */

/* These two opcodes are used by the base application to send test packets
 * on Output queues. */
#define DROQ_PKT_OP1                0x8001
#define DROQ_PKT_OP2                0x8002

/* These two opcodes are used by NIC core application. */
#define CORE_NW_DATA_OP             0x8003
#define CORE_NW_INFO_OP             0x8004

/* This opcode is sent by core PCI driver to indicate cores are ready. */
#define CORE_DRV_ACTIVE_OP          0x8005

/* This opcode is used in octeon pcitest application */
#define CORE_TO_HOST_PKT            0x8006

/* Used by PCI TOE */
#define PCI_TOE_LINKSTATUS_OP       0x8007

#define PCI_INSTR_RESP_OP           0x8F01

#define CORE_MEM_MAP_ACK_OP         0xFF01

#define PCITEST_SETUP_OP            0xFFF4

#define CORE_DRV_TEST_SCATTER_OP    0xFFF5

/* Application codes advertised by the core driver initialization packet. */
#define CVM_DRV_APP_START           0x0
#define CVM_DRV_NO_APP              0
#define CVM_DRV_APP_COUNT           0x5
#define CVM_DRV_BASE_APP            (CVM_DRV_APP_START + 0x1)
#define CVM_DRV_NIC_APP             (CVM_DRV_APP_START + 0x2)
#define CVM_DRV_ZLIB_APP            (CVM_DRV_APP_START + 0x3)
#define CVM_DRV_INVALID_APP         (CVM_DRV_APP_START + 0x4)
#define CVM_DRV_APP_END             (CVM_DRV_INVALID_APP - 1)

#endif

/* $Id:$ */
