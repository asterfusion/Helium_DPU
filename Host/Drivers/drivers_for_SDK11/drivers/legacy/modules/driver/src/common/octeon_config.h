/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  octeon_config.h 
    \brief Host Driver: Configuration data structures for the host driver.
*/

#ifndef __OCTEON_CONFIG_H__
#define __OCTEON_CONFIG_H__


/*--------------------------CONFIG VALUES------------------------*/
/*
    The following variables affect the way the driver data structures 
    are generated for Octeon devices.
    They can be modified.
*/

/*  Maximum no. of octeon devices that the driver can support. */
#define   MAX_OCTEON_DEVICES           128

#define   OCTEON_MAX_DROQS             16	/* Not being used in code */

/** OCTEON-III */
#define   OCTEON3_MAX_IOQS		        64

#define   OCTEON_32BYTE_INSTR			32
#define   OCTEON_64BYTE_INSTR			64
#define   OCTEON_MAX_BASE_IOQ			4
#define   OCTEON_OQ_BUFPTR_MODE			0
#define   OCTEON_OQ_INFOPTR_MODE		1

#define   OCTEON_DMA_INTR_PKT			64
#define   OCTEON_DMA_INTR_TIME			1000

#define   OCTEON_CONFIG_TYPE_DEFAULT	1
/** OCTEON TX and TX2(83xx and 93xx) Models */
#define   OCTEON_CONFIG_TYPE_CUSTOM	2
#define   OCTEON_NUM_NON_IOQ_INTR	16
/* Using 0 for timebeing */
#define   OCTEONTX2_NUM_NON_IOQ_INTR	16
#define   OCTEONTX2_10K_NUM_NON_IOQ_INTR	32

/*-------------- Macros for OCTEON TX Models ----------------*/
#define   CN83XX_MAX_INPUT_QUEUES	64

#define   CN83XX_MAX_IQ_DESCRIPTORS     2048

#define   CN83XX_DB_MIN                 1
#define   CN83XX_DB_TIMEOUT             1
#define   CN83XX_INTR_THRESHOLD		    0x0

/* CN83xx OQ configuration macros */
#define   CN83XX_MAX_OUTPUT_QUEUES	64

#define   CN83XX_MAX_OQ_DESCRIPTORS     4096
#ifdef CONFIG_PPORT
/* PPORT_HLEN, CUSTOM_META_TAG_LEN */
#define MV_PPORT_OVERHEAD (64 + 2)
#else
#define MV_PPORT_OVERHEAD 0
#define TOTAL_TAG_LEN 0
#endif
#define   CN83XX_OQ_BUF_SIZE            (1536 + MV_PPORT_OVERHEAD)
#define   CN83XX_OQ_PKTSPER_INTR        128
/* NIC mode performance tuning: increased from 128 to 1024 */
#define   CN83XX_OQ_REFIL_THRESHOLD     1024

#define   CN83XX_OQ_INTR_PKT            8
#define   CN83XX_OQ_INTR_TIME           2

#define   CN83XX_CFG_IO_QUEUES          64
#define   CN83XX_MAX_MACS               4	/* PEMs count */

/* CN83xx SR-IOV configuration macros */
#define   CN83XX_MIN_RINGS_PER_VF	1
#define   CN83XX_MAX_RINGS_PER_VF	8

#define   CN83XX_EPF_START_RING_NUM	    0

#define   CN83XX_EPF_MAX_RINGS		64

#define   CN83XX_NUM_PFS		    1
#define   CN83XX_EPF_NUM_VFS		0

#define   CN83XX_EPF_RINGS_PER_VF	CN83XX_MIN_RINGS_PER_VF

#define   OCTEON_MAX_83XX_BASE_IOQ		OCTEON_MAX_BASE_IOQ	

#define   CN83XX_VF_CFG_IO_QUEUES       8
#define   OCTEON_MAX_83XX_VF_BASE_IOQ   1


/*----------- Macros for OCTEON TX2 Models 93/96/98/95xx ------------*/
/* A single 93xx PF can up to 128 VFs mapped up into 128 rings */
#define   CN93XX_MAX_INPUT_QUEUES	128
#define   CN93XX_NUM_NON_IOQ_INTR	16

#define   CN93XX_MAX_IQ_DESCRIPTORS	2048

#define   CN93XX_DB_MIN 		1
#define   CN93XX_DB_TIMEOUT		1
#define   CN93XX_INTR_THRESHOLD 	0x0

/* CN93xx OQ configuration macros */
#define   CN93XX_MAX_OUTPUT_QUEUES	128

#define   CN93XX_MAX_OQ_DESCRIPTORS	4096
#define   CN93XX_OQ_BUF_SIZE		(1536 + MV_PPORT_OVERHEAD)
#define   CN93XX_OQ_PKTSPER_INTR	128
/* NIC mode performance tuning: increased from 128 to 1024 */
#define   CN93XX_OQ_REFIL_THRESHOLD	1024

#define   CN93XX_OQ_INTR_PKT		1
#define   CN93XX_OQ_INTR_TIME		10

#define   CN93XX_CFG_IO_QUEUES		128
#define   CN93XX_MAX_MACS		4 /* PEMs count */

/* CN93xx SR-IOV configuration macros */
#define   CN93XX_MIN_RINGS_PER_VF	1
#define   CN93XX_MAX_RINGS_PER_VF	8

#define   CN93XX_EPF_START_RING_NUM	0

#define   CN93XX_EPF_MAX_RINGS		64

/* TODO: Number of PF's exposed by the device. 8 or 16 ? */
#define   CN93XX_NUM_PFS		16
#define   CN93XX_EPF_NUM_VFS		0

#define   CN93XX_EPF_RINGS_PER_VF	CN93XX_MIN_RINGS_PER_VF

#define   OCTEON_MAX_93XX_BASE_IOQ	OCTEON_MAX_BASE_IOQ

#define   CN93XX_VF_CFG_IO_QUEUES	8
#define   OCTEON_MAX_93XX_VF_BASE_IOQ	1

/*-------------- Macros for OCTEON TX2 CNXK Models ----------------*/
/* A single CNXK PF can up to 64 VFs mapped up into 63 rings */
#define   CNXK_MAX_INPUT_QUEUES	63
#define   CNXK_NUM_NON_IOQ_INTR	32

#define   CNXK_MAX_IQ_DESCRIPTORS	2048

#define   CNXK_DB_MIN 		1
#define   CNXK_DB_TIMEOUT		1
#define   CNXK_INTR_THRESHOLD 	0x0

/* CNXK OQ configuration macros */
#define   CNXK_MAX_OUTPUT_QUEUES	63

#define   CNXK_MAX_OQ_DESCRIPTORS	4096
#define   CNXK_OQ_BUF_SIZE		(1536 + MV_PPORT_OVERHEAD)
#define   CNXK_OQ_PKTSPER_INTR	128
/* NIC mode performance tuning: increased from 128 to 1024 */
#define   CNXK_OQ_REFIL_THRESHOLD	1024

#define   CNXK_OQ_INTR_PKT		1
#define   CNXK_OQ_INTR_TIME		10

#define   CNXK_CFG_IO_QUEUES		63
#define   CNXK_MAX_MACS		4 /* PEMs count */

/* CNXK SR-IOV configuration macros */
#define   CNXK_MIN_RINGS_PER_VF	1
#define   CNXK_MAX_RINGS_PER_VF	8

#define   CNXK_EPF_START_RING_NUM	0

#define   CNXK_EPF_MAX_RINGS		63

#define   CNXK_NUM_PFS		2
#define   CNXK_EPF_NUM_VFS		0

#define   CNXK_EPF_RINGS_PER_VF	CNXK_MIN_RINGS_PER_VF

#define   OCTEON_MAX_CNXK_BASE_IOQ	OCTEON_MAX_BASE_IOQ

#define   CNXK_VF_CFG_IO_QUEUES	8
#define   OCTEON_MAX_CNXK_VF_BASE_IOQ	1

/*
 * ISM defines enable the use of ISM (Interrupt Status Messages) for input
 * and output queue management if supported.  When enabled, chips that support
 * ISM will use it, others will use normal CSR accesses.  When disabled, all
 * chips will use CSR accesses.
 * CN9XXX and CNXK support ISM
 */
#define   OCT_DROQ_ISM		0
#define   OCT_IQ_ISM		0

/* ----------------- Host Firmware Handshake Details ----------------- */
/* ----------------- Host Firmware Handshake Details ----------------- */

/** host firmware handshake state information  */
#define HOSTFW_HS_INIT              1
#define HOSTFW_HS_WAIT_NAMED_BLOCK  2
#define HOSTFW_HS_WAIT_CFG_READ     3
#define HOSTFW_HS_NUM_INTF          4
#define HOSTFW_HS_CORE_ACTIVE       5
#define HOSTPF0_HS_INIT             6
#define HOSTPF1_HS_INIT             7
#define PFVF_HS_INIT                8
#define PFVF_HS_WAIT_CORE_CFG       9
#define PFVF_HS_DONE		    0xA
#define HOSTFW_HS_DONE              0x10

/* Macros to get octeon config params */
#define CFG_GET_IQ_CFG(cfg)					((cfg)->iq)
#define CFG_GET_IQ_MAX_Q(cfg)				((cfg)->iq.max_iqs)
#define CFG_GET_IQ_MAX_BASE_Q(cfg)			((cfg)->iq.max_base_iqs)
#define CFG_GET_IQ_PENDING_LIST_SIZE(cfg)	((cfg)->iq.pending_list_size)
#define CFG_GET_IQ_NUM_DESC(cfg)			((cfg)->iq.num_descs)
#define CFG_GET_IQ_INSTR_TYPE(cfg)			((cfg)->iq.instr_type)
#define CFG_GET_IQ_DB_MIN(cfg)				((cfg)->iq.db_min)
#define CFG_GET_IQ_DB_TIMEOUT(cfg)			((cfg)->iq.db_timeout)
#define CFG_GET_IQ_INTR_THRESHOLD(cfg)			((cfg)->iq.intr_threshold)

#define CFG_GET_OQ_MAX_Q(cfg)				((cfg)->oq.max_oqs)
#define CFG_GET_OQ_MAX_BASE_Q(cfg)			((cfg)->oq.max_base_oqs)
#define CFG_GET_OQ_NUM_DESC(cfg)			((cfg)->oq.num_descs)
#define CFG_GET_OQ_BUF_SIZE(cfg)			((cfg)->oq.buf_size)
#define CFG_GET_OQ_INFO_PTR(cfg)			((cfg)->oq.info_ptr)
#define CFG_GET_OQ_PKTS_PER_INTR(cfg)		((cfg)->oq.pkts_per_intr)
#define CFG_GET_OQ_REFILL_THRESHOLD(cfg)	((cfg)->oq.refill_threshold)
#define CFG_GET_OQ_INTR_PKT(cfg)			((cfg)->oq.oq_intr_pkt)
#define CFG_GET_OQ_INTR_TIME(cfg)			((cfg)->oq.oq_intr_time)

#define CFG_GET_DMA_INTR_PKT(cfg)			((cfg)->dma.dma_intr_pkt)
#define CFG_GET_DMA_INTR_TIME(cfg)			((cfg)->dma.dma_intr_time)

#define CFG_GET_PKO_CMDQ_PER_IF(cfg,if)			((cfg)->pko[(if)].cmdq_per_if)
#define CFG_GET_PKO_LINK_PER_IF(cfg,if)			((cfg)->pko[(if)].links_per_if)
#define CFG_GET_PKO_CMDQ_PER_PCI_PORT(cfg,if)	((cfg)->pko[(if)].cmdq_per_pciport)

#define CFG_GET_POOL_BUF_SIZE(cfg,pool)		    ((cfg)->fpa[(pool)].pool_buf_size)
#define CFG_GET_POOL_BUF_CNT(cfg,pool)		    ((cfg)->fpa[(pool)].pool_buf_cnt)

#define CFG_GET_PORTS_NUM_IOQ(cfg)              ((cfg)->port_cfg.num_ioqs)
#define CFG_GET_PORTS_SRN(cfg)                  ((cfg)->port_cfg.srn)

#define CFG_GET_NUM_INTF(cfg)	                ((cfg)->core_cfg.num_intf)
#define CFG_GET_DPI_PKIND(cfg)                  ((cfg)->core_cfg.dpi_pkind)
#define CFG_GET_CORE_TICS_PER_US(cfg)           ((cfg)->core_cfg.core_tics_per_us)
#define CFG_GET_COPROC_TICS_PER_US(cfg)         ((cfg)->core_cfg.coproc_tics_per_us)
#define CFG_GET_APP_MODE(cfg)                   ((cfg)->core_cfg.app_mode)

#define CFG_GET_PF_START_RING_NUM(cfg,pf)          ((cfg)->pf_sriov_cfg[pf].start_ring_num)
#define CFG_GET_TOTAL_PF_RINGS(cfg,pf)             ((cfg)->pf_sriov_cfg[pf].total_pf_rings)
#define CFG_GET_RINGS_PER_VF(cfg,pf)               ((cfg)->pf_sriov_cfg[pf].rings_per_vf)
#define CFG_GET_NUM_VFS(cfg,pf)                    ((cfg)->pf_sriov_cfg[pf].num_vfs)

#define CFG_GET_MEM_SIZE(cfg)					((cfg)->misc.mem_size)
#define CFG_GET_CORE_CNT(cfg)					((cfg)->misc.core_cnt)
#define CFG_GET_CTRL_Q_GRP(cfg)					((cfg)->misc.ctrlq_grp)
#define CFG_GET_CTRL_Q_NO(cfg)					((cfg)->misc.ctrlq_num)
#define CFG_GET_FLAGS(cfg)						((cfg)->misc.flags)
#define CFG_GET_CRC(cfg)						((cfg)->misc.crc)
#define CFG_GET_HOST_LINK_QUERY_INTERVAL(cfg)	((cfg)->misc.host_link_query_interval)
#define CFG_GET_OCT_LINK_QUERY_INTERVAL(cfg)	((cfg)->misc.oct_link_query_interval)
#define CFG_GET_EXTENDED_STATS(cfg)				((cfg)->misc.extended_stats)
#define CFG_GET_FW_DMAC_FLT_STATUS(cfg)         ((cfg)->misc.fw_dmac_filter)
#define CFG_GET_SETUP_CTL_BUFFERS(cfg)			((cfg)->misc.setup_ctl_bufs)
#define CFG_GET_IS_SLI_BP_ON(cfg)				((cfg)->misc.enable_sli_oq_bp)
#define CFG_GET_ENABLE_MTU_VLAN(cfg)            ((cfg)->misc.enable_mtu_vlan)
#define CFG_GET_NUM_PFS(cfg)                    ((cfg)->misc.num_pfs)

/** Max FPA pools OCTEON supports */
#define MAX_FPA1_POOLS			8
#define MAX_FPA3_POOLS			64
#define MAX_FPA3_AURAS			1024

/* Max IOQs per OCTEON Link */
/* VSR: shouldn't it be 63 (as per bit field limits in CSRs) ? */
#define MAX_IOQS_PER_NICIF		64
/* For 78XX EVB Max SGMII ports can be 16 (4 XAUI modules, each having 4 SGMII ports)*/
#define MAX_OCTEON_NICIF		16

/* For multi function support in 73xx*/
#define MAX_PF_FUNCTIONS		16

/* TX timeout value for watchdog timer */
#define TXTIMEOUT			5*HZ

/* Represents invalid Link IOQ number */
#define INVALID_IOQ_NO			0xff

#define MAX_PKO_CONFIG			3

#define CNNIC_IOQ(X,Y)			{.iq_no = (X), .oq_no = (Y)}

#define CNNIC_INVALID_IOQ		{.iq_no = INVALID_IOQ_NO, .oq_no = INVALID_IOQ_NO,}

#define CNNIC_UNUSED_IOQ(X)	[ (X) ... (MAX_IOQS_PER_NICIF - 1) ] = CNNIC_INVALID_IOQ

#ifndef __CAVIUM_BYTE_ORDER
#error "__CAVIUM_BYTE_ORDER not defined"
#endif
/** Structure to define the configuration attributes for each Input queue.
 *  Applicable to all Octeon processors 
 **/
typedef struct {

#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	/* Max number of IQs available */
	uint64_t max_iqs:32;

    /** Number of IQs configured in Base driver */
	uint64_t max_base_iqs:32;

    /** Pending list size (usually set to the sum of the size of all Input
	*  queues) 
	*/
	uint64_t pending_list_size:32;

    /** Size of the Input queue (number of commands) */
	uint64_t num_descs:32;

    /** Command size - 32 or 64 bytes */
	uint64_t instr_type:32;

    /** Minimum number of commands pending to be posted to Octeon before driver
	*  hits the Input queue doorbell. 
	*/
	uint64_t db_min:32;

    /** Minimum ticks to wait before checking for pending instructions. */
	uint64_t db_timeout:32;

    /** Trigger the IQ interrupt when processed cmd count reaches these wmark */
	uint64_t intr_threshold:32;

#else
    /** Number of IQs configured in Base driver */
	uint64_t max_base_iqs:32;

	/* Max number of IQs available */
	uint64_t max_iqs:32;

    /** Size of the Input queue (number of commands) */
	uint64_t num_descs:32;

    /** Pending list size (usually set to the sum of the size of all Input
	*  queues) 
	*/
	uint64_t pending_list_size:32;

    /** Minimum number of commands pending to be posted to Octeon before driver
	*  hits the Input queue doorbell. 
	*/
	uint64_t db_min:32;

    /** Command size - 32 or 64 bytes */
	uint64_t instr_type:32;

    /** Trigger the IQ interrupt when processed cmd count reaches these wmark */
	uint64_t intr_threshold:32;

    /** Minimum ticks to wait before checking for pending instructions. */
	uint64_t db_timeout:32;

#endif

} octeon_iq_config_t;

/** Structure to define the configuration attributes for each Output queue.
 *  Applicable to all Octeon processors
 **/
typedef struct {

#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	/* Max number of OQs available */
	uint64_t max_oqs:32;

    /** Number of Output Queues configured in Base driver */
	uint64_t max_base_oqs:32;

    /** Size of Output queue (number of descriptors) */
	uint64_t num_descs:32;

    /** If set, the Output queue uses info-pointer mode. (Default: 1 ) */
	uint64_t info_ptr:32;

    /** Size of buffer in this Output queue. */
	uint64_t buf_size:32;

	/** Number of packets to be processed by driver tasklet every invocation
 	* for this Output queue.
 	**/
	uint64_t pkts_per_intr:32;

    /** The number of buffers that were consumed during packet processing by
 	 *   the driver on this Output queue before the driver attempts to replenish
 	 *   the descriptor ring with new buffers.
 	**/
	uint64_t refill_threshold:32;

    /** Interrupt Coalescing (Packet Count). Octeon will interrupt the host
    *  only if it sent as many packets as specified by this field. The driver
    *  usually does not use packet count interrupt coalescing. 
    **/
	uint64_t oq_intr_pkt:32;

    /** Interrupt Coalescing (Time Interval). Octeon will interrupt the host
 	 *  if atleast one packet was sent in the time interval specified by this
 	 *  field. The driver uses time interval interrupt coalescing by default.
 	 *  The time is specified in microseconds.
 	 **/
	uint64_t oq_intr_time:32;

	uint64_t reserved:32;
#else

    /** Number of Output Queues configured in Base driver */
	uint64_t max_base_oqs:32;

	/* Max number of OQs available */
	uint64_t max_oqs:32;

	/** If set, the Output queue uses info-pointer mode. (Default: 1 ) */
	uint64_t info_ptr:32;

    /** Size of Output queue (number of descriptors) */
	uint64_t num_descs:32;

	/** Number of packets to be processed by driver tasklet every invocation
 	* for this Output queue.
 	**/
	uint64_t pkts_per_intr:32;

     /** Size of buffer in this Output queue. */
	uint64_t buf_size:32;
   /** Interrupt Coalescing (Packet Count). Octeon will interrupt the host
    *  only if it sent as many packets as specified by this field. The driver
    *  usually does not use packet count interrupt coalescing. 
    **/
	uint64_t oq_intr_pkt:32;

    /** The number of buffers that were consumed during packet processing by
 	 *   the driver on this Output queue before the driver attempts to replenish
 	 *   the descriptor ring with new buffers.
 	**/
	uint64_t refill_threshold:32;

	uint64_t reserved:32;

	/** Interrupt Coalescing (Time Interval). Octeon will interrupt the host
 	 *  if atleast one packet was sent in the time interval specified by this
 	 *  field. The driver uses time interval interrupt coalescing by default.
 	 *  The time is specified in microseconds.
 	 **/
	uint64_t oq_intr_time:32;

#endif

} octeon_oq_config_t;

/** Structure to define the configuration attributes for PKO. 
 *  Applicable to all Octeon processors. 
 **/
typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	/** number of cmd-queues per interface*/
	uint64_t cmdq_per_if:8;

	/** number of links on each interface*/
	uint64_t links_per_if:8;

	/** number of queues per pciport */
	uint64_t cmdq_per_pciport:16;

	uint64_t reserve:32;
#else

	uint64_t reserve:32;

	/** number of queues per pciport */
	uint64_t cmdq_per_pciport:16;

	/** number of links on each interface*/
	uint64_t links_per_if:8;

	/** number of cmd-queues per interface*/
	uint64_t cmdq_per_if:8;
#endif
} octeon_pko_config_t;

/** Structure to define the configuration attributes for different FPA pools. 
 *  Applicable to all Octeon processors. 
 **/
typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN

	/** FPA pool buffer size */
	uint64_t pool_buf_size:32;

	/** FPA pool buffer count */
	uint64_t pool_buf_cnt:32;
#else

	/** FPA pool buffer count */
	uint64_t pool_buf_cnt:32;

	/** FPA pool buffer size */
	uint64_t pool_buf_size:32;
#endif

} octeon_fpapool_config_t;

/** This structure conatins the NIC link configuration attributes,
 *  common for all the OCTEON Modles.
 */
typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	/** Number of IOQs for each interface */
	uint64_t num_ioqs:8;

	/** Starting IOQ number */
	uint64_t srn:8;

	uint64_t reserve:48;
#else

	uint64_t reserve:48;

	/** Starting IOQ number */
	uint64_t srn:8;

	/** Number of IOQs for each interface */
	uint64_t num_ioqs:8;

#endif
} octeon_nicport_config_t;

/** Structure to define the configuration attributes for meta data. 
 *  Applicable to all Octeon processors. 
 */
typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN

	/** max memory( in MB) for booting SE app'n */
	uint64_t mem_size:8;

	/** max OCTEON cores for booting SE app'n */
	uint64_t core_cnt:8;

	/* Control IO Queue number for both host and Core */
	uint64_t ctrlq_num:8;

	/** Support for separate control command bufs */
	uint64_t setup_ctl_bufs:1;

	/** Support for exclusive unicast/multicast promisc mode */
	uint64_t fw_dmac_filter:1;

	/** Extended stats support in firmware */
	uint64_t extended_stats:1;

	/** BP for SLI OQ */
	uint64_t enable_sli_oq_bp:1;

	/** Control IQ Group */
	uint64_t ctrlq_grp:4;

	/** Flags */
	uint64_t flags:16;

	/** cn70xx_hostfw_hs_config data crc */
	uint64_t crc:16;

	/** Host link status polling period */
	uint64_t oct_link_query_interval:16;

	/** Oct link status polling period */
	uint64_t host_link_query_interval:16;

	/** number of physical functions exist on this MAC port */
	uint64_t num_pfs:8;

	/** flag for MTU 1500 */
	uint64_t enable_mtu_vlan:1;

	uint64_t rsvd:7;
    /** RESERVED */
	uint64_t reserved:16;

#else

	/** cn70xx_hostfw_hs_config data crc */
	uint64_t crc:16;

	/** Flags */
	uint64_t flags:16;

	/** Control IQ Group */
	uint64_t ctrlq_grp:4;

	/** BP for SLI OQ */
	uint64_t enable_sli_oq_bp:1;

	/** Extended stats support in firmware */
	uint64_t extended_stats:1;

	/** Support for exclusive unicast/multicast promisc mode */
	uint64_t fw_dmac_filter:1;

	/** Support for separate control command bufs */
	uint64_t setup_ctl_bufs:1;

	/* Control IO Queue number for both host and Core */
	uint64_t ctrlq_num:8;

	/** max OCTEON cores for booting SE app'n */
	uint64_t core_cnt:8;

	/** max memory( in MB) for booting SE app'n */
	uint64_t mem_size:8;

	/** RESERVED */
	uint64_t reserved:16;

	uint64_t rsvd:7;

	/** flag for MTU 1500 */
	uint64_t enable_mtu_vlan:1;

	/** number of physical functions exist on this MAC port */
	uint64_t num_pfs:8;

	/** Host link status polling period */
	uint64_t host_link_query_interval:16;

	/** Oct link status polling period */
	uint64_t oct_link_query_interval:16;

#endif

} octeon_misc_config_t;

typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
	/** PF device's starting ring number */
	uint64_t start_ring_num:8;

	/** Number of PF device IO queues   */
	uint64_t total_pf_rings:8;

	/** Number of rings assigned to VF  */
	uint64_t rings_per_vf:8;

	/** Number of VF devices enabled   */
	uint64_t num_vfs:8;

	/** RESERVED */
	uint64_t reserved:32;

#else

	/** RESERVED */
	uint64_t reserved:32;

	/** Number of VF devices enabled   */
	uint64_t num_vfs:8;

	/** Number of rings assigned to VF  */
	uint64_t rings_per_vf:8;

	/** Number of PF device IO queues   */
	uint64_t total_pf_rings:8;

	/** PF device's starting ring number */
	uint64_t start_ring_num:8;

#endif
} octeon_sriov_config_t;

/** Structure to fill up the core configuration received 
 *   during the host-firmware handshake. 
 * */
typedef struct {
#if __CAVIUM_BYTE_ORDER  ==  __CAVIUM_LITTLE_ENDIAN
    /** PKIND value assigned for the DPI interface */
	uint64_t dpi_pkind:8;

    /** OCTEON core clock multiplier   */
	uint64_t core_tics_per_us:16;

    /** OCTEON coprocessor clock multiplier  */
	uint64_t coproc_tics_per_us:16;

    /** app that currently running on OCTEON  */
	uint64_t app_mode:16;

    /** Number of Interfaces in OCTEON */
	uint64_t num_intf:8;

#else

    /** Number of Interfaces in OCTEON */
	uint64_t num_intf:8;

	/** app that currently running on OCTEON  */
	uint64_t app_mode:16;

	/** OCTEON coprocessor clock multiplier  */
	uint64_t coproc_tics_per_us:16;

	/** OCTEON core clock multiplier   */
	uint64_t core_tics_per_us:16;

	/** PKIND value assigned for the DPI interface */
	uint64_t dpi_pkind:8;
#endif
} octeon_core_config_t;

/** Structure to define the configuration for all OCTEON processors. */
typedef struct {

	/** Input Queue attributes. */
	octeon_iq_config_t iq;

	/** Output Queue attributes. */
	octeon_oq_config_t oq;

	/** OCTEON PKO attributes */
	octeon_pko_config_t pko[MAX_PKO_CONFIG];

	/** FPA pool attributes */
	octeon_fpapool_config_t fpa[MAX_FPA1_POOLS];

	/** NIC Port Configuration */
	octeon_nicport_config_t port_cfg;

	octeon_sriov_config_t pf_sriov_cfg[MAX_PF_FUNCTIONS];

	octeon_core_config_t core_cfg;

	/** Miscellaneous attributes */
	octeon_misc_config_t misc;

} octeon_config_t;

/** Structure to define the configuration for CNXK PF domain Octeon processors. */
typedef octeon_config_t cnxk_pf_config_t;

/** Structure to define the configuration for CNXK VF domain Octeon processors. */
typedef octeon_config_t cnxk_vf_config_t;

/** Structure to define the configuration for CN93XX PF domain Octeon processors. */
typedef octeon_config_t cn93xx_pf_config_t;

/** Structure to define the configuration for CN93XX VF domain Octeon processors. */
typedef octeon_config_t cn93xx_vf_config_t;

/** Structure to define the configuration for CN83XX PF domain Octeon processors. */
typedef octeon_config_t cn83xx_pf_config_t;

/** Structure to define the configuration for CN83XX VF domain Octeon processors. */
typedef octeon_config_t cn83xx_vf_config_t;

/* Maximum number of ordered requests to check for completion. */
#define OCTEON_MAX_ORDERED_COMPLETION	16

/* The following config values are fixed and should not be modified. */

/* Maximum address space to be mapped for Octeon's BAR1 index-based access. */
#define  MAX_BAR1_MAP_INDEX			16
#define  OCTEON_BAR1_ENTRY_SIZE		(4 * 1024 * 1024)

/* BAR1 Index 0 to (MAX_BAR1_MAP_INDEX - 1) for normal mapped memory access.
   Bar1 register at MAX_BAR1_MAP_INDEX used by driver for dynamic access. */
#define  MAX_BAR1_IOREMAP_SIZE		((MAX_BAR1_MAP_INDEX + 1) * OCTEON_BAR1_ENTRY_SIZE)

/* Response lists - 1 ordered, 1 unordered-blocking, 1 unordered-nonblocking */
/* NoResponse Lists are now maintained with each IQ. (Dec' 2007). */
#define MAX_RESPONSE_LISTS           3

/* Number of buffer pools - always fixed at 6. */
#define BUF_POOLS                    6

/*-------------- Dispatch function lookup table -----------*/
/* Opcode hash bits. The opcode is hashed on the lower 6-bits to lookup the
   dispatch table. */
#define OPCODE_MASK_BITS             6

/* Mask for the 6-bit lookup hash */
#define OCTEON_OPCODE_MASK           0x3f

/* Size of the dispatch table. The 6-bit hash can index into 2^6 entries */
#define DISPATCH_LIST_SIZE			(1 << OPCODE_MASK_BITS)

/*----------- The buffer pool -------------------*/

/* Number of  32k buffers. */
#define HUGE_BUFFER_CHUNKS				32

/* Number of  16k buffers. */
#define LARGE_BUFFER_CHUNKS             64

/* Number of  8k buffers. */
#define MEDIUM_BUFFER_CHUNKS            64

/* Number of  4k buffers. */
#define SMALL_BUFFER_CHUNKS             128

/* Number of  2k buffers. */
#define TINY_BUFFER_CHUNKS              512

/* Number of  1k buffers. */
#define EX_TINY_BUFFER_CHUNKS           1024

#define HUGE_BUFFER_CHUNK_SIZE          (32*1024)

#define LARGE_BUFFER_CHUNK_SIZE         (16*1024)

#define MEDIUM_BUFFER_CHUNK_SIZE        (8*1024)

#define SMALL_BUFFER_CHUNK_SIZE         (4*1024)

#define TINY_BUFFER_CHUNK_SIZE	        (2*1024)

#define EX_TINY_BUFFER_CHUNK_SIZE       (1*1024)

#define  MAX_FRAGMENTS                  32

#define  MAX_BUFFER_CHUNKS              1500

/* Maximum number of Octeon Instruction (command) queues */
#define MAX_OCTEON_INSTR_QUEUES         CN83XX_MAX_INPUT_QUEUES

/* Maximum number of Octeon Instruction (command) queues */
#define MAX_OCTEON_OUTPUT_QUEUES        128

/* Maximum number of DMA software output queues per Octeon device. 
   Though CN56XX supports 5 DMA engines, only the first 2 can generate
   interrupts on the host. So we stick with 2 for the time being. */
#define MAX_OCTEON_DMA_QUEUES      		2

#endif /* __OCTEON_CONFIG_H__  */

/* $Id: octeon_config.h 170604 2018-03-20 14:52:48Z vvelumuri $ */
