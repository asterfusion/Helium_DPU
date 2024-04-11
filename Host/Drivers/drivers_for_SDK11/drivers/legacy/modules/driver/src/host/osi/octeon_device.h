/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_device.h
    \brief Host Driver: This file defines the octeon device structure.
*/

#ifndef  _OCTEON_DEVICE_H_
#define  _OCTEON_DEVICE_H_

#include "cavium_sysdep.h"
#include "octeon_config.h"

typedef struct _OCTEON_DEVICE octeon_device_t;


#include "octeon_stats.h"
#include "octeon_iq.h"
#include "octeon_instr.h"
#include "octeon_droq.h"
#include "pending_list.h"
#include "response_manager.h"
#include "octeon_debug.h"
#include "octeon-common.h"

/* OCTEON TX models */
#include "cn83xx_pf_device.h"
#include "cn83xx_vf_device.h"

/* OCTEON TX2 models */
#include "cn93xx_pf_device.h"
#include "cn93xx_vf_device.h"
#include "cnxk_pf_device.h"
#include "cnxk_vf_device.h"
#include "octeon_mbox.h"
#include "barmap.h"

#define PCI_DMA_64BIT                  0xffffffffffffffffULL

#define CAVIUM_PCI_CACHE_LINE_SIZE     2

/** OCTEON TX Models */
#define  OCTEON_CN83XX_PCIID_PF       0xA300177d
#define  OCTEON_CN83XX_PCIID_VF       0xA303177d

/** OCTEON TX2 Models */
#define  OCTEON_CN93XX_PCIID_PF       0xB200177d   //96XX
#define  OCTEON_CN93XX_PCIID_VF       0xB203177d   //TODO:96XX VF

#define  OCTEON_CN3380_PCIID_PF       0x3380177d   //LIO3
#define  OCTEON_CN3383_PCIID_VF       0x3383177d   //TODO:LIO3 VF

#define  OCTEON_CN98XX_PCIID_PF       0xB100177d   //98XX
#define  OCTEON_CN98XX_PCIID_VF       0xB103177d   //TODO:98XX VF

#define  OCTEON_CN95N_PCIID_PF       0xB400177d   //95n
#define  OCTEON_CN95N_PCIID_VF       0xB403177d   //95n VF

#define  OCTEON_CN95O_PCIID_PF       0xB600177d   //95o
#define  OCTEON_CN95O_PCIID_VF       0xB603177d   //95o VF

#define  OCTEON_CN10KA_PCIID_PF      0xB900177d   //106XX PF
#define  OCTEON_CN10KA_PCIID_VF      0xB903177d   //106XX VF

#define  OCTEON_CNF10KA_PCIID_PF      0xBA00177d
#define  OCTEON_CNF10KA_PCIID_VF      0xBA03177d

#define  OCTEON_CNF10KB_PCIID_PF      0xBC00177d
#define  OCTEON_CNF10KB_PCIID_VF      0xBC03177d

#define  OCTEON_CN10KB_PCIID_PF      0xBD00177d
#define  OCTEON_CN10KB_PCIID_VF      0xBD03177d

/** Driver identifies chips by these Ids, created by clubbing together
    DeviceId+RevisionId; Where Revision Id is not used to distinguish
    between chips, a value of 0 is used for revision id.
*/

/** OCTEON TX MODELS */
#define  OCTEON_CN83XX_ID_PF             0xA300
#define  OCTEON_CN83XX_ID_VF             0xA303

/** OCTEON TX2 MODELS */
#define  OCTEON_CN93XX_ID_PF             0xB200   //96XX
#define  OCTEON_CN93XX_ID_VF             0xB203   //TODO:96XX VF

#define  OCTEON_CN3380_ID_PF             0x3380   //96XX
#define  OCTEON_CN3380_ID_VF             0x3383   //TODO:96XX VF

#define  OCTEON_CN98XX_ID_PF             0xB100   //98XX
#define  OCTEON_CN98XX_ID_VF             0xB103   //TODO:98XX VF

#define  OCTEON_CN95N_ID_PF             0xB400   //95N
#define  OCTEON_CN95N_ID_VF             0xB403   //95N VF

#define  OCTEON_CN95O_ID_PF             0xB600   //95O
#define  OCTEON_CN95O_ID_VF             0xB603   //95O VF

#define  OCTEON_CN10KA_ID_PF            0xB900   //106XX
#define  OCTEON_CN10KA_ID_VF            0xB903

#define OCTEON_CNF10KA_ID_PF		0xBA00
#define OCTEON_CNF10KA_ID_VF		0xBA03

#define OCTEON_CNF10KB_ID_PF		0xBC00
#define OCTEON_CNF10KB_ID_VF		0xBC03

#define OCTEON_CN10KB_ID_PF		0xBD00
#define OCTEON_CN10KB_ID_VF		0xBD03

#define OCTEON_CN83XX_PF(chip_id) \
	(chip_id == OCTEON_CN83XX_ID_PF)

#define OCTEON_CN93XX_PF(chip_id) \
	(chip_id == OCTEON_CN93XX_ID_PF)

#define OCTEON_CN98XX_PF(chip_id) \
	(chip_id == OCTEON_CN98XX_ID_PF)

#define OCTEON_CNXK_PF(chip_id) \
	(chip_id == OCTEON_CN10KA_ID_PF || \
	 chip_id == OCTEON_CN10KB_ID_PF)

#define OCTEON_CNFXK_PF(chip_id) \
	(chip_id == OCTEON_CNF10KA_ID_PF || \
	 chip_id == OCTEON_CNF10KB_ID_PF)

#define OCTEON_CN9XXX_PF(chip_id) \
	 (OCTEON_CN93XX_PF(chip_id) || \
	  OCTEON_CN98XX_PF(chip_id))

#define OCTEON_CN9PLUS_PF(chip_id) \
	 (OCTEON_CN93XX_PF(chip_id) || \
	  OCTEON_CN98XX_PF(chip_id) || \
	  OCTEON_CNXK_PF(chip_id))

#define OCTEON_CN8PLUS_PF(chip_id) \
	(OCTEON_CN83XX_PF(chip_id) || \
	 OCTEON_CN93XX_PF(chip_id) || \
	 OCTEON_CN98XX_PF(chip_id) || \
	 OCTEON_CNXK_PF(chip_id))


#define OCTEON_CN83XX_VF(chip_id) \
	(chip_id == OCTEON_CN83XX_ID_VF)

#define OCTEON_CN93XX_VF(chip_id) \
	(chip_id == OCTEON_CN93XX_ID_VF)

#define OCTEON_CN98XX_VF(chip_id) \
	(chip_id == OCTEON_CN98XX_ID_VF)

#define OCTEON_CNXK_VF(chip_id) \
	(chip_id == OCTEON_CN10KA_ID_VF)

#define OCTEON_CN9XXX_VF(chip_id) \
	 (OCTEON_CN93XX_VF(chip_id) || \
	  OCTEON_CN98XX_VF(chip_id))

#define OCTEON_CN9PLUS_VF(chip_id) \
	 (OCTEON_CN93XX_VF(chip_id) || \
	  OCTEON_CN98XX_VF(chip_id) || \
	  OCTEON_CNXK_VF(chip_id))

#define OCTEON_CN8PLUS_VF(chip_id) \
	(OCTEON_CN83XX_VF(chip_id) || \
	 OCTEON_CN93XX_VF(chip_id) || \
	 OCTEON_CN98XX_VF(chip_id) || \
	 OCTEON_CNXK_VF(chip_id))

#define OCTEON_CN83XX_PF_OR_VF(chip_id) \
	((OCTEON_CN83XX_PF(chip_id)) || \
	 (OCTEON_CN83XX_VF(chip_id)))

#define OCTEON_CN93XX_PF_OR_VF(chip_id) \
	((OCTEON_CN93XX_PF(chip_id)) || \
	 (OCTEON_CN93XX_VF(chip_id)))

#define OCTEON_CN98XX_PF_OR_VF(chip_id) \
	((OCTEON_CN98XX_PF(chip_id)) || \
	 (OCTEON_CN98XX_VF(chip_id)))

#define OCTEON_CNXK_PF_OR_VF(chip_id) \
	((OCTEON_CNXK_PF(chip_id)) || \
	 (OCTEON_CNXK_VF(chip_id)))

#define OCTEON_CN9XXX_PF_OR_VF(chip_id) \
	((OCTEON_CN9XXX_PF(chip_id)) || \
	 (OCTEON_CN9XXX_VF(chip_id)))

#define OCTEON_CN9PLUS_PF_OR_VF(chip_id) \
	((OCTEON_CN9PLUS_PF(chip_id)) || \
	 (OCTEON_CN9PLUS_VF(chip_id)))

#define OCTEON_CN8PLUS_PF_OR_VF(chip_id) \
	((OCTEON_CN8PLUS_PF(chip_id)) || \
	 (OCTEON_CN8PLUS_VF(chip_id)))

/** Endian-swap modes supported by Octeon. */
enum octeon_pci_swap_mode {
	OCTEON_PCI_PASSTHROUGH = 0,
	OCTEON_PCI_64BIT_SWAP = 1,
	OCTEON_PCI_32BIT_BYTE_SWAP = 2,
	OCTEON_PCI_32BIT_LW_SWAP = 3
};

/** Flags to disable and enable Interrupts **/
#define  OCTEON_INPUT_INTR    (1)
#define  OCTEON_OUTPUT_INTR   (2)
#define  OCTEON_MBOX_INTR     (4)
#define  OCTEON_ALL_INTR      0xff

#define  OCTEON_INPUT_INTR_MASK   0xfe
#define  OCTEON_OUTPUT_INTR_MASK  0xfd
#define  OCTEON_MBOX_INTR_MASK    0xfb

/** Octeon Device state.
 *  Each octeon device goes through each of these states 
 *  as it is initialized.
 */
//Shuffeled the states, as per the init sequence. 
//Removed the Pending list state, as now it is part of IQ.
// Removed the STOPPING state, as it is not used anywhere.
#define    OCT_DEV_CHECK_FW               0x0
#define    OCT_DEV_BEGIN_STATE            0x1
#define    OCT_DEV_PCI_MAP_DONE           0x2
#define    OCT_DEV_DISPATCH_INIT_DONE     0x3
#define    OCT_DEV_RESP_LIST_INIT_DONE    0x5
#define    OCT_DEV_HOST_OK                0x6
#define    OCT_DEV_CORE_OK                0x7
#define    OCT_DEV_INSTR_QUEUE_INIT_DONE  0x8
#define    OCT_DEV_DROQ_INIT_DONE         0x9
#define    OCT_DEV_RUNNING                0xA
#define    OCT_DEV_IN_RESET               0xB
#define    OCT_DEV_RESET_CLEANUP_DONE     0xC
#define    OCT_DEV_STOPPING               0xD
#define    OCT_DEV_STATE_INVALID          0xE

#define    OCT_DEV_STATES                 OCT_DEV_STATE_INVALID

#define OCTEON_MAX_MODULES 3
enum {
	OCTEON_START_MODULE = 1,
	OCTEON_RESET_MODULE = 2,
	OCTEON_STOP_MODULE
};

#define  OCT_DRV_ONLINE 1
#define  OCT_DRV_OFFLINE 2

#define SDP_HOST_LOADED                 0xDEADBEEFULL
#define SDP_GET_HOST_INFO               0xBEEFDEEDULL
#define SDP_HOST_INFO_RECEIVED          0xDEADDEULL
#define SDP_HANDSHAKE_COMPLETED         0xDEEDDEEDULL
/* 90 byte offset pkind */
#define OTX2_CUSTOM_PKIND		59
/* 24 byte offset pkind */
#define OTX2_GENERIC_PCIE_EP_PKIND	57
/* 0 byte offset pkind */
#define OTX2_LOOP_PCIE_EP_PKIND		0
#ifdef CONFIG_PPORT
#define OTX2_PKIND		OTX2_CUSTOM_PKIND
#else
#define OTX2_PKIND		OTX2_GENERIC_PCIE_EP_PKIND
#endif

typedef void (*cavium_oei_cb_t)(octeon_device_t *oct);

/*---------------------------DISPATCH LIST-------------------------------*/

/** The dispatch list entry.
 *  The driver keeps a record of functions registered for each 
 *  response header opcode in this structure. Since the opcode is
 *  hashed to index into the driver's list, more than one opcode
 *  can hash to the same entry, in which case the list field points
 *  to a linked list with the other entries.
 */
typedef struct {

  /** List head for this entry */
	cavium_list_t list;

  /** The opcode for which the above dispatch function & arg should be
      used */
	octeon_opcode_t opcode;

  /** The function to be called for a packet received by the driver */
	octeon_dispatch_fn_t dispatch_fn;

  /** The application specified argument to be passed to the above
      function along with the received packet */
	void *arg;

} octeon_dispatch_t;

/** The dispatch list structure. */
typedef struct {

	cavium_spinlock_t lock;

	/** Count of dispatch functions currently registered */
	uint32_t count;

	/** The list of dispatch functions */
	octeon_dispatch_t *dlist;

} octeon_dispatch_list_t;

/*-----------------------  THE OCTEON DEVICE  ---------------------------*/

#define OCT_MEM_REGIONS     3
/** PCI address space mapping information.
 *  Each of the 3 address spaces given by BAR0, BAR2 and BAR4 of
 *  Octeon gets mapped to different physical address spaces in
 *  the kernel. 
 */
typedef struct {

  /** PCI address to which the BAR is mapped. */
	unsigned long start;

  /** Length of this PCI address space. */
	unsigned long len;

  /** Length that has been mapped to phys. address space. */
	unsigned long mapped_len;

  /** The physical address to which the PCI address space is mapped. */
	void *hw_addr;

  /** Flag indicating the mapping was successful. */
	int done;

} octeon_mmio;

#define   MAX_OCTEON_MAPS    32

/** Map of Octeon core memory address to Octeon BAR1 indexed space. */
typedef struct {

  /** Starting Core address mapped */
	uint64_t core_addr;

  /** Physical address (of the BAR1 mapped space) 
      corressponding to core_addr. */
	void *mapped_addr;

  /** Indicator that the mapping is valid. */
	int valid;

} octeon_range_table_t;

/* \cond */

typedef struct {

	uint64_t iq;

	uint64_t oq;

	uint64_t iq64B;

} octeon_io_enable_t;

/* \endcond */

struct octeon_reg_list {

	uint32_t *pci_win_wr_addr_hi;
	uint32_t *pci_win_wr_addr_lo;
	uint64_t *pci_win_wr_addr;

	uint32_t *pci_win_rd_addr_hi;
	uint32_t *pci_win_rd_addr_lo;
	uint64_t *pci_win_rd_addr;

	uint32_t *pci_win_wr_data_hi;
	uint32_t *pci_win_wr_data_lo;
	uint64_t *pci_win_wr_data;

	uint32_t *pci_win_rd_data_hi;
	uint32_t *pci_win_rd_data_lo;
	uint64_t *pci_win_rd_data;
};

struct octeon_fn_list {

	void (*setup_iq_regs) (struct _OCTEON_DEVICE *, int);
	void (*setup_oq_regs) (struct _OCTEON_DEVICE *, int);
	void (*setup_mbox_regs) (struct _OCTEON_DEVICE *, int);

	cvm_intr_return_t (*interrupt_handler) (void *);
	cvm_intr_return_t (*msix_interrupt_handler) (void *);
	int (*soft_reset) (struct _OCTEON_DEVICE *);
	int (*setup_device_regs) (struct _OCTEON_DEVICE *);
	void (*reinit_regs) (struct _OCTEON_DEVICE *);
	void (*bar1_idx_setup) (struct _OCTEON_DEVICE *, uint64_t, int, int);
	void (*bar1_idx_write) (struct _OCTEON_DEVICE *, int, uint32_t);
	 uint32_t(*bar1_idx_read) (struct _OCTEON_DEVICE *, int);
	 uint32_t(*update_iq_read_idx) (octeon_instr_queue_t *);

	void (*enable_oq_pkt_time_intr) (octeon_device_t *, int);
	void (*disable_oq_pkt_time_intr) (octeon_device_t *, int);

	void (*enable_interrupt) (void *, uint8_t);
	void (*disable_interrupt) (void *, uint8_t);

	void (*configure_sriov_vfs) (struct _OCTEON_DEVICE *);
	void (*enable_io_queues) (struct _OCTEON_DEVICE *);
	void (*disable_io_queues) (struct _OCTEON_DEVICE *);
	void (*enable_input_queue) (struct _OCTEON_DEVICE *, int);
	void (*disable_input_queue) (struct _OCTEON_DEVICE *, int);
	void (*enable_output_queue) (struct _OCTEON_DEVICE *, int);
	void (*disable_output_queue) (struct _OCTEON_DEVICE *, int);
	void (*force_io_queues_off) (struct _OCTEON_DEVICE *);
	void (*dump_registers) (struct _OCTEON_DEVICE *);
	int (*send_mbox_cmd)(struct _OCTEON_DEVICE *otx_epvf, union otx_vf_mbox_word cmd,
			     union otx_vf_mbox_word *rsp);
	int (*send_mbox_cmd_nolock)(struct _OCTEON_DEVICE *otx_epvf, union otx_vf_mbox_word cmd,
				    union otx_vf_mbox_word *rsp);

};

/* wrappers around work structs */
struct cavium_wk {
	struct work_struct work;
	void *ctxptr;
	u64 ctxul;
};
struct cavium_wq {
	struct workqueue_struct *wq;
	struct cavium_wk wk;
};

struct cavium_delayed_wk {
	struct delayed_work work;
	void *ctxptr;
	u64 ctxul;
};

struct cavium_delayed_wq {
	struct workqueue_struct *wq;
	struct cavium_delayed_wk wk;
};

#define MAX_MSIX_VECTORS	64

typedef struct cvm_sriov_info {

	/** Number of rings assigned to VF  */
	uint32_t rings_per_vf;

	/** Number of VF devices enabled   */
	uint32_t num_vfs;

	/* Actual rings left for PF device */
	uint32_t rings_per_pf;

	/* SRN of PF usable IO queues   */
	uint32_t pf_srn;

	uint32_t sriov_enabled;

	uint32_t max_vfs;
	uint32_t vf_srn;
} octeon_sriov_info_t;

typedef struct octeon_mbox_data {
	uint32_t cmd;
	uint32_t total_len;
	uint32_t recv_len;
	uint32_t rsvd;
	uint64_t *data;

} octeon_mbox_data_t;

typedef struct cvm_mbox_info {
	uint32_t q_no;
	uint32_t state;
	/** SLI_MAC_PF_MBOX_INT for PF, SLI_PKT_MBOX_INT for VF. */
	void *mbox_int_reg;
	/** SLI_PKT_PF_VF_MBOX_SIG(0) for PF, SLI_PKT_PF_VF_MBOX_SIG(1) for VF. */
	void *mbox_write_reg;
	/** SLI_PKT_PF_VF_MBOX_SIG(1) for PF, SLI_PKT_PF_VF_MBOX_SIG(0) for VF. */
	void *mbox_read_reg;
	octeon_mbox_data_t mbox_data;

	/* added for new mail box */
	cavium_mutex_t lock;
	uint32_t vf_id;
	struct cavium_wk wk;
	octeon_device_t *oct;
	uint64_t *pf_vf_data_reg;
	uint64_t *vf_pf_data_reg;
	int32_t config_data_index;
	int32_t message_len;
	uint8_t config_data[MBOX_MAX_DATA_BUF_SIZE];
} octeon_mbox_t;

typedef struct cvm_ioq_vector {

	octeon_device_t *oct_dev;
	octeon_instr_queue_t *iq;
	octeon_droq_t *droq;
	octeon_mbox_t *mbox;
	cpumask_t affinity_mask;
	uint32_t ioq_num;

} octeon_ioq_vector_t;

#define OCTEON_NON_SRIOV_MODE                 (1 << 0)
#define OCTEON_SRIOV_MODE                     (1ULL << 1)
#define OCTEON_MSIX_CAPABLE                   (1 << 2)
#define OCTEON_MBOX_CAPABLE	                  (1ULL << 3)
#define OCTEON_MSIX_AFFINITY_CAPABLE          (1 << 4)

struct iq_intr_wq {
	struct delayed_work work;
	struct workqueue_struct *wq;
	octeon_device_t *oct;
	uint64_t last_ts;
	uint64_t last_pkt_cnt[64];
};

/* The Octeon VF device specific info data structure.*/
struct octep_vf_info {
	u8 mac_addr[ETH_ALEN];
	u32 flags;
};

struct oct_ep_ptp_clock {
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info caps;
	octeon_device_t *oct_dev;
};
/** The Octeon device. 
 *  Each Octeon device has this structure to represent all its
 *  components.
 */
struct _OCTEON_DEVICE {
	/** work queue to initialize device */
	struct cavium_delayed_wq dev_init_wq;

	int num_iqs;

	/** The input instruction queues */
	octeon_instr_queue_t *instr_queue[MAX_OCTEON_INSTR_QUEUES];

	int num_oqs;

	/** The DROQ output queues  */
	octeon_droq_t *droq[MAX_OCTEON_OUTPUT_QUEUES];

   /** Lock for this Octeon device */
	cavium_spinlock_t oct_lock;

   /** OS dependent PCI device pointer */
	cavium_pci_device_t *pci_dev;

   /** Chip specific information. */
	void *chip;

   /** Octeon Chip type. */
	uint16_t chip_id;
	uint16_t rev_id;

   /** This device's id - set by the driver. */
	uint16_t octeon_id;

   /** This device's PEM num used for traffic. */
	uint16_t pem_num;

   /** This device's PCIe port used for traffic. */
	uint16_t pcie_port;

	/* EPF Number */
	uint8_t epf_num;

   /** PCIe PF's function number in multi-function devices. */
	uint8_t pf_num;

   /** The state of this device */
	cavium_atomic_t status;

   /** memory mapped io range */
	octeon_mmio mmio[OCT_MEM_REGIONS];

	struct octeon_reg_list reg_list;

	struct octeon_fn_list fn_list;

	cavium_atomic_t interrupts;

	/* TODO: remove this unused flag */
	cavium_atomic_t in_interrupt;


	cavium_tasklet_struct_t comp_tasklet;

	uint64_t napi_mask;

	void *poll_list;

	cavium_spinlock_t poll_lock;

	/** Moved to IQ structure */
//   uint32_t                 pend_list_size;
//   octeon_pending_list_t    *plist;

   /** The doubly-linked list of instruction response */
	octeon_response_list_t response_list[MAX_RESPONSE_LISTS];
   /** A table maintaining maps of core-addr to BAR1 mapped address. */
	octeon_range_table_t range_table[MAX_OCTEON_MAPS];

   /** Total number of core-address ranges mapped (Upto 32). */
	uint32_t map_count;

	octeon_io_enable_t io_qmask;

   /** List of dispatch functions */
	octeon_dispatch_list_t dispatch;


   /** The /proc file entries */
	void *proc_root_dir;

   /** Statistics for this octeon device. Does not include IQ, DROQ stats */
	oct_dev_stats_t stats;

   /** IRQ assigned to this device. */
	int irq;

	int msi_on;

	int msix_on;

	int num_irqs;

	cavium_msix_entry_t *msix_entries;

	/* when requesting IRQs, the names are stored here */
	void *irq_name_storage;
#define INTRNAMSIZ (32)
#define IRQ_NAME_OFF(i) ((i) * INTRNAMSIZ)

   /** PF device's sr-iov information.  */
	octeon_sriov_info_t sriov_info;

   /** Mail Box details of each octeon queue. */
	octeon_mbox_t *mbox[MAX_OCTEON_OUTPUT_QUEUES];

   /** IOq information of it's corresponding MSI-X interrupt. */
	octeon_ioq_vector_t *ioq_vector[MAX_MSIX_VECTORS];

	uint64_t drv_flags;

   /** Rings per Virtual Function. */
	int rings_per_vf;

   /** The core application is running in this mode. See octeon-drv-opcodes.h
       for values. */
	int app_mode;

   /** The name given to this device. */
	char device_name[32];

   /** Application Context */
	void *app_ctx;

	cavium_atomic_t hostfw_hs_state;

	cavium_atomic_t pfvf_hs_state;

	/*pkind value for DPI */
	uint8_t pkind;

	struct iq_intr_wq iq_intr_wq;

	/* mbox related */
	uint32_t mbox_wait_cond;
	int mbox_stop_thread;
	cavium_wait_channel mbox_wc;
	cavium_spinlock_t vf_mbox_lock;
	cvm_kthread_t mbox_id;
	void *mbox_cmd_queue;

	/* module handler status */
	cavium_atomic_t mod_status[OCTEON_MAX_MODULES];

	struct npu_bar_map npu_memmap_info;
	mv_facility_conf_t facility_conf[MV_FACILITY_COUNT];
	mv_facility_event_cb_t facility_handler[MV_FACILITY_COUNT];
	cavium_oei_cb_t oei_irq_handler;
	int is_alive_flag;	/* flag set by irq handler if alive */
	int heartbeat_miss_cnt; /* count of missed alive checks */
	/* VFs info */
	struct octep_vf_info vf_info[MAX_OCTEON_DEVICES];

	int mbox_cmd_id;

	uint8_t mbox_data_buf[MBOX_MAX_DATA_BUF_SIZE];

	int32_t mbox_data_index;

	int32_t mbox_rcv_message_len;

	/* PHC related fields */
	struct cavium_delayed_wq dev_poll_wq;
	struct oct_ep_ptp_clock *oct_ep_ptp_clock;
	struct kobject phc_sysfs_kobject;

} ____cacheline_aligned_in_smp;

#define CHIP_FIELD(oct, TYPE, field)             \
	(((octeon_##TYPE##_t *)(oct->chip))->field)

/*------------------ Function Prototypes ----------------------*/

/** Allocate memory for Input and Output queue structures for a octeon device */
octeon_device_t *octeon_allocate_device_mem(int);

/** Free memory for Input and Output queue structures for a octeon device */
void octeon_free_device_mem(octeon_device_t *);

/** Look up a free entry in the octeon_device table and allocate resources
    for the octeon_device_t  structure for an octeon device. Called at init
    time. */
octeon_device_t *octeon_allocate_device(int pci_id);

/**  Initialize the driver's dispatch list which is a mix of a hash table
  *  and a linked list. This is done at driver load time.
  *  @param octeon_dev - pointer to the octeon device structure.
  *  @return 0 on success, else -ve error value
  */
int octeon_init_dispatch_list(octeon_device_t * octeon_dev);

/**  Delete the driver's dispatch list and all registered entries.
  *  This is done at driver unload time.
  *  @param octeon_dev - pointer to the octeon device structure.
  */
void octeon_delete_dispatch_list(octeon_device_t * octeon_dev);

/**  Register dispatch functions for packets from core that are of 
  *  interest to the driver.
  *  @param octeon_id - octeon device id.
  */
void octeon_setup_driver_dispatches(uint32_t octeon_id);

/* Perform hot reset of Octeon device. The Octeon input & output queues
 * do not have to be re-allocated. The existing queue setup is reprogrammed
 * into the octeon device after this reset. */
int octeon_hot_reset(octeon_device_t * octeon_dev);

/** Get the octeon device pointer.
 *  @param octeon_id  - The id for which the octeon device pointer is required.
 *  @return Success: Octeon device pointer.
 *  @return Failure: NULL.
 */
octeon_device_t *get_octeon_device(uint32_t octeon_id);

/** Gets the octeon device id when the device structure is given.
 *  @return - The octeon device id.
 */
uint32_t get_octeon_id(octeon_device_t * octeon_dev);

/** Return the core clock cycles per microsecond. */
uint32_t octeon_get_cycles_per_usec(octeon_device_t * oct);

/** Called by the base device driver at init time to initialize the
  * module handler data structures.
  */
void octeon_init_module_handler_list(void);

/** Called by the base driver (in the poll thread) for each octeon
  * device when its state changes to CORE_OK (core application 
  * informs the host of type of application running). This routine
  * checks for handlers for the application type and calls the
  * handler start routine.
  * @param app_type  - The application type detected for the octeon device.
  * @param octeon_id - The device id for the octeon device.
  * @return -ENODEV if no handler was found for the application type or an
  *         invalid octeon id was passed.
  *         -EINVAL if invalid operation was specified.
  *         0 on success.
  */
int octeon_start_module(uint32_t app_type, uint32_t octeon_id);

/** Called by the base driver for each octeon device when the device is being
  * reset (due to hot-reset initiated by user). This function calls the reset
  * routine of handlers for the application type specified.
  * @param app_type  - The application type detected for the octeon device.
  * @param octeon_id - The device id for the octeon device.
  * @return -ENODEV if no handler was found for the application type or an
  *         invalid octeon id was passed.
  *         -EINVAL if invalid operation was specified.
  *         0 on success.
  */
int octeon_reset_module(uint32_t app_type, uint32_t octeon_id);

/** Called by the base driver for each octeon device when the device is being
  * removed (either due to hot-plug or due to base module unload). This 
  * function calls the stop routine of handlers for the application type
  * specified.
  * @param app_type  - The application type detected for the octeon device.
  * @param octeon_id - The device id for the octeon device.
  * @return -ENODEV if no handler was found for the application type or an
  *         invalid octeon id was passed.
  *         -EINVAL if invalid operation was specified.
  *         0 on success.
  */
int octeon_stop_module(uint32_t app_type, uint32_t octeon_id);

char *get_oct_state_string(cavium_atomic_t * state_ptr);

char *get_oct_app_string(int app_mode);

int octeon_setup_instr_queues(octeon_device_t * oct);

int octeon_setup_output_queues(octeon_device_t * oct);

int octeon_setup_mbox(octeon_device_t * oct);

int octeon_enable_msix_interrupts(octeon_device_t * oct);

void octeon_enable_irq(octeon_droq_t *droq, octeon_instr_queue_t *iq);

int octeon_allocate_ioq_vector(octeon_device_t * oct);

int octeon_setup_irq_affinity(octeon_device_t * oct);

void octeon_disable_msix_interrupts(octeon_device_t * oct);

int octeon_clear_irq_affinity(octeon_device_t * oct);

int octeon_delete_mbox(octeon_device_t * oct);

int octeon_delete_ioq_vector(octeon_device_t * oct);

void octeon_set_io_queues_off(octeon_device_t * oct);

void octeon_set_droq_pkt_op(octeon_device_t * oct, int q_no, int enable);

int
octeon_send_short_command(octeon_device_t * oct,
			  uint16_t opcode,
			  uint8_t param, void *rptr, int rsize);

void *oct_get_config_info(octeon_device_t * oct);

int check_bp_on(octeon_device_t * oct);

void print_octeon_state_errormsg(octeon_device_t * oct);

/** Gets the octeon device configuration
 *  @return - pointer to the octeon configuration struture
 */
octeon_config_t *octeon_get_conf(octeon_device_t * oct);

extern int oct_stop_base_module(int oct_id, void *oct_dev);

int octeon_bar_access_valid(octeon_device_t * oct);
#endif

/* $Id: octeon_device.h 170599 2018-03-20 13:42:25Z vvelumuri $ */
