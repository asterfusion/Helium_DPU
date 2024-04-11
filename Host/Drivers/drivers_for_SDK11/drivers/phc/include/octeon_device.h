/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_device.h
    \brief Host Driver: This file defines the octeon device structure.
*/

#ifndef  _OCTEON_DEVICE_H_
#define  _OCTEON_DEVICE_H_

#include "linux_sysdep.h"

typedef struct _OCTEON_DEVICE octeon_device_t;


#if defined(linux) &&  defined(__KERNEL__)
#include <linux/types.h>
#endif

/* OCTEON TX2 models */
#include "cn93xx_pf_regs.h"
#include "cnxk_pf_regs.h"

/*  Maximum no. of octeon devices that the driver can support. */
#define   MAX_OCTEON_DEVICES           128

/* Maximum address space to be mapped for Octeon's BAR1 index-based access. */
#define  MAX_BAR1_MAP_INDEX			16
#define  OCTEON_BAR1_ENTRY_SIZE		(4 * 1024 * 1024)

/* BAR1 Index 0 to (MAX_BAR1_MAP_INDEX - 1) for normal mapped memory access.
 * Bar1 register at MAX_BAR1_MAP_INDEX used by driver for dynamic access.*
 */
#define  MAX_BAR1_IOREMAP_SIZE		((MAX_BAR1_MAP_INDEX + 1) * OCTEON_BAR1_ENTRY_SIZE)

/** OCTEON TX2 Models */
#define  OCTEON_CN93XX_PCIID_PF       0xB200177d   //96XX
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

/** OCTEON TX2 MODELS */
#define  OCTEON_CN93XX_ID_PF             0xB200   //96XX
#define  OCTEON_CN93XX_ID_VF             0xB203   //TODO:96XX VF
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


/** Endian-swap modes supported by Octeon. */
enum octeon_pci_swap_mode {
	OCTEON_PCI_PASSTHROUGH = 0,
	OCTEON_PCI_64BIT_SWAP = 1,
	OCTEON_PCI_32BIT_BYTE_SWAP = 2,
	OCTEON_PCI_32BIT_LW_SWAP = 3
};


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

	/** Lock for this Octeon device */
	spinlock_t oct_lock;

	/** OS dependent PCI device pointer */
	struct pci_dev *pci_dev;

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
	atomic_t status;

	/** memory mapped io range */
	octeon_mmio mmio[OCT_MEM_REGIONS];

	struct octeon_reg_list reg_list;
	/** The name given to this device. */
	char device_name[32];

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

/** Get the octeon device pointer.
 *  @param octeon_id  - The id for which the octeon device pointer is required.
 *  @return Success: Octeon device pointer.
 *  @return Failure: NULL.
 */
octeon_device_t *get_octeon_device(uint32_t octeon_id);

/** Gets the octeon device id when the device structure is given.
 *  @return - The octeon device id.
 */
uint32_t get_octeon_id(octeon_device_t *octeon_dev);

/* Return the core clock cycles per microsecond. */
uint32_t octeon_get_cycles_per_usec(octeon_device_t *oct);

void octeon_unmap_pci_barx(octeon_device_t *oct, int baridx);

int octeon_map_pci_barx(octeon_device_t *oct, int baridx, int max_map_len);

void octeon_destroy_resources(octeon_device_t *oct_dev);

#endif
