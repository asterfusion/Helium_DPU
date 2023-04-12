/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

/*!  \file  octeon_iq.h
     \brief Host Driver: Implementation of Octeon input queues.
*/

#ifndef  __OCTEON_IQ_H__
#define  __OCTEON_IQ_H__

#include "octeon_main.h"
#include "octeon_stats.h"

#define IQ_STATUS_RUNNING   1
#define IQ_STATUS_BP_ON     2

#define  IQ_TURN_BP_ON(iq)      ((iq)->status |= IQ_STATUS_BP_ON)
#define  IQ_TURN_BP_OFF(iq)     ((iq)->status &= ~(IQ_STATUS_BP_ON))
#define  IQ_CHECK_BP_ON(iq)     ((iq)->status & IQ_STATUS_BP_ON)

#define IQ_SEND_OK          0
#define IQ_SEND_STOP        1
#define IQ_SEND_FAILED     -1

/*-------------------------  INSTRUCTION QUEUE --------------------------*/

/* \cond */

#define NORESP_BUFTYPE_NONE          0
#define NORESP_BUFTYPE_INSTR         1
#define NORESP_BUFTYPE_NET_DIRECT    2
#define NORESP_BUFTYPE_NET           NORESP_BUFTYPE_NET_DIRECT
#define NORESP_BUFTYPE_NET_SG        3
#define NORESP_BUFTYPE_OHSM_SEND     4
#define NORESP_BUFTYPE_LAST          4

#define NORESP_TYPES                 NORESP_BUFTYPE_LAST

typedef struct {

	int buftype;

	void *buf;

} octeon_noresponse_list_t;

struct oct_noresp_free_list {

	octeon_noresponse_list_t *q;

	uint32_t put_idx, get_idx;

	cavium_atomic_t count;
};

typedef struct octeon_in_cnt_ism {
	void *pkt_cnt_addr;
	unsigned long pkt_cnt_dma;
} octeon_in_cnt_ism_t;

/* \endcond */

/** The instruction (input) queue. 
    The input queue is used to post raw (instruction) mode data or packet
    data to Octeon device from the host. Each input queue (upto 4) for
    a Octeon device has one such structure to represent it.
*/
typedef struct {

  /** A spinlock to protect access to the input ring.  */
	cavium_spinlock_t lock;

  /** Flag that indicates if the queue uses 64 byte commands. */
	uint32_t iqcmd_64B:1;

  /** Queue Number. Max 64 IQs */
	uint32_t iq_no:6;

	uint32_t rsvd:16;

	/* Controls the periodic flushing of iq */
	uint32_t do_auto_flush:1;

	uint32_t status:8;

  /** Maximum no. of instructions in this queue. */
	uint32_t max_count;

  /** Index in input ring where the driver should write the next packet. */
	uint32_t host_write_index;

  /** Index in input ring where Octeon is expected to read the next packet. */
	uint32_t octeon_read_index;

  /** This index aids in finding the window in the queue where Octeon 
      has read the commands. */
	uint32_t flush_index;

  /** This field keeps track of the instructions pending in this queue. */
	cavium_atomic_t instr_pending;

	uint32_t reset_instr_cnt;

  /** Pointer to the Virtual Base addr of the input ring. */
	uint8_t *base_addr;

	octeon_noresponse_list_t *nrlist;

	struct oct_noresp_free_list nr_free;

  /** Octeon doorbell register for the ring. */
	void *doorbell_reg;

  /** Octeon instruction count register for this ring. */
	void *inst_cnt_reg;

  /** Moved from OCTEOn Device Structure */
	uint32_t pend_list_size;

	void *plist;

  /** Number of instructions pending to be posted to Octeon. */
	uint32_t fill_cnt;

  /** The max. number of instructions that can be held pending by the driver. */
	uint32_t fill_threshold;

  /** The last time that the doorbell was rung. The unit is OS-dependent. */
	unsigned long last_db_time;

  /** The doorbell timeout. If the doorbell was not rung for this time and 
      fill_cnt is non-zero, ring the doorbell again. */
	unsigned long db_timeout;

  /** Statistics for this input queue. */
	oct_iq_stats_t stats;

  /** DMA mapped base address of the input descriptor ring. */
	unsigned long base_addr_dma;
	
  /** Host memory address. HW updates these address with the number of pkts that
      are read by Octeon. */	
	octeon_in_cnt_ism_t ism;

#ifdef OCT_NIC_IQ_USE_NAPI
    /** A spinlock to protect access to the input ring.*/
    spinlock_t iq_flush_running_lock;
#endif	

  /** Application context */
	void *app_ctx;
} octeon_instr_queue_t;

typedef octeon_instr_queue_t octeon_iq_t;

/*----------------------  INSTRUCTION FORMAT ----------------------------*/

/** 32-byte instruction format.
    Format of instruction for a 32-byte mode input queue.
*/
typedef struct {

  /** Pointer where the input data is available. */
	uint64_t dptr;

  /** Instruction Header.  */
	uint64_t ih;

  /** Pointer where the response for a RAW mode packet will be written
      by Octeon. */
	uint64_t rptr;

  /** Input Request Header. Additional info about the input. */
	uint64_t irh;

} octeon_instr_32B_t;

#define OCT_32B_INSTR_SIZE     (sizeof(octeon_instr_32B_t))

/** 64-byte instruction format.
    Format of instruction for a 64-byte mode input queue.
*/
typedef struct {

  /** Pointer where the input data is available. */
	uint64_t dptr;

  /** Instruction Header. */
	uint64_t ih;

  /** Pointer where the response for a RAW mode packet will be written
      by Octeon. */
	uint64_t rptr;

  /** Input Request Header. */
	uint64_t irh;

  /** Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[4];

} octeon_instr_64B_t;

#define OCT_64B_INSTR_SIZE     (sizeof(octeon_instr_64B_t))

/** 64-byte instruction format for OCTEON-III( CN7XXX) Models.
 *  For CN78xx the Instruction Header format is changed and hence
 *  Instruction command format is changed.
*/
typedef struct {

  /** Pointer where the input data is available. */
	uint64_t dptr;

  /** DPI Instruction Header. */
	uint64_t ih3;

  /** PKI Optional Instruction Header. */
	uint64_t pki_ih3;

#ifndef IOQ_PERF_MODE_O3
  /** Pointer where the response for a RAW mode packet will be written
      by Octeon. */
	uint64_t rptr;
#endif

  /** Input Request Header. */
	uint64_t irh;

  /** Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[3];

} octeon_instr3_64B_t;

typedef struct {

  /** Pointer where the input data is available. */
	uint64_t dptr;

  /** DPI Instruction Header. */
	uint64_t ih3;

#ifndef IOQ_PERF_MODE_O3
  /** Pointer where the response for a RAW mode packet will be written
      by Octeon. */
	uint64_t rptr;
#endif

  /** Input Request Header. */
	uint64_t irh;

  /** Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[4];

} octeontx2_instr3_64B_t;

/**
 *  octeon_init_instr_queue()
 *  @param octeon_dev      - pointer to the octeon device structure.
 *  @param iq_no           - queue to be initialized (0 <= q_no <= 3).
 *
 *  Called at driver init time for each input queue. iq_conf has the 
 *  configuration parameters for the queue.
 *
 *  @return  Success: 0   Failure: 1
 */
int octeon_init_instr_queue(octeon_device_t * octeon_dev, int iq_no);

/**
 *  octeon_delete_instr_queue()
 *  @param octeon_dev      - pointer to the octeon device structure.
 *  @param iq_no           - queue to be deleted (0 <= q_no <= 3).
 *
 *  Called at driver unload time for each input queue. Deletes all
 *  allocated resources for the input queue.
 *
 *  @return  Success: 0   Failure: 1
 */
int octeon_delete_instr_queue(octeon_device_t * octeon_dev, int iq_no);

int wait_for_instr_fetch(octeon_device_t * oct);

int wait_for_iq_instr_fetch(octeon_device_t * oct, int q_no);

/** API exported to other modules that want to post a command directly
  * into the Input queue. This way of sending a command to Octeon does not
  * provide for notification of completion or for a callback. Most modules
  * will not use this.
  * @param oct - octeon device pointer
  * @param iq  - pointer to the input queue to which the command is posted
  * @param force_db - flag indicating if the input queue doorbell should be
  *                   rung after this command is posted.
  * @param cmd - pointer to the 32-byte command structure.
  */
int
octeon_iq_post_command(octeon_device_t * oct,
		       octeon_instr_queue_t * iq, uint32_t force_db, void *cmd);

#define NORESP_SEND_OK       IQ_SEND_OK
#define NORESP_SEND_STOP     IQ_SEND_STOP
#define NORESP_SEND_FAILED   IQ_SEND_FAILED

int
octeon_send_noresponse_command(octeon_device_t * oct,
			       int iq_no,
			       int force_db,
			       void *cmd, void *buf, int datasize, int buftype);

/** API exported so that modules like octeon NIC module can flush the input
  * queue to which they had posted a command before.
  * @param oct - octeon device pointer
  * @param iq  - pointer to the octeon device input queue that will be flushed
  * @param pending_thresh - flush instruction queue iq when iq->instr_pending >= pending_thresh
  */
#ifdef OCT_NIC_IQ_USE_NAPI
int
octeon_flush_iq(octeon_device_t * oct, octeon_instr_queue_t * iq,
		uint32_t pending_thresh);
#else
void
octeon_flush_iq(octeon_device_t * oct, octeon_instr_queue_t * iq,
		uint32_t pending_thresh);
#endif

void octeon_perf_flush_iq(octeon_device_t * oct, octeon_instr_queue_t * iq);

int octeon_setup_iq(octeon_device_t * oct, int iq_no, void *app_ctx);

#endif /* __OCTEON_IQ_H__ */

/* $Id: octeon_iq.h 141410 2016-06-30 14:37:41Z mchalla $ */
