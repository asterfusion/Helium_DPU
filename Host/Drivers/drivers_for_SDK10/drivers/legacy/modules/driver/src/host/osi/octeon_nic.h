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

/*!  \file octeon_nic.h
     \brief Host NIC Driver: Routine to send network data & control packet to Octeon.
*/

#ifndef  __CAVIUM_NIC_H__
#define  __CAVIUM_NIC_H__

#include "cavium-list.h"
#include "octeon_device.h"
#include "octeon-nic-common.h"
#ifdef CONFIG_PPORT
#include "if_pport.h"
#endif

/* Maximum of 1 8-byte words can be sent in a NIC control message.
   There is support for upto 7 in the control command sent to Octeon but we
   restrict ourselves to what we need in the NIC module.
 */
#define  MAX_NCTRL_UDD  1

typedef void (*octnic_ctrl_pkt_cb_fn_t) (void *);

/** Structure of control information passed by the NIC module to the OSI
	layer when sending control commands to Octeon device software. */
typedef struct {

	/** Command to be passed to the Octeon device software. */
	octnet_cmd_t ncmd;

	/** Additional data that may be needed by some commands. */
	uint64_t udd[MAX_NCTRL_UDD];

	/** Time to wait for Octeon software to respond to this control command.
	    If wait_time is 0, OSI assumes no response is expected. */
	unsigned long wait_time;

	/** The network device that issued the control command. */
	unsigned long netpndev;

	/** Callback function called when the command has been fetched by
	    Octeon. */
	octnic_ctrl_pkt_cb_fn_t cb_fn;

	unsigned long rsvd;

} octnic_ctrl_pkt_t;

/** Structure of data information passed by the NIC module to the OSI
	layer when forwarding data to Octeon device software. */
typedef struct {

	/** Pointer to information maintained by NIC module for this packet. The
	    OSI layer passes this as-is to the driver. */
	void *buf;

	/** Type of buffer passed in "buf" aboce. */
	int buftype;

	/** Total data bytes to be transferred in this command. */
	int datasize;

	/** Command to be passed to the Octeon device software. */
	octeon_instr_64B_t cmd;

	/** Input queue to use to send this command. */
	int q_no;

} octnic_data_pkt_t;

/** Structure passed by NIC module to OSI layer to prepare a command to send
	network data to Octeon. */
typedef union {

	struct {
		uint32_t ifidx:8;
		uint32_t cksum_offset:7;
		uint32_t gather:1;
		uint32_t rsvd:16;
		union {
			uint32_t datasize;
			uint32_t gatherptrs;
		} u;
	} s;

	uint64_t u64;

} octnic_cmd_setup_t;

typedef struct {
	uint32_t resp_order;
} octnic_ctrl_params_t;

static inline int octnet_iq_is_full(octeon_device_t * oct, int q_no)
{
	return (cavium_atomic_read(&oct->instr_queue[q_no]->instr_pending)
		>= (oct->instr_queue[q_no]->max_count - 2));
}

static inline int octnet_iq_bp_on(octeon_device_t * oct, int q_no)
{
	return IQ_CHECK_BP_ON((octeon_iq_t *) & oct->instr_queue[q_no]);
}

#if defined(ETHERPCI)
static inline void
octnet_prepare_pci_cmd(octeon_device_t * oct,
		       octeon_instr_64B_t * cmd,
		       octnic_cmd_setup_t * setup, int q_no)
								 /* 66xx: q_no for ring backpressure */
#else
static inline void
octnet_prepare_pci_cmd(octeon_device_t * oct,
		       octeon_instr_64B_t * cmd, octnic_cmd_setup_t * setup)
#endif
{
	volatile octeon_instr_irh_t *irh = NULL;

	volatile octeon_instr_pki_ih3_t pki_ih3 = { 0 };
	octeon_instr3_64B_t o3_cmd = { 0 };
	octeontx2_instr3_64B_t o3tx_cmd = { 0 };
	octeon_instr_ihx_t ihx = { 0 };

	cmd->ih = 0ULL;

    if(oct->chip_id == OCTEON_CN83XX_PF
        || oct->chip_id == OCTEON_CN83XX_VF
	|| oct->chip_id == OCTEON_CN93XX_PF ||
	oct->chip_id == OCTEON_CN98XX_PF) {

		ihx.fsz = 16;
#if defined(ETHERPCI)
		ihx.pkind = oct->pkind + q_no;
		ihx.fsz += 8;	/* extra: 8B for PKI_IH3 */
#else
		ihx.pkind = oct->pkind;	/* The SDK decided PKIND value */
		if ((oct->chip_id == OCTEON_CN83XX_PF) ||
		    (oct->chip_id == OCTEON_CN83XX_VF))
			ihx.fsz += 8;	/* extra: 8B for PKI_IH3 */
		ihx.fsz += 8;	/* extra: 8B for Extra Hdr(TSO) */
#endif
		if (!setup->s.gather) {
			ihx.tlen = setup->s.u.datasize + ihx.fsz;
		} else {
			ihx.gsz = setup->s.u.gatherptrs;
			ihx.tlen = setup->s.rsvd + ihx.fsz;
		}
		/* Fill up O3 PKI_IH3 */
		if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF)) {
			pki_ih3.w = 1;
			//pki_ih3.raw = 1;
			//pki_ih3.utag = 1;
			pki_ih3.utt = 1;
			//pki_ih3.uqpg = 1;	/* leave it to PKI to use default QPG */

			//pki_ih3.tag = 0x11111111 + setup->s.ifidx;
			pki_ih3.tagtype = ORDERED_TAG;
			/** 
			 * QPG entry is allocated by the pkipf driver in the octeontx
			 * Currently it is allocated statically with each pkind having 32 qpg entries
			 */
			//pki_ih3.qpg = oct->pkind * 32;	/* PKI will use the defualt sttings */

			pki_ih3.pm = 0x0;	/* 0x0 - meant for Parse starting at LA (L2) */
			pki_ih3.sl = 32 + TOTAL_TAG_LEN;	/* sl will be sizeof(pki_ih3) */
		}
		o3_cmd.ih3 = *((uint64_t *) & ihx);
		o3tx_cmd.ih3 = *((uint64_t *) & ihx);
		if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF))
			o3_cmd.pki_ih3 = *((uint64_t *) & pki_ih3);
		o3_cmd.rptr = 0ull;
		o3tx_cmd.rptr = 0ull;
		o3_cmd.irh = 0ull;
		o3tx_cmd.irh = 0ull;

		irh = (octeon_instr_irh_t *) & o3_cmd.irh;
		if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF))
			irh = (octeon_instr_irh_t *) & o3_cmd.irh;
		if(oct->chip_id == OCTEON_CN93XX_PF ||
		   oct->chip_id == OCTEON_CN98XX_PF)
			irh = (octeon_instr_irh_t *) & o3tx_cmd.irh;
		if (setup->s.cksum_offset)
			irh->rlenssz = setup->s.cksum_offset;

		irh->opcode = OCT_NW_PKT_OP;
		irh->param = setup->s.ifidx;

        /* Swap the FSZ in here, to avoid swapping on Octeon side */
        octeon_swap_8B_data(&o3_cmd.rptr, 1);
        octeon_swap_8B_data(&o3_cmd.irh, 1);
        octeon_swap_8B_data(&o3tx_cmd.rptr, 1);
        octeon_swap_8B_data(&o3tx_cmd.irh, 1);


		/* copy the 64B CN78xx cmd to actual 64B command */
		if((oct->chip_id == OCTEON_CN83XX_PF) || (oct->chip_id == OCTEON_CN83XX_VF))
			memcpy(cmd, (const void *)&o3_cmd, 64);
		if(oct->chip_id == OCTEON_CN93XX_PF ||
		   oct->chip_id == OCTEON_CN98XX_PF)
			memcpy(cmd, (const void *)&o3tx_cmd, 64);

	}

}

int octnet_send_nic_data_pkt(octeon_device_t * oct, octnic_data_pkt_t * ndata);

int
octnet_send_nic_ctrl_pkt(octeon_device_t * oct, octnic_ctrl_pkt_t * nctrl,
			 octnic_ctrl_params_t nparams);

void
octnet_prepare_ls_soft_instr(octeon_device_t * oct,
			     octeon_soft_instruction_t * si);

#endif

/* $Id: octeon_nic.h 170607 2018-03-20 15:52:25Z vvelumuri $ */
