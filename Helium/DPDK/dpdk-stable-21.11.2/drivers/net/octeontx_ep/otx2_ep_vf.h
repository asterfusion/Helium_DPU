/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */
#ifndef _OTX2_EP_VF_H_
#define _OTX2_EP_VF_H_

int
otx2_ep_vf_setup_device(struct otx_ep_device *sdpvf);

struct otx2_ep_instr_64B {
	/* Pointer where the input data is available. */
	uint64_t dptr;

	/* OTX_EP Instruction Header. */
	union otx_ep_instr_ih ih;

	/** Pointer where the response for a RAW mode packet
	 * will be written by OCTEON TX.
	 */
	uint64_t rptr;

	/* Input Request Header. */
	union otx_ep_instr_irh irh;

	/* Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[4];
};


struct otx2_ep_soft_instr {
	/** Input data pointer. It is either pointing directly to input data
	 *  or to a gather list.
	 */
	void *dptr;

	/** Response from OCTEON TX2 comes at this address. It is either
	 *  directlty pointing to output data buffer or to a scatter list.
	 */
	void *rptr;

	/* The instruction header. All input commands have this field. */
	union otx_ep_instr_ih ih;

	/* Input request header. */
	union otx_ep_instr_irh irh;

	/** The PCI instruction to be sent to OCTEON TX2. This is stored in the
	 *  instr to retrieve the physical address of buffers when instr is
	 *  freed.
	 */
	struct otx2_ep_instr_64B command;

	/** If a gather list was allocated, this ptr points to the buffer used
	 *  for the gather list. The gather list has to be 8B aligned, so this
	 *  value may be different from dptr.
	 */
	void *gather_ptr;

	/* Total data bytes transferred in the gather mode request. */
	uint64_t gather_bytes;

	/** If a scatter list was allocated, this ptr points to the buffer used
	 *  for the scatter list. The scatter list has to be 8B aligned, so
	 *  this value may be different from rptr.
	 */
	void *scatter_ptr;

	/* Total data bytes to be received in the scatter mode request. */
	uint64_t scatter_bytes;

	/* IQ number to which this instruction has to be submitted. */
	uint32_t q_no;

	/* IQ instruction request type. */
	uint32_t reqtype;
};

union out_int_lvl_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timet:22;
		uint64_t max_len:7;
		uint64_t max_len_en:1;
		uint64_t time_cnt_en:1;
		uint64_t bmode:1;
	} s;
};

union out_cnts_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timer:22;
		uint64_t rsvd:5;
		uint64_t resend:1;
		uint64_t mbox_int:1;
		uint64_t in_int:1;
		uint64_t out_int:1;
		uint64_t send_ism:1;
	} s;
};

#define OTX2_EP_64B_INSTR_SIZE	(sizeof(otx2_ep_instr_64B))

#define OTX2_EP_SOFT_INSTR_SIZE	(sizeof(otx2_ep_soft_instr))

//#define NIX_L2_OVERHEAD (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)
#define NIX_L2_OVERHEAD (RTE_ETHER_HDR_LEN)
#define OTX2_EP_MTU2PKT_SIZE(mtu)  (NIX_L2_OVERHEAD + (mtu))
#define OTX2_EP_PKT2MTU_SIZE(pkt)  ((pkt) - NIX_L2_OVERHEAD)

#define NIX_MIN_HW_FRS			60
#define NIX_MIN_FRS	 NIX_MIN_HW_FRS


#define NIX_MAX_HW_FRS		(OTX_EP_MAX_PKT_SZ + 4) 

#define NIX_MAX_VTAG_INS		2
#define NIX_MAX_VTAG_ACT_SIZE		(4 * NIX_MAX_VTAG_INS)
#define NIX_MAX_FRS	  (OTX_EP_MAX_PKT_SZ - 4)

#define CN93XX_INTR_R_OUT_INT        (1ULL << 62)
#define CN93XX_INTR_R_IN_INT         (1ULL << 61)
#endif /*_OTX2_EP_VF_H_ */

