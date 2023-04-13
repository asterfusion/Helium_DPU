/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */
#ifndef _OTX_EP_VF_H_
#define _OTX_EP_VF_H_





#define OTX_EP_RING_OFFSET                (0x1ull << 17)

/* OTX_EP VF IQ Registers */
#define OTX_EP_R_IN_CONTROL_START         (0x10000)
#define OTX_EP_R_IN_ENABLE_START          (0x10010)
#define OTX_EP_R_IN_INSTR_BADDR_START     (0x10020)
#define OTX_EP_R_IN_INSTR_RSIZE_START     (0x10030)
#define OTX_EP_R_IN_INSTR_DBELL_START     (0x10040)
#define OTX_EP_R_IN_CNTS_START            (0x10050)
#define OTX_EP_R_IN_INT_LEVELS_START      (0x10060)
#define OTX_EP_R_IN_INT_STATUS_START      (0x10070)
#define OTX_EP_R_IN_PKT_CNT_START         (0x10080)
#define OTX_EP_R_IN_BYTE_CNT_START        (0x10090)

#define OTX_EP_R_IN_CONTROL(ring)  \
	(OTX_EP_R_IN_CONTROL_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_ENABLE(ring)   \
	(OTX_EP_R_IN_ENABLE_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_INSTR_BADDR(ring)   \
	(OTX_EP_R_IN_INSTR_BADDR_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_INSTR_RSIZE(ring)   \
	(OTX_EP_R_IN_INSTR_RSIZE_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_INSTR_DBELL(ring)   \
	(OTX_EP_R_IN_INSTR_DBELL_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_CNTS(ring)          \
	(OTX_EP_R_IN_CNTS_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_INT_LEVELS(ring)    \
	(OTX_EP_R_IN_INT_LEVELS_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_PKT_CNT(ring)       \
	(OTX_EP_R_IN_PKT_CNT_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_IN_BYTE_CNT(ring)          \
	(OTX_EP_R_IN_BYTE_CNT_START + ((ring) * OTX_EP_RING_OFFSET))

/* OTX_EP VF IQ Masks */
#define OTX_EP_R_IN_CTL_RPVF_MASK       (0xF)
#define	OTX_EP_R_IN_CTL_RPVF_POS        (48)

#define OTX_EP_R_IN_CTL_IDLE            (0x1ull << 28)
#define OTX_EP_R_IN_CTL_RDSIZE          (0x3ull << 25) /* Setting to max(4) */
#define OTX_EP_R_IN_CTL_IS_64B          (0x1ull << 24)
#define OTX_EP_R_IN_CTL_D_NSR           (0x1ull << 8)
#define OTX_EP_R_IN_CTL_D_ESR           (0x1ull << 6)
#define OTX_EP_R_IN_CTL_D_ROR           (0x1ull << 5)
#define OTX_EP_R_IN_CTL_NSR             (0x1ull << 3)
#define OTX_EP_R_IN_CTL_ESR             (0x1ull << 1)
#define OTX_EP_R_IN_CTL_ROR             (0x1ull << 0)

#define OTX_EP_R_IN_CTL_MASK  \
	(OTX_EP_R_IN_CTL_RDSIZE | OTX_EP_R_IN_CTL_IS_64B)

/* OTX_EP VF OQ Registers */
#define OTX_EP_R_OUT_CNTS_START              (0x10100)
#define OTX_EP_R_OUT_INT_LEVELS_START        (0x10110)
#define OTX_EP_R_OUT_SLIST_BADDR_START       (0x10120)
#define OTX_EP_R_OUT_SLIST_RSIZE_START       (0x10130)
#define OTX_EP_R_OUT_SLIST_DBELL_START       (0x10140)
#define OTX_EP_R_OUT_CONTROL_START           (0x10150)
#define OTX_EP_R_OUT_ENABLE_START            (0x10160)
#define OTX_EP_R_OUT_INT_STATUS_START        (0x10170)
#define OTX_EP_R_OUT_PKT_CNT_START           (0x10180)
#define OTX_EP_R_OUT_BYTE_CNT_START          (0x10190)

#define OTX_EP_R_OUT_CONTROL(ring)    \
	(OTX_EP_R_OUT_CONTROL_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_ENABLE(ring)     \
	(OTX_EP_R_OUT_ENABLE_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_SLIST_BADDR(ring)  \
	(OTX_EP_R_OUT_SLIST_BADDR_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_SLIST_RSIZE(ring)  \
	(OTX_EP_R_OUT_SLIST_RSIZE_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_SLIST_DBELL(ring)  \
	(OTX_EP_R_OUT_SLIST_DBELL_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_CNTS(ring)   \
	(OTX_EP_R_OUT_CNTS_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_INT_LEVELS(ring)   \
	(OTX_EP_R_OUT_INT_LEVELS_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_PKT_CNT(ring)   \
	(OTX_EP_R_OUT_PKT_CNT_START + ((ring) * OTX_EP_RING_OFFSET))

#define OTX_EP_R_OUT_BYTE_CNT(ring)   \
	(OTX_EP_R_OUT_BYTE_CNT_START + ((ring) * OTX_EP_RING_OFFSET))

/* OTX_EP VF OQ Masks */

#define OTX_EP_R_OUT_CTL_IDLE         (1ull << 36)
#define OTX_EP_R_OUT_CTL_ES_I         (1ull << 34)
#define OTX_EP_R_OUT_CTL_NSR_I        (1ull << 33)
#define OTX_EP_R_OUT_CTL_ROR_I        (1ull << 32)
#define OTX_EP_R_OUT_CTL_ES_D         (1ull << 30)
#define OTX_EP_R_OUT_CTL_NSR_D        (1ull << 29)
#define OTX_EP_R_OUT_CTL_ROR_D        (1ull << 28)
#define OTX_EP_R_OUT_CTL_ES_P         (1ull << 26)
#define OTX_EP_R_OUT_CTL_NSR_P        (1ull << 25)
#define OTX_EP_R_OUT_CTL_ROR_P        (1ull << 24)
#define OTX_EP_R_OUT_CTL_IMODE        (1ull << 23)

#define OTX_EP_R_OUT_INT_LEVELS_BMODE     (1ull << 63)
#define OTX_EP_R_OUT_INT_LEVELS_TIMET     (32)

#define PCI_DEVID_OCTEONTX_EP_VF 0xa303

/* this is a static value set by SLI PF driver in octeon 
 * No handshake is available
 * Change this if changing the value in SLI PF driver
 */
#define SDP_GBL_WMARK 0x100


/* Optional PKI Instruction Header(PKI IH) */
typedef union {

	uint64_t u64;
	struct {
		/** Tag Value */
		uint64_t tag:32;

		/** QPG Value */
		uint64_t qpg:11;

		/** Reserved1 */
		uint64_t reserved1:2;

		/** Tag type */
		uint64_t tagtype:2;

		/** Use Tag Type */
		uint64_t utt:1;

		/** Skip Length */
		uint64_t sl:8;

		/** Parse Mode */
		uint64_t pm:3;

		/** Reserved2 */
		uint64_t reserved2:1;

		/** Use QPG */
		uint64_t uqpg:1;

		/** Use Tag */
		uint64_t utag:1;

		/** Raw mode indicator 1 = RAW */
		uint64_t raw:1;

		/** Wider bit */
		uint64_t w:1;
	} s;
} otx_ep_instr_pki_ih3_t;


/* OTX_EP 64B instruction format */
struct otx_ep_instr_64B {
	/* Pointer where the input data is available. */
	uint64_t dptr;

	/* OTX_EP Instruction Header. */
	union otx_ep_instr_ih ih;

	/* PKI Optional Instruction Header. */
	otx_ep_instr_pki_ih3_t pki_ih3;

	/** Pointer where the response for a RAW mode packet
	 * will be written by OCTEON TX.
	 */
	uint64_t rptr;

	/* Input Request Header. */
	union otx_ep_instr_irh irh;

	/* Additional headers available in a 64-byte instruction. */
	uint64_t exhdr[3];
};
#define OTX_EP_64B_INSTR_SIZE	(sizeof(otx_ep_instr_64B))

struct otx_ep_soft_instr {
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

	otx_ep_instr_pki_ih3_t  pki_ih3;

	/* Input request header. */
	union otx_ep_instr_irh irh;

	/** The PCI instruction to be sent to OCTEON TX2. This is stored in the
	 *  instr to retrieve the physical address of buffers when instr is
	 *  freed.
	 */
	struct otx_ep_instr_64B command;

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

#define OTX_EP_SOFT_INSTR_SIZE	(sizeof(otx_ep_soft_instr))
int
otx_ep_vf_setup_device(struct otx_ep_device *otx_ep);

union otx_out_int_lvl_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timet:22;
		uint64_t raz:9;
		uint64_t bmode:1;
	} s;
};

union otx_out_cnts_t {
	uint64_t d64;
	struct {
		uint64_t cnt:32;
		uint64_t timer:22;
		uint64_t rsvd0:5;
		uint64_t resend:1;
		uint64_t mbox_int:1;
		uint64_t in_int:1;
		uint64_t out_int:1;
		uint64_t rsvd1:1;
	} s;
};

#endif /*_OTX_EP_VF_H_ */
