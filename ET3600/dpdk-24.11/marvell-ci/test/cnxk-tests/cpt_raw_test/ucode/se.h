/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _SE_H_
#define _SE_H_

struct roc_se_enc_context {
	uint64_t iv_source : 1;
	uint64_t aes_key : 2;
	uint64_t rsvd_59 : 1;
	uint64_t enc_cipher : 4;
	uint64_t auth_input_type : 1;
	uint64_t auth_key_src : 1;
	uint64_t rsvd_50_51 : 2;
	uint64_t hash_type : 4;
	uint64_t mac_len : 8;
	uint64_t rsvd_16_39 : 24;
	uint64_t hmac_key_sz : 16;
	uint8_t encr_key[32];
	uint8_t encr_iv[16];
};

struct roc_se_hmac_context {
	uint8_t ipad[64];
	uint8_t opad[64];
};

struct roc_se_context {
	struct roc_se_enc_context enc;
	struct roc_se_hmac_context hmac;
};

struct __rte_aligned(128) se_ctx_s {
	/* Word0 */
	union {
		struct {
			uint64_t rsvd : 48;

			uint64_t ctx_push_size : 7;
			uint64_t rsvd1 : 1;

			uint64_t ctx_hdr_size : 2;
			uint64_t aop_valid : 1;
			uint64_t rsvd2 : 1;
			uint64_t ctx_size : 4;
		} s;
		uint64_t u64;
	} w0;
	union {
		struct roc_se_context fctx;
	};
};

/* SE opcodes */
#define ROC_SE_MAJOR_OP_FC	      0x33

#define ROC_SE_MAJOR_OP_MISC		 0x01ULL
#define ROC_SE_MISC_MINOR_OP_PASSTHROUGH 0x03ULL

#define ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC 0x28UL
#define ROC_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC  0x29UL

#endif /* _SE_H_ */
