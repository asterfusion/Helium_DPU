/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _HW_CPT_H_
#define _HW_CPT_H_

#include <stdint.h>

#define ROC_ALIGN	128

/* Completion codes */
#define CPT_COMP_NOT_DONE (0x0ull)
#define CPT_COMP_GOOD	  (0x1ull)
#define CPT_COMP_FAULT	  (0x2ull)
#define CPT_COMP_SWERR	  (0x3ull)
#define CPT_COMP_HWERR	  (0x4ull)
#define CPT_COMP_INSTERR  (0x5ull)
#define CPT_COMP_WARN	  (0x6ull) /* [CN10K, .) */

/* Default engine groups */
#define ROC_CPT_DFLT_ENG_GRP_SE	   0UL
#define ROC_CPT_DFLT_ENG_GRP_SE_IE 1UL
#define ROC_CPT_DFLT_ENG_GRP_AE	   2UL

union cpt_inst_w4 {
	uint64_t u64;
	struct {
		uint64_t dlen : 16;
		uint64_t param2 : 16;
		uint64_t param1 : 16;
		uint64_t opcode_major : 8;
		uint64_t opcode_minor : 8;
	} s;
};

union cpt_inst_w5 {
	uint64_t u64;
	struct {
		uint64_t dptr : 60;
		uint64_t gather_sz : 4;
	} s;
};

union cpt_inst_w6 {
	uint64_t u64;
	struct {
		uint64_t rptr : 60;
		uint64_t scatter_sz : 4;
	} s;
};

union cpt_inst_w7 {
	uint64_t u64;
	struct {
		uint64_t cptr : 60;
		uint64_t ctx_val : 1;
		uint64_t egrp : 3;
	} s;
};

struct cpt_inst_s {
	union cpt_inst_w0 {
		struct {
			uint64_t nixtxl : 3;
			uint64_t doneint : 1;
			uint64_t nixtx_addr : 60;
		} s;
		uint64_t u64;
	} w0;

	uint64_t res_addr;

	union cpt_inst_w2 {
		struct {
			uint64_t tag : 32;
			uint64_t tt : 2;
			uint64_t grp : 10;
			uint64_t reserved_172_175 : 4;
			uint64_t rvu_pf_func : 16;
		} s;
		uint64_t u64;
	} w2;

	union cpt_inst_w3 {
		struct {
			uint64_t qord : 1;
			uint64_t reserved_194_193 : 2;
			uint64_t wqe_ptr : 61;
		} s;
		uint64_t u64;
	} w3;

	union cpt_inst_w4 w4;

	union {
		union cpt_inst_w5 w5;
		uint64_t dptr;
	};

	union {
		union cpt_inst_w6 w6;
		uint64_t rptr;
	};

	union cpt_inst_w7 w7;
};

union cpt_res_s {
	struct cpt_cn10k_res_s {
		uint64_t compcode : 7;
		uint64_t doneint : 1;
		uint64_t uc_compcode : 8;
		uint64_t rlen : 16;
		uint64_t spi : 32;

		uint64_t esn;
	} cn10k;

	struct cpt_cn9k_res_s {
		uint64_t compcode : 8;
		uint64_t uc_compcode : 8;
		uint64_t doneint : 1;
		uint64_t reserved_17_63 : 47;

		uint64_t reserved_64_127;
	} cn9k;

	uint64_t u64[2];
};


#endif /* _HW_CPT_H_ */
