/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#ifndef _TEST_CASES_
#define _TEST_CASES_

#include <stdint.h>

#include "ucode/se.h"

struct test_case_params {
	uint8_t opcode_major;
	uint8_t opcode_minor;
	uint16_t dlen;
	void *dptr;
	void *rptr;
	void *cptr;
	uint8_t ctx_val;
};

struct test_case_params test_cases[] = {
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 0,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 32,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 64,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 512,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 1024,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 2048,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 8192,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_MISC,
		.opcode_minor = ROC_SE_MISC_MINOR_OP_PASSTHROUGH,
		.dlen = 0,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 64,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 128,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 256,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 512,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1024,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1344,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 2048,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 8192,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 64,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 128,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 256,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 512,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1024,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 1536,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 2048,
		.ctx_val = 1,
	},
	{
		.opcode_major = ROC_SE_MAJOR_OP_FC,
		.opcode_minor = 0,
		.dlen = 8192,
		.ctx_val = 1,
	},
};

#endif /* _TEST_CASES_ */
