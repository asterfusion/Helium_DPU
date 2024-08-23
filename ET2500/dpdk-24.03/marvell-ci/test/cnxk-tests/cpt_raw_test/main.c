/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell.
 */

#include <stdlib.h>

#include <rte_common.h>
#include <rte_cryptodev.h>
#include <rte_eal.h>
#include <rte_malloc.h>

#include <rte_pmd_cnxk_crypto.h>

#include "hw/cpt.h"
#include "test_cases.h"
#include "ucode/se.h"

#define TEST_SUCCESS EXIT_SUCCESS
#define TEST_FAILED  -1
#define TEST_SKIPPED  77

#define NB_DESC		20000
#define NB_CPTR		1
#define MAX_CPTR_LEN	8192
#define MAX_DLEN	16384
#define CPT_RES_ALIGN	sizeof(union cpt_res_s)

struct lcore_conf {
	uint8_t dev_id;
	uint8_t qp_id;
	struct test_ctx *ctx;
};

enum cdev_type {
	CDEV_TYPE_CRYPTO_CN9K = 1,
	CDEV_TYPE_CRYPTO_CN10K,
};

#define CPT_CTX_CACHE_SIZE 256

struct ctx_cache_mirror {
	void *cptrs[CPT_CTX_CACHE_SIZE];
	uint16_t head;
	uint16_t tail;
};

struct test_ctx {
	struct lcore_conf lconf[RTE_MAX_LCORE];
	struct rte_mempool *cptr_mp;
	struct rte_mempool *dptr_mp;
	struct rte_mempool *rptr_mp;
	uint8_t nb_cryptodevs;
	uint8_t enabled_cdevs[RTE_CRYPTO_MAX_DEVS];
	enum cdev_type cdev_type;
	struct ctx_cache_mirror ctx_cache;
};

static struct test_ctx ctx;

static const char *
uc_opcode_major_to_str(uint16_t major_opcode)
{
	switch (major_opcode) {
	case ROC_SE_MAJOR_OP_MISC:
		return "MISC";
	case ROC_SE_MAJOR_OP_FC:
		return "Flexi Crypto";
	default:
		return "Invalid";
	}
}

static int
cryptodev_init(struct test_ctx *ctx, uint8_t nb_lcores)
{
	struct rte_cryptodev_qp_conf qp_conf;
	struct rte_cryptodev_info dev_info;
	struct rte_cryptodev_config config;
	unsigned int j, nb_qp, qps_reqd;
	uint8_t socket_id;
	uint32_t dev_cnt;
	int ret, core_id;
	uint64_t i;

	dev_cnt = rte_cryptodev_devices_get("crypto_cn9k", ctx->enabled_cdevs, RTE_CRYPTO_MAX_DEVS);
	if (dev_cnt) {
		ctx->cdev_type = CDEV_TYPE_CRYPTO_CN9K;
		goto cdev_init;
	}

	dev_cnt = rte_cryptodev_devices_get("crypto_cn10k", ctx->enabled_cdevs,
					    RTE_CRYPTO_MAX_DEVS);
	if (dev_cnt) {
		ctx->cdev_type = CDEV_TYPE_CRYPTO_CN10K;
		goto cdev_init;
	}

	if (dev_cnt == 0)
		return -1;

cdev_init:
	socket_id = rte_socket_id();
	qps_reqd = nb_lcores;
	core_id = 0;
	i = 0;

	do {
		rte_cryptodev_info_get(i, &dev_info);
		qps_reqd = RTE_MIN(dev_info.max_nb_queue_pairs, qps_reqd);

		for (j = 0; j < qps_reqd; j++) {
			ctx->lconf[core_id].dev_id = i;
			ctx->lconf[core_id].qp_id = j;
			ctx->lconf[core_id].ctx = ctx;
			core_id++;
			if (core_id == RTE_MAX_LCORE)
				break;
		}

		nb_qp = j;

		memset(&config, 0, sizeof(config));
		config.nb_queue_pairs = nb_qp;
		config.socket_id = socket_id;

		ret = rte_cryptodev_configure(i, &config);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not configure cryptodev - %" PRIu64 "\n", i);
			return -1;
		}

		memset(&qp_conf, 0, sizeof(qp_conf));
		qp_conf.nb_descriptors = NB_DESC;

		for (j = 0; j < nb_qp; j++) {
			ret = rte_cryptodev_queue_pair_setup(i, j, &qp_conf,
							     socket_id);
			if (ret < 0) {
				RTE_LOG(ERR, USER1,
					"Could not configure queue pair: %" PRIu64 " - %d\n", i, j);
				return -1;
			}
		}

		ret = rte_cryptodev_start(i);
		if (ret < 0) {
			RTE_LOG(ERR, USER1, "Could not start cryptodev\n");
			return -1;
		}

		i++;
		qps_reqd -= j;

	} while (i < dev_cnt && core_id < RTE_MAX_LCORE);

	ctx->nb_cryptodevs = i;

	return 0;
}

static int
cryptodev_fini(struct test_ctx *ctx)
{
	int i, ret = 0;

	for (i = 0; i < ctx->nb_cryptodevs && i < RTE_CRYPTO_MAX_DEVS; i++) {
		rte_cryptodev_stop(ctx->enabled_cdevs[i]);
		ret = rte_cryptodev_close(ctx->enabled_cdevs[i]);
		if (ret)
			RTE_LOG(ERR, USER1, "Could not close device [err: %d]\n", ret);
	}

	return ret;
}

static int
mempool_init(struct test_ctx *ctx)
{
	struct rte_mempool *mp;
	unsigned int len;
	int nb_elt;

	/* Allocate CPTR mempool. */

	len = MAX_CPTR_LEN;

	/* Increment by 1 to make sure we can allocate all buffers. */
	nb_elt = RTE_MAX(NB_CPTR, CPT_CTX_CACHE_SIZE) + 1;

	mp = rte_mempool_create("test_cptr_mp", nb_elt, len, 0, 0, NULL,
				NULL, NULL, NULL, SOCKET_ID_ANY, 0);
	if (mp == NULL) {
		RTE_LOG(ERR, USER1, "Could not create CPTR mempool\n");
		return -1;
	}

	ctx->cptr_mp = mp;

	/* Allocate data pointer mempool. */

	/* CPT_RES_S would be placed at the beginning of data pointer. */
	len = sizeof(union cpt_res_s) + MAX_DLEN;

	nb_elt = NB_DESC;

	mp = rte_mempool_create("test_dptr_mp", nb_elt, len, RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL,
				NULL, NULL, NULL, SOCKET_ID_ANY, 0);
	if (mp == NULL) {
		RTE_LOG(ERR, USER1, "Could not create DPTR mempool\n");
		goto cptr_mp_free;
	}

	ctx->dptr_mp = mp;

	mp = rte_mempool_create("test_rptr_mp", nb_elt, len, RTE_MEMPOOL_CACHE_MAX_SIZE, 0, NULL,
				NULL, NULL, NULL, SOCKET_ID_ANY, 0);
	if (mp == NULL) {
		RTE_LOG(ERR, USER1, "Could not create RPTR mempool\n");
		goto dptr_mp_free;
	}

	ctx->rptr_mp = mp;

	return 0;

dptr_mp_free:
	rte_mempool_free(ctx->dptr_mp);
cptr_mp_free:
	rte_mempool_free(ctx->cptr_mp);
	return -1;
}

static int
mempool_fini(struct test_ctx *ctx)
{
	rte_mempool_free(ctx->rptr_mp);
	rte_mempool_free(ctx->dptr_mp);
	rte_mempool_free(ctx->cptr_mp);

	return 0;
}

static void
cptr_fc_init(struct se_ctx_s *ctx)
{
	struct roc_se_context *fctx = &ctx->fctx;

	fctx->enc.iv_source = 0;
	fctx->enc.aes_key = 1;
	fctx->enc.rsvd_59 = 0;
	fctx->enc.enc_cipher = 2;
	fctx->enc.auth_input_type = 0;
	fctx->enc.auth_key_src = 0;
	fctx->enc.rsvd_50_51 = 0;
	fctx->enc.hash_type = 0;
	fctx->enc.mac_len = 0;
	fctx->enc.rsvd_16_39 = 0;
	fctx->enc.hmac_key_sz = 0;
}

static void
cptr_ctx_init(struct test_case_params *tc_params)
{
	uint8_t opcode_major = tc_params->opcode_major;
	struct se_ctx_s *ctx = tc_params->cptr;
	uint64_t ctx_len, *uc_ctx;
	uint8_t i;

	switch (opcode_major) {
	case ROC_SE_MAJOR_OP_MISC:
		ctx_len = 0;
		break;
	case ROC_SE_MAJOR_OP_FC:
		ctx_len = sizeof(struct roc_se_context);
		cptr_fc_init(ctx);
		break;
	default:
		rte_panic("Invalid opcode for CTX\n");
	}

	if (!tc_params->ctx_val)
		return;

	/* Populate CTX region & swap CPTR data. */

	ctx_len = RTE_ALIGN_CEIL(ctx_len, 8);

	/* Skip w0 for swap */
	uc_ctx = RTE_PTR_ADD(ctx, sizeof(ctx->w0));
	for (i = 0; i < (ctx_len / 8); i++)
		uc_ctx[i] = rte_cpu_to_be_64(((uint64_t *)uc_ctx)[i]);

	/* Include w0 */
	ctx_len += sizeof(ctx->w0);
	ctx_len = RTE_ALIGN_CEIL(ctx_len, 8);

	ctx->w0.s.aop_valid = 1;
	ctx->w0.s.ctx_hdr_size = 0;

	ctx->w0.s.ctx_size = RTE_ALIGN_FLOOR(ctx_len, 128);
	if (ctx->w0.s.ctx_size == 0)
		ctx->w0.s.ctx_size = 1;

	ctx->w0.s.ctx_push_size = ctx_len / 8;
	if (ctx->w0.s.ctx_push_size > 32)
		ctx->w0.s.ctx_push_size = 32;
}

static void
fc_inst_populate(struct cpt_inst_s *inst, struct test_case_params *tc_params)
{
	uint64_t *dptr = tc_params->dptr;
	uint32_t encr_offset;
	uint64_t offset_ctrl;

	if (!tc_params->dlen)
		rte_panic("DLEN = 0 not supported with FC\n");

	/* Encr range is after IV. */
	encr_offset = 16;

	inst->w4.s.dlen = tc_params->dlen + encr_offset;
	inst->w4.s.param1 = tc_params->dlen;
	inst->w4.s.param2 = 0;

	offset_ctrl = rte_cpu_to_be_64((uint64_t)encr_offset << 16);

	dptr[0] = offset_ctrl;

	inst->dptr = (uint64_t)dptr;
}

static void
pt_inst_populate(struct cpt_inst_s *inst, struct test_case_params *tc_params)
{
	if (tc_params->dlen) {
		inst->w4.s.param1 = tc_params->dlen;
		inst->w4.s.dlen = tc_params->dlen;
		inst->w4.s.param2 = 0;
		inst->dptr = (uint64_t)tc_params->dptr;
		inst->rptr = (uint64_t)tc_params->rptr;
	} else {
		inst->w4.s.param1 = 1;
		inst->w4.s.param2 = 1;
		inst->w4.s.dlen = 0;
	}
}

static void
inst_populate(struct cpt_inst_s *inst, struct test_case_params *tc_params)
{
	if (tc_params->ctx_val == 1) {
		inst->w7.s.ctx_val = 1;
		inst->w7.s.cptr = (uint64_t)tc_params->cptr;
	} else {
		inst->w7.s.cptr = (uint64_t)RTE_PTR_ADD(tc_params->cptr, 8);
	}

	/* Set in-place bit in major opcode. */
	inst->w4.s.opcode_major = 1 << 6 | tc_params->opcode_major;
	inst->w4.s.opcode_minor = tc_params->opcode_minor;

	switch (tc_params->opcode_major) {
	case ROC_SE_MAJOR_OP_MISC:
		inst->w7.s.egrp = ROC_CPT_DFLT_ENG_GRP_SE;
		pt_inst_populate(inst, tc_params);
		break;
	case ROC_SE_MAJOR_OP_FC:
		inst->w7.s.egrp = ROC_CPT_DFLT_ENG_GRP_SE_IE;
		fc_inst_populate(inst, tc_params);
		break;
	default:
		rte_panic("Invalid opcode\n");
	};
}

static int
cptr_get(struct test_ctx *ctx, void *cptrs[], int nb_cptr)
{
	uint16_t ctx_in_use, head, tail;
	int ret, avail_count, i;

	head = ctx->ctx_cache.head;
	tail = ctx->ctx_cache.tail;

	ctx_in_use = (CPT_CTX_CACHE_SIZE + head - ctx->ctx_cache.tail) &
		     (CPT_CTX_CACHE_SIZE - 1);

	/* Decrement avail_count by 1 since allocation fails when avail_count is 1*/
	avail_count = rte_mempool_avail_count(ctx->cptr_mp) - 1;

	if (avail_count + ctx_in_use < nb_cptr) {
		printf("Invalid number of CPTRs requested.\n");
		return -ENOENT;
	}

	if (avail_count >= nb_cptr) {
		ret = rte_mempool_get_bulk(ctx->cptr_mp, cptrs, nb_cptr);
		if (ret) {
			printf("Could not allocate context buffers from the pool\n");
			return ret;
		}
	} else {
		if (avail_count > 0) {
			ret = rte_mempool_get_bulk(ctx->cptr_mp, cptrs, avail_count);
			if (ret) {
				printf("Could not allocate context buffers from available pool\n");
				return ret;
			}
		}

		for (i = 0; i < nb_cptr - avail_count; i++) {
			rte_mempool_put(ctx->cptr_mp, ctx->ctx_cache.cptrs[tail]);
			tail = (tail + 1) & (CPT_CTX_CACHE_SIZE - 1);
		}

		ret = rte_mempool_get_bulk(ctx->cptr_mp,
					   RTE_PTR_ADD(cptrs, sizeof(void *) * avail_count),
					   nb_cptr - avail_count);
		if (ret) {
			printf("Could not allocate context buffers after freeing cache buffers\n");
			rte_mempool_put_bulk(ctx->cptr_mp, cptrs, avail_count);
			return ret;
		}
	}

	ctx->ctx_cache.head = head;
	ctx->ctx_cache.tail = tail;

	return 0;
}

static void
cptr_put(struct test_ctx *ctx, void **cptrs, int nb_cptr)
{
	uint16_t free_slot, ctx_in_use, head, tail, i, nb_release;

	head = ctx->ctx_cache.head;
	tail = ctx->ctx_cache.tail;

	ctx_in_use = (CPT_CTX_CACHE_SIZE + head - tail) & (CPT_CTX_CACHE_SIZE - 1);
	free_slot = CPT_CTX_CACHE_SIZE - ctx_in_use;

	if (free_slot > nb_cptr) {
		for (i = 0; i < nb_cptr; i++) {
			ctx->ctx_cache.cptrs[head] = cptrs[i];
			head = (head + 1) & (CPT_CTX_CACHE_SIZE - 1);
		}
	} else {
		if ((ctx_in_use + nb_cptr) > CPT_CTX_CACHE_SIZE)
			nb_release = ctx_in_use + nb_cptr - CPT_CTX_CACHE_SIZE;
		else
			nb_release = 0;

		/* Release the ones in CTX cache to mempool. */
		for (i = 0; i < RTE_MIN(nb_release, ctx_in_use); i++) {
			rte_mempool_put(ctx->cptr_mp, ctx->ctx_cache.cptrs[tail]);
			tail = (tail + 1) & (CPT_CTX_CACHE_SIZE - 1);
		}

		ctx_in_use -= i;
		nb_release -= i;

		/* Release the exceeding ones to mempool directly. */
		if (nb_release)
			rte_mempool_put_bulk(ctx->cptr_mp, cptrs, nb_release);

		/* Keep the remaining ones in the CTX cache. */
		for (i = 0; i < RTE_MIN(nb_release, ctx_in_use); i++) {
			ctx->ctx_cache.cptrs[head] = cptrs[nb_release + i];
			head = (head + 1) & (CPT_CTX_CACHE_SIZE - 1);
		}
	}

	ctx->ctx_cache.head = head;
	ctx->ctx_cache.tail = tail;
}

static void
cptr_flush(struct test_ctx *ctx)
{
	uint16_t ctx_in_use, head, tail, i;

	head = ctx->ctx_cache.head;
	tail = ctx->ctx_cache.tail;

	ctx_in_use = (CPT_CTX_CACHE_SIZE + head - tail) & (CPT_CTX_CACHE_SIZE - 1);

	/* Release the ones in CTX cache to mempool. */
	for (i = 0; i < ctx_in_use; i++) {
		rte_mempool_put(ctx->cptr_mp, ctx->ctx_cache.cptrs[tail]);
		tail = (tail + 1) & (CPT_CTX_CACHE_SIZE - 1);
	}

	ctx->ctx_cache.head = head;
	ctx->ctx_cache.tail = tail;
}

static int
test_cpt_raw_api(struct test_ctx *ctx, struct test_case_params *tc_params, int nb_dptrs)
{
	void *data_ptrs[NB_DESC], *rptrs[NB_DESC], *cptrs[NB_CPTR];
	uint64_t timeout, tsc_start, tsc_end, tsc_cycles;
	double test_us, throughput_gbps, ops_per_second;
	struct cpt_inst_s *inst_mem, *inst;
	int ret, i, status = TEST_SUCCESS;
	union cpt_res_s res, *hw_res;
	void *qptr, *dptr;

	const union cpt_res_s res_init = {
		.cn10k.compcode = CPT_COMP_NOT_DONE,
	};

	if (tc_params->dlen > MAX_DLEN) {
		printf("Invalid dlen requested. Max: %d, requested:%d\n", MAX_DLEN,
		       tc_params->dlen);
		return TEST_FAILED;
	}

	if (tc_params->ctx_val && ctx->cdev_type != CDEV_TYPE_CRYPTO_CN10K)
		return TEST_SKIPPED;


	qptr = rte_pmd_cnxk_crypto_qptr_get(0, 0);
	if (qptr == NULL) {
		printf("Could not get QPTR\n");
		return TEST_FAILED;
	}

	inst_mem = rte_malloc(NULL, NB_DESC * sizeof(struct cpt_inst_s), 0);
	if (inst_mem == NULL) {
		printf("Could not allocate instruction memory\n");
		return TEST_FAILED;
	}

	ret = rte_mempool_get_bulk(ctx->dptr_mp, data_ptrs, nb_dptrs);
	if (ret) {
		printf("Could not allocate data buffers\n");
		status = TEST_FAILED;
		goto inst_mem_free;
	}

	ret = rte_mempool_get_bulk(ctx->rptr_mp, rptrs, nb_dptrs);
	if (ret) {
		printf("Could not allocate result buffers\n");
		status = TEST_FAILED;
		goto dptrs_free;
	}

	ret = cptr_get(ctx, cptrs, NB_CPTR);
	if (ret) {
		printf("Could not allocate context buffers\n");
		status = TEST_FAILED;
		goto rptrs_free;
	}

	for (i = 0; i < nb_dptrs; i++) {
		inst = RTE_PTR_ADD(inst_mem, i * sizeof(struct cpt_inst_s));
		hw_res = RTE_PTR_ALIGN_CEIL(data_ptrs[i], CPT_RES_ALIGN);

		memset(inst, 0, sizeof(struct cpt_inst_s));

		inst->w3.s.qord = 1;

		dptr = RTE_PTR_ADD(hw_res, sizeof(union cpt_res_s));
		tc_params->dptr = dptr;
		tc_params->rptr = rptrs[i];
		tc_params->cptr = RTE_PTR_ALIGN_CEIL(cptrs[0], ROC_ALIGN);

		cptr_ctx_init(tc_params);

		inst_populate(inst, tc_params);

		inst->res_addr = (uint64_t)hw_res;
		__atomic_store_n(&hw_res->u64[0], res_init.u64[0], __ATOMIC_RELAXED);
	}

	inst = inst_mem;

	timeout = rte_rdtsc() + rte_get_tsc_hz() * 60;

	tsc_start = rte_rdtsc_precise();
	rte_pmd_cnxk_crypto_submit(qptr, inst, nb_dptrs);

	do {
		hw_res = data_ptrs[nb_dptrs - 1];
		res.u64[0] = __atomic_load_n(&hw_res->u64[0], __ATOMIC_RELAXED);
	} while ((res.cn10k.compcode == CPT_COMP_NOT_DONE) && (rte_rdtsc() < timeout));

	tsc_end = rte_rdtsc_precise();

	tsc_cycles = tsc_end - tsc_start;
	test_us = (double)tsc_cycles * 1000 * 1000 / rte_get_tsc_hz();

	/* Calculate average operations processed per second */
	ops_per_second = ((double)nb_dptrs / tsc_cycles) * rte_get_tsc_hz();

	/* Calculate average throughput (Gbps) in bits per second */
	throughput_gbps = ((ops_per_second * tc_params->dlen * 8) / 1000000000);

	printf("%18s%#18x%18u%18u%18u%18"PRIu64"%18.2f%18.2f%18.2f\n",
			uc_opcode_major_to_str(tc_params->opcode_major),
			tc_params->opcode_minor,
			tc_params->ctx_val,
			tc_params->dlen,
			nb_dptrs,
			tsc_cycles,
			test_us,
			ops_per_second / (1000 * 1000),
			throughput_gbps);

	if (res.cn10k.compcode != CPT_COMP_GOOD && res.cn10k.compcode != CPT_COMP_WARN) {
		printf("Completion code: 0x%x\n", res.cn10k.compcode);
		status = TEST_FAILED;
	}

	if (res.cn10k.uc_compcode != 0) {
		printf("Microcode completion code: 0x%x\n", res.cn10k.uc_compcode);
		status = TEST_FAILED;
	}

	cptr_put(ctx, cptrs, NB_CPTR);

rptrs_free:
	rte_mempool_put_bulk(ctx->rptr_mp, rptrs, nb_dptrs);

dptrs_free:
	rte_mempool_put_bulk(ctx->dptr_mp, data_ptrs, nb_dptrs);

inst_mem_free:
	rte_free(inst_mem);

	return status;
}

int main(int argc, char **argv)
{
	int i, ret, nb_cases, nb_skipped = 0;
	uint8_t nb_lcores;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");

	argc -= ret;
	argv += ret;

	nb_lcores = rte_lcore_count() - 1;
	if (nb_lcores < 1) {
		RTE_LOG(ERR, USER1,
			"Number of worker cores need to be higher than 1\n");
		return -EINVAL;
	}

	ret = cryptodev_init(&ctx, nb_lcores);
	if (ret)
		goto exit;

	ret = mempool_init(&ctx);
	if (ret)
		goto cryptodev_fini;

	nb_cases = RTE_DIM(test_cases);

	printf("\nTest Params\n");
	printf("-----------\n");
	printf("Number of operations: %d\n", NB_DESC);
	printf("Number of CPTRs     : %d\n", NB_CPTR);

	printf("\n%18s%18s%18s%18s%18s%18s%18s%18s%18s\n", "Opcode major", "Opcode minor",
	       "CTX val", "Data Len", "nb_dptrs", "Cycles", "Total Time(us)", "Mops",
	       "Throughput(Gbps)");

	for (i = 0; i < nb_cases; i++) {
		ret = test_cpt_raw_api(&ctx, &test_cases[i], NB_DESC);
		if (ret == TEST_FAILED)
			break;
		else if (ret == TEST_SKIPPED)
			nb_skipped++;
	}

	printf("\nTest Summary\n");
	printf("------------\n");
	printf("Total number of cases   : %d\n", nb_cases);
	printf("Number of cases run     : %d\n", i);
	printf("Number of cases skipped : %d\n", nb_skipped);
	if (ret == TEST_FAILED)
		printf("Overall status		: [FAIL]\n");
	else
		printf("Overall status		: [SUCCESS]\n");

	cptr_flush(&ctx);
	cryptodev_fini(&ctx);
	mempool_fini(&ctx);

	return ret;
cryptodev_fini:
	cryptodev_fini(&ctx);
exit:
	return EXIT_FAILURE;
}
