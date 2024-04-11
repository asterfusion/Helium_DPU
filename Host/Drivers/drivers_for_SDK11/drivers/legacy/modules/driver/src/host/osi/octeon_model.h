/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _OCTEON_MODEL_H_
#define _OCTEON_MODEL_H_

#ifndef BIT_ULL
#define BIT_ULL(a) (1ULL << (a))
#endif /* BIT_ULL */

#define MAIN_ID_REG_ADDRESS  0x87a008000d00

#define OCTEON_SDP_16K_HW_FRS  16380UL
#define OCTEON_SDP_64K_HW_FRS  65531UL

struct octeon_model {
#define OCTEON_MODEL_CN96xx_A0    BIT_ULL(0)
#define OCTEON_MODEL_CN96xx_B0    BIT_ULL(1)
#define OCTEON_MODEL_CN96xx_C0    BIT_ULL(2)
#define OCTEON_MODEL_CNF95xx_A0   BIT_ULL(4)
#define OCTEON_MODEL_CNF95xx_B0   BIT_ULL(6)
#define OCTEON_MODEL_CNF95xxMM_A0 BIT_ULL(8)
#define OCTEON_MODEL_CNF95xxN_A0  BIT_ULL(12)
#define OCTEON_MODEL_CNF95xxO_A0  BIT_ULL(13)
#define OCTEON_MODEL_CNF95xxN_A1  BIT_ULL(14)
#define OCTEON_MODEL_CNF95xxN_B0  BIT_ULL(15)
#define OCTEON_MODEL_CN98xx_A0    BIT_ULL(16)
#define OCTEON_MODEL_CN98xx_A1    BIT_ULL(17)
#define OCTEON_MODEL_CN106xx_A0   BIT_ULL(20)
#define OCTEON_MODEL_CNF105xx_A0  BIT_ULL(21)
#define OCTEON_MODEL_CNF105xxN_A0 BIT_ULL(22)
#define OCTEON_MODEL_CN103xx_A0   BIT_ULL(23)
#define OCTEON_MODEL_CN106xx_A1   BIT_ULL(24)
#define OCTEON_MODEL_CNF105xx_A1  BIT_ULL(25)
/* Following flags describe platform code is running on */
#define OCTEON_ENV_HW   BIT_ULL(61)
#define OCTEON_ENV_EMUL BIT_ULL(62)
#define OCTEON_ENV_ASIM BIT_ULL(63)

	uint64_t flag;
#define OCTEON_MODEL_STR_LEN_MAX 128
	char name[OCTEON_MODEL_STR_LEN_MAX];
	char env[OCTEON_MODEL_STR_LEN_MAX];
};

extern struct octeon_model octeon_model;
#define OCTEON_MODEL_CN96xx_Ax (OCTEON_MODEL_CN96xx_A0 | OCTEON_MODEL_CN96xx_B0)
#define OCTEON_MODEL_CN98xx_Ax (OCTEON_MODEL_CN98xx_A0 | OCTEON_MODEL_CN98xx_A1)
#define OCTEON_MODEL_CN9K                                                         \
	(OCTEON_MODEL_CN96xx_Ax | OCTEON_MODEL_CN96xx_C0 | OCTEON_MODEL_CNF95xx_A0 |    \
	 OCTEON_MODEL_CNF95xx_B0 | OCTEON_MODEL_CNF95xxMM_A0 |                       \
	 OCTEON_MODEL_CNF95xxO_A0 | OCTEON_MODEL_CNF95xxN_A0 | OCTEON_MODEL_CN98xx_Ax | \
	 OCTEON_MODEL_CNF95xxN_A1 | OCTEON_MODEL_CNF95xxN_B0)
#define OCTEON_MODEL_CNF9K                                                        \
	(OCTEON_MODEL_CNF95xx_A0 | OCTEON_MODEL_CNF95xx_B0 |                         \
	 OCTEON_MODEL_CNF95xxMM_A0 | OCTEON_MODEL_CNF95xxO_A0 |                      \
	 OCTEON_MODEL_CNF95xxN_A0 | OCTEON_MODEL_CNF95xxN_A1 |                       \
	 OCTEON_MODEL_CNF95xxN_B0)

#define OCTEON_MODEL_CN106xx   (OCTEON_MODEL_CN106xx_A0 | OCTEON_MODEL_CN106xx_A1)
#define OCTEON_MODEL_CNF105xx  (OCTEON_MODEL_CNF105xx_A0 | OCTEON_MODEL_CNF105xx_A1)
#define OCTEON_MODEL_CNF105xxN (OCTEON_MODEL_CNF105xxN_A0)
#define OCTEON_MODEL_CN103xx   (OCTEON_MODEL_CN103xx_A0)
#define OCTEON_MODEL_CN10K                                                        \
	(OCTEON_MODEL_CN106xx | OCTEON_MODEL_CNF105xx | OCTEON_MODEL_CNF105xxN |        \
	 OCTEON_MODEL_CN103xx)
#define OCTEON_MODEL_CNF10K (OCTEON_MODEL_CNF105xx | OCTEON_MODEL_CNF105xxN)

/* Runtime variants */
static inline uint64_t
octeon_model_runtime_is_cn9k(void)
{
	return (octeon_model.flag & (OCTEON_MODEL_CN9K));
}

static inline uint64_t
octeon_model_runtime_is_cn10k(void)
{
	return (octeon_model.flag & (OCTEON_MODEL_CN10K));
}

static inline uint64_t
octeon_model_is_cn98xx(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN98xx_Ax);
}

static inline uint64_t
octeon_model_is_cn98xx_a0(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN98xx_A0);
}

static inline uint64_t
octeon_model_is_cn98xx_a1(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN98xx_A1);
}

static inline uint64_t
octeon_model_is_cn96_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN96xx_A0;
}

static inline uint64_t
octeon_model_is_cn96_ax(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN96xx_Ax);
}

static inline uint64_t
octeon_model_is_cn96_b0(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN96xx_B0);
}

static inline uint64_t
octeon_model_is_cn96_cx(void)
{
	return (octeon_model.flag & OCTEON_MODEL_CN96xx_C0);
}

static inline uint64_t
octeon_model_is_cn95_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xx_A0;
}

static inline uint64_t
octeon_model_is_cnf95xxn_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xxN_A0;
}

static inline uint64_t
octeon_model_is_cnf95xxn_a1(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xxN_A1;
}

static inline uint64_t
octeon_model_is_cnf95xxn_b0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xxN_B0;
}

static inline uint64_t
octeon_model_is_cnf95xxo_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xxO_A0;
}

static inline uint16_t
octeon_model_is_cn95xxn_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF95xxN_A0;
}

static inline uint64_t
octeon_model_is_cn10ka(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN106xx;
}

static inline uint64_t
octeon_model_is_cnf10ka(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF105xx;
}

static inline uint64_t
octeon_model_is_cnf10kb(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF105xxN;
}

static inline uint64_t
octeon_model_is_cn10kb_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN103xx_A0;
}

static inline uint64_t
octeon_model_is_cn10ka_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN106xx_A0;
}

static inline uint64_t
octeon_model_is_cn10ka_a1(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN106xx_A1;
}

static inline uint64_t
octeon_model_is_cnf10ka_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF105xx_A0;
}

static inline uint64_t
octeon_model_is_cnf10ka_a1(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF105xx_A1;
}

static inline uint64_t
octeon_model_is_cnf10kb_a0(void)
{
	return octeon_model.flag & OCTEON_MODEL_CNF105xxN_A0;
}

static inline uint64_t
octeon_model_is_cn103xx(void)
{
	return octeon_model.flag & OCTEON_MODEL_CN103xx;
}

/* Errata IPBUNIXTX-35039 */
static inline bool
octeon_errata_sdp_mtu_size_16k(void)
{
	return (octeon_model_is_cnf95xxn_a0() || octeon_model_is_cnf95xxo_a0() ||
			octeon_model_is_cn96_a0() || octeon_model_is_cn96_b0());
}


int octeon_model_info(struct octeon_model *model, octeon_device_t *oct);
#endif
