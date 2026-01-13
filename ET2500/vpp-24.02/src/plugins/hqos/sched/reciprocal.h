/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#ifndef included_hqos_reciprocal_h
#define included_hqos_reciprocal_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdalign.h>

typedef struct _hqos_reciprocal {
    uint32_t m;
    uint8_t sh1, sh2;
} hqos_reciprocal;

typedef struct _hqos_reciprocal_u64 {
    uint64_t m;
    uint8_t sh1, sh2;
} hqos_reciprocal_u64;

static inline uint32_t hqos_reciprocal_divide(uint32_t a, hqos_reciprocal R)
{
    uint32_t t = (uint32_t)(((uint64_t)a * R.m) >> 32);

    return (t + ((a - t) >> R.sh1)) >> R.sh2;
}

static inline __attribute__ ((__always_inline__)) uint64_t
mullhi_u64(uint64_t x, uint64_t y)
{
    uint64_t u0, u1, v0, v1, k, t;
    uint64_t w1, w2;
    uint64_t whi;

    u1 = x >> 32; u0 = x & 0xFFFFFFFF;
    v1 = y >> 32; v0 = y & 0xFFFFFFFF;

    t = u0*v0;
    k = t >> 32;

    t = u1*v0 + k;
    w1 = t & 0xFFFFFFFF;
    w2 = t >> 32;

    t = u0*v1 + w1;
    k = t >> 32;

    whi = u1*v1 + w2 + k;

    return whi;
}

static inline __attribute__ ((__always_inline__)) uint64_t
hqos_reciprocal_divide_u64(uint64_t a, const hqos_reciprocal_u64 *R)
{
    uint64_t t = mullhi_u64(a, R->m);

    return (t + ((a - t) >> R->sh1)) >> R->sh2;
}


hqos_reciprocal hqos_reciprocal_value(uint32_t d);
hqos_reciprocal_u64 hqos_reciprocal_value_u64(uint64_t d);


#ifdef __cplusplus
}
#endif

#endif //included_hqos_reciprocal_h
