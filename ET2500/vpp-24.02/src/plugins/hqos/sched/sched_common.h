/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#ifndef included_hqos_sched_common_h
#define included_hqos_sched_common_h


#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>
#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/mem.h>
#include <vppinfra/types.h>
#include <vppinfra/time.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>

#include <vnet/buffer.h>

extern vlib_main_t *hqos_vlib_main;

static_always_inline vlib_main_t *
hqos_vlib_get_main()
{
    return hqos_vlib_main;
}

static_always_inline u32
vlib_buffer_hqos_tc_get(vlib_buffer_t *b)
{
    return vnet_buffer(b)->hqos.tc_index;
}

static_always_inline void
vlib_buffer_hqos_tc_set(vlib_buffer_t *b, u32 tc_index)
{
    vnet_buffer(b)->hqos.tc_index = tc_index;
}

static_always_inline u32
vlib_buffer_hqos_color_get(vlib_buffer_t *b)
{
    return vnet_buffer(b)->hqos.color;
}

static_always_inline void 
vlib_buffer_hqos_color_set(vlib_buffer_t *b, u32 color)
{
    vnet_buffer(b)->hqos.color = color;
}

static_always_inline u32
vlib_buffer_hqos_user_get(vlib_buffer_t *b)
{
    return vnet_buffer(b)->hqos.user_id;
}

static_always_inline u32
vlib_buffer_hqos_queue_get(vlib_buffer_t *b)
{
    return vnet_buffer(b)->hqos.queue_id;
}

static_always_inline void 
vlib_buffer_hqos_queue_set(vlib_buffer_t *b, u32 queue_id)
{
    vnet_buffer(b)->hqos.queue_id = queue_id;
}

#define HQOS_MIN(a, b) \
    __extension__ ({ \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        _a < _b ? _a : _b; \
    })

#define HQOS_MAX(a, b) \
    __extension__ ({ \
        typeof (a) _a = (a); \
        typeof (b) _b = (b); \
        _a > _b ? _a : _b; \
    })

#define hqos_count_trailing_zeros_32(x)  __builtin_ctz (x)
#define hqos_count_trailing_zeros_64(x)  __builtin_ctzll (x)

#define hqos_count_leading_zeros_32(x) __builtin_clz (x)
#define hqos_count_leading_zeros_64(x) __builtin_clzll (x)

static_always_inline int
hqos_bsf64(uint64_t v)
{
    return hqos_count_trailing_zeros_64(v);
}

static_always_inline int
hqos_bsf64_safe(uint64_t v, uint32_t *pos)
{
    if (v == 0)
        return 0;

    *pos = hqos_bsf64(v);
    return 1;
}

static_always_inline u32 
hqos_min_pos_8_u16(u16 *x)
{
    u32 pos0 = 0;
    u32 pos1 = 2;
    u32 pos2 = 4;
    u32 pos3 = 6;

    if (x[1] <= x[0]) pos0 = 1;                     
    if (x[3] <= x[2]) pos1 = 3;
    if (x[5] <= x[4]) pos2 = 5;
    if (x[7] <= x[6]) pos3 = 7;
    if (x[pos1] <= x[pos0]) pos0 = pos1;
    if (x[pos3] <= x[pos2]) pos2 = pos3;
    if (x[pos2] <= x[pos0]) pos0 = pos2;

    return pos0;
}   

static_always_inline u64 
hqos_get_gcd64(u64 a, u64 b)
{
    u64 c;

    if (a == 0) return b;
    if (b == 0) return a;

    if (a < b) {
        c = a; a = b; b = c;
    }

    while (b != 0) {
        c = a % b;
        a = b; b = c;
    }

    return a;
}

static_always_inline u32 
hqos_get_gcd(u32 a, u32 b)
{
    return hqos_get_gcd64(a, b);
}

static_always_inline u32
hqos_get_lcd(u32 a, u32 b)
{
    return (a * b) / hqos_get_gcd(a, b);
}


extern clib_time_t hqos_clib_time;

void hqos_clib_time_init();

static_always_inline u64
hqos_get_cpu_hz()
{
    return hqos_clib_time.clocks_per_second;
}


#ifdef __cplusplus
}
#endif

#endif //included_hqos_sched_common_h
