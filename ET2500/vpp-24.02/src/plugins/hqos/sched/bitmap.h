/*                                                                                   
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#ifndef included_hqos_bitmap_h
#define included_hqos_bitmap_h

/** 
 * @file
 * Transplant DPDK Bitmap
 */

#include "hqos/sched/sched_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Slab */
#define HQOS_BITMAP_SLAB_BIT_SIZE                 64
#define HQOS_BITMAP_SLAB_BIT_SIZE_LOG2            6
#define HQOS_BITMAP_SLAB_BIT_MASK                 (HQOS_BITMAP_SLAB_BIT_SIZE - 1)

/* Cache line (CL) */
#define HQOS_BITMAP_CL_BIT_SIZE                   (CLIB_CACHE_LINE_BYTES * 8)
#define HQOS_BITMAP_CL_BIT_SIZE_LOG2              (CLIB_LOG2_CACHE_LINE_BYTES + 3)
#define HQOS_BITMAP_CL_BIT_MASK                   (HQOS_BITMAP_CL_BIT_SIZE - 1)

#define HQOS_BITMAP_CL_SLAB_SIZE                  (HQOS_BITMAP_CL_BIT_SIZE / HQOS_BITMAP_SLAB_BIT_SIZE)
#define HQOS_BITMAP_CL_SLAB_SIZE_LOG2             (HQOS_BITMAP_CL_BIT_SIZE_LOG2 - HQOS_BITMAP_SLAB_BIT_SIZE_LOG2)
#define HQOS_BITMAP_CL_SLAB_MASK                  (HQOS_BITMAP_CL_SLAB_SIZE - 1)

/** Bitmap data structure */
typedef struct _hqos_bitmap {
    /* Context for array1 and array2 */
    u64 *array1;                        /**< Bitmap array1 */
    u64 *array2;                        /**< Bitmap array2 */
    u32 array1_size;                    /**< Number of 64-bit slabs in array1 that are actually used */
    u32 array2_size;                    /**< Number of 64-bit slabs in array2 */

    /* Context for the "scan next" operation */
    u32 index1;  /**< Bitmap scan: Index of current array1 slab */
    u32 offset1; /**< Bitmap scan: Offset of current bit within current array1 slab */
    u32 index2;  /**< Bitmap scan: Index of current array2 slab */
    u32 go2;     /**< Bitmap scan: Go/stop condition for current array2 cache line */

    /* Storage space for array1 and array2 */
    u8 memory[];
} hqos_bitmap;

static_always_inline void
__hqos_bitmap_index1_inc(hqos_bitmap *bmp)                               
{       
    bmp->index1 = (bmp->index1 + 1) & (bmp->array1_size - 1);                 
}       
            
static_always_inline u64 
__hqos_bitmap_mask1_get(hqos_bitmap *bmp)
{   
    return (~1llu) << bmp->offset1;
}

static_always_inline void
__hqos_bitmap_index2_set(hqos_bitmap *bmp)
{
    bmp->index2 = (((bmp->index1 << HQOS_BITMAP_SLAB_BIT_SIZE_LOG2) + bmp->offset1) << HQOS_BITMAP_CL_SLAB_SIZE_LOG2);
}

static inline u32 
__hqos_bitmap_get_memory_footprint(u32 n_bits,
                                   u32 *array1_byte_offset, u32 *array1_slabs,
                                   u32 *array2_byte_offset, u32 *array2_slabs)
{
    u32 n_slabs_context, n_slabs_array1, n_cache_lines_context_and_array1;
    u32 n_cache_lines_array2;
    u32 n_bytes_total;

    n_cache_lines_array2 = (n_bits + HQOS_BITMAP_CL_BIT_SIZE - 1) / HQOS_BITMAP_CL_BIT_SIZE;
    n_slabs_array1 = (n_cache_lines_array2 + HQOS_BITMAP_SLAB_BIT_SIZE - 1) / HQOS_BITMAP_SLAB_BIT_SIZE;
    n_slabs_array1 = max_pow2(n_slabs_array1);
    n_slabs_context = (sizeof(hqos_bitmap) + (HQOS_BITMAP_SLAB_BIT_SIZE / 8) - 1) / (HQOS_BITMAP_SLAB_BIT_SIZE / 8);
    n_cache_lines_context_and_array1 = (n_slabs_context + n_slabs_array1 + HQOS_BITMAP_CL_SLAB_SIZE - 1) / HQOS_BITMAP_CL_SLAB_SIZE;
    n_bytes_total = (n_cache_lines_context_and_array1 + n_cache_lines_array2) * CLIB_CACHE_LINE_BYTES;

    if (array1_byte_offset) {
        *array1_byte_offset = n_slabs_context * (HQOS_BITMAP_SLAB_BIT_SIZE / 8);
    }
    if (array1_slabs) {
        *array1_slabs = n_slabs_array1;
    }
    if (array2_byte_offset) {
        *array2_byte_offset = n_cache_lines_context_and_array1 * CLIB_CACHE_LINE_BYTES;
    }
    if (array2_slabs) {
        *array2_slabs = n_cache_lines_array2 * HQOS_BITMAP_CL_SLAB_SIZE;
    }

    return n_bytes_total;
}

static_always_inline void
__hqos_bitmap_scan_init(hqos_bitmap *bmp)
{
    bmp->index1 = bmp->array1_size - 1;
    bmp->offset1 = HQOS_BITMAP_SLAB_BIT_SIZE - 1;
    __hqos_bitmap_index2_set(bmp);
    bmp->index2 += HQOS_BITMAP_CL_SLAB_SIZE;

    bmp->go2 = 0;
}

/**
 * Bitmap memory footprint calculation
 *
 * @param n_bits
 *   Number of bits in the bitmap
 * @return
 *   Bitmap memory footprint measured in bytes on success, 0 on error
 */
static_always_inline u32 
hqos_bitmap_get_memory_footprint(u32 n_bits) {
    /* Check input arguments */
    if (n_bits == 0) {
        return 0;
    }

    return __hqos_bitmap_get_memory_footprint(n_bits, NULL, NULL, NULL, NULL);
}

/**
 * Bitmap initialization
 *
 * @param n_bits
 *   Number of pre-allocated bits in array2.
 * @param mem
 *   Base address of array1 and array2.
 * @param mem_size
 *   Minimum expected size of bitmap.
 * @return
 *   Handle to bitmap instance.
 */
static_always_inline hqos_bitmap *
hqos_bitmap_init(u32 n_bits, u8 *mem, u32 mem_size)
{
    hqos_bitmap *bmp;
    u32 array1_byte_offset, array1_slabs, array2_byte_offset, array2_slabs;
    u32 size;

    /* Check input arguments */
    if (n_bits == 0) {
        return NULL;
    }

    if ((mem == NULL) || (((uintptr_t) mem) & (CLIB_CACHE_LINE_BYTES - 1))) {
        return NULL;
    }

    size = __hqos_bitmap_get_memory_footprint(n_bits,
        &array1_byte_offset, &array1_slabs,
        &array2_byte_offset, &array2_slabs);
    if (size > mem_size)
        return NULL;

    /* Setup bitmap */
    memset(mem, 0, size);
    bmp = (hqos_bitmap *) mem;

    bmp->array1 = (u64 *) &mem[array1_byte_offset];
    bmp->array1_size = array1_slabs;
    bmp->array2 = (u64 *) &mem[array2_byte_offset];
    bmp->array2_size = array2_slabs;

    __hqos_bitmap_scan_init(bmp);

    return bmp;
}

/**
 * Bitmap free
 *
 * @param bmp
 *   Handle to bitmap instance
 * @return
 *   0 upon success, error code otherwise
 */
static_always_inline int
hqos_bitmap_free(hqos_bitmap *bmp)
{
    /* Check input arguments */
    if (bmp == NULL) {
        return -1;
    }

    return 0;
}

/**
 * Bitmap reset
 *
 * @param bmp
 *   Handle to bitmap instance
 */
static_always_inline void
hqos_bitmap_reset(hqos_bitmap *bmp)
{
    memset(bmp->array1, 0, bmp->array1_size * sizeof(u64));
    memset(bmp->array2, 0, bmp->array2_size * sizeof(u64));
    __hqos_bitmap_scan_init(bmp);
}

/**
 * Bitmap location prefetch into CPU L1 cache
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static_always_inline void
hqos_bitmap_prefetch0(hqos_bitmap *bmp, u32 pos)
{
    u64 *slab2;
    u32 index2;

    index2 = pos >> HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
    slab2 = bmp->array2 + index2;

    clib_prefetch_load((void *) slab2);
}

/**
 * Bitmap bit get
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 * @return
 *   0 when bit is cleared, non-zero when bit is set
 */
static_always_inline u64 
hqos_bitmap_get(hqos_bitmap *bmp, u32 pos)
{
    u64 *slab2;
    u32 index2, offset2;

    index2 = pos >> HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
    offset2 = pos & HQOS_BITMAP_SLAB_BIT_MASK;
    slab2 = bmp->array2 + index2;
    return (*slab2) & (1llu << offset2);
}

/**
 * Bitmap bit set
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static_always_inline void
hqos_bitmap_set(hqos_bitmap *bmp, u32 pos)
{
    u64 *slab1, *slab2;
    u32 index1, index2, offset1, offset2;

    /* Set bit in array2 slab and set bit in array1 slab */
    index2 = pos >> HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
    offset2 = pos & HQOS_BITMAP_SLAB_BIT_MASK;
    index1 = pos >> (HQOS_BITMAP_SLAB_BIT_SIZE_LOG2 + HQOS_BITMAP_CL_BIT_SIZE_LOG2);
    offset1 = (pos >> HQOS_BITMAP_CL_BIT_SIZE_LOG2) & HQOS_BITMAP_SLAB_BIT_MASK;
    slab2 = bmp->array2 + index2;
    slab1 = bmp->array1 + index1;

    *slab2 |= 1llu << offset2;
    *slab1 |= 1llu << offset1;
}

/**
 * Bitmap slab set
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position identifying the array2 slab
 * @param slab
 *   Value to be assigned to the 64-bit slab in array2
 */
static_always_inline void
hqos_bitmap_set_slab(hqos_bitmap *bmp, u32 pos, u64 slab)
{
    u64 *slab1, *slab2;
    u32 index1, index2, offset1;

    /* Set bits in array2 slab and set bit in array1 slab */
    index2 = pos >> HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
    index1 = pos >> (HQOS_BITMAP_SLAB_BIT_SIZE_LOG2 + HQOS_BITMAP_CL_BIT_SIZE_LOG2);
    offset1 = (pos >> HQOS_BITMAP_CL_BIT_SIZE_LOG2) & HQOS_BITMAP_SLAB_BIT_MASK;
    slab2 = bmp->array2 + index2;
    slab1 = bmp->array1 + index1;

    *slab2 |= slab;
    *slab1 |= 1llu << offset1;
}

#if HQOS_BITMAP_CL_SLAB_SIZE == 16
static_always_inline u64 
__hqos_bitmap_line_not_empty(u64 *slab2)
{
    u64 v1, v2, v3, v4, v5, v6, v7, v8;

    v1 = slab2[0] | slab2[1];
    v2 = slab2[2] | slab2[3];
    v3 = slab2[4] | slab2[5];
    v4 = slab2[6] | slab2[7];
    v5 = slab2[8] | slab2[9];
    v6 = slab2[10] | slab2[11];
    v7 = slab2[12] | slab2[13];
    v8 = slab2[14] | slab2[15];
    v1 |= v2;
    v3 |= v4;
    v5 |= v6;
    v7 |= v8;

    return v1 | v3 | v5 | v7;
}

#else
static_always_inline u64 
__hqos_bitmap_line_not_empty(u64 *slab2)
{
    u64 v1, v2, v3, v4;

    v1 = slab2[0] | slab2[1];
    v2 = slab2[2] | slab2[3];
    v3 = slab2[4] | slab2[5];
    v4 = slab2[6] | slab2[7];
    v1 |= v2;
    v3 |= v4;

    return v1 | v3;
}
#endif /* HQOS_BITMAP_CL_SLAB_SIZE */

/**
 * Bitmap bit clear
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   Bit position
 */
static_always_inline void
hqos_bitmap_clear(hqos_bitmap *bmp, u32 pos)
{
    u64 *slab1, *slab2;
    u32 index1, index2, offset1, offset2;

    /* Clear bit in array2 slab */
    index2 = pos >> HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
    offset2 = pos & HQOS_BITMAP_SLAB_BIT_MASK;
    slab2 = bmp->array2 + index2;

    /* Return if array2 slab is not all-zeros */
    *slab2 &= ~(1llu << offset2);
    if (*slab2){
        return;
    }

    /* Check the entire cache line of array2 for all-zeros */
    index2 &= ~ HQOS_BITMAP_CL_SLAB_MASK;
    slab2 = bmp->array2 + index2;
    if (__hqos_bitmap_line_not_empty(slab2)) {
        return;
    }

    /* The array2 cache line is all-zeros, so clear bit in array1 slab */
    index1 = pos >> (HQOS_BITMAP_SLAB_BIT_SIZE_LOG2 + HQOS_BITMAP_CL_BIT_SIZE_LOG2);
    offset1 = (pos >> HQOS_BITMAP_CL_BIT_SIZE_LOG2) & HQOS_BITMAP_SLAB_BIT_MASK;
    slab1 = bmp->array1 + index1;
    *slab1 &= ~(1llu << offset1);

    return;
}

static_always_inline int
__hqos_bitmap_scan_search(hqos_bitmap *bmp)
{
    u64 value1;
    u32 i;

    /* Check current array1 slab */
    value1 = bmp->array1[bmp->index1];
    value1 &= __hqos_bitmap_mask1_get(bmp);

    if (hqos_bsf64_safe(value1, &bmp->offset1))
        return 1;

    __hqos_bitmap_index1_inc(bmp);
    bmp->offset1 = 0;

    /* Look for another array1 slab */
    for (i = 0; i < bmp->array1_size; i ++, __hqos_bitmap_index1_inc(bmp)) {
        value1 = bmp->array1[bmp->index1];

        if (hqos_bsf64_safe(value1, &bmp->offset1))
            return 1;
    }

    return 0;
}

static_always_inline void
__hqos_bitmap_scan_read_init(hqos_bitmap *bmp)
{
    __hqos_bitmap_index2_set(bmp);
    bmp->go2 = 1;
    clib_prefetch_load((void *)(bmp->array2 + bmp->index2 + 8));
}

static_always_inline int
__hqos_bitmap_scan_read(hqos_bitmap *bmp, u32 *pos, u64 *slab)
{
    u64 *slab2;

    slab2 = bmp->array2 + bmp->index2;
    for ( ; bmp->go2 ; bmp->index2 ++, slab2 ++, bmp->go2 = bmp->index2 & HQOS_BITMAP_CL_SLAB_MASK) {
        if (*slab2) {
            *pos = bmp->index2 << HQOS_BITMAP_SLAB_BIT_SIZE_LOG2;
            *slab = *slab2;

            bmp->index2 ++;
            slab2 ++;
            bmp->go2 = bmp->index2 & HQOS_BITMAP_CL_SLAB_MASK;
            return 1;
        }
    }

    return 0;
}

/**
 * Bitmap scan (with automatic wrap-around)
 *
 * @param bmp
 *   Handle to bitmap instance
 * @param pos
 *   When function call returns 1, pos contains the position of the next set
 *   bit, otherwise not modified
 * @param slab
 *   When function call returns 1, slab contains the value of the entire 64-bit
 *   slab where the bit indicated by pos is located. Slabs are always 64-bit
 *   aligned, so the position of the first bit of the slab (this bit is not
 *   necessarily set) is pos / 64. Once a slab has been returned by the bitmap
 *   scan operation, the internal pointers of the bitmap are updated to point
 *   after this slab, so the same slab will not be returned again if it
 *   contains more than one bit which is set. When function call returns 0,
 *   slab is not modified.
 * @return
 *   0 if there is no bit set in the bitmap, 1 otherwise
 */
static_always_inline int
hqos_bitmap_scan(hqos_bitmap *bmp, u32 *pos, u64 *slab)
{
    /* Return data from current array2 line if available */
    if (__hqos_bitmap_scan_read(bmp, pos, slab)) {
        return 1;
    }

    /* Look for non-empty array2 line */
    if (__hqos_bitmap_scan_search(bmp)) {
        __hqos_bitmap_scan_read_init(bmp);
        __hqos_bitmap_scan_read(bmp, pos, slab);
        return 1;
    }

    /* Empty bitmap */
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif //included_hqos_bitmap_h
