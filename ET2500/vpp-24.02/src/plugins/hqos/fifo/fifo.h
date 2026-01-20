/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */
#ifndef included_hqos_fifo_h
#define included_hqos_fifo_h

#include <stdint.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <vppinfra/cpu.h>
#include <vppinfra/lock.h>
#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/mem.h>
#include <vppinfra/types.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>


//support SPSC、MPSC、MPMC

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
  HQOS_FIFO_EFULL = -2,
  HQOS_FIFO_EEMPTY = -3,
} hqos_fifo_err_t;


typedef struct _hqos_ring_headtail
{
    volatile uint32_t head;
    volatile uint32_t tail;
} hqos_ring_headtail;

typedef struct _hqos_fifo
{
    CLIB_CACHE_LINE_ALIGN_MARK (base);
    u32 size;                         /**< size of the fifo */
    u32 size_mask;
    u32 elemt_length;                 /**< size of the elemt */
    u32 capacity;

    CLIB_CACHE_LINE_ALIGN_MARK (producer);
    hqos_ring_headtail prod;

    CLIB_CACHE_LINE_ALIGN_MARK (consumer);
    hqos_ring_headtail cons;

    CLIB_CACHE_LINE_ALIGN_MARK (fifo_data);
    u8 data[0];                       /**< start of data */
} hqos_fifo_t;


hqos_fifo_t * hqos_fifo_alloc (u32 fifo_size, u32 elemt_size);
void hqos_fifo_free (hqos_fifo_t * f);

static_always_inline void
__hqos_update_tail(hqos_ring_headtail *ht, 
                  u32 old_val, u32 new_val, u8 is_single)
{
    if (!is_single)
    {
        while(clib_atomic_load_relax_n(
                    &ht->tail) != old_val)
            CLIB_PAUSE();
    }

    clib_atomic_store_rel_n(&ht->tail, new_val);
}

static_always_inline u32
__hqos_move_prod_head(hqos_fifo_t *f, u32 num, 
                      u32 *old_head, u32 *new_head, u32 *free_entries, u8 is_sp)
{
    const u32 capacity = f->capacity;
    u32 cons_tail;
    u32 max = num;
    int success;

    *old_head = clib_atomic_load_relax_n (&f->prod.head);
    do {
       num = max;

       /* Ensure the head is read before tail */
       __atomic_thread_fence(__ATOMIC_ACQUIRE);

       cons_tail = clib_atomic_load_acq_n(&f->cons.tail);

       *free_entries = (capacity + cons_tail - *old_head);

       if (PREDICT_FALSE(num > *free_entries))
       {
           num = *free_entries;
       }

       if (num == 0)
           return 0;

       *new_head = *old_head + num;

       if (is_sp) 
       {
           f->prod.head = *new_head;
           success = 1;
       }
       else
       {
           success = __atomic_compare_exchange_n(&f->prod.head, 
                                                 old_head, *new_head, 0,
                                                 __ATOMIC_RELAXED, __ATOMIC_RELAXED);
       }

    } while(PREDICT_FALSE(success == 0));

    return num;
}

static_always_inline u32
__hqos_move_cons_head(hqos_fifo_t *f, u32 num, u32 *old_head, u32 *new_head, u32 *entries, u8 is_sc)
{
    u32 max = num;
    u32 prod_tail;
    int success;

    *old_head = clib_atomic_load_relax_n (&f->cons.head);
    do {
        num = max;

        /* Ensure the head is read before tail */
        __atomic_thread_fence(__ATOMIC_ACQUIRE);

       prod_tail = clib_atomic_load_acq_n(&f->prod.tail);

       *entries = (prod_tail - *old_head);

       if (num > *entries)
       {
           num = *entries;
       }

       if (PREDICT_FALSE(num == 0))
           return 0;

       *new_head = *old_head + num;

       if (is_sc)
       {
           f->cons.head = *new_head;
           success = 1;
       }
       else
       {
           success = __atomic_compare_exchange_n(&f->cons.head, 
                                                 old_head, *new_head, 0,
                                                 __ATOMIC_RELAXED, __ATOMIC_RELAXED);

       }
    } while(PREDICT_FALSE(success == 0));

    return num;
}

static_always_inline void
__hqos_enqueue_elems_32(hqos_fifo_t *f, const u32 size,
        u32 idx, const void *src, u32 n)
{
    u32 i;
    u32 *ring = (u32 *)&f->data;
    const u32 *obj = (const u32 *)src;
    if (PREDICT_TRUE(idx + n <= size)) {
        for (i = 0; i < (n & ~0x7); i += 8, idx += 8) 
        {
            ring[idx] = obj[i];
            ring[idx + 1] = obj[i + 1];
            ring[idx + 2] = obj[i + 2];
            ring[idx + 3] = obj[i + 3];
            ring[idx + 4] = obj[i + 4];
            ring[idx + 5] = obj[i + 5];
            ring[idx + 6] = obj[i + 6];
            ring[idx + 7] = obj[i + 7];
        }
        switch (n & 0x7) 
        {
        case 7:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 6:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 5:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 4:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 3:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 2:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 1:
            ring[idx++] = obj[i++]; /* fallthrough */
        }
    } 
    else 
    {
        for (i = 0; idx < size; i++, idx++)
            ring[idx] = obj[i];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            ring[idx] = obj[i];
    }
}

static_always_inline void
__hqos_enqueue_elems_64(hqos_fifo_t *f, u32 prod_head, const void *src, u32 num)
{
    u32 i;
    const u32 size = f->size;
    u32 idx = prod_head & f->size_mask;
    u64 *ring = (u64 *)f->data;
    const u64 *obj = (const u64 *)src;
    if (PREDICT_TRUE(idx + num <= size)) 
    {
        for (i = 0; i < (num & ~0x3); i += 4, idx += 4) 
        {
            ring[idx] = obj[i];
            ring[idx + 1] = obj[i + 1];
            ring[idx + 2] = obj[i + 2];
            ring[idx + 3] = obj[i + 3];
        }
        switch (num & 0x3) 
        {
        case 3:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 2:
            ring[idx++] = obj[i++]; /* fallthrough */
        case 1:
            ring[idx++] = obj[i++];
        }
    } 
    else 
    {
        for (i = 0; idx < size; i++, idx++)
            ring[idx] = obj[i];
        /* Start at the beginning */
        for (idx = 0; i < num; i++, idx++)
            ring[idx] = obj[i];
    }
}

static_always_inline void
__hqos_enqueue_elems(hqos_fifo_t *f, u32 prod_head, const void *src, u32 num)
{
    if (f->elemt_length == 8)
    {
        __hqos_enqueue_elems_64(f, prod_head, src, num);
    }
    else 
    {
        uint32_t idx, scale, nr_idx, nr_num, nr_size;
        scale = f->elemt_length / sizeof(u32);
        nr_num = num * scale;
        idx = prod_head & f->size_mask;
        nr_idx = idx * scale;
        nr_size = f->size * scale;
        __hqos_enqueue_elems_32(f, nr_size, nr_idx, src, nr_num);
    }
}

static_always_inline void
__hqos_dequeue_elems_32(hqos_fifo_t *f, const u32 size,
        u32 idx, void *dst, u32 n)
{
    u32 i;
    u32 *ring = (u32 *)f->data;
    u32 *obj = (uint32_t *)dst;
    if (PREDICT_TRUE(idx + n <= size)) 
    {
        for (i = 0; i < (n & ~0x7); i += 8, idx += 8) 
        {
            obj[i] = ring[idx];
            obj[i + 1] = ring[idx + 1];
            obj[i + 2] = ring[idx + 2];
            obj[i + 3] = ring[idx + 3];
            obj[i + 4] = ring[idx + 4];
            obj[i + 5] = ring[idx + 5];
            obj[i + 6] = ring[idx + 6];
            obj[i + 7] = ring[idx + 7];
        }
        switch (n & 0x7) 
        {
        case 7:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 6:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 5:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 4:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 3:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 2:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 1:
            obj[i++] = ring[idx++]; /* fallthrough */
        }
    } 
    else 
    {
        for (i = 0; idx < size; i++, idx++)
            obj[i] = ring[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj[i] = ring[idx];
    }
}

static_always_inline void
__hqos_dequeue_elems_64(hqos_fifo_t *f, u32 cons_head, void *dst, u32 n)
{
    u32 i;
    const u32 size = f->size;
    u32 idx = cons_head & f->size_mask;
    u64 *ring = (u64 *)f->data;
    u64 *obj = (u64 *)dst;
    if (PREDICT_TRUE(idx + n <= size)) 
    {
        for (i = 0; i < (n & ~0x3); i += 4, idx += 4) 
        {
            obj[i] = ring[idx];
            obj[i + 1] = ring[idx + 1];
            obj[i + 2] = ring[idx + 2];
            obj[i + 3] = ring[idx + 3];
        }
        switch (n & 0x3) 
        {
        case 3:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 2:
            obj[i++] = ring[idx++]; /* fallthrough */
        case 1:
            obj[i++] = ring[idx++]; /* fallthrough */
        }
    } 
    else 
    {
        for (i = 0; idx < size; i++, idx++)
            obj[i] = ring[idx];
        /* Start at the beginning */
        for (idx = 0; i < n; i++, idx++)
            obj[i] = ring[idx];
    }
}

static_always_inline void
__hqos_dequeue_elems(hqos_fifo_t *f, u32 cons_head, void *dst, u32 num)
{
    if (f->elemt_length == 8)
        __hqos_dequeue_elems_64(f, cons_head, dst, num);
    else {
        uint32_t idx, scale, nr_idx, nr_num, nr_size;
        scale = f->elemt_length / sizeof(uint32_t);
        nr_num = num * scale;
        idx = cons_head & f->size_mask;
        nr_idx = idx * scale;
        nr_size = f->size * scale;
        __hqos_dequeue_elems_32(f, nr_size, nr_idx, dst, nr_num);
    }
}

static_always_inline int
hqos_fifo_enqueue_sp (hqos_fifo_t * f, u32 num, const void * src)
{
    u32 prod_head, prod_next, free_count;

    num = __hqos_move_prod_head(f, num, &prod_head, &prod_next, &free_count, 1);

    if (num == 0)
        goto end;

    __hqos_enqueue_elems(f, prod_head, src, num);
    __hqos_update_tail(&f->prod, prod_head, prod_next, 1);

end:
    return num;
}

static_always_inline int
hqos_fifo_enqueue_mp (hqos_fifo_t * f, u32 num, const void * src)
{
    u32 prod_head, prod_next, free_entries;

    num = __hqos_move_prod_head(f, num, &prod_head, &prod_next, &free_entries, 0);

    if (num == 0)
        goto end;

    __hqos_enqueue_elems(f, prod_head, src, num);
    __hqos_update_tail(&f->prod, prod_head, prod_next, 0);

end:
    return num;
}

static_always_inline int
hqos_fifo_dequeue_sc (hqos_fifo_t * f, u32 num, void * dst)
{
    u32 cons_head, cons_next;
    u32 entries;

    num = __hqos_move_cons_head(f, num, &cons_head, &cons_next, &entries, 1);

    if (num == 0)
        goto end;

    __hqos_dequeue_elems(f, cons_head, dst, num);
    __hqos_update_tail(&f->cons, cons_head, cons_next, 1);

end:
    return num;
}

static_always_inline int
hqos_fifo_dequeue_mc (hqos_fifo_t * f, u32 num, void * dst)
{
    u32 cons_head, cons_next;
    u32 entries;

    num = __hqos_move_cons_head(f, num, &cons_head, &cons_next, &entries, 0);

    if (num == 0)
        goto end;

    __hqos_dequeue_elems(f, cons_head, dst, num);
    __hqos_update_tail(&f->cons, cons_head, cons_next, 0);

end:
    return num;
}


static_always_inline u32 
hqos_fifo_count(const hqos_fifo_t *f)
{
    uint32_t prod_tail = f->prod.tail;
    uint32_t cons_tail = f->cons.tail;
    uint32_t count = (prod_tail - cons_tail) & f->size_mask;
    return (count > f->capacity) ? f->capacity : count;
}

static_always_inline u32 
hqos_fifo_free_count(const hqos_fifo_t *f)
{
    return f->capacity - hqos_fifo_count(f);
}

static_always_inline int
hqos_fifo_full(const hqos_fifo_t *f)
{
    return hqos_fifo_free_count(f) == 0;
}

static_always_inline int
hqos_fifo_empty(const hqos_fifo_t *f)
{
    uint32_t prod_tail = f->prod.tail;
    uint32_t cons_tail = f->cons.tail;
    return cons_tail == prod_tail;
}

#ifdef __cplusplus
}
#endif

#endif //included_hqos_fifo_h
