/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2027 Asterfusion Network
 */

#include "hqos/fifo/fifo.h"

hqos_fifo_t *
hqos_fifo_alloc (u32 fifo_size, u32 elemt_size)
{
  u32 rounded_elemt_size;
  u32 rounded_fifo_size;
  u32 data_size;
  hqos_fifo_t *f;

  rounded_elemt_size = (1 << (max_log2 (elemt_size)));
  rounded_fifo_size = (1 << (max_log2 (fifo_size)));
  data_size = rounded_fifo_size * rounded_elemt_size;

  f = clib_mem_alloc_aligned_or_null (sizeof (*f) + data_size, CLIB_CACHE_LINE_BYTES);
  if (f == 0)
    return 0;

  clib_memset (f, 0, sizeof (*f));

  f->size = rounded_fifo_size;
  f->size_mask = (rounded_fifo_size - 1);
  f->elemt_length = rounded_elemt_size;
  f->capacity = f->size_mask;

  return f;
}

void
hqos_fifo_free (hqos_fifo_t * f)
{
    clib_mem_free (f);
}
