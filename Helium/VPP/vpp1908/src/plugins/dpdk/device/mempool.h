#ifndef __include_dpdk_mempool_h__
#define __include_dpdk_mempool_h__


#include <dpdk/buffer.h>
#include <dpdk/device/dpdk.h>

#define OTX2_MEMPOOL_REFILL_DEPLETE_COUNT 256

STATIC_ASSERT ((OTX2_MEMPOOL_REFILL_DEPLETE_COUNT % 32) == 0,
	       "Mempool deplete count should be multipe of 32");

static inline u32
otx2_mempool_deplete (vlib_main_t * vm, u32 buffer_pool_index,
		      i64 n_buffers_to_free, u32 * bi, void **buffers)
{
  struct rte_mempool *mp =
    dpdk_mempool_by_buffer_pool_index[buffer_pool_index];

  if (PREDICT_FALSE (!mp))
    clib_panic ("mempool at index %u is NULL", buffer_pool_index);

  if (PREDICT_FALSE (n_buffers_to_free < 1))
    return 0;

  if (PREDICT_FALSE (rte_mempool_get_bulk (mp, buffers, n_buffers_to_free)))
    clib_panic ("rte_mempool_get_bulk failed for mp: %0xlx", mp);

  vlib_get_buffer_indices_with_offset (vm, buffers, bi, n_buffers_to_free,
				       sizeof (struct rte_mbuf));
  vlib_buffer_free_inline (vm, bi, n_buffers_to_free,2);
  return n_buffers_to_free;
}

static inline u32
otx2_mempool_refill (vlib_main_t * vm,
		     u32
		     buffer_pool_index,
		     i64 n_buffers_to_free, u32 * bi, void **buffers)
{
  struct rte_mempool *mp =
    dpdk_mempool_by_buffer_pool_index[buffer_pool_index];

  if (PREDICT_FALSE (!mp))
    clib_panic ("mempool at index %u is NULL", buffer_pool_index);

  if (PREDICT_FALSE (n_buffers_to_free < 1))
    return 0;

  n_buffers_to_free =
    vlib_buffer_alloc_from_pool (vm, bi,
				 n_buffers_to_free, buffer_pool_index);

  vlib_get_buffers_with_offset (vm, bi,
				buffers,
				n_buffers_to_free,
				-(i32) sizeof (struct rte_mbuf));

  rte_mempool_put_bulk (mp, buffers, n_buffers_to_free);

  return (n_buffers_to_free);
}


#endif //__include_dpdk_mempool_h__