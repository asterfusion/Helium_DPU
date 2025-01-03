/*
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef include_dpdk_buffer_h
#define include_dpdk_buffer_h

#define rte_mbuf_from_vlib_buffer(x) (((struct rte_mbuf *)x) - 1)
#define vlib_buffer_from_rte_mbuf(x) ((vlib_buffer_t *)(x+1))

extern struct rte_mempool **dpdk_mempool_by_buffer_pool_index;
extern struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index;
extern u8 dpdk_is_mempool_ops_used;

clib_error_t *dpdk_buffer_pools_create (vlib_main_t *vm, char *, u32);

clib_error_t *dpdk_buffer_pool_init (vlib_main_t *vm, vlib_buffer_pool_t *bp,
				     const char *cache_ops_name,
				     const char *non_cache_ops_name,
				     int use_dpdk_ops, u32 nmbufs);
#ifdef CLIB_MARCH_VARIANT
typedef int (dpdk_ops_vpp_enqueue) (struct rte_mempool *mp,
				    void *const *obj_table, unsigned int n);

typedef int (dpdk_ops_vpp_dequeue) (struct rte_mempool *mp, void **obj_table,
				    unsigned int n);

typedef int (dpdk_ops_vpp_enqueue_no_cache) (struct rte_mempool *cmp,
					     void *const *obj_table,
					     unsigned n);
#endif
#endif /* include_dpdk_buffer_h */

/** @endcond */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
