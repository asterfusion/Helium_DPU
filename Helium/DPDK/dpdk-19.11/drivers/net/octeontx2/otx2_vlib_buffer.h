/*
 * Copyright (c) 2019 Marvell International Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * buffer.h: VLIB buffers
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_otx2_vlib_buffer_h
#define included_otx2_vlib_buffer_h

#include <assert.h>

#include <rte_mempool.h>

#define VLIB_STATIC_ASSERT(s) static_assert(s, #s)

#define DPDK_LOG2_VLIB_BUFFER_FLAG_USER(n)	(32 - (n))
#define DPDK_VLIB_BUFFER_FLAG_USER(n)	(1 << LOG2_VLIB_BUFFER_FLAG_USER(n))
#define DPDK_VLIB_BUFFER_FLAGS_ALL		(0x0f)
#define DPDK_VLIB_BUFFER_PRE_DATA_SIZE	 128
#define DPDK_VLIB_BUFFER_DEFAULT_DATA_SIZE	(2048)
#define DPDK_VLIB_BUFFER_MIN_CHAIN_SEG_SIZE	(128)
#define DPDK_VLIB_BUFFER_CLONE_HEAD_SIZE	(256)
#define DPDK_OTX2_RX_BURST_SZ		256

enum {
	DPDK_VLIB_BUFFER_IS_TRACED = (1 << 0),
	DPDK_VLIB_BUFFER_NEXT_PRESENT = (1 << 1),
	DPDK_VLIB_BUFFER_TOTAL_LENGTH_VALID = (1 << 2),
	DPDK_VLIB_BUFFER_EXT_HDR_VALID = (1 << 3)
};

enum {
	DPDK_VLIB_BUFFER_LOG2_IS_TRACED = 0,
	DPDK_VLIB_BUFFER_LOG2_NEXT_PRESENT = 1,
	DPDK_VLIB_BUFFER_LOG2_TOTAL_LENGTH_VALID = 2,
	DPDK_VLIB_BUFFER_LOG2_EXT_HDR_VALID = 3
};

typedef union {
	struct {
		MARKER cacheline0 __rte_cache_aligned;
		int16_t current_data;
		uint16_t current_length;
		uint32_t flags;
		uint32_t flow_id;
		volatile uint8_t ref_count;
		uint8_t buffer_pool_index;
		uint16_t error;
		uint32_t next_buffer;
		union {
			uint32_t current_config_index;
			uint32_t punt_reason;
		};
		int32_t opaque[10];
		void  *custom_ptr;
		MARKER cacheline1 __rte_cache_aligned;
		uint32_t trace_handle;
		uint32_t total_length_not_including_first_buffer;
		uint32_t opaque2[14];
		MARKER cacheline2 __rte_cache_aligned;
		uint8_t pre_data[DPDK_VLIB_BUFFER_PRE_DATA_SIZE];
		uint8_t data[0];
	};
} dpdk_vlib_buffer_t;

#define DPDK_OTX2_MAX_NUM_MEMPOOLS 8
typedef struct {
	MARKER cacheline0 __rte_cache_aligned;
	dpdk_vlib_buffer_t *vbufs[DPDK_OTX2_RX_BURST_SZ];
	uint32_t buffers[DPDK_OTX2_RX_BURST_SZ];
	uint16_t next[DPDK_OTX2_RX_BURST_SZ];
	dpdk_vlib_buffer_t buffer_template;
	MARKER cacheline1 __rte_cache_aligned;
	/*count to refill or deplete pool */
	int64_t n_buffers_to_free;
	/*Device flags */
	uint64_t xd_flags;
	/*Number of packet bytes */
	uint32_t rx_n_bytes;
	/*packet offload flags */
	uint16_t rx_or_flags;
	/*n_packets not freed by device due to refcount >1 */
	uint16_t tx_not_freed;
	uint32_t buffer_pool_index;
	struct rte_mempool *otx2_mempool_by_index[DPDK_OTX2_MAX_NUM_MEMPOOLS];
	uint16_t holding_cq_tag;
} dpdk_otx2_per_thread_data_t __rte_cache_aligned;

VLIB_STATIC_ASSERT(offsetof(dpdk_vlib_buffer_t, custom_ptr) == 64);

typedef struct {
	uint32_t sw_if_index[2];
	int16_t  l2_hdr_offset;
	int16_t  l3_hdr_offset;
	int16_t  l4_hdr_offset;
	uint8_t  feature_arc_index;
	uint8_t dont_waste_me;
	uint8_t  packet_flags[28];
} dpdk_vnet_buffer_opaque_t;

#define DPDK_VLIB_BUFFER_TEMPLATE_OFFSET (		\
			offsetof(dpdk_otx2_per_thread_data_t, buffer_template))
#define DPDK_PTD_PKT_BYTES_OFFSET (				\
			offsetof(dpdk_otx2_per_thread_data_t, n_bytes))
#define dpdk_vnet_buffer(b) ((dpdk_vnet_buffer_opaque_t *)(b)->opaque)
#define DPDK_VLIB_BUFFER_HDR_SIZE   (sizeof(dpdk_vlib_buffer_t) - \
				DPDK_VLIB_BUFFER_PRE_DATA_SIZE)

#endif /* included_vlib_buffer_h */
