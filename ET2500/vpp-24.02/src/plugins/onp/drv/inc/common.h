/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_common_h
#define included_onp_drv_inc_common_h

#include <vlib/pci/pci.h>
#include <vnet/flow/flow.h>
#include <vnet/udp/udp.h>
#include <vnet/crypto/crypto.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec.h>

#include <onp/drv/roc/base/roc_api.h>
#include <onp/drv/roc/base/roc_priv.h>
#include <onp/drv/roc/util.h>
#include <onp/drv/inc/log.h>

#ifdef VPP_PLATFORM_OCTEON9
#define CNXK_MARCH_PLATFORM CNXK_PLATFORM_CN9K
#elif VPP_PLATFORM_OCTEON10
#define CNXK_MARCH_PLATFORM CNXK_PLATFORM_CN10K
#endif

typedef enum
{
  CNXK_PKTIO_LINK_CGX,
  CNXK_PKTIO_LINK_LBK,
  CNXK_PKTIO_LINK_PCI,
} cnxk_pktio_link_type_t;

typedef enum
{
  CNXK_PLATFORM_CN9K,
  CNXK_PLATFORM_CN10K,
  CNXK_PLATFORM_INVALID
} cnxk_platform_type_t;

#define foreach_cnxk_pktio_mode_flag                                          \
  _ (UNUSED, 0)                                                               \
  _ (TRACE_EN, 1)

typedef enum
{
#define _(name, bit) CNXK_PKTIO_FP_FLAG_##name = (1 << bit),
  foreach_cnxk_pktio_mode_flag
#undef _
} cnxk_pktio_mode_flag_t;

#define CNXK_FRAME_SIZE		   VLIB_FRAME_SIZE
#define CNXK_FRAME_CAPACITY	   ((CNXK_FRAME_SIZE) *4)
#define CNXK_UNSUPPORTED_OPERATION ~(0)
#define CNXK_HW_COMMON_INST_SIZE   64
#define CNXK_PTD_HW_NEXT_INST(ptd, index, type)                               \
  ((type) ((ptd)->hw_inst + ((index) *CNXK_HW_COMMON_INST_SIZE)))

typedef struct
{
  u16 drop_next_node;
  u16 post_drop_next_node;
  struct
  {
    void *work;
    u32 work_source;
    i32 metadata_off;
  } debug;
} cnxk_ptd_ipsec_opaque_t;

typedef struct
{
  u32 feature_next_node;
} cnxk_ptd_pktio_opaque_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  /* 1st DWORD */
  u32 pktio_index;
  u32 flags;

  /* 2nd  DWORD */
  u32 out_flags;

  /* Out pkt/bytes from driver to plugin */
  u32 out_npkts;

  /* 3rd DWORD */
  u32 out_user_nstats;
  u16 pktio_node_state;
  u8 buffer_pool_index;
  u8 buffer_start_index;

  /* 4th DWORD */
  void *user_ptr;

  /* 5th DWORD for pktio_tx_send */
  u32 *tx_buffer_indices;

  /* 6-8th DWORD for buffer refill/deplete */
  i32 *refill_deplete_count_per_pool;
  i32 *default_refill_count_per_pool;
  i32 *default_deplete_count_per_pool;
  CLIB_ALIGN_MARK (c0_next64, 64);
  union
  {
    u64 opaque[8];

    /* Per thread IPsec specific data */
    cnxk_ptd_ipsec_opaque_t ipsec;

    cnxk_ptd_pktio_opaque_t pktio;
  };

  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  vlib_buffer_t *buffers[CNXK_FRAME_CAPACITY];

  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u16 next1[CNXK_FRAME_CAPACITY];

  CLIB_CACHE_LINE_ALIGN_MARK (c3);
  u16 next2[CNXK_FRAME_CAPACITY];

  CLIB_CACHE_LINE_ALIGN_MARK (c4);
  u32 second_buffer_indices[CNXK_FRAME_CAPACITY];

  CLIB_CACHE_LINE_ALIGN_MARK (c5);
  u8 hw_inst[CNXK_FRAME_CAPACITY * CNXK_HW_COMMON_INST_SIZE];

  CLIB_CACHE_LINE_ALIGN_MARK (c6);
  u32 buffer_indices[CNXK_FRAME_CAPACITY];

  vlib_buffer_t buffer_template;

} cnxk_per_thread_data_t;

void cnxk_drv_per_thread_data_init (cnxk_per_thread_data_t *ptd,
				    i16 pktpool_refill_deplete_sz,
				    i32 max_vlib_buffer_pools);

#endif /* included_onp_drv_inc_common_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
