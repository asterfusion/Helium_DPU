/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */
#ifndef included_onp_drv_modules_ipsec_ipsec_priv_h
#define included_onp_drv_modules_ipsec_ipsec_priv_h

#include <onp/drv/roc/base/roc_api.h>
#include <onp/drv/roc/platform.h>
#include <onp/drv/inc/sched.h>
#include <onp/drv/inc/ipsec.h>

#define CNXK_IPSEC_COMMAND_TIMEOUT 4
#define CNXK_MAX_TOTAL_IPSEC_SA	   3600
/* Should be part of ROC */
#define CNXK_ROC_SALT_LEN 4

#define CNXK_IPSEC_MAX_SESSION CNXK_MAX_TOTAL_IPSEC_SA

typedef void cnxk_ipsec_session_t;

typedef struct cnxk_drv_ipsec_ops
{
  i32 (*cnxk_ipsec_session_create) (vlib_main_t *vm, uintptr_t ipsec_queue,
				    u32 sa_index, u64 mode);
  i32 (*cnxk_ipsec_session_destroy) (vlib_main_t *vm, uintptr_t ipsec_queue,
				     u32 sa_index);
  i32 (*cnxk_ipsec_lookaside_setup) (vlib_main_t *vm, cnxk_ipsec_config_t *ic);
  i32 (*cnxk_ipsec_inline_setup) (vlib_main_t *vm, cnxk_ipsec_config_t *ic);
} cnxk_ipsec_ops_t;

extern const cnxk_ipsec_ops_t ipsec_10k_ops;

typedef struct
{
  uint8_t partial_len;
  uint8_t roundup_len;
  uint8_t footer_len;
  uint8_t roundup_byte;
  uint8_t icv_len;
} cnxk_ipsec_encap_len_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  cnxk_sched_vec_header_t *ipsec_pool;

  u32 cnxk_sched_vec_pool_index;
  u16 cnxk_crypto_index;
  u16 cnxk_crypto_queue_index;

} cnxk_ipsec_context_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  union
  {
    cnxk_ipsec_session_t **inline_ipsec_sessions;
    cnxk_ipsec_session_t **lookaside_ipsec_sessions;
  };

  /* IPsec operations */
  const cnxk_ipsec_ops_t *ipsec_ops;

  /* IPsec capability */
  cnxk_ipsec_capability_t ipsec_capa;

  /* IPsec offload configuration status*/
  u16 ipsec_offloads;
} cnxk_ipsec_main_t;

#define CNXK_IPSEC_GET_MAIN() &(cnxk_ipsec_main)

extern cnxk_ipsec_main_t cnxk_ipsec_main;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  struct roc_ot_ipsec_inb_sa roc_sa;
  uint64_t rsvd[11];

  CLIB_CACHE_LINE_ALIGN_MARK (cnxk_sw_area);
  u64 user_data;
  u8 is_inline;
} cnxk_ipsec_inb_sa_t;

#endif /* included_onp_drv_modules_ipsec_ipsec_priv_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
