/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_ipsec_h
#define included_onp_drv_inc_ipsec_h

#include <onp/drv/inc/common.h>
#include <onp/drv/inc/crypto.h>
#include <onp/drv/inc/ipsec_defs.h>

typedef struct
{
  cnxk_crypto_queue_config_t la_crypto_queue_config;
  cnxk_crypto_queue_config_t inl_ipsec_config;

  /* Number of CPT lfs for inline outbound */
  u16 inl_outb_nb_crypto_lf;

  /* Status of IPsec configured */
  u16 *ipsec_offloads_configured;

  /* Inline reassembly configurations */
  struct cnxk_reassembly_config_t
  {
    /* Max wait time in milli seconds for hardware reassembly */
    u32 inl_reassembly_max_wait_time_ms;

    /* Active reassembly entry limit */
    u16 inl_reassembly_active_limit;

    /* Active reassembly entry threshold */
    u16 inl_reassembly_active_thres;

    /* Zombie reassembly entry limit */
    u16 inl_reassembly_zombie_limit;

    /* Zomble reassembly entry threshold */
    u16 inl_reassembly_zombie_thres;
  } reassembly_config;

} cnxk_ipsec_config_t;

typedef struct
{
  /* Lookaside IPsec capability*/
  u64 ipsec_lookaside_supported : 1;

  /* Inline IPsec capability*/
  u64 ipsec_inl_inbound_supported : 1;
  u64 ipsec_inl_outbound_supported : 1;
} cnxk_ipsec_capability_t;

cnxk_ipsec_capability_t *cnxk_drv_ipsec_capability_get (vlib_main_t *vm);

i32 cnxk_drv_ipsec_init (vlib_main_t *vm, cnxk_ipsec_config_t *ic);

i32 cnxk_drv_ipsec_session_create (vlib_main_t *vm, uintptr_t ipsec_queue,
				   u32 sa_index, const u64 mode);

i32 cnxk_drv_ipsec_session_destroy (vlib_main_t *vm, uintptr_t ipsec_queue,
				    u32 sa_index);

i32 cnxk_drv_ipsec_session_reassembly_set (vlib_main_t *vm, u32 sa_index);

#define onp_ptd_ipsec(ptd) (&ptd->ipsec)

#endif /* included_onp_drv_inc_ipsec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
