/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_ipsec_ipsec_fp_cn10k_h
#define included_onp_drv_modules_ipsec_ipsec_fp_cn10k_h

#include <onp/drv/modules/ipsec/ipsec_fp_cnxk.h>

/* Copy size in units of 128 bits */
#define CPT_LMT_SIZE_COPY (sizeof (struct cpt_inst_s) / 16)
#define CN10K_MAX_LMT_SZ  16

/* TODO: Use different LMT line for CPT ops */
#define CN10K_CPT_LMT_GET_LINE_ADDR(lmt_addr, lmt_num)                        \
  (void *) ((u64) (lmt_addr) + ((u64) (lmt_num) << ROC_LMT_LINE_SIZE_LOG2))

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  union
  {
    /* Inbound SA */
    struct roc_ot_ipsec_inb_sa in_sa;
    /* Outbound SA */
    struct roc_ot_ipsec_outb_sa out_sa;
  };

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  /* CPT instruction template */
  struct cpt_inst_s inst;
  uint16_t max_extended_len;
  uint16_t iv_offset;
  uint8_t iv_length;
  /* Packet length for IPsec encapsulation */
  cnxk_ipsec_encap_len_t encap;
  bool is_lookaside;
  u32 itf_sw_idx;
  u32 vnet_sa_index;
} cn10k_ipsec_session_t;

i32 cn10k_ipsec_session_create (vlib_main_t *vm, uintptr_t ipsec_queue,
				u32 sa_index, u64 mode);

i32 cn10k_ipsec_session_destroy (vlib_main_t *vm, uintptr_t ipsec_queue,
				 u32 sa_index);

static_always_inline u32
cn10k_ipsec_sess_itf_idx_get (cnxk_ipsec_session_t *session)
{
  cn10k_ipsec_session_t *sess = session;

  return sess->itf_sw_idx;
}

static_always_inline void
cn10k_ipsec_sess_itf_idx_set (cnxk_ipsec_session_t *session, u32 itf_sw_index)
{
  cn10k_ipsec_session_t *sess = session;

  sess->itf_sw_idx = itf_sw_index;
}

static_always_inline u32
cn10k_ipsec_inl_get_spi (union cpt_res_s *res)
{
  return res->cn10k.spi;
}

static_always_inline u8
cn10k_ipsec_is_inl_op_success (union cpt_res_s *res)
{
  struct cpt_cn10k_res_s *res10k;

  res10k = &res->cn10k;
  return (((1U << res10k->compcode) & CPT_COMP_HWGOOD_MASK) &&
	  roc_ie_ot_ucc_is_success (res10k->uc_compcode));
}

static_always_inline u32
cn10k_ipsec_inl_get_uc_error_code (union cpt_res_s *res)
{
  return res->cn10k.uc_compcode;
}

static_always_inline u16
cn10k_ipsec_inl_get_rlen (union cpt_res_s *res)
{
  return res->cn10k.rlen;
}

#endif /* included_onp_drv_modules_ipsec_ipsec_fp_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
