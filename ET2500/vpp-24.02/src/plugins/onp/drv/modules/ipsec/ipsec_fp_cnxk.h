/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_ipsec_ipsec_fp_cnxk_h
#define included_onp_drv_modules_ipsec_ipsec_fp_cnxk_h

#include <onp/drv/inc/ipsec_fp_defs.h>
#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/modules/ipsec/ipsec_priv.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <onp/drv/inc/pool_fp.h>

static_always_inline void
cnxk_ipsec_sa_len_precalc (ipsec_sa_t *sa, cnxk_ipsec_encap_len_t *encap)
{
#if 0
  if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
    encap->partial_len = ROC_CPT_TUNNEL_IPV6_HDR_LEN;
  else
    encap->partial_len = ROC_CPT_TUNNEL_IPV4_HDR_LEN;

  if (sa->protocol == IPSEC_PROTOCOL_ESP)
    {
      encap->partial_len += ROC_CPT_ESP_HDR_LEN;
      encap->roundup_len = ROC_CPT_ESP_TRL_LEN;
      encap->footer_len = ROC_CPT_ESP_TRL_LEN;
    }
  else
    {
      encap->partial_len = ROC_CPT_AH_HDR_LEN;
    }

  encap->partial_len += sa->crypto_iv_size;
  encap->partial_len += sa->integ_icv_size;

  encap->roundup_byte = sa->esp_block_align;
  encap->icv_len = sa->integ_icv_size;
#endif
}

static_always_inline i32
cnxk_ipsec_rlen_get (cnxk_ipsec_encap_len_t *encap, uint32_t plen)
{
  uint32_t enc_payload_len;

  enc_payload_len =
    round_pow2 (plen + encap->roundup_len, encap->roundup_byte);

  return encap->partial_len + enc_payload_len;
}

static_always_inline int
cnxk_ipsec_sched_frame_alloc (vlib_main_t *vm, cnxk_crypto_dev_t *crypto_dev,
			      cnxk_crypto_queue_t *crypto_queue,
			      cnxk_sched_vec_header_t **vec)
{
  cnxk_ipsec_context_t *cic;

  cic = crypto_dev->cnxk_ipsec_context;
  if (!cnxk_drv_pool_alloc_inline (cic->cnxk_sched_vec_pool_index,
				   (void **) vec, 1))
    return -1;

  vec[0]->frame_size = 0;
  vec[0]->source_thread_index = vm->thread_index;
  vec[0]->pool_index = cic->cnxk_sched_vec_pool_index;
  return 0;
}

static_always_inline int
cnxk_ipsec_sched_frame_free (cnxk_crypto_dev_t *crypto_dev,
			     cnxk_crypto_queue_t *crypto_queue,
			     cnxk_sched_vec_header_t *vec)
{
  cnxk_ipsec_context_t *cic;

  cic = crypto_dev->cnxk_ipsec_context;
  return cnxk_drv_pool_free_inline (cic->cnxk_sched_vec_pool_index,
				    (void **) &vec, 1);
}

static_always_inline u32
cnxk_ipsec_sa_index_get (vlib_buffer_t *b, const int is_tun)
{
  u32 sa_index, adj_index;

  if (is_tun)
    {
      adj_index = vnet_buffer (b)->ip.adj_index[VLIB_TX];
      sa_index = ipsec_tun_protect_get_sa_out (adj_index);
      vnet_buffer (b)->ipsec.sad_index = sa_index;
    }
  else
    sa_index = vnet_buffer (b)->ipsec.sad_index;

  return sa_index;
}

static_always_inline u32
cnxk_ipsec_esp_add_footer_and_icv (cnxk_ipsec_encap_len_t *encap, u32 rlen)
{
  /* plain_text len + pad_bytes + ESP_footer size + icv_len */
  return rlen + encap->icv_len - encap->partial_len;
}

#endif /* included_onp_drv_modules_ipsec_ipsec_fp_cnxk_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
