/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_ipsec_fp_h
#define included_onp_drv_inc_ipsec_fp_h

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/inc/pktio_fp_defs.h>
#include <onp/drv/modules/ipsec/ipsec_fp_out_cn10k.h>
#include <onp/drv/modules/ipsec/ipsec_fp_in_cn10k.h>
#include <onp/drv/inc/ipsec_fp_defs.h>

static_always_inline u32
cnxk_drv_ipsec_encrypt_enqueue_march (
  vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame, uintptr_t q,
  cnxk_per_thread_data_t *ptd, const cnxk_ipsec_flag_op_t flags, u16 core_id)
{
  cnxk_crypto_queue_t *qp = (cnxk_crypto_queue_t *) q;

  ptd->user_ptr = cnxk_crypto_dev_get (qp->cnxk_crypto_index);
  ptd->out_user_nstats = 0;
  ptd->out_npkts = 0;

  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_enqueue_outbound (vm, node, frame, qp, ptd, flags,
					   core_id);
      break;
    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
      return 0;
    }
}

static_always_inline u32
cnxk_drv_ipsec_decrypt_enqueue_march (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame, uintptr_t q,
				      cnxk_per_thread_data_t *ptd,
				      const cnxk_ipsec_flag_op_t flags)
{
  cnxk_crypto_queue_t *qp = (cnxk_crypto_queue_t *) q;

  ptd->user_ptr = cnxk_crypto_dev_get (qp->cnxk_crypto_index);
  ptd->out_user_nstats = 0;
  ptd->out_npkts = 0;

  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_enqueue_inbound (vm, node, frame, qp, ptd, flags);
    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
      return 0;
    }
}

static_always_inline void
cnxk_drv_ipsec_get_enc_error_march (vlib_main_t *vm, vlib_node_runtime_t *node,
				    vlib_frame_t *frame,
				    cnxk_per_thread_data_t *ptd)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_ipsec_get_enc_errors (vm, node, frame, ptd);
      break;

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
}

static_always_inline void
cnxk_drv_ipsec_get_dec_error_march (vlib_main_t *vm, vlib_node_runtime_t *node,
				    vlib_frame_t *frame,
				    cnxk_per_thread_data_t *ptd)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_drv_ipsec_get_dec_errors (vm, node, frame, ptd);
      break;
    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
}

static_always_inline u32
cnxk_drv_ipsec_outbound_sort_march (vlib_main_t *vm, vlib_node_runtime_t *node,
				    vlib_frame_t *frame,
				    cnxk_per_thread_data_t *ptd,
				    const int is_ip6, const int is_tun)
{
#if 0

  ptd->out_npkts = 0;
  ptd->out_user_nstats = 0;

  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_outbound_sort (vm, node, frame, ptd, is_ip6, is_tun);

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
#endif
  return 0;
}

static_always_inline void
cnxk_drv_ipsec_outbound_prepare_inst (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame,
				      cnxk_per_thread_data_t *ptd, u16 core_id,
				      const int is_ipv6)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_outbound_prepare_inst (vm, node, frame, ptd, core_id,
						is_ipv6);

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
}

static_always_inline u32
cnxk_drv_ipsec_session_get_itf_index_march (cnxk_ipsec_session_t *session)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_sess_itf_idx_get (session);

    default:
      clib_error ("ITF based inline inbound IPsec is only supported "
		  "on CN10K");
    }
  return 0;
}

static_always_inline void
cnxk_drv_ipsec_session_set_itf_index_march (cnxk_ipsec_session_t *session,
					    u32 itf_sw_index)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_ipsec_sess_itf_idx_set (session, itf_sw_index);
      break;

    default:
      clib_error ("ITF based inline inbound IPsec is only supported "
		  "on CN10K");
    }
}

static_always_inline u32
cnxk_drv_ipsec_inl_get_spi_march (union cpt_res_s *res)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_inl_get_spi (res);

    default:
      clib_error ("Inline inbound IPsec is only supported "
		  "on CN10K");
    }
  return -1;
}

static_always_inline u32
cnxk_drv_ipsec_is_inl_op_success_march (union cpt_res_s *res)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_is_inl_op_success (res);

    default:
      clib_error ("Inline inbound IPsec is only supported "
		  "on CN10K");
    }
  /* Default is failure */
  return 0;
}

static_always_inline u32
cnxk_drv_ipsec_inl_get_error_march (union cpt_res_s *res)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      switch (res->cn10k.uc_compcode)
	{
	  /* clang-format off */
#define _(e, s)                                                               \
    case ROC_IE_OT_UCC_##e:                                                   \
      return ONP_ESP_ENCRYPT_CN10K_ERROR_##e;                                 \
    foreach_onp_drv_cn10k_ipsec_ucc;
#undef _
	  /* clang-format on */
	}
    default:
      clib_error ("Inline inbound IPsec is only supported "
		  "on CN10K");
    }
  return 0;
}
static_always_inline u32
cnxk_drv_ipsec_inl_get_uc_error_code_march (union cpt_res_s *res)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_inl_get_uc_error_code (res);

    default:
      clib_error ("Inline inbound IPsec is only supported "
		  "on CN10K");
    }
  /* Default uc error is 0(None) */
  return 0;
}

static_always_inline u32
cnxk_drv_ipsec_inl_get_rlen_march (union cpt_res_s *res)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_ipsec_inl_get_rlen (res);

    default:
      clib_error ("Inline inbound IPsec is only supported "
		  "on CN10K");
    }
  /* Default rlen is 0 */
  return 0;
}

static_always_inline void
cnxk_drv_pkt_process_and_enq_to_next_march (vlib_main_t *vm,
					    vlib_node_runtime_t *node,
					    cnxk_per_thread_data_t *ptd,
					    u32 cnt, u32 next_index,
					    u8 *is_single_next)
{
  u32 nxt[] = { next_index, VNET_DEVICE_INPUT_NEXT_DROP };
  vlib_buffer_t **b = ptd->buffers;
  u32 i, idx;

  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      for (i = 0; i < cnt; i++)
	{
	  idx = cnxk_ipsec_inl_data (b[i])->is_ipsec_op_fail;
	  ptd->next1[i] = nxt[idx];

	  if (ptd->next1[i] == VNET_DEVICE_INPUT_NEXT_DROP)
	    *is_single_next = 0;
	}
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->buffers,
					   ptd->buffer_indices, cnt, 0);
      vlib_buffer_enqueue_to_next (vm, node, ptd->buffer_indices, ptd->next1,
				   cnt);
      break;

    default:
      vlib_get_buffer_indices_with_offset (vm, (void **) ptd->buffers,
					   ptd->buffer_indices, cnt, 0);
      vlib_buffer_enqueue_to_single_next (vm, node, ptd->buffer_indices,
					  next_index, cnt);
    }
}

static_always_inline u32
cnxk_ipsec_update_itf_sw_idx (cnxk_ipsec_session_t *session, u32 sa_idx)
{
  clib_bihash_kv_24_16_t bkey60 = { 0 };
  clib_bihash_kv_8_16_t bkey40 = { 0 };
  ipsec_tun_lkup_result_t *res;
  ipsec4_tunnel_kv_t *key40;
  ipsec6_tunnel_kv_t *key60;
  ip_address_t *ip_addr;
  ipsec_main_t *ipm;
  u32 sw_if_index;
  ipsec_sa_t *sa;
  i32 rv;

  sa = ipsec_sa_get (sa_idx);
  ASSERT (sa);

  ipm = &ipsec_main;
  ip_addr = &sa->tunnel.t_src;

  if (AF_IP4 == ip_addr->version)
    {
      key40 = (ipsec4_tunnel_kv_t *) &bkey40;
      ipsec4_tunnel_mk_key (key40, &ip_addr->ip.ip4,
			    clib_host_to_net_u32 (sa->spi));
      rv = clib_bihash_search_inline_8_16 (&ipm->tun4_protect_by_key, &bkey40);
      ASSERT (!rv);

      res = (ipsec_tun_lkup_result_t *) &bkey40.value;
    }
  else
    {

      key60 = (ipsec6_tunnel_kv_t *) &bkey60;
      key60->key.remote_ip = ip_addr->ip.ip6;
      key60->key.spi = clib_host_to_net_u32 (sa->spi);
      key60->key.__pad = 0;

      rv =
	clib_bihash_search_inline_24_16 (&ipm->tun6_protect_by_key, &bkey60);
      ASSERT (!rv);

      res = (ipsec_tun_lkup_result_t *) &bkey60.value;
    }

  sw_if_index = res->sw_if_index;
  /* Store the ITF sw_if_index in the SA session to avoid duplicate
     lookups for each packet */
  cnxk_drv_ipsec_session_set_itf_index_march (session, sw_if_index);
  return sw_if_index;
}

static_always_inline void
cnxk_ipsec_update_sa_counters_x4 (vlib_main_t *vm, cnxk_pktio_main_t *pm,
				  vlib_buffer_t *b0, vlib_buffer_t *b1,
				  vlib_buffer_t *b2, vlib_buffer_t *b3,
				  u32 ilen, u8 frag_cnt, u32 cnxk_sa_idx)
{
  vlib_combined_counter_main_t *rx_counter;
  ipsec_main_t *im = &ipsec_main;
  cnxk_ipsec_session_t *session;
  cnxk_ipsec_inb_sa_t *cnxk_sas;
  vnet_interface_main_t *vim;
  cnxk_ipsec_main_t *cipsm;
  u32 sa_idx, itf_sw_idx;
  vnet_main_t *vnm;

  cnxk_sas = (cnxk_ipsec_inb_sa_t *) pm->inl_dev.inb_sa_base;
  cipsm = CNXK_IPSEC_GET_MAIN ();
  vnm = im->vnet_main;
  vim = &vnm->interface_main;
  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;

  sa_idx = (u32) cnxk_sas[cnxk_sa_idx].user_data;
  vnet_buffer (b0)->ipsec.sad_index = sa_idx;
  vnet_buffer (b1)->ipsec.sad_index = sa_idx;
  vnet_buffer (b2)->ipsec.sad_index = sa_idx;
  vnet_buffer (b3)->ipsec.sad_index = sa_idx;

  ASSERT (sa_idx < vec_len (cipsm->inline_ipsec_sessions));

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx);
  itf_sw_idx = cnxk_drv_ipsec_session_get_itf_index_march (session);
  /*
   * Check if itf_sw_idx is populated already. First packet on the SA
   * populates the itf_sw_idx in the SA session
   */
  if (PREDICT_FALSE (itf_sw_idx == ~0))
    itf_sw_idx = cnxk_ipsec_update_itf_sw_idx (session, sa_idx);

  /* Update IPsec counters with inner IP length */
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx, frag_cnt, ilen);

  /* Update ITF counters with inner IP length */
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx,
				   frag_cnt, ilen);
}

static_always_inline void
cnxk_ipsec_update_counters_x4 (vlib_main_t *vm, union cpt_res_s *res0,
			       vlib_buffer_t *b0, u32 ilen0, u8 frag_cnt0,
			       union cpt_res_s *res1, vlib_buffer_t *b1,
			       u32 ilen1, u8 frag_cnt1, union cpt_res_s *res2,
			       vlib_buffer_t *b2, u32 ilen2, u8 frag_cnt2,
			       union cpt_res_s *res3, vlib_buffer_t *b3,
			       u32 ilen3, u8 frag_cnt3)
{
  vlib_combined_counter_main_t *rx_counter;
  u32 idx0, idx1, idx2, idx3, spi_mask;
  ipsec_main_t *im = &ipsec_main;
  cnxk_ipsec_session_t *session;
  cnxk_ipsec_inb_sa_t *cnxk_sas;
  vnet_interface_main_t *vim;
  cnxk_ipsec_main_t *cipsm;
  u32 sa_idx0, itf_sw_idx0;
  u32 sa_idx1, itf_sw_idx1;
  u32 sa_idx2, itf_sw_idx2;
  u32 sa_idx3, itf_sw_idx3;
  cnxk_pktio_main_t *pm;
  vnet_main_t *vnm;
  u32 idx_xor;

  pm = cnxk_pktio_get_main ();
  spi_mask = pm->inl_dev.inb_spi_mask;

  idx0 = spi_mask & cnxk_drv_ipsec_inl_get_spi_march (res0);
  idx1 = spi_mask & cnxk_drv_ipsec_inl_get_spi_march (res1);
  idx2 = spi_mask & cnxk_drv_ipsec_inl_get_spi_march (res2);
  idx3 = spi_mask & cnxk_drv_ipsec_inl_get_spi_march (res3);

  idx_xor = idx0 ^ idx1;
  idx_xor += idx1 ^ idx2;
  idx_xor += idx2 ^ idx3;

  if (!idx_xor)
    {
      cnxk_ipsec_update_sa_counters_x4 (
	vm, pm, b0, b1, b2, b3, ilen0 + ilen1 + ilen2 + ilen3,
	frag_cnt0 + frag_cnt1 + frag_cnt2 + frag_cnt3, idx0);
      return;
    }

  cnxk_sas = (cnxk_ipsec_inb_sa_t *) pm->inl_dev.inb_sa_base;
  cipsm = CNXK_IPSEC_GET_MAIN ();
  vnm = im->vnet_main;
  vim = &vnm->interface_main;
  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;

  sa_idx0 = (u32) cnxk_sas[idx0].user_data;
  vnet_buffer (b0)->ipsec.sad_index = sa_idx0;

  sa_idx1 = (u32) cnxk_sas[idx1].user_data;
  vnet_buffer (b1)->ipsec.sad_index = sa_idx1;

  sa_idx2 = (u32) cnxk_sas[idx2].user_data;
  vnet_buffer (b2)->ipsec.sad_index = sa_idx2;

  sa_idx3 = (u32) cnxk_sas[idx3].user_data;
  vnet_buffer (b3)->ipsec.sad_index = sa_idx3;

  ASSERT (sa_idx0 < vec_len (cipsm->inline_ipsec_sessions));
  ASSERT (sa_idx1 < vec_len (cipsm->inline_ipsec_sessions));
  ASSERT (sa_idx2 < vec_len (cipsm->inline_ipsec_sessions));
  ASSERT (sa_idx3 < vec_len (cipsm->inline_ipsec_sessions));

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx0);
  itf_sw_idx0 = cnxk_drv_ipsec_session_get_itf_index_march (session);
  /* Check if itf_sw_idx is populated already. First packet on the SA
     populates the itf_sw_idx in the SA session */
  if (PREDICT_FALSE (itf_sw_idx0 == ~0))
    itf_sw_idx0 = cnxk_ipsec_update_itf_sw_idx (session, sa_idx0);

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx1);
  itf_sw_idx1 = cnxk_drv_ipsec_session_get_itf_index_march (session);
  if (PREDICT_FALSE (itf_sw_idx1 == ~0))
    itf_sw_idx1 = cnxk_ipsec_update_itf_sw_idx (session, sa_idx1);

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx2);
  itf_sw_idx2 = cnxk_drv_ipsec_session_get_itf_index_march (session);
  if (PREDICT_FALSE (itf_sw_idx2 == ~0))
    itf_sw_idx2 = cnxk_ipsec_update_itf_sw_idx (session, sa_idx2);

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx3);
  itf_sw_idx3 = cnxk_drv_ipsec_session_get_itf_index_march (session);
  if (PREDICT_FALSE (itf_sw_idx3 == ~0))
    itf_sw_idx3 = cnxk_ipsec_update_itf_sw_idx (session, sa_idx3);

  /* Update IPsec counters with outer IP length */
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx0, frag_cnt0, ilen0);
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx1, frag_cnt1, ilen1);
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx2, frag_cnt2, ilen2);
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx3, frag_cnt3, ilen3);

  /* Update ITF counters with inner IP length */
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx0,
				   frag_cnt0, ilen0);
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx1,
				   frag_cnt1, ilen1);
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx2,
				   frag_cnt2, ilen2);
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx3,
				   frag_cnt3, ilen3);
}

static_always_inline void
cnxk_ipsec_update_counters (vlib_main_t *vm, union cpt_res_s *res,
			    vlib_buffer_t *b, u32 ilen, u8 frag_cnt)
{
  vlib_combined_counter_main_t *rx_counter;
  ipsec_main_t *im = &ipsec_main;
  cnxk_ipsec_inb_sa_t *cnxk_sas;
  cnxk_ipsec_session_t *session;
  u32 sa_idx, idx, itf_sw_idx;
  vnet_interface_main_t *vim;
  cnxk_ipsec_main_t *cipsm;
  cnxk_pktio_main_t *pm;
  vnet_main_t *vnm;

  pm = cnxk_pktio_get_main ();
  cipsm = CNXK_IPSEC_GET_MAIN ();
  vnm = im->vnet_main;
  vim = &vnm->interface_main;
  rx_counter = vim->combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX;

  idx = pm->inl_dev.inb_spi_mask & cnxk_drv_ipsec_inl_get_spi_march (res);
  cnxk_sas = (cnxk_ipsec_inb_sa_t *) (pm->inl_dev.inb_sa_base);
  sa_idx = vnet_buffer (b)->ipsec.sad_index = (u32) cnxk_sas[idx].user_data;
  ASSERT (sa_idx < vec_len (cipsm->inline_ipsec_sessions));

  session = vec_elt (cipsm->inline_ipsec_sessions, sa_idx);
  itf_sw_idx = cnxk_drv_ipsec_session_get_itf_index_march (session);
  /*
   * Check if itf_sw_idx is populated already. First packet on the SA
   * populates the itf_sw_idx in the SA session.
   */
  if (PREDICT_FALSE (itf_sw_idx == ~0))
    itf_sw_idx = cnxk_ipsec_update_itf_sw_idx (session, sa_idx);

  /* Update IPsec counters with inner IP length */
  vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				   sa_idx, frag_cnt, ilen);

  /* Update ITF counters with inner IP length */
  vlib_increment_combined_counter (rx_counter, vm->thread_index, itf_sw_idx,
				   frag_cnt, ilen);
}

#endif /* included_onp_drv_inc_ipsec_fp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
