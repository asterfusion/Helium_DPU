/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_ipsec_ipsec_fp_out_cn10k_h
#define included_onp_drv_modules_ipsec_ipsec_fp_out_cn10k_h

#include <onp/drv/inc/ipsec_defs.h>
#include <onp/drv/modules/ipsec/ipsec_fp_cn10k.h>
#include <onp/drv/modules/sched/sched_fp_cn10k.h>

/*
 * Encoded number of segments to number of dwords macro,
 * each value of nb_segs is encoded as 4bits.
 */
#define NIX_SEGDW_MAGIC		0x76654432210ULL
#define NIX_NB_SEGS_TO_SEGDW(x) ((NIX_SEGDW_MAGIC >> ((x) << 2)) & 0xF)

static_always_inline void
cn10k_ipsec_append_next_buffer (vlib_main_t *vm, vlib_buffer_t *buffer,
				uint16_t bytes_to_append)
{
  u32 buffer_index = 0;
  vlib_buffer_t *tmp;

  if (vlib_buffer_alloc (vm, &buffer_index, 1) != 1)
    {
      clib_warning ("buffer allocation failure");
      return;
    }

  tmp = vlib_get_buffer (vm, buffer_index);
  buffer->next_buffer = buffer_index;
  buffer->flags |= VLIB_BUFFER_NEXT_PRESENT;
  tmp->current_length += bytes_to_append;
}

static_always_inline uint32_t
cn10k_ipsec_fill_sg_buf (vlib_main_t *vm, struct roc_sglist_comp *list,
			 uint32_t i, u64 addr, u16 length, vlib_buffer_t **lb)
{
  struct roc_sglist_comp *to;

  to = &list[i >> 2];
  to->u.s.len[i % 4] = clib_net_to_host_u16 (length);
  to->ptr[i % 4] = clib_net_to_host_u64 (addr);
  i++;

  while (lb[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      to = &list[i >> 2];
      lb[0] = vlib_get_buffer (vm, lb[0]->next_buffer);
      to->ptr[i % 4] =
	clib_net_to_host_u64 ((u64) vlib_buffer_get_current (lb[0]));
      to->u.s.len[i % 4] = clib_net_to_host_u16 (lb[0]->current_length);

      i++;
    }

  return i;
}

static_always_inline int
cn10k_ipsec_outb_prepare_sg_list (vlib_main_t *vm, vlib_buffer_t *b,
				  struct cpt_inst_s *inst, u32 bytes_to_append,
				  u16 l2_hdr_sz, void *m_data)
{
  u64 first_seg_addr = (u64) (vlib_buffer_get_current (b) + l2_hdr_sz);
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 first_seg_len = b->current_length - l2_hdr_sz, dlen;
  struct roc_sglist_comp *scatter_comp, *gather_comp;
  u32 g_size_bytes, s_size_bytes;
  vlib_buffer_t *last_buf = b;
  u8 *in_buffer;
  int i;

  in_buffer = m_data;

  ((uint16_t *) in_buffer)[0] = 0;
  ((uint16_t *) in_buffer)[1] = 0;

  /* Input Gather List */
  i = 0;
  gather_comp = (struct roc_sglist_comp *) ((uint8_t *) m_data + 8);

  i = cn10k_ipsec_fill_sg_buf (vm, gather_comp, i, first_seg_addr,
			       first_seg_len, &last_buf);

  ((uint16_t *) in_buffer)[2] = clib_net_to_host_u16 (i);

  g_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  /* Output Scatter List */
  i = 0;
  scatter_comp =
    (struct roc_sglist_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  if ((bytes_to_append + last_buf->current_length) > buffer_data_size)
    /* Need an extra buffer */
    cn10k_ipsec_append_next_buffer (vm, last_buf, bytes_to_append);
  else
    vlib_buffer_put_uninit (last_buf, bytes_to_append);

  last_buf = b;

  i = cn10k_ipsec_fill_sg_buf (vm, scatter_comp, i, first_seg_addr,
			       first_seg_len, &last_buf);

  ((uint16_t *) in_buffer)[3] = clib_net_to_host_u16 (i);

  s_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  dlen = g_size_bytes + s_size_bytes + ROC_SG_LIST_HDR_SIZE;

  inst->dptr = (uint64_t) in_buffer;
  inst->rptr = inst->dptr;
  inst->w4.s.dlen = dlen;
  inst->w4.s.opcode_major |= (uint64_t) ROC_DMA_MODE_SG;

  b->total_length_not_including_first_buffer += bytes_to_append;

  return i;
}

static_always_inline uint32_t
cn10k_ipsec_fill_sg2_buf (vlib_main_t *vm, struct roc_sg2list_comp *list,
			  int i, vlib_buffer_t **lb)
{
  struct roc_sg2list_comp *to;

  to = &list[i / 3];
  to->u.s.len[i % 3] = lb[0]->current_length;
  to->ptr[i % 3] = (u64) vlib_buffer_get_current (lb[0]);
  to->u.s.valid_segs = (i % 3) + 1;
  i++;

  while (lb[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      to = &list[i / 3];
      lb[0] = vlib_get_buffer (vm, lb[0]->next_buffer);
      to->ptr[i % 3] = (u64) vlib_buffer_get_current (lb[0]);
      to->u.s.len[i % 3] = lb[0]->current_length;
      to->u.s.valid_segs = (i % 3) + 1;
      i++;
    }

  return i;
}

static_always_inline int
cn10k_ipsec_outb_prepare_sg2_list (vlib_main_t *vm, vlib_buffer_t *b,
				   struct cpt_inst_s *inst,
				   u32 bytes_to_append, u32 dlen, void *m_data)
{
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  struct roc_sg2list_comp *scatter_comp, *gather_comp;
  union cpt_inst_w5 cpt_inst_w5;
  union cpt_inst_w6 cpt_inst_w6;
  vlib_buffer_t *last_buf = b;
  u32 g_size_bytes;
  int i;

  /* Input Gather List */
  i = 0;
  gather_comp = (struct roc_sg2list_comp *) ((uint8_t *) m_data);

  i = cn10k_ipsec_fill_sg2_buf (vm, gather_comp, i, &last_buf);

  cpt_inst_w5.s.gather_sz = ((i + 2) / 3);
  g_size_bytes = ((i + 2) / 3) * sizeof (struct roc_sg2list_comp);

  if ((bytes_to_append + last_buf->current_length) > buffer_data_size)
    {
      /* Need an extra buffer */
      cn10k_ipsec_append_next_buffer (vm, last_buf, bytes_to_append);
    }
  else
    {
      vlib_buffer_put_uninit (last_buf, bytes_to_append);
    }

  last_buf = b;

  /* Output Gather List */
  i = 0;
  scatter_comp =
    (struct roc_sg2list_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  i = cn10k_ipsec_fill_sg2_buf (vm, scatter_comp, i, &last_buf);

  cpt_inst_w6.s.scatter_sz = ((i + 2) / 3);
  cpt_inst_w5.s.dptr = (uint64_t) gather_comp;

  cpt_inst_w6.s.rptr = (uint64_t) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;
  inst->w4.s.dlen = dlen;
  inst->w4.s.opcode_major &= (~(ROC_IE_OT_INPLACE_BIT));

  b->total_length_not_including_first_buffer += bytes_to_append;

  return i;
}

static_always_inline void
cn10k_ipsec_outbound_prepare_inst (vlib_main_t *vm, vlib_node_runtime_t *node,
				   vlib_frame_t *f,
				   cnxk_per_thread_data_t *ptd, u16 core_id,
				   const int is_ipv6)
{
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 sa_index, current_sa_index = ~0, rlen, pkt_len;
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cn10k_ipsec_outbound_pkt_meta_t *meta;
  cn10k_ipsec_session_t *sess = NULL;
  bool nix_inl_ipsec_mseg_capable;
  u32 n_left = f->n_vectors;
  vlib_buffer_t **b;
  u16 sa_bytes;
  u64 dptr;

  b = ptd->buffers;

  nix_inl_ipsec_mseg_capable = roc_feature_nix_has_inl_ipsec_mseg ();

  while (n_left > 0)
    {
      sa_index = vnet_buffer (b[0])->ipsec.sad_index;
      if (sa_index != current_sa_index)
	{
	  sess = vec_elt (im->inline_ipsec_sessions, sa_index);
	  current_sa_index = sa_index;
	  ALWAYS_ASSERT (current_sa_index <
			 vec_len (im->inline_ipsec_sessions));
	}

      b[0]->flags |= CNXK_VNET_BUFFER_OFFLOAD_F_IPSEC_OUTBOUND_INLINE;
      vnet_buffer (b[0])->ipsec.sad_index = current_sa_index;

      /*
       * External header buffer is used to store
       * the cn10k_ipsec_outbound_pkt_meta_t
       */

      meta = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[0]);

      clib_memset (meta, 0, sizeof (cn10k_ipsec_outbound_pkt_meta_t));

      meta->res.cn10k.compcode = CPT_COMP_NOT_DONE;

      pkt_len = b[0]->current_length;
      rlen = cnxk_ipsec_rlen_get (&sess->encap, pkt_len);
      meta->core_id = core_id;

      if (is_ipv6)
	meta->ip_ver = 6;
      else
	meta->ip_ver = 4;

      /* Populate CPT instruction template */
      meta->inst.res_addr = (u64) &meta->res;
      meta->inst.w2.u64 = sess->inst.w2.u64;
      /* WQE must be aligned on an 64-bit / 8 byte boundary */
      ASSERT (((uintptr_t) b[0] & 0x7ULL) == 0);
      meta->inst.w3.u64 = (uintptr_t) b[0];
      /* Enable queue ordering */
      meta->inst.w3.u64 |= 0x1ULL;

      if ((b[0]->flags & VLIB_BUFFER_NEXT_PRESENT) ||
	  (rlen > buffer_data_size))
	{
	  u16 total_length;
	  total_length = b[0]->current_length +
			 b[0]->total_length_not_including_first_buffer;
	  rlen = cnxk_ipsec_rlen_get (&sess->encap, total_length);
	  sa_bytes = cnxk_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
	  meta->sa_bytes = sa_bytes;

	  meta->dlen_adj = rlen - total_length;
	  meta->is_sg_mode = 1;
	  meta->inst.w4.u64 = sess->inst.w4.u64;
	}
      else
	{
	  dptr = (u64) vlib_buffer_get_current (b[0]);
	  sa_bytes = cnxk_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
	  meta->sa_bytes = sa_bytes;
	  meta->dlen_adj = rlen - pkt_len;

	  /* Set w0 nixtx_offset */
	  if (nix_inl_ipsec_mseg_capable)
	    meta->inst.w0.u64 |=
	      (((int64_t) meta->nixtx - (int64_t) dptr) & 0xFFFFF) << 32;
	  else
	    meta->inst.w0.u64 = (uintptr_t) meta->nixtx;

	  /*
	   * Set nixtx length to 2 dwords.
	   * NIXTXL + 1 represents the length in dwords
	   */
	  meta->inst.w0.u64 |= 1;
	  meta->inst.w4.u64 = sess->inst.w4.u64 | pkt_len;
	  meta->inst.dptr = dptr;
	  meta->inst.rptr = dptr;
	}

      meta->inst.w7.u64 = sess->inst.w7.u64;

      b++;
      n_left--;
    }
}

static_always_inline void
cn10k_ipsec_outbound_lka_prepare_inst (vlib_main_t *vm, vlib_buffer_t *b,
				       cn10k_ipsec_session_t *sess,
				       struct cpt_inst_s *inst, u16 next_index,
				       const bool is_b0_or_103)
{
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  onp_esp_post_data_t *enc_post = onp_esp_post_data (b);
  cn10k_ipsec_outbound_pkt_meta_t *meta;
  u32 pkt_len, rlen, dlen_adj = 0;
  u16 total_length;
  u64 dptr;

  /*
   * Save next node in vlib buffer opaque,
   * this will be used in post encrypt node
   */
  enc_post->next_index = next_index;

  meta =
    (cn10k_ipsec_outbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (
      b);

  clib_memset (meta, 0, sizeof (cn10k_ipsec_outbound_pkt_meta_t));

  /* Make sure we reset the done bit */
  meta->res.cn10k.compcode = CPT_COMP_NOT_DONE;

  pkt_len = b->current_length;
  rlen = cnxk_ipsec_rlen_get (&sess->encap, pkt_len);

  if ((b->flags & VLIB_BUFFER_NEXT_PRESENT) || (rlen > buffer_data_size))
    {
      total_length =
	b->current_length + b->total_length_not_including_first_buffer;
      rlen = cnxk_ipsec_rlen_get (&sess->encap, total_length);
      meta->sa_bytes = cnxk_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);
      u32 bytes_append = rlen - total_length;

      inst->w4.u64 = sess->inst.w4.u64;

      memset (meta->sg_buffer, 0, sizeof (meta->sg_buffer));

      if (is_b0_or_103)
	cn10k_ipsec_outb_prepare_sg2_list (
	  vm, b, inst, bytes_append, total_length, (void *) meta->sg_buffer);
      else
	cn10k_ipsec_outb_prepare_sg_list (vm, b, inst, bytes_append, 0,
					  (void *) meta->sg_buffer);
    }
  else
    {
      dptr = (u64) vlib_buffer_get_current (b);
      meta->sa_bytes = cnxk_ipsec_esp_add_footer_and_icv (&sess->encap, rlen);

      dlen_adj = rlen - pkt_len;

      /* Update vlib buffer length */
      b->current_length += dlen_adj;
      inst->w4.u64 = sess->inst.w4.u64 | pkt_len;
      inst->dptr = dptr;
      inst->rptr = dptr;
    }

  /* Fill CPT result in inst: w1 */
  inst->res_addr = (u64) &meta->res;

  /* Enable queue ordering */
  inst->w3.s.qord = 1;

  inst->w7.u64 = sess->inst.w7.u64;
  onp_esp_post_data2 (b)->res_ptr = (u64 *) &meta->res;

}

static_always_inline void
cn10k_ipsec_outbound_lka_prepare_inst_x2 (
  vlib_main_t *vm, vlib_buffer_t *b0, cn10k_ipsec_session_t *sess0,
  struct cpt_inst_s *inst0, vlib_buffer_t *b1, cn10k_ipsec_session_t *sess1,
  struct cpt_inst_s *inst1, u16 next_index, const bool is_b0_or_103)
{
  u32 total_length0, total_length1, bytes_append0, bytes_append1, or_flags;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (vm);
  u32 pkt_len0, rlen0, dlen_adj0, pkt_len1, rlen1, dlen_adj1;
  cn10k_ipsec_outbound_pkt_meta_t *meta0, *meta1;
  onp_esp_post_data_t *enc_post0, *enc_post1;
  u64 dptr0, dptr1;

  /*
   * Save next node in vlib buffer opaque,
   * this will be used in post encrypt node
   */
  enc_post0 = onp_esp_post_data (b0);
  enc_post1 = onp_esp_post_data (b1);

  enc_post0->next_index = next_index;
  enc_post1->next_index = next_index;

  meta0 =
    (cn10k_ipsec_outbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (
      b0);
  meta1 =
    (cn10k_ipsec_outbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (
      b1);

  meta0->res.cn10k.compcode = CPT_COMP_NOT_DONE;
  meta1->res.cn10k.compcode = CPT_COMP_NOT_DONE;

  pkt_len0 = b0->current_length;
  pkt_len1 = b1->current_length;

  rlen0 = cnxk_ipsec_rlen_get (&sess0->encap, pkt_len0);
  rlen1 = cnxk_ipsec_rlen_get (&sess1->encap, pkt_len1);

  inst0->res_addr = (u64) &meta0->res;
  inst1->res_addr = (u64) &meta1->res;

  /* Enable queue ordering */
  inst0->w3.s.qord = 1;
  inst1->w3.s.qord = 1;

  or_flags = b0->flags | b1->flags;

  if ((or_flags & VLIB_BUFFER_NEXT_PRESENT) || (rlen0 > buffer_data_size) ||
      (rlen1 > buffer_data_size))
    {
      total_length0 =
	b0->current_length + b0->total_length_not_including_first_buffer;
      total_length1 =
	b1->current_length + b1->total_length_not_including_first_buffer;

      rlen0 = cnxk_ipsec_rlen_get (&sess0->encap, total_length0);
      rlen1 = cnxk_ipsec_rlen_get (&sess1->encap, total_length1);

      meta0->sa_bytes =
	cnxk_ipsec_esp_add_footer_and_icv (&sess0->encap, rlen0);
      meta1->sa_bytes =
	cnxk_ipsec_esp_add_footer_and_icv (&sess1->encap, rlen1);

      bytes_append0 = rlen0 - total_length0;
      bytes_append1 = rlen1 - total_length1;

      inst0->w4.u64 = sess0->inst.w4.u64;
      inst1->w4.u64 = sess1->inst.w4.u64;

      memset (meta0->sg_buffer, 0, sizeof (meta0->sg_buffer));
      memset (meta1->sg_buffer, 0, sizeof (meta1->sg_buffer));

      if (is_b0_or_103)
	{
	  cn10k_ipsec_outb_prepare_sg2_list (vm, b0, inst0, bytes_append0,
					     total_length0,
					     (void *) meta0->sg_buffer);
	  cn10k_ipsec_outb_prepare_sg2_list (vm, b1, inst1, bytes_append1,
					     total_length1,
					     (void *) meta1->sg_buffer);
	}
      else
	{
	  cn10k_ipsec_outb_prepare_sg_list (vm, b0, inst0, bytes_append0, 0,
					    (void *) meta0->sg_buffer);
	  cn10k_ipsec_outb_prepare_sg_list (vm, b1, inst1, bytes_append1, 0,
					    (void *) meta1->sg_buffer);
	}
    }
  else
    {
      dptr0 = (u64) vlib_buffer_get_current (b0);
      dptr1 = (u64) vlib_buffer_get_current (b1);

      meta0->sa_bytes =
	cnxk_ipsec_esp_add_footer_and_icv (&sess0->encap, rlen0);
      meta1->sa_bytes =
	cnxk_ipsec_esp_add_footer_and_icv (&sess1->encap, rlen1);

      dlen_adj0 = rlen0 - pkt_len0;
      dlen_adj1 = rlen1 - pkt_len1;

      inst0->w4.u64 = sess0->inst.w4.u64 | pkt_len0;
      inst1->w4.u64 = sess1->inst.w4.u64 | pkt_len1;

      inst0->dptr = dptr0;
      inst1->dptr = dptr1;

      inst0->rptr = dptr0;
      inst1->rptr = dptr1;

      b0->current_length += dlen_adj0;
      b1->current_length += dlen_adj1;
    }

  inst0->w7.u64 = sess0->inst.w7.u64;
  inst1->w7.u64 = sess1->inst.w7.u64;

  onp_esp_post_data2 (b0)->res_ptr = (u64 *) &meta0->res;
  onp_esp_post_data2 (b1)->res_ptr = (u64 *) &meta1->res;

}

static_always_inline i32
cn10k_ipsec_outbound_finalize_last_inst (vlib_main_t *vm,
					 struct cpt_inst_s *inst,
					 cnxk_sched_vec_header_t *header)
{

  cnxk_sched_work_t work = { 0 };
  work.tag = 0;
  work.source = CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_ENC;

  inst->w2.s.tag = work.tag;
  inst->w2.s.tt = CNXK_SCHED_TAG_ORDERED;
  inst->w2.s.grp = cnxk_sched_grp_app_map_to_actual (
    vm->thread_index, CNXK_SCHED_GRP_APP_CRYPTO_ENQ);

  /*
   * w3 is already set with qord = 1.
   * For VWQE add bufs as wqe_ptr.
   * WQE_PTR is <63:3>, last 3 bits of buffer address should be 0.
   */
  inst->w3.s.wqe_ptr = (u64) header >> 3;

  return 0;
}

static_always_inline u32
cn10k_ipsec_outbound_inst_submit (vlib_main_t *vm, vlib_node_runtime_t *node,
				  vlib_frame_t *frame,
				  cnxk_per_thread_data_t *ptd,
				  cnxk_crypto_queue_t *crypto_queue,
				  vlib_buffer_t **b, struct cpt_inst_s *inst,
				  u64 **lmt_line, uint64_t io_addr,
				  uint64_t core_lmt_id, u32 n_enc)
{

  cnxk_crypto_dev_t *crypto_dev = ptd->user_ptr;
  cnxk_sched_vec_header_t *vec_header = NULL;
  u32 n_noop = 0, count;
  uint64_t lmt_arg;

  if (PREDICT_FALSE (cnxk_ipsec_sched_frame_alloc (
		       vm, crypto_dev, crypto_queue, &vec_header) < 0))
    {
      goto free_all_pkts;
    }

  vlib_get_buffer_indices (vm, b, vec_header->buffer_indices, n_enc);
  vec_header->next_node = ptd->next1[0];
  vec_header->drop_next_node = onp_ptd_ipsec (ptd)->post_drop_next_node;
  vec_header->user_ptr = crypto_queue;
  vec_header->frame_size = n_enc;
  vec_header->buffer_pool_index = ptd->buffers[0]->buffer_pool_index;

  cn10k_ipsec_outbound_finalize_last_inst (vm, inst + (n_enc - 1), vec_header);

  cnxk_pktpool_update_deplete_count (vm, ptd, n_enc,
				     vec_header->buffer_pool_index);

  /*
   * Add a memory barrier so that LMTLINEs from the previous iteration
   * can be reused for a subsequent transfer.
   */

  cnxk_wmb ();

  lmt_arg = ROC_CN10K_CPT_LMT_ARG | (uint64_t) core_lmt_id;

  for (count = 0; count < n_enc; count++)
    {
      roc_lmt_mov_seg ((void *) lmt_line[count], inst + count,
		       CPT_LMT_SIZE_COPY);
    }

  /* Count minus one of LMTSTs in the burst */
  lmt_arg |= (n_enc - 1) << 12;

  roc_lmt_submit_steorl (lmt_arg, io_addr);

  return n_noop;

free_all_pkts:
  for (n_noop = 0; n_noop < n_enc; n_noop++)
    {
      /* Drop node will be decided in plugin based on IP4 or IP6 */
      b[n_noop]->error = node->errors[ONP_ESP_ENCRYPT_ERROR_FRAME_ALLOC];
      ptd->second_buffer_indices[n_noop] =
	vlib_get_buffer_index (vm, b[n_noop]);
    }

  return n_noop;
}

static_always_inline u32
cn10k_ipsec_enqueue_outbound (vlib_main_t *vm, vlib_node_runtime_t *node,
			      vlib_frame_t *frame,
			      cnxk_crypto_queue_t *crypto_queue,
			      cnxk_per_thread_data_t *ptd, const u32 flags,
			      u16 core_id)
{
  u32 sa0_index, sa1_index, current_sa0_index = ~0, current_sa1_index = ~0;
  u32 n_left = frame->n_vectors, n_prep = 0, n_enc = 0, n_noop = 0;
  const bool is_b0_or_103 = roc_feature_nix_has_inl_ipsec_mseg ();
  struct cpt_inst_s *inst = (struct cpt_inst_s *) ptd->hw_inst;
  struct roc_cpt_lmtline *lmtline = &crypto_queue->lmtline;
  cn10k_ipsec_session_t *sess0 = NULL, *sess1 = NULL;
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  uint64_t lmt_base = lmtline->lmt_base;
  uint64_t ioaddr = lmtline->io_addr;
  vlib_buffer_t **b = ptd->buffers;
  u64 *lmt_line[16], core_lmt_id;
  u8 *data0, *data1;
  u16 next_index;

  clib_memset (ptd->hw_inst, 0, sizeof (ptd->hw_inst));
  next_index = ptd->next2[0];

  ROC_LMT_CPT_BASE_ID_GET (lmt_base, core_lmt_id);

  lmt_line[0] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 0);
  lmt_line[1] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 1);
  lmt_line[2] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 2);
  lmt_line[3] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 3);
  lmt_line[4] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 4);
  lmt_line[5] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 5);
  lmt_line[6] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 6);
  lmt_line[7] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 7);
  lmt_line[8] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 8);
  lmt_line[9] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 9);
  lmt_line[10] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 10);
  lmt_line[11] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 11);
  lmt_line[12] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 12);
  lmt_line[13] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 13);
  lmt_line[14] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 14);
  lmt_line[15] = CN10K_CPT_LMT_GET_LINE_ADDR (lmt_base, 15);

  while (n_left > 5)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);

      data0 = vlib_buffer_get_current (b[2]);
      clib_prefetch_load (data0);
      clib_prefetch_store (data0 - 64);

      data1 = vlib_buffer_get_current (b[3]);
      clib_prefetch_load (data1);
      clib_prefetch_store (data1 - 64);

      if (CLIB_DEBUG > 0)
	{
	  vlib_buffer_validate (vm, b[0]);
	  vlib_buffer_validate (vm, b[1]);
	}

      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;
      sa1_index = vnet_buffer (b[1])->ipsec.sad_index;

      if (sa0_index != current_sa0_index)
	{
	  sess0 = vec_elt (im->lookaside_ipsec_sessions, sa0_index);
	  clib_prefetch_load (&sess0->inst);
	  current_sa0_index = sa0_index;
	  ALWAYS_ASSERT (current_sa0_index <
			 vec_len (im->lookaside_ipsec_sessions));
	}

      vnet_buffer (b[0])->ipsec.sad_index = current_sa0_index;

      if (sa1_index != current_sa1_index)
	{
	  sess1 = vec_elt (im->lookaside_ipsec_sessions, sa1_index);
	  clib_prefetch_load (&sess1->inst);
	  current_sa1_index = sa1_index;
	  ALWAYS_ASSERT (current_sa1_index <
			 vec_len (im->lookaside_ipsec_sessions));
	}

      vnet_buffer (b[1])->ipsec.sad_index = current_sa1_index;

      cn10k_ipsec_outbound_lka_prepare_inst_x2 (vm, b[0], sess0, inst, b[1],
						sess1, inst + 1, next_index,
						is_b0_or_103);
      b += 2;
      inst += 2;
      n_prep += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;

      if (sa0_index != current_sa0_index)
	{
	  sess0 = vec_elt (im->lookaside_ipsec_sessions, sa0_index);
	  clib_prefetch_load (&sess0->inst);
	  current_sa0_index = sa0_index;
	  ALWAYS_ASSERT (current_sa0_index <
			 vec_len (im->lookaside_ipsec_sessions));
	}

      vnet_buffer (b[0])->ipsec.sad_index = current_sa0_index;

      if (CLIB_DEBUG > 0)
	vlib_buffer_validate (vm, b[0]);

      cn10k_ipsec_outbound_lka_prepare_inst (vm, b[0], sess0, inst, next_index,
					     is_b0_or_103);

      b++;
      inst++;
      n_prep++;
      n_left--;
    }

  n_enc = n_prep;
  inst = (struct cpt_inst_s *) ptd->hw_inst;
  b = ptd->buffers;

  while (n_enc > CN10K_MAX_LMT_SZ)
    {
      n_noop = cn10k_ipsec_outbound_inst_submit (
	vm, node, frame, ptd, crypto_queue, b, inst, lmt_line, ioaddr,
	core_lmt_id, CN10K_MAX_LMT_SZ);

      if (PREDICT_FALSE (n_noop))
	goto submit_fail;

      n_enc -= CN10K_MAX_LMT_SZ;
      inst += CN10K_MAX_LMT_SZ;
      b += CN10K_MAX_LMT_SZ;
    }

  if (n_enc > 0)
    n_noop = cn10k_ipsec_outbound_inst_submit (vm, node, frame, ptd,
					       crypto_queue, b, inst, lmt_line,
					       ioaddr, core_lmt_id, n_enc);
  if (PREDICT_FALSE (n_noop))
    goto submit_fail;

  n_enc = 0;

submit_fail:
  ptd->out_npkts = n_prep - n_enc;
  return n_noop;
}

#if 1
static_always_inline u32
cn10k_ipsec_outbound_sort (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *f, cnxk_per_thread_data_t *ptd,
			   const int is_ip6, const int is_tun)
{
  u32 *indices = ptd->second_buffer_indices;
  u32 sa0_index, current_sa0_index = ~0;
  u32 sa1_index, current_sa1_index = ~0;
  u32 sa2_index, current_sa2_index = ~0;
  u32 sa3_index, current_sa3_index = ~0;
  vlib_buffer_t **b = ptd->buffers;
  u16 thread0_next = ptd->next1[0];
  u32 n_left = f->n_vectors;
  u16 *next = ptd->next2;
  ipsec_sa_t *sa0 = NULL;
  ipsec_sa_t *sa1 = NULL;
  ipsec_sa_t *sa2 = NULL;
  ipsec_sa_t *sa3 = NULL;
  u32 bi0, bi1, bi2, bi3;

  while (n_left > 11)
    {
      vlib_prefetch_buffer_header (b[8], LOAD);
      vlib_prefetch_buffer_header (b[9], LOAD);
      vlib_prefetch_buffer_header (b[10], LOAD);
      vlib_prefetch_buffer_header (b[11], LOAD);

      sa0_index = cnxk_ipsec_sa_index_get (b[0], is_tun);
      sa1_index = cnxk_ipsec_sa_index_get (b[1], is_tun);
      sa2_index = cnxk_ipsec_sa_index_get (b[2], is_tun);
      sa3_index = cnxk_ipsec_sa_index_get (b[3], is_tun);

      bi0 = vlib_get_buffer_index (vm, b[0]);
      bi1 = vlib_get_buffer_index (vm, b[1]);
      bi2 = vlib_get_buffer_index (vm, b[2]);
      bi3 = vlib_get_buffer_index (vm, b[3]);

      if (sa0_index != current_sa0_index)
	{
	  sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}
      if (sa1_index != current_sa1_index)
	{
	  sa1 = ipsec_sa_get (sa1_index);
	  current_sa1_index = sa1_index;
	}
      if (sa2_index != current_sa2_index)
	{
	  sa2 = ipsec_sa_get (sa2_index);
	  current_sa2_index = sa2_index;
	}
      if (sa3_index != current_sa3_index)
	{
	  sa3 = ipsec_sa_get (sa3_index);
	  current_sa3_index = sa3_index;
	}

      /* Validate buffer to avoid any crashes in internal nodes */
      if (CLIB_DEBUG > 0)
	{
	  vlib_buffer_validate (vm, b[0]);
	  vlib_buffer_validate (vm, b[1]);
	  vlib_buffer_validate (vm, b[2]);
	  vlib_buffer_validate (vm, b[3]);
	}

      /*
       * If this is the first packet to use this SA, claim the SA
       * for this thread. Use atomic operation as this could happen
       * simultaneously on another thread
       */
      if (PREDICT_FALSE (sa0->thread_index == 0xFFFF))
	clib_atomic_cmp_and_swap (&sa0->thread_index, ~0,
				  ipsec_sa_assign_thread (vm->thread_index));
      if (PREDICT_FALSE (sa1->thread_index == 0xFFFF))
	clib_atomic_cmp_and_swap (&sa1->thread_index, ~0,
				  ipsec_sa_assign_thread (vm->thread_index));
      if (PREDICT_FALSE (sa2->thread_index == 0xFFFF))
	clib_atomic_cmp_and_swap (&sa2->thread_index, ~0,
				  ipsec_sa_assign_thread (vm->thread_index));
      if (PREDICT_FALSE (sa3->thread_index == 0xFFFF))
	clib_atomic_cmp_and_swap (&sa3->thread_index, ~0,
				  ipsec_sa_assign_thread (vm->thread_index));

      /*
       * It is possible that other cores have already claimed these SAs.
       * Send all the packets to their respective core-handoff nodes.
       */
      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      vnet_buffer (b[1])->ipsec.thread_index = sa1->thread_index;
      vnet_buffer (b[2])->ipsec.thread_index = sa2->thread_index;
      vnet_buffer (b[3])->ipsec.thread_index = sa3->thread_index;

      next[0] = thread0_next + sa0->thread_index;
      next[1] = thread0_next + sa1->thread_index;
      next[2] = thread0_next + sa2->thread_index;
      next[3] = thread0_next + sa3->thread_index;

      indices[0] = bi0;
      indices[1] = bi1;
      indices[2] = bi2;
      indices[3] = bi3;

      indices += 4;
      next += 4;
      b += 4;
      n_left -= 4;
    }

  current_sa0_index = ~0;
  while (n_left > 0)
    {
      sa0_index = cnxk_ipsec_sa_index_get (b[0], is_tun);

      bi0 = vlib_get_buffer_index (vm, b[0]);

      if (sa0_index != current_sa0_index)
	{
	  sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}

      /* Validate buffer to avoid any crashes in internal nodes */
      if (CLIB_DEBUG > 0)
	vlib_buffer_validate (vm, b[0]);

      if (PREDICT_FALSE (0XFFFF == sa0->thread_index))
	{
	  /*
	   * If this is the first packet to use this SA, claim the SA
	   * for this thread. Use atomic operation as this could happen
	   * simultaneously on another thread
	   */
	  clib_atomic_cmp_and_swap (&sa0->thread_index, ~0,
				    ipsec_sa_assign_thread (vm->thread_index));
	}

      vnet_buffer (b[0])->ipsec.thread_index = sa0->thread_index;
      next[0] = thread0_next + sa0->thread_index;

      indices[0] = bi0;

      indices++;
      next++;
      b++;
      n_left--;
    }
  return f->n_vectors;
}
#endif

static_always_inline void
cn10k_ipsec_get_enc_errors (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame, cnxk_per_thread_data_t *ptd)
{
  cn10k_ipsec_outbound_pkt_meta_t *meta;
  u32 pkt_count = frame->n_vectors;
  vlib_buffer_t *b;
  u32 i;

  for (i = 0; i < pkt_count; i++)
    {
      b = ptd->buffers[i];

      meta = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b);

      switch (meta->res.cn10k.uc_compcode)
	{
	  /* clang-format off */
#define _(e, s)                                               		   \
	case ROC_IE_OT_UCC_##e:                                            \
	  b->error = node->errors[ONP_ESP_ENCRYPT_CN10K_ERROR_##e];        \
	  break;
	foreach_onp_drv_cn10k_ipsec_ucc;
#undef _
	  /* clang-format on */
	default:
	  b->error = node->errors[ONP_ESP_ENCRYPT_ERROR_UNDEFINED];
	}
    }
}

#endif /* included_onp_drv_modules_ipsec_ipsec_fp_out_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
