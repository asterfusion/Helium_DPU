/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_ipsec_ipsec_fp_in_cn10k_h
#define included_onp_drv_modules_ipsec_ipsec_fp_in_cn10k_h

#include <onp/drv/modules/ipsec/ipsec_fp_cn10k.h>

static_always_inline void
cn10k_ipsec_inbound_revert_vlib (vlib_buffer_t *b)
{
  onp_esp_post_data_t *dec_post;

  dec_post = onp_esp_post_data (b);

  /* Update vlib buffer */
  vlib_buffer_advance (b, dec_post->pre_ipsec_l3_hdr_sz);
}

static_always_inline void
cn10k_ipsec_inbound_finalize_last_inst (vlib_main_t *vm,
					cn10k_ipsec_session_t *sess,
					struct cpt_inst_s *inst,
					cnxk_sched_vec_header_t *header,
					const u32 flags)
{
  cnxk_sched_work_t work = { 0 };

  inst->w2.u64 = sess->inst.w2.u64;

  /*
   * w3 is already set with qord = 1.
   * Add VWQE buffer as wqe_ptr.
   * WQE_PTR is <63:3>, last 3 bits of buffer address should be 0.
   */
  inst->w3.s.wqe_ptr = (u64) header >> 3;

  work.tag = 0;
  work.source = CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_DEC;
  /* Add modified tag */
  inst->w2.s.tag = work.tag;
  inst->w2.s.tt = CNXK_SCHED_TAG_ORDERED;
  inst->w2.s.grp =
    cnxk_sched_grp_app_map_to_actual (vm->thread_index, vm->thread_index);
}

static_always_inline uint32_t
cn10k_ipsec_fill_sg2_buf_inb (vlib_main_t *vm, struct roc_sg2list_comp *list,
			      int i, vlib_buffer_t **lb, vlib_buffer_t **pre_b)
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
      pre_b[0] = lb[0];
      lb[0] = vlib_get_buffer (vm, lb[0]->next_buffer);
      to->ptr[i % 3] = (u64) vlib_buffer_get_current (lb[0]);
      to->u.s.len[i % 3] = lb[0]->current_length;
      to->u.s.valid_segs = (i % 3) + 1;
      i++;
    }

  return i;
}

static_always_inline int
cn10k_ipsec_trim_buffer_length (vlib_buffer_t *prev, vlib_buffer_t *b,
				cn10k_ipsec_session_t *sess)
{
  /*
   * Update vlib buffer length in the last buffer. Adjusting
   * length may underflow current buffer length. In that case
   * adjust previous buffer.
   */

  int trim_length = b->current_length - sess->encap.partial_len;

  if (trim_length <= 0)
    {
      /* remove the current buffer and update prev buffer length */
      prev->next_buffer = 0;
      prev->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
      prev->current_length = (prev->current_length - sess->encap.roundup_len -
			      sess->encap.partial_len) +
			     b->current_length;
      return 1;
    }
  else
    {
      b->current_length =
	b->current_length - sess->encap.roundup_len - sess->encap.partial_len;
      return 0;
    }
}

static_always_inline int
cn10k_ipsec_inb_prepare_sg2_list (vlib_main_t *vm, vlib_buffer_t *b,
				  struct cpt_inst_s *inst, u32 dlen,
				  void *m_data, cn10k_ipsec_session_t *sess)
{
  struct roc_sg2list_comp *scatter_comp, *gather_comp;
  union cpt_inst_w5 cpt_inst_w5;
  union cpt_inst_w6 cpt_inst_w6;
  vlib_buffer_t *last_buf = b;
  vlib_buffer_t *prev_buf = b;
  u32 g_size_bytes;
  int i;

  /* Input Gather List */
  i = 0;
  gather_comp = (struct roc_sg2list_comp *) ((uint8_t *) m_data);

  i = cn10k_ipsec_fill_sg2_buf_inb (vm, gather_comp, i, &last_buf, &prev_buf);

  cpt_inst_w5.s.gather_sz = ((i + 2) / 3);
  g_size_bytes = ((i + 2) / 3) * sizeof (struct roc_sg2list_comp);

  cn10k_ipsec_trim_buffer_length (prev_buf, last_buf, sess);

  last_buf = b;
  prev_buf = b;

  /* Output Gather List */
  i = 0;
  scatter_comp =
    (struct roc_sg2list_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  i = cn10k_ipsec_fill_sg2_buf_inb (vm, scatter_comp, i, &last_buf, &prev_buf);

  cpt_inst_w6.s.scatter_sz = ((i + 2) / 3);

  cpt_inst_w5.s.dptr = (uint64_t) gather_comp;
  cpt_inst_w6.s.rptr = (uint64_t) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;
  inst->w4.s.dlen = dlen;
  inst->w4.s.opcode_major &= (~(ROC_IE_OT_INPLACE_BIT));

  b->total_length_not_including_first_buffer =
    b->total_length_not_including_first_buffer -
    (sess->encap.roundup_len + sess->encap.partial_len);
  return i;
}

static_always_inline uint32_t
cn10k_ipsec_fill_sg_inb_buf (vlib_main_t *vm, struct roc_sglist_comp *list,
			     uint32_t i, vlib_buffer_t **lb,
			     vlib_buffer_t **pre_b)
{
  struct roc_sglist_comp *to;

  to = &list[i >> 2];
  to->u.s.len[i % 4] = clib_net_to_host_u16 (lb[0]->current_length);
  to->ptr[i % 4] =
    clib_net_to_host_u64 ((u64) vlib_buffer_get_current (lb[0]));
  i++;

  while (lb[0]->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      to = &list[i >> 2];
      pre_b[0] = lb[0];
      lb[0] = vlib_get_buffer (vm, lb[0]->next_buffer);
      to->ptr[i % 4] =
	clib_net_to_host_u64 ((u64) vlib_buffer_get_current (lb[0]));
      to->u.s.len[i % 4] = clib_net_to_host_u16 (lb[0]->current_length);
      i++;
    }

  return i;
}

static_always_inline int
cn10k_ipsec_inb_prepare_sg_list (vlib_main_t *vm, vlib_buffer_t *b,
				 struct cpt_inst_s *inst, void *m_data,
				 cn10k_ipsec_session_t *sess)
{
  struct roc_sglist_comp *scatter_comp, *gather_comp;
  u32 g_size_bytes, s_size_bytes, dlen, trim_entry;
  vlib_buffer_t *last_buf = b;
  vlib_buffer_t *prev_buf = b;
  u8 *in_buffer;
  int i;

  in_buffer = m_data;

  ((uint16_t *) in_buffer)[0] = 0;
  ((uint16_t *) in_buffer)[1] = 0;

  /* Input Gather List */
  i = 0;
  gather_comp = (struct roc_sglist_comp *) ((uint8_t *) m_data + 8);

  i = cn10k_ipsec_fill_sg_inb_buf (vm, gather_comp, i, &last_buf, &prev_buf);

  ((uint16_t *) in_buffer)[2] = clib_net_to_host_u16 (i);

  g_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  last_buf = b;
  prev_buf = b;

  /* Output Scatter List */

  i = 0;
  scatter_comp =
    (struct roc_sglist_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  i = cn10k_ipsec_fill_sg_inb_buf (vm, scatter_comp, i, &last_buf, &prev_buf);

  trim_entry = cn10k_ipsec_trim_buffer_length (prev_buf, last_buf, sess);

  ((uint16_t *) in_buffer)[3] = clib_net_to_host_u16 (i - trim_entry);

  s_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  dlen = g_size_bytes + s_size_bytes + ROC_SG_LIST_HDR_SIZE;

  inst->dptr = (uint64_t) in_buffer;
  inst->rptr = inst->dptr;
  inst->w4.s.dlen = dlen;
  inst->w4.s.opcode_major |= (uint64_t) ROC_DMA_MODE_SG;

  b->total_length_not_including_first_buffer =
    b->total_length_not_including_first_buffer -
    (sess->encap.roundup_len + sess->encap.partial_len);

  return i;
}

static_always_inline void
cn10k_ipsec_inbound_prepare_inst (vlib_main_t *vm, vlib_buffer_t *b,
				  cn10k_ipsec_session_t *sess,
				  struct cpt_inst_s *inst, const u32 flags)
{
  bool is_b0_or_103 = roc_feature_nix_has_inl_ipsec_mseg ();
  cn10k_ipsec_inbound_pkt_meta_t *pkt_meta;
  onp_esp_post_data_t *sa_dec_post;
  struct cpt_cn10k_res_s *res;
  u16 l3_hdr_sz = 0, total_length;

  /* Current data points to L3 payload. Make it point to L3 header */
  if (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    {
      l3_hdr_sz = b->current_data - vnet_buffer (b)->l3_hdr_offset;
      vlib_buffer_push_uninit (b, l3_hdr_sz);
    }
  sa_dec_post = onp_esp_post_data (b);
  sa_dec_post->pre_ipsec_l3_hdr_sz = l3_hdr_sz;

  ip4_header_t *ip4 = vlib_buffer_get_current (b) ;
  if ((ip4->ip_version_and_header_length & 0xf0) == 0x40)
  {
      b->current_length = clib_net_to_host_u16(ip4->length);
  }

  else
  {
      ip6_header_t *ip6 = vlib_buffer_get_current (b);
      b->current_length = clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);;
  }

  clib_memcpy_fast (inst, &sess->inst, sizeof (struct cpt_inst_s));

  pkt_meta =
    (cn10k_ipsec_inbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b);

  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      total_length =
	b->current_length + b->total_length_not_including_first_buffer;

      if (is_b0_or_103)
	cn10k_ipsec_inb_prepare_sg2_list (vm, b, inst, total_length,
					  (void *) pkt_meta->sg_buffer, sess);
      else
	cn10k_ipsec_inb_prepare_sg_list (vm, b, inst,
					 (void *) pkt_meta->sg_buffer, sess);
    }
  else
    {
      /* Update dptr and dlen: w5 */
      inst->dptr = (uint64_t) vlib_buffer_get_current (b);

      inst->w4.s.dlen = b->current_length;

      /* Update rptr: w6 */
      inst->rptr = inst->dptr;

      b->current_length =
	b->current_length - sess->encap.roundup_len - sess->encap.partial_len;
    }

  res = &pkt_meta->res.cn10k;
  /* Make sure we reset the done bit */
  res->compcode = CPT_COMP_NOT_DONE;

  /* Fill CPT result in inst: w1 */
  inst->res_addr = (u64) res;

  /* Reset group, tag type, tag */
  inst->w2.u64 = 0;

  onp_esp_post_data2 (b)->res_ptr = (u64 *) res;
  b->current_data += l3_hdr_sz;
  b->current_length -= l3_hdr_sz;
}

static_always_inline void
cn10k_ipsec_inbound_prepare_inst_x2 (vlib_main_t *vm, vlib_buffer_t *b0,
				     cn10k_ipsec_session_t *sess0,
				     struct cpt_inst_s *inst0,
				     vlib_buffer_t *b1,
				     cn10k_ipsec_session_t *sess1,
				     struct cpt_inst_s *inst1, const u32 flags)
{
  bool is_b0_or_103 = roc_feature_nix_has_inl_ipsec_mseg ();
  cn10k_ipsec_inbound_pkt_meta_t *pkt_meta0, *pkt_meta1;
  onp_esp_post_data_t *sa0_dec_post, *sa1_dec_post;
  struct cpt_cn10k_res_s *res0, *res1;
  u16 l3_hdr_sz0 = 0, total_length0;
  u16 l3_hdr_sz1 = 0, total_length1;

  /* Current data points to L3 payload. Make it point to L3 header */
  if (b0->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    {
      l3_hdr_sz0 = b0->current_data - vnet_buffer (b0)->l3_hdr_offset;
      vlib_buffer_push_uninit (b0, l3_hdr_sz0);
    }

  if (b1->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    {
      l3_hdr_sz1 = b1->current_data - vnet_buffer (b1)->l3_hdr_offset;
      vlib_buffer_push_uninit (b1, l3_hdr_sz1);
    }

  sa0_dec_post = onp_esp_post_data (b0);
  sa1_dec_post = onp_esp_post_data (b1);

  sa0_dec_post->pre_ipsec_l3_hdr_sz = l3_hdr_sz0;
  sa1_dec_post->pre_ipsec_l3_hdr_sz = l3_hdr_sz1;

  ip4_header_t *ip40 = vlib_buffer_get_current (b0);
  ip4_header_t *ip41 = vlib_buffer_get_current (b1);
  if ((ip40->ip_version_and_header_length & 0xf0) == 0x40)
  {
      b0->current_length = clib_net_to_host_u16(ip40->length);
  }

  else
  {
      ip6_header_t *ip60 = vlib_buffer_get_current (b0);
      b0->current_length = clib_net_to_host_u16 (ip60->payload_length) + sizeof (ip6_header_t);;
  }

  if ((ip41->ip_version_and_header_length & 0xf0) == 0x40)
  {
      b1->current_length = clib_net_to_host_u16(ip41->length);
  }

  else
  {
      ip6_header_t *ip61 = vlib_buffer_get_current (b1);
      b1->current_length = clib_net_to_host_u16 (ip61->payload_length) + sizeof (ip6_header_t);;
  }

  clib_memcpy_fast (inst0, &sess0->inst, sizeof (struct cpt_inst_s));
  clib_memcpy_fast (inst1, &sess1->inst, sizeof (struct cpt_inst_s));

  pkt_meta0 =
    (cn10k_ipsec_inbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (
      b0);
  pkt_meta1 =
    (cn10k_ipsec_inbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (
      b1);

  if ((b0->flags & VLIB_BUFFER_NEXT_PRESENT) ||
      (b1->flags & VLIB_BUFFER_NEXT_PRESENT))
    {

      total_length0 =
	b0->current_length + b0->total_length_not_including_first_buffer;

      total_length1 =
	b1->current_length + b1->total_length_not_including_first_buffer;

      if (is_b0_or_103)
	{
	  cn10k_ipsec_inb_prepare_sg2_list (vm, b0, inst0, total_length0,
					    (void *) pkt_meta0->sg_buffer,
					    sess0);
	  cn10k_ipsec_inb_prepare_sg2_list (vm, b1, inst1, total_length1,
					    (void *) pkt_meta1->sg_buffer,
					    sess1);
	}
      else
	{

	  cn10k_ipsec_inb_prepare_sg_list (
	    vm, b0, inst0, (void *) pkt_meta0->sg_buffer, sess0);
	  cn10k_ipsec_inb_prepare_sg_list (
	    vm, b1, inst1, (void *) pkt_meta1->sg_buffer, sess1);
	}
    }
  else
    {
      /* Update dptr and dlen: w5 */
      inst0->dptr = (uint64_t) vlib_buffer_get_current (b0);
      inst1->dptr = (uint64_t) vlib_buffer_get_current (b1);

      inst0->w4.s.dlen = b0->current_length;
      inst1->w4.s.dlen = b1->current_length;

      /* Update rptr: w6 */
      inst0->rptr = (uint64_t) inst0->dptr;
      inst1->rptr = (uint64_t) inst1->dptr;

      b0->current_length = b0->current_length - sess0->encap.roundup_len -
			   sess0->encap.partial_len;
      b1->current_length = b1->current_length - sess1->encap.roundup_len -
			   sess1->encap.partial_len;
    }

  res0 = &pkt_meta0->res.cn10k;
  res1 = &pkt_meta1->res.cn10k;

  /* Make sure we reset the done bit */
  res0->compcode = CPT_COMP_NOT_DONE;
  res1->compcode = CPT_COMP_NOT_DONE;

  /* Fill CPT result in inst: w1 */
  inst0->res_addr = (u64) res0;
  inst1->res_addr = (u64) res1;

  /* Reset group, tag type, tag */
  inst0->w2.u64 = 0;
  inst1->w2.u64 = 0;

  onp_esp_post_data2 (b0)->res_ptr = (u64 *) res0;
  onp_esp_post_data2 (b1)->res_ptr = (u64 *) res1;

  b0->current_data += l3_hdr_sz0;
  b1->current_data += l3_hdr_sz1;
  b0->current_length -= l3_hdr_sz0;
  b1->current_length -= l3_hdr_sz1;
}

static_always_inline i32
cn10k_ipsec_enqueue_inbound (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *f,
			     cnxk_crypto_queue_t *crypto_queue,
			     cnxk_per_thread_data_t *ptd, const u32 flags)
{
  u32 sa0_index, sa1_index, current_sa0_index = ~0, current_sa1_index = ~0;
  u32 n_left = f->n_vectors, n_prep = 0, n_dec = 0, i = 0, count;
  struct cpt_inst_s *inst = (struct cpt_inst_s *) ptd->hw_inst;
  struct roc_cpt_lmtline *lmtline = &crypto_queue->lmtline;
  cn10k_ipsec_session_t *sess0 = NULL, *sess1 = NULL;
  i64 current_sa1_pkts = 0, current_sa1_bytes = 0;
  i64 current_sa0_pkts = 0, current_sa0_bytes = 0;
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  uint64_t lmt_base = lmtline->lmt_base, lmt_arg;
  cnxk_crypto_dev_t *crypto_dev = ptd->user_ptr;
  cnxk_sched_vec_header_t *vec_header = NULL;
  u32 *from = vlib_frame_vector_args (f);
  vlib_buffer_t **b = ptd->buffers, *buf;
  uint64_t ioaddr = lmtline->io_addr;
  u64 *lmt_line[16], core_lmt_id;
  u8 *data0, *data1;
  u32 buffer_index;
  u16 n_noop = 0;

  if (PREDICT_FALSE (cnxk_ipsec_sched_frame_alloc (
		       vm, crypto_dev, crypto_queue, &vec_header) < 0))
  {
    goto free_all_pkts;
  }

  vec_header->user_ptr = crypto_queue;
  vec_header->next_node = ptd->next1[0];
  vec_header->drop_next_node = onp_ptd_ipsec (ptd)->post_drop_next_node;

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

      clib_prefetch_store (inst + 2);
      clib_prefetch_store (inst + 3);

      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;
      sa1_index = vnet_buffer (b[1])->ipsec.sad_index;

      if (sa0_index != current_sa0_index)
	{
	  sess0 = vec_elt (im->lookaside_ipsec_sessions, sa0_index);
	  clib_prefetch_load (&sess0->inst);

	  if (current_sa0_pkts)
	    vlib_increment_combined_counter (
	      &ipsec_sa_counters, vm->thread_index, current_sa0_index,
	      current_sa0_pkts, current_sa0_bytes);

	  current_sa0_bytes = current_sa0_pkts = 0;
	  current_sa0_index = sa0_index;
	}

      if (sa1_index != current_sa1_index)
	{
	  sess1 = vec_elt (im->lookaside_ipsec_sessions, sa1_index);
	  clib_prefetch_load (&sess1->inst);

	  if (current_sa1_pkts)
	    vlib_increment_combined_counter (
	      &ipsec_sa_counters, vm->thread_index, current_sa1_index,
	      current_sa1_pkts, current_sa1_bytes);

	  current_sa1_bytes = current_sa1_pkts = 0;
	  current_sa1_index = sa1_index;
	}

      current_sa0_pkts += 1;
      current_sa1_pkts += 1;

      current_sa0_bytes += b[0]->current_length;
      current_sa1_bytes += b[1]->current_length;

      cn10k_ipsec_inbound_prepare_inst_x2 (vm, b[0], sess0, inst, b[1], sess1,
					   inst + 1, flags);

      b += 2;
      inst += 2;
      n_prep += 2;
      n_left -= 2;
    }

  /* Loop and create CPT instruction assuming anti-replay would pass */
  while (n_left > 0)
    {
      sa0_index = vnet_buffer (b[0])->ipsec.sad_index;

      if (sa0_index != current_sa0_index)
	{
	  if (current_sa0_pkts)
	    vlib_increment_combined_counter (
	      &ipsec_sa_counters, vm->thread_index, current_sa0_index,
	      current_sa0_pkts, current_sa0_bytes);

	  current_sa0_bytes = current_sa0_pkts = 0;
	  sess0 = vec_elt (im->lookaside_ipsec_sessions, sa0_index);
	  current_sa0_index = sa0_index;
	}

      current_sa0_pkts += 1;
      current_sa0_bytes += b[0]->current_length;

      cn10k_ipsec_inbound_prepare_inst (vm, b[0], sess0, inst, flags);

      b++;
      inst++;
      n_left--;
      n_prep++;
    }

  vec_header->buffer_pool_index = ptd->buffers[0]->buffer_pool_index;

  cn10k_ipsec_inbound_finalize_last_inst (vm, sess0, --inst, vec_header,
					  flags);

  if (current_sa0_pkts)
    vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				     current_sa0_index, current_sa0_pkts,
				     current_sa0_bytes);

  if (current_sa1_pkts)
    vlib_increment_combined_counter (&ipsec_sa_counters, vm->thread_index,
				     current_sa1_index, current_sa1_pkts,
				     current_sa1_bytes);

  /* Prepare for next iteration */
  ASSERT (n_prep == f->n_vectors);
  n_left = n_prep;
  b = ptd->buffers;

  while (n_left > 0)
    {
      buffer_index = vlib_get_buffer_index (vm, b[0]);
      vec_header->buffer_indices[n_dec] = buffer_index;
      n_left--;
      n_dec++;
      i++;
      b++;
    }

  vec_header->frame_size = n_dec;

  /* Collect submitted packets statistics */
  ptd->out_npkts = n_dec;

  inst = (struct cpt_inst_s *) ptd->hw_inst;
  n_left = n_prep;

  while (n_left > CN10K_MAX_LMT_SZ)
    {

      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */
      cnxk_wmb ();

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | (uint64_t) core_lmt_id;

      roc_lmt_mov_seg ((void *) lmt_line[0], inst, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[1], inst + 1, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[2], inst + 2, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[3], inst + 3, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[4], inst + 4, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[5], inst + 5, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[6], inst + 6, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[7], inst + 7, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[8], inst + 8, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[9], inst + 9, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[10], inst + 10, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[11], inst + 11, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[12], inst + 12, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[13], inst + 13, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[14], inst + 14, CPT_LMT_SIZE_COPY);
      roc_lmt_mov_seg ((void *) lmt_line[15], inst + 15, CPT_LMT_SIZE_COPY);

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (CN10K_MAX_LMT_SZ - 1) << 12;

      roc_lmt_submit_steorl (lmt_arg, ioaddr);

      inst += CN10K_MAX_LMT_SZ;
      n_left -= CN10K_MAX_LMT_SZ;
    }

  if (n_left > 0)
    {
      /*
       * Add a memory barrier so that LMTLINEs from the previous iteration
       * can be reused for a subsequent transfer.
       */

      cnxk_wmb ();

      lmt_arg = ROC_CN10K_CPT_LMT_ARG | (uint64_t) core_lmt_id;

      for (count = 0; count < n_left; count++)
	{
	  roc_lmt_mov_seg ((void *) lmt_line[count], inst + count,
			   CPT_LMT_SIZE_COPY);
	}

      /* Set number of LMTSTs, excluding the first */
      lmt_arg |= (n_left - 1) << 12;

      roc_lmt_submit_steorl (lmt_arg, ioaddr);
    }

  /* Deplete by n_dec */
  cnxk_pktpool_update_deplete_count (vm, ptd, n_dec,
				     vec_header->buffer_pool_index);

  ptd->out_user_nstats = 1;

  return 0;

free_all_pkts:
  for (n_noop = 0; n_noop < f->n_vectors; n_noop++)
    {
      ptd->next2[n_noop] = ONP_ESP_DECRYPT_NEXT_DROP;
      buf = vlib_get_buffer (vm, from[n_noop]);
      buf->error = node->errors[ONP_ESP_DECRYPT_ERROR_FRAME_ALLOC];
      ptd->second_buffer_indices[n_noop] = from[n_noop];
    }
  return n_noop;
}

static_always_inline void
cn10k_drv_ipsec_get_dec_errors (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame,
				cnxk_per_thread_data_t *ptd)
{
  u32 pkt_count = frame->n_vectors, i = 0;
  struct cpt_cn10k_res_s *res;
  vlib_buffer_t *b;

  for (i = 0; i < pkt_count; i++)
    {
      b = ptd->buffers[i];

      /* Revert vlib before sending to error node */
      cn10k_ipsec_inbound_revert_vlib (b);

      if (!(b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID))
	{
	  b->error = node->errors[ONP_ESP_DECRYPT_ERROR_L3_HDR_NOT_VALID];
	  continue;
	}

      res = onp_esp_post_data2 (b)->res_ptr;

      switch (res->uc_compcode)
	{
	  /* clang-format off */
#define _(e, s)                                               		   \
	case ROC_IE_OT_UCC_##e:                                            \
	  b->error = node->errors[ONP_ESP_DECRYPT_CN10K_ERROR_##e];        \
	  break;
	foreach_onp_drv_cn10k_ipsec_ucc;
#undef _
	  /* clang-format on */
	default:
	  b->error = node->errors[ONP_ESP_DECRYPT_ERROR_UNDEFINED];
	}
    }
}

#endif /* included_onp_drv_modules_ipsec_ipsec_fp_in_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
