/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_rx_h
#define included_onp_drv_modules_pktio_pktio_rx_h

#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/inc/pktio_fp.h>
#include <onp/drv/inc/ipsec_fp.h>
#include <onp/drv/modules/pktio/pktio_reass_rx.h>

#define CNXK_NIX_CQ_SZ	   128
#define CNXK_SEG_LEN_SHIFT 16
#define CNXK_SEG_LEN_MASK  0xFFFF
#define CPT_RES_SKIP(rxp)                                                     \
  (sizeof (struct nix_wqe_hdr_s) + sizeof (union nix_rx_parse_u) +            \
   (rxp->parse.desc_sizem1 * 16) + 16)

static_always_inline u32
cnxk_cqe_cached_pkts_get (cnxk_pktio_t *pktio, cnxk_fprq_t *fprq, u16 req_pkts,
			  const u64 fp_flags)
{
  u64 npkts, head, tail, reg;

  if (PREDICT_FALSE (fprq->cached_pkts < req_pkts))
    {
      reg = roc_atomic64_add_sync (fprq->wdata, fprq->cq_status);
      if (reg &
	  (BIT_ULL (NIX_CQ_OP_STAT_OP_ERR) | BIT_ULL (NIX_CQ_OP_STAT_CQ_ERR)))
	return 0;

      tail = reg & 0xFFFFF;
      head = (reg >> 20) & 0xFFFFF;

      if (tail < head)
	npkts = tail - head + fprq->qmask + 1;
      else
	npkts = tail - head;

      fprq->cached_pkts = npkts;
    }

  return clib_min (fprq->cached_pkts, req_pkts);
}

static_always_inline void
cnxk_pktio_cq_door_bell_update (cnxk_fprq_t *fprq, u32 n_pkts)
{
  *(volatile u64 *) fprq->cq_door = fprq->wdata | n_pkts;
}

static_always_inline u32
cnxk_pktio_chain_segs (vlib_main_t *vm, const cnxk_pktio_nix_parse_t *rxp0,
		       vlib_buffer_t *bt, vlib_buffer_t *b, i32 data_off,
		       const u64 fp_flags, const u64 off_flags,
		       const u8 is_ipsec)
{
  u32 n_words, n_words_processed, desc_sizem1;
  vlib_buffer_t *last_buf, *seg_buf;
  u32 n_sg_desc, n_segs, next_seg;
  u32 current_desc, bi, sg_len;
  vlib_buffer_t *buf = b;
  struct nix_rx_sg_s *sg;
  u32 total_segs = 1;
  u64 seg_len;
  i64 len;

  desc_sizem1 = rxp0->parse.desc_sizem1;
  if (desc_sizem1 == 0)
    return total_segs;

  n_words = desc_sizem1 << 1;
  n_sg_desc = (n_words / 4) + 1;

  sg = (struct nix_rx_sg_s *) (((char *) rxp0) + sizeof (rxp0->parse));
  /* Typecast to u64 to read each seg length swiftly */
  seg_len = *(u64 *) sg;
  n_segs = sg->segs;

  /* Start with first descriptor */
  current_desc = 0;

  len = buf->current_length;
  /*
   * We updated length which is valid in single segment case.
   * incase of multi seg, update seg1 length and advance total words processed.
   * also, updates total bytes in buffer.
   */
  buf->current_length = seg_len & CNXK_SEG_LEN_MASK;
  len -= buf->current_length;

  /* Process from 2nd segment */
  next_seg = 2;
  seg_len = seg_len >> CNXK_SEG_LEN_SHIFT;
  n_words_processed = 2;

  buf->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  buf->total_length_not_including_first_buffer = 0;
  last_buf = buf;

  while (current_desc <= n_sg_desc)
    {
      while (next_seg <= n_segs)
	{
	  seg_buf = (vlib_buffer_t *) ((*(((u64 *) sg) + n_words_processed)) -
				       data_off);
	  cnxk_pktio_verify_rx_vlib (vm, seg_buf);
	  vlib_buffer_copy_template (seg_buf, bt);
	  sg_len = seg_len & CNXK_SEG_LEN_MASK;

	  if (is_ipsec)
	    {
	      /*
	       * Adjust last buf data length with negative offset for
	       * ipsec pkts if needed.
	       */
	      len -= sg_len;
	      sg_len = (len > 0) ? sg_len : (sg_len + len);
	      len = (len > 0) ? len : 0;
	    }

	  seg_buf->current_length = sg_len;
	  bi = vlib_get_buffer_index (vm, seg_buf);
	  last_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  last_buf->next_buffer = bi;
	  last_buf = seg_buf;
	  seg_len = seg_len >> CNXK_SEG_LEN_SHIFT;
	  buf->total_length_not_including_first_buffer +=
	    seg_buf->current_length;
	  n_words_processed++;
	  next_seg++;
	  total_segs++;
	}
      current_desc++;
      n_sg_desc--;
      if (n_sg_desc)
	{
	  struct nix_rx_sg_s *tsg;

	  tsg = (struct nix_rx_sg_s *) ((u64 *) sg + n_words_processed);
	  seg_len = *((u64 *) (tsg));
	  n_words_processed++;
	  /* Start over */
	  n_segs = tsg->segs;
	  next_seg = 1;
	}
    }

  return total_segs;
}

static_always_inline vlib_buffer_t *
cnxk_pktio_init_vlib_from_cq (vlib_main_t *vm, i32 data_off, u64 *cq_hdr,
			      cnxk_pktio_nix_parse_t *rxp, vlib_buffer_t *bt,
			      cnxk_per_thread_data_t *ptd, cnxk_fprq_t *fprq,
			      vlib_buffer_t **buf, u16 *buffer_next_index,
			      u16 mp_index, const u64 fp_flags,
			      const u64 off_flags, u32 *n_frags_except_first,
			      u32 *n_segs)
{
  u32 l2_sz, l2_ol3_hdr_size, ilen, olen, esp_size, is_fail;
  const u16 rx_parse_bytes = sizeof (union nix_rx_parse_u);
  cnxk_pktio_nix_parse_t *orig_rxp;
  struct cpt_parse_hdr_s *cpt_hdr;
  union cpt_res_s *res, temp_res;
  vlib_buffer_t *b;
  u8 frag_cnt = 1;
  u64 *wqe_ptr;

  if (!cnxk_pktio_is_packet_from_cpt_march (rxp))
    {
      /* Plain packet path */
      b = (vlib_buffer_t *) (*(cq_hdr + 9) - data_off);
      cnxk_pktio_verify_rx_vlib (vm, b);
      vlib_buffer_copy_template (b, bt);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
	ptd->out_flags |= (rxp->u[0] >> 20) & 0xFFF;

      b->current_length = rxp->parse.pkt_lenm1 + 1;
      b->flow_id = rxp->parse.match_id;
      ptd->out_user_nstats += b->current_length;

      if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
	clib_memcpy_fast (b->pre_data, &rxp->parse, rx_parse_bytes);

      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	*n_segs += cnxk_pktio_chain_segs (vm, rxp, bt, b, data_off, fp_flags,
					  off_flags, 0 /* is_ipsec */);
      else
	*n_segs += 1;

      return b;
    }

  cpt_hdr = (struct cpt_parse_hdr_s *) *(cq_hdr + 9);
  wqe_ptr = (u64 *) clib_net_to_host_u64 (cpt_hdr->wqe_ptr);

  b = (vlib_buffer_t *) (*(wqe_ptr + 9) - data_off);
  orig_rxp = (cnxk_pktio_nix_parse_t *) (wqe_ptr + 1);

  res = (union cpt_res_s *) ((u8 *) wqe_ptr + CPT_RES_SKIP (orig_rxp));
  cnxk_pktio_verify_rx_vlib (vm, b);

  clib_memcpy (&temp_res, res, sizeof (res));
  vlib_buffer_copy_template (b, bt);
  res = &temp_res;

  olen = orig_rxp->parse.pkt_lenm1 + 1;

  is_fail = !cnxk_drv_ipsec_is_inl_op_success_march (res);
  if (PREDICT_FALSE (is_fail))
    {
      rxp = orig_rxp;
      /* Set the outer packet length when IPsec operation is unsuccessful */
      b->current_length = olen;
    }
  else
    {
      l2_sz = rxp->parse.lcptr - rxp->parse.laptr;
      l2_ol3_hdr_size = orig_rxp->parse.leptr - orig_rxp->parse.laptr;
      esp_size = olen - l2_ol3_hdr_size;

      ilen = cnxk_drv_ipsec_inl_get_rlen_march (res) + l2_sz;
      /* Set the inner packet length when IPsec operation is successful */
      b->current_length = ilen;

      frag_cnt = cnxk_pktio_reassemble (vm, cpt_hdr, rxp, ptd, b, buf,
					buffer_next_index, data_off, &olen,
					&esp_size, l2_ol3_hdr_size);

      /* Update IPsec counters only when IPsec is successful */
      cnxk_ipsec_update_counters (vm, res, b, esp_size, frag_cnt);

      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	*n_segs += cnxk_pktio_chain_segs (
	  vm, orig_rxp, bt, b, data_off, fp_flags, off_flags, 1 /* is_ipsec*/);
      else
	*n_segs += 1;
    }

  *n_frags_except_first += frag_cnt - 1;

  ptd->out_user_nstats += olen;

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);

  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
    ptd->out_flags |= (rxp->u[0] >> 20) & 0xFFF;

  if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
    clib_memcpy_fast (b->pre_data, &rxp->parse, rx_parse_bytes);

  cnxk_ipsec_inl_data (b)->is_ipsec_op_fail = is_fail;
  cnxk_ipsec_inl_data (b)->uc_err =
    cnxk_drv_ipsec_inl_get_uc_error_code_march (res);

  cnxk_drv_pool_free_inline (mp_index, (void **) &cpt_hdr, 1);

  return b;
}

static_always_inline u32
cnxk_pktio_process_ipsec_pkts_x4 (
  vlib_main_t *vm, cnxk_pktio_nix_parse_t *rxp0, cnxk_pktio_nix_parse_t *rxp1,
  cnxk_pktio_nix_parse_t *rxp2, cnxk_pktio_nix_parse_t *rxp3,
  struct cpt_parse_hdr_s *hdr0, struct cpt_parse_hdr_s *hdr1,
  struct cpt_parse_hdr_s *hdr2, struct cpt_parse_hdr_s *hdr3,
  cnxk_per_thread_data_t *ptd, vlib_buffer_t **b, const u64 fp_flags,
  u16 mp_index, i32 data_off, const u64 off_flags, u16 *buffer_next_index,
  u32 *n_segs)
{
  cnxk_pktio_nix_parse_t *orig_rxp0, *orig_rxp1, *orig_rxp2, *orig_rxp3;
  union cpt_res_s temp_res0, temp_res1, temp_res2, temp_res3;
  const u16 rx_parse_bytes = sizeof (union nix_rx_parse_u);
  u32 l2_ol3_sz0, l2_ol3_sz1, l2_ol3_sz2, l2_ol3_sz3;
  u32 is_fail0, is_fail1, is_fail2, is_fail3;
  union cpt_res_s *res0, *res1, *res2, *res3;
  u32 b0_err_flags = 0, b1_err_flags = 0;
  u32 b2_err_flags = 0, b3_err_flags = 0;
  u32 esp_sz0, esp_sz1, esp_sz2, esp_sz3;
  u32 ilen0, ilen1, ilen2, ilen3, l2_sz;
  u8 frag_cnt0 = 1, frag_cnt1 = 1;
  u8 frag_cnt2 = 1, frag_cnt3 = 1;
  u32 olen0, olen1, olen2, olen3;
  u32 n_frags_except_first = 0;
  u64 *wqe0_ptr, *wqe1_ptr;
  u64 *wqe2_ptr, *wqe3_ptr;
  vlib_buffer_t *bt;
  u16 n_cpt_err;
  vlib_buffer_t *buffer0, *buffer1;
  vlib_buffer_t *buffer2, *buffer3;

  bt = &ptd->buffer_template;
  wqe0_ptr = (u64 *) clib_net_to_host_u64 (hdr0->wqe_ptr);
  wqe1_ptr = (u64 *) clib_net_to_host_u64 (hdr1->wqe_ptr);
  wqe2_ptr = (u64 *) clib_net_to_host_u64 (hdr2->wqe_ptr);
  wqe3_ptr = (u64 *) clib_net_to_host_u64 (hdr3->wqe_ptr);

  buffer0 = (vlib_buffer_t *) (*(wqe0_ptr + 9) - data_off);
  buffer1 = (vlib_buffer_t *) (*(wqe1_ptr + 9) - data_off);
  buffer2 = (vlib_buffer_t *) (*(wqe2_ptr + 9) - data_off);
  buffer3 = (vlib_buffer_t *) (*(wqe3_ptr + 9) - data_off);

  orig_rxp0 = (cnxk_pktio_nix_parse_t *) (wqe0_ptr + 1);
  orig_rxp1 = (cnxk_pktio_nix_parse_t *) (wqe1_ptr + 1);
  orig_rxp2 = (cnxk_pktio_nix_parse_t *) (wqe2_ptr + 1);
  orig_rxp3 = (cnxk_pktio_nix_parse_t *) (wqe3_ptr + 1);

  res0 = (union cpt_res_s *) ((u8 *) wqe0_ptr + CPT_RES_SKIP (orig_rxp0));
  res1 = (union cpt_res_s *) ((u8 *) wqe1_ptr + CPT_RES_SKIP (orig_rxp1));
  res2 = (union cpt_res_s *) ((u8 *) wqe2_ptr + CPT_RES_SKIP (orig_rxp2));
  res3 = (union cpt_res_s *) ((u8 *) wqe3_ptr + CPT_RES_SKIP (orig_rxp3));

  clib_memcpy (&temp_res0, res0, sizeof (res0));
  clib_memcpy (&temp_res1, res1, sizeof (res1));
  clib_memcpy (&temp_res2, res2, sizeof (res2));
  clib_memcpy (&temp_res3, res3, sizeof (res3));

  cnxk_pktio_verify_rx_vlib (vm, buffer0);
  cnxk_pktio_verify_rx_vlib (vm, buffer1);
  cnxk_pktio_verify_rx_vlib (vm, buffer2);
  cnxk_pktio_verify_rx_vlib (vm, buffer3);

  vlib_buffer_copy_template (buffer0, bt);
  vlib_buffer_copy_template (buffer1, bt);
  vlib_buffer_copy_template (buffer2, bt);
  vlib_buffer_copy_template (buffer3, bt);

  res0 = &temp_res0;
  res1 = &temp_res1;
  res2 = &temp_res2;
  res3 = &temp_res3;

  is_fail0 = !cnxk_drv_ipsec_is_inl_op_success_march (res0);
  is_fail1 = !cnxk_drv_ipsec_is_inl_op_success_march (res1);
  is_fail2 = !cnxk_drv_ipsec_is_inl_op_success_march (res2);
  is_fail3 = !cnxk_drv_ipsec_is_inl_op_success_march (res3);

  n_cpt_err = is_fail0 + is_fail1 + is_fail2 + is_fail3;

  l2_sz = rxp0->parse.lcptr - rxp0->parse.laptr;
  l2_ol3_sz0 = orig_rxp0->parse.leptr - rxp0->parse.laptr;
  ilen0 = cnxk_drv_ipsec_inl_get_rlen_march (res0) + l2_sz;
  l2_sz = rxp1->parse.lcptr - rxp1->parse.laptr;
  l2_ol3_sz1 = orig_rxp1->parse.leptr - rxp1->parse.laptr;
  ilen1 = cnxk_drv_ipsec_inl_get_rlen_march (res1) + l2_sz;
  l2_sz = rxp2->parse.lcptr - rxp2->parse.laptr;
  l2_ol3_sz2 = orig_rxp2->parse.leptr - rxp2->parse.laptr;
  ilen2 = cnxk_drv_ipsec_inl_get_rlen_march (res2) + l2_sz;
  l2_sz = rxp3->parse.lcptr - rxp3->parse.laptr;
  l2_ol3_sz3 = orig_rxp3->parse.leptr - rxp3->parse.laptr;
  ilen3 = cnxk_drv_ipsec_inl_get_rlen_march (res3) + l2_sz;

  olen0 = orig_rxp0->parse.pkt_lenm1 + 1;
  olen1 = orig_rxp1->parse.pkt_lenm1 + 1;
  olen2 = orig_rxp2->parse.pkt_lenm1 + 1;
  olen3 = orig_rxp3->parse.pkt_lenm1 + 1;

  esp_sz0 = olen0 - l2_ol3_sz0;
  esp_sz1 = olen1 - l2_ol3_sz1;
  esp_sz2 = olen2 - l2_ol3_sz2;
  esp_sz3 = olen3 - l2_ol3_sz3;

  if (PREDICT_TRUE (!n_cpt_err))
    {
      buffer0->current_length = ilen0;
      buffer1->current_length = ilen1;
      buffer2->current_length = ilen2;
      buffer3->current_length = ilen3;

      ptd->buffers[*buffer_next_index] = buffer0;
      *buffer_next_index += 1;
      frag_cnt0 = cnxk_pktio_reassemble (vm, hdr0, rxp0, ptd, buffer0, b,
					 buffer_next_index, data_off, &olen0,
					 &esp_sz0, l2_ol3_sz0);

      ptd->buffers[*buffer_next_index] = buffer1;
      *buffer_next_index += 1;
      frag_cnt1 = cnxk_pktio_reassemble (vm, hdr1, rxp1, ptd, buffer1, b,
					 buffer_next_index, data_off, &olen1,
					 &esp_sz1, l2_ol3_sz1);

      ptd->buffers[*buffer_next_index] = buffer2;
      *buffer_next_index += 1;
      frag_cnt2 = cnxk_pktio_reassemble (vm, hdr2, rxp2, ptd, buffer2, b,
					 buffer_next_index, data_off, &olen2,
					 &esp_sz2, l2_ol3_sz2);

      ptd->buffers[*buffer_next_index] = buffer3;
      *buffer_next_index += 1;
      frag_cnt3 = cnxk_pktio_reassemble (vm, hdr3, rxp3, ptd, buffer3, b,
					 buffer_next_index, data_off, &olen3,
					 &esp_sz3, l2_ol3_sz3);

      cnxk_ipsec_update_counters_x4 (vm, res0, buffer0, esp_sz0, frag_cnt0,
				     res1, buffer1, esp_sz1, frag_cnt1, res2,
				     buffer2, esp_sz2, frag_cnt2, res3,
				     buffer3, esp_sz3, frag_cnt3);

      if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	{
	  *n_segs +=
	    cnxk_pktio_chain_segs (vm, orig_rxp0, bt, buffer0, data_off,
				   fp_flags, off_flags, 1 /* is_ipsec */);
	  *n_segs +=
	    cnxk_pktio_chain_segs (vm, orig_rxp1, bt, buffer1, data_off,
				   fp_flags, off_flags, 1 /* is_ipsec */);
	  *n_segs +=
	    cnxk_pktio_chain_segs (vm, orig_rxp2, bt, buffer2, data_off,
				   fp_flags, off_flags, 1 /* is_ipsec */);
	  *n_segs +=
	    cnxk_pktio_chain_segs (vm, orig_rxp3, bt, buffer3, data_off,
				   fp_flags, off_flags, 1 /* is_ipsec */);
	}
      else
	*n_segs += 4;
    }
  else
    {
      ptd->buffers[*buffer_next_index] = buffer0;
      *buffer_next_index += 1;

      if (is_fail0)
	{
	  rxp0 = orig_rxp0;
	  /*
	   * Set the outer packet length when IPsec operation is
	   * unsuccessful
	   */
	  buffer0->current_length = olen0;
	}
      else
	{
	  /* Set the inner packet length when IPsec operation is successful */
	  buffer0->current_length = ilen0;

	  frag_cnt0 = cnxk_pktio_reassemble (vm, hdr0, rxp0, ptd, buffer0, b,
					     buffer_next_index, data_off,
					     &olen0, &esp_sz0, l2_ol3_sz0);

	  cnxk_ipsec_update_counters (vm, res0, buffer0, esp_sz0, frag_cnt0);

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	    *n_segs +=
	      cnxk_pktio_chain_segs (vm, orig_rxp0, bt, buffer0, data_off,
				     fp_flags, off_flags, 1 /* is_ipsec */);
	  else
	    *n_segs += 1;
	}

      ptd->buffers[*buffer_next_index] = buffer1;
      *buffer_next_index += 1;

      if (is_fail1)
	{
	  rxp1 = orig_rxp1;
	  buffer1->current_length = olen1;
	}
      else
	{
	  buffer1->current_length = ilen1;

	  frag_cnt1 = cnxk_pktio_reassemble (vm, hdr1, rxp1, ptd, buffer1, b,
					     buffer_next_index, data_off,
					     &olen1, &esp_sz1, l2_ol3_sz1);

	  cnxk_ipsec_update_counters (vm, res1, buffer1, esp_sz1, frag_cnt1);

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	    *n_segs +=
	      cnxk_pktio_chain_segs (vm, orig_rxp1, bt, buffer1, data_off,
				     fp_flags, off_flags, 1 /* is_ipsec */);
	  else
	    *n_segs += 1;
	}

      ptd->buffers[*buffer_next_index] = buffer2;
      *buffer_next_index += 1;

      if (is_fail2)
	{
	  rxp2 = orig_rxp2;
	  buffer2->current_length = olen2;
	}
      else
	{
	  buffer2->current_length = ilen2;

	  frag_cnt2 = cnxk_pktio_reassemble (vm, hdr2, rxp2, ptd, buffer2, b,
					     buffer_next_index, data_off,
					     &olen2, &esp_sz2, l2_ol3_sz2);

	  cnxk_ipsec_update_counters (vm, res2, buffer2, esp_sz2, frag_cnt2);

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	    *n_segs +=
	      cnxk_pktio_chain_segs (vm, orig_rxp2, bt, buffer2, data_off,
				     fp_flags, off_flags, 1 /* is_ipsec */);
	  else
	    *n_segs += 1;
	}

      ptd->buffers[*buffer_next_index] = buffer3;
      *buffer_next_index += 1;

      if (is_fail3)
	{
	  rxp3 = orig_rxp3;
	  buffer3->current_length = olen3;
	}
      else
	{
	  buffer3->current_length = ilen3;

	  frag_cnt3 = cnxk_pktio_reassemble (vm, hdr3, rxp3, ptd, buffer3, b,
					     buffer_next_index, data_off,
					     &olen3, &esp_sz3, l2_ol3_sz3);

	  cnxk_ipsec_update_counters (vm, res3, buffer3, esp_sz3, frag_cnt3);

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	    *n_segs +=
	      cnxk_pktio_chain_segs (vm, orig_rxp3, bt, buffer3, data_off,
				     fp_flags, off_flags, 1 /* is_ipsec */);
	  else
	    *n_segs += 1;
	}
    }
  n_frags_except_first += frag_cnt0 + frag_cnt1 + frag_cnt2 + frag_cnt3 - 4;

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (buffer0);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (buffer1);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (buffer2);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (buffer3);

  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
    {
      b0_err_flags = (rxp0->u[0] >> 20) & 0xFFF;
      b1_err_flags = (rxp1->u[0] >> 20) & 0xFFF;
      b2_err_flags = (rxp2->u[0] >> 20) & 0xFFF;
      b3_err_flags = (rxp3->u[0] >> 20) & 0xFFF;

      ptd->out_flags |=
	b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;
    }

  ptd->out_user_nstats += olen0 + olen1 + olen2 + olen3;

  cnxk_ipsec_inl_data (buffer0)->is_ipsec_op_fail = is_fail0;
  cnxk_ipsec_inl_data (buffer0)->uc_err =
    cnxk_drv_ipsec_inl_get_uc_error_code_march (res0);

  cnxk_ipsec_inl_data (buffer1)->is_ipsec_op_fail = is_fail1;
  cnxk_ipsec_inl_data (buffer1)->uc_err =
    cnxk_drv_ipsec_inl_get_uc_error_code_march (res1);

  cnxk_ipsec_inl_data (buffer2)->is_ipsec_op_fail = is_fail2;
  cnxk_ipsec_inl_data (buffer2)->uc_err =
    cnxk_drv_ipsec_inl_get_uc_error_code_march (res2);

  cnxk_ipsec_inl_data (buffer3)->is_ipsec_op_fail = is_fail3;
  cnxk_ipsec_inl_data (buffer3)->uc_err =
    cnxk_drv_ipsec_inl_get_uc_error_code_march (res3);

  if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
    {
      clib_memcpy_fast (buffer0->pre_data, &rxp0->parse, rx_parse_bytes);
      clib_memcpy_fast (buffer1->pre_data, &rxp1->parse, rx_parse_bytes);
      clib_memcpy_fast (buffer2->pre_data, &rxp2->parse, rx_parse_bytes);
      clib_memcpy_fast (buffer3->pre_data, &rxp3->parse, rx_parse_bytes);
    }

  cnxk_drv_pool_free_inline (mp_index, (void **) &hdr0, 1);
  cnxk_drv_pool_free_inline (mp_index, (void **) &hdr1, 1);
  cnxk_drv_pool_free_inline (mp_index, (void **) &hdr2, 1);
  cnxk_drv_pool_free_inline (mp_index, (void **) &hdr3, 1);

  return n_frags_except_first;
}

static_always_inline i32
cnxk_pkts_recv_process_burst (vlib_main_t *vm, vlib_node_runtime_t *node,
			      cnxk_per_thread_data_t *ptd, cnxk_fprq_t *fprq,
			      u32 head, u32 req_pkts, const u64 fp_flags,
			      const u64 off_flags)
{
  vlib_buffer_t **b = ptd->buffers + ptd->buffer_start_index;
  const u16 rx_parse_bytes = sizeof (union nix_rx_parse_u);
  cnxk_pktio_nix_parse_t *rxp0, *rxp1, *rxp2, *rxp3;
  u16 buffer_next_index = 0, n_processed_pkts = 0;
  struct cpt_parse_hdr_s *cpt0_hdr, *cpt1_hdr;
  struct cpt_parse_hdr_s *cpt2_hdr, *cpt3_hdr;
  u64 *cq0_hdr, *cq1_hdr, *cq2_hdr, *cq3_hdr;
  u32 qmask, head_cnt, n_left, n_segs = 0;
  u32 b0_err_flags = 0, b1_err_flags = 0;
  u32 b2_err_flags = 0, b3_err_flags = 0;
  u32 is_b0_from_cpt, is_b1_from_cpt;
  u32 is_b2_from_cpt, is_b3_from_cpt;
  vlib_buffer_t *buffer0, *buffer1;
  vlib_buffer_t *buffer2, *buffer3;
  i32 data_off = fprq->data_off;
  u32 n_frags_except_first = 0;
  vlib_buffer_t **start_buffer;
  uintptr_t desc = fprq->desc;
  u64 *wqe0_ptr, *wqe1_ptr;
  u64 *wqe2_ptr, *wqe3_ptr;
  u16 i = 0, bp_index;
  u32 n_from_cpt = 0;
  vlib_buffer_t *bt;
  u16 mp_index;

  bt = &ptd->buffer_template;
  vnet_buffer (bt)->sw_if_index[VLIB_RX] = fprq->pktio_rx_sw_if_index;
  bt->buffer_pool_index = bp_index = fprq->vlib_buffer_pool_index;
  bt->current_data = 0;

  if (roc_errata_nix_no_meta_aura ())
    mp_index = bp_index;
  else
    mp_index = cnxk_pool_get_meta_index ();

  qmask = fprq->qmask;
  n_left = req_pkts;
  head_cnt = head;

  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
    ptd->out_flags = 0;

  while (n_left > 8)
    {
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 4) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 5) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 6) & qmask) * CNXK_NIX_CQ_SZ));
      cnxk_prefetch_non_temporal (
	(void *) (desc + ((head + i + 7) & qmask) * CNXK_NIX_CQ_SZ));

      cq0_hdr = (u64 *) (desc + ((head + i) & qmask) * CNXK_NIX_CQ_SZ);
      cq1_hdr = (u64 *) (desc + ((head + i + 1) & qmask) * CNXK_NIX_CQ_SZ);
      cq2_hdr = (u64 *) (desc + ((head + i + 2) & qmask) * CNXK_NIX_CQ_SZ);
      cq3_hdr = (u64 *) (desc + ((head + i + 3) & qmask) * CNXK_NIX_CQ_SZ);

      rxp0 = (cnxk_pktio_nix_parse_t *) (cq0_hdr + 1);
      rxp1 = (cnxk_pktio_nix_parse_t *) (cq1_hdr + 1);
      rxp2 = (cnxk_pktio_nix_parse_t *) (cq2_hdr + 1);
      rxp3 = (cnxk_pktio_nix_parse_t *) (cq3_hdr + 1);

      is_b0_from_cpt = cnxk_pktio_is_packet_from_cpt_march (rxp0);
      is_b1_from_cpt = cnxk_pktio_is_packet_from_cpt_march (rxp1);
      is_b2_from_cpt = cnxk_pktio_is_packet_from_cpt_march (rxp2);
      is_b3_from_cpt = cnxk_pktio_is_packet_from_cpt_march (rxp3);

      n_from_cpt =
	is_b0_from_cpt + is_b1_from_cpt + is_b2_from_cpt + is_b3_from_cpt;

      if (n_from_cpt == 0)
	{
	  /* None of the 4 packets are from CPT */
	  b[0] = (vlib_buffer_t *) (*(cq0_hdr + 9) - data_off);
	  b[1] = (vlib_buffer_t *) (*(cq1_hdr + 9) - data_off);
	  b[2] = (vlib_buffer_t *) (*(cq2_hdr + 9) - data_off);
	  b[3] = (vlib_buffer_t *) (*(cq3_hdr + 9) - data_off);

	  cnxk_pktio_verify_rx_vlib (vm, b[0]);
	  cnxk_pktio_verify_rx_vlib (vm, b[1]);
	  cnxk_pktio_verify_rx_vlib (vm, b[2]);
	  cnxk_pktio_verify_rx_vlib (vm, b[3]);

	  vlib_buffer_copy_template (b[0], bt);
	  vlib_buffer_copy_template (b[1], bt);
	  vlib_buffer_copy_template (b[2], bt);
	  vlib_buffer_copy_template (b[3], bt);

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[0]);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[1]);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[2]);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b[3]);

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_OUTER_CKSUM)
	    {
	      b0_err_flags = (rxp0->u[0] >> 20) & 0xFFF;
	      b1_err_flags = (rxp1->u[0] >> 20) & 0xFFF;
	      b2_err_flags = (rxp2->u[0] >> 20) & 0xFFF;
	      b3_err_flags = (rxp3->u[0] >> 20) & 0xFFF;

	      ptd->out_flags |=
		b0_err_flags | b1_err_flags | b2_err_flags | b3_err_flags;
	    }

	  b[0]->flow_id = rxp0->u[3] >> 48;
	  b[1]->flow_id = rxp1->u[3] >> 48;
	  b[2]->flow_id = rxp2->u[3] >> 48;
	  b[3]->flow_id = rxp3->u[3] >> 48;

	  b[0]->current_length = (rxp0->u[1] & 0xFFFF) + 1;
	  b[1]->current_length = (rxp1->u[1] & 0xFFFF) + 1;
	  b[2]->current_length = (rxp2->u[1] & 0xFFFF) + 1;
	  b[3]->current_length = (rxp3->u[1] & 0xFFFF) + 1;

	  ptd->out_user_nstats += b[0]->current_length + b[1]->current_length +
				  b[2]->current_length + b[3]->current_length;

	  if (fp_flags & CNXK_PKTIO_FP_FLAG_TRACE_EN)
	    {
	      clib_memcpy_fast (b[0]->pre_data, &rxp0->parse, rx_parse_bytes);
	      clib_memcpy_fast (b[1]->pre_data, &rxp1->parse, rx_parse_bytes);
	      clib_memcpy_fast (b[2]->pre_data, &rxp2->parse, rx_parse_bytes);
	      clib_memcpy_fast (b[3]->pre_data, &rxp3->parse, rx_parse_bytes);
	    }
	  buffer_next_index += 4;
	  buffer0 = b[0];
	  buffer1 = b[1];
	  buffer2 = b[2];
	  buffer3 = b[3];

	  if (off_flags & CNXK_PKTIO_RX_OFF_FLAG_MSEG)
	    {
	      n_segs +=
		cnxk_pktio_chain_segs (vm, rxp0, bt, buffer0, data_off,
				       fp_flags, off_flags, 0 /* is_ipsec */);
	      n_segs +=
		cnxk_pktio_chain_segs (vm, rxp1, bt, buffer1, data_off,
				       fp_flags, off_flags, 0 /* is_ipsec */);
	      n_segs +=
		cnxk_pktio_chain_segs (vm, rxp2, bt, buffer2, data_off,
				       fp_flags, off_flags, 0 /* is_ipsec */);
	      n_segs +=
		cnxk_pktio_chain_segs (vm, rxp3, bt, buffer3, data_off,
				       fp_flags, off_flags, 0 /* is_ipsec */);
	    }
	  else
	    n_segs += 4;
	}
      else if (n_from_cpt == 4)
	{
	  /* All 4 packets are from cpt */
	  cpt0_hdr = (struct cpt_parse_hdr_s *) *(cq0_hdr + 9);
	  cpt1_hdr = (struct cpt_parse_hdr_s *) *(cq1_hdr + 9);
	  cpt2_hdr = (struct cpt_parse_hdr_s *) *(cq2_hdr + 9);
	  cpt3_hdr = (struct cpt_parse_hdr_s *) *(cq3_hdr + 9);

	  wqe0_ptr = (u64 *) clib_net_to_host_u64 (cpt0_hdr->wqe_ptr);
	  wqe1_ptr = (u64 *) clib_net_to_host_u64 (cpt1_hdr->wqe_ptr);
	  wqe2_ptr = (u64 *) clib_net_to_host_u64 (cpt2_hdr->wqe_ptr);
	  wqe3_ptr = (u64 *) clib_net_to_host_u64 (cpt3_hdr->wqe_ptr);

	  buffer0 = (vlib_buffer_t *) (*(wqe0_ptr + 9) - data_off);
	  buffer1 = (vlib_buffer_t *) (*(wqe1_ptr + 9) - data_off);
	  buffer2 = (vlib_buffer_t *) (*(wqe2_ptr + 9) - data_off);
	  buffer3 = (vlib_buffer_t *) (*(wqe3_ptr + 9) - data_off);

	  n_frags_except_first += cnxk_pktio_process_ipsec_pkts_x4 (
	    vm, rxp0, rxp1, rxp2, rxp3, cpt0_hdr, cpt1_hdr, cpt2_hdr, cpt3_hdr,
	    ptd, b, fp_flags, mp_index, data_off, off_flags,
	    &buffer_next_index, &n_segs);
	}
      else
	{
	  /* CQ ring contains mix of packets from wire and CPT */

	  start_buffer = &ptd->buffers[buffer_next_index];
	  buffer_next_index += 1;
	  buffer0 = cnxk_pktio_init_vlib_from_cq (
	    vm, data_off, cq0_hdr, rxp0, bt, ptd, fprq, start_buffer,
	    &buffer_next_index, mp_index, fp_flags, off_flags,
	    &n_frags_except_first, &n_segs);
	  start_buffer[0] = buffer0;

	  start_buffer = &ptd->buffers[buffer_next_index];
	  buffer_next_index += 1;
	  buffer1 = cnxk_pktio_init_vlib_from_cq (
	    vm, data_off, cq1_hdr, rxp1, bt, ptd, fprq, start_buffer,
	    &buffer_next_index, mp_index, fp_flags, off_flags,
	    &n_frags_except_first, &n_segs);
	  start_buffer[0] = buffer1;

	  start_buffer = &ptd->buffers[buffer_next_index];
	  buffer_next_index += 1;

	  buffer2 = cnxk_pktio_init_vlib_from_cq (
	    vm, data_off, cq2_hdr, rxp2, bt, ptd, fprq, start_buffer,
	    &buffer_next_index, mp_index, fp_flags, off_flags,
	    &n_frags_except_first, &n_segs);
	  start_buffer[0] = buffer2;

	  start_buffer = &ptd->buffers[buffer_next_index];
	  buffer_next_index += 1;
	  buffer3 = cnxk_pktio_init_vlib_from_cq (
	    vm, data_off, cq3_hdr, rxp3, bt, ptd, fprq, start_buffer,
	    &buffer_next_index, mp_index, fp_flags, off_flags,
	    &n_frags_except_first, &n_segs);
	  start_buffer[0] = buffer3;
	}

      n_segs += n_frags_except_first;

      i += 4;
      b = &ptd->buffers[buffer_next_index];
      n_left -= 4;
      head_cnt += 4;
      n_frags_except_first = 0;
    }

  while (n_left)
    {
      cq0_hdr = (u64 *) (desc + ((head + i) & qmask) * CNXK_NIX_CQ_SZ);
      rxp0 = (cnxk_pktio_nix_parse_t *) (cq0_hdr + 1);

      start_buffer = &ptd->buffers[buffer_next_index];
      buffer_next_index += 1;
      b[0] = cnxk_pktio_init_vlib_from_cq (
	vm, data_off, cq0_hdr, rxp0, bt, ptd, fprq, start_buffer,
	&buffer_next_index, mp_index, fp_flags, off_flags,
	&n_frags_except_first, &n_segs);

      n_segs += n_frags_except_first;

      i += 1;
      b = &ptd->buffers[buffer_next_index];
      n_left -= 1;
      head_cnt += 1;
      n_frags_except_first = 0;
      n_processed_pkts += buffer_next_index;
    }

  n_processed_pkts = buffer_next_index;

  /* All packets belongs to same pool index */
  cnxk_pktpool_update_refill_count (vm, ptd, n_segs, bp_index);

  fprq->cached_pkts -= req_pkts;
  fprq->head = head_cnt;

  ptd->buffer_start_index += n_processed_pkts;

  return n_processed_pkts;
}

static_always_inline u32
cnxk_pktio_rq_peek (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rqid,
		    u16 req_pkts, cnxk_per_thread_data_t *ptd,
		    const u64 fp_flags)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_t *pktio;
  cnxk_fprq_t *fprq;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;
  fprq = vec_elt_at_index (pktio->fprqs, rqid);

  return cnxk_cqe_cached_pkts_get (pktio, fprq, req_pkts, fp_flags);
}

static_always_inline i32
cnxk_pkts_recv_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		       cnxk_pktio_t *pktio, cnxk_fprq_t *fprq, u16 req_pkts,
		       cnxk_per_thread_data_t *ptd, const u64 fp_flags,
		       const u64 off_flags, const u16 enable_poll_retry)
{
  u16 rx_pkts = 0, n_processed_pkts = 0;

  ptd->buffer_start_index = 0;
  ptd->out_user_nstats = 0;

  if (enable_poll_retry)
    {
      rx_pkts = cnxk_cqe_cached_pkts_get (pktio, fprq, req_pkts, fp_flags);

      if (PREDICT_FALSE (rx_pkts < fprq->rxq_min_vec_size))
	{
	  if (!rx_pkts)
	    return 0;

	  fprq->retry_count++;
	  fprq->retry_count %= (fprq->rxq_max_poll_retries + 1);

	  if (PREDICT_FALSE (fprq->retry_count))
	    return n_processed_pkts;
	}
      fprq->retry_count = 0;
      n_processed_pkts = cnxk_pkts_recv_process_burst (
	vm, node, ptd, fprq, fprq->head, rx_pkts, fp_flags, off_flags);

      cnxk_pktio_cq_door_bell_update (fprq, rx_pkts);
    }
  else
    {
      while (n_processed_pkts < req_pkts)
	{
	  rx_pkts = cnxk_cqe_cached_pkts_get (
	    pktio, fprq, req_pkts - n_processed_pkts, fp_flags);

	  if (PREDICT_FALSE (!rx_pkts))
	    break;
	  n_processed_pkts += cnxk_pkts_recv_process_burst (
	    vm, node, ptd, fprq, fprq->head, rx_pkts, fp_flags, off_flags);

	  cnxk_pktio_cq_door_bell_update (fprq, rx_pkts);

	  if (rx_pkts < fprq->rxq_min_vec_size)
	    break;
	}
    }
  return n_processed_pkts;
}

static_always_inline i32
cnxk_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node, u32 rqid,
		u16 req_pkts, cnxk_per_thread_data_t *ptd, const u64 fp_flags,
		const u64 off_flags)
{
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_pktio_t *pktio;
  cnxk_fprq_t *fprq;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;
  fprq = vec_elt_at_index (pktio->fprqs, rqid);

  if (fprq->rxq_max_poll_retries)
    return cnxk_pkts_recv_inline (vm, node, pktio, fprq, req_pkts, ptd,
				  fp_flags, off_flags, 1);

  return cnxk_pkts_recv_inline (vm, node, pktio, fprq, req_pkts, ptd, fp_flags,
				off_flags, 0);
}

#endif /* included_onp_drv_modules_pktio_pktio_rx_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
