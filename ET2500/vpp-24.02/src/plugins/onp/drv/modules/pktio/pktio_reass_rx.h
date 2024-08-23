/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_reass_rx_h
#define included_onp_drv_modules_pktio_pktio_reass_rx_h

#include <onp/drv/modules/pktio/pktio_priv.h>

/*
 * Read upto 4 fragments in case of successful reassembly.
 * Fragments which are further segmented are not
 * supported currently.
 */
static_always_inline u8
cnxk_pktio_reassemble_success (vlib_main_t *vm, struct cpt_parse_hdr_s *hdr,
			       cnxk_pktio_nix_parse_t *rxp_meta,
			       cnxk_per_thread_data_t *ptd, vlib_buffer_t *buf,
			       u16 data_off, u32 *olen, u32 *esp_len,
			       u32 l2_ol3_hdr_size)
{
  cnxk_pktio_nix_parse_t *rxp_ptr2, *rxp_ptr3;
  cnxk_pktio_nix_parse_t *rxp_ptr, *rxp_ptr1;
  u16 frag_size1, frag_size2, frag_size3;
  vlib_buffer_t *bt, *b0, *b1, *b2, *b3;
  struct cpt_frag_info_s *frag_info;
  u32 offset, l2_l3_inner_hdr_size;
  u64 *wqe_ptr2, *wqe_ptr3;
  u64 *wqe_ptr, *wqe_ptr1;
  uint64_t *frag_ptr;
  u8 frag_cnt;

  wqe_ptr = (u64 *) clib_net_to_host_u64 (hdr->wqe_ptr);
  rxp_ptr = (cnxk_pktio_nix_parse_t *) (wqe_ptr + 1);
  ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr) == 1);

  l2_l3_inner_hdr_size = rxp_meta->parse.ldptr - rxp_meta->parse.laptr;
  frag_cnt = hdr->w0.num_frags;
  bt = &ptd->buffer_template;

  buf->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  buf->total_length_not_including_first_buffer = 0;
  b0 = buf;

  /*
   * fi_offset is 8B offset from cpt_parse_hdr_s + fi_pad to frag_info_s.
   * fi_offset 0 indicates 256B.
   */
  offset = hdr->w2.fi_offset;
  offset = (((offset - 1) & 0x1f) + 1) * 8;
  frag_info = PLT_PTR_ADD (hdr, offset);

  if (frag_cnt == 2)
    {
      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      vlib_buffer_copy_template (b1, bt);

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b1->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b0->next_buffer = vlib_get_buffer_index (vm, b1);

      return 2;
    }

  if (PREDICT_FALSE (frag_cnt == 3))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      frag_size2 = clib_net_to_host_u16 (frag_info->w1.frag_size2);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);

      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      b2 = (vlib_buffer_t *) (*(wqe_ptr2 + 9) - data_off);

      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (cnxk_pktio_nix_parse_t *) (wqe_ptr2 + 1);

      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr2) == 1);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      cnxk_pktio_verify_rx_vlib (vm, b2);

      vlib_buffer_copy_template (b1, bt);
      vlib_buffer_copy_template (b2, bt);

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *olen += rxp_ptr2->parse.pkt_lenm1 + 1;

      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b2->current_length = frag_size2;
      b1->current_data = l2_l3_inner_hdr_size;
      b2->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->total_length_not_including_first_buffer += b2->current_length;

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b1->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b0->next_buffer = vlib_get_buffer_index (vm, b1);
      b1->next_buffer = vlib_get_buffer_index (vm, b2);

      return 3;
    }

  if (PREDICT_FALSE (frag_cnt == 4))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      frag_size1 = clib_net_to_host_u16 (frag_info->w1.frag_size1);
      frag_size2 = clib_net_to_host_u16 (frag_info->w1.frag_size2);
      frag_size3 = clib_net_to_host_u16 (frag_info->w1.frag_size3);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);
      wqe_ptr3 = (u64 *) clib_net_to_host_u64 (*(frag_ptr + 1));

      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      b2 = (vlib_buffer_t *) (*(wqe_ptr2 + 9) - data_off);
      b3 = (vlib_buffer_t *) (*(wqe_ptr3 + 9) - data_off);

      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (cnxk_pktio_nix_parse_t *) (wqe_ptr2 + 1);
      rxp_ptr3 = (cnxk_pktio_nix_parse_t *) (wqe_ptr3 + 1);

      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr2) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr3) == 1);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      cnxk_pktio_verify_rx_vlib (vm, b2);
      cnxk_pktio_verify_rx_vlib (vm, b3);

      vlib_buffer_copy_template (b1, bt);
      vlib_buffer_copy_template (b2, bt);
      vlib_buffer_copy_template (b3, bt);

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *olen += rxp_ptr2->parse.pkt_lenm1 + 1;
      *olen += rxp_ptr3->parse.pkt_lenm1 + 1;

      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr3->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      b1->current_length = frag_size1;
      b2->current_length = frag_size2;
      b3->current_length = frag_size3;
      b1->current_data = l2_l3_inner_hdr_size;
      b2->current_data = l2_l3_inner_hdr_size;
      b3->current_data = l2_l3_inner_hdr_size;

      b0->total_length_not_including_first_buffer += b1->current_length;
      b0->total_length_not_including_first_buffer += b2->current_length;
      b0->total_length_not_including_first_buffer += b3->current_length;

      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b1->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b2->flags |= VLIB_BUFFER_NEXT_PRESENT;

      b0->next_buffer = vlib_get_buffer_index (vm, b1);
      b1->next_buffer = vlib_get_buffer_index (vm, b2);
      b2->next_buffer = vlib_get_buffer_index (vm, b3);

      return 4;
    }

  return frag_cnt;
}

/*
 * Reassemble failure cases. Read upto 4 fragments.
 * Append them to the buffer list.
 * Fragments which are further segmented are not
 * supported currently.
 * */
static_always_inline u8
cnxk_pktio_reassemble_failure (vlib_main_t *vm, struct cpt_parse_hdr_s *hdr,
			       cnxk_per_thread_data_t *ptd,
			       vlib_buffer_t **buf, u16 *next, u16 data_off,
			       u32 *olen, u32 *esp_len, u32 l2_ol3_hdr_size)
{
  cnxk_pktio_nix_parse_t *rxp_ptr2, *rxp_ptr3;
  cnxk_pktio_nix_parse_t *rxp_ptr, *rxp_ptr1;
  union cpt_res_s *res1, *res2, *res3;
  struct cpt_frag_info_s *frag_info;
  vlib_buffer_t *b1, *b2, *b3;
  u32 l2_sz1, l2_sz2, l2_sz3;
  u64 *wqe_ptr2, *wqe_ptr3;
  u64 *wqe_ptr, *wqe_ptr1;
  uint64_t *frag_ptr;
  vlib_buffer_t *bt;
  uint32_t offset;
  u8 frag_cnt;

  wqe_ptr = (u64 *) clib_net_to_host_u64 (hdr->wqe_ptr);
  rxp_ptr = (cnxk_pktio_nix_parse_t *) (wqe_ptr + 1);
  ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr) == 1);

  frag_cnt = hdr->w0.num_frags;
  bt = &ptd->buffer_template;

  /*
   * fi_offset is 8B offset from cpt_parse_hdr_s + fi_pad to frag_info_s.
   * fi_offset 0 indicates 256B.
   */
  offset = hdr->w2.fi_offset;
  offset = (((offset - 1) & 0x1f) + 1) * 8;
  frag_info = PLT_PTR_ADD (hdr, offset);

  if (frag_cnt == 2)
    {
      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);
      res1 = (union cpt_res_s *) (wqe_ptr1 + 10);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      vlib_buffer_copy_template (b1, bt);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);

      l2_sz1 = rxp_ptr1->parse.lcptr - rxp_ptr1->parse.laptr;
      b1->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res1) + l2_sz1;
      b1->current_data = 0;
      cnxk_ipsec_inl_data (b1)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b1)->uc_err = 0;

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      ptd->buffers[*next] = b1;
      *next = *next + 1;

      return 2;
    }

  if (PREDICT_FALSE (frag_cnt == 3))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);

      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      b2 = (vlib_buffer_t *) (*(wqe_ptr2 + 9) - data_off);

      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (cnxk_pktio_nix_parse_t *) (wqe_ptr2 + 1);

      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr2) == 1);

      res1 = (union cpt_res_s *) (wqe_ptr1 + 10);
      res2 = (union cpt_res_s *) (wqe_ptr2 + 10);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      cnxk_pktio_verify_rx_vlib (vm, b2);

      vlib_buffer_copy_template (b1, bt);
      vlib_buffer_copy_template (b2, bt);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);

      l2_sz1 = rxp_ptr1->parse.lcptr - rxp_ptr1->parse.laptr;
      l2_sz2 = rxp_ptr2->parse.lcptr - rxp_ptr2->parse.laptr;

      b1->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res1) + l2_sz1;
      b2->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res2) + l2_sz2;
      b1->current_data = 0;
      b2->current_data = 0;

      cnxk_ipsec_inl_data (b1)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b2)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b1)->uc_err = 0;
      cnxk_ipsec_inl_data (b2)->uc_err = 0;

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *olen += rxp_ptr2->parse.pkt_lenm1 + 1;
      *esp_len += rxp_ptr2->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      ptd->buffers[*next] = b1;
      ptd->buffers[*next + 1] = b2;
      *next = *next + 2;

      return 3;
    }

  if (PREDICT_FALSE (frag_cnt == 4))
    {
      frag_ptr = (uint64_t *) (frag_info + 1);

      wqe_ptr1 = (u64 *) clib_net_to_host_u64 (hdr->frag1_wqe_ptr);
      wqe_ptr2 = (u64 *) clib_net_to_host_u64 (*frag_ptr);
      wqe_ptr3 = (u64 *) clib_net_to_host_u64 (*(frag_ptr + 1));
      b1 = (vlib_buffer_t *) (*(wqe_ptr1 + 9) - data_off);
      b2 = (vlib_buffer_t *) (*(wqe_ptr2 + 9) - data_off);
      b3 = (vlib_buffer_t *) (*(wqe_ptr3 + 9) - data_off);
      rxp_ptr1 = (cnxk_pktio_nix_parse_t *) (wqe_ptr1 + 1);
      rxp_ptr2 = (cnxk_pktio_nix_parse_t *) (wqe_ptr2 + 1);
      rxp_ptr3 = (cnxk_pktio_nix_parse_t *) (wqe_ptr3 + 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr1) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr2) == 1);
      ASSERT (cnxk_pktio_n_segs (vm, rxp_ptr3) == 1);
      res1 = (union cpt_res_s *) (wqe_ptr1 + 10);
      res2 = (union cpt_res_s *) (wqe_ptr2 + 10);
      res3 = (union cpt_res_s *) (wqe_ptr3 + 10);

      cnxk_pktio_verify_rx_vlib (vm, b1);
      cnxk_pktio_verify_rx_vlib (vm, b2);
      cnxk_pktio_verify_rx_vlib (vm, b3);

      vlib_buffer_copy_template (b1, bt);
      vlib_buffer_copy_template (b2, bt);
      vlib_buffer_copy_template (b3, bt);

      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
      VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

      l2_sz1 = rxp_ptr1->parse.lcptr - rxp_ptr1->parse.laptr;
      l2_sz2 = rxp_ptr2->parse.lcptr - rxp_ptr2->parse.laptr;
      l2_sz3 = rxp_ptr3->parse.lcptr - rxp_ptr3->parse.laptr;

      b1->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res1) + l2_sz1;
      b2->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res2) + l2_sz2;
      b3->current_length = cnxk_drv_ipsec_inl_get_rlen_march (res3) + l2_sz3;
      b1->current_data = 0;
      b2->current_data = 0;
      b3->current_data = 0;
      cnxk_ipsec_inl_data (b1)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b2)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b3)->is_ipsec_op_fail = 0;
      cnxk_ipsec_inl_data (b1)->uc_err = 0;
      cnxk_ipsec_inl_data (b2)->uc_err = 0;
      cnxk_ipsec_inl_data (b3)->uc_err = 0;

      *olen += rxp_ptr1->parse.pkt_lenm1 + 1;
      *olen += rxp_ptr2->parse.pkt_lenm1 + 1;
      *olen += rxp_ptr3->parse.pkt_lenm1 + 1;
      *esp_len += rxp_ptr1->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr2->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;
      *esp_len += rxp_ptr3->parse.pkt_lenm1 + 1 - l2_ol3_hdr_size;

      ptd->buffers[*next] = b1;
      ptd->buffers[*next + 1] = b2;
      ptd->buffers[*next + 2] = b3;
      *next = *next + 3;

      return 4;
    }

  return frag_cnt;
}

static_always_inline u8
cnxk_pktio_reassemble (vlib_main_t *vm, struct cpt_parse_hdr_s *cpt_hdr,
		       cnxk_pktio_nix_parse_t *rxp_meta,
		       cnxk_per_thread_data_t *ptd, vlib_buffer_t *b,
		       vlib_buffer_t **buf, u16 *buffer_next_index,
		       u16 data_off, u32 *olen, u32 *esp_len,
		       u32 l2_ol3_hdr_size)
{
  if ((cpt_hdr->w0.num_frags) && !(cpt_hdr->w0.reas_sts))
    return cnxk_pktio_reassemble_success (
      vm, cpt_hdr, rxp_meta, ptd, b, data_off, olen, esp_len, l2_ol3_hdr_size);
  else if (cpt_hdr->w0.reas_sts)
    return cnxk_pktio_reassemble_failure (vm, cpt_hdr, ptd, buf,
					  buffer_next_index, data_off, olen,
					  esp_len, l2_ol3_hdr_size);
  else
    return 1;
}

#endif /* included_onp_drv_modules_pktio_pktio_reass_rx_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
