/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_pktio_pktio_fp_tx_cn9k_h
#define included_onp_drv_modules_pktio_pktio_fp_tx_cn9k_h

#include <onp/drv/modules/pktio/pktio_tx.h>

static_always_inline void
cn9k_lmt_copy (void *lmt_addr, u64 io_addr, u64 *desc, u64 dwords)
{
  u64 lmt_status;

  do
    {
      roc_lmt_mov_seg (lmt_addr, desc, dwords);
      lmt_status = roc_lmt_submit_ldeor (io_addr);
    }
  while (lmt_status == 0);
}

static_always_inline u64
cn9k_pktio_add_sg_desc (union nix_send_sg_s *sg, int n_segs,
			vlib_buffer_t *seg1, vlib_buffer_t *seg2,
			vlib_buffer_t *seg3)
{
  sg[0].u = 0;
  sg[0].segs = n_segs;
  sg[0].subdc = NIX_SUBDC_SG;

  switch (n_segs)
    {
    case 3:
      sg[0].seg3_size = seg3->current_length;
      sg[3].u = (u64) vlib_buffer_get_current (seg3);
      /* Fall through */
    case 2:
      sg[0].seg2_size = seg2->current_length;
      sg[2].u = (u64) vlib_buffer_get_current (seg2);
      /* Fall through */
    case 1:
      sg[0].seg1_size = seg1->current_length;
      sg[1].u = (u64) vlib_buffer_get_current (seg1);
      break;
    default:
      ASSERT (0);
      return 0;
    }

  /* Return number of dwords in sub-descriptor */
  return n_segs == 1 ? 1 : 2;
}

static_always_inline u64
cn9k_pktio_add_sg_list (union nix_send_sg_s *sg, vlib_buffer_t *b, u64 n_segs,
			const u64 off_flags)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_buffer_t *seg1, *seg2, *seg3;
  u64 n_dwords;

  if (!(off_flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG))
    return cn9k_pktio_add_sg_desc (sg, 1, b, NULL, NULL);

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_NEXT_PRESENT)))
    return cn9k_pktio_add_sg_desc (sg, 1, b, NULL, NULL);

  seg1 = b;
  n_dwords = 0;
  while (n_segs > 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      seg3 = vlib_get_buffer (vm, seg2->next_buffer);

      n_dwords += cn9k_pktio_add_sg_desc (sg, 3, seg1, seg2, seg3);

      if (seg3->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  seg1 = vlib_get_buffer (vm, seg3->next_buffer);
	  sg += 4;
	}
      n_segs -= 3;
    }

  if (n_segs == 1)
    n_dwords += cn9k_pktio_add_sg_desc (sg, 1, seg1, NULL, NULL);
  else if (n_segs == 2)
    {
      seg2 = vlib_get_buffer (vm, seg1->next_buffer);
      n_dwords += cn9k_pktio_add_sg_desc (sg, 2, seg1, seg2, NULL);
    }

  return n_dwords;
}

static_always_inline u64
cn9k_pktio_add_send_hdr (struct nix_send_hdr_s *hdr, vlib_buffer_t *b,
			 u64 aura_handle, u64 sq, u64 n_dwords,
			 const u64 off_flags)
{
  vnet_buffer_oflags_t oflags;

  hdr->w0.u = 0;
  hdr->w1.u = 0;
  hdr->w0.sq = sq;
  hdr->w0.aura = roc_npa_aura_handle_to_aura (aura_handle);
  hdr->w0.total = b->current_length;
  hdr->w0.sizem1 = n_dwords + CNXK_PKTIO_SEND_HDR_DWORDS - 1;

  if (off_flags & CNXK_PKTIO_TX_OFF_FLAG_MSEG)
    hdr->w0.total = vlib_buffer_length_in_chain (vlib_get_main (), b);

  if (!(b->flags & VNET_BUFFER_F_OFFLOAD))
    return CNXK_PKTIO_SEND_HDR_DWORDS;

  if (off_flags & CNXK_PKTIO_TX_OFF_FLAG_OUTER_CKSUM)
    {
      oflags = vnet_buffer (b)->oflags;
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	{
	  hdr->w1.ol3type = CNXK_PKTIO_NIX_SEND_L3TYPE_IP4_CKSUM;
	  hdr->w1.ol3ptr = vnet_buffer (b)->l3_hdr_offset;
	  hdr->w1.ol4ptr =
	    vnet_buffer (b)->l3_hdr_offset + sizeof (ip4_header_t);
	}

      if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  hdr->w1.ol4type = CNXK_PKTIO_NIX_SEND_L4TYPE_UDP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset;
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  hdr->w1.ol4type = CNXK_PKTIO_NIX_SEND_L4TYPE_TCP_CKSUM;
	  hdr->w1.ol4ptr = vnet_buffer (b)->l4_hdr_offset;
	}
    }

  return CNXK_PKTIO_SEND_HDR_DWORDS;
}

i32 static_always_inline
cn9k_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node, u32 txq,
		u16 tx_pkts, cnxk_per_thread_data_t *ptd, const u32 desc_sz,
		const u64 fp_flags, const u64 off_flags)
{
  u64 desc0[desc_sz], desc1[desc_sz], desc2[desc_sz], desc3[desc_sz];
  u64 aura_handle[4], n_segs[4], n_packets;
  u64 cached_aura = ~0, io_addr, sq_handle, n_dwords[4];
  struct nix_send_hdr_s *send_hdr0, *send_hdr1;
  struct nix_send_hdr_s *send_hdr2, *send_hdr3;
  union nix_send_sg_s *sg0, *sg1, *sg2, *sg3;
  cnxk_pktio_ops_map_t *pktio_ops;
  u8 cached_bp_index = ~0;
  u16 refill_counter = 0;
  struct roc_nix_sq *sq;
  cnxk_pktio_t *pktio;
  cnxk_fpsq_t *fpsq;
  vlib_buffer_t **b;
  void *lmt_addr;

  pktio_ops = cnxk_pktio_get_pktio_ops (ptd->pktio_index);
  pktio = &pktio_ops->pktio;

  sq = &pktio->sqs[txq];
  lmt_addr = sq->lmt_addr;
  io_addr = sq->io_addr;

  fpsq = vec_elt_at_index (pktio->fpsqs, txq);
  sq_handle = fpsq->sq_id;

  b = ptd->buffers;

  /*
   *  if (fp_flags & CNXK_PKTIO_MODE_OP_FLAG_VWQE_SIM)
   *  __cn9k_sched_lock (vm, CNXK_SCHED_LOCK_HEAD_WAIT);
   */

  while (fpsq->cached_pkts < tx_pkts)
  {
      fpsq->cached_pkts = (sq->nb_sqb_bufs_adj - *((uint64_t *) sq->fc))
			  << sq->sqes_per_sqb_log2;

      if (PREDICT_FALSE (fpsq->cached_pkts < tx_pkts))
        {
          if (fpsq->cached_pkts < 0)
          {
            return 0;
          }

          continue;
        }
  }

  send_hdr0 = (struct nix_send_hdr_s *) &desc0[0];
  send_hdr1 = (struct nix_send_hdr_s *) &desc1[0];
  send_hdr2 = (struct nix_send_hdr_s *) &desc2[0];
  send_hdr3 = (struct nix_send_hdr_s *) &desc3[0];

  sg0 = (union nix_send_sg_s *) &desc0[2];
  sg1 = (union nix_send_sg_s *) &desc1[2];
  sg2 = (union nix_send_sg_s *) &desc2[2];
  sg3 = (union nix_send_sg_s *) &desc3[2];

  n_packets = tx_pkts;

  while (n_packets > 11)
    {

      if (n_packets >= 8)
	{
	  vlib_prefetch_buffer_header (b[4], LOAD);
	  vlib_prefetch_buffer_header (b[5], LOAD);
	  vlib_prefetch_buffer_header (b[6], LOAD);
	  vlib_prefetch_buffer_header (b[7], LOAD);
	}

      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);
      n_segs[1] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[1], off_flags);
      n_segs[2] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[2], off_flags);
      n_segs[3] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[3], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[1] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[1], n_segs[1], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[2] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[2], n_segs[2], &cached_aura,
				    &cached_bp_index, &refill_counter);
      aura_handle[3] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[3], n_segs[3], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn9k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[1] = cn9k_pktio_add_sg_list (sg1, b[1], n_segs[1], off_flags);
      n_dwords[2] = cn9k_pktio_add_sg_list (sg2, b[2], n_segs[2], off_flags);
      n_dwords[3] = cn9k_pktio_add_sg_list (sg3, b[3], n_segs[3], off_flags);

      n_dwords[0] += cn9k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);
      n_dwords[1] += cn9k_pktio_add_send_hdr (
	send_hdr1, b[1], aura_handle[1], sq_handle, n_dwords[1], off_flags);
      n_dwords[2] += cn9k_pktio_add_send_hdr (
	send_hdr2, b[2], aura_handle[2], sq_handle, n_dwords[2], off_flags);
      n_dwords[3] += cn9k_pktio_add_send_hdr (
	send_hdr3, b[3], aura_handle[3], sq_handle, n_dwords[3], off_flags);

      cn9k_lmt_copy (lmt_addr, io_addr, desc0, n_dwords[0]);
      cn9k_lmt_copy (lmt_addr, io_addr, desc1, n_dwords[1]);
      cn9k_lmt_copy (lmt_addr, io_addr, desc2, n_dwords[2]);
      cn9k_lmt_copy (lmt_addr, io_addr, desc3, n_dwords[3]);

      n_packets -= 4;
      b += 4;
    }
  while (n_packets)
    {
      if (n_packets > 2)
	vlib_prefetch_buffer_header (b[1], LOAD);

      n_segs[0] = cnxk_pktio_get_tx_vlib_buf_segs (vm, b[0], off_flags);

      aura_handle[0] =
	cnxk_pktio_get_aura_handle (vm, ptd, b[0], n_segs[0], &cached_aura,
				    &cached_bp_index, &refill_counter);

      n_dwords[0] = cn9k_pktio_add_sg_list (sg0, b[0], n_segs[0], off_flags);
      n_dwords[0] += cn9k_pktio_add_send_hdr (
	send_hdr0, b[0], aura_handle[0], sq_handle, n_dwords[0], off_flags);

      cn9k_lmt_copy (lmt_addr, io_addr, desc0, n_dwords[0]);

      n_packets -= 1;
      b += 1;
    }

  cnxk_update_sq_cached_pkts (fpsq, tx_pkts);

  /* TODO: Fix deplete count from different buffer pools */
  cnxk_pktpool_update_deplete_count (vm, ptd, refill_counter, cached_bp_index);
  cnxk_pktpool_deplete_single_aura (vm, node, cached_bp_index, ptd,
				    -(CNXK_POOL_MAX_REFILL_DEPLTE_COUNT * 2));

  return tx_pkts;
}

#endif /* included_onp_drv_modules_pktio_pktio_fp_tx_cn9k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
