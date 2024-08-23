/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_sched_sched_fp_enq_deq_cn10k_h
#define included_onp_drv_modules_sched_sched_fp_enq_deq_cn10k_h

#include <onp/drv/modules/sched/sched_fp_enq_deq_cnxk.h>
#include <onp/drv/modules/sched/sched_fp_cn10k.h>

static_always_inline u32
cn10k_sched_recv_from_inl_ipsec_err_work (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  cnxk_sched_work_t *work,
					  cnxk_per_thread_data_t *ptd)
{
  cn10k_ipsec_outbound_pkt_meta_t *pkt_meta;
  vlib_buffer_t **b = ptd->buffers;
  struct cpt_cn10k_res_s *res;

  ptd->out_npkts = 1;

  b[0] = (vlib_buffer_t *) work->work;
  ptd->buffer_indices[0] = vlib_get_buffer_index (vm, b[0]);

  pkt_meta = (void *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[0]);
  res = &pkt_meta->res.cn10k;

  ASSERT (res->compcode != CPT_COMP_NOT_DONE);

  cnxk_pktpool_update_refill_count (vm, ptd, 1, b[0]->buffer_pool_index);

  return ptd->out_npkts;
}

static_always_inline u32
cn10k_ipsec_recv_from_work (vlib_main_t *vm, cnxk_sched_work_t *work,
			    cnxk_per_thread_data_t *ptd, const u64 ipsec_flags)
{
  cnxk_sched_vec_header_t *header = (cnxk_sched_vec_header_t *) work->work;
  u16 *nexts = ptd->next1, header_next_node, drop_next_node;
  struct cpt_cn10k_res_s *res0, *res1, *res2, *res3;
  u32 pkt_count = header->frame_size, n_left;
  cnxk_crypto_queue_t *crypto_queue;
  cnxk_crypto_dev_t *crypto_dev;
  vlib_buffer_t **b;

  /* crypto_pkts_recv counter */
  ptd->out_npkts = pkt_count;

  ptd->ipsec.debug.work = work;
  ptd->ipsec.debug.work_source = ipsec_flags;

  /* Free sched frame */
  if (PREDICT_FALSE (!pkt_count))
    clib_panic ("sched frame size(%u) cannot be zero", ipsec_flags);

  crypto_queue = header->user_ptr;
  crypto_dev = cnxk_crypto_dev_get (crypto_queue->cnxk_crypto_index);
  ptd->user_ptr = crypto_dev;

  header_next_node = header->next_node;
  drop_next_node = header->drop_next_node;

  /* Copy buffer from sched frame to ptd */
  clib_memcpy (ptd->buffer_indices, header->buffer_indices,
	       pkt_count * sizeof (ptd->buffer_indices[0]));

  /* TODO: Add CLIB_DEBUG to validate buffer */

  vlib_get_buffers (vm, header->buffer_indices, ptd->buffers, pkt_count);

  cnxk_pktpool_update_refill_count (vm, ptd, pkt_count,
				    header->buffer_pool_index);

  n_left = pkt_count;
  b = ptd->buffers;

  /* Free sched frame */
  cnxk_ipsec_sched_frame_free (crypto_dev, crypto_queue, header);

  while (n_left > 11)
    {
      clib_prefetch_load (b[8]);
      clib_prefetch_load (b[9]);
      clib_prefetch_load (b[10]);
      clib_prefetch_load (b[11]);

      clib_prefetch_load (onp_esp_post_data2 (b[4])->res_ptr);
      clib_prefetch_load (onp_esp_post_data2 (b[5])->res_ptr);
      clib_prefetch_load (onp_esp_post_data2 (b[6])->res_ptr);
      clib_prefetch_load (onp_esp_post_data2 (b[7])->res_ptr);

      res0 = (struct cpt_cn10k_res_s *) onp_esp_post_data2 (b[0])->res_ptr;
      res1 = (struct cpt_cn10k_res_s *) onp_esp_post_data2 (b[1])->res_ptr;
      res2 = (struct cpt_cn10k_res_s *) onp_esp_post_data2 (b[2])->res_ptr;
      res3 = (struct cpt_cn10k_res_s *) onp_esp_post_data2 (b[3])->res_ptr;

      if (PREDICT_TRUE ((res0->compcode == CPT_COMP_GOOD) &
			(res0->uc_compcode == ROC_IE_OT_UCC_SUCCESS)))
	  nexts[0] = header_next_node;
      else
	nexts[0] = drop_next_node;

      if (PREDICT_TRUE ((res1->compcode == CPT_COMP_GOOD) &
			(res1->uc_compcode == ROC_IE_OT_UCC_SUCCESS)))
	  nexts[1] = header_next_node;
      else
	nexts[1] = drop_next_node;

      if (PREDICT_TRUE ((res2->compcode == CPT_COMP_GOOD) &
			(res2->uc_compcode == ROC_IE_OT_UCC_SUCCESS)))
	  nexts[2] = header_next_node;
      else
	nexts[2] = drop_next_node;

      if (PREDICT_TRUE ((res3->compcode == CPT_COMP_GOOD) &
			(res3->uc_compcode == ROC_IE_OT_UCC_SUCCESS)))
	  nexts[3] = header_next_node;
      else
	nexts[3] = drop_next_node;

      b += 4;
      n_left -= 4;
      nexts += 4;
    }

  while (n_left > 0)
    {
      res0 = (struct cpt_cn10k_res_s *) onp_esp_post_data2 (b[0])->res_ptr;

      if (PREDICT_TRUE ((res0->compcode == CPT_COMP_GOOD) &
			(res0->uc_compcode == ROC_IE_OT_UCC_SUCCESS)))
	  nexts[0] = header_next_node;
      else
	nexts[0] = drop_next_node;

      b++;
      n_left--;
      nexts++;
    }

  return pkt_count;
}

static_always_inline i32
cn10k_sched_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node,
		     cnxk_sched_work_t work[], cnxk_per_thread_data_t *ptd)
{
  u64 tag, wqp;

  wqp = cn10k_sched_get_work (vm, &tag);
  if (PREDICT_FALSE (!wqp))
    return 0;

  ptd->out_user_nstats = 0;
  ptd->out_npkts = 0;

  cnxk_sched_dev.hws[vm->thread_index].cached_tag = tag;
  work->word0 = tag;
  work->work = wqp;

  switch (work->source)
    {
    case CNXK_SCHED_WORK_SOURCE_CRYPTO_ENC_INLINE:
      return cn10k_sched_recv_from_inl_ipsec_err_work (vm, node, work, ptd);

    case CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_ENC:
      return cn10k_ipsec_recv_from_work (vm, work, ptd,
					 CNXK_IPSEC_FLAG_ENCRYPT_OP);

    case CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_DEC:
      return cn10k_ipsec_recv_from_work (vm, work, ptd,
					 CNXK_IPSEC_FLAG_DECRYPT_OP);

    default:
      ALWAYS_ASSERT (0);
    }
  return 0;
}
#endif /* included_onp_drv_modules_sched_sched_fp_enq_deq_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
