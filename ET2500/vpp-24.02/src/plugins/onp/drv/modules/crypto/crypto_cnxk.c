/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/ipsec/ipsec_fp_cn10k.h>
#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/modules/ipsec/ipsec_priv.h>
#include <onp/drv/modules/pci/pci.h>
#include <onp/drv/inc/pool.h>

#define CPT_MAX_NB_DESC 2097152
#define CPT_MAX_SUBMIT_SIZE 64

#define SRC_IOV_SIZE                                                          \
  (sizeof (struct roc_se_iov_ptr) +                                           \
   (sizeof (struct roc_se_buf_ptr) * ROC_MAX_SG_CNT))

vlib_log_class_t cnxk_crypto_log_class;

cnxk_crypto_main_t cnxk_crypto_main;

static_always_inline cnxk_crypto_session_t *
crypto_session_alloc (vlib_main_t *vm)
{
  cnxk_crypto_session_t *addr = NULL;
  u32 size;

  size = sizeof (cnxk_crypto_session_t);
  addr = cnxk_drv_physmem_alloc (vm, size, CLIB_CACHE_LINE_BYTES);
  if (addr == NULL)
    {
      cnxk_crypto_err ("Failed to allocate crypto session memory");
      return NULL;
    }

  return addr;
}

static_always_inline void
cnxk_crypto_session_free (vlib_main_t *vm, cnxk_crypto_session_t *session)
{
  cnxk_drv_physmem_free (vm, session);

  return;
}

void
cnxk_drv_crypto_key_del_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index)
{
  cnxk_crypto_key_t *ckey;

  vec_validate (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey = vec_elt_at_index (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_ENCRYPT],
			   key_index);
  if (ckey->sess)
    {
      cnxk_crypto_session_free (vm, ckey->sess);
      ckey->sess = NULL;
      return;
    }

  ckey = vec_elt_at_index (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_DECRYPT],
			   key_index);
  if (ckey->sess)
    {
      cnxk_crypto_session_free (vm, ckey->sess);
      ckey->sess = NULL;
      return;
    }
}

void
cnxk_drv_crypto_key_add_handler (vlib_main_t *vm,
				 vnet_crypto_key_index_t key_index)
{
  cnxk_crypto_key_t *ckey;

  vec_validate (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_ENCRYPT], key_index);
  ckey = vec_elt_at_index (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_ENCRYPT],
			   key_index);
  ckey->sess = NULL;

  vec_validate (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_DECRYPT], key_index);
  ckey = vec_elt_at_index (cnxk_crypto_main.keys[CNXK_CRYPTO_OP_TYPE_DECRYPT],
			   key_index);
  ckey->sess = NULL;
}

static_always_inline void
cnxk_map_keyindex_to_session (cnxk_crypto_session_t *sess, u32 key_index,
			      u8 type)
{
  cnxk_crypto_key_t *ckey;

  ckey = vec_elt_at_index (cnxk_crypto_main.keys[type], key_index);

  ckey->sess = sess;
}

static_always_inline i32
cnxk_crypto_link_session_update (vlib_main_t *vm, cnxk_crypto_session_t *sess,
				 u32 key_index, u8 type)
{
  vnet_crypto_key_t *crypto_key, *auth_key;
  roc_se_cipher_type enc_type = 0;
  roc_se_auth_type auth_type = 0;
  vnet_crypto_key_t *key;
  u32 digest_len = ~0;
  i32 rv = 0;

  key = vnet_crypto_get_key (key_index);

  switch (key->async_alg)
    {
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA1_TAG12:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA1_TAG12:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA1_TYPE;
      digest_len = 12;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA224_TAG14:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA224_TAG14:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA224_TAG14:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA224;
      digest_len = 14;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA256_TAG16:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA256_TAG16:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA256;
      digest_len = 16;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA384_TAG24:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA384_TAG24:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA384;
      digest_len = 24;
      break;
    case VNET_CRYPTO_ALG_AES_128_CBC_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_192_CBC_SHA512_TAG32:
    case VNET_CRYPTO_ALG_AES_256_CBC_SHA512_TAG32:
      enc_type = ROC_SE_AES_CBC;
      auth_type = ROC_SE_SHA2_SHA512;
      digest_len = 32;
      break;
    default:
      cnxk_crypto_err (
	"Crypto: Undefined link algo %u specified. Key index %u",
	key->async_alg, key_index);
      return -1;
    }

  if (type == CNXK_CRYPTO_OP_TYPE_ENCRYPT)
    sess->cpt_ctx.ciph_then_auth = true;
  else
    sess->cpt_ctx.auth_then_ciph = true;

  sess->param.iv_length = 16;
  sess->param.cpt_op = type;

  crypto_key = vnet_crypto_get_key (key->index_crypto);
  rv = roc_se_ciph_key_set (&sess->cpt_ctx, enc_type, crypto_key->data,
			    vec_len (crypto_key->data));
  if (rv)
    {
      cnxk_crypto_err ("Error in setting cipher key for enc type %u",
		       enc_type);
      return -1;
    }

  auth_key = vnet_crypto_get_key (key->index_integ);

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, auth_key->data,
			    vec_len (auth_key->data), digest_len);
  if (rv)
    {
      cnxk_crypto_err ("Error in setting auth key for auth type %u",
		       auth_type);
      return -1;
    }

  cnxk_map_keyindex_to_session (sess, key_index, type);
  /*
   * Map session to crypto key index also. This entry can be referred
   * while deleting key
   */
  cnxk_map_keyindex_to_session (sess, key->index_crypto, type);

  return 0;
}

static_always_inline i32
cnxk_crypto_aead_session_update (vlib_main_t *vm, cnxk_crypto_session_t *sess,
				 u32 key_index, u8 type)
{
  vnet_crypto_key_t *key = vnet_crypto_get_key (key_index);
  roc_se_cipher_type enc_type = 0;
  roc_se_auth_type auth_type = 0;
  u32 digest_len = ~0;
  i32 rv = 0;

  switch (key->async_alg)
    {
    case VNET_CRYPTO_ALG_AES_128_GCM:
    case VNET_CRYPTO_ALG_AES_192_GCM:
    case VNET_CRYPTO_ALG_AES_256_GCM:
      enc_type = ROC_SE_AES_GCM;
      sess->param.aes_gcm = 1;
      sess->param.iv_offset = 0;
      sess->param.iv_length = 16;
      sess->cpt_ctx.mac_len = 16;
      sess->param.cpt_op = type;
      digest_len = 16;
      break;
    default:
      cnxk_crypto_err (
	"Crypto: Undefined cipher algo %u specified. Key index %u",
	key->async_alg, key_index);
      return -1;
    }

  rv = roc_se_ciph_key_set (&sess->cpt_ctx, enc_type, key->data,
			    vec_len (key->data));
  if (rv)
    {
      cnxk_crypto_err ("Error in setting cipher key for enc type %u",
		       enc_type);
      return -1;
    }

  rv = roc_se_auth_key_set (&sess->cpt_ctx, auth_type, NULL, 0, digest_len);
  if (rv)
    {
      cnxk_crypto_err ("Error in setting auth key for auth type %u",
		       auth_type);
      return -1;
    }

  cnxk_map_keyindex_to_session (sess, key_index, type);

  return 0;
}

static_always_inline u64
cnxk_cpt_inst_w7_get (cnxk_crypto_session_t *sess, struct roc_cpt *roc_cpt)
{
  union cpt_inst_w7 inst_w7;

  inst_w7.u64 = 0;
  inst_w7.s.cptr = (u64) &sess->cpt_ctx.se_ctx.fctx;
  /* Set the engine group */
  inst_w7.s.egrp = roc_cpt->eng_grp[CPT_ENG_TYPE_IE];

  return inst_w7.u64;
}

i32
cnxk_crypto_session_create (vlib_main_t *vm, vnet_crypto_key_index_t key_index,
			    int op_type)
{
  cnxk_crypto_session_t *session;
  cnxk_crypto_dev_t *crypto_dev;
  vnet_crypto_key_t *key;
  i32 rv = 0;

  /*
   * Use first device if there is more than one device present.
   */
  if (cnxk_crypto_main.n_crypto_dev == 1)
    crypto_dev = cnxk_crypto_dev_get (0);
  else
    crypto_dev = cnxk_crypto_dev_get (op_type);

  key = vnet_crypto_get_key (key_index);

  session = crypto_session_alloc (vm);
  if (session == NULL)
    return -1;

  if (key->type == VNET_CRYPTO_KEY_TYPE_LINK)
    rv = cnxk_crypto_link_session_update (vm, session, key_index, op_type);
  else
    rv = cnxk_crypto_aead_session_update (vm, session, key_index, op_type);

  if (rv)
    {
      cnxk_crypto_session_free (vm, session);
      return -1;
    }

  session->crypto_dev = crypto_dev;

  session->param.cpt_inst_w7 =
    cnxk_cpt_inst_w7_get (session, crypto_dev->cnxk_roc_cpt);

  return 0;
}

static_always_inline void
cnxk_crypto_update_frame_error_status (vnet_crypto_async_frame_t *f,
				       vnet_crypto_op_status_t s)
{
  u32 i;

  for (i = 0; i < f->n_elts; i++)
    f->elts[i].status = s;

  f->state = VNET_CRYPTO_FRAME_STATE_NOT_PROCESSED;
}

void
cnxk_crypto_burst_submit (cnxk_crypto_dev_t *cryptodev,
			  struct cpt_inst_s *inst, u32 n_left)
{
  u64 *lmt_line[CN10K_MAX_LMT_SZ];
  u64 lmt_arg, core_lmt_id;
  cnxk_crypto_queue_t *qp;
  u64 lmt_base;
  u64 io_addr;
  u32 count;

  qp = vec_elt_at_index (cryptodev->crypto_queues, 0);

  lmt_base = qp->lmtline.lmt_base;
  io_addr = qp->lmtline.io_addr;

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

      roc_lmt_submit_steorl (lmt_arg, io_addr);

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

      roc_lmt_submit_steorl (lmt_arg, io_addr);
    }
}

vnet_crypto_async_frame_t *
cnxk_drv_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			       u32 *enqueue_thread_idx)
{
  u32 deq_head, status = VNET_CRYPTO_OP_STATUS_COMPLETED;
  struct cnxk_crypto_pending_queue *pend_q;
  vnet_crypto_async_frame_elt_t *fe = NULL;
  struct cnxk_inflight_req *infl_req;
  vnet_crypto_async_frame_t *frame;
  volatile union cpt_res_s *res;
  int i;

  pend_q = &cnxk_crypto_main.pend_q[vlib_get_thread_index ()];

  if (!pend_q->n_crypto_inflight)
    return NULL;

  deq_head = pend_q->deq_head;
  infl_req = &pend_q->req_queue[deq_head];
  frame = infl_req->frame;

  fe = frame->elts;

  for (i = infl_req->deq_elts; i < infl_req->elts; ++i)
    {
      res = &infl_req->res[i];

      if (PREDICT_FALSE (res->cn10k.compcode == CPT_COMP_NOT_DONE))
	return NULL;

      if (PREDICT_FALSE (res->cn10k.uc_compcode))
	{
	  if (res->cn10k.uc_compcode == ROC_SE_ERR_GC_ICV_MISCOMPARE)
	    status = fe[i].status = VNET_CRYPTO_OP_STATUS_FAIL_BAD_HMAC;
	  else
	    status = fe[i].status = VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR;
	}

      infl_req->deq_elts++;
    }

  vlib_decrement_simple_counter (pend_q->pending_packets[0], vm->thread_index,
				 0, infl_req->elts);
  vlib_increment_simple_counter (pend_q->success_packets[0], vm->thread_index,
				 0, infl_req->elts);

  clib_memset ((void *) infl_req->res, 0,
	       sizeof (union cpt_res_s) * VNET_CRYPTO_FRAME_SIZE);

  CNXK_MOD_INC (pend_q->deq_head, pend_q->n_desc);
  pend_q->n_crypto_inflight--;
  vlib_decrement_simple_counter (pend_q->crypto_inflight[0], vm->thread_index,
				 0, 1);

  frame->state = status == VNET_CRYPTO_OP_STATUS_COMPLETED ?
			 VNET_CRYPTO_FRAME_STATE_SUCCESS :
			 VNET_CRYPTO_FRAME_STATE_ELT_ERROR;

  *nb_elts_processed = frame->n_elts;
  *enqueue_thread_idx = frame->enqueue_thread_index;

  infl_req->deq_elts = 0;
  infl_req->elts = 0;

  return frame;
}

static_always_inline uint32_t
cnxk_crypto_fill_sg_comp_from_iov (struct roc_sglist_comp *list, uint32_t i,
				   struct roc_se_iov_ptr *from,
				   uint32_t from_offset, uint32_t *psize,
				   struct roc_se_buf_ptr *extra_buf,
				   uint32_t extra_offset)
{
  uint32_t extra_len = extra_buf ? extra_buf->size : 0;
  uint32_t size = *psize;
  int32_t j;

  for (j = 0; j < from->buf_cnt; j++)
    {
      struct roc_sglist_comp *to = &list[i >> 2];
      uint32_t buf_sz = from->bufs[j].size;
      void *vaddr = from->bufs[j].vaddr;
      uint64_t e_vaddr;
      uint32_t e_len;

      if (PREDICT_FALSE (from_offset))
	{
	  if (from_offset >= buf_sz)
	    {
	      from_offset -= buf_sz;
	      continue;
	    }
	  e_vaddr = (uint64_t) vaddr + from_offset;
	  e_len = clib_min ((buf_sz - from_offset), size);
	  from_offset = 0;
	}
      else
	{
	  e_vaddr = (uint64_t) vaddr;
	  e_len = clib_min (buf_sz, size);
	}

      to->u.s.len[i % 4] = clib_host_to_net_u16 (e_len);
      to->ptr[i % 4] = clib_host_to_net_u64 (e_vaddr);

      if (extra_len && (e_len >= extra_offset))
	{
	  /* Break the data at given offset */
	  uint32_t next_len = e_len - extra_offset;
	  uint64_t next_vaddr = e_vaddr + extra_offset;

	  if (!extra_offset)
	    {
	      i--;
	    }
	  else
	    {
	      e_len = extra_offset;
	      size -= e_len;
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (e_len);
	    }

	  extra_len = clib_min (extra_len, size);
	  /* Insert extra data ptr */
	  if (extra_len)
	    {
	      i++;
	      to = &list[i >> 2];
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (extra_len);
	      to->ptr[i % 4] =
		clib_host_to_net_u64 ((uint64_t) extra_buf->vaddr);
	      size -= extra_len;
	    }

	  next_len = clib_min (next_len, size);
	  /* insert the rest of the data */
	  if (next_len)
	    {
	      i++;
	      to = &list[i >> 2];
	      to->u.s.len[i % 4] = clib_host_to_net_u16 (next_len);
	      to->ptr[i % 4] = clib_host_to_net_u64 (next_vaddr);
	      size -= next_len;
	    }
	  extra_len = 0;
	}
      else
	{
	  size -= e_len;
	}
      if (extra_offset)
	extra_offset -= size;
      i++;

      if (PREDICT_FALSE (!size))
	break;
    }

  *psize = size;
  return (uint32_t) i;
}

static_always_inline u32
cnxk_crypto_fill_sg2_comp_from_iov (struct roc_sg2list_comp *list, u32 i,
				    struct roc_se_iov_ptr *from,
				    u32 from_offset, u32 *psize,
				    struct roc_se_buf_ptr *extra_buf,
				    u32 extra_offset)
{
  u32 extra_len = extra_buf ? extra_buf->size : 0;
  u32 size = *psize, buf_sz, e_len, next_len;
  struct roc_sg2list_comp *to;
  u64 e_vaddr, next_vaddr;
  void *vaddr;
  i32 j;

  for (j = 0; j < from->buf_cnt; j++)
    {
      to = &list[i / 3];
      buf_sz = from->bufs[j].size;
      vaddr = from->bufs[j].vaddr;

      if (PREDICT_FALSE (from_offset))
	{
	  if (from_offset >= buf_sz)
	    {
	      from_offset -= buf_sz;
	      continue;
	    }
	  e_vaddr = (u64) vaddr + from_offset;
	  e_len = clib_min ((buf_sz - from_offset), size);
	  from_offset = 0;
	}
      else
	{
	  e_vaddr = (u64) vaddr;
	  e_len = clib_min (buf_sz, size);
	}

      to->u.s.len[i % 3] = (e_len);
      to->ptr[i % 3] = (e_vaddr);
      to->u.s.valid_segs = (i % 3) + 1;

      if (extra_len && (e_len >= extra_offset))
	{
	  /* Break the data at given offset */
	  next_len = e_len - extra_offset;
	  next_vaddr = e_vaddr + extra_offset;

	  if (!extra_offset)
	    i--;
	  else
	    {
	      e_len = extra_offset;
	      size -= e_len;
	      to->u.s.len[i % 3] = (e_len);
	    }

	  extra_len = clib_min (extra_len, size);
	  /* Insert extra data ptr */
	  if (extra_len)
	    {
	      i++;
	      to = &list[i / 3];
	      to->u.s.len[i % 3] = (extra_len);
	      to->ptr[i % 3] = ((u64) extra_buf->vaddr);
	      to->u.s.valid_segs = (i % 3) + 1;
	      size -= extra_len;
	    }

	  next_len = clib_min (next_len, size);
	  /* insert the rest of the data */
	  if (next_len)
	    {
	      i++;
	      to = &list[i / 3];
	      to->u.s.len[i % 3] = (next_len);
	      to->ptr[i % 3] = (next_vaddr);
	      to->u.s.valid_segs = (i % 3) + 1;
	      size -= next_len;
	    }
	  extra_len = 0;
	}
      else
	size -= e_len;

      if (extra_offset)
	extra_offset -= size;

      i++;

      if (PREDICT_FALSE (!size))
	break;
    }

  *psize = size;
  return (u32) i;
}

static_always_inline uint32_t
cnxk_crypto_fill_sg_comp_from_buf (struct roc_sglist_comp *list, uint32_t i,
				   struct roc_se_buf_ptr *from)
{
  struct roc_sglist_comp *to = &list[i >> 2];

  to->u.s.len[i % 4] = clib_host_to_net_u16 (from->size);
  to->ptr[i % 4] = clib_host_to_net_u64 ((uint64_t) from->vaddr);
  return ++i;
}

static_always_inline uint32_t
cnxk_crypto_fill_sg_comp (struct roc_sglist_comp *list, uint32_t i,
			  uint64_t dma_addr, uint32_t size)
{
  struct roc_sglist_comp *to = &list[i >> 2];

  to->u.s.len[i % 4] = clib_host_to_net_u16 (size);
  to->ptr[i % 4] = clib_host_to_net_u64 (dma_addr);
  return ++i;
}

static_always_inline u32
cnxk_crypto_fill_sg2_comp (struct roc_sg2list_comp *list, u32 index,
			   u64 dma_addr, u32 size)
{
  struct roc_sg2list_comp *to = &list[index / 3];

  to->u.s.len[index % 3] = (size);
  to->ptr[index % 3] = (dma_addr);
  to->u.s.valid_segs = (index % 3) + 1;
  return ++index;
}

static_always_inline u32
cnxk_crypto_fill_sg2_comp_from_buf (struct roc_sg2list_comp *list, u32 index,
				    struct roc_se_buf_ptr *from)
{
  struct roc_sg2list_comp *to = &list[index / 3];

  to->u.s.len[index % 3] = (from->size);
  to->ptr[index % 3] = ((u64) from->vaddr);
  to->u.s.valid_segs = (index % 3) + 1;
  return ++index;
}

static_always_inline int
cnxk_crypto_sg_inst_prep (struct roc_se_fc_params *params,
			  struct cpt_inst_s *inst, uint64_t offset_ctrl,
			  const uint8_t *iv_s, int iv_len, uint8_t pack_iv,
			  uint8_t pdcp_alg_type, int32_t inputlen,
			  int32_t outputlen, uint32_t passthrough_len,
			  uint32_t req_flags, int pdcp_flag, int decrypt)
{
  struct roc_sglist_comp *gather_comp, *scatter_comp;
  void *m_vaddr = params->meta_buf.vaddr;
  struct roc_se_buf_ptr *aad_buf = NULL;
  uint32_t mac_len = 0, aad_len = 0;
  struct roc_se_ctx *se_ctx;
  uint32_t i, g_size_bytes;
  int zsk_flags, ret = 0;
  uint64_t *offset_vaddr;
  uint32_t s_size_bytes;
  uint8_t *in_buffer;
  uint32_t size;
  uint8_t *iv_d;

  se_ctx = params->ctx;
  zsk_flags = se_ctx->zsk_flags;
  mac_len = se_ctx->mac_len;

  if (PREDICT_FALSE (req_flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      aad_len = params->aad_buf.size;
      aad_buf = &params->aad_buf;
    }

  /* save space for iv */
  offset_vaddr = m_vaddr;

  m_vaddr =
    (uint8_t *) m_vaddr + ROC_SE_OFF_CTRL_LEN + PLT_ALIGN_CEIL (iv_len, 8);

  inst->w4.s.opcode_major |= (uint64_t) ROC_DMA_MODE_SG;

  /* iv offset is 0 */
  *offset_vaddr = offset_ctrl;

  iv_d = ((uint8_t *) offset_vaddr + ROC_SE_OFF_CTRL_LEN);

  if (PREDICT_TRUE (iv_len))
    memcpy (iv_d, iv_s, iv_len);

  /* DPTR has SG list */

  /* TODO Add error check if space will be sufficient */
  gather_comp = (struct roc_sglist_comp *) ((uint8_t *) m_vaddr + 8);

  /*
   * Input Gather List
   */
  i = 0;

  /* Offset control word followed by iv */

  i = cnxk_crypto_fill_sg_comp (gather_comp, i, (uint64_t) offset_vaddr,
				ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = inputlen - iv_len - mac_len;

      if (PREDICT_TRUE (size))
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = cnxk_crypto_fill_sg_comp_from_iov (
	    gather_comp, i, params->src_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space, size %d needed",
			       size);
	      return -1;
	    }
	}

      if (mac_len)
	i =
	  cnxk_crypto_fill_sg_comp_from_buf (gather_comp, i, &params->mac_buf);
    }
  else
    {
      /* input data */
      size = inputlen - iv_len;
      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;
	  i = cnxk_crypto_fill_sg_comp_from_iov (
	    gather_comp, i, params->src_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space, size %d needed",
			       size);
	      return -1;
	    }
	}
    }

  in_buffer = m_vaddr;
  ((uint16_t *) in_buffer)[0] = 0;
  ((uint16_t *) in_buffer)[1] = 0;
  ((uint16_t *) in_buffer)[2] = clib_host_to_net_u16 (i);

  g_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);
  /*
   * Output Scatter List
   */

  i = 0;
  scatter_comp =
    (struct roc_sglist_comp *) ((uint8_t *) gather_comp + g_size_bytes);

  if (zsk_flags == 0x1)
    {
      /* IV in SLIST only for EEA3 & UEA2 or for F8 */
      iv_len = 0;
    }
  if (iv_len)
    i = cnxk_crypto_fill_sg_comp (
      scatter_comp, i, (uint64_t) offset_vaddr + ROC_SE_OFF_CTRL_LEN, iv_len);

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = outputlen - iv_len - mac_len;
      if (size)
	{

	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = cnxk_crypto_fill_sg_comp_from_iov (
	    scatter_comp, i, params->dst_iov, 0, &size, aad_buf, aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space, size %d needed",
			       size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	i = cnxk_crypto_fill_sg_comp_from_buf (scatter_comp, i,
					       &params->mac_buf);
    }
  else
    {
      /* Output including mac */
      size = outputlen - iv_len;

      if (size)
	{
	  uint32_t aad_offset = aad_len ? passthrough_len : 0;

	  i = cnxk_crypto_fill_sg_comp_from_iov (
	    scatter_comp, i, params->dst_iov, 0, &size, aad_buf, aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space, size %d needed",
			       size);
	      return -1;
	    }
	}
    }
  ((uint16_t *) in_buffer)[3] = clib_host_to_net_u16 (i);
  s_size_bytes = ((i + 3) / 4) * sizeof (struct roc_sglist_comp);

  size = g_size_bytes + s_size_bytes + ROC_SG_LIST_HDR_SIZE;

  /* This is DPTR len in case of SG mode */
  inst->w4.s.dlen = size;

  if (PREDICT_FALSE (size > ROC_SG_MAX_DLEN_SIZE))
    {
      cnxk_crypto_err ("Exceeds max supported components. Reduce segments");
      ret = -1;
    }

  inst->dptr = (uint64_t) in_buffer;
  return ret;
}

static_always_inline int
cnxk_crypto_sg2_inst_prep (struct roc_se_fc_params *params,
			   struct cpt_inst_s *inst, u64 offset_ctrl,
			   const u8 *iv_s, int iv_len, u8 pack_iv,
			   u8 pdcp_alg_type, i32 inputlen, i32 outputlen,
			   u32 passthrough_len, u32 req_flags, int pdcp_flag,
			   int decrypt)
{
  u32 mac_len = 0, aad_len = 0, size, index, g_size_bytes;
  struct roc_sg2list_comp *gather_comp, *scatter_comp;
  void *m_vaddr = params->meta_buf.vaddr;
  struct roc_se_buf_ptr *aad_buf = NULL;
  union cpt_inst_w5 cpt_inst_w5;
  union cpt_inst_w6 cpt_inst_w6;
  u16 scatter_sz, gather_sz;
  struct roc_se_ctx *se_ctx;
  int zsk_flags, ret = 0;
  u64 *offset_vaddr;
  u8 *iv_d;

  se_ctx = params->ctx;
  zsk_flags = se_ctx->zsk_flags;
  mac_len = se_ctx->mac_len;

  if (PREDICT_FALSE (req_flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      aad_len = params->aad_buf.size;
      aad_buf = &params->aad_buf;
    }

  /* save space for iv */
  offset_vaddr = m_vaddr;

  m_vaddr = (u8 *) m_vaddr + ROC_SE_OFF_CTRL_LEN + PLT_ALIGN_CEIL (iv_len, 8);

  inst->w4.s.opcode_major |= (u64) ROC_DMA_MODE_SG;

  /* This is DPTR len in case of SG mode */
  inst->w4.s.dlen = inputlen + ROC_SE_OFF_CTRL_LEN;

  /* iv offset is 0 */
  *offset_vaddr = offset_ctrl;

  iv_d = ((u8 *) offset_vaddr + ROC_SE_OFF_CTRL_LEN);

  if (PREDICT_TRUE (iv_len))
    memcpy (iv_d, iv_s, iv_len);

  /* DPTR has SG list */

  /* TODO: Add error check if space will be sufficient */
  gather_comp = (struct roc_sg2list_comp *) ((u8 *) m_vaddr);

  /*
   * Input Gather List
   */
  index = 0;

  /* Offset control word followed by iv */

  index = cnxk_crypto_fill_sg2_comp (gather_comp, index, (u64) offset_vaddr,
				     ROC_SE_OFF_CTRL_LEN + iv_len);

  /* Add input data */
  if (decrypt && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = inputlen - iv_len - mac_len;
      if (size)
	{
	  /* input data only */
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = cnxk_crypto_fill_sg2_comp_from_iov (
	    gather_comp, index, params->src_iov, 0, &size, aad_buf,
	    aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer"
			       " space, size %d needed",
			       size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	index = cnxk_crypto_fill_sg2_comp_from_buf (gather_comp, index,
						    &params->mac_buf);
    }
  else
    {
      /* input data */
      size = inputlen - iv_len;
      if (size)
	{
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = cnxk_crypto_fill_sg2_comp_from_iov (
	    gather_comp, index, params->src_iov, 0, &size, aad_buf,
	    aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space,"
			       " size %d needed",
			       size);
	      return -1;
	    }
	}
    }

  gather_sz = (index + 2) / 3;
  g_size_bytes = gather_sz * sizeof (struct roc_sg2list_comp);

  /*
   * Output Scatter List
   */

  index = 0;
  scatter_comp =
    (struct roc_sg2list_comp *) ((u8 *) gather_comp + g_size_bytes);

  if (zsk_flags == 0x1)
    {
      /* IV in SLIST only for EEA3 & UEA2 or for F8 */
      iv_len = 0;
    }

  if (iv_len)
    {
      index = cnxk_crypto_fill_sg2_comp (
	scatter_comp, index, (u64) offset_vaddr + ROC_SE_OFF_CTRL_LEN, iv_len);
    }

  /* Add output data */
  if ((!decrypt) && (req_flags & ROC_SE_VALID_MAC_BUF))
    {
      size = outputlen - iv_len - mac_len;
      if (size)
	{

	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = cnxk_crypto_fill_sg2_comp_from_iov (
	    scatter_comp, index, params->dst_iov, 0, &size, aad_buf,
	    aad_offset);
	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space,"
			       " size %d needed",
			       size);
	      return -1;
	    }
	}

      /* mac data */
      if (mac_len)
	index = cnxk_crypto_fill_sg2_comp_from_buf (scatter_comp, index,
						    &params->mac_buf);
    }
  else
    {
      /* Output including mac */
      size = outputlen - iv_len;
      if (size)
	{
	  u32 aad_offset = aad_len ? passthrough_len : 0;

	  index = cnxk_crypto_fill_sg2_comp_from_iov (
	    scatter_comp, index, params->dst_iov, 0, &size, aad_buf,
	    aad_offset);

	  if (PREDICT_FALSE (size))
	    {
	      cnxk_crypto_err ("Insufficient buffer space,"
			       " size %d needed",
			       size);
	      return -1;
	    }
	}
    }

  scatter_sz = (index + 2) / 3;

  cpt_inst_w5.s.gather_sz = gather_sz;
  cpt_inst_w6.s.scatter_sz = scatter_sz;

  cpt_inst_w5.s.dptr = (u64) gather_comp;
  cpt_inst_w6.s.rptr = (u64) scatter_comp;

  inst->w5.u64 = cpt_inst_w5.u64;
  inst->w6.u64 = cpt_inst_w6.u64;

  if (PREDICT_FALSE ((scatter_sz >> 4) || (gather_sz >> 4)))
    {
      cnxk_crypto_err ("Exceeds max supported components. Reduce segments");
      ret = -1;
    }

  return ret;
}

static_always_inline int
cnxk_crypto_cpt_hmac_prep (uint32_t flags, uint64_t d_offs, uint64_t d_lens,
			   struct roc_se_fc_params *fc_params,
			   struct cpt_inst_s *inst, u8 is_decrypt)
{
  bool is_cpt_mseg_enabled = roc_feature_nix_has_inl_ipsec_mseg ();
  uint32_t encr_data_len, auth_data_len, aad_len = 0;
  uint32_t encr_offset, auth_offset, iv_offset = 0;
  int32_t inputlen, outputlen, enc_dlen, auth_dlen;
  uint32_t cipher_type, hash_type;
  union cpt_inst_w4 cpt_inst_w4;
  uint32_t passthrough_len = 0;
  const uint8_t *src = NULL;
  struct roc_se_ctx *se_ctx;
  uint64_t offset_ctrl;
  uint8_t iv_len = 16;
  uint8_t op_minor;
  uint32_t mac_len;
  int ret;

  encr_offset = ROC_SE_ENCR_OFFSET (d_offs);
  auth_offset = ROC_SE_AUTH_OFFSET (d_offs);
  encr_data_len = ROC_SE_ENCR_DLEN (d_lens);
  auth_data_len = ROC_SE_AUTH_DLEN (d_lens);

  if (PREDICT_FALSE (flags & ROC_SE_VALID_AAD_BUF))
    {
      /* We don't support both AAD and auth data separately */
      auth_data_len = 0;
      auth_offset = 0;
      aad_len = fc_params->aad_buf.size;
    }

  se_ctx = fc_params->ctx;
  cipher_type = se_ctx->enc_cipher;
  hash_type = se_ctx->hash_type;
  mac_len = se_ctx->mac_len;
  cpt_inst_w4.u64 = se_ctx->template_w4.u64;
  op_minor = cpt_inst_w4.s.opcode_minor;

  if (PREDICT_FALSE (!(flags & ROC_SE_VALID_IV_BUF)))
    {
      iv_len = 0;
      iv_offset = ROC_SE_ENCR_IV_OFFSET (d_offs);
    }

  if (PREDICT_FALSE (flags & ROC_SE_VALID_AAD_BUF))
    {
      /*
       * When AAD is given, data above encr_offset is pass through
       * Since AAD is given as separate pointer and not as offset,
       * this is a special case as we need to fragment input data
       * into passthrough + encr_data and then insert AAD in between.
       */
      if (hash_type != ROC_SE_GMAC_TYPE)
	{
	  passthrough_len = encr_offset;
	  auth_offset = passthrough_len + iv_len;
	  encr_offset = passthrough_len + aad_len + iv_len;
	  auth_data_len = aad_len + encr_data_len;
	}
      else
	{
	  passthrough_len = 16 + aad_len;
	  auth_offset = passthrough_len + iv_len;
	  auth_data_len = aad_len;
	}
    }
  else
    {
      encr_offset += iv_len;
      auth_offset += iv_len;
    }

  if (hash_type == ROC_SE_GMAC_TYPE)
    {
      encr_offset = 0;
      encr_data_len = 0;
    }

  auth_dlen = auth_offset + auth_data_len;
  enc_dlen = encr_data_len + encr_offset;

  cpt_inst_w4.s.opcode_major = ROC_SE_MAJOR_OP_FC;

  if (is_decrypt)
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_DECRYPT;

      if (auth_dlen > enc_dlen)
	{
	  inputlen = auth_dlen + mac_len;
	  outputlen = auth_dlen;
	}
      else
	{
	  inputlen = enc_dlen + mac_len;
	  outputlen = enc_dlen;
	}
    }
  else
    {
      cpt_inst_w4.s.opcode_minor |= ROC_SE_FC_MINOR_OP_ENCRYPT;

      /* Round  up  to 16 bytes alignment */
      if (PREDICT_FALSE (encr_data_len & 0xf))
	{
	  if (PREDICT_TRUE (cipher_type == ROC_SE_AES_CBC))
	    enc_dlen = PLT_ALIGN_CEIL (encr_data_len, 8) + encr_offset;
	}

      /*
       * auth_dlen is larger than enc_dlen in Authentication cases
       * like AES GMAC Authentication
       */
      if (PREDICT_FALSE (auth_dlen > enc_dlen))
	{
	  inputlen = auth_dlen;
	  outputlen = auth_dlen + mac_len;
	}
      else
	{
	  inputlen = enc_dlen;
	  outputlen = enc_dlen + mac_len;
	}
    }

  if (op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST)
    outputlen = enc_dlen;

  cpt_inst_w4.s.param1 = encr_data_len;
  cpt_inst_w4.s.param2 = auth_data_len;

  if (PREDICT_FALSE ((encr_offset >> 16) || (iv_offset >> 8) ||
		     (auth_offset >> 8)))
    {
      cnxk_crypto_err ("Offset not supported");
      cnxk_crypto_err ("enc_offset: %d, iv_offset : %d, auth_offset: %d",
		       encr_offset, iv_offset, auth_offset);
      return -1;
    }

  offset_ctrl = clib_host_to_net_u64 (((uint64_t) encr_offset << 16) |
				      ((uint64_t) iv_offset << 8) |
				      ((uint64_t) auth_offset));
  if (PREDICT_TRUE (iv_len))
    src = fc_params->iv_buf;

  inst->w4.u64 = cpt_inst_w4.u64;

  if (is_cpt_mseg_enabled)
    ret = cnxk_crypto_sg2_inst_prep (fc_params, inst, offset_ctrl, src, iv_len,
				     0, 0, inputlen, outputlen,
				     passthrough_len, flags, 0, is_decrypt);
  else
    ret = cnxk_crypto_sg_inst_prep (fc_params, inst, offset_ctrl, src, iv_len,
				    0, 0, inputlen, outputlen, passthrough_len,
				    flags, 0, is_decrypt);

  if (PREDICT_FALSE (ret))
    {
      cnxk_crypto_err ("sg prep failed");
      return -1;
    }

  return 0;
}

static_always_inline void
cnxk_crypto_fill_fc_params (cnxk_crypto_session_t *sess,
			    struct cpt_inst_s *inst, const bool is_aead,
			    u8 aad_length, u8 *payload,
			    vnet_crypto_async_frame_elt_t *elts, void *mdata,
			    u32 cipher_data_length, u32 cipher_data_offset,
			    u32 auth_data_length, u32 auth_data_offset,
			    vlib_buffer_t *b, u16 adj_len)
{
  struct roc_se_fc_params fc_params = { 0 };
  struct roc_se_ctx *ctx = &sess->cpt_ctx;
  uint64_t d_offs = 0, d_lens = 0;
  uint32_t flags = 0, index = 0;
  uint8_t op_minor = 0, cpt_op;
  vlib_buffer_t *buffer = b;
  char src[SRC_IOV_SIZE];
  uint32_t *iv_buf;

  cpt_op = sess->param.cpt_op;

  if (is_aead)
    {
      if (PREDICT_TRUE (sess->param.iv_length))
	{
	  flags |= ROC_SE_VALID_IV_BUF;
	  iv_buf = (uint32_t *) elts->iv;
	  iv_buf[3] = clib_host_to_net_u32 (0x1);
	  fc_params.iv_buf = elts->iv;
	}

      d_offs = cipher_data_offset;
      d_offs = d_offs << 16;

      d_lens = cipher_data_length;
      d_lens = d_lens << 32;

      fc_params.aad_buf.vaddr = elts->aad;
      fc_params.aad_buf.size = aad_length;
      flags |= ROC_SE_VALID_AAD_BUF;

      /* Digest immediately following data is best case */
      if (sess->cpt_ctx.mac_len)
	{
	  flags |= ROC_SE_VALID_MAC_BUF;
	  fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	  fc_params.mac_buf.vaddr = elts->tag;
	}
    }
  else
    {
      op_minor = ctx->template_w4.s.opcode_minor;

      if (PREDICT_TRUE (sess->param.iv_length))
	{
	  flags |= ROC_SE_VALID_IV_BUF;
	  fc_params.iv_buf = elts->iv;
	}

      d_offs = cipher_data_offset;
      d_offs = (d_offs << 16) | auth_data_offset;

      d_lens = cipher_data_length;
      d_lens = (d_lens << 32) | auth_data_length;

      if (PREDICT_TRUE (sess->cpt_ctx.mac_len))
	{
	  /* hmac immediately following data is best case */
	  if (!(op_minor & ROC_SE_FC_MINOR_OP_HMAC_FIRST))
	    {
	      flags |= ROC_SE_VALID_MAC_BUF;
	      fc_params.mac_buf.size = sess->cpt_ctx.mac_len;
	      fc_params.mac_buf.vaddr = elts->digest;
	    }
	}
    }

  fc_params.ctx = &sess->cpt_ctx;

  fc_params.src_iov = (void *) src;
  fc_params.src_iov->bufs[index].vaddr = payload;
  fc_params.src_iov->bufs[index].size = b->current_length - adj_len;
  index++;

  while (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      buffer = vlib_get_buffer (vlib_get_main (), buffer->next_buffer);
      fc_params.src_iov->bufs[index].vaddr =
	buffer->data + buffer->current_data;
      fc_params.src_iov->bufs[index].size = buffer->current_length;
      index++;
    }

  fc_params.src_iov->buf_cnt = index;

  fc_params.dst_iov = (void *) src;

  fc_params.meta_buf.vaddr = mdata;
  fc_params.meta_buf.size = CNXK_SCATTER_GATHER_BUFFER_SIZE;

  cnxk_crypto_cpt_hmac_prep (flags, d_offs, d_lens, &fc_params, inst, cpt_op);
}

int
cnxk_crypto_enqueue_enc_dec (vlib_main_t *vm, vnet_crypto_async_frame_t *frame,
			     const u8 is_aead, u8 aad_len, const u8 type)
{
  struct cpt_inst_s inst[VNET_CRYPTO_FRAME_SIZE];
  u32 i, enq_tail, enc_auth_len, buffer_index;
  u32 crypto_start_offset, integ_start_offset;
  struct cnxk_crypto_pending_queue *pend_q;
  vnet_crypto_async_frame_elt_t *elts;
  cnxk_crypto_dev_t *cryptodev = NULL;
  struct cnxk_inflight_req *infl_req;
  u64 dptr_start_ptr, curr_ptr;
  cnxk_crypto_session_t *sess;
  u32 crypto_total_length;
  cnxk_crypto_key_t *key;
  vlib_buffer_t *buffer;
  u16 adj_len;

  /* GCM packets having 8 bytes of aad and 8 bytes of iv */
  u8 aad_iv = 8 + 8;

  pend_q = &cnxk_crypto_main.pend_q[vlib_get_thread_index ()];

  enq_tail = pend_q->enq_tail;

  infl_req = &pend_q->req_queue[enq_tail];
  infl_req->frame = frame;

  for (i = 0; i < frame->n_elts; i++)
    {
      elts = &frame->elts[i];
      buffer_index = frame->buffer_indices[i];
      key = vec_elt_at_index (cnxk_crypto_main.keys[type], elts->key_index);

      if (!key->sess)
	{
	  if (cnxk_crypto_session_create (vm, elts->key_index, type) == -1)
	    {
	      cnxk_crypto_update_frame_error_status (
		frame, VNET_CRYPTO_OP_STATUS_FAIL_ENGINE_ERR);
	      return -1;
	    }
	}
      sess = key->sess;
      cryptodev = sess->crypto_dev;

      memset (inst + i, 0, sizeof (struct cpt_inst_s));

      buffer = vlib_get_buffer (vm, buffer_index);

      if (is_aead)
	{

	  dptr_start_ptr =
	    (u64) (buffer->data + (elts->crypto_start_offset - aad_iv));
	  curr_ptr = (u64) (buffer->data + buffer->current_data);
	  adj_len = (u16) (dptr_start_ptr - curr_ptr);

	  crypto_total_length = elts->crypto_total_length;
	  crypto_start_offset = aad_iv;
	  integ_start_offset = 0;

	  cnxk_crypto_fill_fc_params (
	    sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
	    (cnxk_crypto_scatter_gather_t *) (infl_req->sg_data) + i,
	    crypto_total_length /* cipher_len */,
	    crypto_start_offset /* cipher_offset */, 0 /* auth_len */,
	    integ_start_offset /* auth_off */, buffer, adj_len);
	}
      else
	{
	  dptr_start_ptr = (u64) (buffer->data + elts->crypto_start_offset -
				  elts->integ_length_adj);
	  enc_auth_len = elts->crypto_total_length + elts->integ_length_adj;

	  curr_ptr = (u64) (buffer->data + buffer->current_data);
	  adj_len = (u16) (dptr_start_ptr - curr_ptr);

	  crypto_total_length = elts->crypto_total_length;
	  crypto_start_offset =
	    elts->crypto_start_offset - elts->integ_start_offset;
	  integ_start_offset = 0;

	  cnxk_crypto_fill_fc_params (
	    sess, inst + i, is_aead, aad_len, (u8 *) dptr_start_ptr, elts,
	    (cnxk_crypto_scatter_gather_t *) (infl_req->sg_data) + i,
	    crypto_total_length /* cipher_len */,
	    crypto_start_offset /* cipher_offset */,
	    enc_auth_len /* auth_len */, integ_start_offset /* auth_off */,
	    buffer, adj_len);
	}

      inst[i].w7.u64 = sess->param.cpt_inst_w7;
      inst[i].res_addr = (u64) &infl_req->res[i];
    }

  cnxk_crypto_burst_submit (cryptodev, inst, frame->n_elts);

  infl_req->elts = frame->n_elts;
  CNXK_MOD_INC (pend_q->enq_tail, pend_q->n_desc);
  pend_q->n_crypto_inflight++;

  vlib_increment_simple_counter (pend_q->pending_packets[0], vm->thread_index,
				 0, frame->n_elts);
  vlib_increment_simple_counter (pend_q->crypto_inflight[0], vm->thread_index,
				 0, 1);

  return 0;
}

int
cnxk_drv_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame)
{
  cnxk_crypto_enqueue_enc_dec (vm, frame, 0 /* is_aead */, 0 /* aad_len */,
			       CNXK_CRYPTO_OP_TYPE_ENCRYPT);
  return 0;
}

int
cnxk_drv_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
					vnet_crypto_async_frame_t *frame)
{
  cnxk_crypto_enqueue_enc_dec (vm, frame, 0 /* is_aead */, 0 /* aad_len */,
			       CNXK_CRYPTO_OP_TYPE_DECRYPT);
  return 0;
}

int
cnxk_drv_crypto_enqueue_aead_aad_enc (vlib_main_t *vm,
				      vnet_crypto_async_frame_t *frame,
				      u8 aad_len)
{

  cnxk_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
			       CNXK_CRYPTO_OP_TYPE_ENCRYPT);

  return 0;
}

int
cnxk_drv_crypto_enqueue_aead_aad_dec (vlib_main_t *vm,
				      vnet_crypto_async_frame_t *frame,
				      u8 aad_len)
{
  cnxk_crypto_enqueue_enc_dec (vm, frame, 1 /* is_aead */, aad_len,
			       CNXK_CRYPTO_OP_TYPE_DECRYPT);
  return 0;
}

void
cnxk_crypto_iegroup_capability_read (union cpt_eng_caps hw_caps,
				     cnxk_crypto_grp_capability_t *capability)
{
  cnxk_crypto_cipher_algo_capability_t *cipher_algos = NULL;
  cnxk_crypto_auth_algo_capability_t *auth_algos = NULL;
  ipsec_crypto_alg_t calg;
  ipsec_integ_alg_t ialg;

  /* Allocate IE group capability for encryption algorithms */
  vec_validate (cipher_algos, IPSEC_CRYPTO_N_ALG - 1);

  capability->cipher_algos = cipher_algos;

  for (calg = IPSEC_CRYPTO_ALG_NONE; calg < vec_len (cipher_algos); calg++)
    {
      switch (calg)
	{
	case IPSEC_CRYPTO_ALG_NONE:
	  cipher_algos[calg].supported = 1;
	  break;
	case IPSEC_CRYPTO_ALG_AES_GCM_128:
	case IPSEC_CRYPTO_ALG_AES_GCM_192:
	case IPSEC_CRYPTO_ALG_AES_GCM_256:
	case IPSEC_CRYPTO_ALG_AES_CBC_128:
	case IPSEC_CRYPTO_ALG_AES_CBC_192:
	case IPSEC_CRYPTO_ALG_AES_CBC_256:
	case IPSEC_CRYPTO_ALG_AES_CTR_128:
	case IPSEC_CRYPTO_ALG_AES_CTR_192:
	case IPSEC_CRYPTO_ALG_AES_CTR_256:
	  cipher_algos[calg].supported = hw_caps.aes;
	  break;
	default:
	  cipher_algos[calg].supported = 0;
	  break;
	}
    }

  /* Allocate IE group capability for authentication algorithms */
  vec_validate (auth_algos, IPSEC_INTEG_N_ALG - 1);

  capability->auth_algos = auth_algos;

  for (ialg = IPSEC_INTEG_ALG_NONE; ialg < vec_len (auth_algos); ialg++)
    {
      switch (ialg)
	{
	case IPSEC_INTEG_ALG_NONE:
	  auth_algos[ialg].supported = 1;
	  break;
	case IPSEC_INTEG_ALG_MD5_96:
	case IPSEC_INTEG_ALG_SHA1_96:
	case IPSEC_INTEG_ALG_SHA_256_128:
	case IPSEC_INTEG_ALG_SHA_384_192:
	case IPSEC_INTEG_ALG_SHA_512_256:
	  auth_algos[ialg].supported = hw_caps.sha1_sha2;
	  break;
	default:
	  auth_algos[ialg].supported = 0;
	  break;
	}
    }
}

i32
cnxk_crypto_queue_init (vlib_main_t *vm, u16 cnxk_crypto_index,
			cnxk_crypto_queue_config_t *config)
{
  cnxk_drv_pool_params_t params = { 0 };
  struct roc_cpt_lmtline *cpt_lmtline;
  cnxk_crypto_dev_t *crypto_dev;
  cnxk_pool_info_t pool_info;
  struct roc_cpt_lf *cpt_lf;
  cnxk_crypto_queue_t *qp;
  u8 *pool_name = 0;
  u32 pool_index;
  u32 n_buffers;
  int ret;

  crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);
  if (!crypto_dev)
    {
      cnxk_crypto_err ("Invalid crypto device");
      return -1;
    }

  if (crypto_dev->crypto_device_status != CNXK_CRYPTO_CONFIGURED)
    {
      cnxk_crypto_err ("Crypto device %d yet to be configured",
		       cnxk_crypto_index);
      return -1;
    }

  if (clib_bitmap_get (crypto_dev->bitmask_attached_queues,
		       config->crypto_queue_id))
    {
      cnxk_crypto_err ("Crypto qid %d already initialized",
		       config->crypto_queue_id);
      return -1;
    }

  qp = vec_elt_at_index (crypto_dev->crypto_queues, config->crypto_queue_id);
  if (!qp)
    {
      cnxk_crypto_err ("Invalid crypto queue");
      return -1;
    }

  n_buffers = config->n_crypto_desc / config->crypto_min_burst_size;

  cpt_lf = &qp->lf;
  if (config->crypto_queue_pool_buffer_size)
    {
      /*
       * Create packet pool first to know exact number of cpt_descriptors.
       * Since driver uses pool alloc as a measure of CPT enqueue flow control,
       * configured amount of NPA buffers might not be same as number of
       * populated
       */
      pool_name = format (pool_name, "cpt%u-q%u-enq-pool%c", cnxk_crypto_index,
			  config->crypto_queue_id, 0);

      /* Check if number of buffers exceeds the max limit */
      if (n_buffers > (CPT_MAX_NB_DESC / CPT_MAX_SUBMIT_SIZE))
	{
	  /*
	   * vector buffer pool count is minimum of max possible vector buffers
	   * (CPT_MAX_DESC/CPT_MAX_SUBMIT_SIZE) and packet pool buffers
	   */
	  n_buffers = clib_min (CPT_MAX_NB_DESC / CPT_MAX_SUBMIT_SIZE,
				clib_min (n_buffers, config->num_pkt_buf));

	  cnxk_crypto_notice (
	    "Number of buffers in %s pool exceeds max limit "
	    "%u, using %u buffers ",
	    pool_name, (CPT_MAX_NB_DESC / CPT_MAX_SUBMIT_SIZE), n_buffers);
	}

      params.elem_size = config->crypto_queue_pool_buffer_size;
      params.n_elem = n_buffers;
      params.is_pkt_pool = false;
      if (cnxk_drv_pool_setup (vm, (char *) pool_name, params, &pool_index))
	{
	  cnxk_crypto_err ("cnxk_drv_pool_setup() failed");
	  goto free_pool_name;
	}

      if (cnxk_drv_pool_info_get (pool_index, &pool_info))
	{
	  cnxk_crypto_err ("cnxk_drv_pool_info_get() failed for %s",
			   pool_name);
	  goto free_pool_name;
	}
      cpt_lf->nb_desc = (pool_info.elem_available * CNXK_FRAME_SIZE);
      qp->cnxk_cpt_enq_pool_index = pool_index;
    }
  else
    {
      cpt_lf->nb_desc = config->n_crypto_desc;
      qp->cnxk_cpt_enq_pool_index = ~0;
    }

  cpt_lf->lf_id = config->crypto_queue_id;

  ret = roc_cpt_lf_init (crypto_dev->cnxk_roc_cpt, cpt_lf);
  if (ret < 0)
    {
      cnxk_crypto_err ("roc_cpt_lf_init failed for %d",
		       config->crypto_queue_id);
      goto cpt_pool_destroy;
    }

  roc_cpt_iq_enable (cpt_lf);

  cpt_lmtline = &qp->lmtline;
  ret = roc_cpt_lmtline_init (crypto_dev->cnxk_roc_cpt, cpt_lmtline,
			      config->crypto_queue_id);
  if (ret < 0)
    {
      cnxk_crypto_err ("Could not initialize lmtline for crypto queue %d",
		       config->crypto_queue_id);
      goto cpt_pool_destroy;
    }

  qp->cnxk_queue_index = config->crypto_queue_id;
  qp->n_crypto_desc = cpt_lf->nb_desc;
  qp->cnxk_crypto_index = crypto_dev->cnxk_crypto_index;

  clib_bitmap_set (crypto_dev->bitmask_attached_queues,
		   config->crypto_queue_id, 1);
  clib_time_init (&qp->last_crypto_inst_time);

  vec_free (pool_name);

  return qp->cnxk_queue_index;

cpt_pool_destroy:
  /* TODO: Destroy NPA */
free_pool_name:
  vec_free (pool_name);

  return -1;
}

void
cnxk_crypto_main_init (vlib_main_t *vm)
{
  cnxk_crypto_log_class = vlib_log_register_class ("onp/crypto", 0);
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_dev_t *crypto_dev = NULL;
  cnxk_crypto_ops_t *ops = NULL;

  vec_validate_aligned (crypto_dev, CNXK_CRYPTO_MAX_DEVICES,
			CLIB_CACHE_LINE_BYTES);

  vec_validate_aligned (ops, CNXK_CRYPTO_MAX_DEVICES, CLIB_CACHE_LINE_BYTES);

  cm->cnxk_cryptodevs = crypto_dev;
  cm->cnxk_crypto_ops = ops;

  cm->n_crypto_dev = 0;
}

i16
cnxk_crypto_probe (vlib_main_t *vm, vlib_pci_addr_t *pci_addr,
		   vlib_pci_dev_handle_t *pci_handle)
{
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_dev_t *crypto_dev;
  cnxk_plt_pci_device_t *dev;
  struct roc_cpt *roc_cpt;
  i16 cnxk_crypto_index;
  uuid_t uuid;
  int rv;

  cnxk_crypto_index = cm->n_crypto_dev;

  if (cnxk_crypto_index >= CNXK_CRYPTO_MAX_DEVICES)
    {
      cnxk_crypto_err ("Reached max cpt devices threshold value");
      return -1;
    }

  uuid_clear (uuid);
  dev = cnxk_pci_dev_probe (vm, pci_addr, uuid, pci_handle);
  if (!dev)
    {
      cnxk_crypto_err ("Failed to probe %U PCI device", format_vlib_pci_addr,
		       pci_addr);
      return -1;
    }

  roc_cpt = cnxk_drv_physmem_alloc (vm, sizeof (struct roc_cpt),
				    CLIB_CACHE_LINE_BYTES);
  if (roc_cpt == NULL)
    {
      cnxk_crypto_err (
	"Failed to allocate roc crypto device memory for %U PCI device",
	format_vlib_pci_addr, pci_addr);

      return -1;
    }
  roc_cpt->pci_dev = dev;

  rv = roc_cpt_dev_init (roc_cpt);
  if (rv)
    {
      cnxk_crypto_err ("Failed to initalize roc cpt dev");
      cnxk_drv_physmem_free (vm, roc_cpt);
      return -1;
    }
  crypto_dev = vec_elt_at_index (cm->cnxk_cryptodevs, cnxk_crypto_index);
  clib_memset (crypto_dev, 0, sizeof (cnxk_crypto_dev_t));

  crypto_dev->cnxk_roc_cpt = roc_cpt;
  crypto_dev->cnxk_crypto_index = cnxk_crypto_index;
  crypto_dev->crypto_device_status = CNXK_CRYPTO_PROBED;

  cm->n_crypto_dev++;

  return cnxk_crypto_index;
}

i16
cnxk_drv_crypto_probe (vlib_main_t *vm, vlib_pci_addr_t *addr,
		       vlib_pci_dev_handle_t *pci_handle)
{
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_capability_t *crypto_capa;
  cnxk_crypto_ops_t *crypto_ops;
  cnxk_crypto_dev_t *crypto_dev;
  i16 cnxk_crypto_index;

  if (!cm->n_crypto_dev)
    cnxk_crypto_main_init (vm);

  cnxk_crypto_index = cnxk_crypto_probe (vm, addr, pci_handle);
  if (cnxk_crypto_index == -1)
    {
      cnxk_crypto_err ("cnxk_crypto probe fails for %U", format_vlib_pci_addr,
		       addr);
      return -1;
    }

  if (roc_model_is_cn10k ())
    cm->cnxk_crypto_ops[cnxk_crypto_index] = crypto_10k_ops;
  else
    {
      cnxk_crypto_err ("Invalid roc model");
      ASSERT (0);
      return -1;
    }

  crypto_ops = &cm->cnxk_crypto_ops[cnxk_crypto_index];
  if (crypto_ops == NULL)
    {
      cnxk_crypto_err ("Invalid crypto_ops");
      return -1;
    }

  crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);

  crypto_capa = &crypto_dev->crypto_capa;

  if (crypto_ops->cnxk_crypto_capability_populate (vm, cnxk_crypto_index,
						   crypto_capa) == -1)
    return -1;

  return cnxk_crypto_index;
}

i32
cnxk_crypto_clear (vlib_main_t *vm, u16 cnxk_crypto_index)
{
  cnxk_crypto_dev_t *crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);

  if (!crypto_dev)
    {
      cnxk_crypto_err ("crypto device %u ptr is NULL", cnxk_crypto_index);
      return -1;
    }

  if (crypto_dev->crypto_device_status != CNXK_CRYPTO_CONFIGURED)
    {
      cnxk_crypto_err ("crypto device %u is not yet configured",
		       cnxk_crypto_index);
      return -1;
    }

  roc_cpt_dev_clear (crypto_dev->cnxk_roc_cpt);
  crypto_dev->crypto_device_status = CNXK_CRYPTO_PROBED;
  vec_free (crypto_dev->crypto_queues);
  clib_bitmap_free (crypto_dev->bitmask_attached_queues);
  return 0;
}

i16
cnxk_drv_crypto_remove (vlib_main_t *vm, u16 cnxk_crypto_index)
{
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_dev_t *crypto_dev;

  crypto_dev = vec_elt_at_index (cm->cnxk_cryptodevs, cnxk_crypto_index);

  if (roc_cpt_dev_fini (crypto_dev->cnxk_roc_cpt))
    {
      cnxk_crypto_err ("Failed to uninitalize roc crypto device");
      return -1;
    }

  cnxk_drv_physmem_free (vm, crypto_dev->cnxk_roc_cpt);

  crypto_dev->crypto_device_status = CNXK_CRYPTO_UNITITIALIZED;

  return 0;
}

cnxk_crypto_capability_t *
cnxk_drv_crypto_capability_get (vlib_main_t *vm, u16 cnxk_crypto_index)
{
  cnxk_crypto_dev_t *crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);

  if (!crypto_dev)
    {
      cnxk_crypto_err ("Invalid crypto device");
      return NULL;
    }

  return &crypto_dev->crypto_capa;
}

i32
cnxk_crypto_configure (vlib_main_t *vm, u16 cnxk_crypto_index,
		       cnxk_crypto_config_t *config)
{
  cnxk_crypto_queue_t *crypto_queue_vec = NULL;
  cnxk_crypto_dev_t *crypto_dev;
  struct roc_cpt *roc_cpt;
  int nb_lf;

  nb_lf = config->n_crypto_hw_queues;

  crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);
  if (!crypto_dev)
    {
      cnxk_crypto_err ("crypto device %u ptr is NULL", cnxk_crypto_index);
      return -1;
    }

  if (crypto_dev->crypto_device_status != CNXK_CRYPTO_PROBED)
    {
      cnxk_crypto_err ("crypto device %u is not yet probed",
		       cnxk_crypto_index);
      return -1;
    }

  roc_cpt = crypto_dev->cnxk_roc_cpt;
  if (roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_SE) < 0)
    {
      cnxk_crypto_err ("Could not add CPT SE engines");
      return -1;
    }

  if (roc_cpt_eng_grp_add (roc_cpt, CPT_ENG_TYPE_IE) < 0)
    {
      cnxk_crypto_err ("Could not add CPT IE engines");
      return -1;
    }

  if (roc_cpt->eng_grp[CPT_ENG_TYPE_IE] != ROC_CPT_DFLT_ENG_GRP_SE_IE)
    {
      cnxk_crypto_err ("Invalid CPT IE engine group configuration");
      return -1;
    }

  if (roc_cpt->eng_grp[CPT_ENG_TYPE_SE] != ROC_CPT_DFLT_ENG_GRP_SE)
    {
      cnxk_crypto_err ("Invalid CPT SE engine group configuration");
      return -1;
    }

  if (roc_cpt_dev_configure (roc_cpt, nb_lf, false, 0) < 0)
    {
      cnxk_crypto_err ("could not configure crypto device %U",
		       format_vlib_pci_addr, roc_cpt->pci_dev->addr);
      return -1;
    }
  crypto_dev->crypto_device_status = CNXK_CRYPTO_CONFIGURED;

  vec_validate_aligned (crypto_queue_vec,
			crypto_dev->crypto_capa.max_crypto_queues,
			CLIB_CACHE_LINE_BYTES);

  crypto_dev->crypto_queues = crypto_queue_vec;

  clib_bitmap_alloc (crypto_dev->bitmask_attached_queues,
		     crypto_dev->crypto_capa.max_crypto_queues);

  return 0;
}

i32
cnxk_drv_crypto_configure (vlib_main_t *vm, u16 cnxk_crypto_index,
			   cnxk_crypto_config_t *config)
{
  cnxk_crypto_ops_t *crypto_ops = cnxk_crypto_ops_get (cnxk_crypto_index);

  return crypto_ops->cnxk_crypto_configure (vm, cnxk_crypto_index, config);
}

i32
cnxk_drv_crypto_dev_clear (vlib_main_t *vm, u16 cnxk_crypto_index)
{
  cnxk_crypto_ops_t *crypto_ops = cnxk_crypto_ops_get (cnxk_crypto_index);

  return crypto_ops->cnxk_crypto_clear (vm, cnxk_crypto_index);
}

u8 *
cnxk_drv_crypto_format_capability (u8 *s, va_list *arg)
{
  return NULL;
}

int
cnxk_drv_crypto_group_add (vlib_main_t *vm, u16 cnxk_crypto_index,
			   cnxk_crypto_group_t group)
{
  cnxk_crypto_dev_t *crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);

  return (roc_cpt_eng_grp_add (crypto_dev->cnxk_roc_cpt, (u8) group));
}

uintptr_t
cnxk_drv_crypto_queue_get (vlib_main_t *vm, u16 cnxk_crypto_index,
			   u16 cnxk_crypto_queue)
{
  cnxk_crypto_dev_t *crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);

  if (!clib_bitmap_get (crypto_dev->bitmask_attached_queues,
			cnxk_crypto_queue))
    {
      cnxk_crypto_err ("Crypto queue: %d not attached to crypto device: %d",
		       cnxk_crypto_queue, cnxk_crypto_index);
      return 0;
    }

  return (uintptr_t) &crypto_dev->crypto_queues[cnxk_crypto_queue];
}

i32
cnxk_drv_crypto_sw_queue_init (vlib_main_t *vm)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  struct cnxk_inflight_req *infl_req_queue;
  u8 num_worker_cores;
  int i, j = 0;

  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  cnxk_crypto_main.pend_q = cnxk_drv_physmem_alloc (
    vm, num_worker_cores * sizeof (struct cnxk_crypto_pending_queue),
    CLIB_CACHE_LINE_BYTES);

  if (cnxk_crypto_main.pend_q == NULL)
    {
      cnxk_crypto_err ("Failed to allocate memory for crypto pending queue");
      return -1;
    }

  for (i = 0; i <= num_worker_cores; ++i)
    {
      cnxk_crypto_main.pend_q[i].n_desc =
	CNXK_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT;
      cnxk_crypto_main.pend_q[i].req_queue =
	cnxk_drv_physmem_alloc (vm,
				CNXK_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT *
				  sizeof (struct cnxk_inflight_req),
				CLIB_CACHE_LINE_BYTES);

      if (cnxk_crypto_main.pend_q[i].req_queue == NULL)
	{
	  cnxk_crypto_err (
	    "Failed to allocate memory for crypto inflight request");
	  goto free;
	}

      for (j = 0; j <= cnxk_crypto_main.pend_q[i].n_desc; ++j)
	{
	  infl_req_queue = &cnxk_crypto_main.pend_q[i].req_queue[j];
	  infl_req_queue->sg_data = cnxk_drv_physmem_alloc (
	    vm, CNXK_SCATTER_GATHER_BUFFER_SIZE * VNET_CRYPTO_FRAME_SIZE,
	    CLIB_CACHE_LINE_BYTES);

	  if (infl_req_queue->sg_data == NULL)
	    {
	      cnxk_crypto_err (
		"Failed to allocate crypto scatter gather memory");
	      goto free;
	    }
	}
    }
  return 0;

free:
  for (; i >= 0; i--)
    {
      if (cnxk_crypto_main.pend_q[i].req_queue == NULL)
	continue;

      for (; j >= 0; j--)
	{
	  infl_req_queue = &cnxk_crypto_main.pend_q[i].req_queue[j];

	  if (infl_req_queue->sg_data == NULL)
	    continue;

	  cnxk_drv_physmem_free (vm, infl_req_queue->sg_data);
	}
      cnxk_drv_physmem_free (vm, cnxk_crypto_main.pend_q[i].req_queue);
    }
  cnxk_drv_physmem_free (vm, cnxk_crypto_main.pend_q);

  return -1;
}

i32
cnxk_drv_crypto_queue_init (vlib_main_t *vm, u16 cnxk_crypto_index,
			    cnxk_crypto_queue_config_t *config)
{
  cnxk_crypto_ops_t *crypto_ops = cnxk_crypto_ops_get (cnxk_crypto_index);

  return crypto_ops->cnxk_crypto_qpair_init (vm, cnxk_crypto_index, config);
}

void
cnxk_drv_crypto_set_success_packets_counters (
  cnxk_crypto_counter_type_t type, vlib_simple_counter_main_t *crypto_success)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  u8 num_worker_cores;
  int i;
  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  for (i = 0; i <= num_worker_cores; ++i)
    {
      cnxk_crypto_main.pend_q[i].success_packets[type] = crypto_success;
    }
}

void
cnxk_drv_crypto_set_pending_packets_counters (
  cnxk_crypto_counter_type_t type, vlib_simple_counter_main_t *pending_count)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  u8 num_worker_cores;
  int i;
  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  for (i = 0; i <= num_worker_cores; ++i)
    {
      cnxk_crypto_main.pend_q[i].pending_packets[type] = pending_count;
    }
}

void
cnxk_drv_crypto_set_crypto_inflight_counters (
  cnxk_crypto_counter_type_t type,
  vlib_simple_counter_main_t *crypto_inflight_count)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  u8 num_worker_cores;
  int i;
  num_worker_cores =
    vdm->last_worker_thread_index - vdm->first_worker_thread_index + 1;

  for (i = 0; i <= num_worker_cores; ++i)
    {
      cnxk_crypto_main.pend_q[i].crypto_inflight[type] = crypto_inflight_count;
    }
}

VLIB_REGISTER_LOG_CLASS (cnxk_crypto_log) = {
  .class_name = "onp/crypto",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
