/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/modules/ipsec/ipsec_fp_cn10k.h>
#include <onp/drv/modules/pktio/pktio_priv.h>
#include <vnet/ipsec/ipsec.h>

static_always_inline u64
cn10k_ipsec_crypto_inst_w7_get (void *sa)
{
  union cpt_inst_w7 w7;

  w7.u64 = 0;
  w7.s.egrp = ROC_CPT_DFLT_ENG_GRP_SE_IE;
  w7.s.ctx_val = 1;
  w7.s.cptr = (u64) sa;

  return w7.u64;
}

static_always_inline u64
cn10k_ipsec_crypto_inst_w2_get (vlib_main_t *vm)
{
  union cpt_inst_w2 w2 = { 0 };
  cnxk_sched_work_t work = { 0 };

  work.tag = 0;
  work.source = CNXK_SCHED_WORK_SOURCE_CRYPTO_ENC_INLINE;

  w2.s.grp = cnxk_sched_grp_app_map_to_actual (vm->thread_index,
					       CNXK_SCHED_GRP_APP_CRYPTO_ENQ);
  w2.s.tag = work.tag;
  w2.s.tt = CNXK_SCHED_TAG_ORDERED;

  return w2.u64;
}

static void
cn10k_ipsec_hmac_opad_ipad_gen (ipsec_sa_t *sa, u8 *hmac_opad_ipad)
{
  u8 opad[128] = { [0 ... 127] = 0x5c };
  u8 ipad[128] = { [0 ... 127] = 0x36 };
  const u8 *key = sa->integ_key.data;
  u32 length = sa->integ_key.len;
  u32 i;

  /* HMAC OPAD and IPAD */
  for (i = 0; i < 128 && i < length; i++)
    {
      opad[i] = opad[i] ^ key[i];
      ipad[i] = ipad[i] ^ key[i];
    }

  /*
   * Precompute hash of HMAC OPAD and IPAD to avoid
   * per-packet computation
   */
  switch (sa->integ_alg)
    {
    case IPSEC_INTEG_ALG_SHA1_96:
      roc_hash_sha1_gen (opad, (u32 *) &hmac_opad_ipad[0]);
      roc_hash_sha1_gen (ipad, (u32 *) &hmac_opad_ipad[24]);
      break;
    case IPSEC_INTEG_ALG_SHA_256_96:
    case IPSEC_INTEG_ALG_SHA_256_128:
      roc_hash_sha256_gen (opad, (u32 *) &hmac_opad_ipad[0], 256);
      roc_hash_sha256_gen (ipad, (u32 *) &hmac_opad_ipad[64], 256);
      break;
    case IPSEC_INTEG_ALG_SHA_384_192:
      roc_hash_sha512_gen (opad, (u64 *) &hmac_opad_ipad[0], 384);
      roc_hash_sha512_gen (ipad, (u64 *) &hmac_opad_ipad[64], 384);
      break;
    case IPSEC_INTEG_ALG_SHA_512_256:
      roc_hash_sha512_gen (opad, (u64 *) &hmac_opad_ipad[0], 512);
      roc_hash_sha512_gen (ipad, (u64 *) &hmac_opad_ipad[64], 512);
      break;
    default:
      break;
    }
}

static_always_inline i32
cn10k_ipsec_sa_common_param_fill (union roc_ot_ipsec_sa_word2 *w2,
				  u8 *cipher_key, u8 *salt_key,
				  u8 *hmac_opad_ipad, ipsec_sa_t *sa)
{
  u32 *tmp_salt;
  u64 *tmp_key;
  int i;

  /* Set protocol - ESP vs AH */
  if (sa->protocol == IPSEC_PROTOCOL_ESP)
    w2->s.protocol = ROC_IE_SA_PROTOCOL_ESP;
  else
    w2->s.protocol = ROC_IE_SA_PROTOCOL_AH;

  /* Set mode - transport vs tunnel */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    w2->s.mode = ROC_IE_SA_MODE_TUNNEL;
  else
    w2->s.mode = ROC_IE_SA_MODE_TRANSPORT;

  if (ipsec_sa_is_set_IS_CTR (sa))
    {
      if (ipsec_sa_is_set_IS_AEAD (sa))
	{
	  /* AEAD is set for AES_GCM */
	  if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	    {
	      w2->s.enc_type = ROC_IE_OT_SA_ENC_AES_GCM;
	      w2->s.auth_type = ROC_IE_OT_SA_AUTH_NULL;
	    }
	  else
	    {
	      cnxk_ipsec_err ("Unsupported AEAD algorithm");
	      return -1;
	    }
	}
      else
	w2->s.enc_type = ROC_IE_OT_SA_ENC_AES_CTR;
    }
  else
    {
      switch (sa->crypto_alg)
	{
	case IPSEC_CRYPTO_ALG_NONE:
	  w2->s.enc_type = ROC_IE_OT_SA_ENC_NULL;
	  break;
	case IPSEC_CRYPTO_ALG_AES_CBC_128:
	case IPSEC_CRYPTO_ALG_AES_CBC_192:
	case IPSEC_CRYPTO_ALG_AES_CBC_256:
	  w2->s.enc_type = ROC_IE_OT_SA_ENC_AES_CBC;
	  break;
	default:
	  cnxk_ipsec_err ("Unsupported encryption algorithm");
	  return -1;
	}
    }

  switch (sa->crypto_alg)
    {
    case IPSEC_CRYPTO_ALG_AES_GCM_128:
    case IPSEC_CRYPTO_ALG_AES_CBC_128:
    case IPSEC_CRYPTO_ALG_AES_CTR_128:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_128;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_192:
    case IPSEC_CRYPTO_ALG_AES_CBC_192:
    case IPSEC_CRYPTO_ALG_AES_CTR_192:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_192;
      break;
    case IPSEC_CRYPTO_ALG_AES_GCM_256:
    case IPSEC_CRYPTO_ALG_AES_CBC_256:
    case IPSEC_CRYPTO_ALG_AES_CTR_256:
      w2->s.aes_key_len = ROC_IE_SA_AES_KEY_LEN_256;
      break;
    default:
      break;
    }

  if (!ipsec_sa_is_set_IS_AEAD (sa))
    {
      switch (sa->integ_alg)
	{
	case IPSEC_INTEG_ALG_NONE:
	  w2->s.auth_type = ROC_IE_OT_SA_AUTH_NULL;
	  break;
	case IPSEC_INTEG_ALG_SHA1_96:
	  w2->s.auth_type = ROC_IE_OT_SA_AUTH_SHA1;
	  break;
	case IPSEC_INTEG_ALG_SHA_256_96:
	case IPSEC_INTEG_ALG_SHA_256_128:
	  w2->s.auth_type = ROC_IE_OT_SA_AUTH_SHA2_256;
	  break;
	case IPSEC_INTEG_ALG_SHA_384_192:
	  w2->s.auth_type = ROC_IE_OT_SA_AUTH_SHA2_384;
	  break;
	case IPSEC_INTEG_ALG_SHA_512_256:
	  w2->s.auth_type = ROC_IE_OT_SA_AUTH_SHA2_512;
	  break;
	default:
	  cnxk_ipsec_err ("Unsupported authentication algorithm");
	  return -1;
	}
    }

  cn10k_ipsec_hmac_opad_ipad_gen (sa, hmac_opad_ipad);

  tmp_key = (u64 *) hmac_opad_ipad;
  for (i = 0; i < (int) (ROC_CTX_MAX_OPAD_IPAD_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  if (ipsec_sa_is_set_IS_AEAD (sa))
    {
      if (IPSEC_CRYPTO_ALG_IS_GCM (sa->crypto_alg))
	clib_memcpy (salt_key, &sa->salt, CNXK_ROC_SALT_LEN);
      tmp_salt = (u32 *) salt_key;
      *tmp_salt = clib_net_to_host_u32 (*tmp_salt);
    }

  /* Populate encryption key */
  clib_memcpy (cipher_key, sa->crypto_key.data, sa->crypto_key.len);
  tmp_key = (u64 *) cipher_key;
  for (i = 0; i < (int) (ROC_CTX_MAX_CKEY_LEN / sizeof (u64)); i++)
    tmp_key[i] = clib_net_to_host_u64 (tmp_key[i]);

  w2->s.spi = sa->spi;

  return 0;
}

static size_t
cn10k_ipsec_inb_ctx_size (struct roc_ot_ipsec_inb_sa *sa)
{
  size_t size;

  /* Variable based on anti-replay window */
  size = offsetof (struct roc_ot_ipsec_inb_sa, ctx) +
	 offsetof (struct roc_ot_ipsec_inb_ctx_update_reg, ar_winbits);

  if (sa->w0.s.ar_win)
    size += (1 << (sa->w0.s.ar_win - 1)) * sizeof (u64);

  return size;
}

static_always_inline void
cn10k_ipsec_common_inst_param_fill (vlib_main_t *vm, void *sa,
				    cn10k_ipsec_session_t *sess)
{
  union cpt_inst_w2 w2;
  union cpt_inst_w3 w3;

  clib_memset (&sess->inst, 0, sizeof (struct cpt_inst_s));

  sess->inst.w7.u64 = cn10k_ipsec_crypto_inst_w7_get (sa);

  w2.u64 = cn10k_ipsec_crypto_inst_w2_get (vm);
  sess->inst.w2.u64 = w2.u64;

  /* Populate word3 in CPT instruction template */
  w3.u64 = 0;
  w3.s.qord = 1;
  sess->inst.w3.u64 = w3.u64;

  cnxk_ipsec_notice ("w(tag): 0x%x, w(grp): 0x%x, w(tt): 0x%x\n", w2.s.tag,
		     w2.s.grp, w2.s.tt);
}

static_always_inline i32
cn10k_ipsec_outb_session_update (vlib_main_t *vm,
				 cnxk_crypto_queue_t *ipsec_queue,
				 cn10k_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  union roc_ot_ipsec_outb_param1 param1;
  struct roc_ot_ipsec_outb_sa *out_sa;
  union roc_ot_ipsec_sa_word2 w2;
  union cpt_inst_w4 inst_w4;
  uint64_t *ipv6_addr;
  size_t offset;
  int rv = 0;

  out_sa = &sess->out_sa;
  roc_ot_ipsec_outb_sa_init (out_sa);

  w2.u64 = 0;
  rv = cn10k_ipsec_sa_common_param_fill (
    &w2, out_sa->cipher_key, out_sa->iv.s.salt, out_sa->hmac_opad_ipad, sa);
  if (rv)
    return rv;

  /* Set direction and enable ESN (if needed) */
  w2.s.dir = ROC_IE_SA_DIR_OUTBOUND;
  if (ipsec_sa_is_set_USE_ESN (sa))
    out_sa->w0.s.esn_en = 1;

  /* Configure tunnel header generation */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      if (ipsec_sa_is_set_IS_TUNNEL_V6 (sa))
	{
	  w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_6;

	  clib_memcpy (&out_sa->outer_hdr.ipv6.src_addr,
		       &sa->tunnel.t_src.ip.ip6, sizeof (ip6_address_t));
	  clib_memcpy (&out_sa->outer_hdr.ipv6.dst_addr,
		       &sa->tunnel.t_dst.ip.ip6, sizeof (ip6_address_t));

	  /* Convert host to network byte order of ipv6 address */
	  ipv6_addr = (uint64_t *) &out_sa->outer_hdr.ipv6.src_addr;
	  *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	  ipv6_addr++;
	  *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);

	  ipv6_addr = (uint64_t *) &out_sa->outer_hdr.ipv6.dst_addr;
	  *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	  ipv6_addr++;
	  *ipv6_addr = clib_host_to_net_u64 (*ipv6_addr);
	}
      else
	{
	  w2.s.outer_ip_ver = ROC_IE_SA_IP_VERSION_4;
	  out_sa->outer_hdr.ipv4.src_addr =
	    clib_host_to_net_u32 (sa->tunnel.t_src.ip.ip4.as_u32);
	  out_sa->outer_hdr.ipv4.dst_addr =
	    clib_host_to_net_u32 (sa->tunnel.t_dst.ip.ip4.as_u32);
	}
    }

  offset = offsetof (struct roc_ot_ipsec_outb_sa, ctx);
  out_sa->w0.s.hw_ctx_off = offset / 8;
  out_sa->w0.s.ctx_push_size = out_sa->w0.s.hw_ctx_off + 1;
  /* Set context size, in number of 128B units following the first 128B */
  out_sa->w0.s.ctx_size = (round_pow2 (offset, 128) >> 7) - 1;
  out_sa->w0.s.ctx_hdr_size = 1;
  out_sa->w0.s.aop_valid = 1;

  out_sa->w2.u64 = w2.u64;

  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    {
      if (sa->tunnel.t_encap_decap_flags &
	  TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF)
	out_sa->w2.s.ipv4_df_src_or_ipv6_flw_lbl_src =
	  ROC_IE_OT_SA_COPY_FROM_INNER_IP_HDR;
      if (!sa->tunnel.t_dscp)
	out_sa->w2.s.dscp_src = ROC_IE_OT_SA_COPY_FROM_INNER_IP_HDR;
      else
	{
	  out_sa->w2.s.dscp_src = ROC_IE_OT_SA_COPY_FROM_SA;
	  out_sa->w10.s.dscp = sa->tunnel.t_dscp;
	}
    }

  out_sa->w2.s.ipid_gen = 1;
  out_sa->w2.s.iv_src = ROC_IE_OT_SA_IV_SRC_FROM_SA;
  out_sa->w2.s.valid = 1;

  cnxk_wmb ();

  cnxk_ipsec_sa_len_precalc (sa, &sess->encap);

  cn10k_ipsec_common_inst_param_fill (vm, out_sa, sess);

  /* Populate word4 in CPT instruction template */
  inst_w4.u64 = 0;
  inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_OUTBOUND_IPSEC;
  param1.u16 = 0;
  if (sa->tunnel.t_hop_limit)
    param1.s.ttl_or_hop_limit = 1;

  /* Enable IP checksum computation by default */
  param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_ENABLE;
  /* Enable L4 checksum computation by default */
  param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_ENABLE;

  inst_w4.s.param1 = param1.u16;
  sess->inst.w4.u64 = inst_w4.u64;

  if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND)
    {
      rv = cn10k_pktio_inl_dev_outb_ctx_write (
	vm, out_sa, out_sa, sizeof (struct roc_ot_ipsec_outb_sa));
      if (rv)
	{
	  cnxk_ipsec_err (
	    "Could not write inline outbound session to hardware");
	  return rv;
	}
    }
  if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE)
    {
      /*TODO: fetch out_sa from lookaside session */
      rv = roc_cpt_ctx_write (&ipsec_queue->lf, out_sa, out_sa,
			      sizeof (struct roc_ot_ipsec_outb_sa));
      if (rv)
	{
	  cnxk_ipsec_err (
	    "Could not write lookaside outbound session to hardware");
	  return -1;
	}

      /* Trigger CTX flush so that data is written back to DRAM */
      roc_cpt_lf_ctx_flush (&ipsec_queue->lf, out_sa, false);
    }
  return 0;
}

static_always_inline i32
cn10k_ipsec_inb_session_update (vlib_main_t *vm,
				cnxk_crypto_queue_t *ipsec_queue,
				cn10k_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  union roc_ot_ipsec_inb_param1 param1;
  struct roc_ot_ipsec_inb_sa *roc_sa;
  cnxk_pktio_ops_map_t *pktio_ops;
  union roc_ot_ipsec_sa_word2 w2;
  cnxk_ipsec_inb_sa_t *cnxk_sa;
  cnxk_pktio_t *pktio = NULL;
  union cpt_inst_w4 inst_w4;
  u32 min_spi, max_spi;
  size_t offset;
  int rv = -1;

  pktio_ops = cnxk_pktio_get_pktio_ops (0);
  pktio = &pktio_ops->pktio;

  if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_INL_INBOUND)
    {
      /* Ensure SPI is within the range supported by inline pktio device */
      roc_nix_inl_inb_spi_range (NULL, true, &min_spi, &max_spi);
      if (sa->spi < min_spi || sa->spi > max_spi)
	{
	  cnxk_ipsec_err ("SPI %u is not within supported range %u-%u",
			  sa->spi, min_spi, max_spi);
	  return -1;
	}

      cnxk_sa = (cnxk_ipsec_inb_sa_t *) roc_nix_inl_inb_sa_get (&pktio->nix,
								true, sa->spi);
      roc_sa = &cnxk_sa->roc_sa;
      /* sa_index in vpp is same as stat_index */
      cnxk_sa->user_data = sa->stat_index;
    }
  else
    {
      roc_sa = &sess->in_sa;
      roc_ot_ipsec_inb_sa_init (roc_sa, 0);
    }

  w2.u64 = 0;
  rv = cn10k_ipsec_sa_common_param_fill (
    &w2, roc_sa->cipher_key, roc_sa->w8.s.salt, roc_sa->hmac_opad_ipad, sa);
  if (rv)
    return rv;

  cnxk_ipsec_sa_len_precalc (sa, &sess->encap);

#if 0
  if (sa->flags & IPSEC_SA_FLAG_USE_ANTI_REPLAY)
    roc_sa->w0.s.ar_win = max_log2 (IPSEC_SA_ANTI_REPLAY_WINDOW_SIZE (sa)) - 5;
#endif

  /* Set direction and enable ESN (if needed) */
  w2.s.dir = ROC_IE_SA_DIR_INBOUND;
  if (ipsec_sa_is_set_USE_ESN (sa))
    w2.s.esn_en = 1;

  /*
   * Default options for pkt_out and pkt_fmt are with
   * second pass meta and no defrag.
   */
  roc_sa->w0.s.pkt_format = ROC_IE_OT_SA_PKT_FMT_META;
  roc_sa->w0.s.pkt_output = ROC_IE_OT_SA_PKT_OUTPUT_NO_FRAG;
  roc_sa->w0.s.pkind = ROC_IE_OT_CPT_PKIND;

  offset = offsetof (struct roc_ot_ipsec_inb_sa, ctx);
  roc_sa->w0.s.hw_ctx_off = offset / 8;
  roc_sa->w0.s.ctx_push_size = roc_sa->w0.s.hw_ctx_off + 1;

  /* Set context size, in number of 128B units following the first 128B */
  roc_sa->w0.s.ctx_size =
    (round_pow2 (cn10k_ipsec_inb_ctx_size (roc_sa), 128) >> 7) - 1;

  /* Enable SA */
  w2.s.valid = 1;
  roc_sa->w2.u64 = w2.u64;

  cnxk_wmb ();

  cn10k_ipsec_common_inst_param_fill (vm, roc_sa, sess);

  /* Populate word4 in CPT instruction template */
  inst_w4.u64 = 0;
  inst_w4.s.opcode_major = ROC_IE_OT_MAJOR_OP_PROCESS_INBOUND_IPSEC;
  param1.u16 = 0;
  /* Disable IP checksum verification by default */
  param1.s.ip_csum_disable = ROC_IE_OT_SA_INNER_PKT_IP_CSUM_DISABLE;
  /* Disable L4 checksum verification by default */
  param1.s.l4_csum_disable = ROC_IE_OT_SA_INNER_PKT_L4_CSUM_DISABLE;
  param1.s.esp_trailer_disable = 0;
  inst_w4.s.param1 = param1.u16;
  sess->inst.w4.u64 = inst_w4.u64;

  /* Write inline SA context */
  if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_INL_INBOUND)
    {
      rv = cn10k_pktio_inl_dev_inb_ctx_write (
	vm, roc_sa, roc_sa, sizeof (struct roc_ot_ipsec_inb_sa));
      if (rv)
	{
	  cnxk_ipsec_err (
	    "Could not write inline inbound session to hardware");
	  return rv;
	}
      rv = cn10k_pktio_inl_dev_inb_ctx_flush (vm, roc_sa);
      if (rv)
	{
	  cnxk_ipsec_err ("Failed to flush context cache entry");
	  return rv;
	}
    }

  /* Write lookaside SA context */
  if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE)
    {
      rv = roc_cpt_ctx_write (&ipsec_queue->lf, roc_sa, roc_sa,
			      sizeof (struct roc_ot_ipsec_inb_sa));
      if (rv)
	{
	  cnxk_ipsec_err (
	    "Could not write lookaside inbound session to hardware");
	  return -1;
	}

      /* Trigger CTX flush so that data is written back to DRAM */
      roc_cpt_lf_ctx_flush (&ipsec_queue->lf, roc_sa, true);
    }
  return 0;
}

static_always_inline i32
cn10k_ipsec_session_update (vlib_main_t *vm, cnxk_crypto_queue_t *ipsec_queue,
			    cn10k_ipsec_session_t *sess, ipsec_sa_t *sa)
{
  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    return cn10k_ipsec_inb_session_update (vm, ipsec_queue, sess, sa);
  else
    return cn10k_ipsec_outb_session_update (vm, ipsec_queue, sess, sa);
}

i32
cn10k_ipsec_session_create (vlib_main_t *vm, uintptr_t ipsec_queue,
			    u32 sa_index, u64 mode)
{
  cnxk_crypto_queue_t *ipsec_queue_local = (cnxk_crypto_queue_t *) ipsec_queue;
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  ipsec_sa_t *sa = ipsec_sa_get (sa_index);
  cn10k_ipsec_session_t *session = NULL;
  i32 rv;

  if (!sa)
    {
      cnxk_ipsec_err ("Couldnt find SA at sa_index %d", sa_index);
      return -1;
    }

  session = vec_elt (im->inline_ipsec_sessions, sa_index);

  if (!session)
    return -1;

  /*
   * TODO: Add session for both, inline and lookaside once lookaside is
   * supported for cn10k.
   */
  rv = cn10k_ipsec_session_update (vm, ipsec_queue_local, session, sa);
  if (rv)
    return rv;

  session->vnet_sa_index = sa_index;
  /* Initialize the ITF details in ipsec_session for tunnel SAs */
  if (ipsec_sa_is_set_IS_TUNNEL (sa))
    session->itf_sw_idx = ~0;

  return 0;
}

i32
cn10k_ipsec_session_destroy (vlib_main_t *vm, uintptr_t ipsec_queue,
			     u32 sa_index)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cn10k_ipsec_session_t *session = NULL;
  struct roc_ot_ipsec_inb_sa *inb_sa;
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_ipsec_inb_sa_t *cnxk_sa;
  cnxk_pktio_t *pktio = NULL;
  void *sa_dptr = NULL;
  ipsec_sa_t *sa;
  int rv = 0;

  sa = ipsec_sa_get (sa_index);

  pktio_ops = cnxk_pktio_get_pktio_ops (0);
  pktio = &pktio_ops->pktio;

  session = vec_elt (im->inline_ipsec_sessions, sa_index);
  if (!session)
    return -1;

  if (!(sa->flags & IPSEC_SA_FLAG_IS_INBOUND))
    {
      sa_dptr = plt_zmalloc (sizeof (struct roc_ot_ipsec_outb_sa), 8);
      if (sa_dptr != NULL)
	{
	  roc_ot_ipsec_outb_sa_init (sa_dptr);
	  rv = cn10k_pktio_inl_dev_outb_ctx_write (
	    vm, sa_dptr, &session->out_sa,
	    sizeof (struct roc_ot_ipsec_outb_sa));
	  if (rv)
	    {
	      cnxk_ipsec_err (
		"Could not write inline outbound session to hardware");
	      return rv;
	    }
	  cnxk_plt_free (sa_dptr);
	}
    }
  else if (im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_INL_INBOUND)
    {
      /*
       * TODO: Destroy session for inbound lookaside once
       * lookaside is supported for cn10k.
       */

      cnxk_sa = (cnxk_ipsec_inb_sa_t *) roc_nix_inl_inb_sa_get (&pktio->nix,
								true, sa->spi);
      if (!cnxk_sa)
	{
	  cnxk_ipsec_err ("roc_nix_inl_inb_sa_get failed to get SA for spi %u",
			  sa->spi);
	  return -1;
	}

      inb_sa = &cnxk_sa->roc_sa;
      sa_dptr = cnxk_plt_zmalloc (sizeof (struct roc_ot_ipsec_inb_sa), 8);
      if (sa_dptr != NULL)
	{
	  roc_ot_ipsec_inb_sa_init (sa_dptr, true);
	  rv = cn10k_pktio_inl_dev_inb_ctx_write (
	    vm, sa_dptr, inb_sa, sizeof (struct roc_ot_ipsec_inb_sa));
	  if (rv)
	    {
	      cnxk_ipsec_err (
		"Could not write inline inbound session to hardware");
	      return rv;
	    }
	  cnxk_plt_free (sa_dptr);
	}
    }

  clib_memset (session, 0, sizeof (cn10k_ipsec_session_t));
  return 0;
}

i32
cnxk_drv_ipsec_session_reassembly_set (vlib_main_t *vm, u32 sa_index)
{
  struct roc_ot_ipsec_inb_sa *roc_sa;
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_ipsec_inb_sa_t *cnxk_sa;
  cnxk_pktio_t *pktio = NULL;
  ipsec_sa_t *sa;
  int rv = 0;

  sa = ipsec_sa_get (sa_index);

  pktio_ops = cnxk_pktio_get_pktio_ops (0);
  pktio = &pktio_ops->pktio;

  cnxk_sa = (cnxk_ipsec_inb_sa_t *) roc_nix_inl_inb_sa_get (&pktio->nix, true,
							    sa->spi);
  if (!cnxk_sa)
    {
      cnxk_ipsec_err ("roc_nix_inl_inb_sa_get failed to get SA for spi %u",
		      sa->spi);
      return -1;
    }

  roc_sa = &cnxk_sa->roc_sa;
  roc_sa->w0.s.pkt_output = ROC_IE_OT_SA_PKT_OUTPUT_HW_BASED_DEFRAG;

  rv = cn10k_pktio_inl_dev_inb_ctx_reload (vm, roc_sa);
  if (rv)
    {
      cnxk_ipsec_err ("Could not reload sa context to hardware");
      return rv;
    }

  return 0;
}
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
