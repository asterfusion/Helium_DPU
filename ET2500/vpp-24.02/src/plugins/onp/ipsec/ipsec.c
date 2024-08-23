/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP IPsec implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/sched_fp_enq_deq.h>

#define foreach_onp_input_next_node                                           \
  _ (onp_esp4_enc_post_drop_next, "onp-esp4-encrypt-post-drop")               \
  _ (onp_esp6_enc_post_drop_next, "onp-esp6-encrypt-post-drop")               \
  _ (onp_esp4_dec_post_next, "onp-esp4-decrypt-post")                         \
  _ (onp_esp4_dec_post_drop_next, "onp-esp4-decrypt-post-drop")               \
  _ (onp_esp6_dec_post_next, "onp-esp6-decrypt-post")                         \
  _ (onp_esp6_dec_post_drop_next, "onp-esp6-decrypt-post-drop")               \
  _ (onp_esp4_enc_tun_post_next, "onp-esp4-encrypt-tun-post")                 \
  _ (onp_esp6_enc_tun_post_next, "onp-esp6-encrypt-tun-post")

onp_ipsec_main_t onp_ipsec_main;

clib_error_t *
onp_ipsec_reassembly_set (vlib_main_t *vm, u32 sa_index)
{
  ipsec_sa_t *sa = NULL;
  int rv = 0;

  sa = ipsec_sa_get (sa_index);
  if (!sa)
    return clib_error_create ("Could not find given SA index %d in SA pool",
			      sa_index);

  if (!(sa->flags & IPSEC_SA_FLAG_IS_INBOUND))
    return clib_error_create ("SA index %d is not index of an inbound SA",
			      sa_index);

  rv = cnxk_drv_ipsec_session_reassembly_set (vm, sa_index);
  if (rv)
    return clib_error_create ("Failed to set reassembly on given SA index %d",
			      sa_index);

  return 0;
}

static clib_error_t *
onp_ipsec_check_support (ipsec_sa_t *sa)
{
  cnxk_crypto_cipher_algo_capability_t *cipher_algos;
  cnxk_crypto_auth_algo_capability_t *auth_algos;
  onp_ipsec_main_t *im = &onp_ipsec_main;
  cnxk_crypto_capability_t *crypto_capa;
  vlib_main_t *vm = vlib_get_main ();

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    crypto_capa = cnxk_drv_crypto_capability_get (vm, im->in_dev_id);
  else
    crypto_capa = cnxk_drv_crypto_capability_get (vm, im->out_dev_id);

  if (!crypto_capa)
    return clib_error_create ("cnxk_drv_crypto_capability_get failed");

  cipher_algos = crypto_capa->grp_capa[CNXK_CRYPTO_GROUP_IE].cipher_algos;
  auth_algos = crypto_capa->grp_capa[CNXK_CRYPTO_GROUP_IE].auth_algos;

  if (sa->crypto_alg >= vec_len (cipher_algos))
    return clib_error_create (
      "crypto-alg %d > total %d crypto algos supported", sa->crypto_alg,
      vec_len (cipher_algos));

  if (sa->integ_alg >= vec_len (auth_algos))
    return clib_error_create ("integ-alg %d > total %d integ algos supported",
			      sa->integ_alg, vec_len (auth_algos));

  /* Match SA param with driver capabilities */
  if (!vec_elt_at_index (cipher_algos, sa->crypto_alg)->supported)
    return clib_error_create ("crypto-alg %U not supported",
			      format_ipsec_crypto_alg, sa->crypto_alg);

  if (!vec_elt_at_index (auth_algos, sa->integ_alg)->supported)
    return clib_error_create ("integ-alg %U not supported",
			      format_ipsec_integ_alg, sa->integ_alg);

  return 0;
}

static clib_error_t *
onp_esp_add_del_sa_sess (u32 sa_index, u8 is_add)
{
  onp_ipsec_main_t *im = &onp_ipsec_main;
  vlib_main_t *vm = vlib_get_main ();
  onp_main_t *om = onp_get_main ();
  i8 is_inline_outbound_enabled;
  uintptr_t ipsec_queue = 0;
  onp_pktio_t *pktio = NULL;
  ipsec_sa_t *sa = NULL;

  is_inline_outbound_enabled =
    om->onp_conf->onp_ipsecconf.is_inline_outbound_enabled;

  sa = ipsec_sa_get (sa_index);
  if (!sa)
    {
      onp_ipsec_err ("Couldnt find sa using sa_index %d", sa_index);
      return clib_error_create ("Couldnt find sa using sa_index %d", sa_index);
    }

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND)
    ipsec_queue = im->in_ipsec_queue;
  else
    ipsec_queue = im->out_ipsec_queue;

  if (!is_add)
    {
      if (cnxk_drv_ipsec_session_destroy (vm, ipsec_queue, sa_index) < 0)
	{
	  onp_ipsec_err ("IPsec session destroy operation failed for IPsec "
			 "queue %p and SA index %u",
			 ipsec_queue, sa_index);
	  return clib_error_create (
	    "IPsec session destroy operation failed for IPsec "
	    "queue %p and SA index %u",
	    ipsec_queue, sa_index);
	}
      return 0;
    }

  if (cnxk_drv_ipsec_session_create (vm, ipsec_queue, sa_index, 0) < 0)
    {
      onp_ipsec_err ("cnxk_drv_ipsec_session_create failed");
      return clib_error_create ("cnxk_drv_ipsec_session_create failed");
    }

  if ((im->ipsec_offloads_configured & CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND) &&
      is_inline_outbound_enabled)
    pool_foreach (pktio, om->onp_pktios)
      {
	if (!cnxk_drv_pktio_is_inl_dev (vm, pktio->onp_pktio_index))
	  {
	    /*
	     * Overwrite transmit function with inline IPsec transmit function
	     */
	    pktio->tx_offload_flags |= CNXK_PKTIO_TX_OFF_FLAG_INLINE_IPSEC;
	    onp_pktio_txqs_fp_set (vm, pktio->onp_pktio_index, 1);
	  }
      }

  if (sa->flags & IPSEC_SA_FLAG_IS_INBOUND &&
      cnxk_drv_pktio_is_inl_dev_enabled (vm))
    return onp_pktio_inl_inb_ipsec_flow_enable (vm);

  return 0;
}

clib_error_t *
onp_ipsec_config_parse (onp_config_main_t *conf, unformat_input_t *sub_input)
{
  if (!sub_input)
    return 0;

  unformat_skip_white_space (sub_input);

  while (unformat_check_input (sub_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (sub_input, "num-crypto-desc %d",
		    &conf->onp_ipsecconf.n_crypto_desc_per_queue))
	;
      else if (unformat (sub_input, "disable-ipsec-backend"))
	conf->onp_ipsecconf.is_ipsec_backend_enabled = 0;
      else if (unformat (sub_input, "reassembly-wait-time %d",
			 &conf->onp_ipsecconf.reassembly_max_wait_time))
	;
      else if (unformat (sub_input, "enable-inline-ipsec-outbound"))
	conf->onp_ipsecconf.is_inline_outbound_enabled = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, sub_input);
    }
  return 0;
}

clib_error_t *
onp_ipsec_register_esp_backend (vlib_main_t *vm, onp_ipsec_main_t *oim)
{
  const char *esp4_enc_tun, *esp6_enc_tun;
  onp_main_t *om = onp_get_main ();
  ipsec_main_t *im = &ipsec_main;
  i8 is_inline_outbound_enabled;
  u32 idx;
  int rv;

  is_inline_outbound_enabled =
    om->onp_conf->onp_ipsecconf.is_inline_outbound_enabled;

  if ((oim->ipsec_offloads_configured &
       CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND) &&
      is_inline_outbound_enabled)
    {
      esp4_enc_tun = "onp-esp4-encrypt-inl-tun";
      esp6_enc_tun = "onp-esp6-encrypt-inl-tun";
    }
  else if (oim->ipsec_offloads_configured & CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE)
    {
      esp4_enc_tun = "onp-esp4-encrypt-lka-tun";
      esp6_enc_tun = "onp-esp6-encrypt-lka-tun";
    }
  else
    {
      esp4_enc_tun = "onp-esp-encrypt-tun-unsupp";
      esp6_enc_tun = "onp-esp-encrypt-tun-unsupp";
    }

  idx = ipsec_register_esp_backend (
    vm, im, "onp backend", "onp-esp4-encrypt", esp4_enc_tun,
    "onp-esp4-decrypt", "onp-esp4-decrypt-tun", "onp-esp6-encrypt",
    esp6_enc_tun, "onp-esp6-decrypt", "onp-esp6-decrypt-tun",
    "onp-esp-mpls-encrypt-tun", onp_ipsec_check_support,
    onp_esp_add_del_sa_sess);

  rv = ipsec_select_esp_backend (im, idx);
  if (rv)
    return clib_error_return (0, "IPsec ESP backend selection failed");

  return 0;
}

static clib_error_t *
onp_ipsec_init (vlib_main_t *vm)
{
  cnxk_ipsec_capability_t *ipsec_capa = NULL;
  onp_crypto_main_t *cm = &onp_crypto_main;
  onp_ipsec_main_t *im = &onp_ipsec_main;
  onp_crypto_t *cryptodev = NULL;
  onp_main_t *om = &onp_main;
  clib_error_t *error = 0;
  cnxk_ipsec_config_t ic;
  int i = 0, rv = 0;

  clib_memset (&ic, 0, sizeof (ic));

  ipsec_capa = cnxk_drv_ipsec_capability_get (vm);
  if (!ipsec_capa)
    {
      onp_ipsec_err ("cnxk_drv_ipsec_capability_get failed\n");
      return clib_error_create ("cnxk_drv_ipsec_capability_get failed\n");
    }

  /*
   * Prepare Inline IPsec configuration.
   */
  if (ipsec_capa->ipsec_inl_outbound_supported)
    {
      ic.inl_outb_nb_crypto_lf = ONP_IPSEC_INLINE_OUTB_NB_CRYPTO_LF;
      ic.inl_ipsec_config.n_crypto_desc = ONP_IPSEC_INLINE_OUTB_NB_DESC;
    }

  if (ipsec_capa->ipsec_inl_inbound_supported)
    {
      ic.reassembly_config.inl_reassembly_max_wait_time_ms =
	om->onp_conf->onp_ipsecconf.reassembly_max_wait_time;
      ic.reassembly_config.inl_reassembly_active_limit =
	ONP_IPSEC_REASSEMBLY_ACTIVE_LIMIT;
      ic.reassembly_config.inl_reassembly_active_thres =
	ONP_IPSEC_REASSEMBLY_ACTIVE_THRESHOLD;
      ic.reassembly_config.inl_reassembly_zombie_limit =
	ONP_IPSEC_REASSEMBLY_ZOMBIE_LIMIT;
      ic.reassembly_config.inl_reassembly_zombie_thres =
	ONP_IPSEC_REASSEMBLY_ZOMBIE_THRESHOLD;
    }

  /* Passing both, inline and lookaside config to the driver. */
  rv = cnxk_drv_ipsec_init (vm, &ic);
  if (rv < 0)
    {
      onp_ipsec_err ("cnxk_drv_ipsec_init failed\n");
      return clib_error_create ("cnxk_drv_ipsec_init failed\n");
    }

  /*
   * Pass the final IPsec configuration status flag from driver
   * to the plugin.
   */
  im->ipsec_offloads_configured = *ic.ipsec_offloads_configured;
  error = onp_ipsec_register_esp_backend (vm, im);
  if (error)
    {
      onp_ipsec_err ("onp_ipsec_backend_register failed\n");
      return clib_error_return (error, "onp_ipsec_backend_register failed\n");
    }

#define _(index, name)                                                        \
  im->index =                                                                 \
    vlib_node_add_named_next (vm, ONP_SCHED_INPUT_NODE_INDEX, name);          \
  if (im->index == (u16) ~0)                                                  \
    {                                                                         \
      onp_ipsec_err ("Next-node addition from sched-input to %s failed",      \
		     name);                                                   \
      return clib_error_create (                                              \
	"Next-node addition from sched-input to %s failed", name);            \
    }
  foreach_onp_input_next_node;
#undef _

  /*
   * Enable schedule input node only if inline outbound offload is configured
   */
  if (im->ipsec_offloads_configured & CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND)
    onp_sched_input_node_enable_disable (vm, 0, 1);

  /*
   * Set IPsec queue only if lookaside offload is configured.
   */
  if (!(im->ipsec_offloads_configured & CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE))
    return 0;

  vec_foreach (cryptodev, cm->onp_cryptodevs)
    {
      /* Use last cryptodev for inbound IPsec */
      im->in_dev_id = cryptodev->crypto_dev_id;
      /* Save IPsec queue to be used in inbound node */
      im->in_ipsec_queue =
	cnxk_drv_crypto_queue_get (vm, cryptodev->crypto_dev_id,
				   ic.la_crypto_queue_config.crypto_queue_id);

      if (im->in_ipsec_queue == 0ULL)
	{
	  onp_ipsec_err ("cnxk_drv_crypto_queue_get failed");
	  return clib_error_create ("cnxk_drv_crypto_queue_get failed");
	}

      /* Use first cryptodev for outbound IPsec */
      if (i == 0)
	{
	  im->out_dev_id = cryptodev->crypto_dev_id;
	  /*
	   * Save IPsec queue to be used in outbound node.
	   * For single crypto device, same queue is used for both
	   * inbound and outbound
	   */
	  im->out_ipsec_queue = im->in_ipsec_queue;
	}
      i++;
    }

  return 0;
}

clib_error_t *
onp_ipsec_setup (vlib_main_t *vm)
{
  return onp_ipsec_init (vm);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
