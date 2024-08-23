/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/modules/ipsec/ipsec_fp_cn10k.h>
#include <onp/drv/modules/ipsec/ipsec_priv.h>
#include <onp/drv/modules/pool/pool_priv.h>
#include <onp/drv/modules/sched/sched_priv.h>
#include <onp/drv/modules/pktio/pktio_priv.h>

i32
cn10k_ipsec_lookaside_setup (vlib_main_t *vm, cnxk_ipsec_config_t *ic)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_capability_t *capa = NULL;
  cnxk_crypto_dev_t *crypto_dev = NULL;
  cnxk_ipsec_context_t *cic = NULL;
  cnxk_crypto_queue_t *queue;
  u16 cnxk_crypto_index = 0;
  u16 cnxk_crypto_queue = 0;
  int i = 0;

  cnxk_crypto_queue = ic->la_crypto_queue_config.crypto_queue_id;

  for (cnxk_crypto_index = 0; cnxk_crypto_index < cm->n_crypto_dev;
       cnxk_crypto_index++)
    {
      crypto_dev = cnxk_crypto_dev_get (cnxk_crypto_index);
      capa =
	cnxk_drv_crypto_capability_get (vm, crypto_dev->cnxk_crypto_index);
      if (!capa)
	{
	  cnxk_crypto_err ("cnxk_drv_crypto_capability_get failed");
	  return -1;
	}

      if (!capa->grp_capa[CNXK_CRYPTO_GROUP_IE].ipsec_lookaside_mode)
	continue;

      if (crypto_dev->crypto_device_status != CNXK_CRYPTO_CONFIGURED)
	{
	  cnxk_ipsec_err (
	    "Incorrect state of crypto device: %d for cnxk_drv_ipsec_setup",
	    cnxk_crypto_index);
	  return -1;
	}
      if (!clib_bitmap_get (crypto_dev->bitmask_attached_queues,
			    cnxk_crypto_queue))
	{
	  cnxk_ipsec_err ("Crypto queue: %d not attached to crypto device: %d",
			  cnxk_crypto_queue, cnxk_crypto_index);
	  return -1;
	}

      queue = &crypto_dev->crypto_queues[cnxk_crypto_queue];

      if (queue->cnxk_cpt_enq_pool_index == ~0)
	{
	  cnxk_ipsec_err (
	    "No pool configured for crypto device: %u, queue: %u",
	    cnxk_crypto_index, cnxk_crypto_queue);
	  return -1;
	}

      /*
       * Create IPsec context for crypto device. This saves
       * IPsec queue info, pool info, and sessions.
       */
      vec_alloc_aligned (cic, 1, CLIB_CACHE_LINE_BYTES);

      clib_memset (cic, 0, sizeof (cnxk_ipsec_context_t));

      crypto_dev->cnxk_ipsec_context = cic;
      cic->cnxk_sched_vec_pool_index = queue->cnxk_cpt_enq_pool_index;
      cic->cnxk_crypto_index = cnxk_crypto_index;
      cic->cnxk_crypto_queue_index = cnxk_crypto_queue;

      im->ipsec_offloads |= CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE;
    }

  if (!(im->ipsec_offloads & CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE))
    return 0;

  /* Allocate lookaside ipsec sessions */
  vec_validate_aligned (im->lookaside_ipsec_sessions, CNXK_IPSEC_MAX_SESSION,
			CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < vec_len (im->lookaside_ipsec_sessions); i++)
    im->lookaside_ipsec_sessions[i] = cnxk_drv_physmem_alloc (
      vm, sizeof (cn10k_ipsec_session_t), CLIB_CACHE_LINE_BYTES);

  return 0;
}

i32
cn10k_ipsec_inline_setup (vlib_main_t *vm, cnxk_ipsec_config_t *ic)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cnxk_pktio_inl_dev_cfg_t inl_dev_cfg;
  u32 enable_outbound, enable_inbound;
  int i = 0;

  inl_dev_cfg.outb_nb_desc = ic->inl_ipsec_config.n_crypto_desc;
  inl_dev_cfg.outb_nb_crypto_qs = ic->inl_outb_nb_crypto_lf;
  inl_dev_cfg.reassembly_conf.max_wait_time_ms =
    ic->reassembly_config.inl_reassembly_max_wait_time_ms;
  inl_dev_cfg.reassembly_conf.active_limit =
    ic->reassembly_config.inl_reassembly_active_limit;
  inl_dev_cfg.reassembly_conf.active_thres =
    ic->reassembly_config.inl_reassembly_active_thres;
  inl_dev_cfg.reassembly_conf.zombie_limit =
    ic->reassembly_config.inl_reassembly_zombie_limit;
  inl_dev_cfg.reassembly_conf.zombie_thres =
    ic->reassembly_config.inl_reassembly_zombie_thres;

  enable_outbound = im->ipsec_capa.ipsec_inl_outbound_supported;
  enable_inbound = im->ipsec_capa.ipsec_inl_inbound_supported;

  /* TODO: pktio drv call also can be SoC based function pointer. */
  if (cn10k_pktio_inl_dev_cfg (vm, &inl_dev_cfg, enable_outbound,
			       enable_inbound, &im->ipsec_offloads))
    {
      cnxk_pktio_err ("cn10k_pktio_inl_dev_cfg failed");
      return -1;
    }

  /* Allocate inline IPsec sessions */
  vec_validate_aligned (im->inline_ipsec_sessions, CNXK_IPSEC_MAX_SESSION,
			CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < vec_len (im->inline_ipsec_sessions); i++)
    im->inline_ipsec_sessions[i] = cnxk_drv_physmem_alloc (
      vm, sizeof (cn10k_ipsec_session_t), CLIB_CACHE_LINE_BYTES);

  return 0;
}

const cnxk_ipsec_ops_t ipsec_10k_ops = {
  .cnxk_ipsec_session_create = cn10k_ipsec_session_create,
  .cnxk_ipsec_session_destroy = cn10k_ipsec_session_destroy,
  .cnxk_ipsec_lookaside_setup = cn10k_ipsec_lookaside_setup,
  .cnxk_ipsec_inline_setup = cn10k_ipsec_inline_setup,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
