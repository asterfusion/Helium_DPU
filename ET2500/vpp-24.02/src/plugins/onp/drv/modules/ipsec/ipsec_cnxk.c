/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/ipsec/ipsec_priv.h>
#include <onp/drv/modules/pktio/pktio_priv.h>
#include <onp/drv/modules/crypto/crypto_priv.h>
#include <onp/drv/inc/pool.h>
#include <onp/drv/inc/ipsec.h>
#include <onp/drv/modules/pci/pci.h>

cnxk_ipsec_main_t cnxk_ipsec_main;

STATIC_ASSERT ((sizeof (struct cpt_inst_s) <= CNXK_HW_COMMON_INST_SIZE),
	       "cnxk_per_thread_data->hw_inst should be increased from 64");

cnxk_ipsec_capability_t *
cnxk_drv_ipsec_capability_get (vlib_main_t *vm)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cnxk_pktio_main_t *pm = cnxk_pktio_get_main ();
  cnxk_crypto_main_t *cm = CNXK_CRYPTO_MAIN ();
  cnxk_crypto_capability_t *crypto_capa = NULL;
  cnxk_ipsec_capability_t *ipsec_capa = NULL;
  cnxk_pktio_capa_t pktio_capa = { 0 };
  cnxk_pktio_ops_map_t *pktio_ops;
  cnxk_crypto_dev_t *crypto_dev;
  cnxk_pktio_t *pktio;
  int rv = 0;

  ipsec_capa = &im->ipsec_capa;

  /* Check for Lookaside IPsec capability */
  if (!cm->n_crypto_dev)
    goto skip_la_capa_check;

  /* Get first crypto device */
  crypto_dev = cnxk_crypto_dev_get (0);
  crypto_capa =
    cnxk_drv_crypto_capability_get (vm, crypto_dev->cnxk_crypto_index);
  if (!crypto_capa)
    {
      cnxk_crypto_err ("cnxk_drv_crypto_capability_get failed");
      return NULL;
    }

  if (crypto_capa->grp_capa[CNXK_CRYPTO_GROUP_IE].ipsec_lookaside_mode)
    ipsec_capa->ipsec_lookaside_supported = 1;

skip_la_capa_check:

  /* Check for Inline IPsec capability */
  if (!vec_len (pm->pktio_ops))
    goto skip_inl_capa_check;

  /* Get first pktio device */
  pktio_ops = cnxk_pktio_get_pktio_ops (0);
  pktio = &pktio_ops->pktio;
  rv = cnxk_drv_pktio_capa_get (vm, pktio->pktio_index, &pktio_capa);
  if (rv)
    {
      cnxk_pktio_err ("Failed to get cnxk pktio capabilities , rv=%d", rv);
      return NULL;
    }

  if (pktio_capa.is_pktio_inl_outbound)
    {
      cnxk_pktio_notice ("cnxk IPsec inline outbound supported");
      ipsec_capa->ipsec_inl_outbound_supported = 1;
    }

  if (pktio_capa.is_pktio_inl_inbound)
    {
      cnxk_pktio_notice ("cnxk IPsec inline inbound supported");
      ipsec_capa->ipsec_inl_inbound_supported = 1;
    }

skip_inl_capa_check:

  return ipsec_capa;
}

i32
cnxk_drv_ipsec_session_create (vlib_main_t *vm, uintptr_t ipsec_queue,
			       u32 sa_index, const u64 mode)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  const cnxk_ipsec_ops_t *ipsec_ops = NULL;

  ipsec_ops = im->ipsec_ops;

  return ipsec_ops->cnxk_ipsec_session_create (vm, ipsec_queue, sa_index,
					       mode);
}

i32
cnxk_drv_ipsec_session_destroy (vlib_main_t *vm, uintptr_t ipsec_queue,
				u32 sa_index)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  const cnxk_ipsec_ops_t *ipsec_ops = NULL;

  ipsec_ops = im->ipsec_ops;
  if (!ipsec_ops)
    {
      cnxk_ipsec_err ("IPsec ops not supported");
      return -1;
    }

  if (!ipsec_ops->cnxk_ipsec_session_destroy)
    {
      cnxk_ipsec_err ("IPsec session_destroy is not supported");
      return -1;
    }

  return ipsec_ops->cnxk_ipsec_session_destroy (vm, ipsec_queue, sa_index);
}

i32
cnxk_drv_ipsec_inline_setup (vlib_main_t *vm, cnxk_ipsec_config_t *ic)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  const cnxk_ipsec_ops_t *ipsec_ops = NULL;

  ipsec_ops = im->ipsec_ops;

  return ipsec_ops->cnxk_ipsec_inline_setup (vm, ic);
}

i32
cnxk_drv_ipsec_lookaside_setup (vlib_main_t *vm, cnxk_ipsec_config_t *ic)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  const cnxk_ipsec_ops_t *ipsec_ops = NULL;

  ipsec_ops = im->ipsec_ops;

  return ipsec_ops->cnxk_ipsec_lookaside_setup (vm, ic);
}

i32
cnxk_drv_ipsec_init (vlib_main_t *vm, cnxk_ipsec_config_t *ic)
{
  cnxk_ipsec_main_t *im = CNXK_IPSEC_GET_MAIN ();
  cnxk_ipsec_capability_t *capa = NULL;

  capa = cnxk_drv_ipsec_capability_get (vm);
  if (!capa)
    {
      cnxk_ipsec_err ("cnxk_drv_ipsec_capability_get failed");
      return -1;
    }

  ic->ipsec_offloads_configured = &im->ipsec_offloads;

  if (roc_model_is_cn10k ())
    im->ipsec_ops = &ipsec_10k_ops;
  else
    ASSERT (0);

  /* Configure lookaside IPsec. */
  if (cnxk_drv_ipsec_lookaside_setup (vm, ic) < 0)
    {
      cnxk_ipsec_err ("cnxk_drv_ipsec_lookaside_setup failed");
      return -1;
    }

  if (capa->ipsec_inl_outbound_supported || capa->ipsec_inl_inbound_supported)
    {
      /* Configure inline IPsec. */
      if (cnxk_drv_ipsec_inline_setup (vm, ic))
	{
	  cnxk_ipsec_err ("cnxk_drv_ipsec_inline_setup failed");
	  return -1;
	}
    }

  return 0;
}

VLIB_REGISTER_LOG_CLASS (cnxk_ipsec_log) = {
  .class_name = "onp/ipsec",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
