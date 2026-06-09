/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP crypto implementation.
 */

#include <onp/onp.h>

onp_crypto_main_t onp_crypto_main;

always_inline uword
round_multiple (uword x, uword multiple)
{
  return multiple * ((x + multiple - 1) / multiple);
}

static_always_inline void
onp_crypto_key_handler (vlib_main_t *vm, vnet_crypto_key_op_t kop,
			vnet_crypto_key_index_t idx)
{
  if (kop == VNET_CRYPTO_KEY_OP_DEL)
    {
      cnxk_drv_crypto_key_del_handler (vm, idx);
      return;
    }
  cnxk_drv_crypto_key_add_handler (vm, idx);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_8_enc (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_enc (vm, frame, 8);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_12_enc (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_enc (vm, frame, 12);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_0_enc (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_enc (vm, frame, 0);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_8_dec (vlib_main_t *vm,
				   vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_dec (vm, frame, 8);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_12_dec (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_dec (vm, frame, 12);
}

static_always_inline int
onp_crypto_enqueue_aead_aad_0_dec (vlib_main_t *vm,
				    vnet_crypto_async_frame_t *frame)
{
  return cnxk_drv_crypto_enqueue_aead_aad_dec (vm, frame, 0);
}

clib_error_t *
onp_crypto_config_parse (onp_config_main_t *conf, vlib_pci_addr_t pci_addr,
			 unformat_input_t *sub_input)
{
  onp_main_t *om = onp_get_main ();
  onp_crypto_config_t *crypto_conf;
  uword *p;

  if (om->onp_crypto_count >= 2)
    return clib_error_create (
      "More than two crypto devices are not supported");

  /* Check for invalid PCI address */
  if (pci_addr.as_u32 == (u32) ONP_DEV_PCI_ADDR_ANY)
    return clib_error_create ("Invalid PCI addr for default config %U",
			      format_vlib_pci_addr, &pci_addr);

  /* Check duplicate */
  p = hash_get (conf->onp_crypto_config_index_by_pci_addr, pci_addr.as_u32);
  if (p)
    return clib_error_create ("Duplicate configuration for PCI address %U",
			      format_vlib_pci_addr, &pci_addr);

  pool_get_zero (conf->onp_cryptoconfs, crypto_conf);
  hash_set (conf->onp_crypto_config_index_by_pci_addr, pci_addr.as_u32,
	    crypto_conf - conf->onp_cryptoconfs);

  crypto_conf->crypto_pci_addr.as_u32 = pci_addr.as_u32;
  crypto_conf->n_crypto_hw_queues = 1;

  if (sub_input)
    {
      unformat_skip_white_space (sub_input);

      while (unformat_check_input (sub_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (sub_input, "num-hw-queues %u",
			&crypto_conf->n_crypto_hw_queues))
	    ;
	  else
	    return clib_error_create ("unknown input '%U'",
				      format_unformat_error, sub_input);
	}
    }

  om->onp_crypto_count++;

  return 0;
}

static void
onp_crypto_prepare_queue_config (onp_main_t *om,
				 cnxk_crypto_queue_config_t *queue_config)
{
  u32 n_crypto_desc_per_queue;

  queue_config->num_pkt_buf = om->onp_conf->onp_num_pkt_buf;

  n_crypto_desc_per_queue =
    2 * om->onp_conf->onp_num_pkt_buf / om->onp_crypto_count;

  /* use first queue id */
  queue_config->crypto_queue_id = 0;

  queue_config->crypto_queue_pool_buffer_size =
    round_pow2 (sizeof (cnxk_sched_vec_header_t), VLIB_BUFFER_ALIGN);

  queue_config->crypto_min_burst_size = ONP_MIN_VEC_SIZE;

  queue_config->n_crypto_desc =
    round_multiple (n_crypto_desc_per_queue, CNXK_FRAME_SIZE);
}

static clib_error_t *
onp_crypto_init (vlib_main_t *vm)
{
  onp_crypto_main_t *cm = &onp_crypto_main;
  cnxk_crypto_config_t crypto_config;
  vlib_pci_dev_handle_t pci_handle;
  onp_crypto_config_t *conf = NULL;
  cnxk_crypto_capability_t *capa;
  onp_main_t *om = &onp_main;
  onp_crypto_t *dev = NULL;
  clib_error_t *error = 0;
  u32 engine_index;
  u16 i;

  if (!om->onp_conf->is_crypto_config_enabled)
    {
      onp_crypto_warn ("ONP Crypto is disabled");
      return NULL;
    }

  for (i = 0; i < om->onp_crypto_count; i++)
    {
      conf = vec_elt_at_index (om->onp_conf->onp_cryptoconfs, i);
      vec_add2 (cm->onp_cryptodevs, dev, 1);
      clib_memset (dev, 0, sizeof (onp_crypto_t));
      dev->crypto_dev_id =
	cnxk_drv_crypto_probe (vm, &conf->crypto_pci_addr, &pci_handle);

      if (dev->crypto_dev_id < 0)
	{
	  cnxk_crypto_err ("cnxk_drv_crypto_probe for %U failed",
			   format_vlib_pci_addr, conf->crypto_pci_addr);

	  error =
	    clib_error_create ("cnxk_drv_crypto_probe for %U failed",
			       format_vlib_pci_addr, conf->crypto_pci_addr);
	  goto crypto_dev_clear;
	}

      capa = cnxk_drv_crypto_capability_get (vm, dev->crypto_dev_id);
      if (!capa)
	{
	  cnxk_crypto_err ("cnxk_drv_crypto_capability_get failed");
	  error = clib_error_create ("cnxk_drv_crypto_capability_get failed");
	  goto crypto_remove;
	}

      if (capa->max_crypto_queues < conf->n_crypto_hw_queues)
	{
	  cnxk_crypto_err ("Max crypto queues %d not supported",
			   conf->n_crypto_hw_queues);
	  error = clib_error_create ("Max crypto queues %d not supported",
				     conf->n_crypto_hw_queues);
	  goto crypto_remove;
	}

      /* Configure CPT device */
      crypto_config.n_crypto_hw_queues = conf->n_crypto_hw_queues;
      if (cnxk_drv_crypto_configure (vm, dev->crypto_dev_id, &crypto_config) <
	  0)
	{
	  cnxk_crypto_err ("cnxk_drv_crypto_configure failed");
	  error = clib_error_create ("cnxk_drv_crypto_configure failed");
	  goto crypto_remove;
	}

      onp_crypto_prepare_queue_config (om, &crypto_config.queue_config);

      if (cnxk_drv_crypto_queue_init (vm, dev->crypto_dev_id,
				      &crypto_config.queue_config) !=
	  crypto_config.queue_config.crypto_queue_id)
	{
	  cnxk_crypto_err ("cnxk_drv_crypto_queue_init failed for %d",
			   crypto_config.queue_config.crypto_queue_id);
	  goto crypto_remove;
	}
    }

  if (cnxk_drv_crypto_sw_queue_init (vm) < 0)
    {
      cnxk_crypto_err ("Failed to initialize crypto software queue");
      goto crypto_remove;
    }

  cnxk_drv_crypto_set_success_packets_counters (
    CNXK_CRYPTO_COUNTER_TYPE_DEFAULT,
    &om->onp_counters.crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT]
       .success_packets_counters);

  cnxk_drv_crypto_set_pending_packets_counters (
    CNXK_CRYPTO_COUNTER_TYPE_DEFAULT,
    &om->onp_counters.crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT]
       .pending_packets_counters);

  cnxk_drv_crypto_set_crypto_inflight_counters (
    CNXK_CRYPTO_COUNTER_TYPE_DEFAULT,
    &om->onp_counters.crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT]
       .crypto_inflight_counters);

  engine_index = vnet_crypto_register_engine (vm, "onp_cryptodev", 100,
					      "ONP Cryptodev Engine");
#define _(n, k, t, a)                                                         \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_ENC,             \
    onp_crypto_enqueue_aead_aad_##a##_enc);                                   \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##n##_TAG##t##_AAD##a##_DEC,             \
    onp_crypto_enqueue_aead_aad_##a##_dec);
  foreach_onp_crypto_aead_async_alg
#undef _

#define _(c, h, k, d)                                                         \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_ENC,                \
    cnxk_drv_crypto_enqueue_linked_alg_enc);                                  \
  vnet_crypto_register_enqueue_handler (                                      \
    vm, engine_index, VNET_CRYPTO_OP_##c##_##h##_TAG##d##_DEC,                \
    cnxk_drv_crypto_enqueue_linked_alg_dec);
    foreach_onp_crypto_link_async_alg;
#undef _

  vnet_crypto_register_dequeue_handler (vm, engine_index,
					cnxk_drv_crypto_frame_dequeue);

  vnet_crypto_register_key_handler (vm, engine_index, onp_crypto_key_handler);

  return 0;

crypto_remove:
  cnxk_drv_crypto_remove (vm, dev->crypto_dev_id);

crypto_dev_clear:
  for (; i > 0; i--)
    {
      dev = vec_elt_at_index (cm->onp_cryptodevs, i - 1);
      cnxk_drv_crypto_dev_clear (vm, dev->crypto_dev_id);
      cnxk_drv_crypto_remove (vm, dev->crypto_dev_id);
    }
  vec_free (cm->onp_cryptodevs);
  return error;
}

clib_error_t *
onp_crypto_setup (vlib_main_t *vm)
{
  clib_error_t *error = 0;

  error = onp_crypto_init (vm);

  return error;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
