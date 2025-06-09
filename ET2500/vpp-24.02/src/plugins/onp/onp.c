/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON native plugin implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/pool_fp.h>

onp_main_t onp_main;
onp_config_main_t onp_config_main;

clib_error_t *
onp_uuid_parse (char *input, uuid_t uuid)
{
  uuid_clear (uuid);

  if (uuid_parse (input, uuid))
    return clib_error_create ("uuid_parse failed");

  if (uuid_is_null (uuid))
    return clib_error_create ("UUID is null");

  return 0;
}

const char *
onp_address_to_str (void *p)
{
  Dl_info info = { 0 };

  if (dladdr (p, &info) == 0)
    return 0;

  return info.dli_sname;
}

static clib_error_t *
onp_per_thread_data_init (onp_main_t *om)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  onp_config_main_t *conf = &onp_config_main;
  u16 iter;

  /* vlib_buffer_t template */
  vec_validate_aligned (om->onp_per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  onp_pool_debug ("pktpool refill_deplete_sz is %d",
		  conf->onp_pktpool_refill_deplete_sz);

  for (iter = 0; iter < tm->n_vlib_mains; iter++)
    {
      cnxk_per_thread_data_t *ptd =
	vec_elt_at_index (om->onp_per_thread_data, iter);

      clib_memset (ptd, 0, sizeof (cnxk_per_thread_data_t));

      ptd->buffer_template.flags =
	(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
	 VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VLIB_BUFFER_EXT_HDR_VALID);

      vnet_buffer (&ptd->buffer_template)->sw_if_index[VLIB_TX] = (u32) ~0;

      ptd->buffer_template.ref_count = 1;

      ptd->pktio_node_state = 1;

      cnxk_drv_per_thread_data_init (ptd, conf->onp_pktpool_refill_deplete_sz,
				     ONP_MAX_VLIB_BUFFER_POOLS);
    }
  return NULL;
}

void
onp_node_enable_disable (u32 node_index, u32 start_thread, u32 end_thread,
			 u8 enable_disable)
{
  vlib_global_main_t *vgm = vlib_get_global_main ();
  u8 thread_index, state;

  state = enable_disable ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  for (thread_index = start_thread; thread_index <= end_thread; thread_index++)
    {
      if (state !=
	  vlib_node_get_state (vgm->vlib_mains[thread_index], node_index))
	vlib_node_set_state (vgm->vlib_mains[thread_index], node_index, state);
    }
}

uword
onp_dispatch_wrapper_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame)
{
  return node->function (vm, node, frame);
}

void
onp_dispatch_wrapper_fn_enable_disable_on_thread (u16 thread, int is_enable)
{
  onp_main_t *om = onp_get_main ();

  /*
   * TODO: Add details in "show onp dump"
   */
  if (is_enable && om->onp_sched_main.is_scheduler_enabled &&
      thread /* Not on main thread */)
    vlib_node_set_dispatch_wrapper (vlib_get_main_by_index (thread),
				    onp_dispatch_wrapper_fn);

  /*
   * TODO: Clear dispatcher_wrapper when sched mode is disabled
   */
}

void
onp_dispatch_wrapper_fn_enable_disable (u8 enable_disable)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  int iter;

  for (iter = vdm->first_worker_thread_index;
       iter <= vdm->last_worker_thread_index; iter++)
    onp_dispatch_wrapper_fn_enable_disable_on_thread (iter, enable_disable);
}

/*?
 * Configure the ONP plugin.
 *
 * @anchor pci-dev
 * Devices are identified by <pci-dev> in ONP startup configuration.
 * <pci-dev> is a string of the form
 * @c DDDD:BB:SS.F, where
 * @verbatim
 * DDDD Domain
 * BB   Bus
 * SS   Slot
 * F    Function
 * @endverbatim
 * This is similar to the format used in linux to enumerate PCI devices
 * in the sysfs tree (at @c /sys/bus/pci/devices/).
 *
 * @cfgcmd{dev, <pci-dev> \{ ... \}}
 * White-lists and configures a network device.
 * See @ref onp_syscfg_dev.
 *
 * @cfgcmd{dev, default \{ ... \}}
 * Changes the default settings for all network devices.
 * See @ref onp_syscfg_dev_default.
 *
 * @cfgcmd{dev, sched <pci-dev> \{ ... \}}
 * White-lists and configures a scheduler device.
 * See @ref onp_syscfg_sched.
 *
 * @cfgcmd{dev, crypto <pci-dev> \{ ... \}}
 * White-lists and configures a crypto device.
 * See @ref onp_syscfg_crypto.
 *
 * @cfgcmd{ipsec \{ ... \}}
 * Init parameters to control IPsec configuration
 * See @ref onp_syscfg_ipsec.
 *
 * @cfgcmd{num-pkt-bufs, <n>}
 * Sets the number of packet buffers to allocate. The default value is @ref
 * ONP_N_PKT_BUF.
 *
 * @par Example:
 * @verbatim
 * onp {
 *     dev 0000:02:00.0 {
 *         num-rx-queues 3
 *         num-tx-queues 3
 *         num-rx-desc 512
 *         num-tx-desc 1024
 *     }
 *
 *     # Crypto VF PCI BDF
 *     dev crypto 0002:10:00.1
 *
 *     # SSO VF PCI BDF
 *     dev sched 0002:0e:00.1
 *
 *     num-pktbufs 16384
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_dev dev <pci-dev>
 * Configures the NIX device @ref pci-dev.
 *
 * Parameters:
 *
 * @cfgcmd{num-rx-queues, <n>}
 * Selects the number of receive queues. The default value is the number of
 * VPP worker threads.
 *
 * @cfgcmd{num-tx-queues, <n>}
 * Selects the number of transmit queues. The default value is the number of
 * VPP worker threads.
 *
 * @cfgcmd{num-rx-desc, <n>}
 * Selects the number of descriptors in each receive queue. The default value
 * is @ref ONP_DEFAULT_N_RX_DESC
 *
 * @cfgcmd{num-tx-desc, <n>}
 * Selects the number of descriptors in each transmit queue. The default value
 * is @ref ONP_DEFAULT_N_TX_DESC
 *
 * @par Example:
 * @verbatim
 * dev 0000:02:00.0 {
 *     num-rx-queues 2
 *     num-tx-queues 2
 *     num-rx-desc 256
 *     num-tx-desc 256
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_dev_default dev default
 * Changes default settings for all the network interfaces. This section
 * supports the same set of parameters described in @ref onp_syscfg_dev.
 *
 * @par Example:
 * @verbatim
 * dev default {
 *     num-rx-queues 3
 *     num-tx-queues 3
 *     num-rx-desc 512
 *     num-tx-desc 1024
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_sched dev sched <pci-dev>
 * Configures the SSO device @ref pci-dev and enables scheduler mode.
 *
 * @par Example:
 * @verbatim
 * dev sched 0002:0e:00.1
  * @endverbatim
 *
 * @subsection onp_syscfg_crypto dev crypto <pci-dev>
 * Configures the crypto device @ref pci-dev for crypto operations.
 * It also registers the ONP IPsec ESP backend.
 *
 * @par Example:
 * @verbatim
 * dev crypto 0002:10:00.1
 * @endverbatim
 *
 * @subsection onp_syscfg_ipsec ipsec {}
 * Control init IPsec configuration parameters
 *
 * Parameters:
 *
 * @cfgcmd{disable-ipsec-backend}
 * Disables ONP IPsec nodes and allow VPP IPsec nodes to be used. This
 * parameter is only recommended where deployment use-cases do not involve
 * IPsec
 *
 * @cfgcmd{num-crypto-desc, <n>}
 * Selects the number of crypto descriptors per crypto queue. A single crypto
 * queue is used for IPsec offload on OCTEON cn96xx. ONP aligns the
 * provided number of num-crypto-desc in multiple of @ref CNXK_FRAME_SIZE.
 * Default value (@ref ONP_IPSEC_MAX_FRAMES_PER_CORE * max(8, num_of_workers())
 *
 * @cfgcmd{reassembly-wait-time, <n>}
 * Configures the maximum reassembly wait time in hardware. The timeout
 * @c <n> is a integer, in milliseconds. The default value is @c 1000.
 * Applicable only for cn10k device.
 *
 * @par Examples:
 * @verbatim
 * ipsec {
 *     num-crypto-desc 4096
 *     disable-ipsec-backend
 *     reassembly-wait-time 1000
 * }
 * @endverbatim
 *
 * @subsection onp_syscfg_num_pkt_buf num-pkt-bufs
 * Sets the number of packet buffers to allocate.
 ?*/
static clib_error_t *
onp_config (vlib_main_t *vm, unformat_input_t *input)
{
  onp_config_main_t *conf = &onp_config_main;
  onp_pktio_config_t *pktioconf = NULL;
  onp_main_t *om = onp_get_main ();
  vlib_pci_addr_t crypto_pci_addr;
  vlib_pci_addr_t sched_pci_addr;
  unformat_input_t sub_input;
  clib_error_t *error = NULL;
  vlib_pci_addr_t pci_addr;
  onp_sched_main_t *sched;
  onp_pktio_t *pktio;

  sched = &om->onp_sched_main;

  clib_memset (conf, 0, sizeof (*conf));

  conf->onp_pktio_config_index_by_pci_addr = hash_create (0, sizeof (uword));
  conf->onp_crypto_config_index_by_pci_addr = hash_create (0, sizeof (uword));
  conf->onp_num_pkt_buf = ONP_N_PKT_BUF;
  conf->onp_schedconf.sched_pci_addr.as_u32 = ONP_DEV_PCI_ADDR_ANY;
  conf->onp_pktpool_refill_deplete_sz = CNXK_POOL_MAX_REFILL_DEPLTE_COUNT;
  conf->onp_ipsecconf.is_ipsec_backend_enabled = 1;
  conf->onp_ipsecconf.reassembly_max_wait_time =
    ONP_IPSEC_REASSEMBLY_MAX_WAIT_TIME;
  crypto_pci_addr.as_u32 = ONP_DEV_PCI_ADDR_ANY;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dev %U %U", unformat_vlib_pci_addr, &pci_addr,
		    unformat_vlib_cli_sub_input, &sub_input))
	{
	  error = onp_pktio_config_parse (conf, pci_addr, &sub_input, 0);
	  if (error)
	    return error;
	}

      else if (unformat (input, "dev %U", unformat_vlib_pci_addr, &pci_addr))
	{
	  error = onp_pktio_config_parse (conf, pci_addr, 0, 0);
	  if (error)
	    return error;
	}

      else if (unformat (input, "dev default %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  pci_addr.as_u32 = ONP_DEV_PCI_ADDR_ANY;
	  error = onp_pktio_config_parse (conf, pci_addr, &sub_input, 1);
	  if (error)
	    return error;
	}

      else if (unformat (input, "dev crypto %U %U", unformat_vlib_pci_addr,
			 &crypto_pci_addr, unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  conf->is_crypto_config_enabled = 1;
	  /* Use first crypto queue for IPsec */
	  conf->onp_ipsecconf.crypto_hw_queue_id = ONP_IPSEC_QUEUE;

	  error = onp_crypto_config_parse (conf, crypto_pci_addr, &sub_input);
	  if (error)
	    return error;
	}
      else if (unformat (input, "dev crypto %U", unformat_vlib_pci_addr,
			 &crypto_pci_addr))
	{
	  conf->is_crypto_config_enabled = 1;
	  /* Use first crypto queue for IPsec */
	  conf->onp_ipsecconf.crypto_hw_queue_id = ONP_IPSEC_QUEUE;

	  error = onp_crypto_config_parse (conf, crypto_pci_addr, 0);
	  if (error)
	    return error;
	}
      else if (unformat (input, "ipsec %U", unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error = onp_ipsec_config_parse (conf, &sub_input);
	  if (error)
	    return error;
	}

      else if (unformat (input, "num-pkt-buf %d", &conf->onp_num_pkt_buf))
	;
      else if (unformat (input, "enable-sched-based-pkt-vector-simulation"))
	conf->onp_schedconf.pkt_vector_simulation_enabled = 1;

      else if (unformat (input, "disable-scheduler"))
	conf->onp_schedconf.is_sched_config_enabled = 0;

      else if (unformat (input, "dev sched %U %U", unformat_vlib_pci_addr,
			 &sched_pci_addr, unformat_vlib_cli_sub_input,
			 &sub_input))
	{
	  error = onp_sched_config_parse (conf, &sub_input, sched_pci_addr);
	  if (error)
	    return error;
	  conf->onp_schedconf.is_sched_config_enabled = 1;
	}
      else if (unformat (input, "dev sched %U", unformat_vlib_pci_addr,
			 &sched_pci_addr))
	{
	  error = onp_sched_config_parse (conf, NULL, sched_pci_addr);
	  if (error)
	    return error;
	  conf->onp_schedconf.is_sched_config_enabled = 1;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  if (conf->onp_schedconf.is_sched_config_enabled)
    clib_memset (sched, 0, sizeof (onp_sched_main_t));
  else
    /* If scheduler is disabled then it overrides simulation*/
    conf->onp_schedconf.pkt_vector_simulation_enabled = 0;

  onp_pktio_configs_validate (vm, conf);

  /* Configure early_init pktio */
  vec_foreach (pktioconf, om->onp_conf->onp_pktioconfs)
    {
      error = onp_pktio_early_setup (vm, om, pktioconf, &pktio);
      if (error)
	{
	  clib_error_return (0, "onp_pktio_early_setup failed for pci_add: %u",
			     pktioconf->pktio_pci_addr.as_u32);
	  return (error);
	}
    }
  /* Configure pools */
  if (pool_elts (om->onp_pktios))
    {
      error = onp_buffer_pools_setup (vm);
      if (error)
	{
	  clib_error_return (0, "onp_buffer_pools_setup failed");
	  return error;
	}
    }

  return NULL;
}

VLIB_CONFIG_FUNCTION (onp_config, "onp");

static clib_error_t *
onp_init (vlib_main_t *vm, vlib_node_runtime_t *nrt, vlib_frame_t *frame)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  onp_pktio_config_t *pktioconf = NULL;
  onp_sched_main_t *schedm = NULL;
  onp_main_t *om = onp_get_main ();
  clib_error_t *error = NULL;
  onp_pktio_t *pktio;
  int pktio_index = 0;

  /* Initialize per_thread_data */
  onp_per_thread_data_init (om);
  cnxk_drv_pktpool_set_refill_deplete_counters (
    CNXK_POOL_COUNTER_TYPE_DEFAULT,
    &om->onp_counters.pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].refill_counters,
    &om->onp_counters.pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].deplete_counters);

  if (om->onp_conf->onp_schedconf.is_sched_config_enabled)
    {
      /* Configure scheduler */
      error = onp_sched_setup (om, &schedm);
      if (error)
	{
	  clib_error_return (0, "onp_sched_setup failed");
	  return (error);
	}
    }

  /* Configure pktio */
  vec_foreach (pktioconf, om->onp_conf->onp_pktioconfs)
    {
      pktio = &om->onp_pktios[pktio_index];
      error = onp_pktio_setup (vm, om, pktioconf, &pktio);
      if (error)
	{
	  clib_error_return (0, "onp_pktio_setup failed for pci_add: %u",
			     pktioconf->pktio_pci_addr.as_u32);
	  return (error);
	}
      pktio_index++;
    }

  /* Enable pktio input node if simulation is disabled */
  if (schedm && schedm->is_pkt_vector_sim_enabled)
    {
      pool_foreach (pktio, om->onp_pktios)
	{
	  if (!cnxk_drv_pktio_is_inl_dev (vm, pktio->onp_pktio_index))
	    onp_pktio_txqs_fp_set (vm, pktio->onp_pktio_index, 1);
	}

      onp_sched_register_pre_barrier_callback_fn (1);

      onp_dispatch_wrapper_fn_enable_disable (1);

      onp_node_enable_disable (ONP_SCHED_INPUT_NODE_INDEX,
			       vdm->first_worker_thread_index + 1,
			       vdm->last_worker_thread_index, 1);
    }
  else
    {
      pool_foreach (pktio, om->onp_pktios)
	{
	  if (!cnxk_drv_pktio_is_inl_dev (vm, pktio->onp_pktio_index))
	    {
	      onp_pktio_txqs_fp_set (vm, pktio->onp_pktio_index, 1);
	      onp_pktio_assign_and_enable_all_rqs (
		vm, pktio->onp_pktio_index, ONP_PKTIO_INPUT_NODE_INDEX,
		VNET_HW_IF_RXQ_THREAD_ANY, 1);
	    }
	}
    }

  if (om->onp_conf->is_crypto_config_enabled)
    {
      error = onp_crypto_setup (vm);
      if (error)
	{
	  clib_error_return (error, "onp_crypto_setup failed");
	  cnxk_crypto_err ("onp_crypto_setup failed");
	  return (error);
	}

      if (om->onp_conf->onp_ipsecconf.is_ipsec_backend_enabled)
	{
	  error = onp_ipsec_setup (vm);
	  if (error)
	    {
	      clib_error_return (error, "IPsec backend configuration failed");
	      cnxk_crypto_err ("onp_ipsec_setup failed");
	      return (error);
	    }
	}
    }

  om->onp_init_done = 1;
  return error;
}

static uword
onp_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *pktio;
  f64 timeout = 5.0;
  clib_error_t *error;

  error = onp_init (vm, rt, f);

  if (error)
    {
      cnxk_pktio_err ("onp_init failed");
      clib_error_report (error);
      return 0;
    }

  /* Update status before process get suspended */
  vec_foreach (pktio, om->onp_pktios)
    {
      onp_pktio_link_state_update (pktio);
    }

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      vec_foreach (pktio, om->onp_pktios)
	{
	  onp_pktio_link_state_update (pktio);
	}
    }
  return 0;
}

VLIB_REGISTER_NODE (onp_process_node, static) = {
  .function = onp_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "onp-process",
  .process_log2_n_stack_bytes = 18,
};

static clib_error_t *
onp_plugin_init (vlib_main_t *vm)
{
  onp_main_t *om = onp_get_main ();
  clib_error_t *error = 0;

  om->vlib_main = vm;
  om->vnet_main = vnet_get_main ();
  om->onp_conf = &onp_config_main;

  pool_alloc(om->scheduler_profile_pool, 512);

#define _(idx, s, str, v)                                                     \
  om->onp_counters.s##_counters.name = str;                                   \
  om->onp_counters.s##_counters.stat_segment_name = "/onp/" str "_counters";  \
  vlib_validate_simple_counter (&om->onp_counters.s##_counters, 0);           \
  vlib_zero_simple_counter (&om->onp_counters.s##_counters, 0);

  foreach_onp_counters
#undef _

    error = cnxk_plt_model_init ();
  if (error)
    return error;

  return error;
}

VLIB_INIT_FUNCTION (onp_plugin_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Marvell OCTEON native (onp) plugin",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
