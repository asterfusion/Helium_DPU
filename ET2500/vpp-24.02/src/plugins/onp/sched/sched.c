/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP scheduler implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/sched_fp.h>

u32
onp_sched_total_queues_get (void)
{
  onp_main_t *om = onp_get_main ();
  onp_sched_main_t *schedm = &om->onp_sched_main;

  return (schedm->n_sched_core_queues + schedm->n_sched_default_queues);
}

static void
onp_worker_thread_pre_barrier_callback_fn (vlib_main_t *vm)
{
  cnxk_drv_sched_lock_release (vm);
}

void
onp_sched_register_pre_barrier_callback_fn_on_thread (u8 thread_index,
						      u8 enable_disable)
{
  vlib_main_t *vm = vlib_get_main_by_index (thread_index);
  clib_callback_enable_disable (
    vm->worker_thread_pre_barrier_loop_callbacks,
    vm->worker_thread_pre_barrier_loop_callback_tmp,
    vm->worker_thread_pre_barrier_loop_callback_lock,
    onp_worker_thread_pre_barrier_callback_fn, enable_disable);
}

void
onp_sched_register_pre_barrier_callback_fn (u8 enable_disable)
{
  vnet_device_main_t *vdm = &vnet_device_main;
  int iter;

  for (iter = vdm->first_worker_thread_index;
       iter <= vdm->last_worker_thread_index; iter++)
    {
      onp_sched_register_pre_barrier_callback_fn_on_thread (iter,
							    enable_disable);
    }
}

clib_error_t *
onp_sched_config_parse (onp_config_main_t *conf, unformat_input_t *sub_input,
			vlib_pci_addr_t pci_addr)
{
  clib_error_t *error = NULL;
  u8 *uuid_string;

  /* Single SSO device is supported */
  conf->onp_schedconf.sched_pci_addr.as_u32 = pci_addr.as_u32;

  uuid_clear (conf->onp_schedconf.uuid_token);
  /*
   * Sched core queues are from 0 to n_vlib_mains. Use n_threads instead of
   * vlib_num_workers() as vlib_num_workers_xx() API do not take care of
   * worker index properly
   */
  conf->onp_schedconf.n_sched_core_queues = vlib_thread_main.n_vlib_mains;

  /*
   * Plugin specific sched group requirements. [n_threads,  n_threads +
   * CNXK_SCHED_GRP_APP_TYPE_MAX]
   */
  conf->onp_schedconf.n_sched_default_queues = CNXK_SCHED_GRP_APP_TYPE_MAX;

  if (!sub_input)
    return 0;

  unformat_skip_white_space (sub_input);

  while (unformat_check_input (sub_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (sub_input, "vf-token %s", &uuid_string))
	{
	  error = onp_uuid_parse ((char *) uuid_string,
				  conf->onp_schedconf.uuid_token);
	  if (error)
	    return clib_error_return (error, "Failed to parse uuid string");
	}

      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, sub_input);
    }
  return 0;
}

clib_error_t *
onp_sched_setup (onp_main_t *om, onp_sched_main_t **ppschedmain)
{
  onp_sched_config_t *schedconf = &om->onp_conf->onp_schedconf;
  onp_sched_main_t *schedm = &om->onp_sched_main;
  vlib_pci_device_info_t *sched_pci_dev_info;
  u8 n_threads = vlib_num_workers () + 1;
  vlib_pci_addr_t sched_pci_addr = { 0 };
  vlib_main_t *vm = vlib_get_main ();
  cnxk_sched_config_t sched_config;
  i32 sched_dev_id, rv;
  clib_error_t *error;
  int i, j;

  schedm->is_scheduler_enabled = 0;
  if (!schedconf->is_sched_config_enabled)
    {
      onp_sched_warn ("ONP Scheduler is disabled");
      return NULL;
    }
  if (schedconf->sched_pci_addr.as_u32 == ONP_DEV_PCI_ADDR_ANY)
    {
      onp_sched_warn ("ONP Scheduler disabled as no PCI addr provided");
      return NULL;
    }
  sched_pci_addr.as_u32 = schedconf->sched_pci_addr.as_u32;

  sched_pci_dev_info = vlib_pci_get_device_info (vm, &sched_pci_addr, &error);

  if (sched_pci_dev_info == NULL || error)
    {
      error = clib_error_return (error, "Invalid PCI device information");
      return error;
    }
  sched_dev_id =
    cnxk_drv_sched_init (vm, &sched_pci_addr, schedconf->uuid_token);

  if (sched_dev_id < 0)
    {
      error = clib_error_return (error, "cnxk_drv_sched_init failed");
      return error;
    }

  sched_config.n_queues =
    schedconf->n_sched_core_queues + schedconf->n_sched_default_queues;

  rv = cnxk_drv_sched_config (vm, sched_config);
  if (rv < 0)
    {
      error = clib_error_return (error, "cnxk_drv_sched_config failed");
      return error;
    }

  for (i = 0; i < n_threads; i++)
    {

      u16 grp[255];
      /*
       * Link each core (including main core) it's corresponding group
       *   1:1 mapping
       */

      grp[0] = i;
      rv = cnxk_drv_sched_grp_link (vm, grp, i, 1);
      if (rv < 0)
	{
	  error = clib_error_return (error, "cnxk_drv_sched_grp_link failed");
	  return error;
	}

      /* 2. Link each core (including main core) to all default groups */
      for (j = 0; j < schedconf->n_sched_default_queues; j++)
	grp[j] = schedconf->n_sched_core_queues + j;

      rv = cnxk_drv_sched_grp_link (vm, grp, i,
				    schedconf->n_sched_default_queues);
      if (rv < 0)
	{
	  error = clib_error_return (error, "cnxk_drv_sched_grp_link failed");
	  return error;
	}
    }

  /* Set priority for default groups */
  for (j = 1; j <= schedconf->n_sched_default_queues; j++)
    {
      rv = cnxk_drv_sched_grp_prio_set (
	/* Queue X translates to groupX-1 */
	vm, schedconf->n_sched_core_queues + j - 1, j - 1);
      if (rv < 0)
	{
	  error =
	    clib_error_return (error, "cnxk_drv_sched_grp_prio_set failed");
	  return error;
	}
    }
  onp_sched_debug ("sched specific queues [core,default]:[%d,%d]",
		   schedconf->n_sched_core_queues,
		   schedconf->n_sched_default_queues);
  schedm->n_sched_core_queues = schedconf->n_sched_core_queues;
  schedm->n_sched_default_queues = schedconf->n_sched_default_queues;
  schedm->sched_pci_addr.as_u32 = schedconf->sched_pci_addr.as_u32;
  schedm->is_scheduler_enabled = 1;
  schedm->is_pkt_vector_sim_enabled = schedconf->pkt_vector_simulation_enabled;

  if (ppschedmain)
    *ppschedmain = schedm;

  return 0;
}

void
onp_sched_input_node_enable_disable (vlib_main_t *vm, u32 thread_index,
				     int enable_disable)
{
  onp_main_t *om = onp_get_main ();
  vnet_device_main_t *vdm = &vnet_device_main;

  if (!om->onp_sched_main.sched_handling_ref_count)
    {
      /* Pre barrier call back */
      onp_sched_register_pre_barrier_callback_fn (enable_disable);

      /* Dispatcher wrapper function */
      onp_dispatch_wrapper_fn_enable_disable (enable_disable);

      /*
       * Enable/disable sched-input node on worker cores
       */
      onp_node_enable_disable (ONP_SCHED_INPUT_NODE_INDEX,
			       vdm->first_worker_thread_index,
			       vdm->last_worker_thread_index, enable_disable);
      om->onp_sched_main.sched_handling_ref_count++;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
