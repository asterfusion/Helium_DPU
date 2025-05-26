/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP CLI implementation.
 */

#include <onp/onp.h>

static const char *ul = "====================================================="
			"=========================";

static clib_error_t *
onp_ipsec_reassembly_set_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  u32 sa_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &sa_index))
	;
      else
	return clib_error_create ("Invalid input '%U'", format_unformat_error,
				  input);
    }

  if (~0 != sa_index)
    onp_ipsec_reassembly_set (vm, sa_index);

  return 0;
}

/*?
 * This command enables reassembly feature on an inbound SA
 *
 * @cliexpar
 * @cliexstart{set onp ipsec reassembly}
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_ipsec_reassembly_set_command) = {
  .path = "set onp ipsec reassembly",
  .short_help = "set onp ipsec reassembly <sa_index>",
  .function = onp_ipsec_reassembly_set_fn,
};

static void
onp_print_global_counters (vlib_main_t *vm, u64 **stat, u64 *pool_stat,
			   u32 n_threads)
{
  u64 global_stat[ONP_MAX_COUNTERS] = { 0 };
  onp_main_t *om = onp_get_main ();
  unsigned int n_global_stats = 0;
  vlib_simple_counter_main_t *cm;
  u32 cnt_idx, thread_idx = 0;
  u64 global_pool_stat = 0;

  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	{
	  if (stat[cnt_idx][thread_idx])
	    {
	      global_stat[cnt_idx] += stat[cnt_idx][thread_idx];
	      n_global_stats++;
	    }
	}
      global_pool_stat += pool_stat[thread_idx];
    }

  if (!n_global_stats && !global_pool_stat)
    return;

  /* Display cumulative counters */
  vlib_cli_output (vm, "%-16s %-40s %-20s", "", "Global counter", "Value");
  vlib_cli_output (vm, "%-16s %-.40s %-.20s", "", ul, ul);

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  if (global_stat[i])                                                         \
    vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name, global_stat[i]);
  foreach_onp_counters;
#undef _

  if (global_pool_stat)
    vlib_cli_output (vm, "%-16s %-40s %20Ld", "",
		     "default-pool-current-refill-deplete-val",
		     global_pool_stat);
}

unsigned int
onp_get_per_thread_stats (u64 **stat, u64 *pool_stat, u32 n_threads,
			  u8 verbose, u8 *is_valid, u64 *threads_with_stats)
{
  unsigned int idx, cnt_idx, thread_idx = 0, n_threads_with_stats = 0;
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  for (idx = 0; idx < n_threads; idx++)
    {
      ptd = vec_elt_at_index (om->onp_per_thread_data, idx);
      pool_stat[idx] = ptd->refill_deplete_count_per_pool[0];
    }

#define _(i, s, n, v) is_valid[i] = verbose || !v;
  foreach_onp_counters;
#undef _

  /* Identify threads that have non-zero ONP counters */
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      if (pool_stat[thread_idx])
	{
	  threads_with_stats[n_threads_with_stats] = thread_idx;
	  n_threads_with_stats++;
	  continue;
	}
      for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	{
	  if (!is_valid[cnt_idx])
	    continue;
	  if (stat[cnt_idx][thread_idx])
	    {
	      threads_with_stats[n_threads_with_stats++] = thread_idx;
	      break;
	    }
	}
    }

  return n_threads_with_stats;
}

static void
onp_print_per_thread_counters (vlib_main_t *vm, u64 **stat, u64 *pool_stat,
			       u32 n_threads, u8 verbose)
{
  unsigned int idx, thread_idx = 0, n_threads_with_stats = 0;
  u8 is_valid[ONP_MAX_COUNTERS] = { 0 };
  u64 threads_with_stats[n_threads];
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;

  n_threads_with_stats = onp_get_per_thread_stats (
    stat, pool_stat, n_threads, verbose, is_valid, threads_with_stats);

  if (!n_threads_with_stats)
    return;

  vlib_cli_output (vm, "%-16s %-40s %-20s", "Thread", "Per-thread counter",
		   "Value");
  vlib_cli_output (vm, "%-.16s %-.40s %-.20s", ul, ul, ul);

  for (idx = 0; idx < n_threads_with_stats; idx++)
    {
      thread_idx = threads_with_stats[idx];

      vlib_cli_output (vm, "%-16s", vlib_worker_threads[thread_idx].name);

      /* clang-format off */
#define _(i, s, n, v)                                                       \
      cm = &om->onp_counters.s##_counters;                                  \
      if (is_valid[i] && stat[i][thread_idx])                               \
        vlib_cli_output (vm, "%-16s %-40s %20Ld", "", cm->name,             \
                         stat[i][thread_idx]);
      foreach_onp_counters;
#undef _
      /* clang-format on */

      /* Display stats with "current-refill-deplete-val" counter */
      if (pool_stat[thread_idx])
	vlib_cli_output (vm, "%-16s %-40s %20Ld", "",
			 "default-pool-current-refill-deplete-val",
			 pool_stat[thread_idx]);
    }

  vlib_cli_output (vm, "\n");

  return;
}

static clib_error_t *
onp_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  unsigned int cnt_idx = 0, thread_idx = 0;
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  cnxk_per_thread_data_t *ptd;
  u64 *stat[ONP_MAX_COUNTERS] = { 0 };
  u64 *pool_stat = NULL;
  counter_t *counters = NULL;
  u8 verbose = 0;
  u32 n_threads = vlib_get_n_threads ();

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_create ("Invalid input '%U'", format_unformat_error,
				  input);
    }

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vec_validate_init_empty (stat[i], n_threads, 0);                            \
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)                  \
    {                                                                         \
      counters = cm->counters[thread_idx];                                    \
      stat[i][thread_idx] = counters[0];                                      \
    }
  foreach_onp_counters;
#undef _

  vec_validate_init_empty (pool_stat, n_threads, 0);
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
    {
      ptd = vec_elt_at_index (om->onp_per_thread_data, thread_idx);
      pool_stat[thread_idx] = ptd->refill_deplete_count_per_pool[0];
    }

  onp_print_per_thread_counters (vm, stat, pool_stat, n_threads, verbose);

  onp_print_global_counters (vm, stat, pool_stat, n_threads);

  for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    vec_free (stat[cnt_idx]);

  vec_free (pool_stat);

  return 0;
}

/*?
 * This command displays ONP debug counters
 *
 * @cliexpar
 * Example of how to display ONP debug counters:
 * @cliexstart{show onp counters}
 * Per-thread counter                       Value
 * ======================================== ====================
 * default-pool-current-refill-deplete-val                     7
 *
 * Global counter                           Value
 * ======================================== ====================
 * default-pool-current-refill-deplete-val                     7
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_counters_command, static) = {
  .path = "show onp counters",
  .short_help = "show onp counters [verbose]",
  .function = onp_counters_command_fn,
};

static clib_error_t *
onp_counters_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{

  vlib_simple_counter_main_t *cm;
  onp_main_t *om = onp_get_main ();

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vlib_clear_simple_counters (cm);
  foreach_onp_counters;
#undef _

  return 0;
}

/*?
 * This command clears ONP debug counters
 *
 * @cliexpar
 * @cliexstart{clear onp counters}
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_counters_clear_command, static) = {
  .path = "clear onp counters",
  .short_help = "clear onp counters",
  .function = onp_counters_clear_command_fn,
};

static clib_error_t *
onp_show_version (vlib_main_t *vm, unformat_input_t *input,
		  vlib_cli_command_t *cmd)
{
#define _(a, b, c) vlib_cli_output (vm, "%-30s " b, a ":", c);
  _ ("ONP version", "%s", onp_version_str ());
#undef _
  return 0;
}

/*?
 * This command displays ONP version
 *
 * @cliexpar
 * @cliexstart{show onp version}
 * ONP version:            0.3.3
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_show_version_command, static) = {
  .path = "show onp version",
  .short_help = "Show ONP plugin and roc version",
  .function = onp_show_version,
};

static clib_error_t*
set_onp_interface_speed(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  u32 speed = 0;
  onp_pktio_t* pktio;
  onp_main_t* om = onp_get_main();
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%d %U", &speed,
    unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify a speed and interface.");
  }

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->hw_if_index == hw_if_index) {
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = {0};
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  if (!link_info.is_autoneg && link_info.speed != speed) {
    link_info.speed = speed;
    cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);
  }

  return error;
}

/* CLI command registration */
VLIB_CLI_COMMAND(set_onp_interface_speed_command, static) = {
  .path = "set onp interface speed",
  .short_help = "set onp interface speed <speed> <interface>",
  .function = set_onp_interface_speed,
};

static clib_error_t*
set_onp_interface_an(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  bool an = 0;
  onp_pktio_t* pktio;
  onp_main_t* om = onp_get_main();
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%d %U", &an,
    unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify autoneg on interface.");
  }

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios)
    ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->hw_if_index == hw_if_index) {
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = { 0 };
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  link_info.is_autoneg = an;
  cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);

  return error;
}

VLIB_CLI_COMMAND(set_onp_interface_an_command, static) = {
  .path = "set onp interface an",
  .short_help = "set onp interface an <an> <interface> ",
  .function = set_onp_interface_an,
};

static clib_error_t*
set_onp_interface_duplex(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  bool duplex = 0;
  onp_pktio_t* pktio;
  onp_main_t* om = onp_get_main();
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%d %U", &duplex,
    unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify duplex on interface.");
  }

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios)
    ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->hw_if_index == hw_if_index) {
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = { 0 };
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  link_info.is_full_duplex = duplex;
  cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);

  return error;
}

VLIB_CLI_COMMAND(set_onp_interface_duplex_command, static) = {
  .path = "set onp interface duplex",
  .short_help = "set onp interface duplex <duplex> <interface>",
  .function = set_onp_interface_duplex,
};

static clib_error_t*
get_onp_interface_link_info(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  onp_pktio_t* pktio;
  onp_main_t* om = onp_get_main();
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios)
    ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->hw_if_index == hw_if_index) {
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = { 0 };
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);

  vlib_cli_output(vm, "%U (%s):%s %s %u",
    format_vnet_sw_if_index_name, vnm, hw_if_index,
    link_info.is_up ? "up" : "down",
    link_info.is_autoneg ? "an enable" : "an disable",
    link_info.is_full_duplex ? "full duplex" : "half duplex",
    link_info.speed);

  return error;
}

VLIB_CLI_COMMAND(set_onp_interface_link_info_command, static) = {
  .path = "get onp interface link info",
  .short_help = "get onp interface info <interface>",
  .function = get_onp_interface_link_info,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
