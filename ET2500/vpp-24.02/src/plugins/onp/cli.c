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

#ifdef VPP_PLATFORM_ET2500
extern void onp_pktio_intf_link_up_down(u32 hw_if_index, uword up);
#endif

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

VLIB_CLI_COMMAND(get_onp_interface_link_info_command, static) = {
  .path = "get onp interface link info",
  .short_help = "get onp interface link info <interface>",
  .function = get_onp_interface_link_info,
};

static clib_error_t*
set_onp_interface_link_info(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  onp_pktio_t* pktio = NULL;
  onp_main_t* om = onp_get_main();
  vnet_main_t* vnm = vnet_get_main();
  cnxk_pktio_link_info_t link_info = { 0 };
  u32 speed = 0;
  vnet_sw_interface_t *si;

  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
      for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios)
        ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
        if (pktio->hw_if_index == hw_if_index) {
          break;
        }
      }
      si = vnet_get_sw_interface(vnm, hw_if_index);
      // cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
    } else if (unformat(input, "an enable")) {
      link_info.is_autoneg = 1;
    } else if (unformat(input, "an disable")) {
      link_info.is_autoneg = 0;
    } else if (unformat(input, "duplex full")) {
      link_info.is_full_duplex = 1;
    } else if (unformat(input, "duplex half")) {
      link_info.is_full_duplex = 0;
    } else if (unformat(input, "speed %u", &speed)) {
      link_info.speed = speed;
    } else {
      return clib_error_return(0, "Invalid input '%U'", format_unformat_error,
                               input);
    }
  }

  if (!pktio) {
    return clib_error_return(0, "Please specify a valid interface.");
  }

  cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);

#ifdef VPP_PLATFORM_ET2500
  if (si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    onp_pktio_intf_link_up_down(hw_if_index, true);
#endif

  return error;
}

VLIB_CLI_COMMAND(set_onp_interface_link_info_command, static) = {
  .path = "set onp interface link info",
  .short_help = "set onp interface link info <interface> [an <enable | disable>] "
                "[duplex <full | half>] | speed <speed>]",
  .function = set_onp_interface_link_info,
};

static clib_error_t*
set_onp_port_dscp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 dscp, tc;

  if (!unformat(input, "%d %d %U",&dscp, &tc, unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->dscp_to_tc, dscp, tc);

  return error;
}

VLIB_CLI_COMMAND(set_onp_port_dscp_tc_map_command, static) = {
  .path = "set onp port dscp tc",
  .short_help = "set onp port dscp tc <dscp> <tc> <interface>",
  .function = set_onp_port_dscp_tc_map,
};


static clib_error_t*
set_onp_port_dot1p_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 dot1p, tc;

  if (!unformat(input, "%d %d %U",&dot1p, &tc, unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->dot1p_to_tc, dot1p, tc);

  return error;
}

VLIB_CLI_COMMAND(set_onp_port_dot1p_tc_map_command, static) = {
  .path = "set onp port dot1p tc",
  .short_help = "set onp port dot1p tc <dot1p> <tc> <interface>",
  .function = set_onp_port_dot1p_tc_map,
};


static clib_error_t*
set_onp_port_tc_queue_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 queue, tc;

  if (!unformat(input, "%d %d %U",&tc, &queue, unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->tc_to_queue, tc, queue);

  return error;
}

VLIB_CLI_COMMAND(set_onp_port_tc_queue_map_command, static) = {
  .path = "set onp port tc queue",
  .short_help = "set onp port tc queue <tc> <queue> <interface>",
  .function = set_onp_port_tc_queue_map,
};

static clib_error_t*
rm_onp_port_dscp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->dscp_to_tc);

  return error;
}

VLIB_CLI_COMMAND(rm_onp_port_dscp_tc_map_command, static) = {
  .path = "rm onp port dscp tc",
  .short_help = "rm onp port tc <interface>",
  .function = rm_onp_port_dscp_tc_map,
};

static clib_error_t*
rm_onp_port_dot1p_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->dot1p_to_tc);

  return error;
}

VLIB_CLI_COMMAND(rm_onp_port_dot1p_tc_map_command, static) = {
  .path = "rm onp port dot1p tc",
  .short_help = "rm onp port dot1p tc <interface>",
  .function = rm_onp_port_dot1p_tc_map,
};

static clib_error_t*
rm_onp_port_tc_queue_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->tc_to_queue);

  return error;
}

VLIB_CLI_COMMAND(rm_onp_port_tc_queue_map_command, static) = {
  .path = "rm onp port tc queue",
  .short_help = "rm onp port tc queue <interface>",
  .function = rm_onp_port_tc_queue_map,
};

static clib_error_t*
show_onp_port_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 key, value;

  if (!unformat(input, "%U",unformat_vnet_hw_interface,
    vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_foreach(key, value, hi->tc_to_queue, ({
  vlib_cli_output(vm, "%U tc_to_queue (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  hash_foreach(key, value, hi->dscp_to_tc, ({
  vlib_cli_output(vm, "%U dscp_to_tc (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  hash_foreach(key, value, hi->dot1p_to_tc, ({
  vlib_cli_output(vm, "%U dot1p_to_tc (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  return error;
}

VLIB_CLI_COMMAND(show_onp_port_tc_map_command, static) = {
  .path = "show onp port tc map",
  .short_help = "show onp port tc map <interface>",
  .function = show_onp_port_tc_map,
};

static clib_error_t *
set_onp_traffic_class(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u32 hw_if_index = UINT32_MAX;
  vnet_main_t *vnm = vnet_get_main();
  u8 enable_disable = 0;
  u32 flags = 0;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_vnet_hw_interface, vnm,
                 &hw_if_index))
      ;
    else if (unformat(line_input, "enable"))
      enable_disable = 1;
    else if (unformat(line_input, "disable"))
      enable_disable = 0;
    else
    {
      error = clib_error_return(0, "unknown input '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }

  if (enable_disable)
  {
    flags |= VNET_HW_INTERFACE_FLAG_USE_TC;
  }
  else
  {
    flags = 0;
  }

  vnet_hw_interface_set_tc_flags(vnm, hw_if_index, flags);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(set_onp_traffic_command_command, static) = {
  .path = "set onp traffic",
  .short_help = "set onp traffic <interface> [enable|disable]",
  .function = set_onp_traffic_class,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
