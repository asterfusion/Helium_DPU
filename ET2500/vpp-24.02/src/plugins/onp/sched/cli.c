/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP scheduler CLI implementation.
 */

#include <onp/onp.h>

#define foreach_onp_sched_grp_counter                                         \
  _ (ws_pc, ws_pc)                                                            \
  _ (ext_pc, ext_pc)                                                          \
  _ (wa_pc, wa_pc)                                                            \
  _ (ts_pc, ts_pc)                                                            \
  _ (ds_pc, ds_pc)                                                            \
  _ (dq_pc, dq_pc)                                                            \
  _ (aw_status, aw_status)                                                    \
  _ (page_cnt, page_cnt)

static clib_error_t *
onp_sched_queue_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  cnxk_sched_grp_stats_t stats = { 0 };
  onp_main_t *om = onp_get_main ();
  int rv = 0, i;

  if (!om->onp_sched_main.is_scheduler_enabled)
    vlib_cli_output (vm, "sched device is not available");
  else
    {
      u16 n_grps = onp_sched_total_queues_get ();

      vlib_cli_output (vm, "%-10s%-18s%-10s%", "Queue", "Name", "Count");
      for (i = 0; i < n_grps; i++)
	{
	  rv = cnxk_drv_sched_grp_stats_dump (vm, i, &stats);
	  if (rv < 0)
	    {
	      return 0;
	    }
	  vlib_cli_output (vm, "%-10d", i);
#define _(n, c) vlib_cli_output (vm, "%-10s%-10s%10Ld", "", #n, stats.c);

	  foreach_onp_sched_grp_counter
#undef _
	}
    }
  return NULL;
}

/*?
 * This command dumps OCTEON scheduler queue (or group) registers.
 *
 * @cliexpar
 * @cliexstart{show onp sched queue}
 * Queue     Name              Count
 * 0         ws_pc              0
 *           ext_pc             0
 *           wa_pc              0
 *           ts_pc              0
 *           ds_pc              0
 *           dq_pc              0
 *           aw_status        267
 *           page_cnt           0
 * 1         ws_pc              0
 *           ext_pc             0
 *           wa_pc              0
 *           ts_pc              0
 *           ds_pc              0
 *           dq_pc              0
 *           aw_status        267
 *           page_cnt           0
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_sched_queue_show_command, static) = {
  .path = "show onp sched queue",
  .short_help = "show onp sched queue",
  .function = onp_sched_queue_show_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
onp_sched_placement_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  onp_main_t *om = onp_get_main ();

  if (!om->onp_sched_main.is_scheduler_enabled)
    vlib_cli_output (vm, "sched device is not available");
  else
    {
      uword *grp_bit_map;
      int i;
      u8 n_threads;

      n_threads = vlib_thread_main.n_vlib_mains;
      vlib_cli_output (vm, "Sched core Groups:%d, Sched default Groups:%d",
		       n_threads, onp_sched_total_queues_get () - n_threads);
      vlib_cli_output (vm, "%8s%16s", "Thread", "SchedGroup");
      for (i = 0; i < n_threads; i++)
	{
	  clib_bitmap_alloc (grp_bit_map, 256);
	  cnxk_drv_sched_thread_grp_link_status_get (vm, grp_bit_map, i);
	  vlib_cli_output (vm, "%8d%16U", i, format_bitmap_list, grp_bit_map);
	  clib_bitmap_free (grp_bit_map);
	}
    }

  return NULL;
}

/*?
 * This command displays OCTEON scheduler queue (or group) to core mapping
 *
 * @cliexpar
 * @cliexstart{show onp sched placement}
 * Sched core Groups:5, Sched default Groups:4
 *  Thread      SchedGroup
 *       0          0, 5-8
 *       1          1, 5-8
 *       2          2, 5-8
 *       3          3, 5-8
 *       4             4-8
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_show_thread_link_command, static) = {
  .path = "show onp sched placement",
  .short_help = "show onp sched placement",
  .function = onp_sched_placement_command_fn,
  .is_mp_safe = 1,
};

static clib_error_t *
onp_sched_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  onp_main_t *om = onp_get_main ();
  clib_error_t *error = NULL;
  u8 verbose = 0;

  while (unformat_check_input (input) != (uword) UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "verbose"))
	verbose = 1;
      else
	{
	  error = clib_error_create ("Invalid input '%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (!om->onp_sched_main.is_scheduler_enabled)
    vlib_cli_output (vm, "sched device is not available");
  else
    {
      if (verbose)
	cnxk_drv_sched_info_dump (vm);
    }
done:
  return error;
}

/*?
 * This command dumps OCTEON scheduler (aka SSO) registers
 *
 * @cliexpar
 * @cliexstart{show onp sched dump}
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_show_command, static) = {
  .path = "show onp sched dump",
  .short_help = "show onp sched dump",
  .function = onp_sched_command_fn,
  .is_mp_safe = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
