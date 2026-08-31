/*
 * cgnat.c - CGNAT plugin core: init, timer process, feature registration
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_source.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <plugins/acl/public_inlines.h>

#include <nat/cgnat/cgnat.h>

cgnat_main_t cgnat_main;
/* Shared with cgnat_config.c (ACL existence checks on binding). */
acl_plugin_methods_t cgnat_acl_plugin;

u8 *
format_cgnat_instance_name (u8 *s, va_list *args)
{
  cgnat_instance_t *instance = va_arg (*args, cgnat_instance_t *);

  if (instance->label[0])
    return format (s, "%s", instance->label);
  return format (s, "%u", instance->instance_id);
}

static uword
cgnat_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		     vlib_frame_t *f)
{
  cgnat_main_t *cm = &cgnat_main;
  uword event_type = 0, *event_data = NULL;
  f64 last_reap = 0;

  while (1)
    {
      /* Wait for Godot... */
      if (cm->enabled)
      {
          vlib_process_wait_for_event_or_clock (vm, 0.01);
          event_type = vlib_process_get_events (vm, &event_data);
      }
      else
      {
          vlib_process_wait_for_event (vm);
          event_type = vlib_process_get_events (vm, &event_data);
      }

      f64 now = vlib_time_now (vm);
      switch (event_type)
      {
      case CGNAT_TIMER_PROCESS_SCHED:
            break;
      default:
            /* Nothing to do. */
            break;
      }

      /* Expire is lock-synchronized with the datapath (session/cooling timer
       * locks, striped table locks, atomic flags), so it needs no worker
       * barrier even with millions of sessions in flight. */
      cgnat_pba_expire_timers (now);
      cgnat_session_expire_timers (now);

      /* Slot reclamation is different: datapath readers resolve session and
       * mapping pool pointers without any lock, so deleted entries may only
       * return to their pools once every worker has passed a barrier.
       *
       * Run it only when there is actually something to reap, and at most
       * every 200ms: an unconditional barrier at the 10ms expire cadence
       * pauses every worker 100 times a second even when the reap queues
       * are empty.  The vec_len reads race with worker-side vec_add1, which
       * is harmless: a missed update just defers reclamation to the next
       * tick, and the 200ms cadence bounds the delay either way.  The
       * barrier section stays O(reaped count), independent of the expire
       * workload.
       *
       * Depth trigger: under sustained churn the 200ms cadence pins
       * delete_rate x 0.2s pool slots; reap early once the queue exceeds
       * 2% of the session pool so new flows don't fail while capacity
       * exists. */
      u8 reap_pending = vec_len (cm->session_reap_queue) ||
			vec_len (cm->mapping_reap_queue) ||
			vec_len (cm->mapping_reap_quarantine);
      if (reap_pending &&
	  (now - last_reap >= 0.2 ||
	   vec_len (cm->session_reap_queue) > pool_len (cm->sessions) / 50))
	{
	  vlib_worker_thread_barrier_sync (vm);
	  cgnat_reap (cm);
	  vlib_worker_thread_barrier_release (vm);
	  last_reap = now;
	}

      vec_reset_length (event_data);
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_timer_process_node) = {
  .function = cgnat_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-timer-process",
};

VNET_FEATURE_INIT (ip4_cgnat_in2out_policy, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-in2out-policy",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature"),
  .runs_before = VNET_FEATURES ("spi-ip4-input-worker-handoff",
				"spi-ip4-input-node"),
};

VNET_FEATURE_INIT (ip4_cgnat_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "cgnat-out2in",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa",
                               "ip4-sv-reassembly-feature",
                               "ip4-dhcp-client-detect"),
  .runs_before = VNET_FEATURES ("spi-ip4-input-worker-handoff",
				"spi-ip4-input-node"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Carrier-grade NAT",
};
/* *INDENT-ON* */

static clib_error_t *
cgnat_init (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  vlib_node_t *node;
  clib_error_t *error;

  clib_memset (cm, 0, sizeof (*cm));

  cm->vlib_main = vm;
  cm->vnet_main = vnet_get_main ();
  cm->ip4_main = &ip4_main;
  cm->fib_src = fib_source_allocate ("cgnat", FIB_SOURCE_PRIORITY_LOW,
                                     FIB_SOURCE_BH_SIMPLE);
  cm->log_class_dynamic =
    vlib_log_register_class_rate_limit ("CGNAT", "DYNAMIC", 0x7FFFFFFF);
  vlib_log_get_subclass_data (cm->log_class_dynamic)->level =
    VLIB_LOG_LEVEL_DISABLED;
  vlib_log_get_subclass_data (cm->log_class_dynamic)->syslog_level =
    VLIB_LOG_LEVEL_NOTICE;

  cm->log_class_deterministic =
    vlib_log_register_class_rate_limit ("CGNAT", "DETERMINISTIC", 0x7FFFFFFF);
  vlib_log_get_subclass_data (cm->log_class_deterministic)->level =
    VLIB_LOG_LEVEL_DISABLED;
  vlib_log_get_subclass_data (cm->log_class_deterministic)->syslog_level =
    VLIB_LOG_LEVEL_NOTICE;

  cgnat_log_init (cm);

  error = acl_plugin_exports_init (&cgnat_acl_plugin);
  if (error)
    return error;

  node = vlib_get_node_by_name (vm, (u8 *) "cgnat-in2out-policy");
  cm->in2out_policy_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "cgnat-in2out");
  cm->in2out_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "cgnat-out2in");
  cm->out2in_node_index = node->index;

  return cgnat_api_hookup (vm);
}

VLIB_INIT_FUNCTION (cgnat_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
