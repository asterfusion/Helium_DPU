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

      cgnat_pba_expire_timers (now);
      cgnat_session_expire_timers (now);

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
    VLIB_LOG_LEVEL_NOTICE;
  vlib_log_get_subclass_data (cm->log_class_dynamic)->syslog_level =
    VLIB_LOG_LEVEL_NOTICE;

  cm->log_class_deterministic =
    vlib_log_register_class_rate_limit ("CGNAT", "DETERMINISTIC", 0x7FFFFFFF);
  vlib_log_get_subclass_data (cm->log_class_deterministic)->level =
    VLIB_LOG_LEVEL_NOTICE;
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
