/*
 * cgnat_log.c - CGNAT asynchronous log queue
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <string.h>

#include <vlib/vlib.h>
#include <vlib/threads.h>

#include <nat/cgnat/cgnat.h>

static u8 *
format_cgnat_log_instance_snapshot (u8 *s, va_list *args)
{
  u8 *label = va_arg (*args, u8 *);
  u32 instance_id = va_arg (*args, u32);

  if (label && label[0])
    return format (s, "%s", label);
  return format (s, "%u", instance_id);
}

static void
cgnat_log_copy_str (u8 *dst, u32 dst_len, char *src)
{
  u32 len;

  if (!dst_len)
    return;
  dst[0] = 0;
  if (!src)
    return;

  len = clib_min ((u32) strlen (src), dst_len - 1);
  clib_memcpy_fast (dst, src, len);
  dst[len] = 0;
}

static_always_inline char *
cgnat_log_mapping_type (u8 mapping_type)
{
  if (mapping_type == CGNAT_MAPPING_STATIC)
    return "static";
  if (mapping_type == CGNAT_MAPPING_DETERMINISTIC)
    return "deterministic";
  return "dynamic";
}

void
cgnat_log_event_set_common (cgnat_log_event_t *event,
			    cgnat_instance_t *instance, char *event_name,
			    char *reason)
{
  event->instance_id = instance->instance_id;
  cgnat_log_copy_str (event->event, sizeof (event->event), event_name);
  cgnat_log_copy_str (event->reason, sizeof (event->reason), reason);
  cgnat_log_copy_str (event->instance_label, sizeof (event->instance_label),
		      instance->label[0] ? (char *) instance->label : 0);
}

void
cgnat_log_emit (cgnat_log_event_t *event)
{
  vlib_log_class_t log_class = cgnat_main.log_class_dynamic;

  if (event->kind == CGNAT_LOG_EVENT_KIND_SESSION &&
      event->session.mapping_type == CGNAT_MAPPING_DETERMINISTIC)
    log_class = cgnat_main.log_class_deterministic;

  if (event->kind == CGNAT_LOG_EVENT_KIND_PBA_BLOCK)
    {
      if (event->reason[0])
	vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
		  "event=%s instance=%U private_ip=%U "
		  "public_ip=%U public_port_start=%u public_port_end=%u "
		  "reason=%s",
		  event->event,
		  format_cgnat_log_instance_snapshot, event->instance_label,
		  event->instance_id, format_ip4_address, &event->block.private_ip,
		  format_ip4_address, &event->block.public_ip,
		  event->block.public_port_start, event->block.public_port_end,
		  event->reason);
      else
	vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
		  "event=%s instance=%U private_ip=%U "
		  "public_ip=%U public_port_start=%u public_port_end=%u",
		  event->event,
		  format_cgnat_log_instance_snapshot, event->instance_label,
		  event->instance_id, format_ip4_address, &event->block.private_ip,
		  format_ip4_address, &event->block.public_ip,
		  event->block.public_port_start, event->block.public_port_end);
      return;
    }

  if (event->reason[0])
    vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
	      "event=%s instance=%U protocol=%u "
	      "private_ip=%U private_port=%u public_ip=%U public_port=%u "
	      "remote_ip=%U remote_port=%u type=%s reason=%s",
	      event->event,
	      format_cgnat_log_instance_snapshot, event->instance_label,
	      event->instance_id, event->session.protocol, format_ip4_address,
	      &event->session.private_ip, event->session.private_port,
	      format_ip4_address, &event->session.public_ip,
	      event->session.public_port, format_ip4_address,
	      &event->session.remote_ip, event->session.remote_port,
	      cgnat_log_mapping_type (event->session.mapping_type),
	      event->reason);
  else
    vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
	      "event=%s instance=%U protocol=%u "
	      "private_ip=%U private_port=%u public_ip=%U public_port=%u "
	      "remote_ip=%U remote_port=%u type=%s",
	      event->event,
	      format_cgnat_log_instance_snapshot, event->instance_label,
	      event->instance_id, event->session.protocol, format_ip4_address,
	      &event->session.private_ip, event->session.private_port,
	      format_ip4_address, &event->session.public_ip,
	      event->session.public_port, format_ip4_address,
	      &event->session.remote_ip, event->session.remote_port,
	      cgnat_log_mapping_type (event->session.mapping_type));
}

/* Producer side: any vlib thread (workers and main-thread timer paths)
 * pushes a fixed-size POD event.  When the fifo is full the event is
 * emitted synchronously via cgnat_log_emit instead of being dropped.
 * Note: on a worker thread that fallback calls vlib_log off the main
 * thread (debug images assert on this). */
void
cgnat_log_enqueue (cgnat_log_event_t *event)
{
  cgnat_main_t *cm = &cgnat_main;

  if (PREDICT_FALSE (lf_fifo_enqueue_mp (cm->log_fifo, 1, event) == 0))
    {
      clib_atomic_fetch_add_relax (&cm->log_full, 1);
      cgnat_log_emit (event);
      return;
    }
  clib_atomic_fetch_add_relax (&cm->log_enqueued, 1);
}

void
cgnat_log_init (cgnat_main_t *cm)
{
  cm->log_poll_interval = CGNAT_LOG_POLL_INTERVAL_DEFAULT;
  cm->log_fifo =
    lf_fifo_alloc (CGNAT_LOG_FIFO_SIZE, sizeof (cgnat_log_event_t));
}

static uword
cgnat_log_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cgnat_main_t *cm = &cgnat_main;
  uword event_type = 0, *event_data = NULL;
  cgnat_log_event_t *events = NULL;
  u32 n, i;

  vec_prealloc(events, 2048);

  while (1)
    {
      f64 poll_interval = cm->log_poll_interval ?
			    cm->log_poll_interval :
			    CGNAT_LOG_POLL_INTERVAL_DEFAULT;

      /* Wait for Godot... */
      if (cm->enabled)
      {
          vlib_process_wait_for_event_or_clock (vm, poll_interval);
          event_type = vlib_process_get_events (vm, &event_data);
      }
      else
      {
          vlib_process_wait_for_event (vm);
          event_type = vlib_process_get_events (vm, &event_data);
      }

      switch (event_type)
      {
      case CGNAT_TIMER_PROCESS_SCHED:
            break;
      default:
            /* Nothing to do. */
            break;
      }

      while ((n = lf_fifo_dequeue_sc (cm->log_fifo, 2048, events)) > 0)
	for (i = 0; i < n; i++)
	  {
	    cgnat_log_emit (&events[i]);
	    cm->log_sent++;
	  }
    }

  vec_free(events);
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_log_process_node) = {
  .function = cgnat_log_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cgnat-log-process",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
