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

void
cgnat_log_event_set_common (cgnat_log_event_t *event,
			    cgnat_instance_t *instance, char *event_name,
			    char *reason)
{
  event->timestamp = unix_time_now ();
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
		  "CGNAT_LOG event=%s TIMESTAMP=%U instance=%U private_ip=%U "
		  "public_ip=%U reason=%s",
		  event->event, format_cgnat_log_timestamp, event->timestamp,
		  format_cgnat_log_instance_snapshot, event->instance_label,
		  event->instance_id, format_ip4_address, &event->block.private_ip,
		  format_ip4_address, &event->block.public_ip, event->reason);
      else
	vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
		  "CGNAT_LOG event=%s TIMESTAMP=%U instance=%U private_ip=%U "
		  "public_ip=%U",
		  event->event, format_cgnat_log_timestamp, event->timestamp,
		  format_cgnat_log_instance_snapshot, event->instance_label,
		  event->instance_id, format_ip4_address, &event->block.private_ip,
		  format_ip4_address, &event->block.public_ip);
      return;
    }

  if (event->reason[0])
    vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
	      "CGNAT_LOG event=%s TIMESTAMP=%U instance=%U protocol=%u "
	      "private_ip=%U private_port=%u public_ip=%U public_port=%u "
	      "remote_ip=%U remote_port=%u type=%s reason=%s",
	      event->event, format_cgnat_log_timestamp, event->timestamp,
	      format_cgnat_log_instance_snapshot, event->instance_label,
	      event->instance_id, event->session.protocol, format_ip4_address,
	      &event->session.private_ip, event->session.private_port,
	      format_ip4_address, &event->session.public_ip,
	      event->session.public_port, format_ip4_address,
	      &event->session.remote_ip, event->session.remote_port,
	      event->session.mapping_type == CGNAT_MAPPING_STATIC ? "static" :
								    "dynamic",
	      event->reason);
  else
    vlib_log (VLIB_LOG_LEVEL_NOTICE, log_class,
	      "CGNAT_LOG event=%s TIMESTAMP=%U instance=%U protocol=%u "
	      "private_ip=%U private_port=%u public_ip=%U public_port=%u "
	      "remote_ip=%U remote_port=%u type=%s",
	      event->event, format_cgnat_log_timestamp, event->timestamp,
	      format_cgnat_log_instance_snapshot, event->instance_label,
	      event->instance_id, event->session.protocol, format_ip4_address,
	      &event->session.private_ip, event->session.private_port,
	      format_ip4_address, &event->session.public_ip,
	      event->session.public_port, format_ip4_address,
	      &event->session.remote_ip, event->session.remote_port,
	      event->session.mapping_type == CGNAT_MAPPING_STATIC ? "static" :
								    "dynamic");
}

void
cgnat_log_enqueue (cgnat_log_event_t *event)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_log_queue_t *queue;
  u64 head, tail, used;
  u32 thread_index = vlib_get_thread_index ();

  if (PREDICT_FALSE (thread_index >= vec_len (cm->log_queues)))
    {
      cgnat_log_emit (event);
      return;
    }

  queue = vec_elt_at_index (cm->log_queues, thread_index);
  head = queue->head;
  tail = clib_atomic_load_acq_n (&queue->tail);
  used = head - tail;

  if (PREDICT_FALSE (used >= queue->size))
    {
      clib_atomic_fetch_add_relax (&queue->full, 1);
      clib_atomic_fetch_add_relax (&queue->direct, 1);
      cgnat_log_emit (event);
      return;
    }

  queue->events[head & queue->mask] = *event;
  clib_atomic_store_rel_n (&queue->head, head + 1);
  clib_atomic_fetch_add_relax (&queue->enqueued, 1);

  used++;
  if (used > clib_atomic_load_relax_n (&queue->max_used))
    {
      u64 old = clib_atomic_load_relax_n (&queue->max_used);
      while (used > old &&
	     !clib_atomic_cmp_and_swap_acq_relax_n (&queue->max_used, &old,
						   used, 0))
	;
    }
}

static u32
cgnat_log_drain_queue (cgnat_log_queue_t *queue)
{
  cgnat_log_event_t event;
  u64 head, tail;
  u32 drained = 0;

  tail = queue->tail;
  head = clib_atomic_load_acq_n (&queue->head);
  while (tail != head)
    {
      event = queue->events[tail & queue->mask];
      clib_atomic_store_rel_n (&queue->tail, tail + 1);
      tail++;
      cgnat_log_emit (&event);
      clib_atomic_fetch_add_relax (&queue->sent, 1);
      drained++;
    }

  return drained;
}

void
cgnat_log_init (cgnat_main_t *cm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  u32 i;

  cm->log_poll_interval = CGNAT_LOG_POLL_INTERVAL_DEFAULT;
  vec_validate_aligned (cm->log_queues, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  vec_foreach_index (i, cm->log_queues)
    {
      cgnat_log_queue_t *queue = vec_elt_at_index (cm->log_queues, i);
      queue->size = CGNAT_LOG_QUEUE_SIZE;
      queue->mask = CGNAT_LOG_QUEUE_SIZE - 1;
      vec_validate_aligned (queue->events, queue->size - 1,
			    CLIB_CACHE_LINE_BYTES);
    }
}

static uword
cgnat_log_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cgnat_main_t *cm = &cgnat_main;

  while (1)
    {
      f64 poll_interval = cm->log_poll_interval ?
			    cm->log_poll_interval :
			    CGNAT_LOG_POLL_INTERVAL_DEFAULT;
      u32 i;

      vlib_process_wait_for_event_or_clock (vm, poll_interval);
      vlib_process_get_events (vm, 0);

      vec_foreach_index (i, cm->log_queues)
	{
	  cgnat_log_queue_t *queue = vec_elt_at_index (cm->log_queues, i);
	  cgnat_log_drain_queue (queue);
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_log_process_node, static) = {
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
