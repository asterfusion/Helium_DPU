/*
 * cgnat_in2out_slow.c - CGNAT inside to outside slow-path node
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <nat/cgnat/cgnat.h>
#include <nat/cgnat/cgnat_session_inlines.h>

typedef enum
{
  CGNAT_IN2OUT_SLOW_NEXT_LOOKUP,
  CGNAT_IN2OUT_SLOW_NEXT_DROP,
  CGNAT_IN2OUT_SLOW_N_NEXT,
} cgnat_in2out_slow_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 instance_index;
  u32 inside_fib_index;
  u32 next_index;
  i32 rv;
  u8 context_valid;
} cgnat_in2out_slow_trace_t;

#define foreach_cgnat_in2out_slow_error                                    \
  _ (PACKETS, "in2out slow-path packets")                                   \
  _ (TRANSLATED, "in2out slow-path packets translated")                     \
  _ (BYPASSED, "in2out slow-path packets bypassed")                         \
  _ (DROPS, "in2out slow-path packets dropped")                              \
  _ (DROP_ICMP_ERROR, "in2out slow-path drops: ICMP error translation")     \
  _ (DROP_L4_PARSE, "in2out slow-path drops: L4 parse")                     \
  _ (DROP_INSTANCE, "in2out slow-path drops: missing instance")             \
  _ (DROP_STATIC_MAPPING, "in2out slow-path drops: static mapping")         \
  _ (DROP_MAPPING_POOL, "in2out slow-path drops: mapping pool exhausted")   \
  _ (DROP_PORT_ALLOC, "in2out slow-path drops: port allocation")            \
  _ (DROP_IN2OUT_MAPPING_PUBLISH,                                            \
     "in2out slow-path drops: in2out mapping publish")                      \
  _ (DROP_OUT2IN_MAPPING_PUBLISH,                                            \
     "in2out slow-path drops: out2in mapping publish")                      \
  _ (DROP_SESSION_CREATE, "in2out slow-path drops: session create")         \
  _ (DROP_UNKNOWN, "in2out slow-path drops: unknown")

typedef enum
{
#define _(sym, str) CGNAT_IN2OUT_SLOW_ERROR_##sym,
  foreach_cgnat_in2out_slow_error
#undef _
    CGNAT_IN2OUT_SLOW_N_ERROR,
} cgnat_in2out_slow_error_t;

static char *cgnat_in2out_slow_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_in2out_slow_error
#undef _
};

static_always_inline cgnat_in2out_slow_error_t
cgnat_in2out_slow_drop_error (cgnat_in2out_slow_drop_reason_t reason)
{
  switch (reason)
    {
    case CGNAT_IN2OUT_SLOW_DROP_ICMP_ERROR:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_ICMP_ERROR;
    case CGNAT_IN2OUT_SLOW_DROP_L4_PARSE:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_L4_PARSE;
    case CGNAT_IN2OUT_SLOW_DROP_INSTANCE:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_INSTANCE;
    case CGNAT_IN2OUT_SLOW_DROP_STATIC_MAPPING:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_STATIC_MAPPING;
    case CGNAT_IN2OUT_SLOW_DROP_MAPPING_POOL:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_MAPPING_POOL;
    case CGNAT_IN2OUT_SLOW_DROP_PORT_ALLOC:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_PORT_ALLOC;
    case CGNAT_IN2OUT_SLOW_DROP_IN2OUT_MAPPING_PUBLISH:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_IN2OUT_MAPPING_PUBLISH;
    case CGNAT_IN2OUT_SLOW_DROP_OUT2IN_MAPPING_PUBLISH:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_OUT2IN_MAPPING_PUBLISH;
    case CGNAT_IN2OUT_SLOW_DROP_SESSION_CREATE:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_SESSION_CREATE;
    case CGNAT_IN2OUT_SLOW_DROP_NONE:
    case CGNAT_IN2OUT_SLOW_DROP_N:
      return CGNAT_IN2OUT_SLOW_ERROR_DROP_UNKNOWN;
    }

  return CGNAT_IN2OUT_SLOW_ERROR_DROP_UNKNOWN;
}

static u8 *
format_cgnat_in2out_slow_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  cgnat_in2out_slow_trace_t *t =
    va_arg (*args, cgnat_in2out_slow_trace_t *);

  return format (s, "CGNAT_IN2OUT_SLOW: sw_if_index %u instance %u "
		    "inside_fib %u context_valid %u rv %d next_index %u",
		 t->sw_if_index, t->instance_index, t->inside_fib_index,
		 t->context_valid, t->rv, t->next_index);
}

VLIB_NODE_FN (cgnat_in2out_slow_node) (vlib_main_t *vm,
				       vlib_node_runtime_t *node,
				       vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 counters[CGNAT_IN2OUT_SLOW_N_ERROR] = { 0 };
  f64 now = vlib_time_now (vm);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, from[0]);
      u32 instance_index0 = cgnat_buffer_instance_index (b0);
      u32 inside_fib_index0 = CGNAT_INVALID_INDEX;
      u32 next0 = CGNAT_IN2OUT_SLOW_NEXT_LOOKUP;
      u8 context_valid0 = instance_index0 != CGNAT_INVALID_INDEX;
      int rv0 = VNET_API_ERROR_UNSUPPORTED;
      cgnat_in2out_slow_drop_reason_t drop_reason0 =
	CGNAT_IN2OUT_SLOW_DROP_NONE;

      if (context_valid0)
	inside_fib_index0 = cgnat_buffer_inside_fib_index (b0);

      if (PREDICT_TRUE (cm->enabled && context_valid0))
	{
	rv0 = cgnat_session_in2out_slow (
	  vm, b0, instance_index0, inside_fib_index0, now, &drop_reason0);
	  if (PREDICT_FALSE (rv0 && rv0 != VNET_API_ERROR_UNSUPPORTED))
	    {
	      next0 = CGNAT_IN2OUT_SLOW_NEXT_DROP;
	      counters[CGNAT_IN2OUT_SLOW_ERROR_DROPS]++;
	      counters[cgnat_in2out_slow_drop_error (drop_reason0)]++;
	    }
	  else if (rv0 == VNET_API_ERROR_UNSUPPORTED)
	    counters[CGNAT_IN2OUT_SLOW_ERROR_BYPASSED]++;
	  else
	    counters[CGNAT_IN2OUT_SLOW_ERROR_TRANSLATED]++;
	}
      else
	counters[CGNAT_IN2OUT_SLOW_ERROR_BYPASSED]++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cgnat_in2out_slow_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));

	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->instance_index = instance_index0;
	  t->inside_fib_index = inside_fib_index0;
	  t->next_index = next0;
	  t->rv = rv0;
	  t->context_valid = context_valid0;
	}

      next[0] = next0;
      next++;
      from++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);
  counters[CGNAT_IN2OUT_SLOW_ERROR_PACKETS] = frame->n_vectors;
  for (u32 i = 0; i < CGNAT_IN2OUT_SLOW_N_ERROR; i++)
    if (counters[i])
      vlib_node_increment_counter (vm, cm->in2out_slow_node_index, i,
				   counters[i]);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_in2out_slow_node) = {
  .name = "cgnat-in2out-slow",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_slow_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_in2out_slow_error_strings),
  .error_strings = cgnat_in2out_slow_error_strings,
  .n_next_nodes = CGNAT_IN2OUT_SLOW_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_SLOW_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_IN2OUT_SLOW_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
