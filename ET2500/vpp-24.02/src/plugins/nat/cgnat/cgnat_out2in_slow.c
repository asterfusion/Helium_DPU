/*
 * cgnat_out2in_slow.c - CGNAT outside to inside miss path
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
  CGNAT_OUT2IN_SLOW_NEXT_LOOKUP,
  CGNAT_OUT2IN_SLOW_NEXT_DROP,
  CGNAT_OUT2IN_SLOW_N_NEXT,
} cgnat_out2in_slow_next_t;

typedef struct
{
  u32 sw_if_index;
  i32 rv;
  u32 next_index;
} cgnat_out2in_slow_trace_t;

#define foreach_cgnat_out2in_slow_error                                      \
  _ (PACKETS, "out2in slow-path packets")                                     \
  _ (TRANSLATED, "out2in slow-path packets translated")                       \
  _ (BYPASSED, "out2in slow-path packets bypassed")                           \
  _ (DROPS, "out2in slow-path packets dropped")

typedef enum
{
#define _(sym, str) CGNAT_OUT2IN_SLOW_ERROR_##sym,
  foreach_cgnat_out2in_slow_error
#undef _
    CGNAT_OUT2IN_SLOW_N_ERROR,
} cgnat_out2in_slow_error_t;

static char *cgnat_out2in_slow_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_out2in_slow_error
#undef _
};

static u8 *
format_cgnat_out2in_slow_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  cgnat_out2in_slow_trace_t *t =
    va_arg (*args, cgnat_out2in_slow_trace_t *);

  return format (s, "CGNAT_OUT2IN_SLOW: sw_if_index %u rv %d next_index %u",
		 t->sw_if_index, t->rv, t->next_index);
}

VLIB_NODE_FN (cgnat_out2in_slow_node) (vlib_main_t *vm,
				       vlib_node_runtime_t *node,
				       vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 translated = 0;
  u32 bypassed = 0;
  u32 drops = 0;
  f64 now = vlib_time_now (vm);

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, from[0]);
      u32 next0 = CGNAT_OUT2IN_SLOW_NEXT_LOOKUP;
      int rv0 = VNET_API_ERROR_UNSUPPORTED;

      if (PREDICT_TRUE (cm->enabled))
	{
	  rv0 = cgnat_session_out2in (vm, b0, now);
	  if (PREDICT_FALSE (rv0 != 0 && rv0 != VNET_API_ERROR_NO_SUCH_ENTRY &&
			     rv0 != VNET_API_ERROR_UNSUPPORTED))
	    {
	      next0 = CGNAT_OUT2IN_SLOW_NEXT_DROP;
	      drops++;
	    }
	  else if (rv0 == VNET_API_ERROR_NO_SUCH_ENTRY ||
		   rv0 == VNET_API_ERROR_UNSUPPORTED)
	    bypassed++;
	  else
	    translated++;
	}
      else
	bypassed++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cgnat_out2in_slow_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->rv = rv0;
	  t->next_index = next0;
	}

      next[0] = next0;
      next++;
      from++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, cm->out2in_slow_node_index,
			       CGNAT_OUT2IN_SLOW_ERROR_PACKETS, frame->n_vectors);
  vlib_node_increment_counter (vm, cm->out2in_slow_node_index,
			       CGNAT_OUT2IN_SLOW_ERROR_TRANSLATED, translated);
  vlib_node_increment_counter (vm, cm->out2in_slow_node_index,
			       CGNAT_OUT2IN_SLOW_ERROR_BYPASSED, bypassed);
  vlib_node_increment_counter (vm, cm->out2in_slow_node_index,
			       CGNAT_OUT2IN_SLOW_ERROR_DROPS, drops);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_out2in_slow_node) = {
  .name = "cgnat-out2in-slow",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_slow_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_out2in_slow_error_strings),
  .error_strings = cgnat_out2in_slow_error_strings,
  .n_next_nodes = CGNAT_OUT2IN_SLOW_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_SLOW_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_OUT2IN_SLOW_NEXT_DROP] = "error-drop",
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
