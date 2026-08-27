/*
 * cgnat_out2in.c - CGNAT outside to inside node
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
  CGNAT_OUT2IN_NEXT_LOOKUP,
  CGNAT_OUT2IN_NEXT_DROP,
  CGNAT_OUT2IN_N_NEXT,
} cgnat_out2in_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} cgnat_out2in_trace_t;

#define foreach_cgnat_out2in_error                                            \
  _ (OUT2IN_PACKETS, "good out2in packets processed")

typedef enum
{
#define _(sym, str) CGNAT_OUT2IN_ERROR_##sym,
  foreach_cgnat_out2in_error
#undef _
    CGNAT_OUT2IN_N_ERROR,
} cgnat_out2in_error_t;

static char *cgnat_out2in_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_out2in_error
#undef _
};

static u8 *
format_cgnat_out2in_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  cgnat_out2in_trace_t *t = va_arg (*args, cgnat_out2in_trace_t *);

  s = format (s, "CGNAT_OUT2IN: sw_if_index %u next_index %u",
	      t->sw_if_index, t->next_index);
  return s;
}

VLIB_NODE_FN (cgnat_out2in_node) (vlib_main_t *vm,
				  vlib_node_runtime_t *node,
				  vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 pkts_processed = 0;
  f64 now = vlib_time_now (vm);

  while (n_left > 0)
    {
      vlib_buffer_t *b0;
      cgnat_interface_t *interface0;
      u32 bi0 = from[0];
      u32 next0 = CGNAT_OUT2IN_NEXT_LOOKUP;
      u32 sw_if_index0;
      int rv;

      /* Prefetch the next packet's buffer header and IP header so the
       * current packet's dependent loads (buffer -> ip -> bihash bucket)
       * overlap with the next packet's misses. */
      if (PREDICT_TRUE (n_left > 1))
	{
	  vlib_buffer_t *b1 = vlib_get_buffer (vm, from[1]);
	  vlib_prefetch_buffer_header (b1, LOAD);
	  clib_prefetch_load (vlib_buffer_get_current (b1));
	}

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      if (PREDICT_FALSE (!clib_atomic_load_acq_n (&cm->enabled)))
	next0 = CGNAT_OUT2IN_NEXT_LOOKUP;
      else
	{
	  interface0 = cgnat_get_interface (cm, sw_if_index0);
	  if (PREDICT_TRUE (interface0 && cgnat_interface_is_outside (interface0)))
	    {
	      rv = cgnat_session_out2in (vm, b0, now);
	      if (PREDICT_FALSE (rv != 0 &&
				 rv != VNET_API_ERROR_NO_SUCH_ENTRY &&
				 rv != VNET_API_ERROR_UNSUPPORTED))
		next0 = CGNAT_OUT2IN_NEXT_DROP;
	    }
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cgnat_out2in_trace_t *t =
	    vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->next_index = next0;
	}

      pkts_processed += next0 != CGNAT_OUT2IN_NEXT_DROP;
      next[0] = next0;
      next++;
      from++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, cm->out2in_node_index,
			       CGNAT_OUT2IN_ERROR_OUT2IN_PACKETS,
			       pkts_processed);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_out2in_node) = {
  .name = "cgnat-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_out2in_error_strings),
  .error_strings = cgnat_out2in_error_strings,
  .n_next_nodes = CGNAT_OUT2IN_N_NEXT,
  .next_nodes = {
    [CGNAT_OUT2IN_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_OUT2IN_NEXT_DROP] = "error-drop",
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
