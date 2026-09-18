/*
 * cgnat_out2in.c - CGNAT outside to inside fast-path node
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
  CGNAT_OUT2IN_NEXT_SLOW,
  CGNAT_OUT2IN_N_NEXT,
} cgnat_out2in_next_t;

typedef struct
{
  u32 sw_if_index;
  u64 session_value;
  u32 next_index;
} cgnat_out2in_trace_t;

#define foreach_cgnat_out2in_error                                           \
  _ (OUT2IN_PACKETS, "good out2in packets processed")                         \
  _ (SESSION_HITS, "out2in session hits")                                     \
  _ (SLOW_PATH, "out2in packets sent to slow path")

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

  return format (s, "CGNAT_OUT2IN: sw_if_index %u session_value 0x%llx "
		    "next_index %u", t->sw_if_index, t->session_value,
		    t->next_index);
}

/* Return the session only after validating the raw bihash value captured by
 * the lookup stage.  A stale value takes the slow path, preserving the old
 * behavior where a concurrent delete can expose a live mapping instead. */
static_always_inline cgnat_session_t *
cgnat_out2in_ctx_session_get (cgnat_main_t *cm, cgnat_out2in_ctx_t *ctx)
{
  return ctx->session_value ?
	   cgnat_session_get_if_valid (cm, ctx->session_value) :
	   0;
}

static_always_inline u32
cgnat_out2in_ctx_process (cgnat_main_t *cm, cgnat_out2in_ctx_t *ctx,
			  f64 now, u32 *session_hits, u32 *slow_path)
{
  cgnat_session_t *session;
  int rv;

  if (PREDICT_FALSE (!cgnat_interface_role_is_outside (
	cgnat_get_interface_role (cm,
		vnet_buffer (ctx->b)->sw_if_index[VLIB_RX]))))
    return CGNAT_OUT2IN_NEXT_LOOKUP;

  session = cgnat_out2in_ctx_session_get (cm, ctx);
  if (PREDICT_FALSE (!session))
    {
      (*slow_path)++;
      return CGNAT_OUT2IN_NEXT_SLOW;
    }

  rv = cgnat_out2in_translate_session (cm, ctx->b, ctx->ip, ctx->tcp,
					ctx->udp, now, session);
  if (PREDICT_FALSE (rv != 0 && rv != VNET_API_ERROR_NO_SUCH_ENTRY &&
		     rv != VNET_API_ERROR_UNSUPPORTED))
    return CGNAT_OUT2IN_NEXT_DROP;

  (*session_hits)++;
  return CGNAT_OUT2IN_NEXT_LOOKUP;
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
  u32 session_hits = 0;
  u32 slow_path = 0;
  f64 now = vlib_time_now (vm);
  cgnat_out2in_ctx_t contexts[3][2];
  u8 execute_stage = 0;
  u8 lookup_stage = 1;
  u8 prepare_stage = 2;

  if (PREDICT_FALSE (!cm->enabled))
    {
      u32 i;

      for (i = 0; i < frame->n_vectors; i++)
	nexts[i] = CGNAT_OUT2IN_NEXT_LOOKUP;
      vlib_buffer_enqueue_to_next (vm, node, from, nexts,
				   frame->n_vectors);
      vlib_node_increment_counter (vm, cm->out2in_node_index,
				   CGNAT_OUT2IN_ERROR_OUT2IN_PACKETS,
				   frame->n_vectors);
      return frame->n_vectors;
    }

  /* Seed the execute stage.  The following pair is prepared separately so a
   * full iteration elapses between reverse-key prefetch and bihash lookup. */
  if (n_left >= 2)
    {
      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[0]), &contexts[execute_stage][0]);
      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[1]), &contexts[execute_stage][1]);
      cgnat_out2in_ctx_lookup (cm, &contexts[execute_stage][0]);
      cgnat_out2in_ctx_lookup (cm, &contexts[execute_stage][1]);
    }
  if (n_left >= 4)
    {
      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[2]), &contexts[lookup_stage][0]);
      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[3]), &contexts[lookup_stage][1]);
    }

  while (n_left >= 6)
    {
      cgnat_out2in_ctx_t *ctx0 = &contexts[execute_stage][0];
      cgnat_out2in_ctx_t *ctx1 = &contexts[execute_stage][1];
      vlib_buffer_t *bp;
      u32 next0, next1;
      u8 old_execute_stage;

      bp = vlib_get_buffer (vm, from[4]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));
      bp = vlib_get_buffer (vm, from[5]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));

      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[4]), &contexts[prepare_stage][0]);
      cgnat_out2in_ctx_prepare (
	cm, vlib_get_buffer (vm, from[5]), &contexts[prepare_stage][1]);

      cgnat_out2in_ctx_lookup (cm, &contexts[lookup_stage][0]);
      cgnat_out2in_ctx_lookup (cm, &contexts[lookup_stage][1]);

      next0 = cgnat_out2in_ctx_process (cm, ctx0, now, &session_hits,
					 &slow_path);
      next1 = cgnat_out2in_ctx_process (cm, ctx1, now, &session_hits,
					 &slow_path);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (ctx0->b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cgnat_out2in_trace_t *t =
		vlib_add_trace (vm, node, ctx0->b, sizeof (*t));
	      t->sw_if_index = vnet_buffer (ctx0->b)->sw_if_index[VLIB_RX];
	      t->session_value = ctx0->session_value;
	      t->next_index = next0;
	    }
	  if (ctx1->b->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cgnat_out2in_trace_t *t =
		vlib_add_trace (vm, node, ctx1->b, sizeof (*t));
	      t->sw_if_index = vnet_buffer (ctx1->b)->sw_if_index[VLIB_RX];
	      t->session_value = ctx1->session_value;
	      t->next_index = next1;
	    }
	}

      old_execute_stage = execute_stage;
      execute_stage = lookup_stage;
      lookup_stage = prepare_stage;
      prepare_stage = old_execute_stage;

      pkts_processed += (next0 != CGNAT_OUT2IN_NEXT_DROP) +
			(next1 != CGNAT_OUT2IN_NEXT_DROP);
      next[0] = next0;
      next[1] = next1;
      from += 2;
      next += 2;
      n_left -= 2;
    }

  /* Complete the last prepared pair after the main loop has supplied the
   * intended prefetch distance. */
  if (n_left >= 4)
    {
      cgnat_out2in_ctx_lookup (cm, &contexts[lookup_stage][0]);
      cgnat_out2in_ctx_lookup (cm, &contexts[lookup_stage][1]);
    }

  {
    u32 tail_count = n_left;
    u32 tail_i = 0;

    while (n_left > 0)
      {
	cgnat_out2in_ctx_t direct_ctx;
	cgnat_out2in_ctx_t *ctx0;
	u32 next0;

	if (tail_i < 2 && tail_count >= 2)
	  ctx0 = &contexts[execute_stage][tail_i];
	else if (tail_i < 4 && tail_count >= 4)
	  ctx0 = &contexts[lookup_stage][tail_i - 2];
	else
	  {
	    cgnat_out2in_ctx_prepare (cm, vlib_get_buffer (vm, from[0]),
				     &direct_ctx);
	    cgnat_out2in_ctx_lookup (cm, &direct_ctx);
	    ctx0 = &direct_ctx;
	  }

	next0 = cgnat_out2in_ctx_process (cm, ctx0, now, &session_hits,
					  &slow_path);
	if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			   (ctx0->b->flags & VLIB_BUFFER_IS_TRACED)))
	  {
	    cgnat_out2in_trace_t *t =
	      vlib_add_trace (vm, node, ctx0->b, sizeof (*t));
	    t->sw_if_index = vnet_buffer (ctx0->b)->sw_if_index[VLIB_RX];
	    t->session_value = ctx0->session_value;
	    t->next_index = next0;
	  }

	pkts_processed += next0 != CGNAT_OUT2IN_NEXT_DROP;
	next[0] = next0;
	from++;
	next++;
	n_left--;
	tail_i++;
	}
  }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, cm->out2in_node_index,
			       CGNAT_OUT2IN_ERROR_OUT2IN_PACKETS, pkts_processed);
  vlib_node_increment_counter (vm, cm->out2in_node_index,
			       CGNAT_OUT2IN_ERROR_SESSION_HITS, session_hits);
  vlib_node_increment_counter (vm, cm->out2in_node_index,
			       CGNAT_OUT2IN_ERROR_SLOW_PATH, slow_path);
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
    [CGNAT_OUT2IN_NEXT_SLOW] = "cgnat-out2in-slow",
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
