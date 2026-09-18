/*
 * cgnat_in2out.c - CGNAT inside to outside node
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
  CGNAT_IN2OUT_NEXT_LOOKUP,
  CGNAT_IN2OUT_NEXT_SLOW,
  CGNAT_IN2OUT_NEXT_DROP,
  CGNAT_IN2OUT_N_NEXT,
} cgnat_in2out_next_t;

typedef struct
{
  u32 sw_if_index;
  u32 instance_index;
  u32 inside_fib_index;
  u32 acl_index;
  u32 next_index;
  u64 session_value;
  u8 context_valid;
} cgnat_in2out_trace_t;

#define foreach_cgnat_in2out_error                                            \
  _ (IN2OUT_PACKETS, "good in2out packets processed")                         \
  _ (SESSION_HITS, "in2out session hits")                                     \
  _ (SLOW_PATH, "in2out packets sent to slow path")                           \
  _ (INVALID_SESSION, "invalid in2out session drops")

typedef enum
{
#define _(sym, str) CGNAT_IN2OUT_ERROR_##sym,
  foreach_cgnat_in2out_error
#undef _
    CGNAT_IN2OUT_N_ERROR,
} cgnat_in2out_error_t;

static char *cgnat_in2out_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_in2out_error
#undef _
};

static u8 *
format_cgnat_in2out_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  cgnat_in2out_trace_t *t = va_arg (*args, cgnat_in2out_trace_t *);

  s = format (s, "CGNAT_IN2OUT: sw_if_index %u instance %u inside_fib %u "
		 "acl %u session_value 0x%llx context_valid %u next_index %u",
	      t->sw_if_index, t->instance_index, t->inside_fib_index,
	      t->acl_index, t->session_value, t->context_valid, t->next_index);
  return s;
}

VLIB_NODE_FN (cgnat_in2out_node) (vlib_main_t *vm,
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
  u32 invalid_sessions = 0;
  f64 now = vlib_time_now (vm);
  cgnat_in2out_ctx_t contexts[3][2];
  u8 execute_stage = 0;
  u8 lookup_stage = 1;
  u8 prepare_stage = 2;

  if (PREDICT_FALSE (!cm->enabled))
    {
      u32 i;

      for (i = 0; i < frame->n_vectors; i++)
	nexts[i] = CGNAT_IN2OUT_NEXT_LOOKUP;
      vlib_buffer_enqueue_to_next (vm, node, from, nexts,
				   frame->n_vectors);
      vlib_node_increment_counter (vm, cm->in2out_node_index,
				   CGNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
				   frame->n_vectors);
      return frame->n_vectors;
    }

  /* Seed the execute stage.  The next pair is prepared separately so a full
   * loop iteration can elapse between its bucket prefetch and hash lookup. */
  if (n_left >= 2)
    {
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[0]), &contexts[execute_stage][0]);
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[1]), &contexts[execute_stage][1]);
      cgnat_in2out_ctx_lookup (cm, &contexts[execute_stage][0]);
      cgnat_in2out_ctx_lookup (cm, &contexts[execute_stage][1]);
    }
  if (n_left >= 4)
    {
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[2]), &contexts[lookup_stage][0]);
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[3]), &contexts[lookup_stage][1]);
    }

  while (n_left >= 6)
    {
      vlib_buffer_t *b0, *b1, *bp;
      cgnat_in2out_ctx_t *ctx0 = &contexts[execute_stage][0];
      cgnat_in2out_ctx_t *ctx1 = &contexts[execute_stage][1];
      u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP, next1 = CGNAT_IN2OUT_NEXT_LOOKUP;
      u32 sw_if_index0, sw_if_index1;
      u32 instance_index0 = CGNAT_INVALID_INDEX;
      u32 instance_index1 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index0 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index1 = CGNAT_INVALID_INDEX;
      u32 acl_index0 = CGNAT_INVALID_INDEX, acl_index1 = CGNAT_INVALID_INDEX;
      u8 context_valid0 = 0, context_valid1 = 0;
      u8 old_execute_stage;
      int rv;

      bp = vlib_get_buffer (vm, from[4]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));
      bp = vlib_get_buffer (vm, from[5]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));

      /* Two packets ahead: parse once, retain the packet context and
       * prefetch the session-table bucket. */
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[4]), &contexts[prepare_stage][0]);
      cgnat_in2out_ctx_prepare (
	cm, vlib_get_buffer (vm, from[5]), &contexts[prepare_stage][1]);

      /* One pair ahead: consume the prefetched key and prefetch the resolved
       * session object for the next execute stage. */
      cgnat_in2out_ctx_lookup (cm, &contexts[lookup_stage][0]);
      cgnat_in2out_ctx_lookup (cm, &contexts[lookup_stage][1]);

      b0 = ctx0->b;
      b1 = ctx1->b;
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];

      /* The policy node (our only upstream) already resolved the instance
       * and the inside FIB and stashed them in opaque2. */
      instance_index0 = cgnat_buffer_instance_index (b0);
      instance_index1 = cgnat_buffer_instance_index (b1);

      if (PREDICT_TRUE (instance_index0 != CGNAT_INVALID_INDEX))
	{
	  inside_fib_index0 = cgnat_buffer_inside_fib_index (b0);
	  acl_index0 = b0->acl_index;
	  context_valid0 = 1;
	  if (PREDICT_FALSE (ctx0->session_value == 0))
	    {
	      next0 = CGNAT_IN2OUT_NEXT_SLOW;
	      slow_path++;
	    }
	  else
	    {
	      rv = cgnat_in2out_fast_execute (ctx0, now);
	      if (PREDICT_FALSE (rv))
		{
		  next0 = CGNAT_IN2OUT_NEXT_DROP;
		  invalid_sessions++;
		}
	      else
		session_hits++;
	    }
	}
      if (PREDICT_TRUE (instance_index1 != CGNAT_INVALID_INDEX))
	{
	  inside_fib_index1 = cgnat_buffer_inside_fib_index (b1);
	  acl_index1 = b1->acl_index;
	  context_valid1 = 1;
	  if (PREDICT_FALSE (ctx1->session_value == 0))
	    {
	      next1 = CGNAT_IN2OUT_NEXT_SLOW;
	      slow_path++;
	    }
	  else
	    {
	      rv = cgnat_in2out_fast_execute (ctx1, now);
	      if (PREDICT_FALSE (rv))
		{
		  next1 = CGNAT_IN2OUT_NEXT_DROP;
		  invalid_sessions++;
		}
	      else
		session_hits++;
	    }
	}

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cgnat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->instance_index = instance_index0;
	      t->inside_fib_index = inside_fib_index0;
	      t->acl_index = acl_index0;
	      t->session_value = ctx0->session_value;
	      t->context_valid = context_valid0;
	      t->next_index = next0;
	    }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      cgnat_in2out_trace_t *t =
		vlib_add_trace (vm, node, b1, sizeof (*t));
	      t->sw_if_index = sw_if_index1;
	      t->instance_index = instance_index1;
	      t->inside_fib_index = inside_fib_index1;
	      t->acl_index = acl_index1;
	      t->session_value = ctx1->session_value;
	      t->context_valid = context_valid1;
	      t->next_index = next1;
	    }
	}

      old_execute_stage = execute_stage;
      execute_stage = lookup_stage;
      lookup_stage = prepare_stage;
      prepare_stage = old_execute_stage;

      pkts_processed += (next0 != CGNAT_IN2OUT_NEXT_DROP) +
			(next1 != CGNAT_IN2OUT_NEXT_DROP);
      next[0] = next0;
      next[1] = next1;
      from += 2;
      next += 2;
      n_left -= 2;
    }

  /* Complete the prepared tail pair after the main loop has provided enough
   * distance for its bucket prefetch. */
  if (n_left >= 4)
    {
      cgnat_in2out_ctx_lookup (cm, &contexts[lookup_stage][0]);
      cgnat_in2out_ctx_lookup (cm, &contexts[lookup_stage][1]);
    }

  /* Scalar tail also handles short frames.  The first two contexts are ready
   * to execute, the next two are ready after the lookup above, and at most
   * one remaining packet is prepared and looked up directly. */
  {
    u32 tail_count = n_left;
    u32 tail_i = 0;

    while (n_left > 0)
    {
      vlib_buffer_t *b0;
      cgnat_in2out_ctx_t direct_ctx;
      cgnat_in2out_ctx_t *ctx0;
      u32 bi0 = from[0];
      u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP;
      u32 sw_if_index0;
      u32 instance_index0 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index0 = CGNAT_INVALID_INDEX;
      u32 acl_index0 = CGNAT_INVALID_INDEX;
      u8 context_valid0 = 0;
      int rv;

      if (tail_i < 2 && tail_count >= 2)
	ctx0 = &contexts[execute_stage][tail_i];
      else if (tail_i < 4 && tail_count >= 4)
	ctx0 = &contexts[lookup_stage][tail_i - 2];
      else
	{
	  b0 = vlib_get_buffer (vm, bi0);
	  cgnat_in2out_ctx_prepare (cm, b0, &direct_ctx);
	  cgnat_in2out_ctx_lookup (cm, &direct_ctx);
	  ctx0 = &direct_ctx;
	}
      b0 = ctx0->b;
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      instance_index0 = cgnat_buffer_instance_index (b0);
      if (PREDICT_TRUE (instance_index0 != CGNAT_INVALID_INDEX))
	{
	  inside_fib_index0 = cgnat_buffer_inside_fib_index (b0);
	  acl_index0 = b0->acl_index;
	  context_valid0 = 1;
	  if (PREDICT_FALSE (ctx0->session_value == 0))
	    {
	      next0 = CGNAT_IN2OUT_NEXT_SLOW;
	      slow_path++;
	    }
	  else
	    {
	      rv = cgnat_in2out_fast_execute (ctx0, now);
	      if (PREDICT_FALSE (rv))
		{
		  next0 = CGNAT_IN2OUT_NEXT_DROP;
		  invalid_sessions++;
		}
	      else
		session_hits++;
	    }
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cgnat_in2out_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->instance_index = instance_index0;
	  t->inside_fib_index = inside_fib_index0;
	  t->acl_index = acl_index0;
	  t->session_value = ctx0->session_value;
	  t->context_valid = context_valid0;
	  t->next_index = next0;
	}

      pkts_processed += next0 != CGNAT_IN2OUT_NEXT_DROP;
      next[0] = next0;
      next++;
      from++;
      n_left--;
      tail_i++;
    }
  }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);
  vlib_node_increment_counter (vm, cm->in2out_node_index,
			       CGNAT_IN2OUT_ERROR_IN2OUT_PACKETS,
			       pkts_processed);
  vlib_node_increment_counter (vm, cm->in2out_node_index,
			       CGNAT_IN2OUT_ERROR_SESSION_HITS, session_hits);
  vlib_node_increment_counter (vm, cm->in2out_node_index,
			       CGNAT_IN2OUT_ERROR_SLOW_PATH, slow_path);
  vlib_node_increment_counter (vm, cm->in2out_node_index,
			       CGNAT_IN2OUT_ERROR_INVALID_SESSION,
			       invalid_sessions);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_in2out_node) = {
  .name = "cgnat-in2out",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_in2out_error_strings),
  .error_strings = cgnat_in2out_error_strings,
  .n_next_nodes = CGNAT_IN2OUT_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
    [CGNAT_IN2OUT_NEXT_SLOW] = "cgnat-in2out-slow",
    [CGNAT_IN2OUT_NEXT_DROP] = "error-drop",
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
