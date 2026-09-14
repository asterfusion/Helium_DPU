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
  u8 context_valid;
} cgnat_in2out_trace_t;

#define foreach_cgnat_in2out_error                                            \
  _ (IN2OUT_PACKETS, "good in2out packets processed")

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
		 "acl %u context_valid %u next_index %u",
	      t->sw_if_index, t->instance_index, t->inside_fib_index,
	      t->acl_index, t->context_valid, t->next_index);
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
  f64 now = vlib_time_now (vm);

  u64 s0 = 0, s1 = 0;

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

  while (n_left >= 6)
    {
      vlib_buffer_t *b0, *b1, *bp;
      u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP, next1 = CGNAT_IN2OUT_NEXT_LOOKUP;
      u32 sw_if_index0, sw_if_index1;
      u32 instance_index0 = CGNAT_INVALID_INDEX;
      u32 instance_index1 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index0 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index1 = CGNAT_INVALID_INDEX;
      u32 acl_index0 = CGNAT_INVALID_INDEX, acl_index1 = CGNAT_INVALID_INDEX;
      u8 context_valid0 = 0, context_valid1 = 0;
      u64 sn0, sn1;
      int rv;

      bp = vlib_get_buffer (vm, from[4]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));
      bp = vlib_get_buffer (vm, from[5]);
      vlib_prefetch_buffer_header (bp, LOAD);
      clib_prefetch_load (vlib_buffer_get_current (bp));

      /* Two iterations ahead: hash the flow keys and prefetch the
       * session-table bucket + KV page. */
      cgnat_prefetch_session_in2out (cm, vlib_get_buffer (vm, from[4]));
      cgnat_prefetch_session_in2out (cm, vlib_get_buffer (vm, from[5]));

      /* One iteration ahead: resolve the session-table values of the next
       * pair and prefetch the session pool lines - the last dependent cache
       * miss in the lookup chain. */
      sn0 = cgnat_in2out_session_peek (cm, vlib_get_buffer (vm, from[2]));
      sn1 = cgnat_in2out_session_peek (cm, vlib_get_buffer (vm, from[3]));
      if (sn0 && cgnat_value_get_index (sn0) < pool_len (cm->sessions))
	clib_prefetch_load (pool_elt_at_index (cm->sessions,
					       cgnat_value_get_index (sn0)));
      if (sn1 && cgnat_value_get_index (sn1) < pool_len (cm->sessions))
	clib_prefetch_load (pool_elt_at_index (cm->sessions,
					       cgnat_value_get_index (sn1)));

      b0 = vlib_get_buffer (vm, from[0]);
      b1 = vlib_get_buffer (vm, from[1]);
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
	  rv = cgnat_in2out_execute (vm, b0, s0, now);
	  if (PREDICT_FALSE (rv && rv != VNET_API_ERROR_UNSUPPORTED))
	    next0 = CGNAT_IN2OUT_NEXT_DROP;
	}
      if (PREDICT_TRUE (instance_index1 != CGNAT_INVALID_INDEX))
	{
	  inside_fib_index1 = cgnat_buffer_inside_fib_index (b1);
	  acl_index1 = b1->acl_index;
	  context_valid1 = 1;
	  rv = cgnat_in2out_execute (vm, b1, s1, now);
	  if (PREDICT_FALSE (rv && rv != VNET_API_ERROR_UNSUPPORTED))
	    next1 = CGNAT_IN2OUT_NEXT_DROP;
	}

      s0 = sn0;
      s1 = sn1;

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
	      t->context_valid = context_valid1;
	      t->next_index = next1;
	    }
	}

      pkts_processed += (next0 != CGNAT_IN2OUT_NEXT_DROP) +
			(next1 != CGNAT_IN2OUT_NEXT_DROP);
      next[0] = next0;
      next[1] = next1;
      from += 2;
      next += 2;
      n_left -= 2;
    }

  /* Scalar tail (also covers the last prefetched pairs).  The first two
   * buffers still own the values peeked in the last pipeline iteration. */
  {
    u32 tail_i = 0;

    while (n_left > 0)
    {
      vlib_buffer_t *b0;
      u32 bi0 = from[0];
      u32 next0 = CGNAT_IN2OUT_NEXT_LOOKUP;
      u32 sw_if_index0;
      u32 instance_index0 = CGNAT_INVALID_INDEX;
      u32 inside_fib_index0 = CGNAT_INVALID_INDEX;
      u32 acl_index0 = CGNAT_INVALID_INDEX;
      u8 context_valid0 = 0;
      u64 sval = tail_i == 0 ? s0 : tail_i == 1 ? s1 : 0;
      int rv;

      b0 = vlib_get_buffer (vm, bi0);
      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      instance_index0 = cgnat_buffer_instance_index (b0);
      if (PREDICT_TRUE (instance_index0 != CGNAT_INVALID_INDEX))
	{
	  inside_fib_index0 = cgnat_buffer_inside_fib_index (b0);
	  acl_index0 = b0->acl_index;
	  context_valid0 = 1;
	  rv = cgnat_in2out_execute (vm, b0, sval, now);
	  if (PREDICT_FALSE (rv && rv != VNET_API_ERROR_UNSUPPORTED))
	    next0 = CGNAT_IN2OUT_NEXT_DROP;
	}

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{
	  cgnat_in2out_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = sw_if_index0;
	  t->instance_index = instance_index0;
	  t->inside_fib_index = inside_fib_index0;
	  t->acl_index = acl_index0;
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
