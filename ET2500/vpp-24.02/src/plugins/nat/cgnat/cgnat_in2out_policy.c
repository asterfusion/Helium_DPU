/*
 * cgnat_in2out_policy.c - CGNAT inside ACL policy gate
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/feature/feature.h>

#include <nat/cgnat/cgnat.h>

typedef enum
{
  CGNAT_IN2OUT_POLICY_NEXT_IN2OUT,
  CGNAT_IN2OUT_POLICY_NEXT_DROP,
  CGNAT_IN2OUT_POLICY_N_NEXT,
} cgnat_in2out_policy_next_t;

#define foreach_cgnat_in2out_policy_error                                    \
  _ (PERMIT, "ACL permit packets sent to CGNAT in2out")                      \
  _ (BYPASS_DISABLED, "bypassed because CGNAT is disabled")                  \
  _ (BYPASS_NO_INTERFACE, "bypassed because interface is not CGNAT inside")  \
  _ (BYPASS_NO_INSTANCE, "bypassed because CGNAT instance is missing")       \
  _ (BYPASS_NO_ACL, "bypassed because CGNAT instance has no ACL")            \
  _ (BYPASS_FIB_MISMATCH, "bypassed because inside FIB mismatched")          \
  _ (BYPASS_UNSUPPORTED_MODE, "bypassed because instance mode is unsupported") \
  _ (BYPASS_NO_NAT, "bypassed by ACL no-nat")                                \
  _ (BYPASS_ACL_MISS, "bypassed because ACL did not match")                  \
  _ (BYPASS_ACL_MISMATCH, "bypassed because ACL index mismatched")

typedef enum
{
#define _(sym, str) CGNAT_IN2OUT_POLICY_ERROR_##sym,
  foreach_cgnat_in2out_policy_error
#undef _
    CGNAT_IN2OUT_POLICY_N_ERROR,
} cgnat_in2out_policy_error_t;

static char *cgnat_in2out_policy_error_strings[] = {
#define _(sym, str) str,
  foreach_cgnat_in2out_policy_error
#undef _
};

typedef struct
{
  u32 sw_if_index;
  u32 instance_index;
  u32 packet_acl_index;
  u32 instance_acl_index;
  u32 packet_fib_index;
  u32 configured_fib_index;
  u32 next_index;
  u32 arc_next_index;
  u8 no_nat;
} cgnat_in2out_policy_trace_t;

static u8 *
format_cgnat_in2out_policy_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t *vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t *node) = va_arg (*args, vlib_node_t *);
  cgnat_in2out_policy_trace_t *t =
    va_arg (*args, cgnat_in2out_policy_trace_t *);

  s = format (s, "CGNAT_IN2OUT_POLICY: sw_if_index %u instance %u "
		 "packet_fib %u configured_fib %u packet_acl %u "
		 "instance_acl %u no_nat %u next %u arc_next %u",
	      t->sw_if_index, t->instance_index, t->packet_fib_index,
	      t->configured_fib_index, t->packet_acl_index,
	      t->instance_acl_index, t->no_nat, t->next_index,
	      t->arc_next_index);
  return s;
}

/*
 * Pure policy verdict: returns the error/verdict code, writes the final next
 * node to next0 and the feature-arc default next to arc_next1 (trace only).
 * Bypass-by-default: packets stay on the arc unless every gate passes.
 */
static_always_inline u8
cgnat_in2out_policy_inline (cgnat_main_t *cm, vlib_buffer_t *b0, u16 *next0,
			    u16 *arc_next0)
{
  cgnat_interface_t *i;
  cgnat_instance_t *instance;
  u32 sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  u32 packet_fib_index;
  u32 acl_index, instance_index;

  /* vnet_feature_next* advances the arc cursor; call it exactly once. */
  vnet_feature_next_u16 (arc_next0, b0);
  *next0 = *arc_next0;

  if (PREDICT_FALSE (!cm->enabled))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_DISABLED;

  i = cgnat_get_interface (cm, sw_if_index);
  if (PREDICT_FALSE (!i || !cgnat_interface_is_inside (i)))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_NO_INTERFACE;

  if (PREDICT_FALSE ((b0->flags & VLIB_BUFFER_NO_NAT_VALID) && b0->no_nat))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_NO_NAT;

  if (PREDICT_FALSE (!(b0->flags & VLIB_BUFFER_ACL_INDEX_VALID)))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_ACL_MISS;

  /* ACL index 0 means only the default rule matched (no explicit match). */
  acl_index = b0->acl_index;
  if (PREDICT_FALSE (acl_index == 0))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_ACL_MISS;

  instance_index = cgnat_instance_index_by_acl (cm, acl_index);
  if (PREDICT_FALSE (instance_index == CGNAT_INVALID_INDEX))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_ACL_MISMATCH;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (PREDICT_FALSE (!instance))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_NO_INSTANCE;

  packet_fib_index = cgnat_packet_inside_fib_index (b0);
  if (PREDICT_FALSE (
	!cgnat_instance_inside_fib_matches (instance, packet_fib_index)))
    return CGNAT_IN2OUT_POLICY_ERROR_BYPASS_FIB_MISMATCH;

  *next0 = CGNAT_IN2OUT_POLICY_NEXT_IN2OUT;
  return CGNAT_IN2OUT_POLICY_ERROR_PERMIT;
}

/* Trace packing runs only for traced packets; re-derives everything from the
 * buffer (never call vnet_feature_next again here, it would advance the arc
 * cursor a second time). */
static_always_inline void
cgnat_in2out_policy_trace_add (vlib_main_t *vm, vlib_node_runtime_t *node,
			       cgnat_main_t *cm, vlib_buffer_t *b0, u16 next0,
			       u16 arc_next0, u8 error0)
{
  cgnat_in2out_policy_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
  u32 acl_index = (b0->flags & VLIB_BUFFER_ACL_INDEX_VALID) ?
		    b0->acl_index :
		    CGNAT_INVALID_INDEX;
  u32 instance_index = acl_index != CGNAT_INVALID_INDEX ?
			 cgnat_instance_index_by_acl (cm, acl_index) :
			 CGNAT_INVALID_INDEX;
  cgnat_instance_t *instance =
    cgnat_instance_get_by_index (cm, instance_index);

  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
  t->instance_index = instance_index;
  t->packet_acl_index = acl_index;
  t->instance_acl_index = error0 == CGNAT_IN2OUT_POLICY_ERROR_PERMIT ?
			  acl_index :
			  CGNAT_INVALID_INDEX;
  t->packet_fib_index = cgnat_packet_inside_fib_index (b0);
  t->configured_fib_index = instance ? instance->inside_fib_index :
				       CGNAT_INVALID_INDEX;
  t->no_nat = (b0->flags & VLIB_BUFFER_NO_NAT_VALID) && b0->no_nat;
  t->next_index = next0;
  t->arc_next_index = arc_next0;
}

VLIB_NODE_FN (cgnat_in2out_policy_node) (vlib_main_t *vm,
					 vlib_node_runtime_t *node,
					 vlib_frame_t *frame)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 counters[CGNAT_IN2OUT_POLICY_N_ERROR] = { 0 };

  while (n_left >= 4)
    {
      vlib_buffer_t *b0, *b1;
      u16 arc_next0, arc_next1;
      u8 err0, err1;

      vlib_prefetch_buffer_header (vlib_get_buffer (vm, from[2]), LOAD);
      vlib_prefetch_buffer_header (vlib_get_buffer (vm, from[3]), LOAD);

      b0 = vlib_get_buffer (vm, from[0]);
      b1 = vlib_get_buffer (vm, from[1]);

      err0 = cgnat_in2out_policy_inline (cm, b0, &next[0], &arc_next0);
      err1 = cgnat_in2out_policy_inline (cm, b1, &next[1], &arc_next1);

      counters[err0]++;
      counters[err1]++;

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    cgnat_in2out_policy_trace_add (vm, node, cm, b0, next[0],
					   arc_next0, err0);
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    cgnat_in2out_policy_trace_add (vm, node, cm, b1, next[1],
					   arc_next1, err1);
	}

      from += 2;
      next += 2;
      n_left -= 2;
    }

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = vlib_get_buffer (vm, from[0]);
      u16 arc_next0;
      u8 err0 = cgnat_in2out_policy_inline (cm, b0, &next[0], &arc_next0);

      counters[err0]++;

      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
			 (b0->flags & VLIB_BUFFER_IS_TRACED)))
	cgnat_in2out_policy_trace_add (vm, node, cm, b0, next[0], arc_next0,
				       err0);

      from++;
      next++;
      n_left--;
    }

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       nexts, frame->n_vectors);

  for (u32 i = 0; i < CGNAT_IN2OUT_POLICY_N_ERROR; i++)
    if (counters[i])
      vlib_node_increment_counter (vm, cm->in2out_policy_node_index, i,
				   counters[i]);

  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (cgnat_in2out_policy_node) = {
  .name = "cgnat-in2out-policy",
  .vector_size = sizeof (u32),
  .format_trace = format_cgnat_in2out_policy_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (cgnat_in2out_policy_error_strings),
  .error_strings = cgnat_in2out_policy_error_strings,
  .n_next_nodes = CGNAT_IN2OUT_POLICY_N_NEXT,
  .next_nodes = {
    [CGNAT_IN2OUT_POLICY_NEXT_IN2OUT] = "cgnat-in2out",
    [CGNAT_IN2OUT_POLICY_NEXT_DROP] = "error-drop",
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
