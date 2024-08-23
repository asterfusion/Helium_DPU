/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP ESP encrypt nodes implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/ipsec_fp.h>
#include <onp/drv/inc/sched_fp.h>

#define ONP_ESP_ENCRYPT_TUN_PREP_NODES(x, y)                                  \
  [ONP_ESP_ENCRYPT_TUN_NEXT_PREP##y] = #x #y,

typedef struct
{
  u32 sa_index;
  u32 spi;
  u32 seq;
  u32 sa_seq_hi;
  u32 next_index;
  u32 owner_thread;
  u32 handoff_thread;
  u8 udp_encap;
  vlib_error_t error;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 data[256];
  vlib_buffer_t buf;
} onp_esp_encrypt_trace_t;

/* clang-format off */
static char *onp_esp_encrypt_error_strings[] = {
#define _(sym, string) string,
  foreach_onp_drv_encrypt_error
#undef _
#define _(sym, str) str,
  foreach_onp_drv_cn10k_ipsec_ucc
#undef _
};
/* clang-format on */

/* Packet trace format function */
static u8 *
format_onp_esp_encrypt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  onp_esp_encrypt_trace_t *t = va_arg (*args, onp_esp_encrypt_trace_t *);
  vlib_error_main_t *em = &vm->error_main;
  u32 indent = format_get_indent (s);
  vlib_error_t e = t->error;
  u32 ci;

  s = format (s, "%U %U\n", format_white_space, indent, format_vnet_buffer,
	      &t->buf);

  if (e)
    {
      ci = vlib_error_get_code (&vm->node_main, e);

      ci += node->error_heap_index;

      s = format (s, "%UStatus: %s", format_white_space, indent,
		  em->counters_heap[ci].name);

      if (t->handoff_thread == t->owner_thread)
	s = format (s, ", Handoff thread: %u", t->handoff_thread);

      s = format (s, "\n");
    }

  s = format (s, "%USA owner thread: %u\n", format_white_space, indent,
	      t->owner_thread);

  if (t->next_index != ~0)
    s = format (s, "%Unext node: %U\n", format_white_space, indent,
		format_vlib_next_node_name, vm, node->index, t->next_index);

  s = format (s,
	      "%Uesp: sa-index %d spi %u (0x%08x) seq %u sa-seq-hi %u "
	      "crypto %U integrity %U%s",
	      format_white_space, indent, t->sa_index, t->spi, t->spi, t->seq,
	      t->sa_seq_hi, format_ipsec_crypto_alg, t->crypto_alg,
	      format_ipsec_integ_alg, t->integ_alg,
	      t->udp_encap ? " udp-encap-enabled" : "");

  if (vm->trace_main.verbose)
    {
      s = format (s, "\n%U%U", format_white_space, indent + 4, format_hexdump,
		  &t->data, 128);
    }
  return s;
}

static_always_inline void
onp_esp_encrypt_tun_add_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame, vlib_buffer_t *b,
			       u32 next_index)
{
  onp_esp_encrypt_trace_t *tr;
  ipsec_sa_t *sa;
  u32 sa_index;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  sa_index = vnet_buffer (b)->ipsec.sad_index;
  sa = ipsec_sa_get (sa_index);
  tr->next_index = next_index;
  tr->sa_index = sa_index;
  tr->spi = sa->spi;
  tr->seq = sa->seq;
  tr->sa_seq_hi = sa->seq_hi;
  tr->udp_encap = ipsec_sa_is_set_UDP_ENCAP (sa);
  tr->crypto_alg = sa->crypto_alg;
  tr->integ_alg = sa->integ_alg;
  tr->owner_thread = sa->thread_index;

  clib_memcpy_fast (&tr->buf, b, sizeof b[0] - sizeof b->pre_data);
  clib_memcpy_fast (tr->buf.pre_data, b->data, sizeof tr->buf.pre_data);
  clib_memcpy_fast (tr->data, vlib_buffer_get_current (b), 256);
}

static_always_inline uword
onp_esp_encrypt_post_drop (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame, int is_tun,
			   onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  cnxk_drv_ipsec_get_enc_error_march (vm, node, frame, ptd);

  vlib_buffer_enqueue_to_single_next (vm, node, from, 0 /* error-drop */,
				      frame->n_vectors);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].encrypt_result_fail_counters,
    vm->thread_index, 0 /* Index */, frame->n_vectors);

  return frame->n_vectors;
}

static_always_inline uword
onp_esp_encrypt_unsupp_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			       vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);

  vlib_buffer_enqueue_to_single_next (vm, node, from, 0 /* error-drop */,
				      frame->n_vectors);

  return 0;
}

/**
 * @brief ONP IPv4 ESP encryption node.
 * @node onp-esp4-encrypt
 *
 * This is the ONP IPv4 ESP encryption node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_encrypt_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame)
{
  return onp_esp_encrypt_unsupp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (onp_esp4_encrypt_node) = {
  .name = "onp-esp4-encrypt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  }
};
/* clang-format on */

static_always_inline uword
onp_esp_encrypt_tun_post (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, const int is_ip6,
			  onp_ipsec_counter_type_t cnt_type)
{
  cn10k_ipsec_outbound_pkt_meta_t *meta0, *meta1, *meta2, *meta3;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  onp_main_t *om = onp_get_main ();
  u32 n_left = frame->n_vectors;

  vlib_get_buffers (vm, from, b, n_left);

  while (n_left > 11)
    {
      clib_prefetch_load (b[8]);
      clib_prefetch_load (b[9]);
      clib_prefetch_load (b[10]);
      clib_prefetch_load (b[11]);

      next[0] = onp_esp_post_data (b[0])->next_index;
      next[1] = onp_esp_post_data (b[1])->next_index;
      next[2] = onp_esp_post_data (b[2])->next_index;
      next[3] = onp_esp_post_data (b[3])->next_index;

      meta0 = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[0]);
      meta1 = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[1]);
      meta2 = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[2]);
      meta3 = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[3]);

      vlib_increment_combined_counter (
	&ipsec_sa_counters, vlib_get_thread_index (),
	vnet_buffer (b[0])->ipsec.sad_index, 1, meta0->sa_bytes);
      vlib_increment_combined_counter (
	&ipsec_sa_counters, vlib_get_thread_index (),
	vnet_buffer (b[1])->ipsec.sad_index, 1, meta1->sa_bytes);
      vlib_increment_combined_counter (
	&ipsec_sa_counters, vlib_get_thread_index (),
	vnet_buffer (b[2])->ipsec.sad_index, 1, meta2->sa_bytes);
      vlib_increment_combined_counter (
	&ipsec_sa_counters, vlib_get_thread_index (),
	vnet_buffer (b[3])->ipsec.sad_index, 1, meta3->sa_bytes);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    onp_esp_encrypt_tun_add_trace (vm, node, frame, b[0], next[0]);

	  if (PREDICT_FALSE (b[1]->flags & VLIB_BUFFER_IS_TRACED))
	    onp_esp_encrypt_tun_add_trace (vm, node, frame, b[1], next[1]);

	  if (PREDICT_FALSE (b[2]->flags & VLIB_BUFFER_IS_TRACED))
	    onp_esp_encrypt_tun_add_trace (vm, node, frame, b[2], next[2]);

	  if (PREDICT_FALSE (b[3]->flags & VLIB_BUFFER_IS_TRACED))
	    onp_esp_encrypt_tun_add_trace (vm, node, frame, b[3], next[3]);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left > 0)
    {
      next[0] = onp_esp_post_data (b[0])->next_index;

      meta0 = (cn10k_ipsec_outbound_pkt_meta_t *)
	CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b[0]);

      vlib_increment_combined_counter (
	&ipsec_sa_counters, vlib_get_thread_index (),
	vnet_buffer (b[0])->ipsec.sad_index, 1, meta0->sa_bytes);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    onp_esp_encrypt_tun_add_trace (vm, node, frame, b[0], next[0]);
	}

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].encrypt_post_tun_pkts_recv_counters,
    vm->thread_index, 0 /* index */, frame->n_vectors);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

/**
 * @brief ONP IPv4 ESP post encryption tunnel node.
 * @node onp-esp4-encrypt-tun-post
 *
 * This is the ONP IPv4 ESP post encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_encrypt_tun_post_node) (vlib_main_t *vm,
                                           vlib_node_runtime_t *node,
                                           vlib_frame_t *frame)
{

  return onp_esp_encrypt_tun_post (vm, node, frame, 0, ONP_IPSEC_COUNTER_TYPE_ESP4);
}
/* clang-format on */

VLIB_REGISTER_NODE (onp_esp4_encrypt_tun_post_node) = {
  .name = "onp-esp4-encrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .n_errors = ARRAY_LEN (onp_esp_encrypt_error_strings),
  .error_strings = onp_esp_encrypt_error_strings,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "onp-esp4-encrypt-lka-tun",
};

/**
 * @brief ONP IPv6 ESP post encryption tunnel node.
 * @node onp-esp6-encrypt-tun-post
 *
 * This is the ONP IPv6 ESP post encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_encrypt_tun_post_node) (vlib_main_t *vm,
                                           vlib_node_runtime_t *node,
                                           vlib_frame_t *frame)
{

  return onp_esp_encrypt_tun_post (vm, node, frame, 1, ONP_IPSEC_COUNTER_TYPE_ESP6);
}

VLIB_REGISTER_NODE (onp_esp6_encrypt_tun_post_node) = {
  .name = "onp-esp6-encrypt-tun-post",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .n_errors = ARRAY_LEN (onp_esp_encrypt_error_strings),
  .error_strings = onp_esp_encrypt_error_strings,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .sibling_of = "onp-esp6-encrypt-lka-tun",
};
/* clang-format on */

/**
 * @brief ONP IPv4 ESP post encryption drop node.
 * @node onp-esp4-encrypt-post-drop
 *
 * This is the ONP IPv4 ESP post encryption drop node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_encrypt_post_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return onp_esp_encrypt_post_drop (vm, node, frame, 0,
				    ONP_IPSEC_COUNTER_TYPE_ESP4);
}

VLIB_REGISTER_NODE (onp_esp4_encrypt_post_drop_node) = {
  .name = "onp-esp4-encrypt-post-drop",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (onp_esp_encrypt_error_strings),
  .error_strings = onp_esp_encrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* clang-format on */

/**
 * @brief ONP IPv6 ESP encryption node.
 * @node onp-esp6-encrypt
 *
 * This is the ONP IPv6 ESP encryption node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_encrypt_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *frame)
{
  return onp_esp_encrypt_unsupp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (onp_esp6_encrypt_node) = {
  .name = "onp-esp6-encrypt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  }
};
/* clang-format on */

/**
 * @brief ONP IPv6 ESP post encryption drop node.
 * @node onp-esp6-encrypt-post-drop
 *
 * This is the ONP IPv6 ESP post encryption drop node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_encrypt_post_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return onp_esp_encrypt_post_drop (vm, node, frame, 0,
				    ONP_IPSEC_COUNTER_TYPE_ESP6);
}

VLIB_REGISTER_NODE (onp_esp6_encrypt_post_drop_node) = {
  .name = "onp-esp6-encrypt-post-drop",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (onp_esp_encrypt_error_strings),
  .error_strings = onp_esp_encrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  },
};
/* clang-format on */

static_always_inline uword
onp_esp_encrypt_tun (vlib_main_t *vm, vlib_node_runtime_t *node,
		     vlib_frame_t *frame, onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  cnxk_per_thread_data_t *ptd = NULL;
  onp_main_t *om = onp_get_main ();
  u32 n_left = frame->n_vectors;
  vlib_buffer_t **b;
  u32 n_noop = 0;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);
  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);
  b = ptd->buffers;
  ptd->next1[0] = ONP_ESP_ENCRYPT_TUN_NEXT_PREP0;
  n_noop = cnxk_drv_ipsec_outbound_sort_march (
    vm, node, frame, ptd,
    (ONP_IPSEC_COUNTER_TYPE_ESP6 == cnt_type) /* is_ip6 */, 1 /* is_tun */);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      while (n_left > 0)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      onp_esp_encrypt_tun_add_trace (vm, node, frame, b[0],
					     ptd->next2[0]);
	    }

	  b += 1;
	  n_left--;
	}
    }

  if (PREDICT_TRUE (n_noop))
    {
      vlib_buffer_enqueue_to_next (vm, node, ptd->second_buffer_indices,
				   ptd->next2, n_noop);
      vlib_increment_simple_counter (
	&om->onp_counters.ipsec[cnt_type].encrypt_tun_pkts_counters,
	vm->thread_index, 0 /* Index */, n_noop);
    }

  return frame->n_vectors;
}

/**
 * @brief ONP ESP4 encryption inline tunnel node.
 * @node onp-esp4-encrypt-inl-tun
 *
 * This is the ONP ESP4 encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_encrypt_inl_tun_node) (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *frame)
{
  return onp_esp_encrypt_tun (
    vm, node, frame, ONP_IPSEC_COUNTER_TYPE_ESP4);
}

VLIB_REGISTER_NODE (onp_esp4_encrypt_inl_tun_node) = {
  .name = "onp-esp4-encrypt-inl-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = ONP_ESP_ENCRYPT_TUN_N_NEXT,
  .next_nodes = {
#define _(next, node) [ONP_ESP_ENCRYPT_TUN_NEXT_##next] = node,
    foreach_onp_esp_encrypt_tun_next
#undef _
#define _(core)                                                               \
   ONP_ESP_ENCRYPT_TUN_PREP_NODES (onp-esp4-encrypt-inl-tun-prep, core)
    foreach_sched_handoff_core
#undef _
  },

};
/* clang-format on */

/**
 * @brief ONP ESP4 encryption lka tunnel node.
 * @node onp-esp4-encrypt-lka-tun
 *
 * This is the ONP ESP4 encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_encrypt_lka_tun_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return onp_esp_encrypt_tun (
    vm, node, frame, ONP_IPSEC_COUNTER_TYPE_ESP4);
}

VLIB_REGISTER_NODE (onp_esp4_encrypt_lka_tun_node) = {
  .name = "onp-esp4-encrypt-lka-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = ONP_ESP_ENCRYPT_TUN_N_NEXT,
  .next_nodes = {
#define _(next, node) [ONP_ESP_ENCRYPT_TUN_NEXT_##next] = node,
    foreach_onp_esp_encrypt_tun_next
#undef _
#define _(core)                                                               \
   ONP_ESP_ENCRYPT_TUN_PREP_NODES (onp-esp4-encrypt-lka-tun-prep, core)
    foreach_sched_handoff_core
#undef _
  },

};
/* clang-format on */

/**
 * @brief ONP ESP6 encryption tunnel node.
 * @node onp-esp6-encrypt-inl-tun
 *
 * This is the ONP ESP6 encryption tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_encrypt_inl_tun_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return onp_esp_encrypt_tun (
    vm, node, frame, ONP_IPSEC_COUNTER_TYPE_ESP6);
}

VLIB_REGISTER_NODE (onp_esp6_encrypt_inl_tun_node) = {
  .name = "onp-esp6-encrypt-inl-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = ONP_ESP_ENCRYPT_TUN_N_NEXT,
  .next_nodes = {
#define _(next, node) [ONP_ESP_ENCRYPT_TUN_NEXT_##next] = node,
    foreach_onp_esp_encrypt_tun_next
#undef _
#define _(core)                                                               \
   ONP_ESP_ENCRYPT_TUN_PREP_NODES (onp-esp6-encrypt-inl-tun-prep, core)
    foreach_sched_handoff_core
#undef _
  },

};
/* clang-format on */

/**
 * @brief ONP ESP6 encryption lookaside tunnel node.
 * @node onp-esp6-encrypt-lka-tun
 *
 * This is the ONP ESP6 encryption lookaside tunnel node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_encrypt_lka_tun_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return onp_esp_encrypt_tun (
    vm, node, frame, ONP_IPSEC_COUNTER_TYPE_ESP6);
}

VLIB_REGISTER_NODE (onp_esp6_encrypt_lka_tun_node) = {
  .name = "onp-esp6-encrypt-lka-tun",
  .vector_size = sizeof (u32),
  .format_trace = format_onp_esp_encrypt_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = ONP_ESP_ENCRYPT_TUN_N_NEXT,
  .next_nodes = {
#define _(next, node) [ONP_ESP_ENCRYPT_TUN_NEXT_##next] = node,
    foreach_onp_esp_encrypt_tun_next
#undef _
#define _(core)                                                               \
   ONP_ESP_ENCRYPT_TUN_PREP_NODES (onp-esp6-encrypt-lka-tun-prep, core)
    foreach_sched_handoff_core
#undef _
  },

};
/* clang-format on */

/**
 * @brief ONP ESP encryption tunnel unsupported node.
 * @node onp-esp-encrypt-tun-unsupp
 *
 * This is the ONP ESP encryption tunnel unsupported node.
 * It drop all packets.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp_encrypt_tun_unsupp_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return onp_esp_encrypt_unsupp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (onp_esp_encrypt_tun_unsupp_node) = {
  .name = "onp-esp-encrypt-tun-unsupp",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  }
};
/* clang-format on */

/**
 * @brief ONP ESP MPLS encryption tunnel node.
 * @node onp-esp-mpls-encrypt-tun
 *
 * This is the ONP ESP MPLS encryption tunnel node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp_mpls_encrypt_tun_node ) (vlib_main_t *vm,
					       vlib_node_runtime_t *node,
					       vlib_frame_t *frame)
{
  return onp_esp_encrypt_unsupp_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (onp_esp_mpls_encrypt_tun_node) = {
  .name = "onp-esp-mpls-encrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_next_nodes = 1,
  .next_nodes = {
    [0] = "error-drop",
  }
};
/* clang-format on */

static_always_inline uword
onp_esp_inl_prep_to_core (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, u16 core_id, const int is_ipv6,
			  onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;
  vlib_buffer_t **b;
  u32 n_left;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);
  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  cnxk_drv_ipsec_outbound_prepare_inst (vm, node, frame, ptd, core_id,
					is_ipv6);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = frame->n_vectors;
      b = ptd->buffers;

      while (n_left)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      onp_esp_encrypt_tun_add_trace (
		vm, node, frame, b[0],
		ONP_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX);
	    }
	  n_left--;
	  b++;
	}
    }

  vlib_buffer_enqueue_to_single_next (vm, node, from,
				      ONP_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX,
				      frame->n_vectors);

  return frame->n_vectors;
}

static_always_inline uword
onp_esp_lka_prep_to_core (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, u16 core_id, const int is_ipv6,
			  onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_ipsec_main_t *im = &onp_ipsec_main;
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;
  u32 n_left, n_noop = 0;
  u16 drop_next_node;
  vlib_buffer_t **b;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);
  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  if (is_ipv6)
    {
      ptd->next1[0] = onp_ipsec_main.onp_esp6_enc_tun_post_next;
      onp_ptd_ipsec (ptd)->post_drop_next_node =
	onp_ipsec_main.onp_esp6_enc_post_drop_next;
      drop_next_node = ONP_ESP_ENCRYPT_TUN_NEXT_DROP6;
    }
  else
    {
      ptd->next1[0] = onp_ipsec_main.onp_esp4_enc_tun_post_next;
      onp_ptd_ipsec (ptd)->post_drop_next_node =
	onp_ipsec_main.onp_esp4_enc_post_drop_next;
      drop_next_node = ONP_ESP_ENCRYPT_TUN_NEXT_DROP4;
    }

  ptd->next2[0] = ONP_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX;

  n_noop = cnxk_drv_ipsec_encrypt_enqueue_march (
    vm, node, frame, im->out_ipsec_queue, ptd, CNXK_IPSEC_FLAG_ENCRYPT_OP,
    core_id);

  if (PREDICT_FALSE (n_noop))
    {
      vlib_buffer_enqueue_to_single_next (vm, node, ptd->second_buffer_indices,
					  drop_next_node, n_noop);

      vlib_increment_simple_counter (
	&om->onp_counters.ipsec[cnt_type].encrypt_tun_pkts_noop_counters,
	vm->thread_index, 0 /* Index */, n_noop);
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      n_left = frame->n_vectors;
      b = ptd->buffers;

      while (n_left)
	{
	  if (PREDICT_FALSE (b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      onp_esp_encrypt_tun_add_trace (
		vm, node, frame, b[0],
		ONP_ESP_ENCRYPT_TUN_NEXT_ADJ_MIDCHAIN_TX);
	    }
	  n_left--;
	  b++;
	}
    }
  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].encrypt_tun_pkts_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_npkts);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].encrypt_tun_frame_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_user_nstats);

  return frame->n_vectors;
}

/**
 * @brief ONP ESP4 encryption tunnel preparation node.
 * @node onp-esp4-encrypt-inl-tun-prep
 *
 * This is the ONP ESP4 encryption tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define ONP_DEFINE_ESP4_INLINE_TUN_PREP_NODE(core)                            \
  VLIB_NODE_FN (onp_esp4_encrypt_inl_tun_prep##core##_node)                   \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return onp_esp_inl_prep_to_core (vm, node, frame, core,                   \
                              0 /* is_ipv6 */,ONP_IPSEC_COUNTER_TYPE_ESP4);   \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (onp_esp4_encrypt_inl_tun_prep##core##_node) = {         \
    .name = "onp-esp4-encrypt-inl-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_onp_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "onp-esp4-encrypt-inl-tun",                                 \
  };

#define _(core) ONP_DEFINE_ESP4_INLINE_TUN_PREP_NODE (core)
foreach_sched_handoff_core;
#undef _
/* clang-format on */

/**
 * @brief ONP ESP6 encryption tunnel preparation node.
 * @node onp-esp6-encrypt-inl-tun-prep
 *
 * This is the ONP ESP6 encryption tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define ONP_DEFINE_ESP6_TUN_INLINE_PREP_NODE(core)                            \
  VLIB_NODE_FN (onp_esp6_encrypt_inline_tun_prep##core##_node)                \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return onp_esp_inl_prep_to_core (vm, node, frame, core,                   \
                        1 /* is_ipv6 */, ONP_IPSEC_COUNTER_TYPE_ESP6);        \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (onp_esp6_encrypt_inline_tun_prep##core##_node) = {      \
    .name = "onp-esp6-encrypt-inl-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_onp_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "onp-esp6-encrypt-inl-tun",                                 \
  };

#define _(core) ONP_DEFINE_ESP6_TUN_INLINE_PREP_NODE (core)
foreach_sched_handoff_core;
#undef _
/* clang-format on */

/**
 * @brief ONP ESP4 encryption lookaside tunnel preparation node.
 * @node onp-esp4-encrypt-lka-tun-prep
 *
 * This is the ONP ESP4 encryption lookaside tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define ONP_DEFINE_ESP4_LKA_TUN_PREP_NODE(core)                               \
  VLIB_NODE_FN (onp_esp4_encrypt_lka_tun_prep##core##_node)                   \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return onp_esp_lka_prep_to_core (vm, node, frame, core,                   \
                              0 /* is_ipv6 */,ONP_IPSEC_COUNTER_TYPE_ESP4);   \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (onp_esp4_encrypt_lka_tun_prep##core##_node) = {         \
    .name = "onp-esp4-encrypt-lka-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_onp_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "onp-esp4-encrypt-lka-tun",                                 \
  };

#define _(core) ONP_DEFINE_ESP4_LKA_TUN_PREP_NODE (core)
foreach_sched_handoff_core;
#undef _
/* clang-format on */

/**
 * @brief ONP ESP6 encryption lookaside tunnel preparation node.
 * @node onp-esp6-encrypt-lka-tun-prep
 *
 * This is the ONP ESP6 encryption lookaside tunnel preparation node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
#define ONP_DEFINE_ESP6_LKA_TUN_PREP_NODE(core)                               \
  VLIB_NODE_FN (onp_esp6_encrypt_lka_tun_prep##core##_node)                   \
  (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)        \
  {                                                                           \
    return onp_esp_lka_prep_to_core (vm, node, frame, core,                   \
                              1 /* is_ipv6 */,ONP_IPSEC_COUNTER_TYPE_ESP6);   \
  }                                                                           \
                                                                              \
  VLIB_REGISTER_NODE (onp_esp6_encrypt_lka_tun_prep##core##_node) = {         \
    .name = "onp-esp6-encrypt-lka-tun-prep"#core,                             \
    .type = VLIB_NODE_TYPE_INTERNAL,                                          \
    .format_trace = format_onp_esp_encrypt_trace,                             \
    .vector_size = sizeof (u32),                                              \
    .sibling_of = "onp-esp6-encrypt-lka-tun",                                 \
  };

#define _(core) ONP_DEFINE_ESP6_LKA_TUN_PREP_NODE (core)
foreach_sched_handoff_core;
#undef _
/* clang-format on */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
