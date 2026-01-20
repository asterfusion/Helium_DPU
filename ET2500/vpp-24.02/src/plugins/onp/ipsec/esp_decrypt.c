/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP ESP decrypt nodes implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/ipsec_fp.h>
#include <onp/drv/inc/sched_fp.h>
#include <vnet/mpls/mpls_lookup.h>
#include <vnet/l2/l2_input.h>

typedef struct
{
  u32 sa_index;
  u32 spi;
  u32 seq;
  u32 sa_seq;
  u32 sa_seq_hi;
  u8 anti_replay;
  u16 next_index;
  ipsec_crypto_alg_t crypto_alg;
  ipsec_integ_alg_t integ_alg;
  u8 data[256];
  vlib_buffer_t buf;
} onp_esp_decrypt_trace_t;

/* clang-format off */
static char *onp_esp_decrypt_error_strings[] = {
#define _(sym, string) string,
  foreach_onp_esp_decrypt_error
  foreach_onp_drv_cn10k_ipsec_ucc
#undef _
};
/* clang-format on */

/* Packet trace format function */
static u8 *
format_onp_esp_decrypt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  onp_esp_decrypt_trace_t *t = va_arg (*args, onp_esp_decrypt_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%U %U\n", format_white_space, indent, format_vnet_buffer,
	      &t->buf);

  if (t->next_index != (u16) ~0)
    s = format (s, "%Unext node: %U\n", format_white_space, indent,
		format_vlib_next_node_name, vm, node->index, t->next_index);

  s = format (s,
	      "%Uesp: sa-index %d spi %u (0x%08x) "
	      "crypto %U integrity %U pkt-seq %d sa-seq %u sa-seq-hi %u%s",
	      format_white_space, indent, t->sa_index, t->spi, t->spi,
	      format_ipsec_crypto_alg, t->crypto_alg, format_ipsec_integ_alg,
	      t->integ_alg, t->seq, t->sa_seq, t->sa_seq_hi,
	      t->anti_replay ? " anti-replay-enabled" : "");

  if (vm->trace_main.verbose)
    {
      s = format (s, "\n%U%U", format_white_space, indent + 4, format_hexdump,
		  &t->data, 128);
    }
  return s;
}

static_always_inline void
onp_esp_dec_add_trace (ipsec_sa_t *sa, vlib_buffer_t *b, vlib_main_t *vm,
		       u16 next, vlib_node_runtime_t *node, u32 sa_index,
		       u32 seq)
{
#if 1
  onp_esp_decrypt_trace_t *tr;

  if (PREDICT_TRUE (!(b->flags & VLIB_BUFFER_IS_TRACED)))
    return;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->next_index = next;
  tr->anti_replay = ipsec_sa_is_set_USE_ANTI_REPLAY (sa);
  tr->seq = seq;
  tr->sa_index = sa_index;
  tr->spi = sa->spi;
  //tr->sa_seq = sa->seq;
  //tr->sa_seq_hi = sa->seq_hi;
  tr->crypto_alg = sa->crypto_alg;
  tr->integ_alg = sa->integ_alg;

  clib_memcpy_fast (&tr->buf, b, sizeof b[0] - sizeof b->pre_data);
  clib_memcpy_fast (tr->buf.pre_data, b->data, sizeof tr->buf.pre_data);
  clib_memcpy_fast (tr->data, vlib_buffer_get_current (b), 256);
#endif
}

static_always_inline uword
onp_esp_decrypt (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vlib_frame_t *frame, u16 next, u16 drop_next,
		 onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_ipsec_main_t *im = &onp_ipsec_main;
  onp_main_t *om = onp_get_main ();
  u32 n_left = frame->n_vectors;
  cnxk_per_thread_data_t *ptd;
  esp_header_t *esp;
  vlib_buffer_t **b;
  ipsec_sa_t *sa;
  u32 sa_index;
  int n_noop;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  clib_prefetch_load (ptd->c0);

  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  onp_ptd_ipsec (ptd)->post_drop_next_node = drop_next;
  ptd->next1[0] = next;

  n_noop = cnxk_drv_ipsec_decrypt_enqueue_march (
    vm, node, frame, im->in_ipsec_queue, ptd, CNXK_IPSEC_FLAG_DECRYPT_OP);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    {
      b = ptd->buffers;
      while (n_left > 0)
	{
	  sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  sa = ipsec_sa_get (sa_index);
	  esp = vlib_buffer_get_current (b[0]);

	  onp_esp_dec_add_trace (sa, b[0], vm, ~0, node, sa_index, esp->seq);
	  b += 1;
	  n_left--;
	}
    }

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_pkts_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_npkts);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_frame_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_user_nstats);

  if (n_noop)
    {
      vlib_increment_simple_counter (
	&om->onp_counters.ipsec[cnt_type].decrypt_pkts_noop_counters,
	vm->thread_index, 0 /* Index */, n_noop);

      vlib_buffer_enqueue_to_next (vm, node, ptd->second_buffer_indices,
				   ptd->next2, n_noop);
    }

  return frame->n_vectors;
}

static_always_inline uword
onp_esp_decrypt_tun_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    vlib_frame_t *frame, u16 next, u16 drop_next,
			    onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_ipsec_main_t *im = &onp_ipsec_main;
  onp_main_t *om = onp_get_main ();
  u32 n_left = frame->n_vectors;
  cnxk_per_thread_data_t *ptd;
  esp_header_t *esp;
  vlib_buffer_t **b;
  ipsec_sa_t *sa;
  u32 sa_index;
  u32 n_noop;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  clib_prefetch_load (ptd->c0);

  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  onp_ptd_ipsec (ptd)->post_drop_next_node = drop_next;
  ptd->next1[0] = next;

  n_noop = cnxk_drv_ipsec_decrypt_enqueue_march (
    vm, node, frame, im->in_ipsec_queue, ptd, CNXK_IPSEC_FLAG_DECRYPT_OP);

  if (node->flags & VLIB_NODE_FLAG_TRACE)
    {
      b = ptd->buffers;
      while (n_left > 0)
	{
	  sa_index = vnet_buffer (b[0])->ipsec.sad_index;
	  sa = ipsec_sa_get (sa_index);
	  esp = vlib_buffer_get_current (b[0]);

	  onp_esp_dec_add_trace (sa, b[0], vm, ~0, node, sa_index, esp->seq);
	  b += 1;
	  n_left--;
	}
    }

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_pkts_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_npkts);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_frame_submit_counters,
    vm->thread_index, 0 /* Index */, ptd->out_user_nstats);

  if (n_noop)
    {
      vlib_increment_simple_counter (
	&om->onp_counters.ipsec[cnt_type].decrypt_pkts_noop_counters,
	vm->thread_index, 0 /* Index */, n_noop);

      vlib_buffer_enqueue_to_next (vm, node, ptd->second_buffer_indices,
				   ptd->next2, n_noop);
    }

  return frame->n_vectors;
}

static_always_inline u16
onp_esp_dec_post_process (vlib_main_t *vm, ipsec_sa_t *sa, vlib_buffer_t *b,
			  onp_esp_post_data_t *data, vlib_node_runtime_t *node,
			  u16 drop_next, u16 *next)
{
  vlib_buffer_t *chained_buffer = b;
  bool is_chain_buf = 0;
  esp_footer_t *f;

  ip4_header_t *ip4 = vlib_buffer_get_current (chained_buffer);
  if ((ip4->ip_version_and_header_length & 0xf0) == 0x40)
  {
      u16 data_length = clib_net_to_host_u16(ip4->length);
      u16 pay_length = (sa->esp_block_align - (data_length + 2) % sa->esp_block_align) % sa->esp_block_align;
      chained_buffer->current_length = data_length + pay_length;
  }

  else
  {
      ip6_header_t *ip6 = vlib_buffer_get_current (chained_buffer);
      u16 data_length = clib_net_to_host_u16 (ip6->payload_length) + sizeof (ip6_header_t);
      u16 pay_length = (sa->esp_block_align - (data_length + 2) % sa->esp_block_align) % sa->esp_block_align;
      chained_buffer->current_length = data_length + pay_length;
  }
  while (chained_buffer->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      is_chain_buf = 1;
      chained_buffer = vlib_get_next_buffer (vm, chained_buffer);
    }

  f = (esp_footer_t *) (chained_buffer->data + chained_buffer->current_data +
			chained_buffer->current_length);

  if (chained_buffer->current_length > f->pad_length)
    {
      chained_buffer->current_length -= f->pad_length;

      if (is_chain_buf)
	b->total_length_not_including_first_buffer -= f->pad_length;
    }

  switch (f->next_header)
    {
    case IP_PROTOCOL_IP_IN_IP:
      *next = ONP_ESP_DECRYPT_NEXT_IP4_INPUT;
      return 0;
    case IP_PROTOCOL_IPV6:
      *next = ONP_ESP_DECRYPT_NEXT_IP6_INPUT;
      return 0;
    case IP_PROTOCOL_MPLS_IN_IP:
      *next = ONP_ESP_DECRYPT_NEXT_MPLS_INPUT;
      return 0;
    default:
      *next = drop_next;
      return 1;
    }
}

static_always_inline uword
onp_esp_decrypt_post (vlib_main_t *vm, vlib_node_runtime_t *node,
		      vlib_frame_t *frame, onp_ipsec_counter_type_t cnt_type,
		      const u32 is_ipv6)
{
  ipsec_sa_t *current_sa0 = NULL, *current_sa1 = NULL;
  ipsec_sa_t *current_sa2 = NULL, *current_sa3 = NULL;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u32 sa0_index, sa1_index, sa2_index, sa3_index;
  u32 *from = vlib_frame_vector_args (frame);
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 current_sa0_index, current_sa1_index;
  u32 current_sa2_index, current_sa3_index;
  onp_esp_post_data_t *dec_post[4];
  onp_main_t *om = onp_get_main ();
  u32 n_left = frame->n_vectors;
  u16 drop_next;

  current_sa0_index = ~0;
  current_sa1_index = ~0;
  current_sa2_index = ~0;
  current_sa3_index = ~0;

  if (is_ipv6)
    drop_next = ONP_ESP_DECRYPT_NEXT_DROP6;
  else
    drop_next = ONP_ESP_DECRYPT_NEXT_DROP4;

  vlib_get_buffers (vm, from, b, n_left);

  while (n_left > 11)
    {
      vlib_prefetch_buffer_header (b[4], LOAD);
      vlib_prefetch_buffer_header (b[5], LOAD);
      vlib_prefetch_buffer_header (b[6], LOAD);
      vlib_prefetch_buffer_header (b[7], LOAD);

      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[8]) +
			  b[8]->current_length);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[9]) +
			  b[9]->current_length);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[10]) +
			  b[10]->current_length);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[11]) +
			  b[11]->current_length);

      dec_post[0] = onp_esp_post_data (b[0]);
      dec_post[1] = onp_esp_post_data (b[1]);
      dec_post[2] = onp_esp_post_data (b[2]);
      dec_post[3] = onp_esp_post_data (b[3]);

      sa0_index = dec_post[0]->sa_index;
      sa1_index = dec_post[1]->sa_index;
      sa2_index = dec_post[2]->sa_index;
      sa3_index = dec_post[3]->sa_index;

      b[0]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);
      b[1]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);
      b[2]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);
      b[3]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);

      if (PREDICT_FALSE (current_sa0_index != sa0_index))
	{
	  /* Update current_sa */
	  current_sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}
      if (PREDICT_FALSE (current_sa1_index != sa1_index))
	{

	  /* Update current_sa */
	  current_sa1 = ipsec_sa_get (sa1_index);
	  current_sa1_index = sa1_index;
	}
      if (PREDICT_FALSE (current_sa2_index != sa2_index))
	{

	  /* Update current_sa */
	  current_sa2 = ipsec_sa_get (sa2_index);
	  current_sa2_index = sa2_index;
	}

      if (PREDICT_FALSE (current_sa3_index != sa3_index))
	{
	  current_sa3 = ipsec_sa_get (sa3_index);
	  current_sa3_index = sa3_index;
	}

      onp_esp_dec_post_process (vm, current_sa0, b[0], dec_post[0], node,
				drop_next, &next[0]);
      onp_esp_dec_post_process (vm, current_sa1, b[1], dec_post[1], node,
				drop_next, &next[1]);
      onp_esp_dec_post_process (vm, current_sa2, b[2], dec_post[2], node,
				drop_next, &next[2]);
      onp_esp_dec_post_process (vm, current_sa3, b[3], dec_post[3], node,
				drop_next, &next[3]);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	{
	  onp_esp_dec_add_trace (current_sa0, b[0], vm, next[0], node,
				 dec_post[0]->sa_index, dec_post[0]->seq);
	  onp_esp_dec_add_trace (current_sa1, b[1], vm, next[1], node,
				 dec_post[1]->sa_index, dec_post[1]->seq);
	  onp_esp_dec_add_trace (current_sa2, b[2], vm, next[2], node,
				 dec_post[2]->sa_index, dec_post[2]->seq);
	  onp_esp_dec_add_trace (current_sa3, b[3], vm, next[3], node,
				 dec_post[3]->sa_index, dec_post[3]->seq);
	}

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      dec_post[0] = onp_esp_post_data (b[0]);

      sa0_index = dec_post[0]->sa_index;

      b[0]->flags &= ~(VNET_BUFFER_F_L4_CHECKSUM_CORRECT |
		       VNET_BUFFER_F_L4_CHECKSUM_COMPUTED);

      if (PREDICT_FALSE (current_sa0_index != sa0_index))
	{
	  /* Update current_sa */
	  current_sa0 = ipsec_sa_get (sa0_index);
	  current_sa0_index = sa0_index;
	}
      onp_esp_dec_post_process (vm, current_sa0, b[0], dec_post[0], node,
				drop_next, &next[0]);

      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	onp_esp_dec_add_trace (current_sa0, b[0], vm, next[0], node,
			       dec_post[0]->sa_index, dec_post[0]->seq);

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_pkts_recv_counters,
    vm->thread_index, 0 /* Index */, frame->n_vectors);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_frame_recv_counters,
    vm->thread_index, 0 /* Index */, 1);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

static_always_inline uword
onp_esp_decrypt_post_drop (vlib_main_t *vm, vlib_node_runtime_t *node,
			   vlib_frame_t *frame, int is_tun,
			   onp_ipsec_counter_type_t cnt_type)
{
  u32 *from = vlib_frame_vector_args (frame);
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);

  vlib_get_buffers (vm, from, ptd->buffers, frame->n_vectors);

  cnxk_drv_ipsec_get_dec_error_march (vm, node, frame, ptd);

  vlib_buffer_enqueue_to_single_next (
    vm, node, from, ONP_ESP_DECRYPT_NEXT_DROP /* error-drop */,
    frame->n_vectors);

  vlib_increment_simple_counter (
    &om->onp_counters.ipsec[cnt_type].decrypt_result_fail_counters,
    vm->thread_index, 0 /* Index */, frame->n_vectors);

  return frame->n_vectors;
}

/**
 * @brief ONP IPv4 ESP decryption node.
 * @node onp-esp4-decrypt
 *
 * This is the ONP IPv4 ESP decryption node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 *
 * <em>Next Nodes:</em>
 * -  error-drop
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_decrypt_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *from_frame)
{
  return onp_esp_decrypt (
     vm, node, from_frame, onp_ipsec_main.onp_esp4_dec_post_next,
     onp_ipsec_main.onp_esp4_dec_post_drop_next, ONP_IPSEC_COUNTER_TYPE_ESP4);
}
/* clang-format on */

/**
 * @brief ONP IPv4 ESP decryption tunnel node.
 * @node onp-esp4-decrypt-tun
 *
 * This is the ONP IPv4 ESP decryption tunnel node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_decrypt_tun_node) (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *from_frame)
{
 return onp_esp_decrypt_tun_inline (
    vm, node, from_frame, onp_ipsec_main.onp_esp4_dec_post_next,
    onp_ipsec_main.onp_esp4_dec_post_drop_next, ONP_IPSEC_COUNTER_TYPE_ESP4);
}

/* clang-format on */

/**
 * @brief ONP IPv6 ESP decryption node.
 * @node onp-esp6-decrypt
 *
 * This is the ONP IPv6 ESP decryption node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 *
 * <em>Next Nodes:</em>
 * -  error-drop
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_decrypt_node) (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      vlib_frame_t *from_frame)
{
  return onp_esp_decrypt (
     vm, node, from_frame, onp_ipsec_main.onp_esp6_dec_post_next,
     onp_ipsec_main.onp_esp6_dec_post_drop_next, ONP_IPSEC_COUNTER_TYPE_ESP6);
}
/* clang-format on */

/**
 * @brief ONP IPv6 ESP decryption tunnel node.
 * @node onp-esp6-decrypt-tun
 *
 * This is the ONP IPv6 ESP decryption tunnel node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_decrypt_tun_node) (vlib_main_t *vm,
					  vlib_node_runtime_t *node,
					  vlib_frame_t *from_frame)
{
 return onp_esp_decrypt_tun_inline (
    vm, node, from_frame, onp_ipsec_main.onp_esp6_dec_post_next,
    onp_ipsec_main.onp_esp6_dec_post_drop_next, ONP_IPSEC_COUNTER_TYPE_ESP6);
}

/* clang-format on */

/**
 * @brief ONP IPv4 ESP post decryption node.
 * @node onp-esp4-decrypt-post
 *
 * This is the ONP IPv4 ESP post decryption node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_decrypt_post_node) (vlib_main_t *vm,
					   vlib_node_runtime_t *node,
					   vlib_frame_t *from_frame)
{
  return onp_esp_decrypt_post (vm, node, from_frame,
          ONP_IPSEC_COUNTER_TYPE_ESP4, 0 /* ipv4 */);
}

/* clang-format on */

/**
 * @brief ONP IPv4 ESP post decryption drop node.
 * @node onp-esp4-decrypt-post-drop
 *
 * This is the ONP IPv4 ESP post decryption drop node.
 *
 * @param vm    vlib_main_t corresponding to the current thread
 * @param node  vlib_node_runtime_t
 * @param frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp4_decrypt_post_drop_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{

  return onp_esp_decrypt_post_drop (vm, node, frame, 0,
				    ONP_IPSEC_COUNTER_TYPE_ESP4);
}

/* clang-format on */

/**
 * @brief ONP IPv6 ESP post decryption node.
 * @node onp-esp6-decrypt-post
 *
 * This is the ONP IPv6 ESP post decryption node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_decrypt_post_node) (vlib_main_t *vm,
					   vlib_node_runtime_t *node,
					   vlib_frame_t *from_frame)
{
  return onp_esp_decrypt_post (vm, node, from_frame,
          ONP_IPSEC_COUNTER_TYPE_ESP6, 1 /* ipv6 */);
}

/* clang-format on */

/**
 * @brief ONP IPv6 ESP post decryption drop node.
 * @node onp-esp6-decrypt-post-drop
 *
 * This is the ONP IPv6 ESP post decryption drop node.
 *
 * @param vm         vlib_main_t corresponding to the current thread
 * @param node       vlib_node_runtime_t
 * @param from_frame vlib_frame_t
 */
/* clang-format off */
VLIB_NODE_FN (onp_esp6_decrypt_post_drop_node) (vlib_main_t *vm,
                                          vlib_node_runtime_t *node,
                                          vlib_frame_t *frame)
{
  return onp_esp_decrypt_post_drop (vm, node, frame, 0,
				    ONP_IPSEC_COUNTER_TYPE_ESP6);
}

VLIB_REGISTER_NODE (onp_esp4_decrypt_node) = {
  .name = "onp-esp4-decrypt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,
  .n_errors = ARRAY_LEN(onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = ONP_ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP4] = "ip4-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP6] = "ip6-drop",
    [ONP_ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ONP_ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ONP_ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ONP_ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
  },
};

VLIB_REGISTER_NODE (onp_esp6_decrypt_node) = {
  .name = "onp-esp6-decrypt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,
  .n_errors = ARRAY_LEN(onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = ONP_ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP4] = "ip4-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP6] = "ip6-drop",
    [ONP_ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ONP_ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ONP_ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ONP_ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
  },
};

VLIB_REGISTER_NODE (onp_esp4_decrypt_tun_node) = {
  .name = "onp-esp4-decrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,
  .n_errors = ARRAY_LEN(onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = ONP_ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP4] = "ip4-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP6] = "ip6-drop",
    [ONP_ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ONP_ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ONP_ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ONP_ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
  },
};

VLIB_REGISTER_NODE (onp_esp6_decrypt_tun_node) = {
  .name = "onp-esp6-decrypt-tun",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,
  .n_errors = ARRAY_LEN(onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = ONP_ESP_DECRYPT_N_NEXT,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP4] = "ip4-drop",
    [ONP_ESP_DECRYPT_NEXT_DROP6] = "ip6-drop",
    [ONP_ESP_DECRYPT_NEXT_IP4_INPUT] = "ip4-input-no-checksum",
    [ONP_ESP_DECRYPT_NEXT_IP6_INPUT] = "ip6-input",
    [ONP_ESP_DECRYPT_NEXT_MPLS_INPUT] = "mpls-input",
    [ONP_ESP_DECRYPT_NEXT_L2_INPUT] = "l2-input",
  },
};

VLIB_REGISTER_NODE (onp_esp4_decrypt_post_node) = {
  .name = "onp-esp4-decrypt-post",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,

  .n_errors = ARRAY_LEN (onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .sibling_of = "onp-esp4-decrypt-tun",
};

VLIB_REGISTER_NODE (onp_esp4_decrypt_post_drop_node) = {
  .name = "onp-esp4-decrypt-post-drop",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (onp_esp6_decrypt_post_node) = {
  .name = "onp-esp6-decrypt-post",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_onp_esp_decrypt_trace,

  .n_errors = ARRAY_LEN (onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .sibling_of = "onp-esp6-decrypt-tun",
};

VLIB_REGISTER_NODE (onp_esp6_decrypt_post_drop_node) = {
  .name = "onp-esp6-decrypt-post-drop",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (onp_esp_decrypt_error_strings),
  .error_strings = onp_esp_decrypt_error_strings,
  .n_next_nodes = 1,
  .next_nodes = {
    [ONP_ESP_DECRYPT_NEXT_DROP] = "error-drop",
  },
};
/* clang-format on */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
