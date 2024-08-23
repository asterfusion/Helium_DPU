/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief Host DPU interface.
 */

#include <onp/onp.h>
#include <onp/drv/inc/dpu.h>
#include <vnet/interface_output.h>

always_inline void
h2d_compute_checksum (vlib_main_t *vm, vlib_buffer_t *b)
{
  ethernet_header_t *e;
  ip4_header_t *ip;
  tcp_header_t *th;
  udp_header_t *uh;

  e = vlib_buffer_get_current (b);
  if (PREDICT_TRUE (clib_net_to_host_u16 (e->type) == ETHERNET_TYPE_IP4))
    {
      ip = (ip4_header_t *) (((u8 *) e) + sizeof (ethernet_header_t));
      if (ip->protocol == IP_PROTOCOL_TCP)
	{
	  th = (tcp_header_t *) (b->data + b->current_data +
				 sizeof (ethernet_header_t) +
				 ip4_header_bytes (ip));
	  th->checksum = 0;
	  th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip);
	}
      else if (ip->protocol == IP_PROTOCOL_UDP)
	{
	  uh = (udp_header_t *) (b->data + b->current_data +
				 sizeof (ethernet_header_t) +
				 ip4_header_bytes (ip));
	  uh->checksum = 0;
	  uh->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip);
	}
    }
}

static u8 *
format_h2d_input_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "h2d-input:\n");
  return s;
}

VLIB_NODE_FN (h2d_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left, next0, next1, next2, next3;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vlib_buffer_t **b = bufs;
  u32 *from;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 8)
    {
      vlib_buffer_advance (b[0], CNXK_H2D_META_SIZE);
      vlib_buffer_advance (b[1], CNXK_H2D_META_SIZE);
      vlib_buffer_advance (b[2], CNXK_H2D_META_SIZE);
      vlib_buffer_advance (b[3], CNXK_H2D_META_SIZE);

      h2d_compute_checksum (vm, b[0]);
      h2d_compute_checksum (vm, b[1]);
      h2d_compute_checksum (vm, b[2]);
      h2d_compute_checksum (vm, b[3]);

      vnet_feature_next (&next0, b[0]);
      vnet_feature_next (&next1, b[1]);
      vnet_feature_next (&next2, b[2]);
      vnet_feature_next (&next3, b[3]);

      next[0] = (u16) next0;
      next[1] = (u16) next1;
      next[2] = (u16) next2;
      next[3] = (u16) next3;

      b += 4;
      next += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      vlib_buffer_advance (b[0], CNXK_H2D_META_SIZE);
      h2d_compute_checksum (vm, b[0]);
      vnet_feature_next (&next0, b[0]);
      next[0] = (u16) next0;

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VNET_FEATURE_INIT (h2d_input_node, static) = {
  .arc_name = "device-input",
  .node_name = "h2d-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VLIB_REGISTER_NODE (h2d_input_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_h2d_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "h2d-input",
};

always_inline u8
d2h_validate_checksum (vlib_main_t *vm, vlib_buffer_t *b)
{
  u8 csum = CNXK_D2H_CSUM_VERIFIED;
  ethernet_header_t *e;
  ip4_header_t *ip;

  e = vlib_buffer_get_current (b);
  if (PREDICT_TRUE (clib_net_to_host_u16 (e->type) == ETHERNET_TYPE_IP4))
    {
      vlib_buffer_advance (b, sizeof (ethernet_header_t));
      ip = vlib_buffer_get_current (b);

      if (ip->protocol == IP_PROTOCOL_TCP || ip->protocol == IP_PROTOCOL_UDP)
	{
	  ip4_tcp_udp_validate_checksum (vm, b);
	  if (!(b->flags & VNET_BUFFER_F_L4_CHECKSUM_CORRECT))
	    csum = CNXK_D2H_CSUM_FAILED;
	}
      vlib_buffer_advance (b, -sizeof (ethernet_header_t));
    }
  return csum;
}

static u8 *
format_d2h_output_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);

  s = format (s, "d2h-output");
  return s;
}

VLIB_NODE_FN (d2h_output_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  cnxk_d2h_meta_t *hdr0, *hdr1, *hdr2, *hdr3;
  u32 n_left, next0, next1, next2, next3;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u16 nexts[VLIB_FRAME_SIZE], *next;
  u8 csum0, csum1, csum2, csum3;
  vlib_buffer_t **b = bufs;
  u32 *from;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  next = nexts;
  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left >= 8)
    {
      csum0 = d2h_validate_checksum (vm, b[0]);
      csum1 = d2h_validate_checksum (vm, b[1]);
      csum2 = d2h_validate_checksum (vm, b[2]);
      csum3 = d2h_validate_checksum (vm, b[3]);

      vlib_buffer_advance (b[0], -CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[1], -CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[2], -CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[3], -CNXK_D2H_META_SIZE);

      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[4]) -
			  CNXK_D2H_META_SIZE);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[5]) -
			  CNXK_D2H_META_SIZE);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[6]) -
			  CNXK_D2H_META_SIZE);
      clib_prefetch_load ((u8 *) vlib_buffer_get_current (b[7]) -
			  CNXK_D2H_META_SIZE);

      hdr0 = vlib_buffer_get_current (b[0]);
      hdr1 = vlib_buffer_get_current (b[1]);
      hdr2 = vlib_buffer_get_current (b[2]);
      hdr3 = vlib_buffer_get_current (b[3]);

      hdr0->as_u64 = 0;
      hdr1->as_u64 = 0;
      hdr2->as_u64 = 0;
      hdr3->as_u64 = 0;

      hdr0->csum_verified = csum0;
      hdr1->csum_verified = csum1;
      hdr2->csum_verified = csum2;
      hdr3->csum_verified = csum3;

      vnet_feature_next (&next0, b[0]);
      vnet_feature_next (&next1, b[1]);
      vnet_feature_next (&next2, b[2]);
      vnet_feature_next (&next3, b[3]);

      next[0] = (u16) next0;
      next[1] = (u16) next1;
      next[2] = (u16) next2;
      next[3] = (u16) next3;

      vlib_buffer_advance (b[0], CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[1], CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[2], CNXK_D2H_META_SIZE);
      vlib_buffer_advance (b[3], CNXK_D2H_META_SIZE);

      b[0]->flags |= VLIB_BUFFER_DPU_TO_HOST_HDR_VALID;
      b[1]->flags |= VLIB_BUFFER_DPU_TO_HOST_HDR_VALID;
      b[2]->flags |= VLIB_BUFFER_DPU_TO_HOST_HDR_VALID;
      b[3]->flags |= VLIB_BUFFER_DPU_TO_HOST_HDR_VALID;

      b += 4;
      next += 4;
      n_left -= 4;
    }
  while (n_left)
    {
      csum0 = d2h_validate_checksum (vm, b[0]);
      vlib_buffer_advance (b[0], -CNXK_D2H_META_SIZE);
      hdr0 = vlib_buffer_get_current (b[0]);
      hdr0->as_u64 = 0;
      hdr0->csum_verified = csum0;

      vnet_feature_next (&next0, b[0]);
      next[0] = (u16) next0;

      vlib_buffer_advance (b[0], CNXK_D2H_META_SIZE);
      b[0]->flags |= VLIB_BUFFER_DPU_TO_HOST_HDR_VALID;

      b += 1;
      next += 1;
      n_left -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

VNET_FEATURE_INIT (d2h_output_node, static) = {
  .arc_name = "interface-output",
  .node_name = "d2h-output",
  .runs_before = VNET_FEATURES ("interface-output-arc-end"),
};

VLIB_REGISTER_NODE (d2h_output_node) = {
  .vector_size = sizeof (u32),
  .format_trace = format_d2h_output_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 0,
  .name = "d2h-output",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
