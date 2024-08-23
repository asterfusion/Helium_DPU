/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP format helper implementation.
 */

#include <onp/onp.h>

u8 *
format_onp_pktio_tx_trace (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  CLIB_UNUSED (vnet_main_t * vnm) = vnet_get_main ();
  onp_tx_trace_t *t = va_arg (*va, onp_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "SQ: %x, Buffer index 0x%x: %U\n", t->qid, t->buffer_index,
	      format_vnet_buffer, &t->buf);

  if (vm->trace_main.verbose)
    {
      s = format (s, "%UPacket data\n", format_white_space, indent);

      s = format (s, "%U%U\n", format_white_space, indent + 2, format_hexdump,
		  &t->data, 256);
    }

  s = format (s, "%U%U", format_white_space, indent,
	      format_ethernet_header_with_length, t->data, 256);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
