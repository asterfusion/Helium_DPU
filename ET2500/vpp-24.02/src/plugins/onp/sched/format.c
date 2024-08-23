/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP scheduler format helper implementation.
 */

#include <onp/onp.h>

u8 *
format_onp_sched_rx_trace (u8 *s, va_list *va)
{
  vlib_main_t *vm = va_arg (*va, vlib_main_t *);
  vlib_node_t *node = va_arg (*va, vlib_node_t *);
  vnet_main_t *vnm = vnet_get_main ();
  onp_rx_trace_t *ot = va_arg (*va, onp_rx_trace_t *);

  u32 indent = format_get_indent (s);

  s = format (s, "Pktio: %u,RQ:%u, Next node: %U\n", ot->pktio_index,
	      ot->queue_index, format_vlib_next_node_name, vm, node->index,
	      ot->next_node_index);

  s = format (s, "%Ubuffer 0x%x: %U\n", format_white_space, indent,
	      ot->buffer_index, format_vnet_buffer, &ot->buffer);
#if CLIB_DEBUG > 0
  s = format (s, "%U%U\n", format_white_space, indent, format_vlib_buffer,
	      &ot->buffer);
#endif
  if (vm->trace_main.verbose)
    {
      s = format (s, "%UPacket data\n", format_white_space, indent);

      s = format (s, "%U%U\n", format_white_space, indent + 2, format_hexdump,
		  &ot->data, 256);
    }

  s = format (s, "%U%U\n", format_white_space, indent,
	      format_ethernet_header_with_length, ot->data, 256);

  s = format (s, "%U%U\n", format_white_space, indent,
	      cnxk_drv_pktio_format_rx_trace, ot->pktio_index, ot->driver_data,
	      node, vm, vnm);

  s = format (s, "%U%U", format_white_space, indent, cnxk_drv_sched_tag_format,
	      vm, &ot->tag, &ot->tt);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
