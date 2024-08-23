/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio CLI implementation.
 */

#include <onp/onp.h>
#include <onp/pktio/flow.h>

#define flow_cli_help                                                         \
  "ethernet {dmac <xx:xx:xx:xx:xx:xx> smac <xx:xx:xx:xx:xx:xx> type <value> " \
  "| any} [ethernet-mask {...}]  "                                            \
  "vlan {vlan-id <value> cfi <value> | any} [vlan-mask {...}]  "              \
  "ip4 {src <x.x.x.x> dst <x.x.x.x> proto <value> tos "                       \
  "<CS[0-7]|AF[11|12|...|43]|EF> | any} [ip4-mask {...}]  "                   \
  "udp|tcp|sctp {sport <value> dport <value> | any} [<udp|tcp|sctp>-mask "    \
  "{...}]  "                                                                  \
  "esp {spi <value> | any} [esp-mask {...}]  "                                \
  "[redirect-to-queue <qid>] [mark <value>] [drop] [count] [rss queues "      \
  "<queue_start> to <queue_end>] [rss types <flow type>] <interface-name>"

static clib_error_t *
onp_pktio_flow_dump_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *pktio;

  vec_foreach (pktio, om->onp_pktios)
    cnxk_drv_pktio_flow_dump (vm, pktio->cnxk_pktio_index);

  return NULL;
}

/*?
 *
 * @cliexpar
 * Show the information of flow rules programmed in OCTEON hardware
 * ingress classifier:
 * @cliexstart{show onp pktio flow}
 * MCAM Index:192
 * Interface :NIX-RX (0)
 * Priority  :1
 * NPC RX Action:0X00000000204011
 *         ActionOp:NIX_RX_ACTIONOP_UCAST (1)
 *         PF_FUNC: 0X401
 *         RQ Index:0X002
 *         Match Id:0000
 *         Flow Key Alg:0
 * NPC RX VTAG Action:0000000000000000
 * Patterns:
 *         NPC_PARSE_NIBBLE_CHAN:0X800
 *         NPC_PARSE_NIBBLE_ERRCODE:00
 *         NPC_PARSE_NIBBLE_LA_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LB_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LC_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LD_LTYPE:NONE
 *         NPC_PARSE_NIBBLE_LE_LTYPE:LE_ESP
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_pktio_flow_dump_command, static) = {
  .path = "show onp pktio flow",
  .short_help = "show onp pktio flow",
  .function = onp_pktio_flow_dump_command_fn,
};

static_always_inline clib_error_t *
onp_flow_parse_ethernet_item (unformat_input_t *input, ethernet_header_t *spec,
			      u8 *match_all)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "dmac %U", unformat_ethernet_address,
		    spec->dst_address))
	;
      else if (unformat (input, "smac %U", unformat_ethernet_address,
			 spec->src_address))
	;
      else if (unformat (input, "type %U",
			 unformat_ethernet_type_net_byte_order, &spec->type))
	;
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse ethernet item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static_always_inline clib_error_t *
onp_flow_parse_vlan_item (unformat_input_t *input,
			  ethernet_vlan_header_t *spec, u8 *match_all)
{
  u16 vlan_id;
  u16 cfi;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "vlan-id %u", &vlan_id))
	spec->priority_cfi_and_id |= clib_host_to_net_u16 (vlan_id & 0x0fff);
      else if (unformat (input, "cfi %u", &cfi))
	spec->priority_cfi_and_id |= clib_host_to_net_u16 ((cfi & 0xf) << 12);
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse vlan item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static_always_inline clib_error_t *
onp_flow_parse_ip4_item (unformat_input_t *input, ip4_header_t *spec,
			 u8 *match_all)
{
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ip4_address, &spec->src_address))
	;
      else if (unformat (input, "dst %U", unformat_ip4_address,
			 &spec->dst_address))
	;
      else if (unformat (input, "proto %u", &spec->protocol))
	;
      else if (unformat (input, "tos %U", unformat_ip_dscp, &spec->tos))
	;
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse ipv4 item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static_always_inline clib_error_t *
onp_flow_parse_ip6_item (unformat_input_t *input, ip6_header_t *spec,
			 u8 *match_all)
{
  int tos;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src %U", unformat_ip6_address, &spec->src_address))
	;
      else if (unformat (input, "dst %U", unformat_ip6_address,
			 &spec->dst_address))
	;
      else if (unformat (input, "proto %u", &spec->protocol))
	;
      else if (unformat (input, "tos %U", unformat_vlib_number, &tos))
	spec->ip_version_traffic_class_and_flow_label |=
	  clib_host_to_net_u32 ((tos & 0xff) << 20);
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse ipv6 item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static_always_inline clib_error_t *
parse_l4_port_numbers (unformat_input_t *input, void *spec, u8 *match_all)
{
  udp_header_t *l4_hdr = (udp_header_t *) spec;
  u16 sport, dport;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "sport %u", &sport))
	l4_hdr->src_port = clib_host_to_net_u16 (sport);
      else if (unformat (input, "dport %u", &dport))
	l4_hdr->dst_port = clib_host_to_net_u16 (dport);
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse L4 item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

static_always_inline clib_error_t *
onp_flow_parse_udp_item (unformat_input_t *input, udp_header_t *spec,
			 u8 *match_all)
{
  return parse_l4_port_numbers (input, (void *) spec, match_all);
}

static_always_inline clib_error_t *
onp_flow_parse_tcp_item (unformat_input_t *input, tcp_header_t *spec,
			 u8 *match_all)
{
  return parse_l4_port_numbers (input, (void *) spec, match_all);
}

static_always_inline clib_error_t *
onp_flow_parse_sctp_item (unformat_input_t *input,
			  cnxk_drv_sctp_header_t *spec, u8 *match_all)
{
  return parse_l4_port_numbers (input, (void *) spec, match_all);
}

static_always_inline clib_error_t *
onp_flow_parse_esp_item (unformat_input_t *input, esp_header_t *spec,
			 u8 *match_all)
{
  u32 spi;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "spi %u", &spi))
	spec->spi = clib_host_to_net_u32 (spi);
      else if (unformat (input, "any"))
	{
	  *match_all = 1;
	  return 0;
	}
      else
	return clib_error_return (0, "Failed to parse esp item:'%U'",
				  format_unformat_error, input);
    }

  return 0;
}

clib_error_t *
onp_pktio_flow_add_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  struct cnxk_drv_flow_item_info *items = NULL, *item = NULL;
  unformat_input_t _line_input, *line_input = &_line_input;
  struct cnxk_drv_flow_item_info empty_item = { 0 };
  u32 hw_if_index = ~0, flow_index = ~0;
  onp_main_t *om = onp_get_main ();
  vnet_main_t *vnm = om->vnet_main;
  unformat_input_t sub_input;
  u32 queue_start, queue_end;
  vnet_flow_t vf = { 0 };
  clib_error_t *err = 0;
  u8 *rss_type[3] = {};
  u8 *type_str = NULL;
  u8 match_all = 0;
  u16 layer = 0;
  int rc;

  vec_validate_init_empty (items, CNXK_DRV_FLOW_ITEM_TYPE_END, empty_item);
  /* clang-format off */
#define _(protocol, hdr_t, ltype) hdr_t protocol##_item[2];
  foreach_cnxk_flow_supported_protocols;
  /* clang-format on */
  vf.type = VNET_FLOW_TYPE_GENERIC;
  clib_memcpy (vf.generic.pattern.spec, &items, sizeof (uword));

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_hw_interface, vnm,
		    &hw_if_index))
	;
	/* clang-format off */
#undef _
#define _(protocol, hdr, ltype)                                               \
      else if (unformat (line_input, #protocol " %U",                         \
            	     unformat_vlib_cli_sub_input, &sub_input))                \
        {                                                                     \
	  match_all = 0;                                                      \
          memset (protocol##_item, 0, sizeof (protocol##_item));              \
          err = onp_flow_parse_##protocol##_item (&sub_input,                 \
                                                  &(protocol##_item[0]),      \
						  &match_all);                \
          if (err)                                                            \
            goto done;                                                        \
                                                                              \
	  item = vec_elt_at_index (items, layer);                             \
	  layer++;                                                            \
                                                                              \
          if (match_all)                                                      \
            {                                                                 \
              item->spec = NULL;                                              \
	      item->mask = NULL;                                              \
	      item->type = CNXK_DRV_FLOW_ITEM_TYPE_##ltype;                   \
	      continue;                                                       \
	    }                                                                 \
                                                                              \
          unformat_free (&sub_input);                                         \
                                                                              \
	  if (unformat (line_input, #protocol "-mask %U",                     \
			unformat_vlib_cli_sub_input, &sub_input))             \
            {                                                                 \
	      err = onp_flow_parse_##protocol##_item (&sub_input,             \
						      &(protocol##_item[1]),  \
						      &match_all);	      \
              if (err)                                                        \
                goto done;                                                    \
                                                                              \
              item->mask = (void *) &(protocol##_item[1]);                    \
              unformat_free (&sub_input);                                     \
            }                                                                 \
          else                                                                \
            item->mask = (void *) &(protocol##_item[0]);                      \
                                                                              \
        item->spec = (void *) &(protocol##_item[0]);                          \
        item->size = sizeof (hdr);                                            \
        item->type = CNXK_DRV_FLOW_ITEM_TYPE_##ltype;                         \
      }

      foreach_cnxk_flow_supported_protocols

      /* Actions associated to flow */
      else if (unformat (line_input, "redirect-to-queue %d",
			 &vf.redirect_queue))
	vf.actions |= VNET_FLOW_ACTION_REDIRECT_TO_QUEUE;
      else if (unformat (line_input, "drop"))
	vf.actions |= VNET_FLOW_ACTION_DROP;
      else if (unformat (line_input, "mark %u", &vf.mark_flow_id))
	vf.actions |= VNET_FLOW_ACTION_MARK;
      else if (unformat (line_input, "count"))
	vf.actions |= VNET_FLOW_ACTION_COUNT;
      else if (unformat (line_input, "rss function"))
        {
	  if (0)
	    ;
#undef _
#define _(f, s)                                   \
	  else if (unformat (line_input, s))      \
	    vf.rss_fun = VNET_RSS_FUNC_##f;

	  foreach_rss_function

	  else
	    return clib_error_return (0, "unknown input '%U'",
				      format_unformat_error, line_input);

	  vf.actions |= VNET_FLOW_ACTION_RSS;
	}
      else if (unformat (line_input, "rss types"))
	{
	  rss_type[0] = NULL;
	  rss_type[1] = NULL;
	  rss_type[2] = NULL;
	  type_str = NULL;

	  if (unformat (line_input, "%s use %s and %s", &rss_type[0],
			&rss_type[1], &rss_type[2]))
	    ;
	  else if (unformat (line_input, "%s use %s", &rss_type[0],
			     &rss_type[1]))
	    ;
	  else if (unformat (line_input, "%s", &rss_type[0]))
	    ;
#undef _
#define _(a, b, c)                                                            \
	      else if (!clib_strcmp (c, (const char *) type_str))             \
		vf.rss_types |= (1ULL << a);

#define check_rss_types(_str)                                                 \
	  if (_str != NULL)                                                   \
	    {                                                                 \
	      type_str = _str;                                                \
									      \
	      if (0)                                                          \
		;                                                             \
	      foreach_flow_rss_types                                          \
	      else                                                            \
		{                                                             \
		  return clib_error_return (0, "parse error: '%U'",           \
				            format_unformat_error,            \
				            line_input);                      \
	        }                                                             \
	    }

	  check_rss_types (rss_type[0]);
	  check_rss_types (rss_type[1]);
	  check_rss_types (rss_type[2]);

#undef _
	    vf.actions |= VNET_FLOW_ACTION_RSS;
	}
      else if (unformat (line_input, " rss queues"))
	{
	  if (unformat (line_input, "%d to %d", &queue_start, &queue_end))
	    ;
	  else
	    {
	      err = clib_error_return (0, "unknown input '%U'",
				     format_unformat_error, line_input);
	    }

	vf.queue_index = queue_start;
	vf.queue_num = queue_end - queue_start + 1;
	vf.actions |= VNET_FLOW_ACTION_RSS;
	}
      else
	{
	  err = clib_error_return (0, "Unknown input : '%U'",
	    			   format_unformat_error, input);
	  goto done;
	}
      /* clang-format on */
    }

  item = vec_elt_at_index (items, layer);
  item->type = CNXK_DRV_FLOW_ITEM_TYPE_END;

  if (hw_if_index == ~0)
    {
      err = clib_error_return (0, "Please specify interface name");
      goto done;
    }

  if (vf.actions == 0)
    {
      err = clib_error_return (0, "Please specify at least one action");
      goto done;
    }

  rc = vnet_flow_add (vnm, &vf, &flow_index);
  if (rc)
    {
      vlib_cli_output (vm, "Failed to add flow rule");
      goto done;
    }

  rc = vnet_flow_enable (vnm, flow_index, hw_if_index);
  if (rc)
    {
      err = clib_error_return (0, "flow error: '%U'", format_flow_error, rc);
      vlib_cli_output (vm, "Failed to enable flow rule");

      rc = vnet_flow_del (vnm, flow_index);
      if (rc)
	err = clib_error_return (err, "flow error: %U", format_flow_error, rc);

      goto done;
    }

  vlib_cli_output (vm, "flow %u added", flow_index);

done:
  vec_free (items);
  unformat_free (line_input);
  unformat_free (&sub_input);
  return err;
}

VLIB_CLI_COMMAND (onp_pktio_flow_add_command, static) = {
  .path = "onp pktio flow add",
  .short_help = flow_cli_help,
  .function = onp_pktio_flow_add_command_fn,
};

clib_error_t *
onp_pktio_flow_del_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  onp_main_t *om = onp_get_main ();
  vnet_main_t *vnm = om->vnet_main;
  u32 hw_if_index = ~0;
  u32 flow_index = ~0;
  vnet_flow_t *flow;
  int rc;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "index %u", &flow_index))
	;
      else if (unformat (input, "%U", unformat_vnet_hw_interface, vnm,
			 &hw_if_index))
	;
      else
	return clib_error_return (0, "Unknown input '%U'",
				  format_unformat_error, input);
    }

  flow = vnet_get_flow (flow_index);

  if (flow->type != VNET_FLOW_TYPE_GENERIC)
    {
      vlib_cli_output (vm, "Please pass valid index returned when adding rule "
			   "using onp pktio flow add CLI");
      return 0;
    }

  rc = vnet_flow_del (vnm, flow_index);
  if (rc)
    return clib_error_return (0, "flow error: %U", format_flow_error, rc);

  return 0;
}

VLIB_CLI_COMMAND (onp_pktio_flow_del_command, static) = {
  .path = "onp pktio flow del",
  .short_help = "onp pktio flow del index <value> <interface name>",
  .function = onp_pktio_flow_del_command_fn,
};
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
