/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ipoe/ipoe.h>
#include <qinq/qinq.h>

qinq_plugin_main_t qinq_plugin_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "QinQ subport classification and encapsulation",
};

static u8 *
format_qinq_match_type (u8 *s, va_list *args)
{
  qinq_match_type_t type = va_arg (*args, qinq_match_type_t);

  if (type == QINQ_MATCH_EXACT)
    return format (s, "exact");
  if (type == QINQ_MATCH_RANGE)
    return format (s, "range");
  return format (s, "any");
}

static u8 *
format_qinq_service (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);

  if (flags == (QINQ_SERVICE_IPOE | QINQ_SERVICE_PPPOE))
    return format (s, "both");
  if (flags & QINQ_SERVICE_IPOE)
    return format (s, "ipoe");
  if (flags & QINQ_SERVICE_PPPOE)
    return format (s, "pppoe");
  return format (s, "none");
}

static clib_error_t *
qinq_subport_cli_parse (vlib_main_t *vm, unformat_input_t *input,
                        qinq_subport_t *config)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 first;
  u32 last;
  u32 tpid;

  config->rule_id = ~0;
  config->sw_if_index = ~0;
  config->parent_sw_if_index = ~0;
  config->admin_up = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "rule-id %u", &config->rule_id))
        ;
      else if (unformat (input, "parent %U", unformat_vnet_sw_interface,
                         vnm, &config->parent_sw_if_index))
        ;
      else if (unformat (input, "outer-tpid %x", &tpid))
        config->outer_tpid = tpid;
      else if (unformat (input, "outer-vlan %u", &first))
        config->outer_vlan = first;
      else if (unformat (input, "inner-tpid %x", &tpid))
        config->inner_tpid = tpid;
      else if (unformat (input, "exact %u", &first))
        {
          config->match_type = QINQ_MATCH_EXACT;
          config->inner_vlan_first = first;
          config->inner_vlan_last = first;
        }
      else if (unformat (input, "range %u-%u", &first, &last))
        {
          config->match_type = QINQ_MATCH_RANGE;
          config->inner_vlan_first = first;
          config->inner_vlan_last = last;
        }
      else if (unformat (input, "any"))
        config->match_type = QINQ_MATCH_ANY;
      else if (unformat (input, "service ipoe"))
        config->service_flags = QINQ_SERVICE_IPOE;
      else if (unformat (input, "service pppoe"))
        config->service_flags = QINQ_SERVICE_PPPOE;
      else if (unformat (input, "service both"))
        config->service_flags = QINQ_SERVICE_IPOE | QINQ_SERVICE_PPPOE;
      else if (unformat (input, "admin-up"))
        config->admin_up = 1;
      else if (unformat (input, "admin-down"))
        config->admin_up = 0;
      else if (config->sw_if_index == ~0 &&
               unformat (input, "%U", unformat_vnet_sw_interface, vnm,
                         &config->sw_if_index))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  if (config->rule_id == ~0)
    return clib_error_return (0, "rule-id is required");
  if (config->sw_if_index == ~0)
    return clib_error_return (0, "subport interface is required");
  return 0;
}

static clib_error_t *
qinq_subport_add_command_fn (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *cmd)
{
  qinq_subport_t config = {};
  qinq_error_t error;
  clib_error_t *parse_error;

  parse_error = qinq_subport_cli_parse (vm, input, &config);
  if (parse_error)
    return parse_error;
  error = qinq_subport_add (&config);
  if (error != QINQ_ERROR_NONE)
    return clib_error_return (0, "%s", qinq_error_string (error));
  return 0;
}

static clib_error_t *
qinq_subport_update_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  qinq_subport_t config = {};
  qinq_error_t error;
  clib_error_t *parse_error;

  parse_error = qinq_subport_cli_parse (vm, input, &config);
  if (parse_error)
    return parse_error;
  error = qinq_subport_update (config.rule_id, &config);
  if (error != QINQ_ERROR_NONE)
    return clib_error_return (0, "%s", qinq_error_string (error));
  return 0;
}

static clib_error_t *
qinq_subport_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  qinq_error_t error;
  u32 rule_id;

  if (!unformat (input, "rule-id %u", &rule_id))
    return clib_error_return (0, "rule-id is required");
  error = qinq_subport_delete (rule_id);
  if (error != QINQ_ERROR_NONE)
    return clib_error_return (0, "%s", qinq_error_string (error));
  return 0;
}

static clib_error_t *
show_qinq_subport_command_fn (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t *rule;
  vnet_main_t *vnm = vnet_get_main ();

  vlib_cli_output (vm, "%-8s %-20s %-20s %-7s %-11s %-12s %-8s %-5s",
                   "Rule", "Subport", "Parent", "S-VLAN", "C-VLAN",
                   "Match", "Service", "State");
  pool_foreach (rule, qm->rules)
    {
      u8 *inner = 0;

      if (rule->match_type == QINQ_MATCH_EXACT)
        inner = format (inner, "%u", rule->inner_vlan_first);
      else if (rule->match_type == QINQ_MATCH_RANGE)
        inner = format (inner, "%u-%u", rule->inner_vlan_first,
                        rule->inner_vlan_last);
      else
        inner = format (inner, "any");

      vlib_cli_output (
        vm, "%-8u %-20U %-20U %-7u %-11v %-12U %-8U %-5s", rule->rule_id,
        format_vnet_sw_if_index_name, vnm, rule->sw_if_index,
        format_vnet_sw_if_index_name, vnm, rule->parent_sw_if_index,
        rule->outer_vlan, inner, format_qinq_match_type, rule->match_type,
        format_qinq_service, (u32) rule->service_flags,
        rule->admin_up ? "up" : "down");
      vec_free (inner);
    }
  return 0;
}

static clib_error_t *
show_qinq_match_command_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  qinq_match_result_t result = {};
  vnet_main_t *vnm = vnet_get_main ();
  u32 parent = ~0;
  u32 outer_tpid = ETHERNET_TYPE_DOT1AD;
  u32 inner_tpid = ETHERNET_TYPE_VLAN;
  u32 outer_vlan = 0;
  u32 inner_vlan = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "parent %U", unformat_vnet_sw_interface, vnm,
                    &parent))
        ;
      else if (unformat (input, "outer-tpid %x", &outer_tpid))
        ;
      else if (unformat (input, "outer-vlan %u", &outer_vlan))
        ;
      else if (unformat (input, "inner-tpid %x", &inner_tpid))
        ;
      else if (unformat (input, "inner-vlan %u", &inner_vlan))
        ;
      else
        return clib_error_return (0, "unknown input `%U'",
                                  format_unformat_error, input);
    }

  if (parent == ~0 || outer_vlan == 0 || inner_vlan == 0)
    return clib_error_return (
      0, "parent, outer-vlan and inner-vlan are required");

  if (!qinq_subport_lookup (parent, outer_tpid, outer_vlan, inner_tpid,
                            inner_vlan, &result))
    {
      vlib_cli_output (vm, "no match");
      return 0;
    }

  vlib_cli_output (vm, "rule-id %u interface %U match %U service %U",
                   result.rule_id, format_vnet_sw_if_index_name, vnm,
                   result.sw_if_index, format_qinq_match_type,
                   result.match_type, format_qinq_service,
                   (u32) result.service_flags);
  return 0;
}

static clib_error_t *
qinq_ipoe_route_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  qinq_ipoe_route_t route = {
    .route_id = ~0,
    .sw_if_index = ~0,
  };
  vnet_main_t *vnm = vnet_get_main ();
  u8 is_add = 0;
  u8 is_update = 0;
  u8 is_delete = 0;
  u8 has_ip = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "update"))
	is_update = 1;
      else if (unformat (input, "delete"))
	is_delete = 1;
      else if (unformat (input, "route-id %u", &route.route_id))
	;
      else if (unformat (input, "table %u", &route.table_id))
	;
      else if (unformat (input, "%U/32", unformat_ip4_address,
			 &route.user_ip4))
	has_ip = 1;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface,
			 vnm, &route.sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if ((is_add + is_update + is_delete) != 1 || route.route_id == ~0)
    return clib_error_return (0, "one operation and route-id are required");
  if (!is_delete && (!has_ip || route.sw_if_index == ~0))
    return clib_error_return (0, "route and interface are required");

  if (is_add)
    rv = qinq_ipoe_route_add (&route);
  else if (is_update)
    rv = qinq_ipoe_route_update (&route);
  else
    rv = qinq_ipoe_route_delete (route.route_id);
  if (rv != IPOE_OK)
    return clib_error_return (0, "IPoE QinQ route failed: %s",
			      ipoe_error_string (rv));
  return 0;
}

static clib_error_t *
show_qinq_ipoe_route_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  qinq_ipoe_route_t *route;
  vnet_main_t *vnm = vnet_get_main ();

  pool_foreach (route, qpm->ipoe_routes)
    vlib_cli_output (vm, "route-id %u table %u %U/32 interface %U",
		     route->route_id, route->table_id, format_ip4_address,
		     &route->user_ip4, format_vnet_sw_if_index_name, vnm,
		     route->sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (qinq_subport_add_command, static) = {
  .path = "qinq subport add",
  .short_help = "qinq subport add <subport> rule-id <id> parent <parent> "
                "outer-tpid <hex> outer-vlan <vid> inner-tpid <hex> "
                "exact <vid>|range <first>-<last>|any "
                "[service ipoe|pppoe|both] [admin-up|admin-down]",
  .function = qinq_subport_add_command_fn,
};

VLIB_CLI_COMMAND (qinq_subport_update_command, static) = {
  .path = "qinq subport update",
  .short_help = "qinq subport update <subport> rule-id <id> ...",
  .function = qinq_subport_update_command_fn,
};

VLIB_CLI_COMMAND (qinq_subport_delete_command, static) = {
  .path = "qinq subport delete",
  .short_help = "qinq subport delete rule-id <id>",
  .function = qinq_subport_delete_command_fn,
};

VLIB_CLI_COMMAND (show_qinq_subport_command, static) = {
  .path = "show qinq subport",
  .short_help = "show qinq subport",
  .function = show_qinq_subport_command_fn,
};

VLIB_CLI_COMMAND (show_qinq_match_command, static) = {
  .path = "show qinq match",
  .short_help = "show qinq match parent <interface> outer-vlan <vid> "
                "inner-vlan <vid> [outer-tpid <hex>] [inner-tpid <hex>]",
  .function = show_qinq_match_command_fn,
};

VLIB_CLI_COMMAND (qinq_ipoe_route_command, static) = {
  .path = "qinq ipoe route",
  .short_help = "qinq ipoe route add|update route-id <id> table <table-id> "
		"<user-ip>/32 interface <qinq-subport> | "
		"delete route-id <id>",
  .function = qinq_ipoe_route_command_fn,
};

VLIB_CLI_COMMAND (show_qinq_ipoe_route_command, static) = {
  .path = "show qinq ipoe route",
  .short_help = "show qinq ipoe route",
  .function = show_qinq_ipoe_route_command_fn,
};
