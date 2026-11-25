/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <time.h>

static clib_error_t *
ipoe_set_interface_command (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  u32 sw_if_index = ~0;
  u8 enable = 0, operation_set = 0;
  u8 mode = 0, input_path = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    im->vnet_main, &sw_if_index))
	;
      else if (unformat (input, "enable"))
	{
	  enable = 1;
	  operation_set = 1;
	}
      else if (unformat (input, "disable"))
	{
	  enable = 0;
	  operation_set = 1;
	}
      else if (unformat (input, "mode l2")) mode = IPOE_INTERNAL_ACCESS_MODE_L2;
      else if (unformat (input, "mode l3")) mode = IPOE_INTERNAL_ACCESS_MODE_L3;
      else if (unformat (input, "input l2-input")) input_path = IPOE_INPUT_L2;
      else if (unformat (input, "input ip4-input")) input_path = IPOE_INPUT_IP4;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (sw_if_index == ~0 || !operation_set)
    return clib_error_return (0, "interface and enable|disable are required");
  if (enable && (!mode || !input_path))
    return clib_error_return (0, "enable requires mode and input");

  rv = ipoe_interface_enable_disable (sw_if_index, enable, mode, input_path);
  if (rv)
    return clib_error_return (0, "IPoE interface failed: %s",
			      ipoe_error_string (rv));
  vlib_cli_output (vm, "ipoe interface %U %s",
		   format_vnet_sw_if_index_name, im->vnet_main, sw_if_index,
		   enable ? "enabled" : "disabled");
  return 0;
}

VLIB_CLI_COMMAND (ipoe_set_interface_cli, static) = {
  .path = "set ipoe interface",
  .short_help = "set ipoe interface <interface> enable mode <l2|l3> "
		"input <l2-input|ip4-input> | <interface> disable",
  .function = ipoe_set_interface_command,
};

static clib_error_t *
ipoe_set_session_command (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ip4_address_t user_ip4 = {};
  mac_address_t user_mac = {};
  ipoe_qinq_session_t qinq = {};
  u64 external_index = 0;
  u64 generation = 0;
  u64 lease_expiry = 0;
  u32 sw_if_index = ~0, lease_timeout = 0;
  u32 value;
  u8 is_add = 0, is_update = 0, is_del = 0;
  u8 has_ip = 0, has_mac = 0, has_generation = 0;
  u8 admin_state = 1;
  int rv;

  qinq.parent_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add")) is_add = 1;
      else if (unformat (input, "update")) is_update = 1;
      else if (unformat (input, "del")) is_del = 1;
      else if (unformat (input, "index %llu", &external_index)) ;
      else if (unformat (input, "generation %llu", &generation))
	has_generation = 1;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface,
			 im->vnet_main, &sw_if_index)) ;
      else if (unformat (input, "ip %U", unformat_ip4_address, &user_ip4))
	has_ip = 1;
      else if (unformat (input, "mac %U", unformat_ethernet_address,
			 user_mac.bytes))
	has_mac = 1;
      else if (unformat (input, "local-mac %U", unformat_ethernet_address,
			 qinq.local_mac.bytes))
	qinq.enabled = 1;
      else if (unformat (input, "parent %U", unformat_vnet_sw_interface,
			 im->vnet_main, &qinq.parent_sw_if_index))
	qinq.enabled = 1;
      else if (unformat (input, "outer-tpid %x", &value))
	{
	  qinq.outer_tpid = value;
	  qinq.enabled = 1;
	}
      else if (unformat (input, "outer-vlan %u", &value))
	{
	  qinq.outer_vlan = value;
	  qinq.enabled = 1;
	}
      else if (unformat (input, "inner-tpid %x", &value))
	{
	  qinq.inner_tpid = value;
	  qinq.enabled = 1;
	}
      else if (unformat (input, "inner-vlan %u", &value))
	{
	  qinq.inner_vlan = value;
	  qinq.enabled = 1;
	}
      else if (unformat (input, "lease %u", &lease_timeout)) ;
      else if (unformat (input, "lease-expiry %llu", &lease_expiry)) ;
      else if (unformat (input, "state up")) admin_state = 1;
      else if (unformat (input, "state down")) admin_state = 0;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!external_index || (is_add + is_update + is_del) != 1)
    return clib_error_return (
      0, "one add|update|del and non-zero index are required");
  if (is_del)
    rv = ipoe_session_del (external_index);
  else
    {
      if (sw_if_index == ~0 || !has_ip || !lease_timeout)
	return clib_error_return (
	  0, "add|update requires interface, ip and lease");
      if (is_update && !has_generation)
	return clib_error_return (0, "update requires generation");
      if (!lease_expiry)
	lease_expiry = (u64) time (0) + lease_timeout;
      if (is_add)
	rv = ipoe_session_add (
	  external_index, generation, sw_if_index, &user_ip4, &user_mac,
	  has_mac, admin_state, lease_timeout, lease_expiry, &qinq);
      else
	rv = ipoe_session_update (
	  external_index, generation, sw_if_index, &user_ip4, &user_mac,
	  has_mac, admin_state, lease_timeout, lease_expiry, &qinq);
    }
  if (rv)
    return clib_error_return (0, "IPoE session failed: %s",
			      ipoe_error_string (rv));
  vlib_cli_output (vm, "ipoe session index %llu %s", external_index,
		   is_add ? "installed" :
		   is_update ? "updated" : "removed");
  return 0;
}

VLIB_CLI_COMMAND (ipoe_set_session_cli, static) = {
  .path = "set ipoe session",
  .short_help = "set ipoe session add|update index <index> "
		"interface <interface> "
		"ip <ipv4> [mac <mac>] lease <seconds> "
		"[lease-expiry <time>] [generation <generation>] "
		"[state up|down] "
		"[parent <parent> local-mac <mac> outer-tpid <hex> "
		"outer-vlan <vid> inner-tpid <hex> inner-vlan <vid>] | "
		"del index <index>",
  .function = ipoe_set_session_command,
};

static clib_error_t *
ipoe_set_qinq_route_command (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ip4_address_t user_ip4 = {};
  u32 table_id = 0;
  u32 sw_if_index = ~0;
  u8 is_add = 0, is_del = 0;
  u8 has_table = 0, has_ip = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add"))
	is_add = 1;
      else if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "table %u", &table_id))
	has_table = 1;
      else if (unformat (input, "ip %U", unformat_ip4_address, &user_ip4))
	has_ip = 1;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface,
			 im->vnet_main, &sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if ((is_add + is_del) != 1 || !has_table || !has_ip)
    return clib_error_return (
      0, "one add|del, table and ip are required");
  if (is_add && sw_if_index == ~0)
    return clib_error_return (0, "add requires interface");

  rv = ipoe_qinq_route_add_del (table_id, &user_ip4, sw_if_index, is_add);
  if (rv)
    return clib_error_return (0, "IPoE QinQ route failed: %s",
			      ipoe_error_string (rv));

  vlib_cli_output (vm, "IPoE QinQ route %U/32 table %u %s",
		   format_ip4_address, &user_ip4, table_id,
		   is_add ? "installed" : "removed");
  return 0;
}

VLIB_CLI_COMMAND (ipoe_set_qinq_route_cli, static) = {
  .path = "set ipoe qinq route",
  .short_help = "set ipoe qinq route add table <id> ip <ipv4> "
		"interface <interface> | del table <id> ip <ipv4>",
  .function = ipoe_set_qinq_route_command,
};

static void
ipoe_show_one_interface (vlib_main_t *vm, ipoe_interface_t *intf)
{
  vlib_cli_output (vm, "IPoE interface %U",
		   format_vnet_sw_if_index_name, ipoe_main.vnet_main,
		   intf->sw_if_index);
  vlib_cli_output (vm, "  state:        %s",
		   intf->enabled ? "enabled" : "disabled");
  vlib_cli_output (vm, "  access mode:  %s",
		   ipoe_access_mode_name (intf->access_mode));
  vlib_cli_output (vm, "  input path:   %s",
		   ipoe_input_path_name (intf->input_path));
  vlib_cli_output (vm, "  sessions:     %u", intf->session_count);
}

static clib_error_t *
ipoe_show_interface_command (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  u32 sw_if_index = ~0, i;
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
      !unformat (input, "interface %U", unformat_vnet_sw_interface,
		 im->vnet_main, &sw_if_index))
    return clib_error_return (0, "expected interface <name>");

  if (sw_if_index != ~0)
    {
      if (sw_if_index >= vec_len (im->interfaces) ||
	  !im->interfaces[sw_if_index].enabled)
	return clib_error_return (0, "IPoE is not enabled on interface");
      ipoe_show_one_interface (vm, &im->interfaces[sw_if_index]);
      return 0;
    }
  for (i = 0; i < vec_len (im->interfaces); i++)
    if (im->interfaces[i].enabled)
      ipoe_show_one_interface (vm, &im->interfaces[i]);
  return 0;
}

VLIB_CLI_COMMAND (ipoe_show_interface_cli, static) = {
  .path = "show ipoe interface",
  .short_help = "show ipoe interface [interface <interface>]",
  .function = ipoe_show_interface_command,
};

static void
ipoe_show_one_session (vlib_main_t *vm, ipoe_session_t *session)
{
  f64 remaining = session->expires_at - vlib_time_now (ipoe_main.vlib_main);

  if (remaining < 0)
    remaining = 0;

  vlib_cli_output (vm, "IPoE session %llu", session->external_index);
  vlib_cli_output (vm, "  interface:     %U",
		   format_vnet_sw_if_index_name, ipoe_main.vnet_main,
		   session->sw_if_index);
  vlib_cli_output (vm, "  access mode:   %s",
		   ipoe_access_mode_name (
		     ipoe_main.interfaces[session->sw_if_index].access_mode));
  vlib_cli_output (vm, "  user IPv4:     %U", format_ip4_address,
		   &session->user_ip4);
  if (session->has_user_mac)
    vlib_cli_output (vm, "  user MAC:      %U", format_ethernet_address,
		     session->user_mac.bytes);
  else
    vlib_cli_output (vm, "  user MAC:      not configured");
  if (session->qinq.enabled)
    {
      vlib_cli_output (vm, "  QinQ parent:   %U",
		       format_vnet_sw_if_index_name, ipoe_main.vnet_main,
		       session->qinq.parent_sw_if_index);
      vlib_cli_output (vm, "  QinQ tags:     0x%04x/%u 0x%04x/%u",
		       session->qinq.outer_tpid, session->qinq.outer_vlan,
		       session->qinq.inner_tpid, session->qinq.inner_vlan);
      vlib_cli_output (vm, "  local MAC:     %U", format_ethernet_address,
		       session->qinq.local_mac.bytes);
    }
  vlib_cli_output (vm, "  admin state:   %s",
		   session->admin_state ? "up" : "down");
  vlib_cli_output (vm, "  lease expiry:  %llu", session->lease_expiry);
  vlib_cli_output (vm, "  remaining:     %.0f seconds", remaining);
  vlib_cli_output (vm, "  timer handle:  %u", session->timer_handle);
  vlib_cli_output (vm, "  timer token:   %u", session->timer_generation);
  vlib_cli_output (vm, "  counter index: %u", session->counter_index);
  vlib_cli_output (vm, "  IPv6 bindings: %u", session->ip6_binding_count);
}

static void
ipoe_show_one_session_stats (vlib_main_t *vm, ipoe_session_t *session)
{
  ipoe_session_counters_t counters;
  int rv;

  rv = ipoe_session_get_counters (session->external_index, &counters);
  if (rv != IPOE_OK)
    {
      vlib_cli_output (vm, "index=%llu stats_error=%s",
		       session->external_index, ipoe_error_string (rv));
      return;
    }

  vlib_cli_output (vm, "IPoE session %llu statistics",
		   session->external_index);
  vlib_cli_output (vm, "  counter index: %u", session->counter_index);
  vlib_cli_output (vm, "  upstream:");
  vlib_cli_output (vm, "    forward:     packets %-12llu bytes %llu",
		   counters.upstream_forward.packets,
		   counters.upstream_forward.bytes);
  vlib_cli_output (vm, "    gate-drop:   packets %-12llu bytes %llu",
		   counters.upstream_gate_drop.packets,
		   counters.upstream_gate_drop.bytes);
  vlib_cli_output (vm, "  downstream:");
  vlib_cli_output (vm, "    forward:     packets %-12llu bytes %llu",
		   counters.downstream_forward.packets,
		   counters.downstream_forward.bytes);
  vlib_cli_output (vm, "    gate-drop:   packets %-12llu bytes %llu",
		   counters.downstream_gate_drop.packets,
		   counters.downstream_gate_drop.bytes);
}

static clib_error_t *
ipoe_show_session_stats_command (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  u64 external_index = 0;
  uword *p;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
      !unformat (input, "index %llu", &external_index))
    return clib_error_return (0, "expected index <index>");

  if (external_index)
    {
      p = hash_get (im->session_by_index, (uword) external_index);
      if (!p || pool_is_free_index (im->sessions, p[0]))
	return clib_error_return (0, "IPoE session not found");
      ipoe_show_one_session_stats (vm,
				   pool_elt_at_index (im->sessions, p[0]));
      return 0;
    }

  pool_foreach (session, im->sessions)
    ipoe_show_one_session_stats (vm, session);
  return 0;
}

VLIB_CLI_COMMAND (ipoe_show_session_stats_cli, static) = {
  .path = "show ipoe session stats",
  .short_help = "show ipoe session stats [index <index>]",
  .function = ipoe_show_session_stats_command,
};

static clib_error_t *
ipoe_show_session_command (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  u64 external_index = 0;
  uword *p;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT &&
      !unformat (input, "index %llu", &external_index))
    return clib_error_return (0, "expected index <index>");
  if (external_index)
    {
      p = hash_get (im->session_by_index, (uword) external_index);
      if (!p)
	return clib_error_return (0, "IPoE session not found");
      ipoe_show_one_session (vm, pool_elt_at_index (im->sessions, p[0]));
      return 0;
    }
  pool_foreach (session, im->sessions)
    ipoe_show_one_session (vm, session);
  return 0;
}

VLIB_CLI_COMMAND (ipoe_show_session_cli, static) = {
  .path = "show ipoe session",
  .short_help = "show ipoe session [index <index>]",
  .function = ipoe_show_session_command,
};

static clib_error_t *
ipoe_qinq_route_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  ipoe_qinq_route_t route = {
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
    rv = ipoe_qinq_route_add (&route);
  else if (is_update)
    rv = ipoe_qinq_route_update (&route);
  else
    rv = ipoe_qinq_route_delete (route.route_id);
  if (rv != IPOE_OK)
    return clib_error_return (0, "IPoE QinQ route failed: %s",
			      ipoe_error_string (rv));
  return 0;
}

static clib_error_t *
show_ipoe_qinq_route_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_qinq_route_t *route;

  pool_foreach (route, im->qinq_routes)
    vlib_cli_output (vm, "route-id %u table %u %U/32 interface %U",
		     route->route_id, route->table_id, format_ip4_address,
		     &route->user_ip4, format_vnet_sw_if_index_name,
		     im->vnet_main, route->sw_if_index);
  return 0;
}

VLIB_CLI_COMMAND (ipoe_qinq_route_command, static) = {
  .path = "qinq ipoe route",
  .short_help = "qinq ipoe route add|update route-id <id> table <table-id> "
		"<user-ip>/32 interface <qinq-subport> | "
		"delete route-id <id>",
  .function = ipoe_qinq_route_command_fn,
};

VLIB_CLI_COMMAND (show_ipoe_qinq_route_command, static) = {
  .path = "show qinq ipoe route",
  .short_help = "show qinq ipoe route",
  .function = show_ipoe_qinq_route_command_fn,
};

static clib_error_t *
ipoe_ip6_binding_command (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  ipoe_main_t *im = &ipoe_main;
  ip6_address_t prefix = {};
  u64 external_index = 0;
  u32 sw_if_index = ~0, length = 0;
  u8 is_add = 0, is_del = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add")) is_add = 1;
      else if (unformat (input, "del")) is_del = 1;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface,
			 im->vnet_main, &sw_if_index)) ;
      else if (unformat (input, "prefix %U/%u", unformat_ip6_address,
			 &prefix, &length)) ;
      else if (unformat (input, "index %llu", &external_index)) ;
      else return clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
    }
  if ((is_add + is_del) != 1 || sw_if_index == ~0 || !external_index ||
      !length || length > 128)
    return clib_error_return (0, "operation, interface, prefix and index are required");
  rv = ipoe_ip6_binding_add_del (sw_if_index, &prefix, length,
				 external_index, is_add);
  return rv ? clib_error_return (0, "IPoE IPv6 binding failed: %s",
				 ipoe_error_string (rv)) : 0;
}

VLIB_CLI_COMMAND (ipoe_ip6_binding_cli, static) = {
  .path = "set ipoe ip6 binding",
  .short_help = "set ipoe ip6 binding add|del interface <interface> "
    "prefix <ipv6-prefix> index <external-index>",
  .function = ipoe_ip6_binding_command,
};

static clib_error_t *
show_ipoe_ip6_binding_command (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  ipoe_ip6_binding_t *binding;
  pool_foreach (binding, ipoe_main.ip6_bindings)
    vlib_cli_output (vm, "interface %U prefix %U/%u index %llu",
	format_vnet_sw_if_index_name, ipoe_main.vnet_main,
	binding->key.sw_if_index, format_ip6_address, &binding->key.prefix,
	binding->key.prefix_length, binding->external_index);
  return 0;
}

VLIB_CLI_COMMAND (show_ipoe_ip6_binding_cli, static) = {
  .path = "show ipoe ip6 binding",
  .short_help = "show ipoe ip6 binding",
  .function = show_ipoe_ip6_binding_command,
};

static clib_error_t *
ipoe_qinq_ip6_route_command (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  ip6_address_t prefix = {};
  u64 external_index = 0;
  u32 table_id = 0, sw_if_index = ~0, length = 0;
  u8 is_add = 0, is_del = 0;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add")) is_add = 1;
      else if (unformat (input, "delete")) is_del = 1;
      else if (unformat (input, "table %u", &table_id)) ;
      else if (unformat (input, "prefix %U/%u", unformat_ip6_address,
			 &prefix, &length)) ;
      else if (unformat (input, "interface %U", unformat_vnet_sw_interface,
			 ipoe_main.vnet_main, &sw_if_index)) ;
      else if (unformat (input, "index %llu", &external_index)) ;
      else return clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
    }
  if ((is_add + is_del) != 1 || !length || length > 128 ||
	!external_index || (is_add && sw_if_index == ~0))
    return clib_error_return (0, "operation, prefix and index are required");
  rv = ipoe_qinq_ip6_route_add_del (table_id, &prefix, length, sw_if_index,
				    external_index, is_add);
  return rv ? clib_error_return (0, "IPoE QinQ IPv6 route failed: %s",
				 ipoe_error_string (rv)) : 0;
}

VLIB_CLI_COMMAND (ipoe_qinq_ip6_route_cli, static) = {
  .path = "qinq ipoe ip6 route",
  .short_help = "qinq ipoe ip6 route add|delete table <id> "
    "prefix <ipv6-prefix> [interface <qinq-subport>] index <external-index>",
  .function = ipoe_qinq_ip6_route_command,
};

static clib_error_t *
show_ipoe_qinq_ip6_route_command (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  ipoe_qinq_ip6_route_t *route;
  pool_foreach (route, ipoe_main.qinq_ip6_routes)
    vlib_cli_output (vm, "table %u prefix %U/%u interface %U index %llu",
	route->table_id, format_ip6_address, &route->prefix,
	route->prefix_length, format_vnet_sw_if_index_name,
	ipoe_main.vnet_main, route->sw_if_index, route->external_index);
  return 0;
}

VLIB_CLI_COMMAND (show_ipoe_qinq_ip6_route_cli, static) = {
  .path = "show qinq ipoe route ip6",
  .short_help = "show qinq ipoe route ip6",
  .function = show_ipoe_qinq_ip6_route_command,
};
