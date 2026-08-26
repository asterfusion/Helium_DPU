/*
 * cgnat_cli.c - CGNAT plugin CLI
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <string.h>
#include <vnet/fib/fib_table.h>

#include <nat/cgnat/cgnat.h>

static clib_error_t *
cgnat_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  int rv = cgnat_plugin_enable_disable (1);
  return rv ? clib_error_return (0, "cgnat enable returned %d", rv) : 0;
}

static clib_error_t *
cgnat_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  int rv = cgnat_plugin_enable_disable (0);
  return rv ? clib_error_return (0, "cgnat disable returned %d", rv) : 0;
}

static void
cgnat_pool_config_defaults (cgnat_pool_config_t *config)
{
  clib_memset (config, 0, sizeof (*config));
  config->block_size = CGNAT_DEFAULT_BLOCK_SIZE;
  config->reserved_port_end = CGNAT_DEFAULT_START_PORT - 1;
  config->prealloc_blocks_per_user = CGNAT_DEFAULT_PREALLOC_BLOCKS;
  config->cooling_time = CGNAT_DEFAULT_COOLING_TIME;
  config->block_alloc_mode = CGNAT_BLOCK_ALLOC_MODE_ON_DEMAND;
  config->port_alloc_mode = CGNAT_PORT_ALLOC_MODE_RANDOM;
}

static clib_error_t *
cgnat_parse_pool_config (unformat_input_t *input, u32 *pool_id,
			 cgnat_pool_config_t *config, u8 require_addresses)
{
  u32 value, reserved_start, reserved_end;
  u8 *label = 0;
  u8 first_set = !require_addresses, last_set = !require_addresses;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (*pool_id == CGNAT_INVALID_INDEX && unformat (input, "%u", pool_id))
	;
      else if (unformat (input, "pool %u", pool_id))
	;
      else if (unformat (input, "label %s", &label))
	;
      else if (unformat (input, "start-ip %U", unformat_ip4_address,
			 &config->first_ip))
	first_set = 1;
      else if (unformat (input, "end-ip %U", unformat_ip4_address,
			 &config->last_ip))
	last_set = 1;
      else if (unformat (input, "block-size %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "block-size exceeds 65535");
	  config->block_size = value;
	}
      else if (unformat (input, "block-alloc-mode on-demand"))
	config->block_alloc_mode = CGNAT_BLOCK_ALLOC_MODE_ON_DEMAND;
      else if (unformat (input, "block-alloc-mode pre-alloc"))
	config->block_alloc_mode = CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC;
      else if (unformat (input, "port-alloc-mode random"))
	config->port_alloc_mode = CGNAT_PORT_ALLOC_MODE_RANDOM;
      else if (unformat (input, "port-alloc-mode sequence"))
	config->port_alloc_mode = CGNAT_PORT_ALLOC_MODE_SEQUENCE;
      else if (unformat (input, "reserved-port %u %u", &reserved_start,
			 &reserved_end))
	{
	  if (reserved_start > CLIB_U16_MAX || reserved_end > CLIB_U16_MAX)
	    return clib_error_return (0, "reserved-port exceeds 65535");
	  config->reserved_port_start = reserved_start;
	  config->reserved_port_end = reserved_end;
	}
      else if (unformat (input, "prealloc-blocks-per-user %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0,
				      "prealloc-blocks-per-user exceeds 65535");
	  config->prealloc_blocks_per_user = value;
	}
      else if (unformat (input, "cooling-time %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "cooling-time exceeds 65535");
	  config->cooling_time = value;
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (*pool_id == CGNAT_INVALID_INDEX || !first_set || !last_set)
    {
      vec_free (label);
      return clib_error_return (0, "expected pool-id, start-ip and end-ip");
    }
  if (label)
    {
      vec_terminate_c_string (label);
      clib_memcpy (config->label, label,
		   clib_min (vec_len (label) + 1, sizeof (config->label)));
      vec_free (label);
    }
  return 0;
}

static clib_error_t *
cgnat_add_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  cgnat_pool_config_t config;
  u32 pool_id = CGNAT_INVALID_INDEX;
  clib_error_t *error;
  int rv;

  cgnat_pool_config_defaults (&config);
  error = cgnat_parse_pool_config (input, &pool_id, &config, 1);
  if (error)
    return error;
  rv = cgnat_pool_add_del (&pool_id, &config, 1);
  return rv ? clib_error_return (0, "cgnat add pool returned %d", rv) : 0;
}

static clib_error_t *
cgnat_del_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  u32 pool_id = CGNAT_INVALID_INDEX;
  int rv;

  if (!unformat (input, "%u", &pool_id) ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected pool-id");
  rv = cgnat_pool_add_del (&pool_id, 0, 0);
  return rv ? clib_error_return (0, "cgnat del pool returned %d", rv) : 0;
}

static clib_error_t *
cgnat_set_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  u32 pool_id = CGNAT_INVALID_INDEX;
  u32 value, cooling_time = CGNAT_INVALID_INDEX;
  u8 *label = 0;
  int rv;

  if (!unformat (input, "%u", &pool_id))
    return clib_error_return (0, "expected pool-id");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "cooling-time %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "cooling-time exceeds 65535");
	  cooling_time = value;
	}
      else if (unformat (input, "label %s", &label))
	;
      else
	{
	  vec_free (label);
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  if (cooling_time == CGNAT_INVALID_INDEX && !label)
    {
      vec_free (label);
      return clib_error_return (0, "expected cooling-time or label");
    }
  if (cooling_time != CGNAT_INVALID_INDEX)
    {
      rv = cgnat_pool_set_cooling_time (pool_id, cooling_time);
      if (rv)
	{
	  vec_free (label);
	  return clib_error_return (0, "cgnat set pool returned %d", rv);
	}
    }
  if (label)
    {
      vec_terminate_c_string (label);
      rv = cgnat_pool_set_label (pool_id, label);
      vec_free (label);
      if (rv)
	return clib_error_return (0, "cgnat set pool returned %d", rv);
    }
  return 0;
}

static cgnat_pool_t *
cgnat_pool_find_by_label (cgnat_main_t *cm, u8 *label)
{
  cgnat_pool_t *pool;
  vec_foreach (pool, cm->pools)
    if (pool->configured && !strncmp ((char *) pool->label, (char *) label,
				      sizeof (pool->label)))
      return pool;
  return 0;
}

static cgnat_pool_t *
cgnat_pool_find_by_name_or_id (cgnat_main_t *cm, u8 *name)
{
  u32 pool_id;
  u32 pool_index;

  if (sscanf ((char *) name, "%u", &pool_id) == 1)
    {
      if (!cgnat_pool_index_from_id (pool_id, &pool_index))
	return vec_elt_at_index (cm->pools, pool_index);
    }
  return cgnat_pool_find_by_label (cm, name);
}

static cgnat_instance_t *
cgnat_instance_find_by_label (cgnat_main_t *cm, u8 *label)
{
  cgnat_instance_t *instance;
  vec_foreach (instance, cm->instances)
    if (instance->configured && !strncmp ((char *) instance->label,
					  (char *) label,
					  sizeof (instance->label)))
      return instance;
  return 0;
}

static cgnat_instance_t *
cgnat_instance_find_by_name_or_id (cgnat_main_t *cm, u8 *name)
{
  u32 instance_id;
  u32 instance_index;

  if (sscanf ((char *) name, "%u", &instance_id) == 1)
    {
      if (!cgnat_instance_index_from_id (instance_id, &instance_index))
	return cgnat_instance_get_by_index (cm, instance_index);
    }
  return cgnat_instance_find_by_label (cm, name);
}

static clib_error_t *
cgnat_instance_command (vlib_main_t *vm, unformat_input_t *input, u8 is_add)
{
  u32 instance_id = CGNAT_INVALID_INDEX;
  u32 inside_vrf = CGNAT_INVALID_INDEX, outside_vrf = 0;
  u32 *pool_ids = 0, value;
  cgnat_inside_address_t *inside_addresses = 0, address;
  u8 *label = 0;
  u8 mode = CGNAT_INSTANCE_MODE_DYNAMIC;
  int rv;

  if (is_add)
    /* instance-id is optional on add: omitted means auto-assign. */
    unformat (input, "%u", &instance_id);
  else if (!unformat (input, "%u", &instance_id))
    return clib_error_return (0, "expected instance-id");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (is_add && unformat (input, "inside-vrf %u", &inside_vrf))
	;
      else if (is_add && unformat (input, "inside-vrf any"))
	inside_vrf = CGNAT_INVALID_INDEX;
      else if (is_add && unformat (input, "outside-vrf %u", &outside_vrf))
	;
      else if (is_add && unformat (input, "mode dynamic"))
	mode = CGNAT_INSTANCE_MODE_DYNAMIC;
      else if (is_add && unformat (input, "mode deterministic"))
	mode = CGNAT_INSTANCE_MODE_DETERMINISTIC;
      else if (is_add && unformat (input, "pool %u", &value))
	vec_add1 (pool_ids, value);
      else if (is_add &&
	       unformat (input, "inside-address range %U %U",
			 unformat_ip4_address, &address.first_ip,
			 unformat_ip4_address, &address.last_ip))
	{
	  address.type = CGNAT_INSIDE_ADDRESS_RANGE;
	  address.prefix_len = 0xff;
	  vec_add1 (inside_addresses, address);
	}
      else if (is_add &&
	       unformat (input, "inside-address prefix %U/%u",
			 unformat_ip4_address, &address.first_ip, &value))
	{
	  address.type = CGNAT_INSIDE_ADDRESS_PREFIX;
	  address.last_ip.as_u32 = 0;
	  address.prefix_len = value;
	  vec_add1 (inside_addresses, address);
	}
      else if (is_add && unformat (input, "label %s", &label))
	;
      else
	{
	  vec_free (pool_ids);
	  vec_free (inside_addresses);
	  vec_free (label);
	  return clib_error_return (0, "unknown input '%U'",
				    format_unformat_error, input);
	}
    }
  if (label)
    vec_terminate_c_string (label);
  rv = cgnat_instance_add_del (&instance_id, label, inside_vrf, outside_vrf,
			       mode, pool_ids, vec_len (pool_ids),
			       inside_addresses, vec_len (inside_addresses),
			       is_add);
  vec_free (pool_ids);
  vec_free (inside_addresses);
  vec_free (label);
  if (rv)
    return clib_error_return (0, "cgnat instance returned %d", rv);
  if (is_add)
    vlib_cli_output (vm, "instance-id %u", instance_id);
  return 0;
}

static clib_error_t *
cgnat_add_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  return cgnat_instance_command (vm, input, 1);
}

static clib_error_t *
cgnat_del_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  return cgnat_instance_command (vm, input, 0);
}

static clib_error_t *
cgnat_set_instance_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  cgnat_instance_config_t config = { 0 };
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u32 instance_id, instance_index, value, acl_index = CGNAT_INVALID_INDEX;
  ip4_address_t syslog_address = { 0 }, collector_address = { 0 };
  ip4_address_t exporter_src_address = { 0 };
  u32 syslog_port = 0, collector_port = 0, exporter_src_port = 0;
  i8 acl_op = 0, syslog_op = 0, ipfix_op = 0;
  u8 acl_clear = 0;
  int rv;

  if (!unformat (input, "%u", &instance_id))
    return clib_error_return (0, "expected instance-id");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
#define CGNAT_PARSE_U32(name, flag, field)                                   \
      if (unformat (input, name " %u", &config.field))                     \
	config.flags |= flag
      CGNAT_PARSE_U32 ("max-user-sessions",
			    CGNAT_INSTANCE_SET_MAX_USER_SESSIONS,
			    max_user_sessions);
      else CGNAT_PARSE_U32 ("max-user-create-sessions-rate",
			    CGNAT_INSTANCE_SET_MAX_USER_CREATE_RATE,
			    max_user_create_sessions_rate);
      else CGNAT_PARSE_U32 ("aging-tcp-syn",
			    CGNAT_INSTANCE_SET_AGING_TCP_SYN, aging_tcp_syn);
      else CGNAT_PARSE_U32 ("aging-tcp-established",
			    CGNAT_INSTANCE_SET_AGING_TCP_ESTABLISHED,
			    aging_tcp_established);
      else CGNAT_PARSE_U32 ("aging-tcp-fin-rst",
			    CGNAT_INSTANCE_SET_AGING_TCP_FIN_RST,
			    aging_tcp_fin_rst);
      else CGNAT_PARSE_U32 ("aging-udp", CGNAT_INSTANCE_SET_AGING_UDP,
			    aging_udp);
      else CGNAT_PARSE_U32 ("aging-icmp", CGNAT_INSTANCE_SET_AGING_ICMP,
			    aging_icmp);
      else CGNAT_PARSE_U32 ("aging-other", CGNAT_INSTANCE_SET_AGING_OTHER,
			    aging_other);
#undef CGNAT_PARSE_U32
      else if (unformat (input, "max-user-blocks %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "max-user-blocks exceeds 65535");
	  config.max_user_blocks = value;
	  config.flags |= CGNAT_INSTANCE_SET_MAX_USER_BLOCKS;
	}
      else if (unformat (input, "max-user-ports %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "max-user-ports exceeds 65535");
	  config.max_user_ports = value;
	  config.flags |= CGNAT_INSTANCE_SET_MAX_USER_PORTS;
	}
      else if (unformat (input, "filtering-mode eif"))
	config.filter_mode = CGNAT_FILTER_MODE_EIF,
	config.flags |= CGNAT_INSTANCE_SET_FILTER_MODE;
      else if (unformat (input, "filtering-mode adf"))
	config.filter_mode = CGNAT_FILTER_MODE_ADF,
	config.flags |= CGNAT_INSTANCE_SET_FILTER_MODE;
      else if (unformat (input, "filtering-mode adpf"))
	config.filter_mode = CGNAT_FILTER_MODE_ADPF,
	config.flags |= CGNAT_INSTANCE_SET_FILTER_MODE;
      else if (unformat (input, "hairpinning enable"))
	config.hairpinning_enabled = 1,
	config.flags |= CGNAT_INSTANCE_SET_HAIRPINNING;
      else if (unformat (input, "hairpinning disable"))
	config.hairpinning_enabled = 0,
	config.flags |= CGNAT_INSTANCE_SET_HAIRPINNING;
      else if (unformat (input, "log-mode port-block"))
	config.log_mode = CGNAT_LOG_MODE_PORT_BLOCK,
	config.flags |= CGNAT_INSTANCE_SET_LOG_MODE;
      else if (unformat (input, "log-mode session"))
	config.log_mode = CGNAT_LOG_MODE_SESSION,
	config.flags |= CGNAT_INSTANCE_SET_LOG_MODE;
      else if (unformat (input, "syslog enable"))
	config.syslog_enabled = 1, config.flags |= CGNAT_INSTANCE_SET_SYSLOG;
      else if (unformat (input, "syslog disable"))
	config.syslog_enabled = 0, config.flags |= CGNAT_INSTANCE_SET_SYSLOG;
      else if (unformat (input, "ipfix enable"))
	config.ipfix_enabled = 1, config.flags |= CGNAT_INSTANCE_SET_IPFIX;
      else if (unformat (input, "ipfix disable"))
	config.ipfix_enabled = 0, config.flags |= CGNAT_INSTANCE_SET_IPFIX;
      else if (unformat (input, "tcp-mss disable"))
	{
	  config.tcp_mss = 0;
	  config.flags |= CGNAT_INSTANCE_SET_TCP_MSS;
	}
      else if (unformat (input, "tcp-mss %u", &value))
	{
	  if (value > CLIB_U16_MAX)
	    return clib_error_return (0, "tcp-mss exceeds 65535");
	  config.tcp_mss = value;
	  config.flags |= CGNAT_INSTANCE_SET_TCP_MSS;
	}
      else if (unformat (input, "acl-index none"))
	acl_clear = 1;
      else if (unformat (input, "acl-index del %u", &acl_index))
	acl_op = -1;
      else if (unformat (input, "acl-index %u", &acl_index))
	acl_op = 1;
      else if (unformat (input, "syslog server del %U %u",
			 unformat_ip4_address, &syslog_address, &syslog_port))
	syslog_op = -1;
      else if (unformat (input, "syslog server %U %u",
			 unformat_ip4_address, &syslog_address, &syslog_port))
	syslog_op = 1;
      else if (unformat (input, "ipfix collector del %U %u src %U %u",
			 unformat_ip4_address, &collector_address,
			 &collector_port, unformat_ip4_address,
			 &exporter_src_address, &exporter_src_port))
	ipfix_op = -1;
      else if (unformat (input, "ipfix collector %U %u src %U %u",
			 unformat_ip4_address, &collector_address,
			 &collector_port, unformat_ip4_address,
			 &exporter_src_address, &exporter_src_port))
	ipfix_op = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  rv = config.flags ? cgnat_instance_set (instance_id, &config) : 0;
  if (rv)
    return clib_error_return (0, "cgnat set instance returned %d", rv);
  if (!acl_op && !acl_clear && !syslog_op && !ipfix_op)
    return 0;
  if (cgnat_instance_index_from_id (instance_id, &instance_index))
    return clib_error_return (0, "instance does not exist");
  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (acl_clear)
    {
	while (vec_len (instance->acl_indices))
	  {
	    rv = cgnat_instance_set_acl (
	      instance_index,
	      instance->acl_indices[vec_len (instance->acl_indices) - 1], 0);
	    if (rv)
	      return clib_error_return (0, "clear ACL returned %d", rv);
	  }
    }
  if (acl_op)
    {
      rv = cgnat_instance_set_acl (instance_index, acl_index, acl_op > 0);
      if (rv)
	return clib_error_return (0, "cgnat set instance returned %d", rv);
    }
  if (syslog_op)
    {
      if (syslog_port > CLIB_U16_MAX)
	return clib_error_return (0, "invalid syslog port");
      rv = cgnat_instance_syslog_server_add_del (
	instance_index, syslog_address, syslog_port, syslog_op > 0);
      if (rv)
	return clib_error_return (0, "cgnat set instance returned %d", rv);
    }
  if (ipfix_op)
    {
      if (collector_port > CLIB_U16_MAX ||
	  exporter_src_port > CLIB_U16_MAX)
	return clib_error_return (0, "invalid IPFIX port");
      rv = cgnat_instance_ipfix_exporter_add_del (
	instance_index, collector_address, collector_port,
	exporter_src_address, exporter_src_port, ipfix_op > 0);
      if (rv)
	return clib_error_return (0, "cgnat set instance returned %d", rv);
    }
  return 0;
}

static clib_error_t *
cgnat_set_interface_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 sw_if_index = CGNAT_INVALID_INDEX;
  u8 role_set = 0;
  cgnat_interface_role_t role = CGNAT_INTERFACE_ROLE_NONE;
  int rv;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, cm->vnet_main,
		 &sw_if_index))
    return clib_error_return (0, "expected interface");
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "inside"))
	role_set = 1, role = CGNAT_INTERFACE_ROLE_INSIDE;
      else if (unformat (input, "outside"))
	role_set = 1, role = CGNAT_INTERFACE_ROLE_OUTSIDE;
      else if (unformat (input, "none"))
	role_set = 1, role = CGNAT_INTERFACE_ROLE_NONE;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (!role_set)
    return clib_error_return (0, "expected role");
  rv = cgnat_interface_zone_set (sw_if_index, role);
  return rv ? clib_error_return (0, "cgnat interface returned %d", rv) : 0;
}

static u8
cgnat_unformat_static_protocol (unformat_input_t *input, u8 *protocol)
{
  if (unformat (input, "tcp"))
    *protocol = IP_PROTOCOL_TCP;
  else if (unformat (input, "udp"))
    *protocol = IP_PROTOCOL_UDP;
  else if (unformat (input, "icmp"))
    *protocol = IP_PROTOCOL_ICMP;
  else if (unformat (input, "all"))
    *protocol = CGNAT_STATIC_PROTO_ALL;
  else
    return 0;
  return 1;
}

static clib_error_t *
cgnat_static_mapping_command (unformat_input_t *input, u8 is_add)
{
  u32 instance_id = CGNAT_INVALID_INDEX, instance_index;
  u32 outside_port = CGNAT_INVALID_INDEX, inside_port = CGNAT_INVALID_INDEX;
  u32 inside_vrf = 0;
  ip4_address_t outside_ip = { 0 }, inside_ip = { 0 };
  u8 outside_set = 0, inside_set = 0, protocol_set = 0;
  u8 protocol = CGNAT_STATIC_PROTO_ALL;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "instance %u", &instance_id))
	;
      else if (unformat (input, "outside %U %u", unformat_ip4_address,
			 &outside_ip, &outside_port))
	outside_set = 1;
      else if (unformat (input, "outside %U", unformat_ip4_address,
			 &outside_ip))
	outside_set = 1;
      else if (unformat (input, "inside %U %u", unformat_ip4_address,
			 &inside_ip, &inside_port))
	inside_set = 1;
      else if (unformat (input, "inside %U", unformat_ip4_address,
			 &inside_ip))
	inside_set = 1;
      else if (unformat (input, "inside-vrf %u", &inside_vrf))
	;
      else if (unformat (input, "protocol"))
	protocol_set = cgnat_unformat_static_protocol (input, &protocol);
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }
  if (instance_id == CGNAT_INVALID_INDEX || !outside_set || !inside_set ||
      cgnat_instance_index_from_id (instance_id, &instance_index))
    return clib_error_return (0, "expected valid instance, outside and inside");
  if (outside_port != CGNAT_INVALID_INDEX)
    {
	if (outside_port > CLIB_U16_MAX ||
	    (inside_port != CGNAT_INVALID_INDEX && inside_port > CLIB_U16_MAX))
	  return clib_error_return (0, "static mapping port exceeds 65535");
      if (!protocol_set)
	return clib_error_return (0, "port mapping requires a protocol");
      if (inside_port == CGNAT_INVALID_INDEX)
	inside_port = outside_port;

      if (protocol == CGNAT_STATIC_PROTO_ALL)
	{
	  /* Expand port-level protocol-all into three concrete protocol rules. */
	  u8 protos[] = { IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, IP_PROTOCOL_ICMP };
	  int errs[3] = { 0, 0, 0 };
	  u32 i;

	  for (i = 0; i < 3; i++)
	    {
	      rv = cgnat_static_mapping_add_del (
		instance_index, outside_ip, (u16) outside_port, inside_ip,
		(u16) inside_port, protos[i], CGNAT_STATIC_PORT_MAP, inside_vrf,
		is_add);
	      errs[i] = rv;
	      if (rv && is_add)
		break;
	    }

	  if (is_add && rv)
	    {
	      u32 j;
	      for (j = 0; j < i; j++)
		if (!errs[j])
		  cgnat_static_mapping_add_del (
		    instance_index, outside_ip, (u16) outside_port, inside_ip,
		    (u16) inside_port, protos[j], CGNAT_STATIC_PORT_MAP,
		    inside_vrf, 0);
	      return clib_error_return (0, "cgnat static-mapping returned %d", rv);
	    }

	  /* Delete: best-effort remove all three protocol entries. */
	  if (!is_add)
	    return 0;

	  return 0;
	}

      rv = cgnat_static_mapping_add_del (
	instance_index, outside_ip, outside_port, inside_ip, inside_port,
	protocol, CGNAT_STATIC_PORT_MAP, inside_vrf, is_add);
    }
  else
    {
      u8 mapping_type;

      if (inside_port != CGNAT_INVALID_INDEX)
	return clib_error_return (0, "inside port requires outside port");
      if (protocol_set && protocol != CGNAT_STATIC_PROTO_ALL)
	mapping_type = CGNAT_STATIC_ADDR_PROTO_MAP;
      else
	{
	  mapping_type = CGNAT_STATIC_ADDR_MAP;
	  protocol = CGNAT_STATIC_PROTO_ALL;
	}
      rv = cgnat_static_mapping_add_del (
	instance_index, outside_ip, 0, inside_ip, 0, protocol, mapping_type,
	inside_vrf, is_add);
    }
  return rv ? clib_error_return (0, "cgnat static-mapping returned %d", rv) : 0;
}

static clib_error_t *
cgnat_add_static_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  return cgnat_static_mapping_command (input, 1);
}

static clib_error_t *
cgnat_del_static_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  return cgnat_static_mapping_command (input, 0);
}

static int
cgnat_unformat_session_protocol (unformat_input_t *input, u8 *protocol,
				 u8 *is_all)
{
  *is_all = 0;
  if (unformat (input, "tcp"))
    *protocol = IP_PROTOCOL_TCP;
  else if (unformat (input, "udp"))
    *protocol = IP_PROTOCOL_UDP;
  else if (unformat (input, "icmp"))
    *protocol = IP_PROTOCOL_ICMP;
  else if (unformat (input, "all"))
    *is_all = 1;
  else
    return 0;
  return 1;
}

static void
cgnat_show_session_flows (vlib_main_t *vm, cgnat_session_filter_t *filter)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_session_t *sessions = cgnat_session_snapshot (filter), *session;
  f64 now = vlib_time_now (vm);

  vec_foreach (session, sessions)
    {
      cgnat_instance_t *instance =
	cgnat_instance_get_by_index (cm, session->instance_index);
      vlib_cli_output (
	vm, "instance %u protocol %u inside %U:%u public %U:%u remote %U:%u "
	    "state %u type %s idle %.3fs",
	instance ? instance->instance_id : CGNAT_INVALID_INDEX, session->protocol,
	format_ip4_address, &session->inside_ip, session->inside_port,
	format_ip4_address, &session->nat_ip, session->nat_port, format_ip4_address,
	&session->remote_ip, session->remote_port, session->tcp_state,
	session->mapping_type == CGNAT_MAPPING_STATIC ? "static" : "dynamic",
	clib_max (now - session->last_active, 0.0));
    }
  vlib_cli_output (vm, "total sessions: %u", vec_len (sessions));
  vec_free (sessions);
}

static clib_error_t *
cgnat_show_session_all_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cgnat_show_session_flows (vm, 0);
  return 0;
}

static clib_error_t *
cgnat_show_session_user_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  cgnat_session_filter_t filter = {
    .flags = CGNAT_SESSION_FILTER_INSIDE_IP,
  };

  if (!unformat (input, "%U", unformat_ip4_address, &filter.inside_ip))
    return clib_error_return (0, "expected inside IPv4 address");
  cgnat_show_session_flows (vm, &filter);
  return 0;
}

static clib_error_t *
cgnat_show_user_stats (vlib_main_t *vm, unformat_input_t *input, u8 rate_only)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_user_t *user;
  ip4_address_t inside_ip;
  f64 now = vlib_time_now (vm);
  u32 matches = 0;

  if (!unformat (input, "%U", unformat_ip4_address, &inside_ip))
    return clib_error_return (0, "expected inside IPv4 address");
  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      pool_foreach (user, instance->users)
	if (user->key.private_ip.as_u32 == inside_ip.as_u32)
	  {
	    u32 rate = now - user->session_rate_window_start < 1.0 ?
			 user->session_rate_count :
			 0;
	    matches++;
	    if (rate_only)
	      vlib_cli_output (
		vm, "instance %u user %U create-rate %u limit %u rate-drops %u "
		    "lock-drops %u port-block-drops %u",
		instance->instance_id, format_ip4_address, &inside_ip, rate,
		instance->max_session_create_rate, user->session_rate_drops,
		user->session_lock_drops, user->port_block_drops);
	    else
	      vlib_cli_output (
		vm, "instance %u user %U sessions %u/%u ports tcp %u udp %u icmp %u "
	    "blocks %u create-rate %u/%u limit-drops %u rate-drops %u lock-drops %u "
	    "port-block-drops %u",
		instance->instance_id, format_ip4_address, &inside_ip,
		user->active_sessions, instance->max_sessions_per_user,
		user->active_ports[CGNAT_PBA_PROTO_TCP],
		user->active_ports[CGNAT_PBA_PROTO_UDP],
		user->active_ports[CGNAT_PBA_PROTO_ICMP],
		vec_len (user->owned_block_ids), rate,
		instance->max_session_create_rate, user->session_limit_drops,
		user->session_rate_drops, user->session_lock_drops,
		user->port_block_drops);
	  }
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
  if (!matches)
    vlib_cli_output (vm, "user %U not found", format_ip4_address,
		     &inside_ip);
  return 0;
}

static clib_error_t *
cgnat_show_session_summary_command_fn (vlib_main_t *vm,
				       unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  return cgnat_show_user_stats (vm, input, 0);
}

static clib_error_t *
cgnat_del_session_user_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cgnat_session_filter_t filter = {
    .flags = CGNAT_SESSION_FILTER_INSIDE_IP,
  };
  u8 protocol, is_all;

  if (!unformat (input, "%U", unformat_ip4_address, &filter.inside_ip))
    return clib_error_return (0, "expected inside IPv4 address");
  if (unformat (input, "protocol"))
    {
      if (!cgnat_unformat_session_protocol (input, &protocol, &is_all))
	return clib_error_return (0, "expected tcp, udp, icmp or all");
      if (!is_all)
	filter.flags |= CGNAT_SESSION_FILTER_PROTOCOL,
	filter.protocol = protocol;
    }
  vlib_cli_output (vm, "deleted sessions: %u",
		   cgnat_session_delete_matching (&filter));
  return 0;
}

static clib_error_t *
cgnat_del_session_public_command_fn (vlib_main_t *vm,
				     unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  cgnat_session_filter_t filter = {
    .flags = CGNAT_SESSION_FILTER_PUBLIC_IP,
  };

  if (!unformat (input, "%U", unformat_ip4_address, &filter.public_ip))
    return clib_error_return (0, "expected public IPv4 address");
  vlib_cli_output (vm, "deleted sessions: %u",
		   cgnat_session_delete_matching (&filter));
  return 0;
}

static clib_error_t *
cgnat_del_session_exact_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  cgnat_session_filter_t filter = {
    .flags = CGNAT_SESSION_FILTER_INSIDE_IP |
	     CGNAT_SESSION_FILTER_INSIDE_PORT |
	     CGNAT_SESSION_FILTER_PUBLIC_IP |
	     CGNAT_SESSION_FILTER_PUBLIC_PORT,
  };
  u32 inside_port, public_port;
  u8 protocol, is_all;

  if (!unformat (input, "%U port %u outside %U port %u protocol",
		 unformat_ip4_address, &filter.inside_ip, &inside_port,
		 unformat_ip4_address, &filter.public_ip, &public_port) ||
      !cgnat_unformat_session_protocol (input, &protocol, &is_all))
    return clib_error_return (
      0, "expected <inside-ip> port <port> outside <public-ip> port <port> "
	 "protocol <tcp|udp|icmp|all>");
  if (inside_port > CLIB_U16_MAX || public_port > CLIB_U16_MAX)
    return clib_error_return (0, "port exceeds 65535");
  filter.inside_port = inside_port;
  filter.public_port = public_port;
  if (!is_all)
    filter.flags |= CGNAT_SESSION_FILTER_PROTOCOL, filter.protocol = protocol;
  vlib_cli_output (vm, "deleted sessions: %u",
		   cgnat_session_delete_matching (&filter));
  return 0;
}

static clib_error_t *
cgnat_show_det_o2imap_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  ip4_address_t public_ip;
  u32 instance_id, instance_index;
  u32 public_port;
  ip4_address_t inside_ip;
  int rv;

  if (!unformat (input, "instance %u", &instance_id))
    return clib_error_return (0, "expected instance <id>");
  if (cgnat_instance_index_from_id (instance_id, &instance_index))
    return clib_error_return (0, "instance %u not found", instance_id);

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance || !instance->configured)
    return clib_error_return (0, "instance %u not found", instance_id);
  if (instance->mode != CGNAT_INSTANCE_MODE_DETERMINISTIC)
    return clib_error_return (0, "instance %u is not deterministic",
			      instance_id);

  if (!unformat (input, "%U:%u", unformat_ip4_address, &public_ip,
		 &public_port))
    return clib_error_return (0, "expected <public-ip>:<port>");
  if (public_port > CLIB_U16_MAX)
    return clib_error_return (0, "port exceeds 65535");

  rv = cgnat_det_o2imap (instance, public_ip, (u16) public_port, &inside_ip);
  if (rv)
    return clib_error_return (0, "no deterministic mapping found for %U:%u",
			      format_ip4_address, &public_ip, public_port);

  vlib_cli_output (vm, "%U", format_ip4_address, &inside_ip);
  return 0;
}

static clib_error_t *
cgnat_show_det_i2omap_command_fn (vlib_main_t *vm, unformat_input_t *input,
				  vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_det_runtime_t *det;
  u32 instance_id, instance_index;
  ip4_address_t inside_ip;
  u8 show_all = 0;

  if (!unformat (input, "instance %u", &instance_id))
    return clib_error_return (0, "expected instance <id>");
  if (cgnat_instance_index_from_id (instance_id, &instance_index))
    return clib_error_return (0, "instance %u not found", instance_id);

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance || !instance->configured)
    return clib_error_return (0, "instance %u not found", instance_id);
  if (instance->mode != CGNAT_INSTANCE_MODE_DETERMINISTIC)
    return clib_error_return (0, "instance %u is not deterministic",
			      instance_id);

  if (unformat (input, "all"))
    show_all = 1;
  else if (!unformat (input, "%U", unformat_ip4_address, &inside_ip))
    return clib_error_return (0, "expected <inside-ip> or all");

  det = &instance->det;
  if (show_all)
    {
      u32 i;

      for (i = 0; i < det->inside_count; i++)
	{
	  ip4_address_t public_ip;
	  u16 port_start, port_end;
	  ip4_address_t addr;
	  int rv;

	  addr.as_u32 = clib_host_to_net_u32 (det->inside_first_host + i);
	  rv = cgnat_det_i2omap (instance, addr, &public_ip, &port_start,
				 &port_end);
	  if (rv)
	    continue;

	  vlib_cli_output (vm, "%U -> %U:%u-%u", format_ip4_address, &addr,
			   format_ip4_address, &public_ip, port_start,
			   port_end);
	}
    }
  else
    {
      ip4_address_t public_ip;
      u16 port_start, port_end;
      int rv;

      rv = cgnat_det_i2omap (instance, inside_ip, &public_ip, &port_start,
			     &port_end);
      if (rv)
	return clib_error_return (
	  0, "no deterministic mapping found for %U in instance %u",
	  format_ip4_address, &inside_ip, instance_id);

      vlib_cli_output (vm, "%U:%u-%u", format_ip4_address, &public_ip,
		       port_start, port_end);
    }

  return 0;
}

static clib_error_t *
cgnat_show_det_mappings_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_inside_address_t *addr;
  cgnat_det_runtime_t *det;
  u32 instance_id, instance_index;
  u32 *pool_index;
  ip4_address_t out_first, out_last;
  u8 out_first_set = 0;
  u32 active_sessions;

  if (!unformat (input, "instance %u", &instance_id))
    return clib_error_return (0, "expected instance <id>");
  if (cgnat_instance_index_from_id (instance_id, &instance_index))
    return clib_error_return (0, "instance %u not found", instance_id);

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance || !instance->configured)
    return clib_error_return (0, "instance %u not found", instance_id);
  if (instance->mode != CGNAT_INSTANCE_MODE_DETERMINISTIC)
    return clib_error_return (0, "instance %u is not deterministic",
			      instance_id);

  addr = instance->inside_addresses;
  if (!addr || vec_len (addr) != 1)
    return clib_error_return (0,
			      "instance %u has no deterministic inside address",
			      instance_id);

  det = &instance->det;

  vec_foreach (pool_index, instance->pool_indices)
    {
      cgnat_pool_t *pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (!pool)
	continue;
      if (!out_first_set)
	{
	  out_first = pool->first_ip;
	  out_last = pool->last_ip;
	  out_first_set = 1;
	}
      else
	{
	  if (clib_net_to_host_u32 (pool->first_ip.as_u32) <
	      clib_net_to_host_u32 (out_first.as_u32))
	    out_first = pool->first_ip;
	  if (clib_net_to_host_u32 (pool->last_ip.as_u32) >
	      clib_net_to_host_u32 (out_last.as_u32))
	    out_last = pool->last_ip;
	}
    }

  if (!out_first_set)
    return clib_error_return (0, "instance %u has no pool", instance_id);

  if (addr->type == CGNAT_INSIDE_ADDRESS_PREFIX)
    vlib_cli_output (vm, "in %U/%u out %U-%U",
		     format_ip4_address, &addr->first_ip, addr->prefix_len,
		     format_ip4_address, &out_first,
		     format_ip4_address, &out_last);
  else
    vlib_cli_output (vm, "in %U-%U out %U-%U",
		     format_ip4_address, &addr->first_ip,
		     format_ip4_address, &addr->last_ip,
		     format_ip4_address, &out_first,
		     format_ip4_address, &out_last);

  vlib_cli_output (vm, "    outside address sharing ratio: %u",
		   det->sharing_ratio);
  vlib_cli_output (vm, "    number of ports per inside host: %u",
		   det->ports_per_host);
  active_sessions = clib_atomic_load_relax_n (&instance->active_sessions);
  vlib_cli_output (vm, "    sessions number: %u", active_sessions);

  return 0;
}

static void
cgnat_show_interfaces (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_interface_t *interface;

  pool_foreach (interface, cm->interfaces)
    {
      vlib_cli_output (vm, " interface %U %s%s",
		       format_vnet_sw_if_index_name, cm->vnet_main,
		       interface->sw_if_index,
		       cgnat_interface_is_inside (interface) ? "inside" : "",
		       cgnat_interface_is_outside (interface) ? " outside" : "");
    }
}

static const char *
cgnat_protocol_str (u8 protocol)
{
  if (protocol == IP_PROTOCOL_TCP)
    return "tcp";
  if (protocol == IP_PROTOCOL_UDP)
    return "udp";
  if (protocol == IP_PROTOCOL_ICMP)
    return "icmp";
  if (protocol == CGNAT_STATIC_PROTO_ALL)
    return "all";
  return "other";
}

static void
cgnat_show_instance_config_one (vlib_main_t *vm, cgnat_instance_t *instance)
{
  cgnat_main_t *cm = &cgnat_main;
  fib_table_t *inside_fib, *outside_fib;
  cgnat_inside_address_t *address;
  cgnat_syslog_server_t *server;
  cgnat_ipfix_exporter_t *exporter;
  cgnat_static_rule_t *rule;
  cgnat_pool_t *pool;
  u32 *acl_index, *pool_index;

  inside_fib =
    instance->inside_fib_index == CGNAT_INVALID_INDEX ?
      0 :
      fib_table_get (instance->inside_fib_index, FIB_PROTOCOL_IP4);
  outside_fib = fib_table_get (instance->outside_fib_index,
			       FIB_PROTOCOL_IP4);
  if (inside_fib)
    vlib_cli_output (
      vm, "Instance %u label %s mode %s inside-vrf %u outside-vrf %u filter %u "
	  "hairpin %s log %s syslog %s ipfix %s tcp-mss %u",
      instance->instance_id,
      instance->label[0] ? (char *) instance->label : "-",
      instance->mode == CGNAT_INSTANCE_MODE_DETERMINISTIC ?
	"deterministic" :
	"dynamic",
      inside_fib->ft_table_id,
      outside_fib->ft_table_id, instance->filter_mode,
      instance->hairpinning_enabled ? "enable" : "disable",
      instance->log_mode == CGNAT_LOG_MODE_SESSION ? "session" :
							     "port-block",
      instance->syslog_enabled ? "enable" : "disable",
      instance->ipfix_enabled ? "enable" : "disable",
      instance->tcp_mss);
  else
    vlib_cli_output (
      vm, "Instance %u label %s mode %s inside-vrf any outside-vrf %u filter %u "
	  "hairpin %s log %s syslog %s ipfix %s tcp-mss %u",
      instance->instance_id,
      instance->label[0] ? (char *) instance->label : "-",
      instance->mode == CGNAT_INSTANCE_MODE_DETERMINISTIC ?
	"deterministic" :
	"dynamic",
      outside_fib->ft_table_id,
      instance->filter_mode,
      instance->hairpinning_enabled ? "enable" : "disable",
      instance->log_mode == CGNAT_LOG_MODE_SESSION ? "session" :
							     "port-block",
      instance->syslog_enabled ? "enable" : "disable",
      instance->ipfix_enabled ? "enable" : "disable",
      instance->tcp_mss);
  vlib_cli_output (
    vm, " limits blocks %u ports %u sessions %u create-rate %u",
    instance->per_user_max_blocks, instance->per_user_max_ports,
    instance->max_sessions_per_user, instance->max_session_create_rate);
  vec_foreach (address, instance->inside_addresses)
    {
      if (address->type == CGNAT_INSIDE_ADDRESS_PREFIX)
	vlib_cli_output (vm, " inside-address prefix %U/%u",
			 format_ip4_address, &address->first_ip,
			 address->prefix_len);
      else
	vlib_cli_output (vm, " inside-address range %U %U",
			 format_ip4_address, &address->first_ip,
			 format_ip4_address, &address->last_ip);
    }
  vlib_cli_output (
    vm, " aging syn %u established %u fin-rst %u udp %u icmp %u other %u",
    instance->tcp_syn_timeout, instance->tcp_established_timeout,
    instance->tcp_fin_rst_timeout, instance->udp_timeout,
    instance->icmp_timeout, instance->other_timeout);
  vec_foreach (acl_index, instance->acl_indices)
    vlib_cli_output (vm, " acl-index %u", *acl_index);
  vec_foreach (pool_index, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (pool)
	vlib_cli_output (vm, " pool %u%s%s", pool->pool_id,
			 pool->label[0] ? " label " : "",
			 pool->label[0] ? (char *) pool->label : "");
    }
  pool_foreach (rule, instance->static_rules)
    {
      if (rule->type == CGNAT_STATIC_ADDR_MAP)
	vlib_cli_output (vm, " static-mapping outside %U inside %U protocol all",
			 format_ip4_address, &rule->outside_ip,
			 format_ip4_address, &rule->inside_ip);
      else if (rule->type == CGNAT_STATIC_ADDR_PROTO_MAP)
	vlib_cli_output (vm,
			 " static-mapping outside %U inside %U protocol %s",
			 format_ip4_address, &rule->outside_ip,
			 format_ip4_address, &rule->inside_ip,
			 cgnat_protocol_str (rule->protocol));
      else
	vlib_cli_output (
	  vm,
	  " static-mapping outside %U port %u inside %U port %u protocol %s",
	  format_ip4_address, &rule->outside_ip, rule->outside_port,
	  format_ip4_address, &rule->inside_ip, rule->inside_port,
	  cgnat_protocol_str (rule->protocol));
    }
  vec_foreach (server, instance->syslog_servers)
    vlib_cli_output (vm, " syslog server %U %u", format_ip4_address,
		     &server->address, server->port);
  vec_foreach (exporter, instance->ipfix_exporters)
    vlib_cli_output (
      vm, " ipfix collector %U %u src %U %u", format_ip4_address,
      &exporter->collector_address, exporter->collector_port,
      format_ip4_address, &exporter->src_address, exporter->src_port);
}

static clib_error_t *
cgnat_show_instance_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u8 *name = 0;
  u8 show_all = 0;

  if (unformat (input, "all"))
    show_all = 1;
  else
    {
      unformat (input, "instance");
      if (!unformat (input, "%s", &name))
	return clib_error_return (0, "expected all or instance name");
    }

  if (show_all)
    {
      vec_foreach (instance, cm->instances)
	{
	  if (!instance->configured)
	    continue;
	  cgnat_show_instance_config_one (vm, instance);
	}
      cgnat_show_interfaces (vm);
    }
  else
    {
      vec_terminate_c_string (name);
      instance = cgnat_instance_find_by_name_or_id (cm, name);
      if (!instance)
	{
	  clib_error_t *error =
	    clib_error_return (0, "instance %s not found", name);
	  vec_free (name);
	  return error;
	}
      cgnat_show_instance_config_one (vm, instance);
      cgnat_show_interfaces (vm);
      vec_free (name);
    }
  return 0;
}

static void
cgnat_show_instance_stat_one (vlib_main_t *vm, cgnat_instance_t *instance)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u32 *pool_index;
  u32 current_user;
  u32 current_session;
  u32 max_block = 0;
  u32 used_block = 0;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  cgnat_recalculate_instance (cm, instance);
  current_user = clib_atomic_load_relax_n (&instance->active_users);
  current_session = clib_atomic_load_relax_n (&instance->active_sessions);
  vec_foreach (pool_index, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (pool)
	{
	  max_block += pool->total_blocks;
	  used_block += pool->allocated_blocks;
	}
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);

  vlib_cli_output (vm, "Instance %s:",
		   instance->label[0] ? (char *) instance->label : "-");
  vlib_cli_output (vm, "    current-user : %u", current_user);
  vlib_cli_output (vm, "    current-session : %u", current_session);
  vlib_cli_output (vm, "    max-block-num : %u", max_block);
  vlib_cli_output (vm, "    used-block-num : %u", used_block);
  vlib_cli_output (vm, "    avail-block-num : %u", max_block - used_block);
}

static clib_error_t *
cgnat_show_instance_stat_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u8 *name = 0;
  u8 show_all = 0;

  if (unformat (input, "all"))
    show_all = 1;
  else
    {
      unformat (input, "instance");
      if (!unformat (input, "%s", &name))
	return clib_error_return (0, "expected all or instance name");
    }

  if (show_all)
    {
      vec_foreach (instance, cm->instances)
	{
	  if (!instance->configured)
	    continue;
	  cgnat_show_instance_stat_one (vm, instance);
	}
    }
  else
    {
      vec_terminate_c_string (name);
      instance = cgnat_instance_find_by_name_or_id (cm, name);
      if (!instance)
	{
	  clib_error_t *error =
	    clib_error_return (0, "instance %s not found", name);
	  vec_free (name);
	  return error;
	}
      cgnat_show_instance_stat_one (vm, instance);
      vec_free (name);
    }
  return 0;
}

static void
cgnat_show_pool_config_one (vlib_main_t *vm, cgnat_pool_t *pool)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *owner = 0;

  if (pool->owner_instance_index != CGNAT_INVALID_INDEX)
    owner = cgnat_instance_get_by_index (cm, pool->owner_instance_index);

  vlib_cli_output (vm, "Addresses Pool %s:",
		   pool->label[0] ? (char *) pool->label : "-");
  vlib_cli_output (vm, "    pool-id : %u", pool->pool_id);
  vlib_cli_output (vm, "    owner-instance : %u%s%s",
		   owner ? owner->instance_id : CGNAT_INVALID_INDEX,
		   owner && owner->label[0] ? " label " : "",
		   owner && owner->label[0] ? (char *) owner->label : "");
  vlib_cli_output (vm, "    ip-range : %U-%U", format_ip4_address,
		   &pool->first_ip, format_ip4_address, &pool->last_ip);
  vlib_cli_output (vm, "    block-size : %u", pool->block_size);
  vlib_cli_output (vm, "    reserved-ports : %u-%u",
		   pool->exclude_start_port, pool->exclude_end_port);
  vlib_cli_output (vm, "    prealloc-blocks-per-user : %u",
		   pool->prealloc_blocks_per_user);
  vlib_cli_output (vm, "    cooling-time : %u", pool->cooling_time);
  vlib_cli_output (vm, "    block-alloc-mode : %s",
		   pool->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC ?
		     "pre-alloc" :
		     "on-demand");
  vlib_cli_output (vm, "    port-alloc-mode : %s",
		   pool->port_alloc_mode == CGNAT_PORT_ALLOC_MODE_SEQUENCE ?
		     "sequence" :
		     "random");
}

static clib_error_t *
cgnat_show_pool_config_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u8 *name = 0;
  u8 show_all = 0;

  if (unformat (input, "all"))
    show_all = 1;
  else if (!unformat (input, "%s", &name))
    return clib_error_return (0, "expected all or pool name");

  if (show_all)
    {
      vec_foreach (pool, cm->pools)
	{
	  if (!pool->configured)
	    continue;
	  cgnat_show_pool_config_one (vm, pool);
	}
    }
  else
    {
      vec_terminate_c_string (name);
      pool = cgnat_pool_find_by_name_or_id (cm, name);
      if (!pool)
	{
	  clib_error_t *error = clib_error_return (0, "pool %s not found", name);
	  vec_free (name);
	  return error;
	}
      cgnat_show_pool_config_one (vm, pool);
      vec_free (name);
    }
  return 0;
}

static void
cgnat_show_pool_stat_one (vlib_main_t *vm, cgnat_pool_t *pool)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 current_session;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  current_session = clib_atomic_load_relax_n (&pool->active_sessions);
  vlib_worker_thread_barrier_release (cm->vlib_main);

  vlib_cli_output (vm, "Addresses Pool %s:",
		   pool->label[0] ? (char *) pool->label : "-");
  vlib_cli_output (vm, "    current-session : %u", current_session);
  vlib_cli_output (vm, "    max-block-num : %u", pool->total_blocks);
  vlib_cli_output (vm, "    used-block-num : %u", pool->allocated_blocks);
  vlib_cli_output (vm, "    avail-block-num : %u",
		   pool->total_blocks - pool->allocated_blocks);
}

static clib_error_t *
cgnat_show_pool_stat_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u8 *name = 0;
  u8 show_all = 0;

  if (unformat (input, "all"))
    show_all = 1;
  else if (!unformat (input, "%s", &name))
    return clib_error_return (0, "expected all or pool name");

  if (show_all)
    {
      vec_foreach (pool, cm->pools)
	{
	  if (!pool->configured)
	    continue;
	  cgnat_show_pool_stat_one (vm, pool);
	}
    }
  else
    {
      vec_terminate_c_string (name);
      pool = cgnat_pool_find_by_name_or_id (cm, name);
      if (!pool)
	{
	  clib_error_t *error = clib_error_return (0, "pool %s not found", name);
	  vec_free (name);
	  return error;
	}
      cgnat_show_pool_stat_one (vm, pool);
      vec_free (name);
    }
  return 0;
}

static clib_error_t *
cgnat_set_log_queue_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 poll_ms = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "poll-interval %u", &poll_ms))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }

  if (!poll_ms || poll_ms > 10000)
    return clib_error_return (0, "poll-interval must be 1..10000 ms");

  cm->log_poll_interval = (f64) poll_ms / 1000.0;
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (cgnat_enable_command, static) = {
  .path = "cgnat enable",
  .short_help = "cgnat enable",
  .function = cgnat_enable_command_fn,
};
VLIB_CLI_COMMAND (cgnat_disable_command, static) = {
  .path = "cgnat disable",
  .short_help = "cgnat disable",
  .function = cgnat_disable_command_fn,
};
VLIB_CLI_COMMAND (cgnat_add_pool_command, static) = {
  .path = "cgnat add pool",
  .short_help = "cgnat add pool <pool-id> start-ip <ip> end-ip <ip> "
		"[label <name>] [block-size <n>] [reserved-port <start> <end>] "
		"[block-alloc-mode on-demand|pre-alloc] "
		"[port-alloc-mode random|sequence] "
		"[prealloc-blocks-per-user <n>] [cooling-time <n>]",
  .function = cgnat_add_pool_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_pool_command, static) = {
  .path = "cgnat del pool",
  .short_help = "cgnat del pool <pool-id>",
  .function = cgnat_del_pool_command_fn,
};
VLIB_CLI_COMMAND (cgnat_set_pool_command, static) = {
  .path = "cgnat set pool",
  .short_help = "cgnat set pool <pool-id> [cooling-time <n>] [label <name>]",
  .function = cgnat_set_pool_command_fn,
};
VLIB_CLI_COMMAND (cgnat_add_instance_command, static) = {
  .path = "cgnat add instance",
  .short_help = "cgnat add instance [<id>] [label <name>] "
		"[mode <dynamic|deterministic>] "
		"[inside-vrf <id>|any] [outside-vrf <id>] "
		"pool <id> ... "
		"[inside-address range <start> <end>] "
		"[inside-address prefix <ip>/<mask>] ...",
  .function = cgnat_add_instance_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_instance_command, static) = {
  .path = "cgnat del instance",
  .short_help = "cgnat del instance <instance-id>",
  .function = cgnat_del_instance_command_fn,
};
VLIB_CLI_COMMAND (cgnat_set_instance_command, static) = {
  .path = "cgnat set instance",
  .short_help =
    "cgnat set instance <instance-id> "
    "[max-user-sessions <n>] [max-user-create-sessions-rate <n>] "
    "[aging-tcp-syn <n>] [aging-tcp-established <n>] "
    "[aging-tcp-fin-rst <n>] [aging-udp <n>] [aging-icmp <n>] [aging-other <n>] "
    "[max-user-blocks <n>] [max-user-ports <n>] "
    "[filtering-mode <eif|adf|adpf>] [hairpinning <enable|disable>] "
    "[log-mode <port-block|session>] [syslog <enable|disable>] "
    "[ipfix <enable|disable>] [tcp-mss <value>] "
    "[acl-index <index|none|del index>] "
    "[syslog server [del] <address> <port>] "
    "[ipfix collector [del] <address> <port> src <address> <port>]",
  .function = cgnat_set_instance_command_fn,
};
VLIB_CLI_COMMAND (cgnat_set_log_queue_command, static) = {
  .path = "cgnat set log-queue",
  .short_help = "cgnat set log-queue poll-interval <ms>",
  .function = cgnat_set_log_queue_command_fn,
};
VLIB_CLI_COMMAND (cgnat_set_interface_command, static) = {
  .path = "cgnat set interface",
  .short_help = "cgnat set interface <interface> <inside|outside|none>",
  .function = cgnat_set_interface_command_fn,
};
VLIB_CLI_COMMAND (cgnat_add_static_command, static) = {
  .path = "cgnat add static-mapping",
  .short_help = "cgnat add static-mapping instance <id> outside <ip> [<port>] "
		"inside <ip> [<port>] [inside-vrf <id>] "
		"[protocol <tcp|udp|icmp|all>]",
  .function = cgnat_add_static_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_static_command, static) = {
  .path = "cgnat del static-mapping",
  .short_help = "cgnat del static-mapping instance <id> outside <ip> [<port>] "
		"inside <ip> [<port>] [inside-vrf <id>] "
		"[protocol <tcp|udp|icmp|all>]",
  .function = cgnat_del_static_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_session_all_command, static) = {
  .path = "cgnat show session all",
  .short_help = "cgnat show session all",
  .function = cgnat_show_session_all_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_session_user_command, static) = {
  .path = "cgnat show session user",
  .short_help = "cgnat show session user <inside-ip>",
  .function = cgnat_show_session_user_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_session_summary_command, static) = {
  .path = "cgnat show session summary",
  .short_help = "cgnat show session summary <inside-ip>",
  .function = cgnat_show_session_summary_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_instance_config_command, static) = {
  .path = "cgnat show instance config",
  .short_help = "cgnat show instance config <all>|instance <name>|<name>",
  .function = cgnat_show_instance_config_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_instance_stat_command, static) = {
  .path = "cgnat show instance stat",
  .short_help = "cgnat show instance stat <all>|instance <name>|<name>",
  .function = cgnat_show_instance_stat_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_pool_config_command, static) = {
  .path = "cgnat show pool config",
  .short_help = "cgnat show pool config <all>|<pool-name>",
  .function = cgnat_show_pool_config_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_pool_stat_command, static) = {
  .path = "cgnat show pool stat",
  .short_help = "cgnat show pool stat <all>|<pool-name>",
  .function = cgnat_show_pool_stat_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_session_user_command, static) = {
  .path = "cgnat del session user",
  .short_help = "cgnat del session user <inside-ip> "
		"[protocol <tcp|udp|icmp|all>]",
  .function = cgnat_del_session_user_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_session_public_command, static) = {
  .path = "cgnat del session public",
  .short_help = "cgnat del session public <public-ip>",
  .function = cgnat_del_session_public_command_fn,
};
VLIB_CLI_COMMAND (cgnat_del_session_exact_command, static) = {
  .path = "cgnat del session inside",
  .short_help = "cgnat del session inside <inside-ip> port <inside-port> "
		"outside <public-ip> port <public-port> "
		"protocol <tcp|udp|icmp|all>",
  .function = cgnat_del_session_exact_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_det_o2imap_command, static) = {
  .path = "cgnat show det o2imap",
  .short_help = "cgnat show det o2imap instance <id> <public-ip>:<port>",
  .function = cgnat_show_det_o2imap_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_det_i2omap_command, static) = {
  .path = "cgnat show det i2omap",
  .short_help = "cgnat show det i2omap instance <id> <inside-ip>|all",
  .function = cgnat_show_det_i2omap_command_fn,
};
VLIB_CLI_COMMAND (cgnat_show_det_mappings_command, static) = {
  .path = "cgnat show det mappings",
  .short_help = "cgnat show det mappings instance <id>",
  .function = cgnat_show_det_mappings_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
