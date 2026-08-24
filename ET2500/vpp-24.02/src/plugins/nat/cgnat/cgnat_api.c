/*
 * cgnat_api.c - CGNAT binary API handlers
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip_types_api.h>

#include <nat/cgnat/cgnat.h>
#include <nat/cgnat/cgnat.api_enum.h>
#include <nat/cgnat/cgnat.api_types.h>

#include <vlibmemory/api.h>

#define REPLY_MSG_ID_BASE cm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_cgnat_plugin_enable_disable_t_handler (
  vl_api_cgnat_plugin_enable_disable_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_plugin_enable_disable_reply_t *rmp;
  int rv = cgnat_plugin_enable_disable (mp->enable);
  REPLY_MACRO (VL_API_CGNAT_PLUGIN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_cgnat_plugin_get_t_handler (vl_api_cgnat_plugin_get_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_plugin_get_reply_t *rmp;
  int rv = 0;
  REPLY_MACRO2 (VL_API_CGNAT_PLUGIN_GET_REPLY,
		({ rmp->enabled = cm->enabled; }));
}

static void
cgnat_decode_pool_config (vl_api_ip4_address_t first_ip,
			  vl_api_ip4_address_t last_ip, u16 block_size,
			  u16 reserved_start, u16 reserved_end, u16 prealloc,
			  u16 cooling, u8 block_mode, u8 port_mode,
			  cgnat_pool_config_t *config)
{
  clib_memset (config, 0, sizeof (*config));
  ip4_address_decode (first_ip, &config->first_ip);
  ip4_address_decode (last_ip, &config->last_ip);
  config->block_size = ntohs (block_size);
  config->reserved_port_start = ntohs (reserved_start);
  config->reserved_port_end = ntohs (reserved_end);
  config->prealloc_blocks_per_user = ntohs (prealloc);
  config->cooling_time = ntohs (cooling);
  config->block_alloc_mode = block_mode;
  config->port_alloc_mode = port_mode;
}

static void
cgnat_decode_inside_address (vl_api_cgnat_inside_address_t *api,
			     cgnat_inside_address_t *address)
{
  clib_memset (address, 0, sizeof (*address));
  address->type = api->type;
  ip4_address_decode (api->first_ip, &address->first_ip);
  ip4_address_decode (api->last_ip, &address->last_ip);
  address->prefix_len = api->prefix_len;
}

static void
cgnat_encode_inside_address (cgnat_inside_address_t *address,
			     vl_api_cgnat_inside_address_t *api)
{
  clib_memset (api, 0, sizeof (*api));
  api->type = address->type;
  ip4_address_encode (&address->first_ip, api->first_ip);
  ip4_address_encode (&address->last_ip, api->last_ip);
  api->prefix_len = address->prefix_len;
}

static u32
cgnat_api_instance_active_sessions (cgnat_instance_t *instance)
{
  return clib_atomic_load_relax_n (&instance->active_sessions);
}

static void
vl_api_cgnat_pool_add_del_t_handler (vl_api_cgnat_pool_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_pool_add_del_reply_t *rmp;
  cgnat_pool_config_t config;
  u32 pool_id = ntohl (mp->pool_id);
  int rv;

  cgnat_decode_pool_config (
    mp->first_ip, mp->last_ip, mp->block_size, mp->reserved_port_start,
    mp->reserved_port_end, mp->prealloc_blocks_per_user, mp->cooling_time,
    mp->block_alloc_mode, mp->port_alloc_mode, &config);
  clib_memcpy (config.label, mp->label, sizeof (config.label));
  rv = cgnat_pool_add_del (&pool_id, &config, mp->is_add);
  REPLY_MACRO2 (VL_API_CGNAT_POOL_ADD_DEL_REPLY,
		({ rmp->pool_id = htonl (pool_id); }));
}

static void
vl_api_cgnat_pool_set_t_handler (vl_api_cgnat_pool_set_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_pool_set_reply_t *rmp;
  u32 pool_id = ntohl (mp->pool_id);
  int rv;

  rv = cgnat_pool_set_cooling_time (pool_id, ntohs (mp->cooling_time));
  if (rv)
    {
      REPLY_MACRO (VL_API_CGNAT_POOL_SET_REPLY);
      return;
    }
  if (mp->label[0])
    rv = cgnat_pool_set_label (pool_id, mp->label);
  REPLY_MACRO (VL_API_CGNAT_POOL_SET_REPLY);
}

static void
cgnat_send_pool_details (cgnat_pool_t *pool, vl_api_registration_t *reg,
			 u32 context)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u32 allocated_blocks, cooling_blocks;
  vl_api_cgnat_pool_details_t *rmp = vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_CGNAT_POOL_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->pool_id = htonl (pool->pool_id);
  clib_memcpy (rmp->label, pool->label, sizeof (rmp->label));
  instance = cgnat_instance_get_by_index (cm, pool->owner_instance_index);
  rmp->owner_instance_id =
    htonl (instance ? instance->instance_id : CGNAT_INVALID_INDEX);
  ip4_address_encode (&pool->first_ip, rmp->first_ip);
  ip4_address_encode (&pool->last_ip, rmp->last_ip);
  rmp->block_size = htons (pool->block_size);
  rmp->reserved_port_start = htons (pool->exclude_start_port);
  rmp->reserved_port_end = htons (pool->exclude_end_port);
  rmp->prealloc_blocks_per_user = htons (pool->prealloc_blocks_per_user);
  rmp->cooling_time = htons (pool->cooling_time);
  rmp->block_alloc_mode = pool->block_alloc_mode;
  rmp->port_alloc_mode = pool->port_alloc_mode;
  rmp->total_blocks = htonl (pool->total_blocks);
  allocated_blocks = clib_atomic_load_relax_n (&pool->allocated_blocks);
  cooling_blocks = clib_atomic_load_relax_n (&pool->cooling_blocks);
  rmp->allocated_blocks = htonl (allocated_blocks);
  rmp->cooling_blocks = htonl (cooling_blocks);
  rmp->active_users = htonl (clib_atomic_load_relax_n (&pool->active_users));
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_pool_dump_t_handler (vl_api_cgnat_pool_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_pool_t *pool;

  if (!reg)
    return;
  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (pool, cm->pools)
    if (pool->configured)
      cgnat_send_pool_details (pool, reg, mp->context);
  vlib_worker_thread_barrier_release (cm->vlib_main);
}

static void
vl_api_cgnat_pool_stats_get_t_handler (vl_api_cgnat_pool_stats_get_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  vl_api_cgnat_pool_stats_get_reply_t *rmp;
  cgnat_pool_t *pool;
  u32 pool_index;
  u32 pool_id = ntohl (mp->pool_id);
  int rv = VNET_API_ERROR_INVALID_VALUE;

  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_CGNAT_POOL_STATS_GET_REPLY + cm->msg_id_base);
  rmp->context = mp->context;
  rmp->pool_id = htonl (CGNAT_INVALID_INDEX);

  if (!cgnat_pool_index_from_id (pool_id, &pool_index))
    {
      pool = cgnat_pool_get_by_index (cm, pool_index);
      if (pool)
	{
	  cgnat_instance_t *instance =
	    cgnat_instance_get_by_index (cm, pool->owner_instance_index);
	  rv = 0;
	  rmp->pool_id = htonl (pool_id);
	  rmp->owner_instance_id =
	    htonl (instance ? instance->instance_id : CGNAT_INVALID_INDEX);
	  rmp->total_blocks = htonl (pool->total_blocks);
	  rmp->allocated_blocks =
	    htonl (clib_atomic_load_relax_n (&pool->allocated_blocks));
	  rmp->cooling_blocks =
	    htonl (clib_atomic_load_relax_n (&pool->cooling_blocks));
	  rmp->active_users =
	    htonl (clib_atomic_load_relax_n (&pool->active_users));
	}
    }

  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_instance_add_del_t_handler (vl_api_cgnat_instance_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_instance_add_del_reply_t *rmp;
  u32 instance_id = ntohl (mp->instance_id);
  u32 pool_count = ntohl (mp->pool_count);
  u32 inside_address_count = ntohl (mp->inside_address_count);
  u32 *pool_ids = 0;
  cgnat_inside_address_t *inside_addresses = 0;
  int rv = 0;

  if (pool_count > CGNAT_MAX_INSTANCE_POOLS ||
      inside_address_count > CGNAT_MAX_INSIDE_ADDRESSES)
    rv = VNET_API_ERROR_INVALID_VALUE;
  else
    {
      for (u32 i = 0; i < pool_count; i++)
	vec_add1 (pool_ids, ntohl (mp->pool_ids[i]));
      if (inside_address_count)
	{
	  vec_validate (inside_addresses, inside_address_count - 1);
	  for (u32 i = 0; i < inside_address_count; i++)
	    cgnat_decode_inside_address (&mp->inside_addresses[i],
					 &inside_addresses[i]);
	}

      rv = cgnat_instance_add_del (
	&instance_id, mp->is_add ? mp->label : 0, ntohl (mp->inside_vrf_id),
	ntohl (mp->outside_vrf_id), mp->mode, pool_ids, pool_count,
	inside_addresses, inside_address_count, mp->is_add);
    }

  vec_free (pool_ids);
  vec_free (inside_addresses);
  REPLY_MACRO2 (VL_API_CGNAT_INSTANCE_ADD_DEL_REPLY,
		({ rmp->instance_id = htonl (instance_id); }));
}

static void
vl_api_cgnat_instance_set_t_handler (vl_api_cgnat_instance_set_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_instance_set_reply_t *rmp;
  cgnat_instance_config_t config = {
    .flags = ntohl (mp->flags),
    .max_user_sessions = ntohl (mp->max_user_sessions),
    .max_user_create_sessions_rate =
      ntohl (mp->max_user_create_sessions_rate),
    .aging_tcp_syn = ntohl (mp->aging_tcp_syn),
    .aging_tcp_established = ntohl (mp->aging_tcp_established),
    .aging_tcp_fin_rst = ntohl (mp->aging_tcp_fin_rst),
    .aging_udp = ntohl (mp->aging_udp),
    .aging_icmp = ntohl (mp->aging_icmp),
    .aging_other = ntohl (mp->aging_other),
    .max_user_blocks = ntohs (mp->max_user_blocks),
    .max_user_ports = ntohs (mp->max_user_ports),
    .filter_mode = mp->filter_mode,
    .hairpinning_enabled = mp->hairpinning_enabled,
    .log_mode = mp->log_mode,
    .syslog_enabled = mp->syslog_enabled,
    .ipfix_enabled = mp->ipfix_enabled,
    .tcp_mss = ntohs (mp->tcp_mss),
  };
  int rv = cgnat_instance_set (ntohl (mp->instance_id), &config);
  REPLY_MACRO (VL_API_CGNAT_INSTANCE_SET_REPLY);
}

static void
vl_api_cgnat_instance_acl_set_t_handler (
  vl_api_cgnat_instance_acl_set_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_instance_acl_set_reply_t *rmp;
  u32 instance_index;
  int rv = cgnat_instance_index_from_id (ntohl (mp->instance_id),
					 &instance_index);
  if (!rv)
    {
      rv = cgnat_instance_set_acl (instance_index, ntohl (mp->acl_index),
				   mp->enable);
    }
  REPLY_MACRO (VL_API_CGNAT_INSTANCE_ACL_SET_REPLY);
}

static void
cgnat_send_instance_details (cgnat_instance_t *instance,
			     vl_api_registration_t *reg, u32 context)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_recalculate_instance (cm, instance);
  fib_table_t *inside_fib =
    instance->inside_fib_index == CGNAT_INVALID_INDEX ?
      0 :
      fib_table_get (instance->inside_fib_index, FIB_PROTOCOL_IP4);
  fib_table_t *outside_fib =
    fib_table_get (instance->outside_fib_index, FIB_PROTOCOL_IP4);
  vl_api_cgnat_instance_details_t *rmp = vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_CGNAT_INSTANCE_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->instance_id = htonl (instance->instance_id);
  clib_memcpy (rmp->label, instance->label, sizeof (rmp->label));
  rmp->inside_vrf_id =
    htonl (inside_fib ? inside_fib->ft_table_id : CGNAT_INVALID_INDEX);
  rmp->outside_vrf_id = htonl (outside_fib->ft_table_id);
  rmp->mode = instance->mode;
  rmp->acl_count = htonl (vec_len (instance->acl_indices));
  rmp->inside_address_count = htonl (vec_len (instance->inside_addresses));
  rmp->syslog_server_count = htonl (vec_len (instance->syslog_servers));
  rmp->ipfix_exporter_count = htonl (vec_len (instance->ipfix_exporters));
  rmp->filter_mode = instance->filter_mode;
  rmp->hairpinning_enabled = instance->hairpinning_enabled;
  rmp->max_user_blocks = htons (instance->per_user_max_blocks);
  rmp->max_user_ports = htons (instance->per_user_max_ports);
  rmp->max_user_sessions = htonl (instance->max_sessions_per_user);
  rmp->max_user_create_sessions_rate =
    htonl (instance->max_session_create_rate);
  rmp->aging_tcp_syn = htonl (instance->tcp_syn_timeout);
  rmp->aging_tcp_established = htonl (instance->tcp_established_timeout);
  rmp->aging_tcp_fin_rst = htonl (instance->tcp_fin_rst_timeout);
  rmp->aging_udp = htonl (instance->udp_timeout);
  rmp->aging_icmp = htonl (instance->icmp_timeout);
  rmp->aging_other = htonl (instance->other_timeout);
  rmp->log_mode = instance->log_mode;
  rmp->syslog_enabled = instance->syslog_enabled;
  rmp->ipfix_enabled = instance->ipfix_enabled;
  rmp->tcp_mss = htons (instance->tcp_mss);
  rmp->total_blocks = htonl (instance->total_blocks);
  rmp->allocated_blocks = htonl (instance->allocated_blocks);
  rmp->cooling_blocks = htonl (instance->cooling_blocks);
  rmp->active_users = htonl (instance->active_users);
  rmp->active_sessions = htonl (cgnat_api_instance_active_sessions (instance));
  for (u32 i = 0; i < vec_len (instance->inside_addresses) &&
		   i < CGNAT_MAX_INSIDE_ADDRESSES;
       i++)
    cgnat_encode_inside_address (&instance->inside_addresses[i],
				 &rmp->inside_addresses[i]);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_instance_dump_t_handler (vl_api_cgnat_instance_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;

  if (!reg)
    return;
  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    if (instance->configured)
      cgnat_send_instance_details (instance, reg, mp->context);
  vlib_worker_thread_barrier_release (cm->vlib_main);
}

static void
vl_api_cgnat_instance_stats_get_t_handler (
  vl_api_cgnat_instance_stats_get_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  vl_api_cgnat_instance_stats_get_reply_t *rmp;
  cgnat_instance_t *instance;
  u32 instance_index;
  u32 instance_id = ntohl (mp->instance_id);
  int rv = VNET_API_ERROR_INVALID_VALUE;

  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_CGNAT_INSTANCE_STATS_GET_REPLY + cm->msg_id_base);
  rmp->context = mp->context;
  rmp->instance_id = htonl (CGNAT_INVALID_INDEX);

  if (!cgnat_instance_index_from_id (instance_id, &instance_index))
    {
      instance = cgnat_instance_get_by_index (cm, instance_index);
      if (instance)
	{
	  cgnat_recalculate_instance (cm, instance);
	  rv = 0;
	  rmp->instance_id = htonl (instance_id);
	  rmp->total_blocks = htonl (instance->total_blocks);
	  rmp->allocated_blocks = htonl (instance->allocated_blocks);
	  rmp->cooling_blocks = htonl (instance->cooling_blocks);
	  rmp->active_users = htonl (instance->active_users);
	  rmp->active_sessions =
	    htonl (clib_atomic_load_relax_n (&instance->active_sessions));
	}
    }

  rmp->retval = htonl (rv);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_instance_acl_dump_t_handler (
  vl_api_cgnat_instance_acl_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;
  u32 instance_index, *acl_index;

  if (!reg || cgnat_instance_index_from_id (ntohl (mp->instance_id),
					    &instance_index))
    return;
  instance = cgnat_instance_get_by_index (cm, instance_index);
  vec_foreach (acl_index, instance->acl_indices)
    {
      vl_api_cgnat_instance_acl_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_INSTANCE_ACL_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (instance->instance_id);
      rmp->acl_index = htonl (*acl_index);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cgnat_syslog_server_add_del_t_handler (
  vl_api_cgnat_syslog_server_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_syslog_server_add_del_reply_t *rmp;
  ip4_address_t address;
  u32 instance_index;
  int rv;

  ip4_address_decode (mp->address, &address);
  rv = cgnat_instance_index_from_id (ntohl (mp->instance_id),
				     &instance_index);
  if (!rv)
    rv = cgnat_instance_syslog_server_add_del (
      instance_index, address, ntohs (mp->port), mp->is_add);
  REPLY_MACRO (VL_API_CGNAT_SYSLOG_SERVER_ADD_DEL_REPLY);
}

static void
vl_api_cgnat_syslog_server_dump_t_handler (
  vl_api_cgnat_syslog_server_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;
  cgnat_syslog_server_t *server;
  u32 instance_index;

  if (!reg || cgnat_instance_index_from_id (ntohl (mp->instance_id),
					    &instance_index))
    return;
  instance = cgnat_instance_get_by_index (cm, instance_index);
  vec_foreach (server, instance->syslog_servers)
    {
      vl_api_cgnat_syslog_server_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_SYSLOG_SERVER_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (instance->instance_id);
      ip4_address_encode (&server->address, rmp->address);
      rmp->port = htons (server->port);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cgnat_ipfix_exporter_add_del_t_handler (
  vl_api_cgnat_ipfix_exporter_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_ipfix_exporter_add_del_reply_t *rmp;
  ip4_address_t collector_address, src_address;
  u32 instance_index;
  int rv;

  ip4_address_decode (mp->collector_address, &collector_address);
  ip4_address_decode (mp->src_address, &src_address);
  rv = cgnat_instance_index_from_id (ntohl (mp->instance_id),
				     &instance_index);
  if (!rv)
    rv = cgnat_instance_ipfix_exporter_add_del (
      instance_index, collector_address, ntohs (mp->collector_port),
      src_address, ntohs (mp->src_port), mp->is_add);
  REPLY_MACRO (VL_API_CGNAT_IPFIX_EXPORTER_ADD_DEL_REPLY);
}

static void
vl_api_cgnat_ipfix_exporter_dump_t_handler (
  vl_api_cgnat_ipfix_exporter_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;
  cgnat_ipfix_exporter_t *exporter;
  u32 instance_index;

  if (!reg || cgnat_instance_index_from_id (ntohl (mp->instance_id),
					    &instance_index))
    return;
  instance = cgnat_instance_get_by_index (cm, instance_index);
  vec_foreach (exporter, instance->ipfix_exporters)
    {
      vl_api_cgnat_ipfix_exporter_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_IPFIX_EXPORTER_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (instance->instance_id);
      ip4_address_encode (&exporter->collector_address,
			  rmp->collector_address);
      rmp->collector_port = htons (exporter->collector_port);
      ip4_address_encode (&exporter->src_address, rmp->src_address);
      rmp->src_port = htons (exporter->src_port);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cgnat_interface_zone_set_t_handler (
  vl_api_cgnat_interface_zone_set_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_interface_zone_set_reply_t *rmp;
  u32 sw_if_index = ntohl (mp->sw_if_index);
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);
  rv = cgnat_interface_zone_set (sw_if_index,
				 (cgnat_interface_role_t) mp->role);
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_CGNAT_INTERFACE_ZONE_SET_REPLY);
}

static void
vl_api_cgnat_interface_dump_t_handler (vl_api_cgnat_interface_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_interface_t *interface;

  if (!reg)
    return;
  pool_foreach (interface, cm->interfaces)
    {
      vl_api_cgnat_interface_details_t *rmp = vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_INTERFACE_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->sw_if_index = htonl (interface->sw_if_index);
      rmp->is_inside = cgnat_interface_is_inside (interface);
      rmp->is_outside = cgnat_interface_is_outside (interface);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_cgnat_static_mapping_add_del_t_handler (
  vl_api_cgnat_static_mapping_add_del_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_static_mapping_add_del_reply_t *rmp;
  ip4_address_t outside_ip, inside_ip;
  u32 instance_index;
  int rv;

  ip4_address_decode (mp->outside_ip, &outside_ip);
  ip4_address_decode (mp->inside_ip, &inside_ip);
  if (mp->mapping_type > CGNAT_API_STATIC_MAPPING_ADDRESS_PROTOCOL_PORT)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }
  rv = cgnat_instance_index_from_id (ntohl (mp->instance_id),
				     &instance_index);
  if (!rv)
    rv = cgnat_static_mapping_add_del (
      instance_index, outside_ip, ntohs (mp->outside_port), inside_ip,
      ntohs (mp->inside_port), mp->protocol, mp->mapping_type,
      ntohl (mp->inside_vrf_id), mp->is_add);
reply:
  REPLY_MACRO (VL_API_CGNAT_STATIC_MAPPING_ADD_DEL_REPLY);
}

static void
vl_api_cgnat_static_mapping_dump_t_handler (
  vl_api_cgnat_static_mapping_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;
  cgnat_static_rule_t *rule;
  u32 instance_index;

  if (!reg || cgnat_instance_index_from_id (ntohl (mp->instance_id),
					    &instance_index))
    return;
  instance = vec_elt_at_index (cm->instances, instance_index);
  pool_foreach (rule, instance->static_rules)
    {
      vl_api_cgnat_static_mapping_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_STATIC_MAPPING_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (instance->instance_id);
      ip4_address_encode (&rule->outside_ip, rmp->outside_ip);
      ip4_address_encode (&rule->inside_ip, rmp->inside_ip);
      rmp->outside_port = htons (rule->outside_port);
      rmp->inside_port = htons (rule->inside_port);
      rmp->protocol = rule->protocol;
      rmp->mapping_type = rule->type;
      if (rule->inside_fib_index != CGNAT_INVALID_INDEX)
	{
	  fib_table_t *fib = fib_table_get (rule->inside_fib_index,
					    FIB_PROTOCOL_IP4);
	  rmp->inside_vrf_id = htonl (fib ? fib->ft_table_id :
					CGNAT_INVALID_INDEX);
	}
      else
	rmp->inside_vrf_id = htonl (CGNAT_INVALID_INDEX);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static int
cgnat_decode_session_filter (u32 api_flags, vl_api_ip4_address_t inside_ip,
			     vl_api_ip4_address_t public_ip, u16 inside_port,
			     u16 public_port, u8 protocol,
			     cgnat_session_filter_t *filter)
{
  u32 flags = ntohl (api_flags);

  if (flags & ~0x1f)
    return VNET_API_ERROR_INVALID_VALUE;
  clib_memset (filter, 0, sizeof (*filter));
  filter->flags = flags;
  ip4_address_decode (inside_ip, &filter->inside_ip);
  ip4_address_decode (public_ip, &filter->public_ip);
  filter->inside_port = ntohs (inside_port);
  filter->public_port = ntohs (public_port);
  filter->protocol = protocol;
  return 0;
}

static void
vl_api_cgnat_session_dump_t_handler (vl_api_cgnat_session_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_session_filter_t filter;
  cgnat_session_t *sessions, *session;
  f64 now;

  if (!reg || cgnat_decode_session_filter (
		mp->flags, mp->inside_ip, mp->public_ip, mp->inside_port,
		mp->public_port, mp->protocol, &filter))
    return;
  sessions = cgnat_session_snapshot (&filter);
  now = vlib_time_now (cm->vlib_main);
  vec_foreach (session, sessions)
    {
      cgnat_instance_t *instance =
	cgnat_instance_get_by_index (cm, session->instance_index);
      vl_api_cgnat_session_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_SESSION_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id =
	htonl (instance ? instance->instance_id : CGNAT_INVALID_INDEX);
      ip4_address_encode (&session->inside_ip, rmp->inside_ip);
      rmp->inside_port = htons (session->inside_port);
      ip4_address_encode (&session->nat_ip, rmp->public_ip);
      rmp->public_port = htons (session->nat_port);
      ip4_address_encode (&session->remote_ip, rmp->remote_ip);
      rmp->remote_port = htons (session->remote_port);
      rmp->protocol = session->protocol;
      rmp->tcp_state = session->tcp_state;
      rmp->is_static = session->mapping_type == CGNAT_MAPPING_STATIC;
      rmp->idle_milliseconds = clib_host_to_net_u64 (
	(u64) (clib_max (now - session->last_active, 0.0) * 1000.0));
      vl_api_send_msg (reg, (u8 *) rmp);
    }
  vec_free (sessions);
}

static void
vl_api_cgnat_session_delete_t_handler (vl_api_cgnat_session_delete_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_session_delete_reply_t *rmp;
  cgnat_session_filter_t filter;
  u32 deleted = 0;
  int rv;

  rv = cgnat_decode_session_filter (
    mp->flags, mp->inside_ip, mp->public_ip, mp->inside_port,
    mp->public_port, mp->protocol, &filter);
  if (!rv && !filter.flags)
    rv = VNET_API_ERROR_INVALID_VALUE;
  if (!rv)
    deleted = cgnat_session_delete_matching (&filter);
  REPLY_MACRO2 (VL_API_CGNAT_SESSION_DELETE_REPLY,
		({ rmp->deleted_count = htonl (deleted); }));
}

static void
vl_api_cgnat_user_dump_t_handler (vl_api_cgnat_user_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_instance_t *instance;
  cgnat_user_t *user;
  ip4_address_t inside_ip;
  f64 now;

  if (!reg)
    return;
  ip4_address_decode (mp->inside_ip, &inside_ip);
  now = vlib_time_now (cm->vlib_main);
  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      pool_foreach (user, instance->users)
	{
	  vl_api_cgnat_user_details_t *rmp;

	  if (mp->filter_by_inside_ip &&
	      user->key.private_ip.as_u32 != inside_ip.as_u32)
	    continue;
	  rmp = vl_msg_api_alloc (sizeof (*rmp));
	  clib_memset (rmp, 0, sizeof (*rmp));
	  rmp->_vl_msg_id =
	    htons (VL_API_CGNAT_USER_DETAILS + cm->msg_id_base);
	  rmp->context = mp->context;
	  rmp->instance_id = htonl (instance->instance_id);
	  ip4_address_encode (&user->key.private_ip, rmp->inside_ip);
	  rmp->inside_fib_index = htonl (user->key.fib_index);
	  rmp->active_sessions = htonl (user->active_sessions);
	  rmp->active_ports[0] = htonl (user->active_ports[0]);
	  rmp->active_ports[1] = htonl (user->active_ports[1]);
	  rmp->active_ports[2] = htonl (user->active_ports[2]);
	  rmp->session_rate_count = htonl (
	    now - user->session_rate_window_start < 1.0 ?
	      user->session_rate_count :
	      0);
	  rmp->max_sessions = htonl (instance->max_sessions_per_user);
	  rmp->max_session_create_rate =
	    htonl (instance->max_session_create_rate);
	  rmp->session_limit_drops = htonl (user->session_limit_drops);
	  rmp->session_rate_drops = htonl (user->session_rate_drops);
	  rmp->session_lock_drops = htonl (user->session_lock_drops);
	  vl_api_send_msg (reg, (u8 *) rmp);
	}
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
}

static void
cgnat_api_send_block_summary (cgnat_block_ip_summary_t *summary,
			      vl_api_registration_t *reg, u32 context)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_block_summary_details_t *rmp =
    vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_CGNAT_BLOCK_SUMMARY_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->instance_id = htonl (summary->instance_id);
  rmp->pool_id = htonl (summary->pool_id);
  ip4_address_encode (&summary->public_ip, rmp->public_ip);
  rmp->total_blocks = htonl (summary->total_blocks);
  rmp->allocated_blocks = htonl (summary->allocated_blocks);
  rmp->cooling_blocks = htonl (summary->cooling_blocks);
  rmp->active_users = htonl (summary->active_users);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_block_summary_dump_t_handler (
  vl_api_cgnat_block_summary_dump_t *mp)
{
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_block_ip_summary_t *summaries, *summary;

  if (!reg)
    return;
  summaries = cgnat_block_summary_snapshot (0);
  vec_foreach (summary, summaries)
    cgnat_api_send_block_summary (summary, reg, mp->context);
  vec_free (summaries);
}

static void
vl_api_cgnat_block_user_dump_t_handler (vl_api_cgnat_block_user_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_block_user_summary_t *summaries, *summary;
  ip4_address_t inside_ip;

  if (!reg)
    return;
  ip4_address_decode (mp->inside_ip, &inside_ip);
  summaries = cgnat_block_user_snapshot (inside_ip);
  vec_foreach (summary, summaries)
    {
      vl_api_cgnat_block_user_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_BLOCK_USER_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (summary->instance_id);
      rmp->inside_fib_index = htonl (summary->inside_fib_index);
      rmp->pool_id = htonl (summary->pool_id);
      ip4_address_encode (&summary->inside_ip, rmp->inside_ip);
      ip4_address_encode (&summary->public_ip, rmp->public_ip);
      rmp->owned_blocks = htonl (summary->owned_blocks);
      rmp->allocated_blocks = htonl (summary->allocated_blocks);
      rmp->cooling_blocks = htonl (summary->cooling_blocks);
      rmp->active_ports[0] = htonl (summary->active_ports[0]);
      rmp->active_ports[1] = htonl (summary->active_ports[1]);
      rmp->active_ports[2] = htonl (summary->active_ports[2]);
      vl_api_send_msg (reg, (u8 *) rmp);
    }
  vec_free (summaries);
}

static void
cgnat_api_send_block_public_summary (cgnat_block_ip_summary_t *summary,
				     vl_api_registration_t *reg,
				     u32 context)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_cgnat_block_public_details_t *rmp =
    vl_msg_api_alloc (sizeof (*rmp));

  clib_memset (rmp, 0, sizeof (*rmp));
  rmp->_vl_msg_id =
    htons (VL_API_CGNAT_BLOCK_PUBLIC_DETAILS + cm->msg_id_base);
  rmp->context = context;
  rmp->instance_id = htonl (summary->instance_id);
  rmp->pool_id = htonl (summary->pool_id);
  ip4_address_encode (&summary->public_ip, rmp->public_ip);
  rmp->total_blocks = htonl (summary->total_blocks);
  rmp->allocated_blocks = htonl (summary->allocated_blocks);
  rmp->cooling_blocks = htonl (summary->cooling_blocks);
  rmp->active_users = htonl (summary->active_users);
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_cgnat_block_public_dump_t_handler (
  vl_api_cgnat_block_public_dump_t *mp)
{
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_block_ip_summary_t *summaries, *summary;
  ip4_address_t public_ip;

  if (!reg)
    return;
  ip4_address_decode (mp->public_ip, &public_ip);
  summaries = cgnat_block_summary_snapshot (&public_ip);
  vec_foreach (summary, summaries)
    cgnat_api_send_block_public_summary (summary, reg, mp->context);
  vec_free (summaries);
}

static void
vl_api_cgnat_block_public_entry_dump_t_handler (
  vl_api_cgnat_block_public_entry_dump_t *mp)
{
  cgnat_main_t *cm = &cgnat_main;
  vl_api_registration_t *reg =
    vl_api_client_index_to_registration (mp->client_index);
  cgnat_block_public_detail_t *details, *detail;
  ip4_address_t public_ip;

  if (!reg)
    return;
  ip4_address_decode (mp->public_ip, &public_ip);
  details = cgnat_block_public_snapshot (public_ip);
  vec_foreach (detail, details)
    {
      vl_api_cgnat_block_public_entry_details_t *rmp =
	vl_msg_api_alloc (sizeof (*rmp));
      clib_memset (rmp, 0, sizeof (*rmp));
      rmp->_vl_msg_id =
	htons (VL_API_CGNAT_BLOCK_PUBLIC_ENTRY_DETAILS + cm->msg_id_base);
      rmp->context = mp->context;
      rmp->instance_id = htonl (detail->instance_id);
      rmp->inside_fib_index = htonl (detail->inside_fib_index);
      rmp->pool_id = htonl (detail->pool_id);
      ip4_address_encode (&detail->public_ip, rmp->public_ip);
      ip4_address_encode (&detail->inside_ip, rmp->inside_ip);
      rmp->block_id = htons (detail->block_id);
      rmp->start_port = htons (detail->start_port);
      rmp->end_port = htons (detail->end_port);
      rmp->active_ports[0] = htons (detail->active_ports[0]);
      rmp->active_ports[1] = htons (detail->active_ports[1]);
      rmp->active_ports[2] = htons (detail->active_ports[2]);
      rmp->state = detail->state;
      rmp->owner_valid = detail->owner_valid;
      vl_api_send_msg (reg, (u8 *) rmp);
    }
  vec_free (details);
}

#include <vnet/format_fns.h>
#include <nat/cgnat/cgnat.api.c>

clib_error_t *
cgnat_api_hookup (vlib_main_t *vm)
{
  cgnat_main_t *cm = &cgnat_main;
  cm->msg_id_base = setup_message_id_table ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
