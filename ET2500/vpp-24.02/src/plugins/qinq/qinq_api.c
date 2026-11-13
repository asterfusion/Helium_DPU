/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vnet/api_errno.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>

#include <ipoe/ipoe.h>
#include <qinq/qinq.h>

#include <vnet/format_fns.h>
#include <qinq/qinq.api_enum.h>
#include <qinq/qinq.api_types.h>

#define REPLY_MSG_ID_BASE qpm->msg_id_base
#include <vlibapi/api_helper_macros.h>

int
qinq_ipoe_route_add (const qinq_ipoe_route_t *route)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  qinq_ipoe_route_t *stored;
  u32 route_index;
  int rv;

  if (!route || route->route_id == ~0 ||
      hash_get (qpm->ipoe_route_by_id, route->route_id))
    return IPOE_ERROR_ALREADY_EXISTS;
  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 1);
  if (rv != IPOE_OK)
    return rv;

  pool_get (qpm->ipoe_routes, stored);
  *stored = *route;
  route_index = stored - qpm->ipoe_routes;
  hash_set (qpm->ipoe_route_by_id, route->route_id, route_index);
  return IPOE_OK;
}

int
qinq_ipoe_route_update (const qinq_ipoe_route_t *route)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  qinq_ipoe_route_t old;
  qinq_ipoe_route_t *stored;
  uword *p;
  int same_prefix;
  int rv;

  if (!route)
    return IPOE_ERROR_INVALID_VALUE;
  p = hash_get (qpm->ipoe_route_by_id, route->route_id);
  if (!p)
    return IPOE_ERROR_NO_SUCH_ENTRY;
  stored = pool_elt_at_index (qpm->ipoe_routes, p[0]);
  old = *stored;
  same_prefix = old.table_id == route->table_id &&
		old.user_ip4.as_u32 == route->user_ip4.as_u32;

  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 1);
  if (rv != IPOE_OK)
    return rv;
  if (!same_prefix)
    ipoe_qinq_route_add_del (old.table_id, &old.user_ip4,
			     old.sw_if_index, 0);
  *stored = *route;
  return IPOE_OK;
}

int
qinq_ipoe_route_delete (u32 route_id)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  qinq_ipoe_route_t *route;
  uword *p = hash_get (qpm->ipoe_route_by_id, route_id);
  int rv;

  if (!p)
    return IPOE_ERROR_NO_SUCH_ENTRY;
  route = pool_elt_at_index (qpm->ipoe_routes, p[0]);
  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 0);
  if (rv != IPOE_OK)
    return rv;
  hash_unset (qpm->ipoe_route_by_id, route_id);
  pool_put (qpm->ipoe_routes, route);
  return IPOE_OK;
}

static void
qinq_api_decode_config (u32 rule_id, u32 sw_if_index,
                        u32 parent_sw_if_index, u16 outer_tpid,
                        u16 outer_vlan, u16 inner_tpid,
                        u16 inner_vlan_first, u16 inner_vlan_last,
                        u8 match_type, u8 service_flags, u8 admin_up,
                        qinq_subport_t *config)
{
  config->rule_id = clib_net_to_host_u32 (rule_id);
  config->sw_if_index = clib_net_to_host_u32 (sw_if_index);
  config->parent_sw_if_index = clib_net_to_host_u32 (parent_sw_if_index);
  config->outer_tpid = clib_net_to_host_u16 (outer_tpid);
  config->outer_vlan = clib_net_to_host_u16 (outer_vlan);
  config->inner_tpid = clib_net_to_host_u16 (inner_tpid);
  config->inner_vlan_first = clib_net_to_host_u16 (inner_vlan_first);
  config->inner_vlan_last = clib_net_to_host_u16 (inner_vlan_last);
  config->match_type = match_type;
  config->service_flags = service_flags;
  config->admin_up = admin_up;
}

static void
vl_api_qinq_subport_add_t_handler (vl_api_qinq_subport_add_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_subport_add_reply_t *rmp;
  qinq_subport_t config = {};
  qinq_error_t error;
  int rv;

  qinq_api_decode_config (
    mp->rule_id, mp->sw_if_index, mp->parent_sw_if_index, mp->outer_tpid,
    mp->outer_vlan, mp->inner_tpid, mp->inner_vlan_first,
    mp->inner_vlan_last, mp->match_type, mp->service_flags, mp->admin_up,
    &config);
  error = qinq_subport_add (&config);
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_SUBPORT_ADD_REPLY);
}

static void
vl_api_qinq_subport_update_t_handler (vl_api_qinq_subport_update_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_subport_update_reply_t *rmp;
  qinq_subport_t config = {};
  qinq_error_t error;
  int rv;

  qinq_api_decode_config (
    mp->rule_id, mp->sw_if_index, mp->parent_sw_if_index, mp->outer_tpid,
    mp->outer_vlan, mp->inner_tpid, mp->inner_vlan_first,
    mp->inner_vlan_last, mp->match_type, mp->service_flags, mp->admin_up,
    &config);
  error = qinq_subport_update (config.rule_id, &config);
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_SUBPORT_UPDATE_REPLY);
}

static void
vl_api_qinq_subport_delete_t_handler (vl_api_qinq_subport_delete_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_subport_delete_reply_t *rmp;
  qinq_error_t error;
  int rv;

  error = qinq_subport_delete (clib_net_to_host_u32 (mp->rule_id));
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_SUBPORT_DELETE_REPLY);
}

static void
qinq_api_decode_route (u32 route_id, u32 table_id,
		       const vl_api_ip4_address_t user_ip4,
		       u32 sw_if_index, qinq_ipoe_route_t *route)
{
  route->route_id = ntohl (route_id);
  route->table_id = ntohl (table_id);
  route->sw_if_index = ntohl (sw_if_index);
  ip4_address_decode (user_ip4, &route->user_ip4);
}

static void
vl_api_qinq_ipoe_route_add_t_handler (vl_api_qinq_ipoe_route_add_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_ipoe_route_add_reply_t *rmp;
  qinq_ipoe_route_t route;
  int rv;

  qinq_api_decode_route (mp->route_id, mp->table_id, mp->user_ip4,
			 mp->sw_if_index, &route);
  rv = qinq_ipoe_route_add (&route);
  REPLY_MACRO (VL_API_QINQ_IPOE_ROUTE_ADD_REPLY);
}

static void
vl_api_qinq_ipoe_route_update_t_handler (
  vl_api_qinq_ipoe_route_update_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_ipoe_route_update_reply_t *rmp;
  qinq_ipoe_route_t route;
  int rv;

  qinq_api_decode_route (mp->route_id, mp->table_id, mp->user_ip4,
			 mp->sw_if_index, &route);
  rv = qinq_ipoe_route_update (&route);
  REPLY_MACRO (VL_API_QINQ_IPOE_ROUTE_UPDATE_REPLY);
}

static void
vl_api_qinq_ipoe_route_delete_t_handler (
  vl_api_qinq_ipoe_route_delete_t *mp)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;
  vl_api_qinq_ipoe_route_delete_reply_t *rmp;
  int rv = qinq_ipoe_route_delete (ntohl (mp->route_id));

  REPLY_MACRO (VL_API_QINQ_IPOE_ROUTE_DELETE_REPLY);
}

#include <qinq/qinq.api.c>

static clib_error_t *
qinq_api_init (vlib_main_t *vm)
{
  qinq_plugin_main_t *qpm = &qinq_plugin_main;

  qpm->msg_id_base = setup_message_id_table ();
  qpm->ipoe_route_by_id = hash_create (0, sizeof (uword));
  return 0;
}

VLIB_API_INIT_FUNCTION (qinq_api_init);
