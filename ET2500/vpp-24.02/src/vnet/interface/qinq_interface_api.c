/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vlibmemory/api.h>
#include <vnet/ethernet/qinq.h>

#include <vnet/format_fns.h>
#include <vnet/interface/qinq_interface.api_enum.h>
#include <vnet/interface/qinq_interface.api_types.h>

static u16 qinq_interface_msg_id_base;

#define REPLY_MSG_ID_BASE qinq_interface_msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
qinq_interface_api_decode_config (
  u32 rule_id, u32 sw_if_index, u32 parent_sw_if_index, u16 outer_tpid,
  u16 outer_vlan, u16 inner_tpid, u16 inner_vlan_first,
  u16 inner_vlan_last, u8 match_type, u8 admin_up, qinq_subport_t *config)
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
  config->admin_up = admin_up;
}

static void
vl_api_qinq_interface_rule_add_t_handler (
  vl_api_qinq_interface_rule_add_t *mp)
{
  vl_api_qinq_interface_rule_add_reply_t *rmp;
  qinq_subport_t config = {};
  qinq_error_t error;
  int rv;

  qinq_interface_api_decode_config (
    mp->rule_id, mp->sw_if_index, mp->parent_sw_if_index, mp->outer_tpid,
    mp->outer_vlan, mp->inner_tpid, mp->inner_vlan_first,
    mp->inner_vlan_last, mp->match_type, mp->admin_up, &config);
  error = qinq_subport_add (&config);
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_INTERFACE_RULE_ADD_REPLY);
}

static void
vl_api_qinq_interface_rule_update_t_handler (
  vl_api_qinq_interface_rule_update_t *mp)
{
  vl_api_qinq_interface_rule_update_reply_t *rmp;
  qinq_subport_t config = {};
  qinq_error_t error;
  int rv;

  qinq_interface_api_decode_config (
    mp->rule_id, mp->sw_if_index, mp->parent_sw_if_index, mp->outer_tpid,
    mp->outer_vlan, mp->inner_tpid, mp->inner_vlan_first,
    mp->inner_vlan_last, mp->match_type, mp->admin_up, &config);
  error = qinq_subport_update (config.rule_id, &config);
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_INTERFACE_RULE_UPDATE_REPLY);
}

static void
vl_api_qinq_interface_rule_delete_t_handler (
  vl_api_qinq_interface_rule_delete_t *mp)
{
  vl_api_qinq_interface_rule_delete_reply_t *rmp;
  qinq_error_t error;
  int rv;

  error = qinq_subport_delete (clib_net_to_host_u32 (mp->rule_id));
  rv = error == QINQ_ERROR_NONE ? 0 : -(int) error;
  REPLY_MACRO (VL_API_QINQ_INTERFACE_RULE_DELETE_REPLY);
}

#include <vnet/interface/qinq_interface.api.c>

static clib_error_t *
qinq_interface_api_init (vlib_main_t *vm)
{
  qinq_interface_msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (qinq_interface_api_init);
