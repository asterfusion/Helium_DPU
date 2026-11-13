/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef included_vnet_ethernet_qinq_h
#define included_vnet_ethernet_qinq_h

#include <vnet/vnet.h>
#include <vnet/ethernet/mac_address.h>
#include <vppinfra/bihash_16_8.h>

#define QINQ_VLAN_MIN 1
#define QINQ_VLAN_MAX 4094

typedef enum
{
  QINQ_MATCH_EXACT,
  QINQ_MATCH_RANGE,
  QINQ_MATCH_ANY,
} qinq_match_type_t;

typedef enum
{
  QINQ_SERVICE_IPOE = (1 << 0),
  QINQ_SERVICE_PPPOE = (1 << 1),
} qinq_service_flag_t;

typedef enum
{
  QINQ_ERROR_NONE,
  QINQ_ERROR_INVALID_ARGUMENT,
  QINQ_ERROR_INVALID_INTERFACE,
  QINQ_ERROR_INVALID_PARENT,
  QINQ_ERROR_INVALID_TPID,
  QINQ_ERROR_INVALID_VLAN,
  QINQ_ERROR_RULE_EXISTS,
  QINQ_ERROR_RULE_NOT_FOUND,
  QINQ_ERROR_INTERFACE_IN_USE,
  QINQ_ERROR_MATCH_CONFLICT,
} qinq_error_t;

typedef struct
{
  u32 rule_id;
  u32 sw_if_index;
  u32 parent_sw_if_index;
  u16 outer_tpid;
  u16 outer_vlan;
  u16 inner_tpid;
  u16 inner_vlan_first;
  u16 inner_vlan_last;
  qinq_match_type_t match_type;
  u8 service_flags;
  u8 admin_up;
} qinq_subport_t;

typedef struct
{
  u16 first;
  u16 last;
  u32 rule_index;
} qinq_vlan_range_t;

typedef struct
{
  u32 parent_sw_if_index;
  u16 outer_tpid;
  u16 outer_vlan;
  u16 inner_tpid;

  uword *exact_by_vlan;
  qinq_vlan_range_t *ranges;
  u32 any_rule_index;
  u32 rule_count;
} qinq_match_group_t;

typedef struct
{
  u32 sw_if_index;
  u32 parent_sw_if_index;
  u32 rule_id;
  qinq_match_type_t match_type;
  u8 service_flags;
  u8 admin_up;
} qinq_match_result_t;

const qinq_subport_t *qinq_subport_get_by_sw_if_index (u32 sw_if_index);

static_always_inline int
qinq_buffer_matches_rx (vlib_buffer_t *buffer)
{
  u32 sw_if_index = vnet_buffer (buffer)->sw_if_index[VLIB_RX];

  return qinq_subport_get_by_sw_if_index (sw_if_index) != 0;
}

static_always_inline int
qinq_buffer_service_enabled (vlib_buffer_t *buffer, u8 service_flag)
{
  const qinq_subport_t *subport = qinq_subport_get_by_sw_if_index (
    vnet_buffer (buffer)->sw_if_index[VLIB_RX]);

  return subport ? (subport->service_flags & service_flag) != 0 : 1;
}

static_always_inline u32
qinq_buffer_rx_parent (vlib_buffer_t *buffer)
{
  const qinq_subport_t *subport = qinq_subport_get_by_sw_if_index (
    vnet_buffer (buffer)->sw_if_index[VLIB_RX]);

  return subport ? subport->parent_sw_if_index :
		   vnet_buffer (buffer)->sw_if_index[VLIB_RX];
}

typedef struct
{
  clib_bihash_16_8_t group_by_domain;
  qinq_match_group_t *groups;
  qinq_subport_t *rules;
  uword *rule_by_id;
  uword *rule_by_sw_if_index;
  u32 **rules_by_parent;
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} qinq_main_t;

extern qinq_main_t qinq_main;

qinq_error_t qinq_subport_add (const qinq_subport_t *config);
qinq_error_t qinq_subport_delete (u32 rule_id);
qinq_error_t qinq_subport_update (u32 rule_id,
                                  const qinq_subport_t *config);

int qinq_subport_lookup (u32 parent_sw_if_index, u16 outer_tpid,
                         u16 outer_vlan, u16 inner_tpid, u16 inner_vlan,
                         qinq_match_result_t *result);

const qinq_subport_t *qinq_subport_get_by_rule_id (u32 rule_id);
const char *qinq_error_string (qinq_error_t error);
int qinq_rewrite_two_tags (vlib_buffer_t *buffer,
			   const mac_address_t *dst_mac,
			   const mac_address_t *src_mac, u16 outer_tpid,
			   u16 outer_vlan, u16 inner_tpid, u16 inner_vlan,
			   u16 payload_type);

#endif /* included_vnet_ethernet_qinq_h */
