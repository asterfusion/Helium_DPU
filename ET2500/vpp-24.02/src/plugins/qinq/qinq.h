/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef included_qinq_plugin_h
#define included_qinq_plugin_h

#include <vnet/ethernet/qinq.h>

typedef struct
{
  u32 route_id;
  u32 table_id;
  u32 sw_if_index;
  ip4_address_t user_ip4;
} qinq_ipoe_route_t;

typedef struct
{
  u16 msg_id_base;
  qinq_ipoe_route_t *ipoe_routes;
  uword *ipoe_route_by_id;
} qinq_plugin_main_t;

extern qinq_plugin_main_t qinq_plugin_main;

int qinq_ipoe_route_add (const qinq_ipoe_route_t *route);
int qinq_ipoe_route_update (const qinq_ipoe_route_t *route);
int qinq_ipoe_route_delete (u32 route_id);

#endif /* included_qinq_plugin_h */
