/*
 * l2_cast_policer_api.c - l2 cast policer api
 *
 * Copyright 2024-2027 Asterfusion Network
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vnet/vnet.h>
#include <vnet/interface.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#include <l2_cast_policer/l2_cast_policer.api_enum.h>
#include <l2_cast_policer/l2_cast_policer.api_types.h>

#define REPLY_MSG_ID_BASE l2_cast_policer_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <l2_cast_policer/l2_cast_policer.h>

static void
vl_api_l2_mcast_policer_set_interface_t_handler (
  vl_api_l2_mcast_policer_set_interface_t *mp)
{
  int rv;
  vl_api_l2_mcast_policer_set_interface_reply_t *rmp;

  rv = l2_mcast_policer_set_interface (ntohl (mp->sw_if_index),
				       ntohl (mp->policer_index));

  REPLY_MACRO (VL_API_L2_MCAST_POLICER_SET_INTERFACE_REPLY);
}

static void
vl_api_l2_bcast_policer_set_interface_t_handler (
  vl_api_l2_bcast_policer_set_interface_t *mp)
{
  int rv;
  vl_api_l2_bcast_policer_set_interface_reply_t *rmp;

  rv = l2_bcast_policer_set_interface (ntohl (mp->sw_if_index),
				       ntohl (mp->policer_index));

  REPLY_MACRO (VL_API_L2_BCAST_POLICER_SET_INTERFACE_REPLY);
}

#include <vnet/format_fns.h>
#include <l2_cast_policer/l2_cast_policer.api.c>

clib_error_t *
l2_cast_policer_api_hookup (vlib_main_t *vm)
{
  l2_cast_policer_main_t *lcpm = &l2_cast_policer_main;

  lcpm->msg_id_base = setup_message_id_table ();
  return 0;
}
