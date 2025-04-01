/*
 * isolation_group.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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
#include <vnet/plugin/plugin.h>
#include <isolation_group/isolation_group.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <isolation_group/isolation_group.api_enum.h>
#include <isolation_group/isolation_group.api_types.h>

#define REPLY_MSG_ID_BASE isolation_group_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

isolation_group_main_t isolation_group_main;
isolation_group_t *isolation_groups = NULL;
source_port_group_mapping_t *source_port_group_mappings = NULL;

int find_isolation_group (u32 group_id)
{
    for (int i = 0; i < vec_len (isolation_groups); i++) {
        if (isolation_groups[i].group_id == group_id) {
            return i;
        }
    }
    return -1;
}

int find_source_port_mapping(u32 source_sw_if_index)
{
    for (int i = 0; i < vec_len(source_port_group_mappings); i++) {
        if (source_port_group_mappings[i].source_sw_if_index == source_sw_if_index) {
            return i;
        }
    }
    return -1;
}

int add_destination_port_to_group(u32 group_id, u32 destination_sw_if_index)
{
    int idx = find_isolation_group(group_id);
    if (idx != -1) {
        for (int i = 0; i < isolation_groups[idx].num_destinations; i++) {
            if (isolation_groups[idx].destination_sw_if_indices[i] == destination_sw_if_index) {
                return -1; 
            }
        }
        vec_add1(isolation_groups[idx].destination_sw_if_indices, destination_sw_if_index);
        isolation_groups[idx].num_destinations++;
        return 0;
    }
    return -1; 
}

int set_source_port_group_mapping(u32 source_sw_if_index, u32 group_id)
{
    int mapping_index = find_source_port_mapping(source_sw_if_index);
    if (mapping_index != -1) {
        source_port_group_mappings[mapping_index].group_id = group_id;
    } else {
        source_port_group_mapping_t mapping = {
           .source_sw_if_index = source_sw_if_index,
           .group_id = group_id
        };
        vec_add1(source_port_group_mappings, mapping);
        clib_warning ("source sw if index is %d, group id is %d", source_sw_if_index, group_id);

    }
    return 0;
}

int delete_source_port_group_mapping(u32 source_sw_if_index)
{
    int mapping_index = find_source_port_mapping(source_sw_if_index);
    if (mapping_index != -1) {
        vec_del1(source_port_group_mappings, mapping_index);
        return 0; 
    }
    return -1;
}

/* Action function shared between message handler and debug CLI */

int isolation_group_enable_disable (isolation_group_main_t * imp, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (imp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (imp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  isolation_group_create_periodic_process (imp);

  vnet_feature_enable_disable ("interface-output", "isolation_group",
                               sw_if_index, enable_disable, 0, 0);

  /* Send an event to enable/disable the periodic scanner process */
  vlib_process_signal_event (imp->vlib_main,
                             imp->periodic_node_index,
                             ISOLATION_GROUP_EVENT_PERIODIC_ENABLE_DISABLE,
                            (uword)enable_disable);
  return rv;
}

static clib_error_t *
isolation_group_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  isolation_group_main_t * imp = &isolation_group_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         imp->vnet_main, &sw_if_index))
        ;
      else
        break;
  }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = isolation_group_enable_disable (imp, sw_if_index, enable_disable);

  switch(rv)
    {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return
      (0, "Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (0, "Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "isolation_group_enable_disable returned %d",
                              rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (isolation_group_enable_disable_command, static) =
{
  .path = "isolation_group enable-disable",
  .short_help =
  "isolation_group enable-disable <interface-name> [disable]",
  .function = isolation_group_enable_disable_command_fn,
};
/* *INDENT-ON* */

/* API message handler */
static void vl_api_isolation_group_enable_disable_t_handler
(vl_api_isolation_group_enable_disable_t * mp)
{
  vl_api_isolation_group_enable_disable_reply_t * rmp;
  isolation_group_main_t * imp = &isolation_group_main;
  int rv;

  rv = isolation_group_enable_disable (imp, ntohl(mp->sw_if_index),
                                      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_ISOLATION_GROUP_ENABLE_DISABLE_REPLY);
}

static void
vl_api_isolation_group_t_handler (vl_api_isolation_group_t * mp)
{
    vl_api_isolation_group_reply_t *rmp;
    int rv = 0;

    u32 group_id = ntohl (mp->group_id);
    u32 sw_if_index = ntohl (mp->sw_if_index);
    bool is_add = (mp->is_add);
    clib_warning("isolation group passed group id is %d, swifindex is %d", group_id, sw_if_index);
    if (sw_if_index == ~0 && is_add == true) {
      clib_warning("add isolation group");
      isolation_group_t ig;
      ig.group_id = group_id;
      ig.num_destinations = 0;
      ig.destination_sw_if_indices = 0;
      vec_add1 (isolation_groups, ig);
      
    }
    else if (sw_if_index == ~0 && is_add == false) {
      clib_warning("delete isolation group");
      int idx = find_isolation_group(group_id);
      if (idx != -1) {
          vec_free(isolation_groups[idx].destination_sw_if_indices);
          vec_del1(isolation_groups, idx);

          for (int i = 0; i < vec_len(source_port_group_mappings); i++) {
              if (source_port_group_mappings[i].group_id == group_id) {
                  vec_del1(source_port_group_mappings, i);
                  i--;
              }
          }
      }
    }
    else if (sw_if_index != ~0 && is_add == true) {
      clib_warning("add isolation group member");
      int idx = find_isolation_group(group_id);
      if (idx != -1) {
        for (int i = 0; i < isolation_groups[idx].num_destinations; i++) {
          if (isolation_groups[idx].destination_sw_if_indices[i] == sw_if_index) {
              rv = -1;
              break; 
          }
        }
        if(rv == 0)
        {
          vec_add1(isolation_groups[idx].destination_sw_if_indices, sw_if_index);
        } 
      }
    }
    else if (sw_if_index != ~0 && is_add == false) {
      clib_warning("delete isolation group member");
      int idx = find_isolation_group(group_id);
      if (idx != -1) {
        for (int i = 0; i < isolation_groups[idx].num_destinations; i++) {
          if (isolation_groups[idx].destination_sw_if_indices[i] == sw_if_index) {
              vec_del1(isolation_groups[idx].destination_sw_if_indices, i);
              break; 
          }
        }
      }
    }
    REPLY_MACRO (VL_API_ISOLATION_GROUP_REPLY);
}

static void
vl_api_isolation_group_set_source_port_t_handler(vl_api_isolation_group_set_source_port_t *mp)
{
    vl_api_isolation_group_set_source_port_reply_t *rmp;
    int rv = 0;

    u32 source_sw_if_index = ntohl(mp->source_sw_if_index);
    u32 group_id = ntohl(mp->group_id);
    bool is_add = (mp->is_add);

    if(is_add)
    {
      if (set_source_port_group_mapping(source_sw_if_index, group_id) != 0) {
        rv = -1;
      }
    }
    else
    {
      if (delete_source_port_group_mapping(source_sw_if_index) != 0) {
        rv = -1;
      }
    }

    find_isolation_group(group_id);

    REPLY_MACRO(VL_API_ISOLATION_GROUP_SET_SOURCE_PORT_REPLY);
}

/* API definitions */
#include <isolation_group/isolation_group.api.c>

static clib_error_t * isolation_group_init (vlib_main_t * vm)
{
  isolation_group_main_t * imp = &isolation_group_main;
  clib_error_t * error = 0;

  imp->vlib_main = vm;
  imp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  imp->msg_id_base = setup_message_id_table ();

  return error;
}

VLIB_INIT_FUNCTION (isolation_group_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (isolation_group, static) =
{
  .arc_name = "interface-output",
  .node_name = "isolation_group",
  .runs_before = VNET_FEATURES ("interface-output"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "isolation group",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */