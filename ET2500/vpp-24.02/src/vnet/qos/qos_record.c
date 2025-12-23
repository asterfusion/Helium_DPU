/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/qos/qos_record.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/feature/feature.h>
#include <vnet/qos/qos_types.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

/**
 * Per-interface, per-protocol vector of feature on/off configurations
 */
u8 *qos_record_configs[QOS_N_SOURCES];
u32 l2_qos_input_next[QOS_N_SOURCES][32];

static void
qos_record_feature_config (u32 sw_if_index,
			   qos_source_t input_source, u8 enable)
{
  switch (input_source)
    {
    case QOS_SOURCE_IP:
      ip_feature_enable_disable (AF_IP6, N_SAFI, IP_FEATURE_INPUT,
				 "ip6-qos-record",
				 sw_if_index, enable, NULL, 0);
      ip_feature_enable_disable (AF_IP4, N_SAFI, IP_FEATURE_INPUT,
				 "ip4-qos-record",
				 sw_if_index, enable, NULL, 0);
      l2input_intf_bitmap_enable (sw_if_index, L2INPUT_FEAT_L2_IP_QOS_RECORD,
				  enable);

      /* Enable for sub_interface start*/
      u32 id, foreach_sw_if_index;
      vnet_main_t *vnet_main = vnet_get_main();
      vnet_hw_interface_t *hw = vnet_get_hw_interface_or_null(vnet_main, sw_if_index);

      if (!hw)
        break;

      hash_foreach(id, foreach_sw_if_index, hw->sub_interface_sw_if_index_by_id, {
        l2input_intf_bitmap_enable(foreach_sw_if_index, L2INPUT_FEAT_L2_IP_QOS_RECORD,
                                   enable);
      });
      /* Enable for sub_interface end*/

      break;
    case QOS_SOURCE_MPLS:
      vnet_feature_enable_disable ("mpls-input", "mpls-qos-record",
				   sw_if_index, enable, NULL, 0);
      break;
    case QOS_SOURCE_VLAN:
      ip_feature_enable_disable (AF_IP6, N_SAFI, IP_FEATURE_INPUT,
				 "vlan-ip6-qos-record",
				 sw_if_index, enable, NULL, 0);
      ip_feature_enable_disable (AF_IP4, N_SAFI, IP_FEATURE_INPUT,
				 "vlan-ip4-qos-record",
				 sw_if_index, enable, NULL, 0);
      vnet_feature_enable_disable ("mpls-input", "vlan-mpls-qos-record",
				   sw_if_index, enable, NULL, 0);
      break;
    case QOS_SOURCE_EXT:
      /* not a valid option for recording */
      break;
    }
}

int
qos_record_enable (u32 sw_if_index, qos_source_t input_source)
{
  vec_validate (qos_record_configs[input_source], sw_if_index);

  if (0 == qos_record_configs[input_source][sw_if_index])
    {
      qos_record_feature_config (sw_if_index, input_source, 1);
    }

  qos_record_configs[input_source][sw_if_index]++;
  return (0);
}

int
qos_record_disable (u32 sw_if_index, qos_source_t input_source)
{
  if (vec_len (qos_record_configs[input_source]) <= sw_if_index)
    return VNET_API_ERROR_NO_MATCHING_INTERFACE;

  if (0 == qos_record_configs[input_source][sw_if_index])
    return VNET_API_ERROR_VALUE_EXIST;

  qos_record_configs[input_source][sw_if_index]--;

  if (0 == qos_record_configs[input_source][sw_if_index])
    {
      qos_record_feature_config (sw_if_index, input_source, 0);
    }

  return (0);
}

void
qos_record_walk (qos_record_walk_cb_t fn, void *c)
{
  qos_source_t qs;

  FOR_EACH_QOS_SOURCE (qs)
  {
    u32 sw_if_index;

    vec_foreach_index (sw_if_index, qos_record_configs[qs])
    {
      if (0 != qos_record_configs[qs][sw_if_index])
	fn (sw_if_index, qs, c);
    }
  }
}

/*
 * Disable recording feature for all protocols when the interface
 * is deleted
 */
static clib_error_t *
qos_record_ip_interface_add_del (vnet_main_t * vnm,
				 u32 sw_if_index, u32 is_add)
{
  if (!is_add)
    {
      qos_source_t qs;

      FOR_EACH_QOS_SOURCE (qs)
      {
	while (qos_record_disable (sw_if_index, qs) == 0);
      }
    }

  return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (qos_record_ip_interface_add_del);

clib_error_t *
qos_record_init (vlib_main_t * vm)
{
  qos_source_t qs;
  vlib_node_t *node = vlib_get_node_by_name (vm, (u8 *) "l2-ip-qos-record");

  /* Initialize the feature next-node indexes */
  FOR_EACH_QOS_SOURCE (qs)
    feat_bitmap_init_next_nodes (vm,
				 node->index,
				 L2INPUT_N_FEAT,
				 l2input_get_feat_names (),
				 l2_qos_input_next[qs]);
  return 0;
}

VLIB_INIT_FUNCTION (qos_record_init);

static clib_error_t *
qos_record_cli (vlib_main_t * vm,
		unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index, qs;
  u8 enable;

  qs = 0xff;
  enable = 1;
  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
      else if (unformat (input, "%U", unformat_qos_source, &qs))
	;
      else if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else
	break;
    }

  if (~0 == sw_if_index)
    return clib_error_return (0, "interface must be specified");
  if (0xff == qs)
    return clib_error_return (0, "input location must be specified");

  if (enable)
    qos_record_enable (sw_if_index, qs);
  else
    qos_record_disable (sw_if_index, qs);

  return (NULL);
}

/*?
 * Enable QoS bit recording on an interface using the packet's input DSCP bits
 * Which input QoS bits to use are either; IP, MPLS or VLAN. If more than
 * one protocol is chosen (which is foolish) the higher layers override the
 * lower.
 *
 * @cliexpar
 * @cliexcmd{qos record ip GigEthernet0/1/0}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_record_command, static) = {
  .path = "qos record",
  .short_help = "qos record <record-source> <INTERFACE> [disable]",
  .function = qos_record_cli,
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

static void
qos_record_show_one_interface (vlib_main_t * vm, u32 sw_if_index)
{
  u8 n_cfgs[QOS_N_SOURCES] = { };
  qos_source_t qs;
  bool set;

  set = false;

  FOR_EACH_QOS_SOURCE (qs)
  {
    if (vec_len (qos_record_configs[qs]) <= sw_if_index)
      continue;
    if (0 != (n_cfgs[qs] = qos_record_configs[qs][sw_if_index]))
      set = true;
  }

  if (set)
    {
      vlib_cli_output (vm, " %U:", format_vnet_sw_if_index_name,
		       vnet_get_main (), sw_if_index);

      FOR_EACH_QOS_SOURCE (qs)
      {
	if (n_cfgs[qs] != 0)
	  vlib_cli_output (vm, "  %U", format_qos_source, qs);
      }
    }
}

static clib_error_t *
qos_record_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  qos_source_t qs;
  u32 sw_if_index;

  sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_vnet_sw_interface,
		    vnm, &sw_if_index))
	;
    }

  if (~0 == sw_if_index)
    {
      u32 ii, n_ints = 0;

      FOR_EACH_QOS_SOURCE (qs)
      {
	n_ints = clib_max (n_ints, vec_len (qos_record_configs[qs]));
      }

      for (ii = 0; ii < n_ints; ii++)
	{
	  qos_record_show_one_interface (vm, ii);
	}
    }
  else
    qos_record_show_one_interface (vm, sw_if_index);

  return (NULL);
}

/*?
 * Show Egress Qos Maps
 *
 * @cliexpar
 * @cliexcmd{show qos egress map}
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (qos_record_show_command, static) = {
  .path = "show qos record",
  .short_help = "show qos record [interface]",
  .function = qos_record_show,
  .is_mp_safe = 1,
};

static clib_error_t*
qos_map_set_dscp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) {
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 dscp, tc;

  if (!unformat(input, " %U %d %d", unformat_vnet_hw_interface, vnm, &hw_if_index, &dscp, &tc)) 
  {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->dscp_to_tc, dscp, tc);

  return error;
}

VLIB_CLI_COMMAND(set_qos_map_dscp_tc_map_command, static) = {
  .path = "set qos-map dscp-to-tc",
  .short_help = "set qos-map dscp-to-tc <hw-interface> <dscp> <tc>",
  .function = qos_map_set_dscp_tc_map,
};

static clib_error_t*
qos_map_set_dot1p_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 dot1p, tc;

  if (!unformat(input, " %U %d %d", unformat_vnet_hw_interface, vnm, &hw_if_index, &dot1p, &tc)) 
  {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->dot1p_to_tc, dot1p, tc);

  return error;
}

VLIB_CLI_COMMAND(set_qos_map_dot1p_tc_map_command, static) = {
  .path = "set qos-map dot1p-to-tc",
  .short_help = "qos-map dot1p-to-tc <interface> <dot1p> <tc>",
  .function = qos_map_set_dot1p_tc_map,
};

static clib_error_t*
qos_map_set_mpls_exp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 mpls_exp, tc;

  if (!unformat(input, " %U %d %d", unformat_vnet_hw_interface, vnm, &hw_if_index, &mpls_exp, &tc)) 
  {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->mpls_exp_to_tc, mpls_exp, tc);

  return error;
}

VLIB_CLI_COMMAND(set_qos_map_mpls_exp_tc_map_command, static) = {
  .path = "set qos-map mplsexp-to-tc",
  .short_help = "qos-map mplsexp-to-tc <interface> <exp> <tc>",
  .function = qos_map_set_mpls_exp_tc_map,
};

static clib_error_t*
qos_map_set_tc_queue_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 queue, tc;

  if (!unformat(input, "%d %d %U",unformat_vnet_hw_interface, vnm, &hw_if_index, &tc, &queue)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_set(hi->tc_to_queue, tc, queue);

  return error;
}

VLIB_CLI_COMMAND(set_qos_map_tc_queue_map_command, static) = {
  .path = "set qos-map tc-to-queue",
  .short_help = "set qos-map tc-to-queue <interface> <tc> <queue>",
  .function = qos_map_set_tc_queue_map,
};

static clib_error_t*
qos_map_del_dscp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->dscp_to_tc);
  hi->dscp_to_tc = NULL;
  return error;
}

VLIB_CLI_COMMAND(delete_qos_map_dscp_tc_map_command, static) = {
  .path = "delete qos-map dscp-to-tc",
  .short_help = "delete qos-map dscp-to-tc <interface>",
  .function = qos_map_del_dscp_tc_map,
};

static clib_error_t*
qos_map_del_dot1p_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->dot1p_to_tc);
  hi->dot1p_to_tc = NULL;
  return error;
}

VLIB_CLI_COMMAND(delete_qos_map_dot1p_tc_map_command, static) = {
  .path = "delete qos-map dot1p-to-tc",
  .short_help = "delete qos-map dot1p-to-tc <interface>",
  .function = qos_map_del_dot1p_tc_map,
};

static clib_error_t*
qos_map_del_mpls_exp_tc_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->mpls_exp_to_tc);
  hi->mpls_exp_to_tc = NULL;
  return error;
}

VLIB_CLI_COMMAND(delete_qos_map_mpls_exp_tc_map_command, static) = {
  .path = "delete qos-map mplsexp-to-tc",
  .short_help = "delete qos-map mplsexp-to-tc <interface>",
  .function = qos_map_del_mpls_exp_tc_map,
};

static clib_error_t*
qos_map_del_tc_queue_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();

  if (!unformat(input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_free(hi->tc_to_queue);

  return error;
}

VLIB_CLI_COMMAND(delete_qos_map_tc_queue_map_command, static) = {
  .path = "delete qos-map tc-to-queue",
  .short_help = "delete qos-map tc-to-queue <interface>",
  .function = qos_map_del_tc_queue_map,
};

static clib_error_t*
qos_map_show_map(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd) 
{
  clib_error_t* error = 0;
  u32 hw_if_index;
  vnet_main_t* vnm = vnet_get_main();
  u32 key, value;

  if (!unformat(input, "%U",unformat_vnet_hw_interface, vnm, &hw_if_index)) {
    return clib_error_return(0, "Please specify interface.");
  }
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, hw_if_index);
  hash_foreach(key, value, hi->tc_to_queue, ({
  vlib_cli_output(vm, "%U tc_to_queue (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  hash_foreach(key, value, hi->dscp_to_tc, ({
  vlib_cli_output(vm, "%U dscp_to_tc (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  hash_foreach(key, value, hi->dot1p_to_tc, ({
  vlib_cli_output(vm, "%U dot1p_to_tc (%d):%d",
      format_vnet_sw_if_index_name, vnm, hw_if_index,
      key,value); }));
  return error;
}

VLIB_CLI_COMMAND(show_qos_map_command, static) = {
  .path = "show qos-map",
  .short_help = "show qos-map <interface>",
  .function = qos_map_show_map,
};

static clib_error_t *
qos_map_set_traffic_class_enable(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u32 hw_if_index = UINT32_MAX;
  vnet_main_t *vnm = vnet_get_main();
  u8 enable_disable = 0;
  u32 flags = 0;
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input(line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat(line_input, "%U", unformat_vnet_hw_interface, vnm, &hw_if_index))
      ;
    else if (unformat(line_input, "enable"))
      enable_disable = 1;
    else if (unformat(line_input, "disable"))
      enable_disable = 0;
    else
    {
      error = clib_error_return(0, "unknown input '%U'",
                                format_unformat_error, line_input);
      goto done;
    }
  }

  if (enable_disable)
  {
    flags |= VNET_HW_INTERFACE_FLAG_USE_TC;
  }
  else
  {
    flags = 0;
  }

  vnet_hw_interface_set_tc_flags(vnm, hw_if_index, flags);

done:
  unformat_free(line_input);
  return error;
}

VLIB_CLI_COMMAND(set_qos_map_tc_traffic_command_command, static) = {
  .path = "set tc-traffic",
  .short_help = "set tc-traffic <interface> [enable|disable]",
  .function = qos_map_set_traffic_class_enable,
};

static clib_error_t *
qos_check_sw_interface_add_del(vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vnet_sw_interface_t *sw = NULL;
  u32 sup_sw_if_index;

  sw = vnet_get_sw_interface_or_null(vnm, sw_if_index);

  if (!sw)
    return 0;

  sup_sw_if_index = sw->sup_sw_if_index;

  if (sup_sw_if_index == sw_if_index)
  {
    return 0;
  }

  if (vec_len(qos_record_configs[QOS_SOURCE_IP]) <= sup_sw_if_index)
    return 0;

  if (qos_record_configs[QOS_SOURCE_IP][sup_sw_if_index])
  {
    if (is_add)
    {
      l2input_intf_bitmap_enable(sw_if_index, L2INPUT_FEAT_L2_IP_QOS_RECORD,
                                 1);
    }
    else
    {
      l2input_intf_bitmap_enable(sw_if_index, L2INPUT_FEAT_L2_IP_QOS_RECORD,
                                 0);
    }
  }

  return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION(qos_check_sw_interface_add_del);

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
