/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2020 Rubicon Communications, LLC.
 *
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

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>

#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/linux-cp/lcp_match.h>
#include <plugins/linux-cp/lcp_policy.h>
#include <plugins/linux-cp/lcp_stats.h>

static clib_error_t *
lcp_itf_pair_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  u8 *host_if_name = NULL;
  lip_host_type_t host_if_type = LCP_ITF_HOST_TAP;
  u8 *ns = NULL;
  clib_error_t *error = NULL;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d", &sw_if_index))
	    ;
	  else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else if (unformat (line_input, "host-if %s", &host_if_name))
	    ;
	  else if (unformat (line_input, "netns %s", &ns))
	    ;
	  else if (unformat (line_input, "tun"))
	    host_if_type = LCP_ITF_HOST_TUN;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error)
    ;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");
  else if (!host_if_name)
    error = clib_error_return (0, "host interface name required");
  else if (vec_len (ns) >= LCP_NS_LEN)
    error = clib_error_return (
      0, "Namespace name should be fewer than %d characters", LCP_NS_LEN);
  else
    {
      int r;

      r = lcp_itf_pair_create (sw_if_index, host_if_name, host_if_type, ns,
			       NULL);
      if (r)
	error = clib_error_return (0, "linux-cp pair creation failed (%d)", r);
    }

  vec_free (host_if_name);
  vec_free (ns);

  return error;
}

VLIB_CLI_COMMAND (lcp_itf_pair_create_command, static) = {
  .path = "lcp create",
  .short_help = "lcp create <sw_if_index>|<if-name> host-if <host-if-name> "
		"netns <namespace> [tun]",
  .function = lcp_itf_pair_create_command_fn,
};

static clib_error_t *
lcp_sync_command_fn (vlib_main_t *vm, unformat_input_t *input,
		     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	lcp_set_sync (1);
      else if (unformat (line_input, "off") ||
	       unformat (line_input, "disable"))
	lcp_set_sync (0);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_sync_command, static) = {
  .path = "lcp lcp-sync",
  .short_help = "lcp lcp-sync [on|enable|off|disable]",
  .function = lcp_sync_command_fn,
};

static clib_error_t *
lcp_auto_subint_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "on") || unformat (line_input, "enable"))
	lcp_set_auto_subint (1);
      else if (unformat (line_input, "off") ||
	       unformat (line_input, "disable"))
	lcp_set_auto_subint (0);
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_auto_subint_command, static) = {
  .path = "lcp lcp-auto-subint",
  .short_help = "lcp lcp-auto-subint [on|enable|off|disable]",
  .function = lcp_auto_subint_command_fn,
};

static clib_error_t *
lcp_param_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del-static-on-link-down"))
	{
	  if (unformat (line_input, "on") || unformat (line_input, "enable"))
	    lcp_set_del_static_on_link_down (1 /* is_del */);
	  else if (unformat (line_input, "off") ||
		   unformat (line_input, "disable"))
	    lcp_set_del_static_on_link_down (0 /* is_del */);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      else if (unformat (line_input, "del-dynamic-on-link-down"))
	{
	  if (unformat (line_input, "on") || unformat (line_input, "enable"))
	    lcp_set_del_dynamic_on_link_down (1 /* is_del */);
	  else if (unformat (line_input, "off") ||
		   unformat (line_input, "disable"))
	    lcp_set_del_dynamic_on_link_down (0 /* is_del */);
	  else
	    return clib_error_return (0, "unknown input `%U'",
				      format_unformat_error, line_input);
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }

  unformat_free (line_input);
  return 0;
}

VLIB_CLI_COMMAND (lcp_param_command, static) = {
  .path = "lcp param",
  .short_help = "lcp param [del-static-on-link-down (on|enable|off|disable)] "
		"[del-dynamic-on-link-down (on|enable|off|disable)]",
  .function = lcp_param_command_fn,
};

static clib_error_t *
lcp_default_netns_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *ns;
  int r;
  clib_error_t *error = NULL;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  ns = 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "netns %s", &ns))
	;
      else if (unformat (line_input, "clear netns"))
	;
      else
	{
	  vec_free (ns);
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  vlib_cli_output (vm, "lcp set default netns '%s'\n", (char *) ns);

  r = lcp_set_default_ns (ns);

  if (r)
    return clib_error_return (0, "linux-cp set default netns failed (%d)", r);

done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (lcp_default_netns_command, static) = {
  .path = "lcp default",
  .short_help = "lcp default netns [<namespace>]",
  .function = lcp_default_netns_command_fn,
};

static clib_error_t *
lcp_itf_pair_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "%d", &sw_if_index))
	    ;
	  else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error)
    ;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");
  else
    {
      int r;

      r = lcp_itf_pair_delete (sw_if_index);
      if (r)
	error = clib_error_return (0, "linux-cp pair deletion failed (%d)", r);
    }

  return error;
}

VLIB_CLI_COMMAND (lcp_itf_pair_delete_command, static) = {
  .path = "lcp delete",
  .short_help = "lcp delete <sw_if_index>|<if-name>",
  .function = lcp_itf_pair_delete_command_fn,
};

static clib_error_t *
lcp_itf_pair_show_cmd (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 phy_sw_if_index;

  phy_sw_if_index = ~0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "phy %U", unformat_vnet_sw_interface, vnm,
		    &phy_sw_if_index))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  lcp_itf_pair_show (phy_sw_if_index);

  return 0;
}

VLIB_CLI_COMMAND (lcp_itf_pair_show_cmd_node, static) = {
  .path = "show lcp",
  .function = lcp_itf_pair_show_cmd,
  .short_help = "show lcp [phy <interface>]",
  .is_mp_safe = 1,
};

static clib_error_t *
lcp_copp_traps_show_cmd (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u32 trap_id;

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input '%U'", format_unformat_error,
			      input);

  vlib_cli_output (vm, "%-7s %-24s %-10s %-8s %-10s %-8s %-8s", "trap_id",
		   "name", "programmed", "action", "policer", "default",
		   "priority");

  for (trap_id = LCP_TRAP_INVALID + 1; trap_id < LCP_POLICY_N_TRAPS;
       trap_id++)
    {
      const lcp_trap_desc_t *desc =
	lcp_trap_desc_get ((vl_api_lcp_trap_type_t) trap_id);
      const lcp_policy_entry_t *policy;

      policy = lcp_policy_get ((vl_api_lcp_trap_type_t) trap_id);
      if (policy->policer_index == LCP_POLICY_INDEX_INVALID)
	vlib_cli_output (
	  vm, "%-7u %-24s %-10s %-8u %-10s %-8u %-8u", trap_id,
	  desc->name,
	  lcp_policy_is_configured ((vl_api_lcp_trap_type_t) trap_id) ?
	    "yes" :
	    "no",
	  policy->action, "none", desc->default_priority, policy->priority);
      else
	vlib_cli_output (
	  vm, "%-7u %-24s %-10s %-8u %-10u %-8u %-8u", trap_id,
	  desc->name,
	  lcp_policy_is_configured ((vl_api_lcp_trap_type_t) trap_id) ?
	    "yes" :
	    "no",
	  policy->action, policy->policer_index, desc->default_priority,
	  policy->priority);
    }

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_traps_show_cmd_node, static) = {
  .path = "show lcp copp traps",
  .function = lcp_copp_traps_show_cmd,
  .short_help = "show lcp copp traps",
};

static clib_error_t *
lcp_copp_matchers_show_cmd (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input '%U'", format_unformat_error,
			      input);

  vlib_cli_output (vm, "%-5s %-30s %-5s %-10s %-10s", "id", "name",
		   "trap", "contexts", "fields");
  for (u32 i = 0; i < lcp_match_rule_count (); i++)
    {
      const lcp_match_rule_t *rule = lcp_match_rule_get (i);

      vlib_cli_output (vm, "%-5u %-30s %-5u 0x%08x 0x%08x",
		       rule->rule_id, rule->name, rule->trap_type,
		       rule->context_mask, rule->required_fields);
    }
  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_matchers_show_cmd_node, static) = {
  .path = "show lcp copp matchers",
  .function = lcp_copp_matchers_show_cmd,
  .short_help = "show lcp copp matchers",
};

static clib_error_t *
lcp_copp_stats_show_cmd (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  u32 trap_id;
  static const char *counter_names[] = {
    [LCP_STATS_TRAP_HIT] = "trap_hit",
    [LCP_STATS_PUNT_REQUIRED] = "punt_required",
    [LCP_STATS_PUNT_PASS] = "punt_pass",
    [LCP_STATS_PUNT_DROP] = "punt_drop",
    [LCP_STATS_DELIVERY_DROP] = "delivery_drop",
  };

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input '%U'", format_unformat_error,
			      input);

  vlib_cli_output (vm, "%-7s %-10s %-10s %-10s %-10s %-10s", "trap_id",
		   counter_names[LCP_STATS_TRAP_HIT],
		   counter_names[LCP_STATS_PUNT_REQUIRED],
		   counter_names[LCP_STATS_PUNT_PASS],
		   counter_names[LCP_STATS_PUNT_DROP],
		   counter_names[LCP_STATS_DELIVERY_DROP]);

  for (trap_id = 0; trap_id < LCP_POLICY_N_TRAPS; trap_id++)
    {
      vlib_cli_output (
	vm, "%-7u %-10llu %-10llu %-10llu %-10llu %-10llu", trap_id,
	(long long) lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id,
				   LCP_STATS_TRAP_HIT),
	(long long) lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id,
				   LCP_STATS_PUNT_REQUIRED),
	(long long) lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id,
				   LCP_STATS_PUNT_PASS),
	(long long) lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id,
				   LCP_STATS_PUNT_DROP),
	(long long) lcp_stats_get ((vl_api_lcp_trap_type_t) trap_id,
				   LCP_STATS_DELIVERY_DROP));
    }

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_stats_show_cmd_node, static) = {
  .path = "show lcp copp stats",
  .function = lcp_copp_stats_show_cmd,
  .short_help = "show lcp copp stats",
};

static clib_error_t *
lcp_copp_stats_clear_cmd (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input '%U'", format_unformat_error,
			      input);

  vlib_worker_thread_barrier_sync (vm);
  lcp_stats_clear ();
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_stats_clear_cmd_node, static) = {
  .path = "clear lcp copp stats",
  .function = lcp_copp_stats_clear_cmd,
  .short_help = "clear lcp copp stats",
};

static clib_error_t *
lcp_copp_trap_set_command_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 trap_id = ~0;
  u32 action = ~0;
  u32 priority = 0;
  u32 policer_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "trap_id %u", &trap_id))
	;
      else if (unformat (line_input, "action %u", &action))
	;
      else if (unformat (line_input, "priority %u", &priority))
	;
      else if (unformat (line_input, "policer %u", &policer_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (trap_id == ~0)
    return clib_error_return (0, "trap_id required");
  if (action == ~0)
    return clib_error_return (0, "action required");

  vlib_worker_thread_barrier_sync (vm);
  rv = lcp_policy_add ((vl_api_lcp_trap_type_t) trap_id, (u8) action, priority,
		       policer_index);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    return clib_error_return (0, "CoPP trap add failed (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_trap_set_command, static) = {
  .path = "set lcp copp trap",
  .short_help = "set lcp copp trap trap_id <id> action <0..3> "
		"priority <n> policer <index>",
  .function = lcp_copp_trap_set_command_fn,
};

static clib_error_t *
lcp_copp_trap_update_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 trap_id = ~0;
  u32 action = ~0;
  u32 priority = 0;
  u32 policer_index = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "trap_id %u", &trap_id))
	;
      else if (unformat (line_input, "action %u", &action))
	;
      else if (unformat (line_input, "priority %u", &priority))
	;
      else if (unformat (line_input, "policer %u", &policer_index))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, line_input);
    }
  unformat_free (line_input);

  if (trap_id == ~0)
    return clib_error_return (0, "trap_id required");
  if (action == ~0)
    return clib_error_return (0, "action required");

  vlib_worker_thread_barrier_sync (vm);
  rv = lcp_policy_update ((vl_api_lcp_trap_type_t) trap_id, (u8) action,
			  priority, policer_index);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    return clib_error_return (0, "CoPP trap update failed (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_trap_update_command, static) = {
  .path = "update lcp copp trap",
  .short_help = "update lcp copp trap trap_id <id> action <0..3> "
		"priority <n> policer <index>",
  .function = lcp_copp_trap_update_command_fn,
};

static clib_error_t *
lcp_copp_trap_delete_command_fn (vlib_main_t *vm, unformat_input_t *input,
				 vlib_cli_command_t *cmd)
{
  u32 trap_id = ~0;
  int rv;

  if (!unformat (input, "trap_id %u", &trap_id))
    return clib_error_return (0, "trap_id required");

  vlib_worker_thread_barrier_sync (vm);
  rv = lcp_policy_delete ((vl_api_lcp_trap_type_t) trap_id);
  vlib_worker_thread_barrier_release (vm);

  if (rv)
    return clib_error_return (0, "CoPP trap delete failed (%d)", rv);

  return 0;
}

VLIB_CLI_COMMAND (lcp_copp_trap_delete_command, static) = {
  .path = "delete lcp copp trap",
  .short_help = "delete lcp copp trap trap_id <id>",
  .function = lcp_copp_trap_delete_command_fn,
};

#ifdef SUPPORT_LCP_VLAN_TAG_ACT
static clib_error_t *
lcp_itf_pair_set_vlan_tag_cmd (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  lcp_itf_pair_t *pair = NULL;
  lip_host_vlan_tag_e type = LCP_ITF_HOST_VLAN_TAG_ORIGINAL;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "phy %U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else if (unformat (line_input, "vlan_tag strip"))
          type = LCP_ITF_HOST_VLAN_TAG_STRIP;
	  else if (unformat (line_input, "vlan_tag keep"))
          type = LCP_ITF_HOST_VLAN_TAG_KEEP;
	  else if (unformat (line_input, "vlan_tag orig"))
          type = LCP_ITF_HOST_VLAN_TAG_ORIGINAL;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error) return error;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");

  pair = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw_if_index));

  if (pair)
  {
      pair->lip_host_vlan_tag = type;
  }
  else
  {
    error = clib_error_return (0, "interface name or sw_if_index not has lcp_itf_pair");
  }
  return error;
}


VLIB_CLI_COMMAND (lcp_itf_pair_set_vlan_tag_cmd_node, static) = {
  .path = "lcp set vlan-tag",
  .function = lcp_itf_pair_set_vlan_tag_cmd,
  .short_help = "lcp set vlan-tag phy <interface> vlan_tag (strip|keep|orig)",
};

static clib_error_t *
lcp_itf_pair_set_pvlan_cmd (vlib_main_t *vm, unformat_input_t *input,
				vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = ~0;
  clib_error_t *error = NULL;
  lcp_itf_pair_t *pair = NULL;
  u16 pvlan = 0xffff;

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "phy %U", unformat_vnet_sw_interface, vnm,
			     &sw_if_index))
	    ;
	  else if (unformat (line_input, "pvlan %u", &pvlan))
	    ;
	  else
	    {
	      error = clib_error_return (0, "unknown input `%U'",
					 format_unformat_error, line_input);
	      break;
	    }
	}
      unformat_free (line_input);
    }

  if (error) return error;
  else if (sw_if_index == ~0)
    error = clib_error_return (0, "interface name or sw_if_index required");

  pair = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw_if_index));

  if (pair)
  {
      pair->lip_host_pvlan = pvlan;
  }
  else
  {
    error = clib_error_return (0, "interface name or sw_if_index not has lcp_itf_pair");
  }
  return error;
}

VLIB_CLI_COMMAND (lcp_itf_pair_set_pvlan_cmd_node, static) = {
  .path = "lcp set pvlan",
  .function = lcp_itf_pair_set_pvlan_cmd,
  .short_help = "lcp set pvlan phy <interface> pvlan <pvlan>",
};
#endif

clib_error_t *
lcp_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (lcp_cli_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
