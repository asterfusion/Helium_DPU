/*
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

/**
 * @file
 * @brief Security CLI
 */

#include <security_check/security.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/ip46_address.h>

#define SECURITY_CHECK_EXPECTED_ARGUMENT "expected required argument(s)"

u8 *
format_snooping_table_entry (u8 * s, va_list * args)
{
    vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
    snp_entry_t *entry = va_arg (*args, snp_entry_t *);

    s = format (s, "vlan %u\t", entry->vlan_id);

    s = format (s, "mac %U\t", format_ethernet_address, entry->mac.bytes);

    s = format (s, "ip %U\t", format_ip46_address, &entry->ip46);

    s =  format (s, "intf %U\t", format_vnet_sw_interface_name, vnm, vnet_get_sw_interface_or_null (vnm, entry->interface));

    if (entry->interface != entry->sup_interface)
    {
        s =  format (s, "sup-intf %U\t", format_vnet_sw_interface_name, vnm, vnet_get_sw_interface_or_null (vnm, entry->sup_interface));
    }
    return s;
}

static clib_error_t *
security_check_table_show_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    security_check_main_t *secm = &security_check_main;
    vnet_main_t *vnm = vnet_get_main ();
    snp_entry_t *entry;

    vlib_cli_output (vm, "Snooping Table Entrys:");
    pool_foreach (entry, secm->snp_entry_pool)
    {
        vlib_cli_output (vm, " %U", format_snooping_table_entry, vnm, entry);
    }
  return 0;
}

VLIB_CLI_COMMAND (security_check_table_show_command, static) = {
  .path = "security-check table show",
  .short_help = "security-check table show",
  .function = security_check_table_show_fn,
};

static clib_error_t *
security_check_table_add_del_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id; 
    ip46_address_t ip46_addr;
    mac_address_t mac;
    u32 sw_if_index;

    u8 is_add = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "vlan %u", &vlan_id));
        else if (unformat (line_input, "mac %U", unformat_ethernet_address, mac.bytes));
        else if (unformat (line_input, "ip %U", unformat_ip46_address, &ip46_addr));
        else if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "del")) is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }
    rv = snooping_table_add_del(vlan_id, &ip46_addr, &mac, sw_if_index, is_add);
    if(rv)
    {
        clib_error_return (0, "%s snooping table entry failed (rv = %d).", is_add ? "add" : "del", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{security-check table add}
 * Add/delete snooping table.
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_table_add_del_command, static) = {
  .path = "security-check table add",
  .short_help = "security-check table add vlan <vlan-id> mac <mac-address> ip <ip-address> intf <intf> [del]",
  .function = security_check_table_add_del_fn,
};


static clib_error_t *
security_check_dai_enable_disable_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index = ~0;

    u8 is_enable = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "bridge %u", &vlan_id));
        else if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "disable")) is_enable = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id != ~0 && vlan_id <= SECURITY_CHECK_VLAN_NUM)
    {
        rv = security_check_vlan_enable_disable(vlan_id, SECURITY_CHECK_TYPE_DAI, is_enable);
        if(rv)
        {
            clib_error_return (0, "vlan %u : %s dai-check failed (rv = %d).", vlan_id, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }

    if (sw_if_index != ~0)
    {
        rv = security_check_enable_disable(sw_if_index, SECURITY_CHECK_TYPE_DAI, is_enable);
        if(rv)
        {
            clib_error_return (0, "%U : %s dai-check failed (rv = %d).", format_vnet_sw_if_index_name, sw_if_index, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }
done:
  unformat_free (line_input);

  return error;
}


/*?
 * @cliexpar
 * @cliexstart{security-check dai}
 * dai config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_dai_enable_disable_command, static) = {
  .path = "security-check dai",
  .short_help = "security-check dai {intf <sw_if_index> | bridge <bd_id> } [disable]",
  .function = security_check_dai_enable_disable_fn,
};


static clib_error_t *
security_check_dai_vlan_trust_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index, *sw_if_indices = 0;

    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "vlan %u", &vlan_id));
        else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else if (unformat (line_input, "%u", &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id == ~0 || vlan_id > SECURITY_CHECK_VLAN_NUM)
        goto done;

    rv = security_check_vlan_trust_intf_set(vlan_id, SECURITY_CHECK_TYPE_DAI, vec_len (sw_if_indices), sw_if_indices);
    if(rv)
    {
        clib_error_return (0, "vlan %u : set trust intf dai-check failed (rv = %d).", vlan_id, rv);
        goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * @cliexpar
 * @cliexstart{security-check dai}
 * dai config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_dai_vlan_trust_intf_command, static) = {
  .path = "security-check dai vlan-trust",
  .short_help = "security-check dai vlan-trust vlan <vlan_id> [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = security_check_dai_vlan_trust_fn,
};


static clib_error_t *
security_check_savi_enable_disable_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index = ~0;

    u8 is_enable = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "bridge %u", &vlan_id));
        else if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "disable")) is_enable = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id != ~0 && vlan_id <= SECURITY_CHECK_VLAN_NUM)
    {
        rv = security_check_vlan_enable_disable(vlan_id, SECURITY_CHECK_TYPE_SAVI, is_enable);
        if(rv)
        {
            clib_error_return (0, "vlan %u : %s savi-check failed (rv = %d).", vlan_id, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }

    if (sw_if_index != ~0)
    {
        rv = security_check_enable_disable(sw_if_index, SECURITY_CHECK_TYPE_SAVI, is_enable);
        if(rv)
        {
            clib_error_return (0, "%U : %s savi-check failed (rv = %d).", format_vnet_sw_if_index_name, sw_if_index, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }
done:
  unformat_free (line_input);

  return error;
}


/*?
 * @cliexpar
 * @cliexstart{security-check savi}
 * savi config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_savi_enable_disable_command, static) = {
  .path = "security-check savi",
  .short_help = "security-check savi {intf <sw_if_index> | bridge <bd_id> } [disable]",
  .function = security_check_savi_enable_disable_fn,
};


static clib_error_t *
security_check_savi_vlan_trust_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index, *sw_if_indices = 0;

    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "vlan %u", &vlan_id));
        else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else if (unformat (line_input, "%u", &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id == ~0 || vlan_id > SECURITY_CHECK_VLAN_NUM)
        goto done;

    rv = security_check_vlan_trust_intf_set(vlan_id, SECURITY_CHECK_TYPE_SAVI, vec_len (sw_if_indices), sw_if_indices);
    if(rv)
    {
        clib_error_return (0, "vlan %u : set trust intf savi-check failed (rv = %d).", vlan_id, rv);
        goto done;
    }

done:
  unformat_free (line_input);

  return error;
}



/*?
 * @cliexpar
 * @cliexstart{security-check savi}
 * savi config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_savi_vlan_trust_intf_command, static) = {
  .path = "security-check savi vlan-trust",
  .short_help = "security-check savi vlan-trust vlan <vlan_id> [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = security_check_savi_vlan_trust_fn,
};


static clib_error_t *
security_check_ipsg_enable_disable_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index = ~0;

    u8 is_enable = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "bridge %u", &vlan_id));
        else if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "disable")) is_enable = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id != ~0 && vlan_id <= SECURITY_CHECK_VLAN_NUM)
    {
        rv = security_check_vlan_enable_disable(vlan_id, SECURITY_CHECK_TYPE_IPSG, is_enable);
        if(rv)
        {
            clib_error_return (0, "vlan %u : %s ipsg-check failed (rv = %d).", vlan_id, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }

    if (sw_if_index != ~0)
    {
        rv = security_check_enable_disable(sw_if_index, SECURITY_CHECK_TYPE_IPSG, is_enable);
        if(rv)
        {
            clib_error_return (0, "%U : %s ipsg-check failed (rv = %d).", format_vnet_sw_if_index_name, sw_if_index, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }
done:
  unformat_free (line_input);

  return error;
}


/*?
 * @cliexpar
 * @cliexstart{security-check ipsg}
 * ipsg config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_ipsg_enable_disable_command, static) = {
  .path = "security-check ipsg",
  .short_help = "security-check ipsg {intf <sw_if_index> | bridge <bd_id> } [disable]",
  .function = security_check_ipsg_enable_disable_fn,
};


static clib_error_t *
security_check_ipsg_vlan_trust_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index, *sw_if_indices = 0;

    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "vlan %u", &vlan_id));
        else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else if (unformat (line_input, "%u", &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id == ~0 || vlan_id > SECURITY_CHECK_VLAN_NUM)
        goto done;

    rv = security_check_vlan_trust_intf_set(vlan_id, SECURITY_CHECK_TYPE_IPSG, vec_len (sw_if_indices), sw_if_indices);
    if(rv)
    {
        clib_error_return (0, "vlan %u : set trust intf ipsg-check failed (rv = %d).", vlan_id, rv);
        goto done;
    }

done:
  unformat_free (line_input);

  return error;
}



/*?
 * @cliexpar
 * @cliexstart{security-check ipsg}
 * ipsg config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_ipsg_vlan_trust_intf_command, static) = {
  .path = "security-check ipsg vlan-trust",
  .short_help = "security-check ipsg vlan-trust vlan <vlan_id> [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = security_check_ipsg_vlan_trust_fn,
};


static clib_error_t *
security_check_ipsgv6_enable_disable_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index = ~0;

    u8 is_enable = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "bridge %u", &vlan_id));
        else if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "disable")) is_enable = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id != ~0 && vlan_id <= SECURITY_CHECK_VLAN_NUM)
    {
        rv = security_check_vlan_enable_disable(vlan_id, SECURITY_CHECK_TYPE_IPSGV6, is_enable);
        if(rv)
        {
            clib_error_return (0, "vlan %u : %s ipsgv6-check failed (rv = %d).", vlan_id, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }

    if (sw_if_index != ~0)
    {
        rv = security_check_enable_disable(sw_if_index, SECURITY_CHECK_TYPE_IPSGV6, is_enable);
        if(rv)
        {
            clib_error_return (0, "%U : %s ipsgv6-check failed (rv = %d).", format_vnet_sw_if_index_name, sw_if_index, is_enable ? "enable" : "disable", rv);
            goto done;
        }
    }
done:
  unformat_free (line_input);

  return error;
}


/*?
 * @cliexpar
 * @cliexstart{security-check ipsgv6}
 * ipsgv6 config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_ipsgv6_enable_disable_command, static) = {
  .path = "security-check ipsgv6",
  .short_help = "security-check ipsgv6 {intf <sw_if_index> | bridge <bd_id> } [disable]",
  .function = security_check_ipsgv6_enable_disable_fn,
};


static clib_error_t *
security_check_ipsgv6_vlan_trust_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 vlan_id = ~0; 
    u32 sw_if_index, *sw_if_indices = 0;

    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "vlan %u", &vlan_id));
        else if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else if (unformat (line_input, "%u", &sw_if_index))
            vec_add1 (sw_if_indices, sw_if_index);
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (vlan_id == ~0 || vlan_id > SECURITY_CHECK_VLAN_NUM)
        goto done;

    rv = security_check_vlan_trust_intf_set(vlan_id, SECURITY_CHECK_TYPE_IPSGV6, vec_len (sw_if_indices), sw_if_indices);
    if(rv)
    {
        clib_error_return (0, "vlan %u : set trust intf ipsgv6-check failed (rv = %d).", vlan_id, rv);
        goto done;
    }

done:
  unformat_free (line_input);

  return error;
}



/*?
 * @cliexpar
 * @cliexstart{security-check ipsgv6}
 * ipsgv6 config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_ipsgv6_vlan_trust_intf_command, static) = {
  .path = "security-check ipsgv6 vlan-trust",
  .short_help = "security-check ipsgv6 vlan-trust vlan <vlan_id> [<interface> [<interface> [..]]] [<sw_idx> [<sw_idx> [..]]]",
  .function = security_check_ipsgv6_vlan_trust_fn,
};



static clib_error_t *
security_check_raguard_role_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;

    u32 sw_if_index = ~0;

    u32 role = RAGUARD_ROLE_NONE;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SECURITY_CHECK_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "intf %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "role none"))
            role = RAGUARD_ROLE_NONE;
        else if (unformat (line_input, "role router"))
            role = RAGUARD_ROLE_ROUTER;
        else if (unformat (line_input, "role user"))
            role = RAGUARD_ROLE_USER;
        else if (unformat (line_input, "role hybrid"))
            role = RAGUARD_ROLE_HYBRID;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    rv = security_check_ragurad_role(sw_if_index, role);
    if(rv)
    {
        clib_error_return (0, "%U : set raguard role failed (rv = %d).", format_vnet_sw_if_index_name, sw_if_index, rv);
        goto done;
    }
done:
  unformat_free (line_input);
  return error;
}

/*?
 * @cliexpar
 * @cliexstart{security-check raguard}
 * raguard config
 * @cliexend
?*/
VLIB_CLI_COMMAND (security_check_raguard_role_command, static) = {
  .path = "security-check raguard",
  .short_help = "security-check raguard intf <intf> role [none|router|user|hybrid]",
  .function = security_check_raguard_role_fn,
};
