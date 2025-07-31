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
 * @brief l2-uu-policer CLI
 */

#include <uu_policer/l2_uu_policer.h>
#include <vnet/interface_funcs.h>

#define L2_UU_POLICER_EXPECTED_ARGUMENT "expected required argument(s)"

u8 *
format_l2_uu_policer_config (u8 * s, va_list * args)
{
    vnet_main_t *vnm = va_arg (*args, vnet_main_t *);
    u32 sw_if_index = va_arg (*args, u32);
    u32 policer_index = va_arg (*args, u32);

    s = format (s, "intf %U\t", format_vnet_sw_interface_name, vnm, vnet_get_sw_interface_or_null (vnm, sw_if_index));
    s = format (s,  "policer %u\t", policer_index);
    return s;
}

static clib_error_t *
l2_uu_policer_show_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    l2_uu_policer_main_t *uupm = &l2_uu_policer_main;
    vnet_main_t *vnm = vnet_get_main ();
    u32 sw_if_index;

    vlib_cli_output (vm, "l2-uu-policer:");
    vec_foreach_index (sw_if_index, uupm->policer_index_by_sw_if_index)
    {
        if (clib_bitmap_get(uupm->enable_by_sw_if_index, sw_if_index))
        {
            vlib_cli_output (vm, " %U", format_l2_uu_policer_config, 
                             vnm, sw_if_index, uupm->policer_index_by_sw_if_index[sw_if_index]);
        }
    }
  return 0;
}

VLIB_CLI_COMMAND (l2_uu_policer_show_command, static) = {
  .path = "show l2-uu-policer",
  .short_help = "show l2-uu-policer",
  .function = l2_uu_policer_show_fn,
};

static clib_error_t *
l2_uu_policer_set_interface_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 sw_if_index = ~0;
    u32 policer_index = ~0;
    u8 is_del = 0;

    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, L2_UU_POLICER_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "interface %U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "policer %u", &policer_index));
        else if (unformat (line_input, "del")) is_del = 1;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index != ~0)
    {
        rv = l2_uu_policer_set_interface(sw_if_index, is_del ? (~0) : policer_index);
        if(rv)
        {
            clib_error_return (0, "%U : l2_uu_policer failed(rv = %d).", format_vnet_sw_if_index_name, sw_if_index, rv);
            goto done;
        }
    }
done:
  unformat_free (line_input);

  return error;
}


/*?
 * @cliexpar
 * @cliexstart{set policer l2-uu}
 * dai config
 * @cliexend
?*/
VLIB_CLI_COMMAND (l2_uu_policer_set_interface_command, static) = {
  .path = "set policer l2-uu",
  .short_help = "set policer l2-uu interface <int> policer <policer_index> [del]",
  .function = l2_uu_policer_set_interface_fn,
};
