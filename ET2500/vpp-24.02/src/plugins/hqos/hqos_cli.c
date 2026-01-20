/*
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
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <hqos/hqos.h>


#define HQOS_EXPECTED_ARGUMENT "expected required argument(s)"

static clib_error_t *
hqos_user_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u8 *tag = NULL;
    u32 user_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "name %s", &tag));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    rv = hqos_user_add(tag, &user_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos user add failed (rv = %d).", rv);
        goto done;
    }

    vlib_cli_output (vm, "hqos user id: %u", user_id);
done:
  unformat_free (line_input);

  return error;

}

VLIB_CLI_COMMAND (hqos_user_add_command, static) = {
  .path = "hqos user add",
  .short_help = "hqos user add name <name>",
  .function = hqos_user_add_command_fn,
};

static clib_error_t *
hqos_user_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u8 *tag = NULL;
    u32 user_id = (~0);

    hqos_user_t *user = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %u", &user_id));
        else if (unformat (line_input, "name %s", &tag));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (user_id != (~0))
    {
        rv = hqos_user_del(user_id);
    }
    else if (tag)
    {
        pool_foreach(user, hm->user_pool)
        {
            if (clib_memcmp(user->tag, tag, vec_len(tag) < 32 ? vec_len(tag) : 32) == 0)
            {
                user_id = user->user_id;
                rv = hqos_user_del(user_id);
                break;
            }
        }

        if (user_id == (~0))
        {
            error = clib_error_return (0, "Not found user by name %s", tag);
            goto done;
        }
    }
    else
    {
        error = clib_error_return (0, "Missing index or name");
        goto done;
    }

    if(rv)
    {
        error = clib_error_return (0, "hqos user del failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_user_del_command, static) = {
  .path = "hqos user del",
  .short_help = "hqos user del [index <user_id> | name <name>]",
  .function = hqos_user_del_command_fn,
};

static clib_error_t *
hqos_user_update_queue_mode_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 user_id = (~0);
    u32 tc_queue_id = (~0);

    bool is_dwrr = false;
    u32 weight = 1;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %u", &user_id));
        else if (unformat (line_input, "queue %u", &tc_queue_id));
        else if (unformat (line_input, "mode sp"))
        {
            is_dwrr = false;
        }
        else if (unformat (line_input, "mode dwrr %u", &weight))
        {
            is_dwrr = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (user_id == (~0) || tc_queue_id == (~0))
    {
        error = clib_error_return (0, "Missing user index or queue id");
        goto done;
    }

    rv = hqos_user_update_queue_mode(user_id, tc_queue_id, is_dwrr, weight);

    if(rv)
    {
        error = clib_error_return (0, "hqos user update queue mode failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_user_update_queue_mode_command, static) = {
  .path = "hqos user update tcqueue",
  .short_help = "hqos user update tcqueue index <user_id > queue <id> mode [ sp | dwrr <weight> ]",
  .function = hqos_user_update_queue_mode_command_fn,
};

static clib_error_t *
show_hqos_user_command_fn (vlib_main_t * vm, unformat_input_t *input, vlib_cli_command_t * cmd)
{
    hqos_main_t *hm = &hqos_main;

    hqos_user_t *user = NULL;

    u32 tc_queue_id;

    pool_foreach(user, hm->user_pool)
    {
        vlib_cli_output (vm, "User Id : %u  Tag:(%s)", user->user_id, user->tag);
        for (tc_queue_id = 0; tc_queue_id < HQOS_SCHED_BE_QUEUES_PER_PIPE; tc_queue_id ++)
        {
            if (user->tc_queue_mode[tc_queue_id] == HQOS_TC_QUEUE_MODE_DWRR)
            vlib_cli_output (vm, "\t TCQUEUE%u: mode %U weight %u",
                                  tc_queue_id,
                                  format_hqos_tc_queue_mode, &user->tc_queue_mode[tc_queue_id],
                                  user->tc_queue_weight[tc_queue_id]);
            else
            vlib_cli_output (vm, "\t TCQUEUE%u: mode %U",
                                  tc_queue_id,
                                  format_hqos_tc_queue_mode, &user->tc_queue_mode[tc_queue_id]);
        }
    }

    return 0;
}

VLIB_CLI_COMMAND (show_hqos_user_command, static) = {
    .path = "show hqos user",
    .short_help = "show hqos user",
    .function = show_hqos_user_command_fn,
};

static clib_error_t *
hqos_user_group_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u8 *tag = NULL;
    u32 user_group_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "name %s", &tag));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    rv = hqos_user_group_add(tag, &user_group_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos user-group add failed (rv = %d).", rv);
        goto done;
    }

    vlib_cli_output (vm, "hqos user-group id: %u", user_group_id);
done:
  unformat_free (line_input);

  return error;

}

VLIB_CLI_COMMAND (hqos_user_group_add_command, static) = {
  .path = "hqos user_group add",
  .short_help = "hqos user_group add name <name>",
  .function = hqos_user_group_add_command_fn,
};

static clib_error_t *
hqos_user_group_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u8 *tag = NULL;
    u32 user_group_id = (~0);

    hqos_user_group_t *user_group = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %u", &user_group_id));
        else if (unformat (line_input, "name %s", &tag));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (user_group_id != (~0))
    {
        rv = hqos_user_group_del(user_group_id);
    }
    else if (tag)
    {
        pool_foreach(user_group, hm->user_group_pool)
        {
            if (clib_memcmp(user_group->tag, tag, vec_len(tag) < 32 ? vec_len(tag) : 32) == 0)
            {
                user_group_id = user_group->user_group_id;
                rv = hqos_user_del(user_group_id);
                break;
            }
        }

        if (user_group_id == (~0))
        {
            error = clib_error_return (0, "Not found user_group by name %s", tag);
            goto done;
        }
    }
    else
    {
        error = clib_error_return (0, "Missing index or name");
        goto done;
    }

    if(rv)
    {
        error = clib_error_return (0, "hqos user_group del failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_user_group_del_command, static) = {
  .path = "hqos user_group del",
  .short_help = "hqos user_group del [index <user_id> | name <name>]",
  .function = hqos_user_group_del_command_fn,
};

static clib_error_t *
show_hqos_user_group_command_fn (vlib_main_t * vm, unformat_input_t *input, vlib_cli_command_t * cmd)
{
    hqos_main_t *hm = &hqos_main;

    hqos_user_group_t *user_group = NULL;

    pool_foreach(user_group, hm->user_group_pool)
    {
        vlib_cli_output (vm, "User Group Id : %u  Tag:(%s)", user_group->user_group_id, user_group->tag);
    }

    return 0;
}

VLIB_CLI_COMMAND (show_hqos_user_group_command, static) = {
    .path = "show hqos user_group",
    .short_help = "show hqos user_group",
    .function = show_hqos_user_group_command_fn,
};

static clib_error_t *
hqos_interface_update_user_group_user_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();

    int rv = 0;
    u32 sw_if_index = (~0);
    u32 user_group_id = (~0);
    u32 user_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat(line_input, "group %u", &user_group_id));
        else if (unformat(line_input, "user  %u", &user_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    if (user_id == (~0))
    {
        error = clib_error_return (0, "miss user");
        goto done;
    }

    rv = hqos_interface_update_user_group_user(sw_if_index, user_id, user_group_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos interface update user to user group failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;

}

VLIB_CLI_COMMAND (hqos_interface_update_user_group_user_command, static) = {
  .path = "hqos interface user-mapping-user-group",
  .short_help = "hqos interface user-mapping-user-group <interface-name> user <user_id> [group <user_group_id>]",
  .function = hqos_interface_update_user_group_user_command_fn,
};

static clib_error_t *
show_hqos_interface_user_mapping_user_group_command_fn (vlib_main_t * vm, unformat_input_t *input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();
    hqos_main_t *hm = &hqos_main;

    vnet_hw_interface_t *hw;
    hqos_user_t *user = NULL;
    hqos_user_group_t *user_group = NULL;

    u32 sw_if_index = (~0);
    u32 user_id = (~0);
    u32 user_group_id = (~0);
    hash_pair_t *p;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    hw = vnet_get_hw_interface_or_null (hm->vnet_main, sw_if_index);

    if (!hw)
    {
        error = clib_error_return (0, "interface not have hw interface '%U'", format_unformat_error, line_input);
        goto done;
    }

    hash_foreach_pair (p, hw->user_to_ugroup,
   ({
        user_id = p->key;
        user_group_id = p->value[0];

        user = pool_elt_at_index(hm->user_pool, user_id);
        user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

        vlib_cli_output (vm, "User %u[%s] ---> User Group %u[%s] ",
                              user_id, user->tag, user_group_id, user_group->tag);
    }));

    vlib_cli_output (vm, "Other User ---> User Group 0[default_user_group] ");

done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (show_hqos_interface_user_mapping_user_group_command, static) = {
    .path = "show hqos interface user-mapping-user-group",
    .short_help = "show hqos interface user-mapping-user-group <interface-name>",
    .function = show_hqos_interface_user_mapping_user_group_command_fn,
};

static clib_error_t *
hqos_port_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 hqos_port_id = (~0);

    u64 port_rate = (~0);
    u32 n_subports_per_port = 8;
    u32 n_max_subport_profiles = 16;
    u32 n_pipes_per_subport = 1024;
    u32 n_queue_size = HQOS_DEFAULT_SUBPORT_TC_QSIZE;
    u32 mtu = 9100;
    u32 frame_overhead = 24;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "rate %llu", &port_rate));
        else if (unformat (line_input, "subport %u", &n_subports_per_port));
        else if (unformat (line_input, "max-subport-profile %u", &n_max_subport_profiles));
        else if (unformat (line_input, "pipe-pre-subport %u", &n_pipes_per_subport));
        else if (unformat (line_input, "queue-size %u", &n_queue_size));
        else if (unformat (line_input, "mtu %u", &mtu));
        else if (unformat (line_input, "overhead %u", &frame_overhead));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (port_rate == (~0))
    {
        error = clib_error_return (0, "Missing hqos port rate");
        goto done;
    }

    rv = hqos_port_add(port_rate,
                       n_subports_per_port,
                       n_max_subport_profiles,
                       n_pipes_per_subport,
                       n_queue_size,
                       mtu,
                       frame_overhead,
            &hqos_port_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port add failed (rv = %d).", rv);
        goto done;
    }

    vlib_cli_output (vm, "hqos port id: %u", hqos_port_id);
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_port_add_command, static) = {
    .path = "hqos port add",
    .short_help = "hqos port add rate <bytes> "
                  "[subport <num>] [max-subport-profile <num>] [ pipe-pre-subport <num> ] [mtu <value>] [overhead <value>] [queue-size <size>]",
    .function = hqos_port_add_command_fn,
};

static clib_error_t *
hqos_port_del_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 hqos_port_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %u", &hqos_port_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing index");
        goto done;
    }

    rv = hqos_port_del(hqos_port_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port del failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_port_del_command, static) = {
  .path = "hqos port del",
  .short_help = "hqos port del index <hqos_port_id>",
  .function = hqos_port_del_command_fn,
};

static clib_error_t *
hqos_subport_profile_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_port_subport_profile_id = (~0);

    u64 tb_rate = (~0);
    u64 tb_size = HQOS_DEFAULT_BUCKET_SIZE;
    u32 tc_period = HQOS_DEFAULT_TC_PERIOD;
    u64 *tc_rate_vec = NULL;
    u64 tmp_tc_rate = (~0);

    hqos_sched_port *hqos_port = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "tb_rate %llu", &tb_rate));
        else if (unformat (line_input, "tb_size %llu", &tb_size));
        else if (unformat (line_input, "tc_period %u", &tc_period));
        else if (unformat (line_input, "%llu", &tmp_tc_rate))
        {
            vec_add1 (tc_rate_vec, tmp_tc_rate);
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (!clib_bitmap_get(hm->hqos_port_bitmap, hqos_port_id))
    {
        error = clib_error_return (0, "current hqos port id not created");
        goto done;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (tb_rate == (~0))
    {
        tb_rate = hqos_port->rate;
    }

    while (vec_len(tc_rate_vec) < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
        vec_add1(tc_rate_vec, tb_rate);
    }

    rv = hqos_port_subport_profile_add(hqos_port_id,
                                       tb_rate, tb_size, tc_rate_vec,  tc_period,
                                       &hqos_port_subport_profile_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port subport profile add failed (rv = %d).", rv);
        goto done;
    }

    vlib_cli_output (vm, "hqos port subport profile id: %u", hqos_port_subport_profile_id);
done:

    if (tc_rate_vec) vec_free(tc_rate_vec);

    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_subport_profile_add_command, static) = {
    .path = "hqos subport profile add",
    .short_help = "hqos subport profile add port <hqos_port_id> "
                  "[tb_rate <num>] [tb_size <num>] [ tc_period <num> ] [[<tc_rate> [..]]]",
    .function = hqos_subport_profile_add_command_fn,
};

static clib_error_t *
hqos_subport_profile_update_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_port_subport_profile_id = (~0);

    u64 tb_rate = (~0);
    u64 tb_size = HQOS_DEFAULT_BUCKET_SIZE;
    u32 tc_period = HQOS_DEFAULT_TC_PERIOD;
    u64 *tc_rate_vec = NULL;
    u64 tmp_tc_rate = (~0);

    hqos_sched_port *hqos_port = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "profile %u", &hqos_port_subport_profile_id));
        else if (unformat (line_input, "tb_rate %llu", &tb_rate));
        else if (unformat (line_input, "tb_size %llu", &tb_size));
        else if (unformat (line_input, "tc_period %u", &tc_period));
        else if (unformat (line_input, "%llu", &tmp_tc_rate))
        {
            vec_add1 (tc_rate_vec, tmp_tc_rate);
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (hqos_port_subport_profile_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport profile index");
        goto done;
    }

    if (!clib_bitmap_get(hm->hqos_port_bitmap, hqos_port_id))
    {
        error = clib_error_return (0, "current hqos port id not created");
        goto done;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (tb_rate == (~0))
    {
        tb_rate = hqos_port->rate;
    }

    while (vec_len(tc_rate_vec) < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
        vec_add1(tc_rate_vec, hqos_port->rate);
    }

    rv = hqos_port_subport_profile_update(hqos_port_id, hqos_port_subport_profile_id,
                                       tb_rate, tb_size, tc_rate_vec,  tc_period);
    if(rv)
    {
        error = clib_error_return (0, "hqos port subport profile update failed (rv = %d).", rv);
        goto done;
    }

done:

    if (tc_rate_vec) vec_free(tc_rate_vec);

    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_subport_profile_update_command, static) = {
    .path = "hqos subport profile update",
    .short_help = "hqos subport profile update port <hqos_port_id> profile <profile_id> "
                  "[tb_rate <num>] [tb_size <num>] [ tc_period <num> ] [[<tc_rate> [..]]]",
    .function = hqos_subport_profile_update_command_fn,
};

static clib_error_t *
hqos_subport_config_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_subport_id = (~0);
    u32 hqos_port_subport_profile_id = (~0);

    u32 n_pipes_per_subport_enabled;
    u32 n_max_pipe_profiles;

    u16 *qsize_vec = NULL;
    u32 tmp_qsize = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "subport %u", &hqos_subport_id));
        else if (unformat (line_input, "profile %u", &hqos_port_subport_profile_id));
        else if (unformat (line_input, "n_pipes %u", &n_pipes_per_subport_enabled));
        else if (unformat (line_input, "n_max_pipe_profiles %u", &n_max_pipe_profiles));
        else if (unformat (line_input, "%u", &tmp_qsize))
        {
            vec_add1(qsize_vec, tmp_qsize);
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (hqos_subport_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport index");
        goto done;
    }

    if (hqos_port_subport_profile_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport profile index");
        goto done;
    }

    while (vec_len(qsize_vec) < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
        vec_add1(qsize_vec, HQOS_DEFAULT_SUBPORT_TC_QSIZE);
    }

    rv = hqos_port_subport_config(hqos_port_id, hqos_subport_id, hqos_port_subport_profile_id,
                                  n_pipes_per_subport_enabled, n_max_pipe_profiles,
                                  qsize_vec);
    if(rv)
    {
        error = clib_error_return (0, "hqos port subport config failed (rv = %d).", rv);
        goto done;
    }
done:

    if (qsize_vec) vec_free(qsize_vec);

    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_subport_config_command, static) = {
    .path = "hqos subport config",
    .short_help = "hqos subport config port <hqos_port_id> subport <hqos_subport_id> profile <profile_id> "
                  "n_pipes <num> n_max_pipe_profiles <num> [[<qsize> [..]]]",
    .function = hqos_subport_config_command_fn,
};

static clib_error_t *
hqos_subport_update_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_subport_id = (~0);
    u32 hqos_port_subport_profile_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "subport %u", &hqos_subport_id));
        else if (unformat (line_input, "profile %u", &hqos_port_subport_profile_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (hqos_subport_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport index");
        goto done;
    }

    if (hqos_port_subport_profile_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport profile index");
        goto done;
    }

    rv = hqos_port_subport_update_profile(hqos_port_id, hqos_subport_id, hqos_port_subport_profile_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port subport update profile failed (rv = %d).", rv);
        goto done;
    }
done:
    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_subport_update_command, static) = {
    .path = "hqos subport update",
    .short_help = "hqos subport update port <hqos_port_id> subport <hqos_subport_id> profile <profile_id>",
    .function = hqos_subport_update_command_fn,
};

static clib_error_t *
hqos_pipe_profile_add_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_subport_id = (~0);
    u32 hqos_pipe_profile_id = (~0);

    u64 tb_rate = (~0);
    u64 tb_size = HQOS_DEFAULT_BUCKET_SIZE;
    u32 tc_period = HQOS_DEFAULT_TC_PERIOD;
    u32 tc_ov_weight = HQOS_DEFAULT_BE_TC_OV_WEIGHT;


    u8 *weight_vec = NULL;
    u64 *tc_rate_vec = NULL;

    u64 tmp = (~0);
    bool weight_flag = true;

    hqos_sched_port *hqos_port = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "subport %u", &hqos_subport_id));
        else if (unformat (line_input, "tb_rate %llu", &tb_rate));
        else if (unformat (line_input, "tb_size %llu", &tb_size));
        else if (unformat (line_input, "tc_period %u", &tc_period));
        else if (unformat (line_input, "tc_ov_weight %u", &tc_ov_weight));
        else if (unformat (line_input, "weight")) weight_flag = true;
        else if (unformat (line_input, "tc_rate")) weight_flag = false;
        else if (unformat (line_input, "%llu", &tmp))
        {
            if (weight_flag)
                vec_add1 (weight_vec, tmp);
            else
                vec_add1 (tc_rate_vec, tmp);
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (!clib_bitmap_get(hm->hqos_port_bitmap, hqos_port_id))
    {
        error = clib_error_return (0, "current hqos port id not created");
        goto done;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (tb_rate == (~0))
    {
        tb_rate = hqos_port->rate;
    }

    while (vec_len(weight_vec) < HQOS_SCHED_TRAFFIC_CLASS_BE)
    {
        vec_add1(weight_vec, 1);
    }

    while (vec_len(tc_rate_vec) < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
        vec_add1(tc_rate_vec, tb_rate);
    }

    rv = hqos_subport_pipe_profile_add(hqos_port_id, hqos_subport_id,
                                       tb_rate, tb_size,
                                       tc_rate_vec,
                                       tc_period, tc_ov_weight,
                                       weight_vec,
                                       &hqos_pipe_profile_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port pipe profile add failed (rv = %d).", rv);
        goto done;
    }

    vlib_cli_output (vm, "hqos port pipe profile id: %u", hqos_pipe_profile_id);
done:

    if (weight_vec) vec_free(weight_vec);
    if (tc_rate_vec) vec_free(tc_rate_vec);

    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_pipe_profile_add_command, static) = {
    .path = "hqos pipe profile add",
    .short_help = "hqos pipe profile add port <hqos_port_id> subport <hqos_subport_id> "
                  "[tb_rate <num>] [tb_size <num>] [ tc_period <num> ] [tc_ov_weight <num>] weight [[<weight> [..]]] tc_rate [[<tc_rate> [..]]]",
    .function = hqos_pipe_profile_add_command_fn,
};

static clib_error_t *
hqos_pipe_profile_update_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    hqos_main_t *hm = &hqos_main;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_subport_id = (~0);
    u32 hqos_pipe_profile_id = (~0);

    u64 tb_rate = (~0);
    u64 tb_size = HQOS_DEFAULT_BUCKET_SIZE;
    u32 tc_period = HQOS_DEFAULT_TC_PERIOD;
    u32 tc_ov_weight = HQOS_DEFAULT_BE_TC_OV_WEIGHT;


    u8 *weight_vec = NULL;
    u64 *tc_rate_vec = NULL;

    u64 tmp = (~0);
    bool weight_flag = true;

    hqos_sched_port *hqos_port = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "subport %u", &hqos_subport_id));
        else if (unformat (line_input, "profile %u", &hqos_pipe_profile_id));
        else if (unformat (line_input, "tb_rate %llu", &tb_rate));
        else if (unformat (line_input, "tb_size %llu", &tb_size));
        else if (unformat (line_input, "tc_period %u", &tc_period));
        else if (unformat (line_input, "tc_ov_weight %u", &tc_ov_weight));
        else if (unformat (line_input, "weight")) weight_flag = true;
        else if (unformat (line_input, "tc_rate")) weight_flag = false;
        else if (unformat (line_input, "%llu", &tmp))
        {
            if (weight_flag)
                vec_add1 (weight_vec, tmp);
            else
                vec_add1 (tc_rate_vec, tmp);
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (!clib_bitmap_get(hm->hqos_port_bitmap, hqos_port_id))
    {
        error = clib_error_return (0, "current hqos port id not created");
        goto done;
    }

    hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];

    if (tb_rate == (~0))
    {
        tb_rate = hqos_port->rate;
    }

    while (vec_len(weight_vec) < HQOS_SCHED_TRAFFIC_CLASS_BE)
    {
        vec_add1(weight_vec, 1);
    }

    while (vec_len(tc_rate_vec) < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE)
    {
        vec_add1(tc_rate_vec, tb_rate);
    }

    rv = hqos_subport_pipe_profile_update(hqos_port_id, hqos_subport_id, hqos_pipe_profile_id,
                                       tb_rate, tb_size,
                                       tc_rate_vec,
                                       tc_period, tc_ov_weight,
                                       weight_vec);
    if(rv)
    {
        error = clib_error_return (0, "hqos port pipe profile update failed (rv = %d).", rv);
        goto done;
    }

done:

    if (tc_rate_vec) vec_free(tc_rate_vec);

    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_pipe_profile_update_command, static) = {
    .path = "hqos pipe profile update",
    .short_help = "hqos pipe profile update port <hqos_port_id> subport <hqos_subport_id> profile <profile_id> "
                  "[tb_rate <num>] [tb_size <num>] [ tc_period <num> ] [tc_ov_weight <num>] weight [[<weight> [..]]] tc_rate [[<tc_rate> [..]]]",
    .function = hqos_pipe_profile_update_command_fn,
};

static clib_error_t *
hqos_pipe_update_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    int rv = 0;
    u32 hqos_port_id = (~0);
    u32 hqos_subport_id = (~0);
    u32 hqos_pipe_id = (~0);
    u32 hqos_pipe_profile_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "port %u", &hqos_port_id));
        else if (unformat (line_input, "subport %u", &hqos_subport_id));
        else if (unformat (line_input, "pipe %u", &hqos_pipe_id));
        else if (unformat (line_input, "profile %u", &hqos_pipe_profile_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (hqos_port_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos port index");
        goto done;
    }

    if (hqos_subport_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos subport index");
        goto done;
    }

    if (hqos_pipe_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos pipe index");
        goto done;
    }

    if (hqos_pipe_profile_id == (~0))
    {
        error = clib_error_return (0, "Missing hqos pipe profile index");
        goto done;
    }

    rv = hqos_subport_pipe_update_profile(hqos_port_id, hqos_subport_id, hqos_pipe_id, hqos_pipe_profile_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos port pipe update profile failed (rv = %d).", rv);
        goto done;
    }
done:
    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_pipe_update_command, static) = {
    .path = "hqos pipe update",
    .short_help = "hqos pipe update port <hqos_port_id> subport <hqos_subport_id> pipe <hqos_pipe_id> profile <profile_id>",
    .function = hqos_pipe_update_command_fn,
};

static clib_error_t *
show_hqos_port_command_fn (vlib_main_t * vm, unformat_input_t *input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    hqos_main_t *hm = &hqos_main;

    bool has_argument = false;

    uword hqos_port_id = (~0);
    hqos_sched_port *hqos_port = NULL;

    if (!unformat_user (input, unformat_line_input, line_input))
    {
        hqos_port_id = clib_bitmap_first_set(hm->hqos_port_bitmap);
        while(hqos_port_id != ~0)
        {
            hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];
            vlib_cli_output (vm, "%U", format_hqos_port, hqos_port_id, hqos_port);
            hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
        }
    }
    else
    {
        has_argument = true;
        while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
            if (unformat(line_input, "index %llu", &hqos_port_id));
            else
            {
                error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
                goto done;
            }
        }

        if (hqos_port_id == (~0))
        {
            hqos_port_id = clib_bitmap_first_set(hm->hqos_port_bitmap);
            while(hqos_port_id != ~0)
            {
                hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];
                vlib_cli_output (vm, "%U", format_hqos_port, hqos_port_id, hqos_port);
                hqos_port_id = clib_bitmap_next_set(hm->hqos_port_bitmap, hqos_port_id + 1);
            }
        }
        else
        {
            if (!clib_bitmap_get(hm->hqos_port_bitmap, hqos_port_id))
            {
                error = clib_error_return (0, "current hqos port id not created");
                goto done;
            }
            hqos_port = hm->hqos_port_ptr_vec[hqos_port_id];
            vlib_cli_output (vm, "%U", format_hqos_port_detail, hqos_port_id, hqos_port);
        }
    }
done:
    if (has_argument) unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (show_hqos_port_command, static) = {
    .path = "show hqos port",
    .short_help = "show hqos port [index <hqos_port_id>]",
    .function = show_hqos_port_command_fn,
};

static clib_error_t *
hqos_interface_mapping_hqos_port_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();

    int rv = 0;
    u32 sw_if_index = (~0);
    u32 hqos_port_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat(line_input, "port %u", &hqos_port_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    rv = hqos_interface_mapping_hqos_port(sw_if_index, hqos_port_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos interface mapping hqos port failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_interface_mapping_hqos_port_command, static) = {
  .path = "hqos interface hqos-port-mapping",
  .short_help = "hqos interface hqos-port-mapping <interface-name> [port <hqos_port_id>]",
  .function = hqos_interface_mapping_hqos_port_command_fn,
};

static clib_error_t *
hqos_interface_mapping_user_group_subport_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();

    int rv = 0;
    u32 sw_if_index = (~0);
    u32 user_group_id = (~0);
    u32 hqos_subport_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat(line_input, "user_group %u", &user_group_id));
        else if (unformat(line_input, "subport %u", &hqos_subport_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    if (user_group_id == (~0))
    {
        error = clib_error_return (0, "miss user");
        goto done;
    }

    rv = hqos_interface_mapping_user_group_to_hqos_subport(sw_if_index, user_group_id, hqos_subport_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos interface user mapping pipe failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_interface_mapping_user_group_subport_command, static) = {
  .path = "hqos interface user-group-mapping-subport",
  .short_help = "hqos interface user-group-mapping-subport <interface-name> user_group <user_group_id> [subport <hqos_subport_id>]",
  .function = hqos_interface_mapping_user_group_subport_command_fn,
};

static clib_error_t *
hqos_interface_mapping_user_pipe_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();

    int rv = 0;
    u32 sw_if_index = (~0);
    u32 user_id = (~0);
    u32 hqos_pipe_id = (~0);

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat(line_input, "user %u", &user_id));
        else if (unformat(line_input, "pipe %u", &hqos_pipe_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    if (user_id == (~0))
    {
        error = clib_error_return (0, "miss user_group");
        goto done;
    }

    rv = hqos_interface_mapping_user_to_hqos_pipe(sw_if_index, user_id, hqos_pipe_id);
    if(rv)
    {
        error = clib_error_return (0, "hqos interface user mapping pipe failed (rv = %d).", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_interface_mapping_user_pipe_command, static) = {
  .path = "hqos interface user-mapping-pipe",
  .short_help = "hqos interface user-mapping-pipe <interface-name> user <userp_id> [pipe <hqos_pipe_id>]",
  .function = hqos_interface_mapping_user_pipe_command_fn,
};

static clib_error_t *
hqos_interface_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    vnet_main_t *vnm = vnet_get_main ();

    int rv = 0;
    u32 sw_if_index = (~0);
    bool is_enabled = true;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat(line_input, "disable")) is_enabled = false;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (sw_if_index == (~0))
    {
        error = clib_error_return (0, "unknown interface");
        goto done;
    }

    rv = hqos_interface_enable_disable(sw_if_index, is_enabled);
    if(rv)
    {
        error = clib_error_return (0, "hqos interface %s failed (rv = %d).", is_enabled ? "enabled" : "disabled", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;

}

VLIB_CLI_COMMAND (hqos_interface_enable_disable_command, static) = {
  .path = "hqos interface enable",
  .short_help = "hqos interface enable <interface-name> [disable]",
  .function = hqos_interface_enable_disable_command_fn,
};

static clib_error_t *
hqos_user_qosmap_show (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    hqos_main_t *hm = &hqos_main;

    u32 user_id = (~0);

    hqos_user_t *user = NULL;

    u32 key, value;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%u", &user_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (user_id != (~0))
    {
        if (pool_is_free_index(hm->user_pool, user_id))
        {
            vlib_cli_output (vm, "current user not create");
            goto done;
        }

        user = pool_elt_at_index(hm->user_pool, user_id);

        vlib_cli_output(vm, "Id: %u(%s) dscp_to_tc:", user_id, user->tag);
        hash_foreach(key, value, user->dscp_to_tc, (
        {
            vlib_cli_output(vm, "\t dscp %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dscp_to_color:", user_id, user->tag);
        hash_foreach(key, value, user->dscp_to_color, (
        {
            vlib_cli_output(vm, "\t dscp %u : color %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dot1p_to_tc:", user_id, user->tag);
        hash_foreach(key, value, user->dot1p_to_tc, (
        {
            vlib_cli_output(vm, "\t dot1p %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dot1p_to_color:", user_id, user->tag);
        hash_foreach(key, value, user->dot1p_to_color, (
        {
            vlib_cli_output(vm, "\t dot1p %u : color %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) mpls_exp_to_tc:", user_id, user->tag);
        hash_foreach(key, value, user->mpls_exp_to_tc, (
        {
            vlib_cli_output(vm, "\t mpls-exp %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) mpls_exp_to_color:", user_id, user->tag);
        hash_foreach(key, value, user->mpls_exp_to_color, (
        {
            vlib_cli_output(vm, "\t mpls-exp %u : color %u", key, value);
        }));
    }
    else
    {
        error = clib_error_return (0, "Missing index or name");
        goto done;
    }

done:
    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_user_qosmap_show_command, static) = {
  .path = "show hqos qosmap user",
  .short_help = "show hqos qosmap user <user_id>",
  .function = hqos_user_qosmap_show,
};

static clib_error_t *
hqos_user_group_qosmap_show_fn (vlib_main_t * vm,
		 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    hqos_main_t *hm = &hqos_main;

    u32 user_group_id = (~0);

    hqos_user_group_t *user_group = NULL;

    u32 key, value;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, HQOS_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%u", &user_group_id));
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (user_group_id != (~0))
    {
        if (pool_is_free_index(hm->user_group_pool, user_group_id))
        {
            vlib_cli_output (vm, "current user group not create");
            goto done;
        }

        user_group = pool_elt_at_index(hm->user_group_pool, user_group_id);

        vlib_cli_output(vm, "Id: %u(%s) dscp_to_tc:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->dscp_to_tc, (
        {
            vlib_cli_output(vm, "\t dscp %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dscp_to_color:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->dscp_to_color, (
        {
            vlib_cli_output(vm, "\t dscp %u : color %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dot1p_to_tc:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->dot1p_to_tc, (
        {
            vlib_cli_output(vm, "\t dot1p %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) dot1p_to_color:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->dot1p_to_color, (
        {
            vlib_cli_output(vm, "\t dot1p %u : color %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) mpls_exp_to_tc:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->mpls_exp_to_tc, (
        {
            vlib_cli_output(vm, "\t mpls-exp %u : tc %u", key, value);
        }));

        vlib_cli_output(vm, "Id: %u(%s) mpls_exp_to_color:", user_group_id, user_group->tag);
        hash_foreach(key, value, user_group->mpls_exp_to_color, (
        {
            vlib_cli_output(vm, "\t mpls-exp %u : color %u", key, value);
        }));
    }
    else
    {
        error = clib_error_return (0, "Missing index or name");
        goto done;
    }

done:
    unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (hqos_user_group_qosmap_show_command, static) = {
  .path = "show hqos qosmap user_group",
  .short_help = "show hqos qosmap user_group <user_group_id>",
  .function = hqos_user_group_qosmap_show_fn,
};

static clib_error_t*
hqos_user_set_dscp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 dscp, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &dscp, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_dscp_tc_map(user_id, dscp, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_dscp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_dscp_tc_map_command, static) = {
  .path = "hqos user set dscp-to-tc",
  .short_help = "hqos user set dscp-to-tc <user_id> <dscp> <tc>",
  .function = hqos_user_set_dscp_tc_map_fn,
};

static clib_error_t*
hqos_user_set_dscp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 dscp, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &dscp, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_dscp_color_map(user_id, dscp, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_dscp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_dscp_color_map_command, static) = {
  .path = "hqos user set dscp-to-color",
  .short_help = "hqos user set dscp-to-color <user_id> <dscp> <color>",
  .function = hqos_user_set_dscp_color_map_fn,
};


static clib_error_t*
hqos_user_set_dot1p_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 dot1p, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &dot1p, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_dot1p_tc_map(user_id, dot1p, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_dot1p_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_dot1p_tc_map_command, static) = {
  .path = "hqos user set dot1p-to-tc",
  .short_help = "hqos user set dot1p-to-tc <user_id> <dot1p> <tc>",
  .function = hqos_user_set_dot1p_tc_map_fn,
};

static clib_error_t*
hqos_user_set_dot1p_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 dot1p, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &dot1p, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_dot1p_color_map(user_id, dot1p, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_dot1p_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_dot1p_color_map_command, static) = {
  .path = "hqos user set dot1p-to-color",
  .short_help = "hqos user set dot1p-to-color <user_id> <dot1p> <color>",
  .function = hqos_user_set_dot1p_color_map_fn,
};

static clib_error_t*
hqos_user_set_mpls_exp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 mpls_exp, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &mpls_exp, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_mpls_exp_tc_map(user_id, mpls_exp, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_mpls_exp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_mpls_exp_tc_map_command, static) = {
  .path = "hqos user set mplsexp-to-tc",
  .short_help = "hqos user set mplsexp-to-tc <user_id> <mpls_exp> <tc>",
  .function = hqos_user_set_mpls_exp_tc_map_fn,
};

static clib_error_t*
hqos_user_set_mpls_exp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_id = (~0);
    u32 mpls_exp, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_id, &mpls_exp, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_set_mpls_exp_color_map(user_id, mpls_exp, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_set_mpls_exp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_set_mpls_exp_color_map_command, static) = {
  .path = "hqos user set mplsexp-to-color",
  .short_help = "hqos user set mplsexp-to-color <user_id> <mpls_exp> <color>",
  .function = hqos_user_set_mpls_exp_color_map_fn,
};

static clib_error_t*
hqos_user_remove_dscp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_dscp_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_dscp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_dscp_tc_map_command, static) = {
  .path = "hqos user remove dscp-to-tc",
  .short_help = "hqos user remove dscp-to-tc <user_id>",
  .function = hqos_user_remove_dscp_tc_map_fn,
};

static clib_error_t*
hqos_user_remove_dscp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_dscp_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_dscp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_dscp_color_map_command, static) = {
  .path = "hqos user remove dscp-to-color",
  .short_help = "hqos user remove dscp-to-color <user_id>",
  .function = hqos_user_remove_dscp_color_map_fn,
};

static clib_error_t*
hqos_user_remove_dot1p_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_dot1p_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_dot1p_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_dot1p_tc_map_command, static) = {
  .path = "hqos user remove dot1p-to-tc",
  .short_help = "hqos user remove dot1p-to-tc <user_id>",
  .function = hqos_user_remove_dot1p_tc_map_fn,
};

static clib_error_t*
hqos_user_remove_dot1p_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_dot1p_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_dot1p_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_dot1p_color_map_command, static) = {
  .path = "hqos user remove dot1p-to-color",
  .short_help = "hqos user remove dot1p-to-color <user_id>",
  .function = hqos_user_remove_dot1p_color_map_fn,
};

static clib_error_t*
hqos_user_remove_mpls_exp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_mpls_exp_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_mpls_exp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_mpls_exp_tc_map_command, static) = {
  .path = "hqos user remove mplsexp-to-tc",
  .short_help = "hqos user remove mplsexp-to-tc <user_id>",
  .function = hqos_user_remove_mpls_exp_tc_map_fn,
};

static clib_error_t*
hqos_user_remove_mpls_exp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_remove_mpls_exp_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_remove_mpls_exp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_remove_mpls_exp_color_map_command, static) = {
  .path = "hqos user remove mplsexp-to-color",
  .short_help = "hqos user remove mplsexp-to-color <user_id>",
  .function = hqos_user_remove_mpls_exp_color_map_fn,
};

static clib_error_t*
hqos_user_group_set_dscp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 dscp, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &dscp, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_dscp_tc_map(user_group_id, dscp, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_dscp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_dscp_tc_map_command, static) = {
  .path = "hqos user_group set dscp-to-tc",
  .short_help = "hqos user_group set dscp-to-tc <user_id> <dscp> <tc>",
  .function = hqos_user_group_set_dscp_tc_map_fn,
};

static clib_error_t*
hqos_user_group_set_dscp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 dscp, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &dscp, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_dscp_color_map(user_group_id, dscp, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_dscp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_dscp_color_map_command, static) = {
  .path = "hqos user_group set dscp-to-color",
  .short_help = "hqos user_group set dscp-to-color <user_group_id> <dscp> <color>",
  .function = hqos_user_group_set_dscp_color_map_fn,
};


static clib_error_t*
hqos_user_group_set_dot1p_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 dot1p, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &dot1p, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_dot1p_tc_map(user_group_id, dot1p, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_dot1p_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_dot1p_tc_map_command, static) = {
  .path = "hqos user_group set dot1p-to-tc",
  .short_help = "hqos user_group set dot1p-to-tc <user_group_id> <dot1p> <tc>",
  .function = hqos_user_group_set_dot1p_tc_map_fn,
};

static clib_error_t*
hqos_user_group_set_dot1p_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 dot1p, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &dot1p, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_dot1p_color_map(user_group_id, dot1p, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_dot1p_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_dot1p_color_map_command, static) = {
  .path = "hqos user_group set dot1p-to-color",
  .short_help = "hqos user_group set dot1p-to-color <user_group_id> <dot1p> <color>",
  .function = hqos_user_group_set_dot1p_color_map_fn,
};

static clib_error_t*
hqos_user_group_set_mpls_exp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 mpls_exp, tc;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &mpls_exp, &tc))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_mpls_exp_tc_map(user_group_id, mpls_exp, tc);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_mpls_exp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_mpls_exp_tc_map_command, static) = {
  .path = "hqos user_group set mplsexp-to-tc",
  .short_help = "hqos user_group set mplsexp-to-tc <user_group_id> <mpls_exp> <tc>",
  .function = hqos_user_group_set_mpls_exp_tc_map_fn,
};

static clib_error_t*
hqos_user_group_set_mpls_exp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 user_group_id = (~0);
    u32 mpls_exp, color;

    int rv = 0;

    if (!unformat(input, " %u %u %u", &user_group_id, &mpls_exp, &color))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_set_mpls_exp_color_map(user_group_id, mpls_exp, color);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_set_mpls_exp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_set_mpls_exp_color_map_command, static) = {
  .path = "hqos user_group set mplsexp-to-color",
  .short_help = "hqos user_group set mplsexp-to-color <user_group_id> <mpls_exp> <color>",
  .function = hqos_user_group_set_mpls_exp_color_map_fn,
};

static clib_error_t*
hqos_user_group_remove_dscp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_dscp_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_dscp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_dscp_tc_map_command, static) = {
  .path = "hqos user_group remove dscp-to-tc",
  .short_help = "hqos user_group remove dscp-to-tc <user_group_id>",
  .function = hqos_user_group_remove_dscp_tc_map_fn,
};

static clib_error_t*
hqos_user_group_remove_dscp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_dscp_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_dscp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_dscp_color_map_command, static) = {
  .path = "hqos user_group remove dscp-to-color",
  .short_help = "hqos user_group remove dscp-to-color <user_group_id>",
  .function = hqos_user_group_remove_dscp_color_map_fn,
};

static clib_error_t*
hqos_user_group_remove_dot1p_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_dot1p_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_dot1p_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_dot1p_tc_map_command, static) = {
  .path = "hqos user_group remove dot1p-to-tc",
  .short_help = "hqos user_group remove dot1p-to-tc <user_group_id>",
  .function = hqos_user_group_remove_dot1p_tc_map_fn,
};

static clib_error_t*
hqos_user_group_remove_dot1p_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_dot1p_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_dot1p_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_dot1p_color_map_command, static) = {
  .path = "hqos user_group remove dot1p-to-color",
  .short_help = "hqos user_group remove dot1p-to-color <user_group_id>",
  .function = hqos_user_group_remove_dot1p_color_map_fn,
};

static clib_error_t*
hqos_user_group_remove_mpls_exp_tc_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_mpls_exp_tc_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_mpls_exp_tc_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_mpls_exp_tc_map_command, static) = {
  .path = "hqos user_group remove mplsexp-to-tc",
  .short_help = "hqos user_group remove mplsexp-to-tc <user_group_id>",
  .function = hqos_user_group_remove_mpls_exp_tc_map_fn,
};

static clib_error_t*
hqos_user_group_remove_mpls_exp_color_map_fn(vlib_main_t* vm, unformat_input_t* input, vlib_cli_command_t* cmd)
{
    clib_error_t* error = 0;
    u32 id = (~0);

    int rv = 0;

    if (!unformat(input, " %u", &id))
    {
        return clib_error_return(0, "Please specify interface.");
    }

    rv = hqos_user_group_remove_mpls_exp_color_map(id);
    if(rv)
    {
        error = clib_error_return (0, "hqos_user_group_remove_mpls_exp_color_map (rv = %d).", rv);
    }
    return error;
}

VLIB_CLI_COMMAND(hqos_user_group_remove_mpls_exp_color_map_command, static) = {
  .path = "hqos user_group remove mplsexp-to-color",
  .short_help = "hqos user_group remove mplsexp-to-color <user_group_id>",
  .function = hqos_user_group_remove_mpls_exp_color_map_fn,
};
