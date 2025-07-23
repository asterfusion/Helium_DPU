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
 * @brief SPI CLI
 */

#include <spi/spi.h>
#include <spi/spi_inline.h>

#define SPI_EXPECTED_ARGUMENT "expected required argument(s)"

static char *spi_proto_type_strings[] = {
#define _(btype, ltype) #ltype,
    foreach_spi_support_session_type
#undef _
};

static clib_error_t *
spi_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
    spi_main_t *spim = &spi_main;

    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    spi_config_t c = { 0 };

    u8 enable_set = 0, enable = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SPI_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "sessions-per-thread %u", &c.max_sessions_per_thread));
        else if (unformat (line_input, "timer-frequency %u", &c.timer_process_frequency));
        else if (unformat (line_input, "handoff")) c.handoff_enabled = 1;
        else if (!enable_set) 
        {
            enable_set = 1;
            if (unformat (line_input, "disable")) ;
            else if (unformat (line_input, "enable")) enable = 1;
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!enable_set)
    {
        error = clib_error_return (0, "expected enable | disable");
        goto done;
    }

    if (enable)
    {
        if (spim->enabled)
        {
            error = clib_error_return (0, "already enabled");
            goto done;
        }

        if (spi_feature_enable (&c) != 0)
            error = clib_error_return (0, "enable failed");
    }
    else
    {
        if (!spim->enabled)
        {
            error = clib_error_return (0, "already disabled");
            goto done;
        }

        if (spi_feature_disable () != 0)
            error = clib_error_return (0, "disable failed");
    }

done:
    unformat_free (line_input);
    return error;
}

/*?
 * @cliexpar
 * @cliexstart{spi}
 * Enable spi session 
 * To enable spi session, use default:
 *  vpp# spi session enable
 * To disable spi session, use:
 *  vpp# spi session disable
 * To set user config, use:
 *  vpp# spi session enable sessions-per-thread 100000 handoff timer-frequency 2 
 * @cliexend
?*/
VLIB_CLI_COMMAND (spi_enable_disable_command, static) = {
  .path = "spi session",
  .short_help = "spi session <enable [sessions-per-thread <max-number>] [handoff] [timer-frequency <frequency>]>|disable",
  .function = spi_enable_disable_command_fn,
};

static clib_error_t *
spi_session_proto_enable_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
    u8 type_set = 0, is_enable = 1;
    spi_session_type_e type;

    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SPI_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "disable")) is_enable = 0;
        else if (!type_set)
        {
            if (unformat (line_input, "tcp"))
            {
                type = SPI_SESSION_TYPE_TCP;
                type_set = 1;
            }
            else if (unformat (line_input, "udp"))
            {
                type = SPI_SESSION_TYPE_UDP;
                type_set = 1;
            }
            else if (unformat (line_input, "icmp"))
            {
                type = SPI_SESSION_TYPE_ICMP;
                type_set = 1;
            }
            else if (unformat (line_input, "other"))
            {
                type = SPI_SESSION_TYPE_OTHER;
                type_set = 1;
            }
        }
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!type_set)
    {
        error = clib_error_return (0, "expected type");
        goto done;
    }

    if (spi_session_proto_enable_disable (type, is_enable) != 0)
        error = clib_error_return (0, "enable failed");

done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (spi_session_proto_enable_disable_command, static) = {
  .path = "spi session proto",
  .short_help = "spi session proto [tcp|udp|icmp|other] <disable>",
  .function = spi_session_proto_enable_disable_command_fn,
};

static clib_error_t *
spi_session_set_timeout_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    spi_timeouts_config_t c = { 0 };

    u8 reset_set = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SPI_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "reset")) reset_set = 1;
        else if (unformat (line_input, "tcp_transitory %u", &c.tcp_transitory));
        else if (unformat (line_input, "tcp_established %u", &c.tcp_established));
        else if (unformat (line_input, "tcp_closing %u", &c.tcp_closing));
        else if (unformat (line_input, "udp %u", &c.udp));
        else if (unformat (line_input, "icmp %u", &c.icmp));
        else if (unformat (line_input, "other %u", &c.other));
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    spi_timeout_update(reset_set, &c);

done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (spi_session_set_timeout_command, static) = {
  .path = "spi session timeout",
  .short_help = "spi session timeout "
                "<[tcp_transitory <second>]"
                " [tcp_established <second>]"
                " [tcp_closing <second>]"
                " [udp <second>]"
                " [icmp <second>]"
                " [other <second>]> "
                "|reset",
  .function = spi_session_set_timeout_command_fn,
};

static clib_error_t *
spi_add_del_3tuple_timeouts_command_fn (vlib_main_t * vm,
                                 unformat_input_t * input, 
                                 vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u32 tmp = 0;
    u8 proto = 0; 
    u16 l4port = 0; 
    u32 timeout = 0;
    ip46_address_t ip46_addr;
    ip46_type_t type = IP46_TYPE_IP4;

    u8 is_add = 1;
    int rv = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
        return clib_error_return (0, SPI_EXPECTED_ARGUMENT);

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "proto %u", &tmp)) proto = (u8)tmp;
        else if (unformat (line_input, "l4port %u", &tmp)) l4port = (u16)tmp;
        else if (unformat (line_input, "timeout %u", &timeout));
        else if (unformat (line_input, "ip %U", unformat_ip4_address, &ip46_addr.ip4)) type = IP46_TYPE_IP4;
        else if (unformat (line_input, "ip %U", unformat_ip6_address, &ip46_addr.ip6)) type = IP46_TYPE_IP6;
        else if (unformat (line_input, "del")) is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
            goto done;
        }
    }

    if (timeout == 0)
    {
        error = clib_error_return (0, "expected timeout, timeout must be greater than 0 ");
        goto done;
    }

    l4port = clib_host_to_net_u16(l4port);

    rv = spi_exact_3tuple_timeout_add_del(&ip46_addr, type, proto, l4port, timeout, is_add);
    if(rv)
    {
        clib_error_return (0, "%s spi user-define timeout entry failed (rv = %d).", is_add ? "add" : "del", rv);
        goto done;
    }
done:
  unformat_free (line_input);

  return error;
}

VLIB_CLI_COMMAND (spi_add_del_3tuple_timeouts_command, static) = {
  .path = "spi session user-define-timeout",
  .short_help = "spi session user-define-timeout proto <proto> ip <ip-address> l4port <port> timeout <second> [del]",
  .function = spi_add_del_3tuple_timeouts_command_fn,
};

static clib_error_t *
spi_show_global_timeout_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    spi_main_t *spim = &spi_main;

#define _(type, timeout) \
    vlib_cli_output(vm, #type": %u second", spim->spi_timeout_config.type);
    foreach_spi_timeout_def
#undef _

    return 0;
}

VLIB_CLI_COMMAND (spi_show_global_timeouts_command, static) = {
  .path = "show spi timeout global",
  .short_help = "show spi timeout global",
  .function = spi_show_global_timeout_command_fn,
};

static clib_error_t *
spi_show_3tuple_timeouts_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    spi_main_t *spim = &spi_main;

    int verbose = 0;

    if(unformat (input, "verbose")) verbose = 1;

    vlib_cli_output (vm, "\n%U", spim->exact_3tuple_timeout_table.fmt_fn, &spim->exact_3tuple_timeout_table, verbose);
    return 0;
}

VLIB_CLI_COMMAND (spi_show_3tuple_timeouts_command, static) = {
  .path = "show spi timeout user-define-timeout",
  .short_help = "show spi timeout user-define-timeout [verbose]",
  .function = spi_show_3tuple_timeouts_command_fn,
};

static clib_error_t *
spi_show_session_hash_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    spi_main_t *spim = &spi_main;

    int verbose = 0;

    if(unformat (input, "verbose")) verbose = 1;

    vlib_cli_output (vm, "\n%U", spim->session_table.fmt_fn, &spim->exact_3tuple_timeout_table, verbose);
    return 0;
}


VLIB_CLI_COMMAND (spi_show_session_hash_command, static) = {
  .path = "show spi session-hash",
  .short_help = "show spi session-hash [verbose]",
  .function = spi_show_session_hash_command_fn,
};

static void
spi_show_sessions_cli (vlib_main_t * vm,
                       bool ip_flag, u32 ip_type,
                       bool type_flag, u32 type)
{
    spi_main_t *spim = &spi_main;

    u32 wk;

    spi_per_thread_data_t *tspi;
    spi_session_t *session;

    f64 now = vlib_time_now(vm);

    for (wk = 0; wk < vec_len (spim->per_thread_data); wk++)
    {
        tspi = &spim->per_thread_data[wk];
        pool_foreach (session, tspi->sessions)
        {
            if (!ip_flag && !type_flag)
            {
                vlib_cli_output (vm, " %U", format_spi_session, spim, session, now);
            }
            else if (ip_flag && !type_flag)
            {
                if (session->is_ip6 == ip_type)
                {
                    vlib_cli_output (vm, " %U", format_spi_session, spim, session, now);
                }
            }
            else if (!ip_flag && type_flag)
            {
                if (session->session_type == type)
                {
                    vlib_cli_output (vm, " %U", format_spi_session, spim, session, now);
                }
            }
            else if (ip_flag && type_flag)
            {
                if (session->is_ip6 == ip_type && 
                    session->session_type == type)
                {
                    vlib_cli_output (vm, " %U", format_spi_session, spim, session, now);
                }
            }
        }
    }
}

static clib_error_t *
spi_show_session_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;

    counter_t totol_session;
    counter_t ip4_session;
    counter_t ip6_session;
    counter_t ip4_proto_session[SPI_SESSION_TYPE_MAX];
    counter_t ip6_proto_session[SPI_SESSION_TYPE_MAX];

    bool has_argument = false;
    bool ip_flag = false;
    bool type_flag = false;
    u32  type = UINT32_MAX;
    u32  ip_type = 0;

    int verbose = 0;

    if (!unformat_user (input, unformat_line_input, line_input))
    {
        spi_get_session_number(&totol_session, NULL, NULL, NULL, NULL);
        vlib_cli_output (vm, "SPI session totol: %llu", totol_session);
    }
    else
    {
        has_argument = true;
        while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
        {
            if (unformat (line_input, "ip4")) 
            {
                ip_flag = true;
                ip_type = 0;
            }
            else if (unformat (line_input, "ip6")) 
            {
                ip_flag = true;
                ip_type = 1;
            }
            else if (unformat (line_input, "type %u", &type)) type_flag = true;
            else if (unformat (line_input, "verbose")) verbose = 1;
            else
            {
                error = clib_error_return (0, "unknown input '%U'", format_unformat_error, line_input);
                goto done;
            }
        }

        if (type >= SPI_SESSION_TYPE_MAX && type_flag)
        {
            error = _clib_error_return(0, 0, 0,(char *)clib_error_function,
                    "expected type, type("
#define _(btype, ltype) #ltype": %d "
                    foreach_spi_support_session_type
#undef _
                    "%s",
#define _(btype, ltype) SPI_SESSION_TYPE_##btype,
                    foreach_spi_support_session_type
#undef _
                    ")");
            goto done;
        }

        if (!ip_flag && !type_flag)
        {
            spi_get_session_number(&totol_session, NULL, NULL, NULL, NULL);
            vlib_cli_output (vm, "SPI session totol: %llu", totol_session);
        }
        else if (ip_flag && !type_flag)
        {
            if (ip_type == 0)
            {
                spi_get_session_number(NULL, &ip4_session, NULL, NULL, NULL);
                vlib_cli_output (vm, "SPI session ipv4: %llu", ip4_session);
            }
            else
            {
                spi_get_session_number(NULL, NULL, NULL, &ip6_session, NULL);
                vlib_cli_output (vm, "SPI session ipv6: %llu", ip6_session);
            }
        }
        else if (!ip_flag && type_flag)
        {
            spi_get_session_number(NULL, NULL, ip4_proto_session, NULL, ip6_proto_session);
            vlib_cli_output (vm, "SPI session type %s: %llu", 
                             spi_proto_type_strings[type], 
                             ip4_proto_session[type] + ip6_proto_session[type]);
        }
        else if (ip_flag && type_flag)
        {
            if (ip_type == 0)
            {
                spi_get_session_number(NULL, NULL, ip4_proto_session, NULL, NULL);
                vlib_cli_output (vm, "SPI session ipv4 type %s: %llu", 
                             spi_proto_type_strings[type], ip4_proto_session[type]);
            }
            else
            {
                spi_get_session_number(NULL, NULL, NULL, NULL, ip6_proto_session);
                vlib_cli_output (vm, "SPI session ipv6 type %s: %llu", 
                             spi_proto_type_strings[type], ip6_proto_session[type]);
            }
        }

        if (verbose)
        {
            spi_show_sessions_cli(vm, ip_flag, ip_type, type_flag, type);
        }
    }
done:
    if (has_argument) unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (spi_show_session_command, static) = {
  .path = "show spi session",
  .short_help = "show spi session [ip4|ip6] [type <type>] [verbose]",
  .function = spi_show_session_command_fn,
};

