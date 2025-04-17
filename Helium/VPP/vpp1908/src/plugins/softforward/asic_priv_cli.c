#include <softforward/asic_priv.h>


static clib_error_t *
asic_priv_proc_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();

    clib_error_t *error = 0;
    u32 sw_if_index;
    int is_disable = 0;
    int rv = 0;

    sw_if_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "enable %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
            is_disable = 0;
        else if (unformat (line_input, "disable %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
            is_disable = 1;
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (is_disable)
        rv = asic_priv_proc_disable(sw_if_index);
    else
        rv = asic_priv_proc_enable(sw_if_index);

    switch(rv)
    {
    case VNET_API_ERROR_UNIMPLEMENTED:
        error = clib_error_return (0, "Unimplemented(pre-asic-private)");
        goto done;
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "already enable");
        goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "already disable");
        goto done;
    case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "not fount arc (interface-ouput)");
        goto done;
    case VNET_API_ERROR_INVALID_VALUE_2:
        error = clib_error_return (0, "not fount arc (post-asic-private)");
        goto done;
    default:
        break;
    }
done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (set_interface_asic_priv_proc_command, static) = {
    .path = "set interface asic-priv-proc",
    .function = asic_priv_proc_feature_command_fn,
    .short_help = "set interface asic-priv-proc enable|disable <intfc>" ,
};

static clib_error_t *
show_asic_priv_proc_feature_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    vnet_main_t *vnm = vnet_get_main ();
    asic_private_main_t *apm = &ap_main;
    asic_priv_interface_t *i;

    clib_error_t *error = 0;

    pool_foreach (i, apm->interfaces,
    ({
        vlib_cli_output (vm, " %U enable feature", format_vnet_sw_if_index_name, vnm,
             i->sw_if_index);

    }));
    return error;
}

VLIB_CLI_COMMAND (show_interface_asic_priv_proc_command, static) = {
    .path = "show asic-priv-proc",
    .function = show_asic_priv_proc_feature_command_fn,
    .short_help = "show asic-priv-proc" ,
};
