#include <softforward/softforward.h>
#include <vnet/fib/fib_table.h>

static clib_error_t *
softforward_create_delete_mapping_fn (vlib_main_t * vm,
        unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    softforward_main_t *sfm = &sf_main;
    int is_add = 1;
    int rv = 0;
    u8 *mapping_name = NULL;
    clib_error_t *error = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "name %s", &mapping_name))
            ;
        else if (unformat (line_input, "del"))
            is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (vec_len(mapping_name) > MAX_SOFTFORWARD_MAPPING_NAME_LENGHT - 1)
    {
        error = clib_error_return (0, 
                "softforward mapping name exceeds maximum length(%d)", MAX_SOFTFORWARD_MAPPING_NAME_LENGHT - 1);
        goto done;
    }

    rv = softforward_add_del_mapping(sfm, mapping_name, is_add);

    switch (rv)
    {
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "softforward mapping %s already exists.", mapping_name);
        goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "softforward mapping %s not exist.", mapping_name);
        goto done;
    case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "softforward mappings cnt ecceeds maximum.");
        goto done;
    case VNET_API_ERROR_RSRC_IN_USE:
        error = clib_error_return (0, "softforward mapping %s in used. Please unbind by interface.", mapping_name);
        goto done;
    default:
        break;
    }

done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (softforward_create_delete_mapping, static) = {
    .path = "create softforward mapping",
    .short_help = "create softforward mapping name <name> [del]",
    .function = softforward_create_delete_mapping_fn,
};


static void softforward_mapping_entry_format(vlib_main_t * vm, 
                softforward_mapping_t *mapping, u8 hit)
{
    softforward_map_entry_t *mapping_entry = NULL;

    pool_foreach(mapping_entry, mapping->mapping_entrys,
    ({
        if(hit)
        {
            if (mapping_entry->match_cnt)
            {
                if (mapping_entry->map_saddr.as_u32 == 0)
                    vlib_cli_output (vm, "    dst %U dst-map %U forward %d (hit)", 
                           format_ip4_address,  &mapping_entry->daddr, 
                           format_ip4_address,  &mapping_entry->map_daddr, 
                           mapping_entry->forward_port);
                else
                    vlib_cli_output (vm, "    dst %U dst-map %U forward %d modify-src %U (hit)", 
                           format_ip4_address,  &mapping_entry->daddr, 
                           format_ip4_address,  &mapping_entry->map_daddr, 
                           mapping_entry->forward_port,
                           format_ip4_address,  &mapping_entry->map_saddr);
            }

        }
        else
        {
            if (mapping_entry->map_saddr.as_u32 == 0)
                vlib_cli_output (vm, "    dst %U dst-map %U forward %d", 
                       format_ip4_address,  &mapping_entry->daddr, 
                       format_ip4_address,  &mapping_entry->map_daddr, 
                       mapping_entry->forward_port);
            else
                vlib_cli_output (vm, "    dst %U dst-map %U forward %d modify-src %U", 
                       format_ip4_address,  &mapping_entry->daddr, 
                       format_ip4_address,  &mapping_entry->map_daddr, 
                       mapping_entry->forward_port,
                       format_ip4_address,  &mapping_entry->map_saddr);
        }
    }));
}

static clib_error_t *
softforward_show_mappings_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
    softforward_main_t *sfm = &sf_main;
    softforward_mapping_t *mapping = NULL;
    int verbose = 0;

    if (unformat (input, "detail"))
        verbose = 1;

    vlib_cli_output (vm, "softforward mappings:");
    if (!verbose)
    {
        pool_foreach (mapping, sfm->mapping_pool,
        ({
            vlib_cli_output (vm, "  %s mapping : has %u entrys", 
                        (char *)mapping->name, pool_elts(mapping->mapping_entrys));
        }));
    }
    else
    {
        pool_foreach (mapping, sfm->mapping_pool,
        ({
            vlib_cli_output (vm, "  %s mapping : has %u entrys", 
                    (char *)mapping->name, pool_elts(mapping->mapping_entrys));
            softforward_mapping_entry_format(vm, mapping, 0);
        }));
    }
    return 0;
}

VLIB_CLI_COMMAND (softforwad_show_mappings, static) = {
    .path = "show softforward mappings",
    .short_help = "show softforward mappings [detail]",
    .function = softforward_show_mappings_command_fn,
};

static clib_error_t *
softforward_add_del_mapping_entrys_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    softforward_main_t *sfm = &sf_main;
    clib_error_t *error = 0;
    u8 *mapping_name = NULL;
    ip4_address_t dst_addr, dst_map_addr, modify_src_addr;
    u32 forward_pannel_port = ~0;
    u8 dst_set = 0, dst_map_set = 0, forward_port_set = 0, modify_src_set = 0;
    int is_add = 0;
    int rv;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "add"))
            is_add = 1;
        else if (unformat (line_input, "del"))
            is_add = 0;
        else if (unformat (line_input, "name %s", &mapping_name))
            ;
        else if (unformat (line_input, "dst %U", unformat_ip4_address, &dst_addr))
            dst_set = 1;
        else if (unformat (line_input, "dst-map %U", unformat_ip4_address, &dst_map_addr))
            dst_map_set = 1;
        else if (unformat (line_input, "forward %d", &forward_pannel_port))
            forward_port_set = 1;
        else if (unformat (line_input, "src-modify %U", unformat_ip4_address, &modify_src_addr))
            modify_src_set = 1;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }
    /* check */
    if (!softforward_get_mapping_by_name(sfm, mapping_name))
    {
        error = clib_error_return (0, "Not found mapping %s", mapping_name);
        goto done;
    }
    if (!dst_set)
    {
        error = clib_error_return (0, "Missing dst");
        goto done;
    }
    if (!dst_map_set)
    {
        error = clib_error_return (0, "Missing dst-map");
        goto done;
    }
    if (!forward_port_set)
    {
        error = clib_error_return (0, "Missing forward_pannel_port");
        goto done;
    }

    if ( modify_src_set )
        rv = softforward_add_del_mapping_entrys (sfm, mapping_name, 
                &dst_addr, &dst_map_addr, forward_pannel_port,
                &modify_src_addr, is_add);
    else
        rv = softforward_add_del_mapping_entrys (sfm, mapping_name, 
                &dst_addr, &dst_map_addr, forward_pannel_port,
                NULL, is_add);

    switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_NODE:
        error = clib_error_return (0, "Not found mapping %s", mapping_name);
        goto done;
    case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "External port already in use.");
        goto done;
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "Dst address entry not found.");
        goto done;
    case VNET_API_ERROR_NO_SUCH_FIB:
        error = clib_error_return (0, "No such VRF id.");
        goto done;
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "Mapping entry already exist.");
        goto done;
    default:
        break;
    }

done:
  unformat_free (line_input);
  return error;
}


VLIB_CLI_COMMAND (softforward_add_del_mapping_entrys_command, static) = {
    .path = "softforward mapping ",
    .function = softforward_add_del_mapping_entrys_fn,
    .short_help =
        "softforward mapping name <name> add|del dst <addr> dst-map <addr> forward <pannel-port>"
        "[src-modify <addr>]",
};

static clib_error_t *
softforward_show_mapping_entry_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    softforward_main_t *sfm = &sf_main;
    clib_error_t *error = 0;
    u8 *mapping_name = NULL;
    softforward_mapping_t *mapping = NULL;
    u8 all = 0;
    u8 hit = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "all"))
            all = 1;
        else if (unformat (line_input, "hit"))
            hit = 1;
        else if (unformat (line_input, "%s", &mapping_name))
            ;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (all)
    {
        pool_foreach (mapping, sfm->mapping_pool,
        ({
            vlib_cli_output (vm, "  %s mapping : has %u entrys", 
                    (char *)mapping->name, pool_elts(mapping->mapping_entrys));
            softforward_mapping_entry_format(vm, mapping, hit);
        }));
    }
    else
    {
        mapping = softforward_get_mapping_by_name(sfm, mapping_name);
        if (mapping)
        {
            vlib_cli_output (vm, "%s mapping : has %u entrys", 
                    (char *)mapping->name, pool_elts(mapping->mapping_entrys));
            softforward_mapping_entry_format(vm, mapping, hit);
        }
        else
        {
            error = clib_error_return (0, "Not found mapping %s", mapping_name);
            goto done;
        }
    }

done:
    unformat_free (line_input);
    return error;
}

VLIB_CLI_COMMAND (softforward_show_mapping_entry_command, static) = {
  .path = "softforward show mapping",
  .short_help = "softforward show mapping <name>|all [hit]",
  .function = softforward_show_mapping_entry_fn,
};

static clib_error_t *
softforward_bind_interface_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    softforward_main_t *sfm = &sf_main;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u8 *mapping_name = NULL;
    softforward_mapping_t *mapping = NULL;
    u32 sw_if_index;
    int is_unbind = 0;
    int rv;

    sw_if_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
            ;
        else if (unformat (line_input, "mapping %s", &mapping_name))
            ;
        else if (unformat (line_input, "del"))
            is_unbind = 1;
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    /* check */
    mapping = softforward_get_mapping_by_name(sfm, mapping_name);
    if (!mapping)
    {
        error = clib_error_return (0, "Not found mapping %s", mapping_name);
        goto done;
    }

    rv = softforward_interface_bind_unbind(sfm, sw_if_index, mapping, is_unbind);
    switch (rv)
    {
    case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "Not found feature arc index");
        goto done;
    case VNET_API_ERROR_INVALID_VALUE_2:
        error = clib_error_return (0, "Not found feature arc feature node index");
        goto done;
    default:
        break;
    }

done:
  unformat_free (line_input);
  return error;
}


VLIB_CLI_COMMAND (softforward_bind_interface_command, static) = {
  .path = "softforward bind",
  .function = softforward_bind_interface_command_fn,
  .short_help = "softforward bind <intfc> mapping <name>"
                "[del]",
};

static clib_error_t *
softforward_show_bind_fn (vlib_main_t * vm,
				       unformat_input_t * input,
				       vlib_cli_command_t * cmd)
{
    softforward_main_t *sfm = &sf_main;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    softforward_mapping_t *mapping = NULL;
    u32 sw_if_index;

    for(sw_if_index = 0; sw_if_index < vec_len(sfm->mapping_interfaces); sw_if_index++)
    {
        if( sfm->mapping_interfaces[sw_if_index] )
        {
            mapping =  pool_elt_at_index(sfm->mapping_pool, 
                       sfm->mapping_interfaces[sw_if_index] - 1);
            vlib_cli_output (vm, " %U bind %s", format_vnet_sw_if_index_name, vnm,
                     sw_if_index, (char *)mapping->name);
        }
    }

    return error;
}

VLIB_CLI_COMMAND (softforward_show_bind_command, static) = {
  .path = "softforward show bind",
  .short_help = "softforward show bind",
  .function = softforward_show_bind_fn,
};
