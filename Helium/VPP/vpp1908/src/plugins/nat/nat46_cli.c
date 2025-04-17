/**
 * @file
 * @brief NAT46 CLI
 */

#include <nat/nat46.h>
#include <nat/nat.h>
#include <nat/nat_inlines.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/types.h>

static clib_error_t *
nat46_add_del_pool_addr_command_fn (vlib_main_t * vm,
				    unformat_input_t * input,
				    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip6_address_t start_addr, end_addr, this_addr;
    int i, count, rv;
    u32 vrf_id = ~0;
    u8 is_add = 1;
    clib_error_t *error = 0;
    u8 no_pat = 0;
    u32 limit_ip_cnt = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%U - %U",
                    unformat_ip6_address, &start_addr,
                    unformat_ip6_address, &end_addr))
            ;
        else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
            ;
        else if (unformat (line_input, "%U", unformat_ip6_address, &start_addr))
            end_addr = start_addr;
        else if (unformat (line_input, "no-pat"))
            no_pat = 1;
        else if (unformat (line_input, "limit-ip-cnt %u", &limit_ip_cnt))
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

    if (clib_memcmp(start_addr.as_u8, end_addr.as_u8, 16 - NAT46_MAX_ADDR_POOL_SHIFT) != 0)
    {
        error = clib_error_return (0, "range address exceeded maximum limit");
        goto done;
    }
    
    if (clib_net_to_host_u64(end_addr.as_u64[1]) <  clib_net_to_host_u64(start_addr.as_u64[1]))
    {
        error = clib_error_return (0, "end address less than start address");
        goto done;
    }

    count = (clib_net_to_host_u64(end_addr.as_u64[1]) - clib_net_to_host_u64(start_addr.as_u64[1])) + 1;
    this_addr = start_addr;

    for (i = 0; i < count; i++)
    {
        rv = nat46_add_del_pool_addr (0, &this_addr, vrf_id, is_add, no_pat, limit_ip_cnt);

        switch (rv)
        {
        case VNET_API_ERROR_NO_SUCH_ENTRY:
            error = clib_error_return (0, "NAT46 pool address %U not exist.",
                        format_ip6_address, &this_addr);
            goto done;
        case VNET_API_ERROR_VALUE_EXIST:
            error = clib_error_return (0, "NAT46 pool address %U exist.",
                        format_ip6_address, &this_addr);
            goto done;
        case VNET_API_ERROR_INVALID_ARGUMENT:
            error = clib_error_return (0, "NAT46 pool address has prefix addr.");
            goto done;
        default:
            break;

        }
        nat46_increment_v6_address (&this_addr);
    }

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
nat46_add_del_pool_prefix_command_fn (vlib_main_t * vm, unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
    clib_error_t *error = 0;
    unformat_input_t _line_input, *line_input = &_line_input;
    u8 is_add = 1;
    u32 vrf_id = 0;
    ip6_address_t prefix;
    u32 plen = 0;
    u8 no_pat = 0;
    u32 limit_ip_cnt = ~0;
    int rv;

    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat
                (line_input, "%U/%u", unformat_ip6_address, &prefix, &plen))
            ;
        else if (unformat (line_input, "tenant-vrf %u", &vrf_id))
            ;
        else if (unformat (line_input, "del"))
            is_add = 0;
        else if (unformat (line_input, "no-pat"))
            no_pat = 1;
        else if (unformat (line_input, "limit-ip-cnt %u", &limit_ip_cnt))
            ;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!plen)
    {
        error = clib_error_return (0, "NAT46 prefix must be set.");
        goto done;
    }

    rv = nat46_add_del_pool_prefix (0, &prefix, (u8) plen, vrf_id, is_add, no_pat, limit_ip_cnt);

    switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "NAT46 prefix not exist.");
        goto done;
    case VNET_API_ERROR_INVALID_VALUE:
        error = clib_error_return (0, "Invalid prefix length.");
        goto done;
    case VNET_API_ERROR_INVALID_ARGUMENT:
            error = clib_error_return (0, "NAT46 pool address has range addr.");
        goto done;
    default:
        break;
    }
done:
    unformat_free (line_input);

    return error;
}


static int
nat46_cli_pool_walk (nat46_address_t * ap, void *ctx)
{
    vlib_main_t *vm = ctx;

    if (ap->fib_index != ~0)
    {
        fib_table_t *fib;
        fib = fib_table_get (ap->fib_index, FIB_PROTOCOL_IP4);
        if (!fib)
            return -1;
        vlib_cli_output (vm, " %U/%u tenant VRF: %u", format_ip6_address, &ap->addr.prefix, ap->addr.plen, fib->ft_table_id);
    }
    else
        vlib_cli_output (vm, " %U/%u", format_ip6_address, &ap->addr, ap->addr.plen);

    if (ap->no_pat)
        vlib_cli_output (vm, "  no-pat");
    if (ap->limit_user_max != ~0)
        vlib_cli_output (vm, "  limit-ip-cnt %u", ap->limit_user_max);

#define _(N, i, n, s) \
    vlib_cli_output (vm, "  %d busy %s ports", ap->busy_##n##_ports, s);
    foreach_snat_protocol
#undef _
        return 0;
}

static clib_error_t *
nat46_show_pool_command_fn (vlib_main_t * vm,
        unformat_input_t * input,
        vlib_cli_command_t * cmd)
{
    vlib_cli_output (vm, "NAT46 pool:");
    nat46_pool_addr_walk (nat46_cli_pool_walk, vm);

    return 0;
}

static clib_error_t *
nat46_interface_feature_command_fn (vlib_main_t * vm,
				    unformat_input_t *
				    input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    vnet_main_t *vnm = vnet_get_main ();
    clib_error_t *error = 0;
    u32 sw_if_index;
    u32 *inside_sw_if_indices = 0;
    u32 *outside_sw_if_indices = 0;
    u8 is_add = 1;
    int i, rv;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "in %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
            vec_add1 (inside_sw_if_indices, sw_if_index);
        else if (unformat (line_input, "out %U", unformat_vnet_sw_interface,
                    vnm, &sw_if_index))
            vec_add1 (outside_sw_if_indices, sw_if_index);
        else if (unformat (line_input, "del"))
            is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (vec_len (inside_sw_if_indices))
    {
        for (i = 0; i < vec_len (inside_sw_if_indices); i++)
        {
            sw_if_index = inside_sw_if_indices[i];
            rv = nat46_add_del_interface (sw_if_index, 1, is_add);
            switch (rv)
            {
            case VNET_API_ERROR_NO_SUCH_ENTRY:
                error = clib_error_return (0, "%U NAT46 feature not enabled.",
                        format_vnet_sw_if_index_name, vnm,
                        sw_if_index);
                goto done;
            case VNET_API_ERROR_VALUE_EXIST:
                error = clib_error_return (0, "%U NAT46 feature already enabled.",
                        format_vnet_sw_if_index_name, vnm,
                        vnm, sw_if_index);
                goto done;
            case VNET_API_ERROR_INVALID_VALUE:
                error = clib_error_return (0, "%U NAT46 feature enable/disable failed. feature failed",
                            format_vnet_sw_if_index_name, vnm,
                            sw_if_index);
                goto done;
            case VNET_API_ERROR_INVALID_VALUE_2:
                error = clib_error_return (0, "%U NAT46 feature enable/disable failed. arc failed",
                            format_vnet_sw_if_index_name, vnm,
                            sw_if_index);
                goto done;
            default:
                break;

            }
        }
    }

    if (vec_len (outside_sw_if_indices))
    {
        for (i = 0; i < vec_len (outside_sw_if_indices); i++)
        {
            sw_if_index = outside_sw_if_indices[i];
            rv = nat46_add_del_interface (sw_if_index, 0, is_add);
            switch (rv)
            {
            case VNET_API_ERROR_NO_SUCH_ENTRY:
                error = clib_error_return (0, "%U NAT46 feature not enabled.",
                        format_vnet_sw_if_index_name, vnm,
                        sw_if_index);
                goto done;
            case VNET_API_ERROR_VALUE_EXIST:
                error = clib_error_return (0, "%U NAT46 feature already enabled.",
                        format_vnet_sw_if_index_name, vnm,
                        sw_if_index);
                goto done;
            case VNET_API_ERROR_INVALID_VALUE:
            case VNET_API_ERROR_INVALID_VALUE_2:
                error = clib_error_return (0, "%U NAT46 feature enable/disable failed.",
                        format_vnet_sw_if_index_name, vnm,
                        sw_if_index);
                goto done;
            default:
                break;

            }
        }
    }

done:
    unformat_free (line_input);
    vec_free (inside_sw_if_indices);
    vec_free (outside_sw_if_indices);

    return error;
}

static int
nat46_cli_interface_walk (snat_interface_t * i, void *ctx)
{
    vlib_main_t *vm = ctx;
    vnet_main_t *vnm = vnet_get_main ();

    vlib_cli_output (vm, " %U %s", format_vnet_sw_if_index_name, vnm,
            i->sw_if_index,
            (nat_interface_is_inside (i)
             && nat_interface_is_outside (i)) ? "in out" :
            nat_interface_is_inside (i) ? "in" : "out");
    return 0;
}

static clib_error_t *
nat46_show_interfaces_command_fn (vlib_main_t * vm,
				  unformat_input_t *
				  input, vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "NAT46 interfaces:");
  nat46_interfaces_walk (nat46_cli_interface_walk, vm);

  return 0;
}

static clib_error_t *
nat46_add_del_static_bib_command_fn (vlib_main_t *
				     vm,
				     unformat_input_t
				     * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u8 is_add = 1;
    ip4_address_t in_addr;
    ip6_address_t out_addr;
    u32 in_port = 0;
    u32 out_port = 0;
    u32 vrf_id = 0, protocol;
    snat_protocol_t proto = 0;
    u8 p = 0;
    nat46_static_bib_ctx_t ctx = {
        .port_start = 0,
        .port_end   = 0,
    };

    int rv;

    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%U %u", unformat_ip4_address,
                    &in_addr, &in_port))
            ;
        else if (unformat (line_input, "%U %u", unformat_ip6_address,
                    &out_addr, &out_port))
            ;
        else if (unformat (line_input, "vrf %u", &vrf_id))
            ;
        else if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
            ;
        else if (unformat (line_input, "%U %U %u", unformat_ip4_address, &in_addr, unformat_ip6_address, &out_addr, &protocol))
            p = (u8) protocol;
        else if (unformat (line_input, "del"))
            is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!p)
    {
        if (!in_port)
        {
            error =
                clib_error_return (0, "inside port and address  must be set");
            goto done;
        }

        if (!out_port)
        {
            error =
                clib_error_return (0, "outside port and address  must be set");
            goto done;
        }

        p = snat_proto_to_ip_proto (proto);
    }

    rv =
        nat46_add_del_static_bib_entry (&in_addr, &out_addr, (u16) in_port,
                (u16) out_port, p, vrf_id, is_add, &ctx);

    switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "NAT46 BIB entry not exist.");
        goto done;
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "NAT46 BIB entry exist.");
        goto done;
    case VNET_API_ERROR_UNSPECIFIED:
        error = clib_error_return (0, "Crerate NAT46 BIB entry failed.");
        goto done;
    case VNET_API_ERROR_INVALID_VALUE:
        error =
            clib_error_return (0,
                    "Outside address %U and port %u already in use.",
                    format_ip4_address, &out_addr, out_port);
        goto done;
    case VNET_API_ERROR_INVALID_VALUE_2:
        error = clib_error_return (0, "Invalid outside port. range(%u-%u)", ctx.port_start, ctx.port_end);
    default:
        break;
    }

done:
    unformat_free (line_input);

    return error;
}

static int
nat46_cli_bib_walk (nat46_db_bib_entry_t * bibe, void *ctx)
{
    vlib_main_t *vm = ctx;
    fib_table_t *fib;

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP4);
    if (!fib)
        return -1;

    switch (bibe->proto)
    {
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
        vlib_cli_output (vm, " %U %u %U %u protocol %U vrf %u %s %u sessions",
                format_ip4_address, &bibe->in_addr,
                clib_net_to_host_u16 (bibe->in_port),
                format_ip6_address, &bibe->out_addr,
                clib_net_to_host_u16 (bibe->out_port),
                format_snat_protocol,
                ip_proto_to_snat_proto (bibe->proto), fib->ft_table_id,
                bibe->is_static ? "static" : "dynamic", bibe->ses_num);
        break;
    default:
        vlib_cli_output (vm, " %U %U protocol %u vrf %u %s %u sessions",
                format_ip4_address, &bibe->in_addr,
                format_ip6_address, &bibe->out_addr,
                bibe->proto, fib->ft_table_id,
                bibe->is_static ? "static" : "dynamic", bibe->ses_num);
    }
    return 0;
}

static clib_error_t *
nat46_show_bib_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
    nat46_main_t *nm = &nat46_main;
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u32 proto = ~0;
    u8 p = 255;
    nat46_db_t *db;

    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
        p = snat_proto_to_ip_proto (proto);
    else if (unformat (line_input, "unknown"))
        p = 0;
    else if (unformat (line_input, "all"))
        ;
    else
    {
        error = clib_error_return (0, "unknown input: '%U'",
                format_unformat_error, line_input);
        goto done;
    }

    if (p == 255)
        vlib_cli_output (vm, "NAT46 BIB entries:");
    else
        vlib_cli_output (vm, "NAT46 %U BIB entries:", format_snat_protocol, proto);

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    nat46_db_bib_walk (db, p, nat46_cli_bib_walk, vm);
  /* *INDENT-ON* */

done:
  unformat_free (line_input);

  return error;
}

typedef struct nat46_cli_st_walk_ctx_t_
{
  vlib_main_t *vm;
  nat46_db_t *db;
} nat46_cli_st_walk_ctx_t;

static int
nat46_cli_st_walk (nat46_db_st_entry_t * ste, void *arg)
{
    nat46_cli_st_walk_ctx_t *ctx = arg;
    vlib_main_t *vm = ctx->vm;
    nat46_db_bib_entry_t *bibe;
    fib_table_t *fib;

    bibe = nat46_db_bib_entry_by_index (ctx->db, ste->proto, ste->bibe_index);
    if (!bibe)
        return -1;

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP4);
    if (!fib)
        return -1;

    u32 vrf_id = fib->ft_table_id;

    if (ste->proto == IP_PROTOCOL_ICMP)
        vlib_cli_output (vm, " %U %U %u %U %U %u protocol %U vrf %u",
                format_ip4_address, &bibe->in_addr,
                format_ip4_address, &ste->in_r_addr,
                clib_net_to_host_u16 (bibe->in_port),
                format_ip6_address, &bibe->out_addr,
                format_ip6_address, &ste->out_r_addr,
                clib_net_to_host_u16 (bibe->out_port),
                format_snat_protocol,
                ip_proto_to_snat_proto (bibe->proto), vrf_id);
    else if (ste->proto == IP_PROTOCOL_TCP || ste->proto == IP_PROTOCOL_UDP)
        vlib_cli_output (vm, " %U %u %U %u %U %u %U %u protcol %U vrf %u",
                format_ip4_address, &bibe->in_addr,
                clib_net_to_host_u16 (bibe->in_port),
                format_ip4_address, &ste->in_r_addr,
                clib_net_to_host_u16 (ste->r_port),
                format_ip6_address, &bibe->out_addr,
                clib_net_to_host_u16 (bibe->out_port),
                format_ip6_address, &ste->out_r_addr,
                clib_net_to_host_u16 (ste->r_port),
                format_snat_protocol,
                ip_proto_to_snat_proto (bibe->proto), vrf_id);
    else
        vlib_cli_output (vm, " %U %U %U %U protocol %u vrf %u",
                format_ip4_address, &bibe->in_addr,
                format_ip4_address, &ste->in_r_addr,
                format_ip6_address, &bibe->out_addr,
                format_ip6_address, &ste->out_r_addr,
                bibe->proto, vrf_id);

    return 0;
}

static clib_error_t *
nat46_show_st_command_fn (vlib_main_t * vm,
			  unformat_input_t * input, vlib_cli_command_t * cmd)
{
    nat46_main_t *nm = &nat46_main;
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = 0;
    u32 proto = ~0;
    u8 p = 255;
    nat46_db_t *db;
    nat46_cli_st_walk_ctx_t ctx = {
        .vm = vm,
    };

    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
        p = snat_proto_to_ip_proto (proto);
    else if (unformat (line_input, "unknown"))
        p = 0;
    else if (unformat (line_input, "all"))
        ;
    else
    {
        error = clib_error_return (0, "unknown input: '%U'",
                format_unformat_error, line_input);
        goto done;
    }

    if (p == 255)
        vlib_cli_output (vm, "NAT46 sessions:");
    else
        vlib_cli_output (vm, "NAT46 %U sessions:", format_snat_protocol, proto);
    /* *INDENT-OFF* */
    vec_foreach (db, nm->db)
    {
        ctx.db = db;
        nat46_db_st_walk (db, p, nat46_cli_st_walk, &ctx);
    }
    /* *INDENT-ON* */

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
nat46_add_interface_address_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
    vnet_main_t *vnm = vnet_get_main ();
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 sw_if_index;
    int rv;
    int is_add = 1;
    clib_error_t *error = 0;
    u8 no_pat = 0;
    u32 limit_ip_cnt = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat
                (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index));
        else if (unformat (line_input, "no-pat"))
            no_pat = 1;
        else if (unformat (line_input, "limit-ip-cnt %u", &limit_ip_cnt))
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

    rv = nat46_add_interface_address (sw_if_index, is_add, no_pat, limit_ip_cnt);

    switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "entry not exist");
        break;
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "entry exist");
        break;
    default:
        break;
    }

done:
    unformat_free (line_input);

    return error;
}

typedef struct nat46_cli_remote_mapping_walk_ctx_t_
{
  vlib_main_t *vm;
  nat46_db_t *db;
} nat46_cli_remote_mapping_walk_ctx_t;

static int
nat46_cli_remote_mapping_walk (nat46_remote_mapping_entry_t *mapping, void *arg)
{
    nat46_cli_remote_mapping_walk_ctx_t *ctx = arg;
    vlib_main_t *vm = ctx->vm;
    fib_table_t *fib;
    snat_protocol_t proto = 0;

    proto = ip_proto_to_snat_proto (mapping->proto);

    fib = fib_table_get (mapping->fib_index, FIB_PROTOCOL_IP4);
    if (!fib)
        return -1;

    u32 vrf_id = fib->ft_table_id;

    if(proto == ~0)
        vlib_cli_output (vm, " %U %U protocol all vrf %u",
            format_ip4_address, &mapping->l_addr,
            format_ip6_address, &mapping->r_addr,
            vrf_id);
    else
        vlib_cli_output (vm, " %U %U protocol %U vrf %u",
            format_ip4_address, &mapping->l_addr,
            format_ip6_address, &mapping->r_addr,
            format_snat_protocol, proto, 
            vrf_id);
    return 0;
}

static clib_error_t *
show_nat46_remote_mapping_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
    nat46_main_t *nm = &nat46_main;
    nat46_cli_remote_mapping_walk_ctx_t ctx = {
        .vm = vm,
    };
    vlib_cli_output (vm, "NAT46 remote mapping:");
    nat46_db_remote_mapping_walk (&nm->remote_mapping, nat46_cli_remote_mapping_walk, &ctx);
    return 0;
}

static clib_error_t *
nat46_add_remote_mapping_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    int rv;
    int is_add = 1;
    ip46_address_t laddr, raddr;
    u32 vrf_id = 0;
    snat_protocol_t proto = 0;
    u8 ip_proto = 255;
    clib_error_t *error = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "in %U", unformat_ip4_address, &laddr.ip4))
            ;
        else if (unformat (line_input, "out %U", unformat_ip6_address, &raddr))
            ;
        else if (unformat (line_input, "vrf %u", &vrf_id))
            ;
        else if (unformat (line_input, "%U", unformat_snat_protocol, &proto))
        {
            ip_proto = snat_proto_to_ip_proto (proto);
        }
        else if (unformat (line_input, "del"))
            is_add = 0;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    rv = nat46_add_remote_mapping_entry(&laddr.ip4, &raddr.ip6, ip_proto, vrf_id, is_add);

    switch (rv)
    {
    case VNET_API_ERROR_NO_SUCH_ENTRY:
        error = clib_error_return (0, "entry not find");
        break;
    case VNET_API_ERROR_VALUE_EXIST:
        error = clib_error_return (0, "entry exist");
        break;
    case VNET_API_ERROR_NO_SUCH_TABLE:
        error = clib_error_return (0, "entry mapping ip4toip6 failed");
        break;
    case VNET_API_ERROR_NO_SUCH_TABLE2:
        error = clib_error_return (0, "entry mapping ip6toip4 failed");
        break;
    default:
        break;
    }

done:
    unformat_free (line_input);
    return error;
}

static clib_error_t *
show_nat46_expire_walk_interval_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
    nat46_main_t *nm = &nat46_main;
    vlib_cli_output (vm, "NAT46 expire walk interval %lfs", nm->nat46_expire_walk_interval);
    return 0;
}

static clib_error_t *
nat46_set_expire_walk_interval_command_fn (vlib_main_t * vm,
					unformat_input_t * input,
					vlib_cli_command_t * cmd)
{
    nat46_main_t *nm = &nat46_main;
    unformat_input_t _line_input, *line_input = &_line_input;
    f64 second = 10.0;
    clib_error_t *error = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "interval %u", &second))
            ;
        else
        {
            error = clib_error_return (0, "unknown input: '%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }
    nm->nat46_expire_walk_interval = second;
done:
    unformat_free (line_input);
    return error;
}

/* *INDENT-OFF* */

/*?
 * @cliexpar
 * @cliexstart{nat46 add pool address}
 * Add/delete NAT46 pool address.
 * To add single NAT46 pool address use:
 *  vpp# nat46 add pool address ff::1
 * To add NAT46 pool address range use:
 *  vpp# nat46 add pool address ff::1 - ff::10
 * To add NAT46 pool address for specific tenant use:
 *  vpp# nat46 add pool address ff::2 tenant-vrf 100
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat46_add_pool_address_command, static) = {
  .path = "nat46 add pool address range",
  .short_help = "nat46 add pool address range <ip6-range-start> [- <ip6-range-end>] "
                "[tenant-vrf <vrf-id>] [no-pat] [limit-ip-cnt <cnt>] [del]",
  .function = nat46_add_del_pool_addr_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat46 add pool address prefix}
 * Set NAT46 prefix for addr pool prefix .
 * To set NAT46 global prefix use:
 *  vpp# nat46 add pool address prefix 2001:db8::/32
 * To set NAT46 prefix for specific tenant use:
 *  vpp# nat46 add pool address prefix 2001:db8:122:300::/56 tenant-vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat46_add_del_pool_prefix_command, static) = {
  .path = "nat46 add pool address prefix",
  .short_help = "nat46 add pool address prefix <ip6-prefix>/<plen> [tenant-vrf <vrf-id>] "
                "[no-pat] [limit-ip-cnt <cnt>] [del]",
  .function = nat46_add_del_pool_prefix_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat46 pool}
 * Show NAT46 pool.
 *  vpp# show nat46 pool
 *  NAT46 pool:
 *   ff::1 tenant VRF: 0
 *   ff::2 tenant VRF: 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat46_pool_command, static) = {
  .path = "show nat46 pool",
  .short_help = "show nat46 pool",
  .function = nat46_show_pool_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{set interface nat46}
 * Enable/disable NAT46 feature on the interface.
 * To enable NAT46 feature with local (IPv4) network interface
 * GigabitEthernet0/8/0 and external (IPv6) network interface
 * GigabitEthernet0/a/0 use:
 *  vpp# set interface nat46 in GigabitEthernet0/8/0 out GigabitEthernet0/a/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (set_interface_nat46_command, static) = {
  .path = "set interface nat46",
  .short_help = "set interface nat46 in|out <intfc> [del]",
  .function = nat46_interface_feature_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat46 interfaces}
 * Show interfaces with NAT46 feature.
 * To show interfaces with NAT46 feature use:
 *  vpp# show nat46 interfaces
 *  NAT46 interfaces:
 *   GigabitEthernet0/8/0 in
 *   GigabitEthernet0/a/0 out
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat46_interfaces_command, static) = {
  .path = "show nat46 interfaces",
  .short_help = "show nat46 interfaces",
  .function = nat46_show_interfaces_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat46 add static bib}
 * Add/delete NAT46 static BIB entry.
 * To create NAT46 satatic BIB entry use:
 *  vpp# nat46 add static bib 10.1.1.3 1234 2001:db8:c000:221:: 5678 tcp
 *  vpp# nat46 add static bib 10.1.1.3 1234 2001:db8:c000:221:: 5678 udp vrf 10
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat46_add_del_static_bib_command, static) = {
  .path = "nat46 add static bib",
  .short_help = "nat46 add static bib <ip4-addr> <port> <ip6-addr> <port> "
                "tcp|udp|icmp [vfr <table-id>] [del]",
  .function = nat46_add_del_static_bib_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat46 bib}
 * Show NAT46 BIB entries.
 * To show NAT46 TCP BIB entries use:
 *  vpp# show nat46 bib tcp
 *  NAT46 tcp BIB:
 *   10.0.0.3 6303 fd01:1::2 62303 tcp vrf 0 dynamic 1 sessions
 *   10.1.1.3 1234 2001:db8:c000:221:: 5678 tcp vrf 0 static 2 sessions
 * To show NAT46 UDP BIB entries use:
 *  vpp# show nat46 bib udp
 *  NAT46 udp BIB:
 *   10.0.0.3 6304 fd01:1::2 10546 udp vrf 0 dynamic 10 sessions
 *   10.1.1.3 1234 2001:db8:c000:221:: 5678 udp vrf 10 static 0 sessions
 * To show NAT46 ICMP BIB entries use:
 *  vpp# show nat46 bib icmp
 *  NAT46 icmp BIB:
 *   10.0.0.3 6305 fd01:1::2 63209 icmp vrf 10 dynamic 1 sessions
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat46_bib_command, static) = {
  .path = "show nat46 bib",
  .short_help = "show nat46 bib all|tcp|udp|icmp|unknown",
  .function = nat46_show_bib_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{show nat46 session table}
 * Show NAT46 session table.
 * To show NAT46 TCP session table use:
 *  vpp# show nat46 session table tcp
 *  NAT46 tcp session table:
 *   fd01:1::2 6303 64:ff9b::ac10:202 20 10.0.0.3 62303 172.16.2.2 20 tcp vrf 0
 *   fd01:3::2 6303 64:ff9b::ac10:202 20 10.0.10.3 21300 172.16.2.2 20 tcp vrf 10
 * To show NAT46 UDP session table use:
 * #vpp show nat46 session table udp
 * NAT46 udp session table:
 *  fd01:1::2 6304 64:ff9b::ac10:202 20 10.0.0.3 10546 172.16.2.2 20 udp vrf 0
 *  fd01:3::2 6304 64:ff9b::ac10:202 20 10.0.10.3 58627 172.16.2.2 20 udp vrf 10
 *  fd01:1::2 1235 64:ff9b::a00:3 4023 10.0.0.3 24488 10.0.0.3 4023 udp vrf 0
 *  fd01:1::3 23 64:ff9b::a00:3 24488 10.0.0.3 4023 10.0.0.3 24488 udp vrf 0
 * To show NAT46 ICMP session table use:
 * #vpp show nat46 session table icmp
 * NAT46 icmp session table:
 *  fd01:1::2 64:ff9b::ac10:202 6305 10.0.0.3 172.16.2.2 63209 icmp vrf 0
 * @cliexend
?*/
VLIB_CLI_COMMAND (show_nat46_st_command, static) = {
  .path = "show nat46 session table",
  .short_help = "show nat46 session table all|tcp|udp|icmp|unknown",
  .function = nat46_show_st_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat46 add interface address}
 * Add/delete NAT46 pool address from specific (DHCP addressed) interface.
 * To add NAT46 pool address from specific interface use:
 *  vpp# nat46 add interface address GigabitEthernet0/8/0
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat46_add_interface_address_command, static) = {
    .path = "nat46 add interface address",
    .short_help = "nat46 add interface address <interface> [no-pat] [limit-ip-cnt <cnt>] [del]",
    .function = nat46_add_interface_address_command_fn,
};

/*?
 * @cliexpar
 * @cliexstart{nat46 add remote mapping }
 * Add/delete NAT46 ip4 mapping ip6 entry for remote.
 * To create NAT46 satatic BIB entry use:
 *  vpp# nat46 add remote mapping 10.1.1.3 2001:db8:c000:221:: 
 *  vpp# nat46 add remote mapping tcp 10.1.1.3 2001:db8:c000:221::
 *  vpp# nat46 add remote mapping tcp 10.1.1.3 2001:db8:c000:221:: vrf 10
 *  vpp# nat46 add remote mapping tcp 10.1.1.3 80 2001:db8:c000:221:: 80 
 * @cliexend
?*/
VLIB_CLI_COMMAND (nat46_add_remote_mapping_command, static) = {
    .path = "nat46 add remote mapping",
    .short_help = "nat46 add remote mapping tcp|udp|icmp in <ip4> [<port>] out <ip6> [<port>] [vrf <table-id>] [del]",
    .function = nat46_add_remote_mapping_command_fn,
};

VLIB_CLI_COMMAND (show_nat46_remote_mapping_command, static) = {
    .path = "show nat46 remote mapping",
    .short_help = "show nat46 remote mapping",
    .function = show_nat46_remote_mapping_command_fn,
};

VLIB_CLI_COMMAND (nat46_set_expire_walk_interval_command, static) = {
    .path = "nat46 set expire walk interval",
    .short_help = "nat46 set expire walk interval [second]",
    .function = nat46_set_expire_walk_interval_command_fn,
};

VLIB_CLI_COMMAND (show_nat46_set_expire_wakl_interval_command, static) = {
    .path = "show nat46 expire walk interval",
    .short_help = "show nat46 expire walk interval",
    .function = show_nat46_expire_walk_interval_command_fn,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
