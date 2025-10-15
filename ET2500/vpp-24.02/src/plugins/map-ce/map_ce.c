/*
 * map_ce.c : MAP CE support
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

#include <vppinfra/crc32.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include "map_ce.h"

map_ce_main_t map_ce_main;

/* Format */
static char *
map_ce_type_to_string (u32 flags)
{
  if (flags & MAP_CE_DOMAIN_TRANSLATION)
    return "MAP-T";
  else 
    return "MAP-E";
}

u8 *
format_map_ce_domain (u8 * s, va_list * args)
{
    map_ce_domain_t *d = va_arg (*args, map_ce_domain_t *);
    bool counters = va_arg (*args, int);
    map_ce_main_t *mm = &map_ce_main;
    u32 map_domain_index = d - mm->domains;
    map_ce_domain_extra_t *de = 0;

    if (map_domain_index < vec_len (mm->domain_extras))
        de = vec_elt_at_index (mm->domain_extras, map_domain_index);

    s = format (s,
	      "[%d] tag {%s} ip4-pfx %U/%d ip6-pfx %U/%d ip6-dst %U/%d end-user-prefix %U/%d "
	      "ea-bits-len %d psid-offset %d psid-len %d mtu %d %s",
	      map_domain_index, (de && de->tag) ? de->tag : (u8 *) "[no-tag]",
	      format_ip4_address, &d->ip4_prefix, d->ip4_prefix_len,
	      format_ip6_address, &d->ip6_prefix, d->ip6_prefix_len,
	      format_ip6_address, &d->ip6_dst, d->ip6_dst_len,
	      format_ip6_address, &d->end_user_prefix, d->end_user_prefix_len,
	      d->ea_bits_len, d->psid_offset, d->psid_length, d->mtu,
          map_ce_type_to_string (d->flags));

    if (counters)
    {
        map_ce_domain_counter_lock (mm);
        vlib_counter_t v;
        vlib_get_combined_counter (&mm->domain_counters[MAP_CE_DOMAIN_COUNTER_TX], map_domain_index, &v);
        s = format (s, "  TX: %lld/%lld", v.packets, v.bytes);
        vlib_get_combined_counter (&mm->domain_counters[MAP_CE_DOMAIN_COUNTER_RX], map_domain_index, &v);
        s = format (s, "  RX: %lld/%lld", v.packets, v.bytes);
        map_ce_domain_counter_unlock (mm);
    }
    s = format (s, "\n");

    if (d->psid_valid)
        s = format (s, " manually psid valid: %d\n", d->psid);

    //params
    if (d->tc_valid)
    {
        if (d->tc_copy)
            s = format (s, " Ipv6 Traffic class: copy\n");
        else
            s = format (s, " Ipv6 Traffic class: %d\n", d->tc);
    }
    if (d->tos_valid)
    {
        if (d->tc_copy)
            s = format (s, " Ipv4 Tos: copy\n");
        else
            s = format (s, " Ipv4 Tos: %d\n", d->tos);
    }
    if (d->tcp_mss_valid)
    {
        s = format (s, " TCP MSS clamping: %d\n", d->tcp_mss);
    }
    if (d->frag_valid)
    {
        s = format (s, " Fragmentation: %s\n", d->frag_inner ? "Frag Inner" : "Frag tunnel");
        s = format (s, " Ignore df: %s\n", d->frag_ignore_df ? "True" : "False");
    }
    if (d->sec_check_valid)
    {
        s = format (s, " security check on first packet: %s\n", d->sec_check ? "True" : "False");
        s = format (s, " security check on frag packet: %s\n", d->sec_check_frag ? "True" : "False");
    }
    if (d->icmp6_enabled_valid)
    {
        s = format (s, " send icmpv6 unreachable err msg: %s\n", d->icmp6_enabled ? "True" : "False");
    }
    if (d->icmp4_src_address_valid)
    {
        s = format (s, " ipv4 icmp err relay src address: %U\n", format_ip4_address, &d->icmp4_src_address);
    }
  return s;
}

u8 *
format_map_nat44_protocol (u8 *s, va_list *args)
{
  u32 i = va_arg (*args, u32);
  u8 *t = 0;

  switch (i)
    {
#define _(N, j, n, str) case MAP_CE_NAT_PROTOCOL_##N: t = (u8 *) str; break;
      foreach_map_ce_nat_protocol
#undef _
    default:
      s = format (s, "unknown");
      return s;
    }
  s = format (s, "%s", t);
  return s;
}

u8 *
format_map_nat44_ei_key (u8 *s, va_list *args)
{
    u64 key = va_arg (*args, u64);

    ip4_address_t addr;
    u16 port;
    map_ce_nat_protocol_t protocol;

    split_map_nat_key (key, &addr, &port, &protocol);

    s = format (s, "%U proto %U port %d", format_ip4_address, &addr,
                                          format_map_nat44_protocol, protocol, 
                                          clib_net_to_host_u16 (port));
  return s;
}

u8 *
format_map_nat44_ei_static_session_kvp (u8 *s, va_list *args)
{
    clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

    s = format (s, "%U static-mapping-index %llu", format_map_nat44_ei_key, v->key, v->value);

    return s;
}

u8 *
format_map_nat44_ei_session_kvp (u8 *s, va_list *args)
{
    clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

    s = format (s, "%U session-index %llu", format_map_nat44_ei_key, v->key, v->value);

    return s;
}

u8 *
format_map_nat44_ei_user_kvp (u8 *s, va_list *args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);
  map_nat44_ei_user_key_t k;

  k.as_u64 = v->key;

  s = format (s, "%U user-index %llu", format_ip4_address, &k.addr, v->value);

  return s;
}

/*
 * packet trace format function
 */
u8 *
format_map_ce_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    map_ce_trace_t *t = va_arg (*args, map_ce_trace_t *);
    u32 map_domain_index = t->map_domain_index;

    s = format (s, "MAP CE domain index: %d", map_domain_index);

    return s;
}

u8 *
format_map_ce_nat44_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    map_ce_nat44_trace_t *t = va_arg (*args, map_ce_nat44_trace_t *);

    s = format (s, "MAP CE domain index: %d", t->map_domain_index);
    if (t->local_addr_vld)
        s = format (s, "\t: local_addr: %U", format_ip4_address, &t->local_addr);
    else
        s = format (s, "\t: local_addr: None");
    if (t->external_addr_vld)
        s = format (s, "\t: external_addr: %U", format_ip4_address, &t->external_addr);
    else
        s = format (s, "\t: external_addr: None");

    s = format (s, "\t: local_port: %d", t->local_port);
    s = format (s, "\t: external_port: %d", t->external_port);
    s = format (s, "\t: protocol: %U", format_map_nat44_protocol, t->proto);

    return s;
}

/*
 * This code supports MAP-T:
 *
 * With a DMR prefix length of 64 or 96 (RFC6052).
 *
 */

/*
 * Save user-assigned MAP domain names ("tags") in a vector of
 * extra domain information.
 */
static void
map_ce_save_extras (u32 map_domain_index, u8 * tag)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_extra_t *de;

    if (map_domain_index == ~0)
        return;

    vec_validate (mm->domain_extras, map_domain_index);
    de = vec_elt_at_index (mm->domain_extras, map_domain_index);
    clib_memset (de, 0, sizeof (*de));

    if (!tag)
        return;

    vec_validate_init_c_string (de->tag, tag, strlen ((char *) tag));
}


static void
map_ce_free_extras (u32 map_domain_index)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_extra_t *de;

    if (map_domain_index == ~0)
        return;

    if (map_domain_index >= vec_len (mm->domain_extras))
        return;

    de = vec_elt_at_index (mm->domain_extras, map_domain_index);
    vec_free (de->tag);
}

int
map_ce_create_domain (ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
                      ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
                      ip6_address_t * ip6_dst, u8 ip6_dst_len,
                      ip6_address_t * end_user_prefix, u8 end_user_prefix_len,
                      u8 ea_bits_len, u8 psid_offset, u8 psid_length,
                      u32 * map_domain_index, u16 mtu, u8 flags, u8 * tag)
{
    u8 suffix_len, suffix_shift;
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    /* How many, and which bits to grab from the IPv4 SA */
    if (ip4_prefix_len + ea_bits_len < 32)
    {
        flags |= MAP_CE_DOMAIN_PREFIX;
        suffix_shift = 32 - ip4_prefix_len - ea_bits_len;
        suffix_len = ea_bits_len;
    }
    else
    {
        suffix_shift = 0;
        suffix_len = 32 - ip4_prefix_len;
    }

    /* EA bits must be within the first 64 bits */
    if (ea_bits_len > 0 && ((ip6_prefix_len + ea_bits_len) > 64 ||
                ip6_prefix_len + suffix_len + psid_length > 64))
    {
        clib_warning
            ("Embedded Address bits must be within the first 64 bits of "
             "the IPv6 prefix");
        return -1;
    }

    /* Get domain index */
    pool_get_aligned (mm->domains, d, CLIB_CACHE_LINE_BYTES * 2);
    clib_memset (d, 0, sizeof (*d));
    *map_domain_index = d - mm->domains;

    /* Init domain struct */
    d->ip4_prefix.as_u32 = ip4_prefix->as_u32;
    d->ip4_prefix_len = ip4_prefix_len;
    d->ip6_prefix = *ip6_prefix;
    d->ip6_prefix_len = ip6_prefix_len;
    d->ip6_dst = *ip6_dst;
    d->ip6_dst_len = ip6_dst_len;
    d->end_user_prefix = *end_user_prefix;
    d->end_user_prefix_len = end_user_prefix_len;
    d->ea_bits_len = ea_bits_len;
    d->psid_offset = psid_offset;
    d->psid_length = psid_length;
    d->mtu = mtu;
    d->flags = flags;

    if (d->ea_bits_len == 0 &&
        d->psid_length > 0 &&
        d->ip4_prefix_len == 32)
    {
        d->psid_valid = 1;
    }

    d->suffix_shift = suffix_shift;
    d->suffix_mask = (1 << suffix_len) - 1;
    d->psid_shift = 16 - psid_length - psid_offset;
    d->psid_mask = (1 << d->psid_length) - 1;
    d->ea_shift = 64 - ip6_prefix_len - suffix_len - d->psid_length;

    /* Save a user-assigned MAP domain name if provided. */
    if (tag)
        map_ce_save_extras (*map_domain_index, tag);

    map_ce_nat44_domain_create(*map_domain_index);

    /* Validate packet/byte counters */
    map_ce_domain_counter_lock (mm);
    int i;
    for (i = 0; i < vec_len (mm->domain_counters); i++)
    {
        vlib_validate_combined_counter (&mm->domain_counters[i],
                *map_domain_index);
        vlib_zero_combined_counter (&mm->domain_counters[i], *map_domain_index);
    }
    map_ce_domain_counter_unlock (mm);

    /* MAP longest match lookup table (input feature) */
    mm->ip4_prefix_tbl->add (mm->ip4_prefix_tbl, &d->ip4_prefix,
            d->ip4_prefix_len, *map_domain_index);

    mm->ip6_prefix_tbl->add (mm->ip6_prefix_tbl, &d->ip6_prefix,
            d->ip6_prefix_len, *map_domain_index);

    mm->ip4_local_tbl->add (mm->ip4_local_tbl, &d->ip4_prefix,
            d->ip4_prefix_len, *map_domain_index);

    return 0;
}

/*
 * map_ce_delete_domain
 */
int
map_ce_delete_domain (u32 map_domain_index)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;
    uint32_t i;
    ip_prefix_t *prefix;

    if (pool_is_free_index (mm->domains, map_domain_index))
    {
        clib_warning ("MAP CE domain delete: domain does not exist: %d",
                map_domain_index);
        return -1;
    }

    d = pool_elt_at_index (mm->domains, map_domain_index);

    mm->ip4_prefix_tbl->delete (mm->ip4_prefix_tbl, &d->ip4_prefix,
            d->ip4_prefix_len);
    mm->ip6_prefix_tbl->delete (mm->ip6_prefix_tbl, &d->ip6_prefix,
            d->ip6_prefix_len);
    mm->ip4_local_tbl->delete (mm->ip4_local_tbl, &d->ip4_prefix,
            d->ip4_prefix_len);

    /* Release user-assigned MAP CE domain name. */
    map_ce_free_extras (map_domain_index);

    /* Release MAP CE NAT44 domain */
    map_ce_nat44_domain_remove(map_domain_index);

    /* release this domain local_rule */
    for (i = 0; i < vec_len(d->local_rules); i++)
    {
        prefix = &d->local_rules[i];
        if (ip_prefix_version(prefix))
        {
            mm->ip4_local_tbl->delete (mm->ip4_local_tbl, 
                                    &ip_prefix_v4(prefix),
                                    ip_prefix_len(prefix));
        }
    }
    vec_free (d->local_rules);

    pool_put (mm->domains, d);
    return 0;
}

int
map_ce_domain_set_psid (u32 domain_index, u16 psid)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP CE domain does not exist: %d", domain_index);
        return -1;
    }

    if (pool_is_free_index (mm->nat_domains, domain_index))
    {
        clib_warning ("MAP CE nat domain does not exist: %d", domain_index);
        return -1;
    }
    d = pool_elt_at_index (mm->domains, domain_index);

    if (!d->psid_valid)
    {
        clib_warning ("The BMR rule of MAP CE domain does not support manual configuration of psid: %d", domain_index);
        return -1;
    }

    if (psid >= (1 << d->psid_length))
    {
        clib_warning ("MAP CE domain psid invalid: %d", domain_index);
        return -1;
    }

    d->psid = psid;

    map_ce_nat44_domain_update_psid(domain_index, d->psid);

    return 0;
}

static int
map_ce_local_rule_cmp (ip_prefix_t *a, ip_prefix_t *b)
{
  return ip_prefix_len(a) == ip_prefix_len(a) &&
         ip_prefix_version(a) == ip_prefix_version(b) && 
         ip46_address_is_equal(&ip_addr_46(&ip_prefix_addr(a)), &ip_addr_46(&ip_prefix_addr(b)));
}

int
map_ce_add_del_local_prefix (u32 map_domain_index,
                             ip4_address_t * ip4_prefix, 
                             u8 ip4_prefix_len,
                             bool is_add)
{
    map_ce_domain_t *d;
    map_ce_main_t *mm = &map_ce_main;
    ip_prefix_t prefix;
    u32 index = ~0;

    if (pool_is_free_index (mm->domains, map_domain_index))
    {
        clib_warning ("MAP CE rule: domain does not exist: %d", map_domain_index);
        return -1;
    }
    d = pool_elt_at_index (mm->domains, map_domain_index);

    clib_memset(&prefix, 0, sizeof(ip_prefix_t));
    ip_prefix_len(&prefix) = ip4_prefix_len;
    ip_prefix_version(&prefix) = AF_IP4;
    ip_prefix_v4(&prefix).as_u32 = ip4_prefix->as_u32;

    if (is_add)
    {
        mm->ip4_local_tbl->add (mm->ip4_local_tbl, ip4_prefix, ip4_prefix_len, map_domain_index);
        vec_add1(d->local_rules, prefix);
    }
    else
    {
        mm->ip4_local_tbl->delete (mm->ip4_local_tbl, ip4_prefix, ip4_prefix_len);
        index = vec_search_with_function(d->local_rules, &prefix, map_ce_local_rule_cmp);
        vec_del1(d->local_rules, index);
    }
    return 0;
}

static clib_error_t *
map_ce_security_check_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    bool enable = false;
    bool check_frag = false;
    bool saw_enable = false;
    bool saw_frag = false;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "enable"))
        {
            enable = true;
            saw_enable = true;
        }
        else if (unformat (line_input, "disable"))
        {
            enable = false;
            saw_enable = true;
        }
        else if (unformat (line_input, "fragments on"))
        {
            check_frag = true;
            saw_frag = true;
        }
        else if (unformat (line_input, "fragments off"))
        {
            check_frag = false;
            saw_frag = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!saw_enable)
    {
        error = clib_error_return (0,
                "Must specify enable 'enable' or 'disable'");
        goto done;
    }

    if (!saw_frag)
    {
        error = clib_error_return (0, "Must specify fragments 'on' or 'off'");
        goto done;
    }

    map_ce_param_set_security_check (enable, check_frag);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_security_check_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    bool enable = false;
    bool check_frag = false;
    bool saw_enable = false;
    bool saw_frag = false;
    bool is_clean = false;
    u32 map_domain_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat (line_input, "enable"))
        {
            enable = true;
            saw_enable = true;
        }
        else if (unformat (line_input, "disable"))
        {
            enable = false;
            saw_enable = true;
        }
        else if (unformat (line_input, "fragments on"))
        {
            check_frag = true;
            saw_frag = true;
        }
        else if (unformat (line_input, "fragments off"))
        {
            check_frag = false;
            saw_frag = true;
        }
        else if (unformat (line_input, "clean"))
        {
            is_clean = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    if (!is_clean)
    {
        if (!saw_enable)
        {
            error = clib_error_return (0,
                    "Must specify enable 'enable' or 'disable'");
            goto done;
        }

        if (!saw_frag)
        {
            error = clib_error_return (0, "Must specify fragments 'on' or 'off'");
            goto done;
        }
    }
    map_ce_domain_param_set_security_check (map_domain_index, is_clean, enable, check_frag);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_add_domain_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip4_address_t ip4_prefix;
    ip6_address_t ip6_prefix;
    ip6_address_t ip6_dst;
    ip6_address_t end_user_prefix;
    u32 ip6_prefix_len = 0, ip4_prefix_len = 0, ip6_dst_len = 128, end_user_prefix_len = 0;
    u32 map_domain_index;
    u32 num_m_args = 0;

    /* Optional arguments */
    u32 ea_bits_len = 0, psid_offset = 0, psid_length = 0;
    u32 mtu = 0;
    u8 *tag = 0;
    u8 flags = 0;
    clib_error_t *error = NULL;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "ip4-pfx %U/%d", unformat_ip4_address, &ip4_prefix, &ip4_prefix_len))
            num_m_args++;
        else if (unformat (line_input, "ip6-pfx %U/%d", unformat_ip6_address, &ip6_prefix, &ip6_prefix_len))
            num_m_args++;
        else if (unformat (line_input, "ip6-dst %U/%d", unformat_ip6_address, &ip6_dst, &ip6_dst_len))
            num_m_args++;
        else if (unformat (line_input, "ip6-dst %U", unformat_ip6_address, &ip6_dst)) num_m_args++;
        else if (unformat (line_input, "end-user-prefix %U/%d", unformat_ip6_address, &end_user_prefix, &end_user_prefix_len))
            num_m_args++;
        else if (unformat (line_input, "ea-bits-len %d", &ea_bits_len))
            num_m_args++;
        else if (unformat (line_input, "psid-offset %d", &psid_offset))
            num_m_args++;
        else if (unformat (line_input, "psid-len %d", &psid_length))
            num_m_args++;
        else if (unformat (line_input, "mtu %d", &mtu))
            num_m_args++;
        else if (unformat (line_input, "map-t"))
            flags |= MAP_CE_DOMAIN_TRANSLATION;
        else if (unformat (line_input, "tag %s", &tag))
            ;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (num_m_args < 3)
    {
        error = clib_error_return (0, "mandatory argument(s) missing");
        goto done;
    }

    map_ce_create_domain (&ip4_prefix, ip4_prefix_len,
                          &ip6_prefix, ip6_prefix_len,
                          &ip6_dst, ip6_dst_len,
                          &end_user_prefix, end_user_prefix_len,
                          ea_bits_len, psid_offset, psid_length, &map_domain_index,
                          mtu, flags, tag);

done:
    vec_free (tag);
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_del_domain_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 num_m_args = 0;
    u32 map_domain_index;
    clib_error_t *error = NULL;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index))
            num_m_args++;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (num_m_args != 1)
    {
        error = clib_error_return (0, "mandatory argument(s) missing");
        goto done;
    }

    map_ce_delete_domain (map_domain_index);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_add_rule_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip4_address_t ip4_prefix;
    bool is_add = true;
    u32 num_m_args = 0;
    u32 ip4_prefix_len = 0;
    u32 map_domain_index = ~0;
    clib_error_t *error = NULL;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index))
            num_m_args++;
        else if (unformat (line_input, "ip4-prefix %U/%d", unformat_ip4_address, &ip4_prefix, &ip4_prefix_len))
            num_m_args++;
        else if (unformat (line_input, "del"))
            is_add = false;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (num_m_args != 2)
    {
        error = clib_error_return (0, "mandatory argument(s) missing");
        goto done;
    }

    if (map_ce_add_del_local_prefix (map_domain_index, &ip4_prefix, ip4_prefix_len, is_add) != 0)
    {
        error = clib_error_return (0, "Failing to add CE local Mapping Rule");
        goto done;
    }

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_set_psid_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 num_m_args = 0;
    u32 psid = 0, map_domain_index = ~0;
    clib_error_t *error = NULL;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index))
            num_m_args++;
        else if (unformat (line_input, "psid %d", &psid))
            num_m_args++;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (num_m_args != 2)
    {
        error = clib_error_return (0, "mandatory argument(s) missing");
        goto done;
    }

    if (map_ce_domain_set_psid (map_domain_index, psid) != 0)
    {
        error = clib_error_return (0, "Failing to config domain manually psid");
        goto done;
    }

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_icmp_relay_source_address_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip4_address_t icmp_src_address;
    ip4_address_t *p_icmp_addr = 0;
    map_ce_main_t *mm = &map_ce_main;
    clib_error_t *error = NULL;

    mm->icmp4_src_address.as_u32 = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat
                (line_input, "%U", unformat_ip4_address, &icmp_src_address))
        {
            mm->icmp4_src_address = icmp_src_address;
            p_icmp_addr = &icmp_src_address;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    map_ce_param_set_icmp (p_icmp_addr);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_icmp_relay_source_address_command_fn (vlib_main_t * vm,
					  unformat_input_t * input,
					  vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    ip4_address_t icmp_src_address;
    ip4_address_t *p_icmp_addr = 0;
    map_ce_main_t *mm = &map_ce_main;
    clib_error_t *error = NULL;
    bool is_clean = false;
    u32 map_domain_index = ~0;

    icmp_src_address.as_u32 = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat
                (line_input, "%U", unformat_ip4_address, &icmp_src_address))
        {
            mm->icmp4_src_address = icmp_src_address;
            p_icmp_addr = &icmp_src_address;
        }
        else if (unformat (line_input, "clean"))
        {
            is_clean = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    map_ce_domain_param_set_icmp (map_domain_index, is_clean, p_icmp_addr);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_icmp_unreachables_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    int num_m_args = 0;
    clib_error_t *error = NULL;
    bool enabled = false;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        num_m_args++;
        if (unformat (line_input, "on"))
            enabled = true;
        else if (unformat (line_input, "off"))
            enabled = false;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }


    if (num_m_args != 1)
        error = clib_error_return (0, "mandatory argument(s) missing");


    map_ce_param_set_icmp6 (enabled);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_icmp_unreachables_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    int num_m_args = 0;
    clib_error_t *error = NULL;
    bool enabled = false;
    bool is_clean = false;
    u32 map_domain_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        num_m_args++;
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat (line_input, "on"))
            enabled = true;
        else if (unformat (line_input, "off"))
            enabled = false;
        else if (unformat (line_input, "clean"))
            is_clean = true;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    map_ce_domain_param_set_icmp6 (map_domain_index, is_clean, enabled);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_fragment_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    bool frag_inner = false;
    bool frag_ignore_df = false;
    bool saw_in_out = false;
    bool saw_df = false;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "inner"))
        {
            frag_inner = true;
            saw_in_out = true;
        }
        else if (unformat (line_input, "outer"))
        {
            frag_inner = false;
            saw_in_out = true;
        }
        else if (unformat (line_input, "ignore-df"))
        {
            frag_ignore_df = true;
            saw_df = true;
        }
        else if (unformat (line_input, "honor-df"))
        {
            frag_ignore_df = false;
            saw_df = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (!saw_in_out)
    {
        error = clib_error_return (0, "Must specify 'inner' or 'outer'");
        goto done;
    }

    if (!saw_df)
    {
        error = clib_error_return (0, "Must specify 'ignore-df' or 'honor-df'");
        goto done;
    }

    map_ce_param_set_fragmentation (frag_inner, frag_ignore_df);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_fragment_command_fn (vlib_main_t * vm,
			 unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    bool frag_inner = false;
    bool frag_ignore_df = false;
    bool saw_in_out = false;
    bool saw_df = false;
    u32 map_domain_index = ~0;
    bool is_clean; 

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat (line_input, "inner"))
        {
            frag_inner = true;
            saw_in_out = true;
        }
        else if (unformat (line_input, "outer"))
        {
            frag_inner = false;
            saw_in_out = true;
        }
        else if (unformat (line_input, "ignore-df"))
        {
            frag_ignore_df = true;
            saw_df = true;
        }
        else if (unformat (line_input, "honor-df"))
        {
            frag_ignore_df = false;
            saw_df = true;
        }
        else if (unformat (line_input, "clean"))
        {
            is_clean = true;
        }
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }
    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    if (!is_clean)
    {
        if (!saw_in_out)
        {
            error = clib_error_return (0, "Must specify 'inner' or 'outer'");
            goto done;
        }

        if (!saw_df)
        {
            error = clib_error_return (0, "Must specify 'ignore-df' or 'honor-df'");
            goto done;
        }
    }

    map_ce_domain_param_set_fragmentation (map_domain_index, is_clean, frag_inner, frag_ignore_df);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_traffic_class_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 tc = 0;
    clib_error_t *error = NULL;
    bool tc_copy = false;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "copy"))
            tc_copy = true;
        else if (unformat (line_input, "%x", &tc))
            tc = tc & 0xff;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    map_ce_param_set_traffic_class (tc_copy, tc);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_traffic_class_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 tc = 0;
    clib_error_t *error = NULL;
    bool tc_copy = false;
    bool is_clean = false;
    u32 map_domain_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat (line_input, "copy"))
            tc_copy = true;
        else if (unformat (line_input, "%x", &tc))
            tc = tc & 0xff;
        else if (unformat (line_input, "clean"))
            is_clean = true;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    map_ce_domain_param_set_traffic_class (map_domain_index, is_clean, tc_copy, tc);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_tos_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 tos = 0;
    clib_error_t *error = NULL;
    bool tos_copy = false;


    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "copy"))
            tos_copy = true;
        else if (unformat (line_input, "%x", &tos))
            tos = tos & 0xff;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    map_ce_param_set_tos (tos_copy, tos);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_tos_command_fn (vlib_main_t * vm,
			      unformat_input_t * input,
			      vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    u32 tos = 0;
    clib_error_t *error = NULL;
    bool tos_copy = false;
    bool is_clean = false;
    u32 map_domain_index = ~0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index));
        else if (unformat (line_input, "copy"))
            tos_copy = true;
        else if (unformat (line_input, "%x", &tos))
            tos = tos & 0xff;
        else if (unformat (line_input, "clean"))
            is_clean = true;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    map_ce_domain_param_set_tos (map_domain_index, is_clean, tos_copy, tos);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
show_map_ce_domain_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;
    bool counters = false;
    u32 map_domain_index = ~0;
    clib_error_t *error = NULL;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
    {
        /* *INDENT-OFF* */
        pool_foreach (d, mm->domains)
        {vlib_cli_output(vm, "%U", format_map_ce_domain, d, counters);}
        /* *INDENT-ON* */
        return 0;
    }

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "counters"))
            counters = true;
        else if (unformat (line_input, "index %d", &map_domain_index))
            ;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (pool_elts (mm->domains) == 0)
    {
        vlib_cli_output (vm, "No MAP CE domains are configured...");
        goto done;
    }

    if (map_domain_index == ~0)
    {
        /* *INDENT-OFF* */
        pool_foreach (d, mm->domains)
        {vlib_cli_output(vm, "%U", format_map_ce_domain, d, counters);}
        /* *INDENT-ON* */
    }
    else
    {
        if (pool_is_free_index (mm->domains, map_domain_index))
        {
            error = clib_error_return (0, "MAP CE domain does not exists %d",
                    map_domain_index);
            goto done;
        }

        d = pool_elt_at_index (mm->domains, map_domain_index);
        vlib_cli_output (vm, "%U", format_map_ce_domain, d, counters);
    }

done:
    unformat_free (line_input);

    return error;
}

u64
map_ce_error_counter_get (u32 node_index, map_ce_error_t map_error)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, node_index);
  vlib_error_main_t *em = &vm->error_main;
  vlib_error_t e = error_node->errors[map_error];
  vlib_node_t *n = vlib_get_node (vm, node_index);
  u32 ci;

  ci = vlib_error_get_code (&vm->node_main, e);
  ASSERT (ci < n->n_errors);
  ci += n->error_heap_index;

  return (em->counters[ci]);
}

static clib_error_t *
show_map_ce_stats_command_fn (vlib_main_t * vm, unformat_input_t * input,
			   vlib_cli_command_t * cmd)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;
    int domains = 0, domaincount = 0;
    if (pool_elts (mm->domains) == 0)
    {
        vlib_cli_output (vm, "No MAP CE domains are configured...");
        return 0;
    }

    /* *INDENT-OFF* */
    pool_foreach (d, mm->domains)  {
        domains += sizeof(*d);
        domaincount++;
  }

    /* *INDENT-ON* */

    vlib_cli_output (vm, "MAP CE domains structure: %d\n", sizeof (map_ce_domain_t));
    vlib_cli_output (vm, "MAP CE domains: %d (%d bytes)\n", domaincount, domains);
    vlib_cli_output (vm, "Total: %d bytes)\n", domains);

    if (mm->tc_copy)
        vlib_cli_output (vm, "MAP CE IPV6 traffic-class: copy");
    else
        vlib_cli_output (vm, "MAP CE IPV6 traffic-class: %x", mm->tc);

    if (mm->tos_copy)
        vlib_cli_output (vm, "MAP CE IPV4 Tos: copy");
    else
        vlib_cli_output (vm, "MAP CE IPV4 Tos: %x", mm->tos);

    if (mm->tcp_mss)
        vlib_cli_output (vm, "MAP CE TCP MSS clamping: %u", mm->tcp_mss);

    vlib_cli_output (vm, "MAP CE IPv6 inbound security check: %s, fragmented packet security check: %s",
            mm->sec_check ? "enabled" : "disabled",
            mm->sec_check_frag ? "enabled" : "disabled");

    vlib_cli_output (vm, "ICMP-relay IPv4 source address: %U\n",
            format_ip4_address, &mm->icmp4_src_address);
    vlib_cli_output (vm, "ICMP6 unreachables sent for unmatched packets: %s\n",
            mm->icmp6_enabled ? "enabled" : "disabled");
    vlib_cli_output (vm, "Inner fragmentation: %s\n",
            mm->frag_inner ? "enabled" : "disabled");
    vlib_cli_output (vm, "Fragment packets regardless of DF flag: %s\n",
            mm->frag_ignore_df ? "enabled" : "disabled");

    /*
     * Counters
     */
    vlib_combined_counter_main_t *cm = mm->domain_counters;
    u64 total_pkts[MAP_CE_N_DOMAIN_COUNTER];
    u64 total_bytes[MAP_CE_N_DOMAIN_COUNTER];
    int which, i;
    vlib_counter_t v;

    clib_memset (total_pkts, 0, sizeof (total_pkts));
    clib_memset (total_bytes, 0, sizeof (total_bytes));

    map_ce_domain_counter_lock (mm);
    vec_foreach (cm, mm->domain_counters)
    {
        which = cm - mm->domain_counters;

        for (i = 0; i < vlib_combined_counter_n_counters (cm); i++)
        {
            vlib_get_combined_counter (cm, i, &v);
            total_pkts[which] += v.packets;
            total_bytes[which] += v.bytes;
        }
    }
    map_ce_domain_counter_unlock (mm);

    vlib_cli_output (vm, "Encapsulated packets: %lld bytes: %lld\n",
            total_pkts[MAP_CE_DOMAIN_COUNTER_TX],
            total_bytes[MAP_CE_DOMAIN_COUNTER_TX]);
    vlib_cli_output (vm, "Decapsulated packets: %lld bytes: %lld\n",
            total_pkts[MAP_CE_DOMAIN_COUNTER_RX],
            total_bytes[MAP_CE_DOMAIN_COUNTER_RX]);

    vlib_cli_output (vm, "ICMP relayed packets: %d\n",
            vlib_get_simple_counter (&mm->icmp_relayed, 0));

  return 0;
}

static clib_error_t *
map_ce_if_command_fn (vlib_main_t * vm,
		   unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    vnet_main_t *vnm = vnet_get_main ();
    u32 sw_if_index = ~0;
    bool is_enable = true;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index)) 
            ;
        else if (unformat (line_input, "del"))
            is_enable = false;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

done:
    unformat_free (line_input);

    if (sw_if_index == ~0)
    {
        error = clib_error_return (0, "unknown interface");
        return error;
    }

    int rv = map_ce_if_enable_disable (is_enable, sw_if_index);
    if (rv)
    {
        error = clib_error_return (0, "failure enabling MAP CE on interface");
    }

    return error;
}

static clib_error_t *
map_ce_tcp_mss_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    u32 tcp_mss = 0;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "%u", &tcp_mss))
            ;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (tcp_mss >= (0x1 << 16))
    {
        error = clib_error_return (0, "invalid value `%u'", tcp_mss);
        goto done;
    }

    map_ce_param_set_tcp (tcp_mss);

done:
    unformat_free (line_input);

    return error;
}

static clib_error_t *
map_ce_domain_tcp_mss_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
    unformat_input_t _line_input, *line_input = &_line_input;
    clib_error_t *error = NULL;
    u32 tcp_mss = 0;
    u32 map_domain_index = ~0;
    bool is_clean = false;

    /* Get a line of input. */
    if (!unformat_user (input, unformat_line_input, line_input))
        return 0;

    while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (line_input, "index %d", &map_domain_index))
            ;
        else if (unformat (line_input, "%u", &tcp_mss))
            ;
        else if (unformat (line_input, "clean"))
            is_clean = true;
        else
        {
            error = clib_error_return (0, "unknown input `%U'",
                    format_unformat_error, line_input);
            goto done;
        }
    }

    if (map_domain_index == ~0)
    {
        error = clib_error_return (0,
                "Must specify map-ce domain index");
        goto done;
    }

    if (tcp_mss >= (0x1 << 16))
    {
        error = clib_error_return (0, "invalid value `%u'", tcp_mss);
        goto done;
    }

    map_ce_domain_param_set_tcp (map_domain_index, is_clean, tcp_mss);

done:
    unformat_free (line_input);

    return error;
}

/* *INDENT-OFF* */

/*?
 * Set or copy the IP Traffic Class field
 *
 * @cliexpar
 * @cliexstart{map-ce params traffic-class}
 *
 * This command is used to set the traffic-class field in translated
 * or encapsulated packets. If copy is specifed (the default) then the
 * traffic-class field is copied from the original packet to the
 * translated / encapsulating header.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_traffic_class_command, static) = {
  .path = "map-ce params traffic-class",
  .short_help = "map-ce params traffic-class {0x0-0xff | copy}",
  .function = map_ce_traffic_class_command_fn,
};

/*?
 * Set or copy the IP Traffic Class field per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params traffic-class}
 *
 * This command is used to set the traffic-class field in translated
 * or encapsulated packets. If copy is specifed (the default) then the
 * traffic-class field is copied from the original packet to the
 * translated / encapsulating header.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_domain_traffic_class_command, static) = {
  .path = "map-ce domain params traffic-class",
  .short_help = "map-ce domain params traffic-class index <domain> {0x0-0xff | copy} [clean]",
  .function = map_ce_domain_traffic_class_command_fn,
};

/*?
 * Set or copy the IP TOS field
 *
 * @cliexpar
 * @cliexstart{map-ce params tos}
 *
 * This command is used to set the tos field in translated
 * or encapsulated packets. If copy is specifed (the default) then the
 * TOS field is copied from the original packet to the
 * translated / encapsulating header.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_tos_command, static) = {
  .path = "map-ce params tos",
  .short_help = "map-ce params tos {0x0-0xff | copy}",
  .function = map_ce_tos_command_fn,
};

/*?
 * Set or copy the IP TOS field per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params tos}
 *
 * This command is used to set the tos field in translated
 * or encapsulated packets. If copy is specifed (the default) then the
 * TOS field is copied from the original packet to the
 * translated / encapsulating header.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_domain_tos_command, static) = {
  .path = "map-ce domain params tos",
  .short_help = "map-ce domain params tos index <domain> {0x0-0xff | copy} [clean]",
  .function = map_ce_domain_tos_command_fn,
};

/*?
 * TCP MSS clamping
 *
 * @cliexpar
 * @cliexstart{map-ce params tcp-mss}
 *
 * This command is used to set the TCP MSS in translated
 * or encapsulated packets.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_tcp_mss_command, static) = {
  .path = "map-ce params tcp-mss",
  .short_help = "map-ce params tcp-mss <value>",
  .function = map_ce_tcp_mss_command_fn,
};

/*?
 * TCP MSS clamping per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params tcp-mss}
 *
 * This command is used to set the TCP MSS in translated
 * or encapsulated packets.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_domain_tcp_mss_command, static) = {
  .path = "map-ce domain params tcp-mss",
  .short_help = "map-ce domain params tcp-mss index <domain> <value> [clean]",
  .function = map_ce_domain_tcp_mss_command_fn,
};

/*?
 * Enable or disable the MAP-E inbound security check
 * Specify if the inbound security check should be done on fragments
 *
 * @cliexpar
 * @cliexstart{map-ce params security-check}
 *
 * By default, a decapsulated packet's IPv4 source address will be
 * verified against the outer header's IPv6 source address. Disabling
 * this feature will allow IPv4 source address spoofing.
 *
 * Typically the inbound on-decapsulation security check is only done
 * on the first packet. The packet that contains the L4
 * information. While a security check on every fragment is possible,
 * it has a cost. State must be created on the first fragment.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_security_check_command, static) = {
  .path = "map-ce params security-check",
  .short_help = "map-ce params security-check enable|disable fragments on|off",
  .function = map_ce_security_check_command_fn,
};

/*?
 * Enable or disable the MAP-E inbound security check per domain
 * Specify if the inbound security check should be done on fragments
 *
 * @cliexpar
 * @cliexstart{map-ce domain params security-check}
 *
 * By default, a decapsulated packet's IPv4 source address will be
 * verified against the outer header's IPv6 source address. Disabling
 * this feature will allow IPv4 source address spoofing.
 *
 * Typically the inbound on-decapsulation security check is only done
 * on the first packet. The packet that contains the L4
 * information. While a security check on every fragment is possible,
 * it has a cost. State must be created on the first fragment.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_domain_security_check_command, static) = {
  .path = "map-ce domain params security-check",
  .short_help = "map-ce domain params security-check index <domain> enable|disable fragments on|off [clean]",
  .function = map_ce_domain_security_check_command_fn,
};

/*?
 * Specify the IPv4 source address used for relayed ICMP error messages
 *
 * @cliexpar
 * @cliexstart{map-ce params icmp source-address}
 *
 * This command specifies which IPv4 source address (must be local to
 * the system), that is used for relayed received IPv6 ICMP error
 * messages.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_icmp_relay_source_address_command, static) = {
  .path = "map-ce params icmp source-address",
  .short_help = "map-ce params icmp source-address <ip4-address>",
  .function = map_ce_icmp_relay_source_address_command_fn,
};

/*?
 * Specify the IPv4 source address used for relayed ICMP error messages per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params icmp source-address}
 *
 * This command specifies which IPv4 source address (must be local to
 * the system), that is used for relayed received IPv6 ICMP error
 * messages.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_domain_icmp_relay_source_address_command, static) = {
  .path = "map-ce domain params icmp source-address",
  .short_help = "map-ce domain params icmp source-address index <domain> <ip4-address> [clean]",
  .function = map_ce_domain_icmp_relay_source_address_command_fn,
};

/*?
 * Send IPv6 ICMP unreachables
 *
 * @cliexpar
 * @cliexstart{map-ce params icmp6 unreachables}
 *
 * Send IPv6 ICMP unreachable messages back if security check fails or
 * no MAP domain exists.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_icmp_unreachables_command, static) = {
  .path = "map-ce params icmp6 unreachables",
  .short_help = "map-ce params icmp6 unreachables {on|off}",
  .function = map_ce_icmp_unreachables_command_fn,
};

/*?
 * Send IPv6 ICMP unreachables per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params icmp6 unreachables}
 *
 * Send IPv6 ICMP unreachable messages back if security check fails or
 * no MAP domain exists.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_domain_icmp_unreachables_command, static) = {
  .path = "map-ce domain params icmp6 unreachables",
  .short_help = "map-ce domain params icmp6 unreachables index <domain> {on|off} [clean]",
  .function = map_ce_domain_icmp_unreachables_command_fn,
};

/*?
 * Configure MAP fragmentation behaviour
 *
 * @cliexpar
 * @cliexstart{map-ce params fragment}
 *
 * Allows fragmentation of the IPv4 packet even if the DF bit is
 * set. The choice between inner or outer fragmentation of tunnel
 * packets is complicated. The benefit of inner fragmentation is that
 * the ultimate endpoint must reassemble, instead of the tunnel
 * endpoint.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_fragment_command, static) = {
  .path = "map-ce params fragment",
  .short_help = "map-ce params fragment inner|outer ignore-df|honor-df",
  .function = map_ce_fragment_command_fn,
};

/*?
 * Configure MAP fragmentation behaviour per domain
 *
 * @cliexpar
 * @cliexstart{map-ce domain params fragment}
 *
 * Allows fragmentation of the IPv4 packet even if the DF bit is
 * set. The choice between inner or outer fragmentation of tunnel
 * packets is complicated. The benefit of inner fragmentation is that
 * the ultimate endpoint must reassemble, instead of the tunnel
 * endpoint.
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_domain_fragment_command, static) = {
  .path = "map-ce domain params fragment",
  .short_help = "map-ce domain params fragment index <domain> inner|outer ignore-df|honor-df [clean]",
  .function = map_ce_domain_fragment_command_fn,
};

/*?
 * Add MAP CE rule to a domain
 *
 * @cliexpar
 * @cliexstart{map-ce add rule}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_add_rule_command, static) = {
  .path = "map-ce add rule",
  .short_help = "map-ce add rule index <domain> ip4-prefix <ip4-prefix> [del]",
  .function = map_ce_add_rule_command_fn,
};

/*?
 * Add MAP CE domain
 *
 * @cliexpar
 * @cliexstart{map add domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_add_domain_command, static) = {
  .path = "map-ce add domain",
  .short_help = "map-ce add domain [tag <tag>] ip4-pfx <ip4-pfx> "
      "ip6-pfx <ip6-pfx> "
      "ip6-dst <ip6-pfx> "
      "end-user-prefix <end-user-prefix> "
      "ea-bits-len <n> psid-offset <n> psid-len <n> "
      "[mtu <mtu>] [map-t]",
  .function = map_ce_add_domain_command_fn,
};

/*?
 * set MAP CE manually psid
 *
 * @cliexpar
 * @cliexstart{map-ce set psid}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_set_psid_command, static) = {
  .path = "map-ce set psid",
  .short_help = "map-ce set psid index <domain> psid <psid>",
  .function = map_ce_set_psid_command_fn,
};

/*?
 * Delete MAP domain
 *
 * @cliexpar
 * @cliexstart{map del domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(map_ce_del_command, static) = {
  .path = "map-ce del domain",
  .short_help = "map-ce del domain index <domain>",
  .function = map_ce_del_domain_command_fn,
};

/*?
 * Show MAP CE domains
 *
 * @cliexpar
 * @cliexstart{show map-ce domain}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(show_map_ce_domain_command, static) = {
  .path = "show map-ce domain",
  .short_help = "show map-ce domain index <n> [counters]",
  .function = show_map_ce_domain_command_fn,
};

/*?
 * Show MAP CE statistics
 *
 * @cliexpar
 * @cliexstart{show map-ce stats}
 * @cliexend
 ?*/
VLIB_CLI_COMMAND(show_map_ce_stats_command, static) = {
  .path = "show map-ce stats",
  .short_help = "show map-ce stats",
  .function = show_map_ce_stats_command_fn,
};

/*?
 * Enable MAP processing on interface (input feature)
 *
 ?*/
VLIB_CLI_COMMAND(map_ce_if_command, static) = {
  .path = "map-ce interface",
  .short_help = "map-ce interface <interface-name> [del]",
  .function = map_ce_if_command_fn,
};

VLIB_PLUGIN_REGISTER() = {
  .version = VPP_BUILD_VER,
  .description = "Mapping of Address and Port (MAP) By Customer Edge",
};

/* *INDENT-ON* */

/*
 * map_ce_init
 */
clib_error_t *
map_ce_init (vlib_main_t * vm)
{
    map_ce_main_t *mm = &map_ce_main;
    clib_error_t *error = 0;

    memset (mm, 0, sizeof (*mm));

    mm->vnet_main = vnet_get_main ();
    mm->vlib_main = vm;

    /* traffic class */
    mm->tc = 0;
    mm->tc_copy = true;

    /* tos class */
    mm->tos = 0;
    mm->tos_copy = true;

    /* Inbound security check */
    mm->sec_check = true;
    mm->sec_check_frag = false;

    /* ICMP6 Type 1, Code 5 for security check failure */
    mm->icmp6_enabled = false;

    /* Inner or outer fragmentation */
    mm->frag_inner = false;
    mm->frag_ignore_df = false;

    vec_validate (mm->domain_counters, MAP_CE_N_DOMAIN_COUNTER - 1);
    mm->domain_counters[MAP_CE_DOMAIN_COUNTER_RX].name = "/map-ce/rx";
    mm->domain_counters[MAP_CE_DOMAIN_COUNTER_TX].name = "/map-ce/tx";

    vlib_validate_simple_counter (&mm->icmp_relayed, 0);
    vlib_zero_simple_counter (&mm->icmp_relayed, 0);
    mm->icmp_relayed.stat_segment_name = "/map-ce/icmp-relayed";

    /* LPM lookup tables */
    mm->ip4_prefix_tbl = lpm_table_init (LPM_TYPE_KEY32);
    mm->ip6_prefix_tbl = lpm_table_init (LPM_TYPE_KEY128);
    mm->ip4_local_tbl = lpm_table_init (LPM_TYPE_KEY32);

    error = map_ce_plugin_api_hookup (vm);

    return error;
}

VLIB_INIT_FUNCTION (map_ce_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
