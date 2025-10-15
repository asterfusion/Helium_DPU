/*
 *------------------------------------------------------------------
 * map_api.c - vnet map api
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
 *------------------------------------------------------------------
 */

#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>
#include <vnet/fib/fib_table.h>
#include <vlibmemory/api.h>

#include <map-ce/map_ce.h>
#include <map-ce/map_ce.api_enum.h>
#include <map-ce/map_ce.api_types.h>

#define REPLY_MSG_ID_BASE mm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_map_ce_add_domain_t_handler (vl_api_map_ce_add_domain_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_add_domain_reply_t *rmp;
    int rv = 0;
    u32 index;
    u8 flags = 0;

    if (mp->is_map_t)
    {
        flags |= MAP_CE_DOMAIN_TRANSLATION;
    }

    mp->tag[ARRAY_LEN (mp->tag) - 1] = '\0';
    rv =
        map_ce_create_domain ((ip4_address_t *) & mp->ip4_prefix.address,
                mp->ip4_prefix.len,
                (ip6_address_t *) & mp->ip6_prefix.address,
                mp->ip6_prefix.len,
                (ip6_address_t *) & mp->ip6_dst.address,
                mp->ip6_dst.len, 
                (ip6_address_t *) & mp->end_user_ip6_prefix.address, 
                mp->end_user_ip6_prefix.len, 
                mp->ea_bits_len, mp->psid_offset, mp->psid_length, 
                &index, mp->mtu, flags, mp->tag);

    /* *INDENT-OFF* */
    REPLY_MACRO2_END(VL_API_MAP_CE_ADD_DOMAIN_REPLY,
            ({
             rmp->index = index;
             }));

    /* *INDENT-ON* */
}

static void
vl_api_map_ce_del_domain_t_handler (vl_api_map_ce_del_domain_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_del_domain_reply_t *rmp;
    int rv = 0;

    rv = map_ce_delete_domain (ntohl (mp->index));

    REPLY_MACRO (VL_API_MAP_CE_DEL_DOMAIN_REPLY);
}

static void
vl_api_map_ce_add_del_rule_t_handler (vl_api_map_ce_add_del_rule_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_add_del_rule_reply_t *rmp;
    int rv = 0;

    rv =
        map_ce_add_del_local_prefix (ntohl (mp->index), 
                (ip4_address_t *) & mp->ip4_prefix.address, 
                mp->ip4_prefix.len,
                mp->is_add);

    REPLY_MACRO (VL_API_MAP_CE_ADD_DEL_RULE_REPLY);
}

static void
send_ce_domain_details (u32 map_domain_index, vl_api_registration_t * rp,
        u32 context)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_details_t *rmp;
    map_ce_domain_t *d = pool_elt_at_index (mm->domains, map_domain_index);

    /* Make sure every field is initiated (or don't skip the clib_memset()) */
    map_ce_domain_extra_t *de = vec_elt_at_index (mm->domain_extras, map_domain_index);
    int tag_len = clib_min (ARRAY_LEN (rmp->tag), vec_len (de->tag) + 1);

    /* *INDENT-OFF* */
    REPLY_MACRO_DETAILS4(VL_API_MAP_CE_DOMAIN_DETAILS, rp, context,
            ({
             rmp->domain_index = htonl (map_domain_index);
             clib_memcpy (&rmp->ip6_prefix.address, &d->ip6_prefix,
                     sizeof (rmp->ip6_prefix.address));
             clib_memcpy (&rmp->ip4_prefix.address, &d->ip4_prefix,
                     sizeof (rmp->ip4_prefix.address));
             clib_memcpy (&rmp->ip6_dst.address, &d->ip6_dst,
                     sizeof (rmp->ip6_dst.address));
             rmp->ip6_prefix.len = d->ip6_prefix_len;
             rmp->ip4_prefix.len = d->ip4_prefix_len;
             rmp->ip6_dst.len = d->ip6_dst_len;
             rmp->ea_bits_len = d->ea_bits_len;
             rmp->psid_offset = d->psid_offset;
             rmp->psid_length = d->psid_length;
             rmp->flags = d->flags;
             rmp->mtu = htons (d->mtu);
             memcpy (rmp->tag, de->tag, tag_len - 1);
             rmp->tag[tag_len - 1] = '\0';
             }));
    /* *INDENT-ON* */
}

static void
vl_api_map_ce_domain_dump_t_handler (vl_api_map_ce_domain_dump_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    int i;
    vl_api_registration_t *reg;

    if (pool_elts (mm->domains) == 0)
        return;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    /* *INDENT-OFF* */
    pool_foreach_index (i, mm->domains)
    {
        send_ce_domain_details(i, reg, mp->context);
    }
    /* *INDENT-ON* */
}

static void
vl_api_map_ce_domains_get_t_handler (vl_api_map_ce_domains_get_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domains_get_reply_t *rmp;

    i32 rv = 0;

    /* *INDENT-OFF* */
    REPLY_AND_DETAILS_MACRO (VL_API_MAP_CE_DOMAINS_GET_REPLY, mm->domains,
            ({
             send_ce_domain_details (cursor, rp, mp->context);
             }));
    /* *INDENT-ON* */
}

static void
vl_api_map_ce_rule_dump_t_handler (vl_api_map_ce_rule_dump_t * mp)
{
    vl_api_registration_t *reg;
    u32 i;
    vl_api_map_ce_rule_details_t *rmp;
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    u32 map_domain_index = clib_net_to_host_u32(mp->domain_index);

    if (pool_is_free_index (mm->domains, map_domain_index))
        return;

    d = pool_elt_at_index (mm->domains, map_domain_index);
    if (!d)
        return;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    for (i = 0; i < vec_len(d->local_rules); i++)
    {
        rmp = vl_msg_api_alloc (sizeof (*rmp));
        clib_memset (rmp, 0, sizeof (*rmp));
        rmp->_vl_msg_id = ntohs (VL_API_MAP_CE_RULE_DETAILS + mm->msg_id_base);

        clib_memcpy (&rmp->ip4_local_prefix.address, 
                     &ip_prefix_v4(d->local_rules + i), 
                     sizeof (rmp->ip4_local_prefix.address));
        rmp->ip4_local_prefix.len = ip_prefix_len(d->local_rules + i);

        rmp->context = mp->context;
        vl_api_send_msg (reg, (u8 *) rmp);
    }
}

static void
vl_api_map_ce_summary_stats_t_handler (vl_api_map_ce_summary_stats_t * mp)
{
    vl_api_map_ce_summary_stats_reply_t *rmp;
    vlib_combined_counter_main_t *cm;
    vlib_counter_t v;
    int i, which;
    u64 total_pkts[VLIB_N_RX_TX];
    u64 total_bytes[VLIB_N_RX_TX];
    map_ce_main_t *mm = &map_ce_main;
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = htons (VL_API_MAP_CE_SUMMARY_STATS_REPLY + mm->msg_id_base);
    rmp->context = mp->context;
    rmp->retval = 0;

    if (pool_elts (mm->domains) == 0)
    {
        rmp->retval = -1;
        goto out;
    }

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

    /* Note: in network byte order! */
    rmp->total_pkts[MAP_CE_DOMAIN_COUNTER_RX] = clib_host_to_net_u64 (total_pkts[MAP_CE_DOMAIN_COUNTER_RX]);
    rmp->total_bytes[MAP_CE_DOMAIN_COUNTER_RX] = clib_host_to_net_u64 (total_bytes[MAP_CE_DOMAIN_COUNTER_RX]);
    rmp->total_pkts[MAP_CE_DOMAIN_COUNTER_TX] = clib_host_to_net_u64 (total_pkts[MAP_CE_DOMAIN_COUNTER_TX]);
    rmp->total_bytes[MAP_CE_DOMAIN_COUNTER_TX] = clib_host_to_net_u64 (total_bytes[MAP_CE_DOMAIN_COUNTER_TX]);
    rmp->total_bindings = clib_host_to_net_u64 (pool_elts (mm->domains));

    // Not yet implemented. Should be a simple counter.
    rmp->total_security_check[MAP_CE_DOMAIN_COUNTER_TX] = 0;
    rmp->total_security_check[MAP_CE_DOMAIN_COUNTER_RX] = 0;
    rmp->total_ip4_fragments = 0;	

out:
    vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_map_ce_domain_stats_t_handler (vl_api_map_ce_domain_stats_t * mp)
{
  vl_api_map_ce_domain_stats_reply_t *rmp;
  vlib_counter_t v;
  u64 rx_pkts = 0;
  u64 tx_pkts = 0;
  u64 rx_bytes = 0;
  u64 tx_bytes = 0;
  map_ce_main_t *mm = &map_ce_main;
  u32 map_domain_index = ~0;
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  rmp = vl_msg_api_alloc (sizeof (*rmp));
  rmp->_vl_msg_id = htons (VL_API_MAP_CE_DOMAIN_STATS_REPLY + mm->msg_id_base);
  rmp->context = mp->context;
  rmp->retval = 0;

  map_domain_index = ntohl(mp->domain_index);

  if (pool_is_free_index (mm->domains, map_domain_index))
    {
        rmp->rx_pkts = 0; rmp->tx_pkts = 0;
        rmp->rx_bytes = 0; rmp->tx_bytes = 0;
        goto out;
    }

  map_ce_domain_counter_lock (mm);

  vlib_get_combined_counter (&mm->domain_counters[MAP_CE_DOMAIN_COUNTER_RX], map_domain_index, &v);
  rx_pkts = v.packets; rx_bytes = v.bytes;
  vlib_get_combined_counter (&mm->domain_counters[MAP_CE_DOMAIN_COUNTER_TX], map_domain_index, &v);
  tx_pkts = v.packets; tx_bytes = v.bytes;

  map_ce_domain_counter_unlock (mm);

  /* Note: in network byte order! */
  rmp->rx_pkts = clib_host_to_net_u64 (rx_pkts);
  rmp->rx_bytes = clib_host_to_net_u64 (rx_bytes);
  rmp->tx_pkts = clib_host_to_net_u64 (tx_pkts);
  rmp->tx_bytes = clib_host_to_net_u64 (tx_bytes);

out:
  vl_api_send_msg (reg, (u8 *) rmp);
}

int
map_ce_param_set_fragmentation (bool inner, bool ignore_df)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->frag_inner = ! !inner;
    mm->frag_ignore_df = ! !ignore_df;

    return 0;
}

static void
vl_api_map_ce_param_set_fragmentation_t_handler(vl_api_map_ce_param_set_fragmentation_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_fragmentation_reply_t *rmp;
    int rv = 0;

    rv = map_ce_param_set_fragmentation (mp->inner, mp->ignore_df);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_FRAGMENTATION_REPLY);
}

int
map_ce_domain_param_set_fragmentation (u32 domain_index, bool is_clean, bool inner, bool ignore_df)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (is_clean)
    {
        d->frag_valid = 0;
    }
    else
    {
        d->frag_valid = 1;
        d->frag_inner = ! !inner;
        d->frag_ignore_df = ! !ignore_df;
    }
    return 0;
}

static void
vl_api_map_ce_domain_param_set_fragmentation_t_handler (vl_api_map_ce_domain_param_set_fragmentation_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_fragmentation_reply_t *rmp;
    int rv = 0;

    rv = map_ce_domain_param_set_fragmentation (ntohl(mp->domain_index), mp->is_clean, mp->inner, mp->ignore_df);

    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_FRAGMENTATION_REPLY);
}

int
map_ce_param_set_icmp (ip4_address_t * icmp_src_address)
{
    map_ce_main_t *mm = &map_ce_main;

    if (icmp_src_address == 0)
        return -1;

    mm->icmp4_src_address = *icmp_src_address;

    return 0;
}

static void
vl_api_map_ce_param_set_icmp_t_handler (vl_api_map_ce_param_set_icmp_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_icmp_reply_t *rmp;
    int rv;

    rv = map_ce_param_set_icmp ((ip4_address_t *) & mp->ip4_err_relay_src);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_ICMP_REPLY);
}

int
map_ce_domain_param_set_icmp (u32 domain_index, bool is_clean, ip4_address_t * icmp_src_address)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (icmp_src_address == 0)
        return -1;

    if (is_clean)
    {
        d->icmp4_src_address_valid = 0;
    }
    else 
    {
        d->icmp4_src_address_valid = 1;
        d->icmp4_src_address = *icmp_src_address;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_icmp_t_handler (vl_api_map_ce_domain_param_set_icmp_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_icmp_reply_t *rmp;
    int rv;

    rv = map_ce_domain_param_set_icmp (ntohl(mp->domain_index), mp->is_clean, (ip4_address_t *) & mp->ip4_err_relay_src);

    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_ICMP_REPLY);
}

int
map_ce_param_set_icmp6 (u8 enable_unreachable)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->icmp6_enabled = ! !enable_unreachable;

    return 0;
}

static void
vl_api_map_ce_param_set_icmp6_t_handler (vl_api_map_ce_param_set_icmp6_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_icmp6_reply_t *rmp;
    int rv;

    rv = map_ce_param_set_icmp6 (mp->enable_unreachable);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_ICMP6_REPLY);
}

int
map_ce_domain_param_set_icmp6 (u32 domain_index, bool is_clean, u8 enable_unreachable)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (!d)
    {
        d->icmp6_enabled_valid = 0;
    }
    else
    {
        d->icmp6_enabled_valid = 1;
        d->icmp6_enabled = ! !enable_unreachable;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_icmp6_t_handler (vl_api_map_ce_domain_param_set_icmp6_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_icmp6_reply_t *rmp;
    int rv;

    rv = map_ce_domain_param_set_icmp6 (ntohl(mp->domain_index), mp->is_clean, mp->enable_unreachable);

    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_ICMP6_REPLY);
}

int
map_ce_param_set_security_check (bool enable, bool fragments)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->sec_check = ! !enable;
    mm->sec_check_frag = ! !fragments;

    return 0;
}

static void
vl_api_map_ce_param_set_security_check_t_handler (vl_api_map_ce_param_set_security_check_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_security_check_reply_t *rmp;
    int rv;

    rv = map_ce_param_set_security_check (mp->enable, mp->fragments);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_SECURITY_CHECK_REPLY);
}

int
map_ce_domain_param_set_security_check (u32 domain_index, bool is_clean, bool enable, bool fragments)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }
    if (is_clean)
    {
        d->sec_check_valid = 0;
    }
    else
    {
        d->sec_check_valid = 1;
        d->sec_check = ! !enable;
        d->sec_check_frag = ! !fragments;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_security_check_t_handler (vl_api_map_ce_domain_param_set_security_check_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_security_check_reply_t *rmp;
    int rv;

    rv = map_ce_domain_param_set_security_check (ntohl(mp->domain_index), mp->is_clean, mp->enable, mp->fragments);

    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_SECURITY_CHECK_REPLY);
}

int
map_ce_param_set_traffic_class (bool copy, u8 tc)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->tc_copy = ! !copy;
    mm->tc = tc;

    return 0;
}

static void
vl_api_map_ce_param_set_traffic_class_t_handler (vl_api_map_ce_param_set_traffic_class_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_traffic_class_reply_t *rmp;
    int rv;

    rv = map_ce_param_set_traffic_class (mp->copy, mp->tc_class);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_TRAFFIC_CLASS_REPLY);
}

int
map_ce_domain_param_set_traffic_class (u32 domain_index, bool is_clean, bool copy, u8 tc)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (is_clean)
    {
        d->tc_valid = 0;
    }
    else 
    {
        d->tc_valid = 1;
        d->tc_copy = ! !copy;
        d->tc = tc;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_traffic_class_t_handler (vl_api_map_ce_domain_param_set_traffic_class_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_traffic_class_reply_t *rmp;
    int rv;

    rv = map_ce_domain_param_set_traffic_class (ntohl(mp->domain_index), mp->is_clean, mp->copy, mp->tc_class);

    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_TRAFFIC_CLASS_REPLY);
}

int
map_ce_param_set_tos (bool copy, u8 tos)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->tos_copy = ! !copy;
    mm->tos = tos;

    return 0;
}

static void
vl_api_map_ce_param_set_tos_t_handler (vl_api_map_ce_param_set_tos_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_tos_reply_t *rmp;
    int rv;

    rv = map_ce_param_set_tos (mp->copy, mp->tos);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_TOS_REPLY);
}

int
map_ce_domain_param_set_tos (u32 domain_index, bool is_clean, bool copy, u8 tos)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (is_clean)
    {
        d->tos_valid = 0;
    }
    else
    {
        d->tos_valid = 1;
        d->tos_copy = ! !copy;
        d->tos = tos;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_tos_t_handler (vl_api_map_ce_domain_param_set_tos_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_tos_reply_t *rmp;
    int rv;

    rv = map_ce_domain_param_set_tos (ntohl(mp->domain_index), mp->is_clean, mp->copy, mp->tos);

    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_TOS_REPLY);
}

int
map_ce_param_set_tcp (u16 tcp_mss)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->tcp_mss = tcp_mss;

    return 0;
}

static void
vl_api_map_ce_param_set_tcp_t_handler (vl_api_map_ce_param_set_tcp_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_set_tcp_reply_t *rmp;
    int rv = 0;

    map_ce_param_set_tcp (ntohs (mp->tcp_mss));
    REPLY_MACRO (VL_API_MAP_CE_PARAM_SET_TCP_REPLY);
}

int
map_ce_domain_param_set_tcp (u32 domain_index, bool is_clean, u16 tcp_mss)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;

    if (pool_is_free_index (mm->domains, domain_index))
    {
        clib_warning ("MAP rule: domain does not exist: %d", domain_index);
        return 0;
    }

    d = pool_elt_at_index (mm->domains, domain_index);
    if (!d)
    {
        return 0;
    }

    if (is_clean)
    {
        d->tcp_mss_valid = 0;
    }
    else
    {
        d->tcp_mss_valid = 1;
        d->tcp_mss = tcp_mss;
    }

    return 0;
}

static void
vl_api_map_ce_domain_param_set_tcp_t_handler (vl_api_map_ce_domain_param_set_tcp_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_param_set_tcp_reply_t *rmp;
    int rv = 0;

    map_ce_domain_param_set_tcp (ntohl(mp->domain_index), mp->is_clean, ntohs (mp->tcp_mss));
    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_TCP_REPLY);
}

static void
vl_api_map_ce_domain_set_psid_t_handler (vl_api_map_ce_domain_set_psid_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_domain_set_psid_reply_t *rmp;
    int rv = 0;

    map_ce_domain_set_psid (ntohl(mp->domain_index), ntohs (mp->psid));
    REPLY_MACRO (VL_API_MAP_CE_DOMAIN_SET_PSID_REPLY);
}

int
map_ce_domain_param_set_mtu (u32 domain_index, u16 mtu)
{
  map_ce_main_t *mm = &map_ce_main;
  map_ce_domain_t *d;

  if (pool_is_free_index (mm->domains, domain_index))
    {
      clib_warning ("MAP CE rule: domain does not exist: %d", domain_index);
      return 0;
    }

  d = pool_elt_at_index (mm->domains, domain_index);
  if (!d)
    {
      return 0;
    }

  d->mtu = mtu;

  return 0;
}

static void
vl_api_map_ce_domain_param_set_mtu_t_handler (vl_api_map_ce_domain_param_set_mtu_t * mp)
{
  map_ce_main_t *mm = &map_ce_main;
  vl_api_map_ce_domain_param_set_mtu_reply_t *rmp;
  int rv = 0;

  map_ce_domain_param_set_mtu (ntohl(mp->domain_index), ntohs (mp->mtu));
  REPLY_MACRO (VL_API_MAP_CE_DOMAIN_PARAM_SET_MTU_REPLY);
}

static void
vl_api_map_ce_param_get_t_handler (vl_api_map_ce_param_get_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_param_get_reply_t *rmp;
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    rmp = vl_msg_api_alloc (sizeof (*rmp));
    rmp->_vl_msg_id = htons (VL_API_MAP_CE_PARAM_GET_REPLY + mm->msg_id_base);
    rmp->context = mp->context;
    rmp->retval = 0;

    rmp->frag_inner = mm->frag_inner;
    rmp->frag_ignore_df = mm->frag_ignore_df;

    clib_memcpy (&rmp->icmp_ip4_err_relay_src,
            &mm->icmp4_src_address, sizeof (rmp->icmp_ip4_err_relay_src));

    rmp->icmp6_enable_unreachable = mm->icmp6_enabled;

    rmp->sec_check_enable = mm->sec_check;
    rmp->sec_check_fragments = mm->sec_check_frag;

    rmp->tc_copy = mm->tc_copy;
    rmp->tc_class = mm->tc;

    rmp->tos_copy = mm->tos_copy;
    rmp->tos = mm->tos;

    vl_api_send_msg (reg, (u8 *) rmp);
}

int
map_ce_if_enable_disable (bool is_enable, u32 sw_if_index)
{
    map_ce_main_t *mm = &map_ce_main;

    if (pool_is_free_index (mm->vnet_main->interface_main.sw_interfaces, sw_if_index))
        return VNET_API_ERROR_INVALID_SW_IF_INDEX;

    is_enable = ! !is_enable;

    ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, is_enable);
    ip6_full_reass_enable_disable_with_refcnt (sw_if_index, is_enable);
    vnet_feature_enable_disable ("ip4-unicast", "map-ce-ip4-classify", sw_if_index,
            is_enable ? 1 : 0, 0, 0);
    vnet_feature_enable_disable ("ip6-unicast", "map-ce-ip6-classify", sw_if_index,
            is_enable ? 1 : 0, 0, 0);
    return 0;
}

static void
vl_api_map_ce_if_enable_disable_t_handler (vl_api_map_ce_if_enable_disable_t * mp)
{
    map_ce_main_t *mm = &map_ce_main;
    vl_api_map_ce_if_enable_disable_reply_t *rmp;
    int rv = 0;

    VALIDATE_SW_IF_INDEX (mp);

    rv = map_ce_if_enable_disable (mp->is_enable, htonl (mp->sw_if_index));

    BAD_SW_IF_INDEX_LABEL;
    REPLY_MACRO (VL_API_MAP_CE_IF_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <vnet/format_fns.h>
#include <map-ce/map_ce.api.c>

/* Set up the API message handling tables */
clib_error_t *
map_ce_plugin_api_hookup (vlib_main_t * vm)
{
    map_ce_main_t *mm = &map_ce_main;

    mm->msg_id_base = setup_message_id_table ();

    return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
