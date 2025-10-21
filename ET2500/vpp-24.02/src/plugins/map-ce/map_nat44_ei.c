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

#include <vnet/ip/ip_frag.h>
#include "map_ce.h"

void 
map_ce_nat44_domain_update_psid(u32 map_domain_index, u16 psid)
{
    map_ce_main_t *mm = &map_ce_main;
    map_nat44_ei_domain_t *mnat;

    if (map_domain_index >= vec_len(mm->nat_domains))
    {
        clib_warning ("MAP CE nat domain does not exist: %d", map_domain_index);
        return;
    }
    mnat = pool_elt_at_index (mm->nat_domains, map_domain_index);
    mnat->psid = psid;
}

static int
map_nat44_ei_free_static_address_and_port (map_nat44_ei_domain_t *mnat,
                                          ip4_address_t addr, u16 port, 
                                          map_ce_nat_protocol_t proto)
{
    map_nat44_ei_address_t *a = 0;
    int i;

    for (i = 0; i < vec_len (mnat->addresses); i++)
    {
        a = mnat->addresses + i;

        if (a->addr.as_u32 != addr.as_u32)
            continue;

        MAP_NAT_LOCK(a, self);

        a->busy_port_bitmap[proto] = clib_bitmap_set (a->busy_port_bitmap[proto], port, 0);
        if (port > 1024)
        {
            a->busy_ports[proto]--;
        }

        MAP_NAT_UNLOCK(a, self);
        return 0;
    }
    return 1;
}

static void
map_nat44_ei_static_mapping_del_sessions (map_nat44_ei_domain_t *mnat,
                                          map_nat44_ei_user_key_t *u_key, 
                                          ip4_address_t e_addr, u16 e_port)
{
    clib_bihash_kv_8_8_t kv, value;

    u64 user_index;
    u32 elt_index, head_index, ses_index;

    dlist_elt_t *head, *elt;
    map_nat44_ei_user_t *u;
    map_nat44_ei_session_t *s;

    kv.key = u_key->as_u64;

    if (!clib_bihash_search_8_8 (&mnat->users_hash, &kv, &value))
    {
        user_index = value.value;
        u = pool_elt_at_index (mnat->users, user_index);
        if (u->nstaticsessions)
        {
            head_index = u->sessions_per_user_list_head_index;
            head = pool_elt_at_index (mnat->list_pool, head_index);
            elt_index = head->next;
            elt = pool_elt_at_index (mnat->list_pool, elt_index);
            ses_index = elt->value;
            while (ses_index != ~0)
            {
                s = pool_elt_at_index (mnat->sessions, ses_index);

                elt = pool_elt_at_index (mnat->list_pool, elt->next);
                ses_index = elt->value;

                if ((s->out2in.addr.as_u32 != e_addr.as_u32) ||
                    (s->out2in.port != e_port))
                    continue;

                if ((s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING))
                    continue;

                map_nat44_ei_free_session_data (mnat, s);
                map_nat44_ei_delete_session (mnat, s);
                break;
            }
        }
    }
}

static void
map_nat44_ei_delete_matching_dynamic_sessions (map_nat44_ei_domain_t *mnat,
                                               const map_nat44_ei_static_mapping_t *m)
{
    clib_bihash_kv_8_8_t kv, value;
    map_nat44_ei_session_t *s;
    map_nat44_ei_user_key_t u_key;
    map_nat44_ei_user_t *u;
    dlist_elt_t *head, *elt;
    u32 elt_index, head_index;
    u32 ses_index;
    u64 user_index;

    u_key.addr = m->local_addr;
    kv.key = u_key.as_u64;
    if (!clib_bihash_search_8_8 (&mnat->users_hash, &kv, &value))
    {
        user_index = value.value;
        u = pool_elt_at_index (mnat->users, user_index);
        if (u->nsessions)
        {
            head_index = u->sessions_per_user_list_head_index;
            head = pool_elt_at_index (mnat->list_pool, head_index);
            elt_index = head->next;
            elt = pool_elt_at_index (mnat->list_pool, elt_index);
            ses_index = elt->value;
            while (ses_index != ~0)
            {
                s = pool_elt_at_index (mnat->sessions, ses_index);
                elt = pool_elt_at_index (mnat->list_pool, elt->next);
                ses_index = elt->value;

                if (s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING)
                    continue;

                map_nat44_ei_free_session_data (mnat, s);
                map_nat44_ei_delete_session (mnat, s);
                break;
            }
        }
    }
}

int
map_nat44_ei_add_static_mapping (map_nat44_ei_domain_t *mnat,
                                 ip4_address_t l_addr,
                                 ip4_address_t e_addr, 
                                 u16 l_port, u16 e_port, 
                                 map_ce_nat_protocol_t proto,
                                 u32 flags)
{
    clib_bihash_kv_8_8_t kv, value;
    map_nat44_ei_static_mapping_t *m;

    init_map_nat_k (&kv, e_addr, e_port, proto);
    if (!clib_bihash_search_8_8 (&mnat->static_out2in, &kv, &value))
    {
        return VNET_API_ERROR_VALUE_EXIST;
    }

    init_map_nat_k (&kv, l_addr, l_port, proto);
    if (!clib_bihash_search_8_8 (&mnat->static_in2out, &kv, &value))
    {
        return VNET_API_ERROR_VALUE_EXIST;
    }

    if (map_nat44_ei_reserve_port (mnat, e_addr, e_port, proto))
	{
        return VNET_API_ERROR_NO_SUCH_ENTRY;
	}

    pool_get (mnat->static_mappings, m);
    clib_memset (m, 0, sizeof (*m));

    m->flags = flags;
    m->local_addr = l_addr;
    m->external_addr = e_addr;

    m->local_port = l_port;
    m->external_port = e_port;
    m->proto = proto;

    init_map_nat_kv (&kv, m->local_addr, m->local_port, m->proto, m - mnat->static_mappings);
    clib_bihash_add_del_8_8 (&mnat->static_in2out, &kv, 1);

    init_map_nat_kv (&kv, m->external_addr, m->external_port, m->proto, m - mnat->static_mappings);
    clib_bihash_add_del_8_8 (&mnat->static_out2in, &kv, 1);

    map_nat44_ei_delete_matching_dynamic_sessions (mnat, m);

    return 0;
}

int
map_nat44_ei_del_static_mapping (map_nat44_ei_domain_t *mnat,
                                 ip4_address_t l_addr, ip4_address_t e_addr, 
                                 u16 l_port, u16 e_port, 
                                 map_ce_nat_protocol_t proto, u32 flags)
{
    clib_bihash_kv_8_8_t kv, value;
    map_nat44_ei_static_mapping_t *m;
    map_nat44_ei_user_key_t u_key;

    init_map_nat_k (&kv, e_addr, e_port, proto);

    if (clib_bihash_search_8_8 (&mnat->static_out2in, &kv, &value))
    {
        return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

    m = pool_elt_at_index (mnat->static_mappings, value.value);

    if (map_nat44_ei_free_static_address_and_port (mnat, e_addr, e_port, proto))
    {
        return VNET_API_ERROR_INVALID_VALUE;
    }

    u_key.addr = m->local_addr;
    map_nat44_ei_static_mapping_del_sessions (mnat, &u_key, e_addr, e_port);

    init_map_nat_k (&kv, l_addr, l_port, proto);
    clib_bihash_add_del_8_8 (&mnat->static_in2out, &kv, 0);

    init_map_nat_k (&kv, e_addr, e_port, proto);
    clib_bihash_add_del_8_8 (&mnat->static_out2in, &kv, 0);

    pool_put (mnat->static_mappings, m);
    return 0;
}

static int
map_nat44_ei_del_dynamic_mapping (map_nat44_ei_domain_t *mnat, map_nat44_ei_session_t *ses)
{
    map_nat44_ei_free_session_data (mnat, ses);
    map_nat44_ei_delete_session (mnat, ses);
    return 0;
}

void 
map_ce_nat44_domain_create(u32 map_domain_index)
{
    map_ce_main_t *mm = &map_ce_main;
    map_ce_domain_t *d;
    map_nat44_ei_domain_t *mnat;
    map_nat44_ei_address_t *address;
    int i;
    u8 *name = NULL;

    if (map_domain_index == ~0)
    {
        clib_warning("map nat create error: map domain index(%u) is invalid!", map_domain_index);
        return;
    }

    if (pool_is_free_index (mm->domains, map_domain_index))
    {
        clib_warning("map nat create error: map domain index(%u) is invalid!", map_domain_index);
        return;
    }

    d = pool_elt_at_index(mm->domains, map_domain_index);
    vec_validate (mm->nat_domains, map_domain_index);
    mnat = vec_elt_at_index (mm->nat_domains, map_domain_index);
    clib_memset (mnat, 0, sizeof (*mnat));


    /* Init Hash */
    name = format(name, "%s-%u", "map_ce_nat44_static_in2out", map_domain_index);
    vec_validate_init_c_string (mnat->static_in2out_name, name, strlen ((char *) name));
    clib_bihash_init_8_8 (&mnat->static_in2out, (char *)mnat->static_in2out_name, 
                          MAP_NAT_STATIC_HASH_BUCKETS, MAP_NAT_STATIC_HASH_MEMORY_SIZE);
    vec_free(name);

    name = format(name, "%s-%u", "map_ce_nat44_static_out2in", map_domain_index);
    vec_validate_init_c_string (mnat->static_out2in_name, name, strlen ((char *) name));
    clib_bihash_init_8_8 (&mnat->static_out2in, (char *)mnat->static_out2in_name, 
                          MAP_NAT_STATIC_HASH_BUCKETS, MAP_NAT_STATIC_HASH_MEMORY_SIZE);
    vec_free(name);

    name = format(name, "%s-%u", "map_ce_nat44_in2out", map_domain_index);
    vec_validate_init_c_string (mnat->in2out_name, name, strlen ((char *) name));
    clib_bihash_init_8_8 (&mnat->in2out, (char *)mnat->in2out_name, 
                          MAP_NAT_HASH_BUCKETS, MAP_NAT_HASH_MEMORY_SIZE);
    vec_free(name);

    name = format(name, "%s-%u", "map_ce_nat44_out2in", map_domain_index);
    vec_validate_init_c_string (mnat->out2in_name, name, strlen ((char *) name));
    clib_bihash_init_8_8 (&mnat->out2in, (char *)mnat->out2in_name, 
                          MAP_NAT_HASH_BUCKETS, MAP_NAT_HASH_MEMORY_SIZE);
    vec_free(name);

    name = format(name, "%s-%u", "map_ce_nat44_users", map_domain_index);
    vec_validate_init_c_string (mnat->users_hash_name, name, strlen ((char *) name));
    clib_bihash_init_8_8 (&mnat->users_hash, (char *)mnat->users_hash_name, 
                          MAP_NAT_HASH_BUCKETS, MAP_NAT_HASH_MEMORY_SIZE); //Consistent with session size

    vec_free(name);

    clib_bihash_set_kvp_format_fn_8_8 (&mnat->static_in2out, format_map_nat44_ei_static_session_kvp);
    clib_bihash_set_kvp_format_fn_8_8 (&mnat->static_out2in, format_map_nat44_ei_static_session_kvp);
    clib_bihash_set_kvp_format_fn_8_8 (&mnat->in2out, format_map_nat44_ei_session_kvp);
    clib_bihash_set_kvp_format_fn_8_8 (&mnat->out2in, format_map_nat44_ei_session_kvp);
    clib_bihash_set_kvp_format_fn_8_8 (&mnat->users_hash, format_map_nat44_ei_user_kvp);

    /* Pool alloc */
    pool_alloc(mnat->static_mappings, MAP_NAT_STATIC_SESSION_MAX);
    pool_alloc(mnat->sessions, MAP_NAT_SESSION_MAX);
    pool_alloc(mnat->users, MAP_NAT_USER_INITIAL_NUM);

    mnat->max_translations = MAP_NAT_SESSION_MAX;
    mnat->max_translations_per_user = MAP_NAT_SESSION_MAX; //Consistent with session size
    mnat->max_users = MAP_NAT_SESSION_MAX; //Consistent with session size

    /* Init port alg */
    mnat->psid_offset = d->psid_offset;
    mnat->psid_length = d->psid_length;
    if (d->psid_valid)
    {
        mnat->psid = d->psid;
    }
    else
    {
        if(d->psid_length)
        {
            mnat->psid = clib_host_to_net_u64(d->end_user_prefix.as_u64[0]) & ((1 << d->psid_length) - 1);
        }
    }

    /* Addresses init */
    if (d->suffix_shift)
    {
        vec_validate (mnat->addresses, ((1 << d->suffix_shift) - 2)); //exclude broadcast addresses
        vec_foreach_index(i, mnat->addresses)
        {
            address = vec_elt_at_index (mnat->addresses, i);

            address->addr.as_u32 = clib_net_to_host_u32(
                            (clib_host_to_net_u32(d->ip4_prefix.as_u32) | 
                            ((clib_host_to_net_u64(d->end_user_prefix.as_u64[0]) >> (d->ea_shift)) & d->suffix_mask)) +
                            i
                    );

            clib_memset(address->busy_ports, 0, sizeof(address->busy_ports));
            clib_memset(address->busy_port_bitmap, 0, sizeof(address->busy_port_bitmap));
            clib_spinlock_init (&address->lock_self);
        }
    }
    else
    {
        vec_validate (mnat->addresses, 1);
        address = &mnat->addresses[0];
        if (d->ip4_prefix_len == 32)
        {
            address->addr = d->ip4_prefix;
        }
        else
        {
            address->addr.as_u32 = clib_net_to_host_u32(
                            clib_host_to_net_u32(d->ip4_prefix.as_u32) | 
                            ((clib_host_to_net_u64(d->end_user_prefix.as_u64[0]) >> (d->ea_shift + d->psid_length)) & d->suffix_mask)
                    );

        }
        clib_memset(address->busy_ports, 0, sizeof(address->busy_ports));
        clib_memset(address->busy_port_bitmap, 0, sizeof(address->busy_port_bitmap));
        clib_spinlock_init (&address->lock_self);
    }

    map_ce_nat44_reset_timeouts(&mnat->timeouts);

    /* lock init */
    clib_spinlock_init (&mnat->lock_in2out_out2in);
    clib_spinlock_init (&mnat->lock_sessions);
    clib_spinlock_init (&mnat->lock_users);
    clib_spinlock_init (&mnat->lock_users_hash);
    clib_spinlock_init (&mnat->lock_list_pool);
}

void 
map_ce_nat44_domain_remove(u32 map_domain_index)
{
    int error = 0;
    map_ce_main_t *mm = &map_ce_main;
    map_nat44_ei_domain_t *mnat;

    map_nat44_ei_address_t *address;
    map_nat44_ei_static_mapping_t *m, *static_pool;
    map_nat44_ei_session_t *ses;

    if (map_domain_index == ~0)
        return;

    if (map_domain_index >= vec_len (mm->nat_domains))
        return;

    mnat = vec_elt_at_index (mm->nat_domains, map_domain_index);

    /* free static mapping */
    static_pool = pool_dup (mnat->static_mappings);
    pool_foreach (m, static_pool)
    {
        error = map_nat44_ei_del_static_mapping (mnat, m->local_addr, m->external_addr, 
                                                 m->local_port, m->external_port,
                                                 m->proto, m->flags);
        if (error)
        {
            clib_warning ("map-ce nat44 error occurred while removing static mapping");
        }

    }
    pool_free (static_pool);
    pool_free (mnat->static_mappings);

    /* free static hash*/
    clib_bihash_free_8_8 (&mnat->static_in2out);
    clib_bihash_free_8_8 (&mnat->static_out2in);
    vec_free (mnat->static_in2out_name);
    vec_free (mnat->static_out2in_name);

    /* free dynamic mapping */
    pool_foreach (ses, mnat->sessions)
    {
        error = map_nat44_ei_del_dynamic_mapping (mnat, ses);
        if (error)
        {
            clib_warning ("map-ce nat44 error occurred while removing dynamic adderess");
        }
    }
    pool_free (mnat->sessions);

    /* free dynamic hash*/
    clib_bihash_free_8_8 (&mnat->in2out);
    clib_bihash_free_8_8 (&mnat->out2in);
    vec_free (mnat->in2out_name);
    vec_free (mnat->out2in_name);

    /* free user */
    pool_free (mnat->list_pool);
    pool_free (mnat->users);
    clib_bihash_free_8_8 (&mnat->users_hash);
    vec_free (mnat->users_hash_name);

    /* free addresses */
    vec_foreach(address, mnat->addresses)
    {
        map_ce_nat_protocol_t proto;
        for (proto = 0; proto < MAP_CE_NAT_N_PROTOCOLS; ++proto)
        {
            clib_bitmap_free (address->busy_port_bitmap[proto]);
        }
        clib_spinlock_free (&address->lock_self);
    }
    vec_free(mnat->addresses);

    /* free lock */
    clib_spinlock_free (&mnat->lock_in2out_out2in);
    clib_spinlock_free (&mnat->lock_sessions);
    clib_spinlock_free (&mnat->lock_users);
    clib_spinlock_free (&mnat->lock_users_hash);
    clib_spinlock_free (&mnat->lock_list_pool);

    clib_memset(mnat, 0, sizeof(map_nat44_ei_domain_t));
}

