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

enum map_ce_nat44_in2out_next_e
{
    MAP_CE_NAT44_EI_I2O_NEXT_MAP_E,
    MAP_CE_NAT44_EI_I2O_NEXT_MAP_T,
    MAP_CE_NAT44_EI_I2O_NEXT_DROP,
    MAP_CE_NAT44_IN2OUT_N_NEXT,
};

enum map_ce_nat44_out2in_next_e
{
    MAP_CE_NAT44_EI_O2I_NEXT_IP4_LOOKUP,
    MAP_CE_NAT44_EI_O2I_NEXT_NEXT_IP4_FRAGMENT,
    MAP_CE_NAT44_EI_O2I_NEXT_DROP,
    MAP_CE_NAT44_OUT2IN_N_NEXT,
};

static int
map_nat44_i2o_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg)
{
    map_nat44_ei_is_idle_session_ctx_t *ctx = arg;

    clib_bihash_kv_8_8_t s_kv;
    u64 sess_timeout_time;

    map_nat44_ei_domain_t *mnat;
    map_nat44_ei_session_t *s;
    mnat = (map_nat44_ei_domain_t *)ctx->mnat;

    s = pool_elt_at_index (mnat->sessions, kv->value);
    sess_timeout_time = s->last_heard + 
                       (f64) map_ce_nat_session_get_timeout (&mnat->timeouts, s->nat_proto);
    if (ctx->now >= sess_timeout_time)
    {
        init_map_nat_o2i_k (&s_kv, s);
        if (clib_bihash_add_del_8_8 (&mnat->out2in, &s_kv, 0))
        {
            clib_warning ("map nat out2in key del failed");
        }

        if (!(s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING))
        {
            map_nat44_ei_free_outside_address_and_port (mnat, 
                                                        &s->out2in.addr, s->out2in.port, 
                                                        s->nat_proto);
        }
        map_nat44_ei_delete_session (mnat, s);
        return 1;
    }
    return 0;
}

static int
map_nat44_o2i_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg)
{
    map_nat44_ei_is_idle_session_ctx_t *ctx = arg;

    clib_bihash_kv_8_8_t s_kv;
    u64 sess_timeout_time;

    map_nat44_ei_domain_t *mnat;
    map_nat44_ei_session_t *s;
    mnat = (map_nat44_ei_domain_t *)ctx->mnat;

    s = pool_elt_at_index (mnat->sessions, kv->value);
    sess_timeout_time = s->last_heard + 
                        (f64) map_ce_nat_session_get_timeout (&mnat->timeouts, s->nat_proto);

    if (ctx->now >= sess_timeout_time)
    {
        init_map_nat_i2o_k (&s_kv, s);
        if (clib_bihash_add_del_8_8 (&mnat->in2out, &s_kv, 0))
        {
            clib_warning ("map nat in2out key del failed");
        }

        if (!(s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING))
        {
            map_nat44_ei_free_outside_address_and_port (mnat, 
                                                        &s->out2in.addr, s->out2in.port,
                                                        s->nat_proto);
        }
        map_nat44_ei_delete_session (mnat, s);
        return 1;
    }
    return 0;
}



static_always_inline void
map_nat44_ei_session_update_lru (map_nat44_ei_domain_t *mnat, 
                                map_nat44_ei_session_t *s)
{
    /* don't update too often - timeout is in magnitude of seconds anyway */
    if (s->last_heard > s->last_lru_update + 1)
    {
        clib_dlist_remove (mnat->list_pool, s->per_user_index);
        clib_dlist_addtail (mnat->list_pool, s->per_user_list_head_index, s->per_user_index);
        s->last_lru_update = s->last_heard;
    }
}


static_always_inline int
map_nat44_ei_static_mapping_match (map_nat44_ei_domain_t *mnat,
                                   ip4_address_t match_addr, 
                                   u16 match_port,
                                   map_ce_nat_protocol_t match_protocol,
                                   ip4_address_t *mapping_addr, 
                                   u16 *mapping_port, 
                                   u8 by_external)
{
    clib_bihash_kv_8_8_t kv, value;
    map_nat44_ei_static_mapping_t *m;

    if (by_external)
    {
        init_map_nat_k (&kv, match_addr, match_port, match_protocol);
        if (clib_bihash_search_8_8 (&mnat->static_out2in, &kv, &value))
        {
            return 1;
        }
        m = pool_elt_at_index (mnat->static_mappings, value.value);

        *mapping_addr = m->local_addr;
        *mapping_port = m->local_port;
    }
    else
    {
        init_map_nat_k (&kv, match_addr, match_port, match_protocol);
        if (clib_bihash_search_8_8 (&mnat->static_in2out, &kv, &value))
        {
            return 1;
        }
        m = pool_elt_at_index (mnat->static_mappings, value.value);

        *mapping_addr = m->external_addr;
        *mapping_port = m->external_port;
    }
    return 0;
}


static_always_inline map_nat44_ei_user_t *
map_nat44_ei_user_get_or_create (map_nat44_ei_domain_t *mnat,
                                ip4_address_t *addr)
{
    map_nat44_ei_user_t *u = 0;
    map_nat44_ei_user_key_t user_key;
    clib_bihash_kv_8_8_t kv, value;

    dlist_elt_t *per_user_list_head_elt;

    user_key.addr.as_u32 = addr->as_u32;
    kv.key = user_key.as_u64;

    /* Ever heard of the "user" = src ip4 address before? */
    if (clib_bihash_search_8_8 (&mnat->users_hash, &kv, &value))
    {
        if (pool_elts (mnat->users) >= mnat->max_users)
        {
            return NULL;
        }

        /* no, make a new one */

        MAP_NAT_LOCK(mnat, users);

        pool_get (mnat->users, u);
        clib_memset (u, 0, sizeof (*u));
        clib_spinlock_init(&u->lock_self);

        MAP_NAT_UNLOCK(mnat, users);

        u->addr.as_u32 = addr->as_u32;

        MAP_NAT_LOCK(mnat, list_pool);

        pool_get (mnat->list_pool, per_user_list_head_elt);

        MAP_NAT_UNLOCK(mnat, list_pool);

        u->sessions_per_user_list_head_index = per_user_list_head_elt - mnat->list_pool;

        clib_dlist_init (mnat->list_pool, u->sessions_per_user_list_head_index);

        kv.value = u - mnat->users;

        /* add user */
        MAP_NAT_LOCK(mnat, users_hash);

        if (clib_bihash_add_del_8_8 (&mnat->users_hash, &kv, 1))
        {
            map_nat44_ei_delete_user_with_no_session (mnat, u, false);
            return NULL;
        }

        MAP_NAT_UNLOCK(mnat, users_hash);
    }
    else
    {
        u = pool_elt_at_index (mnat->users, value.value);
    }

  return u;
}


static_always_inline map_nat44_ei_session_t *
map_nat44_ei_session_alloc_or_recycle (map_nat44_ei_domain_t *mnat, 
                                       map_nat44_ei_user_t *u,
                                       f64 now)
{
    map_nat44_ei_session_t *s;
    u32 oldest_per_user_translation_list_index, session_index;
    dlist_elt_t *oldest_per_user_translation_list_elt;
    dlist_elt_t *per_user_translation_list_elt;

    /* Over quota? Recycle the least recently used translation */
    if ((u->nsessions + u->nstaticsessions) >= mnat->max_translations_per_user)
    {
        MAP_NAT_LOCK(u, self);

        oldest_per_user_translation_list_index = 
            clib_dlist_remove_head ( mnat->list_pool, u->sessions_per_user_list_head_index);

        ASSERT (oldest_per_user_translation_list_index != ~0);

        /* Add it back to the end of the LRU list */
        clib_dlist_addtail (mnat->list_pool, 
                            u->sessions_per_user_list_head_index,
                            oldest_per_user_translation_list_index);

        /* Get the list element */
        oldest_per_user_translation_list_elt = 
            pool_elt_at_index (mnat->list_pool, oldest_per_user_translation_list_index);

        /* Get the session index from the list element */
        session_index = oldest_per_user_translation_list_elt->value;

        /* Get the session */
        s = pool_elt_at_index (mnat->sessions, session_index);

        map_nat44_ei_free_session_data (mnat, s);
        if ((s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING))
            u->nstaticsessions--;
        else
            u->nsessions--;

        MAP_NAT_UNLOCK(u, self);

        s->flags = 0;
    }
    else
    {
        MAP_NAT_LOCK(mnat, sessions);

        pool_get (mnat->sessions, s);
        clib_memset (s, 0, sizeof (*s));
        clib_spinlock_init(&s->lock_self);

        MAP_NAT_UNLOCK(mnat, sessions);

        /* Create list elts */
        MAP_NAT_LOCK(mnat, list_pool);

        pool_get (mnat->list_pool, per_user_translation_list_elt);

        MAP_NAT_UNLOCK(mnat, list_pool);

        per_user_translation_list_elt->value = s - mnat->sessions;
        clib_dlist_init (mnat->list_pool, per_user_translation_list_elt - mnat->list_pool);

        MAP_NAT_LOCK(s, self);

        s->per_user_index = per_user_translation_list_elt - mnat->list_pool;
        s->per_user_list_head_index = u->sessions_per_user_list_head_index;

        clib_dlist_addtail (mnat->list_pool, 
                            s->per_user_list_head_index,
                            per_user_translation_list_elt - mnat->list_pool);

        s->user_index = u - mnat->users;

        MAP_NAT_UNLOCK(s, self);
    }
    return s;
}


static_always_inline u8
map_nat44_ei_session_alloc_for_static_mapping (map_nat44_ei_domain_t *mnat, 
                                              vlib_buffer_t *b, 
                                              ip4_address_t i2o_addr, 
                                              u16 i2o_port, 
                                              ip4_address_t o2i_addr, 
                                              u16 o2i_port, 
                                              map_ce_nat_protocol_t proto, 
                                              map_nat44_ei_session_t **sessionp,
                                              f64 now)
{
    map_nat44_ei_user_t *u = NULL;
    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv;
    ip4_header_t *ip;
    udp_header_t *udp;
    map_nat44_ei_is_idle_session_ctx_t ctx;

    if (PREDICT_FALSE (map_nat44_maximum_sessions_exceeded (mnat)))
    {
        return MAP_CE_ERROR_NAT_MAX_SESSIONS_EXCEEDED;
    }

    ip = vlib_buffer_get_current (b);
    udp = ip4_next_header (ip);

    u = map_nat44_ei_user_get_or_create (mnat, &i2o_addr);
    if (!u)
    {
        *sessionp = NULL;
        return MAP_CE_ERROR_NAT_CANNOT_CREATE_USER;
    }

    s = map_nat44_ei_session_alloc_or_recycle (mnat, u, now);
    if (!s)
    {
        map_nat44_ei_delete_user_with_no_session (mnat, u, true);
        return MAP_CE_ERROR_NAT_CANNOT_CREATE_SESSION;
    }

    map_nat44_ei_user_session_increment (mnat, u, 1 /* static */);

    s->flags |= MAP_NAT_SESSION_FLAG_STATIC_MAPPING;
    s->in2out.addr = i2o_addr;
    s->in2out.port = i2o_port;
    s->out2in.addr = o2i_addr;
    s->out2in.port = o2i_port;
    s->nat_proto = proto;

    /* Add to translation hashes */
    ctx.now = now;
    ctx.mnat = mnat;

    MAP_NAT_LOCK(mnat, in2out_out2in);
    init_map_nat_i2o_kv (&kv, s, s - mnat->sessions);
    if (clib_bihash_add_or_overwrite_stale_8_8 (
                &mnat->in2out, &kv, map_nat44_i2o_is_idle_session_cb, &ctx))
        clib_warning ("map nat44 ei in2out key add failed");

    init_map_nat_o2i_kv (&kv, s, s - mnat->sessions);
    if (clib_bihash_add_or_overwrite_stale_8_8 (
                &mnat->out2in, &kv, map_nat44_o2i_is_idle_session_cb, &ctx))
        clib_warning ("map nat44 ei out2in key add failed");
    MAP_NAT_UNLOCK(mnat, in2out_out2in);

    *sessionp = s;

    return MAP_CE_ERROR_NONE;
}


static_always_inline u8 
map_nat44_icmp_get_key (vlib_buffer_t *b, 
                        ip4_header_t *ip, 
                        ip4_address_t *addr,
                        u16 *port, 
                        map_ce_nat_protocol_t *nat_proto)
{
    void *l4_header;

    icmp46_header_t *icmp;
    map_ce_nat_icmp_echo_header_t *echo;

    ip4_header_t *inner_ip;
    icmp46_header_t *inner_icmp;
    map_ce_nat_icmp_echo_header_t *inner_echo;

    icmp = (icmp46_header_t *) ip4_next_header (ip);
    echo = (map_ce_nat_icmp_echo_header_t *) (icmp + 1);

    if (!map_ce_nat44_icmp_type_is_error_message(vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags))
    {
        *nat_proto = MAP_CE_NAT_PROTOCOL_ICMP;
        *addr = ip->src_address;
        *port = vnet_buffer (b)->ip.reass.l4_src_port;
    }
    else
    {
        inner_ip = (ip4_header_t *) (echo + 1);
        l4_header = ip4_next_header (inner_ip);
        *nat_proto = ip_proto_to_map_nat_proto (inner_ip->protocol);
        *addr = inner_ip->dst_address;
        switch (*nat_proto)
        {
        case MAP_CE_NAT_PROTOCOL_ICMP:
            inner_icmp = (icmp46_header_t *) l4_header;
            inner_echo = (map_ce_nat_icmp_echo_header_t *) (inner_icmp + 1);
            *port = inner_echo->identifier;
            break;
        case MAP_CE_NAT_PROTOCOL_UDP:
        case MAP_CE_NAT_PROTOCOL_TCP:
            *port = ((map_ce_nat_tcp_udp_header_t *) l4_header)->dst_port;
            break;
        default:
            return MAP_CE_ERROR_NAT_UNSUPPORTED_PROTOCOL;
        }
    }
    return MAP_CE_ERROR_NONE;            /* success */
}

static_always_inline u8
map_nat44_mapping (map_ce_domain_t *d,
                  map_nat44_ei_domain_t *mnat,
                  vlib_buffer_t *b, 
                  ip4_header_t *ip,
                  ip4_address_t i2o_addr, 
                  u16 i2o_port, 
                  map_ce_nat_protocol_t nat_proto, 
                  map_nat44_ei_session_t **sessionp,
                  f64 now)
{
    map_nat44_ei_user_t *u;
    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv;
    u8 is_sm = 0;
    map_nat44_ei_is_idle_session_ctx_t ctx;
    ip4_address_t sm_addr;
    u16 sm_port;

    if (PREDICT_FALSE (map_nat44_maximum_sessions_exceeded (mnat)))
    {
        return MAP_CE_ERROR_NAT_MAX_SESSIONS_EXCEEDED;
    }

    /* First try to match static mapping by local address and port */
    if (map_nat44_ei_static_mapping_match (mnat, i2o_addr, i2o_port, nat_proto, &sm_addr, &sm_port, 0))
    {
        /* Try to create dynamic translation */
        if (map_nat44_ei_alloc_map_addr_port (mnat, 
                                              nat_proto, 
                                              ip->src_address, 
                                              &sm_addr, &sm_port))
        {
            return MAP_CE_ERROR_NAT_OUT_OF_PORTS;
        }
    }
    else
    {
        is_sm = 1;
    }

    u = map_nat44_ei_user_get_or_create (mnat, &ip->src_address);
    if (!u)
    {
        return MAP_CE_ERROR_NAT_CANNOT_CREATE_USER;
    }

    s = map_nat44_ei_session_alloc_or_recycle (mnat, u, now);
    if (!s)
    {
        map_nat44_ei_delete_user_with_no_session (mnat, u, true);
        return MAP_CE_ERROR_NAT_CANNOT_CREATE_SESSION;
    }

    if (is_sm)
        s->flags |= MAP_NAT_SESSION_FLAG_STATIC_MAPPING;

    map_nat44_ei_user_session_increment (mnat, u, is_sm);

    s->in2out.addr = i2o_addr;
    s->in2out.port = i2o_port;
    s->out2in.addr = sm_addr;
    s->out2in.port = sm_port;
    s->nat_proto = nat_proto;

    *sessionp = s;

    /* Add to translation hashes */
    ctx.now = now;
    ctx.mnat = mnat;

    MAP_NAT_LOCK(mnat, in2out_out2in);

    init_map_nat_i2o_kv (&kv, s, s - mnat->sessions);
    if (clib_bihash_add_or_overwrite_stale_8_8 (
                &mnat->in2out, &kv, 
                map_nat44_i2o_is_idle_session_cb, &ctx))
        clib_warning ("map nat44 ei in2out key add failed");

    init_map_nat_o2i_kv (&kv, s, s - mnat->sessions);
    if (clib_bihash_add_or_overwrite_stale_8_8 (
                &mnat->out2in, &kv, 
                map_nat44_o2i_is_idle_session_cb, &ctx))
        clib_warning ("map nat44 ei out2in key add failed");

    MAP_NAT_UNLOCK(mnat, in2out_out2in);

    return MAP_CE_ERROR_NONE;
}


static_always_inline u8
map_nat44_ei_icmp_in2out (map_ce_domain_t *d,
                          map_nat44_ei_domain_t *mnat,
                          vlib_buffer_t *b,
                          ip4_header_t *ip,
                          f64 now, 
                          map_nat44_ei_session_t **p_s,
                          u32 *next)
{
    vlib_main_t *vm = vlib_get_main ();
    u8 error = MAP_CE_ERROR_NONE;

    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv, value;

    icmp46_header_t *icmp;

    ip4_address_t addr;
    u16 port;
    map_ce_nat_protocol_t proto;

    ip_csum_t sum;
    u16 checksum;
    u16 old_checksum, new_checksum;

    u32 new_addr, old_addr;
    u16 new_id, old_id;


    void *l4_header;
    map_ce_nat_icmp_echo_header_t *echo;

    ip4_header_t *inner_ip;
    icmp46_header_t *inner_icmp;
    map_ce_nat_icmp_echo_header_t *inner_echo;

    icmp = ip4_next_header (ip);

    echo = (map_ce_nat_icmp_echo_header_t *) (icmp + 1);

    error = map_nat44_icmp_get_key (b, ip, &addr, &port, &proto);
    if (MAP_CE_ERROR_NONE != error)
    {
        *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
        return error;
    }

    init_map_nat_k (&kv, addr, port, proto);

    if (clib_bihash_search_8_8 (&mnat->in2out, &kv, &value))
    {
        if (PREDICT_FALSE(
               map_ce_nat44_icmp_type_is_error_message(vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
        {
            error = MAP_CE_ERROR_NAT_BAD_ICMP_TYPE;
            *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
            return error;
        }

        error = map_nat44_mapping (d, mnat, b, ip, addr, port, proto, &s, now);
        if (MAP_CE_ERROR_NONE != error)
        {
            *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
            return error;
        }
    }
    else
    {
        if (PREDICT_FALSE(
              vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_request && 
              vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_reply && 
              !map_ce_nat44_icmp_type_is_error_message (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
        {
            *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
            return MAP_CE_ERROR_NAT_BAD_ICMP_TYPE;
        }
        s = pool_elt_at_index (mnat->sessions, value.value);
    }

    if (s)
    {
        addr = s->out2in.addr;
        port = s->out2in.port;
    }
    if (p_s)
        *p_s = s;

    if (PREDICT_TRUE (!ip4_is_fragment (ip)))
    {
        sum = ip_incremental_checksum_buffer (vm, b,
                                             (u8 *) icmp - (u8 *) vlib_buffer_get_current (b),
                                             clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip), 
                                             0);
        checksum = ~ip_csum_fold (sum);
        if (PREDICT_FALSE (checksum != 0 && checksum != 0xffff))
        {
            *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
            return MAP_CE_ERROR_NAT_CHECKSUM_BAD;
        }
    }

    old_addr = ip->src_address.as_u32;
    new_addr = ip->src_address.as_u32 = addr.as_u32;

    sum = ip->checksum;
    sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
    ip->checksum = ip_csum_fold (sum);

    if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
        if (icmp->checksum == 0)
            icmp->checksum = 0xffff;

        if (!map_ce_nat44_icmp_type_is_error_message (icmp->type))
        {
            new_id = port;
            if (PREDICT_FALSE (new_id != echo->identifier))
            {
                old_id = echo->identifier;
                new_id = port;
                echo->identifier = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_icmp_echo_header_t, identifier);
                icmp->checksum = ip_csum_fold (sum);
            }
        }
        else
        {
            inner_ip = (ip4_header_t *) (echo + 1);
            l4_header = ip4_next_header (inner_ip);

            if (!ip4_header_checksum_is_valid (inner_ip))
            {
                *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
                return MAP_CE_ERROR_NAT_CHECKSUM_BAD;
            }

            /* update inner destination IP address */
            old_addr = inner_ip->dst_address.as_u32;
            inner_ip->dst_address = addr;
            new_addr = inner_ip->dst_address.as_u32;
            sum = icmp->checksum;
            sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
            icmp->checksum = ip_csum_fold (sum);

            /* update inner IP header checksum */
            old_checksum = inner_ip->checksum;
            sum = inner_ip->checksum;
            sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
            inner_ip->checksum = ip_csum_fold (sum);
            new_checksum = inner_ip->checksum;
            sum = icmp->checksum;
            sum = ip_csum_update (sum, old_checksum, new_checksum, ip4_header_t, checksum);
            icmp->checksum = ip_csum_fold (sum);

            switch (proto)
            {
            case MAP_CE_NAT_PROTOCOL_ICMP:
                inner_icmp = (icmp46_header_t *) l4_header;
                inner_echo = (map_ce_nat_icmp_echo_header_t *) (inner_icmp + 1);

                old_id = inner_echo->identifier;
                new_id = port;
                inner_echo->identifier = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_icmp_echo_header_t, identifier);
                icmp->checksum = ip_csum_fold (sum);
                break;
            case MAP_CE_NAT_PROTOCOL_UDP:
            case MAP_CE_NAT_PROTOCOL_TCP:
                old_id = ((map_ce_nat_tcp_udp_header_t *) l4_header)->dst_port;
                new_id = port;
                ((map_ce_nat_tcp_udp_header_t *) l4_header)->dst_port = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_tcp_udp_header_t, dst_port);
                icmp->checksum = ip_csum_fold (sum);
                break;
            default:
                ASSERT (0);
            }
        }
    }

    /* update ip.ress */
    vnet_buffer (b)->ip.reass.l4_src_port = s->out2in.port;

    s->last_heard = now;
    map_nat44_ei_session_update_lru (mnat, s);
    return MAP_CE_ERROR_NONE;
}

static_always_inline u8
map_nat44_ei_tcp_udp_in2out (map_ce_domain_t *d,
                          map_nat44_ei_domain_t *mnat,
                          vlib_buffer_t *b,
                          ip4_header_t *ip, 
                          map_ce_nat_protocol_t proto,
                          f64 now, 
                          map_nat44_ei_session_t **p_s,
                          u32 *next)
{
    u8 error = MAP_CE_ERROR_NONE;

    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv, value;

    udp_header_t *udp;
    tcp_header_t *tcp;

    ip_csum_t sum;
    u32 new_addr, old_addr;
    u16 old_port, new_port;

    udp = ip4_next_header (ip);
    tcp = (tcp_header_t *) udp;

    init_map_nat_k (&kv, ip->src_address, vnet_buffer (b)->ip.reass.l4_src_port, proto);

    if (clib_bihash_search_8_8 (&mnat->in2out, &kv, &value))
    {
        error = map_nat44_mapping (d, mnat, 
                                   b, ip, ip->src_address, 
                                   vnet_buffer (b)->ip.reass.l4_src_port, 
                                   proto, &s, now);
        if (MAP_CE_ERROR_NONE != error)
        {
            *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
            return error;
        }
    }
    else
    {
        s = pool_elt_at_index (mnat->sessions, value.value);
    }

    old_addr = ip->src_address.as_u32;
    ip->src_address = s->out2in.addr;
    new_addr = ip->src_address.as_u32;

    sum = ip->checksum;
    sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address /* changed member */ );
    ip->checksum = ip_csum_fold (sum);

    if (proto == MAP_CE_NAT_PROTOCOL_TCP)
    {
        if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
        {
            old_port = vnet_buffer (b)->ip.reass.l4_src_port;
            new_port = tcp->src_port = s->out2in.port;
            sum = tcp->checksum;
            sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address /* changed member */ );
            sum = ip_csum_update (sum, old_port, new_port, ip4_header_t /* cheat */ , length /* changed member */ );
            tcp->checksum = ip_csum_fold (sum);
        }
    }
    else
    {
        if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
        {
            udp->src_port = s->out2in.port;
            if (PREDICT_FALSE (udp->checksum))
            {
                old_port = vnet_buffer (b)->ip.reass.l4_src_port;
                new_port = udp->src_port;
                sum = udp->checksum;
                sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address /* changed member */ );
                sum = ip_csum_update (sum, old_port, new_port, ip4_header_t /* cheat */ , length /* changed member */ );
                udp->checksum = ip_csum_fold (sum);
            }
        }
    }

    /* update ip.ress */
    vnet_buffer (b)->ip.reass.l4_src_port = s->out2in.port;

    /* Per-user LRU list maintenance */
    s->last_heard = now;
    map_nat44_ei_session_update_lru (mnat, s);
    return MAP_CE_ERROR_NONE;
}

static uword
nat44_map_ce_in2out (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip4_map_e_ce_node.index);
    f64 now = vlib_time_now (vm);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    map_ce_main_t *mm = &map_ce_main;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;

            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAP_CE_NAT44_EI_I2O_NEXT_DROP;

            u32 map_domain_index0 = ~0;
            map_ce_domain_t *d0;
            map_nat44_ei_domain_t *mnat0;

            map_nat44_ei_session_t *s0 = NULL;

            ip4_header_t *ip40;
            map_ce_nat_protocol_t proto0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;


            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            if (map_domain_index0 >= vec_len(mm->nat_domains))
            {
                error0 = MAP_CE_ERROR_NO_NAT_DOMAIN;
                goto trace;
            }

            mnat0 = vec_elt_at_index (mm->nat_domains, map_domain_index0);

            next0 = vnet_buffer (p0)->map_ce.is_translation ? 
                                MAP_CE_NAT44_EI_I2O_NEXT_MAP_T : MAP_CE_NAT44_EI_I2O_NEXT_MAP_E;

            proto0 = ip_proto_to_map_nat_proto (ip40->protocol);

            if (PREDICT_FALSE (proto0 == MAP_CE_NAT_PROTOCOL_OTHER))
            {
                next0 = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
                error0 = MAP_CE_ERROR_NAT_UNSUPPORTED_PROTOCOL;
                goto trace;
            }

            if (PREDICT_FALSE (proto0 == MAP_CE_NAT_PROTOCOL_ICMP))
            {
                error0 = map_nat44_ei_icmp_in2out(d0, mnat0, p0, ip40, now, &s0, &next0);
            }
            else
            {
                error0 = map_nat44_ei_tcp_udp_in2out(d0, mnat0, p0, ip40, proto0, now, &s0, &next0);
            }

trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                if (s0)
                {
                    map_ce_add_nat44_trace (vm, node, p0, map_domain_index0, 
                                            &s0->in2out.addr, &s0->out2in.addr, s0->in2out.port, s0->out2in.port, proto0);
                }
                else
                {
                    map_ce_add_nat44_trace (vm, node, p0, map_domain_index0, 
                                            NULL, NULL, 0, 0, proto0);
                }
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next, pi0,
                                             next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return frame->n_vectors;
}

static_always_inline u8
map_nat44_ei_icmp_out2in (map_ce_domain_t *d,
                          map_nat44_ei_domain_t *mnat,
                          vlib_buffer_t *b,
                          ip4_header_t *ip,
                          f64 now, 
                          map_nat44_ei_session_t **p_s,
                          u32 *next)
{
    vlib_main_t *vm = vlib_get_main ();
    u8 error = MAP_CE_ERROR_NONE;

    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv, value;

    ip4_address_t addr;
    u16 port;
    map_ce_nat_protocol_t proto;

    ip_csum_t sum;
    u16 checksum;

    ip4_address_t mapping_addr;
    u16 mapping_port;

    u32 new_addr, old_addr;
    u16 new_id, old_id;

    void *l4_header = 0;

    icmp46_header_t *icmp;

    ip4_header_t *inner_ip;
    icmp46_header_t *inner_icmp;

    map_ce_nat_icmp_echo_header_t *echo;
    map_ce_nat_icmp_echo_header_t *inner_echo;

    icmp = ip4_next_header (ip);
    echo = (map_ce_nat_icmp_echo_header_t *) (icmp + 1);

    error = map_nat44_icmp_get_key (b, ip, &addr, &port, &proto);
    if (MAP_CE_ERROR_NONE != error)
    {
        *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
        return error;
    }

    init_map_nat_k (&kv, addr, port, proto);

    if (clib_bihash_search_8_8 (&mnat->out2in, &kv, &value))
    {
        /* Try to match static mapping by external address and port,
           destination address and port in packet */
        if (map_nat44_ei_static_mapping_match (mnat, addr, port, proto, &mapping_addr, &mapping_port, 1))
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return MAP_CE_ERROR_NAT_NO_TRANSLATION;
        }

        if (PREDICT_FALSE
                (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_reply && 
                (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_request)))
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return MAP_CE_ERROR_NAT_BAD_ICMP_TYPE;
        }

        /* Create session initiated by host from external network */
        error = map_nat44_ei_session_alloc_for_static_mapping (mnat, b, 
                            mapping_addr, mapping_port, addr, port, proto, &s, now);

        if (error != MAP_CE_ERROR_NONE)
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return error;
        }
    }
    else
    {
        if (PREDICT_FALSE(vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_reply && 
                          vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags != ICMP4_echo_request && 
                          !map_ce_nat44_icmp_type_is_error_message (vnet_buffer (b)->ip.reass.icmp_type_or_tcp_flags)))
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return MAP_CE_ERROR_NAT_BAD_ICMP_TYPE;
        }

        s = pool_elt_at_index (mnat->sessions, value.value);
    }

    if (s)
    {
        addr = s->out2in.addr;
        port = s->out2in.port;
    }
    if (p_s)
        *p_s = s;

    if (PREDICT_TRUE (!ip4_is_fragment (ip)))
    {
        sum = ip_incremental_checksum_buffer (vm, b,
                                             (u8 *) icmp - (u8 *) vlib_buffer_get_current (b),
                                             clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip), 
                                             0);
        checksum = ~ip_csum_fold (sum);
        if (PREDICT_FALSE (checksum != 0 && checksum != 0xffff))
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return MAP_CE_ERROR_NAT_CHECKSUM_BAD;
        }
    }

    old_addr = ip->dst_address.as_u32;
    new_addr = ip->dst_address.as_u32 = addr.as_u32;

    sum = ip->checksum;
    sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address /* changed member */ );
    ip->checksum = ip_csum_fold (sum);

    if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
    {
        if (icmp->checksum == 0)
            icmp->checksum = 0xffff;

        if (!map_ce_nat44_icmp_type_is_error_message (icmp->type))
        {
            new_id = port;
            if (PREDICT_FALSE (new_id != echo->identifier))
            {
                old_id = echo->identifier;
                new_id = port;
                echo->identifier = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_icmp_echo_header_t, identifier /* changed member */ );
                icmp->checksum = ip_csum_fold (sum);
            }
        }
        else
        {
            inner_ip = (ip4_header_t *) (echo + 1);
            l4_header = ip4_next_header (inner_ip);

            if (!ip4_header_checksum_is_valid (inner_ip))
            {
                *next = MAP_CE_NAT44_EI_I2O_NEXT_DROP;
                return MAP_CE_ERROR_NAT_CHECKSUM_BAD;
            }

            old_addr = inner_ip->src_address.as_u32;
            inner_ip->src_address = addr;
            new_addr = inner_ip->src_address.as_u32;

            sum = icmp->checksum;
            sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address /* changed member */ );
            icmp->checksum = ip_csum_fold (sum);

            switch (proto)
            {
            case MAP_CE_NAT_PROTOCOL_ICMP:
                inner_icmp = (icmp46_header_t *) l4_header;
                inner_echo = (map_ce_nat_icmp_echo_header_t *) (inner_icmp + 1);

                old_id = inner_echo->identifier;
                new_id = port;
                inner_echo->identifier = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_icmp_echo_header_t, identifier);
                icmp->checksum = ip_csum_fold (sum);
                break;
            case MAP_CE_NAT_PROTOCOL_UDP:
            case MAP_CE_NAT_PROTOCOL_TCP:
                old_id = ((map_ce_nat_tcp_udp_header_t *) l4_header)->src_port;
                new_id = port;
                ((map_ce_nat_tcp_udp_header_t *) l4_header)->src_port = new_id;

                sum = icmp->checksum;
                sum = ip_csum_update (sum, old_id, new_id, map_ce_nat_tcp_udp_header_t, src_port);
                icmp->checksum = ip_csum_fold (sum);
                break;
            default:
                ASSERT (0);
            }
        }
    }

    s->last_heard = now;
    map_nat44_ei_session_update_lru (mnat, s);
    return MAP_CE_ERROR_NONE;
}

static_always_inline u8
map_nat44_ei_tcp_udp_out2in (map_ce_domain_t *d,
                          map_nat44_ei_domain_t *mnat,
                          vlib_buffer_t *b,
                          ip4_header_t *ip, 
                          map_ce_nat_protocol_t proto,
                          f64 now, 
                          map_nat44_ei_session_t **p_s,
                          u32 *next)
{
    u8 error = MAP_CE_ERROR_NONE;

    map_nat44_ei_session_t *s = NULL;
    clib_bihash_kv_8_8_t kv, value;

    udp_header_t *udp;
    tcp_header_t *tcp;

    ip_csum_t sum;

    ip4_address_t mapping_addr;
    u16 mapping_port;

    u32 new_addr, old_addr;
    u16 old_port, new_port;

    udp = ip4_next_header (ip);
    tcp = (tcp_header_t *) udp;

    init_map_nat_k (&kv, ip->dst_address, vnet_buffer (b)->ip.reass.l4_dst_port, proto);

    if (clib_bihash_search_8_8 (&mnat->out2in, &kv, &value))
    {
	  /* Try to match static mapping by external address and port,
	     destination address and port in packet */
        if (map_nat44_ei_static_mapping_match (mnat, ip->dst_address, vnet_buffer (b)->ip.reass.l4_dst_port,
                                               proto, &mapping_addr, &mapping_port, 1))
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return MAP_CE_ERROR_NAT_NO_TRANSLATION;
        }

        /* Create session initiated by host from external network */
        error = map_nat44_ei_session_alloc_for_static_mapping (mnat, b, 
                mapping_addr, mapping_port, ip->dst_address, vnet_buffer (b)->ip.reass.l4_dst_port, proto, &s, now);

        if (error != MAP_CE_ERROR_NONE)
        {
            *next = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
            return error;
        }
    }
    else
    {
        s = pool_elt_at_index (mnat->sessions, value.value);
    }

    old_addr = ip->dst_address.as_u32;
    ip->dst_address = s->in2out.addr;
    new_addr = ip->dst_address.as_u32;

    sum = ip->checksum;
    sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address /* changed member */ );
    ip->checksum = ip_csum_fold (sum);

    if (PREDICT_TRUE (proto == MAP_CE_NAT_PROTOCOL_TCP))
	{
        if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
	    {
            old_port = vnet_buffer (b)->ip.reass.l4_dst_port;
            new_port = udp->dst_port = s->in2out.port;
            sum = tcp->checksum;
            sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address /* changed member */ );

            sum = ip_csum_update (sum, old_port, new_port, ip4_header_t /* cheat */ , length /* changed member */ );
            tcp->checksum = ip_csum_fold (sum);
	    }
    }
    else
	{
	  if (!vnet_buffer (b)->ip.reass.is_non_first_fragment)
	    {
	      old_port = vnet_buffer (b)->ip.reass.l4_dst_port;
	      new_port = udp->dst_port = s->in2out.port;
          if (PREDICT_FALSE (udp->checksum))
          {
              sum = udp->checksum;
              sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address	/* changed member */);
              sum = ip_csum_update (sum, old_port, new_port, ip4_header_t /* cheat */ , length /* changed member */ );
              udp->checksum = ip_csum_fold (sum);
          }
        }
    }
    /* Per-user LRU list maintenance */
    s->last_heard = now;
    map_nat44_ei_session_update_lru (mnat, s);
    return MAP_CE_ERROR_NONE;
}

static uword
nat44_map_ce_out2in (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
    u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
    vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, ip4_map_e_ce_node.index);
    f64 now = vlib_time_now (vm);
    from = vlib_frame_vector_args (frame);
    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    map_ce_main_t *mm = &map_ce_main;

    while (n_left_from > 0)
    {
        vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

        while (n_left_from > 0 && n_left_to_next > 0)
        {
            u32 pi0;
            vlib_buffer_t *p0;

            u8 error0 = MAP_CE_ERROR_NONE;
            u32 next0 = MAP_CE_NAT44_EI_O2I_NEXT_IP4_LOOKUP;

            u32 map_domain_index0 = ~0;
            map_ce_domain_t *d0;
            map_nat44_ei_domain_t *mnat0;

            map_nat44_ei_session_t *s0 = NULL;

            u16 mtu0 = ~0;

            ip4_header_t *ip40;
            map_ce_nat_protocol_t proto0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;


            p0 = vlib_get_buffer (vm, pi0);
            ip40 = vlib_buffer_get_current (p0);

            map_domain_index0 = vnet_buffer (p0)->map_ce.map_domain_index;
            d0 = pool_elt_at_index (mm->domains, map_domain_index0);

            if (map_domain_index0 >= vec_len(mm->nat_domains))
            {
                error0 = MAP_CE_ERROR_NO_NAT_DOMAIN;
                goto trace;
            }

            mnat0 = vec_elt_at_index (mm->nat_domains, map_domain_index0);

            proto0 = ip_proto_to_map_nat_proto (ip40->protocol);

            if (PREDICT_FALSE (proto0 == MAP_CE_NAT_PROTOCOL_OTHER))
            {
                next0 = MAP_CE_NAT44_EI_O2I_NEXT_DROP;
                error0 = MAP_CE_ERROR_NAT_UNSUPPORTED_PROTOCOL;
                goto trace;
            }

            if (PREDICT_FALSE (proto0 == MAP_CE_NAT_PROTOCOL_ICMP))
            {
                error0 = map_nat44_ei_icmp_out2in(d0, mnat0, p0, ip40, now, &s0, &next0);
            }
            else
            {
                error0 = map_nat44_ei_tcp_udp_out2in(d0, mnat0, p0, ip40, proto0, now, &s0, &next0);
            }

            /* MTU check */
            mtu0 = d0->mtu ? d0->mtu : ~0;

            if (mtu0 < p0->current_length)
            {
                //Send to fragmentation node if necessary
                vnet_buffer (p0)->ip_frag.mtu = mtu0;
                vnet_buffer (p0)->ip_frag.next_index = IP_FRAG_NEXT_IP4_LOOKUP;
                next0 = MAP_CE_NAT44_EI_O2I_NEXT_NEXT_IP4_FRAGMENT;
            }
trace:
            if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                if (s0)
                {
                    map_ce_add_nat44_trace (vm, node, p0, map_domain_index0, 
                                            &s0->in2out.addr, &s0->out2in.addr, s0->in2out.port, s0->out2in.port, proto0);
                }
                else
                {
                    map_ce_add_nat44_trace (vm, node, p0, map_domain_index0, 
                                            NULL, NULL, 0, 0, proto0);
                }
            }
            p0->error = error_node->errors[error0];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                             to_next, n_left_to_next, pi0,
                                             next0);
        }
        vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
    return frame->n_vectors;
}

VLIB_REGISTER_NODE(map_ce_nat44_ei_in2out) = {
    .function = nat44_map_ce_in2out,
    .name = "map-ce-nat44-ei-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_map_ce_nat44_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = MAP_CE_N_ERROR,
    .error_counters = map_ce_error_counters,

    .n_next_nodes = MAP_CE_NAT44_IN2OUT_N_NEXT,
    .next_nodes = {
        [MAP_CE_NAT44_EI_I2O_NEXT_MAP_E] = "ip4-map-e-ce",
        [MAP_CE_NAT44_EI_I2O_NEXT_MAP_T] = "ip4-map-t-ce",
        [MAP_CE_NAT44_EI_I2O_NEXT_DROP] = "error-drop",
    },
};

VLIB_REGISTER_NODE(map_ce_nat44_ei_out2in) = {
    .function = nat44_map_ce_out2in,
    .name = "map-ce-nat44-ei-out2in",
    .vector_size = sizeof(u32),
    .format_trace = format_map_ce_nat44_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,

    .n_errors = MAP_CE_N_ERROR,
    .error_counters = map_ce_error_counters,

    .n_next_nodes = MAP_CE_NAT44_OUT2IN_N_NEXT,
    .next_nodes = {
        [MAP_CE_NAT44_EI_O2I_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [MAP_CE_NAT44_EI_O2I_NEXT_NEXT_IP4_FRAGMENT] = "ip4-frag",
        [MAP_CE_NAT44_EI_O2I_NEXT_DROP] = "error-drop",
    },
};
