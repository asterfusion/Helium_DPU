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
#ifndef included_map_ce_nat_h
#define included_map_ce_nat_h

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip.h>
#include <vppinfra/error.h>
#include <vppinfra/lock.h>
#include <vppinfra/dlist.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/hash.h>

/* Fixed Resource DB define */

#define MAP_NAT_STATIC_HASH_BUCKETS   (1024)
#define MAP_NAT_STATIC_HASH_MEMORY_SIZE (64 << 20) //64M
#define MAP_NAT_HASH_BUCKETS   (4096)
#define MAP_NAT_HASH_MEMORY_SIZE (0) //no limit

#define MAP_NAT_STATIC_SESSION_MAX (8192)

#define MAP_NAT_USER_INITIAL_NUM (1024)
#define MAP_NAT_USER_MAX    (5 * 1024)
#define MAP_NAT_SESSION_MAX_PER_USER (512)

#define MAP_NAT_SESSION_MAX (MAP_NAT_USER_MAX * MAP_NAT_SESSION_MAX_PER_USER)

#define MAP_NAT_UDP_TIMEOUT 300
#define MAP_NAT_TCP_TIMEOUT 300
#define MAP_NAT_ICMP_TIMEOUT 60

#define foreach_map_ce_nat_protocol                                           \
  _ (OTHER, 0, other, "other")                                                \
  _ (UDP, 1, udp, "udp")                                                      \
  _ (TCP, 2, tcp, "tcp")                                                      \
  _ (ICMP, 3, icmp, "icmp")


/* Session flags */
#define MAP_NAT_SESSION_FLAG_STATIC_MAPPING (1 << 0)

/* Lock */
#define MAP_NAT_LOCK(a, lock_type) \
    clib_spinlock_lock (&a->lock_##lock_type); 

#define MAP_NAT_UNLOCK(a, lock_type) \
    clib_spinlock_unlock (&a->lock_##lock_type); 

typedef enum
{
#define _(N, i, n, s) MAP_CE_NAT_PROTOCOL_##N = i,
    foreach_map_ce_nat_protocol
#undef _
    MAP_CE_NAT_N_PROTOCOLS
} map_ce_nat_protocol_t;

typedef struct
{
  u16 identifier;
  u16 sequence;
} map_ce_nat_icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} map_ce_nat_tcp_udp_header_t;

typedef struct
{
    ip4_address_t addr;
    u32 busy_ports[MAP_CE_NAT_N_PROTOCOLS];
    uword *busy_port_bitmap[MAP_CE_NAT_N_PROTOCOLS];
    clib_spinlock_t lock_self;
} map_nat44_ei_address_t;

typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
    };
    u64 as_u64;
  };
} map_nat44_ei_user_key_t;

typedef CLIB_PACKED (struct {
  ip4_address_t addr;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
  u32 nstaticsessions;
  clib_spinlock_t lock_self;
}) map_nat44_ei_user_t;

typedef struct
{
  f64 now;
  void *mnat;
} map_nat44_ei_is_idle_session_ctx_t;

typedef struct
{
  u32 tcp;
  u32 udp;
  u32 icmp;
} map_nat44_timeouts_t;

typedef struct
{
    /* local IP address */
    ip4_address_t local_addr;
    /* external IP address */
    ip4_address_t external_addr;
    /* local port */
    u16 local_port;
    /* external port */
    u16 external_port;
    /* protocol */
    map_ce_nat_protocol_t proto;
    /* flags */
    u32 flags;
} map_nat44_ei_static_mapping_t;

typedef struct 
{
    struct
    {
        ip4_address_t addr;
        u16 port;
    } in2out;

    struct
    {
        ip4_address_t addr;
        u16 port;
    } out2in;

    map_ce_nat_protocol_t nat_proto;

    u32 flags;

    /* user index */
    u32 user_index;

    /* Per-user translations */
    u32 per_user_index;
    u32 per_user_list_head_index;

    f64 last_lru_update;

    /* Last heard timer */
    f64 last_heard;

    /* lock */
    clib_spinlock_t lock_self;
}__attribute__ ((packed)) map_nat44_ei_session_t;

typedef struct 
{
    /* Vector of outside addresses */
    map_nat44_ei_address_t *addresses;

    /* Main Dynamic lookup */
    map_nat44_ei_session_t *sessions;
    u8 *in2out_name;
    u8 *out2in_name;
    clib_bihash_8_8_t in2out;
    clib_bihash_8_8_t out2in;

    /* Main Static lookup */
    map_nat44_ei_static_mapping_t *static_mappings;
    u8 *static_in2out_name;
    u8 *static_out2in_name;
    clib_bihash_8_8_t static_in2out; 
    clib_bihash_8_8_t static_out2in;

    /* User lokkup */
    map_nat44_ei_user_t *users;
    u8 *users_hash_name;
    clib_bihash_8_8_t users_hash;

    dlist_elt_t *list_pool;

    u32 max_translations;
    u32 max_translations_per_user;
    u32 max_users;

    /* MAP l4 port alloc alg */
    u8 psid_offset;
    u8 psid_length;
    u16 psid;
    /* Randomize port allocation order */
    u32 random_seed;

    map_nat44_timeouts_t timeouts;

    /* lock */
    clib_spinlock_t lock_sessions;
    clib_spinlock_t lock_users;
    clib_spinlock_t lock_list_pool;

} map_nat44_ei_domain_t;

static_always_inline map_ce_nat_protocol_t
ip_proto_to_map_nat_proto (ip_protocol_t ip_proto)
{
    static const map_ce_nat_protocol_t lookup_table[256] = {
        [IP_PROTOCOL_TCP] = MAP_CE_NAT_PROTOCOL_TCP,
        [IP_PROTOCOL_UDP] = MAP_CE_NAT_PROTOCOL_UDP,
        [IP_PROTOCOL_ICMP] = MAP_CE_NAT_PROTOCOL_ICMP,
        [IP_PROTOCOL_ICMP6] = MAP_CE_NAT_PROTOCOL_ICMP,
    };

    return lookup_table[ip_proto];
}

static_always_inline u64
map_ce_nat44_icmp_type_is_error_message (u8 icmp_type)
{
  int bmp = 0;
  bmp |= 1 << ICMP4_destination_unreachable;
  bmp |= 1 << ICMP4_time_exceeded;
  bmp |= 1 << ICMP4_parameter_problem;
  bmp |= 1 << ICMP4_source_quench;
  bmp |= 1 << ICMP4_redirect;
  bmp |= 1 << ICMP4_alternate_host_address;

  return (1ULL << icmp_type) & bmp;
}

static_always_inline void
map_ce_nat44_reset_timeouts (map_nat44_timeouts_t * timeouts)
{
  timeouts->udp = MAP_NAT_UDP_TIMEOUT;
  timeouts->tcp = MAP_NAT_TCP_TIMEOUT;
  timeouts->icmp = MAP_NAT_ICMP_TIMEOUT;
}

static_always_inline u32
map_ce_nat_session_get_timeout (map_nat44_timeouts_t *timeouts, 
                                map_ce_nat_protocol_t proto)
{
    switch (proto)
    {
    case MAP_CE_NAT_PROTOCOL_ICMP:
        return timeouts->icmp;
    case MAP_CE_NAT_PROTOCOL_UDP:
      return timeouts->udp;
    case MAP_CE_NAT_PROTOCOL_TCP:
      return timeouts->tcp;
    default:
      return timeouts->udp;
    }
    return 0;
}

always_inline u64
calc_map_nat_key (ip4_address_t addr, u16 port, u8 proto)
{
  return (u64) addr.as_u32 << 32 | (u64) port << 16 | (proto) << 8;
}

always_inline void
split_map_nat_key (u64 key, ip4_address_t *addr, u16 *port, map_ce_nat_protocol_t *proto)
{
  if (addr)
    {
      addr->as_u32 = key >> 32;
    }
  if (port)
    {
      *port = (key >> 16) & (u16) ~0;
    }
  if (proto)
    {
      *proto = (key >> 8) & (u8) ~0;
    }
}

always_inline void
init_map_nat_k (clib_bihash_kv_8_8_t *kv, ip4_address_t addr, u16 port, map_ce_nat_protocol_t proto)
{
    kv->key = calc_map_nat_key (addr, port, proto);
    kv->value = ~0ULL;
}

always_inline void
init_map_nat_kv (clib_bihash_kv_8_8_t *kv, ip4_address_t addr, u16 port, map_ce_nat_protocol_t proto, u32 session_index)
{
    init_map_nat_k (kv, addr, port, proto);
    kv->value = session_index;
}

always_inline void
init_map_nat_i2o_k (clib_bihash_kv_8_8_t *kv, map_nat44_ei_session_t *s)
{
    return init_map_nat_k (kv, s->in2out.addr, s->in2out.port, s->nat_proto);
}

always_inline void
init_map_nat_o2i_k (clib_bihash_kv_8_8_t *kv, map_nat44_ei_session_t *s)
{
    return init_map_nat_k (kv, s->out2in.addr, s->out2in.port, s->nat_proto);
}

always_inline void
init_map_nat_i2o_kv (clib_bihash_kv_8_8_t *kv, map_nat44_ei_session_t *s, u32 session_index)
{
    init_map_nat_k (kv, s->in2out.addr, s->in2out.port, s->nat_proto);
    kv->value = session_index;
}

always_inline void
init_map_nat_o2i_kv (clib_bihash_kv_8_8_t *kv, map_nat44_ei_session_t *s, u32 session_index)
{
    init_map_nat_k (kv, s->out2in.addr, s->out2in.port, s->nat_proto);
    kv->value = session_index;
}

always_inline u16
map_nat_random_port (u32 *random_seed, u16 min, u16 max)
{
  u32 rwide;
  u16 r;

  rwide = random_u32 (random_seed);
  r = rwide & 0xFFFF;
  if (r >= min && r <= max)
    return r;

  return min + (rwide % (max - min + 1));
}

static_always_inline u8
map_nat44_maximum_sessions_exceeded (map_nat44_ei_domain_t *mnat)
{
  if (pool_elts (mnat->sessions) >= mnat->max_translations)
    return 1;
  return 0;
}

static_always_inline void
map_nat44_ei_delete_user_with_no_session (map_nat44_ei_domain_t *mnat, 
                                          map_nat44_ei_user_t *u, bool hash_del)
{
    clib_bihash_kv_8_8_t kv;
    map_nat44_ei_user_key_t u_key;

    if (u->nstaticsessions == 0 && u->nsessions == 0)
    {
        u_key.addr.as_u32 = u->addr.as_u32;
        kv.key = u_key.as_u64;

        MAP_NAT_LOCK(mnat, list_pool);
        pool_put_index (mnat->list_pool, u->sessions_per_user_list_head_index);
        MAP_NAT_UNLOCK(mnat, list_pool);


        MAP_NAT_LOCK(mnat, users);
        clib_spinlock_free(&u->lock_self);
        pool_put (mnat->users, u);
        MAP_NAT_UNLOCK(mnat, users);

        if (hash_del)
        {
            clib_bihash_add_del_8_8 (&mnat->users_hash, &kv, 0);
        }
    }
}

always_inline void
map_nat44_ei_user_session_increment (map_nat44_ei_domain_t *mnat, 
                                     map_nat44_ei_user_t *u,
                                     u8 is_static)
{
    MAP_NAT_LOCK(u, self);

    if (u->nsessions + u->nstaticsessions < mnat->max_translations_per_user)
    {
        if (is_static)
            u->nstaticsessions++;
        else
            u->nsessions++;
    }

    MAP_NAT_UNLOCK(u, self);
}

always_inline int
map_nat44_ei_reserve_port (map_nat44_ei_domain_t *mnat,
                           ip4_address_t addr, u16 port, map_ce_nat_protocol_t proto)
{
    map_nat44_ei_address_t *a = 0;
    int i;

    for (i = 0; i < vec_len (mnat->addresses); i++)
    {
        a = mnat->addresses + i;

        if (a->addr.as_u32 != addr.as_u32)
            continue;

        MAP_NAT_LOCK(a, self);

        if (clib_bitmap_get (a->busy_port_bitmap[proto], port))
        {
            MAP_NAT_UNLOCK(a, self);
            continue;
        }

        a->busy_port_bitmap[proto] = clib_bitmap_set (a->busy_port_bitmap[proto], port, 1);
        if (port > 1024)
        {
            a->busy_ports[proto]++;
        }
        
        MAP_NAT_UNLOCK(a, self);
        return 0;
    }
    return 1;
}

always_inline int 
map_nat44_ei_alloc_map_addr_port (map_nat44_ei_domain_t *mnat,
                                  map_ce_nat_protocol_t proto,
                                  ip4_address_t s_addr, 
                                  ip4_address_t *addr, 
                                  u16 *port)
{
    map_nat44_ei_address_t *a;
    u16 m, ports, portnum, A, j;
    m = 16 - (mnat->psid_offset + mnat->psid_length);
    ports = mnat->psid_length == 0 ? (0xffff - 1024) : (1 << (16 - mnat->psid_length)) - (1 << m);

    if (!vec_len (mnat->addresses))
        goto exhausted;

    vec_foreach(a, mnat->addresses)
    {
        MAP_NAT_LOCK(a, self);
        if (a->busy_ports[proto] < ports)
        {
            while (1)
            {
                if (mnat->psid_length != 0)
                {
                    A = map_nat_random_port (&mnat->random_seed, 1, pow2_mask (mnat->psid_offset));
                    j = map_nat_random_port (&mnat->random_seed, 0, pow2_mask (m));
                    portnum = A | (mnat->psid << mnat->psid_offset) | (j << (16 - m));
                }
                else
                {
                    portnum = 1024 + map_nat_random_port (&mnat->random_seed, 0, ports);
                }
                if (clib_bitmap_get (a->busy_port_bitmap[proto], portnum))
                    continue;
                a->busy_port_bitmap[proto] = clib_bitmap_set (a->busy_port_bitmap[proto], portnum, 1);
                a->busy_ports[proto]++;
                *addr = a->addr;
                *port = clib_host_to_net_u16 (portnum);

                MAP_NAT_UNLOCK(a, self);

                return 0;
            }
        }
        MAP_NAT_UNLOCK(a, self);
    }
exhausted:
    return 1;
}

always_inline void 
map_nat44_ei_free_outside_address_and_port (map_nat44_ei_domain_t *mnat,
                                  ip4_address_t *addr,
                                  u16 port, 
                                  map_ce_nat_protocol_t protocol)
{
    map_nat44_ei_address_t *a;
    u32 address_index;
    u16 port_host_byte_order = clib_net_to_host_u16 (port);

    for (address_index = 0; address_index < vec_len (mnat->addresses); address_index++)
    {
        if (mnat->addresses[address_index].addr.as_u32 == addr->as_u32)
            break;
    }

    ASSERT (address_index < vec_len (mnat->addresses));

    a = mnat->addresses + address_index;

    MAP_NAT_LOCK(a, self);

    a->busy_port_bitmap[protocol] = clib_bitmap_set (a->busy_port_bitmap[protocol], port_host_byte_order, 0);
    a->busy_ports[protocol]--;

    MAP_NAT_UNLOCK(a, self);
}

always_inline void 
map_nat44_ei_free_session_data (map_nat44_ei_domain_t *mnat, 
                                map_nat44_ei_session_t *s)
{
    clib_bihash_kv_8_8_t kv;

    /* session lookup tables */

    init_map_nat_i2o_k (&kv, s);
    clib_bihash_add_del_8_8 (&mnat->in2out, &kv, 0);

    init_map_nat_o2i_k (&kv, s);
    clib_bihash_add_del_8_8 (&mnat->out2in, &kv, 0);

    if ((s->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING))
        return;

    map_nat44_ei_free_outside_address_and_port (mnat, &s->out2in.addr, s->out2in.port, s->nat_proto);
}


always_inline void
map_nat44_ei_delete_session (map_nat44_ei_domain_t *mnat, map_nat44_ei_session_t *ses)
{
    clib_bihash_kv_8_8_t kv, value;
    map_nat44_ei_user_t *u;
    map_nat44_ei_user_key_t u_key;

    u_key.as_u64 = 0;
    u_key.addr = ses->in2out.addr;

    clib_dlist_remove (mnat->list_pool, ses->per_user_index);
    pool_put_index (mnat->list_pool, ses->per_user_index);

    MAP_NAT_LOCK(mnat, sessions);
    clib_spinlock_free(&ses->lock_self);
    pool_put (mnat->sessions, ses);
    MAP_NAT_UNLOCK(mnat, sessions);

    kv.key = u_key.as_u64;
    if (!clib_bihash_search_8_8 (&mnat->users_hash, &kv, &value))
    {
        u = pool_elt_at_index (mnat->users, value.value);
        MAP_NAT_LOCK(u, self);
        if (ses->flags & MAP_NAT_SESSION_FLAG_STATIC_MAPPING)
            u->nstaticsessions--;
        else
            u->nsessions--;
        MAP_NAT_UNLOCK(u, self);
        map_nat44_ei_delete_user_with_no_session (mnat, u, true);
    }
}

void map_ce_nat44_domain_create(u32 map_domain_index);
void map_ce_nat44_domain_remove(u32 map_domain_index);
void map_ce_nat44_domain_update_psid(u32 map_domain_index, u16 psid);

int map_nat44_ei_add_static_mapping (map_nat44_ei_domain_t *mnat,
                                 ip4_address_t l_addr, ip4_address_t e_addr, 
                                 u16 l_port, u16 e_port, 
                                 map_ce_nat_protocol_t proto, u32 flags);
int map_nat44_ei_del_static_mapping (map_nat44_ei_domain_t *mnat,
                                 ip4_address_t l_addr, ip4_address_t e_addr, 
                                 u16 l_port, u16 e_port, 
                                 map_ce_nat_protocol_t proto, u32 flags);


#endif /* included_map_ce_nat_h */

