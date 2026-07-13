
/*
 * geosite.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <2024-2027> <Asterfusion Network>
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
#ifndef __included_geosite_h__
#define __included_geosite_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/lock.h>
#include "domain_trie.h"
#include "geoip_trie.h"

#define GEOSITE_RESOLVED_MAX_REFS 31
#define GEOSITE_RESOLVED_POOL_MAX_ENTRIES 160000
#define GEOSITE_RESOLVED_HASH_BUCKETS 65536
#define GEOSITE_RESOLVED_HASH_MEMORY (64 << 20)
#ifndef GEO_CFG
#define GEO_CFG 0XFFFF
#endif

typedef struct
{
    u32 geosite_index;
    u32 expire_time_sec;
} geosite_resolved_ref_t;

typedef struct
{
    u32 ref_bitmap;
    u32 reserved;

    geosite_resolved_ref_t refs[GEOSITE_RESOLVED_MAX_REFS];
} geosite_resolved_entry_t;

static_always_inline void
geosite_resolved_make_ip4_key (clib_bihash_kv_16_8_t *kv,
                               const ip4_address_t *ip4)
{
    ip6_address_t mapped;

    clib_memset (kv, 0, sizeof (*kv));
    clib_memset (&mapped, 0, sizeof (mapped));
    mapped.as_u8[10] = 0xff;
    mapped.as_u8[11] = 0xff;
    clib_memcpy (&mapped.as_u8[12], ip4->as_u8, 4);
    clib_memcpy (kv->key, mapped.as_u8, 16);
}

static_always_inline void
geosite_resolved_make_ip6_key (clib_bihash_kv_16_8_t *kv,
                               const ip6_address_t *ip6)
{
    clib_memset (kv, 0, sizeof (*kv));
    clib_memcpy (kv->key, ip6->as_u8, 16);
}

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* on/off switch for the periodic function */
    u8 periodic_timer_enabled;
    /* Node index, non-zero if the periodic process has been created */
    u32 periodic_node_index;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;

    domain_trie_t * domain_trie;
    geoip_db_t *geoip_trie;
    u32 *enable_refcnt_by_sw_if_index;
    u32 *active_geosite_refcnt;
    u32 global_geosite_rule_refcnt;
    u8 global_feature_enabled;
    clib_spinlock_t active_refcnt_lock;

    clib_bihash_16_8_t resolved_ip_hash;
    geosite_resolved_entry_t *resolved_pool;
    u32 resolved_pool_max_entries;
    clib_spinlock_t resolved_pool_lock;
} geosite_main_t;

extern geosite_main_t geosite_main;

extern vlib_node_registration_t geosite_node;
extern vlib_node_registration_t geosite_periodic_node;

/* Periodic function events */
#define GEOSITE_EVENT1 1
#define GEOSITE_EVENT2 2
#define GEOSITE_EVENT_PERIODIC_ENABLE_DISABLE 3

void geosite_create_periodic_process (geosite_main_t *);


typedef struct {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
} dns_header_t_;



u32 add_domain_to_table(const char *domain);

void init_domain_table(void);
void cleanup_domain_table(void);



/* external call */
//  char *geo_get_domain_by_index(u32 index);
u16 geosite_get_index_by_country_code(char *country_code);
char  *geosite_get_country_code_by_index(u16 index);
u16 geoip_get_index_by_country_code(char *country_code);
char  *geoip_get_country_code_by_index(u16 index);
u32 *geosite_get_country_index_by_domain(char *domain);
u32 *geoip_get_country_code_by_ip4(ip4_address_t ip4);
u32 *geoip_get_country_code_by_ip6(ip6_address_t ip6);
u32 *geosite_get_resolved_country_code_by_ip4(ip4_address_t ip4);
u32 *geosite_get_resolved_country_code_by_ip6(ip6_address_t ip6);
void geosite_active_refcnt_add(u32 geosite_index);
void geosite_active_refcnt_del(u32 geosite_index);
u32 geosite_active_refcnt_get(u32 geosite_index);
// char *get_domain_by_index(u32 index);
// u32 *cc_cache_get(u32 index);
// u32 cc_cache_add(u32 *cc_indices);
// u32 *geosite_get_country_index_by_domain2( char *domain);
#endif /* __included_geosite_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
