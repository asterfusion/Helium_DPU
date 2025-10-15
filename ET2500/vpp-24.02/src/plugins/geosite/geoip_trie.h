
#ifndef __included_geoip_trie_h__
#define __included_geoip_trie_h__

#include <vppinfra/clib.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>

// Patricia Trie node for IPv4
typedef struct geoip_pt_node4_t {
    struct geoip_pt_node4_t *children[2];
    u32 *country_indices;
} geoip_pt_node4_t;

// Patricia Trie node for IPv6
typedef struct geoip_pt_node6_t {
    struct geoip_pt_node6_t *children[2];
    u32 *country_indices;
} geoip_pt_node6_t;

typedef struct geoip_db_t {
    geoip_pt_node4_t *root_v4;
    geoip_pt_node6_t *root_v6;
    uword *country_code_index_by_str;
    char **country_codes; // pool of strings
    //stats
    u32 ipv4_counts;
    u32 ipv6_counts;
} geoip_db_t;

extern geoip_db_t *geoip_db_load(const char *filename);
extern void geoip_db_free(geoip_db_t *db);
extern u32 *geoip_lookup_v4(geoip_db_t *db, const ip4_address_t *a);
extern u32 *geoip_lookup_v6(geoip_db_t *db, const ip6_address_t *a);
extern const char *geoip_get_country_code(geoip_db_t *db, u32 index);

#endif
