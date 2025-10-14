#include "geoip_trie.h"

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <protobuf-c/protobuf-c.h>
#include "common.pb-c.h"

static inline u32 geoip_get_or_create_country_index(geoip_db_t *db, const char *cc) {
    uword *p = hash_get_mem(db->country_code_index_by_str, cc);
    if (p) return (u32) p[0];
    char *copy = clib_mem_alloc(strlen(cc) + 1);
    strcpy(copy, cc);

    char **s;
    pool_get(db->country_codes, s);
    *s = copy;

    u32 idx = (u32)(s - db->country_codes);
    hash_set_mem(db->country_code_index_by_str, *s, idx);
    return idx;
}

static inline void pt_insert_v4(geoip_pt_node4_t **root, const ip4_address_t *addr, u8 plen, u32 cc_index) {
    if (*root == 0) 
    {
        *root = clib_mem_alloc(sizeof(geoip_pt_node4_t));
        if (*root == NULL)
        {
            return;
        }
        memset(*root, 0, sizeof(geoip_pt_node4_t));
    }
    geoip_pt_node4_t *node = *root;
    for (int i = 0; i < plen; i++) {
        int byte = i >> 3;
        int bit = 7 - (i & 7);
        int b = (addr->data[byte] >> bit) & 1;

        if (!node->children[b]) {
            node->children[b] = clib_mem_alloc(sizeof(geoip_pt_node4_t));
            memset(node->children[b], 0, sizeof(geoip_pt_node4_t));
        }
        node = node->children[b];
    }
    u32 *ci;
    vec_foreach(ci, node->country_indices) {
        if (*ci == cc_index) return;
    }
    vec_add1(node->country_indices, cc_index);
}

static inline void pt_insert_v6(geoip_pt_node6_t **root, const ip6_address_t *addr, u8 plen, u32 cc_index) {
    if (*root == 0) 
    {
        *root = clib_mem_alloc(sizeof(geoip_pt_node6_t)); 
        if (*root == NULL)
        {
            return;
        }
        memset(*root, 0, sizeof(geoip_pt_node6_t));
    }
    geoip_pt_node6_t *node = *root;
    for (int i = 0; i < plen; i++) {
        int byte = i >> 3;
        int bit = 7 - (i & 7);
        int b = (addr->as_u8[byte] >> bit) & 1;

        if (!node->children[b]) {
            node->children[b] = clib_mem_alloc(sizeof(geoip_pt_node6_t));
            memset(node->children[b], 0, sizeof(geoip_pt_node6_t));
        }
        node = node->children[b];
    }
    u32 *ci;
    vec_foreach(ci, node->country_indices) {
        if (*ci == cc_index) return;
    }
    vec_add1(node->country_indices, cc_index);
}

static void pt_free_v4(geoip_pt_node4_t *node) {
    if (!node) return;
    pt_free_v4(node->children[0]);
    pt_free_v4(node->children[1]);
    vec_free(node->country_indices);
    clib_mem_free(node);
}

static void pt_free_v6(geoip_pt_node6_t *node) {
    if (!node) return;
    pt_free_v6(node->children[0]);
    pt_free_v6(node->children[1]);
    vec_free(node->country_indices);
    clib_mem_free(node);
}

geoip_db_t *geoip_db_load(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        clib_warning("Failed to open file: %s", filename);
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) { 
        clib_warning("fstat failed: %s", filename);
        close(fd);
        return NULL; 
    }
    void *data = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
    {
        clib_warning("mmap failed for file: %s", filename);
        close(fd);
        return NULL;
    }

    GeoIPList *list = geo_iplist__unpack(0, st.st_size, data);
    if (!list) 
    {
        clib_warning("Failed to parse file: %s", filename);
        munmap(data, st.st_size);
        close(fd);
        return 0;
    }

    geoip_db_t *db = clib_mem_alloc(sizeof(geoip_db_t));
    memset(db, 0, sizeof(*db));
    db->country_code_index_by_str = hash_create_string(0, sizeof(uword));

    for (size_t i = 0; i < list->n_entry; i++) {
        GeoIP *e = list->entry[i];
        if (!e->country_code) continue;
        u32 cc_index = geoip_get_or_create_country_index(db, e->country_code);

        for (size_t j = 0; j < e->n_cidr; ++j) {
            CIDR *cidr = e->cidr[j];
            if (cidr->ip.len == 4) {
                ip4_address_t a; 
                memcpy(&a, cidr->ip.data, 4);
                pt_insert_v4(&db->root_v4, &a, cidr->prefix, cc_index);
                db->ipv4_counts += 1;
            } else if (cidr->ip.len == 16) {
                ip6_address_t a; 
                memcpy(&a, cidr->ip.data, 16);
                pt_insert_v6(&db->root_v6, &a, cidr->prefix, cc_index);
                db->ipv6_counts += 1;
            }
        }
    }
    geo_iplist__free_unpacked(list, 0);

    munmap(data, st.st_size);
    close(fd);
    return db;
}

void geoip_db_free(geoip_db_t *db) {
    if (!db) return;
    pt_free_v4(db->root_v4);
    pt_free_v6(db->root_v6);
    hash_free(db->country_code_index_by_str);
    char **s;
    pool_foreach(s, db->country_codes) { clib_mem_free(*s); }
    pool_free(db->country_codes);
    clib_mem_free(db);
}

const char *geoip_get_country_code(geoip_db_t *db, u32 index) {
    if (!db || pool_is_free_index(db->country_codes, index)) return 0;
    return db->country_codes[index];
}

u32 *geoip_lookup_v4(geoip_db_t *db, const ip4_address_t *a) {
    geoip_pt_node4_t *node = db->root_v4;
    u32 *best = 0;
    for (int i = 0; i < 32 && node; i++) {
        if (node->country_indices) best = node->country_indices;

        int byte = i >> 3;
        int bit = 7 - (i & 7);
        int b = (a->data[byte] >> bit) & 1;
        node = node->children[b];
    }
    return best;
}

u32 *geoip_lookup_v6(geoip_db_t *db, const ip6_address_t *a) {
    geoip_pt_node6_t *node = db->root_v6;
    u32 *best = 0;
    for (int i = 0; i < 128 && node; i++) {
        if (node->country_indices) best = node->country_indices;

        int byte = i >> 3;
        int bit = 7 - (i & 7);
        int b = (a->as_u8[byte] >> bit) & 1;
        node = node->children[b];
    }
    return best;
}

