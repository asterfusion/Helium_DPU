/*
 * domain_trie.c - skeleton vpp engine plug-in
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

#include "domain_trie.h"
#include <string.h>
#include <vlib/vlib.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <protobuf-c/protobuf-c.h>
#include "common.pb-c.h"

void domain_trie_init(domain_trie_t *trie) {
    clib_memset(trie, 0, sizeof(*trie));
    pool_alloc(trie->nodes, 1);  // allocate root node at index 0
    trie->country_code_index_by_str = hash_create_string(0, sizeof(uword));
    clib_spinlock_init(&trie->lock);
}

static u32 add_country_code(domain_trie_t *trie, const char *cc) {
    uword *p = hash_get_mem(trie->country_code_index_by_str, cc);
    if (p)
        return (u32)(*p);

    char *copy = clib_mem_alloc(strlen(cc) + 1);
    strcpy(copy, cc);

    char **new_entry;
    pool_get(trie->country_codes, new_entry);
    *new_entry = copy;

    u32 index = new_entry - trie->country_codes;
    hash_set_mem(trie->country_code_index_by_str, *new_entry, index);

    return index;
}

void domain_trie_add(domain_trie_t *trie, const char *domain, const char *country_code) {
    clib_spinlock_lock(&trie->lock);

    const char *p = domain + strlen(domain);
    u32 node_index = 0;

    while (p > domain) {
        const char *dot = p;
        while (dot > domain && *(dot - 1) != '.') dot--;
        int len = p - dot;
        u8 *label = format(0, "%.*s", len, dot);

        uword *childp = hash_get_mem(trie->nodes[node_index].children, label);
        if (!childp) {
            domain_trie_node_t *new_node = NULL;
            pool_get(trie->nodes, new_node);
            clib_memset(new_node, 0, sizeof(*new_node));
            new_node->children = hash_create_string(0, sizeof(uword));  // must create mem-based hash

            u32 new_index = new_node - trie->nodes;
            hash_set_mem(trie->nodes[node_index].children, label, new_index);
            node_index = new_index;
        } else {
            node_index = *childp;
        }
        p = dot - 1;
    }

    trie->nodes[node_index].is_terminal = 1;
    u32 cc_index = add_country_code(trie, country_code);
    vec_add1(trie->nodes[node_index].country_indices, cc_index);
    trie->domain_counts += 1;

    clib_spinlock_unlock(&trie->lock);
}

u32 *domain_trie_match(domain_trie_t *trie, const char *domain) {
    if(!trie) {
        return NULL;
    }
    const char *p = domain + strlen(domain);
    u32 node_index = 0;
    u32 *results = 0;
    u32 *results_all = 0;
    u32 *c = 0;

    while (p > domain) {
        const char *dot = p;
        while (dot > domain && *(dot - 1) != '.') dot--;
        int len = p - dot;
        u8 *label = format(0, "%.*s", len, dot);

        uword *childp = hash_get_mem(trie->nodes[node_index].children, label);
        if (!childp)
        {
            vec_free(label);
            break;
        }

        node_index = *childp;

        if (trie->nodes[node_index].is_terminal) {
            u32 *cc = trie->nodes[node_index].country_indices;
            vec_foreach(c, cc) vec_add1(results_all, *c);
        }

        p = dot - 1;
        vec_free(label);
    }

    if(vec_len(results_all)) {
        uword *seen = hash_create(0, sizeof(uword));
        vec_foreach(c, results_all) {
            if (!hash_get(seen, *c)) {
                vec_add1(results, *c);
                hash_set(seen, *c, 1);
            }
        }
        hash_free(seen);
        vec_free(results_all);
    }

    return results;
}

int load_geosite_dat(const char *filename, domain_trie_t *domain_trie)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        clib_warning("Failed to open file: %s", filename);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        clib_warning("fstat failed: %s", filename);
        close(fd);
        return -1;
    }

    uint8_t *data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED)
    {
        clib_warning("mmap failed for file: %s", filename);
        close(fd);
        return -1;
    }

    GeoSiteList *geo_list = geo_site_list__unpack(NULL, st.st_size, data);
    if (!geo_list)
    {
        clib_warning("Failed to parse file: %s", filename);
        munmap(data, st.st_size);
        close(fd);
        return -1;
    }

    domain_trie_init(domain_trie);

    for (size_t i = 0; i < geo_list->n_entry; i++)
    {
        GeoSite *site = geo_list->entry[i];
        if(!site->country_code) continue;
        const char *cc = site->country_code;

        for (size_t j = 0; j < site->n_domain; j++)
        {
            Domain *d = site->domain[j];
            const char *domain = d->value;

            // 忽略空域名或正则规则
            if (!domain || d->type == DOMAIN__TYPE__Regex)
            {
                //currently not support regex, to do
                continue;
            }

            domain_trie_add(domain_trie, domain, cc);
        }
    }

    geo_site_list__free_unpacked(geo_list, NULL);
    munmap(data, st.st_size);
    close(fd);

    return 0;
}

void domain_trie_free(domain_trie_t *trie) {
    if(!trie) return;

    domain_trie_node_t *node;
    pool_foreach(node, trie->nodes) {
        u8 *key;
        uword value;

        /* iterate all entries and free keys */
        hash_foreach_mem(key, value, node->children, ({
                    vec_free(key);   // free key string
                    }));

        hash_free(node->children);
        vec_free(node->country_indices);
    }
    pool_free(trie->nodes);

    char **cc;
    pool_foreach(cc, trie->country_codes) {
        clib_mem_free(*cc);
    }
    pool_free(trie->country_codes);

    if (trie->country_code_index_by_str)
        hash_free(trie->country_code_index_by_str);
    clib_mem_free(trie);
}

