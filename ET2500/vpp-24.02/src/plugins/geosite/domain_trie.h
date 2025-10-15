
/*
 * domain_trie.h - skeleton vpp engine plug-in header file
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
#ifndef __included_domain_trie_h__
#define __included_domain_trie_h__

#include <vppinfra/clib.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/lock.h>

typedef struct {
    uword *children;           // hash map: label -> child index
    u32 *country_indices;      // index into global country code pool
    u8 is_terminal;
} domain_trie_node_t;

typedef struct {
    clib_spinlock_t lock;
    domain_trie_node_t *nodes; // pool of trie nodes
    char **country_codes;      // pool of country code strings
    uword *country_code_index_by_str;    // hash table: cc string -> index
    //stats
    u32 domain_counts;
} domain_trie_t;

void domain_trie_init(domain_trie_t *trie);
void domain_trie_add(domain_trie_t *trie, const char *domain, const char *country_code);
u32 *domain_trie_match(domain_trie_t *trie, const char *domain);
void domain_trie_free(domain_trie_t *trie);
int load_geosite_dat(const char *filename, domain_trie_t *domain_trie);

#endif
