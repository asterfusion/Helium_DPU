/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <stddef.h>
#include <netinet/in.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/plugin/plugin.h>
#include <acl/acl.h>
#include <vppinfra/bihash_72_8.h>
#include <vppinfra/bihash_template.c>

#include "hash_lookup.h"
#include "hash_lookup_private.h"

/*
 * The applied ACE entries live in a fixed-size table shared by all
 * lookup contexts. The position of a rule depends only on the ACL number
 * and the rule number (acl_index*ACL_APPLIED_HASH_ACE_STRIDE + ace_index),
 * so it never changes when rules are added/removed/modified or when
 * ACLs are bound/unbound. The bihash values store positions within this
 * table and therefore never need to be rewritten because of a reorder.
 *
 * Rule push (hash_acl_add):       writes the entry; if the ACL is bound
 *                                 to at least one lc (lc_index_list
 *                                 non-empty), inserts the bihash entries.
 * Bind (hash_acl_apply):          does not touch the table; if the ACL
 *                                 was not bound to any lc before, inserts
 *                                 the bihash entries; otherwise nothing.
 * Unbind (hash_acl_unapply):      does not touch the table; if the ACL
 *                                 becomes bound to no lc at all, removes
 *                                 the bihash entries; otherwise nothing.
 * ACL delete (hash_acl_delete):   clears the table slots and removes the
 *                                 bihash entries.
 *
 * The bihash entries are shared across the lookup contexts: the key does
 * NOT include lc_index, the dataplane verifies the lc membership of the
 * matched rule after the lookup using the per-ACL lc_index_list.
 */

always_inline u32
ahace_index (u32 acl_index, u32 ace_index)
{
  ASSERT (acl_index < ACL_APPLIED_HASH_MAX_ACLS);
  ASSERT (ace_index < ACL_APPLIED_HASH_ACE_STRIDE);
  return acl_index * ACL_APPLIED_HASH_ACE_STRIDE + ace_index;
}

/*
 * The applied ACE table is two-level so that the memory is consumed
 * proportionally to the number of ACLs actually in use:
 * am->applied_hash_ace_table[acl_index] points to a slot of
 * ACL_APPLIED_HASH_ACE_STRIDE entries, allocated (and 0xff-filled, i.e.
 * all entries inactive) on the first use of that ACL index.
 */
static void
ahace_ensure_table (acl_main_t *am)
{
  if (PREDICT_TRUE (am->applied_hash_ace_table != 0))
    return;
  vec_validate (am->applied_hash_ace_table, ACL_APPLIED_HASH_MAX_ACLS - 1);
}

/*
 * Return the slot for acl_index, optionally allocating (and
 * marking inactive) it if it does not exist yet.
 */
static applied_hash_ace_entry_t *
ahace_get_slot (acl_main_t *am, u32 acl_index, int do_alloc)
{
  applied_hash_ace_entry_t *slot;

  if (acl_index >= ACL_APPLIED_HASH_MAX_ACLS)
    return 0;
  ahace_ensure_table (am);
  slot = am->applied_hash_ace_table[acl_index];
  if (!slot && do_alloc)
    {
      slot = clib_mem_alloc_aligned (ACL_APPLIED_HASH_ACE_STRIDE *
				     sizeof (applied_hash_ace_entry_t),
				     CLIB_CACHE_LINE_BYTES);
      clib_memset (slot, 0xff,
		   ACL_APPLIED_HASH_ACE_STRIDE * sizeof (applied_hash_ace_entry_t));
      am->applied_hash_ace_table[acl_index] = slot;
    }
  return slot;
}


/* Control-plane accessor: entry by its table position. The slot must exist. */
always_inline applied_hash_ace_entry_t *
ahace_entry_at (acl_main_t *am, u32 entry_index)
{
  applied_hash_ace_entry_t *slot =
    am->applied_hash_ace_table[entry_index / ACL_APPLIED_HASH_ACE_STRIDE];
  ASSERT (slot != 0);
  return &slot[entry_index % ACL_APPLIED_HASH_ACE_STRIDE];
}

static void
hashtable_add_del(acl_main_t *am, clib_bihash_kv_72_8_t *kv, int is_add)
{
    DBG("HASH ADD/DEL: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx add %d",
                        kv->key[0], kv->key[1], kv->key[2],
                        kv->key[3], kv->key[4], kv->key[5],
                        kv->key[6], kv->key[7], kv->key[8],kv->value, is_add);
    BV (clib_bihash_add_del) (&am->acl_lookup_hash, kv, is_add);
}

static u32
find_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
  ace_mask_type_entry_t *mte;
  /* *INDENT-OFF* */
  pool_foreach (mte, am->ace_mask_type_pool)
   {
    if(memcmp(&mte->mask, mask, sizeof(*mask)) == 0)
      return (mte - am->ace_mask_type_pool);
  }
  /* *INDENT-ON* */
  return ~0;
}

static u32
assign_mask_type_index(acl_main_t *am, fa_5tuple_t *mask)
{
  u32 mask_type_index = find_mask_type_index(am, mask);
  ace_mask_type_entry_t *mte;
  if(~0 == mask_type_index) {
    pool_get_aligned (am->ace_mask_type_pool, mte, CLIB_CACHE_LINE_BYTES);
    mask_type_index = mte - am->ace_mask_type_pool;
    clib_memcpy_fast(&mte->mask, mask, sizeof(mte->mask));
    mte->refcount = 0;

    /*
     * We can use only 16 bits, since in the match there is only u16 field.
     * Realistically, once you go to 64K of mask types, it is a huge
     * problem anyway, so we might as well stop half way.
     */
    ASSERT(mask_type_index < 32768);
  }
  mte = am->ace_mask_type_pool + mask_type_index;
  mte->refcount++;
  DBG0("ASSIGN MTE index %d new refcount %d", mask_type_index, mte->refcount);
  return mask_type_index;
}

static void
release_mask_type_index(acl_main_t *am, u32 mask_type_index)
{
  DBG0("RELEAS MTE index %d", mask_type_index);
  ace_mask_type_entry_t *mte = pool_elt_at_index(am->ace_mask_type_pool, mask_type_index);
  mte->refcount--;
  DBG0("RELEAS MTE index %d new refcount %d", mask_type_index, mte->refcount);
  if (mte->refcount == 0) {
    /* we are not using this entry anymore */
    clib_memset(mte, 0xae, sizeof(*mte));
    pool_put(am->ace_mask_type_pool, mte);
  }
}

static void
fill_applied_hash_ace_kv(acl_main_t *am,
                            u32 entry_index, clib_bihash_kv_72_8_t *kv)
{
  fa_5tuple_t *kv_key = (fa_5tuple_t *)kv->key;
  hash_acl_lookup_value_t *kv_val = (hash_acl_lookup_value_t *)&kv->value;
  applied_hash_ace_entry_t *pae = ahace_entry_at(am, entry_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, pae->acl_index);

  /* apply the base mask to ace key */
  hash_ace_info_t *ace_info = vec_elt_at_index(ha->rules, pae->hash_ace_info_index);
  ace_mask_type_entry_t *mte = vec_elt_at_index(am->ace_mask_type_pool, ace_info->base_mask_type_index);

  u64 *pmatch = (u64 *) &ace_info->match;
  u64 *pmask = (u64 *)&mte->mask;
  u64 *pkey = (u64 *)kv->key;

  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;
  *pkey++ = *pmatch++ & *pmask++;

  kv_key->pkt.mask_type_index_lsb = ace_info->base_mask_type_index;
  /* the entries are shared across the lookup contexts: no lc in the key */
  kv_key->pkt.lc_index = 0;
  kv_val->as_u64 = 0;
  kv_val->applied_entry_index = entry_index;
}

static void
add_del_hashtable_entry(acl_main_t *am, u32 entry_index, int is_add)
{
  clib_bihash_kv_72_8_t kv;

  fill_applied_hash_ace_kv(am, entry_index, &kv);
  hashtable_add_del(am, &kv, is_add);
}

/*
 * Rebuild the per-lc list of the distinct mask types of the rules of
 * the ACLs applied to that lc. This is only the list of masks to try
 * during the lookup, the order no longer carries any priority meaning
 * (the priority is decided via acl_priority_by_lc at the match time).
 */
static void
rebuild_lc_mask_info_vec (acl_main_t * am, u32 lc_index)
{
  hash_applied_mask_info_t *new_vec = 0;
  applied_hash_acl_info_t *pal;

  if (lc_index >= vec_len (am->applied_hash_acl_info_by_lc_index))
    return;
  pal = vec_elt_at_index (am->applied_hash_acl_info_by_lc_index, lc_index);

  u32 *acl_index;
  vec_foreach (acl_index, pal->applied_acls)
    {
      if (*acl_index >= vec_len (am->hash_acl_infos))
	continue;
      hash_acl_info_t *ha = vec_elt_at_index (am->hash_acl_infos, *acl_index);
      hash_ace_info_t *rule;
      vec_foreach (rule, ha->rules)
	{
	  u32 mt_index = rule->base_mask_type_index;
	  u32 i;
	  u32 n = vec_len (new_vec);
	  for (i = 0; i < n; i++)
	    if (new_vec[i].mask_type_index == mt_index)
	      break;
	  if (i == n)
	    {
	      hash_applied_mask_info_t minfo;
	      clib_memset (&minfo, 0, sizeof (minfo));
	      minfo.mask_type_index = mt_index;
	      minfo.first_rule_index = 0;
	      vec_add1 (new_vec, minfo);
	    }
	  new_vec[i].num_entries++;
	}
    }

  vec_validate (am->hash_applied_mask_info_vec_by_lc_index, lc_index);
  vec_free (am->hash_applied_mask_info_vec_by_lc_index[lc_index]);
  am->hash_applied_mask_info_vec_by_lc_index[lc_index] = new_vec;
}

static void
vec_del_collision_rule (collision_match_rule_t ** pvec,
                        u32 applied_entry_index)
{
  u32 i = 0;
  u32 deleted = 0;
  while (i < _vec_len ((*pvec)))
    {
      collision_match_rule_t *cr = vec_elt_at_index ((*pvec), i);
      if (cr->applied_entry_index == applied_entry_index)
        {
          /* vec_del1 ((*pvec), i) would be more efficient but would reorder the elements. */
          vec_delete((*pvec), 1, i);
          deleted++;
          DBG0("vec_del_collision_rule deleting one at index %d", i);
        }
      else
        {
          i++;
        }
    }
  ASSERT(deleted > 0);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae);

static void
del_colliding_rule (acl_main_t * am,
                    u32 head_index, u32 applied_entry_index)
{
  DBG0("DEL COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);

  applied_hash_ace_entry_t *head_pae =
    ahace_entry_at (am, head_index);
  vec_del_collision_rule (&head_pae->colliding_rules, applied_entry_index);
}

static void
add_colliding_rule (acl_main_t * am,
                    u32 head_index, u32 applied_entry_index)
{
  applied_hash_ace_entry_t *head_pae =
    ahace_entry_at (am, head_index);
  applied_hash_ace_entry_t *pae =
    ahace_entry_at (am, applied_entry_index);
  DBG0("ADD COLLIDING RULE: head_index %d applied index %d", head_index, applied_entry_index);

  collision_match_rule_t cr;

  cr.acl_index = pae->acl_index;
  cr.ace_index = pae->ace_index;
  cr.acl_position = pae->acl_position;
  cr.applied_entry_index = applied_entry_index;
  cr.rule = am->acls[pae->acl_index].rules[pae->ace_index];
  pae->collision_head_ae_index = head_index;
  vec_add1 (head_pae->colliding_rules, cr);
}

/*
 * Activate an entry: insert the bihash entry if we are the first
 * for this key, otherwise append ourselves to the collision chain
 * of the existing head entry.
 */
static u32
activate_applied_ace_hash_entry(acl_main_t *am, u32 entry_index)
{
  clib_bihash_kv_72_8_t kv;
  clib_bihash_kv_72_8_t result;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *)&result.value;
  applied_hash_ace_entry_t *pae = ahace_entry_at(am, entry_index);

  ASSERT(pae->collision_head_ae_index == ~0);
  DBG("activate_applied_ace_hash_entry entry_index %d", entry_index);

  fill_applied_hash_ace_kv(am, entry_index, &kv);

  int res = BV (clib_bihash_search) (&am->acl_lookup_hash, &kv, &result);
  if (res == 0) {
    u32 head_index = result_val->applied_entry_index;
    ASSERT(head_index != ~0);
    /* There already exists an entry or more. Append at the end. */
    DBG("A key already exists, with applied entry index: %d", head_index);
    add_colliding_rule(am, head_index, entry_index);
    return head_index;
  } else {
    /* It's the very first entry */
    hashtable_add_del(am, &kv, 1);
    add_colliding_rule(am, entry_index, entry_index);
    return entry_index;
  }
}

static void
set_collision_head_ae_index(acl_main_t *am, collision_match_rule_t *colliding_rules, u32 new_index)
{
	collision_match_rule_t *cr;
	vec_foreach(cr, colliding_rules) {
            applied_hash_ace_entry_t *pae = ahace_entry_at(am, cr->applied_entry_index);
            pae->collision_head_ae_index = new_index;
	}
}

/*
 * Deactivate an entry: remove ourselves from the collision chain of
 * the head entry; if we are the head, either transfer the headship
 * (and the bihash entry) to the next collision or delete the bihash
 * entry outright. The mask type refcount is owned by the hash_acl_info
 * rules, so it is not released here.
 */
static void
deactivate_applied_ace_hash_entry(acl_main_t *am, u32 entry_index)
{
  applied_hash_ace_entry_t *pae = ahace_entry_at(am, entry_index);
  DBG("UNAPPLY DEACTIVATE: entry index %d", entry_index);

  if (pae->collision_head_ae_index == ~0)
    return;

  if (pae->collision_head_ae_index != entry_index) {
    DBG("UNAPPLY = index %d has collision head %d", entry_index, pae->collision_head_ae_index);

    u32 head_index = pae->collision_head_ae_index;
    del_colliding_rule(am, head_index, entry_index);
  } else {
    /* It was the first entry. We need either to reset the hash entry or delete it */
    /* delete our entry from the collision vector first */
    del_colliding_rule(am, entry_index, entry_index);
    if (vec_len(pae->colliding_rules) > 0) {
      u32 next_entry_index = pae->colliding_rules[0].applied_entry_index;
      applied_hash_ace_entry_t *next_pae = ahace_entry_at(am, next_entry_index);
      /* Remove ourselves and transfer the ownership of the colliding rules vector */
      next_pae->colliding_rules = pae->colliding_rules;
      set_collision_head_ae_index(am, next_pae->colliding_rules, next_entry_index);
      add_del_hashtable_entry(am, next_entry_index, 1);
      pae->colliding_rules = NULL;
    } else {
      /* no next entry, so just delete the entry in the hash table */
      add_del_hashtable_entry(am, entry_index, 0);
      vec_free(pae->colliding_rules);
    }
  }
  /* invalidate the old entry */
  pae->collision_head_ae_index = ~0;
  /* always has to be 0 */
  pae->colliding_rules = NULL;
}

/*
 * Apply the ACL to the lookup context.
 *
 * The applied ACE entries themselves are NOT touched here - they were
 * written at the rule push time (hash_acl_add). We only:
 * - update the binding lists (per-lc applied ACLs, per-ACL lc list),
 * - remember the (lc, acl) priority in acl_priority_by_lc,
 * - if the ACL was not bound to any lc before, insert its entries
 *   into the bihash,
 * - rebuild the per-lc mask list.
 */
void
hash_acl_apply(acl_main_t *am, u32 lc_index, int acl_index, u32 acl_position)
{
  int i;
  int res = 0;
  clib_bihash_kv_8_8_t key;
  clib_bihash_kv_8_8_t kv_result;

  DBG0("HASH ACL apply: lc_index %d acl %d", lc_index, acl_index);
  if (!am->acl_lookup_hash_initialized) {
    BV (clib_bihash_init) (&am->acl_lookup_hash, "ACL plugin rule lookup bihash",
                           am->hash_lookup_hash_buckets, am->hash_lookup_hash_memory);
    am->acl_lookup_hash_initialized = 1;
  }
  ahace_ensure_table(am);

  clib_memset(&key, 0, sizeof(clib_bihash_kv_8_8_t));
  clib_memset(&kv_result, 0, sizeof(clib_bihash_kv_8_8_t));
  key.key = ((u64)lc_index << 32) | acl_index;
  res = clib_bihash_search_inline_2_8_8(&am->sw_acl_index_priority_hash, &key, &kv_result);

  vec_validate(am->hash_acl_infos, acl_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  vec_validate((*applied_hash_acls), lc_index);
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  /* ensure the list of applied hash acls is initialized and add this acl# to it */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    ASSERT(0);
    return;
  }
  vec_add1(pal->applied_acls, acl_index);
  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 != ~0) {
    clib_warning("BUG: trying to apply twice acl_index %d on lc_index %d, according to hash h-acl info",
                 acl_index, lc_index);
    ASSERT(0);
    return;
  }
  vec_add1((*hash_acl_applied_lc_index), lc_index);

  /* store the (lc,acl) priority, so that later changes of it do not
     require re-pushing the rules */
  if (acl_index < ACL_APPLIED_HASH_MAX_ACLS) {
    u16 priority = (res == 0) ? (uint16_t)kv_result.value : 0;
    vec_validate(am->acl_priority_by_lc,
                 ((u64)(lc_index + 1) * ACL_APPLIED_HASH_MAX_ACLS) - 1);
    am->acl_priority_by_lc[(u64)lc_index * ACL_APPLIED_HASH_MAX_ACLS + acl_index] = priority;
  }

  /*
   * if the applied ACL is empty, the current code will cause a
   * different behavior compared to current linear search: an empty ACL will
   * simply fallthrough to the next ACL, or the default deny in the end.
   *
   * This is not a problem, because after vpp-dev discussion,
   * the consensus was it should not be possible to apply the non-existent
   * ACL, so the change adding this code also takes care of that.
   */
  int first_bind = (vec_len(*hash_acl_applied_lc_index) == 1);
  if (first_bind && ha->hash_acl_exists &&
      (acl_index < ACL_APPLIED_HASH_MAX_ACLS)) {
    /* the ACL was not bound to any lc before: insert its rules into the bihash */
    for(i=0; i < vec_len(ha->rules); i++) {
      activate_applied_ace_hash_entry(am, ahace_index(acl_index, i));
    }
  }

  /* update the list of the mask types to try during the lookup */
  rebuild_lc_mask_info_vec(am, lc_index);
}

/*
 * Remove the ACL from the lookup context.
 *
 * The applied ACE entries themselves are NOT touched here. We only:
 * - update the binding lists,
 * - clear the (lc, acl) priority,
 * - if the ACL becomes bound to no lc at all, remove its entries
 *   from the bihash,
 * - rebuild the per-lc mask list.
 */
void
hash_acl_unapply(acl_main_t *am, u32 lc_index, int acl_index)
{
  int i;

  DBG0("HASH ACL unapply: lc_index %d acl %d", lc_index, acl_index);
  applied_hash_acl_info_t **applied_hash_acls = &am->applied_hash_acl_info_by_lc_index;
  applied_hash_acl_info_t *pal = vec_elt_at_index((*applied_hash_acls), lc_index);

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  u32 **hash_acl_applied_lc_index = &ha->lc_index_list;

  /* remove this acl# from the list of applied hash acls */
  u32 index = vec_search(pal->applied_acls, acl_index);
  if (index == ~0) {
    clib_warning("BUG: trying to unapply unapplied acl_index %d on lc_index %d, according to lc",
                 acl_index, lc_index);
    return;
  }
  vec_del1(pal->applied_acls, index);

  u32 index2 = vec_search((*hash_acl_applied_lc_index), lc_index);
  if (index2 == ~0) {
    clib_warning("BUG: trying to unapply twice acl_index %d on lc_index %d, according to h-acl info",
                 acl_index, lc_index);
    return;
  }
  vec_del1((*hash_acl_applied_lc_index), index2);

  /* clear the (lc,acl) priority */
  if (acl_index < ACL_APPLIED_HASH_MAX_ACLS) {
    u64 prio_index = (u64)lc_index * ACL_APPLIED_HASH_MAX_ACLS + acl_index;
    if (prio_index < vec_len(am->acl_priority_by_lc))
      am->acl_priority_by_lc[prio_index] = 0;
  }

  /* if the ACL is not bound to any lc anymore, remove its rules from the bihash */
  if ((vec_len(*hash_acl_applied_lc_index) == 0) && ha->hash_acl_exists &&
      (acl_index < ACL_APPLIED_HASH_MAX_ACLS) &&
      (am->applied_hash_ace_table != 0)) {
    for(i=0; i < vec_len(ha->rules); i ++) {
      deactivate_applied_ace_hash_entry(am, ahace_index(acl_index, i));
    }
  }

  rebuild_lc_mask_info_vec(am, lc_index);
}

static void
make_ip6_address_mask(ip6_address_t *addr, u8 prefix_len)
{
  ip6_address_mask_from_width(addr, prefix_len);
}


/* Maybe should be moved into the core somewhere */
always_inline void
ip4_address_mask_from_width (ip4_address_t * a, u32 width)
{
  int i, byte, bit, bitnum;
  ASSERT (width <= 32);
  clib_memset (a, 0, sizeof (a[0]));
  for (i = 0; i < width; i++)
    {
      bitnum = (7 - (i & 7));
      byte = i / 8;
      bit = 1 << bitnum;
      a->as_u8[byte] |= bit;
    }
}


static void
make_ip4_address_mask(ip4_address_t *addr, u8 prefix_len)
{
  ip4_address_mask_from_width(addr, prefix_len);
}

static void
make_port_mask(u16 *portmask, u16 port_first, u16 port_last)
{
  if (port_first == port_last) {
    *portmask = 0xffff;
    /* single port is representable by masked value */
    return;
  }

  *portmask = 0;
  return;
}

static void
make_mask_and_match_from_rule(fa_5tuple_t *mask, acl_rule_t *r, hash_ace_info_t *hi)
{
  clib_memset(mask, 0, sizeof(*mask));
  clib_memset(&hi->match, 0, sizeof(hi->match));
  hi->action = r->is_permit;

  hi->action_expand_bitmap = r->action_expand_bitmap;
  hi->policer_index = r->policer_index;
  hi->set_tc_value = r->set_tc_value;
  hi->set_hqos_user_id = r->set_hqos_user_id;
  hi->set_hqos_guser_id = r->set_hqos_guser_id;

  /* we will need to be matching based on lc_index and mask_type_index when applied */
  mask->pkt.lc_index = ~0;
  /* we will assign the match of mask_type_index later when we find it*/
  mask->pkt.mask_type_index_lsb = ~0;

  mask->pkt.is_ip6 = 1;
  hi->match.pkt.is_ip6 = r->is_ipv6;
  
  if (r->is_ipv6) {
    clib_memset(hi->match.l3_zero_pad_1, 0, sizeof(u8) * 3);
    if (r->src_mac_len != 0)
    {
        clib_memcpy(&hi->match.mac6_addr[0], r->src_mac, 6);
        for (int i = 0; i < r->src_mac_len; i++)
        {
            mask->mac6_addr[0].bytes[i] = 0xff;
        }
    }

    if (r->dst_mac_len != 0)
    {
        clib_memcpy(&hi->match.mac6_addr[1], r->dst_mac, 6);
        for (int i = 0; i < r->src_mac_len; i++)
        {
            mask->mac6_addr[1].bytes[i] = 0xff;
        }
    }
    make_ip6_address_mask(&mask->ip6_addr[0], r->src_prefixlen);
    hi->match.ip6_addr[0] = r->src.ip6;
    make_ip6_address_mask(&mask->ip6_addr[1], r->dst_prefixlen);
    hi->match.ip6_addr[1] = r->dst.ip6;
    if (r->dscp != 0xff)
    {
        mask->dscp_v6 = ~0;
        hi->match.dscp_v6 = r->dscp;
    }
  } else {
    clib_memset(hi->match.l3_zero_pad, 0, sizeof(u8) * 27);
    if (r->src_mac_len != 0)
    {
        clib_memcpy(&hi->match.mac4_addr[0], r->src_mac, 6);
        for (int i = 0; i < r->src_mac_len; i++)
        {
            mask->mac4_addr[0].bytes[i] = 0xff;
        }
    }

    if (r->dst_mac_len != 0)
    {
        clib_memcpy(&hi->match.mac4_addr[1], r->dst_mac, 6);
        for (int i = 0; i < r->src_mac_len; i++)
        {
            mask->mac4_addr[1].bytes[i] = 0xff;
        }
    }
    make_ip4_address_mask(&mask->ip4_addr[0], r->src_prefixlen);
    hi->match.ip4_addr[0] = r->src.ip4;
    make_ip4_address_mask(&mask->ip4_addr[1], r->dst_prefixlen);
    hi->match.ip4_addr[1] = r->dst.ip4;
    if (r->dscp != 0xff)
    {
        mask->dscp_v4 = ~0;
        hi->match.dscp_v4 = r->dscp;
    }
  }

  if (r->src_sw_if_index != 0) {
      mask->src_sw_if_index = ~0;
      hi->match.src_sw_if_index = r->src_sw_if_index;
  }

  if (r->geosite_cc_index != 0xffff) {
      mask->geosite_cc_index = ~0;
      hi->match.geosite_cc_index = r->geosite_cc_index;
  }
    if (r->geoip_cc_index != 0xffff) {
      mask->geoip_cc_index = ~0;
      hi->match.geoip_cc_index = r->geoip_cc_index;
  }
  if (r->proto != 0) {
    mask->l4.proto = ~0; /* L4 proto needs to be matched */
    hi->match.l4.proto = r->proto;

    /* Calculate the src/dst port masks and make the src/dst port matches accordingly */
    make_port_mask(&mask->l4.port[0], r->src_port_or_type_first, r->src_port_or_type_last);
    hi->match.l4.port[0] = r->src_port_or_type_first & mask->l4.port[0];

    make_port_mask(&mask->l4.port[1], r->dst_port_or_code_first, r->dst_port_or_code_last);
    hi->match.l4.port[1] = r->dst_port_or_code_first & mask->l4.port[1];
    /* L4 info must be valid in order to match */
    mask->pkt.l4_valid = 1;
    hi->match.pkt.l4_valid = 1;
    /* And we must set the mask to check that it is an initial fragment */
    mask->pkt.is_nonfirst_fragment = 1;
    hi->match.pkt.is_nonfirst_fragment = 0;
    if ((r->proto == IPPROTO_TCP) && (r->tcp_flags_mask != 0)) {
      /* if we want to match on TCP flags, they must be masked off as well */
      mask->pkt.tcp_flags = r->tcp_flags_mask;
      hi->match.pkt.tcp_flags = r->tcp_flags_value;
      /* and the flags need to be present within the packet being matched */
      mask->pkt.tcp_flags_valid = 1;
      hi->match.pkt.tcp_flags_valid = 1;
    }
  }
  /* Sanitize the mask and the match */
  u64 *pmask = (u64 *)mask;
  u64 *pmatch = (u64 *)&hi->match;
  int j;
  for(j=0; j<9; j++) {
    pmatch[j] = pmatch[j] & pmask[j];
  }
}

int hash_acl_exists(acl_main_t *am, int acl_index)
{
  if (acl_index >= vec_len(am->hash_acl_infos))
    return 0;

  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  return ha->hash_acl_exists;
}

/*
 * Push the rules of the ACL into the applied ACE table at the fixed
 * positions acl_index*ACL_APPLIED_HASH_ACE_STRIDE + ace_index.
 * The bihash is not touched unless the ACL is bound to at least one
 * lc (lc_index_list non-empty) - in that case the entries are
 * activated (inserted into the bihash).
 */
void hash_acl_add(acl_main_t *am, int acl_index)
{
  DBG("HASH ACL add : %d", acl_index);
  int i;
  acl_rule_t *acl_rules = am->acls[acl_index].rules;
  vec_validate(am->hash_acl_infos, acl_index);
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  clib_memset(ha, 0, sizeof(*ha));
  ha->hash_acl_exists = 1;

  if (acl_index >= ACL_APPLIED_HASH_MAX_ACLS) {
    clib_warning("acl-plugin-error: ACL %d exceeds the maximum of %d ACLs supported by the hash lookup",
                 acl_index, ACL_APPLIED_HASH_MAX_ACLS);
  }

  /* walk the newly added ACL entries and ensure that for each of them there
     is a mask type, increment a reference count for that mask type */

  /* avoid small requests by preallocating the entire vector before running the additions */
  if (vec_len(acl_rules) > 0) {
    vec_validate(ha->rules, vec_len(acl_rules)-1);
    vec_reset_length(ha->rules);
  }

  ahace_ensure_table(am);

  applied_hash_ace_entry_t *slot = 0;
  if (acl_index < ACL_APPLIED_HASH_MAX_ACLS)
    /* allocate (and mark inactive) the slot on its first use */
    slot = ahace_get_slot(am, acl_index, 1);

  for(i=0; i < vec_len(acl_rules); i++) {
    hash_ace_info_t ace_info;
    fa_5tuple_t mask;
    clib_memset(&ace_info, 0, sizeof(ace_info));
    ace_info.acl_index = acl_index;
    ace_info.ace_index = i;

    make_mask_and_match_from_rule(&mask, &acl_rules[i], &ace_info);
    mask.pkt.flags_reserved = 0b000;
    ace_info.base_mask_type_index = assign_mask_type_index(am, &mask);
    /* assign the mask type index for matching itself */
    ace_info.match.pkt.mask_type_index_lsb = ace_info.base_mask_type_index;
    DBG("ACE: %d mask_type_index: %d", i, ace_info.base_mask_type_index);

    if (slot) {
      /* write the applied ACE entry at its fixed position */
      applied_hash_ace_entry_t *pae = &slot[i];
      pae->acl_index = acl_index;
      pae->ace_index = i;
      pae->hash_ace_info_index = i;
      pae->mask_type_index = ace_info.base_mask_type_index;
      pae->collision_head_ae_index = ~0;
      pae->colliding_rules = NULL;
      pae->hitcount = 0;
      pae->acl_position = 0;
      pae->action = ace_info.action;
      pae->action_expand_bitmap = ace_info.action_expand_bitmap;
      pae->policer_index = ace_info.policer_index;
      pae->set_tc_value = ace_info.set_tc_value;
      pae->set_hqos_user_id = ace_info.set_hqos_user_id;
      pae->set_hqos_guser_id = ace_info.set_hqos_guser_id;
      pae->priority = 0;
    }
    vec_add1(ha->rules, ace_info);
  }

  /*
   * if an ACL is applied somewhere (lc_index_list non-empty),
   * insert the entries into the bihash and refresh the per-lc mask lists.
   */
  if (acl_index < vec_len(am->lc_index_vec_by_acl)) {
    ha->lc_index_list = vec_dup(am->lc_index_vec_by_acl[acl_index]);
  }
  if ((vec_len(ha->lc_index_list) > 0) &&
      (acl_index < ACL_APPLIED_HASH_MAX_ACLS)) {
    for(i=0; i < vec_len(ha->rules); i++) {
      activate_applied_ace_hash_entry(am, ahace_index(acl_index, i));
    }
    u32 *lc_index;
    vec_foreach(lc_index, ha->lc_index_list) {
      rebuild_lc_mask_info_vec(am, *lc_index);
    }
  }
}

/*
 * Delete the ACL: remove the bihash entries of its rules (if it is
 * still bound somewhere, which normally only happens during the
 * delete+add of an acl_add_replace), release the mask type references,
 * and clear the applied ACE table slots.
 */
void hash_acl_delete(acl_main_t *am, int acl_index)
{
  DBG0("HASH ACL delete : %d", acl_index);
  /*
   * This routine is called in process of reapplication
   * during the acl_add_replace() API call - the old acl ruleset is deleted,
   * then the new one is added, without the change in the applied ACLs -
   * so this case has to be handled (the ACL may still be bound to lcs here).
   */
  hash_acl_info_t *ha = vec_elt_at_index(am->hash_acl_infos, acl_index);
  int n_rules = vec_len(ha->rules);
  int i;

  /* if the ACL rules are active in the bihash, remove them */
  if ((vec_len(ha->lc_index_list) > 0) && ha->hash_acl_exists &&
      (acl_index < ACL_APPLIED_HASH_MAX_ACLS) &&
      (am->applied_hash_ace_table != 0)) {
    for (i = 0; i < n_rules; i++) {
      deactivate_applied_ace_hash_entry(am, ahace_index(acl_index, i));
    }
  }
  vec_free(ha->lc_index_list);
  ha->lc_index_list = 0;

  /* walk the mask types for the ACL about-to-be-deleted, and decrease
   * the reference count, possibly freeing up some of them */
  for(i=0; i < n_rules; i++) {
    release_mask_type_index(am, ha->rules[i].base_mask_type_index);
  }

  if ((acl_index < ACL_APPLIED_HASH_MAX_ACLS) &&
      (am->applied_hash_ace_table != 0) &&
      (am->applied_hash_ace_table[acl_index] != 0)) {
    clib_mem_free (am->applied_hash_ace_table[acl_index]);
    am->applied_hash_ace_table[acl_index] = 0;
  }

  ha->hash_acl_exists = 0;
  vec_free(ha->rules);
}


void
show_hash_acl_hash (vlib_main_t * vm, acl_main_t *am, u32 verbose)
{
  vlib_cli_output(vm, "\nACL lookup hash table:\n%U\n",
                  BV (format_bihash), &am->acl_lookup_hash, verbose);
}

void
acl_plugin_show_tables_mask_type (void)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  ace_mask_type_entry_t *mte;

  vlib_cli_output (vm, "Mask-type entries:");
    /* *INDENT-OFF* */
    pool_foreach (mte, am->ace_mask_type_pool)
     {
      vlib_cli_output(vm, "     %3d: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx  refcount %d",
		    mte - am->ace_mask_type_pool,
		    mte->mask.kv_64_8.key[0], mte->mask.kv_64_8.key[1], mte->mask.kv_64_8.key[2],
		    mte->mask.kv_64_8.key[3], mte->mask.kv_64_8.key[4], mte->mask.kv_64_8.key[5],
		    mte->mask.kv_64_8.key[6], mte->mask.kv_64_8.key[7],mte->mask.kv_64_8.value, mte->refcount);
    }
    /* *INDENT-ON* */
}

void
acl_plugin_show_tables_acl_hash_info (u32 acl_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 i, j;
  u64 *m;
  vlib_cli_output (vm, "Mask-ready ACL representations\n");
  for (i = 0; i < vec_len (am->hash_acl_infos); i++)
    {
      if ((acl_index != ~0) && (acl_index != i))
	{
	  continue;
	}
      hash_acl_info_t *ha = &am->hash_acl_infos[i];
      vlib_cli_output (vm, "acl-index %u bitmask-ready layout\n", i);
      vlib_cli_output (vm, "  applied lc_index list: %U\n",
		       format_vec32, ha->lc_index_list, "%d");
      for (j = 0; j < vec_len (ha->rules); j++)
	{
	  hash_ace_info_t *pa = &ha->rules[j];
	  m = (u64 *) & pa->match;
	  vlib_cli_output (vm,
			   "    %4d: %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx base mask index %d acl %d rule %d action %d\n",
			   j, m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8],
			   pa->base_mask_type_index, pa->acl_index, pa->ace_index,
			   pa->action);
	}
    }
}

static void
acl_plugin_print_colliding_rule (vlib_main_t * vm, int j, collision_match_rule_t *cr) {
  vlib_cli_output(vm,
                  "        %4d: acl %d ace %d acl pos %d pae index: %d",
                  j, cr->acl_index, cr->ace_index, cr->acl_position, cr->applied_entry_index);
}

static void
acl_plugin_print_pae (vlib_main_t * vm, int j, applied_hash_ace_entry_t * pae)
{
  vlib_cli_output (vm,
		   "    %4d: acl %d rule %d action %d bitmask-ready rule %d mask type index: %d colliding_rules: %d collision_head_ae_idx %d hitcount %lld acl_pos: %d",
		   j, pae->acl_index, pae->ace_index, pae->action,
		   pae->hash_ace_info_index, pae->mask_type_index, vec_len(pae->colliding_rules), pae->collision_head_ae_index,
		   pae->hitcount, pae->acl_position);
  int jj;
  for(jj=0; jj<vec_len(pae->colliding_rules); jj++)
    acl_plugin_print_colliding_rule(vm, jj, vec_elt_at_index(pae->colliding_rules, jj));
}

static void
acl_plugin_print_applied_mask_info (vlib_main_t * vm, int j, hash_applied_mask_info_t *mi)
{
  vlib_cli_output (vm,
		   "    %4d: mask type index %d first rule index %d num_entries %d max_collisions %d",
		   j, mi->mask_type_index, mi->first_rule_index, mi->num_entries, mi->max_collisions);
}

void
acl_plugin_show_tables_applied_info (u32 lc_index)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  u32 lci, j;
  vlib_cli_output (vm, "Applied lookup entries for lookup contexts");

  for (lci = 0;
       (lci < vec_len(am->applied_hash_acl_info_by_lc_index)); lci++)
    {
      if ((lc_index != ~0) && (lc_index != lci))
	{
	  continue;
	}
      vlib_cli_output (vm, "lc_index %d:", lci);
      applied_hash_acl_info_t *pal =
	&am->applied_hash_acl_info_by_lc_index[lci];
      vlib_cli_output (vm, "  applied acls: %U", format_vec32,
		       pal->applied_acls, "%d");
      if (lci < vec_len (am->hash_applied_mask_info_vec_by_lc_index))
	{
	  vlib_cli_output (vm, "  applied mask info entries:");
	  for (j = 0;
	       j < vec_len (am->hash_applied_mask_info_vec_by_lc_index[lci]);
	       j++)
	    {
	      acl_plugin_print_applied_mask_info (vm, j,
				    &am->hash_applied_mask_info_vec_by_lc_index
				    [lci][j]);
	    }
	}
      if (am->applied_hash_ace_table != 0)
	{
	  u32 *acl_index;
	  vlib_cli_output (vm, "  lookup applied entries:");
	  vec_foreach (acl_index, pal->applied_acls)
	    {
	      if (*acl_index >= vec_len (am->hash_acl_infos))
		continue;
	      hash_acl_info_t *ha = &am->hash_acl_infos[*acl_index];
	      applied_hash_ace_entry_t *slot =
		ahace_get_slot (am, *acl_index, 0);
	      if (!slot)
		continue;
	      for (j = 0; j < vec_len (ha->rules); j++)
		{
		  acl_plugin_print_pae (vm, ahace_index (*acl_index, j), &slot[j]);
		}
	    }
	}
    }
}

void
acl_plugin_show_tables_bihash (u32 show_bihash_verbose)
{
  acl_main_t *am = &acl_main;
  vlib_main_t *vm = am->vlib_main;
  show_hash_acl_hash (vm, am, show_bihash_verbose);
}
