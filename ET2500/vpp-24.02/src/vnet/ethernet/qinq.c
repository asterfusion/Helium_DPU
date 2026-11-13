/*
 * Copyright (c) 2026 Asterfusion Networks
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vnet/ethernet/qinq.h>
#include <vnet/ethernet/ethernet.h>

qinq_main_t qinq_main;

static_always_inline void
qinq_domain_key_init (clib_bihash_kv_16_8_t *kv, u32 parent_sw_if_index,
                      u16 outer_tpid, u16 outer_vlan, u16 inner_tpid)
{
  kv->key[0] = ((u64) parent_sw_if_index << 32) |
               ((u64) outer_tpid << 16) | inner_tpid;
  kv->key[1] = outer_vlan;
}

static qinq_match_group_t *
qinq_group_find (u32 parent_sw_if_index, u16 outer_tpid, u16 outer_vlan,
                 u16 inner_tpid, u32 *group_index)
{
  qinq_main_t *qm = &qinq_main;
  clib_bihash_kv_16_8_t kv = {};

  qinq_domain_key_init (&kv, parent_sw_if_index, outer_tpid, outer_vlan,
                        inner_tpid);
  if (clib_bihash_search_16_8 (&qm->group_by_domain, &kv, &kv) != 0)
    return 0;

  if (pool_is_free_index (qm->groups, kv.value))
    return 0;

  if (group_index)
    *group_index = kv.value;

  return pool_elt_at_index (qm->groups, kv.value);
}

static qinq_match_group_t *
qinq_group_get_or_create (const qinq_subport_t *config, u32 *group_index)
{
  qinq_main_t *qm = &qinq_main;
  qinq_match_group_t *group;
  clib_bihash_kv_16_8_t kv = {};

  group = qinq_group_find (config->parent_sw_if_index, config->outer_tpid,
                           config->outer_vlan, config->inner_tpid,
                           group_index);
  if (group)
    return group;

  pool_get_zero (qm->groups, group);
  group->parent_sw_if_index = config->parent_sw_if_index;
  group->outer_tpid = config->outer_tpid;
  group->outer_vlan = config->outer_vlan;
  group->inner_tpid = config->inner_tpid;
  group->any_rule_index = ~0;
  *group_index = group - qm->groups;

  qinq_domain_key_init (&kv, config->parent_sw_if_index, config->outer_tpid,
                        config->outer_vlan, config->inner_tpid);
  kv.value = *group_index;
  clib_bihash_add_del_16_8 (&qm->group_by_domain, &kv, 1);

  return group;
}

static void
qinq_group_destroy (qinq_match_group_t *group, u32 group_index)
{
  qinq_main_t *qm = &qinq_main;
  clib_bihash_kv_16_8_t kv = {};

  qinq_domain_key_init (&kv, group->parent_sw_if_index, group->outer_tpid,
                        group->outer_vlan, group->inner_tpid);
  clib_bihash_add_del_16_8 (&qm->group_by_domain, &kv, 0);
  hash_free (group->exact_by_vlan);
  vec_free (group->ranges);
  pool_put_index (qm->groups, group_index);
}

static int
qinq_range_compare (void *a1, void *a2)
{
  qinq_vlan_range_t *r1 = a1;
  qinq_vlan_range_t *r2 = a2;
  u16 width1 = r1->last - r1->first;
  u16 width2 = r2->last - r2->first;

  if (width1 != width2)
    return width1 < width2 ? -1 : 1;
  if (r1->first != r2->first)
    return r1->first < r2->first ? -1 : 1;
  return 0;
}

static qinq_error_t
qinq_config_validate (const qinq_subport_t *config, u32 replaced_rule_index)
{
  qinq_main_t *qm = &qinq_main;
  vnet_interface_main_t *im = &qm->vnet_main->interface_main;
  vnet_sw_interface_t *sw;
  qinq_match_group_t *group;
  uword *p;
  u32 i;

  if (!config || config->rule_id == ~0 || config->sw_if_index == ~0 ||
      config->parent_sw_if_index == ~0)
    {
      if (!config)
        clib_warning ("qinq config validation failed: null config");
      else
        clib_warning (
          "qinq config validation failed: invalid identifier "
          "rule_id %u sw_if_index %u parent_sw_if_index %u",
          config->rule_id, config->sw_if_index,
          config->parent_sw_if_index);
      return QINQ_ERROR_INVALID_ARGUMENT;
    }

  if (pool_is_free_index (im->sw_interfaces, config->sw_if_index))
    return QINQ_ERROR_INVALID_INTERFACE;
  if (pool_is_free_index (im->sw_interfaces, config->parent_sw_if_index))
    return QINQ_ERROR_INVALID_PARENT;

  sw = vnet_get_sw_interface (qm->vnet_main, config->sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_SUB ||
      !sw->sub.eth.flags.qinq_carrier ||
      sw->sup_sw_if_index != config->parent_sw_if_index)
    return QINQ_ERROR_INVALID_PARENT;

  if (config->outer_tpid != ETHERNET_TYPE_VLAN &&
      config->outer_tpid != ETHERNET_TYPE_DOT1AD)
    return QINQ_ERROR_INVALID_TPID;
  if (config->inner_tpid != ETHERNET_TYPE_VLAN &&
      config->inner_tpid != ETHERNET_TYPE_DOT1AD)
    return QINQ_ERROR_INVALID_TPID;

  if (config->outer_vlan < QINQ_VLAN_MIN ||
      config->outer_vlan > QINQ_VLAN_MAX)
    return QINQ_ERROR_INVALID_VLAN;

  if (config->match_type == QINQ_MATCH_EXACT)
    {
      if (config->inner_vlan_first < QINQ_VLAN_MIN ||
          config->inner_vlan_first > QINQ_VLAN_MAX ||
          config->inner_vlan_last != config->inner_vlan_first)
        return QINQ_ERROR_INVALID_VLAN;
    }
  else if (config->match_type == QINQ_MATCH_RANGE)
    {
      if (config->inner_vlan_first < QINQ_VLAN_MIN ||
          config->inner_vlan_last > QINQ_VLAN_MAX ||
          config->inner_vlan_first > config->inner_vlan_last)
        return QINQ_ERROR_INVALID_VLAN;
    }
  else if (config->match_type != QINQ_MATCH_ANY)
    {
      clib_warning (
        "qinq config validation failed: invalid match_type %u rule_id %u",
        config->match_type, config->rule_id);
      return QINQ_ERROR_INVALID_ARGUMENT;
    }

  if ((config->service_flags &
       ~(QINQ_SERVICE_IPOE | QINQ_SERVICE_PPPOE)) != 0)
    {
      clib_warning (
        "qinq config validation failed: invalid service_flags 0x%x "
        "rule_id %u",
        config->service_flags, config->rule_id);
      return QINQ_ERROR_INVALID_ARGUMENT;
    }

  p = hash_get (qm->rule_by_id, config->rule_id);
  if (p && p[0] != replaced_rule_index)
    return QINQ_ERROR_RULE_EXISTS;
  p = hash_get (qm->rule_by_sw_if_index, config->sw_if_index);
  if (p && p[0] != replaced_rule_index)
    return QINQ_ERROR_INTERFACE_IN_USE;

  group = qinq_group_find (config->parent_sw_if_index, config->outer_tpid,
                           config->outer_vlan, config->inner_tpid, 0);
  if (!group)
    return QINQ_ERROR_NONE;

  if (config->match_type == QINQ_MATCH_EXACT)
    {
      p = hash_get (group->exact_by_vlan, config->inner_vlan_first);
      if (p && p[0] != replaced_rule_index)
        return QINQ_ERROR_MATCH_CONFLICT;
    }
  else if (config->match_type == QINQ_MATCH_RANGE)
    {
      u16 new_width = config->inner_vlan_last - config->inner_vlan_first;

      vec_foreach_index (i, group->ranges)
        {
          qinq_vlan_range_t *range = vec_elt_at_index (group->ranges, i);
          u16 width = range->last - range->first;
          int overlaps = config->inner_vlan_first <= range->last &&
                         config->inner_vlan_last >= range->first;

          if (range->rule_index != replaced_rule_index && overlaps &&
              width == new_width)
            return QINQ_ERROR_MATCH_CONFLICT;
        }
    }
  else if (group->any_rule_index != ~0 &&
           group->any_rule_index != replaced_rule_index)
    return QINQ_ERROR_MATCH_CONFLICT;

  return QINQ_ERROR_NONE;
}

static void
qinq_rule_attach (u32 rule_index)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t *rule = pool_elt_at_index (qm->rules, rule_index);
  qinq_match_group_t *group;
  qinq_vlan_range_t range;
  u32 group_index;

  group = qinq_group_get_or_create (rule, &group_index);
  if (rule->match_type == QINQ_MATCH_EXACT)
    hash_set (group->exact_by_vlan, rule->inner_vlan_first, rule_index);
  else if (rule->match_type == QINQ_MATCH_RANGE)
    {
      range.first = rule->inner_vlan_first;
      range.last = rule->inner_vlan_last;
      range.rule_index = rule_index;
      vec_add1 (group->ranges, range);
      vec_sort_with_function (group->ranges, qinq_range_compare);
    }
  else
    group->any_rule_index = rule_index;

  group->rule_count++;
  hash_set (qm->rule_by_id, rule->rule_id, rule_index);
  hash_set (qm->rule_by_sw_if_index, rule->sw_if_index, rule_index);
  vec_validate (qm->rules_by_parent, rule->parent_sw_if_index);
  vec_add1 (qm->rules_by_parent[rule->parent_sw_if_index], rule_index);
}

static void
qinq_rule_detach (u32 rule_index)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t *rule = pool_elt_at_index (qm->rules, rule_index);
  qinq_match_group_t *group;
  u32 group_index;
  u32 i;

  group = qinq_group_find (rule->parent_sw_if_index, rule->outer_tpid,
                           rule->outer_vlan, rule->inner_tpid, &group_index);
  ASSERT (group != 0);

  if (rule->match_type == QINQ_MATCH_EXACT)
    hash_unset (group->exact_by_vlan, rule->inner_vlan_first);
  else if (rule->match_type == QINQ_MATCH_RANGE)
    {
      vec_foreach_index (i, group->ranges)
        if (group->ranges[i].rule_index == rule_index)
          {
            vec_del1 (group->ranges, i);
            break;
          }
    }
  else
    group->any_rule_index = ~0;

  hash_unset (qm->rule_by_id, rule->rule_id);
  hash_unset (qm->rule_by_sw_if_index, rule->sw_if_index);

  vec_foreach_index (i, qm->rules_by_parent[rule->parent_sw_if_index])
    if (qm->rules_by_parent[rule->parent_sw_if_index][i] == rule_index)
      {
        vec_del1 (qm->rules_by_parent[rule->parent_sw_if_index], i);
        break;
      }

  group->rule_count--;
  if (group->rule_count == 0)
    qinq_group_destroy (group, group_index);
}

qinq_error_t
qinq_subport_add (const qinq_subport_t *config)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t *rule;
  qinq_error_t error;
  u32 rule_index;

  error = qinq_config_validate (config, ~0);
  if (error != QINQ_ERROR_NONE)
    return error;

  vlib_worker_thread_barrier_sync (qm->vlib_main);
  pool_get (qm->rules, rule);
  *rule = *config;
  rule_index = rule - qm->rules;
  qinq_rule_attach (rule_index);
  vlib_worker_thread_barrier_release (qm->vlib_main);

  return QINQ_ERROR_NONE;
}

qinq_error_t
qinq_subport_delete (u32 rule_id)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t *rule;
  uword *p = hash_get (qm->rule_by_id, rule_id);
  u32 rule_index;

  if (!p)
    return QINQ_ERROR_RULE_NOT_FOUND;

  rule_index = p[0];
  vlib_worker_thread_barrier_sync (qm->vlib_main);
  qinq_rule_detach (rule_index);
  rule = pool_elt_at_index (qm->rules, rule_index);
  pool_put (qm->rules, rule);
  vlib_worker_thread_barrier_release (qm->vlib_main);

  return QINQ_ERROR_NONE;
}

qinq_error_t
qinq_subport_update (u32 rule_id, const qinq_subport_t *config)
{
  qinq_main_t *qm = &qinq_main;
  qinq_subport_t replacement;
  qinq_subport_t *rule;
  qinq_error_t error;
  uword *p = hash_get (qm->rule_by_id, rule_id);
  u32 rule_index;

  if (!p)
    return QINQ_ERROR_RULE_NOT_FOUND;
  if (!config)
    return QINQ_ERROR_INVALID_ARGUMENT;

  rule_index = p[0];
  replacement = *config;
  replacement.rule_id = rule_id;
  error = qinq_config_validate (&replacement, rule_index);
  if (error != QINQ_ERROR_NONE)
    return error;

  vlib_worker_thread_barrier_sync (qm->vlib_main);
  qinq_rule_detach (rule_index);
  rule = pool_elt_at_index (qm->rules, rule_index);
  *rule = replacement;
  qinq_rule_attach (rule_index);
  vlib_worker_thread_barrier_release (qm->vlib_main);

  return QINQ_ERROR_NONE;
}

int
qinq_subport_lookup (u32 parent_sw_if_index, u16 outer_tpid,
                     u16 outer_vlan, u16 inner_tpid, u16 inner_vlan,
                     qinq_match_result_t *result)
{
  qinq_main_t *qm = &qinq_main;
  qinq_match_group_t *group;
  qinq_subport_t *rule;
  uword *p;
  u32 rule_index = ~0;
  u32 i;

  group = qinq_group_find (parent_sw_if_index, outer_tpid, outer_vlan,
                           inner_tpid, 0);
  if (!group)
    return 0;

  p = hash_get (group->exact_by_vlan, inner_vlan);
  if (p && !pool_is_free_index (qm->rules, p[0]))
    {
      rule = pool_elt_at_index (qm->rules, p[0]);
      if (rule->admin_up &&
	  vnet_sw_interface_is_admin_up (qm->vnet_main,
					 rule->sw_if_index))
        rule_index = p[0];
    }

  if (rule_index == ~0)
    {
      vec_foreach_index (i, group->ranges)
        if (inner_vlan >= group->ranges[i].first &&
            inner_vlan <= group->ranges[i].last)
          {
	    u32 candidate = group->ranges[i].rule_index;

	    if (!pool_is_free_index (qm->rules, candidate))
	      {
		rule = pool_elt_at_index (qm->rules, candidate);
		if (rule->admin_up &&
		    vnet_sw_interface_is_admin_up (qm->vnet_main,
						 rule->sw_if_index))
		  {
		    rule_index = candidate;
		    break;
		  }
	      }
          }
    }

  if (rule_index == ~0)
    {
      u32 candidate = group->any_rule_index;

      if (candidate != ~0 && !pool_is_free_index (qm->rules, candidate))
	{
	  rule = pool_elt_at_index (qm->rules, candidate);
	  if (rule->admin_up &&
	      vnet_sw_interface_is_admin_up (qm->vnet_main,
					   rule->sw_if_index))
	    rule_index = candidate;
	}
    }
  if (rule_index == ~0 || pool_is_free_index (qm->rules, rule_index))
    return 0;

  rule = pool_elt_at_index (qm->rules, rule_index);
  result->sw_if_index = rule->sw_if_index;
  result->parent_sw_if_index = rule->parent_sw_if_index;
  result->rule_id = rule->rule_id;
  result->match_type = rule->match_type;
  result->service_flags = rule->service_flags;
  result->admin_up = rule->admin_up;
  return 1;
}

const qinq_subport_t *
qinq_subport_get_by_rule_id (u32 rule_id)
{
  qinq_main_t *qm = &qinq_main;
  uword *p = hash_get (qm->rule_by_id, rule_id);

  return p ? pool_elt_at_index (qm->rules, p[0]) : 0;
}

const qinq_subport_t *
qinq_subport_get_by_sw_if_index (u32 sw_if_index)
{
  qinq_main_t *qm = &qinq_main;
  uword *p = hash_get (qm->rule_by_sw_if_index, sw_if_index);

  return p ? pool_elt_at_index (qm->rules, p[0]) : 0;
}

const char *
qinq_error_string (qinq_error_t error)
{
  switch (error)
    {
    case QINQ_ERROR_NONE:
      return "success";
    case QINQ_ERROR_INVALID_ARGUMENT:
      return "invalid argument";
    case QINQ_ERROR_INVALID_INTERFACE:
      return "invalid subport interface";
    case QINQ_ERROR_INVALID_PARENT:
      return "invalid parent interface";
    case QINQ_ERROR_INVALID_TPID:
      return "TPID must be 0x8100 or 0x88a8";
    case QINQ_ERROR_INVALID_VLAN:
      return "VLAN must be in range 1-4094";
    case QINQ_ERROR_RULE_EXISTS:
      return "rule id already exists";
    case QINQ_ERROR_RULE_NOT_FOUND:
      return "rule id was not found";
    case QINQ_ERROR_INTERFACE_IN_USE:
      return "subport already has a QinQ rule";
    case QINQ_ERROR_MATCH_CONFLICT:
      return "QinQ match conflicts with an existing rule";
    }

  return "unknown QinQ error";
}

int
qinq_rewrite_two_tags (vlib_buffer_t *buffer, const mac_address_t *dst_mac,
		       const mac_address_t *src_mac, u16 outer_tpid,
		       u16 outer_vlan, u16 inner_tpid, u16 inner_vlan,
		       u16 payload_type)
{
  ethernet_header_t *ethernet;
  ethernet_vlan_header_t *outer;
  ethernet_vlan_header_t *inner;
  const u32 header_size = sizeof (*ethernet) + 2 * sizeof (*outer);

  if ((i32) buffer->current_data + VLIB_BUFFER_PRE_DATA_SIZE <
      (i32) header_size)
    return 0;

  vlib_buffer_advance (buffer, -(i32) header_size);
  ethernet = vlib_buffer_get_current (buffer);
  outer = (ethernet_vlan_header_t *) (ethernet + 1);
  inner = outer + 1;

  mac_address_to_bytes (dst_mac, ethernet->dst_address);
  mac_address_to_bytes (src_mac, ethernet->src_address);
  ethernet->type = clib_host_to_net_u16 (outer_tpid);
  outer->priority_cfi_and_id = clib_host_to_net_u16 (outer_vlan);
  outer->type = clib_host_to_net_u16 (inner_tpid);
  inner->priority_cfi_and_id = clib_host_to_net_u16 (inner_vlan);
  inner->type = clib_host_to_net_u16 (payload_type);

  vnet_buffer (buffer)->l2_hdr_offset = buffer->current_data;
  vnet_buffer (buffer)->l3_hdr_offset = buffer->current_data + header_size;
  buffer->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		   VNET_BUFFER_F_L3_HDR_OFFSET_VALID;
  ethernet_buffer_set_vlan_count (buffer, 2);
  return 1;
}

static clib_error_t *
qinq_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  qinq_main_t *qm = &qinq_main;
  const qinq_subport_t *rule;
  u32 *rule_ids = 0;
  u32 *rule_index;

  if (is_add)
    return 0;

  rule = qinq_subport_get_by_sw_if_index (sw_if_index);
  if (rule)
    vec_add1 (rule_ids, rule->rule_id);

  if (sw_if_index < vec_len (qm->rules_by_parent))
    vec_foreach (rule_index, qm->rules_by_parent[sw_if_index])
      {
	rule = pool_elt_at_index (qm->rules, *rule_index);
	vec_add1 (rule_ids, rule->rule_id);
      }

  vec_foreach (rule_index, rule_ids)
    qinq_subport_delete (*rule_index);
  vec_free (rule_ids);
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (qinq_sw_interface_add_del);

static clib_error_t *
qinq_init (vlib_main_t *vm)
{
  qinq_main_t *qm = &qinq_main;

  qm->vlib_main = vm;
  qm->vnet_main = vnet_get_main ();
  qm->rule_by_id = hash_create (0, sizeof (uword));
  qm->rule_by_sw_if_index = hash_create (0, sizeof (uword));
  clib_bihash_init_16_8 (&qm->group_by_domain, "qinq-match-groups", 64,
                         1 << 20);
  return 0;
}

VLIB_INIT_FUNCTION (qinq_init);
