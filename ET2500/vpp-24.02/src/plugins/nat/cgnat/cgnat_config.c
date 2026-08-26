/*
 * cgnat_config.c - CGNAT control-plane configuration
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <plugins/acl/public_inlines.h>

#include <nat/cgnat/cgnat.h>

/* Owned by cgnat.c, used here to validate ACL existence on binding. */
extern acl_plugin_methods_t cgnat_acl_plugin;

static_always_inline int
cgnat_find_free_instance_slot (cgnat_main_t *cm)
{
  cgnat_instance_t *instance;

  vec_foreach (instance, cm->instances)
    if (!instance->configured)
      return instance - cm->instances;
  return CGNAT_INVALID_INDEX;
}

static_always_inline u32
cgnat_find_free_instance_id (cgnat_main_t *cm)
{
  u32 instance_id;

  for (instance_id = 0; instance_id < CGNAT_INVALID_INDEX; instance_id++)
    if (hash_get (cm->instance_index_by_id, instance_id) == 0)
      return instance_id;
  return CGNAT_INVALID_INDEX;
}

static_always_inline u32
cgnat_find_free_pool_id (cgnat_main_t *cm)
{
  u32 pool_id;

  for (pool_id = 0; pool_id < CGNAT_INVALID_INDEX; pool_id++)
    if (hash_get (cm->pool_index_by_id, pool_id) == 0)
      return pool_id;
  return CGNAT_INVALID_INDEX;
}

static_always_inline int
cgnat_find_free_pool_slot (cgnat_main_t *cm)
{
  cgnat_pool_t *pool;

  vec_foreach (pool, cm->pools)
    if (!pool->configured)
      return pool - cm->pools;
  return CGNAT_INVALID_INDEX;
}

static int
cgnat_inside_address_validate_one (cgnat_inside_address_t *address)
{
  u32 first, last, mask;

  if (!address)
    return VNET_API_ERROR_INVALID_VALUE;

  if (address->type == CGNAT_INSIDE_ADDRESS_PREFIX)
    {
      if (address->prefix_len > 32)
	return VNET_API_ERROR_INVALID_VALUE;
      mask = ip4_main.fib_masks[address->prefix_len];
      address->first_ip.as_u32 &= mask;
      address->last_ip.as_u32 =
	address->first_ip.as_u32 | clib_host_to_net_u32 (
				     ~clib_net_to_host_u32 (mask));
    }
  else if (address->type != CGNAT_INSIDE_ADDRESS_RANGE)
    return VNET_API_ERROR_INVALID_VALUE;

  first = clib_net_to_host_u32 (address->first_ip.as_u32);
  last = clib_net_to_host_u32 (address->last_ip.as_u32);
  if (!first || !last || first > last)
    return VNET_API_ERROR_INVALID_VALUE;

  if (address->type == CGNAT_INSIDE_ADDRESS_RANGE)
    address->prefix_len = 0xff;

  return 0;
}

static int
cgnat_inside_address_validate (cgnat_inside_address_t *addresses,
			       u32 address_count)
{
  u32 i, j, first, last, other_first, other_last;
  int rv;

  if (address_count > CGNAT_MAX_INSIDE_ADDRESSES)
    return VNET_API_ERROR_INVALID_VALUE;
  if (address_count && !addresses)
    return VNET_API_ERROR_INVALID_VALUE;

  for (i = 0; i < address_count; i++)
    {
      rv = cgnat_inside_address_validate_one (&addresses[i]);
      if (rv)
	return rv;

      first = clib_net_to_host_u32 (addresses[i].first_ip.as_u32);
      last = clib_net_to_host_u32 (addresses[i].last_ip.as_u32);
      for (j = 0; j < i; j++)
	{
	  other_first = clib_net_to_host_u32 (addresses[j].first_ip.as_u32);
	  other_last = clib_net_to_host_u32 (addresses[j].last_ip.as_u32);
	  if (first <= other_last && other_first <= last)
	    return VNET_API_ERROR_ADDRESS_IN_USE;
	}
    }
  return 0;
}

int
cgnat_instance_index_from_id (u32 instance_id, u32 *instance_index)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->instance_index_by_id, instance_id);

  if (!p || !cgnat_instance_get_by_index (cm, p[0]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  *instance_index = p[0];
  return 0;
}

int
cgnat_pool_index_from_id (u32 pool_id, u32 *pool_index)
{
  cgnat_main_t *cm = &cgnat_main;
  uword *p = hash_get (cm->pool_index_by_id, pool_id);

  if (!p || !cgnat_pool_get_by_index (cm, p[0]))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  *pool_index = p[0];
  return 0;
}

void
cgnat_recalculate_instance (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  u32 *pool_index;

  instance->total_blocks = 0;
  instance->allocated_blocks = 0;
  instance->cooling_blocks = 0;
  instance->active_users = 0;
  vec_foreach (pool_index, instance->pool_indices)
    {
      cgnat_pool_t *pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (!pool)
	continue;
      instance->total_blocks += pool->total_blocks;
      instance->allocated_blocks +=
	clib_atomic_load_relax_n (&pool->allocated_blocks);
      instance->cooling_blocks += clib_atomic_load_relax_n (&pool->cooling_blocks);
      instance->active_users += clib_atomic_load_relax_n (&pool->active_users);
    }
}

static int
cgnat_pool_config_validate (cgnat_pool_config_t *config)
{
  u32 first = clib_net_to_host_u32 (config->first_ip.as_u32);
  u32 last = clib_net_to_host_u32 (config->last_ip.as_u32);

  if (first > last || (last - first + 1) > CGNAT_MAX_PUBLIC_IPS_PER_POOL ||
      config->reserved_port_start != 0 ||
      config->reserved_port_end > CGNAT_DEFAULT_END_PORT ||
      config->block_alloc_mode > CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC ||
      config->port_alloc_mode > CGNAT_PORT_ALLOC_MODE_SEQUENCE ||
      config->prealloc_blocks_per_user > 256 || config->cooling_time > 3600)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Dynamic-specific checks (block_size, pow2 reserved end, usable ports) are
   * deferred to cgnat_pool_runtime_init() when the pool is attached to a
   * dynamic instance.  Deterministic instances only use the IP range and the
   * usable port range. */
  return 0;
}

static int
cgnat_pool_overlaps (cgnat_main_t *cm, cgnat_pool_t *skip,
		     cgnat_pool_config_t *config)
{
  cgnat_pool_t *pool;
  u32 first = clib_net_to_host_u32 (config->first_ip.as_u32);
  u32 last = clib_net_to_host_u32 (config->last_ip.as_u32);

  vec_foreach (pool, cm->pools)
    {
      u32 other_first, other_last;

      if (!pool->configured || pool == skip)
	continue;
      other_first = clib_net_to_host_u32 (pool->first_ip.as_u32);
      other_last = clib_net_to_host_u32 (pool->last_ip.as_u32);
      if (first <= other_last && other_first <= last)
	return 1;
    }
  return 0;
}

static void
cgnat_pool_apply_config (cgnat_pool_t *pool, cgnat_pool_config_t *config)
{
  clib_memcpy (pool->label, config->label, sizeof (pool->label));
  pool->first_ip = config->first_ip;
  pool->last_ip = config->last_ip;
  pool->exclude_start_port = config->reserved_port_start;
  pool->exclude_end_port = config->reserved_port_end;
  pool->start_port = config->reserved_port_end + 1;
  pool->end_port = CGNAT_DEFAULT_END_PORT;
  pool->block_size = config->block_size;
  pool->prealloc_blocks_per_user = config->prealloc_blocks_per_user;
  pool->cooling_time = config->cooling_time;
  pool->block_alloc_mode = config->block_alloc_mode;
  pool->port_alloc_mode = config->port_alloc_mode;
}

static void
cgnat_pool_free_runtime (cgnat_pool_t *pool)
{
  cgnat_block_t *block;
  cgnat_public_ip_t *ip;
  u32 i, j;

  vec_foreach (ip, pool->public_ips)
    {
      if (ip->blocks)
	{
	  pool_foreach (block, ip->blocks)
	    {
	      for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
		for (j = 0; j < 2; j++)
		  clib_bitmap_free (block->free_port_bitmap[i][j]);
	    }
	  clib_bitmap_free (ip->free_block_bitmap);
	  vec_free (ip->block_index_by_id);
	  pool_free (ip->blocks);
	  clib_spinlock_free (&ip->lock);
	}
    }
  vec_free (pool->public_ips);
  clib_bitmap_free (pool->free_port_offset_bitmap[0]);
  clib_bitmap_free (pool->free_port_offset_bitmap[1]);
  pool->free_port_offset_bitmap[0] = 0;
  pool->free_port_offset_bitmap[1] = 0;
}

static void
cgnat_instance_free_runtime (cgnat_instance_t *instance)
{
  cgnat_static_rule_t *rule;
  cgnat_user_t *user;
  u32 i;

  pool_foreach (user, instance->users)
    {
      int i;

      vec_free (user->owned_block_ids);
      for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
	clib_bitmap_free (user->det_port_bitmap[i]);
      clib_spinlock_free (&user->session_lock);
    }
  pool_foreach (rule, instance->static_rules)
    {
      vec_free (rule->exact_mapping_indices);
      clib_spinlock_free (&rule->lock);
    }

  hash_free (instance->user_index_by_key);
  pool_free (instance->users);
  pool_free (instance->static_rules);
  vec_free (instance->acl_indices);
  vec_free (instance->syslog_servers);
  vec_free (instance->ipfix_exporters);
  vec_free (instance->pool_indices);
  vec_free (instance->inside_addresses);

  for (i = 0; i < CGNAT_USER_LOCK_BUCKETS; i++)
    clib_spinlock_free (&instance->user_locks[i]);
  clib_spinlock_free (&instance->random_lock);

  clib_memset (instance, 0, sizeof (*instance));
}

static void
cgnat_instance_runtime_init (cgnat_main_t *cm, cgnat_instance_t *instance,
			     u32 instance_index)
{
  u32 i;

  (void) cm;

  for (i = 0; i < CGNAT_USER_LOCK_BUCKETS; i++)
    clib_spinlock_init (&instance->user_locks[i]);
  clib_spinlock_init (&instance->random_lock);
  instance->random_seed =
    random_default_seed () ^ instance->instance_id ^ instance_index;

  instance->users = 0;
  instance->user_index_by_key =
    hash_create_mem (0, sizeof (cgnat_user_key_t), sizeof (uword));

  instance->total_blocks = 0;
  instance->allocated_blocks = 0;
  instance->cooling_blocks = 0;
  instance->active_users = 0;
  instance->active_sessions = 0;
}

static_always_inline void
cgnat_instance_runtime_fini (cgnat_instance_t *instance)
{
  u32 i;

  for (i = 0; i < CGNAT_USER_LOCK_BUCKETS; i++)
    clib_spinlock_free (&instance->user_locks[i]);
  clib_spinlock_free (&instance->random_lock);

  if (instance->users)
    pool_free (instance->users);
  instance->users = 0;

  if (instance->user_index_by_key)
    hash_free (instance->user_index_by_key);
  instance->user_index_by_key = 0;
}

static_always_inline void
cgnat_instance_runtime_reset (cgnat_main_t *cm, cgnat_instance_t *instance,
			      u32 instance_index)
{
  cgnat_instance_cleanup_runtime_state (cm, instance);
  cgnat_instance_runtime_fini (instance);
  cgnat_instance_runtime_init (cm, instance, instance_index);
}

static_always_inline void
cgnat_pool_runtime_reset_full (cgnat_pool_t *pool)
{
  cgnat_pool_free_runtime (pool);
  pool->total_blocks = 0;
  clib_atomic_store_relax_n (&pool->allocated_blocks, 0);
  clib_atomic_store_relax_n (&pool->cooling_blocks, 0);
  clib_atomic_store_relax_n (&pool->active_users, 0);
  pool->active_sessions = 0;
}

static_always_inline void
_cgnat_instance_acl_del (cgnat_main_t *cm, u32 acl_index)
{
  if (acl_index < vec_len (cm->instance_index_by_acl))
    cm->instance_index_by_acl[acl_index] = CGNAT_INVALID_INDEX;
}

static_always_inline void
cgnat_instance_clear_acls_inline (cgnat_main_t *cm,
				  cgnat_instance_t *instance)
{
  u32 acl_index;

  while (vec_len (instance->acl_indices))
    {
      acl_index = instance->acl_indices[vec_len (instance->acl_indices) - 1];
      _cgnat_instance_acl_del (cm, acl_index);
      vec_del1 (instance->acl_indices, vec_len (instance->acl_indices) - 1);
    }
}

/* Add/remove a /32 local receive entry for a public IP on an outside
 * interface so VPP answers ARP for that address. */
static void
cgnat_add_fib_entry_reg (ip4_address_t addr, u32 sw_if_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_fib_entry_reg_t *fe;
  u32 i;

  for (i = 0; i < vec_len (cm->fib_entry_reg); i++)
    {
      fe = cm->fib_entry_reg + i;
      if (fe->addr.as_u32 == addr.as_u32 && fe->sw_if_index == sw_if_index)
        break;
    }

  if (i == vec_len (cm->fib_entry_reg))
    {
      fib_prefix_t prefix = {
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
        .fp_addr.ip4.as_u32 = addr.as_u32,
      };
      u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
      fib_table_entry_update_one_path (
        fib_index, &prefix, cm->fib_src,
        FIB_ENTRY_FLAG_CONNECTED | FIB_ENTRY_FLAG_LOCAL |
          FIB_ENTRY_FLAG_EXCLUSIVE,
        DPO_PROTO_IP4, NULL, sw_if_index, ~0, 1, NULL,
        FIB_ROUTE_PATH_FLAG_NONE);

      vec_add2 (cm->fib_entry_reg, fe, 1);
      fe->addr.as_u32 = addr.as_u32;
      fe->sw_if_index = sw_if_index;
      fe->count = 0;
    }

  fe->count++;
}

static void
cgnat_del_fib_entry_reg (ip4_address_t addr, u32 sw_if_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_fib_entry_reg_t *fe;
  u32 i;

  for (i = 0; i < vec_len (cm->fib_entry_reg); i++)
    {
      fe = cm->fib_entry_reg + i;
      if (fe->addr.as_u32 == addr.as_u32 && fe->sw_if_index == sw_if_index)
        {
          if (--fe->count == 0)
            {
              fib_prefix_t prefix = {
                .fp_len = 32,
                .fp_proto = FIB_PROTOCOL_IP4,
                .fp_addr.ip4.as_u32 = addr.as_u32,
              };
              u32 fib_index =
                ip4_fib_table_get_index_for_sw_if_index (sw_if_index);
              fib_table_entry_delete (fib_index, &prefix, cm->fib_src);
              vec_del1 (cm->fib_entry_reg, i);
            }
          return;
        }
    }
}

static_always_inline void
cgnat_add_pool_fib_entries_for_sw_if (cgnat_pool_t *pool, u32 sw_if_index)
{
  cgnat_public_ip_t *ip;

  vec_foreach (ip, pool->public_ips)
    cgnat_add_fib_entry_reg (ip->addr, sw_if_index);
}

static_always_inline void
cgnat_del_pool_fib_entries_for_sw_if (cgnat_pool_t *pool, u32 sw_if_index)
{
  cgnat_public_ip_t *ip;

  vec_foreach (ip, pool->public_ips)
    cgnat_del_fib_entry_reg (ip->addr, sw_if_index);
}

static void
cgnat_del_pool_fib_entries (cgnat_main_t *cm, cgnat_pool_t *pool)
{
  cgnat_interface_t *i;

  pool_foreach (i, cm->interfaces)
    {
      if (cgnat_interface_is_outside (i))
        cgnat_del_pool_fib_entries_for_sw_if (pool, i->sw_if_index);
    }
}

static void
cgnat_add_all_pool_fib_entries_for_sw_if (cgnat_main_t *cm, u32 sw_if_index)
{
  cgnat_pool_t *pool;

  vec_foreach (pool, cm->pools)
    {
      if (pool->configured)
        cgnat_add_pool_fib_entries_for_sw_if (pool, sw_if_index);
    }
}

static void
cgnat_add_all_pool_fib_entries (cgnat_main_t *cm)
{
  cgnat_interface_t *i;

  pool_foreach (i, cm->interfaces)
    {
      if (cgnat_interface_is_outside (i))
	cgnat_add_all_pool_fib_entries_for_sw_if (cm, i->sw_if_index);
    }
}

static void
cgnat_del_all_pool_fib_entries_for_sw_if (cgnat_main_t *cm, u32 sw_if_index)
{
  cgnat_pool_t *pool;

  vec_foreach (pool, cm->pools)
    {
      if (pool->configured)
        cgnat_del_pool_fib_entries_for_sw_if (pool, sw_if_index);
    }
}

static void
cgnat_add_static_fib_entries_for_sw_if (cgnat_main_t *cm, u32 sw_if_index)
{
  cgnat_instance_t *instance;
  cgnat_static_rule_t *rule;

  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      pool_foreach (rule, instance->static_rules)
	cgnat_add_fib_entry_reg (rule->outside_ip, sw_if_index);
    }
}

static void
cgnat_del_static_fib_entries_for_sw_if (cgnat_main_t *cm, u32 sw_if_index)
{
  cgnat_instance_t *instance;
  cgnat_static_rule_t *rule;

  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      pool_foreach (rule, instance->static_rules)
	cgnat_del_fib_entry_reg (rule->outside_ip, sw_if_index);
    }
}

static void
cgnat_add_all_static_fib_entries (cgnat_main_t *cm)
{
  cgnat_interface_t *i;

  pool_foreach (i, cm->interfaces)
    {
      if (cgnat_interface_is_outside (i))
	cgnat_add_static_fib_entries_for_sw_if (cm, i->sw_if_index);
    }
}

void
cgnat_static_fib_add_for_rule (cgnat_main_t *cm, cgnat_static_rule_t *rule)
{
  cgnat_interface_t *i;

  pool_foreach (i, cm->interfaces)
    {
      if (cgnat_interface_is_outside (i))
	cgnat_add_fib_entry_reg (rule->outside_ip, i->sw_if_index);
    }
}

void
cgnat_static_fib_del_for_rule (cgnat_main_t *cm, cgnat_static_rule_t *rule)
{
  cgnat_interface_t *i;

  pool_foreach (i, cm->interfaces)
    {
      if (cgnat_interface_is_outside (i))
	cgnat_del_fib_entry_reg (rule->outside_ip, i->sw_if_index);
    }
}

static void
cgnat_del_all_fib_entry_regs (cgnat_main_t *cm)
{
  cgnat_fib_entry_reg_t *fe;

  vec_foreach (fe, cm->fib_entry_reg)
    {
      fib_prefix_t prefix = {
	.fp_len = 32,
	.fp_proto = FIB_PROTOCOL_IP4,
	.fp_addr.ip4.as_u32 = fe->addr.as_u32,
      };
      u32 fib_index = ip4_fib_table_get_index_for_sw_if_index (fe->sw_if_index);

      fib_table_entry_delete (fib_index, &prefix, cm->fib_src);
    }
  vec_free (cm->fib_entry_reg);
}

int
cgnat_pool_add_del (u32 *pool_id, cgnat_pool_config_t *config, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  cgnat_instance_t *instance = 0;
  u32 pool_index;
  int slot;

  if (!pool_id)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      if (!config || cgnat_pool_config_validate (config))
	return VNET_API_ERROR_INVALID_VALUE;
      if (*pool_id == CGNAT_INVALID_INDEX)
	{
	  *pool_id = cgnat_find_free_pool_id (cm);
	  if (*pool_id == CGNAT_INVALID_INDEX)
	    return VNET_API_ERROR_LIMIT_EXCEEDED;
	}
      else if (!cgnat_pool_index_from_id (*pool_id, &pool_index))
	return VNET_API_ERROR_VALUE_EXIST;
      if (cgnat_pool_overlaps (cm, 0, config))
	return VNET_API_ERROR_ADDRESS_IN_USE;

      slot = cgnat_find_free_pool_slot (cm);
      vlib_worker_thread_barrier_sync (cm->vlib_main);
      if (slot == (int) CGNAT_INVALID_INDEX)
	{
	  vec_add2 (cm->pools, pool, 1);
	  slot = pool - cm->pools;
	}
      else
	pool = vec_elt_at_index (cm->pools, slot);
      clib_memset (pool, 0, sizeof (*pool));
      pool->pool_id = *pool_id;
      pool->owner_instance_index = CGNAT_INVALID_INDEX;
      pool->configured = 1;
      cgnat_pool_apply_config (pool, config);
      /* Runtime (public IPs and optional blocks) is initialized lazily when
       * the pool is attached to an instance, so dynamic vs deterministic mode
       * can decide whether blocks are needed. */
      hash_set (cm->pool_index_by_id, *pool_id, slot);
      vlib_worker_thread_barrier_release (cm->vlib_main);
      return 0;
    }

  if (*pool_id == CGNAT_INVALID_INDEX ||
      cgnat_pool_index_from_id (*pool_id, &pool_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  pool = vec_elt_at_index (cm->pools, pool_index);
  instance = cgnat_instance_get_by_index (cm, pool->owner_instance_index);

  if (instance)
    {
      u32 i;

      vec_foreach_index (i, instance->pool_indices)
	{
	  if (instance->pool_indices[i] == pool_index)
	    {
	      vec_del1 (instance->pool_indices, i);
	      break;
	    }
	}
      pool->owner_instance_index = CGNAT_INVALID_INDEX;
    }

  cgnat_pool_cleanup_runtime (cm, pool, pool_index, instance);

  hash_unset (cm->pool_index_by_id, *pool_id);
  cgnat_del_pool_fib_entries (cm, pool);
  cgnat_pool_free_runtime (pool);
  clib_memset (pool, 0, sizeof (*pool));

  if (instance)
    cgnat_recalculate_instance (cm, instance);
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

int
cgnat_pool_set_cooling_time (u32 pool_id, u16 cooling_time)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u32 pool_index;

  if (cooling_time > 3600 || cgnat_pool_index_from_id (pool_id, &pool_index))
    return VNET_API_ERROR_INVALID_VALUE;
  pool = vec_elt_at_index (cm->pools, pool_index);

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  pool->cooling_time = cooling_time;
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

int
cgnat_pool_set_label (u32 pool_id, u8 *label)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u32 pool_index;

  if (cgnat_pool_index_from_id (pool_id, &pool_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pool = vec_elt_at_index (cm->pools, pool_index);

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  clib_memcpy (pool->label, label, sizeof (pool->label));
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

static void
cgnat_instance_defaults (cgnat_instance_t *instance)
{
  instance->filter_mode = CGNAT_FILTER_MODE_EIF;
  instance->log_mode = CGNAT_LOG_MODE_PORT_BLOCK;
  instance->syslog_enabled = 1;
  instance->per_user_max_blocks = CGNAT_DEFAULT_MAX_USER_BLOCKS;
  instance->per_user_max_ports = CGNAT_DEFAULT_MAX_USER_PORTS;
  instance->tcp_syn_timeout = CGNAT_TCP_SYN_TIMEOUT;
  instance->tcp_established_timeout = CGNAT_TCP_ESTABLISHED_TIMEOUT;
  instance->tcp_fin_rst_timeout = CGNAT_TCP_FIN_RST_TIMEOUT;
  instance->udp_timeout = CGNAT_UDP_TIMEOUT;
  instance->icmp_timeout = CGNAT_ICMP_TIMEOUT;
  instance->other_timeout = CGNAT_OTHER_TIMEOUT;
  instance->tcp_mss = CGNAT_DEFAULT_TCP_MSS;
}

static int
cgnat_instance_det_pools_validate (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  cgnat_pool_t *pool, *first_pool = 0;
  u32 *pool_index;

  vec_foreach (pool_index, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (!pool)
	continue;
      if (!first_pool)
	{
	  first_pool = pool;
	  continue;
	}
      if (pool->start_port != first_pool->start_port ||
	  pool->end_port != first_pool->end_port ||
	  pool->exclude_end_port != first_pool->exclude_end_port)
	return VNET_API_ERROR_INVALID_VALUE;
    }
  return 0;
}

static int
cgnat_instance_det_runtime_compute (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  cgnat_inside_address_t *addr = instance->inside_addresses;
  cgnat_pool_t *pool;
  u32 *pool_index;
  u32 inside_count, outside_count, sharing_ratio, ports_per_host;
  u32 usable_port_start, usable_port_end, usable_port_count;
  cgnat_det_runtime_t *det = &instance->det;

  /* First version: exactly one contiguous inside address range/prefix. */
  if (!addr || vec_len (addr) != 1)
    return VNET_API_ERROR_INVALID_VALUE;

  inside_count =
    clib_net_to_host_u32 (addr->last_ip.as_u32) -
    clib_net_to_host_u32 (addr->first_ip.as_u32) + 1;
  if (!inside_count)
    return VNET_API_ERROR_INVALID_VALUE;

  outside_count = 0;
  vec_foreach (pool_index, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (!pool)
	continue;
      outside_count +=
	clib_net_to_host_u32 (pool->last_ip.as_u32) -
	clib_net_to_host_u32 (pool->first_ip.as_u32) + 1;
    }
  if (!outside_count)
    return VNET_API_ERROR_INVALID_VALUE;

  sharing_ratio = (inside_count + outside_count - 1) / outside_count;
  if (!sharing_ratio)
    return VNET_API_ERROR_INVALID_VALUE;

  pool = cgnat_pool_get_by_index (cm, instance->pool_indices[0]);
  usable_port_start = pool->start_port;
  usable_port_end = pool->end_port;
  usable_port_count = usable_port_end - usable_port_start + 1;
  if (usable_port_count < sharing_ratio)
    return VNET_API_ERROR_INVALID_VALUE;

  ports_per_host = usable_port_count / sharing_ratio;
  if (!ports_per_host)
    return VNET_API_ERROR_INVALID_VALUE;

  clib_memset (det, 0, sizeof (*det));
  det->inside_count = inside_count;
  det->outside_count = outside_count;
  det->sharing_ratio = sharing_ratio;
  det->ports_per_host = ports_per_host;
  det->usable_port_start = usable_port_start;
  det->usable_port_end = usable_port_end;
  det->usable_port_count = usable_port_count;
  det->inside_first_host = clib_net_to_host_u32 (addr->first_ip.as_u32);

  return 0;
}

int
cgnat_instance_add_del (u32 *instance_id, u8 *label, u32 inside_vrf_id,
			u32 outside_vrf_id, u8 mode, u32 *pool_ids,
			u32 pool_count, cgnat_inside_address_t *inside_addresses,
			u32 inside_address_count, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  u32 instance_index, inside_fib_index, outside_fib_index, *pool_indices = 0;
  cgnat_inside_address_t *saved_inside_addresses = 0;
  cgnat_det_runtime_t det_runtime;
  u32 i, j, pool_index;
  int slot, rv;

  if (!instance_id)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      if (mode > CGNAT_INSTANCE_MODE_DETERMINISTIC)
	return VNET_API_ERROR_INVALID_VALUE;
      if ((mode == CGNAT_INSTANCE_MODE_DYNAMIC && inside_address_count) ||
	  (mode == CGNAT_INSTANCE_MODE_DETERMINISTIC && !inside_address_count))
	return VNET_API_ERROR_INVALID_VALUE;
      if (pool_count > CGNAT_MAX_INSTANCE_POOLS)
	return VNET_API_ERROR_INVALID_VALUE;
      if (inside_address_count)
	{
	  vec_validate (saved_inside_addresses, inside_address_count - 1);
	  clib_memcpy_fast (saved_inside_addresses, inside_addresses,
			    inside_address_count * sizeof (inside_addresses[0]));
	  int rv = cgnat_inside_address_validate (saved_inside_addresses,
						  inside_address_count);
	  if (rv)
	    {
	      vec_free (saved_inside_addresses);
	      return rv;
	    }
	}

      if (*instance_id == CGNAT_INVALID_INDEX)
	{
	  *instance_id = cgnat_find_free_instance_id (cm);
	  if (*instance_id == CGNAT_INVALID_INDEX)
	    {
	      vec_free (saved_inside_addresses);
	      return VNET_API_ERROR_LIMIT_EXCEEDED;
	    }
	}
      else if (!cgnat_instance_index_from_id (*instance_id, &instance_index))
	{
	  vec_free (saved_inside_addresses);
	  return VNET_API_ERROR_VALUE_EXIST;
	}
      if (!pool_count || !pool_ids)
	{
	  vec_free (saved_inside_addresses);
	  return VNET_API_ERROR_INVALID_VALUE;
	}
      for (i = 0; i < pool_count; i++)
	{
	  if (cgnat_pool_index_from_id (pool_ids[i], &pool_index))
	    {
	      vec_free (saved_inside_addresses);
	      vec_free (pool_indices);
	      return VNET_API_ERROR_NO_SUCH_ENTRY;
	    }
	  vec_foreach_index (j, pool_indices)
	    if (pool_indices[j] == pool_index)
	      {
		vec_free (saved_inside_addresses);
		vec_free (pool_indices);
		return VNET_API_ERROR_VALUE_EXIST;
	      }
	  pool = vec_elt_at_index (cm->pools, pool_index);
	  if (pool->owner_instance_index != CGNAT_INVALID_INDEX)
	    {
	      vec_free (saved_inside_addresses);
	      vec_free (pool_indices);
	      return VNET_API_ERROR_ADDRESS_IN_USE;
	    }
	  vec_add1 (pool_indices, pool_index);
	}
      inside_fib_index =
	inside_vrf_id == CGNAT_INVALID_INDEX ?
	  CGNAT_INVALID_INDEX :
	  fib_table_find (FIB_PROTOCOL_IP4, inside_vrf_id);
      outside_fib_index = fib_table_find (FIB_PROTOCOL_IP4, outside_vrf_id);
      if ((inside_vrf_id != CGNAT_INVALID_INDEX &&
	   inside_fib_index == CGNAT_INVALID_INDEX) ||
	  outside_fib_index == CGNAT_INVALID_INDEX)
	{
	  vec_free (saved_inside_addresses);
	  vec_free (pool_indices);
	  return VNET_API_ERROR_NO_SUCH_FIB;
	}

      /* Pre-compute deterministic runtime outside the barrier; copy it in on
       * success so we never need to roll back a partially-initialized instance. */
      if (mode == CGNAT_INSTANCE_MODE_DETERMINISTIC)
	{
	  cgnat_instance_t tmp;
	  int rv;

	  clib_memset (&tmp, 0, sizeof (tmp));
	  tmp.pool_indices = pool_indices;
	  tmp.inside_addresses = saved_inside_addresses;
	  rv = cgnat_instance_det_pools_validate (cm, &tmp);
	  if (rv)
	    {
	      vec_free (saved_inside_addresses);
	      vec_free (pool_indices);
	      return rv;
	    }
	  rv = cgnat_instance_det_runtime_compute (cm, &tmp);
	  if (rv)
	    {
	      vec_free (saved_inside_addresses);
	      vec_free (pool_indices);
	      return rv;
	    }
	  det_runtime = tmp.det;
	}

      slot = cgnat_find_free_instance_slot (cm);
      vlib_worker_thread_barrier_sync (cm->vlib_main);
      if (slot == (int) CGNAT_INVALID_INDEX)
	{
	  vec_add2 (cm->instances, instance, 1);
	  slot = instance - cm->instances;
	}
      else
	instance = vec_elt_at_index (cm->instances, slot);
      clib_memset (instance, 0, sizeof (*instance));
      instance->instance_id = *instance_id;
      if (label)
	{
	  u32 n = 0;

	  /* API wire format is a fixed 64-byte field, NUL not guaranteed. */
	  while (n < sizeof (instance->label) - 1 && label[n])
	    n++;
	  clib_memcpy_fast (instance->label, label, n);
	  instance->label[n] = 0;
	}
      instance->inside_fib_index = inside_fib_index;
      instance->outside_fib_index = outside_fib_index;
      instance->mode = mode;
      instance->inside_addresses = saved_inside_addresses;
      instance->configured = 1;
      cgnat_instance_defaults (instance);
      cgnat_instance_runtime_init (cm, instance, slot);
      instance->pool_indices = pool_indices;
      if (mode == CGNAT_INSTANCE_MODE_DETERMINISTIC)
	instance->det = det_runtime;
      vec_foreach_index (i, instance->pool_indices)
	{
	  pool = vec_elt_at_index (cm->pools, instance->pool_indices[i]);
	  pool->owner_instance_index = slot;
	}

      /* Initialize pool runtime.  Dynamic instances need blocks; deterministic
       * instances only need the public IP list. */
      {
	u8 create_blocks = (mode == CGNAT_INSTANCE_MODE_DYNAMIC);
	u32 *pi;

	vec_foreach (pi, instance->pool_indices)
	  {
	    cgnat_pool_t *p = cgnat_pool_get_by_index (cm, *pi);
	    if (!p)
	      continue;
	    rv = cgnat_pool_runtime_init (p, create_blocks);
	    if (rv)
	      {
		u32 *pi2;
		/* Roll back any pools that were initialized. */
		vec_foreach (pi2, instance->pool_indices)
		  {
		    cgnat_pool_t *p2 = cgnat_pool_get_by_index (cm, *pi2);
		    if (p2)
		      cgnat_pool_free_runtime (p2);
		  }
		vec_foreach (pi2, instance->pool_indices)
		  {
		    cgnat_pool_t *p2 = cgnat_pool_get_by_index (cm, *pi2);
		    if (p2)
		      p2->owner_instance_index = CGNAT_INVALID_INDEX;
		  }
		cgnat_instance_runtime_fini (instance);
		clib_memset (instance, 0, sizeof (*instance));
		vlib_worker_thread_barrier_release (cm->vlib_main);
		vec_free (saved_inside_addresses);
		vec_free (pool_indices);
		return rv;
	      }
	  }
      }

      /* Add FIB receive entries for pool public IPs on outside interfaces. */
      cgnat_add_all_pool_fib_entries (cm);

      cgnat_recalculate_instance (cm, instance);
      hash_set (cm->instance_index_by_id, *instance_id, slot);
      vlib_worker_thread_barrier_release (cm->vlib_main);
      return 0;
    }

  if (cgnat_instance_index_from_id (*instance_id, &instance_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  instance = vec_elt_at_index (cm->instances, instance_index);

  cgnat_instance_clear_acls_inline (cm, instance);
  cgnat_instance_cleanup_resources (cm, instance);

  /* Cascade delete all pools owned by this instance. */
  {
    u32 *owned_pool_indices = 0;
    u32 *pi;

    vec_foreach (pi, instance->pool_indices)
      vec_add1 (owned_pool_indices, *pi);

    vec_foreach (pi, owned_pool_indices)
      {
	pool = cgnat_pool_get_by_index (cm, *pi);
	if (!pool)
	  continue;
	cgnat_pool_runtime_reset (pool);
	hash_unset (cm->pool_index_by_id, pool->pool_id);
	cgnat_del_pool_fib_entries (cm, pool);
	cgnat_pool_free_runtime (pool);
	clib_memset (pool, 0, sizeof (*pool));
      }
    vec_free (owned_pool_indices);
  }

  hash_unset (cm->instance_index_by_id, *instance_id);
  cgnat_instance_free_runtime (instance);
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

int
cgnat_instance_set (u32 instance_id, cgnat_instance_config_t *config)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u32 instance_index;

  if (!config ||
      cgnat_instance_index_from_id (instance_id, &instance_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (config->flags & ~CGNAT_INSTANCE_SET_VALID_FLAGS)
    return VNET_API_ERROR_INVALID_VALUE;
  instance = vec_elt_at_index (cm->instances, instance_index);

  if ((config->flags & CGNAT_INSTANCE_SET_FILTER_MODE) &&
      config->filter_mode > CGNAT_FILTER_MODE_ADPF)
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_LOG_MODE) &&
      config->log_mode > CGNAT_LOG_MODE_SESSION)
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_MAX_USER_BLOCKS) &&
      (config->max_user_blocks < 1 || config->max_user_blocks > 256))
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_MAX_USER_PORTS) &&
      config->max_user_ports < 1)
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_MAX_USER_SESSIONS) &&
      config->max_user_sessions > 10240)
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_MAX_USER_CREATE_RATE) &&
      config->max_user_create_sessions_rate > 10240)
    return VNET_API_ERROR_INVALID_VALUE;
  if ((config->flags & CGNAT_INSTANCE_SET_TCP_MSS) && config->tcp_mss &&
      (config->tcp_mss < 160 || config->tcp_mss > 9540))
    return VNET_API_ERROR_INVALID_VALUE;

#define CGNAT_VALIDATE_AGING(flag, field)                                     \
  if ((config->flags & (flag)) &&                                            \
      ((config->field) < 1 || (config->field) > 262144))                    \
    return VNET_API_ERROR_INVALID_VALUE
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_TCP_SYN, aging_tcp_syn);
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_TCP_ESTABLISHED,
			aging_tcp_established);
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_TCP_FIN_RST,
			aging_tcp_fin_rst);
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_UDP, aging_udp);
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_ICMP, aging_icmp);
  CGNAT_VALIDATE_AGING (CGNAT_INSTANCE_SET_AGING_OTHER, aging_other);
#undef CGNAT_VALIDATE_AGING

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  cgnat_recalculate_instance (cm, instance);
#define CGNAT_SET_FIELD(flag, dst, src)                                      \
  if (config->flags & (flag))                                                \
    instance->dst = config->src
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_FILTER_MODE, filter_mode, filter_mode);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_HAIRPINNING, hairpinning_enabled,
		   hairpinning_enabled);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_MAX_USER_BLOCKS, per_user_max_blocks,
		   max_user_blocks);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_MAX_USER_PORTS, per_user_max_ports,
		   max_user_ports);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_MAX_USER_SESSIONS,
		   max_sessions_per_user, max_user_sessions);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_MAX_USER_CREATE_RATE,
		   max_session_create_rate, max_user_create_sessions_rate);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_TCP_SYN, tcp_syn_timeout,
		   aging_tcp_syn);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_TCP_ESTABLISHED,
		   tcp_established_timeout, aging_tcp_established);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_TCP_FIN_RST,
		   tcp_fin_rst_timeout, aging_tcp_fin_rst);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_UDP, udp_timeout, aging_udp);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_ICMP, icmp_timeout, aging_icmp);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_AGING_OTHER, other_timeout, aging_other);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_LOG_MODE, log_mode, log_mode);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_SYSLOG, syslog_enabled, syslog_enabled);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_IPFIX, ipfix_enabled, ipfix_enabled);
  CGNAT_SET_FIELD (CGNAT_INSTANCE_SET_TCP_MSS, tcp_mss, tcp_mss);
#undef CGNAT_SET_FIELD
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

int
cgnat_plugin_enable_disable (u8 enable)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_interface_t *saved_interfaces = 0;
  cgnat_interface_t *i;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  u8 *pools_inited = 0;
  u32 ii, pi;
  int rv = 0, ret = 0;

  if (enable && clib_atomic_load_relax_n (&cm->enabled))
    return VNET_API_ERROR_VALUE_EXIST;

  if (!enable && !clib_atomic_load_relax_n (&cm->enabled))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_foreach (i, cm->interfaces)
    vec_add1 (saved_interfaces, *i);

  if (enable)
    {
      vlib_worker_thread_barrier_sync (cm->vlib_main);

      /* Re-create pool runtime state from preserved configuration.
       * Dynamic instances need blocks; deterministic instances only need the
       * public IP list. */
      vec_foreach_index (pi, cm->pools)
	{
	  cgnat_instance_t *owner;

	  pool = vec_elt_at_index (cm->pools, pi);
	  if (!pool->configured)
	    continue;
	  owner = cgnat_instance_get_by_index (cm, pool->owner_instance_index);
	  rv = cgnat_pool_runtime_init (
	    pool, !owner || owner->mode == CGNAT_INSTANCE_MODE_DYNAMIC);
	  if (rv)
	    {
	      ret = rv;
	      break;
	    }
	  vec_validate (pools_inited, pi);
	  pools_inited[pi] = 1;
	}

      if (ret)
	{
	  /* Roll back any pools that were successfully initialized. */
	  vec_foreach_index (pi, cm->pools)
	    {
	      if (pi < vec_len (pools_inited) && pools_inited[pi])
		cgnat_pool_runtime_reset_full (vec_elt_at_index (cm->pools, pi));
	    }
	  vec_free (pools_inited);
	  vlib_worker_thread_barrier_release (cm->vlib_main);
	  vec_free (saved_interfaces);
	  return ret;
	}
      vec_free (pools_inited);

      /* Recalculate instance-level block/user totals. */
      vec_foreach (instance, cm->instances)
	{
	  if (instance->configured)
	    cgnat_recalculate_instance (cm, instance);
	}

      /* Re-register /32 local receive entries so VPP answers ARP for pool
       * public IPs and static mapping outside IPs on outside interfaces. */
      cgnat_add_all_pool_fib_entries (cm);
      cgnat_add_all_static_fib_entries (cm);

      /* Re-enable interface features before marking enabled. */
      vec_foreach (i, saved_interfaces)
	{
	  if (i->flags & CGNAT_INTERFACE_FLAG_IS_INSIDE)
	    {
	      rv = ip4_sv_reass_enable_disable_with_refcnt (i->sw_if_index, 1);
	      if (rv && !ret)
		ret = rv;
	      rv = vnet_feature_enable_disable ("ip4-unicast",
						"cgnat-in2out-policy",
						i->sw_if_index, 1, 0, 0);
	      if (rv && !ret)
		ret = rv;
	    }
	  if (i->flags & CGNAT_INTERFACE_FLAG_IS_OUTSIDE)
	    {
	      rv = ip4_sv_reass_enable_disable_with_refcnt (i->sw_if_index, 1);
	      if (rv && !ret)
		ret = rv;
	      rv = vnet_feature_enable_disable ("ip4-unicast", "cgnat-out2in",
						i->sw_if_index, 1, 0, 0);
	      if (rv && !ret)
		ret = rv;
	    }
	}

      if (!ret)
	clib_atomic_store_rel_n (&cm->enabled, 1);
      else
	{
	  /* Feature enablement failed; roll back pool runtime state so a later
	   * enable attempt starts from a clean runtime. */
	  vec_foreach_index (pi, cm->pools)
	    {
	      pool = vec_elt_at_index (cm->pools, pi);
	      if (pool->configured)
		cgnat_pool_runtime_reset_full (pool);
	    }
	}

      vlib_worker_thread_barrier_release (cm->vlib_main);
      vec_free (saved_interfaces);
      return ret;
    }

  /* Disable path: keep instance/pool/interface configuration, but tear down
   * all runtime state (sessions, mappings, users, blocks, timers, FIB). */
  vlib_worker_thread_barrier_sync (cm->vlib_main);
  clib_atomic_store_rel_n (&cm->enabled, 0);

  /* 1. Delete all runtime objects tied to instances.  Static rules are kept
   *    as configuration; their cached mapping handles are reset. */
  vec_foreach_index (ii, cm->instances)
    {
      instance = vec_elt_at_index (cm->instances, ii);
      if (instance->configured)
	cgnat_instance_runtime_reset (cm, instance, ii);
    }

  /* 2. Free per-pool runtime structures (public IPs, blocks, bitmaps). */
  vec_foreach_index (pi, cm->pools)
    {
      pool = vec_elt_at_index (cm->pools, pi);
      if (pool->configured)
	cgnat_pool_runtime_reset_full (pool);
    }

  /* 3. Reset cooling timer wheel so no stale timers fire after runtime is freed. */
  cgnat_pba_reset (cm);

  /* 4. Reset global session/mapping tables and remove ARP/FIB entries. */
  cgnat_session_reset (cm);
  cgnat_del_all_fib_entry_regs (cm);

  vlib_worker_thread_barrier_release (cm->vlib_main);

  /* 4. Remove interface feature arcs now that workers are quiesced. */
  vec_foreach (i, saved_interfaces)
    {
      if (i->flags & CGNAT_INTERFACE_FLAG_IS_INSIDE)
	{
	  rv = vnet_feature_enable_disable ("ip4-unicast", "cgnat-in2out-policy",
					     i->sw_if_index, 0, 0, 0);
	  if (rv && !ret)
	    ret = rv;
	  rv = ip4_sv_reass_enable_disable_with_refcnt (i->sw_if_index, 0);
	  if (rv && !ret)
	    ret = rv;
	}
      if (i->flags & CGNAT_INTERFACE_FLAG_IS_OUTSIDE)
	{
	  rv = vnet_feature_enable_disable ("ip4-unicast", "cgnat-out2in",
					     i->sw_if_index, 0, 0, 0);
	  if (rv && !ret)
	    ret = rv;
	  rv = ip4_sv_reass_enable_disable_with_refcnt (i->sw_if_index, 0);
	  if (rv && !ret)
	    ret = rv;
	}
    }
  vec_free (saved_interfaces);

  return ret;
}

int
cgnat_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_interface_t *match = 0;
  u8 flag = is_inside ? CGNAT_INTERFACE_FLAG_IS_INSIDE :
				CGNAT_INTERFACE_FLAG_IS_OUTSIDE;
  char *feature_name = is_inside ? "cgnat-in2out-policy" : "cgnat-out2in";
  int rv;

  if (pool_is_free_index (cm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  match = cgnat_get_interface (cm, sw_if_index);

  if (is_add)
    {
      if (match && (match->flags & flag))
	return VNET_API_ERROR_VALUE_EXIST;

      /* CGNAT needs fragments reassembled before the policy node; enable
       * shallow virtual reassembly on the interface (refcounted, shared
       * with other consumers such as nat44). */
      rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
      if (rv)
	return rv;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
					sw_if_index, 1, 0, 0);
      if (rv)
	{
	  ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
	  return rv;
	}

      if (!match)
	{
	  /* Workers dereference cm->interfaces and
	   * interface_index_by_sw_if_index lock-free in the packet path, and
	   * pool/vec growth can realloc the backing store.  Mutate them only
	   * while the workers are paused. */
	  vlib_worker_thread_barrier_sync (cm->vlib_main);
	  pool_get_zero (cm->interfaces, match);
	  match->sw_if_index = sw_if_index;
	  vec_validate_init_empty (cm->interface_index_by_sw_if_index,
				   sw_if_index, CGNAT_INVALID_INDEX);
	  match->flags |= flag;
	  cm->interface_index_by_sw_if_index[sw_if_index] =
	    match - cm->interfaces;
	  vlib_worker_thread_barrier_release (cm->vlib_main);
	}
      else
	match->flags |= flag;

      /* Make VPP answer ARP for all pool public IPs and static mapping
       * outside IPs on this outside interface. */
      if (!is_inside)
	{
	  cgnat_add_all_pool_fib_entries_for_sw_if (cm, sw_if_index);
	  cgnat_add_static_fib_entries_for_sw_if (cm, sw_if_index);
	}
    }
  else
    {
      if (!match || !(match->flags & flag))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      rv = vnet_feature_enable_disable ("ip4-unicast", feature_name,
					sw_if_index, 0, 0, 0);
      if (rv)
	return rv;

      ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);

      /* Remove local receive entries before clearing the outside flag. */
      if (!is_inside)
	{
	  cgnat_del_all_pool_fib_entries_for_sw_if (cm, sw_if_index);
	  cgnat_del_static_fib_entries_for_sw_if (cm, sw_if_index);
	}

      match->flags &= ~flag;
      if (!match->flags)
	{
	  /* Pause workers before unlinking and freeing the interface entry;
	   * the packet path reads it lock-free. */
	  vlib_worker_thread_barrier_sync (cm->vlib_main);
	  cm->interface_index_by_sw_if_index[sw_if_index] =
	    CGNAT_INVALID_INDEX;
	  pool_put (cm->interfaces, match);
	  vlib_worker_thread_barrier_release (cm->vlib_main);
	}
    }

  return 0;
}

int
cgnat_interface_zone_set (u32 sw_if_index, cgnat_interface_role_t role)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_interface_t *match;
  u8 old_flags;
  int rv;

  if (pool_is_free_index (cm->vnet_main->interface_main.sw_interfaces, sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (role > CGNAT_INTERFACE_ROLE_OUTSIDE)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Single state snapshot; add_del may free the entry, so never reuse
   * the pointer past this point. */
  match = cgnat_get_interface (cm, sw_if_index);
  old_flags = match ? match->flags : 0;

  if (role == old_flags)
    return 0;
  
  if (old_flags == CGNAT_INTERFACE_ROLE_NONE)
  {
    return cgnat_interface_add_del (sw_if_index, role == CGNAT_INTERFACE_ROLE_INSIDE, 1);
  }
  else if (old_flags != CGNAT_INTERFACE_ROLE_NONE && role == CGNAT_INTERFACE_ROLE_NONE)
  {
    return cgnat_interface_add_del (sw_if_index, old_flags == CGNAT_INTERFACE_ROLE_INSIDE, 0);
  }
  else if (old_flags != CGNAT_INTERFACE_ROLE_NONE && role != CGNAT_INTERFACE_ROLE_NONE)
  {
    rv = cgnat_interface_add_del (sw_if_index, old_flags == CGNAT_INTERFACE_ROLE_INSIDE, 0);
    if (rv)
      return rv;
    return cgnat_interface_add_del (sw_if_index, role == CGNAT_INTERFACE_ROLE_INSIDE, 1);
  }
  return 0;
}

static_always_inline int
cgnat_instance_acl_add (cgnat_main_t *cm, u32 instance_index, u32 acl_index)
{
  u32 owner;

  /* Packet metadata carries only 15 bits; a flat vec beats a hash here. */
  vec_validate_init_empty (cm->instance_index_by_acl, 0x7fff,
			   CGNAT_INVALID_INDEX);
  owner = cm->instance_index_by_acl[acl_index];
  if (owner != CGNAT_INVALID_INDEX)
    return owner == instance_index ? VNET_API_ERROR_VALUE_EXIST :
				     VNET_API_ERROR_ADDRESS_IN_USE;

  cm->instance_index_by_acl[acl_index] = instance_index;
  return 0;
}

int
cgnat_instance_set_acl (u32 instance_index, u32 acl_index, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u32 *p;
  int rv;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* Index 0 means ACL miss; packet metadata can represent only 15 bits. */
  if (acl_index == 0 || acl_index > 0x7fff)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      if (!cgnat_acl_plugin.acl_exists (acl_index))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      vec_foreach (p, instance->acl_indices)
	if (*p == acl_index)
	  return VNET_API_ERROR_VALUE_EXIST;

      vlib_worker_thread_barrier_sync (cm->vlib_main);
      rv = cgnat_instance_acl_add (cm, instance_index, acl_index);
      if (rv)
	{
	  vlib_worker_thread_barrier_release (cm->vlib_main);
	  return rv;
	}

      vec_add1 (instance->acl_indices, acl_index);
      vlib_worker_thread_barrier_release (cm->vlib_main);
      return 0;
    }

  vec_foreach (p, instance->acl_indices)
    if (*p == acl_index)
      {
	vlib_worker_thread_barrier_sync (cm->vlib_main);
	vec_del1 (instance->acl_indices, p - instance->acl_indices);
	_cgnat_instance_acl_del (cm, acl_index);
	vlib_worker_thread_barrier_release (cm->vlib_main);
	return 0;
      }

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

void
cgnat_instance_clear_acls (u32 instance_index)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  u32 acl_index;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  while (vec_len (instance->acl_indices))
    {
      acl_index = instance->acl_indices[vec_len (instance->acl_indices) - 1];
      _cgnat_instance_acl_del (cm, acl_index);
      vec_del1 (instance->acl_indices, vec_len (instance->acl_indices) - 1);
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
}

int
cgnat_instance_syslog_server_add_del (u32 instance_index,
				      ip4_address_t address, u16 port,
				      u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_syslog_server_t *server;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (!address.as_u32 || !port)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_foreach (server, instance->syslog_servers)
    if (server->address.as_u32 == address.as_u32 && server->port == port)
      {
	if (is_add)
	  return VNET_API_ERROR_VALUE_EXIST;
	vlib_worker_thread_barrier_sync (cm->vlib_main);
	vec_del1 (instance->syslog_servers,
		  server - instance->syslog_servers);
	vlib_worker_thread_barrier_release (cm->vlib_main);
	return 0;
      }

  if (!is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_add2 (instance->syslog_servers, server, 1);
  server->address = address;
  server->port = port;
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

int
cgnat_instance_ipfix_exporter_add_del (
  u32 instance_index, ip4_address_t collector_address, u16 collector_port,
  ip4_address_t src_address, u16 src_port, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_ipfix_exporter_t *exporter;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (!collector_address.as_u32 || !collector_port || !src_address.as_u32 ||
      !src_port)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_foreach (exporter, instance->ipfix_exporters)
    if (exporter->collector_address.as_u32 == collector_address.as_u32 &&
	exporter->collector_port == collector_port &&
	exporter->src_address.as_u32 == src_address.as_u32 &&
	exporter->src_port == src_port)
      {
	if (is_add)
	  return VNET_API_ERROR_VALUE_EXIST;
	vlib_worker_thread_barrier_sync (cm->vlib_main);
	vec_del1 (instance->ipfix_exporters,
		  exporter - instance->ipfix_exporters);
	vlib_worker_thread_barrier_release (cm->vlib_main);
	return 0;
      }

  if (!is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_add2 (instance->ipfix_exporters, exporter, 1);
  exporter->collector_address = collector_address;
  exporter->collector_port = collector_port;
  exporter->src_address = src_address;
  exporter->src_port = src_port;
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
