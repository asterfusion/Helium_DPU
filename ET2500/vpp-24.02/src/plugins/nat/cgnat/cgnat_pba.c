/*
 * cgnat_pba.c - dynamic PBA block and port allocator
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <nat/cgnat/cgnat.h>

#define CGNAT_PBA_ALLOC_RETRIES 4
#define CGNAT_PBA_FALLBACK_PROBES 32

static_always_inline int
cgnat_pba_proto_index (u8 protocol)
{
  if (protocol == IP_PROTOCOL_TCP)
    return CGNAT_PBA_PROTO_TCP;
  if (protocol == IP_PROTOCOL_UDP)
    return CGNAT_PBA_PROTO_UDP;
  if (protocol == IP_PROTOCOL_ICMP)
    return CGNAT_PBA_PROTO_ICMP;
  return -1;
}

static_always_inline u8
cgnat_block_has_active_ports (cgnat_block_t *block)
{
  return block->active_ports[CGNAT_PBA_PROTO_TCP] ||
	 block->active_ports[CGNAT_PBA_PROTO_UDP] ||
	 block->active_ports[CGNAT_PBA_PROTO_ICMP];
}

static_always_inline u8
cgnat_user_has_active_ports (cgnat_user_t *user)
{
  return user->active_ports[CGNAT_PBA_PROTO_TCP] ||
	 user->active_ports[CGNAT_PBA_PROTO_UDP] ||
	 user->active_ports[CGNAT_PBA_PROTO_ICMP];
}

static_always_inline u16
cgnat_pool_start_port (cgnat_pool_t *pool)
{
  return pool->start_port ? pool->start_port : CGNAT_DEFAULT_START_PORT;
}

static_always_inline u16
cgnat_pool_end_port (cgnat_pool_t *pool)
{
  return pool->end_port ? pool->end_port : CGNAT_DEFAULT_END_PORT;
}

static u16
cgnat_effective_max_ports (cgnat_instance_t *instance,
			   cgnat_pool_t *pool)
{
  u32 by_blocks, max_ports = instance->per_user_max_ports;
  u16 max_blocks = instance->per_user_max_blocks;

  if (!max_blocks)
    max_blocks = pool->prealloc_blocks_per_user;
  if (!max_blocks)
    max_blocks = 1;

  by_blocks = clib_min (max_blocks * pool->block_size, 65535u);
  if (!max_ports || max_ports > by_blocks)
    max_ports = by_blocks;

  return (u16) max_ports;
}

static_always_inline u16
cgnat_prealloc_blocks (cgnat_pool_t *pool)
{
  return pool->prealloc_blocks_per_user ? pool->prealloc_blocks_per_user : 1;
}

static u16
cgnat_effective_max_blocks (cgnat_instance_t *instance,
			    cgnat_pool_t *pool)
{
  u32 blocks_by_ports;
  u16 max_blocks = instance->per_user_max_blocks;
  u16 max_ports = instance->per_user_max_ports;

  if (!max_blocks)
    max_blocks = pool->prealloc_blocks_per_user;
  if (!max_blocks)
    max_blocks = 1;

  if (!max_ports)
    return max_blocks;

  blocks_by_ports = (max_ports + pool->block_size - 1) / pool->block_size;
  return (u16) clib_min ((u32) max_blocks, blocks_by_ports);
}

static_always_inline u16
cgnat_blocks_needed_for_new_user (cgnat_instance_t *instance,
				  cgnat_pool_t *pool)
{
  if (pool->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC)
    return cgnat_prealloc_blocks (pool);

  return cgnat_effective_max_blocks (instance, pool);
}

static_always_inline u32
cgnat_public_ip_unavailable_blocks (cgnat_public_ip_t *ip)
{
  return ip->allocated_blocks + ip->cooling_blocks;
}

static_always_inline u32
cgnat_public_ip_free_blocks (cgnat_public_ip_t *ip)
{
  return ip->total_blocks - cgnat_public_ip_unavailable_blocks (ip);
}

static_always_inline u8
cgnat_public_ip_below_threshold (cgnat_public_ip_t *ip)
{
  return cgnat_public_ip_unavailable_blocks (ip) * 100 <
	 ip->total_blocks * CGNAT_DEFAULT_UTIL_THRESHOLD;
}

static_always_inline u32
cgnat_pool_unavailable_blocks (cgnat_pool_t *pool)
{
  return clib_atomic_load_relax_n (&pool->allocated_blocks) +
	 clib_atomic_load_relax_n (&pool->cooling_blocks);
}

static_always_inline u32
cgnat_pool_free_blocks (cgnat_pool_t *pool)
{
  return pool->total_blocks - cgnat_pool_unavailable_blocks (pool);
}

static_always_inline u32
cgnat_pool_alloc_weight (cgnat_pool_t *pool)
{
  if (!pool->configured)
    return 0;
  return cgnat_pool_free_blocks (pool) ? pool->total_blocks : 0;
}

static_always_inline void
cgnat_pool_counter_add (u32 *counter, i32 delta)
{
  u32 old, new;

  do
    {
      old = clib_atomic_load_relax_n (counter);
      if (delta < 0 && old < (u32) -delta)
	new = 0;
      else
	new = old + delta;
    }
  while (!clib_atomic_cmp_and_swap_acq_relax_n (counter, &old, new, 0));
}

static_always_inline void
cgnat_pool_allocated_blocks_add (cgnat_pool_t *pool, i32 delta)
{
  cgnat_pool_counter_add (&pool->allocated_blocks, delta);
}

static_always_inline void
cgnat_pool_cooling_blocks_add (cgnat_pool_t *pool, i32 delta)
{
  cgnat_pool_counter_add (&pool->cooling_blocks, delta);
}

static_always_inline void
cgnat_pool_active_users_add (cgnat_pool_t *pool, i32 delta)
{
  cgnat_pool_counter_add (&pool->active_users, delta);
}

static int
cgnat_util_cmp (u32 used_a, u32 total_a, u32 users_a, u32 used_b,
		u32 total_b, u32 users_b)
{
  u64 lhs, rhs;

  if (!total_a && !total_b)
    return 0;
  if (!total_a)
    return 1;
  if (!total_b)
    return -1;

  lhs = (u64) used_a * total_b;
  rhs = (u64) used_b * total_a;
  if (lhs < rhs)
    return -1;
  if (lhs > rhs)
    return 1;

  if (users_a < users_b)
    return -1;
  if (users_a > users_b)
    return 1;
  return 0;
}

static_always_inline u16
cgnat_block_start_port (cgnat_pool_t *pool, u16 block_id)
{
  return cgnat_pool_start_port (pool) + block_id * pool->block_size;
}

static_always_inline void
cgnat_log_pba_block (cgnat_instance_t *instance, char *event, char *reason,
		     ip4_address_t private_ip, ip4_address_t public_ip,
		     cgnat_pool_t *pool, cgnat_block_t *block,
		     u32 pool_index)
{
  cgnat_log_event_t log_event;
  u32 block_start, block_end;

  (void) pool_index;

  if (!instance || !pool || !block || !instance->syslog_enabled ||
      instance->log_mode != CGNAT_LOG_MODE_PORT_BLOCK)
    return;

  block_start = cgnat_block_start_port (pool, block->block_id);
  block_end = clib_min (block_start + pool->block_size - 1,
			(u32) cgnat_pool_end_port (pool));

  clib_memset (&log_event, 0, sizeof (log_event));
  log_event.kind = CGNAT_LOG_EVENT_KIND_PBA_BLOCK;
  cgnat_log_event_set_common (&log_event, instance, event, reason);
  log_event.block.private_ip = private_ip;
  log_event.block.public_ip = public_ip;
  log_event.block.public_port_start = (u16) block_start;
  log_event.block.public_port_end = (u16) block_end;
  cgnat_log_enqueue (&log_event);
}

static void
cgnat_pool_free_port_bitmap_init (cgnat_pool_t *pool)
{
  u32 i;

  if (pool->free_port_offset_bitmap[0] || pool->free_port_offset_bitmap[1])
    return;

  for (i = 0; i < pool->block_size; i++)
    pool->free_port_offset_bitmap[i & 1] =
      clib_bitmap_set (pool->free_port_offset_bitmap[i & 1], i, 1);
}

static void
cgnat_public_ip_runtime_init (cgnat_public_ip_t *ip, cgnat_pool_t *pool)
{
  u32 i;

  if (ip->total_blocks)
    return;

  ip->total_blocks =
    (cgnat_pool_end_port (pool) - cgnat_pool_start_port (pool) + 1) /
    pool->block_size;
  vec_validate_init_empty (ip->block_index_by_id, ip->total_blocks - 1,
			   CGNAT_INVALID_INDEX);
  for (i = 0; i < ip->total_blocks; i++)
    ip->free_block_bitmap = clib_bitmap_set (ip->free_block_bitmap, i, 1);

  clib_spinlock_init (&ip->lock);
}

int
cgnat_pool_runtime_init (cgnat_pool_t *pool, u8 create_blocks)
{
  u32 first, last, i, old_len, n_ips;
  cgnat_public_ip_t *ip;

  if (!pool->start_port)
    pool->start_port = CGNAT_DEFAULT_START_PORT;
  if (!pool->end_port)
    pool->end_port = CGNAT_DEFAULT_END_PORT;
  if (!pool->exclude_start_port && !pool->exclude_end_port)
    pool->exclude_end_port = CGNAT_DEFAULT_START_PORT - 1;

  if (pool->exclude_start_port)
    return VNET_API_ERROR_INVALID_VALUE;
  if (pool->start_port <= pool->exclude_end_port)
    return VNET_API_ERROR_INVALID_VALUE;
  if (pool->start_port > pool->end_port)
    return VNET_API_ERROR_INVALID_VALUE;

  if (create_blocks)
    {
      if (pool->port_alloc_mode > CGNAT_PORT_ALLOC_MODE_SEQUENCE)
	return VNET_API_ERROR_INVALID_VALUE;
      if (!pool->block_size || pool->block_size < 2)
	return VNET_API_ERROR_INVALID_VALUE;
      if (!is_pow2 (pool->exclude_end_port + 1))
	return VNET_API_ERROR_INVALID_VALUE;
      if (((pool->end_port - pool->start_port + 1) / pool->block_size) == 0)
	return VNET_API_ERROR_INVALID_VALUE;
    }

  first = clib_net_to_host_u32 (pool->first_ip.as_u32);
  last = clib_net_to_host_u32 (pool->last_ip.as_u32);
  if (first > last)
    return VNET_API_ERROR_INVALID_VALUE;

  n_ips = last - first + 1;
  if (n_ips > CGNAT_MAX_PUBLIC_IPS_PER_POOL)
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  if (create_blocks)
    cgnat_pool_free_port_bitmap_init (pool);

  old_len = vec_len (pool->public_ips);
  if (old_len >= n_ips)
    {
      if (create_blocks)
	return pool->total_blocks ? 0 : VNET_API_ERROR_NO_SUCH_ENTRY;
      return 0;
    }

  vec_validate (pool->public_ips, n_ips - 1);
  for (i = old_len; i < n_ips; i++)
    {
      ip = vec_elt_at_index (pool->public_ips, i);
      clib_memset (ip, 0, sizeof (*ip));
      ip->addr.as_u32 = clib_host_to_net_u32 (first + i);
      if (create_blocks)
	{
	  cgnat_public_ip_runtime_init (ip, pool);
	  pool->total_blocks += ip->total_blocks;
	}
    }

  return create_blocks && !pool->total_blocks ?
	   VNET_API_ERROR_NO_SUCH_ENTRY : 0;
}

static void cgnat_block_return_free (cgnat_pool_t *pool,
				     cgnat_public_ip_t *ip,
				     cgnat_block_t *block, u8 from_cooling);

void
cgnat_pool_runtime_reset (cgnat_pool_t *pool)
{
  cgnat_public_ip_t *ip;
  cgnat_block_t *block;
  u32 *block_indices = 0;
  u32 *bi;

  if (!pool || !pool->public_ips)
    return;

  vec_foreach (ip, pool->public_ips)
    {
      if (ip->blocks)
	{
	  pool_foreach (block, ip->blocks)
	    vec_add1 (block_indices, block - ip->blocks);

	  vec_foreach (bi, block_indices)
	    {
	      if (pool_is_free_index (ip->blocks, *bi))
		continue;
	      block = pool_elt_at_index (ip->blocks, *bi);
	      cgnat_block_return_free (pool, ip, block,
				       block->state == CGNAT_BLOCK_COOLING);
	    }
	  vec_reset_length (block_indices);
	}

      ip->active_users = 0;
    }
  vec_free (block_indices);

  clib_atomic_store_relax_n (&pool->active_users, 0);
  clib_atomic_store_relax_n (&pool->allocated_blocks, 0);
  clib_atomic_store_relax_n (&pool->cooling_blocks, 0);
}

static cgnat_pool_t *
cgnat_sample_pool_weighted (cgnat_main_t *cm, cgnat_instance_t *instance,
			    u32 *pool_index)
{
  cgnat_pool_t *pool;
  u64 total_weight = 0, cursor;
  u32 *index;

  vec_foreach (index, instance->pool_indices)
  {
    pool = cgnat_pool_get_by_index (cm, *index);
    if (!pool)
      continue;
    total_weight += cgnat_pool_alloc_weight (pool);
  }

  if (!total_weight)
    return 0;

  cursor = cgnat_instance_random_u32 (instance) % total_weight;
  vec_foreach (index, instance->pool_indices)
  {
    pool = cgnat_pool_get_by_index (cm, *index);
    if (!pool)
      continue;
    if (!cgnat_pool_alloc_weight (pool))
      continue;
    if (cursor < cgnat_pool_alloc_weight (pool))
    {
      *pool_index = *index;
      return pool;
    }
    cursor -= cgnat_pool_alloc_weight (pool);
  }

  return 0;
}

static cgnat_pool_t *
cgnat_select_pool_2choice (cgnat_main_t *cm, cgnat_instance_t *instance,
			   u32 *pool_index)
{
  cgnat_pool_t *a, *b;
  u32 ai = CGNAT_INVALID_INDEX, bi = CGNAT_INVALID_INDEX;

  a = cgnat_sample_pool_weighted (cm, instance, &ai);
  b = cgnat_sample_pool_weighted (cm, instance, &bi);

  if (!a)
  {
    *pool_index = bi;
    return b;
  }
  if (!b)
  {
    *pool_index = ai;
    return a;
  }

  if (cgnat_util_cmp (cgnat_pool_unavailable_blocks (a), a->total_blocks,
		      clib_atomic_load_relax_n (&a->active_users),
		      cgnat_pool_unavailable_blocks (b), b->total_blocks,
		      clib_atomic_load_relax_n (&b->active_users)) <= 0)
  {
    *pool_index = ai;
    return a;
  }

  *pool_index = bi;
  return b;
}

static int
cgnat_public_ip_better (cgnat_public_ip_t *a, cgnat_public_ip_t *b,
			u16 blocks_needed)
{
  u32 free_a = cgnat_public_ip_free_blocks (a);
  u32 free_b = cgnat_public_ip_free_blocks (b);
  u8 enough_a = free_a >= blocks_needed;
  u8 enough_b = free_b >= blocks_needed;
  u8 below_a = cgnat_public_ip_below_threshold (a);
  u8 below_b = cgnat_public_ip_below_threshold (b);

  if (below_a != below_b)
    return below_a;

  if (below_a && below_b)
    return clib_atomic_load_relax_n (&a->active_users) <=
	   clib_atomic_load_relax_n (&b->active_users);

  if (enough_a != enough_b)
    return enough_a;

  if (free_a != free_b)
    return free_a > free_b;

  return cgnat_util_cmp (cgnat_public_ip_unavailable_blocks (a),
			 a->total_blocks,
			 clib_atomic_load_relax_n (&a->active_users),
			 cgnat_public_ip_unavailable_blocks (b),
			 b->total_blocks,
			 clib_atomic_load_relax_n (&b->active_users)) <= 0;
}

static cgnat_public_ip_t *
cgnat_select_public_ip_2choice (cgnat_instance_t *instance,
				cgnat_pool_t *pool,
				u16 blocks_needed, u32 *public_ip_index)
{
  cgnat_public_ip_t *a, *b;
  u32 n_ips = vec_len (pool->public_ips);
  u32 ai, bi;

  if (!n_ips)
    return 0;

  ai = cgnat_instance_random_u32 (instance) % n_ips;
  bi = n_ips > 1 ? cgnat_instance_random_u32 (instance) % n_ips : ai;
  a = vec_elt_at_index (pool->public_ips, ai);
  b = vec_elt_at_index (pool->public_ips, bi);

  if (!cgnat_public_ip_free_blocks (a) && !cgnat_public_ip_free_blocks (b))
    return 0;
  if (!cgnat_public_ip_free_blocks (a))
    {
      *public_ip_index = bi;
      return b;
    }
  if (!cgnat_public_ip_free_blocks (b))
    {
      *public_ip_index = ai;
      return a;
    }

  if (cgnat_public_ip_better (a, b, blocks_needed))
    {
      *public_ip_index = ai;
      return a;
    }

  *public_ip_index = bi;
  return b;
}

static cgnat_public_ip_t *
cgnat_fallback_select_public_ip (cgnat_main_t *cm, cgnat_instance_t *instance,
				 u32 *pool_index,
				 u32 *public_ip_index)
{
  cgnat_pool_t *pool;
  cgnat_public_ip_t *ip;
  u16 blocks_needed;
  u32 i;

  for (i = 0; i < CGNAT_PBA_FALLBACK_PROBES; i++)
    {
      pool = cgnat_select_pool_2choice (cm, instance, pool_index);
      if (!pool)
	continue;

      blocks_needed = cgnat_blocks_needed_for_new_user (instance, pool);
      
      ip = cgnat_select_public_ip_2choice (instance, pool, blocks_needed,
					   public_ip_index);
      if (ip)
	      return ip;
    }

  return 0;
}

static cgnat_block_t *
cgnat_public_ip_alloc_block (cgnat_pool_t *pool, cgnat_public_ip_t *ip,
			     u32 user_index)
{
  cgnat_block_t *block;
  uword block_id = clib_bitmap_first_set (ip->free_block_bitmap);

  if (block_id == ~0 || block_id >= ip->total_blocks)
    return 0;

  u32 i;

  pool_get_zero (ip->blocks, block);
  block->block_id = block_id;
  block->state = CGNAT_BLOCK_ALLOCATED;
  block->owner_user_index = user_index;
  for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
    {
      block->free_port_bitmap[i][0] =
	clib_bitmap_dup (pool->free_port_offset_bitmap[0]);
      block->free_port_bitmap[i][1] =
	clib_bitmap_dup (pool->free_port_offset_bitmap[1]);
    }
  ip->block_index_by_id[block_id] = block - ip->blocks;
  ip->free_block_bitmap =
    clib_bitmap_set (ip->free_block_bitmap, block_id, 0);
  ip->allocated_blocks++;
  cgnat_pool_allocated_blocks_add (pool, 1);

  return block;
}

static int
cgnat_alloc_port_from_block (cgnat_instance_t *instance,
			     cgnat_pool_t *pool,
			     cgnat_block_t *block, u16 private_port,
			     u8 protocol, u16 *public_port)
{
  u32 block_start, offset = ~0;
  u8 offset_odd;
  int proto_index;
  clib_bitmap_t *free_ports;

  proto_index = cgnat_pba_proto_index (protocol);
  if (proto_index < 0)
    return VNET_API_ERROR_UNSUPPORTED;

  if (block->active_ports[proto_index] >= pool->block_size)
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  block_start = cgnat_block_start_port (pool, block->block_id);
  offset_odd = (private_port ^ block_start) & 1;
  free_ports = block->free_port_bitmap[proto_index][offset_odd];

  if (pool->port_alloc_mode == CGNAT_PORT_ALLOC_MODE_RANDOM)
  {
    u32 start = cgnat_instance_random_u32 (instance) % pool->block_size;
    offset = clib_bitmap_next_set (free_ports, start);

    if (offset == ~0)
      offset = clib_bitmap_first_set (free_ports);
  }
  else
    offset = clib_bitmap_first_set (free_ports);

  if (offset == ~0)
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  block->free_port_bitmap[proto_index][offset_odd] =
    clib_bitmap_set (block->free_port_bitmap[proto_index][offset_odd], offset, 0);

  block->active_ports[proto_index]++;
  *public_port = block_start + offset;
  return 0;
}

static void
cgnat_block_free_port_bitmaps (cgnat_block_t *block)
{
  u32 i;

  for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
    {
      clib_bitmap_free (block->free_port_bitmap[i][0]);
      clib_bitmap_free (block->free_port_bitmap[i][1]);
      block->free_port_bitmap[i][0] = 0;
      block->free_port_bitmap[i][1] = 0;
    }
}

static void
cgnat_user_remove_owned_block (cgnat_user_t *user, u16 block_id)
{
  u32 i;

  for (i = 0; i < vec_len (user->owned_block_ids); i++)
    {
      if (user->owned_block_ids[i] == block_id)
	{
	  vec_del1 (user->owned_block_ids, i);
	  return;
	}
    }
}

void
cgnat_delete_user (cgnat_instance_t *instance, cgnat_user_t *user);

static void
cgnat_start_block_cooling (cgnat_main_t *cm, u32 instance_index,
			   u32 pool_index, u32 public_ip_index,
			   cgnat_pool_t *pool, cgnat_public_ip_t *ip,
			   cgnat_block_t *block, ip4_address_t private_ip);

static void
cgnat_delete_user_if_idle (cgnat_instance_t *instance, cgnat_user_t *user)
{
  if (!cgnat_user_has_active_ports (user) && !user->active_sessions &&
      !vec_len (user->owned_block_ids))
    cgnat_delete_user (instance, user);
}

static void
cgnat_block_return_free (cgnat_pool_t *pool, cgnat_public_ip_t *ip,
			 cgnat_block_t *block,
			 u8 from_cooling)
{
  ip->block_index_by_id[block->block_id] = CGNAT_INVALID_INDEX;
  ip->free_block_bitmap =
    clib_bitmap_set (ip->free_block_bitmap, block->block_id, 1);

  if (from_cooling)
    {
      ip->cooling_blocks--;
      cgnat_pool_cooling_blocks_add (pool, -1);
    }
  else
    {
      ip->allocated_blocks--;
      cgnat_pool_allocated_blocks_add (pool, -1);
    }

  cgnat_block_free_port_bitmaps (block);
  pool_put (ip->blocks, block);
}

static void
cgnat_reactivate_cooling_block (cgnat_pool_t *pool, cgnat_public_ip_t *ip,
				cgnat_block_t *block)
{
  u32 i;

  block->state = CGNAT_BLOCK_ALLOCATED;
  /* Leave the old timer in the wheel; gen_id makes it expire as stale. */
  block->gen_id++;
  for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
    {
      block->free_port_bitmap[i][0] =
	clib_bitmap_dup (pool->free_port_offset_bitmap[0]);
      block->free_port_bitmap[i][1] =
	clib_bitmap_dup (pool->free_port_offset_bitmap[1]);
    }

  ip->cooling_blocks--;
  cgnat_pool_cooling_blocks_add (pool, -1);
  ip->allocated_blocks++;
  cgnat_pool_allocated_blocks_add (pool, 1);
}

static_always_inline u8
cgnat_prealloc_user_idle (cgnat_user_t *user)
{
  return user && user->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC &&
	 !cgnat_user_has_active_ports (user) && !user->active_sessions &&
	 vec_len (user->owned_block_ids);
}

static void
cgnat_reactivate_prealloc_user_blocks (cgnat_instance_t *instance,
				       cgnat_pool_t *pool, cgnat_public_ip_t *ip,
				       cgnat_user_t *user)
{
  u16 *block_id;

  vec_foreach (block_id, user->owned_block_ids)
    {
      u32 block_index;
      cgnat_block_t *block;

      if (*block_id >= vec_len (ip->block_index_by_id))
	continue;
      block_index = ip->block_index_by_id[*block_id];
      if (block_index == CGNAT_INVALID_INDEX ||
	  pool_is_free_index (ip->blocks, block_index))
	continue;

      block = pool_elt_at_index (ip->blocks, block_index);
      if (block->owner_user_index != (u32) (user - instance->users) ||
	  block->state != CGNAT_BLOCK_COOLING)
	continue;

      cgnat_reactivate_cooling_block (pool, ip, block);
      cgnat_log_pba_block (instance, "PBA_BLOCK_ALLOC", 0,
			   user->key.private_ip, ip->addr, pool, block,
			   user->pool_index);
    }
}

static void
cgnat_start_prealloc_user_cooling (cgnat_main_t *cm,
				   cgnat_instance_t *instance,
				   u32 instance_index, u32 pool_index,
				   u32 public_ip_index, cgnat_pool_t *pool,
				   cgnat_public_ip_t *ip, cgnat_user_t *user)
{
  u16 *owned_block_ids = 0;
  u16 *block_id;
  u32 user_index = user - instance->users;
  ip4_address_t private_ip = user->key.private_ip;

  vec_append (owned_block_ids, user->owned_block_ids);
  vec_foreach (block_id, owned_block_ids)
    {
      u32 block_index;
      cgnat_block_t *block;

      if (*block_id >= vec_len (ip->block_index_by_id))
	continue;
      block_index = ip->block_index_by_id[*block_id];
      if (block_index == CGNAT_INVALID_INDEX ||
	  pool_is_free_index (ip->blocks, block_index))
	continue;

      block = pool_elt_at_index (ip->blocks, block_index);
      if (block->owner_user_index != user_index ||
	  block->state != CGNAT_BLOCK_ALLOCATED ||
	  cgnat_block_has_active_ports (block))
	continue;

      cgnat_start_block_cooling (cm, instance_index, pool_index,
				 public_ip_index, pool, ip, block,
				 private_ip);
    }
  vec_free (owned_block_ids);
}

static void
cgnat_cooling_process_expired (u32 *expired_timers)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_cooling_timer_t *entry;
  u32 i, entry_index, processed = 0;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      cgnat_instance_t *instance;
      cgnat_pool_t *pool;
      cgnat_public_ip_t *ip;
      cgnat_block_t *block;

      entry_index = expired_timers[i] & 0x7FFFFFFF;
      if (processed >= CGNAT_COOLING_TIMER_MAX_EXPIRATIONS)
	{
	  if (!pool_is_free_index (cm->cooling_timers, entry_index))
	    tw_timer_start_2t_1w_2048sl (&cm->cooling_timer_wheel,
					 entry_index, 0, 1);
	  continue;
	}

      processed++;
      if (pool_is_free_index (cm->cooling_timers, entry_index))
	continue;

      entry = pool_elt_at_index (cm->cooling_timers, entry_index);
      instance = cgnat_instance_get_by_index (cm, entry->instance_index);
      if (!instance)
	goto done;
      pool = cgnat_pool_get_by_index (cm, entry->pool_index);
      if (!pool || pool->owner_instance_index != entry->instance_index)
	goto done;
      if (entry->public_ip_index >= vec_len (pool->public_ips))
	goto done;

      ip = vec_elt_at_index (pool->public_ips, entry->public_ip_index);
      cgnat_user_lock (instance, entry->inside_fib_index, entry->private_ip);
      clib_spinlock_lock (&ip->lock);

      if (entry->block_index < vec_len (ip->blocks) &&
	  !pool_is_free_index (ip->blocks, entry->block_index))
	{
	  block = pool_elt_at_index (ip->blocks, entry->block_index);
	  if (block->state == CGNAT_BLOCK_COOLING &&
	      block->block_id == entry->block_id &&
	      block->gen_id == entry->gen_id)
	    {
	      if (entry->remaining_time)
		{
		  u16 delay = clib_min (entry->remaining_time,
					CGNAT_TIMER_MAX_DELAY);
		  entry->remaining_time -= delay;
		  tw_timer_start_2t_1w_2048sl (&cm->cooling_timer_wheel,
					       entry_index, 0, delay);
		  clib_spinlock_unlock (&ip->lock);
		  cgnat_user_unlock (instance, entry->inside_fib_index,
				     entry->private_ip);
		  continue;
		}
	      if (!pool_is_free_index (instance->users,
				       block->owner_user_index))
		{
		  cgnat_user_t *user =
		    pool_elt_at_index (instance->users,
				       block->owner_user_index);
		  cgnat_user_remove_owned_block (user, block->block_id);
		  cgnat_delete_user_if_idle (instance, user);
		}
	      cgnat_log_pba_block (instance, "PBA_BLOCK_RELEASE",
				   "cooling_expire", entry->private_ip,
				   ip->addr, pool, block, entry->pool_index);
	      cgnat_block_return_free (pool, ip, block, 1);
	    }
	}

      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, entry->inside_fib_index,
			 entry->private_ip);

    done:
      pool_put_index (cm->cooling_timers, entry_index);
    }
}

static void
cgnat_start_block_cooling (cgnat_main_t *cm, u32 instance_index,
			   u32 pool_index, u32 public_ip_index,
			   cgnat_pool_t *pool, cgnat_public_ip_t *ip,
			   cgnat_block_t *block, ip4_address_t private_ip)
{
  cgnat_cooling_timer_t *entry;
  u32 entry_index;

  block->gen_id++;
  block->active_ports[CGNAT_PBA_PROTO_TCP] = 0;
  block->active_ports[CGNAT_PBA_PROTO_UDP] = 0;
  block->active_ports[CGNAT_PBA_PROTO_ICMP] = 0;

  if (!pool->cooling_time)
    {
      cgnat_instance_t *instance =
	cgnat_instance_get_by_index (cm, instance_index);
      if (!instance)
	return;
      if (!pool_is_free_index (instance->users, block->owner_user_index))
	{
	  cgnat_user_t *user =
	    pool_elt_at_index (instance->users, block->owner_user_index);
	  cgnat_user_remove_owned_block (user, block->block_id);
	  cgnat_delete_user_if_idle (instance, user);
	}

      cgnat_log_pba_block (instance, "PBA_BLOCK_RELEASE", "idle",
			   private_ip, ip->addr, pool, block, pool_index);
      cgnat_block_return_free (pool, ip, block, 0);
      return;
    }

  /* Keep owner_user_index while cooling so the same user can revive it. */
  block->state = CGNAT_BLOCK_COOLING;
  cgnat_block_free_port_bitmaps (block);

  ip->allocated_blocks--;
  ip->cooling_blocks++;
  cgnat_pool_allocated_blocks_add (pool, -1);
  cgnat_pool_cooling_blocks_add (pool, 1);
  cgnat_log_pba_block (cgnat_instance_get_by_index (cm, instance_index),
		       "PBA_BLOCK_RELEASE", "idle", private_ip, ip->addr,
		       pool, block, pool_index);
  pool_get_zero (cm->cooling_timers, entry);
  entry_index = entry - cm->cooling_timers;
  entry->instance_index = instance_index;
  entry->pool_index = pool_index;
  entry->public_ip_index = public_ip_index;
  entry->block_index = block - ip->blocks;
  entry->block_id = block->block_id;
  entry->gen_id = block->gen_id;
  entry->inside_fib_index = CGNAT_INVALID_INDEX;
  entry->private_ip = private_ip;
  if (instance_index < vec_len (cm->instances) &&
      !pool_is_free_index (cm->instances[instance_index].users,
			   block->owner_user_index))
    {
      cgnat_user_t *user =
	pool_elt_at_index (cm->instances[instance_index].users,
			   block->owner_user_index);
      entry->inside_fib_index = user->key.fib_index;
    }
  entry->remaining_time =
    pool->cooling_time > CGNAT_TIMER_MAX_DELAY ?
      pool->cooling_time - CGNAT_TIMER_MAX_DELAY :
      0;

  tw_timer_start_2t_1w_2048sl (&cm->cooling_timer_wheel, entry_index, 0,
			       clib_min (pool->cooling_time,
				 CGNAT_TIMER_MAX_DELAY));
}

void
cgnat_pba_init (cgnat_main_t *cm)
{
  if (cm->cooling_timer_initialized)
    return;

  /* No wheel callback: expired timers are collected directly with
   * tw_timer_expire_timers_vec_2t_1w_2048sl(). */
  tw_timer_wheel_init_2t_1w_2048sl (&cm->cooling_timer_wheel, 0, 1.0,
				    CGNAT_COOLING_TIMER_MAX_EXPIRATIONS);
  cm->cooling_timer_initialized = 1;
}

void
cgnat_pba_reset (cgnat_main_t *cm)
{
  pool_free (cm->cooling_timers);
  if (cm->cooling_timer_initialized)
    {
      tw_timer_wheel_free_2t_1w_2048sl (&cm->cooling_timer_wheel);
      cm->cooling_timer_initialized = 0;
    }

  cgnat_pba_init (cm);
}

void
cgnat_pba_expire_timers (f64 now)
{
  cgnat_main_t *cm = &cgnat_main;

  if (!cm->cooling_timer_initialized)
    return;

  u32 *expired = vec_new(u32, CGNAT_COOLING_TIMER_MAX_EXPIRATIONS);
  expired = tw_timer_expire_timers_vec_2t_1w_2048sl ( &cm->cooling_timer_wheel, now, expired);
  cgnat_cooling_process_expired (expired);
  vec_free (expired);
}

static cgnat_user_t *
cgnat_find_user (cgnat_instance_t *instance, cgnat_user_key_t *key)
{
  uword *p;
  cgnat_user_t *user = 0;

  clib_spinlock_lock (&instance->users_lock);
  if (instance->user_index_by_key)
    {
      p = hash_get_mem (instance->user_index_by_key, key);
      if (p)
	user = pool_elt_at_index (instance->users, p[0]);
    }
  clib_spinlock_unlock (&instance->users_lock);

  return user;
}

static cgnat_user_t *
cgnat_create_user (cgnat_instance_t *instance, cgnat_user_key_t *key,
		   u32 pool_index)
{
  cgnat_user_t *user;

  clib_spinlock_lock (&instance->users_lock);
  if (!instance->user_index_by_key)
    instance->user_index_by_key =
      hash_create_mem (0, sizeof (cgnat_user_key_t), sizeof (uword));

  pool_get_zero (instance->users, user);
  user->key = *key;
  user->pool_index = pool_index;
  user->public_ip_index = CGNAT_INVALID_INDEX;
  clib_spinlock_init (&user->session_lock);
  clib_spinlock_unlock (&instance->users_lock);

  return user;
}

static_always_inline void
cgnat_commit_user (cgnat_instance_t *instance, cgnat_user_t *user)
{
  clib_spinlock_lock (&instance->users_lock);
  hash_set_mem_alloc (&instance->user_index_by_key, &user->key,
		      user - instance->users);
  clib_spinlock_unlock (&instance->users_lock);
}

void
cgnat_delete_user (cgnat_instance_t *instance, cgnat_user_t *user)
{
  uword *p;
  u32 user_index;

  clib_spinlock_lock (&instance->users_lock);
  p = hash_get_mem (instance->user_index_by_key, &user->key);
  user_index = user - instance->users;

  if (p && p[0] == user_index)
    {
      cgnat_pool_t *pool =
	cgnat_pool_get_by_index (&cgnat_main, user->pool_index);

      if (pool && user->public_ip_index < vec_len (pool->public_ips))
	{
	  cgnat_public_ip_t *ip =
	    vec_elt_at_index (pool->public_ips, user->public_ip_index);

	  /* Some deletion paths (idle timeout, instance teardown) run
	   * without ip->lock held; keep the counter atomic to avoid lost
	   * updates against the bind path. */
	  if (clib_atomic_load_relax_n (&ip->active_users))
	    clib_atomic_fetch_add (&ip->active_users, -1);
	  cgnat_pool_active_users_add (pool, -1);
	}
    }

  hash_unset_mem_free (&instance->user_index_by_key, &user->key);
  vec_free (user->owned_block_ids);
  {
    int i;
    for (i = 0; i < CGNAT_PBA_PROTO_COUNT; i++)
      clib_bitmap_free (user->det_port_bitmap[i]);
  }
  clib_spinlock_free (&user->session_lock);
  pool_put (instance->users, user);
  clib_spinlock_unlock (&instance->users_lock);
}

void
cgnat_pba_release_user_if_idle (u32 instance_index, u32 inside_fib_index,
				ip4_address_t private_ip)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_public_ip_t *ip;
  cgnat_user_key_t key;
  cgnat_user_t *user;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return;

  cgnat_user_lock (instance, inside_fib_index, private_ip);
  key.fib_index = inside_fib_index;
  key.private_ip = private_ip;
  user = cgnat_find_user (instance, &key);
  if (!user)
    {
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return;
    }

  if (vec_len (user->owned_block_ids))
    {
      /* Pre-allocated dynamic user: cool all owned blocks when fully idle. */
      if (!cgnat_prealloc_user_idle (user))
	{
	  cgnat_user_unlock (instance, inside_fib_index, private_ip);
	  return;
	}

      pool = cgnat_pool_get_by_index (cm, user->pool_index);
      if (!pool || user->public_ip_index >= vec_len (pool->public_ips))
	{
	  cgnat_user_unlock (instance, inside_fib_index, private_ip);
	  return;
	}

      ip = vec_elt_at_index (pool->public_ips, user->public_ip_index);
      clib_spinlock_lock (&ip->lock);
      if (cgnat_prealloc_user_idle (user))
	cgnat_start_prealloc_user_cooling (cm, instance, instance_index,
					   user->pool_index, user->public_ip_index,
					   pool, ip, user);
      clib_spinlock_unlock (&ip->lock);
    }
  else
    {
      /* On-demand dynamic or deterministic user: delete when fully idle. */
      if (!cgnat_user_has_active_ports (user) && !user->active_sessions)
	cgnat_delete_user (instance, user);
    }

  cgnat_user_unlock (instance, inside_fib_index, private_ip);
}

static u16
cgnat_prealloc_blocks_for_user (cgnat_instance_t *instance,
				cgnat_pool_t *pool, cgnat_public_ip_t *ip,
				cgnat_user_t *user, u32 pool_index)
{
  cgnat_block_t *block;
  u16 count = 0;

  while (vec_len (user->owned_block_ids) < user->max_blocks &&
	 cgnat_public_ip_free_blocks (ip))
    {
      block = cgnat_public_ip_alloc_block (pool, ip, user - instance->users);
      if (!block)
        break;

      vec_add1 (user->owned_block_ids, block->block_id);
      cgnat_log_pba_block (instance, "PBA_BLOCK_ALLOC", 0,
			   user->key.private_ip, ip->addr, pool, block,
			   pool_index);
      count++;
    }

  return count;
}

static int
cgnat_bind_user_to_public_ip (cgnat_instance_t *instance, u32 instance_index,
			      u32 pool_index, u32 public_ip_index,
			      cgnat_pool_t *pool, cgnat_public_ip_t *ip,
			      cgnat_user_t *user)
{
  cgnat_block_t *block;

  user->instance_index = instance_index;
  user->pool_index = pool_index;
  user->public_ip_index = public_ip_index;
  if (pool->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC)
  {
    user->max_blocks = cgnat_prealloc_blocks (pool);
  }
  else
  {
    user->max_blocks = cgnat_effective_max_blocks (instance, pool);
    user->max_ports = cgnat_effective_max_ports (instance, pool);
  }
  user->block_alloc_mode = pool->block_alloc_mode;

  clib_spinlock_lock (&ip->lock);
  if (pool->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC)
  {
    u16 allocated_blocks =
    cgnat_prealloc_blocks_for_user (instance, pool, ip, user, pool_index);
    if (!allocated_blocks)
    {
      clib_spinlock_unlock (&ip->lock);
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

    /* Cap the quota at the configured effective maximum, and compute the
     * port quota in u32 before clamping to u16 - a plain
     * allocated_blocks * block_size product can exceed 65535 and would be
     * truncated when stored into the u16 max_ports. */
    user->max_blocks = clib_min (allocated_blocks,
				 cgnat_effective_max_blocks (instance, pool));
    user->max_ports =
      (u16) clib_min ((u32) user->max_blocks * pool->block_size,
		      (u32) cgnat_effective_max_ports (instance, pool));
  }
  else
  {
    block = cgnat_public_ip_alloc_block (pool, ip, user - instance->users);
    if (!block)
    {
      clib_spinlock_unlock (&ip->lock);
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }
    vec_add1 (user->owned_block_ids, block->block_id);
    cgnat_log_pba_block (instance, "PBA_BLOCK_ALLOC", 0,
        user->key.private_ip, ip->addr, pool, block,
        pool_index);
  }

  clib_atomic_fetch_add (&ip->active_users, 1);
  cgnat_pool_active_users_add (pool, 1);
  clib_spinlock_unlock (&ip->lock);
  return 0;
}

/* Roll back a newly committed user whose first port allocation failed. */
static void
cgnat_rollback_new_user (cgnat_instance_t *instance, cgnat_pool_t *pool,
			 cgnat_public_ip_t *ip, cgnat_user_t *user)
{
  u16 *block_id;

  clib_spinlock_lock (&ip->lock);
  vec_foreach (block_id, user->owned_block_ids)
    {
      u32 block_index;
      cgnat_block_t *block;

      if (*block_id >= vec_len (ip->block_index_by_id))
	continue;
      block_index = ip->block_index_by_id[*block_id];
      if (block_index == CGNAT_INVALID_INDEX ||
	  pool_is_free_index (ip->blocks, block_index))
	continue;
      block = pool_elt_at_index (ip->blocks, block_index);
      if (block->owner_user_index != (u32) (user - instance->users) ||
	  block->state != CGNAT_BLOCK_ALLOCATED ||
	  cgnat_block_has_active_ports (block))
	continue;
      cgnat_log_pba_block (instance, "PBA_BLOCK_RELEASE", "force_delete",
			   user->key.private_ip, ip->addr, pool, block,
			   user->pool_index);
      cgnat_block_return_free (pool, ip, block, 0);
    }
  vec_reset_length (user->owned_block_ids);
  cgnat_delete_user (instance, user);
  clib_spinlock_unlock (&ip->lock);
}

static int
cgnat_alloc_port_for_user (cgnat_main_t *cm, cgnat_instance_t *instance,
			   cgnat_user_t *user, u16 private_port,
			   u8 protocol,
			   cgnat_pba_alloc_result_t *result)
{
  cgnat_pool_t *pool;
  cgnat_public_ip_t *ip;
  cgnat_block_t *block = 0;
  u16 public_port;
  u32 i, bi;
  int proto_index;
  int rv = VNET_API_ERROR_LIMIT_EXCEEDED;

  proto_index = cgnat_pba_proto_index (protocol);
  if (proto_index < 0)
    return VNET_API_ERROR_UNSUPPORTED;

  if (user->active_ports[proto_index] >= user->max_ports)
    {
      user->port_block_drops++;
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

  pool = cgnat_pool_get_by_index (cm, user->pool_index);
  if (!pool)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (user->public_ip_index >= vec_len (pool->public_ips))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  ip = vec_elt_at_index (pool->public_ips, user->public_ip_index);

  clib_spinlock_lock (&ip->lock);

  for (i = 0; i < vec_len (user->owned_block_ids); i++)
    {
      u16 block_id = user->owned_block_ids[i];
      bi = ip->block_index_by_id[block_id];
      if (bi == CGNAT_INVALID_INDEX)
	continue;
      block = pool_elt_at_index (ip->blocks, bi);
      if (block->owner_user_index != user - instance->users)
	continue;

      if (block->state == CGNAT_BLOCK_COOLING)
	{
	  if (user->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC)
	    cgnat_reactivate_prealloc_user_blocks (instance, pool, ip, user);
	  else
	    {
	      cgnat_reactivate_cooling_block (pool, ip, block);
	      cgnat_log_pba_block (instance, "PBA_BLOCK_ALLOC", 0,
				   user->key.private_ip, ip->addr, pool, block,
				   user->pool_index);
	    }
	}
      else if (block->state != CGNAT_BLOCK_ALLOCATED)
	continue;

      rv = cgnat_alloc_port_from_block (instance, pool, block, private_port,
					protocol, &public_port);

      if (!rv)
	goto done;
    }

  if (user->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_ON_DEMAND &&
      vec_len (user->owned_block_ids) < user->max_blocks)
    {
      block = cgnat_public_ip_alloc_block (pool, ip, user - instance->users);
      if (!block)
	{
	  rv = VNET_API_ERROR_LIMIT_EXCEEDED;
	  goto done;
	}

      vec_add1 (user->owned_block_ids, block->block_id);
      cgnat_log_pba_block (instance, "PBA_BLOCK_ALLOC", 0,
			   user->key.private_ip, ip->addr, pool, block,
			   user->pool_index);
      rv = cgnat_alloc_port_from_block (instance, pool, block, private_port,
					protocol, &public_port);
    }

  /* PRE_ALLOC: blocks reclaimed by the cooling timer are removed from
   * owned_block_ids, so a user returning after an idle period would
   * otherwise keep a permanently shrunken capacity.  Top back up to the
   * user's quota before giving up. */
  if (user->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC &&
      vec_len (user->owned_block_ids) < user->max_blocks)
    {
      u16 old_owned = vec_len (user->owned_block_ids);

      cgnat_prealloc_blocks_for_user (instance, pool, ip, user,
				      user->pool_index);
      for (i = old_owned; i < vec_len (user->owned_block_ids); i++)
	{
	  u16 block_id = user->owned_block_ids[i];

	  bi = ip->block_index_by_id[block_id];
	  if (bi == CGNAT_INVALID_INDEX)
	    continue;
	  block = pool_elt_at_index (ip->blocks, bi);
	  if (block->owner_user_index != user - instance->users ||
	      block->state != CGNAT_BLOCK_ALLOCATED)
	    continue;

	  rv = cgnat_alloc_port_from_block (instance, pool, block,
					    private_port, protocol,
					    &public_port);
	  if (!rv)
	    goto done;
	}
    }

done:
  if (rv == VNET_API_ERROR_LIMIT_EXCEEDED)
    user->port_block_drops++;
  if (!rv)
    {
      user->active_ports[proto_index]++;
      result->public_ip = ip->addr;
      result->public_port = public_port;
      result->pool_index = user->pool_index;
      result->public_ip_index = user->public_ip_index;
      result->user_index = user - instance->users;
      result->block_index = block - ip->blocks;
    }
  clib_spinlock_unlock (&ip->lock);
  return rv;
}

int
cgnat_pba_alloc_port_locked (u32 instance_index, u32 fib_index,
			     ip4_address_t private_ip, u16 private_port,
			     u8 protocol,
			     cgnat_pba_alloc_result_t *result)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_public_ip_t *ip;
  cgnat_user_key_t key;
  cgnat_user_t *user;
  u32 pool_index, public_ip_index, retry;
  u16 blocks_needed;
  int rv;

  if (!result)
    return VNET_API_ERROR_INVALID_VALUE;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  clib_memset (result, 0xff, sizeof (*result));

  key.fib_index = fib_index;
  key.private_ip = private_ip;
  user = cgnat_find_user (instance, &key);
  // if user exists, rapidly search
  if (user)
    return cgnat_alloc_port_for_user (cm, instance, user, private_port,
			      protocol, result);

  // alloc public_ip for new user
  for (retry = 0; retry < CGNAT_PBA_ALLOC_RETRIES; retry++)
  {
    // select pool
    pool = cgnat_select_pool_2choice (cm, instance, &pool_index);
    if (!pool)
      continue;

    blocks_needed = cgnat_blocks_needed_for_new_user (instance, pool);
    
    ip = cgnat_select_public_ip_2choice (instance, pool, blocks_needed,
            &public_ip_index);
    if (!ip)
      continue;

    user = cgnat_create_user (instance, &key, pool_index);

    rv = cgnat_bind_user_to_public_ip (instance, instance_index, pool_index,
          public_ip_index, pool, ip, user);
    if (rv)
    {
      cgnat_delete_user (instance, user);
      continue;
    }

    cgnat_commit_user (instance, user);

    rv = cgnat_alloc_port_for_user (cm, instance, user, private_port,
			      protocol, result);
    if (!rv)
      return 0;

    // alloc failed, release new user resource
    cgnat_rollback_new_user (instance, pool, ip, user);
    continue;
  }

  
  ip = cgnat_fallback_select_public_ip (cm, instance, &pool_index, &public_ip_index);
  if (ip)
  {
    pool = cgnat_pool_get_by_index (cm, pool_index);
    if (!pool)
      return VNET_API_ERROR_NO_SUCH_ENTRY;

    user = cgnat_create_user (instance, &key, pool_index);
    rv = cgnat_bind_user_to_public_ip (instance, instance_index, pool_index,
          public_ip_index, pool, ip, user);
    if (rv)
    {
      cgnat_delete_user (instance, user);
      return rv;
    }

    cgnat_commit_user (instance, user);
    rv = cgnat_alloc_port_for_user (cm, instance, user, private_port,
			      protocol, result);
    if (!rv)
      return 0;

    cgnat_rollback_new_user (instance, pool, ip, user);
    
    return rv;
  }

  return VNET_API_ERROR_LIMIT_EXCEEDED;
}

static void
cgnat_det_global_offset_to_pool_ip (cgnat_instance_t *instance, u32 global_offset,
				    u32 *pool_index, u32 *public_ip_index,
				    ip4_address_t *public_ip)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u32 *pi, offset = 0;

  *pool_index = CGNAT_INVALID_INDEX;
  *public_ip_index = CGNAT_INVALID_INDEX;
  public_ip->as_u32 = 0;

  vec_foreach (pi, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pi);
      if (!pool)
	continue;
      u32 count = clib_net_to_host_u32 (pool->last_ip.as_u32) -
		  clib_net_to_host_u32 (pool->first_ip.as_u32) + 1;
      if (global_offset < offset + count)
	{
	  *pool_index = *pi;
	  *public_ip_index = global_offset - offset;
	  public_ip->as_u32 =
	    clib_host_to_net_u32 (clib_net_to_host_u32 (pool->first_ip.as_u32) +
				  global_offset - offset);
	  return;
	}
      offset += count;
    }
}

/* Allocate a deterministic public port for (inside_ip, inside_port, protocol).
 * Caller must hold the user lock for the corresponding inside host. */
int
cgnat_det_alloc_port (cgnat_instance_t *instance, u32 inside_fib_index,
		      ip4_address_t inside_ip, u16 inside_port, u8 protocol,
		      cgnat_pba_alloc_result_t *result)
{
  cgnat_det_runtime_t *det = &instance->det;
  cgnat_user_t *user;
  cgnat_user_key_t key;
  u32 in_offset, global_out_offset, host_slot;
  u32 pool_index, public_ip_index, base_port, public_port;
  ip4_address_t public_ip;
  int proto_index;

  proto_index = cgnat_pba_proto_index (protocol);
  if (proto_index < 0)
    return VNET_API_ERROR_INVALID_VALUE;

  in_offset = clib_net_to_host_u32 (inside_ip.as_u32) - det->inside_first_host;
  if (in_offset >= det->inside_count)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  global_out_offset = in_offset / det->sharing_ratio;
  host_slot = in_offset % det->sharing_ratio;

  cgnat_det_global_offset_to_pool_ip (instance, global_out_offset, &pool_index,
				      &public_ip_index, &public_ip);
  if (pool_index == CGNAT_INVALID_INDEX)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  base_port = det->usable_port_start + host_slot * det->ports_per_host;
  public_port = base_port + (inside_port % det->ports_per_host);

  clib_memset (&key, 0, sizeof (key));
  key.fib_index = inside_fib_index;
  key.private_ip = inside_ip;
  user = cgnat_find_user (instance, &key);
  if (!user)
    {
      user = cgnat_create_user (instance, &key, pool_index);
      if (!user)
	return VNET_API_ERROR_LIMIT_EXCEEDED;
      cgnat_commit_user (instance, user);
    }

  if (!user->det_port_bitmap[proto_index])
    clib_bitmap_alloc (user->det_port_bitmap[proto_index],
		       det->ports_per_host);

  if (clib_bitmap_get (user->det_port_bitmap[proto_index],
		       public_port - base_port))
    {
      u32 idx;
      for (idx = 0; idx < det->ports_per_host; idx++)
	{
	  if (!clib_bitmap_get (user->det_port_bitmap[proto_index], idx))
	    {
	      public_port = base_port + idx;
	      goto port_found;
	    }
	}
      /* Caller is expected to hold the user lock. */
      cgnat_delete_user_if_idle (instance, user);
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }
port_found:
  user->det_port_bitmap[proto_index] =
    clib_bitmap_set (user->det_port_bitmap[proto_index],
		     public_port - base_port, 1);
  user->active_ports[proto_index]++;

  result->public_ip = public_ip;
  result->public_port = public_port;
  result->pool_index = pool_index;
  result->public_ip_index = public_ip_index;
  result->user_index = user - instance->users;
  result->block_index = CGNAT_INVALID_INDEX;

  return 0;
}

void
cgnat_det_release_port (cgnat_instance_t *instance, cgnat_mapping_t *mapping)
{
  cgnat_det_runtime_t *det = &instance->det;
  cgnat_user_t *user;
  cgnat_user_key_t key;
  u32 in_offset, host_slot, base_port;
  int proto_index;

  proto_index = cgnat_pba_proto_index (mapping->protocol);
  if (proto_index < 0)
    return;

  clib_memset (&key, 0, sizeof (key));
  key.fib_index = mapping->inside_fib_index;
  key.private_ip = mapping->inside_ip;

  cgnat_user_lock (instance, key.fib_index, key.private_ip);
  user = cgnat_find_user (instance, &key);
  if (!user)
    {
      cgnat_user_unlock (instance, key.fib_index, key.private_ip);
      return;
    }

  in_offset =
    clib_net_to_host_u32 (mapping->inside_ip.as_u32) - det->inside_first_host;
  if (in_offset >= det->inside_count)
    goto done;

  host_slot = in_offset % det->sharing_ratio;
  base_port = det->usable_port_start + host_slot * det->ports_per_host;

  if (user->det_port_bitmap[proto_index] &&
      mapping->nat_port >= base_port &&
      mapping->nat_port < base_port + det->ports_per_host)
    {
      user->det_port_bitmap[proto_index] =
	clib_bitmap_set (user->det_port_bitmap[proto_index],
			 mapping->nat_port - base_port, 0);
      if (user->active_ports[proto_index])
	user->active_ports[proto_index]--;
    }

done:
  cgnat_delete_user_if_idle (instance, user);
  cgnat_user_unlock (instance, key.fib_index, key.private_ip);
}

/* Compute the deterministic outside mapping for INSIDE_IP.
 * Returns the public IP and the inclusive port range allocated to that host. */
int
cgnat_det_i2omap (cgnat_instance_t *instance, ip4_address_t inside_ip,
		  ip4_address_t *public_ip, u16 *port_start, u16 *port_end)
{
  cgnat_det_runtime_t *det = &instance->det;
  u32 in_offset, global_out_offset, host_slot;
  u32 pool_index, public_ip_index;

  in_offset = clib_net_to_host_u32 (inside_ip.as_u32) - det->inside_first_host;
  if (in_offset >= det->inside_count)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  global_out_offset = in_offset / det->sharing_ratio;
  host_slot = in_offset % det->sharing_ratio;

  cgnat_det_global_offset_to_pool_ip (instance, global_out_offset, &pool_index,
				      &public_ip_index, public_ip);
  if (pool_index == CGNAT_INVALID_INDEX)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *port_start = det->usable_port_start + host_slot * det->ports_per_host;
  *port_end = *port_start + det->ports_per_host - 1;
  return 0;
}

/* Compute the deterministic inside IP that maps to PUBLIC_IP:PUBLIC_PORT.
 * Only validates that the public side falls inside the deterministic space. */
int
cgnat_det_o2imap (cgnat_instance_t *instance, ip4_address_t public_ip,
		  u16 public_port, ip4_address_t *inside_ip)
{
  cgnat_det_runtime_t *det = &instance->det;
  cgnat_main_t *cm = &cgnat_main;
  cgnat_pool_t *pool;
  u32 *pi, global_out_offset = CGNAT_INVALID_INDEX;
  u32 host_slot;
  u64 inside_offset;
  u32 offset = 0;

  if (public_port < det->usable_port_start || public_port > det->usable_port_end)
    return VNET_API_ERROR_INVALID_VALUE;

  vec_foreach (pi, instance->pool_indices)
    {
      u32 first, last, pub;

      pool = cgnat_pool_get_by_index (cm, *pi);
      if (!pool)
	continue;
      first = clib_net_to_host_u32 (pool->first_ip.as_u32);
      last = clib_net_to_host_u32 (pool->last_ip.as_u32);
      pub = clib_net_to_host_u32 (public_ip.as_u32);
      if (pub >= first && pub <= last)
	{
	  global_out_offset = offset + (pub - first);
	  break;
	}
      offset += last - first + 1;
    }

  if (global_out_offset == CGNAT_INVALID_INDEX)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  host_slot = (public_port - det->usable_port_start) / det->ports_per_host;
  if (host_slot >= det->sharing_ratio)
    return VNET_API_ERROR_INVALID_VALUE;

  inside_offset = (u64) global_out_offset * det->sharing_ratio + host_slot;
  if (inside_offset >= det->inside_count)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  inside_ip->as_u32 =
    clib_host_to_net_u32 (det->inside_first_host + (u32) inside_offset);
  return 0;
}

int
cgnat_pba_alloc_port (u32 instance_index, u32 fib_index,
		      ip4_address_t private_ip, u16 private_port,
		      u8 protocol,
		      cgnat_pba_alloc_result_t *result)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  int rv;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cgnat_user_lock (instance, fib_index, private_ip);
  rv = cgnat_pba_alloc_port_locked (instance_index, fib_index, private_ip,
				    private_port, protocol, result);
  cgnat_user_unlock (instance, fib_index, private_ip);
  return rv;
}

int
cgnat_pba_release_port (u32 instance_index, u32 pool_index,
			u32 public_ip_index, u32 inside_fib_index,
			ip4_address_t private_ip, u16 port, u8 protocol)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_public_ip_t *ip;
  cgnat_block_t *block;
  cgnat_user_t *user = 0;
  ip4_address_t log_private_ip;
  u32 block_id, port_offset, block_index;
  u16 pool_start;
  int proto_index;

  proto_index = cgnat_pba_proto_index (protocol);
  if (proto_index < 0)
    return VNET_API_ERROR_INVALID_VALUE;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pool = cgnat_pool_get_by_index (cm, pool_index);
  if (!pool || pool->owner_instance_index != instance_index)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  if (public_ip_index >= vec_len (pool->public_ips))
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  pool_start = cgnat_pool_start_port (pool);
  if (port < pool_start || port > cgnat_pool_end_port (pool))
    return VNET_API_ERROR_INVALID_VALUE;

  block_id = (port - pool_start) / pool->block_size;
  port_offset = (port - pool_start) % pool->block_size;
  ip = vec_elt_at_index (pool->public_ips, public_ip_index);

  cgnat_user_lock (instance, inside_fib_index, private_ip);
  clib_spinlock_lock (&ip->lock);
  if (block_id >= vec_len (ip->block_index_by_id))
    {
      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  block_index = ip->block_index_by_id[block_id];
  if (block_index == CGNAT_INVALID_INDEX)
    {
      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  block = pool_elt_at_index (ip->blocks, block_index);
  if (block->state != CGNAT_BLOCK_ALLOCATED ||
      clib_bitmap_get (block->free_port_bitmap[proto_index][port_offset & 1],
		       port_offset))
    {
      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (pool_is_free_index (instance->users, block->owner_user_index))
    {
      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  user = pool_elt_at_index (instance->users, block->owner_user_index);
  if (user->key.fib_index != inside_fib_index ||
      user->key.private_ip.as_u32 != private_ip.as_u32)
    {
      clib_spinlock_unlock (&ip->lock);
      cgnat_user_unlock (instance, inside_fib_index, private_ip);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  block->free_port_bitmap[proto_index][port_offset & 1] =
    clib_bitmap_set (block->free_port_bitmap[proto_index][port_offset & 1],
		     port_offset, 1);
  block->active_ports[proto_index]--;
  user->active_ports[proto_index]--;

  if (!cgnat_block_has_active_ports (block))
    {
      if (cgnat_prealloc_user_idle (user))
	cgnat_start_prealloc_user_cooling (cm, instance, instance_index,
					   pool_index, public_ip_index, pool, ip,
					   user);
      else if (!user ||
	       user->block_alloc_mode == CGNAT_BLOCK_ALLOC_MODE_ON_DEMAND)
	{
	  log_private_ip.as_u32 = 0;
	  if (user)
	    log_private_ip = user->key.private_ip;

	  cgnat_start_block_cooling (cm, instance_index, pool_index,
				     public_ip_index, pool, ip, block,
				     log_private_ip);
	}
    }

  clib_spinlock_unlock (&ip->lock);
  cgnat_user_unlock (instance, inside_fib_index, private_ip);
  return 0;
}

static_always_inline int
cgnat_block_snapshot_pool_get (cgnat_main_t *cm, u32 pool_index,
			       cgnat_pool_t **pool)
{
  if (pool_index >= vec_len (cm->pools) ||
      !cm->pools[pool_index].configured)
    return 0;
  *pool = vec_elt_at_index (cm->pools, pool_index);
  return 1;
}

cgnat_block_ip_summary_t *
cgnat_block_summary_snapshot (ip4_address_t *public_ip_filter)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_block_ip_summary_t *result = 0;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_public_ip_t *public_ip;
  u32 *pool_index;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      vec_foreach (pool_index, instance->pool_indices)
	{
	  if (!cgnat_block_snapshot_pool_get (cm, *pool_index, &pool))
	    continue;
	  vec_foreach (public_ip, pool->public_ips)
	    {
	      cgnat_block_ip_summary_t *summary;
	      u32 unavailable;

	      if (public_ip_filter &&
		  public_ip->addr.as_u32 != public_ip_filter->as_u32)
		continue;
	      vec_add2 (result, summary, 1);
	      summary->instance_id = instance->instance_id;
	      summary->pool_id = pool->pool_id;
	      summary->public_ip = public_ip->addr;
	      summary->total_blocks = public_ip->total_blocks;
	      summary->allocated_blocks = public_ip->allocated_blocks;
	      summary->cooling_blocks = public_ip->cooling_blocks;
	      unavailable = public_ip->allocated_blocks +
			    public_ip->cooling_blocks;
	      summary->free_blocks =
		unavailable < public_ip->total_blocks ?
		  public_ip->total_blocks - unavailable :
		  0;
	      summary->active_users =
		clib_atomic_load_relax_n (&public_ip->active_users);
	    }
	}
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return result;
}

cgnat_block_user_summary_t *
cgnat_block_user_snapshot (ip4_address_t inside_ip)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_block_user_summary_t *result = 0;
  cgnat_instance_t *instance;
  cgnat_user_t *user;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      pool_foreach (user, instance->users)
	{
	  cgnat_block_user_summary_t *summary;
	  cgnat_pool_t *pool;
	  cgnat_public_ip_t *public_ip;
	  u16 *block_id;

	  if (user->key.private_ip.as_u32 != inside_ip.as_u32 ||
	      !cgnat_block_snapshot_pool_get (cm, user->pool_index, &pool) ||
	      user->public_ip_index >= vec_len (pool->public_ips))
	    continue;
	  public_ip =
	    vec_elt_at_index (pool->public_ips, user->public_ip_index);

	  vec_add2 (result, summary, 1);
	  clib_memset (summary, 0, sizeof (*summary));
	  summary->instance_id = instance->instance_id;
	  summary->inside_fib_index = user->key.fib_index;
	  summary->pool_id = pool->pool_id;
	  summary->inside_ip = user->key.private_ip;
	  summary->public_ip = public_ip->addr;
	  clib_memcpy (summary->active_ports, user->active_ports,
		       sizeof (summary->active_ports));

	  vec_foreach (block_id, user->owned_block_ids)
	    {
	      cgnat_block_t *block;
	      u32 block_index;

	      if (*block_id >= vec_len (public_ip->block_index_by_id))
		continue;
	      block_index = public_ip->block_index_by_id[*block_id];
	      if (block_index == CGNAT_INVALID_INDEX ||
		  pool_is_free_index (public_ip->blocks, block_index))
		continue;
	      block = pool_elt_at_index (public_ip->blocks, block_index);
	      if (block->owner_user_index != (u32) (user - instance->users))
		continue;
	      summary->owned_blocks++;
	      if (block->state == CGNAT_BLOCK_COOLING)
		summary->cooling_blocks++;
	      else if (block->state == CGNAT_BLOCK_ALLOCATED &&
		       cgnat_block_has_active_ports (block))
		summary->allocated_blocks++;
	      else if (block->state == CGNAT_BLOCK_ALLOCATED)
		summary->free_blocks++;
	    }
	}
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return result;
}

cgnat_block_public_detail_t *
cgnat_block_public_snapshot (ip4_address_t public_ip_filter)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_block_public_detail_t *result = 0;
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_public_ip_t *public_ip;
  u32 *pool_index;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  vec_foreach (instance, cm->instances)
    {
      if (!instance->configured)
	continue;
      vec_foreach (pool_index, instance->pool_indices)
	{
	  if (!cgnat_block_snapshot_pool_get (cm, *pool_index, &pool))
	    continue;
	  vec_foreach (public_ip, pool->public_ips)
	    {
	      u32 block_id;

	      if (public_ip->addr.as_u32 != public_ip_filter.as_u32)
		continue;

	      for (block_id = 0; block_id < public_ip->total_blocks;
		   block_id++)
		{
		  cgnat_block_public_detail_t *detail;
		  cgnat_block_t *block;
		  cgnat_user_t *user;
		  u32 block_index;

		  if (block_id >= vec_len (public_ip->block_index_by_id))
		    break;
		  block_index = public_ip->block_index_by_id[block_id];
		  if (block_index == CGNAT_INVALID_INDEX ||
		      pool_is_free_index (public_ip->blocks, block_index))
		    continue;
		  block = pool_elt_at_index (public_ip->blocks, block_index);
		  vec_add2 (result, detail, 1);
		  clib_memset (detail, 0, sizeof (*detail));
		  detail->instance_id = instance->instance_id;
		  detail->pool_id = pool->pool_id;
		  detail->public_ip = public_ip->addr;
		  detail->block_id = block->block_id;
		  detail->start_port =
		    cgnat_block_start_port (pool, block->block_id);
		  detail->end_port =
		    detail->start_port + pool->block_size - 1;
		  clib_memcpy (detail->active_ports, block->active_ports,
		       sizeof (detail->active_ports));
		  detail->state = block->state;
		  if (instance->users &&
		      block->owner_user_index < vec_len (instance->users) &&
		      !pool_is_free_index (instance->users,
					   block->owner_user_index))
		    {
		      user = pool_elt_at_index (instance->users,
						block->owner_user_index);
		      detail->owner_valid = 1;
		      detail->inside_ip = user->key.private_ip;
		      detail->inside_fib_index = user->key.fib_index;
		    }
		}
	    }
	}
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return result;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
