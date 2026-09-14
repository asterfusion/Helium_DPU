/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

static vlib_combined_counter_main_t *
ipoe_counter_main (ipoe_session_counter_type_t counter_type)
{
  ipoe_main_t *im = &ipoe_main;

  switch (counter_type)
    {
    case IPOE_SESSION_COUNTER_UPSTREAM_FORWARD:
      return &im->upstream_forward;
    case IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD:
      return &im->downstream_forward;
    case IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP:
      return &im->upstream_gate_drop;
    case IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP:
      return &im->downstream_gate_drop;
    default:
      return 0;
    }
}

static void
ipoe_session_counter_allocate (ipoe_session_t *session)
{
  ipoe_main_t *im = &ipoe_main;
  u32 counter_index;
  u32 counter_type;

  if (vec_len (im->free_counter_indices))
    counter_index = vec_pop (im->free_counter_indices);
  else
    counter_index = im->next_counter_index++;

  for (counter_type = 0; counter_type < IPOE_SESSION_COUNTER_N_TYPES;
       counter_type++)
    {
      vlib_combined_counter_main_t *counter_main =
	ipoe_counter_main (counter_type);

      vlib_validate_combined_counter (counter_main, counter_index);
      vlib_zero_combined_counter (counter_main, counter_index);
    }
  session->counter_index = counter_index;
}

static void
ipoe_session_counter_release (ipoe_session_t *session)
{
  vec_add1 (ipoe_main.free_counter_indices, session->counter_index);
}

void
ipoe_session_counter_add (u32 counter_index,
			  ipoe_session_counter_type_t counter_type,
			  u32 ip4_bytes)
{
  vlib_combined_counter_main_t *counter_main =
    ipoe_counter_main (counter_type);

  ASSERT (counter_main);
  vlib_increment_combined_counter (counter_main, vlib_get_thread_index (),
				  counter_index, 1, ip4_bytes);
}

static void
ipoe_session_get_counter (vlib_combined_counter_main_t *counter_main,
			  u32 counter_index, vlib_counter_t *counter)
{
  vlib_get_combined_counter (counter_main, counter_index, counter);
}

static void
ipoe_session_get_counters_locked (ipoe_session_t *session,
				  ipoe_session_counters_t *counters)
{
  ipoe_main_t *im = &ipoe_main;

  ipoe_session_get_counter (&im->upstream_forward, session->counter_index,
			    &counters->upstream_forward);
  ipoe_session_get_counter (&im->downstream_forward, session->counter_index,
			    &counters->downstream_forward);
  ipoe_session_get_counter (&im->upstream_gate_drop, session->counter_index,
			    &counters->upstream_gate_drop);
  ipoe_session_get_counter (&im->downstream_gate_drop, session->counter_index,
			    &counters->downstream_gate_drop);
}

int
ipoe_session_get_counters (u64 external_index,
			   ipoe_session_counters_t *counters)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  uword *p;

  if (!counters)
    return IPOE_ERROR_INVALID_VALUE;
  p = hash_get (im->session_by_index, (uword) external_index);
  if (!p || pool_is_free_index (im->sessions, p[0]))
    return IPOE_ERROR_NO_SUCH_ENTRY;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  session = pool_elt_at_index (im->sessions, p[0]);
  ipoe_session_get_counters_locked (session, counters);
  vlib_worker_thread_barrier_release (im->vlib_main);
  return IPOE_OK;
}

int
ipoe_session_quiesce_snapshot_batch (
  const u64 *external_indices, const u64 *generations, u32 count,
  ipoe_session_snapshot_result_t *results)
{
  ipoe_main_t *im = &ipoe_main;
  u32 i;

  if (!external_indices || !generations || !results || !count ||
      count > IPOE_SESSION_SNAPSHOT_BATCH_MAX)
    return IPOE_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  for (i = 0; i < count; i++)
    {
      ipoe_session_t *session;
      uword *p;

      results[i].external_index = external_indices[i];
      results[i].generation = generations[i];
      results[i].retval = IPOE_ERROR_NO_SUCH_ENTRY;

      p = hash_get (im->session_by_index, (uword) external_indices[i]);
      if (!p || pool_is_free_index (im->sessions, p[0]))
	continue;

      session = pool_elt_at_index (im->sessions, p[0]);
      if (session->generation != generations[i])
	{
	  results[i].retval = IPOE_ERROR_GENERATION_STALE;
	  continue;
	}
      session->admin_state = 0;
      results[i].retval = IPOE_OK;
    }
  vlib_worker_thread_barrier_release (im->vlib_main);

  return IPOE_OK;
}

static void
ipoe_session_remove_index (u32 session_index, u8 stop_timer)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  ipoe_interface_t *intf;

  if (pool_is_free_index (im->sessions, session_index))
    return;

  session = pool_elt_at_index (im->sessions, session_index);
  if (stop_timer)
    ipoe_timer_stop (session);
  hash_unset (im->session_by_index, (uword) session->external_index);
  hash_unset (im->session_by_user,
	      (uword) ipoe_user_key (session->sw_if_index, &session->user_ip4));

  if (session->sw_if_index < vec_len (im->interfaces))
    {
      intf = vec_elt_at_index (im->interfaces, session->sw_if_index);
      if (intf->session_count)
	intf->session_count--;
    }
  ipoe_session_counter_release (session);
  pool_put (im->sessions, session);
}

static int
ipoe_session_add_locked (u64 external_index, u64 generation, u32 sw_if_index,
		  const ip4_address_t *user_ip4,
		  const mac_address_t *user_mac, u8 has_user_mac,
		  u8 admin_state,
		  u32 lease_timeout, u64 lease_expiry)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_interface_t *intf;
  ipoe_session_t *session;
  uword *p;
  u32 session_index;
  u64 user_key;

  if (!external_index || !lease_timeout || !lease_expiry ||
      sw_if_index >= vec_len (im->interfaces))
    return IPOE_ERROR_INVALID_VALUE;
  if (user_ip4->as_u32 == 0 || ip4_address_is_multicast (user_ip4) ||
      ip4_address_is_global_broadcast (user_ip4))
    return IPOE_ERROR_INVALID_VALUE;
  admin_state = !!admin_state;
  intf = vec_elt_at_index (im->interfaces, sw_if_index);
  if (!intf->enabled)
    return IPOE_ERROR_INVALID_INTERFACE;
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L2 && !has_user_mac)
    return IPOE_ERROR_INVALID_VALUE;
  if (has_user_mac &&
      ((user_mac->bytes[0] & 1) ||
       (user_mac->bytes[0] == 0 && user_mac->bytes[1] == 0 &&
	user_mac->bytes[2] == 0 && user_mac->bytes[3] == 0 &&
	user_mac->bytes[4] == 0 && user_mac->bytes[5] == 0)))
    return IPOE_ERROR_INVALID_VALUE;
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L3)
    has_user_mac = 0;

  user_key = ipoe_user_key (sw_if_index, user_ip4);
  p = hash_get (im->session_by_index, (uword) external_index);
  if (p)
    {
      session_index = p[0];
      session = pool_elt_at_index (im->sessions, session_index);
      if (session->sw_if_index == sw_if_index &&
	  session->user_ip4.as_u32 == user_ip4->as_u32 &&
	  session->has_user_mac == has_user_mac &&
	  (!has_user_mac ||
	   !memcmp (&session->user_mac, user_mac, sizeof (*user_mac))))
	{
	  if (generation < session->generation)
	    return IPOE_ERROR_GENERATION_STALE;
	  if (generation == session->generation &&
	      lease_expiry == session->lease_expiry &&
	      admin_state == session->admin_state)
	    return IPOE_OK;
	  session->generation = generation;
	  session->lease_expiry = lease_expiry;
	  session->expires_at = vlib_time_now (im->vlib_main) + lease_timeout;
	  session->admin_state = admin_state;
	  session->timer_generation++;
	  ipoe_timer_update (session_index, lease_timeout);
#if 0
	  clib_warning ("ipoe session lease update index=%llu "
		"sw_if_index=%u ip=%U lease_timeout=%u lease_expiry=%llu",
		external_index, sw_if_index,
			format_ip4_address, user_ip4, lease_timeout,
			lease_expiry);
#endif
	  return IPOE_OK;
	}
      return IPOE_ERROR_ALREADY_EXISTS;
    }

  if (hash_get (im->session_by_user, (uword) user_key))
    return IPOE_ERROR_IP_CONFLICT;

  pool_get_zero (im->sessions, session);
  session_index = session - im->sessions;
  session->external_index = external_index;
  session->generation = generation;
  session->lease_expiry = lease_expiry;
  session->expires_at = vlib_time_now (im->vlib_main) + lease_timeout;
  session->user_ip4 = *user_ip4;
  session->sw_if_index = sw_if_index;
  session->has_user_mac = has_user_mac;
  session->admin_state = admin_state;
  session->timer_handle = ~0;
  session->timer_generation = 1;
  ipoe_session_counter_allocate (session);
  if (has_user_mac)
    session->user_mac = *user_mac;

  hash_set (im->session_by_index, (uword) external_index, session_index);
  hash_set (im->session_by_user, (uword) user_key, session_index);
  intf->session_count++;
  ipoe_timer_start (session_index, lease_timeout);
#if 0
	  clib_warning ("ipoe session add index=%llu sw_if_index=%u ip=%U "
		"lease_timeout=%u lease_expiry=%llu "
		"timer_handle=%u", external_index, sw_if_index,
		format_ip4_address, user_ip4, lease_timeout, lease_expiry,
		session->timer_handle);
#endif
  return IPOE_OK;
}

int
ipoe_session_add (u64 external_index, u64 generation, u32 sw_if_index,
		  const ip4_address_t *user_ip4,
		  const mac_address_t *user_mac, u8 has_user_mac,
		  u8 admin_state, u32 lease_timeout, u64 lease_expiry)
{
  ipoe_main_t *im = &ipoe_main;
  int rv;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  rv = ipoe_session_add_locked (
    external_index, generation, sw_if_index, user_ip4, user_mac,
    has_user_mac, admin_state, lease_timeout, lease_expiry);
  vlib_worker_thread_barrier_release (im->vlib_main);

  return rv;
}

int
ipoe_session_add_batch (
  const ipoe_session_add_batch_entry_t *entries, u32 count,
  ipoe_session_add_batch_result_t *results)
{
  ipoe_main_t *im = &ipoe_main;
  u32 i;

  if (!entries || !results || !count || count > IPOE_SESSION_ADD_BATCH_MAX)
    return IPOE_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  for (i = 0; i < count; i++)
    {
      ipoe_session_add_batch_result_t *result = &results[i];
      uword *p;

      result->external_index = entries[i].external_index;
      result->generation = entries[i].generation;
      result->counter_index = ~0;
      result->retval = ipoe_session_add_locked (
        entries[i].external_index, entries[i].generation,
        entries[i].sw_if_index, &entries[i].user_ip4,
        &entries[i].user_mac, entries[i].has_user_mac,
        entries[i].admin_state, entries[i].lease_timeout,
        entries[i].lease_expiry);
      if (result->retval != IPOE_OK)
	continue;

      p = hash_get (im->session_by_index, (uword) entries[i].external_index);
      if (!p || pool_is_free_index (im->sessions, p[0]))
	{
	  result->retval = IPOE_ERROR_NO_SUCH_ENTRY;
	  continue;
	}
      result->counter_index =
	pool_elt_at_index (im->sessions, p[0])->counter_index;
    }
  vlib_worker_thread_barrier_release (im->vlib_main);

  return IPOE_OK;
}

int
ipoe_session_del (u64 external_index)
{
  ipoe_main_t *im = &ipoe_main;
  uword *p = hash_get (im->session_by_index, (uword) external_index);
  if (!p)
    return IPOE_ERROR_NO_SUCH_ENTRY;
#if 0
  clib_warning ("ipoe session del index=%llu pool_index=%u",
		external_index, (u32) p[0]);
#endif
  vlib_worker_thread_barrier_sync (im->vlib_main);
  ipoe_session_remove_index (p[0], 1);
  vlib_worker_thread_barrier_release (im->vlib_main);
  return IPOE_OK;
}

int
ipoe_session_set_state (u64 external_index, u64 generation, u8 admin_state)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  uword *p;

  if (!external_index)
    return IPOE_ERROR_INVALID_VALUE;
  admin_state = !!admin_state;
  p = hash_get (im->session_by_index, (uword) external_index);
  if (!p || pool_is_free_index (im->sessions, p[0]))
    return IPOE_ERROR_NO_SUCH_ENTRY;
  session = pool_elt_at_index (im->sessions, p[0]);
  if (session->generation != generation)
    return IPOE_ERROR_GENERATION_STALE;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  session->admin_state = admin_state;
  vlib_worker_thread_barrier_release (im->vlib_main);
#if 0
  clib_warning ("ipoe session state index=%llu state=%u", external_index,
		admin_state);
#endif
  return IPOE_OK;
}

int
ipoe_session_flush_interface (u32 sw_if_index)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  u32 *session_indices = 0;
  u32 *session_index;

  if (sw_if_index >= vec_len (im->interfaces))
    return IPOE_ERROR_INVALID_INTERFACE;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  pool_foreach (session, im->sessions)
    {
      if (session->sw_if_index == sw_if_index)
	vec_add1 (session_indices, session - im->sessions);
    }

  vec_foreach (session_index, session_indices)
    ipoe_session_remove_index (*session_index, 1);
  im->interfaces[sw_if_index].session_count = 0;
  vlib_worker_thread_barrier_release (im->vlib_main);

  vec_free (session_indices);
  return IPOE_OK;
}

void
ipoe_session_expire (u32 session_index)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  f64 now;

  if (pool_is_free_index (im->sessions, session_index))
    return;
  session = pool_elt_at_index (im->sessions, session_index);
  now = vlib_time_now (im->vlib_main);
  if (session->expires_at > now)
    {
      session->timer_generation++;
      ipoe_timer_start (session_index,
			(u32) clib_max (1.0, session->expires_at - now));
      return;
    }
  session->timer_handle = ~0;
#if 0
	clib_warning ("ipoe session expire index=%llu sw_if_index=%u ip=%U "
		"lease_expiry=%llu", session->external_index,
		session->sw_if_index, format_ip4_address, &session->user_ip4,
		session->lease_expiry);
#endif
  vlib_worker_thread_barrier_sync (im->vlib_main);
  ipoe_session_remove_index (session_index, 0);
  vlib_worker_thread_barrier_release (im->vlib_main);
}
