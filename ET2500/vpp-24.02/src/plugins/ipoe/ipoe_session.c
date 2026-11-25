/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

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
			  u32 packet_bytes)
{
  vlib_combined_counter_main_t *counter_main =
    ipoe_counter_main (counter_type);

  ASSERT (counter_main);
  vlib_increment_combined_counter (counter_main, vlib_get_thread_index (),
				  counter_index, 1, packet_bytes);
}

ipoe_session_t *
ipoe_session_lookup_downstream (
  u32 sw_if_index, const ip4_address_t *dst_ip, u64 expected_external_index,
  u8 check_session, ipoe_downstream_lookup_result_t *result)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  uword *p;

  p = hash_get (im->session_by_user,
		(uword) ipoe_user_key (sw_if_index, dst_ip));
  if (!p || pool_is_free_index (im->sessions, p[0]))
    {
      *result = IPOE_DOWNSTREAM_LOOKUP_NO_SESSION;
      return 0;
    }

  session = pool_elt_at_index (im->sessions, p[0]);
  if (!session->admin_state)
    *result = IPOE_DOWNSTREAM_LOOKUP_SESSION_INACTIVE;
  else if (session->sw_if_index != sw_if_index)
    *result = IPOE_DOWNSTREAM_LOOKUP_ACCESS_MISMATCH;
  else if (check_session &&
           session->external_index != expected_external_index)
    *result = IPOE_DOWNSTREAM_LOOKUP_SESSION_MISMATCH;
  else
    *result = IPOE_DOWNSTREAM_LOOKUP_OK;

  return session;
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
ipoe_session_validate (u64 external_index, u32 sw_if_index,
		       const ip4_address_t *user_ip4,
		       const mac_address_t *user_mac, u8 *has_user_mac,
		       u32 lease_timeout, u64 lease_expiry,
		       const ipoe_qinq_session_t *qinq)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_interface_t *intf;
  const qinq_subport_t *qinq_rule;

  if (!external_index || !lease_timeout || !lease_expiry ||
      sw_if_index >= vec_len (im->interfaces))
    return IPOE_ERROR_INVALID_VALUE;
  if (user_ip4->as_u32 == 0 || ip4_address_is_multicast (user_ip4) ||
      ip4_address_is_global_broadcast (user_ip4))
    return IPOE_ERROR_INVALID_VALUE;
  intf = vec_elt_at_index (im->interfaces, sw_if_index);
  if (!intf->enabled)
    return IPOE_ERROR_INVALID_INTERFACE;
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L2 && !*has_user_mac)
    return IPOE_ERROR_INVALID_VALUE;
  if (*has_user_mac &&
      ((user_mac->bytes[0] & 1) ||
       (user_mac->bytes[0] == 0 && user_mac->bytes[1] == 0 &&
	user_mac->bytes[2] == 0 && user_mac->bytes[3] == 0 &&
	user_mac->bytes[4] == 0 && user_mac->bytes[5] == 0)))
    return IPOE_ERROR_INVALID_VALUE;
  if (qinq && qinq->enabled)
    {
      qinq_rule = qinq_subport_get_by_sw_if_index (sw_if_index);
      if (!qinq_rule || !*has_user_mac ||
	  qinq->parent_sw_if_index != qinq_rule->parent_sw_if_index ||
	  qinq->outer_tpid != qinq_rule->outer_tpid ||
	  qinq->outer_vlan != qinq_rule->outer_vlan ||
	  qinq->inner_tpid != qinq_rule->inner_tpid ||
	  qinq->inner_vlan < QINQ_VLAN_MIN ||
	  qinq->inner_vlan > QINQ_VLAN_MAX ||
	  (qinq_rule->match_type == QINQ_MATCH_EXACT &&
	   qinq->inner_vlan != qinq_rule->inner_vlan_first) ||
	  (qinq_rule->match_type == QINQ_MATCH_RANGE &&
	   (qinq->inner_vlan < qinq_rule->inner_vlan_first ||
	    qinq->inner_vlan > qinq_rule->inner_vlan_last)) ||
	  mac_address_is_zero (&qinq->local_mac) ||
	  (qinq->local_mac.bytes[0] & 1))
	return IPOE_ERROR_INVALID_VALUE;
    }
  if (intf->access_mode == IPOE_INTERNAL_ACCESS_MODE_L3 &&
      (!qinq || !qinq->enabled))
    *has_user_mac = 0;

  return IPOE_OK;
}

static int
ipoe_session_add_locked (u64 external_index, u64 generation, u32 sw_if_index,
		  const ip4_address_t *user_ip4,
		  const mac_address_t *user_mac, u8 has_user_mac,
		  u8 admin_state, u32 lease_timeout, u64 lease_expiry,
		  const ipoe_qinq_session_t *qinq)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_interface_t *intf;
  ipoe_session_t *session;
  uword *p;
  u32 session_index;
  u64 user_key;
  int rv;

  rv = ipoe_session_validate (external_index, sw_if_index, user_ip4,
			      user_mac, &has_user_mac, lease_timeout,
			      lease_expiry, qinq);
  if (rv != IPOE_OK)
    return rv;

  admin_state = !!admin_state;
  intf = vec_elt_at_index (im->interfaces, sw_if_index);

  user_key = ipoe_user_key (sw_if_index, user_ip4);
  p = hash_get (im->session_by_index, (uword) external_index);
  if (p)
    {
      session_index = p[0];
      session = pool_elt_at_index (im->sessions, session_index);
      if (session->sw_if_index == sw_if_index &&
	  session->user_ip4.as_u32 == user_ip4->as_u32 &&
	  session->has_user_mac == has_user_mac &&
	  session->qinq.enabled == (qinq && qinq->enabled) &&
	  (!session->qinq.enabled ||
	   !memcmp (&session->qinq, qinq, sizeof (*qinq))) &&
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
  session->upstream_policer_index = ~0u;
  session->downstream_policer_index = ~0u;
  if (qinq && qinq->enabled)
    session->qinq = *qinq;
  session->timer_handle = ~0;
  session->timer_generation = 1;
  ipoe_session_counter_allocate (session);
  if (has_user_mac)
    session->user_mac = *user_mac;

  hash_set (im->session_by_index, (uword) external_index, session_index);
  hash_set (im->session_by_user, (uword) user_key, session_index);
  intf->session_count++;
  ipoe_timer_start (session_index, lease_timeout);
  return IPOE_OK;
}

static int
ipoe_session_update_locked (u64 external_index, u64 generation,
			    u32 sw_if_index,
			    const ip4_address_t *user_ip4,
			    const mac_address_t *user_mac, u8 has_user_mac,
			    u8 admin_state, u32 lease_timeout,
			    u64 lease_expiry,
			    const ipoe_qinq_session_t *qinq)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  ipoe_interface_t *old_intf;
  ipoe_interface_t *new_intf;
  u64 old_user_key;
  u64 new_user_key;
  uword *p;
  u32 session_index;
  int rv;

  p = hash_get (im->session_by_index, (uword) external_index);
  if (!p || pool_is_free_index (im->sessions, p[0]))
    return IPOE_ERROR_NO_SUCH_ENTRY;

  session_index = p[0];
  session = pool_elt_at_index (im->sessions, session_index);
  if (generation < session->generation)
    return IPOE_ERROR_GENERATION_STALE;
  if ((session->ip6_binding_count && session->sw_if_index != sw_if_index) ||
      (session->ip6_qinq_route_count &&
       (session->sw_if_index != sw_if_index || !qinq || !qinq->enabled ||
	memcmp (&session->qinq, qinq, sizeof (*qinq)))))
    return IPOE_ERROR_OBJECT_IN_USE;

  rv = ipoe_session_validate (external_index, sw_if_index, user_ip4,
			      user_mac, &has_user_mac, lease_timeout,
			      lease_expiry, qinq);
  if (rv != IPOE_OK)
    return rv;

  new_user_key = ipoe_user_key (sw_if_index, user_ip4);
  p = hash_get (im->session_by_user, (uword) new_user_key);
  if (p && p[0] != session_index)
    return IPOE_ERROR_IP_CONFLICT;

  old_user_key = ipoe_user_key (session->sw_if_index, &session->user_ip4);
  old_intf = vec_elt_at_index (im->interfaces, session->sw_if_index);
  new_intf = vec_elt_at_index (im->interfaces, sw_if_index);
  hash_unset (im->session_by_user, (uword) old_user_key);

  if (session->sw_if_index != sw_if_index)
    {
      if (old_intf->session_count)
	old_intf->session_count--;
      new_intf->session_count++;
    }

  session->generation = generation;
  session->lease_expiry = lease_expiry;
  session->expires_at = vlib_time_now (im->vlib_main) + lease_timeout;
  session->user_ip4 = *user_ip4;
  session->sw_if_index = sw_if_index;
  session->has_user_mac = has_user_mac;
  session->admin_state = !!admin_state;
  clib_memset (&session->user_mac, 0, sizeof (session->user_mac));
  clib_memset (&session->qinq, 0, sizeof (session->qinq));
  if (has_user_mac)
    session->user_mac = *user_mac;
  if (qinq && qinq->enabled)
    session->qinq = *qinq;

  hash_set (im->session_by_user, (uword) new_user_key, session_index);
  session->timer_generation++;
  ipoe_timer_update (session_index, lease_timeout);
  return IPOE_OK;
}

int
ipoe_session_add (u64 external_index, u64 generation, u32 sw_if_index,
		  const ip4_address_t *user_ip4,
		  const mac_address_t *user_mac, u8 has_user_mac,
		  u8 admin_state, u32 lease_timeout, u64 lease_expiry,
		  const ipoe_qinq_session_t *qinq)
{
  ipoe_main_t *im = &ipoe_main;
  int rv;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  rv = ipoe_session_add_locked (
    external_index, generation, sw_if_index, user_ip4, user_mac,
    has_user_mac, admin_state, lease_timeout, lease_expiry, qinq);
  vlib_worker_thread_barrier_release (im->vlib_main);

  return rv;
}

int
ipoe_session_update (u64 external_index, u64 generation, u32 sw_if_index,
		     const ip4_address_t *user_ip4,
		     const mac_address_t *user_mac, u8 has_user_mac,
		     u8 admin_state, u32 lease_timeout, u64 lease_expiry,
		     const ipoe_qinq_session_t *qinq)
{
  ipoe_main_t *im = &ipoe_main;
  int rv;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  rv = ipoe_session_update_locked (
    external_index, generation, sw_if_index, user_ip4, user_mac,
    has_user_mac, admin_state, lease_timeout, lease_expiry, qinq);
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
        entries[i].lease_expiry, &entries[i].qinq);
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
  if (pool_elt_at_index (im->sessions, p[0])->ip6_binding_count ||
      pool_elt_at_index (im->sessions, p[0])->ip6_qinq_route_count)
    return IPOE_ERROR_OBJECT_IN_USE;
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
  if (session->ip6_binding_count || session->ip6_qinq_route_count)
    {
      session->admin_state = 0;
      return;
    }
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


int
ipoe_session_set_policer (u64 external_index, u32 upstream_index,
			  u32 downstream_index)
{
  ipoe_main_t *im = &ipoe_main;
  vnet_policer_main_t *pm = &vnet_policer_main;
  uword *p = hash_get (im->session_by_index, (uword) external_index);
  ipoe_session_t *session;

  if (!p || pool_is_free_index (im->sessions, p[0]))
    return IPOE_ERROR_NO_SUCH_ENTRY;
  if ((upstream_index != ~0u &&
       pool_is_free_index (pm->policers, upstream_index)) ||
      (downstream_index != ~0u &&
       pool_is_free_index (pm->policers, downstream_index)))
    return IPOE_ERROR_INVALID_VALUE;

  session = pool_elt_at_index (im->sessions, p[0]);
  session->upstream_policer_index = upstream_index;
  session->downstream_policer_index = downstream_index;
  return IPOE_OK;
}

int
ipoe_session_police (vlib_main_t *vm, vlib_buffer_t *b,
		     ipoe_session_t *session, vlib_dir_t dir)
{
  u32 policer_index;
  u64 now;
  u8 action;

  policer_index = dir == VLIB_RX ? session->upstream_policer_index :
    session->downstream_policer_index;
  if (policer_index == ~0u)
    return 0;

  now = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;
  action = vnet_policer_police (vm, b, policer_index, now,
				POLICE_CONFORM, false);
  if (action != QOS_ACTION_DROP)
    return 0;

  return 1;
}
