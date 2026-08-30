/*
 * cgnat_session.c - CGNAT global mapping and session state
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

#include <nat/lib/nat_inlines.h>
#include <nat/lib/inlines.h>
#include <nat/lib/lib.h>
#include <nat/cgnat/cgnat.h>
#include <nat/cgnat/cgnat_session_inlines.h>

static_always_inline u32
cgnat_calc_bihash_buckets (u32 n_elts)
{
  n_elts = n_elts / 2.5;
  u64 lower_pow2 = 1;
  while (lower_pow2 * 2 < n_elts)
    {
      lower_pow2 = 2 * lower_pow2;
    }
  u64 upper_pow2 = 2 * lower_pow2;
  if ((upper_pow2 - n_elts) < (n_elts - lower_pow2))
    {
      if (upper_pow2 <= UINT32_MAX)
	{
	  return upper_pow2;
	}
    }
  return lower_pow2;
}

static_always_inline void
cgnat_make_static_rule_key (clib_bihash_kv_24_8_t *kv,
			    cgnat_static_rule_t *rule)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) rule->instance_index << 32 |
	       (u64) rule->type << 24 | (u64) rule->protocol << 16;
  kv->key[1] = (u64) rule->outside_ip.as_u32 << 32 |
	       rule->inside_ip.as_u32;
  kv->key[2] = (u64) rule->outside_port << 48 |
	       (u64) rule->inside_port << 32;
}

static_always_inline void
cgnat_make_flow_key_from_flow (clib_bihash_kv_24_8_t *kv, cgnat_session_t *session)
{
  cgnat_make_flow_key (kv, session->instance_index, session->inside_fib_index,
				       session->inside_ip, session->remote_ip, session->inside_port,
				       session->remote_port, session->protocol);
}

static_always_inline void
cgnat_session_counter_inc (cgnat_main_t *cm, cgnat_mapping_t *mapping)
{
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_session_counters_t *c =
    vec_elt_at_index (cm->session_counters_per_thread,
		      vlib_get_main ()->thread_index);

  /* Per-thread, plain increments: only this thread ever writes its slot. */
  c->total++;
  if (mapping->protocol == IP_PROTOCOL_TCP)
    c->tcp++;
  else if (mapping->protocol == IP_PROTOCOL_UDP)
    c->udp++;
  else if (mapping->protocol == IP_PROTOCOL_ICMP)
    c->icmp++;

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (instance)
    clib_atomic_fetch_add (&instance->active_sessions, 1);
  pool = cgnat_pool_get_by_index (cm, mapping->pool_index);
  if (pool)
    clib_atomic_fetch_add (&pool->active_sessions, 1);
}

static_always_inline void
cgnat_session_counter_dec (cgnat_main_t *cm, cgnat_mapping_t *mapping)
{
  cgnat_instance_t *instance;
  cgnat_pool_t *pool;
  cgnat_session_counters_t *c =
    vec_elt_at_index (cm->session_counters_per_thread,
		      vlib_get_main ()->thread_index);

  c->total--;
  if (mapping->protocol == IP_PROTOCOL_TCP)
    c->tcp--;
  else if (mapping->protocol == IP_PROTOCOL_UDP)
    c->udp--;
  else if (mapping->protocol == IP_PROTOCOL_ICMP)
    c->icmp--;

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (instance)
    clib_atomic_fetch_add (&instance->active_sessions, -1);
  pool = cgnat_pool_get_by_index (cm, mapping->pool_index);
  if (pool)
    clib_atomic_fetch_add (&pool->active_sessions, -1);
}

/* Aggregate the per-thread counters.  May be called without a worker
 * barrier; individual u64 reads can race with writers, which is acceptable
 * for statistics. */
void
cgnat_session_counts (cgnat_main_t *cm, u64 *total, u64 *tcp, u64 *udp,
		      u64 *icmp)
{
  cgnat_session_counters_t *c;
  u64 t = 0, p = 0, u = 0, i = 0;

  vec_foreach (c, cm->session_counters_per_thread)
    {
      t += c->total;
      p += c->tcp;
      u += c->udp;
      i += c->icmp;
    }

  if (total)
    *total = t;
  if (tcp)
    *tcp = p;
  if (udp)
    *udp = u;
  if (icmp)
    *icmp = i;
}

static_always_inline void
cgnat_make_adf_remote_key (clib_bihash_kv_24_8_t *kv,
			   u32 outside_fib_index, ip4_address_t nat_ip,
			   u16 nat_port, u8 protocol, ip4_address_t remote_ip)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) outside_fib_index << 32 | nat_ip.as_u32;
  kv->key[1] = (u64) remote_ip.as_u32 << 32 | (u64) nat_port << 16 |
	       protocol;
}

static_always_inline void
cgnat_make_adf_remote_key_from_mapping (clib_bihash_kv_24_8_t *kv,
					cgnat_mapping_t *mapping,
					ip4_address_t remote_ip)
{
  cgnat_make_adf_remote_key (kv, mapping->outside_fib_index, mapping->nat_ip,
			     mapping->nat_port, mapping->protocol, remote_ip);
}

static_always_inline void
cgnat_adf_remote_lock (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_spinlock_lock (
    &cm->adf_remote_locks[cgnat_kv24_lock_index (
      kv, CGNAT_ADF_REMOTE_LOCK_BUCKETS)]);
}

static_always_inline void
cgnat_adf_remote_unlock (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_spinlock_unlock (
    &cm->adf_remote_locks[cgnat_kv24_lock_index (
      kv, CGNAT_ADF_REMOTE_LOCK_BUCKETS)]);
}

static_always_inline u32
cgnat_session_get_timeout (cgnat_main_t *cm, cgnat_session_t *session)
{
  cgnat_instance_t *instance =
    cgnat_instance_get_by_index (cm, session->instance_index);

  if (!instance)
    return 0;
  if (session->protocol == IP_PROTOCOL_TCP)
    {
      if (session->tcp_state == CGNAT_TCP_CLOSED)
	return 0;
      if (session->tcp_state == CGNAT_TCP_SYN)
	return instance->tcp_syn_timeout;
      if (session->tcp_state == CGNAT_TCP_FIN_RST)
	return instance->tcp_fin_rst_timeout;
      return instance->tcp_established_timeout;
    }

  if (session->protocol == IP_PROTOCOL_UDP)
    return instance->udp_timeout;
  if (session->protocol == IP_PROTOCOL_ICMP)
    return instance->icmp_timeout;
  return instance->other_timeout;
}


/* Like cgnat_mapping_get_if_valid, but allows mappings already scheduled for
 * deletion (e.g. sitting in mapping_reap_quarantine).  Session teardown must
 * still decrement active_sessions / user reservations / ADF remote refs even
 * when the mapping is no longer reachable from the lookup tables. */
static cgnat_mapping_t *
cgnat_mapping_get_for_session_delete (cgnat_main_t *cm, u64 value)
{
  u32 mapping_index = cgnat_value_get_index (value);
  u32 generation = cgnat_value_get_generation (value);
  cgnat_mapping_t *mapping;

  if (PREDICT_FALSE (pool_is_free_index (cm->mappings, mapping_index)))
    return 0;

  mapping = pool_elt_at_index (cm->mappings, mapping_index);
  if (PREDICT_FALSE (mapping->generation != generation))
    return 0;

  return mapping;
}

static_always_inline int
cgnat_icmp_error_extract_inner (vlib_buffer_t *b, ip4_header_t *ip,
				ip4_header_t **inner_ip, u8 *inner_protocol,
				u16 *inner_src_port, u16 *inner_dst_port)
{
  icmp46_header_t *icmp;
  nat_icmp_echo_header_t *echo;
  ip4_header_t *inner;
  u8 *l4;
  u16 inner_l4_len;
  u32 icmp_payload_len;

  icmp = (icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
  echo = (nat_icmp_echo_header_t *) (icmp + 1);
  inner = (ip4_header_t *) (echo + 1);

  /* The ICMP payload must carry at least the original IP header + 8 bytes. */
  icmp_payload_len =
    clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip) -
    sizeof (*icmp) - sizeof (*echo);
  if (PREDICT_FALSE (icmp_payload_len < sizeof (ip4_header_t) + 8))
    return VNET_API_ERROR_INVALID_VALUE;

  if (PREDICT_FALSE
      ((u8 *) inner + sizeof (*inner) >
       (u8 *) vlib_buffer_get_current (b) + b->current_length))
    return VNET_API_ERROR_INVALID_VALUE;

  *inner_ip = inner;
  *inner_protocol = inner->protocol;

  l4 = (u8 *) inner + ip4_header_bytes (inner);

  if (inner->protocol == IP_PROTOCOL_TCP)
    inner_l4_len = sizeof (tcp_header_t);
  else if (inner->protocol == IP_PROTOCOL_UDP)
    inner_l4_len = sizeof (udp_header_t);
  else if (inner->protocol == IP_PROTOCOL_ICMP)
    inner_l4_len = sizeof (icmp46_header_t) + sizeof (nat_icmp_echo_header_t);
  else
    return VNET_API_ERROR_UNSUPPORTED;

  /* ICMP errors only carry the original IP header + 8 bytes of L4; do not
   * trust inner->length (some implementations truncate it, others keep the
   * original value).  Only verify the data we actually have in the buffer. */
  if (PREDICT_FALSE
      (l4 + inner_l4_len >
       (u8 *) vlib_buffer_get_current (b) + b->current_length))
    return VNET_API_ERROR_INVALID_VALUE;

  if (inner->protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) l4;
      *inner_src_port = clib_net_to_host_u16 (tcp->src_port);
      *inner_dst_port = clib_net_to_host_u16 (tcp->dst_port);
    }
  else if (inner->protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) l4;
      *inner_src_port = clib_net_to_host_u16 (udp->src_port);
      *inner_dst_port = clib_net_to_host_u16 (udp->dst_port);
    }
  else
    {
      icmp46_header_t *inner_icmp = (icmp46_header_t *) l4;
      nat_icmp_echo_header_t *inner_echo =
	(nat_icmp_echo_header_t *) (inner_icmp + 1);
      *inner_src_port = clib_net_to_host_u16 (inner_echo->identifier);
      *inner_dst_port = *inner_src_port;
    }
  return 0;
}

static_always_inline int
cgnat_icmp_error_validate_checksum (vlib_main_t *vm, vlib_buffer_t *b,
				    ip4_header_t *ip)
{
  icmp46_header_t *icmp = (icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
  ip_csum_t sum;
  u16 checksum;

  sum = ip_incremental_checksum_buffer (
    vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b),
    clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip), 0);
  checksum = ~ip_csum_fold (sum);
  if (PREDICT_FALSE (checksum != 0 && checksum != 0xffff))
    return VNET_API_ERROR_INVALID_VALUE;
  return 0;
}

static_always_inline ip_csum_t
cgnat_ip_csum_delta_for_ip4_address (ip4_address_t old_addr,
				     ip4_address_t new_addr)
{
  ip_csum_t delta = 0;
  if (old_addr.as_u32 == new_addr.as_u32)
    return 0;
  /* Build delta = old - new.  Callers apply it via
   * ip_csum_sub_even (sum, delta) = sum + old - new, as required by
   * RFC 1624.  Note that ip_csum_add_even()/ip_csum_sub_even() subtract/add
   * their argument respectively (see src/vnet/ip/ip_packet.h). */
  delta = ip_csum_sub_even (delta, old_addr.as_u32);
  delta = ip_csum_add_even (delta, new_addr.as_u32);
  return delta;
}

static_always_inline void
cgnat_icmp_error_rewrite_inner_l4 (ip4_header_t *inner_ip, void *inner_l4,
				   u8 inner_protocol, ip4_address_t new_src_ip,
				   u16 new_src_port, ip4_address_t new_dst_ip,
				   u16 new_dst_port)
{
  ip_csum_t l3_delta = 0;
  ip_csum_t l4_delta = 0;

  /* Accumulate deltas with ones-complement-aware adds: a plain "+=" on two
   * ip_csum_t values can lose the end-around carry out of bit 63 when both
   * deltas went "negative" (borrowed), corrupting the result by one. */
  l3_delta =
    cgnat_ip_csum_delta_for_ip4_address (inner_ip->src_address, new_src_ip);
  l3_delta = ip_csum_sub_even (
    l3_delta,
    cgnat_ip_csum_delta_for_ip4_address (inner_ip->dst_address, new_dst_ip));

  if (inner_protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = inner_l4;
      /* All quantities fed into the delta must share one representation:
       * network-order field values, same as the raw checksum field and the
       * as_u32 addresses used by cgnat_ip_csum_delta_for_ip4_address(). */
      l4_delta = ip_csum_sub_even (l4_delta, tcp->src_port);
      l4_delta = ip_csum_sub_even (l4_delta, tcp->dst_port);
      l4_delta = ip_csum_add_even (l4_delta, clib_host_to_net_u16 (new_src_port));
      l4_delta = ip_csum_add_even (l4_delta, clib_host_to_net_u16 (new_dst_port));
      tcp->src_port = clib_host_to_net_u16 (new_src_port);
      tcp->dst_port = clib_host_to_net_u16 (new_dst_port);
      /* Apply the two deltas separately: ip_csum_sub_even() folds the
       * end-around carry of each addition, while "l3_delta + l4_delta"
       * would lose a carry out of bit 63. */
      ip_csum_t sum = tcp->checksum;
      sum = ip_csum_sub_even (sum, l3_delta);
      sum = ip_csum_sub_even (sum, l4_delta);
      tcp->checksum = ip_csum_fold (sum);
    }
  else if (inner_protocol == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = inner_l4;
      l4_delta = ip_csum_sub_even (l4_delta, udp->src_port);
      l4_delta = ip_csum_sub_even (l4_delta, udp->dst_port);
      l4_delta = ip_csum_add_even (l4_delta, clib_host_to_net_u16 (new_src_port));
      l4_delta = ip_csum_add_even (l4_delta, clib_host_to_net_u16 (new_dst_port));
      udp->src_port = clib_host_to_net_u16 (new_src_port);
      udp->dst_port = clib_host_to_net_u16 (new_dst_port);
      if (udp->checksum)
	{
	  ip_csum_t sum = udp->checksum;
	  sum = ip_csum_sub_even (sum, l3_delta);
	  sum = ip_csum_sub_even (sum, l4_delta);
	  udp->checksum = ip_csum_fold (sum);
	}
    }
  else if (inner_protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = inner_l4;
      nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp + 1);
      u16 old_id = echo->identifier;
      u16 new_id = clib_host_to_net_u16 (new_src_port);
      ip_csum_t sum = icmp->checksum;
      sum = ip_csum_update (sum, old_id, new_id, nat_icmp_echo_header_t,
			    identifier);
      icmp->checksum = ip_csum_fold (sum);
      echo->identifier = new_id;
    }
}

int
cgnat_icmp_error_translate_out2in (cgnat_main_t *cm, vlib_main_t *vm,
				   vlib_buffer_t *b, ip4_header_t *ip)
{
  ip4_header_t *inner_ip;
  u8 inner_protocol;
  u16 inner_src_port, inner_dst_port;
  clib_bihash_kv_16_8_t kv, value;
  cgnat_mapping_t *mapping;
  cgnat_instance_t *instance;
  u32 outside_fib_index;
  void *inner_l4;
  int rv;

  rv = cgnat_icmp_error_extract_inner (b, ip, &inner_ip, &inner_protocol,
				       &inner_src_port, &inner_dst_port);
  if (rv)
    return rv;

  outside_fib_index = fib_table_get_index_for_sw_if_index (
    FIB_PROTOCOL_IP4, vnet_buffer (b)->sw_if_index[VLIB_RX]);

  /* The original packet was inside -> remote; after CGNAT its source became
   * the public side.  The ICMP error is coming back to that public source,
   * so look it up in the out2in table. */
  cgnat_make_out2in_mapping_key (&kv, outside_fib_index, inner_ip->src_address,
				 inner_src_port, inner_protocol);
  if (cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv, &value))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  mapping = cgnat_mapping_get_if_valid (cm, value.value);
  if (!mapping)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = cgnat_icmp_error_validate_checksum (vm, b, ip);
  if (rv)
    return rv;

  inner_l4 = (u8 *) inner_ip + ip4_header_bytes (inner_ip);

  /* Rewrite outer IP destination to the inside host. */
  ip->dst_address = mapping->inside_ip;
  ip->checksum = ip4_header_checksum (ip);

  /* Rewrite inner IP source and L4 source to the inside values. */
  cgnat_icmp_error_rewrite_inner_l4 (inner_ip, inner_l4, inner_protocol,
				     mapping->inside_ip, mapping->inside_port,
				     inner_ip->dst_address, inner_dst_port);
  inner_ip->checksum = ip4_header_checksum (inner_ip);

  /* Recompute outer ICMP checksum over the rewritten payload.  Zero the
   * checksum field before summing and store the one's complement of the
   * folded sum. */
  {
    icmp46_header_t *icmp =
      (icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
    u32 icmp_len =
      clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip);
    ip_csum_t sum;

    icmp->checksum = 0;
    sum = ip_incremental_checksum_buffer (
      vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b), icmp_len, 0);
    icmp->checksum = ~ip_csum_fold (sum);
  }

  vnet_buffer (b)->sw_if_index[VLIB_TX] = mapping->inside_fib_index;
  return 0;
}

int
cgnat_icmp_error_translate_in2out (cgnat_main_t *cm, vlib_main_t *vm,
				   vlib_buffer_t *b, ip4_header_t *ip,
				   u32 instance_index, u32 inside_fib_index)
{
  ip4_header_t *inner_ip;
  u8 inner_protocol;
  u16 inner_src_port, inner_dst_port;
  clib_bihash_kv_16_8_t kv, value;
  cgnat_mapping_t *mapping;
  cgnat_instance_t *instance;
  void *inner_l4;
  int rv;

  rv = cgnat_icmp_error_extract_inner (b, ip, &inner_ip, &inner_protocol,
				       &inner_src_port, &inner_dst_port);
  if (rv)
    return rv;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /* The quoted datagram is the packet as the inside network saw it, i.e.
   * after out2in translation: src = remote, dst = inside_ip:inside_port.
   * Find the mapping that performed that translation in the in2out table;
   * the out2in table is keyed by public values and can never match the
   * private inside address quoted here. */
  cgnat_make_in2out_mapping_key (&kv, instance_index, inside_fib_index,
				 inner_ip->dst_address, inner_dst_port,
				 inner_protocol);
  if (cgnat_mapping_table_search (cm, &cm->in2out_mapping_table, &kv, &value))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  mapping = cgnat_mapping_get_if_valid (cm, value.value);
  if (!mapping)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = cgnat_icmp_error_validate_checksum (vm, b, ip);
  if (rv)
    return rv;

  inner_l4 = (u8 *) inner_ip + ip4_header_bytes (inner_ip);

  /* Rewrite the inner destination back to the public endpoint the remote
   * peer originally addressed (nat_ip:nat_port); the inner source (remote
   * endpoint) is left untouched. */
  cgnat_icmp_error_rewrite_inner_l4 (inner_ip, inner_l4, inner_protocol,
				     inner_ip->src_address, inner_src_port,
				     mapping->nat_ip, mapping->nat_port);
  inner_ip->checksum = ip4_header_checksum (inner_ip);

  /* The error itself was originated inside (by the NATed host or an inside
   * router); translate the outer source address with the same mapping so
   * the remote peer can associate the error with the public endpoint and
   * no private address leaks out. */
  ip->src_address = mapping->nat_ip;
  ip->checksum = ip4_header_checksum (ip);

  /* Recompute outer ICMP checksum over the rewritten payload.  Zero the
   * checksum field before summing and store the one's complement of the
   * folded sum. */
  {
    icmp46_header_t *icmp =
      (icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
    u32 icmp_len =
      clib_net_to_host_u16 (ip->length) - ip4_header_bytes (ip);
    ip_csum_t sum;

    icmp->checksum = 0;
    sum = ip_incremental_checksum_buffer (
      vm, b, (u8 *) icmp - (u8 *) vlib_buffer_get_current (b), icmp_len, 0);
    icmp->checksum = ~ip_csum_fold (sum);
  }

  /* The packet continues toward the remote destination on the outside fib. */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = mapping->outside_fib_index;
  return 0;
}

cgnat_mapping_t *
cgnat_mapping_alloc (cgnat_main_t *cm, u32 *mapping_index)
{
  cgnat_mapping_t *mapping;

  clib_spinlock_lock (&cm->mapping_pool_lock);
  /* The pool is preallocated at init and must never grow: a realloc would
   * move the base under lock-free datapath readers.  Fail instead and let
   * the caller drop the new flow. */
  if (PREDICT_FALSE (pool_free_elts (cm->mappings) == 0))
    {
      clib_spinlock_unlock (&cm->mapping_pool_lock);
      return 0;
    }
  pool_get_zero (cm->mappings, mapping);
  *mapping_index = mapping - cm->mappings;
  vec_validate (cm->mapping_generation_by_index, *mapping_index);
  mapping->generation = ++cm->mapping_generation_by_index[*mapping_index];
  clib_spinlock_unlock (&cm->mapping_pool_lock);

  return mapping;
}

static cgnat_session_t *
cgnat_session_alloc (cgnat_main_t *cm, u32 *session_index)
{
  cgnat_session_t *session;

  clib_spinlock_lock (&cm->session_pool_lock);
  /* Same fixed-capacity rule as cgnat_mapping_alloc: never move the base
   * under lock-free readers. */
  if (PREDICT_FALSE (pool_free_elts (cm->sessions) == 0))
    {
      clib_spinlock_unlock (&cm->session_pool_lock);
      return 0;
    }
  pool_get_zero (cm->sessions, session);
  *session_index = session - cm->sessions;
  vec_validate (cm->session_generation_by_index, *session_index);
  session->generation = ++cm->session_generation_by_index[*session_index];
  session->timer_handle = CGNAT_INVALID_INDEX;
  clib_spinlock_unlock (&cm->session_pool_lock);

  return session;
}

static_always_inline void
cgnat_session_free_unpublished (cgnat_main_t *cm, cgnat_session_t *session)
{
  clib_spinlock_lock (&cm->session_pool_lock);
  pool_put (cm->sessions, session);
  clib_spinlock_unlock (&cm->session_pool_lock);
}

/* The returned user pointer is only stable while the caller holds the
 * user's stripe lock (cgnat_user_lock) or a worker barrier: all deletions
 * of committed users run under one of the two. */
static cgnat_user_t *
cgnat_mapping_get_user (cgnat_main_t *cm, cgnat_mapping_t *mapping,
			cgnat_instance_t **instancep)
{
  cgnat_instance_t *instance;
  cgnat_user_t *user;

  if (mapping->user_index == CGNAT_INVALID_INDEX)
    return 0;

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (!instance)
    return 0;

  user = cgnat_user_from_index (instance, mapping->user_index);
  if (!user)
    return 0;

  if (instancep)
    *instancep = instance;
  return user;
}

/* Call with the adf stripe lock for kv held: refcnt is a plain counter
 * shared by sessions on different workers, so lookup + refcnt + table
 * mutation must run as one critical section. */
static int
cgnat_adf_remote_ref_locked (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_bihash_kv_24_8_t value;
  cgnat_adf_remote_t *remote;
  u32 remote_index;

  if (!clib_bihash_search_24_8 (&cm->adf_remote_table, kv, &value))
    {
      if (pool_is_free_index (cm->adf_remotes,
			      cgnat_value_get_index (value.value)))
	{
	  clib_bihash_add_del_24_8 (&cm->adf_remote_table, kv, 0);
	}
      else
	{
	  remote = pool_elt_at_index (cm->adf_remotes,
				      cgnat_value_get_index (value.value));
	  if (remote->generation == cgnat_value_get_generation (value.value))
	    {
	      remote->refcnt++;
	      return 0;
	    }
	  clib_bihash_add_del_24_8 (&cm->adf_remote_table, kv, 0);
	}
    }

  clib_spinlock_lock (&cm->adf_remote_pool_lock);
  pool_get_zero (cm->adf_remotes, remote);
  remote_index = remote - cm->adf_remotes;
  vec_validate (cm->adf_remote_generation_by_index, remote_index);
  remote->generation = ++cm->adf_remote_generation_by_index[remote_index];
  if (!remote->generation)
    remote->generation = ++cm->adf_remote_generation_by_index[remote_index];
  clib_spinlock_unlock (&cm->adf_remote_pool_lock);

  /* Element-local init does not need the pool lock. */
  remote->refcnt = 1;
  remote->kv = *kv;

  kv->value = cgnat_index_to_value (remote_index, remote->generation);
  if (clib_bihash_add_del_24_8 (&cm->adf_remote_table, kv, 1))
    {
      clib_spinlock_lock (&cm->adf_remote_pool_lock);
      pool_put (cm->adf_remotes, remote);
      clib_spinlock_unlock (&cm->adf_remote_pool_lock);
      return VNET_API_ERROR_BUG;
    }
  return 0;
}

u8
cgnat_adf_remote_allowed (cgnat_main_t *cm, cgnat_mapping_t *mapping,
			  ip4_address_t remote_ip)
{
  clib_bihash_kv_24_8_t kv, value;
  cgnat_adf_remote_t *remote;
  u8 allowed = 0;

  if (!cgnat_mapping_is_auto (mapping))
    return 1;

  cgnat_make_adf_remote_key_from_mapping (&kv, mapping, remote_ip);
  /* Take the stripe lock: the adf_remotes pool has no reservation and can
   * be reallocated by a concurrent ref, and refcnt is updated under this
   * lock. */
  cgnat_adf_remote_lock (cm, &kv);
  if (!clib_bihash_search_24_8 (&cm->adf_remote_table, &kv, &value))
    {
      if (pool_is_free_index (cm->adf_remotes,
			      cgnat_value_get_index (value.value)))
	{
	  cgnat_adf_remote_unlock (cm, &kv);
	  return 0;
	}
      remote = pool_elt_at_index (cm->adf_remotes,
				  cgnat_value_get_index (value.value));
      allowed = remote->generation == cgnat_value_get_generation (value.value) &&
		remote->refcnt;
    }
  cgnat_adf_remote_unlock (cm, &kv);

  return allowed;
}

/* Call with the adf stripe lock for kv held (same critical-section rule as
 * cgnat_adf_remote_ref_locked). */
static void
cgnat_adf_remote_unref_locked (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_bihash_kv_24_8_t value;
  cgnat_adf_remote_t *remote;

  if (clib_bihash_search_24_8 (&cm->adf_remote_table, kv, &value))
    return;

  if (pool_is_free_index (cm->adf_remotes, cgnat_value_get_index (value.value)))
    return;

  remote = pool_elt_at_index (cm->adf_remotes, cgnat_value_get_index (value.value));
  if (remote->generation != cgnat_value_get_generation (value.value))
    return;

  if (remote->refcnt)
    remote->refcnt--;

  if (!remote->refcnt)
    {
      clib_bihash_add_del_24_8 (&cm->adf_remote_table, &remote->kv, 0);
      clib_spinlock_lock (&cm->adf_remote_pool_lock);
      pool_put (cm->adf_remotes, remote);
      clib_spinlock_unlock (&cm->adf_remote_pool_lock);
    }
}

int
cgnat_session_ensure_adf_remote (cgnat_main_t *cm, cgnat_mapping_t *mapping,
				 cgnat_session_t *session)
{
  clib_bihash_kv_24_8_t kv;
  int rv;

  if (!cgnat_mapping_is_auto (mapping) ||
      (session->flags & CGNAT_SESSION_FLAG_ADF_REMOTE_RECORDED))
    return 0;

  /* The flag is re-checked under the adf stripe lock: the delete path reads
   * ADF_REMOTE_RECORDED under the same lock before unref'ing, so ref+record
   * here and read+unref there are mutually exclusive and can neither leak a
   * reference nor double-free one.  A session already marked DELETING is
   * refused: its delete side has already passed the unref point. */
  cgnat_make_adf_remote_key_from_mapping (&kv, mapping, session->remote_ip);
  cgnat_adf_remote_lock (cm, &kv);
  if (session->flags & CGNAT_SESSION_FLAG_ADF_REMOTE_RECORDED)
    {
      cgnat_adf_remote_unlock (cm, &kv);
      return 0;
    }
  if (PREDICT_FALSE (session->flags & CGNAT_SESSION_FLAG_DELETING))
    {
      cgnat_adf_remote_unlock (cm, &kv);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  rv = cgnat_adf_remote_ref_locked (cm, &kv);
  if (!rv)
    clib_atomic_fetch_or (&session->flags,
			  CGNAT_SESSION_FLAG_ADF_REMOTE_RECORDED);
  cgnat_adf_remote_unlock (cm, &kv);
  return rv;
}

static_always_inline int
cgnat_user_session_reserve (cgnat_instance_t *instance, cgnat_user_t *user,
			    f64 now)
{
  if (!instance->max_sessions_per_user && !instance->max_session_create_rate)
  {
    clib_atomic_fetch_add (&user->active_sessions, 1);
    return 0;
  }

  clib_spinlock_lock (&user->session_lock);

  if (instance->max_sessions_per_user &&
      user->active_sessions >= instance->max_sessions_per_user)
  {
    user->session_limit_drops++;
    clib_spinlock_unlock (&user->session_lock);
    return VNET_API_ERROR_LIMIT_EXCEEDED;
  }

  if (instance->max_session_create_rate)
  {
    if (now - user->session_rate_window_start >= 1.0)
    {
      user->session_rate_window_start = now;
      user->session_rate_count = 0;
    }

    if (user->session_rate_count >= instance->max_session_create_rate)
    {
      user->session_rate_drops++;
      clib_spinlock_unlock (&user->session_lock);
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

    user->session_rate_count++;
  }

  clib_spinlock_unlock (&user->session_lock);

  clib_atomic_fetch_add (&user->active_sessions, 1);
  return 0;
}

static_always_inline void
cgnat_user_session_unreserve (cgnat_user_t *user)
{
  if (user->active_sessions)
    clib_atomic_fetch_add (&user->active_sessions, -1);
}

void
cgnat_session_start_timer (cgnat_main_t *cm, cgnat_session_t *session, f64 now)
{
  cgnat_session_timer_t *entry;
  tw_timer_wheel_2t_2w_512sl_t *w = &cm->session_timer_wheel;
  u32 delay, entry_index, timeout, wh;
  f64 remaining;

  timeout = cgnat_session_get_timeout (cm, session);
  if (!timeout)
    return;
  remaining = timeout - (now - session->last_active);
  if (remaining <= 0)
    delay = 1;
  else
    {
      delay = (u32) remaining;
      if ((f64) delay < remaining)
	delay++;
      delay = clib_min (clib_max (delay, 1), CGNAT_TIMER_MAX_DELAY);
    }

  clib_spinlock_lock (&cm->session_timer_lock);

  /* Fast case: the session already has an armed timer - update it in place
   * (no new entry, nothing orphaned).  The identity chain validates that the
   * handle still names this session's own timer entry: a wheel slot is freed
   * at expire time and may have been reissued to another session's timer,
   * so the wheel entry's user_handle must resolve back to our timer entry,
   * which must point back at this session and this handle. */
  wh = session->timer_handle;
  if (wh != CGNAT_INVALID_INDEX &&
      !tw_timer_handle_is_free_2t_2w_512sl (w, wh))
    {
      u32 ei = pool_elt_at_index (w->timers, wh)->user_handle & 0x7FFFFFFF;

      if (!pool_is_free_index (cm->session_timers, ei))
	{
	  entry = pool_elt_at_index (cm->session_timers, ei);
	  if (entry->session_index == (u32) (session - cm->sessions) &&
	      entry->session_generation == session->generation &&
	      entry->wheel_handle == wh)
	    {
	      tw_timer_update_2t_2w_512sl (w, wh, delay);
	      clib_spinlock_unlock (&cm->session_timer_lock);
	      return;
	    }
	}
    }

  /* Fresh arm (creation, or the old entry already fired). */
  pool_get_zero (cm->session_timers, entry);
  entry_index = entry - cm->session_timers;
  entry->session_index = session - cm->sessions;
  entry->session_generation = session->generation;
  wh = tw_timer_start_2t_2w_512sl (w, entry_index, 0, delay);
  entry->wheel_handle = wh;
  /* Atomic: the delete path stores INVALID without session_timer_lock. */
  clib_atomic_store_relax_n (&session->timer_handle, wh);

  clib_spinlock_unlock (&cm->session_timer_lock);
}

static void
cgnat_log_session (cgnat_main_t *cm, char *event, char *reason,
		   cgnat_session_t *session)
{
  cgnat_instance_t *instance;
  cgnat_log_event_t log_event;

  instance = cgnat_instance_get_by_index (cm, session->instance_index);
  if (!instance || !instance->syslog_enabled ||
      instance->log_mode != CGNAT_LOG_MODE_SESSION)
    return;

  /* May run on a worker thread: vlib_log is main-thread only, so snapshot a
   * fixed-size event and hand it to the main-thread log process. */
  clib_memset (&log_event, 0, sizeof (log_event));
  log_event.kind = CGNAT_LOG_EVENT_KIND_SESSION;
  cgnat_log_event_set_common (&log_event, instance, event, reason);
  log_event.session.private_ip = session->inside_ip;
  log_event.session.private_port = session->inside_port;
  log_event.session.public_ip = session->nat_ip;
  log_event.session.public_port = session->nat_port;
  log_event.session.remote_ip = session->remote_ip;
  log_event.session.remote_port = session->remote_port;
  log_event.session.protocol = session->protocol;
  log_event.session.mapping_type = session->mapping_type;
  cgnat_log_enqueue (&log_event);
}

static void cgnat_static_addr_mapping_schedule_delete (cgnat_main_t *cm,
					    cgnat_mapping_t *mapping);

/* Park a deleted session for reclamation under the next worker barrier.
 * Until cgnat_session_reap() runs, the pool slot stays allocated with
 * DELETING set, so a lock-free session-table reader that already resolved
 * the value can still lock the session and revalidate it. */
static_always_inline void
cgnat_session_reap_push (cgnat_main_t *cm, cgnat_session_t *session)
{
  u64 value =
    cgnat_index_to_value (session - cm->sessions, session->generation);

  clib_spinlock_lock (&cm->session_reap_lock);
  vec_add1 (cm->session_reap_queue, value);
  clib_spinlock_unlock (&cm->session_reap_lock);
}

static void
cgnat_session_delete_with_locks (cgnat_main_t *cm, cgnat_session_t *session,
				 clib_bihash_kv_24_8_t *kv,
				 clib_bihash_kv_24_8_t *rkv, char *reason,
				 u8 timer_just_fired)
{
  clib_bihash_kv_24_8_t current;
  cgnat_mapping_t *mapping;
  cgnat_instance_t *instance;
  cgnat_user_t *user;
  u32 previous_active_sessions = 0;
  u32 release_user_instance_index = CGNAT_INVALID_INDEX;
  u32 release_user_inside_fib_index = CGNAT_INVALID_INDEX;
  ip4_address_t release_user_private_ip = { 0 };
  u32 mapping_index = CGNAT_INVALID_INDEX;
  u32 mapping_generation = 0;
  u8 mapping_is_auto = 0;

  /* Atomic test-and-set: the DELETING bit both serializes concurrent
   * deleters (barrier-bound timer/CLI paths vs the worker-side
   * adf_remote_ref_failed self-delete) and tells lock-free readers to back
   * off.  session->flags is only ever modified with atomic RMW. */
  if (clib_atomic_fetch_or (&session->flags, CGNAT_SESSION_FLAG_DELETING) &
      CGNAT_SESSION_FLAG_DELETING)
    return;

  /* The value check runs under the stripe lock together with the delete:
   * checking first and locking afterwards could remove the table entry of a
   * re-created same-flow session. */
  cgnat_session_table_lock (cm, kv);
  if (!clib_bihash_search_24_8 (&cm->session_table, kv, &current) &&
      current.value == cgnat_index_to_value (session - cm->sessions, session->generation))
    clib_bihash_add_del_24_8 (&cm->session_table, kv, 0);
  cgnat_session_table_unlock (cm, kv);
  /* Remove the reverse entry as well; the value check protects against
   * deleting an entry that a recreated same-flow session already owns. */
  if (rkv)
    {
      clib_bihash_kv_24_8_t rcur;

      cgnat_session_table_lock (cm, rkv);
      if (!clib_bihash_search_24_8 (&cm->session_table, rkv, &rcur) &&
	  rcur.value == cgnat_index_to_value (session - cm->sessions, session->generation))
	clib_bihash_add_del_24_8 (&cm->session_table, rkv, 0);
      cgnat_session_table_unlock (cm, rkv);
    }

  mapping = cgnat_mapping_get_for_session_delete (cm,
    cgnat_index_to_value (session->mapping_index, session->mapping_generation));
  if (mapping)
    {
      u32 old, new;

      mapping_index = session->mapping_index;
      mapping_generation = session->mapping_generation;
      mapping_is_auto = cgnat_mapping_is_auto (mapping);

      /* Atomic decrement with CAS to avoid the check-then-act race on
       * mapping->active_sessions; the create path increments it with an
       * atomic add, so no mapping-wide lock is needed on either side. */
      do
	{
	  old = clib_atomic_load_relax_n (&mapping->active_sessions);
	  if (old == 0)
	    break;
	  new = old - 1;
	}
      while (!clib_atomic_cmp_and_swap_acq_relax_n (
		      &mapping->active_sessions, &old, new, 0));
      previous_active_sessions = old;
      if (old)
	cgnat_session_counter_dec (cm, mapping);

      instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
      if (instance)
	{
	  /* Hold the user's stripe lock across lookup + unreserve: every
	   * deletion of a committed user (idle release, cooling expiry)
	   * runs under the same stripe, so the user cannot be freed or
	   * recycled while we touch it. */
	  cgnat_user_lock (instance, mapping->inside_fib_index, mapping->inside_ip);
	  user = cgnat_mapping_get_user (cm, mapping, 0);
	  if (user)
	    {
	      cgnat_user_session_unreserve (user);
	      release_user_instance_index = mapping->instance_index;
	      release_user_inside_fib_index = mapping->inside_fib_index;
	      release_user_private_ip = mapping->inside_ip;
	    }
	  cgnat_user_unlock (instance, mapping->inside_fib_index, mapping->inside_ip);
	}
      if (mapping_is_auto && mapping->filter_mode == CGNAT_FILTER_MODE_ADF)
	{
	  clib_bihash_kv_24_8_t adf_kv;

	  /* Pairs with cgnat_session_ensure_adf_remote: the RECORDED flag is
	   * read and the unref runs under the same adf stripe lock, so a
	   * racing ref+record can neither slip past this check nor be
	   * unref'ed twice. */
	  cgnat_make_adf_remote_key_from_mapping (&adf_kv, mapping,
						  session->remote_ip);
	  cgnat_adf_remote_lock (cm, &adf_kv);
	  if (session->flags & CGNAT_SESSION_FLAG_ADF_REMOTE_RECORDED)
	    cgnat_adf_remote_unref_locked (cm, &adf_kv);
	  cgnat_adf_remote_unlock (cm, &adf_kv);
	}
    }

  /* No lock needed: the session is already invisible (table entries removed,
   * DELETING set) and the log only snapshots immutable identity fields. */
  session->tcp_state = CGNAT_TCP_CLOSED;

  /* Stop the armed aging timer right away so its entry does not linger in
   * the wheel until the original fire time.  timer_just_fired (expiry-driven
   * deletes) means the session's armed entry is the one currently being
   * processed: already out of the wheel, pool_put by the expire flush.
   * (Residual race: a datapath re-arm slipping in after the caller's
   * validation leaves an orphan that is discarded at its fire time.)
   *
   * Otherwise stop under session_timer_lock.  The wheel entry being still
   * armed (not handle_is_free) implies our timer entry cannot sit in any
   * in-flight expire batch, so pool_put here cannot race the expiry path's
   * unlocked reads.  The identity chain guards against a recycled wheel
   * handle aliasing another session's timer. */
  if (timer_just_fired)
    clib_atomic_store_relax_n (&session->timer_handle, CGNAT_INVALID_INDEX);
  else
    {
      u32 wh = clib_atomic_swap_acq_n (&session->timer_handle,
				       CGNAT_INVALID_INDEX);

      if (wh != CGNAT_INVALID_INDEX)
	{
	  tw_timer_wheel_2t_2w_512sl_t *w = &cm->session_timer_wheel;

	  clib_spinlock_lock (&cm->session_timer_lock);
	  if (!tw_timer_handle_is_free_2t_2w_512sl (w, wh))
	    {
	      u32 ei =
		pool_elt_at_index (w->timers, wh)->user_handle & 0x7FFFFFFF;

	      if (!pool_is_free_index (cm->session_timers, ei))
		{
		  cgnat_session_timer_t *entry =
		    pool_elt_at_index (cm->session_timers, ei);

		  if (entry->session_index == (u32) (session - cm->sessions) &&
		      entry->session_generation == session->generation &&
		      entry->wheel_handle == wh)
		    {
		      tw_timer_stop_2t_2w_512sl (w, wh);
		      pool_put_index (cm->session_timers, ei);
		    }
		}
	    }
	  clib_spinlock_unlock (&cm->session_timer_lock);
	}
    }
  cgnat_log_session (cm, "SESSION_DELETE", reason, session);

  if (release_user_instance_index != CGNAT_INVALID_INDEX)
    cgnat_pba_release_user_if_idle (release_user_instance_index,
				    release_user_inside_fib_index,
				    release_user_private_ip);

  /* The last session schedules the mapping for deletion; the mapping itself
   * is reclaimed by the reap path once it is out of the lookup tables. */
  if (mapping_index != CGNAT_INVALID_INDEX && mapping_is_auto &&
      previous_active_sessions == 1)
    {
      mapping = cgnat_mapping_get_if_valid (
	cm, cgnat_index_to_value (mapping_index, mapping_generation));
      if (mapping)
	cgnat_dynamic_mapping_schedule_delete (cm, mapping);
    }

  /* Address-level static mappings are created on demand per session; once
   * the last session goes away, release the exact mapping as well. */
  if (mapping_index != CGNAT_INVALID_INDEX && !mapping_is_auto &&
      previous_active_sessions == 1)
    {
      mapping = cgnat_mapping_get_if_valid (
	cm, cgnat_index_to_value (mapping_index, mapping_generation));
      if (mapping && mapping->mapping_type == CGNAT_MAPPING_STATIC)
	cgnat_static_addr_mapping_schedule_delete (cm, mapping);
    }

  /* Deferred reclamation: the slot stays allocated (with DELETING set) until
   * cgnat_session_reap() runs under a worker barrier, so lock-free
   * session-table readers holding a resolved pointer stay safe. */
  cgnat_session_reap_push (cm, session);
}

static void
cgnat_session_delete (cgnat_main_t *cm, cgnat_session_t *session, char *reason)
{
  clib_bihash_kv_24_8_t kv, rkv;
  cgnat_instance_t *instance;
  u8 have_reverse = 0;

  cgnat_make_flow_key_from_flow (&kv, session);

  /* The session's identity fields are immutable after creation, so reading
   * them unlocked here is safe; all synchronization lives in
   * cgnat_session_delete_with_locks(). */
  instance = cgnat_instance_get_by_index (cm, session->instance_index);
  if (instance)
    {
      cgnat_make_reverse_flow_key (&rkv, instance->outside_fib_index,
				   session->nat_ip, session->remote_ip,
				   session->nat_port, session->remote_port,
				   session->protocol);
      have_reverse = 1;
    }
  cgnat_session_delete_with_locks (cm, session, &kv, have_reverse ? &rkv : 0, reason, 0);
}

static_always_inline int
cgnat_session_filter_match (cgnat_session_t *session,
			    cgnat_session_filter_t *filter)
{
  if (!filter)
    return 1;
  if ((filter->flags & CGNAT_SESSION_FILTER_INSIDE_IP) &&
      session->inside_ip.as_u32 != filter->inside_ip.as_u32)
    return 0;
  if ((filter->flags & CGNAT_SESSION_FILTER_INSIDE_PORT) &&
      session->inside_port != filter->inside_port)
    return 0;
  if ((filter->flags & CGNAT_SESSION_FILTER_PUBLIC_IP) &&
      session->nat_ip.as_u32 != filter->public_ip.as_u32)
    return 0;
  if ((filter->flags & CGNAT_SESSION_FILTER_PUBLIC_PORT) &&
      session->nat_port != filter->public_port)
    return 0;
  if ((filter->flags & CGNAT_SESSION_FILTER_PROTOCOL) &&
      session->protocol != filter->protocol)
    return 0;
  return 1;
}

cgnat_session_t *
cgnat_session_snapshot (cgnat_session_filter_t *filter)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_session_t *session, *snapshot = 0;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  pool_foreach (session, cm->sessions)
    if (!(session->flags & CGNAT_SESSION_FLAG_DELETING) &&
	cgnat_session_filter_match (session, filter))
      vec_add1 (snapshot, *session);
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return snapshot;
}

u32
cgnat_session_delete_matching (cgnat_session_filter_t *filter)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 session_index, next_index, deleted = 0;

  if (!cm->sessions)
    return 0;

  vlib_worker_thread_barrier_sync (cm->vlib_main);
  session_index = pool_get_first_index (cm->sessions);
  while (session_index < vec_len (cm->sessions))
    {
      cgnat_session_t *session = pool_elt_at_index (cm->sessions, session_index);
      next_index = pool_next_index (cm->sessions, session_index);
      if (!(session->flags & CGNAT_SESSION_FLAG_DELETING) &&
	  cgnat_session_filter_match (session, filter))
	{
	  cgnat_session_delete (cm, session, "force_delete");
	  deleted++;
	}
      session_index = next_index;
    }
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return deleted;
}

static void
cgnat_session_process_expired_timers (u32 *expired_timers)
{
  cgnat_main_t *cm = &cgnat_main;
  f64 now = vlib_time_now (cm->vlib_main);
  u32 i, processed = 0;
  /* Wheel/pool bookkeeping is batched and flushed under a single
   * session_timer_lock section at the end.  Safe because the entries being
   * processed belong to neither the wheel nor the free pool while we work
   * on them, session deletion invalidates armed timers only via
   * timer_handle invalidation (never touches the timer pool/wheel), and
   * nothing else ever puts entries back into the session_timers pool.
   *
   * Per-batch processing cap: bounds the main-thread time one wakeup spends
   * here; entries beyond the cap are re-armed as-is with a 1s delay (the
   * wheel's tick granularity) and retried on a later wakeup. */
  u32 *pending_put = 0;
  u32 *pending_rearm_keep = 0;
  u32 *pending_rearm = 0;
  u32 *rearm_delays = 0;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      cgnat_session_timer_t *entry;
      cgnat_session_t *session;
      u32 entry_index, timeout;
      clib_bihash_kv_24_8_t kv, current, rkv;
      cgnat_instance_t *instance;
      u64 session_value;
      u8 have_reverse = 0;

      entry_index = expired_timers[i] & 0x7FFFFFFF;
      if (processed >= CGNAT_SESSION_TIMER_MAX_EXPIRATIONS)
	{
	  /* Over the per-batch cap: re-arm as-is for 1s, no gen bump. */
	  vec_add1 (pending_rearm_keep, entry_index);
	  continue;
	}

      processed++;
      if (pool_is_free_index (cm->session_timers, entry_index))
	continue;

      entry = pool_elt_at_index (cm->session_timers, entry_index);
      if (pool_is_free_index (cm->sessions, entry->session_index))
	{
	  vec_add1 (pending_put, entry_index);
	  continue;
	}

      session = pool_elt_at_index (cm->sessions, entry->session_index);
      cgnat_make_flow_key_from_flow (&kv, session);

      /* Identity fields are immutable after creation; synchronization lives
       * in cgnat_session_delete_with_locks(). */
      instance = cgnat_instance_get_by_index (cm, session->instance_index);
      if (instance)
	{
	  cgnat_make_reverse_flow_key (&rkv, instance->outside_fib_index,
				       session->nat_ip, session->remote_ip,
				       session->nat_port, session->remote_port,
				       session->protocol);
	  have_reverse = 1;
	}

      session_value = cgnat_index_to_value (entry->session_index, entry->session_generation);

      if (clib_bihash_search_24_8 (&cm->session_table, &kv, &current) || current.value != session_value)
	{
	  vec_add1 (pending_put, entry_index);
	  continue;
	}

      if (session->generation != entry->session_generation ||
	  session->timer_handle != entry->wheel_handle ||
	  (session->flags & CGNAT_SESSION_FLAG_DELETING))
	{
	  vec_add1 (pending_put, entry_index);
	  continue;
	}

      timeout = cgnat_session_get_timeout (cm, session);
      if (!timeout || session->tcp_state == CGNAT_TCP_CLOSED)
	{
	  cgnat_session_delete_with_locks (cm, session, &kv, have_reverse ? &rkv : 0, "tcp_closed", 1);
	  vec_add1 (pending_put, entry_index);
	  continue;
	}

      if (now - session->last_active < timeout)
	{
	  /* Still active: re-arm the same entry.  The wheel entry was freed
	   * when it fired, so the flush section re-arms it and refreshes
	   * entry->wheel_handle / session->timer_handle. */
	  u32 delay;
	  f64 remaining = (f64) timeout - (now - session->last_active);

	  if (remaining <= 0)
	    delay = 1;
	  else
	    {
	      delay = (u32) remaining;
	      if ((f64) delay < remaining)
		delay++;
	      delay = clib_min (clib_max (delay, 1), CGNAT_TIMER_MAX_DELAY);
	    }
	  vec_add1 (pending_rearm, entry_index);
	  vec_add1 (rearm_delays, delay);
	  continue;
	}

      cgnat_session_delete_with_locks (cm, session, &kv, have_reverse ? &rkv : 0, "timeout", 1);
      vec_add1 (pending_put, entry_index);
    }

  if (vec_len (pending_put) + vec_len (pending_rearm_keep) +
      vec_len (pending_rearm))
    {
      u32 *pi;

      clib_spinlock_lock (&cm->session_timer_lock);

      /* Fired wheel entries were freed at expire time, so both re-arm kinds
       * need a fresh tw_timer_start; refresh the entry and session handles
       * to the new wheel slot.  If the session was concurrently deleted
       * since the loop above, the armed timer fires later and is discarded
       * by the generation/DELETING/handle checks. */
      vec_foreach (pi, pending_rearm_keep)
	{
	  cgnat_session_timer_t *entry =
	    pool_elt_at_index (cm->session_timers, *pi);
	  cgnat_session_t *session =
	    pool_elt_at_index (cm->sessions, entry->session_index);
	  u32 wh = tw_timer_start_2t_2w_512sl (&cm->session_timer_wheel, *pi,
					     0, 1);

	  entry->wheel_handle = wh;
	  clib_atomic_store_relax_n (&session->timer_handle, wh);
	}

      for (i = 0; i < vec_len (pending_rearm); i++)
	{
	  u32 ei = pending_rearm[i];
	  cgnat_session_timer_t *entry =
	    pool_elt_at_index (cm->session_timers, ei);
	  cgnat_session_t *session =
	    pool_elt_at_index (cm->sessions, entry->session_index);
	  u32 wh = tw_timer_start_2t_2w_512sl (&cm->session_timer_wheel, ei, 0,
					     rearm_delays[i]);

	  entry->wheel_handle = wh;
	  clib_atomic_store_relax_n (&session->timer_handle, wh);
	}

      vec_foreach (pi, pending_put)
	pool_put_index (cm->session_timers, *pi);

      clib_spinlock_unlock (&cm->session_timer_lock);
    }

  vec_free (pending_put);
  vec_free (pending_rearm_keep);
  vec_free (pending_rearm);
  vec_free (rearm_delays);
}

int
cgnat_session_lookup_or_create (cgnat_main_t *cm, cgnat_mapping_t *mapping,
				 ip4_address_t remote_ip, u16 remote_port,
				 u8 direction_flag, tcp_header_t *tcp, f64 now,
				 u8 allow_create, u8 ensure_adf_remote)
{
  clib_bihash_kv_24_8_t kv, rkv, value;
  cgnat_instance_t *instance = 0;
  cgnat_session_t *session;
  cgnat_session_t *new_session;
  cgnat_user_t *user;
  u32 session_index;
  u32 new_session_index;
  int rv;

  cgnat_make_flow_key (&kv, mapping->instance_index,
		       mapping->inside_fib_index, mapping->inside_ip,
		       remote_ip, mapping->inside_port, remote_port,
		       mapping->protocol);

  /* No initial table search here: every caller gets here right after a
   * fast-path miss on this same key, and the create section below re-checks
   * under the bucket lock anyway (the in2out/out2in first packets of one
   * connection can race on different workers).  A redundant first search
   * would only save a wasted alloc/free in that rare race. */
  if (!allow_create)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  new_session = cgnat_session_alloc (cm, &new_session_index);
  if (PREDICT_FALSE (!new_session))
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  /* The session is stored under both the forward and the reverse
   * (translated) 5-tuple in the same table; lock both hash buckets in
   * bucket-index order. */
  cgnat_make_reverse_flow_key (&rkv, mapping->outside_fib_index,
			       mapping->nat_ip, remote_ip, mapping->nat_port,
			       remote_port, mapping->protocol);
  // check whether session already create
  if (!clib_bihash_search_24_8 (&cm->session_table, &kv, &value))
  {
	  session = cgnat_session_get_if_valid (cm, value.value);
	  if (session)
	    {
	      cgnat_session_free_unpublished (cm, new_session);
          if (PREDICT_FALSE (session->flags & CGNAT_SESSION_FLAG_DELETING))
		{
		  return VNET_API_ERROR_NO_SUCH_ENTRY;
		}
          if (cgnat_session_touch (session, now, direction_flag, tcp) && session->tcp_state == CGNAT_TCP_FIN_RST)
		{
		  cgnat_session_start_timer (cm, session, now);
		}
	      if (ensure_adf_remote)
		{
		  rv = cgnat_session_ensure_adf_remote (cm, mapping, session);
		  if (rv)
		    {
		      return rv;
		    }
		}
	      return 0;
	    }

	  cgnat_session_table_lock (cm, &kv);
	  clib_bihash_add_del_24_8 (&cm->session_table, &kv, 0);
	  cgnat_session_table_unlock (cm, &kv);
  }

  // check mapping status, if apping is deleting
  if (PREDICT_FALSE (clib_atomic_load_acq_n (&mapping->flags) &
		     CGNAT_MAPPING_FLAG_DELETING))
    {
      cgnat_session_free_unpublished (cm, new_session);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  // only dynamic-mapping users can be session-limited
  if (mapping->mapping_type == CGNAT_MAPPING_STATIC)
    user = 0;
  else
  {
    instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
    if (PREDICT_FALSE (!instance))
    {
      cgnat_session_free_unpublished (cm, new_session);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

    /* Hold the user's stripe lock across lookup + reserve so the user
     * cannot be deleted or recycled in between: every deletion of a
     * committed user runs under the same stripe. */
    cgnat_user_lock (instance, mapping->inside_fib_index, mapping->inside_ip);
    user = cgnat_mapping_get_user (cm, mapping, 0);
    if (PREDICT_FALSE (!user))
    {
      cgnat_user_unlock (instance, mapping->inside_fib_index, mapping->inside_ip);
      cgnat_session_free_unpublished (cm, new_session);
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

    rv = cgnat_user_session_reserve (instance, user, now);
    cgnat_user_unlock (instance, mapping->inside_fib_index,
		       mapping->inside_ip);
    if (rv)
    {
      cgnat_session_free_unpublished (cm, new_session);
      return rv;
    }
  }

  // create sessions
  session = new_session;
  session_index = new_session_index;
  session->mapping_index = mapping - cm->mappings;
  session->mapping_generation = mapping->generation;
  session->inside_ip = mapping->inside_ip;
  session->remote_ip = remote_ip;
  session->nat_ip = mapping->nat_ip;
  session->inside_port = mapping->inside_port;
  session->remote_port = remote_port;
  session->nat_port = mapping->nat_port;
  session->instance_index = mapping->instance_index;
  session->inside_fib_index = mapping->inside_fib_index;
  session->outside_fib_index = mapping->outside_fib_index;
  session->protocol = mapping->protocol;
  session->tcp_state = CGNAT_TCP_SYN;
  session->mapping_type = mapping->mapping_type;
  session->last_active = now;
  session->flags = direction_flag;
  /* Not yet published: no concurrent reader, no lock needed. */
  cgnat_update_tcp_state (session, tcp);

  kv.value = cgnat_index_to_value (session_index, session->generation);
  rkv.value = kv.value;


  cgnat_session_table_lock (cm, &kv);
  rv = clib_bihash_add_del_24_8 (&cm->session_table, &kv, 1);
  cgnat_session_table_unlock (cm, &kv);
  if (rv)
  {
    if (user)
      {
	cgnat_user_lock (instance, mapping->inside_fib_index,
			 mapping->inside_ip);
	cgnat_user_session_unreserve (user);
	cgnat_user_unlock (instance, mapping->inside_fib_index,
			   mapping->inside_ip);
      }
    cgnat_session_free_unpublished (cm, session);
    return VNET_API_ERROR_BUG;
  }

  cgnat_session_table_lock (cm, &rkv);
  rv = clib_bihash_add_del_24_8 (&cm->session_table, &rkv, 1);
  cgnat_session_table_unlock (cm, &rkv);
  if (rv)
  {
    /* kv was already published, so a lock-free reader may hold a pointer to
     * this session: mark it DELETING and reclaim it only under the next
     * worker barrier via the reap queue. */
    cgnat_session_table_lock (cm, &kv);
    clib_bihash_add_del_24_8 (&cm->session_table, &kv, 0);
    cgnat_session_table_unlock (cm, &kv);
    if (user)
      {
	cgnat_user_lock (instance, mapping->inside_fib_index,
			 mapping->inside_ip);
	cgnat_user_session_unreserve (user);
	cgnat_user_unlock (instance, mapping->inside_fib_index,
			   mapping->inside_ip);
      }
    clib_atomic_fetch_or (&session->flags, CGNAT_SESSION_FLAG_DELETING);
    cgnat_session_reap_push (cm, session);
    return VNET_API_ERROR_BUG;
  }

  clib_atomic_fetch_add (&mapping->active_sessions, 1);
  cgnat_session_counter_inc (cm, mapping);
  /* Re-check after the atomic increment: pairs with
   * cgnat_dynamic_mapping_schedule_delete(), which reads active_sessions
   * after setting DELETING.  Exactly one side sees the other's update; if we
   * lost the race, withdraw the session we just published. */
  if (PREDICT_FALSE (clib_atomic_load_acq_n (&mapping->flags) &
		     CGNAT_MAPPING_FLAG_DELETING))
    {
      cgnat_session_delete (cm, session, "mapping_deleting");
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  if (ensure_adf_remote)
    {
      rv = cgnat_session_ensure_adf_remote (cm, mapping, session);
      if (rv)
	{
	  cgnat_session_delete (cm, session, "adf_remote_ref_failed");
	  return rv;
	}
    }
  cgnat_log_session (cm, "SESSION_CREATE", 0, session);
  cgnat_session_start_timer (cm, session, now);
  return 0;
}

static int
cgnat_static_rule_public_pool_overlap (cgnat_main_t *cm,
			       cgnat_instance_t *instance,
			       ip4_address_t outside_ip,
			       u8 mapping_type, u16 outside_port)
{
  cgnat_pool_t *pool;
  u32 *pool_index;
  u32 outside = clib_net_to_host_u32 (outside_ip.as_u32);

  vec_foreach (pool_index, instance->pool_indices)
    {
      pool = cgnat_pool_get_by_index (cm, *pool_index);
      if (!pool)
	continue;
      if (outside >= clib_net_to_host_u32 (pool->first_ip.as_u32) &&
	  outside <= clib_net_to_host_u32 (pool->last_ip.as_u32))
	{
	  /* Address-level mappings must not overlap the dynamic pool at all.
	   * Port-level mappings may reuse a pool IP, but only on reserved ports
	   * that the dynamic PBA allocator will never use. */
	  if (mapping_type == CGNAT_STATIC_PORT_MAP)
	    return outside_port > pool->exclude_end_port;
	  return 1;
	}
    }

  return 0;
}

static_always_inline int
cgnat_static_protocol_conflict (u8 a, u8 b)
{
  return a == b || a == CGNAT_STATIC_PROTO_ALL ||
	 b == CGNAT_STATIC_PROTO_ALL;
}

static int
cgnat_static_rule_conflict (cgnat_instance_t *instance,
			    cgnat_static_rule_t *candidate,
			    u32 skip_index)
{
  cgnat_static_rule_t *rule;

  pool_foreach (rule, instance->static_rules)
    {
      if ((u32) (rule - instance->static_rules) == skip_index)
	continue;

      if (!cgnat_static_protocol_conflict (rule->protocol,
					   candidate->protocol))
	continue;

      if (rule->outside_ip.as_u32 == candidate->outside_ip.as_u32)
	{
	  if (rule->type != CGNAT_STATIC_PORT_MAP ||
	      candidate->type != CGNAT_STATIC_PORT_MAP ||
	      rule->outside_port == candidate->outside_port)
	    return 1;
	}

      if (rule->inside_ip.as_u32 == candidate->inside_ip.as_u32)
	{
	  if (rule->type != CGNAT_STATIC_PORT_MAP ||
	      candidate->type != CGNAT_STATIC_PORT_MAP ||
	      rule->inside_port == candidate->inside_port)
	    return 1;
	}
    }

  return 0;
}

/*
 * Remove a zero-session dynamic/deterministic mapping from both lookup tables
 * immediately, but defer pool/PBA reclamation until the main thread has crossed
 * a worker barrier. Workers that already resolved the old value can then finish
 * safely.
 */
void
cgnat_dynamic_mapping_schedule_delete (cgnat_main_t *cm,
				       cgnat_mapping_t *mapping)
{
  u64 value;
  clib_bihash_kv_16_8_t in_kv, out_kv;

  if (!mapping || !cgnat_mapping_is_auto (mapping))
    return;

  /* Atomic test-and-set of DELETING: the create path increments
   * active_sessions with an atomic add and re-checks DELETING right after,
   * so exactly one side observes the other; the reap path quarantines a
   * mapping whose sessions are still draining. */
  if (clib_atomic_load_acq_n (&mapping->active_sessions) ||
      (clib_atomic_fetch_or (&mapping->flags, CGNAT_MAPPING_FLAG_DELETING) &
       CGNAT_MAPPING_FLAG_DELETING))
    return;
  cgnat_make_in2out_mapping_key (&in_kv, mapping->instance_index,
				 mapping->inside_fib_index, mapping->inside_ip,
				 mapping->inside_port, mapping->protocol);
  cgnat_make_out2in_mapping_key (&out_kv, mapping->outside_fib_index,
				 mapping->nat_ip, mapping->nat_port,
				 mapping->protocol);
  cgnat_mapping_table_locks_lock (cm, &in_kv, &out_kv);
  clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 0);
  clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &out_kv, 0);
  cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);

  value = cgnat_index_to_value (mapping - cm->mappings,
				mapping->generation);
  clib_spinlock_lock (&cm->mapping_reap_lock);
  vec_add1 (cm->mapping_reap_queue, value);
  clib_spinlock_unlock (&cm->mapping_reap_lock);
}

/*
 * Schedule deletion of an address-level or address+protocol-level static
 * mapping once its last session has gone away.  Port-level static mappings
 * are persistent and must not be auto-released.
 */
static void
cgnat_static_addr_mapping_schedule_delete (cgnat_main_t *cm,
					   cgnat_mapping_t *mapping)
{
  cgnat_instance_t *instance;
  cgnat_static_rule_t *rule;
  clib_bihash_kv_16_8_t in_kv, out_kv;
  u32 *p;
  u32 rule_index;
  u64 value;

  if (!mapping || mapping->mapping_type != CGNAT_MAPPING_STATIC)
    return;

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (!instance)
    return;

  rule_index = mapping->static_rule_index;
  if (pool_is_free_index (instance->static_rules, rule_index))
    return;
  rule = pool_elt_at_index (instance->static_rules, rule_index);

  if (rule->type == CGNAT_STATIC_PORT_MAP)
    return;

  /* Same atomic DELETING test-and-set as cgnat_dynamic_mapping_schedule_delete. */
  if (clib_atomic_load_acq_n (&mapping->active_sessions) ||
      (clib_atomic_fetch_or (&mapping->flags, CGNAT_MAPPING_FLAG_DELETING) &
       CGNAT_MAPPING_FLAG_DELETING))
    return;

  cgnat_make_in2out_mapping_key (&in_kv, mapping->instance_index,
				 mapping->inside_fib_index, mapping->inside_ip,
				 mapping->inside_port, mapping->protocol);
  cgnat_make_out2in_mapping_key (&out_kv, mapping->outside_fib_index,
				 mapping->nat_ip, mapping->nat_port,
				 mapping->protocol);
  cgnat_mapping_table_locks_lock (cm, &in_kv, &out_kv);
  clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 0);
  clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &out_kv, 0);
  cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);

  value = cgnat_index_to_value (mapping - cm->mappings,
				mapping->generation);

  clib_spinlock_lock (&cm->mapping_reap_lock);
  vec_add1 (cm->mapping_reap_queue, value);

  /* Remove the mapping from the rule vector so rule deletion does not
   * try to free it again.  Use INVALID_INDEX as a tombstone to avoid
   * re-allocating or compacting the vector concurrently. */
  clib_spinlock_lock (&rule->lock);
  for (p = rule->exact_mapping_indices;
       p < vec_end (rule->exact_mapping_indices); p++)
    {
      if (*p == (u32) (mapping - cm->mappings))
	{
	  *p = CGNAT_INVALID_INDEX;
	  break;
	}
    }
  clib_spinlock_unlock (&rule->lock);
  clib_spinlock_unlock (&cm->mapping_reap_lock);
}

/* Called only by the main thread while all workers are at the barrier. */
static void
cgnat_dynamic_mapping_reap (cgnat_main_t *cm)
{
  u64 *pending;
  u64 *value;

  clib_spinlock_lock (&cm->mapping_reap_lock);
  pending = cm->mapping_reap_queue;
  cm->mapping_reap_queue = 0;
  /* Retry quarantined mappings every round: their sessions may have aged
   * out (or a transient PBA release failure may have cleared) since they
   * were parked here.  Without this, quarantined mappings and their ports
   * would leak permanently. */
  vec_append (pending, cm->mapping_reap_quarantine);
  vec_reset_length (cm->mapping_reap_quarantine);
  clib_spinlock_unlock (&cm->mapping_reap_lock);

  vec_foreach (value, pending)
    {
      u32 mapping_index = cgnat_value_get_index (*value);
      u32 generation = cgnat_value_get_generation (*value);
      cgnat_mapping_t *mapping;
      int rv;

      if (pool_is_free_index (cm->mappings, mapping_index))
	continue;
      mapping = pool_elt_at_index (cm->mappings, mapping_index);
      if (mapping->generation != generation || !(mapping->flags & CGNAT_MAPPING_FLAG_DELETING))
	continue;

      if (mapping->active_sessions)
	{
	  cgnat_log_err ("dynamic mapping %u generation %u quarantined with "
			 "%u active sessions", mapping_index, generation,
			 mapping->active_sessions);
	  clib_spinlock_lock (&cm->mapping_reap_lock);
	  vec_add1 (cm->mapping_reap_quarantine, *value);
	  clib_spinlock_unlock (&cm->mapping_reap_lock);
	  continue;
	}

      if (mapping->mapping_type == CGNAT_MAPPING_STATIC)
	{
	  /* Address-level static mappings have no PBA/det port resource to
	   * release; the lookup table entries were already removed by
	   * schedule_delete.  Free the mapping entry itself. */
	}
      else if (mapping->mapping_type == CGNAT_MAPPING_DETERMINISTIC)
	{
	  cgnat_instance_t *instance =
	    cgnat_instance_get_by_index (cm, mapping->instance_index);
	  if (instance)
	    cgnat_det_release_port (instance, mapping);
	}
      else
	{
	  rv = cgnat_pba_release_port (
	    mapping->instance_index, mapping->pool_index, mapping->public_ip_index,
	    mapping->inside_fib_index, mapping->inside_ip, mapping->nat_port,
	    mapping->protocol);
	  if (rv == VNET_API_ERROR_NO_SUCH_ENTRY ||
	      rv == VNET_API_ERROR_INVALID_VALUE)
	    {
	      /* Terminal: the port/block is already gone (teardown or a
	       * cooling timer released it first); retrying would never
	       * succeed, so free the mapping instead of quarantining it
	       * forever. */
	      cgnat_log_warn ("dynamic mapping %u PBA release already done: %d",
			      mapping_index, rv);
	    }
	  else if (rv)
	    {
	      cgnat_log_err ("dynamic mapping %u PBA release failed: %d; "
			     "quarantined", mapping_index, rv);
	      clib_spinlock_lock (&cm->mapping_reap_lock);
	      vec_add1 (cm->mapping_reap_quarantine, *value);
	      clib_spinlock_unlock (&cm->mapping_reap_lock);
	      continue;
	    }
	}
      cgnat_mapping_pool_put (cm, mapping);
    }
  vec_free (pending);
}

/* Called only with a worker barrier held (the periodic timer path).  Any
 * sessions deleted by teardown paths are reclaimed by the next timer tick.
 * Returns reaped sessions to the pool; until this runs, deleted slots stay
 * allocated so lock-free readers can still lock them and revalidate. */
static void
cgnat_session_reap (cgnat_main_t *cm)
{
  u64 *pending, *value;

  clib_spinlock_lock (&cm->session_reap_lock);
  pending = cm->session_reap_queue;
  cm->session_reap_queue = 0;
  clib_spinlock_unlock (&cm->session_reap_lock);

  vec_foreach (value, pending)
    {
      u32 session_index = cgnat_value_get_index (*value);
      u32 generation = cgnat_value_get_generation (*value);
      cgnat_session_t *session;

      if (pool_is_free_index (cm->sessions, session_index))
	continue;
      session = pool_elt_at_index (cm->sessions, session_index);
      if (session->generation != generation ||
	  !(session->flags & CGNAT_SESSION_FLAG_DELETING))
	continue;

      clib_spinlock_lock (&cm->session_pool_lock);
      pool_put (cm->sessions, session);
      clib_spinlock_unlock (&cm->session_pool_lock);
    }
  vec_free (pending);
}

static_always_inline void
cgnat_static_rule_pool_put (cgnat_instance_t *instance,
			    cgnat_static_rule_t *rule)
{
  vec_free (rule->exact_mapping_indices);
  clib_spinlock_free (&rule->lock);
  pool_put (instance->static_rules, rule);
}

static int
cgnat_static_dynamic_mapping_conflict (cgnat_main_t *cm,
				       cgnat_static_rule_t *candidate)
{
  cgnat_mapping_t *mapping;

  pool_foreach (mapping, cm->mappings)
    {
      if (!cgnat_mapping_is_auto (mapping) ||
	  mapping->instance_index != candidate->instance_index ||
	  (mapping->flags & CGNAT_MAPPING_FLAG_DELETING))
	continue;

      if (candidate->protocol != CGNAT_STATIC_PROTO_ALL &&
	  mapping->protocol != candidate->protocol)
	continue;

      if (candidate->type != CGNAT_STATIC_PORT_MAP)
	{
	  if (mapping->inside_ip.as_u32 == candidate->inside_ip.as_u32 ||
	      mapping->nat_ip.as_u32 == candidate->outside_ip.as_u32)
	    return 1;
	}
      else if ((mapping->inside_ip.as_u32 == candidate->inside_ip.as_u32 &&
		mapping->inside_port == candidate->inside_port) ||
	       (mapping->nat_ip.as_u32 == candidate->outside_ip.as_u32 &&
		mapping->nat_port == candidate->outside_port))
	return 1;
    }

  return 0;
}

static int
cgnat_static_exact_mapping_create (cgnat_main_t *cm,
				   cgnat_static_rule_t *rule, u16 outside_port,
				   u16 inside_port, u8 protocol,
				   u32 inside_fib_index,
				   u32 *mapping_index)
{
  clib_bihash_kv_16_8_t in_kv, out_kv, value;
  cgnat_mapping_t *mapping;

  cgnat_make_in2out_mapping_key (&in_kv, rule->instance_index,
				 inside_fib_index, rule->inside_ip,
				 inside_port, protocol);
  if (!cgnat_mapping_table_search (cm, &cm->in2out_mapping_table, &in_kv,
				   &value))
    return VNET_API_ERROR_VALUE_EXIST;

  cgnat_make_out2in_mapping_key (&out_kv, rule->outside_fib_index,
				 rule->outside_ip, outside_port,
				 protocol);
  if (!cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &out_kv,
				   &value))
    return VNET_API_ERROR_VALUE_EXIST;

  mapping = cgnat_mapping_alloc (cm, mapping_index);
  if (PREDICT_FALSE (!mapping))
    return VNET_API_ERROR_LIMIT_EXCEEDED;
  mapping->inside_ip = rule->inside_ip;
  mapping->nat_ip = rule->outside_ip;
  mapping->inside_port = inside_port;
  mapping->nat_port = outside_port;
  mapping->protocol = protocol;
  mapping->mapping_type = CGNAT_MAPPING_STATIC;
  mapping->instance_index = rule->instance_index;
  mapping->inside_fib_index = inside_fib_index;
  mapping->outside_fib_index = rule->outside_fib_index;
  mapping->pool_index = CGNAT_INVALID_INDEX;
  mapping->public_ip_index = CGNAT_INVALID_INDEX;
  mapping->user_index = CGNAT_INVALID_INDEX;
  mapping->block_index = CGNAT_INVALID_INDEX;
  mapping->static_rule_index = rule - vec_elt_at_index (
					cm->instances,
					rule->instance_index)->static_rules;

  in_kv.value = cgnat_index_to_value (*mapping_index, mapping->generation);
  cgnat_mapping_table_locks_lock (cm, &in_kv, &out_kv);
  if (clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 1))
  {
    cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);
    cgnat_mapping_pool_put (cm, mapping);
    return VNET_API_ERROR_BUG;
  }

  out_kv.value = cgnat_index_to_value (*mapping_index, mapping->generation);
  if (clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &out_kv, 1))
  {
    clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 0);
    cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);
    cgnat_mapping_pool_put (cm, mapping);
    return VNET_API_ERROR_BUG;
  }
  cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);

  return 0;
}

int
cgnat_static_addr_lookup (cgnat_main_t *cm, clib_bihash_16_8_t *table,
			  u32 fib_index, ip4_address_t ip, u8 protocol,
			  cgnat_static_rule_t **rulep)
{
  /* Exact (fib, protocol), then (fib, all-protocols).  Rules always carry
   * a concrete fib (default vrf 0), so there is no any-fib fallback. */
  clib_bihash_kv_16_8_t kv, value;
  cgnat_instance_t *instance;
  u32 instance_index, rule_index;

  cgnat_make_static_addr_key (&kv, fib_index, ip, protocol);
  if (clib_bihash_search_16_8 (table, &kv, &value))
  {
    if (protocol == CGNAT_STATIC_PROTO_ALL)
      return VNET_API_ERROR_NO_SUCH_ENTRY;

    cgnat_make_static_addr_key (&kv, fib_index, ip, CGNAT_STATIC_PROTO_ALL);
    if (clib_bihash_search_16_8 (table, &kv, &value))
      return VNET_API_ERROR_NO_SUCH_ENTRY;
  }

  instance_index = value.value >> 32;
  rule_index = value.value & ~(u32) 0;
  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance || pool_is_free_index (instance->static_rules, rule_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *rulep = pool_elt_at_index (instance->static_rules, rule_index);
  return 0;
}

cgnat_mapping_t *
cgnat_static_addr_get_or_create_mapping (cgnat_main_t *cm,
					 cgnat_static_rule_t *rule,
					 u16 packet_port, u8 protocol,
					 u32 inside_fib_index)
{
  clib_bihash_kv_16_8_t kv, value;
  cgnat_mapping_t *mapping;
  u32 mapping_index;
  int rv;

  cgnat_make_out2in_mapping_key (&kv, rule->outside_fib_index,
				 rule->outside_ip, packet_port, protocol);
  if (!cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv, &value))
    return cgnat_mapping_get_if_valid (cm, value.value);

  if (!cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv, &value))
    {
      mapping = cgnat_mapping_get_if_valid (cm, value.value);
      return mapping;
    }

  rv = cgnat_static_exact_mapping_create (cm, rule, packet_port, packet_port,
					  protocol, inside_fib_index,
					  &mapping_index);
  if (rv)
  {
    if (!cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv,
				     &value))
    {
      mapping = cgnat_mapping_get_if_valid (cm, value.value);
      return mapping;
    }
    return 0;
  }

  clib_spinlock_lock (&rule->lock);
  mapping = pool_elt_at_index (cm->mappings, mapping_index);
  vec_add1 (rule->exact_mapping_indices, mapping_index);
  clib_spinlock_unlock (&rule->lock);
  return mapping;
}

static void
cgnat_static_mapping_delete_exact (cgnat_main_t *cm, cgnat_mapping_t *mapping)
{
  clib_bihash_kv_16_8_t kv, in_kv;
  cgnat_session_t *session;
  u32 *session_indices = 0;
  u32 *session_index;

  if (mapping->flags & CGNAT_MAPPING_FLAG_DELETING)
    return; /* already scheduled for deletion/reap elsewhere */

  mapping->flags |= CGNAT_MAPPING_FLAG_DELETING;
  cgnat_make_in2out_mapping_key (&kv, mapping->instance_index,
				 mapping->inside_fib_index, mapping->inside_ip,
				 mapping->inside_port, mapping->protocol);
  in_kv = kv;
  cgnat_make_out2in_mapping_key (&kv, mapping->outside_fib_index,
				 mapping->nat_ip, mapping->nat_port,
				 mapping->protocol);
  cgnat_mapping_table_locks_lock (cm, &in_kv, &kv);
  clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 0);
  clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &kv, 0);
  cgnat_mapping_table_locks_unlock (cm, &in_kv, &kv);

  pool_foreach (session, cm->sessions)
    {
      if (session->mapping_index == (u32) (mapping - cm->mappings) &&
	  session->mapping_generation == mapping->generation)
	vec_add1 (session_indices, session - cm->sessions);
    }

  vec_foreach (session_index, session_indices)
    {
      if (!pool_is_free_index (cm->sessions, *session_index))
	{
	  session = pool_elt_at_index (cm->sessions, *session_index);
	  cgnat_session_delete (cm, session, "static_delete");
	}
    }
  vec_free (session_indices);

  cgnat_mapping_pool_put (cm, mapping);
}

static void
cgnat_static_rule_delete_mappings (cgnat_main_t *cm,
				   cgnat_instance_t *instance,
				   cgnat_static_rule_t *rule)
{
  cgnat_mapping_t *mapping;
  u32 *mapping_index;
  u32 rule_index = rule - instance->static_rules;

  if (rule->type == CGNAT_STATIC_PORT_MAP)
    {
      if (rule->exact_mapping_index == CGNAT_INVALID_INDEX ||
	  pool_is_free_index (cm->mappings, rule->exact_mapping_index))
	return;

      mapping = pool_elt_at_index (cm->mappings, rule->exact_mapping_index);
      if (mapping->mapping_type == CGNAT_MAPPING_STATIC &&
	  mapping->static_rule_index == rule_index)
	cgnat_static_mapping_delete_exact (cm, mapping);
      return;
    }

  vec_foreach (mapping_index, rule->exact_mapping_indices)
    {
      /* Skip tombstones written by
       * cgnat_static_addr_mapping_schedule_delete(): ~0u is outside the
       * mappings pool, so pool_is_free_index on it is an out-of-bounds
       * bitmap read. */
      if (*mapping_index == CGNAT_INVALID_INDEX)
	continue;
      if (!pool_is_free_index (cm->mappings, *mapping_index))
	{
	  mapping = pool_elt_at_index (cm->mappings, *mapping_index);
	  if (mapping->mapping_type == CGNAT_MAPPING_STATIC &&
	      mapping->static_rule_index == rule_index)
	    cgnat_static_mapping_delete_exact (cm, mapping);
	}
    }
}

static int
cgnat_static_rule_find (cgnat_instance_t *instance,
			cgnat_static_rule_t *candidate, u32 *rule_index)
{
  cgnat_main_t *cm = &cgnat_main;
  clib_bihash_kv_24_8_t kv, value;
  cgnat_static_rule_t *rule;
  u32 instance_index;

  cgnat_make_static_rule_key (&kv, candidate);
  if (clib_bihash_search_24_8 (&cm->static_rule_table, &kv, &value))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  instance_index = value.value >> 32;
  if (instance_index != (u32) (instance - cm->instances))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *rule_index = value.value & ~(u32) 0;
  if (pool_is_free_index (instance->static_rules, *rule_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rule = pool_elt_at_index (instance->static_rules, *rule_index);
  if (rule->type == candidate->type &&
      rule->protocol == candidate->protocol &&
      rule->outside_ip.as_u32 == candidate->outside_ip.as_u32 &&
      rule->inside_ip.as_u32 == candidate->inside_ip.as_u32 &&
      rule->outside_port == candidate->outside_port &&
      rule->inside_port == candidate->inside_port)
    return 0;

  return VNET_API_ERROR_NO_SUCH_ENTRY;
}

int
cgnat_static_mapping_add_del (u32 instance_index, ip4_address_t outside_ip,
			      u16 outside_port, ip4_address_t inside_ip,
			      u16 inside_port, u8 protocol, u8 mapping_type,
			      u32 inside_vrf_id, u8 is_add)
{
  cgnat_main_t *cm = &cgnat_main;
  cgnat_instance_t *instance;
  cgnat_static_rule_t candidate, *rule;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_kv_24_8_t rule_kv;
  u32 rule_index = CGNAT_INVALID_INDEX;
  u32 mapping_index = CGNAT_INVALID_INDEX;
  u32 inside_fib_index = CGNAT_INVALID_INDEX;
  int rv = 0;

  /* Runtime tables exist only after the plugin is enabled; reject all
   * configuration changes before that point. */
  if (PREDICT_FALSE (!clib_atomic_load_relax_n (&cm->enabled)))
    return VNET_API_ERROR_FEATURE_ALREADY_DISABLED;

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (mapping_type > CGNAT_STATIC_PORT_MAP)
    return VNET_API_ERROR_INVALID_VALUE;

  /* Port-level mappings need TCP/UDP/ICMP; address+protocol also allows ICMP. */
  if (mapping_type == CGNAT_STATIC_PORT_MAP &&
      protocol != IP_PROTOCOL_TCP && protocol != IP_PROTOCOL_UDP &&
      protocol != IP_PROTOCOL_ICMP)
    return VNET_API_ERROR_UNSUPPORTED;

  if (mapping_type == CGNAT_STATIC_ADDR_PROTO_MAP &&
      protocol != IP_PROTOCOL_TCP && protocol != IP_PROTOCOL_UDP &&
      protocol != IP_PROTOCOL_ICMP)
    return VNET_API_ERROR_UNSUPPORTED;

  /* Address-only mappings cover all protocols. */
  if (mapping_type == CGNAT_STATIC_ADDR_MAP &&
      protocol != CGNAT_STATIC_PROTO_ALL)
    return VNET_API_ERROR_UNSUPPORTED;

  /* The rule pins its own inside fib (default vrf 0); this keeps static
   * mappings working on inside-vrf-any instances. */
  if (is_add)
    {
      inside_fib_index = fib_table_find (FIB_PROTOCOL_IP4, inside_vrf_id);
      if (inside_fib_index == CGNAT_INVALID_INDEX)
	return VNET_API_ERROR_NO_SUCH_FIB;
    }

  clib_memset (&candidate, 0, sizeof (candidate));
  candidate.type = mapping_type;
  candidate.protocol = protocol;
  candidate.outside_ip = outside_ip;
  candidate.inside_ip = inside_ip;
  candidate.outside_port = outside_port;
  candidate.inside_port =
    mapping_type == CGNAT_STATIC_PORT_MAP ? inside_port : 0;
  candidate.instance_index = instance_index;
  candidate.inside_fib_index =
    is_add ? inside_fib_index : instance->inside_fib_index;
  candidate.outside_fib_index = instance->outside_fib_index;
  candidate.exact_mapping_index = CGNAT_INVALID_INDEX;
  candidate.exact_mapping_indices = 0;

  vlib_worker_thread_barrier_sync (cm->vlib_main);

  if (!is_add)
    {
      rv = cgnat_static_rule_find (instance, &candidate, &rule_index);
      if (rv)
	goto done;

      rule = pool_elt_at_index (instance->static_rules, rule_index);

      /* Remove the local receive entry for this static mapping's outside IP. */
      cgnat_static_fib_del_for_rule (cm, rule);

      cgnat_make_static_rule_key (&rule_kv, rule);
      clib_bihash_add_del_24_8 (&cm->static_rule_table, &rule_kv, 0);
      if (rule->type != CGNAT_STATIC_PORT_MAP)
	{
	  cgnat_make_static_addr_key (&kv, rule->inside_fib_index,
				      rule->inside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_in2out_table, &kv, 0);
	  cgnat_make_static_addr_key (&kv, rule->outside_fib_index,
				      rule->outside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_out2in_table, &kv, 0);
	}

      cgnat_static_rule_delete_mappings (cm, instance, rule);
      cgnat_static_rule_pool_put (instance, rule);
      goto done;
    }

  if (cgnat_static_rule_public_pool_overlap (cm, instance, outside_ip,
					     mapping_type, outside_port))
    {
      rv = VNET_API_ERROR_VALUE_EXIST;
      goto done;
    }

  if (cgnat_static_rule_conflict (instance, &candidate, CGNAT_INVALID_INDEX))
    {
      rv = VNET_API_ERROR_VALUE_EXIST;
      goto done;
    }

  if (cgnat_static_dynamic_mapping_conflict (cm, &candidate))
    {
      rv = VNET_API_ERROR_VALUE_EXIST;
      goto done;
    }

  pool_get_zero (instance->static_rules, rule);
  rule_index = rule - instance->static_rules;
  *rule = candidate;
  clib_spinlock_init (&rule->lock);

  if (rule->type == CGNAT_STATIC_PORT_MAP)
    {
      rv = cgnat_static_exact_mapping_create (cm, rule, outside_port,
					      inside_port, protocol,
					      rule->inside_fib_index,
					      &mapping_index);
      if (rv)
	{
	  cgnat_static_rule_pool_put (instance, rule);
	  goto done;
	}
      rule->exact_mapping_index = mapping_index;
    }
  else
    {
      cgnat_make_static_addr_key (&kv, rule->inside_fib_index,
				  rule->inside_ip, rule->protocol);
      kv.value = ((u64) instance_index << 32) | rule_index;
      if (clib_bihash_add_del_16_8 (&cm->static_addr_in2out_table, &kv, 1))
	{
	  cgnat_static_rule_pool_put (instance, rule);
	  rv = VNET_API_ERROR_BUG;
	  goto done;
	}

      cgnat_make_static_addr_key (&kv, rule->outside_fib_index,
				  rule->outside_ip, rule->protocol);
      kv.value = ((u64) instance_index << 32) | rule_index;
      if (clib_bihash_add_del_16_8 (&cm->static_addr_out2in_table, &kv, 1))
	{
	  cgnat_make_static_addr_key (&kv, rule->inside_fib_index,
				      rule->inside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_in2out_table, &kv, 0);
	  cgnat_static_rule_pool_put (instance, rule);
	  rv = VNET_API_ERROR_BUG;
	  goto done;
	}
    }

  cgnat_make_static_rule_key (&rule_kv, rule);
  rule_kv.value = ((u64) instance_index << 32) | rule_index;
  if (clib_bihash_add_del_24_8 (&cm->static_rule_table, &rule_kv, 1))
    {
      if (rule->type != CGNAT_STATIC_PORT_MAP)
	{
	  cgnat_make_static_addr_key (&kv, rule->inside_fib_index,
				      rule->inside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_in2out_table, &kv, 0);
	  cgnat_make_static_addr_key (&kv, rule->outside_fib_index,
				      rule->outside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_out2in_table, &kv, 0);
	}
      cgnat_static_rule_delete_mappings (cm, instance, rule);
      cgnat_static_rule_pool_put (instance, rule);
      rv = VNET_API_ERROR_BUG;
      goto done;
    }

  /* Make VPP answer ARP for this static mapping's outside IP on all outside
   * interfaces. */
  cgnat_static_fib_add_for_rule (cm, rule);

done:
  vlib_worker_thread_barrier_release (cm->vlib_main);
  return rv;
}

cgnat_mapping_t *
cgnat_in2out_hairpin_dst_lookup (cgnat_main_t *cm, cgnat_instance_t *instance,
				 ip4_header_t *ip, u16 dst_port,
				 u32 inside_fib_index)
{
  clib_bihash_kv_16_8_t kv, value;
  cgnat_mapping_t *mapping;

  cgnat_make_out2in_mapping_key (&kv, instance->outside_fib_index,
				 ip->dst_address, dst_port, ip->protocol);
  if (!cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv,
				   &value))
  {
    mapping = cgnat_mapping_get_if_valid (cm, value.value);
    if (!mapping || mapping->instance_index != (u32) (instance - cm->instances))
      return 0;
    return mapping;
  }

  cgnat_static_rule_t *rule = 0;
  if (cgnat_static_addr_lookup (cm, &cm->static_addr_out2in_table,
				instance->outside_fib_index, ip->dst_address, ip->protocol, &rule))
    return 0;

  if (rule->instance_index != (u32) (instance - cm->instances))
    return 0;

  return cgnat_static_addr_get_or_create_mapping (cm, rule, dst_port,
						  ip->protocol,
						  rule->inside_fib_index);
}

static void
cgnat_instance_delete_sessions (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  cgnat_session_t *session;
  u32 *session_indices = 0;
  u32 *si;
  u32 instance_index = instance - cm->instances;

  pool_foreach (session, cm->sessions)
    {
      if (session->instance_index == instance_index &&
	  !(session->flags & CGNAT_SESSION_FLAG_DELETING))
	vec_add1 (session_indices, session - cm->sessions);
    }

  vec_foreach (si, session_indices)
    {
      if (pool_is_free_index (cm->sessions, *si))
	continue;
      session = pool_elt_at_index (cm->sessions, *si);
      cgnat_session_delete (cm, session, "instance_delete");
    }
  vec_free (session_indices);
}

static void
cgnat_mapping_delete_runtime (cgnat_main_t *cm, cgnat_mapping_t *mapping,
			      char *reason)
{
  clib_bihash_kv_16_8_t in_kv, out_kv;
  u32 mapping_index = mapping - cm->mappings;

  if (cgnat_mapping_is_auto (mapping))
    {
      int rv;

      if (mapping->mapping_type == CGNAT_MAPPING_DETERMINISTIC)
	{
	  cgnat_instance_t *instance =
	    cgnat_instance_get_by_index (cm, mapping->instance_index);
	  if (instance)
	    cgnat_det_release_port (instance, mapping);
	}
      else
	{
	  rv = cgnat_pba_release_port (
	    mapping->instance_index, mapping->pool_index, mapping->public_ip_index,
	    mapping->inside_fib_index, mapping->inside_ip, mapping->nat_port,
	    mapping->protocol);
	  if (rv)
	    cgnat_log_err ("%s: PBA release failed for mapping %u: %d", reason,
			   mapping_index, rv);
	}
    }

  cgnat_make_in2out_mapping_key (&in_kv, mapping->instance_index,
				 mapping->inside_fib_index, mapping->inside_ip,
				 mapping->inside_port, mapping->protocol);
  cgnat_make_out2in_mapping_key (&out_kv, mapping->outside_fib_index,
				 mapping->nat_ip, mapping->nat_port,
				 mapping->protocol);
  cgnat_mapping_table_locks_lock (cm, &in_kv, &out_kv);
  clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &in_kv, 0);
  clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &out_kv, 0);
  cgnat_mapping_table_locks_unlock (cm, &in_kv, &out_kv);

  cgnat_mapping_pool_put (cm, mapping);
}

static void
cgnat_instance_delete_mappings (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  cgnat_mapping_t *mapping;
  u32 *mapping_indices = 0;
  u32 *mi;
  u32 instance_index = instance - cm->instances;

  pool_foreach (mapping, cm->mappings)
    {
      if (mapping->instance_index == instance_index)
	vec_add1 (mapping_indices, mapping - cm->mappings);
    }

  vec_foreach (mi, mapping_indices)
    {
      if (pool_is_free_index (cm->mappings, *mi))
	continue;
      mapping = pool_elt_at_index (cm->mappings, *mi);
      cgnat_mapping_delete_runtime (cm, mapping, "instance_delete");
    }
  vec_free (mapping_indices);
}

static void
cgnat_instance_delete_static_rules (cgnat_main_t *cm,
				    cgnat_instance_t *instance)
{
  cgnat_static_rule_t *rule;
  u32 *rule_indices = 0;
  u32 *ri;

  pool_foreach (rule, instance->static_rules)
    vec_add1 (rule_indices, rule - instance->static_rules);

  vec_foreach (ri, rule_indices)
    {
      clib_bihash_kv_16_8_t kv;
      clib_bihash_kv_24_8_t rule_kv;

      if (pool_is_free_index (instance->static_rules, *ri))
	continue;
      rule = pool_elt_at_index (instance->static_rules, *ri);

      cgnat_static_fib_del_for_rule (cm, rule);
      cgnat_static_rule_delete_mappings (cm, instance, rule);

      cgnat_make_static_rule_key (&rule_kv, rule);
      clib_bihash_add_del_24_8 (&cm->static_rule_table, &rule_kv, 0);

      if (rule->type != CGNAT_STATIC_PORT_MAP)
	{
	  cgnat_make_static_addr_key (&kv, rule->inside_fib_index,
				      rule->inside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_in2out_table, &kv, 0);
	  cgnat_make_static_addr_key (&kv, rule->outside_fib_index,
				      rule->outside_ip, rule->protocol);
	  clib_bihash_add_del_16_8 (&cm->static_addr_out2in_table, &kv, 0);
	}

      cgnat_static_rule_pool_put (instance, rule);
    }
  vec_free (rule_indices);
}

static void
cgnat_instance_delete_users (cgnat_main_t *cm, cgnat_instance_t *instance)
{
  cgnat_user_t *user;
  u32 *user_indices = 0;
  u32 *ui;
  u32 s;

  (void) cm;
  for (s = 0; s < CGNAT_USER_LOCK_BUCKETS; s++)
    pool_foreach (user, instance->users_per_shard[s])
      vec_add1 (user_indices, cgnat_user_to_index (instance, user));

  vec_foreach (ui, user_indices)
    {
      user = cgnat_user_from_index (instance, *ui);
      if (user)
	cgnat_delete_user (instance, user);
    }
  vec_free (user_indices);
}


static void
cgnat_pool_delete_sessions_of_pool (cgnat_main_t *cm, u32 pool_index)
{
  cgnat_session_t *session;
  cgnat_mapping_t *mapping;
  u32 *session_indices = 0;
  u32 *si;

  pool_foreach (session, cm->sessions)
    {
      if (session->flags & CGNAT_SESSION_FLAG_DELETING)
	continue;
      if (pool_is_free_index (cm->mappings, session->mapping_index))
	continue;

      mapping = pool_elt_at_index (cm->mappings, session->mapping_index);
      if (mapping->generation != session->mapping_generation ||
	  mapping->pool_index != pool_index)
	continue;

      vec_add1 (session_indices, session - cm->sessions);
    }

  vec_foreach (si, session_indices)
    {
      if (pool_is_free_index (cm->sessions, *si))
	continue;
      session = pool_elt_at_index (cm->sessions, *si);
      cgnat_session_delete (cm, session, "pool_delete");
    }
  vec_free (session_indices);
}

static void
cgnat_pool_delete_mappings_of_pool (cgnat_main_t *cm, u32 pool_index)
{
  cgnat_mapping_t *mapping;
  u32 *mapping_indices = 0;
  u32 *mi;

  pool_foreach (mapping, cm->mappings)
    {
      if (mapping->pool_index == pool_index)
	vec_add1 (mapping_indices, mapping - cm->mappings);
    }

  vec_foreach (mi, mapping_indices)
    {
      if (pool_is_free_index (cm->mappings, *mi))
	continue;
      mapping = pool_elt_at_index (cm->mappings, *mi);
      cgnat_mapping_delete_runtime (cm, mapping, "pool_delete");
    }
  vec_free (mapping_indices);
}

static void
cgnat_pool_delete_users_of_pool (cgnat_instance_t *instance, u32 pool_index)
{
  cgnat_user_t *user;
  u32 *user_indices = 0;
  u32 *ui;
  u32 s;

  for (s = 0; s < CGNAT_USER_LOCK_BUCKETS; s++)
    pool_foreach (user, instance->users_per_shard[s])
      {
	if (user->pool_index == pool_index)
	  vec_add1 (user_indices, cgnat_user_to_index (instance, user));
      }

  vec_foreach (ui, user_indices)
    {
      user = cgnat_user_from_index (instance, *ui);
      if (user)
	cgnat_delete_user (instance, user);
    }
  vec_free (user_indices);
}

void
cgnat_pool_cleanup_runtime (cgnat_main_t *cm, cgnat_pool_t *pool,
			    u32 pool_index, cgnat_instance_t *instance)
{
  cgnat_pool_delete_sessions_of_pool (cm, pool_index);
  cgnat_dynamic_mapping_reap (cm);
  cgnat_pool_delete_mappings_of_pool (cm, pool_index);
  if (instance)
    cgnat_pool_delete_users_of_pool (instance, pool_index);
  /* Session deletion can arm fresh cooling timers via release_user_if_idle;
   * purge after all deletes so no timer outlives the pool. */
  cgnat_pba_purge_cooling_timers (cm, pool->owner_instance_index, pool_index);
  cgnat_pool_runtime_reset (pool);
}

void
cgnat_instance_cleanup_runtime_state (cgnat_main_t *cm,
				      cgnat_instance_t *instance)
{
  cgnat_static_rule_t *rule;

  /* Sessions and dynamic mappings are runtime state.  Static rules are
   * configuration and are preserved; only their cached exact-mapping handles
   * (which point to freed mappings) are reset. */
  cgnat_instance_delete_sessions (cm, instance);
  cgnat_dynamic_mapping_reap (cm);
  cgnat_instance_delete_mappings (cm, instance);
  cgnat_dynamic_mapping_reap (cm);

  pool_foreach (rule, instance->static_rules)
    {
      rule->exact_mapping_index = CGNAT_INVALID_INDEX;
      vec_free (rule->exact_mapping_indices);
      rule->exact_mapping_indices = 0;
    }

  cgnat_instance_delete_users (cm, instance);
  cgnat_pba_purge_cooling_timers (cm, instance - cm->instances,
				  CGNAT_INVALID_INDEX);

  instance->total_blocks = 0;
  instance->allocated_blocks = 0;
  instance->cooling_blocks = 0;
  instance->active_users = 0;
  instance->active_sessions = 0;
}

void
cgnat_instance_cleanup_resources (cgnat_main_t *cm,
				  cgnat_instance_t *instance)
{
  cgnat_instance_delete_static_rules (cm, instance);
  cgnat_instance_delete_sessions (cm, instance);
  cgnat_dynamic_mapping_reap (cm);
  cgnat_instance_delete_mappings (cm, instance);
  cgnat_instance_delete_users (cm, instance);
  cgnat_pba_purge_cooling_timers (cm, instance - cm->instances,
				  CGNAT_INVALID_INDEX);
}

void
cgnat_session_init (cgnat_main_t *cm, u32 max_sessions, u32 max_mappings)
{
  u32 i;

  if (cm->session_tables_initialized)
    return;

  max_sessions = max_sessions > 0 ? max_sessions : CGNAT_SESSION_POOL_INITIAL_SIZE;
  max_mappings = max_mappings > 0 ? max_mappings : CGNAT_MAPPING_POOL_INITIAL_SIZE;

  /* The session table stores two entries per session (forward + reverse
   * key), so size the buckets for 2 * max_sessions; otherwise half of the
   * buckets split to a second page and every lookup pays an extra
   * dependent cache miss.  Mapping entries go one-per-table, so the
   * mapping tables stay sized on max_mappings. */
  u32 sessions_buckets = cgnat_calc_bihash_buckets (2 * max_sessions);
  u32 mappings_buckets = cgnat_calc_bihash_buckets (max_mappings);

  /* Keep a modest initial reserve to reduce early pool growth without
   * requiring a large VPP main heap on small test machines. */
  pool_alloc_aligned (cm->sessions, max_sessions, CLIB_CACHE_LINE_BYTES);
  pool_alloc_aligned (cm->mappings, max_mappings, CLIB_CACHE_LINE_BYTES);
  vec_validate (cm->session_generation_by_index, max_sessions - 1);
  vec_validate (cm->mapping_generation_by_index, max_mappings - 1);

  /* One cache line of session counters per vlib thread. */
  vec_validate_aligned (cm->session_counters_per_thread,
			vlib_get_thread_main ()->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);

  /* BIHASH_USE_HEAP=1 in this tree: the memory_size argument is ignored,
   * so pass 0 (same as the static/adf tables). */
  clib_bihash_init_16_8 (&cm->in2out_mapping_table, "cgnat-in2out-mapping",
			 mappings_buckets, 0);
  clib_bihash_init_16_8 (&cm->out2in_mapping_table, "cgnat-out2in-mapping",
			 mappings_buckets, 0);

  clib_bihash_init_16_8 (&cm->static_addr_in2out_table,
			 "cgnat-static-addr-in2out",
			 CGNAT_STATIC_MAPPING_HASH_BUCKETS, CGNAT_STATIC_MAPPING_HASH_MEMORY);
  clib_bihash_init_16_8 (&cm->static_addr_out2in_table,
			 "cgnat-static-addr-out2in",
			 CGNAT_STATIC_MAPPING_HASH_BUCKETS, CGNAT_STATIC_MAPPING_HASH_MEMORY);
  clib_bihash_init_24_8 (&cm->static_rule_table, "cgnat-static-rule",
			 CGNAT_STATIC_RULE_HASH_BUCKETS,
			 CGNAT_STATIC_RULE_HASH_MEMORY);

  clib_bihash_init_24_8 (&cm->session_table, "cgnat-session",
		     sessions_buckets, 0);
  clib_bihash_init_24_8 (&cm->adf_remote_table, "cgnat-adf-remote",
			 CGNAT_ADF_REMOTE_HASH_BUCKETS,
			 CGNAT_ADF_REMOTE_HASH_MEMORY);
  /* No wheel callback: expired timers are collected directly with
   * tw_timer_expire_timers_vec_2t_2w_512sl(). */
  tw_timer_wheel_init_2t_2w_512sl (&cm->session_timer_wheel, 0, 1.0,
				    CGNAT_SESSION_TIMER_MAX_EXPIRATIONS);
  vec_prealloc(cm->session_expired, CGNAT_SESSION_TIMER_VEC);

  /* Preallocate the timer bookkeeping pools (growable, same as the
   * session/mapping pools): in-place timer updates keep one entry per live
   * session, so max_sessions plus a fixed margin (one drain round) covers
   * transient double occupancy and out-of-band delete orphans.  Avoids
   * whole-pool realloc copies under session_timer_lock during ramp-up. */
  pool_alloc_aligned (cm->session_timers,
		      max_sessions + CGNAT_SESSION_TIMER_POOL_MARGIN,
		      CLIB_CACHE_LINE_BYTES);
  pool_alloc_aligned (cm->session_timer_wheel.timers,
		      max_sessions + CGNAT_SESSION_TIMER_POOL_MARGIN,
		      CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < CGNAT_MAPPING_TABLE_LOCK_BUCKETS; i++)
    clib_spinlock_init (&cm->mapping_table_locks[i]);
  for (i = 0; i < CGNAT_SESSION_TABLE_LOCK_BUCKETS; i++)
    clib_spinlock_init (&cm->session_table_locks[i]);
  for (i = 0; i < CGNAT_ADF_REMOTE_LOCK_BUCKETS; i++)
    clib_spinlock_init (&cm->adf_remote_locks[i]);
  clib_spinlock_init (&cm->mapping_pool_lock);
  clib_spinlock_init (&cm->adf_remote_pool_lock);
  clib_spinlock_init (&cm->mapping_reap_lock);
  clib_spinlock_init (&cm->session_pool_lock);
  clib_spinlock_init (&cm->session_timer_lock);
  clib_spinlock_init (&cm->session_reap_lock);
  cm->session_timer_initialized = 1;
  cm->session_tables_initialized = 1;
}

void
cgnat_session_reset (cgnat_main_t *cm)
{
  u32 i;

  if (!cm->session_tables_initialized)
    return;

  pool_free (cm->sessions);
  pool_free (cm->mappings);
  pool_free (cm->adf_remotes);
  vec_free (cm->session_generation_by_index);
  vec_free (cm->mapping_generation_by_index);
  vec_free (cm->adf_remote_generation_by_index);
  vec_free (cm->mapping_reap_queue);
  vec_free (cm->mapping_reap_quarantine);
  vec_free (cm->session_reap_queue);
  pool_free (cm->session_timers);

  clib_bihash_free_16_8 (&cm->in2out_mapping_table);
  clib_bihash_free_16_8 (&cm->out2in_mapping_table);
  clib_bihash_free_16_8 (&cm->static_addr_in2out_table);
  clib_bihash_free_16_8 (&cm->static_addr_out2in_table);
  clib_bihash_free_24_8 (&cm->static_rule_table);
  clib_bihash_free_24_8 (&cm->session_table);
  clib_bihash_free_24_8 (&cm->adf_remote_table);

  if (cm->session_timer_initialized)
    {
      tw_timer_wheel_free_2t_2w_512sl (&cm->session_timer_wheel);
      vec_free(cm->session_expired);
      cm->session_timer_initialized = 0;
    }

  for (i = 0; i < CGNAT_MAPPING_TABLE_LOCK_BUCKETS; i++)
    clib_spinlock_free (&cm->mapping_table_locks[i]);
  for (i = 0; i < CGNAT_SESSION_TABLE_LOCK_BUCKETS; i++)
    clib_spinlock_free (&cm->session_table_locks[i]);
  for (i = 0; i < CGNAT_ADF_REMOTE_LOCK_BUCKETS; i++)
    clib_spinlock_free (&cm->adf_remote_locks[i]);
  clib_spinlock_free (&cm->mapping_pool_lock);
  clib_spinlock_free (&cm->adf_remote_pool_lock);
  clib_spinlock_free (&cm->mapping_reap_lock);
  clib_spinlock_free (&cm->session_pool_lock);
  clib_spinlock_free (&cm->session_timer_lock);
  clib_spinlock_free (&cm->session_reap_lock);

  cm->session_tables_initialized = 0;

  vec_free (cm->session_counters_per_thread);
}

void
cgnat_session_expire_timers (f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  u32 total = 0, n;

  if (!cm->session_timer_initialized)
    return;

  /* Lock-synchronized with the datapath (cgnat_session_start_timer holds the
   * same lock); no worker barrier is taken here.  Slot reclamation happens
   * in cgnat_reap(), which the timer process calls under a barrier.
   *
   * Drain loop: the wheel stops a round once max_expirations handles were
   * collected, but last_run_time only advances by the ticks actually
   * consumed - so calling expire again with the same `now` picks up the
   * remaining overdue ticks immediately instead of waiting 10ms per batch.
   * The drain cap bounds one wakeup's work so the timer process cannot
   * starve other main-thread processes under an expiry storm. */
  for (;;)
    {
      clib_spinlock_lock (&cm->session_timer_lock);
      cm->session_expired = tw_timer_expire_timers_vec_2t_2w_512sl (&cm->session_timer_wheel, now, cm->session_expired);
      clib_spinlock_unlock (&cm->session_timer_lock);

      n = vec_len (cm->session_expired);
      if (!n)
	break;
      cgnat_session_process_expired_timers (cm->session_expired);
      vec_reset_length (cm->session_expired);
      total += n;
      if (n < CGNAT_SESSION_TIMER_MAX_EXPIRATIONS ||
	  total >= CGNAT_SESSION_TIMER_DRAIN_CAP)
	break;
    }
}

/* Called by the timer process with a worker barrier held: this is the only
 * point where deleted sessions/mappings return to their pools, which is
 * what allows datapath readers to resolve pool pointers without locks. */
void
cgnat_reap (cgnat_main_t *cm)
{
  cgnat_session_reap (cm);
  cgnat_dynamic_mapping_reap (cm);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
