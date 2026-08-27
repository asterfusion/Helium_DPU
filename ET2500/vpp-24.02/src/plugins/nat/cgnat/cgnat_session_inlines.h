/*
 * cgnat_session_inlines.h - CGNAT data-plane fast-path inline functions
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 *
 * Include after <nat/cgnat/cgnat.h>.  These functions are shared by the
 * packet nodes (cgnat_in2out.c / cgnat_out2in.c, built per multiarch
 * variant) and by cgnat_session.c, which owns the slow path.
 */

#ifndef included_cgnat_session_inlines_h
#define included_cgnat_session_inlines_h

#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>
#include <nat/lib/nat_inlines.h>
#include <nat/lib/inlines.h>
#include <nat/lib/lib.h>

/* Slow-path / heavyweight helpers implemented in cgnat_session.c. */
int cgnat_icmp_error_translate_out2in (cgnat_main_t *cm, vlib_main_t *vm,
				       vlib_buffer_t *b, ip4_header_t *ip);
int cgnat_icmp_error_translate_in2out (cgnat_main_t *cm, vlib_main_t *vm,
				       vlib_buffer_t *b, ip4_header_t *ip,
				       u32 instance_index, u32 inside_fib_index);
int cgnat_session_ensure_adf_remote (cgnat_main_t *cm,
				     cgnat_mapping_t *mapping,
				     cgnat_session_t *session);
void cgnat_session_start_timer (cgnat_main_t *cm, cgnat_session_t *session,
				f64 now);
u8 cgnat_adf_remote_allowed (cgnat_main_t *cm, cgnat_mapping_t *mapping,
			     ip4_address_t remote_ip);
cgnat_mapping_t *cgnat_mapping_alloc (cgnat_main_t *cm, u32 *mapping_index);
int cgnat_session_lookup_or_create (cgnat_main_t *cm, cgnat_mapping_t *mapping,
				    ip4_address_t remote_ip, u16 remote_port,
				    u8 direction_flag, tcp_header_t *tcp,
				    f64 now, u8 allow_create,
				    u8 ensure_adf_remote);
void cgnat_dynamic_mapping_schedule_delete (cgnat_main_t *cm,
					    cgnat_mapping_t *mapping);
int cgnat_static_addr_lookup (cgnat_main_t *cm, clib_bihash_16_8_t *table,
			      u32 fib_index, ip4_address_t ip, u8 protocol,
			      cgnat_static_rule_t **rulep);
cgnat_mapping_t *
cgnat_static_addr_get_or_create_mapping (cgnat_main_t *cm,
					 cgnat_static_rule_t *rule,
					 u16 packet_port, u8 protocol,
					 u32 inside_fib_index);
cgnat_mapping_t *cgnat_in2out_hairpin_dst_lookup (cgnat_main_t *cm,
						  cgnat_instance_t *instance,
						  ip4_header_t *ip,
						  u16 dst_port,
						  u32 inside_fib_index);

static_always_inline u64
cgnat_index_to_value (u32 index, u32 generation)
{
  return ((u64) generation << 32) | index;
}

static_always_inline u32
cgnat_value_get_index (u64 value)
{
  return (u32) value;
}

static_always_inline u32
cgnat_value_get_generation (u64 value)
{
  return (u32) (value >> 32);
}

static_always_inline void
cgnat_make_in2out_mapping_key (clib_bihash_kv_16_8_t *kv,
			       u32 instance_index, u32 inside_fib_index,
			       ip4_address_t inside_ip, u16 inside_port,
			       u8 protocol)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) instance_index << 32 | inside_fib_index;
  kv->key[1] = (u64) inside_ip.as_u32 << 32 | (u64) inside_port << 16 |
	       protocol;
}

static_always_inline void
cgnat_make_out2in_mapping_key (clib_bihash_kv_16_8_t *kv,
			       u32 outside_fib_index, ip4_address_t nat_ip,
			       u16 nat_port, u8 protocol)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) outside_fib_index << 32 | nat_ip.as_u32;
  kv->key[1] = (u64) nat_port << 48 | (u64) protocol << 40;
}

static_always_inline void
cgnat_make_static_addr_key (clib_bihash_kv_16_8_t *kv, u32 fib_index,
			    ip4_address_t ip, u8 protocol)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) fib_index << 32 | ip.as_u32;
  kv->key[1] = (u64) protocol << 40;
}

static_always_inline void
cgnat_make_flow_key (clib_bihash_kv_24_8_t *kv, u32 instance_index,
		     u32 inside_fib_index, ip4_address_t inside_ip,
		     ip4_address_t remote_ip, u16 inside_port,
		     u16 remote_port, u8 protocol)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = (u64) instance_index << 32 | inside_fib_index;
  kv->key[1] = (u64) inside_ip.as_u32 << 32 | remote_ip.as_u32;
  kv->key[2] = (u64) inside_port << 48 | (u64) remote_port << 32 |
	       (u64) protocol << 24;
}

/* Reverse flow key, stored in the SAME session table: the 5-tuple as seen
 * on the outside after translation.  Bit 63 of key[0] tags the direction so
 * a reverse key can never alias a forward key.  The outside 5-tuple
 * (outside_fib, nat_ip, nat_port, proto, remote) is globally unique across
 * instances, so the key needs no instance index and can be built on the
 * out2in side without knowing one. */
#define CGNAT_SESSION_KEY_FLAG_REVERSE (1ULL << 63)

static_always_inline void
cgnat_make_reverse_flow_key (clib_bihash_kv_24_8_t *kv, u32 outside_fib_index,
			     ip4_address_t nat_ip, ip4_address_t remote_ip,
			     u16 nat_port, u16 remote_port, u8 protocol)
{
  clib_memset (kv, 0, sizeof (*kv));
  kv->key[0] = CGNAT_SESSION_KEY_FLAG_REVERSE | outside_fib_index;
  kv->key[1] = (u64) nat_ip.as_u32 << 32 | remote_ip.as_u32;
  kv->key[2] = (u64) nat_port << 48 | (u64) remote_port << 32 |
	       (u64) protocol << 24;
}

static_always_inline u32
cgnat_kv16_lock_index (clib_bihash_kv_16_8_t *kv, u32 buckets)
{
  u64 h = kv->key[0] ^ kv->key[1];

  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  return (u32) h & (buckets - 1);
}

static_always_inline u32
cgnat_kv24_lock_index (clib_bihash_kv_24_8_t *kv, u32 buckets)
{
  u64 h = kv->key[0] ^ kv->key[1] ^ kv->key[2];

  h ^= h >> 33;
  h *= 0xc4ceb9fe1a85ec53ULL;
  h ^= h >> 33;
  return (u32) h & (buckets - 1);
}

static_always_inline void
cgnat_mapping_table_locks_lock (cgnat_main_t *cm,
				clib_bihash_kv_16_8_t *a,
				clib_bihash_kv_16_8_t *b)
{
  u32 ai = cgnat_kv16_lock_index (a, CGNAT_MAPPING_TABLE_LOCK_BUCKETS);
  u32 bi = cgnat_kv16_lock_index (b, CGNAT_MAPPING_TABLE_LOCK_BUCKETS);

  if (ai == bi)
    {
      clib_spinlock_lock (&cm->mapping_table_locks[ai]);
      return;
    }

  if (ai > bi)
    {
      u32 tmp = ai;
      ai = bi;
      bi = tmp;
    }
  clib_spinlock_lock (&cm->mapping_table_locks[ai]);
  clib_spinlock_lock (&cm->mapping_table_locks[bi]);
}

static_always_inline void
cgnat_mapping_table_locks_unlock (cgnat_main_t *cm,
				  clib_bihash_kv_16_8_t *a,
				  clib_bihash_kv_16_8_t *b)
{
  u32 ai = cgnat_kv16_lock_index (a, CGNAT_MAPPING_TABLE_LOCK_BUCKETS);
  u32 bi = cgnat_kv16_lock_index (b, CGNAT_MAPPING_TABLE_LOCK_BUCKETS);

  if (ai == bi)
    {
      clib_spinlock_unlock (&cm->mapping_table_locks[ai]);
      return;
    }

  if (ai > bi)
    {
      u32 tmp = ai;
      ai = bi;
      bi = tmp;
    }
  clib_spinlock_unlock (&cm->mapping_table_locks[bi]);
  clib_spinlock_unlock (&cm->mapping_table_locks[ai]);
}

static_always_inline int
cgnat_mapping_table_search (CLIB_UNUSED (cgnat_main_t *cm),
			    clib_bihash_16_8_t *table,
			    clib_bihash_kv_16_8_t *kv,
			    clib_bihash_kv_16_8_t *value)
{
  /* clib_bihash lookups are thread-safe and lock-free by design: writers
   * build working copies and publish bucket pointers atomically, so readers
   * never need locking (see src/vppinfra/bihash_doc.h).  The striped
   * mapping_table_locks only serialize writers (add/del paths).
   *
   * A looked-up value stays safe to dereference: mapping pool entries are
   * freed only from the reap path, which runs under a worker barrier, and
   * cgnat_mapping_get_if_valid() revalidates generation + DELETING. */
  return clib_bihash_search_16_8 (table, kv, value);
}

static_always_inline void
cgnat_session_table_lock (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_spinlock_lock (
    &cm->session_table_locks[cgnat_kv24_lock_index (
      kv, CGNAT_SESSION_TABLE_LOCK_BUCKETS)]);
}

static_always_inline void
cgnat_session_table_unlock (cgnat_main_t *cm, clib_bihash_kv_24_8_t *kv)
{
  clib_spinlock_unlock (
    &cm->session_table_locks[cgnat_kv24_lock_index (
      kv, CGNAT_SESSION_TABLE_LOCK_BUCKETS)]);
}

/* Lock the hash buckets of two keys in one go, in bucket-index order to
 * avoid lock-order cycles (used when a session's forward and reverse keys
 * are inserted/removed together). */
static_always_inline void
cgnat_session_table_lock2 (cgnat_main_t *cm, clib_bihash_kv_24_8_t *a,
			   clib_bihash_kv_24_8_t *b)
{
  u32 ai = cgnat_kv24_lock_index (a, CGNAT_SESSION_TABLE_LOCK_BUCKETS);
  u32 bi = cgnat_kv24_lock_index (b, CGNAT_SESSION_TABLE_LOCK_BUCKETS);

  if (ai == bi)
    {
      clib_spinlock_lock (&cm->session_table_locks[ai]);
      return;
    }
  if (ai > bi)
    {
      u32 tmp = ai;
      ai = bi;
      bi = tmp;
    }
  clib_spinlock_lock (&cm->session_table_locks[ai]);
  clib_spinlock_lock (&cm->session_table_locks[bi]);
}

static_always_inline void
cgnat_session_table_unlock2 (cgnat_main_t *cm, clib_bihash_kv_24_8_t *a,
			     clib_bihash_kv_24_8_t *b)
{
  u32 ai = cgnat_kv24_lock_index (a, CGNAT_SESSION_TABLE_LOCK_BUCKETS);
  u32 bi = cgnat_kv24_lock_index (b, CGNAT_SESSION_TABLE_LOCK_BUCKETS);

  if (ai == bi)
    {
      clib_spinlock_unlock (&cm->session_table_locks[ai]);
      return;
    }
  if (ai > bi)
    {
      u32 tmp = ai;
      ai = bi;
      bi = tmp;
    }
  clib_spinlock_unlock (&cm->session_table_locks[bi]);
  clib_spinlock_unlock (&cm->session_table_locks[ai]);
}

static_always_inline int
cgnat_extract_l4 (vlib_buffer_t *b, ip4_header_t *ip, u16 *src_port,
		  u16 *dst_port, tcp_header_t **tcp, udp_header_t **udp)
{
  u8 *l4 = (u8 *) ip + ip4_header_bytes (ip);
  u32 l4_len;

  *tcp = 0;
  *udp = 0;

  /* Non-first fragments carry no L4 header.  Interfaces with CGNAT enabled
   * get shallow virtual reassembly automatically, so a raw non-first
   * fragment here means reassembly is off or failed: drop it instead of
   * reading payload bytes as port numbers. */
  if (PREDICT_FALSE (ip4_is_fragment (ip) && !ip4_is_first_fragment (ip)))
    return VNET_API_ERROR_INVALID_VALUE;

  if (ip->protocol == IP_PROTOCOL_TCP)
    l4_len = sizeof (tcp_header_t);
  else if (ip->protocol == IP_PROTOCOL_UDP)
    l4_len = sizeof (udp_header_t);
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    l4_len = sizeof (icmp46_header_t) + sizeof (nat_icmp_echo_header_t);
  else
    return VNET_API_ERROR_UNSUPPORTED;

  /* ip4-input guarantees ip->length <= the buffer chain length; additionally
   * require the L4 header to be inside both the declared packet length and
   * the current buffer segment (chains may split below the L4 header). */
  if (PREDICT_FALSE (ip4_header_bytes (ip) + l4_len >
			 clib_net_to_host_u16 (ip->length) ||
		     l4 + l4_len >
			 (u8 *) vlib_buffer_get_current (b) + b->current_length))
    return VNET_API_ERROR_INVALID_VALUE;

  if (ip->protocol == IP_PROTOCOL_TCP)
    {
      *tcp = (tcp_header_t *) l4;
      *src_port = clib_net_to_host_u16 ((*tcp)->src_port);
      *dst_port = clib_net_to_host_u16 ((*tcp)->dst_port);
      return 0;
    }

  if (ip->protocol == IP_PROTOCOL_UDP)
    {
      *udp = (udp_header_t *) l4;
      *src_port = clib_net_to_host_u16 ((*udp)->src_port);
      *dst_port = clib_net_to_host_u16 ((*udp)->dst_port);
      return 0;
    }

  /* ICMP Echo Request / Reply: the identifier acts as the "port".  Other
   * ICMP types are left to future phases and return UNSUPPORTED here. */
  {
    icmp46_header_t *icmp = (icmp46_header_t *) l4;
    nat_icmp_echo_header_t *echo =
      (nat_icmp_echo_header_t *) (icmp + 1);

    if (PREDICT_FALSE (icmp->type != ICMP4_echo_request &&
		       icmp->type != ICMP4_echo_reply))
      return VNET_API_ERROR_UNSUPPORTED;

    *src_port = clib_net_to_host_u16 (echo->identifier);
    *dst_port = *src_port;
    return 0;
  }
}

static_always_inline u16
cgnat_session_remote_port (u8 protocol, u16 remote_port)
{
  return protocol == IP_PROTOCOL_ICMP ? 0 : remote_port;
}

/* Stage-ahead prefetch: hash the packet's forward flow key and prefetch the
 * session-table bucket and KV page.  Called for the *next* packet while the
 * current one is processed, hiding the longest dependent cache miss in the
 * lookup chain.  Read-only; packets that can't be keyed simply skip. */
static_always_inline void
cgnat_prefetch_session_in2out (cgnat_main_t *cm, vlib_buffer_t *b)
{
  ip4_header_t *ip = vlib_buffer_get_current (b);
  clib_bihash_kv_24_8_t kv;
  tcp_header_t *tcp;
  udp_header_t *udp;
  u32 instance_index = cgnat_buffer_instance_index (b);
  u16 inside_port, remote_port;
  u64 hash;

  if (PREDICT_FALSE (instance_index == CGNAT_INVALID_INDEX))
    return;
  if (PREDICT_FALSE (cgnat_extract_l4 (b, ip, &inside_port, &remote_port,
				       &tcp, &udp)))
    return;

  cgnat_make_flow_key (&kv, instance_index, cgnat_buffer_inside_fib_index (b),
		       ip->src_address, ip->dst_address, inside_port,
		       cgnat_session_remote_port (ip->protocol, remote_port),
		       ip->protocol);
  hash = clib_bihash_hash_24_8 (&kv);
  clib_bihash_prefetch_bucket_24_8 (&cm->session_table, hash);
  clib_bihash_prefetch_data_24_8 (&cm->session_table, hash);
}

/* Same for the out2in direction: hash the reverse flow key and prefetch the
 * session-table bucket and KV page (the out2in fast path looks the session
 * up by its reverse key first). */
static_always_inline void
cgnat_prefetch_session_out2in (cgnat_main_t *cm, vlib_buffer_t *b)
{
  ip4_header_t *ip = vlib_buffer_get_current (b);
  clib_bihash_kv_24_8_t kv;
  tcp_header_t *tcp;
  udp_header_t *udp;
  u16 remote_port, nat_port;
  u32 outside_fib_index;
  u64 hash;

  if (PREDICT_FALSE (cgnat_extract_l4 (b, ip, &remote_port, &nat_port,
				       &tcp, &udp)))
    return;

  outside_fib_index = fib_table_get_index_for_sw_if_index (
    FIB_PROTOCOL_IP4, vnet_buffer (b)->sw_if_index[VLIB_RX]);
  cgnat_make_reverse_flow_key (&kv, outside_fib_index, ip->dst_address,
			       ip->src_address, nat_port,
			       cgnat_session_remote_port (ip->protocol,
							  remote_port),
			       ip->protocol);
  hash = clib_bihash_hash_24_8 (&kv);
  clib_bihash_prefetch_bucket_24_8 (&cm->session_table, hash);
  clib_bihash_prefetch_data_24_8 (&cm->session_table, hash);
}

static_always_inline u8
cgnat_update_tcp_state (cgnat_session_t *session, tcp_header_t *tcp)
{
  u8 old_state = session->tcp_state;
  u8 new_state = old_state;

  if (!tcp)
    return 0;

  /* Transitions must not resurrect a closing session: once FIN/RST is seen
   * the session stays in FIN_RST until it ages out on the short timeout -
   * a plain ACK of a half-closed connection or a retransmitted SYN must not
   * pull it back to ESTABLISHED (which would keep the port block alive for
   * the full established timeout).  Likewise a stray SYN must not downgrade
   * an ESTABLISHED session. */
  if (tcp->flags & (TCP_FLAG_FIN | TCP_FLAG_RST))
    new_state = CGNAT_TCP_FIN_RST;
  else if (tcp->flags & TCP_FLAG_SYN)
    {
      if (old_state != CGNAT_TCP_FIN_RST && old_state != CGNAT_TCP_ESTABLISHED)
	new_state = CGNAT_TCP_SYN;
    }
  else if (tcp->flags & TCP_FLAG_ACK)
    {
      if (old_state != CGNAT_TCP_FIN_RST)
	new_state = CGNAT_TCP_ESTABLISHED;
    }

  /* Write back only on change: an unconditional store would dirty the
   * session cache line on every packet and cause cross-core ping-pong for
   * bidirectional flows handled on different workers. */
  if (new_state == old_state)
    return 0;
  session->tcp_state = new_state;
  return 1;
}

static_always_inline u8
cgnat_session_touch (cgnat_session_t *session, f64 now, u8 direction_flag,
		  tcp_header_t *tcp)
{
  if (now - session->last_active >= 1.0)
    session->last_active = now;

  /* Conditional write: keep the session line clean once both directions
   * have been seen. */
  if (!(session->flags & direction_flag))
    session->flags |= direction_flag;
  return cgnat_update_tcp_state (session, tcp);
}

static_always_inline cgnat_mapping_t *
cgnat_mapping_get_if_valid (cgnat_main_t *cm, u64 value)
{
  u32 mapping_index = cgnat_value_get_index (value);
  u32 generation = cgnat_value_get_generation (value);
  cgnat_mapping_t *mapping;

  /* Bounds + generation + DELETING suffice: a stale table entry either still
   * carries DELETING (freed but not yet reused) or a bumped generation
   * (reused).  Avoid pool_is_free_index() here - the pool free bitmap is a
   * hot, frequently dirtied cache line shared across all workers. */
  if (PREDICT_FALSE (mapping_index >= pool_len (cm->mappings)))
    return 0;

  mapping = pool_elt_at_index (cm->mappings, mapping_index);
  if (PREDICT_FALSE (mapping->generation != generation ||
		     (mapping->flags & CGNAT_MAPPING_FLAG_DELETING)))
    return 0;

  return mapping;
}

static_always_inline cgnat_session_t *
cgnat_session_get_if_valid (cgnat_main_t *cm, u64 value)
{
  u32 session_index = cgnat_value_get_index (value);
  u32 generation = cgnat_value_get_generation (value);
  cgnat_session_t *session;

  /* Same rationale as cgnat_mapping_get_if_valid(): bounds + generation +
   * DELETING are sufficient, and skipping the pool free bitmap avoids a
   * dependency on a cache line dirtied by every create/delete. */
  if (PREDICT_FALSE (session_index >= pool_len (cm->sessions)))
    return 0;

  session = pool_elt_at_index (cm->sessions, session_index);
  if (PREDICT_FALSE (session->generation != generation ||
		     (session->flags & CGNAT_SESSION_FLAG_DELETING)))
    return 0;

  return session;
}

static_always_inline void
cgnat_l4_rewrite_in2out (ip4_header_t *ip, tcp_header_t *tcp, udp_header_t *udp,
			 cgnat_mapping_t *mapping, u16 tcp_mss)
{
  u32 old_addr = ip->src_address.as_u32;
  u32 new_addr = mapping->nat_ip.as_u32;
  u16 old_port, new_port = clib_host_to_net_u16 (mapping->nat_port);
  ip_csum_t sum;

  ip->src_address = mapping->nat_ip;
  /* Incremental IP header checksum update instead of a full recompute. */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, src_address);
  ip->checksum = ip_csum_fold (sum);
  if (PREDICT_FALSE (ip->checksum == 0xffff))
    ip->checksum = 0;

  if (tcp)
    {
      old_port = tcp->src_port;
      tcp->src_port = new_port;
      sum = tcp->checksum;
      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
			    src_address);
      sum = ip_csum_update (sum, old_port, new_port, tcp_header_t, src_port);
      mss_clamping (tcp_mss, tcp, &sum);
      tcp->checksum = ip_csum_fold (sum);
    }
  else if (udp && udp->checksum)
    {
      old_port = udp->src_port;
      udp->src_port = new_port;
      sum = udp->checksum;
      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
			    src_address);
      sum = ip_csum_update (sum, old_port, new_port, udp_header_t, src_port);
      udp->checksum = ip_csum_fold (sum);
    }
  else if (udp)
    udp->src_port = new_port;
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) ((u8 *) ip +
						     ip4_header_bytes (ip));
      nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp + 1);

      old_port = echo->identifier;
      echo->identifier = new_port;
      sum = icmp->checksum;
      sum = ip_csum_update (sum, old_port, new_port, nat_icmp_echo_header_t,
			    identifier);
      icmp->checksum = ip_csum_fold (sum);
    }
}

static_always_inline void
cgnat_l4_rewrite_out2in (ip4_header_t *ip, tcp_header_t *tcp, udp_header_t *udp,
			 cgnat_mapping_t *mapping, u16 tcp_mss)
{
  u32 old_addr = ip->dst_address.as_u32;
  u32 new_addr = mapping->inside_ip.as_u32;
  u16 old_port, new_port = clib_host_to_net_u16 (mapping->inside_port);
  ip_csum_t sum;

  ip->dst_address = mapping->inside_ip;
  /* Incremental IP header checksum update instead of a full recompute. */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t, dst_address);
  ip->checksum = ip_csum_fold (sum);
  if (PREDICT_FALSE (ip->checksum == 0xffff))
    ip->checksum = 0;

  if (tcp)
    {
      old_port = tcp->dst_port;
      tcp->dst_port = new_port;
      sum = tcp->checksum;
      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
			    dst_address);
      sum = ip_csum_update (sum, old_port, new_port, tcp_header_t, dst_port);
      mss_clamping (tcp_mss, tcp, &sum);
      tcp->checksum = ip_csum_fold (sum);
    }
  else if (udp && udp->checksum)
    {
      old_port = udp->dst_port;
      udp->dst_port = new_port;
      sum = udp->checksum;
      sum = ip_csum_update (sum, old_addr, new_addr, ip4_header_t,
			    dst_address);
      sum = ip_csum_update (sum, old_port, new_port, udp_header_t, dst_port);
      udp->checksum = ip_csum_fold (sum);
    }
  else if (udp)
    udp->dst_port = new_port;
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) ((u8 *) ip +
						     ip4_header_bytes (ip));
      nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp + 1);

      old_port = echo->identifier;
      echo->identifier = new_port;
      sum = icmp->checksum;
      sum = ip_csum_update (sum, old_port, new_port, nat_icmp_echo_header_t,
			    identifier);
      icmp->checksum = ip_csum_fold (sum);
    }
}

static_always_inline void
cgnat_l4_rewrite_hairpin (ip4_header_t *ip, tcp_header_t *tcp,
			  udp_header_t *udp, cgnat_mapping_t *src_mapping,
			  cgnat_mapping_t *dst_mapping)
{
  u32 old_src_addr = ip->src_address.as_u32;
  u32 old_dst_addr = ip->dst_address.as_u32;
  u32 new_src_addr = src_mapping->nat_ip.as_u32;
  u32 new_dst_addr = dst_mapping->inside_ip.as_u32;
  u16 old_src_port, old_dst_port;
  u16 new_src_port = clib_host_to_net_u16 (src_mapping->nat_port);
  u16 new_dst_port = clib_host_to_net_u16 (dst_mapping->inside_port);
  ip_csum_t sum;

  ip->src_address = src_mapping->nat_ip;
  ip->dst_address = dst_mapping->inside_ip;
  /* Incremental IP header checksum update instead of a full recompute. */
  sum = ip->checksum;
  sum = ip_csum_update (sum, old_src_addr, new_src_addr, ip4_header_t,
			src_address);
  sum = ip_csum_update (sum, old_dst_addr, new_dst_addr, ip4_header_t,
			dst_address);
  ip->checksum = ip_csum_fold (sum);
  if (PREDICT_FALSE (ip->checksum == 0xffff))
    ip->checksum = 0;

  if (tcp)
    {
      old_src_port = tcp->src_port;
      old_dst_port = tcp->dst_port;
      tcp->src_port = new_src_port;
      tcp->dst_port = new_dst_port;

      sum = tcp->checksum;
      sum = ip_csum_update (sum, old_src_addr, new_src_addr, ip4_header_t,
			    src_address);
      sum = ip_csum_update (sum, old_dst_addr, new_dst_addr, ip4_header_t,
			    dst_address);
      sum = ip_csum_update (sum, old_src_port, new_src_port, tcp_header_t,
			    src_port);
      sum = ip_csum_update (sum, old_dst_port, new_dst_port, tcp_header_t,
			    dst_port);
      tcp->checksum = ip_csum_fold (sum);
    }
  else if (udp && udp->checksum)
    {
      old_src_port = udp->src_port;
      old_dst_port = udp->dst_port;
      udp->src_port = new_src_port;
      udp->dst_port = new_dst_port;

      sum = udp->checksum;
      sum = ip_csum_update (sum, old_src_addr, new_src_addr, ip4_header_t,
			    src_address);
      sum = ip_csum_update (sum, old_dst_addr, new_dst_addr, ip4_header_t,
			    dst_address);
      sum = ip_csum_update (sum, old_src_port, new_src_port, udp_header_t,
			    src_port);
      sum = ip_csum_update (sum, old_dst_port, new_dst_port, udp_header_t,
			    dst_port);
      udp->checksum = ip_csum_fold (sum);
    }
  else if (udp)
    {
      udp->src_port = new_src_port;
      udp->dst_port = new_dst_port;
    }
  else if (ip->protocol == IP_PROTOCOL_ICMP)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) ((u8 *) ip +
						     ip4_header_bytes (ip));
      nat_icmp_echo_header_t *echo = (nat_icmp_echo_header_t *) (icmp + 1);

      /* Currently unreachable: ICMP echo hairpinning is disabled at the
       * call site (see cgnat_session_in2out).  Kept correct for when it is
       * revisited: the ICMP checksum covers only the ICMP message itself,
       * so the rewritten IP addresses must NOT be folded into it - only
       * the identifier change matters. */
      old_src_port = echo->identifier;
      echo->identifier = new_src_port;

      sum = icmp->checksum;
      sum = ip_csum_update (sum, old_src_port, new_src_port,
			    nat_icmp_echo_header_t, identifier);
      icmp->checksum = ip_csum_fold (sum);
    }
}

/* Fast path: look the flow up in the session table directly.  On a hit the
 * in2out mapping lookup (one bihash search plus a cache miss on the mapping
 * pool entry) is skipped entirely - the session caches the mapping index and
 * the mapping carries the translation.  Returns the mapping, or 0 to fall
 * back to the full slow path.  The session is touched with its lock held,
 * mirroring cgnat_session_lookup_or_create's hit path. */
static_always_inline cgnat_mapping_t *
cgnat_in2out_session_fast_path (cgnat_main_t *cm, cgnat_instance_t *instance,
				u32 instance_index, u32 inside_fib_index,
				ip4_header_t *ip, u16 inside_port,
				u16 remote_port, tcp_header_t *tcp, f64 now)
{
  clib_bihash_kv_24_8_t kv, value;
  cgnat_session_t *session;
  cgnat_mapping_t *mapping;
  int rv;

  cgnat_make_flow_key (&kv, instance_index, inside_fib_index,
		       ip->src_address, ip->dst_address, inside_port,
		       cgnat_session_remote_port (ip->protocol, remote_port),
		       ip->protocol);

  cgnat_session_table_lock (cm, &kv);
  if (clib_bihash_search_24_8 (&cm->session_table, &kv, &value))
    {
      cgnat_session_table_unlock (cm, &kv);
      return 0;
    }
  session = cgnat_session_get_if_valid (cm, value.value);
  if (PREDICT_FALSE (!session))
    {
      cgnat_session_table_unlock (cm, &kv);
      return 0;
    }
  clib_spinlock_lock (&session->lock);
  cgnat_session_table_unlock (cm, &kv);

  if (PREDICT_FALSE (session->flags & CGNAT_SESSION_FLAG_DELETING))
    {
      clib_spinlock_unlock (&session->lock);
      return 0;
    }

  if (cgnat_session_touch (session, now, CGNAT_SESSION_FLAG_SEEN_IN2OUT,
			   tcp) &&
      session->tcp_state == CGNAT_TCP_FIN_RST)
    cgnat_session_start_timer (cm, session, now);

  mapping = cgnat_mapping_get_if_valid (
    cm, cgnat_index_to_value (session->mapping_index,
			      session->mapping_generation));
  if (PREDICT_FALSE (!mapping))
    {
      clib_spinlock_unlock (&session->lock);
      return 0;
    }

  if (PREDICT_FALSE (cgnat_mapping_is_auto (mapping) &&
		     instance->filter_mode == CGNAT_FILTER_MODE_ADF))
    {
      rv = cgnat_session_ensure_adf_remote (cm, mapping, session);
      if (PREDICT_FALSE (rv))
	{
	  clib_spinlock_unlock (&session->lock);
	  return 0;
	}
    }

  clib_spinlock_unlock (&session->lock);
  return mapping;
}

/* Fast path for the out2in direction: the session table also carries a
 * reverse key per session (the translated 5-tuple), so one lookup finds the
 * session and its mapping.  A session only exists if the flow was admitted
 * by the instance filter mode at creation, so no filter re-check is needed
 * here. */
static_always_inline cgnat_mapping_t *
cgnat_out2in_session_fast_path (cgnat_main_t *cm, clib_bihash_kv_24_8_t *rkv,
				tcp_header_t *tcp, f64 now)
{
  clib_bihash_kv_24_8_t value;
  cgnat_session_t *session;
  cgnat_mapping_t *mapping;
  cgnat_instance_t *instance;
  int rv;

  cgnat_session_table_lock (cm, rkv);
  if (clib_bihash_search_24_8 (&cm->session_table, rkv, &value))
    {
      cgnat_session_table_unlock (cm, rkv);
      return 0;
    }
  session = cgnat_session_get_if_valid (cm, value.value);
  if (PREDICT_FALSE (!session))
    {
      cgnat_session_table_unlock (cm, rkv);
      return 0;
    }
  clib_spinlock_lock (&session->lock);
  cgnat_session_table_unlock (cm, rkv);

  if (PREDICT_FALSE (session->flags & CGNAT_SESSION_FLAG_DELETING))
    {
      clib_spinlock_unlock (&session->lock);
      return 0;
    }

  if (cgnat_session_touch (session, now, CGNAT_SESSION_FLAG_SEEN_OUT2IN,
			   tcp) &&
      session->tcp_state == CGNAT_TCP_FIN_RST)
    cgnat_session_start_timer (cm, session, now);

  mapping = cgnat_mapping_get_if_valid (
    cm, cgnat_index_to_value (session->mapping_index,
			      session->mapping_generation));
  if (PREDICT_FALSE (!mapping))
    {
      clib_spinlock_unlock (&session->lock);
      return 0;
    }

  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (PREDICT_FALSE (instance &&
		     instance->filter_mode == CGNAT_FILTER_MODE_ADF &&
		     cgnat_mapping_is_auto (mapping)))
    {
      rv = cgnat_session_ensure_adf_remote (cm, mapping, session);
      if (PREDICT_FALSE (rv))
	{
	  clib_spinlock_unlock (&session->lock);
	  return 0;
	}
    }

  clib_spinlock_unlock (&session->lock);
  return mapping;
}

static_always_inline int
cgnat_session_in2out (vlib_main_t *vm, vlib_buffer_t *b,
		      u32 instance_index, u32 inside_fib_index, f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  tcp_header_t *tcp;
  udp_header_t *udp;
  cgnat_mapping_t *mapping = 0;
  cgnat_mapping_t *hairpin_dst_mapping = 0;
  u8 static_addr_hit = 0;
  u8 dynamic_mapping_created = 0;
  cgnat_instance_t *instance;
  cgnat_pba_alloc_result_t result;
  clib_bihash_kv_16_8_t kv, value;
  u32 mapping_index;
  u16 inside_port, remote_port, session_remote_port;
  int rv;

  /* ICMP Error Messages carry an inner IP datagram; translate them through
   * the mapping that owns the public address embedded in that inner packet.
   * Errors are not fragmented in normal operation; drop fragments to avoid
   * reading partial ICMP headers. */
  if (ip->protocol == IP_PROTOCOL_ICMP && !ip4_is_fragment (ip))
    {
      icmp46_header_t *icmp =
	(icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
      if (icmp_type_is_error_message (icmp->type))
	return cgnat_icmp_error_translate_in2out (cm, vm, b, ip,
						  instance_index,
						  inside_fib_index);
    }

  rv = cgnat_extract_l4 (b, ip, &inside_port, &remote_port, &tcp, &udp);
  if (rv)
    return rv;
  session_remote_port = cgnat_session_remote_port (ip->protocol, remote_port);

  instance = cgnat_instance_get_by_index (cm, instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  // if (!cgnat_instance_inside_fib_matches (instance, inside_fib_index))
  //   return VNET_API_ERROR_UNSUPPORTED;

  /* Fast path: an existing session makes the mapping lookup unnecessary. */
  mapping = cgnat_in2out_session_fast_path (cm, instance, instance_index,
					    inside_fib_index, ip, inside_port,
					    remote_port, tcp, now);
  if (PREDICT_TRUE (mapping != 0))
    goto have_mapping;

  cgnat_make_in2out_mapping_key (&kv, instance_index, inside_fib_index,
				 ip->src_address, inside_port, ip->protocol);
  
  // hit mapping table ?
  if (!cgnat_mapping_table_search (cm, &cm->in2out_mapping_table, &kv,
				   &value))
    mapping = cgnat_mapping_get_if_valid (cm, value.value);

  // hit static rule ?
  if (!mapping) 
  {
    cgnat_static_rule_t *rule = 0;
    if (!cgnat_static_addr_lookup (cm, &cm->static_addr_in2out_table,
            inside_fib_index, ip->src_address,
            ip->protocol, &rule))
    {
      static_addr_hit = 1;
      mapping = cgnat_static_addr_get_or_create_mapping (
        cm, rule, inside_port, ip->protocol, inside_fib_index);
    }
  }

  if (static_addr_hit && !mapping)
    return VNET_API_ERROR_BUG;

  // not hit static rule, begin dynamic/deterministic allocation
  if (!mapping)
    {
      cgnat_user_lock (instance, inside_fib_index, ip->src_address);
      if (!cgnat_mapping_table_search (cm, &cm->in2out_mapping_table, &kv,
				       &value))
	mapping = cgnat_mapping_get_if_valid (cm, value.value);

      if (!mapping)
	{
	  if (instance->mode == CGNAT_INSTANCE_MODE_DETERMINISTIC)
	    rv = cgnat_det_alloc_port (instance, inside_fib_index,
				       ip->src_address, inside_port,
				       ip->protocol, &result);
	  else
	    rv = cgnat_pba_alloc_port_locked (instance_index, inside_fib_index,
					      ip->src_address, inside_port,
					      ip->protocol, &result);

	  if (rv)
	    {
	      cgnat_user_unlock (instance, inside_fib_index, ip->src_address);
	      return rv;
	    }

	  mapping = cgnat_mapping_alloc (cm, &mapping_index);
	  mapping->inside_ip = ip->src_address;
	  mapping->nat_ip = result.public_ip;
	  mapping->inside_port = inside_port;
	  mapping->nat_port = result.public_port;
	  mapping->protocol = ip->protocol;
	  mapping->filter_mode = instance->filter_mode;
	  mapping->instance_index = instance_index;
	  mapping->inside_fib_index = inside_fib_index;
	  mapping->outside_fib_index = instance->outside_fib_index;
	  mapping->pool_index = result.pool_index;
	  mapping->public_ip_index = result.public_ip_index;
	  mapping->user_index = result.user_index;
	  mapping->block_index = result.block_index;
	  mapping->mapping_type =
	    (instance->mode == CGNAT_INSTANCE_MODE_DETERMINISTIC) ?
	      CGNAT_MAPPING_DETERMINISTIC : CGNAT_MAPPING_DYNAMIC;

	  // allocate and fill mapping
	  kv.value = cgnat_index_to_value (mapping_index, mapping->generation);
	  cgnat_make_out2in_mapping_key (&value, instance->outside_fib_index,
					 result.public_ip, result.public_port,
					 ip->protocol);
	  value.value = cgnat_index_to_value (mapping_index, mapping->generation);
	  cgnat_mapping_table_locks_lock (cm, &kv, &value);
	  if (clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &kv, 1))
	    {
	      cgnat_mapping_table_locks_unlock (cm, &kv, &value);
	      cgnat_dynamic_mapping_schedule_delete (cm, mapping);
	      cgnat_user_unlock (instance, inside_fib_index, ip->src_address);
	      return VNET_API_ERROR_BUG;
	    }

	  if (clib_bihash_add_del_16_8 (&cm->out2in_mapping_table, &value, 1))
	    {
	      clib_bihash_add_del_16_8 (&cm->in2out_mapping_table, &kv, 0);
	      cgnat_mapping_table_locks_unlock (cm, &kv, &value);
	      cgnat_dynamic_mapping_schedule_delete (cm, mapping);
	      cgnat_user_unlock (instance, inside_fib_index, ip->src_address);
	      return VNET_API_ERROR_BUG;
	    }
	  cgnat_mapping_table_locks_unlock (cm, &kv, &value);
	  dynamic_mapping_created = 1;
	}

      cgnat_user_unlock (instance, inside_fib_index, ip->src_address);
    }

  // search session, create or find
  rv = cgnat_session_lookup_or_create (cm, mapping, ip->dst_address,
				       session_remote_port,
				       CGNAT_SESSION_FLAG_SEEN_IN2OUT,
				       tcp, now, 1,
				       cgnat_mapping_is_auto (mapping) &&
					 instance->filter_mode ==
					   CGNAT_FILTER_MODE_ADF);
  if (rv)
    {
      if (dynamic_mapping_created)
	cgnat_dynamic_mapping_schedule_delete (cm, mapping);
      return rv;
    }

have_mapping:
  /* Check whether hairpinning is enabled.  ICMP echo is excluded: the echo
   * identifier serves as the NAT "port" for both directions of the
   * hairpinned exchange and cannot be pair-wise translated without extra
   * state - the echo reply would miss the peer's mapping and allocate a
   * bogus port.  ICMP packets take the normal in2out path.
   *
   * Cheap pre-filter: only a destination inside this instance's public
   * address envelope can possibly hairpin; anything else skips the hash
   * lookups entirely. */
  if (PREDICT_FALSE (instance->hairpinning_enabled) &&
      ip->protocol != IP_PROTOCOL_ICMP &&
      clib_net_to_host_u32 (ip->dst_address.as_u32) >=
	clib_net_to_host_u32 (instance->pool_addr_min.as_u32) &&
      clib_net_to_host_u32 (ip->dst_address.as_u32) <=
	clib_net_to_host_u32 (instance->pool_addr_max.as_u32))
    hairpin_dst_mapping = cgnat_in2out_hairpin_dst_lookup (
      cm, instance, ip, remote_port, inside_fib_index);

  if (hairpin_dst_mapping)
    {
      cgnat_l4_rewrite_hairpin (ip, tcp, udp, mapping, hairpin_dst_mapping);
      vnet_buffer (b)->sw_if_index[VLIB_TX] = hairpin_dst_mapping->inside_fib_index;
    }
  else
    {
      cgnat_l4_rewrite_in2out (ip, tcp, udp, mapping, instance->tcp_mss);
      vnet_buffer (b)->sw_if_index[VLIB_TX] = mapping->outside_fib_index;
    }
  return 0;
}

static_always_inline int
cgnat_session_out2in (vlib_main_t *vm, vlib_buffer_t *b, f64 now)
{
  cgnat_main_t *cm = &cgnat_main;
  ip4_header_t *ip = vlib_buffer_get_current (b);
  tcp_header_t *tcp;
  udp_header_t *udp;
  cgnat_mapping_t *mapping;
  cgnat_instance_t *instance;
  clib_bihash_kv_16_8_t kv, value;
  u16 remote_port, nat_port, session_remote_port;
  u8 filter_mode;
  u8 allow_create;
  u32 outside_fib_index;
  int rv;

  /* ICMP Error Messages carry an inner IP datagram; translate them through
   * the mapping that owns the public address embedded in that inner packet.
   * Errors are not fragmented in normal operation; drop fragments to avoid
   * reading partial ICMP headers. */
  if (ip->protocol == IP_PROTOCOL_ICMP && !ip4_is_fragment (ip))
    {
      icmp46_header_t *icmp =
	(icmp46_header_t *) ((u8 *) ip + ip4_header_bytes (ip));
      if (icmp_type_is_error_message (icmp->type))
	return cgnat_icmp_error_translate_out2in (cm, vm, b, ip);
    }

  rv = cgnat_extract_l4 (b, ip, &remote_port, &nat_port, &tcp, &udp);
  if (rv)
    return rv;
  session_remote_port = cgnat_session_remote_port (ip->protocol, remote_port);

  outside_fib_index = fib_table_get_index_for_sw_if_index (
    FIB_PROTOCOL_IP4, vnet_buffer (b)->sw_if_index[VLIB_RX]);

  /* Fast path: the session table also carries a reverse key per session
   * (the translated 5-tuple), so a hit skips both the mapping lookup and
   * the admission checks - a session only exists if the flow passed the
   * filter mode at creation. */
  {
    clib_bihash_kv_24_8_t rkv;

    cgnat_make_reverse_flow_key (&rkv, outside_fib_index, ip->dst_address,
				 ip->src_address, nat_port,
				 session_remote_port, ip->protocol);
    mapping = cgnat_out2in_session_fast_path (cm, &rkv, tcp, now);
    if (PREDICT_TRUE (mapping != 0))
      {
	instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
	if (PREDICT_FALSE (!instance))
	  return VNET_API_ERROR_NO_SUCH_ENTRY;
	goto rewrite;
      }
  }

  cgnat_make_out2in_mapping_key (&kv, outside_fib_index, ip->dst_address,
				 nat_port, ip->protocol);
  
  // search mapping
  if (cgnat_mapping_table_search (cm, &cm->out2in_mapping_table, &kv, &value))
    {
      cgnat_static_rule_t *rule = 0;
      // mapping not found, search static map rule
      if (cgnat_static_addr_lookup (cm, &cm->static_addr_out2in_table,
				    outside_fib_index, ip->dst_address,
				    ip->protocol, &rule))
	return VNET_API_ERROR_NO_SUCH_ENTRY;
      // found, create mapping
      mapping = cgnat_static_addr_get_or_create_mapping (cm, rule, nat_port,
							 ip->protocol,
							 rule->inside_fib_index);
    }
  else
    mapping = cgnat_mapping_get_if_valid (cm, value.value);

  if (!mapping)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  
  // found mapping, get instance
  instance = cgnat_instance_get_by_index (cm, mapping->instance_index);
  if (!instance)
    return VNET_API_ERROR_NO_SUCH_ENTRY;
  // obtain filter mode
  filter_mode = instance->filter_mode;
  if (mapping->mapping_type == CGNAT_MAPPING_STATIC ||
      filter_mode == CGNAT_FILTER_MODE_EIF)
    allow_create = 1;
  else if (filter_mode == CGNAT_FILTER_MODE_ADF)
    {
      rv = cgnat_session_lookup_or_create ( cm, mapping, ip->src_address, session_remote_port,
          CGNAT_SESSION_FLAG_SEEN_OUT2IN, tcp, now, 0, 1);
      if (!rv)
	goto rewrite;
      if (rv != VNET_API_ERROR_NO_SUCH_ENTRY)
	return rv;
      if (!cgnat_adf_remote_allowed (cm, mapping, ip->src_address))
	return VNET_API_ERROR_INVALID_VALUE;
      allow_create = 1;
    }
  else
    allow_create = 0;
  rv = cgnat_session_lookup_or_create ( cm, mapping, ip->src_address, session_remote_port,
      CGNAT_SESSION_FLAG_SEEN_OUT2IN, tcp, now, allow_create, filter_mode == CGNAT_FILTER_MODE_ADF &&
      cgnat_mapping_is_auto (mapping));
  if (rv)
    {
      /* Mapping hit means this packet targets a CGNAT public endpoint.
       * Static mappings are explicit ingress rules. EIF accepts any remote
       * endpoint, ADF accepts a learned remote address, and ADPF requires an
       * existing exact session.
       */
      return allow_create ? rv : VNET_API_ERROR_INVALID_VALUE;
    }

rewrite:
  cgnat_l4_rewrite_out2in (ip, tcp, udp, mapping, instance->tcp_mss);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = mapping->inside_fib_index;
  return 0;
}

#endif /* included_cgnat_session_inlines_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
