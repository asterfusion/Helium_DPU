/*
 * Copyright 2024-2027 Asterfusion Network
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
#ifndef included_map_ce_h
#define included_map_ce_h

#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>
#include <vnet/fib/fib_types.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/load_balance.h>
#include <vppinfra/lock.h>

#include <map-ce/map_ce.api_enum.h>
#include "lpm.h"
#include "map_ce_nat.h"

#define MAP_CE_ERR_GOOD			0
#define MAP_CE_ERR_BAD_POOL_SIZE		-1
#define MAP_CE_ERR_BAD_HT_RATIO		-2
#define MAP_CE_ERR_BAD_LIFETIME		-3
#define MAP_CE_ERR_BAD_BUFFERS		-4
#define MAP_CE_ERR_BAD_BUFFERS_TOO_LARGE	-5
#define MAP_CE_ERR_UNSUPPORTED             -6

u8 *format_map_ce_domain (u8 * s, va_list * args);
u8 *format_map_ce_trace (u8 * s, va_list * args);
u8 *format_map_ce_nat44_trace (u8 * s, va_list * args);
u8 *format_map_nat44_protocol (u8 *s, va_list *args);
u8 *format_map_nat44_ei_static_session_kvp (u8 *s, va_list *args);
u8 *format_map_nat44_ei_session_kvp (u8 *s, va_list *args);
u8 *format_map_nat44_ei_key (u8 *s, va_list *args);
u8 *format_map_nat44_ei_user_kvp (u8 *s, va_list *args);

int map_ce_create_domain (ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
		       ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
		       ip6_address_t * ip6_dst, u8 ip6_dst_len,
		       ip6_address_t * end_user_prefix, u8 end_user_prefix_len,
		       u8 ea_bits_len, u8 psid_offset, u8 psid_length,
		       u32 * map_domain_index, u16 mtu, u8 flags, u8 * tag,
		       u32 nat_max_static_session, u32 nat_max_user, u32 nat_max_session_per_user);
int map_ce_delete_domain (u32 map_domain_index);

int map_ce_if_enable_disable (bool is_enable, u32 sw_if_index);

int map_ce_add_del_local_prefix (u32 map_domain_index, ip4_address_t * ip4_prefix, u8 ip4_prefix_len, bool is_add); 

int map_ce_domain_set_psid (u32 domain_index, u16 psid);

void map_ce_nat44_domain_update_psid(u32 map_domain_index, u16 psid);

int map_ce_param_set_fragmentation (bool inner, bool ignore_df);
int map_ce_param_set_icmp (ip4_address_t * ip4_err_relay_src);
int map_ce_param_set_icmp6 (u8 enable_unreachable);
int map_ce_param_set_security_check (bool enable, bool fragments);
int map_ce_param_set_traffic_class (bool copy, u8 tc);
int map_ce_param_set_tos (bool copy, u8 tos);
int map_ce_param_set_tcp (u16 tcp_mss);

int map_ce_domain_param_set_fragmentation (u32 domain_index, bool is_clean, bool inner, bool ignore_df);
int map_ce_domain_param_set_icmp (u32 domain_index, bool is_clean, ip4_address_t * ip4_err_relay_src);
int map_ce_domain_param_set_icmp6 (u32 domain_index, bool is_clean, u8 enable_unreachable);
int map_ce_domain_param_set_security_check (u32 domain_index, bool is_clean, bool enable, bool fragments);
int map_ce_domain_param_set_traffic_class (u32 domain_index, bool is_clean, bool copy, u8 tc);
int map_ce_domain_param_set_tos (u32 domain_index, bool is_clean, bool copy, u8 tos);
int map_ce_domain_param_set_tcp (u32 domain_index, bool is_clean, u16 tcp_mss);
int map_ce_domain_param_set_mtu (u32 domain_index, u16 mtu);

typedef enum
{
  MAP_CE_DOMAIN_PREFIX = 1 << 0,
  MAP_CE_DOMAIN_TRANSLATION = 1 << 1,	// The domain uses MAP-T
} __attribute__ ((__packed__)) map_ce_domain_flags_e;

/*
 * This structure _MUST_ be no larger than a single cache line (64 bytes).
 * If more space is needed make a union of ip6_prefix as those are mutually exclusive.
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ip6_address_t ip6_dst; /* map-t dmr, map-e br-ipv6-address */
  ip6_address_t ip6_prefix; /* Baisc mapping rule */
  ip6_address_t end_user_prefix; /* end_user_prefix */

  ip4_address_t ip4_prefix; /* Baisc mapping rule */

  u8 ip6_dst_len;           
  u8 ip6_prefix_len;
  u8 ip4_prefix_len;
  u8 end_user_prefix_len;

  u8 ea_bits_len;           /* Baisc mapping rule */
  u8 psid_offset;           /* Baisc mapping rule */
  u8 psid_length;           /* Baisc mapping rule */
  map_ce_domain_flags_e flags; /* domain flags */

  /* MTU */
  u16 mtu;

  /* Manually psid only for ea_bits_len is 0 */
  u16 psid;              

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /* helpers */
  u32 suffix_mask;
  u16 psid_mask;
  u8 psid_shift;
  u8 suffix_shift;
  u8 ea_shift;

  /* Parame */
  u8 psid_valid:1;
  u8 tc_valid:1;
  u8 tos_valid:1;
  u8 tcp_mss_valid:1;
  u8 frag_valid:1;
  u8 sec_check_valid:1;
  u8 icmp6_enabled_valid:1;
  u8 icmp4_src_address_valid:1;

  ip_prefix_t *local_rules; /* Local ipv4 rule */


  bool tc_copy;
  u8 tc; /* Ipv6 Traffic class: zero, copy (~0) or fixed value */

  bool tos_copy;
  u8 tos; /* Ipv4 Tos: zero, copy (~0) or fixed value */

  bool frag_inner; /* Inner or outer fragmentation */
  bool frag_ignore_df; /* Fragment (outer) packet even if DF is set */

  bool sec_check; /* Inbound security check */
  bool sec_check_frag; /* Inbound security check for (subsequent) fragments */

  bool icmp6_enabled; /* Send destination unreachable for security check failure */

  u16 tcp_mss; /* TCP MSS clamp value */

  ip4_address_t icmp4_src_address; /* ICMPv6 -> ICMPv4 relay parameters */

} map_ce_domain_t;

STATIC_ASSERT ((sizeof (map_ce_domain_t) <= CLIB_CACHE_LINE_BYTES * 2),
	       "MAP CE domain fits in one cacheline");

/*
 * Extra data about a domain that doesn't need to be time/space critical.
 * This structure is in a vector parallel to the main map_ce_domain_t,
 * and indexed by the same map-ce-domain-index values.
 */
typedef struct
{
  u8 *tag;			/* Probably a user-assigned domain name. */
} map_ce_domain_extra_t;

#define MAP_CE_REASS_INDEX_NONE ((u16)0xffff)

/*
 * MAP domain counters
 */
typedef enum
{
  /* Simple counters */
  MAP_CE_DOMAIN_IPV4_FRAGMENT = 0,
  /* Combined counters */
  MAP_CE_DOMAIN_COUNTER_RX = 0,
  MAP_CE_DOMAIN_COUNTER_TX,
  MAP_CE_N_DOMAIN_COUNTER
} map_ce_domain_counter_t;

typedef struct
{
  /* pool of MAP domains */
  map_ce_domain_t *domains;
  map_ce_domain_extra_t *domain_extras;
  map_nat44_ei_domain_t *nat_domains;

  /* MAP Domain packet/byte counters indexed by map domain index */
  vlib_combined_counter_main_t *domain_counters;
  volatile u32 *counter_lock;

  /* API message id base */
  u16 msg_id_base;

  /* Ipv6 Traffic class: zero, copy (~0) or fixed value */
  u8 tc;
  bool tc_copy;

  /* Ipv4 Tos: zero, copy (~0) or fixed value */
  u8 tos;
  bool tos_copy;

  /* Inbound security check */
  bool sec_check;		    

  /* Inbound security check for (subsequent) fragments */
  bool sec_check_frag;		

  /* Send destination unreachable for security check failure */
  bool icmp6_enabled;		

  /* Inner or outer fragmentation */
  bool frag_inner;		

  /* Fragment (outer) packet even if DF is set */
  bool frag_ignore_df;		

  /* TCP MSS clamp value */
  u16 tcp_mss;			

  /* ICMPv6 -> ICMPv4 relay parameters */
  ip4_address_t icmp4_src_address;
  vlib_simple_counter_main_t icmp_relayed;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Lookup tables */
  lpm_t *ip4_prefix_tbl;
  lpm_t *ip6_prefix_tbl;
  lpm_t *ip4_local_tbl;

  uword ip4_sv_reass_custom_next_index;
} map_ce_main_t;

typedef vl_counter_map_ce_enum_t map_ce_error_t;
u64 map_ce_error_counter_get (u32 node_index, map_ce_error_t map_error);

typedef struct
{
  u32 map_domain_index;
} map_ce_trace_t;

always_inline void
map_ce_add_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_buffer_t * b, u32 map_domain_index)
{
  map_ce_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->map_domain_index = map_domain_index;
}

typedef struct 
{
  u32 map_domain_index;
  bool local_addr_vld;
  ip4_address_t local_addr;
  bool external_addr_vld;
  ip4_address_t external_addr;
  u16 local_port;
  u16 external_port;
  map_ce_nat_protocol_t proto;
} map_ce_nat44_trace_t;

always_inline void
map_ce_add_nat44_trace (vlib_main_t * vm, vlib_node_runtime_t * node,
	       vlib_buffer_t * b, u32 map_domain_index, 
           ip4_address_t *local_addr,
           ip4_address_t *external_addr,
           u16 local_port,
           u16 external_port,
           map_ce_nat_protocol_t proto)
{
  map_ce_nat44_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));

  clib_memset(tr, 0, sizeof(*tr));

  tr->map_domain_index = map_domain_index;
  if (local_addr)
  {
      tr->local_addr_vld = true;
      tr->local_addr = *local_addr;
  }
  if (external_addr)
  {
      tr->external_addr_vld = true;
      tr->external_addr = *external_addr;
  }

  tr->local_port = local_port;
  tr->external_port = external_port;
  tr->proto = proto;
}
 
extern map_ce_main_t map_ce_main;

extern vlib_node_registration_t map_ce_ip4_classify_node;
extern vlib_node_registration_t map_ce_ip6_classify_node;

extern vlib_node_registration_t ip4_map_e_ce_node;
extern vlib_node_registration_t ip6_map_e_ce_node;

extern vlib_node_registration_t ip4_map_t_ce_node;
extern vlib_node_registration_t ip6_map_t_ce_node;

extern vlib_node_registration_t ip6_map_ce_post_ip4_reass_node;

/*
 * map_ce_get_pfx
 */
static_always_inline u64
map_ce_get_pfx (map_ce_domain_t * d, u32 addr, u16 port)
{
    u16 psid = d->psid_valid ? d->psid : (port >> d->psid_shift) & d->psid_mask;

    if (d->ea_bits_len == 0)
        return clib_net_to_host_u64 (d->end_user_prefix.as_u64[0]);

    u32 suffix = (addr >> d->suffix_shift) & d->suffix_mask;
    u64 ea = (((u64) suffix << d->psid_length)) | psid;

    if (d->flags & MAP_CE_DOMAIN_PREFIX)
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[0]) | ea << d->ea_shift | (addr & ((1u << d->suffix_shift) - 1));
    else 
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[0]) | ea << d->ea_shift;
}

static_always_inline u64
map_ce_get_pfx_net (map_ce_domain_t * d, u32 addr, u16 port)
{
    return clib_host_to_net_u64 (map_ce_get_pfx (d, clib_net_to_host_u32 (addr),
                clib_net_to_host_u16 (port)));
}

static_always_inline u64
map_ce_get_pfx_fmr (map_ce_domain_t * d, u32 addr, u16 port)
{
    u16 psid = (port >> d->psid_shift) & d->psid_mask;

    if (d->ea_bits_len == 0)
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[0]);

    u32 suffix = (addr >> d->suffix_shift) & d->suffix_mask;
    u64 ea = (((u64) suffix << d->psid_length)) | psid;

    if (d->flags & MAP_CE_DOMAIN_PREFIX)
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[0]) | ea << d->ea_shift | (addr & ((1u << d->suffix_shift) - 1));
    else 
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[0]) | ea << d->ea_shift;
}

static_always_inline u64
map_ce_get_pfx_fmr_net (map_ce_domain_t * d, u32 addr, u16 port)
{
    return clib_host_to_net_u64 (map_ce_get_pfx_fmr (d, clib_net_to_host_u32 (addr),
                clib_net_to_host_u16 (port)));
}

/*
 * map_ce_get_sfx
 */
static_always_inline u64
map_ce_get_sfx (map_ce_domain_t * d, u32 addr, u16 port)
{
    u16 psid = d->psid_valid ? d->psid : (port >> d->psid_shift) & d->psid_mask;

    if (d->ip6_prefix_len == 96)
        return (clib_net_to_host_u64 (d->ip6_prefix.as_u64[1]) | addr);

    if (d->ip6_prefix_len == 128)
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[1]);

    if (d->flags & MAP_CE_DOMAIN_PREFIX)
        return (u64) (addr & (0xFFFFFFFF << d->suffix_shift)) << 16;

    /* Shared or full IPv4 address */
    return ((u64) addr << 16) | psid;
}

static_always_inline u64
map_ce_get_sfx_fmr (map_ce_domain_t * d, u32 addr, u16 port)
{
    u16 psid = (port >> d->psid_shift) & d->psid_mask;

    if (d->ip6_prefix_len == 96)
        return (clib_net_to_host_u64 (d->ip6_prefix.as_u64[1]) | addr);

    if (d->ip6_prefix_len == 128)
        return clib_net_to_host_u64 (d->ip6_prefix.as_u64[1]);

    if (d->flags & MAP_CE_DOMAIN_PREFIX)
        return (u64) (addr & (0xFFFFFFFF << d->suffix_shift)) << 16;

    /* Shared or full IPv4 address */
    return ((u64) addr << 16) | psid;
}

static_always_inline u64
map_ce_get_sfx_net (map_ce_domain_t * d, u32 addr, u16 port)
{
    return clib_host_to_net_u64 (map_ce_get_sfx (d, clib_net_to_host_u32 (addr),
                clib_net_to_host_u16 (port)));
}

static_always_inline u64
map_ce_get_sfx_fmr_net (map_ce_domain_t * d, u32 addr, u16 port)
{
    return clib_host_to_net_u64 (map_ce_get_sfx_fmr (d, clib_net_to_host_u32 (addr),
                clib_net_to_host_u16 (port)));
}

static_always_inline u32
map_ce_get_ip4 (map_ce_domain_t * d, ip6_address_t * addr)
{
  if (d->flags & MAP_CE_DOMAIN_PREFIX)
  {
      /* 
       * |ip6_prefix_len | ea_bits_len | subnet | Interface Id 
       * And now only support |ip6_prefix_len | ea_bits_len | subnet | <= 64
       */
      u8  subnet_bit_len = 32 - d->ip4_prefix_len - d->ea_bits_len;
      u32 ip4_addr_u32 = clib_host_to_net_u32(d->ip4_prefix.as_u32) & ~(~0u >> d->ip4_prefix_len);
      u64 ea_bits_subnet = (clib_net_to_host_u64(addr->as_u64[0]) & (~0ull >> d->ip6_prefix_len));
      ip4_addr_u32 |= (ea_bits_subnet >> (64 - d->ip6_prefix_len - d->ea_bits_len)) << subnet_bit_len;
      ip4_addr_u32 |= ea_bits_subnet & ((1u << subnet_bit_len) - 1) ;

      return clib_host_to_net_u32(ip4_addr_u32);
  }
  else
  {
      ASSERT (d->ip6_dst_len == 64 || d->ip6_dst_len == 96);
      if (d->ip6_dst_len == 96)
          return clib_host_to_net_u32 (clib_net_to_host_u64 (addr->as_u64[1]));
      else
          return clib_host_to_net_u32 (clib_net_to_host_u64 (addr->as_u64[1]) >> 16);
  }
}

static_always_inline map_ce_domain_t *
ip4_map_get_domain (ip4_address_t * addr, u32 * map_domain_index, u8 * error)
{
  map_ce_main_t *mm = &map_ce_main;

  u32 mdi = mm->ip4_prefix_tbl->lookup (mm->ip4_prefix_tbl, addr, 32);
  if (mdi == ~0)
    {
      *error = MAP_CE_ERROR_NO_DOMAIN;
      return 0;
    }
  *map_domain_index = mdi;
  return pool_elt_at_index (mm->domains, mdi);
}

/*
 * Get the MAP domain from an IPv6 address.
 * If the IPv6 address or prefix is shared the IPv4 address must be used.
 */
static_always_inline map_ce_domain_t *
ip6_map_get_domain (ip6_address_t * addr, u32 * map_domain_index, u8 * error)
{
    map_ce_main_t *mm = &map_ce_main;
    u32 mdi = mm->ip6_prefix_tbl->lookup (mm->ip6_prefix_tbl, addr, 128);
    if (mdi == ~0)
    {
        *error = MAP_CE_ERROR_NO_DOMAIN;
        return 0;
    }

    *map_domain_index = mdi;
    return pool_elt_at_index (mm->domains, mdi);
}

static_always_inline map_ce_domain_t *
ip4_local_map_get_domain (ip4_address_t * addr, u32 * map_domain_index, u8 * error)
{
    map_ce_main_t *mm = &map_ce_main;

    u32 mdi = mm->ip4_local_tbl->lookup (mm->ip4_local_tbl, addr, 32);
    if (mdi == ~0)
    {
        *error = MAP_CE_ERROR_NO_DOMAIN;
        return 0;
    }
    *map_domain_index = mdi;
    return pool_elt_at_index (mm->domains, mdi);
}

clib_error_t *map_ce_plugin_api_hookup (vlib_main_t * vm);

/*
 * True is goto CE
 * False is goto BR
 */
static_always_inline bool ip4_map_check_dst_ip_type(map_ce_domain_t * d, const ip4_address_t * ip4)
{
    u32 prefix = clib_host_to_net_u32(d->ip4_prefix.as_u32) & ~(~0u >> d->ip4_prefix_len);
    u32 ip     = clib_host_to_net_u32(ip4->as_u32) & ~(~0u >> d->ip4_prefix_len);
    return prefix == ip;
}

/*
 * Supports prefix of 96 or 64 (with u-octet)
 */

static_always_inline void
ip4_map_t_ce_embedded_address (map_ce_domain_t * d,
			    ip6_address_t * ip6, const ip4_address_t * ip4)
{
    ASSERT (d->ip6_dst_len == 96 || d->ip6_dst_len == 64);	//No support for other lengths for now
    u8 offset = d->ip6_dst_len == 64 ? 9 : 12;
    ip6->as_u64[0] = d->ip6_dst.as_u64[0];
    ip6->as_u64[1] = d->ip6_dst.as_u64[1];
    clib_memcpy_fast (&ip6->as_u8[offset], ip4, 4);
}

static_always_inline u32
ip6_map_t_ce_embedded_address (map_ce_domain_t * d, ip6_address_t * addr)
{
    ASSERT (d->ip6_dst_len == 64 || d->ip6_dst_len == 96);
    u32 x;
    u8 offset = d->ip6_dst_len == 64 ? 9 : 12;
    clib_memcpy (&x, &addr->as_u8[offset], 4);
    return x;
}

static_always_inline void
map_mss_clamping (tcp_header_t * tcp, ip_csum_t * sum, u16 mss_clamping)
{
    u8 *data;
    u8 opt_len, opts_len, kind;
    u16 mss;
    u16 mss_value_net = clib_host_to_net_u16 (mss_clamping);

    if (!tcp_syn (tcp))
        return;

    opts_len = (tcp_doff (tcp) << 2) - sizeof (tcp_header_t);
    data = (u8 *) (tcp + 1);
    for (; opts_len > 0; opts_len -= opt_len, data += opt_len)
    {
        kind = data[0];

        if (kind == TCP_OPTION_EOL)
            break;
        else if (kind == TCP_OPTION_NOOP)
        {
            opt_len = 1;
            continue;
        }
        else
        {
            if (opts_len < 2)
                return;
            opt_len = data[1];

            if (opt_len < 2 || opt_len > opts_len)
                return;
        }

        if (kind == TCP_OPTION_MSS)
        {
            mss = *(u16 *) (data + 2);
            if (clib_net_to_host_u16 (mss) > mss_clamping)
            {
                *sum =
                    ip_csum_update (*sum, mss, mss_value_net, ip4_header_t,
                            length);
                clib_memcpy (data + 2, &mss_value_net, 2);
            }
            return;
        }
    }
}


static inline void
map_ce_domain_counter_lock (map_ce_main_t * mm)
{
    if (mm->counter_lock)
        while (clib_atomic_test_and_set (mm->counter_lock))
            /* zzzz */ ;
}

static inline void
map_ce_domain_counter_unlock (map_ce_main_t * mm)
{
    if (mm->counter_lock)
        clib_atomic_release (mm->counter_lock);
}

static_always_inline map_nat44_ei_domain_t *
map_ce_get_nat44_domain (u32 map_domain_index, u8 * error)
{
    map_ce_main_t *mm = &map_ce_main;

    if (pool_is_free_index (mm->nat_domains, map_domain_index))
        return 0 ;

    return pool_elt_at_index (mm->nat_domains, map_domain_index);
}
#endif
