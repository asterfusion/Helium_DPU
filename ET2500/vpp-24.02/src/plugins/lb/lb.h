/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

/**
 * lb-plugin implements a MagLev-like load balancer.
 * http://research.google.com/pubs/pub44824.html
 *
 * It hasn't been tested for interoperability with the original MagLev
 * but intends to provide similar functionality.
 * The load-balancer receives traffic destined to VIP (Virtual IP)
 * addresses from one or multiple(ECMP) routers.
 * The load-balancer tunnels the traffic toward many application servers
 * ensuring session stickiness (i.e. that a single sessions is tunneled
 * towards a single application server).
 *
 */

#ifndef LB_PLUGIN_LB_LB_H_
#define LB_PLUGIN_LB_LB_H_

#include <lb/util.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <lb/lbhash.h>
#include <vppinfra/lock.h>

#define LB_DEFAULT_STICKY_BUCKETS         (1 << 20)
#define LB_DEFAULT_STICKY_MEMORY_SIZE     (0)

#define LB_MAPPING_BUCKETS                (1024 * 16)
#define LB_MAPPING_MEMORY_SIZE            (0)

#define LB_DEFAULT_FLOW_TIMEOUT           (40)
#define LB_DEFAULT_FLOW_TCP_TRANSITORY    (40)
#define LB_DEFAULT_FLOW_TCP_CLOSING       (10)

#define LB_DYNAMIC_MAPPING_BUCKETS        (1024 * 512)
#define LB_DYNAMIC_MAPPING_MEMORY_SIZE    (0)

#define LB_VIP_PER_PORT_BUCKETS           (1024)
#define LB_VIP_PER_PORT_MEMORY_SIZE       (0)

typedef enum {
  LB_NEXT_DROP,
  LB_N_NEXT,
} lb_next_t;

typedef enum {
  LB_NAT4_IN2OUT_NEXT_DROP,
  LB_NAT4_IN2OUT_NEXT_LOOKUP,
  LB_NAT4_IN2OUT_N_NEXT,
} LB_nat4_in2out_next_t;

typedef enum {
  LB_NAT6_IN2OUT_NEXT_DROP,
  LB_NAT6_IN2OUT_NEXT_LOOKUP,
  LB_NAT6_IN2OUT_N_NEXT,
} LB_nat6_in2out_next_t;

#define foreach_lb_nat_in2out_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(IN2OUT_PACKETS, "Good in2out packets processed")      \
_(NO_TRANSLATION, "No translation")

typedef enum {
#define _(sym,str) LB_NAT_IN2OUT_ERROR_##sym,
  foreach_lb_nat_in2out_error
#undef _
  LB_NAT_IN2OUT_N_ERROR,
} lb_nat_in2out_error_t;


#define foreach_lb_nat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")

typedef enum {
#define _(N, i, n, s) LB_NAT_PROTOCOL_##N = i,
  foreach_lb_nat_protocol
#undef _

  LB_NAT_N_PROTOCOLS
} lb_nat_protocol_t;

/**
 * lb for kube-proxy supports three types of service
 */
typedef enum {
  LB_SRV_TYPE_CLUSTERIP,
  LB_SRV_TYPE_NODEPORT,
  LB_SRV_N_TYPES,
} lb_svr_type_t;

typedef enum {
  LB4_NODEPORT_NEXT_IP4_NAT4,
  LB4_NODEPORT_NEXT_DROP,
  LB4_NODEPORT_N_NEXT,
} lb4_nodeport_next_t;

typedef enum {
  LB6_NODEPORT_NEXT_IP6_NAT6,
  LB6_NODEPORT_NEXT_DROP,
  LB6_NODEPORT_N_NEXT,
} lb6_nodeport_next_t;

/**
 * Each VIP is configured with a set of
 * application server.
 */
typedef struct {
  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

  /**
   * Destination address used to tunnel traffic towards
   * that application server.
   * The address is also used as ID and pseudo-random
   * seed for the load-balancing process.
   */
  ip46_address_t address;

  /**
   * ASs are indexed by address and VIP Index.
   * Which means there will be duplicated if the same server
   * address is used for multiple VIPs.
   */
  u32 vip_index;

  /**
   * Some per-AS flags.
   * For now only LB_AS_FLAGS_USED is defined.
   */
  u8 flags;

#define LB_AS_FLAGS_USED 0x1

  /**
   * Rotating timestamp of when LB_AS_FLAGS_USED flag was last set.
   *
   * AS removal is based on garbage collection and reference counting.
   * When an AS is removed, there is a race between configuration core
   * and worker cores which may still add a reference while it should not
   * be used. This timestamp is used to not remove the AS while a race condition
   * may happen.
   */
  u32 last_used;

  /**
   * The FIB entry index for the next-hop
   */
  fib_node_index_t next_hop_fib_entry_index;

  /**
   * The child index on the FIB entry
   */
  u32 next_hop_child_index;

  /**
   * The next DPO in the graph to follow.
   */
  dpo_id_t dpo;

  /**
   * Vrf Support
   */
  u32 vrf_id;
  u32 fib_index;

} lb_as_t;

format_function_t format_lb_as;

typedef struct {
  u32 as_index;
} lb_new_flow_entry_t;

#define lb_foreach_vip_counter \
 _(NEXT_PACKET, "packet from existing sessions", 0) \
 _(FIRST_PACKET, "first session packet", 1) \
 _(UNTRACKED_PACKET, "untracked packet", 2) \
 _(NO_SERVER, "no server configured", 3)

typedef enum {
#define _(a,b,c) LB_VIP_COUNTER_##a = c,
  lb_foreach_vip_counter
#undef _
  LB_N_VIP_COUNTERS
} lb_vip_counter_t;

typedef enum {
  LB_ENCAP_TYPE_GRE4,
  LB_ENCAP_TYPE_GRE6,
  LB_ENCAP_TYPE_L3DSR,
  LB_ENCAP_TYPE_NAT4,
  LB_ENCAP_TYPE_NAT6,
  LB_ENCAP_N_TYPES,
} lb_encap_type_t;

/**
 * Lookup type
 */

typedef enum {
  LB_LKP_SAME_IP_PORT,
  LB_LKP_DIFF_IP_PORT,
  LB_LKP_ALL_PORT_IP,
  LB_LKP_N_TYPES,
} lb_lkp_type_t;

/**
 * The load balancer supports IPv4 and IPv6 traffic
 * and GRE4, GRE6, L3DSR and NAT4, NAT6 encap.
 */
typedef enum {
  LB_VIP_TYPE_IP6_GRE6,
  LB_VIP_TYPE_IP6_GRE4,
  LB_VIP_TYPE_IP4_GRE6,
  LB_VIP_TYPE_IP4_GRE4,
  LB_VIP_TYPE_IP4_L3DSR,
  LB_VIP_TYPE_IP4_NAT4,
  LB_VIP_TYPE_IP6_NAT6,
  LB_VIP_TYPE_IP6_NAT4,
  LB_VIP_N_TYPES,
} lb_vip_type_t;

format_function_t format_lb_vip_type;
unformat_function_t unformat_lb_vip_type;

format_function_t format_lb_nat_proto;

/* args for different vip encap types */
typedef struct {
  union
  {
    struct
    {
      /* Service type. clusterip or nodeport */
      u8 srv_type;

      /* Pod's port corresponding to specific service. network byte order */
      u16 target_port;
    };
    /* DSCP bits for L3DSR */
    u8 dscp;
    u64 as_u64;
  };
} lb_vip_encap_args_t;

typedef struct {
  /* all fields in NET byte order */
  union {
    struct {
      u32 vip_prefix_index;
      u16 port;
      u8  protocol;
      u32 fib_index;
    };
    u64 as_u64[2];
  };
} vip_port_key_t;

typedef struct
{
    clib_spinlock_t lock_self;

    ip4_address_t addr;
    u32 busy_ports[LB_NAT_N_PROTOCOLS];
    uword *busy_port_bitmap[LB_NAT_N_PROTOCOLS];

    //record the flow index by per port 
    u32 *flow_index[LB_NAT_N_PROTOCOLS];
} lb_vip_snat_address_t;

typedef struct
{
    u32 id;
    u32 refcnt;
    lb_vip_snat_address_t *addresses;
} lb_vip_snat_addresses_pool_t;

/**
 * Load balancing service is provided per VIP+protocol+port.
 * In this data model, a VIP can be a whole prefix.
 * But load balancing only
 * occurs on a per-source-address/port basis. Meaning that if a given source
 * reuses the same port for multiple destinations within the same VIP,
 * they will be considered as a single flow.
 */
typedef struct {

  //Runtime

  /**
   * Vector mapping (flow-hash & new_connect_table_mask) to AS index.
   * This is used for new flows.
   */
  lb_new_flow_entry_t *new_flow_table;

  /**
   * New flows table length - 1
   * (length MUST be a power of 2)
   */
  u32 new_flow_table_mask;

  /**
   * Last time garbage collection was run to free the ASs.
   */
  u32 last_garbage_collection;

  //Not runtime
  
  /**
   * Vrf Support
   */
  u32 vrf_id;
  u32 fib_index;

  /**
   * A Virtual IP represents a given service delivered
   * by a set of application servers. It can be a single
   * address or a prefix.
   * IPv4 prefixes are encoded using IPv4-in-IPv6 embedded address
   * (i.e. ::/96 prefix).
   */
  ip46_address_t prefix;

  /**
   * The VIP prefix length.
   * In case of IPv4, plen = 96 + ip4_plen.
   */
  u8 plen;

  /* tcp or udp. If not per-port vip, set to ~0 */
  u8 protocol;

  /* tcp port or udp port. If not per-port vip, set to 0 */
  u16 port;

  /* Valid for per-port vip */
  u32 vip_prefix_index;

  /**
   * The type of traffic for this.
   * LB_TYPE_UNDEFINED if unknown.
   */
  lb_vip_type_t type;

  /* args for different vip encap types */
  lb_vip_encap_args_t encap_args;

  /* 
   * dynamic snat44 snat64 pool index
   *
   */
  u32 vip_snat_pool_index;

  /**
   * Flags related to this VIP.
   * LB_VIP_FLAGS_USED means the VIP is active.
   * When it is not set, the VIP in the process of being removed.
   * We cannot immediately remove a VIP because the VIP index still may be stored
   * in the adjacency index.
   */
  u8 flags;
#define LB_VIP_FLAGS_USED 0x1
#define LB_VIP_FLAGS_SRC_IP_STICKY 0x2
#define LB_VIP_FLAGS_IPV4_SNAT 0x4

  /**
   * Pool of AS indexes used for this VIP.
   * This also includes ASs that have been removed (but are still referenced).
   */
  u32 *as_indexes;
} lb_vip_t;

#define lb_vip_is_ip4(type) (type == LB_VIP_TYPE_IP4_GRE6 \
                            || type == LB_VIP_TYPE_IP4_GRE4 \
                            || type == LB_VIP_TYPE_IP4_L3DSR \
                            || type == LB_VIP_TYPE_IP4_NAT4 )

#define lb_vip_is_ip6(type) (type == LB_VIP_TYPE_IP6_GRE6 \
                            || type == LB_VIP_TYPE_IP6_GRE4 \
                            || type == LB_VIP_TYPE_IP6_NAT6 \
                            || type == LB_VIP_TYPE_IP6_NAT4 )

#define lb_encap_is_ip4(vip) ((vip)->type == LB_VIP_TYPE_IP6_GRE4 \
                             || (vip)->type == LB_VIP_TYPE_IP4_GRE4 \
                             || (vip)->type == LB_VIP_TYPE_IP4_L3DSR \
                             || (vip)->type == LB_VIP_TYPE_IP4_NAT4 \
                             || (vip)->type == LB_VIP_TYPE_IP6_NAT4 )

#define lb_vip_is_src_ip_sticky(vip)                                          \
  (((vip)->flags & LB_VIP_FLAGS_SRC_IP_STICKY) != 0)

#define lb_vip_is_double_nat44(vip)                                          \
  (((vip)->flags & LB_VIP_FLAGS_IPV4_SNAT) != 0)

/* clang-format off */
#define lb_vip_is_gre4(vip) (((vip)->type == LB_VIP_TYPE_IP6_GRE4 \
                            || (vip)->type == LB_VIP_TYPE_IP4_GRE4) \
                            && ((vip)->port == 0))

#define lb_vip_is_gre6(vip) (((vip)->type == LB_VIP_TYPE_IP6_GRE6 \
                            || (vip)->type == LB_VIP_TYPE_IP4_GRE6) \
                            && ((vip)->port == 0))

#define lb_vip_is_gre4_port(vip) (((vip)->type == LB_VIP_TYPE_IP6_GRE4 \
                                 || (vip)->type == LB_VIP_TYPE_IP4_GRE4) \
                                 && ((vip)->port != 0))

#define lb_vip_is_gre6_port(vip) (((vip)->type == LB_VIP_TYPE_IP6_GRE6 \
                                 || (vip)->type == LB_VIP_TYPE_IP4_GRE6) \
                                 && ((vip)->port != 0))
/* clang-format on */

always_inline bool
lb_vip_is_l3dsr(const lb_vip_t *vip)
{
  return (vip->type == LB_VIP_TYPE_IP4_L3DSR && vip->port == 0);
}

always_inline bool
lb_vip_is_l3dsr_port(const lb_vip_t *vip)
{
  return (vip->type == LB_VIP_TYPE_IP4_L3DSR && vip->port != 0);
}
always_inline bool
lb_vip_is_nat4_port(const lb_vip_t *vip)
{
  return (vip->type == LB_VIP_TYPE_IP4_NAT4 && vip->port != 0);
}
always_inline bool
lb_vip_is_nat6_port(const lb_vip_t *vip)
{
  return (vip->type == LB_VIP_TYPE_IP6_NAT6 && vip->port != 0);
}

format_function_t format_lb_vip;
format_function_t format_lb_vip_detailed;

format_function_t format_lb_snat_pool;

always_inline u32
lb_ip_proto_to_nat_proto (u8 ip_proto)
{
  u32 nat_proto = ~0;

  nat_proto = (ip_proto == IP_PROTOCOL_UDP) ? LB_NAT_PROTOCOL_UDP : nat_proto;
  nat_proto = (ip_proto == IP_PROTOCOL_TCP) ? LB_NAT_PROTOCOL_TCP : nat_proto;

  return nat_proto;
}

typedef union {
    u64 key;
    struct {
        u32 hash;
        u32 vip_index;
    };
} lb_sticky_key_t;

typedef union {
    u64 value;
    struct {
        u32 timeout;
        u32 asindex;
    };
} lb_sticky_value_t;

typedef union {
    struct {
        u64 key;
        u64 value;
    };
    struct {
        lb_sticky_key_t lb_key;
        lb_sticky_value_t lb_value;
    };
} lb_sticky_kv_t;

typedef struct
{
    u32 lb_time_now;
    u32 thread_index;
} lb_sticky_is_idle_ctx_t;

typedef struct
{
    u32 vip_index;
    u32 as_index;
} lb_sticky_is_foreach_ctx_t;

/* Key for Pod's egress SNAT */
typedef struct {
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u8 protocol;
      u32 fib_index;
    };
    u64 as_u64[2];
  };
} lb_snat4_key_t;

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t addr;
      u16 port;
      u8 protocol;
      u32 fib_index;
    };
    u64 as_u64[3];
  };
} lb_snat6_key_t;

/* Key for Pod's egress DNAT */
typedef struct {
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u8 protocol;
      u32 fib_index;
    };
    u64 as_u64[2];
  };
} lb_snat_vip_key_t;

typedef struct {
  /**
   * for vip + port case, src_ip = vip;
   * for node ip + node_port, src_ip = node_ip
   */
  ip46_address_t src_ip;
  ip46_address_t as_ip;
  u8 src_ip_is_ipv6;
  u8 as_ip_is_ipv6;
  /**
   * Network byte order
   * for vip + port case, src_port = port;
   * for node ip + node_port, src_port = node_port
   */
  u16 src_port;
  u16 target_port; /* Network byte order */

  u32 fib_index;

  /**
   * vip record
   */
  u32 vip_index;
} lb_snat_mapping_t;

typedef struct {
  /**
   * for snat-vip + port case, ip = snat-vip;
   */
  ip46_address_t ip;
  ip46_address_t outside_ip;
  u8 ip_is_ipv6;
  u8 outside_ip_is_ipv6;

  /**
   * Network byte order
   * for snat-vip + port case, port = snat-port;
   */
  u16 port;
  u16 outside_port; /* Network byte order */

  u32 fib_index;
  u32 outside_fib_index;

  u8 protocol;
  /**
   * record
   */
  u32 vip_index;
  u32 timeout;
} lb_vip_snat_mapping_t;

typedef struct {
  /**
   * Pool of all Virtual IPs
   */
  lb_vip_t *vips;

  /**
   * bitmap for vip prefix to support per-port vip
   * Due to the fact that there are two types of VIP: 
   *    For non per port, use VIP's index.
   *    For per port, use the index obtained from this request and move the highest position to 1.
   */
  uword *vip_prefix_indexes;
#define LB_VIP_PREFIX_PER_PORT_FLAG (1 << 31)

  /**
   * Pool of ASs.
   * ASs are referenced by address and vip index.
   * The first element (index 0) is special and used only to fill
   * new_flow_tables when no AS has been configured.
   */
  lb_as_t *ass;

  /**
   * Each AS has an associated reference counter.
   * As ass[0] has a special meaning, its associated counter
   * starts at 0 and is decremented instead. i.e. do not use it.
   */
  u64 *as_refcount;

  /* hash lookup vip_index by key: {u16: nodeport} */
  uword * vip_index_by_nodeport;

  /**
   * Node next index for IP adjacencies, for each of the traffic types.
   */
  u32 ip_lookup_next_index[LB_VIP_N_TYPES];

  /**
   * Source address used in IPv6 encapsulated traffic
   */
  ip6_address_t ip6_src_address;

  /**
   * Source address used for IPv4 encapsulated traffic
   */
  ip4_address_t ip4_src_address;

  /**
   * Number of buckets in the per-cpu sticky hash table.
   */
  u32 sticky_buckets;

  /* sticky hash */
  clib_bihash_8_8_t sticky_ht;

  /**
   * Flow timeout in seconds.
   */
  u32 flow_timeout;
  u32 flow_tcp_transitory_timeout;
  u32 flow_tcp_closing_timeout;

  /**
   * dynamic random seed
   */
  u32 random_seed;

  /**
   * Per VIP counter
   */
  vlib_simple_counter_main_t vip_counters[LB_N_VIP_COUNTERS];

  /**
   * DPO used to send packet from IP4/6 lookup to LB node.
   */
  dpo_type_t dpo_gre4_type;
  dpo_type_t dpo_gre6_type;
  dpo_type_t dpo_gre4_port_type;
  dpo_type_t dpo_gre6_port_type;
  dpo_type_t dpo_l3dsr_type;
  dpo_type_t dpo_l3dsr_port_type;
  dpo_type_t dpo_nat4_port_type;
  dpo_type_t dpo_nat6_port_type;
  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* lookup per_port vip by key */
  clib_bihash_16_8_t vip_index_per_port;

  /* Find a static mapping by AS IP : target_port */
  clib_bihash_16_8_t mapping_by_as4;
  clib_bihash_24_8_t mapping_by_as6;

  /* Static mapping pool : AS uplink */
  lb_snat_mapping_t * snat_mappings;

  /* Find a dynamic mapping by AS uplink DstIP : uplink port */
  clib_bihash_16_8_t mapping_by_uplink_dnat4;

  /* Find a dynamic mapping by VIP downlink SrcIP : downlink port */
  clib_bihash_16_8_t mapping_by_downlink_snat4;

  /* dynamic mapping pool : AS uplink */
  lb_vip_snat_mapping_t * vip_snat_mappings;

  /* Vip snat address pool */
  lb_vip_snat_addresses_pool_t *vip_snat_pool;

  /* lb nat interface */
  u32 *lb_enabled_nat4_by_sw_if;
  u32 *lb_enabled_nat6_by_sw_if;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;

  clib_spinlock_t writer_lock;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} lb_main_t;


u8 *format_lb_sticky_ht_kvp (u8 *s, va_list *args);
u8 *format_lb_vip_index_per_port_kvp (u8 *s, va_list *args);
u8 *format_lb_mapping_by_as4_kvp (u8 *s, va_list *args);
u8 *format_lb_mapping_by_as6_kvp (u8 *s, va_list *args);
u8 *format_lb_mapping_by_uplink_dnat4_kvp (u8 *s, va_list *args);
u8 *format_lb_mapping_by_downlink_snat4_kvp (u8 *s, va_list *args);

#define lb_vip_prefix_is_per_port(index) (index & LB_VIP_PREFIX_PER_PORT_FLAG)

/* args for different vip encap types */
typedef struct {
  u32 vrf_id;
  ip46_address_t prefix;
  u8 plen;
  u8 protocol;
  u16 port;
  u8 src_ip_sticky;
  lb_vip_type_t type;
  u32 new_length;
  lb_vip_encap_args_t encap_args;
} lb_vip_add_args_t;

extern lb_main_t lb_main;
extern vlib_node_registration_t lb4_node;
extern vlib_node_registration_t lb6_node;
extern vlib_node_registration_t lb4_nodeport_node;
extern vlib_node_registration_t lb6_nodeport_node;
extern vlib_node_registration_t lb_nat4_in2out_node;
extern vlib_node_registration_t lb_nat6_in2out_node;

/**
 * Fix global load-balancer parameters.
 * @param ip4_address IPv4 source address used for encapsulated traffic
 * @param ip6_address IPv6 source address used for encapsulated traffic
 * @param sticky_buckets FIXME
 * @param flow_timeout FIXME
 * @return 0 on success. VNET_LB_ERR_XXX on error
 */
int lb_conf(ip4_address_t *ip4_address, ip6_address_t *ip6_address,
            u32 sticky_buckets, u32 flow_timeout,
            u32 flow_tcp_transitory_timeout,
            u32 flow_tcp_closing_timeout);

int lb_vip_add(lb_vip_add_args_t args, u32 *vip_index);

int lb_vip_del(u32 vip_index);

int lb_add_snat_pool(u32 *pool_idx);

int lb_del_snat_pool(u32 pool_idx);

int lb_add_snat_pool_address(u32 pool_idx, ip4_address_t *snat_ip_address);

int lb_del_snat_pool_address(u32 pool_idx, ip4_address_t *snat_ip_address);

int lb_vip_set_snat_address_pool(u32 vip_index, u32 snat_pool_index);

int lb_vip_set_src_ip_sticky(u32 vip_index, bool src_ip_sticky);

int lb_vip_find_index(u32 vrf_id, ip46_address_t *prefix, u8 plen, u8 protocol,
                      u16 port, u32 *vip_index);

#define lb_vip_get_by_index(index) (pool_is_free_index(lb_main.vips, index)?NULL:pool_elt_at_index(lb_main.vips, index))

int lb_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n, u32 as_vrf_id);
int lb_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n, u8 flush);
int lb_flush_vip_as (u32 vip_index, u32 as_index);

u32 lb_hash_time_now(vlib_main_t * vm);

void lb_garbage_collection();

int lb_nat4_interface_add_del (u32 sw_if_index, int is_del);
int lb_nat6_interface_add_del (u32 sw_if_index, int is_del);

format_function_t format_lb_main;


#define lb_get_writer_lock() clib_spinlock_lock (&lb_main.writer_lock)
#define lb_put_writer_lock() clib_spinlock_unlock (&lb_main.writer_lock)

#define lb_get_vip_nat_address_lock(a) clib_spinlock_lock (&a->lock_self); 
#define lb_put_vip_nat_address_lock(a) clib_spinlock_unlock (&a->lock_self); 

#endif /* LB_PLUGIN_LB_LB_H_ */
