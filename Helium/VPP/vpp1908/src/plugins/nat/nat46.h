/**
 * @file
 * @brief NAT46 global declarations
 */
#ifndef __included_nat46_h__
#define __included_nat46_h__

#include <nat/nat.h>
#include <nat/nat46_db.h>

#define foreach_nat46_tcp_ses_state            \
  _(0, CLOSED, "closed")                       \
  _(1, V4_INIT, "v4-init")                     \
  _(2, V6_INIT, "v6-init")                     \
  _(3, ESTABLISHED, "established")             \
  _(4, V4_FIN_RCV, "v4-fin-rcv")               \
  _(5, V6_FIN_RCV, "v6-fin-rcv")               \
  _(6, V6_FIN_V4_FIN_RCV, "v6-fin-v4-fin-rcv") \
  _(7, TRANS, "trans")

typedef enum
{
#define _(v, N, s) NAT46_TCP_STATE_##N = v,
  foreach_nat46_tcp_ses_state
#undef _
} nat46_tcp_ses_state_t;

typedef enum
{
  NAT46_CLEANER_RESCHEDULE = 1,
} nat46_cleaner_process_event_e;


typedef struct
{
  ip6_address_t prefix;
  u8 plen;
} nat46_prefix_t;

typedef struct
{
  nat46_prefix_t addr;
  u8 no_pat;
  u32 vrf_id;
  u32 fib_index;
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  u16 * busy_##n##_ports_per_thread; \
  u8 * busy_##n##_port_used_flag; \
  u8 * port_range_workers_##n##_ports; 
  foreach_snat_protocol
#undef _

  u32 limit_user_max;
  u32 limit_user_cnt;
  nat46_db_bib_entry_t **limit_user;
/* *INDENT-ON* */
} nat46_address_t;

typedef struct
{
    u16 port_start;
    u16 port_end;
} nat46_static_bib_ctx_t;

typedef struct
{
  ip4_address_t in_addr;
  ip6_address_t out_addr;
  u16 in_port;
  u16 out_port;
  u32 fib_index;
  u32 thread_index;
  u8 proto;
  u8 is_add;
  u8 done;
} nat46_static_bib_to_update_t;

/* session key (4-tuple) */
typedef struct
{
  union
  {
    struct
    {
      ip6_address_t addr;
      ip4_address_t in_addr;
      u16 port;
      u8  protocol;
      u8 rsvd;
    };
    u64 as_u64[3];
  };
} nat46_session_key_t;

/* NAT46 address and port allacotaion function */
typedef int (nat46_alloc_out_addr_and_port_function_t) (nat46_address_t *
						      addresses,
						      u32 fib_index,
						      u32 thread_index,
						      nat46_session_key_t * k,
						      u16 port_per_thread,
						      u32 snat_thread_index);



typedef struct
{
  /** Interface pool */
  snat_interface_t *interfaces;

  /** Address pool vector */
  nat46_address_t *addr_pool;

  /** sw_if_indices whose interface addresses should be auto-added */
  u32 *auto_add_sw_if_indices;

  /** BIB and session DB per thread */
  nat46_db_t *db;

  /** DB global dynamic no pat **/
  nat46_db_dynamic_no_pat_t dnop;

  /* remote ip4 mapping ip6*/
  nat46_db_remote_mapping_t remote_mapping;

  /* Address and port allocation function */
  nat46_alloc_out_addr_and_port_function_t *alloc_addr_and_port;

  /** Worker handoff */
  u32 fq_in2out_index;
  u32 fq_out2in_index;

  /** Pool of static BIB entries to be added/deleted in worker threads */
  nat46_static_bib_to_update_t *static_bibs;

  /** config parameters */
  u32 max_translations;
  u32 bib_buckets;
  u32 bib_memory_size;
  u32 st_buckets;
  u32 st_memory_size;
  u32 no_pat_buckets;
  u32 no_pat_memory_size;
  u32 remote_map_buckets; 
  u32 remote_map_memory_size;

  /** values of various timeouts */
  u32 udp_timeout;
  u32 icmp_timeout;
  u32 tcp_trans_timeout;
  u32 tcp_est_timeout;

  /* Total count of interfaces enabled */
  u32 total_enabled_count;
  /* The process node which orcherstrates the cleanup */
  u32 nat46_expire_walk_node_index;
  f64 nat46_expire_walk_interval;

  /* counters/gauges */
  vlib_simple_counter_main_t total_bibs;
  vlib_simple_counter_main_t total_sessions;

  /** node index **/
  u32 error_node_index;

  u32 in2out_node_index;
  u32 in2out_slowpath_node_index;
  u32 in2out_reass_node_index;

  u32 out2in_node_index;
  u32 out2in_reass_node_index;

  ip4_main_t *ip4_main;
  ip6_main_t *ip6_main;
  snat_main_t *sm;
} nat46_main_t;

extern nat46_main_t nat46_main;
extern vlib_node_registration_t nat46_in2out_node;
extern vlib_node_registration_t nat46_out2in_node;
extern vlib_node_registration_t nat46_expire_worker_walk_node;

/**
 * @brief Increment IPv6 address
 */
void nat46_increment_v6_address (ip6_address_t * a);

/**
 * @brief Add/delete address to NAT46 pool.
 *
 * @param addr   IPv6 address.
 * @param p_len   IPv6 address mask.
 * @param sw_if_index Index of the interface.
 * @param is_add      1 if add, 0 if delete.
 *
 */
void
nat46_add_del_addr_to_fib (ip6_address_t * addr, u8 p_len, u32 sw_if_index, int is_add);

/**
 * @brief Add/delete address to NAT46 pool.
 *
 * @param thread_index Thread index used by ipfix nat logging (not address per thread).
 * @param addr   IPv6 address.
 * @param vrf_id VRF id of tenant, ~0 means independent of VRF.
 * @param is_add 1 if add, 0 if delete.
 * @param no_pat 1 if no pat 1, 0 if pat.
 * @param limit_ip_cnt !=~0 if limit, ~0 if no limit.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_del_pool_addr (u32 thread_index,
			     ip6_address_t * addr, u32 vrf_id, u8 is_add, u8 no_pat, u32 limit_ip_cnt);

/**
 * @brief Call back function when walking addresses in NAT46 pool, non-zero
 * return value stop walk.
 */
typedef int (*nat46_pool_addr_walk_fn_t) (nat46_address_t * addr, void *ctx);

/**
 * @brief Walk NAT46 pool.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat46_pool_addr_walk (nat46_pool_addr_walk_fn_t fn, void *ctx);

/**
 * @brief NAT46 pool address from specific (DHCP addressed) interface.
 *
 * @param sw_if_index Index of the interface.
 * @param is_add      1 if add, 0 if delete.
 * @param no_pat 1 if no pat 1, 0 if pat.
 * @param limit_ip_cnt !=~0 if limit, ~0 if no limit.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_interface_address (u32 sw_if_index, int is_add, u8 no_pat, u32 limit_ip_cnt);

/**
 * @brief Enable/disable NAT46 feature on the interface.
 *
 * @param sw_if_index Index of the interface.
 * @param is_inside   1 if inside, 0 if outside.
 * @param is_add      1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_del_interface (u32 sw_if_index, u8 is_inside, u8 is_add);

/**
 * @brief Call back function when walking interfaces with NAT46 feature,
 * non-zero return value stop walk.
 */
typedef int (*nat46_interface_walk_fn_t) (snat_interface_t * i, void *ctx);

/**
 * @brief Walk NAT46 interfaces.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat46_interfaces_walk (nat46_interface_walk_fn_t fn, void *ctx);

/**
 * @brief Initialize NAT46.
 *
 * @param vm vlib main.
 *
 * @return error code.
 */
clib_error_t *nat46_init (vlib_main_t * vm);

/**
 * @brief Add/delete NAT46 remote mapping.
 *
 * @param laddr  Inside dip IPv4 address.
 * @param raddr  Outside dip IPv6 address.
 * @param proto    L4 protocol.
 * @param vrf_id   VRF id of tenant.
 * @param is_add   1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_remote_mapping_entry(ip4_address_t * laddr,
				ip6_address_t * raddr, u8 proto, u32 vrf_id, u8 is_add);

/**
 * @brief Add/delete static NAT46 BIB entry.
 *
 * @param in_addr  Inside IPv4 address.
 * @param out_addr Outside IPv6 address.
 * @param in_port  Inside port number.
 * @param out_port Outside port number.
 * @param proto    L4 protocol.
 * @param vrf_id   VRF id of tenant.
 * @param is_add   1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_del_static_bib_entry (ip4_address_t * in_addr,
				    ip6_address_t * out_addr, u16 in_port,
				    u16 out_port, u8 proto, u32 vrf_id,
				    u8 is_add, nat46_static_bib_ctx_t *ctx);

int
nat46_alloc_addr_and_port_default (nat46_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 nat46_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index);
int
nat46_alloc_addr_and_port_range (nat46_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 nat46_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index);
int
nat46_alloc_addr_and_port_mape (nat46_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 nat46_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index);
/**
 * @brief Alloce IPv4 address and port pair from NAT46 pool.
 *
 * @param fib_index    FIB index of tenant.
 * @param proto        L4 protocol.
 * @param in_addr      raw IPv4 address.
 * @param in_port      raw port number.
 * @param addr         Allocated IPv6 address.
 * @param port         Allocated port number.
 * @param thread_index Thread index.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_alloc_out_addr_and_port (u32 fib_index, snat_protocol_t proto,
				   ip4_address_t *in_addr, u16 in_port, 
                   ip6_address_t * addr, u16 * port, 
                   u8 *no_pat, u32 thread_index);

/**
 * @brief Set UDP session timeout.
 *
 * @param timeout Timeout value in seconds (if 0 reset to default value 300sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_set_udp_timeout (u32 timeout);

/**
 * @brief Get UDP session timeout.
 *
 * @returns UDP session timeout in seconds.
 */
u32 nat46_get_udp_timeout (void);

/**
 * @brief Set ICMP session timeout.
 *
 * @param timeout Timeout value in seconds (if 0 reset to default value 60sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_set_icmp_timeout (u32 timeout);

/**
 * @brief Get ICMP session timeout.
 *
 * @returns ICMP session timeout in seconds.
 */
u32 nat46_get_icmp_timeout (void);

/**
 * @brief Set TCP session timeouts.
 *
 * @param trans Transitory timeout in seconds (if 0 reset to default value 240sec).
 * @param est Established timeout in seconds (if 0 reset to default value 7440sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_set_tcp_timeouts (u32 trans, u32 est);

/**
 * @brief Get TCP transitory timeout.
 *
 * @returns TCP transitory timeout in seconds.
 */
u32 nat46_get_tcp_trans_timeout (void);

/**
 * @brief Get TCP established timeout.
 *
 * @returns TCP established timeout in seconds.
 */
u32 nat46_get_tcp_est_timeout (void);

/**
 * @brief Reset NAT46 session timeout.
 *
 * @param ste Session table entry.
 * @param vm VLIB main.
 **/
void nat46_session_reset_timeout (nat46_db_st_entry_t * ste,
				  vlib_main_t * vm);

/**
 * @brief Set NAT46 TCP session state.
 *
 * @param ste Session table entry.
 * @param tcp TCP header.
 * @param is_ip6 1 if IPv6 packet, 0 if IPv4.
 */
void nat46_tcp_session_set_state (nat46_db_st_entry_t * ste,
				  tcp_header_t * tcp, u8 is_ip6);

/**
 * @brief Add/delete NAT46 prefix.
 *
 * @param thread_index Thread index used by ipfix nat logging (not address per thread).
 * @param prefix NAT46 prefix.
 * @param plen Prefix length.
 * @param vrf_id VRF id of tenant.
 * @param is_add 1 if add, 0 if delete.
 * @param no_pat 1 if no pat 1, 0 if pat.
 * @param limit_ip_cnt !=~0 if limit, ~0 if no limit.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat46_add_del_pool_prefix (u32 thread_index, ip6_address_t * prefix, u8 plen, u32 vrf_id,
			  u8 is_add, u8 no_pat, u32 limit_ip_cnt);

/**
 * Compose IPv4-embedded IPv6 addresses.
 * @param ip6 IPv4-embedded IPv6 addresses.
 * @param ip4 IPv4 address.
 * @param plen ip6 prefix len.
 */
void nat46_compose_ip6 (ip6_address_t * ip6, ip4_address_t * ip4, u32 plen);

/**
 * @brief Set NAT46 hash tables configuration.
 *
 * @param max_st_per_worker nat46 st max limit.
 * @param bib_buckets Number of BIB hash buckets.
 * @param bib_memory_size Memory size of BIB hash.
 * @param st_buckets Number of session table hash buckets.
 * @param st_memory_size Memory size of session table hash.
 * @param no_pat_buckets Number of nopat table hash buckets.
 * @param no_pat_memory_size Memory size of nopat table hash.
 * @param remote_map_buckets Number of remote mapping table hash buckets.
 * @param remote_map_memory_size Memory size of remote mapping table hash.
 */
void nat46_set_hash (u32 max_st_per_worker, u32 bib_buckets, u32 bib_memory_size, 
        u32 st_buckets, u32 st_memory_size, 
        u32 no_pat_buckets, u32 no_pat_memory_size,
        u32 remote_map_buckets, u32 remote_map_memory_size);

/**
 * @brief Get worker thread index for NAT46 in2out.
 *
 * @param addr IPv4 src address.
 *
 * @returns worker thread index.
 */
u32 nat46_get_worker_in2out (ip4_address_t * addr);

/**
 * @brief Get worker thread index for NAT46 out2in.
 *
 * @param ip IPv6 header.
 * @param fib_index   rx fib index.
 *
 * @returns worker thread index.
 */
u32 nat46_get_worker_out2in (ip6_header_t * ip, u32 fib_index);

#endif /* __included_nat46_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
