/*
 * cgnat.h - CGNAT plugin definitions
 *
 * Copyright (c) 2026 Asterfusion.
 * Licensed under the Apache License, Version 2.0.
 */

#ifndef __included_cgnat_h__
#define __included_cgnat_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/api_errno.h>
#include <vlibapi/api.h>
#include <vlib/log.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#define CGNAT_INVALID_INDEX ((u32) ~0)
#define CGNAT_DEFAULT_START_PORT 1024
#define CGNAT_DEFAULT_END_PORT 65535
#define CGNAT_DEFAULT_BLOCK_SIZE 2048
#define CGNAT_DEFAULT_PREALLOC_BLOCKS 1
#define CGNAT_DEFAULT_COOLING_TIME 120
#define CGNAT_DEFAULT_MAX_USER_BLOCKS 8
#define CGNAT_DEFAULT_MAX_USER_PORTS 2048
#define CGNAT_DEFAULT_TCP_MSS 0
#define CGNAT_DEFAULT_UTIL_THRESHOLD 80
#define CGNAT_MAPPING_HASH_BUCKETS (64 * 1024)
#define CGNAT_MAPPING_HASH_MEMORY (256 << 20)
#define CGNAT_SESSION_HASH_BUCKETS (128 * 1024)
#define CGNAT_SESSION_HASH_MEMORY (512 << 20)
#define CGNAT_STATIC_RULE_HASH_BUCKETS (64 * 1024)
#define CGNAT_STATIC_RULE_HASH_MEMORY (64 << 20)
#define CGNAT_ADF_REMOTE_HASH_BUCKETS (128 * 1024)
#define CGNAT_ADF_REMOTE_HASH_MEMORY (128 << 20)
#define CGNAT_TCP_SYN_TIMEOUT 75
#define CGNAT_TCP_ESTABLISHED_TIMEOUT 7440
#define CGNAT_TCP_FIN_RST_TIMEOUT 60
#define CGNAT_UDP_TIMEOUT 60
#define CGNAT_ICMP_TIMEOUT 60
#define CGNAT_OTHER_TIMEOUT 60
#define CGNAT_TIMER_MAX_DELAY 2047
#define CGNAT_SESSION_TIMER_MAX_EXPIRATIONS 1024
#define CGNAT_COOLING_TIMER_MAX_EXPIRATIONS 1024
#define CGNAT_LOG_QUEUE_SIZE (64 * 1024)
#define CGNAT_LOG_POLL_INTERVAL_DEFAULT 0.1
#define CGNAT_LOG_EVENT_STR_LEN 24
#define CGNAT_LOG_REASON_STR_LEN 32
#define CGNAT_LOG_INSTANCE_LABEL_LEN 64
#define CGNAT_MAX_INSTANCE_POOLS 16
#define CGNAT_MAX_INSIDE_ADDRESSES 16
#define CGNAT_MAX_PUBLIC_IPS_PER_POOL 65536
#define CGNAT_USER_LOCK_BUCKETS 128
#define CGNAT_MAPPING_TABLE_LOCK_BUCKETS 128
#define CGNAT_SESSION_TABLE_LOCK_BUCKETS 256
#define CGNAT_ADF_REMOTE_LOCK_BUCKETS 256

/* PBA allocates public ports independently per protocol. */
#define CGNAT_PBA_PROTO_TCP   0
#define CGNAT_PBA_PROTO_UDP   1
#define CGNAT_PBA_PROTO_ICMP  2
#define CGNAT_PBA_PROTO_COUNT 3

typedef enum
{
  CGNAT_FILTER_MODE_EIF = 0,
  CGNAT_FILTER_MODE_ADF = 1,
  CGNAT_FILTER_MODE_ADPF = 2,
} cgnat_filter_mode_t;

typedef enum
{
  CGNAT_TCP_SYN = 0,
  CGNAT_TCP_ESTABLISHED,
  CGNAT_TCP_FIN_RST,
  CGNAT_TCP_CLOSED,
} cgnat_tcp_state_t;

typedef enum
{
  CGNAT_INTERFACE_FLAG_IS_INSIDE = 1,
  CGNAT_INTERFACE_FLAG_IS_OUTSIDE = 2,
} cgnat_interface_flags_t;

typedef enum
{
  CGNAT_BLOCK_ALLOC_MODE_ON_DEMAND = 0,
  CGNAT_BLOCK_ALLOC_MODE_PRE_ALLOC = 1,
} cgnat_block_alloc_mode_t;

typedef enum
{
  /* Default mode: randomize the port offset inside the selected block. */
  CGNAT_PORT_ALLOC_MODE_RANDOM = 0,
  CGNAT_PORT_ALLOC_MODE_SEQUENCE = 1,
} cgnat_port_alloc_mode_t;

typedef enum
{
  CGNAT_BLOCK_ALLOCATED = 1,
  CGNAT_BLOCK_COOLING,
} cgnat_block_state_t;

typedef enum
{
  CGNAT_MAPPING_FLAG_DELETING = 1,
} cgnat_mapping_flags_t;

typedef enum
{
  CGNAT_MAPPING_DYNAMIC = 0,
  CGNAT_MAPPING_STATIC = 1,
  CGNAT_MAPPING_DETERMINISTIC = 2,
} cgnat_mapping_type_t;

typedef enum
{
  CGNAT_LOG_MODE_PORT_BLOCK = 0,
  CGNAT_LOG_MODE_SESSION = 1,
} cgnat_log_mode_t;

typedef enum
{
  CGNAT_LOG_EVENT_KIND_PBA_BLOCK = 0,
  CGNAT_LOG_EVENT_KIND_SESSION = 1,
} cgnat_log_event_kind_t;

typedef struct
{
  u8 kind;
  u8 event[CGNAT_LOG_EVENT_STR_LEN];
  u8 reason[CGNAT_LOG_REASON_STR_LEN];
  u8 instance_label[CGNAT_LOG_INSTANCE_LABEL_LEN];
  u32 instance_id;

  union
  {
    struct
    {
      ip4_address_t private_ip;
      ip4_address_t public_ip;
    } block;

    struct
    {
      ip4_address_t private_ip;
      ip4_address_t public_ip;
      ip4_address_t remote_ip;
      u16 private_port;
      u16 public_port;
      u16 remote_port;
      u8 protocol;
      u8 mapping_type;
    } session;
  };
} cgnat_log_event_t;

typedef struct
{
  cgnat_log_event_t *events;
  u32 size;
  u32 mask;
  u64 head;
  u64 tail;
  u64 enqueued;
  u64 sent;
  u64 full;
  u64 direct;
  u64 max_used;
} cgnat_log_queue_t;

typedef enum
{
  CGNAT_INSTANCE_MODE_DYNAMIC = 0,
  CGNAT_INSTANCE_MODE_DETERMINISTIC = 1,
} cgnat_instance_mode_t;

typedef enum
{
  CGNAT_INSIDE_ADDRESS_RANGE = 0,
  CGNAT_INSIDE_ADDRESS_PREFIX = 1,
} cgnat_inside_address_type_t;

typedef enum
{
  CGNAT_INSTANCE_SET_FILTER_MODE = (1ULL << 0),
  CGNAT_INSTANCE_SET_HAIRPINNING = (1ULL << 1),
  CGNAT_INSTANCE_SET_MAX_USER_BLOCKS = (1ULL << 2),
  CGNAT_INSTANCE_SET_MAX_USER_PORTS = (1ULL << 3),
  CGNAT_INSTANCE_SET_MAX_USER_SESSIONS = (1ULL << 4),
  CGNAT_INSTANCE_SET_MAX_USER_CREATE_RATE = (1ULL << 5),
  CGNAT_INSTANCE_SET_AGING_TCP_SYN = (1ULL << 6),
  CGNAT_INSTANCE_SET_AGING_TCP_ESTABLISHED = (1ULL << 7),
  CGNAT_INSTANCE_SET_AGING_TCP_FIN_RST = (1ULL << 8),
  CGNAT_INSTANCE_SET_AGING_UDP = (1ULL << 9),
  CGNAT_INSTANCE_SET_AGING_ICMP = (1ULL << 10),
  CGNAT_INSTANCE_SET_AGING_OTHER = (1ULL << 11),
  CGNAT_INSTANCE_SET_LOG_MODE = (1ULL << 12),
  CGNAT_INSTANCE_SET_SYSLOG = (1ULL << 13),
  CGNAT_INSTANCE_SET_IPFIX = (1ULL << 14),
  CGNAT_INSTANCE_SET_TCP_MSS = (1ULL << 15),
} cgnat_instance_set_flags_t;

#define CGNAT_INSTANCE_SET_VALID_FLAGS                                       \
  (CGNAT_INSTANCE_SET_FILTER_MODE | CGNAT_INSTANCE_SET_HAIRPINNING |         \
   CGNAT_INSTANCE_SET_MAX_USER_BLOCKS | CGNAT_INSTANCE_SET_MAX_USER_PORTS |  \
   CGNAT_INSTANCE_SET_MAX_USER_SESSIONS |                                    \
   CGNAT_INSTANCE_SET_MAX_USER_CREATE_RATE |                                 \
   CGNAT_INSTANCE_SET_AGING_TCP_SYN |                                        \
   CGNAT_INSTANCE_SET_AGING_TCP_ESTABLISHED |                                \
   CGNAT_INSTANCE_SET_AGING_TCP_FIN_RST | CGNAT_INSTANCE_SET_AGING_UDP |     \
   CGNAT_INSTANCE_SET_AGING_ICMP | CGNAT_INSTANCE_SET_AGING_OTHER |          \
   CGNAT_INSTANCE_SET_LOG_MODE | CGNAT_INSTANCE_SET_SYSLOG |                 \
   CGNAT_INSTANCE_SET_IPFIX | CGNAT_INSTANCE_SET_TCP_MSS)

typedef enum
{
  /* Address only: 1:1 IP mapping covering all protocols. */
  CGNAT_STATIC_ADDR_MAP = 0,
  /* Address + protocol: all ports of one protocol. */
  CGNAT_STATIC_ADDR_PROTO_MAP = 1,
  /* Address + protocol + port. */
  CGNAT_STATIC_PORT_MAP = 2,
} cgnat_static_type_t;

typedef enum
{
  CGNAT_STATIC_PROTO_TCP = IP_PROTOCOL_TCP,
  CGNAT_STATIC_PROTO_UDP = IP_PROTOCOL_UDP,
  CGNAT_STATIC_PROTO_ICMP = IP_PROTOCOL_ICMP,
  CGNAT_STATIC_PROTO_ALL = 0xff,
} cgnat_static_proto_t;

typedef enum
{
  CGNAT_SESSION_FLAG_SEEN_IN2OUT = 1,
  CGNAT_SESSION_FLAG_SEEN_OUT2IN = 2,
  CGNAT_SESSION_FLAG_DELETING = 4,
  CGNAT_SESSION_FLAG_ADF_REMOTE_RECORDED = 8,
} cgnat_session_flags_t;

typedef struct
{
  u16 block_id;
  cgnat_block_state_t state;

  /* Active port allocations per protocol (TCP/UDP/ICMP). */
  u16 active_ports[CGNAT_PBA_PROTO_COUNT];
  u32 owner_user_index;
  u32 gen_id;

  /*
   * Present only while the block is allocated; bit 1 means the port offset is
   * free. First dimension indexes protocol (TCP/UDP/ICMP), second stores
   * even/odd offsets.
   */
  clib_bitmap_t *free_port_bitmap[CGNAT_PBA_PROTO_COUNT][2];
} cgnat_block_t;

typedef struct
{
  ip4_address_t addr;

  u16 total_blocks;
  /* ALLOCATED only. COOLING is tracked separately and is not reusable. */
  u16 allocated_blocks;
  u16 cooling_blocks;
  /* Updated atomically: user deletion paths do not always hold ip->lock. */
  u32 active_users;

  clib_spinlock_t lock;

  /* 1 means the block is immediately available for allocation. */
  clib_bitmap_t *free_block_bitmap;

  /* block_id -> cgnat_block_t pool index; free blocks keep ~0 here. */
  u32 *block_index_by_id;

  /* Contains only ALLOCATED and COOLING blocks. FREE has no structure. */
  cgnat_block_t *blocks;
} cgnat_public_ip_t;

typedef struct
{
  u32 fib_index;
  ip4_address_t private_ip;
} cgnat_user_key_t;

typedef struct
{
  u8 type;
  ip4_address_t first_ip;
  ip4_address_t last_ip;
  u8 prefix_len;
} cgnat_inside_address_t;

typedef struct
{
  cgnat_user_key_t key;

  u32 instance_index;
  u32 pool_index;
  u32 public_ip_index;

  /* Active port allocations per protocol (TCP/UDP/ICMP). */
  u16 active_ports[CGNAT_PBA_PROTO_COUNT];

  u16 max_blocks;
  /* Per-protocol limit on active port allocations. */
  u16 max_ports;
  cgnat_block_alloc_mode_t block_alloc_mode;
  /* Owned blocks include both ALLOCATED and user-revivable COOLING blocks. */
  u16 *owned_block_ids;

  /* Deterministic NAT only: per-protocol port bitmap within the host's
   * ports_per_host range. */
  clib_bitmap_t *det_port_bitmap[CGNAT_PBA_PROTO_COUNT];

  clib_spinlock_t session_lock;
  u32 active_sessions;
  f64 session_rate_window_start;
  u32 session_rate_count;
  u32 session_limit_drops;
  u32 session_rate_drops;
  u32 session_lock_drops;
  u32 port_block_drops;
} cgnat_user_t;

typedef struct
{
  ip4_address_t public_ip;
  u16 public_port;

  u32 pool_index;
  u32 public_ip_index;
  u32 user_index;
  u32 block_index;
} cgnat_pba_alloc_result_t;

typedef struct
{
  u32 instance_id;
  u32 pool_id;
  ip4_address_t public_ip;
  u32 total_blocks;
  u32 allocated_blocks;
  u32 free_blocks;
  u32 cooling_blocks;
  u32 active_users;
} cgnat_block_ip_summary_t;

typedef struct
{
  u32 instance_id;
  u32 inside_fib_index;
  u32 pool_id;
  ip4_address_t inside_ip;
  ip4_address_t public_ip;
  u32 owned_blocks;
  /* User-visible allocated means the block currently has active ports. */
  u32 allocated_blocks;
  /* Reserved to this user, but all ports are currently available. */
  u32 free_blocks;
  u32 cooling_blocks;
  /* Active port allocations per protocol (TCP/UDP/ICMP). */
  u32 active_ports[CGNAT_PBA_PROTO_COUNT];
} cgnat_block_user_summary_t;

typedef struct
{
  u32 instance_id;
  u32 inside_fib_index;
  u32 pool_id;
  ip4_address_t public_ip;
  ip4_address_t inside_ip;
  u16 block_id;
  u16 start_port;
  u16 end_port;
  /* Active port allocations per protocol (TCP/UDP/ICMP). */
  u16 active_ports[CGNAT_PBA_PROTO_COUNT];
  u8 state;
  u8 owner_valid;
} cgnat_block_public_detail_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 generation;
  u32 active_sessions;
  clib_spinlock_t lock;

  ip4_address_t inside_ip;
  ip4_address_t nat_ip;
  u16 inside_port;
  u16 nat_port;
  u8 protocol;
  u8 filter_mode;
  u8 mapping_type;
  u8 flags;

  u32 instance_index;
  u32 inside_fib_index;
  u32 outside_fib_index;

  u32 pool_index;
  u32 public_ip_index;
  u32 user_index;
  u32 block_index;
  u32 static_rule_index;
} cgnat_mapping_t;

STATIC_ASSERT_SIZEOF (cgnat_mapping_t, 64);

static_always_inline u8
cgnat_mapping_is_auto (cgnat_mapping_t *mapping)
{
  return mapping->mapping_type == CGNAT_MAPPING_DYNAMIC ||
	 mapping->mapping_type == CGNAT_MAPPING_DETERMINISTIC;
}

typedef struct
{
  u32 generation;
  u32 refcnt;
  clib_bihash_kv_24_8_t kv;
} cgnat_adf_remote_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u32 generation;
  u32 mapping_index;
  u32 mapping_generation;

  ip4_address_t inside_ip;
  ip4_address_t remote_ip;
  ip4_address_t nat_ip;
  u16 inside_port;
  u16 remote_port;
  u16 nat_port;

  u32 instance_index;
  u32 inside_fib_index;

  u8 protocol;
  u8 tcp_state;
  u8 flags;
  u8 mapping_type;
  u32 timer_gen_id;
  clib_spinlock_t lock;

  f64 last_active;
} cgnat_session_t;

typedef enum
{
  CGNAT_SESSION_FILTER_INSIDE_IP = (1 << 0),
  CGNAT_SESSION_FILTER_INSIDE_PORT = (1 << 1),
  CGNAT_SESSION_FILTER_PUBLIC_IP = (1 << 2),
  CGNAT_SESSION_FILTER_PUBLIC_PORT = (1 << 3),
  CGNAT_SESSION_FILTER_PROTOCOL = (1 << 4),
} cgnat_session_filter_flags_t;

typedef struct
{
  u32 flags;
  ip4_address_t inside_ip;
  ip4_address_t public_ip;
  u16 inside_port;
  u16 public_port;
  u8 protocol;
} cgnat_session_filter_t;

typedef struct
{
  u8 type;
  u8 protocol;
  u8 flags;
  u8 pad;

  ip4_address_t outside_ip;
  ip4_address_t inside_ip;
  u16 outside_port;
  u16 inside_port;

  u32 instance_index;
  u32 inside_fib_index;
  u32 outside_fib_index;

  clib_spinlock_t lock;
  u32 exact_mapping_index;
  u32 *exact_mapping_indices;
} cgnat_static_rule_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} cgnat_interface_t;

typedef struct
{
  ip4_address_t address;
  u16 port;
} cgnat_syslog_server_t;

typedef struct
{
  ip4_address_t collector_address;
  ip4_address_t src_address;
  u16 collector_port;
  u16 src_port;
} cgnat_ipfix_exporter_t;

typedef struct
{
  u32 pool_id;
  /* Optional operator-provided alias, used in show output. */
  u8 label[64];
  u32 owner_instance_index;
  u8 configured;
  ip4_address_t first_ip;
  ip4_address_t last_ip;
  u16 start_port;
  u16 end_port;
  u16 exclude_start_port;
  u16 exclude_end_port;
  u16 block_size;
  u16 prealloc_blocks_per_user;
  u16 cooling_time;
  cgnat_block_alloc_mode_t block_alloc_mode;
  cgnat_port_alloc_mode_t port_alloc_mode;

  cgnat_public_ip_t *public_ips;
  clib_bitmap_t *free_port_offset_bitmap[2];

  u32 total_blocks;
  u32 allocated_blocks;
  u32 cooling_blocks;
  u32 active_users;
  u32 active_sessions;
} cgnat_pool_t;

typedef struct
{
  /* Total deterministic outside addresses across all pools of this instance. */
  u32 outside_count;
  /* Total inside addresses (single contiguous prefix/range). */
  u32 inside_count;
  /* ceil(inside_count / outside_count). */
  u32 sharing_ratio;
  /* Ports allocated per inside host. */
  u32 ports_per_host;

  u16 usable_port_start;
  u16 usable_port_end;
  u16 usable_port_count;

  /* First inside IP (network byte order host address). */
  u32 inside_first_host;
} cgnat_det_runtime_t;

typedef struct
{
  u32 instance_id;
  u8 configured;
  /* Optional operator-provided alias, used in logs and show output. */
  u8 label[64];
  u32 inside_fib_index;
  u32 outside_fib_index;
  u8 mode;
  cgnat_inside_address_t *inside_addresses;
  u32 *acl_indices;
  cgnat_syslog_server_t *syslog_servers;
  cgnat_ipfix_exporter_t *ipfix_exporters;
  u8 filter_mode;
  u8 hairpinning_enabled;
  u8 log_mode;
  u8 syslog_enabled;
  u8 ipfix_enabled;
  /* 0 = no TCP MSS clamping; non-zero clamps SYN MSS option to this value. */
  u16 tcp_mss;
  clib_spinlock_t user_locks[CGNAT_USER_LOCK_BUCKETS];
  clib_spinlock_t random_lock;
  u32 random_seed;

  u16 per_user_max_blocks;
  u16 per_user_max_ports;
  u32 max_sessions_per_user;
  u32 max_session_create_rate;

  /* Global pool indices. Configuration updates run under a worker barrier. */
  u32 *pool_indices;

  u32 tcp_syn_timeout;
  u32 tcp_established_timeout;
  u32 tcp_fin_rst_timeout;
  u32 udp_timeout;
  u32 icmp_timeout;
  u32 other_timeout;

  u32 total_blocks;
  u32 allocated_blocks;
  u32 cooling_blocks;
  u32 active_users;
  u32 active_sessions;

  cgnat_user_t *users;
  uword *user_index_by_key;

  cgnat_static_rule_t *static_rules;

  /* Valid when mode == CGNAT_INSTANCE_MODE_DETERMINISTIC. */
  cgnat_det_runtime_t det;
} cgnat_instance_t;

typedef struct
{
  u32 instance_index;
  u32 pool_index;
  u32 public_ip_index;
  u32 block_index;
  u32 gen_id;
  u32 inside_fib_index;
  ip4_address_t private_ip;
  u16 block_id;
  u16 remaining_time;
} cgnat_cooling_timer_t;

typedef struct
{
  u32 session_index;
  u32 session_generation;
  u32 timer_gen_id;
} cgnat_session_timer_t;

typedef struct
{
  ip4_address_t addr;
  u32 sw_if_index;
  u32 count;
} cgnat_fib_entry_reg_t;

typedef struct
{
  u8 enabled;

  cgnat_interface_t *interfaces;
  u32 *interface_index_by_sw_if_index;

  cgnat_instance_t *instances;
  uword *instance_index_by_id;
  /* acl_index -> instance_index; one ACL steers into exactly one instance. */
  u32 *instance_index_by_acl;
  cgnat_pool_t *pools;
  uword *pool_index_by_id;

  clib_bihash_16_8_t in2out_mapping_table;
  clib_bihash_16_8_t out2in_mapping_table;
  clib_bihash_16_8_t static_addr_in2out_table;
  clib_bihash_16_8_t static_addr_out2in_table;
  clib_bihash_24_8_t static_rule_table;
  clib_bihash_24_8_t session_table;
  clib_bihash_24_8_t adf_remote_table;
  u8 session_tables_initialized;

  cgnat_mapping_t *mappings;
  cgnat_session_t *sessions;
  cgnat_adf_remote_t *adf_remotes;
  u32 *mapping_generation_by_index;
  u32 *session_generation_by_index;
  u32 *adf_remote_generation_by_index;

  /* Active session counters maintained atomically (data plane hot path). */
  u32 active_sessions_tcp;
  u32 active_sessions_udp;
  u32 active_sessions_icmp;
  u32 active_sessions_total;
  clib_spinlock_t mapping_table_locks[CGNAT_MAPPING_TABLE_LOCK_BUCKETS];
  clib_spinlock_t session_table_locks[CGNAT_SESSION_TABLE_LOCK_BUCKETS];
  clib_spinlock_t adf_remote_locks[CGNAT_ADF_REMOTE_LOCK_BUCKETS];
  clib_spinlock_t mapping_pool_lock;
  clib_spinlock_t adf_remote_pool_lock;
  clib_spinlock_t mapping_reap_lock;
  u64 *mapping_reap_queue;
  u64 *mapping_reap_quarantine;
  clib_spinlock_t session_pool_lock;

  tw_timer_wheel_2t_1w_2048sl_t cooling_timer_wheel;
  cgnat_cooling_timer_t *cooling_timers;
  u8 cooling_timer_initialized;

  tw_timer_wheel_2t_1w_2048sl_t session_timer_wheel;
  cgnat_session_timer_t *session_timers;
  u8 session_timer_initialized;
  clib_spinlock_t session_timer_lock;

  u32 in2out_policy_node_index;
  u32 in2out_node_index;
  u32 out2in_node_index;

  u16 msg_id_base;
  vlib_log_class_t log_class_dynamic;
  vlib_log_class_t log_class_deterministic;
  cgnat_log_queue_t *log_queues;
  f64 log_poll_interval;

  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *ip4_main;

  /* FIB receive entries for pool public IPs, so VPP answers ARP on the
   * outside interface(s) without requiring proxy-ARP. */
  cgnat_fib_entry_reg_t *fib_entry_reg;
  fib_source_t fib_src;
} cgnat_main_t;

typedef struct
{
  u8 label[64];
  ip4_address_t first_ip;
  ip4_address_t last_ip;
  u16 block_size;
  u16 reserved_port_start;
  u16 reserved_port_end;
  u16 prealloc_blocks_per_user;
  u16 cooling_time;
  u8 block_alloc_mode;
  u8 port_alloc_mode;
} cgnat_pool_config_t;

typedef struct
{
  u64 flags;
  u32 max_user_sessions;
  u32 max_user_create_sessions_rate;
  u32 aging_tcp_syn;
  u32 aging_tcp_established;
  u32 aging_tcp_fin_rst;
  u32 aging_udp;
  u32 aging_icmp;
  u32 aging_other;
  u16 max_user_blocks;
  u16 max_user_ports;
  u8 filter_mode;
  u8 hairpinning_enabled;
  u8 log_mode;
  u8 syslog_enabled;
  u8 ipfix_enabled;
  u16 tcp_mss;
} cgnat_instance_config_t;

extern cgnat_main_t cgnat_main;

u8 *format_cgnat_instance_name (u8 *s, va_list *args);
void cgnat_log_init (cgnat_main_t *cm);
void cgnat_log_enqueue (cgnat_log_event_t *event);
void cgnat_log_emit (cgnat_log_event_t *event);
void cgnat_log_event_set_common (cgnat_log_event_t *event,
				 cgnat_instance_t *instance, char *event_name,
				 char *reason);

#define cgnat_log_err(...)                                                    \
  vlib_log (VLIB_LOG_LEVEL_ERR, cgnat_main.log_class_dynamic, __VA_ARGS__)
#define cgnat_log_warn(...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cgnat_main.log_class_dynamic, __VA_ARGS__)
#define cgnat_log_notice(...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cgnat_main.log_class_dynamic, __VA_ARGS__)
#define cgnat_log_info(...)                                                   \
  vlib_log (VLIB_LOG_LEVEL_INFO, cgnat_main.log_class_dynamic, __VA_ARGS__)
#define cgnat_log_debug(...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cgnat_main.log_class_dynamic, __VA_ARGS__)

#define cgnat_log_det_err(...)                                                \
  vlib_log (VLIB_LOG_LEVEL_ERR, cgnat_main.log_class_deterministic,          \
	    __VA_ARGS__)
#define cgnat_log_det_warn(...)                                               \
  vlib_log (VLIB_LOG_LEVEL_WARNING, cgnat_main.log_class_deterministic,      \
	    __VA_ARGS__)
#define cgnat_log_det_notice(...)                                             \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, cgnat_main.log_class_deterministic,       \
	    __VA_ARGS__)
#define cgnat_log_det_info(...)                                               \
  vlib_log (VLIB_LOG_LEVEL_INFO, cgnat_main.log_class_deterministic,         \
	    __VA_ARGS__)
#define cgnat_log_det_debug(...)                                              \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, cgnat_main.log_class_deterministic,        \
	    __VA_ARGS__)

#define cgnat_interface_is_inside(i)                                          \
  ((i)->flags & CGNAT_INTERFACE_FLAG_IS_INSIDE)
#define cgnat_interface_is_outside(i)                                         \
  ((i)->flags & CGNAT_INTERFACE_FLAG_IS_OUTSIDE)

typedef enum
{
  CGNAT_INTERFACE_ROLE_NONE = 0,
  CGNAT_INTERFACE_ROLE_INSIDE = 1,
  CGNAT_INTERFACE_ROLE_OUTSIDE = 2,
} cgnat_interface_role_t;

static_always_inline cgnat_interface_t *
cgnat_get_interface (cgnat_main_t *cm, u32 sw_if_index)
{
  u32 interface_index;

  if (PREDICT_FALSE (
	sw_if_index >= vec_len (cm->interface_index_by_sw_if_index)))
    return 0;

  interface_index = cm->interface_index_by_sw_if_index[sw_if_index];
  if (PREDICT_FALSE (interface_index == CGNAT_INVALID_INDEX ||
		     pool_is_free_index (cm->interfaces, interface_index)))
    return 0;

  return pool_elt_at_index (cm->interfaces, interface_index);
}

static_always_inline cgnat_instance_t *
cgnat_instance_get_by_index (cgnat_main_t *cm, u32 instance_index)
{
  if (PREDICT_FALSE (instance_index >= vec_len (cm->instances)))
    return 0;

  cgnat_instance_t *instance =
    vec_elt_at_index (cm->instances, instance_index);
  return instance->configured ? instance : 0;
}

static_always_inline cgnat_pool_t *
cgnat_pool_get_by_index (cgnat_main_t *cm, u32 pool_index)
{
  if (PREDICT_FALSE (pool_index >= vec_len (cm->pools)))
    return 0;

  cgnat_pool_t *pool = vec_elt_at_index (cm->pools, pool_index);
  return pool->configured ? pool : 0;
}

static_always_inline u32
cgnat_packet_inside_fib_index (vlib_buffer_t *b)
{
  return fib_table_get_index_for_sw_if_index (
    FIB_PROTOCOL_IP4,
    vnet_buffer (b)->sw_if_index[VLIB_RX]);
}

static_always_inline u8
cgnat_instance_inside_fib_matches (cgnat_instance_t *instance,
				   u32 packet_inside_fib_index)
{
  return instance->inside_fib_index == CGNAT_INVALID_INDEX ||
	 instance->inside_fib_index == packet_inside_fib_index;
}

static_always_inline u32
cgnat_user_lock_index (u32 fib_index, ip4_address_t private_ip)
{
  u32 h = fib_index ^ private_ip.as_u32;

  h ^= h >> 16;
  h *= 0x7feb352d;
  h ^= h >> 15;
  h *= 0x846ca68b;
  h ^= h >> 16;
  return h & (CGNAT_USER_LOCK_BUCKETS - 1);
}

static_always_inline void
cgnat_user_lock (cgnat_instance_t *instance, u32 fib_index,
		 ip4_address_t private_ip)
{
  clib_spinlock_lock (
    &instance->user_locks[cgnat_user_lock_index (fib_index, private_ip)]);
}

static_always_inline void
cgnat_user_unlock (cgnat_instance_t *instance, u32 fib_index,
		   ip4_address_t private_ip)
{
  clib_spinlock_unlock (
    &instance->user_locks[cgnat_user_lock_index (fib_index, private_ip)]);
}

static_always_inline u32
cgnat_instance_random_u32 (cgnat_instance_t *instance)
{
  u32 rv;

  clib_spinlock_lock (&instance->random_lock);
  rv = random_u32 (&instance->random_seed);
  clib_spinlock_unlock (&instance->random_lock);
  return rv;
}

static_always_inline u32
cgnat_instance_index_by_acl (cgnat_main_t *cm, u32 acl_index)
{
  if (PREDICT_FALSE (acl_index == 0 ||
		     acl_index >= vec_len (cm->instance_index_by_acl)))
    return CGNAT_INVALID_INDEX;
  return cm->instance_index_by_acl[acl_index];
}

extern vlib_node_registration_t cgnat_in2out_node;
extern vlib_node_registration_t cgnat_in2out_policy_node;
extern vlib_node_registration_t cgnat_out2in_node;

int cgnat_plugin_enable_disable (u8 enable);
int cgnat_pool_add_del (u32 *pool_id, cgnat_pool_config_t *config, u8 is_add);
int cgnat_pool_set_cooling_time (u32 pool_id, u16 cooling_time);
int cgnat_pool_set_label (u32 pool_id, u8 *label);
int cgnat_instance_add_del (u32 *instance_id, u8 *label, u32 inside_vrf_id,
			    u32 outside_vrf_id, u8 mode, u32 *pool_ids,
			    u32 pool_count,
			    cgnat_inside_address_t *inside_addresses,
			    u32 inside_address_count, u8 is_add);
int cgnat_instance_set (u32 instance_id, cgnat_instance_config_t *config);
int cgnat_instance_index_from_id (u32 instance_id, u32 *instance_index);
int cgnat_pool_index_from_id (u32 pool_id, u32 *pool_index);
void cgnat_recalculate_instance (cgnat_main_t *cm,
				 cgnat_instance_t *instance);
int cgnat_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add);
int cgnat_interface_zone_set (u32 sw_if_index, cgnat_interface_role_t role);
int cgnat_instance_set_acl (u32 instance_index, u32 acl_index, u8 is_add);
void cgnat_instance_clear_acls (u32 instance_index);
int cgnat_instance_syslog_server_add_del (u32 instance_index,
					  ip4_address_t address, u16 port,
					  u8 is_add);
int cgnat_instance_ipfix_exporter_add_del (
  u32 instance_index, ip4_address_t collector_address, u16 collector_port,
  ip4_address_t src_address, u16 src_port, u8 is_add);
int cgnat_static_mapping_add_del (u32 instance_index, ip4_address_t outside_ip,
				  u16 outside_port, ip4_address_t inside_ip,
				  u16 inside_port, u8 protocol,
				  u8 mapping_type, u32 inside_vrf_id,
				  u8 is_add);
void cgnat_static_fib_add_for_rule (cgnat_main_t *cm,
				    cgnat_static_rule_t *rule);
void cgnat_static_fib_del_for_rule (cgnat_main_t *cm,
				    cgnat_static_rule_t *rule);
void cgnat_instance_cleanup_resources (cgnat_main_t *cm,
				       cgnat_instance_t *instance);
void cgnat_instance_cleanup_runtime_state (cgnat_main_t *cm,
					   cgnat_instance_t *instance);
void cgnat_pool_cleanup_runtime (cgnat_main_t *cm, cgnat_pool_t *pool,
				 u32 pool_index, cgnat_instance_t *instance);

void cgnat_pba_init (cgnat_main_t *cm);
int cgnat_pool_runtime_init (cgnat_pool_t *pool, u8 create_blocks);
void cgnat_pool_runtime_reset (cgnat_pool_t *pool);
void cgnat_pba_reset (cgnat_main_t *cm);
void cgnat_pba_expire_timers (f64 now);
void cgnat_session_init (cgnat_main_t *cm);
void cgnat_session_reset (cgnat_main_t *cm);
void cgnat_session_expire_timers (f64 now);
cgnat_session_t *cgnat_session_snapshot (cgnat_session_filter_t *filter);
u32 cgnat_session_delete_matching (cgnat_session_filter_t *filter);

int cgnat_pba_alloc_port (u32 instance_index, u32 fib_index,
			  ip4_address_t private_ip, u16 private_port, u8 protocol,
			  cgnat_pba_alloc_result_t *result);
int cgnat_pba_alloc_port_locked (u32 instance_index, u32 fib_index,
				 ip4_address_t private_ip, u16 private_port,
				 u8 protocol,
				 cgnat_pba_alloc_result_t *result);
int cgnat_pba_release_port (u32 instance_index, u32 pool_index,
			    u32 public_ip_index, u32 inside_fib_index,
			    ip4_address_t private_ip, u16 port, u8 protocol);
void cgnat_pba_release_user_if_idle (u32 instance_index, u32 inside_fib_index,
				     ip4_address_t private_ip);
void cgnat_delete_user (cgnat_instance_t *instance, cgnat_user_t *user);

int cgnat_det_alloc_port (cgnat_instance_t *instance, u32 inside_fib_index,
			  ip4_address_t inside_ip, u16 inside_port, u8 protocol,
			  cgnat_pba_alloc_result_t *result);
void cgnat_det_release_port (cgnat_instance_t *instance, cgnat_mapping_t *mapping);
int cgnat_det_i2omap (cgnat_instance_t *instance, ip4_address_t inside_ip,
		      ip4_address_t *public_ip, u16 *port_start, u16 *port_end);
int cgnat_det_o2imap (cgnat_instance_t *instance, ip4_address_t public_ip,
		      u16 public_port, ip4_address_t *inside_ip);
cgnat_block_ip_summary_t *
cgnat_block_summary_snapshot (ip4_address_t *public_ip);
cgnat_block_user_summary_t *
cgnat_block_user_snapshot (ip4_address_t inside_ip);
cgnat_block_public_detail_t *
cgnat_block_public_snapshot (ip4_address_t public_ip);

int cgnat_session_in2out (vlib_main_t *vm, vlib_buffer_t *b,
			  u32 instance_index, u32 inside_fib_index);
int cgnat_session_out2in (vlib_main_t *vm, vlib_buffer_t *b);

clib_error_t *cgnat_api_hookup (vlib_main_t *vm);

#endif /* __included_cgnat_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
