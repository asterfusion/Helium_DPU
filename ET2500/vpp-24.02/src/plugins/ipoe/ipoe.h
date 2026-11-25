/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_ipoe_h
#define included_ipoe_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ethernet/qinq.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

typedef enum
{
  IPOE_INTERNAL_ACCESS_MODE_L2 = 1,
  IPOE_INTERNAL_ACCESS_MODE_L3 = 2,
} ipoe_access_mode_t;

typedef enum
{
  IPOE_INPUT_L2 = 1,
  IPOE_INPUT_IP4 = 2,
} ipoe_input_path_t;

typedef enum
{
  IPOE_SESSION_COUNTER_UPSTREAM_FORWARD,
  IPOE_SESSION_COUNTER_DOWNSTREAM_FORWARD,
  IPOE_SESSION_COUNTER_UPSTREAM_GATE_DROP,
  IPOE_SESSION_COUNTER_DOWNSTREAM_GATE_DROP,
  IPOE_SESSION_COUNTER_N_TYPES,
} ipoe_session_counter_type_t;

typedef struct
{
  mac_address_t local_mac;
  u32 parent_sw_if_index;
  u16 outer_tpid;
  u16 outer_vlan;
  u16 inner_tpid;
  u16 inner_vlan;
  u8 enabled;
} ipoe_qinq_session_t;

typedef struct
{
  vlib_counter_t upstream_forward;
  vlib_counter_t downstream_forward;
  vlib_counter_t upstream_gate_drop;
  vlib_counter_t downstream_gate_drop;
} ipoe_session_counters_t;

typedef enum
{
  IPOE_OK = 0,
  IPOE_ERROR_INVALID_INTERFACE = -1,
  IPOE_ERROR_INVALID_VALUE = -2,
  IPOE_ERROR_OBJECT_IN_USE = -3,
  IPOE_ERROR_ALREADY_EXISTS = -4,
  IPOE_ERROR_NO_SUCH_ENTRY = -5,
  IPOE_ERROR_IP_CONFLICT = -6,
  IPOE_ERROR_GENERATION_STALE = -7,
  IPOE_ERROR_FEATURE_FAILED = -8,
} ipoe_error_t;

typedef struct
{
  u32 sw_if_index;
  u32 session_count;
  u8 access_mode;
  u8 input_path;
  u8 enabled;
} ipoe_interface_t;

typedef struct
{
  u64 external_index;
  u64 generation;
  u64 lease_expiry;
  f64 expires_at;
  ip4_address_t user_ip4;
  mac_address_t user_mac;
  u32 sw_if_index;
  u32 timer_handle;
  u32 timer_generation;
  u32 counter_index;
  u32 ip6_binding_count;
  u32 ip6_qinq_route_count;
  u8 has_user_mac;
  u8 admin_state;
  u32 upstream_policer_index;
  u32 downstream_policer_index;
  ipoe_qinq_session_t qinq;
} ipoe_session_t;

typedef enum
{
  IPOE_DOWNSTREAM_LOOKUP_OK,
  IPOE_DOWNSTREAM_LOOKUP_NO_SESSION,
  IPOE_DOWNSTREAM_LOOKUP_SESSION_INACTIVE,
  IPOE_DOWNSTREAM_LOOKUP_ACCESS_MISMATCH,
  IPOE_DOWNSTREAM_LOOKUP_SESSION_MISMATCH,
} ipoe_downstream_lookup_result_t;

typedef struct
{
  u32 qinq_sw_if_index;
  u32 fib_index;
  u64 external_index;
  u32 locks;
} ipoe_qinq_dpo_t;

#define IPOE_SESSION_ADD_BATCH_MAX 64
#define IPOE_SESSION_SNAPSHOT_BATCH_MAX 128

typedef struct
{
  u64 external_index;
  u64 generation;
  u64 lease_expiry;
  u32 sw_if_index;
  u32 lease_timeout;
  ip4_address_t user_ip4;
  mac_address_t user_mac;
  u8 access_mode;
  u8 has_user_mac;
  u8 admin_state;
  ipoe_qinq_session_t qinq;
} ipoe_session_add_batch_entry_t;

typedef struct
{
  u64 external_index;
  u64 generation;
  int retval;
  u32 counter_index;
} ipoe_session_add_batch_result_t;

typedef struct
{
  u64 external_index;
  u64 generation;
  int retval;
} ipoe_session_snapshot_result_t;

typedef struct
{
  u32 route_id;
  u32 table_id;
  u32 sw_if_index;
  ip4_address_t user_ip4;
} ipoe_qinq_route_t;

typedef struct
{
  ip6_address_t prefix;
  u32 sw_if_index;
  u8 prefix_length;
  u8 pad[3];
} ipoe_ip6_binding_key_t;

typedef struct
{
  ipoe_ip6_binding_key_t key;
  u64 external_index;
} ipoe_ip6_binding_t;

typedef struct
{
  ip6_address_t prefix;
  u64 external_index;
  u32 table_id;
  u32 sw_if_index;
  u8 prefix_length;
} ipoe_qinq_ip6_route_t;

typedef struct
{
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ipoe_interface_t *interfaces;
  ipoe_session_t *sessions;
  uword *session_by_index;
  uword *session_by_user;
  ipoe_qinq_route_t *qinq_routes;
  uword *qinq_route_by_id;
  clib_bihash_24_8_t ip6_binding_hash;
  ipoe_ip6_binding_t *ip6_bindings;
  ipoe_qinq_ip6_route_t *qinq_ip6_routes;
  u32 ip6_prefix_length_refcount[129];
  u32 *free_counter_indices;
  u32 next_counter_index;
  vlib_combined_counter_main_t upstream_forward;
  vlib_combined_counter_main_t downstream_forward;
  vlib_combined_counter_main_t upstream_gate_drop;
  vlib_combined_counter_main_t downstream_gate_drop;
  tw_timer_wheel_1t_3w_1024sl_ov_t timer_wheel;
  u16 msg_id_base;
} ipoe_main_t;

extern ipoe_main_t ipoe_main;

const char *ipoe_error_string (int rv);
const char *ipoe_access_mode_name (u8 mode);
const char *ipoe_input_path_name (u8 input_path);

int ipoe_interface_enable_disable (u32 sw_if_index, u8 enable,
				   u8 access_mode, u8 input_path);
int ipoe_session_add (u64 external_index, u64 generation,
		      u32 sw_if_index, const ip4_address_t *user_ip4,
		      const mac_address_t *user_mac, u8 has_user_mac,
		      u8 admin_state,
		      u32 lease_timeout, u64 lease_expiry,
		      const ipoe_qinq_session_t *qinq);
int ipoe_session_update (u64 external_index, u64 generation,
			 u32 sw_if_index, const ip4_address_t *user_ip4,
			 const mac_address_t *user_mac, u8 has_user_mac,
			 u8 admin_state, u32 lease_timeout, u64 lease_expiry,
			 const ipoe_qinq_session_t *qinq);
int ipoe_session_add_batch (
  const ipoe_session_add_batch_entry_t *entries, u32 count,
  ipoe_session_add_batch_result_t *results);
int ipoe_session_del (u64 external_index);
int ipoe_session_set_state (u64 external_index, u64 generation,
			    u8 admin_state);
int ipoe_session_set_policer (u64 external_index, u32 upstream_index,
				      u32 downstream_index);
int ipoe_session_police (vlib_main_t *vm, vlib_buffer_t *b,
			 ipoe_session_t *session, vlib_dir_t dir);
int ipoe_session_flush_interface (u32 sw_if_index);
void ipoe_session_expire (u32 session_index);
void ipoe_session_counter_add (u32 counter_index,
			       ipoe_session_counter_type_t counter_type,
			       u32 packet_bytes);
ipoe_session_t *ipoe_session_lookup_downstream (
  u32 sw_if_index, const ip4_address_t *dst_ip, u64 expected_external_index,
  u8 check_session, ipoe_downstream_lookup_result_t *result);
int ipoe_session_get_counters (u64 external_index,
			       ipoe_session_counters_t *counters);
int ipoe_session_quiesce_snapshot_batch (
  const u64 *external_indices, const u64 *generations, u32 count,
  ipoe_session_snapshot_result_t *results);

void ipoe_timer_init (vlib_main_t *vm);
void ipoe_timer_start (u32 session_index, u32 lease_timeout);
void ipoe_timer_stop (ipoe_session_t *session);
void ipoe_timer_update (u32 session_index, u32 lease_timeout);

void ipoe_qinq_dpo_module_init (void);
const ipoe_qinq_dpo_t *ipoe_qinq_dpo_get (u32 dpo_index);
int ipoe_qinq_route_add_del (u32 table_id, const ip4_address_t *user_ip4,
			     u32 sw_if_index, u8 is_add);
int ipoe_qinq_route_add (const ipoe_qinq_route_t *route);
int ipoe_qinq_route_update (const ipoe_qinq_route_t *route);
int ipoe_qinq_route_delete (u32 route_id);
int ipoe_ip6_binding_add_del (u32 sw_if_index, const ip6_address_t *prefix,
			      u8 prefix_length, u64 external_index,
			      u8 is_add);
ipoe_session_t *ipoe_ip6_binding_lookup (u32 sw_if_index,
					 const ip6_address_t *address,
					 u8 *prefix_length);
void ipoe_ip6_binding_flush_interface (u32 sw_if_index);
int ipoe_qinq_ip6_route_add_del (u32 table_id,
				 const ip6_address_t *prefix,
				 u8 prefix_length, u32 sw_if_index,
				 u64 external_index, u8 is_add);
void ipoe_qinq_ip6_route_flush_interface (u32 sw_if_index);

static_always_inline u64
ipoe_user_key (u32 sw_if_index, const ip4_address_t *user_ip4)
{
  return ((u64) sw_if_index << 32) | (u64) user_ip4->as_u32;
}

#endif
