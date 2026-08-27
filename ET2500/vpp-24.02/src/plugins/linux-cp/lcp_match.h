/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __LCP_MATCH_H__
#define __LCP_MATCH_H__

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/ip/ip46_address.h>

#include <linux-cp/lcp.api_types.h>

typedef enum
{
  LCP_MATCH_CTX_L2_DIRECT = 1 << 0,
  LCP_MATCH_CTX_L2_IP4 = 1 << 1,
  LCP_MATCH_CTX_L2_IP6 = 1 << 2,
  LCP_MATCH_CTX_IP4 = 1 << 3,
  LCP_MATCH_CTX_IP6 = 1 << 4,
  LCP_MATCH_CTX_LOCAL4 = 1 << 5,
  LCP_MATCH_CTX_LOCAL6 = 1 << 6,
  LCP_MATCH_CTX_ARP = 1 << 7,
} lcp_match_context_t;

#define LCP_MATCH_CTX_LOCAL_IP46                                      \
  (LCP_MATCH_CTX_LOCAL4 | LCP_MATCH_CTX_LOCAL6)
#define LCP_MATCH_CTX_IP4_L2                                         \
  (LCP_MATCH_CTX_IP4 | LCP_MATCH_CTX_L2_IP4)
#define LCP_MATCH_CTX_IP6_L2                                         \
  (LCP_MATCH_CTX_IP6 | LCP_MATCH_CTX_L2_IP6)

typedef enum
{
  LCP_MATCH_FIELD_ETHERTYPE = 1 << 0,
  LCP_MATCH_FIELD_MAC = 1 << 1,
  LCP_MATCH_FIELD_SLOW_SUBTYPE = 1 << 2,
  LCP_MATCH_FIELD_ARP_OPCODE = 1 << 3,
  LCP_MATCH_FIELD_IP = 1 << 4,
  LCP_MATCH_FIELD_IP_PROTOCOL = 1 << 5,
  LCP_MATCH_FIELD_L4_PORTS = 1 << 6,
  LCP_MATCH_FIELD_ICMP_TYPE = 1 << 7,
  LCP_MATCH_FIELD_IGMP_TYPE = 1 << 8,
  LCP_MATCH_FIELD_HOST_BOUND = 1 << 9,
  LCP_MATCH_FIELD_LLC = 1 << 10,
  LCP_MATCH_FIELD_ISIS_PDU = 1 << 11,
} lcp_match_field_t;

typedef enum
{
  LCP_MATCH_STATE_HOST_BOUND = 1 << 0,
  LCP_MATCH_STATE_BROADCAST = 1 << 1,
  LCP_MATCH_STATE_MULTICAST = 1 << 2,
  LCP_MATCH_STATE_FRAGMENT = 1 << 3,
  LCP_MATCH_STATE_NON_FIRST_FRAGMENT = 1 << 4,
  LCP_MATCH_STATE_TRUSTED_L4 = 1 << 5,
} lcp_match_state_t;

typedef struct
{
  vlib_main_t *vm;
  vlib_buffer_t *buffer;
  u32 context;
  u32 valid_fields;
  u32 state;
  u32 rx_sw_if_index;
  u64 src_mac;
  u64 dst_mac;
  ip46_address_t src_ip;
  ip46_address_t dst_ip;
  u16 ethertype;
  u16 arp_opcode;
  u16 l4_src_port;
  u16 l4_dst_port;
  u8 ip_version;
  u8 ip_protocol;
  u8 slow_subtype;
  u8 llc_dsap;
  u8 llc_ssap;
  u8 llc_control;
  u8 osi_protocol;
  u8 isis_pdu_type;
  u8 icmp_type;
  u8 igmp_type;
} lcp_packet_view_t;

typedef bool (*lcp_match_fn_t) (const lcp_packet_view_t *view,
				const void *data);

typedef struct
{
  u16 rule_id; /* Stable diagnostic ID; append-only, never reused. */
  const char *name;
  vl_api_lcp_trap_type_t trap_type;
  u32 context_mask;
  u32 required_fields;
  lcp_match_fn_t matches;
  const void *match_data;
} lcp_match_rule_t;

typedef struct
{
  vl_api_lcp_trap_type_t trap_type;
  u16 evidence_rule_id; /* Diagnostic only; never used for arbitration. */
} lcp_match_result_t;

bool lcp_packet_parse (vlib_main_t *vm, vlib_buffer_t *b, u32 context,
		       lcp_packet_view_t *view);
bool lcp_match_select (const lcp_packet_view_t *view,
		       lcp_match_result_t *result);
const lcp_match_rule_t *lcp_match_rule_find (u16 rule_id);
u32 lcp_match_rule_count (void);
const lcp_match_rule_t *lcp_match_rule_get (u32 index);

#endif /* __LCP_MATCH_H__ */
