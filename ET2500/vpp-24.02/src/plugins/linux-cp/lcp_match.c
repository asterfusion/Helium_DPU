/* SPDX-License-Identifier: Apache-2.0 */

#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/igmp_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

#include <linux-cp/lcp_match.h>
#include <linux-cp/lcp_policy.h>

typedef enum
{
  LCP_PORT_SRC,
  LCP_PORT_DST,
  LCP_PORT_SRC_OR_DST,
} lcp_port_direction_t;

typedef struct
{
  u8 protocol;
  u8 direction;
  u16 port;
} lcp_l4_match_data_t;

typedef struct
{
  u16 ethertype;
  u8 subtype;
} lcp_l2_subtype_match_data_t;

typedef struct
{
  u64 value;
  u64 mask;
  bool source;
} lcp_mac_match_data_t;

typedef struct
{
  u32 state;
} lcp_state_match_data_t;

typedef struct
{
  bool snp;
} lcp_isis_match_data_t;

static const lcp_state_match_data_t lcp_state_host_bound = {
  .state = LCP_MATCH_STATE_HOST_BOUND,
};

static_always_inline u64
lcp_mac_to_u64 (const u8 *mac)
{
  return ((u64) mac[0] << 40) | ((u64) mac[1] << 32) |
	 ((u64) mac[2] << 24) | ((u64) mac[3] << 16) |
	 ((u64) mac[4] << 8) | mac[5];
}

static bool
lcp_match_ethertype (const lcp_packet_view_t *view, const void *data)
{
  return view->ethertype == *(const u16 *) data;
}

static bool
lcp_match_l2_subtype (const lcp_packet_view_t *view, const void *data)
{
  const lcp_l2_subtype_match_data_t *d = data;

  return view->ethertype == d->ethertype && view->slow_subtype == d->subtype;
}

static bool
lcp_match_mac (const lcp_packet_view_t *view, const void *data)
{
  const lcp_mac_match_data_t *d = data;
  u64 address = d->source ? view->src_mac : view->dst_mac;

  return (address & d->mask) == (d->value & d->mask);
}

static bool
lcp_match_ip_protocol (const lcp_packet_view_t *view, const void *data)
{
  return view->ip_protocol == *(const u8 *) data;
}

static bool
lcp_match_l4_port (const lcp_packet_view_t *view, const void *data)
{
  const lcp_l4_match_data_t *d = data;

  if (d->protocol == 0 && view->ip_protocol != IP_PROTOCOL_TCP &&
      view->ip_protocol != IP_PROTOCOL_UDP)
    return false;
  if (d->protocol != 0 && view->ip_protocol != d->protocol)
    return false;
  if (d->direction == LCP_PORT_SRC)
    return view->l4_src_port == d->port;
  if (d->direction == LCP_PORT_DST)
    return view->l4_dst_port == d->port;
  return view->l4_src_port == d->port || view->l4_dst_port == d->port;
}

static bool
lcp_match_icmp_type (const lcp_packet_view_t *view, const void *data)
{
  return view->icmp_type == *(const u8 *) data;
}

static bool
lcp_match_igmp_type (const lcp_packet_view_t *view, const void *data)
{
  return view->igmp_type == *(const u8 *) data;
}

static bool
lcp_match_arp_opcode (const lcp_packet_view_t *view, const void *data)
{
  return view->arp_opcode == *(const u16 *) data;
}

static bool
lcp_match_state (const lcp_packet_view_t *view, const void *data)
{
  const lcp_state_match_data_t *d = data;

  return (view->state & d->state) == d->state;
}

static bool
lcp_match_isis (const lcp_packet_view_t *view, const void *data)
{
  const lcp_isis_match_data_t *d = data;
  bool snp;

  if (!(view->valid_fields & LCP_MATCH_FIELD_LLC) ||
      !(view->valid_fields & LCP_MATCH_FIELD_ISIS_PDU))
    return false;
  if (!((view->dst_mac & 0xfffffffffffeULL) == 0x0180c2000014ULL))
    return false;
  if (!((view->llc_dsap == 0xfe && view->llc_ssap == 0xfe) ||
        (view->llc_dsap == 0x14 && view->llc_ssap == 0x14)) ||
      view->llc_control != 0x03 || view->osi_protocol != 0x83)
    return false;

  snp = view->isis_pdu_type >= 24 && view->isis_pdu_type <= 27;
  if (d->snp)
    return snp;
  return view->isis_pdu_type == 15 || view->isis_pdu_type == 16 ||
         view->isis_pdu_type == 17 || view->isis_pdu_type == 18 ||
         view->isis_pdu_type == 20;
}

#define LCP_CONTEXT_LOCAL4 LCP_MATCH_CTX_LOCAL4
#define LCP_CONTEXT_LOCAL6 LCP_MATCH_CTX_LOCAL6
#define LCP_CONTEXT_L2_DIRECT LCP_MATCH_CTX_L2_DIRECT
#define LCP_CONTEXT_IP4 LCP_MATCH_CTX_IP4
#define LCP_CONTEXT_IP6 LCP_MATCH_CTX_IP6
#define LCP_CONTEXT_L2_IP4 LCP_MATCH_CTX_L2_IP4
#define LCP_CONTEXT_L2_IP6 LCP_MATCH_CTX_L2_IP6
#define LCP_CONTEXT_IP4_L2 LCP_MATCH_CTX_IP4_L2
#define LCP_CONTEXT_IP6_L2 LCP_MATCH_CTX_IP6_L2
#define LCP_CONTEXT_ARP LCP_MATCH_CTX_ARP

#define LCP_PROTOCOL_TCP IP_PROTOCOL_TCP
#define LCP_PROTOCOL_UDP IP_PROTOCOL_UDP
#define LCP_PROTOCOL_TCP_OR_UDP 0
#define LCP_PROTOCOL_OSPF IP_PROTOCOL_OSPF
#define LCP_PROTOCOL_PIM IP_PROTOCOL_PIM
#define LCP_PROTOCOL_VRRP IP_PROTOCOL_VRRP
#define LCP_DIRECTION_SRC LCP_PORT_SRC
#define LCP_DIRECTION_DST LCP_PORT_DST
#define LCP_DIRECTION_SRC_OR_DST LCP_PORT_SRC_OR_DST

#define LCP_TYPE_FIELD_IGMP LCP_MATCH_FIELD_IGMP_TYPE
#define LCP_TYPE_FIELD_ICMP4 LCP_MATCH_FIELD_ICMP_TYPE
#define LCP_TYPE_FIELD_ICMP6 LCP_MATCH_FIELD_ICMP_TYPE
#define LCP_TYPE_MATCH_IGMP lcp_match_igmp_type
#define LCP_TYPE_MATCH_ICMP4 lcp_match_icmp_type
#define LCP_TYPE_MATCH_ICMP6 lcp_match_icmp_type
#define LCP_TYPE_VALUE_IGMP_MEMBERSHIP_QUERY IGMP_TYPE_membership_query
#define LCP_TYPE_VALUE_IGMP_LEAVE_GROUP_V2 IGMP_TYPE_leave_group_v2
#define LCP_TYPE_VALUE_IGMP_MEMBERSHIP_REPORT_V1                         \
  IGMP_TYPE_membership_report_v1
#define LCP_TYPE_VALUE_IGMP_MEMBERSHIP_REPORT_V2                         \
  IGMP_TYPE_membership_report_v2
#define LCP_TYPE_VALUE_IGMP_MEMBERSHIP_REPORT_V3                         \
  IGMP_TYPE_membership_report_v3
#define LCP_TYPE_VALUE_ICMP6_ROUTER_SOLICITATION                         \
  ICMP6_router_solicitation
#define LCP_TYPE_VALUE_ICMP6_ROUTER_ADVERTISEMENT                       \
  ICMP6_router_advertisement
#define LCP_TYPE_VALUE_ICMP6_REDIRECT ICMP6_redirect
#define LCP_TYPE_VALUE_ICMP6_NEIGHBOR_SOLICITATION                       \
  ICMP6_neighbor_solicitation
#define LCP_TYPE_VALUE_ICMP6_NEIGHBOR_ADVERTISEMENT                     \
  ICMP6_neighbor_advertisement
#define LCP_TYPE_VALUE_ICMP6_MULTICAST_LISTENER_REQUEST                 \
  ICMP6_multicast_listener_request
#define LCP_TYPE_VALUE_ICMP6_MULTICAST_LISTENER_REPORT                  \
  ICMP6_multicast_listener_report
#define LCP_TYPE_VALUE_ICMP6_MULTICAST_LISTENER_DONE                    \
  ICMP6_multicast_listener_done
#define LCP_TYPE_VALUE_ICMP6_MULTICAST_LISTENER_REPORT_V2               \
  ICMP6_multicast_listener_report_v2
#define LCP_TYPE_VALUE_ICMP4_ECHO_REQUEST ICMP4_echo_request
#define LCP_TYPE_VALUE_ICMP4_ECHO_REPLY ICMP4_echo_reply
#define LCP_TYPE_VALUE_ICMP6_ECHO_REQUEST ICMP6_echo_request
#define LCP_TYPE_VALUE_ICMP6_ECHO_REPLY ICMP6_echo_reply

#define LCP_REQUIRED_HOST_BOUND LCP_MATCH_FIELD_HOST_BOUND

#define LCP_ISIS_RULE(id, rule_name, trap, ctx, is_snp)                 \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_MAC | LCP_MATCH_FIELD_LLC |       \
                       LCP_MATCH_FIELD_ISIS_PDU,                         \
    .matches = lcp_match_isis,                                            \
    .match_data = &(const lcp_isis_match_data_t) { .snp = is_snp },       \
  },

#define LCP_L4_RULE(id, rule_name, trap, ctx, proto, dir, pvalue)        \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_IP_PROTOCOL |                     \
		       LCP_MATCH_FIELD_L4_PORTS,                           \
    .matches = lcp_match_l4_port,                                          \
    .match_data = &(const lcp_l4_match_data_t) {                         \
      .protocol = LCP_PROTOCOL_##proto,                                  \
      .direction = LCP_DIRECTION_##dir, .port = pvalue,                  \
    },                                                                   \
  },
#define LCP_IP_RULE(id, rule_name, trap, ctx, proto)                     \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_IP_PROTOCOL,                      \
    .matches = lcp_match_ip_protocol,                                      \
    .match_data = &(const u8) { LCP_PROTOCOL_##proto },                  \
  },
#define LCP_L2_ETHERTYPE_RULE(id, rule_name, trap, ctx, evalue)          \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_ETHERTYPE,                        \
    .matches = lcp_match_ethertype, .match_data = &(const u16) { evalue }, \
  },
#define LCP_L2_SUBTYPE_RULE(id, rule_name, trap, ctx, etype, subvalue)   \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_ETHERTYPE |                       \
		       LCP_MATCH_FIELD_SLOW_SUBTYPE,                       \
    .matches = lcp_match_l2_subtype,                                       \
    .match_data = &(const lcp_l2_subtype_match_data_t) {                 \
      .ethertype = etype, .subtype = subvalue,                           \
    },                                                                   \
  },
#define LCP_L2_MAC_RULE(id, rule_name, trap, ctx, val, msk)              \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_MAC, .matches = lcp_match_mac,      \
    .match_data = &(const lcp_mac_match_data_t) {                        \
      .value = val, .mask = msk, .source = false,                        \
    },                                                                   \
  },
#define LCP_L2_SRC_MAC_RULE(id, rule_name, trap, ctx, val, msk)          \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_MAC, .matches = lcp_match_mac,      \
    .match_data = &(const lcp_mac_match_data_t) {                        \
      .value = val, .mask = msk, .source = true,                         \
    },                                                                   \
  },
#define LCP_STATE_MASK_RULE(id, rule_name, trap, ctx, fields, state_bits) \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx, .required_fields = fields,        \
    .matches = lcp_match_state,                                            \
    .match_data = &(const lcp_state_match_data_t) {                      \
      .state = state_bits,                                               \
    },                                                                   \
  },
#define LCP_TYPE_RULE(id, rule_name, trap, ctx, kind, tvalue)            \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_TYPE_FIELD_##kind,                            \
    .matches = LCP_TYPE_MATCH_##kind,                                      \
    .match_data = &(const u8) { LCP_TYPE_VALUE_##tvalue },               \
  },
#define LCP_STATE_RULE(id, rule_name, trap, ctx, fields, fn, data)       \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_REQUIRED_##fields,                            \
    .matches = fn, .match_data = data,                                     \
  },
#define LCP_ARP_RULE(id, rule_name, trap, ctx, opcode)                   \
  {                                                                      \
    .rule_id = id, .name = #rule_name, .trap_type = LCP_TRAP_##trap,    \
    .context_mask = LCP_CONTEXT_##ctx,                                   \
    .required_fields = LCP_MATCH_FIELD_ARP_OPCODE,                       \
    .matches = lcp_match_arp_opcode,                                       \
    .match_data = &(const u16) { opcode },                               \
  },

static const lcp_match_rule_t lcp_match_rules[] = {
#include <linux-cp/lcp_rules.def>
};

#undef LCP_L4_RULE
#undef LCP_IP_RULE
#undef LCP_L2_ETHERTYPE_RULE
#undef LCP_L2_SUBTYPE_RULE
#undef LCP_L2_MAC_RULE
#undef LCP_L2_SRC_MAC_RULE
#undef LCP_STATE_MASK_RULE
#undef LCP_TYPE_RULE
#undef LCP_STATE_RULE
#undef LCP_ARP_RULE
#undef LCP_ISIS_RULE

const lcp_match_rule_t *
lcp_match_rule_find (u16 rule_id)
{
  for (u32 i = 0; i < ARRAY_LEN (lcp_match_rules); i++)
    if (lcp_match_rules[i].rule_id == rule_id)
      return &lcp_match_rules[i];

  return 0;
}

u32
lcp_match_rule_count (void)
{
  return ARRAY_LEN (lcp_match_rules);
}

const lcp_match_rule_t *
lcp_match_rule_get (u32 index)
{
  return index < ARRAY_LEN (lcp_match_rules) ? &lcp_match_rules[index] : 0;
}

static void
lcp_parse_ethernet (vlib_buffer_t *b, lcp_packet_view_t *view)
{
  const ethernet_header_t *eh;
  const u8 *current, *l2, *payload;
  u32 available, header_size, payload_available;

  if (!(b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID))
    return;

  current = vlib_buffer_get_current (b);
  eh = ethernet_buffer_get_header (b);
  l2 = (const u8 *) eh;
  if (current < l2)
    return;

  available = b->current_length + (u32) (current - l2);
  header_size = ethernet_buffer_header_size (b);

  /* A VLAN count of three means that the actual depth is unknown.  Direct
   * protocol classification supports the depths parsed by ethernet-input. */
  if (ethernet_buffer_get_vlan_count (b) > 2 ||
      header_size < sizeof (*eh) || header_size > available)
    return;

  view->src_mac = lcp_mac_to_u64 (eh->src_address);
  view->dst_mac = lcp_mac_to_u64 (eh->dst_address);
  view->valid_fields |= LCP_MATCH_FIELD_MAC;
  if (eh->dst_address[0] & 1)
    view->state |= LCP_MATCH_STATE_MULTICAST;
  if (view->dst_mac == 0xffffffffffff)
    view->state |= LCP_MATCH_STATE_BROADCAST;

  view->ethertype = clib_net_to_host_u16 (
    clib_mem_unaligned (l2 + header_size - sizeof (u16), u16));
  view->valid_fields |= LCP_MATCH_FIELD_ETHERTYPE;

  payload = l2 + header_size;
  payload_available = available - header_size;
  if (payload_available != 0)
    {
      view->slow_subtype = payload[0];
      view->valid_fields |= LCP_MATCH_FIELD_SLOW_SUBTYPE;
    }

  /* LLC/OSI input nodes advance current past these headers.  Recover the
   * original payload from the Ethernet header so direct adapters can still
   * classify it safely. */
  if (payload_available < 3 + 5)
    return;
  {
    u16 declared = view->ethertype;
    const u8 *llc = payload;
    const u8 *osi = llc + 3;

    if (declared < 3 + 5 || declared > 1500 ||
	declared > payload_available ||
        (llc[0] != 0xfe && llc[0] != 0x14) || llc[1] != llc[0] ||
        llc[2] != 0x03 || osi[0] != 0x83)
      return;
    view->llc_dsap = llc[0];
    view->llc_ssap = llc[1];
    view->llc_control = llc[2];
    view->osi_protocol = osi[0];
    view->isis_pdu_type = osi[4] & 0x1f;
    view->valid_fields |= LCP_MATCH_FIELD_LLC | LCP_MATCH_FIELD_ISIS_PDU;
  }
}

static void
lcp_parse_ip4 (const u8 *data, u32 available, lcp_packet_view_t *view)
{
  const ip4_header_t *ip4 = (const ip4_header_t *) data;
  u32 ihl, ip_length;

  if (available < sizeof (*ip4) ||
      (ip4->ip_version_and_header_length >> 4) != 4)
    return;
  ihl = ip4_header_bytes (ip4);
  ip_length = clib_net_to_host_u16 (ip4->length);
  if (ihl < sizeof (*ip4) || ihl > available || ip_length < ihl)
    return;
  available = clib_min (available, ip_length);

  view->ip_version = 4;
  view->src_ip.ip4 = ip4->src_address;
  view->dst_ip.ip4 = ip4->dst_address;
  view->ip_protocol = ip4->protocol;
  view->valid_fields |= LCP_MATCH_FIELD_IP | LCP_MATCH_FIELD_IP_PROTOCOL;
  if (ip4_address_is_multicast (&ip4->dst_address))
    view->state |= LCP_MATCH_STATE_MULTICAST;

  if (ip4_get_fragment_offset (ip4) != 0)
    {
      view->state |= LCP_MATCH_STATE_FRAGMENT |
		     LCP_MATCH_STATE_NON_FIRST_FRAGMENT;
      return;
    }
  if (ip4_get_fragment_more (ip4))
    view->state |= LCP_MATCH_STATE_FRAGMENT;

  if ((ip4->protocol == IP_PROTOCOL_TCP ||
       ip4->protocol == IP_PROTOCOL_UDP) &&
      ihl + sizeof (udp_header_t) <= available)
    {
      const udp_header_t *l4 = (const void *) (data + ihl);
      view->l4_src_port = clib_net_to_host_u16 (l4->src_port);
      view->l4_dst_port = clib_net_to_host_u16 (l4->dst_port);
      view->valid_fields |= LCP_MATCH_FIELD_L4_PORTS;
      view->state |= LCP_MATCH_STATE_TRUSTED_L4;
    }
  else if (ip4->protocol == IP_PROTOCOL_IGMP &&
	   ihl + sizeof (igmp_header_t) <= available)
    {
      view->igmp_type = ((const igmp_header_t *) (data + ihl))->type;
      view->valid_fields |= LCP_MATCH_FIELD_IGMP_TYPE;
    }
  else if (ip4->protocol == IP_PROTOCOL_ICMP &&
	   ihl + sizeof (icmp46_header_t) <= available)
    {
      view->icmp_type = ((const icmp46_header_t *) (data + ihl))->type;
      view->valid_fields |= LCP_MATCH_FIELD_ICMP_TYPE;
    }
}

static void
lcp_parse_ip6 (vlib_buffer_t *b, const u8 *data, u32 available,
	       lcp_packet_view_t *view)
{
  const ip6_header_t *ip6 = (const ip6_header_t *) data;
  ip6_ext_hdr_chain_t hdr_chain;
  u32 offset = 0, ip_length;
  int protocol, fragment_index;

  if (available < sizeof (*ip6) ||
      (clib_net_to_host_u32 (
	 ip6->ip_version_traffic_class_and_flow_label) >> 28) != 6)
    return;
  ip_length = sizeof (*ip6) + clib_net_to_host_u16 (ip6->payload_length);
  available = clib_min (available, ip_length);

  view->ip_version = 6;
  view->src_ip.ip6 = ip6->src_address;
  view->dst_ip.ip6 = ip6->dst_address;
  view->valid_fields |= LCP_MATCH_FIELD_IP;
  if (ip6->dst_address.as_u8[0] == 0xff)
    view->state |= LCP_MATCH_STATE_MULTICAST;

  fragment_index = ip6_ext_header_walk (
    b, (ip6_header_t *) ip6, IP_PROTOCOL_IPV6_FRAGMENTATION, &hdr_chain);
  if (fragment_index < 0 || hdr_chain.length == 0)
    return;
  if (fragment_index >= 0 &&
      hdr_chain.eh[fragment_index].protocol ==
	IP_PROTOCOL_IPV6_FRAGMENTATION)
    {
      const ip6_frag_hdr_t *frag =
	(const void *) (data + hdr_chain.eh[fragment_index].offset);

      view->state |= LCP_MATCH_STATE_FRAGMENT;
      if (ip6_frag_hdr_offset (frag) != 0)
	{
	  view->state |= LCP_MATCH_STATE_NON_FIRST_FRAGMENT;
	  view->ip_protocol = frag->next_hdr;
	  view->valid_fields |= LCP_MATCH_FIELD_IP_PROTOCOL;
	  return;
	}
    }

  protocol = hdr_chain.eh[hdr_chain.length - 1].protocol;
  offset = hdr_chain.eh[hdr_chain.length - 1].offset;
  if (offset > available)
    return;
  view->ip_protocol = protocol;
  view->valid_fields |= LCP_MATCH_FIELD_IP_PROTOCOL;

  if ((protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP) &&
      offset + sizeof (udp_header_t) <= available)
    {
      const udp_header_t *l4 = (const void *) (data + offset);
      view->l4_src_port = clib_net_to_host_u16 (l4->src_port);
      view->l4_dst_port = clib_net_to_host_u16 (l4->dst_port);
      view->valid_fields |= LCP_MATCH_FIELD_L4_PORTS;
      view->state |= LCP_MATCH_STATE_TRUSTED_L4;
    }
  else if (protocol == IP_PROTOCOL_ICMP6 &&
	   offset + sizeof (icmp46_header_t) <= available)
    {
      view->icmp_type = ((const icmp46_header_t *) (data + offset))->type;
      view->valid_fields |= LCP_MATCH_FIELD_ICMP_TYPE;
    }
}

bool
lcp_packet_parse (vlib_main_t *vm, vlib_buffer_t *b, u32 context,
		  lcp_packet_view_t *view)
{
  const u8 *current = vlib_buffer_get_current (b);

  clib_memset (view, 0, sizeof (*view));
  view->vm = vm;
  view->buffer = b;
  view->context = context;
  view->rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];

  if (context == LCP_MATCH_CTX_L2_DIRECT)
    lcp_parse_ethernet (b, view);
  else if (context == LCP_MATCH_CTX_ARP)
    {
      if (b->current_length < sizeof (ethernet_arp_header_t))
	return false;
      view->arp_opcode = clib_net_to_host_u16 (
	((const ethernet_arp_header_t *) current)->opcode);
      view->valid_fields |= LCP_MATCH_FIELD_ARP_OPCODE;
    }
  else if (context == LCP_MATCH_CTX_L2_IP4 ||
	   context == LCP_MATCH_CTX_L2_IP6)
    {
      u32 l2_len = vnet_buffer (b)->l2.l2_len;

      if (l2_len >= b->current_length)
	return false;
      if (context == LCP_MATCH_CTX_L2_IP4)
	lcp_parse_ip4 (current + l2_len, b->current_length - l2_len,
		       view);
      else
	lcp_parse_ip6 (b, current + l2_len, b->current_length - l2_len,
		       view);
    }
  else if (context == LCP_MATCH_CTX_IP4 ||
	   context == LCP_MATCH_CTX_LOCAL4)
    lcp_parse_ip4 (current, b->current_length, view);
  else if (context == LCP_MATCH_CTX_IP6 ||
	   context == LCP_MATCH_CTX_LOCAL6)
    lcp_parse_ip6 (b, current, b->current_length, view);
  else
    return false;

  if (context == LCP_MATCH_CTX_LOCAL4 || context == LCP_MATCH_CTX_LOCAL6)
    {
      if (!(view->valid_fields & LCP_MATCH_FIELD_IP))
	return false;
      view->state |= LCP_MATCH_STATE_HOST_BOUND;
      view->valid_fields |= LCP_MATCH_FIELD_HOST_BOUND;
    }
  return true;
}

typedef struct
{
  bool matched;
  u16 evidence_rule_id;
} lcp_trap_candidate_t;

static_always_inline void
lcp_candidate_add (lcp_trap_candidate_t *candidates,
		   const lcp_match_rule_t *rule)
{
  lcp_trap_candidate_t *candidate = &candidates[rule->trap_type];

  if (!candidate->matched || rule->rule_id < candidate->evidence_rule_id)
    {
      candidate->matched = true;
      candidate->evidence_rule_id = rule->rule_id;
    }
}

static void
lcp_match_rules_collect (const lcp_packet_view_t *view,
			 lcp_trap_candidate_t *candidates)
{
  for (u32 i = 0; i < ARRAY_LEN (lcp_match_rules); i++)
    {
      const lcp_match_rule_t *rule = &lcp_match_rules[i];

      if (!(rule->context_mask & view->context) ||
	  (view->valid_fields & rule->required_fields) !=
	    rule->required_fields ||
	  !rule->matches (view, rule->match_data))
	continue;

      lcp_candidate_add (candidates, rule);
    }
}

static bool
lcp_trap_candidate_select (const lcp_trap_candidate_t *candidates,
			   lcp_match_result_t *result)
{
  vl_api_lcp_trap_type_t winner = LCP_TRAP_INVALID;
  u32 winner_priority = 0;

  for (vl_api_lcp_trap_type_t trap = LCP_TRAP_INVALID + 1;
       trap < LCP_TRAP_N_TYPES; trap++)
    {
      const lcp_trap_candidate_t *candidate = &candidates[trap];
      const lcp_policy_entry_t *policy;

      if (!candidate->matched)
	continue;

      policy = lcp_policy_get (trap);
      ASSERT (policy != 0);
      if (winner == LCP_TRAP_INVALID || policy->priority > winner_priority ||
	  (policy->priority == winner_priority && trap < winner))
	{
	  winner = trap;
	  winner_priority = policy->priority;
	}
    }

  if (winner == LCP_TRAP_INVALID)
    return false;

  result->trap_type = winner;
  result->evidence_rule_id = candidates[winner].evidence_rule_id;
  return true;
}

bool
lcp_match_select (const lcp_packet_view_t *view, lcp_match_result_t *result)
{
  lcp_trap_candidate_t candidates[LCP_TRAP_N_TYPES] = { 0 };

  lcp_match_rules_collect (view, candidates);
  return lcp_trap_candidate_select (candidates, result);
}

static clib_error_t *
lcp_match_init (vlib_main_t *vm)
{
  CLIB_UNUSED (vlib_main_t *unused_vm) = vm;
  const u32 valid_contexts = LCP_MATCH_CTX_L2_DIRECT |
			     LCP_MATCH_CTX_L2_IP4 | LCP_MATCH_CTX_L2_IP6 |
			     LCP_MATCH_CTX_IP4 | LCP_MATCH_CTX_IP6 |
			     LCP_MATCH_CTX_LOCAL4 | LCP_MATCH_CTX_LOCAL6 |
			     LCP_MATCH_CTX_ARP;
  const u32 valid_fields = LCP_MATCH_FIELD_ETHERTYPE |
			   LCP_MATCH_FIELD_MAC |
			   LCP_MATCH_FIELD_SLOW_SUBTYPE |
			   LCP_MATCH_FIELD_ARP_OPCODE |
			   LCP_MATCH_FIELD_IP |
			   LCP_MATCH_FIELD_IP_PROTOCOL |
			   LCP_MATCH_FIELD_L4_PORTS |
			   LCP_MATCH_FIELD_ICMP_TYPE |
			   LCP_MATCH_FIELD_IGMP_TYPE |
			   LCP_MATCH_FIELD_HOST_BOUND |
			   LCP_MATCH_FIELD_LLC | LCP_MATCH_FIELD_ISIS_PDU;

  for (u32 i = 0; i < ARRAY_LEN (lcp_match_rules); i++)
    {
      const lcp_match_rule_t *rule = &lcp_match_rules[i];

      if (!rule->rule_id || !rule->name ||
	  rule->trap_type <= LCP_TRAP_INVALID ||
	  rule->trap_type >= LCP_TRAP_N_TYPES || !rule->context_mask ||
	  (rule->context_mask & ~valid_contexts) || !rule->required_fields ||
	  (rule->required_fields & ~valid_fields) || !rule->matches ||
	  !rule->match_data || !lcp_trap_desc_get (rule->trap_type))
	return clib_error_return (0, "invalid LCP match rule %u",
				  rule->rule_id);
      for (u32 j = i + 1; j < ARRAY_LEN (lcp_match_rules); j++)
	if (rule->rule_id == lcp_match_rules[j].rule_id)
	  return clib_error_return (0, "duplicate LCP match rule id %u",
				    rule->rule_id);
    }
  return 0;
}

VLIB_INIT_FUNCTION (lcp_match_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
