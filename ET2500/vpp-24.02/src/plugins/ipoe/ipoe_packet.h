/* SPDX-License-Identifier: Apache-2.0 */
#ifndef included_ipoe_packet_h
#define included_ipoe_packet_h

#include <ipoe/ipoe.h>

#include <vnet/ip/ip4.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>

#define IPOE_MAX_VLAN_DEPTH 2

typedef enum
{
  IPOE_PACKET_IP4_OK,
  IPOE_PACKET_NON_IP4,
  IPOE_PACKET_MALFORMED,
  IPOE_PACKET_UNSUPPORTED_VLAN_DEPTH,
} ipoe_packet_result_t;

typedef struct
{
  ip4_header_t *ip4;
  u32 packet_ip4_bytes;
  u32 contiguous_ip4_bytes;
  u8 vlan_depth;
} ipoe_ip4_view_t;

static_always_inline ipoe_packet_result_t
ipoe_ip4_validate (vlib_main_t *vm, vlib_buffer_t *b, u32 l3_offset,
		   ipoe_ip4_view_t *view)
{
  u32 chain_bytes = vlib_buffer_length_in_chain (vm, b);
  u32 contiguous_bytes = b->current_length;
  ip4_header_t *ip4;
  u32 header_bytes;
  u32 total_bytes;

  if (contiguous_bytes < l3_offset + sizeof (*ip4) ||
      chain_bytes < l3_offset + sizeof (*ip4))
    return IPOE_PACKET_MALFORMED;

  ip4 = (ip4_header_t *) ((u8 *) vlib_buffer_get_current (b) + l3_offset);
  header_bytes = ip4_header_bytes (ip4);
  if ((ip4->ip_version_and_header_length >> 4) != 4 ||
      header_bytes < sizeof (*ip4) ||
      contiguous_bytes < l3_offset + header_bytes ||
      chain_bytes < l3_offset + header_bytes)
    return IPOE_PACKET_MALFORMED;

  total_bytes = clib_net_to_host_u16 (ip4->length);
  if (total_bytes < header_bytes || chain_bytes < l3_offset + total_bytes)
    return IPOE_PACKET_MALFORMED;

  view->ip4 = ip4;
  view->packet_ip4_bytes = total_bytes;
  view->contiguous_ip4_bytes = contiguous_bytes - l3_offset;
  return IPOE_PACKET_IP4_OK;
}

static_always_inline ipoe_packet_result_t
ipoe_ip4_from_current (vlib_main_t *vm, vlib_buffer_t *b,
		       ipoe_ip4_view_t *view)
{
  view->vlan_depth = 0;
  return ipoe_ip4_validate (vm, b, 0, view);
}

static_always_inline ipoe_packet_result_t
ipoe_ip4_from_ethernet (vlib_main_t *vm, vlib_buffer_t *b,
			ipoe_ip4_view_t *view)
{
  ethernet_header_t *eth = vlib_buffer_get_current (b);
  u32 contiguous_bytes = b->current_length;
  u32 offset = sizeof (*eth);
  u16 type;

  view->vlan_depth = 0;
  if (contiguous_bytes < sizeof (*eth))
    return IPOE_PACKET_MALFORMED;

  type = eth->type;
  while (type == clib_host_to_net_u16 (ETHERNET_TYPE_VLAN) ||
	 type == clib_host_to_net_u16 (ETHERNET_TYPE_DOT1AD))
    {
      ethernet_vlan_header_t *vlan;

      if (view->vlan_depth == IPOE_MAX_VLAN_DEPTH)
	return IPOE_PACKET_UNSUPPORTED_VLAN_DEPTH;
      if (contiguous_bytes < offset + sizeof (*vlan))
	return IPOE_PACKET_MALFORMED;
      vlan = (ethernet_vlan_header_t *) ((u8 *) eth + offset);
      type = vlan->type;
      offset += sizeof (*vlan);
      view->vlan_depth++;
    }

  if (type != clib_host_to_net_u16 (ETHERNET_TYPE_IP4))
    return IPOE_PACKET_NON_IP4;
  return ipoe_ip4_validate (vm, b, offset, view);
}

static_always_inline const udp_header_t *
ipoe_ip4_udp_header (const ipoe_ip4_view_t *view)
{
  u32 header_bytes = ip4_header_bytes (view->ip4);

  if (view->ip4->protocol != IP_PROTOCOL_UDP ||
      ip4_is_fragment (view->ip4) ||
      view->packet_ip4_bytes < header_bytes + sizeof (udp_header_t) ||
      view->contiguous_ip4_bytes < header_bytes + sizeof (udp_header_t))
    return 0;
  return (const udp_header_t *) ((const u8 *) view->ip4 + header_bytes);
}

static_always_inline u8
ipoe_ip4_is_dhcp_client (const ipoe_ip4_view_t *view)
{
  const udp_header_t *udp = ipoe_ip4_udp_header (view);

  return udp &&
    clib_net_to_host_u16 (udp->src_port) == UDP_DST_PORT_dhcp_to_client &&
    clib_net_to_host_u16 (udp->dst_port) == UDP_DST_PORT_dhcp_to_server;
}

static_always_inline u8
ipoe_ip4_is_dhcp_downstream (const ipoe_ip4_view_t *view)
{
  const udp_header_t *udp = ipoe_ip4_udp_header (view);
  u16 src;
  u16 dst;

  if (!udp)
    return 0;
  src = clib_net_to_host_u16 (udp->src_port);
  dst = clib_net_to_host_u16 (udp->dst_port);
  return src == UDP_DST_PORT_dhcp_to_server &&
    (dst == UDP_DST_PORT_dhcp_to_client ||
     dst == UDP_DST_PORT_dhcp_to_server);
}

#endif
