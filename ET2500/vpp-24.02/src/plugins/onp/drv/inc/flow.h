/*
 * Copyright (c) 2024 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_flow_h
#define included_onp_drv_inc_flow_h

/* Below enumeration values should be in sync with the RoC enum type
 * roc_npc_item_type defined in roc/base/roc_npc.h */
enum cnxk_drv_flow_item_type
{
  CNXK_DRV_FLOW_ITEM_TYPE_VOID,
  CNXK_DRV_FLOW_ITEM_TYPE_ANY,
  CNXK_DRV_FLOW_ITEM_TYPE_ETH,
  CNXK_DRV_FLOW_ITEM_TYPE_VLAN,
  CNXK_DRV_FLOW_ITEM_TYPE_E_TAG,
  CNXK_DRV_FLOW_ITEM_TYPE_IPV4,
  CNXK_DRV_FLOW_ITEM_TYPE_IPV6,
  CNXK_DRV_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
  CNXK_DRV_FLOW_ITEM_TYPE_ARP_ETH_IPV4,
  CNXK_DRV_FLOW_ITEM_TYPE_MPLS,
  CNXK_DRV_FLOW_ITEM_TYPE_ICMP,
  CNXK_DRV_FLOW_ITEM_TYPE_IGMP,
  CNXK_DRV_FLOW_ITEM_TYPE_UDP,
  CNXK_DRV_FLOW_ITEM_TYPE_TCP,
  CNXK_DRV_FLOW_ITEM_TYPE_SCTP,
  CNXK_DRV_FLOW_ITEM_TYPE_ESP,
  CNXK_DRV_FLOW_ITEM_TYPE_GRE,
  CNXK_DRV_FLOW_ITEM_TYPE_NVGRE,
  CNXK_DRV_FLOW_ITEM_TYPE_VXLAN,
  CNXK_DRV_FLOW_ITEM_TYPE_GTPC,
  CNXK_DRV_FLOW_ITEM_TYPE_GTPU,
  CNXK_DRV_FLOW_ITEM_TYPE_GENEVE,
  CNXK_DRV_FLOW_ITEM_TYPE_VXLAN_GPE,
  CNXK_DRV_FLOW_ITEM_TYPE_IPV6_EXT,
  CNXK_DRV_FLOW_ITEM_TYPE_GRE_KEY,
  CNXK_DRV_FLOW_ITEM_TYPE_HIGIG2,
  CNXK_DRV_FLOW_ITEM_TYPE_CPT_HDR,
  CNXK_DRV_FLOW_ITEM_TYPE_L3_CUSTOM,
  CNXK_DRV_FLOW_ITEM_TYPE_QINQ,
  CNXK_DRV_FLOW_ITEM_TYPE_RAW,
  CNXK_DRV_FLOW_ITEM_TYPE_MARK,
  CNXK_DRV_FLOW_ITEM_TYPE_TX_QUEUE,
  CNXK_DRV_FLOW_ITEM_TYPE_END,
};

/* Below structure should be in sync with the RoC structure roc_npc_item_info
 * defined in roc/base/roc_npc.h */
struct cnxk_drv_flow_item_info
{
  enum cnxk_drv_flow_item_type type; /* Item type */
  uint32_t size;		     /* item size */
  const void *spec; /**< Pointer to item specification structure. */
  const void *mask; /**< Bit-mask applied to spec and last. */
  const void *last; /* For range */
};

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u32 verification_tag;
  u32 cksum;
} cnxk_drv_sctp_header_t;

#endif /* included_onp_drv_inc_flow_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
