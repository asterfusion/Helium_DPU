#ifndef __included_asic_priv_h__
#define __included_asic_priv_h__

#include <vppinfra/clib.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vnet.h>

/* asic private header*/
#define ASIC_PRIVATE_ETHER_TYPE 0xafaf

typedef CLIB_PACKED(struct
{
    u16 ingress_port;
    u16 ingress_vrf;
    u16 ingress_rmac_group;
    u8  ghc_data[3];
    u8  reserved[3];
    u16 ether_type;

}) ghc_header_t;

typedef CLIB_PACKED(struct
{
    ethernet_header_t eth;
    ghc_header_t ghc;

}) ethernet_asic_header_t;

typedef struct
{
    u8  dst_address[6];
    u16 ether_type;

    u16 ingress_port;
    u16 ingress_vrf;
    u16 ingress_rmac_group;

} asic_private_opaque2_t;

typedef struct
{
    u32 sw_if_index;
    u32 hw_if_index;
    u8  flag;

} asic_priv_interface_t;

typedef struct asic_private_main_s
{
    /* convenience */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    /* record enable asic_priv proc interfaces pool */
    asic_priv_interface_t *interfaces;

    /* plugin node index */
    u32 pre_asic_private_node;
    u32 post_asic_private_node;

} asic_private_main_t;

#define asic_private_buffer_opaque2(b) \
  (((vnet_buffer_opaque2_t *)b->opaque2)->unused)

extern asic_private_main_t ap_main;


int asic_priv_proc_enable(u32 sw_if_index);
int asic_priv_proc_disable(u32 sw_if_index);

/* end */

#endif  /* __included_asic_priv_h__ */
