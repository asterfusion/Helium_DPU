
/*
 * l2mc.h - skeleton vpp engine plug-in header file
 *
 * Copyright (c) <current-year> <your-organization>
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
#ifndef __included_l2mc_h__
#define __included_l2mc_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ip/ip_format_fns.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

#include <vnet/l2/l2_input.h>
#include <vnet/l2/feat_bitmap.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
    
    u32 l2_input_feat_next[32];
    u32 **clones;
} l2mc_main_t;

typedef enum {
  L2MC_NEXT_DROP,
  L2MC_NEXT_L2_OUTPUT,
  L2MC_N_NEXT,
} l2mc_next_t;

typedef enum {
    L2MC_SG_TYPE = 0,
    L2MC_XG_TYPE = 1,
}l2mc_type;

typedef struct {
    u16 bd_id;
    u8 src_mac[6];
    u8 dst_mac[6];
    l2mc_type type;
    u32 *output_sw_if_indices;  
} l2mc_group_t;

extern l2mc_group_t *l2mc_groups;
extern l2mc_main_t l2mc_main;
extern vlib_node_registration_t l2mc_node;

static_always_inline int
is_multicast_mac (const u8 * mac)
{
    return (mac[0] & 0x01);
}

#endif /* __included_l2mc_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

