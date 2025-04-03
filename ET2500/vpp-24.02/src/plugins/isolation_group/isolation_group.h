
/*
 * isolation_group.h - skeleton vpp engine plug-in header file
 *
 * Copyright 2024-2027 Asterfusion Network
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
#ifndef __included_isolation_group_h__
#define __included_isolation_group_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>

typedef struct {
    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
    ethernet_main_t * ethernet_main;
} isolation_group_main_t;

// isolation group struct
typedef struct {
    u32 group_id;
    u32 *destination_sw_if_indices;
    u32 num_destinations;
} isolation_group_t;

// src_port to isolation group mapping struct
typedef struct {
    u32 source_sw_if_index;
    u32 group_id;
} source_port_group_mapping_t;

// store all isolation groups
extern isolation_group_t *isolation_groups;

// store all src_port to isolation group mappings
extern source_port_group_mapping_t *source_port_group_mappings;

extern isolation_group_main_t isolation_group_main;

extern vlib_node_registration_t isolation_group_node;

int find_isolation_group (u32 group_id);
int find_source_port_mapping(u32 source_sw_if_index);
int add_destination_port_to_group(u32 group_id, u32 destination_sw_if_index);
int set_source_port_group_mapping(u32 source_sw_if_index, u32 group_id);
int delete_source_port_group_mapping(u32 source_sw_if_index);

#endif /* __included_isolation_group_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

