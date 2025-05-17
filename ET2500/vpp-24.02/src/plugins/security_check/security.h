/*
 * security.h: types/functions for security-check.
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

#ifndef included_security_h
#define included_security_h

#include <vnet/vnet.h>

#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/format.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/sparse_vec.h>
#include <vppinfra/pool.h>


#define SECURITY_CHECK_SNP_TABLE_POOL_DEFAULT_INITIAL_SIZE   (1024)
#define SECURITY_CHECK_SNP_TABLE_HASH_DEFAULT_INITIAL_BUCKET (1024 * 1024)

#define SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM              (1024)
#define SECURITY_CHECK_VLAN_NUM                              (4096)

typedef enum {
    SECURITY_CHECK_ERROR_DROP,
    SECURITY_CHECK_PUNT,
    SECURITY_CHECK_N_NEXT,
} security_check_next_t;

typedef enum security_check_type
{
    SECURITY_CHECK_TYPE_NONE = 0,
    SECURITY_CHECK_TYPE_DAI = 1,
    SECURITY_CHECK_TYPE_SAVI = 2,
    SECURITY_CHECK_TYPE_IPSG = 3,
    SECURITY_CHECK_TYPE_IPSGV6 = 4,
} security_check_type_e;

typedef struct
{
    /* vlan */
    uint16_t vlan_id;

    /* mac */
    mac_address_t mac; 

    /* ip */
    ip46_address_t ip46;

    /* intf */
    u32 interface;
    u32 sup_interface;

} snp_entry_t;

typedef struct 
{
    bool enable;
    uint64_t pkt;
    uint64_t bytes;
} security_check_counter_t;

typedef struct 
{
    security_check_counter_t *if_counter;
    security_check_counter_t *vlan_counter;
} security_check_per_thread_counter_t;

typedef struct 
{
    uword *enable_by_sw_if_index;
    uword *enable_by_vlan;       
    uword *trust_sw_if_index_by_vlan[SECURITY_CHECK_VLAN_NUM];
    security_check_per_thread_counter_t *counter;

} dai_config_t;

typedef struct
{
    uword *enable_by_sw_if_index;
    uword *enable_by_vlan;
    uword *trust_sw_if_index_by_vlan[SECURITY_CHECK_VLAN_NUM];
    security_check_per_thread_counter_t *counter;

} savi_config_t;

typedef struct
{
    uword *enable_by_sw_if_index;
    uword *enable_by_vlan;
    uword *trust_sw_if_index_by_vlan[SECURITY_CHECK_VLAN_NUM];
    security_check_per_thread_counter_t *counter;

} ipsg_config_t;

typedef struct
{
    uword *enable_by_sw_if_index;
    uword *enable_by_vlan;
    uword *trust_sw_if_index_by_vlan[SECURITY_CHECK_VLAN_NUM];
    security_check_per_thread_counter_t *counter;

} ipsgv6_config_t;

typedef enum raguard_role_e 
{
    RAGUARD_ROLE_NONE,
    RAGUARD_ROLE_USER,
    RAGUARD_ROLE_ROUTER,
    RAGUARD_ROLE_HYBRID,

} raguard_role_e;

typedef struct
{
    raguard_role_e *role_by_sw_if_index;

} raguard_config_t;

typedef struct
{
    bool init_done;
    /* convenience */
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    /* api */
    u16 msg_id_base;

    /* SNP */
    clib_bihash_24_8_t snp_table;
    snp_entry_t *snp_entry_pool;

    /* DAI */
    dai_config_t dai_config;

    /* SAVI */
    savi_config_t savi_config;

    /* IPSG */
    ipsg_config_t ipsg_config;
    ipsgv6_config_t ipsgv6_config;

    /* Ra Guard */
    raguard_config_t raguard_config;

} security_check_main_t;

extern security_check_main_t security_check_main;

clib_error_t *security_check_api_hookup (vlib_main_t *vm);

int snooping_table_add_del(u16 vlan, ip46_address_t *ip, mac_address_t *mac, u32 sw_if_index, u8 is_add);
int security_check_enable_disable(u32 sw_if_index, u32 security_check_type, u8 is_enable);
int security_check_vlan_enable_disable(u16 vlan_id, u32 security_check_type, u8  is_enable);
int security_check_vlan_refresh(u16 vlan_id, u32 security_check_type);
int security_check_vlan_trust_intf_set(u16 vlan_id, u32 security_check_type, u32 count, u32 *sw_if_index_list);
int security_check_ragurad_role(u32 sw_if_index, u32 role);

#endif /* included_security_h */
