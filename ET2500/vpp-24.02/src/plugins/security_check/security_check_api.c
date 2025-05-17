/*
 * security_check_api.c - security check api
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

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#include <security_check/security_check.api_enum.h>
#include <security_check/security_check.api_types.h>

#define REPLY_MSG_ID_BASE security_check_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <security_check/security.h>


static int 
api_snooping_add_del(u32 count, vl_api_snooping_entry_t entrys[], 
                     u8 is_add)
{
    u32 i;
    ip46_address_t ip;
    mac_address_t mac;
    u16 vlan;
    u32 sw_if_index;

    for (i = 0; i < count; i++)
    {
        vlan = ntohs (entrys[i].vlan_id);
        if (vlan > 4096)
            return VNET_API_ERROR_INVALID_VLAN;

        if (ip_address_decode(&entrys[i].ip_address, &ip) == IP46_TYPE_ANY)
            return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;

        mac_address_decode(entrys[i].mac_address, &mac);

        sw_if_index = ntohl (entrys[i].sw_if_index);

        if (snooping_table_add_del(vlan, &ip, &mac, sw_if_index, is_add))
            return VNET_API_ERROR_INVALID_VALUE;
    }
    return 0;
}

static int
api_security_check_enable_disable(u32 sw_if_index, 
                                  u32 security_check_type,
                                  u8  is_enable)
{
    return security_check_enable_disable(sw_if_index, security_check_type, is_enable);
}

static int
api_security_check_vlan_enable_disable(u16 vlan_id, 
                                      u32 security_check_type,
                                      u8  is_enable)
{
    return security_check_vlan_enable_disable(vlan_id, security_check_type, is_enable);
}

static int
api_security_check_vlan_refresh(u16 vlan_id, 
                                u32 security_check_type)
{
    return security_check_vlan_refresh(vlan_id, security_check_type);
}

static int 
api_security_check_vlan_trust_intf_set(u16 vlan_id, 
                                       u32 security_check_type, 
                                       u32 count,
                                       u32 *sw_if_index_list)
{
    u32 *sw_if_index_vec = 0;
    for (u32 i = 0; i < count; i++)
    {
        vec_add1 (sw_if_index_vec, ntohl(sw_if_index_list[i]));
    }

    if (security_check_vlan_trust_intf_set(vlan_id, security_check_type, count, sw_if_index_vec))
    {
            return VNET_API_ERROR_INVALID_VALUE;
    }

    vec_free(sw_if_index_vec);
    return 0;
}

static int 
api_security_check_ragurad_role(u32 sw_if_index, 
                                u32 role)
{
    return security_check_ragurad_role(sw_if_index, role);
}

static void
vl_api_snooping_add_del_t_handler (vl_api_snooping_add_del_t * mp)
{
    int rv;
    vl_api_snooping_add_del_reply_t *rmp;

    rv = api_snooping_add_del(ntohl (mp->count), mp->entry, mp->is_add);

    REPLY_MACRO (VL_API_SNOOPING_ADD_DEL_REPLY);
}

static void
vl_api_security_check_enable_disable_t_handler (vl_api_security_check_enable_disable_t * mp)
{
    int rv;
    vl_api_security_check_enable_disable_reply_t *rmp;

    rv = api_security_check_enable_disable(ntohl (mp->sw_if_index), ntohl (mp->type), mp->is_enable);

    REPLY_MACRO (VL_API_SECURITY_CHECK_ENABLE_DISABLE_REPLY);
}

static void
vl_api_security_check_vlan_enable_disable_t_handler (vl_api_security_check_vlan_enable_disable_t * mp)
{
    int rv;
    vl_api_security_check_vlan_enable_disable_reply_t *rmp;

    rv = api_security_check_vlan_enable_disable(ntohs (mp->vlan_id), ntohl (mp->type), mp->is_enable);

    REPLY_MACRO (VL_API_SECURITY_CHECK_VLAN_ENABLE_DISABLE_REPLY);
}

static void
vl_api_security_check_vlan_refresh_t_handler (vl_api_security_check_vlan_refresh_t * mp)
{
    int rv;
    vl_api_security_check_vlan_refresh_reply_t *rmp;

    rv = api_security_check_vlan_refresh(ntohs (mp->vlan_id), ntohl (mp->type));

    REPLY_MACRO (VL_API_SECURITY_CHECK_VLAN_REFRESH_REPLY);
}

static void
vl_api_security_check_vlan_trust_intf_set_t_handler (vl_api_security_check_vlan_trust_intf_set_t * mp)
{
    int rv;
    vl_api_security_check_vlan_trust_intf_set_reply_t *rmp;

    rv = api_security_check_vlan_trust_intf_set(ntohs (mp->vlan_id), ntohl (mp->type), ntohl(mp->count), mp->sw_if_index_list);

    REPLY_MACRO (VL_API_SECURITY_CHECK_VLAN_TRUST_INTF_SET_REPLY);
}

static void
vl_api_security_check_raguard_role_t_handler (vl_api_security_check_raguard_role_t * mp)
{
    int rv;
    vl_api_security_check_raguard_role_reply_t *rmp;

    rv = api_security_check_ragurad_role(ntohs (mp->sw_if_index), ntohl (mp->role));

    REPLY_MACRO (VL_API_SECURITY_CHECK_RAGUARD_ROLE_REPLY);
}

static void
send_security_check_intf_drop_detail (vl_api_registration_t * reg, 
                                     u32 context,
                                     u32 sw_if_index,
                                     u32 type)
{
    security_check_main_t *secm = &security_check_main;

    vl_api_security_check_intf_drop_details_t *mp;

    vnet_hw_interface_t *hw;
    u32 id, foreach_sw_if_index;
    security_check_per_thread_counter_t *pcounter;

    u64 drop_pkt = 0, drop_bytes = 0;

    mp = vl_msg_api_alloc (sizeof (*mp));

    clib_memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (VL_API_SECURITY_CHECK_INTF_DROP_DETAILS + secm->msg_id_base);


    hw = vnet_get_hw_interface_or_null (secm->vnet_main, sw_if_index);

    if (!hw)
        goto intf_drop_detail_fill;

    hash_foreach (id, foreach_sw_if_index, hw->sub_interface_sw_if_index_by_id,
    ({
        switch(type)
        {
        case SECURITY_CHECK_TYPE_DAI:
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            break;
        case SECURITY_CHECK_TYPE_SAVI:
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            break;
        case SECURITY_CHECK_TYPE_IPSG:
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            break;
        case SECURITY_CHECK_TYPE_IPSGV6:
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            break;
        case SECURITY_CHECK_TYPE_NONE:
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                vec_validate(pcounter->if_counter, foreach_sw_if_index);
                drop_pkt   += pcounter->if_counter[foreach_sw_if_index].pkt;
                drop_bytes += pcounter->if_counter[foreach_sw_if_index].bytes;
            }
            break;
        }
    }));

intf_drop_detail_fill:
    /* fill in the message */
    mp->context = context;
    mp->drop_pkt = clib_host_to_net_u64 (drop_pkt);
    mp->drop_bytes = clib_host_to_net_u64 (drop_bytes);

    vl_api_send_msg (reg, (u8 *) mp);
}


static void
vl_api_security_check_intf_drop_dump_t_handler (vl_api_security_check_intf_drop_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_security_check_intf_drop_detail(reg, mp->context, htonl(mp->sw_if_index), htonl(mp->type));

    return; 
}

static void
send_security_check_vlan_drop_detail (vl_api_registration_t * reg, 
                                     u32 context,
                                     u16 vlan_id,
                                     u32 type)
{
    security_check_main_t *secm = &security_check_main;

    vl_api_security_check_vlan_drop_details_t *mp;

    security_check_per_thread_counter_t *pcounter;

    u64 drop_pkt = 0, drop_bytes = 0;

    mp = vl_msg_api_alloc (sizeof (*mp));

    clib_memset (mp, 0, sizeof (*mp));

    mp->_vl_msg_id = ntohs (VL_API_SECURITY_CHECK_VLAN_DROP_DETAILS + secm->msg_id_base);

    if (vlan_id > SECURITY_CHECK_VLAN_NUM)
        goto vlan_drop_detail_fill;

    switch(type)
    {
    case SECURITY_CHECK_TYPE_DAI:
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            drop_pkt   += pcounter->vlan_counter[vlan_id].pkt;
            drop_bytes += pcounter->vlan_counter[vlan_id].bytes;
        }
        break;
    case SECURITY_CHECK_TYPE_SAVI:
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            drop_pkt   += pcounter->vlan_counter[vlan_id].pkt;
            drop_bytes += pcounter->vlan_counter[vlan_id].bytes;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSG:
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            drop_pkt   += pcounter->vlan_counter[vlan_id].pkt;
            drop_bytes += pcounter->vlan_counter[vlan_id].bytes;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSGV6:
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            drop_pkt   += pcounter->vlan_counter[vlan_id].pkt;
            drop_bytes += pcounter->vlan_counter[vlan_id].bytes;
        }
        break;
    }

vlan_drop_detail_fill:
    /* fill in the message */
    mp->context = context;
    mp->drop_pkt = clib_host_to_net_u64 (drop_pkt);
    mp->drop_bytes = clib_host_to_net_u64 (drop_bytes);

    vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_security_check_vlan_drop_dump_t_handler (vl_api_security_check_vlan_drop_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_security_check_vlan_drop_detail(reg, mp->context, htons(mp->vlan_id), htonl(mp->type));

    return; 
}


/* API definitions */
#include <vnet/format_fns.h>
#include <security_check/security_check.api.c>

/* Set up the API message handling tables */
clib_error_t *
security_check_api_hookup (vlib_main_t *vm)
{
    security_check_main_t *secm = &security_check_main;
    secm->msg_id_base = setup_message_id_table ();
    return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
