/*
 * security.c: security check
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

#include <vpp/app/version.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/l2/l2_input.h>

#include <vlib/threads.h>
#include <security_check/security.h>

security_check_main_t security_check_main;

static snp_entry_t *snooping_table_lookup(security_check_main_t *secm,
                                   u16 vlan, 
                                   ip46_address_t *ip, 
                                   mac_address_t *mac)
{
    clib_bihash_kv_24_8_t k;
    clib_bihash_kv_24_8_t v;
    int rc;

    //mac and vlan
    k.key[0] = (u64)mac->bytes[0] << 56 | 
               (u64)mac->bytes[1] << 48 | 
               (u64)mac->bytes[2] << 40 | 
               (u64)mac->bytes[3] << 32 | 
               (u64)mac->bytes[4] << 24 | 
               (u64)mac->bytes[5] << 16 | 
                vlan;
    //ip 
    k.key[1] = ip->as_u64[0];
    k.key[2] = ip->as_u64[1];

    rc = clib_bihash_search_24_8 (&secm->snp_table, &k, &v);
    if (!rc)
    {
        return (snp_entry_t *)v.value;
    }
    return NULL;
}

static int snooping_table_add(security_check_main_t *secm,
                        u16 vlan, 
                        ip46_address_t *ip, 
                        mac_address_t *mac, 
                        u32 sw_if_index)
{
    vnet_sw_interface_t *sw = NULL;
    snp_entry_t *entry = NULL;
    clib_bihash_kv_24_8_t kv;
    int rc;

    entry = snooping_table_lookup(secm, vlan, ip, mac);
    if (entry)
    {
        if (entry->interface != sw_if_index)
        {
            //update value
            sw = vnet_get_sup_sw_interface(secm->vnet_main, sw_if_index);
            entry->interface = sw_if_index;
            entry->sup_interface = sw->sw_if_index;
        }
        return 0;
    }

    pool_get (secm->snp_entry_pool, entry);

    entry->vlan_id = vlan;
    mac_address_copy(&entry->mac, mac);
    ip46_address_copy(&entry->ip46, ip); 
    sw = vnet_get_sup_sw_interface(secm->vnet_main, sw_if_index);
    entry->interface = sw_if_index;
    entry->sup_interface = sw->sw_if_index;

    //mac and vlan
    kv.key[0] = (u64)mac->bytes[0] << 56 | 
                (u64)mac->bytes[1] << 48 | 
                (u64)mac->bytes[2] << 40 | 
                (u64)mac->bytes[3] << 32 | 
                (u64)mac->bytes[4] << 24 | 
                (u64)mac->bytes[5] << 16 | 
                 vlan;
    //ip 
    kv.key[1] = ip->as_u64[0];
    kv.key[2] = ip->as_u64[1];

    kv.value = (u64) entry;

    rc = clib_bihash_add_del_24_8 (&secm->snp_table, &kv, 1 /*is_add*/);
    if (rc)
    {
        clib_warning ("Snooping Table: Adding entry error");
        pool_put (secm->snp_entry_pool, entry);
        return rc;
    }
    return rc;
}

static int snooping_table_del(security_check_main_t *secm,
                        u16 vlan, 
                        ip46_address_t *ip, 
                        mac_address_t *mac)
{
    snp_entry_t *entry = NULL;
    clib_bihash_kv_24_8_t k, v;
    int rc;

    //mac and vlan
    k.key[0] = (u64)mac->bytes[0] << 56 | 
               (u64)mac->bytes[1] << 48 | 
               (u64)mac->bytes[2] << 40 | 
               (u64)mac->bytes[3] << 32 | 
               (u64)mac->bytes[4] << 24 | 
               (u64)mac->bytes[5] << 16 | 
                vlan;
    //ip 
    k.key[1] = ip->as_u64[0];
    k.key[2] = ip->as_u64[1];

    rc = clib_bihash_search_24_8 (&secm->snp_table, &k, &v);
    if (rc)
    {
        //not exist, Do noting
        clib_warning ("Snooping Table: Deleting a non-existent entry");
        return 0;
    }

    rc = clib_bihash_add_del_24_8 (&secm->snp_table, &k, 0 /*is_del*/);
    if (rc)
    {
        clib_warning ("Snooping Table: Deleting entry error");
        return rc;
    }

    entry = (snp_entry_t *)v.value;
    pool_put (secm->snp_entry_pool, entry);
    return 0;
}

int snooping_table_add_del(u16 vlan, 
                           ip46_address_t *ip, 
                           mac_address_t *mac, 
                           u32 sw_if_index, 
                           u8 is_add)
{
    security_check_main_t *secm = &security_check_main;
    if (is_add)
    {
        return snooping_table_add(secm, vlan, ip, mac, sw_if_index);
    }
    else 
    {
        return snooping_table_del(secm, vlan, ip, mac);
    }
    return 0;
}


int security_check_enable_disable(u32 sw_if_index, 
                                  u32 security_check_type, 
                                  u8 is_enable)
{
    security_check_main_t *secm = &security_check_main;

    int rv;
    vnet_hw_interface_t *hw;
    security_check_per_thread_counter_t *pcounter;

    u32 id, foreach_sw_if_index;

    hw = vnet_get_hw_interface_or_null (secm->vnet_main, sw_if_index);

    if (!hw)
        return VNET_ERR_INVALID_VALUE;

    switch(security_check_type)
    {
    case SECURITY_CHECK_TYPE_DAI:
        if (clib_bitmap_get(secm->dai_config.enable_by_sw_if_index, sw_if_index) && is_enable)
            //already enable
            break;
        rv = vnet_l2_feature_enable_disable ("l2-input-nonip", "dai-check-node",
                sw_if_index, is_enable, 0, 0);
        if (rv) clib_error ("Could not %s dai-check-node on l2-input-nonip feature", is_enable ? "enable" : "diable");
        clib_bitmap_set(secm->dai_config.enable_by_sw_if_index, sw_if_index, is_enable);
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_SAVI:
        if (clib_bitmap_get(secm->savi_config.enable_by_sw_if_index, sw_if_index) && is_enable)
            //already enable
            break;
        rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "savi-check-node",
                sw_if_index, is_enable, 0, 0);
        if (rv) clib_error ("Could not %s savi-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
        clib_bitmap_set(secm->savi_config.enable_by_sw_if_index, sw_if_index, is_enable);
        vec_foreach(pcounter, secm->savi_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSG:
        if (clib_bitmap_get(secm->ipsg_config.enable_by_sw_if_index, sw_if_index) && is_enable)
            //already enable
            break;
        rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipsg-check-node",
                sw_if_index, is_enable, 0, 0);
        if (rv) clib_error ("Could not %s ipsg-check-node on l2-input-ip4 feature", is_enable ? "enable" : "diable");

        clib_bitmap_set(secm->ipsg_config.enable_by_sw_if_index, sw_if_index, is_enable);
        vec_foreach(pcounter, secm->ipsg_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSGV6:
        if (clib_bitmap_get(secm->ipsgv6_config.enable_by_sw_if_index, sw_if_index) && is_enable)
            //already enable
            break;
        rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "ipsgv6-check-node",
                sw_if_index, is_enable, 0, 0);
        if (rv) clib_error ("Could not %s ipsgv6-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");

        clib_bitmap_set(secm->ipsgv6_config.enable_by_sw_if_index, sw_if_index, is_enable);
        vec_foreach(pcounter, secm->ipsgv6_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        break;
    default:
        return VNET_ERR_INVALID_VALUE;
    }

    hash_foreach (id, foreach_sw_if_index, hw->sub_interface_sw_if_index_by_id,
    ({
        switch(security_check_type)
        {
        case SECURITY_CHECK_TYPE_DAI:
            if (clib_bitmap_get(secm->dai_config.enable_by_sw_if_index, foreach_sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-nonip", "dai-check-node",
                                                  foreach_sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s dai-check-node on l2-input-nonip feature", is_enable ? "enable" : "diable");
            clib_bitmap_set(secm->dai_config.enable_by_sw_if_index, foreach_sw_if_index, is_enable);
            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                pcounter->if_counter[foreach_sw_if_index].pkt = 0;
                pcounter->if_counter[foreach_sw_if_index].bytes = 0;
            }
            break;
        case SECURITY_CHECK_TYPE_SAVI:
            if (clib_bitmap_get(secm->savi_config.enable_by_sw_if_index, foreach_sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "savi-check-node",
                                                  foreach_sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s savi-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
            clib_bitmap_set(secm->savi_config.enable_by_sw_if_index, foreach_sw_if_index, is_enable);
            vec_foreach(pcounter, secm->savi_config.counter) 
            {
                pcounter->if_counter[foreach_sw_if_index].pkt = 0;
                pcounter->if_counter[foreach_sw_if_index].bytes = 0;
            }
            break;
        case SECURITY_CHECK_TYPE_IPSG:
            if (clib_bitmap_get(secm->ipsg_config.enable_by_sw_if_index, foreach_sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipsg-check-node",
                                                 foreach_sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsg-check-node on l2-input-ip4 feature", is_enable ? "enable" : "diable");

            clib_bitmap_set(secm->ipsg_config.enable_by_sw_if_index, foreach_sw_if_index, is_enable);
            vec_foreach(pcounter, secm->ipsg_config.counter) 
            {
                pcounter->if_counter[foreach_sw_if_index].pkt = 0;
                pcounter->if_counter[foreach_sw_if_index].bytes = 0;
            }
            break;
        case SECURITY_CHECK_TYPE_IPSGV6:
            if (clib_bitmap_get(secm->ipsgv6_config.enable_by_sw_if_index, foreach_sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "ipsgv6-check-node",
                                                 foreach_sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsgv6-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");

            clib_bitmap_set(secm->ipsgv6_config.enable_by_sw_if_index, foreach_sw_if_index, is_enable);
            vec_foreach(pcounter, secm->ipsgv6_config.counter) 
            {
                pcounter->if_counter[foreach_sw_if_index].pkt = 0;
                pcounter->if_counter[foreach_sw_if_index].bytes = 0;
            }
            break;
        default:
            return VNET_ERR_INVALID_VALUE;
        }
    }));
    return 0;
}

int security_check_vlan_enable_disable(u16 vlan_id, 
                                      u32 security_check_type,
                                      u8  is_enable)
{
    security_check_main_t *secm = &security_check_main;
    u32 bd_index;
    l2_bridge_domain_t *bd_config;
    security_check_per_thread_counter_t *pcounter;
    int rv;
    u32 member;

    if (vlan_id > SECURITY_CHECK_VLAN_NUM)
        return VNET_ERR_INVALID_VALUE;

    bd_index = bd_find_index(&bd_main, vlan_id);

    if (bd_index == ~0)
        return VNET_ERR_INVALID_VALUE;

    bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);

    vec_foreach_index (member, bd_config->members)
    {
        l2_flood_member_t *m = vec_elt_at_index (bd_config->members, member);

        switch(security_check_type)
        {
        case SECURITY_CHECK_TYPE_DAI:
            if (clib_bitmap_get(secm->dai_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-nonip", "dai-check-node",
                                                  m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s dai-check-node on l2-input-nonip feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_SAVI:
            if (clib_bitmap_get(secm->savi_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "savi-check-node",
                                                  m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s savi-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_IPSG:
            if (clib_bitmap_get(secm->ipsg_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipsg-check-node",
                                                 m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsg-check-node on l2-input-ip4 feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_IPSGV6:
            if (clib_bitmap_get(secm->ipsgv6_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "ipsgv6-check-node",
                                                 m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsgv6-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
            break;
        default:
            return VNET_ERR_INVALID_VALUE;
        }
    }

    switch(security_check_type)
    {
    case SECURITY_CHECK_TYPE_DAI:
        clib_bitmap_set(secm->dai_config.enable_by_vlan, vlan_id, is_enable);
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            pcounter->vlan_counter[vlan_id].pkt = 0;
            pcounter->vlan_counter[vlan_id].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_SAVI:
        clib_bitmap_set(secm->savi_config.enable_by_vlan, vlan_id, is_enable);
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            pcounter->vlan_counter[vlan_id].pkt = 0;
            pcounter->vlan_counter[vlan_id].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSG:
        clib_bitmap_set(secm->ipsg_config.enable_by_vlan, vlan_id, is_enable);
        vec_foreach(pcounter, secm->ipsg_config.counter) 
        {
            pcounter->vlan_counter[vlan_id].pkt = 0;
            pcounter->vlan_counter[vlan_id].bytes = 0;
        }
        break;
    case SECURITY_CHECK_TYPE_IPSGV6:
        clib_bitmap_set(secm->ipsgv6_config.enable_by_vlan, vlan_id, is_enable);
        vec_foreach(pcounter, secm->ipsgv6_config.counter) 
        {
            pcounter->vlan_counter[vlan_id].pkt = 0;
            pcounter->vlan_counter[vlan_id].bytes = 0;
        }
        break;
    default:
        return VNET_ERR_INVALID_VALUE;
    }
    return 0;
}

int security_check_vlan_refresh(u16 vlan_id, u32 security_check_type)
{
    security_check_main_t *secm = &security_check_main;
    l2_bridge_domain_t *bd_config;

    int rv;
    u32 bd_index;
    u32 member;

    int is_enable;
    
    if (vlan_id > SECURITY_CHECK_VLAN_NUM)
        return VNET_ERR_INVALID_VALUE;

    bd_index = bd_find_index(&bd_main, vlan_id);

    if (bd_index == ~0)
        return VNET_ERR_INVALID_VALUE;

    bd_config = vec_elt_at_index (l2input_main.bd_configs, bd_index);

    vec_foreach_index (member, bd_config->members)
    {
        l2_flood_member_t *m = vec_elt_at_index (bd_config->members, member);

        switch(security_check_type)
        {
        case SECURITY_CHECK_TYPE_DAI:
            is_enable = clib_bitmap_get_no_check(secm->dai_config.enable_by_vlan, vlan_id) ? 1 : 0;

            if (clib_bitmap_get(secm->dai_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;

            rv = vnet_l2_feature_enable_disable ("l2-input-nonip", "dai-check-node",
                                                  m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s dai-check-node on l2-input-nonip feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_SAVI:
            is_enable = clib_bitmap_get_no_check(secm->savi_config.enable_by_vlan, vlan_id) ? 1 : 0;

            if (clib_bitmap_get(secm->savi_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;

            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "savi-check-node",
                                                  m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s savi-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_IPSG:
            is_enable = clib_bitmap_get_no_check(secm->ipsg_config.enable_by_vlan, vlan_id) ? 1 : 0;

            if (clib_bitmap_get(secm->ipsg_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;

            rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipsg-check-node",
                                                 m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsg-check-node on l2-input-ip4 feature", is_enable ? "enable" : "diable");
            break;
        case SECURITY_CHECK_TYPE_IPSGV6:
            is_enable = clib_bitmap_get_no_check(secm->ipsgv6_config.enable_by_vlan, vlan_id) ? 1 : 0;

            if (clib_bitmap_get(secm->ipsgv6_config.enable_by_sw_if_index, m->sw_if_index) && is_enable)
                //already enable
                break;

            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "ipsgv6-check-node",
                                                 m->sw_if_index, is_enable, 0, 0);
            if (rv) clib_error ("Could not %s ipsgv6-check-node on l2-input-ip6 feature", is_enable ? "enable" : "diable");
            break;
        default:
            return VNET_ERR_INVALID_VALUE;
        }
    }

    return 0;
}

int security_check_vlan_trust_intf_set(u16 vlan_id, 
                                       u32 security_check_type, 
                                       u32 count,
                                       u32 *sw_if_index_list)
{
    security_check_main_t *secm = &security_check_main;

    if (vlan_id > SECURITY_CHECK_VLAN_NUM)
        return VNET_ERR_INVALID_VALUE;

    switch(security_check_type)
    {
    case SECURITY_CHECK_TYPE_DAI:
        clib_bitmap_zero(secm->dai_config.trust_sw_if_index_by_vlan[vlan_id]);
        for (u32 i = 0; i < count; i++)
        {
            clib_bitmap_set(secm->dai_config.trust_sw_if_index_by_vlan[vlan_id], sw_if_index_list[i], 1);
        }
        break;
    case SECURITY_CHECK_TYPE_SAVI:
        clib_bitmap_zero(secm->savi_config.trust_sw_if_index_by_vlan[vlan_id]);
        for (u32 i = 0; i < count; i++)
        {
            clib_bitmap_set(secm->savi_config.trust_sw_if_index_by_vlan[vlan_id], sw_if_index_list[i], 1);
        }
        break;
    case SECURITY_CHECK_TYPE_IPSG:
        clib_bitmap_zero(secm->ipsg_config.trust_sw_if_index_by_vlan[vlan_id]);
        for (u32 i = 0; i < count; i++)
        {
            clib_bitmap_set(secm->ipsg_config.trust_sw_if_index_by_vlan[vlan_id], sw_if_index_list[i], 1);
        }
        break;
    case SECURITY_CHECK_TYPE_IPSGV6:
        clib_bitmap_zero(secm->ipsgv6_config.trust_sw_if_index_by_vlan[vlan_id]);
        for (u32 i = 0; i < count; i++)
        {
            clib_bitmap_set(secm->ipsgv6_config.trust_sw_if_index_by_vlan[vlan_id], sw_if_index_list[i], 1);
        }
        break;
    default:
        return VNET_ERR_INVALID_VALUE;
    }
    return 0;
}

int security_check_ragurad_role(u32 sw_if_index, 
                                    u32 role)
{
    security_check_main_t *secm = &security_check_main;

    int rv;

    vnet_hw_interface_t *hw;

    u32 id, foreach_sw_if_index;

    hw = vnet_get_hw_interface_or_null (secm->vnet_main, sw_if_index);

    if (!hw)
        return VNET_ERR_INVALID_VALUE;

    switch(role)
    {
    case RAGUARD_ROLE_NONE:
    case RAGUARD_ROLE_ROUTER:
        rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "raguard-check-node-l2",
                sw_if_index, 0, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-l2 on l2-input-ip6 feature");

        rv = vnet_feature_enable_disable("ip6-unicast", "raguard-check-node-ip6", 
                sw_if_index, 0, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-unicast feature");

        rv = vnet_feature_enable_disable("ip6-multicast", "raguard-check-node-ip6", 
                sw_if_index, 0, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-multicast feature");

        vec_validate(secm->raguard_config.role_by_sw_if_index, sw_if_index);
        secm->raguard_config.role_by_sw_if_index[sw_if_index] = role;

        break;
    case RAGUARD_ROLE_USER:
    case RAGUARD_ROLE_HYBRID:
        rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "raguard-check-node-l2",
                sw_if_index, 1, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-l2 on l2-input-ip6 feature");

        rv = vnet_feature_enable_disable("ip6-unicast", "raguard-check-node-ip6", 
                sw_if_index, 1, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-unicast feature");

        rv = vnet_feature_enable_disable("ip6-multicast", "raguard-check-node-ip6", 
                sw_if_index, 1, 0, 0);
        if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-multicast feature");

        vec_validate(secm->raguard_config.role_by_sw_if_index, sw_if_index);
        secm->raguard_config.role_by_sw_if_index[sw_if_index] = role;
        break;
    default:
        return VNET_ERR_INVALID_VALUE;
    }

    hash_foreach (id, foreach_sw_if_index, hw->sub_interface_sw_if_index_by_id,
    ({
        switch(role)
        {
        case RAGUARD_ROLE_NONE:
        case RAGUARD_ROLE_ROUTER:
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "raguard-check-node-l2",
                                                 foreach_sw_if_index, 0, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-l2 on l2-input-ip6 feature");

            rv = vnet_feature_enable_disable("ip6-unicast", "raguard-check-node-ip6", 
                                             foreach_sw_if_index, 0, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-unicast feature");

            rv = vnet_feature_enable_disable("ip6-multicast", "raguard-check-node-ip6", 
                                             foreach_sw_if_index, 0, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-multicast feature");

            vec_validate(secm->raguard_config.role_by_sw_if_index, foreach_sw_if_index);
            secm->raguard_config.role_by_sw_if_index[foreach_sw_if_index] = role;

            break;
        case RAGUARD_ROLE_USER:
        case RAGUARD_ROLE_HYBRID:
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "raguard-check-node-l2",
                                                 foreach_sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-l2 on l2-input-ip6 feature");

            rv = vnet_feature_enable_disable("ip6-unicast", "raguard-check-node-ip6", 
                                             foreach_sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-unicast feature");

            rv = vnet_feature_enable_disable("ip6-multicast", "raguard-check-node-ip6", 
                                             foreach_sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not disable raguard-check-node-ip6 on ip6-multicast feature");

            vec_validate(secm->raguard_config.role_by_sw_if_index, foreach_sw_if_index);
            secm->raguard_config.role_by_sw_if_index[foreach_sw_if_index] = role;
            break;
        default:
            return VNET_ERR_INVALID_VALUE;
        }
    }));

    return 0;
}

static clib_error_t *
security_check_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
    security_check_main_t *secm = &security_check_main;

    int rv;

    vnet_sw_interface_t *sw = NULL;
    u32 sup_sw_if_index;

    security_check_per_thread_counter_t *pcounter = NULL;

    if (!secm->init_done)
        return 0;

    sw = vnet_get_sw_interface (secm->vnet_main, sw_if_index);

    sup_sw_if_index = sw->sup_sw_if_index;

    if (sup_sw_if_index == sw_if_index)
    {
        return 0;
    }

    if (is_add)
    {
        if (clib_bitmap_get_no_check(secm->dai_config.enable_by_sw_if_index, sup_sw_if_index))
        {
            rv = vnet_l2_feature_enable_disable ("l2-input-nonip", "dai-check-node",
                                                 sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable dai-check-node on l2-input-nonip feature");

            clib_bitmap_set(secm->dai_config.enable_by_sw_if_index, sw_if_index, 1);

            vec_foreach(pcounter, secm->dai_config.counter) 
            {
                pcounter->if_counter[sw_if_index].pkt = 0;
                pcounter->if_counter[sw_if_index].bytes = 0;
            }
        }
        if (clib_bitmap_get_no_check(secm->savi_config.enable_by_sw_if_index, sup_sw_if_index))
        {
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "savi-check-node",
                                                 sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable savi-check-node on l2-input-ip6 feature");

            clib_bitmap_set(secm->savi_config.enable_by_sw_if_index, sw_if_index, 1);
            vec_foreach(pcounter, secm->savi_config.counter) 
            {
                pcounter->if_counter[sw_if_index].pkt = 0;
                pcounter->if_counter[sw_if_index].bytes = 0;
            }
        }
        if (clib_bitmap_get_no_check(secm->ipsg_config.enable_by_sw_if_index, sup_sw_if_index))
        {
            rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipsg-check-node",
                                                 sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable ipsg-check-node on l2-input-ip4 feature");

            clib_bitmap_set(secm->ipsg_config.enable_by_sw_if_index, sw_if_index, 1);
            vec_foreach(pcounter, secm->ipsg_config.counter) 
            {
                pcounter->if_counter[sw_if_index].pkt = 0;
                pcounter->if_counter[sw_if_index].bytes = 0;
            }
        }
        if (clib_bitmap_get_no_check(secm->ipsgv6_config.enable_by_sw_if_index, sup_sw_if_index))
        {
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "ipsgv6-check-node",
                                                 sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable ipsgv6-check-node on l2-input-ip6 feature");

            clib_bitmap_set(secm->ipsgv6_config.enable_by_sw_if_index, sw_if_index, 1);
            vec_foreach(pcounter, secm->ipsgv6_config.counter) 
            {
                pcounter->if_counter[sw_if_index].pkt = 0;
                pcounter->if_counter[sw_if_index].bytes = 0;
            }
        }

        vec_validate(secm->raguard_config.role_by_sw_if_index, sup_sw_if_index);
        if (secm->raguard_config.role_by_sw_if_index[sup_sw_if_index] == RAGUARD_ROLE_USER || 
            secm->raguard_config.role_by_sw_if_index[sup_sw_if_index] == RAGUARD_ROLE_HYBRID)
        {
            rv = vnet_l2_feature_enable_disable ("l2-input-ip6", "raguard-check-node-l2",
                                                 sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable raguard-check-node-l2 on l2-input-ip6 feature");

            rv = vnet_feature_enable_disable("ip6-unicast", "raguard-check-node-ip6", 
                                             sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable raguard-check-node-ip6 on ip6-unicast feature");

            rv = vnet_feature_enable_disable("ip6-multicast", "raguard-check-node-ip6", 
                                             sw_if_index, 1, 0, 0);
            if (rv) clib_error ("Could not enable raguard-check-node-ip6 on ip6-multicast feature");

            vec_validate(secm->raguard_config.role_by_sw_if_index, sw_if_index);
            secm->raguard_config.role_by_sw_if_index[sw_if_index] = 
                        secm->raguard_config.role_by_sw_if_index[sup_sw_if_index];
        }
    }
    else 
    {
        clib_bitmap_set(secm->dai_config.enable_by_sw_if_index, sw_if_index, 0);
        vec_foreach(pcounter, secm->dai_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        clib_bitmap_set(secm->savi_config.enable_by_sw_if_index, sw_if_index, 0);
        vec_foreach(pcounter, secm->savi_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        clib_bitmap_set(secm->ipsg_config.enable_by_sw_if_index, sw_if_index, 0);
        vec_foreach(pcounter, secm->ipsg_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }
        clib_bitmap_set(secm->ipsgv6_config.enable_by_sw_if_index, sw_if_index, 0);
        vec_foreach(pcounter, secm->ipsgv6_config.counter) 
        {
            pcounter->if_counter[sw_if_index].pkt = 0;
            pcounter->if_counter[sw_if_index].bytes = 0;
        }

        secm->raguard_config.role_by_sw_if_index[sw_if_index] = RAGUARD_ROLE_NONE;
    }

    return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (security_check_sw_interface_add_del);


static void security_check_dai_init(security_check_main_t *secm)
{
    vlib_thread_main_t *tm = vlib_get_thread_main ();
    dai_config_t *dai = &secm->dai_config;
    uword vlan; 
    u16 wk;

    /* bitmap init */
    clib_bitmap_alloc(dai->enable_by_sw_if_index, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    clib_bitmap_alloc(dai->enable_by_vlan, SECURITY_CHECK_VLAN_NUM);

    /* per vlan trust port init */
    vec_validate (dai->trust_sw_if_index_by_vlan, SECURITY_CHECK_VLAN_NUM);
    for (vlan = 0; vlan < SECURITY_CHECK_VLAN_NUM; vlan++)
    {
        clib_bitmap_alloc(dai->trust_sw_if_index_by_vlan[vlan], SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    }

    /* counter init */
    vec_validate (dai->counter, tm->n_vlib_mains - 1);
    for (wk = 0; wk < vec_len (dai->counter); wk++)
    {
        security_check_per_thread_counter_t *per_counter = &dai->counter[wk];
        vec_validate(per_counter->if_counter, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
        vec_validate(per_counter->vlan_counter, SECURITY_CHECK_VLAN_NUM);
    }
}

static void security_check_savi_init(security_check_main_t *secm)
{
    vlib_thread_main_t *tm = vlib_get_thread_main ();
    savi_config_t *savi = &secm->savi_config;
    uword vlan; 
    u16 wk;

    /* bitmap init */
    clib_bitmap_alloc(savi->enable_by_sw_if_index, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    clib_bitmap_alloc(savi->enable_by_vlan, SECURITY_CHECK_VLAN_NUM);

    /* per vlan trust port init */
    vec_validate (savi->trust_sw_if_index_by_vlan, SECURITY_CHECK_VLAN_NUM);
    for (vlan = 0; vlan < SECURITY_CHECK_VLAN_NUM; vlan++)
    {
        clib_bitmap_alloc(savi->trust_sw_if_index_by_vlan[vlan], SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    }

    /* counter init */
    vec_validate (savi->counter, tm->n_vlib_mains - 1);
    for (wk = 0; wk < vec_len (savi->counter); wk++)
    {
        security_check_per_thread_counter_t *per_counter = &savi->counter[wk];
        vec_validate(per_counter->if_counter, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
        vec_validate(per_counter->vlan_counter, SECURITY_CHECK_VLAN_NUM);
    }
}

static void security_check_ipsg_init(security_check_main_t *secm)
{
    vlib_thread_main_t *tm = vlib_get_thread_main ();
    ipsg_config_t *ipsg = &secm->ipsg_config;
    uword vlan; 
    u16 wk;

    /* bitmap init */
    clib_bitmap_alloc(ipsg->enable_by_sw_if_index, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    clib_bitmap_alloc(ipsg->enable_by_vlan, SECURITY_CHECK_VLAN_NUM);

    /* per vlan trust port init */
    vec_validate (ipsg->trust_sw_if_index_by_vlan, SECURITY_CHECK_VLAN_NUM);
    for (vlan = 0; vlan < SECURITY_CHECK_VLAN_NUM; vlan++)
    {
        clib_bitmap_alloc(ipsg->trust_sw_if_index_by_vlan[vlan], SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    }

    /* counter init */
    vec_validate (ipsg->counter, tm->n_vlib_mains - 1);
    for (wk = 0; wk < vec_len (ipsg->counter); wk++)
    {
        security_check_per_thread_counter_t *per_counter = &ipsg->counter[wk];
        vec_validate(per_counter->if_counter, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
        vec_validate(per_counter->vlan_counter, SECURITY_CHECK_VLAN_NUM);
    }
}

static void security_check_ipsgv6_init(security_check_main_t *secm)
{
    vlib_thread_main_t *tm = vlib_get_thread_main ();
    ipsgv6_config_t *ipsgv6 = &secm->ipsgv6_config;
    uword vlan; 
    u16 wk;

    /* bitmap init */
    clib_bitmap_alloc(ipsgv6->enable_by_sw_if_index, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    clib_bitmap_alloc(ipsgv6->enable_by_vlan, SECURITY_CHECK_VLAN_NUM);

    /* per vlan trust port init */
    vec_validate (ipsgv6->trust_sw_if_index_by_vlan, SECURITY_CHECK_VLAN_NUM);
    for (vlan = 0; vlan < SECURITY_CHECK_VLAN_NUM; vlan++)
    {
        clib_bitmap_alloc(ipsgv6->trust_sw_if_index_by_vlan[vlan], SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
    }

    /* counter init */
    vec_validate (ipsgv6->counter, tm->n_vlib_mains - 1);
    for (wk = 0; wk < vec_len (ipsgv6->counter); wk++)
    {
        security_check_per_thread_counter_t *per_counter = &ipsgv6->counter[wk];
        vec_validate(per_counter->if_counter, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
        vec_validate(per_counter->vlan_counter, SECURITY_CHECK_VLAN_NUM);
    }
}

static void sccurity_check_raguard_init(security_check_main_t *secm)
{
    raguard_config_t *raguard = &secm->raguard_config;

    raguard->role_by_sw_if_index = vec_new(raguard_role_e, SECURITY_CHECK_DEFAULT_INTF_INITIAL_NUM);
}

static clib_error_t *
security_check_init (vlib_main_t *vm)
{
    clib_error_t *error = 0;
    security_check_main_t *secm = &security_check_main;

    clib_memset (secm, 0, sizeof (*secm));

    secm->vlib_main = vm;
    secm->vnet_main = vnet_get_main();

    vlib_node_t *lcp_node = vlib_get_node_by_name (vm, (u8 *) "linux-cp-punt");
    if(lcp_node == NULL )
    {
        error = clib_error_return (0, "security_check_plugin depends on linux_cp_plugin");
        return error;
    }

    /* init snp table */
    pool_alloc(secm->snp_entry_pool, SECURITY_CHECK_SNP_TABLE_POOL_DEFAULT_INITIAL_SIZE);
    clib_bihash_init_24_8(&secm->snp_table, "snooping-table", SECURITY_CHECK_SNP_TABLE_HASH_DEFAULT_INITIAL_BUCKET, 0);

    /* init DAI/SAVI/IPSG/IPSGV6 config */
    security_check_dai_init(secm);
    security_check_savi_init(secm);    
    security_check_ipsg_init(secm);    
    security_check_ipsgv6_init(secm);    

    sccurity_check_raguard_init(secm);

    /* api init */
    error = security_check_api_hookup (vm);

    secm->init_done = true;

    return error;
}

VLIB_INIT_FUNCTION (security_check_init);
