/*
 * l2mc.c - skeleton vpp engine plug-in
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <l2mc/l2mc.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <l2mc/l2mc.api_enum.h>
#include <l2mc/l2mc.api_types.h>

#define REPLY_MSG_ID_BASE l2mc_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

l2mc_main_t l2mc_main;
l2mc_group_t *l2mc_groups;

int
l2mc_ip_to_mac (const ip46_address_t *src_ip, const ip46_address_t *dst_ip,
                u8 *src_mac, u8 *dst_mac, l2mc_type type)
{
  memset(src_mac, 0, 6);
  memset(dst_mac, 0, 6);
  
  if (ip46_address_is_ip4(dst_ip))
  {
    dst_mac[0] = 0x01;
    dst_mac[1] = 0x00;
    dst_mac[2] = 0x5e;
    
    u32 ip_addr = clib_net_to_host_u32(dst_ip->ip4.as_u32);

    dst_mac[3] = (ip_addr >> 16) & 0x7f; 
    dst_mac[4] = (ip_addr >> 8) & 0xff; 
    dst_mac[5] = ip_addr & 0xff;
    
    if (type == L2MC_SG_TYPE && src_ip && ip46_address_is_ip4(src_ip))
    {
      u32 src_ip_addr = clib_net_to_host_u32(src_ip->ip4.as_u32);
      src_mac[0] = 0x00;
      src_mac[1] = 0x00;
      src_mac[2] = 0x5e;
      src_mac[3] = (src_ip_addr >> 16) & 0xff; 
      src_mac[4] = (src_ip_addr >> 8) & 0xff;
      src_mac[5] = src_ip_addr & 0xff;
    }
  }
  else
  {
    dst_mac[0] = 0x33;
    dst_mac[1] = 0x33;
    
    memcpy(&dst_mac[2], &dst_ip->ip6.as_u8[12], 4);
    
    if (type == L2MC_SG_TYPE && src_ip && !ip46_address_is_ip4(src_ip))
    {
      src_mac[0] = 0x00;
      src_mac[1] = 0x00;
      src_mac[2] = 0x5e;
      memcpy(&src_mac[3], &src_ip->ip6.as_u8[13], 3);
    }
  }
  return 0;
}

l2mc_group_t *
l2mc_group_find (u32 bd_id, const u8 *src_mac, const u8 *dst_mac, l2mc_type type)
{
    l2mc_group_t *group;
    
    pool_foreach (group, l2mc_groups)
    {
        if (group->bd_id != bd_id)
            continue;
            
        if (memcmp(group->dst_mac, dst_mac, 6) != 0)
            continue;
            
        if (group->type != type)
            continue;
            
        if (type == L2MC_SG_TYPE && memcmp(group->src_mac, src_mac, 6) != 0)
            continue;
            
        return group;
    }
    
    return NULL;
}
int
l2mc_group_add_del_member (u32 bd_id, const u8 *src_mac, const u8 *dst_mac,
                          l2mc_type type, u32 sw_if_index, bool is_add)
{
    l2mc_group_t *group;
    
    group = l2mc_group_find(bd_id, src_mac, dst_mac, type);
    
    if (is_add)
    {
      if (!group)
      {
        pool_get(l2mc_groups, group);
        memset(group, 0, sizeof(l2mc_group_t));
        
        group->bd_id = bd_id;
        memcpy(group->src_mac, src_mac, 6);
        memcpy(group->dst_mac, dst_mac, 6);
        group->type = type;
        
        vec_validate(group->output_sw_if_indices, 0);
      }
      
      u32 *swif;
      vec_foreach(swif, group->output_sw_if_indices)
      {
        if (*swif == sw_if_index)
          return 0;
      }
      
      vec_add1(group->output_sw_if_indices, sw_if_index);
      
      return 1;
    }
    else
    {
      if (!group)
        return 0;
          
      u32 i;
      for (i = 0; i < vec_len(group->output_sw_if_indices); i++)
      {
        if (group->output_sw_if_indices[i] == sw_if_index)
        {
          vec_del1(group->output_sw_if_indices, i);
          
          if (vec_len(group->output_sw_if_indices) == 0)
          {
            vec_free(group->output_sw_if_indices);
            pool_put(l2mc_groups, group);
          }
          
          return 1;
        }
      }
      
      return 0;
    }
}

static void
vl_api_bridge_domain_add_del_multicast_t_handler (vl_api_bridge_domain_add_del_multicast_t * mp)
{
  vl_api_bridge_domain_add_del_multicast_reply_t *rmp;
  int rv = 0;

  ip46_address_t src_ip, dst_ip;
  u8 src_mac[6], dst_mac[6];
  l2mc_type type;
  ip46_type_t dst_itype;
  ip46_type_t src_itype;

  memset(&src_ip, 0, sizeof(src_ip));
  memset(&dst_ip, 0, sizeof(dst_ip));

  dst_itype = ip_address_decode(&mp->dst_ip, &dst_ip);

  if(dst_itype != IP46_TYPE_IP4 && dst_itype != IP46_TYPE_IP6)
  {
    rv = VNET_API_ERROR_INVALID_VALUE;
    goto reply;
  }

  if (mp->sg_flag == true)
  {
    src_itype = ip_address_decode(&mp->src_ip, &src_ip);

    if(src_itype != IP46_TYPE_IP4 && src_itype != IP46_TYPE_IP6)
    {
        rv = VNET_API_ERROR_INVALID_VALUE;
        goto reply;
    }
    type = L2MC_SG_TYPE;
  }
  else
  {
    type = L2MC_XG_TYPE;
  }

  rv = l2mc_ip_to_mac((type == L2MC_SG_TYPE) ? &src_ip : NULL, 
                        &dst_ip, src_mac, dst_mac, type);
  if (rv != 0)
  {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
  }

  rv = l2mc_group_add_del_member(ntohl(mp->bd_id), src_mac, dst_mac, type,
                                  ntohl(mp->sw_if_index), mp->is_add);
    
  if (rv == 0)
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
  else
      rv = 0;

reply:
    REPLY_MACRO(VL_API_BRIDGE_DOMAIN_ADD_DEL_MULTICAST_REPLY);

}

/* API definitions */
#include <l2mc/l2mc.api.c>

static clib_error_t * l2mc_init (vlib_main_t * vm)
{
  l2mc_main_t * lmp = &l2mc_main;
  clib_error_t * error = 0;
  vlib_node_t *node = NULL;

  lmp->vlib_main = vm;
  lmp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  lmp->msg_id_base = setup_message_id_table ();
  
  vec_validate (lmp->clones, vlib_num_workers ());
  node = vlib_get_node_by_name (vm, (u8 *) "l2-multicast");

  feat_bitmap_init_next_nodes (vm,
                              node->index,
                              L2INPUT_N_FEAT,
                              l2input_get_feat_names (),
                              lmp->l2_input_feat_next);

  return error;
}

VLIB_INIT_FUNCTION (l2mc_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "l2mc plugin description goes here",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
