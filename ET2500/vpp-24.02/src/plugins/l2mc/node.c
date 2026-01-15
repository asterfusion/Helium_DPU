/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <l2mc/l2mc.h>


typedef struct {
  u32 sw_if_index;
  u32 bd_index;
  u32 group_bd_id;
  u8 src[6];
  u8 dst[6];
  u8 flags;
}l2mc_trace_t;


#ifndef CLIB_MARCH_VARIANT
static u8 *
my_format_mac_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		 a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* packet trace format function */
static u8 * format_l2mc_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l2mc_trace_t * t = va_arg (*args, l2mc_trace_t *);
  
  s = format (s, "L2MC: sw_if_index %d, bd index %d ,flag %d\n",
              t->sw_if_index, t->bd_index, t->flags);
  s = format (s, "  new src %U -> new dst %U",
              my_format_mac_address, t->src, 
              my_format_mac_address, t->dst);
  return s;
}

vlib_node_registration_t l2mc_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_l2mc_error                    \
_(DROP, "l2mc dropped packets")               \
    

typedef enum
{
#define _(sym,str) L2MC_ERROR_##sym,
  foreach_l2mc_error
#undef _
    L2MC_N_ERROR,
} l2mc_error_t;

#ifndef CLIB_MARCH_VARIANT
static char *l2mc_error_strings[] = {
#define _(sym,string) string,
    foreach_l2mc_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

static void
modify_vlan_header_for_mapping(vlib_buffer_t *b, l2mc_output_mapping_t *mapping)
{
  ethernet_header_t *eh = vlib_buffer_get_current(b);
  u16 eth_type = clib_net_to_host_u16(eh->type);
  
  if (eth_type == ETHERNET_TYPE_VLAN)
  {
    ethernet_vlan_header_t *vlanh = (ethernet_vlan_header_t *)(eh + 1);
    
    u16 priority_cfi_and_id = clib_net_to_host_u16(vlanh->priority_cfi_and_id);
    
    u16 new_priority_cfi_and_id = (priority_cfi_and_id & 0xF000) | 
                                   (mapping->mapped_bd_id & 0x0FFF);
    
    vlanh->priority_cfi_and_id = clib_host_to_net_u16(new_priority_cfi_and_id);
    
    clib_warning("Modified VLAN header: original=0x%04x, new=0x%04x, mapped_bd_id=%u", 
                 priority_cfi_and_id, new_priority_cfi_and_id, mapping->mapped_bd_id);
  }
  else if (mapping->mapped_bd_id != 0)
  {
    clib_warning("Packet doesn't have VLAN header, but mapped_bd_id=%u. "
                 "Need to insert VLAN header?", mapping->mapped_bd_id);
  }
}

VLIB_NODE_FN (l2mc_node) (vlib_main_t * vm,
                          vlib_node_runtime_t * node,
                          vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l2mc_main_t *lmm = &l2mc_main;
  u32 thread_index = vm->thread_index;
  u32 next_index = node->cached_next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0) 
  {
    u32 n_left_to_next;
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u16 n_clones, n_cloned;
      l2mc_group_t *group = NULL;
      u32 sw_if_index0, bi0, ci0 = 0;
      vlib_buffer_t *b0, *c0;
      u16 next0;
      ethernet_header_t *eh0;
      u16 eh0_type;
      uword is_ip;
      u32 bd_index0;
      l2_bridge_domain_t *config0;
      i16 l3_hdr_offset;
      ethernet_vlan_header_t *vlanh;

      /* speculatively enqueue b0 to the current next frame */
      bi0 = from[0];
      from += 1;
      n_left_from -= 1;

      b0 = vlib_get_buffer (vm, bi0);

      /* Get config for the bridge domain interface */
      config0 = vec_elt_at_index (l2input_main.bd_configs,
                vnet_buffer (b0)->l2.bd_index);
      bd_index0 = config0->bd_id;

      sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

      /* Get Ethernet header */
      eh0 = vlib_buffer_get_current (b0);

      /* Default next node - continue with normal L2 processing */
      next0 = vnet_l2_feature_next (b0, lmm->l2_input_feat_next,
                                    L2INPUT_FEAT_MULTICAST);

      eh0_type = clib_net_to_host_u16 (eh0->type);
      l3_hdr_offset = sizeof(ethernet_header_t);
      u32 packet_has_vlan = 0;

      if (eh0_type == ETHERNET_TYPE_VLAN)
      {
        packet_has_vlan = 1;
        vlanh = (ethernet_vlan_header_t *)(eh0 + 1);
        eh0_type = clib_net_to_host_u16(vlanh->type);
        l3_hdr_offset += sizeof(ethernet_vlan_header_t);
      }

      is_ip = (eh0_type == ETHERNET_TYPE_IP4 || eh0_type == ETHERNET_TYPE_IP6);
      clib_warning("eh0_type %d is_ip %d", eh0_type, is_ip);
      bool mul = is_multicast_mac(eh0->dst_address);
      clib_warning("is multicast %d", mul);

      l2_bridge_domain_t *bd_config = vec_elt_at_index (l2input_main.bd_configs, vnet_buffer (b0)->l2.bd_index);
      bool drop_flag = bd_config->drop_unknown_multicast;

      if (is_multicast_mac(eh0->dst_address)&&(is_ip)) 
      {
        l2mc_group_t *group = NULL;
        
        for (int i = 0; i < vec_len(l2mc_groups); i++)
        {
          clib_warning("group mac %U packet mac %U", 
             format_mac_address, l2mc_groups[i].dst_mac,
             format_mac_address, eh0->dst_address);
          clib_warning("group bd_id %d packet bd_index %d",l2mc_groups[i].bd_id, bd_index0);
          if(l2mc_groups[i].bd_id != bd_index0)
            continue;
          
          clib_warning("group mac %U packet mac %U", 
             format_mac_address, l2mc_groups[i].dst_mac,
             format_mac_address, eh0->dst_address);
          if (memcmp(l2mc_groups[i].dst_mac, eh0->dst_address, 6) != 0)
            continue;

          if(l2mc_groups[i].type == L2MC_SG_TYPE)
          {
            clib_warning("group eth type %d packet type %d", l2mc_groups[i].ip_type, eh0_type);
            if((eh0_type == ETHERNET_TYPE_IP4 && l2mc_groups[i].ip_type == IP46_TYPE_IP6)||
              (eh0_type == ETHERNET_TYPE_IP6 && l2mc_groups[i].ip_type == IP46_TYPE_IP4))
              continue;
            if (eh0_type == ETHERNET_TYPE_IP4)
            {
                ip4_header_t *ip_h = (ip4_header_t *)((u8 *)vlib_buffer_get_current(b0) + l3_hdr_offset);
                
                clib_warning("group ip %U packet ip %U", 
                            format_ip4_address, &l2mc_groups[i].src_ip.ip4,
                            format_ip4_address, &ip_h->src_address);
                
                if (memcmp(&l2mc_groups[i].src_ip.ip4, &ip_h->src_address, sizeof(ip4_address_t)) != 0)
                {
                    continue;
                }
            }
            else if (eh0_type == ETHERNET_TYPE_IP6)
            {
              ip6_header_t *ip6_h = (ip6_header_t *)((u8 *)vlib_buffer_get_current(b0) + l3_hdr_offset);
              
              if (memcmp(&l2mc_groups[i].src_ip.ip6, &ip6_h->src_address, sizeof(ip6_address_t)) != 0)
              {
                  continue;
              }
            } 
          }
          group = &l2mc_groups[i];
          break;
        }
        
        if (group && vec_len (group->output_mappings) > 0) 
        {
          clib_warning("group found");
          u32 valid_output_count = 0;
          l2mc_output_mapping_t *mapping;
          
          vec_foreach (mapping, group->output_mappings) 
          {
            if (mapping->sw_if_index != sw_if_index0 && mapping->sw_if_index != 0)
              valid_output_count++;
          }
          clib_warning("valid output count %d", valid_output_count);
          if (valid_output_count == 0)
          {
            clib_warning("no valid output, drop flag %d",drop_flag);
            if(drop_flag)
            {
              to_next[0] = bi0;
              to_next += 1;
              n_left_to_next -= 1;

              b0->error = node->errors[L2MC_ERROR_DROP];
              vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                      to_next, n_left_to_next,
                      bi0, L2MC_NEXT_DROP);
              continue;
            }
            else
            {
              ci0 = bi0;
            }
          }
          else
          {
            clib_warning("valid output count %d", valid_output_count);
            next0 = L2MC_NEXT_L2_OUTPUT;
            
            /* Multiple outputs, need to clone buffers */
            vec_validate (lmm->clones[thread_index], valid_output_count);

            n_clones = valid_output_count;

            n_cloned = vlib_buffer_clone (vm, bi0,
                  lmm->clones[thread_index],
                  n_clones,
                  VLIB_BUFFER_CLONE_HEAD_SIZE);

            vec_set_len (lmm->clones[thread_index], n_cloned);

            if (PREDICT_FALSE (n_cloned != n_clones))
            {
              b0->error = node->errors[L2MC_ERROR_DROP];
              /* If no clones, use original buffer for one output */
              if (n_cloned == 0)
              {
                ci0 = bi0;
                vec_foreach (mapping, group->output_mappings)
                {
                  if (mapping->sw_if_index != sw_if_index0)
                  {
                    vnet_buffer (b0)->sw_if_index[VLIB_TX] = mapping->sw_if_index;
                    break;
                  }
                }

                if (packet_has_vlan)
                {
                  modify_vlan_header_for_mapping(b0, mapping);
                }

                goto enqueue_original_buffer;
              }
            }

            /* Send all clones */
            u32 clone_index = 0;
            vec_foreach (mapping, group->output_mappings)
            {
              if (mapping->sw_if_index == sw_if_index0 || mapping->sw_if_index == 0)
                continue;

              if (clone_index < n_cloned)
              {
                ci0 = lmm->clones[thread_index][clone_index];
                c0 = vlib_get_buffer (vm, ci0);

                if (packet_has_vlan)
                {
                  modify_vlan_header_for_mapping(c0, mapping);
                }

                to_next[0] = ci0;
                to_next += 1;
                n_left_to_next -= 1;

                if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                (b0->flags & VLIB_BUFFER_IS_TRACED)))
                {
                  l2mc_trace_t *t;
                  t = vlib_add_trace (vm, node, c0, sizeof (*t));
                  t->sw_if_index = sw_if_index0;
                  t->bd_index = bd_index0;
                  clib_memcpy_fast (t->src, eh0->src_address, 6);
                  clib_memcpy_fast (t->dst, eh0->dst_address, 6);
                  t->group_bd_id = group->bd_id;
                  t->flags = 1;
                }

                /* Set output interface for the clone */
                vnet_buffer (c0)->sw_if_index[VLIB_TX] = mapping->sw_if_index;

                vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                        to_next, n_left_to_next,
                        ci0, next0);
                        
                /* Handle frame full condition */
                if (PREDICT_FALSE (0 == n_left_to_next))
                {
                  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
                  vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
                }
              }
              clone_index++;
            }
            
            /* Original buffer is already handled by clones, skip further processing */
            continue;
          }
        }
        else
        {
          clib_warning("no group found,drop flag %d",drop_flag);
          
          if(drop_flag)
          {
            to_next[0] = bi0;
            to_next += 1;
            n_left_to_next -= 1;

            b0->error = node->errors[L2MC_ERROR_DROP];
            vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                    to_next, n_left_to_next,
                    bi0, L2MC_NEXT_DROP);
            continue;
          }
          else
          {
            ci0 = bi0;
          }
        }
      }
      else
      {
        clib_warning("not multicast packet");
        /* Not multicast, continue with normal processing */
        ci0 = bi0;
      }
      
      /* Enqueue buffer for normal processing (non-multicast or no group found) */
      enqueue_original_buffer:
        c0 = vlib_get_buffer (vm, ci0);

        to_next[0] = ci0;
        to_next += 1;
        n_left_to_next -= 1;

        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
              (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
          l2mc_trace_t *t;
          t = vlib_add_trace (vm, node, c0, sizeof (*t));
          t->sw_if_index = sw_if_index0;
          t->bd_index = bd_index0;
          clib_memcpy_fast (t->src, eh0->src_address, 6);
          clib_memcpy_fast (t->dst, eh0->dst_address, 6);
          if (group)
            t->group_bd_id = group->bd_id;
          else
            t->group_bd_id = ~0;
        }

        vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                to_next, n_left_to_next,
                ci0, next0);

        /* Handle frame full condition */
        if (PREDICT_FALSE (0 == n_left_to_next))
        {
          vlib_put_next_frame (vm, node, next_index, n_left_to_next);
          vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
        }
    }

    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  
  return frame->n_vectors;
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (l2mc_node) = 
{
  .name = "l2-multicast",
  .vector_size = sizeof (u32),
  .format_trace = format_l2mc_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(l2mc_error_strings),
  .error_strings = l2mc_error_strings,

  .n_next_nodes = L2MC_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [L2MC_NEXT_DROP] = "error-drop",
        [L2MC_NEXT_L2_OUTPUT] = "l2-output",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
