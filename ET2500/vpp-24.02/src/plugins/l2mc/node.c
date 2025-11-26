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

#define foreach_l2mc_error                    \
_(DROP, "l2mc dropped packets")               \
    


typedef enum
{
#define _(sym,str) L2MC_ERROR_##sym,
  foreach_l2mc_error
#undef _
    L2MC_N_ERROR,
} l2mc_error_t;

static char *l2mc_error_strings[] = {
#define _(sym,string) string,
    foreach_l2mc_error
#undef _
};

vlib_node_registration_t l2mc_node;

#endif /* CLIB_MARCH_VARIANT */

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
      u32 bd_index0;
      l2_bridge_domain_t *config0;

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

      if (is_multicast_mac(eh0->dst_address)) 
      {
        l2mc_group_t *group = NULL;
        
        for (int i = 0; i < vec_len(l2mc_groups); i++)
        {
          if(l2mc_groups[i].bd_id != bd_index0)
            continue;
          
          if (memcmp(l2mc_groups[i].dst_mac, eh0->dst_address, 6) != 0)
            continue;

          if((l2mc_groups[i].type == L2MC_SG_TYPE) && (memcmp(l2mc_groups[i].src_mac, eh0->src_address, 6) != 0))
            continue;

          group = &l2mc_groups[i];
          break;
        }
        
        if (group && vec_len (group->output_sw_if_indices) > 0) 
        {
          u32 *output_swif;
          u32 valid_output_count = 0;
          
          vec_foreach (output_swif, group->output_sw_if_indices) 
          {
            if (*output_swif != sw_if_index0 && *output_swif != 0)
              valid_output_count++;
          }
          
          if (valid_output_count == 0)
          {
            /* No valid outputs - drop packet */
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
                vec_foreach (output_swif, group->output_sw_if_indices)
                {
                  if (*output_swif != sw_if_index0)
                  {
                    vnet_buffer (b0)->sw_if_index[VLIB_TX] = *output_swif;
                    break;
                  }
                }
                goto enqueue_original_buffer;
              }
            }

            /* Send all clones */
            u32 clone_index = 0;
            vec_foreach (output_swif, group->output_sw_if_indices)
            {
              if (*output_swif == sw_if_index0 || *output_swif == 0)
                continue;

              if (clone_index < n_cloned)
              {
                ci0 = lmm->clones[thread_index][clone_index];
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
                  t->group_bd_id = group->bd_id;
                  t->flags = 1;
                }

                /* Set output interface for the clone */
                vnet_buffer (c0)->sw_if_index[VLIB_TX] = *output_swif;

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
          /* No matching group found or group has no members, continue with normal processing */
          ci0 = bi0;
        }
      }
      else
      {
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
