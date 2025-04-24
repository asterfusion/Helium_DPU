/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <isolation_group/isolation_group.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} isolation_group_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 * format_isolation_group_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  isolation_group_trace_t * t = va_arg (*args, isolation_group_trace_t *);
  
  s = format (s, "ISOLATION_GROUP: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t isolation_group_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_isolation_group_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum 
{
#define _(sym,str) ISOLATION_GROUP_ERROR_##sym,
  foreach_isolation_group_error
#undef _
  ISOLATION_GROUP_N_ERROR,
} isolation_group_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * isolation_group_error_strings[] = 
{
#define _(sym,string) string,
  foreach_isolation_group_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum 
{
  ISOLATION_GROUP_NEXT_DROP,
  ISOLATION_GROUP_N_NEXT,
} isolation_group_next_t;

static u32 get_parent_sw_if_index(u32 sw_if_index) {
    vnet_sw_interface_t *sw = vnet_get_sw_interface(vnet_get_main(), sw_if_index);
    if (sw && sw->type == VNET_SW_INTERFACE_TYPE_SUB) {
        return sw->sup_sw_if_index;
    }
    return sw_if_index;
}

always_inline uword
isolation_group_inline (vlib_main_t * vm,
              vlib_node_runtime_t * node, vlib_frame_t * frame,
         int is_ip4, int is_trace)
{
  u32 n_left_from, *from;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  bool find = false;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;
  next = nexts;

  while (n_left_from > 0)
    {
      find = false;
      u32 rx_sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
      u32 tx_sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_TX];

      rx_sw_if_index = get_parent_sw_if_index(rx_sw_if_index);
      tx_sw_if_index = get_parent_sw_if_index(tx_sw_if_index);
      
      int mapping_index = find_source_port_mapping(rx_sw_if_index);
      if (mapping_index != -1) {
          u32 group_id = source_port_group_mappings[mapping_index].group_id;
          int group_index = find_isolation_group(group_id);
          if (group_index != -1) {
              for (int i = 0; i < isolation_groups[group_index].num_destinations; i++) {
                  clib_warning("isolation group Checking destination_sw_if_indices[%d]: %d", i, isolation_groups[group_index].destination_sw_if_indices[i]);
                  if (isolation_groups[group_index].destination_sw_if_indices[i] == tx_sw_if_index) {
                      next[0] = ISOLATION_GROUP_NEXT_DROP;
                      find = true;
                      break;
                  }
              }
          }
    
      }

      if(!find)
      {
        vnet_feature_next_u16 (&next[0], b[0]);
      }

      if (is_trace)
    {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
        {
          isolation_group_trace_t *t = 
                    vlib_add_trace (vm, node, b[0], sizeof (*t));
          t->next_index = next[0];
              t->sw_if_index = vnet_buffer(b[0])->sw_if_index[VLIB_RX];
        }
    }

      b += 1;
      next += 1;
      n_left_from -= 1;
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_NODE_FN (isolation_group_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
                             vlib_frame_t * frame)
{
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    return isolation_group_inline (vm, node, frame, 1 /* is_ip4 */ ,
                1 /* is_trace */ );
  else
    return isolation_group_inline (vm, node, frame, 1 /* is_ip4 */ ,
                0 /* is_trace */ );
}

/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (isolation_group_node) = 
{
  .name = "isolation_group",
  .vector_size = sizeof (u32),
  .format_trace = format_isolation_group_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(isolation_group_error_strings),
  .error_strings = isolation_group_error_strings,

  .n_next_nodes = ISOLATION_GROUP_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [ISOLATION_GROUP_NEXT_DROP] = "error-drop",
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
