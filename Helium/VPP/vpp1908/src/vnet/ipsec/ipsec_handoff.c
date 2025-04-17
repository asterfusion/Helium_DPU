/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file
 * @brief ipsec worker handoff
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/handoff.h>
#include <vnet/fib/ip4_fib.h>
#include <vppinfra/error.h>

static u32 counter[VLIB_MAX_CPUS];

static inline uword
ipsec_worker_handoff_fn_inline (vlib_main_t * vm,
				vlib_node_runtime_t * node,
				vlib_frame_t * frame,u32 fq_index)
{
  u32 n_left_from, *from;
  u16 thread_indices[VLIB_FRAME_SIZE], *ti = thread_indices;
  ipsec_main_t *im = &ipsec_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  vlib_get_buffers (vm, from, bufs, n_left_from);
  b = bufs;

  while (n_left_from > 0)
    {
      u32 next0;
      ip4_header_t *ip0;

      /*should call in handoff*/
      vnet_feature_next (&next0, b[0]);
      ip0 = vlib_buffer_get_current (b[0]);
      if (PREDICT_TRUE((ip0->protocol == IP_PROTOCOL_IPSEC_ESP) && !(b[0]->flags& VLIB_BUFFER_IPSEC_HADNOFF_DISABLE)))
      {
      /*self do not decrypt*/
      if(counter[thread_index]% im->num_workers +1 == thread_index) 
        counter[thread_index] += 1;
      ti[0] = counter[thread_index]% im->num_workers +1;
      counter[thread_index] += 1;
      }
      else
      {
        ti[0] = thread_index;
      }
      b += 1;
      ti += 1;
      n_left_from -= 1;
    }

    vlib_buffer_enqueue_to_thread (vm, fq_index, from, thread_indices,
					 frame->n_vectors, 1);

      /*
      if (n_enq < frame->n_vectors)
      {
      //error count
      }
      */
  return frame->n_vectors;
}


VLIB_NODE_FN (ipsec_worker_handoff_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
  return ipsec_worker_handoff_fn_inline (vm, node, frame, ipsec_main.fq_input_index);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec_worker_handoff_node) = {
  .name = "ipsec-worker-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};
/* *INDENT-ON* */

VLIB_NODE_FN (ipsec6_worker_handoff_node) (vlib_main_t * vm,
						       vlib_node_runtime_t *
						       node,
						       vlib_frame_t * frame)
{
  return ipsec_worker_handoff_fn_inline (vm, node, frame, ipsec_main.fq_input6_index);
}
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ipsec6_worker_handoff_node) = {
  .name = "ipsec6-worker-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
