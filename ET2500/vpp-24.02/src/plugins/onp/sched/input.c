/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP scheduler input node implementation.
 */

#include <onp/onp.h>
#include <onp/input.h>
#include <onp/drv/inc/sched_fp_enq_deq.h>
#include <onp/drv/inc/sched_fp.h>
#include <vnet/interface/rx_queue_funcs.h>

static char *onp_sched_error_strings[] = {
#define _(n, s) s,
  foreach_onp_sched_error
#undef _
};

static_always_inline u32
send_packet_to_post_crypto (vlib_main_t *vm, vlib_node_runtime_t *node,
			    cnxk_per_thread_data_t *ptd,
			    cnxk_sched_work_t *work, u32 n_rx_packets,
			    u64 n_trace)
{
  vlib_buffer_t **bufs = ptd->buffers;
  i32 n_left = n_rx_packets;
  onp_rx_trace_t *trace;
  u32 count = 0;

  if (PREDICT_FALSE (n_trace))
    {
      while (n_trace && n_left)
	{

#if CLIB_DEBUG > 0
	  if (vlib_trace_buffer (vm, node, ptd->next1[count], bufs[count], 1))
#else
	  if (vlib_trace_buffer (vm, node, ptd->next1[count], bufs[count], 0))
#endif
	    {
	      trace = vlib_add_trace (vm, node, bufs[count], sizeof trace[0]);
	      trace->buffer_index = vlib_get_buffer_index (vm, bufs[count]);
	      trace->pktio_index = work->port;
	      trace->tag.as_u32 = cnxk_drv_sched_current_tag_get (vm);
	      trace->tt = cnxk_drv_sched_current_tag_type_get (vm);
	      trace->next_node_index = ptd->next1[count];
	      clib_memcpy_fast (&trace->buffer, bufs[count],
				sizeof trace->buffer -
				  sizeof trace->buffer.pre_data);
	      clib_memcpy_fast (trace->data, bufs[count]->data,
				sizeof trace->data);
	      clib_memcpy_fast (trace->driver_data, bufs[count]->pre_data,
				sizeof trace->driver_data);

	      n_trace--;
	    }
	  count++;
	  n_left--;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_buffer_enqueue_to_next (vm, node, ptd->buffer_indices, ptd->next1,
			       n_rx_packets);
  return n_rx_packets;
}

static_always_inline void
onp_sched_update_next (vlib_main_t *vm, vlib_node_runtime_t *node,
		       cnxk_per_thread_data_t *ptd, u32 n_packets)
{
  vlib_buffer_t **b = ptd->buffers;
  u8 ip_ver;
  u32 i;

  for (i = 0; i < n_packets; i++)
    {
      ip_ver = onp_ipsec_pkt_meta (b[i])->ip_ver;
      vlib_increment_combined_counter (&ipsec_sa_counters,
				       vlib_get_thread_index (),
				       vnet_buffer (b[i])->ipsec.sad_index, -1,
				       -onp_ipsec_pkt_meta (b[i])->sa_bytes);
      ptd->next1[i] = (ip_ver == 4) ?
			      onp_ipsec_main.onp_esp4_enc_post_drop_next :
			      onp_ipsec_main.onp_esp6_enc_post_drop_next;
    }
}

static_always_inline u32
onp_sched_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			cnxk_per_thread_data_t *ptd)
{
  cnxk_sched_work_t work;
  u32 n_rx_packets = 0;
  vlib_buffer_t *bt;
  u8 n_trace;

  bt = &ptd->buffer_template;
  n_trace = vlib_get_trace_count (vm, node);
  onp_update_bt_fields (node, bt, ONP_SCHED_ERROR_NONE);
  ptd->pktio_node_state = 1;

  /*
   * TODO:
   * Both if and else code does the same thing
   * this will be fixed once we have sched fast path function
   * pointers in place
   */
  if (PREDICT_FALSE (n_trace))
    n_rx_packets = cnxk_drv_sched_dequeue (vm, node, &work, ptd);
  else
    n_rx_packets = cnxk_drv_sched_dequeue (vm, node, &work, ptd);

  if (PREDICT_FALSE (!n_rx_packets))
    return 0;

  switch (work.source)
    {
    case CNXK_SCHED_WORK_SOURCE_CRYPTO_ENC_INLINE:
      onp_sched_update_next (vm, node, ptd, n_rx_packets);
      /* Fall through */
    case CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_ENC:
    case CNXK_SCHED_WORK_SOURCE_VWORK_CRYPTO_DEC:
      send_packet_to_post_crypto (vm, node, ptd, &work, n_rx_packets, n_trace);
      return n_rx_packets;

    default:
      ALWAYS_ASSERT (0);
      /* Do nothing */
      break;
    }

  return n_rx_packets;
}

/**
 * @brief ONP sched input node.
 * @node onp-sched-input
 *
 * This is the main ONP scheduler input node.
 * It receives scheduler events from SSO and converts them into vlib buffers.
 * vlib buffers then get enqueued to next VPP stack nodes.
 *
 * @param vm   vlib_main_t corresponding to the current thread.
 * @param node vlib_node_runtime_t.
 * @param f    vlib_frame_t input-node, not used.
 *
 * @par Graph mechanics: buffer metadata, next index usage
 *
 * @em Sets:
 * - <code>b->flags</code> with VLIB_FRAME_TYPE_FAT_FLOW flag.
 *
 * <em>Next Nodes:</em>
 * - Static arcs to: error-drop, ethernet-input, ip4-input,
 *   ip4-input-no-checksum, ip6-input,
 * - per-interface redirection, controlled by
 *   <code>od->per_interface_next_index</code>
 */
/* clang-format off */
VLIB_NODE_FN (onp_sched_input_node) (vlib_main_t *vm,
				     vlib_node_runtime_t *node,
				     vlib_frame_t *f)
{
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);
  ptd->out_user_nstats = 0;

  return onp_sched_input_inline (vm, node, ptd);
}
/* clang-format on */

VLIB_REGISTER_NODE (onp_sched_input_node) = {
  .type = VLIB_NODE_TYPE_INPUT,
  .name = "onp-sched-input",
  .sibling_of = "device-input",
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .state = VLIB_NODE_STATE_DISABLED,
  .format_buffer = format_ethernet_header_with_length,
  .format_trace = format_onp_sched_rx_trace,
  .n_errors = ONP_SCHED_N_ERROR,
  .error_strings = onp_sched_error_strings,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
