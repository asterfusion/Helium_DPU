/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio/device output node implementation.
 */

#include <onp/onp.h>
#include <onp/drv/inc/dpu.h>

#define foreach_onp_tx_func_error                                             \
  _ (BAD_PARAM, "Invalid parameters")                                         \
  _ (TX_BURST, "TX failed due to insufficient descriptors")

typedef enum
{
#define _(f, s) ONP_TX_FUNC_ERROR_##f,
  foreach_onp_tx_func_error
#undef _
    ONP_TX_FUNC_N_ERROR,
} onp_tx_func_error_t;

static char *onp_tx_func_error_strings[] = {
#define _(n, s) s,
  foreach_onp_tx_func_error
#undef _
};

static void
onp_pktio_intf_counters_clear (u32 instance)
{
  vlib_main_t *vm = vlib_get_main ();
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *op;
  int i, rv;

  op = pool_elt_at_index (om->onp_pktios, instance);

  if (cnxk_drv_pktio_stats_clear (vm, op->cnxk_pktio_index) < 0)
    onp_pktio_warn ("Failed to clear pktio(%d) stats", op->cnxk_pktio_index);

  for (i = 0; i < op->n_rx_q; i++)
    {
      rv = cnxk_drv_pktio_queue_stats_clear (vm, op->cnxk_pktio_index, i, 1);
      if (rv < 0)
	onp_pktio_warn ("Failed to clear pktio(%d) RX queue(%d) stats",
			op->cnxk_pktio_index, i);
    }

  for (i = 0; i < op->n_tx_q; i++)
    {
      rv = cnxk_drv_pktio_queue_stats_clear (vm, op->cnxk_pktio_index, i, 0);
      if (rv < 0)
	onp_pktio_warn ("Failed to clear pktio(%d) TX queue(%d) stats",
			op->cnxk_pktio_index, i);
    }
}

static_always_inline void
onp_pktio_tx_pkts_trace (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, vlib_buffer_t **b, u32 n_left,
			 u8 qid)
{
  onp_tx_trace_t *trace0;

  while (n_left)
    {
      if (b[0]->flags & VLIB_BUFFER_IS_TRACED)
	{
	  trace0 = vlib_add_trace (vm, node, b[0], sizeof (*trace0));
	  trace0->buffer_index = vlib_get_buffer_index (vm, b[0]);
	  trace0->qid = qid;
	  clib_memcpy_fast (&trace0->buf, b[0],
			    sizeof b[0][0] - sizeof b[0]->pre_data);
	  clib_memcpy_fast (trace0->data, vlib_buffer_get_current (b[0]), 256);
	}
      n_left -= 1;
      b += 1;
    }
}

#ifdef VPP_PLATFORM_ET2500
#define ETH_CMD_LINK_BRING_UP 0x0000000000000015
#define ETH_CMD_LINK_BRING_DOWN 0x0000000000000019
#define ET2500_PORT_NUM 16
#define SFP_SYSFS_BASE_PATH "/sys/bus/i2c/devices/3-0040/ET2500_SFP"
#define SFP_TX_CTRL_PREFIX  "SFP_tx_ctrl_"
#define GPIO_OFFSET(hw_if_index) ((hw_if_index) - 9)
typedef struct {
  int a_param;
  int b_param;
} port_mapping_t;

void
onp_pktio_intf_link_up_down(u32 hw_if_index, uword up) {
  static const port_mapping_t port_mappings[] = {
    {-1,-1},
    {0, 3}, //index 1
    {0, 0}, //index 2
    {0, 2}, //index 3
    {0, 1}, //index 4
    {0, 7}, //index 5
    {0, 4}, //index 6
    {0, 6}, //index 7
    {0, 5}, //index 8
    {1, 3}, //index 9
    {1, 0}, //index 10
    {1, 2}, //index 11
    {1, 1}  //index 12
  };
  if (hw_if_index < sizeof(port_mappings) / sizeof(port_mappings[0])) {
    u8 a_param = port_mappings[hw_if_index].a_param;
    u8 b_param = port_mappings[hw_if_index].b_param;

    u64 cmd_value = up ? ETH_CMD_LINK_BRING_UP : ETH_CMD_LINK_BRING_DOWN;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "txcsr RPMX_CMRX_SCRATCHX -a %d -b %d -c 1 0x%016lx",
      a_param, b_param, cmd_value);
    int __attribute__((unused)) ret = system(cmd);
  }
  else if (hw_if_index <= ET2500_PORT_NUM) {
    char path[256];
    snprintf(path, sizeof(path), SFP_SYSFS_BASE_PATH "/" SFP_TX_CTRL_PREFIX "%d",
      hw_if_index);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "echo %d > %s", up ? 0 : 1, path);
    printf("%s\n", cmd);
    int __attribute__((unused)) ret = system(cmd);
    if (!up) {
      char cmd[256];
      snprintf(cmd, sizeof(cmd), "gpioset gpiochip0 %d=0", GPIO_OFFSET(hw_if_index));
      int __attribute__((unused)) ret = system(cmd);
    }
  }
}
#endif


static clib_error_t *
onp_pktio_intf_admin_up_down (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  uword is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;
  vlib_main_t *vm = vlib_get_main ();

  if (od->pktio_flags & ONP_DEVICE_F_ERROR)
    return clib_error_return (0, "Invalid (error) device state");

  if (is_up)
    {
      vnet_hw_interface_set_flags (vnm, od->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
      od->pktio_flags |= ONP_DEVICE_F_ADMIN_UP;
      if (cnxk_drv_pktio_start (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device start failed");
    }
  else
    {
      if (cnxk_drv_pktio_stop (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device stop failed");
      vnet_hw_interface_set_flags (vnm, od->hw_if_index, 0);
      od->pktio_flags &= ~ONP_DEVICE_F_ADMIN_UP;
    }

#ifdef VPP_PLATFORM_ET2500
      onp_pktio_intf_link_up_down(hw_if_index, is_up);
#endif
  return 0;
}

static clib_error_t *
onp_pktio_subif_add_del (vnet_main_t *vnm, u32 hw_if_index,
			 struct vnet_sw_interface_t *st, int is_add)
{
  clib_error_t *error = NULL;
  ASSERT (0);

  return error;
}

static void
onp_pktio_intf_next_node_set (vnet_main_t *vnm, u32 hw_if_index,
			      u32 node_index)
{
  onp_main_t *om = onp_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hw->dev_instance);

  if (node_index == ~0)
    {
      od->per_interface_next_index = node_index;
      return;
    }
}

static clib_error_t *
onp_pktio_mac_addr_add_del (vnet_hw_interface_t *hi, const u8 *addr, u8 is_add)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  int rv;

  rv = cnxk_drv_pktio_mac_addr_add (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address add failed");

  return NULL;
}

static clib_error_t *
onp_pktio_mac_addr_set (vnet_hw_interface_t *hi, const u8 *old_addr,
			const u8 *addr)
{
  onp_main_t *om = onp_get_main ();
  onp_pktio_t *od = vec_elt_at_index (om->onp_pktios, hi->dev_instance);
  int rv;

  rv = cnxk_drv_pktio_mac_addr_set (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address set failed");

  return NULL;
}

/**
 * @brief ONP output node.
 * @node onp-output.
 *
 * ONP output node - Transmit packets using device tx queues.
 *
 * @param vm       vlib_main_t corresponding to the current thread.
 * @param node     vlib_node_runtime_t.
 * @param frame    vlib_frame_t.
 */
/* clang-format off */
VNET_DEVICE_CLASS_TX_FN (onp_pktio_device_class) (vlib_main_t *vm,
					   vlib_node_runtime_t *node,
					   vlib_frame_t *frame)
{
  vnet_interface_output_runtime_t *rd = (void *) node->runtime_data;
  vnet_hw_if_tx_frame_t *tx_frame = vlib_frame_scalar_args (frame);
  onp_pktio_t *od = onp_get_pktio (rd->dev_instance);
  u32 n_left, n_sent, *from, queue, CLIB_UNUSED(is_queue_shared);
  onp_main_t *om = onp_get_main ();
  cnxk_per_thread_data_t *ptd;
	vlib_buffer_t **b;

  from = vlib_frame_vector_args (frame);
  n_left = frame->n_vectors;
  queue = tx_frame->queue_id;
  is_queue_shared = tx_frame->shared_queue;

  ptd = vec_elt_at_index (om->onp_per_thread_data, vm->thread_index);
  vlib_get_buffers (vm, from, ptd->buffers, n_left);
  ptd->pktio_index = od->cnxk_pktio_index;
	b = ptd->buffers;

	if(b[0]->flags & VLIB_BUFFER_DPU_TO_HOST_HDR_VALID)
	{
	  while (n_left >= 8)
	    {
	      vlib_buffer_advance (b[0], -CNXK_D2H_META_SIZE);
	      vlib_buffer_advance (b[1], -CNXK_D2H_META_SIZE);
	      vlib_buffer_advance (b[2], -CNXK_D2H_META_SIZE);
	      vlib_buffer_advance (b[3], -CNXK_D2H_META_SIZE);

	      b +=4;
	      n_left -= 4;
	    }
	  while (n_left)
	  {
	         vlib_buffer_advance (b[0], -CNXK_D2H_META_SIZE);
	         b +=1;
	         n_left -= 1;
	  }

	  n_left = frame->n_vectors;
	}

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    onp_pktio_tx_pkts_trace (vm, node, frame, ptd->buffers, n_left, queue);

   n_sent = od->onp_pktio_txqs[queue].pktio_send_func (vm, node, queue,
						       n_left, ptd);

  if (PREDICT_FALSE (n_sent != n_left))
    {
      u32 n_failed = n_left - n_sent;
      vlib_error_count (vm, node->node_index, ONP_TX_FUNC_ERROR_TX_BURST,
			n_failed);
      return 0;
    }

  return n_sent;
}
/* clang-format on */

VNET_DEVICE_CLASS (onp_pktio_device_class) = {
  .name = "onp",
  .tx_function_n_errors = ONP_TX_FUNC_N_ERROR,
  .tx_function_error_strings = onp_tx_func_error_strings,
  .format_device_name = format_onp_pktio_name,
  .format_device = format_onp_pktio,
  .format_tx_trace = format_onp_pktio_tx_trace,
  .clear_counters = onp_pktio_intf_counters_clear,
  .admin_up_down_function = onp_pktio_intf_admin_up_down,
  .subif_add_del_function = onp_pktio_subif_add_del,
  .rx_redirect_to_node = onp_pktio_intf_next_node_set,
  .mac_addr_change_function = onp_pktio_mac_addr_set,
  .mac_addr_add_del_function = onp_pktio_mac_addr_add_del,
  .format_flow = format_onp_pktio_flow,
  .flow_ops_function = onp_pktio_flow_ops,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
