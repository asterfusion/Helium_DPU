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
#include <vppinfra/linux/sysfs.h>

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
typedef enum
{
  ONP_PORT_TYPE_UNKNOWN = 0,
  ONP_PORT_TYPE_RJ45,
  ONP_PORT_TYPE_SFP,
  ONP_PORT_TYPE_QSFP,
} onp_port_type_t;

typedef struct
{
  onp_port_type_t type;
  int a_param; /* scratch params or path id override; -1 unused */
  int b_param; /* scratch register params; -1 when unused */
} onp_port_map_entry_t;

typedef struct
{
  const onp_port_map_entry_t *map;
  u32 port_count;
  const char *sfp_path_fmt;  /* printf format with single %u */
  const char *qsfp_path_fmt; /* printf format with single %u */
  const char *sfp_up;
  const char *sfp_down;
  const char *qsfp_up;
  const char *qsfp_down;
  bool gpio_on_down;
  int gpio_offset_adjust; /* gpio_offset = hw_if_index + adjust */
  i8 *state_cache;	      /* optional dedup cache, 1-based indexed */
} onp_platform_desc_t;

/* ---------------------- ET2500 ---------------------- */

#define ETH_CMD_LINK_BRING_UP 0x0000000000000015
#define ETH_CMD_LINK_BRING_DOWN 0x0000000000000019
#define ET2500_PORT_NUM 16
#define ET2500_SFP_SYSFS_BASE "/sys/bus/i2c/devices/3-0040/ET2500_SFP"
#define ET2500_SFP_TX_CTRL_PREFIX "SFP_tx_ctrl_"

static const onp_port_map_entry_t onp_et2500_port_map[ET2500_PORT_NUM + 1] = {
  { ONP_PORT_TYPE_UNKNOWN, -1, -1 },
  { ONP_PORT_TYPE_RJ45, 0, 3 },  { ONP_PORT_TYPE_RJ45, 0, 0 },
  { ONP_PORT_TYPE_RJ45, 0, 2 },  { ONP_PORT_TYPE_RJ45, 0, 1 },
  { ONP_PORT_TYPE_RJ45, 0, 7 },  { ONP_PORT_TYPE_RJ45, 0, 4 },
  { ONP_PORT_TYPE_RJ45, 0, 6 },  { ONP_PORT_TYPE_RJ45, 0, 5 },
  { ONP_PORT_TYPE_RJ45, 1, 3 },  { ONP_PORT_TYPE_RJ45, 1, 0 },
  { ONP_PORT_TYPE_RJ45, 1, 2 },  { ONP_PORT_TYPE_RJ45, 1, 1 },
  { ONP_PORT_TYPE_SFP, -1, -1 }, { ONP_PORT_TYPE_SFP, -1, -1 },
  { ONP_PORT_TYPE_SFP, -1, -1 }, { ONP_PORT_TYPE_SFP, -1, -1 },
};

/* ---------------------- ET3600 ---------------------- */

#define ET3600_SYSFS_BASE "/sys/bus/i2c/devices/4-0040"
#define ET3600_PORT_NUM 4

static const onp_port_map_entry_t onp_et3600_port_map[ET3600_PORT_NUM + 1] = {
  { ONP_PORT_TYPE_UNKNOWN, -1, -1 },
  { ONP_PORT_TYPE_SFP, 1, -1 },  { ONP_PORT_TYPE_SFP, 2, -1 },
  { ONP_PORT_TYPE_QSFP, 1, -1 }, { ONP_PORT_TYPE_QSFP, 2, -1 },
};

static i8 onp_et3600_last_state[ET3600_PORT_NUM + 1] = { -1, -1, -1, -1,
							 -1 };
/* ---------------------- END ---------------------- */

static const onp_platform_desc_t *
onp_get_platform_desc (onp_main_t *om)
{
  switch (om->platform_type)
    {
    case ONP_PLATFORM_ET2500:
      {
	static const onp_platform_desc_t desc = {
	  .map = onp_et2500_port_map,
	  .port_count = ET2500_PORT_NUM,
	  .sfp_path_fmt = ET2500_SFP_SYSFS_BASE "/" ET2500_SFP_TX_CTRL_PREFIX
			  "%u",
	  .sfp_up = "0",
	  .sfp_down = "1",
	  .gpio_on_down = true,
	  .gpio_offset_adjust = -9,
	};
	return &desc;
      }
    case ONP_PLATFORM_ET3600:
      {
	static const onp_platform_desc_t desc = {
	  .map = onp_et3600_port_map,
	  .port_count = ET3600_PORT_NUM,
	  .sfp_path_fmt = ET3600_SYSFS_BASE "/ET3600_SFP/sfp%u_tx_disable",
	  .qsfp_path_fmt = ET3600_SYSFS_BASE "/ET3600_QSFP/qsfp%u_reset",
	  .sfp_up = "0",
	  .sfp_down = "1",
	  .qsfp_up = "1",
	  .qsfp_down = "0",
	  .state_cache = onp_et3600_last_state,
	};
	return &desc;
      }
    default:
      return NULL;
    }
}

static void
onp_platform_state_cache_reset (const onp_platform_desc_t *pd)
{
  if (!pd || !pd->state_cache)
    return;

  for (u32 i = 0; i <= pd->port_count; i++)
    pd->state_cache[i] = -1;
}

static void
onp_platform_link_up_down (onp_main_t *om, u32 hw_if_index, bool is_up)
{
  const onp_platform_desc_t *pd = onp_get_platform_desc (om);
  const char *platform_name = onp_platform_to_string (om->platform_type);

  if (!pd)
    return;

  if (hw_if_index == 0 || hw_if_index > pd->port_count)
    {
      onp_pktio_warn ("platform %s: hw_if_index %u out of range", platform_name,
		      hw_if_index);
      return;
    }

  const onp_port_map_entry_t *map = &pd->map[hw_if_index];
  u32 port_id = hw_if_index; /* 1-based */

  if (map->type == ONP_PORT_TYPE_UNKNOWN)
    {
      onp_pktio_warn ("platform %s: hw_if_index %u unmapped", platform_name,
		      hw_if_index);
      return;
    }

  if (pd->state_cache && pd->state_cache[hw_if_index] == (i8) is_up)
    return;

  if (map->type == ONP_PORT_TYPE_RJ45)
    {
      if (map->a_param < 0 || map->b_param < 0)
	{
	  onp_pktio_warn ("platform %s: hw_if_index %u rpm params missing",
			  platform_name, hw_if_index);
	  return;
	}

      u64 cmd_value = is_up ? ETH_CMD_LINK_BRING_UP : ETH_CMD_LINK_BRING_DOWN;
      char cmd[128];
      int rc = snprintf (cmd, sizeof (cmd),
			 "txcsr RPMX_CMRX_SCRATCHX -a %d -b %d -c 1 0x%016lx",
			 map->a_param, map->b_param, cmd_value);
      if (rc < 0 || rc >= (int) sizeof (cmd))
	{
	  onp_pktio_warn ("platform %s: format txcsr failed for port %u",
			  platform_name, port_id);
	  return;
	}

      (void) system (cmd);
    }
  else
    {
      const char *path_fmt = map->type == ONP_PORT_TYPE_SFP ? pd->sfp_path_fmt :
							      pd->qsfp_path_fmt;
      const char *val_up = map->type == ONP_PORT_TYPE_SFP ? pd->sfp_up :
							    pd->qsfp_up;
      const char *val_down = map->type == ONP_PORT_TYPE_SFP ? pd->sfp_down :
							      pd->qsfp_down;
      int path_id = map->a_param >= 0 ? map->a_param : (int) port_id;

      if (!path_fmt || !val_up || !val_down)
	{
	  onp_pktio_warn ("platform %s: missing sysfs config for port %u",
			  platform_name, port_id);
	  return;
	}

      char path[256];
      int rc = snprintf (path, sizeof (path), path_fmt, path_id);
      if (rc < 0 || rc >= (int) sizeof (path))
	{
	  onp_pktio_warn ("platform %s: format sysfs path failed for port %u",
			  platform_name, port_id);
	  return;
	}

      clib_sysfs_write ((char *) path, "%s", is_up ? val_up : val_down);
      if (!is_up && pd->gpio_on_down)
	{
	  int gpio_offset = hw_if_index + pd->gpio_offset_adjust;
	  if (gpio_offset >= 0)
	    {
	      char cmd[128];
	      rc = snprintf (cmd, sizeof (cmd), "gpioset gpiochip0 %d=0",
			     gpio_offset);
	      if (rc >= 0 && rc < (int) sizeof (cmd))
		(void) system (cmd);
	    }
	}
    }

  if (pd->state_cache)
    {
      pd->state_cache[hw_if_index] = is_up;
      onp_pktio_notice ("platform %s: port %u set %s", platform_name, port_id,
			is_up ? "up" : "down");
    }
  else
    onp_pktio_notice ("platform %s: port %u set %s", platform_name, port_id,
		      is_up ? "up" : "down");
}

void
onp_platform_ports_force_down (void)
{
  onp_main_t *om = onp_get_main ();
  const onp_platform_desc_t *pd = onp_get_platform_desc (om);

  if (!pd)
    return;

  onp_platform_state_cache_reset (pd);
  for (u32 i = 1; i <= pd->port_count; i++)
    onp_platform_link_up_down (om, i, false);
}
#endif /* VPP_PLATFORM_ET2500 */

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
      // vnet_hw_interface_set_flags (vnm, od->hw_if_index,
			// 	   VNET_HW_INTERFACE_FLAG_LINK_UP);
      od->pktio_flags |= ONP_DEVICE_F_ADMIN_UP;
      if (cnxk_drv_pktio_start (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device start failed");
    }
  else
    {
      if (cnxk_drv_pktio_stop (vm, od->cnxk_pktio_index) < 0)
	return clib_error_return (0, "device stop failed");
      // vnet_hw_interface_set_flags (vnm, od->hw_if_index, 0);
      od->pktio_flags &= ~ONP_DEVICE_F_ADMIN_UP;
    }

#ifdef VPP_PLATFORM_ET2500
  onp_platform_link_up_down (om, hw_if_index, is_up);
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

#ifdef VPP_PLATFORM_ET2500
  if (is_add)
  {
  rv = cnxk_drv_pktio_mac_addr_add (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address add failed");
  }
  else
  {
  rv = cnxk_drv_pktio_mac_addr_del (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address del failed");
  }
#else
  rv = cnxk_drv_pktio_mac_addr_add (vlib_get_main (), od->cnxk_pktio_index,
				    (char *) addr);
  if (rv < 0)
    onp_pktio_notice ("mac address add failed");

#endif
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
