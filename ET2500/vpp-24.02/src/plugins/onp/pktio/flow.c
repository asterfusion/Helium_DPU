/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP pktio flow implementation.
 */

#include <onp/onp.h>

static int
onp_pktio_flow_add (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_id,
		    u32 flow_index, uword *private_data)
{
  vnet_flow_t *flow = vnet_get_flow (flow_index);
  u32 flow_action;
  i32 rv;

  flow_action = flow->actions;

  /* Add special case for inline IPsec */
  if ((flow_action & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE) &&
      flow->redirect_queue == ~0 && flow->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP)
    {
      rv = cnxk_drv_pktio_flow_inl_dev_update (vnm, op, dev_id, flow,
					       private_data);
      if (rv)
	{
	  onp_pktio_warn (
	    "cnxk_drv_pktio_flow_inl_dev_update failed with rv %d", rv);
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }
  else
    {
      rv = cnxk_drv_pktio_flow_update (vnm, op, dev_id, flow, private_data);
      if (rv)
	{
	  onp_pktio_warn ("cnxk_drv_pktio_flow_update failed with rv %d", rv);
	  return VNET_FLOW_ERROR_NOT_SUPPORTED;
	}
    }

  return 0;
}

static int
onp_pktio_flow_del (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_id,
		    u32 flow_index, uword *priv_data)
{
  vnet_flow_t *flow;
  int rv = 0;

  flow = vnet_get_flow (flow_index);
  rv = cnxk_drv_pktio_flow_update (vnm, op, dev_id, flow, priv_data);
  if (rv)
    {
      onp_pktio_warn ("cnxk_drv_pktio_flow_update failed");
      return VNET_FLOW_ERROR_NOT_SUPPORTED;
    }

  return 0;
}

int
onp_pktio_flow_ops (vnet_main_t *vnm, vnet_flow_dev_op_t op, u32 dev_id,
		    u32 flow_index, uword *priv_data)
{
  if (op == VNET_FLOW_DEV_OP_ADD_FLOW)
    return onp_pktio_flow_add (vnm, op, dev_id, flow_index, priv_data);

  if (op == VNET_FLOW_DEV_OP_DEL_FLOW)
    return onp_pktio_flow_del (vnm, op, dev_id, flow_index, priv_data);

  return VNET_FLOW_ERROR_NOT_SUPPORTED;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
