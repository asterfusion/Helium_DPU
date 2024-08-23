/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "octep_cp_lib.h"
#include "cp_compat.h"
#include "octep_ctrl_net.h"
#include "octep_hw.h"
#include "octep_input.h"
#include "octep_action.h"
#include "octep_config.h"

#define LOOP_RX_BUF_CNT 6

static struct octep_cp_msg rx_msg[LOOP_RX_BUF_CNT];
static int rx_num = LOOP_RX_BUF_CNT;
static int max_msg_sz = sizeof (union octep_ctrl_net_max_data);

extern struct octep_cp_lib_cfg cp_lib_cfg;
extern struct octep_pf_vf_cfg cfg_idx;

static const uint32_t resp_hdr_sz = sizeof (union octep_ctrl_net_resp_hdr);
static const uint32_t mtu_sz = sizeof (struct octep_ctrl_net_h2f_resp_cmd_mtu);
static const uint32_t mac_sz = sizeof (struct octep_ctrl_net_h2f_resp_cmd_mac);
static const uint32_t state_sz =
  sizeof (struct octep_ctrl_net_h2f_resp_cmd_state);
static const uint32_t link_info_sz = sizeof (struct octep_ctrl_net_link_info);
static const uint32_t if_stats_sz =
  sizeof (struct octep_ctrl_net_h2f_resp_cmd_get_stats);
static const uint32_t info_sz =
  sizeof (struct octep_ctrl_net_h2f_resp_cmd_get_info);

#define CTRL_NET_RESP_OFFLOADS_SZ sizeof (struct octep_ctrl_net_offloads)

/*
 * Initialize max receive burst size and each message size.
 *
 */

int
octep_cp_initialize_receive_vector ()
{
  int i, j;
  struct octep_cp_msg *msg;

  clib_warning ("Loop: Init\n");
  /* For now only support single buffer messages */
  for (i = 0; i < cp_lib_cfg.ndoms; i++)
    {
      for (j = 0; j < cp_lib_cfg.doms[i].npfs; j++)
	{
	  if (cp_lib_cfg.doms[i].pfs[j].max_msg_sz < max_msg_sz)
	    return -EINVAL;
	}
    }

  for (i = 0; i < rx_num; i++)
    {
      msg = &rx_msg[i];
      msg->info.s.sz = max_msg_sz;
      msg->sg_num = 1;
      msg->sg_list[0].sz = max_msg_sz;
      msg->sg_list[0].msg = calloc (1, max_msg_sz);
      if (!msg->sg_list[0].msg)
	goto mem_alloc_fail;
    }

  clib_warning ("Loop: using single buffer with msg sz %u.\n", max_msg_sz);

  return 0;

mem_alloc_fail:
  for (i = 0; i < LOOP_RX_BUF_CNT; i++)
    {
      msg = &rx_msg[i];
      if (msg->sg_list[0].msg)
	free (msg->sg_list[0].msg);
      msg->sg_list[0].sz = 0;
      msg->sg_num = 0;
    }

  return -ENOMEM;
}

static int
process_mtu (struct if_cfg *iface, struct octep_ctrl_net_h2f_req *req,
	     struct octep_ctrl_net_h2f_resp *resp)
{
  int ret = 0;

  if (req->mtu.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      resp->mtu.val = iface->max_rx_pktlen;
      clib_warning ("Cmd: get mtu : %u\n", resp->mtu.val);
      ret = mtu_sz;
    }
  else
    {
      iface->mtu = req->mtu.val;
      clib_warning ("Cmd: set mtu : %u\n", req->mtu.val);
      octep_update_pktio (req->mtu.cmd, req->mtu.val);
    }
  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return ret;
}

static int
process_mac (struct if_cfg *iface, struct octep_ctrl_net_h2f_req *req,
	     struct octep_ctrl_net_h2f_resp *resp)
{
  int ret = 0;

  if (req->mac.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      memcpy (&resp->mac.addr, &iface->mac_addr, ETH_ALEN);
      ret = mac_sz;
      clib_warning ("Cmd: get mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
		    resp->mac.addr[0], resp->mac.addr[1], resp->mac.addr[2],
		    resp->mac.addr[3], resp->mac.addr[4], resp->mac.addr[5]);
    }
  else
    {
      memcpy (&iface->mac_addr, &req->mac.addr, ETH_ALEN);
      clib_warning ("Cmd: set mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
		    req->mac.addr[0], req->mac.addr[1], req->mac.addr[2],
		    req->mac.addr[3], req->mac.addr[4], req->mac.addr[5]);
    }
  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return ret;
}

static int
process_get_if_stats (struct if_stats *ifstats,
		      struct octep_ctrl_net_h2f_req *req,
		      struct octep_ctrl_net_h2f_resp *resp)
{
  /* Struct if_stats = struct octep_ctrl_net_h2f_resp_cmd_get_stats */
  memcpy (&resp->if_stats, ifstats, if_stats_sz);
  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;
  clib_warning ("Cmd: get if stats\n");

  return if_stats_sz;
}

static int
process_link_status (struct if_cfg *iface, struct octep_ctrl_net_h2f_req *req,
		     struct octep_ctrl_net_h2f_resp *resp)
{
  int ret = 0;

  if (req->link.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      resp->link.state = iface->link_state;
      ret = state_sz;
    }
  else
    iface->link_state = req->link.state;

  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return ret;
}

static int
process_rx_state (struct if_cfg *iface, struct octep_ctrl_net_h2f_req *req,
		  struct octep_ctrl_net_h2f_resp *resp)
{
  int ret = 0;

  if (req->rx.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      resp->rx.state = iface->rx_state;
      ret = state_sz;
    }
  else
    iface->rx_state = req->rx.state;

  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return ret;
}

static int
process_link_info (struct if_cfg *iface, struct octep_ctrl_net_h2f_req *req,
		   struct octep_ctrl_net_h2f_resp *resp)
{
  int ret = 0;

  if (req->link_info.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      resp->link_info.supported_modes = iface->supported_modes;
      resp->link_info.advertised_modes = iface->advertised_modes;
      resp->link_info.autoneg = iface->autoneg;
      resp->link_info.pause = iface->pause_mode;
      resp->link_info.speed = iface->speed;
      ret = link_info_sz;
    }
  else
    {
      iface->advertised_modes = req->link_info.info.advertised_modes;
      iface->autoneg = req->link_info.info.autoneg;
      iface->pause_mode = req->link_info.info.pause;
      iface->speed = req->link_info.info.speed;
    }
  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return ret;
}

static int
process_get_info (struct octep_fw_info *info,
		  struct octep_ctrl_net_h2f_req *req,
		  struct octep_ctrl_net_h2f_resp *resp)
{
  memcpy (&resp->info.fw_info, info, sizeof (struct octep_fw_info));
  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return info_sz;
}

clib_error_t *
octep_enable_disable_offload_feature_arc (u8 *if_name, bool enable)
{
  uword *p;
  u32 hw_if_index;
  clib_error_t *error = NULL;
  vnet_hw_interface_t *hi = NULL;
  vnet_feature_registration_t *reg;
  vnet_main_t *vnm = vnet_get_main ();

  if (!(p = hash_get (vnm->interface_main.hw_interface_by_name, if_name)))
    return clib_error_return (0, "Unknown interfacse name (%s)... ",
			      (const char *) if_name);

  hw_if_index = p[0];
  hi = vnet_get_hw_interface (vnm, hw_if_index);

  reg = vnet_get_feature_reg ((const char *) DEVICE_INPUT,
			      (const char *) DPU_INPUT_NODE);
  if (reg == 0)
    {
      error = clib_error_return (
	0,
	"Feature (%s) not registered to arc (%s)... See 'show "
	"features verbose' for valid feature/arc combinations. ",
	DPU_INPUT_NODE, DEVICE_INPUT);
      return error;
    }

  if (reg->enable_disable_cb)
    error = reg->enable_disable_cb (hi->sw_if_index, enable);

  if (error)
    return error;

  vnet_feature_enable_disable ((const char *) DEVICE_INPUT,
			       (const char *) DPU_INPUT_NODE, hi->sw_if_index,
			       enable, 0, 0);

  reg = vnet_get_feature_reg ((const char *) DEVICE_OUTPUT,
			      (const char *) DPU_OUTPUT_NODE);
  if (reg == 0)
    return clib_error_return (
      0,
      "Feature (%s) not registered to arc (%s)... See 'show "
      "features verbose' for valid feature/arc combinations. ",
      DPU_OUTPUT_NODE, DEVICE_OUTPUT);

  if (reg->enable_disable_cb)
    error = reg->enable_disable_cb (hi->sw_if_index, enable);

  if (error)
    return error;

  vnet_feature_enable_disable ((const char *) DEVICE_OUTPUT,
			       (const char *) DPU_OUTPUT_NODE, hi->sw_if_index,
			       enable, 0, 0);

  return error;
}

static int
process_offloads (struct octep_fw_info *info,
		  struct octep_ctrl_net_h2f_req *req,
		  struct octep_ctrl_net_h2f_resp *resp, struct if_cfg *iface)
{

  if (req->offloads.cmd == OCTEP_CTRL_NET_CMD_GET)
    {
      resp->offloads.rx_offloads = info->rx_offloads;
      resp->offloads.tx_offloads = info->tx_offloads;
      resp->offloads.ext_offloads = info->ext_offloads;
      resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;
      return CTRL_NET_RESP_OFFLOADS_SZ;
    }

  /**
   * Disable/enable feature arc based on Host request or existing config.
   */
  if (!req->offloads.offloads.rx_offloads &&
      !req->offloads.offloads.tx_offloads)
    {
      if (octep_enable_disable_offload_feature_arc (iface->if_name, 0))
	return 0;
    }
  else if (!info->rx_offloads && !info->tx_offloads)
    {
      if (octep_enable_disable_offload_feature_arc (iface->if_name, 1))
	return 0;
    }

  info->rx_offloads = req->offloads.offloads.rx_offloads;
  info->tx_offloads = req->offloads.offloads.tx_offloads;
  info->ext_offloads = req->offloads.offloads.ext_offloads;

  resp->hdr.s.reply = OCTEP_CTRL_NET_REPLY_OK;

  return CTRL_NET_RESP_OFFLOADS_SZ;
}

static int
process_msg (union octep_cp_msg_info *ctx, struct octep_cp_msg *msg)
{
  struct octep_ctrl_net_h2f_req *req;
  struct octep_ctrl_net_h2f_resp resp = { 0 };
  struct octep_cp_msg resp_msg;
  struct if_cfg *iface;
  struct if_stats *ifdata;
  struct octep_fw_info *info;
  int err = 0, resp_sz = 0;

  err =
    app_config_get_if_from_msg_info (ctx, &msg->info, &iface, &ifdata, &info);
  if (err)
    {
      clib_warning ("Invalid msg[%lx]\n", msg->info.words[0]);
      return err;
    }

  req = (struct octep_ctrl_net_h2f_req *) msg->sg_list[0].msg;
  resp.hdr.words[0] = req->hdr.words[0];
  iface->host_if_id = req->hdr.s.sender;
  resp_sz = resp_hdr_sz;
  switch (req->hdr.s.cmd)
    {
    case OCTEP_CTRL_NET_H2F_CMD_MTU:
      resp_sz += process_mtu (iface, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_MAC:
      resp_sz += process_mac (iface, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_GET_IF_STATS:
      resp_sz += process_get_if_stats (ifdata, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_LINK_STATUS:
      resp_sz += process_link_status (iface, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_RX_STATE:
      resp_sz += process_rx_state (iface, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_LINK_INFO:
      resp_sz += process_link_info (iface, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_GET_INFO:
      resp_sz += process_get_info (info, req, &resp);
      break;
    case OCTEP_CTRL_NET_H2F_CMD_OFFLOADS:
      resp_sz += process_offloads (info, req, &resp, iface);
      break;
    default:
      clib_warning ("Unhandled Cmd : %u\n", req->hdr.s.cmd);
      resp_sz = 0;
      break;
    }

  if (resp_sz >= resp_hdr_sz)
    {
      resp_msg.info = msg->info;
      resp_msg.info.s.sz = resp_sz;
      resp_msg.sg_num = 1;
      resp_msg.sg_list[0].sz = resp_sz;
      resp_msg.sg_list[0].msg = &resp;
      octep_cp_lib_send_msg_resp (ctx, &resp_msg, 1);
      ifdata->tx_stats.pkts++;
      ifdata->tx_stats.octs += resp_sz;
    }

  ifdata->rx_stats.pkts++;
  ifdata->rx_stats.octets += msg->info.s.sz;

  return 0;
}

int
loop_process_msgs ()
{
  union octep_cp_msg_info ctx;
  struct octep_cp_msg *msg;
  int ret, i, j, m;

  for (i = 0; i < cp_lib_cfg.ndoms; i++)
    {
      ctx.s.pem_idx = cp_lib_cfg.doms[i].idx;
      for (j = 0; j < cp_lib_cfg.doms[i].npfs; j++)
	{
	  ctx.s.pf_idx = cp_lib_cfg.doms[i].pfs[j].idx;
	  ret = octep_cp_lib_recv_msg (&ctx, rx_msg, rx_num);
	  for (m = 0; m < ret; m++)
	    {
	      msg = &rx_msg[m];
	      process_msg (&ctx, msg);
	      /* Library will overwrite msg size in header so reset it */
	      msg->info.s.sz = max_msg_sz;
	    }
	}
    }

  return 0;
}

int
octep_cp_uninitialize_receive_vector ()
{
  int i;

  clib_warning ("%s\n", __func__);

  for (i = 0; i < rx_num; i++)
    {
      if (rx_msg[i].sg_list[0].msg)
	free (rx_msg[i].sg_list[0].msg);
      rx_msg[i].sg_list[0].sz = 0;
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
