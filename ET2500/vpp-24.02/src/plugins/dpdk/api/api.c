/*
 * Copyright (c) 2026 Cisco and/or its affiliates.
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

#include <stddef.h>

#include <vnet/vnet.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <dpdk/device/dpdk.h>
#include <dpdk/device/dpdk_priv.h>

#define vl_endianfun
#include <plugins/dpdk/api/dpdk.api_enum.h>
#include <plugins/dpdk/api/dpdk.api_types.h>
#undef vl_endianfun

#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

static u32 dpdk_api_msg_id_base;
#define REPLY_MSG_ID_BASE dpdk_api_msg_id_base

#include <vlibapi/api_helper_macros.h>

#define DPDK_REPLY_MACRO(t, api, body)                                        \
  do                                                                          \
    {                                                                         \
      vl_api_##api##_reply_t *reply;                                          \
      vl_api_registration_t *rp;                                              \
                                                                              \
      rp = vl_api_client_index_to_registration (mp->client_index);            \
      if (rp == 0)                                                            \
        return;                                                               \
                                                                              \
      reply = vl_msg_api_alloc (sizeof (*reply));                             \
      if (!reply)                                                             \
        return;                                                               \
                                                                              \
      memset (reply, 0, sizeof (vl_api_##api##_reply_t));                     \
      reply->_vl_msg_id = clib_host_to_net_u16 ((t) + dpdk_api_msg_id_base);  \
      reply->context = mp->context;                                           \
      do                                                                      \
        {                                                                     \
          body;                                                               \
        }                                                                     \
      while (0);                                                              \
      reply->retval = clib_host_to_net_u32 (rv);                              \
      vl_api_send_msg (rp, (u8 *) reply);                                     \
    }                                                                         \
  while (0)

#define htonll(x)                                                             \
  ((1 == htonl (1)) ?                                                         \
     (x) :                                                                    \
     ((u64) htonl ((x) & 0xFFFFFFFF) << 32) | htonl ((x) >> 32))

static int
dpdk_reply_port_stats (dpdk_device_t *xd, vl_api_dpdk_port_stats_data_t *stats)
{
  struct rte_eth_stats eth_stats = {};
  int rv;

  rv = rte_eth_stats_get (xd->port_id, &eth_stats);

  stats->in_octets = htonll (eth_stats.ibytes);
  stats->in_packets = htonll (eth_stats.ipackets);
  stats->in_discards = htonll (eth_stats.imissed);
  stats->in_errors = htonll (eth_stats.ierrors);
  stats->out_octets = htonll (eth_stats.obytes);
  stats->out_packets = htonll (eth_stats.opackets);
  stats->out_errors = htonll (eth_stats.oerrors);
  stats->rx_nombuf = htonll (eth_stats.rx_nombuf);

  return rv;
}

static void
vl_api_dpdk_port_stats_t_handler (vl_api_dpdk_port_stats_t *mp)
{
  u32 sw_if_index = clib_net_to_host_u32 (mp->sw_if_index);
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hi;
  dpdk_main_t *dm = &dpdk_main;
  dpdk_device_t *xd;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (mp);

  hi = vnet_get_sup_hw_interface (vnm, sw_if_index);
  if (hi->dev_class_index != dpdk_device_class.index ||
      hi->dev_instance >= vec_len (dm->devices))
    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;

  BAD_SW_IF_INDEX_LABEL;

  DPDK_REPLY_MACRO (VL_API_DPDK_PORT_STATS_REPLY, dpdk_port_stats, ({
    if (rv == 0)
      {
	xd = vec_elt_at_index (dm->devices, hi->dev_instance);
	rv = dpdk_reply_port_stats (xd, &reply->stats);
      }
  }));
}

#include <dpdk/api/dpdk.api.c>

static clib_error_t *
dpdk_api_init (vlib_main_t *vm)
{
  dpdk_api_msg_id_base = setup_message_id_table ();

  return 0;
}

VLIB_INIT_FUNCTION (dpdk_api_init);
