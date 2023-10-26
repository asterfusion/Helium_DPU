/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
 * Copyright (c) 2022 Marvell Technology, Inc and/or its affiliates.
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

#include <linux/xfrm.h>
#include <linux/udp.h>
#include <netlink/xfrm/sa.h>
#include <netlink/xfrm/sp.h>
#include <netlink/xfrm/template.h>
#include <netlink/xfrm/selector.h>
#include <netlink/xfrm/lifetime.h>
#include <netlink/xfrm/ae.h>
#include <sys/socket.h>
#include <linux/if.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>
#include <vnet/fib/fib.h>
#include <vnet/ipip/ipip.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>

#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_cover.h>
#include <vnet/fib/fib_internal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/mpls_fib.h>

#define NL_RT_COMMON		     uword is_mp_safe
#define NL_RX_BUF_SIZE_DEF	     (1 << 28) /* 256 MB */
#define NL_TX_BUF_SIZE_DEF	     (1 << 20) /* 1 MB */
#define NL_BATCH_SIZE_DEF	     (1 << 11) /* 2048 */
#define NL_BATCH_DELAY_MS_DEF	     50	       /* 50 ms, max 20 batch/s */
#define NL_SYNC_BATCH_LIMIT_DEF	     (1 << 10) /* 1024 */
#define NL_SYNC_BATCH_DELAY_MS_DEF   20	       /* 20ms, max 50 batch/s */
#define NL_SYNC_ATTEMPT_DELAY_MS_DEF 2000      /* 2s */

#define DAY_F64 (1.0 * (24 * 60 * 60))

#define NL_DBG(...)   vlib_log_debug (nl_xfrm_main.nl_logger, __VA_ARGS__);
#define NL_WARN(...)  vlib_log_warn (nl_xfrm_main.nl_logger, __VA_ARGS__);
#define NL_INFO(...)  vlib_log_notice (nl_xfrm_main.nl_logger, __VA_ARGS__);
#define NL_ERROR(...) vlib_log_err (nl_xfrm_main.nl_logger, __VA_ARGS__);

#define FOREACH_XFRM_VFT(__func, __arg)                                       \
  {                                                                           \
    nl_xfrm_main_t *nm = &nl_xfrm_main;                                       \
    nl_xfrm_vft_t *__nv;                                                      \
    vec_foreach (__nv, nm->nl_xfrm_vfts)                                      \
      {                                                                       \
	if (!__nv->__func.cb)                                                 \
	  continue;                                                           \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_sync (vlib_get_main ());                 \
                                                                              \
	__nv->__func.cb (__arg);                                              \
                                                                              \
	if (!__nv->__func.is_mp_safe)                                         \
	  vlib_worker_thread_barrier_release (vlib_get_main ());              \
      }                                                                       \
  }

typedef void (*nl_rt_sa_cb_t) (struct xfrmnl_sa *sa);
typedef void (*nl_rt_sp_cb_t) (struct xfrmnl_sp *sp);

typedef struct nl_rt_sa_cfg_t_
{
  NL_RT_COMMON;

  nl_rt_sa_cb_t cb;
} nl_rt_sa_cfg_t;

typedef struct nl_rt_sp_cfg_t_
{
  NL_RT_COMMON;

  nl_rt_sp_cb_t cb;
} nl_rt_sp_cfg_t;

typedef struct nl_xfrm_vft_t_
{
  nl_rt_sa_cfg_t nvl_rt_xfrm_sa_cfg;
  nl_rt_sp_cfg_t nvl_rt_xfrm_sp_cfg;
} nl_xfrm_vft_t;

typedef enum nl_status_t_
{
  NL_STATUS_NOTIF_PROC,
  NL_STATUS_SYNC,
} nl_status_t;

typedef enum nl_event_type_t_
{
  NL_EVENT_READ,
  NL_EVENT_ERR,
} nl_event_type_t;

typedef struct nl_msg_info
{
  struct nl_msg *msg;
} nl_msg_info_t;

typedef struct nl_xfrm_main
{

  nl_status_t nl_status;
  struct nl_sock *sk_xfrm;
  u8 xfrm_fd;
  u8 is_tunnel_mode;
  vlib_log_class_t nl_logger;
  nl_xfrm_vft_t *nl_xfrm_vfts;
  nl_msg_info_t *nl_msg_queue;
  uword clib_file_index;

  u32 rx_buf_size;
  u32 tx_buf_size;
  u32 batch_size;
  u32 batch_delay_ms;

  u32 sync_batch_limit;
  u32 sync_batch_delay_ms;
  u32 sync_attempt_delay_ms;
} nl_xfrm_main_t;

extern nl_xfrm_main_t *nm;

extern void nl_xfrm_register_vft (const nl_xfrm_vft_t *nv);
void nl_xfrm_sa_cfg (struct xfrmnl_sa *sa);
void nl_xfrm_sp_cfg (struct xfrmnl_sp *sp);
u8 check_for_expiry ();
int send_nl_msg (struct nlmsghdr *nl_hdr, unsigned int groups, u8 msg_type);
uword ipsec_xfrm_expire_process (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vlib_frame_t *frame);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
