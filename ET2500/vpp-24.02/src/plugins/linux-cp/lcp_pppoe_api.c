/*
 * Copyright 2024 Asterfusion Network
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/fib/fib_api.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>
#include <linux-cp/pppoe.h>

#include <linux-cp/lcp_pppoe.api_enum.h>
#include <linux-cp/lcp_pppoe.api_types.h>

static u16 lcp_pppoe_msg_id_base;
#define REPLY_MSG_ID_BASE lcp_pppoe_msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_lcp_pppoe_add_del_session_t_handler (
  vl_api_lcp_pppoe_add_del_session_t *mp)
{
  vl_api_lcp_pppoe_add_del_session_reply_t *rmp;
  int rv = 0;
  u32 encap_sw_if_index = ntohl (mp->encap_sw_if_index);
  u8 server_mac[6];
  u16 ppp_session_id = ntohs(mp->session_id);
  u32 sw_if_index;
  u8 sw_if_name[16];

  if (!vnet_sw_if_index_is_api_valid(encap_sw_if_index)) {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;     
      goto bad_sw_if_index;                       
  }
  clib_memcpy (server_mac, mp->server_mac, 6);

  if(mp->is_add)
  {
      rv = lcp_pppoe_session_add(server_mac, ppp_session_id, encap_sw_if_index, &sw_if_index, sw_if_name, 1);
  }
  else
  {
      rv = lcp_pppoe_session_add(server_mac, ppp_session_id, encap_sw_if_index, &sw_if_index, sw_if_name, 0);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2(VL_API_LCP_PPPOE_ADD_DEL_SESSION_REPLY, ({
			  rmp->sw_if_index = htonl(sw_if_index);
			  clib_memcpy(rmp->sw_if_name, sw_if_name, 16);
			  }));
}

static int
lcp_pppoe_ip_route_add_del_t_handler (vl_api_lcp_pppoe_ip_route_add_del_t * mp, u32 * stats_index)
{
  fib_route_path_t *rpaths = NULL, *rpath;
  fib_entry_flag_t entry_flags;
  vl_api_fib_path_t *apath;
  fib_prefix_t pfx;
  u32 fib_index;
  int rv, ii;

  entry_flags = FIB_ENTRY_FLAG_NONE;
  ip_prefix_decode (&mp->route.prefix, &pfx);

  rv = fib_api_table_id_decode (pfx.fp_proto,
				ntohl (mp->route.table_id), &fib_index);
  if (0 != rv)
    goto out;

  if (0 != mp->route.n_paths)
    vec_validate (rpaths, mp->route.n_paths - 1);

  for (ii = 0; ii < mp->route.n_paths; ii++)
    {
      apath = &mp->route.paths[ii];
      rpath = &rpaths[ii];

      rv = fib_api_path_decode (apath, rpath);

      if ((rpath->frp_flags & FIB_ROUTE_PATH_LOCAL) &&
	  (~0 == rpath->frp_sw_if_index))
	entry_flags |= (FIB_ENTRY_FLAG_CONNECTED | FIB_ENTRY_FLAG_LOCAL);

      if (0 != rv)
	goto out;
    }

  rv = fib_api_route_add_del (mp->is_add, mp->is_multipath, fib_index, &pfx,
			      pppoe_fib_src, entry_flags, rpaths);

  if (mp->is_add && 0 == rv)
    *stats_index = fib_table_entry_get_stats_index (fib_index, &pfx);

out:
  vec_free (rpaths);

  return (rv);
}

static void
vl_api_lcp_pppoe_ip_route_add_del_t_handler (vl_api_lcp_pppoe_ip_route_add_del_t * mp)
{
  vl_api_lcp_pppoe_ip_route_add_del_reply_t *rmp;
  u32 stats_index = ~0;
  int rv;

  rv = lcp_pppoe_ip_route_add_del_t_handler (mp, &stats_index);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_LCP_PPPOE_IP_ROUTE_ADD_DEL_REPLY,
  ({
    rmp->stats_index = htonl (stats_index);
  }))
  /* *INDENT-ON* */
}

/*
 * Set up the API message handling tables
 */
#include <linux-cp/lcp_pppoe.api.c>

static clib_error_t *
lcp_pppoe_api_init (vlib_main_t *vm)
{
  /* Ask for a correctly-sized block of API message decode slots */
  lcp_pppoe_msg_id_base = setup_message_id_table ();

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_pppoe_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
