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

  sw_if_name[0] = '\0';
  if (!vnet_sw_if_index_is_api_valid(encap_sw_if_index)) {
      rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;     
      goto bad_sw_if_index;                       
  }
  clib_memcpy (server_mac, mp->server_mac, 6);

  u32 lcp_magic = ntohl (mp->lcp_magic);
  /* vl_api_ip4_address_t carries the 4 octets in network byte order; copy
   * them straight into a u32 so it matches ip4_address_t.as_u32. */
  u32 client_ip4 = 0;
  u32 client_table_id = ntohl (mp->client_table_id);
  clib_memcpy (&client_ip4, mp->client_ip, 4);

  if(mp->is_add)
  {
      rv = lcp_pppoe_session_add (server_mac, ppp_session_id, encap_sw_if_index,
				  &sw_if_index, sw_if_name, 1, lcp_magic,
				  client_ip4, client_table_id);
  }
  else
  {
      rv = lcp_pppoe_session_add (server_mac, ppp_session_id, encap_sw_if_index,
				  &sw_if_index, sw_if_name, 0, 0, 0, 0);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO2(VL_API_LCP_PPPOE_ADD_DEL_SESSION_REPLY, ({
			  rmp->sw_if_index = htonl(sw_if_index);
			  clib_memcpy(rmp->sw_if_name, sw_if_name, 16);
			  }));
}

static void
vl_api_lcp_pppoe_bulk_add_del_sessions_t_handler (
  vl_api_lcp_pppoe_bulk_add_del_sessions_t *mp)
{
  vl_api_lcp_pppoe_bulk_add_del_sessions_reply_t *rmp;
  u32 count = ntohl (mp->count);
  u32 *sw_if_indices = NULL;
  u8 (*sw_if_names)[16] = NULL;
  /* Collect sw_if_indices of brand-new (not reused) interfaces so we can
   * apply the 12 feature calls in a single batch after all sessions are
   * created, rather than interleaving them with each session add. */
  u32 *new_if_sw_indices = NULL;
  int rv = 0, i;

  if (count > 0)
    {
      vec_validate_init_empty (sw_if_indices, count - 1, (u32) ~0);
      sw_if_names = clib_mem_alloc (count * 16);
      clib_memset (sw_if_names, 0, count * 16);
    }

  for (i = 0; i < (int) count; i++)
    {
      vl_api_lcp_pppoe_session_entry_t *e = &mp->entries[i];
      u32 encap_sw_if_index = ntohl (e->encap_sw_if_index);
      u16 ppp_session_id = ntohs (e->session_id);
      u8 server_mac[6];
      u32 sw_if_index = ~0;
      u8 is_new_if = 0;
      int err;

      if (!vnet_sw_if_index_is_api_valid (encap_sw_if_index))
	{
	  sw_if_indices[i] = ~0;
	  if (rv == 0)
	    rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
	  continue;
	}

      clib_memcpy (server_mac, e->server_mac, 6);
      /* network-byte-order octets -> as_u32 (see single-add handler). */
      u32 client_ip4 = 0;
      u32 client_table_id = ntohl (e->client_table_id);
      clib_memcpy (&client_ip4, e->client_ip, 4);
      err = lcp_pppoe_session_add_bulk (server_mac, ppp_session_id,
					encap_sw_if_index, &sw_if_index,
					sw_if_names[i], e->is_add,
					&is_new_if, ntohl (e->lcp_magic),
					client_ip4, client_table_id);
      sw_if_indices[i] = (err == 0) ? sw_if_index : (u32) ~0;
      if (err != 0 && rv == 0)
	rv = err;

      /* Collect new interfaces that need feature setup. */
      if (err == 0 && is_new_if && e->is_add)
	vec_add1 (new_if_sw_indices, sw_if_index);
    }

  /* Apply the 12 vnet_feature_enable_disable() calls once per new interface,
   * after all sessions have been created.  This batching removes N-1 rounds
   * of feature-arc locking compared to the per-session path. */
  {
    u32 j;
    vec_foreach_index (j, new_if_sw_indices)
      lcp_pppoe_setup_new_if_features (new_if_sw_indices[j]);
    vec_free (new_if_sw_indices);
  }

  /* *INDENT-OFF* */
  REPLY_MACRO3 (VL_API_LCP_PPPOE_BULK_ADD_DEL_SESSIONS_REPLY,
		count * sizeof (vl_api_lcp_pppoe_session_result_t),
  ({
    rmp->count = htonl (count);
    for (i = 0; i < (int) count; i++)
      {
	rmp->results[i].sw_if_index = htonl (sw_if_indices[i]);
	clib_memcpy (rmp->results[i].sw_if_name,
		     sw_if_names[i], 16);
      }
  }));
  /* *INDENT-ON* */

  if (sw_if_names)
    clib_mem_free (sw_if_names);
  vec_free (sw_if_indices);
}

static void
vl_api_lcp_pppoe_hw_if_pool_ensure_t_handler (
  vl_api_lcp_pppoe_hw_if_pool_ensure_t *mp)
{
  vl_api_lcp_pppoe_hw_if_pool_ensure_reply_t *rmp;
  pppoe_main_t *pem = &pppoe_main;
  u32 target = ntohl (mp->target);
  u32 batch = ntohl (mp->batch);
  int rv;

  rv = lcp_pppoe_hw_if_pool_ensure (target, batch);

  /* *INDENT-OFF* */
  REPLY_MACRO2 (VL_API_LCP_PPPOE_HW_IF_POOL_ENSURE_REPLY, ({
    rmp->created = htonl (pem->next_pppoe_dev_instance);
    rmp->free_count = htonl (vec_len (pem->free_pppoe_session_hw_if_indices));
    rmp->is_async = (pem->next_pppoe_dev_instance < pem->hw_if_pool_target
		  || pem->hw_if_pool_growing);
  }));
  /* *INDENT-ON* */
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
