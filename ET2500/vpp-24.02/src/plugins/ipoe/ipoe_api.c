/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

#include <vnet/ethernet/ethernet_types_api.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <ipoe/ipoe.api_enum.h>
#include <ipoe/ipoe.api_types.h>

#define REPLY_MSG_ID_BASE ipoe_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ipoe_interface_enable_disable_t_handler (
  vl_api_ipoe_interface_enable_disable_t *mp)
{
  vl_api_ipoe_interface_enable_disable_reply_t *rmp;
  int rv = ipoe_interface_enable_disable (
    ntohl (mp->sw_if_index), mp->enable, mp->access_mode, mp->input_path);

  REPLY_MACRO (VL_API_IPOE_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ipoe_session_add_del_t_handler (vl_api_ipoe_session_add_del_t *mp)
{
  ipoe_main_t *im = &ipoe_main;
  vl_api_ipoe_session_add_del_reply_t *rmp;
  ip4_address_t user_ip4;
  mac_address_t user_mac;
  ipoe_interface_t *intf;
  ipoe_session_t *session;
  uword *p;
  u32 sw_if_index;
  u32 counter_index = 0;
  int rv;

  if (!mp->is_add)
    {
      rv = ipoe_session_del (clib_net_to_host_u64 (mp->index));
      REPLY_MACRO (VL_API_IPOE_SESSION_ADD_DEL_REPLY);
      return;
    }

  sw_if_index = ntohl (mp->sw_if_index);
  if (sw_if_index >= vec_len (im->interfaces) ||
      (mp->access_mode != IPOE_ACCESS_MODE_L2 &&
       mp->access_mode != IPOE_ACCESS_MODE_L3))
    {
      rv = IPOE_ERROR_INVALID_VALUE;
      REPLY_MACRO (VL_API_IPOE_SESSION_ADD_DEL_REPLY);
      return;
    }
  intf = vec_elt_at_index (im->interfaces, sw_if_index);
  if (!intf->enabled || intf->access_mode != mp->access_mode)
    {
      rv = IPOE_ERROR_INVALID_VALUE;
      REPLY_MACRO (VL_API_IPOE_SESSION_ADD_DEL_REPLY);
      return;
    }

  ip4_address_decode (mp->user_ip4, &user_ip4);
  mac_address_decode (mp->user_mac, &user_mac);
  rv = ipoe_session_add (
    clib_net_to_host_u64 (mp->index),
    clib_net_to_host_u64 (mp->generation), sw_if_index, &user_ip4,
    &user_mac, mp->has_user_mac, mp->admin_state,
    ntohl (mp->lease_timeout_sec), clib_net_to_host_u64 (mp->lease_expiry));
  if (rv == IPOE_OK)
    {
      p = hash_get (im->session_by_index,
		    clib_net_to_host_u64 (mp->index));
      if (!p || pool_is_free_index (im->sessions, p[0]))
	rv = IPOE_ERROR_NO_SUCH_ENTRY;
      else
	{
	  session = pool_elt_at_index (im->sessions, p[0]);
	  counter_index = session->counter_index;
	}
    }

  REPLY_MACRO2 (VL_API_IPOE_SESSION_ADD_DEL_REPLY,
		({ rmp->counter_index = htonl (counter_index); }));
}

static void
vl_api_ipoe_session_set_state_t_handler (
  vl_api_ipoe_session_set_state_t *mp)
{
  vl_api_ipoe_session_set_state_reply_t *rmp;
  int rv = ipoe_session_set_state (clib_net_to_host_u64 (mp->index),
				   clib_net_to_host_u64 (mp->generation),
				   mp->admin_state);

  REPLY_MACRO (VL_API_IPOE_SESSION_SET_STATE_REPLY);
}

static void
vl_api_ipoe_session_add_batch_t_handler (
  vl_api_ipoe_session_add_batch_t *mp)
{
  vl_api_ipoe_session_add_batch_reply_t *rmp;
  ipoe_session_add_batch_entry_t entries[IPOE_SESSION_ADD_BATCH_MAX];
  ipoe_session_add_batch_result_t results[IPOE_SESSION_ADD_BATCH_MAX];
  vl_api_registration_t *reg;
  u32 count = ntohl (mp->count);
  u32 i;
  int rv = IPOE_OK;

  if (!count || count > IPOE_SESSION_ADD_BATCH_MAX)
    {
      count = 0;
      rv = IPOE_ERROR_INVALID_VALUE;
    }
  for (i = 0; i < count; i++)
    {
      ip4_address_decode (mp->entries[i].user_ip4, &entries[i].user_ip4);
      mac_address_decode (mp->entries[i].user_mac, &entries[i].user_mac);
      entries[i].external_index = clib_net_to_host_u64 (mp->entries[i].index);
      entries[i].generation = clib_net_to_host_u64 (mp->entries[i].generation);
      entries[i].lease_expiry =
	clib_net_to_host_u64 (mp->entries[i].lease_expiry);
      entries[i].lease_timeout = ntohl (mp->entries[i].lease_timeout_sec);
      entries[i].access_mode = mp->entries[i].access_mode;
      entries[i].sw_if_index = ntohl (mp->entries[i].sw_if_index);
      entries[i].has_user_mac = mp->entries[i].has_user_mac;
      entries[i].admin_state = mp->entries[i].admin_state;
      if (entries[i].access_mode != IPOE_ACCESS_MODE_L2 &&
	  entries[i].access_mode != IPOE_ACCESS_MODE_L3)
	entries[i].lease_timeout = 0;
    }
  if (rv == IPOE_OK)
    rv = ipoe_session_add_batch (entries, count, results);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  rmp = vl_msg_api_alloc (sizeof (*rmp) +
			  count * sizeof (rmp->results[0]));
  clib_memset (rmp, 0, sizeof (*rmp) + count * sizeof (rmp->results[0]));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE +
				   VL_API_IPOE_SESSION_ADD_BATCH_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->count = htonl (count);
  for (i = 0; i < count; i++)
    {
      rmp->results[i].index = clib_host_to_net_u64 (results[i].external_index);
      rmp->results[i].generation = clib_host_to_net_u64 (results[i].generation);
      rmp->results[i].retval = htonl (results[i].retval);
      rmp->results[i].counter_index = htonl (results[i].counter_index);
    }
  vl_api_send_msg (reg, (u8 *) rmp);
}

static void
vl_api_ipoe_session_quiesce_snapshot_batch_t_handler (
  vl_api_ipoe_session_quiesce_snapshot_batch_t *mp)
{
  vl_api_ipoe_session_quiesce_snapshot_batch_reply_t *rmp;
  ipoe_session_snapshot_result_t results[IPOE_SESSION_SNAPSHOT_BATCH_MAX];
  u64 indices[IPOE_SESSION_SNAPSHOT_BATCH_MAX];
  u64 generations[IPOE_SESSION_SNAPSHOT_BATCH_MAX];
  vl_api_registration_t *reg;
  u32 count = ntohl (mp->count);
  u32 i;
  int rv = IPOE_OK;

  if (!count || count > IPOE_SESSION_SNAPSHOT_BATCH_MAX)
    {
      count = 0;
      rv = IPOE_ERROR_INVALID_VALUE;
    }
  for (i = 0; i < count; i++)
    {
      indices[i] = clib_net_to_host_u64 (mp->entries[i].index);
      generations[i] =
	clib_net_to_host_u64 (mp->entries[i].generation);
    }
  if (rv == IPOE_OK)
    rv = ipoe_session_quiesce_snapshot_batch (
      indices, generations, count, results);

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;
  rmp = vl_msg_api_alloc (sizeof (*rmp) +
			  count * sizeof (rmp->results[0]));
  clib_memset (rmp, 0, sizeof (*rmp) + count * sizeof (rmp->results[0]));
  rmp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE +
				   VL_API_IPOE_SESSION_QUIESCE_SNAPSHOT_BATCH_REPLY);
  rmp->context = mp->context;
  rmp->retval = htonl (rv);
  rmp->count = htonl (count);
  for (i = 0; i < count; i++)
    {
      rmp->results[i].index = clib_host_to_net_u64 (results[i].external_index);
      rmp->results[i].generation = clib_host_to_net_u64 (results[i].generation);
      rmp->results[i].retval = htonl (results[i].retval);
    }
  vl_api_send_msg (reg, (u8 *) rmp);
}

#include <vnet/format_fns.h>
#include <ipoe/ipoe.api.c>

static clib_error_t *
ipoe_api_init (vlib_main_t *vm)
{
  (void) vm;
  ipoe_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_INIT_FUNCTION (ipoe_api_init);
