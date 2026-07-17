#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip_types_api.h>
#include <vnet/feature/feature.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#include <ha_sync/ha_sync.h>
#include <ha_sync/ha_sync.api_enum.h>
#include <ha_sync/ha_sync.api_types.h>

#define REPLY_MSG_ID_BASE ha_sync_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_ha_sync_enable_disable_t_handler (vl_api_ha_sync_enable_disable_t *mp)
{
  vl_api_ha_sync_enable_disable_reply_t *rmp;
  i32 rv = ha_sync_apply_enable_disable (mp->enable);

  REPLY_MACRO (VL_API_HA_SYNC_ENABLE_DISABLE_REPLY);
}

static void
vl_api_ha_sync_add_del_src_address_t_handler (vl_api_ha_sync_add_del_src_address_t *mp)
{
  vl_api_ha_sync_add_del_src_address_reply_t *rmp;
  i32 rv;
  ip4_address_t addr;

  if (mp->is_add)
    {
      ip4_address_decode (mp->src_address, &addr);
      rv = ha_sync_apply_add_del_src_address (1, &addr);
    }
  else
    rv = ha_sync_apply_add_del_src_address (0, 0);

  REPLY_MACRO (VL_API_HA_SYNC_ADD_DEL_SRC_ADDRESS_REPLY);
}

static void
vl_api_ha_sync_add_del_peer_address_t_handler (vl_api_ha_sync_add_del_peer_address_t *mp)
{
  vl_api_ha_sync_add_del_peer_address_reply_t *rmp;
  i32 rv;
  ip4_address_t addr;

  if (mp->is_add)
    {
      ip4_address_decode (mp->peer_address, &addr);
      rv = ha_sync_apply_add_del_peer_address (1, &addr);
    }
  else
    rv = ha_sync_apply_add_del_peer_address (0, 0);

  REPLY_MACRO (VL_API_HA_SYNC_ADD_DEL_PEER_ADDRESS_REPLY);
}

static void
vl_api_ha_sync_add_del_interface_t_handler (vl_api_ha_sync_add_del_interface_t *mp)
{
  vl_api_ha_sync_add_del_interface_reply_t *rmp;
  i32 rv;
  u32 sw_if_index = ntohl (mp->sw_if_index);

  rv = ha_sync_apply_add_del_interface (mp->is_add, sw_if_index);
  REPLY_MACRO (VL_API_HA_SYNC_ADD_DEL_INTERFACE_REPLY);
}

static void
vl_api_ha_sync_set_config_t_handler (vl_api_ha_sync_set_config_t *mp)
{
  vl_api_ha_sync_set_config_reply_t *rmp;
  i32 rv = ha_sync_apply_set_config (ntohl (mp->domain_id),
                                     ntohs (mp->packet_size),
                                     ntohl (mp->retransmit_times),
                                     ntohl (mp->retransmit_interval_ms),
                                     ntohl (mp->heartbeat_interval_ms),
                                     ntohl (mp->heartbeat_max_fail_counts));

  REPLY_MACRO (VL_API_HA_SYNC_SET_CONFIG_REPLY);
}

static void
vl_api_ha_sync_get_config_t_handler (vl_api_ha_sync_get_config_t *mp)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  vl_api_ha_sync_get_config_reply_t *rmp;
  i32 rv = 0;

  REPLY_MACRO2 (VL_API_HA_SYNC_GET_CONFIG_REPLY,
                ({
                  rmp->enabled = hsm->enabled;
                  rmp->config_ready = hsm->config_ready;
                  rmp->connection_established = hsm->connection_established;
                  rmp->src_is_set = hsm->src_is_set;
                  rmp->peer_is_set = hsm->peer_is_set;
                  rmp->sw_if_index_is_set = hsm->sw_if_index_is_set;
                  ip4_address_encode (&hsm->src_address, rmp->src_address);
                  ip4_address_encode (&hsm->peer_address, rmp->peer_address);
                  rmp->sw_if_index = htonl (hsm->sw_if_index);
                  rmp->src_port = htons (hsm->src_port);
                  rmp->dst_port = htons (hsm->dst_port);
                  rmp->domain_id = htonl (hsm->domain_id);
                  rmp->packet_size = htons (hsm->packet_size);
                  rmp->retransmit_times = htonl (hsm->retransmit_times);
                  rmp->retransmit_interval_ms =
                    htonl ((u32) (hsm->retransmit_interval * 1000.0));
                  rmp->snapshot_sequence = htons (hsm->snapshot_sequence);
                }));

  (void) mp;
}

static void
vl_api_ha_sync_reset_config_t_handler (vl_api_ha_sync_reset_config_t *mp)
{
  vl_api_ha_sync_reset_config_reply_t *rmp;
  i32 rv = ha_sync_apply_reset_config ();

  (void) mp;
  REPLY_MACRO (VL_API_HA_SYNC_RESET_CONFIG_REPLY);
}

#include <vnet/format_fns.h>
#include <ha_sync/ha_sync.api.c>

static clib_error_t *
ha_sync_api_hookup (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  (void) vm;

  hsm->msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_API_INIT_FUNCTION (ha_sync_api_hookup);
