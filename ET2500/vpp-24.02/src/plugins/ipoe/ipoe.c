/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_in_out_feat_arc.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

ipoe_main_t ipoe_main;

int
ipoe_qinq_route_add (const ipoe_qinq_route_t *route)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_qinq_route_t *stored;
  u32 route_index;
  int rv;

  if (!route || route->route_id == ~0 ||
      hash_get (im->qinq_route_by_id, route->route_id))
    return IPOE_ERROR_ALREADY_EXISTS;
  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 1);
  if (rv != IPOE_OK)
    return rv;

  pool_get (im->qinq_routes, stored);
  *stored = *route;
  route_index = stored - im->qinq_routes;
  hash_set (im->qinq_route_by_id, route->route_id, route_index);
  return IPOE_OK;
}

int
ipoe_qinq_route_update (const ipoe_qinq_route_t *route)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_qinq_route_t old;
  ipoe_qinq_route_t *stored;
  uword *p;
  int same_prefix;
  int rv;

  if (!route)
    return IPOE_ERROR_INVALID_VALUE;
  p = hash_get (im->qinq_route_by_id, route->route_id);
  if (!p)
    return IPOE_ERROR_NO_SUCH_ENTRY;
  stored = pool_elt_at_index (im->qinq_routes, p[0]);
  old = *stored;
  same_prefix = old.table_id == route->table_id &&
		old.user_ip4.as_u32 == route->user_ip4.as_u32;

  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 1);
  if (rv != IPOE_OK)
    return rv;
  if (!same_prefix)
    ipoe_qinq_route_add_del (old.table_id, &old.user_ip4,
			     old.sw_if_index, 0);
  *stored = *route;
  return IPOE_OK;
}

int
ipoe_qinq_route_delete (u32 route_id)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_qinq_route_t *route;
  uword *p = hash_get (im->qinq_route_by_id, route_id);
  int rv;

  if (!p)
    return IPOE_ERROR_NO_SUCH_ENTRY;
  route = pool_elt_at_index (im->qinq_routes, p[0]);
  rv = ipoe_qinq_route_add_del (route->table_id, &route->user_ip4,
				route->sw_if_index, 0);
  if (rv != IPOE_OK)
    return rv;
  hash_unset (im->qinq_route_by_id, route_id);
  pool_put (im->qinq_routes, route);
  return IPOE_OK;
}

__clib_export const char *
ipoe_error_string (int rv)
{
  switch (rv)
    {
    case IPOE_OK: return "ok";
    case IPOE_ERROR_INVALID_INTERFACE: return "invalid interface";
    case IPOE_ERROR_INVALID_VALUE: return "invalid value";
    case IPOE_ERROR_OBJECT_IN_USE: return "object in use";
    case IPOE_ERROR_ALREADY_EXISTS: return "entry already exists";
    case IPOE_ERROR_NO_SUCH_ENTRY: return "no such entry";
    case IPOE_ERROR_IP_CONFLICT: return "interface and user IPv4 conflict";
    case IPOE_ERROR_GENERATION_STALE: return "generation stale";
    case IPOE_ERROR_FEATURE_FAILED: return "feature enable/disable failed";
    default: return "unknown error";
    }
}

static int
ipoe_l2_feature_enable_disable (u32 sw_if_index, u8 enable)
{
  int rv;

  rv = vnet_l2_feature_enable_disable ("l2-input-ip4", "ipoe-l2-input",
				       sw_if_index, enable, 0, 0);
  if (rv)
    {
#if 0
      clib_warning ("ipoe interface feature operation failed "
		    "sw_if_index=%u enable=%u rv=%d",
		    sw_if_index, enable, rv);
#endif
      return IPOE_ERROR_FEATURE_FAILED;
    }
  return IPOE_OK;
}

static int
ipoe_ip4_feature_enable_disable (u32 sw_if_index, u8 enable)
{
  int rv;

  rv = vnet_feature_enable_disable ("ip4-unicast", "ipoe-ip4-input",
				    sw_if_index, enable, 0, 0);
  if (rv)
    {
#if 0
      clib_warning ("ipoe interface feature operation failed "
		    "arc=ip4-unicast node=ipoe-ip4-input "
		    "sw_if_index=%u enable=%u rv=%d",
		    sw_if_index, enable, rv);
#endif
      return IPOE_ERROR_FEATURE_FAILED;
    }
  return IPOE_OK;
}

static int
ipoe_ip6_input_feature_enable_disable (u32 sw_if_index, u8 enable)
{
  int rv;

  rv = vnet_l2_feature_enable_disable ("l2-input-ip6",
				       "ipoe-l2-ip6-input", sw_if_index,
				       enable, 0, 0);
  if (rv)
    return IPOE_ERROR_FEATURE_FAILED;
  rv = vnet_feature_enable_disable ("ip6-unicast", "ipoe-ip6-input",
				    sw_if_index, enable, 0, 0);
  if (rv)
    {
      vnet_l2_feature_enable_disable ("l2-input-ip6",
	"ipoe-l2-ip6-input", sw_if_index, !enable, 0, 0);
      return IPOE_ERROR_FEATURE_FAILED;
    }
  return IPOE_OK;
}

static int
ipoe_output_feature_enable_disable (u32 sw_if_index, u8 enable)
{
  int rv;

  rv = vnet_l2_feature_enable_disable ("l2-output-ip4", "ipoe-output",
				       sw_if_index, enable, 0, 0);
  if (rv)
    {
#if 0
      clib_warning ("ipoe interface feature operation failed "
		    "arc=l2-output-ip4 node=ipoe-output "
		    "sw_if_index=%u enable=%u rv=%d",
		    sw_if_index, enable, rv);
#endif
      return IPOE_ERROR_FEATURE_FAILED;
    }

  rv = vnet_feature_enable_disable ("ip4-output", "ipoe-output",
				    sw_if_index, enable, 0, 0);
  if (rv)
    {
      vnet_l2_feature_enable_disable ("l2-output-ip4", "ipoe-output",
				      sw_if_index, !enable, 0, 0);
#if 0
      clib_warning ("ipoe interface feature operation failed "
		    "arc=ip4-output node=ipoe-output "
		    "sw_if_index=%u enable=%u rv=%d",
		    sw_if_index, enable, rv);
#endif
      return IPOE_ERROR_FEATURE_FAILED;
    }
  rv = vnet_l2_feature_enable_disable ("l2-output-ip6",
				       "ipoe-ip6-output", sw_if_index,
				       enable, 0, 0);
  if (rv)
    goto rollback_ip4;
  rv = vnet_feature_enable_disable ("ip6-output", "ipoe-ip6-output",
				    sw_if_index, enable, 0, 0);
  if (rv)
    {
      vnet_l2_feature_enable_disable ("l2-output-ip6",
	"ipoe-ip6-output", sw_if_index, !enable, 0, 0);
      goto rollback_ip4;
    }
  return IPOE_OK;

rollback_ip4:
  vnet_feature_enable_disable ("ip4-output", "ipoe-output", sw_if_index,
			       !enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip4", "ipoe-output",
				  sw_if_index, !enable, 0, 0);
  return IPOE_ERROR_FEATURE_FAILED;
}

static int
ipoe_input_feature_enable_disable (u32 sw_if_index, u8 enable)
{
  int rv;

  rv = ipoe_l2_feature_enable_disable (sw_if_index, enable);
  if (rv != IPOE_OK)
    return rv;

  rv = ipoe_ip4_feature_enable_disable (sw_if_index, enable);
  if (rv != IPOE_OK)
    {
      ipoe_l2_feature_enable_disable (sw_if_index, !enable);
      return rv;
    }

  rv = ipoe_ip6_input_feature_enable_disable (sw_if_index, enable);
  if (rv != IPOE_OK)
    {
      ipoe_ip4_feature_enable_disable (sw_if_index, !enable);
      ipoe_l2_feature_enable_disable (sw_if_index, !enable);
      return rv;
    }

  return IPOE_OK;
}

const char *
ipoe_access_mode_name (u8 mode)
{
  return mode == IPOE_INTERNAL_ACCESS_MODE_L2 ? "l2" : "l3";
}

const char *
ipoe_input_path_name (u8 input_path)
{
  return input_path == IPOE_INPUT_IP4 ? "ip4-input" : "l2-input";
}

int
ipoe_interface_enable_disable (u32 sw_if_index, u8 enable,
			       u8 access_mode, u8 input_path)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_interface_t *intf;

  if (!vnet_sw_interface_is_api_valid (im->vnet_main, sw_if_index))
    return IPOE_ERROR_INVALID_INTERFACE;

  vlib_worker_thread_barrier_sync (im->vlib_main);
  vec_validate (im->interfaces, sw_if_index);
  vlib_worker_thread_barrier_release (im->vlib_main);
  intf = vec_elt_at_index (im->interfaces, sw_if_index);

  if (!enable)
    {

      int rv;

      if (!intf->enabled)
	return IPOE_OK;
      ipoe_ip6_binding_flush_interface (sw_if_index);
      ipoe_qinq_ip6_route_flush_interface (sw_if_index);
      rv = ipoe_session_flush_interface (sw_if_index);
      if (rv != IPOE_OK)
	return rv;
      rv = ipoe_output_feature_enable_disable (sw_if_index, 0);
      if (rv != IPOE_OK)
	return rv;
      rv = ipoe_input_feature_enable_disable (sw_if_index, 0);
      if (rv != IPOE_OK)
	return rv;
      vlib_worker_thread_barrier_sync (im->vlib_main);
      clib_memset (intf, 0, sizeof (*intf));
      intf->sw_if_index = sw_if_index;
      vlib_worker_thread_barrier_release (im->vlib_main);
#if 0
      clib_warning ("ipoe interface disable sw_if_index=%u", sw_if_index);
#endif
      return IPOE_OK;
    }

  if ((access_mode != IPOE_INTERNAL_ACCESS_MODE_L2 &&
       access_mode != IPOE_INTERNAL_ACCESS_MODE_L3) ||
      (input_path != IPOE_INPUT_L2 && input_path != IPOE_INPUT_IP4))
    return IPOE_ERROR_INVALID_VALUE;

  if (intf->enabled)
    {
      if (intf->access_mode == access_mode && intf->input_path == input_path)
	return IPOE_OK;
      return IPOE_ERROR_ALREADY_EXISTS;
    }

  if (ipoe_input_feature_enable_disable (sw_if_index, 1) != IPOE_OK)
    return IPOE_ERROR_FEATURE_FAILED;
  if (ipoe_output_feature_enable_disable (sw_if_index, 1) != IPOE_OK)
    {
      ipoe_input_feature_enable_disable (sw_if_index, 0);
      return IPOE_ERROR_FEATURE_FAILED;
    }

  vlib_worker_thread_barrier_sync (im->vlib_main);
  intf->sw_if_index = sw_if_index;
  intf->access_mode = access_mode;
  intf->input_path = input_path;
  intf->enabled = 1;
  vlib_worker_thread_barrier_release (im->vlib_main);
#if 0
  clib_warning ("ipoe interface enable sw_if_index=%u mode=%s input=%s",
		sw_if_index,
		ipoe_access_mode_name (access_mode),
		ipoe_input_path_name (input_path));
#endif
  return IPOE_OK;
}

static clib_error_t *
ipoe_init (vlib_main_t *vm)
{
  ipoe_main_t *im = &ipoe_main;
  im->vlib_main = vm;
  im->vnet_main = vnet_get_main ();
  im->session_by_index = hash_create (0, sizeof (uword));
  im->session_by_user = hash_create (0, sizeof (uword));
  im->qinq_route_by_id = hash_create (0, sizeof (uword));
  clib_bihash_init_24_8 (&im->ip6_binding_hash, "ipoe-ip6-binding",
			  1024, 1 << 20);
  im->upstream_forward.stat_segment_name =
    "/ipoe/session/upstream-forward";
  im->downstream_forward.stat_segment_name =
    "/ipoe/session/downstream-forward";
  im->upstream_gate_drop.stat_segment_name =
    "/ipoe/session/upstream-gate-drop";
  im->downstream_gate_drop.stat_segment_name =
    "/ipoe/session/downstream-gate-drop";
  ipoe_timer_init (vm);
  ipoe_qinq_dpo_module_init ();
  return 0;
}

VLIB_INIT_FUNCTION (ipoe_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "IPoE standalone session and lease manager",
};
