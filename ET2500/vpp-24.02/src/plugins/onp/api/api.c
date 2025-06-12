/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <stddef.h>

#include <vnet/vnet.h>
#include <vpp/app/version.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <onp/onp.h>

/* Define generated endian-swappers */
#define vl_endianfun
#include <plugins/onp/api/onp.api_enum.h>
#include <plugins/onp/api/onp.api_types.h>
#undef vl_endianfun

/* Instantiate all the print functions we know about */
#define vl_print(handle, ...) vlib_cli_output (handle, __VA_ARGS__)

/**
 * Base message ID for the plugin
 */
static u32 onp_base_msg_id;

#include <vlibapi/api_helper_macros.h>

#define mp_be_to_cpu(x, bits)                                                 \
  do                                                                          \
    {                                                                         \
      if ((bits) == 16)                                                       \
	x = clib_net_to_host_u16 (x);                                         \
      if ((bits) == 32)                                                       \
	x = clib_net_to_host_u32 (x);                                         \
      if ((bits) == 64)                                                       \
	x = clib_net_to_host_u64 (x);                                         \
    }                                                                         \
  while (0)

#define ONP_MP_ENDIAN_MACRO(api, body)                                        \
  do                                                                          \
    {                                                                         \
      body;                                                                   \
    }                                                                         \
  while (0)

#define mp_cpu_to_be(x, bits)                                                 \
  do                                                                          \
    {                                                                         \
      if ((bits) == 16)                                                       \
	x = clib_host_to_net_u16 (x);                                         \
      if ((bits) == 32)                                                       \
	x = clib_host_to_net_u32 (x);                                         \
      if ((bits) == 64)                                                       \
	x = clib_host_to_net_u64 (x);                                         \
    }                                                                         \
  while (0)

#define ONP_REPLY_MACRO(t, api, body)                                         \
  do                                                                          \
    {                                                                         \
      vl_api_##api##_reply_t *reply;                                          \
      vl_api_registration_t *rp;                                              \
                                                                              \
      /* Send response message back */                                        \
      rp = vl_api_client_index_to_registration (mp->client_index);            \
      if (rp == 0)                                                            \
	return;                                                               \
                                                                              \
      reply = vl_msg_api_alloc (sizeof (*reply));                             \
      if (!reply)                                                             \
	return;                                                               \
                                                                              \
      memset (reply, 0, sizeof (vl_api_##api##_reply_t));                     \
      reply->_vl_msg_id = clib_host_to_net_u16 ((t) + onp_base_msg_id);       \
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

static void
vl_api_onp_show_version_t_handler (vl_api_onp_show_version_t *mp)
{
  int rv = 0;

  /* clang-format off */
  ONP_MP_ENDIAN_MACRO(onp_show_version, ({
   /*
    * All fields required to be used from API msg needs
    * to be called as shown below. They will be converted
    * to host-endian format before usage in the handler
    * when called in binary API mode.
    *
    * mp_be_to_cpu(mp->field16, 16);
    * mp_be_to_cpu(mp->field32, 32);
    * mp_be_to_cpu(mp->field64, 64);
    */
  }));

  /*
   * NOTE: Updates to reply field MUST be done only inside
   * this macro body.
   */

  ONP_REPLY_MACRO(VL_API_ONP_SHOW_VERSION_REPLY, onp_show_version, ({
    reply->patch_version = ONP_PATCH_VERSION;
    reply->major_version = ONP_MAJOR_VERSION;
    reply->minor_version = ONP_MINOR_VERSION;
    mp_cpu_to_be(reply->patch_version, 32);
    mp_cpu_to_be(reply->major_version, 32);
    mp_cpu_to_be(reply->minor_version, 32);
  }));
  /* clang-format on */
}

static void
onp_update_per_thread_stats (u64 **stat, u64 *pool_stat, u32 n_threads,
			     u8 *is_valid, u64 *threads_with_stats,
			     unsigned int n_threads_with_stats,
			     vl_api_onp_show_counters_reply_t *reply)
{
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  u32 idx, thread_idx = 0;

  for (idx = 0; idx < n_threads_with_stats; idx++)
    {

      thread_idx = threads_with_stats[idx];
      clib_memcpy (reply->td[thread_idx].thread_name,
		   vlib_worker_threads[thread_idx].name,
		   sizeof (reply->td[thread_idx].thread_name));

      /* clang-format off */
#define _(i, s, n, v)                                                 \
      cm = &om->onp_counters.s##_counters;                            \
      clib_memcpy (reply->cd[i].counter_name, cm->name,               \
                   sizeof (reply->cd[i].counter_name));               \
      if (is_valid[i] && stat[i][thread_idx])                         \
        reply->td[thread_idx].counter_value[i] = stat[i][thread_idx];
      foreach_onp_counters;
#undef _
      /* clang-format on */

      if (pool_stat[thread_idx])
	reply->td[thread_idx].pool_stat = pool_stat[thread_idx];
    }
}

static void
vl_api_onp_show_counters_t_handler (vl_api_onp_show_counters_t *mp)
{
  u32 cnt_idx = 0, thread_idx = 0, n_threads_with_stats = 0;
  u32 n_threads = vlib_get_n_threads ();
  u8 is_valid[ONP_MAX_COUNTERS] = { 0 };
  u64 *stat[ONP_MAX_COUNTERS] = { 0 };
  u64 threads_with_stats[n_threads];
  onp_main_t *om = onp_get_main ();
  vlib_simple_counter_main_t *cm;
  counter_t *counters = NULL;
  u64 *pool_stat = NULL;
  u8 verbose = 0;
  int rv = 0;

  /* clang-format off */
  ONP_MP_ENDIAN_MACRO(onp_show_counters, ({
   /*
    * All fields required to be used from API msg needs
    * to be called as shown below. They will be converted
    * to host-endian format before usage in the handler
    * when called in binary API mode.
    *
    * mp_be_to_cpu(mp->field16, 16);
    * mp_be_to_cpu(mp->field32, 32);
    * mp_be_to_cpu(mp->field64, 64);
    */
  }));

#define _(i, s, n, v)                                                         \
  cm = &om->onp_counters.s##_counters;                                        \
  vec_validate_init_empty (stat[i], n_threads, 0);                            \
  for (thread_idx = 0; thread_idx < n_threads; thread_idx++)                  \
    {                                                                         \
      counters = cm->counters[thread_idx];                                    \
      stat[i][thread_idx] = counters[0];                                      \
    }
  foreach_onp_counters;
#undef _
  /* clang-format on */

  vec_validate_init_empty (pool_stat, n_threads, 0);

  n_threads_with_stats = onp_get_per_thread_stats (
    stat, pool_stat, n_threads, verbose, is_valid, threads_with_stats);

  /* clang-format off */
  /*
   * NOTE: Updates to reply field MUST be done only inside
   * this macro body.
   */

  ONP_REPLY_MACRO(VL_API_ONP_SHOW_COUNTERS_REPLY, onp_show_counters, ({

    reply->n_threads_with_stats = n_threads_with_stats;
    reply->onp_max_counters = ONP_MAX_COUNTERS;
    onp_update_per_thread_stats (stat, pool_stat, n_threads,
				 is_valid, threads_with_stats,
				 n_threads_with_stats, reply);
    for (thread_idx = 0; thread_idx < n_threads; thread_idx++)
      {
	for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
	  {
	    reply->global_counter_value[cnt_idx] += stat[cnt_idx][thread_idx];
	    reply->n_global_stats++;
	    mp_cpu_to_be (reply->td[thread_idx].counter_value[cnt_idx], 64);
	  }

	reply->global_pool_stat += pool_stat[thread_idx];
	mp_cpu_to_be (reply->td[thread_idx].pool_stat, 64);
      }

    for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    mp_cpu_to_be (reply->global_counter_value[cnt_idx], 64);

    mp_cpu_to_be (reply->global_pool_stat, 64);

  }));

  /* clang-format on */

  for (cnt_idx = 0; cnt_idx < ONP_MAX_COUNTERS; cnt_idx++)
    vec_free (stat[cnt_idx]);

  vec_free (pool_stat);
}

static void
vl_api_onp_set_port_speed_t_handler(vl_api_onp_set_port_speed_t* mp) {
  onp_main_t* om = onp_get_main();
  u32 sw_if_index = ntohl(mp->sw_if_index);
  u32 port_speed = ntohl(mp->port_speed);
  vlib_main_t* vm = vlib_get_main();
  onp_pktio_t* pktio;
  int rv = 1;

  VALIDATE_SW_IF_INDEX(mp);

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ? __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->sw_if_index == sw_if_index)
    {
      rv = 0;
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = {};
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  if (!link_info.is_autoneg && link_info.speed != port_speed) {
    link_info.speed = port_speed;
    cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);
  }

  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_SPEED_REPLY, onp_set_port_speed,);
}

static void
vl_api_onp_set_port_autoneg_t_handler(vl_api_onp_set_port_autoneg_t* mp) {
  onp_main_t *om = onp_get_main();
  vlib_main_t *vm = vlib_get_main();

  u32 sw_if_index = ntohl(mp->sw_if_index);
  bool autoneg_enable = mp->autoneg;
  onp_pktio_t* pktio;
  int rv = 1;

  VALIDATE_SW_IF_INDEX(mp);

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ?
    __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->sw_if_index == sw_if_index)
    {
      rv = 0;
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = {};
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  link_info.is_autoneg = autoneg_enable;
  cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);

  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_AUTONEG_REPLY, onp_set_port_autoneg,);
}

static void
vl_api_onp_get_port_autoneg_t_handler(vl_api_onp_get_port_autoneg_t* mp) {
  onp_main_t* om = onp_get_main();
  vlib_main_t* vm = vlib_get_main();

  u32 sw_if_index = ntohl(mp->sw_if_index);
  cnxk_pktio_link_info_t link_info = {};
  onp_pktio_t* pktio;
  int rv = 1;

  VALIDATE_SW_IF_INDEX(mp);

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ?
    __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->sw_if_index == sw_if_index) {
      rv = 0;
      break;
    }
  }


  ONP_REPLY_MACRO(VL_API_ONP_GET_PORT_AUTONEG_REPLY, onp_get_port_autoneg, ({
  rv = cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
    reply->autoneg = link_info.is_autoneg;
    }));
  return;

  BAD_SW_IF_INDEX_LABEL;
  ONP_REPLY_MACRO(VL_API_ONP_GET_PORT_AUTONEG_REPLY, onp_get_port_autoneg, );
  return;
}

static void
vl_api_onp_set_port_duplex_t_handler(vl_api_onp_set_port_duplex_t* mp) {
  onp_main_t *om = onp_get_main();
  vlib_main_t *vm = vlib_get_main();

  u32 sw_if_index = ntohl(mp->sw_if_index);
  bool duplex_enable = mp->duplex;
  onp_pktio_t* pktio;
  int rv = 1;

  VALIDATE_SW_IF_INDEX(mp);

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ?
    __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->sw_if_index == sw_if_index)
    {
      rv = 0;
      break;
    }
  }

  cnxk_pktio_link_info_t link_info = {};
  cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
  link_info.is_full_duplex = duplex_enable;
  cnxk_drv_pktio_link_advertise_set(vm, pktio->cnxk_pktio_index, &link_info);

  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_DUPLEX_REPLY, onp_set_port_duplex,);
}

static void
vl_api_onp_get_port_duplex_t_handler(vl_api_onp_get_port_duplex_t* mp) {
  onp_main_t *om = onp_get_main();
  vlib_main_t *vm = vlib_get_main();

  u32 sw_if_index = ntohl(mp->sw_if_index);
  cnxk_pktio_link_info_t link_info = {};
  onp_pktio_t* pktio;
  int rv = 1;

  VALIDATE_SW_IF_INDEX(mp);

  for (pktio = (om->onp_pktios); pktio < ((om->onp_pktios) + ((om->onp_pktios) ?
    __vec_len((void*)(om->onp_pktios)) : 0)); pktio++) {
    if (pktio->sw_if_index == sw_if_index)
    {
      rv = 0;
      break;
    }
  }


  ONP_REPLY_MACRO(VL_API_ONP_GET_PORT_DUPLEX_REPLY, onp_get_port_duplex, ({
  rv = cnxk_drv_pktio_link_info_get(vm, pktio->cnxk_pktio_index, &link_info);
		reply->duplex = link_info.is_full_duplex;
    }));
  return;

  BAD_SW_IF_INDEX_LABEL;
  ONP_REPLY_MACRO(VL_API_ONP_GET_PORT_DUPLEX_REPLY, onp_get_port_duplex, );
  return;
}

static void
vl_api_onp_set_port_dscp_tc_map_t_handler(vl_api_onp_set_port_dscp_tc_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  u8 dscp = mp->dscp;
  u8 tc = mp->tc;
  hash_set(hi->dscp_to_tc, dscp, tc);
  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_DSCP_TC_MAP_REPLY, onp_set_port_dscp_tc_map, );
}

static void
vl_api_onp_set_port_dot1p_tc_map_t_handler(vl_api_onp_set_port_dot1p_tc_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  u8 dot1p = mp->dot1p;
  u8 tc = mp->tc;
  hash_set(hi->dot1p_to_tc, dot1p, tc);
  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_DOT1P_TC_MAP_REPLY, onp_set_port_dot1p_tc_map, );
}

static void
vl_api_onp_set_port_tc_queue_map_t_handler(vl_api_onp_set_port_tc_queue_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  u8 tc = mp->tc;
  u8 queue = mp->queue;
  hash_set(hi->tc_to_queue, tc, queue);
  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_SET_PORT_TC_QUEUE_MAP_REPLY, onp_set_port_tc_queue_map, );
}

static void
vl_api_onp_rm_port_dscp_tc_map_t_handler(vl_api_onp_rm_port_dscp_tc_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  hash_free(hi->dscp_to_tc);
  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_RM_PORT_DSCP_TC_MAP_REPLY, onp_rm_port_dscp_tc_map, );
}

static void
vl_api_onp_rm_port_dot1p_tc_map_t_handler(vl_api_onp_rm_port_dot1p_tc_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  hash_free(hi->dot1p_to_tc);
  BAD_SW_IF_INDEX_LABEL;

  ONP_REPLY_MACRO(VL_API_ONP_RM_PORT_DOT1P_TC_MAP_REPLY, onp_rm_port_dot1p_tc_map, );
}

static void
vl_api_onp_rm_port_tc_queue_map_t_handler(vl_api_onp_rm_port_tc_queue_map_t* mp) {
  vnet_main_t* vnm = vnet_get_main();
  int rv;

  VALIDATE_SW_IF_INDEX(mp);
  u32 sw_if_index = ntohl(mp->sw_if_index);
  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);

  hash_free(hi->tc_to_queue);
  BAD_SW_IF_INDEX_LABEL;
  ONP_REPLY_MACRO(VL_API_ONP_RM_PORT_TC_QUEUE_MAP_REPLY, onp_rm_port_tc_queue_map, );
}
static void
vl_api_onp_interface_stats_t_handler(vl_api_onp_interface_stats_t* mp) {
  u64 xstats[CNXK_PKTIO_MAX_XSTATS_COUNT] = { 0 };
  u32 sw_if_index = ntohl(mp->sw_if_index);
  int rv;

  vnet_main_t* vnm = vnet_get_main();
  vlib_main_t* vm = vlib_get_main();
  if (!vnet_sw_interface_is_api_valid(vnm,sw_if_index))
    goto bad_sw_if_index;

  vnet_hw_interface_t* hi = vnet_get_hw_interface(vnm, sw_if_index);
  onp_main_t* om = onp_get_main();
  onp_pktio_t* op;
  u32 xstats_count;
  u16 cpi;

  if (pool_is_free_index(om->onp_pktios, hi->dev_instance))
    goto bad_sw_if_index;

  op = pool_elt_at_index(om->onp_pktios, hi->dev_instance);
  cpi = op->cnxk_pktio_index;
  xstats_count = op->xstats_count;

  ONP_REPLY_MACRO(VL_API_ONP_INTERFACE_STATS_REPLY, onp_interface_stats, ({
	clib_memset (&xstats, 0, sizeof (xstats));
	rv = cnxk_drv_pktio_xstats_get(vm, cpi, xstats, xstats_count);
	for(int i = 0; i < xstats_count; i++)
		reply->onp_xstats.stats[i] = htonl(xstats[i]);
    }));
  return;

  BAD_SW_IF_INDEX_LABEL;
  ONP_REPLY_MACRO(VL_API_ONP_INTERFACE_STATS_REPLY, onp_interface_stats, ({
        rv = VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }));
  return;
}

static void
vl_api_onp_pktio_port_set_scheduler_t_handler(vl_api_onp_pktio_port_set_scheduler_t* mp) {
    int rv;
    vlib_main_t* vm = vlib_get_main();
    onp_main_t *om = onp_get_main ();

    u32 hw_if_index = ~0;
    u32 scheduler_profile_id = ONP_PKTIO_SCHEDULER_PROFILE_NONE;

    hw_if_index = ntohl(mp->sw_if_index);
    scheduler_profile_id = ntohl(mp->profile_id);

    rv = onp_pktio_root_node_scheduler_shaping_update(vm, om, hw_if_index, scheduler_profile_id, true);

    ONP_REPLY_MACRO (VL_API_ONP_PKTIO_PORT_SET_SCHEDULER_REPLY, onp_pktio_port_set_scheduler, );
}

static void
vl_api_onp_pktio_port_queue_set_scheduler_t_handler(vl_api_onp_pktio_port_queue_set_scheduler_t* mp) {
    int rv;
    vlib_main_t* vm = vlib_get_main();
    onp_main_t *om = onp_get_main ();

    u32 hw_if_index = ~0;
    u32 scheduler_profile_id = ONP_PKTIO_SCHEDULER_PROFILE_NONE;
    u32 queue_id = 0;

    hw_if_index = ntohl(mp->sw_if_index);
    scheduler_profile_id = ntohl(mp->profile_id);
    queue_id = ntohl(mp->queue_id);

    rv = onp_pktio_mdq_node_scheduler_update(vm, om, hw_if_index, queue_id, scheduler_profile_id);

    ONP_REPLY_MACRO (VL_API_ONP_PKTIO_PORT_QUEUE_SET_SCHEDULER_REPLY, onp_pktio_port_queue_set_scheduler, );
}

static void
vl_api_onp_pktio_scheduler_profile_add_del_t_handler(vl_api_onp_pktio_scheduler_profile_add_del_t* mp) {
    int rv;
    vlib_main_t* vm = vlib_get_main();
    onp_main_t *om = onp_get_main ();

    onp_pktio_scheduler_profile_t profile;
    clib_memset(&profile, 0, sizeof(profile));

    profile.id = ntohl(mp->profile_id);
    profile.type = ntohl(mp->type);
    profile.weight = ntohl(mp->weight);

    profile.shaping_profile.tm_shaper_profile.pkt_mode = mp->pkt_mode;

    profile.shaping_profile.tm_shaper_profile.commit_rate = clib_host_to_net_u64(mp->min_rate);
    profile.shaping_profile.tm_shaper_profile.commit_sz = clib_host_to_net_u64(mp->min_burst);
    profile.shaping_profile.tm_shaper_profile.peak_rate = clib_host_to_net_u64(mp->max_rate);
    profile.shaping_profile.tm_shaper_profile.peak_sz = clib_host_to_net_u64(mp->max_burst);

  if (profile.shaping_profile.tm_shaper_profile.commit_rate ||
      profile.shaping_profile.tm_shaper_profile.commit_sz ||
      profile.shaping_profile.tm_shaper_profile.peak_rate ||
      profile.shaping_profile.tm_shaper_profile.peak_sz )
  {
      profile.shaping_flag = true;
  }

    rv = onp_pktio_scheduler_profile_add_del(vm, om, &profile, mp->is_add ? false : true);

    ONP_REPLY_MACRO (VL_API_ONP_PKTIO_SCHEDULER_PROFILE_ADD_DEL_REPLY, onp_pktio_scheduler_profile_add_del, (
        {
            if (mp->is_add)
                reply->profile_id = ntohl(profile.id);
            else
                reply->profile_id = ntohl(ONP_PKTIO_SCHEDULER_PROFILE_NONE);
        }
    ));
}

static void
vl_api_onp_traffic_class_t_handler(vl_api_onp_traffic_class_t *mp)
{
  int rv = 0;
  u32 hw_if_index = UINT32_MAX;
  vnet_main_t *vnm = vnet_get_main();
  u32 flags = 0;

  bool enable = mp->enable;
  hw_if_index = ntohl(mp->sw_if_index);

  if (enable)
  {
    flags |= VNET_HW_INTERFACE_FLAG_USE_TC;
  }
  else
  {
    flags = 0;
  }

  vnet_hw_interface_set_tc_flags(vnm, hw_if_index, flags);

  ONP_REPLY_MACRO(VL_API_ONP_TRAFFIC_CLASS_REPLY, onp_traffic_class, );
}

static void
send_onp_pktio_tx_queue_stat_detail (vl_api_registration_t * reg,
                                     u32 context,
                                     u32 sw_if_index,
                                     u32 qid)
{
    cnxk_pktio_queue_stats_t qstats;

    vlib_main_t* vm = vlib_get_main();
    onp_main_t *om = onp_get_main ();

    vl_api_onp_pktio_tx_queue_stat_details_t *mp;

    mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_ONP_PKTIO_TX_QUEUE_STAT_DETAILS + onp_base_msg_id);

    clib_memset(&qstats, 0, sizeof (qstats));
    onp_pktio_get_tx_queue_stat(vm, om, sw_if_index, qid, &qstats);

    /* fill in the message */
    mp->context = context;
    mp->tx_pkts = clib_host_to_net_u64 (qstats.tx_pkts);
    mp->tx_octs = clib_host_to_net_u64 (qstats.tx_octs);
    mp->tx_drop_pkts = clib_host_to_net_u64 (qstats.tx_drop_pkts);
    mp->tx_drop_octs = clib_host_to_net_u64 (qstats.tx_drop_octs);

    vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_onp_pktio_tx_queue_stat_dump_t_handler (vl_api_onp_pktio_tx_queue_stat_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_onp_pktio_tx_queue_stat_detail(reg, mp->context, htonl(mp->sw_if_index), htonl(mp->queue_id));

    return;
}

static void
send_onp_pktio_rx_queue_stat_detail (vl_api_registration_t * reg,
                                     u32 context,
                                     u32 sw_if_index,
                                     u32 qid)
{
    cnxk_pktio_queue_stats_t qstats;

    vlib_main_t* vm = vlib_get_main();
    onp_main_t *om = onp_get_main ();

    vl_api_onp_pktio_rx_queue_stat_details_t *mp;
    mp = vl_msg_api_alloc (sizeof (*mp));
    clib_memset (mp, 0, sizeof (*mp));
    mp->_vl_msg_id = ntohs (VL_API_ONP_PKTIO_RX_QUEUE_STAT_DETAILS + onp_base_msg_id);

    clib_memset(&qstats, 0, sizeof (qstats));
    onp_pktio_get_rx_queue_stat(vm, om, sw_if_index, qid, &qstats);

    /* fill in the message */
    mp->context = context;
    mp->rx_pkts = clib_host_to_net_u64 (qstats.rx_pkts);
    mp->rx_octs = clib_host_to_net_u64 (qstats.rx_octs);
    mp->rx_drop_pkts = clib_host_to_net_u64 (qstats.rx_drop_pkts);
    mp->rx_drop_octs = clib_host_to_net_u64 (qstats.rx_drop_octs);
    mp->rx_error_pkts = clib_host_to_net_u64 (qstats.rx_error_pkts);

    vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_onp_pktio_rx_queue_stat_dump_t_handler (vl_api_onp_pktio_rx_queue_stat_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_onp_pktio_rx_queue_stat_detail(reg, mp->context, htonl(mp->sw_if_index), htonl(mp->queue_id));

    return;
}

#include <onp/api/onp.api.c>

static clib_error_t *
onp_api_init (vlib_main_t *vm)
{
  api_main_t *am = vlibapi_get_main ();

  /* Add our API messages to the global name_crc hash table */
  onp_base_msg_id = setup_message_id_table ();

  vl_api_set_msg_thread_safe(am, onp_base_msg_id + VL_API_ONP_INTERFACE_STATS, 1);
  vl_api_set_msg_thread_safe(am, onp_base_msg_id + VL_API_ONP_PKTIO_TX_QUEUE_STAT_DUMP, 1);
  vl_api_set_msg_thread_safe(am, onp_base_msg_id + VL_API_ONP_PKTIO_RX_QUEUE_STAT_DUMP, 1);
  return NULL;
}

VLIB_INIT_FUNCTION (onp_api_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
