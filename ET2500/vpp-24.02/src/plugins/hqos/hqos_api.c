/*
 *------------------------------------------------------------------
 * hqos_api.c - vnet hqos api
 *
 * Copyright 2024-2027 Asterfusion Network
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
 *------------------------------------------------------------------
 */

#include <hqos/hqos.h>
#include <hqos/hqos.api_enum.h>
#include <hqos/hqos.api_types.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#define REPLY_MSG_ID_BASE hm->msg_id_base
#include <vlibapi/api_helper_macros.h>

static void
vl_api_hqos_user_add_t_handler (vl_api_hqos_user_add_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_user_add_reply_t *rmp;

    int rv = 0;
    u32 user_id;

    rv = hqos_user_add(mp->tag, &user_id);

    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_HQOS_USER_ADD_REPLY,
            ({
             rmp->user_id = htonl(user_id);
             }));

    /* *INDENT-ON* */
}

static void
vl_api_hqos_user_del_t_handler (vl_api_hqos_user_del_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_user_del_reply_t *rmp;

    int rv = 0;

    rv = hqos_user_del(ntohl(mp->user_id));

    REPLY_MACRO (VL_API_HQOS_USER_DEL_REPLY);
}

static void
vl_api_hqos_user_update_queue_mode_t_handler (vl_api_hqos_user_update_queue_mode_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_user_update_queue_mode_reply_t *rmp;

    int rv = 0;

    rv = hqos_user_update_queue_mode(ntohl(mp->user_id), ntohl(mp->tc_queue_id), mp->is_dwrr, mp->weight);

    REPLY_MACRO (VL_API_HQOS_USER_UPDATE_QUEUE_MODE_REPLY);
}

static void
vl_api_hqos_user_group_add_t_handler (vl_api_hqos_user_group_add_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_user_group_add_reply_t *rmp;

    int rv = 0;
    u32 user_group_id;

    rv = hqos_user_group_add(mp->tag, &user_group_id);

    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_HQOS_USER_GROUP_ADD_REPLY,
            ({
             rmp->user_group_id = htonl(user_group_id);
             }));

    /* *INDENT-ON* */
}

static void
vl_api_hqos_user_group_del_t_handler (vl_api_hqos_user_group_del_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_user_group_del_reply_t *rmp;

    int rv = 0;

    rv = hqos_user_group_del(ntohl(mp->user_group_id));

    REPLY_MACRO (VL_API_HQOS_USER_GROUP_DEL_REPLY);
}

static void
vl_api_hqos_interface_update_user_group_user_t_handler (vl_api_hqos_interface_update_user_group_user_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_interface_update_user_group_user_reply_t *rmp;

    int rv = 0;

    rv = hqos_interface_update_user_group_user(ntohl(mp->sw_if_index), ntohl(mp->user_id), ntohl(mp->user_group_id));

    REPLY_MACRO (VL_API_HQOS_INTERFACE_UPDATE_USER_GROUP_USER_REPLY);
}

static void
vl_api_hqos_interface_mapping_hqos_port_t_handler (vl_api_hqos_interface_mapping_hqos_port_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_interface_mapping_hqos_port_reply_t *rmp;

    int rv = 0;

    rv = hqos_interface_mapping_hqos_port(ntohl(mp->sw_if_index), ntohl(mp->hqos_port_id));

    REPLY_MACRO (VL_API_HQOS_INTERFACE_MAPPING_HQOS_PORT_REPLY);
}

static void
vl_api_hqos_interface_mapping_user_group_to_hqos_subport_t_handler (vl_api_hqos_interface_mapping_user_group_to_hqos_subport_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_interface_mapping_user_group_to_hqos_subport_reply_t *rmp;

    int rv = 0;

    rv = hqos_interface_mapping_user_group_to_hqos_subport(ntohl(mp->sw_if_index), 
                                                           ntohl(mp->user_group_id), 
                                                           ntohl(mp->hqos_subport_id));

    REPLY_MACRO (VL_API_HQOS_INTERFACE_MAPPING_USER_GROUP_TO_HQOS_SUBPORT_REPLY);
}

static void
vl_api_hqos_interface_mapping_user_to_hqos_pipe_t_handler (vl_api_hqos_interface_mapping_user_to_hqos_pipe_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_interface_mapping_user_to_hqos_pipe_reply_t *rmp;

    int rv = 0;

    rv = hqos_interface_mapping_user_to_hqos_pipe(ntohl(mp->sw_if_index), 
                                                  ntohl(mp->user_id), 
                                                  ntohl(mp->hqos_pipe_id));

    REPLY_MACRO (VL_API_HQOS_INTERFACE_MAPPING_USER_TO_HQOS_PIPE_REPLY);
}

static void
vl_api_hqos_interface_enable_disable_t_handler (vl_api_hqos_interface_enable_disable_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_interface_enable_disable_reply_t *rmp;

    int rv = 0;

    rv = hqos_interface_enable_disable(ntohl(mp->sw_if_index), mp->is_enable);

    REPLY_MACRO (VL_API_HQOS_INTERFACE_ENABLE_DISABLE_REPLY);
}

static void
vl_api_hqos_port_add_t_handler (vl_api_hqos_port_add_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_add_reply_t *rmp;

    int rv = 0;
    u32 hqos_port_id;

    rv = hqos_port_add(clib_net_to_host_u64(mp->port_rate),
                       ntohl(mp->n_subports_per_port), 
                       ntohl(mp->n_max_subport_profiles), 
                       ntohl(mp->n_pipes_per_subport), 
                       ntohl(mp->n_queue_size),
                       ntohl(mp->mtu), ntohl(mp->frame_overhead),
                       &hqos_port_id);

    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_HQOS_PORT_ADD_REPLY,
            ({
             rmp->hqos_port_id = htonl(hqos_port_id);
             }));

    /* *INDENT-ON* */
}

static void
vl_api_hqos_port_del_t_handler (vl_api_hqos_port_del_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_del_reply_t *rmp;

    int rv = 0;

    rv = hqos_port_del(ntohl(mp->hqos_port_id));

    REPLY_MACRO (VL_API_HQOS_PORT_DEL_REPLY);
}

static void
vl_api_hqos_port_subport_profile_add_t_handler (vl_api_hqos_port_subport_profile_add_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_subport_profile_add_reply_t *rmp;

    int rv = 0, i = 0;
    u32 hqos_port_subport_profile_id;

    u64 *tc_rate_vec = NULL;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        vec_add1 (tc_rate_vec, clib_net_to_host_u64 (mp->tc_rate[i]));
    }

    rv = hqos_port_subport_profile_add(ntohl(mp->hqos_port_id),
                       clib_net_to_host_u64(mp->tb_rate),
                       clib_net_to_host_u64(mp->tb_size), 
                       tc_rate_vec,
                       clib_net_to_host_u64(mp->tc_period),
                       &hqos_port_subport_profile_id);

    vec_free(tc_rate_vec);

    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_HQOS_PORT_SUBPORT_PROFILE_ADD_REPLY,
            ({
             rmp->hqos_port_id = mp->hqos_port_id;
             rmp->hqos_port_subport_profile_id = htonl(hqos_port_subport_profile_id);
             }));

    /* *INDENT-ON* */
}

static void
vl_api_hqos_port_subport_profile_update_t_handler (vl_api_hqos_port_subport_profile_update_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_subport_profile_update_reply_t *rmp;

    int rv = 0, i = 0;

    u64 *tc_rate_vec = NULL;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        vec_add1 (tc_rate_vec, clib_net_to_host_u64 (mp->tc_rate[i]));
    }

    rv = hqos_port_subport_profile_update(ntohl(mp->hqos_port_id), ntohl(mp->hqos_port_subport_profile_id),
                       clib_net_to_host_u64(mp->tb_rate),
                       clib_net_to_host_u64(mp->tb_size), 
                       tc_rate_vec,
                       clib_net_to_host_u64(mp->tc_period));

    vec_free(tc_rate_vec);

    REPLY_MACRO (VL_API_HQOS_PORT_SUBPORT_PROFILE_UPDATE_REPLY);
}

static void
vl_api_hqos_port_subport_config_t_handler (vl_api_hqos_port_subport_config_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_subport_config_reply_t *rmp;

    int rv = 0, i = 0;

    u16 *qsize_vec = NULL;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        vec_add1 (qsize_vec, ntohs (mp->qsize[i]));
    }

    rv = hqos_port_subport_config(ntohl(mp->hqos_port_id),
                                  ntohl(mp->hqos_subport_id),
                                  ntohl(mp->hqos_port_subport_profile_id),
                                  ntohl(mp->n_pipes_per_subport_enabled),
                                  ntohl(mp->n_max_pipe_profiles),
                                  qsize_vec);

    vec_free(qsize_vec);

    REPLY_MACRO (VL_API_HQOS_PORT_SUBPORT_CONFIG_REPLY);
}

static void
vl_api_hqos_port_subport_update_profile_t_handler (vl_api_hqos_port_subport_update_profile_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_port_subport_update_profile_reply_t *rmp;

    int rv = 0;

    rv = hqos_port_subport_update_profile(ntohl(mp->hqos_port_id),
                                         ntohl(mp->hqos_subport_id),
                                         ntohl(mp->hqos_port_subport_profile_id));

    REPLY_MACRO (VL_API_HQOS_PORT_SUBPORT_UPDATE_PROFILE_REPLY);
}

static void
vl_api_hqos_subport_pipe_profile_add_t_handler (vl_api_hqos_subport_pipe_profile_add_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_subport_pipe_profile_add_reply_t *rmp;

    int rv = 0, i = 0;
    u32 hqos_pipe_profile_id;

    u64 *tc_rate_vec = NULL;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        vec_add1 (tc_rate_vec, clib_net_to_host_u64 (mp->tc_rate[i]));
    }

    rv = hqos_subport_pipe_profile_add(ntohl(mp->hqos_port_id),
                                       ntohl(mp->hqos_subport_id),
                                       clib_net_to_host_u64(mp->tb_rate),
                                       clib_net_to_host_u64(mp->tb_size), 
                                       tc_rate_vec,
                                       clib_net_to_host_u64(mp->tc_period),
                                       mp->tc_ov_weight,
                                       mp->wrr_weight,
                                       &hqos_pipe_profile_id);

    vec_free(tc_rate_vec);

    /* *INDENT-OFF* */
    REPLY_MACRO2(VL_API_HQOS_SUBPORT_PIPE_PROFILE_ADD_REPLY,
            ({
             rmp->hqos_port_id = mp->hqos_port_id;
             rmp->hqos_subport_id = mp->hqos_subport_id;
             rmp->hqos_pipe_profile_id = htonl(hqos_pipe_profile_id);
             }));

    /* *INDENT-ON* */
}

static void
vl_api_hqos_subport_pipe_profile_update_t_handler (vl_api_hqos_subport_pipe_profile_update_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_subport_pipe_profile_update_reply_t *rmp;

    int rv = 0, i = 0;

    u64 *tc_rate_vec = NULL;

    for (i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        vec_add1 (tc_rate_vec, clib_net_to_host_u64 (mp->tc_rate[i]));
    }

    rv = hqos_subport_pipe_profile_update(ntohl(mp->hqos_port_id),
                                          ntohl(mp->hqos_subport_id),
                                          ntohl(mp->hqos_pipe_profile_id),
                                          clib_net_to_host_u64(mp->tb_rate),
                                          clib_net_to_host_u64(mp->tb_size), 
                                          tc_rate_vec,
                                          clib_net_to_host_u64(mp->tc_period),
                                          mp->tc_ov_weight,
                                          mp->wrr_weight);

    vec_free(tc_rate_vec);

    REPLY_MACRO (VL_API_HQOS_SUBPORT_PIPE_PROFILE_UPDATE_REPLY);
}

static void
vl_api_hqos_subport_pipe_update_profile_t_handler (vl_api_hqos_subport_pipe_update_profile_t * mp)
{
    hqos_main_t *hm = &hqos_main;
    vl_api_hqos_subport_pipe_update_profile_reply_t *rmp;

    int rv = 0;

    rv = hqos_subport_pipe_update_profile(ntohl(mp->hqos_port_id),
                                          ntohl(mp->hqos_subport_id),
                                          ntohl(mp->hqos_pipe_id),
                                          ntohl(mp->hqos_pipe_profile_id));

    REPLY_MACRO (VL_API_HQOS_SUBPORT_PIPE_UPDATE_PROFILE_REPLY);
}

static void
send_hqos_subport_stat_details (vl_api_registration_t * reg, u32 context,
                                u32 hqos_port_id, u32 hqos_subport_id)
{
    hqos_main_t *hm = &hqos_main;

    vl_api_hqos_subport_stat_details_t *mp;

    hqos_sched_subport_stats stat;

    mp = vl_msg_api_alloc (sizeof (*mp));

    clib_memset (mp, 0, sizeof (*mp));
    clib_memset (&stat, 0, sizeof (stat));

    mp->_vl_msg_id = ntohs (VL_API_HQOS_SUBPORT_STAT_DETAILS + hm->msg_id_base);

    hqos_subport_stat_get(hqos_port_id, hqos_subport_id, &stat);
    
    /* fill in the message */
    mp->context = context;
    for (int i = 0; i < HQOS_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
    {
        mp->tc_pkts[i] = clib_net_to_host_u64(stat.n_pkts_tc[i]);
        mp->tc_bytes[i] = clib_net_to_host_u64(stat.n_bytes_tc[i]);
        mp->tc_drop_pkts[i] = clib_net_to_host_u64(stat.n_pkts_tc_dropped[i]);
        mp->tc_drop_bytes[i] = clib_net_to_host_u64(stat.n_bytes_tc_dropped[i]);
        mp->cman_drop_pkts[i] = clib_net_to_host_u64(stat.n_pkts_cman_dropped[i]);
    }
    vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_hqos_subport_stat_dump_t_handler (vl_api_hqos_subport_stat_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_hqos_subport_stat_details(reg, mp->context, 
                                   htonl(mp->hqos_port_id), 
                                   htonl(mp->hqos_subport_id));
    return; 
}

static void
send_hqos_queue_stat_details (vl_api_registration_t * reg, u32 context,
                              u32 hqos_port_id, u32 hqos_subport_id, u32 hqos_pipe_id, u32 hqos_queue_id)
{
    hqos_main_t *hm = &hqos_main;

    vl_api_hqos_queue_stat_details_t *mp;

    hqos_sched_queue_stats stat;

    mp = vl_msg_api_alloc (sizeof (*mp));

    clib_memset (mp, 0, sizeof (*mp));
    clib_memset (&stat, 0, sizeof (stat));

    mp->_vl_msg_id = ntohs (VL_API_HQOS_QUEUE_STAT_DETAILS + hm->msg_id_base);

    hqos_queue_stat_get(hqos_port_id, hqos_subport_id, hqos_pipe_id, hqos_queue_id, &stat);

    mp->context = context;
    mp->pkts = clib_net_to_host_u64(stat.n_pkts);
    mp->bytes = clib_net_to_host_u64(stat.n_bytes);
    mp->drop_pkts = clib_net_to_host_u64(stat.n_pkts_dropped);
    mp->drop_bytes = clib_net_to_host_u64(stat.n_bytes_dropped);
    mp->cman_drop_pkts = clib_net_to_host_u64(stat.n_pkts_cman_dropped);

    vl_api_send_msg (reg, (u8 *) mp);
}

static void
vl_api_hqos_queue_stat_dump_t_handler (vl_api_hqos_queue_stat_dump_t * mp)
{
    vl_api_registration_t *reg;

    reg = vl_api_client_index_to_registration (mp->client_index);
    if (!reg)
        return;

    send_hqos_queue_stat_details(reg, mp->context, 
                                 htonl(mp->hqos_port_id), 
                                 htonl(mp->hqos_subport_id), 
                                 htonl(mp->hqos_pipe_id), 
                                 htonl(mp->hqos_queue_id));
    return; 
}

void
vl_api_hqos_user_dscp_tc_map_t_handler (vl_api_hqos_user_dscp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_dscp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_dscp_tc_map(ntohl(mp->user_id), mp->dscp, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_DSCP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_dscp_color_map_t_handler (vl_api_hqos_user_dscp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_dscp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_dscp_color_map(ntohl(mp->user_id), mp->dscp, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_DSCP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_dot1p_tc_map_t_handler (vl_api_hqos_user_dot1p_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_dot1p_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_dot1p_tc_map(ntohl(mp->user_id), mp->dot1p, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_DOT1P_TC_MAP_REPLY);
}

void
vl_api_hqos_user_dot1p_color_map_t_handler (vl_api_hqos_user_dot1p_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_dot1p_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_dot1p_color_map(ntohl(mp->user_id), mp->dot1p, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_DOT1P_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_mpls_exp_tc_map_t_handler (vl_api_hqos_user_mpls_exp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_mpls_exp_tc_map(ntohl(mp->user_id), mp->mpls_exp, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_MPLS_EXP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_mpls_exp_color_map_t_handler (vl_api_hqos_user_mpls_exp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_mpls_exp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_set_mpls_exp_color_map(ntohl(mp->user_id), mp->mpls_exp, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_MPLS_EXP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_remove_dscp_tc_map_t_handler (vl_api_hqos_user_remove_dscp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_dscp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_dscp_tc_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_DSCP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_remove_dscp_color_map_t_handler (vl_api_hqos_user_remove_dscp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_dscp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_dscp_color_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_DSCP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_remove_dot1p_tc_map_t_handler (vl_api_hqos_user_remove_dot1p_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_dot1p_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_dot1p_tc_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_DOT1P_TC_MAP_REPLY);
}

void
vl_api_hqos_user_remove_dot1p_color_map_t_handler (vl_api_hqos_user_remove_dot1p_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_dot1p_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_dot1p_color_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_DOT1P_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_remove_mpls_exp_tc_map_t_handler (vl_api_hqos_user_remove_mpls_exp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_mpls_exp_tc_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_MPLS_EXP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_remove_mpls_exp_color_map_t_handler (vl_api_hqos_user_remove_mpls_exp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_remove_mpls_exp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_remove_mpls_exp_color_map(ntohl(mp->user_id));

  REPLY_MACRO (VL_API_HQOS_USER_REMOVE_MPLS_EXP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_dscp_tc_map_t_handler (vl_api_hqos_user_group_dscp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_dscp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_dscp_tc_map(ntohl(mp->user_group_id), mp->dscp, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_DSCP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_dscp_color_map_t_handler (vl_api_hqos_user_group_dscp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_dscp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_dscp_color_map(ntohl(mp->user_group_id), mp->dscp, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_DSCP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_dot1p_tc_map_t_handler (vl_api_hqos_user_group_dot1p_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_dot1p_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_dot1p_tc_map(ntohl(mp->user_group_id), mp->dot1p, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_DOT1P_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_dot1p_color_map_t_handler (vl_api_hqos_user_group_dot1p_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_dot1p_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_dot1p_color_map(ntohl(mp->user_group_id), mp->dot1p, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_DOT1P_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_mpls_exp_tc_map_t_handler (vl_api_hqos_user_group_mpls_exp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_mpls_exp_tc_map(ntohl(mp->user_group_id), mp->mpls_exp, mp->tc);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_MPLS_EXP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_mpls_exp_color_map_t_handler (vl_api_hqos_user_group_mpls_exp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_mpls_exp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_set_mpls_exp_color_map(ntohl(mp->user_group_id), mp->mpls_exp, mp->color);

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_MPLS_EXP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_dscp_tc_map_t_handler (vl_api_hqos_user_group_remove_dscp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_dscp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_dscp_tc_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_DSCP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_dscp_color_map_t_handler (vl_api_hqos_user_group_remove_dscp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_dscp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_dscp_color_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_DSCP_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_dot1p_tc_map_t_handler (vl_api_hqos_user_group_remove_dot1p_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_dot1p_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_dot1p_tc_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_DOT1P_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_dot1p_color_map_t_handler (vl_api_hqos_user_group_remove_dot1p_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_dot1p_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_dot1p_color_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_DOT1P_COLOR_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_mpls_exp_tc_map_t_handler (vl_api_hqos_user_group_remove_mpls_exp_tc_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_mpls_exp_tc_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_MPLS_EXP_TC_MAP_REPLY);
}

void
vl_api_hqos_user_group_remove_mpls_exp_color_map_t_handler (vl_api_hqos_user_group_remove_mpls_exp_color_map_t * mp)
{
  hqos_main_t *hm = &hqos_main;
  vl_api_hqos_user_group_remove_mpls_exp_color_map_reply_t *rmp;
  int rv = 0;

  rv = hqos_user_group_remove_mpls_exp_color_map(ntohl(mp->user_group_id));

  REPLY_MACRO (VL_API_HQOS_USER_GROUP_REMOVE_MPLS_EXP_COLOR_MAP_REPLY);
}


/* API definitions */
#include <vnet/format_fns.h>
#include <hqos/hqos.api.c>

/* Set up the API message handling tables */
clib_error_t *
hqos_plugin_api_hookup (vlib_main_t * vm)
{
    api_main_t *am = vlibapi_get_main ();
    hqos_main_t *hm = &hqos_main;

    hm->msg_id_base = setup_message_id_table ();

    vl_api_set_msg_thread_safe(am, hm->msg_id_base + VL_API_HQOS_SUBPORT_STAT_DUMP, 1);
    vl_api_set_msg_thread_safe(am, hm->msg_id_base + VL_API_HQOS_QUEUE_STAT_DUMP, 1);
    return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
