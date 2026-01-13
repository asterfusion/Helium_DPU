/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/vnet.h>
#include <vlibmemory/api.h>
#include <vnet/api_errno.h>

#include <vnet/qos/qos_record.h>
#include <vnet/qos/qos_store.h>
#include <vnet/qos/qos_mark.h>
#include <vnet/qos/qos_egress_map.h>

#include <vnet/format_fns.h>
#include <vnet/qos/qos.api_enum.h>
#include <vnet/qos/qos.api_types.h>

#define REPLY_MSG_ID_BASE msg_id_base
#include <vlibapi/api_helper_macros.h>

static u16 msg_id_base;

static int
qos_source_decode (vl_api_qos_source_t v, qos_source_t * q)
{
  switch (v)
    {
    case QOS_API_SOURCE_EXT:
      *q = QOS_SOURCE_EXT;
      return 0;
    case QOS_API_SOURCE_VLAN:
      *q = QOS_SOURCE_VLAN;
      return 0;
    case QOS_API_SOURCE_MPLS:
      *q = QOS_SOURCE_MPLS;
      return 0;
    case QOS_API_SOURCE_IP:
      *q = QOS_SOURCE_IP;
      return 0;
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

static vl_api_qos_source_t
qos_source_encode (qos_source_t q)
{
  return ((vl_api_qos_source_t) q);
}

void
vl_api_qos_record_enable_disable_t_handler (vl_api_qos_record_enable_disable_t
					    * mp)
{
  vl_api_qos_record_enable_disable_reply_t *rmp;
  qos_source_t qs;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (&(mp->record));

  rv = qos_source_decode (mp->record.input_source, &qs);

  if (0 == rv)
    {
      if (mp->enable)
	rv = qos_record_enable (ntohl (mp->record.sw_if_index), qs);
      else
	rv = qos_record_disable (ntohl (mp->record.sw_if_index), qs);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_RECORD_ENABLE_DISABLE_REPLY);
}

void
vl_api_qos_record_port_dscp_tc_map_t_handler (vl_api_qos_record_port_dscp_tc_map_t * mp)
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_port_dscp_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      u8 dscp = mp->dscp;
      u8 tc = mp->tc;
      hash_set(hi->dscp_to_tc, dscp, tc);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_RECORD_PORT_DSCP_TC_MAP_REPLY);
}

void
vl_api_qos_record_port_dot1p_tc_map_t_handler (vl_api_qos_record_port_dot1p_tc_map_t * mp)
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_port_dot1p_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      u8 dot1p = mp->dot1p;
      u8 tc = mp->tc;
      hash_set(hi->dot1p_to_tc, dot1p, tc);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_RECORD_PORT_DOT1P_TC_MAP_REPLY);
}

void
vl_api_qos_record_port_mpls_exp_tc_map_t_handler (vl_api_qos_record_port_mpls_exp_tc_map_t * mp)
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_port_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      u8 mpls_exp = mp->mpls_exp;
      u8 tc = mp->tc;
      hash_set(hi->mpls_exp_to_tc, mpls_exp, tc);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_RECORD_PORT_MPLS_EXP_TC_MAP_REPLY);
}

void
vl_api_qos_record_port_tc_queue_map_t_handler (vl_api_qos_record_port_tc_queue_map_t * mp)
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_port_tc_queue_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      u8 tc = mp->tc;
      u8 queue = mp->queue;
      hash_set(hi->tc_to_queue, tc, queue);
  }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_RECORD_PORT_TC_QUEUE_MAP_REPLY);
}

static void
vl_api_qos_record_rm_port_dscp_tc_map_t_handler(vl_api_qos_record_rm_port_dscp_tc_map_t* mp) 
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_rm_port_dscp_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      hash_free(hi->dscp_to_tc);
      hi->dscp_to_tc = NULL;
  }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_QOS_RECORD_RM_PORT_DSCP_TC_MAP_REPLY);
}

static void
vl_api_qos_record_rm_port_dot1p_tc_map_t_handler(vl_api_qos_record_rm_port_dot1p_tc_map_t* mp) 
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_rm_port_dot1p_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      hash_free(hi->dot1p_to_tc);
      hi->dot1p_to_tc = NULL;
  }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_QOS_RECORD_RM_PORT_DOT1P_TC_MAP_REPLY);
}

static void
vl_api_qos_record_rm_port_mpls_exp_tc_map_t_handler(vl_api_qos_record_rm_port_mpls_exp_tc_map_t* mp) 
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_rm_port_mpls_exp_tc_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      hash_free(hi->mpls_exp_to_tc);
      hi->mpls_exp_to_tc = NULL;
  }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_QOS_RECORD_RM_PORT_MPLS_EXP_TC_MAP_REPLY);
}

static void
vl_api_qos_record_rm_port_tc_queue_map_t_handler(vl_api_qos_record_rm_port_tc_queue_map_t* mp) 
{
  vnet_main_t* vnm = vnet_get_main();
  vl_api_qos_record_rm_port_tc_queue_map_reply_t *rmp;
  int rv = 0;
  vnet_sw_interface_t *sw = NULL;
  vnet_hw_interface_t *hi = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  hi = vnet_get_hw_interface_or_null(vnm, sw->hw_if_index);

  if (hi != NULL)
  {
      hash_free(hi->tc_to_queue);
      hi->tc_to_queue = NULL;
  }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_QOS_RECORD_RM_PORT_TC_QUEUE_MAP_REPLY);
}

static void
vl_api_qos_record_tc_traffic_class_t_handler(vl_api_qos_record_tc_traffic_class_t *mp)
{
  int rv = 0;
  vnet_main_t *vnm = vnet_get_main();
  u32 flags = 0;
  vl_api_qos_record_tc_traffic_class_reply_t *rmp;
  vnet_sw_interface_t *sw = NULL;

  VALIDATE_SW_IF_INDEX(mp);

  bool enable = mp->enable;

  u32 sw_if_index = ntohl(mp->sw_if_index);

  sw = vnet_get_sup_sw_interface (vnm, sw_if_index);

  if (vnet_hw_interface_is_valid(vnm, sw->hw_if_index))
  {
      if (enable)
      {
          flags |= VNET_HW_INTERFACE_FLAG_USE_TC;
      }
      else
      {
          flags = 0;
      }
      vnet_hw_interface_set_tc_flags(vnm, sw->hw_if_index, flags);
  }

  BAD_SW_IF_INDEX_LABEL;

  REPLY_MACRO (VL_API_QOS_RECORD_TC_TRAFFIC_CLASS_REPLY);
}

typedef struct qos_record_send_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} qos_record_send_walk_ctx_t;

static walk_rc_t
send_qos_record_details (u32 sw_if_index, qos_source_t input_source, void *c)
{
  qos_record_send_walk_ctx_t *ctx;
  vl_api_qos_record_details_t *mp;

  ctx = c;
  mp = vl_msg_api_alloc_zero (sizeof (*mp));

  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_QOS_RECORD_DETAILS);
  mp->context = ctx->context;
  mp->record.sw_if_index = htonl (sw_if_index);
  mp->record.input_source = qos_source_encode (input_source);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_qos_record_dump_t_handler (vl_api_qos_record_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  qos_record_send_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };
  qos_record_walk (send_qos_record_details, &ctx);
}

void
vl_api_qos_store_enable_disable_t_handler (vl_api_qos_store_enable_disable_t
					   * mp)
{
  vl_api_qos_store_enable_disable_reply_t *rmp;
  qos_source_t qs;
  int rv = 0;

  VALIDATE_SW_IF_INDEX (&(mp->store));

  rv = qos_source_decode (mp->store.input_source, &qs);

  if (0 == rv)
    {
      if (mp->enable)
	rv = qos_store_enable (ntohl (mp->store.sw_if_index), qs,
			       mp->store.value);
      else
	rv = qos_store_disable (ntohl (mp->store.sw_if_index), qs);
    }

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_QOS_STORE_ENABLE_DISABLE_REPLY);
}

typedef struct qos_store_send_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} qos_store_send_walk_ctx_t;

static walk_rc_t
send_qos_store_details (u32 sw_if_index,
			qos_source_t input_source, qos_bits_t value, void *c)
{
  qos_store_send_walk_ctx_t *ctx;
  vl_api_qos_store_details_t *mp;

  ctx = c;
  mp = vl_msg_api_alloc_zero (sizeof (*mp));

  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_QOS_STORE_DETAILS);
  mp->context = ctx->context;
  mp->store.sw_if_index = htonl (sw_if_index);
  mp->store.input_source = qos_source_encode (input_source);
  mp->store.value = value;

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_qos_store_dump_t_handler (vl_api_qos_store_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  qos_store_send_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };
  qos_store_walk (send_qos_store_details, &ctx);
}

void
vl_api_qos_egress_map_update_t_handler (vl_api_qos_egress_map_update_t * mp)
{
  vl_api_qos_egress_map_update_reply_t *rmp;
  qos_source_t qs;
  int rv = 0;

  FOR_EACH_QOS_SOURCE (qs)
  {
    qos_egress_map_update (ntohl (mp->map.id), qs,
			   &mp->map.rows[qs].outputs[0]);
  }

  REPLY_MACRO (VL_API_QOS_EGRESS_MAP_UPDATE_REPLY);
}

void
vl_api_qos_egress_map_delete_t_handler (vl_api_qos_egress_map_delete_t * mp)
{
  vl_api_qos_egress_map_delete_reply_t *rmp;
  int rv = 0;

  qos_egress_map_delete (ntohl (mp->id));

  REPLY_MACRO (VL_API_QOS_EGRESS_MAP_DELETE_REPLY);
}

typedef struct qos_egress_map_send_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} qos_egress_map_send_walk_ctx_t;

static walk_rc_t
send_qos_egress_map_details (qos_egress_map_id_t id,
			     const qos_egress_map_t * m, void *c)
{
  qos_egress_map_send_walk_ctx_t *ctx;
  vl_api_qos_egress_map_details_t *mp;
  u8 ii;

  ctx = c;
  mp = vl_msg_api_alloc_zero (sizeof (*mp));

  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_QOS_EGRESS_MAP_DETAILS);
  mp->context = ctx->context;
  mp->map.id = htonl (id);

  for (ii = 0; ii < 4; ii++)
    clib_memcpy (mp->map.rows[ii].outputs, m->qem_output[ii], 256);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_qos_egress_map_dump_t_handler (vl_api_qos_egress_map_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  qos_egress_map_send_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };
  qos_egress_map_walk (send_qos_egress_map_details, &ctx);
}

void
vl_api_qos_mark_enable_disable_t_handler (vl_api_qos_mark_enable_disable_t *
					  mp)
{
  vl_api_qos_mark_enable_disable_reply_t *rmp;
  qos_source_t qs;
  int rv = 0;

  rv = qos_source_decode (mp->mark.output_source, &qs);

  if (0 == rv)
    {
      if (mp->enable)
	rv = qos_mark_enable (ntohl (mp->mark.sw_if_index),
			      qs, ntohl (mp->mark.map_id));
      else
	rv = qos_mark_disable (ntohl (mp->mark.sw_if_index), qs);
    }

  REPLY_MACRO (VL_API_QOS_MARK_ENABLE_DISABLE_REPLY);
}

typedef struct qos_mark_send_walk_ctx_t_
{
  vl_api_registration_t *reg;
  u32 context;
} qos_mark_send_walk_ctx_t;

static walk_rc_t
send_qos_mark_details (u32 sw_if_index,
		       u32 map_id, qos_source_t output_source, void *c)
{
  qos_mark_send_walk_ctx_t *ctx;
  vl_api_qos_mark_details_t *mp;

  ctx = c;
  mp = vl_msg_api_alloc_zero (sizeof (*mp));

  mp->_vl_msg_id = ntohs (REPLY_MSG_ID_BASE + VL_API_QOS_MARK_DETAILS);
  mp->context = ctx->context;
  mp->mark.sw_if_index = htonl (sw_if_index);
  mp->mark.output_source = qos_source_encode (output_source);
  mp->mark.map_id = htonl (map_id);

  vl_api_send_msg (ctx->reg, (u8 *) mp);

  return (WALK_CONTINUE);
}

static void
vl_api_qos_mark_dump_t_handler (vl_api_qos_mark_dump_t * mp)
{
  vl_api_registration_t *reg;

  reg = vl_api_client_index_to_registration (mp->client_index);
  if (!reg)
    return;

  qos_mark_send_walk_ctx_t ctx = {
    .reg = reg,
    .context = mp->context,
  };
  qos_mark_walk (send_qos_mark_details, &ctx);
}

#include <vnet/qos/qos.api.c>

static clib_error_t *
qos_api_hookup (vlib_main_t * vm)
{
  /*
   * Set up the (msg_name, crc, message-id) table
   */
  REPLY_MSG_ID_BASE = setup_message_id_table ();

  return 0;
}

VLIB_API_INIT_FUNCTION (qos_api_hookup);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
