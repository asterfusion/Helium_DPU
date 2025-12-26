/*
 * Copyright (c) 2016-2018 Cisco and/or its affiliates.
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
#include <netinet/in.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/l2/l2_input.h>
#include <vppinfra/error.h>

#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

#include <acl/acl.h>
#include <vnet/ip/icmp46_packet.h>

#include <plugins/acl/fa_node.h>
#include <plugins/acl/acl.h>
#include <plugins/acl/lookup_context.h>
#include <plugins/acl/public_inlines.h>
#include <plugins/acl/session_inlines.h>

#include <vppinfra/bihash_64_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>
#include <plugins/geosite/geosite.h>
#include <plugins/dns/dns.h>
//#include <vppinfra/bihash_template.c>

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
  u32 lc_index;
  u32 match_acl_in_index;
  u32 match_rule_index;
  u64 packet_info[9];
  u32 trace_bitmap;
  u8 action;
} acl_fa_trace_t;

/* *INDENT-OFF* */
#define foreach_acl_fa_error \
_(ACL_DROP, "ACL deny packets")  \
_(ACL_PERMIT, "ACL permit packets")  \
_(ACL_NEW_SESSION, "new sessions added") \
_(ACL_EXIST_SESSION, "existing session packets") \
_(ACL_CHECK, "checked packets") \
_(ACL_RESTART_SESSION_TIMER, "restart session timer") \
_(ACL_TOO_MANY_SESSIONS, "too many sessions to add new") \
/* end  of errors */

typedef enum
{
#define _(sym,str) ACL_FA_ERROR_##sym,
  foreach_acl_fa_error
#undef _
    ACL_FA_N_ERROR,
} acl_fa_error_t;

/* *INDENT-ON* */

always_inline u16
get_current_policy_epoch (acl_main_t * am, int is_input, u32 sw_if_index0)
{
  u32 **p_epoch_vec =
    is_input ? &am->input_policy_epoch_by_sw_if_index :
    &am->output_policy_epoch_by_sw_if_index;
  u16 current_policy_epoch =
    sw_if_index0 < vec_len (*p_epoch_vec) ? vec_elt (*p_epoch_vec,
						     sw_if_index0)
    : (is_input * FA_POLICY_EPOCH_IS_INPUT);
  return current_policy_epoch;
}

always_inline void
maybe_trace_buffer (vlib_main_t * vm, vlib_node_runtime_t * node,
		    vlib_buffer_t * b, u32 sw_if_index0, u32 lc_index0,
		    u16 next0, int match_acl_in_index, int match_rule_index,
		    fa_5tuple_t * fa_5tuple, u8 action, u32 trace_bitmap)
{
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      acl_fa_trace_t *t = vlib_add_trace (vm, node, b, sizeof (*t));
      t->sw_if_index = sw_if_index0;
      t->lc_index = lc_index0;
      t->next_index = next0;
      t->match_acl_in_index = match_acl_in_index;
      t->match_rule_index = match_rule_index;
      t->packet_info[0] = fa_5tuple->kv_64_8.key[0];
      t->packet_info[1] = fa_5tuple->kv_64_8.key[1];
      t->packet_info[2] = fa_5tuple->kv_64_8.key[2];
      t->packet_info[3] = fa_5tuple->kv_64_8.key[3];
      t->packet_info[4] = fa_5tuple->kv_64_8.key[4];
      t->packet_info[5] = fa_5tuple->kv_64_8.key[5];
      t->packet_info[6] = fa_5tuple->kv_64_8.key[6];
      t->packet_info[7] = fa_5tuple->kv_64_8.key[7];
      t->packet_info[8] = fa_5tuple->kv_64_8.value;
      t->action = action;
      t->trace_bitmap = trace_bitmap;
    }
}


always_inline int
stale_session_deleted (acl_main_t * am, int is_input,
		       acl_fa_per_worker_data_t * pw, u64 now,
		       u32 sw_if_index0, fa_full_session_id_t f_sess_id)
{
  u16 current_policy_epoch =
    get_current_policy_epoch (am, is_input, sw_if_index0);

  /* if the MSB of policy epoch matches but not the LSB means it is a stale session */
  if ((0 ==
       ((current_policy_epoch ^
	 f_sess_id.intf_policy_epoch) &
	FA_POLICY_EPOCH_IS_INPUT))
      && (current_policy_epoch != f_sess_id.intf_policy_epoch))
    {
      /* delete session and increment the counter */
      vec_validate (pw->fa_session_epoch_change_by_sw_if_index, sw_if_index0);
      vec_elt (pw->fa_session_epoch_change_by_sw_if_index, sw_if_index0)++;
      if (acl_fa_conn_list_delete_session (am, f_sess_id, now))
	{
	  /* delete the session only if we were able to unlink it */
	  acl_fa_two_stage_delete_session (am, sw_if_index0, f_sess_id, now);
	}
      return 1;
    }
  else
    return 0;
}





always_inline void
get_sw_if_index_xN (int vector_sz, int is_input, vlib_buffer_t ** b,
		    u32 * out_sw_if_index)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    if (is_input)
      out_sw_if_index[ii] = vnet_buffer (b[ii])->sw_if_index[VLIB_RX];
    else
      out_sw_if_index[ii] = vnet_buffer (b[ii])->sw_if_index[VLIB_TX];
}

always_inline void
fill_5tuple_xN (int vector_sz, acl_main_t * am, int is_ip6, int is_input,
		int is_l2_path, vlib_buffer_t ** b, u32 * sw_if_index,
		fa_5tuple_t * out_fa_5tuple)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
  {
    acl_fill_5tuple (am, sw_if_index[ii], b[ii], is_ip6,
		     is_input, is_l2_path, &out_fa_5tuple[ii]);
    out_fa_5tuple[ii].pkt.is_ip6 = is_ip6;
  }
}

always_inline void
make_session_hash_xN (int vector_sz, acl_main_t * am, int is_ip6,
		      u32 * sw_if_index, fa_5tuple_t * fa_5tuple,
		      u64 * out_hash)
{
  int ii;
  for (ii = 0; ii < vector_sz; ii++)
    out_hash[ii] =
      acl_fa_make_session_hash (am, is_ip6, sw_if_index[ii], &fa_5tuple[ii]);
}

always_inline void
prefetch_session_entry (acl_main_t * am, fa_full_session_id_t f_sess_id)
{
  fa_session_t *sess = get_session_ptr_no_check (am, f_sess_id.thread_index,
						 f_sess_id.session_index);
  CLIB_PREFETCH (sess, sizeof (*sess), STORE);
}

always_inline u8
process_established_session (vlib_main_t * vm, acl_main_t * am,
			     u32 counter_node_index, int is_input, u64 now,
			     fa_full_session_id_t f_sess_id,
			     u32 * sw_if_index, fa_5tuple_t * fa_5tuple,
			     u32 pkt_len, int node_trace_on,
			     u32 * trace_bitmap)
{
  u8 action = ACL_ACTION_DENY;
  fa_session_t *sess = get_session_ptr_no_check (am, f_sess_id.thread_index,
						 f_sess_id.session_index);

  int old_timeout_type = fa_session_get_timeout_type (am, sess);
  action =
    acl_fa_track_session (am, is_input, sw_if_index[0], now,
			  sess, &fa_5tuple[0], pkt_len);
  int new_timeout_type = fa_session_get_timeout_type (am, sess);
  /* Tracking might have changed the session timeout type, e.g. from transient to established */
  if (PREDICT_FALSE (old_timeout_type != new_timeout_type))
    {
      acl_fa_restart_timer_for_session (am, now, f_sess_id);
      vlib_node_increment_counter (vm, counter_node_index,
				   ACL_FA_ERROR_ACL_RESTART_SESSION_TIMER, 1);
      if (node_trace_on)
	*trace_bitmap |=
	  0x00010000 + ((0xff & old_timeout_type) << 8) +
	  (0xff & new_timeout_type);
    }
  /*
   * I estimate the likelihood to be very low - the VPP needs
   * to have >64K interfaces to start with and then on
   * exactly 64K indices apart needs to be exactly the same
   * 5-tuple... Anyway, since this probability is nonzero -
   * print an error and drop the unlucky packet.
   * If this shows up in real world, we would need to bump
   * the hash key length.
   */
  if (PREDICT_FALSE (sess->sw_if_index != sw_if_index[0]))
    {
      clib_warning
	("BUG: session LSB16(sw_if_index)=%d and 5-tuple=%d collision!",
	 sess->sw_if_index, sw_if_index[0]);
      action = 0;
    }
  return action;

}

#define ACL_PLUGIN_VECTOR_SIZE 4
#define ACL_PLUGIN_PREFETCH_GAP 3

always_inline void
acl_fa_node_common_prepare_fn (vlib_main_t * vm,
			       vlib_node_runtime_t * node,
			       vlib_frame_t * frame, int is_ip6, int is_input,
			       int is_l2_path, int with_stateful_datapath)
	/* , int node_trace_on,
	   int reclassify_sessions) */
{
  u32 n_left, *from;
  acl_main_t *am = &acl_main;
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  vlib_buffer_t **b;
  u32 *sw_if_index;
  fa_5tuple_t *fa_5tuple;
  u64 *hash;

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, pw->bufs, frame->n_vectors);

  /* set the initial values for the current buffer the next pointers */
  b = pw->bufs;
  sw_if_index = pw->sw_if_indices;
  fa_5tuple = pw->fa_5tuples;
  hash = pw->hashes;

  /*
   * fill the sw_if_index, 5tuple and session hash,
   * First in strides of size ACL_PLUGIN_VECTOR_SIZE,
   * with buffer prefetch being
   * ACL_PLUGIN_PREFETCH_GAP * ACL_PLUGIN_VECTOR_SIZE entries
   * in front. Then with a simple single loop.
   */

  n_left = frame->n_vectors;
  memset(fa_5tuple, 0, sizeof(fa_5tuple_t) * VLIB_FRAME_SIZE);
  while (n_left >= (ACL_PLUGIN_PREFETCH_GAP + 1) * ACL_PLUGIN_VECTOR_SIZE)
    {
      const int vec_sz = ACL_PLUGIN_VECTOR_SIZE;
      {
	int ii;
	for (ii = ACL_PLUGIN_PREFETCH_GAP * vec_sz;
	     ii < (ACL_PLUGIN_PREFETCH_GAP + 1) * vec_sz; ii++)
	  {
	    clib_prefetch_load (b[ii]);
	    CLIB_PREFETCH (b[ii]->data, 2 * CLIB_CACHE_LINE_BYTES, LOAD);
	  }
      }


      get_sw_if_index_xN (vec_sz, is_input, b, sw_if_index);
      fill_5tuple_xN (vec_sz, am, is_ip6, is_input, is_l2_path, &b[0],
		      &sw_if_index[0], &fa_5tuple[0]);
      if (with_stateful_datapath)
	make_session_hash_xN (vec_sz, am, is_ip6, &sw_if_index[0],
			      &fa_5tuple[0], &hash[0]);

      n_left -= vec_sz;

      fa_5tuple += vec_sz;
      b += vec_sz;
      sw_if_index += vec_sz;
      hash += vec_sz;
    }

  while (n_left > 0)
    {
      const int vec_sz = 1;

      get_sw_if_index_xN (vec_sz, is_input, b, sw_if_index);
      fill_5tuple_xN (vec_sz, am, is_ip6, is_input, is_l2_path, &b[0],
		      &sw_if_index[0], &fa_5tuple[0]);
      if (with_stateful_datapath)
	make_session_hash_xN (vec_sz, am, is_ip6, &sw_if_index[0],
			      &fa_5tuple[0], &hash[0]);

      n_left -= vec_sz;

      fa_5tuple += vec_sz;
      b += vec_sz;
      sw_if_index += vec_sz;
      hash += vec_sz;
    }
}

always_inline void acl_calc_action(match_acl_t *match_acl_info, u32 *acl_index, u32 *rule_index, u8 *action, match_rule_expand_t *action_expand)
{
    u16 priority = 0;

    *action = match_acl_info->action[0];
    *acl_index = match_acl_info->acl_index[0];
    *rule_index = match_acl_info->rule_index[0];
    action_expand->action_expand_bitmap = match_acl_info->action_expand_bitmap[0];
    action_expand->policer_index = match_acl_info->policer_index[0];
    action_expand->set_tc_value = match_acl_info->set_tc_value[0];
    action_expand->set_hqos_user_id = match_acl_info->set_hqos_user_id[0];
    priority = match_acl_info->acl_priority[0];

    for (int i = 1; i < match_acl_info->acl_match_count; i++)
    {
        if (match_acl_info->acl_priority[i] > priority)
        {
            *action = match_acl_info->action[i];
            *acl_index = match_acl_info->acl_index[i];
            *rule_index = match_acl_info->rule_index[i];
            action_expand->action_expand_bitmap = match_acl_info->action_expand_bitmap[i];
            action_expand->policer_index = match_acl_info->policer_index[i];
            action_expand->set_tc_value = match_acl_info->set_tc_value[i];
            action_expand->set_hqos_user_id = match_acl_info->set_hqos_user_id[i];
            priority = match_acl_info->acl_priority[i];
        }
    }

    return;
}




always_inline u8
acl_get_country_index_by_domain(vlib_buffer_t **b, u32 **cc_indices, u32 **dns_cc_indices, int is_ipv6)
{
  u8 result = 0;



    if(vnet_buffer2(b[0])->geosite_domain_ptr == NULL){
    return result;
 
  }

  char *domain_name;
  domain_name =  vnet_buffer2(b[0])->geosite_domain_ptr;
  *cc_indices = ((__typeof__(geosite_get_country_index_by_domain) *)geosite_get_country_index_by_domain_ptr)(domain_name);
  if (*cc_indices)
  {
    result |= GEOSITE_FIND_CC_CODE;
  }




  dns_resolve_name_t *rn=NULL;

  u8 rv = ((__typeof__(dns_query_domain_name) *)dns_query_domain_ptr)((u8 *)domain_name, &rn);
  if (rv)
  {
    for (int i = 0; i < vec_len(rn); i++)
    {
      dns_resolve_name_t *_rn = &rn[i];
      u8 *ip_str = format(0, "%U", format_ip4_address, &_rn->address.ip.ip4);
      vec_free(ip_str);
      u32 *cc_indices_tmp;
      if (is_ipv6)
      {
        cc_indices_tmp = ((__typeof__(geoip_get_country_code_by_ip6) *)geoip_get_country_code_by_ip6_ptr)(_rn->address.ip.ip6);
      }
      else
      {
        cc_indices_tmp = ((__typeof__(geoip_get_country_code_by_ip4) *)geoip_get_country_code_by_ip4_ptr)(_rn->address.ip.ip4);
      }
      if (cc_indices_tmp)
      {
      
        u32 *tmp_ptr;
        vec_foreach(tmp_ptr, cc_indices_tmp)
        {
          vec_add1(*dns_cc_indices, *tmp_ptr);
        }
        vec_free(cc_indices_tmp);
      }
    }
    vec_free(rn);
    if (*dns_cc_indices)
    {
      result |= GEOSITE_DNS_FIND_CC_CODE;
    }
  }

  return result;
}

always_inline u8
acl_get_country_index_by_dip4(vlib_buffer_t **b, u32 **cc_indices, ip4_address_t ip4)
{
  u8 result = 0;
  *cc_indices = ((__typeof__(geoip_get_country_code_by_ip4) *)geoip_get_country_code_by_ip4_ptr)(ip4);
  if (*cc_indices)
  {
    result |= GEOIP_FIND_CC_CODE;
  }
  return result;
}


always_inline u8
acl_get_country_index_by_dip6(vlib_buffer_t **b, u32 **cc_indices, ip6_address_t ip6)
{
  u8 result = 0;
  *cc_indices = ((__typeof__(geoip_get_country_code_by_ip6) *)geoip_get_country_code_by_ip6_ptr)(ip6);
  if (*cc_indices)
  {
    result |= GEOIP_FIND_CC_CODE;
  }
  return result;
}



always_inline void 
acl_action_expand_proc(vlib_main_t *vm, vlib_buffer_t *b, u16 *next, const match_rule_expand_t *action_expand)
{
    if (action_expand->action_expand_bitmap & (1 << ACL_ACTION_EXPAND_NO_NAT))
    {
        b->no_nat = 1;
        b->flags |= VLIB_BUFFER_NO_NAT_VALID;
    }

    if (action_expand->action_expand_bitmap & (1 << ACL_ACTION_EXPAND_POLICER))
    {
        u8 policer_act;
        u64 time_in_policer_periods = clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;
        policer_act = vnet_policer_police(vm, b, action_expand->policer_index, time_in_policer_periods, POLICE_CONFORM, false);
        if (policer_act == QOS_ACTION_DROP)
        {
            *next = 0;
        }
    }

    if (action_expand->action_expand_bitmap & (1 << ACL_ACTION_EXPAND_SET_TC))
    {
        vnet_buffer2(b)->tc_index = action_expand->set_tc_value;
        b->flags |= VLIB_BUFFER_ACL_SET_TC_VALID;
    }

    if (action_expand->action_expand_bitmap & (1 << ACL_ACTION_EXPAND_SET_HQOS_USER))
    {
         vnet_buffer2(b)->hqos_user_id = action_expand->set_hqos_user_id;
        b->flags |= VLIB_BUFFER_ACL_SET_USER_VALID;
    }
    return;
}

always_inline uword
acl_fa_inner_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_ip6, int is_input, int is_l2_path,
		      int with_stateful_datapath, int node_trace_on,
		      int reclassify_sessions)
{
  u32 n_left;
  u32 pkts_exist_session = 0;
  u32 pkts_new_session = 0;
  u32 pkts_acl_permit = 0;
  u32 trace_bitmap = 0;
  acl_main_t *am = &acl_main;
  vlib_node_runtime_t *error_node;
  vlib_error_t no_error_existing_session;
  u64 now = clib_cpu_time_now ();
  uword thread_index = os_get_thread_index ();
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[thread_index];

  u16 *next;
  vlib_buffer_t **b;
  u32 *sw_if_index;
  fa_5tuple_t *fa_5tuple;
  u64 *hash;
  /* for the delayed counters */
  u32 saved_byte_count = 0;
  u8 *pinout_reflect_by_sw_if_index = is_input ? am->input_reflect_by_sw_if_index : am->output_reflect_by_sw_if_index;
  match_acl_t match_acl_info;

  error_node = vlib_node_get_runtime (vm, node->node_index);
  no_error_existing_session =
    error_node->errors[ACL_FA_ERROR_ACL_EXIST_SESSION];

  b = pw->bufs;
  next = pw->nexts;
  sw_if_index = pw->sw_if_indices;
  fa_5tuple = pw->fa_5tuples;
  hash = pw->hashes;

  /*
   * Now the "hard" work of session lookups and ACL lookups for new sessions.
   * Due to the complexity, do it for the time being in single loop with
   * the pipeline of three prefetches:
   *    1) bucket for the session bihash
   *    2) data for the session bihash
   *    3) worker session record
   */

  fa_full_session_id_t f_sess_id_next = {.as_u64 = ~0ULL };

  /* find the "next" session so we can kickstart the pipeline */
  if (with_stateful_datapath)
    acl_fa_find_session_with_hash (am, is_ip6, sw_if_index[0], hash[0],
				   &fa_5tuple[0], &f_sess_id_next.as_u64);

  n_left = frame->n_vectors;
  while (n_left > 0)
    {
      u8 action = 0;
      u32 lc_index0 = ~0;
      int acl_check_needed = 1;
      u32 match_acl_in_index = ~0;
      u32 match_rule_index = ~0;
      match_rule_expand_t action_expand;
      
      u32 *cc_indices = NULL;
      u32 *dns_cc_indices = NULL;
      u8 get_cc_code =0;
      memset(&match_acl_info, 0, sizeof(match_acl_t));
      memset(&action_expand, 0, sizeof(match_rule_expand_t));

      next[0] = 0;		/* drop by default */
   
     
      /* Try to match an existing session first */

      if (with_stateful_datapath)
	{
	  fa_full_session_id_t f_sess_id = f_sess_id_next;
	  switch (n_left)
	    {
	    default:
	      acl_fa_prefetch_session_bucket_for_hash (am, is_ip6, hash[5]);
	      /* fallthrough */
	    case 5:
	    case 4:
	      acl_fa_prefetch_session_data_for_hash (am, is_ip6, hash[3]);
	      /* fallthrough */
	    case 3:
	    case 2:
	      acl_fa_find_session_with_hash (am, is_ip6, sw_if_index[1],
					     hash[1], &fa_5tuple[1],
					     &f_sess_id_next.as_u64);
	      if (f_sess_id_next.as_u64 != ~0ULL)
		{
		  prefetch_session_entry (am, f_sess_id_next);
		}
	      /* fallthrough */
	    case 1:
	      if (f_sess_id.as_u64 != ~0ULL)
		{
		  if (node_trace_on)
		    {
		      trace_bitmap |= 0x80000000;
		    }
		  ASSERT (f_sess_id.thread_index < vlib_get_n_threads ());
		  b[0]->error = no_error_existing_session;
		  acl_check_needed = 0;
		  pkts_exist_session += 1;
		  action =
		    process_established_session (vm, am, node->node_index,
						 is_input, now, f_sess_id,
						 &sw_if_index[0],
						 &fa_5tuple[0],
						 b[0]->current_length,
						 node_trace_on,
						 &trace_bitmap);

                   fa_session_t *sess = get_session_ptr (am, f_sess_id.thread_index, f_sess_id.session_index);
                  saved_byte_count = vlib_buffer_length_in_chain (vm, b[0]);

                  if (!is_l2_path && is_input)
                  {
                        saved_byte_count += ethernet_buffer_header_size(b[0]);
                  }

                  /* prefetch the counter that we are going to increment */
                  clib_atomic_fetch_add (&sess->hitcount_pkts, 1);
                  clib_atomic_fetch_add (&sess->hitcount_bytes, saved_byte_count);
                  action_expand.action_expand_bitmap = sess->action_expand.action_expand_bitmap;
                  action_expand.policer_index = sess->action_expand.policer_index;
                  action_expand.set_tc_value = sess->action_expand.set_tc_value;

		  /* expose the session id to the tracer */
		  if (node_trace_on)
		    {
		      match_rule_index = f_sess_id.session_index;
		    }

		  if (reclassify_sessions)
		    {
		      if (PREDICT_FALSE
			  (stale_session_deleted
			   (am, is_input, pw, now, sw_if_index[0],
			    f_sess_id)))
			{
			  acl_check_needed = 1;
			  if (node_trace_on)
			    {
			      trace_bitmap |= 0x40000000;
			    }
			  /*
			   * If we have just deleted the session, and the next
			   * buffer is the same 5-tuple, that session prediction
			   * is wrong, correct it.
			   */
			  if ((f_sess_id_next.as_u64 != ~0ULL)
			      && 0 == memcmp (&fa_5tuple[1], &fa_5tuple[0],
					      sizeof (fa_5tuple[1])))
			    f_sess_id_next.as_u64 = ~0ULL;
			}
		    }
		}
	    }
        }

	  if (acl_check_needed)
	    {

     if(b[0]->flags & VLIB_BUFFER_DOMAIN_VALID )
      {

         get_cc_code =acl_get_country_index_by_domain(&b[0],&cc_indices,&dns_cc_indices,is_ip6);

      }else{
       if(is_ip6)
        get_cc_code =acl_get_country_index_by_dip6(&b[0],&cc_indices, fa_5tuple->ip6_addr[1]);
      else
        get_cc_code =acl_get_country_index_by_dip4(&b[0],&cc_indices, fa_5tuple->ip4_addr[1]);
      }
   


	      if (is_input)
		lc_index0 = am->input_lc_index_by_sw_if_index[sw_if_index[0]];
	      else
		lc_index0 =
		  am->output_lc_index_by_sw_if_index[sw_if_index[0]];

	      action = 0;	/* deny by default */
	      acl_plugin_match_5tuple_inline_sai (am, lc_index0,
							     (fa_5tuple_opaque_t *) & fa_5tuple[0], is_ip6,
							     &trace_bitmap,
							     &match_acl_info,get_cc_code,cc_indices,dns_cc_indices);
              //Only hit the default rule and enabled acl reflect
              if (PREDICT_FALSE((1 == match_acl_info.acl_match_count) && 0 == match_acl_info.acl_index[0] && 
+                                 1 == pinout_reflect_by_sw_if_index[sw_if_index[0]]))
              {
                  //icmpv6 NA or RA
                  if (IP_PROTOCOL_ICMP6 == fa_5tuple->l4.proto &&  
                      (fa_5tuple->l4.port[0] == 133 || fa_5tuple->l4.port[0] == 134 ||
                       fa_5tuple->l4.port[0] == 135 || fa_5tuple->l4.port[0] == 136))
                  {
                      match_acl_info.acl_match_count = 1;
                  }

                  //arp
                  else if (is_l2_path)
                  {
                      u16 ethertype = 0;
                      ethernet_header_t *h0 = vlib_buffer_get_current (b[0]);
                      u8 *l3h0 = (u8 *) h0 + vnet_buffer (b[0])->l2.l2_len;
                      ethertype = clib_net_to_host_u16(*((u16 *)(l3h0 - 2)));
                      if (ETHERNET_TYPE_ARP != ethertype)
                      {
                          match_acl_info.acl_match_count = 0;
                      }
                  }

                  else
                  {
                        match_acl_info.acl_match_count = 0;
                  }
              }
#if 0
	      if (PREDICT_FALSE
		  (match_acl_info.acl_match_count && am->interface_acl_counters_enabled))
		{
		  u32 buf_len = vlib_buffer_length_in_chain (vm, b[0]);
          saved_byte_count = buf_len;
          if (!is_l2_path && is_input)
		  {
			saved_byte_count += ethernet_buffer_header_size(b[0]);
		  }
          for (int i = 0; i < match_acl_info.acl_match_count; i++)
          {
              /* prefetch the counter that we are going to increment */
		      vlib_prefetch_combined_counter (am->combined_acl_counters +
						  match_acl_info.acl_index[i],
						  thread_index,
						  match_acl_info.rule_index[i]);

		      vlib_increment_combined_counter (am->combined_acl_counters +
						   match_acl_info.acl_index[i],
						   thread_index,
						   match_acl_info.rule_index[i],
						   1,
						   saved_byte_count);
              
          }

		}
#endif

          if (match_acl_info.acl_match_count > 0)
          {
              acl_calc_action(&match_acl_info, &match_acl_in_index, &match_rule_index, &action, &action_expand);
          }
	      if (PREDICT_FALSE(match_acl_info.acl_match_count > 0 && match_acl_in_index != 0 && am->interface_acl_counters_enabled))
              {
                  u32 buf_len = vlib_buffer_length_in_chain (vm, b[0]);
                  saved_byte_count = buf_len;
                  if (!is_l2_path && is_input)
                  {
                        saved_byte_count += ethernet_buffer_header_size(b[0]);
                  }
                  vlib_increment_combined_counter (am->combined_acl_counters +
                                                   match_acl_in_index,
                                                   thread_index,
                                                   match_rule_index,
                                                   1,
                                                   saved_byte_count);

              }

	      b[0]->error = error_node->errors[action];

	      if (ACL_ACTION_PERMIT == action)
		pkts_acl_permit++;

	      if (ACL_ACTION_PERMIT_REFLECT == action)
		{
		  if (!acl_fa_can_add_session (am, is_input, sw_if_index[0]))
		    acl_fa_try_recycle_session (am, is_input,
						thread_index,
						sw_if_index[0], now);

		  if (acl_fa_can_add_session (am, is_input, sw_if_index[0]))
		    {
		      u16 current_policy_epoch =
			get_current_policy_epoch (am, is_input,
						  sw_if_index[0]);
		      fa_full_session_id_t f_sess_id =
			acl_fa_add_session (am, is_input, is_ip6,
					    sw_if_index[0],
					    now, &fa_5tuple[0],
					    current_policy_epoch, &action_expand);

		      /* perform the accounting for the newly added session */
		      process_established_session (vm, am,
						   node->node_index,
						   is_input, now,
						   f_sess_id,
						   &sw_if_index[0],
						   &fa_5tuple[0],
						   b[0]->current_length,
						   node_trace_on,
						   &trace_bitmap);
		      pkts_new_session++;
		      /*
		       * If the next 5tuple is the same and we just added the session,
		       * the f_sess_id_next can not be ~0. Correct it.
		       */
		      if ((f_sess_id_next.as_u64 == ~0ULL)
			  && 0 == memcmp (&fa_5tuple[1], &fa_5tuple[0],
					  sizeof (fa_5tuple[1])))
			f_sess_id_next = f_sess_id;
		    }
		  else
		    {
		      action = ACL_ACTION_DENY;
		      b[0]->error =
			error_node->errors
			[ACL_FA_ERROR_ACL_TOO_MANY_SESSIONS];
		    }
		}

	    }

	  {
	    /* speculatively get the next0 */
	    vnet_feature_next_u16 (&next[0], b[0]);
	    /* if the action is not deny - then use that next */
	    next[0] = action ? next[0] : 0;

        if (ACL_ACTION_PUNT == action)
        {
            next[0] = ACL_FA_PUNT;
        }

        /* Proc action expand */
        acl_action_expand_proc(vm, b[0], &next[0], &action_expand);

        b[0]->acl_index = match_acl_in_index;
        b[0]->flags |= VLIB_BUFFER_ACL_INDEX_VALID;
	  }

	  if (node_trace_on)	// PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	    {
	      maybe_trace_buffer (vm, node, b[0], sw_if_index[0], lc_index0,
				  next[0], match_acl_in_index,
				  match_rule_index, &fa_5tuple[0], action,
				  trace_bitmap);
	    }

	  next++;
	  b++;
	  fa_5tuple++;
	  sw_if_index++;
	  hash++;
	  n_left -= 1;
    }

  /*
   * if we were had an acl match then we have a counter to increment.
   * else it is all zeroes, so this will be harmless.
   */

  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_CHECK, frame->n_vectors);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_EXIST_SESSION,
			       pkts_exist_session);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_NEW_SESSION,
			       pkts_new_session);
  vlib_node_increment_counter (vm, node->node_index,
			       ACL_FA_ERROR_ACL_PERMIT, pkts_acl_permit);
  return frame->n_vectors;
}

always_inline uword
acl_fa_outer_node_fn (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame,
		      int is_ip6, int is_input, int is_l2_path,
		      int do_stateful_datapath)
{
  acl_main_t *am = &acl_main;

  acl_fa_node_common_prepare_fn (vm, node, frame, is_ip6, is_input,
				 is_l2_path, do_stateful_datapath);

  if (am->reclassify_sessions)
    {
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	return acl_fa_inner_node_fn (vm, node, frame, is_ip6, is_input,
				     is_l2_path, do_stateful_datapath,
				     1 /* trace */ ,
				     1 /* reclassify */ );
      else
	return acl_fa_inner_node_fn (vm, node, frame, is_ip6, is_input,
				     is_l2_path, do_stateful_datapath, 0,
				     1 /* reclassify */ );
    }
  else
    {
      if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
	return acl_fa_inner_node_fn (vm, node, frame, is_ip6, is_input,
				     is_l2_path, do_stateful_datapath,
				     1 /* trace */ ,
				     0);
      else
	return acl_fa_inner_node_fn (vm, node, frame, is_ip6, is_input,
				     is_l2_path, do_stateful_datapath, 0, 0);
    }
}

always_inline uword
acl_fa_node_fn (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame, int is_ip6,
		int is_input, int is_l2_path)
{
  /* select the reclassify/no-reclassify version of the datapath */
  acl_main_t *am = &acl_main;
  acl_fa_per_worker_data_t *pw = &am->per_worker_data[vm->thread_index];
  uword rv;

  if (am->fa_sessions_hash_is_initialized)
    rv = acl_fa_outer_node_fn (vm, node, frame, is_ip6, is_input,
			       is_l2_path, 1);
  else
    rv = acl_fa_outer_node_fn (vm, node, frame, is_ip6, is_input,
			       is_l2_path, 0);

  vlib_buffer_enqueue_to_next (vm, node, vlib_frame_vector_args (frame),
			       pw->nexts, frame->n_vectors);
  return rv;
}


static u8 *
format_fa_5tuple (u8 * s, va_list * args)
{
  fa_5tuple_t *p5t = va_arg (*args, fa_5tuple_t *);
  void *paddr0;
  void *paddr1;
  void *format_address_func;
  void *ip_af;
  void *ip_frag_txt =
    p5t->pkt.is_nonfirst_fragment ? " non-initial fragment" : "";

  if (p5t->pkt.is_ip6)
    {
      ip_af = "ip6";
      format_address_func = format_ip6_address;
      paddr0 = &p5t->ip6_addr[0];
      paddr1 = &p5t->ip6_addr[1];
    }
  else
    {
      ip_af = "ip4";
      format_address_func = format_ip4_address;
      paddr0 = &p5t->ip4_addr[0];
      paddr1 = &p5t->ip4_addr[1];
    }

  s =
    format (s, "lc_index %d l3 %s%s ", p5t->pkt.lc_index, ip_af, ip_frag_txt);
  s =
    format (s, "src_sw_if_index %d ", p5t->src_sw_if_index);
  s =
    format (s, "%U -> %U ", format_address_func, paddr0, format_address_func,
	    paddr1);
  s = format (s, "%U ", format_fa_session_l4_key, &p5t->l4);
  s = format (s, "tcp flags (%s) %02x rsvd %x",
	      p5t->pkt.tcp_flags_valid ? "valid" : "invalid",
	      p5t->pkt.tcp_flags, p5t->pkt.flags_reserved);
  return s;
}

#ifndef CLIB_MARCH_VARIANT
u8 *
format_acl_plugin_5tuple (u8 * s, va_list * args)
{
  return format_fa_5tuple (s, args);
}
#endif

/* packet trace format function */
static u8 *
format_acl_plugin_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  acl_fa_trace_t *t = va_arg (*args, acl_fa_trace_t *);

  s =
    format (s,
	    "acl-plugin: lc_index: %d, sw_if_index %d, next index %d, action: %d, match: acl %d rule %d trace_bits %08x\n"
	    "  pkt info %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",
	    t->lc_index, t->sw_if_index, t->next_index, t->action,
	    t->match_acl_in_index, t->match_rule_index, t->trace_bitmap,
	    t->packet_info[0], t->packet_info[1], t->packet_info[2],
	    t->packet_info[3], t->packet_info[4], t->packet_info[5],
	    t->packet_info[6], t->packet_info[7], t->packet_info[8]
        );

  /* Now also print out the packet_info in a form usable by humans */
  s = format (s, "\n   %U", format_fa_5tuple, t->packet_info);
  return s;
}

/* *INDENT-OFF* */

static char *acl_fa_error_strings[] = {
#define _(sym,string) string,
  foreach_acl_fa_error
#undef _
};

VLIB_NODE_FN (acl_in_l2_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 1, 1);
}

VLIB_NODE_FN (acl_in_l2_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 1);
}

VLIB_NODE_FN (acl_out_l2_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 1);
}

VLIB_NODE_FN (acl_out_l2_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 1);
}

/**** L3 processing path nodes ****/

VLIB_NODE_FN (acl_in_fa_ip6_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 1, 0);
}

VLIB_NODE_FN (acl_in_fa_ip4_node) (vlib_main_t * vm,
				   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 0);
}

VLIB_NODE_FN (acl_out_fa_ip6_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 1, 0, 0);
}

VLIB_NODE_FN (acl_out_fa_ip4_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 0);
}

VLIB_NODE_FN (acl_in_sai_nonip_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 1, 1);
}

VLIB_NODE_FN (acl_out_sai_nonip_node) (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame)
{
  return acl_fa_node_fn (vm, node, frame, 0, 0, 1);
}

VLIB_REGISTER_NODE (acl_in_l2_ip6_node) =
{
  .name = "acl-plugin-in-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip6_fa_feature, static) =
{
  .arc_name = "l2-input-ip6",
  .node_name = "acl-plugin-in-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_in_l2_ip4_node) =
{
  .name = "acl-plugin-in-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_in_l2_ip4_fa_feature, static) =
{
  .arc_name = "l2-input-ip4",
  .node_name = "acl-plugin-in-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_out_l2_ip6_node) =
{
  .name = "acl-plugin-out-ip6-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip6_fa_feature, static) =
{
  .arc_name = "l2-output-ip6",
  .node_name = "acl-plugin-out-ip6-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_out_l2_ip4_node) =
{
  .name = "acl-plugin-out-ip4-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_out_l2_ip4_fa_feature, static) =
{
  .arc_name = "l2-output-ip4",
  .node_name = "acl-plugin-out-ip4-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};


VLIB_REGISTER_NODE (acl_in_fa_ip6_node) =
{
  .name = "acl-plugin-in-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_in_ip6_fa_feature, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "acl-plugin-in-ip6-fa",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};

VLIB_REGISTER_NODE (acl_in_fa_ip4_node) =
{
  .name = "acl-plugin-in-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_in_ip4_fa_feature, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "acl-plugin-in-ip4-fa",
  .runs_before = VNET_FEATURES ("ip4-flow-classify"),
};


VLIB_REGISTER_NODE (acl_out_fa_ip6_node) =
{
  .name = "acl-plugin-out-ip6-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_out_ip6_fa_feature, static) = {
  .arc_name = "ip6-output",
  .node_name = "acl-plugin-out-ip6-fa",
  .runs_before = VNET_FEATURES ("ip6-dvr-reinject", "interface-output"),
};

VLIB_REGISTER_NODE (acl_out_fa_ip4_node) =
{
  .name = "acl-plugin-out-ip4-fa",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
    /* edit / add dispositions here */
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_out_ip4_fa_feature, static) = {
  .arc_name = "ip4-output",
  .node_name = "acl-plugin-out-ip4-fa",
  .runs_before = VNET_FEATURES ("ip4-dvr-reinject", "interface-output"),
};

VLIB_REGISTER_NODE (acl_in_sai_nonip_node) =
{
  .name = "acl-plugin-in-sai-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
    /* edit / add dispositions here */
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_in_l2_sai_nonip_fa_feature, static) =
{
  .arc_name = "l2-input-nonip",
  .node_name = "acl-plugin-in-sai-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-input-feat-arc-end"),
};

VLIB_REGISTER_NODE (acl_out_sai_nonip_node) =
{
  .name = "acl-plugin-out-sai-nonip-l2",
  .vector_size = sizeof (u32),
  .format_trace = format_acl_plugin_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (acl_fa_error_strings),
  .error_strings = acl_fa_error_strings,
  .n_next_nodes = ACL_FA_N_NEXT,
    /* edit / add dispositions here */
  .next_nodes =
  {
    [ACL_FA_ERROR_DROP] = "error-drop",
    [ACL_FA_PUNT] = "linux-cp-punt",
  }
};

VNET_FEATURE_INIT (acl_out_l2_sai_nonip_fa_feature, static) =
{
  .arc_name = "l2-output-nonip",
  .node_name = "acl-plugin-out-sai-nonip-l2",
  .runs_before = VNET_FEATURES ("l2-output-feat-arc-end"),
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

