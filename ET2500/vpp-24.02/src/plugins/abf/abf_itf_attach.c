/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <plugins/abf/abf_itf_attach.h>
#include <vnet/fib/fib_path_list.h>
#include <plugins/acl/exports.h>
#include <plugins/spi/spi.h>
#include <plugins/acl/fa_node.h>
#include <plugins/geosite/geosite.h>
#include <plugins/dns/dns.h>

/**
 * Forward declarations;
 */
extern vlib_node_registration_t abf_ip4_node;
extern vlib_node_registration_t abf_ip6_node;

/**
 * FIB node registered type for the bonds
 */
static fib_node_type_t abf_itf_attach_fib_node_type;

/**
 * Pool of ABF interface attachment objects
 */
abf_itf_attach_t *abf_itf_attach_pool;

/**
 * A per interface vector of attached policies. used in the data-plane
 */
static u32 **abf_per_itf[FIB_PROTOCOL_MAX];

/**
 * Per interface values of ACL lookup context IDs. used in the data-plane
 */
static u32 *abf_alctx_per_itf[FIB_PROTOCOL_MAX];

/**
 * ABF ACL module user id returned during the initialization
 */
static u32 abf_acl_user_id;
/*
 * ACL plugin method vtable
 */

static acl_plugin_methods_t acl_plugin;

static void *spi_get_associated_session_ptr;

/**
 * A DB of attachments; key={abf_index,sw_if_index}
 */
static uword *abf_itf_attach_db;

void *geosite_get_index_by_country_code_ptr;
void *geosite_country_index_get_code_ptr;


void *geoip_get_index_by_country_code_ptr;
void *geoip_country_index_get_code_ptr;


void *geosite_get_country_index_by_domain_ptr;

void *geoip_get_country_code_by_ip4_ptr;
void *geoip_get_country_code_by_ip6_ptr;
void *geosite_get_resolved_country_code_by_ip4_ptr;
void *geosite_get_resolved_country_code_by_ip6_ptr;

#define ABF_DNS_PORT 53
#define ABF_DNS_MAX_DOMAIN_LEN 256
#define ABF_DNS_MAX_JUMPS 8

static u64
abf_itf_attach_mk_key (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_index;
  key = key << 32;
  key |= sw_if_index;

  return (key);
}

static abf_itf_attach_t *
abf_itf_attach_db_find (u32 abf_index, u32 sw_if_index)
{
  uword *p;
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  p = hash_get (abf_itf_attach_db, key);

  if (NULL != p)
    return (pool_elt_at_index (abf_itf_attach_pool, p[0]));

  return (NULL);
}

static void
abf_itf_attach_db_add (u32 abf_index, u32 sw_if_index, abf_itf_attach_t * aia)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_set (abf_itf_attach_db, key, aia - abf_itf_attach_pool);
}

static void
abf_itf_attach_db_del (u32 abf_index, u32 sw_if_index)
{
  u64 key;

  key = abf_itf_attach_mk_key (abf_index, sw_if_index);

  hash_unset (abf_itf_attach_db, key);
}

static void
abf_itf_attach_stack (abf_itf_attach_t * aia)
{
  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  dpo_id_t via_dpo = DPO_INVALID;
  abf_policy_t *ap;

  ap = abf_policy_get (aia->aia_abf);

  fib_path_list_contribute_forwarding (ap->ap_pl,
				       (FIB_PROTOCOL_IP4 == aia->aia_proto ?
					FIB_FORW_CHAIN_TYPE_UNICAST_IP4 :
					FIB_FORW_CHAIN_TYPE_UNICAST_IP6),
				       FIB_PATH_LIST_FWD_FLAG_COLLAPSE,
				       &via_dpo);

  dpo_stack_from_node ((FIB_PROTOCOL_IP4 == aia->aia_proto ?
			abf_ip4_node.index :
			abf_ip6_node.index), &aia->aia_dpo, &via_dpo);
  dpo_reset (&via_dpo);
}

static int
abf_cmp_attach_for_sort (void *v1, void *v2)
{
  const abf_itf_attach_t *aia1;
  const abf_itf_attach_t *aia2;

  aia1 = abf_itf_attach_get (*(u32 *) v1);
  aia2 = abf_itf_attach_get (*(u32 *) v2);

  return (aia1->aia_prio - aia2->aia_prio);
}

void
abf_setup_acl_lc (fib_protocol_t fproto, u32 sw_if_index)
{
  u32 *acl_vec = 0;
  u32 *aiai;
  abf_itf_attach_t *aia;

  if (~0 == abf_alctx_per_itf[fproto][sw_if_index])
    return;

  vec_foreach (aiai, abf_per_itf[fproto][sw_if_index])
  {
    aia = abf_itf_attach_get (*aiai);
    vec_add1 (acl_vec, aia->aia_acl);
  }
  acl_plugin.set_acl_vec_for_context (abf_alctx_per_itf[fproto][sw_if_index],
				      acl_vec);
  vec_free (acl_vec);
}

int
abf_itf_attach (fib_protocol_t fproto,
		u32 policy_id, u32 priority, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  abf_policy_t *ap;
  u32 api, aiai;

  api = abf_policy_find (policy_id);

  ASSERT (INDEX_INVALID != api);
  ap = abf_policy_get (api);

  /*
   * check this is not a duplicate
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL != aia)
    return (VNET_API_ERROR_ENTRY_ALREADY_EXISTS);

  /*
   * construct a new attachment object
   */
  pool_get (abf_itf_attach_pool, aia);

  fib_node_init (&aia->aia_node, abf_itf_attach_fib_node_type);
  aia->aia_prio = priority;
  aia->aia_proto = fproto;
  aia->aia_acl = ap->ap_acl;
  aia->aia_abf = api;
  aia->aia_sw_if_index = sw_if_index;
  aiai = aia - abf_itf_attach_pool;
  abf_itf_attach_db_add (policy_id, sw_if_index, aia);

  /*
   * stack the DPO on the forwarding contributed by the path-list
   */
  abf_itf_attach_stack (aia);

  /*
   * Insert the policy on the interfaces list.
   */
  vec_validate_init_empty (abf_per_itf[fproto], sw_if_index, NULL);
  vec_add1 (abf_per_itf[fproto][sw_if_index], aia - abf_itf_attach_pool);
  if (1 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when enabling the first ABF policy on the interface
       * we need to enable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 1, NULL, 0);

      /* if this is the first ABF policy, we need to acquire an ACL lookup context */
      vec_validate_init_empty (abf_alctx_per_itf[fproto], sw_if_index, ~0);
      abf_alctx_per_itf[fproto][sw_if_index] =
	acl_plugin.get_lookup_context_index (abf_acl_user_id, sw_if_index, 0);
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_setup_acl_lc (fproto, sw_if_index);

  /*
   * become a child of the ABF policy so we are notified when
   * its forwarding changes.
   */
  aia->aia_sibling = fib_node_child_add (abf_policy_fib_node_type,
					 api,
					 abf_itf_attach_fib_node_type, aiai);

  return (0);
}

int
abf_itf_detach (fib_protocol_t fproto, u32 policy_id, u32 sw_if_index)
{
  abf_itf_attach_t *aia;
  u32 index;

  /*
   * check this is a valid attachment
   */
  aia = abf_itf_attach_db_find (policy_id, sw_if_index);

  if (NULL == aia)
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  /*
   * first remove from the interface's vector
   */
  ASSERT (abf_per_itf[fproto]);
  ASSERT (abf_per_itf[fproto][sw_if_index]);

  index = vec_search (abf_per_itf[fproto][sw_if_index],
		      aia - abf_itf_attach_pool);

  ASSERT (index != ~0);
  vec_del1 (abf_per_itf[fproto][sw_if_index], index);

  if (0 == vec_len (abf_per_itf[fproto][sw_if_index]))
    {
      /*
       * when deleting the last ABF policy on the interface
       * we need to disable the interface input feature
       */
      vnet_feature_enable_disable ((FIB_PROTOCOL_IP4 == fproto ?
				    "ip4-unicast" :
				    "ip6-unicast"),
				   (FIB_PROTOCOL_IP4 == fproto ?
				    "abf-input-ip4" :
				    "abf-input-ip6"),
				   sw_if_index, 0, NULL, 0);

      /* Return the lookup context, invalidate its id in our records */
      acl_plugin.put_lookup_context_index (abf_alctx_per_itf[fproto]
					   [sw_if_index]);
      abf_alctx_per_itf[fproto][sw_if_index] = ~0;
    }
  else
    {
      vec_sort_with_function (abf_per_itf[fproto][sw_if_index],
			      abf_cmp_attach_for_sort);
    }

  /* Prepare and set the list of ACLs for lookup within the context */
  abf_setup_acl_lc (fproto, sw_if_index);

  /*
   * remove the dependency on the policy
   */
  fib_node_child_remove (abf_policy_fib_node_type,
			 aia->aia_abf, aia->aia_sibling);

  /*
   * remove the attachment from the DB
   */
  abf_itf_attach_db_del (policy_id, sw_if_index);

  /*
   * release our locks on FIB forwarding data
   */
  dpo_reset (&aia->aia_dpo);

  /*
   * return the object
   */
  pool_put (abf_itf_attach_pool, aia);

  return (0);
}

static u8 *
format_abf_intf_attach (u8 * s, va_list * args)
{
  abf_itf_attach_t *aia = va_arg (*args, abf_itf_attach_t *);
  abf_policy_t *ap;

  ap = abf_policy_get (aia->aia_abf);
  s = format (s, "abf-interface-attach: policy:%d priority:%d",
	      ap->ap_id, aia->aia_prio);
  s = format (s, "\n  %U", format_dpo_id, &aia->aia_dpo, 2);

  return (s);
}

static clib_error_t *
abf_itf_attach_cmd (vlib_main_t * vm,
		    unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u32 policy_id, sw_if_index;
  fib_protocol_t fproto;
  u32 is_del, priority;
  vnet_main_t *vnm;

  is_del = 0;
  sw_if_index = policy_id = ~0;
  vnm = vnet_get_main ();
  fproto = FIB_PROTOCOL_MAX;
  priority = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "del"))
	is_del = 1;
      else if (unformat (input, "add"))
	is_del = 0;
      else if (unformat (input, "ip4"))
	fproto = FIB_PROTOCOL_IP4;
      else if (unformat (input, "ip6"))
	fproto = FIB_PROTOCOL_IP6;
      else if (unformat (input, "policy %d", &policy_id))
	;
      else if (unformat (input, "priority %d", &priority))
	;
      else if (unformat (input, "%U",
			 unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == policy_id)
    {
      return (clib_error_return (0, "invalid policy ID:%d", policy_id));
    }
  if (~0 == sw_if_index)
    {
      return (clib_error_return (0, "invalid interface name"));
    }
  if (FIB_PROTOCOL_MAX == fproto)
    {
      return (clib_error_return (0, "Specify either ip4 or ip6"));
    }

  if (~0 == abf_policy_find (policy_id))
    return (clib_error_return (0, "invalid policy ID:%d", policy_id));

  if (is_del)
    abf_itf_detach (fproto, policy_id, sw_if_index);
  else
    abf_itf_attach (fproto, policy_id, priority, sw_if_index);

  return (NULL);
}

/* *INDENT-OFF* */
/**
 * Attach an ABF policy to an interface.
 */
VLIB_CLI_COMMAND (abf_itf_attach_cmd_node, static) = {
  .path = "abf attach",
  .function = abf_itf_attach_cmd,
  .short_help = "abf attach <ip4|ip6> [del] policy <value> <interface>",
  // this is not MP safe
};
/* *INDENT-ON* */

static clib_error_t *
abf_show_attach_cmd (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  const abf_itf_attach_t *aia;
  u32 sw_if_index, *aiai;
  fib_protocol_t fproto;
  vnet_main_t *vnm;

  sw_if_index = ~0;
  vnm = vnet_get_main ();

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U",
		    unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else
	return (clib_error_return (0, "unknown input '%U'",
				   format_unformat_error, input));
    }

  if (~0 == sw_if_index)
    {
      vlib_cli_output (vm, "specify an interface");
    }

  /* *INDENT-OFF* */
  FOR_EACH_FIB_IP_PROTOCOL(fproto)
  {
    if (sw_if_index < vec_len(abf_per_itf[fproto]))
      {
        if (vec_len(abf_per_itf[fproto][sw_if_index]))
          vlib_cli_output(vm, "%U:", format_fib_protocol, fproto);

        vec_foreach(aiai, abf_per_itf[fproto][sw_if_index])
          {
            aia = pool_elt_at_index(abf_itf_attach_pool, *aiai);
            vlib_cli_output(vm, " %U", format_abf_intf_attach, aia);
          }
      }
  }
  /* *INDENT-ON* */
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (abf_show_attach_cmd_node, static) = {
  .path = "show abf attach",
  .function = abf_show_attach_cmd,
  .short_help = "show abf attach <interface>",
  .is_mp_safe = 1,
};
/* *INDENT-ON* */

void
abf_itf_attach_walk (abf_itf_attach_walk_cb_t cb, void *ctx)
{
  u32 aii;

  /* *INDENT-OFF* */
  pool_foreach_index (aii, abf_itf_attach_pool)
   {
    if (!cb(aii, ctx))
      break;
  }
  /* *INDENT-ON* */
}

typedef enum abf_next_t_
{
  ABF_NEXT_DROP,
  ABF_N_NEXT,
} abf_next_t;

typedef struct abf_input_trace_t_
{
  abf_next_t next;
  index_t index;
  u32 src_sw_if_index;
  u32 acl_index;
  u32 acl_rule;
} abf_input_trace_t;

typedef enum
{
#define abf_error(n,s) ABF_ERROR_##n,
#include "abf_error.def"
#undef abf_error
  ABF_N_ERROR,
} abf_error_t;



always_inline void
abf_vec_add_unique_u32 (u32 **dst, u32 value)
{
  u32 *p;

  vec_foreach (p, *dst)
    {
      if (*p == value)
	return;
    }

  vec_add1 (*dst, value);
}

always_inline void
abf_vec_append_unique_u32 (u32 **dst, u32 *src)
{
  u32 *p;

  vec_foreach (p, src)
    abf_vec_add_unique_u32 (dst, *p);
}

always_inline int
abf_dns_read_name (const u8 *dns, const u8 *end, const u8 *pos,
		   char *domain, u16 *domain_length, const u8 **next)
{
  const u8 *p = pos;
  u16 domain_len = 0;
  int jumps = 0;
  int jumped = 0;

  if (pos >= end)
    return -1;

  while (p < end)
    {
      u8 label_len = *p;

      if (label_len == 0)
	{
	  if (!jumped)
	    *next = p + 1;
	  if (domain_len > 0)
	    domain[domain_len - 1] = '\0';
	  else
	    domain[0] = '\0';
	  *domain_length = domain_len;
	  return domain_len > 0 ? 0 : -1;
	}

      if ((label_len & 0xC0) == 0xC0)
	{
	  u16 offset;

	  if (p + 1 >= end)
	    return -1;

	  offset = clib_net_to_host_u16 (*(u16 *) p) & 0x3FFF;
	  if (offset >= (u16) (end - dns))
	    return -1;

	  if (!jumped)
	    *next = p + 2;

	  if (jumps++ >= ABF_DNS_MAX_JUMPS)
	    return -1;

	  p = dns + offset;
	  jumped = 1;
	  continue;
	}

      if ((label_len & 0xC0) != 0)
	return -1;

      p++;
      if (p + label_len > end)
	return -1;

      if (domain_len + label_len + 1 >= ABF_DNS_MAX_DOMAIN_LEN)
	return -1;

      clib_memcpy (domain + domain_len, p, label_len);
      domain_len += label_len;
      domain[domain_len++] = '.';
      p += label_len;
    }

  return -1;
}

always_inline u8
abf_get_udp_payload (vlib_buffer_t *b0, int is_ip6, u8 **payload,
		     u16 *payload_length)
{
  i16 l3_hdr_offset = 0;

  if (b0->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    l3_hdr_offset = vnet_buffer (b0)->l3_hdr_offset;

  if (is_ip6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) (b0->data + l3_hdr_offset);
      udp_header_t *udp;

      if (ip6->protocol != IP_PROTOCOL_UDP)
	return 0;

      udp = (udp_header_t *) (ip6 + 1);
      if (clib_net_to_host_u16 (udp->length) < sizeof (*udp))
	return 0;

      *payload = (u8 *) (udp + 1);
      *payload_length = clib_net_to_host_u16 (udp->length) - sizeof (*udp);
      return 1;
    }
  else
    {
      ip4_header_t *ip4 = (ip4_header_t *) (b0->data + l3_hdr_offset);
      u8 ip4_hdr_len = ip4_header_bytes (ip4);
      udp_header_t *udp;

      if (ip4->protocol != IP_PROTOCOL_UDP)
	return 0;

      udp = (udp_header_t *) (((u8 *) ip4) + ip4_hdr_len);
      if (clib_net_to_host_u16 (udp->length) < sizeof (*udp))
	return 0;

      *payload = (u8 *) (udp + 1);
      *payload_length = clib_net_to_host_u16 (udp->length) - sizeof (*udp);
      return 1;
    }
}

always_inline u8
abf_get_dns_request_geosite_indices (vlib_buffer_t *b0, fa_5tuple_t *tuple,
				     int is_ip6, u32 **indices)
{
  u8 *payload = 0;
  const u8 *pos;
  const u8 *end;
  dns_header_t_ *dns;
  char qname[ABF_DNS_MAX_DOMAIN_LEN];
  u16 qname_len = 0;
  u16 flags;
  u16 qdcount;
  u16 payload_length = 0;
  u32 *tmp = 0;

  if (tuple->l4.proto != IP_PROTOCOL_UDP || tuple->l4.port[1] != ABF_DNS_PORT)
    return 0;

  if (!abf_get_udp_payload (b0, is_ip6, &payload, &payload_length))
    return 0;

  if (payload_length < sizeof (*dns))
    {
      return 0;
    }

  dns = (dns_header_t_ *) payload;
  flags = clib_net_to_host_u16 (dns->flags);
  qdcount = clib_net_to_host_u16 (dns->qdcount);
  if ((flags & 0x8000) || qdcount == 0)
    return 0;

  pos = payload + sizeof (*dns);
  end = payload + payload_length;
  if (abf_dns_read_name (payload, end, pos, qname, &qname_len, &pos))
    {
      return 0;
    }

  if (pos + 4 > end)
    {
      return 0;
    }

  tmp = ((__typeof__ (geosite_get_country_index_by_domain) *)
	 geosite_get_country_index_by_domain_ptr) (qname);
  if (tmp)
    {
      abf_vec_append_unique_u32 (indices, tmp);
      vec_free (tmp);
      // clib_warning ("abf dns req: qname=%s geosite-count=%u", qname,
      // 	    vec_len (*indices));
      return 1;
    }

  return 0;
}

always_inline u8
abf_get_resolved_geosite_indices (fa_5tuple_t *tuple, int is_ip6,
				  u32 **indices)
{
  u32 *tmp = 0;

  if (is_ip6)
    {
      tmp = ((__typeof__ (geosite_get_resolved_country_code_by_ip6) *)
	     geosite_get_resolved_country_code_by_ip6_ptr) (tuple->ip6_addr[1]);
      abf_vec_append_unique_u32 (indices, tmp);
      vec_free (tmp);
    }
  else
    {
      tmp = ((__typeof__ (geosite_get_resolved_country_code_by_ip4) *)
	     geosite_get_resolved_country_code_by_ip4_ptr) (tuple->ip4_addr[1]);
      abf_vec_append_unique_u32 (indices, tmp);
      vec_free (tmp);
    }

  if (vec_len (*indices))
    {
      // clib_warning ("abf resolved geosite: count=%u", vec_len (*indices));
      return 1;
    }

  return 0;
}

always_inline u8
abf_get_geoip_indices (fa_5tuple_t *tuple, int is_ip6, u32 **indices)
{
  u32 *tmp = 0;

  if (is_ip6)
    tmp = ((__typeof__ (geoip_get_country_code_by_ip6) *)
	   geoip_get_country_code_by_ip6_ptr) (tuple->ip6_addr[1]);
  else
    tmp = ((__typeof__ (geoip_get_country_code_by_ip4) *)
	   geoip_get_country_code_by_ip4_ptr) (tuple->ip4_addr[1]);

  abf_vec_append_unique_u32 (indices, tmp);
  vec_free (tmp);

  if (vec_len (*indices))
    {
      return 1;
    }

  return 0;
}

always_inline void
abf_keep_best_acl_match (u8 matched, u8 cand_action, u32 cand_acl_pos,
			 u32 cand_acl_index, u32 cand_rule_index,
			 u8 *best_action, u32 *best_acl_pos,
			 u32 *best_acl_index, u32 *best_rule_index,
			 u32 branch)
{
  if (!matched || cand_action == 0)
    return;

  if (cand_acl_pos < *best_acl_pos)
    {
      *best_action = cand_action;
      *best_acl_pos = cand_acl_pos;
      *best_acl_index = cand_acl_index;
      *best_rule_index = cand_rule_index;
    }
}

always_inline void
abf_match_one_geo_index (u32 lc_index, fa_5tuple_opaque_t *tuple,
			 int is_ip6, u32 cc_index, u8 branch,
			 u8 *best_action, u32 *best_acl_pos,
			 u32 *best_acl_index, u32 *best_rule_index,
			 u32 *trace_bitmap)
{
  acl_main_t *am = acl_plugin.p_acl_main;
  fa_5tuple_opaque_t tuple_copy;
  fa_5tuple_t *tuple_internal;
  u32 *cc_indices = 0;
  u8 action = 0;
  u32 acl_pos = ~0;
  u32 acl_index = ~0;
  u32 rule_index = ~0;
  u8 get_cc_code;
  int hash_path;
  int matched;

  clib_memcpy_fast (&tuple_copy, tuple, sizeof (tuple_copy));
  tuple_internal = (fa_5tuple_t *) &tuple_copy;

  if (branch == ACL_PKT_GET_GEOIP_INDEX)
    {
      tuple_internal->geosite_cc_index = GEO_CFG;
      tuple_internal->geoip_cc_index = (u16) cc_index;
      get_cc_code = ACL_PKT_GET_GEOIP_INDEX;
    }
  else
    {
      tuple_internal->geosite_cc_index = (u16) cc_index;
      tuple_internal->geoip_cc_index = GEO_CFG;
      get_cc_code = branch;
    }

  vec_add1 (cc_indices, cc_index);
  hash_path = am->use_hash_acl_matching &&
	      !tuple_internal->pkt.is_nonfirst_fragment;

  matched = acl_plugin_match_5tuple_inline (
    acl_plugin.p_acl_main, lc_index, &tuple_copy, is_ip6, &action, &acl_pos,
    &acl_index, &rule_index, trace_bitmap, get_cc_code, cc_indices);

  if (!hash_path)
    vec_free (cc_indices);

  abf_keep_best_acl_match (matched, action, acl_pos, acl_index, rule_index,
			   best_action, best_acl_pos, best_acl_index,
			   best_rule_index, branch);
}

always_inline void
abf_match_geo_index_vec (u32 lc_index, fa_5tuple_opaque_t *tuple, int is_ip6,
			 u32 *indices, u8 branch, u8 *best_action,
			 u32 *best_acl_pos, u32 *best_acl_index,
			 u32 *best_rule_index, u32 *trace_bitmap)
{
  u32 *cc;

  vec_foreach (cc, indices)
    abf_match_one_geo_index (lc_index, tuple, is_ip6, *cc, branch,
			     best_action, best_acl_pos, best_acl_index,
			     best_rule_index, trace_bitmap);
}

always_inline void
abf_match_normal_5tuple (u32 lc_index, fa_5tuple_opaque_t *tuple, int is_ip6,
			 u8 *best_action, u32 *best_acl_pos,
			 u32 *best_acl_index, u32 *best_rule_index,
			 u32 *trace_bitmap)
{
  fa_5tuple_opaque_t tuple_copy;
  u8 action = 0;
  u32 acl_pos = ~0;
  u32 acl_index = ~0;
  u32 rule_index = ~0;
  int matched;

  clib_memcpy_fast (&tuple_copy, tuple, sizeof (tuple_copy));
  matched = acl_plugin_match_5tuple_inline (
    acl_plugin.p_acl_main, lc_index, &tuple_copy, is_ip6, &action, &acl_pos,
    &acl_index, &rule_index, trace_bitmap, 0, NULL);

  abf_keep_best_acl_match (matched, action, acl_pos, acl_index, rule_index,
			   best_action, best_acl_pos, best_acl_index,
			   best_rule_index, 0);
}

always_inline int
abf_match_5tuple_with_geo (u32 lc_index, vlib_buffer_t *b0,
			   fa_5tuple_opaque_t *tuple, int is_ip6,
			   u8 *best_action, u32 *best_acl_pos,
			   u32 *best_acl_index, u32 *best_rule_index,
			   u32 *trace_bitmap)
{
  acl_main_t *am = acl_plugin.p_acl_main;
  acl_lookup_context_t *lc;
  fa_5tuple_t *tuple_internal = (fa_5tuple_t *) tuple;
  u32 *dns_req_geosite_indices = 0;
  u32 *resolved_geosite_indices = 0;
  u32 *geoip_indices = 0;
  u8 get_cc_code = 0;

  *best_action = 0;
  *best_acl_pos = ~0;
  *best_acl_index = ~0;
  *best_rule_index = ~0;

  lc = pool_elt_at_index (am->acl_lookup_contexts, lc_index);

  if (lc->geosite_required)
    {
      if (abf_get_dns_request_geosite_indices (b0, tuple_internal, is_ip6,
					       &dns_req_geosite_indices))
	get_cc_code |= ACL_PKT_GET_DNS_REQ;
      else if (abf_get_resolved_geosite_indices (tuple_internal, is_ip6,
						 &resolved_geosite_indices))
	get_cc_code |= ACL_PKT_GET_GEOSITE_INDEX;
    }

  if (lc->geoip_required &&
      abf_get_geoip_indices (tuple_internal, is_ip6, &geoip_indices))
    get_cc_code |= ACL_PKT_GET_GEOIP_INDEX;

  if (get_cc_code & ACL_PKT_GET_DNS_REQ)
    abf_match_geo_index_vec (lc_index, tuple, is_ip6, dns_req_geosite_indices,
			     ACL_PKT_GET_DNS_REQ, best_action, best_acl_pos,
			     best_acl_index, best_rule_index, trace_bitmap);
  else if (get_cc_code & ACL_PKT_GET_GEOSITE_INDEX)
    abf_match_geo_index_vec (lc_index, tuple, is_ip6, resolved_geosite_indices,
			     ACL_PKT_GET_GEOSITE_INDEX, best_action,
			     best_acl_pos, best_acl_index, best_rule_index,
			     trace_bitmap);

  if (get_cc_code & ACL_PKT_GET_GEOIP_INDEX)
    abf_match_geo_index_vec (lc_index, tuple, is_ip6, geoip_indices,
			     ACL_PKT_GET_GEOIP_INDEX, best_action,
			     best_acl_pos, best_acl_index, best_rule_index,
			     trace_bitmap);

  abf_match_normal_5tuple (lc_index, tuple, is_ip6, best_action,
			   best_acl_pos, best_acl_index, best_rule_index,
			   trace_bitmap);

  // clib_warning ("abf geo match: final get_cc=0x%x best_pos=%u acl=%u rule=%u action=%u",
  // 	get_cc_code, *best_acl_pos, *best_acl_index, *best_rule_index,
  // 	*best_action);

  vec_free (dns_req_geosite_indices);
  vec_free (resolved_geosite_indices);
  vec_free (geoip_indices);

  return *best_acl_pos != ~0;
}




always_inline uword
abf_input_inline (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame, fib_protocol_t fproto)
{
  u32 n_left_from, *from, *to_next, next_index, matches, misses;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  matches = misses = 0;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const u32 *attachments0;
	  const abf_itf_attach_t *aia0;
	  abf_next_t next0 = ABF_NEXT_DROP;
	  vlib_buffer_t *b0;
	  u32 bi0, sw_if_index0;
	  fa_5tuple_opaque_t fa_5tuple0;
	  u32 match_acl_index = ~0;
	  u32 match_acl_pos = ~0;
	  u32 match_rule_index = ~0;
      u32 match_src_sw_if_index = 0;
	  u32 trace_bitmap = 0;
	  u32 lc_index;
	  u8 action;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  ASSERT (vec_len (abf_per_itf[fproto]) > sw_if_index0);
	  attachments0 = abf_per_itf[fproto][sw_if_index0];

	  ASSERT (vec_len (abf_alctx_per_itf[fproto]) > sw_if_index0);
	  /*
	   * check if any of the policies attached to this interface matches.
	   */
	  lc_index = abf_alctx_per_itf[fproto][sw_if_index0];

	  /*
	     A non-inline version looks like this:

	     acl_plugin.fill_5tuple (lc_index, b0, (FIB_PROTOCOL_IP6 == fproto),
	     1, 0, &fa_5tuple0);
	     if (acl_plugin.match_5tuple
	     (lc_index, &fa_5tuple0, (FIB_PROTOCOL_IP6 == fproto), &action,
	     &match_acl_pos, &match_acl_index, &match_rule_index,
	     &trace_bitmap))
	     . . .
	   */
	  acl_plugin_fill_5tuple_inline (acl_plugin.p_acl_main, lc_index, b0,
					 (FIB_PROTOCOL_IP6 == fproto), 1, 0,
					 &fa_5tuple0);

      fa_5tuple_t *fa_5tuple_p = (fa_5tuple_t*)&fa_5tuple0;
      fa_5tuple_p->src_sw_if_index = 0;

      spi_session_t *spi_associated_sess = ((__typeof__ (vlib_buffer_spi_get_associated_session) *)spi_get_associated_session_ptr) (b0);
      if(spi_associated_sess != NULL)
      {
          fa_5tuple_p->src_sw_if_index = spi_associated_sess->flow[SPI_FLOW_DIR_UPLINK].in_sw_if_index;;
          match_src_sw_if_index = fa_5tuple_p->src_sw_if_index;
      }

	  if (abf_match_5tuple_with_geo (
		lc_index, b0, &fa_5tuple0, (FIB_PROTOCOL_IP6 == fproto),
		&action, &match_acl_pos, &match_acl_index, &match_rule_index,
		&trace_bitmap) &&
	      action > 0)
	    {
	      /*
	       * match:
	       *  follow the DPO chain
	       */
	      aia0 = abf_itf_attach_get (attachments0[match_acl_pos]);

	      next0 = aia0->aia_dpo.dpoi_next_node;
	      vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
		aia0->aia_dpo.dpoi_index;
	      matches++;
	    }
	  else
	    {
	      /*
	       * miss:
	       *  move on down the feature arc
	       */
	      vnet_feature_next (&next0, b0);
	      misses++;
	    }

	  if (PREDICT_FALSE (b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      abf_input_trace_t *tr;

	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next = next0;
	      tr->index = vnet_buffer (b0)->ip.adj_index[VLIB_TX];
          tr->src_sw_if_index = match_src_sw_if_index;
          tr->acl_index = match_acl_index;
          tr->acl_rule = match_rule_index;
	    }
	  vnet_buffer (b0)->ip.flow_hash = 0;
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, bi0,
					   next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm,
			       (fproto = FIB_PROTOCOL_IP6 ?
				abf_ip4_node.index :
				abf_ip6_node.index),
			       ABF_ERROR_MATCHED, matches);
  vlib_node_increment_counter (vm,
			       (fproto = FIB_PROTOCOL_IP6 ?
				abf_ip4_node.index :
				abf_ip6_node.index),
			       ABF_ERROR_MISSED, misses);

  return frame->n_vectors;
}

static uword
abf_input_ip4 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP4);
}

static uword
abf_input_ip6 (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return abf_input_inline (vm, node, frame, FIB_PROTOCOL_IP6);
}

static u8 *
format_abf_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  abf_input_trace_t *t = va_arg (*args, abf_input_trace_t *);

  s = format (s, " next %d index %d", t->next, t->index);
  s = format (s, " src_sw_if_index %d match acl_index %d rule %d", 
          t->src_sw_if_index, t->acl_index, t->acl_rule);
  return s;
}

static char *abf_error_strings[] = {
#define abf_error(n,s) s,
#include "abf_error.def"
#undef abf_error
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (abf_ip4_node) =
{
  .function = abf_input_ip4,
  .name = "abf-input-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ABF_N_ERROR,
  .error_strings = abf_error_strings,
  .n_next_nodes = ABF_N_NEXT,
  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VLIB_REGISTER_NODE (abf_ip6_node) =
{
  .function = abf_input_ip6,
  .name = "abf-input-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_abf_input_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = ABF_N_NEXT,

  .next_nodes =
  {
    [ABF_NEXT_DROP] = "error-drop",
  }
};

VNET_FEATURE_INIT (abf_ip4_feat, static) =
{
  .arc_name = "ip4-unicast",
  .node_name = "abf-input-ip4",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip4-fa"),
};

VNET_FEATURE_INIT (abf_ip6_feat, static) =
{
  .arc_name = "ip6-unicast",
  .node_name = "abf-input-ip6",
  .runs_after = VNET_FEATURES ("acl-plugin-in-ip6-fa"),
};
/* *INDENT-ON* */

static fib_node_t *
abf_itf_attach_get_node (fib_node_index_t index)
{
  abf_itf_attach_t *aia = abf_itf_attach_get (index);
  return (&(aia->aia_node));
}

static abf_itf_attach_t *
abf_itf_attach_get_from_node (fib_node_t * node)
{
  return ((abf_itf_attach_t *) (((char *) node) -
				STRUCT_OFFSET_OF (abf_itf_attach_t,
						  aia_node)));
}

static void
abf_itf_attach_last_lock_gone (fib_node_t * node)
{
  /*
   * ABF interface attachments are leaves on the graph.
   * we do not manage locks from children.
   */
}

/*
 * abf_itf_attach_back_walk_notify
 *
 * A back walk has reached this BIER fmask
 */
static fib_node_back_walk_rc_t
abf_itf_attach_back_walk_notify (fib_node_t * node,
				 fib_node_back_walk_ctx_t * ctx)
{
  /*
   * re-stack the fmask on the n-eos of the via
   */
  abf_itf_attach_t *aia = abf_itf_attach_get_from_node (node);

  abf_itf_attach_stack (aia);

  return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t abf_itf_attach_vft = {
  .fnv_get = abf_itf_attach_get_node,
  .fnv_last_lock = abf_itf_attach_last_lock_gone,
  .fnv_back_walk = abf_itf_attach_back_walk_notify,
};

static clib_error_t *
abf_itf_bond_init (vlib_main_t * vm)
{
  abf_itf_attach_fib_node_type =
    fib_node_register_new_type ("abf-attach", &abf_itf_attach_vft);
  clib_error_t *acl_init_res = acl_plugin_exports_init (&acl_plugin);
  if (acl_init_res)
    return (acl_init_res);

  abf_acl_user_id =
    acl_plugin.register_user_module ("ABF plugin", "sw_if_index", NULL);

  spi_get_associated_session_ptr = 
    vlib_get_plugin_symbol ("spi_plugin.so", "vlib_buffer_spi_get_associated_session");
  if(spi_get_associated_session_ptr == NULL)
  {
      return clib_error_return (0, "spi_plugin.so is not loaded");
  }

 geosite_get_index_by_country_code_ptr = 
    vlib_get_plugin_symbol ("geosite_plugin.so", "geosite_get_index_by_country_code");
  if(geosite_get_index_by_country_code_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugins5.so is not loaded");
  }

      geosite_country_index_get_code_ptr = 
    vlib_get_plugin_symbol ("geosite_plugin.so", "geosite_get_country_code_by_index");
  if(geosite_country_index_get_code_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugins3.so is not loaded");
  }

      geoip_get_index_by_country_code_ptr = 
    vlib_get_plugin_symbol ("geosite_plugin.so", "geoip_get_index_by_country_code");
  if(geoip_get_index_by_country_code_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugins5.so is not loaded");
  }

      geoip_country_index_get_code_ptr = 
    vlib_get_plugin_symbol ("geosite_plugin.so", "geoip_get_country_code_by_index");
  if(geoip_country_index_get_code_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugins3.so is not loaded");
  }



      geosite_get_country_index_by_domain_ptr = 
    vlib_get_plugin_symbol ("geosite_plugin.so", "geosite_get_country_index_by_domain");
  if(geosite_get_country_index_by_domain_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugins2.so is not loaded");
  }


  geoip_get_country_code_by_ip4_ptr = 
   vlib_get_plugin_symbol ("geosite_plugin.so", "geoip_get_country_code_by_ip4");
  if(geoip_get_country_code_by_ip4_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugin7.so is not loaded");
  }

    geoip_get_country_code_by_ip6_ptr = 
   vlib_get_plugin_symbol ("geosite_plugin.so", "geoip_get_country_code_by_ip6");
  if(geoip_get_country_code_by_ip6_ptr == NULL)
  {
      return clib_error_return (0, "geosite_plugin6.so is not loaded");
  }

  geosite_get_resolved_country_code_by_ip4_ptr =
    vlib_get_plugin_symbol ("geosite_plugin.so",
			    "geosite_get_resolved_country_code_by_ip4");
  if (geosite_get_resolved_country_code_by_ip4_ptr == NULL)
    {
      return clib_error_return (0, "geosite resolved ip4 symbol is not loaded");
    }

  geosite_get_resolved_country_code_by_ip6_ptr =
    vlib_get_plugin_symbol ("geosite_plugin.so",
			    "geosite_get_resolved_country_code_by_ip6");
  if (geosite_get_resolved_country_code_by_ip6_ptr == NULL)
    {
      return clib_error_return (0, "geosite resolved ip6 symbol is not loaded");
    }

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (abf_itf_bond_init) =
{
  .runs_after = VLIB_INITS("acl_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
