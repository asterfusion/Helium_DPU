/*
 * lcp_pppoe.c - pppoe CP packet punt handling node definitions
 *
 * Copyright 2024-2027 Asterfusion Network
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <vlib/vlib.h>
#include <vlibmemory/api.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/fib/fib_sas.h>
#include <vppinfra/error.h>
#include <linux-cp/lcp.api_enum.h>
#include <plugins/linux-cp/lcp_interface.h>
#include <plugins/linux-cp/pppoe.h>

#include <vnet/ppp/packet.h>

pppoe_main_t pppoe_main;

fib_source_t pppoe_fib_src;

static u8 *
format_pppoe_name (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  return format (s, "ppp%d", dev_instance);
}

static clib_error_t *
pppoe_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  u32 hw_flags = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
    VNET_HW_INTERFACE_FLAG_LINK_UP : 0;
  vnet_hw_interface_set_flags (vnm, hw_if_index, hw_flags);

  return /* no error */ 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (pppoe_device_class,static) = {
  .name = "PPPoE",
  .format_device_name = format_pppoe_name,
  .admin_up_down_function = pppoe_interface_admin_up_down,
};
/* *INDENT-ON* */

static u8 *
format_pppoe_header_with_length (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  s = format (s, "unimplemented dev %u", dev_instance);
  return s;
}

static u8 *
pppoe_build_rewrite (vnet_main_t * vnm,
		     u32 sw_if_index,
		     vnet_link_t link_type, const void *dst_address)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;
  pppoe_header_t *pppoe;
  u32 session_id;
  u8 *rw = 0;

  session_id = pem->session_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pem->sessions, session_id);

  int len = sizeof (pppoe_header_t) + sizeof (ethernet_header_t);
  si = vnet_get_sw_interface (vnm, t->encap_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  len += sizeof (ethernet_vlan_header_t);
	}
    }

  vec_validate_aligned (rw, len - 1, CLIB_CACHE_LINE_BYTES);

  ethernet_header_t *eth_hdr = (ethernet_header_t *) rw;
  eth_hdr->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
  pppoe = (pppoe_header_t *) (eth_hdr + 1);

  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  eth_hdr->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
	  ethernet_vlan_header_t *vlan =
	    (ethernet_vlan_header_t *) (eth_hdr + 1);
	  vlan->type = clib_host_to_net_u16 (ETHERNET_TYPE_PPPOE_SESSION);
	  vlan->priority_cfi_and_id =
	    clib_host_to_net_u16 (si->sub.eth.outer_vlan_id);
	  pppoe = (pppoe_header_t *) (vlan + 1);
	}
      si = vnet_get_sw_interface (vnm, si->sup_sw_if_index);
    }

  // set the right mac addresses
  hi = vnet_get_hw_interface (vnm, si->hw_if_index);
  clib_memcpy (eth_hdr->src_address, hi->hw_address, 6);
  clib_memcpy (eth_hdr->dst_address, t->server_mac, 6);

  pppoe->ver_type = PPPOE_VER_TYPE;
  pppoe->code = 0;
  pppoe->session_id = clib_host_to_net_u16 (t->session_id);
  pppoe->length = 0;		/* To be filled in at run-time */

  switch (link_type)
    {
    case VNET_LINK_IP4:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip4);
      break;
    case VNET_LINK_IP6:
      pppoe->ppp_proto = clib_host_to_net_u16 (PPP_PROTOCOL_ip6);
      break;
    default:
      break;
    }

  return rw;
}

/**
 * @brief Fixup the adj rewrite post encap. Insert the packet's length
 */
static void
pppoe_fixup (vlib_main_t * vm,
	     const ip_adjacency_t * adj, vlib_buffer_t * b0, const void *data)
{
  //const pppoe_session_t *t;
  pppoe_header_t *pppoe0;
  uword len = (uword) data;

  /* update the rewrite string */
  pppoe0 = vlib_buffer_get_current (b0) + len;

  pppoe0->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b0)
					 - sizeof (pppoe_header_t)
					 + sizeof (pppoe0->ppp_proto) - len);
}

static void
pppoe_update_adj (vnet_main_t * vnm, u32 sw_if_index, adj_index_t ai)
{
  pppoe_main_t *pem = &pppoe_main;
  dpo_id_t dpo = DPO_INVALID;
  ip_adjacency_t *adj;
  pppoe_session_t *t;
  vnet_sw_interface_t *si;
  u32 session_id;

  ASSERT (ADJ_INDEX_INVALID != ai);

  adj = adj_get (ai);
  session_id = pem->session_index_by_sw_if_index[sw_if_index];
  t = pool_elt_at_index (pem->sessions, session_id);

  uword len = sizeof (ethernet_header_t);

  si = vnet_get_sw_interface (vnm, t->encap_if_index);
  if (si->type == VNET_SW_INTERFACE_TYPE_SUB)
    {
      if (si->sub.eth.flags.one_tag == 1)
	{
	  len += sizeof (ethernet_vlan_header_t);
	}
    }

  switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
      adj_nbr_midchain_update_rewrite (ai, pppoe_fixup, (void *) len,
				       ADJ_FLAG_NONE,
				       pppoe_build_rewrite (vnm,
							    sw_if_index,
							    adj->ia_link,
							    NULL));
      break;
    case IP_LOOKUP_NEXT_MCAST:
      /*
       * Construct a partial rewrite from the known ethernet mcast dest MAC
       * There's no MAC fixup, so the last 2 parameters are 0
       */
      adj_mcast_midchain_update_rewrite (ai, pppoe_fixup, (void *) len,
					 ADJ_FLAG_NONE,
					 pppoe_build_rewrite (vnm,
							      sw_if_index,
							      adj->ia_link,
							      NULL), 0, 0);
      break;

    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
      ASSERT (0);
      break;
    }

  interface_tx_dpo_add_or_lock (vnet_link_to_dpo_proto (adj->ia_link),
				t->encap_if_index, &dpo);

  adj_nbr_midchain_stack (ai, &dpo);

  dpo_reset (&dpo);
}

/* *INDENT-OFF* */
VNET_HW_INTERFACE_CLASS (pppoe_hw_class) =
{
  .name = "PPPoE",
  .format_header = format_pppoe_header_with_length,
  .build_rewrite = pppoe_build_rewrite,
  .update_adjacency = pppoe_update_adj,
  .flags = VNET_HW_INTERFACE_CLASS_FLAG_P2P,
};
/* *INDENT-ON* */

#define foreach_copy_field                      \
_(session_id)                                   \
_(encap_if_index)                               \
_(decap_fib_index)                              \
_(client_ip)                                    \
_(server_ip)

#if 0
static bool
pppoe_decap_next_is_valid (pppoe_main_t * pem, u32 is_ip6,
			   u32 decap_fib_index)
{
  vlib_main_t *vm = pem->vlib_main;
  u32 input_idx = (!is_ip6) ? ip4_input_node.index : ip6_input_node.index;
  vlib_node_runtime_t *r = vlib_node_get_runtime (vm, input_idx);

  return decap_fib_index < r->n_next_nodes;
}
#endif

int lcp_pppoe_session_add(u8 *server_mac, u16 ppp_session_id, u32 encap_sw_if_index, u32 *p_sw_if_index, u8 *sw_if_name, u8 is_add)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t = 0;
  vnet_main_t *vnm = pem->vnet_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  vnet_hw_interface_t *hi;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;
  u32 bucket;
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;

  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */
  /* lookup session_table */
  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
		  server_mac, clib_host_to_net_u16 (ppp_session_id),
		  &key, &bucket, &result);

  if(is_add)
  {
      /* adding a session: session must not already exist */
      if (result.fields.session_index != ~0)
          return VNET_API_ERROR_TUNNEL_EXIST;

      pool_get_aligned (pem->sessions, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      t->session_id = ppp_session_id;
      t->encap_if_index = encap_sw_if_index;
      //t->decap_fib_index; //vrf others to do
      clib_memcpy (t->server_mac, server_mac, 6);

      if (vec_len (pem->free_pppoe_session_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = pem->free_pppoe_session_hw_if_indices
	    [vec_len (pem->free_pppoe_session_hw_if_indices) - 1];
	  vec_dec_len (pem->free_pppoe_session_hw_if_indices, 1);

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - pem->sessions;
	  hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed session before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter (&im->combined_sw_if_counters
				      [VNET_INTERFACE_COUNTER_RX],
				      sw_if_index);
	  vlib_zero_simple_counter (&im->sw_if_counters
				    [VNET_INTERFACE_COUNTER_DROP],
				    sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, pppoe_device_class.index, t - pem->sessions,
	     pppoe_hw_class.index, t - pem->sessions);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);

	  sw_if_index = hi->sw_if_index;
	  /* add default punt feature */
	  vnet_feature_enable_disable("ip4-multicast", "linux-cp-ospfv2-phy",
	          sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable("ip6-multicast", "linux-cp-ospfv3-phy",
	          sw_if_index, 1, NULL, 0);
	  /* enable bfd/bfdv6 punt for interfaces */
	  vnet_feature_enable_disable("ip4-unicast", "linux-cp-bfd-phy",
	          sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable("ip4-multicast", "linux-cp-bfd-phy",
	          sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable("ip6-unicast", "linux-cp-bfdv6-phy",
	          sw_if_index, 1, NULL, 0);
	  vnet_feature_enable_disable("ip6-multicast", "linux-cp-bfdv6-phy",
	          sw_if_index, 1, NULL, 0);

	}

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;
      if(sw_if_name)
      {
	  clib_memcpy(sw_if_name, hi->name, 16);
      }

      vec_validate_init_empty (pem->session_index_by_sw_if_index, sw_if_index,
			       ~0);
      pem->session_index_by_sw_if_index[sw_if_index] = t - pem->sessions;

      /* update pppoe fib with session_index */
      result.fields.session_index = t - pem->sessions;
      result.fields.sw_if_index = sw_if_index;
      pppoe_update_1 (&pem->session_table,
		      server_mac, clib_host_to_net_u16 (ppp_session_id),
		      &key, &bucket, &result);

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      vnet_set_interface_l3_output_node (vnm->vlib_main, sw_if_index,
					 (u8 *) "tunnel-output");

  }
  else
  {
      /* deleting a session: session must exist */
      if (result.fields.session_index == ~0)
          return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (pem->sessions, result.fields.session_index);
      sw_if_index = t->sw_if_index;

      hi = vnet_get_hw_interface (vnm, t->hw_if_index);
      if(sw_if_name && hi)
      {
	  clib_memcpy(sw_if_name, hi->name, 16);
      }

      vnet_reset_interface_l3_output_node (vnm->vlib_main, sw_if_index);
      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      vec_add1 (pem->free_pppoe_session_hw_if_indices, t->hw_if_index);

      pem->session_index_by_sw_if_index[t->sw_if_index] = ~0;

      /* update pppoe fib with session_inde=~0x */
      result.fields.session_index = ~0;
      pppoe_update_1 (&pem->session_table,
		      server_mac, clib_host_to_net_u16 (ppp_session_id),
		      &key, &bucket, &result);
      pool_put (pem->sessions, t);

  }

  if(p_sw_if_index)
  {
     *p_sw_if_index = sw_if_index;
  }
  return 0;
}

int vnet_pppoe_add_del_session
  (vnet_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp)
#if 1
{
  int ret = 0;

  ret = lcp_pppoe_session_add(a->server_mac, a->session_id, a->encap_if_index, sw_if_indexp, NULL, a->is_add);
  if(ret!=0)
  {
     return ret;
  }

  return ret;
}
#else
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t = 0;
  vnet_main_t *vnm = pem->vnet_main;
  u32 hw_if_index = ~0;
  u32 sw_if_index = ~0;
  u32 is_ip6 = a->is_ip6;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;
  u32 bucket;
  pppoe_entry_key_t key;
  pppoe_entry_result_t result;
  fib_prefix_t pfx;

  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */
  clib_memset (&pfx, 0, sizeof (pfx));

  if (!is_ip6)
    {
      pfx.fp_addr.ip4.as_u32 = a->server_ip.ip4.as_u32;
      pfx.fp_len = 32;
      pfx.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      pfx.fp_addr.ip6.as_u64[0] = a->server_ip.ip6.as_u64[0];
      pfx.fp_addr.ip6.as_u64[1] = a->server_ip.ip6.as_u64[1];
      pfx.fp_len = 128;
      pfx.fp_proto = FIB_PROTOCOL_IP6;
    }


  /* lookup session_table */
  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
		  a->server_mac, clib_host_to_net_u16 (a->session_id),
		  &key, &bucket, &result);


  if (a->is_add)
    {
      /* adding a session: session must not already exist */
      if (result.fields.session_index != ~0)
          return VNET_API_ERROR_TUNNEL_EXIST;

#if 0
      /*if not set explicitly, default to ip4 */
      if (!pppoe_decap_next_is_valid (pem, is_ip6, a->decap_fib_index))
	return VNET_API_ERROR_INVALID_DECAP_NEXT;
#endif

      pool_get_aligned (pem->sessions, t, CLIB_CACHE_LINE_BYTES);
      clib_memset (t, 0, sizeof (*t));

      //clib_memcpy (t->local_mac, hi->hw_address, vec_len (hi->hw_address));

      /* copy from arg structure */
#define _(x) t->x = a->x;
      foreach_copy_field;
#undef _

      clib_memcpy (t->server_mac, a->server_mac, 6);

      vnet_hw_interface_t *hi;
      if (vec_len (pem->free_pppoe_session_hw_if_indices) > 0)
	{
	  vnet_interface_main_t *im = &vnm->interface_main;
	  hw_if_index = pem->free_pppoe_session_hw_if_indices
	    [vec_len (pem->free_pppoe_session_hw_if_indices) - 1];
	  vec_dec_len (pem->free_pppoe_session_hw_if_indices, 1);

	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	  hi->dev_instance = t - pem->sessions;
	  hi->hw_instance = hi->dev_instance;

	  /* clear old stats of freed session before reuse */
	  sw_if_index = hi->sw_if_index;
	  vnet_interface_counter_lock (im);
	  vlib_zero_combined_counter
	    (&im->combined_sw_if_counters[VNET_INTERFACE_COUNTER_TX],
	     sw_if_index);
	  vlib_zero_combined_counter (&im->combined_sw_if_counters
				      [VNET_INTERFACE_COUNTER_RX],
				      sw_if_index);
	  vlib_zero_simple_counter (&im->sw_if_counters
				    [VNET_INTERFACE_COUNTER_DROP],
				    sw_if_index);
	  vnet_interface_counter_unlock (im);
	}
      else
	{
	  hw_if_index = vnet_register_interface
	    (vnm, pppoe_device_class.index, t - pem->sessions,
	     pppoe_hw_class.index, t - pem->sessions);
	  hi = vnet_get_hw_interface (vnm, hw_if_index);
	}

      t->hw_if_index = hw_if_index;
      t->sw_if_index = sw_if_index = hi->sw_if_index;

      vec_validate_init_empty (pem->session_index_by_sw_if_index, sw_if_index,
			       ~0);
      pem->session_index_by_sw_if_index[sw_if_index] = t - pem->sessions;

      /* update pppoe fib with session_index */
      result.fields.session_index = t - pem->sessions;
      result.fields.sw_if_index = sw_if_index;
      pppoe_update_1 (&pem->session_table,
		      a->server_mac, clib_host_to_net_u16 (a->session_id),
		      &key, &bucket, &result);

      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, sw_if_index);
      si->flags &= ~VNET_SW_INTERFACE_FLAG_HIDDEN;
      vnet_sw_interface_set_flags (vnm, sw_if_index,
				   VNET_SW_INTERFACE_FLAG_ADMIN_UP);
      vnet_set_interface_l3_output_node (vnm->vlib_main, sw_if_index,
					 (u8 *) "tunnel-output");

      if (!is_ip6)
      {
          ip4_add_del_interface_address(vnm->vlib_main, 
                  sw_if_index,
                  &a->client_ip.ip4, 32, 0);
      }
      else
      {
          ip6_add_del_interface_address (vnm->vlib_main,
                  sw_if_index,
                  &a->client_ip.ip6,
			       128, 0);
      }

      /* add reverse route for client ip */
      fib_table_entry_path_add (a->decap_fib_index, &pfx,
				pppoe_fib_src, FIB_ENTRY_FLAG_NONE,
				fib_proto_to_dpo (pfx.fp_proto),
				&pfx.fp_addr, sw_if_index, ~0,
				1, NULL, FIB_ROUTE_PATH_FLAG_NONE);

    }
  else
    {
      /* deleting a session: session must exist */
      if (result.fields.session_index == ~0)
          return VNET_API_ERROR_NO_SUCH_ENTRY;

      t = pool_elt_at_index (pem->sessions, result.fields.session_index);
      sw_if_index = t->sw_if_index;

      vnet_reset_interface_l3_output_node (vnm->vlib_main, sw_if_index);
      vnet_sw_interface_set_flags (vnm, t->sw_if_index, 0 /* down */ );
      vnet_sw_interface_t *si = vnet_get_sw_interface (vnm, t->sw_if_index);
      si->flags |= VNET_SW_INTERFACE_FLAG_HIDDEN;

      vec_add1 (pem->free_pppoe_session_hw_if_indices, t->hw_if_index);

      pem->session_index_by_sw_if_index[t->sw_if_index] = ~0;

      /* update pppoe fib with session_inde=~0x */
      result.fields.session_index = ~0;
      pppoe_update_1 (&pem->session_table,
		      a->server_mac, clib_host_to_net_u16 (a->session_id),
		      &key, &bucket, &result);

      if (!is_ip6)
      {
          ip4_add_del_interface_address(vnm->vlib_main, 
                  sw_if_index,
                  &a->client_ip.ip4, 32, 1);
      }
      else
      {
          ip6_add_del_interface_address (vnm->vlib_main,
                  sw_if_index,
                  &a->client_ip.ip6,
			       128, 1);
      }


      /* delete reverse route for client ip */
      fib_table_entry_path_remove (a->decap_fib_index, &pfx,
				   pppoe_fib_src,
				   fib_proto_to_dpo (pfx.fp_proto),
				   &pfx.fp_addr,
				   sw_if_index, ~0, 1,
				   FIB_ROUTE_PATH_FLAG_NONE);

      pool_put (pem->sessions, t);
    }

  if (sw_if_indexp)
    *sw_if_indexp = sw_if_index;

  return 0;
}
#endif

static clib_error_t *
pppoe_add_del_session_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u16 session_id = 0;
  ip46_address_t client_ip;
  ip46_address_t server_ip;
  u8 is_add = 1;
  u8 client_ip_set = 0;
  u8 ipv4_set = 0;
  u8 ipv6_set = 0;
  u32 encap_if_index = ~0;
  u8 encap_set = 0;
  u32 decap_fib_index = 0;
  u8 server_mac[6] = { 0 };
  u8 server_mac_set = 0;
  int rv;
  u32 tmp;
  vnet_pppoe_add_del_session_args_t _a, *a = &_a;
  u32 session_sw_if_index;
  clib_error_t *error = NULL;

  /* Cant "universally zero init" (={0}) due to GCC bug 53119 */
  clib_memset (&client_ip, 0, sizeof client_ip);

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "del"))
	{
	  is_add = 0;
	}
      else if (unformat (line_input, "session-id %d", &session_id))
	;
      else if (unformat (line_input, "encap-if-index %d", &encap_if_index))
      {
          encap_set = 1;
      }
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip4_address, &client_ip.ip4))
	{
	  client_ip_set = 1;
	  ipv4_set = 1;
	}
      else if (unformat (line_input, "client-ip %U",
			 unformat_ip6_address, &client_ip.ip6))
	{
	  client_ip_set = 1;
	  ipv6_set = 1;
	}
      else if (unformat (line_input, "server-ip %U",
			 unformat_ip4_address, &server_ip.ip4))
	{
	}
      else if (unformat (line_input, "server-ip %U",
			 unformat_ip6_address, &server_ip.ip6))
	{
	}
      else if (unformat (line_input, "decap-vrf-id %d", &tmp))
	{
	  if (ipv6_set)
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP6, tmp);
	  else
	    decap_fib_index = fib_table_find (FIB_PROTOCOL_IP4, tmp);

	  if (decap_fib_index == ~0)
	    {
	      error =
		clib_error_return (0, "nonexistent decap fib id %d", tmp);
	      goto done;
	    }
	}
      else
	if (unformat
	    (line_input, "server-mac %U", unformat_ethernet_address,
	     server_mac))
        server_mac_set = 1;
    else
	{
	  error = clib_error_return (0, "parse error: '%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (client_ip_set == 0)
    {
      error =
	clib_error_return (0, "session client ip address not specified");
      goto done;
    }

  if (encap_set == 0)
    {
      error =
	clib_error_return (0, "session encap if index not specified");
      goto done;
    }

  if (ipv4_set && ipv6_set)
    {
      error = clib_error_return (0, "both IPv4 and IPv6 addresses specified");
      goto done;
    }

  if (server_mac_set == 0)
    {
      error = clib_error_return (0, "session client mac not specified");
      goto done;
    }

  clib_memset (a, 0, sizeof (*a));

  a->is_add = is_add;
  a->is_ip6 = ipv6_set;

#define _(x) a->x = x;
  foreach_copy_field;
#undef _

  clib_memcpy (a->server_mac, server_mac, 6);

  rv = vnet_pppoe_add_del_session (a, &session_sw_if_index);

  switch (rv)
    {
    case 0:
      if (is_add)
	vlib_cli_output (vm, "%U\n", format_vnet_sw_if_index_name,
			 vnet_get_main (), session_sw_if_index);
      break;

    case VNET_API_ERROR_TUNNEL_EXIST:
      error = clib_error_return (0, "session already exists...");
      goto done;

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      error = clib_error_return (0, "session does not exist...");
      goto done;

    default:
      error = clib_error_return
	(0, "vnet_pppoe_add_del_session returned %d", rv);
      goto done;
    }

done:
  unformat_free (line_input);

  return error;
}

/*?
 * Add or delete a PPPoE Session.
 *
 * @cliexpar
 * Example of how to create a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             server-mac 00:01:02:03:04:05 }
 * Example of how to delete a PPPoE Session:
 * @cliexcmd{create pppoe session client-ip 10.0.3.1 session-id 13
 *             server-mac 00:01:02:03:04:05 del }
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (create_pppoe_session_command, static) = {
  .path = "create pppoe session",
  .short_help =
  "create pppoe session client-ip <client-ip> server-ip <server-ip> session-id <nn>"
  " server-mac <server-mac> encap-if-index <nn> [decap-vrf-id <nn>] [del]",
  .function = pppoe_add_del_session_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
pppoe_vnet_ip_route_cmd (vlib_main_t * vm,
		   unformat_input_t * main_input, vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 table_id, is_del, fib_index, payload_proto;
  //dpo_id_t dpo = DPO_INVALID, 
  dpo_id_t *dpos = NULL;
  fib_route_path_t *rpaths = NULL, rpath;
  fib_prefix_t *prefixs = NULL, pfx;
  clib_error_t *error = NULL;
  f64 count;
  int i;

  is_del = 0;
  table_id = 0;
  count = 1;
  clib_memset (&pfx, 0, sizeof (pfx));

  /* Get a line of input. */
  if (!unformat_user (main_input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      clib_memset (&rpath, 0, sizeof (rpath));

      if (unformat (line_input, "table %d", &table_id))
	;
      else if (unformat (line_input, "count %f", &count))
	;

      else if (unformat (line_input, "%U/%d",
			 unformat_ip4_address, &pfx.fp_addr.ip4, &pfx.fp_len))
	{
	  payload_proto = pfx.fp_proto = FIB_PROTOCOL_IP4;
	  vec_add1 (prefixs, pfx);
	}
      else if (unformat (line_input, "%U/%d",
			 unformat_ip6_address, &pfx.fp_addr.ip6, &pfx.fp_len))
	{
	  payload_proto = pfx.fp_proto = FIB_PROTOCOL_IP6;
	  vec_add1 (prefixs, pfx);
	}
      else if (unformat (line_input, "via %U",
			 unformat_fib_route_path, &rpath, &payload_proto))
	{
	  vec_add1 (rpaths, rpath);
	}
#if 0
      else if (vec_len (prefixs) > 0 &&
	       unformat (line_input, "via %U",
			 unformat_dpo, &dpo, prefixs[0].fp_proto))
	{
	  vec_add1 (dpos, dpo);
	}
#endif
      else if (unformat (line_input, "del"))
	is_del = 1;
      else if (unformat (line_input, "add"))
	is_del = 0;
      else
	{
	  error = unformat_parse_error (line_input);
	  goto done;
	}
    }

  if (vec_len (prefixs) == 0)
    {
      error =
	clib_error_return (0, "expected ip4/ip6 destination address/length.");
      goto done;
    }

  if (!is_del && vec_len (rpaths) + vec_len (dpos) == 0)
    {
      error = clib_error_return (0, "expected paths.");
      goto done;
    }

  if (~0 == table_id)
    {
      /*
       * if no table_id is passed we will manipulate the default
       */
      fib_index = 0;
    }
  else
    {
      fib_index = fib_table_find (prefixs[0].fp_proto, table_id);

      if (~0 == fib_index)
	{
	  error = clib_error_return (0, "Nonexistent table id %d", table_id);
	  goto done;
	}
    }

  for (i = 0; i < vec_len (prefixs); i++)
    {
      if (is_del && 0 == vec_len (rpaths))
	{
	  fib_table_entry_delete (fib_index, &prefixs[i], pppoe_fib_src);
	}
      else if (!is_del && 1 == vec_len (dpos))
	{
	  fib_table_entry_special_dpo_add (fib_index,
					   &prefixs[i],
					   pppoe_fib_src,
					   FIB_ENTRY_FLAG_EXCLUSIVE,
					   &dpos[0]);
	  dpo_reset (&dpos[0]);
	}
      else if (vec_len (dpos) > 0)
	{
	  error =
	    clib_error_return (0,
			       "Load-balancing over multiple special adjacencies is unsupported");
	  goto done;
	}
      else if (0 < vec_len (rpaths))
	{
	  u32 k, n;
	  f64 t[2];
	  n = count;
	  t[0] = vlib_time_now (vm);

	  for (k = 0; k < n; k++)
	    {
	      fib_prefix_t rpfx = {
		.fp_len = prefixs[i].fp_len,
		.fp_proto = prefixs[i].fp_proto,
		.fp_addr = prefixs[i].fp_addr,
	      };

	      if (!fib_prefix_validate (&rpfx))
		{
		  vlib_cli_output (vm, "Invalid prefix len: %d", rpfx.fp_len);
		  continue;
		}

	      if (is_del)
		fib_table_entry_path_remove2 (fib_index,
					      &rpfx, pppoe_fib_src, rpaths);
	      else
		fib_table_entry_path_add2 (fib_index,
					   &rpfx,
					   pppoe_fib_src,
					   FIB_ENTRY_FLAG_NONE, rpaths);

	      fib_prefix_increment (&prefixs[i]);
	    }

	  t[1] = vlib_time_now (vm);
	  if (count > 1)
	    vlib_cli_output (vm, "%.6e routes/sec", count / (t[1] - t[0]));
	}
      else
	{
	  error = clib_error_return (0, "Don't understand what you want...");
	  goto done;
	}
    }

done:
  vec_free (dpos);
  vec_free (prefixs);
  vec_free (rpaths);
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (pppoe_ip_route_command, static) = {
  .path = "pppoe ip route",
  .short_help = "pppoe ip route [add|del] [count <n>] <dst-ip-addr>/<width> [table "
		"<table-id>] via [next-hop-address] [next-hop-interface] "
		"[next-hop-table <value>] [weight <value>] [preference "
		"<value>] [udp-encap <value>] [ip4-lookup-in-table <value>] "
		"[ip6-lookup-in-table <value>] [mpls-lookup-in-table <value>] "
		"[resolve-via-host] [resolve-via-connected] [rx-ip4 "
		"<interface>] [out-labels <value value value>]",
  .function = pppoe_vnet_ip_route_cmd,
  .is_mp_safe = 1,
};

u8 *
format_pppoe_session (u8 * s, va_list * args)
{
  pppoe_session_t *t = va_arg (*args, pppoe_session_t *);
  pppoe_main_t *pem = &pppoe_main;

  s = format (s, "[%d] sw-if-index %d client-ip %U server-ip %U session-id %d ",
	      t - pem->sessions, t->sw_if_index,
	      format_ip46_address, &t->client_ip, IP46_TYPE_ANY,
	      format_ip46_address, &t->server_ip, IP46_TYPE_ANY,
	      t->session_id);

  s = format (s, "encap-if-index %d decap-fib-index %d\n",
	      t->encap_if_index, t->decap_fib_index);

  s = format (s, "    local-mac %U  server-mac %U",
	      format_ethernet_address, t->local_mac,
	      format_ethernet_address, t->server_mac);

  return s;
}

/* *INDENT-OFF* */
static clib_error_t *
show_pppoe_session_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_session_t *t;

  if (pool_elts (pem->sessions) == 0)
    vlib_cli_output (vm, "No pppoe sessions configured...");

  pool_foreach (t, pem->sessions)
		 {
		    vlib_cli_output (vm, "%U",format_pppoe_session, t);
		}

  return 0;
}
/*?
 * Display all the PPPoE Session entries.
 *
 * @cliexpar
 * Example of how to display the PPPoE Session entries:
 * @cliexstart{show pppoe session}
 * [0] client-ip 10.0.3.1 session_id 13 encap-if-index 0 decap-vrf-id 13 sw_if_index 5
 *     local-mac a0:b0:c0:d0:e0:f0 server-mac 00:01:02:03:04:05
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pppoe_session_command, static) = {
    .path = "show pppoe session",
    .short_help = "show pppoe session",
    .function = show_pppoe_session_command_fn,
};
/* *INDENT-ON* */

typedef struct pppoe_show_walk_ctx_t_
{
  vlib_main_t *vm;
  u8 first_entry;
  u32 total_entries;
} pppoe_show_walk_ctx_t;

static int
pppoe_show_walk_cb (BVT (clib_bihash_kv) * kvp, void *arg)
{
  pppoe_show_walk_ctx_t *ctx = arg;
  pppoe_entry_result_t result;
  pppoe_entry_key_t key;

  if (ctx->first_entry)
    {
      ctx->first_entry = 0;
      vlib_cli_output (ctx->vm,
		       "%=19s%=12s%=13s%=14s",
		       "Mac-Address", "session_id", "sw_if_index",
		       "session_index");
    }

  key.raw = kvp->key;
  result.raw = kvp->value;

  vlib_cli_output (ctx->vm,
		   "%=19U%=12d%=13d%=14d",
		   format_ethernet_address, key.fields.mac,
		   clib_net_to_host_u16 (key.fields.session_id),
		   result.fields.sw_if_index == ~0
		   ? -1 : result.fields.sw_if_index,
		   result.fields.session_index == ~0
		   ? -1 : result.fields.session_index);
  ctx->total_entries++;

  return (BIHASH_WALK_CONTINUE);
}

/** Display the contents of the PPPoE Fib. */
static clib_error_t *
show_pppoe_fib_command_fn (vlib_main_t * vm,
			   unformat_input_t * input, vlib_cli_command_t * cmd)
{
  pppoe_main_t *pem = &pppoe_main;
  pppoe_show_walk_ctx_t ctx = {
    .first_entry = 1,
    .vm = vm,
  };

  BV (clib_bihash_foreach_key_value_pair)
    (&pem->session_table, pppoe_show_walk_cb, &ctx);

  if (ctx.total_entries == 0)
    vlib_cli_output (vm, "no pppoe fib entries");
  else
    vlib_cli_output (vm, "%lld pppoe fib entries", ctx.total_entries);

  return 0;
}

/*?
 * This command displays the MAC Address entries of the PPPoE FIB table.
 * Output can be filtered to just get the number of MAC Addresses or display
 * each MAC Address.
 *
 * @cliexpar
 * Example of how to display the number of MAC Address entries in the PPPoE
 * FIB table:
 * @cliexstart{show pppoe fib}
 *    Mac Address    session_id    Interface         sw_if_index session_index
 * 52:54:00:53:18:33   1        GigabitEthernet0/8/0      2          0
 * 52:54:00:53:18:55   2        GigabitEthernet0/8/1      3          1
 * @cliexend
?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (show_pppoe_fib_command, static) = {
    .path = "show pppoe fib",
    .short_help = "show pppoe fib",
    .function = show_pppoe_fib_command_fn,
};
/* *INDENT-ON* */


#define foreach_lcp_pppoe                                                       \
  _ (DROP, "error-drop")                                                      \
  _ (IO, "interface-output")

typedef enum
{
#define _(sym, str) LCP_PPPOE_NEXT_##sym,
  foreach_lcp_pppoe
#undef _
    LCP_PPPOE_N_NEXT,
} lcp_pppoe_next_t;

typedef struct lcp_pppoe_trace_t_
{
  u32 sw_if_index;
  u8 is_ipv6;
} lcp_pppoe_trace_t;

/* packet trace format function */
static u8 *
format_lcp_pppoe_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lcp_pppoe_trace_t *t = va_arg (*args, lcp_pppoe_trace_t *);

  s = format (s, "pppoe: sw_if_index %d IPv%d\n",
        t->sw_if_index, (t->is_ipv6) ? 6 : 4);

  return s;
}
VLIB_NODE_FN (lcp_pppoe_punt_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  while (n_left_from > 0)
  {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 2 && n_left_to_next >= 2)
      {
          u32 bi0, bi1;
          vlib_buffer_t *b0, *b1;
          u32 next0, next1;
          u32 sw_if_index0, sw_if_index1;
          lcp_itf_pair_t *lip0 = NULL;
          lcp_itf_pair_t *lip1 = NULL;
          u32 lipi0 = 0;
          u32 lipi1 = 0;
          u32 is_host0 = 0;
          u32 is_host1 = 0;
          u8 len0, len1;

          bi0 = from[0];
          bi1 = from[1];

          to_next[0] = bi0;
          to_next[1] = bi1;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);

          next0 = next1 = LCP_PPPOE_NEXT_DROP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];

          vnet_feature_next (&next0, b0);
          vnet_feature_next (&next1, b1);

	      lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID)
              {
                  is_host0 = 1;
                  //set max tc priority
                  lcp_set_max_tc(b0);
                  lcp_set_max_tc(b1);
              }
          }
          lip0 = lcp_itf_pair_get (lipi0);

          if (lip0)
          {
              next0 = LCP_PPPOE_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }

	      lipi1 = lcp_itf_pair_find_by_phy ( sw_if_index1);
          if (lipi1 == INDEX_INVALID)
          {
              lipi1 = lcp_itf_pair_find_by_host (sw_if_index1);
              if (lipi1 != INDEX_INVALID)
              {
                  is_host1 = 1;
              }
          }
          lip1 = lcp_itf_pair_get (lipi1);

          if (lip1)
          {
              next1 = LCP_PPPOE_NEXT_IO;
              vnet_buffer (b1)->sw_if_index[VLIB_TX] = is_host1 ? lip1->lip_phy_sw_if_index : lip1->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len1 = ((u8 *) vlib_buffer_get_current (b1) -
                      (u8 *) ethernet_buffer_get_header (b1));
              vlib_buffer_advance (b1, -len1);
          }

          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pppoe_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));

              t->sw_if_index = sw_if_index0;
          }

          if (b1->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pppoe_trace_t *t =
                  vlib_add_trace (vm, node, b1, sizeof (*t));

              t->sw_if_index = sw_if_index1;
          }

          from += 2;
          n_left_from -= 2;
          to_next += 2;
          n_left_to_next -= 2;

          vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
                  to_next, n_left_to_next,
                  bi0, bi1, next0, next1);
      }

      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          u32 sw_if_index0;
	      lcp_itf_pair_t *lip0 = NULL;
	      u32 lipi0 = 0;
          u32 is_host0 = 0;
	  u8 len0;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);

          next0 = LCP_PPPOE_NEXT_DROP;

          /* most packets will follow feature arc */
          vnet_feature_next (&next0, b0);

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

	      lipi0 = lcp_itf_pair_find_by_phy (sw_if_index0); 
          if (lipi0 == INDEX_INVALID)
          {
              lipi0 = lcp_itf_pair_find_by_host (sw_if_index0);
              if (lipi0 != INDEX_INVALID)
              {
                  is_host0 = 1;
                  //set max tc priority
                  lcp_set_max_tc(b0);
              }
          }
          lip0 = lcp_itf_pair_get (lipi0);

          if (lip0)
          {
              next0 = LCP_PPPOE_NEXT_IO;
              vnet_buffer (b0)->sw_if_index[VLIB_TX] = is_host0 ? lip0->lip_phy_sw_if_index : lip0->lip_host_sw_if_index;
              /*
               * rewind to eth header, copy, advance back to current
               */
              len0 = ((u8 *) vlib_buffer_get_current (b0) -
                      (u8 *) ethernet_buffer_get_header (b0));
              vlib_buffer_advance (b0, -len0);
          }


          if (b0->flags & VLIB_BUFFER_IS_TRACED)
          {
              lcp_pppoe_trace_t *t =
                  vlib_add_trace (vm, node, b0, sizeof (*t));

              t->sw_if_index = sw_if_index0;
          }

          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                  to_next, n_left_to_next,
                  bi0, next0);
      }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }

  return frame->n_vectors;
}

/*
 * pppoe input graph node declaration
 */
/* *INDENT-OFF* */
VLIB_REGISTER_NODE(lcp_pppoe_punt_node) = {
  .name = "lcp-pppoe-punt",
  .vector_size = sizeof(u32),
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = LINUXCP_N_ERROR,
  .error_counters = linuxcp_error_counters,

  .format_trace = format_lcp_pppoe_trace,

  .n_next_nodes = LCP_PPPOE_N_NEXT,
  .next_nodes =
  {
    [LCP_PPPOE_NEXT_DROP] = "error-drop",
    [LCP_PPPOE_NEXT_IO] = "interface-output",
  },
};


#ifndef CLIB_MARCH_VARIANT
char * pppoe_error_strings[] = {
#define pppoe_error(n,s) s,
    pppoe_error (DECAPSULATED, "good packets decapsulated")
    pppoe_error (CONTROL_PLANE, "control plane packet")
    pppoe_error (NO_SUCH_SESSION, "no such sessions")
    pppoe_error (BAD_VER_TYPE, "bad version and type in pppoe header")
#undef pppoe_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */


typedef struct {
  u32 next_index;
  u32 session_index;
  u32 session_id;
  u32 error;
} pppoe_rx_trace_t;

static u8 * format_pppoe_rx_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  pppoe_rx_trace_t * t = va_arg (*args, pppoe_rx_trace_t *);

  if (t->session_index != ~0)
    {
      s = format (s, "PPPoE decap from ppp%d session_id %d next %d error %d",
                  t->session_index, t->session_id, t->next_index, t->error);
    }
  else
    {
      s = format (s, "PPPoE decap error - ppp%d session_id %d ",
                  t->session_index, t->session_id);
    }
  return s;
}

VLIB_NODE_FN (pppoe_input_node) (vlib_main_t * vm,
             vlib_node_runtime_t * node,
             vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index = node->cached_next_index;
  pppoe_main_t *pem = &pppoe_main;
  u32 pkts_decapsulated = 0;
  pppoe_entry_key_t cached_key;
  pppoe_entry_result_t cached_result;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  /* Clear the one-entry cache in case session table was updated */
  cached_key.raw = ~0;
  cached_result.raw = ~0;	/* warning be gone */

  while (n_left_from > 0)
  {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
      {
          u32 bi0;
          vlib_buffer_t *b0;
          u32 next0;
          ethernet_header_t *h0;
          ethernet_vlan_header_t *vlan0 = 0;
          pppoe_header_t * pppoe0;
          u32 error0;
          u16 ppp_proto0 = 0;
          u16 type0;
          pppoe_session_t * t0;
	  pppoe_entry_key_t key0;
	  pppoe_entry_result_t result0;
	  u32 bucket0;

          bi0 = from[0];
          to_next[0] = bi0;

          b0 = vlib_get_buffer (vm, bi0);
          error0 = 0;

          /* get mac */
          vlib_buffer_reset(b0);
          h0 = vlib_buffer_get_current (b0);
	  result0.fields.session_index = ~0;

          /* get pppoe header */
          type0 = clib_net_to_host_u16(h0->type);
          if(type0 == ETHERNET_TYPE_VLAN){
              vlan0 = (ethernet_vlan_header_t *)(h0+1);
              type0 = clib_net_to_host_u16(vlan0->type);
              pppoe0 = (pppoe_header_t*)(vlan0+1);
              if( type0 != ETHERNET_TYPE_PPPOE_DISCOVERY && type0 != ETHERNET_TYPE_PPPOE_SESSION ) {
                  error0 = PPPOE_ERROR_BAD_VER_TYPE;
                  next0 = PPPOE_INPUT_NEXT_DROP;
                  goto trace00;
              }
          } else {
              pppoe0 = (pppoe_header_t*)(h0+1);
          }

          ppp_proto0 = clib_net_to_host_u16(pppoe0->ppp_proto);   
          if ((ppp_proto0 != PPP_PROTOCOL_ip4)
             && (ppp_proto0 != PPP_PROTOCOL_ip6))
          {
              //control packets
              error0 = PPPOE_ERROR_CONTROL_PLANE;
              next0 = PPPOE_INPUT_NEXT_CP_INPUT;
              goto trace00;
          }

	  pppoe_lookup_1 (&pem->session_table, &cached_key, &cached_result,
			  h0->src_address, pppoe0->session_id,
			  &key0, &bucket0, &result0);

          /* Pop Eth and PPPoE header */
          vlan0 == 0 ?
              vlib_buffer_advance(b0, sizeof(*h0)+sizeof(*pppoe0))
              :
              vlib_buffer_advance(b0, sizeof(*h0)+sizeof(*vlan0)+sizeof(*pppoe0));

          next0 = (ppp_proto0==PPP_PROTOCOL_ip4)?
              PPPOE_INPUT_NEXT_IP4_INPUT
              : PPPOE_INPUT_NEXT_IP6_INPUT;
          pkts_decapsulated ++;
          if (PREDICT_FALSE (result0.fields.session_index != ~0))
	  {
	     t0 = pool_elt_at_index (pem->sessions,
				  result0.fields.session_index);
	     vnet_buffer2(b0)->l2_rx_sw_if_index = vnet_buffer(b0)->sw_if_index[VLIB_RX];
	     vnet_buffer(b0)->sw_if_index[VLIB_RX] = t0->sw_if_index;
	  }

trace00:
          b0->error = error0 ? node->errors[error0] : 0;

          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
          {
              pppoe_rx_trace_t *tr
                = vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->next_index = next0;
              tr->error = error0;
              tr->session_index = result0.fields.session_index;
              tr->session_id = clib_net_to_host_u16(pppoe0->session_id);
          }
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
             to_next, n_left_to_next,
             bi0, next0);
      }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  vlib_node_increment_counter (vm, pppoe_input_node.index,
                               PPPOE_ERROR_DECAPSULATED,
                               pkts_decapsulated);
  return frame->n_vectors;

}

VLIB_REGISTER_NODE (pppoe_input_node) = {
  .name = "lcp-pppoe-input",
  /* Takes a vector of packets. */
  .vector_size = sizeof (u32),

  .n_errors = PPPOE_N_ERROR,
  .error_strings = pppoe_error_strings,

  .n_next_nodes = PPPOE_INPUT_N_NEXT,
  .next_nodes = {
#define _(s,n) [PPPOE_INPUT_NEXT_##s] = n,
    foreach_pppoe_input_next
#undef _
  },

  .format_trace = format_pppoe_rx_trace,
};

/* *INDENT-OFF* */
VNET_FEATURE_INIT (pppoe_input_node, static) =
{
  .arc_name = "device-input",
  .node_name = "lcp-pppoe-input",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

/* *INDENT-ON */
static clib_error_t *
lcp_pppoe_init (vlib_main_t *vm)
{
  pppoe_main_t *pem = &pppoe_main;

  pem->vnet_main = vnet_get_main ();
  pem->vlib_main = vm;

  BV (clib_bihash_init) (&pem->session_table, "pppoe session table",
			 PPPOE_NUM_BUCKETS, PPPOE_MEMORY_SIZE);

  pppoe_fib_src = fib_source_allocate ("pppoe",
				       FIB_SOURCE_PRIORITY_HI,
				       FIB_SOURCE_BH_API);

  /* register pppoe punt node */
  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_DISCOVERY,
      lcp_pppoe_punt_node.index);

  ethernet_register_input_type (vm, ETHERNET_TYPE_PPPOE_SESSION,
      pppoe_input_node.index);
  return NULL;
}

VLIB_INIT_FUNCTION (lcp_pppoe_init) = {
  .runs_after = VLIB_INITS ("lcp_interface_init"),
};
