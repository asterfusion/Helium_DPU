/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/pktio/pktio_priv.h>

#define FLOW_IS_ETHERNET_CLASS(f) (f->type == VNET_FLOW_TYPE_ETHERNET)

#define FLOW_IS_IPV4_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP4) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_L2TPV3OIP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP) ||                               \
   (f->type == VNET_FLOW_TYPE_IP4_IPSEC_AH))

#define FLOW_IS_IPV6_CLASS(f)                                                 \
  ((f->type == VNET_FLOW_TYPE_IP6) ||                                         \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN))

#define FLOW_IS_L3_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4) || (f->type == VNET_FLOW_TYPE_IP6))

#define FLOW_IS_L4_TYPE(f)                                                    \
  ((f->type == VNET_FLOW_TYPE_IP4_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE) ||                                 \
   (f->type == VNET_FLOW_TYPE_IP4_N_TUPLE_TAGGED) ||                          \
   (f->type == VNET_FLOW_TYPE_IP6_N_TUPLE_TAGGED))

#define FLOW_IS_L4_TUNNEL_TYPE(f)                                             \
  ((f->type == VNET_FLOW_TYPE_IP4_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP6_VXLAN) ||                                   \
   (f->type == VNET_FLOW_TYPE_IP4_GTPC) ||                                    \
   (f->type == VNET_FLOW_TYPE_IP4_GTPU))

#define FLOW_IS_GENERIC_CLASS(f) (f->type == VNET_FLOW_TYPE_GENERIC)

#define CNXK_FLOW_UNSUPPORTED_ACTIONS(f)                                      \
  ((f->actions == VNET_FLOW_ACTION_BUFFER_ADVANCE) ||                         \
   (f->actions == VNET_FLOW_ACTION_REDIRECT_TO_NODE))

/* Keep values in sync with vnet/flow.h */
#define foreach_cnxk_flow_rss_types                                           \
  _ (1, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_TCP, "ipv4-tcp")                   \
  _ (2, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_UDP, "ipv4-udp")                   \
  _ (3, FLOW_KEY_TYPE_IPV4 | FLOW_KEY_TYPE_SCTP, "ipv4-sctp")                 \
  _ (5, FLOW_KEY_TYPE_IPV4, "ipv4")                                           \
  _ (9, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_TCP, "ipv6-tcp")                   \
  _ (10, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_UDP, "ipv6-udp")                  \
  _ (11, FLOW_KEY_TYPE_IPV6 | FLOW_KEY_TYPE_SCTP, "ipv6-sctp")                \
  _ (13, FLOW_KEY_TYPE_IPV6_EXT, "ipv6-ex")                                   \
  _ (14, FLOW_KEY_TYPE_IPV6, "ipv6")                                          \
  _ (16, FLOW_KEY_TYPE_PORT, "port")                                          \
  _ (17, FLOW_KEY_TYPE_VXLAN, "vxlan")                                        \
  _ (18, FLOW_KEY_TYPE_GENEVE, "geneve")                                      \
  _ (19, FLOW_KEY_TYPE_NVGRE, "nvgre")                                        \
  _ (20, FLOW_KEY_TYPE_GTPU, "gtpu")                                          \
  _ (60, FLOW_KEY_TYPE_L4_DST, "l4-dst-only")                                 \
  _ (61, FLOW_KEY_TYPE_L4_SRC, "l4-src-only")                                 \
  _ (62, FLOW_KEY_TYPE_L3_DST, "l3-dst-only")                                 \
  _ (63, FLOW_KEY_TYPE_L3_SRC, "l3-src-only")

typedef struct
{
  u16 src_port;
  u16 dst_port;
  u32 verification_tag;
  u32 cksum;
} sctp_header_t;

typedef struct
{
  u8 ver_flags;
  u8 type;
  u16 length;
  u32 teid;
} gtpu_header_t;

static void
cnxk_flow_convert_rss_types (u64 *key, u64 rss_types)
{
#define _(a, b, c)                                                            \
  if (rss_types & (1UL << a))                                                 \
    *key |= b;

  foreach_cnxk_flow_rss_types
#undef _

    return;
}

static i32
cnxk_flow_rule_del (vnet_main_t *vnm, cnxk_pktio_t *dev, vnet_flow_t *flow,
		    uword *private_data)
{
  struct roc_npc *npc = &dev->npc;
  struct roc_npc_flow *npc_flow;
  cnxk_pktio_flow_t *flow_entry;
  int rv = 0, index;

  index = *private_data;
  flow_entry = pool_elt_at_index (dev->flow_entries, index);
  npc_flow = flow_entry->npc_flow;
  rv = roc_npc_flow_destroy (npc, npc_flow);
  if (rv)
    {
      cnxk_pktio_err ("roc_npc_flow_destroy failed with '%s' error",
		      roc_error_msg_get (rv));
      return CNXK_UNSUPPORTED_OPERATION;
    }
  pool_put (dev->flow_entries, flow_entry);

  return 0;
}

static i32
cnxk_flow_rule_create (cnxk_pktio_t *dev, struct roc_npc_action *actions,
		       struct roc_npc_item_info *item_info, vnet_flow_t *flow,
		       uword *private_data)
{
  struct roc_npc_attr attr = { 0 };
  struct roc_npc_flow *npc_flow;
  cnxk_pktio_flow_t *flow_entry;
  struct roc_npc *npc;
  int rv = 0;

  npc = &dev->npc;
  attr.priority = 1;
  attr.ingress = 1;

  npc_flow =
    roc_npc_flow_create (npc, &attr, item_info, actions, npc->pf_func, &rv);
  if (rv)
    {
      cnxk_pktio_warn ("roc_npc_flow_create failed with '%s' error",
		       roc_error_msg_get (rv));
      return CNXK_UNSUPPORTED_OPERATION;
    }
  roc_npc_mcam_clear_counter (npc, npc_flow->ctr_id);

  pool_get_zero (dev->flow_entries, flow_entry);
  flow_entry->index = flow_entry - dev->flow_entries;
  flow_entry->vnet_flow_index = flow->index;
  flow_entry->npc_flow = npc_flow;

  *private_data = flow_entry->index;

  return 0;
}

static i32
cnxk_flow_rule_add (vnet_main_t *vnm, cnxk_pktio_t *dev, vnet_flow_t *flow,
		    uword *private_data)
{
  struct roc_npc_item_info item_info[ROC_NPC_ITEM_TYPE_END] = { 0 };
  struct roc_npc_action actions[ROC_NPC_ITEM_TYPE_END] = { 0 };
  ethernet_header_t eth_spec = { 0 }, eth_mask = { 0 };
  sctp_header_t sctp_spec = { 0 }, sctp_mask = { 0 };
  gtpu_header_t gtpu_spec = { 0 }, gtpu_mask = { 0 };
  ip4_header_t ip4_spec = { 0 }, ip4_mask = { 0 };
  ip6_header_t ip6_spec = { 0 }, ip6_mask = { 0 };
  udp_header_t udp_spec = { 0 }, udp_mask = { 0 };
  tcp_header_t tcp_spec = { 0 }, tcp_mask = { 0 };
  esp_header_t esp_spec = { 0 }, esp_mask = { 0 };
  u16 l4_src_port = { 0 }, l4_dst_port = { 0 };
  u16 l4_src_mask = { 0 }, l4_dst_mask = { 0 };
  struct roc_npc_action_rss rss_conf = { 0 };
  struct roc_npc_item_info *patterns = NULL;
  struct roc_npc_action_queue conf = { 0 };
  struct roc_npc_action_mark mark = { 0 };
  vnet_flow_ip4_n_tuple_t *ip4_tuple_hdr;
  vnet_flow_ip6_n_tuple_t *ip6_tuple_hdr;
  vnet_flow_ip4_ipsec_esp_t *esp_hdr;
  int layer = 0, index = 0, rv = 0;
  struct roc_npc *npc = &dev->npc;
  vnet_flow_ip4_gtpu_t *gtpu_hdr;
  vnet_flow_ethernet_t *eth_hdr;
  vnet_flow_ip4_t *ip4_hdr;
  vnet_flow_ip6_t *ip6_hdr;
  u16 *queues = NULL;
  u64 flow_key = 0;
  u8 l4_proto = 0;
  u16 action = 0;

  if (FLOW_IS_GENERIC_CLASS (flow))
    {
      clib_memcpy (&patterns, flow->generic.pattern.spec, sizeof (uword));
      if (patterns == NULL)
	{
	  cnxk_pktio_err ("Generic flow spec is NULL");
	  return -1;
	}

      goto parse_actions;
    }

  if (FLOW_IS_ETHERNET_CLASS (flow))
    {
      eth_hdr = &flow->ethernet;

      eth_spec.type = clib_host_to_net_u16 (eth_hdr->eth_hdr.type);
      eth_mask.type = clib_host_to_net_u16 (0xFFFF);

      item_info[layer].spec = (void *) &eth_spec;
      item_info[layer].mask = (void *) &eth_mask;
      item_info[layer].size = sizeof (ethernet_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_ETH;
      layer++;
    }

  else if (FLOW_IS_IPV4_CLASS (flow))
    {
      ip4_hdr = &flow->ip4;
      l4_proto = ip4_hdr->protocol.prot;

      ip4_spec.src_address = ip4_hdr->src_addr.addr;
      ip4_mask.src_address = ip4_hdr->src_addr.mask;
      ip4_spec.dst_address = ip4_hdr->dst_addr.addr;
      ip4_mask.dst_address = ip4_hdr->dst_addr.mask;

      item_info[layer].spec = (void *) &ip4_spec;
      item_info[layer].mask = (void *) &ip4_mask;
      item_info[layer].size = sizeof (ip4_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_IPV4;
      layer++;

      if (FLOW_IS_L4_TYPE (flow))
	{
	  ip4_tuple_hdr = &flow->ip4_n_tuple;

	  l4_src_port = ip4_tuple_hdr->src_port.port;
	  l4_dst_port = ip4_tuple_hdr->dst_port.port;
	  l4_src_mask = ip4_tuple_hdr->src_port.mask;
	  l4_dst_mask = ip4_tuple_hdr->dst_port.mask;
	}
    }
  else if (FLOW_IS_IPV6_CLASS (flow))
    {
      ip6_hdr = &flow->ip6;
      l4_proto = ip6_hdr->protocol.prot;

      clib_memcpy (&ip6_spec.src_address, &ip6_hdr->src_addr.addr,
		   ARRAY_LEN (ip6_hdr->src_addr.addr.as_u8));
      clib_memcpy (&ip6_mask.src_address, &ip6_hdr->src_addr.mask,
		   ARRAY_LEN (ip6_hdr->src_addr.mask.as_u8));
      clib_memcpy (&ip6_spec.dst_address, &ip6_hdr->dst_addr.addr,
		   ARRAY_LEN (ip6_hdr->dst_addr.addr.as_u8));
      clib_memcpy (&ip6_mask.dst_address, &ip6_hdr->dst_addr.mask,
		   ARRAY_LEN (ip6_hdr->dst_addr.mask.as_u8));

      item_info[layer].spec = (void *) &ip6_spec;
      item_info[layer].mask = (void *) &ip6_mask;
      item_info[layer].size = sizeof (ip6_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_IPV6;
      layer++;

      if (FLOW_IS_L4_TYPE (flow))
	{
	  ip6_tuple_hdr = &flow->ip6_n_tuple;

	  l4_src_port = ip6_tuple_hdr->src_port.port;
	  l4_dst_port = ip6_tuple_hdr->dst_port.port;
	  l4_src_mask = ip6_tuple_hdr->src_port.mask;
	  l4_dst_mask = ip6_tuple_hdr->dst_port.mask;
	}
    }

  if (!l4_proto)
    goto end_item_info;

  switch (l4_proto)
    {
    case IP_PROTOCOL_UDP:
      udp_spec.src_port = clib_host_to_net_u16 (l4_src_port);
      udp_spec.dst_port = clib_host_to_net_u16 (l4_dst_port);

      udp_mask.src_port = clib_host_to_net_u16 (l4_src_mask);
      udp_mask.dst_port = clib_host_to_net_u16 (l4_dst_mask);

      item_info[layer].spec = (void *) &udp_spec;
      item_info[layer].mask = (void *) &udp_mask;
      item_info[layer].size = sizeof (udp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_UDP;
      layer++;

      if (FLOW_IS_L4_TUNNEL_TYPE (flow))
	{
	  switch (flow->type)
	    {
	    case VNET_FLOW_TYPE_IP4_GTPU:
	      gtpu_hdr = &flow->ip4_gtpu;

	      gtpu_spec.teid = clib_host_to_net_u32 (gtpu_hdr->teid);
	      gtpu_mask.teid = clib_host_to_net_u32 (0XFFFFFFFF);

	      item_info[layer].spec = (void *) &gtpu_spec;
	      item_info[layer].mask = (void *) &gtpu_mask;
	      item_info[layer].size = sizeof (gtpu_header_t);
	      item_info[layer].type = ROC_NPC_ITEM_TYPE_GTPU;
	      layer++;
	      break;

	    default:
	      cnxk_pktio_err ("Unsupported L4 tunnel type");
	      return -1;
	    }
	} /* FLOW_IS_L4_TUNNEL_TYPE */
      break;

    case IP_PROTOCOL_TCP:
      tcp_spec.src_port = clib_host_to_net_u16 (l4_src_port);
      tcp_mask.src_port = clib_host_to_net_u16 (l4_src_mask);
      tcp_spec.dst_port = clib_host_to_net_u16 (l4_dst_port);
      tcp_mask.dst_port = clib_host_to_net_u16 (l4_dst_mask);

      item_info[layer].spec = (void *) &tcp_spec;
      item_info[layer].mask = (void *) &tcp_mask;
      item_info[layer].size = sizeof (tcp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_TCP;
      layer++;
      break;

    case IP_PROTOCOL_SCTP:
      sctp_spec.src_port = clib_host_to_net_u16 (l4_src_port);
      sctp_mask.src_port = clib_host_to_net_u16 (l4_src_mask);
      sctp_spec.dst_port = clib_host_to_net_u16 (l4_dst_port);
      sctp_mask.dst_port = clib_host_to_net_u16 (l4_dst_mask);

      item_info[layer].spec = (void *) &sctp_spec;
      item_info[layer].mask = (void *) &sctp_mask;
      item_info[layer].size = sizeof (sctp_header_t);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_SCTP;
      layer++;
      break;

    case IP_PROTOCOL_IPSEC_ESP:
      esp_hdr = &flow->ip4_ipsec_esp;

      esp_spec.spi = clib_host_to_net_u32 (esp_hdr->spi);
      esp_mask.spi = clib_host_to_net_u32 (0xFFFFFFFF);

      item_info[layer].spec = (void *) &esp_spec;
      item_info[layer].mask = (void *) &esp_mask;
      item_info[layer].size = sizeof (u32);
      item_info[layer].type = ROC_NPC_ITEM_TYPE_ESP;
      layer++;
      break;

    default:
      cnxk_pktio_err ("Unsupported L4 protocol '%U'", format_ip_protocol,
		      l4_proto);
      return -1;
    }

end_item_info:
  item_info[layer].type = ROC_NPC_ITEM_TYPE_END;

parse_actions:

  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      conf.index = flow->redirect_queue;
      actions[action].type = ROC_NPC_ACTION_TYPE_QUEUE;
      actions[action].conf = &conf;
      action++;
    }

  else if (flow->actions & VNET_FLOW_ACTION_DROP)
    {
      actions[action].type = ROC_NPC_ACTION_TYPE_DROP;
      action++;
    }

  else if (flow->actions & VNET_FLOW_ACTION_RSS)
    {
      if (!flow->queue_num)
	{
	  cnxk_pktio_err ("RSS action has no queues");
	  return CNXK_UNSUPPORTED_OPERATION;
	}
      queues = clib_mem_alloc (sizeof (u16) * dev->n_rx_queues);

      for (index = 0; index < flow->queue_num; index++)
	queues[index] = flow->queue_index++;

      cnxk_flow_convert_rss_types (&flow_key, flow->rss_types);
      if (!flow_key)
	{
	  cnxk_pktio_err ("Invalid RSS hash function");
	  return CNXK_UNSUPPORTED_OPERATION;
	}
      npc->flowkey_cfg_state = flow_key;
      rss_conf.queue_num = flow->queue_num;
      rss_conf.queue = queues;

      actions[action].type = ROC_NPC_ACTION_TYPE_RSS;
      actions[action].conf = &rss_conf;
      action++;
    }

  /* Below actions can be chained with above actions */
  if (flow->actions & VNET_FLOW_ACTION_MARK)
    {
      mark.id = flow->mark_flow_id;
      actions[action].type = ROC_NPC_ACTION_TYPE_MARK;
      actions[action].conf = &mark;
      action++;
    }

  /* make count as default action */
  actions[action].type = ROC_NPC_ACTION_TYPE_COUNT;
  actions[action + 1].type = ROC_NPC_ACTION_TYPE_END;

  if (FLOW_IS_GENERIC_CLASS (flow))
    rv = cnxk_flow_rule_create (dev, actions, patterns, flow, private_data);
  else
    rv = cnxk_flow_rule_create (dev, actions, item_info, flow, private_data);

  if (queues)
    clib_mem_free (queues);

  return rv;
}

i32
cnxk_pktio_flow_validate_params (vnet_main_t *vnm, vnet_flow_dev_op_t op,
				 cnxk_pktio_t *dev, vnet_flow_t *flow,
				 uword *private_data)
{
  u32 last_queue;
  u32 qid;

  if (CNXK_FLOW_UNSUPPORTED_ACTIONS (flow))
    {
      cnxk_pktio_err ("Unsupported action type");
      return -1;
    }

  if (flow->actions & VNET_FLOW_ACTION_REDIRECT_TO_QUEUE)
    {
      qid = flow->redirect_queue;
      if (qid > dev->n_rx_queues - 1 || qid < 0)
	{
	  cnxk_pktio_err ("Given Q(%d) is invalid, supported range is %d-%d",
			  qid, 0, dev->n_rx_queues - 1);
	  return CNXK_UNSUPPORTED_OPERATION;
	}
    }

  if (flow->actions & VNET_FLOW_ACTION_RSS)
    {
      last_queue = flow->queue_index + flow->queue_num;
      if (last_queue > dev->n_rx_queues - 1)
	{
	  cnxk_pktio_err (
	    "Given Q range(%d-%d) is invalid, supported range is %d-%d",
	    flow->queue_index, flow->queue_index + flow->queue_num, 0,
	    dev->n_rx_queues - 1);
	  return CNXK_UNSUPPORTED_OPERATION;
	}
    }
  return 0;
}

i32
cnxk_pktio_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
			cnxk_pktio_t *dev, vnet_flow_t *flow,
			uword *private_data)
{
  int rv;

  rv = cnxk_pktio_flow_validate_params (vnm, op, dev, flow, private_data);
  if (rv < 0)
    {
      cnxk_pktio_err ("cnxk_pktio_flow_validate_params failed");
      return CNXK_UNSUPPORTED_OPERATION;
    }

  switch (op)
    {
    case VNET_FLOW_DEV_OP_ADD_FLOW:
      return cnxk_flow_rule_add (vnm, dev, flow, private_data);

    case VNET_FLOW_DEV_OP_DEL_FLOW:
      return cnxk_flow_rule_del (vnm, dev, flow, private_data);

    default:
      return CNXK_UNSUPPORTED_OPERATION;
    }
  return 0;
}

i32
cnxk_pktio_flow_inl_dev_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
				cnxk_pktio_t *dev, vnet_flow_t *flow,
				uword *private_data)
{
  struct roc_npc_item_info item_info[ROC_NPC_ITEM_TYPE_END] = { 0 };
  struct roc_npc_action actions[ROC_NPC_ITEM_TYPE_END] = { 0 };
  esp_header_t esp_spec = { 0 }, esp_mask = { 0 };
  vnet_flow_ip4_ipsec_esp_t *esp_hdr;

  if (op == VNET_FLOW_DEV_OP_ADD_FLOW)
    {
      if (flow->type == VNET_FLOW_TYPE_IP4_IPSEC_ESP &&
	  flow->redirect_queue == ~0)
	{
	  esp_hdr = &flow->ip4_ipsec_esp;

	  esp_spec.spi = clib_host_to_net_u32 (esp_hdr->spi);
	  esp_mask.spi = 0; /* Any */

	  item_info[0].spec = (void *) &esp_spec;
	  item_info[0].mask = (void *) &esp_mask;
	  item_info[0].size = sizeof (u32);
	  item_info[0].type = ROC_NPC_ITEM_TYPE_ESP;
	  item_info[1].type = ROC_NPC_ITEM_TYPE_END;

	  actions[0].conf = (void *) NULL;
	  actions[0].type = ROC_NPC_ACTION_TYPE_SEC;
	  actions[1].type = ROC_NPC_ACTION_TYPE_COUNT;
	  actions[2].type = ROC_NPC_ACTION_TYPE_END;

	  return cnxk_flow_rule_create (dev, actions, item_info, flow,
					private_data);
	}
    }

  return CNXK_UNSUPPORTED_OPERATION;
}

u32
cnxk_pktio_flow_query (vlib_main_t *vm, cnxk_pktio_t *dev, uword private_data,
		       cnxk_flow_stats_t *stats)
{
  struct roc_npc *npc = &dev->npc;
  struct roc_npc_flow *npc_flow;
  cnxk_pktio_flow_t *flow_entry;
  i32 flow_count;
  u64 hits;

  flow_count = pool_elts (dev->flow_entries);
  if (!flow_count)
    {
      cnxk_pktio_err ("Flow entry pool is empty");
      return CNXK_UNSUPPORTED_OPERATION;
    }

  flow_entry = pool_elt_at_index (dev->flow_entries, private_data);
  npc_flow = flow_entry->npc_flow;
  if (npc_flow->ctr_id == NPC_COUNTER_NONE)
    {
      cnxk_pktio_err ("Counters are not available for given flow id (%u)",
		      flow_entry->index);
      return CNXK_UNSUPPORTED_OPERATION;
    }

  roc_npc_mcam_read_counter (npc, npc_flow->ctr_id, &hits);
  stats->flow_index = flow_entry->index;
  stats->hits = hits;

  return 0;
}

u32
cnxk_pktio_flow_dump (vlib_main_t *vm, cnxk_pktio_t *dev)
{
  uint8_t key[ROC_NIX_RSS_KEY_LEN] = { 0 };
  u16 reta[ROC_NIX_RSS_RETA_MAX] = { 0 };
  struct roc_nix *roc_nix = &dev->nix;
  struct roc_npc *npc = &dev->npc;
  int rv, index;

  fformat (stdout, "\nPktio device %d \n", dev->pktio_index);

  roc_nix_rss_key_get (roc_nix, key);
  fformat (stdout, "\tRSS hash key:\n");
  for (index = 0; index < ROC_NIX_RSS_KEY_LEN; index++)
    {
      if (index % 16 == 0)
	fformat (stdout, "\t\t");

      fformat (stdout, "%02x", key[index]);
      if (index % 16 == 15)
	fformat (stdout, "\n");
      else
	fformat (stdout, ":");
    }
  rv = roc_nix_rss_reta_get (roc_nix, ROC_NIX_RSS_GROUP_DEFAULT, reta);
  if (rv < 0)
    {
      cnxk_pktio_err ("roc_nix_rss_reta_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  fformat (stdout, "\n\tRETA table:\n");
  for (index = 0; index < roc_nix->reta_sz; index++)
    {
      if (index % 16 == 0)
	fformat (stdout, "\t\t%4u: ", index);
      fformat (stdout, " %4u", reta[index]);

      if (index % 16 == 15)
	fformat (stdout, "\n");
    }

  roc_npc_flow_dump (stdout, npc, -1);
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
