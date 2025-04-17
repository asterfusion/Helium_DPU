/**
 * @file
 * @brief NAT46 implementation
 */

#include <nat/nat.h>
#include <nat/nat46.h>
#include <nat/nat46_db.h>
#include <nat/nat_reass.h>
#include <nat/nat_inlines.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/crc32.h>
#include <nat/nat_ipfix_logging.h>


nat46_main_t nat46_main;

/* *INDENT-OFF* */

/* Hook up input features */
VNET_FEATURE_INIT (nat46_in2out, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat46-out2in",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (nat46_out2in, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat46-in2out",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};
VNET_FEATURE_INIT (nat46_in2out_handoff, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "nat46-out2in-handoff",
  .runs_before = VNET_FEATURES ("ip6-lookup"),
};
VNET_FEATURE_INIT (nat46_out2in_handoff, static) = {
  .arc_name = "ip4-unicast",
  .node_name = "nat46-in2out-handoff",
  .runs_before = VNET_FEATURES ("ip4-lookup"),
};


/* *INDENT-ON* */

void
nat46_increment_v6_address (ip6_address_t * i)
{
  u64 v0, v1;

  v0 = clib_net_to_host_u64 (i->as_u64[0]);
  v1 = clib_net_to_host_u64 (i->as_u64[1]);

  v1 += 1;
  if (v1 == 0)
    v0 += 1;
  i->as_u64[0] = clib_net_to_host_u64 (v0);
  i->as_u64[1] = clib_net_to_host_u64 (v1);
}

static void
nat46_ip6_add_del_interface_address_cb (ip6_main_t * im, uword opaque,
					u32 sw_if_index,
					ip6_address_t * address,
					u32 address_length,
					u32 if_address_index, u32 is_delete)
{
    nat46_main_t *nm = &nat46_main;
    int i, j;

    for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
    {
        if (sw_if_index == nm->auto_add_sw_if_indices[i])
        {
            if (!is_delete)
            {
                /* Don't trip over lease renewal, static config */
                for (j = 0; j < vec_len (nm->addr_pool); j++)
                    if (nm->addr_pool[j].addr.prefix.as_u64[0] == address->as_u64[0] &&
                        nm->addr_pool[j].addr.prefix.as_u64[1] == address->as_u64[1])
                        return;

                (void) nat46_add_del_pool_addr (vlib_get_thread_index (),
                        address, ~0, 1, 0, ~0);
                return;
            }
            else
            {
                (void) nat46_add_del_pool_addr (vlib_get_thread_index (),
                        address, ~0, 0, 0, ~0);
                return;
            }
        }
    }
}

static u32
nat46_port_range_get_worker_index( ip6_address_t *addr, u32 proto, u16 port)
{
    nat46_main_t *nm = &nat46_main;
    nat46_address_t *a;
    u32 address_index;
    ip6_address_t ip6, mask;

    for (address_index = 0; address_index < vec_len (nm->addr_pool); address_index++)
    {
        ip6_address_mask_from_width(&mask, nm->addr_pool[address_index].addr.plen);
        ip6.as_u64[0] = addr->as_u64[0];
        ip6.as_u64[1] = addr->as_u64[1];
        ip6_address_mask(&ip6, &mask);
        if (ip6.as_u64[0] == nm->addr_pool[address_index].addr.prefix.as_u64[0] &&
            ip6.as_u64[1] == nm->addr_pool[address_index].addr.prefix.as_u64[1])
            break;
    }
    if(address_index >= vec_len (nm->addr_pool))
    {
        nat_elog_info ("range port not match address");
        return vlib_get_thread_index ();
    }
    a = nm->addr_pool + address_index;
    switch (proto)
    {
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
          if(a->port_range_workers_##n##_ports[port] == (u8)~0) \
              return vlib_get_thread_index (); \
          return a->port_range_workers_##n##_ports[port]; 
	  foreach_snat_protocol
#undef _
	default:
	  nat_elog_info ("unknown protocol");
      return vlib_get_thread_index ();
    }
    return vlib_get_thread_index ();
}

u32
nat46_get_worker_in2out (ip4_address_t * addr)
{
    nat46_main_t *nm = &nat46_main;
    snat_main_t *sm = nm->sm;
    u32 next_worker_index = nm->sm->first_worker_index;
    u32 hash;

    hash = addr->as_u32 + (addr->as_u32 >> 8) +
        (addr->as_u32 >> 16) + (addr->as_u32 >> 24);

    if (PREDICT_TRUE (is_pow2 (_vec_len (sm->workers))))
        next_worker_index += sm->workers[hash & (_vec_len (sm->workers) - 1)];
    else
        next_worker_index += sm->workers[hash % _vec_len (sm->workers)];

    return next_worker_index;
}

u32
nat46_get_worker_out2in (ip6_header_t * ip, u32 fib_index)
{
  nat46_main_t *nm = &nat46_main;
  snat_main_t *sm = nm->sm;

  u16 port;
  u8  l4_proto;
  ip6_frag_hdr_t *frag;
  u16 l4_offset;
  udp_header_t *udp;

  u32 proto;

  nat46_db_dynamic_no_pat_key_t key;

  clib_memset(&key, 0 , sizeof(key));

  l4_proto = ip->protocol;
  proto = ip_proto_to_snat_proto (ip->protocol);
  udp = ip6_next_header (ip);
  port = udp->dst_port;

  /* fragments */
  if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION))
  {
      if (PREDICT_FALSE (nat_reass_is_drop_frag (1)))
          return vlib_get_thread_index ();

      frag = ((ip6_frag_hdr_t *) (ip + 1));
      l4_proto = frag->next_hdr;
      l4_offset = sizeof (*ip) + sizeof (ip6_frag_hdr_t);

      //update proto udp port
      proto = ip_proto_to_snat_proto (l4_proto);
      udp = (udp_header_t *) u8_ptr_add (ip, l4_offset);
      port = udp->dst_port;

      nat_reass_ip6_t *reass;

      reass = nat_ip6_reass_find (ip->src_address, ip->dst_address,
              frag->identification, ip->protocol);

      if (reass && (reass->thread_index != (u32) ~ 0))
          return reass->thread_index;

      /* ICMP */
      if (PREDICT_FALSE (l4_proto == IP_PROTOCOL_ICMP6))
      {
          icmp46_header_t *icmp = (icmp46_header_t *) udp;
          icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
          l4_proto = IP_PROTOCOL_ICMP;
          if (!icmp6_is_error_message (icmp))
              port = echo->identifier;
          else
          {
              ip6_header_t *inner_ip = (ip6_header_t *) (echo + 1);
              proto = ip_proto_to_snat_proto (inner_ip->protocol);
              void *l6_header = ip6_next_header (inner_ip);
              switch (proto)
              {
              case SNAT_PROTOCOL_ICMP:
                  icmp = (icmp46_header_t *) l6_header;
                  echo = (icmp_echo_header_t *) (icmp + 1);
                  port = echo->identifier;
                  break;
              case SNAT_PROTOCOL_UDP:
              case SNAT_PROTOCOL_TCP:
                  port = ((tcp_udp_header_t *) l6_header)->src_port;
                  break;
              default:
                  return vlib_get_thread_index ();
              }
          }
      }

      if (PREDICT_TRUE(ip6_frag_hdr_offset (frag)))
      {
          return vlib_get_thread_index ();
      }
      else
      {
          reass = nat_ip6_reass_create (ip->src_address, ip->dst_address,
                      frag->identification, ip->protocol);
          if (!reass)
              goto no_reass;

          /* try dynamic_mapping_by_no_pat with port*/
          if (nm->dnop.dynamic_no_pat_mappings_cnt)
          {
              clib_bihash_kv_24_8_t kv, value;
              nat46_db_st_entry_t *d_nopat;
              key.addr.ip6 = ip->dst_address;
              key.port = port;
              key.proto = ip->protocol;
              key.fib_index = fib_index;
              kv.key[0] = key.as_u64[0];
              kv.key[1] = key.as_u64[1];
              kv.key[2] = key.as_u64[2];
              if (!clib_bihash_search_24_8 (&nm->dnop.dynamic_mapping_by_no_pat, &kv, &value))
              {
                  d_nopat = (nat46_db_st_entry_t *)value.value;
                  reass->thread_index = d_nopat->worker_index;
                  return reass->thread_index;
              }
          }

          /* worker by outside port  (TCP/UDP) */
          switch(sm->addr_and_port_alloc_alg)
          {
          case NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE:
              reass->thread_index = nat46_port_range_get_worker_index(&ip->dst_address, proto, clib_net_to_host_u16 (port));
              break;
          case NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT:
          case NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE:
          default:
              port = clib_net_to_host_u16 (port);
              if (port > 1024)
                  reass->thread_index = nm->sm->first_worker_index + ((port - 1024) / sm->port_per_thread);
              else
                  reass->thread_index = vlib_get_thread_index ();
              break;
          }
          return reass->thread_index;
      }
  }

no_reass:
  /* unknown protocol */
  if (PREDICT_FALSE (proto == ~0))
  {
      nat46_db_t *db;
      ip46_address_t daddr;
      nat46_db_bib_entry_t *bibe;

      clib_memset (&daddr, 0, sizeof (daddr));
      daddr.ip6.as_u64[0] = ip->dst_address.as_u64[0];
      daddr.ip6.as_u64[1] = ip->dst_address.as_u64[1];

      /* *INDENT-OFF* */
      vec_foreach (db, nm->db)
      {
          bibe = nat46_db_bib_entry_find (db, &daddr, 0, ip->protocol, 0, 1);
          if (bibe)
              return (u32) (db - nm->db);
      }
      /* *INDENT-ON* */
      return vlib_get_thread_index ();
  }

  /* ICMP */
  if (PREDICT_FALSE (l4_proto == IP_PROTOCOL_ICMP6))
  {
      icmp46_header_t *icmp = (icmp46_header_t *) udp;
      icmp_echo_header_t *echo = (icmp_echo_header_t *) (icmp + 1);
      l4_proto = IP_PROTOCOL_ICMP;
      if (!icmp6_is_error_message (icmp))
          port = echo->identifier;
      else
      {
          ip6_header_t *inner_ip = (ip6_header_t *) (echo + 1);
          proto = ip_proto_to_snat_proto (inner_ip->protocol);
          void *l6_header = ip6_next_header (inner_ip);
          switch (proto)
          {
          case SNAT_PROTOCOL_ICMP:
              icmp = (icmp46_header_t *) l6_header;
              echo = (icmp_echo_header_t *) (icmp + 1);
              port = echo->identifier;
              break;
          case SNAT_PROTOCOL_UDP:
          case SNAT_PROTOCOL_TCP:
              port = ((tcp_udp_header_t *) l6_header)->src_port;
              break;
          default:
              return vlib_get_thread_index ();
          }
      }
  }

  /* try dynamic_mapping_by_no_pat with port*/
  if (nm->dnop.dynamic_no_pat_mappings_cnt)
  {
      clib_bihash_kv_24_8_t kv, value;
      nat46_db_st_entry_t *d_nopat;
      key.addr.ip6 = ip->dst_address;
      key.port = port;
      key.proto = l4_proto;
      key.fib_index = fib_index;
      kv.key[0] = key.as_u64[0];
      kv.key[1] = key.as_u64[1];
      kv.key[2] = key.as_u64[2];
      if (!clib_bihash_search_24_8(&nm->dnop.dynamic_mapping_by_no_pat, &kv, &value))
      {
          d_nopat = (nat46_db_st_entry_t *)value.value;
          return d_nopat->worker_index;
      }
  }

  /* worker by outside port  (TCP/UDP) */
  switch(sm->addr_and_port_alloc_alg)
  {
  case NAT_ADDR_AND_PORT_ALLOC_ALG_RANGE:
      return nat46_port_range_get_worker_index(&ip->dst_address, proto, clib_net_to_host_u16 (port));
  case NAT_ADDR_AND_PORT_ALLOC_ALG_DEFAULT:
  case NAT_ADDR_AND_PORT_ALLOC_ALG_MAPE:
  default:
      port = clib_net_to_host_u16 (port);
      if (port > 1024)
          return nm->sm->first_worker_index + ((port - 1024) / sm->port_per_thread);
      break;
  }
  return vlib_get_thread_index ();
}

clib_error_t *
nat46_init (vlib_main_t * vm)
{
  nat46_main_t *nm = &nat46_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  ip6_add_del_interface_address_callback_t cb6;
  ip4_main_t *im4 = &ip4_main;
  ip6_main_t *im6 = &ip6_main;
  nm->sm = &snat_main;
  vlib_node_t *node;

  vec_validate (nm->db, tm->n_vlib_mains - 1);

  nm->fq_in2out_index = ~0;
  nm->fq_out2in_index = ~0;

  nm->alloc_addr_and_port = nat46_alloc_addr_and_port_default;

  node = vlib_get_node_by_name (vm, (u8 *) "error-drop");
  nm->error_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat46-in2out");
  nm->in2out_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat46-in2out-slowpath");
  nm->in2out_slowpath_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat46-in2out-reass");
  nm->in2out_reass_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat46-out2in");
  nm->out2in_node_index = node->index;

  node = vlib_get_node_by_name (vm, (u8 *) "nat46-out2in-reass");
  nm->out2in_reass_node_index = node->index;

  /* set session timeouts to default values */
  nm->udp_timeout = SNAT_UDP_TIMEOUT;
  nm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  nm->tcp_trans_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  nm->tcp_est_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;

  nm->total_enabled_count = 0;
  nm->nat46_expire_walk_interval = NAT46_EXPIRE_WALK_INTERVAL;

  /* Set up the interface address add/del callback */
  cb6.function = nat46_ip6_add_del_interface_address_cb;
  cb6.function_opaque = 0;
  vec_add1 (im6->add_del_interface_address_callbacks, cb6);

  nm->ip4_main = im4;
  nm->ip6_main = im6;

  /* Init counters */
  nm->total_bibs.name = "total-bibs";
  nm->total_bibs.stat_segment_name = "/nat46/total-bibs";
  vlib_validate_simple_counter (&nm->total_bibs, 0);
  vlib_zero_simple_counter (&nm->total_bibs, 0);
  nm->total_sessions.name = "total-sessions";
  nm->total_sessions.stat_segment_name = "/nat46/total-sessions";
  vlib_validate_simple_counter (&nm->total_sessions, 0);
  vlib_zero_simple_counter (&nm->total_sessions, 0);

  return 0;
}

static void nat46_free_out_addr_and_port (struct nat46_db_s *db,
					  ip6_address_t * addr, u16 port,
					  u8 protocol);

void
nat46_add_del_addr_to_fib (ip6_address_t * addr, u8 p_len, u32 sw_if_index,
			  int is_add)
{
  fib_prefix_t prefix = {
    .fp_len = p_len,
    .fp_proto = FIB_PROTOCOL_IP6,
    .fp_addr = {
		.ip6.as_u64[0] = addr->as_u64[0],
		.ip6.as_u64[1] = addr->as_u64[1],
		},
  };
  u32 fib_index = ip6_fib_table_get_index_for_sw_if_index (sw_if_index);

  if (is_add)
    fib_table_entry_update_one_path (fib_index,
				     &prefix,
				     FIB_SOURCE_PLUGIN_LOW,
				     (FIB_ENTRY_FLAG_CONNECTED |
				      FIB_ENTRY_FLAG_LOCAL |
				      FIB_ENTRY_FLAG_EXCLUSIVE),
				     DPO_PROTO_IP6,
				     NULL,
				     sw_if_index,
				     ~0, 1, NULL, FIB_ROUTE_PATH_FLAG_NONE);
  else
    fib_table_entry_delete (fib_index, &prefix, FIB_SOURCE_PLUGIN_LOW);
}

void
nat46_set_hash (u32 max_st_per_worker, u32 bib_buckets, u32 bib_memory_size, u32 st_buckets,
		u32 st_memory_size, u32 no_pat_buckets, u32 no_pat_memory_size, 
        u32 remote_map_buckets, u32 remote_map_memory_size)
{
  nat46_main_t *nm = &nat46_main;
  nat46_db_t *db;

  nm->max_translations = max_st_per_worker;
  nm->bib_buckets = bib_buckets;
  nm->bib_memory_size = bib_memory_size;
  nm->st_buckets = st_buckets;
  nm->st_memory_size = st_memory_size;
  nm->no_pat_buckets = no_pat_buckets;
  nm->no_pat_memory_size = no_pat_memory_size;
  nm->remote_map_buckets = remote_map_buckets;
  nm->remote_map_memory_size = remote_map_memory_size;

  clib_bihash_init_24_8 (&nm->dnop.dynamic_mapping_by_no_pat, "nat46-dynamic-no-pat", 
			 nm->bib_buckets, nm->bib_memory_size);

  clib_bihash_init_24_8 (&nm->remote_mapping.remote_ip4toip6, "nat46-remote-mapping-4to6", 
			 nm->remote_map_buckets,
			 nm->remote_map_memory_size);
  clib_bihash_init_24_8 (&nm->remote_mapping.remote_ip6toip4, "nat46-remote-mapping-6to4", 
			 nm->remote_map_buckets,
			 nm->remote_map_memory_size);

  /* *INDENT-OFF* */
  vec_foreach (db, nm->db)
    {
      if (nat46_db_init (max_st_per_worker, db, bib_buckets, bib_memory_size, st_buckets,
                         st_memory_size, nat46_free_out_addr_and_port))
	nat_elog_err ("NAT46 DB init failed");
    }
  /* *INDENT-ON* */
}

int
nat46_add_del_pool_addr (u32 thread_index,
			 ip6_address_t * addr, u32 vrf_id, u8 is_add, u8 no_pat, u32 limit_ip_cnt)
{
    nat46_main_t *nm = &nat46_main;
    nat46_address_t *a = 0;
    snat_interface_t *interface;
    int i;
    nat46_db_t *db;
    vlib_thread_main_t *tm = vlib_get_thread_main ();

    /* Check if address already exists */
    for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
        if (nm->addr_pool[i].vrf_id == vrf_id && nm->addr_pool[i].addr.plen != 128)
            return VNET_API_ERROR_INVALID_ARGUMENT;

        if (nm->addr_pool[i].addr.prefix.as_u64[0] == addr->as_u64[0] &&
            nm->addr_pool[i].addr.prefix.as_u64[1] == addr->as_u64[1] &&
            nm->addr_pool[i].addr.plen == 128)
        {
            a = nm->addr_pool + i;
            break;
        }
    }

    if (is_add)
    {
        if (a)
            return VNET_API_ERROR_VALUE_EXIST;

        vec_add2 (nm->addr_pool, a, 1);

        clib_memset(a, 0 , sizeof(nat46_address_t));

        a->addr.prefix.as_u64[0] = addr->as_u64[0];
        a->addr.prefix.as_u64[1] = addr->as_u64[1];
        a->addr.plen = 128;

        a->no_pat = no_pat;

        a->limit_user_max = limit_ip_cnt;
        a->limit_user_cnt = 0;

        a->vrf_id = vrf_id;
        a->fib_index = ~0;
        if (vrf_id != ~0)
        {
            a->fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id, FIB_SOURCE_PLUGIN_HI);
        }
#define _(N, id, n, s) \
        vec_validate_init_empty (a->busy_##n##_port_used_flag, 65536, 0); \
        vec_validate_init_empty (a->port_range_workers_##n##_ports, 65536, ~0); \
        a->busy_##n##_ports = 0; \
        a->busy_##n##_ports_per_thread = 0;\
        vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
        foreach_snat_protocol
#undef _
    }
    else
    {
        if (!a)
            return VNET_API_ERROR_NO_SUCH_ENTRY;

        if (a->fib_index != ~0)
            fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_HI);

        /* Delete sessions using address */
        /* *INDENT-OFF* */
        vec_foreach (db, nm->db)
        {
            nat46_db_free_out_addr (thread_index, db, &a->addr.prefix, a->addr.plen);
            vlib_set_simple_counter (&nm->total_bibs, db - nm->db, 0, db->bib.bib_entries_num);
            vlib_set_simple_counter (&nm->total_sessions, db - nm->db, 0, db->st.st_entries_num);
        }
#define _(N, id, n, s) \
        vec_free (a->busy_##n##_port_used_flag); \
        vec_free (a->busy_##n##_ports_per_thread); \
        vec_free (a->port_range_workers_##n##_ports);
        foreach_snat_protocol
#undef _

        a->no_pat = 0;
        a->limit_user_max = ~0;
        a->limit_user_cnt = 0;

        vec_free(a->limit_user);

        clib_memset(a, 0 , sizeof(nat46_address_t));
        /* *INDENT-ON* */
        vec_del1 (nm->addr_pool, i);
    }

    /* Add/del external address to FIB */
    /* *INDENT-OFF* */
    pool_foreach (interface, nm->interfaces,
    ({
        if (nat_interface_is_inside(interface))
        continue;

        nat46_add_del_addr_to_fib (addr, 128, interface->sw_if_index, is_add);
        break;
    }));
    /* *INDENT-ON* */

  return 0;
}

int
nat46_add_del_pool_prefix (u32 thread_index,
        ip6_address_t * prefix, u8 plen, u32 vrf_id, u8 is_add, u8 no_pat, u32 limit_ip_cnt)
{
    nat46_main_t *nm = &nat46_main;
    nat46_address_t *a = 0;
    int i;
    vlib_thread_main_t *tm = vlib_get_thread_main ();
    nat46_db_t *db;
    snat_interface_t *interface;

    /* Verify prefix length */
    if (plen != 32 && plen != 40 && plen != 48 && plen != 56 && plen != 64 && plen != 96)
        return VNET_API_ERROR_INVALID_VALUE;

    /* Check if tenant  already have pool prefix exists */
    for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
        if (nm->addr_pool[i].vrf_id == vrf_id)
        {
            if(nm->addr_pool[i].addr.plen == 128)
                return VNET_API_ERROR_INVALID_ARGUMENT;
            else
                a = nm->addr_pool + i;
            break;

        }
    }

    if (is_add)
    {
        if (!a)
        {
            vec_add2 (nm->addr_pool, a, 1);

            a->no_pat = no_pat;
            a->limit_user_max = limit_ip_cnt;
            a->limit_user_cnt = 0;

            a->vrf_id = vrf_id;
            a->fib_index = ~0;
            if (vrf_id != ~0)
            {
                a->vrf_id = vrf_id;
                a->fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id, FIB_SOURCE_PLUGIN_HI);
            }
#define _(N, id, n, s) \
            vec_validate_init_empty (a->busy_##n##_port_used_flag, 65536, 0); \
            vec_validate_init_empty (a->port_range_workers_##n##_ports, 65536, ~0); \
            a->busy_##n##_ports = 0; \
            a->busy_##n##_ports_per_thread = 0;\
            vec_validate_init_empty (a->busy_##n##_ports_per_thread, tm->n_vlib_mains - 1, 0);
            foreach_snat_protocol
#undef _
        }
        a->addr.prefix.as_u64[0] = prefix->as_u64[0];
        a->addr.prefix.as_u64[1] = prefix->as_u64[1];
        a->addr.plen = plen;
    }
    else
    {
        if (!a)
            return VNET_API_ERROR_NO_SUCH_ENTRY;

        if (a->fib_index != ~0)
            fib_table_unlock (a->fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_HI);

        /* Delete sessions using address */
        /* *INDENT-OFF* */
        vec_foreach (db, nm->db)
        {
            nat46_db_free_out_addr (thread_index, db, &a->addr.prefix, a->addr.plen);
            vlib_set_simple_counter (&nm->total_bibs, db - nm->db, 0, db->bib.bib_entries_num);
            vlib_set_simple_counter (&nm->total_sessions, db - nm->db, 0, db->st.st_entries_num);
        }
#define _(N, id, n, s) \
        vec_free (a->busy_##n##_port_used_flag); \
        vec_free (a->busy_##n##_ports_per_thread); \
        vec_free (a->port_range_workers_##n##_ports);
        foreach_snat_protocol
#undef _

        a->no_pat = 0;
        a->limit_user_max = ~0;
        a->limit_user_cnt = 0;

        vec_free(a->limit_user);

        /* *INDENT-ON* */
        vec_del1 (nm->addr_pool, i);
    }

    /* Add/del external address to FIB */
    /* *INDENT-OFF* */
    pool_foreach (interface, nm->interfaces,
    ({
        if (nat_interface_is_inside(interface))
        continue;

        nat46_add_del_addr_to_fib (prefix, plen, interface->sw_if_index, is_add);
        break;
    }));
    /* *INDENT-ON* */

  return 0;
}


void
nat46_pool_addr_walk (nat46_pool_addr_walk_fn_t fn, void *ctx)
{
  nat46_main_t *nm = &nat46_main;
  nat46_address_t *a = 0;

  /* *INDENT-OFF* */
  vec_foreach (a, nm->addr_pool)
    {
      if (fn (a, ctx))
        break;
    };
  /* *INDENT-ON* */
}

int
nat46_add_interface_address (u32 sw_if_index, int is_add, u8 no_pat, u32 limit_ip_cnt)
{
    nat46_main_t *nm = &nat46_main;
    ip6_main_t *ip6_main = nm->ip6_main;
    ip6_address_t *first_int_addr;
    ip6_address_t *follow_int_addr;
    ip_interface_address_t * ia;
    u32 ia_index;
    int i;

    first_int_addr = ip6_interface_first_address (ip6_main, sw_if_index, &ia);

    for (i = 0; i < vec_len (nm->auto_add_sw_if_indices); i++)
    {
        if (nm->auto_add_sw_if_indices[i] == sw_if_index)
        {
            if (is_add)
                return VNET_API_ERROR_VALUE_EXIST;
            else
            {
                /* if have address remove it */
                if (first_int_addr)
                {
                    (void) nat46_add_del_pool_addr (vlib_get_thread_index (), first_int_addr, ~0, 0, no_pat, limit_ip_cnt);
                    ia_index = ia->next_this_sw_interface;                            
                    while(ia_index != ~0)
                    {
                        ia = pool_elt_at_index (ip6_main->lookup_main.if_address_pool, ia_index);
                        follow_int_addr = ip_interface_address_get_address (&ip6_main->lookup_main, ia);
                        (void) nat46_add_del_pool_addr (vlib_get_thread_index (), follow_int_addr, ~0, 0, no_pat, limit_ip_cnt);
                        ia_index = ia->next_this_sw_interface;                            
                    }
                }
                vec_del1 (nm->auto_add_sw_if_indices, i);
                return 0;
            }
        }
    }

    if (!is_add)
        return VNET_API_ERROR_NO_SUCH_ENTRY;

    /* add to the auto-address list */
    vec_add1 (nm->auto_add_sw_if_indices, sw_if_index);

    /* If the address is already bound - or static - add it now */
    if (first_int_addr)
    {
        (void) nat46_add_del_pool_addr (vlib_get_thread_index (), first_int_addr, ~0, 1, no_pat, limit_ip_cnt);
        ia_index = ia->next_this_sw_interface;                            
        while(ia_index != ~0)
        {
            ia = pool_elt_at_index (ip6_main->lookup_main.if_address_pool, ia_index);
            follow_int_addr = ip_interface_address_get_address (&ip6_main->lookup_main, ia);
            (void) nat46_add_del_pool_addr (vlib_get_thread_index (), follow_int_addr, ~0, 1, no_pat, limit_ip_cnt);
            ia_index = ia->next_this_sw_interface;                            
        }
    }

    return 0;
}

int
nat46_add_del_interface (u32 sw_if_index, u8 is_inside, u8 is_add)
{
    nat46_main_t *nm = &nat46_main;
    snat_interface_t *interface = 0, *i;
    nat46_address_t *ap;
    const char *feature_name, *arc_name;

    /* Check if interface already exists */
    /* *INDENT-OFF* */
    pool_foreach (i, nm->interfaces,
    ({
        if (i->sw_if_index == sw_if_index)
        {
            interface = i;
            break;
        }
     }));
    /* *INDENT-ON* */

    if (is_add)
    {
        if (interface)
            goto set_flags;

        pool_get (nm->interfaces, interface);
        interface->sw_if_index = sw_if_index;
        interface->flags = 0;
set_flags:
        if (is_inside)
            interface->flags |= NAT_INTERFACE_FLAG_IS_INSIDE;
        else
            interface->flags |= NAT_INTERFACE_FLAG_IS_OUTSIDE;

        nm->total_enabled_count++;
        vlib_process_signal_event (nm->sm->vlib_main,
                nm->nat46_expire_walk_node_index,
                NAT46_CLEANER_RESCHEDULE, 0);

    }
    else
    {
        if (!interface)
            return VNET_API_ERROR_NO_SUCH_ENTRY;

        if ((nat_interface_is_inside (interface) && nat_interface_is_outside (interface)))
            interface->flags &= is_inside ? ~NAT_INTERFACE_FLAG_IS_INSIDE : ~NAT_INTERFACE_FLAG_IS_OUTSIDE;
        else
            pool_put (nm->interfaces, interface);

        nm->total_enabled_count--;
    }

    if (!is_inside)
    {
        /* *INDENT-OFF* */
        vec_foreach (ap, nm->addr_pool)
            nat46_add_del_addr_to_fib(&ap->addr.prefix, ap->addr.plen, sw_if_index, is_add);
        /* *INDENT-ON* */
    }

    if (nm->sm->num_workers > 1)
    {
      feature_name = is_inside ? "nat46-in2out-handoff" : "nat46-out2in-handoff";
      if (nm->fq_in2out_index == ~0)
          nm->fq_in2out_index = vlib_frame_queue_main_init (nat46_in2out_node.index, 0);
      if (nm->fq_out2in_index == ~0)
          nm->fq_out2in_index = vlib_frame_queue_main_init (nat46_out2in_node.index, 0);
    }
    else
        feature_name = is_inside ? "nat46-in2out" : "nat46-out2in";

    arc_name = is_inside ? "ip4-unicast" : "ip6-unicast";

    return vnet_feature_enable_disable (arc_name, feature_name, sw_if_index, is_add, 0, 0);
}

void
nat46_interfaces_walk (nat46_interface_walk_fn_t fn, void *ctx)
{
  nat46_main_t *nm = &nat46_main;
  snat_interface_t *i = 0;

  /* *INDENT-OFF* */
  pool_foreach (i, nm->interfaces,
  ({
    if (fn (i, ctx))
      break;
  }));
  /* *INDENT-ON* */
}

void
nat46_compose_ip6 (ip6_address_t * ip6, ip4_address_t * ip4, u32 plen)
{
    switch (plen)
    {
    case 32:
        ip6->as_u32[1] = ip4->as_u32;
        break;
    case 40:
        ip6->as_u8[5] = ip4->as_u8[0];
        ip6->as_u8[6] = ip4->as_u8[1];
        ip6->as_u8[7] = ip4->as_u8[2];
        ip6->as_u8[9] = ip4->as_u8[3];
        break;
    case 48:
        ip6->as_u8[6] = ip4->as_u8[0];
        ip6->as_u8[7] = ip4->as_u8[1];
        ip6->as_u8[9] = ip4->as_u8[2];
        ip6->as_u8[10] = ip4->as_u8[3];
        break;
    case 56:
        ip6->as_u8[7] = ip4->as_u8[0];
        ip6->as_u8[9] = ip4->as_u8[1];
        ip6->as_u8[10] = ip4->as_u8[2];
        ip6->as_u8[11] = ip4->as_u8[3];
        break;
    case 64:
        ip6->as_u8[9] = ip4->as_u8[0];
        ip6->as_u8[10] = ip4->as_u8[1];
        ip6->as_u8[11] = ip4->as_u8[2];
        ip6->as_u8[12] = ip4->as_u8[3];
        break;
    case 96:
        ip6->as_u32[3] = ip4->as_u32;
        break;
    default:
        nat_elog_notice ("invalid prefix length");
        break;
    }
}

static_always_inline u16
snat46_random_port (u16 min, u16 max)
{
  snat_main_t *sm = &snat_main;
  return min + random_u32 (&sm->random_seed) /
    (random_u32_max () / (max - min + 1) + 1);
}

int
nat46_alloc_addr_and_port_default (nat46_address_t * addresses,
				 u32 fib_index,
				 u32 thread_index,
				 nat46_session_key_t * k,
				 u16 port_per_thread, u32 snat_thread_index)
{
    int i;
    nat46_address_t *a, *ga = 0;
    u32 portnum;

    for (i = 0; i < vec_len (addresses); i++)
    {
        a = addresses + i;
        if(a->limit_user_cnt >= a->limit_user_max)
            continue;
        switch (k->protocol)
        {
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
            if (a->busy_##n##_ports_per_thread[thread_index] < port_per_thread) \
            { \
                if (a->fib_index == fib_index) \
                { \
                    while (1) \
                    { \
                        if(!a->no_pat) \
                        { \
                            portnum = (port_per_thread * \
                                    snat_thread_index) + snat46_random_port(1, port_per_thread) + 1024; \
                            if (a->busy_##n##_port_used_flag[portnum] > 0) \
                                continue; \
                            k->port = clib_host_to_net_u16(portnum); \
                        } \
                        else \
                        { \
                            portnum = clib_net_to_host_u16(k->port); \
                            if (a->busy_##n##_port_used_flag[portnum] > 0) \
                            break; \
                        } \
                        a->busy_##n##_port_used_flag[portnum] = 1; \
                        a->busy_##n##_ports_per_thread[thread_index]++; \
                        clib_atomic_fetch_add(&a->busy_##n##_ports, 1); \
                        clib_memcpy_fast (&k->addr, &a->addr.prefix, sizeof (ip6_address_t)); \
                        nat46_compose_ip6(&k->addr, &k->in_addr, a->addr.plen); \
                        return 0; \
                    } \
                } \
                else if (a->fib_index == ~0) \
                { \
                    ga = a; \
                } \
            } \
            break;
            foreach_snat_protocol
#undef _
        default:
                nat_elog_info ("unknown protocol");
                return 1;
        }

    }

    if (ga)
    {
        a = ga;
        switch (k->protocol)
        {
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
            while (1) \
            { \
                if(!a->no_pat) \
                { \
                    portnum = (port_per_thread * \
                            snat_thread_index) + \
                    snat46_random_port(1, port_per_thread) + 1024; \
                    if (a->busy_##n##_port_used_flag[portnum] > 0) \
                    continue; \
                    k->port = clib_host_to_net_u16(portnum); \
                } \
                else\
                { \
                    portnum = clib_net_to_host_u16(k->port); \
                    if (a->busy_##n##_port_used_flag[portnum] > 0) \
                    break; \
                } \
                a->busy_##n##_port_used_flag[portnum] = 1; \
                a->busy_##n##_ports_per_thread[thread_index]++; \
                clib_atomic_fetch_add(&a->busy_##n##_ports, 1); \
                if (a->addr.plen == 128) \
                { \
                    clib_memcpy_fast (&k->addr, &a->addr.prefix, sizeof (ip6_address_t)); \
                } \
                else \
                { \
                    clib_memcpy_fast (&k->addr, &a->addr.prefix, sizeof (ip6_address_t)); \
                    nat46_compose_ip6(&k->addr, &k->in_addr, a->addr.plen); \
                } \
                return 0; \
            } \
            break;
            foreach_snat_protocol
#undef _
        default:
                nat_elog_info ("unknown protocol");
                return 1;
        }
    }

    /* Totally out of translations to use... */
    snat_ipfix_logging_addresses_exhausted (thread_index, 0);
    return 1;
}

int
nat46_alloc_addr_and_port_mape (nat46_address_t * addresses,
			      u32 fib_index,
			      u32 thread_index,
			      nat46_session_key_t * k,
			      u16 port_per_thread, u32 snat_thread_index)
{
    snat_main_t *sm = &snat_main;
    nat46_address_t *a = addresses;
    u16 m, ports, portnum, A, j;
    m = 16 - (sm->psid_offset + sm->psid_length);
    ports = (1 << (16 - sm->psid_length)) - (1 << m);

    if (!vec_len (addresses))
        goto exhausted;

    switch (k->protocol)
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        if (a->busy_##n##_ports < ports) \
        { \
            while (1) \
            { \
                if(!a->no_pat) \
                { \
                    A = snat46_random_port(1, pow2_mask(sm->psid_offset)); \
                    j = snat46_random_port(0, pow2_mask(m)); \
                    portnum = A | (sm->psid << sm->psid_offset) | (j << (16 - m)); \
                    if (clib_atomic_load_acq_n(&a->busy_##n##_port_used_flag[portnum]) > 0) \
                        continue; \
                    k->port = clib_host_to_net_u16 (portnum); \
                } \
                else \
                { \
                    portnum = clib_net_to_host_u16(k->port); \
                    if (clib_atomic_load_acq_n(&a->busy_##n##_port_used_flag[portnum]) > 0) \
                    break; \
                } \
                clib_atomic_fetch_add(&a->busy_##n##_port_used_flag[portnum], 1); \
                clib_atomic_fetch_add(&a->busy_##n##_ports, 1); \
                clib_memcpy_fast (&k->addr, &a->addr.prefix, sizeof (ip6_address_t)); \
                nat46_compose_ip6(&k->addr, &k->in_addr, a->addr.plen); \
                return 0; \
            } \
        } \
        break;
        foreach_snat_protocol
#undef _
    default:
            nat_elog_info ("unknown protocol");
            return 1;
    }

exhausted:
    /* Totally out of translations to use... */
    snat_ipfix_logging_addresses_exhausted (thread_index, 0);
    return 1;
}

int
nat46_alloc_addr_and_port_range (nat46_address_t * addresses,
			       u32 fib_index,
			       u32 thread_index,
			       nat46_session_key_t * k,
			       u16 port_per_thread, u32 snat_thread_index)
{
    snat_main_t *sm = &snat_main;
    nat46_address_t *a = addresses;
    u16 portnum, ports;
    int i;

    ports = sm->end_port - sm->start_port + 1;

    if (!vec_len (addresses))
        goto exhausted;

    for (i = 0; i < vec_len (addresses); i++)
    {
        a = addresses + i;
        if(a->limit_user_cnt >= a->limit_user_max)
            continue;
        switch (k->protocol)
        {
#define _(N, i, n, s) \
        case SNAT_PROTOCOL_##N: \
            if (a->busy_##n##_ports < ports) \
            { \
                while (1) \
                { \
                    if(!a->no_pat) \
                    { \
                        portnum = snat46_random_port(sm->start_port, sm->end_port); \
                        if (clib_atomic_load_acq_n(&a->busy_##n##_port_used_flag[portnum]) > 0) \
                            continue; \
                        k->port = clib_host_to_net_u16 (portnum); \
                    } \
                    else  \
                    { \
                        portnum = clib_net_to_host_u16(k->port); \
                        if (clib_atomic_load_acq_n(&a->busy_##n##_port_used_flag[portnum]) > 0) \
                        break; \
                    } \
                    a->port_range_workers_##n##_ports[portnum] = thread_index; \
                    clib_atomic_fetch_add(&a->busy_##n##_port_used_flag[portnum], 1); \
                    clib_atomic_fetch_add(&a->busy_##n##_ports, 1); \
                    clib_memcpy_fast (&k->addr, &a->addr.prefix, sizeof (ip6_address_t)); \
                    nat46_compose_ip6(&k->addr, &k->in_addr, a->addr.plen); \
                    return 0; \
                } \
            } \
            break;
            foreach_snat_protocol
#undef _
        default:
                nat_elog_info ("unknown protocol");
                return 1;
        }
    }

exhausted:
    /* Totally out of translations to use... */
    snat_ipfix_logging_addresses_exhausted (thread_index, 0);
    return 1;
}

int
nat46_alloc_out_addr_and_port (u32 fib_index, snat_protocol_t proto,
			       ip4_address_t *in_addr,  u16 in_port,
                   ip6_address_t * addr, u16 * port, 
                   u8 *no_pat, u32 thread_index)
{
  nat46_main_t *nm = &nat46_main;
  snat_main_t *sm = nm->sm;
  nat46_session_key_t k;
  u32 worker_index = 0;
  int rv;

  k.protocol = proto;
  k.port = in_port;
  k.in_addr.as_u32 = in_addr->as_u32;

  if (sm->num_workers > 1)
    worker_index = thread_index - sm->first_worker_index;

  rv =
    nm->alloc_addr_and_port (nm->addr_pool, fib_index, thread_index, &k,
			     sm->port_per_thread, worker_index);

  if (!rv)
    {
      *port = k.port;
      addr->as_u64[0] = k.addr.as_u64[0];
      addr->as_u64[1] = k.addr.as_u64[1];
      
      if (in_port == k.port)
          *no_pat = 1;
    }

  return rv;
}

static void
nat46_free_out_addr_and_port (struct nat46_db_s *db, ip6_address_t * addr,
			      u16 port, u8 protocol)
{
    nat46_main_t *nm = &nat46_main;
    int i;
    nat46_address_t *a;
    u32 thread_index = db - nm->db;
    snat_protocol_t proto = ip_proto_to_snat_proto (protocol);
    u16 port_host_byte_order = clib_net_to_host_u16 (port);
    ip6_address_t ip6, mask;

    for (i = 0; i < vec_len (nm->addr_pool); i++)
    {
        a = nm->addr_pool + i;
        ip6_address_mask_from_width(&mask, a->addr.plen);
        ip6.as_u64[0] = addr->as_u64[0];
        ip6.as_u64[1] = addr->as_u64[1];
        ip6_address_mask(&ip6, &mask);
        if (ip6.as_u64[0] != a->addr.prefix.as_u64[0] ||
            ip6.as_u64[1] != a->addr.prefix.as_u64[1])
            continue;
        switch (proto)
        {
#define _(N, j, n, s) \
        case SNAT_PROTOCOL_##N: \
            ASSERT (a->busy_##n##_port_used_flag[port_host_byte_order] > 0); \
            a->busy_##n##_port_used_flag[port_host_byte_order] = 0; \
            a->port_range_workers_##n##_ports[port_host_byte_order] = ~0; \
            clib_atomic_fetch_sub(&a->busy_##n##_ports, 1); \
            a->busy_##n##_ports_per_thread[thread_index]--; \
            break;
            foreach_snat_protocol
#undef _
        default:
                nat_elog_notice ("unknown protocol");
                return;
        }
        break;
    }
}

/**
 * @brief Add/delete static BIB entry in worker thread.
 */
static uword
nat46_static_bib_worker_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			    vlib_frame_t * f)
{
    nat46_main_t *nm = &nat46_main;
    u32 thread_index = vm->thread_index;
    nat46_db_t *db = &nm->db[thread_index];
    nat46_static_bib_to_update_t *static_bib;
    nat46_db_bib_entry_t *bibe;
    ip46_address_t addr;

    clib_memset (&addr, 0, sizeof (addr));
  /* *INDENT-OFF* */
    pool_foreach (static_bib, nm->static_bibs,
    ({
        if ((static_bib->thread_index != thread_index) || (static_bib->done))
            continue;

        if (static_bib->is_add)
        {
           (void) nat46_db_bib_entry_create (thread_index, db,
                                            &static_bib->in_addr,
                                            &static_bib->out_addr,
                                            static_bib->in_port,
                                            static_bib->out_port,
                                            static_bib->fib_index,
                                            static_bib->proto, 1);
           vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
                                   db->bib.bib_entries_num);
       }
       else
       {
           addr.ip4.as_u32 = static_bib->in_addr.as_u32;
           bibe = nat46_db_bib_entry_find (db, &addr, static_bib->in_port,
                   static_bib->proto,
                   static_bib->fib_index, 0);
           if (bibe)
           {
               nat46_db_bib_entry_free (thread_index, db, bibe);
               vlib_set_simple_counter (&nm->total_bibs, thread_index, 0, db->bib.bib_entries_num);
               vlib_set_simple_counter (&nm->total_sessions, thread_index, 0, db->st.st_entries_num);
           }
       }
      static_bib->done = 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

static vlib_node_registration_t nat46_static_bib_worker_node;

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_static_bib_worker_node, static) = {
    .function = nat46_static_bib_worker_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat46-static-bib-worker",
};
/* *INDENT-ON* */

int
nat46_add_del_static_bib_entry (ip4_address_t * in_addr,
				ip6_address_t * out_addr, u16 in_port,
				u16 out_port, u8 proto, u32 vrf_id, u8 is_add, 
                nat46_static_bib_ctx_t * ctx)
{
    nat46_main_t *nm = &nat46_main;
    nat46_db_bib_entry_t *bibe;
    u32 fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id, FIB_SOURCE_PLUGIN_HI);
    snat_protocol_t p = ip_proto_to_snat_proto (proto);
    ip46_address_t addr;
    ip6_address_t ip6, mask;
    int i;
    nat46_address_t *a;
    u32 thread_index = 0;
    nat46_db_t *db;
    nat46_static_bib_to_update_t *static_bib;
    vlib_main_t *worker_vm;
    u32 *to_be_free = 0, *index;

    if (nm->sm->num_workers > 1)
    {
        thread_index = nat46_get_worker_in2out (in_addr);
        db = &nm->db[thread_index];
    }
    else
        db = &nm->db[nm->sm->num_workers];

    clib_memset (&addr, 0, sizeof (addr));
    addr.ip4.as_u32 = in_addr->as_u32;
    bibe = nat46_db_bib_entry_find (db, &addr, clib_host_to_net_u16 (in_port), proto, fib_index, 0);

    if (is_add)
    {
        if (bibe)
            return VNET_API_ERROR_VALUE_EXIST;

        /* outside port must be assigned to same thread as internall address */
        if ((out_port > 1024) && (nm->sm->num_workers > 1))
        {
            if (ctx != NULL)
            {
                ctx->port_start = (thread_index - 1) * nm->sm->port_per_thread + 1024;
                ctx->port_end   =  thread_index * nm->sm->port_per_thread + 1024 -1;
            }
            if (thread_index != ((out_port - 1024) / nm->sm->port_per_thread) + nm->sm->first_worker_index)
                return VNET_API_ERROR_INVALID_VALUE_2;
        }

        for (i = 0; i < vec_len (nm->addr_pool); i++)
        {
            a = nm->addr_pool + i;
            ip6_address_mask_from_width(&mask, a->addr.plen);
            ip6.as_u64[0] = out_addr->as_u64[0];
            ip6.as_u64[1] = out_addr->as_u64[1];
            ip6_address_mask(&ip6, &mask);
            if (ip6.as_u64[0] != a->addr.prefix.as_u64[0] ||
                ip6.as_u64[1] != a->addr.prefix.as_u64[1])
                continue;
            switch (p)
            {
#define _(N, j, n, s) \
            case SNAT_PROTOCOL_##N: \
                if (a->busy_##n##_port_used_flag[out_port] > 0) \
                    return VNET_API_ERROR_INVALID_VALUE; \
                a->busy_##n##_port_used_flag[out_port] = 1; \
                if (out_port > 1024) \
                { \
                    a->busy_##n##_ports++; \
                    a->busy_##n##_ports_per_thread[thread_index]++; \
                } \
                break;
                foreach_snat_protocol
#undef _
            default:
                clib_memset (&addr, 0, sizeof (addr));
                addr.ip6.as_u64[0] = out_addr->as_u64[0];
                addr.ip6.as_u64[1] = out_addr->as_u64[1];
                if (nat46_db_bib_entry_find (db, &addr, 0, proto, fib_index, 1))
                    return VNET_API_ERROR_INVALID_VALUE;
            }
            break;
        }
        if (!nm->sm->num_workers)
        {
            bibe = nat46_db_bib_entry_create (thread_index, db, in_addr, out_addr,
                        clib_host_to_net_u16 (in_port),
                        clib_host_to_net_u16 (out_port),
                        fib_index, proto, 1);
            if (!bibe)
                return VNET_API_ERROR_UNSPECIFIED;

            vlib_set_simple_counter (&nm->total_bibs, thread_index, 0, db->bib.bib_entries_num);
        }
    }
    else
    {
        if (!bibe)
            return VNET_API_ERROR_NO_SUCH_ENTRY;

        if (!nm->sm->num_workers)
        {
            nat46_db_bib_entry_free (thread_index, db, bibe);
            vlib_set_simple_counter (&nm->total_bibs, thread_index, 0, db->bib.bib_entries_num);
        }
    }

    if (nm->sm->num_workers)
    {
        /* *INDENT-OFF* */
        pool_foreach (static_bib, nm->static_bibs,
        ({
            if (static_bib->done)
                vec_add1 (to_be_free, static_bib - nm->static_bibs);
        }));
        vec_foreach (index, to_be_free)
            pool_put_index (nm->static_bibs, index[0]);
        /* *INDENT-ON* */
        vec_free (to_be_free);
        pool_get (nm->static_bibs, static_bib);
        static_bib->in_addr.as_u32 = in_addr->as_u32;
        static_bib->in_port = clib_host_to_net_u16 (in_port);
        static_bib->out_addr.as_u64[0] = out_addr->as_u64[0];
        static_bib->out_addr.as_u64[1] = out_addr->as_u64[1];
        static_bib->out_port = clib_host_to_net_u16 (out_port);
        static_bib->fib_index = fib_index;
        static_bib->proto = proto;
        static_bib->is_add = is_add;
        static_bib->thread_index = thread_index;
        static_bib->done = 0;
        worker_vm = vlib_mains[thread_index];
        if (worker_vm)
            vlib_node_set_interrupt_pending (worker_vm, nat46_static_bib_worker_node.index);
        else
            return VNET_API_ERROR_UNSPECIFIED;
    }

    return 0;
}

int
nat46_add_remote_mapping_entry(ip4_address_t * laddr,
				ip6_address_t * raddr, 
                u8 proto, u32 vrf_id, u8 is_add)
{
    nat46_main_t *nm = &nat46_main;
    nat46_db_remote_mapping_t *mapping = &nm->remote_mapping;
    nat46_remote_mapping_entry_t *mapping_entry = NULL;
    nat46_remote_mapping_key_t key46, key64;
    clib_bihash_kv_24_8_t kv, value;
    u64 value_index = ~0;
    u32 fib_index = ~0;

    clib_memset (&key46.addr, 0, sizeof (key46));
    key46.addr.ip4.as_u32 = laddr->as_u32;
    key46.proto = proto;
    key46.rsvd16 = 0;
    key46.rsvd8 = 0;

    key64.addr.ip6.as_u64[0] = raddr->as_u64[0];
    key64.addr.ip6.as_u64[1] = raddr->as_u64[1];
    key64.proto = proto;
    key64.rsvd16 = 0;
    key64.rsvd8 = 0;

    if(is_add)
    {
        fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP4, vrf_id, FIB_SOURCE_PLUGIN_HI);

        key46.fib_index = fib_index;
        key64.fib_index = fib_index;

        pool_get (mapping->mapping_entrys, mapping_entry);

        if(!mapping_entry)
            return VNET_API_ERROR_NO_SUCH_ENTRY;

        clib_memset (mapping_entry, 0, sizeof (*mapping_entry));

        mapping_entry->fib_index = fib_index;
        mapping_entry->proto = proto;
        mapping_entry->l_addr.as_u32 = key46.addr.ip4.as_u32;
        mapping_entry->r_addr.as_u64[0] = key64.addr.ip6.as_u64[0];
        mapping_entry->r_addr.as_u64[1] = key64.addr.ip6.as_u64[1];

        kv.key[0] = key46.as_u64[0];
        kv.key[1] = key46.as_u64[1];
        kv.key[2] = key46.as_u64[2];
        kv.value = mapping_entry - mapping->mapping_entrys;
        if (!clib_bihash_search_24_8 (&mapping->remote_ip4toip6, &kv, &value))
        {
            pool_put (mapping->mapping_entrys, mapping_entry);
            return VNET_API_ERROR_VALUE_EXIST;
        }
        if (clib_bihash_add_del_24_8 (&mapping->remote_ip4toip6, &kv, 1))
        {
            pool_put (mapping->mapping_entrys, mapping_entry);
            return VNET_API_ERROR_NO_SUCH_TABLE;
        }

        kv.key[0] = key64.as_u64[0];
        kv.key[1] = key64.as_u64[1];
        kv.key[2] = key64.as_u64[2];
        kv.value = mapping_entry - mapping->mapping_entrys;
        if (!clib_bihash_search_24_8 (&mapping->remote_ip6toip4, &kv, &value))
        {
            pool_put (mapping->mapping_entrys, mapping_entry);
            return VNET_API_ERROR_VALUE_EXIST;
        }
        if (clib_bihash_add_del_24_8 (&mapping->remote_ip6toip4, &kv, 1))
        {
            pool_put (mapping->mapping_entrys, mapping_entry);
            return VNET_API_ERROR_NO_SUCH_TABLE2;
        }
    }
    else
    {
        if (vrf_id != ~0)
            fib_index = fib_table_find(FIB_PROTOCOL_IP4, vrf_id);

        if(fib_index != ~0)
            fib_table_unlock (fib_index, FIB_PROTOCOL_IP4, FIB_SOURCE_PLUGIN_HI);

        key46.fib_index = fib_index;
        key64.fib_index = fib_index;

        kv.key[0] = key46.as_u64[0];
        kv.key[1] = key46.as_u64[1];
        kv.key[2] = key46.as_u64[2];

        if (!clib_bihash_search_24_8 (&mapping->remote_ip4toip6, &kv, &value))
        {
            value_index = value.value;
            clib_bihash_add_del_24_8 (&mapping->remote_ip4toip6, &kv, 0);
        }
        else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
        kv.key[0] = key64.as_u64[0];
        kv.key[1] = key64.as_u64[1];
        kv.key[2] = key64.as_u64[2];
        if (!clib_bihash_search_24_8 (&mapping->remote_ip6toip4, &kv, &value))
        {
            ASSERT(value_index == value.value);
            mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);
            pool_put (mapping->mapping_entrys, mapping_entry);
            clib_bihash_add_del_24_8 (&mapping->remote_ip6toip4, &kv, 0);
        }
        else
            return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
    return 0;
}



int
nat46_set_udp_timeout (u32 timeout)
{
  nat46_main_t *nm = &nat46_main;

  if (timeout == 0)
    nm->udp_timeout = SNAT_UDP_TIMEOUT;
  else
    nm->udp_timeout = timeout;

  return 0;
}

u32
nat46_get_udp_timeout (void)
{
  nat46_main_t *nm = &nat46_main;

  return nm->udp_timeout;
}

int
nat46_set_icmp_timeout (u32 timeout)
{
  nat46_main_t *nm = &nat46_main;

  if (timeout == 0)
    nm->icmp_timeout = SNAT_ICMP_TIMEOUT;
  else
    nm->icmp_timeout = timeout;

  return 0;
}

u32
nat46_get_icmp_timeout (void)
{
  nat46_main_t *nm = &nat46_main;

  return nm->icmp_timeout;
}

int
nat46_set_tcp_timeouts (u32 trans, u32 est)
{
  nat46_main_t *nm = &nat46_main;

  if (trans == 0)
    nm->tcp_trans_timeout = SNAT_TCP_TRANSITORY_TIMEOUT;
  else
    nm->tcp_trans_timeout = trans;

  if (est == 0)
    nm->tcp_est_timeout = SNAT_TCP_ESTABLISHED_TIMEOUT;
  else
    nm->tcp_est_timeout = est;

  return 0;
}

u32
nat46_get_tcp_trans_timeout (void)
{
  nat46_main_t *nm = &nat46_main;

  return nm->tcp_trans_timeout;
}

u32
nat46_get_tcp_est_timeout (void)
{
  nat46_main_t *nm = &nat46_main;

  return nm->tcp_est_timeout;
}

void
nat46_session_reset_timeout (nat46_db_st_entry_t * ste, vlib_main_t * vm)
{
  nat46_main_t *nm = &nat46_main;
  u32 now = (u32) vlib_time_now (vm);

  switch (ip_proto_to_snat_proto (ste->proto))
    {
    case SNAT_PROTOCOL_ICMP:
      ste->expire = now + nm->icmp_timeout;
      return;
    case SNAT_PROTOCOL_TCP:
      {
	switch (ste->tcp_state)
	  {
	  case NAT46_TCP_STATE_V4_INIT:
	  case NAT46_TCP_STATE_V6_INIT:
	  case NAT46_TCP_STATE_V4_FIN_RCV:
	  case NAT46_TCP_STATE_V6_FIN_RCV:
	  case NAT46_TCP_STATE_V6_FIN_V4_FIN_RCV:
	  case NAT46_TCP_STATE_TRANS:
	    ste->expire = now + nm->tcp_trans_timeout;
	    return;
	  case NAT46_TCP_STATE_ESTABLISHED:
	    ste->expire = now + nm->tcp_est_timeout;
	    return;
	  default:
	    return;
	  }
      }
    case SNAT_PROTOCOL_UDP:
      ste->expire = now + nm->udp_timeout;
      return;
    default:
      ste->expire = now + nm->udp_timeout;
      return;
    }
}

void
nat46_tcp_session_set_state (nat46_db_st_entry_t * ste, tcp_header_t * tcp, u8 is_ip6)
{
    switch (ste->tcp_state)
    {
    case NAT46_TCP_STATE_CLOSED:
        {
            if (tcp->flags & TCP_FLAG_SYN)
            {
                if (is_ip6)
                    ste->tcp_state = NAT46_TCP_STATE_V6_INIT;
                else
                    ste->tcp_state = NAT46_TCP_STATE_V4_INIT;
            }
            return;
        }
    case NAT46_TCP_STATE_V4_INIT:
        {
            if (is_ip6 && (tcp->flags & TCP_FLAG_SYN))
                ste->tcp_state = NAT46_TCP_STATE_ESTABLISHED;
            return;
        }
    case NAT46_TCP_STATE_V6_INIT:
        {
            if (!is_ip6 && (tcp->flags & TCP_FLAG_SYN))
                ste->tcp_state = NAT46_TCP_STATE_ESTABLISHED;
            return;
        }
    case NAT46_TCP_STATE_ESTABLISHED:
        {
            if (tcp->flags & TCP_FLAG_FIN)
            {
                if (is_ip6)
                    ste->tcp_state = NAT46_TCP_STATE_V6_FIN_RCV;
                else
                    ste->tcp_state = NAT46_TCP_STATE_V4_FIN_RCV;
            }
            else if (tcp->flags & TCP_FLAG_RST)
            {
                ste->tcp_state = NAT46_TCP_STATE_TRANS;
            }
            return;
        }
    case NAT46_TCP_STATE_V4_FIN_RCV:
        {
            if (is_ip6 && (tcp->flags & TCP_FLAG_FIN))
                ste->tcp_state = NAT46_TCP_STATE_V6_FIN_V4_FIN_RCV;
            return;
        }
    case NAT46_TCP_STATE_V6_FIN_RCV:
        {
            if (!is_ip6 && (tcp->flags & TCP_FLAG_FIN))
                ste->tcp_state = NAT46_TCP_STATE_V6_FIN_V4_FIN_RCV;
            return;
        }
    case NAT46_TCP_STATE_TRANS:
        {
            if (!(tcp->flags & TCP_FLAG_RST))
                ste->tcp_state = NAT46_TCP_STATE_ESTABLISHED;
            return;
        }
    default:
        return;
    }
}

static vlib_node_registration_t nat46_expire_walk_node;

/**
 * @brief Centralized process to drive per worker expire walk.
 */
static uword
nat46_expire_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		      vlib_frame_t * f)
{
  nat46_main_t *nm = &nat46_main;
  vlib_main_t **worker_vms = 0, *worker_vm;
  int i;
  uword event_type, *event_data = 0;

  nm->nat46_expire_walk_node_index = nat46_expire_walk_node.index;

  if (vec_len (vlib_mains) == 0)
    vec_add1 (worker_vms, vm);
  else
    {
      for (i = 0; i < vec_len (vlib_mains); i++)
	{
	  worker_vm = vlib_mains[i];
	  if (worker_vm)
	    vec_add1 (worker_vms, worker_vm);
	}
    }

  while (1)
    {
      if (nm->total_enabled_count)
	{
	  vlib_process_wait_for_event_or_clock (vm, nm->nat46_expire_walk_interval);
	  event_type = vlib_process_get_events (vm, &event_data);
	}
      else
	{
	  vlib_process_wait_for_event (vm);
	  event_type = vlib_process_get_events (vm, &event_data);
	}

      switch (event_type)
	{
	case ~0:
	  break;
	case NAT46_CLEANER_RESCHEDULE:
	  break;
	default:
	  nat_elog_notice_X1 ("unknown event %d", "i4", event_type);
	  break;
	}

      for (i = 0; i < vec_len (worker_vms); i++)
	{
	  worker_vm = worker_vms[i];
	  vlib_node_set_interrupt_pending (worker_vm,
					   nat46_expire_worker_walk_node.index);
	}
    }

  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_expire_walk_node, static) = {
    .function = nat46_expire_walk_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "nat46-expire-walk",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
