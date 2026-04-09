/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <lb/lb.h>
#include <lb/lb_ha_sync.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/ip6_to_ip4.h>

#include <vnet/gre/packet.h>
#include <lb/lbhash.h>

#define foreach_lb_error \
 _(NONE, "no error") \
 _(PROTO_NOT_SUPPORTED, "protocol not supported") \
 _(NAT46_NOT_SUPPORTED, "nat46 not supported") \
 _(IP6_FRAG_NOT_SUPPORTED, "ip6 frag not supported") \
 _(VIP_SNAT_NO_ADDRESS, "vip snat no address") \
 _(VIP_SNAT_OUT_OF_PORTS, "vip snat out of ports") \
 _(VIP_TYPE, "error vip type") 

typedef enum
{
#define _(sym,str) LB_ERROR_##sym,
  foreach_lb_error
#undef _
  LB_N_ERROR,
} lb_error_t;

static char *lb_error_strings[] =
  {
#define _(sym,string) string,
      foreach_lb_error
#undef _
    };

typedef struct
{
  u32 vip_index;
  u32 as_index;
} lb_trace_t;

typedef struct
{
  u32 vip_index;

  u32 node_port;
} lb_nodeport_trace_t;

typedef struct
{
  u32 vip_index;
  u32 as_index;
  u32 rx_sw_if_index;
  u32 next_index;
} lb_nat_trace_t;

typedef struct
{
  u32 rx_sw_if_index;
  u32 rx_fib_index;
  u32 vip_index;
  u32 vip_prefix_index;
  u32 next_index;
} lb_local_trace_t;

static u8 *
format_lb_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lb_trace_t *t = va_arg (*args, lb_trace_t *);
  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }
  if (pool_is_free_index(lbm->ass, t->as_index))
    {
      s = format (s, "lb as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "lb as[%d]: %U\n", t->as_index, format_lb_as,
                  &lbm->ass[t->as_index]);
    }
  return s;
}

static u8 *
format_lb_nat_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lb_nat_trace_t *t = va_arg (*args, lb_nat_trace_t *);

  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }
  if (pool_is_free_index(lbm->ass, t->as_index))
    {
      s = format (s, "lb as[%d]: This AS was freed since capture\n");
    }
  else
    {
      s = format (s, "lb as[%d]: %U\n", t->as_index, format_lb_as,
                  &lbm->ass[t->as_index]);
    }
  s = format (s, "lb nat: rx_sw_if_index = %d, next_index = %d",
              t->rx_sw_if_index, t->next_index);

  return s;
}

static u8 *
format_lb_local_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lb_local_trace_t *t = va_arg (*args, lb_local_trace_t *);

  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }

  s = format (s, "lb vip[%d]: vip_prefix_index %u\n", t->vip_index, t->vip_prefix_index);


  s = format (s, "lb local: rx_sw_if_index = %d, next_index = %d", t->rx_sw_if_index, t->next_index);

  return s;
}

static_always_inline u32
lb_get_ip4_protocol_timeout(vlib_main_t *vm, vlib_buffer_t *b, ip4_header_t *ip4)
{
    lb_main_t *lbm = &lb_main;

    if (ip4->protocol != IP_PROTOCOL_TCP)
    {
        return lbm->flow_timeout;
    }

    tcp_header_t *th = (tcp_header_t *) (ip4 + 1);

    if (tcp_rst(th))
    {
        return 1;
    }
    else if (tcp_fin(th))
    {
        return lbm->flow_tcp_closing_timeout;
    }

    return lbm->flow_tcp_transitory_timeout;
}

static_always_inline u32
lb_get_ip6_protocol_timeout(vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip6)
{
    lb_main_t *lbm = &lb_main;

    u8 l4_protocol;
    u16 l4_offset, frag_hdr_offset;

    if (PREDICT_FALSE (ip6_parse (vm, b, ip6, b->current_length,
                       &l4_protocol, &l4_offset, &frag_hdr_offset)))
    {
        return lbm->flow_timeout;
    }

    if (PREDICT_FALSE(frag_hdr_offset))
    {
        return lbm->flow_timeout;
    }

    if (l4_protocol != IP_PROTOCOL_TCP)
    {
        return lbm->flow_timeout;
    }

    tcp_header_t *th = (tcp_header_t *) u8_ptr_add (ip6, l4_offset);

    if (tcp_rst(th))
    {
        return 0;
    }
    else if (tcp_fin(th))
    {
        return lbm->flow_tcp_closing_timeout;
    }

    return lbm->flow_tcp_transitory_timeout;
}

static_always_inline u64
lb_node_get_other_ports4 (ip4_header_t *ip40)
{
  return 0;
}

static_always_inline u64
lb_node_get_other_ports6 (ip6_header_t *ip60)
{
  return 0;
}

static_always_inline u16
lb_snat_random_port (u16 min, u16 max)
{
  lb_main_t *lbm = &lb_main;
  u32 rwide;
  u16 r;

  rwide = random_u32 (&lbm->random_seed);
  r = rwide & 0xFFFF;
  if (r >= min && r <= max)
    return r;

  return min + (rwide % (max - min + 1));
}

static_always_inline u8
lb_vip_snat_alloc_recycle_address_port(vlib_main_t * vm,
                                       lb_main_t *lbm,
                                       lb_vip_snat_addresses_pool_t *snat_addresses,
                                       u8 proto,
                                       ip4_address_t *new_addr,
                                       u16 *new_port,
                                       u32 flow_index, 
                                       u32 lb_time_now)
{
    u16 portnum;
    lb_vip_snat_address_t *address = NULL;
    lb_vip_snat_mapping_t *record_flow = NULL;

    u32 lb_proto = lb_ip_proto_to_nat_proto(proto);

    /**
     * number of attempts to get a port for overloading algorithm, if rolling
     * a dice this many times doesn't produce a free port, it's treated
     * as if there were no free ports available to conserve resources 
     * */
    u32 attempts = 20;
    clib_bihash_kv_16_8_t kv;
    lb_snat_vip_key_t key;

    //Prioritize the use of addresses with remaining ports
    vec_foreach(address, snat_addresses->addresses)
    {
        lb_get_vip_nat_address_lock(address);
        if (address->busy_ports[lb_proto] < 0xfbff) //65535 - 1024
        {
            while (1)
            {
                portnum = lb_snat_random_port (1024, 0xffff);
                if (clib_bitmap_get (address->busy_port_bitmap[lb_proto], portnum))
                {
                    continue;
                }
                else
                {
                    address->busy_port_bitmap[lb_proto] = 
                        clib_bitmap_set (address->busy_port_bitmap[lb_proto], portnum, 1);
                    address->busy_ports[lb_proto]++;
                }

                address->flow_index[lb_proto][portnum] = flow_index;

                *new_addr = address->addr;
                *new_port = clib_host_to_net_u16 (portnum);

                lb_put_vip_nat_address_lock(address);

                return 0;
            }
        }
        lb_put_vip_nat_address_lock(address);
    }

    //If all ports of the address have been used, check timeout and free it
    vec_foreach(address, snat_addresses->addresses)
    {
        lb_get_vip_nat_address_lock(address);
        do {
            portnum = lb_snat_random_port (1024, 0xffff);
            if (clib_bitmap_get (address->busy_port_bitmap[lb_proto], portnum))
            {
                //check timeout
                record_flow = pool_elt_at_index(lbm->vip_snat_mappings, address->flow_index[lb_proto][portnum]);
                if (clib_u32_loop_gt(lb_time_now, record_flow->timeout))
                {
                    /**
                     * Timeouted :
                     *  1. free record_flow
                     *  2. recycle this address and portnum 
                     */
                    clib_memset(&key, 0, sizeof(key));

                    //remove entry by table
                    key.addr.as_u32 = record_flow->ip.ip4.as_u32;
                    key.port = record_flow->port;
                    key.protocol = proto;
                    key.fib_index = record_flow->fib_index;

                    kv.key[0] = key.as_u64[0];
                    kv.key[1] = key.as_u64[1];

                    if (clib_bihash_add_del_16_8 (&lbm->mapping_by_uplink_dnat4, &kv, 0))
                    {
                        clib_warning ("Lb vip-snat as-mapping dnat4 table del failed");
                    }

                    key.addr.as_u32 = record_flow->outside_ip.ip4.as_u32;
                    key.port = record_flow->outside_port;
                    key.protocol = proto;
                    key.fib_index = record_flow->outside_fib_index;

                    kv.key[0] = key.as_u64[0];
                    kv.key[1] = key.as_u64[1];

                    if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv, 0))
                    {
                        clib_warning ("Lb vip-snat vip-mapping snat4 table del failed");
                    }

                    //ha sync notify
                    lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_DEL_FORCE,
                                                             pool_elt_at_index(lbm->vips, record_flow->vip_index),
                                                             record_flow, 0);

                    address->flow_index[lb_proto][portnum] = flow_index;

                    *new_addr = address->addr;
                    *new_port = clib_host_to_net_u16 (portnum);

                    lb_put_vip_nat_address_lock(address);

                    lb_get_writer_lock();
                    pool_put(lbm->vip_snat_mappings, record_flow);
                    lb_put_writer_lock();
                    return 0;
                }
            }
            else
            {
                address->busy_port_bitmap[lb_proto] = 
                    clib_bitmap_set (address->busy_port_bitmap[lb_proto], portnum, 1);
                address->busy_ports[lb_proto]++;

                address->flow_index[lb_proto][portnum] = flow_index;

                *new_addr = address->addr;
                *new_port = clib_host_to_net_u16 (portnum);

                lb_put_vip_nat_address_lock(address);
                return 0;
            }
            --attempts;
        } while (attempts > 0);

        lb_put_vip_nat_address_lock(address);
    }
    return 1;
}

static_always_inline void
lb_node_get_hash (lb_main_t *lbm, vlib_buffer_t *p, u8 is_input_v4, u32 *hash,
		  u32 *vip_index, u8 per_port_vip)
{
  vip_port_key_t key;
  clib_bihash_kv_16_8_t kv, value;
  ip4_header_t *ip40;
  ip6_header_t *ip60;
  lb_vip_t *vip0;
  u64 ports;
  u32 fib_index;

  /**
   * For vip case, retrieve vip index for ip lookup 
   * By no per port vip :  ip.adj_index is vip_index
   * By per port vip : ip.adj_index is key field by vip_index_per_port
   */
  *vip_index = vnet_buffer (p)->ip.adj_index[VLIB_TX];
  fib_index = vnet_buffer (p)->ip.fib_index;

  /* Extract the L4 port number from the packet */
  if (is_input_v4)
    {
      ip40 = vlib_buffer_get_current (p);
      if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_TCP || 
                       ip40->protocol == IP_PROTOCOL_UDP))
          ports = ((u64) ((udp_header_t *) (ip40 + 1))->src_port << 16)
              | ((u64) ((udp_header_t *) (ip40 + 1))->dst_port);
      else
          ports = lb_node_get_other_ports4 (ip40);
    }
  else
    {
      ip60 = vlib_buffer_get_current (p);

      if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_TCP || 
                       ip60->protocol == IP_PROTOCOL_UDP))
          ports = ((u64) ((udp_header_t *) (ip60 + 1))->src_port << 16)
              | ((u64) ((udp_header_t *) (ip60 + 1))->dst_port);
      else
        ports = lb_node_get_other_ports6 (ip60);
    }

  if (per_port_vip)
    {
      /* For per-port-vip case, ip lookup stores placeholder index */
      clib_memset(&key, 0, sizeof(key));
      key.vip_prefix_index = *vip_index;
      key.port = (u16) (ports & 0xFFFF);
      key.fib_index = fib_index;
      if (is_input_v4)
	{
	  key.protocol = ip40->protocol;
	}
      else
	{
	  key.protocol = ip60->protocol;
	}

      /* For per-port-vip case, retrieve vip index for vip_port_filter table */
      kv.key[0] = key.as_u64[0];
      kv.key[1] = key.as_u64[1];
      if (clib_bihash_search_16_8 (&lbm->vip_index_per_port, &kv, &value) < 0)
	{
	  /* Set default vip */
	  *vip_index = 0;
	}
      else
	{
	  *vip_index = value.value;
	}
    }

  vip0 = pool_elt_at_index (lbm->vips, *vip_index);

  if (is_input_v4)
    {
      if (lb_vip_is_src_ip_sticky (vip0))
	{
	  *hash = lb_hash_hash (*((u64 *) &ip40->address_pair), 0, 0, 0, 0);
	}
      else
	{
	  *hash =
	    lb_hash_hash (*((u64 *) &ip40->address_pair), ports, 0, 0, 0);
	}
    }
  else
    {
      if (lb_vip_is_src_ip_sticky (vip0))
	{
	  *hash = lb_hash_hash (
	    ip60->src_address.as_u64[0], ip60->src_address.as_u64[1],
	    ip60->dst_address.as_u64[0], ip60->dst_address.as_u64[1], 0);
	}
      else
	{
	  *hash = lb_hash_hash (
	    ip60->src_address.as_u64[0], ip60->src_address.as_u64[1],
	    ip60->dst_address.as_u64[0], ip60->dst_address.as_u64[1], ports);
	}
    }
}

static_always_inline u8 
lb_node_encap_gre(vlib_main_t * vm, 
                  lb_main_t *lbm, 
                  vlib_buffer_t *p, 
                  u8 is_input_v4, 
                  u16 len, 
                  lb_encap_type_t encap_type, 
                  lb_vip_t *vip, u32 asindex)
{
    gre_header_t *gre;
    if (encap_type == LB_ENCAP_TYPE_GRE4) /* encap GRE4*/
    {
        if (vip->type != LB_VIP_TYPE_IP4_GRE4 && vip->type != LB_VIP_TYPE_IP6_GRE4)
        {
            return LB_ERROR_VIP_TYPE;
        }
        ip4_header_t *ip4;
        vlib_buffer_advance (p, -sizeof(ip4_header_t) - sizeof(gre_header_t));
        ip4 = vlib_buffer_get_current (p);
        gre = (gre_header_t *) (ip4 + 1);
        ip4->src_address = lbm->ip4_src_address;
        ip4->dst_address = lbm->ass[asindex].address.ip4;
        ip4->ip_version_and_header_length = 0x45;
        ip4->ttl = 128;
        ip4->fragment_id = 0;
        ip4->flags_and_fragment_offset = 0;
        ip4->length = clib_host_to_net_u16 (len + sizeof(gre_header_t) + sizeof(ip4_header_t));
        ip4->protocol = IP_PROTOCOL_GRE;
        ip4->checksum = ip4_header_checksum (ip4);
    }
    else /* encap GRE6*/
    {
        if (vip->type != LB_VIP_TYPE_IP4_GRE6 && vip->type != LB_VIP_TYPE_IP6_GRE6)
        {
            return LB_ERROR_VIP_TYPE;
        }
        ip6_header_t *ip6;
        vlib_buffer_advance (p, -sizeof(ip6_header_t) - sizeof(gre_header_t));
        ip6 = vlib_buffer_get_current (p);
        gre = (gre_header_t *) (ip6 + 1);
        ip6->dst_address = lbm->ass[asindex].address.ip6;
        ip6->src_address = lbm->ip6_src_address;
        ip6->hop_limit = 128;
        ip6->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
        ip6->payload_length = clib_host_to_net_u16 (len + sizeof(gre_header_t));
        ip6->protocol = IP_PROTOCOL_GRE;
    }

    gre->flags_and_version = 0;
    gre->protocol = (is_input_v4) ?
        clib_host_to_net_u16 (0x0800):
        clib_host_to_net_u16 (0x86DD);

    return LB_ERROR_NONE;
}

static_always_inline u8 
lb_node_encap_l3dsr(vlib_main_t * vm,
                    lb_main_t *lbm,
                    vlib_buffer_t *p,
                    u8 is_input_v4,
                    lb_vip_t *vip, u32 asindex)
{
    ip4_header_t *ip4;
    ip_csum_t csum;
    u32 old_dst, new_dst;
    u8 old_tos, new_tos;

    if (vip->type != LB_VIP_TYPE_IP4_L3DSR || !is_input_v4)
    {
        return LB_ERROR_VIP_TYPE;
    }

    ip4 = vlib_buffer_get_current (p);
    old_dst = ip4->dst_address.as_u32;
    new_dst = lbm->ass[asindex].address.ip4.as_u32;
    ip4->dst_address.as_u32 = lbm->ass[asindex].address.ip4.as_u32;

    /* Get and rewrite DSCP bit */
    old_tos = ip4->tos;
    new_tos = (u8) ((vip->encap_args.dscp & 0x3F) << 2);
    ip4->tos = (u8) ((vip->encap_args.dscp & 0x3F) << 2);

    csum = ip4->checksum;
    csum = ip_csum_update (csum, old_tos, new_tos, ip4_header_t, tos /* changed member */);
    csum = ip_csum_update (csum, old_dst, new_dst, ip4_header_t, dst_address /* changed member */);
    ip4->checksum = ip_csum_fold (csum);

    /* Recomputing L4 checksum after dst-IP modifying */
    if (ip4->protocol == IP_PROTOCOL_TCP)
    {
        tcp_header_t *th;
        th = ip4_next_header (ip4);
        th->checksum = 0;
        th->checksum = ip4_tcp_udp_compute_checksum (vm, p, ip4);
    }
    else if (ip4->protocol == IP_PROTOCOL_UDP)
    {
        udp_header_t *uh;
        uh = ip4_next_header (ip4);
        uh->checksum = 0;
        uh->checksum = ip4_tcp_udp_compute_checksum (vm, p, ip4);
    }

    return LB_ERROR_NONE;
}

static_always_inline u8 lb_node_encap_nat(vlib_main_t * vm,
                                          lb_main_t *lbm, 
                                          vlib_buffer_t *p, 
                                          u8 is_input_v4,
                                          lb_encap_type_t encap_type, 
                                          lb_vip_t *vip, u32 asindex) 
{
    ip_csum_t csum;
    udp_header_t *uh;
    tcp_header_t *th;

    /* do NAT */
    if ((is_input_v4 == 1) && (encap_type == LB_ENCAP_TYPE_NAT4))
    {
        if (vip->type != LB_VIP_TYPE_IP4_NAT4)
        {
            return LB_ERROR_VIP_TYPE;
        }

        /* NAT44 */
        ip4_header_t *ip4;
        u32 old_dst;
        u16 old_dst_port;
        ip4 = vlib_buffer_get_current (p);
        uh = (udp_header_t *) (ip4 + 1);
        th = (tcp_header_t *) (ip4 + 1);
        old_dst = ip4->dst_address.as_u32;
        ip4->dst_address = lbm->ass[asindex].address.ip4;

        csum = ip4->checksum;
        csum = ip_csum_sub_even (csum, old_dst);
        csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip4.as_u32);
        ip4->checksum = ip_csum_fold (csum);

        if (ip4->protocol == IP_PROTOCOL_UDP)
        {
            old_dst_port = uh->dst_port;
            uh->dst_port = vip->encap_args.target_port;
            if (PREDICT_FALSE (uh->checksum))
            {
                csum = uh->checksum;
                csum = ip_csum_sub_even (csum, old_dst);
                csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip4.as_u32);
                csum = ip_csum_sub_even (csum, old_dst_port);
                csum = ip_csum_add_even (csum, vip->encap_args.target_port);
                uh->checksum = ip_csum_fold (csum);
            }
        }
        else if (ip4->protocol == IP_PROTOCOL_TCP)
        {
            old_dst_port = th->dst_port;
            th->dst_port = vip->encap_args.target_port;
            csum = th->checksum;
            csum = ip_csum_sub_even (csum, old_dst);
            csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip4.as_u32);
            csum = ip_csum_sub_even (csum, old_dst_port);
            csum = ip_csum_add_even (csum, vip->encap_args.target_port);
            th->checksum = ip_csum_fold (csum);
        }
        else
        {
            return LB_ERROR_PROTO_NOT_SUPPORTED;
        }
    }
    else if ((is_input_v4 == 0) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        if (vip->type != LB_VIP_TYPE_IP6_NAT6)
        {
            return LB_ERROR_VIP_TYPE;
        }

        /* NAT66 */
        ip6_header_t *ip6;
        ip6_address_t old_dst;
        u16 old_dst_port;
        u8 l4_protocol;
        u16 l4_offset, frag_hdr_offset;

        ip6 = vlib_buffer_get_current (p);

        if (PREDICT_FALSE (ip6_parse (vm, p, ip6, p->current_length,
                           &l4_protocol, &l4_offset, &frag_hdr_offset)))
        {
            return LB_ERROR_PROTO_NOT_SUPPORTED;
        }

        if (PREDICT_FALSE(frag_hdr_offset))
        {
            return LB_ERROR_IP6_FRAG_NOT_SUPPORTED;
        }

        uh = (udp_header_t *) u8_ptr_add (ip6, l4_offset);
        th = (tcp_header_t *) u8_ptr_add (ip6, l4_offset);

        old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
        old_dst.as_u64[1] = ip6->dst_address.as_u64[1];
        ip6->dst_address.as_u64[0] = lbm->ass[asindex].address.ip6.as_u64[0];
        ip6->dst_address.as_u64[1] = lbm->ass[asindex].address.ip6.as_u64[1];

        if (PREDICT_TRUE(l4_protocol == IP_PROTOCOL_UDP))
        {
            old_dst_port = uh->dst_port;
            uh->dst_port = vip->encap_args.target_port;
            if (PREDICT_FALSE (uh->checksum))
            {
                csum = uh->checksum;
                csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
                csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
                csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip6.as_u64[0]);
                csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip6.as_u64[1]);
                csum = ip_csum_sub_even (csum, old_dst_port);
                csum = ip_csum_add_even (csum, vip->encap_args.target_port);
                uh->checksum = ip_csum_fold (csum);
            }
        }
        else if (PREDICT_TRUE(l4_protocol == IP_PROTOCOL_TCP))
        {
            old_dst_port = th->dst_port;
            th->dst_port = vip->encap_args.target_port;
            csum = th->checksum;
            csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
            csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
            csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip6.as_u64[0]);
            csum = ip_csum_add_even (csum, lbm->ass[asindex].address.ip6.as_u64[1]);
            csum = ip_csum_sub_even (csum, old_dst_port);
            csum = ip_csum_add_even (csum, vip->encap_args.target_port);
            th->checksum = ip_csum_fold (csum);
        }
        else
        {
            return LB_ERROR_PROTO_NOT_SUPPORTED;
        }
    }
    else if ((is_input_v4 == 0) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        if (vip->type != LB_VIP_TYPE_IP6_NAT4)
        {
            return LB_ERROR_VIP_TYPE;
        }
        /* NAT64 Plan support*/
        //TODO
        return LB_ERROR_PROTO_NOT_SUPPORTED;
    }
    else if ((is_input_v4 == 1) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        /* NAT46 No planned support*/
        return LB_ERROR_NAT46_NOT_SUPPORTED;
    }

    return LB_ERROR_NONE;
}

static_always_inline u8 lb_node_encap_nat_vip_snat(vlib_main_t * vm,
                                          lb_main_t *lbm, 
                                          vlib_buffer_t *p, 
                                          u8 is_input_v4,
                                          lb_encap_type_t encap_type, 
                                          lb_vip_t *vip, u32 asindex, 
                                          u32 lb_time_now, u32 timeout)
{
    ip_csum_t csum;
    udp_header_t *uh;
    tcp_header_t *th;

    /* do NAT */
    if ((is_input_v4 == 1) && (encap_type == LB_ENCAP_TYPE_NAT4))
    {
        if (vip->type != LB_VIP_TYPE_IP4_NAT4)
        {
            return LB_ERROR_VIP_TYPE;
        }

        /* NAT44 */
        ip4_header_t *ip4;
        u32 old_src;
        u16 old_src_port;

        ip4_address_t new_addr;
        u16 new_port;

        lb_vip_snat_addresses_pool_t *snat_addresses = NULL;
        lb_vip_snat_mapping_t *flow = NULL;
        u32 flow_index;
        clib_bihash_kv_16_8_t kv, value;
        lb_snat_vip_key_t key;

        ip4 = vlib_buffer_get_current (p);

        if (ip4->protocol != IP_PROTOCOL_UDP && 
            ip4->protocol != IP_PROTOCOL_TCP)
        {
            return LB_ERROR_PROTO_NOT_SUPPORTED;
        }

        old_src = ip4->src_address.as_u32;

        uh = (udp_header_t *) (ip4 + 1);
        old_src_port = uh->src_port;

        //find mapping_by_downlink_snat4 
        clib_memset(&key, 0, sizeof(key));
        key.addr.as_u32 = old_src;
        key.port = old_src_port;
        key.protocol = ip4->protocol;
        key.fib_index = vip->fib_index;

        kv.key[0] = key.as_u64[0];
        kv.key[1] = key.as_u64[1];

        if (clib_bihash_search_16_8 (&lbm->mapping_by_downlink_snat4, &kv, &value))
        {
            /* Try to alloc and recycle dynamic translation*/
            snat_addresses = pool_elt_at_index(lbm->vip_snat_pool, vip->vip_snat_pool_index);
            if (!vec_len (snat_addresses->addresses))
            {
                return LB_ERROR_VIP_SNAT_NO_ADDRESS;
            }

            //per alloc flow entry
            lb_get_writer_lock();

            pool_get_zero(lbm->vip_snat_mappings, flow);

            lb_put_writer_lock();

            flow_index = flow - lbm->vip_snat_mappings;

            if(lb_vip_snat_alloc_recycle_address_port(vm, lbm, snat_addresses, ip4->protocol, &new_addr, &new_port, flow_index, lb_time_now))
            {
                lb_get_writer_lock();

                pool_get_zero(lbm->vip_snat_mappings, flow);

                lb_put_writer_lock();
                return LB_ERROR_VIP_SNAT_OUT_OF_PORTS;
            }

            flow->ip.ip4 = new_addr;
            flow->outside_ip.ip4 = ip4->src_address;
            flow->port = new_port;
            flow->outside_port = old_src_port;
            flow->fib_index = lbm->ass[asindex].fib_index;
            flow->outside_fib_index = vip->fib_index;
            flow->protocol = ip4->protocol;
            flow->vip_index = vip - lbm->vips;
            flow->timeout = lb_time_now + timeout;
            flow->last_ha_sync_timeout = lb_time_now;

            kv.value = flow_index;
            //add flow to mapping downlink snat4 table
            if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv, 1))
                clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");

            //add flow to mapping uplink dnat4 table
            key.addr.as_u32 = new_addr.as_u32;
            key.port = new_port;
            key.protocol = ip4->protocol;
            key.fib_index = lbm->ass[asindex].fib_index;

            kv.key[0] = key.as_u64[0];
            kv.key[1] = key.as_u64[1];

            if (clib_bihash_add_del_16_8 (&lbm->mapping_by_uplink_dnat4, &kv, 1))
                clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");

            //ha sync notify
            lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_ADD_FORCE,
                                                     vip, flow, timeout);
        }
        else
        {
            flow = pool_elt_at_index (lbm->vip_snat_mappings, value.value);

            if (lb_time_now - flow->last_ha_sync_timeout >
                lb_ha_sync_ctx.ha_sync_timeout_update_interval)
            {
                lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                        vip, flow, timeout);
                flow->last_ha_sync_timeout = lb_time_now;
            }

            flow->timeout = lb_time_now + timeout;
        }

        ip4->src_address = flow->ip.ip4;
        csum = ip4->checksum;
        csum = ip_csum_sub_even (csum, old_src);
        csum = ip_csum_add_even (csum, flow->ip.ip4.as_u32);
        ip4->checksum = ip_csum_fold (csum);

        if (ip4->protocol == IP_PROTOCOL_UDP)
        {
            uh->src_port = flow->port;
            if (PREDICT_FALSE (uh->checksum))
            {
                csum = uh->checksum;
                csum = ip_csum_sub_even (csum, old_src);
                csum = ip_csum_add_even (csum, flow->ip.ip4.as_u32);
                csum = ip_csum_sub_even (csum, old_src_port);
                csum = ip_csum_add_even (csum, flow->port);
                uh->checksum = ip_csum_fold (csum);
            }
        }
        else if (ip4->protocol == IP_PROTOCOL_TCP)
        {
            th = (tcp_header_t *) (uh);
            th->src_port = flow->port;
            csum = th->checksum;
            csum = ip_csum_sub_even (csum, old_src);
            csum = ip_csum_add_even (csum, flow->ip.ip4.as_u32);
            csum = ip_csum_sub_even (csum, old_src_port);
            csum = ip_csum_add_even (csum, flow->port);
            th->checksum = ip_csum_fold (csum);
        }
    }
    else if ((is_input_v4 == 0) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        if (vip->type != LB_VIP_TYPE_IP6_NAT4)
        {
            return LB_ERROR_VIP_TYPE;
        }
        /* NAT64 Plan support*/
        //TODO
        return LB_ERROR_PROTO_NOT_SUPPORTED;
    }
    else if ((is_input_v4 == 1) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        /* NAT46 No planned support double nat*/
        return LB_ERROR_NAT46_NOT_SUPPORTED;
    }
    else if ((is_input_v4 == 0) && (encap_type == LB_ENCAP_TYPE_NAT6))
    {
        /* NAT66 No planned support double nat*/
        return LB_ERROR_NAT46_NOT_SUPPORTED;
    }
    return LB_ERROR_NONE;
}

/* clang-format off */
static_always_inline uword
lb_node_fn (vlib_main_t * vm,
            vlib_node_runtime_t * node,
            vlib_frame_t * frame,
            u8 is_input_v4, //Compile-time parameter stating that is input is v4 (or v6)
            lb_encap_type_t encap_type, //Compile-time parameter is GRE4/GRE6/L3DSR/NAT4/NAT6
            u8 per_port_vip) //Compile-time parameter stating that is per_port_vip or not
{
  lb_main_t *lbm = &lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 thread_index = vm->thread_index;
  u32 lb_time = lb_hash_time_now (vm);

  clib_bihash_8_16_t *sticky_ht = &lbm->sticky_ht;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 nexthash0 = 0;
  u32 next_vip_idx0 = ~0;
  u64 next_sticky_hash0 = 0;
  lb_sticky_kv_t next_kv0;
  if (PREDICT_TRUE(n_left_from > 0))
    {
      vlib_buffer_t *p0 = vlib_get_buffer (vm, from[0]);
      lb_node_get_hash (lbm, p0, is_input_v4, &nexthash0,
                        &next_vip_idx0, per_port_vip);

      next_kv0.lb_key.hash = nexthash0;
      next_kv0.lb_key.vip_index = next_vip_idx0;
      next_sticky_hash0 = clib_bihash_hash_8_16((clib_bihash_kv_8_16_t *)&next_kv0);
    }

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);
      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0;
          vlib_buffer_t *p0;
          lb_vip_t *vip0;
          u8 error = LB_ERROR_NONE;
          u32 asindex0 = 0;
          u16 len0;
          u8 counter = 0;
          u32 hash0 = nexthash0;
          u32 vip_index0 = next_vip_idx0;
          u32 timeout0 = lbm->flow_timeout;
          u64 sticky_hash0 = 0;
          lb_sticky_kv_t k0;
          lb_sticky_kv_t v0;
          u32 next0;

          k0.lb_key.hash = hash0;
          k0.lb_key.vip_index = vip_index0;
          sticky_hash0 = clib_bihash_hash_8_16((clib_bihash_kv_8_16_t *)&k0);

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Compute next hash and prefetch bucket
              lb_node_get_hash (lbm, p1, is_input_v4,
                                &nexthash0, &next_vip_idx0,
                                per_port_vip);

              next_kv0.lb_key.hash = nexthash0;
              next_kv0.lb_key.vip_index = next_vip_idx0;
              next_sticky_hash0 = clib_bihash_hash_8_16((clib_bihash_kv_8_16_t *)&next_kv0);
              clib_bihash_prefetch_bucket_8_16 (sticky_ht, next_sticky_hash0);
              //Prefetch for encap, next
              CLIB_PREFETCH(vlib_buffer_get_current (p1) - 64, 64, STORE);
            }

          if (PREDICT_TRUE(n_left_from > 2))
            {
              vlib_buffer_t *p2;
              p2 = vlib_get_buffer (vm, from[2]);
              /* prefetch packet header and data */
              vlib_prefetch_buffer_header(p2, STORE);
              CLIB_PREFETCH(vlib_buffer_get_current (p2), 64, STORE);
            }

          pi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          vip0 = pool_elt_at_index(lbm->vips, vip_index0);

          if (is_input_v4)
            {
              ip4_header_t *ip40;
              ip40 = vlib_buffer_get_current (p0);
              len0 = clib_net_to_host_u16 (ip40->length);
              timeout0 = lb_get_ip4_protocol_timeout(vm, p0, ip40);
            }
          else
            {
              ip6_header_t *ip60;
              ip60 = vlib_buffer_get_current (p0);
              len0 = clib_net_to_host_u16 (ip60->payload_length)
                  + sizeof(ip6_header_t);
              timeout0 = lb_get_ip6_protocol_timeout(vm, p0, ip60);
            }

          if (!clib_bihash_search_inline_2_with_hash_8_16(sticky_ht, sticky_hash0, (clib_bihash_kv_8_16_t *)&k0, (clib_bihash_kv_8_16_t *)&v0))
          {
              counter = LB_VIP_COUNTER_NEXT_PACKET;
              asindex0 = v0.lb_value.asindex;

              if (lb_time - v0.lb_value.last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_sticky_session_notify(thread_index, LB_HA_OP_UPDATE,
                                                         vip0, hash0,
                                                         &lbm->ass[asindex0].address, timeout0);
                  v0.lb_value.last_ha_sync_timeout = lb_time;
              }

              //update timeout
              v0.lb_value.timeout = lb_time + timeout0;

              //update sticky
              clib_bihash_add_del_with_hash_8_16(sticky_ht, (clib_bihash_kv_8_16_t *)&v0, sticky_hash0, 1);
          }
          else
          {
              asindex0 = vip0->new_flow_table[hash0 & vip0->new_flow_table_mask].as_index;
              counter = LB_VIP_COUNTER_FIRST_PACKET;
              counter = (asindex0 == 0) ? LB_VIP_COUNTER_NO_SERVER : counter;

              k0.lb_value.timeout = lb_time + timeout0;
              k0.lb_value.asindex = asindex0;
              k0.lb_value.last_ha_sync_timeout = lb_time;

              lb_sticky_is_idle_ctx_t ctx;
              ctx.lb_time_now = lb_time;
              ctx.thread_index = thread_index;

              if (clib_bihash_add_or_overwrite_stale_8_16 (
                          sticky_ht, (clib_bihash_kv_8_16_t * )&k0,
                          lb_sticky_is_idle_cb, &ctx))
              {
                  counter = LB_VIP_COUNTER_UNTRACKED_PACKET;
              }
              else
              {
                  //ha sync notify
                  lb_ha_sync_event_sticky_session_notify(thread_index, LB_HA_OP_ADD_FORCE,
                                                         vip0, hash0,
                                                         &lbm->ass[asindex0].address, timeout0);

                  clib_atomic_fetch_add (&lbm->as_refcount[asindex0], 1);
              }
          }

          vlib_increment_simple_counter (
              &lbm->vip_counters[counter], thread_index,
              vip_index0,
              1);

          //Now let's encap
          if ((encap_type == LB_ENCAP_TYPE_GRE4) || (encap_type == LB_ENCAP_TYPE_GRE6))
            {
                error = lb_node_encap_gre(vm, lbm, p0, is_input_v4, len0, encap_type, vip0, asindex0);
                if (error != LB_ERROR_NONE)
                {
                    asindex0 = 0;
                    p0->error = node->errors[error];
                }
            }
          else if (encap_type == LB_ENCAP_TYPE_L3DSR) /* encap L3DSR*/
            {
                error = lb_node_encap_l3dsr(vm, lbm, p0, is_input_v4, vip0, asindex0);
                if (error != LB_ERROR_NONE)
                {
                    asindex0 = 0;
                    p0->error = node->errors[error];
                }
            }
          else if ((encap_type == LB_ENCAP_TYPE_NAT4) || (encap_type == LB_ENCAP_TYPE_NAT6))
            {
                error = lb_node_encap_nat(vm, lbm, p0, is_input_v4, encap_type, vip0, asindex0);
                if (error != LB_ERROR_NONE)
                {
                    asindex0 = 0;
                    p0->error = node->errors[error];
                }

                if (error == LB_ERROR_NONE && lb_vip_is_double_nat44(vip0))
                {
                    error = lb_node_encap_nat_vip_snat(vm, lbm, p0, is_input_v4, encap_type, vip0, asindex0, lb_time, timeout0);
                    if (error != LB_ERROR_NONE)
                    {
                        asindex0 = 0;
                        p0->error = node->errors[error];
                    }
                }
            }
          next0 = lbm->ass[asindex0].dpo.dpoi_next_node;
          //Note that this is going to error if asindex0 == 0
          vnet_buffer (p0)->ip.adj_index[VLIB_TX] =
              lbm->ass[asindex0].dpo.dpoi_index;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lb_trace_t *tr = vlib_add_trace (vm, node, p0, sizeof(*tr));
              tr->as_index = asindex0;
              tr->vip_index = vip_index0;
            }

          //Enqueue to next
          vlib_validate_buffer_enqueue_x1(
              vm, node, next_index, to_next, n_left_to_next, pi0, next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}
/* clang-format on */

static u8 *
format_nodeport_lb_trace (u8 * s, va_list * args)
{
  lb_main_t *lbm = &lb_main;
  CLIB_UNUSED(vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED(vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  lb_nodeport_trace_t *t = va_arg (*args, lb_nodeport_trace_t *);
  if (pool_is_free_index(lbm->vips, t->vip_index))
    {
      s = format (s, "lb vip[%d]: This VIP was freed since capture\n");
    }
  else
    {
      s = format (s, "lb vip[%d]: %U\n", t->vip_index, format_lb_vip,
                  &lbm->vips[t->vip_index]);
    }

  s = format (s, "  lb node_port: %d", t->node_port);

  return s;
}

static uword
lb_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                     vlib_frame_t * frame, u8 is_input_v4)
{
  lb_main_t *lbm = &lb_main;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 pi0;
          vlib_buffer_t *p0;
          udp_header_t * udp_0;
          uword * entry0;

          if (PREDICT_TRUE(n_left_from > 1))
            {
              vlib_buffer_t *p1 = vlib_get_buffer (vm, from[1]);
              //Prefetch for encap, next
              CLIB_PREFETCH(vlib_buffer_get_current (p1) - 64, 64, STORE);
            }

          if (PREDICT_TRUE(n_left_from > 2))
            {
              vlib_buffer_t *p2;
              p2 = vlib_get_buffer (vm, from[2]);
              /* prefetch packet header and data */
              vlib_prefetch_buffer_header(p2, STORE);
              CLIB_PREFETCH(vlib_buffer_get_current (p2), 64, STORE);
            }

          pi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;

          p0 = vlib_get_buffer (vm, pi0);

          if (is_input_v4)
            {
              ip4_header_t *ip40;
              vlib_buffer_advance (
                  p0, -(word) (sizeof(udp_header_t) + sizeof(ip4_header_t)));
              ip40 = vlib_buffer_get_current (p0);
              udp_0 = (udp_header_t *) (ip40 + 1);
            }
          else
            {
              ip6_header_t *ip60;
              vlib_buffer_advance (
                  p0, -(word) (sizeof(udp_header_t) + sizeof(ip6_header_t)));
              ip60 = vlib_buffer_get_current (p0);
              udp_0 = (udp_header_t *) (ip60 + 1);
            }

          entry0 = hash_get_mem(lbm->vip_index_by_nodeport, &(udp_0->dst_port));

          //Enqueue to next
          vnet_buffer(p0)->ip.adj_index[VLIB_TX] = entry0 ? entry0[0]
              : ADJ_INDEX_INVALID;

          if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
              lb_nodeport_trace_t *tr = vlib_add_trace (vm, node, p0,
                                                        sizeof(*tr));
              tr->vip_index = entry0 ? entry0[0] : ADJ_INDEX_INVALID;
              tr->node_port = (u32) clib_net_to_host_u16 (udp_0->dst_port);
            }

          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
              n_left_to_next, pi0,
              is_input_v4 ?
                  LB4_NODEPORT_NEXT_IP4_NAT4 : LB6_NODEPORT_NEXT_IP6_NAT6);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;

}

/**
 * @brief Match NAT44 static mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param index       index to the pool.
 *
 * @returns 0 if match found, otherwise -1.
 */
static_always_inline int
lb_nat44_mapping_match (lb_main_t *lbm, lb_snat4_key_t * match, u32 *index)
{
  clib_bihash_kv_16_8_t kv4, value;
  clib_bihash_16_8_t *mapping_hash = &lbm->mapping_by_as4;

  kv4.key[0] = match->as_u64[0];
  kv4.key[1] = match->as_u64[1];
  kv4.value = 0;
  if (clib_bihash_search_16_8 (mapping_hash, &kv4, &value))
    {
      return 1;
    }

  *index = value.value;
  return 0;
}

/**
 * @brief Match NAT66 static mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param mapping     External or local address and port of the matched mapping.
 *
 * @returns 0 if match found otherwise 1.
 */
static_always_inline int
lb_nat66_mapping_match (lb_main_t *lbm, lb_snat6_key_t * match, u32 *index)
{
  clib_bihash_kv_24_8_t kv6, value;
  clib_bihash_24_8_t *mapping_hash = &lbm->mapping_by_as6;

  kv6.key[0] = match->as_u64[0];
  kv6.key[1] = match->as_u64[1];
  kv6.key[2] = match->as_u64[2];
  kv6.value = 0;
  if (clib_bihash_search_24_8 (mapping_hash, &kv6, &value))
    {
      return 1;
    }

  *index = value.value;
  return 0;
}

/**
 * @brief Match NAT44 DNAT mapping.
 *
 * @param sm          NAT main.
 * @param match       Address and port to match.
 * @param index       index to the pool.
 *
 * @returns 0 if match found, otherwise -1.
 */
static_always_inline int
lb_nat44_dnat_mapping_match (lb_main_t *lbm, lb_snat_vip_key_t * match, u32 *index)
{
  clib_bihash_kv_16_8_t kv4, value;
  clib_bihash_16_8_t *mapping_hash = &lbm->mapping_by_uplink_dnat4;

  kv4.key[0] = match->as_u64[0];
  kv4.key[1] = match->as_u64[1];
  kv4.value = 0;
  if (clib_bihash_search_16_8 (mapping_hash, &kv4, &value))
    {
      return 1;
    }

  *index = value.value;
  return 0;
}

static_always_inline uword
lb_nat4_in2out_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  lb_main_t *lbm = &lb_main;
  u32 lb_time_now = lb_hash_time_now (vm);
  u32 stats_node_index;

  stats_node_index = lb_nat4_in2out_node.index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8  && n_left_to_next >= 4)
        {
          u32 bi0, bi1, bi2, bi3;
          vlib_buffer_t *b0, *b1, *b2, *b3;
          u32 next0, next1, next2, next3;
          u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;

          ip_csum_t csum0, csum1, csum2, csum3;

          u32 timeout0 = lbm->flow_timeout;
          u32 timeout1 = lbm->flow_timeout;
          u32 timeout2 = lbm->flow_timeout;
          u32 timeout3 = lbm->flow_timeout;

          ip4_header_t *ip40, *ip41, *ip42, *ip43;
          udp_header_t *udp0, *udp1, *udp2, *udp3;
          tcp_header_t *tcp0, *tcp1, *tcp2, *tcp3;

          u32 old_saddr0, new_saddr0, old_saddr1, new_saddr1, old_saddr2, new_saddr2, old_saddr3, new_saddr3;
          u16 old_sport0, new_sport0, old_sport1, new_sport1, old_sport2, new_sport2, old_sport3, new_sport3;
          u32 old_daddr0, new_daddr0, old_daddr1, new_daddr1, old_daddr2, new_daddr2, old_daddr3, new_daddr3;
          u16 old_dport0, new_dport0, old_dport1, new_dport1, old_dport2, new_dport2, old_dport3, new_dport3;

          lb_snat4_key_t key40, key41, key42, key43;
          lb_snat_mapping_t *sm40, *sm41, *sm42, *sm43;
          u32 index40, index41, index42, index43;

          lb_snat_vip_key_t dnat_key40, dnat_key41, dnat_key42, dnat_key43;
          lb_vip_snat_mapping_t *flow0, *flow1, *flow2, *flow3;
          u32 dindex40, dindex41, dindex42, dindex43;

          bool translated0 = false;
          bool translated1 = false;
          bool translated2 = false;
          bool translated3 = false;

          lb_vip_t *vip0, *vip1, *vip2, *vip3;

          u32 next_fib_index0, next_fib_index1, next_fib_index2, next_fib_index3;
          u32 rx_fib_index0, rx_fib_index1, rx_fib_index2, rx_fib_index3;

          /* Prefetch next iteration. */
          {
              vlib_buffer_t *p4, *p5, *p6, *p7;

              p4 = vlib_get_buffer (vm, from[4]);
              p5 = vlib_get_buffer (vm, from[5]);
              p6 = vlib_get_buffer (vm, from[6]);
              p7 = vlib_get_buffer (vm, from[7]);

              vlib_prefetch_buffer_header (p4, LOAD);
              vlib_prefetch_buffer_header (p5, LOAD);
              vlib_prefetch_buffer_header (p6, LOAD);
              vlib_prefetch_buffer_header (p7, LOAD);

              clib_prefetch_store (p4->data);
              clib_prefetch_store (p5->data);
              clib_prefetch_store (p6->data);
              clib_prefetch_store (p7->data);
          }

          /* speculatively enqueue b0 to the current next frame */
          to_next[0] = bi0 = from[0];
          to_next[1] = bi1 = from[1];
          to_next[2] = bi2 = from[2];
          to_next[3] = bi3 = from[3];
          from += 4;
          to_next += 4;
          n_left_from -= 4;
          n_left_to_next -= 4;

          b0 = vlib_get_buffer (vm, bi0);
          b1 = vlib_get_buffer (vm, bi1);
          b2 = vlib_get_buffer (vm, bi2);
          b3 = vlib_get_buffer (vm, bi3);

          next0 = LB_NAT4_IN2OUT_NEXT_LOOKUP;
          next1 = LB_NAT4_IN2OUT_NEXT_LOOKUP;
          next2 = LB_NAT4_IN2OUT_NEXT_LOOKUP;
          next3 = LB_NAT4_IN2OUT_NEXT_LOOKUP;

          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          sw_if_index1 = vnet_buffer(b1)->sw_if_index[VLIB_RX];
          sw_if_index2 = vnet_buffer(b2)->sw_if_index[VLIB_RX];
          sw_if_index3 = vnet_buffer(b3)->sw_if_index[VLIB_RX];

          rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index0);
          rx_fib_index1 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index1);
          rx_fib_index2 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index2);
          rx_fib_index3 = ip4_fib_table_get_index_for_sw_if_index(sw_if_index3);

          ip40 = vlib_buffer_get_current (b0);
          ip41 = vlib_buffer_get_current (b1);
          ip42 = vlib_buffer_get_current (b2);
          ip43 = vlib_buffer_get_current (b3);

          udp0 = ip4_next_header (ip40);
          udp1 = ip4_next_header (ip41);
          udp2 = ip4_next_header (ip42);
          udp3 = ip4_next_header (ip43);

          tcp0 = (tcp_header_t *) udp0;
          tcp1 = (tcp_header_t *) udp1;
          tcp2 = (tcp_header_t *) udp2;
          tcp3 = (tcp_header_t *) udp3;

          clib_memset(&dnat_key40, 0, sizeof(dnat_key40));
          clib_memset(&dnat_key41, 0, sizeof(dnat_key41));
          clib_memset(&dnat_key42, 0, sizeof(dnat_key42));
          clib_memset(&dnat_key43, 0, sizeof(dnat_key43));

          dnat_key40.addr = ip40->dst_address;
          dnat_key40.protocol = ip40->protocol;
          dnat_key40.port = udp0->dst_port;
          dnat_key40.fib_index = rx_fib_index0;

          dnat_key41.addr = ip41->dst_address;
          dnat_key41.protocol = ip41->protocol;
          dnat_key41.port = udp1->dst_port;
          dnat_key41.fib_index = rx_fib_index1;

          dnat_key42.addr = ip42->dst_address;
          dnat_key42.protocol = ip42->protocol;
          dnat_key42.port = udp2->dst_port;
          dnat_key42.fib_index = rx_fib_index2;

          dnat_key43.addr = ip43->dst_address;
          dnat_key43.protocol = ip43->protocol;
          dnat_key43.port = udp3->dst_port;
          dnat_key43.fib_index = rx_fib_index3;

          if (lb_nat44_dnat_mapping_match (lbm, &dnat_key40, &dindex40) == 0)
          {
              flow0 = pool_elt_at_index (lbm->vip_snat_mappings, dindex40);

              vip0 = pool_elt_at_index(lbm->vips, flow0->vip_index);

              if (!lb_vip_is_double_nat44(vip0))
              {
                  vnet_feature_next (&next0, b0);
                  goto trace00;
              }

              next_fib_index0 = flow0->outside_fib_index;

              timeout0 = lb_get_ip4_protocol_timeout(vm, b0, ip40);

              old_saddr0 = ip40->src_address.as_u32;
              old_daddr0 = ip40->dst_address.as_u32;
              new_saddr0 = vip0->prefix.ip4.as_u32;
              new_daddr0 = flow0->outside_ip.ip4.as_u32;
              ip40->src_address.as_u32 = new_saddr0;
              ip40->dst_address.as_u32 = new_daddr0;

              new_sport0 = vip0->net_port;
              new_dport0 = flow0->outside_port;

              csum0 = ip40->checksum;
              csum0 = ip_csum_sub_even (csum0, old_saddr0);
              csum0 = ip_csum_sub_even (csum0, old_daddr0);
              csum0 = ip_csum_add_even (csum0, new_saddr0);
              csum0 = ip_csum_add_even (csum0, new_daddr0);
              ip40->checksum = ip_csum_fold (csum0);

              if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport0 = tcp0->src_port;
                  old_dport0 = tcp0->dst_port;
                  tcp0->src_port = new_sport0;
                  tcp0->dst_port = new_dport0;

                  csum0 = tcp0->checksum;
                  csum0 = ip_csum_sub_even (csum0, old_saddr0);
                  csum0 = ip_csum_sub_even (csum0, old_daddr0);
                  csum0 = ip_csum_sub_even (csum0, old_sport0);
                  csum0 = ip_csum_sub_even (csum0, old_dport0);
                  csum0 = ip_csum_add_even (csum0, new_saddr0);
                  csum0 = ip_csum_add_even (csum0, new_daddr0);
                  csum0 = ip_csum_add_even (csum0, new_sport0);
                  csum0 = ip_csum_add_even (csum0, new_dport0);
                  tcp0->checksum = ip_csum_fold (csum0);
              }
              else if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport0 = tcp0->src_port;
                  old_dport0 = udp0->dst_port;
                  udp0->src_port = new_sport0;
                  udp0->dst_port = new_dport0;

                  if (udp0->checksum)
                  {
                      csum0 = udp0->checksum;
                      csum0 = ip_csum_sub_even (csum0, old_saddr0);
                      csum0 = ip_csum_sub_even (csum0, old_daddr0);
                      csum0 = ip_csum_sub_even (csum0, old_sport0);
                      csum0 = ip_csum_sub_even (csum0, old_dport0);
                      csum0 = ip_csum_add_even (csum0, flow0->outside_ip.ip4.as_u32);
                      csum0 = ip_csum_add_even (csum0, flow0->outside_ip.ip4.as_u32);
                      csum0 = ip_csum_add_even (csum0, new_sport0);
                      csum0 = ip_csum_add_even (csum0, new_dport0);
                      udp0->checksum = ip_csum_fold (csum0);
                  }
              }

              if (lb_time_now - flow0->last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                          vip0, flow0, timeout0);
                  flow0->last_ha_sync_timeout = lb_time_now;
              }

              flow0->timeout = lb_time_now + timeout0;
          }
          else
          {
              clib_memset(&key40, 0, sizeof(key40));
              key40.addr = ip40->src_address;
              key40.protocol = ip40->protocol;
              key40.port = udp0->src_port;
              key40.fib_index = rx_fib_index0;

              if (lb_nat44_mapping_match (lbm, &key40, &index40))
              {
                  vnet_feature_next (&next0, b0);
                  goto trace00;
              }

              sm40 = pool_elt_at_index(lbm->snat_mappings, index40);

              next_fib_index0 = sm40->fib_index;

              new_saddr0 = sm40->src_ip.ip4.as_u32;
              new_sport0 = sm40->src_port;
              old_saddr0 = ip40->src_address.as_u32;
              ip40->src_address.as_u32 = new_saddr0;

              csum0 = ip40->checksum;
              csum0 = ip_csum_sub_even (csum0, old_saddr0);
              csum0 = ip_csum_add_even (csum0, new_saddr0);
              ip40->checksum = ip_csum_fold (csum0);

              if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport0 = tcp0->src_port;
                  tcp0->src_port = new_sport0;

                  csum0 = tcp0->checksum;
                  csum0 = ip_csum_sub_even (csum0, old_saddr0);
                  csum0 = ip_csum_sub_even (csum0, old_sport0);
                  csum0 = ip_csum_add_even (csum0, new_saddr0);
                  csum0 = ip_csum_add_even (csum0, new_sport0);
                  tcp0->checksum = ip_csum_fold (csum0);
              }
              else if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport0 = udp0->src_port;
                  udp0->src_port = new_sport0;

                  if (udp0->checksum)
                  {
                      csum0 = udp0->checksum;
                      csum0 = ip_csum_sub_even (csum0, old_saddr0);
                      csum0 = ip_csum_sub_even (csum0, old_sport0);
                      csum0 = ip_csum_add_even (csum0, new_saddr0);
                      csum0 = ip_csum_add_even (csum0, new_sport0);
                      udp0->checksum = ip_csum_fold (csum0);
                  }
              }
          }

          vnet_buffer(b0)->sw_if_index[VLIB_TX] = next_fib_index0;
          translated0 = true;

          trace00:
          pkts_processed += translated0 != true;
          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
              t->rx_sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          if (lb_nat44_dnat_mapping_match (lbm, &dnat_key41, &dindex41) == 0)
          {
              flow1 = pool_elt_at_index (lbm->vip_snat_mappings, dindex41);

              vip1 = pool_elt_at_index(lbm->vips, flow1->vip_index);

              if (!lb_vip_is_double_nat44(vip1))
              {
                  vnet_feature_next (&next1, b1);
                  goto trace01;
              }

              next_fib_index1 = flow1->outside_fib_index;

              timeout1 = lb_get_ip4_protocol_timeout(vm, b1, ip41);

              old_saddr1 = ip41->src_address.as_u32;
              old_daddr1 = ip41->dst_address.as_u32;
              new_saddr1 = vip1->prefix.ip4.as_u32;
              new_daddr1 = flow1->outside_ip.ip4.as_u32;
              ip41->src_address.as_u32 = new_saddr1;
              ip41->dst_address.as_u32 = new_daddr1;

              new_sport1 = vip1->net_port;
              new_dport1 = flow1->outside_port;

              csum1 = ip41->checksum;
              csum1 = ip_csum_sub_even (csum1, old_saddr1);
              csum1 = ip_csum_sub_even (csum1, old_daddr1);
              csum1 = ip_csum_add_even (csum1, new_saddr1);
              csum1 = ip_csum_add_even (csum1, new_daddr1);
              ip41->checksum = ip_csum_fold (csum1);

              if (PREDICT_TRUE(ip41->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport1 = tcp1->src_port;
                  old_dport1 = tcp1->dst_port;
                  tcp1->src_port = new_sport1;
                  tcp1->dst_port = new_dport1;

                  csum1 = tcp1->checksum;
                  csum1 = ip_csum_sub_even (csum1, old_saddr1);
                  csum1 = ip_csum_sub_even (csum1, old_daddr1);
                  csum1 = ip_csum_sub_even (csum1, old_sport1);
                  csum1 = ip_csum_sub_even (csum1, old_dport1);
                  csum1 = ip_csum_add_even (csum1, new_saddr1);
                  csum1 = ip_csum_add_even (csum1, new_daddr1);
                  csum1 = ip_csum_add_even (csum1, new_sport1);
                  csum1 = ip_csum_add_even (csum1, new_dport1);
                  tcp1->checksum = ip_csum_fold (csum1);
              }
              else if (PREDICT_TRUE(ip41->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport1 = tcp1->src_port;
                  old_dport1 = udp1->dst_port;
                  udp1->src_port = new_sport1;
                  udp1->dst_port = new_dport1;

                  if (udp1->checksum)
                  {
                      csum1 = udp1->checksum;
                      csum1 = ip_csum_sub_even (csum1, old_saddr1);
                      csum1 = ip_csum_sub_even (csum1, old_daddr1);
                      csum1 = ip_csum_sub_even (csum1, old_sport1);
                      csum1 = ip_csum_sub_even (csum1, old_dport1);
                      csum1 = ip_csum_add_even (csum1, flow1->outside_ip.ip4.as_u32);
                      csum1 = ip_csum_add_even (csum1, flow1->outside_ip.ip4.as_u32);
                      csum1 = ip_csum_add_even (csum1, new_sport1);
                      csum1 = ip_csum_add_even (csum1, new_dport1);
                      udp1->checksum = ip_csum_fold (csum1);
                  }
              }

              if (lb_time_now - flow1->last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                          vip1, flow1, timeout1);
                  flow1->last_ha_sync_timeout = lb_time_now;
              }

              flow1->timeout = lb_time_now + timeout1;
          }
          else
          {
              clib_memset(&key41, 0, sizeof(key41));
              key41.addr = ip41->src_address;
              key41.protocol = ip41->protocol;
              key41.port = udp1->src_port;
              key41.fib_index = rx_fib_index1;

              if (lb_nat44_mapping_match (lbm, &key41, &index41))
              {
                  vnet_feature_next (&next1, b1);
                  goto trace01;
              }

              sm41 = pool_elt_at_index(lbm->snat_mappings, index41);

              next_fib_index1 = sm41->fib_index;

              new_saddr1 = sm41->src_ip.ip4.as_u32;
              new_sport1 = sm41->src_port;
              old_saddr1 = ip41->src_address.as_u32;
              ip41->src_address.as_u32 = new_saddr1;

              csum1 = ip41->checksum;
              csum1 = ip_csum_sub_even (csum1, old_saddr1);
              csum1 = ip_csum_add_even (csum1, new_saddr1);
              ip41->checksum = ip_csum_fold (csum1);

              if (PREDICT_TRUE(ip41->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport1 = tcp1->src_port;
                  tcp1->src_port = new_sport1;

                  csum1 = tcp1->checksum;
                  csum1 = ip_csum_sub_even (csum1, old_saddr1);
                  csum1 = ip_csum_sub_even (csum1, old_sport1);
                  csum1 = ip_csum_add_even (csum1, new_saddr1);
                  csum1 = ip_csum_add_even (csum1, new_sport1);
                  tcp1->checksum = ip_csum_fold (csum1);
              }
              else if (PREDICT_TRUE(ip41->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport1 = udp1->src_port;
                  udp1->src_port = new_sport1;

                  if (udp1->checksum)
                  {
                      csum1 = udp1->checksum;
                      csum1 = ip_csum_sub_even (csum1, old_saddr1);
                      csum1 = ip_csum_sub_even (csum1, old_sport1);
                      csum1 = ip_csum_add_even (csum1, new_saddr1);
                      csum1 = ip_csum_add_even (csum1, new_sport1);
                      udp1->checksum = ip_csum_fold (csum1);
                  }
              }
          }

          vnet_buffer(b1)->sw_if_index[VLIB_TX] = next_fib_index1;
          translated1 = true;

          trace01:
          pkts_processed += translated1 != true;
          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b1->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b1, sizeof(*t));
              t->rx_sw_if_index = sw_if_index1;
              t->next_index = next1;
            }

          if (lb_nat44_dnat_mapping_match (lbm, &dnat_key42, &dindex42) == 0)
          {
              flow2 = pool_elt_at_index (lbm->vip_snat_mappings, dindex42);

              vip2 = pool_elt_at_index(lbm->vips, flow2->vip_index);

              if (!lb_vip_is_double_nat44(vip2))
              {
                  vnet_feature_next (&next2, b2);
                  goto trace02;
              }

              next_fib_index2 = flow2->outside_fib_index;

              timeout2 = lb_get_ip4_protocol_timeout(vm, b2, ip42);

              old_saddr2 = ip42->src_address.as_u32;
              old_daddr2 = ip42->dst_address.as_u32;
              new_saddr2 = vip2->prefix.ip4.as_u32;
              new_daddr2 = flow2->outside_ip.ip4.as_u32;
              ip42->src_address.as_u32 = new_saddr2;
              ip42->dst_address.as_u32 = new_daddr2;

              new_sport2 = vip2->net_port;
              new_dport2 = flow2->outside_port;

              csum2 = ip42->checksum;
              csum2 = ip_csum_sub_even (csum2, old_saddr2);
              csum2 = ip_csum_sub_even (csum2, old_daddr2);
              csum2 = ip_csum_add_even (csum2, new_saddr2);
              csum2 = ip_csum_add_even (csum2, new_daddr2);
              ip42->checksum = ip_csum_fold (csum2);

              if (PREDICT_TRUE(ip42->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport2 = tcp2->src_port;
                  old_dport2 = tcp2->dst_port;
                  tcp2->src_port = new_sport2;
                  tcp2->dst_port = new_dport2;

                  csum2 = tcp2->checksum;
                  csum2 = ip_csum_sub_even (csum2, old_saddr2);
                  csum2 = ip_csum_sub_even (csum2, old_daddr2);
                  csum2 = ip_csum_sub_even (csum2, old_sport2);
                  csum2 = ip_csum_sub_even (csum2, old_dport2);
                  csum2 = ip_csum_add_even (csum2, new_saddr2);
                  csum2 = ip_csum_add_even (csum2, new_daddr2);
                  csum2 = ip_csum_add_even (csum2, new_sport2);
                  csum2 = ip_csum_add_even (csum2, new_dport2);
                  tcp2->checksum = ip_csum_fold (csum2);
              }
              else if (PREDICT_TRUE(ip42->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport2 = tcp2->src_port;
                  old_dport2 = udp2->dst_port;
                  udp2->src_port = new_sport2;
                  udp2->dst_port = new_dport2;

                  if (udp2->checksum)
                  {
                      csum2 = udp2->checksum;
                      csum2 = ip_csum_sub_even (csum2, old_saddr2);
                      csum2 = ip_csum_sub_even (csum2, old_daddr2);
                      csum2 = ip_csum_sub_even (csum2, old_sport2);
                      csum2 = ip_csum_sub_even (csum2, old_dport2);
                      csum2 = ip_csum_add_even (csum2, flow2->outside_ip.ip4.as_u32);
                      csum2 = ip_csum_add_even (csum2, flow2->outside_ip.ip4.as_u32);
                      csum2 = ip_csum_add_even (csum2, new_sport2);
                      csum2 = ip_csum_add_even (csum2, new_dport2);
                      udp2->checksum = ip_csum_fold (csum2);
                  }
              }

              if (lb_time_now - flow2->last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                          vip2, flow2, timeout2);
                  flow2->last_ha_sync_timeout = lb_time_now;
              }

              flow2->timeout = lb_time_now + timeout2;
          }
          else
          {
              clib_memset(&key42, 0, sizeof(key42));
              key42.addr = ip42->src_address;
              key42.protocol = ip42->protocol;
              key42.port = udp2->src_port;
              key42.fib_index = rx_fib_index2;

              if (lb_nat44_mapping_match (lbm, &key42, &index42))
              {
                  vnet_feature_next (&next2, b2);
                  goto trace02;
              }

              sm42 = pool_elt_at_index(lbm->snat_mappings, index42);

              next_fib_index2 = sm42->fib_index;

              new_saddr2 = sm42->src_ip.ip4.as_u32;
              new_sport2 = sm42->src_port;
              old_saddr2 = ip42->src_address.as_u32;
              ip42->src_address.as_u32 = new_saddr2;

              csum2 = ip42->checksum;
              csum2 = ip_csum_sub_even (csum2, old_saddr2);
              csum2 = ip_csum_add_even (csum2, new_saddr2);
              ip42->checksum = ip_csum_fold (csum2);

              if (PREDICT_TRUE(ip42->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport2 = tcp2->src_port;
                  tcp2->src_port = new_sport2;

                  csum2 = tcp2->checksum;
                  csum2 = ip_csum_sub_even (csum2, old_saddr2);
                  csum2 = ip_csum_sub_even (csum2, old_sport2);
                  csum2 = ip_csum_add_even (csum2, new_saddr2);
                  csum2 = ip_csum_add_even (csum2, new_sport2);
                  tcp2->checksum = ip_csum_fold (csum2);
              }
              else if (PREDICT_TRUE(ip42->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport2 = udp2->src_port;
                  udp2->src_port = new_sport2;

                  if (udp2->checksum)
                  {
                      csum2 = udp2->checksum;
                      csum2 = ip_csum_sub_even (csum2, old_saddr2);
                      csum2 = ip_csum_sub_even (csum2, old_sport2);
                      csum2 = ip_csum_add_even (csum2, new_saddr2);
                      csum2 = ip_csum_add_even (csum2, new_sport2);
                      udp2->checksum = ip_csum_fold (csum2);
                  }
              }
          }

          vnet_buffer(b2)->sw_if_index[VLIB_TX] = next_fib_index2;
          translated2 = true;

          trace02:
          pkts_processed += translated2 != true;
          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b2->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b2, sizeof(*t));
              t->rx_sw_if_index = sw_if_index2;
              t->next_index = next2;
            }

          if (lb_nat44_dnat_mapping_match (lbm, &dnat_key43, &dindex43) == 0)
          {
              flow3 = pool_elt_at_index (lbm->vip_snat_mappings, dindex43);

              vip3 = pool_elt_at_index(lbm->vips, flow3->vip_index);

              if (!lb_vip_is_double_nat44(vip3))
              {
                  vnet_feature_next (&next3, b3);
                  goto trace03;
              }

              next_fib_index3 = flow3->outside_fib_index;

              timeout3 = lb_get_ip4_protocol_timeout(vm, b3, ip43);

              old_saddr3 = ip43->src_address.as_u32;
              old_daddr3 = ip43->dst_address.as_u32;
              new_saddr3 = vip3->prefix.ip4.as_u32;
              new_daddr3 = flow3->outside_ip.ip4.as_u32;
              ip43->src_address.as_u32 = new_saddr3;
              ip43->dst_address.as_u32 = new_daddr3;

              new_sport3 = vip3->net_port;
              new_dport3 = flow3->outside_port;

              csum3 = ip43->checksum;
              csum3 = ip_csum_sub_even (csum3, old_saddr3);
              csum3 = ip_csum_sub_even (csum3, old_daddr3);
              csum3 = ip_csum_add_even (csum3, new_saddr3);
              csum3 = ip_csum_add_even (csum3, new_daddr3);
              ip43->checksum = ip_csum_fold (csum3);

              if (PREDICT_TRUE(ip43->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport3 = tcp3->src_port;
                  old_dport3 = tcp3->dst_port;
                  tcp3->src_port = new_sport3;
                  tcp3->dst_port = new_dport3;

                  csum3 = tcp3->checksum;
                  csum3 = ip_csum_sub_even (csum3, old_saddr3);
                  csum3 = ip_csum_sub_even (csum3, old_daddr3);
                  csum3 = ip_csum_sub_even (csum3, old_sport3);
                  csum3 = ip_csum_sub_even (csum3, old_dport3);
                  csum3 = ip_csum_add_even (csum3, new_saddr3);
                  csum3 = ip_csum_add_even (csum3, new_daddr3);
                  csum3 = ip_csum_add_even (csum3, new_sport3);
                  csum3 = ip_csum_add_even (csum3, new_dport3);
                  tcp3->checksum = ip_csum_fold (csum3);
              }
              else if (PREDICT_TRUE(ip43->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport3 = tcp3->src_port;
                  old_dport3 = udp3->dst_port;
                  udp3->src_port = new_sport3;
                  udp3->dst_port = new_dport3;

                  if (udp3->checksum)
                  {
                      csum3 = udp3->checksum;
                      csum3 = ip_csum_sub_even (csum3, old_saddr3);
                      csum3 = ip_csum_sub_even (csum3, old_daddr3);
                      csum3 = ip_csum_sub_even (csum3, old_sport3);
                      csum3 = ip_csum_sub_even (csum3, old_dport3);
                      csum3 = ip_csum_add_even (csum3, flow3->outside_ip.ip4.as_u32);
                      csum3 = ip_csum_add_even (csum3, flow3->outside_ip.ip4.as_u32);
                      csum3 = ip_csum_add_even (csum3, new_sport3);
                      csum3 = ip_csum_add_even (csum3, new_dport3);
                      udp3->checksum = ip_csum_fold (csum3);
                  }
              }

              if (lb_time_now - flow3->last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                          vip3, flow3, timeout3);
                  flow3->last_ha_sync_timeout = lb_time_now;
              }

              flow3->timeout = lb_time_now + timeout3;
          }
          else
          {
              clib_memset(&key43, 0, sizeof(key43));
              key43.addr = ip43->src_address;
              key43.protocol = ip43->protocol;
              key43.port = udp3->src_port;
              key43.fib_index = rx_fib_index3;

              if (lb_nat44_mapping_match (lbm, &key43, &index43))
              {
                  vnet_feature_next (&next3, b3);
                  goto trace03;
              }

              sm43 = pool_elt_at_index(lbm->snat_mappings, index43);

              next_fib_index3 = sm43->fib_index;

              new_saddr3 = sm43->src_ip.ip4.as_u32;
              new_sport3 = sm43->src_port;
              old_saddr3 = ip43->src_address.as_u32;
              ip43->src_address.as_u32 = new_saddr3;

              csum3 = ip43->checksum;
              csum3 = ip_csum_sub_even (csum3, old_saddr3);
              csum3 = ip_csum_add_even (csum3, new_saddr3);
              ip43->checksum = ip_csum_fold (csum3);

              if (PREDICT_TRUE(ip43->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport3 = tcp3->src_port;
                  tcp3->src_port = new_sport3;

                  csum3 = tcp3->checksum;
                  csum3 = ip_csum_sub_even (csum3, old_saddr3);
                  csum3 = ip_csum_sub_even (csum3, old_sport3);
                  csum3 = ip_csum_add_even (csum3, new_saddr3);
                  csum3 = ip_csum_add_even (csum3, new_sport3);
                  tcp3->checksum = ip_csum_fold (csum3);
              }
              else if (PREDICT_TRUE(ip43->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport3 = udp3->src_port;
                  udp3->src_port = new_sport3;

                  if (udp3->checksum)
                  {
                      csum3 = udp3->checksum;
                      csum3 = ip_csum_sub_even (csum3, old_saddr3);
                      csum3 = ip_csum_sub_even (csum3, old_sport3);
                      csum3 = ip_csum_add_even (csum3, new_saddr3);
                      csum3 = ip_csum_add_even (csum3, new_sport3);
                      udp3->checksum = ip_csum_fold (csum3);
                  }
              }
          }

          vnet_buffer(b3)->sw_if_index[VLIB_TX] = next_fib_index3;
          translated3 = true;

          trace03:
          pkts_processed += translated3 != true;
          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b3->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b3, sizeof(*t));
              t->rx_sw_if_index = sw_if_index3;
              t->next_index = next3;
            }

          /* verify speculative enqueue, maybe switch current next frame */
	      vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                  to_next, n_left_to_next,
                  bi0, bi1, bi2, bi3,
                  next0, next1, next2, next3);
        }

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          u32 timeout0 = lbm->flow_timeout;

          ip4_header_t * ip40;
          udp_header_t * udp0;
          tcp_header_t * tcp0;

          ip_csum_t csum0;
          u32 old_saddr0, new_saddr0;
          u16 old_sport0, new_sport0;
          u32 old_daddr0, new_daddr0;
          u16 old_dport0, new_dport0;

          lb_snat4_key_t key40;
          lb_snat_mapping_t *sm40;
          u32 index40;

          lb_snat_vip_key_t dnat_key40;
          lb_vip_snat_mapping_t *flow0;
          u32 dindex40;

          u32 next_fib_index0;
          bool translated0 = false;

          lb_vip_t *vip0;

          u32 rx_fib_index0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          next0 = LB_NAT4_IN2OUT_NEXT_LOOKUP;
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (
              sw_if_index0);

          ip40 = vlib_buffer_get_current (b0);
          udp0 = ip4_next_header (ip40);
          tcp0 = (tcp_header_t *) udp0;

          clib_memset(&dnat_key40, 0, sizeof(dnat_key40));
          dnat_key40.addr = ip40->dst_address;
          dnat_key40.protocol = ip40->protocol;
          dnat_key40.port = udp0->dst_port;
          dnat_key40.fib_index = rx_fib_index0;

          if (lb_nat44_dnat_mapping_match (lbm, &dnat_key40, &dindex40) == 0)
          {
              flow0 = pool_elt_at_index (lbm->vip_snat_mappings, dindex40);

              vip0 = pool_elt_at_index(lbm->vips, flow0->vip_index);

              if (!lb_vip_is_double_nat44(vip0))
              {
                  vnet_feature_next (&next0, b0);
                  goto trace0;
              }

              next_fib_index0 = flow0->outside_fib_index;

              timeout0 = lb_get_ip4_protocol_timeout(vm, b0, ip40);

              old_saddr0 = ip40->src_address.as_u32;
              old_daddr0 = ip40->dst_address.as_u32;
              new_saddr0 = vip0->prefix.ip4.as_u32;
              new_daddr0 = flow0->outside_ip.ip4.as_u32;
              ip40->src_address.as_u32 = new_saddr0;
              ip40->dst_address.as_u32 = new_daddr0;

              new_sport0 = vip0->net_port;
              new_dport0 = flow0->outside_port;

              csum0 = ip40->checksum;
              csum0 = ip_csum_sub_even (csum0, old_saddr0);
              csum0 = ip_csum_sub_even (csum0, old_daddr0);
              csum0 = ip_csum_add_even (csum0, new_saddr0);
              csum0 = ip_csum_add_even (csum0, new_daddr0);
              ip40->checksum = ip_csum_fold (csum0);

              if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport0 = tcp0->src_port;
                  old_dport0 = tcp0->dst_port;
                  tcp0->src_port = new_sport0;
                  tcp0->dst_port = new_dport0;

                  csum0 = tcp0->checksum;
                  csum0 = ip_csum_sub_even (csum0, old_saddr0);
                  csum0 = ip_csum_sub_even (csum0, old_daddr0);
                  csum0 = ip_csum_sub_even (csum0, old_sport0);
                  csum0 = ip_csum_sub_even (csum0, old_dport0);
                  csum0 = ip_csum_add_even (csum0, new_saddr0);
                  csum0 = ip_csum_add_even (csum0, new_daddr0);
                  csum0 = ip_csum_add_even (csum0, new_sport0);
                  csum0 = ip_csum_add_even (csum0, new_dport0);
                  tcp0->checksum = ip_csum_fold (csum0);
              }
              else if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport0 = tcp0->src_port;
                  old_dport0 = udp0->dst_port;
                  udp0->src_port = new_sport0;
                  udp0->dst_port = new_dport0;

                  if (udp0->checksum)
                  {
                      csum0 = udp0->checksum;
                      csum0 = ip_csum_sub_even (csum0, old_saddr0);
                      csum0 = ip_csum_sub_even (csum0, old_daddr0);
                      csum0 = ip_csum_sub_even (csum0, old_sport0);
                      csum0 = ip_csum_sub_even (csum0, old_dport0);
                      csum0 = ip_csum_add_even (csum0, flow0->outside_ip.ip4.as_u32);
                      csum0 = ip_csum_add_even (csum0, flow0->outside_ip.ip4.as_u32);
                      csum0 = ip_csum_add_even (csum0, new_sport0);
                      csum0 = ip_csum_add_even (csum0, new_dport0);
                      udp0->checksum = ip_csum_fold (csum0);
                  }
              }

              if (lb_time_now - flow0->last_ha_sync_timeout >
                  lb_ha_sync_ctx.ha_sync_timeout_update_interval)
              {
                  lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_UPDATE,
                          vip0, flow0, timeout0);
                  flow0->last_ha_sync_timeout = lb_time_now;
              }

              flow0->timeout = lb_time_now + timeout0;
          }
          else
          {
              clib_memset(&key40, 0, sizeof(key40));
              key40.addr = ip40->src_address;
              key40.protocol = ip40->protocol;
              key40.port = udp0->src_port;
              key40.fib_index = rx_fib_index0;

              if (lb_nat44_mapping_match (lbm, &key40, &index40))
              {
                  vnet_feature_next (&next0, b0);
                  goto trace0;
              }

              sm40 = pool_elt_at_index(lbm->snat_mappings, index40);

              next_fib_index0 = sm40->fib_index;

              new_saddr0 = sm40->src_ip.ip4.as_u32;
              new_sport0 = sm40->src_port;
              old_saddr0 = ip40->src_address.as_u32;
              ip40->src_address.as_u32 = new_saddr0;

              csum0 = ip40->checksum;
              csum0 = ip_csum_sub_even (csum0, old_saddr0);
              csum0 = ip_csum_add_even (csum0, new_saddr0);
              ip40->checksum = ip_csum_fold (csum0);

              if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_TCP))
              {
                  old_sport0 = tcp0->src_port;
                  tcp0->src_port = new_sport0;

                  csum0 = tcp0->checksum;
                  csum0 = ip_csum_sub_even (csum0, old_saddr0);
                  csum0 = ip_csum_sub_even (csum0, old_sport0);
                  csum0 = ip_csum_add_even (csum0, new_saddr0);
                  csum0 = ip_csum_add_even (csum0, new_sport0);
                  tcp0->checksum = ip_csum_fold (csum0);
              }
              else if (PREDICT_TRUE(ip40->protocol == IP_PROTOCOL_UDP))
              {
                  old_sport0 = udp0->src_port;
                  udp0->src_port = new_sport0;

                  if (udp0->checksum)
                  {
                      csum0 = udp0->checksum;
                      csum0 = ip_csum_sub_even (csum0, old_saddr0);
                      csum0 = ip_csum_sub_even (csum0, old_sport0);
                      csum0 = ip_csum_add_even (csum0, new_saddr0);
                      csum0 = ip_csum_add_even (csum0, new_sport0);
                      udp0->checksum = ip_csum_fold (csum0);
                  }
              }
          }

          vnet_buffer(b0)->sw_if_index[VLIB_TX] = next_fib_index0;

          translated0 = true;

          trace0: 

          pkts_processed += translated0 != true;

          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
              t->rx_sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               LB_NAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static_always_inline uword
lb_nat6_in2out_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  u32 next_index;
  u32 pkts_processed = 0;
  lb_main_t *lbm = &lb_main;
  u32 stats_node_index;

  stats_node_index = lb_nat6_in2out_node.index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame(vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
        {
          u32 bi0;
          vlib_buffer_t * b0;
          u32 next0;
          u32 sw_if_index0;
          ip_csum_t csum;

          ip6_header_t * ip60;
          u8 l4_protocol0;
          u16 l4_offset0, frag_hdr_offset0;

          udp_header_t * udp0;
          tcp_header_t * tcp0;


          ip6_address_t old_addr0, new_addr0;
          u16 old_port0, new_port0;

          lb_snat6_key_t key60;
          lb_snat_mapping_t *sm60;
          u32 index60;

          bool translated = false;

          u32 rx_fib_index0;

          /* speculatively enqueue b0 to the current next frame */
          bi0 = from[0];
          to_next[0] = bi0;
          from += 1;
          to_next += 1;
          n_left_from -= 1;
          n_left_to_next -= 1;

          b0 = vlib_get_buffer (vm, bi0);
          next0 = LB_NAT6_IN2OUT_NEXT_LOOKUP;
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];
          rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (
              sw_if_index0);

          ip60 = vlib_buffer_get_current (b0);

          if (PREDICT_FALSE (ip6_parse (vm, b0, ip60, b0->current_length,
                          &l4_protocol0, &l4_offset0, &frag_hdr_offset0)))
          {
              b0->error = node->errors[LB_ERROR_PROTO_NOT_SUPPORTED];
              vnet_feature_next (&next0, b0);
              goto trace0;
          }

          if (PREDICT_FALSE(frag_hdr_offset0))
          {
              b0->error = node->errors[LB_ERROR_IP6_FRAG_NOT_SUPPORTED];
              vnet_feature_next (&next0, b0);
              goto trace0;
          }

          udp0 = (udp_header_t *) u8_ptr_add (ip60, l4_offset0);
          tcp0 = (tcp_header_t *) u8_ptr_add (ip60, l4_offset0);

          clib_memset(&key60, 0, sizeof(key60));
          key60.addr.as_u64[0] = ip60->src_address.as_u64[0];
          key60.addr.as_u64[1] = ip60->src_address.as_u64[1];
          key60.protocol = ip60->protocol;
          key60.port = udp0->src_port;
          key60.fib_index = rx_fib_index0;

          if (lb_nat66_mapping_match (lbm, &key60, &index60))
            {
              vnet_feature_next (&next0, b0);
              goto trace0;
            }

          sm60 = pool_elt_at_index(lbm->snat_mappings, index60);
          new_addr0.as_u64[0] = sm60->src_ip.as_u64[0];
          new_addr0.as_u64[1] = sm60->src_ip.as_u64[1];
          new_port0 = sm60->src_port;
          vnet_buffer(b0)->sw_if_index[VLIB_TX] = sm60->fib_index;
          old_addr0.as_u64[0] = ip60->src_address.as_u64[0];
          old_addr0.as_u64[1] = ip60->src_address.as_u64[1];
          ip60->src_address.as_u64[0] = new_addr0.as_u64[0];
          ip60->src_address.as_u64[1] = new_addr0.as_u64[1];

          if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_TCP))
            {
              old_port0 = tcp0->src_port;
              tcp0->src_port = new_port0;

              csum = tcp0->checksum;
              csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
              csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
              csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
              csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
              csum = ip_csum_sub_even (csum, old_port0);
              csum = ip_csum_add_even (csum, new_port0);
              tcp0->checksum = ip_csum_fold (csum);
            }
          else if (PREDICT_TRUE(ip60->protocol == IP_PROTOCOL_UDP))
            {
              old_port0 = udp0->src_port;
              udp0->src_port = new_port0;

              csum = udp0->checksum;
              csum = ip_csum_sub_even (csum, old_addr0.as_u64[0]);
              csum = ip_csum_sub_even (csum, old_addr0.as_u64[1]);
              csum = ip_csum_add_even (csum, new_addr0.as_u64[0]);
              csum = ip_csum_add_even (csum, new_addr0.as_u64[1]);
              csum = ip_csum_sub_even (csum, old_port0);
              csum = ip_csum_add_even (csum, new_port0);
              udp0->checksum = ip_csum_fold (csum);
            }

          translated = true;

          trace0: 

          pkts_processed += translated != true;

          if (PREDICT_FALSE(
              (node->flags & VLIB_NODE_FLAG_TRACE) && (b0->flags & VLIB_BUFFER_IS_TRACED)))
            {
              lb_nat_trace_t *t = vlib_add_trace (vm, node, b0, sizeof(*t));
              t->rx_sw_if_index = sw_if_index0;
              t->next_index = next0;
            }

          /* verify speculative enqueue, maybe switch current next frame */
          vlib_validate_buffer_enqueue_x1(vm, node, next_index, to_next,
                                          n_left_to_next, bi0, next0);
        }

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, stats_node_index,
                               LB_NAT_IN2OUT_ERROR_IN2OUT_PACKETS,
                               pkts_processed);
  return frame->n_vectors;
}

static uword
lb6_gre6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE6, 0);
}

static uword
lb6_gre4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE4, 0);
}

static uword
lb4_gre6_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE6, 0);
}

static uword
lb4_gre4_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                  vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE4, 0);
}

static uword
lb6_gre6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE6, 1);
}

static uword
lb6_gre4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_GRE4, 1);
}

static uword
lb4_gre6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE6, 1);
}

static uword
lb4_gre4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_GRE4, 1);
}

static uword
lb4_l3dsr_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_L3DSR, 0);
}

static uword
lb4_l3dsr_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_L3DSR, 1);
}

static uword
lb6_nat6_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 0, LB_ENCAP_TYPE_NAT6, 1);
}

static uword
lb4_nat4_port_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                       vlib_frame_t * frame)
{
  return lb_node_fn (vm, node, frame, 1, LB_ENCAP_TYPE_NAT4, 1);
}

static uword
lb_nat4_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_nat4_in2out_node_inline (vm, node, frame);
}

static uword
lb_nat6_in2out_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                        vlib_frame_t * frame)
{
  return lb_nat6_in2out_node_inline (vm, node, frame);
}

VLIB_REGISTER_NODE (lb6_gre6_node) =
  {
    .function = lb6_gre6_node_fn,
    .name = "lb6-gre6",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre4_node) =
  {
    .function = lb6_gre4_node_fn,
    .name = "lb6-gre4",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre6_node) =
  {
    .function = lb4_gre6_node_fn,
    .name = "lb4-gre6",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre4_node) =
  {
    .function = lb4_gre4_node_fn,
    .name = "lb4-gre4",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre6_port_node) =
  {
    .function = lb6_gre6_port_node_fn,
    .name = "lb6-gre6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_gre4_port_node) =
  {
    .function = lb6_gre4_port_node_fn,
    .name = "lb6-gre4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre6_port_node) =
  {
    .function = lb4_gre6_port_node_fn,
    .name = "lb4-gre6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_gre4_port_node) =
  {
    .function = lb4_gre4_port_node_fn,
    .name = "lb4-gre4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_l3dsr_port_node) =
  {
    .function = lb4_l3dsr_port_node_fn,
    .name = "lb4-l3dsr-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_l3dsr_node) =
  {
    .function = lb4_l3dsr_node_fn,
    .name = "lb4-l3dsr",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb6_nat6_port_node) =
  {
    .function = lb6_nat6_port_node_fn,
    .name = "lb6-nat6-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

VLIB_REGISTER_NODE (lb4_nat4_port_node) =
  {
    .function = lb4_nat4_port_node_fn,
    .name = "lb4-nat4-port",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_N_NEXT,
    .next_nodes =
        { [LB_NEXT_DROP] = "error-drop" },
  };

static uword
lb4_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return lb_nodeport_node_fn (vm, node, frame, 1);
}

static uword
lb6_nodeport_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
                      vlib_frame_t * frame)
{
  return lb_nodeport_node_fn (vm, node, frame, 0);
}

VLIB_REGISTER_NODE (lb4_nodeport_node) =
  {
    .function = lb4_nodeport_node_fn,
    .name = "lb4-nodeport",
    .vector_size = sizeof(u32),
    .format_trace = format_nodeport_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB4_NODEPORT_N_NEXT,
    .next_nodes =
        {
            [LB4_NODEPORT_NEXT_IP4_NAT4] = "lb4-nat4-port",
            [LB4_NODEPORT_NEXT_DROP] = "error-drop",
        },
  };

VLIB_REGISTER_NODE (lb6_nodeport_node) =
  {
    .function = lb6_nodeport_node_fn,
    .name = "lb6-nodeport",
    .vector_size = sizeof(u32),
    .format_trace = format_nodeport_lb_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB6_NODEPORT_N_NEXT,
    .next_nodes =
      {
          [LB6_NODEPORT_NEXT_IP6_NAT6] = "lb6-nat6-port",
          [LB6_NODEPORT_NEXT_DROP] = "error-drop",
      },
  };

VNET_FEATURE_INIT (lb_nat4_in2out_node_fn, static) =
  {
    .arc_name = "ip4-unicast",
    .node_name = "lb-nat4-in2out",
    .runs_before =  VNET_FEATURES("ip4-lookup"),
  };

VLIB_REGISTER_NODE (lb_nat4_in2out_node) =
  {
    .function = lb_nat4_in2out_node_fn,
    .name = "lb-nat4-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_nat_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_NAT4_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [LB_NAT4_IN2OUT_NEXT_DROP] = "error-drop",
          [LB_NAT4_IN2OUT_NEXT_LOOKUP] = "ip4-lookup",
      },
  };

VNET_FEATURE_INIT (lb_nat6_in2out_node_fn, static) =
  {
    .arc_name = "ip6-unicast",
    .node_name = "lb-nat6-in2out",
    .runs_before = VNET_FEATURES("ip6-lookup"),
  };

VLIB_REGISTER_NODE (lb_nat6_in2out_node) =
  {
    .function = lb_nat6_in2out_node_fn,
    .name = "lb-nat6-in2out",
    .vector_size = sizeof(u32),
    .format_trace = format_lb_nat_trace,
    .n_errors = LB_N_ERROR,
    .error_strings = lb_error_strings,
    .n_next_nodes = LB_NAT6_IN2OUT_N_NEXT,
    .next_nodes =
      {
          [LB_NAT6_IN2OUT_NEXT_DROP] = "error-drop",
          [LB_NAT6_IN2OUT_NEXT_LOOKUP] = "ip6-lookup",
      },
  };

extern vnet_feature_arc_registration_t vnet_feat_arc_ip4_local;

VLIB_NODE_FN (lb_local4_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 next_index;
  u32 n_left_from, *from, *to_next;

  lb_main_t *lbm = &lb_main;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip4_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
        u32 bi0, bi1, bi2, bi3;
        vlib_buffer_t *b0, *b1, *b2, *b3;

        ip4_header_t *ip0, *ip1, *ip2, *ip3;
        udp_header_t *udp0, *udp1, *udp2, *udp3;

        lb_vip_local4_key_t key0, key1, key2, key3;
        uword *value0, *value1, *value2, *value3;

        u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
        u32 rx_fib_index0, rx_fib_index1, rx_fib_index2, rx_fib_index3;

        u32 vip_index0 = ~0, vip_index1 = ~0, vip_index2 = ~0, vip_index3 = ~0;
        u32 vip_prefix_index0 = ADJ_INDEX_INVALID, vip_prefix_index1 = ADJ_INDEX_INVALID;
        u32 vip_prefix_index2 = ADJ_INDEX_INVALID, vip_prefix_index3 = ADJ_INDEX_INVALID;
        lb_vip_t *vip0, *vip1, *vip2, *vip3;

        u32 next0, next1, next2, next3;

        /* Prefetch next iteration. */
        {
            vlib_buffer_t *p4, *p5, *p6, *p7;

            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);

            vlib_prefetch_buffer_header (p4, LOAD);
            vlib_prefetch_buffer_header (p5, LOAD);
            vlib_prefetch_buffer_header (p6, LOAD);
            vlib_prefetch_buffer_header (p7, LOAD);

            clib_prefetch_load (p4->data);
            clib_prefetch_load (p5->data);
            clib_prefetch_load (p6->data);
            clib_prefetch_load (p7->data);
        }

        to_next[0] = bi0 = from[0];
        to_next[1] = bi1 = from[1];
        to_next[2] = bi2 = from[2];
        to_next[3] = bi3 = from[3];

        from += 4;
        to_next += 4;
        n_left_from -= 4;
        n_left_to_next -= 4;

        b0 = vlib_get_buffer (vm, bi0);
        b1 = vlib_get_buffer (vm, bi1);
        b2 = vlib_get_buffer (vm, bi2);
        b3 = vlib_get_buffer (vm, bi3);

        b0 = vlib_get_buffer (vm, bi0);
        b1 = vlib_get_buffer (vm, bi1);
        b2 = vlib_get_buffer (vm, bi2);
        b3 = vlib_get_buffer (vm, bi3);

        ip0 = vlib_buffer_get_current (b0);
        ip1 = vlib_buffer_get_current (b1);
        ip2 = vlib_buffer_get_current (b2);
        ip3 = vlib_buffer_get_current (b3);

        sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
        sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
        sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX];
        sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX];

        rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);
        rx_fib_index1 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index1);
        rx_fib_index2 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index2);
        rx_fib_index3 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index3);

        vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);
        vnet_get_config_data (&cm->config_main, &b1->current_config_index, &next1, 0);
        vnet_get_config_data (&cm->config_main, &b2->current_config_index, &next2, 0);
        vnet_get_config_data (&cm->config_main, &b3->current_config_index, &next3, 0);

        if (ip0->protocol != IP_PROTOCOL_TCP &&
                ip0->protocol != IP_PROTOCOL_UDP)
            goto trace00;

        udp0 = ip4_next_header (ip0);

        clib_memset(&key0, 0, sizeof(lb_vip_local4_key_t));

        //try search protocol and dst port
        key0.address = ip0->dst_address;
        key0.fib_index = rx_fib_index0;
        key0.protocol = ip0->protocol;
        key0.port = udp0->dst_port;

        value0 = hash_get_mem(lbm->vip_index_by_local4, &(key0));

        if (!value0)
        {
            //try search only address
            key0.protocol = (~0);
            key0.port = 0;
            value0 = hash_get_mem(lbm->vip_index_by_local4, &(key0));
        }

        if (value0)
        {
            vip_index0 = value0[0];
            vip0 = pool_elt_at_index(lbm->vips, vip_index0);
            if (PREDICT_FALSE(!(vip0->flags & LB_VIP_FLAGS_USED)))
                goto trace00;

            switch(vip0->type)
            {
            case LB_VIP_TYPE_IP4_GRE6:
                next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE6 : LB_LOCAL4_NEXT_IP4_GRE6_PORT;
                vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_GRE4:
                next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE4 : LB_LOCAL4_NEXT_IP4_GRE4_PORT;
                vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_L3DSR:
                next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_DSR : LB_LOCAL4_NEXT_IP4_DSR_PORT;
                vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_NAT4:
                next0 = LB_LOCAL4_NEXT_IP4_NAT4;
                vip_prefix_index0 = vip0->vip_prefix_index;
                break;
            default:
                goto trace00;
            }
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = vip_prefix_index0;
        }
trace00:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->rx_sw_if_index = sw_if_index0;
            t->rx_fib_index = rx_fib_index0;
            t->vip_index = vip_index0;
            t->vip_prefix_index = vip_prefix_index0;
            t->next_index = next0;
        }

        if (ip1->protocol != IP_PROTOCOL_TCP &&
                ip1->protocol != IP_PROTOCOL_UDP)
            goto trace01;

        udp1 = ip4_next_header (ip1);

        clib_memset(&key1, 0, sizeof(lb_vip_local4_key_t));

        //try search protocol and dst port
        key1.address = ip1->dst_address;
        key1.fib_index = rx_fib_index1;
        key1.protocol = ip1->protocol;
        key1.port = udp1->dst_port;

        value1 = hash_get_mem(lbm->vip_index_by_local4, &(key1));

        if (!value1)
        {
            //try search only address
            key1.protocol = (~0);
            key1.port = 0;
            value1 = hash_get_mem(lbm->vip_index_by_local4, &(key1));
        }

        if (value1)
        {
            vip_index1 = value1[0];
            vip1 = pool_elt_at_index(lbm->vips, vip_index1);
            if (PREDICT_FALSE(!(vip1->flags & LB_VIP_FLAGS_USED)))
                goto trace01;

            switch(vip1->type)
            {
            case LB_VIP_TYPE_IP4_GRE6:
                next1 = (vip1->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE6 : LB_LOCAL4_NEXT_IP4_GRE6_PORT;
                vip_prefix_index1 = (vip1->port == 0) ? vip_index1 : vip1->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_GRE4:
                next1 = (vip1->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE4 : LB_LOCAL4_NEXT_IP4_GRE4_PORT;
                vip_prefix_index1 = (vip1->port == 0) ? vip_index1 : vip1->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_L3DSR:
                next1 = (vip1->port == 0) ? LB_LOCAL4_NEXT_IP4_DSR : LB_LOCAL4_NEXT_IP4_DSR_PORT;
                vip_prefix_index1 = (vip1->port == 0) ? vip_index1 : vip1->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_NAT4:
                next1 = LB_LOCAL4_NEXT_IP4_NAT4;
                vip_prefix_index1 = vip1->vip_prefix_index;
                break;
            default:
                goto trace01;
            }
            vnet_buffer(b1)->ip.adj_index[VLIB_TX] = vip_prefix_index1;
        }
trace01:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b1->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
            t->rx_sw_if_index = sw_if_index1;
            t->rx_fib_index = rx_fib_index1;
            t->vip_index = vip_index1;
            t->vip_prefix_index = vip_prefix_index1;
            t->next_index = next1;
        }

        if (ip2->protocol != IP_PROTOCOL_TCP &&
                ip2->protocol != IP_PROTOCOL_UDP)
            goto trace02;

        udp2 = ip4_next_header (ip2);

        clib_memset(&key2, 0, sizeof(lb_vip_local4_key_t));

        //try search protocol and dst port
        key2.address = ip2->dst_address;
        key2.fib_index = rx_fib_index2;
        key2.protocol = ip2->protocol;
        key2.port = udp2->dst_port;

        value2 = hash_get_mem(lbm->vip_index_by_local4, &(key2));

        if (!value2)
        {
            //try search only address
            key2.protocol = (~0);
            key2.port = 0;
            value2 = hash_get_mem(lbm->vip_index_by_local4, &(key2));
        }

        if (value2)
        {
            vip_index2 = value2[0];
            vip2 = pool_elt_at_index(lbm->vips, vip_index2);
            if (PREDICT_FALSE(!(vip2->flags & LB_VIP_FLAGS_USED)))
                goto trace02;

            switch(vip2->type)
            {
            case LB_VIP_TYPE_IP4_GRE6:
                next2 = (vip2->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE6 : LB_LOCAL4_NEXT_IP4_GRE6_PORT;
                vip_prefix_index2 = (vip2->port == 0) ? vip_index2 : vip2->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_GRE4:
                next2 = (vip2->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE4 : LB_LOCAL4_NEXT_IP4_GRE4_PORT;
                vip_prefix_index2 = (vip2->port == 0) ? vip_index2 : vip2->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_L3DSR:
                next2 = (vip2->port == 0) ? LB_LOCAL4_NEXT_IP4_DSR : LB_LOCAL4_NEXT_IP4_DSR_PORT;
                vip_prefix_index2 = (vip2->port == 0) ? vip_index2 : vip2->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_NAT4:
                next2 = LB_LOCAL4_NEXT_IP4_NAT4;
                vip_prefix_index2 = vip2->vip_prefix_index;
                break;
            default:
                goto trace02;
            }
            vnet_buffer(b2)->ip.adj_index[VLIB_TX] = vip_prefix_index2;
        }
trace02:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b2->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b2, sizeof (*t));
            t->rx_sw_if_index = sw_if_index2;
            t->rx_fib_index = rx_fib_index2;
            t->vip_index = vip_index2;
            t->vip_prefix_index = vip_prefix_index2;
            t->next_index = next2;
        }

        if (ip3->protocol != IP_PROTOCOL_TCP &&
                ip3->protocol != IP_PROTOCOL_UDP)
            goto trace03;

        udp3 = ip4_next_header (ip3);

        clib_memset(&key3, 0, sizeof(lb_vip_local4_key_t));

        //try search protocol and dst port
        key3.address = ip3->dst_address;
        key3.fib_index = rx_fib_index3;
        key3.protocol = ip3->protocol;
        key3.port = udp3->dst_port;

        value3 = hash_get_mem(lbm->vip_index_by_local4, &(key3));

        if (!value3)
        {
            //try search only address
            key3.protocol = (~0);
            key3.port = 0;
            value3 = hash_get_mem(lbm->vip_index_by_local4, &(key3));
        }

        if (value3)
        {
            vip_index3 = value3[0];
            vip3 = pool_elt_at_index(lbm->vips, vip_index3);
            if (PREDICT_FALSE(!(vip3->flags & LB_VIP_FLAGS_USED)))
                goto trace03;

            switch(vip3->type)
            {
            case LB_VIP_TYPE_IP4_GRE6:
                next3 = (vip3->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE6 : LB_LOCAL4_NEXT_IP4_GRE6_PORT;
                vip_prefix_index3 = (vip3->port == 0) ? vip_index3 : vip3->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_GRE4:
                next3 = (vip3->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE4 : LB_LOCAL4_NEXT_IP4_GRE4_PORT;
                vip_prefix_index3 = (vip3->port == 0) ? vip_index3 : vip3->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_L3DSR:
                next3 = (vip3->port == 0) ? LB_LOCAL4_NEXT_IP4_DSR : LB_LOCAL4_NEXT_IP4_DSR_PORT;
                vip_prefix_index3 = (vip3->port == 0) ? vip_index3 : vip3->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP4_NAT4:
                next3 = LB_LOCAL4_NEXT_IP4_NAT4;
                vip_prefix_index3 = vip3->vip_prefix_index;
                break;
            default:
                goto trace03;
            }
            vnet_buffer(b3)->ip.adj_index[VLIB_TX] = vip_prefix_index3;
        }
trace03:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b3->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b3, sizeof (*t));
            t->rx_sw_if_index = sw_if_index3;
            t->rx_fib_index = rx_fib_index3;
            t->vip_index = vip_index3;
            t->vip_prefix_index = vip_prefix_index3;
            t->next_index = next3;
        }

        vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                to_next, n_left_to_next,
                bi0, bi1, bi2, bi3,
                next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  ip4_header_t *ip0;
	  udp_header_t *udp0;

      lb_vip_local4_key_t key0;
      uword * value0;

	  u32 sw_if_index0;
      u32 rx_fib_index0;

      u32 vip_index0 = ~0;
      u32 vip_prefix_index0 = ADJ_INDEX_INVALID;
      lb_vip_t *vip0;

	  u32 next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip4_fib_table_get_index_for_sw_if_index (sw_if_index0);

      vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);

      if (ip0->protocol != IP_PROTOCOL_TCP &&
          ip0->protocol != IP_PROTOCOL_UDP)
          goto trace0;

      udp0 = ip4_next_header (ip0);

      clib_memset(&key0, 0, sizeof(lb_vip_local4_key_t));

      //try search protocol and dst port
      key0.address = ip0->dst_address;
      key0.fib_index = rx_fib_index0;
      key0.protocol = ip0->protocol;
      key0.port = udp0->dst_port;

      value0 = hash_get_mem(lbm->vip_index_by_local4, &(key0));

      if (!value0)
      {
          //try search only address
          key0.protocol = (~0);
          key0.port = 0;
          value0 = hash_get_mem(lbm->vip_index_by_local4, &(key0));
      }

      if (value0)
      {
          vip_index0 = value0[0];
          vip0 = pool_elt_at_index(lbm->vips, vip_index0);
          if (PREDICT_FALSE(!(vip0->flags & LB_VIP_FLAGS_USED)))
              goto trace0;

          switch(vip0->type)
          {
          case LB_VIP_TYPE_IP4_GRE6:
              next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE6 : LB_LOCAL4_NEXT_IP4_GRE6_PORT;
              vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
              break;
          case LB_VIP_TYPE_IP4_GRE4:
              next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_GRE4 : LB_LOCAL4_NEXT_IP4_GRE4_PORT;
              vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
              break;
          case LB_VIP_TYPE_IP4_L3DSR:
              next0 = (vip0->port == 0) ? LB_LOCAL4_NEXT_IP4_DSR : LB_LOCAL4_NEXT_IP4_DSR_PORT;
              vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
              break;
          case LB_VIP_TYPE_IP4_NAT4:
              next0 = LB_LOCAL4_NEXT_IP4_NAT4;
              vip_prefix_index0 = vip0->vip_prefix_index;
              break;
          default:
              goto trace0;
          }
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = vip_prefix_index0;
      }
trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                        (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lb_local_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = sw_if_index0;
	      t->rx_fib_index = rx_fib_index0;
          t->vip_index = vip_index0;
          t->vip_prefix_index = vip_prefix_index0;
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

extern vnet_feature_arc_registration_t vnet_feat_arc_ip6_local;

VLIB_NODE_FN (lb_local6_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 next_index;
  u32 n_left_from, *from, *to_next;

  lb_main_t *lbm = &lb_main;
  vnet_feature_main_t *fm = &feature_main;
  u8 arc_index = vnet_feat_arc_ip6_local.feature_arc_index;
  vnet_feature_config_main_t *cm = &fm->feature_config_mains[arc_index];

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
        u32 bi0, bi1, bi2, bi3;
        vlib_buffer_t *b0, *b1, *b2, *b3;

        ip6_header_t *ip0, *ip1, *ip2, *ip3;
        udp_header_t *udp0, *udp1, *udp2, *udp3;

        lb_vip_local4_key_t key0, key1, key2, key3;
        uword *value0, *value1, *value2, *value3;

        u32 sw_if_index0, sw_if_index1, sw_if_index2, sw_if_index3;
        u32 rx_fib_index0, rx_fib_index1, rx_fib_index2, rx_fib_index3;

        u32 vip_index0 = ~0, vip_index1 = ~0, vip_index2 = ~0, vip_index3 = ~0;
        u32 vip_prefix_index0 = ADJ_INDEX_INVALID, vip_prefix_index1 = ADJ_INDEX_INVALID;
        u32 vip_prefix_index2 = ADJ_INDEX_INVALID, vip_prefix_index3 = ADJ_INDEX_INVALID;
        lb_vip_t *vip0, *vip1, *vip2, *vip3;

        u32 next0, next1, next2, next3;

        u8 l4_protocol0, l4_protocol1, l4_protocol2, l4_protocol3;
        u16 l4_offset0, l4_offset1, l4_offset2, l4_offset3;
        u16 frag_hdr_offset0, frag_hdr_offset1, frag_hdr_offset2, frag_hdr_offset3;

        /* Prefetch next iteration. */
        {
            vlib_buffer_t *p4, *p5, *p6, *p7;

            p4 = vlib_get_buffer (vm, from[4]);
            p5 = vlib_get_buffer (vm, from[5]);
            p6 = vlib_get_buffer (vm, from[6]);
            p7 = vlib_get_buffer (vm, from[7]);

            vlib_prefetch_buffer_header (p4, LOAD);
            vlib_prefetch_buffer_header (p5, LOAD);
            vlib_prefetch_buffer_header (p6, LOAD);
            vlib_prefetch_buffer_header (p7, LOAD);

            clib_prefetch_load (p4->data);
            clib_prefetch_load (p5->data);
            clib_prefetch_load (p6->data);
            clib_prefetch_load (p7->data);
        }

        to_next[0] = bi0 = from[0];
        to_next[1] = bi1 = from[1];
        to_next[2] = bi2 = from[2];
        to_next[3] = bi3 = from[3];

        from += 4;
        to_next += 4;
        n_left_from -= 4;
        n_left_to_next -= 4;

        b0 = vlib_get_buffer (vm, bi0);
        b1 = vlib_get_buffer (vm, bi1);
        b2 = vlib_get_buffer (vm, bi2);
        b3 = vlib_get_buffer (vm, bi3);

        b0 = vlib_get_buffer (vm, bi0);
        b1 = vlib_get_buffer (vm, bi1);
        b2 = vlib_get_buffer (vm, bi2);
        b3 = vlib_get_buffer (vm, bi3);

        ip0 = vlib_buffer_get_current (b0);
        ip1 = vlib_buffer_get_current (b1);
        ip2 = vlib_buffer_get_current (b2);
        ip3 = vlib_buffer_get_current (b3);

        sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
        sw_if_index1 = vnet_buffer (b1)->sw_if_index[VLIB_RX];
        sw_if_index2 = vnet_buffer (b2)->sw_if_index[VLIB_RX];
        sw_if_index3 = vnet_buffer (b3)->sw_if_index[VLIB_RX];

        rx_fib_index0 = ip6_fib_table_get_index_for_sw_if_index (sw_if_index0);
        rx_fib_index1 = ip6_fib_table_get_index_for_sw_if_index (sw_if_index1);
        rx_fib_index2 = ip6_fib_table_get_index_for_sw_if_index (sw_if_index2);
        rx_fib_index3 = ip6_fib_table_get_index_for_sw_if_index (sw_if_index3);

        vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);
        vnet_get_config_data (&cm->config_main, &b1->current_config_index, &next1, 0);
        vnet_get_config_data (&cm->config_main, &b2->current_config_index, &next2, 0);
        vnet_get_config_data (&cm->config_main, &b3->current_config_index, &next3, 0);

        if (PREDICT_FALSE (ip6_parse (vm, b0, ip0, b0->current_length,
                        &l4_protocol0, &l4_offset0, &frag_hdr_offset0)))
            goto trace00;

        if (PREDICT_FALSE(frag_hdr_offset0))
            goto trace00;

        if (l4_protocol0 != IP_PROTOCOL_TCP &&
                l4_protocol0 != IP_PROTOCOL_UDP)
            goto trace00;


        udp0 = (udp_header_t *) u8_ptr_add (ip0, l4_offset0);

        clib_memset(&key0, 0, sizeof(lb_vip_local6_key_t));

        //try search protocol and dst port
        clib_memcpy(&key0.address, &ip0->dst_address, sizeof(ip6_address_t));
        key0.fib_index = rx_fib_index0;
        key0.protocol = l4_protocol0;
        key0.port = udp0->dst_port;

        value0 = hash_get_mem(lbm->vip_index_by_local6, &(key0));
        if (!value0)
        {
            //try search only address
            key0.protocol = (~0);
            key0.port = 0;
            value0 = hash_get_mem(lbm->vip_index_by_local6, &(key0));
        }

        if (value0)
        {
            vip_index0 = value0[0];
            vip0 = pool_elt_at_index(lbm->vips, vip_index0);

            if (PREDICT_FALSE(vip0->flags & LB_VIP_FLAGS_USED))
                goto trace00;

            switch(vip0->type)
            {
            case LB_VIP_TYPE_IP6_GRE6:
                next0 = (vip0->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE6 : LB_LOCAL6_NEXT_IP6_GRE6_PORT;
                vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_GRE4:
                next0 = (vip0->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE4 : LB_LOCAL6_NEXT_IP6_GRE4_PORT;
                vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_NAT6:
                next0 = LB_LOCAL6_NEXT_IP6_NAT6;
                vip_prefix_index0 = vip0->vip_prefix_index;
                break;
            default:
                goto trace00;
            }
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = vip_prefix_index0;
        }
trace00:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b0->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
            t->rx_sw_if_index = sw_if_index0;
            t->rx_fib_index = rx_fib_index0;
            t->vip_index = vip_index0;
            t->vip_prefix_index = vip_prefix_index0;
            t->next_index = next0;
        }

        if (PREDICT_FALSE (ip6_parse (vm, b1, ip1, b1->current_length,
                        &l4_protocol1, &l4_offset1, &frag_hdr_offset1)))
            goto trace01;

        if (PREDICT_FALSE(frag_hdr_offset1))
            goto trace01;

        if (l4_protocol1 != IP_PROTOCOL_TCP &&
                l4_protocol1 != IP_PROTOCOL_UDP)
            goto trace01;


        udp1 = (udp_header_t *) u8_ptr_add (ip1, l4_offset1);

        clib_memset(&key1, 0, sizeof(lb_vip_local6_key_t));

        //try search protocol and dst port
        clib_memcpy(&key1.address, &ip1->dst_address, sizeof(ip6_address_t));
        key1.fib_index = rx_fib_index1;
        key1.protocol = l4_protocol1;
        key1.port = udp1->dst_port;

        value1 = hash_get_mem(lbm->vip_index_by_local6, &(key1));
        if (!value1)
        {
            //try search only address
            key1.protocol = (~0);
            key1.port = 0;
            value1 = hash_get_mem(lbm->vip_index_by_local6, &(key1));
        }

        if (value1)
        {
            vip_index1 = value1[0];
            vip1 = pool_elt_at_index(lbm->vips, vip_index1);

            if (PREDICT_FALSE(vip1->flags & LB_VIP_FLAGS_USED))
                goto trace01;

            switch(vip1->type)
            {
            case LB_VIP_TYPE_IP6_GRE6:
                next1 = (vip1->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE6 : LB_LOCAL6_NEXT_IP6_GRE6_PORT;
                vip_prefix_index1 = (vip1->port == 0) ? vip_index1 : vip1->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_GRE4:
                next1 = (vip1->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE4 : LB_LOCAL6_NEXT_IP6_GRE4_PORT;
                vip_prefix_index1 = (vip1->port == 0) ? vip_index1 : vip1->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_NAT6:
                next1 = LB_LOCAL6_NEXT_IP6_NAT6;
                vip_prefix_index1 = vip1->vip_prefix_index;
                break;
            default:
                goto trace01;
            }
            vnet_buffer(b1)->ip.adj_index[VLIB_TX] = vip_prefix_index1;
        }
trace01:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b1->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
            t->rx_sw_if_index = sw_if_index1;
            t->rx_fib_index = rx_fib_index1;
            t->vip_index = vip_index1;
            t->vip_prefix_index = vip_prefix_index1;
            t->next_index = next1;
        }

        if (PREDICT_FALSE (ip6_parse (vm, b2, ip2, b2->current_length,
                        &l4_protocol2, &l4_offset2, &frag_hdr_offset2)))
            goto trace02;

        if (PREDICT_FALSE(frag_hdr_offset2))
            goto trace02;

        if (l4_protocol2 != IP_PROTOCOL_TCP &&
                l4_protocol2 != IP_PROTOCOL_UDP)
            goto trace02;


        udp2 = (udp_header_t *) u8_ptr_add (ip2, l4_offset2);

        clib_memset(&key2, 0, sizeof(lb_vip_local6_key_t));

        //try search protocol and dst port
        clib_memcpy(&key2.address, &ip2->dst_address, sizeof(ip6_address_t));
        key2.fib_index = rx_fib_index2;
        key2.protocol = l4_protocol2;
        key2.port = udp2->dst_port;

        value2 = hash_get_mem(lbm->vip_index_by_local6, &(key2));
        if (!value2)
        {
            //try search only address
            key2.protocol = (~0);
            key2.port = 0;
            value2 = hash_get_mem(lbm->vip_index_by_local6, &(key2));
        }

        if (value2)
        {
            vip_index2 = value2[0];
            vip2 = pool_elt_at_index(lbm->vips, vip_index2);

            if (PREDICT_FALSE(vip2->flags & LB_VIP_FLAGS_USED))
                goto trace02;

            switch(vip2->type)
            {
            case LB_VIP_TYPE_IP6_GRE6:
                next2 = (vip2->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE6 : LB_LOCAL6_NEXT_IP6_GRE6_PORT;
                vip_prefix_index2 = (vip2->port == 0) ? vip_index2 : vip2->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_GRE4:
                next2 = (vip2->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE4 : LB_LOCAL6_NEXT_IP6_GRE4_PORT;
                vip_prefix_index2 = (vip2->port == 0) ? vip_index2 : vip2->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_NAT6:
                next2 = LB_LOCAL6_NEXT_IP6_NAT6;
                vip_prefix_index2 = vip2->vip_prefix_index;
                break;
            default:
                goto trace02;
            }
            vnet_buffer(b2)->ip.adj_index[VLIB_TX] = vip_prefix_index2;
        }
trace02:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b2->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b2, sizeof (*t));
            t->rx_sw_if_index = sw_if_index2;
            t->rx_fib_index = rx_fib_index2;
            t->vip_index = vip_index2;
            t->vip_prefix_index = vip_prefix_index2;
            t->next_index = next2;
        }

        if (PREDICT_FALSE (ip6_parse (vm, b3, ip3, b3->current_length,
                        &l4_protocol3, &l4_offset3, &frag_hdr_offset3)))
            goto trace03;

        if (PREDICT_FALSE(frag_hdr_offset3))
            goto trace03;

        if (l4_protocol3 != IP_PROTOCOL_TCP &&
                l4_protocol3 != IP_PROTOCOL_UDP)
            goto trace03;


        udp3 = (udp_header_t *) u8_ptr_add (ip3, l4_offset3);

        clib_memset(&key3, 0, sizeof(lb_vip_local6_key_t));

        //try search protocol and dst port
        clib_memcpy(&key3.address, &ip3->dst_address, sizeof(ip6_address_t));
        key3.fib_index = rx_fib_index3;
        key3.protocol = l4_protocol3;
        key3.port = udp3->dst_port;

        value3 = hash_get_mem(lbm->vip_index_by_local6, &(key3));
        if (!value3)
        {
            //try search only address
            key3.protocol = (~0);
            key3.port = 0;
            value3 = hash_get_mem(lbm->vip_index_by_local6, &(key3));
        }

        if (value3)
        {
            vip_index3 = value3[0];
            vip3 = pool_elt_at_index(lbm->vips, vip_index3);

            if (PREDICT_FALSE(vip3->flags & LB_VIP_FLAGS_USED))
                goto trace03;

            switch(vip3->type)
            {
            case LB_VIP_TYPE_IP6_GRE6:
                next3 = (vip3->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE6 : LB_LOCAL6_NEXT_IP6_GRE6_PORT;
                vip_prefix_index3 = (vip3->port == 0) ? vip_index3 : vip3->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_GRE4:
                next3 = (vip3->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE4 : LB_LOCAL6_NEXT_IP6_GRE4_PORT;
                vip_prefix_index3 = (vip3->port == 0) ? vip_index3 : vip3->vip_prefix_index;
                break;
            case LB_VIP_TYPE_IP6_NAT6:
                next3 = LB_LOCAL6_NEXT_IP6_NAT6;
                vip_prefix_index3 = vip3->vip_prefix_index;
                break;
            default:
                goto trace03;
            }
            vnet_buffer(b3)->ip.adj_index[VLIB_TX] = vip_prefix_index3;
        }
trace03:
        if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                    (b3->flags & VLIB_BUFFER_IS_TRACED)))
        {
            lb_local_trace_t *t = vlib_add_trace (vm, node, b3, sizeof (*t));
            t->rx_sw_if_index = sw_if_index3;
            t->rx_fib_index = rx_fib_index3;
            t->vip_index = vip_index3;
            t->vip_prefix_index = vip_prefix_index3;
            t->next_index = next3;
        }

        vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
                to_next, n_left_to_next,
                bi0, bi1, bi2, bi3,
                next0, next1, next2, next3);
	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;

	  ip6_header_t *ip0;
	  udp_header_t *udp0;

      lb_vip_local6_key_t key0;
      uword * value0;

	  u32 sw_if_index0;
      u32 rx_fib_index0;

      u32 vip_index0 = ~0;
      u32 vip_prefix_index0 = ADJ_INDEX_INVALID;
      lb_vip_t *vip0;

	  u32 next0;

	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip0 = vlib_buffer_get_current (b0);
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
      rx_fib_index0 = ip6_fib_table_get_index_for_sw_if_index (sw_if_index0);

      vnet_get_config_data (&cm->config_main, &b0->current_config_index, &next0, 0);

      u8 l4_protocol;
      u16 l4_offset, frag_hdr_offset;

      if (PREDICT_FALSE (ip6_parse (vm, b0, ip0, b0->current_length,
                      &l4_protocol, &l4_offset, &frag_hdr_offset)))
          goto trace0;

      if (PREDICT_FALSE(frag_hdr_offset))
          goto trace0;

      if (l4_protocol != IP_PROTOCOL_TCP &&
          l4_protocol != IP_PROTOCOL_UDP)
          goto trace0;


      udp0 = (udp_header_t *) u8_ptr_add (ip0, l4_offset);

      clib_memset(&key0, 0, sizeof(lb_vip_local6_key_t));

      //try search protocol and dst port
      clib_memcpy(&key0.address, &ip0->dst_address, sizeof(ip6_address_t));
      key0.fib_index = rx_fib_index0;
      key0.protocol = l4_protocol;
      key0.port = udp0->dst_port;

      value0 = hash_get_mem(lbm->vip_index_by_local6, &(key0));
      if (!value0)
      {
          //try search only address
          key0.protocol = (~0);
          key0.port = 0;
          value0 = hash_get_mem(lbm->vip_index_by_local6, &(key0));
      }

      if (value0)
      {
          vip_index0 = value0[0];
          vip0 = pool_elt_at_index(lbm->vips, vip_index0);

          if (PREDICT_FALSE(vip0->flags & LB_VIP_FLAGS_USED))
              goto trace0;

          switch(vip0->type)
          {
          case LB_VIP_TYPE_IP6_GRE6:
              next0 = (vip0->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE6 : LB_LOCAL6_NEXT_IP6_GRE6_PORT;
              vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
              break;
          case LB_VIP_TYPE_IP6_GRE4:
              next0 = (vip0->port == 0) ? LB_LOCAL6_NEXT_IP6_GRE4 : LB_LOCAL6_NEXT_IP6_GRE4_PORT;
              vip_prefix_index0 = (vip0->port == 0) ? vip_index0 : vip0->vip_prefix_index;
              break;
          case LB_VIP_TYPE_IP6_NAT6:
              next0 = LB_LOCAL6_NEXT_IP6_NAT6;
              vip_prefix_index0 = vip0->vip_prefix_index;
              break;
          default:
              goto trace0;
          }
          vnet_buffer(b0)->ip.adj_index[VLIB_TX] = vip_prefix_index0;
      }
trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE) &&
                        (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      lb_local_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->rx_sw_if_index = sw_if_index0;
	      t->rx_fib_index = rx_fib_index0;
          t->vip_index = vip_index0;
          t->vip_prefix_index = vip_prefix_index0;
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VNET_FEATURE_INIT (lb_local4_node_fn, static) =
  {
    .arc_name = "ip4-local",
    .node_name = "lb-local4-input",
    .runs_before = VNET_FEATURES ("ip4-local-end-of-arc"),
  };

VNET_FEATURE_INIT (lb_local6_node_fn, static) =
  {
    .arc_name = "ip6-local",
    .node_name = "lb-local6-input",
    .runs_before = VNET_FEATURES ("ip6-local-end-of-arc"),
  };

VLIB_REGISTER_NODE (lb_local4_node) = {
  .name = "lb-local4-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_lb_local_trace,
  .n_next_nodes = LB_LOCAL4_N_NEXT,
  .next_nodes = {
    [LB_LOCAL4_NEXT_DROP] = "error-drop",
    [LB_LOCAL4_NEXT_LOOKUP] = "ip4-lookup",
    [LB_LOCAL4_NEXT_IP4_NAT4] = "lb4-nat4-port",
    [LB_LOCAL4_NEXT_IP4_GRE4] = "lb4-gre4",
    [LB_LOCAL4_NEXT_IP4_GRE6] = "lb4-gre6",
    [LB_LOCAL4_NEXT_IP4_GRE4_PORT] = "lb4-gre4-port",
    [LB_LOCAL4_NEXT_IP4_GRE6_PORT] = "lb4-gre6-port",
    [LB_LOCAL4_NEXT_IP4_DSR] = "lb4-l3dsr",
    [LB_LOCAL4_NEXT_IP4_DSR_PORT] = "lb4-l3dsr-port",
  },
};

VLIB_REGISTER_NODE (lb_local6_node) = {
  .name = "lb-local6-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_lb_local_trace,
  .n_next_nodes = LB_LOCAL6_N_NEXT,
  .next_nodes = {
    [LB_LOCAL6_NEXT_DROP] = "error-drop",
    [LB_LOCAL6_NEXT_LOOKUP] = "ip6-lookup",
    [LB_LOCAL6_NEXT_IP6_NAT6] = "lb6-nat6-port",
    [LB_LOCAL6_NEXT_IP6_GRE4] = "lb6-gre4",
    [LB_LOCAL6_NEXT_IP6_GRE6] = "lb6-gre6",
    [LB_LOCAL6_NEXT_IP6_GRE4_PORT] = "lb6-gre4-port",
    [LB_LOCAL6_NEXT_IP6_GRE6_PORT] = "lb6-gre6-port",
  },
};
