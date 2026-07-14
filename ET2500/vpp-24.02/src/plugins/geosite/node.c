/*
 * node.c - skeleton vpp engine plug-in dual-loop node skeleton
 *
 * Copyright (c) <2024-2027> <Asterfusion Network>
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <geosite/geosite.h>


#define DNS_DPORT 53
#define DNS_MAX_PACKET_SIZE 512
#define DNS_MAX_DOMAIN_LEN 256
#define DNS_MAX_LABELS 128
#define DNS_MAX_JUMPS 5
#define DNS_TYPE_A 1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1
#define DNS_RESPONSE_DELAY_DELETE_SEC 30

#define QUIC_LONG_HEADER_FORM 0x80
#define QUIC_INITIAL_PACKET 0x00
#define QUIC_VERSION_1 0x00000001

        
typedef struct 
{
  u32 next_index;
  u32 sw_if_index;
  char domain[DNS_MAX_DOMAIN_LEN];
  
} geosite_trace_t;

#ifndef CLIB_MARCH_VARIANT

/* packet trace format function */
static u8 * format_geosite_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  geosite_trace_t * t = va_arg (*args, geosite_trace_t *);
  
  s = format (s, "GEOSITE: sw_if_index %d, next index %d\n",
              t->sw_if_index, t->next_index);
  s = format (s, "  domain : %s",t->domain);
              
  return s;
}

vlib_node_registration_t geosite_node;

#endif /* CLIB_MARCH_VARIANT */

#define foreach_geosite_error \
_(SWAPPED, "Mac swap packets processed")

typedef enum {
#define _(sym,str) GEOSITE_ERROR_##sym,
  foreach_geosite_error
#undef _
  GEOSITE_N_ERROR,
} geosite_error_t;

#ifndef CLIB_MARCH_VARIANT
static char * geosite_error_strings[] = 
{
#define _(sym,string) string,
  foreach_geosite_error
#undef _
};
#endif /* CLIB_MARCH_VARIANT */

typedef enum 
{
  GEOSITE_NEXT_DROP,
  GEOSITE_N_NEXT,
} geosite_next_t;


static_always_inline u16
get_ip6_tcp_udp_payload_offset(vlib_buffer_t *b, ip6_header_t *ip6, u16 *sport,
                               u16 *dport, u16 *payload_length,
                               u16 ip6_payload_length)
{
  ip6_ext_hdr_chain_t hdr_chain;
  //u16 payload_offset = 0;
  u8 *l3_start = (u8 *)ip6;
  
  
  int transport_index = ip6_ext_header_walk(b, ip6, -1, &hdr_chain);
  
  if (transport_index < 0) {
   
    return 0;
  }
  
  
  u8 transport_proto = hdr_chain.eh[transport_index].protocol;
  
  u16 transport_offset = hdr_chain.eh[transport_index].offset;
  
  u8 *transport_header = l3_start + transport_offset;
  

  if(transport_proto == IP_PROTOCOL_TCP )
    {
       tcp_header_t *tcp = (tcp_header_t *)transport_header;
      
      u8 tcp_header_len = (tcp->data_offset_and_reserved >> 4) * 4;
      *sport =  clib_net_to_host_u16(tcp->src_port);
      *dport =  clib_net_to_host_u16(tcp->dst_port);
      *payload_length = ip6_payload_length - tcp_header_len-transport_offset;
      return tcp_header_len + transport_offset;
    
      
      }
    else if (transport_proto == IP_PROTOCOL_UDP)
      {
        udp_header_t *udp = (udp_header_t *)transport_header;
        *sport =  clib_net_to_host_u16(udp->src_port);
        *dport =  clib_net_to_host_u16(udp->dst_port);
        *payload_length = ip6_payload_length - sizeof(udp_header_t)-transport_offset;
        return  transport_offset+ sizeof(udp_header_t);
      }

    return 0;
  
  

}

static_always_inline void
get_l4_payload_offset(vlib_buffer_t *b, u8 *payload_offset, u8 *ip_proto_,
                      u16 *sport, u16 *dport,u16 *payload_length)
{
  ethernet_header_t *eh;
  ip4_header_t *ip4h;
  ip6_header_t *ip6h;
  ethernet_vlan_header_t *vlanh;
  i16 l3_hdr_offset;
  i16 l4_hdr_offset;
  u16 type;
  u8 ip_proto;
//  u8 *current_header;
  u16 current_offset;

  eh = ethernet_buffer_get_header(b);
  type = clib_net_to_host_u16(eh->type);
  l3_hdr_offset = sizeof(ethernet_header_t);

  if (type == ETHERNET_TYPE_VLAN)
  {
    vlanh = (ethernet_vlan_header_t *)(eh + 1);
    type = clib_net_to_host_u16(vlanh->type);
    l3_hdr_offset += sizeof(ethernet_vlan_header_t);
    
  }

  if (b->flags & VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
  {
    l3_hdr_offset = vnet_buffer(b)->l3_hdr_offset;
  }

  if (PREDICT_TRUE(type == ETHERNET_TYPE_IP4))
  {
    ip4h = (ip4_header_t *)(b->data + l3_hdr_offset);
    ip_proto = ip4h->protocol;

    u8 ip_header_len = (ip4h->ip_version_and_header_length & 0x0F) * 4;
    l4_hdr_offset = l3_hdr_offset + ip_header_len;
    *ip_proto_ = ip_proto;
   
    if (ip_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *)(b->data + l4_hdr_offset);

      u8 tcp_header_len = (tcp->data_offset_and_reserved >> 4) * 4;
      *payload_offset = l4_hdr_offset + tcp_header_len;
       *sport =  clib_net_to_host_u16(tcp->src_port);
       *dport =  clib_net_to_host_u16(tcp->dst_port);
        *payload_length = clib_net_to_host_u16(ip4h->length) - ip_header_len - tcp_header_len;
    }
    else if (ip_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *)(b->data + l4_hdr_offset);
      *payload_offset = l4_hdr_offset + sizeof(udp_header_t);
      *sport =  clib_net_to_host_u16(udp->src_port);
      *dport =  clib_net_to_host_u16(udp->dst_port);
      *payload_length = clib_net_to_host_u16(udp->length) - sizeof(udp_header_t);
    }
    else
    {

      *payload_offset = 0;
    }
  }
  else if (PREDICT_TRUE(type == ETHERNET_TYPE_IP6))
  {
    u16 payload_offset_from_ip6 = 0;
     
    ip6h = (ip6_header_t *)(b->data + l3_hdr_offset);
    ip_proto = ip6h->protocol;

    current_offset = l3_hdr_offset + sizeof(ip6_header_t);
   // current_header = b->data + current_offset;
    *ip_proto_ = ip_proto;
    if (ip_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *)(b->data + current_offset);

      u8 tcp_header_len = (tcp->data_offset_and_reserved >> 4) * 4;
      *payload_offset = current_offset + tcp_header_len;
       *sport =  clib_net_to_host_u16(tcp->src_port);
       *dport =  clib_net_to_host_u16(tcp->dst_port);
       *payload_length = clib_net_to_host_u16(ip6h->payload_length) - tcp_header_len;
    }
    else if (ip_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *)(b->data + current_offset);
      *payload_offset = current_offset + sizeof(udp_header_t);
      *sport =  clib_net_to_host_u16(udp->src_port);
      *dport =  clib_net_to_host_u16(udp->dst_port);
       *payload_length = clib_net_to_host_u16(ip6h->payload_length) - sizeof(udp_header_t);
    }
    else
      {   
          payload_offset_from_ip6 =
            get_ip6_tcp_udp_payload_offset(b, ip6h, sport, dport,
                                           payload_length,
                                           ip6h->payload_length);
          if (payload_offset_from_ip6 > 0) {
            *payload_offset = payload_offset_from_ip6 + l3_hdr_offset+ sizeof(ip6_header_t);
          } else {
            *payload_offset = 0;
          }
      }
  }

  else
  {
    *payload_offset = 0;
    return;
  }


}



static int
geosite_dns_read_name (u8 *dns, u8 *end, u8 *pos, char *domain,
		       u16 *domain_length, u8 **next)
{
    u8 *p = pos;
    int domain_len = 0;
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

            if (jumps++ >= DNS_MAX_JUMPS)
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

        if (domain_len + label_len + 1 >= DNS_MAX_DOMAIN_LEN)
            return -1;

        clib_memcpy (domain + domain_len, p, label_len);
        domain_len += label_len;
        domain[domain_len++] = '.';
        p += label_len;
    }

    return -1;
}

static int
geosite_resolved_entry_is_stale (clib_bihash_kv_16_8_t *kv, void *arg)
{
    geosite_main_t *gmp = &geosite_main;
    u32 now_sec = pointer_to_uword (arg);
    u32 pool_index = (u32) kv->value;
    geosite_resolved_entry_t *entry;
    u32 i;

    if (pool_is_free_index (gmp->resolved_pool, pool_index))
    {
        return 1;
    }

    entry = pool_elt_at_index (gmp->resolved_pool, pool_index);
    for (i = 0; i < GEOSITE_RESOLVED_MAX_REFS; i++)
    {
        if ((entry->ref_bitmap & (1u << i)) == 0)
            continue;

        if (now_sec < entry->refs[i].expire_time_sec +
                      DNS_RESPONSE_DELAY_DELETE_SEC)
            return 0;
    }

    pool_put_index (gmp->resolved_pool, pool_index);
    return 1;
}

static int
geosite_resolved_entry_update (geosite_resolved_entry_t *entry,
			       u32 geosite_index, u32 expire_time_sec,
			       u32 now_sec)
{
    i32 free_slot = -1;
    u32 i;

    for (i = 0; i < GEOSITE_RESOLVED_MAX_REFS; i++)
    {
        if ((entry->ref_bitmap & (1u << i)) == 0)
        {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }

        if (now_sec >= entry->refs[i].expire_time_sec)
        {
            entry->ref_bitmap &= ~(1u << i);
            if (free_slot < 0)
                free_slot = i;
            continue;
        }

        if (entry->refs[i].geosite_index == geosite_index)
        {
            entry->refs[i].expire_time_sec = expire_time_sec;
            return 0;
        }
    }

    if (free_slot < 0)
    {
        clib_warning ("geosite resolved ip update failed: refs full "
                      "geosite_index=%u ref_bitmap=0x%08x now=%u expire=%u",
                      geosite_index, entry->ref_bitmap, now_sec,
                      expire_time_sec);
        return -1;
    }

    entry->refs[free_slot].geosite_index = geosite_index;
    entry->refs[free_slot].expire_time_sec = expire_time_sec;
    entry->ref_bitmap |= (1u << free_slot);
    return 0;
}

static int
geosite_resolved_ip_add (clib_bihash_kv_16_8_t *key, u32 geosite_index,
			 u32 expire_time_sec, u32 now_sec)
{
    geosite_main_t *gmp = &geosite_main;
    clib_bihash_kv_16_8_t result;
    geosite_resolved_entry_t *entry;
    u32 pool_index;
    int rv;

    if (clib_bihash_search_16_8 (&gmp->resolved_ip_hash, key, &result) == 0)
    {
        pool_index = (u32) result.value;
        if (pool_is_free_index (gmp->resolved_pool, pool_index))
        {
            clib_warning ("geosite resolved ip add failed: stale pool index "
                          "pool_index=%u geosite_index=%u",
                          pool_index, geosite_index);
            return -1;
        }

        entry = pool_elt_at_index (gmp->resolved_pool, pool_index);
        rv = geosite_resolved_entry_update (entry, geosite_index,
                                            expire_time_sec, now_sec);
        if (rv != 0)
        {
            clib_warning ("geosite resolved ip add failed: update existing "
                          "geosite_index=%u rv=%d",
                          geosite_index, rv);
        }
        return rv;
    }

    clib_spinlock_lock (&gmp->resolved_pool_lock);

    if (clib_bihash_search_16_8 (&gmp->resolved_ip_hash, key, &result) == 0)
    {
        pool_index = (u32) result.value;
        clib_spinlock_unlock (&gmp->resolved_pool_lock);

        if (pool_is_free_index (gmp->resolved_pool, pool_index))
        {
            clib_warning ("geosite resolved ip add failed: stale pool index "
                          "after lock pool_index=%u geosite_index=%u",
                          pool_index, geosite_index);
            return -1;
        }

        entry = pool_elt_at_index (gmp->resolved_pool, pool_index);
        rv = geosite_resolved_entry_update (entry, geosite_index,
                                            expire_time_sec, now_sec);
        if (rv != 0)
        {
            clib_warning ("geosite resolved ip add failed: update existing "
                          "after lock geosite_index=%u rv=%d",
                          geosite_index, rv);
        }
        return rv;
    }

    if (pool_elts (gmp->resolved_pool) >= gmp->resolved_pool_max_entries)
    {
        clib_warning ("geosite resolved ip add failed: pool full "
                      "pool_elts=%u max=%u geosite_index=%u",
                      (u32) pool_elts (gmp->resolved_pool),
                      gmp->resolved_pool_max_entries, geosite_index);
        clib_spinlock_unlock (&gmp->resolved_pool_lock);
        return -1;
    }

    pool_get (gmp->resolved_pool, entry);
    clib_memset (entry, 0, sizeof (*entry));
    pool_index = entry - gmp->resolved_pool;

    rv = geosite_resolved_entry_update (entry, geosite_index,
                                        expire_time_sec, now_sec);
    if (rv != 0)
    {
        clib_warning ("geosite resolved ip add failed: init new entry "
                      "geosite_index=%u rv=%d",
                      geosite_index, rv);
        pool_put (gmp->resolved_pool, entry);
        clib_spinlock_unlock (&gmp->resolved_pool_lock);
        return rv;
    }

    key->value = pool_index;
    rv = clib_bihash_add_or_overwrite_stale_16_8 (
        &gmp->resolved_ip_hash, key, geosite_resolved_entry_is_stale,
        uword_to_pointer ((uword) now_sec, void *));
    if (rv != 0)
    {
        clib_warning ("geosite resolved ip add failed: hash add "
                      "pool_index=%u geosite_index=%u rv=%d",
                      pool_index, geosite_index, rv);
        pool_put (gmp->resolved_pool, entry);
        clib_spinlock_unlock (&gmp->resolved_pool_lock);
        return -1;
    }

    clib_spinlock_unlock (&gmp->resolved_pool_lock);
    return 0;
}

static void
geosite_dns_response_learn (vlib_main_t *vm, u8 *payload, u16 payload_length)
{
    dns_header_t_ *dns;
    u8 *end = payload + payload_length;
    u8 *pos;
    char qname[DNS_MAX_DOMAIN_LEN];
    u16 qname_len = 0;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u32 *cc_indices;
    u32 *cc;
    u32 now_sec = (u32) vlib_time_now (vm);
    u16 i;

    if (payload_length < sizeof (*dns))
    {
        return;
    }

    dns = (dns_header_t_ *) payload;
    flags = clib_net_to_host_u16 (dns->flags);
    qdcount = clib_net_to_host_u16 (dns->qdcount);
    ancount = clib_net_to_host_u16 (dns->ancount);

    if ((flags & 0x8000) == 0)
        return;

    if ((flags & 0x000f) != 0)
    {
        return;
    }

    if (qdcount == 0 || ancount == 0)
    {
        return;
    }

    pos = payload + sizeof (*dns);
    if (geosite_dns_read_name (payload, end, pos, qname, &qname_len, &pos))
    {
        return;
    }

    if (pos + 4 > end)
    {
        return;
    }

    pos += 4;
    for (i = 1; i < qdcount; i++)
    {
        char skip_name[DNS_MAX_DOMAIN_LEN];
        u16 skip_len = 0;

        if (geosite_dns_read_name (payload, end, pos, skip_name, &skip_len,
                                   &pos) || pos + 4 > end)
        {
            return;
        }
        pos += 4;
    }

    // clib_warning ("geosite dns response: qname=%s qd=%u an=%u",
    //               qname, qdcount, ancount);

    cc_indices = geosite_get_country_index_by_domain (qname);
    if (vec_len (cc_indices) == 0)
    {
        // clib_warning ("geosite dns response: qname=%s no geosite match",
        //               qname);
    }

    for (i = 0; i < ancount && pos < end; i++)
    {
        char answer_name[DNS_MAX_DOMAIN_LEN];
        u16 answer_len = 0;
        u16 rr_type;
        u16 rr_class;
        u32 ttl;
        u16 rdlen;
        u8 *rdata;

        if (geosite_dns_read_name (payload, end, pos, answer_name,
                                   &answer_len, &pos))
        {
            break;
        }

        if (pos + 10 > end)
        {
            break;
        }

        rr_type = clib_net_to_host_u16 (*(u16 *) pos);
        pos += 2;
        rr_class = clib_net_to_host_u16 (*(u16 *) pos);
        pos += 2;
        ttl = clib_net_to_host_u32 (*(u32 *) pos);
        pos += 4;
        rdlen = clib_net_to_host_u16 (*(u16 *) pos);
        pos += 2;

        if (pos + rdlen > end)
        {
            break;
        }

        rdata = pos;
        pos += rdlen;

        if (rr_class != DNS_CLASS_IN)
        {
            continue;
        }

        if (rr_type == DNS_TYPE_A && rdlen == 4)
        {
            ip4_address_t ip4;
            clib_bihash_kv_16_8_t key;

            clib_memcpy (ip4.as_u8, rdata, 4);
            geosite_resolved_make_ip4_key (&key, &ip4);
            // clib_warning ("geosite dns A: qname=%s answer=%s ip=%U ttl=%u",
            //               qname, answer_name, format_ip4_address, &ip4, ttl);

            vec_foreach (cc, cc_indices)
            {
                u32 refcnt;
                int rv;

                refcnt = geosite_active_refcnt_get (*cc);
                if (refcnt == 0)
                {
                    continue;
                }

                // clib_warning ("geosite dns A: active geosite=%u refcnt=%u qname=%s answer=%s",
                //               *cc, refcnt, qname, answer_name);
                rv = geosite_resolved_ip_add (&key, *cc, now_sec + ttl,
                                              now_sec);
                if (rv != 0)
                {
                    clib_warning ("geosite dns A add failed: qname=%s "
                                  "answer=%s ip=%U geosite=%u ttl=%u rv=%d",
                                  qname, answer_name, format_ip4_address,
                                  &ip4, *cc, ttl, rv);
                }
            }
        }
        else if (rr_type == DNS_TYPE_AAAA && rdlen == 16)
        {
            ip6_address_t ip6;
            clib_bihash_kv_16_8_t key;

            clib_memcpy (ip6.as_u8, rdata, 16);
            geosite_resolved_make_ip6_key (&key, &ip6);
            // clib_warning ("geosite dns AAAA: qname=%s answer=%s ip=%U ttl=%u",
            //               qname, answer_name, format_ip6_address, &ip6, ttl);

            vec_foreach (cc, cc_indices)
            {
                u32 refcnt;
                int rv;

                refcnt = geosite_active_refcnt_get (*cc);
                if (refcnt == 0)
                {
                    continue;
                }

                // clib_warning ("geosite dns AAAA: active geosite=%u refcnt=%u qname=%s answer=%s",
                //               *cc, refcnt, qname, answer_name);
                rv = geosite_resolved_ip_add (&key, *cc, now_sec + ttl,
                                              now_sec);
                if (rv != 0)
                {
                    clib_warning ("geosite dns AAAA add failed: qname=%s "
                                  "answer=%s ip=%U geosite=%u ttl=%u rv=%d",
                                  qname, answer_name, format_ip6_address,
                                  &ip6, *cc, ttl, rv);
                }
            }
        }
    }

    vec_free (cc_indices);
}







VLIB_NODE_FN (geosite_node) (vlib_main_t * vm,
		  vlib_node_runtime_t * node,
		  vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  geosite_next_t next_index;
  

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;


    while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	    u32 bi0;
	    vlib_buffer_t * b0;
          u32 next0 = GEOSITE_NEXT_DROP;
          
          u8 l4_payload_offset = 0;
          u8 ip_proto;
          u16 sport = 0;
          u16 dport;
          u8 *payload;
          u16 payload_length = 0;
          u32 sw_if_index0;
          /* speculatively enqueue b0 to the current next frame */
        bi0 = from[0];
        to_next[0] = bi0;
        from += 1;
        to_next += 1;
        n_left_from -= 1;
        n_left_to_next -= 1;
        b0 = vlib_get_buffer (vm, bi0);
        sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

        get_l4_payload_offset(b0,&l4_payload_offset,&ip_proto,&sport,&dport,
                              &payload_length);

        if(l4_payload_offset != 0)
        {
          payload = (u8 *)b0->data + l4_payload_offset;
          if (ip_proto == IP_PROTOCOL_UDP)
          {
            if (sport == DNS_DPORT)
            {
              geosite_dns_response_learn (vm, payload, payload_length);
            }
          }
          else if (ip_proto == IP_PROTOCOL_TCP)
          {
            if (sport == DNS_DPORT)
            {
              if (payload_length >= 2)
              {
                u16 dns_length = clib_net_to_host_u16 (*(u16 *) payload);

                if (dns_length <= payload_length - 2)
                {
                  // clib_warning ("geosite-input tcp dns response candidate: payload_len=%u dns_len=%u sport=%u dport=%u",
                  //               payload_length, dns_length, sport, dport);
                  geosite_dns_response_learn (vm, payload + 2, dns_length);
                }
              }
            }
          }
        }

        
        vnet_feature_next (&next0, b0);


          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            geosite_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
                         
            
            }
            
	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;






}











/* *INDENT-OFF* */
#ifndef CLIB_MARCH_VARIANT
VLIB_REGISTER_NODE (geosite_node) = 
{
  .name = "geosite-input",
  .vector_size = sizeof (u32),
  .format_trace = format_geosite_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = ARRAY_LEN(geosite_error_strings),
  .error_strings = geosite_error_strings,

  .n_next_nodes = GEOSITE_N_NEXT,

  /* edit / add dispositions here */
  .next_nodes = {
        [GEOSITE_NEXT_DROP] = "error-drop",
  },
};
#endif /* CLIB_MARCH_VARIANT */
/* *INDENT-ON* */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
