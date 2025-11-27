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
get_ip6_tcp_udp_payload_offset(vlib_buffer_t *b, ip6_header_t *ip6, u16 *dport ,u16 *payload_length,u16 ip6_payload_length)
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
      *dport =  clib_net_to_host_u16(tcp->dst_port);
      *payload_length = ip6_payload_length - tcp_header_len-transport_offset;
      return tcp_header_len + transport_offset;
    
      
      }
    else if (transport_proto == IP_PROTOCOL_UDP)
      {
        udp_header_t *udp = (udp_header_t *)transport_header;
        *dport =  clib_net_to_host_u16(udp->dst_port);
        *payload_length = ip6_payload_length - sizeof(udp_header_t)-transport_offset;
        return  transport_offset+ sizeof(udp_header_t);
      }

    return 0;
  
  

}

static_always_inline void
get_l4_payload_offset(vlib_buffer_t *b, u8 *payload_offset, u8 *ip_proto_, u16 *dport,u16 *payload_length)
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
       *dport =  clib_net_to_host_u16(tcp->dst_port);
        *payload_length = clib_net_to_host_u16(ip4h->length) - ip_header_len - tcp_header_len;
    }
    else if (ip_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *)(b->data + l4_hdr_offset);
      *payload_offset = l4_hdr_offset + sizeof(udp_header_t);
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
       *dport =  clib_net_to_host_u16(tcp->dst_port);
       *payload_length = clib_net_to_host_u16(ip6h->payload_length) - tcp_header_len;
    }
    else if (ip_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *)(b->data + current_offset);
      *payload_offset = current_offset + sizeof(udp_header_t);
      *dport =  clib_net_to_host_u16(udp->dst_port);
       *payload_length = clib_net_to_host_u16(ip6h->payload_length) - sizeof(udp_header_t);
    }
    else
      {   
          payload_offset_from_ip6 = get_ip6_tcp_udp_payload_offset(b, ip6h,dport,payload_length,ip6h->payload_length);
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
get_dns_domain(u8 *payload, char *domain , u16 payload_length,u16 *domain_length)
{
    u8 *qname_ptr = payload + sizeof(dns_header_t_);
    u8 *end = payload + payload_length;
    int domain_len = 0;
    int jumps = 0;
    while (qname_ptr < end && *qname_ptr != 0)
    {
        if ((*qname_ptr & 0xC0) == 0xC0)
        {
            if (qname_ptr + 1 >= end) return -1; 
            
            u16 offset = clib_net_to_host_u16(*(u16 *)qname_ptr) & 0x3FFF;
            if (offset >= (end - payload)) return -1; 
            
            if (jumps++ >= DNS_MAX_JUMPS) return -1;
            
            qname_ptr = payload + offset;
            continue;
        }
        
        u8 label_len = *qname_ptr++;
        if (qname_ptr + label_len >= end) return -1; 
        
        if (domain_len + label_len + 1 >= DNS_MAX_DOMAIN_LEN) 
            return -1;
        
      
        memcpy(domain + domain_len, qname_ptr, label_len);
        domain_len += label_len;
        domain[domain_len++] = '.';
        
        qname_ptr += label_len;
    }
    
    if (domain_len > 0) domain[domain_len-1] = '\0';
    else domain[0] = '\0';
    *domain_length =domain_len;
    return (domain_len > 0) ? 0 : -1;
}

static int
get_http_domain(u8 *payload, char *domain, u16 payload_length, u16 *domain_length)
{
    int i = 0;
    uint8_t *current_ptr = payload;
    uint8_t *ptr = payload;
    uint8_t *end = NULL;
    while (*current_ptr != 0x20) // == space
    {
        i++;
        current_ptr++;
        if (i > 17) // 17 bytes is max len
        {
            return -1;
        }
    }
    // Support the command prefix that identifies the presence of a "mandatory" header.
    if (i >= 2 && strncmp((const char *)ptr, "M-", 2) == 0)
    {
        ptr += 2;
        i -= 2;
    }
    if ((i >= 5 && strncmp((const char *)ptr, "HTTP/", 5) == 0) ||
        (i >= 3 && strncmp((const char *)ptr, "ICY", 3) == 0))
    {
        goto is_http;
    }
    else
    {
        if (i < 3)
        {
            return -1;
        }
        switch (i)
        {
        case 3:
            if (strncmp((const char *)ptr, "GET", i) == 0 ||
                strncmp((const char *)ptr, "PUT", i) == 0)
                goto is_http;
            break;
        case 4:
            if (strncmp((const char *)ptr, "POST", i) == 0 ||
                strncmp((const char *)ptr, "HEAD", i) == 0 ||
                strncmp((const char *)ptr, "LOCK", i) == 0 ||
                strncmp((const char *)ptr, "MOVE", i) == 0 ||
                strncmp((const char *)ptr, "COPY", i) == 0 ||
                strncmp((const char *)ptr, "POLL", i) == 0)
                goto is_http;
            break;
        case 5:
            if (strncmp((const char *)ptr, "PATCH", i) == 0 ||
                strncmp((const char *)ptr, "BCOPY", i) == 0 ||
                strncmp((const char *)ptr, "MKCOL", i) == 0 ||
                strncmp((const char *)ptr, "TRACE", i) == 0 ||
                strncmp((const char *)ptr, "LABEL", i) == 0 ||
                strncmp((const char *)ptr, "MERGE", i) == 0)
                goto is_http;
            break;
        case 6:
            if (strncmp((const char *)ptr, "DELETE", i) == 0 ||
                strncmp((const char *)ptr, "SEARCH", i) == 0 ||
                strncmp((const char *)ptr, "UNLOCK", i) == 0 ||
                strncmp((const char *)ptr, "REPORT", i) == 0 ||
                strncmp((const char *)ptr, "UPDATE", i) == 0 ||
                strncmp((const char *)ptr, "NOTIFY", i) == 0)
                goto is_http;
            break;
        case 7:
            if (strncmp((const char *)ptr, "BDELETE", i) == 0 ||
                strncmp((const char *)ptr, "CONNECT", i) == 0 ||
                strncmp((const char *)ptr, "OPTIONS", i) == 0 ||
                strncmp((const char *)ptr, "CHECKIN", i) == 0)
                goto is_http;
            break;
        case 8:
            if (strncmp((const char *)ptr, "PROPFIND", i) == 0 ||
                strncmp((const char *)ptr, "CHECKOUT", i) == 0 ||
                strncmp((const char *)ptr, "CCM_POST", i) == 0)
                goto is_http;
            break;
        case 9:
            if (strncmp((const char *)ptr, "SUBSCRIBE", i) == 0 ||
                strncmp((const char *)ptr, "PROPPATCH", i) == 0 ||
                strncmp((const char *)ptr, "BPROPFIND", i) == 0)
                goto is_http;
            break;
        case 10:
            if (strncmp((const char *)ptr, "BPROPPATCH", i) == 0 ||
                strncmp((const char *)ptr, "UNCHECKOUT", i) == 0 ||
                strncmp((const char *)ptr, "MKACTIVITY", i) == 0)
                goto is_http;
            break;
        case 11:
            if (strncmp((const char *)ptr, "MKWORKSPACE", i) == 0 ||
                strncmp((const char *)ptr, "RPC_CONNECT", i) == 0 ||
                strncmp((const char *)ptr, "UNSUBSCRIBE", i) == 0 ||
                strncmp((const char *)ptr, "RPC_IN_DATA", i) == 0)
                goto is_http;
            break;
        case 12:
            if (strncmp((const char *)ptr, "RPC_OUT_DATA", i) == 0)
                goto is_http;
            break;
        case 15:
            if (strncmp((const char *)ptr, "VERSION-CONTROL", i) == 0)
                goto is_http;
            break;

        case 16:
            if (strncmp((const char *)ptr, "BASELINE-CONTROL", i) == 0 ||
                strncmp((const char *)ptr, "SSTP_DUPLEX_POST", i) == 0)
                goto is_http;
            break;
        default:
            return -1;
        }
    }

is_http:

    end = payload + payload_length; //declarations are not allowed immediately after a label in gcc 12
    uint8_t *line_start = current_ptr + 1;

    // find the last str of the request line
    while (line_start < end && !(*line_start == '\r' && *(line_start + 1) == '\n'))
    {
        line_start++;
    }

    if (line_start >= end)
    {
        return -1;
    }

    // another line start
    uint8_t *header_start = line_start + 2; // skip 0x0d 0x0a

    // find host
    while (header_start < end)
    {

        if (*header_start == '\r' && *(header_start + 1) == '\n')
        {
            break;
        }

        if (header_start + 5 < end &&
            (header_start[0] == 'H' || header_start[0] == 'h') &&
            (header_start[1] == 'O' || header_start[1] == 'o') &&
            (header_start[2] == 'S' || header_start[2] == 's') &&
            (header_start[3] == 'T' || header_start[3] == 't') &&
            header_start[4] == ':')
        {

            uint8_t *host_value_start = header_start + 5; 

            while (host_value_start < end &&
                   (*host_value_start == ' ' || *host_value_start == '\t'))
            {
                host_value_start++;
            }

            uint8_t *host_value_end = host_value_start;
            while (host_value_end < end &&
                   !(*host_value_end == '\r' && *(host_value_end + 1) == '\n'))
            {
                host_value_end++;
            }

            if (host_value_end > host_value_start)
            {
                int host_len = host_value_end - host_value_start;

                int colon_pos = -1;
                for (int j = 0; j < host_len; j++)
                {
                    if (host_value_start[j] == ':')
                    {
                        colon_pos = j;
                        break;
                    }
                }

                int copy_len = (colon_pos >= 0) ? colon_pos : host_len;
                if (copy_len > DNS_MAX_DOMAIN_LEN - 1)
                {
                    copy_len = DNS_MAX_DOMAIN_LEN - 1;
                }

                memcpy(domain, host_value_start, copy_len);
                domain[copy_len] = '\0';
                *domain_length = copy_len;
                return 0; 
            }

            break;
        }

     
        while (header_start < end &&
               !(*header_start == '\r' && *(header_start + 1) == '\n'))
        {
            header_start++;
        }

        if (header_start >= end)
        {
            break;
        }

        header_start += 2; 
    }

    return -1;
}

static int
get_tls_domain(u8 *payload, char *domain, u16 payload_length,u16 *domain_length)
{
    if (payload_length < 9) {
        return -1;
    }
    
    if (payload[0] != 0x16) {
        return -1;
    }
    
    uint16_t version = clib_net_to_host_u16(*(uint16_t*)(payload + 1));
    if (version != 0x0301 && version != 0x0302 && version != 0x0303 && version != 0x0304) { // SSL 3.0 或更低
        return -1;
    }
    
    uint16_t record_len = clib_net_to_host_u16(*(uint16_t*)(payload + 3));
    if (record_len > payload_length - 5) {
        return -1;
    }
    
    if (payload[5] != 0x01) {
        return -1;
    }
    
    uint32_t handshake_len = (payload[6] << 16) | (payload[7] << 8) | payload[8];
    if (handshake_len > record_len - 4) {
        return -1;
    }
    
    // tls header(5) + handshake header(4) + version(2) + random(32) 
    uint8_t *ptr = payload + 5 + 4 +2+ 32;
    uint8_t *end = payload + 5 + record_len;
    
    if (ptr >= end) return -1;
    uint8_t session_id_len = *ptr++;
    if (ptr + session_id_len > end) return -1;
    ptr += session_id_len;
    
    if (ptr + 2 > end) return -1;
    uint16_t cipher_suites_len = clib_net_to_host_u16(*(uint16_t*)ptr);
    ptr += 2;
    if (ptr + cipher_suites_len > end) return -1;
    ptr += cipher_suites_len;
    
    if (ptr >= end) return -1;
    uint8_t compression_methods_len = *ptr++;
    if (ptr + compression_methods_len > end) return -1;
    ptr += compression_methods_len;
    
    if (ptr + 2 > end) return -1;
    uint16_t extensions_len = clib_net_to_host_u16(*(uint16_t*)ptr);
    ptr += 2;
    
    if (ptr + extensions_len > end) return -1;
    uint8_t *extensions_end = ptr + extensions_len;
    
    while (ptr + 4 <= extensions_end) {
        uint16_t ext_type = clib_net_to_host_u16(*(uint16_t*)ptr);
        uint16_t ext_len = clib_net_to_host_u16(*(uint16_t*)(ptr + 2));
        ptr += 4;
        
        if (ptr + ext_len > extensions_end) {
            break;
        }
        
        if (ext_type == 0x0000) { 
            if (ext_len < 2) break;
            uint16_t server_name_list_len = clib_net_to_host_u16(*(uint16_t*)ptr);
            uint8_t *sni_ptr = ptr + 2;
            uint8_t *sni_end = ptr + ext_len;
            
            if (sni_ptr + server_name_list_len > sni_end) {
                break;
            }
            
            while (sni_ptr + 3 <= sni_end) {
                uint8_t name_type = *sni_ptr++;
                
                uint16_t name_len = clib_net_to_host_u16(*(uint16_t*)sni_ptr);
                sni_ptr += 2;
                
                if (sni_ptr + name_len > sni_end) {
                    break;
                }
                
                if (name_type == 0x00) { 
                    
                    if (name_len > DNS_MAX_DOMAIN_LEN - 1) {
                        name_len = DNS_MAX_DOMAIN_LEN - 1;
                    }
                    
                    memcpy(domain, sni_ptr, name_len);
                    domain[name_len] = '\0';
                    *domain_length =name_len;
                    return 0; 
                }
                
                sni_ptr += name_len;
            }
            
            break;
        }
        
        ptr += ext_len;
    }
    
    return -1;
}


static int
get_socks5_domain(u8 *payload, char *domain, u16 payload_length,u16 *domain_length)
{
    if (payload_length < 10) {
        return -1;
    }
    
    if (payload[0] != 0x05) {
        return -1;
    }
    
    uint8_t cmd = payload[1];
    if (cmd != 0x01 && cmd != 0x02 && cmd != 0x03) {
        return -1;
    }
    
    if (payload[2] != 0x00) {
        return -1;
    }
    
    uint8_t atyp = payload[3];
    uint8_t *addr_ptr = payload + 4;
    uint8_t *end = payload + payload_length;
    
    if (addr_ptr >= end) {
        return -1;
    }
    
 if (atyp == 0x03) { 
        uint8_t domain_len = *addr_ptr++;
        
        if (addr_ptr + domain_len + 2 > end) { 
            return -1;
        }
        
        if (domain_len > DNS_MAX_DOMAIN_LEN - 1) {
            domain_len = DNS_MAX_DOMAIN_LEN - 1;
        }
        
        memcpy(domain, addr_ptr, domain_len);
        domain[domain_len] = '\0';
        *domain_length =domain_len;
        
        return 0;
    }
   
    else {
        return -1;
    }
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
          u32 sw_if_index0;
          //u8 tmp0[6];
          
          u8 l4_payload_offset = 0;
          u8 ip_proto;
          u16 dport;
          u8 *payload;
          char *domain;
          u16 payload_length;
          u16 domain_length =0;
        bool get_domain =false;
          /* speculatively enqueue b0 to the current next frame */
        bi0 = from[0];
        to_next[0] = bi0;
        from += 1;
        to_next += 1;
        n_left_from -= 1;
        n_left_to_next -= 1;
        domain = clib_mem_alloc(DNS_MAX_DOMAIN_LEN * sizeof(char));
        clib_memset(domain, 0, DNS_MAX_DOMAIN_LEN);
        domain[0] ='\0';
        b0 = vlib_get_buffer (vm, bi0);
        sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
        geosite_domain_t *geosite_domain;
        get_l4_payload_offset(b0,&l4_payload_offset,&ip_proto,&dport,&payload_length);
        vnet_buffer2(b0)->geosite_domain_index =~0;

        if(l4_payload_offset != 0)
        {
          payload = (u8 *)b0->data + l4_payload_offset;
          //dns
          if (dport == DNS_DPORT && ip_proto == IP_PROTOCOL_UDP)
          {
            if(get_dns_domain(payload,domain,payload_length,&domain_length)== 0){
             get_domain = true;
             goto end_process;
            }
            }
          else if (dport == DNS_DPORT && ip_proto == IP_PROTOCOL_TCP)
             {
            if(get_dns_domain(payload+2,domain,payload_length-2,&domain_length)== 0){
              get_domain = true;
              goto end_process;
             }
            }

          //http

          if(get_http_domain(payload,domain,payload_length,&domain_length)== 0)
          {
              get_domain = true;
              goto end_process;
          }


          //tls
          if(get_tls_domain(payload,domain,payload_length,&domain_length)== 0)
          {
              get_domain = true;
              goto end_process;
          }

          //SOCKS5
          if(get_socks5_domain(payload,domain,payload_length,&domain_length)== 0)
          {
              get_domain = true;
              goto end_process;
          }


        //   if ( ip_proto == IP_PROTOCOL_UDP)
        //   {
        //     if(get_quic_domain(payload,domain,payload_length,&domain_length)== 0);
        //   {
        //     //clib_warning("quic domain = %s,,domain_length %d",domain,domain_length);
        //       get_domain = true;
        //       goto end_process;
        //   }
        //     }            

          }

        
end_process:        vnet_feature_next (&next0, b0);

       if(get_domain && domain_length < DNS_MAX_DOMAIN_LEN)
       
        {

          b0->flags|=VLIB_BUFFER_DOMAIN_VALID ; 
          
            pool_get(geosite_main.pool, geosite_domain);
            clib_memset(geosite_domain, 0, sizeof(*geosite_domain));
            geosite_domain->refcnt =1;
            strncpy(geosite_domain->str, domain, sizeof(geosite_domain->str) - 1);
            u32 idx = geosite_domain - geosite_main.pool ; 
           vnet_buffer2(b0)->geosite_domain_index = idx;
           geosite_domain_t *m = pool_elt_at_index(geosite_main.pool, idx);
        }
        else{
            clib_mem_free(domain);
        }

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE) 
                            && (b0->flags & VLIB_BUFFER_IS_TRACED))) {
            geosite_trace_t *t = 
               vlib_add_trace (vm, node, b0, sizeof (*t));
            t->sw_if_index = sw_if_index0;
            t->next_index = next0;
            if(get_domain && domain_length < DNS_MAX_DOMAIN_LEN){
                clib_memcpy (t->domain, domain,domain_length);
            }else{
                t->domain[0]='\0';
            }
                         
            
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
