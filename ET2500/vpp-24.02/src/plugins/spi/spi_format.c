/*
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
 */

#include <spi/spi.h>
#include <spi/spi_inline.h>

u8 *
format_spi_tcp_state (u8 *s, va_list *args)
{
  spi_tcp_state_e e = va_arg (*args, spi_tcp_state_e);
  switch (e)
    {
    case SPI_TCP_STATE_CLOSED:
      s = format (s, "closed");
      break;
    case SPI_TCP_STATE_TRANSITORY:
      s = format (s, "transitory");
      break;
    case SPI_TCP_STATE_ESTABLISHED:
      s = format (s, "established");
      break;
    case SPI_TCP_STATE_CLOSING:
      s = format (s, "closing");
      break;
    case SPI_TCP_STATE_FREE:
      s = format (s, "free");
      break;
    case SPI_TCP_N_STATE:
    default:
      s = format (s, "BUG! unexpected N_STATE! BUG!");
      break;
    }
  return s;
}

u8 *
format_spi_general_state (u8 *s, va_list *args)
{
  spi_general_state_e e = va_arg (*args, spi_general_state_e);
  switch (e)
    {
    case SPI_GENERAL_STATE_CLOSED:
      s = format (s, "closed");
      break;
    case SPI_GENERAL_STATE_TRANSMIT:
      s = format (s, "transmit");
      break;
    case SPI_GENERAL_STATE_IDLE:
      s = format (s, "idle");
      break;
    case SPI_GENERAL_N_STATE:
    default:
      s = format (s, "BUG! unexpected N_STATE! BUG!");
      break;
    }
  return s;
}

u8 *
format_spi_session_kvp (u8 *s, va_list *args)
{
    clib_bihash_kv_48_8_t *v = va_arg (*args, clib_bihash_kv_48_8_t *);

    /* only pkt_l3l4 is valid*/
    spi_pkt_info_t *pkt = (spi_pkt_info_t *)v;

    if (pkt->pkt_l3l4.is_ip6)
    {
        s = format (s, "SPI IPV6 session-index %lu proto %U : %U:%u <--> %U:%u",
                    v->value, 
                    format_ip_protocol, pkt->pkt_l3l4.proto,
                    format_ip6_address, &pkt->pkt_l3l4.ip6.addr[0], clib_net_to_host_u16 (pkt->pkt_l3l4.port[0]),
                    format_ip6_address, &pkt->pkt_l3l4.ip6.addr[1], clib_net_to_host_u16 (pkt->pkt_l3l4.port[1]));
    }
    else
    {
        s = format (s, "SPI IPV4 session-index %lu proto %U : %U:%u <--> %U:%u",
                    v->value, 
                    format_ip_protocol, pkt->pkt_l3l4.proto,
                    format_ip4_address, &pkt->pkt_l3l4.ip4.addr[0], clib_net_to_host_u16 (pkt->pkt_l3l4.port[0]),
                    format_ip4_address, &pkt->pkt_l3l4.ip4.addr[1], clib_net_to_host_u16 (pkt->pkt_l3l4.port[1]));

    }
    return s;
}

u8 *
format_spi_exact_3tuple_timeout_kvp (u8 * s, va_list * args)
{
    spi_exact_3tuple_timeout_entry_t *e = va_arg (*args, spi_exact_3tuple_timeout_entry_t *);

    if (e->key.is_ip6)
    {
        s = format (s, "SPI exact 3tuple key proto: %U ip: %U port: %u timeout: %u",
                    format_ip_protocol, e->key.proto,
                    format_ip6_address, &e->key.ip6.addr, 
                    clib_net_to_host_u16 (e->key.port),
                    e->value.transmit_timeout);
    }
    else
    {
        s = format (s, "SPI exact 3tuple key proto: %U ip: %U port: %u timeout: %u",
                    format_ip_protocol, e->key.proto,
                    format_ip4_address, &e->key.ip6.addr, 
                    clib_net_to_host_u16 (e->key.port),
                    e->value.transmit_timeout);
    }
    return s;
}

u8 *
format_spi_session (u8 * s, va_list * args)
{
    spi_main_t *spim = va_arg (*args, spi_main_t *);
    spi_session_t *session = va_arg (*args, spi_session_t *);

    f64 now = va_arg (*args, f64);

    s = format (s, "SPI session create_side %s create-thread %u, session-index %lu , proto %U",
                    session->create_by_output ? "OUTPUT" : "INPUT",
                    session->thread_index, session->index, 
                    format_ip_protocol, session->proto);

    if (session->is_ip6)
    {
        s = format (s, "\n\tUplink %U:%u --> %U:%u ; ",
                      format_ip6_address, &session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr,
                      clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_UPLINK].sport),
                      format_ip6_address, &session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr,
                      clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_UPLINK].dport));

        if (session->flow[SPI_FLOW_DIR_UPLINK].out_sw_if_index != ~0)
        {
            s = format (s, "in %U --> out %U",
                        format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].in_sw_if_index,
                        format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].out_sw_if_index);
        }
        else
        {
            s = format (s, "in %U --> out(Session conversion)",
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].in_sw_if_index);

        }

        s = format (s, "\n\tDownlink %U:%u --> %U:%u ; ",
                      format_ip6_address, &session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr,
                      clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_DOWNLINK].sport),
                      format_ip6_address, &session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr,
                      clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_DOWNLINK].dport));

        if (session->flow[SPI_FLOW_DIR_DOWNLINK].out_sw_if_index != ~0)
        {
            s = format (s, "in %U --> out %U",
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].in_sw_if_index,
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].out_sw_if_index);
        }
        else
        {
            s = format (s, "in %U --> out(Session conversion)",
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].in_sw_if_index);
        }
    }
    else
    {
        s = format (s, "\n\tUplink %U:%u --> %U:%u ; ",
                  format_ip4_address, &session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr,
                  clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_UPLINK].sport),
                  format_ip4_address, &session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr,
                  clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_UPLINK].dport));
        if (session->flow[SPI_FLOW_DIR_UPLINK].out_sw_if_index != ~0)
        {
            s = format (s, "in %U --> out %U",
                  format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].in_sw_if_index,
                  format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].out_sw_if_index);
        }
        else
        {
            s = format (s, "in %U --> out(Session conversion)",
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_UPLINK].in_sw_if_index);
        }

        s = format (s, "\n\tDownlink %U:%u --> %U:%u ; ",
                  format_ip4_address, &session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr,
                  clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_DOWNLINK].sport),
                  format_ip4_address, &session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr,
                  clib_net_to_host_u16 (session->flow[SPI_FLOW_DIR_DOWNLINK].dport));
        if (session->flow[SPI_FLOW_DIR_DOWNLINK].out_sw_if_index != ~0)
        {
            s = format (s, "in %U --> out %U",
                  format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].in_sw_if_index,
                  format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].out_sw_if_index);
        }
        else
        {
            s = format (s, "in %U --> out(Session conversion)",
                      format_vnet_sw_if_index_name, spim->vnet_main, session->flow[SPI_FLOW_DIR_DOWNLINK].in_sw_if_index);
        }
    }

    switch (session->proto)
    {
    case IP_PROTOCOL_TCP:
        s = format (s, "\n\tState: %U", format_spi_tcp_state, session->state_tcp);
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
        s = format (s, "\n\tState: %U", format_spi_general_state, session->state_icmp);
        break;
    case IP_PROTOCOL_UDP:
        s = format (s, "\n\tState: %U", format_spi_general_state, session->state_udp);
        break;
    default:
        s = format (s, "\n\tState: %U", format_spi_general_state, session->state_other);
        break;
    }

    s = format (s, "\n\tSession duration %.2lfs", now - session->create_timestamp);
    s = format (s, "\n\tSession transmit_timeout %ds", session->transmit_timeout);
    s = format (s, "\n\tUplink : total pkts %lu, total bytes %llu", session->total_pkts[SPI_FLOW_DIR_UPLINK], session->total_bytes[SPI_FLOW_DIR_UPLINK]);
    s = format (s, "\n\tUplink : drop  pkts %lu, drop  bytes %llu", session->drop_pkts[SPI_FLOW_DIR_UPLINK], session->drop_bytes[SPI_FLOW_DIR_UPLINK]);
    s = format (s, "\n\tDownlink : total pkts %lu, total bytes %llu", session->total_pkts[SPI_FLOW_DIR_DOWNLINK], session->total_bytes[SPI_FLOW_DIR_DOWNLINK]);
    s = format (s, "\n\tDownlink : drop  pkts %lu, drop  bytes %llu\n", session->drop_pkts[SPI_FLOW_DIR_DOWNLINK], session->drop_bytes[SPI_FLOW_DIR_DOWNLINK]);

    if (session->associated_session_valid)
    {
        s = format (s, "\tASSOCIATED-SESSION create-thread %u, session-index %lu\n", session->associated_session.session_thread, session->associated_session.session_index);
    }
    return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
