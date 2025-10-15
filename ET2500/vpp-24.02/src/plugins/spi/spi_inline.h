/*
 * spi.h: types/functions for SPI.
 *
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

#ifndef included_spi_inline_h
#define included_spi_inline_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <spi/spi.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/udp/udp_packet.h>


static_always_inline void
spi_create_session_associated_session_proc(spi_main_t *spim, 
                            vlib_buffer_t *buffer, 
                            spi_session_t *new_session, 
                            int is_output)
{
    spi_per_thread_data_t *tspi = NULL;
    spi_session_t *cached_session = NULL;

    if (!is_output)
        return;

    if (!(buffer->flags & VLIB_BUFFER_SPI_SESSION_VALID))
        return;

    if (new_session->index == vnet_buffer2(buffer)->spi.cached_session_index && 
        new_session->thread_index == vnet_buffer2(buffer)->spi.cached_session_thread)
        return;

    tspi = &spim->per_thread_data[vnet_buffer2(buffer)->spi.cached_session_thread];
    cached_session =  pool_elt_at_index (tspi->sessions, vnet_buffer2(buffer)->spi.cached_session_index);

    new_session->associated_session_valid = 1;
    new_session->associated_session.session_thread = vnet_buffer2(buffer)->spi.cached_session_thread;
    new_session->associated_session.session_index = vnet_buffer2(buffer)->spi.cached_session_index;

    cached_session->associated_session_valid = 1;
    cached_session->associated_session.session_thread = new_session->thread_index;
    cached_session->associated_session.session_index = new_session->index;
}

static_always_inline void
spi_submit_or_update_session_timer(spi_per_thread_data_t *tspi, spi_session_t *session, u32 timeout)
{
    //update
    if (session->session_timer_handle != (~0) &&
        !tw_timer_handle_is_free_16t_2w_512sl(tspi->timers_per_worker, session->session_timer_handle))
    {
        //need update tw_timer user_handle
#if 0
        tw_timer_stop_16t_2w_512sl(tspi->timers_per_worker, session->session_timer_handle);
        session->session_timer_handle = 
                tw_timer_start_16t_2w_512sl(tspi->timers_per_worker,
                                           session->index, 0,
                                           timeout);
#else
        tw_timer_update_16t_2w_512sl(tspi->timers_per_worker, 
                                    session->session_timer_handle,
                                    timeout);
#endif
    }
    else
    {
        session->session_timer_handle = 
                tw_timer_start_16t_2w_512sl(tspi->timers_per_worker,
                                           session->index, 0,
                                           timeout);
    }

}

static_always_inline void
spi_clear_session_timer(spi_per_thread_data_t *tspi, spi_session_t *session)
{
    //clear
    if (session->session_timer_handle != (~0) &&
        !tw_timer_handle_is_free_16t_2w_512sl(tspi->timers_per_worker, session->session_timer_handle))
    {
        tw_timer_stop_16t_2w_512sl(tspi->timers_per_worker, session->session_timer_handle);
    }
    session->session_timer_handle = (~0);
}

static_always_inline u32
spi_search_exact_3tuple_timeout(spi_main_t *spim, spi_session_t *session)
{
    /* 
     * search exact 3tuple timeout entry 
     * Prioritize searching for exact timeout configurations for downlinks.
     * if the downlink is not found, search for uplink side.
     * if the uplink is not found, using protocol based timeout.
     *
     * (Downlink exact timeout > Uplink exact timeout > Proto timeout)
     * 
     * The timeout confirmed here:
     * Tcp : tcp_established timeout
     * other : proto transmit timeout
     */

    spi_exact_3tuple_timeout_entry_t search;

    clib_memset(&search, 0, sizeof(spi_exact_3tuple_timeout_entry_t));
    search.key.proto = session->proto;
    search.key.port  = session->flow[SPI_FLOW_DIR_DOWNLINK].sport;
    search.key.is_ip6 = session->is_ip6;
    if (session->is_ip6)
    {
        search.key.ip6.addr.as_u64[0] = session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr.as_u64[0];
        search.key.ip6.addr.as_u64[1] = session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr.as_u64[1];
    }
    else
    {
        search.key.ip4.addr.as_u32 = session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32;
    }

    if (!clib_bihash_search_24_8 (&spim->exact_3tuple_timeout_table, &search.kv, &search.kv))
    {
        return search.value.transmit_timeout;
    }

    clib_memset(&search, 0, sizeof(spi_exact_3tuple_timeout_entry_t));

    search.key.proto = session->proto;
    search.key.port  = session->flow[SPI_FLOW_DIR_UPLINK].sport;
    search.key.is_ip6 = session->is_ip6;
    if (session->is_ip6)
    {
        search.key.ip6.addr.as_u64[0] = session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[0];
        search.key.ip6.addr.as_u64[1] = session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[1];
    }
    else
    {
        search.key.ip4.addr.as_u32 = session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32;
    }

    if (!clib_bihash_search_24_8 (&spim->exact_3tuple_timeout_table, &search.kv, &search.kv))
    {
        return search.value.transmit_timeout;
    }

    return (~0);
}

static_always_inline spi_flow_dir_e 
spi_check_flow_dir(spi_session_t *session, spi_pkt_info_t *pkt)
{
    if (pkt->pkt_info.exchanged_tuple)
    {
        if (pkt->pkt_l3l4.is_ip6)
        {
            if (session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[0] == 
                pkt->pkt_l3l4.ip6.addr[1].as_u64[0] &&
                session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[1] == 
                pkt->pkt_l3l4.ip6.addr[1].as_u64[1])
                return SPI_FLOW_DIR_UPLINK;
            else
                return SPI_FLOW_DIR_DOWNLINK;
        }
        else
        {
            if (session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 == 
                pkt->pkt_l3l4.ip4.addr[1].as_u32)
                return SPI_FLOW_DIR_UPLINK;
            else
                return SPI_FLOW_DIR_DOWNLINK;
        }
    }
    else
    {
        if (pkt->pkt_l3l4.is_ip6)
        {
            if (session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[0] == 
                pkt->pkt_l3l4.ip6.addr[0].as_u64[0] &&
                session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr.as_u64[1] == 
                pkt->pkt_l3l4.ip6.addr[0].as_u64[1])
                return SPI_FLOW_DIR_UPLINK;
            else
                return SPI_FLOW_DIR_DOWNLINK;

        }
        else
        {
            if (session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 == 
                pkt->pkt_l3l4.ip4.addr[0].as_u32)
                return SPI_FLOW_DIR_UPLINK;
            else
                return SPI_FLOW_DIR_DOWNLINK;
        }
    }
}

static_always_inline int
spi_tcp_session_state_proc(spi_session_t *session, 
                           spi_pkt_info_t *pkt, 
                           spi_flow_dir_e dir, 
                           f64 now)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    switch (session->state_tcp)
    {
    case SPI_TCP_STATE_CLOSED:
        {
            if (dir == SPI_FLOW_DIR_UPLINK && 
                pkt->pkt_info.icmp_o_tcp_flags == TCP_FLAG_SYN)
            {
                session->state_tcp = SPI_TCP_STATE_TRANSITORY;
                session->tcp_last_syn_timestamp = now;
                session->need_change_timeout = 1;
            }
            else
            {
                //DROP
                err = SPI_NODE_ERROR_TCP_NON_SYN_DROP;
            }
        }
        break;
    case SPI_TCP_STATE_TRANSITORY:
        {
            /* 
             * When uplink endpoint not revc SYN, Client need resend SYNC
             * so should be forward SYN, but we need check revc SYN timestamp,
             * If receiving a lot in a short period of time is unreasonable, 
             * we should drop it
             */
            if (dir == SPI_FLOW_DIR_UPLINK && 
                pkt->pkt_info.icmp_o_tcp_flags == TCP_FLAG_SYN)
            {
                //if it is less than 1 second, drop it
                if ((now - session->tcp_last_syn_timestamp) < (1.0))
                {
                    //DROP
                    err = SPI_NODE_ERROR_TCP_SYN_FAST;
                }
                else
                {
                    session->tcp_last_syn_timestamp = now;
                }
            }
            else if (dir == SPI_FLOW_DIR_DOWNLINK && 
                     pkt->pkt_info.icmp_o_tcp_flags == ( TCP_FLAG_SYN | TCP_FLAG_ACK ))
            {
                session->state_tcp = SPI_TCP_STATE_ESTABLISHED;
                session->need_change_timeout = 1;
            }
            else if (pkt->pkt_info.icmp_o_tcp_flags & TCP_FLAG_FIN)
            {
                session->state_tcp = SPI_TCP_STATE_CLOSING;
                session->need_change_timeout = 1;
            }
            else if (pkt->pkt_info.icmp_o_tcp_flags & TCP_FLAG_RST)
            {
                session->state_tcp = SPI_TCP_STATE_FREE;
                session->need_change_timeout = 1;
            }
            else
            {
                //DROP
                err = SPI_NODE_ERROR_TCP_TRNSL_DROP;
            }
        }
        break;
    case SPI_TCP_STATE_ESTABLISHED:
        {
            if (pkt->pkt_info.icmp_o_tcp_flags & TCP_FLAG_FIN)
            {
                session->state_tcp = SPI_TCP_STATE_CLOSING;
                session->need_change_timeout = 1;
            }
            else if (pkt->pkt_info.icmp_o_tcp_flags & TCP_FLAG_RST)
            {
                session->state_tcp = SPI_TCP_STATE_FREE;
                session->need_change_timeout = 1;
            }
        }
        break;

    case SPI_TCP_STATE_CLOSING:
        {
            if (dir == SPI_FLOW_DIR_UPLINK && 
                pkt->pkt_info.icmp_o_tcp_flags == TCP_FLAG_SYN)
            {
                session->state_tcp = SPI_TCP_STATE_TRANSITORY;
                session->tcp_last_syn_timestamp = now;
                session->need_change_timeout = 1;
            }
            else if (pkt->pkt_info.icmp_o_tcp_flags & TCP_FLAG_RST)
            {
                session->state_tcp = SPI_TCP_STATE_FREE;
                session->need_change_timeout = 1;
            }
        }
        break;

    case SPI_TCP_STATE_FREE:
        {
            //DROP
            err = SPI_NODE_ERROR_TCP_CLOSING_DROP;
        }
        break;
    default:
        clib_warning("SPI tcp session state bug error!!");
        session->state_tcp = SPI_TCP_STATE_FREE;
        session->need_change_timeout = 1;
        err = SPI_NODE_ERROR_STATE_ERROR_DROP;
        break;
    }
    return err;
}

static_always_inline int
spi_tcp_session_timeout_proc(spi_main_t *spim,
                             spi_per_thread_data_t *tspi,
                             spi_session_t *session)
{
    int err = SPI_NODE_ERROR_NO_ERR;
    u32 timeout = (u32)(~0);

    if (PREDICT_TRUE(session->need_change_timeout == 0))
        return err;

    switch (session->state_tcp)
    {
    case SPI_TCP_STATE_CLOSED:
    case SPI_TCP_STATE_TRANSITORY:
        {
            timeout = spim->spi_timeout_config.tcp_transitory;
        }
        break;
    case SPI_TCP_STATE_ESTABLISHED:
        {
            timeout = spi_search_exact_3tuple_timeout(spim, session);
            if (timeout == (u32)(~0))
            {
                timeout = spim->spi_timeout_config.tcp_established;
            }
            session->transmit_timeout = timeout;
        }
        break;
    case SPI_TCP_STATE_CLOSING:
        {
            timeout = spim->spi_timeout_config.tcp_closing;
        }
        break;

    case SPI_TCP_STATE_FREE:
    default:
        {
            timeout = 1;
        }
        break;
    }

    spi_submit_or_update_session_timer(tspi, session, timeout);
    session->need_change_timeout = 0;

    return err;
}

static_always_inline int
spi_icmp_session_state_proc(spi_session_t *session, 
                           spi_pkt_info_t *pkt, 
                           spi_flow_dir_e dir, 
                           f64 now)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    switch (session->state_icmp)
    {
    case SPI_GENERAL_STATE_CLOSED:
        {
            session->state_icmp = SPI_GENERAL_STATE_TRANSMIT;
            session->need_change_timeout = 1;
        }
        break;
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            //do nothing
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
        {
            err = SPI_NODE_ERROR_GENERAL_IDLE_DROP;
        }
        break;
    default:
        clib_warning("SPI icmp session state bug error!!");
        session->state_icmp = SPI_GENERAL_STATE_IDLE;
        session->need_change_timeout = 1;
        err = SPI_NODE_ERROR_STATE_ERROR_DROP;
        break;
    }
    return err;
}

static_always_inline int
spi_icmp_session_timeout_proc(spi_main_t *spim,
                              spi_per_thread_data_t *tspi,
                           spi_session_t *session)
{
    int err = SPI_NODE_ERROR_NO_ERR;
    u32 timeout = (u32)(~0);

    if (PREDICT_TRUE(session->need_change_timeout == 0))
        return err;

    switch (session->state_icmp)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            timeout = spi_search_exact_3tuple_timeout(spim, session);
            if (timeout == (u32)(~0))
            {
                timeout = spim->spi_timeout_config.icmp;
            }
            session->transmit_timeout = timeout;
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            timeout = 1;
        }
        break;
    }

    spi_submit_or_update_session_timer(tspi, session, timeout);
    session->need_change_timeout = 0;

    return err;
}

static_always_inline int
spi_udp_session_state_proc(spi_session_t *session, 
                           spi_pkt_info_t *pkt, 
                           spi_flow_dir_e dir, 
                           f64 now)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    switch (session->state_udp)
    {
    case SPI_GENERAL_STATE_CLOSED:
        {
            session->state_udp = SPI_GENERAL_STATE_TRANSMIT;
            session->need_change_timeout = 1;
        }
        break;
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            //do nothing
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
        {
            err = SPI_NODE_ERROR_GENERAL_IDLE_DROP;
        }
        break;
    default:
        clib_warning("SPI udp session state bug error!!");
        session->state_udp = SPI_GENERAL_STATE_IDLE;
        session->need_change_timeout = 1;
        err = SPI_NODE_ERROR_STATE_ERROR_DROP;
        break;
    }
    return err;
}

static_always_inline int
spi_udp_session_timeout_proc(spi_main_t *spim,
                             spi_per_thread_data_t *tspi,
                             spi_session_t *session)
{
    int err = SPI_NODE_ERROR_NO_ERR;
    u32 timeout = (u32)(~0);

    if (PREDICT_TRUE(session->need_change_timeout == 0))
        return err;

    switch (session->state_udp)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            timeout = spi_search_exact_3tuple_timeout(spim, session);
            if (timeout == (u32)(~0))
            {
                timeout = spim->spi_timeout_config.udp;
            }
            session->transmit_timeout = timeout;
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            timeout = 1;
        }
        break;
    }

    spi_submit_or_update_session_timer(tspi, session, timeout);
    session->need_change_timeout = 0;

    return err;
}

static_always_inline int
spi_other_session_state_proc(spi_session_t *session, 
                           spi_pkt_info_t *pkt, 
                           spi_flow_dir_e dir, 
                           f64 now)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    switch (session->state_other)
    {
    case SPI_GENERAL_STATE_CLOSED:
        {
            session->state_other = SPI_GENERAL_STATE_TRANSMIT;
            session->need_change_timeout = 1;
        }
        break;
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            //do nothing
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
        {
            err = SPI_NODE_ERROR_GENERAL_IDLE_DROP;
        }
        break;
    default:
        clib_warning("SPI other session state bug error!!");
        session->state_other = SPI_GENERAL_STATE_IDLE;
        session->need_change_timeout = 1;
        err = SPI_NODE_ERROR_STATE_ERROR_DROP;
        break;
    }
    return err;
}

static_always_inline int
spi_other_session_timeout_proc(spi_main_t *spim,
                               spi_per_thread_data_t *tspi,
                               spi_session_t *session)
{
    int err = SPI_NODE_ERROR_NO_ERR;
    u32 timeout = (u32)(~0);

    if (PREDICT_TRUE(session->need_change_timeout == 0))
        return err;

    switch (session->state_other)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            timeout = spi_search_exact_3tuple_timeout(spim, session);
            if (timeout == (u32)(~0))
            {
                timeout = spim->spi_timeout_config.other;
            }
            session->transmit_timeout = timeout;
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            timeout = 1;
        }
        break;
    }

    spi_submit_or_update_session_timer(tspi, session, timeout);
    session->need_change_timeout = 0;

    return err;
}

static_always_inline spi_session_t *
spi_search_session(spi_main_t *spim,
                   u64 hash,
                   spi_pkt_info_t *pkt)
{
    clib_bihash_kv_48_8_t kv_result;

    spi_per_thread_data_t *tspi = NULL;

    if (!clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                                                    hash, 
                                                    (clib_bihash_kv_48_8_t *)pkt->pkt_l3l4.key, 
                                                    &kv_result))
    {
        tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(kv_result.value)];
        return pool_elt_at_index (tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(kv_result.value));
    }

    return NULL;
}

static_always_inline int
spi_create_session(f64 now, 
                   spi_main_t *spim,
                   spi_per_thread_data_t *tspi,
                   u64 hash,
                   spi_pkt_info_t *pkt, 
                   int is_output,
                   spi_session_t **new_session)
{
    clib_bihash_kv_48_8_t kv;

    spi_session_type_e type;

    spi_session_t *session = NULL;

    switch(pkt->pkt_l3l4.proto)
    {
    case IP_PROTOCOL_TCP:
        if (pkt->pkt_info.icmp_o_tcp_flags != TCP_FLAG_SYN)
        {
            return SPI_NODE_ERROR_TCP_NON_SYN_DROP;
        }
        type = SPI_SESSION_TYPE_TCP;
        break;
    case IP_PROTOCOL_ICMP:
        if (pkt->pkt_info.icmp_o_tcp_flags != ICMP4_echo_request)
        {
            return SPI_NODE_ERROR_BAD_ICMP_TYPE;
        }
        type = SPI_SESSION_TYPE_ICMP;
        break;
    case IP_PROTOCOL_ICMP6:
        if (pkt->pkt_info.icmp_o_tcp_flags != ICMP6_echo_request)
        {
            return SPI_NODE_ERROR_BAD_ICMP_TYPE;
        }
        type = SPI_SESSION_TYPE_ICMP;
        break;
    case IP_PROTOCOL_UDP:
        type = SPI_SESSION_TYPE_UDP;
        break;
    default:
        type = SPI_SESSION_TYPE_OTHER;
        break;
    }

    if (pool_elts (tspi->sessions) >= tspi->max_session)
    {
        clib_warning ("SPI Thread %d: MAX_SESSIONS_EXCEEDED(%u-%u)!!", tspi->thread_index, pool_elts (tspi->sessions), tspi->max_session);
        return SPI_NODE_ERROR_MAX_SESSIONS_EXCEEDED;
    }

    pool_get_zero (tspi->sessions, session);

    session->index = session - tspi->sessions;
    session->thread_index = tspi->thread_index;
    session->hash = hash;
    session->create_by_output = is_output;
    session->exchanged_tuple = pkt->pkt_info.exchanged_tuple;
    session->is_ip6 = pkt->pkt_l3l4.is_ip6;
    session->proto        = pkt->pkt_l3l4.proto;
    session->session_type = type;
    session->create_timestamp = now;
    session->session_timer_handle = (~0);
    session->flow[SPI_FLOW_DIR_UPLINK].geosite_match_acl = (~0);
    //fill flow
    if (pkt->pkt_info.exchanged_tuple)
    {
        session->flow[SPI_FLOW_DIR_UPLINK].sport = pkt->pkt_l3l4.port[1];
        session->flow[SPI_FLOW_DIR_UPLINK].dport = pkt->pkt_l3l4.port[0];
        session->flow[SPI_FLOW_DIR_DOWNLINK].sport = pkt->pkt_l3l4.port[0];
        session->flow[SPI_FLOW_DIR_DOWNLINK].dport = pkt->pkt_l3l4.port[1];

        if (pkt->pkt_l3l4.is_ip6)
        {
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr, &pkt->pkt_l3l4.ip6.addr[1]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr, &pkt->pkt_l3l4.ip6.addr[0]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr, &pkt->pkt_l3l4.ip6.addr[0]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr, &pkt->pkt_l3l4.ip6.addr[1]);
        }
        else
        {
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 = pkt->pkt_l3l4.ip4.addr[1].as_u32;
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32 = pkt->pkt_l3l4.ip4.addr[0].as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32 = pkt->pkt_l3l4.ip4.addr[0].as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr.as_u32 = pkt->pkt_l3l4.ip4.addr[1].as_u32;
        }
    }
    else 
    {
        session->flow[SPI_FLOW_DIR_UPLINK].sport = pkt->pkt_l3l4.port[0];
        session->flow[SPI_FLOW_DIR_UPLINK].dport = pkt->pkt_l3l4.port[1];
        session->flow[SPI_FLOW_DIR_DOWNLINK].sport = pkt->pkt_l3l4.port[1];
        session->flow[SPI_FLOW_DIR_DOWNLINK].dport = pkt->pkt_l3l4.port[0];

        if (pkt->pkt_l3l4.is_ip6)
        {
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr, &pkt->pkt_l3l4.ip6.addr[0]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr, &pkt->pkt_l3l4.ip6.addr[1]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr, &pkt->pkt_l3l4.ip6.addr[1]);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr, &pkt->pkt_l3l4.ip6.addr[0]);
        }
        else
        {
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 = pkt->pkt_l3l4.ip4.addr[0].as_u32;
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32 = pkt->pkt_l3l4.ip4.addr[1].as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32 = pkt->pkt_l3l4.ip4.addr[1].as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr.as_u32 = pkt->pkt_l3l4.ip4.addr[0].as_u32;
        }
    }

    if (pkt->pkt_l3l4.proto == IP_PROTOCOL_TCP)
    {
        session->flow[SPI_FLOW_DIR_UPLINK].tcp_ack_number = pkt->pkt_info.tcp_ack_number;
        session->flow[SPI_FLOW_DIR_UPLINK].tcp_seq_number = pkt->pkt_info.tcp_seq_number;
    }

    /* add session to session table */
    clib_memcpy(kv.key, pkt->pkt_l3l4.key, 48);
    SPI_BIHASH_SESSION_VALUE_SET(kv.value, session->thread_index, session->index);
    clib_bihash_add_del_with_hash_48_8(&spim->session_table, &kv, hash, 1);

    vlib_set_simple_counter (&spim->total_sessions_counter, tspi->thread_index, 0, pool_elts (tspi->sessions));
    vlib_increment_simple_counter (&spim->session_ip_type_counter, tspi->thread_index, pkt->pkt_l3l4.is_ip6, 1);
    vlib_increment_simple_counter (&spim->session_type_counter[type], tspi->thread_index, pkt->pkt_l3l4.is_ip6, 1);

    *new_session = session;

    return SPI_NODE_ERROR_NO_ERR;
}

static_always_inline int
spi_delete_session(spi_main_t *spim,
                   spi_per_thread_data_t *tspi,
                   spi_session_t *session)
{
    clib_bihash_kv_48_8_t kv;
    spi_session_type_e type;

    clib_memset(&kv, 0, sizeof(clib_bihash_kv_48_8_t));

    /* only pkt_l3l4 is valid*/
    spi_pkt_info_t *pkt =  (spi_pkt_info_t *)&kv;

    pkt->pkt_l3l4.is_ip6 = session->is_ip6;
    pkt->pkt_l3l4.proto = session->proto;

    if (session->exchanged_tuple)
    {
        pkt->pkt_l3l4.port[1] = session->flow[SPI_FLOW_DIR_UPLINK].sport;
        pkt->pkt_l3l4.port[0] = session->flow[SPI_FLOW_DIR_UPLINK].dport;
        if (pkt->pkt_l3l4.is_ip6)
        {
            ip6_address_copy(&pkt->pkt_l3l4.ip6.addr[1], &session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr);
            ip6_address_copy(&pkt->pkt_l3l4.ip6.addr[0], &session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr);
        }
        else
        {
            pkt->pkt_l3l4.ip4.addr[1].as_u32 = session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 ;
            pkt->pkt_l3l4.ip4.addr[0].as_u32 = session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32 ;
        }

    }
    else
    {
        pkt->pkt_l3l4.port[0] = session->flow[SPI_FLOW_DIR_UPLINK].sport;
        pkt->pkt_l3l4.port[1] = session->flow[SPI_FLOW_DIR_UPLINK].dport;
        if (pkt->pkt_l3l4.is_ip6)
        {
            ip6_address_copy(&pkt->pkt_l3l4.ip6.addr[0], &session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr);
            ip6_address_copy(&pkt->pkt_l3l4.ip6.addr[1], &session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr);
        }
        else
        {
            pkt->pkt_l3l4.ip4.addr[0].as_u32 = session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32;
            pkt->pkt_l3l4.ip4.addr[1].as_u32 = session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32;
        }
    }

    type = session->session_type;

    /* del session to timer */
    spi_clear_session_timer(tspi, session);

    /* del session to session table */
    clib_bihash_add_del_with_hash_48_8(&spim->session_table, &kv, session->hash, 0);

    session->session_is_free = 1;

    pool_put_index (tspi->sessions, session->index);

    vlib_set_simple_counter (&spim->total_sessions_counter, tspi->thread_index, 0, pool_elts (tspi->sessions));
    vlib_decrement_simple_counter (&spim->session_ip_type_counter, tspi->thread_index, pkt->pkt_l3l4.is_ip6, 1);
    vlib_decrement_simple_counter (&spim->session_type_counter[type], tspi->thread_index, pkt->pkt_l3l4.is_ip6, 1);

    return SPI_NODE_ERROR_NO_ERR;
}

static_always_inline int  
spi_check_update_spi_session(f64 now, 
                             spi_main_t *spim,
                             vlib_buffer_t *buffer, 
                             spi_session_t *session, 
                             spi_pkt_info_t *pkt,
                             spi_flow_dir_e dir,
                             u32 in_sw_if_index, 
                             u32 out_sw_if_index,
                             int is_output)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    spi_per_thread_data_t *tspi = &spim->per_thread_data[session->thread_index];

    if (session->proto != pkt->pkt_l3l4.proto)
        return SPI_NODE_ERROR_PROTOCOL_MATCH_ERR;

    session->flow[dir].in_sw_if_index = in_sw_if_index;
    session->flow[dir].out_sw_if_index = out_sw_if_index;

    /* 
     * For sessions created in input, on the output side, 
     * we only need to update the export information briefly
     * This is also the most common situation
     *
     * Output side sessions created usually occurs when the message has undergone NAT, tunnel, etc 
     * There are two situations:
     *    one is to re-enter the input, and the other is to directly enter the output
     *
     * Sessions processed through SPI will be saved in the vnet_buffer2 cache
     * Therefore, we determine whether it is consistent with the cache, 
     * and if so, skip this process
     */
    if ((buffer->flags & VLIB_BUFFER_SPI_SESSION_VALID) &&
        session->index == vnet_buffer2(buffer)->spi.cached_session_index && 
        session->thread_index == vnet_buffer2(buffer)->spi.cached_session_thread)
    {
        return SPI_NODE_ERROR_NO_ERR;
    }

    /* process session state and timeout */

    SPI_THREAD_LOCK(tspi);

    switch(session->proto)
    {
    case IP_PROTOCOL_TCP:
        err = spi_tcp_session_state_proc(session, pkt, dir, now);
        spi_tcp_session_timeout_proc(spim, tspi, session);
        if (!err)
        {
            session->flow[dir].tcp_ack_number = pkt->pkt_info.tcp_ack_number;
            session->flow[dir].tcp_seq_number = pkt->pkt_info.tcp_seq_number;
        }
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
        err = spi_icmp_session_state_proc(session, pkt, dir, now);
        spi_icmp_session_timeout_proc(spim, tspi, session);
        break;
    case IP_PROTOCOL_UDP:
        err = spi_udp_session_state_proc(session, pkt, dir, now);
        spi_udp_session_timeout_proc(spim, tspi, session);
        break;
    default:
        err = spi_other_session_state_proc(session, pkt, dir, now);
        spi_other_session_timeout_proc(spim, tspi, session);
        break;
    }

    SPI_THREAD_UNLOCK(tspi);

    if (!err) 
    {
        session->last_pkt_timestamp = now;
        session->total_bytes[dir] += pkt->pkt_info.pkt_len;
        session->total_pkts[dir] += 1;
    }
    else
    {
        session->drop_bytes[dir] += pkt->pkt_info.pkt_len;
        session->drop_pkts[dir] += 1;
    }

    return err;
}

static_always_inline void
spi_proc_session_fn(vlib_main_t *vm, 
                    vlib_node_runtime_t *node,
                    spi_runtime_t *rt,
                    vlib_buffer_t *buffer,
                    spi_pkt_info_t *pkt, u16 *next, 
                    u64 hash, u32 in_sw_if_index, u32 out_sw_if_index,
                    int is_output,
                    spi_trace_t *trace)
{
    int err = SPI_NODE_ERROR_NO_ERR;

    spi_main_t *spim = &spi_main;

    f64 now = vlib_time_now (vm);

    spi_session_t *session = NULL;
    spi_flow_dir_e dir;
    u8 skip_spi = 0;

    spi_per_thread_data_t *tspi = &spim->per_thread_data[vm->thread_index];

    if (PREDICT_FALSE(!spim->enabled))
    {
        skip_spi = 1;
        goto spi_trace;
    }

    switch(pkt->pkt_l3l4.proto)
    {
    case IP_PROTOCOL_TCP:
        if (!spim->tcp_enable)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        break;
    case IP_PROTOCOL_UDP:
        if (!spim->udp_enable)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        break;
    case IP_PROTOCOL_ICMP:
        if (!spim->icmp_enable)
        {
            skip_spi = 1;
            goto spi_trace;
        }

        if (pkt->pkt_info.icmp_o_tcp_flags != ICMP4_echo_request &&
            pkt->pkt_info.icmp_o_tcp_flags != ICMP4_echo_reply)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        break;
    case IP_PROTOCOL_ICMP6:
        if (!spim->icmp_enable)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        if (pkt->pkt_info.icmp_o_tcp_flags != ICMP6_echo_request &&
            pkt->pkt_info.icmp_o_tcp_flags != ICMP6_echo_reply)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        break;
    default:
        if (!spim->other_enable)
        {
            skip_spi = 1;
            goto spi_trace;
        }
        break;
    }

    session = spi_search_session(spim, hash, pkt);
    if (session == NULL)
    {
        err = spi_create_session(now, spim, tspi, hash, pkt, is_output, &session);
        if (session == NULL) 
        {
            buffer->error = node->errors[err];
            *next = 0;
            goto spi_trace;
        }

        spi_create_session_associated_session_proc(spim, buffer, session, is_output);

    }

    dir = spi_check_flow_dir(session, pkt);

    err = spi_check_update_spi_session(now, spim, buffer, session, pkt, dir, in_sw_if_index, out_sw_if_index, is_output);
    if (err != SPI_NODE_ERROR_NO_ERR) 
    {
        //drop
        buffer->error = node->errors[err];
        *next = 0;
        goto spi_trace;
    }

    //update vnet_buffer spi cached
    buffer->flags |= VLIB_BUFFER_SPI_SESSION_VALID;
    vnet_buffer2(buffer)->spi.cached_session_thread = session->thread_index;
    vnet_buffer2(buffer)->spi.cached_session_index = session->index;

spi_trace:
    if (trace)
    {
        trace->skip_spi = skip_spi;

        trace->thread_index = tspi->thread_index;
        trace->in_sw_if_index  = in_sw_if_index;
        trace->out_sw_if_index  = out_sw_if_index;
        trace->next_index  = *next;
        trace->icmp_o_tcp_flags = pkt->pkt_info.icmp_o_tcp_flags;

        trace->session_index = session ? session->index : (u32)(~0);
    }
    return;
}

static_always_inline void
spi_get_sw_if_index (int is_output, 
                     vlib_buffer_t ** b, 
                     u32 * in_sw_if_index, 
                     u32 * out_sw_if_index)
{
    if (is_output)
    {
        in_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
        out_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
    }
    else
    {
        in_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
        out_sw_if_index[0] = ~0;
    }
}

static_always_inline void
spi_get_sw_if_index_x4 (int is_output, 
                        vlib_buffer_t ** b, 
                        u32 * in_sw_if_index, 
                        u32 * out_sw_if_index)
{
    if (is_output)
    {
        in_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
        out_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_TX];

        in_sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
        out_sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_TX];

        in_sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
        out_sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_TX];

        in_sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
        out_sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_TX];
    }
    else
    {
        in_sw_if_index[0] = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
        in_sw_if_index[1] = vnet_buffer (b[1])->sw_if_index[VLIB_RX];
        in_sw_if_index[2] = vnet_buffer (b[2])->sw_if_index[VLIB_RX];
        in_sw_if_index[3] = vnet_buffer (b[3])->sw_if_index[VLIB_RX];
    }
}

/**
 * @brief Get L4 information like port number or ICMP id from IPv6 packet.
 *
 * @param ip6        IPv6 header.
 * @param buffer_len Buffer length.
 * @param ip_protocol L4 protocol
 * @param src_port L4 src port or icmp id
 * @param dst_post L4 dst port or icmp id
 * @param icmp_type_or_tcp_flags ICMP type or TCP flags, if applicable
 * @param tcp_ack_number TCP ack number, if applicable
 * @param tcp_seq_number TCP seq number, if applicable
 *
 * @returns 0 on success, -1 parse fail, -2 not first fragment.
 */
static_always_inline int
spi_ip6_get_port (vlib_main_t * vm, vlib_buffer_t * b, ip6_header_t * ip6,
	      u16 buffer_len, u8 * ip_protocol, u16 * src_port,
	      u16 * dst_port, u8 * icmp_type_or_tcp_flags,
	      u32 * tcp_ack_number, u32 * tcp_seq_number)
{
    u8 l4_protocol;
    u16 l4_offset;
    u16 frag_offset;
    u8 *l4;

    if (ip6_parse (vm, b, ip6, buffer_len, &l4_protocol, &l4_offset,
                &frag_offset))
    {
        return -1;
    }
    if (frag_offset &&
            ip6_frag_hdr_offset (((ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset))))
        return -2;			//Can't deal with non-first fragment for now

    if (ip_protocol)
    {
        *ip_protocol = l4_protocol;
    }
    l4 = u8_ptr_add (ip6, l4_offset);
    if (l4_protocol == IP_PROTOCOL_TCP || l4_protocol == IP_PROTOCOL_UDP)
    {
        if (src_port)
            *src_port = ((udp_header_t *) (l4))->src_port;
        if (dst_port)
            *dst_port = ((udp_header_t *) (l4))->dst_port;
        if (icmp_type_or_tcp_flags && l4_protocol == IP_PROTOCOL_TCP)
            *icmp_type_or_tcp_flags = ((tcp_header_t *) (l4))->flags;
        if (tcp_ack_number && l4_protocol == IP_PROTOCOL_TCP)
            *tcp_ack_number = ((tcp_header_t *) (l4))->ack_number;
        if (tcp_seq_number && l4_protocol == IP_PROTOCOL_TCP)
            *tcp_seq_number = ((tcp_header_t *) (l4))->seq_number;
    }
    else if (l4_protocol == IP_PROTOCOL_ICMP6)
    {
        icmp46_header_t *icmp = (icmp46_header_t *) (l4);
        if (icmp_type_or_tcp_flags)
            *icmp_type_or_tcp_flags = ((icmp46_header_t *) (l4))->type;
        if (icmp->type == ICMP6_echo_request)
        {
            if (src_port)
                *src_port = ((u16 *) (icmp))[2];
            if (dst_port)
                *dst_port = ((u16 *) (icmp))[2];
        }
        else if (icmp->type == ICMP6_echo_reply)
        {
            if (src_port)
                *src_port = ((u16 *) (icmp))[2];
            if (dst_port)
                *dst_port = ((u16 *) (icmp))[2];
        }
        else if (clib_net_to_host_u16 (ip6->payload_length) >= 64)
        {
            u16 ip6_pay_len;
            ip6_header_t *inner_ip6;
            u8 inner_l4_protocol;
            u16 inner_l4_offset;
            u16 inner_frag_offset;
            u8 *inner_l4;

            ip6_pay_len = clib_net_to_host_u16 (ip6->payload_length);
            inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);

            if (ip6_parse (vm, b, inner_ip6, ip6_pay_len - 8,
                        &inner_l4_protocol, &inner_l4_offset,
                        &inner_frag_offset))
                return -1;

            if (inner_frag_offset &&
                    ip6_frag_hdr_offset (((ip6_frag_hdr_t *)
                            u8_ptr_add (inner_ip6,
                                inner_frag_offset))))
                return -2;

            inner_l4 = u8_ptr_add (inner_ip6, inner_l4_offset);
            if (inner_l4_protocol == IP_PROTOCOL_TCP ||
                    inner_l4_protocol == IP_PROTOCOL_UDP)
            {
                if (src_port)
                    *src_port = ((udp_header_t *) (inner_l4))->dst_port;
                if (dst_port)
                    *dst_port = ((udp_header_t *) (inner_l4))->src_port;
            }
            else if (inner_l4_protocol == IP_PROTOCOL_ICMP6)
            {
                icmp46_header_t *inner_icmp = (icmp46_header_t *) (inner_l4);
                if (inner_icmp->type == ICMP6_echo_request)
                {
                    if (src_port)
                        *src_port = ((u16 *) (inner_icmp))[2];
                    if (dst_port)
                        *dst_port = ((u16 *) (inner_icmp))[2];
                }
                else if (inner_icmp->type == ICMP6_echo_reply)
                {
                    if (src_port)
                        *src_port = ((u16 *) (inner_icmp))[2];
                    if (dst_port)
                        *dst_port = ((u16 *) (inner_icmp))[2];
                }
            }
        }
    }
    return 0;
}

static_always_inline void
spi_fill_pkt (vlib_main_t * vm,
              int is_ip6, int is_output,
              vlib_buffer_t * b0, 
              spi_pkt_info_t * pkt)
{
    int l3_offset;
    int rv = 0;

    clib_memset(pkt, 0, sizeof(spi_pkt_info_t));

    if (is_output)
    {
        l3_offset = vnet_buffer(b0)->ip.reass.save_rewrite_length;
    }
    else
    {
        l3_offset = 0;
    }

    if (is_ip6)
    {
        ip6_header_t *ip6 = vlib_buffer_get_current (b0) + l3_offset;
        pkt->pkt_l3l4.is_ip6 = 1;

        if (is_output)
        {
            if (clib_memcmp(&ip6->src_address, &ip6->dst_address, sizeof(ip6_address_t)) >= 0)
            {
                pkt->pkt_l3l4.ip6.addr[0].as_u128 = ip6->src_address.as_u128;
                pkt->pkt_l3l4.ip6.addr[1].as_u128 = ip6->dst_address.as_u128;
                rv = spi_ip6_get_port (vm, b0, ip6, b0->current_length,
                            &pkt->pkt_l3l4.proto,
                            &pkt->pkt_l3l4.port[0],
                            &pkt->pkt_l3l4.port[1],
                            &pkt->pkt_info.icmp_o_tcp_flags,
                            &pkt->pkt_info.tcp_ack_number,
                            &pkt->pkt_info.tcp_seq_number);
                if (rv == -2 )
                    pkt->pkt_info.is_nonfirst_fragment = vnet_buffer(b0)->ip.reass.is_non_first_fragment;
            }
            else
            {
                pkt->pkt_info.exchanged_tuple = 1;
                pkt->pkt_l3l4.ip6.addr[1].as_u128 = ip6->src_address.as_u128;
                pkt->pkt_l3l4.ip6.addr[0].as_u128 = ip6->dst_address.as_u128;
                rv = spi_ip6_get_port (vm, b0, ip6, b0->current_length,
                            &pkt->pkt_l3l4.proto,
                            &pkt->pkt_l3l4.port[1],
                            &pkt->pkt_l3l4.port[0],
                            &pkt->pkt_info.icmp_o_tcp_flags,
                            &pkt->pkt_info.tcp_ack_number,
                            &pkt->pkt_info.tcp_seq_number);
                if (rv == -2 )
                    pkt->pkt_info.is_nonfirst_fragment = vnet_buffer(b0)->ip.reass.is_non_first_fragment;
            }
        }
        else
        {
            if (clib_memcmp(&ip6->src_address, &ip6->dst_address, sizeof(ip6_address_t)) >= 0)
            {
                pkt->pkt_l3l4.ip6.addr[0].as_u128 = ip6->src_address.as_u128;
                pkt->pkt_l3l4.ip6.addr[1].as_u128 = ip6->dst_address.as_u128;
                pkt->pkt_l3l4.port[0] = vnet_buffer(b0)->ip.reass.l4_src_port;
                pkt->pkt_l3l4.port[1] = vnet_buffer(b0)->ip.reass.l4_dst_port;
            }
            else
            {
                pkt->pkt_info.exchanged_tuple = 1;
                pkt->pkt_l3l4.ip6.addr[1].as_u128 = ip6->src_address.as_u128;
                pkt->pkt_l3l4.ip6.addr[0].as_u128 = ip6->dst_address.as_u128;
                pkt->pkt_l3l4.port[1] = vnet_buffer(b0)->ip.reass.l4_src_port;
                pkt->pkt_l3l4.port[0] = vnet_buffer(b0)->ip.reass.l4_dst_port;
            }
            pkt->pkt_l3l4.proto = vnet_buffer(b0)->ip.reass.ip_proto;
            pkt->pkt_info.icmp_o_tcp_flags = vnet_buffer(b0)->ip.reass.icmp_type_or_tcp_flags;
            pkt->pkt_info.tcp_ack_number = vnet_buffer(b0)->ip.reass.tcp_ack_number;
            pkt->pkt_info.tcp_seq_number = vnet_buffer(b0)->ip.reass.tcp_seq_number;
            pkt->pkt_info.is_nonfirst_fragment = vnet_buffer(b0)->ip.reass.is_non_first_fragment;
        }

        pkt->pkt_info.pkt_len = vlib_buffer_length_in_chain(vm, b0);
    }
    else
    {
        pkt->pkt_l3l4.is_ip6 = 0;

        ip4_header_t *ip4 = vlib_buffer_get_current (b0) + l3_offset;
        if (ip4->src_address.as_u32 > ip4->dst_address.as_u32)
        {
            pkt->pkt_l3l4.ip4.addr[0].as_u32 = ip4->src_address.as_u32;
            pkt->pkt_l3l4.ip4.addr[1].as_u32 = ip4->dst_address.as_u32;
            pkt->pkt_l3l4.port[0] = vnet_buffer(b0)->ip.reass.l4_src_port;
            pkt->pkt_l3l4.port[1] = vnet_buffer(b0)->ip.reass.l4_dst_port;
        }
        else
        {
            pkt->pkt_info.exchanged_tuple = 1;
            pkt->pkt_l3l4.ip4.addr[1].as_u32 = ip4->src_address.as_u32;
            pkt->pkt_l3l4.ip4.addr[0].as_u32 = ip4->dst_address.as_u32;
            pkt->pkt_l3l4.port[1] = vnet_buffer(b0)->ip.reass.l4_src_port;
            pkt->pkt_l3l4.port[0] = vnet_buffer(b0)->ip.reass.l4_dst_port;
        }
        pkt->pkt_l3l4.proto = vnet_buffer(b0)->ip.reass.ip_proto;
        pkt->pkt_info.icmp_o_tcp_flags = vnet_buffer(b0)->ip.reass.icmp_type_or_tcp_flags;
        pkt->pkt_info.tcp_ack_number = vnet_buffer(b0)->ip.reass.tcp_ack_number;
        pkt->pkt_info.tcp_seq_number = vnet_buffer(b0)->ip.reass.tcp_seq_number;
        pkt->pkt_info.is_nonfirst_fragment = vnet_buffer(b0)->ip.reass.is_non_first_fragment;

        pkt->pkt_info.pkt_len = vlib_buffer_length_in_chain(vm, b0);
    }
}

static_always_inline void
spi_fill_pkt_x4 (vlib_main_t * vm,
                 int is_ip6, int is_output,
                 vlib_buffer_t ** b, 
                 spi_pkt_info_t * pkt)
{
    spi_fill_pkt (vm, is_ip6, is_output, b[0], &pkt[0]);
    spi_fill_pkt (vm, is_ip6, is_output, b[1], &pkt[1]);
    spi_fill_pkt (vm, is_ip6, is_output, b[2], &pkt[2]);
    spi_fill_pkt (vm, is_ip6, is_output, b[3], &pkt[3]);
}


static_always_inline void
spi_session_hash (spi_pkt_info_t * pkt, u64 * hash)
{
    *hash = clib_bihash_hash_48_8 ((clib_bihash_kv_48_8_t *)pkt->pkt_l3l4.key);
}

static_always_inline void
spi_session_hash_x4 (spi_pkt_info_t * pkt, u64 * hash)
{
    spi_session_hash (&pkt[0], &hash[0]);
    spi_session_hash (&pkt[1], &hash[1]);
    spi_session_hash (&pkt[2], &hash[2]);
    spi_session_hash (&pkt[3], &hash[3]);
}

static_always_inline void 
spi_node_common_prepare_fn (vlib_main_t * vm,
                            spi_runtime_t *rt,
                            u32 n_left, u32 *from,
                            int is_ip6, int is_output)
{
    vlib_buffer_t **b;
    u32 *in_sw_if_index;
    u32 *out_sw_if_index;
    spi_pkt_info_t *spi_pkt;
    u64 *hash;

    b = rt->bufs;
    in_sw_if_index = rt->in_sw_if_indices;
    out_sw_if_index = rt->out_sw_if_indices;
    spi_pkt = rt->pkts;
    hash = rt->hashes;


    while (n_left >= 8)
    {
        vlib_prefetch_buffer_header (b[4], LOAD);
        vlib_prefetch_buffer_header (b[5], LOAD);
        vlib_prefetch_buffer_header (b[6], LOAD);
        vlib_prefetch_buffer_header (b[7], LOAD);
        vlib_prefetch_buffer_data (b[4], LOAD);
        vlib_prefetch_buffer_data (b[5], LOAD);
        vlib_prefetch_buffer_data (b[6], LOAD);
        vlib_prefetch_buffer_data (b[7], LOAD);

        spi_get_sw_if_index_x4 (is_output, b, in_sw_if_index, out_sw_if_index);
        spi_fill_pkt_x4 (vm, is_ip6, is_output, b, spi_pkt);
        spi_session_hash_x4 (spi_pkt, hash);

        n_left -= 4;

        b += 4;
        in_sw_if_index += 4;
        out_sw_if_index += 4;
        spi_pkt += 4;
        hash += 4;
    }

    while (n_left > 0)
    {
        spi_get_sw_if_index (is_output, b, in_sw_if_index, out_sw_if_index);
        spi_fill_pkt (vm, is_ip6, is_output, b[0], spi_pkt);
        spi_session_hash (spi_pkt, hash);

        n_left -= 1;
        b += 1;
        in_sw_if_index += 1;
        out_sw_if_index += 1;
        spi_pkt += 1;
        hash += 1;
    }

    return;
}

static_always_inline void 
spi_handoff_node_common_prepare_fn (vlib_main_t * vm,
                            spi_handoff_runtime_t *rt,
                            u32 n_left, u32 *from,
                            int is_ip6, int is_output)
{
    vlib_buffer_t **b;
    spi_pkt_info_t *spi_pkt;
    u64 *hash;

    b = rt->bufs;
    spi_pkt = rt->pkts;
    hash = rt->hashes;

    while (n_left >= 8)
    {
        vlib_prefetch_buffer_header (b[4], LOAD);
        vlib_prefetch_buffer_header (b[5], LOAD);
        vlib_prefetch_buffer_header (b[6], LOAD);
        vlib_prefetch_buffer_header (b[7], LOAD);
        vlib_prefetch_buffer_data (b[4], LOAD);
        vlib_prefetch_buffer_data (b[5], LOAD);
        vlib_prefetch_buffer_data (b[6], LOAD);
        vlib_prefetch_buffer_data (b[7], LOAD);

        spi_fill_pkt_x4 (vm, is_ip6, is_output, b, spi_pkt);
        spi_session_hash_x4 (spi_pkt, hash);

        n_left -= 4;

        b += 4;
        spi_pkt += 4;
        hash += 4;
    }

    while (n_left > 0)
    {
        spi_fill_pkt (vm, is_ip6, is_output, b[0], spi_pkt);
        spi_session_hash (spi_pkt, hash);

        n_left -= 1;
        b += 1;
        spi_pkt += 1;
        hash += 1;
    }

    return;
}


#endif
