/*
 * spi_api.c - spi api
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

#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip_types_api.h>

#include <vlibmemory/api.h>
#include <vlibapi/api.h>

#include <spi/spi.api_enum.h>
#include <spi/spi.api_types.h>

#define REPLY_MSG_ID_BASE spi_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

#include <spi/spi.h>

static int 
api_spi_session_enable_disable(bool is_enable, 
                               bool handoff_enabled, 
                               u32 max_sessions_per_thread,
                               u32 timer_process_frequency)
{
    spi_config_t config;

    memset(&config, 0, sizeof(spi_config_t));

    config.handoff_enabled = handoff_enabled ? 1 : 0;

    config.max_sessions_per_thread = max_sessions_per_thread;
    config.timer_process_frequency = timer_process_frequency;

    if (is_enable)
        return spi_feature_enable (&config);
    else
        return spi_feature_disable ();
}

static int 
api_spi_session_proto_enable_disable(bool is_enable, 
                                    vl_api_spi_support_session_proto_type_t type)
{
    return spi_session_proto_enable_disable((spi_session_type_e) type, is_enable);
}

static int 
api_spi_set_session_timeouts(bool use_default, 
                             u32 tcp_transitory,
                             u32 tcp_established,
                             u32 tcp_closing,
                             u32 udp, u32 icmp, u32 other)
{
    spi_timeouts_config_t spi_timeout_config;

    memset(&spi_timeout_config, 0, sizeof(spi_timeouts_config_t));

    spi_timeout_config.tcp_transitory = tcp_transitory;
    spi_timeout_config.tcp_established = tcp_established;
    spi_timeout_config.tcp_closing = tcp_closing;
    spi_timeout_config.udp = udp;
    spi_timeout_config.icmp = icmp;
    spi_timeout_config.other = other;

    spi_timeout_update (use_default, &spi_timeout_config);

    return 0;
}

static int 
api_spi_add_del_3tuple_timeouts(bool is_add, 
                                vl_api_address_t *ip_address,
                                u16 port,
                                u8 proto,
                                u32 timeout)
{
    ip46_address_t ip;
    ip46_type_t type;
    type = ip_address_decode(ip_address, &ip);
    return spi_exact_3tuple_timeout_add_del(&ip, type, proto, htons(port), timeout, is_add);
}

static int 
api_spi_get_session_number(bool ip_filter, 
                           vl_api_address_family_t af,
                           bool proto_filter,
                           vl_api_spi_support_session_proto_type_t type,
                           u64 *session_num)
{
    counter_t totol_session;
    counter_t ip4_session;
    counter_t ip6_session;
    counter_t ip4_proto_session[SPI_SESSION_TYPE_MAX];
    counter_t ip6_proto_session[SPI_SESSION_TYPE_MAX];

    if (!ip_filter && !proto_filter)
    {
        spi_get_session_number(&totol_session, NULL, NULL, NULL, NULL);
        *session_num = totol_session;
        return 0;
    }
    else if (ip_filter && !proto_filter)
    {
        if (af == ADDRESS_IP4)
        {
            spi_get_session_number(NULL, &ip4_session, NULL, NULL, NULL);
            *session_num = ip4_session;
            return 0;
        }
        else
        {
            spi_get_session_number(NULL, NULL, NULL, &ip6_session, NULL);
            *session_num = ip6_session;
            return 0;
        }
    }
    else if (!ip_filter && proto_filter)
    {
        spi_get_session_number(NULL, NULL, ip4_proto_session, NULL, ip6_proto_session);
        *session_num = ip4_proto_session[type] + ip6_proto_session[type];
        return 0;
    }
    else if (ip_filter && proto_filter)
    {
        if (af == ADDRESS_IP4)
        {
            spi_get_session_number(NULL, NULL, ip4_proto_session, NULL, NULL);
            *session_num = ip4_proto_session[type];
        }
        else
        {
            spi_get_session_number(NULL, NULL, NULL, NULL, ip6_proto_session);
            *session_num = ip6_proto_session[type];
        }
    }
    return 0;
}

static void
vl_api_spi_session_enable_disable_t_handler (vl_api_spi_session_enable_disable_t * mp)
{
    int rv;
    vl_api_spi_session_enable_disable_reply_t *rmp;

    rv = api_spi_session_enable_disable(mp->is_enable, 
                                        mp->handoff_enabled, 
                                        ntohl(mp->max_sessions_per_thread), 
                                        ntohl(mp->timer_process_frequency));

    REPLY_MACRO (VL_API_SPI_SESSION_ENABLE_DISABLE_REPLY);
}

static void
vl_api_spi_session_proto_enable_disable_t_handler (vl_api_spi_session_proto_enable_disable_t * mp)
{
    int rv;
    vl_api_spi_session_proto_enable_disable_reply_t *rmp;

    rv = api_spi_session_proto_enable_disable(mp->is_enable, ntohl(mp->type));

    REPLY_MACRO (VL_API_SPI_SESSION_PROTO_ENABLE_DISABLE_REPLY);
}

static void
vl_api_spi_set_session_timeouts_t_handler (vl_api_spi_set_session_timeouts_t * mp)
{
    int rv;
    vl_api_spi_set_session_timeouts_reply_t *rmp;

    rv = api_spi_set_session_timeouts(mp->use_default, 
                                     ntohl(mp->tcp_transitory),
                                     ntohl(mp->tcp_established),
                                     ntohl(mp->tcp_closing),
                                     ntohl(mp->udp),
                                     ntohl(mp->icmp),
                                     ntohl(mp->other));

    REPLY_MACRO (VL_API_SPI_SET_SESSION_TIMEOUTS_REPLY);
}

static void
vl_api_spi_add_del_3tuple_timeouts_t_handler (vl_api_spi_add_del_3tuple_timeouts_t * mp)
{
    int rv;
    vl_api_spi_add_del_3tuple_timeouts_reply_t *rmp;

    rv = api_spi_add_del_3tuple_timeouts(mp->is_add, 
                                         &mp->ip_address,
                                         ntohs(mp->port),
                                         mp->proto,
                                         ntohl(mp->timeout));

    REPLY_MACRO (VL_API_SPI_ADD_DEL_3TUPLE_TIMEOUTS_REPLY);
}

static void
vl_api_spi_get_session_number_t_handler (vl_api_spi_get_session_number_t * mp)
{
    int rv;
    vl_api_spi_get_session_number_reply_t *rmp;

    u64 session_num = 0;

    rv = api_spi_get_session_number(mp->ip_filter, mp->af,
                                    mp->proto_filter, ntohl(mp->type), &session_num);

    REPLY_MACRO2 (VL_API_SPI_GET_SESSION_NUMBER_REPLY,
       ({
        rmp->session_num = clib_host_to_net_u64(session_num);
        })
    );
}

/* API definitions */
#include <vnet/format_fns.h>
#include <spi/spi.api.c>

/* Set up the API message handling tables */
clib_error_t *
spi_api_hookup (vlib_main_t *vm)
{
    spi_main_t *spim = &spi_main;
    spim->msg_id_base = setup_message_id_table ();
    return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
