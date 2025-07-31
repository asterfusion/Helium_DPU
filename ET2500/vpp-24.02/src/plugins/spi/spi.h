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

#ifndef included_spi_h
#define included_spi_h

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <vppinfra/tw_timer_16t_2w_512sl.h>
#include <vppinfra/bihash_48_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/pool.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/sparse_vec.h>


#define SPI_TW_TIMER_PROCESS_DEFAULT_FREQUENCY   (2)
#define SPI_TW_TIMER_PER_PROCESS_MAX_EXPIRATIONS (1024)

#define SPI_DEFAULT_MAX_SESSION_PER_THREAD        (128 * 1024) //128K session
#define SPI_EXACT_3TUPLE_MAX_TIMEOUTS             (1024) //1k exact timeout

#define SPI_BIHASH_SESSION_VALUE_GET_THREAD(x)     ((x >> 32) & 0xff)
#define SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(x) (x & 0xffffffff)
#define SPI_BIHASH_SESSION_VALUE_SET(x, thread, session_id)     (x = ((u64)thread << 32) | (session_id))

#define SPI_THREAD_LOCK(tspi) \
    do {\
        if (tspi->session_change_lock)  \
            clib_spinlock_lock (&tspi->session_change_lock); \
    } while(0);

#define SPI_THREAD_UNLOCK(tspi) \
    do {\
        if (tspi->session_change_lock)  \
            clib_spinlock_unlock (&tspi->session_change_lock); \
    } while(0);

#define foreach_spi_node_error                                                \
  _ (NO_ERR, "no error")                                                      \
  _ (PROTOCOL_MATCH_ERR, "session match proto err")                           \
  _ (UNSUPPORTED_PROTOCOL, "unsupported protocol")                            \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")                                  \
  _ (MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")                      \
  _ (TCP_SYN_FAST, "Tcp SYN too fast packet drop")                            \
  _ (TCP_NON_SYN_DROP, "Tcp non-SYN packet drop")                             \
  _ (TCP_TRNSL_DROP, "Tcp state translate : date packet drop")                \
  _ (TCP_CLOSING_DROP, "Tcp state closing : date packet drop")                \
  _ (GENERAL_IDLE_DROP, "general state idle : date packet drop")              \
  _ (STATE_ERROR_DROP, "state bug error : date packet drop")

typedef enum
{
#define _(sym,str) SPI_NODE_ERROR_##sym,
    foreach_spi_node_error
#undef _
    SPI_NODE_N_ERROR,
} spi_node_error_t;

#define foreach_spi_handoff_error                                           \
  _ (CONGESTION_DROP, "congestion drop")                                    \
  _ (SAME_WORKER, "same worker")                                            \
  _ (DO_HANDOFF, "do handoff")

typedef enum
{
#define _(sym, str) SPI_HANDOFF_ERROR_##sym,
    foreach_spi_handoff_error
#undef _
    SPI_HANDOFF_N_ERROR,
} spi_handoff_error_t;

#define foreach_spi_support_session_type    \
    _(TCP, tcp)                                  \
    _(UDP, udp)                                  \
    _(ICMP, icmp)                                 \
    _(OTHER, other)  

#define foreach_spi_timeout_def             \
    _(tcp_transitory, 10)                   \
    _(tcp_established, 600)                 \
    _(tcp_closing, 10)                      \
    _(udp, 120)                             \
    _(icmp, 20)                             \
    _(other, 120)                           

typedef enum
{ 
#define _(btype, ltype) SPI_SESSION_TYPE_##btype,
    foreach_spi_support_session_type
#undef _
    SPI_SESSION_TYPE_MAX,
} spi_session_type_e;

STATIC_ASSERT (SPI_SESSION_TYPE_MAX <= 64, 
                "SPI session types support a maximum of 64 types");

typedef enum
{ 
#define _(btype, ltype) SPI_SESSION_TYPE_BITMAP_##btype = (1 << SPI_SESSION_TYPE_##btype),
    foreach_spi_support_session_type
#undef _
} spi_session_type_bitmap_e;

typedef struct
{
#define _(type, timeout) u32 type;
    foreach_spi_timeout_def
#undef _

} spi_timeouts_config_t;

typedef struct
{
    u32 max_sessions_per_thread;
    u32 timer_process_frequency;
    u8 handoff_enabled;
} spi_config_t;

typedef enum
{
    SPI_AGING_PROCESS_RECONF = 1,
    SPI_AGING_PROCESS_DISABLE = 2,
} spi_aging_process_event_e;

typedef enum {
    SPI_ERROR_DROP,
    SPI_N_NEXT,
} spi_next_t;

typedef enum
{
    SPI_TCP_STATE_CLOSED = 0,
    SPI_TCP_STATE_TRANSITORY,
    SPI_TCP_STATE_ESTABLISHED,
    SPI_TCP_STATE_CLOSING,
    SPI_TCP_STATE_FREE,
    SPI_TCP_N_STATE,
} spi_tcp_state_e;

typedef enum
{
    SPI_GENERAL_STATE_CLOSED = 0,
    SPI_GENERAL_STATE_TRANSMIT,
    SPI_GENERAL_STATE_IDLE,
    SPI_GENERAL_N_STATE,
} spi_general_state_e;

typedef spi_general_state_e spi_udp_state_e;
typedef spi_general_state_e spi_icmp_state_e;
typedef spi_general_state_e spi_other_state_e;

typedef CLIB_PACKED(union
{
    clib_bihash_kv_24_8_t kv;
    struct {
        struct {
            u8 is_ip6;
            u8 proto;
            u16 port;
            u32 reserve;
            union 
            {
                struct 
                {
                    ip4_address_t  addr;
                } ip4;
                struct 
                {
                    ip6_address_t  addr;
                } ip6;
            };
        } key;
        struct {
            u32 transmit_timeout;
            u32 reserve;
        } value;
    };
}) spi_exact_3tuple_timeout_entry_t;

typedef enum
{
    SPI_FLOW_DIR_UPLINK = 0,
    SPI_FLOW_DIR_DOWNLINK,
    SPI_FLOW_N_DIR,
} spi_flow_dir_e;

typedef union {
    struct {
        union {
            u64 key[6];

            struct {
                u8             is_ip6;
                u8             proto;
                u16            port[2];
                union {
                    struct {
                        ip4_address_t  addr[2];
                    } ip4;
                    struct {
                        ip6_address_t  addr[2];
                    } ip6;
                };
            }; 
        } pkt_l3l4;

        union {
            u64 data[2];

            struct {
                u8 is_nonfirst_fragment:1;
                u8 exchanged_tuple:1; //if fill session exchanged set 1
                u8 flags_reserved:6;

                u8 icmp_o_tcp_flags;
                u8 u8_padding[2];

                u32 pkt_len;
                u32 tcp_ack_number;
                u32 tcp_seq_number;
            };
        } pkt_info;
    };
    u64 padding[8];
} spi_pkt_info_t;

typedef struct
{
    union  {
        struct {
            ip4_address_t saddr;
            ip4_address_t daddr;
        } ip4;

        struct {
            ip6_address_t saddr;
            ip6_address_t daddr;
        } ip6;
    };
    u16 sport;
    u16 dport;

    /* sw_if_index */
    u32 in_sw_if_index;
    u32 out_sw_if_index;

    /* tcp seg ack */    
    u32 tcp_ack_number;
    u32 tcp_seq_number;

} spi_flow_t;

typedef struct
{
    /* session index */
    u32 index;
    u32 hash;

    u8 thread_index;
    u8 session_is_free;
    u8 create_by_output;
    u8 exchanged_tuple;
    u8 associated_session_valid;

    /* flow */
    u8 is_ip6;
    u8 proto;
    spi_flow_t flow[SPI_FLOW_N_DIR];

    /* session state */
    spi_session_type_e session_type;
    union {
#define _(btype, ltype) spi_##ltype##_state_e state_##ltype;
        foreach_spi_support_session_type
#undef _
        u32 state;
    };
    u8 need_change_timeout;

    u32 transmit_timeout; //dynamic

    /* timer handler */
    u32 session_timer_handle;

    /* timestamp */
    f64 create_timestamp;
    f64 last_pkt_timestamp;
    f64 tcp_last_syn_timestamp;

    /* Counters */
    u64 total_bytes[SPI_FLOW_N_DIR];
    u64 drop_bytes[SPI_FLOW_N_DIR];
    u32 total_pkts[SPI_FLOW_N_DIR];
    u32 drop_pkts[SPI_FLOW_N_DIR];

    /* 
     * association session 
     * Session after NAT and Tunnel
     */
    struct {
        u8 session_thread; 
        u32 session_index;
    } associated_session;

}__attribute__ ((packed)) spi_session_t;

typedef struct
{
    u8 thread_index;

    /* Session pool */
    spi_session_t *sessions;
    u32 max_session;

    /* Session Timer */
    TWT (tw_timer_wheel) *timers_per_worker;
    u32 *expired_session_per_worker;

    /* Interrupt is pending from main thread */
    int interrupt_is_pending;

    /* incoming session change from other workers */
    clib_spinlock_t session_change_lock;

} spi_per_thread_data_t;

typedef struct
{
    /* spi plugin enabled */
    u8 enabled;

    /* proto enable */
#define _(btype, ltype) u8 ltype##_enable;
    foreach_spi_support_session_type
#undef _

    /* plugin config */
    spi_config_t spi_config;

    spi_timeouts_config_t spi_timeout_config;

    /* 3tuple exact timeout */
    clib_bihash_24_8_t exact_3tuple_timeout_table;

    /* Per thread data */
    u32 num_threads;
    u32 num_workers;
    u32 first_worker_index;
    spi_per_thread_data_t *per_thread_data;

    /* session lookup tables */
    clib_bihash_48_8_t session_table;

    /* Timer node index */
    u32 spi_session_timer_process_node_index;
    u32 spi_session_timer_worker_node_index;

    /* process node time wait interval: Dynamic updates */
    u32 spi_current_aging_process_timer_wait_frequency;
    u64 spi_current_aging_process_timer_wait_interval;

    /* Worker handoff frame-queue index */
    u32 fq_ip4_input_index;
    u32 fq_ip4_output_index;
    u32 fq_ip6_input_index;
    u32 fq_ip6_output_index;

    /* counters */
    vlib_simple_counter_main_t total_sessions_counter;
    vlib_simple_counter_main_t session_ip_type_counter;
    vlib_simple_counter_main_t session_type_counter[SPI_SESSION_TYPE_MAX];

    /* convenience */
    vnet_main_t *vnet_main;
    ip4_main_t *ip4_main;
    ip6_main_t *ip6_main;

    /* api */
    u16 msg_id_base;
       
} spi_main_t;

extern spi_main_t spi_main;

/* Node */
typedef struct
{
    u64 *hashes;
    vlib_buffer_t **bufs;
    u16 *nexts;
    spi_pkt_info_t *pkts;
    u32 *in_sw_if_indices;
    u32 *out_sw_if_indices;
} spi_runtime_t;

typedef struct
{
    u64 *hashes;
    vlib_buffer_t **bufs;
    u16 *thread_indices;
    spi_pkt_info_t *pkts;
} spi_handoff_runtime_t;

typedef struct
{
  u32 thread_index;
  u32 in_sw_if_index;
  u32 out_sw_if_index;
  u32 next_index;
  u32 session_index;
  u8 icmp_o_tcp_flags;
  u8 skip_spi;
} spi_trace_t;

typedef struct
{
    u32 next_worker_index;
    u32 trace_index;
    u8  is_output;
} spi_handoff_trace_t;


extern vlib_node_registration_t spi_ip4_input_node;
extern vlib_node_registration_t spi_ip4_output_node;
extern vlib_node_registration_t spi_ip6_input_node;
extern vlib_node_registration_t spi_ip6_output_node;
extern vlib_node_registration_t spi_ip4_input_worker_handoff_node;
extern vlib_node_registration_t spi_ip4_output_worker_handoff_node;
extern vlib_node_registration_t spi_ip6_input_worker_handoff_node;
extern vlib_node_registration_t spi_ip6_output_worker_handoff_node;

extern vlib_node_registration_t spi_timer_process_node;
extern vlib_node_registration_t spi_worker_timer_process_node;

/* Function */
static_always_inline u32
spi_calc_bihash_buckets (u32 n_elts)
{
    n_elts = n_elts / 2.5;
    u64 lower_pow2 = 1;
    while (lower_pow2 * 2 < n_elts)
    {
        lower_pow2 = 2 * lower_pow2;
    }
    u64 upper_pow2 = 2 * lower_pow2;
    if ((upper_pow2 - n_elts) < (n_elts - lower_pow2))
    {
        if (upper_pow2 <= UINT32_MAX)
        {
            return upper_pow2;
        }
    }
    return lower_pow2;
}

format_function_t format_spi_tcp_state;
format_function_t format_spi_general_state;
format_function_t format_spi_session_kvp;
format_function_t format_spi_exact_3tuple_timeout_kvp;
format_function_t format_spi_session;

clib_error_t *spi_api_hookup (vlib_main_t *vm);
int spi_feature_enable (spi_config_t *config);
int spi_feature_disable ();
int spi_session_proto_enable_disable(spi_session_type_e type, bool is_enable);

void spi_reset_timeouts ();
void spi_timeout_update (u8 use_default, spi_timeouts_config_t *spi_timeout_config);

int spi_exact_3tuple_timeout_add_del(ip46_address_t *ip, ip46_type_t type, u8 proto, u16 port, u32 timeout, bool is_add);

int spi_get_session_number(counter_t *totol_session, 
                           counter_t *ip4_session, counter_t ip4_proto_session[SPI_SESSION_TYPE_MAX], 
                           counter_t *ip6_session, counter_t ip6_proto_session[SPI_SESSION_TYPE_MAX]);

/* external call */
spi_session_t *vlib_buffer_spi_get_session(vlib_buffer_t *b);
spi_session_t *vlib_buffer_spi_get_associated_session(vlib_buffer_t *b);

#endif /* included_spi_h */
