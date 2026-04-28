/*
 * ha_sync.h - ha_sync plugin header
 */
#ifndef __included_ha_sync_h__
#define __included_ha_sync_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vppinfra/pool.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/lock.h>
#include <vppinfra/atomics.h>
#include <vppinfra/fifo.h>
#include <vnet/ip/format.h>
#include <vppinfra/tw_timer_16t_2w_512sl.h>
#include <vppinfra/lffifo.h>

#define HA_SYNC_UDP_PORT 10311
#define HA_SYNC_MAX_TX_PAYLOAD 1400
#define HA_SYNC_MTU 1500
#define HA_SYNC_HEARTBEAT_INTERVAL_SEC 5
#define HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS 3
#define HA_SYNC_DEFAULT_DOMAIN_ID 0
#define HA_SYNC_DEFAULT_POOL_SIZE 8192
#define HA_SYNC_MAGIC 0xAF25EE00
#define HA_SYNC_DEFAULT_INTERVAL_SEC 0.01
#define HA_SYNC_ACK_AGGREGATION_WINDOW_SEC 0.005
#define HA_SYNC_DEFAULT_REQUEST_PACING_INTERVAL_SEC 0.003
#define HA_SYNC_DEFAULT_REQUEST_PACING_INTERVAL_MS 3
#define HA_SYNC_DEFAULT_REQUEST_PACING_PKTS 128
#define HA_SYNC_THREAD_BUFFER_FLUSH_INTERVAL_SEC 0.5
#define HA_SYNC_RETRANSMIT_TIMES 3
#define HA_SYNC_RETRANSMIT_INTERVAL_SEC 2
#define HA_SYNC_HELLO_RETRY_INTERVAL_SEC 3
#define HA_SYNC_TIMER_WHEEL_INTERVAL_SEC 0.01
#define HA_SYNC_ACK_FIFO_SIZE 65536

typedef enum
{
    HA_SYNC_MSG_REQUEST = 0,
    HA_SYNC_MSG_RESPONSE = 1,
    HA_SYNC_MSG_HELLO = 2,
    HA_SYNC_MSG_HELLO_RESPONSE = 3,
    HA_SYNC_MSG_HEARTBEAT = 4,
} ha_sync_msg_type_t;

typedef enum
{
    HA_SYNC_SNAPSHOT_MODE_SINGLE = 0,
    HA_SYNC_SNAPSHOT_MODE_PER_THREAD = 1,
} ha_sync_snapshot_mode_t;

typedef enum
{
    HA_SYNC_APP_LB = 23,
    HA_SYNC_APP_SPI = 25,
    HA_SYNC_APP_NAT = 33,
    HA_SYNC_APP_MAP_CE = 35,
    HA_SYNC_APP_ACL_REFLECT = 37,
} ha_sync_app_type_t;


typedef int (*ha_sync_snapshot_send_cb_t) (u32 app_type, void *ctx, u32 thread_index);
typedef void (*ha_sync_session_apply_cb_t) (u32 app_type, void *ctx, u8 *session, u16 session_len);

typedef struct __attribute__ ((packed))
{
    u32 magic;              /* magic number 0xAF25EE00 */
    ip4_address_t src_ip;   /* source ip address */
    u8 domain;              /* domain id */
    u8 msg_type;            /* message type */
    u16 length;             /* packet length */
    u32 seq_number;         /* sequence number */
    u8 count;               /* message count */
    u8 thread_index;        /* owner thread on sender */
    u8 reserve[6];          /* reserve bytes */
} ha_sync_packet_header_t;

typedef struct __attribute__ ((packed))
{
    u16 session_length;     /* session length */
    u8 app_type;            /* application type */
} ha_sync_session_header_t;

typedef struct
{
    u8 ha_sync_enable;
    u8 ha_sync_config_ready;
    u8 ha_sync_connected;
    u16 ha_sync_snapshot_sequence;
} ha_sync_common_ctx_t;
/* when register conext to ha_sync, the context must start with ha_sync_common_ctx_t */

typedef struct
{
    u8 app_type;
    /* context must start with ha_sync_common_ctx_t */
    void *context;
    ha_sync_snapshot_send_cb_t snapshot_send_cb;
    ha_sync_session_apply_cb_t session_apply_cb;
    u8 snapshot_mode;
} ha_sync_session_registration_t;


typedef struct
{
    u8 msg_type;            /* message type */
    u8 session_count;       /* session count */
    u16 length;             /* payload length */
    u32 seq_number;         /* sequence number */
    u8 *payload;
    u32 retry_count;
    u32 timer_handle;       /* timer handle, used to stop timer */
} ha_sync_tx_packet_t;

typedef struct
{
    u8 msg_type;
    u8 owner_thread;
    u8 count;
    u16 length;
    u32 seq_number;
    u8 *payload;
} ha_sync_fast_msg_t;   /* control message, optional payload */

typedef struct
{
    u32 *seqs;               /* host-order ACK sequence numbers */
    u8 in_active_list;
    f64 first_enqueue_time;
} ha_sync_ack_batch_t;

typedef enum
{
    HA_SYNC_STAT_TX = 0,
    HA_SYNC_STAT_TX_REQUEST_NEW,
    HA_SYNC_STAT_TX_REQUEST_RETX,
    HA_SYNC_STAT_TX_RESPONSE,
    HA_SYNC_STAT_TX_RESPONSE_BATCH_PKTS,
    HA_SYNC_STAT_TX_RESPONSE_BATCH_ACKS,
    HA_SYNC_STAT_TX_HELLO,
    HA_SYNC_STAT_TX_HELLO_RESPONSE,
    HA_SYNC_STAT_TX_HEARTBEAT,
    HA_SYNC_STAT_RX,
    HA_SYNC_STAT_RX_MATCH,
    HA_SYNC_STAT_RX_REQUEST,
    HA_SYNC_STAT_RX_RESPONSE,
    HA_SYNC_STAT_RX_RESPONSE_BATCH_PKTS,
    HA_SYNC_STAT_RX_RESPONSE_BATCH_ACKS,
    HA_SYNC_STAT_RX_HELLO,
    HA_SYNC_STAT_RX_HELLO_RESPONSE,
    HA_SYNC_STAT_RX_HEARTBEAT,
    HA_SYNC_STAT_TX_NO_BUFFER,
    HA_SYNC_STAT_TX_POOL_MISS,
    HA_SYNC_STAT_TX_NO_PEER,
    HA_SYNC_STAT_RETRY_EXCEEDED,
    HA_SYNC_STAT_N,
} ha_sync_stat_t;

typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
    u8 *data;
    u8 *spare_data;
    u32 session_count;
    u32 *pending_fifo;      /* sequence number queue waiting to be sent */
    u32 *retry_fifo;        /* retransmit queue isolated from new traffic */
    lf_fifo_t *ack_fifo;  /* MPSC ack queue using shared HQOS fifo */
    u32 *ack_drain_vec;     /* reused temp vector for ack drain */
    u32 ack_wakeup_pending;
    f64 last_flush_time;
    f64 next_request_send_time;
    ha_sync_fast_msg_t *fast_msg_queue;
    ha_sync_ack_batch_t *response_batches;
    u32 *response_batch_active_threads;

    ha_sync_tx_packet_t *tx_pool;   
    uword *seq_to_pool_index;
    TWT (tw_timer_wheel) timer_wheel;
    u32 *timer_expired_vec;

    clib_spinlock_t lock;
} ha_sync_per_thread_data_t;


typedef struct
{
    vlib_main_t *vlib_main;
    vnet_main_t *vnet_main;

    u8 enabled;
    u32 fib_index;
    u32 sw_if_index;
    u8 sw_if_index_is_set;
    ip4_address_t src_address;
    u16 src_port;
    u16 dst_port;
    u32 domain_id;
    u16 packet_size;
    ip4_address_t peer_address;
    u8 src_is_set;
    u8 peer_is_set;
    u8 config_ready;
    u8 connection_established;

    f64 heartbeat_interval_sec;
    u32 heartbeat_max_fail_counts;
    f64 last_heartbeat_send_time;
    f64 last_heartbeat_recv_time;
    u32 hello_retry_count;
    f64 next_hello_time;
    u32 retransmit_times;
    f64 retransmit_interval;
    f64 request_pacing_interval_sec;
    u32 request_pacing_pkts_per_interval;
    u32 global_seq_number;

    ha_sync_session_registration_t *registrations;
    u32 num_registrations;

    ha_sync_per_thread_data_t *per_thread_data;

    u16 snapshot_sequence;          /* increment on each snapshot trigger */
    u8 snapshot_trigger_pending;    /* one-shot snapshot trigger flag */
    u8 snapshot_triggered_for_connection; /* edge guard: once per connection */
    u16 msg_id_base;
    u64 stats[HA_SYNC_STAT_N];

} ha_sync_main_t;

extern ha_sync_main_t ha_sync_main;

static_always_inline u32
ha_sync_next_seq_number (void)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    u32 old_value;
    u32 new_value;

    do
    {
        old_value = clib_atomic_load_relax_n (&hsm->global_seq_number);
        new_value = (old_value == ~0u) ? 0 : (old_value + 1);
    }
    while (!clib_atomic_bool_cmp_and_swap (&hsm->global_seq_number, old_value,
                                           new_value));

    return new_value;
}

static_always_inline void
ha_sync_stat_inc (ha_sync_stat_t stat, u64 value)
{
    if (PREDICT_FALSE (stat >= HA_SYNC_STAT_N || value == 0))
        return;
    clib_atomic_fetch_add_relax (&ha_sync_main.stats[stat], value);
}

extern vlib_node_registration_t ha_sync_process_node;
extern vlib_node_registration_t ha_sync_input_worker_node;
extern vlib_node_registration_t ha_sync_output_worker_node;
extern vlib_node_registration_t ha_sync_snapshot_node;
extern vlib_node_registration_t ha_sync_timer_node;

void ha_sync_per_thread_buffer_flush (u32 thread_index);

void ha_sync_tx_pool_add (u32 thread_index, u32 seq, u8 msg_type,
                          u8 session_count, u8 *payload, u16 payload_len);
int ha_sync_tx_pool_prepare_send (u32 thread_index, u32 seq,
                                  ha_sync_tx_packet_t *out_data);
void ha_sync_tx_pool_del_by_seq (u32 thread_index, u32 seq);
void ha_sync_pool_clear_keep (void);
void ha_sync_tx_pool_free (void);
void ha_sync_release_resources (void);
void ha_sync_reset_runtime_state (void);
int ha_sync_apply_enable_disable (u8 enable);
int ha_sync_apply_add_del_src_address (u8 is_add,
                                       const ip4_address_t *addr);
int ha_sync_apply_add_del_peer_address (u8 is_add,
                                        const ip4_address_t *addr);
int ha_sync_apply_add_del_interface (u8 is_add, u32 sw_if_index);
int ha_sync_apply_set_config (u32 domain_id, u16 packet_size,
                              u32 retransmit_times,
                              u32 retransmit_interval_ms,
                              u32 heartbeat_interval_ms,
                              u32 heartbeat_max_fail_counts);
int ha_sync_apply_set_request_pacing (u32 interval_ms,
                                      u32 pkts_per_interval);
int ha_sync_apply_clear_request_pacing (void);
int ha_sync_apply_reset_config (void);

void ha_sync_update_all_contexts (void);
void ha_sync_send_hello (u32 thread_index);
void ha_sync_send_hello_response (u32 thread_index);
void ha_sync_enqueue_acks (u8 owner_thread, const u32 *seq_numbers,
                           u32 n_seq_numbers);
void ha_sync_enqueue_ack (u8 owner_thread, u32 seq_number);
void ha_sync_wake_output_thread (u32 thread_index);
void ha_sync_snapshot_trigger (void);

static_always_inline void
ha_sync_send_response_message (u32 seq_number, u8 owner_thread,
                               u32 thread_index, u8 count, u16 length,
                               u8 *payload)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd;
    ha_sync_fast_msg_t msg = { 0 };

    if (PREDICT_FALSE (thread_index != vlib_get_thread_index ()))
    {
        clib_warning ("ha_sync_send_response cross-thread enqueue is not allowed");
        return;
    }
    if (PREDICT_FALSE (thread_index >= vec_len (hsm->per_thread_data)))
        return;

    ptd = &hsm->per_thread_data[thread_index];
    msg.seq_number = seq_number;
    msg.msg_type = HA_SYNC_MSG_RESPONSE;
    msg.owner_thread = owner_thread;
    msg.count = count;
    msg.length = length;
    msg.payload = payload;
    clib_fifo_add1 (ptd->fast_msg_queue, msg);
    ha_sync_wake_output_thread (thread_index);
}

static_always_inline void
ha_sync_send_response (u32 seq_number, u8 owner_thread, u32 thread_index)
{
    ha_sync_send_response_message (seq_number, owner_thread, thread_index, 0,
                                   0, 0);
}

static_always_inline void
ha_sync_send_response_aggregated (u32 seq_number, u8 owner_thread,
                                  u32 thread_index, u8 count, u16 length,
                                  u8 *payload)
{
    ha_sync_send_response_message (seq_number, owner_thread, thread_index,
                                   count, length, payload);
}

__clib_export void ha_sync_per_thread_buffer_add (u32 thread_index, u8 app_type,
                                                  u8 *session_data,
                                                  u16 data_len);
__clib_export int ha_sync_register_session_application (ha_sync_session_registration_t *reg);
__clib_export int ha_sync_unregister_session_application (u32 app_type);



#endif 
