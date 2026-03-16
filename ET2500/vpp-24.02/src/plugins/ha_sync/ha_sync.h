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

#define HA_SYNC_UDP_PORT 10311
#define HA_SYNC_MAX_TX_PAYLOAD 1400
#define HA_SYNC_MTU 1500
#define HA_SYNC_HEARTBEAT_INTERVAL_SEC 5
#define HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS 3
#define HA_SYNC_DEFAULT_DOMAIN_ID 0
#define HA_SYNC_DEFAULT_POOL_SIZE 2048
#define HA_SYNC_MAGIC 0xAF25EE00
#define HA_SYNC_DEFAULT_INTERVAL_SEC 0.1
#define HA_SYNC_THREAD_BUFFER_FLUSH_INTERVAL_SEC 0.5
#define HA_SYNC_SNAPSHOT_INTERVAL_SEC 0.1
#define HA_SYNC_RETRANSMIT_TIMES 3
#define HA_SYNC_RETRANSMIT_INTERVAL_SEC 2
#define HA_SYNC_HELLO_RETRY_INTERVAL_SEC 3



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
    HA_SYNC_SNAPSHOT_DISCONNECTED = 0,
    HA_SYNC_SNAPSHOT_CONNECTED_WAIT = 1,
    HA_SYNC_SNAPSHOT_SNAPSHOTTING = 2,
    HA_SYNC_SNAPSHOT_DONE = 3,
} ha_sync_snapshot_state_t;

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
    u8 reserve[7];          /* reserve bytes */
} ha_sync_packet_header_t;

typedef struct __attribute__ ((packed))
{ 
    u16 session_length;     /* session length */
    u8 app_type;            /* application type */
} ha_sync_session_header_t;

typedef struct 
{
    u8 app_type;
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
    u32 seq_number;
} ha_sync_fast_msg_t;   /* fast message, no payload, no retransmission, mainly for response,heartbeat,hello and hello response */


typedef struct
{
    CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
    u8 *data;
    u32 session_count;
    u32 *pending_fifo;      /* sequence number queue waiting to be sent */
    f64 last_flush_time;
    ha_sync_fast_msg_t *fast_msg_queue;
} ha_sync_per_thread_buffer_t;


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
    u32 global_seq_number;

    ha_sync_tx_packet_t *ha_sync_tx_pool;
    uword *seq_to_pool_index;
    clib_spinlock_t tx_lock; 
    
    ha_sync_session_registration_t *registrations;
    u32 num_registrations;

    ha_sync_per_thread_buffer_t *per_thread_buffers;

    TWT (tw_timer_wheel) timer_wheel;

    u8 snapshot_state;              /* snapshot state machine */
    f64 snapshot_due_time;          /* earliest time to start snapshot after hello response */
    f64 snapshot_next_time;         /* next scheduled snapshot tick in SNAPSHOTTING */
    u8 snapshot_round_inflight;     /* 1 when a per-thread round is running */
    u8 snapshot_round_pending_main; /* main-thread plugins returned pending in current round */
    u8 *snapshot_worker_state;      /* per-thread state: 0=not done, 1=done, 2=done but pending */

} ha_sync_main_t;

extern ha_sync_main_t ha_sync_main;

extern vlib_node_registration_t ha_sync_process_node;
extern vlib_node_registration_t ha_sync_input_worker_node;
extern vlib_node_registration_t ha_sync_output_worker_node;
extern vlib_node_registration_t ha_sync_snapshot_node;
extern vlib_node_registration_t ha_sync_snapshot_worker_node;
extern vlib_node_registration_t ha_sync_timer_node;

void ha_sync_per_thread_buffer_add (u32 thread_index, u8 app_type, u8 *session_data, u16 data_len);
void ha_sync_per_thread_buffer_flush (u32 thread_index);

u32 ha_sync_tx_pool_add (u32 seq, u8 msg_type, u8 session_count, u8 *payload, u16 payload_len);
int ha_sync_tx_pool_get_by_seq (u32 seq, ha_sync_tx_packet_t *out_data);
void ha_sync_tx_pool_del_by_seq (u32 seq);
void ha_sync_pool_clear_keep ();
void ha_sync_tx_pool_free ();
void ha_sync_release_resources ();
void ha_sync_reset_runtime_state ();

int ha_sync_register_session_application (ha_sync_session_registration_t *reg);
int ha_sync_unregister_session_application (u32 app_type);
void ha_sync_send_response (u32 seq_number, u32 thread_index);
void ha_sync_send_hello (u32 thread_index);
void ha_sync_send_hello_response (u32 thread_index);
void ha_sync_snapshot_trigger (void);


#endif 
