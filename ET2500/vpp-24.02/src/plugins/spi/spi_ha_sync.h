#ifndef included_spi_ha_h
#define included_spi_ha_h

#include <spi/spi.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <ha_sync/ha_sync.h>
#include <vppinfra/lffifo.h>

#define SPI_HASH_SYNC_DEBUG 1

#define SPI_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY   (128)
#define SPI_HA_SYNC_SNAPSHOT_BUCKET_WALK_SCALING        (9)

#define SPI_HA_SYNC_FIRST_TIMEOUT             (10) //10s
#define SPI_HA_SYNC_DEBOUNCE_TIMEOUT          (5)  //5s

#define SPI_HA_SYNC_CTX_FLAG_SNAPSHOT_SESSION (1 << 0)

#define spi_ha_sync_snapshot_act(flag) ((flag & SPI_HA_SYNC_CTX_FLAG_SNAPSHOT_SESSION))

#define SPI_HA_SYNC_HANDOFF_QUEUE_SIZE                  (16384)
#define SPI_HA_SYNC_HANDOFF_PER_NUM                     (1024)

typedef enum
{
    SPI_HA_SYNC_SNAPSHOT_PROCESS_RESTART = 1,

} spi_ha_sync_snapshot_event_e;

#define SPI_CHECK_HA_SYNC (!spi_ha_sync_ctx.ha_sync_plugin_found || \
                           !spi_ha_sync_ctx.ha_sync_register || \
                           !spi_ha_sync_ctx.ha_sync_ctx.ha_sync_connected)

typedef enum
{
    SPI_HA_OP_NONE = 0,

    SPI_HA_OP_ADD,
    SPI_HA_OP_ADD_FORCE,

    SPI_HA_OP_DEL,
    SPI_HA_OP_DEL_FORCE,

    SPI_HA_OP_UPDATE,

    SPI_HA_OP_REFRESH,

    SPI_HA_OP_VALID,
    SPI_HA_OP_MAX = 255,
} __attribute__ ((packed)) spi_ha_event_op_e;

typedef enum
{
    SPI_HA_TYPE_NONE = 0,

    SPI_HA_TYPE_SESSION,

    SPI_HA_TYPE_VALID,
    SPI_HA_TYPE_MAX = 255,
} __attribute__ ((packed)) spi_ha_event_type_e;

typedef struct
{
    u8 event_thread_id;
    u8 event_op;
    u8 event_type;
    u8 resv;
    u16 event_data_len;
} __attribute__ ((packed))spi_ha_sync_header_t;

typedef union
{
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
} spi_ha_sync_key_t;

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

    /* tcp seg ack */    
    u32 tcp_ack_number;
    u32 tcp_seq_number;

} spi_ha_sync_flow_t;

typedef struct
{
    u32 hash;

    u8 thread_index;
    u8 create_by_output;
    u8 exchanged_tuple;

    u8 is_ip6;
    u8 proto;

    spi_ha_sync_flow_t up_link_flow;
    spi_ha_sync_flow_t down_link_flow;

    /* session state */
    spi_session_type_e session_type;
    u32 state;

    u32 timeout;
    u32 transmit_timeout;

    /* 
     * association session 
     * Session after NAT and Tunnel
     */
    struct {
        u8 associated_session_valid;
        u32 hash;
        spi_ha_sync_key_t association_key;
    } associated_session;

} __attribute__ ((packed))spi_ha_sync_session_data_t;

typedef struct 
{
    spi_ha_sync_header_t header; 

    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    spi_ha_sync_session_data_t data;

} __attribute__ ((packed))spi_ha_sync_event_session_t;

typedef struct
{
    /* fifo */
    lf_fifo_t *session_fifo;
} spi_ha_sync_event_session_handoff_t;

typedef struct
{
    ha_sync_common_ctx_t ha_sync_ctx;

    u8 ha_sync_plugin_found;
    u8 ha_sync_register;

    u32 flag;

    u32 current_snapshot_version;

    u8 snapshot_start;
    u8 *snapshot_session_end;

    spi_ha_sync_event_session_handoff_t *handoff;
} spi_ha_sync_ctx_t;

extern spi_ha_sync_ctx_t spi_ha_sync_ctx;

int spi_ha_sync_register (void);
void spi_ha_sync_unregister (void);

extern vlib_node_registration_t spi_ha_sync_snapshot_process_node;
extern vlib_node_registration_t spi_ha_sync_snapshot_node;

extern void *spi_ha_sync_per_thread_buffer_add_ptr;

static_always_inline void spi_ha_sync_event_push (u32 thread_id, u8 *event_entry, u32 length)
{
    u32 thread_index = vlib_get_thread_index ();

    if (PREDICT_FALSE(spi_ha_sync_per_thread_buffer_add_ptr == NULL)) return;

    ((__typeof__ (ha_sync_per_thread_buffer_add) *)
     spi_ha_sync_per_thread_buffer_add_ptr)(
         thread_index, HA_SYNC_APP_SPI, event_entry, length);
}

static_always_inline void spi_ha_sync_event_session_notify(u32 thread_id, spi_ha_event_op_e op, spi_session_t *s, u32 timeout)
{
    if(SPI_CHECK_HA_SYNC) return;

    spi_ha_sync_event_session_t event;

    event.header.event_thread_id = thread_id;
    event.header.event_op = op;
    event.header.event_type = SPI_HA_TYPE_SESSION;
    event.header.resv = 0;
    event.header.event_data_len = clib_host_to_net_u16(sizeof(event.data));

    event.data.hash = s->hash;
    event.data.thread_index = s->thread_index;
    event.data.create_by_output = s->create_by_output;
    event.data.exchanged_tuple = s->exchanged_tuple;

    event.data.is_ip6 = s->is_ip6;
    event.data.proto = s->proto;
    event.data.session_type = s->session_type;
    event.data.state = s->state;

    //timeout debounce  
    event.data.timeout = timeout + SPI_HA_SYNC_DEBOUNCE_TIMEOUT;
    event.data.transmit_timeout = s->transmit_timeout;

    event.data.up_link_flow.sport = s->flow[SPI_FLOW_DIR_UPLINK].sport;
    event.data.up_link_flow.dport = s->flow[SPI_FLOW_DIR_UPLINK].dport;
    event.data.up_link_flow.tcp_ack_number = s->flow[SPI_FLOW_DIR_UPLINK].tcp_ack_number;
    event.data.up_link_flow.tcp_seq_number = s->flow[SPI_FLOW_DIR_UPLINK].tcp_seq_number;

    event.data.down_link_flow.sport = s->flow[SPI_FLOW_DIR_DOWNLINK].sport;
    event.data.down_link_flow.dport = s->flow[SPI_FLOW_DIR_DOWNLINK].dport;
    event.data.down_link_flow.tcp_ack_number = s->flow[SPI_FLOW_DIR_DOWNLINK].tcp_ack_number;
    event.data.down_link_flow.tcp_seq_number = s->flow[SPI_FLOW_DIR_DOWNLINK].tcp_seq_number;

    if (s->is_ip6)
    {
        ip6_address_copy(&event.data.up_link_flow.ip6.saddr, &s->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr);
        ip6_address_copy(&event.data.up_link_flow.ip6.daddr, &s->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr);
        ip6_address_copy(&event.data.down_link_flow.ip6.saddr, &s->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr);
        ip6_address_copy(&event.data.down_link_flow.ip6.daddr, &s->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr);
    }
    else
    {
        event.data.up_link_flow.ip4.saddr.as_u32 = s->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32;
        event.data.up_link_flow.ip4.daddr.as_u32 = s->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32;
        event.data.down_link_flow.ip4.saddr.as_u32 = s->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32;
        event.data.down_link_flow.ip4.daddr.as_u32 = s->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr.as_u32;
    }

    //association session
    if (s->associated_session_valid)
    {
        spi_main_t *spim = &spi_main;

        event.data.associated_session.associated_session_valid = s->associated_session_valid;
        spi_session_t *associated_session = NULL;
        spi_per_thread_data_t *tspi = NULL;

        event.data.associated_session.associated_session_valid = s->associated_session_valid;

        tspi = &spim->per_thread_data[s->associated_session.session_thread];
        associated_session =  pool_elt_at_index (tspi->sessions, s->associated_session.session_index);

        event.data.associated_session.hash = associated_session->hash;

        event.data.associated_session.association_key.is_ip6 = associated_session->is_ip6;
        event.data.associated_session.association_key.proto = associated_session->proto;

        if (associated_session->exchanged_tuple)
        {
            event.data.associated_session.association_key.port[0] = associated_session->flow[SPI_FLOW_DIR_DOWNLINK].sport;
            event.data.associated_session.association_key.port[1] = associated_session->flow[SPI_FLOW_DIR_DOWNLINK].dport;

            if (associated_session->is_ip6)
            {
                ip6_address_copy(&event.data.associated_session.association_key.ip6.addr[0], 
                                 &associated_session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr);
                ip6_address_copy(&event.data.associated_session.association_key.ip6.addr[1], 
                                 &associated_session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr);
            }
            else
            {
                event.data.associated_session.association_key.ip4.addr[0].as_u32 = 
                                 associated_session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32;
                event.data.associated_session.association_key.ip4.addr[1].as_u32 = 
                                 associated_session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr.as_u32;
            }
        }
        else
        {
            event.data.associated_session.association_key.port[0] = associated_session->flow[SPI_FLOW_DIR_UPLINK].sport;
            event.data.associated_session.association_key.port[1] = associated_session->flow[SPI_FLOW_DIR_UPLINK].dport;

            if (associated_session->is_ip6)
            {
                ip6_address_copy(&event.data.associated_session.association_key.ip6.addr[0], 
                                 &associated_session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr);
                ip6_address_copy(&event.data.associated_session.association_key.ip6.addr[1], 
                                 &associated_session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr);
            }
            else
            {
                event.data.associated_session.association_key.ip4.addr[0].as_u32 = 
                                 associated_session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32;
                event.data.associated_session.association_key.ip4.addr[1].as_u32 = 
                                 associated_session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32;
            }
        }
    }

    clib_warning("timeout %u", event.data.timeout);
    spi_ha_sync_event_push(thread_id, (u8 *)&event, sizeof(spi_ha_sync_event_session_t));
}

#endif /* included_spi_ha_h */
