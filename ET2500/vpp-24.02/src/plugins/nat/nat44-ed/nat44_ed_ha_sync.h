#ifndef included_nat44_ed_ha_h
#define included_nat44_ed_ha_h

#include <nat/nat44-ed/nat44_ed.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <ha_sync/ha_sync.h>
#include <vppinfra/lffifo.h>

#define NAT44_ED_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY   (128)
#define NAT44_ED_HA_SYNC_SNAPSHOT_BUCKET_WALK_SCALING        (9)

#define NAT44_ED_HA_SYNC_TIMEOUT_UPDATE_INTERVAL             (2) //2s

#define NAT44_ED_HA_SYNC_CTX_FLAG_SNAPSHOT_FLOW (1 << 0)

#define nat44_ed_ha_sync_snapshot_act(flag) ((flag & NAT44_ED_HA_SYNC_CTX_FLAG_SNAPSHOT_FLOW))

#define NAT44_ED_HA_SYNC_HANDOFF_QUEUE_SIZE                  (16384)
#define NAT44_ED_HA_SYNC_HANDOFF_PER_NUM                     (1024)

typedef enum
{
    NAT44_ED_HA_SYNC_SNAPSHOT_PROCESS_RESTART = 1,

} nat44_ed_ha_sync_snapshot_event_e;

#define NAT44_ED_CHECK_HA_SYNC (!nat44_ed_ha_sync_ctx.ha_sync_plugin_found || \
                                !nat44_ed_ha_sync_ctx.ha_sync_register || \
                                !nat44_ed_ha_sync_ctx.ha_sync_ctx.ha_sync_connected)

typedef enum
{
    NAT44_ED_HA_OP_NONE = 0,

    NAT44_ED_HA_OP_ADD,
    NAT44_ED_HA_OP_ADD_FORCE,

    NAT44_ED_HA_OP_DEL,
    NAT44_ED_HA_OP_DEL_FORCE,

    NAT44_ED_HA_OP_UPDATE,

    NAT44_ED_HA_OP_REFRESH,

    NAT44_ED_HA_OP_VALID,
    NAT44_ED_HA_OP_MAX = 255,
} __attribute__ ((packed)) nat44_ed_ha_event_op_e;

typedef enum
{
    NAT44_ED_HA_TYPE_NONE = 0,

    NAT44_ED_HA_TYPE_FLOW,

    NAT44_ED_HA_TYPE_VALID,
    NAT44_ED_HA_TYPE_MAX = 255,
} __attribute__ ((packed)) nat44_ed_ha_event_type_e;

typedef struct
{
    u8 event_thread_id;
    u8 event_op;
    u8 event_type;
    u8 resv;
    u16 event_data_len;
} __attribute__ ((packed))nat44_ed_ha_sync_header_t;

typedef struct 
{
    /* Outside network tuple */
    struct
    {
        ip4_address_t addr;
        u32 table_id;  //vrf_id, need mapping to fib_Index
        u16 port;
    } out2in;

    /* Inside network tuple */
    struct
    {
        ip4_address_t addr;
        u32 table_id; //vrf_id, need mapping to fib_index
        u16 port;
    } in2out;

    ip_protocol_t proto;

    nat_6t_flow_t i2o;
    nat_6t_flow_t o2i;

    /* Flags */
    u32 flags;

    /* External host address and port */
    ip4_address_t ext_host_addr;
    u16 ext_host_port;

    /* External host address and port after translation */
    ip4_address_t ext_host_nat_addr;
    u16 ext_host_nat_port;

    /* TCP session state */
    u8 tcp_flags[NAT44_ED_N_DIR];
    nat44_ed_tcp_state_e tcp_state;

} __attribute__ ((packed))nat44_ed_ha_sync_flow_data_t;

typedef struct 
{
    nat44_ed_ha_sync_header_t header; 

    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    nat44_ed_ha_sync_flow_data_t data;

} __attribute__ ((packed))nat44_ed_ha_sync_event_flow_t;

typedef struct
{
    /* fifo */
    lf_fifo_t *flow_fifo;
} nat44_ed_ha_sync_event_flow_handoff_t;

typedef struct
{
    ha_sync_common_ctx_t ha_sync_ctx;

    u8 ha_sync_plugin_found;
    u8 ha_sync_register;

    u32 ha_sync_timeout_update_interval;

    u32 flag;

    u32 current_snapshot_version;

    u8 snapshot_start;
    u8 *snapshot_flow_end;

    nat44_ed_ha_sync_event_flow_handoff_t *handoff;
} nat44_ed_ha_sync_ctx_t;

extern nat44_ed_ha_sync_ctx_t nat44_ed_ha_sync_ctx;

int nat44_ed_ha_sync_register (void);
void nat44_ed_ha_sync_unregister (void);
int nat44_ed_ha_sync_set_timeout_update_interval(u32 ha_sync_timeout_update_interval);

extern vlib_node_registration_t nat44_ed_ha_sync_snapshot_process_node;
extern vlib_node_registration_t nat44_ed_ha_sync_snapshot_node;

extern void *nat44_ed_ha_sync_per_thread_buffer_add_ptr;

static_always_inline void nat44_ed_ha_sync_event_push (u32 thread_id, u8 *event_entry, u32 length)
{
    if (PREDICT_FALSE(nat44_ed_ha_sync_per_thread_buffer_add_ptr == NULL)) return;

    ((__typeof__ (ha_sync_per_thread_buffer_add) *)
     nat44_ed_ha_sync_per_thread_buffer_add_ptr)(
         thread_id, HA_SYNC_APP_NAT, event_entry, length);
}

static_always_inline void nat44_ed_ha_sync_event_flow_notify(u32 thread_id, nat44_ed_ha_event_op_e op, snat_session_t *s)
{
    if(NAT44_ED_CHECK_HA_SYNC) return;

    nat44_ed_ha_sync_event_flow_t event;

    event.header.event_thread_id = thread_id;
    event.header.event_op = op;
    event.header.event_type = NAT44_ED_HA_TYPE_FLOW;
    event.header.resv = 0;
    event.header.event_data_len = clib_host_to_net_u16(sizeof(event.data));

    //convert fib_index to table_id
    u32 i2o_table_id = fib_table_get_table_id(s->in2out.fib_index, FIB_PROTOCOL_IP4);
    u32 o2i_table_id = fib_table_get_table_id(s->out2in.fib_index, FIB_PROTOCOL_IP4);

    event.data.in2out.table_id = i2o_table_id;
    event.data.in2out.addr = s->in2out.addr;
    event.data.in2out.port = s->in2out.port;

    event.data.out2in.table_id = o2i_table_id;
    event.data.out2in.addr = s->out2in.addr;
    event.data.out2in.port = s->out2in.port;

    event.data.proto = s->proto;

    clib_memcpy(&event.data.i2o, &s->i2o, sizeof(nat_6t_flow_t));
    clib_memcpy(&event.data.o2i, &s->o2i, sizeof(nat_6t_flow_t));

    event.data.flags = s->flags;

    event.data.ext_host_addr = s->ext_host_addr;
    event.data.ext_host_port = s->ext_host_port;

    event.data.ext_host_nat_addr = s->ext_host_nat_addr;
    event.data.ext_host_nat_port = s->ext_host_nat_port;

    clib_memcpy(&event.data.tcp_flags, &s->tcp_flags, sizeof(u8) * NAT44_ED_N_DIR);
    event.data.tcp_state = s->tcp_state;

    nat44_ed_ha_sync_event_push(thread_id, (u8 *)&event, sizeof(nat44_ed_ha_sync_event_flow_t));
}

#endif /* included_nat44_ed_ha_h */
