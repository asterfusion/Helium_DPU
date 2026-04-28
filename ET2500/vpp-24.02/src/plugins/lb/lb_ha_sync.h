#ifndef included_lb_ha_h
#define included_lb_ha_h

#include <lb/lb.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <ha_sync/ha_sync.h>


#define LB_HASH_SYNC_DEBUG  1


#define LB_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY   (128)

#define LB_HA_SYNC_SNAPSHOT_BUCKET_WALK_SCALING        (9)

#define LB_HA_SYNC_TIMEOUT_UPDATE_INTERVAL             (2) //2s

#define LB_HA_SYNC_CTX_FLAG_SNAPSHOT_STICKY_ACT (1 << 0)
#define LB_HA_SYNC_CTX_FLAG_SNAPSHOT_VIP_SNAT_ACT (1 << 1)

#define lb_ha_sync_snapshot_act(flag) ((flag & LB_HA_SYNC_CTX_FLAG_SNAPSHOT_STICKY_ACT) ||  \
                                       (flag & LB_HA_SYNC_CTX_FLAG_SNAPSHOT_VIP_SNAT_ACT))

typedef struct
{
    ha_sync_common_ctx_t ha_sync_ctx;

    u8 ha_sync_plugin_found;
    u8 ha_sync_register;

    /*
     * The active time of the lb table entry is affected by the corresponding single packet.
     * Sending event information for each packet to update timeouts will incur significant overhead.
     * Setting an update interval will effectively reduce this cost.
     *
     * The basic idea is as follows: 
     *   When there is a packet update timeout, it will check whether it exceeds the configured interval, 
     *   and send an event if it exceeds.
     *
     *   When synchronizing table entries, the timeout in the event will be added to it. 
     *   The actual timeout received by the receiver is (real_timeout+interval). 
     *   The reason is that we need to ensure that the timeout of the synchronization side device 
     *   for this table entry is greater than that of the device initiating the table entry event
     */
    u32 ha_sync_timeout_update_interval;

    u32 flag;

    u32 current_snapshot_version;
    uword snapshot_sticky_index;
    uword snapshot_vip_snat_index;

} lb_ha_sync_ctx_t;

typedef enum
{
    LB_HA_SYNC_SNAPSHOT_PROCESS_RESTART = 1,

} lb_ha_sync_snapshot_event_e;

typedef enum
{
    LB_HA_OP_NONE = 0,

    LB_HA_OP_ADD,
    LB_HA_OP_ADD_FORCE,

    LB_HA_OP_DEL,
    LB_HA_OP_DEL_FORCE,

    LB_HA_OP_UPDATE,

    LB_HA_OP_REFRESH,

    LB_HA_OP_VALID,
    LB_HA_OP_MAX = 255,
} __attribute__ ((packed)) lb_ha_event_op_e;

typedef enum
{
    LB_HA_TYPE_NONE = 0,

    LB_HA_TYPE_STICK_TABLE,
    LB_HA_TYPE_VIP_SNAT_SESSION,

    LB_HA_TYPE_VALID,
    LB_HA_TYPE_MAX = 255,
} __attribute__ ((packed)) lb_ha_event_type_e;

typedef struct
{
    u8 event_thread_id;
    u8 event_op;
    u8 event_type;
    u8 resv;
    u16 event_data_len;
} __attribute__ ((packed))lb_ha_sync_header_t;

typedef struct 
{
    //vip key
    u8 type; //lb_vip_type_t
    u8 protocol;
    u16 l4_port;
    ip46_address_t prefix;
    u8 plen;
    u32 table_id;

    u32 hash;

    ip46_address_t address; //Based on this, search for asindex
    u32 timeout;

} __attribute__ ((packed))lb_ha_sync_stick_table_data_t;

typedef struct 
{
    //vip key
    u8 type; //lb_vip_type_t
    u8 protocol;
    u16 l4_port;
    ip46_address_t prefix;
    u8 plen;

    //mapping
    u8 ip_is_ipv6;
    u8 outside_ip_is_ipv6;

    ip46_address_t ip;
    ip46_address_t outside_ip;

    u16 port;
    u16 outside_port;

    /*
     * fib how to sync ?
     * To eliminate the influence of configuration sequence:
     * There are two options:
     *   table_id  -->  fib_index
     * 1. When creating a table, we must fill in the description
     *    Here is a description containing fib. 
     *    The receiving end traverses the fib table to match the description
     * 2. When creating, specify the table_id to make it a specific index. 
     *    Here, the table_id is included
     *
     * It seems that using table_id is better, * but this relies on the 
     * external control program to ensure that tables have the same table_id when they are created
     */
    u32 table_id;
    u32 outside_table_id;

    u32 timeout;

} __attribute__ ((packed))lb_ha_sync_vip_snat_session_data_t;

typedef struct 
{
    lb_ha_sync_header_t header; 
    lb_ha_sync_stick_table_data_t data;

} __attribute__ ((packed))lb_ha_sync_event_sticky_session_t;

typedef struct 
{
    lb_ha_sync_header_t header; 
    lb_ha_sync_vip_snat_session_data_t data;

} __attribute__ ((packed))lb_ha_sync_event_vip_snat_session_t;

/* global val */
extern lb_ha_sync_ctx_t lb_ha_sync_ctx;
extern vlib_node_registration_t lb_ha_sync_snapshot_process_node;

extern void *ha_sync_per_thread_buffer_add_ptr;

/* func */
int lb_ha_sync_register (void);
void lb_ha_sync_unregister (void);
int lb_ha_sync_set_timeout_update_interval(u32 ha_sync_timeout_update_interval);

#define LB_CHECK_HA_SYNC (!lb_ha_sync_ctx.ha_sync_plugin_found || \
                          !lb_ha_sync_ctx.ha_sync_register || \
                          !lb_ha_sync_ctx.ha_sync_ctx.ha_sync_connected)


static_always_inline void lb_ha_sync_event_push (u32 thread_id, u8 *event_entry, u32 length)
{
    if (PREDICT_FALSE(ha_sync_per_thread_buffer_add_ptr == NULL)) return;

    ((__typeof__ (ha_sync_per_thread_buffer_add) *)
     ha_sync_per_thread_buffer_add_ptr)(
         thread_id, HA_SYNC_APP_LB, event_entry, length);
}

static_always_inline void lb_ha_sync_event_sticky_session_notify(u32 thread_id, lb_ha_event_op_e op, 
                                                                 lb_vip_t *vip, u32 hash, 
                                                                 ip46_address_t *address, u32 timeout)
{
    if(LB_CHECK_HA_SYNC) return;

    lb_ha_sync_event_sticky_session_t event;

    timeout += lb_ha_sync_ctx.ha_sync_timeout_update_interval;

    event.header.event_thread_id = thread_id;
    event.header.event_op = op;
    event.header.event_type = LB_HA_TYPE_STICK_TABLE;
    event.header.resv = 0;
    event.header.event_data_len = clib_host_to_net_u16(sizeof(event.data));


    event.data.type = vip->type;
    event.data.protocol = vip->protocol;
    event.data.l4_port = clib_host_to_net_u16(vip->port);
    clib_memcpy (&(event.data.prefix), &(vip->prefix), sizeof(ip46_address_t));
    event.data.plen = vip->plen;

    event.data.table_id = clib_host_to_net_u32(vip->vrf_id);

    event.data.hash = clib_host_to_net_u32(hash);
    clib_memcpy (&(event.data.address), address, sizeof(ip46_address_t));
    event.data.timeout = clib_host_to_net_u32(timeout);

    lb_ha_sync_event_push(thread_id, (u8 *)&event, sizeof(lb_ha_sync_event_sticky_session_t));
}

static_always_inline void lb_ha_sync_event_vip_snat_session_notify(u32 thread_id, lb_ha_event_op_e op, 
                                                                  lb_vip_t *vip, lb_vip_snat_mapping_t *flow, u32 timeout)
{
    if(LB_CHECK_HA_SYNC) return;

    lb_ha_sync_event_vip_snat_session_t event;

    timeout += lb_ha_sync_ctx.ha_sync_timeout_update_interval;

    event.header.event_thread_id = thread_id;
    event.header.event_op = op;
    event.header.event_type = LB_HA_TYPE_VIP_SNAT_SESSION;
    event.header.resv = 0;
    event.header.event_data_len = clib_host_to_net_u16(sizeof(event.data));

    event.data.type = vip->type;
    event.data.protocol = vip->protocol;
    event.data.l4_port = clib_host_to_net_u16(vip->port);
    clib_memcpy (&(event.data.prefix), &(vip->prefix), sizeof(ip46_address_t));
    event.data.plen = vip->plen;

    event.data.ip_is_ipv6 = flow->ip_is_ipv6;
    event.data.outside_ip_is_ipv6 = flow->outside_ip_is_ipv6;


    clib_memcpy (&(event.data.ip), &flow->ip, sizeof(ip46_address_t));
    clib_memcpy (&(event.data.outside_ip), &flow->outside_ip, sizeof(ip46_address_t));

    event.data.port = flow->port;
    event.data.outside_port = flow->outside_port;

    event.data.timeout = clib_host_to_net_u32(timeout);

    if (flow->ip_is_ipv6)
    {
        ip6_fib_t *v6_fib = ip6_fib_get(flow->fib_index);
        event.data.table_id = clib_host_to_net_u32(v6_fib->table_id);
    }
    else
    {
        ip4_fib_t *v4_fib = ip4_fib_get(flow->fib_index);
        event.data.table_id = clib_host_to_net_u32(v4_fib->hash.table_id);
    }

    if (flow->outside_ip_is_ipv6)
    {
        ip6_fib_t *v6_fib = ip6_fib_get(flow->outside_fib_index);
        event.data.outside_table_id = clib_host_to_net_u32(v6_fib->table_id);
    }
    else
    {
        ip4_fib_t *v4_fib = ip4_fib_get(flow->outside_fib_index);
        event.data.outside_table_id = clib_host_to_net_u32(v4_fib->hash.table_id);
    }

    lb_ha_sync_event_push(thread_id, (u8 *)&event, sizeof(lb_ha_sync_event_vip_snat_session_t));
}

#endif /* included_lb_ha_h */
