#include <spi/spi.h>
#include <spi/spi_inline.h>
#include <spi/spi_ha_sync.h>
#include <vnet/plugin/plugin.h>

spi_ha_sync_ctx_t spi_ha_sync_ctx;

typedef struct
{
    u32 snapshot_version;

    uword snapshot_session_index;

} spi_ha_sync_snapshot_runtime_t;

typedef struct
{
    spi_ha_sync_event_session_t *session;
} spi_ha_sync_handoff_runtime_t;

static char *spi_event_op_string[] = {
    [SPI_HA_OP_NONE] = "none",
    [SPI_HA_OP_ADD] = "add",
    [SPI_HA_OP_ADD_FORCE] = "add_force",
    [SPI_HA_OP_DEL] = "del",
    [SPI_HA_OP_DEL_FORCE] = "del_force",
    [SPI_HA_OP_UPDATE] = "update",
    [SPI_HA_OP_REFRESH] = "refresh",
};

static char *spi_event_type_string[] = {
    [SPI_HA_TYPE_NONE] = "none",
    [SPI_HA_TYPE_SESSION] = "session",
};

static u8 *format_spi_event_op (u8 * s, va_list * args)
{
  u8 *op = va_arg (*args, u8 *);
  if (*op < SPI_HA_OP_VALID)
  {
      return format(s, spi_event_op_string[*op]);
  }
  return format(s, "WRONG_OP");
}

static u8 *format_spi_event_type (u8 * s, va_list * args)
{
  u8 *type = va_arg (*args, u8 *);
  if (*type < SPI_HA_OP_VALID)
  {
      return format(s, spi_event_type_string[*type]);
  }
  return format(s, "WRONG_TYPE");
}

u8 *format_spi_ha_sync_header_format (u8 * s, va_list * args)
{
  spi_ha_sync_header_t *header = va_arg (*args, spi_ha_sync_header_t *);
  s = format(s, "\tevent_thread_id %u, op %U, event_type %U, data length %u\n", 
             header->event_thread_id, 
             format_spi_event_op, &header->event_op,
             format_spi_event_type, &header->event_type,
             clib_net_to_host_u16(header->event_data_len));
  return s;
}

u8 *format_spi_ha_sync_session_format (u8 * s, va_list * args)
{
    spi_ha_sync_session_data_t *data = va_arg (*args, spi_ha_sync_session_data_t *);

    s = format (s, "SPI session create_side %s create-thread %u, , proto %U",
                    data->create_by_output ? "OUTPUT" : "INPUT",
                    data->thread_index, format_ip_protocol, data->proto);

    if (data->is_ip6)
    {
        s = format (s, "\n\tUplink %U:%u --> %U:%u ; ",
                      format_ip6_address, &data->up_link_flow.ip6.saddr,
                      clib_net_to_host_u16 (data->up_link_flow.sport),
                      format_ip6_address, &data->up_link_flow.ip6.daddr,
                      clib_net_to_host_u16 (data->up_link_flow.dport));

        s = format (s, "\n\tDownlink %U:%u --> %U:%u ; ",
                      format_ip6_address, &data->down_link_flow.ip6.saddr,
                      clib_net_to_host_u16 (data->down_link_flow.sport),
                      format_ip6_address, &data->down_link_flow.ip6.daddr,
                      clib_net_to_host_u16 (data->down_link_flow.dport));

    }
    else
    {
        s = format (s, "\n\tUplink %U:%u --> %U:%u ; ",
                  format_ip4_address, &data->up_link_flow.ip4.saddr,
                  clib_net_to_host_u16 (data->up_link_flow.sport),
                  format_ip4_address, &data->up_link_flow.ip4.daddr,
                  clib_net_to_host_u16 (data->up_link_flow.dport));

        s = format (s, "\n\tDownlink %U:%u --> %U:%u ; ",
                  format_ip4_address, &data->down_link_flow.ip4.saddr,
                  clib_net_to_host_u16 (data->down_link_flow.sport),
                  format_ip4_address, &data->down_link_flow.ip4.daddr,
                  clib_net_to_host_u16 (data->down_link_flow.dport));
    }

    switch (data->proto)
    {
    case IP_PROTOCOL_TCP:
        s = format (s, "\n\tState: %U", format_spi_tcp_state, data->state);
        break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
        s = format (s, "\n\tState: %U", format_spi_general_state, data->state);
        break;
    case IP_PROTOCOL_UDP:
        s = format (s, "\n\tState: %U", format_spi_general_state, data->state);
        break;
    default:
        s = format (s, "\n\tState: %U", format_spi_general_state, data->state);
        break;
    }

    s = format (s, "\n\tSession timeout %us transmit_timeout %us", data->timeout, data->transmit_timeout);

    if (data->associated_session.associated_session_valid)
    {
        s = format (s, "\n\tassociated_session hash %u", data->associated_session.hash);
        if (data->associated_session.association_key.is_ip6)
        {
            s = format (s, "\n\tKey proto %U ( %U:%u <--> %U:%u )",
                    format_ip_protocol, data->associated_session.association_key.proto,
                    format_ip6_address, &data->associated_session.association_key.ip6.addr[0],
                    clib_net_to_host_u16 (data->associated_session.association_key.port[0]),
                    format_ip6_address, &data->associated_session.association_key.ip6.addr[1],
                    clib_net_to_host_u16 (data->associated_session.association_key.port[1]));
        }
        else
        {
            s = format (s, "\n\tKey proto %U ( %U:%u <--> %U:%u )",
                    format_ip_protocol, data->associated_session.association_key.proto,
                    format_ip4_address, &data->associated_session.association_key.ip4.addr[0],
                    clib_net_to_host_u16 (data->associated_session.association_key.port[0]),
                    format_ip4_address, &data->associated_session.association_key.ip4.addr[1],
                    clib_net_to_host_u16 (data->associated_session.association_key.port[1]));
        }
    }

  return s;
}

static int
spi_ha_sync_snapshot_send_cb (u32 app_type, void *ctx, u32 thread_index)
{
    ASSERT(app_type == HA_SYNC_APP_SPI);

    spi_ha_sync_ctx_t *spi_ctx = (spi_ha_sync_ctx_t *)ctx;

    //Triggering an interrupt to notify the process to start a snapshot
    if (spi_ctx->current_snapshot_version != spi_ctx->ha_sync_ctx.ha_sync_snapshot_sequence)
    {
        vlib_process_signal_event_mt (vlib_get_main(), 
                                     spi_ha_sync_snapshot_process_node.index, 
                                     SPI_HA_SYNC_SNAPSHOT_PROCESS_RESTART, 0);

        spi_ctx->current_snapshot_version = spi_ctx->ha_sync_ctx.ha_sync_snapshot_sequence;
    }

    return 0;
}

static_always_inline 
void generate_session_table_snapshot(vlib_main_t * vm, 
                                  spi_ha_sync_ctx_t *ctx, 
                                  spi_ha_sync_snapshot_runtime_t *rt)
{
    u32 thread_index = vm->thread_index;
    spi_main_t *spim = &spi_main;
    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];

    spi_session_t *s = NULL;

    uword pool_active_num = pool_elts(tspi->sessions);
    uword pool_max_num = pool_max_len(tspi->sessions);

    if (PREDICT_FALSE (pool_active_num == 0))
    {
        ctx->snapshot_session_end[thread_index] = 1;
        return;
    }

    uword i;
    uword pool_walk_end = (pool_max_num >> SPI_HA_SYNC_SNAPSHOT_BUCKET_WALK_SCALING);
    pool_walk_end = rt->snapshot_session_index + pool_walk_end > 0 ? pool_walk_end : pool_max_num;
    pool_walk_end = pool_walk_end < pool_max_num ? pool_walk_end : pool_max_num;

    pool_foreach_stepping_index(i, rt->snapshot_session_index, pool_walk_end, tspi->sessions)
    {
        if (pool_is_free_index(tspi->sessions, i)) continue;

        s = pool_elt_at_index (tspi->sessions, i);
        spi_ha_sync_event_session_notify(vm->thread_index, SPI_HA_OP_ADD_FORCE, s, s->transmit_timeout);
    }
    rt->snapshot_session_index = i;

    if (rt->snapshot_session_index >= pool_max_num)
    {
        ctx->snapshot_session_end[thread_index] = 1;
        rt->snapshot_session_index = 0;
    }

    return;
}

static uword
spi_ha_sync_snapshot_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    uword event_type = 0, *event_data = NULL;

    u32 n_threads = vlib_get_n_threads ();

    f64 cpu_cps = vm->clib_time.clocks_per_second;

    u64 max_timer_wait_interval = cpu_cps / SPI_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY;

    vec_validate(spi_ha_sync_ctx.snapshot_session_end, n_threads);

    while (1)
    {
        /* Wait for Godot... */
        if (spi_ha_sync_snapshot_act(spi_ha_sync_ctx.flag))
        {
            vlib_process_wait_for_event_or_clock (vm, (max_timer_wait_interval / cpu_cps));
        }
        else
        {
            vlib_process_wait_for_event (vm);
        }

        if(SPI_CHECK_HA_SYNC) continue;

        event_type = vlib_process_get_events (vm, &event_data);

        if (event_type == SPI_HA_SYNC_SNAPSHOT_PROCESS_RESTART)
        {
            spi_ha_sync_ctx.flag |= SPI_HA_SYNC_CTX_FLAG_SNAPSHOT_SESSION;
            vec_zero(spi_ha_sync_ctx.snapshot_session_end);
        }

        u32 ti;
        u32 session_end_cnt = 0;
        for (ti = 0; ti < n_threads; ti++)
        {
           session_end_cnt += spi_ha_sync_ctx.snapshot_session_end[ti] ? 1 : 0;
        }

        if (session_end_cnt == n_threads)
        {
            spi_ha_sync_ctx.flag &= ~SPI_HA_SYNC_CTX_FLAG_SNAPSHOT_SESSION;
        }

        /*
         * snapshot worker interrupt 
         */
        for (ti = 0; ti < n_threads; ti++)
        {
            vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                    spi_ha_sync_snapshot_node.index);
        }

        vec_reset_length (event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE (spi_ha_sync_snapshot_process_node) = {
  .function = spi_ha_sync_snapshot_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "spi-ha-sync-snapshot-process",
  .n_next_nodes = 0,
  .next_nodes = {},
};

VLIB_NODE_FN (spi_ha_sync_snapshot_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 thread_index = vm->thread_index;

    spi_ha_sync_snapshot_runtime_t *rt = (spi_ha_sync_snapshot_runtime_t *) node->runtime_data;

    if (rt->snapshot_version == spi_ha_sync_ctx.current_snapshot_version)
        return 0;

    if (!spi_ha_sync_ctx.snapshot_session_end[thread_index])
    {
        generate_session_table_snapshot(vm, &spi_ha_sync_ctx, rt);
    }

    if (spi_ha_sync_ctx.snapshot_session_end[thread_index])
    {
        rt->snapshot_version = spi_ha_sync_ctx.current_snapshot_version;
    }
    return 0;
}

VLIB_REGISTER_NODE (spi_ha_sync_snapshot_node) = {
  .name = "spi-ha-sync-snapshot",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .runtime_data_bytes = sizeof (spi_ha_sync_snapshot_runtime_t),
};

static_always_inline void
spi_ha_sync_session_add(u32 thread_index, spi_ha_sync_session_data_t *data, int is_force)
{
    vlib_main_t *vm = vlib_get_main();
    spi_main_t *spim = &spi_main;
    f64 now = vlib_time_now (vm);

    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];

    clib_bihash_kv_48_8_t kv;
    spi_ha_sync_key_t key;

    spi_session_t *session = NULL;

    clib_memset(&key, 0, sizeof(spi_ha_sync_key_t));

    key.is_ip6 = data->is_ip6;
    key.proto = data->proto;
    if (data->exchanged_tuple)
    {
        key.port[0] = data->down_link_flow.sport;
        key.port[1] = data->down_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->down_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->down_link_flow.ip4.daddr.as_u32;
        }
    }
    else
    {
        key.port[0] = data->up_link_flow.sport;
        key.port[1] = data->up_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->up_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->up_link_flow.ip4.daddr.as_u32;
        }
    }

    if (!clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                                                     data->hash, 
                                                     (clib_bihash_kv_48_8_t *)key.key,
                                                     &kv))
    {
        tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(kv.value)];
        session =  pool_elt_at_index (tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(kv.value));
    }

    if (session && !is_force)
    {
        clib_warning ("SPI HA SYNC Thread %d: Session alreadly exists skip", tspi->thread_index);
        return;
    }

    SPI_THREAD_LOCK(tspi);
    if (!session)
    {
        if (pool_elts (tspi->sessions) >= tspi->max_session)
        {
            clib_warning ("SPI HA SYNC Thread %d: MAX_SESSIONS_EXCEEDED(%u-%u)!", 
                    tspi->thread_index, pool_elts (tspi->sessions), tspi->max_session);
            SPI_THREAD_UNLOCK(tspi);
            return;
        }

        pool_get_zero (tspi->sessions, session);

        session->index = session - tspi->sessions;
        session->thread_index = data->thread_index;
        session->hash = data->hash;
        session->create_by_output = data->create_by_output;
        session->exchanged_tuple = data->exchanged_tuple;

        session->create_timestamp = now;
        session->is_ip6 = data->is_ip6;
        session->proto = data->proto;
        session->session_type = data->session_type;

        session->session_timer_handle = (~0);
        session->flow[SPI_FLOW_DIR_UPLINK].geosite_match_acl = (~0);
        session->flow[SPI_FLOW_DIR_DOWNLINK].geosite_match_acl = (~0);

        session->flow[SPI_FLOW_DIR_UPLINK].sport = data->up_link_flow.sport;
        session->flow[SPI_FLOW_DIR_UPLINK].dport = data->up_link_flow.dport;
        session->flow[SPI_FLOW_DIR_DOWNLINK].sport = data->down_link_flow.sport;
        session->flow[SPI_FLOW_DIR_DOWNLINK].dport = data->down_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.saddr, &data->up_link_flow.ip6.saddr);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_UPLINK].ip6.daddr, &data->up_link_flow.ip6.daddr);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.saddr, &data->down_link_flow.ip6.saddr);
            ip6_address_copy(&session->flow[SPI_FLOW_DIR_DOWNLINK].ip6.daddr, &data->down_link_flow.ip6.daddr);
        }
        else
        {
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.saddr.as_u32 = data->up_link_flow.ip4.saddr.as_u32;
            session->flow[SPI_FLOW_DIR_UPLINK].ip4.daddr.as_u32 = data->up_link_flow.ip4.daddr.as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.saddr.as_u32 = data->down_link_flow.ip4.saddr.as_u32;
            session->flow[SPI_FLOW_DIR_DOWNLINK].ip4.daddr.as_u32 = data->down_link_flow.ip4.daddr.as_u32;
        }

        session->flow[SPI_FLOW_DIR_UPLINK].tcp_ack_number = data->up_link_flow.tcp_ack_number;
        session->flow[SPI_FLOW_DIR_UPLINK].tcp_seq_number = data->up_link_flow.tcp_seq_number;
        session->flow[SPI_FLOW_DIR_DOWNLINK].tcp_ack_number = data->down_link_flow.tcp_ack_number;
        session->flow[SPI_FLOW_DIR_DOWNLINK].tcp_seq_number = data->down_link_flow.tcp_seq_number;

        session->state = data->state;
        session->transmit_timeout = data->transmit_timeout;
        session->last_pkt_timestamp = now;

        clib_memcpy(kv.key, &key, 48);
        SPI_BIHASH_SESSION_VALUE_SET(kv.value, session->thread_index, session->index);

        if (clib_bihash_add_del_with_hash_48_8(&spim->session_table, &kv, data->hash, 1))
        {
            clib_warning("SPI ha sync add session hash add failed");
            pool_put_index (tspi->sessions, session->index);
            SPI_THREAD_UNLOCK(tspi);
            return;
        }

        vlib_set_simple_counter (&spim->total_sessions_counter, tspi->thread_index, 0, pool_elts (tspi->sessions));
        vlib_increment_simple_counter (&spim->session_ip_type_counter, tspi->thread_index, data->is_ip6, 1);
        vlib_increment_simple_counter (&spim->session_type_counter[data->session_type], tspi->thread_index, data->is_ip6, 1);
    }
    else
    {
        //force update
        session->flow[SPI_FLOW_DIR_UPLINK].tcp_ack_number = data->up_link_flow.tcp_ack_number;
        session->flow[SPI_FLOW_DIR_UPLINK].tcp_seq_number = data->up_link_flow.tcp_seq_number;
        session->flow[SPI_FLOW_DIR_DOWNLINK].tcp_ack_number = data->down_link_flow.tcp_ack_number;
        session->flow[SPI_FLOW_DIR_DOWNLINK].tcp_seq_number = data->down_link_flow.tcp_seq_number;

        session->state = data->state;
        session->transmit_timeout = data->transmit_timeout;
        session->last_pkt_timestamp = now;
    }

    //timeout submit
    spi_submit_or_update_session_timer(tspi, session, data->timeout, true);

    SPI_THREAD_UNLOCK(tspi);

    //associated session proc
    if (data->associated_session.associated_session_valid)
    {
        clib_bihash_kv_48_8_t associated_kv;

        if (!clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                    data->associated_session.hash, 
                    (clib_bihash_kv_48_8_t *)data->associated_session.association_key.key,
                    &associated_kv))
        {
            spi_per_thread_data_t *associated_tspi = NULL;
            spi_session_t *associated_session = NULL;
            associated_tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(associated_kv.value)];
            associated_session = pool_elt_at_index (associated_tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(associated_kv.value));

            associated_session->associated_session_valid = data->associated_session.associated_session_valid;
            associated_session->associated_session.session_thread = session->thread_index;
            associated_session->associated_session.session_index = session->index;

            session->associated_session_valid = data->associated_session.associated_session_valid;
            session->associated_session.session_thread = associated_session->thread_index;
            session->associated_session.session_index = associated_session->index;
        }
    }
    return;
}

static_always_inline void
spi_ha_sync_session_update(u32 thread_index, spi_ha_sync_session_data_t *data)
{
    vlib_main_t *vm = vlib_get_main();
    spi_main_t *spim = &spi_main;
    f64 now = vlib_time_now (vm);

    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];

    clib_bihash_kv_48_8_t kv;
    spi_ha_sync_key_t key;

    spi_session_t *session = NULL;

    clib_memset(&key, 0, sizeof(spi_ha_sync_key_t));

    key.is_ip6 = data->is_ip6;
    key.proto = data->proto;
    if (data->exchanged_tuple)
    {
        key.port[0] = data->down_link_flow.sport;
        key.port[1] = data->down_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->down_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->down_link_flow.ip4.daddr.as_u32;
        }
    }
    else
    {
        key.port[0] = data->up_link_flow.sport;
        key.port[1] = data->up_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->up_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->up_link_flow.ip4.daddr.as_u32;
        }
    }

    if (clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                                                    data->hash, 
                                                    (clib_bihash_kv_48_8_t *)key.key,
                                                    &kv))
    {
        clib_warning("SPI ha sync session not found!");
        return;
    }

    tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(kv.value)];
    session =  pool_elt_at_index (tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(kv.value));

    SPI_THREAD_LOCK(tspi);

    session->state = data->state;

    session->last_pkt_timestamp = now;

    session->transmit_timeout = data->transmit_timeout;

    //timeout submit
    spi_submit_or_update_session_timer(tspi, session, data->timeout, true);

    SPI_THREAD_UNLOCK(tspi);

    //associated session proc
    if (data->associated_session.associated_session_valid && !session->associated_session_valid)
    {
        clib_bihash_kv_48_8_t associated_kv;

        if (!clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                    data->associated_session.hash, 
                    (clib_bihash_kv_48_8_t *)data->associated_session.association_key.key,
                    &associated_kv))
        {
            spi_per_thread_data_t *associated_tspi = NULL;
            spi_session_t *associated_session = NULL;
            associated_tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(associated_kv.value)];
            associated_session = pool_elt_at_index (associated_tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(associated_kv.value));

            associated_session->associated_session_valid = data->associated_session.associated_session_valid;
            associated_session->associated_session.session_thread = session->thread_index;
            associated_session->associated_session.session_index = session->index;

            session->associated_session_valid = data->associated_session.associated_session_valid;
            session->associated_session.session_thread = associated_session->thread_index;
            session->associated_session.session_index = associated_session->index;
        }
    }
    return;
}
static_always_inline void
spi_ha_sync_session_del(u32 thread_index, spi_ha_sync_session_data_t *data, int is_force)
{
    spi_main_t *spim = &spi_main;

    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];

    clib_bihash_kv_48_8_t kv;
    spi_ha_sync_key_t key;

    spi_session_t *session = NULL;

    clib_memset(&key, 0, sizeof(spi_ha_sync_key_t));

    key.is_ip6 = data->is_ip6;
    key.proto = data->proto;
    if (data->exchanged_tuple)
    {
        key.port[0] = data->down_link_flow.sport;
        key.port[1] = data->down_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->down_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->down_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->down_link_flow.ip4.daddr.as_u32;
        }
    }
    else
    {
        key.port[0] = data->up_link_flow.sport;
        key.port[1] = data->up_link_flow.dport;

        if (data->is_ip6)
        {
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.saddr);
            ip6_address_copy(&key.ip6.addr[0], &data->up_link_flow.ip6.daddr);
        }
        else
        {
            key.ip4.addr[0].as_u32 = data->up_link_flow.ip4.saddr.as_u32;
            key.ip4.addr[1].as_u32 = data->up_link_flow.ip4.daddr.as_u32;
        }
    }

    if (clib_bihash_search_inline_2_with_hash_48_8 (&spim->session_table, 
                                                     data->hash, 
                                                     (clib_bihash_kv_48_8_t *)key.key,
                                                     &kv))
    {
        clib_warning("SPI ha sync session not found!");
        return;
    }

    tspi = &spim->per_thread_data[SPI_BIHASH_SESSION_VALUE_GET_THREAD(kv.value)];
    session =  pool_elt_at_index (tspi->sessions, SPI_BIHASH_SESSION_VALUE_GET_SESSION_ID(kv.value));

    SPI_THREAD_LOCK(tspi);

    if(PREDICT_FALSE(spi_delete_session(spim, tspi, session, true)))
    {
        clib_warning ("SPI ha sync del session is failed\n");
    }

    SPI_THREAD_UNLOCK(tspi);
    return;
}

static_always_inline void
spi_ha_sync_apply_session_proc(spi_ha_sync_event_session_t *event)
{
#if SPI_HASH_SYNC_DEBUG
    u8 *s = 0;
    s = format(s, "Header: \n%U", format_spi_ha_sync_header_format, &event->header);
    s = format(s, "Data: \n%U", format_spi_ha_sync_session_format, &event->data);
    clib_warning("%s", s);
    vec_free(s);
#endif
    spi_ha_sync_header_t *header  = &event->header;
    spi_ha_sync_session_data_t *data  = &event->data;

    switch (header->event_op)
    {
    case SPI_HA_OP_ADD:
        {
            spi_ha_sync_session_add(header->event_thread_id, data, 0);
        }
        break;
    case SPI_HA_OP_ADD_FORCE:
        {
            spi_ha_sync_session_add(header->event_thread_id, data, 1);
        }
        break;
    case SPI_HA_OP_UPDATE:
        {
            spi_ha_sync_session_update(header->event_thread_id, data);
        }
        break;
    case SPI_HA_OP_DEL:
        {
            spi_ha_sync_session_del(header->event_thread_id, data, 0);
        }
        break;
    case SPI_HA_OP_DEL_FORCE:
        {
            spi_ha_sync_session_del(header->event_thread_id, data, 1);
        }
        break;
    case SPI_HA_OP_REFRESH:
        clib_warning("SPI ha-sync session current not support op %u", header->event_op);
        break;
    }

    return;
}

static void
spi_ha_sync_session_apply_cb (u32 app_type, void *ctx, u8 *session, u16 session_len)
{
    ASSERT(app_type == HA_SYNC_APP_SPI);

    u32 thread_index = vlib_get_thread_index();
    spi_ha_sync_header_t *header = (spi_ha_sync_header_t *)session;

    if (header->event_type >= SPI_HA_TYPE_VALID)
    {
        clib_warning("spi ha sync received undefined type %d", header->event_type);
        return;
    }

    if (header->event_type == SPI_HA_OP_NONE)
    {
        /*
         * current do nothing 
         */
        return;
    }

    switch(header->event_type)
    {
    case SPI_HA_TYPE_SESSION:
        {
            if (session_len < sizeof(spi_ha_sync_event_session_t))
            {
                clib_warning("spi ha sync received session event length too small (current %u expected %u)", session_len, sizeof(spi_ha_sync_event_session_t));
                return;
            }
            if (header->event_thread_id != thread_index)
            {
                lf_fifo_enqueue_mp(spi_ha_sync_ctx.handoff[header->event_thread_id].session_fifo, 1, (void *)session);
                return;
            }
            spi_ha_sync_apply_session_proc((spi_ha_sync_event_session_t *)session);
        }
        break;
    }
    return;
}

VLIB_NODE_FN (spi_ha_sync_handoff_proc_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 thread_index = vm->thread_index;
    spi_ha_sync_handoff_runtime_t *rt = (spi_ha_sync_handoff_runtime_t *) node->runtime_data;
    spi_ha_sync_event_session_handoff_t *handoff = &spi_ha_sync_ctx.handoff[thread_index];

    if (PREDICT_FALSE(!rt->session))
    {
        vec_validate(rt->session, SPI_HA_SYNC_HANDOFF_PER_NUM);
    }

    if (lf_fifo_empty(handoff->session_fifo))
    {
        return 0;
    }

    u32 num = 0;
    u32 i;

    num = lf_fifo_dequeue_sc (handoff->session_fifo, SPI_HA_SYNC_HANDOFF_PER_NUM, rt->session);

    if (num > 0)
    {
        for (i = 0; i < num; i++)
        {
            spi_ha_sync_apply_session_proc(&rt->session[i]);
        }
    }
    return num;
}

VLIB_REGISTER_NODE (spi_ha_sync_handoff_proc_node) = {
  .name = "spi-ha-sync-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .runtime_data_bytes = sizeof (spi_ha_sync_handoff_runtime_t),
};

static int *spi_ha_sync_register_session_application_ptr;
static int *spi_ha_sync_unregister_session_application_ptr;
void *spi_ha_sync_per_thread_buffer_add_ptr;

static ha_sync_session_registration_t spi_ha_sync_registration = {
    .app_type = HA_SYNC_APP_SPI,
    .context = &spi_ha_sync_ctx,
    .snapshot_send_cb = spi_ha_sync_snapshot_send_cb,
    .session_apply_cb = spi_ha_sync_session_apply_cb,
    .snapshot_mode = HA_SYNC_SNAPSHOT_MODE_PER_THREAD,
};

static_always_inline void spi_ha_sync_handoff_init()
{
    u32 num_workers = vlib_num_workers();
    vlib_global_main_t *vgm = vlib_get_global_main ();
    int i;

    spi_ha_sync_event_session_handoff_t *handoff;

    vec_validate (spi_ha_sync_ctx.handoff, num_workers);

    vec_foreach (handoff, spi_ha_sync_ctx.handoff)
    {
        handoff->session_fifo = lf_fifo_alloc(SPI_HA_SYNC_HANDOFF_QUEUE_SIZE, sizeof(spi_ha_sync_event_session_t));
    }

    vec_foreach_index (i, vgm->vlib_mains)
    {
        if (i == 0) continue;
        vlib_node_set_state (vgm->vlib_mains[i], spi_ha_sync_handoff_proc_node.index, VLIB_NODE_STATE_POLLING);
    }

    return;
}

static_always_inline void spi_ha_sync_handoff_deinit()
{
    spi_ha_sync_event_session_handoff_t *handoff;
    vlib_global_main_t *vgm = vlib_get_global_main ();
    int i;

    vec_foreach_index (i, vgm->vlib_mains)
    {
        if (i == 0) continue;
        vlib_node_set_state (vgm->vlib_mains[i], spi_ha_sync_handoff_proc_node.index, VLIB_NODE_STATE_DISABLED);
    }

    vec_foreach (handoff, spi_ha_sync_ctx.handoff)
    {
        lf_fifo_free(handoff->session_fifo);
    }

    vec_free (spi_ha_sync_ctx.handoff);
    return;
}

int spi_ha_sync_register (void)
{
    spi_ha_sync_handoff_init();

    spi_ha_sync_register_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_register_session_application");

    spi_ha_sync_per_thread_buffer_add_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_per_thread_buffer_add");

    if(spi_ha_sync_register_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        spi_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    if(spi_ha_sync_per_thread_buffer_add_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_per_thread_buffer_add is not found");
        spi_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    spi_ha_sync_ctx.ha_sync_plugin_found = 1;


    if (((__typeof__ (ha_sync_register_session_application) *)spi_ha_sync_register_session_application_ptr) (&spi_ha_sync_registration))
    {
        clib_warning ("spi register ha sync failed");
        spi_ha_sync_ctx.ha_sync_register = 0;
        return 0;
    }

    spi_ha_sync_ctx.ha_sync_register = 1;

    return 0;
}

void spi_ha_sync_unregister (void)
{
    spi_ha_sync_handoff_deinit();

    spi_ha_sync_unregister_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_unregister_session_application");

    if(spi_ha_sync_unregister_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        spi_ha_sync_ctx.ha_sync_plugin_found = 0;
        return;
    }

    spi_ha_sync_ctx.ha_sync_plugin_found = 1;

    if (((__typeof__ (ha_sync_unregister_session_application) *)spi_ha_sync_unregister_session_application_ptr) (HA_SYNC_APP_SPI))
    {
        clib_warning ("spi unregister ha sync failed");
    }
    spi_ha_sync_ctx.ha_sync_register = 0;
}
