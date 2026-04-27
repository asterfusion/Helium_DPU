#include <nat/nat44-ed/nat44_ed.h>
#include <nat/nat44-ed/nat44_ed_inlines.h>
#include <nat/nat44-ed/nat44_ed_ha_sync.h>
#include <vnet/plugin/plugin.h>

nat44_ed_ha_sync_ctx_t nat44_ed_ha_sync_ctx;

typedef struct
{
    u32 snapshot_version;

    uword snapshot_flow_index;

} nat44_ed_ha_sync_snapshot_runtime_t;

typedef struct
{
    nat44_ed_ha_sync_event_flow_t *flow_session;
} nat44_ed_ha_sync_handoff_runtime_t;

static char *nat44_ed_event_op_string[] = {
    [NAT44_ED_HA_OP_NONE] = "none",
    [NAT44_ED_HA_OP_ADD] = "add",
    [NAT44_ED_HA_OP_ADD_FORCE] = "add_force",
    [NAT44_ED_HA_OP_DEL] = "del",
    [NAT44_ED_HA_OP_DEL_FORCE] = "del_force",
    [NAT44_ED_HA_OP_UPDATE] = "update",
    [NAT44_ED_HA_OP_REFRESH] = "refresh",
};

static char *nat44_ed_event_type_string[] = {
    [NAT44_ED_HA_TYPE_NONE] = "none",
    [NAT44_ED_HA_TYPE_FLOW] = "flow",
};

static u8 *format_nat44_ed_event_op (u8 * s, va_list * args)
{
  u8 *op = va_arg (*args, u8 *);
  if (*op < NAT44_ED_HA_OP_VALID)
  {
      return format(s, nat44_ed_event_op_string[*op]);
  }
  return format(s, "WRONG_OP");
}

static u8 *format_nat44_ed_event_type (u8 * s, va_list * args)
{
  u8 *type = va_arg (*args, u8 *);
  if (*type < NAT44_ED_HA_OP_VALID)
  {
      return format(s, nat44_ed_event_type_string[*type]);
  }
  return format(s, "WRONG_TYPE");
}

u8 *format_nat44_ed_ha_sync_header_format (u8 * s, va_list * args)
{
  nat44_ed_ha_sync_header_t *header = va_arg (*args, nat44_ed_ha_sync_header_t *);
  s = format(s, "\tevent_thread_id %u, op %U, event_type %U, data length %u\n", 
             header->event_thread_id, 
             format_nat44_ed_event_op, &header->event_op,
             format_nat44_ed_event_type, &header->event_type,
             clib_net_to_host_u16(header->event_data_len));
  return s;
}

u8 *format_nat44_ed_ha_sync_flow_format (u8 * s, va_list * args)
{
  nat44_ed_ha_sync_flow_data_t *data = va_arg (*args, nat44_ed_ha_sync_flow_data_t *);

  if (nat44_ed_is_unk_proto (data->proto))
  {
      s = format (s, "i2o %U proto %u vrf table %u\n",
              format_ip4_address, &data->in2out.addr,
              data->in2out.port, data->in2out.table_id);
      s = format (s, "o2i %U proto %u vrf table %u\n", 
              format_ip4_address, &data->out2in.addr, 
              data->out2in.port, data->out2in.table_id);
  }
  else
  {
      s = format (s, "i2o %U proto %U port %d vrf table %d\n", format_ip4_address,
              &data->in2out.addr, format_ip_protocol, data->proto,
              clib_net_to_host_u16 (data->in2out.port),
              data->in2out.table_id);
      s = format (s, "o2i %U proto %U port %d vrf table %d\n",
              format_ip4_address, &data->out2in.addr, format_ip_protocol,
              data->proto, clib_net_to_host_u16 (data->out2in.port),
              data->out2in.table_id);
  }
  if (data->flags & SNAT_SESSION_FLAG_TWICE_NAT)
  {
      s = format (s, "\texternal host o2i %U:%d i2o %U:%d\n",
              format_ip4_address, &data->ext_host_addr,
              clib_net_to_host_u16 (data->ext_host_port),
              format_ip4_address, &data->ext_host_nat_addr,
              clib_net_to_host_u16 (data->ext_host_nat_port));
  }
  else
  {
      if (data->ext_host_addr.as_u32)
          s = format (s, "\texternal host %U:%u\n",
                  format_ip4_address, &data->ext_host_addr,
                  clib_net_to_host_u16 (data->ext_host_port));
  }

  s = format (s, "i2o flow: %U\n", format_nat_6t_flow, &data->i2o);
  s = format (s, "o2i flow: %U\n", format_nat_6t_flow, &data->o2i);

  if (data->flags & SNAT_SESSION_FLAG_STATIC_MAPPING)
      s = format (s, "static translation\n");
  else
      s = format (s, "dynamic translation\n");

  if (data->flags & SNAT_SESSION_FLAG_FWD_BYPASS)
      s = format (s, "forwarding-bypass\n");

  if (data->flags & SNAT_SESSION_FLAG_LOAD_BALANCING)
      s = format (s, "load-balancing\n");

  if (data->flags & SNAT_SESSION_FLAG_TWICE_NAT)
      s = format (s, "twice-nat\n");

  return s;
}

static int
nat44_ed_ha_sync_snapshot_send_cb (u32 app_type, void *ctx, u32 thread_index)
{
    ASSERT(app_type == HA_SYNC_APP_NAT);

    nat44_ed_ha_sync_ctx_t *nat44_ed_ctx = (nat44_ed_ha_sync_ctx_t *)ctx;

    //Triggering an interrupt to notify the process to start a snapshot
    if (nat44_ed_ctx->current_snapshot_version != nat44_ed_ctx->ha_sync_ctx.ha_sync_snapshot_sequence)
    {
        vlib_process_signal_event_mt (vlib_get_main(), 
                                     nat44_ed_ha_sync_snapshot_process_node.index, 
                                     NAT44_ED_HA_SYNC_SNAPSHOT_PROCESS_RESTART, 0);

        nat44_ed_ctx->current_snapshot_version = nat44_ed_ctx->ha_sync_ctx.ha_sync_snapshot_sequence;
    }

    return 0;
}

static_always_inline 
void generate_flow_table_snapshot(vlib_main_t * vm, 
                                  nat44_ed_ha_sync_ctx_t *ctx, 
                                  nat44_ed_ha_sync_snapshot_runtime_t *rt)
{
    u32 thread_index = vm->thread_index;
    snat_main_t *sm = &snat_main;
    snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

    snat_session_t *s = NULL;

    uword pool_active_num = pool_elts(tsm->sessions);
    uword pool_max_num = pool_max_len(tsm->sessions);

    if (PREDICT_FALSE (pool_active_num == 0))
    {
        ctx->snapshot_flow_end[thread_index] = 1;
        return;
    }

    uword i;
    uword pool_walk_end = (pool_max_num >> NAT44_ED_HA_SYNC_SNAPSHOT_BUCKET_WALK_SCALING);
    pool_walk_end = rt->snapshot_flow_index + pool_walk_end > 0 ? pool_walk_end : pool_max_num;
    pool_walk_end = pool_walk_end < pool_max_num ? pool_walk_end : pool_max_num;

    pool_foreach_stepping_index(i, rt->snapshot_flow_index, pool_walk_end, tsm->sessions)
    {
        if (pool_is_free_index(tsm->sessions, i)) continue;

        s = pool_elt_at_index (tsm->sessions, i);
        nat44_ed_ha_sync_event_flow_notify(thread_index, NAT44_ED_HA_OP_ADD_FORCE, s);
    }
    rt->snapshot_flow_index = i;

    if (rt->snapshot_flow_index >= pool_max_num)
    {
        ctx->snapshot_flow_end[thread_index] = 1;
        rt->snapshot_flow_index = 0;
    }

    return;
}

static uword
nat44_ed_ha_sync_snapshot_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    uword event_type = 0, *event_data = NULL;

    u32 n_threads = vlib_get_n_threads ();

    f64 cpu_cps = vm->clib_time.clocks_per_second;

    u64 max_timer_wait_interval = cpu_cps / NAT44_ED_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY;

    vec_validate(nat44_ed_ha_sync_ctx.snapshot_flow_end, n_threads);

    while (1)
    {
        /* Wait for Godot... */
        if (nat44_ed_ha_sync_snapshot_act(nat44_ed_ha_sync_ctx.flag))
        {
            vlib_process_wait_for_event_or_clock (vm, (max_timer_wait_interval / cpu_cps));
        }
        else
        {
            vlib_process_wait_for_event (vm);
        }

        if(NAT44_ED_CHECK_HA_SYNC) continue;

        event_type = vlib_process_get_events (vm, &event_data);

        if (event_type == NAT44_ED_HA_SYNC_SNAPSHOT_PROCESS_RESTART)
        {
            nat44_ed_ha_sync_ctx.flag |= NAT44_ED_HA_SYNC_CTX_FLAG_SNAPSHOT_FLOW;
            vec_zero(nat44_ed_ha_sync_ctx.snapshot_flow_end);
        }

        u32 ti;
        u32 flow_end_cnt = 0;
        for (ti = 0; ti < n_threads; ti++)
        {
           flow_end_cnt += nat44_ed_ha_sync_ctx.snapshot_flow_end[ti] ? 1 : 0;
        }

        if (flow_end_cnt == n_threads)
        {
            nat44_ed_ha_sync_ctx.flag &= ~NAT44_ED_HA_SYNC_CTX_FLAG_SNAPSHOT_FLOW;
        }

        /*
         * snapshot worker interrupt 
         */
        for (ti = 0; ti < n_threads; ti++)
        {
            vlib_node_set_interrupt_pending (vlib_get_main_by_index (ti),
                    nat44_ed_ha_sync_snapshot_node.index);
        }

        vec_reset_length (event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE (nat44_ed_ha_sync_snapshot_process_node) = {
  .function = nat44_ed_ha_sync_snapshot_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "nat44-ed-ha-sync-snapshot-process",
  .n_next_nodes = 0,
  .next_nodes = {},
};

VLIB_NODE_FN (nat44_ed_ha_sync_snapshot_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 thread_index = vm->thread_index;

    nat44_ed_ha_sync_snapshot_runtime_t *rt = (nat44_ed_ha_sync_snapshot_runtime_t *) node->runtime_data;

    if (rt->snapshot_version == nat44_ed_ha_sync_ctx.current_snapshot_version)
        return 0;

    if (!nat44_ed_ha_sync_ctx.snapshot_flow_end[thread_index])
    {
        generate_flow_table_snapshot(vm, &nat44_ed_ha_sync_ctx, rt);
    }

    if (nat44_ed_ha_sync_ctx.snapshot_flow_end[thread_index])
    {
        rt->snapshot_version = nat44_ed_ha_sync_ctx.current_snapshot_version;
    }
    return 0;
}

VLIB_REGISTER_NODE (nat44_ed_ha_sync_snapshot_node) = {
  .name = "nat44-ed-ha-sync-snapshot",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .runtime_data_bytes = sizeof (nat44_ed_ha_sync_snapshot_runtime_t),
};

static_always_inline void
nat44_ed_ha_sync_flow_add(u32 thread_index, nat44_ed_ha_sync_flow_data_t *data, int is_force)
{
    vlib_main_t *vm = vlib_get_main();
    snat_main_t *sm = &snat_main;
    f64 now = vlib_time_now (vm);
    //snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

    u32 s_thread_index = thread_index;
    snat_main_per_thread_data_t *ptsm = &sm->per_thread_data[thread_index];

    snat_session_t *s = NULL;

    nat_6t_flow_t i2o;
    nat_6t_flow_t o2i;
    clib_bihash_kv_16_8_t kv_i2o, value_i2o;
    clib_bihash_kv_16_8_t kv_o2i, value_o2i;

    int search_i2o = 0,  search_o2i = 0;

    clib_memcpy(&i2o, &data->i2o, sizeof(nat_6t_flow_t));
    clib_memcpy(&o2i, &data->o2i, sizeof(nat_6t_flow_t));

    nat_6t_flow_to_ed_k (&kv_i2o, &i2o);
    nat_6t_flow_to_ed_k (&kv_o2i, &o2i);

    search_i2o = clib_bihash_search_16_8 (&sm->flow_hash, &kv_i2o, &value_i2o);
    search_o2i = clib_bihash_search_16_8 (&sm->flow_hash, &kv_o2i, &value_o2i);

    if (!search_i2o && !search_o2i)
    {
        if (value_i2o.value == value_o2i.value)
        {
            s_thread_index = ed_value_get_thread_index(&value_i2o);
            ptsm = &sm->per_thread_data[s_thread_index];
            if (thread_index != s_thread_index)
            {
                clib_warning("NAT44-ED ha sync create sessions existed : the threads are different");
            }

            s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_i2o));

            s->flags = data->flags;

            clib_memcpy(&s->tcp_flags, &data->tcp_flags, sizeof(u8) * NAT44_ED_N_DIR);
            s->tcp_state = data->tcp_state;
            s->last_heard = now;

            per_vrf_sessions_register_session (s, s_thread_index);

            nat44_session_update_lru (sm, s, s_thread_index);

            return;
        }
        else
        {
            /*
             * If the sessions corresponding to i2i and o2i are inconsistent:
             * not_force:
             *    Ignore this
             * is_force:
             *    Remove existing session and add new session
             */
            if (!is_force)
                return;

            s_thread_index = ed_value_get_thread_index(&value_i2o);
            ptsm = &sm->per_thread_data[s_thread_index];
            s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_i2o));
            nat44_ed_free_session_data (sm, s, s_thread_index, 1);
            nat_ed_session_delete (sm, s, s_thread_index, 1);

            s_thread_index = ed_value_get_thread_index(&value_o2i);
            ptsm = &sm->per_thread_data[s_thread_index];
            s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_o2i));
            nat44_ed_free_session_data (sm, s, s_thread_index, 1);
            nat_ed_session_delete (sm, s, s_thread_index, 1);

            goto session_create;
        }
    }
    else if (!search_i2o && search_o2i)
    {
        /*
         * session inconsistent
         */
        if (!is_force)
            return;

        s_thread_index = ed_value_get_thread_index(&value_i2o);
        ptsm = &sm->per_thread_data[s_thread_index];
        s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_i2o));
        nat44_ed_free_session_data (sm, s, s_thread_index, 1);
        nat_ed_session_delete (sm, s, s_thread_index, 1);

        goto session_create;
    }
    else if (search_i2o && !search_o2i)
    {
        /*
         * session inconsistent
         */
        if (!is_force)
            return;

        s_thread_index = ed_value_get_thread_index(&value_o2i);
        ptsm = &sm->per_thread_data[s_thread_index];
        s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_o2i));
        nat44_ed_free_session_data (sm, s, s_thread_index, 1);
        nat_ed_session_delete (sm, s, s_thread_index, 1);

        goto session_create;
    }

session_create:
    s = nat_ed_session_alloc(sm, thread_index, now, data->proto);
    if (!s)
    {
        clib_warning("NAT44-ED ha sync create NAT session failed!");
        return;
    }
    //in2out
    clib_memcpy(&s->i2o, &data->i2o, sizeof(nat_6t_flow_t));
    s->in2out.addr = data->in2out.addr;
    s->in2out.fib_index = fib_table_find (FIB_PROTOCOL_IP4, data->in2out.table_id);
    s->in2out.port = data->in2out.port;

    //out2in
    clib_memcpy(&s->o2i, &data->o2i, sizeof(nat_6t_flow_t));
    s->out2in.addr = data->out2in.addr;
    s->out2in.fib_index = fib_table_find (FIB_PROTOCOL_IP4, data->out2in.table_id);
    s->out2in.port = data->out2in.port;

    s->proto = data->proto;
    s->ext_host_addr = data->ext_host_addr;
    s->ext_host_port = data->ext_host_port;
    s->ext_host_nat_addr = data->ext_host_nat_addr;
    s->ext_host_nat_port = data->ext_host_nat_port;

    s->flags = data->flags;

    clib_memcpy(&s->tcp_flags, &data->tcp_flags, sizeof(u8) * NAT44_ED_N_DIR);
    s->tcp_state = data->tcp_state;
    s->last_heard = now;

    if (is_force)
    {
        if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 1))
        {
            clib_warning("NAT44-ED ha sync add_force in2out flow hash add failed");
            nat_ed_session_delete (sm, s, thread_index, 1);
            return;
        }

        if (!(data->flags & SNAT_SESSION_FLAG_FWD_BYPASS))
        {
            if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 1))
            {
                clib_warning("NAT44-ED ha sync add_force out2in flow hash add failed");
                nat_ed_session_delete (sm, s, thread_index, 1);
                return;
            }
        }
    }
    else
    {
        if (nat_ed_ses_i2o_flow_hash_add_del (sm, thread_index, s, 2))
        {
            clib_warning("NAT44-ED ha sync add in2out flow hash add failed");
            nat_ed_session_delete (sm, s, thread_index, 1);
            return;
        }

        if (!(data->flags & SNAT_SESSION_FLAG_FWD_BYPASS))
        {
            if (nat_ed_ses_o2i_flow_hash_add_del (sm, thread_index, s, 2))
            {
                clib_warning("NAT44-ED ha sync add out2in flow hash add failed");
                nat_ed_session_delete (sm, s, thread_index, 1);
                return;
            }
        }
    }

    per_vrf_sessions_register_session (s, thread_index);

    nat44_session_update_lru (sm, s, thread_index);

    return;
}

static_always_inline void
nat44_ed_ha_sync_flow_update(u32 thread_index, nat44_ed_ha_sync_flow_data_t *data)
{
    vlib_main_t *vm = vlib_get_main();
    snat_main_t *sm = &snat_main;
    f64 now = vlib_time_now (vm);
    snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

    snat_session_t *s = NULL;

    nat_6t_flow_t i2o;
    nat_6t_flow_t o2i;
    clib_bihash_kv_16_8_t kv_i2o, value_i2o;
    clib_bihash_kv_16_8_t kv_o2i, value_o2i;

    clib_memcpy(&i2o, &data->i2o, sizeof(nat_6t_flow_t));
    clib_memcpy(&o2i, &data->o2i, sizeof(nat_6t_flow_t));

    nat_6t_flow_to_ed_k (&kv_i2o, &i2o);
    nat_6t_flow_to_ed_k (&kv_o2i, &o2i);

    if (clib_bihash_search_16_8 (&sm->flow_hash, &kv_i2o, &value_i2o))
    {
        clib_warning("NAT44-ED ha sync update i2o flow not found");
        return;
    }

    if (!(data->flags & SNAT_SESSION_FLAG_FWD_BYPASS))
    {
        if (clib_bihash_search_16_8 (&sm->flow_hash, &kv_o2i, &value_o2i))
        {
            clib_warning("NAT44-ED ha sync update o2i flow not found");
            return;
        }

        if (value_i2o.value != value_o2i.value)
        {
            clib_warning("NAT44-ED ha sync update sessions corresponding to i2i and o2i are not the same");
            return;
        }
    }

    if (thread_index != ed_value_get_thread_index(&value_i2o))
    {
        thread_index = ed_value_get_thread_index(&value_i2o);
        tsm = &sm->per_thread_data[thread_index];
    }

    s = pool_elt_at_index (tsm->sessions, ed_value_get_session_index (&value_i2o));

    s->last_heard = now;
    s->ha_last_refreshed = now;

    clib_memcpy(&s->tcp_flags, &data->tcp_flags, sizeof(u8) * NAT44_ED_N_DIR);
    s->tcp_state = data->tcp_state;

    nat44_session_update_lru (sm, s, thread_index);

    return;
}
static_always_inline void
nat44_ed_ha_sync_flow_del(u32 thread_index, nat44_ed_ha_sync_flow_data_t *data, int is_force)
{
    snat_main_t *sm = &snat_main;

    //snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];

    u32 s_thread_index = thread_index;
    snat_main_per_thread_data_t *ptsm = &sm->per_thread_data[thread_index];

    snat_session_t *s = NULL;

    nat_6t_flow_t i2o;
    nat_6t_flow_t o2i;
    clib_bihash_kv_16_8_t kv_i2o, value_i2o;
    clib_bihash_kv_16_8_t kv_o2i, value_o2i;

    clib_memcpy(&i2o, &data->i2o, sizeof(nat_6t_flow_t));
    clib_memcpy(&o2i, &data->o2i, sizeof(nat_6t_flow_t));

    nat_6t_flow_to_ed_k (&kv_i2o, &i2o);
    nat_6t_flow_to_ed_k (&kv_o2i, &o2i);

    if (clib_bihash_search_16_8 (&sm->flow_hash, &kv_i2o, &value_i2o))
    {
        clib_warning("NAT44-ED ha sync del i2o flow not found");
        return;
    }

    if (!(data->flags & SNAT_SESSION_FLAG_FWD_BYPASS))
    {
        if (clib_bihash_search_16_8 (&sm->flow_hash, &kv_o2i, &value_o2i))
        {
            clib_warning("NAT44-ED ha sync del o2i flow not found");
            return;
        }

        if (value_i2o.value != value_o2i.value)
        {
            clib_warning("NAT44-ED ha sync del sessions corresponding to i2i and o2i are not the same");
            if (!is_force)
                return;

            s_thread_index = ed_value_get_thread_index(&value_o2i);
            ptsm = &sm->per_thread_data[s_thread_index];

            s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_o2i));
            nat44_ed_free_session_data (sm, s, s_thread_index, 1);
            nat_ed_session_delete (sm, s, s_thread_index, 1);
        }
    }

    s_thread_index = ed_value_get_thread_index(&value_i2o);
    ptsm = &sm->per_thread_data[s_thread_index];

    if (thread_index != s_thread_index)
    {
        clib_warning("NAT44-ED ha sync delete sessions threads are different");
    }

    s = pool_elt_at_index (ptsm->sessions, ed_value_get_session_index (&value_i2o));
    nat44_ed_free_session_data (sm, s, s_thread_index, 1);
    nat_ed_session_delete (sm, s, s_thread_index, 1);
    return;
}

static_always_inline void
nat44_ed_ha_sync_apply_flow_proc(nat44_ed_ha_sync_event_flow_t *event)
{
#if NAT44_ED_HASH_SYNC_DEBUG
    u8 *s = 0;
    s = format(s, "Header: \n%U", format_nat44_ed_ha_sync_header_format, &event->header);
    s = format(s, "Data: \n%U", format_nat44_ed_ha_sync_flow_format, &event->data);
    clib_warning("%s", s);
    vec_free(s);
#endif
    nat44_ed_ha_sync_header_t *header  = &event->header;
    nat44_ed_ha_sync_flow_data_t *data  = &event->data;

    switch (header->event_op)
    {
    case NAT44_ED_HA_OP_ADD:
        {
            nat44_ed_ha_sync_flow_add(header->event_thread_id, data, 0);
        }
        break;
    case NAT44_ED_HA_OP_ADD_FORCE:
        {
            nat44_ed_ha_sync_flow_add(header->event_thread_id, data, 1);
        }
        break;
    case NAT44_ED_HA_OP_UPDATE:
        {
            nat44_ed_ha_sync_flow_update(header->event_thread_id, data);
        }
        break;
    case NAT44_ED_HA_OP_DEL:
        {
            nat44_ed_ha_sync_flow_del(header->event_thread_id, data, 0);
        }
        break;
    case NAT44_ED_HA_OP_DEL_FORCE:
        {
            nat44_ed_ha_sync_flow_del(header->event_thread_id, data, 1);
        }
        break;
    case NAT44_ED_HA_OP_REFRESH:
        clib_warning("NAT44-ED ha-sync flow current not support op %u", header->event_op);
        break;
    }

    return;
}

static void
nat44_ed_ha_sync_session_apply_cb (u32 app_type, void *ctx, u8 *session, u16 session_len)
{
    ASSERT(app_type == HA_SYNC_APP_NAT);

    u32 thread_index = vlib_get_thread_index();
    nat44_ed_ha_sync_header_t *header = (nat44_ed_ha_sync_header_t *)session;

    if (header->event_type >= NAT44_ED_HA_TYPE_VALID)
    {
        clib_warning("nat44-ed ha sync received undefined type %d", header->event_type);
        return;
    }

    if (header->event_type == NAT44_ED_HA_OP_NONE)
    {
        /*
         * current do nothing 
         */
        return;
    }

    switch(header->event_type)
    {
    case NAT44_ED_HA_TYPE_FLOW:
        {
            if (session_len < sizeof(nat44_ed_ha_sync_event_flow_t))
            {
                clib_warning("nat44-ed ha sync received flow event length too small (current %u expected %u)", session_len, sizeof(nat44_ed_ha_sync_event_flow_t));
                return;
            }
            if (header->event_thread_id != thread_index)
            {
                lf_fifo_enqueue_mp(nat44_ed_ha_sync_ctx.handoff[header->event_thread_id].flow_fifo, 1, (void *)session);
                return;
            }
            nat44_ed_ha_sync_apply_flow_proc((nat44_ed_ha_sync_event_flow_t *)session);
        }
        break;
    }
    return;
}

VLIB_NODE_FN (nat44_ed_ha_sync_handoff_proc_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
    u32 thread_index = vm->thread_index;
    nat44_ed_ha_sync_handoff_runtime_t *rt = (nat44_ed_ha_sync_handoff_runtime_t *) node->runtime_data;
    nat44_ed_ha_sync_event_flow_handoff_t *handoff = &nat44_ed_ha_sync_ctx.handoff[thread_index];

    if (PREDICT_FALSE(!rt->flow_session))
    {
        vec_validate(rt->flow_session, NAT44_ED_HA_SYNC_HANDOFF_PER_NUM);
    }

    if (lf_fifo_empty(handoff->flow_fifo))
    {
        return 0;
    }

    u32 num = 0;
    u32 i;

    num = lf_fifo_dequeue_sc (handoff->flow_fifo, NAT44_ED_HA_SYNC_HANDOFF_PER_NUM, rt->flow_session);

    if (num > 0)
    {
        for (i = 0; i < num; i++)
        {
            nat44_ed_ha_sync_apply_flow_proc(&rt->flow_session[i]);
        }
    }
    return num;
}

VLIB_REGISTER_NODE (nat44_ed_ha_sync_handoff_proc_node) = {
  .name = "nat44-ed-ha-sync-handoff",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .runtime_data_bytes = sizeof (nat44_ed_ha_sync_handoff_runtime_t),
};

static int *nat44_ed_ha_sync_register_session_application_ptr;
static int *nat44_ed_ha_sync_unregister_session_application_ptr;
void *nat44_ed_ha_sync_per_thread_buffer_add_ptr;

static ha_sync_session_registration_t nat44_ed_ha_sync_registration = {
    .app_type = HA_SYNC_APP_NAT,
    .context = &nat44_ed_ha_sync_ctx,
    .snapshot_send_cb = nat44_ed_ha_sync_snapshot_send_cb,
    .session_apply_cb = nat44_ed_ha_sync_session_apply_cb,
    .snapshot_mode = HA_SYNC_SNAPSHOT_MODE_PER_THREAD,
};

int nat44_ed_ha_sync_set_timeout_update_interval(u32 ha_sync_timeout_update_interval)
{
    nat44_ed_ha_sync_ctx.ha_sync_timeout_update_interval = ha_sync_timeout_update_interval;
    return 0;
}

static_always_inline void nat44_ed_ha_sync_handoff_init()
{
    u32 num_workers = vlib_num_workers();
    vlib_global_main_t *vgm = vlib_get_global_main ();
    int i;

    nat44_ed_ha_sync_event_flow_handoff_t *handoff;

    vec_validate (nat44_ed_ha_sync_ctx.handoff, num_workers);

    vec_foreach (handoff, nat44_ed_ha_sync_ctx.handoff)
    {
        handoff->flow_fifo = lf_fifo_alloc(NAT44_ED_HA_SYNC_HANDOFF_QUEUE_SIZE, sizeof(nat44_ed_ha_sync_event_flow_t));
    }

    vec_foreach_index (i, vgm->vlib_mains)
    {
        if (i == 0) continue;
        vlib_node_set_state (vgm->vlib_mains[i], nat44_ed_ha_sync_handoff_proc_node.index, VLIB_NODE_STATE_POLLING);
    }

    return;
}

static_always_inline void nat44_ed_ha_sync_handoff_deinit()
{
    nat44_ed_ha_sync_event_flow_handoff_t *handoff;
    vlib_global_main_t *vgm = vlib_get_global_main ();
    int i;

    vec_foreach_index (i, vgm->vlib_mains)
    {
        if (i == 0) continue;
        vlib_node_set_state (vgm->vlib_mains[i], nat44_ed_ha_sync_handoff_proc_node.index, VLIB_NODE_STATE_DISABLED);
    }

    vec_foreach (handoff, nat44_ed_ha_sync_ctx.handoff)
    {
        lf_fifo_free(handoff->flow_fifo);
    }

    vec_free (nat44_ed_ha_sync_ctx.handoff);
    return;
}

int nat44_ed_ha_sync_register (void)
{
    nat44_ed_ha_sync_handoff_init();

    nat44_ed_ha_sync_register_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_register_session_application");

    nat44_ed_ha_sync_per_thread_buffer_add_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_per_thread_buffer_add");

    if(nat44_ed_ha_sync_register_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        nat44_ed_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    if(nat44_ed_ha_sync_per_thread_buffer_add_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_per_thread_buffer_add is not found");
        nat44_ed_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    nat44_ed_ha_sync_ctx.ha_sync_plugin_found = 1;


    if (((__typeof__ (ha_sync_register_session_application) *)nat44_ed_ha_sync_register_session_application_ptr) (&nat44_ed_ha_sync_registration))
    {
        clib_warning ("nat44-ed register ha sync failed");
        nat44_ed_ha_sync_ctx.ha_sync_register = 0;
        return 0;
    }

    nat44_ed_ha_sync_ctx.ha_sync_register = 1;

    nat44_ed_ha_sync_ctx.ha_sync_timeout_update_interval = NAT44_ED_HA_SYNC_TIMEOUT_UPDATE_INTERVAL;

    return 0;
}

void nat44_ed_ha_sync_unregister (void)
{
    nat44_ed_ha_sync_handoff_deinit();

    nat44_ed_ha_sync_unregister_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_unregister_session_application");

    if(nat44_ed_ha_sync_unregister_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        nat44_ed_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    nat44_ed_ha_sync_ctx.ha_sync_plugin_found = 1;

    if (((__typeof__ (ha_sync_unregister_session_application) *)nat44_ed_ha_sync_unregister_session_application_ptr) (HA_SYNC_APP_NAT))
    {
        clib_warning ("nat44-ed unregister ha sync failed");
    }
    nat44_ed_ha_sync_ctx.ha_sync_register = 0;
}
