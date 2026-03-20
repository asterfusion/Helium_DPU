#include <lb/lb_ha_sync.h>
#include <vnet/plugin/plugin.h>

lb_ha_sync_ctx_t lb_ha_sync_ctx;

static char *lb_event_op_string[] = {
    [LB_HA_OP_NONE] = "none",
    [LB_HA_OP_ADD] = "add",
    [LB_HA_OP_ADD_FORCE] = "add_force",
    [LB_HA_OP_DEL] = "del",
    [LB_HA_OP_DEL_FORCE] = "del_force",
    [LB_HA_OP_UPDATE] = "update",
    [LB_HA_OP_REFRESH] = "refresh",
};

static char *lb_event_type_string[] = {
    [LB_HA_TYPE_NONE] = "none",
    [LB_HA_TYPE_STICK_TABLE] = "sticky_table",
    [LB_HA_TYPE_VIP_SNAT_SESSION] = "vip_snat_table",
};

static u8 *format_lb_event_op (u8 * s, va_list * args)
{
  u8 *op = va_arg (*args, u8 *);
  if (*op < LB_HA_OP_VALID)
  {
      return format(s, lb_event_op_string[*op]);
  }
  return format(s, "WRONG_OP");
}

static u8 *format_lb_event_type (u8 * s, va_list * args)
{
  u8 *type = va_arg (*args, u8 *);
  if (*type < LB_HA_OP_VALID)
  {
      return format(s, lb_event_type_string[*type]);
  }
  return format(s, "WRONG_TYPE");
}

u8 *format_lb_ha_sync_header_format (u8 * s, va_list * args)
{
  lb_ha_sync_header_t *header = va_arg (*args, lb_ha_sync_header_t *);
  s = format(s, "\tevent_thread_id %u, op %U, event_type %U, data length %u\n", 
             header->event_thread_id, 
             format_lb_event_op, &header->event_op,
             format_lb_event_type, &header->event_type,
             clib_net_to_host_u16(header->event_data_len));
  return s;
}


u8 *format_lb_ha_sync_stick_format (u8 * s, va_list * args)
{
  lb_ha_sync_stick_table_data_t *data = va_arg (*args, lb_ha_sync_stick_table_data_t *);

  s = format(s, "\tvip_type %U, ip %U, protocol %u, l4_port %u, table_id %u hash %u",
             format_lb_vip_type, data->type,
             format_ip46_prefix, &data->prefix, (u32) data->plen, IP46_TYPE_ANY,
             data->protocol, clib_net_to_host_u16(data->l4_port),
             clib_net_to_host_u32(data->table_id),
             clib_net_to_host_u32(data->hash));

  s = format(s, "\t\tas ip %U , timeout %u",
             format_ip46_address, &data->address, IP46_TYPE_ANY,
             clib_net_to_host_u32(data->timeout));
  return s;
}

u8 *format_lb_ha_sync_vip_snat_format (u8 * s, va_list * args)
{
  lb_ha_sync_vip_snat_session_data_t *data = va_arg (*args, lb_ha_sync_vip_snat_session_data_t *);

  s = format(s, "\tvip_type %U, ip %U, protocol %u, l4_port %u",
             format_lb_vip_type, data->type, 
             format_ip46_prefix, &data->prefix, (u32) data->plen, IP46_TYPE_ANY,
             data->protocol, clib_net_to_host_u16(data->l4_port));

  s = format(s, "\t\toutside ip %U , outside port %u, outside_table_id %u", 
             format_ip46_address, &data->outside_ip, data->outside_ip_is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
             clib_net_to_host_u16(data->outside_port),
             clib_net_to_host_u32(data->outside_table_id));

  s = format(s, "\t\tsnat ip %U , snat port %u, snat_table_id %u", 
             format_ip46_address, &data->ip, data->ip_is_ipv6 ? IP46_TYPE_IP6 : IP46_TYPE_IP4,
             clib_net_to_host_u16(data->port),
             clib_net_to_host_u32(data->table_id));

  s = format(s, "\t\ttimeout %u", clib_net_to_host_u32(data->timeout));
  return s;
}

static int
lb_ha_sync_snapshot_send_cb (u32 app_type, void *ctx, u32 thread_index)
{
    ASSERT(app_type == HA_SYNC_APP_LB);

    lb_ha_sync_ctx_t *lb_ctx = (lb_ha_sync_ctx_t *)ctx;

    //Triggering an interrupt to notify the process to start a snapshot
    if (lb_ctx->current_snapshot_version != lb_ctx->ha_sync_ctx.ha_sync_snapshot_sequence)
    {
        vlib_process_signal_event_mt (vlib_get_main(), 
                                     lb_ha_sync_snapshot_process_node.index, 
                                     LB_HA_SYNC_SNAPSHOT_PROCESS_RESTART, 0);

        lb_ctx->current_snapshot_version = lb_ctx->ha_sync_ctx.ha_sync_snapshot_sequence;
        lb_ctx->snapshot_sticky_index = 0;
        lb_ctx->snapshot_vip_snat_index = 0;
    }

    return 0;
}

static_always_inline 
void generate_lb_sticky_table_snapshot(vlib_main_t * vm, lb_ha_sync_ctx_t *ctx)
{
    lb_main_t *lbm = &lb_main;

    u32 lb_time_now = lb_hash_time_now (vm);

    clib_bihash_8_8_t *sticky_ht = &lbm->sticky_ht;

    if (PREDICT_FALSE (sticky_ht->instantiated == 0))
    {
        ctx->flag &= ~LB_HA_SYNC_CTX_FLAG_SNAPSHOT_STICKY_ACT;
        return;
    }

    u32 i, j, k;

    clib_bihash_bucket_8_8_t *b;
    clib_bihash_value_8_8_t *v;
    lb_sticky_kv_t *lb_kv;
    lb_vip_t *vip;

    u32 bucket_walk_end = (sticky_ht->nbuckets >> LB_HAS_SYNC_SNAPSHOT_BUCKET_WALK_SCALING);

    bucket_walk_end = ctx->snapshot_sticky_index + bucket_walk_end > 0 ? bucket_walk_end : sticky_ht->nbuckets;
    bucket_walk_end = bucket_walk_end < sticky_ht->nbuckets ? bucket_walk_end : sticky_ht->nbuckets;
                            
    for (i = ctx->snapshot_sticky_index; i < bucket_walk_end; i++)
    {
        b = clib_bihash_get_bucket_8_8 (sticky_ht, i);
        if (clib_bihash_bucket_is_empty_8_8 (b))
            continue;

        v = clib_bihash_get_value_8_8 (sticky_ht, b->offset);
        for (j = 0; j < (1 << b->log2_pages); j++)
        {
            for (k = 0; k < (sizeof(v->kvp) / sizeof(clib_bihash_kv_8_8_t)); k++) 
            {
                if (clib_bihash_is_free_8_8 (&v->kvp[k])) continue;

                if (clib_u32_loop_gt(lb_time_now, lb_kv->lb_value.timeout)) continue;

                lb_kv = (lb_sticky_kv_t *)&v->kvp[k];
                vip = pool_elt_at_index(lbm->vips, lb_kv->lb_key.vip_index);

                lb_ha_sync_event_sticky_session_notify(vm->thread_index, LB_HA_OP_ADD_FORCE, 
                                                       vip, lb_kv->lb_key.hash, 
                                                       &lbm->ass[lb_kv->lb_value.asindex].address, 
                                                       lb_kv->lb_value.timeout - lb_time_now);
            }
            v++;
        }
    }

    ctx->snapshot_sticky_index = i;

    if (ctx->snapshot_sticky_index >= sticky_ht->nbuckets)
    {
        lb_ha_sync_ctx.flag &= ~LB_HA_SYNC_CTX_FLAG_SNAPSHOT_STICKY_ACT;
    }
}

static_always_inline 
void generate_lb_vip_snat_table_snapshot(vlib_main_t *vm, lb_ha_sync_ctx_t *ctx)
{
    lb_main_t *lbm = &lb_main;

    u32 lb_time_now = lb_hash_time_now (vm);

    uword pool_active_num = pool_elts(lbm->vip_snat_mappings);
    uword pool_max_num = pool_max_len(lbm->vip_snat_mappings);

    if (PREDICT_FALSE (pool_active_num == 0))
    {
        ctx->flag &= ~LB_HA_SYNC_CTX_FLAG_SNAPSHOT_VIP_SNAT_ACT;
        return;
    }

    uword i;

    lb_vip_t *vip;
    lb_vip_snat_mapping_t *flow;

    uword pool_walk_end = (pool_max_num >> LB_HAS_SYNC_SNAPSHOT_BUCKET_WALK_SCALING);
    pool_walk_end = ctx->snapshot_vip_snat_index + pool_walk_end > 0 ? pool_walk_end : pool_max_num;
    pool_walk_end = pool_walk_end < pool_max_num ? pool_walk_end : pool_max_num;

    lb_get_writer_lock();

    pool_foreach_stepping_index(i, ctx->snapshot_vip_snat_index, pool_walk_end, lbm->vip_snat_mappings)
    {
        flow = pool_elt_at_index (lbm->vip_snat_mappings, i);

        if (clib_u32_loop_gt(lb_time_now, flow->timeout)) continue;

        vip = pool_elt_at_index(lbm->vips, flow->vip_index);

        lb_ha_sync_event_vip_snat_session_notify(vm->thread_index, LB_HA_OP_ADD_FORCE,
                vip, flow, flow->timeout - lb_time_now);

    }
    ctx->snapshot_vip_snat_index = i;

    lb_put_writer_lock();

    if (ctx->snapshot_vip_snat_index >= pool_max_num)
    {
        ctx->flag &= ~LB_HA_SYNC_CTX_FLAG_SNAPSHOT_VIP_SNAT_ACT;
    }
}

static uword
lb_ha_sync_snapshot_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    uword event_type = 0, *event_data = NULL;

    f64 cpu_cps = vm->clib_time.clocks_per_second;

    u64 max_timer_wait_interval = cpu_cps / LB_HA_SYNC_SNAPSHOT_PROCESS_DEFAULT_FREQUENCY;

    while (1)
    {
        /* Wait for Godot... */
        if (lb_ha_sync_snapshot_act(lb_ha_sync_ctx.flag))
        {
            vlib_process_wait_for_event_or_clock (vm, (max_timer_wait_interval / cpu_cps));
        }
        else
        {
            vlib_process_wait_for_event (vm);
        }

        if(LB_CHECK_HA_SYNC) continue;

        event_type = vlib_process_get_events (vm, &event_data);

        if (event_type == LB_HA_SYNC_SNAPSHOT_PROCESS_RESTART)
        {
            lb_ha_sync_ctx.flag |= LB_HA_SYNC_CTX_FLAG_SNAPSHOT_STICKY_ACT;
            lb_ha_sync_ctx.flag |= LB_HA_SYNC_CTX_FLAG_SNAPSHOT_VIP_SNAT_ACT;
        }

        /*
         * snapshot generate 
         */
        generate_lb_sticky_table_snapshot(vm, &lb_ha_sync_ctx);
        generate_lb_vip_snat_table_snapshot(vm, &lb_ha_sync_ctx);

        vec_reset_length (event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE (lb_ha_sync_snapshot_process_node) = {
  .function = lb_ha_sync_snapshot_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lb-ha-sync-snapshot-process",
  .n_next_nodes = 0,
  .next_nodes = {},
};

static_always_inline void
lb_ha_sync_apply_sticky_session_proc(lb_ha_sync_event_sticky_session_t *event)
{
#if LB_HASH_SYNC_DEBUG
    u8 *s = 0;
    s = format(s, "Header: \n%U", format_lb_ha_sync_header_format, &event->header);
    s = format(s, "Data: \n%U", format_lb_ha_sync_stick_format, &event->data);
    clib_warning("%s", s);
    vec_free(s);
#endif
    vlib_main_t *vm = vlib_get_main();

    lb_main_t *lbm = &lb_main;
    lb_vip_t *vip;
    lb_as_t *as;
    u32 *asi;
    u32 vip_index = (~0);
    u32 as_index = (~0);

    lb_sticky_kv_t kv;

    u32 lb_time = lb_hash_time_now (vm);

    lb_ha_sync_header_t *header  = &event->header;
    lb_ha_sync_stick_table_data_t *data  = &event->data;

    u32 vrf_id = clib_net_to_host_u32(data->table_id);

    //Extract key to obtain VIP index
    ip46_prefix_normalize(&data->prefix, data->plen);
    pool_foreach (vip, lbm->vips) 
    {
        if ((vip->flags & LB_AS_FLAGS_USED) &&
             vip->type == data->type &&
             vip->vrf_id == vrf_id && 
             vip->plen == data->plen &&
             vip->prefix.as_u64[0] == data->prefix.as_u64[0] && 
             vip->prefix.as_u64[1] == data->prefix.as_u64[1] &&
             vip->protocol == data->protocol &&
             vip->port == clib_net_to_host_u16(data->l4_port))
        {
            vip_index = vip - lbm->vips;
            break;
        }
    }

    if (vip_index == (~0))
    {
        clib_warning("Lb ha-sync sticky table not found vip : skip it!");
        return ;
    }


    //Obtain AS index based on AS address
    ip46_type_t type = lb_encap_is_ip4(vip)?IP46_TYPE_IP4:IP46_TYPE_IP6;
    if (ip46_address_type(&data->address) != type) {
        clib_warning("Lb ha-sync sticky table as address type invalid : skip it!");
        return;
    }
    pool_foreach (asi, vip->as_indexes) 
    {
        as = &lbm->ass[*asi];
        if (as->vip_index == (vip_index) &&
            as->address.as_u64[0] == data->address.as_u64[0] &&
            as->address.as_u64[1] == data->address.as_u64[1] &&
            as->flags & LB_AS_FLAGS_USED)
        {
            as_index = as - lbm->ass;
            break;
        }
    }

    if (as_index == (~0))
    {
        clib_warning("Lb ha-sync sticky table not found vip as : skip it!");
        return ;
    }

    //Construct a key-value (KV) pair of sticky table
    kv.lb_key.hash = clib_net_to_host_u32(data->hash);
    kv.lb_key.vip_index = vip_index;
    kv.lb_value.asindex = as_index;
    kv.lb_value.timeout = clib_net_to_host_u32(data->timeout) + lb_time;

    
    clib_bihash_8_8_t *sticky_ht = &lbm->sticky_ht;
    u64 sticky_hash = clib_bihash_hash_8_8((clib_bihash_kv_8_8_t *)&kv);
    switch (header->event_op)
    {
    case LB_HA_OP_ADD:
    case LB_HA_OP_ADD_FORCE:
        {
            lb_sticky_kv_t vv;
            //check kv exists
            if (!clib_bihash_search_inline_2_with_hash_8_8(sticky_ht, sticky_hash, (clib_bihash_kv_8_8_t *)&kv, (clib_bihash_kv_8_8_t *)&vv))
            {
                //update timeout
                vv.lb_value.timeout = lb_time + data->timeout;
                //update sticky
                clib_bihash_add_del_with_hash_8_8(sticky_ht, (clib_bihash_kv_8_8_t *)&vv, sticky_hash, 1);
            }
            else
            {
                lb_sticky_is_idle_ctx_t ctx;
                ctx.lb_time_now = lb_time;
                ctx.thread_index = header->event_thread_id;
                if (clib_bihash_add_or_overwrite_stale_8_8 (
                          sticky_ht, (clib_bihash_kv_8_8_t * )&kv,
                          lb_sticky_is_idle_cb, &ctx))
                {
                    clib_warning("Lb ha-sync stick table add entry failed!!");
                }
                else
                {
                    clib_atomic_fetch_add (&lbm->as_refcount[as_index], 1);
                }
            }
        }
        break;
    case LB_HA_OP_DEL:
    case LB_HA_OP_DEL_FORCE:
        {
            lb_sticky_kv_t vv;
            //check kv exists
            if (!clib_bihash_search_inline_2_with_hash_8_8(sticky_ht, sticky_hash, (clib_bihash_kv_8_8_t *)&kv, (clib_bihash_kv_8_8_t *)&vv))
            {
                //del entry
                clib_bihash_add_del_with_hash_8_8(sticky_ht, (clib_bihash_kv_8_8_t *)&kv, sticky_hash, 0);
            }
#if LB_HASH_SYNC_DEBUG
            else
            {
                clib_warning("Lb ha-sync stick table del entry failed : entry not found!!");
            }
#endif
        }
        break;
    case LB_HA_OP_UPDATE:
    case LB_HA_OP_REFRESH:
        clib_warning("LB ha-sync sticky table current not support op %u", header->event_op);
        break;
    }

    return;
}

static_always_inline void
lb_ha_sync_vip_snat_sesson_add(lb_ha_sync_vip_snat_session_data_t *data,
                               lb_vip_t *vip, 
                               lb_vip_snat_addresses_pool_t *snat_addresses,
                               lb_vip_snat_address_t *address,
                               u32 outside_vrf_id, u32 vrf_id, int is_force)
{
    lb_main_t *lbm = &lb_main;
    vlib_main_t *vm = vlib_get_main();
    u32 lb_time_now = lb_hash_time_now (vm);

    lb_snat_vip_key_t key0, key1;
    clib_bihash_kv_16_8_t kv0, kv1, vv0, vv1;
    int search_rv0 = 0,  search_rv1 = 0;

    lb_vip_snat_mapping_t *flow = NULL;
    u32 flow_index = (~0);

    u32 outside_fib_index = fib_table_find (lb_vip_is_ip4(data->type) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, outside_vrf_id);
    u32 fib_index = fib_table_find (lb_vip_encap_is_ip4(data->type) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, vrf_id);

    u32 lb_proto = lb_ip_proto_to_nat_proto(data->protocol);
    u16 mapping_port = clib_net_to_host_u16(data->port);

    //key of flow to mapping downlink snat4 table
    clib_memset(&key0, 0, sizeof(key0));
    key0.addr.as_u32 = data->outside_ip.ip4.as_u32;
    key0.port = data->outside_port;
    key0.protocol = data->protocol;
    key0.fib_index = outside_fib_index;

    kv0.key[0] = key0.as_u64[0];
    kv0.key[1] = key0.as_u64[1];

    //key of flow to mapping uplink snat4 table
    clib_memset(&key1, 0, sizeof(key1));
    key1.addr.as_u32 = data->ip.ip4.as_u32;
    key1.port = data->port;
    key1.protocol = data->protocol;
    key1.fib_index = fib_index;

    kv1.key[0] = key1.as_u64[0];
    kv1.key[1] = key1.as_u64[1];

    search_rv0 = clib_bihash_search_16_8 (&lbm->mapping_by_downlink_snat4, &kv0, &vv0);
    search_rv1 = clib_bihash_search_16_8 (&lbm->mapping_by_uplink_dnat4, &kv1, &vv1);

    if (search_rv0 && search_rv1)
    {
        //check mapping port and direct sync
        lb_get_vip_nat_address_lock(address);

        if (clib_bitmap_get (address->busy_port_bitmap[lb_proto], mapping_port))
        {
            clib_warning("Lb ha-sync vip snat table snat mapping address pool address port is used!");
            lb_put_vip_nat_address_lock(address);
            return;
        }

        address->busy_port_bitmap[lb_proto] = clib_bitmap_set (address->busy_port_bitmap[lb_proto], mapping_port, 1);
        address->busy_ports[lb_proto]++;

        lb_put_vip_nat_address_lock(address);

        lb_get_writer_lock();

        pool_get_zero(lbm->vip_snat_mappings, flow);

        lb_put_writer_lock();

        flow_index = flow - lbm->vip_snat_mappings;

        address->flow_index[lb_proto][mapping_port] = flow_index;

        flow->ip.ip4 = data->ip.ip4;
        flow->outside_ip.ip4 = data->outside_ip.ip4;
        flow->port = data->port;
        flow->outside_port = data->outside_port;
        flow->fib_index = fib_index;
        flow->outside_fib_index = outside_fib_index;
        flow->protocol = data->protocol;
        flow->vip_index = vip - lbm->vips;
        flow->timeout = lb_time_now + clib_net_to_host_u32(data->timeout);

        kv0.value = flow_index;
        kv1.value = flow_index;
        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv0, 1))
            clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");

        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_uplink_dnat4, &kv1, 1))
            clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");
    }
    else if ( !search_rv0 && !search_rv1 && vv0.value == vv1.value)
    {
        //update flow timeout
        flow = pool_elt_at_index(lbm->vip_snat_mappings, vv0.value);
        flow->timeout = lb_time_now + clib_net_to_host_u32(data->timeout);
    }
    else
    {
        if (!is_force)
        {
            clib_warning ("Lb vip-snat vip-mapping snat4 table out of sync : hash diff skip it");
            return;
        }

        if (!search_rv0 && search_rv1)
        {
            /*
             * downlink vip snat found 
             * uplink as dnat not found
             * it indicates that "outside" already has a corresponding Snat mapping, 
             * but the mapping is not using what is expected
             * 
             * if not force: should ignore this sync session
             * if force : We need to clear the existing flow and use sync session, just as if it timed out
             *
             */
            lb_vip_snat_address_t *tmp_address = NULL;
            u16 tmp_mapping_port = 0;

            //Priority occupation mapping port
            lb_get_vip_nat_address_lock(address);

            if (clib_bitmap_get (address->busy_port_bitmap[lb_proto], mapping_port))
            {
                clib_warning("Lb ha-sync vip snat table snat mapping address pool address port is used! Insufficient granularity of locking!");
                lb_put_vip_nat_address_lock(address);
                return;
            }

            address->busy_port_bitmap[lb_proto] = clib_bitmap_set (address->busy_port_bitmap[lb_proto], mapping_port, 1);
            address->busy_ports[lb_proto]++;
            address->flow_index[lb_proto][mapping_port] = vv0.value;

            lb_put_vip_nat_address_lock(address);

            //Remove old mapping ref
            flow = pool_elt_at_index(lbm->vip_snat_mappings, vv0.value);
            vec_foreach(tmp_address, snat_addresses->addresses)
            {
                if (tmp_address->addr.as_u32 == flow->ip.ip4.as_u32)
                {
                    tmp_mapping_port = clib_net_to_host_u16(flow->port);

                    lb_get_vip_nat_address_lock(tmp_address);

                    tmp_address->busy_port_bitmap[lb_proto] = clib_bitmap_set (tmp_address->busy_port_bitmap[lb_proto], tmp_mapping_port, 0);
                    tmp_address->busy_ports[lb_proto]--;
                    tmp_address->flow_index[lb_proto][tmp_mapping_port] = (~0);

                    lb_put_vip_nat_address_lock(tmp_address);
                    break;
                }
            }

            //update old flow
            flow->ip.ip4 = data->ip.ip4;
            flow->outside_ip.ip4 = data->outside_ip.ip4;
            flow->port = data->port;
            flow->outside_port = data->outside_port;
            flow->fib_index = fib_index;
            flow->outside_fib_index = outside_fib_index;
            flow->protocol = data->protocol;
            flow->vip_index = vip - lbm->vips;
            flow->timeout = lb_time_now + data->timeout;

            kv0.value = flow_index;
            kv1.value = flow_index;
            if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv0, 1))
                clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");

            if (clib_bihash_add_del_16_8 (&lbm->mapping_by_uplink_dnat4, &kv1, 1))
                clib_warning ("Lb vip-snat vip-mapping snat4 table add failed");
        }
        else if (search_rv0 && !search_rv1)
        {
            /*
             * downlink vip snat not found 
             * uplink as dnat found
             * In this scenario, it indicates that the corresponding (address, port) in snat pool of the VIP
             * are being utilized by other outside (address, port)
             * 
             * if not force: should ignore this sync session
             * if force : 
             *    if force update flow, it may trigger more updates. 
             *    (Just like when a port that requires mandatory updates is 
             *    being used by a third party, we have to update the third party, 
             *    but this is not something that shouldn't be done)
             *
             * So, we should ignore "force" here
             */
            clib_warning ("Lb vip-snat vip-mapping snat4 table out of sync (force): downlink hash diff skip it");
            return;
        }
        else
        {
            /*
             * downlink vip snat found 
             * uplink as dnat found
             * But their flow entries are not consistent.
             *
             * if not force: should ignore this sync session
             * if force :
             *    if force update flow, it may trigger more updates. 
             *    (Just like when a port that requires mandatory updates is 
             *    being used by a third party, we have to update the third party, 
             *    but this is not something that shouldn't be done)
             *
             * So, we should ignore "force" here
             */
            clib_warning ("Lb vip-snat vip-mapping snat4 table out of sync (force): uplink/downlink hash diff skip it");
            return;
        }
    }
    return;
}

static_always_inline void
lb_ha_sync_vip_snat_sesson_del(lb_ha_sync_vip_snat_session_data_t *data,
                               lb_vip_t *vip, 
                               lb_vip_snat_addresses_pool_t *snat_addresses,
                               lb_vip_snat_address_t *address,
                               u32 outside_vrf_id, u32 vrf_id, int is_force)
{
    lb_main_t *lbm = &lb_main;
    lb_snat_vip_key_t key0, key1;
    clib_bihash_kv_16_8_t kv0, kv1, vv0, vv1;
    int search_rv0 = 0,  search_rv1 = 0;

    lb_vip_snat_mapping_t *flow = NULL;

    u32 outside_fib_index = fib_table_find (lb_vip_is_ip4(data->type) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, outside_vrf_id);
    u32 fib_index = fib_table_find (lb_vip_encap_is_ip4(data->type) ? FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6, vrf_id);

    u32 lb_proto = lb_ip_proto_to_nat_proto(data->protocol);
    u16 mapping_port = clib_net_to_host_u16(data->port);

    //key of flow to mapping downlink snat4 table
    clib_memset(&key0, 0, sizeof(key0));
    key0.addr.as_u32 = data->outside_ip.ip4.as_u32;
    key0.port = data->outside_port;
    key0.protocol = data->protocol;
    key0.fib_index = outside_fib_index;

    kv0.key[0] = key0.as_u64[0];
    kv0.key[1] = key0.as_u64[1];

    //key of flow to mapping uplink snat4 table
    clib_memset(&key1, 0, sizeof(key1));
    key1.addr.as_u32 = data->ip.ip4.as_u32;
    key1.port = data->port;
    key1.protocol = data->protocol;
    key1.fib_index = fib_index;

    kv1.key[0] = key1.as_u64[0];
    kv1.key[1] = key1.as_u64[1];

    search_rv0 = clib_bihash_search_16_8 (&lbm->mapping_by_downlink_snat4, &kv0, &vv0);
    search_rv1 = clib_bihash_search_16_8 (&lbm->mapping_by_uplink_dnat4, &kv1, &vv1);

    if (!search_rv0 && !search_rv1 && vv0.value == vv1.value)
    {
        flow = pool_elt_at_index(lbm->vip_snat_mappings, vv0.value);

        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &vv0, 0))
            clib_warning ("Lb vip-snat vip-mapping snat4 table del failed");

        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_uplink_dnat4, &vv1, 0))
            clib_warning ("Lb vip-snat vip-mapping snat4 table del failed");

        lb_get_writer_lock();

        pool_put(lbm->vip_snat_mappings, flow);

        lb_put_writer_lock();

        address->flow_index[lb_proto][mapping_port] = (~0);

        lb_get_vip_nat_address_lock(address);

        address->busy_port_bitmap[lb_proto] = clib_bitmap_set (address->busy_port_bitmap[lb_proto], mapping_port, 0);
        address->busy_ports[lb_proto]--;

        lb_put_vip_nat_address_lock(address);
    }
    else if ((!search_rv0 && search_rv1) || (!search_rv0 && !search_rv1))
    {
        clib_warning("Lb ha-sync vip snat table downlink not same!");

        /*
         * downlink vip snat found 
         * uplink as dnat not found
         * it indicates that "outside" already has a corresponding Snat mapping, 
         * but the mapping is not using what is expected
         * 
         * if not force: should ignore this sync session
         * if force :
         *    We only need to delete the downlink vip snat flows on the "outside" side.
         *
         */

        /*
         * downlink vip snat found 
         * uplink as dnat found
         * But their flow entries are not consistent.
         *
         * if not force: should ignore this sync session
         * if force :
         *    We only need to delete the downlink vip snat flows on the "outside" side.
         *
         */
        if (!is_force)

        {
            clib_warning("Lb ha-sync vip snat table downlink flow not same : skip it!");
            return;
        }

        lb_vip_snat_address_t *tmp_address = NULL;
        u16 tmp_mapping_port = 0;

        key1.addr.as_u32 = flow->ip.ip4.as_u32;
        key1.port = flow->port;
        key1.fib_index = flow->fib_index;

        kv1.key[0] = key1.as_u64[0];
        kv1.key[1] = key1.as_u64[1];

        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv0, 0))
            clib_warning ("Lb vip-snat vip-mapping snat4 table del failed");

        if (clib_bihash_add_del_16_8 (&lbm->mapping_by_downlink_snat4, &kv1, 0))
            clib_warning ("Lb vip-snat vip-mapping snat4 table del failed");

        //Remove old mapping ref
        flow = pool_elt_at_index(lbm->vip_snat_mappings, vv0.value);
        vec_foreach(tmp_address, snat_addresses->addresses)
        {
            if (tmp_address->addr.as_u32 == flow->ip.ip4.as_u32)
            {
                tmp_mapping_port = clib_net_to_host_u16(flow->port);

                lb_get_vip_nat_address_lock(tmp_address);

                tmp_address->busy_port_bitmap[lb_proto] = clib_bitmap_set (tmp_address->busy_port_bitmap[lb_proto], tmp_mapping_port, 0);
                tmp_address->busy_ports[lb_proto]--;
                tmp_address->flow_index[lb_proto][tmp_mapping_port] = (~0);

                lb_put_vip_nat_address_lock(tmp_address);
                break;
            }
        }

        lb_get_writer_lock();

        pool_put(lbm->vip_snat_mappings, flow);

        lb_put_writer_lock();
    }
    else if (search_rv0 && !search_rv1)
    {
        /*
         * downlink vip snat not found 
         * uplink as dnat found
         * In this scenario, it indicates that the corresponding (address, port) in snat pool of the VIP
         * are being utilized by other outside (address, port)
         * 
         * For delete session: We can skip it directly
         */
        clib_warning("Lb ha-syn vip snat table session (outside) not found : skip it!");
    }
    else 
    {
        clib_warning("Lb ha-syn vip snat table session not found : skip it!");
    }
    return;
}

static_always_inline void
lb_ha_sync_apply_vip_snat_session_proc(lb_ha_sync_event_vip_snat_session_t *event)
{

#if LB_HASH_SYNC_DEBUG
    u8 *s = 0;
    s = format(s, "Header: \n%U", format_lb_ha_sync_header_format, &event->header);
    s = format(s, "Data: \n%U", format_lb_ha_sync_vip_snat_format, &event->data);
    clib_warning("%s", s);
    vec_free(s);
#endif

    lb_main_t *lbm = &lb_main;
    lb_vip_t *vip;
    u32 vip_index = (~0);

    lb_vip_snat_addresses_pool_t *snat_addresses = NULL;
    lb_vip_snat_address_t *address = NULL;
    u8 is_found_snat_address = 0;

    lb_ha_sync_header_t *header  = &event->header;
    lb_ha_sync_vip_snat_session_data_t *data  = &event->data;

    u32 outside_vrf_id = clib_net_to_host_u32(data->outside_table_id);
    u32 vrf_id = clib_net_to_host_u32(data->table_id);


    //Extract key to obtain VIP index
    ip46_prefix_normalize(&data->prefix, data->plen);
    pool_foreach (vip, lbm->vips) 
    {
        if ((vip->flags & LB_AS_FLAGS_USED) &&
             vip->type == data->type &&
             vip->vrf_id == outside_vrf_id && 
             vip->plen == data->plen &&
             vip->prefix.as_u64[0] == data->prefix.as_u64[0] && 
             vip->prefix.as_u64[1] == data->prefix.as_u64[1] &&
             vip->protocol == data->protocol &&
             vip->port == clib_net_to_host_u16(data->l4_port))
        {
            vip_index = vip - lbm->vips;
            break;
        }
    }

    if (vip_index == (~0))
    {
        clib_warning("Lb ha-sync vip snat table not found vip : skip it!");
        return;
    }

    if (!lb_vip_is_double_nat44(vip))
    {
        clib_warning("Lb ha-sync vip snat table : vip snat not enabled skip it!");
        return;
    }

    if (data->ip_is_ipv6)
    {
        clib_warning("Lb ha-sync vip snat table : snat mapping must be ipv4 skip it!");
        return;
    }

    if (vip->type != LB_VIP_TYPE_IP4_NAT4)
    {
        clib_warning("Lb ha-sync vip snat table : vip type must be IP4 NAT4!");
        return;
    }

    //Extract the mapping IP and obtain the address from the address
    snat_addresses = pool_elt_at_index(lbm->vip_snat_pool, vip->vip_snat_pool_index);

    if(!vec_len (snat_addresses->addresses))
    {
        clib_warning("Lb ha-sync vip snat table : snat mapping address pool not addresses skip it!");
        return;
    }

    vec_foreach(address, snat_addresses->addresses)
    {
        if (address->addr.as_u32 == data->ip.ip4.as_u32)
        {
            is_found_snat_address = 1;
            break;
        }
    }

    if (!is_found_snat_address)
    {
        clib_warning("Lb ha-sync vip snat table : snat mapping address pool address not found skip it!");
        return;
    }

    switch (header->event_op)
    {
    case LB_HA_OP_ADD:
        {
            lb_ha_sync_vip_snat_sesson_add(data, vip, snat_addresses, address, outside_vrf_id, vrf_id, 0);
        }
        break;
    case LB_HA_OP_ADD_FORCE:
        {
            lb_ha_sync_vip_snat_sesson_add(data, vip, snat_addresses, address, outside_vrf_id, vrf_id, 1);
        }
        break;
    case LB_HA_OP_DEL:
        {
            lb_ha_sync_vip_snat_sesson_del(data, vip, snat_addresses, address, outside_vrf_id, vrf_id, 0);
        }
    case LB_HA_OP_DEL_FORCE:
        {
            lb_ha_sync_vip_snat_sesson_del(data, vip, snat_addresses, address, outside_vrf_id, vrf_id, 1);
        }
        break;
    case LB_HA_OP_UPDATE:
    case LB_HA_OP_REFRESH:
        clib_warning("LB ha-sync sticky table current not support op %u", header->event_op);
        break;
    }

    return;
}

static void
lb_ha_sync_session_apply_cb (u32 app_type, void *ctx, u8 *session, u16 session_len)
{
    ASSERT(app_type == HA_SYNC_APP_LB);

    lb_ha_sync_header_t *header = (lb_ha_sync_header_t *)session;

    if (header->event_type >= LB_HA_TYPE_VALID)
    {
        clib_warning("lb ha sync received undefined type %d", header->event_type);
        return;
    }

    if (header->event_type == LB_HA_OP_NONE)
    {
        /*
         * current do nothing 
         */
        return;
    }

    switch(header->event_type)
    {
    case LB_HA_TYPE_STICK_TABLE:
        if (session_len < sizeof(lb_ha_sync_event_sticky_session_t))
        {
            clib_warning("lb ha sync received stick event length too small (current %u expected %u)", session_len, sizeof(lb_ha_sync_event_sticky_session_t));
            return;
        }
        lb_ha_sync_apply_sticky_session_proc((lb_ha_sync_event_sticky_session_t *)session);
        break;
    case LB_HA_TYPE_VIP_SNAT_SESSION:
        if (session_len < sizeof(lb_ha_sync_event_vip_snat_session_t))
        {
            clib_warning("lb ha sync received vip snat event length too small (current %u expected %u)", session_len, sizeof(lb_ha_sync_event_vip_snat_session_t));
            return;
        }
        lb_ha_sync_apply_vip_snat_session_proc((lb_ha_sync_event_vip_snat_session_t *)session);
        break;
    }
    return;
}

static ha_sync_session_registration_t lb_ha_sync_registration = {
    .app_type = HA_SYNC_APP_LB,
    .context = &lb_ha_sync_ctx,
    .snapshot_send_cb = lb_ha_sync_snapshot_send_cb,
    .session_apply_cb = lb_ha_sync_session_apply_cb,
    .snapshot_mode = HA_SYNC_SNAPSHOT_MODE_SINGLE,
};

static int *ha_sync_register_session_application_ptr;
static int *ha_sync_unregister_session_application_ptr;
void *ha_sync_per_thread_buffer_add_ptr;

int lb_ha_sync_register (void)
{
    ha_sync_register_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_register_session_application");

    ha_sync_per_thread_buffer_add_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_per_thread_buffer_add");

    if(ha_sync_register_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        lb_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    if(ha_sync_per_thread_buffer_add_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_per_thread_buffer_add is not found");
        lb_ha_sync_ctx.ha_sync_plugin_found = 0;
        return 0;
    }

    lb_ha_sync_ctx.ha_sync_plugin_found = 1;


    if (((__typeof__ (ha_sync_register_session_application) *)ha_sync_register_session_application_ptr) (&lb_ha_sync_registration))
    {
        clib_warning ("lb register ha sync failed");
        lb_ha_sync_ctx.ha_sync_register = 0;
        return 0;
    }

    lb_ha_sync_ctx.ha_sync_register = 1;
    return 0;
}

void lb_ha_sync_unregister (void)
{
    ha_sync_unregister_session_application_ptr =
        vlib_get_plugin_symbol ("ha_sync_plugin.so", "ha_sync_unregister_session_application");

    if(ha_sync_register_session_application_ptr == NULL)
    {
        clib_warning ("ha_sync_plugin.so ha_sync_unregister_session_application is not found");
        lb_ha_sync_ctx.ha_sync_plugin_found = 0;
    }

    lb_ha_sync_ctx.ha_sync_plugin_found = 1;

    if (((__typeof__ (ha_sync_unregister_session_application) *)ha_sync_unregister_session_application_ptr) (HA_SYNC_APP_LB))
    {
        clib_warning ("lb unregister ha sync failed");
    }
    lb_ha_sync_ctx.ha_sync_register = 0;
}
