/**
 * @file
 * @brief NAT46 DB
 */
#include <nat/nat46.h>
#include <nat/nat46_db.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_inlines.h>
#include <nat/nat_syslog.h>
#include <vnet/fib/fib_table.h>

int
nat46_db_init (u32 max_st_per_worker, nat46_db_t * db, u32 bib_buckets, u32 bib_memory_size,
        u32 st_buckets, u32 st_memory_size,
        nat46_db_free_addr_port_function_t free_addr_port_cb)
{
    clib_bihash_init_24_8 (&db->bib.in2out, "46-bib-in2out", bib_buckets,
            bib_memory_size);

    clib_bihash_init_24_8 (&db->bib.out2in, "46-bib-out2in", bib_buckets,
            bib_memory_size);

    clib_bihash_init_48_8 (&db->st.in2out, "46-st-in2out", st_buckets,
            st_memory_size);

    clib_bihash_init_48_8 (&db->st.out2in, "46-st-out2in", st_buckets,
            st_memory_size);

    db->free_addr_port_cb = free_addr_port_cb;
    db->bib.limit = max_st_per_worker;
    db->bib.bib_entries_num = 0;
    db->st.limit = max_st_per_worker;
    db->st.st_entries_num = 0;
    db->addr_free = 0;

#ifndef USER_WALK_EXPIRE_FLAG
    db->timers_per_worker = clib_mem_alloc (sizeof (TWT (tw_timer_wheel)));
    tw_timer_wheel_init_1t_3w_64sl (db->timers_per_worker, NULL, 1.0, NAT64_PER_WORKER_MAX_ST);
#endif

    return 0;
}

void 
nat46_submit_or_update_session_timer(nat46_db_t * db, nat46_db_st_entry_t *ste)
{
    u32 timeout = 0;
    /* 
     * In tw_timer, we can actually set the type of timer task
     * like xt_3w_64, x represents the number of task types
     * It occupies the high byte
     * For esay, here we write directly on the submitted task
     *
     * max type is 0b11
     *
     * submit index  = session_index | _st_db_index << 30
     */
    u32 session_index;
    u32 _st_db_index;
    u32 submit_index;

    switch (ip_proto_to_snat_proto (ste->proto))
    {
    case SNAT_PROTOCOL_TCP: 
        switch (ste->tcp_state)
        { 
        case NAT46_TCP_STATE_V4_INIT: 
        case NAT46_TCP_STATE_V6_INIT: 
        case NAT46_TCP_STATE_V4_FIN_RCV: 
        case NAT46_TCP_STATE_V6_FIN_RCV: 
        case NAT46_TCP_STATE_V6_FIN_V4_FIN_RCV: 
        case NAT46_TCP_STATE_TRANS: 
            timeout = nat46_get_tcp_trans_timeout(); 
            break; 
        case NAT46_TCP_STATE_ESTABLISHED: 
            timeout = nat46_get_tcp_est_timeout(); 
            break; 
        default: 
            timeout = nat46_get_tcp_trans_timeout(); 
            break; 
        } 
        _st_db_index = SNAT_PROTOCOL_TCP; 
        session_index = ste - db->st._tcp_st; 
        submit_index = session_index | _st_db_index << 30; 
        break;
    case SNAT_PROTOCOL_UDP: 
        timeout = nat46_get_udp_timeout(); 
        _st_db_index = SNAT_PROTOCOL_UDP; 
        session_index = ste - db->st._udp_st; 
        submit_index = session_index | _st_db_index << 30; 
        break;
    case SNAT_PROTOCOL_ICMP:
        timeout = nat46_get_udp_timeout(); 
        _st_db_index = SNAT_PROTOCOL_ICMP; 
        session_index = ste - db->st._icmp_st; 
        submit_index = session_index | _st_db_index << 30; 
        break;
    default:
        timeout = nat46_get_udp_timeout();
        _st_db_index = 3;
        session_index = ste - db->st._unk_proto_st; 
        submit_index = session_index | _st_db_index << 30;
        break;
    }
    //update
    if (ste->session_timer_handle != 0 &&
        !tw_timer_handle_is_free_1t_3w_64sl(db->timers_per_worker, ste->session_timer_handle))
    {
        tw_timer_update_1t_3w_64sl(db->timers_per_worker, ste->session_timer_handle, timeout);
    }
    else
    {
        ste->session_timer_handle = tw_timer_start_1t_3w_64sl(
                db->timers_per_worker, submit_index, 0, timeout);
    }
}

void 
nat46_delete_session_timer(nat46_db_t * db, nat46_db_st_entry_t *ste)
{
    if (ste->session_timer_handle != 0 &&
        !tw_timer_handle_is_free_1t_3w_64sl(db->timers_per_worker, ste->session_timer_handle))
    {
        tw_timer_stop_1t_3w_64sl(db->timers_per_worker, ste->session_timer_handle);
    }
}

nat46_db_bib_entry_t *
nat46_db_bib_entry_create (u32 thread_index, nat46_db_t * db,
        ip4_address_t * in_addr,
        ip6_address_t * out_addr, 
        u16 in_port, u16 out_port, 
        u32 fib_index, u8 proto,
        u8 is_static)
{
    nat46_db_bib_entry_t *bibe;
    nat46_db_bib_entry_key_t bibe_key;
    clib_bihash_kv_24_8_t kv;
    fib_table_t *fib;

    if (db->bib.bib_entries_num >= db->bib.limit)
    {
        db->free_addr_port_cb (db, out_addr, out_port, proto);
        nat_ipfix_logging_max_bibs (thread_index, db->bib.limit);
        return 0;
    }

    /* create pool entry */
    switch (ip_proto_to_snat_proto (proto))
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        pool_get (db->bib._##n##_bib, bibe); \
        kv.value = bibe - db->bib._##n##_bib; \
        break;
        foreach_snat_protocol
#undef _
    default:
        pool_get (db->bib._unk_proto_bib, bibe);
        kv.value = bibe - db->bib._unk_proto_bib;
        break;
    }

    db->bib.bib_entries_num++;

    clib_memset (bibe, 0, sizeof (*bibe));
    bibe->in_addr.as_u32 = in_addr->as_u32;
    bibe->out_addr.as_u64[0] = out_addr->as_u64[0];
    bibe->out_addr.as_u64[1] = out_addr->as_u64[1];

    bibe->in_port = in_port;
    bibe->out_port = out_port;
    bibe->proto = proto;

    bibe->fib_index = fib_index;
    bibe->is_static = is_static;

    /* create hash lookup */
    clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
    bibe_key.addr.ip4.as_u32 = bibe->in_addr.as_u32;
    bibe_key.fib_index = bibe->fib_index;
    bibe_key.port = bibe->in_port;
    bibe_key.proto = bibe->proto;
    bibe_key.rsvd = 0;
    kv.key[0] = bibe_key.as_u64[0];
    kv.key[1] = bibe_key.as_u64[1];
    kv.key[2] = bibe_key.as_u64[2];
    clib_bihash_add_del_24_8 (&db->bib.in2out, &kv, 1);

    clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
    bibe_key.addr.ip6.as_u64[0] = bibe->out_addr.as_u64[0];
    bibe_key.addr.ip6.as_u64[1] = bibe->out_addr.as_u64[1];
    bibe_key.fib_index = 0;
    bibe_key.port = bibe->out_port;
    kv.key[0] = bibe_key.as_u64[0];
    kv.key[1] = bibe_key.as_u64[1];
    kv.key[2] = bibe_key.as_u64[2];
    clib_bihash_add_del_24_8 (&db->bib.out2in, &kv, 1);

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP4);
    nat_ipfix_logging_nat46_bib (thread_index, in_addr, out_addr, proto,
            in_port, out_port, fib->ft_table_id, 1);
    return bibe;
}

void
nat46_db_bib_entry_free (u32 thread_index, nat46_db_t * db,
        nat46_db_bib_entry_t * bibe)
{
    nat46_db_bib_entry_key_t bibe_key;
    clib_bihash_kv_24_8_t kv;
    nat46_db_bib_entry_t *bib;
    u32 *ste_to_be_free = 0, *ste_index, bibe_index;
    nat46_db_st_entry_t *st, *ste;
    fib_table_t *fib;

    switch (ip_proto_to_snat_proto (bibe->proto))
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        bib = db->bib._##n##_bib; \
        st = db->st._##n##_st; \
        break;
        foreach_snat_protocol
#undef _
    default:
        bib = db->bib._unk_proto_bib;
        st = db->st._unk_proto_st;
        break;
    }

    db->bib.bib_entries_num--;

    bibe_index = bibe - bib;

    /* delete ST entries for static BIB entry */
    if (bibe->is_static)
    {
        pool_foreach (ste, st, (
        {
            if (ste->bibe_index == bibe_index)
            vec_add1 (ste_to_be_free, ste - st);}
        ));

        vec_foreach (ste_index, ste_to_be_free)
            nat46_db_st_entry_free (thread_index, db, pool_elt_at_index (st, ste_index[0]));

        vec_free (ste_to_be_free);
    }

    /* delete hash lookup */
    clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
    bibe_key.addr.ip4.as_u32 = bibe->in_addr.as_u32;
    bibe_key.fib_index = bibe->fib_index;
    bibe_key.port = bibe->in_port;
    bibe_key.proto = bibe->proto;
    bibe_key.rsvd = 0;
    kv.key[0] = bibe_key.as_u64[0];
    kv.key[1] = bibe_key.as_u64[1];
    kv.key[2] = bibe_key.as_u64[2];
    clib_bihash_add_del_24_8 (&db->bib.in2out, &kv, 0);

    clib_memset (&bibe_key.addr, 0, sizeof (bibe_key.addr));
    bibe_key.addr.as_u64[0] = bibe->out_addr.as_u64[0];
    bibe_key.addr.as_u64[1] = bibe->out_addr.as_u64[1];
    bibe_key.fib_index = 0;
    bibe_key.port = bibe->out_port;
    kv.key[0] = bibe_key.as_u64[0];
    kv.key[1] = bibe_key.as_u64[1];
    kv.key[2] = bibe_key.as_u64[2];
    clib_bihash_add_del_24_8 (&db->bib.out2in, &kv, 0);

    if (!db->addr_free)
        db->free_addr_port_cb (db, &bibe->out_addr, bibe->out_port, bibe->proto);

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
    nat_ipfix_logging_nat46_bib (thread_index, &bibe->in_addr, &bibe->out_addr,
            bibe->proto, bibe->in_port, bibe->out_port,
            fib->ft_table_id, 0);

    /* delete from pool */
    pool_put (bib, bibe);

}

nat46_db_bib_entry_t *
nat46_db_bib_entry_find (nat46_db_t * db, ip46_address_t * addr, u16 port,
        u8 proto, u32 fib_index, u8 is_ip6)
{
    nat46_db_bib_entry_t *bibe = 0;
    nat46_db_bib_entry_key_t bibe_key;
    clib_bihash_kv_24_8_t kv, value;
    nat46_db_bib_entry_t *bib;

    switch (ip_proto_to_snat_proto (proto))
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        bib = db->bib._##n##_bib; \
        break;
        foreach_snat_protocol
#undef _
    default:
        bib = db->bib._unk_proto_bib;
        break;
    }

    bibe_key.addr.as_u64[0] = addr->as_u64[0];
    bibe_key.addr.as_u64[1] = addr->as_u64[1];
    bibe_key.fib_index = fib_index;
    bibe_key.port = port;
    bibe_key.proto = proto;
    bibe_key.rsvd = 0;

    kv.key[0] = bibe_key.as_u64[0];
    kv.key[1] = bibe_key.as_u64[1];
    kv.key[2] = bibe_key.as_u64[2];

    if (!clib_bihash_search_24_8
            (is_ip6 ? &db->bib.out2in : &db->bib.in2out, &kv, &value))
        bibe = pool_elt_at_index (bib, value.value);

    return bibe;
}

void
nat46_db_bib_walk (nat46_db_t * db, u8 proto,
        nat46_db_bib_walk_fn_t fn, void *ctx)
{
    nat46_db_bib_entry_t *bib, *bibe;

    if (proto == 255)
    {
#define _(N, i, n, s) \
        bib = db->bib._##n##_bib; \
        pool_foreach (bibe, bib, ({ \
                    if (fn (bibe, ctx)) \
                    return; \
                    }));
        foreach_snat_protocol
#undef _
        bib = db->bib._unk_proto_bib;
        pool_foreach (bibe, bib, ({
                    if (fn (bibe, ctx))
                        return;
                    }));
    }
    else
    {
        switch (ip_proto_to_snat_proto (proto))
        {
#define _(N, i, n, s) \
        case SNAT_PROTOCOL_##N: \
            bib = db->bib._##n##_bib; \
            break;
            foreach_snat_protocol
#undef _
        default:
                bib = db->bib._unk_proto_bib;
                break;
        }

        pool_foreach (bibe, bib,
        ({
         if (fn (bibe, ctx))
            return;
         }));
    }
}

nat46_db_bib_entry_t *
nat46_db_bib_entry_by_index (nat46_db_t * db, u8 proto, u32 bibe_index)
{
    nat46_db_bib_entry_t *bib;

    switch (ip_proto_to_snat_proto (proto))
    {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        bib = db->bib._##n##_bib; \
        break;
        foreach_snat_protocol
#undef _
    default:
        bib = db->bib._unk_proto_bib;
        break;
    }

    return pool_elt_at_index (bib, bibe_index);
}

void
nat46_db_st_walk (nat46_db_t * db, u8 proto,
        nat46_db_st_walk_fn_t fn, void *ctx)
{
    nat46_db_st_entry_t *st, *ste;

    if (proto == 255)
    {
#define _(N, i, n, s) \
        st = db->st._##n##_st; \
        pool_foreach (ste, st, ({ \
            if (fn (ste, ctx)) \
            return; \
        }));
        foreach_snat_protocol
#undef _
        st = db->st._unk_proto_st;
        pool_foreach (ste, st, ({
           if (fn (ste, ctx))
           return;
        }));
    }
    else
    {
        switch (ip_proto_to_snat_proto (proto))
        {
#define _(N, i, n, s) \
        case SNAT_PROTOCOL_##N: \
            st = db->st._##n##_st; \
            break;
            foreach_snat_protocol
#undef _
        default:
            st = db->st._unk_proto_st;
            break;
        }

        pool_foreach (ste, st, ({
            if (fn (ste, ctx))
            return;
        }));
    }
}

nat46_db_st_entry_t *
nat46_db_st_entry_create (u32 thread_index, nat46_db_t * db,
        nat46_db_bib_entry_t * bibe,
        ip4_address_t * in_r_addr,
        ip6_address_t * out_r_addr, 
        u16 r_port)
{
    nat46_db_st_entry_t *ste;
    nat46_db_bib_entry_t *bib;
    nat46_db_st_entry_key_t ste_key;
    clib_bihash_kv_48_8_t kv;
    fib_table_t *fib;

    if (db->st.st_entries_num >= db->st.limit)
    {
        nat_ipfix_logging_max_sessions (thread_index, db->st.limit);
        return 0;
    }

    /* create pool entry */
    switch (ip_proto_to_snat_proto (bibe->proto))
    {
        /* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        pool_get (db->st._##n##_st, ste); \
        kv.value = ste - db->st._##n##_st; \
        bib = db->bib._##n##_bib; \
        break;
        foreach_snat_protocol
#undef _
            /* *INDENT-ON* */
    default:
        pool_get (db->st._unk_proto_st, ste);
        kv.value = ste - db->st._unk_proto_st;
        bib = db->bib._unk_proto_bib;
        break;
    }

    db->st.st_entries_num++;

    clib_memset (ste, 0, sizeof (*ste));
    ste->in_r_addr.as_u32 = in_r_addr->as_u32;
    ste->out_r_addr.as_u64[0] = out_r_addr->as_u64[0];
    ste->out_r_addr.as_u64[1] = out_r_addr->as_u64[1];
    ste->r_port = r_port;
    ste->bibe_index = bibe - bib;
    ste->proto = bibe->proto;
    ste->worker_index = thread_index;

    /* increment session number for BIB entry */
    bibe->ses_num++;

    /* create hash lookup */
    clib_memset (&ste_key, 0, sizeof (ste_key));
    ste_key.l_addr.ip4.as_u32 = bibe->in_addr.as_u32;
    ste_key.r_addr.ip4.as_u32 = ste->in_r_addr.as_u32;
    ste_key.fib_index = bibe->fib_index;
    ste_key.l_port = bibe->in_port;
    ste_key.r_port = ste->r_port;
    ste_key.proto = ste->proto;
    kv.key[0] = ste_key.as_u64[0];
    kv.key[1] = ste_key.as_u64[1];
    kv.key[2] = ste_key.as_u64[2];
    kv.key[3] = ste_key.as_u64[3];
    kv.key[4] = ste_key.as_u64[4];
    kv.key[5] = ste_key.as_u64[5];
    clib_bihash_add_del_48_8 (&db->st.in2out, &kv, 1);

    clib_memset (&ste_key, 0, sizeof (ste_key));
    ste_key.l_addr.as_u64[0] = bibe->out_addr.as_u64[0];
    ste_key.l_addr.as_u64[1] = bibe->out_addr.as_u64[1];
    ste_key.r_addr.as_u64[0] = ste->out_r_addr.as_u64[0];
    ste_key.r_addr.as_u64[1] = ste->out_r_addr.as_u64[1];
    ste_key.l_port = bibe->out_port;
    ste_key.r_port = ste->r_port;
    ste_key.proto = ste->proto;
    kv.key[0] = ste_key.as_u64[0];
    kv.key[1] = ste_key.as_u64[1];
    kv.key[2] = ste_key.as_u64[2];
    kv.key[3] = ste_key.as_u64[3];
    kv.key[4] = ste_key.as_u64[4];
    kv.key[5] = ste_key.as_u64[5];
    clib_bihash_add_del_48_8 (&db->st.out2in, &kv, 1);

#ifndef USER_WALK_EXPIRE_FLAG
  /* session timer */
    nat46_submit_or_update_session_timer(db, ste);
#endif

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP4);
    nat_ipfix_logging_nat46_session (thread_index, &bibe->in_addr,
            &bibe->out_addr, bibe->proto,
            bibe->in_port, bibe->out_port,
            &ste->in_r_addr, &ste->out_r_addr,
            ste->r_port, ste->r_port, fib->ft_table_id,
            1);
    nat_syslog_nat46_sadd (bibe->fib_index, &bibe->in_addr, bibe->in_port,
            &bibe->out_addr, bibe->out_port, &ste->out_r_addr,
            ste->r_port, bibe->proto);
    return ste;
}

void
nat46_db_st_entry_free (u32 thread_index,
        nat46_db_t * db, nat46_db_st_entry_t * ste)
{
    nat46_db_st_entry_t *st;
    nat46_db_bib_entry_t *bib, *bibe;
    nat46_db_st_entry_key_t ste_key;
    clib_bihash_kv_48_8_t kv;
    fib_table_t *fib;

    switch (ip_proto_to_snat_proto (ste->proto))
    {
        /* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
                            st = db->st._##n##_st; \
        bib = db->bib._##n##_bib; \
        break;
        foreach_snat_protocol
#undef _
            /* *INDENT-ON* */
    default:
            st = db->st._unk_proto_st;
            bib = db->bib._unk_proto_bib;
            break;
    }

    bibe = pool_elt_at_index (bib, ste->bibe_index);

    db->st.st_entries_num--;

    /* delete hash lookup */
    clib_memset (&ste_key, 0, sizeof (ste_key));
    ste_key.l_addr.ip4.as_u32 = bibe->in_addr.as_u32;
    ste_key.r_addr.ip4.as_u32 = ste->in_r_addr.as_u32;
    ste_key.fib_index = bibe->fib_index;
    ste_key.l_port = bibe->in_port;
    ste_key.r_port = ste->r_port;
    ste_key.proto = ste->proto;
    kv.key[0] = ste_key.as_u64[0];
    kv.key[1] = ste_key.as_u64[1];
    kv.key[2] = ste_key.as_u64[2];
    kv.key[3] = ste_key.as_u64[3];
    kv.key[4] = ste_key.as_u64[4];
    kv.key[5] = ste_key.as_u64[5];
    clib_bihash_add_del_48_8 (&db->st.in2out, &kv, 0);

    clib_memset (&ste_key, 0, sizeof (ste_key));
    ste_key.l_addr.as_u64[0] = bibe->out_addr.as_u64[0];
    ste_key.l_addr.as_u64[1] = bibe->out_addr.as_u64[1];
    ste_key.r_addr.as_u64[0] = ste->out_r_addr.as_u64[0];
    ste_key.r_addr.as_u64[1] = ste->out_r_addr.as_u64[1];
    ste_key.l_port = bibe->out_port;
    ste_key.r_port = ste->r_port;
    ste_key.proto = ste->proto;
    kv.key[0] = ste_key.as_u64[0];
    kv.key[1] = ste_key.as_u64[1];
    kv.key[2] = ste_key.as_u64[2];
    kv.key[3] = ste_key.as_u64[3];
    kv.key[4] = ste_key.as_u64[4];
    kv.key[5] = ste_key.as_u64[5];
    clib_bihash_add_del_48_8 (&db->st.out2in, &kv, 0);

    fib = fib_table_get (bibe->fib_index, FIB_PROTOCOL_IP6);
    nat_ipfix_logging_nat46_session (thread_index, &bibe->in_addr,
            &bibe->out_addr, bibe->proto,
            bibe->in_port, bibe->out_port,
            &ste->in_r_addr, &ste->out_r_addr,
            ste->r_port, ste->r_port, fib->ft_table_id,
            0);
    nat_syslog_nat46_sdel (bibe->fib_index, &bibe->in_addr, bibe->in_port,
            &bibe->out_addr, bibe->out_port, &ste->out_r_addr,
            ste->r_port, bibe->proto);

    /* if dynamic no pat ste, free dynamic no pat*/
    if (ste->is_no_pat)
        nat46_db_dynamic_no_pat_free (bibe);

#ifndef USER_WALK_EXPIRE_FLAG
    /* delete timer*/
    nat46_delete_session_timer(db, ste);
#endif

    /* delete from pool */
    pool_put (st, ste);

    /* decrement session number for BIB entry */
    bibe->ses_num--;

    /* delete BIB entry if last session and dynamic */
    if (!bibe->is_static && !bibe->ses_num)
    {
        nat46_db_bib_entry_free (thread_index, db, bibe);
    }
}

nat46_db_st_entry_t *
nat46_db_st_entry_find (nat46_db_t * db, ip46_address_t * l_addr,
        ip46_address_t * r_addr, u16 l_port, u16 r_port,
        u8 proto, u32 fib_index, u8 is_ip6)
{
    nat46_db_st_entry_t *ste = 0;
    nat46_db_st_entry_t *st;
    nat46_db_st_entry_key_t ste_key;
    clib_bihash_kv_48_8_t kv, value;

    switch (ip_proto_to_snat_proto (proto))
    {
        /* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
                            st = db->st._##n##_st; \
        break;
        foreach_snat_protocol
#undef _
            /* *INDENT-ON* */
    default:
            st = db->st._unk_proto_st;
            break;
    }

    clib_memset (&ste_key, 0, sizeof (ste_key));
    ste_key.l_addr.as_u64[0] = l_addr->as_u64[0];
    ste_key.l_addr.as_u64[1] = l_addr->as_u64[1];
    ste_key.r_addr.as_u64[0] = r_addr->as_u64[0];
    ste_key.r_addr.as_u64[1] = r_addr->as_u64[1];
    ste_key.fib_index = fib_index;
    ste_key.l_port = l_port;
    ste_key.r_port = r_port;
    ste_key.proto = proto;
    kv.key[0] = ste_key.as_u64[0];
    kv.key[1] = ste_key.as_u64[1];
    kv.key[2] = ste_key.as_u64[2];
    kv.key[3] = ste_key.as_u64[3];
    kv.key[4] = ste_key.as_u64[4];
    kv.key[5] = ste_key.as_u64[5];

    if (!clib_bihash_search_48_8
            (is_ip6 ? &db->st.out2in : &db->st.in2out, &kv, &value))
        ste = pool_elt_at_index (st, value.value);

    return ste;
}

u32
nat46_db_st_entry_get_index (nat46_db_t * db, nat46_db_st_entry_t * ste)
{
    nat46_db_st_entry_t *st;

    switch (ip_proto_to_snat_proto (ste->proto))
    {
        /* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
                            st = db->st._##n##_st; \
        break;
        foreach_snat_protocol
#undef _
            /* *INDENT-ON* */
    default:
            st = db->st._unk_proto_st;
            return (u32) ~ 0;
    }

    return ste - st;
}

nat46_db_st_entry_t *
nat46_db_st_entry_by_index (nat46_db_t * db, u8 proto, u32 ste_index)
{
    nat46_db_st_entry_t *st;

    switch (ip_proto_to_snat_proto (proto))
    {
        /* *INDENT-OFF* */
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
                            st = db->st._##n##_st; \
        break;
        foreach_snat_protocol
#undef _
            /* *INDENT-ON* */
    default:
            st = db->st._unk_proto_st;
            break;
    }

    return pool_elt_at_index (st, ste_index);
}

u32
nat46_db_st_free_walk_expired (u32 thread_index, nat46_db_t * db, u32 now)
{
    u32 num = 0;
    u32 *ste_to_be_free = 0, *ste_index;
    nat46_db_st_entry_t *st, *ste;

    /* *INDENT-OFF* */
#define _(N, i, n, s) \
    st = db->st._##n##_st; \
    pool_foreach (ste, st, ({\
                if (i == SNAT_PROTOCOL_TCP && !ste->tcp_state) \
                    continue; \
                if (ste->expire < now) \
                    vec_add1 (ste_to_be_free, ste - st); \
                })); \
    vec_foreach (ste_index, ste_to_be_free) \
        nat46_db_st_entry_free (thread_index, db, pool_elt_at_index(st, ste_index[0])); \
    num += vec_len(ste_to_be_free); \
    vec_free (ste_to_be_free); \
    ste_to_be_free = 0;
    foreach_snat_protocol
#undef _
    st = db->st._unk_proto_st;
    pool_foreach (ste, st, ({
                if (ste->expire < now)
                    vec_add1 (ste_to_be_free, ste - st);
                }));
    vec_foreach (ste_index, ste_to_be_free)
        nat46_db_st_entry_free (thread_index, db, pool_elt_at_index(st, ste_index[0]));
    num += vec_len(ste_to_be_free);
    vec_free (ste_to_be_free);
    /* *INDENT-ON* */
    return num;
}

u32
nat46_db_st_free_timer_expired (u32 thread_index, nat46_db_t * db, u32 now)
{
  u32 num = 0;
  nat46_db_st_entry_t *ste;
  u32 *timer_handlers_vec;
  u32 *timer_handler;
  u32 _st_db_index;
  u32 session_index;

  timer_handlers_vec = tw_timer_expire_timers_1t_3w_64sl (db->timers_per_worker, now);
  vec_foreach(timer_handler, timer_handlers_vec)
  {
      _st_db_index =  timer_handler[0] >> 30;
      session_index = timer_handler[0] & 0x3fffffff;
      switch (_st_db_index)
      {
#define _(N, i, n, s) \
    case SNAT_PROTOCOL_##N: \
        ste = pool_elt_at_index (db->st._##n##_st, session_index); \
        if (i == SNAT_PROTOCOL_TCP && !ste->tcp_state) \
        { \
          ste->session_timer_handle =  \
                tw_timer_start_1t_3w_64sl (db->timers_per_worker, timer_handler[0], 0, nat46_get_tcp_trans_timeout()); \
            continue; \
        } \
        if (ste->expire < now) \
        { \
          nat46_db_st_entry_free (thread_index, db, ste); \
          num++; \
        } \
        else \
        { \
          u64 delta = ste->expire - now; \
          ste->session_timer_handle =  \
                tw_timer_start_1t_3w_64sl (db->timers_per_worker, timer_handler[0], 0, delta); \
        } \
        break;
        foreach_snat_protocol
#undef _
    default:
        ste = pool_elt_at_index (db->st._unk_proto_st, session_index);
        if (ste->expire < now)
        {
          nat46_db_st_entry_free (thread_index, db, ste);
          num++;
        }
        else
        {
          u64 delta = ste->expire - now; 
          ste->session_timer_handle = 
                tw_timer_start_1t_3w_64sl (db->timers_per_worker, timer_handler[0], 0, delta);
        }
        break;
      }
  }
  return num;
}

void
nat46_db_free_out_addr (u32 thread_index,
        nat46_db_t * db, ip6_address_t * out_addr, u32 plen)
{
    u32 *ste_to_be_free = 0, *ste_index;
    nat46_db_st_entry_t *st, *ste;
    nat46_db_bib_entry_t *bibe;
    ip6_address_t ip6, mask;

    ip6_address_mask_from_width(&mask, plen);

    db->addr_free = 1;
    /* *INDENT-OFF* */
#define _(N, i, n, s) \
    st = db->st._##n##_st; \
    pool_foreach (ste, st, ({ \
                bibe = pool_elt_at_index (db->bib._##n##_bib, ste->bibe_index); \
                ip6.as_u64[0] = bibe->out_addr.as_u64[0]; \
                ip6.as_u64[1] = bibe->out_addr.as_u64[1]; \
                ip6_address_mask(&ip6, &mask); \
                if (ip6.as_u64[0] == out_addr->as_u64[0] &&  \
                    ip6.as_u64[1] == out_addr->as_u64[1]) \
                vec_add1 (ste_to_be_free, ste - st); \
                })); \
    vec_foreach (ste_index, ste_to_be_free) \
    nat46_db_st_entry_free (thread_index, db, \
            pool_elt_at_index(st, ste_index[0])); \
    vec_free (ste_to_be_free); \
    ste_to_be_free = 0;
    foreach_snat_protocol
#undef _
    st = db->st._unk_proto_st;
    pool_foreach (ste, st, ({
                bibe = pool_elt_at_index (db->bib._unk_proto_bib, ste->bibe_index);
                ip6.as_u64[0] = bibe->out_addr.as_u64[0]; \
                ip6.as_u64[1] = bibe->out_addr.as_u64[1]; \
                ip6_address_mask(&ip6, &mask); \
                if (ip6.as_u64[0] == out_addr->as_u64[0] &&
                    ip6.as_u64[1] == out_addr->as_u64[1])
                    vec_add1 (ste_to_be_free, ste - st);
                }));
    vec_foreach (ste_index, ste_to_be_free)
        nat46_db_st_entry_free (thread_index, db, pool_elt_at_index(st, ste_index[0]));
    vec_free (ste_to_be_free);
    db->addr_free = 0;
    /* *INDENT-ON* */
}

void nat46_db_dynamic_no_pat_create(u32 fib_index,
        nat46_db_st_entry_t *ste,
        ip6_address_t * addr_6, 
        u16 port, u8 proto)
{
    nat46_main_t *nm = &nat46_main;
    clib_bihash_kv_24_8_t kv;
    nat46_db_dynamic_no_pat_key_t key;

    clib_memset (&key, 0, sizeof (key));
    key.fib_index = fib_index;
    key.port = port;
    key.proto = proto;
    key.rsvd = 0;

    key.addr.ip6.as_u64[0] = addr_6->as_u64[0];
    key.addr.ip6.as_u64[1] = addr_6->as_u64[1];

    kv.key[0] = key.as_u64[0];
    kv.key[1] = key.as_u64[1];
    kv.key[2] = key.as_u64[2];
    kv.value = (u64)ste;

    ste->is_no_pat = 1;
    if (clib_bihash_add_del_24_8(&nm->dnop.dynamic_mapping_by_no_pat, &kv, 1))
        nat_elog_notice ("NAT46 dynamic no pat mapping key add failed");
    clib_atomic_fetch_add(&nm->dnop.dynamic_no_pat_mappings_cnt, 1);
}

void
nat46_db_dynamic_no_pat_free (nat46_db_bib_entry_t * bibe)
{
    nat46_main_t *nm = &nat46_main;
    nat46_db_dynamic_no_pat_key_t key;
    clib_bihash_kv_24_8_t kv;

    clib_memset (&key, 0, sizeof (key));
    /* delete hash lookup */
    key.addr.ip6.as_u64[0] = bibe->out_addr.as_u64[0];
    key.addr.ip6.as_u64[1] = bibe->out_addr.as_u64[1];

    key.fib_index = bibe->fib_index;
    key.port = bibe->out_port;
    key.proto = bibe->proto;
    key.rsvd = 0;
    kv.key[0] = key.as_u64[0];
    kv.key[1] = key.as_u64[1];
    kv.key[2] = key.as_u64[2];
    clib_bihash_add_del_24_8 (&nm->dnop.dynamic_mapping_by_no_pat, &kv, 0);
    clib_atomic_fetch_sub(&nm->dnop.dynamic_no_pat_mappings_cnt, 1);
}

void nat46_db_remote_mapping_walk (nat46_db_remote_mapping_t *mappings, 
        nat46_db_remote_mapping_walk_fn_t fn, void *ctx)
{
    nat46_remote_mapping_entry_t *mapping;
    pool_foreach (mapping, mappings->mapping_entrys, ({
        if (fn (mapping, ctx))
            return;
    }));
}

int nat46_db_remote_mapping_find_and_map46(u32 fib_index, 
        ip4_address_t *in_ip4, ip6_address_t *out_ip6, 
        u8 proto)
{
    nat46_main_t *nm = &nat46_main;
    nat46_db_remote_mapping_t *mapping = &nm->remote_mapping;
    nat46_remote_mapping_entry_t *mapping_entry = NULL;
    nat46_remote_mapping_key_t key46;
    clib_bihash_kv_24_8_t kv, value;

    clib_memset(&key46, 0 ,sizeof(nat46_remote_mapping_key_t));
    //search 2 tuple 
    key46.addr.ip4.as_u32 = in_ip4->as_u32;
    key46.proto = proto;
    key46.rsvd16 = 0;
    key46.rsvd8 = 0;
    key46.fib_index = fib_index;

    kv.key[0] = key46.as_u64[0];
    kv.key[1] = key46.as_u64[1];
    kv.key[2] = key46.as_u64[2];

    if (!clib_bihash_search_24_8 (&mapping->remote_ip4toip6, &kv, &value))
    {
        mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);
        out_ip6->as_u64[0] = mapping_entry->r_addr.as_u64[0];
        out_ip6->as_u64[1] = mapping_entry->r_addr.as_u64[1];
        return 0;
    }
    //search 1 tuple 
    key46.proto = ~0;

    kv.key[0] = key46.as_u64[0];
    kv.key[1] = key46.as_u64[1];
    kv.key[2] = key46.as_u64[2];
    if (!clib_bihash_search_24_8 (&mapping->remote_ip4toip6, &kv, &value))
    {
        mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);
        out_ip6->as_u64[0] = mapping_entry->r_addr.as_u64[0];
        out_ip6->as_u64[1] = mapping_entry->r_addr.as_u64[1];
        return 0;
    }
    return 1;
}

int nat46_db_remote_mapping_find_and_map64(u32 fib_index, 
        ip6_address_t *in_ip6, ip4_address_t *out_ip4, 
        u8 proto)
{
    nat46_main_t *nm = &nat46_main;
    nat46_db_remote_mapping_t *mapping = &nm->remote_mapping;
    nat46_remote_mapping_entry_t *mapping_entry = NULL;
    nat46_remote_mapping_key_t key64;
    clib_bihash_kv_24_8_t kv, value;

    clib_memset(&key64, 0 ,sizeof(nat46_remote_mapping_key_t));
    //search 2 tuple 
    key64.addr.ip6.as_u64[0] = in_ip6->as_u64[0];
    key64.addr.ip6.as_u64[1] = in_ip6->as_u64[1];
    key64.proto = proto;
    key64.rsvd16 = 0;
    key64.rsvd8 = 0;
    key64.fib_index = fib_index;

    kv.key[0] = key64.as_u64[0];
    kv.key[1] = key64.as_u64[1];
    kv.key[2] = key64.as_u64[2];

    if (!clib_bihash_search_24_8 (&mapping->remote_ip6toip4, &kv, &value))
    {
        mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);
        out_ip4->as_u32 = mapping_entry->l_addr.as_u32;
        return 0;
    }

    //search 1 tuple 
    key64.proto = ~0;

    kv.key[0] = key64.as_u64[0];
    kv.key[1] = key64.as_u64[1];
    kv.key[2] = key64.as_u64[2];
    if (!clib_bihash_search_24_8 (&mapping->remote_ip6toip4, &kv, &value))
    {
        mapping_entry = pool_elt_at_index (mapping->mapping_entrys, value.value);
        out_ip4->as_u32 = mapping_entry->l_addr.as_u32;
        return 0;
    }
    return 1;

}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
