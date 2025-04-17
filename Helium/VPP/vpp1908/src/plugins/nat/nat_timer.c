#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>

#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/fib/ip4_fib.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>
#include <vppinfra/crc32.h>

#include <nat/nat.h>
#include <nat/nat_inlines.h>
#include <nat/nat_reass.h>
#include <nat/nat64.h>
#include <nat/nat64_db.h>
#include <nat/nat46.h>
#include <nat/nat46_db.h>
#include <nat/nat_ha.h>
#include <nat/nat_ipfix_logging.h>
#include <nat/nat_syslog.h>

/**
 * @brief Per worker process checking expire time for NAT44 sessions.
 */
static uword
nat44_expire_worker_walk_fn (vlib_main_t * vm,
        vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    int num = 0;
    snat_session_t *s, *sessions_pool;
    clib_bihash_kv_8_8_t s_kv, s_value;
    snat_main_t *sm = &snat_main;
    u32 thread_index = vm->thread_index;

    snat_main_per_thread_data_t *tsm = &sm->per_thread_data[thread_index];
    sessions_pool = tsm->sessions;
    f64 now = vlib_time_now (vm);
    u64 sess_timeout_time ;

/* walk all seesions to check expire time  */ 
#ifdef USER_WALK_EXPIRE_FLAG
    pool_foreach (s, sessions_pool, ({
         sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
         if (now < sess_timeout_time)
            continue;

        num++;

        s_kv.key = s->in2out.as_u64;
        if (clib_bihash_add_del_8_8 (&tsm->in2out, &s_kv, 0))
            nat_elog_warn ("in2out key del failed");

        s_kv.key = s->out2in.as_u64;
        if (clib_bihash_add_del_8_8 (&tsm->out2in, &s_kv, 0))
            nat_elog_warn ("out2in key del failed");

        if (!clib_bihash_search_8_8 (&sm->dynamic_mapping_by_no_pat, &s_kv, &s_value))
        {
            clib_bihash_add_del_8_8 (&sm->dynamic_mapping_by_no_pat, &s_kv, 0);
            clib_atomic_fetch_sub(&sm->dynamic_no_pat_mappings_cnt, 1);
        }

        snat_ipfix_logging_nat44_ses_delete (thread_index,
                s->in2out.addr.as_u32,
                s->out2in.addr.as_u32,
                s->in2out.protocol,
                s->in2out.port,
                s->out2in.port,
                s->in2out.fib_index);

        nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
                &s->in2out.addr, s->in2out.port,
                &s->out2in.addr, s->out2in.port,
                s->in2out.protocol);

        nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
                s->ext_host_port, s->out2in.protocol, s->out2in.fib_index,
                thread_index);

        if (!snat_is_session_static (s))
            snat_free_outside_address_and_port (s->pool_address, thread_index, &s->out2in);

        nat44_delete_session (sm, s, thread_index);
    }));
#else
/* walk expire session timer to check expire time  */ 
    u32 *timer_handlers_vec;
    u32 *timer_handler;
    timer_handlers_vec = tw_timer_expire_timers_1t_3w_64sl (tsm->timers_per_worker, now);
    vec_foreach(timer_handler, timer_handlers_vec)
    {
        s = pool_elt_at_index (sessions_pool, timer_handler[0]);
        sess_timeout_time = s->last_heard + (f64) nat44_session_get_timeout (sm, s);
        if (now < sess_timeout_time)
        {
            u64 delta = sess_timeout_time - now;
            s->session_timer_handle = tw_timer_start_1t_3w_64sl (tsm->timers_per_worker, timer_handler[0], 0, delta);
        }
        else
        {
            num++;
            s_kv.key = s->in2out.as_u64;
            if (clib_bihash_add_del_8_8 (&tsm->in2out, &s_kv, 0))
                nat_elog_warn ("in2out key del failed");

            s_kv.key = s->out2in.as_u64;
            if (clib_bihash_add_del_8_8 (&tsm->out2in, &s_kv, 0))
                nat_elog_warn ("out2in key del failed");

            if (!clib_bihash_search_8_8 (&sm->dynamic_mapping_by_no_pat, &s_kv, &s_value))
            {
                clib_bihash_add_del_8_8 (&sm->dynamic_mapping_by_no_pat, &s_kv, 0);
                clib_atomic_fetch_sub(&sm->dynamic_no_pat_mappings_cnt, 1);
            }

            snat_ipfix_logging_nat44_ses_delete (thread_index,
                    s->in2out.addr.as_u32,
                    s->out2in.addr.as_u32,
                    s->in2out.protocol,
                    s->in2out.port,
                    s->out2in.port,
                    s->in2out.fib_index);

            nat_syslog_nat44_apmdel (s->user_index, s->in2out.fib_index,
                    &s->in2out.addr, s->in2out.port,
                    &s->out2in.addr, s->out2in.port,
                    s->in2out.protocol);

            nat_ha_sdel (&s->out2in.addr, s->out2in.port, &s->ext_host_addr,
                    s->ext_host_port, s->out2in.protocol, s->out2in.fib_index,
                    thread_index);

            if (!snat_is_session_static (s))
                snat_free_outside_address_and_port (s->pool_address, thread_index, &s->out2in);

            nat44_delete_session (sm, s, thread_index);
        }
    }

#endif

    return num;
}

VLIB_REGISTER_NODE (nat44_expire_worker_walk_node) = {
    .function = nat44_expire_worker_walk_fn,
    .name = "nat44-expire-worker-walk",
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
};

/**
 * @brief Per worker process checking expire time for NAT64 sessions.
 */
static uword
nat64_expire_worker_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			     vlib_frame_t * f)
{
  nat64_main_t *nm = &nat64_main;
  u32 thread_index = vm->thread_index;
  nat64_db_t *db = &nm->db[thread_index];
  u32 now = (u32) vlib_time_now (vm);
  u32 num;

#ifdef USER_WALK_EXPIRE_FLAG
  num = nat64_db_st_free_walk_expired (thread_index, db, now);
#else
  num = nat64_db_st_free_timer_expired(thread_index, db, now);
#endif
  vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
			   db->bib.bib_entries_num);
  vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
			   db->st.st_entries_num);

  return num;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat64_expire_worker_walk_node) = {
    .function = nat64_expire_worker_walk_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat64-expire-worker-walk",
};
/* *INDENT-ON* */


/**
 * @brief Per worker process checking expire time for NAT46 sessions.
 */
static uword
nat46_expire_worker_walk_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
			     vlib_frame_t * f)
{
  nat46_main_t *nm = &nat46_main;
  u32 thread_index = vm->thread_index;
  nat46_db_t *db = &nm->db[thread_index];
  u32 now = (u32) vlib_time_now (vm);
  int num;

#ifdef USER_WALK_EXPIRE_FLAG
  num = nat46_db_st_free_walk_expired (thread_index, db, now);
#else
  num = nat46_db_st_free_timer_expired(thread_index, db, now);
#endif
  vlib_set_simple_counter (&nm->total_bibs, thread_index, 0,
			   db->bib.bib_entries_num);
  vlib_set_simple_counter (&nm->total_sessions, thread_index, 0,
			   db->st.st_entries_num);

  return num;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (nat46_expire_worker_walk_node) = {
    .function = nat46_expire_worker_walk_fn,
    .type = VLIB_NODE_TYPE_INPUT,
    .state = VLIB_NODE_STATE_INTERRUPT,
    .name = "nat46-expire-worker-walk",
};
/* *INDENT-ON* */

