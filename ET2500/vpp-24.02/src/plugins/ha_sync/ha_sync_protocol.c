#include <ha_sync/ha_sync.h>

void
ha_sync_update_all_contexts (void)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_session_registration_t *reg;

    vec_foreach (reg, hsm->registrations)
    {
        ha_sync_common_ctx_t *cctx;
        if (!reg->context)
            continue;
        cctx = (ha_sync_common_ctx_t *) reg->context;

        cctx->ha_sync_enable = hsm->enabled;
        cctx->ha_sync_config_ready = hsm->config_ready;
        cctx->ha_sync_connected = hsm->connection_established;
        cctx->ha_sync_snapshot_sequence = hsm->snapshot_sequence;
    }
}

int ha_sync_register_session_application (ha_sync_session_registration_t *reg)
{
    vlib_main_t *vm = vlib_get_main();
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_session_registration_t *r;
    if (!reg || !reg->context)
    {
        clib_warning ("ha_sync_register_session_application requires non-null context");
        return -1;
    }
    if (vlib_get_thread_index () != 0)
    {
        clib_warning ("ha_sync_register_session_application must run on main thread");
        return -1;
    }

    vec_foreach(r, hsm->registrations)
    {
        if (r->app_type == reg->app_type)
        {
            return 0;
        }
    }

    vlib_worker_thread_barrier_sync(vm);
    vec_add2(hsm->registrations, r, 1);
    clib_memcpy(r, reg, sizeof(ha_sync_session_registration_t));
    if (r->snapshot_mode != HA_SYNC_SNAPSHOT_MODE_PER_THREAD)
      r->snapshot_mode = HA_SYNC_SNAPSHOT_MODE_SINGLE;
    hsm->num_registrations++;
    ha_sync_update_all_contexts ();
    vlib_worker_thread_barrier_release(vm);

    return 0;
}


int ha_sync_unregister_session_application (u32 app_type)
{
    vlib_main_t *vm = vlib_get_main();
    ha_sync_main_t *hsm = &ha_sync_main;
    u32 i;
    int found = 0;
    if (vlib_get_thread_index () != 0)
    {
        clib_warning ("ha_sync_unregister_session_application must run on main thread");
        return -1;
    }

    vlib_worker_thread_barrier_sync(vm);
    vec_foreach_index(i, hsm->registrations)
    {
        if (hsm->registrations[i].app_type == app_type)
        {
            vec_del1(hsm->registrations, i);
            hsm->num_registrations--;
            found = 1;
            break;
        }
    }
    vlib_worker_thread_barrier_release(vm);
        
    if (!found)
    {
        clib_warning("app type %d not registered", app_type);
    }

    return 0;
}

void
ha_sync_wake_output_thread (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;

    if (thread_index >= vlib_get_n_threads ())
        return;
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;

    vlib_node_set_interrupt_pending (vlib_get_main_by_index (thread_index),
                                     ha_sync_output_worker_node.index);
}


void ha_sync_send_response (u32 seq_number, u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    if (thread_index != vlib_get_thread_index ())
    {
        clib_warning ("ha_sync_send_response cross-thread enqueue is not allowed");
        return;
    }
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;
    ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

    ha_sync_fast_msg_t msg;
    msg.seq_number = seq_number;
    msg.msg_type = HA_SYNC_MSG_RESPONSE;

    clib_fifo_add1(ptb->fast_msg_queue, msg);
    ha_sync_wake_output_thread (thread_index);
}


void ha_sync_send_hello (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    if (thread_index != vlib_get_thread_index ())
    {
        clib_warning ("ha_sync_send_hello cross-thread enqueue is not allowed");
        return;
    }
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;
    ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

    ha_sync_fast_msg_t msg;
    msg.seq_number = clib_atomic_add_fetch(&hsm->global_seq_number, 1);
    msg.msg_type = HA_SYNC_MSG_HELLO;

    clib_fifo_add1(ptb->fast_msg_queue, msg);
    ha_sync_wake_output_thread (thread_index);
    // clib_warning ("ha_sync_send_hello seq_number %d", msg.seq_number);
}

void ha_sync_send_hello_response (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    if (thread_index != vlib_get_thread_index ())
    {
        clib_warning ("ha_sync_send_hello_response cross-thread enqueue is not allowed");
        return;
    }
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;
    ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

    ha_sync_fast_msg_t msg;
    msg.seq_number = clib_atomic_add_fetch(&hsm->global_seq_number, 1);
    msg.msg_type = HA_SYNC_MSG_HELLO_RESPONSE;

    clib_fifo_add1(ptb->fast_msg_queue, msg);
    ha_sync_wake_output_thread (thread_index);

}

void ha_sync_snapshot_trigger (void)
{
    ha_sync_main_t *hsm = &ha_sync_main;

    if (!hsm->enabled || !hsm->connection_established)
        return;
    if (hsm->snapshot_triggered_for_connection)
        return;

    hsm->snapshot_triggered_for_connection = 1;
    hsm->snapshot_sequence++;
    hsm->snapshot_trigger_pending = 1;
    ha_sync_update_all_contexts ();
}
