#include <ha_sync/ha_sync.h>


void ha_sync_per_thread_buffer_add (u32 thread_index, u8 app_type, u8 *session_data, u16 data_len)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    if (!hsm->connection_established)
        return;
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;
    ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

    u32 entry_len = sizeof(ha_sync_session_header_t) + data_len;
    if (entry_len > hsm->packet_size)
    {
        clib_warning ("ha_sync session entry too large: %u > packet_size %u",
                      entry_len, hsm->packet_size);
        return;
    }

    if (vec_len (ptb->data) + entry_len > hsm->packet_size)
    {
        ha_sync_per_thread_buffer_flush (thread_index);
    }

    if (ptb->session_count == 0)
    {
        ptb->last_flush_time = vlib_time_now (hsm->vlib_main);
    }

    ha_sync_session_header_t hdr;
    hdr.app_type = app_type;
    hdr.session_length = clib_host_to_net_u16 (data_len);

    // Add header and session data to the buffer
    vec_add (ptb->data, (u8 *)&hdr, sizeof(hdr));
    vec_add (ptb->data, session_data, data_len);
    ptb->session_count++;
}



void ha_sync_per_thread_buffer_flush (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    if (!hsm->connection_established)
        return;
    if (thread_index >= vec_len (hsm->per_thread_buffers))
        return;
    ha_sync_per_thread_buffer_t *ptb = &hsm->per_thread_buffers[thread_index];

    if (PREDICT_FALSE (ptb->session_count == 0))
        return;
    
    u32 seq = clib_atomic_add_fetch (&hsm->global_seq_number, 1);

    ha_sync_tx_pool_add (seq, HA_SYNC_MSG_REQUEST, ptb->session_count, ptb->data, vec_len(ptb->data));
    clib_warning ("ha_sync per_thread_buffer_flush seq %u, thread_index %u, session_count %u, data_len %u", seq, thread_index, ptb->session_count, vec_len(ptb->data));

    vec_reset_length (ptb->data);
    ptb->session_count = 0;
    clib_fifo_add1 (ptb->pending_fifo, seq); // add seq to pending fifo
    ptb->last_flush_time = vlib_time_now (hsm->vlib_main);
}
