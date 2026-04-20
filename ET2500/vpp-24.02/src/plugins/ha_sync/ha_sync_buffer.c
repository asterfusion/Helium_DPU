#include <ha_sync/ha_sync.h>

void
ha_sync_per_thread_buffer_add (u32 thread_index, u8 app_type, u8 *session_data,
                               u16 data_len)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd;
    u32 entry_len;
    ha_sync_session_header_t hdr;

    if (!hsm->connection_established)
        return;
    if (thread_index >= vec_len (hsm->per_thread_data))
    {
        clib_warning ("ha_sync thread_index out of range: %u, max %u",
                      thread_index, vec_len (hsm->per_thread_data));
        return;
    }

    ptd = &hsm->per_thread_data[thread_index];
    entry_len = sizeof (ha_sync_session_header_t) + data_len;
    if (entry_len > hsm->packet_size)
    {
        clib_warning ("ha_sync session entry too large: %u > packet_size %u",
                      entry_len, hsm->packet_size);
        return;
    }

    if (vec_len (ptd->data) + entry_len > hsm->packet_size)
        ha_sync_per_thread_buffer_flush (thread_index);

    if (ptd->session_count == 0)
        ptd->last_flush_time = vlib_time_now (hsm->vlib_main);

    hdr.app_type = app_type;
    hdr.session_length = clib_host_to_net_u16 (data_len);
    vec_add (ptd->data, (u8 *) &hdr, sizeof (hdr));
    vec_add (ptd->data, session_data, data_len);
    ptd->session_count++;
}

void
ha_sync_per_thread_buffer_flush (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd;
    u8 *payload;
    u32 seq;

    if (!hsm->connection_established)
        return;
    if (thread_index >= vec_len (hsm->per_thread_data))
        return;

    ptd = &hsm->per_thread_data[thread_index];
    if (PREDICT_FALSE (ptd->session_count == 0))
        return;

    seq = ha_sync_next_seq_number ();
    payload = ptd->data;
    ptd->data = ptd->spare_data;
    ptd->spare_data = 0;
    if (!ptd->data)
      vec_validate (ptd->data, hsm->packet_size - 1);
    vec_reset_length (ptd->data);

    ha_sync_tx_pool_add (thread_index, seq, HA_SYNC_MSG_REQUEST,
                         ptd->session_count, payload, vec_len (payload));

    ptd->session_count = 0;
    clib_fifo_add1 (ptd->pending_fifo, seq);
    ha_sync_wake_output_thread (thread_index);
    ptd->last_flush_time = vlib_time_now (hsm->vlib_main);
}
