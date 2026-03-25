#include <ha_sync/ha_sync.h>

static_always_inline ha_sync_per_thread_data_t *
ha_sync_get_ptd (u32 thread_index)
{
    ha_sync_main_t *hsm = &ha_sync_main;

    if (thread_index >= vec_len (hsm->per_thread_data))
        return 0;
    return &hsm->per_thread_data[thread_index];
}

static_always_inline u32
ha_sync_timer_ticks (ha_sync_main_t *hsm, ha_sync_per_thread_data_t *ptd)
{
    u32 ticks;

    ticks = (u32) (hsm->retransmit_interval / ptd->timer_wheel.timer_interval);
    if (ticks < 1)
        ticks = 1;
    return ticks;
}

static_always_inline void
ha_sync_recycle_payload_vec (ha_sync_per_thread_data_t *ptd, u8 *payload)
{
    if (!payload)
        return;

    vec_reset_length (payload);
    if (!ptd->spare_data)
    {
        ptd->spare_data = payload;
        return;
    }
    vec_free (payload);
}

void
ha_sync_tx_pool_add (u32 thread_index, u32 seq, u8 msg_type, u8 session_count,
                     u8 *payload, u16 payload_len)
{
    ha_sync_per_thread_data_t *ptd = ha_sync_get_ptd (thread_index);
    ha_sync_tx_packet_t *req;
    uword *p;

    if (!ptd)
        return;

    p = hash_get (ptd->seq_to_pool_index, seq);
    if (p)
    {
        req = pool_elt_at_index (ptd->tx_pool, p[0]);
        if (req->timer_handle != ~0)
        {
            tw_timer_stop_16t_2w_512sl (&ptd->timer_wheel, req->timer_handle);
            req->timer_handle = ~0;
        }
        ha_sync_recycle_payload_vec (ptd, req->payload);
        req->payload = 0;
    }
    else
    {
        pool_get (ptd->tx_pool, req);
        hash_set (ptd->seq_to_pool_index, seq, req - ptd->tx_pool);
        req->payload = 0;
        req->timer_handle = ~0;
    }

    req->seq_number = seq;
    req->msg_type = msg_type;
    req->length = payload_len;
    req->session_count = session_count;
    req->retry_count = 0;
    req->payload = payload;
}

int
ha_sync_tx_pool_prepare_send (u32 thread_index, u32 seq,
                              ha_sync_tx_packet_t *out_data)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd = ha_sync_get_ptd (thread_index);
    uword *p;
    ha_sync_tx_packet_t *req;

    if (!ptd || !out_data)
        return 0;

    p = hash_get (ptd->seq_to_pool_index, seq);
    if (!p)
        return 0;

    req = pool_elt_at_index (ptd->tx_pool, p[0]);
    if (req->msg_type == HA_SYNC_MSG_REQUEST && req->timer_handle == ~0 &&
        hsm->retransmit_times > 0 && hsm->retransmit_interval > 0)
    {
        req->timer_handle = tw_timer_start_16t_2w_512sl (
            &ptd->timer_wheel, p[0], 0, ha_sync_timer_ticks (hsm, ptd));
    }

    out_data->seq_number = req->seq_number;
    out_data->msg_type = req->msg_type;
    out_data->session_count = req->session_count;
    out_data->length = req->length;
    out_data->payload = req->payload;
    out_data->retry_count = req->retry_count;
    out_data->timer_handle = req->timer_handle;
    return 1;
}

void
ha_sync_tx_pool_del_by_seq (u32 thread_index, u32 seq)
{
    ha_sync_per_thread_data_t *ptd = ha_sync_get_ptd (thread_index);
    uword *p;
    ha_sync_tx_packet_t *req;
    u32 index;

    if (!ptd)
        return;

    p = hash_get (ptd->seq_to_pool_index, seq);
    if (!p)
        return;

    index = p[0];
    req = pool_elt_at_index (ptd->tx_pool, index);
    if (req->timer_handle != ~0)
    {
        tw_timer_stop_16t_2w_512sl (&ptd->timer_wheel, req->timer_handle);
        req->timer_handle = ~0;
    }

    ha_sync_recycle_payload_vec (ptd, req->payload);
    req->payload = 0;
    req->length = 0;
    req->retry_count = 0;
    pool_put_index (ptd->tx_pool, index);
    hash_unset (ptd->seq_to_pool_index, seq);
}

void
ha_sync_pool_clear_keep (void)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd;

    vec_foreach (ptd, hsm->per_thread_data)
    {
        ha_sync_tx_packet_t *req;
        u32 *pool_indices = 0;
        uword *keys = 0;
        hash_pair_t *p;
        uword i;

        if (ptd->tx_pool)
        {
            pool_foreach_index (i, ptd->tx_pool)
            {
                vec_add1 (pool_indices, (u32) i);
            }

            u32 *pi;
            vec_foreach (pi, pool_indices)
            {
                req = pool_elt_at_index (ptd->tx_pool, *pi);
                if (req->timer_handle != ~0)
                {
                    tw_timer_stop_16t_2w_512sl (&ptd->timer_wheel,
                                                req->timer_handle);
                    req->timer_handle = ~0;
                }
                ha_sync_recycle_payload_vec (ptd, req->payload);
                req->payload = 0;
                req->length = 0;
                req->retry_count = 0;
                pool_put_index (ptd->tx_pool, *pi);
            }
        }

        if (ptd->seq_to_pool_index)
        {
            hash_foreach_pair (p, ptd->seq_to_pool_index, ({
                vec_add1 (keys, p->key);
            }));

            uword *k;
            vec_foreach (k, keys)
            {
                hash_unset (ptd->seq_to_pool_index, *k);
            }
        }

        vec_free (pool_indices);
        vec_free (keys);
    }
}

void
ha_sync_tx_pool_free (void)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_per_thread_data_t *ptd;

    vec_foreach (ptd, hsm->per_thread_data)
    {
        ha_sync_tx_packet_t *req;

        if (ptd->tx_pool)
        {
            pool_foreach (req, ptd->tx_pool)
            {
                if (req->timer_handle != ~0)
                {
                    tw_timer_stop_16t_2w_512sl (&ptd->timer_wheel,
                                                req->timer_handle);
                    req->timer_handle = ~0;
                }
                ha_sync_recycle_payload_vec (ptd, req->payload);
                req->payload = 0;
            }
            pool_free (ptd->tx_pool);
            ptd->tx_pool = 0;
        }

        if (ptd->seq_to_pool_index)
        {
            hash_free (ptd->seq_to_pool_index);
            ptd->seq_to_pool_index = 0;
        }
    }
}
