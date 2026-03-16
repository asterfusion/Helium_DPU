#include <ha_sync/ha_sync.h>


u32 ha_sync_tx_pool_add (u32 seq, u8 msg_type, u8 session_count, u8 *payload, u16 payload_len)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u32 index;
    u8 *payload_vec = 0;
    u8 *old_payload_to_free = 0;

    if (payload_len > 0)
    {
        vec_validate(payload_vec, payload_len - 1);
        clib_memcpy(payload_vec, payload, payload_len);
    }

    clib_spinlock_lock(&hsm->tx_lock);

    uword *p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        ha_sync_tx_packet_t *old_req = pool_elt_at_index (hsm->ha_sync_tx_pool, p[0]);
        old_payload_to_free = old_req->payload;
        index = p[0];
        req = old_req;

        if (req->timer_handle != ~0)
        {
            tw_timer_stop_16t_2w_512sl(&hsm->timer_wheel, req->timer_handle);
            req->timer_handle = ~0;
        }
    } else {
        pool_get(hsm->ha_sync_tx_pool, req);
        index = req - hsm->ha_sync_tx_pool;
        hash_set(hsm->seq_to_pool_index, seq, index);
        req->timer_handle = ~0;
    }

    req->seq_number = seq;
    req->msg_type = msg_type;
    req->length = payload_len;
    req->payload = payload_vec;
    req->session_count = session_count;
    req->retry_count = 0;

    // start timer only when retransmission is enabled
    if (hsm->retransmit_times > 0 && hsm->retransmit_interval > 0)
    {
        u32 ticks = (u32)(hsm->retransmit_interval / hsm->timer_wheel.timer_interval);
        if (ticks < 1)
            ticks = 1;
        req->timer_handle = tw_timer_start_16t_2w_512sl(&hsm->timer_wheel, index, 0, ticks);
        clib_warning ("ha_sync_tx_pool_add: start timer seq %u handle %u ticks %u",
                      seq, req->timer_handle, ticks);
    }
    else
    {
        clib_warning ("ha_sync_tx_pool_add: timer disabled seq %u (times=%u interval=%f)",
                      seq, hsm->retransmit_times, hsm->retransmit_interval);
    }

    clib_spinlock_unlock(&hsm->tx_lock);

    if (old_payload_to_free)
        vec_free(old_payload_to_free);

    return index;
}


int ha_sync_tx_pool_get_by_seq (u32 seq, ha_sync_tx_packet_t *out_data)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    uword *p;
    int found = 0;
    u8 *payload_copy = 0;

    clib_spinlock_lock(&hsm->tx_lock);
    p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        ha_sync_tx_packet_t *req = pool_elt_at_index (hsm->ha_sync_tx_pool, p[0]);
        out_data->seq_number = req->seq_number;
        out_data->msg_type = req->msg_type;
        out_data->session_count = req->session_count;
        out_data->retry_count = req->retry_count;
        out_data->length = req->length;
        out_data->payload = 0;
        if (req->length > 0 && req->payload)
        {
            vec_validate(payload_copy, req->length - 1);
            clib_memcpy(payload_copy, req->payload, req->length);
            out_data->payload = payload_copy;
        }
        found = (req->length == 0 || out_data->payload != 0);
    }
    clib_spinlock_unlock(&hsm->tx_lock);

    if (!found && payload_copy)
        vec_free(payload_copy);
    return found;
}


void ha_sync_tx_pool_del_by_seq (u32 seq)
{
    ha_sync_main_t *hsm = &ha_sync_main;
    uword *p;
    u8 *vec_to_free = 0;

    clib_spinlock_lock(&hsm->tx_lock);
    p = hash_get(hsm->seq_to_pool_index, seq);
    if (p) {
        u32 index = p[0];
        ha_sync_tx_packet_t *req = pool_elt_at_index (hsm->ha_sync_tx_pool, index);

        if (req->timer_handle != ~0)
        {
            tw_timer_stop_16t_2w_512sl(&hsm->timer_wheel, req->timer_handle);
            req->timer_handle = ~0;
        }

        vec_to_free = req->payload;
        req->payload = 0;
        req->length = 0;
        pool_put_index(hsm->ha_sync_tx_pool, index);
        hash_unset(hsm->seq_to_pool_index, seq);
    }
    clib_spinlock_unlock(&hsm->tx_lock);

    if (vec_to_free)
        vec_free(vec_to_free);
}

void ha_sync_pool_clear_keep ()
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u8 **vecs_to_free = 0;
    uword *keys = 0;
    hash_pair_t *p;
    u32 *pool_indices = 0;
    uword i;

    clib_spinlock_lock(&hsm->tx_lock);

    if (hsm->ha_sync_tx_pool)
    {
        pool_foreach_index (i, hsm->ha_sync_tx_pool)
        {
            vec_add1 (pool_indices, (u32) i);
        }

        u32 *pi;
        vec_foreach (pi, pool_indices)
        {
            req = pool_elt_at_index (hsm->ha_sync_tx_pool, *pi);
            if (req->timer_handle != ~0)
            {
                tw_timer_stop_16t_2w_512sl(&hsm->timer_wheel, req->timer_handle);
                req->timer_handle = ~0;
            }
            if (req->payload)
            {
                vec_add1 (vecs_to_free, req->payload);
                req->payload = 0;
            }
            req->length = 0;
            req->retry_count = 0;
            pool_put_index (hsm->ha_sync_tx_pool, *pi);
        }
    }

    if (hsm->seq_to_pool_index)
    {
        hash_foreach_pair (p, hsm->seq_to_pool_index, ({
            vec_add1 (keys, p->key);
        }));

        uword *k;
        vec_foreach (k, keys)
        {
            hash_unset (hsm->seq_to_pool_index, *k);
        }
    }

    clib_spinlock_unlock(&hsm->tx_lock);

    u8 **v;
    vec_foreach(v, vecs_to_free)
    {
        vec_free(*v);
    }
    vec_free(vecs_to_free);
    vec_free(keys);
    vec_free(pool_indices);
}


void ha_sync_tx_pool_free ()
{
    ha_sync_main_t *hsm = &ha_sync_main;
    ha_sync_tx_packet_t *req;
    u8 **vecs_to_free = 0;

    clib_spinlock_lock(&hsm->tx_lock);

    if (hsm->ha_sync_tx_pool)
    {
        pool_foreach (req, hsm->ha_sync_tx_pool)
        {
            if (req->timer_handle != ~0)
            {
                tw_timer_stop_16t_2w_512sl(&hsm->timer_wheel, req->timer_handle);
                req->timer_handle = ~0;
            }
            if (req->payload)
                vec_add1 (vecs_to_free, req->payload);
        }
        pool_free(hsm->ha_sync_tx_pool);
        hsm->ha_sync_tx_pool = 0;
    }

    if (hsm->seq_to_pool_index)
    {
        hash_free(hsm->seq_to_pool_index);
        hsm->seq_to_pool_index = 0;
    }

    clib_spinlock_unlock(&hsm->tx_lock);

    u8 **v;
    vec_foreach(v, vecs_to_free)
    {
        vec_free(v[0]);
    }
    vec_free(vecs_to_free);

}
