/*
 * Copyright 2024-2027 Asterfusion Network
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <vppinfra/error.h>

#include <plugins/spi/spi.h>
#include <plugins/spi/spi_inline.h>

/* *INDENT-OFF* */
#define foreach_spi_aging_process_error \
_(UNKNOWN_EVENT, "unknown event received")  \
/* end  of errors */

typedef enum
{
#define _(sym,str) SPI_AGING_PROCESS_ERROR_##sym,
    foreach_spi_aging_process_error
#undef _
    SPI_AGING_PROCESS_N_ERROR,
} spi_aging_process_error_t;

static char *spi_aging_process_error_strings[] = {
#define _(sym,string) string,
  foreach_spi_aging_process_error
#undef _
};

static void
send_one_worker_interrupt (vlib_main_t * vm, spi_main_t *spim,
			   int thread_index)
{
    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];
    if (!tspi->interrupt_is_pending)
    {
        tspi->interrupt_is_pending = 1;

        vlib_node_set_interrupt_pending (vlib_get_main_by_index (thread_index), spim->spi_session_timer_worker_node_index);
        /* if the interrupt was requested, mark that done. */
        CLIB_MEMORY_BARRIER ();
    }
}

static void
send_interrupts_to_workers (vlib_main_t * vm, spi_main_t *spim)
{
    int i;
    int n_threads = vlib_get_n_threads ();
    for (i = 0; i < n_threads; i++)
    {
        send_one_worker_interrupt (vm, spim, i);
    }
}


static_always_inline void
spi_aging_tcp_session(spi_main_t *spim, 
                      spi_per_thread_data_t *tspi, 
                      spi_session_t *session,
                      f64 time_now)
{
    u32 timeout = (u32)(~0);
    u8 do_free = 0;

    //change state
    switch (session->state_tcp)
    {
    case SPI_TCP_STATE_CLOSED:
    case SPI_TCP_STATE_TRANSITORY:
        {
            session->state_tcp = SPI_TCP_STATE_CLOSING;
        }
        break;
    case SPI_TCP_STATE_ESTABLISHED:
        {
            if ((time_now - session->last_pkt_timestamp) >= ((u64)session->transmit_timeout))
            {
                session->state_tcp = SPI_TCP_STATE_CLOSING;
            }
        }
        break;
    case SPI_TCP_STATE_CLOSING:
        {
            session->state_tcp = SPI_TCP_STATE_FREE;
        }
        break;
    case SPI_TCP_STATE_FREE:
    default:
        {
            do_free = 1;
        }
        break;
    }

    if (do_free)
    {
        if(PREDICT_FALSE(spi_delete_session(spim, tspi, session)))
        {
            clib_warning ("spi del session is failed\n");
        }
    }
    else
    {
        switch (session->state_tcp)
        {
        case SPI_TCP_STATE_CLOSED:
        case SPI_TCP_STATE_TRANSITORY:
            {
                timeout = spim->spi_timeout_config.tcp_transitory;
            }
            break;
        case SPI_TCP_STATE_ESTABLISHED:
            {
                /*
                 * Check the timestamp, 
                 * if the interval between the last incoming pkt 
                 * is less than 10% of the timeout, submit a full timeout
                 */
                timeout = spi_search_exact_3tuple_timeout(spim, session);
                if (timeout == (u32)(~0))
                {
                    timeout = spim->spi_timeout_config.tcp_established;
                }

                if ((time_now - session->last_pkt_timestamp) > ((u64)session->transmit_timeout * 0.1))
                {
                     timeout = timeout - (u32)(time_now - session->last_pkt_timestamp);
                }
                session->transmit_timeout = timeout;
            }
            break;
        case SPI_TCP_STATE_CLOSING:
            {
                timeout = spim->spi_timeout_config.tcp_closing;
            }
            break;
        case SPI_TCP_STATE_FREE:
        default:
            {
                timeout = 1;
            }
            break;
        }
        spi_submit_or_update_session_timer(tspi, session, timeout);
    }
}

static_always_inline void
spi_aging_icmp_session(spi_main_t *spim, 
                       spi_per_thread_data_t *tspi, 
                       spi_session_t *session,
                       f64 time_now)
{
    u32 timeout = (u32)(~0);
    u8 do_free = 0;

    //change state
    switch (session->state_icmp)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            if ((time_now - session->last_pkt_timestamp) >= ((u64)session->transmit_timeout))
            {
                session->state_icmp = SPI_GENERAL_STATE_IDLE;
            }
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            do_free = 1;
        }
        break;
    }

    if (do_free)
    {
        if(PREDICT_FALSE(spi_delete_session(spim, tspi, session)))
        {
            clib_warning ("spi del session is failed\n");
        }
    }
    else
    {
        switch (session->state_icmp)
        {
        case SPI_GENERAL_STATE_CLOSED:
        case SPI_GENERAL_STATE_TRANSMIT:
            {
                /*
                 * Check the timestamp, 
                 * if the interval between the last incoming pkt 
                 * is less than 10% of the timeout, submit a full timeout
                 */
                timeout = spi_search_exact_3tuple_timeout(spim, session);
                if (timeout == (u32)(~0))
                {
                    timeout = spim->spi_timeout_config.icmp;
                }

                if ((time_now - session->last_pkt_timestamp) > ((u64)session->transmit_timeout * 0.1))
                {
                     timeout = timeout - (u32)(time_now - session->last_pkt_timestamp);
                }
                session->transmit_timeout = timeout;
            }
            break;
        case SPI_GENERAL_STATE_IDLE:
        default:
            {
                timeout = 1;
            }
            break;
        }
        spi_submit_or_update_session_timer(tspi, session, timeout);
    }
}

static_always_inline void
spi_aging_udp_session(spi_main_t *spim, 
                      spi_per_thread_data_t *tspi, 
                      spi_session_t *session,
                      f64 time_now)
{
    u32 timeout = (u32)(~0);
    u8 do_free = 0;

    //change state
    switch (session->state_udp)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            if ((time_now - session->last_pkt_timestamp) >= ((u64)session->transmit_timeout))
            {
                session->state_udp = SPI_GENERAL_STATE_IDLE;
            }
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            do_free = 1;
        }
        break;
    }

    if (do_free)
    {
        if(PREDICT_FALSE(spi_delete_session(spim, tspi, session)))
        {
            clib_warning ("spi del session is failed\n");
        }
    }
    else
    {
        switch (session->state_udp)
        {
        case SPI_GENERAL_STATE_CLOSED:
        case SPI_GENERAL_STATE_TRANSMIT:
            {
                /*
                 * Check the timestamp, 
                 * if the interval between the last incoming pkt 
                 * is less than 10% of the timeout, submit a full timeout
                 */
                timeout = spi_search_exact_3tuple_timeout(spim, session);
                if (timeout == (u32)(~0))
                {
                    timeout = spim->spi_timeout_config.udp;
                }

                if ((time_now - session->last_pkt_timestamp) > ((u64)session->transmit_timeout * 0.1))
                {
                     timeout = timeout - (u32)(time_now - session->last_pkt_timestamp);
                }
                session->transmit_timeout = timeout;
            }
            break;
        case SPI_GENERAL_STATE_IDLE:
        default:
            {
                timeout = 1;
            }
            break;
        }
        spi_submit_or_update_session_timer(tspi, session, timeout);
    }
}

static_always_inline void
spi_aging_other_session(spi_main_t *spim, 
                        spi_per_thread_data_t *tspi, 
                        spi_session_t *session,
                        f64 time_now)
{
    u32 timeout = (u32)(~0);
    u8 do_free = 0;

    //change state
    switch (session->state_other)
    {
    case SPI_GENERAL_STATE_CLOSED:
    case SPI_GENERAL_STATE_TRANSMIT:
        {
            if ((time_now - session->last_pkt_timestamp) >= ((u64)session->transmit_timeout))
            {
                session->state_other = SPI_GENERAL_STATE_IDLE;
            }
        }
        break;
    case SPI_GENERAL_STATE_IDLE:
    default:
        {
            do_free = 1;
        }
        break;
    }

    if (do_free)
    {
        if(PREDICT_FALSE(spi_delete_session(spim, tspi, session)))
        {
            clib_warning ("spi del session is failed\n");
        }
    }
    else
    {
        switch (session->state_other)
        {
        case SPI_GENERAL_STATE_CLOSED:
        case SPI_GENERAL_STATE_TRANSMIT:
            {
                /*
                 * Check the timestamp, 
                 * if the interval between the last incoming pkt 
                 * is less than 10% of the timeout, submit a full timeout
                 */
                timeout = spi_search_exact_3tuple_timeout(spim, session);
                if (timeout == (u32)(~0))
                {
                    timeout = spim->spi_timeout_config.other;
                }

                if ((time_now - session->last_pkt_timestamp) > ((u64)session->transmit_timeout * 0.1))
                {
                     timeout = timeout - (u32)(time_now - session->last_pkt_timestamp);
                }
                session->transmit_timeout = timeout;
            }
            break;
        case SPI_GENERAL_STATE_IDLE:
        default:
            {
                timeout = 1;
            }
            break;
        }
        spi_submit_or_update_session_timer(tspi, session, timeout);
    }
}

/*
 *  Per worker process processing the spi expired session
 */
static uword
spi_worker_timer_input (vlib_main_t * vm,
                        vlib_node_runtime_t * rt,
                        vlib_frame_t * f)
{
    spi_main_t *spim = &spi_main;

    u16 thread_index = vm->thread_index;

    f64 time_now = vlib_time_now (vm);

    u32 *i;
    u32 num_expired = 0;
    u32 pool_index = 0;
    CLIB_UNUSED(u32 timer_id) = 0;

    spi_per_thread_data_t *tspi = &spim->per_thread_data[thread_index];

    spi_session_t *session = NULL;

    /* allow another interrupt to be queued */
    tspi->interrupt_is_pending = 0;

    if (PREDICT_FALSE(!spim->enabled)) 
    {
        return 0;
    }

    tspi->expired_session_per_worker = tw_timer_expire_timers_vec_16t_2w_512sl (tspi->timers_per_worker,
                                              time_now, 
                                              tspi->expired_session_per_worker);

    vec_foreach (i, tspi->expired_session_per_worker)
    {
        pool_index = (*i) & ((1 << (32 - LOG2_TW_TIMERS_PER_OBJECT)) - 1);
        timer_id = (*i) >> (32 - LOG2_TW_TIMERS_PER_OBJECT);

        if (pool_is_free_index (tspi->sessions, pool_index))
        {
            clib_warning ("session is %u is freed already\n", pool_index);
            num_expired++;
            continue;
        }

        session = pool_elt_at_index (tspi->sessions, pool_index);

        session->session_timer_handle = (~0);

        SPI_THREAD_LOCK(tspi);

        switch(session->proto)
        {
        case IP_PROTOCOL_TCP:
            spi_aging_tcp_session(spim, tspi, session, time_now);
            break;
        case IP_PROTOCOL_ICMP:
        case IP_PROTOCOL_ICMP6:
            spi_aging_icmp_session(spim, tspi, session, time_now);
            break;
        case IP_PROTOCOL_UDP:
            spi_aging_udp_session(spim, tspi, session, time_now);
            break;
        default:
            spi_aging_other_session(spim, tspi, session, time_now);
            break;
        }

        SPI_THREAD_UNLOCK(tspi);

        num_expired++;
        if (num_expired > SPI_TW_TIMER_PER_PROCESS_MAX_EXPIRATIONS)
            break;
    }
    if (num_expired)
        vec_delete (tspi->expired_session_per_worker, num_expired, 0);

    return num_expired;
}

/*
 * Main-core process, sending an interrupt to the per worker input
 * process that spins the per worker timer wheel.
 */
static uword
spi_timer_process (vlib_main_t * vm, vlib_node_runtime_t * rt, vlib_frame_t * f)
{
    spi_main_t *spim = &spi_main;

    uword event_type = 0, *event_data = NULL;

    f64 cpu_cps = vm->clib_time.clocks_per_second;

    u64 max_timer_wait_interval = cpu_cps / SPI_TW_TIMER_PROCESS_DEFAULT_FREQUENCY;

    spim->spi_current_aging_process_timer_wait_frequency = SPI_TW_TIMER_PROCESS_DEFAULT_FREQUENCY;
    spim->spi_current_aging_process_timer_wait_interval = max_timer_wait_interval;

    u8 skip_send_interrupt;

    while (1)
    {
        skip_send_interrupt = 0;

        /* Wait for Godot... */
        if (spim->enabled)
        {
            vlib_process_wait_for_event_or_clock (vm, (max_timer_wait_interval / cpu_cps));
            event_type = vlib_process_get_events (vm, &event_data);
        }
        else
        {
            vlib_process_wait_for_event (vm);
            event_type = vlib_process_get_events (vm, &event_data);
        }

        switch (event_type)
        {
        case ~0:
            /* nothing to do */
            break;
        case SPI_AGING_PROCESS_RECONF:
            max_timer_wait_interval = cpu_cps / spim->spi_config.timer_process_frequency;
            spim->spi_current_aging_process_timer_wait_frequency = spim->spi_config.timer_process_frequency;
            spim->spi_current_aging_process_timer_wait_interval = max_timer_wait_interval;
            break;
        case SPI_AGING_PROCESS_DISABLE:
            skip_send_interrupt = 1;
            break;
        default:
            /* Nothing to do. */
            break;
        }

        if (!skip_send_interrupt)
        {
            /* Send an interrupt to each timer input node */
            send_interrupts_to_workers(vm, spim);
        }
        vec_reset_length (event_data);
    }
    return 0;
}

VLIB_REGISTER_NODE (spi_worker_timer_process_node) = {
  .function = spi_worker_timer_input,
  .name = "spi-worker-timer-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

VLIB_REGISTER_NODE (spi_timer_process_node) = {
  .function = spi_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "spi-timer-process",
  .n_errors = ARRAY_LEN (spi_aging_process_error_strings),
  .error_strings = spi_aging_process_error_strings,
  .n_next_nodes = 0,
  .next_nodes = {},
};
