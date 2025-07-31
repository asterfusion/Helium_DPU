/*
 * spi.c: Statful Packet Inspection 
 *
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

#include <vpp/app/version.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vnet/ip/ip.h>
#include <vnet/ip/reass/ip4_sv_reass.h>
#include <vnet/ip/reass/ip6_sv_reass.h>

#include <vlib/threads.h>
#include <spi/spi.h>
#include <spi/spi_inline.h>

spi_main_t spi_main;

#define spi_init_simple_counter(c, n, sn, i)                                  \
  do                                                                          \
    {                                                                         \
      c.name = n;                                                             \
      c.stat_segment_name = sn;                                               \
      vlib_validate_simple_counter (&c, i);                                   \
      vlib_zero_simple_counter (&c, i);                                       \
    }                                                                         \
  while (0);

int spi_get_session_number(counter_t *totol_session, 
                           counter_t *ip4_session, counter_t ip4_proto_session[SPI_SESSION_TYPE_MAX], 
                           counter_t *ip6_session, counter_t ip6_proto_session[SPI_SESSION_TYPE_MAX])
{
    spi_main_t *spim = &spi_main;

    if (totol_session)
        *totol_session = vlib_get_simple_counter(&spim->total_sessions_counter, 0);

    if (ip4_session)
        *ip4_session = vlib_get_simple_counter(&spim->session_ip_type_counter, 0);

    if (ip4_proto_session)
    {
#define _(btype, ltype) \
        ip4_proto_session[SPI_SESSION_TYPE_##btype] = vlib_get_simple_counter(&spim->session_type_counter[SPI_SESSION_TYPE_##btype], 0);
        foreach_spi_support_session_type
#undef _
    }

    if (ip6_session)
        *ip6_session = vlib_get_simple_counter(&spim->session_ip_type_counter, 1);

    if (ip6_proto_session)
    {
#define _(btype, ltype) \
        ip6_proto_session[SPI_SESSION_TYPE_##btype] = vlib_get_simple_counter(&spim->session_type_counter[SPI_SESSION_TYPE_##btype], 1);
        foreach_spi_support_session_type
#undef _
    }

    return 0;
}

int spi_exact_3tuple_timeout_add_del(ip46_address_t *ip, ip46_type_t type, u8 proto, u16 port, u32 timeout, bool is_add)
{

    int rv = 0;

    spi_main_t *spim = &spi_main;

    spi_exact_3tuple_timeout_entry_t entry;

    clib_memset(&entry, 0, sizeof(spi_exact_3tuple_timeout_entry_t));

    if (type == IP46_TYPE_ANY)
        return VNET_API_ERROR_INVALID_ADDRESS_FAMILY;

    entry.key.proto = proto;
    entry.key.port  = port;

    if (type == IP46_TYPE_IP6)
    {
        entry.key.is_ip6 = 1;

        entry.key.ip6.addr.as_u64[0] = ip->ip6.as_u64[0];
        entry.key.ip6.addr.as_u64[1] = ip->ip6.as_u64[1];
    }
    else
    {
        entry.key.ip4.addr.as_u32 = ip->ip4.as_u32;
    }

    entry.value.transmit_timeout = timeout;

    rv = clib_bihash_add_del_24_8(&spim->exact_3tuple_timeout_table, &entry.kv, is_add ? 1 : 0);
    if (rv)
    {
        clib_warning ("SPI exact-3tuple-timeout Table: %s entry error", is_add ? "add" : "del");
        return VNET_API_ERROR_UNSPECIFIED;
    }
    return rv;
}

void spi_reset_timeouts ()
{
    spi_main_t *spim = &spi_main;

#define _(type, timeout) spim->spi_timeout_config.type = timeout;
    foreach_spi_timeout_def
#undef _
}

void spi_timeout_update (u8 use_default, spi_timeouts_config_t *spi_timeout_config)
{
    spi_main_t *spim = &spi_main;

#define _(type, timeout) \
    if (spi_timeout_config->type)  \
        spim->spi_timeout_config.type = spi_timeout_config->type; \
    else \
        if (use_default) spim->spi_timeout_config.type = timeout;

    foreach_spi_timeout_def
#undef _
}

static int
spi_handoff_node_enable_disable (u32 sw_if_index, int is_enable)
{
    int rv = 0;
    rv = vnet_feature_enable_disable ("ip4-unicast",
                                       "spi-ip4-input-worker-handoff",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip4-input-worker-handoff on ip4-unicast feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    rv = vnet_feature_enable_disable ("ip4-output",
                                       "spi-ip4-output-worker-handoff",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip4-output-worker-handoff on ip4-output feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }

    rv = vnet_feature_enable_disable ("ip6-unicast",
                                       "spi-ip6-input-worker-handoff",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip6-input-worker-handoff on ip6-unicast feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    rv = vnet_feature_enable_disable ("ip6-output",
                                       "spi-ip6-output-worker-handoff",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip6-output-worker-handoff on ip6-output feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    return 0;
}

static int
spi_node_enable_disable (u32 sw_if_index, int is_enable)
{
    int rv = 0;
    rv = vnet_feature_enable_disable ("ip4-unicast",
                                      "spi-ip4-input-node",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip4-input-node on ip4-unicast feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    rv = vnet_feature_enable_disable ("ip4-output",
                                       "spi-ip4-output-node",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip4-output-node on ip4-output feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }

    rv = vnet_feature_enable_disable ("ip6-unicast",
                                       "spi-ip6-input-node",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip6-input-node on ip6-unicast feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    rv = vnet_feature_enable_disable ("ip6-output",
                                       "spi-ip6-output-node",
                                       sw_if_index, is_enable, 0, 0);
    if (rv)
    {
        clib_warning ("Could not %s spi-ip6-output-node on ip6-output feature", 
                    is_enable ? "enable" : "disable");
        return rv;
    }
    return 0;
}

static int
spi_features_node_enable (u8 handoff_enabled)
{
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;
    vnet_sw_interface_t *si;
    u32 sw_if_index = ~0;
    int rv = 0;

    pool_foreach (si, im->sw_interfaces)
    {
        sw_if_index = si->sw_if_index;

        //need enable ip4 sv reass
        rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
        if (rv)
        {
            clib_warning("ip4_sv_reass_enable_disable_with_refcnt enable failed");
        }
        if (ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 1))
        {
            clib_warning("ip4_sv_reass_output_enable_disable_with_refcnt enable failed");
        }
        //need enable ip6 sv reass
        rv = ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
        if (rv)
        {
            clib_warning("ip6_sv_reass_enable_disable_with_refcnt enable failed");
        }
        if(handoff_enabled)
        {
            rv = spi_handoff_node_enable_disable (sw_if_index, 1);
            if (rv)
            {
                clib_warning("spi_handoff_node_enable_disable enable failed");
            }
        }
        else 
        {
            rv = spi_node_enable_disable (sw_if_index, 1);
            if (rv)
            {
                clib_warning("spi_node_enable_disable enable failed");
            }
        }
    }
    return rv;
}

static int
spi_features_node_disable ()
{
    spi_main_t *spim = &spi_main;
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;
    vnet_sw_interface_t *si;
    u32 sw_if_index = ~0;
    int rv = 0;

    pool_foreach (si, im->sw_interfaces)
    {
        sw_if_index = si->sw_if_index;

        //need disable ip4 sv reass
        rv = ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
        if (rv)
        {
            clib_warning("ip4_sv_reass_enable_disable_with_refcnt disable failed");
        }
        if (ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 0))
        {
            clib_warning("ip4_sv_reass_output_enable_disable_with_refcnt disable failed");
        }
        //need disable ip6 sv reass
        rv = ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, 0);
        if (rv)
        {
            clib_warning("ip6_sv_reass_enable_disable_with_refcnt disable failed");
        }
        if(spim->spi_config.handoff_enabled)
        {
            rv = spi_handoff_node_enable_disable (sw_if_index, 0);
            if (rv)
            {
                clib_warning("spi_handoff_node_enable_disable disable failed");
            }
        }
        else
        {
            rv = spi_node_enable_disable (sw_if_index, 0);
            if (rv)
            {
                clib_warning("spi_node_enable_disable disable failed");
            }
        }
    }
    return rv;
}

static int 
spi_worker_resource_init (spi_per_thread_data_t *tspi, u32 max_session, u8 handoff_enabled)
{
    //init session pool
    pool_init_fixed (tspi->sessions, max_session);
    tspi->max_session = max_session;

    //init tw timer 
    tspi->timers_per_worker = clib_mem_alloc (sizeof (TWT (tw_timer_wheel)));
    tw_timer_wheel_init_16t_2w_512sl (tspi->timers_per_worker, 
            NULL, 1.0, 
            SPI_TW_TIMER_PER_PROCESS_MAX_EXPIRATIONS);

    vec_prealloc(tspi->expired_session_per_worker, SPI_TW_TIMER_PER_PROCESS_MAX_EXPIRATIONS);

    if (!handoff_enabled)
    {
        clib_spinlock_init (&tspi->session_change_lock);
    }
    return 0;
}

static int 
spi_worker_resource_deinit (spi_main_t *spim, spi_per_thread_data_t *tspi)
{
    spi_session_t *i;

    //free session pool
    pool_foreach (i, tspi->sessions)
    {
        spi_delete_session(spim, tspi, i);
    }
    pool_free (tspi->sessions);

    //free tw timer
    tw_timer_wheel_free_16t_2w_512sl (tspi->timers_per_worker);
    clib_mem_free(tspi->timers_per_worker);
    tspi->timers_per_worker = NULL;
    vec_free(tspi->expired_session_per_worker);

    if(!spim->spi_config.handoff_enabled)
    {
        clib_spinlock_free (&tspi->session_change_lock);
    }

    return 0;
}

static int
spi_session_resource_init (spi_main_t *spim, spi_config_t *config)
{
    spi_per_thread_data_t *tspi;
    u32 ii;

    u32 spi_bihash_bucket = spi_calc_bihash_buckets(config->max_sessions_per_thread);
    clib_bihash_init_48_8 (&spim->session_table, "spi-session-hash", 
                           clib_max (1, spim->num_workers) * 2 * spi_bihash_bucket, 
                           0);
    clib_bihash_set_kvp_format_fn_48_8 (&spim->session_table, format_spi_session_kvp);

    vec_foreach_index (ii, spim->per_thread_data)
    {
        tspi = &spim->per_thread_data[ii];
        clib_memset(tspi, 0, sizeof(spi_per_thread_data_t));
        tspi->thread_index = ii;
        spi_worker_resource_init (tspi, config->max_sessions_per_thread, config->handoff_enabled);
    }
    return 0;
}

static int
spi_session_resource_deinit (spi_main_t *spim)
{
    spi_per_thread_data_t *tspi;

    vec_foreach (tspi, spim->per_thread_data)
    {
        spi_worker_resource_deinit (spim, tspi);
    }

    clib_bihash_free_48_8 (&spim->session_table);

    return 0;
}

int spi_session_proto_enable_disable(spi_session_type_e type, bool is_enable)
{
    spi_main_t *spim = &spi_main;

    switch(type)
    {
#define _(btype, ltype) \
    case SPI_SESSION_TYPE_##btype: \
        spim->ltype##_enable = is_enable ? 1 : 0; \
        break;
    foreach_spi_support_session_type
#undef _
    default:
        return VNET_API_ERROR_INVALID_VALUE;
    }
    return 0;
}

int spi_feature_enable (spi_config_t *config)
{
    int rc, error = 0;
    vlib_main_t *vm = vlib_get_main ();
    spi_main_t *spim = &spi_main;

    vlib_node_t *node = NULL;

    if (PREDICT_FALSE (spim->enabled))
	{
        clib_warning ("SPI feature already enabled");
        return VNET_API_ERROR_FEATURE_ALREADY_ENABLED;
    }                                                                    

    if (!config->max_sessions_per_thread)
        config->max_sessions_per_thread = SPI_DEFAULT_MAX_SESSION_PER_THREAD;

    if (!config->timer_process_frequency)
        config->timer_process_frequency = SPI_TW_TIMER_PROCESS_DEFAULT_FREQUENCY;

    if (config->handoff_enabled)
    {
        if (spim->fq_ip4_input_index == ~0)
        {
            node = vlib_get_node_by_name (vm, (u8 *) "spi-ip4-input-node");
            spim->fq_ip4_input_index = vlib_frame_queue_main_init (node->index, 0);
        }
        if (spim->fq_ip4_output_index == ~0)
        {
            node = vlib_get_node_by_name (vm, (u8 *) "spi-ip4-output-node");
            spim->fq_ip4_output_index = vlib_frame_queue_main_init (node->index, 0);
        }
        if (spim->fq_ip6_input_index == ~0)
        {
            node = vlib_get_node_by_name (vm, (u8 *) "spi-ip6-input-node");
            spim->fq_ip6_input_index = vlib_frame_queue_main_init (node->index, 0);
        }
        if (spim->fq_ip6_output_index == ~0)
        {
            node = vlib_get_node_by_name (vm, (u8 *) "spi-ip6-output-node");
            spim->fq_ip6_output_index = vlib_frame_queue_main_init (node->index, 0);
        }
    }
    else 
    {
        spim->fq_ip4_input_index = ~0;
        spim->fq_ip4_output_index = ~0;
        spim->fq_ip6_input_index = ~0;
        spim->fq_ip6_output_index = ~0;
    }

    vlib_zero_simple_counter (&spim->total_sessions_counter, 0);
    vlib_zero_simple_counter (&spim->session_ip_type_counter, 0);
    vlib_zero_simple_counter (&spim->session_ip_type_counter, 1);
#define _(btype, ltype) \
    vlib_zero_simple_counter (&spim->session_type_counter[SPI_SESSION_TYPE_##btype], 0); \
    vlib_zero_simple_counter (&spim->session_type_counter[SPI_SESSION_TYPE_##btype], 1);
        foreach_spi_support_session_type
#undef _

    rc = spi_session_resource_init (spim, config);
    if (rc)
        error = VNET_API_ERROR_BUG;

    rc = spi_features_node_enable (config->handoff_enabled);
    if (rc)
        error = VNET_API_ERROR_BUG;

    memcpy(&spim->spi_config, config, sizeof(spi_config_t));

    spim->enabled = 1;

    vlib_process_signal_event (vm, spim->spi_session_timer_process_node_index, SPI_AGING_PROCESS_RECONF, 0);

    return error;
}

int spi_feature_disable ()
{
    int rc, error = 0;
    spi_main_t *spim = &spi_main;
    vlib_main_t *vm = vlib_get_main ();

    if (PREDICT_FALSE (!spim->enabled))                                   
    {                                                                     
        clib_warning ("SPI feature already disable");
        return VNET_API_ERROR_FEATURE_ALREADY_DISABLED;                     
    }                                                                     

    spim->enabled = 0;

    vlib_process_signal_event (vm, spim->spi_session_timer_process_node_index, SPI_AGING_PROCESS_DISABLE, 0);

    rc = spi_features_node_disable ();
    if (rc)
        error = VNET_API_ERROR_BUG;

    rc = spi_session_resource_deinit (spim);
    if (rc)
        error = VNET_API_ERROR_BUG;

    spim->fq_ip4_input_index = ~0;
    spim->fq_ip4_output_index = ~0;
    spim->fq_ip6_input_index = ~0;
    spim->fq_ip6_output_index = ~0;

    clib_memset (&spim->spi_config, 0, sizeof (spi_config_t));

    return error;
}


clib_error_t *
spi_worker_init (vlib_main_t * vm)
{
    //spi_main_t *spim = &spi_main;
    spi_runtime_t *rt;
    spi_handoff_runtime_t *handoff_rt;

#define SPI_RUNTIME_INIT_MACRO(x) \
    rt = vlib_node_get_runtime_data (vm, x.index); \
    clib_memset(rt, 0, sizeof(spi_runtime_t)); \
    vec_validate (rt->hashes, VLIB_FRAME_SIZE);  \
    vec_validate (rt->bufs, VLIB_FRAME_SIZE);  \
    vec_validate (rt->nexts, VLIB_FRAME_SIZE);  \
    vec_validate (rt->in_sw_if_indices, VLIB_FRAME_SIZE); \
    vec_validate (rt->out_sw_if_indices, VLIB_FRAME_SIZE); \
    vec_validate (rt->pkts, VLIB_FRAME_SIZE);  

    SPI_RUNTIME_INIT_MACRO(spi_ip4_input_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip6_input_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip4_output_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip6_output_node);
#undef SPI_RUNTIME_INIT_MACRO

#define SPI_RUNTIME_INIT_MACRO(x) \
    handoff_rt = vlib_node_get_runtime_data (vm, x.index); \
    clib_memset(handoff_rt, 0, sizeof(spi_handoff_runtime_t)); \
    vec_validate (handoff_rt->hashes, VLIB_FRAME_SIZE);  \
    vec_validate (handoff_rt->bufs, VLIB_FRAME_SIZE);  \
    vec_validate (handoff_rt->thread_indices, VLIB_FRAME_SIZE);  \
    vec_validate (handoff_rt->pkts, VLIB_FRAME_SIZE);  

    SPI_RUNTIME_INIT_MACRO(spi_ip4_input_worker_handoff_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip6_input_worker_handoff_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip4_output_worker_handoff_node);
    SPI_RUNTIME_INIT_MACRO(spi_ip6_output_worker_handoff_node);
#undef SPI_RUNTIME_INIT_MACRO


    return 0;
}

VLIB_WORKER_INIT_FUNCTION (spi_worker_init);

static clib_error_t *
spi_init (vlib_main_t *vm)
{
    clib_error_t *error = 0;
    vlib_node_t *node = NULL;
    vlib_thread_registration_t *tr = NULL;
    uword *p;

    spi_main_t *spim = &spi_main;
    vlib_thread_main_t *tm = vlib_get_thread_main ();

    clib_memset (spim, 0, sizeof (*spim));

    /* Per thread data */
    spim->num_threads = tm->n_vlib_mains - 1;
    vec_validate (spim->per_thread_data, spim->num_threads);

    p = hash_get_mem (tm->thread_registrations_by_name, "workers");
    if (p)
    {
        tr = (vlib_thread_registration_t *) p[0];
        if (tr)
        {
            spim->num_workers = tr->count;
            spim->first_worker_index = tr->first_index;
        }
    }

    /* 3tuple exact timeout */
    clib_bihash_init_24_8 (&spim->exact_3tuple_timeout_table, "spi-3tuple-timeout", 
                           SPI_EXACT_3TUPLE_MAX_TIMEOUTS, 
                           0);
    clib_bihash_set_kvp_format_fn_24_8 (&spim->exact_3tuple_timeout_table, format_spi_exact_3tuple_timeout_kvp);


    /* Timeout config */
    spi_reset_timeouts ();

    /* Process Timer node index */
    node = vlib_get_node_by_name (vm, (u8 *) "spi-timer-process");
    spim->spi_session_timer_process_node_index = node->index;

    /* Worker Timer node index */
    node = vlib_get_node_by_name (vm, (u8 *) "spi-worker-timer-input");
    spim->spi_session_timer_worker_node_index = node->index;

    /* Worker handoff frame-queue index */
    spim->fq_ip4_input_index = ~0;
    spim->fq_ip4_output_index = ~0;
    spim->fq_ip6_input_index = ~0;
    spim->fq_ip6_output_index = ~0;

    /* counter */
    spi_init_simple_counter (spim->total_sessions_counter, "total-sessions", "/spi/total-sessions", 0);
    spi_init_simple_counter (spim->session_ip_type_counter, "ip-sessions", "/spi/ip-sessions", 1);
#define _(btype, ltype) spi_init_simple_counter (spim->session_type_counter[SPI_SESSION_TYPE_##btype], #ltype"-sessions", "/spi/"#ltype"-sessions", 1);
    foreach_spi_support_session_type
#undef _

    /* convenience init */
    spim->vnet_main = vnet_get_main();
    spim->ip4_main = &ip4_main;
    spim->ip6_main = &ip6_main;

    /* runtime init */
    spi_worker_init(vm);

    /* api init */
    error = spi_api_hookup (vm);

    return error;
}

VLIB_INIT_FUNCTION (spi_init);

static clib_error_t *
spi_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
    int rv;
    spi_main_t *spim = &spi_main;

    if (spim->enabled)
    {
        if (is_add)
        {
            //need enable ip4 sv reass
            if (ip4_sv_reass_enable_disable_with_refcnt (sw_if_index, 1))
            {
                clib_warning("ip4_sv_reass_enable_disable_with_refcnt enable failed");
            }
            if (ip4_sv_reass_output_enable_disable_with_refcnt (sw_if_index, 1))
            {
                clib_warning("ip4_sv_reass_output_enable_disable_with_refcnt enable failed");
            }
            //need enable ip6 sv reass
            rv = ip6_sv_reass_enable_disable_with_refcnt (sw_if_index, 1);
            if (rv)
            {
                clib_warning("ip6_sv_reass_enable_disable_with_refcnt enable failed");
            }

            if(spim->spi_config.handoff_enabled)
            {
                rv = spi_handoff_node_enable_disable (sw_if_index, 1);
                if (rv)
                {
                    clib_warning("spi_handoff_node_enable_disable enable failed");
                }
            }
            else
            {
                rv = spi_node_enable_disable (sw_if_index, 1);
                if (rv)
                {
                    clib_warning("spi_node_enable_disable enable failed");
                }
            }
        }
    }
    return 0;
}
VNET_SW_INTERFACE_ADD_DEL_FUNCTION (spi_sw_interface_add_del);

VLIB_NODE_FN (spi_default_node) (vlib_main_t * vm,
				 vlib_node_runtime_t * node,
				 vlib_frame_t * frame)
{
  return 0;
}

VLIB_REGISTER_NODE (spi_default_node) = {
  .name = "spi-default",
  .vector_size = sizeof (u32),
  .format_trace = 0,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = 0,
  .n_next_nodes = 1,
  .next_nodes = {
      [0] = "error-drop",
  },
};

/* external call */
__clib_export
spi_session_t *vlib_buffer_spi_get_session(vlib_buffer_t *b)
{
    spi_main_t *spim = &spi_main;
    spi_per_thread_data_t *tspi = NULL;
    spi_session_t *session = NULL;
    if (!(b->flags & VLIB_BUFFER_SPI_SESSION_VALID))
        return NULL;

    tspi = &spim->per_thread_data[vnet_buffer2(b)->spi.cached_session_thread];
    session =  pool_elt_at_index (tspi->sessions, vnet_buffer2(b)->spi.cached_session_index);

    return session->session_is_free ? NULL : session;
}
__clib_export
spi_session_t *vlib_buffer_spi_get_associated_session(vlib_buffer_t *b)
{
    spi_main_t *spim = &spi_main;
    spi_per_thread_data_t *tspi = NULL;
    spi_session_t *session = NULL;
    spi_session_t *associated_session = NULL;
    if (!(b->flags & VLIB_BUFFER_SPI_SESSION_VALID))
        return NULL;

    tspi = &spim->per_thread_data[vnet_buffer2(b)->spi.cached_session_thread];
    session =  pool_elt_at_index (tspi->sessions, vnet_buffer2(b)->spi.cached_session_index);

    if (session->session_is_free)
        return NULL;

    if (!session->associated_session_valid)
        return NULL;

    tspi = &spim->per_thread_data[session->associated_session.session_thread];
    associated_session =  pool_elt_at_index (tspi->sessions, session->associated_session.session_index);

    return associated_session->session_is_free ? NULL : session;
}
