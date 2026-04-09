/*
 * ha_sync.c - ha_sync plugin init and CLI
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ha_sync/ha_sync.h>
#include <vnet/api_errno.h>
#include <vnet/interface_funcs.h>
#include <vnet/feature/feature.h>

uword unformat_ip4_address (unformat_input_t *input, va_list *args);

ha_sync_main_t ha_sync_main;

static void
ha_sync_ack_fifo_reset (ha_sync_per_thread_data_t *ptd)
{
  if (ptd->ack_fifo)
    hqos_fifo_free (ptd->ack_fifo);
  ptd->ack_fifo = hqos_fifo_alloc (HA_SYNC_ACK_FIFO_SIZE, sizeof (u32));
}

static void
ha_sync_fast_msg_queue_reset (ha_sync_per_thread_data_t *ptd)
{
  while (clib_fifo_elts (ptd->fast_msg_queue) > 0)
    {
      ha_sync_fast_msg_t msg;
      clib_fifo_sub1 (ptd->fast_msg_queue, msg);
      vec_free (msg.payload);
    }
  clib_fifo_free (ptd->fast_msg_queue);
  ptd->fast_msg_queue = 0;
  clib_fifo_validate (ptd->fast_msg_queue, 1024);
}

static void
ha_sync_fast_msg_queue_free (ha_sync_per_thread_data_t *ptd)
{
  while (clib_fifo_elts (ptd->fast_msg_queue) > 0)
    {
      ha_sync_fast_msg_t msg;
      clib_fifo_sub1 (ptd->fast_msg_queue, msg);
      vec_free (msg.payload);
    }
  clib_fifo_free (ptd->fast_msg_queue);
  ptd->fast_msg_queue = 0;
}

static void
ha_sync_response_batches_reset (ha_sync_per_thread_data_t *ptd, u32 n_threads)
{
  u32 i;

  vec_validate (ptd->response_batches, n_threads - 1);
  for (i = 0; i < n_threads; i++)
    {
      vec_reset_length (ptd->response_batches[i].seqs);
      ptd->response_batches[i].in_active_list = 0;
      ptd->response_batches[i].first_enqueue_time = 0;
    }
  vec_reset_length (ptd->response_batch_active_threads);
}

static void
ha_sync_response_batches_free (ha_sync_per_thread_data_t *ptd)
{
  ha_sync_ack_batch_t *batch;

  vec_foreach (batch, ptd->response_batches)
    vec_free (batch->seqs);
  vec_free (ptd->response_batches);
  ptd->response_batches = 0;
  vec_free (ptd->response_batch_active_threads);
  ptd->response_batch_active_threads = 0;
}

static void
ha_sync_resources_init (ha_sync_main_t *hsm)
{
  u32 n_threads;
  ha_sync_per_thread_data_t *ptd;

  n_threads = vlib_get_n_threads ();
  vec_validate (hsm->per_thread_data, n_threads - 1);
  vec_foreach (ptd, hsm->per_thread_data)
  {
    if (!ptd->data)
      vec_validate (ptd->data, HA_SYNC_MTU - 1);
    if (!ptd->spare_data)
      vec_validate (ptd->spare_data, HA_SYNC_MTU - 1);
    if (ptd->data)
      vec_reset_length (ptd->data);
    if (ptd->spare_data)
      vec_reset_length (ptd->spare_data);
    ptd->session_count = 0;

    if (!ptd->tx_pool)
      pool_alloc (ptd->tx_pool, HA_SYNC_DEFAULT_POOL_SIZE);
    if (!ptd->seq_to_pool_index)
      ptd->seq_to_pool_index =
        hash_create (HA_SYNC_DEFAULT_POOL_SIZE, sizeof (uword));
    if (!ptd->timer_wheel.timers)
      tw_timer_wheel_init_16t_2w_512sl (&ptd->timer_wheel, NULL,
                                        HA_SYNC_TIMER_WHEEL_INTERVAL_SEC,
                                        8192);

    clib_fifo_free (ptd->pending_fifo);
    ptd->pending_fifo = 0;
    clib_fifo_validate (ptd->pending_fifo, HA_SYNC_DEFAULT_POOL_SIZE);

    clib_fifo_free (ptd->retry_fifo);
    ptd->retry_fifo = 0;
    clib_fifo_validate (ptd->retry_fifo, HA_SYNC_DEFAULT_POOL_SIZE);
    ha_sync_ack_fifo_reset (ptd);
    vec_reset_length (ptd->ack_drain_vec);
    ptd->ack_wakeup_pending = 0;
    ptd->next_request_send_time = 0;
    ha_sync_response_batches_reset (ptd, n_threads);

    ha_sync_fast_msg_queue_reset (ptd);

    vec_free (ptd->timer_expired_vec);
    ptd->timer_expired_vec = 0;
  }
}

void
ha_sync_release_resources ()
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_data_t *ptd;

  ha_sync_tx_pool_free ();

  vec_foreach (ptd, hsm->per_thread_data)
  {
    vec_free (ptd->data);
    vec_free (ptd->spare_data);
    vec_free (ptd->pending_fifo);
    vec_free (ptd->retry_fifo);
    vec_free (ptd->ack_drain_vec);
    ha_sync_fast_msg_queue_free (ptd);
    vec_free (ptd->timer_expired_vec);
    hqos_fifo_free (ptd->ack_fifo);
    ptd->ack_fifo = 0;
    ha_sync_response_batches_free (ptd);
    if (ptd->timer_wheel.timers)
      tw_timer_wheel_free_16t_2w_512sl (&ptd->timer_wheel);
  }
  vec_free (hsm->per_thread_data);
  hsm->per_thread_data = 0;

  hsm->connection_established = 0;
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
  ha_sync_update_all_contexts ();
}

void
ha_sync_reset_runtime_state ()
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_data_t *ptd;

  if (vlib_get_thread_index () != 0)
  {
    clib_warning ("ha_sync_reset_runtime_state must run on main thread");
    return;
  }

  vlib_worker_thread_barrier_sync (vm);
  ha_sync_pool_clear_keep ();
  hsm->snapshot_sequence = 0;
  hsm->snapshot_triggered_for_connection = 0;

  vec_foreach (ptd, hsm->per_thread_data)
  {
    if (!ptd->data)
      vec_validate (ptd->data, HA_SYNC_MTU - 1);
    if (!ptd->spare_data)
      vec_validate (ptd->spare_data, HA_SYNC_MTU - 1);
    if (ptd->data)
      vec_reset_length (ptd->data);
    if (ptd->spare_data)
      vec_reset_length (ptd->spare_data);
    ptd->session_count = 0;
    clib_fifo_free (ptd->pending_fifo);
    ptd->pending_fifo = 0;
    clib_fifo_validate (ptd->pending_fifo, HA_SYNC_DEFAULT_POOL_SIZE);
    clib_fifo_free (ptd->retry_fifo);
    ptd->retry_fifo = 0;
    clib_fifo_validate (ptd->retry_fifo, HA_SYNC_DEFAULT_POOL_SIZE);
    ha_sync_ack_fifo_reset (ptd);
    vec_reset_length (ptd->ack_drain_vec);
    ptd->ack_wakeup_pending = 0;
    ptd->next_request_send_time = 0;
    ha_sync_response_batches_reset (ptd, vec_len (hsm->per_thread_data));
    ha_sync_fast_msg_queue_reset (ptd);
    vec_free (ptd->timer_expired_vec);
    ptd->timer_expired_vec = 0;
    if (ptd->timer_wheel.timers)
      tw_timer_wheel_free_16t_2w_512sl (&ptd->timer_wheel);
    tw_timer_wheel_init_16t_2w_512sl (&ptd->timer_wheel, NULL,
                                      HA_SYNC_TIMER_WHEEL_INTERVAL_SEC,
                                      8192);
    ptd->last_flush_time = 0;
  }
  vlib_worker_thread_barrier_release (vm);
}

static_always_inline void
ha_sync_refresh_config_ready (ha_sync_main_t *hsm)
{
  hsm->config_ready =
    hsm->src_is_set && hsm->peer_is_set && hsm->sw_if_index_is_set;
}

static_always_inline void
ha_sync_arm_hello_if_ready (vlib_main_t *vm, ha_sync_main_t *hsm)
{
  if (hsm->enabled && hsm->config_ready)
    {
      hsm->hello_retry_count = 0;
      hsm->next_hello_time = vlib_time_now (vm);
    }
}

static_always_inline void
ha_sync_clear_connection_state (ha_sync_main_t *hsm)
{
  hsm->connection_established = 0;
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
}

static_always_inline clib_error_t *
ha_sync_cli_return_api_error (i32 rv)
{
  if (rv == 0)
    return 0;
  return clib_error_return (0, "%U", format_vnet_api_errno, rv);
}

int
ha_sync_apply_enable_disable (u8 enable)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_global_main_t *vgm = vlib_get_global_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  int i;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (vm);
  if (enable)
    {
      ha_sync_resources_init (hsm);
      hsm->enabled = 1;
      ha_sync_arm_hello_if_ready (vm, hsm);
      ha_sync_update_all_contexts ();

      vec_foreach_index (i, vgm->vlib_mains)
        {
          vlib_node_set_state (vgm->vlib_mains[i],
                               ha_sync_output_worker_node.index,
                               i == 0 ? VLIB_NODE_STATE_INTERRUPT :
                                        VLIB_NODE_STATE_POLLING);
        }
    }
  else
    {
      hsm->enabled = 0;
      hsm->fib_index = 0;
      hsm->src_port = HA_SYNC_UDP_PORT;
      hsm->dst_port = HA_SYNC_UDP_PORT;
      hsm->domain_id = HA_SYNC_DEFAULT_DOMAIN_ID;
      hsm->packet_size = HA_SYNC_MAX_TX_PAYLOAD;
      hsm->heartbeat_interval_sec = HA_SYNC_HEARTBEAT_INTERVAL_SEC;
      hsm->heartbeat_max_fail_counts = HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS;
      hsm->retransmit_interval = HA_SYNC_RETRANSMIT_INTERVAL_SEC;
      hsm->retransmit_times = HA_SYNC_RETRANSMIT_TIMES;
      hsm->request_pacing_interval_sec =
        HA_SYNC_DEFAULT_REQUEST_PACING_INTERVAL_SEC;
      hsm->request_pacing_pkts_per_interval =
        HA_SYNC_DEFAULT_REQUEST_PACING_PKTS;
      ha_sync_release_resources ();
      ha_sync_update_all_contexts ();

      vec_foreach_index (i, vgm->vlib_mains)
        {
          vlib_node_set_state (vgm->vlib_mains[i],
                               ha_sync_output_worker_node.index,
                               VLIB_NODE_STATE_DISABLED);
        }
    }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

int
ha_sync_apply_add_del_src_address (u8 is_add, const ip4_address_t *addr)
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;
  if (is_add && !addr)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      hsm->src_address = *addr;
      hsm->src_is_set = 1;
      ha_sync_refresh_config_ready (hsm);
      ha_sync_update_all_contexts ();
      ha_sync_arm_hello_if_ready (vm, hsm);
      return 0;
    }

  hsm->src_is_set = 0;
  hsm->src_address.as_u32 = 0;
  ha_sync_refresh_config_ready (hsm);
  ha_sync_clear_connection_state (hsm);
  ha_sync_reset_runtime_state ();
  ha_sync_update_all_contexts ();
  return 0;
}

int
ha_sync_apply_add_del_peer_address (u8 is_add, const ip4_address_t *addr)
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  u8 peer_changed;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;
  if (is_add && !addr)
    return VNET_API_ERROR_INVALID_VALUE;

  if (!is_add)
    {
      hsm->peer_is_set = 0;
      hsm->peer_address.as_u32 = 0;
      ha_sync_refresh_config_ready (hsm);
      ha_sync_clear_connection_state (hsm);
      ha_sync_reset_runtime_state ();
      ha_sync_update_all_contexts ();
      return 0;
    }

  peer_changed = (!hsm->peer_is_set || hsm->peer_address.as_u32 != addr->as_u32);
  hsm->peer_address = *addr;
  hsm->peer_is_set = 1;
  ha_sync_refresh_config_ready (hsm);

  if (peer_changed)
    {
      hsm->connection_established = 0;
      hsm->snapshot_trigger_pending = 0;
      ha_sync_reset_runtime_state ();
    }

  ha_sync_update_all_contexts ();
  ha_sync_arm_hello_if_ready (vm, hsm);
  return 0;
}

int
ha_sync_apply_add_del_interface (u8 is_add, u32 sw_if_index)
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  vnet_main_t *vnm = vnet_get_main ();

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_add)
    {
      if (!vnm || !vnet_sw_interface_is_api_valid (vnm, sw_if_index))
        return VNET_API_ERROR_INVALID_SW_IF_INDEX;

      if (hsm->sw_if_index_is_set && hsm->sw_if_index != sw_if_index)
        vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                     hsm->sw_if_index, 0, 0, 0);

      hsm->sw_if_index = sw_if_index;
      hsm->sw_if_index_is_set = 1;
      vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                   hsm->sw_if_index, 1, 0, 0);
      ha_sync_refresh_config_ready (hsm);
      ha_sync_update_all_contexts ();
      ha_sync_arm_hello_if_ready (vm, hsm);
      return 0;
    }

  if (hsm->sw_if_index_is_set)
    vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                 hsm->sw_if_index, 0, 0, 0);

  hsm->sw_if_index = ~0;
  hsm->sw_if_index_is_set = 0;
  ha_sync_refresh_config_ready (hsm);
  ha_sync_clear_connection_state (hsm);
  ha_sync_reset_runtime_state ();
  ha_sync_update_all_contexts ();
  return 0;
}

int
ha_sync_apply_set_config (u32 domain_id, u16 packet_size,
                          u32 retransmit_times,
                          u32 retransmit_interval_ms,
                          u32 heartbeat_interval_ms,
                          u32 heartbeat_max_fail_counts)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;
  if (packet_size == 0 || packet_size > HA_SYNC_MAX_TX_PAYLOAD)
    return VNET_API_ERROR_INVALID_VALUE;
  if (heartbeat_interval_ms == 0 || heartbeat_max_fail_counts == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  hsm->domain_id = domain_id;
  hsm->packet_size = packet_size;
  hsm->retransmit_times = retransmit_times;
  hsm->retransmit_interval = ((f64) retransmit_interval_ms) / 1000.0;
  hsm->heartbeat_interval_sec = ((f64) heartbeat_interval_ms) / 1000.0;
  hsm->heartbeat_max_fail_counts = heartbeat_max_fail_counts;
  return 0;
}

int
ha_sync_apply_set_request_pacing (u32 interval_ms, u32 pkts_per_interval)
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_data_t *ptd;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;
  if (interval_ms == 0 || pkts_per_interval == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (vm);
  hsm->request_pacing_interval_sec = ((f64) interval_ms) / 1000.0;
  hsm->request_pacing_pkts_per_interval = pkts_per_interval;
  vec_foreach (ptd, hsm->per_thread_data)
    ptd->next_request_send_time = 0;
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

int
ha_sync_apply_clear_request_pacing (void)
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_data_t *ptd;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  vlib_worker_thread_barrier_sync (vm);
  hsm->request_pacing_interval_sec = 0;
  hsm->request_pacing_pkts_per_interval = 0;
  vec_foreach (ptd, hsm->per_thread_data)
    ptd->next_request_send_time = 0;
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

int
ha_sync_apply_reset_config (void)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  if (vlib_get_thread_index () != 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hsm->enabled && hsm->sw_if_index_is_set)
    vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                 hsm->sw_if_index, 0, 0, 0);

  hsm->fib_index = 0;
  hsm->src_port = HA_SYNC_UDP_PORT;
  hsm->dst_port = HA_SYNC_UDP_PORT;
  hsm->domain_id = HA_SYNC_DEFAULT_DOMAIN_ID;
  hsm->packet_size = HA_SYNC_MAX_TX_PAYLOAD;
  hsm->heartbeat_interval_sec = HA_SYNC_HEARTBEAT_INTERVAL_SEC;
  hsm->heartbeat_max_fail_counts = HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS;
  hsm->retransmit_interval = HA_SYNC_RETRANSMIT_INTERVAL_SEC;
  hsm->retransmit_times = HA_SYNC_RETRANSMIT_TIMES;
  hsm->request_pacing_interval_sec =
    HA_SYNC_DEFAULT_REQUEST_PACING_INTERVAL_SEC;
  hsm->request_pacing_pkts_per_interval = HA_SYNC_DEFAULT_REQUEST_PACING_PKTS;

  hsm->src_address.as_u32 = 0;
  hsm->peer_address.as_u32 = 0;
  hsm->sw_if_index = ~0;
  hsm->src_is_set = 0;
  hsm->peer_is_set = 0;
  hsm->sw_if_index_is_set = 0;
  hsm->config_ready = 0;
  ha_sync_clear_connection_state (hsm);
  ha_sync_reset_runtime_state ();
  ha_sync_update_all_contexts ();
  return 0;
}

static clib_error_t *
ha_sync_control_command_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  int enable_disable = -1;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
        enable_disable = 1;
      else if (unformat (input, "disable"))
        enable_disable = 0;
      else
        return clib_error_return (0, "unknown input `%U`", format_unformat_error,
                                  input);
    }

  if (enable_disable < 0)
    return clib_error_return (0, "usage: ha_sync control <enable|disable>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_enable_disable ((u8) enable_disable));
}

static clib_error_t *
ha_sync_set_src_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  ip4_address_t ip4;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set src-address <ip4>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_add_del_src_address (1, &ip4));
}

static clib_error_t *
ha_sync_set_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  ip4_address_t ip4;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set peer-address <ip4>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_add_del_peer_address (1, &ip4));
}

static clib_error_t *
ha_sync_clear_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  return ha_sync_cli_return_api_error (
    ha_sync_apply_add_del_peer_address (0, 0));
}

static clib_error_t *
ha_sync_set_domain_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 domain_id;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%u", &domain_id))
    return clib_error_return (0, "usage: ha_sync set domain <domain-id>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_set_config (domain_id, hsm->packet_size,
                              hsm->retransmit_times,
                              (u32) (hsm->retransmit_interval * 1000.0),
                              (u32) (hsm->heartbeat_interval_sec * 1000.0),
                              hsm->heartbeat_max_fail_counts));
}

static clib_error_t *
ha_sync_set_packet_size_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 packet_size;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%u", &packet_size))
    return clib_error_return (0, "usage: ha_sync set packet_size <bytes>");

  if (packet_size == 0 || packet_size > HA_SYNC_MAX_TX_PAYLOAD)
    return clib_error_return (0, "packet_size must be in [1, %u]",
                              HA_SYNC_MAX_TX_PAYLOAD);

  return ha_sync_cli_return_api_error (
    ha_sync_apply_set_config (hsm->domain_id, (u16) packet_size,
                              hsm->retransmit_times,
                              (u32) (hsm->retransmit_interval * 1000.0),
                              (u32) (hsm->heartbeat_interval_sec * 1000.0),
                              hsm->heartbeat_max_fail_counts));
}

static clib_error_t *
ha_sync_set_retransmit_times_command_fn (vlib_main_t *vm,
                                         unformat_input_t *input,
                                         vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 times;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%u", &times))
    return clib_error_return (0, "usage: ha_sync set retransmit-times <n>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_set_config (hsm->domain_id, hsm->packet_size, times,
                              (u32) (hsm->retransmit_interval * 1000.0),
                              (u32) (hsm->heartbeat_interval_sec * 1000.0),
                              hsm->heartbeat_max_fail_counts));
}

static clib_error_t *
ha_sync_set_retransmit_interval_command_fn (vlib_main_t *vm,
                                            unformat_input_t *input,
                                            vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  f64 interval;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%f", &interval))
    return clib_error_return (0,
                              "usage: ha_sync set retransmit-interval <sec>");

  if (interval < 0)
    return clib_error_return (0, "retransmit-interval must be >= 0");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_set_config (hsm->domain_id, hsm->packet_size,
                              hsm->retransmit_times,
                              (u32) (interval * 1000.0),
                              (u32) (hsm->heartbeat_interval_sec * 1000.0),
                              hsm->heartbeat_max_fail_counts));
}

static clib_error_t *
ha_sync_set_request_pacing_command_fn (vlib_main_t *vm,
                                       unformat_input_t *input,
                                       vlib_cli_command_t *cmd)
{
  u32 interval_ms = 0;
  u32 pkts_per_interval = 0;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "interval %u", &interval_ms))
        ;
      else if (unformat (input, "pkts %u", &pkts_per_interval))
        ;
      else
        return clib_error_return (0, "unknown input `%U`",
                                  format_unformat_error, input);
    }

  if (interval_ms == 0 || pkts_per_interval == 0)
    return clib_error_return (
      0, "usage: ha_sync set request-pacing interval <ms> pkts <n>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_set_request_pacing (interval_ms, pkts_per_interval));
}

static clib_error_t *
ha_sync_clear_request_pacing_command_fn (vlib_main_t *vm,
                                         unformat_input_t *input,
                                         vlib_cli_command_t *cmd)
{
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  return ha_sync_cli_return_api_error (ha_sync_apply_clear_request_pacing ());
}

static clib_error_t *
ha_sync_set_intfc_command_fn (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 sw_if_index = ~0;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_vnet_sw_interface, hsm->vnet_main,
                 &sw_if_index))
    return clib_error_return (0, "usage: ha_sync set intfc <interface>");

  return ha_sync_cli_return_api_error (
    ha_sync_apply_add_del_interface (1, sw_if_index));
}

static clib_error_t *
ha_sync_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  vnet_main_t *vnm = vnet_get_main ();
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  vlib_cli_output (vm, "ha_sync:");
  vlib_cli_output (vm, "  enabled: %u", hsm->enabled);
  vlib_cli_output (vm, "  config_ready: %u", hsm->config_ready);
  vlib_cli_output (vm, "  src_address: %s%U",
                   hsm->src_is_set ? "" : "(unset) ",
                   format_ip4_address, &hsm->src_address);
  vlib_cli_output (vm, "  peer_address: %s%U",
                   hsm->peer_is_set ? "" : "(unset) ",
                   format_ip4_address, &hsm->peer_address);
  vlib_cli_output (vm, "  src_port: %u", hsm->src_port);
  vlib_cli_output (vm, "  dst_port: %u", hsm->dst_port);
  if (hsm->sw_if_index_is_set &&
      vnm &&
      vnet_sw_interface_is_api_valid (vnm, hsm->sw_if_index))
    vlib_cli_output (vm, "  intfc: %U",
                     format_vnet_sw_if_index_name, vnm,
                     hsm->sw_if_index);
  else if (hsm->sw_if_index_is_set)
    vlib_cli_output (vm, "  intfc: (invalid index %u)", hsm->sw_if_index);
  else
    vlib_cli_output (vm, "  intfc: (unset)");
  vlib_cli_output (vm, "  domain_id: %u", hsm->domain_id);
  vlib_cli_output (vm, "  packet_size: %u", hsm->packet_size);
  vlib_cli_output (vm, "  retransmit_times: %u", hsm->retransmit_times);
  vlib_cli_output (vm, "  retransmit_interval: %.3f",
                   hsm->retransmit_interval);
  if (hsm->request_pacing_interval_sec > 0 &&
      hsm->request_pacing_pkts_per_interval > 0)
    {
      vlib_cli_output (
        vm, "  request_pacing: enabled interval=%u ms pkts=%u (~%u pkt/s)",
        (u32) (hsm->request_pacing_interval_sec * 1000.0),
        hsm->request_pacing_pkts_per_interval,
        (u32) (hsm->request_pacing_pkts_per_interval /
               hsm->request_pacing_interval_sec));
    }
  else
    vlib_cli_output (vm, "  request_pacing: disabled");
  vlib_cli_output (vm, "  heartbeat_interval: %.3f",
                   hsm->heartbeat_interval_sec);
  vlib_cli_output (vm, "  heartbeat_max_fail_counts: %u",
                   hsm->heartbeat_max_fail_counts);
  vlib_cli_output (vm, "  connection_established: %u",
                   hsm->connection_established);
  vlib_cli_output (vm, "  snapshot_sequence: %u", hsm->snapshot_sequence);
  vlib_cli_output (vm, "  snapshot_trigger_pending: %u",
                   hsm->snapshot_trigger_pending);
  return 0;
}

static const char *ha_sync_stat_names[HA_SYNC_STAT_N] = {
  [HA_SYNC_STAT_TX] = "tx-total",
  [HA_SYNC_STAT_TX_REQUEST_NEW] = "tx-request-new",
  [HA_SYNC_STAT_TX_REQUEST_RETX] = "tx-request-retransmit",
  [HA_SYNC_STAT_TX_RESPONSE] = "tx-response",
  [HA_SYNC_STAT_TX_RESPONSE_BATCH_PKTS] = "tx-response-batch-pkts",
  [HA_SYNC_STAT_TX_RESPONSE_BATCH_ACKS] = "tx-response-batch-acks",
  [HA_SYNC_STAT_TX_HELLO] = "tx-hello",
  [HA_SYNC_STAT_TX_HELLO_RESPONSE] = "tx-hello-response",
  [HA_SYNC_STAT_TX_HEARTBEAT] = "tx-heartbeat",
  [HA_SYNC_STAT_RX] = "rx-total",
  [HA_SYNC_STAT_RX_MATCH] = "rx-udp-match",
  [HA_SYNC_STAT_RX_REQUEST] = "rx-request",
  [HA_SYNC_STAT_RX_RESPONSE] = "rx-response",
  [HA_SYNC_STAT_RX_RESPONSE_BATCH_PKTS] = "rx-response-batch-pkts",
  [HA_SYNC_STAT_RX_RESPONSE_BATCH_ACKS] = "rx-response-batch-acks",
  [HA_SYNC_STAT_RX_HELLO] = "rx-hello",
  [HA_SYNC_STAT_RX_HELLO_RESPONSE] = "rx-hello-response",
  [HA_SYNC_STAT_RX_HEARTBEAT] = "rx-heartbeat",
  [HA_SYNC_STAT_TX_NO_BUFFER] = "tx-no-buffer",
  [HA_SYNC_STAT_TX_POOL_MISS] = "tx-pool-miss",
  [HA_SYNC_STAT_TX_NO_PEER] = "tx-no-peer",
  [HA_SYNC_STAT_RETRY_EXCEEDED] = "retry-exceeded",
};

static clib_error_t *
ha_sync_stats_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u32 i;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  vlib_cli_output (vm, "ha_sync stats:");
  for (i = 0; i < HA_SYNC_STAT_N; i++)
    {
      const char *name =
        ha_sync_stat_names[i] ? ha_sync_stat_names[i] : "unknown";
      u64 value = clib_atomic_load_relax_n (&hsm->stats[i]);
      vlib_cli_output (vm, "  %-22s %llu", name,
                       (unsigned long long) value);
    }
  return 0;
}

static clib_error_t *
ha_sync_stats_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  vlib_worker_thread_barrier_sync (vm);
  clib_memset (hsm->stats, 0, sizeof (hsm->stats));
  vlib_worker_thread_barrier_release (vm);

  vlib_cli_output (vm, "ha_sync stats cleared");
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ha_sync_control_command, static) = {
  .path = "ha_sync control",
  .short_help = "ha_sync control <enable|disable>",
  .function = ha_sync_control_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_src_address_command, static) = {
  .path = "ha_sync set src-address",
  .short_help = "ha_sync set src-address <ip4>",
  .function = ha_sync_set_src_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_peer_address_command, static) = {
  .path = "ha_sync set peer-address",
  .short_help = "ha_sync set peer-address <ip4>",
  .function = ha_sync_set_peer_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_clear_peer_address_command, static) = {
  .path = "ha_sync clear peer-address",
  .short_help = "ha_sync clear peer-address",
  .function = ha_sync_clear_peer_address_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_domain_command, static) = {
  .path = "ha_sync set domain",
  .short_help = "ha_sync set domain <domain-id>",
  .function = ha_sync_set_domain_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_packet_size_command, static) = {
  .path = "ha_sync set packet_size",
  .short_help = "ha_sync set packet_size <bytes>",
  .function = ha_sync_set_packet_size_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_retransmit_times_command, static) = {
  .path = "ha_sync set retransmit-times",
  .short_help = "ha_sync set retransmit-times <n>",
  .function = ha_sync_set_retransmit_times_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_retransmit_interval_command, static) = {
  .path = "ha_sync set retransmit-interval",
  .short_help = "ha_sync set retransmit-interval <sec>",
  .function = ha_sync_set_retransmit_interval_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_request_pacing_command, static) = {
  .path = "ha_sync set request-pacing",
  .short_help = "ha_sync set request-pacing interval <ms> pkts <n>",
  .function = ha_sync_set_request_pacing_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_clear_request_pacing_command, static) = {
  .path = "ha_sync clear request-pacing",
  .short_help = "ha_sync clear request-pacing",
  .function = ha_sync_clear_request_pacing_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_set_intfc_command, static) = {
  .path = "ha_sync set intfc",
  .short_help = "ha_sync set intfc <interface>",
  .function = ha_sync_set_intfc_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_show_command, static) = {
  .path = "ha_sync show",
  .short_help = "ha_sync show",
  .function = ha_sync_show_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_stats_show_command, static) = {
  .path = "ha_sync stats show",
  .short_help = "ha_sync stats show",
  .function = ha_sync_stats_show_command_fn,
};

VLIB_CLI_COMMAND (ha_sync_stats_clear_command, static) = {
  .path = "ha_sync stats clear",
  .short_help = "ha_sync stats clear",
  .function = ha_sync_stats_clear_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
ha_sync_init (vlib_main_t *vm)
{
  ha_sync_main_t *hsm = &ha_sync_main;

  hsm->vlib_main = vm;
  hsm->vnet_main = vnet_get_main ();
  hsm->enabled = 0;
  hsm->fib_index = 0;
  hsm->sw_if_index = ~0;
  hsm->sw_if_index_is_set = 0;
  hsm->src_address.as_u32 = clib_host_to_net_u32 (0x7f000001); /* 127.0.0.1 */
  hsm->src_is_set = 0;
  hsm->src_port = HA_SYNC_UDP_PORT;
  hsm->dst_port = HA_SYNC_UDP_PORT;
  hsm->domain_id = HA_SYNC_DEFAULT_DOMAIN_ID;
  hsm->packet_size = HA_SYNC_MAX_TX_PAYLOAD;
  hsm->heartbeat_interval_sec = HA_SYNC_HEARTBEAT_INTERVAL_SEC;
  hsm->heartbeat_max_fail_counts = HA_SYNC_HEARTBEAT_MAX_FAIL_COUNTS;
  hsm->peer_is_set = 0;
  hsm->config_ready = 0;
  hsm->peer_address.as_u32 = 0;
  hsm->num_registrations = 0;
  hsm->retransmit_interval = HA_SYNC_RETRANSMIT_INTERVAL_SEC;
  hsm->retransmit_times = HA_SYNC_RETRANSMIT_TIMES;
  hsm->request_pacing_interval_sec = HA_SYNC_DEFAULT_REQUEST_PACING_INTERVAL_SEC;
  hsm->request_pacing_pkts_per_interval = HA_SYNC_DEFAULT_REQUEST_PACING_PKTS;
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
  ha_sync_update_all_contexts ();

  return 0;
}

VLIB_INIT_FUNCTION (ha_sync_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "HA sync framework plugin",
};
/* *INDENT-ON* */
