/*
 * ha_sync.c - ha_sync plugin init and CLI
 */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <ha_sync/ha_sync.h>
#include <vnet/interface_funcs.h>
#include <vnet/feature/feature.h>

uword unformat_ip4_address (unformat_input_t *input, va_list *args);

ha_sync_main_t ha_sync_main;

static void
ha_sync_resources_init (ha_sync_main_t *hsm)
{
  u32 n_threads;
  ha_sync_per_thread_buffer_t *ptb;

  if (!hsm->ha_sync_tx_pool)
    pool_alloc (hsm->ha_sync_tx_pool, HA_SYNC_DEFAULT_POOL_SIZE);
  if (!hsm->seq_to_pool_index)
    hsm->seq_to_pool_index =
      hash_create (HA_SYNC_DEFAULT_POOL_SIZE, sizeof (uword));

  n_threads = vlib_get_n_threads ();
  vec_validate (hsm->per_thread_buffers, n_threads - 1);
  vec_foreach (ptb, hsm->per_thread_buffers)
  {
    vec_validate (ptb->data, HA_SYNC_MTU);
    vec_reset_length (ptb->data);
    ptb->session_count = 0;

    clib_fifo_free (ptb->pending_fifo);
    ptb->pending_fifo = 0;
    clib_fifo_validate (ptb->pending_fifo, HA_SYNC_DEFAULT_POOL_SIZE);

    clib_fifo_free (ptb->fast_msg_queue);
    ptb->fast_msg_queue = 0;
    clib_fifo_validate (ptb->fast_msg_queue, 1024);
  }

}

void
ha_sync_release_resources ()
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb;

  ha_sync_tx_pool_free ();

  vec_foreach (ptb, hsm->per_thread_buffers)
  {
    vec_free (ptb->data);
    vec_free (ptb->pending_fifo);
    vec_free (ptb->fast_msg_queue);
  }
  vec_free (hsm->per_thread_buffers);
  hsm->per_thread_buffers = 0;

  hsm->connection_established = 0;
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
  vec_free (hsm->timer_expired_vec);
  hsm->timer_expired_vec = 0;
  ha_sync_update_all_contexts ();
}

void
ha_sync_reset_runtime_state ()
{
  vlib_main_t *vm = vlib_get_main ();
  ha_sync_main_t *hsm = &ha_sync_main;
  ha_sync_per_thread_buffer_t *ptb;

  if (vlib_get_thread_index () != 0)
  {
    clib_warning ("ha_sync_reset_runtime_state must run on main thread");
    return;
  }

  vlib_worker_thread_barrier_sync (vm);
  ha_sync_pool_clear_keep ();
  hsm->snapshot_sequence = 0;
  vec_free (hsm->timer_expired_vec);
  hsm->timer_expired_vec = 0;
  hsm->snapshot_triggered_for_connection = 0;
  if (hsm->timer_wheel.timers)
    tw_timer_wheel_free_16t_2w_512sl (&hsm->timer_wheel);
  tw_timer_wheel_init_16t_2w_512sl (&hsm->timer_wheel, NULL, 0.1, 8192);

  vec_foreach (ptb, hsm->per_thread_buffers)
  {
    vec_reset_length (ptb->data);
    ptb->session_count = 0;
    clib_fifo_free (ptb->pending_fifo);
    ptb->pending_fifo = 0;
    clib_fifo_validate (ptb->pending_fifo, HA_SYNC_DEFAULT_POOL_SIZE);
    clib_fifo_free (ptb->fast_msg_queue);
    ptb->fast_msg_queue = 0;
    clib_fifo_validate (ptb->fast_msg_queue, 1024);
    ptb->last_flush_time = 0;
  }
  vlib_worker_thread_barrier_release (vm);
}

static clib_error_t *
ha_sync_control_command_fn (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
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

  vlib_worker_thread_barrier_sync (vm);
  if (enable_disable)
    {
      if (!hsm->timer_wheel.timers)
        tw_timer_wheel_init_16t_2w_512sl (&hsm->timer_wheel, NULL, 0.1, 8192);
      ha_sync_resources_init (hsm);
      hsm->enabled = 1;
      if (hsm->config_ready)
      {
        if (hsm->sw_if_index_is_set)
          vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                       hsm->sw_if_index, 1, 0, 0);
        hsm->hello_retry_count = 0;
        hsm->next_hello_time = vlib_time_now (vm);
      }
      ha_sync_update_all_contexts ();
    }
  else
    {
      hsm->enabled = 0;
      if (hsm->sw_if_index_is_set)
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
      ha_sync_release_resources ();
      if (hsm->timer_wheel.timers)
        tw_timer_wheel_free_16t_2w_512sl (&hsm->timer_wheel);
      ha_sync_update_all_contexts ();
    }
  vlib_worker_thread_barrier_release (vm);
  return 0;
}

static clib_error_t *
ha_sync_set_src_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  ip4_address_t ip4;
  f64 now;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set src-address <ip4>");

  hsm->src_address = ip4;
  hsm->src_is_set = 1;
  hsm->config_ready =
    hsm->src_is_set && hsm->peer_is_set && hsm->sw_if_index_is_set;
  ha_sync_update_all_contexts ();
  if (hsm->enabled && hsm->config_ready)
  {
    now = vlib_time_now (vm);
    hsm->hello_retry_count = 0;
    hsm->next_hello_time = now;
  }
  return 0;
}

static clib_error_t *
ha_sync_set_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u8 peer_changed = 0;
  ip4_address_t ip4;
  f64 now;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  if (!unformat (input, "%U", unformat_ip4_address, &ip4))
    return clib_error_return (0, "usage: ha_sync set peer-address <ip4>");

  peer_changed = (!hsm->peer_is_set || hsm->peer_address.as_u32 != ip4.as_u32);
  hsm->peer_address = ip4;
  hsm->peer_is_set = 1;
  hsm->config_ready =
    hsm->src_is_set && hsm->peer_is_set && hsm->sw_if_index_is_set;

  /*
   * Peer changed: drop runtime TX state/FIFOs and force a fresh
   * hello/handshake to rebuild the connection against the new peer.
   */
  if (peer_changed)
  {
    hsm->connection_established = 0;
    hsm->snapshot_trigger_pending = 0;
    ha_sync_reset_runtime_state ();
  }

  ha_sync_update_all_contexts ();
  if (hsm->enabled && hsm->config_ready)
  {
    now = vlib_time_now (vm);
    hsm->hello_retry_count = 0;
    hsm->next_hello_time = now;
  }
  return 0;
}

static clib_error_t *
ha_sync_clear_peer_address_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                       vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  CLIB_UNUSED (vlib_main_t * _vm) = vm;
  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;
  CLIB_UNUSED (unformat_input_t * _input) = input;

  hsm->peer_is_set = 0;
  hsm->config_ready = 0;
  hsm->peer_address.as_u32 = 0;
  hsm->connection_established = 0;
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
  /* Drop runtime FIFOs/pool/timers when peer is cleared. */
  ha_sync_reset_runtime_state ();
  ha_sync_update_all_contexts ();
  return 0;
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

  hsm->domain_id = domain_id;
  return 0;
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

  hsm->packet_size = (u16) packet_size;
  return 0;
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

  hsm->retransmit_times = times;
  return 0;
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

  hsm->retransmit_interval = interval;
  return 0;
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

  if (hsm->sw_if_index_is_set && hsm->sw_if_index != sw_if_index)
    vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                 hsm->sw_if_index, 0, 0, 0);

  hsm->sw_if_index = sw_if_index;
  hsm->sw_if_index_is_set = 1;
  hsm->config_ready =
    hsm->src_is_set && hsm->peer_is_set && hsm->sw_if_index_is_set;
  ha_sync_update_all_contexts ();
  if (hsm->enabled && hsm->config_ready)
    vnet_feature_enable_disable ("ip4-unicast", "ha-sync-input-worker",
                                 hsm->sw_if_index, 1, 0, 0);
  return 0;
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
  hsm->hello_retry_count = 0;
  hsm->next_hello_time = 0;
  hsm->timer_expired_vec = 0;
  hsm->snapshot_sequence = 0;
  hsm->snapshot_trigger_pending = 0;
  hsm->snapshot_triggered_for_connection = 0;
  tw_timer_wheel_init_16t_2w_512sl (&hsm->timer_wheel, NULL, 0.1, 8192);
  
  clib_spinlock_init (&hsm->tx_lock);
  ha_sync_resources_init (hsm);
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
