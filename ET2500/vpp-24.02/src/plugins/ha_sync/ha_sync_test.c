#include <vlib/vlib.h>
#include <ha_sync/ha_sync.h>

#define HA_SYNC_TEST_SNAPSHOT_COUNT 64
#define HA_SYNC_TEST_RATE_INTERVAL_MS 50

/* Simple fixed NAT-like session table */
typedef struct __attribute__ ((packed))
{
  ip4_address_t src_addr;
  ip4_address_t dst_addr;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
} ha_sync_test_nat_entry_t;

typedef struct
{
  u8 registered;
  u8 snapshot_sent;
  u8 sync_enabled;
  u8 rate_active;
  u32 applied_count;
  u32 snapshot_count;
  u32 incr_count;
  u32 rate_sessions_per_sec;
  u32 rate_interval_ms;
  u32 rate_burst_sessions;
  u32 rate_sent_count;
  u32 rate_seq;
} ha_sync_test_nat_ctx_t;

static ha_sync_test_nat_ctx_t ha_sync_test_nat_ctx;

static ha_sync_test_nat_entry_t ha_sync_test_nat_table[HA_SYNC_TEST_SNAPSHOT_COUNT];

extern vlib_node_registration_t ha_sync_test_rate_process_node;

static void
ha_sync_test_nat_init_table (void)
{
  u32 i;
  for (i = 0; i < HA_SYNC_TEST_SNAPSHOT_COUNT; i++)
  {
    ha_sync_test_nat_entry_t *e = &ha_sync_test_nat_table[i];
    e->src_addr.as_u32 = clib_host_to_net_u32 (0x0c0c0c00 + 1 + i);
    e->dst_addr.as_u32 = clib_host_to_net_u32 (0x0c0c1c00 + 1 + i);
    e->src_port = (u16) (10000 + i);
    e->dst_port = (u16) (20000 + i);
    e->protocol = (u8) ((i % 3) == 0 ? 6 : ((i % 3) == 1 ? 17 : 1));
  }
}

static void
ha_sync_test_nat_send_sessions (u32 thread_index, u32 count)
{
  u32 i;

  for (i = 0; i < count; i++)
  {
    ha_sync_test_nat_entry_t entry = {
      .src_addr = { .as_u32 = clib_host_to_net_u32 (0x0c0c0caa) },
      .dst_addr = { .as_u32 = clib_host_to_net_u32 (0x0c0c0cbb) },
      .src_port = (u16) (30000 + (ha_sync_test_nat_ctx.rate_seq & 0xffff)),
      .dst_port = (u16) (40000 + (ha_sync_test_nat_ctx.rate_seq & 0xffff)),
      .protocol = 6,
    };

    ha_sync_test_nat_ctx.rate_seq++;
    ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT,
                                   (u8 *) &entry, sizeof (entry));
  }
}

static void
ha_sync_test_nat_rate_configure (u32 sessions_per_sec, u32 interval_ms)
{
  ha_sync_test_nat_ctx.rate_sessions_per_sec = sessions_per_sec;
  ha_sync_test_nat_ctx.rate_interval_ms = interval_ms;
  ha_sync_test_nat_ctx.rate_burst_sessions =
    (sessions_per_sec * interval_ms) / 1000;
  if (ha_sync_test_nat_ctx.rate_burst_sessions == 0)
    ha_sync_test_nat_ctx.rate_burst_sessions = 1;
}

static void
ha_sync_test_nat_session_apply_cb (u32 app_type, void *ctx, u8 *session,
                                   u16 session_len)
{
  ha_sync_test_nat_ctx_t *tctx = ctx;
  (void) app_type;
  (void) session;
  (void) session_len;

  if (tctx)
    tctx->applied_count++;
}

static int
ha_sync_test_nat_snapshot_send_cb (u32 app_type, void *ctx, u32 thread_index)
{
  ha_sync_test_nat_ctx_t *tctx = ctx;
  u32 i;

  (void) app_type;
  (void) thread_index;

  if (!tctx || tctx->snapshot_sent)
    return 0;

  for (i = 0; i < HA_SYNC_TEST_SNAPSHOT_COUNT; i++)
  {
    ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT,
                                   (u8 *) &ha_sync_test_nat_table[i],
                                   sizeof (ha_sync_test_nat_table[i]));
  }

  tctx->snapshot_sent = 1;
  tctx->snapshot_count += HA_SYNC_TEST_SNAPSHOT_COUNT;
  return 0;
}

static ha_sync_session_registration_t ha_sync_test_nat_reg = {
  .app_type = HA_SYNC_APP_NAT,
  .context = &ha_sync_test_nat_ctx,
  .snapshot_send_cb = ha_sync_test_nat_snapshot_send_cb,
  .session_apply_cb = ha_sync_test_nat_session_apply_cb,
  .snapshot_mode = HA_SYNC_SNAPSHOT_MODE_SINGLE,
};

static clib_error_t *
test_ha_sync_command_fn (vlib_main_t *vm, unformat_input_t *input,
                         vlib_cli_command_t *cmd)
{
  ha_sync_main_t *hsm = &ha_sync_main;
  u8 do_register = 0;
  u8 do_unregister = 0;
  u8 do_show = 0;
  u8 do_incr = 0;
  u8 do_rate = 0;
  u8 do_stop = 0;
  u32 incr_count = 1;
  u32 sessions_per_sec = 0;
  u32 interval_ms = HA_SYNC_TEST_RATE_INTERVAL_MS;
  u32 thread_index = vlib_get_thread_index ();

  CLIB_UNUSED (vlib_cli_command_t * _cmd) = cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
  {
    if (unformat (input, "nat"))
      ;
    else if (unformat (input, "register"))
      do_register = 1;
    else if (unformat (input, "unregister"))
      do_unregister = 1;
    else if (unformat (input, "show"))
      do_show = 1;
    else if (unformat (input, "incr %u", &incr_count))
      do_incr = 1;
    else if (unformat (input, "rate %u interval %u", &sessions_per_sec,
                       &interval_ms))
      do_rate = 1;
    else if (unformat (input, "rate %u", &sessions_per_sec))
      do_rate = 1;
    else if (unformat (input, "stop"))
      do_stop = 1;
    else
      return clib_error_return (0, "unknown input `%U`", format_unformat_error, input);
  }

  if (do_register)
  {
    if (ha_sync_test_nat_ctx.registered)
      return clib_error_return (0, "already registered");

    ha_sync_test_nat_init_table ();

    ha_sync_test_nat_ctx.registered = 1;
    ha_sync_test_nat_ctx.snapshot_sent = 0;
    ha_sync_test_nat_ctx.sync_enabled = 1;
    ha_sync_test_nat_ctx.applied_count = 0;
    ha_sync_test_nat_ctx.snapshot_count = 0;
    ha_sync_test_nat_ctx.incr_count = 0;
    ha_sync_test_nat_ctx.rate_active = 0;
    ha_sync_test_nat_ctx.rate_sessions_per_sec = 0;
    ha_sync_test_nat_ctx.rate_interval_ms = HA_SYNC_TEST_RATE_INTERVAL_MS;
    ha_sync_test_nat_ctx.rate_burst_sessions = 0;
    ha_sync_test_nat_ctx.rate_sent_count = 0;
    ha_sync_test_nat_ctx.rate_seq = 0;

    if (ha_sync_register_session_application (&ha_sync_test_nat_reg) != 0)
      return clib_error_return (0, "register failed");

    vlib_cli_output (vm, "ha-sync test nat: registered (snapshot size=%u)",
                     (u32) HA_SYNC_TEST_SNAPSHOT_COUNT);
    return 0;
  }

  if (do_unregister)
  {
    if (ha_sync_test_nat_ctx.registered)
      (void) ha_sync_unregister_session_application (HA_SYNC_APP_NAT);

    ha_sync_test_nat_ctx.registered = 0;
    ha_sync_test_nat_ctx.sync_enabled = 0;
    ha_sync_test_nat_ctx.rate_active = 0;
    vlib_cli_output (vm, "ha-sync test nat: unregistered");
    return 0;
  }

  if (do_incr)
  {
    if (!ha_sync_test_nat_ctx.registered)
      return clib_error_return (0, "register first");
    if (!ha_sync_test_nat_ctx.sync_enabled)
      return clib_error_return (0, "sync is disabled");
    if (!hsm->connection_established)
      return clib_error_return (0, "connection not established");

    ha_sync_test_nat_send_sessions (thread_index, incr_count);

    ha_sync_test_nat_ctx.incr_count += incr_count;
    vlib_cli_output (vm, "ha-sync test nat: enqueued %u incremental sessions", incr_count);
    return 0;
  }

  if (do_rate)
  {
    if (!ha_sync_test_nat_ctx.registered)
      return clib_error_return (0, "register first");
    if (!ha_sync_test_nat_ctx.sync_enabled)
      return clib_error_return (0, "sync is disabled");
    if (!hsm->connection_established)
      return clib_error_return (0, "connection not established");
    if (interval_ms == 0)
      return clib_error_return (0, "interval must be > 0");

    ha_sync_test_nat_rate_configure (sessions_per_sec, interval_ms);
    ha_sync_test_nat_ctx.rate_active = 1;
    vlib_process_signal_event (vm, ha_sync_test_rate_process_node.index, 1, 0);
    vlib_cli_output (vm,
                     "ha-sync test nat: rate sender enabled rate=%u sess/s interval=%u ms burst=%u",
                     ha_sync_test_nat_ctx.rate_sessions_per_sec,
                     ha_sync_test_nat_ctx.rate_interval_ms,
                     ha_sync_test_nat_ctx.rate_burst_sessions);
    return 0;
  }

  if (do_stop)
  {
    ha_sync_test_nat_ctx.rate_active = 0;
    vlib_cli_output (vm, "ha-sync test nat: rate sender stopped");
    return 0;
  }

  if (do_show)
  {
    vlib_cli_output (vm,
                     "ha-sync test nat: registered=%u snapshot_sent=%u snapshot_count=%u incr_count=%u applied=%u rate_active=%u rate=%u interval_ms=%u burst=%u rate_sent=%u",
                     ha_sync_test_nat_ctx.registered,
                     ha_sync_test_nat_ctx.snapshot_sent,
                     ha_sync_test_nat_ctx.snapshot_count,
                     ha_sync_test_nat_ctx.incr_count,
                     ha_sync_test_nat_ctx.applied_count,
                     ha_sync_test_nat_ctx.rate_active,
                     ha_sync_test_nat_ctx.rate_sessions_per_sec,
                     ha_sync_test_nat_ctx.rate_interval_ms,
                     ha_sync_test_nat_ctx.rate_burst_sessions,
                     ha_sync_test_nat_ctx.rate_sent_count);
    return 0;
  }

  vlib_cli_output (vm,
                   "test ha-sync nat register\n"
                   "test ha-sync nat unregister\n"
                   "test ha-sync nat incr <n>\n"
                   "test ha-sync nat rate <sessions-per-sec> [interval <ms>]\n"
                   "test ha-sync nat stop\n"
                   "test ha-sync nat show");
  return 0;
}

VLIB_NODE_FN (ha_sync_test_rate_process_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  CLIB_UNUSED (vlib_node_runtime_t * _node) = node;
  CLIB_UNUSED (vlib_frame_t * _frame) = frame;

  while (1)
  {
    if (!ha_sync_test_nat_ctx.rate_active)
    {
      vlib_process_wait_for_event (vm);
      vlib_process_get_events (vm, 0);
      continue;
    }

    vlib_process_wait_for_event_or_clock (
      vm, (f64) ha_sync_test_nat_ctx.rate_interval_ms / 1000.0);
    vlib_process_get_events (vm, 0);

    if (!ha_sync_test_nat_ctx.rate_active)
      continue;
    if (!ha_sync_test_nat_ctx.registered || !ha_sync_test_nat_ctx.sync_enabled)
      continue;
    if (!ha_sync_main.connection_established)
      continue;

    ha_sync_test_nat_send_sessions (vlib_get_thread_index (),
                                    ha_sync_test_nat_ctx.rate_burst_sessions);
    ha_sync_test_nat_ctx.incr_count += ha_sync_test_nat_ctx.rate_burst_sessions;
    ha_sync_test_nat_ctx.rate_sent_count +=
      ha_sync_test_nat_ctx.rate_burst_sessions;
  }
}

VLIB_REGISTER_NODE (ha_sync_test_rate_process_node) = {
  .name = "ha-sync-test-rate-process",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_PROCESS,
};

VLIB_CLI_COMMAND (test_ha_sync_command, static) = {
  .path = "test ha-sync",
  .short_help = "test ha-sync nat register|unregister|incr|rate|stop|show",
  .function = test_ha_sync_command_fn,
};
