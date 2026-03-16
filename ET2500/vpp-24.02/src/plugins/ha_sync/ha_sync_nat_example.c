// 示例 NAT 会话同步
#include <ha_sync/ha_sync.h>


typedef struct __attribute__ ((packed))
{
  ip4_address_t in_src_addr;
  ip4_address_t in_dst_addr;
  u16 in_src_port;
  u16 in_dst_port;
  u8 protocol;
} nat44_5tuple_t;

typedef struct
{
  u8 sync_enabled;
  u32 applied_count;
  nat44_5tuple_t last_applied;
  nat44_5tuple_t *snapshot_entries;
  u32 snapshot_entries_count;
  u32 snapshot_cursor;
} ha_sync_nat_ctx_t;

static ha_sync_nat_ctx_t ha_sync_nat_ctx;




/** apply nat session */
static void
ha_sync_nat_session_apply_cb (u32 app_type, void *ctx, u8 *session,
                              u16 session_len)
{
  ha_sync_nat_ctx_t *nctx = ctx;
  (void) app_type;

  if (PREDICT_FALSE (!nctx || !nctx->sync_enabled))
    return;
  if (PREDICT_FALSE (session_len != sizeof (nat44_5tuple_t)))
    return;

  clib_memcpy_fast (&nctx->last_applied, session, sizeof (nat44_5tuple_t));
  nctx->applied_count++;
}

static int
ha_sync_nat_snapshot_send_cb (u32 app_type, void *ctx, u32 thread_index)
{
  /** read nat session table, call ha_sync_per_thread_buffer_add to add session to pending_fifo */
  // ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT, (u8 *) entry,
  //                                sizeof (*entry));
  /** every 500 sessions(It depends on the situation), yield cpu and return 1. if ha_sync return 1, continue call this function until return 0. */
  enum { HA_SYNC_NAT_SNAPSHOT_BATCH = 500 };
  ha_sync_nat_ctx_t *nctx = ctx;
  u32 cursor;
  u32 remaining;
  u32 to_send;
  u32 i;

  (void) app_type;

  if (PREDICT_FALSE (!nctx || !nctx->sync_enabled))
    return 0;
  if (PREDICT_FALSE (!nctx->snapshot_entries ||
                     nctx->snapshot_entries_count == 0))
    return 0;

  cursor = nctx->snapshot_cursor;
  if (PREDICT_FALSE (cursor >= nctx->snapshot_entries_count))
  {
    nctx->snapshot_cursor = 0;
    return 0;
  }

  remaining = nctx->snapshot_entries_count - cursor;
  to_send = remaining > HA_SYNC_NAT_SNAPSHOT_BATCH
              ? HA_SYNC_NAT_SNAPSHOT_BATCH
              : remaining;

  nat44_5tuple_t *entries = nctx->snapshot_entries + cursor;
  for (i = 0; i < to_send; i++)
  {
    ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT,
                                   (u8 *) &entries[i], sizeof (entries[i]));
  }

  cursor += to_send;
  nctx->snapshot_cursor = cursor;
  if (cursor < nctx->snapshot_entries_count)
    return 1;

  nctx->snapshot_cursor = 0;
  return 0;
}

static ha_sync_session_registration_t ha_sync_nat_registration = {
  .app_type = HA_SYNC_APP_NAT,
  .context = &ha_sync_nat_ctx,
  .snapshot_send_cb = ha_sync_nat_snapshot_send_cb,
  .session_apply_cb = ha_sync_nat_session_apply_cb,
  .snapshot_mode = HA_SYNC_SNAPSHOT_MODE_SINGLE,
};

/** register nat session application */
int ha_sync_nat_register_example (void)
{
  ha_sync_nat_ctx.sync_enabled = 1;
  return ha_sync_register_session_application (&ha_sync_nat_registration);
}
/** unregister nat session application */
void
ha_sync_nat_unregister_example (void)
{
  ha_sync_nat_ctx.sync_enabled = 0;
  (void) ha_sync_unregister_session_application (HA_SYNC_APP_NAT);
}

/** enqueue nat session to pending_fifo */
void ha_sync_nat_enqueue_session_example (const nat44_5tuple_t *entry)
{
  u32 thread_index = vlib_get_thread_index ();

  if (!ha_sync_nat_ctx.sync_enabled || !entry)
    return;

  /** enqueue nat session to pending_fifo */
  /** not support cross-thread enqueue, thread_index must be current thread */
  ha_sync_per_thread_buffer_add (thread_index, HA_SYNC_APP_NAT, (u8 *) entry,
                                 sizeof (*entry));
}
