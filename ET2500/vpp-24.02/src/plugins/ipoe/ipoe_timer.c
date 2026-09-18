/* SPDX-License-Identifier: Apache-2.0 */
#include <ipoe/ipoe.h>

#define IPOE_TIMER_INDEX_BITS 20
#define IPOE_TIMER_INDEX_MASK ((1U << IPOE_TIMER_INDEX_BITS) - 1)
#define IPOE_TIMER_GENERATION_MASK 0x7ffU

static void
ipoe_timer_expired (u32 *expired_timers)
{
  ipoe_main_t *im = &ipoe_main;
  ipoe_session_t *session;
  u32 i, object_id, session_index, timer_generation;
  for (i = 0; i < vec_len (expired_timers); i++)
    {
      object_id = expired_timers[i];
      session_index = object_id & IPOE_TIMER_INDEX_MASK;
      timer_generation = object_id >> IPOE_TIMER_INDEX_BITS;
      if (pool_is_free_index (im->sessions, session_index))
	continue;
      session = pool_elt_at_index (im->sessions, session_index);
      if (timer_generation !=
	  (session->timer_generation & IPOE_TIMER_GENERATION_MASK))
	continue;
      session->timer_handle = ~0;
      ipoe_session_expire (session_index);
    }
}

static uword
ipoe_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
		    vlib_frame_t *f)
{
  ipoe_main_t *im = &ipoe_main;
  uword *event_data = 0;
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 1.0);
      vlib_process_get_events (vm, &event_data);
      tw_timer_expire_timers_1t_3w_1024sl_ov (&im->timer_wheel,
					       vlib_time_now (vm));
      vec_reset_length (event_data);
    }
  return 0;
}

VLIB_REGISTER_NODE (ipoe_timer_process_node) = {
  .function = ipoe_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "ipoe-timer-process",
};

void
ipoe_timer_init (vlib_main_t *vm)
{
  (void) vm;
  tw_timer_wheel_init_1t_3w_1024sl_ov (&ipoe_main.timer_wheel,
				       ipoe_timer_expired, 1.0, ~0);
}

void
ipoe_timer_start (u32 session_index, u32 lease_timeout)
{
  ipoe_session_t *session =
    pool_elt_at_index (ipoe_main.sessions, session_index);
  u32 object_id =
    ((session->timer_generation & IPOE_TIMER_GENERATION_MASK)
     << IPOE_TIMER_INDEX_BITS) | session_index;
  ASSERT (session_index <= IPOE_TIMER_INDEX_MASK);
  session->timer_handle = tw_timer_start_1t_3w_1024sl_ov (
    &ipoe_main.timer_wheel, object_id, 0, lease_timeout);
}

void
ipoe_timer_stop (ipoe_session_t *session)
{
  if (session->timer_handle == ~0)
    return;
  tw_timer_stop_1t_3w_1024sl_ov (&ipoe_main.timer_wheel,
				 session->timer_handle);
  session->timer_handle = ~0;
}

void
ipoe_timer_update (u32 session_index, u32 lease_timeout)
{
  ipoe_session_t *session =
    pool_elt_at_index (ipoe_main.sessions, session_index);
  ipoe_timer_stop (session);
  ipoe_timer_start (session_index, lease_timeout);
}
