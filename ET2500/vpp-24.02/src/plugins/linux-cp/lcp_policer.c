/* SPDX-License-Identifier: Apache-2.0 */
#include <vnet/policer/policer.h>
#include <vnet/policer/police_inlines.h>

#include <linux-cp/lcp_policy.h>
#include <linux-cp/lcp_policer.h>

u8
lcp_policer_police (vlib_main_t *vm, vlib_buffer_t *b, u32 policer_index)
{
  qos_action_type_en policer_action;
  u64 time_in_policer_periods;

  if (policer_index == LCP_POLICY_INDEX_INVALID)
    return 1;

  time_in_policer_periods =
    clib_cpu_time_now () >> POLICER_TICKS_PER_PERIOD_SHIFT;
  policer_action =
    vnet_policer_police (vm, b, policer_index, time_in_policer_periods,
			 POLICE_CONFORM, false);

  return policer_action == QOS_ACTION_TRANSMIT ||
	 policer_action == QOS_ACTION_MARK_AND_TRANSMIT;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
