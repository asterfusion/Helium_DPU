/* SPDX-License-Identifier: Apache-2.0 */
#include <vlib/vlib.h>

#include <linux-cp/lcp_policy.h>
#include <linux-cp/lcp_stats.h>

static vlib_simple_counter_main_t lcp_stats_counters[] = {
  [LCP_STATS_TRAP_HIT] = {
    .name = "LCP_COPP_TRAP_HIT",
    .stat_segment_name = "/lcp/copp/trap_hit",
  },
  [LCP_STATS_PUNT_REQUIRED] = {
    .name = "LCP_COPP_PUNT_REQUIRED",
    .stat_segment_name = "/lcp/copp/punt_required",
  },
  [LCP_STATS_PUNT_PASS] = {
    .name = "LCP_COPP_PUNT_PASS",
    .stat_segment_name = "/lcp/copp/punt_pass",
  },
  [LCP_STATS_PUNT_DROP] = {
    .name = "LCP_COPP_PUNT_DROP",
    .stat_segment_name = "/lcp/copp/punt_drop",
  },
  [LCP_STATS_DELIVERY_DROP] = {
    .name = "LCP_COPP_DELIVERY_DROP",
    .stat_segment_name = "/lcp/copp/delivery_drop",
  },
};

STATIC_ASSERT (ARRAY_LEN (lcp_stats_counters) == LCP_STATS_N_COUNTERS,
	       "LCP CoPP counter table size mismatch");

void
lcp_stats_increment (vlib_main_t *vm, vl_api_lcp_trap_type_t trap_id,
		     lcp_stats_counter_t counter)
{
  ASSERT (counter < LCP_STATS_N_COUNTERS);
  if (PREDICT_FALSE (!lcp_trap_id_is_valid (trap_id)))
    return;

  vlib_increment_simple_counter (&lcp_stats_counters[counter],
				 vm->thread_index, trap_id, 1);
}

void
lcp_stats_clear (void)
{
  lcp_stats_counter_t counter;

  for (counter = 0; counter < LCP_STATS_N_COUNTERS; counter++)
    vlib_clear_simple_counters (&lcp_stats_counters[counter]);
}

u64
lcp_stats_get (vl_api_lcp_trap_type_t trap_id, lcp_stats_counter_t counter)
{
  ASSERT (counter < LCP_STATS_N_COUNTERS);
  if (PREDICT_FALSE (!lcp_trap_id_is_valid (trap_id)))
    return 0;

  return vlib_get_simple_counter (&lcp_stats_counters[counter], trap_id);
}

static clib_error_t *
lcp_stats_init (vlib_main_t *vm)
{
  for (lcp_stats_counter_t counter = 0; counter < LCP_STATS_N_COUNTERS;
       counter++)
    {
      vlib_validate_simple_counter (&lcp_stats_counters[counter],
				    LCP_POLICY_N_TRAPS - 1);
    }

  lcp_stats_clear ();

  return 0;
}

#ifndef LCP_COPP_UNIT_TEST
VLIB_INIT_FUNCTION (lcp_stats_init);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
