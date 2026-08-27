/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __LCP_STATS_H__
#define __LCP_STATS_H__

#include <stdbool.h>
#include <vlib/vlib.h>

#include <linux-cp/lcp.api_types.h>

typedef enum
{
  LCP_STATS_TRAP_HIT,
  LCP_STATS_PUNT_REQUIRED,
  LCP_STATS_PUNT_PASS,
  LCP_STATS_PUNT_DROP,
  LCP_STATS_DELIVERY_DROP,
  LCP_STATS_N_COUNTERS,
} lcp_stats_counter_t;

void lcp_stats_increment (vlib_main_t *vm, vl_api_lcp_trap_type_t trap_id,
			  lcp_stats_counter_t counter);
void lcp_stats_clear (void);
u64 lcp_stats_get (vl_api_lcp_trap_type_t trap_id,
		   lcp_stats_counter_t counter);

#endif /* __LCP_STATS_H__ */
