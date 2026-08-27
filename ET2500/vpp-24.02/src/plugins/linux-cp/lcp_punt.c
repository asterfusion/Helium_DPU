/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include <vnet/buffer.h>

#include <linux-cp/lcp.api_types.h>
#include <linux-cp/lcp_policer.h>
#include <linux-cp/lcp_policy.h>
#include <linux-cp/lcp_punt.h>
#include <linux-cp/lcp_stats.h>

lcp_action_result_t
lcp_punt_process_with_default (vlib_main_t *vm, vlib_buffer_t *b,
			       u8 default_action)
{
  const lcp_policy_entry_t *policy;
  vlib_buffer_t *copy;
  u8 action;
  vl_api_lcp_trap_type_t trap_id = vnet_buffer2 (b)->trap_id;
  lcp_action_result_t result = {
    .disposition = LCP_DISPOSITION_DROP,
    .cpu_bi = LCP_PUNT_BUFFER_INVALID,
  };

  policy = lcp_policy_get (trap_id);
  if (PREDICT_FALSE (policy == 0))
    return result;

  lcp_stats_increment (vm, trap_id, LCP_STATS_TRAP_HIT);
  if (lcp_policy_is_configured (trap_id))
    {
      action = policy->action;
    }
  else
    {
      /*
       * The policy table is initialized from lcp_traps.def and a delete
       * restores that descriptor default.  Use the table here as the single
       * source of truth; relying on a producer-supplied legacy action can
       * leave the default behavior inconsistent after a policy is deleted.
       */
      action = policy->action;
    }

  switch (action)
    {
    case LCP_COPP_ACTION_DROP:
      lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_DROP);
      result.disposition = LCP_DISPOSITION_DROP;
      break;

    case LCP_COPP_ACTION_FORWARD:
      result.disposition = LCP_DISPOSITION_FORWARD;
      break;

    case LCP_COPP_ACTION_COPY:
      lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_REQUIRED);
      {
	word l2_len = 0;
	if (b->flags & VNET_BUFFER_F_L2_HDR_OFFSET_VALID)
	  {
	    if (b->current_data > vnet_buffer (b)->l2_hdr_offset)
	      l2_len = b->current_data - vnet_buffer (b)->l2_hdr_offset;
	  }
	copy = vlib_buffer_copy (vm, b);
	if (copy != 0)
	  {
	    /* vlib_buffer_copy() does not copy bytes before current_data. */
	    if (l2_len > 0)
	      clib_memcpy_fast (vlib_buffer_get_current (copy) - l2_len,
				vlib_buffer_get_current (b) - l2_len, l2_len);
	    result.disposition = LCP_DISPOSITION_COPY;
	    result.cpu_bi = vlib_get_buffer_index (vm, copy);
	  }
	else
	  {
	    lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_DROP);
	    result.disposition = LCP_DISPOSITION_FORWARD;
	  }
      }
      break;

    case LCP_COPP_ACTION_TRAP:
      lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_REQUIRED);
      result.disposition = LCP_DISPOSITION_TRAP;
      break;

    default:
      /* Invalid actions are rejected on the write path; fail closed here. */
      lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_DROP);
      result.disposition = LCP_DISPOSITION_DROP;
      break;
    }

  return result;
}

lcp_action_result_t
lcp_punt_process (vlib_main_t *vm, vlib_buffer_t *b)
{
  return lcp_punt_process_with_default (
    vm, b, LCP_COPP_ACTION_TRAP);
}

bool
lcp_cpu_branch_pass (vlib_main_t *vm, vlib_buffer_t *b)
{
  vl_api_lcp_trap_type_t trap_id = vnet_buffer2 (b)->trap_id;
  const lcp_policy_entry_t *policy = lcp_policy_get (trap_id);

  if (PREDICT_FALSE (policy == 0))
    return false;

  if (lcp_policer_police (vm, b, policy->policer_index))
    {
      lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_PASS);
      return true;
    }

  lcp_stats_increment (vm, trap_id, LCP_STATS_PUNT_DROP);
  return false;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
