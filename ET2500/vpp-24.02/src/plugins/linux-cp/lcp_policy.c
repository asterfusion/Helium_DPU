/* SPDX-License-Identifier: Apache-2.0 */
#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/api_errno.h>

#include <linux-cp/lcp.api_types.h>
#include <linux-cp/lcp_policy.h>

static const lcp_trap_desc_t lcp_trap_descs[LCP_POLICY_N_TRAPS] = {
#define LCP_TRAP_DEF(trap, trap_name, priority, action)                  \
  [LCP_TRAP_##trap] = {                                                 \
    .trap_type = LCP_TRAP_##trap, .name = #trap_name,                   \
    .default_priority = priority, .default_action = action,              \
  },
#include <linux-cp/lcp_traps.def>
#undef LCP_TRAP_DEF
};

static lcp_policy_entry_t lcp_policy_table[LCP_POLICY_N_TRAPS];
static u8 lcp_policy_configured[LCP_POLICY_N_TRAPS];

static_always_inline lcp_policy_entry_t *
lcp_policy_get_unchecked (vl_api_lcp_trap_type_t trap_id)
{
  ASSERT (lcp_trap_id_is_valid (trap_id));
  return &lcp_policy_table[trap_id];
}

const lcp_trap_desc_t *
lcp_trap_desc_get (vl_api_lcp_trap_type_t trap_id)
{
  if (!lcp_trap_id_is_valid (trap_id) ||
      lcp_trap_descs[trap_id].name == 0)
    return 0;

  return &lcp_trap_descs[trap_id];
}

const lcp_policy_entry_t *
lcp_policy_get (vl_api_lcp_trap_type_t trap_id)
{
  if (PREDICT_FALSE (!lcp_trap_id_is_valid (trap_id)))
    return 0;

  return &lcp_policy_table[trap_id];
}

bool
lcp_policy_is_configured (vl_api_lcp_trap_type_t trap_id)
{
  if (PREDICT_FALSE (!lcp_trap_id_is_valid (trap_id)))
    return false;

  return lcp_policy_configured[trap_id];
}

static void
lcp_policy_store (vl_api_lcp_trap_type_t trap_id, u8 action, u32 priority,
		  u32 policer_index)
{
  lcp_policy_entry_t *policy = lcp_policy_get_unchecked (trap_id);

  policy->action = action;
  policy->priority = priority;
  policy->policer_index = policer_index;
}

static int
lcp_policy_validate_action (vl_api_lcp_trap_type_t trap_id, u8 action)
{
  if (action > LCP_COPP_ACTION_TRAP)
    return VNET_API_ERROR_INVALID_VALUE;
  if (trap_id == LCP_TRAP_PTP_TX_EVENT &&
      action != LCP_COPP_ACTION_DROP && action != LCP_COPP_ACTION_TRAP)
    return VNET_API_ERROR_INVALID_VALUE;

  return 0;
}

static int
lcp_policy_validate_trap (vl_api_lcp_trap_type_t trap_id)
{
  return lcp_trap_id_is_valid (trap_id) ? 0 : VNET_API_ERROR_INVALID_VALUE;
}

int
lcp_policy_add (vl_api_lcp_trap_type_t trap_id, u8 action, u32 priority,
		u32 policer_index)
{
  lcp_policy_entry_t *policy;
  int rv;

  rv = lcp_policy_validate_trap (trap_id);
  if (rv != 0)
    return rv;
  rv = lcp_policy_validate_action (trap_id, action);
  if (rv != 0)
    return rv;
  policy = lcp_policy_get_unchecked (trap_id);

  if (lcp_policy_is_configured (trap_id))
    {
      if (policy->action == action && policy->priority == priority &&
	  policy->policer_index == policer_index)
	return 0;

      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

  lcp_policy_store (trap_id, action, priority, policer_index);
  lcp_policy_configured[trap_id] = 1;

  return 0;
}

int
lcp_policy_update (vl_api_lcp_trap_type_t trap_id, u8 action, u32 priority,
		   u32 policer_index)
{
  int rv;

  rv = lcp_policy_validate_trap (trap_id);
  if (rv != 0)
    return rv;
  rv = lcp_policy_validate_action (trap_id, action);
  if (rv != 0)
    return rv;

  if (!lcp_policy_is_configured (trap_id))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  lcp_policy_store (trap_id, action, priority, policer_index);

  return 0;
}

int
lcp_policy_delete (vl_api_lcp_trap_type_t trap_id)
{
  const lcp_trap_desc_t *desc;
  int rv = lcp_policy_validate_trap (trap_id);

  if (rv != 0)
    return rv;
  desc = lcp_trap_desc_get (trap_id);
  lcp_policy_store (trap_id, desc->default_action, desc->default_priority,
		    LCP_POLICY_INDEX_INVALID);
  lcp_policy_configured[trap_id] = 0;

  return 0;
}

static clib_error_t *
lcp_policy_init (vlib_main_t *vm)
{
  CLIB_UNUSED (vlib_main_t *unused_vm) = vm;

  for (vl_api_lcp_trap_type_t trap = LCP_TRAP_INVALID + 1;
       trap < LCP_TRAP_N_TYPES; trap++)
    {
      const lcp_trap_desc_t *desc = lcp_trap_desc_get (trap);

      if (!desc || desc->trap_type != trap)
	return clib_error_return (0, "invalid LCP trap descriptor %u", trap);
      lcp_policy_store (trap, desc->default_action, desc->default_priority,
			LCP_POLICY_INDEX_INVALID);
    }

  return 0;
}

VLIB_INIT_FUNCTION (lcp_policy_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
