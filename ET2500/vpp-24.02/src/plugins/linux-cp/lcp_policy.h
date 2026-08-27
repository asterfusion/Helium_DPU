/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __LCP_POLICY_H__
#define __LCP_POLICY_H__

#include <vppinfra/types.h>
#include <stdbool.h>
#include <linux-cp/lcp.api_types.h>

#define LCP_POLICY_N_TRAPS LCP_TRAP_N_TYPES
#define LCP_POLICY_INDEX_INVALID ((u32) ~0)

typedef struct
{
  u8 action;
  u32 priority;
  u32 policer_index;
} lcp_policy_entry_t;

typedef struct
{
  vl_api_lcp_trap_type_t trap_type;
  const char *name;
  u32 default_priority;
  u8 default_action;
} lcp_trap_desc_t;

static_always_inline bool
lcp_trap_id_is_valid (vl_api_lcp_trap_type_t trap_id)
{
  return trap_id > LCP_TRAP_INVALID && trap_id < LCP_TRAP_N_TYPES;
}

const lcp_policy_entry_t *
lcp_policy_get (vl_api_lcp_trap_type_t trap_id);
const lcp_trap_desc_t *
lcp_trap_desc_get (vl_api_lcp_trap_type_t trap_id);
bool lcp_policy_is_configured (vl_api_lcp_trap_type_t trap_id);

int lcp_policy_add (vl_api_lcp_trap_type_t trap_id, u8 action, u32 priority,
		    u32 policer_index);
int lcp_policy_update (vl_api_lcp_trap_type_t trap_id, u8 action, u32 priority,
		       u32 policer_index);
int lcp_policy_delete (vl_api_lcp_trap_type_t trap_id);

#endif /* __LCP_POLICY_H__ */
