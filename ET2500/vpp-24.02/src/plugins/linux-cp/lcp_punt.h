/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __LCP_PUNT_H__
#define __LCP_PUNT_H__

#include <stdbool.h>
#include <vlib/vlib.h>
#include <vnet/buffer.h>
#include <linux-cp/lcp.api_types.h>
#include <linux-cp/lcp_policy.h>

#define LCP_PUNT_BUFFER_INVALID ((u32) ~0)
#define LCP_TRAP_PROCESSED_FLAG ((u8) 0x80)
#define LCP_TRAP_ID_MASK        ((u8) 0x7f)

STATIC_ASSERT (LCP_TRAP_N_TYPES <= LCP_TRAP_PROCESSED_FLAG,
	       "LCP trap type must fit in vnet_buffer_opaque2_t::trap_id");

typedef enum
{
  LCP_DISPOSITION_DROP,
  LCP_DISPOSITION_FORWARD,
  LCP_DISPOSITION_TRAP,
  LCP_DISPOSITION_COPY,
} lcp_disposition_t;

typedef struct
{
  lcp_disposition_t disposition;
  u32 cpu_bi;
} lcp_action_result_t;

static_always_inline bool
lcp_buffer_set_trap_id (vlib_buffer_t *b,
			vl_api_lcp_trap_type_t trap_id)
{
  if (PREDICT_FALSE (!lcp_trap_id_is_valid (trap_id)))
    return false;

  vnet_buffer2 (b)->trap_id = (u8) trap_id;
  return true;
}

static_always_inline bool
lcp_buffer_copp_processed (vlib_buffer_t *b)
{
  return (vnet_buffer2 (b)->trap_id & LCP_TRAP_PROCESSED_FLAG) != 0;
}

static_always_inline void
lcp_buffer_mark_copp_processed (vlib_buffer_t *b)
{
  vnet_buffer2 (b)->trap_id |= LCP_TRAP_PROCESSED_FLAG;
}

static_always_inline void
lcp_buffer_clear_copp_processed (vlib_buffer_t *b)
{
  vnet_buffer2 (b)->trap_id &= LCP_TRAP_ID_MASK;
}

static_always_inline u8
lcp_legacy_action (vl_api_lcp_trap_type_t trap_id)
{
#define LCP_TRAP_DEF(trap, trap_name, priority, action)                  \
    case LCP_TRAP_##trap:                                                 \
      return action;
  switch (trap_id)
    {
#include <linux-cp/lcp_traps.def>
    default:
      return LCP_COPP_ACTION_TRAP;
    }
#undef LCP_TRAP_DEF
}

lcp_action_result_t lcp_punt_process (vlib_main_t *vm, vlib_buffer_t *b);
lcp_action_result_t
lcp_punt_process_with_default (vlib_main_t *vm, vlib_buffer_t *b,
			       u8 default_action);
bool lcp_cpu_branch_pass (vlib_main_t *vm, vlib_buffer_t *b);

#endif /* __LCP_PUNT_H__ */
