/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_sched_fp_enq_deq_h
#define included_onp_drv_inc_sched_fp_enq_deq_h

#include <onp/drv/modules/sched/sched_fp_enq_deq_cn10k.h>

static_always_inline i32
cnxk_drv_sched_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node,
			cnxk_sched_work_t work[], cnxk_per_thread_data_t *ptd)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_sched_dequeue (vm, node, work, ptd);

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
  return 0;
}

#endif /* included_onp_drv_inc_sched_fp_enq_deq_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
