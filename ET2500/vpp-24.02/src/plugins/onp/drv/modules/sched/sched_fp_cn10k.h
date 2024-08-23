/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_sched_sched_fp_cn10k_h
#define included_onp_drv_modules_sched_sched_fp_cn10k_h

#include <onp/drv/modules/sched/sched_fp_cnxk.h>

#define cn10k_sched_get_work cnxk_sched_get_work
#define cn10k_sched_enqueue(vm, node, wrk, num, ptr)                          \
  cnxk_sched_add_work (wrk, num)
#define cn10k_sched_add_work		 cnxk_sched_add_work
#define cn10k_sched_current_tag_get	 cnxk_sched_get_current_tag
#define cn10k_sched_current_tag_type_get cnxk_sched_get_current_tag_type
#define cn10k_sched_lock_wait(vm)                                             \
  cnxk_sched_lock (vm, CNXK_SCHED_LOCK_HEAD_WAIT)
#define cn10k_sched_lock_release cnxk_sched_tag_release
#define cn10k_sched_tag_switch	 cnxk_sched_tag_switch

#endif /* included_onp_drv_modules_sched_sched_fp_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
