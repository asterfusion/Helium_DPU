/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/sched/sched_priv.h>

const cnxk_sched_dev_ops_t sched_10k_ops = {
  .sched_thread_grp_link_status_get = cnxk_sched_thread_grp_link_status_get,
  .sched_grp_stats_dump = cnxk_sched_grp_stats_dump,
  .sched_grp_prio_set = cnxk_sched_grp_prio_set,
  .sched_grp_unlink = cnxk_sched_grp_unlink,
  .sched_tag_format = cnxk_sched_tag_format,
  .sched_grp_link = cnxk_sched_grp_link,
  .sched_dump = cnxk_sched_info_dump,
  .sched_config = cnxk_sched_config,
  .sched_init = cnxk_sched_init,
  .sched_exit = cnxk_sched_exit,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
