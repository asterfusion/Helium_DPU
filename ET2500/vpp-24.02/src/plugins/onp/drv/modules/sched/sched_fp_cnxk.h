/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_sched_sched_fp_cnxk_h
#define included_onp_drv_modules_sched_sched_fp_cnxk_h

#include <onp/drv/modules/sched/sched_priv.h>

static_always_inline void
cnxk_sched_tag_switch (vlib_main_t *vm, u8 tag_type, u32 new_tag)
{
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;
  cnxk_ssow_lf_gws_swtag swtag = { 0 };

  swtag.u = new_tag | ((u64) (tag_type & CNXK_SCHED_TT_MASK)
		       << CNXK_SSOW_LF_GWS_TAG_TT_BIT);

  plt_write64 (swtag.u, addr + SSOW_LF_GWS_OP_SWTAG_NORM);

  cnxk_sched_dev.hws[vm->thread_index].cached_tag = swtag.u;
}

static_always_inline void
cnxk_sched_lock (vlib_main_t *vm, cnxk_sched_lock_type_t locktype)
{
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;
  cnxk_ssow_lf_gws_tag_t tag;

  do
    {
      tag.u = (plt_read64 (addr + SSOW_LF_GWS_TAG));
    }
  while ((CNXK_SCHED_TT (tag.u) == SSO_TT_ORDERED) &&
	 !(CNXK_SCHED_HEAD_BIT (tag.u)));
}

static_always_inline void
cnxk_sched_tag_release (vlib_main_t *vm)
{
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;
  cnxk_ssow_lf_gws_tag_t tag;

  /* Not a valid operation to flush in empty state */
  tag.u = (plt_read64 (addr + SSOW_LF_GWS_TAG));

  if (CNXK_SCHED_TT (tag.u) == SSO_TT_EMPTY)
    return;

  plt_write64 (0, addr + SSOW_LF_GWS_OP_SWTAG_FLUSH);
}

static_always_inline i32
cnxk_sched_add_work (cnxk_sched_work_t *wqe, int n_events)
{
  cnxk_sched_work_t *work;
  u64 reg0, reg1, addr;
  int n_left;
  u8 queue;

  work = wqe;
  n_left = n_events;

  while (n_left > 0)
    {
      queue = work[0].enq_sched_group;
      addr = cnxk_sched_dev.hw_grps[queue].base;

      ASSERT (queue < cnxk_sched_dev.hw_grps_config);
      reg0 = work[0].tag;
      reg1 = work[0].work;

      roc_store_pair (reg0, reg1, addr + SSO_LF_GGRP_OP_ADD_WORK0);

      work++;
      n_left--;
    }

  return n_events;
}

static_always_inline u64
cnxk_sched_get_work (vlib_main_t *vm, u64 *ptag)
{
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;
  cnxk_ssow_lf_gws_tag_t tag;
  volatile u64 wqp;

  plt_write64 (0X1, addr + SSOW_LF_GWS_OP_GET_WORK0);
  do
    {
      tag.u = (plt_read64 (addr + SSOW_LF_GWS_TAG));
    }
  while (CNXK_SCHED_PEND_GET_WORK (tag.u));

  *ptag = tag.u;
  wqp = plt_read64 (addr + SSOW_LF_GWS_WQP);

  return wqp;
}

static_always_inline u32
cnxk_sched_get_current_tag (vlib_main_t *vm)
{
  cnxk_ssow_lf_gws_tag_t tag;
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;

  tag.u = (plt_read64 (addr + SSOW_LF_GWS_TAG));

  return (CNXK_SCHED_TAG_MASK & tag.u);
}

static_always_inline cnxk_sched_tt_t
cnxk_sched_get_current_tag_type (vlib_main_t *vm)
{
  cnxk_ssow_lf_gws_tag_t tag;
  u64 addr = cnxk_sched_dev.hws[vm->thread_index].base;

  tag.u = (plt_read64 (addr + SSOW_LF_GWS_TAG));

  return CNXK_SCHED_TT (tag.u);
}

#endif /* included_onp_drv_modules_sched_sched_fp_cnxk_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
