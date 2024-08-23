/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_sched_fp_h
#define included_onp_drv_inc_sched_fp_h

#include <onp/drv/modules/sched/sched_fp_cn10k.h>

static_always_inline u32
cnxk_drv_sched_current_tag_get (vlib_main_t *vm)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_sched_current_tag_get (vm);

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
  return 0;
}

static_always_inline cnxk_sched_tt_t
cnxk_drv_sched_current_tag_type_get (vlib_main_t *vm)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return cn10k_sched_current_tag_type_get (vm);

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
  return CNXK_SCHED_TAG_EMPTY;
}

static_always_inline void
cnxk_drv_sched_tag_switch (vlib_main_t *vm, u8 tag_type, u32 new_tag)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_sched_tag_switch (vm, tag_type, new_tag);
      break;

    default:
      clib_panic ("Compile with latest GNU compiler to enable OCTEON code");
    }
}

static_always_inline void
cnxk_drv_sched_lock_wait (vlib_main_t *vm)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_sched_lock_wait (vm);
      break;

    default:
      /*
       * Note: This function is also used in non multi-arch sources:
       * - onp/onp.c
       */
      cnxk_sched_lock (vm, CNXK_SCHED_LOCK_HEAD_WAIT);
    }
}

static_always_inline void
cnxk_drv_sched_lock_release (vlib_main_t *vm)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      cn10k_sched_lock_release (vm);
      break;

    default:
      /*
       * Note: This function is also used in non multi-arch sources:
       * - onp/sched/sched.c
       */
      cnxk_sched_tag_release (vm);
    }
}

#endif /* included_onp_drv_inc_sched_fp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
