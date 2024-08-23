/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_sched_sched_priv_h
#define included_onp_drv_modules_sched_sched_priv_h

#include <onp/drv/inc/log.h>
#include <onp/drv/inc/sched.h>

#include <onp/drv/roc/platform.h>
#include <onp/drv/roc/base/roc_api.h>

#define MAX_HW_GRPS 256
#define MAX_HWS	    52
#define MAX_WE	    16384

#define CNXK_SCHED_GRP_DEF_WEIGHT   0x3F
#define CNXK_SCHED_GRP_DEF_AFFINITY 0xF

typedef union
{
#define CNXK_SCHED_TAG_MASK	    0xFFFFFFFF
#define CNXK_SCHED_TT_MASK	    0x3
#define CNXK_SSOW_LF_GWS_TAG_TT_BIT 32

#define CNXK_SCHED_TT(x)                                                      \
  (((x) >> CNXK_SSOW_LF_GWS_TAG_TT_BIT) & CNXK_SCHED_TT_MASK)
#define CNXK_SCHED_PEND_GET_WORK(x)                                           \
  (((x) >> SSOW_LF_GWS_TAG_PEND_GET_WORK_BIT) & 1)
#define CNXK_SCHED_PENDSWITCH(x) (((x) >> SSOW_LF_GWS_TAG_PEND_SWITCH_BIT) & 1)
#define CNXK_SCHED_HEAD_BIT(x)	 (((x) >> SSOW_LF_GWS_TAG_HEAD_BIT) & 1)
  u64 u;
} cnxk_ssow_lf_gws_tag_t;

typedef union
{
  u64 u;
} cnxk_ssow_lf_gws_swtag;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 base;
  u64 cached_tag;
} cnxk_hws_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  u64 base;
} cnxk_hw_grps_t;

typedef struct
{
  cnxk_hws_t hws[MAX_HWS];
  cnxk_hw_grps_t hw_grps[MAX_HW_GRPS];
  struct roc_sso sso;
  u64 aura_id;
  u64 xaq_addr;
  u8 init_done;
  u8 hws_config;
  u8 hw_grps_config;
} cnxk_sched_dev_t;

extern cnxk_sched_dev_t cnxk_sched_dev;

typedef struct cnxk_sched_dev_ops
{
  i32 (*sched_init) (vlib_main_t *vm, vlib_pci_addr_t *addr,
		     uuid_t uuid_token);
  i32 (*sched_config) (vlib_main_t *vm, cnxk_sched_config_t sched_config);
  i32 (*sched_grp_link) (vlib_main_t *vm, u16 *grp, u8 thread_id, u16 n_grps);
  i32 (*sched_grp_unlink) (vlib_main_t *vm, u16 *grp, u8 thread_id,
			   u16 n_grps);
  i32 (*sched_grp_prio_set) (vlib_main_t *vm, u16 grp, u8 prio);
  i32 (*sched_thread_grp_link_status_get) (vlib_main_t *vm, uword *grp_bitmap,
					   u8 thread_id);
  i32 (*sched_grp_stats_dump) (vlib_main_t *vm, u16 grp,
			       cnxk_sched_grp_stats_t *stats);
  u8 *(*sched_tag_format) (u8 *s, va_list *va);
  void (*sched_dump) (vlib_main_t *vm);
  i32 (*sched_exit) (vlib_main_t *vm);
} cnxk_sched_dev_ops_t;

static_always_inline cnxk_sched_dev_t *
cnxk_sched_get_dev ()
{
  extern cnxk_sched_dev_t cnxk_sched_dev;

  return &cnxk_sched_dev;
}

i32 cnxk_sched_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
		     uuid_t uuid_token);
i32 cnxk_sched_config (vlib_main_t *vm, cnxk_sched_config_t sched_config);
i32 cnxk_sched_grp_link (vlib_main_t *vm, u16 *grp, u8 thread_id, u16 n_grps);
i32 cnxk_sched_grp_unlink (vlib_main_t *vm, u16 *grp, u8 thread_id,
			   u16 n_grps);
i32 cnxk_sched_grp_prio_set (vlib_main_t *vm, u16 grp, u8 prio);
i32 cnxk_sched_grp_stats_dump (vlib_main_t *vm, u16 grp,
			       cnxk_sched_grp_stats_t *stats);
i32 cnxk_sched_thread_grp_link_status_get (vlib_main_t *vm, uword *grp_bitmap,
					   u8 thread_id);
i32 cnxk_sched_exit (vlib_main_t *vm);
u8 *cnxk_sched_tag_format (u8 *s, va_list *va);
void cnxk_sched_info_dump (vlib_main_t *vm);

#endif /* included_onp_drv_modules_sched_sched_priv_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
