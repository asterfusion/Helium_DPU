/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/drv/modules/sched/sched_priv.h>
#include <onp/drv/modules/pci/pci.h>

cnxk_sched_dev_t cnxk_sched_dev;
cnxk_sched_dev_ops_t *sched_ops;

extern cnxk_sched_dev_ops_t sched_10k_ops;

void
cnxk_sched_info_dump (vlib_main_t *vm)
{
  cnxk_sched_dev_t *sd = cnxk_sched_get_dev ();

  roc_sso_dump (&sd->sso, sd->hws_config, sd->hw_grps_config, stdout);
}

i32
cnxk_sched_grp_stats_dump (vlib_main_t *vm, u16 grp,
			   cnxk_sched_grp_stats_t *stats)
{
  struct roc_sso_hwgrp_stats hwgrp_stats = { 0 };
  cnxk_sched_dev_t *sd;
  int rv = 0;

  sd = cnxk_sched_get_dev ();
  rv = roc_sso_hwgrp_stats_get (&sd->sso, grp, &hwgrp_stats);
  if (rv)
    {
      cnxk_sched_err ("roc_sso_hwgrp_stats_get failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  clib_memcpy (stats, &hwgrp_stats, sizeof (struct roc_sso_hwgrp_stats));

  return 0;
}

i32
cnxk_sched_exit (vlib_main_t *vm)
{
  return 0;
}

i32
cnxk_sched_init (vlib_main_t *vm, vlib_pci_addr_t *addr, uuid_t uuid_token)
{
  cnxk_plt_pci_device_t *dev;
  cnxk_sched_dev_t *sd;
  int rv = 0;

  sd = cnxk_sched_get_dev ();

  if (sd->init_done)
    {
      cnxk_sched_err ("Device is already initialized");
      return -1;
    }

  dev = cnxk_pci_dev_probe (vm, addr, uuid_token, NULL);
  if (!dev)
    {
      cnxk_sched_err ("Failed to probe %U PCI device", format_vlib_pci_addr,
		      addr);
      return -1;
    }
  sd->sso.pci_dev = dev;
  rv = roc_sso_dev_init (&sd->sso);
  if (rv)
    {
      cnxk_sched_err ("roc_sso_dev_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  if (roc_model_is_cn10k ())
    sched_ops = &sched_10k_ops;
  else
    ASSERT (0);

  sd->init_done = 1;

  return 0;
}

i32
cnxk_sched_grp_link (vlib_main_t *vm, u16 *grp, u8 n_hws, u16 n_grps)
{
  cnxk_sched_dev_t *sd;
  int rv = 0;

  sd = cnxk_sched_get_dev ();
  rv = roc_sso_hws_link (&sd->sso, n_hws, grp, n_grps, 0, 0);
  if (rv < 0)
    {
      cnxk_sched_err ("roc_sso_hws_link failed");
      return -1;
    }
  return 0;
}

i32
cnxk_sched_grp_unlink (vlib_main_t *vm, u16 *grp, u8 n_hws, u16 n_grps)
{
  cnxk_sched_dev_t *sd;
  int rv = 0;

  sd = cnxk_sched_get_dev ();
  rv = roc_sso_hws_unlink (&sd->sso, n_hws, grp, n_grps, 0, 0);
  if (rv < 0)
    {
      cnxk_sched_err ("roc_sso_hws_unlink failed");
      return -1;
    }
  return 0;
}

i32
cnxk_sched_grp_prio_set (vlib_main_t *vm, u16 grp, u8 prio)
{
  u8 grp_weight, grp_affinity, grp_prio;
  cnxk_sched_dev_t *sd;
  int rv = 0;

  sd = cnxk_sched_get_dev ();
  grp_weight = CNXK_SCHED_GRP_DEF_WEIGHT;
  grp_affinity = CNXK_SCHED_GRP_DEF_AFFINITY;

  grp_prio = cnxk_sched_grp_app_map_to_actual (vm->thread_index, prio);
  rv = roc_sso_hwgrp_set_priority (&sd->sso, grp, grp_weight, grp_affinity,
				   grp_prio);
  if (rv)
    {
      cnxk_sched_err ("roc_sso_hwgrp_set_priority set failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }
  return 0;
}

i32
cnxk_sched_thread_grp_link_status_get (vlib_main_t *vm, uword *grp_bitmap,
				       u8 thread_id)
{
  cnxk_sched_dev_t *sd;
  int i;

  sd = cnxk_sched_get_dev ();
  for (i = 0; i < sd->hw_grps_config; i++)
    {
      if (roc_sso_hwgrp_hws_link_status (&sd->sso, thread_id, i))
	clib_bitmap_set (grp_bitmap, i, 1);
    }

  return 0;
}

static i32
cnxk_sched_hws_config (vlib_main_t *vm, cnxk_sched_dev_t *sd, u8 n_hws)
{
  u64 addr;
  int i;

  for (i = 0; i < n_hws; i++)
    {
      addr = roc_sso_hws_base_get (&sd->sso, i);
      sd->hws[i].base = addr;
    }
  return 0;
}

static i32
cnxk_sched_hw_grp_config (vlib_main_t *vm, cnxk_sched_dev_t *sd, u16 n_queues)
{
  int q_id, rv = 0;
  u8 grp_prio;
  u64 addr;

  for (q_id = 0; q_id < n_queues; q_id++)
    {
      addr = roc_sso_hwgrp_base_get (&sd->sso, q_id);
      sd->hw_grps[q_id].base = addr;
      grp_prio = cnxk_sched_grp_app_map_to_actual (
	vm->thread_index, CNXK_SCHED_GRP_APP_DEF_PRIO);

      rv = cnxk_sched_grp_prio_set (vm, q_id, grp_prio);
      if (rv < 0)
	{
	  cnxk_sched_err ("cnxk_sched_grp_prio_set failed");
	  return -1;
	}

      cnxk_plt_write64_relaxed (
	1,
	uword_to_pointer (sd->hw_grps[q_id].base + SSO_LF_GGRP_QCTL, void *));
    }
  return 0;
}

static i32
cnxk_sched_xaq_buffer_config (vlib_main_t *vm, cnxk_sched_dev_t *sd,
			      u16 n_queues)
{
  u64 aura_handle;
  u32 n_xaq_lines;
  int rv;

  n_xaq_lines = n_queues * 4 + (MAX_WE / sd->sso.xae_waes);

  rv = roc_sso_hwgrp_init_xaq_aura (&sd->sso, n_xaq_lines);
  if (rv < 0)
    {
      cnxk_sched_err ("roc_sso_hwgrp_init_xaq_aura failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  aura_handle = roc_npa_aura_handle_to_aura (sd->sso.xaq.aura_handle);
  rv = roc_sso_hwgrp_alloc_xaq (&sd->sso, aura_handle, n_queues);
  if (rv < 0)
    {
      cnxk_sched_err ("roc_sso_hwgrp_alloc_xaq failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  return 0;
}

i32
cnxk_sched_config (vlib_main_t *vm, cnxk_sched_config_t sched_config)
{
  vlib_thread_main_t *tm;
  cnxk_sched_dev_t *sd;
  u16 n_queues;
  u8 n_hws;
  int rv;

  sd = cnxk_sched_get_dev ();
  tm = vlib_get_thread_main ();
  n_hws = tm->n_vlib_mains;
  n_queues = sched_config.n_queues;

  rv = roc_sso_rsrc_init (&sd->sso, n_hws, n_queues, 0);
  if (rv < 0)
    {
      cnxk_sched_err ("roc_sso_rsrc_init failed with '%s' error",
		      roc_error_msg_get (rv));
      return -1;
    }

  rv = cnxk_sched_xaq_buffer_config (vm, sd, n_queues);
  if (rv < 0)
    {
      cnxk_sched_err ("cnxk_sched_xaq_buffer_config, rv=%d", rv);
      return -1;
    }

  rv = cnxk_sched_hws_config (vm, sd, n_hws);
  if (rv < 0)
    {
      cnxk_sched_err ("cnxk_sched_hws_config failed, rv=%d", rv);
      return -1;
    }

  rv = cnxk_sched_hw_grp_config (vm, sd, n_queues);
  if (rv < 0)
    {
      cnxk_sched_err ("cnxk_sched_hw_grp_config failed, rv=%d", rv);
      return -1;
    }

  sd->hws_config = n_hws;
  sd->hw_grps_config = n_queues;

  return 0;
}

u8 *
cnxk_sched_tag_format (u8 *s, va_list *va)
{
  CLIB_UNUSED (vlib_main_t * vm);
  cnxk_sched_work_tag_t *tag;
  cnxk_sched_tt_t *tt;
  u32 indent;

  vm = va_arg (*va, vlib_main_t *);
  tag = va_arg (*va, cnxk_sched_work_tag_t *);
  tt = va_arg (*va, cnxk_sched_tt_t *);
  indent = format_get_indent (s);

  s = format (s, "Tag: 0x%x\n", tag->as_u32);
  s = format (s, "%Uflow_or_rq 0x%x, port 0x%x, ", format_white_space,
	      indent + 2, tag->flow_or_rq, tag->port);

  switch (tag->source)
    {
      /* clang-format off */
 #define _(source, index)                                                     \
     case CNXK_SCHED_WORK_SOURCE_##source:                                    \
       s = format (s, "source " #source ", ");                                \
       break;

     foreach_cnxk_sched_work_source;
 #undef _
    /* clang-format on */
    default:
      s = format (s, "source INVALID, ");
    }

  switch (*tt)
    {
      /* clang-format off */
 #define _(mode, value)                                                       \
     case CNXK_SCHED_TAG_##mode:                                              \
       s = format (s, "tag_type " #mode);                                     \
       break;

     foreach_cnxk_sched_tt;
 #undef _
      /* clang-format on */

    default:
      s = format (s, "tag_type INVALID");
    }
  return s;
}

u8 *
cnxk_drv_sched_tag_format (u8 *s, va_list *va)
{
  return sched_ops->sched_tag_format (s, va);
}

void
cnxk_drv_sched_info_dump (vlib_main_t *vm)
{
  sched_ops->sched_dump (vm);
}

i32
cnxk_drv_sched_init (vlib_main_t *vm, vlib_pci_addr_t *addr, uuid_t uuid_token)
{
  ASSERT (vm->thread_index == 0);
  return cnxk_sched_init (vm, addr, uuid_token);
}

i32
cnxk_drv_sched_config (vlib_main_t *vm, cnxk_sched_config_t sched_config)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_config (vm, sched_config);
}

i32
cnxk_drv_sched_grp_link (vlib_main_t *vm, u16 *grp, u8 thread_id, u16 n_grps)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_grp_link (vm, grp, thread_id, n_grps);
}

i32
cnxk_drv_sched_grp_unlink (vlib_main_t *vm, u16 *grp, u8 thread_id, u16 n_grps)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_grp_unlink (vm, grp, thread_id, n_grps);
}

i32
cnxk_drv_sched_grp_prio_set (vlib_main_t *vm, u16 grp, u16 prio)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_grp_prio_set (vm, grp, prio);
}

i32
cnxk_drv_sched_grp_stats_dump (vlib_main_t *vm, u16 grp,
			       cnxk_sched_grp_stats_t *stats)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_grp_stats_dump (vm, grp, stats);
}

i32
cnxk_drv_sched_thread_grp_link_status_get (vlib_main_t *vm, uword *grp_bitmap,
					   u8 thread_id)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_thread_grp_link_status_get (vm, grp_bitmap,
						      thread_id);
}

i32
cnxk_drv_sched_exit (vlib_main_t *vm)
{
  ASSERT (vm->thread_index == 0);
  return sched_ops->sched_exit (vm);
}

VLIB_REGISTER_LOG_CLASS (cnxk_sched_log) = {
  .class_name = "onp/sched",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
