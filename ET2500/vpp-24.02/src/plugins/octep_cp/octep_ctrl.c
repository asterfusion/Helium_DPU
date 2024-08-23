/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>

#include "octep_cp_lib.h"
#include "octep_input.h"
#include "octep_config.h"
#include <onp/onp.h>
#include <vpp/app/version.h>
#include <assert.h>
#include <vnet/plugin/plugin.h>

/* Control plane version */
#define CP_VERSION_MAJOR   1
#define CP_VERSION_MINOR   0
#define CP_VERSION_VARIANT_MIN 0
#define CP_VERSION_VARIANT_CUR 1
#define MAX_EVENTS	       16

#define CP_VERSION_MIN                                                        \
  (OCTEP_CP_VERSION (CP_VERSION_MAJOR, CP_VERSION_MINOR,                      \
		     CP_VERSION_VARIANT_MIN))

#define CP_VERSION_MAX                                                        \
  (OCTEP_CP_VERSION (CP_VERSION_MAJOR, CP_VERSION_MINOR,                      \
		     CP_VERSION_VARIANT_CUR))

#define SOC_CFG_PATH "/etc/vpp/octep_cp_cn10kxx.cfg"
struct octep_pf_vf_cfg cfg_idx;

/*
 * The PERST# (PCI Express Reset) signal is an open drain, active low output
 * from the root port. It is released when all power rails and the REFCLK
 * signal have stabilized.
 */
static volatile int perst = 0;
static int hb_interval = 0;

struct octep_cp_lib_cfg cp_lib_cfg = { 0 };

static int
process_events ()
{
  struct octep_cp_event_info e[MAX_EVENTS];
  int n, i;

  n = octep_cp_lib_recv_event (e, MAX_EVENTS);
  if (n < 0)
    return n;

  for (i = 0; i < n; i++)
    {
      if (e[i].e == OCTEP_CP_EVENT_TYPE_PERST)
	{
	  clib_warning ("Event: perst on dom[%d]\n", e[i].u.perst.dom_idx);
	  perst = 1;
	}
    }

  return 0;
}

static int
send_heartbeat ()
{
  struct octep_cp_event_info info;
  int i, j;

  info.e = OCTEP_CP_EVENT_TYPE_HEARTBEAT;
  for (i = 0; i < cp_lib_cfg.ndoms; i++)
    {
      info.u.hbeat.dom_idx = cp_lib_cfg.doms[i].idx;
      for (j = 0; j < cp_lib_cfg.doms[i].npfs; j++)
	{
	  info.u.hbeat.pf_idx = cp_lib_cfg.doms[i].pfs[j].idx;
	  octep_cp_lib_send_event (&info);
	}
    }

  return 0;
}

void
sigint_handler (int sig_num)
{
  if (sig_num == SIGALRM)
    {
      if (perst)
	return;
      send_heartbeat ();
      alarm (hb_interval);
    }
}

static int
set_fw_ready (int ready)
{
  struct octep_cp_event_info info;
  int i, j;

  info.e = OCTEP_CP_EVENT_TYPE_FW_READY;
  info.u.fw_ready.ready = ready;
  for (i = 0; i < cp_lib_cfg.ndoms; i++)
    {
      info.u.fw_ready.dom_idx = cp_lib_cfg.doms[i].idx;
      for (j = 0; j < cp_lib_cfg.doms[i].npfs; j++)
	{
	  info.u.fw_ready.pf_idx = cp_lib_cfg.doms[i].pfs[j].idx;
	  octep_cp_lib_send_event (&info);
	}
    }

  return 0;
}

static uword
octep_cp_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame)
{
  int err = 0, i, j;
  struct pem_cfg *pem;
  struct pf_cfg *pf;
  const char *soc_cfg = SOC_CFG_PATH;

  /* init will wake it up */
  vlib_process_wait_for_event (vm);

  err = octep_cp_config_init (soc_cfg);
  if (err)
    return err;

  // signal(SIGINT, sigint_handler);
  signal (SIGALRM, sigint_handler);

  cp_lib_cfg.ndoms = cfg.npem;
  cp_lib_cfg.min_version = CP_VERSION_MIN;
  cp_lib_cfg.max_version = CP_VERSION_MAX;
  cfg_idx.n_pems = cfg.npem;
  pem = cfg.pems;
  i = 0;
  while (pem)
    {
      cp_lib_cfg.doms[i].idx = pem->idx;
      cp_lib_cfg.doms[i].npfs = pem->npf;
      cfg_idx.pemconfig[i].n_pfs = pem->npf;
      pf = pem->pfs;
      j = 0;
      while (pf)
	{
	  cp_lib_cfg.doms[i].pfs[j++].idx = pf->idx;
	  if (hb_interval == 0 || pf->info.hb_interval < hb_interval)
	    hb_interval = pf->info.hb_interval;

	  pf = pf->next;
	}
      pem = pem->next;
      i++;
    }
  err = octep_cp_lib_init (&cp_lib_cfg);
  if (err)
    return err;

  err = octep_cp_initialize_receive_vector ();
  if (err)
    {
      octep_cp_lib_uninit ();
      return err;
    }

  set_fw_ready (1);
  clib_warning ("Heartbeat interval : %u msecs\n", hb_interval);
  hb_interval /= 1000;
  alarm (hb_interval);
  while (1)
    {
      /*
       * Host PF driver has a timeout of 500ms, so keeping polling interval
       * less than that(100ms). Else the host PF driver octeon_ep.ko timesout
       */
      vlib_process_wait_for_event_or_clock (vm, 0.1);
      vlib_process_get_events (vm, NULL);
      loop_process_msgs ();
      process_events ();
    }
  return 0;
}

static clib_error_t *
octep_cp_process_exit (vlib_main_t *vm)
{
  set_fw_ready (0);
  octep_cp_lib_uninit ();
  octep_cp_initialize_receive_vector ();
  octep_cp_config_uninit ();
  return 0;
}

VLIB_REGISTER_NODE (octep_cp_process_node, static) = {
  .function = octep_cp_process,
  .name = "octep-cp-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

clib_error_t *
octep_cp_init (vlib_main_t *vm)
{

  vlib_process_signal_event (vlib_get_main (), octep_cp_process_node.index, 0,
			     0);
  return NULL;
}

VLIB_INIT_FUNCTION (octep_cp_init) = {
  .runs_after = VLIB_INITS ("onp_plugin_init"),
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "OCTEON PCI End-point Control Agent",
  .default_disabled = 1,
};

VLIB_MAIN_LOOP_EXIT_FUNCTION (octep_cp_process_exit);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
