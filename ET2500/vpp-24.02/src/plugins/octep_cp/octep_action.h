/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef __OCTEP_ACTION_H__
#define __OCTEP_ACTION_H__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

struct pf_config
{
  int n_vfs;
};

struct pem_config
{
  int n_pfs;
  struct pf_config pfconfig[64];
};

struct octep_pf_vf_cfg
{
  struct pem_config pemconfig[4];
  int n_pems;
  int pem_idx;
  int pf_idx;
  int is_vf;
  int vf_idx;
};

extern struct octep_pf_vf_cfg cfg_idx;

void octep_update_pktio (uint8_t cmd, uint32_t value);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
