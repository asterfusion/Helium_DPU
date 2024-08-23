/*
 * Copyright (c) 2023 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#include <onp/onp.h>
#include <vnet/vnet.h>
#include "octep_action.h"
#include "octep_ctrl_net.h"
#include <vlib/unix/plugin.h>
#include <vnet/plugin/plugin.h>

void
octep_update_pktio (uint8_t cmd, uint32_t value)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;

  pool_foreach (si, im->sw_interfaces)
    {
      vnet_hw_interface_set_mtu (vnm, si->hw_if_index, value);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
