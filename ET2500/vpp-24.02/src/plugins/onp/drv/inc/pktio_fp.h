/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pktio_fp_h
#define included_onp_drv_inc_pktio_fp_h

#include <onp/drv/modules/pktio/pktio_priv.h>

static_always_inline u32
cnxk_pktio_is_packet_from_cpt_march (cnxk_pktio_nix_parse_t *rxp)
{
  switch (CNXK_MARCH_PLATFORM)
    {
    case CNXK_PLATFORM_CN10K:
      return rxp->parse.chan >> 11;

    case CNXK_PLATFORM_CN9K:
      return 0;

    default:
      ALWAYS_ASSERT (0);
    }
  return 0;
}

#endif /* included_onp_drv_inc_pktio_fp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
