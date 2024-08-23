/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_ipsec_defs_h
#define included_onp_drv_inc_ipsec_defs_h

#include <onp/drv/inc/common.h>

#define IPSEC_ESP_ENCRYPT_OPT_ENABLE

typedef enum
{
  CNXK_IPSEC_OFFLOAD_FLAG_LOOKASIDE = (1 << 0),
  CNXK_IPSEC_OFFLOAD_FLAG_INL_OUTBOUND = (1 << 1),
  CNXK_IPSEC_OFFLOAD_FLAG_INL_INBOUND = (1 << 2),
} cnxk_ipsec_offload_flag_t;

typedef enum
{
  CNXK_IPSEC_FLAG_ENCRYPT_OP = (1 << 0),
  CNXK_IPSEC_FLAG_DECRYPT_OP = (1 << 1),
} cnxk_ipsec_flag_op_t;

typedef enum
{
  CNXK_VNET_BUFFER_OFFLOAD_F_IPSEC_OUTBOUND_INLINE = VNET_BUFFER_F_AVAIL1,
} cnxk_vnet_buffer_offload_flag_t;

#endif /* included_onp_drv_inc_ipsec_defs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
