/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_dpu_h
#define included_onp_drv_inc_dpu_h

typedef union
{
  u64 as_u64[3];
} cnxk_h2d_meta_t;

#define CNXK_H2D_META_SIZE (sizeof (cnxk_h2d_meta_t))

typedef union
{
  u64 as_u64;
  struct
  {
    u64 request_id : 16;
    u64 reserved : 2;
    u64 csum_verified : 2;
    u64 destqport : 22;
    u64 sport : 6;
    u64 opcode : 16;
  };
} cnxk_d2h_meta_t;

#define CNXK_D2H_META_SIZE (sizeof (cnxk_d2h_meta_t))

#define CNXK_D2H_CSUM_FAILED	0x0
#define CNXK_D2H_L4SUM_VERIFIED 0x1
#define CNXK_D2H_IPSUM_VERIFIED 0x2
#define CNXK_D2H_CSUM_VERIFIED                                                \
  (CNXK_D2H_L4SUM_VERIFIED | CNXK_D2H_IPSUM_VERIFIED)

#endif /* included_onp_drv_inc_dpu_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
