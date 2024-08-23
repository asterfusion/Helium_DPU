/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pktio_defs_h
#define included_onp_drv_inc_pktio_defs_h

#include <onp/drv/inc/common.h>
#define CNXK_PKTIO_EXT_HDR_SIZE	  sizeof (cnxk_pktio_external_hdr_t)
#define CNXK_PKTIO_NPA_BUF_OFFSET 10

/* Common pktio macro/definitions used by other modules */
typedef struct
{
  /* NIX WQE/CQE header */
  union
  {
    uint64_t nix_xqe_hdr;
    struct nix_wqe_hdr_s wqe;
    struct nix_cqe_hdr_s cqe;
  };
  /* NIX RX parse */
  union nix_rx_parse_u rx_parse;
  /* Scatter gather descriptors and iovas */
  struct nix_rx_sg_s sg0;
  struct nix_iova_s iova0;
  struct nix_iova_s iova1;
  struct nix_iova_s iova2;
  struct nix_rx_sg_s sg1;
  struct nix_iova_s iova3;
  struct nix_iova_s iova4;
  struct nix_iova_s iova5;
} cnxk_pktio_meta_t __cnxk_cache_aligned;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  u8 ext_buf[VLIB_BUFFER_ALIGN * CNXK_PKTIO_NPA_BUF_OFFSET];

  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  cnxk_pktio_meta_t meta;
} cnxk_pktio_external_hdr_t __cnxk_cache_aligned;

STATIC_ASSERT (
  sizeof (cnxk_pktio_external_hdr_t) ==
    (sizeof (cnxk_pktio_meta_t) +
     VLIB_BUFFER_ALIGN * CNXK_PKTIO_NPA_BUF_OFFSET),
  "cnxk pktio external header size should be equal to sizeof "
  "(cnxk_pktio_meta_t) + VLIB_BUFFER_ALIGN * CNXK_PKTIO_NPA_BUF_OFFSET");

#endif /* included_onp_drv_inc_pktio_defs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
