/*
 * Copyright (c) 2022 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_ipsec_fp_defs_cn10k_h
#define included_onp_drv_inc_ipsec_fp_defs_cn10k_h

#include <onp/drv/inc/pktio_defs.h>

#define foreach_onp_drv_cn10k_ipsec_ucc                                       \
  _ (SUCCESS, "IPsec pkts successfully processed")                            \
  _ (ERR_SA_INVAL, "SA invalid")                                              \
  _ (ERR_SA_EXPIRED, "SA hard-expired")                                       \
  _ (ERR_SA_OVERFLOW, "SA overflow")                                          \
  _ (ERR_SA_ESP_BAD_ALGO, "ESP bad algorithm")                                \
  _ (ERR_SA_AH_BAD_ALGO, "SA AH bad algorithm")                               \
  _ (ERR_SA_BAD_CTX, "Bad SA context received on CPT")                        \
  _ (SA_CTX_FLAG_MISMATCH, "SA context flags mismatch")                       \
  _ (ERR_AOP_IPSEC, "AOP logical error")                                      \
  _ (ERR_PKT_IP, "Bad IP version or TTL")                                     \
  _ (ERR_PKT_IP6_BAD_EXT, "IPv6 mobility extension not supported")            \
  _ (ERR_PKT_IP6_HBH, "Error with IPv6 hop-by-hop header")                    \
  _ (ERR_PKT_IP6_BIGEXT, "IPv6 extension header length exceeded")             \
  _ (ERR_PKT_IP_ULP, "Bad protocol in IP header")                             \
  _ (ERR_PKT_SA_MISMATCH, "IP address mismatch b/w SA and packet")            \
  _ (ERR_PKT_SPI_MISMATCH, "SPI mismatch b/w SA and packet")                  \
  _ (ERR_PKT_ESP_BADPAD, "Bad padding in ESP packet")                         \
  _ (ERR_PKT_BADICV, "ICV verification failed")                               \
  _ (ERR_PKT_REPLAY_SEQ, "Sequence number out of anti-replay window")         \
  _ (ERR_PKT_BADNH, "Bad next-hop")                                           \
  _ (ERR_PKT_SA_PORT_MISMATCH, "Port mismatch b/w packet and SA")             \
  _ (ERR_PKT_BAD_DLEN, "Dlen mismatch")                                       \
  _ (ERR_SA_ESP_BAD_KEYS, "Bad key-size for selected ESP algorithm")          \
  _ (ERR_SA_AH_BAD_KEYS, "Bad key-size for selected AH algorithm")            \
  _ (ERR_SA_BAD_IP, "IP version mismatch b/w packet and SA")                  \
  _ (ERR_PKT_IP_FRAG, "IPsec packet is an outer-IP fragment")                 \
  _ (ERR_PKT_REPLAY_WINDOW, "Sequence number already seen")                   \
  _ (SUCCESS_PKT_IP_BADCSUM, "Bad IP checksum ")                              \
  _ (SUCCESS_PKT_L4_GOODCSUM, "Good inner L4 checksum")                       \
  _ (SUCCESS_PKT_L4_BADCSUM, "Bad inner L4 checksum")                         \
  _ (SUCCESS_SA_SOFTEXP_FIRST, "SA soft-expired - first encounter")           \
  _ (SUCCESS_PKT_UDPESP_NZCSUM, "Non-zero UDP checksum in UDP-ESP packet")    \
  _ (SUCCESS_SA_SOFTEXP_AGAIN, "SA soft-expired - subsequent encounter")      \
  _ (SUCCESS_PKT_UDP_ZEROCSUM, "Zero UDP checksum")

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  struct cpt_inst_s inst;
  CLIB_ALIGN_MARK (c0_next64, 64);
  union cpt_res_s res;
  u32 dlen_adj;
  u16 sa_bytes;
  u8 core_id;
  u8 ip_ver;
  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u64 nixtx[4];
  CLIB_CACHE_LINE_ALIGN_MARK (c3);
  u8 sg_buffer[1024];
  bool is_sg_mode;
} cn10k_ipsec_outbound_pkt_meta_t;

STATIC_ASSERT (
  sizeof (cn10k_ipsec_outbound_pkt_meta_t) <= CNXK_PKTIO_EXT_HDR_SIZE,
  "cn10k_ipsec_outbound_pkt_meta_t greater than CNXK_PKTIO_EXT_HDR_SIZE");

#define onp_ipsec_pkt_meta(b)                                                 \
  ((cn10k_ipsec_outbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b))

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  struct cpt_inst_s inst;
  CLIB_ALIGN_MARK (c0_next64, 64);
  union cpt_res_s res;
  u32 dlen_adj;
  u8 core_id;
  u8 ip_ver;
  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u8 sg_buffer[1024];
} cn10k_ipsec_inbound_pkt_meta_t;

STATIC_ASSERT (
  sizeof (cn10k_ipsec_inbound_pkt_meta_t) <= CNXK_PKTIO_EXT_HDR_SIZE,
  "cn10k_ipsec_inbound_pkt_meta_t greater than CNXK_PKTIO_EXT_HDR_SIZE");

#define onp_ipsec_inb_pkt_meta(b)                                             \
  ((cn10k_ipsec_inbound_pkt_meta_t *) CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER (b))

#endif /* included_onp_drv_inc_ipsec_fp_defs_cn10k_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
