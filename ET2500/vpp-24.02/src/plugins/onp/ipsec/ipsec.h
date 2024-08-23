/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP IPsec interface.
 */

#ifndef included_onp_ipsec_ipsec_h
#define included_onp_ipsec_ipsec_h

#include <onp/drv/inc/ipsec.h>
#include <onp/drv/inc/crypto.h>
#include <vnet/vnet.h>
#include <vnet/ipsec/esp.h>
#include <vnet/ipsec/ipsec.h>

#define ONP_IPSEC_QUEUE 0

#define ONP_IPSEC_INLINE_OUTB_NB_CRYPTO_LF 1

#define ONP_IPSEC_INLINE_OUTB_NB_DESC 8192

#define ONP_IPSEC_REASSEMBLY_MAX_WAIT_TIME 1000

#define ONP_IPSEC_REASSEMBLY_ACTIVE_LIMIT     0xFFF
#define ONP_IPSEC_REASSEMBLY_ACTIVE_THRESHOLD 2001
#define ONP_IPSEC_REASSEMBLY_ZOMBIE_LIMIT     0x7FF
#define ONP_IPSEC_REASSEMBLY_ZOMBIE_THRESHOLD 2001

typedef struct
{
  u32 n_crypto_desc_per_queue;
  i8 is_ipsec_backend_enabled;
  i8 is_inline_outbound_enabled;
  u16 crypto_hw_queue_id;
  u32 reassembly_max_wait_time;
} onp_ipsec_config_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  uintptr_t in_ipsec_queue;
  u32 in_dev_id;
  uintptr_t out_ipsec_queue;
  u32 out_dev_id;
  /* Inline or lookaside IPsec */
  u16 ipsec_offloads_configured;
  /* Next drop node index for IPv4 ESP encryption */
  u16 onp_esp4_enc_post_drop_next;
  /* Next node index for IPv4 ESP decryption */
  u16 onp_esp4_dec_post_next;
  /* Next drop node index for IPv4 ESP encryption */
  u16 onp_esp4_dec_post_drop_next;
  /* Next drop node index for IPv6 ESP encryption */
  u16 onp_esp6_enc_post_drop_next;
  /* Next node index for IPv6 ESP decryption */
  u16 onp_esp6_dec_post_next;
  /* Next drop node index for IPv6 ESP decryption */
  u16 onp_esp6_dec_post_drop_next;
  /* Next node index for IPv4 ESP tunnel encryption */
  u16 onp_esp4_enc_tun_post_next;
  /* Next node index for IPv6 ESP tunnel encryption */
  u16 onp_esp6_enc_tun_post_next;

} onp_ipsec_main_t;

extern onp_ipsec_main_t onp_ipsec_main;
clib_error_t *onp_ipsec_setup (vlib_main_t *vm);

#endif /* included_onp_ipsec_ipsec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
