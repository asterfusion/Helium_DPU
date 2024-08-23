/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_ipsec_fp_defs_h
#define included_onp_drv_inc_ipsec_fp_defs_h

#include <onp/drv/inc/ipsec_fp_defs_cn10k.h>
#include <onp/drv/inc/ipsec_defs.h>
#include <onp/drv/inc/sched_defs.h>

typedef struct
{
  uint32_t outb_nb_desc;
  uint16_t outb_nb_crypto_qs;
  struct roc_cpt_lf *cpt_lf;
  u64 cpt_io_addr;
  u32 cached_cpt_pkts;
} cnxk_ipsec_fp_ctx_t;

#define foreach_onp_esp_encrypt_tun_next                                      \
  _ (DROP4, "ip4-drop")                                                       \
  _ (DROP6, "ip6-drop")                                                       \
  _ (ADJ_MIDCHAIN_TX, "adj-midchain-tx")

/* clang-format off */
typedef enum
{
#define _(v, s) ONP_ESP_ENCRYPT_TUN_NEXT_##v,
  foreach_onp_esp_encrypt_tun_next
#undef _
#define _(Y) ONP_ESP_ENCRYPT_TUN_NEXT_PREP##Y,
  foreach_sched_handoff_core
#undef _
} onp_esp_encrypt_tun_next_t;
/* clang-format on */

#define ONP_ESP_ENCRYPT_TUN_N_NEXT (ONP_ESP_ENCRYPT_TUN_NEXT_PREP35 + 1)

#define foreach_onp_drv_encrypt_error                                         \
  _ (RX_PKTS, "ESP pkts received")                                            \
  _ (RX_POST_PKTS, "ESP-POST pkts received")                                  \
  _ (NOT_L3PKT, "L3 header offset not valid")                                 \
  _ (CHAINING_NOSUPP, "Packet chainining not supported in IPsec")             \
  _ (SEQ_CYCLED, "sequence number cycled (packet dropped)")                   \
  _ (HANDOFF, "handoff")                                                      \
  _ (INVALID_SA, "invalid SA")                                                \
  _ (FRAME_ALLOC, "encrypt ipsec frame alloc failed")                         \
  _ (UNDEFINED, "undefined encrypt error")

/* clang-format off */
typedef enum
{
#define _(sym, str) ONP_ESP_ENCRYPT_ERROR_##sym,
  foreach_onp_drv_encrypt_error
#undef _
#define _(sym, str) ONP_ESP_ENCRYPT_CN10K_ERROR_##sym,
  foreach_onp_drv_cn10k_ipsec_ucc
#undef _
} onp_esp_encrypt_error_t;
/* clang-format on */

#define foreach_onp_esp_decrypt_next                                          \
  _ (DROP, "error-drop")                                                      \
  _ (DROP4, "ip4-drop")                                                       \
  _ (DROP6, "ip6-drop")                                                       \
  _ (IP4_INPUT, "ip4-input-no-checksum")                                      \
  _ (IP6_INPUT, "ip6-input")                                                  \
  _ (MPLS_INPUT, "mpls-input")                                                \
  _ (L2_INPUT, "l2-input")

/* clang-format off */
typedef enum
{
#define _(v, s) ONP_ESP_DECRYPT_NEXT_##v,
  foreach_onp_esp_decrypt_next
#undef _
  ONP_ESP_DECRYPT_N_NEXT,
} onp_esp_decrypt_next_t;
/* clang-format on */

#define foreach_onp_esp_decrypt_error                                         \
  _ (RX_PKTS, "ESP pkts received")                                            \
  _ (RX_POST_PKTS, "ESP-POST pkts received")                                  \
  _ (DECRYPTION_FAILED, "ESP decryption failed")                              \
  _ (CHAINING_NOSUPP, "Packet chainining not supported in IPsec")             \
  _ (REPLAY, "SA replayed packet")                                            \
  _ (INST_SUBMIT_ERROR, "inst submission error")                              \
  _ (INVALID_SA, "invalid inbound SA")                                        \
  _ (L3_HDR_NOT_VALID, "l3 header offset not valid")                          \
  _ (FRAME_ALLOC, "decrypt ipsec frame alloc failed")                         \
  _ (UNDEFINED, "undefined decrypt error")

/* clang-format off */
typedef enum
{
#define _(sym, str) ONP_ESP_DECRYPT_ERROR_##sym,
  foreach_onp_esp_decrypt_error
#undef _
#define _(sym, str) ONP_ESP_DECRYPT_CN10K_ERROR_##sym,
  foreach_onp_drv_cn10k_ipsec_ucc
#undef _
} onp_esp_decrypt_error_t;
/* clang-format on */

typedef struct
{
  u32 __pad_vnet[3];
  u32 sa_index;
  u32 seq;
  u16 next_index;
  u16 pre_ipsec_l3_hdr_sz;
} onp_esp_post_data_t;

STATIC_ASSERT (sizeof (onp_esp_post_data_t) <=
		 STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
	       "Custom meta-data too large for vnet_buffer_opaque_t");

#define onp_esp_post_data(b)                                                  \
  ((onp_esp_post_data_t *) ((u8 *) (b)->opaque +                              \
			    STRUCT_OFFSET_OF (vnet_buffer_opaque_t, unused)))

STATIC_ASSERT (
  STRUCT_OFFSET_OF (onp_esp_post_data_t, sa_index) ==
    STRUCT_OFFSET_OF (typeof (((vnet_buffer_opaque_t *) 0)->ipsec), sad_index),
  "onp sa_index is not same location as vnet ipsec");

/* Following structure fields for inline Inbound IPsec */
typedef struct
{
  void *cpt_parse;
  u16 uc_err;
  u8 is_ipsec_op_fail;
} cnxk_ipsec_inl_data_t;

STATIC_ASSERT (sizeof (cnxk_ipsec_inl_data_t) <=
		 STRUCT_SIZE_OF (vnet_buffer_opaque_t, unused),
	       "Custom inline IPsec meta-data too large for vlib->opaque");

#define cnxk_ipsec_inl_data(b)                                                \
  ((cnxk_ipsec_inl_data_t *) ((u8 *) (b)->opaque +                            \
			      STRUCT_OFFSET_OF (vnet_buffer_opaque_t,         \
						unused)))

typedef struct
{
  u64 __pad_vnet2[2];
  void *res_ptr;
  i32 metadata_off;
} onp_esp_post_data2_t;

STATIC_ASSERT (sizeof (onp_esp_post_data2_t) <=
		 STRUCT_SIZE_OF (vnet_buffer_opaque2_t, unused),
	       "Custom meta-data too large for vnet_buffer_opaque2_t");

#define onp_esp_post_data2(b)                                                 \
  ((onp_esp_post_data2_t *) ((u8 *) (b)->opaque2 +                            \
			     STRUCT_OFFSET_OF (vnet_buffer_opaque2_t,         \
					       unused)))

#endif /* included_onp_drv_inc_ipsec_fp_defs_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
