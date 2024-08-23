/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_crypto_h
#define included_onp_drv_inc_crypto_h

#include <onp/drv/inc/common.h>

/* Total onp crypto counter types */
#define CNXK_CRYPTO_COUNTER_TYPE_MAX (1)

typedef enum
{
  CNXK_CRYPTO_COUNTER_TYPE_DEFAULT,
} cnxk_crypto_counter_type_t;

typedef enum
{
  CNXK_CRYPTO_GROUP_AE,
  CNXK_CRYPTO_GROUP_SE,
  CNXK_CRYPTO_GROUP_IE,
  CNXK_CRYPTO_MAX_GROUPS
} cnxk_crypto_group_t;

typedef struct
{
  /* number of sw pending queues */
  u32 n_sw_pending_crypto_queues;

  /* number of descriptors per pending queue */
  u32 n_crypto_desc;

  u16 crypto_min_burst_size;

  /* uniqueu id to be used for initialising hw queue */
  u16 crypto_queue_id;

  u32 crypto_queue_pool_buffer_size;

  u32 num_pkt_buf;
} cnxk_crypto_queue_config_t;

typedef struct
{
  /* number of hardware queue */
  u32 n_crypto_hw_queues;

  cnxk_crypto_queue_config_t queue_config;

} cnxk_crypto_config_t;

/**
 * Cipher algorithms in a bit field structure
 */
typedef struct
{
  /** Support for cipher algorithms */
  u8 supported;
} cnxk_crypto_cipher_algo_capability_t;

/**
 * Authentication algorithms in a bit field structure
 */
typedef struct
{
  /** Support for authentication algorithms */
  u8 supported;
} cnxk_crypto_auth_algo_capability_t;

typedef struct
{
  /* cipher algo capability */
  cnxk_crypto_cipher_algo_capability_t *cipher_algos;

  /* authentication algo capability */
  cnxk_crypto_auth_algo_capability_t *auth_algos;

  /* IE specific capability */
  struct
  {
    u32 ipsec_max_num_sa;
    u32 ipsec_max_antireplay_ws;
    u64 ipsec_protocol_ah : 1;
    u64 ipsec_tunnel_mode : 1;
    u64 ipsec_transport_mode : 1;
    u64 ipsec_udp_encapsulation : 1;
    u64 ipsec_inbound_direction : 1;
    u64 ipsec_outbound_direction : 1;
    u64 ipsec_tunnel_ip_type_v4 : 1;
    u64 ipsec_tunnel_ip_type_v6 : 1;
    u64 ipsec_tunnel_cross_ip_type : 1;
    u64 ipsec_lookaside_mode : 1;
  };
} cnxk_crypto_grp_capability_t;

typedef struct
{
  /* Maximum descriptors per CPT queue */
  u32 max_crypto_descriptors;

  /* Maximum CPT queues */
  u32 max_crypto_queues;

  u32 cnxk_crypto_groups;

  /* Capabilities unique to SE, IE and AE groups */
  cnxk_crypto_grp_capability_t grp_capa[CNXK_CRYPTO_MAX_GROUPS];

} cnxk_crypto_capability_t;

i16 cnxk_drv_crypto_probe (vlib_main_t *vm, vlib_pci_addr_t *addr,
			   vlib_pci_dev_handle_t *pci_handle);
i16 cnxk_drv_crypto_remove (vlib_main_t *vm, u16 cnxk_crypto_index);

i32 cnxk_drv_crypto_configure (vlib_main_t *vm, u16 cnxk_crypto_index,
			       cnxk_crypto_config_t *config);
i32 cnxk_drv_crypto_dev_clear (vlib_main_t *vm, u16 cnxk_crypto_index);

cnxk_crypto_capability_t *
cnxk_drv_crypto_capability_get (vlib_main_t *vm, u16 cnxk_crypto_index);

i32 cnxk_drv_crypto_queue_init (vlib_main_t *vm, u16 cnxk_crypto_index,
				cnxk_crypto_queue_config_t *config);

i32 cnxk_drv_crypto_sw_queue_init (vlib_main_t *vm);

uintptr_t cnxk_drv_crypto_queue_get (vlib_main_t *vm, u16 cnxk_crypto_index,
				     u16 cnxk_crypto_queue);

int cnxk_drv_crypto_group_add (vlib_main_t *vm, u16 cnxk_crypto_index,
			       cnxk_crypto_group_t group);

u8 *cnxk_drv_crypto_format_capability (u8 *s, va_list *arg);

int cnxk_drv_crypto_enqueue_aead_aad_enc (vlib_main_t *vm,
					  vnet_crypto_async_frame_t *frame,
					  u8 aad_len);

int cnxk_drv_crypto_enqueue_aead_aad_dec (vlib_main_t *vm,
					  vnet_crypto_async_frame_t *frame,
					  u8 aad_len);

i32 cnxk_drv_crypto_session_create (vlib_main_t *vm,
				    vnet_crypto_key_index_t key_index);

void cnxk_drv_crypto_key_add_handler (vlib_main_t *vm,
				      vnet_crypto_key_index_t key_index);

void cnxk_drv_crypto_key_del_handler (vlib_main_t *vm,
				      vnet_crypto_key_index_t key_index);

vnet_crypto_async_frame_t *
cnxk_drv_crypto_frame_dequeue (vlib_main_t *vm, u32 *nb_elts_processed,
			       u32 *enqueue_thread_idx);

int cnxk_drv_crypto_enqueue_linked_alg_enc (vlib_main_t *vm,
					    vnet_crypto_async_frame_t *frame);

int cnxk_drv_crypto_enqueue_linked_alg_dec (vlib_main_t *vm,
					    vnet_crypto_async_frame_t *frame);

void cnxk_drv_crypto_set_success_packets_counters (
  cnxk_crypto_counter_type_t type,
  vlib_simple_counter_main_t *success_packets);

void cnxk_drv_crypto_set_pending_packets_counters (
  cnxk_crypto_counter_type_t type,
  vlib_simple_counter_main_t *pending_packets);

void cnxk_drv_crypto_set_crypto_inflight_counters (
  cnxk_crypto_counter_type_t type,
  vlib_simple_counter_main_t *crypto_inflight);
#endif /* included_onp_drv_inc_crypto_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
