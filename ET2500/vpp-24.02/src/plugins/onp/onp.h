/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief OCTEON native plugin interface.
 */

#ifndef included_onp_onp_h
#define included_onp_onp_h

#include <assert.h>
#include <string.h>
#define __USE_GNU
#include <dlfcn.h>
#include <stdbool.h>
#include <vppinfra/vec.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vlib/vlib.h>
#include <vlib/pci/pci.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/plugin/plugin.h>
#include <vnet/flow/flow.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>

#include <onp/drv/inc/common.h>

#include <onp/pool/buffer.h>
#include <onp/sched/sched.h>
#include <onp/pktio/pktio.h>
#include <onp/crypto/crypto.h>
#include <onp/ipsec/ipsec.h>

#define ONP_MAJOR_VERSION 3
#define ONP_MINOR_VERSION 2
#define ONP_PATCH_VERSION 0

#define ONP_VERSION_STR_EXPAND(x) #x

#define ONP_VERSION_TO_STR(x) ONP_VERSION_STR_EXPAND (x)

#define ONP_VERSION_STR                                                       \
  ONP_VERSION_TO_STR (ONP_MAJOR_VERSION)                                      \
  "." ONP_VERSION_TO_STR (ONP_MINOR_VERSION) "." ONP_VERSION_TO_STR (         \
    ONP_PATCH_VERSION)

#define ONP_INIT_MAGIC_NUM 0xdeadbeaf
#define onp_get_main()	   &onp_main

#define onp_pktio_err	 cnxk_pktio_err
#define onp_pktio_warn	 cnxk_pktio_warn
#define onp_pktio_notice cnxk_pktio_notice
#define onp_pktio_debug	 cnxk_pktio_debug

#define onp_pool_err	cnxk_pool_err
#define onp_pool_warn	cnxk_pool_warn
#define onp_pool_notice cnxk_pool_notice
#define onp_pool_debug	cnxk_pool_debug

#define onp_sched_err	 cnxk_sched_err
#define onp_sched_warn	 cnxk_sched_warn
#define onp_sched_notice cnxk_sched_notice
#define onp_sched_debug	 cnxk_sched_debug

#define onp_crypto_err	  cnxk_crypto_err
#define onp_crypto_warn	  cnxk_crypto_warn
#define onp_crypto_notice cnxk_crypto_notice
#define onp_crypto_debug  cnxk_crypto_debug

#define onp_ipsec_err	 cnxk_ipsec_err
#define onp_ipsec_warn	 cnxk_ipsec_warn
#define onp_ipsec_notice cnxk_ipsec_notice
#define onp_ipsec_debug	 cnxk_ipsec_debug

static_always_inline const char *
onp_version_str (void)
{
  return ONP_VERSION_STR;
}

typedef struct
{
  /* Pktio */
  onp_pktio_config_t onp_pktioconf_default;
  onp_pktio_config_t *onp_pktioconfs;
  uword *onp_pktio_config_index_by_pci_addr;

  /* Sched */
  onp_sched_config_t onp_schedconf;

  /* Crypto */
  i8 is_crypto_config_enabled;
  onp_crypto_config_t *onp_cryptoconfs;
  uword *onp_crypto_config_index_by_pci_addr;

  /* IPsec */
  onp_ipsec_config_t onp_ipsecconf;

  /* Pool */
  u32 onp_num_pkt_buf;
  i16 onp_pktpool_refill_deplete_sz;
} onp_config_main_t;

/* clang-format off */

/*
 * Plugin generic counters
 * All of them are simple counters
 */

/* counter, name, verbose */
#define foreach_onp_counters                                                                                  \
  _ (0, pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].refill,              "default-pool-refill-count", 1)             \
  _ (1, pool[CNXK_POOL_COUNTER_TYPE_DEFAULT].deplete,             "default-pool-deplete-count", 1)            \
  _ (2, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_tun_pkts,    "esp4-encrypt-tun-pkts",    1)                \
  _ (3, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_result_fail,  "esp4-encrypt-result-fail",  1)              \
  _ (4, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_tun_pkts,    "esp6-encrypt-tun-pkts",    1)                \
  _ (5, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_result_fail,  "esp6-encrypt-result-fail",  1)              \
  _ (6, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_pkts_noop,    "esp4-decrypt-pkts-noop",   1)               \
  _ (7, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_pkts_submit,  "esp4-decrypt-pkts-submit",  1)              \
  _ (8, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_result_fail,  "esp4-decrypt-result-fail",  1)              \
  _ (9, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_pkts_recv,    "esp4-decrypt-pkts-recv",    1)              \
  _ (10, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_frame_submit, "esp4-decrypt-frame-submit", 1)             \
  _ (11, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].decrypt_frame_recv,   "esp4-decrypt-frame-recv",   1)             \
  _ (12, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_pkts_noop,    "esp6-decrypt-pkts-noop",    1)             \
  _ (13, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_pkts_submit,  "esp6-decrypt-pkts-submit",  1)             \
  _ (14, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_result_fail,  "esp6-decrypt-result-fail",  1)             \
  _ (15, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_pkts_recv,    "esp6-decrypt-pkts-recv",    1)             \
  _ (16, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_frame_submit, "esp6-decrypt-frame-submit", 1)             \
  _ (17, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].decrypt_frame_recv,   "esp6-decrypt-frame-recv",   1)             \
  _ (18, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_tun_pkts_noop,    "esp4-encrypt-tun-pkts-noop",    1)     \
  _ (19, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_tun_pkts_submit,  "esp4-encrypt-tun-pkts-submit",  1)     \
  _ (20, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_tun_frame_submit, "esp4-encrypt-tun-frame-submit", 1)     \
  _ (21, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_tun_pkts_noop,    "esp6-encryp-tun-t-pkts-noop",    1)    \
  _ (22, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_tun_pkts_submit,  "esp6-encrypt-tun-pkts-submit",  1)     \
  _ (23, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_tun_frame_submit, "esp6-encrypt-tun-frame-submit", 1)     \
  _ (24, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP4].encrypt_post_tun_pkts_recv, "esp4-encrypt-post-tun-pkts-recv", 1) \
  _ (25, ipsec[ONP_IPSEC_COUNTER_TYPE_ESP6].encrypt_post_tun_pkts_recv, "esp6-encrypt-post-tun-pkts-recv", 1) \
  _ (26, crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT].pending_packets, "default-crypto-pending-packets", 1)       \
  _ (27, crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT].crypto_inflight, "default-crypto-crypto-inflight", 1)	      \
  _ (28, crypto[CNXK_CRYPTO_COUNTER_TYPE_DEFAULT].success_packets, "default-crypto-success-packets", 1)

/* clang-format on */

#define foreach_pool_counter_names                                            \
  _ (refill)                                                                  \
  _ (deplete)

#define foreach_ipsec_counter_names                                           \
  _ (encrypt_tun_pkts)                                                        \
  _ (encrypt_result_fail)                                                     \
  _ (decrypt_pkts_noop)                                                       \
  _ (decrypt_pkts_submit)                                                     \
  _ (decrypt_frame_submit)                                                    \
  _ (decrypt_result_fail)                                                     \
  _ (decrypt_pkts_recv)                                                       \
  _ (decrypt_frame_recv)                                                      \
  _ (encrypt_tun_pkts_noop)                                                   \
  _ (encrypt_tun_pkts_submit)                                                 \
  _ (encrypt_tun_frame_submit)                                                \
  _ (encrypt_post_tun_pkts_recv)

#define foreach_crypto_counter_names                                          \
  _ (pending_packets)                                                         \
  _ (crypto_inflight)                                                         \
  _ (success_packets)

typedef struct
{
#define _(s) vlib_simple_counter_main_t s##_counters;
  foreach_ipsec_counter_names
#undef _
} onp_ipsec_counters_t;

typedef enum
{
  ONP_IPSEC_COUNTER_TYPE_ESP4,
  ONP_IPSEC_COUNTER_TYPE_ESP6,
} onp_ipsec_counter_type_t;

/* Total onp ipsec counter types */
#define ONP_IPSEC_COUNTER_TYPE_MAX (ONP_IPSEC_COUNTER_TYPE_ESP6 + 1)

typedef struct
{
#define _(s) vlib_simple_counter_main_t s##_counters;
  foreach_pool_counter_names
#undef _
} onp_pool_counters_t;

typedef struct
{
#define _(s) vlib_simple_counter_main_t s##_counters;
  foreach_crypto_counter_names
#undef _
} onp_crypto_counters_t;

typedef struct
{
  onp_ipsec_counters_t ipsec[ONP_IPSEC_COUNTER_TYPE_MAX];
  onp_pool_counters_t pool[CNXK_POOL_COUNTER_TYPE_MAX];
  onp_crypto_counters_t crypto[CNXK_CRYPTO_COUNTER_TYPE_MAX];
} onp_counters_t;

/* Total number of counters in onp_counters_t */
#define ONP_MAX_COUNTERS                                                      \
  sizeof (onp_counters_t) / sizeof (vlib_simple_counter_main_t)

STATIC_ASSERT (ONP_MAX_COUNTERS <= 64,
	       "ONP_MAX_COUNTERS is larger than api counter array size");
typedef struct
{
  /* Fast path per thread data */
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  cnxk_per_thread_data_t *onp_per_thread_data;

  /* Fast path pktio structure */
  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  onp_pktio_t *onp_pktios;

  /* Sched global config */
  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  onp_sched_main_t onp_sched_main;

  u8 *cnxk_pool_by_buffer_pool_index;

  u8 *buffer_pool_by_cnxk_pool_index;

  u16 onp_pktio_count;

  u16 onp_crypto_count;

  /* Startup config */
  onp_config_main_t *onp_conf;

  /* onp scheduler profile */
  onp_pktio_scheduler_profile_t *scheduler_profile_pool;

  /* API message ID base */
  u16 onp_msg_id_base;

  u8 onp_init_done;

  /* Convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ethernet_main_t *ethernet_main;

  onp_counters_t onp_counters;

} onp_main_t;

extern onp_config_main_t onp_config_main;
extern onp_main_t onp_main;

const char *onp_address_to_str (void *p);

void onp_dispatch_wrapper_fn_set (void);
clib_error_t *cnxk_plt_model_init ();

clib_error_t *onp_pktio_config_parse (onp_config_main_t *conf,
				      vlib_pci_addr_t pci_addr,
				      unformat_input_t *input, u32 is_default);

clib_error_t *onp_pktio_configs_validate (vlib_main_t *vm,
					  onp_config_main_t *conf);

clib_error_t *onp_pktio_early_setup (vlib_main_t *vm, onp_main_t *om,
				     onp_pktio_config_t *pconf,
				     onp_pktio_t **ppktio);

clib_error_t *onp_pktio_setup (vlib_main_t *vm, onp_main_t *om,
			       onp_pktio_config_t *pconf,
			       onp_pktio_t **ppktio);

void onp_dispatch_wrapper_fn_enable_disable_on_thread (u16 thread,
						       int is_enable);

void onp_dispatch_wrapper_fn_enable_disable (u8 enable_disable);

void onp_input_node_enable_disable (u32 node_index, u32 start_thread,
				    u32 end_thread, u8 enable_disable);

clib_error_t *onp_sched_setup (onp_main_t *om, onp_sched_main_t **ppschedmain);

clib_error_t *onp_sched_config_parse (onp_config_main_t *conf,
				      unformat_input_t *sub_input,
				      vlib_pci_addr_t pci_addr);

clib_error_t *onp_ipsec_config_parse (onp_config_main_t *conf,
				      unformat_input_t *sub_input);

clib_error_t *onp_crypto_config_parse (onp_config_main_t *conf,
				       vlib_pci_addr_t pci_addr,
				       unformat_input_t *sub_input);
clib_error_t *onp_pktio_link_state_update (onp_pktio_t *od);

void onp_node_enable_disable (u32 node_index, u32 start_thread, u32 end_thread,
			      u8 enable_disable);

unsigned int onp_get_per_thread_stats (u64 **stat, u64 *pool_stat,
				       u32 n_threads, u8 verbose, u8 *is_valid,
				       u64 *threads_with_stats);

clib_error_t *onp_pktio_inl_inb_ipsec_flow_enable (vlib_main_t *vm);

clib_error_t *onp_ipsec_reassembly_set (vlib_main_t *vm, u32 sa_index);

clib_error_t *onp_uuid_parse (char *input, uuid_t uuid);

format_function_t format_onp_sched_rx_trace;

/* TM */
int onp_pktio_scheduler_profile_add_del(
        vlib_main_t *vm,
        onp_main_t *om,
        onp_pktio_scheduler_profile_t *profile,
        bool is_delete);
int onp_pktio_root_node_scheduler_shaping_update(
        vlib_main_t *vm,
        onp_main_t *om,
        u32 sw_if_index,
        u32 scheduler_profile_id,
        bool force_update);
int onp_pktio_mdq_node_scheduler_update(
        vlib_main_t *vm,
        onp_main_t *om,
        u32 sw_if_index,
        u32 qid,
        u32 scheduler_profile_id);


#endif /* included_onp_onp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
