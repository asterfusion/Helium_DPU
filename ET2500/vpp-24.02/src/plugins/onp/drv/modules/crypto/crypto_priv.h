/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_modules_crypto_crypto_priv_h
#define included_onp_drv_modules_crypto_crypto_priv_h

#include <onp/drv/inc/crypto.h>
#include <onp/drv/inc/log.h>
#include <onp/drv/roc/platform.h>
#include <onp/drv/roc/base/roc_api.h>

#define CNXK_CRYPTO_MAIN()		  (&cnxk_crypto_main)
#define CNXK_CRYPTO_MAX_DEVICES		  2
#define CNXK_CRYPTO_MAX_QUEUES_PER_DEVICE 1

#define CNXK_CRYPTO_OP_TYPE_ENCRYPT 0
#define CNXK_CRYPTO_OP_TYPE_DECRYPT 1

#define CPT_LMT_SIZE_COPY (sizeof (struct cpt_inst_s) / 16)

#define CNXK_MOD_INC(i, l) ((i) == (l - 1) ? (i) = 0 : (i)++)

#define CNXK_SCATTER_GATHER_BUFFER_SIZE		 1024
#define CNXK_CRYPTO_DEFAULT_SW_ASYNC_FRAME_COUNT 256

typedef enum
{
  CNXK_CRYPTO_UNITITIALIZED,
  CNXK_CRYPTO_PROBED,
  CNXK_CRYPTO_CONFIGURED,
} cnxk_cryptodev_status_t;

typedef struct cnxk_crypto_scatter_gather
{
  u8 buf[CNXK_SCATTER_GATHER_BUFFER_SIZE];
} cnxk_crypto_scatter_gather_t;

typedef struct cnxk_inflight_req
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  volatile union cpt_res_s res[VNET_CRYPTO_FRAME_SIZE];
  void *sg_data;
  vnet_crypto_async_frame_t *frame;
  u16 elts;
  u16 deq_elts;
} cnxk_inflight_req_t;

struct cnxk_crypto_pending_queue
{
  /** Array of pending request */
  cnxk_inflight_req_t *req_queue;
  /** Counter for number of inflight operations in queue */
  vlib_simple_counter_main_t *crypto_inflight[CNXK_CRYPTO_COUNTER_TYPE_MAX];
  /** Counter for pending packets in queue */
  vlib_simple_counter_main_t *pending_packets[CNXK_CRYPTO_COUNTER_TYPE_MAX];
  /** Counter for successfully dequeued packets */
  vlib_simple_counter_main_t *success_packets[CNXK_CRYPTO_COUNTER_TYPE_MAX];
  /** Number of inflight operations in queue */
  u32 n_crypto_inflight;
  /** Tail of queue to be used for enqueue */
  u16 enq_tail;
  /** Head of queue to be used for dequeue */
  u16 deq_head;
  /** Number of descriptors */
  u16 n_desc;
} __cnxk_cache_aligned;

typedef struct cnxk_crypto_session_param
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /** CPT opcode */
  u16 cpt_op : 4;
  /** Flag for AES GCM */
  u16 aes_gcm : 1;
  /** Flag for NULL cipher/auth */
  u16 is_null : 1;
  /** IV length in bytes */
  u8 iv_length;
  /** Auth IV length in bytes */
  u8 auth_iv_length;
  /** IV offset in bytes */
  u16 iv_offset;
  /** Auth IV offset in bytes */
  u16 auth_iv_offset;
  /** CPT inst word 7 */
  u64 cpt_inst_w7;
} cnxk_crypto_session_param_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  struct roc_cpt_lmtline lmtline;

  struct roc_cpt_lf lf;

  u16 cnxk_crypto_index;
  u16 cnxk_queue_index;
  u32 n_crypto_desc;
  u32 cnxk_cpt_enq_pool_index;

  clib_time_t last_crypto_inst_time;
} cnxk_crypto_queue_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /* CPT ROC reference */
  struct roc_cpt *cnxk_roc_cpt;

  /* IPsec context */
  void *cnxk_ipsec_context;

  /* Array of cnxk_crypto_queue_pair_t */
  cnxk_crypto_queue_t *crypto_queues;

  /* crypto device index */
  u16 cnxk_crypto_index;

  u8 cnxk_crypto_device_mode;

  u8 crypto_device_status;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  clib_bitmap_t *bitmask_attached_queues;

  u64 cnxk_physmem_allocated;

  /* Crypto capability */
  cnxk_crypto_capability_t crypto_capa;
} cnxk_crypto_dev_t;

typedef struct cnxk_crypto_session
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cnxk_crypto_session_param_t param;

  cnxk_crypto_dev_t *crypto_dev;

  struct roc_se_ctx cpt_ctx;
} cnxk_crypto_session_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  cnxk_crypto_session_t *sess;
} cnxk_crypto_key_t;

typedef struct cnxk_crypto_ops
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);
  i32 (*cnxk_crypto_configure) (vlib_main_t *vm, u16 cnxk_crypto_index,
				cnxk_crypto_config_t *config);
  i32 (*cnxk_crypto_clear) (vlib_main_t *vm, u16 cnxk_crypto_index);
  i32 (*cnxk_crypto_qpair_init) (vlib_main_t *vm, u16 cnxk_crypto_index,
				 cnxk_crypto_queue_config_t *config);
  i32 (*cnxk_crypto_capability_populate) (vlib_main_t *vm,
					  u16 cnxk_crypto_index,
					  cnxk_crypto_capability_t *capa);
  i32 (*cnxk_crypto_enqueue_aead_aad_enc) (vlib_main_t *vm,
					   vnet_crypto_async_frame_t *frame,
					   u8 aad_len);
  i32 (*cnxk_crypto_enqueue_aead_aad_dec) (vlib_main_t *vm,
					   vnet_crypto_async_frame_t *frame,
					   u8 aad_len);
} cnxk_crypto_ops_t;

typedef struct
{
  cnxk_crypto_dev_t *cnxk_cryptodevs;

  cnxk_crypto_ops_t *cnxk_crypto_ops;

  struct cnxk_crypto_pending_queue *pend_q;

  cnxk_crypto_key_t *keys[VNET_CRYPTO_ASYNC_OP_N_TYPES];

  u16 n_crypto_dev;
} cnxk_crypto_main_t;

extern cnxk_crypto_ops_t crypto_10k_ops;
extern cnxk_crypto_main_t cnxk_crypto_main;

void cn10k_ipsec_capability_read (union cpt_eng_caps hw_caps,
				  cnxk_crypto_grp_capability_t *capability);

static_always_inline cnxk_crypto_dev_t *
cnxk_crypto_dev_get (u16 cnxk_crypto_index)
{
  cnxk_crypto_main_t *crypto_main = CNXK_CRYPTO_MAIN ();

  ASSERT (cnxk_crypto_index < crypto_main->n_crypto_dev);
  return vec_elt_at_index (crypto_main->cnxk_cryptodevs, cnxk_crypto_index);
}

static_always_inline cnxk_crypto_ops_t *
cnxk_crypto_ops_get (u16 cnxk_crypto_index)
{
  cnxk_crypto_main_t *crypto_main = CNXK_CRYPTO_MAIN ();

  return vec_elt_at_index (crypto_main->cnxk_crypto_ops, cnxk_crypto_index);
}

i32 cnxk_crypto_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
		      vlib_pci_dev_handle_t *phandle);

i32 cnxk_crypto_clear (vlib_main_t *vm, u16 cnxk_crypto_index);

i32 cnxk_crypto_queue_init (vlib_main_t *vm, u16 cnxk_crypto_index,
			    cnxk_crypto_queue_config_t *config);

i32 cnxk_crypto_configure (vlib_main_t *vm, u16 cnxk_crypto_index,
			   cnxk_crypto_config_t *config);

i32 cnxk_crypto_capability_populate (vlib_main_t *vm, u16 cnxk_crypto_index,
				     cnxk_crypto_capability_t *capability);

void
cn10k_crypto_group_capability_read (union cpt_eng_caps hw_caps_list[],
				    cnxk_crypto_grp_capability_t *capability,
				    cnxk_crypto_group_t group);

void
cnxk_crypto_iegroup_capability_read (union cpt_eng_caps hw_caps,
				     cnxk_crypto_grp_capability_t *capability);

#endif /* included_onp_drv_modules_crypto_crypto_priv_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
