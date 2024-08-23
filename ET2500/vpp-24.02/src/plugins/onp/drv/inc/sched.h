/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_sched_h
#define included_onp_drv_inc_sched_h

#include <onp/drv/inc/common.h>

#define foreach_onp_sched_error                                               \
  _ (NONE, "No error")                                                        \
  _ (UNDEFINED_ENC, "Undefined encrypt error")

typedef enum
{
#define _(f, s) ONP_SCHED_ERROR_##f,
  foreach_onp_sched_error
#undef _
    ONP_SCHED_N_ERROR,
} onp_sched_error_t;

#define foreach_cnxk_sched_work_source                                        \
  _ (CRYPTO_ENC_INLINE, 1)                                                    \
  _ (VWORK_CRYPTO_DEC, 2)                                                     \
  _ (VWORK_CRYPTO_ENC, 3)

typedef enum
{
#define _(mode, value) CNXK_SCHED_WORK_SOURCE_##mode = (value),
  foreach_cnxk_sched_work_source
#undef _
} cnxk_sched_work_source_t;

#define foreach_cnxk_sched_tt                                                 \
  _ (ORDERED, 0)                                                              \
  _ (ATOMIC, 1)                                                               \
  _ (UNTAGGED, 2)                                                             \
  _ (EMPTY, 3)

typedef enum
{
#define _(mode, value) CNXK_SCHED_TAG_##mode = (value),
  foreach_cnxk_sched_tt
#undef _
} cnxk_sched_tt_t;

/* Main thread group */
#define CNXK_SCHED_GRP_ON_MAIN_THREAD 0 /* Should be 0 */

#define CNXK_SCHED_GRP_APP_BASE_VAL 36

/* Lowest group has highest priority */
#define foreach_cnxk_sched_grp_app_type                                       \
  _ (POST_CRYPTO_ENQ, 0)                                                      \
  _ (CRYPTO_ENQ, 1)                                                           \
  _ (PKTIO, 1)                                                                \
  _ (DEF_PRIO, 2)

#define CNXK_SCHED_GRP_APP_TYPE_UPPER_BOUND (CNXK_SCHED_GRP_APP_DEF_PRIO + 1)

/* IPsec outbound and inbound should have equal priority */
#define CNXK_SCHED_GRP_APP_CORE_HANDOFF CNXK_SCHED_GRP_APP_PKTIO

typedef enum
{
#define _(mode, value)                                                        \
  CNXK_SCHED_GRP_APP_##mode = (CNXK_SCHED_GRP_APP_BASE_VAL + value),
  foreach_cnxk_sched_grp_app_type
#undef _
} cnxk_sched_grp_app_type_t;

#define CNXK_SCHED_GRP_APP_TYPE_MAX                                           \
  (CNXK_SCHED_GRP_APP_TYPE_UPPER_BOUND - CNXK_SCHED_GRP_APP_BASE_VAL)

typedef struct
{
  u16 n_queues;
} cnxk_sched_config_t;

typedef struct
{
  u64 ws_pc;
  u64 ext_pc;
  u64 wa_pc;
  u64 ts_pc;
  u64 ds_pc;
  u64 dq_pc;
  u64 aw_status;
  u64 page_cnt;
} cnxk_sched_grp_stats_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (c0);
  u32 sched_header_flag;
  u16 pool_index;
  u16 frame_size;
  u16 next_node;
  u16 drop_next_node;
  u8 res_offset;
  u8 source_thread_index;
  u8 buffer_pool_index;
  void *user_ptr;

  CLIB_CACHE_LINE_ALIGN_MARK (c1);
  u32 buffer_indices[CNXK_FRAME_SIZE];

  CLIB_CACHE_LINE_ALIGN_MARK (c2);
  u32 param1[CNXK_FRAME_SIZE];

  CLIB_CACHE_LINE_ALIGN_MARK (c3);
  u32 param2[CNXK_FRAME_SIZE];

  CLIB_CACHE_LINE_ALIGN_MARK (c4);
  u32 param3[CNXK_FRAME_SIZE];

  CLIB_CACHE_LINE_ALIGN_MARK (c5);
  u64 param4[CNXK_FRAME_SIZE];
} cnxk_sched_vec_header_t;

typedef struct
{
  union
  {
    u32 as_u32;
    struct
    {
      u32 source : 8; /* ETHDEV | CPU | CRYPTO */
      u32 port : 8;   /* pktio */
      u32 flow_or_rq : 16;
    };
  };
} cnxk_sched_work_tag_t;

typedef struct
{
  union
  {
    u64 word0;
    struct
    {
      union
      {
	u32 tag;
	struct
	{
	  u32 source : 8; /* ETHDEV | CPU | CRYPTO */
	  u32 port : 8;	  /* PKTIO */
	  u32 flow_or_rq : 16;
	};
      };
      struct
      {
	union
	{
	  u32 work_info;
	  /* NIX_WQE_HDR_S. Valid only if source: PKTIO */
	  struct
	  {
	    u32 whdr_tt : 2;
	    u32 whdr_sched_group : 10;
	    u32 whdr_numa_node : 2;
	    u32 whdr_hw_rq : 14;
	    u32 whdr_work_type : 4;
	  };
	  /* Required for sched_enq */
	  struct
	  {
	    u32 enq_tt : 2;
	    u32 enq_sched_group : 10;
	    /* NEW | FORWARD */
	    u32 enq_op : 2;
	    u32 reserved : 18;
	  };
	  /* GWS_TAG */
	  struct
	  {
	    u32 reg_tt : 2;
	    u32 reg_rsvd34 : 1;
	    u32 reg_head : 1;
	    u32 reg_sched_group : 10;
	    u32 reg_rsvd : 16;
	    u32 reg_pend_switch : 1;
	    u32 reg_pend_get_work : 1;
	  };
	};
      };
    };
  };
  union
  {
    u64 work;
    /* For VWORK SIM: work is not a pointer but encoded as follows */
    struct
    {
      u64 vwork_sim1_resv1 : 16;
      u64 vwork_sim1_cqe_head : 16;
      u64 vwork_sim1_npkts : 16;
      u64 vwork_sim1_resv2 : 16;
    };
  };
} cnxk_sched_work_t;

typedef enum
{
  CNXK_SCHED_LOCK_HEAD_WAIT,
} cnxk_sched_lock_type_t;

typedef enum
{
  CNXK_SCHED_HANDOFF_HEADER_FLAG_SA_VALID = (1 << 0),
  CNXK_SCHED_HANDOFF_HEADER_FLAG_ESP_META_VALID = (1 << 1),
} cnxk_sched_handoff_header_flag_t;

static_always_inline u16
cnxk_sched_grp_app_map_to_actual (u32 thread_index, u16 relative_sched_grp)
{

  if (PREDICT_FALSE (relative_sched_grp >=
		     CNXK_SCHED_GRP_APP_TYPE_UPPER_BOUND))
    {
      cnxk_sched_err ("Unsupported sched grp: %d. Changing to %d\n",
		      relative_sched_grp, CNXK_SCHED_GRP_APP_TYPE_MAX - 1);

      /* Convert to low priority value */
      relative_sched_grp =
	vlib_thread_main.n_vlib_mains + CNXK_SCHED_GRP_APP_TYPE_MAX - 1;
    }

  if (relative_sched_grp >= CNXK_SCHED_GRP_APP_BASE_VAL)
    return ((u16) (vlib_thread_main.n_vlib_mains + relative_sched_grp -
		   CNXK_SCHED_GRP_APP_BASE_VAL));

  return relative_sched_grp;
}

i32 cnxk_drv_sched_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
			 uuid_t uuid_token);

i32 cnxk_drv_sched_config (vlib_main_t *vm, cnxk_sched_config_t sched_config);

i32 cnxk_drv_sched_grp_link (vlib_main_t *vm, u16 *grp, u8 thread_id,
			     u16 n_grps);

i32 cnxk_drv_sched_grp_unlink (vlib_main_t *vm, u16 *grp, u8 thread_id,
			       u16 n_grps);

i32 cnxk_drv_sched_grp_prio_set (vlib_main_t *vm, u16 grp, u16 prio);

i32 cnxk_drv_sched_thread_grp_link_status_get (vlib_main_t *vm,
					       uword *grp_bitmap,
					       u8 thread_id);

i32 cnxk_drv_sched_grp_stats_dump (vlib_main_t *vm, u16 grp,
				   cnxk_sched_grp_stats_t *stats);

u8 *cnxk_drv_sched_tag_format (u8 *s, va_list *va);
void cnxk_drv_sched_info_dump (vlib_main_t *vm);

#endif /* included_onp_drv_inc_sched_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
