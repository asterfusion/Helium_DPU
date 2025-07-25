/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

#ifndef included_onp_drv_inc_pktio_h
#define included_onp_drv_inc_pktio_h

#include <onp/drv/inc/common.h>

#define VLIB_BUFFER_FROM_CNXK_PKTIO_META(x) ((vlib_buffer_t *) ((x) + 1))
#define CNXK_PKTIO_META_FROM_VLIB_BUFFER(x) (((cnxk_pktio_meta_t *) (x)) - 1)
#define CNXK_PKTIO_EXT_HDR_FROM_VLIB_BUFFER(x)                                \
  (((cnxk_pktio_external_hdr_t *) (x)) - 1)

#define CNXK_PKTIO_MAX_XSTATS_COUNT 256

/* In Sync with AF driver, denoted in Mbps */

#define CNXK_PKTIO_LINK_SPEED_10M   10
#define CNXK_PKTIO_LINK_SPEED_100M  100
#define CNXK_PKTIO_LINK_SPEED_1G    1000
#define CNXK_PKTIO_LINK_SPEED_2_5_G 2500
#define CNXK_PKTIO_LINK_SPEED_5G    5000
#define CNXK_PKTIO_LINK_SPEED_10G   10000
#define CNXK_PKTIO_LINK_SPEED_20G   20000
#define CNXK_PKTIO_LINK_SPEED_25G   25000
#define CNXK_PKTIO_LINK_SPEED_40G   40000
#define CNXK_PKTIO_LINK_SPEED_50G   50000
#define CNXK_PKTIO_LINK_SPEED_80G   80000
#define CNXK_PKTIO_LINK_SPEED_100G  100000

/* RSS key fields */

#define foreach_cnxk_pktio_rss_flow_key                                       \
  _ (PORT, 0)                                                                 \
  _ (IPV4, 1)                                                                 \
  _ (IPV6, 2)                                                                 \
  _ (TCP, 3)                                                                  \
  _ (UDP, 4)                                                                  \
  _ (SCTP, 5)                                                                 \
  _ (NVGRE, 6)                                                                \
  _ (VXLAN, 7)                                                                \
  _ (GENEVE, 8)                                                               \
  _ (ETH_DMAC, 9)                                                             \
  _ (IPV6_EXT, 10)                                                            \
  _ (GTPU, 11)                                                                \
  _ (INNR_IPV4, 12)                                                           \
  _ (INNR_IPV6, 13)                                                           \
  _ (INNR_TCP, 14)                                                            \
  _ (INNR_UDP, 15)                                                            \
  _ (INNR_SCTP, 16)                                                           \
  _ (INNR_ETH_DMAC, 17)                                                       \
  _ (CH_LEN_90B, 18)                                                          \
  _ (CUSTOM0, 19)                                                             \
  _ (VLAN, 20)                                                                \
  _ (L4_DST, 28)                                                              \
  _ (L4_SRC, 29)                                                              \
  _ (L3_DST, 30)                                                              \
  _ (L3_SRC, 31)

typedef enum
{
#define _(type, bit) CNXK_PKTIO_RSS_FLOW_KEY_##type = (1ULL << bit),
  foreach_cnxk_pktio_rss_flow_key
#undef _
} cnxk_pktio_rss_flow_key_t;

/* TX offloads */
#define foreach_cnxk_pktio_tx_off_flag                                        \
  _ (OUTER_CKSUM, 0)                                                          \
  _ (MSEG, 1)                                                                 \
  _ (INLINE_IPSEC, 2)                                                         \
  _ (SCHED_EN, 3)

typedef enum
{
#define _(name, value) CNXK_PKTIO_TX_OFF_FLAG_##name = (1ULL << value),
  foreach_cnxk_pktio_tx_off_flag
#undef _
} cnxk_pktio_tx_off_flag_t;

/* RX offloads */
#define foreach_cnxk_pktio_rx_off_flag                                        \
  _ (OUTER_CKSUM, 0)                                                          \
  _ (MSEG, 1)

#define foreach_cnxk_pktio_rq_poll_algo                                       \
  _ (0, LAZY, lazy, "Poll retries to get max-burst-size")                     \
  _ (1, GREEDY, greedy, "Poll retries to get min-burst-size")

typedef enum
{
#define _(name, value) CNXK_PKTIO_RX_OFF_FLAG_##name = (1ULL << value),
  foreach_cnxk_pktio_rx_off_flag
#undef _
} cnxk_pktio_rx_off_flag_t;

typedef enum
{
#define _(val, alg, str, desc) CNXK_PKTIO_RQ_POLL_ALGO_##alg = val,
  foreach_cnxk_pktio_rq_poll_algo
#undef _
} cnxk_pktio_rq_poll_algo_t;

enum LMAC_TYPE {
	LMAC_MODE_SGMII		= 0,
	LMAC_MODE_XAUI		= 1,
	LMAC_MODE_RXAUI		= 2,
	LMAC_MODE_10G_R		= 3,
	LMAC_MODE_40G_R		= 4,
	LMAC_MODE_QSGMII	= 6,
	LMAC_MODE_25G_R		= 7,
	LMAC_MODE_50G_R		= 8,
	LMAC_MODE_100G_R	= 9,
	LMAC_MODE_USXGMII	= 10,
	LMAC_MODE_USGMII	= 11,
	LMAC_MODE_MAX,
};

typedef i32 (*cnxk_drv_pktio_rxq_recv_func_t) (vlib_main_t *vm,
					       vlib_node_runtime_t *node,
					       u32 rxqid, u16 req_pkts,
					       cnxk_per_thread_data_t *ptd);

typedef i32 (*cnxk_drv_pktio_txq_send_func_t) (vlib_main_t *vm,
					       vlib_node_runtime_t *node,
					       u32 txqid, u16 req_pkts,
					       cnxk_per_thread_data_t *ptd);
typedef struct
{
  u64 rx_octets;
  u64 rx_drop_octets;
  u64 rx_ucast_pkts;
  u64 rx_mcast_pkts;
  u64 rx_bcast_pkts;
  u64 rx_drop_pkts;
  u64 rx_drop_bcast_pkts;
  u64 rx_drop_mcast_pkts;
  u64 rx_fcs_pkts;
  u64 rx_err;
  u64 tx_octets;
  u64 tx_ucast_pkts;
  u64 tx_mcast_pkts;
  u64 tx_bcast_pkts;
  u64 tx_drop_pkts;
} cnxk_pktio_stats_t;

typedef struct
{
  union
  {
    struct
    {
      u64 rx_pkts;
      u64 rx_octs;
      u64 rx_drop_pkts;
      u64 rx_drop_octs;
      u64 rx_error_pkts;
    };

    struct
    {
      u64 tx_pkts;
      u64 tx_octs;
      u64 tx_drop_pkts;
      u64 tx_drop_octs;
    };
  };
} cnxk_pktio_queue_stats_t;

typedef struct
{
  u32 min_frame_size;
  u32 max_frame_size;
  u32 frame_overhead;
} cnxk_pktio_mtu_capa_t;

typedef struct
{
  u8 vector_enable;
  u8 is_pktio_inl_outbound;
  u8 is_pktio_inl_inbound;
  cnxk_pktio_mtu_capa_t mtu;
} cnxk_pktio_capa_t;

typedef struct
{
  u32 n_rx_queues;
  u32 n_tx_queues;
  u32 n_tx_ipsec_queues;
} cnxk_pktio_config_t;

typedef struct
{
  /* RQ offloads */
  u64 rxq_offloads;

  /* pktio software index */
  u32 pktio_sw_if_index;

  /* Number of rx descriptors in RSS RQ */
  u32 rx_desc;

  /* Poll algo for RSS RQs */
  cnxk_pktio_rq_poll_algo_t rxq_poll_algo;

  /* Number of poll retries for RSS RQ poll algo */
  u8 rxq_max_poll_retries;

  /* Min burst size required for RSS RQ as per poll algo selected */
  u16 rxq_min_vec_size;

  /*
   * Requested max burst size required for RSS RQ (as per poll algo selected)
   */
  u16 rxq_max_vec_size;

  /* cnxk pool index for RSS RQ */
  u8 cnxk_pool_index;

  /* VLIB buffer pool index for RSS RQ */
  u8 vlib_buffer_pool_index;
} cnxk_pktio_rxq_conf_t;

typedef struct
{
  u64 txq_offloads;
  u32 tx_desc;
} cnxk_pktio_txq_conf_t;

typedef struct
{
  cnxk_drv_pktio_rxq_recv_func_t pktio_recv_func_ptr;
  u64 offload_flags;
  u64 fp_flags;
} cnxk_pktio_rxq_fn_conf_t;

typedef struct
{
  cnxk_drv_pktio_txq_send_func_t pktio_send_func_ptr;
  u64 offload_flags;
  u64 fp_flags;
} cnxk_pktio_txq_fn_conf_t;

typedef struct
{
  u32 flow_index;
  u64 hits;
} cnxk_flow_stats_t;

typedef struct
{
  u32 is_up : 1;
  u32 is_full_duplex : 1;
  u32 is_autoneg : 1;
  u32 speed : 20;
  u64 lmac_type_id;
} cnxk_pktio_link_info_t;

i32 cnxk_drv_pktio_pkts_recv (vlib_main_t *vm, vlib_node_runtime_t *node,
			      u32 rxq, u16 req_pkts,
			      cnxk_per_thread_data_t *rxptd, const u64 mode,
			      const u64 flags);

i32 cnxk_drv_pktio_pkts_send (vlib_main_t *vm, vlib_node_runtime_t *node,
			      u32 txq, u16 tx_pkts,
			      cnxk_per_thread_data_t *txptd, const u64 mode,
			      const u64 flags);

i32 cnxk_drv_pktio_rxq_fp_set (vlib_main_t *vm, u16 pktio_idx, u32 rxq,
			       cnxk_pktio_rxq_fn_conf_t *rxq_fn_conf);

i32 cnxk_drv_pktio_txq_fp_set (vlib_main_t *vm, u16 pktio_idx, u32 txq,
			       cnxk_pktio_txq_fn_conf_t *txq_fn_conf);

i32 cnxk_drv_pktio_init (vlib_main_t *vm, vlib_pci_addr_t *addr,
			 uuid_t uuid_token, vlib_pci_dev_handle_t *);

i32 cnxk_drv_pktio_exit (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_start (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_stop (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_flowkey_set (vlib_main_t *vm, u16 index,
				cnxk_pktio_rss_flow_key_t flowkey);

i32 cnxk_drv_pktio_capa_get (vlib_main_t *vm, u16 pktio_idx,
			     cnxk_pktio_capa_t *capa);

i32 cnxk_drv_pktio_promisc_enable (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_promisc_disable (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_multicast_enable (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_multicast_disable (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_mac_addr_set (vlib_main_t *vm, u16 pktio_idx, char *addr);

i32 cnxk_drv_pktio_mac_addr_get (vlib_main_t *vm, u16 pktio_idx, char *addr);

i32 cnxk_drv_pktio_mac_addr_add (vlib_main_t *vm, u16 pktio_idx, char *addr);

#ifdef VPP_PLATFORM_ET2500
i32 cnxk_drv_pktio_mac_addr_del (vlib_main_t *vm, u16 pktio_idx, char *addr);
#else
i32 cnxk_drv_pktio_mac_addr_del (vlib_main_t *vm, u16 pktio_idx);
#endif

i32 cnxk_drv_pktio_is_inl_dev_enabled (vlib_main_t *vm);

i32 cnxk_drv_pktio_mtu_set (vlib_main_t *vm, u16 pktio_idx, u32 mtu);

i32 cnxk_drv_pktio_mtu_get (vlib_main_t *vm, u16 pktio_idx, u32 *mtu);

i32 cnxk_drv_pktio_config (vlib_main_t *vm, u16 pktio_idx,
			   cnxk_pktio_config_t *config);

i32 cnxk_drv_pktio_rxq_setup (vlib_main_t *vm, u16 pktio_idx,
			      cnxk_pktio_rxq_conf_t *conf);

i32 cnxk_drv_pktio_txq_setup (vlib_main_t *vm, u16 pktio_idx,
			      cnxk_pktio_txq_conf_t *conf);

i32 cnxk_drv_pktio_stats_get (vlib_main_t *vm, u16 pktio_idx,
			      cnxk_pktio_stats_t *stats);

i32 cnxk_drv_pktio_stats_clear (vlib_main_t *vm, u16 pktio_idx);

i32 cnxk_drv_pktio_queue_stats_get (vlib_main_t *vm, u16 pktio_idx, u16 qid,
				    cnxk_pktio_queue_stats_t *qstats,
				    bool is_rxq);

i32 cnxk_drv_pktio_queue_stats_clear (vlib_main_t *vm, u16 pktio_idx, u16 qid,
				      bool is_rxq);

i32 cnxk_drv_pktio_xstats_count_get (vlib_main_t *vm, u16 pktio_idx,
				     u32 *n_xstats);

i32 cnxk_drv_pktio_xstats_get (vlib_main_t *vm, u16 pktio_idx, u64 *xstats,
			       u32 count);

i32 cnxk_drv_pktio_xstats_names_get (vlib_main_t *vm, u16 pktio_idx,
				     u8 *xstats_names[], u32 count);

i32 cnxk_drv_pktio_link_advertise_set (vlib_main_t *vm, u16 pktio_idx,
				  cnxk_pktio_link_info_t *link_info);

i32 cnxk_drv_pktio_link_info_set (vlib_main_t *vm, u16 pktio_idx,
				  cnxk_pktio_link_info_t *link_info);

i32 cnxk_drv_pktio_link_info_get (vlib_main_t *vm, u16 pktio_idx,
				  cnxk_pktio_link_info_t *link_info);

u8 *cnxk_drv_pktio_format_rx_trace (u8 *s, va_list *);

i32 cnxk_drv_pktio_flow_update (vnet_main_t *vnm, vnet_flow_dev_op_t op,
				u32 dev_instance, vnet_flow_t *flow,
				uword *private_data);

i32 cnxk_drv_pktio_flow_inl_dev_update (vnet_main_t *vnm,
					vnet_flow_dev_op_t op,
					u32 dev_instance, vnet_flow_t *flow,
					uword *private_data);

u32 cnxk_drv_pktio_flow_query (vlib_main_t *, u32, uword, cnxk_flow_stats_t *);

u32 cnxk_drv_pktio_flow_dump (vlib_main_t *, u32);

u8 cnxk_drv_pktio_is_inl_dev (vlib_main_t *, u16 pktio_idx);

u32 cnxk_drv_pktio_get_lmac_speed(enum LMAC_TYPE lmac_type);

#endif /* included_onp_drv_inc_pktio_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
