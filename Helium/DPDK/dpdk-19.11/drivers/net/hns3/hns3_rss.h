/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#ifndef _HNS3_RSS_H_
#define _HNS3_RSS_H_
#include <rte_ethdev.h>
#include <rte_flow.h>

#define HNS3_ETH_RSS_SUPPORT ( \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_NONFRAG_IPV4_SCTP | \
	ETH_RSS_NONFRAG_IPV4_OTHER | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_NONFRAG_IPV6_SCTP | \
	ETH_RSS_NONFRAG_IPV6_OTHER)

#define HNS3_RSS_IND_TBL_SIZE	512 /* The size of hash lookup table */
#define HNS3_RSS_KEY_SIZE	40
#define HNS3_RSS_CFG_TBL_NUM \
	(HNS3_RSS_IND_TBL_SIZE / HNS3_RSS_CFG_TBL_SIZE)
#define HNS3_RSS_SET_BITMAP_MSK	0xffff

#define HNS3_RSS_HASH_ALGO_TOEPLITZ	0
#define HNS3_RSS_HASH_ALGO_SIMPLE	1
#define HNS3_RSS_HASH_ALGO_SYMMETRIC	2
#define HNS3_RSS_HASH_ALGO_MASK		0xf

#define HNS3_RSS_INPUT_TUPLE_OTHER	GENMASK(3, 0)
#define HNS3_RSS_INPUT_TUPLE_SCTP	GENMASK(4, 0)
#define HNS3_IP_FRAG_BIT_MASK		GENMASK(3, 2)
#define HNS3_IP_OTHER_BIT_MASK		GENMASK(1, 0)

struct hns3_rss_tuple_cfg {
	uint8_t ipv4_tcp_en;      /* Bit8.0~8.3 */
	uint8_t ipv4_udp_en;      /* Bit9.0~9.3 */
	uint8_t ipv4_sctp_en;     /* Bit10.0~10.4 */
	uint8_t ipv4_fragment_en; /* Bit11.0~11.3 */
	uint8_t ipv6_tcp_en;      /* Bit12.0~12.3 */
	uint8_t ipv6_udp_en;      /* Bit13.0~13.3 */
	uint8_t ipv6_sctp_en;     /* Bit14.0~14.4 */
	uint8_t ipv6_fragment_en; /* Bit15.0~15.3 */
};

#define HNS3_RSS_QUEUES_BUFFER_NUM	64 /* Same as the Max rx/tx queue num */
struct hns3_rss_conf {
	/* RSS parameters :algorithm, flow_types,  key, queue */
	struct rte_flow_action_rss conf;
	uint8_t key[HNS3_RSS_KEY_SIZE];  /* Hash key */
	struct hns3_rss_tuple_cfg rss_tuple_sets;
	uint8_t rss_indirection_tbl[HNS3_RSS_IND_TBL_SIZE]; /* Shadow table */
	uint16_t queue[HNS3_RSS_QUEUES_BUFFER_NUM]; /* Queues indices to use */
};

/* Bit 8 ~Bit 15 */
#define HNS3_INSET_IPV4_SRC        0x00000100UL
#define HNS3_INSET_IPV4_DST        0x00000200UL
#define HNS3_INSET_IPV6_SRC        0x00000400UL
#define HNS3_INSET_IPV6_DST        0x00000800UL
#define HNS3_INSET_SRC_PORT        0x00001000UL
#define HNS3_INSET_DST_PORT        0x00002000UL
#define HNS3_INSET_SCTP_VT         0x00004000UL

#ifndef ilog2
static inline int rss_ilog2(uint32_t x)
{
	int log = 0;
	x >>= 1;

	while (x) {
		log++;
		x >>= 1;
	}
	return log;
}
#define ilog2(x) rss_ilog2(x)
#endif

static inline uint32_t fls(uint32_t x)
{
	uint32_t position;
	uint32_t i;

	if (x == 0)
		return 0;

	for (i = (x >> 1), position = 0; i != 0; ++position)
		i >>= 1;

	return position + 1;
}

static inline uint32_t roundup_pow_of_two(uint32_t x)
{
	return 1UL << fls(x - 1);
}

struct hns3_adapter;

int hns3_dev_rss_hash_update(struct rte_eth_dev *dev,
			     struct rte_eth_rss_conf *rss_conf);
int hns3_dev_rss_hash_conf_get(struct rte_eth_dev *dev,
			       struct rte_eth_rss_conf *rss_conf);
int hns3_dev_rss_reta_update(struct rte_eth_dev *dev,
			     struct rte_eth_rss_reta_entry64 *reta_conf,
			     uint16_t reta_size);
int hns3_dev_rss_reta_query(struct rte_eth_dev *dev,
			    struct rte_eth_rss_reta_entry64 *reta_conf,
			    uint16_t reta_size);
void hns3_set_default_rss_args(struct hns3_hw *hw);
int hns3_set_rss_indir_table(struct hns3_hw *hw, uint8_t *indir, uint16_t size);
int hns3_rss_reset_indir_table(struct hns3_hw *hw);
int hns3_config_rss(struct hns3_adapter *hns);
void hns3_rss_uninit(struct hns3_adapter *hns);
int hns3_set_rss_tuple_by_rss_hf(struct hns3_hw *hw,
				 struct hns3_rss_tuple_cfg *tuple,
				 uint64_t rss_hf);
int hns3_set_rss_algo_key(struct hns3_hw *hw, uint8_t hash_algo,
			  const uint8_t *key);
#endif /* _HNS3_RSS_H_ */
