/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_ethdev.h"
#include "cn10k_tx.h"

static __rte_used inline void
pick_tx_func(struct rte_eth_dev *eth_dev,
	     const eth_tx_burst_t tx_burst[NIX_TX_OFFLOAD_MAX])
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);

	/* [SEC] [TSP] [TSO] [NOFF] [VLAN] [OL3_OL4_CSUM] [IL3_IL4_CSUM] */
	eth_dev->tx_pkt_burst =
		tx_burst[dev->tx_offload_flags & (NIX_TX_OFFLOAD_MAX - 1)];

	if (eth_dev->data->dev_started)
		rte_eth_fp_ops[eth_dev->data->port_id].tx_pkt_burst =
			eth_dev->tx_pkt_burst;
}

#if defined(RTE_ARCH_ARM64)
static int
cn10k_nix_tx_queue_count(void *tx_queue)
{
	struct cn10k_eth_txq *txq = (struct cn10k_eth_txq *)tx_queue;

	return cnxk_nix_tx_queue_count(txq->fc_mem, txq->sqes_per_sqb_log2);
}

static int
cn10k_nix_tx_queue_sec_count(void *tx_queue)
{
	struct cn10k_eth_txq *txq = (struct cn10k_eth_txq *)tx_queue;

	return cnxk_nix_tx_queue_sec_count(txq->fc_mem, txq->sqes_per_sqb_log2, txq->cpt_fc);
}
#endif

void
cn10k_eth_set_tx_function(struct rte_eth_dev *eth_dev)
{
#if defined(RTE_ARCH_ARM64)
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);

	const eth_tx_burst_t nix_eth_tx_burst[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn10k_nix_xmit_pkts_##name,

		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_burst_mseg[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn10k_nix_xmit_pkts_mseg_##name,

		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_vec_burst[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn10k_nix_xmit_pkts_vec_##name,

		NIX_TX_FASTPATH_MODES
#undef T
	};

	const eth_tx_burst_t nix_eth_tx_vec_burst_mseg[NIX_TX_OFFLOAD_MAX] = {
#define T(name, sz, flags)[flags] = cn10k_nix_xmit_pkts_vec_mseg_##name,

		NIX_TX_FASTPATH_MODES
#undef T
	};

	if (dev->scalar_ena || dev->tx_mark) {
		pick_tx_func(eth_dev, nix_eth_tx_burst);
		if (dev->tx_offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
			pick_tx_func(eth_dev, nix_eth_tx_burst_mseg);
	} else {
		pick_tx_func(eth_dev, nix_eth_tx_vec_burst);
		if (dev->tx_offloads & RTE_ETH_TX_OFFLOAD_MULTI_SEGS)
			pick_tx_func(eth_dev, nix_eth_tx_vec_burst_mseg);
	}
	if (dev->tx_offloads & RTE_ETH_TX_OFFLOAD_SECURITY)
		eth_dev->tx_queue_count = cn10k_nix_tx_queue_sec_count;
	else
		eth_dev->tx_queue_count = cn10k_nix_tx_queue_count;

	rte_mb();
#else
	RTE_SET_USED(eth_dev);
#endif
}
