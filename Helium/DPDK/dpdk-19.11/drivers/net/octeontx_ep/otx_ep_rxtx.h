/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _OTX_EP_RXTX_H_
#define _OTX_EP_RXTX_H_

#include <rte_byteorder.h>

#define OTX_EP_IQ_SEND_FAILED      (-1)
#define OTX_EP_IQ_SEND_SUCCESS     (0)

#define OTX_EP_OQ_RECV_FAILED      (-1)
#define OTX_EP_OQ_RECV_SUCCESS     (0)

#define OTX_EP_MAX_DELAYED_PKT_RETRIES 10000

static inline void
otx_ep_swap_8B_data(uint64_t *data, uint32_t blocks)
{
	/* Swap 8B blocks */
	while (blocks) {
		*data = rte_bswap64(*data);
		blocks--;
		data++;
	}
}

static inline uint32_t
otx_ep_incr_index(uint32_t index, uint32_t count, uint32_t max)
{
	if ((index + count) >= max)
		index = index + count - max;
	else
		index += count;

	return index;
}
uint16_t
otx_ep_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts);
uint16_t
otx2_ep_xmit_pkts(void *tx_queue, struct rte_mbuf **pkts, uint16_t nb_pkts);
uint16_t
otx_ep_recv_pkts(void *rx_queue,
		  struct rte_mbuf **rx_pkts,
		  uint16_t budget);

#endif /* _OTX_EP_RXTX_H_ */
