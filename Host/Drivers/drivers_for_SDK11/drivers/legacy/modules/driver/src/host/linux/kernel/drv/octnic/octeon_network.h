/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file  octeon_network.h
     \brief Host NIC Driver: Structure and Macro definitions used by NIC Module.
*/

#ifndef __OCTEON_NETWORK_H__
#define __OCTEON_NETWORK_H__

#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ethtool.h>
#include "octeon_main.h"
#include "octeon_nic.h"
#include "octeon_compat.h"

typedef struct net_device octnet_os_devptr_t;

/* Bit mask values for priv->ifstate */
#define   OCT_NIC_IFSTATE_DROQ_OPS         1
#define   OCT_NIC_IFSTATE_REGISTERED       2
#define   OCT_NIC_IFSTATE_RUNNING          4
#define   OCT_NIC_IFSTATE_TXENABLED        8

/* #define OCTEON_NET_PROFILE */

/* runtime link query interval */
#define OCTNET_LINK_QUERY_INTERVAL         CAVIUM_TICKS_PER_SEC

/* TSO related info */
#define OCTNIC_GSO_MAX_HEADER_SIZE   128
/* Limited to 32K, due to bi-directional iperf load test stability issues */
#define CN83XX_DEFAULT_INPUT_JABBER  32000
//#define CN83XX_DEFAULT_INPUT_JABBER  64000
#define OCTNIC_GSO_MAX_SIZE  (CN83XX_DEFAULT_INPUT_JABBER - OCTNIC_GSO_MAX_HEADER_SIZE)

/* Octeon's interface mode of operation */
typedef enum {
	INTERFACE_MODE_DISABLED,
	INTERFACE_MODE_RGMII,
	INTERFACE_MODE_GMII,
	INTERFACE_MODE_SPI,
	INTERFACE_MODE_PCIE,
	INTERFACE_MODE_XAUI,
	INTERFACE_MODE_SGMII,
	INTERFACE_MODE_PICMG,
	INTERFACE_MODE_NPI,
	INTERFACE_MODE_LOOP,
	INTERFACE_MODE_SRIO,
	INTERFACE_MODE_ILK,
	INTERFACE_MODE_RXAUI,
	INTERFACE_MODE_QSGMII,
	INTERFACE_MODE_AGL,
} oct_interface_mode_t;

typedef struct {

	struct {
		int octeon_id;

		cavium_wait_channel wc;

		int cond;
	} s;

	uint64_t resp_hdr;

	uint64_t link_count;

	oct_link_info_t link_info[MAX_OCTEON_LINKS];

	uint64_t status;

} oct_link_status_resp_t;

#define OCT_LINK_STATUS_RESP_SIZE   (sizeof(oct_link_status_resp_t))

/** Octeon device properties to be used by the NIC module.
    Each octeon device in the system will be represented
    by this structure in the NIC module. */
struct octdev_props_t {

	/** Number of interfaces detected in this octeon device. */
	int ifcount;

	/* Link status sent by core app is stored in a buffer at this
	   address. */
	oct_link_status_resp_t *ls;

	/** Pointer to pre-allocated soft instr used to send link status
	    request to Octeon app. */
	octeon_soft_instruction_t *si_link_status;

	/** Flag to indicate if a link status instruction is currently
	    being processed. */
	cavium_atomic_t ls_flag;

	/** The last tick at which the link status was checked. The
	    status is checked every second. */
	unsigned long last_check;

	/** Each interface in the Octeon device has a network
	   device pointer (used for OS specific calls). */
	octnet_os_devptr_t *pndev[MAX_OCTEON_LINKS];
};

/** Octeon per-interface Network Private Data */
typedef struct {
	/** Pointer to the octeon device structure. */
	void *oct_dev;

	char init_name[64];

	/** Link information sent by the core application for this interface. */
	oct_link_info_t linfo;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	struct napi_struct napi;
#endif

#ifdef OCT_NIC_LOOPBACK
	int (*priv_xmit)(struct sk_buff *skb, struct net_device *dev);
#endif

	octnet_os_devptr_t *pndev;

	cavium_spinlock_t lock;

	/** State of the interface. Rx/Tx happens only in the RUNNING state.  */
	atomic_t ifstate;

	/** Octeon Interface index number. This device will be represented as
	    oct<ifidx> in the system. */
	int ifidx;

	/** Octeon Input queue to use to transmit for this network interface. */
	int txq;

	/** Octeon Output queue from which pkts arrive for this network interface.*/
	int rxq;

	/** Pointer to the NIC properties for the Octeon device this network
	    interface is associated with. */
	struct octdev_props_t *octprops;


	/** Statistics for this interface. */
	struct net_device_stats stats;

	/** Size of Tx queue for this octeon device. */
	uint32_t tx_qsize;

	/** Size of Rx queue for this octeon device. */
	uint32_t rx_qsize;

	/** Copy of netdevice flags. */
	uint32_t pndev_flags;

	/* Copy of the flags managed by core app & NIC module. */
	octnet_ifflags_t core_flags;

} ____cacheline_aligned_in_smp octnet_priv_t;
#define OCTNET_PRIV_SIZE   (sizeof(octnet_priv_t))

/** This structure is used by NIC driver to store information required
	to free the sk_buff when the packet has been fetched by Octeon.
	Bytes offset below assume worst-case of a 64-bit system. */
struct octnet_buf_free_info {

	/** Bytes 1-8.  Pointer to network device private structure. */
	octnet_priv_t *priv;

	/** Bytes 9-16.  Pointer to sk_buff. */
	struct sk_buff *skb;

	/** Bytes 17-24.  Pointer to gather list. */
	struct octeon_gather *g;

	/** Bytes 25-32. Physical address of skb->data or gather list. */
	uint64_t dptr;

};

/* TSO related info - used for sending to firmware */
typedef union tso_info {
	u64 u64;

	struct {
#ifdef __CAVIUM_BIG_ENDIAN_BITFIELD
		u16 gso_size;
		u16 gso_segs;
		u32 reserved;
#else
		u32 reserved;
		u16 gso_segs;
		u16 gso_size;
#endif
	} s;

} tso_info_t;

static inline int OCTNET_IFSTATE_CHECK(octnet_priv_t * priv, int state_flag)
{
	return (cavium_atomic_read(&priv->ifstate) & state_flag);
}

static inline void OCTNET_IFSTATE_SET(octnet_priv_t * priv, int state_flag)
{
	cavium_atomic_set(&priv->ifstate,
			  (cavium_atomic_read(&priv->ifstate) | state_flag));
}

static inline void OCTNET_IFSTATE_RESET(octnet_priv_t * priv, int state_flag)
{
	cavium_atomic_set(&priv->ifstate,
			  (cavium_atomic_read(&priv->ifstate) & ~(state_flag)));
}

void octnic_free_netbuf(void *buf);

void octnic_free_netsgbuf(void *buf);

void octnet_free_tx_buf(octeon_req_status_t status, void *arg);

int octnet_open(octnet_os_devptr_t * pndev);

int octnet_stop(octnet_os_devptr_t * pndev);

void octnet_set_mcast_list(octnet_os_devptr_t * pndev);

int octnet_set_mac(octnet_os_devptr_t * pndev, void *addr);

int octnet_change_mtu(octnet_os_devptr_t * pndev, int new_mtu);

int octnet_get_vf_config(struct net_device *dev,
			 int vf, struct ifla_vf_info *ivi);

int octnet_set_vf_mac(struct net_device *dev, int vf, u8 *mac);

int octnet_set_vf_vlan(struct net_device *dev, int vf, u16 vlan, u8 qos,
		       __be16 vlan_proto);

int octnet_set_vf_spoofchk(struct net_device *dev, int vf, bool setting);

int octnet_set_vf_trust(struct net_device *dev, int vf, bool setting);

int octnet_set_vf_rate(struct net_device *dev, int vf, int min_tx_rate,
		      int max_tx_rate);

int octnet_set_vf_link_state(struct net_device *dev, int vf,
			     int link_state);

int octnet_get_vf_stats(struct net_device *dev, int vf,
			struct ifla_vf_stats *vf_stats);

int octnet_xmit(struct sk_buff *skb, octnet_os_devptr_t * pndev);

#ifdef OCT_NIC_LOOPBACK
int __octnet_xmit(struct sk_buff *skb, octnet_os_devptr_t * pndev);
#endif

struct net_device_stats *octnet_stats(octnet_os_devptr_t * pndev);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0) || defined(HAS_MULTI_TXQUEUE)
void octnet_tx_timeout(struct net_device *pndev, unsigned int txqueue);
#else
void octnet_tx_timeout(struct net_device *pndev);
#endif


int octnet_setup_instr(int octeon_id, octnet_priv_t * priv, int port);

static inline char *octnet_get_devname(octnet_os_devptr_t * dev)
{
	struct net_device *ldev = (struct net_device *)dev;

	return ldev->name;
}

void oct_set_ethtool_ops(octnet_os_devptr_t * netdev);

#define GET_NETDEV_PRIV(pndev)  ((octnet_priv_t *)netdev_priv(pndev))

int octnet_napi_poll_fn(struct napi_struct *napi, int budget);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
int octnet_napi_poll(struct napi_struct *napi, int budget);
#else
int octnet_napi_poll(struct net_device *pndev, int *budget);
#endif

void octnet_stop_txqueue(octnet_os_devptr_t * pndev);

void octnet_start_txqueue(octnet_os_devptr_t * pndev);

void octnet_restart_txqueue(octnet_os_devptr_t * pndev);

/* Added for OCTEON_MQ replacement */
static inline octnet_os_devptr_t *octnet_alloc_netdev(int size, int nq)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (nq > 1)
		return cvm_alloc_netdev_mq(size, "oct%d", ether_setup, nq);
	else
#endif
		return cvm_alloc_netdev(size, "oct%d", ether_setup);
}

static inline void octnet_txqueues_start(octnet_os_devptr_t * pndev)
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(pndev)) {	/* mq support: sub-queues running for netdevice */
		int i;
		for (i = 0; i < pndev->num_tx_queues; i++)
			netif_start_subqueue(pndev, i);	/* mq support: start each sub-queue */
	} else
#endif
	{
		netif_start_queue(pndev);
	}
}

static inline void octnet_txqueues_wake(octnet_os_devptr_t * pndev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(pndev)) {	/* mq support: sub-queues running for netdevice */
		int i;
		for (i = 0; i < pndev->num_tx_queues; i++)
			netif_wake_subqueue(pndev, i);	/* mq support: wake each sub-queue */
	} else
#endif
	{
		netif_wake_queue(pndev);
	}
}

static inline void octnet_txqueues_stop(octnet_os_devptr_t * pndev)
{
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(pndev)) {	/* mq support: sub-queues running for netdevice */
		int i;
		for (i = 0; i < pndev->num_tx_queues; i++)
			netif_stop_subqueue(pndev, i);	/* mq support: stop each sub-queue */
	} else
#endif
	{
		netif_stop_queue(pndev);
	}
}

static inline void octnet_wake_queue(octnet_os_devptr_t * pndev, int q)
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(pndev))
		netif_wake_subqueue(pndev, q);
	else
#endif
		netif_wake_queue(pndev);
}

static inline void octnet_stop_queue(octnet_os_devptr_t * pndev, int q)
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(pndev))
		netif_stop_subqueue(pndev, q);
	else
#endif
		netif_stop_queue(pndev);
}

static inline int
octnet_check_txq_state(octnet_priv_t *priv, u16 queue_mapping)
{

	int q = 0, iq = 0;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(priv->pndev)) {
		q = queue_mapping;
		iq = priv->txq + (q % priv->linfo.num_txpciq);
	} else
#endif
	{
		iq = priv->txq;
	}

	if (OCTNET_IFSTATE_CHECK(priv, OCT_NIC_IFSTATE_TXENABLED))
		return 0;

	if (octnet_iq_is_full(priv->oct_dev, iq))
		return 0;

	OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_TXENABLED);
	octnet_wake_queue(priv->pndev, q);

	return 1;
}

static inline int octnet_check_txq_status(octnet_priv_t * priv)
{

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (netif_is_multiqueue(priv->pndev)) {
		int numqs = priv->pndev->num_tx_queues;	/* mq support: number of sub-queues */
		int q, iq = 0, ret_val = 1;

		for (q = 0; q < numqs; q++) {	/* mq support: check each sub-queue state */
			iq = priv->txq + (q % priv->linfo.num_txpciq);

			if (OCTNET_IFSTATE_CHECK
			    (priv, OCT_NIC_IFSTATE_TXENABLED)) {
				ret_val = 0;
				continue;
			}

			if (octnet_iq_is_full(priv->oct_dev, iq)) {
				ret_val = 0;
				continue;
			}

			OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_TXENABLED);
			octnet_wake_queue(priv->pndev, q);
		}

		return ret_val;
	} else
#endif
	{
		if (OCTNET_IFSTATE_CHECK(priv, OCT_NIC_IFSTATE_TXENABLED))
			return 0;

		if (octnet_iq_is_full(priv->oct_dev, priv->txq))
			return 0;

		OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_TXENABLED);
		octnet_wake_queue(priv->pndev, priv->txq);

		return 1;
	}
}

#endif

/* $Id: octeon_network.h 163569 2017-07-25 15:58:46Z mchalla $ */
