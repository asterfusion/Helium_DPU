/*
 *
 * CNNIC SDK
 *
 * Copyright (c) 2018 Cavium Networks. All rights reserved.
 *
 * This file, which is part of the CNNIC SDK which also includes the
 * CNNIC SDK Package from Cavium Networks, contains proprietary and
 * confidential information of Cavium Networks and in some cases its
 * suppliers. 
 *
 * Any licensed reproduction, distribution, modification, or other use of
 * this file or the confidential information or patented inventions
 * embodied in this file is subject to your license agreement with Cavium
 * Networks. Unless you and Cavium Networks have agreed otherwise in
 * writing, the applicable license terms "OCTEON SDK License Type 5" can be
 * found under the directory: $CNNIC_ROOT/licenses/
 *
 * All other use and disclosure is prohibited.
 *
 * Contact Cavium Networks at info@caviumnetworks.com for more information.
 *
 */

//open the macrodefine for debug
//#define CAVIUM_DEBUG
#include "cavium_sysdep.h"
#include "cavium_defs.h"
#include "octeon_network.h"
#include "octeon_macros.h"
#include "octeon_nic.h"
#include "cavium_release.h"
#ifdef CONFIG_PPORT
#include "if_pport.h"
#endif

extern struct octdev_props_t *octprops[MAX_OCTEON_DEVICES];
#define ARRAY_LENGTH(a) (sizeof(a)/ sizeof( (a)[0]))

static struct {
	const char str[ETH_GSTRING_LEN];
} ethtool_stats_keys[] = {
	{
	"tx_packets"}, {
	"tx_bytes"}, {
	"rx_packets"}, {
	"rx_bytes"}, {
	"tx_errors"}, {
	"tx_dropped"}, {
"rx_dropped"},};

static const char oct_iq_stats_strings[][ETH_GSTRING_LEN] = {
	"packets",
	"bytes",
	"dropped",
};

/* statistics of host rx queue */
static const char oct_droq_stats_strings[][ETH_GSTRING_LEN] = {
	"packets",
	"bytes",
	"dropped",
};

#define OCT_NIC_TX_OK     NETDEV_TX_OK
#define OCT_NIC_TX_BUSY   NETDEV_TX_BUSY

#define OCTNIC_NCMD_AUTONEG_ON  0x1
#define OCTNIC_NCMD_PHY_ON      0x2

void oct_net_setup_if(octeon_recv_info_t * recv_info, void *buf);
void octeon_network_free_tx_buf(octeon_req_status_t status, void *arg);

void octnet_napi_enable(octnet_priv_t * priv);
void octnet_napi_disable(octnet_priv_t * priv);

static inline void __octnet_stop_txqueue(octnet_os_devptr_t * pndev)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	octnet_txqueues_stop(pndev);

	OCTNET_IFSTATE_RESET(priv, OCT_NIC_IFSTATE_TXENABLED);
}

static inline int
__octnet_start_txqueue(octnet_os_devptr_t * pndev, int restart)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	if (OCTNET_IFSTATE_CHECK(priv, OCT_NIC_IFSTATE_TXENABLED))
		return 0;

	if (priv->linfo.link.s.status) {
		if (restart) {
			octnet_txqueues_wake(pndev);
		} else {
			octnet_txqueues_start(pndev);
		}

		OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_TXENABLED);
		return 0;
	}

	return 1;
}

void octnet_stop_txqueue(octnet_os_devptr_t * pndev)
{
	__octnet_stop_txqueue(pndev);
}

void octnet_start_txqueue(octnet_os_devptr_t * pndev)
{
	__octnet_start_txqueue((pndev), 0);
}

void octnet_restart_txqueue(octnet_os_devptr_t * pndev)
{
	__octnet_start_txqueue((pndev), 1);
}

oct_poll_fn_status_t
octnet_poll_check_txq_status(void *oct, unsigned long ul_priv)
{
	if (!OCTNET_IFSTATE_CHECK
	    ((octnet_priv_t *) ul_priv, OCT_NIC_IFSTATE_RUNNING))
		return OCT_POLL_FN_FINISHED;

	octnet_check_txq_status((octnet_priv_t *) ul_priv);

	return OCT_POLL_FN_CONTINUE;
}

void __setup_tx_poll_fn(octnet_os_devptr_t * pndev)
{
	octeon_poll_ops_t poll_ops;
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	poll_ops.fn = octnet_poll_check_txq_status;
	poll_ops.fn_arg = (unsigned long)priv;
	poll_ops.ticks = 1;
	poll_ops.rsvd = 0xff;
	octeon_register_poll_fn(get_octeon_device_id(priv->oct_dev), &poll_ops);
}

/* Net device open */
int octnet_open(struct net_device *pndev)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_RUNNING);

	__setup_tx_poll_fn(pndev);
	octnet_start_txqueue(pndev);

	CVM_MOD_INC_USE_COUNT;

	return 0;
}

/* Net device close */
int octnet_stop(struct net_device *pndev)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	OCTNET_IFSTATE_RESET(priv, OCT_NIC_IFSTATE_RUNNING);
#ifdef OCT_NIC_USE_NAPI
	/* This is a hack that allows DHCP to continue working. */
	set_bit(__LINK_STATE_START, &priv->pndev->state);
#endif
	octnet_txqueues_stop(pndev);

	CVM_MOD_DEC_USE_COUNT;

	return 0;
}

/*
   This routine is called by the callback function when a ctrl pkt sent to
   core app completes. The nctrl_ptr contains a copy of the command type
   and data sent to the core app. This routine is only called if the ctrl
   pkt was sent successfully to the core app.
*/
void octnet_link_ctrl_cmd_completion(void *nctrl_ptr)
{
	octnic_ctrl_pkt_t *nctrl = (octnic_ctrl_pkt_t *) nctrl_ptr;
	octnet_os_devptr_t *pndev;
	octnet_priv_t *priv;

	pndev = (octnet_os_devptr_t *) nctrl->netpndev;
	priv = GET_NETDEV_PRIV(pndev);

	switch (nctrl->ncmd.s.cmd) {
	case OCTNET_CMD_CHANGE_DEVFLAGS:
		/* Save a copy of the flags sent to core app in the private area. */
		priv->core_flags = nctrl->udd[0];
		break;

	case OCTNET_CMD_CHANGE_MACADDR:
		/* If command is successful, change the MACADDR for net device. */
		{
#if 0
			octeon_device_t *oct =
			    (octeon_device_t *) priv->oct_dev;
			/* For 83XX, only lower 3 bytes of mac address is configurable */
			if ((oct->chip_id == OCTEON_CN83XX_PF)
			    || (oct->chip_id == OCTEON_CN83XX_VF))
				cavium_memcpy(pndev->dev_addr + 3,
					      ((uint8_t *) & nctrl->udd[0]) + 5,
					      ETH_ALEN - 3);
			else
#endif
				cavium_memcpy(pndev->dev_addr,
					      (uint8_t *) & nctrl->udd[0] + 2,
					      ETH_ALEN);

			cavium_print_msg
			    ("OCTNIC: %s MACAddr changed to 0x%llx\n",
			     octnet_get_devname(pndev),
			     *((uint64_t *) & pndev->dev_addr));
		}
		break;

	case OCTNET_CMD_CHANGE_MTU:
		/* If command is successful, change the MTU for net device. */
		cavium_print_msg("OCTNIC: %s MTU Changed from %d to %d\n",
				 octnet_get_devname(pndev), pndev->mtu,
				 nctrl->ncmd.s.param2);
		pndev->mtu = nctrl->ncmd.s.param2;
		break;

	case OCTNET_CMD_SET_SETTINGS:
		cavium_print_msg("OCTNIC : %s settings changed\n",
				 octnet_get_devname(pndev));

		break;

	default:
		cavium_error("OCTNIC: %s Unknown cmd: %d\n", __CVM_FUNCTION__,
			     nctrl->ncmd.s.cmd);
	}

}

/* This routine generates a octnet_ifflags_t mask from the net device flags
   received from the OS. */
static inline octnet_ifflags_t octnet_get_new_flags(octnet_os_devptr_t * pndev)
{
	octnet_ifflags_t f = 0;

	if (pndev->flags & IFF_PROMISC) {
		f |= OCTNET_IFFLAG_PROMISC;
	}

	if (pndev->flags & IFF_ALLMULTI) {
		f |= OCTNET_IFFLAG_ALLMULTI;
	}

	if (pndev->flags & IFF_MULTICAST) {
		f |= OCTNET_IFFLAG_MULTICAST;
	}

	return f;
}

/* Net device set_multicast_list */
void octnet_set_mcast_list(octnet_os_devptr_t * pndev)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;
	int ret;

	if (pndev->flags == priv->pndev_flags)
		return;

	/* Save the OS net device flags. */
	priv->pndev_flags = pndev->flags;

	/* Create a ctrl pkt command to be sent to core app. */
	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = OCTNET_CMD_CHANGE_DEVFLAGS;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.ncmd.s.param2 = 0;
	nctrl.ncmd.s.more = 1;
	nctrl.netpndev = (unsigned long)pndev;
	nctrl.cb_fn = octnet_link_ctrl_cmd_completion;

	nctrl.udd[0] = (uint64_t) octnet_get_new_flags(pndev);
	octeon_swap_8B_data(&nctrl.udd[0], 1);

	/* Apparently, any activity in this call from the kernel has to
	   be atomic. So we won't wait for response. */
	nctrl.wait_time = 0;

	nparams.resp_order = OCTEON_RESP_NORESPONSE;

#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	ret = octnet_send_nic_ctrl_pkt(priv->oct_dev, &nctrl, nparams);
	if (ret < 0) {
		cavium_error
		    ("OCTNIC: DevFlags change failed in core (ret: 0x%x)\n",
		     ret);
	}
#else
	octnet_link_ctrl_cmd_completion((void *)&nctrl);
	ret = 0;
#endif
}

/* Net device set_mac_address */
int octnet_set_mac(struct net_device *pndev, void *addr)
{
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	int ret = 0;
#endif
	octnet_priv_t *priv;
	struct sockaddr *p_sockaddr = (struct sockaddr *)addr;
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;

	priv = GET_NETDEV_PRIV(pndev);

	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = OCTNET_CMD_CHANGE_MACADDR;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.ncmd.s.param2 = 0;
	nctrl.ncmd.s.more = 1;
	nctrl.netpndev = (unsigned long)pndev;
	nctrl.cb_fn = octnet_link_ctrl_cmd_completion;
	nctrl.wait_time = 100;

	nctrl.udd[0] = 0;
	/* The MAC Address is presented in network byte order. */
	cavium_memcpy((uint8_t *) & nctrl.udd[0] + 2, p_sockaddr->sa_data,
		      ETH_ALEN);

	nparams.resp_order = OCTEON_RESP_ORDERED;
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	ret = octnet_send_nic_ctrl_pkt(priv->oct_dev, &nctrl, nparams);
	if (ret < 0) {
		cavium_error("OCTNIC: MAC Address change failed\n");
		return -1;
	}
#else
	octnet_link_ctrl_cmd_completion((void *)&nctrl);
#endif

	return 0;
}

/* Net device change_mtu */
int octnet_change_mtu(struct net_device *pndev, int new_mtu)
{
	octnet_priv_t *priv;
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;
	int max_frm_size = new_mtu + 18;
#if  !defined(ETHERPCI)
	int ret = 0;
#endif

	cavium_print(PRINT_FLOW, "OCTNIC: %s called\n", __CVM_FUNCTION__);
	priv = GET_NETDEV_PRIV(pndev);

	/* Limit the MTU to make sure the ethernet packets are between 64 bytes
	   and 65535 bytes */
	if ((max_frm_size < OCTNET_MIN_FRM_SIZE)
	    || (max_frm_size > priv->linfo.link.s.mtu)) {
		cavium_error
		    ("OCTNIC: Invalid MTU: %d (Valid values are between %d and %d)\n",
		     new_mtu, (OCTNET_MIN_FRM_SIZE - 18),
		     (priv->linfo.link.s.mtu - 18));
		return -EINVAL;
	}
#if 0
	if (octeon_reset_oq_bufsize
	    (get_octeon_device_id(priv->oct_dev), priv->rxq, new_mtu)) {
		cavium_error("Error changing output queue buffer size\n");
		ret = -EINVAL;
		goto change_mtu_finish;
	}
#endif

	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = OCTNET_CMD_CHANGE_MTU;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.ncmd.s.param2 = new_mtu;
	nctrl.wait_time = 100;
	nctrl.netpndev = (unsigned long)pndev;
	nctrl.cb_fn = octnet_link_ctrl_cmd_completion;

	nparams.resp_order = OCTEON_RESP_ORDERED;
#if  !defined(ETHERPCI)
	ret = 0;
	if (ret < 0) {
		cavium_error("OCTNIC: Failed to set MTU\n");
		return -1;
	}
#else
	octnet_link_ctrl_cmd_completion((void *)&nctrl);
#endif
	octnet_link_ctrl_cmd_completion((void *)&nctrl);

	return 0;
}

/** Routine to push packets arriving on Octeon interface upto network layer.
  * @param octeon_id  - pointer to octeon device.
  * @param skbuff     - skbuff struct to be passed to network layer.
  * @param len        - size of total data received.
  * @param resp_hdr   - Response header
  * @param lastpkt    - indicates whether this is last packet to push
  * @param napi       - NAPI handler
  */
void
octnet_push_packet(int octeon_id,
		   void *skbuff,
		   uint32_t len,
		   octeon_resp_hdr_t * resp_hdr, int lastpkt, void *napi)
{
// *INDENT-OFF*
	struct sk_buff     *skb   = (struct sk_buff *)skbuff;
	octnet_os_devptr_t *pndev = (octnet_os_devptr_t *)octprops[octeon_id]->pndev[resp_hdr->dest_qport];
// *INDENT-ON*

	if (pndev) {

		int rc;

		octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

		/* Do not proceed if the interface is not in RUNNING state. */
		if (!
		    (cavium_atomic_read(&priv->ifstate) &
		     OCT_NIC_IFSTATE_RUNNING)) {
			free_recv_buffer(skb);
			atomic64_inc((atomic64_t *) & priv->stats.rx_dropped);	/* atomic increment: multi-core support:66xx */
			return;
		}

		skb->dev = pndev;
#ifndef CONFIG_PPORT
		skb->protocol = eth_type_trans(skb, skb->dev);
#else
		if (unlikely(false == (pport_do_receive(skb)))) {
			cavium_print(PRINT_DEBUG,
				     "pport receive error port_id(0x%08x)\n",
				     ntohs(*(__be16 *)skb->data));
			free_recv_buffer(skb);
			atomic64_inc((atomic64_t *) & priv->stats.rx_errors);
			return;
		}
#endif

		if (resp_hdr->csum_verified == CNNIC_CSUM_VERIFIED)
			skb->ip_summed = CHECKSUM_UNNECESSARY;	/* checksum has already verified on OCTEON */
		else
			skb->ip_summed = CHECKSUM_NONE;

#if defined (OCT_NIC_USE_NAPI)
		rc = napi_gro_receive(napi, skb);
#else
		rc = (lastpkt) ? netif_rx_ni(skb) : netif_rx(skb);	/* tuned for TCP_RR/STREAM perf: speed-up packet push */
#endif

#ifdef OCT_NIC_USE_NAPI
		if (rc != GRO_DROP) {
#else
		if (rc != NET_RX_DROP) {
#endif
			priv->stats.rx_bytes += len;
			atomic64_inc((atomic64_t *) & priv->stats.rx_packets);	/* atomic increment: multi-core support:66xx */
//			pndev->last_rx = jiffies;
		} else {
			atomic64_inc((atomic64_t *) & priv->stats.rx_dropped);	/* atomic increment: multi-core support:66xx */
		}

	} else {

		free_recv_buffer(skb);
	}

}

void octnic_free_netbuf(void *buf)
{
	struct sk_buff *skb;
	struct octnet_buf_free_info *finfo;
	octnet_priv_t *priv;

	finfo = (struct octnet_buf_free_info *)buf;
	skb = finfo->skb;
	priv = finfo->priv;

	octeon_unmap_single_buffer(get_octeon_device_id(priv->oct_dev),
				   finfo->dptr, skb->len,
				   CAVIUM_PCI_DMA_TODEVICE);
	free_recv_buffer((cavium_netbuf_t *) skb);

	octnet_check_txq_state(priv, skb);	/* mq support: sub-queue state check */

}

void octnic_free_netsgbuf(void *buf)
{
	struct octnet_buf_free_info *finfo;
	struct sk_buff *skb;
	octnet_priv_t *priv;
	struct octnic_gather *g;
	int i, frags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
    struct skb_frag_struct *frag;
#else
    struct bio_vec *frag;
#endif

	finfo = (struct octnet_buf_free_info *)buf;
	skb = finfo->skb;
	priv = finfo->priv;
	g = finfo->g;
	frags = skb_shinfo(skb)->nr_frags;

	octeon_unmap_single_buffer(get_octeon_device_id(priv->oct_dev),
				   g->sg[0].ptr[0], (skb->len - skb->data_len),
				   CAVIUM_PCI_DMA_TODEVICE);

	i = 1;
	while (frags--) {
		frag = &skb_shinfo(skb)->frags[i - 1];

		octeon_unmap_page(get_octeon_device_id(priv->oct_dev),
				  g->sg[(i >> 2)].ptr[(i & 3)],
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
                  frag->size, 
#else
                  frag->bv_len,
#endif
                  CAVIUM_PCI_DMA_TODEVICE);
		i++;
	}

	octeon_unmap_single_buffer(get_octeon_device_id(priv->oct_dev),
				   finfo->dptr, g->sg_size,
				   CAVIUM_PCI_DMA_TODEVICE);

	cavium_spin_lock(&priv->lock);
	cavium_list_add_tail(&g->list, &priv->glist);
	cavium_spin_unlock(&priv->lock);

	free_recv_buffer((cavium_netbuf_t *) skb);

	octnet_check_txq_state(priv, skb);	/* mq support: sub-queue state check */
}

void print_ip_header(struct iphdr *ip)
{
	cavium_print_msg
	    ("ip: tos: %x tot_len: %x id: %x frag_off: %x ttl: %x proto: %x\n",
	     ip->tos, ip->tot_len, ip->id, ip->frag_off, ip->ttl, ip->protocol);
}

static inline int is_ipv4(struct sk_buff *skb)
{
	return ((skb->protocol == htons(ETH_P_IP))
		&& (cvm_ip_hdr(skb)->version == 4)
		&& (cvm_ip_hdr(skb)->ihl == 5));
}

static inline int is_ip_fragmented(struct sk_buff *skb)
{
	/* The Don't fragment and Reserved flag fields are ignored.
	   IP is fragmented if
	   -  the More fragments bit is set (indicating this IP is a fragment with
	   more to follow; the current offset could be 0 ). 
	   -  ths offset field is non-zero. */
	return (htons(cvm_ip_hdr(skb)->frag_off) & 0x3fff);
}

static inline int is_ipv6(struct sk_buff *skb)
{
	return ((skb->protocol == htons(ETH_P_IPV6))
		&& (cvm_ip6_hdr(skb)->version == 6));
}

static inline int is_wo_extn_hdr(struct sk_buff *skb)
{
	return ((cvm_ip6_hdr(skb)->nexthdr == IPPROTO_TCP) ||
		(cvm_ip6_hdr(skb)->nexthdr == IPPROTO_UDP));
}

static inline int is_tcpudp(struct sk_buff *skb)
{
	return ((cvm_ip_hdr(skb)->protocol == IPPROTO_TCP)
		|| (cvm_ip_hdr(skb)->protocol == IPPROTO_UDP));
}

int octnet_xmit(struct sk_buff *skb, struct net_device *pndev)
{
	octnet_priv_t *priv;
	struct octnet_buf_free_info *finfo;
	octnic_cmd_setup_t cmdsetup;
	octnic_data_pkt_t ndata;
	int cpu = 0, status = 0;


	priv = GET_NETDEV_PRIV(pndev);

	cavium_print(PRINT_FLOW, "OCTNIC: network xmit called, qno %d\n", priv->txq);

#ifdef CONFIG_PPORT
	if (unlikely(*(u32 *)(&skb->cb[SKB_CB_PPORT_MAGIC_OFFSET]) !=
		     SKB_CB_PPORT_MAGIC_U32)) {
		cavium_print(PRINT_ERROR,
			     "pport mode - can't send packets from Linux stack\n");
		goto oct_xmit_failed;
	}
#endif
	atomic64_inc((atomic64_t *) & priv->stats.tx_packets);	/* atomic increment: multi-core support:66xx */
	priv->stats.tx_bytes += skb->len;

	if (!OCTNET_IFSTATE_CHECK(priv, OCT_NIC_IFSTATE_TXENABLED)) {
		return OCT_NIC_TX_BUSY;
	}

	/* Check for all conditions in which the current packet cannot be
	   transmitted. */
	if (!(cavium_atomic_read(&priv->ifstate) & OCT_NIC_IFSTATE_RUNNING)
	    || (!priv->linfo.link.s.status)
	    || (skb->len <= 0)) {
		goto oct_xmit_failed;
	}

	/* Use space in skb->cb to store info used to unmap and free the buffers. */
	finfo = (struct octnet_buf_free_info *)skb->cb;
	finfo->priv = priv;
	finfo->skb = skb;

	/* Prepare the attributes for the data to be passed to OSI. */
	ndata.buf = (void *)finfo;

	ndata.q_no = priv->txq;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
#if !defined(ETHERPCI)
	if (netif_is_multiqueue(pndev)) {
              cpu = skb->queue_mapping;       /* mq support: sk_buff sub-queue mapping */

		//cpu = smp_processor_id();	/* queue mapping: tuned for TCP_RR/STREAM perf: get corenum */

		ndata.q_no = priv->txq + (cpu & (priv->linfo.num_txpciq - 1));
		if (octnet_iq_is_full(priv->oct_dev, ndata.q_no)) {	/* mq support: defer sending if qfull */
			return OCT_NIC_TX_BUSY;
		}
	}
#endif
#endif
	//printk(" XMIT - valid Qs: %d, 1st Q no: %d, cpu:  %d, q_no:%d\n",priv->linfo.num_txpciq, priv->txq, cpu, ndata.q_no );

	ndata.datasize = skb->len;
	cavium_print(PRINT_FLOW, "OCTNIC: network xmit cpu %d, qno %d\n", cpu, ndata.q_no);

	cmdsetup.u64 = 0;
	cmdsetup.s.ifidx = priv->linfo.ifidx;

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		if ((is_ipv4(skb) && !is_ip_fragmented(skb) && is_tcpudp(skb)) ||
		    (is_ipv6(skb) && is_wo_extn_hdr(skb))) {
			cmdsetup.s.cksum_offset = TOTAL_TAG_LEN +
							sizeof(struct ethhdr) + 1;
		}
	}

	if (skb_shinfo(skb)->nr_frags == 0) {

		cmdsetup.s.u.datasize = skb->len;
#if defined(ETHERPCI)
		octnet_prepare_pci_cmd(priv->oct_dev, &(ndata.cmd), &cmdsetup,
				       ndata.q_no);
#else
		octnet_prepare_pci_cmd(priv->oct_dev, &(ndata.cmd), &cmdsetup);
#endif
		/* Offload checksum calculation for TCP/UDP packets */
		ndata.cmd.dptr =
		    octeon_map_single_buffer(get_octeon_device_id
					     (priv->oct_dev), skb->data,
					     skb->len, CAVIUM_PCI_DMA_TODEVICE);

		finfo->dptr = ndata.cmd.dptr;

		ndata.buftype = NORESP_BUFTYPE_NET;

	} else {
		int i, frags;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
        struct skb_frag_struct *frag;
#else
        struct bio_vec *frag;
#endif
		struct octnic_gather *g;

		cavium_spin_lock(&priv->lock);
		g = (struct octnic_gather *)
		    cavium_list_delete_head(&priv->glist);
		cavium_spin_unlock(&priv->lock);

		if (g == NULL)
			goto oct_xmit_failed;

		//cmdsetup.s.u.datasize = skb->len;
        /* Using reserved field to pass data len for timebeing */
		cmdsetup.s.rsvd = skb->len; //CHK
		cmdsetup.s.gather = 1;
		cmdsetup.s.u.gatherptrs = (skb_shinfo(skb)->nr_frags + 1);
        //printk("Gather: len:%d\n", skb->len);
#if defined(ETHERPCI)
		octnet_prepare_pci_cmd(priv->oct_dev, &(ndata.cmd), &cmdsetup,
				       ndata.q_no);
#else
		octnet_prepare_pci_cmd(priv->oct_dev, &(ndata.cmd), &cmdsetup);
#endif

		memset(g->sg, 0, g->sg_size);

		g->sg[0].ptr[0] =
		    octeon_map_single_buffer(get_octeon_device_id
					     (priv->oct_dev), skb->data,
					     (skb->len - skb->data_len),
					     CAVIUM_PCI_DMA_TODEVICE);
		CAVIUM_ADD_SG_SIZE(&(g->sg[0]), (skb->len - skb->data_len), 0);

		frags = skb_shinfo(skb)->nr_frags;
		i = 1;
		while (frags--) {
			frag = &skb_shinfo(skb)->frags[i - 1];

			g->sg[(i >> 2)].ptr[(i & 3)] =
			    octeon_map_page(get_octeon_device_id(priv->oct_dev),
#if  LINUX_VERSION_CODE <= KERNEL_VERSION(3,1,10)
					    frag->page,
					    frag->page_offset,
					    frag->size,
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
                        frag->page.p,
					    frag->page_offset,
					    frag->size,
#else
                        frag->bv_page,
                        frag->bv_offset,
                        frag->bv_len,
#endif
					    CAVIUM_PCI_DMA_TODEVICE);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
            CAVIUM_ADD_SG_SIZE(&(g->sg[(i >> 2)]), frag->size,
                       (i & 3));
#else
            CAVIUM_ADD_SG_SIZE(&(g->sg[(i >> 2)]), frag->bv_len,
                       (i & 3));
#endif
			i++;
		}

		ndata.cmd.dptr =
		    octeon_map_single_buffer(get_octeon_device_id
					     (priv->oct_dev), g->sg, g->sg_size,
					     CAVIUM_PCI_DMA_TODEVICE);

		finfo->dptr = ndata.cmd.dptr;
		finfo->g = g;

		ndata.buftype = NORESP_BUFTYPE_NET_SG;
	}

	{
		octeon_device_t *oct = (octeon_device_t *) priv->oct_dev;
		if ((oct->chip_id == OCTEON_CN83XX_PF)
		    || (oct->chip_id == OCTEON_CN83XX_VF)
		    || (oct->chip_id == OCTEON_CN93XX_PF)
		    || (oct->chip_id == OCTEON_CN98XX_PF)) {

			if (skb_shinfo(skb)->gso_size) {
				tso_info_t *tx_info;
				octeon_instr3_64B_t *cmd_o3;

				cmd_o3 = (octeon_instr3_64B_t *) & (ndata.cmd);
				tx_info = (tso_info_t *) & (cmd_o3->exhdr[0]);

				tx_info->s.gso_size = skb_shinfo(skb)->gso_size;
				tx_info->s.gso_segs = skb_shinfo(skb)->gso_segs;
				//printk("gso_size: %d, gso_segs: %d\n", tx_info->s.gso_size, tx_info->s.gso_segs);
			}
		}
	}

	status = octnet_send_nic_data_pkt(priv->oct_dev, &ndata);
	if (status == NORESP_SEND_FAILED)
		goto oct_xmit_failed;

	if (status == NORESP_SEND_STOP) {

		octnet_stop_queue(priv->pndev, cpu);

		OCTNET_IFSTATE_RESET(priv, OCT_NIC_IFSTATE_TXENABLED);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
	/* TODO: shouldn't it be updated to queue, instead of device ? */
       netif_trans_update(pndev);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
       pndev->trans_start = jiffies;
#endif

	return OCT_NIC_TX_OK;

oct_xmit_failed:
	atomic64_inc((atomic64_t *) & priv->stats.tx_dropped);	/* atomic increment: multi-core support:66xx */
	free_recv_buffer(skb);
	return OCT_NIC_TX_OK;
}

void octnet_napi_enable(octnet_priv_t * priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	napi_enable(&priv->napi);
#else
	netif_poll_enable(priv->pndev);
#endif
}

void octnet_napi_disable(octnet_priv_t * priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	napi_disable(&priv->napi);
#else
	netif_poll_disable(priv->pndev);
#endif
}

void octnet_notify_napi_complete(octnet_priv_t * priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	napi_complete(&priv->napi);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	netif_rx_complete(priv->pndev, &priv->napi);
#else
	netif_rx_complete(priv->pndev);
#endif
}

void octnet_notify_napi_start(octnet_priv_t * priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	napi_schedule(&priv->napi);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	netif_rx_schedule(priv->pndev, &priv->napi);
#else
	netif_rx_schedule(priv->pndev);
#endif
}

void octnet_napi_drv_callback(int oct_id, int oq_no, int event)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(octprops[oct_id]->pndev[oq_no]);
	if (event == POLL_EVENT_INTR_ARRIVED) {
		octnet_notify_napi_start(priv);
	}
}

void octnet_napi_callback(octeon_droq_t * droq)
{
	//printk("%s:q_no:%d cpu:%d\n",__func__,droq->q_no,smp_processor_id());
	napi_schedule(&droq->napi);
}

int octnet_napi_do_rx(octnet_priv_t * priv, int budget)
{
	int work_done, oct_id;

	oct_id = get_octeon_device_id(priv->oct_dev);

	work_done = octeon_process_droq_poll_cmd(oct_id, priv->rxq,
						 POLL_EVENT_PROCESS_PKTS,
						 budget);
	if (work_done < 0) {
		cavium_error
		    ("\n %s: CHECK THE OCTEON DEVICE ID OR DROQ NUMBER\n",
		     __FUNCTION__);
		goto octnet_napi_finish;
	}

	if (work_done > budget) {
		cavium_error(">>>> %s work_done: %d budget: %d\n", __FUNCTION__,
			     work_done, budget);
	}

	return work_done;

octnet_napi_finish:
	octnet_notify_napi_complete(priv);
	octeon_process_droq_poll_cmd(oct_id, priv->rxq, POLL_EVENT_ENABLE_INTR,
				     0);
	return 0;
}

int octnet_napi_poll_fn(struct napi_struct *napi, int budget)
{
	octeon_droq_t *droq;
	int work_done, oct_id;

	droq = container_of(napi, octeon_droq_t, napi);
	oct_id = get_octeon_device_id(droq->oct_dev);
	//printk("%s: q_no:%d cpu:%d budget:%d\n",__func__,droq->q_no,smp_processor_id(),budget);

	work_done = octeon_process_droq_poll_cmd(oct_id, droq->q_no,
						 POLL_EVENT_PROCESS_PKTS,
						 budget);
	//printk("work_done:%d budget:%d\n", work_done, budget);
#ifdef OCT_NIC_IQ_USE_NAPI
	iq = droq->oct_dev->instr_queue[iq_no];
	if (iq) {
		if (atomic_read(&iq->instr_pending))
		/* Process iq buffers with in the budget limits */
			tx_done = octeon_flush_iq(oct, iq, budget);
		else
			tx_done = 1;
		/* Update iq read-index rather than waiting for next interrupt.
		 * Return back if tx_done is false.
		 */
		update_txq_status(oct, iq_no);
	} else {
		dev_err(&oct->pci_dev->dev, "%s:  iq (%d) num invalid\n",
				__func__, iq_no);
	}
	/* force enable interrupt if reg cnts are high to avoid wraparound */
	if ((work_done < budget && tx_done) ||
		(iq && iq->pkt_in_done >= MAX_REG_CNT) ||
		(droq->pkt_count >= MAX_REG_CNT)) {
		tx_done = 1;
		napi_complete_done(napi, work_done);
		octeon_process_droq_poll_cmd(oct_id, droq->q_no,
						POLL_EVENT_ENABLE_INTR, 0);
			return 0;
	}
	return (!tx_done) ? (budget) : (work_done);
#else	
	if (work_done < budget) {
		napi_complete(napi);
		octeon_process_droq_poll_cmd(oct_id, droq->q_no,
					     POLL_EVENT_ENABLE_INTR, 0);
		return 0;
	}

	if (work_done > budget) {
		cavium_error("work_done(%d) > budget(%d)\n", work_done, budget);
	}
	return work_done;
#endif	
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)

int octnet_napi_poll(struct napi_struct *napi, int budget)
{
	struct net_device *pndev = napi->dev;
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);
	int work_done;

	work_done = octnet_napi_do_rx(priv, budget);

	if (work_done < budget) {
		int oct_id = get_octeon_device_id(priv->oct_dev);
		octnet_notify_napi_complete(priv);
		octeon_process_droq_poll_cmd(oct_id, priv->rxq,
					     POLL_EVENT_ENABLE_INTR, 0);
		return 0;
	}

	return work_done;
}

#else

int octnet_napi_poll(struct net_device *pndev, int *budget)
{
	int work_done = 0;
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);

	work_done = octnet_napi_do_rx(priv, *budget);

	*budget -= work_done;
	pndev->quota -= work_done;

	if (work_done < *budget) {
		int oct_id = get_octeon_device_id(priv->oct_dev);
		octnet_notify_napi_complete(priv);
		octeon_process_droq_poll_cmd(oct_id, priv->rxq,
					     POLL_EVENT_ENABLE_INTR, 0);
		return 0;
	}

	return 1;
}

#endif

struct net_device_stats *octnet_stats(struct net_device *pndev)
{
	cavium_print(PRINT_FLOW, "octnet_stats: network stats called\n");
	return &(GET_NETDEV_PRIV(pndev)->stats);
}

void octnet_tx_timeout(struct net_device *pndev)
{
	octnet_priv_t *priv;
	priv = GET_NETDEV_PRIV(pndev);

	cavium_error("OCTNIC: tx timeout for %s\n", octnet_get_devname(pndev));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
	/* TODO: shouldn't it be updated to queue, instead of device ? */
       netif_trans_update(pndev);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
       pndev->trans_start = jiffies;
#endif

	octnet_txqueues_wake(pndev);
}

static int oct_get_link_ksettings(struct net_device *netdev,
				   struct ethtool_link_ksettings *ecmd)
{
	octnet_priv_t *priv;
	oct_link_info_t *linfo;
	u32 val;

	priv = GET_NETDEV_PRIV(netdev);
	linfo = &priv->linfo;

	if (linfo->link.s.interface == INTERFACE_MODE_XAUI ||
	    linfo->link.s.interface == INTERFACE_MODE_RXAUI) {
		ecmd->base.port = PORT_FIBRE;
		val = (SUPPORTED_10000baseT_Full | SUPPORTED_Autoneg | SUPPORTED_FIBRE);
		ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.supported, val);

		val = (ADVERTISED_10000baseT_Full | ADVERTISED_Autoneg);
		ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.advertising,
							val);
	} else {
		ecmd->base.port = PORT_TP;
		val =
		    (SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
		     SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full |
		     SUPPORTED_1000baseT_Half | SUPPORTED_1000baseT_Full |
		     SUPPORTED_Autoneg | SUPPORTED_MII);
		ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.supported, val);

		val =
		    (ADVERTISED_1000baseT_Full | ADVERTISED_100baseT_Full |
		     ADVERTISED_10baseT_Full | ADVERTISED_10baseT_Half |
		     ADVERTISED_100baseT_Half | ADVERTISED_1000baseT_Half |
		     ADVERTISED_Autoneg);
		ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.advertising,
							val);
	}

	if (linfo->link.s.status) {
		ecmd->base.speed = linfo->link.s.speed;
		ecmd->base.duplex = linfo->link.s.duplex;
		ecmd->base.autoneg = linfo->link.s.autoneg;
	} else {
		ecmd->base.speed = -1;
		ecmd->base.duplex = -1;
	}

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
static int
oct_get_settings(octnet_os_devptr_t * netdev, struct ethtool_cmd *ecmd)
{
	octnet_priv_t *priv;
	oct_link_info_t *linfo;

	priv = GET_NETDEV_PRIV(netdev);
	linfo = &priv->linfo;

	if (linfo->link.s.interface == INTERFACE_MODE_XAUI ||
	    linfo->link.s.interface == INTERFACE_MODE_RXAUI) {
		ecmd->port = PORT_FIBRE;
		ecmd->supported =
		    (SUPPORTED_10000baseT_Full | SUPPORTED_Autoneg |
		     SUPPORTED_FIBRE);
		ecmd->advertising =
		    (ADVERTISED_10000baseT_Full | ADVERTISED_Autoneg);

	} else {
		ecmd->port = PORT_TP;
		ecmd->supported =
		    (SUPPORTED_10baseT_Half | SUPPORTED_10baseT_Full |
		     SUPPORTED_100baseT_Half | SUPPORTED_100baseT_Full |
		     SUPPORTED_1000baseT_Half | SUPPORTED_1000baseT_Full |
		     SUPPORTED_Autoneg | SUPPORTED_MII);

		ecmd->advertising =
		    (ADVERTISED_1000baseT_Full | ADVERTISED_100baseT_Full |
		     ADVERTISED_10baseT_Full | ADVERTISED_10baseT_Half |
		     ADVERTISED_100baseT_Half | ADVERTISED_1000baseT_Half |
		     ADVERTISED_Autoneg);

	}

	if (linfo->link.s.status) {
		ecmd->speed = linfo->link.s.speed;
		ecmd->duplex = linfo->link.s.duplex;
		ecmd->autoneg = linfo->link.s.autoneg;
	} else {
		ecmd->speed = -1;
		ecmd->duplex = -1;
	}

	return 0;
}
#endif

u32 oct_get_link(octnet_os_devptr_t * dev)
{
	u32 ret;
	ret = netif_carrier_ok(dev) ? 1 : 0;
	return ret;
}

static void
oct_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *drvinfo)
{
	octnet_priv_t *priv;
	octeon_device_t *oct;
	const char *nic_cvs_tag = CNNIC_VERSION;
	char nic_version[sizeof(CNNIC_VERSION) + 100];

	cavium_parse_cvs_string(nic_cvs_tag, nic_version, sizeof(nic_version));
	priv = GET_NETDEV_PRIV(netdev);
	oct = priv->oct_dev;

	memset(drvinfo, 0, sizeof(struct ethtool_drvinfo));
	strcpy(drvinfo->driver, "OCTNIC");
	strcpy(drvinfo->version, nic_version);
	strcpy(drvinfo->fw_version, "no information");
	strncpy(drvinfo->bus_info, pci_name(oct->pci_dev), 32);
}

static void
oct_ethtool_get_ringparam(struct net_device *netdev,
			  struct ethtool_ringparam *ering)
{
	octnet_priv_t *priv;
	priv = GET_NETDEV_PRIV(netdev);

	ering->tx_max_pending = CN83XX_MAX_INPUT_QUEUES;
	ering->rx_max_pending = CN83XX_MAX_OUTPUT_QUEUES;
	ering->rx_mini_max_pending = 0;
	ering->rx_jumbo_max_pending = 0;

	ering->rx_pending = 1;
	ering->tx_pending = 1;
	ering->rx_mini_pending = 0;
	ering->rx_jumbo_pending = 0;
}

static void
oct_get_ethtool_stats(struct net_device *netdev,
		      struct ethtool_stats *stats, u64 * data)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	octeon_device_t *oct_dev = priv->oct_dev;
	octeon_droq_t *droq;
	octeon_instr_queue_t *instr_queue;
	int i, cnt, total_rings;

	cnt = 0;
	data[cnt++] = priv->stats.tx_packets;
	data[cnt++] = priv->stats.tx_bytes;
	data[cnt++] = priv->stats.rx_packets;
	data[cnt++] = priv->stats.rx_bytes;
	data[cnt++] = priv->stats.tx_errors;
	data[cnt++] = priv->stats.tx_dropped;
	data[cnt++] = priv->stats.rx_dropped;

	total_rings = oct_dev->sriov_info.rings_per_pf;
	for (i = 0; i < total_rings; i++) {
		instr_queue =  oct_dev->instr_queue[i];
		data[cnt++] = instr_queue->stats.instr_processed;
		data[cnt++] = instr_queue->stats.bytes_sent;
		data[cnt++] = instr_queue->stats.instr_dropped;
	}

	for (i = 0; i < total_rings; i++) {
		droq = oct_dev->droq[i];
		data[cnt++] = droq->stats.pkts_received;
		data[cnt++] = droq->stats.bytes_received;
		data[cnt++] = droq->stats.dropped_nodispatch +
			droq->stats.dropped_nomem +
			droq->stats.dropped_toomany +
			droq->stats.dropped_zlp;
	}
}

static void oct_get_strings(struct net_device *netdev, u32 stringset, u8 * data)
{
	int i, j, num_stats, total_rings;
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	octeon_device_t *oct_dev = priv->oct_dev;

	num_stats = ARRAY_LENGTH(ethtool_stats_keys);
	for (j = 0; j < num_stats; j++) {
		sprintf(data, "%s", ethtool_stats_keys[j].str);
		data += ETH_GSTRING_LEN;
	}

	total_rings = oct_dev->sriov_info.rings_per_pf;
	num_stats = ARRAY_LENGTH(oct_iq_stats_strings);
	for (i = 0; i < total_rings; i++) {
		for (j = 0; j < num_stats; j++) {
			sprintf(data, "tx-%d-%s", i, oct_iq_stats_strings[j]);
			data += ETH_GSTRING_LEN;
		}
	}

	num_stats = ARRAY_LENGTH(oct_droq_stats_strings);
	for (i = 0; i < total_rings; i++) {
		for (j = 0; j < num_stats; j++) {
			sprintf(data, "rx-%d-%s", i, oct_droq_stats_strings[j]);
			data += ETH_GSTRING_LEN;
		}
	}
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24)
static int oct_get_sset_count(struct net_device *netdev, int sset)
{
	int total_rings;
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	octeon_device_t *oct_dev = priv->oct_dev;

	total_rings = oct_dev->sriov_info.rings_per_pf;
	return ARRAY_LENGTH(ethtool_stats_keys) +
		(total_rings * ARRAY_LENGTH(oct_iq_stats_strings)) +
		(total_rings * ARRAY_LENGTH(oct_droq_stats_strings));
}
#else
static int oct_get_stats_count(struct net_device *netdev)
{
	int total_rings;
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	octeon_device_t *oct_dev = priv->oct_dev;

	total_rings = oct_dev->sriov_info.rings_per_pf;
	return ARRAY_LENGTH(ethtool_stats_keys) +
		(total_rings * ARRAY_LENGTH(oct_iq_stats_strings)) +
		(total_rings * ARRAY_LENGTH(oct_droq_stats_strings));
}
#endif

static int oct_set_link_ksettings(struct net_device *netdev,
				   const struct ethtool_link_ksettings *ecmd)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	oct_link_info_t *linfo;
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	int ret = 0;
#endif
	u32 val;

	/* get the link info */
	linfo = &priv->linfo;

	if (ecmd->base.autoneg != AUTONEG_ENABLE &&
	    ecmd->base.autoneg != AUTONEG_DISABLE)
		return -EINVAL;

	if (ecmd->base.autoneg == AUTONEG_DISABLE &&
	    ((ecmd->base.speed != SPEED_100 && ecmd->base.speed != SPEED_10) ||
	     (ecmd->base.duplex != DUPLEX_HALF &&
	      ecmd->base.duplex != DUPLEX_FULL)))
		return -EINVAL;

	/* Ethtool Support is not provided for XAUI and RXAUI Interfaces
	 * as they operate at fixed Speed and Duplex settings
	 * */
	if (linfo->link.s.interface == INTERFACE_MODE_XAUI ||
	    linfo->link.s.interface == INTERFACE_MODE_RXAUI) {
		cavium_print_msg(" XAUI IFs settings cannot be modified.\n");
		cavium_print_msg
		    (" Because they always operate with constant settings. \n");
		return -EINVAL;
	}

	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = OCTNET_CMD_SET_SETTINGS;
	nctrl.wait_time = 1000;
	nctrl.netpndev = (unsigned long)netdev;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.cb_fn = octnet_link_ctrl_cmd_completion;

	/* Passing the parameters sent by ethtool like Speed, Autoneg & Duplex
	 * to SE core application using ncmd.s.more & ncmd.s.param
	 */
	if (ecmd->base.autoneg == AUTONEG_ENABLE) {
		/* Autoneg ON */
		nctrl.ncmd.s.more = OCTNIC_NCMD_PHY_ON | OCTNIC_NCMD_AUTONEG_ON;
		ethtool_convert_link_mode_to_legacy_u32(&val,
							ecmd->link_modes.advertising);
		nctrl.ncmd.s.param2 = val;
	} else {
		/* Autoneg OFF */
		nctrl.ncmd.s.more = OCTNIC_NCMD_PHY_ON;

		nctrl.ncmd.s.param3 = ecmd->base.duplex;

		nctrl.ncmd.s.param2 = ecmd->base.speed;
	}

	nparams.resp_order = OCTEON_RESP_ORDERED;
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	ret = octnet_send_nic_ctrl_pkt(priv->oct_dev, &nctrl, nparams);
	if (ret < 0) {
		cavium_error("OCTNIC: Failed to set settings\n");
		return -1;
	}
#else
	octnet_link_ctrl_cmd_completion((void *)&nctrl);
#endif

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
static int oct_set_settings(struct net_device *netdev, struct ethtool_cmd *ecmd)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(netdev);
	oct_link_info_t *linfo;
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	int ret = 0;
#endif

	/* get the link info */
	linfo = &priv->linfo;

	if (ecmd->autoneg != AUTONEG_ENABLE && ecmd->autoneg != AUTONEG_DISABLE)
		return -EINVAL;

	if (ecmd->autoneg == AUTONEG_DISABLE && ((ecmd->speed != SPEED_100 &&
						  ecmd->speed != SPEED_10) ||
						 (ecmd->duplex != DUPLEX_HALF
						  && ecmd->duplex !=
						  DUPLEX_FULL)))
		return -EINVAL;

	/* Ethtool Support is not provided for XAUI and RXAUI Interfaces 
	 * as they operate at fixed Speed and Duplex settings
	 * */
	if (linfo->link.s.interface == INTERFACE_MODE_XAUI ||
	    linfo->link.s.interface == INTERFACE_MODE_RXAUI) {
		cavium_print_msg(" XAUI IFs settings cannot be modified.\n");
		cavium_print_msg
		    (" Because they always operate with constant settings. \n");
		return -EINVAL;
	}

	nctrl.ncmd.u64 = 0;
	nctrl.ncmd.s.cmd = OCTNET_CMD_SET_SETTINGS;
	nctrl.wait_time = 1000;
	nctrl.netpndev = (unsigned long)netdev;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.cb_fn = octnet_link_ctrl_cmd_completion;

	/* Passing the parameters sent by ethtool like Speed, Autoneg & Duplex 
	 * to SE core application using ncmd.s.more & ncmd.s.param 
	 */
	if (ecmd->autoneg == AUTONEG_ENABLE) {
		/* Autoneg ON */
		nctrl.ncmd.s.more = OCTNIC_NCMD_PHY_ON | OCTNIC_NCMD_AUTONEG_ON;
		nctrl.ncmd.s.param2 = ecmd->advertising;
	} else {
		/* Autoneg OFF */
		nctrl.ncmd.s.more = OCTNIC_NCMD_PHY_ON;

		nctrl.ncmd.s.param3 = ecmd->duplex;

		nctrl.ncmd.s.param2 = ecmd->speed;
	}

	nparams.resp_order = OCTEON_RESP_ORDERED;
#if !defined(ETHERPCI) && defined(OCTNIC_CTRL)
	ret = octnet_send_nic_ctrl_pkt(priv->oct_dev, &nctrl, nparams);
	if (ret < 0) {
		cavium_error("OCTNIC: Failed to set settings\n");
		return -1;
	}
#else
	octnet_link_ctrl_cmd_completion((void *)&nctrl);
#endif

	return 0;
}
#endif

static int oct_nway_reset(struct net_device *netdev)
{
	if (netif_running(netdev))
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
		struct ethtool_cmd ecmd;
		memset(&ecmd, 0, sizeof(struct ethtool_cmd));

		ecmd.autoneg = AUTONEG_ENABLE;
		ecmd.speed = 0;
		ecmd.duplex = 0;
		oct_set_settings(netdev, &ecmd);
#else
        struct ethtool_link_ksettings ecmd;

        memset(&ecmd, 0, sizeof(struct ethtool_link_ksettings));

        ecmd.base.autoneg = AUTONEG_ENABLE;
        ecmd.base.speed = 0;
        ecmd.base.duplex = 0;
        oct_set_link_ksettings(netdev, &ecmd);
#endif
	}

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
static const struct ethtool_ops oct_ethtool_ops = {
#else
static struct ethtool_ops oct_ethtool_ops = {
#endif
	.get_link = oct_get_link,
	.get_drvinfo = oct_get_drvinfo,
	.get_ringparam = oct_ethtool_get_ringparam,
	.get_strings = oct_get_strings,
	.get_ethtool_stats = oct_get_ethtool_stats,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,24)
	.get_sset_count = oct_get_sset_count,
#else
	.get_stats_count = oct_get_stats_count,
#endif
	.nway_reset = oct_nway_reset,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,4,0)
	.get_settings = oct_get_settings,
    .set_settings = oct_set_settings,
#endif
	.get_link_ksettings = oct_get_link_ksettings,
	.set_link_ksettings = oct_set_link_ksettings,
};

void oct_set_ethtool_ops(octnet_os_devptr_t * netdev)
{
	CVM_SET_ETHTOOL_OPS(netdev, &oct_ethtool_ops);
}

/* $Id: octeon_network.c 170607 2018-03-20 15:52:25Z vvelumuri $ */
