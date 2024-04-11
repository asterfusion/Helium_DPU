/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "cavium_sysdep.h"
#include "cavium_release.h"
#include "octeon_network.h"
#include "octeon_macros.h"
#include "octeon_nic.h"
#include "octeon_compat.h"

#include "octeon_vf_mbox.h"
MODULE_AUTHOR("Cavium Networks");
MODULE_DESCRIPTION("Octeon Host PCI Nic Driver");
MODULE_LICENSE("GPL");

/*
 * This is only used on the PF.  This file is shared with the VF, so it
 * also is present for the VF, but is not used.
 */
int keepalive_miss_limit = 20;
module_param(keepalive_miss_limit, int, 0600);
MODULE_PARM_DESC(keepalive_miss_limit, "Number of missed keepalive IRQS required to bring link down");
int keepalive_period_ms = 1000;
module_param(keepalive_period_ms, int, 0);
MODULE_PARM_DESC(keepalive_period_ms, "Period of keepalive checks in ms.");

extern void octnet_napi_drv_callback(int oct_id, int oq_no, int event);
extern void octnet_napi_callback(void *);

static inline uint32_t octnet_get_num_ioqs(octeon_device_t * octeon_dev);
struct octdev_props_t *octprops[MAX_OCTEON_DEVICES];

octeon_config_t *octeon_dev_conf(octeon_device_t * oct);

#define LINK_STATUS_REQUESTED    1
#define LINK_STATUS_FETCHED      2

#ifdef CONFIG_PPORT
#define OCTEON_NETDEV_DEV_NAME   "mux_dev"
#endif

static inline void octnet_free_netdev(octnet_os_devptr_t * dev)
{
	return free_netdev(dev);
}

#if defined(OCTEON_EXCLUDE_BASE_LOAD)
extern void get_base_compile_options(char *copts);
#endif

void get_nic_compile_options(char *copts)
{
#if defined(OCTEON_EXCLUDE_BASE_LOAD)
	get_base_compile_options(copts);
#endif
	strcat(copts, "NAPI");
}

void octnet_print_link_info(octnet_os_devptr_t * pndev)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);
// *INDENT-OFF*

	if(cavium_atomic_read(&priv->ifstate) & OCT_NIC_IFSTATE_REGISTERED) {
		oct_link_info_t   *linfo = &(priv->linfo);
		if(linfo->link.s.status)
			cavium_print_msg("OCTNIC: %s -> %d Mbps %s Duplex UP\n",
		                 octnet_get_devname(pndev), linfo->link.s.speed,
		                 (linfo->link.s.duplex)?"Full":"Half");
		else
			cavium_print_msg("OCTNIC: %s Link Down\n",
		                 octnet_get_devname(pndev));
	}
// *INDENT-ON*
}

/* Called on receipt of a link status response from the core application to
   update each interface's link status. */
static inline void
octnet_update_link_status(octnet_os_devptr_t * pndev, oct_link_status_t * ls)
{
	octnet_priv_t *priv = GET_NETDEV_PRIV(pndev);
	oct_link_status_t prev_st;

	prev_st.u64 = priv->linfo.link.u64;
	priv->linfo.link.u64 = ls->u64;

	if (prev_st.u64 != ls->u64) {
		octnet_print_link_info(pndev);
		if (priv->linfo.link.s.status) {
			netif_carrier_on(pndev);
			//octnet_start_txqueue(pndev);
			octnet_txqueues_wake(pndev);
		} else {
			netif_carrier_off(pndev);
			octnet_stop_txqueue(pndev);
		}
	}
}

/* Callback called by BASE driver when response arrives for a link status
   instruction sent by the poll function (runtime link status monitoring). */
// *INDENT-OFF*
void
octnet_link_change_callback(octeon_req_status_t  status, void *props_ptr)
{
	struct octdev_props_t       *props;
	oct_link_status_resp_t      *ls;
	int                          ifidx;

	props = (struct octdev_props_t  *)props_ptr;
	ls    = props->ls;

	/* Don't do anything if the status is not 0. */
	if(ls->status) {
		goto end_of_link_change_callback;
	}

	/* The link count should be swapped on little endian systems. */
	octeon_swap_8B_data(&(ls->link_count), 1);

	if(ls->link_count > MAX_OCTEON_LINKS) {
		cavium_error("%s: Link count (%llu) exceeds max (%d)\n", __FUNCTION__,
		             ls->link_count, MAX_OCTEON_LINKS);
		goto end_of_link_change_callback;
	}

	for(ifidx = 0; ifidx < ls->link_count; ifidx++)
        octeon_swap_8B_data((uint64_t *)&ls->link_info[ifidx],((OCT_LINK_INFO_SIZE - (sizeof(ls->link_info[ifidx].txpciq) + sizeof(ls->link_info[ifidx].rxpciq)))) >> 3);

	for(ifidx = 0; ifidx < ls->link_count; ifidx++) {
		octnet_update_link_status(props->pndev[ifidx],
		                          &ls->link_info[ifidx].link);
	}

end_of_link_change_callback:
	cavium_atomic_set(&props->ls_flag, LINK_STATUS_FETCHED);
}
// *INDENT-ON*

/* Callback called by BASE driver when response arrives for a link status
   instruction sent by the NIC module init routine (inittime link status). */
void octnet_inittime_ls_callback(octeon_req_status_t status, void *buf)
{
	oct_link_status_resp_t *link_status;
	link_status = (oct_link_status_resp_t *) buf;
	if (link_status->status)
		cavium_error
		    ("OCTNIC: Link status instruction failed in callback. Status: %llx\n",
		     CVM_CAST64(link_status->status));

	link_status->s.cond = 1;
	cavium_wakeup(&link_status->s.wc);
}

int octnet_query_set_vf_mac(octeon_device_t *oct, uint8_t *mac_addr)
{
	int ret_val;

	if (OCTEON_CN9PLUS_VF(oct->chip_id)) {
		memset(mac_addr, 0, ETH_ALEN);
		ret_val = octnet_vf_mbox_get_mac_addr(oct, mac_addr);
		if (!ret_val) {
			if (!is_valid_ether_addr(mac_addr)) {
				eth_random_addr(mac_addr);
				cavium_print_msg("%s PF doesn't have VF MAC address\n",
						 __func__);
				cavium_print_msg("%sVF setting Random MAC address %pM\n",
						 __func__, mac_addr);
				ret_val = octnet_vf_mbox_set_mac_addr(oct, mac_addr);
				if (ret_val) {
					cavium_error("%s vf_mbox_set_mac_addr %pM fail\n",
							__func__, mac_addr);
					return -EADDRNOTAVAIL;
				}
			}
		} else {
			cavium_error("%s vf_mbox_get_mac_addr %pM fail ret_val: %d\n",
				      __func__, mac_addr, ret_val);
			return -EADDRNOTAVAIL;
		}
	}
	return 0;
}

/* Get the link status at init time. This routine sleeps till a response
   arrives from the core app. This is because the initialization cannot
   proceed till the host knows about the number of ethernet interfaces
   supported by the Octeon NIC target device. */
int octnet_get_inittime_link_status(void *oct, void *props_ptr)
{
	struct octdev_props_t *props;
	//octeon_soft_instruction_t *si;
	oct_link_status_resp_t *ls;
///	octeon_instr_status_t retval;
//	oct_stats_dma_info_t *dma_info;
	int q_no;
	int num_q = 0, i, j;
	uint8_t macaddr[ETH_ALEN];

	octeon_device_t *oct_dev = (octeon_device_t *) oct;
	props = (struct octdev_props_t *)props_ptr;

#if 0
	/* Use the link status soft instruction pre-allocated
	   for this octeon device. */
	si = props->si_link_status;
#endif

	/* Reset the link status buffer in props for this octeon device. */
	ls = props->ls;
	cavium_memset(ls, 0, OCT_LINK_STATUS_RESP_SIZE);

#if 0
	cavium_init_wait_channel(&ls->s.wc);
	si->rptr = &(ls->resp_hdr);
	si->irh.rlenssz = (OCT_LINK_STATUS_RESP_SIZE - sizeof(ls->s));
	si->status_word = (uint64_t *) & (ls->status);
	*(si->status_word) = COMPLETION_WORD_INIT;
	ls->s.cond = 0;
	ls->s.octeon_id = get_octeon_device_id(oct);
	SET_SOFT_INSTR_OCTEONID(si, ls->s.octeon_id);
	SET_SOFT_INSTR_CALLBACK(si, octnet_inittime_ls_callback);
	SET_SOFT_INSTR_CALLBACK_ARG(si, (void *)ls);

	//Allocate memory and populate the dma_info
	dma_info = cavium_alloc_buffer(oct_dev, sizeof(oct_stats_dma_info_t));
	cavium_memset(dma_info, 0, sizeof(oct_stats_dma_info_t));

	dma_info->pcieport = oct_dev->pcie_port;
	dma_info->status_len = si->irh.rlenssz;
	dma_info->status_addr =
	    (uint64_t) octeon_map_single_buffer(oct_dev->octeon_id,
						(void *)&ls->resp_hdr,
						si->irh.rlenssz,
						CAVIUM_PCI_DMA_FROMDEVICE);
	dma_info->stats_len = 0xadcd;
	dma_info->stats_addr = 0x123456789abcdeULL;
#endif

#if 0
	{
		int i = 0;
		uint64_t *tmp = (uint64_t *) dma_info;
		for (i = 0; i < 5; i++)
			printk("dma[%d]: 0x%016llx\n", i, *(tmp + i));
	}
#endif
#if 0

	si->dptr = dma_info;
	si->ih.dlengsz = sizeof(oct_stats_dma_info_t);
	si->ih.gather = 0;

	retval = octeon_process_instruction(oct, si, NULL);
	if (retval.s.error) {
		cavium_error
		    ("OCTNIC: Link status instruction failed status: %x\n",
		     retval.s.status);
		/* Soft instr is freed by driver in case of failure. */
		return EBUSY;
	}
	/* Sleep on a wait queue till the cond flag indicates that the
	   response arrived or timed-out. */
	cavium_sleep_timeout_cond(&ls->s.wc, (int *)&ls->s.cond, 1000);
#endif
        /* Currently DPI is not accessible from the DPDK based nic firmware,
	 *  So firmware cannot communicate the link status info to host driver,
	 *  hence hardcoding link_info details here in the host driver itself. */
	if (OCTEON_CN83XX_PF_OR_VF(oct_dev->chip_id))
		num_q = octnet_get_num_ioqs(oct_dev);
	else if (OCTEON_CN9PLUS_PF_OR_VF(oct_dev->chip_id))
		num_q = octnet_get_num_ioqs(oct_dev);

        ls->status = 0;
        ls->link_count = 1;
        ls->link_info[0].ifidx = 0;
        ls->link_info[0].gmxport = 2048;
        ls->link_info[0].hw_addr = (0x20f000b9849 + oct_dev->octeon_id);

	/* Query VF's MAC address from PF using mailbox command */
	if (OCTEON_CN9PLUS_VF(oct_dev->chip_id)) {
		if (octnet_query_set_vf_mac(oct_dev, macaddr)) {
			cavium_error("%s setting VF's Mac Address %pM fail\n",
				      __func__, macaddr);
			return -1;
		}
		for (i = 0, j = 5; i < 6; i++, j--)
			*((uint8_t *) (((uint8_t *) &ls->link_info[0].hw_addr) + j)) = macaddr[i];
	}

//        ls->link_info[0].hw_addr = 0x000FB71188BC;
        ls->link_info[0].num_rxpciq = num_q;
        ls->link_info[0].num_txpciq = num_q;
        ls->link_info[0].link.s.mtu = 10018;
        ls->link_info[0].link.s.status = 1;
        ls->link_info[0].link.s.speed = 10000;
        ls->link_info[0].link.s.duplex = 1;

        for(q_no = 0 ; q_no < num_q; q_no++) {
                ls->link_info[0].txpciq[q_no] = q_no;
                ls->link_info[0].rxpciq[q_no] = q_no;
        }
	return (ls->status);
}

oct_poll_fn_status_t
octnet_check_alive(void *oct, unsigned long props_ptr)
{
	struct octdev_props_t *props;
	oct_link_status_resp_t *ls;
	octeon_device_t *oct_dev = (octeon_device_t *) oct;

	props = (struct octdev_props_t *)props_ptr;
	ls = props->ls;

	if (!oct_dev->is_alive_flag) {
		oct_dev->heartbeat_miss_cnt++;
		if (oct_dev->heartbeat_miss_cnt <= keepalive_miss_limit)
			cavium_print_msg("OCTNIC[%d] - missed heartbeat: %d\n",
					 oct_dev->octeon_id,
					 oct_dev->heartbeat_miss_cnt);
	} else {
		if (ls->link_info[0].link.s.status == 0)
			cavium_print_msg("OCTNIC[%d] - setting link up, hearbeat found.\n",
					 oct_dev->octeon_id);
		ls->link_info[0].link.s.status = 1;
		netif_carrier_on(props->pndev[0]);
		octnet_txqueues_wake(props->pndev[0]);
		oct_dev->heartbeat_miss_cnt = 0;
	}

	if (!oct_dev->is_alive_flag
	    && oct_dev->heartbeat_miss_cnt >= keepalive_miss_limit
	    && ls->link_info[0].link.s.status) {
		cavium_print_msg("OCTNIC[%d] - setting link down down due to %d missed heartbeats.\n",
				 oct_dev->octeon_id, keepalive_miss_limit);
		ls->link_info[0].link.s.status = 0;
		netif_carrier_off(props->pndev[0]);
		octnet_stop_txqueue(props->pndev[0]);
	}

	/* reset the value. Interrupt will set this value again */
	oct_dev->is_alive_flag = 0;
	return OCT_POLL_FN_CONTINUE;
}

/* Get the link status at run time. This routine does not sleep waiting for
   a response. The link status is updated in a callback called when a response
   arrives from the core app. */

// *INDENT-OFF*
oct_poll_fn_status_t
octnet_get_runtime_link_status(void            *oct,
                               unsigned long    props_ptr)
{
	int                          ifidx;
	struct octdev_props_t       *props;
	oct_link_status_resp_t      *ls, *tmp_status;

	props = (struct octdev_props_t  *)props_ptr;
	ls    = props->ls;

	/* Don't do anything if the status is not 0. */
	if(ls->status) {
		return OCT_POLL_FN_CONTINUE;
	}

	cavium_print_msg("Go the link status update\n");
	/* Store the status and read it back.
	 * If there is a change in the status take the recent status */
	ls->status = COMPLETION_WORD_INIT;
	tmp_status = cavium_alloc_virt(sizeof(oct_link_status_resp_t));
        if (tmp_status == NULL) {
		cavium_error("%s: Unable to allocate memory \n", __FUNCTION__);
		return OCT_POLL_FN_CONTINUE;
	}

	cavium_memcpy(tmp_status, ls, sizeof(oct_link_status_resp_t));
	if(ls->status == COMPLETION_WORD_INIT)
   		cavium_memcpy(ls, tmp_status, sizeof(oct_link_status_resp_t));
	else
        	ls->status = COMPLETION_WORD_INIT;
	/* The link count should be swapped on little endian systems. */
	//octeon_swap_8B_data(&(ls->link_count), 1);
	if(ls->link_count > MAX_OCTEON_LINKS) {
		cavium_error("%s: Link count (%llu) exceeds max (%d)\n", __FUNCTION__,
		             ls->link_count, MAX_OCTEON_LINKS);
		cavium_free_virt(tmp_status);
		return OCT_POLL_FN_CONTINUE;
	}

	//for(ifidx = 0; ifidx < ls->link_count; ifidx++)
    //    octeon_swap_8B_data((uint64_t *)&ls->link_info[ifidx],((OCT_LINK_INFO_SIZE - (sizeof(ls->link_info[ifidx].txpciq) + sizeof(ls->link_info[ifidx].rxpciq)))) >> 3);

	for(ifidx = 0; ifidx < ls->link_count; ifidx++) {
		octnet_update_link_status(props->pndev[ifidx],
		                          &ls->link_info[ifidx].link);
	}
	cavium_free_virt(tmp_status);
	return OCT_POLL_FN_CONTINUE;
}
// *INDENT-ON*


/* Register droq_ops for each interface. By default all interfaces for a
   Octeon device uses the same Octeon output queue, but this can be easily
   changed by setting priv->rxq to the output queue you want to use. */
int octnet_setup_net_queues(int octeon_id, octnet_priv_t * priv)
{
	octeon_droq_ops_t droq_ops;

	memset(&droq_ops, 0, sizeof(octeon_droq_ops_t));

	droq_ops.poll_mode = 1;
	droq_ops.napi_fn = octnet_napi_drv_callback;
	cavium_print(PRINT_DEBUG,
		     "Setting droq ops for q %d poll_mode: %d napi_fn: %p drop: %d\n",
		     priv->rxq, droq_ops.poll_mode, droq_ops.napi_fn,
		     droq_ops.drop_on_max);


	return 0;
}

#if defined(OCTNIC_CTRL)
void octnet_send_rx_ctrl_cmd(octnet_priv_t * priv, int start_stop)
{
	octnic_ctrl_pkt_t nctrl;
	octnic_ctrl_params_t nparams;

	memset(&nctrl, 0, sizeof(octnic_ctrl_pkt_t));

	nctrl.ncmd.s.cmd = OCTNET_CMD_RX_CTL;
	nctrl.ncmd.s.param1 = priv->linfo.ifidx;
	nctrl.ncmd.s.param2 = start_stop;
	nctrl.netpndev = (unsigned long)priv->pndev;

	nparams.resp_order = OCTEON_RESP_NORESPONSE;
	if (octnet_send_nic_ctrl_pkt(priv->oct_dev, &nctrl, nparams) < 0) {
		cavium_error("OCTNIC: Failed to send RX Control message\n");
	}

	return;
}

#endif
/* Cleanup associated with each interface for an Octeon device  when NIC
   module is being unloaded or if initialization fails during load. */
void octnet_destroy_nic_device(int octeon_id, int ifidx)
{
	octnet_os_devptr_t *pndev = octprops[octeon_id]->pndev[ifidx];
	octnet_priv_t *priv;
	if (pndev == NULL) {
		cavium_error("OCTNIC: %s No netdevice ptr for index %d\n",
			     __CVM_FUNCTION__, ifidx);
		return;
	}

	priv = GET_NETDEV_PRIV(pndev);

#if defined(OCTNIC_CTRL)
	if (octeon_bar_access_valid(priv->oct_dev))
		octnet_send_rx_ctrl_cmd(priv, 0);
#endif
	if (cavium_atomic_read(&priv->ifstate) & OCT_NIC_IFSTATE_RUNNING)
		octnet_txqueues_stop(pndev);

	if (cavium_atomic_read(&priv->ifstate) & OCT_NIC_IFSTATE_REGISTERED)
		unregister_netdev(pndev);	/* corrupting link_info structure ???? */

	octnet_free_netdev(pndev);

	octprops[octeon_id]->pndev[ifidx] = NULL;
}

#if 0
static void octnet_setup_napi(octnet_priv_t * priv)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	netif_napi_add(priv->pndev, &priv->napi, octnet_napi_poll, 64);
#else
	priv->pndev->poll = octnet_napi_poll;
	priv->pndev->weight = 64;
	set_bit(__LINK_STATE_START, &priv->pndev->state);
#endif
}
#endif


/* mq support: queue selection support function for netdevice */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
static u16 octnet_select_queue(struct net_device *dev, struct sk_buff *skb,
			       struct net_device *sb_dev)
#elif defined(HAS_SELECT_QUEUE_FALLBACK) || (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 0))
static u16 octnet_select_queue(struct net_device *dev, struct sk_buff *skb,
				struct net_device *sb_dev,
				select_queue_fallback_t fallback)
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0))
static u16 octnet_select_queue(struct net_device *dev, struct sk_buff *skb,
			       void *accel_priv,
			       select_queue_fallback_t fallback)
#else
#error "No support for kernel version < 3.14"
#endif
{
	int qindex;
	octnet_priv_t *priv;

	priv = GET_NETDEV_PRIV(dev);
#ifdef OCTEON_SELECT_FLOW
	/* select queue on hash based scheme */
	qindex = skb_tx_hash(dev, skb);
#else
	/* select queue on chosen queue_mapping or core */
	qindex = skb_rx_queue_recorded(skb) ?
	    skb_get_rx_queue(skb) : smp_processor_id();
#endif /* OCTEON_SELECT_FLOW */
	return ((u16) (qindex % priv->linfo.num_txpciq));
}

#if  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static struct net_device_ops octnetdevops = {
	.ndo_open = octnet_open,
	.ndo_stop = octnet_stop,
	.ndo_start_xmit = octnet_xmit,
	.ndo_get_stats = octnet_stats,
	.ndo_set_mac_address = octnet_set_mac,
#if  LINUX_VERSION_CODE <= KERNEL_VERSION(3,1,10)
	.ndo_set_multicast_list = octnet_set_mcast_list,
#endif
	.ndo_set_rx_mode = octnet_set_mcast_list,
	.ndo_tx_timeout = octnet_tx_timeout,
	.ndo_change_mtu = octnet_change_mtu,

// VF Related
	.ndo_get_vf_config = octnet_get_vf_config,
	.ndo_set_vf_mac = octnet_set_vf_mac,
	.ndo_set_vf_vlan = octnet_set_vf_vlan,
	.ndo_set_vf_spoofchk = octnet_set_vf_spoofchk,
	.ndo_set_vf_trust = octnet_set_vf_trust,
	.ndo_set_vf_rate = octnet_set_vf_rate,
	.ndo_get_vf_config = octnet_get_vf_config,
	.ndo_set_vf_link_state = octnet_set_vf_link_state,
	.ndo_get_vf_stats = octnet_get_vf_stats,
};
#endif

void octnet_napi_enable(octnet_priv_t * priv);

void octnet_oei_irq_cb(octeon_device_t *oct)
{
	oct->is_alive_flag = 1;
}
/*
   Called during init time for each interface. This routine after the NIC
   module receives the link status information from core app at init time.
   The link information for each interface is passed in link_info.
*/
static int
octnet_setup_nic_device(int octeon_id, oct_link_info_t * link_info, int ifidx)
{
	octnet_priv_t *priv;
	octnet_os_devptr_t *pndev;
	uint8_t macaddr[ETH_ALEN], i, j;
	octeon_device_t *oct =
	    (octeon_device_t *) get_octeon_device_ptr(octeon_id);

	pndev = octnet_alloc_netdev(OCTNET_PRIV_SIZE, link_info->num_txpciq);

	if (!pndev) {
		cavium_error("OCTNIC: Device allocation failed\n");
		return -ENOMEM;
	}

	octprops[octeon_id]->pndev[ifidx] = pndev;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,18)
	if (link_info->num_txpciq > 1) {
		octnetdevops.ndo_select_queue = octnet_select_queue;	/* mq support: queue selection */
	}
#endif

	/* Associate the routines that will handle different netdev tasks. */
#if  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
	pndev->netdev_ops = &octnetdevops;
#else
	pndev->open = octnet_open;
	pndev->stop = octnet_stop;
	pndev->hard_start_xmit = octnet_xmit;
	pndev->get_stats = octnet_stats;
	pndev->set_mac_address = octnet_set_mac;
	pndev->set_multicast_list = octnet_set_mcast_list;
	pndev->tx_timeout = octnet_tx_timeout;
	pndev->change_mtu = octnet_change_mtu;
#endif
	/* kernel side SDP NIX VF interface supports 9182 only */
	pndev->max_mtu = 9182;
	pndev->mtu  = 1500;

	/* Register ethtool support to OCTNIC */
	oct_set_ethtool_ops(pndev);

	pndev->hw_features = NETIF_F_SG;
#if 0
	/* Notify the n/w stack regarding TSO capability feature */
	if (OCTEON_CN83XX_PF_OR_VF(oct->chip_id)) {
		pndev->features |= NETIF_F_TSO;
		pndev->features |= NETIF_F_GRO;
		netif_set_gso_max_size(pndev, OCTNIC_GSO_MAX_SIZE);
	}
#endif

	priv = GET_NETDEV_PRIV(pndev);
	cavium_memset(priv, 0, sizeof(octnet_priv_t));

	priv->ifidx = ifidx;
#ifdef OCT_NIC_LOOPBACK
	priv->priv_xmit = __octnet_xmit;
#endif

	/* Point to the  properties for octeon device to which this interface
	   belongs. */
	priv->oct_dev = oct;
	priv->octprops = octprops[octeon_id];
	priv->pndev = pndev;
	cavium_spin_lock_init(&(priv->lock));

#ifdef CONFIG_PPORT
	/* Assign base device init_name */
	snprintf(priv->init_name, 64, "%s%d",
		 OCTEON_NETDEV_DEV_NAME, octeon_id);
	pndev->dev.init_name = (const char *)&priv->init_name;
#endif

	/* Record the ethernet port number on the Octeon target for this
	   interface. */
	priv->linfo.gmxport = link_info->gmxport;
	/* Record the maximum mtu supported by this interface */
	priv->linfo.link.s.mtu = link_info->link.s.mtu;

	/* Record the pci port that the core app will send and receive packets
	   from host for this interface. */
	priv->linfo.ifidx = link_info->ifidx;
	priv->linfo.hw_addr = link_info->hw_addr;
	priv->linfo.num_rxpciq = link_info->num_rxpciq;
	priv->linfo.num_txpciq = link_info->num_txpciq;

	for (j = 0; j < MAX_IOQS_PER_NICIF; j++) {
		priv->linfo.txpciq[j] = link_info->txpciq[j];
		priv->linfo.rxpciq[j] = link_info->rxpciq[j];
	}

	cavium_print(PRINT_DEBUG, "OCTNIC: if%d gmx: %d hw_addr: 0x%llx\n",
		     ifidx, priv->linfo.gmxport,
		     CVM_CAST64(priv->linfo.hw_addr));

	/* 64-bit swap required on LE machines */
	//octeon_swap_8B_data(&priv->linfo.hw_addr, 1);
	for (i = 0, j = 5; i < 6; i++, j--)
		macaddr[i] =
		    *((uint8_t *) (((uint8_t *) & priv->linfo.hw_addr) +
				   j));

	/* Copy MAC Address to OS network device structure */
	cavium_memcpy(pndev->dev_addr, macaddr, ETH_ALEN);

	priv->linfo.link.u64 = link_info->link.u64;

	priv->tx_qsize = octeon_get_tx_qsize(octeon_id, priv->txq);
	priv->rx_qsize = octeon_get_rx_qsize(octeon_id, priv->rxq);

	OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_DROQ_OPS);

	pndev->features |= pndev->hw_features;

	/*
	 * Only advertise offload features if we can support them by
	 * communicating with the Otx2 using packet headers.
	 * Loop mode does not have these headers, and so cannot
	 * support the offload features.
	 */
	if (oct->pkind == OTX2_GENERIC_PCIE_EP_PKIND)
		pndev->features |= NETIF_F_HW_CSUM;

	pndev->watchdog_timeo = TXTIMEOUT;
	SET_NETDEV_DEV(pndev, &oct->pci_dev->dev);
	/* Register the network device with the OS */
	if (register_netdev(pndev)) {
		cavium_error("OCTNIC: Device registration failed\n");
		goto setup_nic_dev_fail;
	}
#ifdef CONFIG_PPORT
	/* Re-Assign base device init_name modified by register_netdev */
	snprintf(priv->init_name, 64, "%s%d",
		 OCTEON_NETDEV_DEV_NAME, octeon_id);
	pndev->dev.init_name = (const char *)priv->init_name;
#endif
	netif_carrier_off(pndev);

	if (priv->linfo.link.s.status) {
		netif_carrier_on(pndev);
		octnet_start_txqueue(pndev);
	} else {
		netif_carrier_off(pndev);
	}

	/* Register the fast path function pointers after the network device
	   related activities are completed. We should be ready for Rx at this
	   point. */
	/* By default all interfaces on a single Octeon uses the same tx and rx
	   queues */
	priv->txq = priv->linfo.txpciq[0];
	priv->rxq = priv->linfo.rxpciq[0];


	OCTNET_IFSTATE_SET(priv, OCT_NIC_IFSTATE_REGISTERED);

#ifdef OCTNIC_CTRL
	/* Define OCTNIC_CTRL if octeon supports NIC control commands */
	octnet_send_rx_ctrl_cmd(priv, 1);
#endif

	octnet_print_link_info(pndev);
	oct->oei_irq_handler = octnet_oei_irq_cb;

	return 0;

setup_nic_dev_fail:
	octnet_destroy_nic_device(octeon_id, ifidx);
	return -ENODEV;

}

octeon_config_t *octeon_dev_conf(octeon_device_t * oct)
{
	uint16_t chip_id = oct->chip_id;

	switch (chip_id) {
	case OCTEON_CN83XX_ID_PF:
		return ((octeon_cn83xx_pf_t *) (oct->chip))->conf;

	case OCTEON_CN83XX_ID_VF:
		return ((octeon_cn83xx_vf_t *) (oct->chip))->conf;
	case OCTEON_CN93XX_ID_PF:
	case OCTEON_CN98XX_ID_PF:
		return ((octeon_cn93xx_pf_t *) (oct->chip))->conf;
	case OCTEON_CN93XX_ID_VF:
	case OCTEON_CN98XX_ID_VF:
		return ((octeon_cn93xx_vf_t *) (oct->chip))->conf;

	case OCTEON_CN10KA_ID_PF:
		return ((octeon_cnxk_pf_t *) (oct->chip))->conf;
	case OCTEON_CN10KA_ID_VF:
		return ((octeon_cnxk_vf_t *) (oct->chip))->conf;
	/* VSR: TODO: add for CNXK VF too */
	default:
		cavium_error("OCTEON: Unknown device found (chip_id: %x)\n",
			     chip_id);

	}
	return NULL;
}

/* Returns the number of interfaces octeon has */
static inline uint32_t octnet_get_num_intf(octeon_device_t * octeon_dev)
{

	octeon_config_t *conf = octeon_dev_conf(octeon_dev);
	if (conf == NULL)
		return 0;
	else
		return (CFG_GET_NUM_INTF(conf));
}

/* Returns the numbers of ioqs used by each interface */
static inline uint32_t octnet_get_num_ioqs(octeon_device_t * octeon_dev)
{

	uint32_t num_ioqs = 0, vf_rings = 0;
	octeon_config_t *conf = octeon_dev_conf(octeon_dev);
	if (conf == NULL)
		return 0;

	if (OCTEON_CN8PLUS_PF(octeon_dev->chip_id)) {
		num_ioqs = octeon_dev->sriov_info.rings_per_pf;
		vf_rings = octeon_dev->sriov_info.rings_per_vf;

		if (num_ioqs > MAX_IOQS_PER_NICIF)
			num_ioqs = MAX_IOQS_PER_NICIF;

		octeon_dev->sriov_info.rings_per_pf = num_ioqs;

	} else if (OCTEON_CN83XX_VF(octeon_dev->chip_id)) {

		num_ioqs = octeon_dev->rings_per_vf;

	} else if (OCTEON_CN9PLUS_VF(octeon_dev->chip_id)) {

		num_ioqs = octeon_dev->rings_per_vf;

	} else {

		num_ioqs = CFG_GET_PORTS_NUM_IOQ(conf);
	}

	return num_ioqs;
}

/* Returns the starting queue number used by the interface */
static inline
    uint32_t octnet_get_intf_baseq(octeon_device_t * octeon_dev, uint32_t ifidx)
{

	uint32_t srn = 0, num_ioqs = 0;
	octeon_config_t *conf = octeon_dev_conf(octeon_dev);
	if (conf == NULL)
		return 0;

	srn = CFG_GET_PORTS_SRN(conf);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);

	return (srn + ifidx * num_ioqs);
}

int octnet_destroy_io_queues(octeon_device_t * octeon_dev,
			     oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0;

	num_intf = octnet_get_num_intf(octeon_dev);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);

	octeon_cleanup_iq_intr_moderation(octeon_dev);
	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		/* delete  DROQs. */
		for (index = 0; index < num_ioqs; index++) {
			if (octeon_dev->droq[baseq + index]) {
				octeon_delete_droq(octeon_dev, (baseq + index));
				octeon_dev->num_oqs--;
			}
			cavium_print(PRINT_DEBUG,
			     "deleting droq in index: %d with qno: %d, remaining queues: %d\n",
			     index, (baseq + index), octeon_dev->num_oqs);
		}

		/* delete input queues. */
		for (index = 0; index < num_ioqs; index++) {
			if (octeon_dev->instr_queue[baseq + index]) {
				octeon_delete_instr_queue(octeon_dev,
							  (baseq + index));
				octeon_dev->num_iqs--;
			}
			cavium_print(PRINT_DEBUG,
			     "deleting iq in index: %d with qno: %d, remaining queeus: %d\n",
			     index, (baseq + index), octeon_dev->num_iqs);
		}

	}

	return 0;
}

/* This routine enable the IOQs for octnic module*/
int octnet_enable_io_queues(octeon_device_t * oct, oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0;

	num_intf = octnet_get_num_intf(oct);
	num_ioqs = octnet_get_num_ioqs(oct);

	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(oct, ifidx);
		/* enable IQs. */
		for (index = 0; index < num_ioqs; index++) {
			oct->fn_list.enable_input_queue(oct, (baseq + index));
		}

		/* enable DROQs after enabling IQs as enable_input_queue() checks and releases ioq reset. */
		for (index = 0; index < num_ioqs; index++) {
			oct->fn_list.enable_output_queue(oct, (baseq + index));
		}
	}
	return 0;
}

/** This routine disable the IOQs for octnic module **/
int octnet_disable_io_queues(octeon_device_t * oct, oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0;

	num_intf = octnet_get_num_intf(oct);
	num_ioqs = octnet_get_num_ioqs(oct);

	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(oct, ifidx);
		/* disable IQs. */
		for (index = 0; index < num_ioqs; index++) {
			oct->fn_list.disable_input_queue(oct, (baseq + index));
		}

		/* disable DROQs. */
		for (index = 0; index < num_ioqs; index++) {
			oct->fn_list.disable_output_queue(oct, (baseq + index));
		}
	}

	return 0;
}

extern void octeon_reset_ioq(octeon_device_t * octeon_dev, int ioq);

/** This routine sets up the IOQs for octnic module
 *
 */
int
octnet_setup_io_queues(octeon_device_t * octeon_dev,
		       oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0, failed_iq_if = 0, failed_oq_if = 0;
	int retval = 0;

	num_intf = octnet_get_num_intf(octeon_dev);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);

	if (octeon_dev->sriov_info.rings_per_pf > num_ioqs)
		octeon_dev->sriov_info.rings_per_pf = num_ioqs;

	cavium_print_msg("OCTEON: setup ioqs: num_intf: %d, num_ioqs: %d\n",
			 num_intf, num_ioqs);

	/* set up IQs. */
	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		for (index = 0; index < num_ioqs; index++) {
			if (OCTEON_CN8PLUS_PF_OR_VF(octeon_dev->chip_id)) {
				/* check and release ioq reset before setting up the ioqs */
				octeon_reset_ioq(octeon_dev, (baseq + index));
			}

			retval =
			    octeon_setup_iq(octeon_dev, (baseq + index), NULL);
			if (retval) {
				int counter = (int)index;
				for (; counter >= 0; counter--) {
					octeon_delete_instr_queue(octeon_dev,
								  (baseq +
								   index));
					octeon_dev->num_iqs--;
				}

				cavium_print_msg
				    (" %s : Runtime IQ(TxQ) creation failed.\n",
				     __FUNCTION__);
				failed_iq_if = ifidx;
				goto iq_fail;
			}
		}
	}
#if 0
	/* Disabled, conflicts with ISM, not needed with NAPI support */
	octeon_init_iq_intr_moderation(octeon_dev);
#endif
	cavium_atomic_set(&octeon_dev->status, OCT_DEV_INSTR_QUEUE_INIT_DONE);

	/* set up DROQs. */
	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		for (index = 0; index < num_ioqs; index++) {

			retval =
			    octeon_setup_droq(octeon_dev->octeon_id,
					      (baseq + index), NULL);
			if (retval) {
				int counter = (int)index;
				for (; counter >= 0; counter--) {
					octeon_delete_droq(octeon_dev,
							   (baseq + counter));
					octeon_dev->num_oqs--;
				}

				cavium_print_msg
				    (" %s : Runtime DROQ(RxQ) creation failed.\n",
				     __FUNCTION__);
				failed_oq_if = ifidx;
				failed_iq_if = num_intf;
				goto oq_fail;
			}
		}
	}
	cavium_atomic_set(&octeon_dev->status, OCT_DEV_DROQ_INIT_DONE);

	return 0;

oq_fail:
	/* Destroy created DROQs. */
	for (ifidx = 0; ifidx < failed_oq_if; ifidx--) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);
		{
			octeon_delete_droq(octeon_dev, (baseq + index));
			octeon_dev->num_oqs--;
		}

	}

iq_fail:
	/* Destroy created IQs. */
	for (ifidx = 0; ifidx < failed_iq_if; ifidx--) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);
		{
			octeon_delete_instr_queue(octeon_dev, (baseq + index));
			octeon_dev->num_iqs--;
		}
	}
	return -1;
}

/* This routine is registered by the NIC module with the BASE driver. The BASE
   driver calls this routine for each Octeon device that runs the NIC core
   application. */
int octnet_init_nic_module(int octeon_id, void *octeon_dev)
{
	oct_link_status_resp_t *ls = NULL;
	octeon_soft_instruction_t *si = NULL;
	int ifidx, retval = 0;
	int prev_status;
	octeon_device_t *oct = (octeon_device_t *) octeon_dev;
	octeon_poll_ops_t poll_ops;
	int i, j;

	octeon_droq_t *droq;
	octeon_config_t *conf;
	conf = octeon_dev_conf(octeon_dev);

	prev_status = cavium_atomic_read(&oct->status);
	if (prev_status != OCT_DEV_CORE_OK) {
		cavium_print_msg
		    ("OCTNIC: OCTEON[%d] is in state: %d. core is not booted yet.\n",
		     octeon_id, cavium_atomic_read(&oct->status));
		return -1;
	}

	cavium_print_msg
	    ("OCTNIC: Initializing network interfaces for Octeon %d\n",
	     octeon_id);

	/* Allocate the local NIC properties structure for this octeon device. */
	octprops[octeon_id] = cavium_alloc_virt(sizeof(struct octdev_props_t));
	if (octprops[octeon_id] == NULL) {
		cavium_error("OCTNIC: Alloc failed at %s:%d\n",
			     __CVM_FUNCTION__, __CVM_LINE__);
		return -ENOMEM;
	}
	cavium_memset(octprops[octeon_id], 0, sizeof(struct octdev_props_t));

	/* Allocate a buffer to collect link status from the core app. */
	ls = cavium_malloc_dma(sizeof(oct_link_status_resp_t),
			       __CAVIUM_MEM_GENERAL);
	if (ls == NULL) {
		cavium_error("OCTNIC: Alloc failed at %s:%d\n",
			     __CVM_FUNCTION__, __CVM_LINE__);
		cavium_free_virt(octprops[octeon_id]);
		octprops[octeon_id] = NULL;
		return -ENOMEM;
	}

	octprops[octeon_id]->ls = ls;

	/* Allocate a soft instruction to be used to send link status requests
	   to the core app. */
	si = (octeon_soft_instruction_t *)
	    cavium_alloc_buffer(octeon_dev, OCT_SOFT_INSTR_SIZE);
	if (si == NULL) {
		cavium_error
		    ("OCTNIC: soft instr allocation failed in net setup\n");
		cavium_free_dma(ls);
		cavium_free_virt(octprops[octeon_id]);
		octprops[octeon_id] = NULL;
		return ENOMEM;
	}

	octprops[octeon_id]->si_link_status = si;

	octnet_prepare_ls_soft_instr(octeon_dev, si);

	/* set up the IOQs for each OCTEON link */
	retval = octnet_setup_io_queues(octeon_dev, ls);
	if (retval)
		goto octnet_ioq_failure;

    cavium_print_msg("IO queue creation success\n");
	if (oct->drv_flags & OCTEON_MSIX_CAPABLE) {
		if (OCTEON_CN83XX_PF(oct->chip_id))
			CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cn83xx_pf, conf))
			    = oct->sriov_info.rings_per_pf;
		else if (OCTEON_CN9XXX_PF(oct->chip_id))
			CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cn93xx_pf, conf))
			    = oct->sriov_info.rings_per_pf;
		else if (OCTEON_CNXK_PF(oct->chip_id))
			CFG_GET_OQ_MAX_BASE_Q(CHIP_FIELD(oct, cnxk_pf, conf))
			    = oct->sriov_info.rings_per_pf;

		if (octeon_allocate_ioq_vector(oct)) {
			cavium_error("OCTEON: ioq vector allocation failed\n");
			goto octnet_msix_failure;
		}
	}

	/* Enable Octeon device interrupts */
	oct->fn_list.enable_interrupt(oct->chip, OCTEON_ALL_INTR);

	octnet_enable_io_queues(octeon_dev, ls);

	if (OCTEON_CN8PLUS_PF_OR_VF(oct->chip_id)) {
		/* dbell needs to be programmed after enabling OQ. */
		for (j = 0; j < oct->num_oqs; j++) {
			OCTEON_WRITE32(oct->droq[j]->pkts_credit_reg,
				       oct->droq[j]->max_count);
		}
	}

	cavium_atomic_set(&oct->status, OCT_DEV_RUNNING);

	/* Send an instruction to get the link status information from core. */
	retval =
	    octnet_get_inittime_link_status(octeon_dev, octprops[octeon_id]);
	if (retval) {
		cavium_error("OCTNIC: Link initialization failed\n");
		goto octnet_init_failure;
	}

	ls->status = COMPLETION_WORD_INIT;

	for(ifidx = 0; ifidx < ls->link_count; ifidx++) {
		cavium_print_msg("OCTNIC: if%d rxq: %2d to %2d txq: %2d to %2d gmx: %d max_mtu:%d hw_addr: 0x%llx\n",
	             ifidx, ls->link_info[ifidx].rxpciq[0], ls->link_info[ifidx].rxpciq[0] + ls->link_info[ifidx].num_rxpciq -1,
				 ls->link_info[ifidx].txpciq[0], ls->link_info[ifidx].txpciq[0] +  ls->link_info[ifidx].num_txpciq -1,
				 ls->link_info[ifidx].gmxport, ls->link_info[ifidx].link.s.mtu, CVM_CAST64(ls->link_info[ifidx].hw_addr));
	}

#if 0
	{
		int i = 0;
		for (i = 0; i < ls->link_info[0].num_txpciq; i++)
			printk("TEST- txpciq[%d]: %d, rxpciq[%d]: %d\n", i,
			       ls->link_info[0].txpciq[i], i,
			       ls->link_info[0].rxpciq[i]);
		printk(" IOQ-IDX : %d \n", ls->link_info[0].ioqidx);

	}
#endif

	octprops[octeon_id]->ifcount = ls->link_count;

	octeon_register_noresp_buf_free_fn(octeon_id, NORESP_BUFTYPE_NET,
					   octnic_free_netbuf);

	octeon_register_noresp_buf_free_fn(octeon_id, NORESP_BUFTYPE_NET_SG,
					   octnic_free_netsgbuf);

	/* For each ethernet port on the Octeon target, setup a NIC interface on
	   the host. */
	for (ifidx = 0; ifidx < ls->link_count; ifidx++) {
		retval =
		    octnet_setup_nic_device(octeon_id, &ls->link_info[ifidx],
					    ifidx);
		if (retval) {
			/* Fix error handling 
			   ifidx should point at the nic device that has failed
			   to setup therfore the first nic to destory is the 
			   one before it, thus we predecrement (--ifidx).  At 
			   the end, we enter the loop as (1), but we 
			   destory (0) */
			while (ifidx) {
				octnet_destroy_nic_device(octeon_id, --ifidx);
				goto octnet_init_failure;
			}
		}
		/* assign droq's to netdev's
		 * link_count = 1: all DROQs assigned to the same link
		 * link_count > 1: 1 DROQ per link
		 */
		if (ls->link_count == 1)
			octeon_droq_set_netdev(oct, 0,
					octnet_get_num_ioqs(oct),
					octprops[octeon_id]->pndev[ifidx]);
		else
			octeon_droq_set_netdev(oct, ifidx, 1,
					octprops[octeon_id]->pndev[ifidx]);
	}

	/* Loop through for the number of interfaces gets created */
	for (i = 0; i < ls->link_count; i++) {	/* setup rxQs: TCP_RR/STREAM perf. */
		octeon_droq_ops_t droq_ops;
		struct net_device *netdev = octprops[octeon_id]->pndev[i];

		memset(&droq_ops, 0, sizeof(octeon_droq_ops_t));
		droq_ops.poll_mode = 1;
		droq_ops.napi_fun = octnet_napi_callback;
		/* Register the droq ops structure so that we can start handling packets
		 * received on the Octeon interfaces. */
		/* Sending the droq number of the interface */
		for (j = 0; j < ls->link_info[i].num_rxpciq; j++) {
			int q_no = ls->link_info[i].rxpciq[j];
			droq = oct->droq[q_no];
			/* NIC mode performance tuning: increased the budget from 64 to 96 */
			netif_napi_add(netdev, &droq->napi, octnet_napi_poll_fn,
				       96);

            cavium_print(PRINT_DEBUG,
            "%s using NAPI : oct_id:%d ifidx:%d droq->q_no:%d q_no:%d\n",
			       __func__, octeon_id, i, droq->q_no, q_no);

			napi_enable(&droq->napi);
			if (octeon_register_droq_ops
			    (octeon_id, ls->link_info[i].rxpciq[j],
			     &droq_ops)) {
				cavium_error
				    ("OCTNIC: Failed to register DROQ function\n");
				return -ENODEV;
			}
		}

	}
	/* Enable MSI-X interrupts only after droq_ops.napi_fun is set up. */
	if (oct->drv_flags & OCTEON_MSIX_CAPABLE) {
		if (octeon_enable_msix_interrupts(oct)) {
			octeon_delete_ioq_vector(oct);
			cavium_error("OCTEON: setup msix interrupt failed\n");
			retval = -ENODEV;
			for (i = 0; i < ls->link_count; i++) {
				octnet_destroy_nic_device(octeon_id, i);
			}
			goto octnet_init_failure;
		}
		octeon_setup_irq_affinity(octeon_dev);
	}

	cavium_atomic_set(&octprops[octeon_id]->ls_flag, LINK_STATUS_FETCHED);
	octprops[octeon_id]->last_check = cavium_jiffies;
#if !defined(OCTEON_VF)
	/* Register a poll function to run every second to collect and update
	   link status. */
	{
		poll_ops.fn = octnet_get_runtime_link_status;
		poll_ops.fn_arg = (unsigned long)octprops[octeon_id];
		poll_ops.ticks = OCTNET_LINK_QUERY_INTERVAL;
		strcpy(poll_ops.name, "NIC Link Status");
		octeon_register_poll_fn(octeon_id, &poll_ops);
	}
#endif
	/* register a poll fn to check if octeon is alive */
	poll_ops.fn = octnet_check_alive;
	poll_ops.fn_arg = (unsigned long)octprops[octeon_id];
	poll_ops.ticks = msecs_to_jiffies(keepalive_period_ms);
	strcpy(poll_ops.name, "Octeon Alive Status");
	octeon_register_poll_fn(octeon_id, &poll_ops);


	cavium_print_msg("OCTNIC: Network interfaces ready for Octeon %d\n",
			 octeon_id);

	return retval;

octnet_init_failure:
	cavium_error("OCTNIC: Initialization Failed\n");

#if 0 //this is not processed by NPU
	if (OCTEON_CN8PLUS_PF_OR_VF(oct->chip_id)) {
		/* Send short command to firmware to free these interface's PCAM entry */
		octeon_send_short_command(oct, HOST_NW_STOP_OP, 0, NULL, 0);
	}
#endif

	cavium_atomic_set(&oct->status, prev_status);
	cavium_print_msg("resetting the state to prev_status: %d\n", prev_status);
	octnet_disable_io_queues(oct, ls);

	oct->fn_list.disable_interrupt(oct->chip, OCTEON_ALL_INTR);

	/* Clean up ioq_vector structures. */
	if (oct->drv_flags & OCTEON_MSIX_CAPABLE) {
		octeon_clear_irq_affinity(oct);
		octeon_disable_msix_interrupts(oct);
		octeon_delete_ioq_vector(oct);
	}

octnet_msix_failure:
	octnet_destroy_io_queues(oct, ls);

octnet_ioq_failure:
	if (si)
		cavium_free_buffer(octeon_dev, si);
	if (ls)
		cavium_free_dma(ls);
	cavium_free_virt(octprops[octeon_id]);
	octprops[octeon_id] = NULL;

	return retval;
}

/* This routine checks for the pending entries of each IQ which is used by NIC interface. */
int octnet_wait_for_pending_requests(octeon_device_t * octeon_dev,
				     oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0;
	int ret_val = 0;

	num_intf = octnet_get_num_intf(octeon_dev);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);

	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		/* Ckeck for pending req in IQs. */
		for (index = 0; index < num_ioqs; index++) {
			if (wait_for_pending_requests
			    (octeon_dev, (baseq + index))) {
				cavium_error
				    ("OCTEON[%d]: There were pending requests in IQ:%d\n",
				     octeon_dev->octeon_id, (baseq + index));
				ret_val = 1;
			}
		}
	}

	return ret_val;
}

/*
 * This routine checks for the pending req in IQs, and is only called when
 * stopping the NIC module.
 */
int octnet_wait_for_instr_fetch(octeon_device_t * octeon_dev,
				oct_link_status_resp_t * ls)
{
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	uint32_t index = 0;
	int ret_val = 0;

	num_intf = octnet_get_num_intf(octeon_dev);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);

	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		/* Ckeck for pending req in IQs. */
		for (index = 0; index < num_ioqs; index++) {
			if (wait_for_iq_instr_fetch
			    (octeon_dev, (baseq + index))) {
				cavium_error
				    ("OCTEON[%d]: There were instructions in IQ:%d\n",
				     octeon_dev->octeon_id, (baseq + index));
				ret_val = 1;
			}
		}
	}

	return ret_val;
}

/* This routine is registered by the NIC module with the BASE driver. The BASE
   driver calls this routine before stopping each Octeon device that runs
   the NIC core application. */
int octnet_stop_nic_module(int octeon_id, void *oct)
{
	int i, j;
	oct_link_status_resp_t *ls_resp;
	octeon_device_t *octeon_dev = (octeon_device_t *) oct;
	octeon_config_t *conf;
	uint32_t ifidx = 0, num_intf = 0, num_ioqs = 0, baseq = 0;
	octeon_droq_t *droq;

	cavium_print_msg
	    ("OCTNIC: Stopping network interfaces for Octeon device %d\n",
	     octeon_id);

	if (octprops[octeon_id] == NULL) {
		cavium_error("OCTNIC: Init for Octeon%d was not completed\n",
			     octeon_id);
		return 1;
	}
	ls_resp = cavium_alloc_virt(sizeof(oct_link_status_resp_t));
	if (ls_resp == NULL) {
		cavium_error("OCTNIC: Unable to allocate memory, Octeon device %d\n",
			     octeon_id);
		return 1;
	}
	octeon_unregister_poll_fn(octeon_id, octnet_get_runtime_link_status,
				  (unsigned long)octprops[octeon_id]);

	cavium_memset(ls_resp, 0, OCT_LINK_STATUS_RESP_SIZE);
	conf = octeon_dev_conf(octeon_dev);

	num_intf = octnet_get_num_intf(octeon_dev);
	num_ioqs = octnet_get_num_ioqs(octeon_dev);


	/*
	 * Must do this before unregistering DROQ ops, as those
	 * delete the NAPI functions called by MSIX interrupt
	 * handlers.
	 */
	if (octeon_dev->msix_on) {
		octeon_clear_irq_affinity(octeon_dev);
		octeon_disable_msix_interrupts(octeon_dev);
		octeon_delete_ioq_vector(octeon_dev);
	}

#if 0 //this is not processed by NPU
	if (OCTEON_CN8PLUS_PF_OR_VF(octeon_dev->chip_id)) {
		/* Send short command to firmware to free these interface's PCAM entry */
		octeon_send_short_command(oct, HOST_NW_STOP_OP, 0, NULL, 0);
	}
#endif
	for (ifidx = 0; ifidx < num_intf; ifidx++) {
		baseq = octnet_get_intf_baseq(octeon_dev, ifidx);

		for (j = 0; j < num_ioqs; j++) {

			int q_no = (baseq + j);
			droq = octeon_dev->droq[q_no];
			/* Disable napi on this droq */
			napi_disable(&droq->napi);

			/* Delete napi context from this droq and interface */
			netif_napi_del(&droq->napi);

            cavium_print(PRINT_DEBUG,
            "Disabled and deleted napi context from droq:%d q_no:%d\n",
			     droq->q_no, q_no);
			octeon_unregister_droq_ops(octeon_id, (baseq + j));
		}
	}

	octeon_unregister_poll_fn(octeon_id, octnet_check_alive,
				  (unsigned long)octprops[octeon_id]);
	//cavium_atomic_set(&octeon_dev->status, OCT_DEV_CORE_OK);
	//ls = NULL;

	for (i = 0; i < octprops[octeon_id]->ifcount; i++) {
		octnet_destroy_nic_device(octeon_id, i);
	}

	cavium_atomic_set(&octeon_dev->status, OCT_DEV_CORE_OK);

	cavium_print(PRINT_DEBUG, "wait for pending instructions\n");

	if (octnet_wait_for_pending_requests(octeon_dev, ls_resp)) {
		cavium_error("OCTEON[%d]: NIC has pending requests.\n",
			     octeon_dev->octeon_id);
	}

	cavium_print(PRINT_DEBUG, "wait for instr fetch\n");
	if (octnet_wait_for_instr_fetch(octeon_dev, ls_resp)) {
		cavium_error("OCTEON[%d]: IQ had pending instructions\n",
			     octeon_dev->octeon_id);
	}

	cavium_print(PRINT_DEBUG, "waited for all ioqs. disabling the ioq queues\n");
	/* disable NIC IOQs */
	octnet_disable_io_queues(octeon_dev, ls_resp);
#if 0
	printk("disabled the io queues. destroying the io queues\n");
	/* Clean up the NIC IOQs. */
	octnet_destroy_io_queues(octeon_dev, &ls_resp);
#endif


	cavium_print(PRINT_DEBUG, "disabled the io queues. destroying the io queues\n");
	/* Clean up the NIC IOQs. */
	octnet_destroy_io_queues(octeon_dev, ls_resp);

	/* Free the link status buffer allocated for this Octeon device. */
	if (octprops[octeon_id]->ls) {
		cavium_free_dma(octprops[octeon_id]->ls);
	}

	/* Free the soft instruction buffer used for sending the link status to the core app. */
	if (octprops[octeon_id]->si_link_status) {
		cavium_free_buffer(octeon_dev,
				   octprops[octeon_id]->si_link_status);
	}

	/* Free the props structures for this octeon device. */
	cavium_free_virt(octprops[octeon_id]);

	octprops[octeon_id] = NULL;

	cavium_free_virt(ls_resp);
	cavium_print_msg("OCTNIC: Network interfaces stopped for Octeon %d\n",
			 octeon_id);
	return 0;
}

/* This routine is registered by the NIC module with the BASE driver. The BASE
   driver calls this routine before performing hot-reset for each Octeon device
   that runs the NIC core application. */
int octnet_reset_nic_module(int octeon_id, void *octeon_dev)
{
	if (CVM_MOD_IN_USE)
		return 1;
	return octnet_stop_nic_module(octeon_id, octeon_dev);
}

extern int octeon_base_init_module(void);
extern void octeon_base_exit_module(void);

int init_module()
{
	const char *nic_cvs_tag = CNNIC_VERSION;
	char nic_version[sizeof(CNNIC_VERSION) + 100];
	char copts[160];
	octeon_module_handler_t nethandler;

	cavium_print_msg("OCTNIC: Starting Network module for Octeon\n");
	cavium_parse_cvs_string(nic_cvs_tag, nic_version, sizeof(nic_version));
	cavium_print_msg("Version: %s\n", nic_version);

	copts[0] = '\0';
	get_nic_compile_options(copts);
	if (strlen(copts))
		cavium_print_msg("OCTNIC: Driver compile options: %s\n", copts);
	else
		cavium_print_msg("OCTNIC: Driver compile options: NONE\n");

	cavium_memset(octprops, 0, sizeof(void *) * MAX_OCTEON_DEVICES);

#if defined(OCTEON_EXCLUDE_BASE_LOAD)
	if (octeon_base_init_module()) {
		cavium_error("OCTNIC: Octeon initialization failed\n");
		return -EINVAL;
	}
#endif

	/* Register handlers with the BASE driver. For each octeon device that
	   runs the NIC core app, the BASE driver would call the functions
	   below for initialization, reset and shutdown operations. */
	nethandler.startptr = octnet_init_nic_module;
	nethandler.resetptr = octnet_reset_nic_module;
	nethandler.stopptr = octnet_stop_nic_module;
	nethandler.app_type = CVM_DRV_NIC_APP;
	if (octeon_register_module_handler(&nethandler))
		return -EINVAL;

	cavium_print_msg("OCTNIC: Network module loaded for Octeon\n");
	return 0;
}

void cleanup_module()
{
	cavium_print_msg("OCTNIC: Stopping Octeon Network module\n");
	octeon_unregister_module_handler(CVM_DRV_NIC_APP);
#if defined(OCTEON_EXCLUDE_BASE_LOAD)
	octeon_base_exit_module();
#endif
	cavium_print_msg("OCTNIC: Octeon Network module is now unloaded\n");
}

/* $Id: octeon_netmain.c 170606 2018-03-20 15:42:45Z vvelumuri $ */
