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

#include "octeon_main.h"
#include "octeon_debug.h"
#include "octeon_macros.h"
#include "octeon_hw.h"

//#define PERF_MODE

uint32_t octeon_droq_refill(octeon_device_t * octeon_dev, octeon_droq_t * droq);

oct_poll_fn_status_t check_droq_refill(void *octptr, unsigned long q_no);

#ifdef  USE_DROQ_THREADS
static int oct_droq_thread(void *arg);
#endif

struct niclist {
	cavium_list_t list;
	void *ptr;
};

struct __dispatch {
	cavium_list_t list;
	octeon_recv_info_t *rinfo;
	octeon_dispatch_fn_t disp_fn;
};

int octeon_droq_check_hw_for_pkts(octeon_device_t * oct, octeon_droq_t * droq)
{
	int pkt_count = 0;

	pkt_count = OCTEON_READ32(droq->pkts_sent_reg);
	/*printk("%s: pkt_count(sent_reg):%d pkts_pending:%d\n",
	   __func__, pkt_count, cavium_atomic_read(&droq->pkts_pending)); */
	if (pkt_count) {
		cavium_atomic_add(pkt_count, &droq->pkts_pending);
		if (!oct->msix_on) {
			OCTEON_WRITE32(droq->pkts_sent_reg, pkt_count);
		}
#ifdef OCT_NIC_USE_NAPI
		else
			OCTEON_WRITE32(droq->pkts_sent_reg, pkt_count);
#endif
	}

	return pkt_count;
}

void oct_dump_droq_state(octeon_droq_t * oq)
{

	cavium_print_msg("DROQ[%d] state dump\n", oq->q_no);
	cavium_print_msg("Attr: Size: %u Pkts/intr: %u  refillafter: %u\n",
			 oq->max_count, oq->pkts_per_intr,
			 oq->refill_threshold);
	cavium_print_msg
	    ("Attr: fastpath: %s poll_mode: %s drop_on_max: %s fptr: %p napi_fn: %p\n",
	     (oq->fastpath_on) ? "ON" : "OFF",
	     (oq->ops.poll_mode) ? "ON" : "OFF",
	     (oq->ops.drop_on_max) ? "ON" : "OFF", oq->ops.fptr,
	     oq->ops.napi_fn);

	cavium_print_msg("idx:  read: %u write: %u  refill: %u\n",
			 oq->host_read_index, oq->octeon_write_index,
			 oq->host_refill_index);

	cavium_print_msg("Pkts: pending: %u forrefill: %u\n",
			 cavium_atomic_read(&oq->pkts_pending),
			 oq->refill_count);

	cavium_print_msg("Stats: PktsRcvd: %llu BytesRcvd: %llu\n",
			 oq->stats.pkts_received, oq->stats.bytes_received);
	cavium_print_msg
	    ("Stats: Dropped: Nodispatch: %llu NoMem: %llu TooMany: %llu\n",
	     oq->stats.dropped_nodispatch, oq->stats.dropped_nomem,
	     oq->stats.dropped_toomany);
}

static void octeon_droq_compute_max_packet_bufs(octeon_droq_t * droq)
{
	uint32_t count = 0;

	/* max_empty_descs is the max. no. of descs that can have no buffers.
	   If the empty desc count goes beyond this value, we cannot safely 
	   read in a 64K packet sent by Octeon (64K is max pkt size from Octeon) */
	droq->max_empty_descs = 0;

	do {
		droq->max_empty_descs++;
		count += droq->buffer_size;
	} while (count < (64 * 1024));

	droq->max_empty_descs = droq->max_count - droq->max_empty_descs;
}

static void octeon_droq_reset_indices(octeon_droq_t * droq)
{
	droq->host_read_index = 0;
	droq->octeon_write_index = 0;
	droq->host_refill_index = 0;
	droq->refill_count = 0;
	cavium_atomic_set(&droq->pkts_pending, 0);
}

static void
octeon_droq_destroy_ring_buffers(octeon_device_t * oct UNUSED,
				 octeon_droq_t * droq)
{
	uint32_t i;

// *INDENT-OFF*
	for(i = 0; i < droq->max_count; i++)  {
		if(droq->recv_buf_list[i].buffer) {
			if(droq->desc_ring) {
#ifndef BUFPTR_ONLY_MODE                
				octeon_pci_unmap_single(oct->pci_dev, (unsigned long)droq->desc_ring[i].info_ptr, OCT_DROQ_INFO_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);
#endif                
#ifdef OCT_REUSE_RX_BUFS
				octeon_pci_unmap_single(oct->pci_dev, (unsigned long)droq->desc_ring[i].buffer_ptr, RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE );
#else
				octeon_pci_unmap_single(oct->pci_dev, (unsigned long)droq->desc_ring[i].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE );
#endif
			}
#ifdef OCT_REUSE_RX_BUFS
			cav_net_kfree(droq->recv_buf_list[i].buffer);
#else
			free_recv_buffer(droq->recv_buf_list[i].buffer);
#endif
		}
	}
// *INDENT-ON*

	octeon_droq_reset_indices(droq);
}

static int
octeon_droq_setup_ring_buffers(octeon_device_t * oct UNUSED,
			       octeon_droq_t * droq)
{
	uint32_t i;
	void *buf;
	octeon_droq_desc_t *desc_ring = droq->desc_ring;

	for (i = 0; i < droq->max_count; i++) {

#ifdef OCT_REUSE_RX_BUFS
		buf = (void *)cav_net_kmalloc(RCV_BUF_SIZE, GFP_ATOMIC);
#else
#if defined(ETHERPCI)
		/* allocationg extra 8 bytes to keep the droq->buffer_size same in ETHERPCI mode */
		buf =
		    cav_net_buff_rx_alloc(((droq->buffer_size) + 8),
					  droq->app_ctx);
#else
		buf = cav_net_buff_rx_alloc(droq->buffer_size, droq->app_ctx);
#endif
#endif
		if (cavium_unlikely(!buf)) {
			cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
			return -ENOMEM;
		}

		droq->recv_buf_list[i].buffer = buf;
#ifdef OCT_REUSE_RX_BUFS
		/* SKB data pointer should point after skb header room */
		droq->recv_buf_list[i].data = buf + CAV_NET_SKB_PAD;
		droq->recv_buf_list[i].skbptr = NULL;
#else
		droq->recv_buf_list[i].data =
		    get_recv_buffer_data(buf, droq->app_ctx);
#endif
#ifndef BUFPTR_ONLY_MODE
		droq->info_list[i].length = 0;

		desc_ring[i].info_ptr =
		    (uint64_t) octeon_pci_map_single(oct->pci_dev,
						     &droq->info_list[i],
						     OCT_DROQ_INFO_SIZE,
						     CAVIUM_PCI_DMA_FROMDEVICE);
#endif
#if defined(ETHERPCI)
		/* infoptr bytes = 0 doesnt work in 56xx. To workaround that, we copy
		   8 bytes of data into infoptr for all Octeon devices. We'll copy it
		   back into data buffer during pkt processing. */
		droq->recv_buf_list[i].data += 8;
#endif
#ifdef OCT_REUSE_RX_BUFS
		desc_ring[i].buffer_ptr =
		    (uint64_t) cnnic_pci_map_single(oct->pci_dev,
						    droq->recv_buf_list[i].data,
						    RCV_BUF_MAP_SIZE,
						    CAVIUM_PCI_DMA_FROMDEVICE,
						    droq->app_ctx);
#else
		desc_ring[i].buffer_ptr =
		    (uint64_t) cnnic_pci_map_single(oct->pci_dev,
						    droq->recv_buf_list[i].data,
						    droq->buffer_size,
						    CAVIUM_PCI_DMA_FROMDEVICE,
						    droq->app_ctx);
#endif
	}

	octeon_droq_reset_indices(droq);

	octeon_droq_compute_max_packet_bufs(droq);

	return 0;
}

int octeon_delete_droq(octeon_device_t * oct, uint32_t q_no)
{
	octeon_droq_t *droq = oct->droq[q_no];

	cavium_print(PRINT_FLOW, "\n\n---#  octeon_delete_droq[%d]  #---\n",
		     q_no);

#ifdef  USE_DROQ_THREADS

	if (CVM_KTHREAD_EXISTS(&droq->thread)) {
		cavium_print_msg("Killing DROQ[%d] thread\n", q_no);

		cavium_atomic_inc(&droq->pkts_pending);
		droq->stop_thread = 1;
		cavium_flush_write();

		cavium_kthread_destroy(&droq->thread);

		/* Wait till the droq thread has come out of its loop. */
		while (cavium_atomic_read(&droq->thread_active))
			cavium_sleep_timeout(1);
	}
#endif

	octeon_unregister_poll_fn(oct->octeon_id, check_droq_refill, q_no);

	octeon_droq_destroy_ring_buffers(oct, droq);

	if (droq->recv_buf_list)
		cavium_free_virt(droq->recv_buf_list);

#ifndef BUFPTR_ONLY_MODE
	if (droq->info_base_addr)
		cnnic_free_aligned_dma(droq->info_base_addr,
				       droq->info_alloc_size, droq->app_ctx);
#endif

	if (droq->desc_ring)
		octeon_pci_free_consistent(oct->pci_dev,
					   (droq->max_count *
					    OCT_DROQ_DESC_SIZE),
					   droq->desc_ring, droq->desc_ring_dma,
					   droq->app_ctx);

	oct->io_qmask.oq &= ~(1ULL << q_no);

	cavium_memset(droq, 0, OCT_DROQ_SIZE);

	cavium_free_virt(oct->droq[q_no]);

	oct->droq[q_no] = NULL;

	return 0;
}

int octeon_init_droq(octeon_device_t * oct, uint32_t q_no, void *app_ctx)
{
	octeon_droq_t *droq;
	uint32_t desc_ring_size = 0;
	uint32_t c_num_descs = 0, c_buf_size = 0, c_pkts_per_intr =
	    0, c_refill_threshold = 0;
#ifndef APP_DROQ_REFILL
	octeon_poll_ops_t poll_ops;
#endif

	cavium_print(PRINT_FLOW, "\n\n----# octeon_init_droq #----\n");
	cavium_print(PRINT_DEBUG, "q_no: %d\n", q_no);

	droq = oct->droq[q_no];
	cavium_memset(droq, 0, OCT_DROQ_SIZE);

	droq->oct_dev = oct;
	droq->q_no = q_no;
	if (app_ctx)
		droq->app_ctx = app_ctx;
	else
		droq->app_ctx = (void *)(long)q_no;

	if (oct->chip_id == OCTEON_CN83XX_VF) {
		cn83xx_vf_config_t *conf83 = CHIP_FIELD(oct, cn83xx_vf, conf);
		c_num_descs = CFG_GET_OQ_NUM_DESC(conf83);
		c_buf_size = CFG_GET_OQ_BUF_SIZE(conf83);
		c_pkts_per_intr = CFG_GET_OQ_PKTS_PER_INTR(conf83);
		c_refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(conf83);
	}
	if (oct->chip_id == OCTEON_CN93XX_VF) {
		cn93xx_vf_config_t *conf93 = CHIP_FIELD(oct, cn93xx_vf, conf);
		c_num_descs = CFG_GET_OQ_NUM_DESC(conf93);
		c_buf_size = CFG_GET_OQ_BUF_SIZE(conf93);
		c_pkts_per_intr = CFG_GET_OQ_PKTS_PER_INTR(conf93);
		c_refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(conf93);
	}

	droq->max_count = c_num_descs;
	droq->buffer_size = c_buf_size;

	desc_ring_size = droq->max_count * OCT_DROQ_DESC_SIZE;
	droq->desc_ring =
	    octeon_pci_alloc_consistent(oct->pci_dev, desc_ring_size,
					&droq->desc_ring_dma, droq->app_ctx);

	if (cavium_unlikely(!droq->desc_ring)) {
		cavium_error("OCTEON[%d]: Output queue %d ring alloc failed\n",
			     oct->octeon_id, q_no);
		return 1;
	}

	cavium_print(PRINT_REGS, "droq[%d]: desc_ring: virt: 0x%p, dma: %lx",
		     q_no, droq->desc_ring, droq->desc_ring_dma);
	cavium_print(PRINT_REGS, "droq[%d]: num_desc: %d",
		     q_no, droq->max_count);

#ifndef BUFPTR_ONLY_MODE
	droq->info_list =
	    cavium_alloc_aligned_memory((droq->max_count * OCT_DROQ_INFO_SIZE),
					&droq->info_alloc_size,
					&droq->info_base_addr, droq->app_ctx);

	if (cavium_unlikely(!droq->info_list)) {
		cavium_error
		    ("OCTEON[%d]: Cannot allocate memory for info list.\n",
		     oct->octeon_id);
		octeon_pci_free_consistent(oct->pci_dev,
					   (droq->max_count *
					    OCT_DROQ_DESC_SIZE),
					   droq->desc_ring, droq->desc_ring_dma,
					   droq->app_ctx);
		return 1;
	}
	cavium_print(PRINT_DEBUG, "setup_droq: droq_info: 0x%p\n",
		     droq->info_list);
#endif

	droq->recv_buf_list = (octeon_recv_buffer_t *)
	    cavium_alloc_virt(droq->max_count * OCT_DROQ_RECVBUF_SIZE);
	if (cavium_unlikely(!droq->recv_buf_list)) {
		cavium_error
		    ("OCTEON[%d]: Output queue recv buf list alloc failed\n",
		     oct->octeon_id);
		goto init_droq_fail;
	}
	cavium_print(PRINT_DEBUG, "setup_droq: q:%d recv_buf_list: 0x%p\n",
		     q_no, droq->recv_buf_list);

	if (octeon_droq_setup_ring_buffers(oct, droq)) {
		goto init_droq_fail;
	}

	droq->pkts_per_intr = c_pkts_per_intr;
	droq->refill_threshold = c_refill_threshold;

	cavium_print(PRINT_DEBUG, "DROQ INIT: max_empty_descs: %d\n",
		     droq->max_empty_descs);

	cavium_spin_lock_init(&droq->lock);

	CAVIUM_INIT_LIST_HEAD(&droq->dispatch_list);

	/* For 56xx Pass1, this function won't be called, so no checks. */
	oct->fn_list.setup_oq_regs(oct, q_no);

	oct->io_qmask.oq |= (1ULL << q_no);

#ifndef APP_DROQ_REFILL
	poll_ops.fn = check_droq_refill;
	poll_ops.fn_arg = (unsigned long)q_no;
	poll_ops.ticks = 1;
	cavium_strcpy(poll_ops.name, sizeof(poll_ops.name), "DROQ Refill");
	poll_ops.rsvd = 0xff;
	octeon_register_poll_fn(oct->octeon_id, &poll_ops);
#endif

#ifdef  USE_DROQ_THREADS
	cavium_init_wait_channel(&droq->wc);
	cavium_kthread_setup(&droq->thread, oct_droq_thread, droq,
			     "Oct DROQ Thread", 0);
	if (cavium_kthread_create(&droq->thread))
		goto init_droq_fail;
	cavium_kthread_set_cpu_affinity(&droq->thread,
					(droq->q_no % cavium_get_cpu_count()));
	cavium_kthread_run(&droq->thread);
#endif

	return 0;

init_droq_fail:
	octeon_delete_droq(oct, q_no);
	return 1;
}

int octeon_shutdown_output_queue(octeon_device_t * oct, int q_no)
{
	octeon_droq_t *droq = oct->droq[q_no];
	volatile uint32_t *resp;
	uint32_t *respbuf = cavium_malloc_dma(4, GFP_ATOMIC), loop_count = 100;
	int retval = 0, pkt_count = 0;

	if (respbuf == NULL) {
		cavium_error("%s buffer alloc failed\n", __CVM_FUNCTION__);
		return -ENOMEM;
	}
	resp = (volatile uint32_t *)respbuf;

	*resp = 0xFFFFFFFF;

	/* Handle stop cmd of each vf indipendtly on core side */
#if 1
	/* Send a command to Octeon to stop further packet processing */
	if (octeon_send_short_command(oct, DEVICE_STOP_OP,
				      (q_no << 8 | DEVICE_PKO), respbuf, 4)) {
		cavium_error("%s command failed\n", __CVM_FUNCTION__);
		retval = -EINVAL;
		goto shutdown_oq_done;
	}
#endif
	/* Wait for response from Octeon. */
	while ((*resp == 0xFFFFFFFF) && (loop_count--)) {
		cavium_sleep_timeout(1);
	}

	if (*resp != 0) {
		cavium_error("%s command failed: %s\n", __CVM_FUNCTION__,
			     (*resp ==
			      0xFFFFFFFF) ? "time-out" : "Failed in core");
		retval = -EBUSY;
		goto shutdown_oq_done;
	}

	/* Wait till any in-transit packets are processed. */
	pkt_count = OCTEON_READ32(droq->pkts_sent_reg);
	loop_count = 100;
	while (pkt_count && (loop_count--)) {
		cavium_sleep_timeout(1);
		pkt_count = OCTEON_READ32(droq->pkts_sent_reg);
	}

	if (pkt_count) {
		cavium_error("%s Pkts processing timed-out (pkt_count: %d)\n",
			     __CVM_FUNCTION__, pkt_count);
		retval = -EBUSY;
		goto shutdown_oq_done;
	}

	if (oct->chip_id == OCTEON_CN83XX_VF) {
		uint64_t reg_val = 0ULL;

		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								  q_no),
				   reg_val);
	}
	if (oct->chip_id == OCTEON_CN93XX_VF) {
		uint64_t reg_val = 0ULL;

		octeon_write_csr64(oct,
				   CN93XX_VF_SDP_R_OUT_ENABLE(q_no),
				   reg_val);
	}

	/* Reset the credit count register after enabling the queues. */
	OCTEON_WRITE32(oct->droq[q_no]->pkts_credit_reg, 0);

shutdown_oq_done:
	if (resp)
		cavium_free_dma(respbuf);
	return retval;

}

int octeon_restart_output_queue(octeon_device_t * oct, int q_no)
{
	int retval = 0;
	uint32_t *respbuf, loop_count = 100;
	volatile uint32_t *resp;

	respbuf = cavium_malloc_dma(4, GFP_ATOMIC);
	if (respbuf == NULL) {
		cavium_error("%s buffer alloc failed\n", __CVM_FUNCTION__);
		return -ENOMEM;
	}
	resp = (volatile uint32_t *)respbuf;
	*resp = 0xFFFFFFFF;
	if (oct->chip_id == OCTEON_CN83XX_VF) {
		uint64_t reg_val = 0x1ULL;

		octeon_write_csr64(oct,
				   CN83XX_VF_SDP_EPF_R_OUT_ENABLE(oct->epf_num,
								  q_no),
				   reg_val);
	}

	cavium_flush_write();

	/* Write the credit count register after enabling the queues. */
	OCTEON_WRITE32(oct->droq[q_no]->pkts_credit_reg,
		       oct->droq[q_no]->max_count);

	cavium_sleep_timeout(1);

	/* Send a command to Octeon to START further packet processing */
	if (octeon_send_short_command(oct, DEVICE_START_OP,
				      ((q_no << 8) | DEVICE_PKO), respbuf, 4)) {
		cavium_error("%s command failed\n", __CVM_FUNCTION__);
		retval = -EINVAL;
		goto restart_oq_done;
	}

	/* Wait for response from Octeon. */
	while ((*resp == 0xFFFFFFFF) && (loop_count--)) {
		cavium_sleep_timeout(1);
	}

	if (*resp != 0) {
		cavium_error("%s command failed: %s\n", __CVM_FUNCTION__,
			     (*resp ==
			      0xFFFFFFFF) ? "time-out" : "Failed in core");
		retval = -EBUSY;
		goto restart_oq_done;
	}

restart_oq_done:
	if (resp)
		cavium_free_dma(respbuf);
	return retval;

}

int wait_for_output_queue_pkts(octeon_device_t * oct, int q_no)
{
	int retry = 100, pkt_cnt = 0, pending_pkts = 0;

	do {
		pending_pkts = 0;

#if defined(USE_DROQ_THREADS)

		pkt_cnt = octeon_droq_check_hw_for_pkts(oct, oct->droq[q_no]);
		if (pkt_cnt > 0) {
			pending_pkts += pkt_cnt;
			cavium_wakeup(&oct->droq[q_no]->wc);
		}
#endif
		cavium_sleep_timeout(1);

	} while (retry-- && pending_pkts);

	return pkt_cnt;
}

int wait_for_oq_pkts(octeon_device_t * oct)
{
	int retry = 100, pkt_cnt = 0, pending_pkts = 0;
#if defined(USE_DROQ_THREADS)
	int i = 0;
#endif

	do {
		pending_pkts = 0;

#if defined(USE_DROQ_THREADS)
		for (i = 0; i < oct->num_oqs; i++) {
			pkt_cnt =
			    octeon_droq_check_hw_for_pkts(oct, oct->droq[i]);
			if (pkt_cnt > 0) {
				pending_pkts += pkt_cnt;
				cavium_wakeup(&oct->droq[i]->wc);
			}
		}
#endif
		cavium_sleep_timeout(1);

	} while (retry-- && pending_pkts);

	return pkt_cnt;
}

int
octeon_reset_recv_buf_size(octeon_device_t * oct, int q_no, uint32_t newsize)
{
	int num_qs = 1, oq_no = q_no;

	if (!newsize) {
		cavium_error("%s Invalid buffer size (%d)\n", __CVM_FUNCTION__,
			     newsize);
		return -EINVAL;
	}

	/*
	   If the new buffer size is smaller than the current buffer size, do not
	   do anything. Else change for all rings.
	 */
	if (newsize <= oct->droq[q_no]->buffer_size)
		return 0;

	if (oct->chip_id == OCTEON_CN83XX_VF) {
		cn83xx_vf_setup_global_output_regs(oct);
		num_qs = oct->num_oqs;
		oq_no = 0;
	}

	while (num_qs--) {
		int retval;

		retval = octeon_restart_output_queue(oct, oq_no);
		if (retval != 0)
			return retval;
		oq_no++;
	}

	return 0;
}

/*
  octeon_create_recv_info
  Parameters: 
    octeon_dev - pointer to the octeon device structure
    droq       - droq in which the packet arrived. 
    buf_cnt    - no. of buffers used by the packet.
    idx        - index in the descriptor for the first buffer in the packet.
  Description:
    Allocates a recv_info_t and copies the buffer addresses for packet data 
    into the recv_pkt space which starts at an 8B offset from recv_info_t.
    Flags the descriptors for refill later. If available descriptors go 
    below the threshold to receive a 64K pkt, new buffers are first allocated
    before the recv_pkt_t is created.
    This routine will be called in interrupt context.
  Returns:
    Success: Pointer to recv_info_t 
    Failure: NULL. 
  Locks:
    The droq->lock is held when this routine is called.
*/
static inline octeon_recv_info_t *octeon_create_recv_info(octeon_device_t *
							  octeon_dev,
							  octeon_droq_t * droq,
							  uint32_t buf_cnt,
							  uint32_t idx)
{
	octeon_droq_info_t *info;
	octeon_recv_pkt_t *recv_pkt;
	octeon_recv_info_t *recv_info;
	uint32_t i, bytes_left;

	cavium_print(PRINT_FLOW, "\n\n----#  create_recv_pkt #----\n");

#ifndef BUFPTR_ONLY_MODE
	info = &droq->info_list[idx];
#else
	info = (octeon_droq_info_t *) (droq->recv_buf_list[idx].data);
#endif

	cavium_print(PRINT_DEBUG, "buf_cnt: %d  idx: %d\n", buf_cnt, idx);
	recv_info = octeon_alloc_recv_info(sizeof(struct __dispatch));
	if (!recv_info)
		return NULL;

	recv_pkt = recv_info->recv_pkt;

#if  !defined(ETHERPCI)
	/* This function is never called in EtherPCI. Also info_ptr does not have
	   resp_hdr for ETHERPCI. Just don't wan't this code to compile. */
	recv_pkt->resp_hdr = info->resp_hdr;
#endif
	recv_pkt->length = info->length;
	recv_pkt->offset = sizeof(octeon_droq_info_t);
	recv_pkt->buffer_count = (uint16_t) buf_cnt;
	recv_pkt->octeon_id = (uint16_t) octeon_dev->octeon_id;
	recv_pkt->buf_type = OCT_RECV_BUF_TYPE_2;

	cavium_print(PRINT_DEBUG, "recv_pkt: len: %x  buf_cnt: %x\n",
		     recv_pkt->length, recv_pkt->buffer_count);

	i = 0;
	bytes_left = info->length;

	while (buf_cnt) {

		/* Done for IOMMU: Don't unmap buffer from the device, since we are reusing it */
// *INDENT-OFF*
#ifndef DROQ_TEST_REUSE_BUFS
      octeon_pci_unmap_single(octeon_dev->pci_dev, (unsigned long)droq->desc_ring[idx].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);
#endif
// *INDENT-ON*

	/* In BUF ptr mode, First buffer contains resp headr and len. 
	 * when data spans multiple buffers data present 
	 * in first buffer is less than the actual buffer size*/
#ifdef BUFPTR_ONLY_MODE
		if(!i) {
			recv_pkt->buffer_size[i] =
				( (bytes_left + sizeof(octeon_droq_info_t)) >= droq->buffer_size)
				? (droq->buffer_size - sizeof(octeon_droq_info_t)) : bytes_left;
          
			bytes_left -= (droq->buffer_size - sizeof(octeon_droq_info_t));
		}
		else
#endif
		{
			recv_pkt->buffer_size[i] =
				(bytes_left >= droq->buffer_size)?droq->buffer_size: bytes_left;
				bytes_left -= droq->buffer_size;
		}

		recv_pkt->buffer_ptr[i] = droq->recv_buf_list[idx].buffer;

		/* Done for IOMMU: To avoid refilling the buffer index */
#ifndef DROQ_TEST_REUSE_BUFS
		droq->recv_buf_list[idx].buffer = 0;
#endif

		INCR_INDEX_BY1(idx, droq->max_count);
		bytes_left -= droq->buffer_size;
		i++;
		buf_cnt--;
	}

	return recv_info;

}

/* If we were not able to refill all buffers, try to move around
   the buffers that were not dispatched.
*/
static inline uint32_t
octeon_droq_refill_pullup_descs(octeon_droq_t * droq,
				octeon_droq_desc_t * desc_ring)
{
	uint32_t desc_refilled = 0;

	uint32_t refill_index = droq->host_refill_index;

	while (refill_index != droq->host_read_index) {
		if (droq->recv_buf_list[refill_index].buffer != 0) {
			droq->recv_buf_list[droq->host_refill_index].buffer =
			    droq->recv_buf_list[refill_index].buffer;
			droq->recv_buf_list[droq->host_refill_index].data =
			    droq->recv_buf_list[refill_index].data;
			desc_ring[droq->host_refill_index].buffer_ptr =
			    desc_ring[refill_index].buffer_ptr;
			droq->recv_buf_list[refill_index].buffer = 0;
			desc_ring[refill_index].buffer_ptr = 0;
// *INDENT-OFF*
			do {
				INCR_INDEX_BY1(droq->host_refill_index, droq->max_count);
				desc_refilled++;
				droq->refill_count--;
			} while (droq->recv_buf_list[droq->host_refill_index].buffer);
// *INDENT-ON*
		}
		INCR_INDEX_BY1(refill_index, droq->max_count);
	}			/* while */
	return desc_refilled;
}

/*
  octeon_droq_refill
  Parameters: 
    droq       - droq in which descriptors require new buffers. 
  Description:
    Called during normal DROQ processing in interrupt mode or by the poll
    thread to refill the descriptors from which buffers were dispatched
    to upper layers. Attempts to allocate new buffers. If that fails, moves
    up buffers (that were not dispatched) to form a contiguous ring.
  Returns:
    No of descriptors refilled.
  Locks:
    This routine is called with droq->lock held.
*/
uint32_t
octeon_droq_refill(octeon_device_t * octeon_dev UNUSED, octeon_droq_t * droq)
{
	octeon_droq_desc_t *desc_ring;
#ifndef OCT_REUSE_RX_BUFS
	void *buf;
	uint8_t *data;
	uint32_t map = 1;
#else
	uint8_t users = 0, ref_count = 0;
	void *skbptr;
#endif
	uint32_t desc_refilled = 0;

	desc_ring = droq->desc_ring;

	cavium_print(PRINT_DEBUG, "\n\n----#   octeon_droq_refill #----\n");
	cavium_print(PRINT_DEBUG,
		     "refill_count: %d host_refill_index: %d, host_read_index: %d\n",
		     droq->refill_count, droq->host_refill_index,
		     droq->host_read_index);

	while (droq->refill_count && (desc_refilled < droq->max_count)) {
#ifdef OCT_REUSE_RX_BUFS
		/* Get SKB pointer corresponding to the index */
		skbptr = droq->recv_buf_list[droq->host_refill_index].skbptr;

		/* SKB is given to the stack and need to check users and 
		 * data reference count before giving back to the device */
		if (skbptr) {
			/* Get number of users for this SKB */
			users = cav_net_get_skb_users(skbptr);

			/* Get number of references to the data buffer in the SKB */
			ref_count = cav_net_get_skb_data_ref_count(skbptr);

			/* If users and data reference count equals to one, then
			 * we are the only user for this SKB and data, we can 
			 * send same buffer back to the device */
			if (users == 1 && ref_count == 1 &&
			    skb_is_linear(skb)) {
				//printk("Users for skb: %d Data reference count:%d reusing DMA buffer\n",users, ref_count);
				/* We have to make skb->head = NULL to free only SKB pointer
				 * and not data pointer since we are giving back data pointer 
				 * to the device */
				cav_net_make_skb_head_null(skbptr);

				/* This will free only SKB pointer and not data pointer 
				 * since we are making skb->head = NULL */
				cav_net_free_skb(skbptr);

				/* Giving data buffer back to the device */
// *INDENT-OFF*
				cnnic_pci_dma_sync_single_for_device(octeon_dev->pci_dev,
					(unsigned long)droq->desc_ring[droq->host_refill_index].buffer_ptr,
					RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);
// *INDENT-ON*
			} else {
				/* We are here because some other layer still has access to the 
				 * SKB buffer or data buffer. Release the skb and allocate new buffer */
				void *buf;

				/* Decrement reference count and free skb if there are no users. */
				cav_net_free_skb(skbptr);
				//printk("users for skb:%d data: %d Unmapping buffer and freeing skb\n",users, ref_count);

				/* Unmap buffer from the device */
// *INDENT-OFF*
				octeon_pci_unmap_single(octeon_dev->pci_dev,
					(unsigned long)droq->desc_ring[droq->host_refill_index].buffer_ptr,
					RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);

				/* Allocate new DMA buffer */
				buf = (void *)cav_net_kmalloc(RCV_BUF_SIZE, GFP_ATOMIC);
				if(cavium_unlikely(!buf)) {
					cavium_error("%s buffer alloc failed\n", __CVM_FUNCTION__);
					return -ENOMEM;
				}

				droq->recv_buf_list[droq->host_refill_index].buffer  = buf;
				/* SKB data pointer should point after skb header room */
				droq->recv_buf_list[droq->host_refill_index].data    = buf + CAV_NET_SKB_PAD;
            
				/* Map new buffer to the device */
				desc_ring[droq->host_refill_index].buffer_ptr = (uint64_t)cnnic_pci_map_single(octeon_dev->pci_dev, 
						droq->recv_buf_list[droq->host_refill_index].data, RCV_BUF_MAP_SIZE, 
						CAVIUM_PCI_DMA_FROMDEVICE, droq->app_ctx);
// *INDENT-ON*
			}
		} else {
			/* SKB is not forwareded to the stack, maybe data is copied 
			 * in to another skb(happens in jumbo packet case)  
			 * or some failure during skb creation. we can freely send 
			 * same buffer to the device */
			//printk("Jumbo packet buffer, Giving back to the device\n");
			cnnic_pci_dma_sync_single_for_device
			    (octeon_dev->pci_dev, (unsigned long)
			     droq->desc_ring
			     [droq->host_refill_index].buffer_ptr,
			     RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);

		}
		/* In either case we have to reset skb pointer to NULL */
		droq->recv_buf_list[droq->host_refill_index].skbptr = NULL;
#else
		/* If a valid buffer exists (happens if there is no dispatch), reuse 
		   the buffer, else allocate. */
		if (droq->recv_buf_list[droq->host_refill_index].buffer == 0) {
#if defined(ETHERPCI)
			/* allocationg extra 8 bytes to keep the droq->buffer_size same in ETHERPCI mode */
			buf =
			    cav_net_buff_rx_alloc(droq->buffer_size + 8,
						  droq->app_ctx);
#else
			buf =
			    cav_net_buff_rx_alloc(droq->buffer_size,
						  droq->app_ctx);
#endif
			/* If a buffer could not be allocated, no point in continuing */
			if(cavium_unlikely(!buf)) { 
				cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
				break;
			}
			droq->recv_buf_list[droq->host_refill_index].buffer =
			    buf;
			data = get_recv_buffer_data(buf, droq->app_ctx);
			map = 1;
		} else {
			map = 0;
// *INDENT-OFF*
			data = get_recv_buffer_data(droq->recv_buf_list[droq->host_refill_index].buffer,droq->app_ctx);
// *INDENT-ON*
		}

#if defined(ETHERPCI)
		data += 8;
#endif
		droq->recv_buf_list[droq->host_refill_index].data = data;
		if (map) {
			desc_ring[droq->host_refill_index].buffer_ptr =
			    (uint64_t) cnnic_pci_map_single(octeon_dev->pci_dev,
							    data,
							    droq->buffer_size,
							    CAVIUM_PCI_DMA_FROMDEVICE,
							    droq->app_ctx);
		}
#endif

#ifndef BUFPTR_ONLY_MODE
		/* Reset any previous values in the length field. */
		droq->info_list[droq->host_refill_index].length = 0;
#endif

		INCR_INDEX_BY1(droq->host_refill_index, droq->max_count);
		desc_refilled++;
		droq->refill_count--;
	}

	cavium_print(PRINT_DEBUG, "First pass of refill completed\n");
	cavium_print(PRINT_DEBUG,
		     "refill_count: %d host_refill_index: %d, host_read_index: %d\n",
		     droq->refill_count, droq->host_refill_index,
		     droq->host_read_index);

	if (droq->refill_count) {
		desc_refilled +=
		    octeon_droq_refill_pullup_descs(droq, desc_ring);
	}

	/* if droq->refill_count */
	/* The refill count would not change in pass two. We only moved buffers
	   to close the gap in the ring, but we would still have the same no. of
	   buffers to refill.
	 */
	return desc_refilled;
}

static inline uint32_t
octeon_droq_get_bufcount(uint32_t buf_size, uint32_t total_len)
{
	uint32_t buf_cnt = 0;

#ifdef BUFPTR_ONLY_MODE
	if (total_len <= (buf_size - sizeof(octeon_droq_info_t))) {
		buf_cnt++;
	} else {
		total_len -= (buf_size - sizeof(octeon_droq_info_t));
#endif
		while (total_len > (buf_size * buf_cnt))
			buf_cnt++;

#ifdef BUFPTR_ONLY_MODE
		buf_cnt++;
	}
#endif

	return buf_cnt;
}

#if !defined(ETHERPCI)
static int
octeon_droq_dispatch_pkt(octeon_device_t * oct,
			 octeon_droq_t * droq,
			 octeon_resp_hdr_t * resp_hdr,
			 octeon_droq_info_t * info)
{
	uint32_t cnt;
	octeon_dispatch_fn_t disp_fn;
	octeon_recv_info_t *rinfo;

	cnt = octeon_droq_get_bufcount(droq->buffer_size, info->length);

	disp_fn = octeon_get_dispatch(oct, (uint16_t) resp_hdr->opcode);
	if (disp_fn) {
		rinfo =
		    octeon_create_recv_info(oct, droq, cnt,
					    droq->host_read_index);
		if (rinfo) {
			struct __dispatch *rdisp = rinfo->rsvd;
			rdisp->rinfo = rinfo;
			rdisp->disp_fn = disp_fn;
			rinfo->recv_pkt->resp_hdr = *resp_hdr;
			cavium_list_add_tail(&rdisp->list,
					     &droq->dispatch_list);
		} else {
			droq->stats.dropped_nomem++;
		}
	} else {
		droq->stats.dropped_nodispatch++;
	}			/* else (dispatch_fn ... */

	return cnt;
}
#endif

static inline void octeon_droq_drop_packets(octeon_droq_t * droq, uint32_t cnt)
{
	uint32_t i = 0, buf_cnt;
	octeon_droq_info_t *info;
	octeon_device_t *oct = droq->oct_dev;

	for (i = 0; i < cnt; i++) {

#ifndef BUFPTR_ONLY_MODE
		info = &(droq->info_list[droq->host_read_index]);
#else
		info =
		    (octeon_droq_info_t
		     *) (droq->recv_buf_list[droq->host_read_index].data);
#endif

		/* Swap length field on 83xx*/
		if (oct->chip_id == OCTEON_CN83XX_VF)
			octeon_swap_8B_data((uint64_t *) &(info->length), 1);

		if (info->length) {
			info->length -= OCT_RESP_HDR_SIZE;
			droq->stats.bytes_received += info->length;
			buf_cnt =
			    octeon_droq_get_bufcount(droq->buffer_size,
						     info->length);
		} else {
			cavium_error("OCTEON:DROQ: In drop: pkt with len 0\n");
			buf_cnt = 1;
		}

#if  defined(FAST_PATH_DROQ_DISPATCH)
		{
			octeon_resp_hdr_t *resp_hdr = &info->resp_hdr;
			if ((resp_hdr->opcode & droq->ops.op_mask) !=
			    droq->ops.op_major) {
				octeon_droq_dispatch_pkt(droq->oct_dev, droq,
							 resp_hdr, info);
			}
		}
#endif

		INCR_INDEX(droq->host_read_index, buf_cnt, droq->max_count);
		droq->refill_count += buf_cnt;
	}
}

#define OCTEON_PKTPUSH_THRESHOLD	128

#ifndef OCT_REUSE_RX_BUFS

static uint32_t
octeon_droq_fast_process_packets(octeon_device_t * oct,
				 octeon_droq_t * droq, uint32_t pkts_to_process)
{
	octeon_droq_info_t *info;
	octeon_resp_hdr_t *resp_hdr;
	uint32_t pkt, total_len = 0, pkt_count, bufs_used = 0;
#ifdef ETHERPCI
	uint64_t etherpci_resp_hdr = 0ULL;
#endif

#if !defined(USE_DROQ_THREADS)
#ifndef APP_DROQ_POLL
	if (pkts_to_process > droq->pkts_per_intr)
		pkt_count = droq->pkts_per_intr;
	else
#endif /* APP_DROQ_POLL */
#endif
		pkt_count = pkts_to_process;

	for (pkt = 0; pkt < pkt_count; pkt++) {

		uint32_t pkt_len = 0;
		cavium_netbuf_t *nicbuf = NULL;

#ifndef BUFPTR_ONLY_MODE
		info = &(droq->info_list[droq->host_read_index]);
#else
		info =
		    (octeon_droq_info_t
		     *) (droq->recv_buf_list[droq->host_read_index].data);
#endif

#if defined(ETHERPCI)
		octeon_swap_8B_data((uint64_t *) & info->length, 1);
		/* infoptr bytes = 0 doesnt work in 56xx. To workaround that, we copy
		   8 bytes of data from infoptr for all Octeon devices. */
		cavium_memcpy(droq->recv_buf_list[droq->host_read_index].data -
			      8, (char *)info, 8);
#else
		/* Swap length field on 83xx*/
		if (oct->chip_id == OCTEON_CN83XX_VF || oct->chip_id == OCTEON_CN93XX_VF)
			octeon_swap_8B_data((uint64_t *) &(info->length), 1);
#endif

		if (cavium_unlikely(!info->length)) {
			cavium_error
			    ("OCTEON:DROQ[%d] idx: %d len:0, pkt_cnt: %d \n",
			     droq->q_no, droq->host_read_index, pkt_count);
			cavium_error_print_data((uint8_t *) info,
						OCT_DROQ_INFO_SIZE);
			pkt++;

			break;
		}
#ifdef ETHERPCI
		resp_hdr = (octeon_resp_hdr_t *) & etherpci_resp_hdr;
		resp_hdr->dest_qport = droq->q_no;
#else
		/* Len of resp hdr in included in the received data len. */
		info->length -= OCT_RESP_HDR_SIZE;
		resp_hdr = &info->resp_hdr;
#endif

		total_len += info->length;

#if  defined(FAST_PATH_DROQ_DISPATCH)
		if ((resp_hdr->opcode & droq->ops.op_mask) !=
		    droq->ops.op_major) {
			int cnt =
			    octeon_droq_dispatch_pkt(oct, droq, resp_hdr, info);
			INCR_INDEX(droq->host_read_index, cnt, droq->max_count);
			bufs_used += cnt;
			continue;
		}
#endif

#ifndef BUFPTR_ONLY_MODE
		if (info->length <= droq->buffer_size) {
#else
		if (info->length <=
		    (droq->buffer_size - sizeof(octeon_droq_info_t))) {
#endif
// *INDENT-OFF*
			octeon_pci_unmap_single(oct->pci_dev,
				(unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr,
				droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);
// *INDENT-ON*
			pkt_len = info->length;
			nicbuf =
			    droq->recv_buf_list[droq->host_read_index].buffer;
#ifdef BUFPTR_ONLY_MODE
			nicbuf->data += sizeof(octeon_droq_info_t);
			nicbuf->tail += sizeof(octeon_droq_info_t);
#endif
			droq->recv_buf_list[droq->host_read_index].buffer = 0;
			INCR_INDEX_BY1(droq->host_read_index, droq->max_count);
			(void)recv_buf_put(nicbuf, pkt_len);
			bufs_used++;
		} else {
			nicbuf =
			    cav_net_buff_rx_alloc(info->length, droq->app_ctx);
			if(cavium_unlikely(!nicbuf)) { 
				cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
			}
			pkt_len = 0;
			/* nicbuf allocation can fail. We'll handle it inside the loop. */
			while (pkt_len < info->length) {
				int copy_len = 0;


// *INDENT-OFF*
				if(cavium_likely(nicbuf)) {
					octeon_pci_unmap_single(oct->pci_dev, (unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);



#ifdef ETHERPCI	
				copy_len = ((pkt_len + droq->buffer_size) > info->length)?(info->length - pkt_len):droq->buffer_size;
					if(pkt_len >= droq->buffer_size) {
						/* copy the next buffer bytes from (buf->data + 8) 
                                                 * offset instead from buf->data offset
                                                 */
						cavium_memcpy( (get_recv_buffer_data(nicbuf, droq->app_ctx) + pkt_len ), 
					                     ((get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx)) + 8),
                                                             copy_len);
						recv_buf_put(nicbuf, copy_len);

					} else {
						/* Since 1st buffer has size = (droq->buffer_size + 8), so 
 						 * adjusting copy_len for this extra 8 bytes in ETHERPCI mode. 
 						 */
						copy_len += ((info->length - droq->buffer_size) < 8 )?(info->length - droq->buffer_size):8;
						cavium_memcpy(get_recv_buffer_data(nicbuf, droq->app_ctx),
                                                              get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx), 
                                                              copy_len );
						recv_buf_put(nicbuf, copy_len);

					}
					
#else	
#ifdef BUFPTR_ONLY_MODE
					if(!pkt_len) {
						copy_len = ((pkt_len + droq->buffer_size - sizeof(octeon_droq_info_t)) > info->length)?(info->length - pkt_len):(droq->buffer_size - sizeof(octeon_droq_info_t));

						cavium_memcpy( recv_buf_put(nicbuf, copy_len),
							((get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx)) + sizeof(octeon_droq_info_t)),
								copy_len);
					} else {
#endif
						copy_len = ((pkt_len + droq->buffer_size) > info->length)?(info->length - pkt_len):droq->buffer_size;

						cavium_memcpy( recv_buf_put(nicbuf, copy_len),
							get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx),
								copy_len);
#ifdef BUFPTR_ONLY_MODE
					}
#endif



#endif /* ETHERPCI */

				}
// *INDENT-ON*

				pkt_len += copy_len;
				INCR_INDEX_BY1(droq->host_read_index,
					       droq->max_count);
				bufs_used++;
			}
		}

		if (cavium_likely(nicbuf)) {
			if (cavium_likely(droq->ops.fptr))
#ifdef OCT_NIC_USE_NAPI
				droq->ops.fptr(oct->octeon_id, nicbuf, pkt_len, resp_hdr, (pkt_count < OCTEON_PKTPUSH_THRESHOLD) && (pkt == (pkt_count - 1)), &droq->napi);	/* tuned for TCP_RR/STREAM perf:add last packet arg.: speed-up packet push */
#else
				droq->ops.fptr(oct->octeon_id, nicbuf, pkt_len, resp_hdr, (pkt_count < OCTEON_PKTPUSH_THRESHOLD) && (pkt == (pkt_count - 1)), NULL);	/* tuned for TCP_RR/STREAM perf:add last packet arg.: speed-up packet push */
#endif
			else
				free_recv_buffer(nicbuf);
		}

	}			/* for ( each packet )... */

	/* Increment refill_count by the number of buffers processed. */
	droq->refill_count += bufs_used;

	droq->stats.pkts_received += pkt;
	droq->stats.bytes_received += total_len;

	if ((droq->ops.drop_on_max) && (pkts_to_process - pkt)) {
		octeon_droq_drop_packets(droq, (pkts_to_process - pkt));
		droq->stats.dropped_toomany += (pkts_to_process - pkt);
		return pkts_to_process;
	}

	return pkt;
}

#else

static uint32_t
octeon_droq_fast_process_packets_reuse_bufs(octeon_device_t * oct,
					    octeon_droq_t * droq,
					    uint32_t pkts_to_process)
{
	octeon_droq_info_t *info;
	octeon_resp_hdr_t *resp_hdr;
	uint32_t pkt, total_len = 0, pkt_count, bufs_used = 0;

	if (pkts_to_process > droq->pkts_per_intr)
		pkt_count = droq->pkts_per_intr;
	else
		pkt_count = pkts_to_process;

// *INDENT-OFF*
	for(pkt = 0; pkt < pkt_count; pkt++) {
		uint32_t         pkt_len = 0;
		cavium_netbuf_t  *nicbuf = NULL;

#ifndef BUFPTR_ONLY_MODE
		info = &(droq->info_list[droq->host_read_index]);
#else
		info = (octeon_droq_info_t *)(droq->recv_buf_list[droq->host_read_index].data);
#endif        

		/* Swap length field on 83xx*/
		if (oct->chip_id == OCTEON_CN83XX_VF)
			octeon_swap_8B_data((uint64_t *) &(info->length), 1);

		if(cavium_unlikely(!info->length)) {
			cavium_error("OCTEON:DROQ[%d] idx: %d len:0, pkt_cnt: %d \n",
			             droq->q_no, droq->host_read_index, pkt_count);
			cavium_error_print_data((uint8_t *)info, OCT_DROQ_INFO_SIZE);
			pkt++;

			break;
		}

		/* Len of resp hdr in included in the received data len. */
		info->length -= OCT_RESP_HDR_SIZE;
		resp_hdr     = &info->resp_hdr;
		total_len    += info->length;

        //printk("droq_buf_size:%d packet len:%d\n",(int)droq->buffer_size,(int)info->length);
#ifndef BUFPTR_ONLY_MODE
		if(info->length <= droq->buffer_size) {
#else
		if(info->length <= (droq->buffer_size - sizeof(octeon_droq_info_t))) {
#endif

			void *buf;
			/* Get DMA buffer from Device */
			cnnic_pci_dma_sync_single_for_cpu(oct->pci_dev,
				(unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr,
			    RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);

			pkt_len = info->length;
			buf = droq->recv_buf_list[droq->host_read_index].buffer;

			/* Build skb from the data buffer.
			 * Passing 0 as second argument to notify that the data buffer
			 * is allocated by using kmalloc and not by page allocator
			 * build_skb() allocates skb buffer and initializes it.
			 * newly allocated skb data buffer points to the buffer 
			 * provided as first argument */
			nicbuf = cav_net_build_skb(buf, 0);
			if(nicbuf != NULL) {
				/* Allocate header room in the SKB */
				cav_net_skb_reserve(nicbuf, CAV_NET_SKB_PAD);

#ifdef BUFPTR_ONLY_MODE
			nicbuf->data += sizeof(octeon_droq_info_t);
			nicbuf->tail += sizeof(octeon_droq_info_t);
#endif

				/* Set data length in SKB */
				cav_net_skb_put(nicbuf, pkt_len);

				//printk("Number of users before skb_get:%d\n",atomic_read(&nicbuf->users));
				/* Increment SKB user count to avoid data buffer free */
				cav_net_skb_get(nicbuf);
				//printk("Number of users after skb_get:%d\n",atomic_read(&nicbuf->users));

				/* Store skb buffer address to retrive it in refill thread */
				droq->recv_buf_list[droq->host_read_index].skbptr = (void *)nicbuf;
			}
			/* To indicate refill thread that buffer can be reused 
			 * since we are not sending it to stack */
			else
				droq->recv_buf_list[droq->host_read_index].skbptr = NULL;

			/* Increment host_read index */
			INCR_INDEX_BY1(droq->host_read_index, droq->max_count);
			bufs_used++;

		} else {
			nicbuf  = cav_net_buff_rx_alloc(info->length, droq->app_ctx);
			if(cavium_unlikely(!nicbuf)) {
				printk("Failed to allocate skb buffer\n");
				return pkt;
			}
            //printk("Received jumbo packet with size:%d. copying to the new skb\n",(int)info->length);
			pkt_len = 0;
			while(pkt_len < info->length) {
				int copy_len = 0;
				copy_len = ((pkt_len + droq->buffer_size) > info->length)?(info->length - pkt_len):droq->buffer_size;

				/* Get DMA buffer from device */
				cnnic_pci_dma_sync_single_for_cpu(oct->pci_dev,
					(unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr,
					RCV_BUF_MAP_SIZE, CAVIUM_PCI_DMA_FROMDEVICE);

#ifdef BUFPTR_ONLY_MODE
				if(!pkt_len) {
					copy_len = ((pkt_len + droq->buffer_size - sizeof(octeon_droq_info_t)) > info->length)?(info->length - pkt_len):(droq->buffer_size - sizeof(octeon_droq_info_t));

					cavium_memcpy(recv_buf_put(nicbuf, copy_len),
						droq->recv_buf_list[droq->host_read_index].buffer + CAV_NET_SKB_PAD + sizeof(octeon_droq_info_t), copy_len);
				}
				else {
#endif       
					copy_len = ((pkt_len + droq->buffer_size) > info->length)?(info->length - pkt_len):droq->buffer_size;
    
					cavium_memcpy(recv_buf_put(nicbuf, copy_len),
						droq->recv_buf_list[droq->host_read_index].buffer + CAV_NET_SKB_PAD, copy_len);
#ifdef BUFPTR_ONLY_MODE
				}
#endif

				/* To indicate refill thread that buffer can be reused 
				 * since we are not sending it to stack */
				droq->recv_buf_list[droq->host_read_index].skbptr = NULL;
				
				pkt_len += copy_len;
				INCR_INDEX_BY1(droq->host_read_index, droq->max_count);
				bufs_used++;
			}
		}

		if(cavium_likely(nicbuf)) {
			if(cavium_likely(droq->ops.fptr)) {
#ifdef OCT_NIC_USE_NAPI
				droq->ops.fptr(oct->octeon_id, nicbuf, pkt_len, resp_hdr,
					(pkt_count < OCTEON_PKTPUSH_THRESHOLD) && (pkt == (pkt_count - 1)), &droq->napi);
#else
				/* tuned for TCP_RR/STREAM perf: add last packet arg: speed-up packet push */
				droq->ops.fptr(oct->octeon_id, nicbuf, pkt_len, resp_hdr,
					(pkt_count < OCTEON_PKTPUSH_THRESHOLD) && (pkt == (pkt_count - 1)), NULL);
#endif
			}
			else
				free_recv_buffer(nicbuf);
		}

	}  /* for ( each packet )... */
// *INDENT-ON*

	/* Increment refill_count by the number of buffers processed. */
	droq->refill_count += bufs_used;

	droq->stats.pkts_received += pkt;
	droq->stats.bytes_received += total_len;

	if ((droq->ops.drop_on_max) && (pkts_to_process - pkt)) {
		octeon_droq_drop_packets(droq, (pkts_to_process - pkt));
		droq->stats.dropped_toomany += (pkts_to_process - pkt);
		return pkts_to_process;
	}

	return pkt;
}
#endif

#if !defined(ETHERPCI)

static uint32_t
octeon_droq_slow_process_packets(octeon_device_t * oct,
				 octeon_droq_t * droq, uint32_t pkts_to_process)
{
	octeon_resp_hdr_t *resp_hdr;
	uint32_t desc_processed = 0;
	octeon_droq_info_t *info;
	uint32_t pkt, pkt_count, buf_cnt = 0;

	if (pkts_to_process > droq->pkts_per_intr)
		pkt_count = droq->pkts_per_intr;
	else
		pkt_count = pkts_to_process;

	for (pkt = 0; pkt < pkt_count; pkt++) {
#ifndef BUFPTR_ONLY_MODE
		info = &(droq->info_list[droq->host_read_index]);
#else
		info =
		    (octeon_droq_info_t
		     *) (droq->recv_buf_list[droq->host_read_index].data);
#endif
		resp_hdr = (octeon_resp_hdr_t *) & info->resp_hdr;

		/* Swap length field on 83xx*/
		if (oct->chip_id == OCTEON_CN83XX_VF || oct->chip_id == OCTEON_CN93XX_VF)
			octeon_swap_8B_data((uint64_t *) &(info->length), 1);

		if (cavium_unlikely(!info->length)) {
			cavium_error
			    ("OCTEON:DROQ[idx: %d]: len:%llx, pkt_cnt: %d \n",
			     droq->host_read_index, CVM_CAST64(info->length),
			     pkt_count);
			cavium_error_print_data((uint8_t *) info,
						OCT_DROQ_INFO_SIZE);

			pkt++;
			break;
		}

		/* Len of resp hdr in included in the received data len. */
		info->length -= OCT_RESP_HDR_SIZE;
		droq->stats.bytes_received += info->length;

		buf_cnt = octeon_droq_dispatch_pkt(oct, droq, resp_hdr, info);

		INCR_INDEX(droq->host_read_index, buf_cnt, droq->max_count);
		droq->refill_count += buf_cnt;
		desc_processed += buf_cnt;
	}			/* for ( each packet )... */

	droq->stats.pkts_received += pkt;

	if ((droq->ops.drop_on_max) && (pkts_to_process - pkt)) {
		octeon_droq_drop_packets(droq, (pkts_to_process - pkt));
		droq->stats.dropped_toomany += (pkts_to_process - pkt);
		return pkts_to_process;
	}

	return pkt;
}

#endif

#ifdef  PERF_MODE

static int droq_pkts = 0;

static inline int
octeon_droq_process_packets(octeon_device_t * oct, octeon_droq_t * droq)
{
	static uint8_t allow_core_active_pkt = 1;
	uint32_t pkt_count = 0, pkts_processed = 0, desc_refilled = 0, i = 0;
	cavium_list_t *tmp, *tmp2;

	pkt_count = cavium_atomic_read(&droq->pkts_pending);
	if (!pkt_count)
		return 0;

	/* Grab the lock */
	cavium_spin_lock(&droq->lock);

	if (allow_core_active_pkt) {
		for (i = 0; i < pkt_count; i++) {
			octeon_droq_info_t *info;
			uint32_t buf_cnt;

			droq_pkts++;
#ifndef BUFPTR_ONLY_MODE
			info = &(droq->info_list[droq->host_read_index]);
#else
			info =
			    (octeon_droq_info_t
			     *) (droq->recv_buf_list
				 [droq->host_read_index].data);
#endif

			/* Swap length field on 83xx*/
			if (oct->chip_id == OCTEON_CN83XX_VF)
				octeon_swap_8B_data((uint64_t *) &(info->length), 1);

			buf_cnt = 0;
			if (cavium_likely(info->length)) {
				droq->stats.bytes_received += info->length;
				info->length -= OCT_RESP_HDR_SIZE;
				buf_cnt =
				    octeon_droq_get_bufcount(droq->buffer_size,
							     info->length);
			}
			INCR_INDEX(droq->host_read_index, buf_cnt,
				   droq->max_count);
			droq->refill_count += buf_cnt;
		}

		droq->stats.pkts_received += pkt_count;
		droq->stats.dropped_toomany += pkt_count;
		cavium_atomic_sub(pkt_count, &droq->pkts_pending);

		if (droq->refill_count >= droq->refill_threshold) {
			uint32_t desc_refilled = octeon_droq_refill(oct, droq);
			cavium_flush_write();
			OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
		}

		/* Release the spin lock */
		cavium_spin_unlock(&droq->lock);

	} else {
		allow_core_active_pkt = 0;

		cavium_print(PRINT_DEBUG,
			     "\n droq_process_packets called for:%d, fastpath: %d\n",
			     droq->q_no, droq->fastpath_on);
		if (droq->fastpath_on)
			pkts_processed =
			    octeon_droq_fast_process_packets(oct, droq,
							     pkt_count);
		else {
#if defined(ETHERPCI)
			octeon_droq_drop_packets(droq, pkt_count);
			droq->stats.dropped_toomany += pkt_count;
			pkts_processed = pkt_count;
#else
			pkts_processed =
			    octeon_droq_slow_process_packets(oct, droq,
							     pkt_count);
#endif
		}
		cavium_atomic_sub(pkts_processed, &droq->pkts_pending);

		if (droq->refill_count >= droq->refill_threshold) {
			desc_refilled = octeon_droq_refill(oct, droq);
			cavium_flush_write();
			OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
		}
		/* Release the spin lock */
		cavium_spin_unlock(&droq->lock);

// *INDENT-OFF*
		cavium_list_for_each_safe(tmp, tmp2, &droq->dispatch_list) {
			struct __dispatch *rdisp = (struct __dispatch *)tmp;
			cavium_list_del(tmp);
			rdisp->disp_fn(rdisp->rinfo,
                        	  octeon_get_dispatch_arg(oct, rdisp->rinfo->recv_pkt->resp_hdr.opcode));
		}
// *INDENT-ON*
	}

	/* If there are packets pending. schedule tasklet again */
	if (cavium_atomic_read(&droq->pkts_pending))
		return 1;

	return 0;

}

#else

static inline int
octeon_droq_process_packets(octeon_device_t * oct, octeon_droq_t * droq)
{
	uint32_t pkt_count = 0, pkts_processed = 0, desc_refilled = 0;
	cavium_list_t *tmp, *tmp2;

	pkt_count = cavium_atomic_read(&droq->pkts_pending);
	if (!pkt_count)
		return 0;

	/* Grab the lock */
	cavium_spin_lock(&droq->lock);

	cavium_print(PRINT_DEBUG,
		     "\n droq_process_packets called for:%d, fastpath: %d\n",
		     droq->q_no, droq->fastpath_on);
	if (droq->fastpath_on)
#ifdef OCT_REUSE_RX_BUFS
		pkts_processed =
		    octeon_droq_fast_process_packets_reuse_bufs(oct, droq,
								pkt_count);
#else
		pkts_processed =
		    octeon_droq_fast_process_packets(oct, droq, pkt_count);
#endif
	else {
#if defined(ETHERPCI)
		octeon_droq_drop_packets(droq, pkt_count);
		droq->stats.dropped_toomany += pkt_count;
		pkts_processed = pkt_count;
#else
		pkts_processed =
		    octeon_droq_slow_process_packets(oct, droq, pkt_count);
#endif
	}
	cavium_atomic_sub(pkts_processed, &droq->pkts_pending);

	if (droq->refill_count >= droq->refill_threshold) {
		desc_refilled = octeon_droq_refill(oct, droq);
		cavium_flush_write();
		OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
	}

	/* Release the spin lock */
	cavium_spin_unlock(&droq->lock);


// *INDENT-OFF*
	cavium_list_for_each_safe(tmp, tmp2, &droq->dispatch_list) {
		struct __dispatch *rdisp = (struct __dispatch *)tmp;
		cavium_list_del(tmp);
		rdisp->disp_fn(rdisp->rinfo,
			octeon_get_dispatch_arg(oct, rdisp->rinfo->recv_pkt->resp_hdr.opcode));
	}
// *INDENT-ON*

	/* If there are packets pending. schedule tasklet again */
	if (cavium_atomic_read(&droq->pkts_pending))
		return 1;

	return 0;
}

/**
 * Utility function to poll for packets. check_hw_for_packets must be
 * called before calling this routine.
 */

int octeon_droq_poll_packets(octeon_device_t * oct, octeon_droq_t * droq)
{
	return octeon_droq_process_packets(oct, droq);
}

#endif

#ifdef  USE_DROQ_THREADS

static int oct_droq_thread(void *arg)
{
	char name[] = "Octeon DROQ Thread";
	octeon_droq_t *droq = (octeon_droq_t *) arg;

	cavium_atomic_set(&droq->thread_active, 1);

	cavium_print_msg
	    ("OCTEON[%d]: %s %d starting execution now on CPU %d!\n",
	     droq->oct_dev->octeon_id, name, droq->q_no, smp_processor_id());

	while (!droq->stop_thread && !cavium_kthread_signalled()) {

		while (cavium_atomic_read(&droq->pkts_pending))
			octeon_droq_process_packets(droq->oct_dev, droq);

		cavium_sleep_atomic_cond(&droq->wc, &droq->pkts_pending);
	}

	cavium_print_msg("OCTEON[%d]: DROQ thread quitting now\n",
			 droq->oct_dev->octeon_id);
	cavium_atomic_set(&droq->thread_active, 0);

	return 0;
}

#endif

static int
octeon_droq_process_poll_pkts(octeon_device_t * oct,
			      octeon_droq_t * droq, uint32_t budget)
{
	uint32_t pkts_available = 0, pkts_processed = 0, total_pkts_processed =
	    0;

	if (budget > droq->max_count)
		budget = droq->max_count;

	cavium_spin_lock(&droq->lock);

	while (total_pkts_processed < budget) {

		pkts_available = CVM_MIN((budget - total_pkts_processed),
					 (uint32_t) (cavium_atomic_read
						     (&droq->pkts_pending)));
		if (pkts_available == 0)
			break;
#ifdef OCT_REUSE_RX_BUFS
		pkts_processed =
		    octeon_droq_fast_process_packets_reuse_bufs(oct, droq,
								pkts_available);
#else
		pkts_processed = octeon_droq_fast_process_packets(oct, droq,
								  pkts_available);
#endif

		cavium_atomic_sub(pkts_processed, &droq->pkts_pending);

		total_pkts_processed += pkts_processed;

		octeon_droq_check_hw_for_pkts(oct, droq);
	}

	if (droq->refill_count >= droq->refill_threshold) {
		int desc_refilled = octeon_droq_refill(oct, droq);
		cavium_flush_write();
		OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
	}
	cavium_spin_unlock(&droq->lock);

	//printk("%s:%d pkts_processed:%d\n",__func__,__LINE__,total_pkts_processed);
	return total_pkts_processed;
}

#if 0
static int
octeon_droq_process_poll_pkts(octeon_device_t * oct,
			      octeon_droq_t * droq, uint32_t budget)
{
	uint32_t pkts_available = 0, pkts_processed = 0, total_pkts_processed =
	    0;

	if (budget > droq->max_count)
		budget = droq->max_count;

	cavium_spin_lock(&droq->lock);

	pkts_available =
	    CVM_MIN(budget, (cavium_atomic_read(&droq->pkts_pending)));

process_some_more:
	pkts_processed =
	    octeon_droq_fast_process_packets(oct, droq, pkts_available);
	cavium_atomic_sub(pkts_processed, &droq->pkts_pending);
	total_pkts_processed += pkts_processed;

	if (total_pkts_processed < budget) {
		octeon_droq_check_hw_for_pkts(oct, droq);
		if (cavium_atomic_read(&droq->pkts_pending)) {
			pkts_available =
			    CVM_MIN((budget - total_pkts_processed),
				    (cavium_atomic_read(&droq->pkts_pending)));
			goto process_some_more;
		}
	}

	if (droq->refill_count >= droq->refill_threshold) {
		int desc_refilled = octeon_droq_refill(oct, droq);
		cavium_flush_write();
		OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
	}

	cavium_spin_unlock(&droq->lock);

	return total_pkts_processed;
}
#endif

int
octeon_process_droq_poll_cmd(int oct_id, uint32_t q_no, int cmd, uint32_t arg)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_droq_t *droq;
	//octeon_config_t *oct_cfg = NULL;

	if (cavium_unlikely(!oct)) {
		cavium_error(" %s: No Octeon device (id: %d)\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}
#if 0
	oct_cfg = octeon_get_conf(oct);

	if (!oct_cfg)
		return -EINVAL;

	if (q_no >= CFG_GET_OQ_MAX_Q(oct_cfg)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, (oct->num_oqs - 1));
		return -EINVAL;
	}
#endif	
	if (cavium_unlikely(q_no >= oct->num_oqs)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, (oct->num_oqs - 1));
		return -EINVAL;
	}

	droq = oct->droq[q_no];

	if (cmd == POLL_EVENT_PROCESS_PKTS) {
		//printk("%s: droq->q_no: %d cpu:%d\n",__func__,droq->q_no,smp_processor_id());
		return octeon_droq_process_poll_pkts(oct, droq, arg);
	}

	if (cmd == POLL_EVENT_ENABLE_INTR) {
		/* Need to enable Pkt Interrupt, add for VF interrupt IMP */
		switch (oct->chip_id) {

		case OCTEON_CN83XX_VF:{
                droq = oct->droq[q_no];
				//printk("Enabled interupt on q:%d irq:%d\n",q_no,droq->irq_num);
                cavium_enable_irq(droq->irq_num);
				break;
			}
		}

		return 0;
	}

	cavium_error("%s Unknown command: %d\n", __FUNCTION__, cmd);
	return -EINVAL;
}

int octeon_register_droq_ops(int oct_id, uint32_t q_no, octeon_droq_ops_t * ops)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_droq_t *droq;
	unsigned long flags;
	//octeon_config_t *oct_cfg = NULL;

	if (cavium_unlikely(oct)) {
		cavium_error(" %s: No Octeon device (id: %d)\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}
#if 0	
	oct_cfg = octeon_get_conf(oct);

	if (!oct_cfg)
		return -EINVAL;
#endif		

	if (cavium_unlikely(!ops)) {
		cavium_error(" %s: droq_ops pointer is NULL\n",
			     __CVM_FUNCTION__);
		return -EINVAL;
	}

#if 0
	if (q_no >= CFG_GET_OQ_MAX_Q(oct_cfg)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, (oct->num_oqs - 1));
		return -EINVAL;
	}
#endif	
	if (cavium_unlikely(q_no >= oct->num_oqs)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, (oct->num_oqs - 1));
		return -EINVAL;
	}
#ifdef  USE_DROQ_THREADS
	if (ops->poll_mode) {
		cavium_error
		    (" %s: Cannot Support Polling when BASE Driver uses DROQ Threads. \n",
		     __CVM_FUNCTION__);
		return -EINVAL;
	}
#endif

	droq = oct->droq[q_no];

	cavium_spin_lock_irqsave(&droq->lock, flags);

	memcpy(&droq->ops, ops, sizeof(octeon_droq_ops_t));

	if (droq->ops.fptr)
		droq->fastpath_on = 1;

	cavium_spin_unlock_irqrestore(&droq->lock, flags);

	return 0;
}

int octeon_unregister_droq_ops(int oct_id, uint32_t q_no)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_droq_t *droq;
	//octeon_config_t *oct_cfg = NULL;

	if (cavium_unlikely(!oct)) {
		cavium_error(" %s: No Octeon device (id: %d)\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}
#if 0
	oct_cfg = octeon_get_conf(oct);

	if (!oct_cfg)
		return -EINVAL;

	if (q_no >= CFG_GET_OQ_MAX_Q(oct_cfg)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, oct->num_oqs - 1);
		return -EINVAL;
	}
#endif	
	if (cavium_unlikely(q_no >= oct->num_oqs)) {
		cavium_error(" %s: droq id (%d) exceeds MAX (%d)\n",
			     __CVM_FUNCTION__, q_no, (oct->num_oqs - 1));
		return -EINVAL;
	}

	droq = oct->droq[q_no];

	if (cavium_unlikely(!droq)) {
		cavium_print_msg("Droq id (%d) not available.\n", q_no);
		return 0;
	}

	cavium_spin_lock(&droq->lock);

#ifdef OCT_NIC_USE_NAPI
	/* reset napi related structures */
	droq->ops.napi_fun = NULL;
	droq->ops.poll_mode = 0;
#endif

	droq->fastpath_on = 0;
	droq->ops.fptr = NULL;
	droq->ops.drop_on_max = 0;
#if  defined(FAST_PATH_DROQ_DISPATCH)
	droq->ops.op_mask = 0;
	droq->ops.op_major = 0;
#endif

	cavium_spin_unlock(&droq->lock);

	return 0;
}

oct_poll_fn_status_t check_droq_refill(void *octptr, unsigned long q_no)
{
	octeon_device_t *oct = (octeon_device_t *) octptr;
	octeon_droq_t *droq;

	droq = oct->droq[q_no];

	if (droq->refill_count >= droq->refill_threshold) {
		uint32_t desc_refilled;

		cavium_spin_lock_softirqsave(&droq->lock);
		desc_refilled = octeon_droq_refill(oct, droq);
		if (desc_refilled) {
			cavium_flush_write();
			OCTEON_WRITE32(droq->pkts_credit_reg, desc_refilled);
		}
		cavium_spin_unlock_softirqrestore(&droq->lock);
	}

	return OCT_POLL_FN_CONTINUE;
}

int32_t octeon_create_droq(octeon_device_t * oct, int q_no, void *app_ctx)
{
	octeon_droq_t *droq;

	cavium_print(PRINT_DEBUG, "octeon_create_droq for droq:%d ----\n",
		     q_no);
	if (cavium_unlikely(oct->droq[q_no])) {
		cavium_error
		    ("Droq already in use. Cannot create droq %d again\n",
		     q_no);
		return -1;
	}

	/* Allocate the DS for the new droq. */
	droq = cavium_alloc_virt(sizeof(octeon_droq_t));
	if (droq == NULL)
		goto create_droq_fail;
	cavium_memset(droq, 0, sizeof(octeon_droq_t));

	cavium_print(PRINT_DEBUG, "create_droq: q_no: %d\n", q_no);

	/*Disable the pkt o/p for this Q  */
	octeon_set_droq_pkt_op(oct, q_no, 0);
	oct->droq[q_no] = droq;

	/* Initialize the Droq */
	octeon_init_droq(oct, q_no, app_ctx);

	oct->num_oqs++;

	cavium_print(PRINT_DEBUG, "create_droq: Toatl number of OQ: %d\n",
		     oct->num_oqs);

	/* Global Droq register settings */

	/* As of now not required, as setting are done for all 32 Droqs at the same time. 
	 */
	return 0;

create_droq_fail:
	octeon_delete_droq(oct, q_no);
	return -1;

}

/* $Id: octeon_droq.c 118468 2015-05-27 11:26:18Z vattunuru $ */
