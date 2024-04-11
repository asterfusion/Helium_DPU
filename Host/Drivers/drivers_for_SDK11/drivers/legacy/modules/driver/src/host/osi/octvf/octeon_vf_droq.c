/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_main.h"
#include "octeon_debug.h"
#include "octeon_macros.h"
#include "octeon_hw.h"
#include "octeon_network.h"

uint32_t octeon_droq_refill(octeon_device_t * octeon_dev, octeon_droq_t * droq);

oct_poll_fn_status_t check_droq_refill(void *octptr, unsigned long q_no);

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
	uint32_t pkt_count = 0;
	uint32_t new_pkts;

	pkt_count = OCTEON_READ32(droq->pkts_sent_reg);
	new_pkts = pkt_count - droq->last_pkt_count;
//	printk("%s: Q-%d pkt_count(sent_reg):%u last_cnt:%u pkts_pending:%u\n",
//		__func__, droq->q_no, pkt_count, droq->last_pkt_count, droq->pkts_pending);

	while (unlikely(pkt_count > 0xF0000000U)) {
		/* TODO: should be handled differently for OCT_TX2_ISM_INT ?? */
		OCTEON_WRITE32(droq->pkts_sent_reg, pkt_count);
		pkt_count = OCTEON_READ32(droq->pkts_sent_reg);
		if (pkt_count == 0xFFFFFFFF) {
			new_pkts = 0;
			pkt_count = 0;
			printk("VF detected PCIe read error F's in %s \n",__func__);
			break;
		}
		printk("In loop VF detected PCIe read error F's in %s \n",__func__);
		new_pkts += pkt_count;
	}

	droq->last_pkt_count = pkt_count;
	if (new_pkts)
		droq->pkts_pending += new_pkts;
	return new_pkts;
}
int octeon_droq_check_hw_for_pkts_ism(octeon_device_t * oct, octeon_droq_t * droq)
{
	uint32_t new_pkts;
	uint32_t pkt_count;

	pkt_count = droq->ism.pkt_cnt_addr[droq->ism.index];
	new_pkts = pkt_count - droq->last_pkt_count;
	droq->last_pkt_count = pkt_count;
	if (new_pkts) {
		/*
		 * Request an ISM write, so next poll in NAPI mode will have
		 * an updated count.
		 * If we don't have new packets, we will exit the NAPI poll loop,
		 * and a new IRQ/ISM will be requested on that NAPI complete
		 * path.
		 */
		OCTEON_WRITE64(droq->pkts_sent_reg, 1ULL << 63);
		droq->pkts_pending += new_pkts;
	}
	return new_pkts;
}

void oct_dump_droq_state(octeon_droq_t * oq)
{

	cavium_print_msg("DROQ[%d] state dump\n", oq->q_no);
	cavium_print_msg("Attr: Size: %u Pkts/intr: %u  refillafter: %u\n",
			 oq->max_count, oq->pkts_per_intr,
			 oq->refill_threshold);
	cavium_print_msg
	    ("Attr: fastpath: %s poll_mode: %s drop_on_max: %s napi_fn: %p\n",
	     (oq->fastpath_on) ? "ON" : "OFF",
	     (oq->ops.poll_mode) ? "ON" : "OFF",
	     (oq->ops.drop_on_max) ? "ON" : "OFF",
	     oq->ops.napi_fn);

	cavium_print_msg("idx:  read: %u write: %u  refill: %u\n",
			 oq->host_read_index, oq->octeon_write_index,
			 oq->host_refill_index);

	cavium_print_msg("Pkts: pending: %u forrefill: %u\n",
			 oq->pkts_pending,
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
	 * If the empty desc count goes beyond this value, we cannot safely 
	 * read in a 64K packet sent by Octeon (64K is max pkt size from Octeon)
	 */
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
	droq->last_pkt_count = 0;
	droq->pkts_pending = 0;
}

// *INDENT-OFF*
static void
octeon_droq_destroy_ring_buffers(octeon_device_t  *oct UNUSED, octeon_droq_t  *droq)
{
	uint32_t  i;

	for(i = 0; i < droq->max_count; i++)  {
		if(droq->recv_buf_list[i].buffer) {
			if(droq->desc_ring) {
				octeon_pci_unmap_single(oct->pci_dev, (unsigned long)droq->desc_ring[i].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE );
			}
			free_recv_buffer(droq->recv_buf_list[i].buffer);
		}
	}


	octeon_droq_reset_indices(droq);
}
// *INDENT-ON*

static int
octeon_droq_setup_ring_buffers(octeon_device_t * oct UNUSED,
			       octeon_droq_t * droq)
{
	uint32_t i;
	void *buf;
	octeon_droq_desc_t *desc_ring = droq->desc_ring;

	for (i = 0; i < droq->max_count; i++) {

		buf = cav_net_buff_rx_alloc(droq->buffer_size, droq->app_ctx);
		if (cavium_unlikely(!buf)) {
			cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
			return -ENOMEM;
		}

		droq->recv_buf_list[i].buffer = buf;
		droq->recv_buf_list[i].data =
		    get_recv_buffer_data(buf, droq->app_ctx);


		desc_ring[i].buffer_ptr =
		    (uint64_t) cnnic_pci_map_single(oct->pci_dev,
						    droq->recv_buf_list[i].data,
						    droq->buffer_size,
						    CAVIUM_PCI_DMA_FROMDEVICE,
						    droq->app_ctx);
		if (octeon_pci_mapping_error(oct->pci_dev,
					     desc_ring[i].buffer_ptr)) {
			cavium_error("pci dma mapping error\n");
			free_recv_buffer(droq->recv_buf_list[i].buffer);
			droq->recv_buf_list[i].buffer = NULL;
			droq->recv_buf_list[i].data = NULL;
			return -ENOMEM;
		}
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

	octeon_droq_destroy_ring_buffers(oct, droq);

	if (droq->recv_buf_list)
		cavium_free_virt(droq->recv_buf_list);

	if (droq->ism.pkt_cnt_addr)
		octeon_pci_free_consistent(oct->pci_dev, OCTEON_ISM_OQ_MEM_SIZE,
					   droq->ism.pkt_cnt_addr, droq->ism.pkt_cnt_dma,
					   droq->app_ctx);

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

	if (OCTEON_CN83XX_VF(oct->chip_id)) {
		cn83xx_vf_config_t *conf83 = CHIP_FIELD(oct, cn83xx_vf, conf);
		c_num_descs = CFG_GET_OQ_NUM_DESC(conf83);
		c_buf_size = CFG_GET_OQ_BUF_SIZE(conf83);
		c_pkts_per_intr = CFG_GET_OQ_PKTS_PER_INTR(conf83);
		c_refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(conf83);
	} else if (OCTEON_CN9XXX_VF(oct->chip_id)) {
		cn93xx_vf_config_t *conf93 = CHIP_FIELD(oct, cn93xx_vf, conf);
		c_num_descs = CFG_GET_OQ_NUM_DESC(conf93);
		c_buf_size = CFG_GET_OQ_BUF_SIZE(conf93);
		c_pkts_per_intr = CFG_GET_OQ_PKTS_PER_INTR(conf93);
		c_refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(conf93);
	} else if (OCTEON_CNXK_VF(oct->chip_id)) {
		cnxk_vf_config_t *conf_cnxk = CHIP_FIELD(oct, cnxk_vf, conf);
		c_num_descs = CFG_GET_OQ_NUM_DESC(conf_cnxk);
		c_buf_size = CFG_GET_OQ_BUF_SIZE(conf_cnxk);
		c_pkts_per_intr = CFG_GET_OQ_PKTS_PER_INTR(conf_cnxk);
		c_refill_threshold = CFG_GET_OQ_REFILL_THRESHOLD(conf_cnxk);
	}

	droq->max_count = c_num_descs;
	droq->buffer_size = c_buf_size;
	droq->max_single_buffer_size = c_buf_size - sizeof(octeon_droq_info_t);
	if (c_num_descs & (c_num_descs-1)) {
		printk(KERN_ERR
		       "OCTEON_VF: ring size must be a power of 2; current size = %u\n",
		       c_num_descs);
		return -1;
	}
	droq->ring_size_mask = c_num_descs - 1;

	desc_ring_size = droq->max_count * OCT_DROQ_DESC_SIZE;
	droq->desc_ring =
	    octeon_pci_alloc_consistent(oct->pci_dev, desc_ring_size,
					&droq->desc_ring_dma, droq->app_ctx);

	if (cavium_unlikely(!droq->desc_ring)) {
		cavium_error("OCTEON_VF[%d]: Output queue %d ring alloc failed\n",
			     oct->octeon_id, q_no);
		return 1;
	}

	cavium_print(PRINT_REGS, "droq[%d]: desc_ring: virt: 0x%px, dma: %lx",
		     q_no, droq->desc_ring, droq->desc_ring_dma);
	cavium_print(PRINT_REGS, "droq[%d]: num_desc: %d",
		     q_no, droq->max_count);

	droq->check_hw_for_pkts = octeon_droq_check_hw_for_pkts;
	if (OCT_DROQ_ISM) {
		if (OCTEON_CN9XXX_VF(oct->chip_id) || OCTEON_CNXK_VF(oct->chip_id)) {
			droq->ism.pkt_cnt_addr =
			    octeon_pci_alloc_consistent(oct->pci_dev, OCTEON_ISM_OQ_MEM_SIZE,
							&droq->ism.pkt_cnt_dma, droq->app_ctx);

			if (cavium_unlikely(!droq->ism.pkt_cnt_addr)) {
				cavium_error("OCTEON_VF: Output queue %d ism memory alloc failed\n",
					     q_no);
				return 1;
			}

			cavium_print(PRINT_REGS, "droq[%d]: ism addr: virt: 0x%p, dma: %lx",
				     q_no, droq->ism.pkt_cnt_addr, droq->ism.pkt_cnt_dma);
			droq->ism.pkt_cnt_addr[droq->ism.index] = 0;
			droq->check_hw_for_pkts = octeon_droq_check_hw_for_pkts_ism;
			printk_once("OCTEON_VF[%d]: using ISM for output queue management\n",
					 oct->octeon_id);
		} else {
			printk_once("OCTEON_VF[%d]: using CSR reads for output queue management\n",
					 oct->octeon_id);
		}
	}


	droq->recv_buf_list = (octeon_recv_buffer_t *)
	    cavium_alloc_virt(droq->max_count * OCT_DROQ_RECVBUF_SIZE);
	if (cavium_unlikely(!droq->recv_buf_list)) {
		cavium_error
		    ("OCTEON_VF[%d]: Output queue recv buf list alloc failed\n",
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

	/* Send a command to Octeon to stop further packet processing */
	if (octeon_send_short_command(oct, DEVICE_STOP_OP,
				      (q_no << 8 | DEVICE_PKO), respbuf, 4)) {
		cavium_error("%s command failed\n", __CVM_FUNCTION__);
		retval = -EINVAL;
		goto shutdown_oq_done;
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

	/* Disable the output queues */
	oct->fn_list.disable_output_queue(oct, q_no);

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

	/* Enable the output queues */
	oct->fn_list.enable_output_queue(oct, q_no);

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

int
octeon_reset_recv_buf_size(octeon_device_t * oct, int q_no, uint32_t newsize)
{
	int num_qs = 1, oq_no = q_no;

	if (!newsize) {
		cavium_error("%s Invalid buffer size (%d)\n", __CVM_FUNCTION__,
			     newsize);
		return -EINVAL;
	}

	/**
	 * If the new buffer size is smaller than the current buffer size, do not
	 * do anything. Else change for all rings.
	 */
	if (newsize <= oct->droq[q_no]->buffer_size)
		return 0;

	cavium_print_msg
	    ("%s changing bufsize from %d to %d for %d queues first q: %d\n",
	     __CVM_FUNCTION__, oct->droq[oq_no]->buffer_size, newsize, num_qs,
	     oq_no);
	if (OCTEON_CN83XX_VF(oct->chip_id)) {
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
	uint32_t i = 0, bytes_left;

	cavium_print(PRINT_FLOW, "\n\n----#  create_recv_pkt #----\n");
	info = (octeon_droq_info_t *) (droq->recv_buf_list[idx].data);

	cavium_print(PRINT_DEBUG, "buf_cnt: %d  idx: %d\n", buf_cnt, idx);
	recv_info = octeon_alloc_recv_info(sizeof(struct __dispatch));
	if (!recv_info)
		return NULL;

	recv_pkt = recv_info->recv_pkt;

	recv_pkt->resp_hdr = info->resp_hdr;
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
// *INDENT-ON*
	/* In BUF ptr mode, First buffer contains resp headr and len.
	 * when data spans multiple buffers data present
	 * in first buffer is less than the actual buffer size*/
		if(!i) {
			recv_pkt->buffer_size[i] =
				((bytes_left + sizeof(octeon_droq_info_t) >=
				 droq->buffer_size)) ?
				(droq->buffer_size -
				 sizeof(octeon_droq_info_t)) : bytes_left;

			bytes_left -= (droq->buffer_size -
				       sizeof(octeon_droq_info_t));
		}
		else
		{
			recv_pkt->buffer_size[i] =
				(bytes_left >= droq->buffer_size) ?
				droq->buffer_size : bytes_left;
			bytes_left -= droq->buffer_size;
		}

		recv_pkt->buffer_ptr[i] = droq->recv_buf_list[idx].buffer;

		/* Done for IOMMU: To avoid refilling the buffer index */

		INCR_INDEX_BY1(idx, droq->max_count);
		i++;
		buf_cnt--;
	}

	return recv_info;

}

/**
 * If we were not able to refill all buffers, try to move around
 * the buffers that were not dispatched.
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
	void *buf;
	uint8_t *data;
	uint32_t map = 1;
	uint32_t desc_refilled = 0;

	desc_ring = droq->desc_ring;

	cavium_print(PRINT_DEBUG, "\n\n----#   octeon_droq_refill #----\n");
	cavium_print(PRINT_DEBUG,
		     "refill_count: %d host_refill_index: %d, host_read_index: %d\n",
		     droq->refill_count, droq->host_refill_index,
		     droq->host_read_index);

	while (droq->refill_count && (desc_refilled < droq->max_count)) {
		/* If a valid buffer exists (happens if there is no dispatch), reuse 
		 * the buffer, else allocate. */
		if(droq->recv_buf_list[droq->host_refill_index].buffer == 0)  {
			buf = cav_net_buff_rx_alloc(droq->buffer_size, droq->app_ctx);
			/* If a buffer could not be allocated, no point in continuing */
			if(!buf) {
				cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
				break;
			}
			droq->recv_buf_list[droq->host_refill_index].buffer = buf;
			data = get_recv_buffer_data(buf, droq->app_ctx);
			map = 1;
		} else {
			map = 0;
			data = get_recv_buffer_data(droq->recv_buf_list[droq->host_refill_index].buffer,droq->app_ctx);
		}
// *INDENT-ON*

		droq->recv_buf_list[droq->host_refill_index].data = data;
		if (map) {
			desc_ring[droq->host_refill_index].buffer_ptr =
			    (uint64_t) cnnic_pci_map_single(octeon_dev->pci_dev,
							    data,
							    droq->buffer_size,
							    CAVIUM_PCI_DMA_FROMDEVICE,
							    droq->app_ctx);
			if (octeon_pci_mapping_error(octeon_dev->pci_dev,
						     desc_ring[droq->host_refill_index].buffer_ptr)) {
				cavium_error("pci dma mapping error\n");
				free_recv_buffer(droq->recv_buf_list[droq->host_refill_index].buffer);
				droq->recv_buf_list[droq->host_refill_index].buffer = NULL;
				droq->recv_buf_list[droq->host_refill_index].data = NULL;
				break;
			}
		}

		droq->host_refill_index = (droq->host_refill_index + 1) & droq->ring_size_mask;
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
	 * to close the gap in the ring, but we would still have the same no. of
	 * buffers to refill.
	 */
	return desc_refilled;
}

static inline uint32_t
octeon_droq_get_bufcount(uint32_t buf_size, uint32_t total_len)
{
	uint32_t buf_cnt = 0;

	if (total_len <= (buf_size - sizeof(octeon_droq_info_t))) {
		buf_cnt++;
	} else {
		total_len -= (buf_size - sizeof(octeon_droq_info_t));
		while (total_len > (buf_size * buf_cnt))
			buf_cnt++;

		buf_cnt++;
	}

	return buf_cnt;
}

static inline void octeon_droq_drop_packets(octeon_droq_t * droq, uint32_t cnt)
{
	uint32_t i = 0, buf_cnt;
	octeon_droq_info_t *info;
	octeon_device_t *oct = droq->oct_dev;

	for (i = 0; i < cnt; i++) {
		info =
		    (octeon_droq_info_t
		     *) (droq->recv_buf_list[droq->host_read_index].data);
		/* Swap length field on 83xx*/
		if (OCTEON_CN8PLUS_VF(oct->chip_id))
			octeon_swap_8B_data((uint64_t *) &(info->length), 1);
		/* VSR: TODO: this swap not required for CNXK ? */

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

/** Routine to push packets arriving on Octeon interface upto network layer.
  * @param octeon_id  - pointer to octeon device.
  * @param skbuff     - skbuff struct to be passed to network layer.
  * @param len        - size of total data received.
  * @param resp_hdr   - Response header
  * @param lastpkt    - indicates whether this is last packet to push
  * @param napi       - NAPI handler
  */
void octnet_push_packet(octeon_droq_t *droq,
		   void *skbuff,
		   uint32_t len,
		   octeon_resp_hdr_t * resp_hdr, void *napi)
{
	struct net_device *pndev = droq->pndev;
	struct sk_buff     *skb   = (struct sk_buff *)skbuff;

	skb->dev = pndev;
#ifndef CONFIG_PPORT
	skb->protocol = eth_type_trans(skb, skb->dev);
#else
	if (unlikely(false == (pport_do_receive(skb)))) {
		cavium_print(PRINT_DEBUG,
			     "pport receive error port_id(0x%08x)\n",
			     ntohs(*(__be16 *)skb->data));
		/* TODO: This is in octnic; should be moved here */
		free_recv_buffer(skb);
		droq->stats.dropped_nodispatch++;
		return;
	}
#endif

	if (resp_hdr && resp_hdr->csum_verified == CNNIC_CSUM_VERIFIED)
		skb->ip_summed = CHECKSUM_UNNECESSARY;	/* checksum has already verified on OCTEON */
	else
		skb->ip_summed = CHECKSUM_NONE;

	napi_gro_receive(napi, skb);

	droq->stats.bytes_st_received += len;
	droq->stats.pkts_st_received++;
}

#define OCTEON_PKTPUSH_THRESHOLD	128	/* packet push threshold: TCP_RR/STREAM perf. */

uint32_t
octeon_droq_fast_process_packets(octeon_device_t * oct,
				 octeon_droq_t * droq, uint32_t pkts_to_process)
{
	octeon_droq_info_t *info;
	octeon_resp_hdr_t *resp_hdr = NULL;
	uint32_t pkt, total_len = 0, bufs_used = 0;
#ifdef OCT_NIC_LOOPBACK
	octnet_priv_t *priv = GET_NETDEV_PRIV(droq->pndev);
#endif
	int data_offset;

	for(pkt = 0; pkt < pkts_to_process; pkt++)   {
		uint32_t         pkt_len = 0;
		cavium_netbuf_t  *nicbuf = NULL;

		cnnic_pci_dma_sync_single_for_cpu(oct->pci_dev,
			droq->desc_ring[droq->host_read_index].buffer_ptr,
			droq->buffer_size, CAVIUM_PCI_DMA_BIDIRECTIONAL);
		info = (octeon_droq_info_t *)(droq->recv_buf_list[droq->host_read_index].data);

		/* Prefetch next buffer */
		if (pkts_to_process - pkt > 1)
			prefetch(droq->recv_buf_list[(droq->host_read_index+1) & droq->ring_size_mask].data);

		if(cavium_unlikely(*((volatile uint64_t *)&info->length) == 0)) {
			int retry = 100;

			cavium_print(PRINT_DEBUG,
				     "OCTEON DROQ[%d]: host_read_idx: %d; Data not ready yet, "
				     "Retry; pkt=%u, pkt_count=%u, pending=%u\n",
				     droq->q_no, droq->host_read_index,
				     pkt, pkts_to_process,
				     droq->pkts_pending);
			droq->stats.pkts_delayed_data++;
			while (retry-- && cavium_unlikely(
				*((volatile uint64_t *)&info->length) == 0))
				udelay(50);
			if (cavium_unlikely(!info->length)) {
				printk("OCTEON DROQ[%d]: host_read_idx: %d; Retry failed !!\n",
				       droq->q_no, droq->host_read_index);
				BUG();
			}
		}

		/* Swap length field on 83xx*/
		octeon_swap_8B_data((uint64_t *) &(info->length), 1);

		/* Len of resp hdr is included in the received data len. */
		if (oct->pkind != OTX2_LOOP_PCIE_EP_PKIND) {
			/* No response header in LOOP mode */
			info->length -= OCT_RESP_HDR_SIZE;
			resp_hdr = &info->resp_hdr;
			data_offset = sizeof(octeon_droq_info_t);
		} else
			data_offset = sizeof(octeon_droq_info_t) - OCT_RESP_HDR_SIZE;

		total_len    += info->length;

		if(info->length <= (droq->max_single_buffer_size)) {
			octeon_pci_unmap_single(oct->pci_dev,
				(unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr,
				droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);
			pkt_len = info->length;
			nicbuf = droq->recv_buf_list[droq->host_read_index].buffer;
			nicbuf->data += data_offset;
//			prefetch(nicbuf->data);
			nicbuf->tail += data_offset;
			droq->recv_buf_list[droq->host_read_index].buffer = 0;
			droq->host_read_index = (droq->host_read_index + 1) & droq->ring_size_mask;
			(void)recv_buf_put(nicbuf, pkt_len);
			bufs_used++;
		} else {
			int info_len = info->length;
			/* nicbuf allocation can fail. We'll handle it inside the loop. */
			nicbuf  = cav_net_buff_rx_alloc(info->length, droq->app_ctx);
			if (cavium_unlikely(!nicbuf)) {
				cavium_error("%s buffer alloc failed\n",
				     __CVM_FUNCTION__);
				droq->stats.dropped_nomem++;
			}
			pkt_len = 0;
			/* initiating a csr read helps to flush pending dma */
			droq->sent_reg_val = OCTEON_READ32(droq->pkts_sent_reg);
			smp_rmb();
			while(pkt_len < info_len) {
				int copy_len = 0;
				uint8_t copy_offset;
				uint8_t *data;

				if (pkt_len) {
					if ((info_len - pkt_len) > droq->buffer_size)
						copy_len = droq->buffer_size;
					else
						copy_len = info_len - pkt_len;
					copy_offset = 0;
				} else {
					copy_len = droq->buffer_size - data_offset;
					copy_offset = data_offset;
				}
				cnnic_pci_dma_sync_single_for_cpu(oct->pci_dev, (unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);

				if (cavium_likely(nicbuf))
					cavium_memcpy(recv_buf_put(nicbuf, copy_len),
						      (get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx)) + copy_offset, copy_len);
				/* Remap the buffers after copy is done */
				data = get_recv_buffer_data(droq->recv_buf_list[droq->host_read_index].buffer, droq->app_ctx);
				/* clear info ptr */
				memset(data, 0, 16);
				cnnic_pci_dma_sync_single_for_device(oct->pci_dev, (unsigned long)droq->desc_ring[droq->host_read_index].buffer_ptr, droq->buffer_size, CAVIUM_PCI_DMA_FROMDEVICE);
				pkt_len += copy_len;
				INCR_INDEX_BY1(droq->host_read_index, droq->max_count);
				bufs_used++;
			}
		}
		if (cavium_likely(nicbuf)) {
#ifdef OCT_NIC_LOOPBACK
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
			if (pkt == pkts_to_process - 1)
				nicbuf->xmit_more = 0;
			else
				nicbuf->xmit_more = 1;
#else
			if (pkt == pkts_to_process - 1)
				__this_cpu_write(softnet_data.xmit.more, 0);
			else
				__this_cpu_write(softnet_data.xmit.more, 1);
#endif
			nicbuf->dev = droq->pndev;
			nicbuf->ip_summed = CHECKSUM_UNNECESSARY;
			nicbuf->queue_mapping = droq->q_no;
			priv->priv_xmit(nicbuf, droq->pndev);
			droq->stats.bytes_st_received += pkt_len;
			droq->stats.pkts_st_received++;
#else
			octnet_push_packet(droq, nicbuf,
					   pkt_len, resp_hdr, &droq->napi);
#endif
		}
	}  /* for ( each packet )... */

	/* Increment refill_count by the number of buffers processed. */
	droq->refill_count += bufs_used;

	droq->stats.pkts_received += pkt;
	droq->stats.bytes_received += total_len;

	return pkt;
}

int octeon_droq_process_poll_pkts(octeon_droq_t *droq, uint32_t budget)
{
	uint32_t pkts_available = 0, pkts_processed = 0, total_pkts_processed =
	    0;
	octeon_device_t *oct = droq->oct_dev;

	while (total_pkts_processed < budget) {
		/* update pending count only when current one exhausted */
		if(droq->pkts_pending == 0)
			droq->check_hw_for_pkts(oct, droq);

		pkts_available = CVM_MIN((budget - total_pkts_processed),
					 droq->pkts_pending);
		if (pkts_available == 0)
			break;
		pkts_processed = octeon_droq_fast_process_packets(oct, droq,
								  pkts_available);

		droq->pkts_pending -= pkts_processed;

		total_pkts_processed += pkts_processed;
	}

	if (droq->refill_count >= droq->refill_threshold) {
		int desc_refilled = octeon_droq_refill(oct, droq);
		cavium_flush_write();
		OCTEON_WRITE32(droq->pkts_credit_reg, (desc_refilled));
	}

//	printk("%s:%d Q-%d pkts_processed:%d\n",
//		__func__, __LINE__, droq->q_no, total_pkts_processed);
	return total_pkts_processed;
}

int octeon_register_droq_ops(int oct_id, uint32_t q_no, octeon_droq_ops_t * ops)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_droq_t *droq;
	unsigned long flags;
	//octeon_config_t *oct_cfg = NULL;

	if (cavium_unlikely(!(oct))) {
		cavium_error(" %s: No Octeon device (id: %d)\n",
			     __CVM_FUNCTION__, oct_id);
		return -ENODEV;
	}
#if 0	
	oct_cfg = octeon_get_conf(oct);

	if (!oct_cfg)
		return -EINVAL;
#endif		

	if (cavium_unlikely(!(ops))) {
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

	droq = oct->droq[q_no];

	cavium_spin_lock_irqsave(&droq->lock, flags);

	memcpy(&droq->ops, ops, sizeof(octeon_droq_ops_t));


	cavium_spin_unlock_irqrestore(&droq->lock, flags);

	return 0;
}

int octeon_unregister_droq_ops(int oct_id, uint32_t q_no)
{
	octeon_device_t *oct = get_octeon_device(oct_id);
	octeon_droq_t *droq;
	//octeon_config_t *oct_cfg = NULL;
	if (cavium_unlikely(!(oct))) {
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

	/* reset napi related structures */
	droq->ops.napi_fun = NULL;
	droq->ops.poll_mode = 0;

	droq->fastpath_on = 0;
	droq->ops.drop_on_max = 0;
#if  defined(FAST_PATH_DROQ_DISPATCH)
	droq->ops.op_mask = 0;
	droq->ops.op_major = 0;
#endif

	cavium_spin_unlock(&droq->lock);

	return 0;
}

#if 0
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
#endif

int32_t octeon_create_droq(octeon_device_t * oct, int q_no, void *app_ctx)
{
	octeon_droq_t *droq;

	cavium_print(PRINT_DEBUG, "octeon_create_droq for droq:%d ----\n",
		     q_no);
	if (oct->droq[q_no]) {
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

/*
 * q_cnt = 0,  assign all queues to the pndev
 * q_cnt != 0, assign 'q_cnt' queues starting from 'q_no'
 * 	       q_no to (q_no + q_cnt - 1)
 */
int32_t octeon_droq_set_netdev(octeon_device_t *oct, int q_no, int q_cnt,
			       struct net_device *pndev)
{
	int i, last_q;
	octeon_droq_t *droq;

	if (pndev == NULL) {
		printk(KERN_ERR "OCTNIC: cannot assign droqs to netdev; Invalid device\n");
		return -1;
	}

	last_q = q_no + q_cnt - 1;
	printk(KERN_INFO "OCTNIC: assign Q-%d to Q-%d to netdev %s\n",
			 q_no, last_q, pndev->name);
	if (last_q >= oct->num_oqs) {
		printk(KERN_INFO "OCTNIC: invalid queue range: '%d' to %d\n",
				 q_no, last_q);
		return -1;
	}

	for (i = q_no; i < (q_no + q_cnt); i++) {
		/* TODO: VSR: remove this line; only for devel debug */
		printk(KERN_INFO "OCTNIC: assign Q-%d to netdev %s\n", i, pndev->name);
		droq = oct->droq[i];
		if (droq == NULL) {
			printk(KERN_ERR "OCTNIC: DROQ-%d not created yet\n", i);
			WARN_ON(1);
			return -1;
		}
		droq->pndev = pndev;
	}
	return 0;
}

/* $Id: octeon_droq.c 170606 2018-03-20 15:42:45Z vvelumuri $ */
