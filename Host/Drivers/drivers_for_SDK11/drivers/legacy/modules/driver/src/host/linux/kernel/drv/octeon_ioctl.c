/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#include "octeon_main.h"
#include "octeon_ioctl.h"

#ifdef CAVIUM_DEBUG
#include "octeon_debug.h"
#endif
#include "octeon_macros.h"

#include "octeon_mem_ops.h"

typedef struct {

	/** wait channel head for this request. */
	cavium_wait_channel wait_head;

	/** completion condition */
	int condition;

	/** Status of request. Used in NORESPONSE completion. */
	octeon_req_status_t status;

} octeon_user_req_complete_t;

/*---------------------IOCTL user copy buffer ----------------------------*/
/**  This structure is used to copy the response for a request
     from kernel space to user space.
*/
typedef struct {

  /** The kernel Input buffer. */
	uint8_t *kern_inptr;

  /** Size of the kernel output buffer. */
	uint32_t kern_outsize;

  /** Address of the kernel output buffer. */
	uint8_t *kern_outptr;

  /** Number of user space buffers */
	uint32_t user_bufcnt;

  /** Address of user-space buffers. */
	uint8_t *user_ptr[MAX_BUFCNT];

  /** Size of each user-space buffer. */
	uint32_t user_size[MAX_BUFCNT];

  /** The octeon device from which response is awaited. */
	octeon_device_t *octeon_dev;

  /** Wait queue and completion flag for user request. */
	octeon_user_req_complete_t *comp;

} octeon_copy_buffer_t;

int octeon_ioctl_send_request(unsigned int, void *);
int octeon_ioctl_query_request(unsigned int, void *);
void octeon_copy_user_buffer(octeon_req_status_t, void *);
int octeon_ioctl_get_num_ioqs(unsigned int, void *);

extern octeon_instr_status_t
__do_request_processing(octeon_device_t * oct, octeon_soft_request_t * sr);

static inline void
octeon_user_req_copyout_response(octeon_copy_buffer_t * copy_buf,
				 octeon_req_status_t status)
{
	int i, ret;
	uint8_t *mem = copy_buf->kern_outptr + 8;

	/* The first 8 bytes holds the ORH and should be skipped
	   Copy to user space is done only if the request was successful */
	if (status == OCTEON_REQUEST_DONE) {
		cavium_print(PRINT_DEBUG,
			     "Copying %d buffers from kernel to user ..",
			     copy_buf->user_bufcnt);
		for (i = 0; i < copy_buf->user_bufcnt; i++) {
			if ((ret =
			     cavium_copy_out(copy_buf->user_ptr[i], mem,
					     copy_buf->user_size[i]))) {
				cavium_error
				    ("OCTEON: Failed to copy out %d of %d bytes to user address %p\n",
				     ret, copy_buf->user_size[i],
				     copy_buf->user_ptr[i]);
				return;
			}
			mem += copy_buf->user_size[i];
		}
		cavium_print(PRINT_DEBUG, "done\n");
	} else {
		cavium_error
		    ("copy_user_buffer: No copy done, status: %d (0x%x)\n",
		     status, status);
	}
	return;
}

static inline octeon_user_req_complete_t
    * octeon_alloc_user_req_complete(octeon_device_t * oct_dev UNUSED)
{
	octeon_user_req_complete_t *comp;
	comp = cavium_alloc_buffer(oct_dev, sizeof(octeon_user_req_complete_t));
	if (comp) {
		cavium_init_wait_channel(&comp->wait_head);
		comp->condition = 0;
	}
	return comp;
}

static inline int
octeon_copy_input_dma_buffers(octeon_device_t * octeon_dev UNUSED,
			      octeon_soft_request_t * soft_req, uint32_t gather)
{
	uint32_t total_size, i;
	uint8_t *mem = NULL, *memtmp = NULL;

	for (i = 0, total_size = 0; i < soft_req->inbuf.cnt; i++)
		total_size += soft_req->inbuf.size[i];

	if (!gather) {
		if (total_size > OCT_MAX_DIRECT_INPUT_DATA_SIZE) {
			cavium_error
			    ("Input size (%d) exceeds max direct dma size (%d)\n",
			     total_size, OCT_MAX_DIRECT_INPUT_DATA_SIZE);
			return -EINVAL;
		}
	} else {
		if (total_size > OCT_MAX_GATHER_DATA_SIZE) {
			cavium_error
			    ("Input size (%d) exceeds max gather data size (%d)\n",
			     total_size, OCT_MAX_GATHER_DATA_SIZE);
			return -EINVAL;
		}
	}

	mem = cavium_alloc_buffer(octeon_dev, total_size);
	if (mem == NULL) {
		cavium_error
		    ("OCTEON: Memory allocation failed for direct buffers\n");
		return -ENOMEM;
	}

	memtmp = mem;

	/* If gather mode is used, each pointer is set as a buffer is copied from
	   user-space. If gather mode is not used, all user-space data is copied
	   in this loop and the pointer and size is set when we exit the loop.
	 */
	for (i = 0; i < soft_req->inbuf.cnt; i++) {
		if (cavium_copy_in
		    ((void *)memtmp, (void *)SOFT_REQ_INBUF(soft_req, i),
		     soft_req->inbuf.size[i])) {
			cavium_error("OCTEON: copy in failed for inbuf\n");
			cavium_free_buffer(octeon_dev, mem);
			soft_req->inbuf.cnt = 0;
			SOFT_REQ_INBUF(soft_req, 0) = NULL;
			return -EFAULT;
		}
		if (gather)
			SOFT_REQ_INBUF(soft_req, i) = memtmp;
		memtmp += soft_req->inbuf.size[i];
	}

	if (!gather) {
		soft_req->inbuf.cnt = 1;
		soft_req->inbuf.size[0] = total_size;
		SOFT_REQ_INBUF(soft_req, 0) = mem;
	}
	cavium_free_buffer(octeon_dev, mem);
	return 0;
}

static inline int
octeon_create_output_dma_buffers(octeon_device_t * octeon_dev UNUSED,
				 octeon_soft_request_t * soft_req,
				 octeon_copy_buffer_t * copy_buf,
				 uint32_t scatter)
{
	uint32_t total_size, i, cnt, size, buf_size;
#define GENERATE_TEST_SIZES
#ifdef  GENERATE_TEST_SIZES
	uint32_t leftover = 0;
#endif
	uint8_t *mem = NULL;

	cnt = soft_req->outbuf.cnt;
	cavium_print(PRINT_DEBUG, "%s: #1 soft_req->outbuf.cnt = %d\n", __func__,
				 soft_req->outbuf.cnt);

	if (cnt > MAX_BUFCNT) {
		cavium_error
		    ("OCTEON: Octeon supports <= %d buffers, request had %d\n",
		     MAX_BUFCNT, cnt);
		return -EINVAL;
	}

	/* Coalesce all output buffers here to make user requests more efficient.
	   Allocate extra bytes for status word and ORH.  */
	for (i = 0, total_size = 0; i < cnt; i++)
		total_size += soft_req->outbuf.size[i];

	/* OCT_MAX_DIRECT_OUTPUT_DATA_SIZE excludes ORH and status bytes. Check 
	   the user output buf size now. */
	if (!scatter) {
		if (total_size > OCT_MAX_DIRECT_OUTPUT_DATA_SIZE) {
			cavium_error
			    ("Output size (%d) exceeds max direct dma size (%d)\n",
			     total_size, OCT_MAX_DIRECT_OUTPUT_DATA_SIZE);
			return -EINVAL;
		}
	} else {
		if (total_size > OCT_MAX_SCATTER_DATA_SIZE) {
			cavium_error
			    ("Output size (%d) exceeds max scatter dma size (%d)\n",
			     total_size, OCT_MAX_SCATTER_DATA_SIZE);
			return -EINVAL;
		}
	}

	total_size += OCT_RESP_HDR_SIZE + 8;

	mem = cavium_alloc_buffer(octeon_dev, total_size);
	if (mem == NULL) {
		cavium_error("Memory allocation for outbuf failed\n");
		return -ENOMEM;
	}

	/* When we copy back, we should not copy the extra resp hdr bytes */
	copy_buf->kern_outsize = total_size - OCT_RESP_HDR_SIZE - 8;
	copy_buf->kern_outptr = mem;
	copy_buf->user_bufcnt = cnt;
	for (i = 0; i < cnt; i++) {
		copy_buf->user_ptr[i] = SOFT_REQ_OUTBUF(soft_req, i);
		copy_buf->user_size[i] = soft_req->outbuf.size[i];
	}

	size = 0;
	i = 0;
	while (size < total_size) {
		SOFT_REQ_OUTBUF(soft_req, i) = mem + size;
#ifdef  GENERATE_TEST_SIZES
		buf_size = copy_buf->user_size[i] + ((i == 0) ? 16 : leftover);
		if (buf_size > OCT_MAX_USER_BUF_SIZE) {
			leftover = buf_size - OCT_MAX_USER_BUF_SIZE;
			buf_size = OCT_MAX_USER_BUF_SIZE;
		} else {
			leftover = 0;
		}
#else
		if ((size + OCT_MAX_USER_BUF_SIZE) > total_size)
			buf_size = (total_size - size);
		else
			buf_size = OCT_MAX_USER_BUF_SIZE;
#endif
		soft_req->outbuf.size[i] = buf_size;
		size += buf_size;
		cavium_print(PRINT_DEBUG,
			     "addr: %p bufsize[%d]: %d total: %d\n",
			     SOFT_REQ_OUTBUF(soft_req, i), i, buf_size, size);
		i++;
	}
	if (scatter && (i > MAX_SCATTER_PTRS)) {
		cavium_error("Output data requires more than %d buffers\n",
			     MAX_SCATTER_PTRS);
		cavium_free_buffer(octeon_dev, mem);
		return -ENOMEM;
	}
	soft_req->outbuf.cnt = i;
	cavium_print(PRINT_DEBUG, "%s: #2 soft_req->outbuf.cnt = %d\n", __func__,
				 soft_req->outbuf.cnt);

	return 0;
}

int octeon_ioctl_send_request(unsigned int cmd, void *arg)
{
	octeon_soft_request_t *soft_req = NULL;
	octeon_request_info_t *req_info = NULL, *user_req_info = NULL;
	octeon_copy_buffer_t *copy_buf = NULL;
	octeon_device_t *octeon_dev = NULL;
	octeon_user_req_complete_t *comp = NULL;
	octeon_instr_status_t status;
	OCTEON_RESPONSE_ORDER resp_order;
	OCTEON_RESPONSE_MODE resp_mode;
	OCTEON_DMA_MODE dma_mode;
	int retval = 0;

	if (!(cavium_access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd)))) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: User data not ready\n");
		return -EFAULT;
	}

	soft_req =
	    (octeon_soft_request_t *) cavium_alloc_buffer(octeon_dev,
							  OCT_SOFT_REQUEST_SIZE);
	if (soft_req == NULL) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Memory allocation failed (1)\n");
		return -ENOMEM;
	}
	cavium_memset(soft_req, 0, OCT_SOFT_REQUEST_SIZE);

	if (cavium_copy_in(soft_req, (void *)arg, OCT_SOFT_REQUEST_SIZE)) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST:Copy in failed for soft_req\n");
		retval = -EFAULT;
		goto free_soft_req;
	}

	if (soft_req->inbuf.cnt > MAX_BUFCNT
	    || soft_req->outbuf.cnt > MAX_BUFCNT
	    || soft_req->exhdr_info.exhdr_count > 4) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Max buffers allowed is %d "
		     "max extra headers allowed is 4\n",
		     MAX_BUFCNT);
		retval = -EINVAL;
		goto free_soft_req;
	}

	/* User space address of req_info structure */
	user_req_info = SOFT_REQ_INFO(soft_req);
	req_info =
	    (octeon_request_info_t *) cavium_alloc_buffer(octeon_dev,
							  OCT_REQ_INFO_SIZE);
	if (req_info == NULL) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Memory allocation failed (2)\n");
		retval = -ENOMEM;
		goto free_soft_req;
	}
	cavium_memset(req_info, 0, OCT_REQ_INFO_SIZE);

	if (cavium_copy_in
	    ((void *)req_info, (void *)user_req_info, OCT_USER_REQ_INFO_SIZE)) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Copy in failed for req_info\n");
		retval = -EFAULT;
		goto free_req_info;
	}

	SOFT_REQ_INFO(soft_req) = req_info;
	resp_order = GET_SOFT_REQ_RESP_ORDER(soft_req);
	resp_mode = GET_SOFT_REQ_RESP_MODE(soft_req);
	dma_mode = GET_SOFT_REQ_DMA_MODE(soft_req);

	octeon_dev = get_octeon_device(GET_REQ_INFO_OCTEON_ID(req_info));
	if (octeon_dev == NULL) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Octeon device (%d) not found\n",
		     GET_REQ_INFO_OCTEON_ID(req_info));
		retval = -EINVAL;
		goto free_req_info;
	}

	if ((int)cavium_atomic_read(&octeon_dev->status) != OCT_DEV_RUNNING) {
		print_octeon_state_errormsg(octeon_dev);
		retval = -EBUSY;
		goto free_req_info;
	}

	if (GET_REQ_INFO_IQ_NO(SOFT_REQ_INFO(soft_req)) >= octeon_dev->num_iqs) {
		cavium_error("OCTEON: Invalid IQ (%d)\n",
			     GET_REQ_INFO_IQ_NO(SOFT_REQ_INFO(soft_req)));
		retval = -EINVAL;
		//return retval;
		goto free_req_info;
	}

	if (resp_mode == OCTEON_RESP_BLOCKING) {
		comp = octeon_alloc_user_req_complete(octeon_dev);
		if (comp == NULL) {
			cavium_error
			    ("IOCTL_OCTEON_SEND_REQUEST: Alloc failed for wait channel\n");
			retval = -ENOMEM;
			goto free_req_info;
		}
	}

	/* Coalesce all input buffers here to make user requests more efficient */
	if (soft_req->inbuf.cnt && (soft_req->inbuf.cnt < MAX_BUFCNT)) {
		if ((dma_mode == OCTEON_DMA_DIRECT)
		    || (dma_mode == OCTEON_DMA_SCATTER))
			retval =
			    octeon_copy_input_dma_buffers(octeon_dev, soft_req,
							  0);
		else
			retval =
			    octeon_copy_input_dma_buffers(octeon_dev, soft_req,
							  1);
		if (retval)
			goto free_req_info;
	} else {
		soft_req->inbuf.cnt = 0;
		soft_req->inbuf.size[0] = 0;
		SOFT_REQ_INBUF(soft_req, 0) = NULL;
	}

	/* copy buf is used to free kernel buffers and copy the response back to
	   the user in the callback.  This cannot be virtual since freeing can
	   happen in interrupt context. */
	copy_buf =
	    cavium_alloc_buffer(octeon_dev, sizeof(octeon_copy_buffer_t));
	if (copy_buf == NULL) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Memory allocation failed (5)\n");
		retval = -ENOMEM;
		goto free_inbuf;
	}
	cavium_memset(copy_buf, 0, sizeof(octeon_copy_buffer_t));

	/* Copy the address of the input buffer allocated by driver. */
	copy_buf->kern_inptr = SOFT_REQ_INBUF(soft_req, 0);
	copy_buf->octeon_dev = octeon_dev;
	copy_buf->comp = comp;

	/* The outbuf field should be ignored for NORESPONSE mode packets */
	if (GET_REQ_INFO_RESP_ORDER(req_info) == OCTEON_RESP_NORESPONSE) {
		soft_req->outbuf.cnt = 0;
		soft_req->outbuf.size[0] = 0;
		SOFT_REQ_OUTBUF(soft_req, 0) = NULL;
		copy_buf->user_bufcnt = 0;
	} else {

		if ((dma_mode == OCTEON_DMA_DIRECT)
		    || (dma_mode == OCTEON_DMA_GATHER)) {
			retval =
			    octeon_create_output_dma_buffers(octeon_dev,
							     soft_req, copy_buf,
							     0);
		} else {
			retval =
			    octeon_create_output_dma_buffers(octeon_dev,
							     soft_req, copy_buf,
							     1);
		}
		if (retval)
			goto free_copybuf;
	}

	SET_REQ_INFO_CALLBACK(req_info, octeon_copy_user_buffer, copy_buf);

	status = __do_request_processing(octeon_dev, soft_req);
	if (status.s.error) {
		cavium_print(PRINT_DEBUG,
			     "OCTEON: SEND REQUEST ioctl failed status: %x\n",
			     status.s.status);
		retval = -ENOMEM;
		goto free_outbuf;
	}

	SOFT_REQ_INFO(soft_req)->status = status.s.status;
	SOFT_REQ_INFO(soft_req)->request_id = status.s.request_id;

	if (resp_mode == OCTEON_RESP_BLOCKING) {

		if (resp_order == OCTEON_RESP_UNORDERED) {

			octeon_query_request_t query;

			query.request_id = GET_SOFT_REQ_REQUEST_ID(soft_req);
			query.octeon_id = GET_SOFT_REQ_OCTEON_ID(soft_req);
			query.status = OCTEON_REQUEST_PENDING;

			do {
				if (!SOFT_REQ_IGNORE_SIGNAL(soft_req)
				    && signal_pending(current))
					query.status =
					    OCTEON_REQUEST_INTERRUPTED;

				retval =
				    (octeon_query_request_status
				     (query.octeon_id, &query)
				     && (query.status !=
					 OCTEON_REQUEST_PENDING));

				/* comp->condition would be set in the callback octeon_copy_user_buffer()
				   called from the request completion tasklet */
				if (comp->condition == 0)
					cavium_sleep_timeout_cond
					    (&comp->wait_head, &comp->condition,
					     1);
				else
					query.status = comp->status;
			} while ((query.status == OCTEON_REQUEST_PENDING)
				 && (!retval));

			/*### Copy query status to req_info here ### */
			SOFT_REQ_INFO(soft_req)->status = query.status;
			octeon_user_req_copyout_response(copy_buf,
							 query.status);
		} else {
			cavium_error
			    ("IOCTL_OCTEON_SEND_REQUEST: ORDERED mode not supported\n");
			retval = -EINVAL;
			goto free_outbuf;
		}
	}

	retval = 0;
	cavium_print(PRINT_REGS,
		     "ioctl: Status of request: 0x%x req_id is %d\n",
		     SOFT_REQ_INFO(soft_req)->status,
		     SOFT_REQ_INFO(soft_req)->request_id);

	if (cavium_copy_out
	    (user_req_info, SOFT_REQ_INFO(soft_req), OCT_USER_REQ_INFO_SIZE)) {
		cavium_error
		    ("IOCTL_OCTEON_SEND_REQUEST: Request Info copyback failed\n");
		retval = -EFAULT;
		goto free_outbuf;
	}

	/* For blocking mode we now free buffers here and not in callback. */
	if (resp_mode != OCTEON_RESP_BLOCKING)
		goto free_req_info;
	/* End of ioctl_octeon_send_request processing */

/* We come here to free our buffers only if something failed. */
free_outbuf:
	if (SOFT_REQ_OUTBUF(soft_req, 0))
		cavium_free_buffer(octeon_dev, SOFT_REQ_OUTBUF(soft_req, 0));
free_copybuf:
	if (copy_buf)
		cavium_free_buffer(octeon_dev, copy_buf);
free_inbuf:
	if (SOFT_REQ_INBUF(soft_req, 0))
		cavium_free_buffer(octeon_dev, SOFT_REQ_INBUF(soft_req, 0));
free_req_info:
	if (SOFT_REQ_INFO(soft_req))
		cavium_free_buffer(octeon_dev, SOFT_REQ_INFO(soft_req));
free_soft_req:
	if (soft_req)
		cavium_free_buffer(octeon_dev, soft_req);
	if (comp)
		cavium_free_buffer(octeon_dev, comp);

	return retval;
}

int octeon_ioctl_query_request(unsigned int cmd UNUSED, void *arg)
{
	octeon_query_request_t query;

	if (cavium_copy_in(&query, (void *)arg, OCT_QUERY_REQUEST_SIZE))
		return -EFAULT;

	if (octeon_query_request_status(query.octeon_id, &query)
	    && (query.status != OCTEON_REQUEST_PENDING)) {
		return -EINVAL;
	} else {
		if (cavium_copy_out
		    ((void *)arg, &query, OCT_QUERY_REQUEST_SIZE))
			return -EFAULT;
	}

	return 0;
}

int octeon_ioctl_get_num_ioqs(unsigned int cmd UNUSED, void *arg)
{
	int num_ioqs = 0;
	octeon_rw_reg_buf_t rw_buf;
	octeon_device_t *oct_dev;

	if (cavium_copy_in(&rw_buf, arg, sizeof(octeon_rw_reg_buf_t)))
		return -EFAULT;

	oct_dev = get_octeon_device(rw_buf.oct_id);
	if (!oct_dev) {
		cavium_error("%s:%d invalid octeon id %d\n", __CVM_FILE__,
			     __CVM_LINE__, rw_buf.oct_id);
		return -EINVAL;
	}

	switch (oct_dev->chip_id) {
	case OCTEON_CN83XX_ID_PF:
		num_ioqs = oct_dev->sriov_info.rings_per_pf;
		break;

	case OCTEON_CN83XX_ID_VF:
		num_ioqs = oct_dev->rings_per_vf;
		break;

	default:
		num_ioqs = oct_dev->num_iqs;
	}

	rw_buf.val = num_ioqs;

	if (cavium_copy_out((void *)arg, &rw_buf, sizeof(octeon_rw_reg_buf_t)))
		return -EFAULT;

	return 0;
}

int octeon_ioctl_hot_reset(unsigned int cmd UNUSED, void *arg)
{
	octeon_rw_reg_buf_t rw_buf;
	octeon_device_t *oct_dev;

	if (cavium_copy_in(&rw_buf, arg, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;

	oct_dev = get_octeon_device(rw_buf.oct_id);
	if (!oct_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
		return -EINVAL;
	}
#if 0
	/* For 73xx, need to reset both the PFs(PF0, PF1).
	 * Initiate hot reset for PF0 first and then for PF1
	 */
	if (oct_dev->chip_id == OCTEON_CN73XX_PF) {

		oct_dev = get_octeon_device(rw_buf.oct_id & (~0x1));
		if (!oct_dev) {
			cavium_error("%s:%d invalid octeon id %d\n",
				     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
			return -EINVAL;
		}

		if (octeon_hot_reset(oct_dev))
			return 1;

		oct_dev = get_octeon_device((rw_buf.oct_id & (~0x1)) | 0x1);
		if (!oct_dev) {
			cavium_error("%s:%d invalid octeon id %d\n",
				     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
			return -EINVAL;
		}
		return octeon_hot_reset(oct_dev);
	} else {
		return octeon_hot_reset(oct_dev);
	}
#endif	

	return octeon_hot_reset(oct_dev);
}

int octeon_ioctl_get_mapping_info(unsigned int cmd UNUSED, void *arg)
{
	int ret = 0, mmio_idx;
	octeon_rw_reg_buf_t rw_buf;
	octeon_device_t *oct_dev;

	if (cavium_copy_in(&rw_buf, arg, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;

	oct_dev = get_octeon_device(rw_buf.oct_id);
	if (!oct_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
		return -EINVAL;
	}

	switch (rw_buf.type) {
	case PCI_BAR0_MAPPED:
		mmio_idx = 0;
		break;

	case PCI_BAR2_MAPPED:
		mmio_idx = 1;
		break;

	case PCI_BAR4_MAPPED:
		mmio_idx = 2;
		break;

	default:
		cavium_error("%s:%d invalid type 0x%x\n", __CVM_FILE__,
			     __CVM_LINE__, rw_buf.type);
		ret = -EINVAL;
		return ret;

	}			/* switch(type) */

	if (oct_dev->mmio[mmio_idx].done) {
		rw_buf.addr =
		    (uint64_t) ((unsigned long)oct_dev->mmio[mmio_idx].hw_addr);
		rw_buf.val = oct_dev->mmio[mmio_idx].mapped_len;
	} else {
		return -EINVAL;
	}

	if (cavium_copy_out(arg, &rw_buf, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;

	return ret;
}				/*octeon_ioctl_get_mapped_address */

int octeon_ioctl_read(unsigned int cmd, void *arg)
{
	octeon_rw_reg_buf_t rw_buf;
	octeon_device_t *oct_dev;

	if (cavium_copy_in(&rw_buf, arg, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;
	oct_dev = get_octeon_device(rw_buf.oct_id);
	if (!oct_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
		return -EINVAL;
	}

	switch (cmd) {
	case IOCTL_OCTEON_READ32:
		rw_buf.val = (uint32_t)
		    OCTEON_READ32((void *)((unsigned long)rw_buf.addr));
		break;
	case IOCTL_OCTEON_READ16:
		rw_buf.val = (uint16_t)
		    OCTEON_READ16((void *)((unsigned long)rw_buf.addr));
		break;
	case IOCTL_OCTEON_READ8:
		rw_buf.val = (uint8_t)
		    OCTEON_READ8((void *)((unsigned long)rw_buf.addr));
		break;
	case IOCTL_OCTEON_WIN_READ:
		rw_buf.val = OCTEON_PCI_WIN_READ(oct_dev, rw_buf.addr);
		break;
	case IOCTL_OCTEON_READ_PCI_CONFIG:
		OCTEON_READ_PCI_CONFIG(oct_dev, (uint32_t) rw_buf.addr,
				       (uint32_t *) & rw_buf.val);
		break;
	default:
		cavium_error("%s:%d invalid read command\n", __CVM_FILE__,
			     __CVM_LINE__);
		return -EINVAL;
	}

	cavium_print(PRINT_FLOW,
		     "%s read reg addr=0x%llx, val=0x%llx swap: 0x%llx\n",
		     __CVM_FILE__, CVM_CAST64(rw_buf.addr),
		     CVM_CAST64(rw_buf.val),
		     CVM_CAST64(ENDIAN_SWAP_8_BYTE(rw_buf.val)));

	if (cavium_copy_out(arg, &rw_buf, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;

	return 0;
}				/*octeon_ioctl_read_register */

int octeon_ioctl_write(unsigned int cmd, void *arg)
{
	octeon_rw_reg_buf_t rw_buf;
	octeon_device_t *oct_dev;

	if (cavium_copy_in(&rw_buf, arg, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;
	oct_dev = get_octeon_device(rw_buf.oct_id);
	if (!oct_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, rw_buf.oct_id);
		return -EINVAL;
	}

	switch (cmd) {
	case IOCTL_OCTEON_WRITE32:
		OCTEON_WRITE32((void *)((unsigned long)rw_buf.addr),
			       (uint32_t) rw_buf.val);
		break;
	case IOCTL_OCTEON_WRITE16:
		OCTEON_WRITE16((void *)((unsigned long)rw_buf.addr),
			       (uint16_t) rw_buf.val);
		break;
	case IOCTL_OCTEON_WRITE8:
		OCTEON_WRITE8((void *)((unsigned long)rw_buf.addr),
			      (uint8_t) rw_buf.val);
		break;
	case IOCTL_OCTEON_WIN_WRITE:
		OCTEON_PCI_WIN_WRITE(oct_dev, rw_buf.addr, rw_buf.val);
		break;
	case IOCTL_OCTEON_WRITE_PCI_CONFIG:
		OCTEON_WRITE_PCI_CONFIG(oct_dev, (uint32_t) rw_buf.addr,
					(uint32_t) rw_buf.val);
		break;
	default:
		cavium_error("%s:%d invalid write command\n", __CVM_FILE__,
			     __CVM_LINE__);
		return -EINVAL;
	}

	cavium_print(PRINT_FLOW, "%s:%d write: addr=0x%llx, val=0x%llx\n",
		     __CVM_FILE__, __CVM_LINE__, CVM_CAST64(rw_buf.addr),
		     CVM_CAST64(rw_buf.val));

	if (cavium_copy_out(arg, &rw_buf, OCTEON_RW_REG_BUF_SIZE))
		return -EFAULT;

	return 0;
}				/*octeon_ioctl_write_register */

int octeon_ioctl_get_dev_count(unsigned int cmd UNUSED, void *arg)
{
	int oct_count = get_octeon_count();
	if (cavium_copy_out(arg, &oct_count, sizeof(uint32_t)))
		return -EFAULT;
	return 0;
}				/*octeon_ioctl_get_dev_count */

int octeon_ioctl_read_core_mem(unsigned int cmd UNUSED, void *arg)
{
	octeon_core_mem_rw_t core_mem;
	octeon_device_t *octeon_dev;
	void *data = NULL;

	if (cavium_copy_in(&core_mem, arg, OCTEON_CORE_MEM_RW_SIZE))
		return -EFAULT;
	octeon_dev = get_octeon_device(core_mem.oct_id);
	if (!octeon_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, core_mem.oct_id);
		return -EINVAL;
	}
	if (core_mem.size < 0xffffff)
		data = cavium_alloc_virt(core_mem.size);
	if (!data) {
		cavium_error
		    ("%s:%d Data alloc failed in core mem write ioctl\n",
		     __CVM_FILE__, __CVM_LINE__);
		return -EINVAL;
	}
	octeon_pci_read_core_mem(octeon_dev, core_mem.addr, data, core_mem.size,
				 core_mem.endian);
	if (cavium_copy_out(core_mem.data, data, core_mem.size)) {
		cavium_free_virt(data);
		return -EFAULT;
	}
	cavium_free_virt(data);
	return 0;
}

int octeon_ioctl_write_core_mem(unsigned int cmd UNUSED, void *arg)
{
	octeon_core_mem_rw_t core_mem;
	octeon_device_t *octeon_dev;
	void *data;

	if (cavium_copy_in(&core_mem, arg, OCTEON_CORE_MEM_RW_SIZE))
		return -EFAULT;
	octeon_dev = get_octeon_device(core_mem.oct_id);
	if (!octeon_dev) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, core_mem.oct_id);
		return -EINVAL;
	}
	data = cavium_alloc_virt(core_mem.size);
	if (!data) {
		cavium_error
		    ("%s:%d Data alloc failed in core mem write ioctl\n",
		     __CVM_FILE__, __CVM_LINE__);
		return -EINVAL;
	}
	if (cavium_copy_in(data, core_mem.data, core_mem.size)) {
		cavium_free_virt(data);
		return -EFAULT;
	}

	octeon_pci_write_core_mem(octeon_dev, core_mem.addr, data,
				  core_mem.size, core_mem.endian);
	cavium_free_virt(data);

	return 0;
}

int octeon_ioctl_stats(unsigned int cmd UNUSED, void *arg)
{
	octeon_device_t *oct;
	oct_stats_t *stats;
	int i;

	stats = cavium_alloc_virt(OCT_STATS_SIZE);
	if (stats == NULL)
		return -ENOMEM;

	if (cavium_copy_in(stats, arg, OCT_STATS_SIZE)) {
		cavium_free_virt(stats);
		return -EFAULT;
	}

	oct = get_octeon_device(stats->oct_id);
	if (!oct) {
		cavium_error("%s:%d invalid octeon id %d\n",
			     __CVM_FILE__, __CVM_LINE__, stats->oct_id);
		cavium_free_virt(stats);
		return -EINVAL;
	}

	cavium_memset(stats, 0, OCT_STATS_SIZE);

	stats->oct_id = oct->octeon_id;
	stats->magic = CAVIUM_STATS_MAGIC;

#ifdef CAVIUM_DEBUG
	stats->debug_level = octeon_debug_level;
#else
	stats->debug_level = -1;
#endif

	strcpy(stats->dev_state, get_oct_state_string(&oct->status));


	for (i = 0; i < oct->num_iqs; i++) {
		cavium_memcpy(&stats->iq[i], &oct->instr_queue[i]->stats,
			      OCT_IQ_STATS_SIZE);
	}

	for (i = 0; i < oct->num_oqs; i++) {
		cavium_memcpy(&stats->droq[i], &oct->droq[i]->stats,
			      OCT_DROQ_STATS_SIZE);
	}

	if (cavium_copy_out(arg, stats, OCT_STATS_SIZE)) {
		cavium_free_virt(stats);
		return -EFAULT;
	}

	cavium_free_virt(stats);

	return 0;
}

/*
 *  Standard ioctl() entry point.
 */
int octeon_ioctl(struct inode *inode UNUSED,
		 struct file *file UNUSED, unsigned int cmd, unsigned long arg)
{
	int retval = 0;

	switch (cmd) {

	case IOCTL_OCTEON_HOT_RESET:
		retval = octeon_ioctl_hot_reset(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_SEND_REQUEST:
		retval = octeon_ioctl_send_request(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_QUERY_REQUEST:
		retval = octeon_ioctl_query_request(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_GET_NUM_IOQS:
		retval = octeon_ioctl_get_num_ioqs(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_STATS:
		retval = octeon_ioctl_stats(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_READ32:
	case IOCTL_OCTEON_READ16:
	case IOCTL_OCTEON_READ8:
	case IOCTL_OCTEON_READ_PCI_CONFIG:
	case IOCTL_OCTEON_WIN_READ:
		retval = octeon_ioctl_read(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_WRITE32:
	case IOCTL_OCTEON_WRITE16:
	case IOCTL_OCTEON_WRITE8:
	case IOCTL_OCTEON_WRITE_PCI_CONFIG:
	case IOCTL_OCTEON_WIN_WRITE:
		retval = octeon_ioctl_write(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_CORE_MEM_READ:
		retval = octeon_ioctl_read_core_mem(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_CORE_MEM_WRITE:
		retval = octeon_ioctl_write_core_mem(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_GET_DEV_COUNT:
		retval = octeon_ioctl_get_dev_count(cmd, (void *)arg);
		break;

	case IOCTL_OCTEON_GET_MAPPING_INFO:
		retval = octeon_ioctl_get_mapping_info(cmd, (void *)arg);
		break;

	default:
		cavium_error("octeon_ioctl: Unknown ioctl command\n");
		retval = -ENOTTY;
		break;
	}			/* switch */

	return retval;
}

long octeon_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	return (long)octeon_ioctl(NULL, f, cmd, arg);
}

long octeon_unlocked_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	return (long)octeon_ioctl(NULL, f, cmd, arg);
}

#ifdef CAVIUM_DEBUG
static inline void octeon_print_copy_buf_data(uint8_t * buf, uint32_t datasize)
{
	int i;

	cavium_print(PRINT_DEBUG, "copy_user_buffer: kern: %p, size: %d\n", buf,
		     datasize);
	cavium_print(PRINT_DEBUG, "ORH @ %p: ", buf);
	for (i = 0; i < 8; i++)
		cavium_print(PRINT_DEBUG, " %02x ", buf[i]);
	buf = (uint8_t *) ((unsigned long)buf + (datasize + 8));
	cavium_print(PRINT_DEBUG, "\nStatus @ %p: ", buf);
	for (i = 0; i < 8; i++)
		cavium_print(PRINT_DEBUG, " %02x ", buf[i]);
	cavium_print(PRINT_DEBUG, "\n");
}
#endif

void octeon_copy_user_buffer(octeon_req_status_t status, void *arg)
{
	octeon_copy_buffer_t *copy_buf;
	octeon_device_t *octeon_dev;

	copy_buf = (octeon_copy_buffer_t *) arg;
	cavium_print(PRINT_FLOW,
		     "----#  octeon_copy_user_buffer; status: %x \n", status);
	octeon_dev = copy_buf->octeon_dev;
	/* copy_buf->comp is always present for blocking call.
	   Copy to user and free bufs in sleeping process for blocking. */
	if (copy_buf->comp) {
		copy_buf->comp->condition = 1;
		copy_buf->comp->status = status;
		cavium_wakeup(&(copy_buf->comp->wait_head));
	} else {
		/* For non-blocking there is no process sleeping. So do copy
		   to user here and free buffers here. */
		if (copy_buf->kern_inptr) {
			cavium_free_buffer(octeon_dev, copy_buf->kern_inptr);
		}

		if (copy_buf->user_bufcnt) {
			octeon_user_req_copyout_response(copy_buf, status);
		}

		if (copy_buf->kern_outptr) {
			cavium_free_buffer(octeon_dev, copy_buf->kern_outptr);
		}
		cavium_free_buffer(octeon_dev, copy_buf);
	}
}

/* $Id: octeon_ioctl.c 162810 2017-07-17 18:05:03Z mchalla $ */
