/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cavium_deprecated.h
    \brief Host Driver: Structures & functions that have been deprecated in this
                        release are available from this file. They may be
                        removed from the next release.
*/

#if defined(CVM_SUPPORT_DEPRECATED_API)

#ifndef CVM_SUPPRESS_DEPRECATED_WARNINGS
#warning "Enable CVM_SUPPRESS_DEPRECATED_WARNINGS in cavium_defs.h to suppress messages on deprecated API"
#endif

typedef struct {

  /** The Octeon device to use for this request */
	uint32_t octeon_id;

  /** The request mask */
	octeon_request_mask_t req_mask;

  /** timeout for this request */
	uint32_t timeout;

  /** Status of this request */
	octeon_req_status_t status;

  /** The request id assigned by driver to this request */
	uint32_t request_id;

  /** The callback function to call after request completion */
	instr_callback_t callback;

  /** Argument to the callback function */
	void *callback_arg;

} octeon_request_info_t
#ifndef CVM_SUPPRESS_DEPRECATED_WARNINGS
    __attribute__ ((deprecated))
#endif
    ;

#define OCT_REQ_INFO_SIZE       (sizeof(octeon_request_info_t))

#define OCT_USER_REQ_INFO_SIZE  OCT_REQ_INFO_SIZE

/**
  Structure for passing input and output buffers in the request structure.
*/
typedef struct {

  /** number of buffers */
	uint32_t cnt;

  /** buffer pointers */
	uint8_t *ptr[MAX_BUFCNT];

  /** their data sizes*/
	uint32_t size[MAX_BUFCNT];

} octeon_buffer_t
#ifndef CVM_SUPPRESS_DEPRECATED_WARNINGS
    __attribute__ ((deprecated))
#endif
    ;

#define  OCT_SOFT_REQ_BUFPTR(buf, idx)   (buf->ptr[idx])

typedef struct {

  /** The input buffers and their sizes. */
	octeon_buffer_t inbuf;

  /** The output buffer pointers and the size allocated at each pointer. */
	octeon_buffer_t outbuf;

  /** The instruction header to be sent with this request to Octeon. */
	octeon_instr_ih_t ih;

  /** The Input Request Header to be sent with the request to Octeon. */
	octeon_instr_irh_t irh;

  /** The extra headers (upto 4 64-bit words) for a 64-bytes instruction. */
	uint64_t exhdr[4];

  /** Information about the formatting to be done to each extra header. */
	octeon_exhdr_info_t exhdr_info;

  /** Additional information required for processing this request. Also
      driver returns an id identifying the request and the current status
      of the request in its fields.*/
	octeon_request_info_t *req_info;

} octeon_soft_request_t
#ifndef CVM_SUPPRESS_DEPRECATED_WARNINGS
    __attribute__ ((deprecated))
#endif
    ;

#define OCT_SOFT_REQUEST_SIZE   (sizeof(octeon_soft_request_t))

#define  SOFT_REQ_INBUF(sr, idx)        ((sr)->inbuf.ptr[(idx)])
#define  SOFT_REQ_OUTBUF(sr, idx)       ((sr)->outbuf.ptr[(idx)])
#define  SOFT_REQ_INFO(sr)              ((sr)->req_info)
#define  SOFT_REQ_IGNORE_SIGNAL(sr)     ((sr)->req_info->req_mask.ignore_signal)

#define GET_SOFT_REQ_DMA_MODE(sreq)     ((sreq)->req_info->req_mask.dma_mode)

#define GET_SOFT_REQ_RESP_ORDER(sreq)   ((sreq)->req_info->req_mask.resp_order)

#define GET_SOFT_REQ_RESP_MODE(sreq)    ((sreq)->req_info->req_mask.resp_mode)

#endif
