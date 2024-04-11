/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file  cavium_defs.h
    \brief Host Driver: Instruction field formats, soft request format and
                        macros to operate on its fields, Swap macros.
     The Octeon Hardware Manual should be referred to understand the
     structures and macros defined here.
 */

#ifndef _CAVIUM_DEFS_H
#define _CAVIUM_DEFS_H

#include "octeon-error.h"
#include "octeon_stats.h"

/* This flag is disabled by default.
   Enable this flag to support the deprecated octeon_soft_request_t structure.
   It is advised to move to the new structure definition available in this file.
   The deprecated structure definition is in "cavium_deprecated.h".
 */
//#define   CVM_SUPPORT_DEPRECATED_API

/* Using the deprecated octeon_soft_request structure will print warnings during
   compilation. If you wish to continue using the deprecated API, enable this
   flag to suppress the warning messages.
 */
//#define   CVM_SUPPRESS_DEPRECATED_WARNINGS

/** Maximum buffers in inbuf/outbuf. This value can be changed to be
    greater for user-space applications provided the data size
    constraints described below are met. */
#define MAX_BUFCNT         16

/* Maximum scatter pointers supported by Octeon Hardware for a single DMA
   operation. Currently the core driver uses a single PCI DMA transaction
   for a scatter response. */
#define MAX_SCATTER_PTRS   13

/***----- DIRECT DMA:  Input & Output Data Size Constraints -------****/

/* The maximum data size that can be sent or received in a single buffer
   by Octeon is determined by the dlengsz field in dptr & rlenssz field
   in rptr both of which are 14-bits allowing 16K - 1 bytes.
 */
#define    OCT_MAX_DIRECT_DMA_SIZE           ((16 * 1024) - 1)

/* This constant is for backward compatibility. */
#define    OCT_MAX_DIRECT_DATA_SIZE          (OCT_MAX_DIRECT_DMA_SIZE)

/* The maximum data bytes that can be sent from host to Octeon is the
   maximum that the Octeon Hardware allows - the instruction bytes that
   get added in the WQE packet data for RAW instructions. */
#define    OCT_MAX_DIRECT_INPUT_DATA_SIZE    (OCT_MAX_DIRECT_DATA_SIZE - 32)

/* The maximum data that can be output is 16 bytes less then max input
   size, since 16 bytes are reserved for ORH and status bytes in the
   response from Octeon cores to host.*/
#define    OCT_MAX_DIRECT_OUTPUT_DATA_SIZE   (OCT_MAX_DIRECT_DATA_SIZE - 16)

/* This value is currently used by driver to split user-space output buffers
   efficiently.
 */
#define    OCT_MAX_USER_BUF_SIZE              (OCT_MAX_DIRECT_DMA_SIZE)

/***----- CN38XX Errata PCI-500: DMA component length limitation ----***/
//#define   OCT_MAX_COMP_BUF_LEN              ((64 * 1024) - 8)
#define   OCT_MAX_COMP_BUF_LEN              ((64 * 1000) - 8)

/***----- GATHER DMA: Input Data Size Constraints -------****/

/* The maximum data size that can be sent in GATHER DMA is determined by
   the WQE length field which is 16-bits allowing 64K -1 (65535) bytes.
 */
//#define    OCT_MAX_GATHER_DMA_SIZE           ((64 * 1024) - 1)
#define    OCT_MAX_GATHER_DMA_SIZE           ((64 * 1000) - 1)

/* Octeon PASS3 Errata PCI-500 limits each gather buffer to 65528 bytes.
   This is not checked by the driver since the maximum gather data allowed from
   user or kernel process (defined by OCT_MAX_GATHER_DATA_SIZE below) is less
   than this value. The driver does check for OCT_MAX_GATHER_DATA_SIZE.
 */
//#define    OCT_MAX_GATHER_BUFFER_SIZE         ((64 * 1024) - 8)
#define    OCT_MAX_GATHER_BUFFER_SIZE         ((64 * 1000) - 8)

/*
   When sending an instruction, however another 24 bytes of front data
   get added from the instruction, so make allowance for that too.
 */
#define    OCT_MAX_GATHER_DATA_SIZE          (OCT_MAX_GATHER_DMA_SIZE - 32)

/***----- SCATTER DMA: Output Data Size Constraints -------****/

/* The Octeon PCI DMA engine allows upto 14 local (octeon memory) buffers
 * to be used to send a DMA response. Each buffer can have a maximum size
 * of (8K - 8). This gives a total of 14 * 8184 = 114576 bytes.
 * See Octeon CN38XX PASS3 Errata PCI-500.
 */
#define    OCT_MAX_SCATTER_DMA_SIZE          (14 * 8184)

/* Since 16 bytes are reserved for ORH and status, the actual response
 * data size is 16 bytes lesser.
 */
#define    OCT_MAX_SCATTER_DATA_SIZE         (OCT_MAX_SCATTER_DMA_SIZE - 16)

#define ENDIAN_SWAP_8_BYTE(_i) \
    ((((((uint64_t)(_i)) >>  0) & (uint64_t)0xff) << 56) | \
    (((((uint64_t)(_i)) >>  8) & (uint64_t)0xff) << 48) | \
    (((((uint64_t)(_i)) >> 16) & (uint64_t)0xff) << 40) | \
    (((((uint64_t)(_i)) >> 24) & (uint64_t)0xff) << 32) | \
    (((((uint64_t)(_i)) >> 32) & (uint64_t)0xff) << 24) | \
    (((((uint64_t)(_i)) >> 40) & (uint64_t)0xff) << 16) | \
    (((((uint64_t)(_i)) >> 48) & (uint64_t)0xff) <<  8) | \
    (((((uint64_t)(_i)) >> 56) & (uint64_t)0xff) <<  0))

#define ENDIAN_SWAP_4_BYTE(_i) \
    ((((uint32_t)(_i)) & 0xff000000) >> 24) | \
    ((((uint32_t)(_i)) & 0x00ff0000) >>  8) | \
    ((((uint32_t)(_i)) & 0x0000ff00) <<  8) | \
    ((((uint32_t)(_i)) & 0x000000ff) << 24)

#define ENDIAN_SWAP_2_BYTE(_i) \
    ((((uint16_t)(_i)) & 0xff00) >> 8) | \
    ((((uint16_t)(_i)) & 0x00ff) << 8)

#if defined(__CAVIUM_BYTE_ORDER)
#if __CAVIUM_BYTE_ORDER == __CAVIUM_LITTLE_ENDIAN
#define OCTEON_SWAP_DATA_BYTES
#endif
#else
#error Undefined __CAVIUM_BYTE_ORDER
#endif /*#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN */

/** Swap 8B blocks */
static __inline void octeon_swap_8B_data(uint64_t * data, uint32_t blocks)
{
#ifdef OCTEON_SWAP_DATA_BYTES
	while (blocks) {
		*data = ENDIAN_SWAP_8_BYTE(*data);
		blocks--;
		data++;
	}
#endif
}

/** Swap 4B blocks */
static __inline void octeon_swap_4B_data(uint32_t * data, uint32_t blocks)
{
#ifdef OCTEON_SWAP_DATA_BYTES
	while (blocks) {
		*data = ENDIAN_SWAP_4_BYTE(*data);
		blocks--;
		data++;
	}
#endif
}

/** Swap 2B blocks */
static __inline void octeon_swap_2B_data(uint16_t * data, uint32_t blocks)
{
#ifdef OCTEON_SWAP_DATA_BYTES
	while (blocks) {
		*data = ENDIAN_SWAP_2_BYTE(*data);
		blocks--;
		data++;
	}
#endif
}

#ifndef ROUNDUP4
#define ROUNDUP4(val) (((val) + 3)&0xfffffffc)
#endif

#ifndef ROUNDUP8
#define ROUNDUP8(val) (((val) + 7)&0xfffffff8)
#endif

#ifndef ROUNDUP16
#define ROUNDUP16(val) (((val) + 15)&0xfffffff0)
#endif

#ifndef ROUNDUP128
#define ROUNDUP128(val) (((val) + 127)&0xffffff80)
#endif

typedef uint16_t octeon_opcode_t;
typedef uint32_t octeon_req_status_t;

/** Use this type to pass buffer address to the driver in ioctls. Use the
    addr field to copy your buffer's address. */
typedef union {

	uint64_t addr64;
	uint8_t *addr;

} cavium_ptr_t;

#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
/* Instruction Header (DPI - CN78xx) - for OCTEON-TX models */
typedef struct {

  /** Reserved3 */
	uint64_t reserved3:1;

  /** Gather indicator 1=gather*/
	uint64_t gather:1;

  /** No. of entries in gather list */
	uint64_t gsz:14;

  /** Front Data size */
	uint64_t fsz:6;

  /** Reserved2 */
	uint64_t pkind:6;

  /** PKI port kind - PKIND */
	uint64_t rsvd:20;

  /** Data Len */
	uint64_t tlen:16;

} octeon_instr_ihx_t;

/* Instruction Header (DPI - CN78xx) - for OCTEON-III models */
typedef struct {

  /** Reserved3 */
	uint64_t reserved3:1;

  /** Gather indicator 1=gather*/
	uint64_t gather:1;

  /** Data length OR no. of entries in gather list */
	uint64_t dlengsz:14;

  /** Front Data size */
	uint64_t fsz:6;

  /** Reserved2 */
	uint64_t reserved2:4;

  /** PKI port kind - PKIND */
	uint64_t pkind:6;

  /** Reserved1 */
	uint64_t reserved1:32;

} octeon_instr_ih3_t;

/* Optional PKI Instruction Header(PKI IH) - for OCTEON CN78XX models */
/** BIG ENDIAN format.   */
typedef struct {

  /** Wider bit */
	uint64_t w:1;

  /** Raw mode indicator 1 = RAW */
	uint64_t raw:1;

  /** Use Tag */
	uint64_t utag:1;

  /** Use QPG */
	uint64_t uqpg:1;

  /** Reserved2 */
	uint64_t reserved2:1;

  /** Parse Mode */
	uint64_t pm:3;

  /** Skip Length */
	uint64_t sl:8;

  /** Use Tag Type */
	uint64_t utt:1;

  /** Tag type */
	uint64_t tagtype:2;

  /** Reserved1 */
	uint64_t reserved1:2;

  /** QPG Value */
	uint64_t qpg:11;

  /** Tag Value */
	uint64_t tag:32;

} octeon_instr_pki_ih3_t;

#else
/* Instruction Header - for OCTEON-TX models */
typedef struct {

  /** Data Len */
	uint64_t tlen:16;

  /** Reserved */
	uint64_t rsvd:20;

  /** PKIND for SDP */
	uint64_t pkind:6;

  /** Front Data size */
	uint64_t fsz:6;

  /** No. of entries in gather list */
	uint64_t gsz:14;

  /** Gather indicator 1=gather*/
	uint64_t gather:1;

  /** Reserved3 */
	uint64_t reserved3:1;

} octeon_instr_ihx_t;

/* Instruction Header - for OCTEON-III models */
typedef struct {

  /** Reserved1 */
	uint64_t reserved1:32;

  /** PKI port kind - PKIND */
	uint64_t pkind:6;

  /** Reserved2 */
	uint64_t reserved2:4;

  /** Front Data size */
	uint64_t fsz:6;

  /** Data length OR no. of entries in gather list */
	uint64_t dlengsz:14;

  /** Gather indicator 1=gather*/
	uint64_t gather:1;

  /** Reserved3 */
	uint64_t reserved3:1;

} octeon_instr_ih3_t;

/* Optional PKI Instruction Header(PKI IH) - for OCTEON CN78XX models */
typedef struct {

  /** Tag Value */
	uint64_t tag:32;

  /** QPG Value */
	uint64_t qpg:11;

  /** Reserved1 */
	uint64_t reserved1:2;

  /** Tag type */
	uint64_t tagtype:2;

  /** Use Tag Type */
	uint64_t utt:1;

  /** Skip Length */
	uint64_t sl:8;

  /** Parse Mode */
	uint64_t pm:3;

  /** Reserved2 */
	uint64_t reserved2:1;

  /** Use QPG */
	uint64_t uqpg:1;

  /** Use Tag */
	uint64_t utag:1;

  /** Raw mode indicator 1 = RAW */
	uint64_t raw:1;

  /** Wider bit */
	uint64_t w:1;

} octeon_instr_pki_ih3_t;

#endif

#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN

/** Instruction Header in BIG ENDIAN format.   */

typedef struct {

    /** Raw mode indicator 1 = RAW */
	uint64_t raw:1;

    /** Gather indicator 1=gather*/
	uint64_t gather:1;

    /** Data length OR no. of entries in gather list */
	uint64_t dlengsz:14;

    /** Front Data size */
	uint64_t fsz:6;

    /** Packet Order / Work Unit selection (1 of 8)*/
	uint64_t qos:3;

    /** Core group selection (1 of 16) */
	uint64_t grp:4;

    /** Short Raw Packet Indicator 1=short raw pkt */
	uint64_t rs:1;

    /** Tag type */
	uint64_t tagtype:2;

    /** Tag Value */
	uint64_t tag:32;

} octeon_instr_ih_t;

/** Input Request Header in BIG ENDIAN format.  */

typedef struct {

    /** Opcode for the return packet  */
	uint64_t opcode:16;

    /** Opcode Specific parameters */
	uint64_t param:8;

    /** Desired destination port for result */
	uint64_t dport:6;

    /** Size of Expected result OR no. of entries in scatter list */
	uint64_t rlenssz:14;

    /** Scatter indicator  1=scatter */
	uint64_t scatter:1;

    /** PCIe port to use for response */
	uint64_t pcie_port:3;

    /** Request ID  */
	uint64_t rid:16;

} octeon_instr_irh_t;

/** Response Header in BIG ENDIAN format */

typedef struct {

    /** Opcode for this packet. */
	uint64_t opcode:16;

    /** The source port for a packet thats in response to pkt sent by host. */
	uint64_t src_port:6;

    /** The destination Queue port. */
	uint64_t dest_qport:22;

    /** checksum verified. */
	uint64_t csum_verified:2;

    /** Reserved. */
	uint64_t reserved:2;

    /** The request id for a packet thats in response to pkt sent by host. */
	uint64_t request_id:16;

} octeon_resp_hdr_t;

#else

/** Instruction Header in LITTLE ENDIAN format. */

typedef struct {

    /** Tag Value */
	uint64_t tag:32;

    /** Tag type */
	uint64_t tagtype:2;

    /** Short Raw Packet Indicator 1=short raw pkt */
	uint64_t rs:1;

    /** Core group selection (1 of 16) */
	uint64_t grp:4;

    /** Packet Order / Work Unit selection (1 of 8)*/
	uint64_t qos:3;

    /** Front Data size */
	uint64_t fsz:6;

    /** Data length OR no. of entries in gather list */
	uint64_t dlengsz:14;

    /** Gather indicator 1=gather*/
	uint64_t gather:1;

    /** Raw mode indicator 1 = RAW */
	uint64_t raw:1;

} octeon_instr_ih_t;

/** Input Request Header in LITTLE ENDIAN format */

typedef struct {

    /** Request ID  */
	uint64_t rid:16;

    /** PCIe port to use for response */
	uint64_t pcie_port:3;

    /** Scatter indicator  1=scatter */
	uint64_t scatter:1;

    /** Size of Expected result OR no. of entries in scatter list */
	uint64_t rlenssz:14;

    /** Desired destination port for result */
	uint64_t dport:6;

    /** Opcode Specific parameters */
	uint64_t param:8;

    /** Opcode for the return packet  */
	uint64_t opcode:16;

} octeon_instr_irh_t;

/** Response Header in LITTLE ENDIAN format */

typedef struct {

    /** The request id for a packet thats in response to pkt sent by host. */
	uint64_t request_id:16;

    /** Reserved. */
	uint64_t reserved:2;

    /** checksum verified. */
	uint64_t csum_verified:2;

    /** The destination Queue port. */
	uint64_t dest_qport:22;

    /** The source port for a packet thats in response to pkt sent by host. */
	uint64_t src_port:6;

    /** Opcode for this packet. */
	uint64_t opcode:16;

} octeon_resp_hdr_t;

#endif /* Little or Big Endian */

#define  OCT_RESP_HDR_SIZE   (sizeof(octeon_resp_hdr_t))

/* \cond */

typedef union {

	uint64_t u64;

	struct {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
		uint64_t es:2;
		uint64_t ns:1;
		uint64_t ro:1;
		uint64_t addr:60;
#else
		uint64_t addr:60;
		uint64_t ro:1;
		uint64_t ns:1;
		uint64_t es:2;
#endif
	} f1;

	struct {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
		uint64_t pm:2;
		uint64_t sl:7;
		uint64_t addr:55;
#else
		uint64_t addr:55;
		uint64_t sl:7;
		uint64_t pm:2;
#endif
	} f2;

	struct {
#if __CAVIUM_BYTE_ORDER == __CAVIUM_BIG_ENDIAN
		uint64_t es:2;
		uint64_t ns:1;
		uint64_t ro:1;
		uint64_t pm:2;
		uint64_t sl:7;
		uint64_t addr:51;
#else
		uint64_t addr:51;
		uint64_t sl:7;
		uint64_t pm:2;
		uint64_t ro:1;
		uint64_t ns:1;
		uint64_t es:2;
#endif
	} f3;

} oct_dptr_format_t;

/* \endcond */

/*-------------------------------- REQUEST INFO ----------------------------*/
/*                Used in both soft-request and soft_instruction            */

/** Response mode value for a Octeon request. */
typedef enum {
	OCTEON_RESP_BLOCKING = 0,
	OCTEON_RESP_NON_BLOCKING
} OCTEON_RESPONSE_MODE;

#define  OCTEON_RESP_MODE_STRING(resp_order)                                \
    ({                                                                          \
        char str[16];                                                          \
        switch(resp_order) {                                                    \
            case OCTEON_RESP_BLOCKING: cavium_strncpy(str, sizeof(str),"BLOCKING",sizeof(str) - 1); break;          \
            case OCTEON_RESP_NON_BLOCKING: cavium_strncpy(str, sizeof(str),"NON-BLOCKING",sizeof(str) - 1); break;  \
            default: cavium_strncpy(str, sizeof(str),"UNKNOWN",sizeof(str) - 1); break;                             \
        }                                                                       \
        str;                                                                    \
    })

/** Response Order values for a Octeon Request. */
typedef enum {
	OCTEON_RESP_ORDERED = 0,
	OCTEON_RESP_UNORDERED = 1,
	OCTEON_RESP_NORESPONSE = 2
} OCTEON_RESPONSE_ORDER;

#define  OCTEON_RESP_ORDER_STRING(resp_order)                          \
    ({                                                                     \
        char str[16];                                                     \
        switch(resp_order) {                                               \
            case OCTEON_RESP_ORDERED: cavium_strncpy(str, sizeof(str),"ORDERED",sizeof(str) - 1); break;       \
            case OCTEON_RESP_UNORDERED: cavium_strncpy(str, sizeof(str),"UNORDERED",sizeof(str) - 1); break;   \
            case OCTEON_RESP_NORESPONSE: cavium_strncpy(str, sizeof(str),"NORESPONSE",sizeof(str) - 1); break; \
            default: cavium_strncpy(str, sizeof(str),"UNKNOWN",sizeof(str) - 1); break;                        \
        }                                                                  \
        str;                                                               \
    })

/** The DMA mode values that canbe used for the request. */
typedef enum {
	OCTEON_DMA_DIRECT = 0,
	OCTEON_DMA_SCATTER = 1,
	OCTEON_DMA_GATHER = 2,
	OCTEON_DMA_SCATTER_GATHER = 3
} OCTEON_DMA_MODE;

#define  OCTEON_DMA_MODE_STRING(dma_mode)                                     \
    ({                                                                            \
        char str[16];                                                            \
        switch(dma_mode) {                                                        \
            case OCTEON_DMA_DIRECT: cavium_strncpy(str,sizeof(str), "DIRECT",sizeof(str) - 1); break;                 \
            case OCTEON_DMA_SCATTER: cavium_strncpy(str, sizeof(str),"SCATTER",sizeof(str) - 1); break;               \
            case OCTEON_DMA_GATHER: cavium_strncpy(str, sizeof(str),"GATHER",sizeof(str) - 1); break;                 \
            case OCTEON_DMA_SCATTER_GATHER: cavium_strncpy(str, sizeof(str),"SCATTER_GATHER",sizeof(str) - 1); break; \
            default: cavium_strncpy(str, sizeof(str),"UNKNOWN",sizeof(str) - 1); break;                               \
        }                                                                         \
        str;                                                                      \
    })

/** Status for a request.
   If a request is not queued to Octeon by the driver, the driver returns
   an error condition that's describe by one of the OCTEON_REQ_ERR_* value
   below. If the request is successfully queued, the driver will return
   a OCTEON_REQUEST_PENDING status. OCTEON_REQUEST_TIMEOUT and
   OCTEON_REQUEST_INTERRUPTED are only returned by the driver if the response for
   request failed to arrive before a time-out period or if the request processing
   got interrupted due to a signal respectively. */
typedef enum {
	OCTEON_REQUEST_DONE = (DRIVER_ERROR_NONE),
	OCTEON_REQUEST_PENDING = (DRIVER_ERROR_REQ_PENDING),
	OCTEON_REQUEST_TIMEOUT = (DRIVER_ERROR_REQ_TIMEOUT),
	OCTEON_REQUEST_INTERRUPTED = (DRIVER_ERROR_REQ_EINTR),
	OCTEON_REQUEST_NO_DEVICE = (0x00000021),
	OCTEON_REQUEST_NOT_RUNNING,
	OCTEON_REQUEST_INVALID_IQ,
	OCTEON_REQUEST_INVALID_BUFCNT,
	OCTEON_REQUEST_INVALID_RESP_ORDER,
	OCTEON_REQUEST_NO_MEMORY,
	OCTEON_REQUEST_INVALID_BUFSIZE,
	OCTEON_REQUEST_NO_PENDING_ENTRY,
	OCTEON_REQUEST_NO_IQ_SPACE = (0x7FFFFFFF)

} OCTEON_REQUEST_STATUS;

/* The request status was failed */
#define OCTEON_REQUEST_STATUS_FAILED        OCTEON_REQUEST_NO_IQ_SPACE
/* Includes the request_id and status to failed values */
#define OCTEON_REQUEST_FAILED           (~0ULL)

/** Tag types used by Octeon cores in its work. */
enum octeon_tag_type {
	ORDERED_TAG = 0,
	ATOMIC_TAG = 1,
	NULL_TAG = 2,
	NULL_NULL_TAG = 3
};

/** The format of the extra headers (upto 4) in 64-byte instruction
    mode. */
typedef enum {
	OCTEON_EXHDR_PASS_THRU = 0,	/* Send extra header word as-is */
	OCTEON_EXHDR_ENDIAN_SWAP = 1	/* Send extra header word after 64-bit swap */
} OCTEON_EXHDR_FMT;

/** A bit mask describing the response mode, DMA mode, response order
    and instruction queue to use for a request. */
typedef struct {

    /** Use a value of type OCTEON_RESP_MODE */
	uint32_t resp_mode:2;

    /** Use a value of type OCTEON_DMA_MODE */
	uint32_t dma_mode:2;

    /** Use a value of type OCTEON_RESP_ORDER */
	uint32_t resp_order:2;

    /** If set, the driver will ignore any pending signals when processing
        a BLOCKING request. */
	uint32_t ignore_signal:2;

   /** The Input queue on which the request will be sent to Octeon */
	uint32_t iq_no:6;

	uint32_t rsvd:18;

} octeon_request_mask_t;

/** Information about each of the extra headers added for a 64-byte
    instruction. */
typedef struct {

    /** The number of 64-bit extra header words in this request. */
	uint64_t exhdr_count:4;

    /** Use a value of type OCTEON_EXHDR_FMT */
	uint64_t exhdr1_op:2;

	uint64_t exhdr2_op:2;

	uint64_t exhdr3_op:2;

	uint64_t exhdr4_op:2;

	uint64_t rsvd:52;

} octeon_exhdr_info_t;

#define OCT_EXHDR_INFO_SIZE   (sizeof(octeon_exhdr_info_t))

/** Format of the function called at the completion of instruction
    processing by the driver. */
typedef void (*instr_callback_t) (octeon_req_status_t, void *);

#if defined(CVM_SUPPORT_DEPRECATED_API)

#include "cavium_deprecated.h"

#else

/** Information about the request sent to driver by user-space applications. */
typedef struct {

    /** The Octeon device to use for this request */
	uint32_t octeon_id;

    /** The request mask */
	octeon_request_mask_t req_mask;

    /** timeout for this request */
	uint32_t timeout;

    /** Status of this request */
	octeon_req_status_t status;

    /** The request id assigned by driver to this request. Used by the
        application to query status of request (for UNORDERED NONBLOCKING calls)*/
	uint32_t request_id;

} octeon_user_request_info_t;

#define  OCT_USER_REQ_INFO_SIZE     (sizeof(octeon_user_request_info_t))

/**
   Structure for passing input and output buffers in the request structure.
 */
typedef struct {

    /** number of buffers */
	uint32_t cnt;

	uint32_t rsvd;

    /** buffer pointers */
	cavium_ptr_t ptr[MAX_BUFCNT];

    /** their data sizes*/
	uint32_t size[MAX_BUFCNT];

} octeon_buffer_t;

#define  OCT_SOFT_REQ_BUFPTR(buf, idx)   (buf->ptr[idx].addr)

#if  !defined(OCTEON_REQ_INFO_CB)

typedef octeon_user_request_info_t octeon_request_info_t;
#define OCT_REQ_INFO_SIZE       (sizeof(octeon_request_info_t))

#else

/** Information about the request sent to driver by kernel mode applications. */
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

    /** Argument passed to callback */
	void *callback_arg;

} octeon_request_info_t;

#define OCT_REQ_INFO_SIZE       (sizeof(octeon_request_info_t))

#endif /* If in kernel mode */

/** Information about the request sent to driver. This structure
 *  points to the input data buffer(s), to the output buffer(s) (if any)
 *  if a response is expected. It also keep information about the type of
 *  DMA, mode of operation (response order, mode etc).
 *  Several MACROS are defined to help access the fields.
 */
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
	union {
		uint64_t addr64;
		octeon_request_info_t *ptr;
	} req_info;

} octeon_soft_request_t;

#define OCT_SOFT_REQUEST_SIZE   (sizeof(octeon_soft_request_t))

#define  SOFT_REQ_INBUF(sr, idx)    ((sr)->inbuf.ptr[(idx)].addr)
#define  SOFT_REQ_OUTBUF(sr, idx)   ((sr)->outbuf.ptr[(idx)].addr)
#define  SOFT_REQ_INFO(sr)          ((sr)->req_info.ptr)
#define  SOFT_REQ_IGNORE_SIGNAL(sr) ((sr)->req_info.ptr->req_mask.ignore_signal)

#define GET_SOFT_REQ_DMA_MODE(sr)   ((sr)->req_info.ptr->req_mask.dma_mode)

#define GET_SOFT_REQ_RESP_ORDER(sr) ((sr)->req_info.ptr->req_mask.resp_order)

#define GET_SOFT_REQ_RESP_MODE(sr)  ((sr)->req_info.ptr->req_mask.resp_mode)

#endif /* If not supporting deprecated */

/** Status of request as returned by octeon_process_request(). */
typedef union {
    /** Set to OCTEON_SOFT_INSTR_FAILED on failure.
        Else s.status has current status. */
	uint64_t u64;
#define OCTEON_REQUEST_FAILED  (~0ULL)
	struct {
	/** The request_id assigned by driver for this instruction.*/
		uint64_t request_id:32;

	/** The current status of this instruction. */

		/* Request status gives the reason if the request failed,
		 * otherwise gives the status of request processing.
		 */
		uint64_t status:31;

		/* The driver sets this bit to 1 for all failure conditions.
		 * The request has been queued successfully only if this bit is 0.
		 */
		uint64_t error:1;

	} s;
} octeon_instr_status_t;

/***          GET macros for the request structure     ***/

#define GET_REQ_INFO_DMA_MODE(reqinfo)     ((reqinfo)->req_mask.dma_mode)

#define GET_REQ_INFO_RESP_ORDER(reqinfo)   ((reqinfo)->req_mask.resp_order)

#define GET_REQ_INFO_RESP_MODE(reqinfo)    ((reqinfo)->req_mask.resp_mode)

#define GET_REQ_INFO_IQ_NO(reqinfo)        ((reqinfo)->req_mask.iq_no)

#define GET_REQ_INFO_OCTEON_ID(reqinfo)    ((reqinfo)->octeon_id)

#define GET_REQ_INFO_STATUS(reqinfo)       ((reqinfo)->status)

#define GET_REQ_INFO_REQUEST_ID(reqinfo)   ((reqinfo)->request_id)

#define GET_SOFT_REQ_EXHDR_CNT(sreq)       ((sreq)->exhdr_info.exhdr_count)

#define GET_SOFT_REQ_EXHDR(sreq, hdr_no)   ((sreq)->exhdr[hdr_no])

static __inline OCTEON_EXHDR_FMT
GET_SOFT_REQ_EXHDR_INFO(octeon_soft_request_t * soft_req_ptr, uint32_t hdr_no)
{
	switch (hdr_no) {
	case 0:
		return ((OCTEON_EXHDR_FMT) soft_req_ptr->exhdr_info.exhdr1_op);
	case 1:
		return ((OCTEON_EXHDR_FMT) soft_req_ptr->exhdr_info.exhdr2_op);
	case 2:
		return ((OCTEON_EXHDR_FMT) soft_req_ptr->exhdr_info.exhdr3_op);
	case 3:
		return ((OCTEON_EXHDR_FMT) soft_req_ptr->exhdr_info.exhdr4_op);
	}

	return 0;
}

#define  GET_SOFT_REQ_REQUEST_ID(sr)    (SOFT_REQ_INFO(sr)->request_id)
#define  GET_SOFT_REQ_OCTEON_ID(sr)     (SOFT_REQ_INFO(sr)->octeon_id)

#define SOFT_REQ_IS_RAW(sreq)           ((sreq)->ih.raw)

/***          SET macros for the request structure     ***/

/* *** Request Info Operations *** */

/** Set the DMA mode for a request info field.
 *  @param  req_info  - pointer to the request info field of the request.
 *  @param  dma_mode  - DMA mode in OCTEON_DMA_MODE enum format.
 */
static __inline void
SET_REQ_INFO_DMA_MODE(octeon_request_info_t * req_info,
		      OCTEON_DMA_MODE dma_mode)
{
	req_info->req_mask.dma_mode = dma_mode;
}

/** Set the RESPONSE ORDER used for a request info field.
 *  @param  req_info   - pointer to the request info field of the request.
 *  @param  resp_order - RESPONSE ORDER in OCTEON_RESPONSE_ORDER enum format.
 */
static __inline void
SET_REQ_INFO_RESP_ORDER(octeon_request_info_t * req_info,
			OCTEON_RESPONSE_ORDER resp_order)
{
	req_info->req_mask.resp_order = resp_order;
}

/** Set the RESPONSE MODE used for a request info field.
 *  @param   req_info  - pointer to the request info field of the request.
 *  @param   resp_mode - RESPONSE MODE in OCTEON_RESPONSE_MODE enum format.
 */
static __inline void
SET_REQ_INFO_RESP_MODE(octeon_request_info_t * req_info,
		       OCTEON_RESPONSE_MODE resp_mode)
{
	req_info->req_mask.resp_mode = resp_mode;
}

/** Set the INPUT QUEUE to use for a request info field.
 *  @param  req_info  - pointer to the request info field of the request.
 *  @param  iq_no     - instruction queue number (0 <= q_no <= 3).
 */
static __inline void
SET_REQ_INFO_IQ_NO(octeon_request_info_t * req_info, uint32_t iq_no)
{
	req_info->req_mask.iq_no = (uint8_t) iq_no;
}

/** Set the Octeon device id where this request is to be sent.
 *  @param  req_info  - pointer to the request info field of the request.
 *  @param  octeon_id - id of the octeon device.
 */
static __inline void
SET_REQ_INFO_OCTEON_ID(octeon_request_info_t * req_info, uint32_t octeon_id)
{
	req_info->octeon_id = octeon_id;
}

/** Set the timeout value for this request.
 *  @param  req_info  - pointer to the request info field of the request.
 *  @param  timeout   - timeout in millisecs.
 */
static __inline void
SET_REQ_INFO_TIMEOUT(octeon_request_info_t * req_info, uint32_t timeout)
{
	req_info->timeout = timeout;
}

#if  defined(CVM_SUPPORT_DEPRECATED_API) || defined(OCTEON_REQ_INFO_CB)

/** Set the callback for this request. This is available only for kernel
 *  mode requests. The driver calls this function when the request
 *  completes or is timed-out. The status is returned as the first parameter
 *  of the callback.
 *  @param  req_info  - pointer to the request info field of the request.
 *  @param  cb_fn     - the function to callback.
 *  @param  cb_arg    - The user specified argument returned to the user.
 */
static __inline void
SET_REQ_INFO_CALLBACK(octeon_request_info_t * req_info,
		      instr_callback_t cb_fn, void *cb_arg)
{
	req_info->callback = cb_fn;
	req_info->callback_arg = cb_arg;
}

#endif

static __inline void
SET_REQ_INFO_REQUEST_ID(octeon_request_info_t * req_info, uint32_t req_id)
{
	req_info->request_id = req_id;
}

/* *** Request structure Operations *** */

/** Set the DMA mode for this request.
 *  @param  soft_req_ptr  - pointer to the request structure.
 *  @param  dma_mode      - DMA mode in OCTEON_DMA_MODE enum format.
 */
static __inline void
SET_SOFT_REQ_DMA_MODE(octeon_soft_request_t * soft_req_ptr,
		      OCTEON_DMA_MODE dma_mode)
{
#if defined(CVM_SUPPORT_DEPRECATED_API)
	soft_req_ptr->req_info->req_mask.dma_mode = dma_mode;
#else
	soft_req_ptr->req_info.ptr->req_mask.dma_mode = dma_mode;
#endif
}

/** Set the RESPONSE ORDER used for this request.
 *  @param  soft_req_ptr  - pointer to the request structure.
 *  @param  resp_order - RESPONSE ORDER in OCTEON_RESPONSE_ORDER enum format.
 */
static __inline void
SET_SOFT_REQ_RESP_ORDER(octeon_soft_request_t * soft_req_ptr,
			OCTEON_RESPONSE_ORDER resp_order)
{
#if defined(CVM_SUPPORT_DEPRECATED_API)
	soft_req_ptr->req_info->req_mask.resp_order = resp_order;
#else
	soft_req_ptr->req_info.ptr->req_mask.resp_order = resp_order;
#endif
}

/** Set the RESPONSE MODE used for a request.
 *  @param  soft_req_ptr  - pointer to the request structure.
 *  @param  resp_mode     - RESPONSE MODE in OCTEON_RESPONSE_MODE enum format.
 */
static __inline void
SET_SOFT_REQ_RESP_MODE(octeon_soft_request_t * soft_req_ptr,
		       OCTEON_RESPONSE_MODE resp_mode)
{
#if defined(CVM_SUPPORT_DEPRECATED_API)
	soft_req_ptr->req_info->req_mask.resp_mode = resp_mode;
#else
	soft_req_ptr->req_info.ptr->req_mask.resp_mode = resp_mode;
#endif
}

/** Set the count of extra headers used in this request.
 *  @param soft_req_ptr  - pointer to the request.
 *   @param count         - Number of extra headers.
 */
static __inline void
SET_SOFT_REQ_EXHDR_CNT(octeon_soft_request_t * soft_req_ptr, uint32_t count)
{
	soft_req_ptr->exhdr_info.exhdr_count = count;
}

/**  Set the format type of a extra header at index "hdr_no".
 *  @param soft_req_ptr  - pointer to soft request.
 *  @param hdr_no  - index of the header to be set (0 <= hdr_no <= 3).
 *  @param hdr_fmt - header format type enum OCTEON_EXHDR_FMT.
 */
static __inline void
SET_SOFT_REQ_EXHDR_INFO(octeon_soft_request_t * soft_req_ptr,
			uint32_t hdr_no, OCTEON_EXHDR_FMT hdr_fmt)
{
	switch (hdr_no) {
	case 0:
		soft_req_ptr->exhdr_info.exhdr1_op = hdr_fmt;
		break;
	case 1:
		soft_req_ptr->exhdr_info.exhdr2_op = hdr_fmt;
		break;
	case 2:
		soft_req_ptr->exhdr_info.exhdr3_op = hdr_fmt;
		break;
	case 3:
		soft_req_ptr->exhdr_info.exhdr4_op = hdr_fmt;
		break;
	}
}

/* macros to set IRH fields in a request */

/**  Set the opcode to be used for this request.
 *   @param soft_req_ptr - pointer to the soft request.
 *   @param opcode - operation code for this request (16-bits).
 */
static __inline void
SET_SOFT_REQ_OPCODE(octeon_soft_request_t * soft_req_ptr,
		    octeon_opcode_t opcode)
{
	soft_req_ptr->irh.opcode = opcode;
}

/** Set any additional parameter required for this operation request.
 *  @param soft_req_ptr - pointer to the soft request.
 *  @param param - additional 8-bit parameter for the operation.
 */
static __inline void
SET_SOFT_REQ_OPCODE_PARAM(octeon_soft_request_t * soft_req_ptr, uint8_t param)
{
	soft_req_ptr->irh.param = param;
}

/**  Set the destination port to be used by the core for sending the response.
 *   @param soft_req_ptr - pointer to the soft request.
 *   @param dport  - destination port (0 <= dport <= 35)
 */
static __inline void
SET_SOFT_REQ_DESTPORT(octeon_soft_request_t * soft_req_ptr, uint8_t dport)
{
	soft_req_ptr->irh.dport = dport;
}

/*  Macros to set IH fields in a request */
/** Set this request as a raw operation.
 *  @param soft_req_ptr - pointer to the soft request.
 */
static __inline void SET_SOFT_REQ_RAW(octeon_soft_request_t * soft_req_ptr)
{
	soft_req_ptr->ih.raw = 1;
}

/** Set this request as a raw and short operation.
 *  @param soft_req_ptr - pointer to the soft request.
 */
static __inline void SET_SOFT_REQ_SHORTRAW(octeon_soft_request_t * soft_req_ptr)
{
	soft_req_ptr->ih.raw = 1;
	soft_req_ptr->ih.rs = 1;
}

static __inline void
SET_SOFT_REQ_FRONTDATA(octeon_soft_request_t * soft_req_ptr, uint8_t fsz)
{
	soft_req_ptr->ih.fsz = fsz;
}

/** Set the tag and tagtype to be used for the request.
 *  @param soft_req_ptr - pointer to the soft request.
 *  @param tagtype - type of tag.
 *  @param tag  - tag value (32-bit).
 */
static __inline void
SET_SOFT_REQ_TAG(octeon_soft_request_t * soft_req_ptr,
		 uint8_t tagtype, uint32_t tag)
{
	soft_req_ptr->ih.tagtype = tagtype;
	soft_req_ptr->ih.tag = tag;
}

/**  Set the group for this request.
 *  @param soft_req_ptr - pointer to the soft request.
 *  @param group - core group that should operate on this request. (0 <=group <= 15)
 */
static __inline void
SET_SOFT_REQ_GROUP(octeon_soft_request_t * soft_req_ptr, uint8_t group)
{
	soft_req_ptr->ih.grp = group;
}

/**  Set the QOS value for this request.
 *  @param soft_req_ptr - pointer to the soft request.
 *  @param qos - qos for this request (0 <= qos <= 7)
 */
static __inline void
SET_SOFT_REQ_QOS(octeon_soft_request_t * soft_req_ptr, uint8_t qos)
{
	soft_req_ptr->ih.qos = qos;
}

/** Structure used when querying the status of a pending request. */
typedef struct {

    /** The octeon device to query. */
	uint32_t octeon_id;

    /** The id of the request for which we need status. */
	uint32_t request_id;

    /** The status will be returned here by the driver */
	octeon_req_status_t status;

} octeon_query_request_t;

#define  OCT_QUERY_REQUEST_SIZE     (sizeof(octeon_query_request_t))

/*------------------------------   INPUT   QUEUE  -------------------------*/

/** Each instruction queue can operate in 32-byte or 64-byte instruction
    mode. */
typedef enum {
	IQ_MODE_32 = 0,
	IQ_MODE_64 = 1
} OCTEON_IQ_INSTRUCTION_MODE;

/*-----------REGISTER READ/WRITE structs and defines------------*/

/** PCI mapped space for a Octeon device. */
typedef enum {
	PCI_CFG = 0,	 /**< Config space */
	PCI_BAR0_MAPPED = 1,
			 /**< BAR0 has the CSR's */
	PCI_BAR2_MAPPED = 2,
			 /**< BAR2 indirectly maps Octeon core memory */
	PCI_BAR4_MAPPED = 3,
			 /**< BAR4 maps the Octeon core memory directly */
	WINDOWED = 4	/**< Indirect access to Octeon registers. */
} octeon_reg_type_t;

/** Structure used to pass register address and values to write/read.
    This structure is passed by user apps to pass parameters to
    register read/write ioctls. */
typedef struct {

    /** The octeon device to which the ioctl operation should be sent */
	int oct_id;

    /** Type of PCI space in which the register in mapped. */
	octeon_reg_type_t type;

    /** Address of the register to read/write. */
	uint64_t addr;

    /** Value to write OR Value read from register */
	uint64_t val;

} octeon_rw_reg_buf_t;

#define OCTEON_RW_REG_BUF_SIZE    (sizeof(octeon_rw_reg_buf_t))

/** Octeon core memory Read/Write operations from user-application using
 * Octeon BAR1 access provide information in this structure.
 */
typedef struct {
	uint32_t oct_id;   /**< The Octeon device id to which the op is sent. */
	uint32_t size;	   /**< Size of data to read/write. */
	uint32_t endian;   /**< The endian-swap mode to use for the operation. */
	uint32_t bar1_index;
			   /**< The BAR1 index register to use for this op. */
	uint64_t addr;	   /**< The core memory address to read/write. */
	void *data;	 /**< Pointer to the data buffer to write/read. */
} octeon_core_mem_rw_t;

#define OCTEON_CORE_MEM_RW_SIZE    (sizeof(octeon_core_mem_rw_t))

/**   The entry point for kernel applications to send requests to
 *    Octeon device. All requests for Octeon arrive as a soft_request
 *    to this routine. This routine formats the requests to the driver's
 *    internal format and posts it to Octeon Input queue. When the routine
 *    returns successfully, the request should have been scheduled for
 *    fetching by the Octeon Input queue hardware.
 *
 *    @param  octeon_id  -  the request is meant for this octeon device.
 *    @param  soft_req   -  the soft request structure.
 *    @return A compound structure that stores the status and the request id
 *            of the request if the request was queued successfully. If the
 *            request failed, the 64-bit value in the structure reads as -1.
 */
octeon_instr_status_t
octeon_process_request(uint32_t octeon_id, octeon_soft_request_t * soft_req);

/**  Query the status of a previously posted request. The request id that
 *   identifies the request should be passed in the query parameter. The
 *   driver returns the status in the status field of query.
 *   @param octeon_id  - query the request sent to this device.
 *   @param query      - request id is sent by caller. the status is returned
 *                       by driver.
 *   @return Success: 0; Failure: 1
 */
uint32_t
octeon_query_request_status(uint32_t octeon_id, octeon_query_request_t * query);

#endif /*  _CAVIUM_DEFS_H  */

/* $Id: cavium_defs.h 148641 2016-11-14 18:08:28Z vvelumuri $ */
