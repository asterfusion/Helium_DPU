/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*!  \file  octeon-error.h
     \brief Common: Error codes used in host-core communication. 
*/

#ifndef __OCTEON_ERROR_H__
#define __OCTEON_ERROR_H__

/** Error codes  used in Octeon Host-Core communication.
 *
 *   31            16 15            0 
 *   ---------------------------------
 *   |               |               |
 *   ---------------------------------
 *   Error codes are 32-bit wide. The upper 16-bits, called Major Error Number,
 *   are reserved to identify the group to which the error code belongs. The
 *   lower 16-bits, called Minor Error Number, carry the actual code. 
 *
 *   So error codes are (MAJOR NUMBER << 16)| MINOR_NUMBER.
 */

/*------------   Error codes used by host driver   -----------------*/
#define DRIVER_MAJOR_ERROR_CODE           0x0000

/**  A value of 0x00000000 indicates no error i.e. success */
#define DRIVER_ERROR_NONE                 0x00000000

/**  (Major number: 0x0000; Minor Number: 0x0001) */
#define DRIVER_ERROR_REQ_PENDING          0x00000001
#define DRIVER_ERROR_REQ_TIMEOUT          0x00000003
#define DRIVER_ERROR_REQ_EINTR            0x00000004
#define DRIVER_ERROR_REQ_ENXIO            0x00000006
#define DRIVER_ERROR_REQ_ENOMEM           0x0000000C
#define DRIVER_ERROR_REQ_EINVAL           0x00000016
#define DRIVER_ERROR_REQ_FAILED           0x000000ff

#define OPV_MAJOR_ERROR_CODE              0x00010000

/*-----------  Error codes reported by the Octeon Core Crypto Target----*/

/* (Major number: 0x0002; Minor Number 0000) */
#define CVM_CRYPTO_OCTEON_ERROR           0x00020000
#define CVM_OCT_OUT_OF_MEMORY             (CVM_CRYPTO_OCTEON_ERROR | 0x01)
#define CVM_OCT_INVALID_ARGUMENT          (CVM_CRYPTO_OCTEON_ERROR | 0x02)
#define CVM_OCT_DES_KEY_PARITY_ERROR      (CVM_CRYPTO_OCTEON_ERROR | 0x03)
#define CVM_OCT_DES_ILLEGAL_WEAK_KEY      (CVM_CRYPTO_OCTEON_ERROR | 0x04)
#define CVM_OCT_INVALID_AES_ALGO          (CVM_CRYPTO_OCTEON_ERROR | 0x05)
#define CVM_OCT_VERIFY_FAIL               (CVM_CRYPTO_OCTEON_ERROR | 0x06)

/*-- Error codes reported by the Octeon Core Crypto Library(OpenSSL Errors)--*/

/* (Major number: 0x0003) */
#define CVM_CRYPTO_OCT_OPENSSL_ERROR      0x00030000
	/* The SSL error is Or'd with this CVM_CRYPTO_OCT_OPENSSL_ERROR */

#endif /* __OCTEON_ERROR_H__ */

/* $Id: octeon-error.h 141410 2016-06-30 14:37:41Z mchalla $ */
