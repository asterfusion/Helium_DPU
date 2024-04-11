/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

#ifndef __OCTEON_OPCODES_H__
#define __OCTEON_OPCODES_H__

/** Opcodes used in Octeon Host-Core communication.
 *
 *    15 14                                         0
 *   -------------------------------------------------
 *   |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
 *   -------------------------------------------------
 *    ^   ^
 *    |   |
 *    |  Raw Mode
 *   Direction  
 *
 *  Opcodes are 16-bit wide. Bit 15 determines the direction of the operation.
 *  Bit 15 is 0 for operations on the Core and 1 for operation on the host.
 *  So,
 *      Opcodes in the range 0x0000 to 0x7FFF are used by the Octeon host 
 *      driver and applications. 
 *      Opcodes in the range 0x8000 to 0xFFFF are used by the Octeon core
 *      driver and applications.
 *  
 *  Bit 14 can be used for raw mode operations. For such operations, the 
 *  driver will not create a recv_pkt_t but instead send the  
 */

#define OCT_RAW_OP_MASK            0x4000

#define OPCODE_IS_RAW(opcode)      (opcode & OCT_RAW_OP_MASK)

/* Opcodes used by host driver/apps to perform operations on the core */
/* Opcodes in the ranges
   - (0x1000 to 0x1FFF) & (0x7000 to 0x7FFF) are reserved by the host driver 
   - (0x8000 to 0x8FFF) & (0xF001 to 0xFFFF) are reserved by the core driver */
#include "octeon-drv-opcodes.h"

/* Crypto OP codes (4000 - 40ff)*/
/* This is the major opcode for Crypto Operations */
#define CVM_CRYPTO                     0x4000
/* The following are Crypto Minor opcodes. 
   The value of the opcode passed is Logical OR of CVM_CRYPTO and 
   the following minor */
#define CVM_HASH_SHA1                  0x0000
#define CVM_HASH_SHA1_INIT             0x0001
#define CVM_HASH_SHA1_UPDATE           0x0002
#define CVM_HASH_SHA1_FINAL            0x0003
#define CVM_HASH_MD5                   0x0004
#define CVM_HASH_MD5_INIT              0x0005
#define CVM_HASH_MD5_UPDATE            0x0006
#define CVM_HASH_MD5_FINAL             0x0007
#define CVM_HASH_HMAC                  0x0008
#define CVM_HASH_HMAC_CTX_INIT         0x0009
#define CVM_HASH_HMAC_INIT             0x000a
#define CVM_HASH_HMAC_UPDATE           0x000b
#define CVM_HASH_HMAC_FINAL            0x000c
#define CVM_DES_SET_KEY_CHECKED        0x000d
#define CVM_AES_ECB_ENCRYPT            0x002a
#define CVM_AES_ECB_DECRYPT            0x002b
#define CVM_DES_EDE3_ECB_ENCRYPT       0x002c
#define CVM_DES_EDE3_ECB_DECRYPT       0x002d
#define CVM_DES_EDE3_CBC_ENCRYPT       0x000e
#define CVM_DES_EDE3_CBC_DECRYPT       0x000f
#define CVM_DES_NCBC_ENCRYPT           0x0010
#define CVM_DES_NCBC_DECRYPT           0x0011
#define CVM_AES_SET_ENCRYPT_KEY        0x0012
#define CVM_AES_SET_DECRYPT_KEY        0x0013
#define CVM_AES_CBC_ENCRYPT            0x0014
#define CVM_AES_CBC_DECRYPT            0x0015
#define CVM_RC4_SET_KEY                0x0016
#define CVM_RC4_ENCRYPT                0x0017
#define CVM_RC4_DECRYPT                0x0018
#define CVM_DSA_GENERATE_PARAMETERS    0x0019
#define CVM_DSA_GENERATE_KEY           0x001a
#define CVM_DSA_SIGN                   0x001b
#define CVM_DSA_VERIFY                 0x001c
#define CVM_DSA_DO_SIGN                0x001d
#define CVM_DSA_DO_VERIFY              0x001e
#define CVM_DH_GENERATE_PARAMETERS     0x001f
#define CVM_DH_GENERATE_KEY            0x0020
#define CVM_DH_COMPUTE_KEY             0x0021
#define CVM_RSA_GENERATE_KEY           0x0022
#define CVM_RSA_SIGN                   0x0024
#define CVM_RSA_VERIFY                 0x0025
#define CVM_RSA_PUBLIC_ENCRYPT         0x0026
#define CVM_RSA_PRIVATE_DECRYPT        0x0027
#define CVM_RSA_PRIVATE_ENCRYPT        0x0028
#define CVM_RSA_PUBLIC_DECRYPT         0x0029

/*  SSL  Record Processing Opcodes  */
/* Opcodes reserved for SSL 0x4100 to 0x41ff */
/** Major opcode for SSL record processing application **/
#define CVM_SSL_RP                     0x4100
/** Minor opcodes for some of the operations in SSL RP **/
#define CVM_SRP_ALLOC_CONTEXT          0x0001
#define CVM_SRP_FREE_CONTEXT           0x0002
#define CVM_SRP_AES_SHA1_ENCRYPT       0x0003
#define CVM_SRP_AES_SHA1_DECRYPT       0x0004
#define CVM_SRP_WRITE_CONTEXT          0x0005

/*
 * windows specific opcodes
 * 
 * 0x2000 - 0x20ff are reserved for operations on core
 * 0x9000 - 0x90ff are reserved for operations on host
 * 
 * WIN_<kind of driver>_<operation> where <kind of driver> is IPSEC or TOE
 */

/*
 * IPSEC driver opcodes
 */

/* Control operations (host to core) */
#define WIN_IPSEC_GET_MAC_PHY_INFO        0x2000
#define WIN_IPSEC_SET_MAC_PHY_INFO        0x2001
#define WIN_IPSEC_ADD_SA                          0x2002
#define WIN_IPSEC_DELETE_SA                      0x2003

/* Packet operations (host to core) */
#define WIN_IPSEC_SEND_PLAIN_PACKET         0x20f0
#define WIN_IPSEC_SEND_IPSEC_PACKET         0x20f1

/* Control opcodes (core to host) */
#define WIN_IPSEC_CHANGE_IN_MAC_PHY_INFO 0x9000

/* Packet operations (core to host) */
#define WIN_IPSEC_RECV_PLAIN_PACKET        0x90f0
#define WIN_IPSEC_RECV_IPSEC_PACKET        0X90f1

/*--------------------------------------------------------------------------*/
/*   TAG & TAG types */
/*--------------------------------------------------------------------------*/

#define OCTEON_TAG_TYPE_ORDERED        0x00
#define OCTEON_TAG_TYPE_ATOMIC         0x01
#define OCTEON_TAG_TYPE_NULL           0x02
#define OCTEON_TAG_TYPE_NULL_NULL      0x03

#endif /* __OCTEON_OPCODES_H__ */

/* $Id: octeon-opcodes.h 141410 2016-06-30 14:37:41Z mchalla $ */
