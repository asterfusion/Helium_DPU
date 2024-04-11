/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file octeon_ioctl.h
    \brief Host Driver: Ioctl values available to host user applications.
*/

#ifndef  __OCTEON_IOCTL_H__
#define  __OCTEON_IOCTL_H__

#if defined(_WIN32)

#define _IOWR(_A, _B, _C) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 | _B, METHOD_NEITHER, \
				   FILE_READ_DATA | FILE_WRITE_DATA)
#endif

#define OCTEON_MAGIC   0xC1

/* NOTE: It is recommended that you don't call the ioctl directly but use the
         octeon driver API's defined in
         $OCTEON_ROOT/components/driver/api/octeon_user.h.
         The API's perform sanity checks on the values passed to the driver.
*/

#define OCTEON_SEND_REQUEST_CODE               1
#define OCTEON_QUERY_REQUEST_CODE              2
#define OCTEON_READ_PCI_CONFIG_CODE            4
#define OCTEON_WRITE_PCI_CONFIG_CODE           5
#define OCTEON_READ32_CODE                     6
#define OCTEON_WRITE32_CODE                    7
#define OCTEON_READ16_CODE                     8
#define OCTEON_WRITE16_CODE                    9
#define OCTEON_READ8_CODE                      10
#define OCTEON_WRITE8_CODE                     11
#define OCTEON_GET_DEV_COUNT_CODE              12
#define OCTEON_GET_MAPPING_INFO_CODE           13
#define OCTEON_WIN_READ_CODE                   14
#define OCTEON_WIN_WRITE_CODE                  15
#define OCTEON_STATS_CODE                      16
#define OCTEON_GET_NUM_IOQS                    17

#define OCTEON_CORE_MEM_READ_CODE              30
#define OCTEON_CORE_MEM_WRITE_CODE             31

#define OCTEON_HOT_RESET_CODE                  40

#define IOCTL_OCTEON_SEND_REQUEST   \
        _IOWR(OCTEON_MAGIC, OCTEON_SEND_REQUEST_CODE, octeon_soft_request_t)

#define IOCTL_OCTEON_QUERY_REQUEST   \
        _IOWR(OCTEON_MAGIC, OCTEON_QUERY_REQUEST_CODE, octeon_query_request_t)

#define IOCTL_OCTEON_READ_PCI_CONFIG   \
        _IOWR(OCTEON_MAGIC, OCTEON_READ_PCI_CONFIG_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_WRITE_PCI_CONFIG   \
        _IOWR(OCTEON_MAGIC, OCTEON_WRITE_PCI_CONFIG_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_GET_MAPPING_INFO \
        _IOWR(OCTEON_MAGIC, OCTEON_GET_MAPPING_INFO_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_READ32   \
        _IOWR(OCTEON_MAGIC, OCTEON_READ32_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_WRITE32   \
        _IOWR(OCTEON_MAGIC, OCTEON_WRITE32_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_READ16   \
        _IOWR(OCTEON_MAGIC, OCTEON_READ16_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_WRITE16   \
        _IOWR(OCTEON_MAGIC, OCTEON_WRITE16_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_READ8   \
        _IOWR(OCTEON_MAGIC, OCTEON_READ8_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_WRITE8   \
        _IOWR(OCTEON_MAGIC, OCTEON_WRITE8_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_GET_DEV_COUNT   \
        _IOWR(OCTEON_MAGIC, OCTEON_GET_DEV_COUNT_CODE, int)

#define IOCTL_OCTEON_WIN_READ   \
        _IOWR(OCTEON_MAGIC, OCTEON_WIN_READ_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_WIN_WRITE  \
        _IOWR(OCTEON_MAGIC, OCTEON_WIN_WRITE_CODE, octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_STATS  \
        _IOWR(OCTEON_MAGIC, OCTEON_STATS_CODE, oct_stats_t)

#define IOCTL_OCTEON_CORE_MEM_READ \
        _IOWR(OCTEON_MAGIC, OCTEON_CORE_MEM_READ_CODE, octeon_core_mem_rw_t)

#define IOCTL_OCTEON_CORE_MEM_WRITE \
        _IOWR(OCTEON_MAGIC, OCTEON_CORE_MEM_WRITE_CODE, octeon_core_mem_rw_t)

#define IOCTL_OCTEON_HOT_RESET  \
        _IOWR(OCTEON_MAGIC, OCTEON_HOT_RESET_CODE , octeon_rw_reg_buf_t)

#define IOCTL_OCTEON_GET_NUM_IOQS  \
        _IOWR(OCTEON_MAGIC, OCTEON_GET_NUM_IOQS , octeon_rw_reg_buf_t)

#endif	/*__OCTEON_IOCTL_H__ */

/* $Id: octeon_ioctl.h 141410 2016-06-30 14:37:41Z mchalla $ */
