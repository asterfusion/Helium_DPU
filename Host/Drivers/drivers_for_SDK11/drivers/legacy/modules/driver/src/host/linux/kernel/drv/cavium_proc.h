/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
 */

/*! \file cavium_proc.h
    \brief Host Driver: Routines to process read/write operations on
                        /proc entries exported by the Octeon driver.
*/

#ifndef __CAVIUM_PROC_H__
#define __CAVIUM_PROC_H__

/** Host: Routine to create /proc files for Octeon driver.
  * @param octeon_dev - Octeon device pointer.
  */
int cavium_init_proc(octeon_device_t * octeon_dev);

/** Host: Routine to delete /proc files for Octeon driver.
  * @param octeon_dev - Octeon device pointer.
  */
void cavium_delete_proc(octeon_device_t * octeon_dev);

#endif /*   __CAVIUM_PROC_H__  */

/* $Id: cavium_proc.h 141410 2016-06-30 14:37:41Z mchalla $ */
