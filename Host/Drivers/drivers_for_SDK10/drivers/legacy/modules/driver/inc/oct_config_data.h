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

/*! \file  oct_config_data.h
    \brief Host Driver: Default Configuration data for Octeon devices.
 */

/* This file contains default configuration data for Octeon devices. There is
   one definition each for
   - CN73XX devices(PFs and VFs).
   - CN78XX devices(PFs and VFs).
   - CN83XX devices(PFs and VFs).
   The configuration data follows the structures definitions in
   include/octeon_config.h.
 */

#ifndef  __OCT_CONFIG_DATA_H__
#define  __OCT_CONFIG_DATA_H__

/* OCTEON TX Models */
#include "cn83xx_pf_config_data.h"
#include "cn83xx_vf_config_data.h"

/* OCTEON TX2 Models */
#include "cn93xx_pf_config_data.h"
#include "cn93xx_vf_config_data.h"

#endif
