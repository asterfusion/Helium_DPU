/* Copyright (c) 2020 Marvell.
 * SPDX-License-Identifier: GPL-2.0
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

/* OCTEON CNXK Models */
#include "cnxk_pf_config_data.h"
#include "cnxk_vf_config_data.h"

#endif
