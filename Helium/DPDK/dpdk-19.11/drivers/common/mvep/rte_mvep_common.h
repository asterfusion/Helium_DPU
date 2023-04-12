/*  SPDX-License-Identifier: BSD-3-Clause
 *  Copyright(c) 2018 Marvell International Ltd.
 */

#ifndef __RTE_MVEP_COMMON_H__
#define __RTE_MVEP_COMMON_H__

#include <rte_kvargs.h>
#ifdef MVCONF_NMP_BUILT
#include <mng/mv_nmp_guest.h>
#endif /* MVCONF_NMP_BUILT */

enum mvep_module_type {
	MVEP_MOD_T_NONE = 0,
	MVEP_MOD_T_PP2,
	MVEP_MOD_T_SAM,
	MVEP_MOD_T_NETA,
	MVEP_MOD_T_GIU,

	MVEP_MOD_T_LAST
};

int rte_mvep_init(enum mvep_module_type module, struct rte_kvargs *kvlist);
int rte_mvep_deinit(enum mvep_module_type module);

#ifdef MVCONF_NMP_BUILT
int rte_mvep_get_nmp_guest_info(struct nmp_guest_info *inf, char **prb_str);
#endif /* MVCONF_NMP_BUILT */

#endif /* __RTE_MVEP_COMMON_H__ */
