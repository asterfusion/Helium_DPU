/*  SPDX-License-Identifier: BSD-3-Clause
 *  Copyright(c) 2018 Marvell International Ltd.
 */

#include <rte_common.h>
#include <rte_log.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <env/mv_autogen_comp_flags.h>
#include <env/mv_sys_dma.h>

#include "rte_mvep_common.h"

#ifdef MVCONF_NMP_BUILT
/* NMP Guest ID */
#define NMP_GUEST_ID		2
/* NMP Guest Timeout (ms)*/
#define NMP_GUEST_TIMEOUT	1000
#endif /* MVCONF_NMP_BUILT */

/* Memory size (in bytes) for MUSDK dma buffers */
#define MRVL_MUSDK_DMA_MEMSIZE (40 * 1024 * 1024)

struct mvep {
	uint32_t ref_count;

#ifdef MVCONF_NMP_BUILT
	/* Guest Info */
	struct nmp_guest *nmp_guest;
	char *guest_prb_str;
	struct nmp_guest_info guest_info;
#endif /* MVCONF_NMP_BUILT */
};

static struct mvep mvep;

int rte_mvep_init(enum mvep_module_type module __rte_unused,
		  struct rte_kvargs *kvlist __rte_unused)
{
	int ret;

	if (!mvep.ref_count) {
		ret = mv_sys_dma_mem_init(MRVL_MUSDK_DMA_MEMSIZE);
		if (ret)
			return ret;
	}
	mvep.ref_count++;

	switch (module) {
	case MVEP_MOD_T_GIU:
#ifdef MVCONF_NMP_BUILT
		if (!mvep.nmp_guest) {
			struct nmp_guest_params nmp_guest_params;

			/* NMP Guest initializations */
			memset(&nmp_guest_params, 0, sizeof(nmp_guest_params));
			nmp_guest_params.id = NMP_GUEST_ID;
			nmp_guest_params.timeout = NMP_GUEST_TIMEOUT;
			ret = nmp_guest_init(&nmp_guest_params,
					     &mvep.nmp_guest);
			if (ret)
				return ret;

			nmp_guest_get_probe_str(mvep.nmp_guest,
						&mvep.guest_prb_str);
			nmp_guest_get_relations_info(mvep.nmp_guest,
						     &mvep.guest_info);
		}
#endif /* MVCONF_NMP_BUILT */
		break;
	case MVEP_MOD_T_PP2:
	case MVEP_MOD_T_NETA:
	default:
		break;
	}

	return 0;
}

int rte_mvep_deinit(enum mvep_module_type module __rte_unused)
{
	mvep.ref_count--;

	if (!mvep.ref_count) {
		mv_sys_dma_mem_destroy();

#ifdef MVCONF_NMP_BUILT
		if (mvep.nmp_guest) {
			nmp_guest_deinit(mvep.nmp_guest);
			mvep.nmp_guest = NULL;
		}
#endif /* MVCONF_NMP_BUILT */
	}

	return 0;
}

#ifdef MVCONF_NMP_BUILT
int rte_mvep_get_nmp_guest_info(struct nmp_guest_info *inf, char **prb_str)
{
	if (!mvep.guest_prb_str)
		return -EFAULT;

	memcpy(inf, &mvep.guest_info, sizeof(mvep.guest_info));
	*prb_str = mvep.guest_prb_str;

	return 0;
}
#endif /* MVCONF_NMP_BUILT */

