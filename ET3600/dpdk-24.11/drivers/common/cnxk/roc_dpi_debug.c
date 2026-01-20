/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include <fcntl.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "roc_api.h"
#include "roc_priv.h"

#define dpi_dump(file, fmt, ...)                                                                   \
	do {                                                                                       \
		if ((file) == NULL)                                                                \
			plt_dump(fmt, ##__VA_ARGS__);                                              \
		else                                                                               \
			fprintf(file, fmt "\n", ##__VA_ARGS__);                                    \
	} while (0)

int
roc_dpi_lf_dump(struct roc_dpi_lf *lf, FILE *file)
{
	struct roc_dpi_lf_que *lf_que;
	uintptr_t rbase;
	int i;

	dpi_dump(file, "DPI LF%u", lf->slot);

	rbase = lf->rbase;
	for (i = 0; i < ROC_DPI_LF_RINGS; i++) {
		lf_que = &lf->queue[i];
		dpi_dump(file, "\tcmd_base@%u: 0x%" PRIx64, i, PLT_U64_CAST(lf_que->cmd_base));
		dpi_dump(file, "\tqsize@%u: %u", i, lf_que->qsize);
		dpi_dump(file, "\tDPI_LF_RING[%u]_CFG: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_CFG(i)));
		dpi_dump(file, "\tDPI_LF_RING[%u]_BASE: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_BASE(i)));
		dpi_dump(file, "\tDPI_LF_RING[%u]_RIDX: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_RIDX(i)));
		dpi_dump(file, "\tDPI_LF_RING[%u]_WIDX: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_WIDX(i)));
		dpi_dump(file, "\tDPI_LF_RING[%u]_ERR: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_ERR(i)));
		dpi_dump(file, "\tDPI_LF_RING[%u]_INT: 0x%" PRIx64, i,
			 plt_read64(rbase + DPI_LF_RINGX_INT(i)));
	}

	return 0;
}
