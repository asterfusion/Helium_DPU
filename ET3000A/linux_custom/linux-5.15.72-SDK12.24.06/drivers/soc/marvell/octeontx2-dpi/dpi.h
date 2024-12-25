/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell OcteonTx2 DPI PF driver
 *
 * Copyright (C) 2023 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __DPI_H__
#define __DPI_H__

 /* PCI device IDs */
#define PCI_DEVID_OCTEONTX2_DPI_PF	0xA080
#define PCI_DEVID_OCTEONTX2_DPI_VF	0xA081
#define PCI_SUBDEVID_OCTEONTX3_DPI_PF	0xB900

/* PCI BAR nos */
#define PCI_DPI_PF_CFG_BAR		0
#define PCI_DPI_PF_MSIX_BAR		4
#define PCI_DPI_VF_CFG_BAR		0
#define PCI_DPI_VF_MSIX_BAR		4
#define DPI_VF_CFG_SIZE			0x100000
#define DPI_VF_OFFSET(x)		(0x20000000 | 0x100000 * (x))

/* MSI-X interrupts */
#define DPI_MAX_REQQ_INT ({				\
	u32 val;					\
	val = 8;					\
	if (is_cn10k_dpi(dpi))				\
		val = 32;				\
	val; })						\

#define DPI_MAX_CC_INT			64

/* MSI-X interrupt vectors indexes */
#define DPI_CCX_INT_IDX			0x0
#define DPI_REQQX_INT_IDX		0x40
#define DPI_SDP_FLR_RING_LINTX_IDX	0x48
#define DPI_SDP_IRE_LINTX_IDX		0x4C
#define DPI_SDP_ORE_LINTX_IDX		0x50
#define DPI_SDP_ORD_LINTX_IDX		0x54
#define DPI_EPFX_PP_VF_LINTX_IDX	0x58
#define DPI_EPFX_DMA_VF_LINTX_IDX	0x78
#define DPI_EPFX_MISC_LINTX_IDX		0x98
#define DPI_PF_RAS_IDX			0xA8

#define DPI_MAX_ENGINES			6
#define DPI_MAX_VFS			32

/****************  Macros for register modification ************/
#define DPI_DMA_IBUFF_CSIZE_CSIZE(x)		((x) & 0x3fff)
#define DPI_DMA_IBUFF_CSIZE_GET_CSIZE(x)	((x) & 0x3fff)

#define DPI_DMA_IBUFF_CSIZE_NPA_FREE		(1 << 16)

#define DPI_DMA_IDS_INST_STRM(x)		((uint64_t)((x) & 0xff) << 40)
#define DPI_DMA_IDS_GET_INST_STRM(x)		(((x) >> 40) & 0xff)

#define DPI_DMA_IDS_DMA_STRM(x)			((uint64_t)((x) & 0xff) << 32)
#define DPI_DMA_IDS_GET_DMA_STRM(x)		(((x) >> 32) & 0xff)

#define DPI_DMA_IDS_DMA_NPA_PF_FUNC(x)		((uint64_t)((x) & 0xffff) << 16)
#define DPI_DMA_IDS_GET_DMA_NPA_PF_FUNC(x)	(((x) >> 16) & 0xffff)

#define DPI_DMA_IDS_DMA_SSO_PF_FUNC(x)		((uint64_t)((x) & 0xffff))
#define DPI_DMA_IDS_GET_DMA_SSO_PF_FUNC(x)	((x) & 0xffff)

#define DPI_DMA_IDS2_INST_AURA(x)		((uint64_t)((x) & 0xfffff))
#define DPI_DMA_IDS2_GET_INST_AURA(x)		((x) & 0xfffff)

#define DPI_ENG_BUF_BLKS(x)			((x) & 0x1fULL)
#define DPI_ENG_BUF_GET_BLKS(x)			((x) & 0x1fULL)

#define DPI_ENG_BUF_BASE(x)			(((x) & 0x3fULL) << 16)
#define DPI_ENG_BUF_GET_BASE(x)			(((x) >> 16) & 0x3fULL)

#define DPI_DMA_ENG_EN_QEN(x)			((x) & 0xffULL)
#define DPI_DMA_ENG_EN_GET_QEN(x)		((x) & 0xffULL)

#define DPI_DMA_ENG_EN_MOLR(x)			(((x) & 0x3ffULL) << 32)
#define DPI_DMA_ENG_EN_GET_MOLR(x)		(((x) >> 32) & 0x3ffULL)

#define DPI_DMA_CONTROL_DMA_ENB(x)		(((x) & 0x3fULL) << 48)
#define DPI_DMA_CONTROL_GET_DMA_ENB(x)		(((x) >> 48) & 0x3fULL)

#define DPI_DMA_CONTROL_O_ES(x)			(((x) & 0x3ULL) << 15)
#define DPI_DMA_CONTROL_GET_O_ES(x)		(((x) >> 15) & 0x3ULL)

#define DPI_DMA_CONTROL_O_MODE			(0x1ULL << 14)
#define DPI_DMA_CONTROL_O_NS			(0x1ULL << 17)
#define DPI_DMA_CONTROL_O_RO			(0x1ULL << 18)
#define DPI_DMA_CONTROL_O_ADD1			(0x1ULL << 19)
#define DPI_DMA_CONTROL_LDWB			(0x1ULL << 32)
#define DPI_DMA_CONTROL_NCB_TAG_DIS		(0x1ULL << 34)
#define DPI_DMA_CONTROL_WQECSMODE1		(0x1ULL << 37)
#define DPI_DMA_CONTROL_ZBWCSEN			(0x1ULL << 39)
#define DPI_DMA_CONTROL_WQECSOFF(offset)	(((uint64_t)offset) << 40)
#define DPI_DMA_CONTROL_WQECSDIS		(0x1ULL << 47)
#define DPI_DMA_CONTROL_UIO_DIS			(0x1ULL << 55)
#define DPI_DMA_CONTROL_PKT_EN			(0x1ULL << 56)
#define DPI_DMA_CONTROL_FFP_DIS			(0x1ULL << 59)

#define DPI_CTL_EN				(0x1ULL)

/******************** macros for Interrupts ************************/
#define DPI_DMA_CC_INT				(0x1ULL)

#define DPI_REQQ_INT_INSTRFLT			(0x1ULL)
#define DPI_REQQ_INT_RDFLT			(0x1ULL << 1)
#define DPI_REQQ_INT_WRFLT			(0x1ULL << 2)
#define DPI_REQQ_INT_CSFLT			(0x1ULL << 3)
#define DPI_REQQ_INT_INST_DBO			(0x1ULL << 4)
#define DPI_REQQ_INT_INST_ADDR_NULL		(0x1ULL << 5)
#define DPI_REQQ_INT_INST_FILL_INVAL		(0x1ULL << 6)
#define DPI_REQQ_INT_INSTR_PSN			(0x1ULL << 7)

#define DPI_REQQ_INT \
	(DPI_REQQ_INT_INSTRFLT		| \
	DPI_REQQ_INT_RDFLT		| \
	DPI_REQQ_INT_WRFLT		| \
	DPI_REQQ_INT_CSFLT		| \
	DPI_REQQ_INT_INST_DBO		| \
	DPI_REQQ_INT_INST_ADDR_NULL	| \
	DPI_REQQ_INT_INST_FILL_INVAL	| \
	DPI_REQQ_INT_INSTR_PSN)

#define DPI_PF_RAS_EBI_DAT_PSN		(0x1ULL)
#define DPI_PF_RAS_NCB_DAT_PSN		(0x1ULL << 1)
#define DPI_PF_RAS_NCB_CMD_PSN		(0x1ULL << 2)
#define DPI_PF_RAS_INT \
	(DPI_PF_RAS_EBI_DAT_PSN  | \
	 DPI_PF_RAS_NCB_DAT_PSN  | \
	 DPI_PF_RAS_NCB_CMD_PSN)


/***************** Registers ******************/
#define DPI_DMAX_IBUFF_CSIZE(x)			(0x0ULL | ((x) << 11))
#define DPI_DMAX_REQBANK0(x)			(0x8ULL | ((x) << 11))
#define DPI_DMAX_REQBANK1(x)			(0x10ULL | ((x) << 11))
#define DPI_DMAX_IDS(x)				(0x18ULL | ((x) << 11))
#define DPI_DMAX_IDS2(x)			(0x20ULL | ((x) << 11))
#define DPI_DMAX_IFLIGHT(x)			(0x28ULL | ((x) << 11))
#define DPI_DMAX_QRST(x)			(0x30ULL | ((x) << 11))
#define DPI_DMAX_ERR_RSP_STATUS(x)		(0x38ULL | ((x) << 11))

#define DPI_CSCLK_ACTIVE_PC ({				\
	u64 offset;					\
							\
	offset = (0x4000ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10000ULL);			\
	offset; })					\

#define DPI_CTL ({					\
	u64 offset;					\
							\
	offset = (0x4010ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10010ULL);			\
	offset; })					\

#define DPI_DMA_CONTROL ({				\
	u64 offset;					\
							\
	offset = (0x4018ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10018ULL);			\
	offset; })					\

#define DPI_DMA_ENGX_EN(x) ({				\
	u64 offset;					\
							\
	offset = (0x4040ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10040ULL | ((x) << 3));	\
	offset; })					\

#define DPI_ENGX_BUF(x)	({				\
	u64 offset;					\
							\
	offset = (0x40C0ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x100C0ULL | ((x) << 3));	\
	offset; })					\

#define DPI_EBUS_PORTX_CFG(x) ({			\
	u64 offset;					\
							\
	offset = (0x4100ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10100ULL | ((x) << 3));	\
	offset; })					\

#define DPI_EBUS_PORTX_ERR_INFO(x) ({			\
	u64 offset;					\
							\
	offset = (0x4200ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10200ULL | ((x) << 3));	\
	offset; })					\

#define DPI_EBUS_PORTX_ERR(x) ({			\
	u64 offset;					\
							\
	offset = (0x4280ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10280ULL | ((x) << 3));	\
	offset; })					\

#define DPI_REQ_ERR_RSP ({				\
	u64 offset;					\
							\
	offset = 0x4078ULL;				\
	if (is_cn10k_dpi(dpi))				\
		offset = 0x10070ULL;			\
	offset; })					\

#define DPI_PKT_ERR_RSP ({				\
	u64 offset;					\
							\
	offset = 0x4098ULL;				\
	if (is_cn10k_dpi(dpi))				\
		offset = 0x10080ULL;			\
	offset; })					\

#define DPI_EPFX_MAX_CNT ({				\
	u32 val;					\
	val = 16;					\
	if (is_cn10k_dpi(dpi))				\
		val = 4;				\
	val; })						\

#define DPI_EPFX_DMA_VF_LINTX(x, y) ({			\
	u64 offset;					\
							\
	offset = (0x6800ULL | (x) << 5 | (y) << 4);	\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x14000ULL | ((x) << 5));	\
	offset; })					\

#define DPI_EPFX_PP_VF_LINTX(x, y) ({			\
	u64 offset;					\
							\
	offset = (0x7200ULL | (x) << 5 | (y) << 4);	\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x14C00ULL | ((x) << 5));	\
	offset; })					\

#define DPI_EPFX_MISC_LINTX(x) ({			\
	u64 offset;					\
							\
	offset = (0x7000ULL | (x) << 5);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x14A00ULL | ((x) << 5));	\
	offset; })					\

#define DPI_PF_RAS ({					\
	u64 offset;					\
							\
	offset = (0x4308ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10308ULL);			\
	offset; })					\

#define DPI_PF_RAS_ENA_W1C ({				\
	u64 offset;					\
							\
	offset = (0x4318ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10318ULL);			\
	offset; })					\

#define DPI_PF_RAS_ENA_W1S ({				\
	u64 offset;					\
							\
	offset = (0x4320ULL);				\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x10320ULL);			\
	offset; })					\

#define DPI_DMA_CCX_INT(x) ({				\
	u64 offset;					\
							\
	offset = (0x5000ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x11000ULL | ((x) << 3));	\
	offset; })					\

#define DPI_DMA_CCX_INT_ENA_W1C(x) ({			\
	u64 offset;					\
							\
	offset = (0x5800ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x11800ULL | ((x) << 3));	\
	offset; })					\

#define DPI_REQQX_INT(x) ({				\
	u64 offset;					\
							\
	offset = (0x6600ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x12C00ULL | ((x) << 5));	\
	offset; })					\

#define DPI_REQQX_INT_ENA_W1C(x) ({			\
	u64 offset;					\
							\
	offset = (0x6680ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x13800ULL | ((x) << 5));	\
	offset; })					\

#define DPI_REQQX_INT_ENA_W1S(x) ({			\
	u64 offset;					\
							\
	offset = (0x66C0ULL | (x) << 3);		\
	if (is_cn10k_dpi(dpi))				\
		offset = (0x13C00ULL | ((x) << 5));	\
	offset; })					\

#define DPI_WCTL_FIF_THR			(0x17008ULL)

#define DPI_EBUS_MRRS_MIN			128
#define DPI_EBUS_MRRS_MAX			1024
#define DPI_EBUS_MPS_MIN			128
#define DPI_EBUS_MPS_MAX			1024
#define DPI_EBUS_MAX_PORTS			2
#define DPI_EBUS_PORTX_CFG_MRRS(x)		(((x) & 0x7) << 0)
#define DPI_EBUS_PORTX_CFG_MPS(x)		(((x) & 0x7) << 4)

/* VF Registers: */
#define DPI_VDMA_EN		(0x0ULL)
#define DPI_VDMA_REQQ_CTL	(0x8ULL)
#define DPI_VDMA_DBELL		(0x10ULL)
#define DPI_VDMA_SADDR		(0x18ULL)
#define DPI_VDMA_COUNTS		(0x20ULL)
#define DPI_VDMA_NADDR		(0x28ULL)
#define DPI_VDMA_IWBUSY		(0x30ULL)
#define DPI_VDMA_CNT		(0x38ULL)
#define DPI_VF_INT		(0x100ULL)
#define DPI_VF_INT_W1S		(0x108ULL)
#define DPI_VF_INT_ENA_W1C	(0x110ULL)
#define DPI_VF_INT_ENA_W1S	(0x118ULL)

struct dpivf_config {
	uint16_t csize;
	uint32_t aura;
	uint16_t sso_pf_func;
	uint16_t npa_pf_func;
};

struct dpipf_vf {
	uint8_t this_vfid;
	bool setup_done;
	struct dpivf_config vf_config;
};

struct dpipf {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	int			num_vec;
	struct msix_entry	*msix_entries;
	int			total_vfs;
	int			vfs_in_use;
	struct dpipf_vf		vf[DPI_MAX_VFS];
	/* lock to serialize queue access */
	spinlock_t		vf_lock;
};

#define DPI_QUEUE_OPEN  0x1
#define DPI_QUEUE_CLOSE 0x2
#define DPI_REG_DUMP    0x3
#define DPI_GET_REG_CFG 0x4
#define DPI_QUEUE_OPEN_V2 0x5

union dpi_mbox_message_t {
	uint64_t u[2];
	struct dpi_mbox_message_s {
		/* VF ID to configure */
		uint64_t vfid           :8;
		/* Command code */
		uint64_t cmd            :4;
		/* Command buffer size in 8-byte words */
		uint64_t csize          :14;
		/* aura of the command buffer */
		uint64_t aura           :20;
		/* SSO PF function */
		uint64_t sso_pf_func    :16;
		/* NPA PF function */
		uint64_t npa_pf_func    :16;
		/* Work queue completion status enable */
		uint64_t wqecs		:1;
		/* Work queue completion status byte offset */
		uint64_t wqecsoff	:7;
	} s;
};

struct otx2_dpipf_com_s {
	int (*queue_config)(struct pci_dev *pfdev,
			    union dpi_mbox_message_t *req);
};

extern struct otx2_dpipf_com_s otx2_dpipf_com;

#endif
