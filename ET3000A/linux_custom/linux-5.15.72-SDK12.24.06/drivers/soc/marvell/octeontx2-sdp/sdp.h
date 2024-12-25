/* SPDX-License-Identifier: GPL-2.0
 * OcteonTX2 SDP driver
 *
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#ifndef SDP_H_
#define SDP_H_

#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/pci.h>
#include "mbox.h"

#define RVU_SDP_MAX_VFS		128
#define RVU_PFVF_PF_SHIFT	10
#define RVU_PFVF_PF_MASK	0x3F
#define RVU_PFVF_FUNC_SHIFT	0
#define RVU_PFVF_FUNC_MASK	0x3FF

#define RVU_PFFUNC(pf, func)	\
	((((pf) & RVU_PFVF_PF_MASK) << RVU_PFVF_PF_SHIFT) | \
	(((func) & RVU_PFVF_FUNC_MASK) << RVU_PFVF_FUNC_SHIFT))

#define SDP_BASE(a)		(0x86E080000000ull | a << 36)
#define SDP_REG_SIZE		0x42000000

#define SDPX_OUT_WMARK		(0x40060000ull)
#define SDPX_LINK_CFG		(0x40080180ull)
#define SDPX_OUT_BP_ENX_W1S(a)  (0x40080280ull | a << 4)
#define SDPX_GBL_CONTROL	(0x40080200ull)

#define SDPX_EPFX_RINFO(a) ({					\
		u64 offset;					\
		offset = (0x205f0ull | a << 25);		\
		if (is_cn10k_sdp(sdp))				\
			offset = (0x209f0ull | a << 25);	\
		offset; })

#define SDPX_EPVF_RINGX(a)		(0x26000ull | a << 4)
#define RINFO_NUMVF_BIT			48
#define RINFO_RPVF_BIT			32
#define RINFO_SRN_BIT			0

#define SDPX_MACX_PF_RING_CTL(a)	(0x2c000ull | a << 4)
#define RPPF_BIT_96XX			16
#define RPPF_BIT_98XX			32
#define PF_SRN_BIT_96XX			8
#define PF_SRN_BIT_98XX			0
#define NPFS_BIT_96XX			0
#define NPFS_BIT_98XX			48

#define MAX_PEMS			4
#define MAC_MASK_96XX			0x3
#define MAC_MASK_98XX			0x1
#define MAC_MASK_CN10K			0x1
#define MAX_PFS_PER_PEM			8

/* 96xx only PEM0 and PEM2 have SDP */
#define VALID_EP_PEMS_MASK_96XX		0x5
/* 95xx only PEM0 has SDP  */
#define VALID_EP_PEMS_MASK_95XX		0x1
/* 93xx only PEM0 has SDP */
#define VALID_EP_PEMS_MASK_93XX		0x1

/* 98xx only PEM0 and PEM1 for SDP0 */
#define VALID_EP_PEMS_MASK_98XX_SDP0	0x3
/* 98xx only PEM2 and PEM3 for SDP1 */
#define VALID_EP_PEMS_MASK_98XX_SDP1	0xc

#define VALID_EP_PEMS_MASK_106XX	0x1

#define PEMX_CFG(a)			(0x8E00000000D8ull | a << 36)
#define PEMX_CFG_HOSTMD_BIT_MASK	0x1
#define PEMX_CFG_HOSTMD_BIT_POS		0
#define PEMX_CFG_LANES_BIT_MASK		0x3
#define PEMX_CFG_LANES_BIT_POS		1

#define GPIO_PKG_VER			(0x803000001610ull)
#define CN93XXN_PKG			5

#define PCI_SUBSYS_DEVID_95XXN                 0xB400
#define PCI_SUBSYS_DEVID_95XXO                 0xB600

struct sdp_epf_info {
	u8      start_vf_idx;
	u8      num_sdp_vfs;
	u8      num_sdp_vf_rings;
};

struct sdp_dev {
	struct list_head	list;
	struct mutex		lock;
	struct pci_dev		*pdev;
	void __iomem		*sdp_base;
	void __iomem		*bar2;
	void __iomem		*af_mbx_base;
	void __iomem		*pfvf_mbx_base;
#define SDP_VF_ENABLED 0x1
	u32			flags;
	u32			num_vfs;
	u16			chan_base;
	u16			num_chan;
	bool			*irq_allocated;
	char			*irq_names;
	int			msix_count;
	int			pf;
	u8			valid_ep_pem_mask;
	u8			mac_mask;
	u8                      num_sdp_pfs;
	u8                      num_sdp_pf_rings;
#define SDP_MAX_EPFS   16
	struct sdp_epf_info     epf[SDP_MAX_EPFS];
	struct sdp_node_info info;

	struct otx2_mbox	pfvf_mbox; /* MBOXes for VF => PF channel */
	struct otx2_mbox	pfvf_mbox_up; /* MBOXes for PF => VF channel */
	struct otx2_mbox	afpf_mbox; /* MBOX for PF => AF channel */
	struct otx2_mbox	afpf_mbox_up; /* MBOX for AF => PF channel */
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct workqueue_struct	*afpf_mbox_wq; /* MBOX handler */
	struct workqueue_struct	*pfvf_mbox_wq; /* VF MBOX handler */
	struct rvu_vf		*vf_info;
	struct free_rsrcs_rsp	limits; /* Maximum limits for all VFs */
};

struct rvu_vf {
	struct work_struct	mbox_wrk;
	struct work_struct	mbox_wrk_up;
	struct work_struct	pfvf_flr_work;
	struct device_attribute in_use_attr;
	struct pci_dev		*pdev;
	struct kobject		*limits_kobj;
	/* pointer to PF struct this PF belongs to */
	struct sdp_dev		*sdp;
	int			vf_id;
	int			intr_idx; /* vf_id%64 actually */
	bool			in_use;
	bool			got_flr;
};

#endif

