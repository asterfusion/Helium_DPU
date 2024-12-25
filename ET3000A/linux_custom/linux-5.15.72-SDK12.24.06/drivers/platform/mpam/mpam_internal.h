// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2021 Arm Ltd.

#ifndef MPAM_INTERNAL_H
#define MPAM_INTERNAL_H

#include <linux/arm_mpam.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/jump_label.h>
#include <linux/mailbox_client.h>
#include <linux/mutex.h>
#include <linux/resctrl.h>
#include <linux/sizes.h>
#include <linux/srcu.h>

DECLARE_STATIC_KEY_FALSE(mpam_enabled);

/* Value to indicate the allocated monitor is derived from the RMID index. */
#define USE_RMID_IDX	(U16_MAX + 1)

static inline bool mpam_is_enabled(void)
{
	return static_branch_likely(&mpam_enabled);
}

struct mpam_msc
{
	/* member of mpam_all_msc */
	struct list_head        glbl_list;

	int			id;
	struct platform_device *pdev;

	/* Not modified after mpam_is_enabled() becomes true */
	enum mpam_msc_iface	iface;
	u32			pcc_subspace_id;
	struct mbox_client	pcc_cl;
	struct pcc_mbox_chan	*pcc_chan;
	u32			nrdy_usec;
	cpumask_t		accessibility;
	bool			has_extd_esr;

	int				reenable_error_ppi;
	struct mpam_msc * __percpu	*error_dev_id;

	atomic_t		online_refs;
	
	struct mutex		lock;
	bool			probed;
	bool			error_irq_registered;
	u16			partid_max;
	u8			pmg_max;
	unsigned long		ris_idxs[128 / BITS_PER_LONG];
	u32			ris_max;

	/* mpam_msc_ris of this component */
	struct list_head	ris;

	/*
	 * part_sel_lock protects access to the MSC hardware registers that are
	 * affected by MPAMCFG_PART_SEL. (including the ID registers)
	 * If needed, take msc->lock first.
	 */
	spinlock_t		part_sel_lock;
	spinlock_t		mon_sel_lock;
	void __iomem *		mapped_hwpage;
	size_t			mapped_hwpage_sz;
};

/*
 * When we compact the supported features, we don't care what they are.
 * Storing them as a bitmap makes life easy.
 */
typedef u32 mpam_features_t;

/* Bits for mpam_features_t */
enum mpam_device_features {
	mpam_feat_ccap_part = 0,
	mpam_feat_cpor_part,
	mpam_feat_mbw_part,
	mpam_feat_mbw_min,
	mpam_feat_mbw_max,
	mpam_feat_mbw_prop,
	mpam_feat_intpri_part,
	mpam_feat_intpri_part_0_low,
	mpam_feat_dspri_part,
	mpam_feat_dspri_part_0_low,
	mpam_feat_msmon,
	mpam_feat_msmon_csu,
	mpam_feat_msmon_csu_capture,
	mpam_feat_msmon_mbwu,
	mpam_feat_msmon_mbwu_capture,
	mpam_feat_msmon_capt,
	mpam_feat_partid_nrw,
	MPAM_FEATURE_LAST,
};
#define MPAM_ALL_FEATURES      ((1<<MPAM_FEATURE_LAST) - 1)

struct mpam_props
{
	mpam_features_t		features;

	u16			cpbm_wd;
	u16			mbw_pbm_bits;
	u8			bwa_wd;
	u16			cmax_wd;
	u16			intpri_wd;
	u16			dspri_wd;
	u16			num_csu_mon;
	u16			num_mbwu_mon;
};

#define mpam_has_feature(_feat, x)	((1<<_feat) & (x)->features)
#define mpam_set_feature(_feat, x)	((x)->features |= (1<<_feat))

static inline void mpam_clear_feature(enum mpam_device_features feat,
				      mpam_features_t *supported)
{
	*supported &= ~(1<<feat);
}

struct mpam_class
{
	/* mpam_components in this class */
	struct list_head	components;

	cpumask_t		affinity;

	struct mpam_props	props;
	u32			nrdy_usec;
	u8			level;
	enum mpam_class_types	type;

	/* member of mpam_classes */
	struct list_head	classes_list;

	struct ida		ida_csu_mon;
	struct ida		ida_mbwu_mon;
};

struct mpam_config {
	/* Which configuration values are valid. 0 is used for reset */
	mpam_features_t		features;

	u32	cpbm;
	u32	mbw_pbm;
	u16	mbw_max;
};

struct mpam_component
{
	u32			comp_id;

	/* mpam_msc_ris in this component */
	struct list_head	ris;

	cpumask_t		affinity;

	/*
	 * Array of configuration values, indexed by partid.
	 * Read from cpuhp callbacks, hold the cpuhp lock when writing.
	 */
	struct mpam_config	*cfg;

	/* member of mpam_class:components */
	struct list_head	class_list;

	/* parent: */
	struct mpam_class	*class;
};

struct mon_cfg {
	u16     mon;
	u8      pmg;
	bool    match_pmg;
	u32     partid;
};


/*
 * Changes to enabled and cfg are protected by the msc->lock.
 * Changes to reset_on_next_read, prev_val and correction are protected by the
 * msc's mon_sel_lock.
 */
struct msmon_mbwu_state {
	bool		enabled;
	bool		reset_on_next_read;
	struct mon_cfg	cfg;

	/* The value last read from the hardware. Used to detect overflow. */
	u64		prev_val;

	/*
	 * The value to add to the new reading to account for power management,
	 * and shifts to trigger the overflow interrupt.
	 */
	u64		correction;
};

struct mpam_msc_ris
{
	u8			ris_idx;
	u64			idr;
	struct mpam_props	props;
	bool			in_reset_state;

	cpumask_t		affinity;

	/* member of mpam_component:ris */
	struct list_head	comp_list;

	/* member of mpam_msc:ris */
	struct list_head	msc_list;

	/* parents: */
	struct mpam_msc		*msc;
	struct mpam_component	*comp;

	/* msmon mbwu configuration is preserved over reset */
	struct msmon_mbwu_state	*mbwu_state;
};

struct mpam_resctrl_dom {
	struct mpam_component	*comp;
	struct rdt_domain	resctrl_dom;
};

struct mpam_resctrl_res {
	struct mpam_class	*class;
	struct rdt_resource	resctrl_res;
};

static inline int mpam_alloc_csu_mon(struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_msmon_csu, cprops))
		return -EOPNOTSUPP;

	return ida_alloc_range(&class->ida_csu_mon, 0, cprops->num_csu_mon,
                                GFP_KERNEL);
}

static inline void mpam_free_csu_mon(struct mpam_class *class, int csu_mon)
{
	ida_free(&class->ida_csu_mon, csu_mon);
}

static inline int mpam_alloc_mbwu_mon(struct mpam_class *class)
{
	struct mpam_props *cprops = &class->props;

	if (!mpam_has_feature(mpam_feat_msmon_mbwu, cprops))
		return -EOPNOTSUPP;

	return ida_alloc_range(&class->ida_mbwu_mon, 0, cprops->num_mbwu_mon,
                                GFP_KERNEL);
}

static inline void mpam_free_mbwu_mon(struct mpam_class *class, int mbwu_mon)
{
	ida_free(&class->ida_mbwu_mon, mbwu_mon);
}

/* List of all classes */
extern struct list_head mpam_classes;
extern struct srcu_struct mpam_srcu;

/* System wide partid/pmg values */
extern u16 mpam_partid_max;
extern u8 mpam_pmg_max;

/* Scheduled work callback to enable mpam once all MSC have been probed */
void mpam_enable(struct work_struct *work);
void mpam_disable(struct work_struct *work);

void mpam_reset_class(struct mpam_class *class);

int mpam_apply_config(struct mpam_component *comp, u16 partid,
		      struct mpam_config *cfg);

int mpam_msmon_read(struct mpam_component *comp, struct mon_cfg *ctx,
		    enum mpam_device_features, u64 *val);
void mpam_msmon_reset_mbwu(struct mpam_component *comp, struct mon_cfg *ctx);

int mpam_resctrl_online_cpu(unsigned int cpu);
int mpam_resctrl_offline_cpu(unsigned int cpu);

int mpam_resctrl_setup(void);
void mpam_resctrl_exit(void);

/*
 * MPAM MSCs have the following register layout. See:
 * Arm Architecture Reference Manual Supplement - Memory System Resource
 * Partitioning and Monitoring (MPAM), for Armv8-A. DDI 0598A.a
 */
#define MPAM_ARCHITECTURE_V1    0x10

/* Memory mapped control pages: */
/* ID Register offsets in the memory mapped page */
#define MPAMF_IDR               0x0000  /* features id register */
#define MPAMF_MSMON_IDR         0x0080  /* performance monitoring features */
#define MPAMF_IMPL_IDR          0x0028  /* imp-def partitioning */
#define MPAMF_CPOR_IDR          0x0030  /* cache-portion partitioning */
#define MPAMF_CCAP_IDR          0x0038  /* cache-capacity partitioning */
#define MPAMF_MBW_IDR           0x0040  /* mem-bw partitioning */
#define MPAMF_PRI_IDR           0x0048  /* priority partitioning */
#define MPAMF_CSUMON_IDR        0x0088  /* cache-usage monitor */
#define MPAMF_MBWUMON_IDR       0x0090  /* mem-bw usage monitor */
#define MPAMF_PARTID_NRW_IDR    0x0050  /* partid-narrowing */
#define MPAMF_IIDR              0x0018  /* implementer id register */
#define MPAMF_AIDR              0x0020  /* architectural id register */

/* Configuration and Status Register offsets in the memory mapped page */
#define MPAMCFG_PART_SEL        0x0100  /* partid to configure: */
#define MPAMCFG_CPBM            0x1000  /* cache-portion config */
#define MPAMCFG_CMAX            0x0108  /* cache-capacity config */
#define MPAMCFG_MBW_MIN         0x0200  /* min mem-bw config */
#define MPAMCFG_MBW_MAX         0x0208  /* max mem-bw config */
#define MPAMCFG_MBW_WINWD       0x0220  /* mem-bw accounting window config */
#define MPAMCFG_MBW_PBM         0x2000  /* mem-bw portion bitmap config */
#define MPAMCFG_PRI             0x0400  /* priority partitioning config */
#define MPAMCFG_MBW_PROP        0x0500  /* mem-bw stride config */
#define MPAMCFG_INTPARTID       0x0600  /* partid-narrowing config */

#define MSMON_CFG_MON_SEL       0x0800  /* monitor selector */
#define MSMON_CFG_CSU_FLT       0x0810  /* cache-usage monitor filter */
#define MSMON_CFG_CSU_CTL       0x0818  /* cache-usage monitor config */
#define MSMON_CFG_MBWU_FLT      0x0820  /* mem-bw monitor filter */
#define MSMON_CFG_MBWU_CTL      0x0828  /* mem-bw monitor config */
#define MSMON_CSU               0x0840  /* current cache-usage */
#define MSMON_CSU_CAPTURE       0x0848  /* last cache-usage value captured */
#define MSMON_MBWU              0x0860  /* current mem-bw usage value */
#define MSMON_MBWU_CAPTURE      0x0868  /* last mem-bw value captured */
#define MSMON_CAPT_EVNT         0x0808  /* signal a capture event */
#define MPAMF_ESR               0x00F8  /* error status register */
#define MPAMF_ECR               0x00F0  /* error control register */

/* MPAMF_IDR - MPAM features ID register */
#define MPAMF_IDR_PARTID_MAX            GENMASK(15, 0)
#define MPAMF_IDR_PMG_MAX               GENMASK(23, 16)
#define MPAMF_IDR_HAS_CCAP_PART         BIT(24)
#define MPAMF_IDR_HAS_CPOR_PART         BIT(25)
#define MPAMF_IDR_HAS_MBW_PART          BIT(26)
#define MPAMF_IDR_HAS_PRI_PART          BIT(27)
#define MPAMF_IDR_HAS_EXT               BIT(28)
#define MPAMF_IDR_HAS_IMPL_IDR          BIT(29)
#define MPAMF_IDR_HAS_MSMON             BIT(30)
#define MPAMF_IDR_HAS_PARTID_NRW        BIT(31)
#define MPAMF_IDR_HAS_RIS               BIT(32)
#define MPAMF_IDR_HAS_EXT_ESR           BIT(38)
#define MPAMF_IDR_HAS_ESR               BIT(39)
#define MPAMF_IDR_RIS_MAX               GENMASK(59, 56)


/* MPAMF_MSMON_IDR - MPAM performance monitoring ID register */
#define MPAMF_MSMON_IDR_MSMON_CSU               BIT(16)
#define MPAMF_MSMON_IDR_MSMON_MBWU              BIT(17)
#define MPAMF_MSMON_IDR_HAS_LOCAL_CAPT_EVNT     BIT(31)

/* MPAMF_CPOR_IDR - MPAM features cache portion partitioning ID register */
#define MPAMF_CPOR_IDR_CPBM_WD                  GENMASK(15, 0)

/* MPAMF_CCAP_IDR - MPAM features cache capacity partitioning ID register */
#define MPAMF_CCAP_IDR_CMAX_WD                  GENMASK(5, 0)

/* MPAMF_MBW_IDR - MPAM features memory bandwidth partitioning ID register */
#define MPAMF_MBW_IDR_BWA_WD            GENMASK(5, 0)
#define MPAMF_MBW_IDR_HAS_MIN           BIT(10)
#define MPAMF_MBW_IDR_HAS_MAX           BIT(11)
#define MPAMF_MBW_IDR_HAS_PBM           BIT(12)
#define MPAMF_MBW_IDR_HAS_PROP          BIT(13)
#define MPAMF_MBW_IDR_WINDWR            BIT(14)
#define MPAMF_MBW_IDR_BWPBM_WD          GENMASK(28, 16)

/* MPAMF_PRI_IDR - MPAM features priority partitioning ID register */
#define MPAMF_PRI_IDR_HAS_INTPRI        BIT(0)
#define MPAMF_PRI_IDR_INTPRI_0_IS_LOW   BIT(1)
#define MPAMF_PRI_IDR_INTPRI_WD         GENMASK(9, 4)
#define MPAMF_PRI_IDR_HAS_DSPRI         BIT(16)
#define MPAMF_PRI_IDR_DSPRI_0_IS_LOW    BIT(17)
#define MPAMF_PRI_IDR_DSPRI_WD          GENMASK(25, 20)

/* MPAMF_CSUMON_IDR - MPAM cache storage usage monitor ID register */
#define MPAMF_CSUMON_IDR_NUM_MON        GENMASK(15, 0)
#define MPAMF_CSUMON_IDR_HAS_CAPTURE    BIT(31)

/* MPAMF_MBWUMON_IDR - MPAM memory bandwidth usage monitor ID register */
#define MPAMF_MBWUMON_IDR_NUM_MON       GENMASK(15, 0)
#define MPAMF_MBWUMON_IDR_HAS_CAPTURE   BIT(31)

/* MPAMF_PARTID_NRW_IDR - MPAM PARTID narrowing ID register */
#define MPAMF_PARTID_NRW_IDR_INTPARTID_MAX      GENMASK(15, 0)

/* MPAMF_IIDR - MPAM implementation ID register */
#define MPAMF_IIDR_PRODUCTID    GENMASK(31, 20)
#define MPAMF_IIDR_PRODUCTID_SHIFT	20
#define MPAMF_IIDR_VARIANT      GENMASK(19, 16)
#define MPAMF_IIDR_VARIANT_SHIFT	16
#define MPAMF_IIDR_REVISON      GENMASK(15, 12)
#define MPAMF_IIDR_REVISON_SHIFT	12
#define MPAMF_IIDR_IMPLEMENTER  GENMASK(11, 0)
#define MPAMF_IIDR_IMPLEMENTER_SHIFT	0

/* MPAMF_AIDR - MPAM architecture ID register */
#define MPAMF_AIDR_ARCH_MAJOR_REV       GENMASK(7, 4)
#define MPAMF_AIDR_ARCH_MINOR_REV       GENMASK(3, 0)

/* MPAMCFG_PART_SEL - MPAM partition configuration selection register */
#define MPAMCFG_PART_SEL_PARTID_SEL     GENMASK(15, 0)
#define MPAMCFG_PART_SEL_INTERNAL       BIT(16)
#define MPAMCFG_PART_SEL_RIS            GENMASK(27, 24)

/* MPAMCFG_CMAX - MPAM cache portion bitmap partition configuration register */
#define MPAMCFG_CMAX_CMAX               GENMASK(15, 0)

/*
 * MPAMCFG_MBW_MIN - MPAM memory minimum bandwidth partitioning configuration
 *                   register
 */
#define MPAMCFG_MBW_MIN_MIN             GENMASK(15, 0)

/*
 * MPAMCFG_MBW_MAX - MPAM memory maximum bandwidth partitioning configuration
 *                   register
 */
#define MPAMCFG_MBW_MAX_MAX             GENMASK(15, 0)
#define MPAMCFG_MBW_MAX_HARDLIM         BIT(31)

/*
 * MPAMCFG_MBW_WINWD - MPAM memory bandwidth partitioning window width
 *                     register
 */
#define MPAMCFG_MBW_WINWD_US_FRAC       GENMASK(7, 0)
#define MPAMCFG_MBW_WINWD_US_INT        GENMASK(23, 8)


/* MPAMCFG_PRI - MPAM priority partitioning configuration register */
#define MPAMCFG_PRI_INTPRI              GENMASK(15, 0)
#define MPAMCFG_PRI_DSPRI               GENMASK(31, 16)

/*
 * MPAMCFG_MBW_PROP - Memory bandwidth proportional stride partitioning
 *                    configuration register
 */
#define MPAMCFG_MBW_PROP_STRIDEM1       GENMASK(15, 0)
#define MPAMCFG_MBW_PROP_EN             BIT(31)

/*
 * MPAMCFG_INTPARTID - MPAM internal partition narrowing configuration register
 */
#define MPAMCFG_INTPARTID_INTPARTID     GENMASK(15, 0)
#define MPAMCFG_INTPARTID_INTERNAL      BIT(16)

/* MSMON_CFG_MON_SEL - Memory system performance monitor selection register */
#define MSMON_CFG_MON_SEL_MON_SEL       GENMASK(7, 0)
#define MSMON_CFG_MON_SEL_RIS           GENMASK(27, 24)

/* MPAMF_ESR - MPAM Error Status Register */
#define MPAMF_ESR_PARTID_OR_MON GENMASK(15, 0)
#define MPAMF_ESR_PMG           GENMASK(23, 16)
#define MPAMF_ESR_ERRCODE       GENMASK(27, 24)
#define MPAMF_ESR_OVRWR         BIT(31)
#define MPAMF_ESR_RIS           GENMASK(35, 32)

/* MPAMF_ECR - MPAM Error Control Register */
#define MPAMF_ECR_INTEN         BIT(0)

/* Error conditions in accessing memory mapped registers */
#define MPAM_ERRCODE_NONE                       0
#define MPAM_ERRCODE_PARTID_SEL_RANGE           1
#define MPAM_ERRCODE_REQ_PARTID_RANGE           2
#define MPAM_ERRCODE_MSMONCFG_ID_RANGE          3
#define MPAM_ERRCODE_REQ_PMG_RANGE              4
#define MPAM_ERRCODE_MONITOR_RANGE              5
#define MPAM_ERRCODE_INTPARTID_RANGE            6
#define MPAM_ERRCODE_UNEXPECTED_INTERNAL        7

/*
 * MSMON_CFG_CSU_FLT - Memory system performance monitor configure cache storage
 *                    usage monitor filter register
 */
#define MSMON_CFG_CSU_FLT_PARTID       GENMASK(15, 0)
#define MSMON_CFG_CSU_FLT_PMG          GENMASK(23, 16)

/*
 * MSMON_CFG_CSU_CTL - Memory system performance monitor configure cache storage
 *                    usage monitor control register
 * MSMON_CFG_MBWU_CTL - Memory system performance monitor configure memory
 *                     bandwidth usage monitor control register
 */
#define MSMON_CFG_x_CTL_TYPE           GENMASK(7, 0)
#define MSMON_CFG_x_CTL_MATCH_PARTID   BIT(16)
#define MSMON_CFG_x_CTL_MATCH_PMG      BIT(17)
#define MSMON_CFG_x_CTL_SCLEN          BIT(19)
#define MSMON_CFG_x_CTL_SUBTYPE        GENMASK(23, 20)
#define MSMON_CFG_x_CTL_OFLOW_FRZ      BIT(24)
#define MSMON_CFG_x_CTL_OFLOW_INTR     BIT(25)
#define MSMON_CFG_x_CTL_OFLOW_STATUS   BIT(26)
#define MSMON_CFG_x_CTL_CAPT_RESET     BIT(27)
#define MSMON_CFG_x_CTL_CAPT_EVNT      GENMASK(30, 28)
#define MSMON_CFG_x_CTL_EN             BIT(31)

#define MSMON_CFG_MBWU_CTL_TYPE_MBWU			0x42
#define MSMON_CFG_MBWU_CTL_TYPE_CSU			0x43

#define MSMON_CFG_MBWU_CTL_SUBTYPE_NONE                 0
#define MSMON_CFG_MBWU_CTL_SUBTYPE_READ                 1
#define MSMON_CFG_MBWU_CTL_SUBTYPE_WRITE                2
#define MSMON_CFG_MBWU_CTL_SUBTYPE_BOTH                 3

#define MSMON_CFG_MBWU_CTL_SUBTYPE_MAX                  3
#define MSMON_CFG_MBWU_CTL_SUBTYPE_MASK                 0x3

/*
 * MSMON_CFG_MBWU_FLT - Memory system performance monitor configure memory
 *                     bandwidth usage monitor filter register
 */
#define MSMON_CFG_MBWU_FLT_PARTID               GENMASK(15, 0)
#define MSMON_CFG_MBWU_FLT_PMG                  GENMASK(23, 16)

/*
 * MSMON_CSU - Memory system performance monitor cache storage usage monitor
 *            register
 * MSMON_CSU_CAPTURE -  Memory system performance monitor cache storage usage
 *                     capture register
 * MSMON_MBWU  - Memory system performance monitor memory bandwidth usage
 *               monitor register
 * MSMON_MBWU_CAPTURE - Memory system performance monitor memory bandwidth usage
 *                     capture register
 */
#define MSMON___VALUE          GENMASK(30, 0)
#define MSMON___NRDY           BIT(31)
#define MSMON_MBWU_L_VALUE     GENMASK(62, 0)
/*
 * MSMON_CAPT_EVNT - Memory system performance monitoring capture event
 *                  generation register
 */
#define MSMON_CAPT_EVNT_NOW    BIT(0)

#endif /* MPAM_INTERNAL_H */
