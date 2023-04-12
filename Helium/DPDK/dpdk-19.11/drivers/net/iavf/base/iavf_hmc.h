/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2013 - 2015 Intel Corporation
 */

#ifndef _IAVF_HMC_H_
#define _IAVF_HMC_H_

#define IAVF_HMC_MAX_BP_COUNT 512

/* forward-declare the HW struct for the compiler */
struct iavf_hw;

#define IAVF_HMC_INFO_SIGNATURE		0x484D5347 /* HMSG */
#define IAVF_HMC_PD_CNT_IN_SD		512
#define IAVF_HMC_DIRECT_BP_SIZE		0x200000 /* 2M */
#define IAVF_HMC_PAGED_BP_SIZE		4096
#define IAVF_HMC_PD_BP_BUF_ALIGNMENT	4096
#define IAVF_FIRST_VF_FPM_ID		16

struct iavf_hmc_obj_info {
	u64 base;	/* base addr in FPM */
	u32 max_cnt;	/* max count available for this hmc func */
	u32 cnt;	/* count of objects driver actually wants to create */
	u64 size;	/* size in bytes of one object */
};

enum iavf_sd_entry_type {
	IAVF_SD_TYPE_INVALID = 0,
	IAVF_SD_TYPE_PAGED   = 1,
	IAVF_SD_TYPE_DIRECT  = 2
};

struct iavf_hmc_bp {
	enum iavf_sd_entry_type entry_type;
	struct iavf_dma_mem addr; /* populate to be used by hw */
	u32 sd_pd_index;
	u32 ref_cnt;
};

struct iavf_hmc_pd_entry {
	struct iavf_hmc_bp bp;
	u32 sd_index;
	bool rsrc_pg;
	bool valid;
};

struct iavf_hmc_pd_table {
	struct iavf_dma_mem pd_page_addr; /* populate to be used by hw */
	struct iavf_hmc_pd_entry  *pd_entry; /* [512] for sw book keeping */
	struct iavf_virt_mem pd_entry_virt_mem; /* virt mem for pd_entry */

	u32 ref_cnt;
	u32 sd_index;
};

struct iavf_hmc_sd_entry {
	enum iavf_sd_entry_type entry_type;
	bool valid;

	union {
		struct iavf_hmc_pd_table pd_table;
		struct iavf_hmc_bp bp;
	} u;
};

struct iavf_hmc_sd_table {
	struct iavf_virt_mem addr; /* used to track sd_entry allocations */
	u32 sd_cnt;
	u32 ref_cnt;
	struct iavf_hmc_sd_entry *sd_entry; /* (sd_cnt*512) entries max */
};

struct iavf_hmc_info {
	u32 signature;
	/* equals to pci func num for PF and dynamically allocated for VFs */
	u8 hmc_fn_id;
	u16 first_sd_index; /* index of the first available SD */

	/* hmc objects */
	struct iavf_hmc_obj_info *hmc_obj;
	struct iavf_virt_mem hmc_obj_virt_mem;
	struct iavf_hmc_sd_table sd_table;
};

#define IAVF_INC_SD_REFCNT(sd_table)	((sd_table)->ref_cnt++)
#define IAVF_INC_PD_REFCNT(pd_table)	((pd_table)->ref_cnt++)
#define IAVF_INC_BP_REFCNT(bp)		((bp)->ref_cnt++)

#define IAVF_DEC_SD_REFCNT(sd_table)	((sd_table)->ref_cnt--)
#define IAVF_DEC_PD_REFCNT(pd_table)	((pd_table)->ref_cnt--)
#define IAVF_DEC_BP_REFCNT(bp)		((bp)->ref_cnt--)

/**
 * IAVF_SET_PF_SD_ENTRY - marks the sd entry as valid in the hardware
 * @hw: pointer to our hw struct
 * @pa: pointer to physical address
 * @sd_index: segment descriptor index
 * @type: if sd entry is direct or paged
 **/
#define IAVF_SET_PF_SD_ENTRY(hw, pa, sd_index, type)			\
{									\
	u32 val1, val2, val3;						\
	val1 = (u32)(IAVF_HI_DWORD(pa));				\
	val2 = (u32)(pa) | (IAVF_HMC_MAX_BP_COUNT <<			\
		 IAVF_PFHMC_SDDATALOW_PMSDBPCOUNT_SHIFT) |		\
		((((type) == IAVF_SD_TYPE_PAGED) ? 0 : 1) <<		\
		IAVF_PFHMC_SDDATALOW_PMSDTYPE_SHIFT) |			\
		BIT(IAVF_PFHMC_SDDATALOW_PMSDVALID_SHIFT);		\
	val3 = (sd_index) | BIT_ULL(IAVF_PFHMC_SDCMD_PMSDWR_SHIFT);	\
	wr32((hw), IAVF_PFHMC_SDDATAHIGH, val1);			\
	wr32((hw), IAVF_PFHMC_SDDATALOW, val2);				\
	wr32((hw), IAVF_PFHMC_SDCMD, val3);				\
}

/**
 * IAVF_CLEAR_PF_SD_ENTRY - marks the sd entry as invalid in the hardware
 * @hw: pointer to our hw struct
 * @sd_index: segment descriptor index
 * @type: if sd entry is direct or paged
 **/
#define IAVF_CLEAR_PF_SD_ENTRY(hw, sd_index, type)			\
{									\
	u32 val2, val3;							\
	val2 = (IAVF_HMC_MAX_BP_COUNT <<				\
		IAVF_PFHMC_SDDATALOW_PMSDBPCOUNT_SHIFT) |		\
		((((type) == IAVF_SD_TYPE_PAGED) ? 0 : 1) <<		\
		IAVF_PFHMC_SDDATALOW_PMSDTYPE_SHIFT);			\
	val3 = (sd_index) | BIT_ULL(IAVF_PFHMC_SDCMD_PMSDWR_SHIFT);	\
	wr32((hw), IAVF_PFHMC_SDDATAHIGH, 0);				\
	wr32((hw), IAVF_PFHMC_SDDATALOW, val2);				\
	wr32((hw), IAVF_PFHMC_SDCMD, val3);				\
}

/**
 * IAVF_INVALIDATE_PF_HMC_PD - Invalidates the pd cache in the hardware
 * @hw: pointer to our hw struct
 * @sd_idx: segment descriptor index
 * @pd_idx: page descriptor index
 **/
#define IAVF_INVALIDATE_PF_HMC_PD(hw, sd_idx, pd_idx)			\
	wr32((hw), IAVF_PFHMC_PDINV,					\
	    (((sd_idx) << IAVF_PFHMC_PDINV_PMSDIDX_SHIFT) |		\
	     ((pd_idx) << IAVF_PFHMC_PDINV_PMPDIDX_SHIFT)))

/**
 * IAVF_FIND_SD_INDEX_LIMIT - finds segment descriptor index limit
 * @hmc_info: pointer to the HMC configuration information structure
 * @type: type of HMC resources we're searching
 * @index: starting index for the object
 * @cnt: number of objects we're trying to create
 * @sd_idx: pointer to return index of the segment descriptor in question
 * @sd_limit: pointer to return the maximum number of segment descriptors
 *
 * This function calculates the segment descriptor index and index limit
 * for the resource defined by iavf_hmc_rsrc_type.
 **/
#define IAVF_FIND_SD_INDEX_LIMIT(hmc_info, type, index, cnt, sd_idx, sd_limit)\
{									\
	u64 fpm_addr, fpm_limit;					\
	fpm_addr = (hmc_info)->hmc_obj[(type)].base +			\
		   (hmc_info)->hmc_obj[(type)].size * (index);		\
	fpm_limit = fpm_addr + (hmc_info)->hmc_obj[(type)].size * (cnt);\
	*(sd_idx) = (u32)(fpm_addr / IAVF_HMC_DIRECT_BP_SIZE);		\
	*(sd_limit) = (u32)((fpm_limit - 1) / IAVF_HMC_DIRECT_BP_SIZE);	\
	/* add one more to the limit to correct our range */		\
	*(sd_limit) += 1;						\
}

/**
 * IAVF_FIND_PD_INDEX_LIMIT - finds page descriptor index limit
 * @hmc_info: pointer to the HMC configuration information struct
 * @type: HMC resource type we're examining
 * @idx: starting index for the object
 * @cnt: number of objects we're trying to create
 * @pd_index: pointer to return page descriptor index
 * @pd_limit: pointer to return page descriptor index limit
 *
 * Calculates the page descriptor index and index limit for the resource
 * defined by iavf_hmc_rsrc_type.
 **/
#define IAVF_FIND_PD_INDEX_LIMIT(hmc_info, type, idx, cnt, pd_index, pd_limit)\
{									\
	u64 fpm_adr, fpm_limit;						\
	fpm_adr = (hmc_info)->hmc_obj[(type)].base +			\
		  (hmc_info)->hmc_obj[(type)].size * (idx);		\
	fpm_limit = fpm_adr + (hmc_info)->hmc_obj[(type)].size * (cnt);	\
	*(pd_index) = (u32)(fpm_adr / IAVF_HMC_PAGED_BP_SIZE);		\
	*(pd_limit) = (u32)((fpm_limit - 1) / IAVF_HMC_PAGED_BP_SIZE);	\
	/* add one more to the limit to correct our range */		\
	*(pd_limit) += 1;						\
}
enum iavf_status_code iavf_add_sd_table_entry(struct iavf_hw *hw,
					      struct iavf_hmc_info *hmc_info,
					      u32 sd_index,
					      enum iavf_sd_entry_type type,
					      u64 direct_mode_sz);

enum iavf_status_code iavf_add_pd_table_entry(struct iavf_hw *hw,
					      struct iavf_hmc_info *hmc_info,
					      u32 pd_index,
					      struct iavf_dma_mem *rsrc_pg);
enum iavf_status_code iavf_remove_pd_bp(struct iavf_hw *hw,
					struct iavf_hmc_info *hmc_info,
					u32 idx);
enum iavf_status_code iavf_prep_remove_sd_bp(struct iavf_hmc_info *hmc_info,
					     u32 idx);
enum iavf_status_code iavf_remove_sd_bp_new(struct iavf_hw *hw,
					    struct iavf_hmc_info *hmc_info,
					    u32 idx, bool is_pf);
enum iavf_status_code iavf_prep_remove_pd_page(struct iavf_hmc_info *hmc_info,
					       u32 idx);
enum iavf_status_code iavf_remove_pd_page_new(struct iavf_hw *hw,
					      struct iavf_hmc_info *hmc_info,
					      u32 idx, bool is_pf);

#endif /* _IAVF_HMC_H_ */
