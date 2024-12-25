/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_RESCTRL_H
#define _ASM_X86_RESCTRL_H

#ifdef CONFIG_X86_CPU_RESCTRL

#include <linux/bug.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/resctrl_types.h>

#define IA32_PQR_ASSOC	0x0c8f

void resctrl_arch_reset_resources(void);

/**
 * struct resctrl_pqr_state - State cache for the PQR MSR
 * @cur_rmid:		The cached Resource Monitoring ID
 * @cur_closid:	The cached Class Of Service ID
 * @default_rmid:	The user assigned Resource Monitoring ID
 * @default_closid:	The user assigned cached Class Of Service ID
 *
 * The upper 32 bits of IA32_PQR_ASSOC contain closid and the
 * lower 10 bits rmid. The update to IA32_PQR_ASSOC always
 * contains both parts, so we need to cache them. This also
 * stores the user configured per cpu CLOSID and RMID.
 *
 * The cache also helps to avoid pointless updates if the value does
 * not change.
 */
struct resctrl_pqr_state {
	u32			cur_rmid;
	u32			cur_closid;
	u32			default_rmid;
	u32			default_closid;
};

DECLARE_PER_CPU(struct resctrl_pqr_state, pqr_state);

extern bool rdt_alloc_capable;
extern bool rdt_mon_capable;
extern unsigned int rdt_mon_features;

DECLARE_STATIC_KEY_FALSE(rdt_enable_key);
DECLARE_STATIC_KEY_FALSE(rdt_alloc_enable_key);
DECLARE_STATIC_KEY_FALSE(rdt_mon_enable_key);

/*
 * __resctrl_sched_in() - Writes the task's CLOSid/RMID to IA32_PQR_MSR
 *
 * Following considerations are made so that this has minimal impact
 * on scheduler hot path:
 * - This will stay as no-op unless we are running on an Intel SKU
 *   which supports resource control or monitoring and we enable by
 *   mounting the resctrl file system.
 * - Caches the per cpu CLOSid/RMID values and does the MSR write only
 *   when a task with a different CLOSid/RMID is scheduled in.
 * - We allocate RMIDs/CLOSids globally in order to keep this as
 *   simple as possible.
 * Must be called with preemption disabled.
 */
static void __resctrl_sched_in(void)
{
	struct resctrl_pqr_state *state = this_cpu_ptr(&pqr_state);
	u32 closid = READ_ONCE(state->default_closid);
	u32 rmid = READ_ONCE(state->default_rmid);
	u32 tmp;

	/*
	 * If this task has a closid/rmid assigned, use it.
	 * Else use the closid/rmid assigned to this cpu.
	 */
	if (static_branch_likely(&rdt_alloc_enable_key)) {
		tmp = READ_ONCE(current->closid);
		if (tmp)
			closid = tmp;
	}

	if (static_branch_likely(&rdt_mon_enable_key)) {
		tmp = READ_ONCE(current->rmid);
		if (tmp)
			rmid = tmp;
	}

	if (closid != state->cur_closid || rmid != state->cur_rmid) {
		state->cur_closid = closid;
		state->cur_rmid = rmid;
		wrmsr(IA32_PQR_ASSOC, rmid, closid);
	}
}

static inline unsigned int resctrl_arch_round_mon_val(unsigned int val)
{
	unsigned int scale = boot_cpu_data.x86_cache_occ_scale;

	/* h/w works in units of "boot_cpu_data.x86_cache_occ_scale" */
	val /= scale;
	return val * scale;
}

static inline void resctrl_arch_set_cpu_default_closid_rmid(int cpu, u32 closid,
							    u32 rmid)
{
	WRITE_ONCE(per_cpu(pqr_state.default_closid, cpu), closid);
	WRITE_ONCE(per_cpu(pqr_state.default_rmid, cpu), rmid);
}

static inline void resctrl_arch_set_closid_rmid(struct task_struct *tsk,
						u32 closid, u32 rmid)
{
	WRITE_ONCE(tsk->closid, closid);
	WRITE_ONCE(tsk->rmid, rmid);
}

static inline bool resctrl_arch_match_closid(struct task_struct *tsk, u32 closid)
{
	return READ_ONCE(tsk->closid) == closid;
}

static inline bool resctrl_arch_match_rmid(struct task_struct *tsk, u32 ignored,
					   u32 rmid)
{
	return READ_ONCE(tsk->rmid) == rmid;
}

static inline void resctrl_sched_in(void)
{
	if (static_branch_likely(&rdt_enable_key))
		__resctrl_sched_in();
}

static inline u32 resctrl_arch_system_num_rmid_idx(void)
{
	/* RMID are independent numbers for x86. num_rmid_idx==num_rmid */
	return boot_cpu_data.x86_cache_max_rmid + 1;
}

static inline void resctrl_arch_rmid_idx_decode(u32 idx, u32 *closid, u32 *rmid)
{
	*rmid = idx;
	*closid = ~0;
}

static inline u32 resctrl_arch_rmid_idx_encode(u32 closid, u32 rmid)
{
	return rmid;
}

/* x86 can always read an rmid, nothing needs allocating */
struct rdt_resource;
static inline int resctrl_arch_mon_ctx_alloc_no_wait(struct rdt_resource *r,
						     int evtid)
{
	return 0;
};
static inline void resctrl_arch_mon_ctx_free(struct rdt_resource *r, int evtid,
					     int ctx) { };

/* Does the event count even when no context is allocated? */
static inline bool resctrl_arch_event_is_free_running(enum resctrl_event_id evt)
{
	return true;
}

static inline bool resctrl_arch_alloc_capable(void)
{
	return rdt_alloc_capable;
}

static inline void resctrl_arch_enable_alloc(void)
{
	static_branch_enable_cpuslocked(&rdt_alloc_enable_key);
	static_branch_inc_cpuslocked(&rdt_enable_key);
}

static inline void resctrl_arch_disable_alloc(void)
{
	static_branch_disable_cpuslocked(&rdt_alloc_enable_key);
	static_branch_dec_cpuslocked(&rdt_enable_key);
}

static inline bool resctrl_arch_mon_capable(void)
{
	return rdt_mon_capable;
}

static inline void resctrl_arch_enable_mon(void)
{
	static_branch_enable_cpuslocked(&rdt_mon_enable_key);
	static_branch_inc_cpuslocked(&rdt_enable_key);
}

static inline void resctrl_arch_disable_mon(void)
{
	static_branch_disable_cpuslocked(&rdt_mon_enable_key);
	static_branch_dec_cpuslocked(&rdt_enable_key);
}

static inline bool resctrl_arch_is_llc_occupancy_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_OCCUP_EVENT_ID));
}

static inline bool resctrl_arch_is_mbm_total_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_MBM_TOTAL_EVENT_ID));
}

static inline bool resctrl_arch_is_mbm_local_enabled(void)
{
	return (rdt_mon_features & (1 << QOS_L3_MBM_LOCAL_EVENT_ID));
}

u64 resctrl_arch_get_prefetch_disable_bits(void);
int resctrl_arch_pseudo_lock_fn(void *_plr);
int resctrl_arch_measure_cycles_lat_fn(void *_plr);
int resctrl_arch_measure_l2_residency(void *_plr);
int resctrl_arch_measure_l3_residency(void *_plr);
void resctrl_cpu_detect(struct cpuinfo_x86 *c);

bool resctrl_arch_get_cdp_enabled(enum resctrl_res_level l);
int resctrl_arch_set_cdp_enabled(enum resctrl_res_level l, bool enable);

/* Not supported: */
static inline int resctrl_arch_set_iommu_closid_rmid(struct iommu_group *group,
						     u32 closid, u32 rmid)
{
	return -EOPNOTSUPP;
}
static inline bool resctrl_arch_match_iommu_closid(struct iommu_group *group,
						   u32 closid)
{
	return false;
}
static inline bool resctrl_arch_match_iommu_closid_rmid(struct iommu_group *group,
							u32 closid, u32 rmid)
{
	return false;
}
#else

static inline void resctrl_sched_in(void) {}
static inline void resctrl_cpu_detect(struct cpuinfo_x86 *c) {}

#endif /* CONFIG_X86_CPU_RESCTRL */

#endif /* _ASM_X86_RESCTRL_H */
