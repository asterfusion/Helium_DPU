// SPDX-License-Identifier: GPL-2.0-only
/*
 * Resource Director Technology(RDT)
 * - Monitoring code
 *
 * Copyright (C) 2017 Intel Corporation
 *
 * Author:
 *    Vikas Shivappa <vikas.shivappa@intel.com>
 *
 * This replaces the cqm.c based on perf but we reuse a lot of
 * code and datastructures originally from Peter Zijlstra and Matt Fleming.
 *
 * More information about RDT be found in the Intel (R) x86 Architecture
 * Software Developer Manual June 2016, volume 3, section 17.17.
 */

#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/sizes.h>
#include <linux/slab.h>

#include <asm/cpu_device_id.h>
#include <asm/resctrl.h>

#include "internal.h"

/*
 * Global boolean for rdt_monitor which is true if any
 * resource monitoring is enabled.
 */
bool rdt_mon_capable;

/*
 * Global to indicate which monitoring events are enabled.
 */
unsigned int rdt_mon_features;

#define CF(cf)	((unsigned long)(1048576 * (cf) + 0.5))

/*
 * The correction factor table is documented in Documentation/x86/resctrl.rst.
 * If rmid > rmid threshold, MBM total and local values should be multiplied
 * by the correction factor.
 *
 * The original table is modified for better code:
 *
 * 1. The threshold 0 is changed to rmid count - 1 so don't do correction
 *    for the case.
 * 2. MBM total and local correction table indexed by core counter which is
 *    equal to (x86_cache_max_rmid + 1) / 8 - 1 and is from 0 up to 27.
 * 3. The correction factor is normalized to 2^20 (1048576) so it's faster
 *    to calculate corrected value by shifting:
 *    corrected_value = (original_value * correction_factor) >> 20
 */
static const struct mbm_correction_factor_table {
	u32 rmidthreshold;
	u64 cf;
} mbm_cf_table[] __initconst = {
	{7,	CF(1.000000)},
	{15,	CF(1.000000)},
	{15,	CF(0.969650)},
	{31,	CF(1.000000)},
	{31,	CF(1.066667)},
	{31,	CF(0.969650)},
	{47,	CF(1.142857)},
	{63,	CF(1.000000)},
	{63,	CF(1.185115)},
	{63,	CF(1.066553)},
	{79,	CF(1.454545)},
	{95,	CF(1.000000)},
	{95,	CF(1.230769)},
	{95,	CF(1.142857)},
	{95,	CF(1.066667)},
	{127,	CF(1.000000)},
	{127,	CF(1.254863)},
	{127,	CF(1.185255)},
	{151,	CF(1.000000)},
	{127,	CF(1.066667)},
	{167,	CF(1.000000)},
	{159,	CF(1.454334)},
	{183,	CF(1.000000)},
	{127,	CF(0.969744)},
	{191,	CF(1.280246)},
	{191,	CF(1.230921)},
	{215,	CF(1.000000)},
	{191,	CF(1.143118)},
};

static u32 mbm_cf_rmidthreshold __read_mostly = UINT_MAX;
static u64 mbm_cf __read_mostly;

static inline u64 get_corrected_mbm_count(u32 rmid, unsigned long val)
{
	/* Correct MBM value. */
	if (rmid > mbm_cf_rmidthreshold)
		val = (val * mbm_cf) >> 20;

	return val;
}

static struct arch_mbm_state *get_arch_mbm_state(struct rdt_hw_domain *hw_dom,
						 u32 rmid,
						 enum resctrl_event_id eventid)
{
	switch (eventid) {
	case QOS_L3_OCCUP_EVENT_ID:
		return NULL;
	case QOS_L3_MBM_TOTAL_EVENT_ID:
		return &hw_dom->arch_mbm_total[rmid];
	case QOS_L3_MBM_LOCAL_EVENT_ID:
		return &hw_dom->arch_mbm_local[rmid];
	}

	/* Never expect to get here */
	WARN_ON_ONCE(1);

	return NULL;
}

void resctrl_arch_reset_rmid(struct rdt_resource *r, struct rdt_domain *d,
			     u32 closid, u32 rmid,
			     enum resctrl_event_id eventid)
{
	struct rdt_hw_domain *hw_dom = resctrl_to_arch_dom(d);
	struct arch_mbm_state *am;

	am = get_arch_mbm_state(hw_dom, rmid, eventid);
	if (am)
		memset(am, 0, sizeof(*am));
}

static u64 mbm_overflow_count(u64 prev_msr, u64 cur_msr, unsigned int width)
{
	u64 shift = 64 - width, chunks;

	chunks = (cur_msr << shift) - (prev_msr << shift);
	return chunks >> shift;
}

struct __rmid_read_arg
{
	u32 rmid;
	enum resctrl_event_id eventid;
	struct rdt_hw_resource *hw_res;
	struct rdt_hw_domain *hw_dom;

	int err;
	u64 val;
};

static int ___rmid_read(struct __rmid_read_arg *arg)
{
	enum resctrl_event_id eventid = arg->eventid;
	u64 prev_msr, msr_val, chunks;
	struct arch_mbm_state *am;
	u32 rmid = arg->rmid;

	am = get_arch_mbm_state(arg->hw_dom, rmid, eventid);
	if (am)
		prev_msr = atomic64_read(&am->prev_msr);

	/*
	 * As per the SDM, when IA32_QM_EVTSEL.EvtID (bits 7:0) is configured
	 * with a valid event code for supported resource type and the bits
	 * IA32_QM_EVTSEL.RMID (bits 41:32) are configured with valid RMID,
	 * IA32_QM_CTR.data (bits 61:0) reports the monitored data.
	 * IA32_QM_CTR.Error (bit 63) and IA32_QM_CTR.Unavailable (bit 62)
	 * are error bits.
	 */
	wrmsr(MSR_IA32_QM_EVTSEL, eventid, rmid);
	rdmsrl(MSR_IA32_QM_CTR, msr_val);

	if (msr_val & RMID_VAL_ERROR)
		return -EIO;
	if (msr_val & RMID_VAL_UNAVAIL)
		return -EINVAL;

	if (am) {
		chunks = mbm_overflow_count(prev_msr, msr_val,
					    arg->hw_res->mbm_width);

		if (atomic64_cmpxchg(&am->prev_msr, prev_msr, msr_val) != prev_msr)
			return -EINTR;

		chunks = atomic64_add_return(chunks, &am->chunks);
		chunks = get_corrected_mbm_count(rmid, chunks);
	} else {
		chunks = msr_val;
	}

	arg->val = chunks * arg->hw_res->mon_scale;

	return 0;
}

static void __rmid_read(void *_arg)
{
	struct __rmid_read_arg *arg = _arg;

	do {
		arg->err = ___rmid_read(arg);
	} while (arg->err && arg->err != -EINTR);
}

int resctrl_arch_rmid_read(struct rdt_resource *r, struct rdt_domain *d,
			   u32 closid, u32 rmid, enum resctrl_event_id eventid,
			   u64 *val, int ignored)
{
	struct __rmid_read_arg arg;
	int err = -EIO;

	arg.rmid = rmid;
	arg.eventid = eventid;
	arg.hw_res = resctrl_to_arch_res(r);
	arg.hw_dom = resctrl_to_arch_dom(d);

	preempt_disable();
	if (cpumask_test_cpu(smp_processor_id(), &d->cpu_mask)) {
		__rmid_read(&arg);
		preempt_enable();
		err = 0;
	} else if (!irqs_disabled()) {
		preempt_enable();
		err = smp_call_function_any(&d->cpu_mask, __rmid_read, &arg,
					    true);
	} else {
		preempt_enable();
	}
	if (err)
		return err;
	if (arg.err)
		return arg.err;

	*val = arg.val;

	return 0;
}

int __init rdt_get_mon_l3_config(struct rdt_resource *r)
{
	unsigned int mbm_offset = boot_cpu_data.x86_cache_mbm_width_offset;
	struct rdt_hw_resource *hw_res = resctrl_to_arch_res(r);
	unsigned int threshold;

	resctrl_rmid_realloc_limit = boot_cpu_data.x86_cache_size * 1024;
	hw_res->mon_scale = boot_cpu_data.x86_cache_occ_scale;
	r->num_rmid = boot_cpu_data.x86_cache_max_rmid + 1;
	hw_res->mbm_width = MBM_CNTR_WIDTH_BASE;

	if (mbm_offset > 0 && mbm_offset <= MBM_CNTR_WIDTH_OFFSET_MAX)
		hw_res->mbm_width += mbm_offset;
	else if (mbm_offset > MBM_CNTR_WIDTH_OFFSET_MAX)
		pr_warn("Ignoring impossible MBM counter offset\n");

	/*
	 * A reasonable upper limit on the max threshold is the number
	 * of lines tagged per RMID if all RMIDs have the same number of
	 * lines tagged in the LLC.
	 *
	 * For a 35MB LLC and 56 RMIDs, this is ~1.8% of the LLC.
	 */
	threshold = resctrl_rmid_realloc_limit / r->num_rmid;

	/*
	 * Because num_rmid may not be a power of two, round the value
	 * to the nearest multiple of hw_res->mon_scale so it matches a
	 * value the hardware will measure. mon_scale may not be a power of 2.
	 */
	resctrl_rmid_realloc_threshold = resctrl_arch_round_mon_val(threshold);

	r->mon_capable = true;

	return 0;
}

void __init intel_rdt_mbm_apply_quirk(void)
{
	int cf_index;

	cf_index = (boot_cpu_data.x86_cache_max_rmid + 1) / 8 - 1;
	if (cf_index >= ARRAY_SIZE(mbm_cf_table)) {
		pr_info("No MBM correction factor available\n");
		return;
	}

	mbm_cf_rmidthreshold = mbm_cf_table[cf_index].rmidthreshold;
	mbm_cf = mbm_cf_table[cf_index].cf;
}
