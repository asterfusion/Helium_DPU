/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>

#include <rte_errno.h>
#include <rte_spinlock.h>

#include "rte_power.h"
#include "power_acpi_cpufreq.h"
#include "power_cppc_cpufreq.h"
#include "power_common.h"
#include "power_kvm_vm.h"
#include "power_pstate_cpufreq.h"
#include "power_amd_pstate_cpufreq.h"

enum power_management_env global_default_env = PM_ENV_NOT_SET;

static rte_spinlock_t global_env_cfg_lock = RTE_SPINLOCK_INITIALIZER;

/* function pointers */
rte_power_freqs_t rte_power_freqs  = NULL;
rte_power_get_freq_t rte_power_get_freq = NULL;
rte_power_set_freq_t rte_power_set_freq = NULL;
rte_power_freq_change_t rte_power_freq_up = NULL;
rte_power_freq_change_t rte_power_freq_down = NULL;
rte_power_freq_change_t rte_power_freq_max = NULL;
rte_power_freq_change_t rte_power_freq_min = NULL;
rte_power_freq_change_t rte_power_turbo_status;
rte_power_freq_change_t rte_power_freq_enable_turbo;
rte_power_freq_change_t rte_power_freq_disable_turbo;
rte_power_get_capabilities_t rte_power_get_capabilities;

static void
reset_power_function_ptrs(void)
{
	rte_power_freqs  = NULL;
	rte_power_get_freq = NULL;
	rte_power_set_freq = NULL;
	rte_power_freq_up = NULL;
	rte_power_freq_down = NULL;
	rte_power_freq_max = NULL;
	rte_power_freq_min = NULL;
	rte_power_turbo_status = NULL;
	rte_power_freq_enable_turbo = NULL;
	rte_power_freq_disable_turbo = NULL;
	rte_power_get_capabilities = NULL;
}

int
rte_power_check_env_supported(enum power_management_env env)
{
	switch (env) {
	case PM_ENV_ACPI_CPUFREQ:
		return power_acpi_cpufreq_check_supported();
	case PM_ENV_PSTATE_CPUFREQ:
		return power_pstate_cpufreq_check_supported();
	case PM_ENV_KVM_VM:
		return power_kvm_vm_check_supported();
	case PM_ENV_CPPC_CPUFREQ:
		return power_cppc_cpufreq_check_supported();
	case PM_ENV_AMD_PSTATE_CPUFREQ:
		return power_amd_pstate_cpufreq_check_supported();
	default:
		rte_errno = EINVAL;
		return -1;
	}
}

int
rte_power_set_env(enum power_management_env env)
{
	rte_spinlock_lock(&global_env_cfg_lock);

	if (global_default_env != PM_ENV_NOT_SET) {
		POWER_LOG(ERR, "Power Management Environment already set.");
		rte_spinlock_unlock(&global_env_cfg_lock);
		return -1;
	}

	int ret = 0;

	if (env == PM_ENV_ACPI_CPUFREQ) {
		rte_power_freqs = power_acpi_cpufreq_freqs;
		rte_power_get_freq = power_acpi_cpufreq_get_freq;
		rte_power_set_freq = power_acpi_cpufreq_set_freq;
		rte_power_freq_up = power_acpi_cpufreq_freq_up;
		rte_power_freq_down = power_acpi_cpufreq_freq_down;
		rte_power_freq_min = power_acpi_cpufreq_freq_min;
		rte_power_freq_max = power_acpi_cpufreq_freq_max;
		rte_power_turbo_status = power_acpi_turbo_status;
		rte_power_freq_enable_turbo = power_acpi_enable_turbo;
		rte_power_freq_disable_turbo = power_acpi_disable_turbo;
		rte_power_get_capabilities = power_acpi_get_capabilities;
	} else if (env == PM_ENV_KVM_VM) {
		rte_power_freqs = power_kvm_vm_freqs;
		rte_power_get_freq = power_kvm_vm_get_freq;
		rte_power_set_freq = power_kvm_vm_set_freq;
		rte_power_freq_up = power_kvm_vm_freq_up;
		rte_power_freq_down = power_kvm_vm_freq_down;
		rte_power_freq_min = power_kvm_vm_freq_min;
		rte_power_freq_max = power_kvm_vm_freq_max;
		rte_power_turbo_status = power_kvm_vm_turbo_status;
		rte_power_freq_enable_turbo = power_kvm_vm_enable_turbo;
		rte_power_freq_disable_turbo = power_kvm_vm_disable_turbo;
		rte_power_get_capabilities = power_kvm_vm_get_capabilities;
	} else if (env == PM_ENV_PSTATE_CPUFREQ) {
		rte_power_freqs = power_pstate_cpufreq_freqs;
		rte_power_get_freq = power_pstate_cpufreq_get_freq;
		rte_power_set_freq = power_pstate_cpufreq_set_freq;
		rte_power_freq_up = power_pstate_cpufreq_freq_up;
		rte_power_freq_down = power_pstate_cpufreq_freq_down;
		rte_power_freq_min = power_pstate_cpufreq_freq_min;
		rte_power_freq_max = power_pstate_cpufreq_freq_max;
		rte_power_turbo_status = power_pstate_turbo_status;
		rte_power_freq_enable_turbo = power_pstate_enable_turbo;
		rte_power_freq_disable_turbo = power_pstate_disable_turbo;
		rte_power_get_capabilities = power_pstate_get_capabilities;

	} else if (env == PM_ENV_CPPC_CPUFREQ) {
		rte_power_freqs = power_cppc_cpufreq_freqs;
		rte_power_get_freq = power_cppc_cpufreq_get_freq;
		rte_power_set_freq = power_cppc_cpufreq_set_freq;
		rte_power_freq_up = power_cppc_cpufreq_freq_up;
		rte_power_freq_down = power_cppc_cpufreq_freq_down;
		rte_power_freq_min = power_cppc_cpufreq_freq_min;
		rte_power_freq_max = power_cppc_cpufreq_freq_max;
		rte_power_turbo_status = power_cppc_turbo_status;
		rte_power_freq_enable_turbo = power_cppc_enable_turbo;
		rte_power_freq_disable_turbo = power_cppc_disable_turbo;
		rte_power_get_capabilities = power_cppc_get_capabilities;
	} else if (env == PM_ENV_AMD_PSTATE_CPUFREQ) {
		rte_power_freqs = power_amd_pstate_cpufreq_freqs;
		rte_power_get_freq = power_amd_pstate_cpufreq_get_freq;
		rte_power_set_freq = power_amd_pstate_cpufreq_set_freq;
		rte_power_freq_up = power_amd_pstate_cpufreq_freq_up;
		rte_power_freq_down = power_amd_pstate_cpufreq_freq_down;
		rte_power_freq_min = power_amd_pstate_cpufreq_freq_min;
		rte_power_freq_max = power_amd_pstate_cpufreq_freq_max;
		rte_power_turbo_status = power_amd_pstate_turbo_status;
		rte_power_freq_enable_turbo = power_amd_pstate_enable_turbo;
		rte_power_freq_disable_turbo = power_amd_pstate_disable_turbo;
		rte_power_get_capabilities = power_amd_pstate_get_capabilities;
	} else {
		POWER_LOG(ERR, "Invalid Power Management Environment(%d) set",
				env);
		ret = -1;
	}

	if (ret == 0)
		global_default_env = env;
	else {
		global_default_env = PM_ENV_NOT_SET;
		reset_power_function_ptrs();
	}

	rte_spinlock_unlock(&global_env_cfg_lock);
	return ret;
}

void
rte_power_unset_env(void)
{
	rte_spinlock_lock(&global_env_cfg_lock);
	global_default_env = PM_ENV_NOT_SET;
	reset_power_function_ptrs();
	rte_spinlock_unlock(&global_env_cfg_lock);
}

enum power_management_env
rte_power_get_env(void) {
	return global_default_env;
}

int
rte_power_init(unsigned int lcore_id)
{
	int ret = -1;

	switch (global_default_env) {
	case PM_ENV_ACPI_CPUFREQ:
		return power_acpi_cpufreq_init(lcore_id);
	case PM_ENV_KVM_VM:
		return power_kvm_vm_init(lcore_id);
	case PM_ENV_PSTATE_CPUFREQ:
		return power_pstate_cpufreq_init(lcore_id);
	case PM_ENV_CPPC_CPUFREQ:
		return power_cppc_cpufreq_init(lcore_id);
	case PM_ENV_AMD_PSTATE_CPUFREQ:
		return power_amd_pstate_cpufreq_init(lcore_id);
	default:
		POWER_LOG(INFO, "Env isn't set yet!");
	}

	/* Auto detect Environment */
	POWER_LOG(INFO, "Attempting to initialise ACPI cpufreq power management...");
	ret = power_acpi_cpufreq_init(lcore_id);
	if (ret == 0) {
		rte_power_set_env(PM_ENV_ACPI_CPUFREQ);
		goto out;
	}

	POWER_LOG(INFO, "Attempting to initialise PSTAT power management...");
	ret = power_pstate_cpufreq_init(lcore_id);
	if (ret == 0) {
		rte_power_set_env(PM_ENV_PSTATE_CPUFREQ);
		goto out;
	}

	POWER_LOG(INFO, "Attempting to initialise AMD PSTATE power management...");
	ret = power_amd_pstate_cpufreq_init(lcore_id);
	if (ret == 0) {
		rte_power_set_env(PM_ENV_AMD_PSTATE_CPUFREQ);
		goto out;
	}

	POWER_LOG(INFO, "Attempting to initialise CPPC power management...");
	ret = power_cppc_cpufreq_init(lcore_id);
	if (ret == 0) {
		rte_power_set_env(PM_ENV_CPPC_CPUFREQ);
		goto out;
	}

	POWER_LOG(INFO, "Attempting to initialise VM power management...");
	ret = power_kvm_vm_init(lcore_id);
	if (ret == 0) {
		rte_power_set_env(PM_ENV_KVM_VM);
		goto out;
	}
	POWER_LOG(ERR, "Unable to set Power Management Environment for lcore "
			"%u", lcore_id);
out:
	return ret;
}

int
rte_power_exit(unsigned int lcore_id)
{
	switch (global_default_env) {
	case PM_ENV_ACPI_CPUFREQ:
		return power_acpi_cpufreq_exit(lcore_id);
	case PM_ENV_KVM_VM:
		return power_kvm_vm_exit(lcore_id);
	case PM_ENV_PSTATE_CPUFREQ:
		return power_pstate_cpufreq_exit(lcore_id);
	case PM_ENV_CPPC_CPUFREQ:
		return power_cppc_cpufreq_exit(lcore_id);
	case PM_ENV_AMD_PSTATE_CPUFREQ:
		return power_amd_pstate_cpufreq_exit(lcore_id);
	default:
		POWER_LOG(ERR, "Environment has not been set, unable to exit gracefully");

	}
	return -1;

}
