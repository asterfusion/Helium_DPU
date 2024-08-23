#!/bin/bash -x
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2020 Marvell.

# Script syntax:
# cnxk-target-setup.sh
#
# Optional environment variables:
# HP How many hugepages of default size to enable.
# NOHP Flag disallowing hugepages allocation
# DEVS Space separated list of PCI devices to bind to VFIO.
# VFIO_DEVBIND Alternative location of oxk-devbind-basic.sh script.
# TARGET_BOARD Optional SSH URL for the target board to setup. If not given,
#              all commands are run locally. If it is given the script is
#              copied to REMOTE_DIR on the TARGET_BOARD and run from there.
# PERF_STAGE Flag to bind PF devices used in perf stage to vfio.
# TM_SETUP Enable traffic manager specific configurations.
#
# Below options are used only when TARGET_BOARD is set.
#
# TARGET_SSH_CMD ssh cmd used to connect to target. Default is "ssh"
# TARGET_SCP_CMD scp cmd used to connect to target. Default is "scp"
# REMOTE_DIR Directory where build dir is located on the remote target.
#            It is used to find oxk-devbind-basic.sh script.
# SUDO This is used only when the command is to run as sudo on the
#      remote target. Default set to "sudo" i.e. to run as SUDO.
#
# Script will:
# 1. Mount hugetlbfs and enable HP hugepages of default size.
# 2. Bind each PCI device using VFIO_DEVBIND script
# 3. Sets device configuration.

set -euo pipefail
shopt -s extglob

function get_cpu_string() {
	local cpu_impl
	local cpu_str
	local cpu_pn

	cpu_pn=$(grep -m 1 'CPU part' /proc/cpuinfo | awk -F': ' '{print $2}')
	cpu_impl=$(grep -m 1 'CPU implementer' /proc/cpuinfo | awk -F': ' '{print $2}')

	if [[ $cpu_impl == 0x43 ]] && [[ $cpu_pn == 0x0b1 ]]; then
		cpu_str="98xx"
	elif [[ $cpu_impl == 0x43 ]] && [[ $cpu_pn == 0x0b2 ]]; then
		cpu_str="96xx"
	elif [[ $cpu_impl == 0x43 ]] && [[ $cpu_pn == 0x0b4 ]]; then
		cpu_str="95xx"
	elif [[ $cpu_impl == 0x41 ]] && [[ $cpu_pn == 0xd49 ]]; then
		cpu_str="cn10ka"
		compatible=`cat /proc/device-tree/compatible`
		IFS=',' read -ra list <<< "$compatible"
		if [[ "${list[0]}" = "marvell" ]]
		then
			cpu_str=${list[1]}
		fi
	else
		echo "Invalid CPU (Implementer=$cpu_impl Part Number=$cpu_pn"
		exit 1
	fi
	echo $cpu_str
}

function mount_hugetlbfs() {
	# Mount hugetlbfs.
	if ! mount | grep -q hugepages; then
		mount -t hugetlbfs none /dev/hugepages/
	fi
}

function setup_hp() {
	if [[ -n $NO_HP ]]; then
		echo "Skipping huge page setup"
		return
	fi
	# Enable HP hugepages.
	echo $HP > /proc/sys/vm/nr_hugepages
}

function setup_devices() {
	local npa_pf
	local sso_pf
	local dma_pf
	local dma_vf
	local cpt_pf=""
	local cpt_vf=""
	local inl_pf
	local devs
	local nix_lbk_vfs
	local nix_pfs
	local pcid

	nix_lbk_vfs="0002:01:00.1 0002:01:00.2 0002:01:00.3"
	devs=${DEVS:-$nix_lbk_vfs}

	if [[ $CPU == "cn10ka" ]] || [[ $CPU == "cn10kb" ]]; then
		cpt_pf="0002:20:00.0"
		cpt_vf="0002:20:00.1"
	elif [[ $IS_CN9K -eq 1 ]]; then
		cpt_pf="0002:10:00.0"
		cpt_vf="0002:10:00.1"
	fi

	# Set KVF Limits
	if [[ $CPU == "cn10kb" ]]; then
		echo 8 > /sys/bus/pci/devices/$cpt_pf/kvf_limits
	else
		echo 24 > /sys/bus/pci/devices/$cpt_pf/kvf_limits
	fi

	# Disable existing VFs and enable CPT VFs
	if [[ -e /sys/bus/pci/devices/$cpt_pf/sriov_numvfs ]]; then
		echo 0 > /sys/bus/pci/devices/$cpt_pf/sriov_numvfs
		echo 2 > /sys/bus/pci/devices/$cpt_pf/sriov_numvfs
		devlink dev info pci/$cpt_pf
		devs+=" $cpt_vf"
	fi

	# SSO and NPA devices
	sso_pf=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
	npa_pf=${NPA_DEV:-$(lspci -d :a0fb | tail -1 | awk -e '{ print $1 }')}
	devs+=" $sso_pf"
	devs+=" $npa_pf"

	# DMA device
	dma_pf=$(lspci -d :a080 | tail -1 | awk -e '{ print $1 }')
	if [[ -e /sys/bus/pci/devices/$dma_pf/sriov_numvfs ]]; then
		echo 0 > /sys/bus/pci/devices/$dma_pf/sriov_numvfs
		echo 1 > /sys/bus/pci/devices/$dma_pf/sriov_numvfs
		dma_vf=$(lspci -d :a081 | tail -1 | awk -e '{ print $1 }')
		devs+=" $dma_vf"
	fi

	if [[ $CPU == "cn10ka" ]]; then
		inl_pf=${INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
		devs+=" $inl_pf"
	fi

	if [[ $CPU == "cn10kb" ]]; then
		nix_pfs=${ETH_DEV:-$(lspci -d :a063 | tail -1 | awk -e '{ print $1 }')}
		devs+=" $nix_pfs"
		inl_pf=${INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
		devs+=" $inl_pf"
	fi

	# Unbind all SSO devices first
	for d in $(lspci -d :a0f9 | awk -e '{ print $1 }'); do
		$VFIO_DEVBIND -u $d || exit 1
	done

	# Bind devices
	for d in $devs; do
		$VFIO_DEVBIND -b vfio-pci $d || exit 1
	done

	if [[ $IS_CN9K -eq 0 ]]; then
		echo "Skipping limits configuration on 106xx"
		return
	fi

	# Configure limits
	pcid="02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10"
	if [[ $CPU == "98xx" ]]; then
		pcid="$pcid 11 12 13 14 15 16 17 18"
	fi
	set +euo pipefail
	for d in $pcid;  do
		path=/sys/bus/pci/devices/0002\:$d\:00.0/limits/
		if [[ -d $path ]]; then
			echo 0 > ${path}ssow
			echo 0 > ${path}sso
		fi
	done

	path=/sys/bus/pci/devices/$sso_pf/limits/
	if [[ ! -d $path ]]; then
		set -euo pipefail
		return
	fi
	echo 256 > ${path}sso
	# Max number of available work slots are (2 x num_core) + 4.
	# Max limit needs to be set for tests to run in dual workslot mode.
	if [[ $CPU == "96xx" ]] || [[ $CPU == "95xx" ]]; then
		echo 46 > ${path}ssow
	elif [[ $CPU == "98xx" ]]; then
		echo 76 > ${path}ssow
	fi
	echo 8 > ${path}tim
	set -euo pipefail
}

function setup_tm() {
	local pktio_pf_list
	local count
	local per_pf

	if [[ -z $TM_SETUP ]] || [[ $IS_CN9K -eq 0 ]]; then
		echo "Skipping TM setup"
		return
	fi

	# test/validation/api/traffic_mngr_main needs more resources.
	# Set 256 SMQ and TL4 for AFVF's and give remaining 256 to PF's
	pktio_pf_list=$(lspci -d :a063 | cut -f 1 -d ' ')
	count=$(echo $pktio_pf_list | wc -w)
	per_pf=$((256 / count))

	for d in $pktio_pf_list; do
		# Unbind before changing limits
		$VFIO_DEVBIND -u $d || exit 1
		path=/sys/bus/pci/devices/$d/limits/
		if [[ -d $path ]]; then
			echo 0 > ${path}smq
			echo 0 > ${path}tl4
		fi
	done

	for d in $pktio_pf_list; do
		path=/sys/bus/pci/devices/$d/limits/
		if [[ -d $path ]]; then
			echo $per_pf > ${path}smq
			echo $per_pf > ${path}tl4
		fi
	done
	path=/sys/bus/pci/devices/0002:01:00.0/limits/
	if [[ -d $path ]]; then
		echo 256 > ${path}smq
		echo 256 > ${path}tl4
	fi
}

function setup_perf() {
	local perf_pf_list

	if [[ -z $PERF_STAGE ]]; then
		echo "Skipping Perf Setup"
		return
	fi

	# Bind interfaces used in perf stage to vfio
	perf_pf_list=(0002:02:00.0 0002:03:00.0)
	for pf in  ${perf_pf_list[@]}; do
		$VFIO_DEVBIND -b vfio-pci $pf || exit 1
	done
}

# Environment variables
PERF_STAGE=${PERF_STAGE:-}
TM_SETUP=${TM_SETUP:-}
NO_HP=${NO_HP:-}
HP=${HP:-8}

if [[ -n ${TARGET_BOARD:-} ]]; then
	# Run on remote by copying this script to the remote board
	SCRIPTPATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
	SCRIPTNAME="$(basename $0)"
	SUDO=${SUDO:-"sudo"}
	TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
	TARGET_SCP_CMD=${TARGET_SCP_CMD:-"scp"}
	REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
	$TARGET_SSH_CMD $TARGET_BOARD mkdir -p $REMOTE_DIR
	$TARGET_SCP_CMD $SCRIPTPATH/$SCRIPTNAME $TARGET_BOARD:$REMOTE_DIR/cnxk-target-setup.sh
	VFIO_DEVBIND=${VFIO_DEVBIND:-$REMOTE_DIR/marvell-ci/test/board/oxk-devbind-basic.sh}
	TARGET_EXPORTS="VFIO_DEVBIND=$VFIO_DEVBIND PERF_STAGE=$PERF_STAGE HP=$HP TM_SETUP=$TM_SETUP"
	$TARGET_SSH_CMD $TARGET_BOARD \
		"$SUDO $TARGET_EXPORTS $REMOTE_DIR/cnxk-target-setup.sh"
	exit 0
fi

VFIO_DEVBIND=${VFIO_DEVBIND:-$(command -v oxk-devbind-basic.sh)}
if [[ ! -x $VFIO_DEVBIND ]]; then
	echo "VFIO_DEVBIND Invalid. Set VFIO_DEVBIND to a valid oxk-devbind-basic.sh script."
	exit 1
fi

# Get CPU
CPU=$(get_cpu_string)
IS_CN9K=0
if [[ "$CPU" == "98xx" ]] || [[ "$CPU" == "96xx" ]] || [[ "$CPU" == "cnf10ka" ]]
then
	IS_CN9K=1
fi

mount_hugetlbfs
setup_hp
setup_devices
setup_tm
setup_perf

set -euo pipefail
