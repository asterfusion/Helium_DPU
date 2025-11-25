#!/bin/bash -x
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

# Script syntax:
# cnxk-ep-setup.sh
#
# Optional environment variables:
# HP How many hugepages of default size to enable.
# VFIO_DEVBIND - Alternative location of oxk-devbind-basic.sh script.
# TARGET_URL   - Optional SSH URL for the endpoint host/board to setup. If not
#                given, all commands are run locally. If it is given, the script
#                is copied to REMOTE_DIR on the host/board and run from there.
# AGENT_PATH   - Path to octep_cp_agent and conf files.
# MODULE_PATH  - Path to pcie-marvell-cnxk-ep.ko/octeon_ep.ko module path.
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
# 2. The script prepares either the host or the board by performing the
#    following tasks: inserting the necessary modules, creating Virtual
#    Functions (VFs), and binding each PCI device using the VFIO_DEVBIND
#    script.


set -euo pipefail

HP=${HP:-8}
AGENT_PATH=${AGENT_PATH:-/usr/bin}
MODULE_PATH=${MODULE_PATH:-/usr/lib/modules/`uname -r`}
PCI_DEVID_CN10K_RVU_PEM_PF="0xa06c"

setup_hp() {
	if ! mount | grep -q hugepages; then
		mount -t hugetlbfs none /dev/hugepages/
	fi

	echo $HP > /proc/sys/vm/nr_hugepages
}

setup_host()
{
	local host_pf
	local host_vf
	local part

	VFIO_DEVBIND=${VFIO_DEVBIND:-$(command -v oxk-devbind-basic.sh)}
	if [[ ! -x $VFIO_DEVBIND ]]; then
		echo "Set VFIO_DEVBIND to a valid oxk-devbind-basic.sh script."
		exit 1
	fi

	if [[ ! -e /sys/module/octeon_ep ]]; then
		if [[ -e $MODULE_PATH/octeon_ep.ko ]]; then
			insmod $MODULE_PATH/octeon_ep.ko
		elif modinfo octeon_ep &> /dev/null; then
			modprobe octeon_ep
		else
			echo "Set MODULE_PATH to a valid octeon_ep.ko location"
			exit 1
		fi

		# Wait for driver load
		timeout 15m bash -c '
			while ! (dmesg | grep -q "octeon_ep .* Device setup successful"); do
				sleep 1;
			done
		'
	fi

	sleep 5

	part="ba" # CN105xx
	host_pf=$(lspci -Dd :${part}00 | head -1 | awk '{ print $1 }')
	if [[ -z $host_pf ]]; then
		part="b9" # CN106xx
		host_pf=$(lspci -Dd :${part}00 | head -1 | awk '{ print $1 }')
		if [[ -z $host_pf ]]; then
			echo "No host PF found"
			exit 1
		fi
	fi
	echo 2 > /sys/bus/pci/devices/${host_pf}/sriov_numvfs

	host_vf=$(lspci -Dd :${part}03 | head -1 | awk '{ print $1 }')
	modprobe vfio
	echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
	$VFIO_DEVBIND -b vfio-pci $host_vf
}

function get_part()
{
	local vendor
	local dev_id
	local subsys_dev_id
	local part
	local vendor_cavium="0x177d"
	# RVU device IDs   RVU_PF  RVU_VF  RVU_AF  SSO_PF  SSO_VF  NPA_PF  NPA_VF  RVU_AFVF CPT_PF  CPT_VF
	local rvu_dev_ids="0xa063  0xa064  0xa065  0xa0f9  0xa0fa  0xa0fb  0xa0fc  0xa0f8   0xa0f2  0xa0f3"

	set +x
	for d in $(ls /sys/bus/pci/devices); do
		local is_rvu_dev=0

		vendor=$(cat /sys/bus/pci/devices/$d/vendor)
		if [[ "$vendor" != "$vendor_cavium" ]]; then
			continue
		fi
		dev_id=$(cat /sys/bus/pci/devices/$d/device)
		for r in $rvu_dev_ids; do
			if [[ "$dev_id" == "$r" ]]; then
				is_rvu_dev=1
				break
			fi
		done
		if [[ $is_rvu_dev == 0 ]]; then
			continue
		fi
		subsys_dev_id=$(cat /sys/bus/pci/devices/$d/subsystem_device)
		part=${subsys_dev_id:2:2}
		break
	done
	set -x
	echo $part
}

function ep_device_unbind_driver()
{
	local s=$1
	local dev=$2

	if [[ -e /sys/bus/$s/devices/$dev/driver/unbind ]]; then
		echo $dev > /sys/bus/$s/devices/$dev/driver/unbind
		sleep 1
		echo > /sys/bus/$s/devices/$dev/driver_override
		sleep 1
	fi
}

function ep_device_bind_driver()
{
        local s=$1
        local dev=$2
        local driver=$3

        ep_device_unbind_driver $s $dev
        echo $driver > /sys/bus/$s/devices/$dev/driver_override
        echo $dev > /sys/bus/$s/drivers/$driver/bind
        echo $dev > /sys/bus/$s/drivers_probe
}

function ep_device_pcie_addr_get()
{
	local devid=$1
	local num=${2:-}

	if [[ -z $num ]]; then
		num=1
	elif [[ $num == "all" ]]; then
		num=100
	fi

	echo $(lspci -Dd :$devid | awk '{print $1}' | head -n$num)
}

function ep_device_hugepage_setup()
{
	local hp_sz=$1
	local hp_num=$2
	local hp_pool_sz=$3

	# Check for hugepages
	if mount | grep hugetlbfs | grep none; then
		echo "Hugepages already mounted"
	else
		echo "Mounting Hugepages"
		mkdir -p /dev/huge
		mount -t hugetlbfs none /dev/huge
	fi
	echo $hp_num > /proc/sys/vm/nr_hugepages
	echo $hp_pool_sz >/sys/kernel/mm/hugepages/hugepages-${hp_sz}kB/nr_hugepages
}

setup_board()
{
	local sdp_vf1
	local sdp_vf1_if
	local sdp_vf2
	local part_105="0xba"
	local part_106="0xb9"
	local part
	local cfg

	export LD_LIBRARY_PATH=/usr/local/lib:
	ep_device_hugepage_setup 524288 24 12

	for dev in $(lspci -d :a0ef | awk -e '{print $1}'); do
		# Bind the device to vfio-pci driver
		ep_device_bind_driver pci $dev vfio-pci
		echo "Device $dev configured."
	done

	pem_pf_pcie=$(ep_device_pcie_addr_get $PCI_DEVID_CN10K_RVU_PEM_PF)
	ep_device_bind_driver pci $pem_pf_pcie vfio-pci

	sdp_vf1=$(lspci -d :a0f7 | head -1 | awk -e '{ print $1 }')
	sdp_vf1_if=$(ls /sys/bus/pci/devices/${sdp_vf1}/net)
	ifconfig $sdp_vf1_if up
	part=$(get_part)
	if [[ "0x$part" == "$part_105" ]]; then
		cfg="cnf105xx.cfg"
	elif [[ "0x$part" == "$part_106" ]]; then
		cfg="cn106xx.cfg"
	else
		echo "Unsupported part $part"
		exit 1
	fi
	cp $AGENT_PATH/libconfig.so.11 /usr/lib/

	$AGENT_PATH/octep_cp_agent \
		$AGENT_PATH/$cfg  -- --sdp_rvu_pf 0002:18:00.0,0002:19:00.0 \
		--pem_dev 0001:00:10.0  &> /tmp/octep_cp_agent_log.txt &

	sdp_vf2=$(lspci -Dd :a0f7 | head -2 | tail -1 | awk -e '{ print $1 }')
	$VFIO_DEVBIND -b vfio-pci $sdp_vf2
}

if [[ -n ${TARGET_URL:-} ]]; then
	# Run on remote by copying this script to the target URL
	SCRIPTPATH="$(cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
	SCRIPTNAME="$(basename $0)"
	SUDO=${SUDO:-"sudo"}
	SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
	SCP_CMD=${TARGET_SCP_CMD:-"scp"}
	REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
	$SSH_CMD $TARGET_URL mkdir -p $REMOTE_DIR
	$SCP_CMD $SCRIPTPATH/$SCRIPTNAME $TARGET_URL:$REMOTE_DIR/cnxk-ep-setup.sh
	VFIO_DEVBIND=${VFIO_DEVBIND:-$REMOTE_DIR/marvell-ci/test/board/oxk-devbind-basic.sh}
	$SSH_CMD $TARGET_URL "$SUDO VFIO_DEVBIND=$VFIO_DEVBIND HP=$HP \
		AGENT_PATH=$AGENT_PATH MODULE_PATH=$MODULE_PATH $REMOTE_DIR/cnxk-ep-setup.sh"
	exit 0
fi

setup_hp

if grep -qi "vendor_id\s*:.*genuineintel" /proc/cpuinfo; then
	setup_host
else
	setup_board
fi
