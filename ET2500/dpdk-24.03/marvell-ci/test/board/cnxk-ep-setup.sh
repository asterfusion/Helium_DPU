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

	host_pf=$(lspci -Dd :ba00 | head -1 | awk '{ print $1 }')
	echo 2 > /sys/bus/pci/devices/${host_pf}/sriov_numvfs

	host_vf=$(lspci -Dd :ba03 | head -1 | awk '{ print $1 }')
	echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
	$VFIO_DEVBIND -b vfio-pci $host_vf
}

setup_board()
{
	local sdp_vf1
	local sdp_vf1_if
	local sdp_vf2

	if [[ ! -e /sys/module/pcie_marvell_cnxk_ep ]]; then
		if [[ -e $MODULE_PATH/pcie-marvell-cnxk-ep.ko ]]; then
			insmod $MODULE_PATH/pcie-marvell-cnxk-ep.ko
		elif modinfo pcie-marvell_cnxk_ep &> /dev/null; then
			modprobe pcie-marvell_cnxk_ep
		else
			echo "Set MODULE_PATH to a valid pcie-marvell-cnxk-ep.ko location"
			exit 1
		fi
	fi

	sdp_vf1=$(lspci -d :a0f7 | head -1 | awk -e '{ print $1 }')
	sdp_vf1_if=$(ls /sys/bus/pci/devices/${sdp_vf1}/net)
	ifconfig $sdp_vf1_if up
	$AGENT_PATH/octep_cp_agent $AGENT_PATH/cnf105xx.cfg &> /tmp/octep_cp_agent_log.txt &

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
