#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="fc-config"
PRFX_VF="vf_fc-config"

TESTPMD_PORT="0002:02:00.0"
TESTPMD_VF_PORT="0002:02:00.1"
DTC=$(tr -d '\0' </proc/device-tree/model | awk '{print $2}')
if [[ $DTC == "CN103XX" ]]; then
	TESTPMD_COREMASK="0xff"
	CORES=7
else
	TESTPMD_COREMASK="0xfff"
	CORES=8
fi

if [ -f $CNXKTESTPATH/../board/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$CNXKTESTPATH/../board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

function bind_pf_interface()
{
	echo "port $TESTPMD_PORT is bound to VFIO"
	$VFIO_DEVBIND -b vfio-pci $TESTPMD_PORT
}

function bind_vf_interface()
{
	echo "port $TESTPMD_VF_PORT is bound to VFIO"
	$VFIO_DEVBIND -b vfio-pci $TESTPMD_VF_PORT
}

function release_pf_interface()
{
	if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
		NICPF="octeontx2-nicpf"
	else
		NICPF="rvu_nicpf"
	fi

	$VFIO_DEVBIND -b $NICPF $TESTPMD_PORT
}

function release_vf_interface()
{
	if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
		NICVF="octeontx2-nicvf"
	else
		NICVF="rvu_nicvf"
	fi

	$VFIO_DEVBIND -b $NICVF $TESTPMD_VF_PORT
}

function verify_fc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		if [ $1 == "pf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
		fi
		if [ $1 == "vf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1:VF0" | awk '{print $3}' | head -1)
		fi
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf 0" > $cq_ctx
		bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "W1: bp_ena" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	if [[ $bp_ena -ne $2 ]]; then
		echo "flow control validation failed."
		exit 1
	fi
}

function verify_pfc_state()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	cq_ctx="$debug_dir/nix/cq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"

	if $SUDO test -f "$rsrc_alloc"; then
		if [ $1 == "pf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
		fi
		if [ $1 == "vf" ] ;then
			nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1:VF0" | awk '{print $3}' | head -1)
		fi
	else
		echo "$rsrc_alloc is not available"
		exit 1
	fi

	if $SUDO test -f "$cq_ctx"; then
		$SUDO echo "$nix_lf $3" > $cq_ctx
		bp_ena=$(echo "`$SUDO cat $cq_ctx`" | grep "W1: bp_ena" | awk '{print $3}')
	else
		echo "$cq_ctx is not available"
		exit 1
	fi

	if [[ $bp_ena -ne $2 ]]; then
		echo "priority flow control validation failed."
		exit 1
	fi
}

function stop_testpmd()
{
	testpmd_quit $PRFX_VF
	sleep 1
	testpmd_cleanup $PRFX_VF
	sleep 3
	testpmd_quit $PRFX
	sleep 1
	testpmd_cleanup $PRFX
	sleep 1
}

function configure_fc()
{
	testpmd_cmd $PRFX "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	testpmd_cmd $PRFX_VF "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	verify_fc_state pf 1
	sleep 1
	verify_fc_state vf 1
	sleep 1
	echo "PF and VF flow control configuration Success"
}

function configure_pfc()
{
	testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on 0 0 tx on 0 0 2047"
	sleep 1
	testpmd_cmd $PRFX_VF "set pfc_queue_ctrl 0 rx on 0 0 tx on 0 0 2047"
	sleep 1
	verify_pfc_state pf 1 0
	sleep 1
	verify_pfc_state vf 1 0
	sleep 1
	echo "PF and VF Priority flow control configuration Success"
}

function configure_pf_vf()
{
	echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
	testpmd_launch $PRFX \
		"-c $TESTPMD_COREMASK -a $TESTPMD_PORT,flow_max_priority=8 \
		--vfio-vf-token=$TOKEN --file-prefix=pf" \
		"--no-flush-rx --rxq=1 --txq=1 --nb-cores=1"
	sleep 1
	testpmd_cmd $PRFX "port stop all"
	sleep 1
	testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
	echo "Testpmd running with $TESTPMD_VF_PORT, Coremask=$TESTPMD_COREMASK"
	testpmd_launch $PRFX_VF \
		"-c $TESTPMD_COREMASK -a $TESTPMD_VF_PORT,flow_max_priority=8 \
		--vfio-vf-token=$TOKEN --file-prefix=vf" \
		"--no-flush-rx --rxq=1 --txq=1 --nb-cores=1"
	testpmd_cmd $PRFX_VF "port stop all"
	sleep 1
	testpmd_cmd $PRFX_VF "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
	sleep 1
}

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
	fi

	testpmd_cleanup $PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# Enable SRIOV
echo 1 > /sys/module/vfio_pci/parameters/enable_sriov
TOKEN=$(uuidgen)
echo $TOKEN
bind_pf_interface
echo 1 > /sys/bus/pci/devices/$TESTPMD_PORT/sriov_numvfs
bind_vf_interface

echo "Starting PFC & FC Test for PF and VF with DPDK"

configure_pf_vf

configure_fc

stop_testpmd

configure_pf_vf

configure_pfc

stop_testpmd

release_vf_interface

echo "Starting FC and PFC Test for PF DPDK and VF with kernel"

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT,flow_max_priority=8" \
	"--no-flush-rx --rxq=8 --txq=8 --nb-cores=$CORES"

# Part - 1: Validate priority flow control (802.3x)
# Test case - 1: Validate flow control default configuration. Must be enable
verify_fc_state pf 1

testpmd_cmd $PRFX "port stop all"
# Test case - 2: Validate flow control configuration after disabling
testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 3
verify_fc_state pf 0

# Test case - 3: Validate flow control configuration after re-enable
testpmd_cmd $PRFX "set flow_ctrl rx on tx on 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 3
verify_fc_state pf 1

# Part - 2: Validate priority flow control (802.1Qbb)
# Test case - 4: Validate priority flow control
testpmd_cmd $PRFX "set flow_ctrl rx off tx off 0 0 0 0 mac_ctrl_frame_fwd off autoneg off 0"
sleep 1

txq=0
prio=7
while [[ $txq -ne 8 ]]; do
	testpmd_cmd $PRFX "flow create 0 priority $prio ingress pattern vlan pcp is $txq / end actions queue index $txq / end"
	sleep 1
	testpmd_cmd $PRFX "set pfc_queue_ctrl 0 rx on $txq $txq tx on $txq $txq 2047"
	sleep 1
	txq=`expr $txq + 1`
	prio=$((prio-1))
done

testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"
sleep 1

cq=0
while [[ $cq -ne 8 ]]; do
	verify_pfc_state pf 1 $cq
	cq=`expr $cq + 1`
done

testpmd_quit $PRFX
sleep 1
testpmd_cleanup $PRFX
sleep 1

#testpmd_log $PRFX

echo "SUCCESS: testpmd flow control configuration test suit completed"

release_pf_interface
