#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="mtr-config"

TESTPMD_PORT="0002:02:00.0"
TESTPMD_COREMASK="0x3"

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

function bind_interface()
{
	echo "port $TESTPMD_PORT is bound to VFIO"
	$VFIO_DEVBIND -b vfio-pci $TESTPMD_PORT
}

function check_meter_algo()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/cn10k"
	bpf_ctx="$debug_dir/nix/ingress_policer_ctx"

	if $SUDO test -f "$bpf_ctx"; then
		mtr_algo=$(echo "`$SUDO cat $bpf_ctx`" | grep meter_algo | awk '{print $3}')
	else
		echo "$bpf_ctx is not available"
		exit 1
	fi

	if [[ $mtr_algo != $1 ]]; then
		echo "Wrong meter algorithm is configured. Configured algo $mtr_algo"
		exit 1
	fi
}


function check_meter_actions()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/cn10k"
	bpf_ctx="$debug_dir/nix/ingress_policer_ctx"

	if $SUDO test -f "$bpf_ctx"; then
		gc_action=$(echo "`$SUDO cat $bpf_ctx`" | grep gc_action | awk '{print $3}')
		yc_action=$(echo "`$SUDO cat $bpf_ctx`" | grep yc_action | awk '{print $3}')
		rc_action=$(echo "`$SUDO cat $bpf_ctx`" | grep rc_action | awk '{print $3}')
	else
		echo "$bpf_ctx is not available"
		exit 1
	fi

	if [[ $gc_action != $1 ]]; then
		echo "gc_action is not same. Configured action $gc_action"
		exit 1
	fi

	if [[ $yc_action != $2 ]]; then
		echo "yc_action is not same. Configured action $yc_action"
		exit 1
	fi

	if [[ $rc_action != $3 ]]; then
		echo "rc_action is not same. Configured action $rc_action"
		exit 1
	fi
}

function check_meter_input_color()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/cn10k"
	bpf_ctx="$debug_dir/nix/ingress_policer_ctx"

	if $SUDO test -f "$bpf_ctx"; then
		icolor=$(echo "`$SUDO cat $bpf_ctx`" | grep icolor | awk '{print $3}')
	else
		echo "$bpf_ctx is not available"
		exit 1
	fi

	if [[ $icolor != $1 ]]; then
		echo "input color is not same. Configured action $icolor"
		exit 1
	fi
}

function check_meter_input_color_method()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/cn10k"
	bpf_ctx="$debug_dir/nix/ingress_policer_ctx"

	if $SUDO test -f "$bpf_ctx"; then
		pc_mode=$(echo "`$SUDO cat $bpf_ctx`" | grep pc_mode | awk '{print $3}')
		tnl_ena=$(echo "`$SUDO cat $bpf_ctx`" | grep tnl_ena | awk '{print $3}')
	else
		echo "$bpf_ctx is not available"
		exit 1
	fi

	if [[ $pc_mode != $1 || $tnl_ena != $2 ]]; then
		echo "input color method is not same. pc_mode $pc_mode and tnl_ena $tnl_ena"
		exit 1
	fi
}

function check_meter_rq_config()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/cn10k"
	rq_ctx="$debug_dir/nix/rq_ctx"
	rsrc_alloc="$debug_dir/rsrc_alloc"
	nix_lf=$(echo "`$SUDO cat $rsrc_alloc`" | grep "PF1" | awk '{print $3}' | head -1)
	$SUDO echo "$nix_lf 0" > $rq_ctx

	if $SUDO test -f "$rq_ctx"; then
		is_policer_ena=$(echo "`$SUDO cat $rq_ctx`" | grep policer_ena | awk '{print $3}')
	else
		echo "$rq_ctx is not available"
		exit 1
	fi

	if [[ $is_policer_ena != "1" ]]; then
		echo "Policer is not configured on RQ 0"
		exit 1
	fi
}

function check_meter_input_color_table()
{
	local error
	local search

	search="Meter object not found"
	error=`testpmd_log $PRFX | tail -n1 | grep -v "$search"`
	if [[ "$error" != "testpmd> " ]]; then
		echo "$error"
		exit 1
	fi

	search="Invalid input color protocol"
	error=`testpmd_log $PRFX | tail -n1 | grep -v "$search"`
	if [[ "$error" != "testpmd> " ]]; then
		echo "$error"
		exit 1
	fi

	search="Table size must be"
	error=`testpmd_log $PRFX | tail -n1 | grep -v "$search"`
	if [[ "$error" != "testpmd> " ]]; then
		echo "$error"
		exit 1
	fi
}

function check_meter_input_color_protocol()
{
	local protocol

	protocol=`testpmd_log $PRFX | tail -n2 | grep "$1"`
	if [[ -z $protocol ]]; then
		echo "Invalid protocol"
		exit 1
	fi
}

function check_meter_input_color_protocol_priority()
{
	local priority
	local search

	search="CNXK: Only single priority supported i.e. 0"
	priority=`testpmd_log $PRFX | tail -n2 | grep "$search"`
	if [[ -z $priority ]]; then
		echo "Invalid protocol priority"
		exit 1
	fi
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

bind_interface

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
	"--no-flush-rx --nb-cores=1"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"

# Test case - 1: Validate metering algorithm configuration
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_algo "3"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile trtcm_rfc2698 0 0 1000000000 2000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_algo "1"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 2: Validate action configuration based on color
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_actions "PASS" "PASS" "PASS"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions drop / end y_actions drop / end r_actions drop / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_actions "DROP" "DROP" "DROP"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 3: Validate input color configuration
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color "Green"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color "Yellow"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 r 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color "Red"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 4: Validate input color method configuration
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 outer_vlan 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color_method "VLAN" "0"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 g 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 inner_vlan 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color_method "VLAN" "1"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 outer_ip 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern ipv4 src is 1.1.1.1 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color_method "DSCP" "0"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 inner_ip 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern ipv4 src is 1.1.1.1 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_input_color_method "DSCP" "1"
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 5: Validate meter configuration association with RQ
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "flow create 0 ingress pattern ipv4 src is 1.1.1.1 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3
check_meter_rq_config
testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 6: Validate meter VLAN input color table runtime update
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 outer_vlan 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3

testpmd_cmd $PRFX "set port meter vlan table 0 0 r r r r r r r r r r r r r r r r"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "set port meter vlan table 0 0 g g g g g g g g g g g g g g g g"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "set port meter vlan table 0 0 y y y y y y y y y y y y y y y y"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 7: Validate meter DSCP input color table runtime update
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 outer_ip 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern ipv4 src is 1.1.1.1 / end actions meter mtr_id 0 / queue index 0 / end"
sleep 3

testpmd_cmd $PRFX "set port meter dscp table 0 0 g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g g"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "set port meter dscp table 0 0 r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r r"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "set port meter dscp table 0 0 y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y y"
sleep 3
check_meter_input_color_table

testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

# Test case - 8: Validate meter protocol and priority retrieve operation
testpmd_cmd $PRFX "add port meter profile srtcm_rfc2697 0 0 1000000000 5000 10000 0"
testpmd_cmd $PRFX "add port meter policy 0 0 g_actions void / end y_actions void / end r_actions void / end"
testpmd_cmd $PRFX "create port meter 0 0 0 0 yes 0 0 y 0 r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y g r y y y y y y y y y y y y y y y y"
testpmd_cmd $PRFX "set port meter proto 0 0 outer_vlan 0"
testpmd_cmd $PRFX "flow create 0 ingress pattern vlan pcp is 0 / end actions meter mtr_id 0 / queue index 0 / end"
testpmd_cmd $PRFX "get port meter proto 0 0"
sleep 3
check_meter_input_color_protocol "outer_vlan"

testpmd_cmd $PRFX "set port meter proto 0 0 inner_vlan 0"
testpmd_cmd $PRFX "get port meter proto 0 0"
sleep 3
check_meter_input_color_protocol "inner_vlan"

testpmd_cmd $PRFX "set port meter proto 0 0 outer_ip 0"
testpmd_cmd $PRFX "get port meter proto 0 0"
sleep 3
check_meter_input_color_protocol "outer_ip"

testpmd_cmd $PRFX "set port meter proto 0 0 inner_ip 0"
testpmd_cmd $PRFX "get port meter proto 0 0"
sleep 3
check_meter_input_color_protocol "inner_ip"

testpmd_cmd $PRFX "get port meter proto_prio 0 0 outer_vlan"
sleep 3
check_meter_input_color_protocol_priority

testpmd_cmd $PRFX "get port meter proto_prio 0 0 inner_vlan"
sleep 3
check_meter_input_color_protocol_priority

testpmd_cmd $PRFX "get port meter proto_prio 0 0 outer_ip"
sleep 3
check_meter_input_color_protocol_priority

testpmd_cmd $PRFX "get port meter proto_prio 0 0 inner_ip"
sleep 3
check_meter_input_color_protocol_priority

testpmd_cmd $PRFX "del port meter 0 0"
testpmd_cmd $PRFX "del port meter profile 0 0"
testpmd_cmd $PRFX "del port meter policy 0 0"

testpmd_log $PRFX

echo "SUCCESS: testpmd meter configuration test suit completed"
