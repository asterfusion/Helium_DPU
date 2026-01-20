#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env


PRFX="pktgen"
CAP_PRFX="dut"
TXPORT="0002:01:00.2"
RXPORT="0002:01:00.1"
COREMASK="0xC"
CAP_COREMASK="0x3"

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
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

DTC=$(tr -d '\0' </proc/device-tree/model | awk '{print $2}')

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

	testpmd_quit $CAP_PRFX
	testpmd_quit $PRFX
	testpmd_cleanup $CAP_PRFX
	testpmd_cleanup $PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT


function ingress_policer_test()
{
	if [ "$1" == "level_3" ]; then
		testpmd_cmd $CAP_PRFX "add port meter profile srtcm_rfc2697 0 100 1000000000 5000 10000 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 200 g_actions void / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 300 100 200 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 201 g_actions meter mtr_id 300 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 301 100 201 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 202 g_actions meter mtr_id 300 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 302 100 202 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 203 g_actions meter mtr_id 301 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 303 100 203 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 204 g_actions meter mtr_id 301 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 304 100 204 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 205 g_actions meter mtr_id 302 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 305 100 205 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 206 g_actions meter mtr_id 302 / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 306 100 206 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 303 / queue index 0 / end"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 304 / queue index 1 / end"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 305 / queue index 2 / end"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 306 / queue index 3 / end"

	fi

	if [ "$1" == "level_1" ]; then
		testpmd_cmd $CAP_PRFX "add port meter profile srtcm_rfc2697 0 100 1000000000 5000 10000 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 200 g_actions void / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 300 100 200 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 300 / queue index 0 / end"
	fi

	if [ "$1" == "test_red" ]; then
		testpmd_cmd $CAP_PRFX "set port cman config 0 0 obj queue mode red 10 20 1"
		testpmd_cmd $CAP_PRFX "add port meter profile srtcm_rfc2697 0 100 1000000000 5000 10000 0"
		testpmd_cmd $CAP_PRFX "add port meter policy 0 200 g_actions void / end y_actions drop / end r_actions drop / end"
		testpmd_cmd $CAP_PRFX "create port meter 0 300 100 200 yes 0 0 g 0"
		testpmd_cmd $CAP_PRFX "flow create 0 ingress pattern eth / end actions meter mtr_id 300 / queue index 0 / end"
		sleep 2

	fi

	if [ "$1" == "test_red" ]; then
		testpmd_red_configuration
	else

		testpmd_cmd $CAP_PRFX "start"
		sleep 5
		testpmd_cmd $CAP_PRFX "show port stats all"
		sleep 1
		testpmd_cmd $CAP_PRFX "show port stats all"
		sleep 1
		testpmd_rxbps_stats $CAP_PRFX
	fi
}

function testpmd_red_configuration()
{
	local debug_dir

	debug_dir="/sys/kernel/debug/octeontx2"
	if [[ -d /sys/kernel/debug/cn10k ]]; then
		debug_dir="/sys/kernel/debug/cn10k"
	fi

	ingress_policer_ctx="$debug_dir/nix/ingress_policer_ctx"

	if $SUDO test -f "$ingress_policer_ctx"; then
		action=$(echo "`$SUDO cat $ingress_policer_ctx`" | grep "rc_action" \
				| awk '{print $3}')
		if [ "$action" == "RED" ]; then
			echo "RED action for policer is success"
		else
			echo "RED action for policer failed"
		fi
	else
		echo "$ingress_policer_ctx is not available"
		exit 1
	fi


}
function testpmd_rxbps_stats()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	val=`cat $out | grep "Rx-bps:" | awk -e '{print $4}' | tail -1`
	if [[ $val -le 8000000000 && $val -ge 7700000000 ]] ;then
		echo "Ingress policy $1 success"
	else
		echo "Ingress policy $1 failed"
		exit 1
	fi
}

function run_testpmd()
{
	echo "Testpmd running with Coremask=$COREMASK"
	CORES_TX="0-4"
	CORES_RX="5-10"
	CORES=4

	if [[ $DTC == "CN103XX" ]]; then
		CORES_TX="0-3"
		CORES_RX="4-7"
		CORES=3
	fi

	testpmd_launch $PRFX \
		"-l $CORES_TX -a $TXPORT" \
		"--no-flush-rx --nb-cores=$CORES --forward-mode=txonly --txonly-multi-flow --txq=4 --rxq=4"

	testpmd_cmd $PRFX "start"

	# Launch capture testpmd
	testpmd_launch $CAP_PRFX \
		"-l $CORES_RX -a $RXPORT" \
		"--no-flush-rx --nb-cores=$CORES --forward-mode=rxonly --txq=4 --rxq=4"
}

function stop_testpmd()
{
        testpmd_quit $PRFX
        sleep 1
        testpmd_cleanup $PRFX
        sleep 3
        testpmd_quit $CAP_PRFX
        sleep 1
        testpmd_cleanup $CAP_PRFX
        sleep 1
}

echo "Ingress policer with 4 leaf nodes 2 mid nodes 1 root node"
run_testpmd
sleep 1
ingress_policer_test level_3

stop_testpmd

echo "Ingress policer with single node"
run_testpmd
sleep 1
ingress_policer_test level_1

stop_testpmd

echo "Configure RED to meter"
run_testpmd
sleep 1
ingress_policer_test test_red
