#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

L3FWD_SCRIPT_PATH=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))

if [[ -f $L3FWD_SCRIPT_PATH/../../../../examples/dpdk-l3fwd-power ]]; then
	# This is running from build directory
	L3FWD=$L3FWD_SCRIPT_PATH/../../../../examples/dpdk-l3fwd-power
elif [[ -f $L3FWD_SCRIPT_PATH/../../../dpdk-l3fwd-power ]]; then
	# This is running from install directory
	L3FWD=$L3FWD_SCRIPT_PATH/../../../dpdk-l3fwd-power
else
	L3FWD=$(command -v dpdk-l3fwd-power)
fi

if [[ -z $L3FWD ]]; then
	echo "dpdk-l3fwd-power not found !!"
	exit 1
fi

PRFX="pktgen"
CAP_PRFX="dut"

PORT0="0002:01:00.2"
PORT1="0002:01:00.4"
CAP_PORT0="0002:01:00.1"
CAP_PORT1="0002:01:00.3"
CAP_COREMASK="0x3"
COREMASK="0xFF8"

out=l3fwd.out.$CAP_PRFX
in=l3fwd.in.$CAP_PRFX

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

#Bind extra LBK to test port close
if [[ -f $1/marvell-ci/test/board/oxk-devbind-basic.sh ]]; then
	VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(command -v oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

$VFIO_DEVBIND -b vfio-pci $PORT1

function l3fwd_cleanup()
{
	local prefix=$1

	# Issue kill
	ps -eo "pid,args" | grep l3fwd-power | grep $prefix | \
		awk '{print $1}' | xargs -I[] -n1 kill -9 [] 2>/dev/null || true

	# Wait until the process is killed
	while (ps -ef | grep l3fwd-power | grep -q $prefix); do
		sleep 1
	done
}

function l3fwd_launch()
{
	local prefix=$1
	local eal_args=$2
	local l3fwd_args=$3

	l3fwd_cleanup $prefix
	rm -f $out
	rm -f $in
	touch $in
	tail -f $in | \
		(stdbuf -o0 $L3FWD $eal_args --file-prefix $prefix -- \
			$l3fwd_args &>$out) &
	# Wait till out file is created
	while [[ ! -f $out ]]; do
		sleep 1
	done
	# Wait for l3fwd to be up
	itr=0
	while ! (tail -n20 $out | grep -q "L3FWD_POWER:  -- lcoreid=0 portid=0 rxqueueid=0"); do
		sleep 1
		((itr+=1))
		if [[ itr -eq 1000 ]]; then
			echo "Timeout waiting for l3fwd";
			exit 1;
		fi
	done
}

function cleanup_interface()
{
	$VFIO_DEVBIND -b $NICVF $PORT1
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

	testpmd_quit $PRFX
	testpmd_cleanup $PRFX
	l3fwd_cleanup $CAP_PRFX
	cleanup_interface
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

echo "l3fwd-power running with $CAP_PORT0 & $CAP_PORT1, Coremask=$CAP_COREMASK"
l3fwd_launch $CAP_PRFX "-c $CAP_COREMASK -a $CAP_PORT0 -a $CAP_PORT1 -n 4" \
	"-p 0x3 -P --config=\"(0,0,0),(1,0,1)\""

# Launch testpmd to send packets on PORT0
testpmd_launch $PRFX "-c $COREMASK -a $PORT0 " "--nb-cores=8 --no-flush-rx -i"

# Start capturing
testpmd_cmd $PRFX "start tx_first"
sleep 3
#Check for interrupt
if ! (tail -n20 $out | \
       grep -q "L3FWD_POWER: lcore 0 is waked up from rx interrupt on port 0 queue 0"); then
	echo "Interrupt not received $PORT0"
	exit 1;
fi
testpmd_cmd $PRFX "stop"
sleep 2
#When traffic stopped, core get in to sleep state
if ! (tail -n20 $out | grep -q "L3FWD_POWER: lcore 0 sleeps until interrupt triggers"); then
	echo "Core sleep failed $PORT0"
	exit 1;
fi
testpmd_quit $PRFX
testpmd_cleanup $PRFX

sleep 10

# Launch testpmd to send packets on PORT1
testpmd_launch $PRFX "-c $COREMASK -a $PORT1 " "--nb-cores=8 --no-flush-rx -i"

# Start capturing
testpmd_cmd $PRFX "start tx_first"
sleep 3
#Check for interrupt
if ! (tail -n20 $out | \
       grep -q "L3FWD_POWER: lcore 1 is waked up from rx interrupt on port 1 queue 0"); then
	echo "Interrupt not received for $PORT1"
	exit 1;
fi
testpmd_cmd $PRFX "stop"
sleep 2
#When traffic stopped, core get in to sleep state
if ! (tail -n20 $out | grep -q "L3FWD_POWER: lcore 1 sleeps until interrupt triggers"); then
	echo "Core sleep failed $PORT1"
	exit 1;
fi

testpmd_quit $PRFX
testpmd_cleanup $PRFX
l3fwd_cleanup $CAP_PRFX

#Bind interface back to kernel
cleanup_interface

echo "SUCCESS: l3fwd queue interrupt test completed"
