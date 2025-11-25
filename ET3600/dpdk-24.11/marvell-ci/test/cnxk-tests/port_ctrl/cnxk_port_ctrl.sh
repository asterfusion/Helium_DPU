#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="pktgen"
CAP_PRFX="dut"

PORT0="0002:01:00.4"
CAP_PORT0="0002:01:00.2"
CAP_PORT1="0002:01:00.3"
COREMASK="0xC"
CAP_COREMASK="0x3"
EXPECTED_CNT=1000

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

#Bind extra LBK to test port close
if [ -f $1/marvell-ci/test/board/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

$VFIO_DEVBIND -b vfio-pci $PORT0

function cleanup_interface()
{
	$VFIO_DEVBIND -b $NICVF $PORT0
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

	testpmd_quit $CAP_PRFX
	testpmd_quit $PRFX
	testpmd_cleanup $CAP_PRFX
	testpmd_cleanup $PRFX
	cleanup_interface
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function pkt_test()
{
	rx_count=`testpmd_port_rx_count $CAP_PRFX 1`
	#Wait until to read valid counters
	while ! [[ $rx_count =~ ^[-+]?[0-9]+$ ]]
	do
		sleep 1
		rx_count=`testpmd_port_rx_count $CAP_PRFX 1`
	done
	# Wait for receiving all packets
	start_ts=`date +%s`
	start_ts=$((start_ts + 60))
	while [[ $rx_count -lt $EXPECTED_CNT ]]
	do
		sleep 0.1
		rx_count=`testpmd_port_rx_count $CAP_PRFX 1`
		ts=`date +%s`
		if (( $ts > $start_ts ))
		then
			echo "Timeout unable to received $EXPECTED_CNT packets"
			cleanup_interface
			exit 1
		fi

	done
	tx_count=`testpmd_port_tx_count $CAP_PRFX 0`
	#Wait until to read valid counters
	sleep 5
	tx_count=`testpmd_port_tx_count $CAP_PRFX 0`
	if [[ $rx_count -gt $tx_count ]]
	then
		echo "Unable to forward received packets"
		cleanup_interface
		exit 1
	fi
}

echo "Testpmd running with $PORT0, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0" \
	"--no-flush-rx --nb-cores=1 --forward-mode=txonly --no-flush-rx"

testpmd_cmd $PRFX "start"

# Launch capture testpmd
testpmd_launch $CAP_PRFX \
	"-c $CAP_COREMASK -a $CAP_PORT0 -a $CAP_PORT1" \
        "--no-flush-rx --nb-cores=1 --forward-mode=io"

# Start capturing
testpmd_cmd $CAP_PRFX "port start all"
testpmd_cmd $CAP_PRFX "start"
pkt_test
echo "PASSED: port start"

#Test 1 (port stop)
testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port stop all"
testpmd_cmd $CAP_PRFX "clear port stats all"
sleep 5

testpmd_cmd $CAP_PRFX "port start all"
testpmd_cmd $CAP_PRFX "start"
pkt_test
echo "PASSED: port stop"

#Test 1 (port reset)
testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port stop all"
testpmd_cmd $CAP_PRFX "clear port stats all"
testpmd_cmd $CAP_PRFX "port reset 1"
sleep 5

testpmd_cmd $CAP_PRFX "port start all"
testpmd_cmd $CAP_PRFX "start"
pkt_test
echo "PASSED: port reset"

#Test 1 (port close)
testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port stop all"
testpmd_cmd $CAP_PRFX "clear port stats all"
testpmd_cmd $CAP_PRFX "port close 1"
testpmd_cmd $CAP_PRFX "device detach $CAP_PORT1"
testpmd_cmd $CAP_PRFX "show device info all"
testpmd_cmd $CAP_PRFX "port attach $CAP_PORT1"
sleep 5

testpmd_cmd $CAP_PRFX "port start all"
testpmd_cmd $CAP_PRFX "start"
pkt_test
echo "PASSED: port close"

testpmd_quit $CAP_PRFX
testpmd_quit $PRFX
testpmd_cleanup $CAP_PRFX
testpmd_cleanup $PRFX
#Bind interface back to kernel
cleanup_interface

echo "SUCCESS: testpmd port control test completed"
