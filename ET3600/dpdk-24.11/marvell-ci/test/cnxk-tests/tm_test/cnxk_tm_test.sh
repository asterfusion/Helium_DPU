#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="pktgen"
CAP_PRFX="dut"
TMP_DIR=/tmp/dpdk-$PRFX
OFF=0
#2 Gbps (5% range)
BPSX=1900000000
#1 Gbps (5% range)
BPSY=950000000
#Packet Count should be morethan this when queue selected for scheduling
QCNT_UP=100000
#Packet Count should be lessthan this, in few cases when Queue was not
#scheduled due to priority queue TX count may be ~512 instead of 0
QCNT_DOWN=2000
retry_cnt=10
percentage=95

PORT0="0002:01:00.4"
CAP_PORT0="0002:01:00.2"
CAP_PORT1="0002:01:00.3"
EXPECTED_CNT=1000

DTC=$(tr -d '\0' </proc/device-tree/model | awk '{print $2}')
if [[ $DTC == "CN103XX" ]]; then
	COREMASK="0x0F"
	CAP_COREMASK="0xF0"
	CORES=2
else
	COREMASK="0xF000"
	CAP_COREMASK="0xFF8"
	CORES=8
fi


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

rm -rf $TMP_DIR
mkdir -p $TMP_DIR

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

function queue_stats()
{
	idx=$1
	a=$(($((3*$idx))+1))
#	testpmd_log_off $CAP_PRFX $OFF

	# Wait until we have the output
	val=$(testpmd_log_off $CAP_PRFX $OFF | grep "show fwd stats all") || true
	while [[ "$val" == "" ]]
	do
		sleep 1
		val=$(testpmd_log_off $CAP_PRFX $OFF | grep "show fwd stats all") || true
	done
	val=`testpmd_log_off $CAP_PRFX $OFF | head -$a | tail -1 | \
		grep -ao "TX-packets: [0-9]*" | awk -e '{print $2}'`
	echo $val
}

function capture_count()
{
	val=`testpmd_log $CAP_PRFX | tail -7 | grep -ao "Tx-bps:   [0-9]*"| \
	        cut -f 2 -d ":"`
	echo $val
}

function port_stats_check()
{
	testpmd_cmd $CAP_PRFX "show port stats 0"
	sleep 1
	# Show log till now
	start_ts=`date +%s`
	start_ts=$((start_ts + 60))
	tx_count=`capture_count`
	while [[ $tx_count -lt $1 ]]
	do
		OFF=`testpmd_log_sz $CAP_PRFX`
		testpmd_cmd $CAP_PRFX "show port stats 0"
		sleep 1
		ts=`date +%s`
		tx_count=`capture_count`
		if (( $ts > $start_ts ))
		then
			echo "Timeout unable to send $1 packets"
			cleanup_interface
			exit 1
		fi
	done
	OFF=`testpmd_log_sz $CAP_PRFX`
}

#Port TX ~2 Gbps, Q0=> 100% and no change in Q1-7 stats
function verify_case_1()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSX
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		q1=`queue_stats 2`
		q2=`queue_stats 3`
		q3=`queue_stats 4`
		q4=`queue_stats 5`
		q5=`queue_stats 6`
		q6=`queue_stats 7`
		q7=`queue_stats 8`
		if [[ $q0 -gt $QCNT_UP && $q1 -lt $QCNT_DOWN &&
		       	$q2 -lt $QCNT_DOWN && $q3 -lt $QCNT_DOWN &&
		       	$q4 -lt $QCNT_DOWN && $q5 -lt $QCNT_DOWN &&
		       	$q6 -lt $QCNT_DOWN && $q7 -lt $QCNT_DOWN ]]
		then
			echo "TM test-1 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-1 Failed"
	cleanup_interface
	exit 1
}

#Port TX ~2 Gbps, Q0-5 => 0% and packet count on Q6-7 stats
function verify_case_2()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSX
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		q1=`queue_stats 2`
		q2=`queue_stats 3`
		q3=`queue_stats 4`
		q4=`queue_stats 5`
		q5=`queue_stats 6`
		q6=`queue_stats 7`
		if [[ $q0 -lt $QCNT_DOWN && $q1 -lt $QCNT_DOWN &&
			$q2 -lt $QCNT_DOWN && $q3 -lt $QCNT_DOWN &&
			$q4 -lt $QCNT_DOWN && $q5 -gt $QCNT_UP &&
			$q6 -gt $QCNT_UP ]]
		then
			echo "TM test-2 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-2 Failed"
	cleanup_interface
	exit 1
}

#Port TX ~2 Gbps, Q0-6 => 0% and packet count on Q7 stats
function verify_case_3()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSX
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		q1=`queue_stats 2`
		q2=`queue_stats 3`
		q3=`queue_stats 4`
		q4=`queue_stats 5`
		q5=`queue_stats 6`
		if [[ $q0 -lt $QCNT_DOWN && $q1 -lt $QCNT_DOWN &&
			$q2 -lt $QCNT_DOWN && $q3 -lt $QCNT_DOWN &&
			$q4 -lt $QCNT_DOWN && $q5 -gt $QCNT_UP ]]
		then
			echo "TM test-3 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-3 Failed"
	cleanup_interface
	exit 1
}

#Port TX ~2 Gbps, Q0,6,7 => 0% and packet count on Q1:2:3:4:5 should be
#1:16:64:255:1 stats
function verify_case_4()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSX
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		q1=`queue_stats 2`
		q2=`queue_stats 3`
		q3=`queue_stats 4`
		q4=`queue_stats 5`
		q116=$((q0*16*percentage/100))
	        q164=$((q0*64*percentage/100))
		q1255=$((q0*255*percentage/100))
		q11=$((q0*percentage/100))
		#This case is to verify scaling of queue count, queue0 count
	        #with very few packets (QCNT_DOWN) will be considered as success
		if [[ $q0 -gt $QCNT_DOWN && $q1 -gt $q116 && $q2 -gt $q164 &&
			$q3 -gt $q1255 && $q4 -gt $q11 ]]
		then
			echo "TM test-4 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-4 Failed"
	cleanup_interface
	exit 1
}

#Port TX ~1 Gbps, Q0-5,7 => 0% and packet count on Q6 stats
function verify_case_5()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSY
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		if [[ $q0 -gt $QCNT_UP ]]
		then
			echo "TM test-5 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-5 Failed"
	cleanup_interface
	exit 1
}

#Port TX ~2 Gbps, Q0-5 => 0% and packet count on Q6:7 => 1:3 stats
function verify_case_6()
{
	i=0
	OFF=`testpmd_log_sz $CAP_PRFX`
	port_stats_check $BPSX
	while [[ $i -lt $retry_cnt ]]
	do
		testpmd_cmd $CAP_PRFX "show fwd stats all"
		sleep 1
		q0=`queue_stats 1`
		q1=`queue_stats 2`
		q63=$((q0*3*percentage/100))
		if [[ $q0 -gt $QCNT_UP && $q1 -gt $q63 ]]
		then
			echo "TM test-6 PASSED"
			OFF=`testpmd_log_sz $CAP_PRFX`
			return
		fi
		OFF=`testpmd_log_sz $CAP_PRFX`
		i=$((i+1))
	done
	echo "TM test-6 Failed"
	cleanup_interface
	exit 1
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

echo "Testpmd running with $PORT0, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0" \
	"--nb-cores=$CORES --rxq=4 --txq=4 --forward-mode=flowgen --txonly-multi-flow --txpkts=256 -i"

testpmd_cmd $PRFX "start"

# Launch capture testpmd
testpmd_launch $CAP_PRFX \
	"-c $CAP_COREMASK -a $CAP_PORT0 -a $CAP_PORT1" \
        "--rxq=8 --txq=8 --nb-cores=$CORES --rss-udp --no-flush-rx -i"

# Start capturing
#2Gbps PIR
testpmd_cmd $CAP_PRFX "add port tm node shaper profile 0 2000 0 0 250000000 2500 0 0"
#1Gbps PIR
testpmd_cmd $CAP_PRFX "add port tm node shaper profile 0 1000 0 0 125000000 2500 0 0"
#L0_TL2_*
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 200 -1 0 100 0 2000 1 0 0"
#L1_TL3_*
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 300 200 0 0 1 2000 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 301 200 1 0 1 2000 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 302 200 1 0 1 2000 1 0 0"
#L2_TL4_*
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 400 302 0 0 2 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 401 301 0 0 2 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 402 300 0 0 2 -1 1 0 0"
#L3_SMQ_*
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 500 402 0 0 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 507 400 0 0 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 501 400 1 1 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 502 400 1 16 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 503 400 1 64 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 504 400 1 255 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 505 400 1 1 3 -1 1 0 0"
testpmd_cmd $CAP_PRFX "add port tm nonleaf node 0 506 401 0 0 3 -1 1 0 0"
#L4_TXQ_*
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 0 500 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 1 501 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 2 502 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 3 503 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 4 504 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 5 505 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 6 506 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "add port tm leaf node 0 7 507 0 100 4 0 0 0 0 0"
testpmd_cmd $CAP_PRFX "port tm hierarchy commit 0 yes"

testpmd_cmd $CAP_PRFX "port stop 1"
testpmd_cmd $CAP_PRFX "set flow_ctrl rx off 1"
testpmd_cmd $CAP_PRFX "set flow_ctrl tx off 1"
testpmd_cmd $CAP_PRFX "port start 1"

testpmd_cmd $CAP_PRFX "start"

sleep 3
# Show log till now
#testpmd_log_off $CAP_PRFX $OFF
OFF=`testpmd_log_sz $CAP_PRFX`

#Check case_1 results
verify_case_1

testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port 0 txq 0 stop"
testpmd_cmd $CAP_PRFX "start"

#Check case_2 results
verify_case_2

testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port 0 txq 6 stop"
testpmd_cmd $CAP_PRFX "start"

#Check case_3 results
verify_case_3

testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port 0 txq 7 stop"
testpmd_cmd $CAP_PRFX "start"

#Check case_3 results
verify_case_4

testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port 0 txq 1 stop"
testpmd_cmd $CAP_PRFX "port 0 txq 2 stop"
testpmd_cmd $CAP_PRFX "port 0 txq 3 stop"
testpmd_cmd $CAP_PRFX "port 0 txq 4 stop"
testpmd_cmd $CAP_PRFX "port 0 txq 5 stop"
testpmd_cmd $CAP_PRFX "port 0 txq 6 start"
testpmd_cmd $CAP_PRFX "start"

#Check case_5 results
verify_case_5

testpmd_cmd $CAP_PRFX "stop"
testpmd_cmd $CAP_PRFX "port 0 txq 7 start"
#set port tm node shaper profile <port_id> <node_id> <shaper_profile_id>
testpmd_cmd $CAP_PRFX "set port tm node shaper profile 0 301 2000"
#set port tm node parent <port_id> <node_id> <parent_node_id> <priority>
#<weight>
testpmd_cmd $CAP_PRFX "set port tm node parent 0 301 200 1 5"
testpmd_cmd $CAP_PRFX "set port tm node parent 0 302 200 1 15"
testpmd_cmd $CAP_PRFX "start"

#Check case_6 results
verify_case_6

#
## Show log till now
#testpmd_log_off $CAP_PRFX $OFF
#OFF=`testpmd_log_sz $CAP_PRFX`

testpmd_cmd $CAP_PRFX "stop"

testpmd_quit $CAP_PRFX
testpmd_cleanup $CAP_PRFX



#Close Packet Generation only after all tests
testpmd_quit $PRFX
testpmd_cleanup $PRFX
#Bind interface back to kernel
cleanup_interface

echo "SUCCESS: testpmd TM test completed"
