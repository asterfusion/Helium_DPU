#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

echo $CNXKTESTPATH

source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/pcap/pcap.env

if [[ -f $CNXKTESTPATH/../../../app/dpdk-proc-info ]]; then
	# This is running from build directory
	TESTDPDK=$CNXKTESTPATH/../../../app/dpdk-proc-info
elif [[ -f $CNXKTESTPATH/../../../dpdk-proc-info ]]; then
	# This is running from install directory
	TESTDPDK=$CNXKTESTPATH/../../../dpdk-proc-info
else
	TESTDPDK=$(which dpdk-proc-info)
fi

if [[ -z $TESTDPDK ]]; then
	echo "dpdk-proc-info not found !!"
	exit 1
fi

PRFX="txrx-stats"
CAP_PRFX="txrx-stats-cap"
TMP_DIR=/tmp/dpdk-$PRFX

TX_PCAP="$CNXKTESTPATH/txrx_stats/in.pcap"
EXPECTED_PCAP="$CNXKTESTPATH/txrx_stats/out.pcap"
RECV_PCAP="recv.pcap"
PORT0="0002:01:00.1"
PORT1="--vdev net_pcap0,rx_pcap=$TX_PCAP"
INLINE_DEV="0002:1d:00.0"
PORT2="-a $INLINE_DEV"
CAP_PORT0="0002:01:00.2"
CAP_PORT1="--vdev net_pcap0,tx_pcap=$TMP_DIR/for-$RECV_PCAP"
COREMASK="0x3"
CAP_COREMASK="0xc"
OFF=0

PROC_CMD="$TESTDPDK -a $PORT0 $PORT1 $PORT2 --file-prefix $PRFX"
APP_LOG=proc_info.$PRFX.log
rm -f $APP_LOG
rm -rf $TMP_DIR
mkdir -p $TMP_DIR

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
		# Dump error logs
		testpmd_log_off $PRFX $OFF
	fi

	testpmd_cleanup $PRFX
	testpmd_cleanup $CAP_PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function start_capture()
{
	rm -rf $TMP_DIR/for-$RECV_PCAP
	rm -rf $TMP_DIR/$RECV_PCAP
	testpmd_cmd $CAP_PRFX "port start all"
	testpmd_cmd $CAP_PRFX "start"
}

function capture_count()
{
	testpmd_cmd $CAP_PRFX "show port stats 1"
	val=`testpmd_log $CAP_PRFX | tail -7 | grep -ao "TX-packets: [0-9]*"| \
		cut -f 2 -d ":"`
	echo $val
}

function stop_capture()
{
	testpmd_cmd $CAP_PRFX "stop"
	testpmd_cmd $CAP_PRFX "port stop all"
	testpmd_cmd $CAP_PRFX "clear port stats all"

	cp $TMP_DIR/for-$RECV_PCAP $TMP_DIR/$RECV_PCAP
}

function run_app()
{
	eval "nohup $1 >> $APP_LOG 2>&1 &"

	# Wait until the process is completed
	while (ps -ef | grep dpdk-proc-info | grep -q $PRFX); do
		continue
	done
}

tcpdump -nr $TX_PCAP -xvve -t >$TMP_DIR/sent.txt
tcpdump -nr $EXPECTED_PCAP -xvve -t >$TMP_DIR/expect.txt

EXPECTED_CNT=$(pcap_packet_count $EXPECTED_PCAP)

echo "Testpmd running with $PORT0, $PORT1, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0	$PORT1 $PORT2" \
	"--no-flush-rx --nb-cores=1 "

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "set verbose 2"

# Launch capture testpmd
testpmd_launch $CAP_PRFX \
	"-c $CAP_COREMASK -a $CAP_PORT0 $CAP_PORT1" \
        "--no-flush-rx --nb-cores=1 --forward-mode=io"
testpmd_cmd $CAP_PRFX "port stop all"

# Start capturing
start_capture

testpmd_cmd $PRFX "port start all"

# Show log till now
testpmd_log_off $PRFX $OFF
OFF=`testpmd_log_sz $PRFX`

testpmd_cmd_refresh $PRFX "start"
# Peek to start log as we don't want to see pkt logs now
testpmd_log_off $PRFX $OFF | head -32

# Wait for receiving all packets
start_ts=`date +%s`
start_ts=$((start_ts + 60))
count=`capture_count`
while [[ "$count" != "$EXPECTED_CNT" ]]
do
	sleep 0.1
	count=`capture_count`
	ts=`date +%s`
	if (( $ts > $start_ts ))
	then
		echo "Timeout waiting for all packets"
		exit 1
	fi

done

# Stop capturing
stop_capture

# Skip Dump testpmd log containing pkts
OFF=`testpmd_log_sz $PRFX`

testpmd_cmd $PRFX "stop"
testpmd_cmd $PRFX "port stop all"

testpmd_cmd $PRFX "show port stats all"
testpmd_cmd $PRFX "show port xstats 0"
run_app '$PROC_CMD -- --xstats-name tx_ucast'
run_app '$PROC_CMD -- --xstats-ids 1'
testpmd_cmd $PRFX "clear port stats all"
testpmd_cmd $PRFX "clear port xstats all"

sleep 2
# Dump testpmd log
testpmd_log_off $PRFX $OFF
OFF=`testpmd_log_sz $PRFX`

sleep 2
echo ""

XSTATS=`testpmd_log $PRFX | grep "Error: Unable to get xstats" || true`
if [ "$XSTATS" != "" ]
then
        exit 1
fi

val=`cat $APP_LOG | grep -a "tx_ucast:" || true`
if [ "$val" == "" ]
then
	echo "xstats ID by name is failed"
	exit 1
fi
echo "[dpdk-proc-info: ID number of xstats name] $val"
val=`cat $APP_LOG | grep -a "tx_good_packets:" || true`
if [ "$val" == "" ]
then
	echo "xstats count value from ID is failed"
	exit 1
fi
echo "[dpdp-proc-info: xstats count of ID 1] $val"

echo "SUCCESS: testpmd tx-rx stats test completed"
