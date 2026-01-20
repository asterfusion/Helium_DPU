#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# Verify TX VLAN and VLAN QinQ(double) offloads.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/pcap/pcap.env

PRFX="tx_vlan"
CAP_PRFX="tx_vlan_cap"
TMP_DIR=/tmp/dpdk_$PRFX

TX_PCAP="$CNXKTESTPATH/tx_vlan/in.pcap"
EXPECTED_VLAN_PCAP="$CNXKTESTPATH/$PRFX/expect_vlan.pcap"
EXPECTED_VLAN_QINQ_PCAP="$CNXKTESTPATH/$PRFX/expect_vlan_QinQ.pcap"
RECV_PCAP="recv.pcap"
PORT0="0002:01:00.1"
PORT1="--vdev net_pcap0,rx_pcap=$TX_PCAP"
CAP_PORT0="0002:01:00.2"
CAP_PORT1="--vdev net_pcap0,tx_pcap=$TMP_DIR/for-$RECV_PCAP"
COREMASK="0x3"
CAP_COREMASK="0xc"
OFF=0

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

	testpmd_cmd $PRFX "port start all"
	testpmd_cmd $PRFX "start"
}

function stop_capture()
{
	testpmd_cmd $PRFX "stop"
	testpmd_cmd $PRFX "port stop all"
	testpmd_cmd $PRFX "clear port stats all"

	testpmd_cmd $CAP_PRFX "stop"
	testpmd_cmd $CAP_PRFX "port stop all"
	testpmd_cmd $CAP_PRFX "clear port stats all"

	cp $TMP_DIR/for-$RECV_PCAP $TMP_DIR/$RECV_PCAP
}

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

$VFIO_DEVBIND -b vfio-pci $PORT0 $CAP_PORT0

tcpdump -nr $EXPECTED_VLAN_PCAP -e -t >$TMP_DIR/expect_vlan.txt
tcpdump -nr $EXPECTED_VLAN_QINQ_PCAP -e -t >$TMP_DIR/expect_vlan_QinQ.txt

echo "Testpmd running with $PORT0, $PORT1, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0	$PORT1" \
	"--no-flush-rx --nb-cores=1 --forward-mode=mac --no-flush-rx"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "mac_addr set 0 02:00:00:00:00:01"
testpmd_cmd $PRFX "set fwd mac"

echo "Testpmd running with $CAP_PORT0, $CAP_PORT1, Coremask=$CAP_COREMASK"
# Launch capture testpmd
testpmd_launch $CAP_PRFX \
		"-c $CAP_COREMASK -a $CAP_PORT0 $CAP_PORT1" \
		"--no-flush-rx --nb-cores=1 --forward-mode=io"
testpmd_cmd $CAP_PRFX "mac_addr set 0 02:00:00:00:00:02"
testpmd_cmd $CAP_PRFX "port stop all"

#VLAN insert
echo "Vlan insert:"
testpmd_cmd $PRFX "port config 0 tx_offload vlan_insert on"
testpmd_cmd $PRFX "tx_vlan set 0 99"

#Start capturing
start_capture

sleep 1

#Stop capturing
stop_capture

#confirm vlan header is present
tcpdump -nr $TMP_DIR/$RECV_PCAP -e -t > $TMP_DIR/recv.txt
diff -sqad $TMP_DIR/recv.txt $TMP_DIR/expect_vlan.txt

#VLAN QinQ insert
echo "Vlan QinQ insert:"
testpmd_cmd $PRFX "port config 0 tx_offload qinq_insert on"
testpmd_cmd $PRFX "tx_vlan set 0 99 88"

#Start capturing
start_capture

sleep 1

#Stop capturing
stop_capture

#confirm vlan QinQ header is present
tcpdump -nr $TMP_DIR/$RECV_PCAP -e -t > $TMP_DIR/recv.txt
diff -sqad $TMP_DIR/recv.txt $TMP_DIR/expect_vlan_QinQ.txt

echo "SUCCESS: tx_vlan test case completed"
