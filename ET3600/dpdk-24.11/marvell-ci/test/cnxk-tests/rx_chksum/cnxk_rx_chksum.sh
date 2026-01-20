#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/testpmd/pktgen.env
source $CNXKTESTPATH/common/pcap/pcap.env

PRFX="rx-chksum"
TMP_DIR=/tmp/dpdk-$PRFX

PKTGEN_PCAP="$CNXKTESTPATH/rx_chksum/in.pcap"
TESTPMD_PORT="0002:01:00.1"
PKTGEN_PORT="0002:01:00.2"
PKTGEN_COREMASK="0x5"
TESTPMD_COREMASK="0x3"

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
	pktgen_cleanup
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

PACKET_CNT=$(pcap_packet_count $PKTGEN_PCAP)

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
	"--no-flush-rx --nb-cores=1"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "set verbose 1"
testpmd_cmd $PRFX "port config 0 rx_offload ipv4_cksum on"
testpmd_cmd $PRFX "port config 0 rx_offload udp_cksum on"
testpmd_cmd $PRFX "port config 0 rx_offload tcp_cksum on"
testpmd_cmd $PRFX "port config 0 rx_offload outer_ipv4_cksum on"
testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"

OFF=`testpmd_log_sz $PRFX`

pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $PKTGEN_PCAP
pktgen_start

# Wait for packets to be received
sleep 5

testpmd_log_off $PRFX $OFF | grep "ol_flags:" >rx_chksum.log

while IFS="" read -r p || [ -n "$p" ]
do
	if ! [[ $p =~ "BAD" ]]
	then
		echo $p
		echo "Error: BAD checksum packet not found"
		exit 1
	fi
done < rx_chksum.log

testpmd_cmd $PRFX "show port stats all"
pktgen_stats

testpmd_log $PRFX
pktgen_log

echo "SUCCESS: testpmd rx checksum offload test completed"
