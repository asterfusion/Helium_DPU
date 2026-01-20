#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

#set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
PRFX="rte_flow_aging"

source $CNXKTESTPATH/common/testpmd/pktgen.env
source $CNXKTESTPATH/common/testpmd/lbk.env
source $CNXKTESTPATH/common/pcap/pcap.env

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

PKTGEN_PORT="0002:01:00.1"
PKTGEN_COREMASK="0x5"
TESTPMD_PORT="0002:01:00.2"
TESTPMD_COREMASK="0x3"

#trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function pktgen_send_flow()
{
	local pcapfile=$1

	echo "Starting pktgen with Port=$PKTGEN_PORT, Coremask=$PKTGEN_COREMASK, Pcap=$pcapfile"
	pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $pcapfile
	pktgen_start

	sleep 3

	pktgen_stats > /dev/null
	echo "-------------------------PKTGEN LOG-----------------------------"
	pktgen_log
}

function testpmd_check_aging()
{
	local prefix=$1
	local cnt=$2
	local out=testpmd.out.$prefix

	testpmd_cmd $prefix "flow aged 0"

	sleep 3
	testpmd_prompt $prefix
	COUNT=`cat $out | tail -n7 | grep "total aged flows:" | cut -d':' -f2`

	echo -e "Total aged flows:$COUNT \n"

	if [[ "$COUNT" -eq "$cnt" ]]; then
		return 0
	fi

	return -1
}

function testpmd_test_aging()
{
	local prefix=$1
	local name=$2
	local flow=$3
	local pcapfile=$4
	local in=testpmd.in.$prefix
	echo "$cmd" >> $in
	testpmd_prompt $prefix

	#Add rule
	testpmd_cmd $prefix "$flow"

	testpmd_cmd $prefix "start"

	pktgen_send_flow $pcapfile

	sleep 3

	pktgen_quit
	pktgen_cleanup

	sleep 40

	if testpmd_check_aging $prefix 1; then
		echo "$name passed"
		#Delete rule
		testpmd_cmd $prefix "flow destroy 0 rule 0"
		return 0
	else
		echo "$name failed"
		exit -1
	fi
}

function testpmd_test_aging_2flows()
{
	local prefix=$1
	local name=$2
	local flow1=$3
	local flow2=$4
	local pcapfile=$5
	local in=testpmd.in.$prefix
	echo "$cmd" >> $in
	testpmd_prompt $prefix

	#Add rule
	testpmd_cmd $prefix "$flow1"
	testpmd_cmd $prefix "$flow2"

	testpmd_cmd $prefix "start"

	pktgen_send_flow $pcapfile

	sleep 3

	pktgen_quit
	pktgen_cleanup

	sleep 40

	if testpmd_check_aging $prefix 2; then
		echo "$name passed"
		#Delete rule
		testpmd_cmd $prefix "flow destroy 0 rule 0"
		testpmd_cmd $prefix "flow destroy 0 rule 1"
		return 0
	else
		echo "$name failed"
		exit -1
	fi
}

echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
		" -c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
		" --no-flush-rx --nb-cores=1 --rxq 8 --txq 8" \
		" --port-topology=loop"

#---------------------------FLOW_AGING-----------------------------------------
testpmd_test_aging $PRFX FLOW_AGING "flow create 0 ingress pattern eth / \
 vlan / ipv4 / tcp / end actions age timeout 20 / queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_aging_2flows $PRFX FLOW_AGING "flow create 0 ingress pattern eth / \
 vlan / ipv4 / tcp / end actions age timeout 20 / queue index 2 / count / end" \
 "flow create 0 ingress pattern eth / vlan / ipv6 / tcp / end actions age \
 timeout 20 / queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_ipv6_tcp_2flows.pcap"

testpmd_quit $PRFX
echo "SUCCESS: flow aging test completed"
exit 0
