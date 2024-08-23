#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

#set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
PRFX="rte_flow_regr"

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
PKTGEN_OUTPCAP="out.pcap"

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

function testpmd_check_hits()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	testpmd_cmd $prefix "flow query 0 0 count"

	sleep 3
	testpmd_prompt $prefix
	COUNT=`cat $out | tail -n4 | grep "hits:" | cut -d':' -f2`

	echo -e "hit count:$COUNT \n"

	if [[ "$COUNT" -gt "0" ]]; then
		return 0
	fi

	return -1
}

function testpmd_enable_verbose()
{
	local prefix=$1

	testpmd_cmd $prefix "set verbose 1"

	testpmd_prompt $prefix
}

function testpmd_test_flow()
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

	echo "-------------------------TESTPMD LOG-----------------------------"
	testpmd_cmd $PRFX "show port stats all"
	testpmd_log $prefix
	sleep 3

	if testpmd_check_hits $1; then
		echo "$name passed"
		#Delete rule
		testpmd_cmd $prefix "flow destroy 0 rule 0"
		return 0
	else
		echo "$name failed"
		exit -1
	fi
}

function check_pkt_count()
{
	local pkt_filt_cmd=$1
	local expected_cnt=$2

	TCPDUMP_OUT=`$pkt_filt_cmd`

	PKTCOUNT=`echo $TCPDUMP_OUT | grep "packet" | cut -d' ' -f1`

	echo "packet count:$PKTCOUNT"

	if [[ "$PKTCOUNT" -ne "$expected_cnt" ]]; then
		echo "Expected:$expected_cnt, Found:$PKTCOUNT"
		return 1
	fi

	return 0
}

function testpmd_check_mark_flag()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	COUNT=`cat $out | grep "RTE_MBUF_F_RX_FDIR" | wc -l`

	echo "MARK Flag occurrence count:" $COUNT

	if [[ "$COUNT" -gt "0" ]]; then
		return 0
	fi

	return -1
}

function testpmd_check_mark_id()
{
	local prefix=$1
	local out=testpmd.out.$prefix
	local markid=$2

	ID_COUNT=`cat $out | grep "FDIR matched ID=$markid" | wc -l`
	COUNT=`cat $out | grep "RTE_MBUF_F_RX_FDIR_ID" | wc -l`

	echo "MARKID occurrence count:" $COUNT

	if [[ "$COUNT" -gt "0" && "$COUNT" -eq "$ID_COUNT" ]]; then
		return 0
	fi

	return -1
}

function testpmd_check_vlan_flags()
{
	local prefix=$1
	local out=testpmd.out.$prefix

	COUNT=`cat $out | grep "RTE_MBUF_F_RX_VLAN_STRIPPED" | wc -l`

	echo "VLAN_STRIPPED occurrence count:" $COUNT

	if [[ "$COUNT" -gt "0" ]]; then
		return 0
	fi

	return -1
}

function testpmd_check_queue_index()
{
	local prefix=$1
	local out=testpmd.out.$prefix
	local queue_idx=$2

	QUEUE_ID_COUNT=`cat $out | grep "queue=$queue_idx" | wc -l`

	echo "queue occurrence count:" $QUEUE_ID_COUNT

	if [[ "$QUEUE_ID_COUNT" -gt "0" ]]; then
		return 0
	fi

	return -1
}


echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
		" -c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
		" --no-flush-rx --nb-cores=1 --rxq 8 --txq 8" \
		" --port-topology=loop"

testpmd_test_flow $PRFX FLOW_ETH "flow create 0 ingress pattern eth dst is \
 aa:bb:cc:dd:ee:ff / end actions queue index 3 / \
 count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_VLAN "flow create 0 ingress pattern vlan \
 vid is 0x123 inner_type is 0x800 / end actions queue index 3 / count \
 / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_IPV4_1 "flow create 0 ingress pattern ipv4 src \
 is 10.11.12.13 / end actions queue index 1 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_IPV4_2 "flow create 0 ingress pattern ipv4 src \
 is 10.11.12.13 dst is 10.10.10.10 / end actions queue index 1 / \
 count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_TCP "flow create 0 ingress pattern tcp src is \
 0x345 / end actions queue index 1 / count / end" "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_UDP "flow create 0 ingress pattern udp src is \
 0x345 / end actions queue index 2 / count / end" "pcap/eth_vlan_ipv4_udp.pcap"

testpmd_test_flow $PRFX FLOW_ALL "flow create 0 ingress pattern eth dst is \
 aa:bb:cc:dd:ee:ff  type is 0x800 / ipv4 src is 10.11.12.13 dst is 10.10.10.10 \
 / tcp src is 0x345 / end actions queue index 1 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST1 "flow create 0 ingress pattern eth / \
 vlan / ipv4 / udp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_udp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST2 "flow create 0 ingress pattern eth / \
 vlan / ipv4 / tcp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

testpmd_test_flow $PRFX FLOW_LTYPE_TEST3 "flow create 0 ingress pattern eth / \
 vlan / ipv6 / tcp / end actions queue index 2 / count / end" \
 "pcap/eth_vlan_ipv6_tcp.pcap"

VID1=0xBAD
VID2=0xABC
#---------------------------FLOW_ACTION_1VLAN_INSERT---------------------------

testpmd_test_flow $PRFX FLOW_ACTION_1VLAN_INSERT "flow create 0 egress pattern \
 eth / end actions of_push_vlan ethertype 0x88A8 / of_set_vlan_pcp vlan_pcp 3 \
 / of_set_vlan_vid vlan_vid $VID1 / count / end" \
 "pcap/eth_ipv4_tcp.pcap"

TCPDUMP_CMD="tcpdump --count -r ./$PKTGEN_OUTPCAP (vlan $VID1)"

if ! check_pkt_count "$TCPDUMP_CMD" 1; then
	echo FAILED
	exit 1
fi
echo "FLOW_ACTION_1VLAN_INSERT passed"

#---------------------------FLOW_ACTION_2VLAN_INSERT---------------------------

testpmd_test_flow $PRFX FLOW_ACTION_2VLAN_INSERT "flow create 0 egress pattern \
 eth / end actions of_push_vlan ethertype 0x88A8 / of_set_vlan_pcp vlan_pcp 3 \
 / of_set_vlan_vid vlan_vid $VID1 / of_set_vlan_vid vlan_vid $VID2 / \
 of_push_vlan ethertype 0x8100 / of_set_vlan_pcp vlan_pcp 4 / count / end" \
 "pcap/eth_ipv4_tcp.pcap"

TCPDUMP_CMD="tcpdump --count -r ./$PKTGEN_OUTPCAP (vlan $VID1 and vlan $VID2)"

if ! check_pkt_count "$TCPDUMP_CMD" 1; then
	echo FAILED
	exit 1
fi
echo "FLOW_ACTION_2VLAN_INSERT passed"

testpmd_enable_verbose $PRFX
#---------------------------FLOW_ACTION_VLAN_STRIP-----------------------------

testpmd_test_flow $PRFX FLOW_VLAN_POP "flow create 0 ingress pattern ipv4 src \
 is 10.11.12.13  / end actions of_pop_vlan / queue index 0 / count / end" \
 "pcap/eth_vlan_ipv4_tcp.pcap"

#Note: "(host 10.11.12.13)" will not match if a vlan is present.
#Expression to match vlan and an IPv4 address is "(vlan and host 10.11.12.13)".
TCPDUMP_CMD="tcpdump --count -r ./$PKTGEN_OUTPCAP ( host 10.11.12.13 )"
if ! check_pkt_count "$TCPDUMP_CMD" 1; then
	echo "FAILED: vlan stripped packet not found"
	exit 1
fi

if ! testpmd_check_vlan_flags $PRFX; then
	echo "FAILED: ol_flags VLAN_STRIPPED not set"
	exit 1
fi

echo "FLOW_ACTION_VLAN_STRIP passed"

#---------------------------FLOW_ACTION_FLAG-----------------------------------
testpmd_test_flow $PRFX FLOW_FLAG "flow create 0 ingress pattern ipv4 src is \
 10.11.12.13 / end actions flag / queue index 0 / count / end" \
 "pcap/eth_ipv4_tcp.pcap"

if ! testpmd_check_mark_flag $PRFX; then
	echo "FAILED: mark not set in ol_flags"
	exit 1
fi
echo "FLOW_ACTION_FLAG passed"

#---------------------------FLOW_ACTION_MARK-----------------------------------
MARKID=0xdead

testpmd_test_flow $PRFX FLOW_MARK "flow create 0 ingress pattern ipv4 src is \
 10.11.12.13 / end actions mark id $MARKID / queue index 0 / count / end" \
 "pcap/eth_ipv4_tcp.pcap"

if ! testpmd_check_mark_id $PRFX $MARKID; then
	echo "FAILED: mark not set in ol_flags"
	exit 1
fi

echo "FLOW_ACTION_MARK passed"

#---------------------------FLOW_ACTION_QUEUE-----------------------------------
QUEUE_ID=0x3

testpmd_test_flow $PRFX FLOW_QUEUE "flow create 0 ingress pattern ipv4 src is \
 10.11.12.13 / end actions  queue index $QUEUE_ID / count / end" \
 "pcap/eth_ipv4_tcp.pcap"

if ! testpmd_check_queue_index $PRFX $QUEUE_ID; then
	echo "FAILED: incorrect queue"
	exit 1
fi

echo "FLOW_ACTION_QUEUE passed"


testpmd_quit  $PRFX
echo "SUCCESS: flow regression tests completed"
exit 0
