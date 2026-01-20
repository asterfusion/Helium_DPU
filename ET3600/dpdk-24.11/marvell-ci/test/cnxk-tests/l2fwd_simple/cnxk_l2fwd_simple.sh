#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

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
	pktgen_quit
	pktgen_cleanup
	lbk_quit
	lbk_cleanup
	exit $status
}

PKTGEN_PCAP="in.pcap"
PKTGEN_PORT="0002:01:00.1"
PKTGEN_COREMASK="0x5"
L2FWD_PORT="0002:01:00.2"
L2FWD_COREMASK="0x3"

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

PCAP_CNT=$(pcap_packet_count $PKTGEN_PCAP)
PCAP_LEN=$(pcap_length $PKTGEN_PCAP)

echo "Starting l2fwd with Port=$L2FWD_PORT, Coremask=$L2FWD_COREMASK"
lbk_launch -c $L2FWD_COREMASK -p $L2FWD_PORT
lbk_start
echo "Starting pktgen with Port=$PKTGEN_PORT, Coremask=$PKTGEN_COREMASK, Pcap=$PKTGEN_PCAP"
pktgen_launch -c $PKTGEN_COREMASK -p $PKTGEN_PORT -i $PKTGEN_PCAP
pktgen_start

sleep 5

lbk_stats > /dev/null
pktgen_stats > /dev/null

echo "-------------------- L2FWD LOGS ---------------------"
lbk_log 'L2FWD'
echo "-------------------- PKTGEN LOGS --------------------"
pktgen_log

if [[ $(lbk_rx_count) -ne $PCAP_CNT ]] ||
   [[ $(lbk_tx_count) -ne $PCAP_CNT ]] ||
   [[ $(lbk_rx_bytes) -ne $PCAP_LEN ]] ||
   [[ $(lbk_tx_bytes) -ne $PCAP_LEN ]]; then
	echo "FAILURE: Error in simple l2fwd"
	exit 1
fi

echo "SUCCESS: simple l2fwd completed"
