#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -e

if [[ ! -f cnxk-extbuf ]]; then
	echo "cnxk-extbuf not found !!"
	exit 1
fi

RX_LOG=rx.txt
TX_LOG=tx.txt
TX_PREFIX=extbuf_tx
RX_PREFIX=extbuf_rx

rm -rf $RX_LOG
rm -rf $TX_LOG
rm -rf /var/run/dpdk/$RX_PREFIX
rm -rf /var/run/dpdk/$TX_PREFIX

echo "================================"
echo "Starting RX"
echo "================================"
(stdbuf -o 0 ./cnxk-extbuf \
	--file-prefix $RX_PREFIX \
	-c 0x3 \
	-a 0002:01:00.2 \
	-- \
	--max-pkts 100 \
	--rx 2>&1) > $RX_LOG &

while [[ ! -f $RX_LOG ]]; do
	echo "Waiting for RX log"
	sleep 1
	continue
done

sleep 5

echo "================================"
echo "Starting TX"
echo "================================"
(./cnxk-extbuf \
	--file-prefix $TX_PREFIX \
	-c 0x5 \
	-a 0002:01:00.1 \
	-- \
	--max-pkts 100 2>&1) > $TX_LOG

echo "================================"
echo "Waiting for RX to complete"
echo "================================"
wait

TX_PKTS=$(grep "Total TX Pkts" $TX_LOG | tail -n1 | awk '{print $4}')
RX_PKTS=$(grep "Total RX Pkts" $RX_LOG | tail -n1 | awk '{print $4}')

if [[ $TX_PKTS != $RX_PKTS ]] || [[ -z $TX_PKTS ]] || [[ -z $RX_PKTS ]] ; then
	echo "TX and RX Packets not matching \"$TX_PKTS\" != \"$RX_PKTS\""
	cat $RX_LOG
	cat $TX_LOG
	exit 1
fi

echo "EXTBUF TEST SUCCESSFUL Rx=Tx $TX_PKTS=$RX_PKTS"
