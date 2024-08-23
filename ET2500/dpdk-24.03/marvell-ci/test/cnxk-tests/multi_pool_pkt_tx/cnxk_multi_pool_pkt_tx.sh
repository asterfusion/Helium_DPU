#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -e

BINARY=cnxk-multi_pool_pkt_tx

if [[ ! -f $BINARY ]]; then
	echo "$BINARY not found !!"
	exit 1
fi

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
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

RX_LOG=rx.txt
TX_LOG=tx.txt
MAX_PKTS=1024
NUM_SEGS=6
SCALAR_ENABLE=${1:-0}
TX_PREFIX=multi_pool_pkt_tx
RX_PREFIX=multi_pool_pkt_rx
PORT0=0002:01:00.1
PORT1=0002:01:00.2

function sig_handler()
{
	local signame=$1

	echo "#### SIGNAL HANDLER (SIG${signame}) ####"

	# Make sure that sig_handler is fully executed.
	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT
	trap - KILL
	trap - EXIT

	if [[ -f $RX_LOG ]]; then
		echo "================================"
		echo "RX LOG"
		echo "================================"
		cat $RX_LOG
	fi
	if [[ -f $TX_LOG ]]; then
		echo "================================"
		echo "TX LOG"
		echo "================================"
		cat $TX_LOG
	fi

	exit 1
}

trap "sig_handler INT" INT
trap "sig_handler TERM" TERM
trap "sig_handler ERR" ERR
trap "sig_handler QUIT" QUIT
trap "sig_handler KILL" KILL

rm -rf $RX_LOG
rm -rf $TX_LOG
rm -rf /var/run/dpdk/$RX_PREFIX
rm -rf /var/run/dpdk/$TX_PREFIX

$VFIO_DEVBIND -b vfio-pci $PORT0
$VFIO_DEVBIND -b vfio-pci $PORT1

echo "================================"
if [[ "$SCALAR_ENABLE" == "0" ]]; then
	echo "Running VECTOR Tx Test"
else
	echo "Running SCALAR Tx Test"
fi
echo "================================"

echo "================================"
echo "Starting RX"
echo "================================"
(stdbuf -o 0 ./$BINARY \
	--file-prefix $RX_PREFIX \
	-c 0x3 \
	-a $PORT1 \
	-- \
	--max-pkts $MAX_PKTS \
	--rx 2>&1) > $RX_LOG &

while [[ ! -f $RX_LOG ]]; do
	echo "Waiting for RX log"
	sleep 1
	continue
done

while ! $(grep -q "Total RX Pkts" $RX_LOG); do
	echo "Waiting for RX to be ready to receive"
	sleep 1
	continue
done

echo "================================"
echo "Starting TX"
echo "================================"
(./$BINARY \
	--file-prefix $TX_PREFIX \
	-c 0x5 \
	-a $PORT0,scalar_enable=$SCALAR_ENABLE \
	-- \
	--num-segs $NUM_SEGS \
	--max-pkts $MAX_PKTS 2>&1)  > $TX_LOG

echo "================================"
echo "Waiting for TX/RX to complete"
echo "================================"
wait

TX_PKTS=$(grep "Total TX Pkts" $TX_LOG | tail -n1 | awk '{print $4}')
RX_PKTS=$(grep "Total RX Pkts" $RX_LOG | tail -n1 | awk '{print $4}')

if [[ $TX_PKTS != $RX_PKTS ]] || [[ -z $TX_PKTS ]] || [[ -z $RX_PKTS ]] ; then
	echo "TX and RX Packets not matching \"$TX_PKTS\" != \"$RX_PKTS\""
	trap "sig_handler EXIT" EXIT
	exit 1
fi

echo "TEST SUCCESSFUL Rx=Tx $TX_PKTS=$RX_PKTS"
