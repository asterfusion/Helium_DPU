#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

# This script verifies multi-mempool capability by sending two
# packets with one packet size 128B and the other with 4496B.
#
# Here, two pools are created with sizes, 6000B & 3000B, allowing
# PMD to configure LPB with 5000B  and SPB with 3000B.
#
# Multiple mempool test case will be successful when 128B packet is
# allocated from SPB pool and 4496B packet from LPB pool.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/pcap/pcap.env

PRFX="mempool"
CAP_PRFX="mempool_cap"

TX_PCAP="$CNXKTESTPATH/multi_mempool/in.pcap"
RECV_PCAP="recv.pcap"
PORT0="0002:01:00.1"
PORT1="--vdev net_pcap0,rx_pcap=$TX_PCAP"
INLINE_DEV="0002:1d:00.0"
PORT2="-a $INLINE_DEV"
CAP_PORT0="0002:01:00.2"
COREMASK="0x3"
CAP_COREMASK="0xc"
OFF=0

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
		testpmd_log_off $CAP_PRFX $OFF
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
	testpmd_cmd $CAP_PRFX "set verbose 9"
	testpmd_cmd $CAP_PRFX "port start all"
	testpmd_cmd $CAP_PRFX "start"

	testpmd_cmd $PRFX "set verbose 9"
	testpmd_cmd $PRFX "port start all"
	testpmd_cmd_refresh $PRFX "start"
}

function stop_capture()
{
	testpmd_cmd $PRFX "stop"
	testpmd_cmd $PRFX "port stop all"

	testpmd_cmd $CAP_PRFX "stop"
	testpmd_cmd $CAP_PRFX "port stop all"
}

echo "Testpmd running with $PORT0, $PORT1, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0	$PORT1" \
	"--nb-cores=1 --no-flush-rx --max-pkt-len=9600"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "stop"

echo "Testpmd running with $CAP_PORT0, Coremask=$CAP_COREMASK"
# Here, LPB pool is going to be the first pool, mb_pool_0, and
# the second pool, mb_pool_0_1, is going to be SPB pool.
testpmd_launch $CAP_PRFX \
		"-c $CAP_COREMASK -a $CAP_PORT0" \
		"--portmask=1 --nb-cores=1 --no-flush-rx --mbuf-size 6000,3000 --max-pkt-len=9600 --multi-rx-mempool"

testpmd_cmd $CAP_PRFX "port stop all"
testpmd_cmd $CAP_PRFX "stop"

echo "start capture"
#Start capturing
start_capture

sleep 2

echo "stop capture"
#Stop capturing
stop_capture

#confirm large packet came from LPB and small packet from SPB
#first rx packet
spb_pool=`testpmd_log_off $CAP_PRFX $OFF | grep -ao ".* - Receive" \
	 | grep -ao -m 1 "pool=.* " | cut -d " " -f 1 \
	 | cut -d "=" -f 2`

len1=`testpmd_log_off $CAP_PRFX $OFF | grep -ao ".* - Receive" \
     | grep -ao -m 1 "length=.* " | cut -d " " -f 1 \
     | cut -d "=" -f 2`

#second rx packet
lpb_pool=`testpmd_log_off $CAP_PRFX $OFF | grep -ao ".* - Receive" \
	 | grep -ao -m 2  "pool=.* " | tail -n 1 | cut -d " " -f 1 \
	 | cut -d "=" -f 2`

len2=`testpmd_log_off $CAP_PRFX $OFF | grep -ao ".* - Receive" \
     | grep -ao -m 3 "length=.* " | tail -n 1 | cut -d " " -f 1 \
     | cut -d "=" -f 2`

echo "lpb:$lpb_pool lpb-len:$len2 spb:$spb_pool spb-len:$len1"

if [[ $spb_pool != "mb_pool_0_1" ]] || [[ $lpb_pool != "mb_pool_0" ]]
then
	echo "FAILURE: packets assigned from invali pools"
	exit 1
fi

echo "SUCCESS: Multiple mempool test case completed!"
