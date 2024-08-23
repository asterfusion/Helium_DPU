#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

set -eou pipefail
CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
source $CNXKTESTPATH/common/testpmd/common.env

TX_PRFX="tpmd_tx"
RX_PRFX="tpmd_rx"
PORT0="${PORT0:-0002:02:00.0}"
PORT1="${PORT1:-0002:03:00.0}"

function sig_handler()
{
        local status=$?
        set +e
        trap - ERR
        trap - INT
        if [[ $status -ne 0 ]]; then
                echo "$1 Handler"
                # Dump error logs
                testpmd_log $TX_PRFX
                testpmd_log $RX_PRFX
        fi

        testpmd_cleanup $TX_PRFX
        testpmd_cleanup $RX_PRFX
        exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT

launch_testpmd_rx()
{
	#local out=testpmd.out.$1
	testpmd_launch $1 \
		"-c 0xfc -a $PORT1" \
		"--nb-cores=1 --forward-mode=rxonly" \
		</dev/null 2>/dev/null &
	sleep 1
	testpmd_cmd $1 "port stop 0"
	testpmd_cmd $1 "set flow_ctrl rx off 0"
	testpmd_cmd $1 "set flow_ctrl tx off 0"
	testpmd_cmd $1 "port start 0"
}

launch_testpmd_tx_outb()
{
	echo "launch_testpmd_tx_outb"
	testpmd_launch $1 \
		"-c 0xFC --vdev net_pcap0,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,infinite_rx=1 -a $PORT0 " \
		"--nb-cores=5 --txq=5 --rxq=5 --no-flush-rx" \
		</dev/null 2>/dev/null &
	sleep 1
	testpmd_cmd $1 "port stop 0"
	testpmd_cmd $1 "set flow_ctrl rx off 0"
	testpmd_cmd $1 "set flow_ctrl tx off 0"
	testpmd_cmd $1 "port start 0"
}

launch_testpmd_tx_inb()
{
	testpmd_launch $1 \
		"-c 0xFC --vdev net_pcap0,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,rx_pcap=$2,infinite_rx=1 -a $PORT0 " \
		"--nb-cores=5 --txq=5 --rxq=5 --no-flush-rx" \
		</dev/null 2>/dev/null &
	sleep 1
	testpmd_cmd $1 "port stop 0"
	testpmd_cmd $1 "set flow_ctrl rx off 0"
	testpmd_cmd $1 "set flow_ctrl tx off 0"
	testpmd_cmd $1 "port start 0"
}

case $TESTPMD_OP in
	launch_tx_outb)
		launch_testpmd_tx_outb $1 $2
		;;
	launch_tx_inb)
		launch_testpmd_tx_inb $1 $2
		;;
	launch_rx)
		launch_testpmd_rx $1
		;;
	start)
		testpmd_cmd $1 "start tx_first 64"
		testpmd_cmd $1 "show port stats all"
		;;
	stop)
		testpmd_cmd $1 "stop"
		;;
	rx_pps)
		prev=$(testpmd_log_sz $1)
		curr=$prev
		testpmd_cmd $1 "show port stats $2"

		while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $1); done
		testpmd_prompt $1
		val=`testpmd_log $1 | tail -4 | grep -ao 'Rx-pps: .*' | \
		    awk -e '{print $2}'`
		echo $val
		;;
	pktsize)
		testpmd_cmd $1 "set txpkts $2"
		;;
	quit)
		testpmd_quit $1
		;;
	log)
		testpmd_log $1
		;;
esac
exit 0
