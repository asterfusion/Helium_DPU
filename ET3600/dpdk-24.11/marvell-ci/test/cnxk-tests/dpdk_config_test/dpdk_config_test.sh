#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="config-test"
TMP_DIR=/tmp/dpdk-$PRFX

TESTPMD_PORT="0002:01:00.1"
TESTPMD_COREMASK="0x3"

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
        NICVF="octeontx2-nicvf"
else
        NICVF="rvu_nicvf"
fi

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
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT


function port_bind_interface()
{
        $VFIO_DEVBIND -b vfio-pci $TESTPMD_PORT
}

function tx_rx_info()
{
        TX=`testpmd_log $1 | grep "Current number of TX queues:"`
        txqueue=$(awk -F' ' '{print $6}' <<< `echo $TX`)
        RX=`testpmd_log $1 | grep "Current number of RX queues:"`
        rxqueue=$(awk -F' ' '{print $6}' <<< `echo $RX`)

        if [ $txqueue == $rxqueue ]
        then
                echo "TX RX queue configuration is Success"
        else
                echo "TX RX queue configuration failed"
        fi

}

function get_rss_reta_info()
{
	rss=`testpmd_log $1 | grep "RSS RETA configuration:"`
	q_idx0=$(awk -F' ' '{print $6}' <<< `echo $rss`)
	q_idx1=$(awk -F' ' '{print $12}' <<< `echo $rss`)
	q_idx0=$(awk -F'=' '{print $2}' <<< `echo $q_idx0`)
	q_idx1=$(awk -F'=' '{print $2}' <<< `echo $q_idx1`)

	if (($q_idx0 == 0 && $q_idx1 == 1))
	then
		echo "RSS Reta Configuration Success"
	else
		echo "RSS Reta Configuration Failed"
	fi
}

function get_burst_mode()
{
	burst=`testpmd_log $1 | grep "Burst mode:"`
	mode=$(awk -F' ' '{print $3}' <<< `echo $burst`)

	if (($mode == "Vector" || $mode == "Scalar"))
	then
		echo "Burst mode Configuration Success"
	else
		echo "Burst mode Configuration Failed"
	fi
}

port_bind_interface $TESTPMD_PORT
sleep 1
echo "Testpmd running with $TESTPMD_PORT, Coremask=$TESTPMD_COREMASK"
testpmd_launch $PRFX \
	"-c $TESTPMD_COREMASK -a $TESTPMD_PORT" \
	"--no-flush-rx --nb-cores=1 --txq=2 --rxq=2"

testpmd_cmd $PRFX "show txq info 0 0"
testpmd_cmd $PRFX "show port info 0"
testpmd_cmd $PRFX "show port 0 rss reta 64 (0x3)"
testpmd_cmd $PRFX "port start all"
testpmd_cmd $PRFX "start"

# Wait for packets to be received
sleep 5

MODEL=`testpmd_log $PRFX | grep "RoC Model:"`
HW=$(awk '{split($0, array, " ", sep); print array[4];}' <<< `echo $MODEL`)

tx_rx_info $PRFX $HW
sleep 1
get_burst_mode $PRFX $HW
sleep 1
get_rss_reta_info $PRFX $HW
sleep 1
echo "TX RX queue, Burst Mode and RSS  configuration test completed"
