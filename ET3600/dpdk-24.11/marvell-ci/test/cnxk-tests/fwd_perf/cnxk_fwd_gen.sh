#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

TEST_OP=${TEST_OP:-}
set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

PRFX="fwd-gen"
PORT0="${PORT0:-0002:02:00.0}"
PLAT=${PLAT:?}

if [ -f $1/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$1/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(find $1 -iname oxk-devbind-basic.sh)
fi

function sig_handler()
{
        local status=$?
        set +e
        trap - ERR
        trap - INT
        if [[ $status -ne 0 ]]; then
                echo "$1 Handler"
                # Dump error logs
                testpmd_log $PRFX
        fi

        testpmd_cleanup $PRFX
        exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT

case $TEST_OP in
	launch)
		$VFIO_DEVBIND -b vfio-pci $PORT0
		num_cores=$(grep -c ^processor /proc/cpuinfo)
		((num_cores-=1))
		num_cores=${GEN_CORES:-$num_cores}
		((fwd_cores=num_cores-1))

		# Limit the number forwarding cores on cn10k.
		# Tx rate peaks (99 MPPS) after 10 cores and drop after 18.
		if [[ $PLAT == "cn10k" ]]; then
			fwd_cores=$(( fwd_cores < 12 ? fwd_cores : 12 ))
		fi

		testpmd_launch $PRFX \
			"-l 1-$num_cores -a $PORT0" \
			"--no-flush-rx --nb-cores=$fwd_cores --forward-mode=flowgen \
			-i --txq=$fwd_cores --rxq=$fwd_cores \
			--tx-ip 1.1.1.1,198.18.0.1" </dev/null 2>/dev/null
		testpmd_cmd $PRFX "port stop 0"
		testpmd_cmd $PRFX "set flow_ctrl rx off 0"
		testpmd_cmd $PRFX "set flow_ctrl tx off 0"
		testpmd_cmd $PRFX "port start 0"
		;;
	launch_basic)
		$VFIO_DEVBIND -b vfio-pci $PORT0
		num_cores=$(grep -c ^processor /proc/cpuinfo)
		((num_cores-=1))
		num_cores=${GEN_CORES:-$num_cores}
		((fwd_cores=num_cores-1))

		# Limit the number forwarding cores on cn10k.
		# Tx rate peaks (99 MPPS) after 10 cores and drop after 18.
		if [[ $PLAT == "cn10k" ]]; then
			fwd_cores=$(( fwd_cores < 12 ? fwd_cores : 12 ))
		fi

		testpmd_launch $PRFX \
			"-l 1-$num_cores -a $PORT0" \
			"--no-flush-rx --nb-cores=$fwd_cores \
			-i" </dev/null 2>/dev/null
		testpmd_cmd $PRFX "port stop 0"
		testpmd_cmd $PRFX "set flow_ctrl rx off 0"
		testpmd_cmd $PRFX "set flow_ctrl tx off 0"
		testpmd_cmd $PRFX "port start 0"
		;;
	start)
		testpmd_cmd $PRFX "start tx_first 256"
		testpmd_cmd $PRFX "show port stats all"
		;;
	stop)
		testpmd_cmd $PRFX "show port stats all"
		testpmd_cmd $PRFX "stop"
		;;
	rx_pps)
		testpmd_cmd $PRFX "show port stats all"
		val=`testpmd_log $PRFX | tail -4 | grep -ao 'Rx-pps: .*' | \
		    awk -e '{print $2}'`
		echo $val
		;;
	tx_pps)
		testpmd_cmd $PRFX "show port stats all"
			cut -f 2 -d ":"
		val=`testpmd_log $PRFX | tail -4 | grep -ao 'Tx-pps: .*' | \
		    awk -e '{print $2}'`
		echo $val
		;;
	cleanup)
		testpmd_cleanup $PRFX
		;;
	log)
		testpmd_log $PRFX
		;;
esac

exit 0
