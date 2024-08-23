#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.
set -eou pipefail
CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
source $CNXKTESTPATH/common/testpmd/common.env
IF0=${IF0:-0002:02:00.0}
PRFX="event_perf"
PLAT=${PLAT:?}

trap "cleanup $?" EXIT

cleanup()
{
	if [[ $1 -ne 0 ]]; then
		testpmd_cleanup $PRFX
	fi

	exit $1
}

launch_testpmd()
{
	local fwd_cores=$(($(grep -c ^processor /proc/cpuinfo) - 1))

	# Limit the number forwarding cores on cn9/10k.
	# Tx rate peaks (99 MPPS) after 10 cores and drop after 18.
	fwd_cores=$(( fwd_cores < 12 ? fwd_cores : 12 ))

	testpmd_launch $PRFX \
		"-l 0-$fwd_cores -a $IF0" \
		"--nb-cores=$fwd_cores --rxq=$fwd_cores --txq=$fwd_cores \
		--forward-mode=flowgen --flowgen-flows=100" \
		</dev/null 2>/dev/null &
	sleep 1
	testpmd_cmd $PRFX "port stop 0"
	testpmd_cmd $PRFX "set flow_ctrl rx off 0"
	testpmd_cmd $PRFX "set flow_ctrl tx off 0"
	testpmd_cmd $PRFX "port start 0"

}

case $TESTPMD_OP in
	launch)
		launch_testpmd
		;;
	start)
		testpmd_cmd $PRFX "start tx_first 64"
		;;
	stop)
		testpmd_cmd $PRFX "stop";;
	rx_pps)
		testpmd_cmd $PRFX "show port stats all"
		sleep 5
		testpmd_cmd $PRFX "show port stats all"
		val=`testpmd_log $PRFX | tail -4 | grep -ao 'Rx-pps: .*' \
			| awk -e '{print $2}'`
		echo $val
		;;
	cleanup)
		testpmd_cleanup $PRFX;;
esac
