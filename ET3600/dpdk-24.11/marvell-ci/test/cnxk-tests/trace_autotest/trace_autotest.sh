#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

TRACE_DIR="$HOME/dpdk-traces"
TEST_TRACE_DIR="$TRACE_DIR/rte-*"
CNXK_EAL_ARGS+=" --trace=.* --trace-dir=$TRACE_DIR"

if [[ -f $SCRIPTPATH/../../../../app/test/dpdk-test ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/test/dpdk-test
elif [[ -f $SCRIPTPATH/../../dpdk-test ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test
else
	DPDK_TEST_BIN=$(which dpdk-test)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test not found !!"
		exit 1
	fi
fi

rm -rf $TRACE_DIR

DPDK_TEST=trace_autotest $DPDK_TEST_BIN $CNXK_EAL_ARGS &
PID=$!

wait $PID
ret=$?

if [ ! -d "$TRACE_DIR" ]; then
	echo "Trace files not generated with trace enabled."
	ret=$(($ret | 1))
else
	if [ $(ls $TRACE_DIR | wc -l) -eq 1 ]; then
		# Expand trace dir name and replace, so that we can use it later on
		for f in $TEST_TRACE_DIR; do
			TEST_TRACE_DIR=$f
		done
		if [ ! -d "$TEST_TRACE_DIR" ]; then
			echo "Test trace subdirectory does not exist"
			ret=$(($ret | 1))
		else
			if [ ! -f "$TEST_TRACE_DIR/metadata" ]; then
				echo "Test trace metadata file does not exist"
				ret=$(($ret | 1))
			else
				if [ $(wc -c "$TEST_TRACE_DIR/metadata" |
				       cut -d' ' -f 1) -eq 0 ]
				then
					echo "Test trace metadata file is empty"
					ret=$(($ret | 1))
				fi
			fi

			channel_files=$(ls $TEST_TRACE_DIR/channel0_* | wc -l)
			if [ $channel_files -eq 0 ]; then
				echo "No channel trace file found"
				ret=$(($ret | 1))
			elif [ $channel_files -gt 1 ]; then
				echo "More than one channel trace file created"
			fi
			if [ ! -f "$TEST_TRACE_DIR/channel0_0" ]; then
				echo "File channel0_0 does not exist"
				ret=$(($ret | 1))
			else
				ch_sz=$(wc -c "$TEST_TRACE_DIR/channel0_0" | cut -d' ' -f 1)
				if [ $ch_sz -eq 0 ]; then
					echo "File channel0_0 is empty"
					ret=$(($ret | 1))
				fi
			fi
		fi
	else
		echo "Number of trace subdirectories is not 1"
		ret=$(($ret | 1))
	fi
	rm -rf $TRACE_DIR
fi

exit $ret
