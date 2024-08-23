#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SUDO=${SUDO:-"sudo"}
TEST_LOG=cnxk_mempool_perf.log
PREFIX="cmpt"
TOLERANCE=${TOLERANCE:-3}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-"/tmp/dpdk/deps/lib"}

# Find the cnxk_mempool_perf application
if [[ -f $SCRIPTPATH/cnxk_mempool_perf ]]; then
	TEST_BIN=$SCRIPTPATH/cnxk_mempool_perf
else
	TEST_BIN=$(command -v cnxk_mempool_perf)
	if [[ -z $TEST_BIN ]]; then
		echo "cnxk_mempool_perf not found !!"
		exit 1
	fi
fi

function test_cleanup()
{
	rm -f $TEST_LOG
}
trap test_cleanup EXIT

function test_mempool_perf()
{
	local ref_file=$1
	local unbuffer="stdbuf -o0"
	local pattern='mempool_autotest cache'
	local ref_value
	local expected
	local result

	# Run the cnxk_mempool_perf application
	$SUDO LD_LIBRARY_PATH=$LD_LIBRARY_PATH DPDK_TEST=cnxk_mempool_perf \
		$unbuffer $TEST_BIN --file-prefix $PREFIX |& tee $TEST_LOG

	result=$(grep "$pattern" $TEST_LOG | awk -F '=' '{print $8}' | sort -g | tail -n1)
	echo "Result=$result"

	ref_value=$(<$ref_file)
	expected=$(($ref_value * (100 - $TOLERANCE) / 100))
	echo "Reference File=$ref_file"
	echo "Reference Value=$ref_value"
	echo "Tolerance=${TOLERANCE}%"
	echo "Expected=$expected"

	# compare results
	if [[ $result -lt $expected ]]; then
		echo "CNXK Mempool Perf Failed"
		exit 1
	fi
	echo "CNXK Mempool Perf Passed"
}

function get_ref_file()
{
	local pn_106xx="0xd49"
	local pn_96xx="0xd49"
	local pn
	local rclk
	local sclk
	local div=1000000

	pn=$(grep -m 1 'CPU part' /proc/cpuinfo | awk -F': ' '{print $2}')
	if [[ $pn == $pn_106xx ]]; then
		soc="cn106xx"
		rclk=$(cat /sys/kernel/debug/clk/coreclk/clk_rate)
	else
		soc="cn96xx"
		rclk=$(cat /sys/kernel/debug/clk/rclk/clk_rate)
	fi
	rclk=$((rclk / div))

	sclk=$(cat /sys/kernel/debug/clk/sclk/clk_rate)
	sclk=$((sclk / div))
	echo "ref_numbers/${soc}_rclk${rclk}_sclk${sclk}"
}

ref_file=$(get_ref_file)
test_mempool_perf $ref_file
