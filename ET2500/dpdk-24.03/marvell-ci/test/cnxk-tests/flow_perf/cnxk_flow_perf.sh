#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

FLOWPERF_PORT="0002:01:00.1"
FLOWPERF_CORE=0x300
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

if [[ -f $SCRIPTPATH/../../../../app/dpdk-test-flow-perf ]]; then
	# This is running from build directory
	TESTFLOWPERF=$SCRIPTPATH/../../../../app/dpdk-test-flow-perf
elif [[ -f $SCRIPTPATH/../../../dpdk-test-flow-perf ]]; then
	# This is running from install directory
	TESTFLOWPERF=$SCRIPTPATH/../../../dpdk-test-flow-perf
else
	TESTFLOWPERF=$(which dpdk-test-flow-perf)
fi

if [[ -z $TESTFLOWPERF ]]; then
	echo "dpdk-test-flow-perf not found !!"
	exit 1
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
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

declare -i SCLK
declare -i RCLK
declare -i REF_PERF_NUMBER

function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
	fp_rclk="$sysclk_dir/rclk/clk_rate"
	fp_sclk="$sysclk_dir/sclk/clk_rate"

	if $SUDO test -f "$fp_rclk"; then
		RCLK=$(echo "`$SUDO cat $fp_rclk` / $div" | bc)
	else
		echo "$fp_rclk not available"
		exit 1
	fi

	if $SUDO test -f "$fp_sclk"; then
		SCLK=$(echo "`$SUDO cat $fp_sclk` / $div" | bc)
	else
		echo "$fp_sclk not available"
		exit 1
	fi

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
}

function is_perf_pass()
{
	local ref_num=$1
	local obs_perf_num=$2
	local lim
	local variation
	res=0

	#Performance difference in percentage
	lim=`echo "$ref_num - ($ref_num / 10)" | bc -l`
	echo "Minimum Acceptable Rate:$lim"

	res=`echo "$obs_perf_num < $lim" | bc -l`
	if [ $res -eq 1 ]; then
		return 1
	else
		return 0
	fi
}

get_system_info
FNAME="rclk"${RCLK}"_sclk"${SCLK}".96xx"
FPATH="$SCRIPTPATH/ref_numbers/cn9k/$FNAME"
echo "Reference numbers file:$FPATH"

if [ ! -f "$FPATH" ]; then
	echo "Performance reference numbers file $FPATH does not exist. Skipping test.."
	exit 0
fi

ref_num=$(cat $FPATH)
ref_perf_number=`echo "$ref_num * 1000" | bc -l`
REF_PERF_NUMBER=${ref_perf_number%.*}
RANDSEED=12345678
TMO=60
ARGS="-c $FLOWPERF_CORE -a $FLOWPERF_PORT,flow_max_priority=10 -- \
	--random-priority=10,$RANDSEED --ingress --ether --ipv4 --drop \
	--rules-count=800 --rules-batch=100 --deletion-rate"

echo "Starting dpdk-test-flow-perf with Port=$FLOWPERF_PORT, \
	Coremask=$FLOWPERF_CORE"
echo "ARGS: $ARGS"

#Sample dpdk-test-flow-perf output string:-
#:: [Latency | Insertion] All Cores :: Port 0 :: \
#Total flows insertion rate -> 0.066450 K Rules/Sec

PAT1="Throughput"
PAT2="flows insertion rate"
MAX_ITR=3
ITR=1
FLOWRATE_ACC=0

while [ $ITR -le $MAX_ITR ]
do
	FLOWPERF_OUT=`timeout --foreground -k 10 -s 3 $TMO $TESTFLOWPERF \
			$ARGS | grep "$PAT1" | grep "$PAT2"`

	if [ $? -ne 0 ]; then
		echo "flow-perf-test exited with error"
		exit 1
	fi

	echo $FLOWPERF_OUT
	FLOWRATE=`echo $FLOWPERF_OUT |  grep -o '\-> .* K' | cut -d' ' -f2`
	FLOWRATE=`echo "$FLOWRATE * 1000" | bc -l`

	FLOWRATE_ACC=`echo "$FLOWRATE_ACC + $FLOWRATE" | bc -l`
	ITR=$(( $ITR + 1 ))
done

AVG_FLOWRATE=`echo "$FLOWRATE_ACC / $MAX_ITR" | bc -l`

echo "Reference Performance Number:$REF_PERF_NUMBER"
echo "Observed Flow Creation Rate:$AVG_FLOWRATE"

if is_perf_pass $REF_PERF_NUMBER $AVG_FLOWRATE; then
	echo "flow-perf-test passed"
	exit 0
else
	echo "flow-perf-test failed"
	exit 1
fi

