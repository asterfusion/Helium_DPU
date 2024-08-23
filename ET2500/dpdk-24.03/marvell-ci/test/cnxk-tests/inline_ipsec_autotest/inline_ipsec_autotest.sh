#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -uo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

NIX_INL_DEV=${NIX_INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
NIX_INL_DEVICE="$NIX_INL_DEV"

ETH_DEV=${ETH_DEV:-$(lspci -d :a0f8 | head -1 | awk -e '{ print $1 }')}
ETHERNET_DEVICE="$ETH_DEV"

CRYPTO_DEV=${CRYPTO_DEV:-$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')}
CRYPTO_DEVICE="$CRYPTO_DEV"

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_DEVICE="$SSO_DEV"

TEST_TYPE=$1

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

PART_106B0=$(cat /proc/device-tree/soc\@0/chiprevision)
declare -A cn10k_inline_ipsec_test_args

register_cn10k_inline_ipsec_test() {
        cn10k_inline_ipsec_test_args[$1]="${2-}"
}

run_cn10k_inline_ipsec_tests() {
	unbuffer="$(command -v stdbuf) -o 0" || unbuffer=
	local out=ipsec_out.txt
	local parse=log_ipsec_parse_out.txt
	total_fail_cnt=0
	for test in ${!cn10k_inline_ipsec_test_args[@]}; do
		DPDK_TEST=$test $unbuffer $DPDK_TEST_BIN ${cn10k_inline_ipsec_test_args[$test]} >$out 2>&1
		cat $out
		cat $out | grep "failed" > temp_1.txt
		awk '!/failed:/' temp_1.txt > temp_2.txt
		fail_cnt=`cat $out | grep "Tests Failed :" | awk '{print $5}'`

		if [[ $test == "inline_ipsec_sg_autotest" ]]; then
			awk '!/Inner L4 checksum test failed/' temp_2.txt > temp_1.txt
			cat temp_1.txt > temp_2.txt
			# Two failures of L4 checksum are expected
			fail_cnt=`expr $fail_cnt - 2`
		fi
		cat temp_2.txt >> $parse
		rm -rf temp_1.txt temp_2.txt $out
		total_fail_cnt=`expr $total_fail_cnt + $fail_cnt`
	done
	count=`grep -c "failed" $parse`
	rm $parse
	if [[ $count -ne 0 && $total_fail_cnt -ne 0 ]]; then
		echo "FAILURE count $count $total_fail_cnt"
		exit 1;
	fi
}

run_inline_ipsec_tests() {
	case $PLAT in
		cn10*) run_cn10k_inline_ipsec_tests ;;
	esac
}


#					DPDK TEST NAME		TEST ARGS
register_cn10k_inline_ipsec_test	inline_ipsec_autotest	"-a $ETHERNET_DEVICE,rx_inj_ena=1 -a $NIX_INL_DEVICE,rx_inj_ena=1 -a $CRYPTO_DEVICE"
register_cn10k_inline_ipsec_test	event_inline_ipsec_autotest	"-a $ETHERNET_DEVICE,rx_inj_ena=1 -a $NIX_INL_DEVICE,rx_inj_ena=1 -a $CRYPTO_DEVICE -a $EVENT_DEVICE"

if [[ $PLAT == "cn10k" && $PART_106B0 == "B0" ]]; then
register_cn10k_inline_ipsec_test	inline_ipsec_sg_autotest	"-a $ETHERNET_DEVICE,rx_inj_ena=1 -a $NIX_INL_DEVICE,rx_inj_ena=1 -a $CRYPTO_DEVICE"
fi

case $TEST_TYPE in
	inline_ipsec_tests)
		run_inline_ipsec_tests
		;;
esac
