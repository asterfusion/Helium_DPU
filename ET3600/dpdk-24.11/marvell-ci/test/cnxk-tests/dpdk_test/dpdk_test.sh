#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_DEVICE="$SSO_DEV"
TEST_TYPE=$1
ISOLCPUS=$(</sys/devices/system/cpu/isolated)

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

declare -A cn9k_event_test_args cn10k_event_test_args cnxk_event_test_args

register_cn9k_event_test() {
        cn9k_event_test_args[$1]="${2-}"
}

register_cn10k_event_test() {
        cn10k_event_test_args[$1]="${2-}"
}

register_cnxk_event_test() {
        cnxk_event_test_args[$1]="${2-}"
}

run_cn9k_event_tests() {
	for test in ${!cn9k_event_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${cn9k_event_test_args[$test]}
	done
}

run_cn10k_event_tests() {
	for test in ${!cn10k_event_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${cn10k_event_test_args[$test]}
	done
}

run_event_tests() {
	case $PLAT in
		cn9*) run_cn9k_event_tests ;;
		cn10*) run_cn10k_event_tests ;;
	esac

	for test in ${!cnxk_event_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${cnxk_event_test_args[$test]}
	done
}

#				DPDK TEST NAME			TEST ARGS
register_cn9k_event_test	event_timer_adapter_test	"-l $ISOLCPUS -a $EVENT_DEVICE,single_ws=1,tim_stats_ena=1"
register_cn9k_event_test	eventdev_selftest_cn9k		"-l $ISOLCPUS"
register_cn10k_event_test	eventdev_selftest_cn10k		"-l $ISOLCPUS"
register_cn10k_event_test	event_timer_adapter_test	"-l $ISOLCPUS -a $EVENT_DEVICE,gw_mode=0,tim_stats_ena=1"
register_cnxk_event_test	event_eth_rx_adapter_autotest	"-l $ISOLCPUS"
register_cnxk_event_test	event_crypto_adapter_autotest	"-l 0,1"

case $TEST_TYPE in
	event_tests)
		run_event_tests
		;;
esac
