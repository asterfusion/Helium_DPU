#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

ETH_DEV=${ETH_DEV:-$(lspci -d :a063 | tail -1 | awk -e '{ print $1 }')}
ETHERNET_DEVICE="$ETH_DEV"

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

declare -A cn103_inline_macsec_test_args

register_cn103_inline_macsec_test() {
        cn103_inline_macsec_test_args[$1]="${2-}"
}

run_cn103_inline_macsec_tests() {
	for test in ${!cn103_inline_macsec_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${cn103_inline_macsec_test_args[$test]}
	done
}

run_inline_macsec_tests() {
	case $PLAT in
		cn10*) run_cn103_inline_macsec_tests ;;
	esac

	for test in ${!cn103_inline_macsec_test_args[@]}; do
		DPDK_TEST=$test $DPDK_TEST_BIN ${cn103_inline_macsec_test_args[$test]}
	done
}


#					DPDK TEST NAME		TEST ARGS
register_cn103_inline_macsec_test	inline_macsec_autotest	"-a $ETHERNET_DEVICE "

case $TEST_TYPE in
	inline_macsec_tests)
		run_inline_macsec_tests
		;;
esac
