#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

echo "TEST NAME : $DPDK_TEST"
echo "TEST DIR  : $PWD"
echo "TEST ARGS : $@"

# Find the cnxk-test application
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

# Note that below setting of DPDK_TEST has nothing to with exe_wrapper or
# meson test. It is specific to the below command.
DPDK_TEST=version_autotest $DPDK_TEST_BIN

