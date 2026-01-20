#!/bin/bash

# Copyright(C) 2021 Marvell.
# SPDX-License-Identifier: BSD-3-Clause

# This script creates a list of tests from meson test. This will be
# later used in cnxk/asim_test_run.sh to run the tests on the target.

set -euo pipefail

TEST_BINARY=$1

if [[ $(basename $TEST_BINARY) == cnxk-test-script-wrapper ]]; then
	# For test-cnxk-scripts the script is passed as an argument to
	# cnxk-test-script-wrapper binary by meson test and the
	# directory from where the test is to be run will be given in
	# TEST_DIR env var.
	shift
	TEST_BINARY=$TEST_DIR/$1
else
	# For all other meson, the tests can be run from base build dir.
	TEST_DIR=$BUILD_DIR
fi

shift

TEST_ARGS=$@

source $TEST_ENV_CONF

TEST_ENV_VARS="DPDK_TEST=$DPDK_TEST LD_LIBRARY_PATH=$TARGET_RUN_DIR/deps/lib PLAT=$PLAT"
if [[ $PLAT == cn10k-ep ]]; then
	TEST_ENV_VARS="$TEST_ENV_VARS EP_BOARD=$EP_BOARD"
else
	TEST_ENV_VARS="$TEST_ENV_VARS TARGET_BOARD=$TARGET_BOARD GENERATOR_BOARD=$GENERATOR_BOARD"
fi

add_test "$DPDK_TEST" "$TEST_BINARY" "$TEST_DIR" "$TEST_ARGS" "$TEST_ENV_VARS"

exit 77
