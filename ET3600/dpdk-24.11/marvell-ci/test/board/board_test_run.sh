#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

source $TEST_ENV_CONF

SKIP_SYNC=${SKIP_SYNC:-}
SKIP_TARGET_SETUP=${SKIP_TARGET_SETUP:-}
TARGET_BOARD=${TARGET_BOARD:-root@127.0.0.1}
GENERATOR_BOARD=${GENERATOR_BOARD:-}
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
TARGET_SCP_CMD=${TARGET_SCP_CMD:-"scp"}
REMOTE="$TARGET_SSH_CMD $TARGET_BOARD -n"
TARGET_RUN_DIR=${TARGET_RUN_DIR:-/tmp/dpdk}
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
REBOOT_ON_FAIL=${REBOOT_ON_FAIL:-}

function save_log()
{
	local logfile=$1
	local save_name=${2:-}

	if [[ -z $RUN_DIR ]] || [[ ! -d $RUN_DIR ]]; then
		return
	fi

	if [[ -n $save_name ]]; then
		cp $logfile $RUN_DIR/$save_name 2>/dev/null || true
	else
		cp $logfile $RUN_DIR/ 2>/dev/null || true
	fi
}

function test_init()
{
	$REMOTE 'sudo dmesg -c' 2>&1 > /dev/null
	$REMOTE 'uname -a'
}

# Sync the files
function target_sync()
{
	local sync="rsync -azzh --delete"
	if [[ -n $SKIP_SYNC ]]; then
		return
	fi
	echo "Syncing files to target"
	$REMOTE "rm -rf $TARGET_RUN_DIR"
	$REMOTE "mkdir -p $TARGET_RUN_DIR/deps"
	# If DEPS_INSTALL_DIR is not same as BUILD_DIR/deps, then sync the deps separately
	if [[ $(realpath $DEPS_INSTALL_DIR) != $(realpath $BUILD_DIR/deps) ]]; then
		$sync -e "$TARGET_SSH_CMD" -r $DEPS_INSTALL_DIR/ $TARGET_BOARD:$TARGET_RUN_DIR/deps/
	fi
	$sync -e "$TARGET_SSH_CMD" -r $BUILD_DIR/* $TARGET_BOARD:$TARGET_RUN_DIR
	$sync -e "$TARGET_SSH_CMD" -r --exclude "marvell-ci/test/cnxk-tests/*" \
		$PROJECT_ROOT/marvell-ci $TARGET_BOARD:$TARGET_RUN_DIR

	if [[ -n $GENERATOR_BOARD ]]; then
		$TARGET_SSH_CMD $GENERATOR_BOARD mkdir -p $TARGET_RUN_DIR/deps
		# If DEPS_INSTALL_DIR is not same as BUILD_DIR/deps, then sync the deps separately
		if [[ $(realpath $DEPS_INSTALL_DIR) != $(realpath $BUILD_DIR/deps) ]]; then
			$sync -e "$TARGET_SSH_CMD" -r $DEPS_INSTALL_DIR/ $GENERATOR_BOARD:$TARGET_RUN_DIR/deps/
		fi
		$sync -e "$TARGET_SSH_CMD" -r $BUILD_DIR/* $GENERATOR_BOARD:$TARGET_RUN_DIR
		$sync -e "$TARGET_SSH_CMD" \
			$PROJECT_ROOT/marvell-ci/test/board/oxk-devbind-basic.sh \
			$GENERATOR_BOARD:$TARGET_RUN_DIR
	fi
}

function target_setup()
{
	echo "Setting up target"
	# Setup the board
	export TARGET_BOARD
	export TARGET_SSH_CMD
	export REMOTE_DIR=$TARGET_RUN_DIR
	export PERF_STAGE
	export TM_SETUP
	if [[ -n $SKIP_TARGET_SETUP ]]; then
		return
	fi
	$PROJECT_ROOT/marvell-ci/test/board/cnxk-target-setup.sh

	if [[ -n $GENERATOR_BOARD ]]; then
		# Setup Generator Board also
		TARGET_BOARD=$GENERATOR_BOARD VFIO_DEVBIND=$TARGET_RUN_DIR/oxk-devbind-basic.sh \
			$PROJECT_ROOT/marvell-ci/test/board/cnxk-target-setup.sh
	fi
}

function run_test()
{
	local name=$1
	local tmo
	local cmd
	local curtime
	local exec_bin
	local res

	exec_bin=$(get_test_exec_bin $name)
	binary_name=$(basename $exec_bin)
	tmo=$(get_test_timeout $name)

	# Update sig handlers to pass in test name also.
	trap "sig_handler INT $binary_name" INT
	trap "sig_handler TERM $binary_name" TERM
	trap "sig_handler QUIT $binary_name" QUIT

	test_info_print $name
	cmd=$(get_test_command $name)

	curtime=$SECONDS
	timeout --foreground -v -k 30 -s 3 $tmo $REMOTE "$cmd"
	res=$?
	echo -en "\n$name completed in $((SECONDS - curtime)) seconds ... "
	if [[ $res -eq 0 ]]; then
		echo "TEST SUCCESS (ret = $res)"
	elif [[ $res -eq 77 ]]; then
		echo "TEST SKIPPED (ret = $res)"
	else
		echo "TEST FAILURE (ret = $res)"
	fi

	return $res
}

function run_all_tests()
{
	local tst
	local res
	local failed_tests=""
	local passed_tests=""
	local skipped_tests=""
	local test_num=0

	# Errors will be handled inline. No need for sig handler
	set +e
	trap - ERR

	# Read the tests info one by one from the test list created by meson test
	while [[ true ]]; do
		test_num=$((test_num + 1))
		test_enabled $test_num
		res=$?
		tst=$(get_test_name $test_num)
		if [[ $res == 77 ]]; then
			skipped_tests="${skipped_tests}${tst}#"
			continue
		fi
		if [[ $res -ne 0 ]]; then
			break
		fi

		# Run the tests
		run_test $tst
		res=$?
		if [[ $res -ne 0 ]] && [[ $res -ne 77 ]] ; then
			failed_tests="${failed_tests}${tst}#"
			if [[ -n $CONTINUE_ON_FAILURE ]]; then
				echo "FAILURE: Test $tst failed"
			else
				test_exit -1 "FAILURE: Test $tst failed"
			fi
		else
			passed_tests="${passed_tests}${tst}#"
		fi
	done
	if [[ -n $STATUS_OUTFILE ]] ; then
		echo "FAILED: $failed_tests" > $STATUS_OUTFILE
		echo "PASSED: $passed_tests" >> $STATUS_OUTFILE
		echo "SKIPPED: $skipped_tests" >> $STATUS_OUTFILE
	fi
	if [[ -n $failed_tests ]]; then
		test_exit -1 "FAILURE: Test(s) [$failed_tests] failed"
	fi
}

function test_exit()
{
	local result=$1
	local msg=$2
	local waittime

	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT

	$REMOTE 'dmesg; uptime; cat /proc/uptime' > remote_dmesg.log
	save_log remote_dmesg.log

	if [[ $result -ne 0 ]]; then
		if [[ -n $REBOOT_ON_FAIL ]]; then
			echo "Test case failure, rebooting the board."
			waittime=300
			while [[ $waittime -gt 0 ]]; do
				$REMOTE true 2> /dev/null && break
				sleep 10
				waittime=$((waittime - 1))
			done

			if ($REMOTE true 2> /dev/null); then
				echo "Rebooting board failed."
			fi
		fi
	fi
	echo "###########################################################"
	echo "Run time: $((SECONDS / 60)) mins $((SECONDS % 60)) secs"
	echo "$msg"
	echo "###########################################################"

	exit $result
}

function sig_handler()
{
	local signame=$1
	local binary_name=$2

	# Make sure that sig_handler is fully executed.
	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT

	$REMOTE "sudo killall -SIGINT $binary_name" 2>/dev/null

	test_exit 1 "Error: Caught signal $signame in $0"
}

trap "sig_handler INT NONE" INT
trap "sig_handler TERM NONE" TERM
trap "sig_handler ERR NONE" ERR
trap "sig_handler QUIT NONE" QUIT

test_init
target_sync
target_setup

run_all_tests

test_exit 0 "SUCCESS: Tests Completed"
