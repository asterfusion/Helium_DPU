#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

set -euo pipefail

source $TEST_ENV_CONF

SKIP_SYNC=${SKIP_SYNC:-}
SKIP_TARGET_SETUP=${SKIP_TARGET_SETUP:-}
EP_HOST=${EP_HOST:-?}
EP_BOARD=${EP_BOARD:-?}
EP_FILES=${EP_FILES:-/tmp/ep_files}
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh"}
TARGET_SCP_CMD=${TARGET_SCP_CMD:-"scp"}
REMOTE_HOST="$TARGET_SSH_CMD $EP_HOST -n"
REMOTE_BOARD="$TARGET_SSH_CMD $EP_BOARD -n"
REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
BUILD_DIR_HOST=${BUILD_DIR:-$PWD/build}
BUILD_DIR_BOARD=${EP_BUILD_DIR:-$PWD/build}

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

function copy_build_files()
{
	local sync="rsync -azzh --delete"
	if [[ -n $SKIP_SYNC ]]; then
		return
	fi

	$REMOTE_HOST "rm -rf $REMOTE_DIR"
	$REMOTE_HOST "mkdir -p $REMOTE_DIR"
	$sync -e "$TARGET_SSH_CMD" -r $BUILD_DIR_HOST/* $EP_HOST:$REMOTE_DIR
	$sync -e "$TARGET_SSH_CMD" -r --exclude "marvell-ci/test/cnxk-tests/*" \
		$PROJECT_ROOT/marvell-ci $EP_HOST:$REMOTE_DIR

	$REMOTE_BOARD "rm -rf $REMOTE_DIR"
	$REMOTE_BOARD "mkdir -p $REMOTE_DIR"
	$sync -e "$TARGET_SSH_CMD" -r $BUILD_DIR_BOARD/* $EP_BOARD:$REMOTE_DIR
	$sync -e "$TARGET_SSH_CMD" -r --exclude "marvell-ci/test/cnxk-tests/*" \
		$PROJECT_ROOT/marvell-ci $EP_BOARD:$REMOTE_DIR
}

function ep_setup()
{
	export TARGET_SSH_CMD
	export TARGET_SCP_CMD
	export REMOTE_DIR

	if [[ -n $SKIP_TARGET_SETUP ]]; then
		return
	fi

	TARGET_URL=$EP_BOARD AGENT_PATH=$EP_FILES MODULE_PATH=$EP_FILES \
		$PROJECT_ROOT/marvell-ci/test/board/cnxk-ep-setup.sh
	TARGET_URL=$EP_HOST HP=1024 $PROJECT_ROOT/marvell-ci/test/board/cnxk-ep-setup.sh
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
	timeout --foreground -v -k 30 -s 3 $tmo $REMOTE_HOST "$cmd"
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
	local test_num=0

	# Errors will be handled inline. No need for sig handler
	set +e
	trap - ERR

	# Read the tests info one by one from the test list created by meson test
	while [[ true ]]; do
		test_num=$((test_num + 1))
		test_enabled $test_num
		res=$?
		if [[ $res == 77 ]]; then
			continue
		fi
		if [[ $res -ne 0 ]]; then
			break
		fi

		tst=$(get_test_name $test_num)

		# Run the tests
		run_test $tst
		res=$?
		if [[ $res -ne 0 ]] && [[ $res -ne 77 ]] ; then
			test_exit -1 "FAILURE: Test $tst failed"
		fi
	done
}

function test_exit()
{
	local result=$1
	local msg=$2

	set +e
	trap - INT
	trap - TERM
	trap - ERR
	trap - QUIT

	$REMOTE_HOST 'dmesg; uptime; cat /proc/uptime' > remote_dmesg.log
	save_log remote_dmesg.log

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

	$REMOTE_HOST "sudo killall -SIGINT $binary_name" 2>/dev/null

	test_exit 1 "Error: Caught signal $signame in $0"
}

trap "sig_handler INT NONE" INT
trap "sig_handler TERM NONE" TERM
trap "sig_handler ERR NONE" ERR
trap "sig_handler QUIT NONE" QUIT

echo "Copying files to EP host/board"
copy_build_files

echo "Setting up EP host/board"
ep_setup

echo "Running tests on EP host/board"
run_all_tests

test_exit 0 "SUCCESS: Tests Completed"
