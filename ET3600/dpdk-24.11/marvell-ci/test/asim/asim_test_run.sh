#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

source $TEST_ENV_CONF

SKIP_SYNC=${SKIP_SYNC:-}
TARGET_ASIM=${TARGET_ASIM:-root@127.0.0.1}
TARGET_ASIM_PORT=${TARGET_ASIM_PORT:-22}
REMOTE="ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30  $TARGET_ASIM -p $TARGET_ASIM_PORT"
REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
PLAT=${PLAT:-"cn10ka"}
ASIM_BOOT_TIMEOUT=${ASIM_BOOT_TIMEOUT:-300}
ASIM_REF_REMOTE=${ASIM_REF_REMOTE:-}
ASIM_REF_REMOTE_IMAGES=${ASIM_REF_REMOTE_IMAGES:-}
ASIM_MAX_REBOOTS=${ASIM_MAX_REBOOTS:-5}
RUN_DIR=${RUN_DIR:-}
TMP_DIR=$(mktemp -d)

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

function cleanup_remote_logs()
{
	echo "Cleaning up remote logs"
	# Clear old dmesg logs
	$REMOTE sudo dmesg -c > /dev/null || true
}

function save_remote_logs()
{
	$REMOTE sudo dmesg -c > ${TMP_DIR}/remote_dmesg.log
	$REMOTE sudo ps aux > ${TMP_DIR}/remote_psaux.log

	save_log ${TMP_DIR}/remote_dmesg.log
	save_log ${TMP_DIR}/remote_psaux.log
}

function cleanup_asim_logs()
{
	echo "Cleaning up ASIM logs"
	$REMOTE sudo rm -f /tmp/asim_screen.log
	$REMOTE sudo rm -f /tmp/asim_trace.log
	$REMOTE sudo rm -f /tmp/asim_cmd_uart.log
	$REMOTE sudo rm -f /tmp/asim_screen.log.prev
	$REMOTE sudo rm -f /tmp/asim_trace.log.prev
	$REMOTE sudo rm -f /tmp/asim_cmd_uart.log.prev
}

function save_asim_cmd_logs()
{
	local prefix=$1
	local test=${2:-}
	local logs="asim_screen.log asim_trace.log asim_cmd_uart.log"
	local lc

	# Extract the logs for the current command only. Dump the diff of
	# current and prev logs to get the logs for the command.
	for log in $logs; do
		rm -f ${TMP_DIR}/$log && touch ${TMP_DIR}/$log
		($REMOTE sudo cat /tmp/$log > ${TMP_DIR}/$log) 2>/dev/null || true
		rm -f ${TMP_DIR}/$log.prev && touch ${TMP_DIR}/$log.prev
		($REMOTE sudo cat /tmp/$log.prev > ${TMP_DIR}/$log.prev) 2>/dev/null || true
		lc=$(wc -l ${TMP_DIR}/${log}.prev | cut -d' ' -f1)
		touch ${TMP_DIR}/test.log
		if [[ $lc -ne 0 ]]; then
			tail -n +$((lc + 1)) ${TMP_DIR}/$log > ${TMP_DIR}/test.log
		fi
		save_log ${TMP_DIR}/test.log ${prefix}.${test}.$log
		rm ${TMP_DIR}/test.log
	done
}

function save_asim_complete_logs()
{
	local prefix=$1

	rm -f ${TMP_DIR}/asim_screen.log && touch ${TMP_DIR}/asim_screen.log
	rm -f ${TMP_DIR}/asim_trace.log && touch ${TMP_DIR}/asim_trace.log
	rm -f ${TMP_DIR}/asim_cmd_uart.log && touch ${TMP_DIR}/asim_cmd_uart.log
	$REMOTE sudo cat /tmp/asim_screen.log > ${TMP_DIR}/asim_screen.log 2>/dev/null || true
	$REMOTE sudo cat /tmp/asim_trace.log > ${TMP_DIR}/asim_trace.log 2>/dev/null || true
	$REMOTE sudo cat /tmp/asim_cmd_uart.log > ${TMP_DIR}/asim_cmd_uart.log 2>/dev/null || true
	save_log ${TMP_DIR}/asim_screen.log ${prefix}.asim_screen.log
	save_log ${TMP_DIR}/asim_trace.log ${prefix}.asim_trace.log
	save_log ${TMP_DIR}/asim_cmd_uart.log ${prefix}.asim_cmd_uart.log
}

function cleanup_asim_instances()
{
	echo "Cleaning up ASIM instances"
	$REMOTE sudo pkill -9 -x asim 2>/dev/null || true
	sleep 3
}

function test_exit()
{
	local result=$1
	local save_asim_log=$2
	local msg=$3

	set +e
	trap - INT
	trap - ERR
	trap - QUIT
	trap - TERM

	if [[ $save_asim_log == yes ]]; then
		save_asim_complete_logs last_run
	fi
	save_remote_logs

	cleanup_asim_instances
	cleanup_remote_logs
	cleanup_asim_logs
	echo "###########################################################"
	echo "Run time: $((SECONDS / 60)) mins $((SECONDS % 60)) secs"
	echo $msg
	echo "###########################################################"
	exit $result
}

function sig_handler()
{
	local sig
	local signame=$1
	local save_asim_log=$2

	set +e
	trap - INT
	trap - ERR
	trap - QUIT
	trap - TERM

	sig=$(kill -l $signame)
	test_exit $sig $save_asim_log "Error: Caught signal $signame in $0"
}

function test_init()
{
	cleanup_remote_logs
	cleanup_asim_instances
	cleanup_asim_logs
}

function target_sync()
{
	local rsync_ssh="ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -p $TARGET_ASIM_PORT"

	if [[ -n $SKIP_SYNC ]]; then
		return
	fi

	echo "Syncing files to target"
	$REMOTE sudo rm -rf $REMOTE_DIR
	$REMOTE mkdir -p $REMOTE_DIR/build

	rsync -azzh --stats -e "$rsync_ssh" -r --exclude .libs --exclude .deps \
		$BUILD_DIR/* $TARGET_ASIM:$REMOTE_DIR/build
	rsync -azzh --stats -e "$rsync_ssh" -r \
		$PROJECT_ROOT/marvell-ci $TARGET_ASIM:$REMOTE_DIR
}

function check_asim_errors()
{
	local pattern
	local res=0

	rm -f ${TMP_DIR}/asim_trace.log.check && touch ${TMP_DIR}/asim_trace.log.check
	$REMOTE sudo cat /tmp/asim_trace.log > ${TMP_DIR}/asim_trace.log.check 2>/dev/null || true

	for pattern in "${ASIM_IGNORE_PATTERNS[@]}"; do
		sed --in-place "/$pattern/d" ${TMP_DIR}/asim_trace.log.check
	done

	for pattern in "${ASIM_ERROR_PATTERNS[@]}"; do
		grep -i $pattern ${TMP_DIR}/asim_trace.log.check 2>/dev/null 1>/dev/null
		if [ $? -eq 0 ]; then
			echo "ASIM has errors [pattern: $pattern]"
			res=1
			break
		fi
	done
	rm -f ${TMP_DIR}/asim_trace.log.check

	# Check for errors in UART logs also.
	rm -f ${TMP_DIR}/asim_cmd_uart.log.check && touch ${TMP_DIR}/asim_cmd_uart.log.check
	$REMOTE sudo cat /tmp/asim_cmd_uart.log > ${TMP_DIR}/asim_cmd_uart.log.check 2>/dev/null || true
	for err in "${ASIM_UART_ERROR_PATTERNS[@]}"; do
		grep -i "$err" ${TMP_DIR}/asim_cmd_uart.log.check 2>/dev/null 1>/dev/null
		if [ $? -eq 0 ]; then
			echo "ASIM UART log has errors [$err]"
			res=2
			break
		fi
	done
	rm -f ${TMP_DIR}/asim_cmd_uart.log.check

	return $res
}

function launch_asim()
{
	local status
	local asim_launch_cmd

	cleanup_asim_instances
	cleanup_asim_logs
	echo "Launching ASIM"

	asim_launch_cmd="ASIM_CONSOLE_TIMEOUT=${ASIM_BOOT_TIMEOUT} \
		ASIM=$ASIM \
		ASIM_CFG=$REMOTE_DIR/marvell-ci/test/asim/$PLAT.asim \
		ASIM_TARGET_IMAGES=$ASIM_TARGET_IMAGES bash \
		$REMOTE_DIR/marvell-ci/test/asim/asim_start.sh -k -p $PLAT"

	if [[ -z $ASIM_INTERACTIVE ]]; then
		$REMOTE $asim_launch_cmd -c
		status=$?
	else
		echo "Entering Interactive mode"
		$REMOTE -tt $asim_launch_cmd
		echo "Exiting Interactive mode"
		exit 0
	fi

	return $status
}

function run_test()
{
	local iter=$1
	local name=$2
	local cmd
	local tmo
	local curtime
	local run_status
	local int_err_status
	local ret

	# Backup current logs so that logs specific to this test can be extracted
	# out later.
	$REMOTE sudo cp /tmp/asim_cmd_uart.log /tmp/asim_cmd_uart.log.prev 2>/dev/null
	$REMOTE sudo cp /tmp/asim_screen.log /tmp/asim_screen.log.prev 2>/dev/null
	$REMOTE sudo cp /tmp/asim_trace.log /tmp/asim_trace.log.prev 2>/dev/null

	# Get Test information
	test_info_print $name
	cmd=$(get_test_command $name)
	tmo=$(get_test_timeout $name)

	# Run the test
	curtime=$SECONDS
	$REMOTE timeout --foreground -v -k 30 -s 3 $tmo \
		"$REMOTE_DIR/marvell-ci/test/asim/asim_cmd.py --cmd '$cmd'"
	run_status=$?

	echo -en "\n$name completed in $((SECONDS - curtime)) seconds ... "

	# Check for errors and known issues
	check_asim_errors
	int_err_status=$?

	ret=0
	if [[ $run_status -eq 0 ]]; then
		echo "TEST SUCCESS (ret = $run_status)"
	elif [[ $run_status -eq 77 ]]; then
		echo "TEST SKIPPED (ret = $run_status)"
	else
		ret=1
		echo "TEST FAILURE (ret = $run_status)"
	fi

	# ASIM errors should cause a test re-run, irrespective of test result
	if [[ $int_err_status -ne 0 ]]; then
		echo "ASIM Error Found [$int_err_status], Retrying !!"
		ret=2
	fi

	# Make sure that next command does not start too fast
	sleep 2

	return $ret
}

function run_all_tests()
{
	local tst
	local iter=1
	local res
	local test_num=0

	# Errors will be handled inline. No need for sig handler.
	set +e
	trap - ERR

	# Launch ASIM for first time
	launch_asim
	if [[ $? -ne 0 ]]; then
		echo "ASIM Launch Error"
		test_exit -1 yes "FAILURE: ASIM Launch Failed"
	fi

	# Read the tests info one by one from the test list created by meson test
	while [[ true ]]; do
		test_num=$((test_num + 1))
		test_enabled $test_num
		res=$?
		# Test is skipped, goto next test
		if [[ $res == 77 ]]; then
			continue
		fi
		# All tests have been completed, break out
		if [[ $res -ne 0 ]]; then
			break
		fi
		tst=$(get_test_name $test_num)

		# Run the test
		while [[ true ]]; do
			# Run the test
			run_test $iter $tst
			res=$?

			# Test was success / Skipped, break out
			if [[ $res -eq 0 ]]; then
				break
			fi

			# Failed and max retries hit
			if [[ $iter -ge $ASIM_MAX_REBOOTS ]]; then
				save_asim_cmd_logs last_run ${tst}
				test_exit -1 yes "FAILURE: Not retrying $tst as max reboots hit"
			fi

			# Failed, but attempt retry
			save_asim_complete_logs iter.$((iter))
			launch_asim
			if [[ $? -ne 0 ]]; then
				test_exit -1 yes "FAILURE: ASIM Launch Error when running $tst"
			fi
			iter=$((iter + 1))
		done
	done
}

trap "sig_handler INT no" INT
trap "sig_handler ERR no" ERR
trap "sig_handler QUIT no" QUIT
trap "sig_handler TERM no" TERM
test_init
cleanup_mount_point
target_sync
create_dataplane_disk_image

trap "sig_handler ERR yes" ERR
trap "sig_handler INT yes" INT
trap "sig_handler QUIT yes" QUIT
trap "sig_handler TERM yes" TERM
run_all_tests

test_exit 0 yes "SUCCESS: Tests Completed"
