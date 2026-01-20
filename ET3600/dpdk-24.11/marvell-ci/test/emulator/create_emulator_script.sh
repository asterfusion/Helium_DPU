#!/bin/bash

# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

source $TEST_ENV_CONF

TARGET_ASIM=${TARGET_ASIM:-root@127.0.0.1}
TARGET_ASIM_PORT=${TARGET_ASIM_PORT:-22}
REMOTE="ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30  $TARGET_ASIM -p $TARGET_ASIM_PORT -n"
REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
EXTRA_TARGET_ENV=${EXTRA_TARGET_ENV:-}
ASIM_REF_REMOTE=${ASIM_REF_REMOTE:-}
ASIM_REF_REMOTE_IMAGES=${ASIM_REF_REMOTE_IMAGES:-}
EMULATOR_RUN_SCRIPT=${EMULATOR_RUN_SCRIPT:-$BUILD_DIR/emulator_run.sh}

function test_exit()
{
	local result=$1
	local msg=$2

	set +e
	trap - INT
	trap - ERR
	trap - QUIT
	trap - TERM

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

	sig=$(kill -l $signame)
	test_exit $sig "Error: Caught signal $signame in $0"
}

function target_sync()
{
	local rsync_ssh="ssh -o StrictHostKeyChecking=no -o ServerAliveInterval=30 -p $TARGET_ASIM_PORT"

	echo "Syncing files to target"
	$REMOTE sudo rm -rf $REMOTE_DIR
	$REMOTE mkdir -p $REMOTE_DIR/build

	rsync -azzh --stats -e "$rsync_ssh" -r --exclude .libs --exclude .deps \
		$BUILD_DIR/* $TARGET_ASIM:$REMOTE_DIR/build
	rsync -azzh --stats -e "$rsync_ssh" -r \
		$PROJECT_ROOT/marvell-ci $TARGET_ASIM:$REMOTE_DIR
}

function create_emulator_run_script()
{
	local name
	local test_num=0
	local cmd
	local tmo

	set +e
	trap - ERR
	# Read the tests info one by one from the test list created by meson test
	rm -f $EMULATOR_RUN_SCRIPT
	echo -e "#!/bin/bash -e" > $EMULATOR_RUN_SCRIPT
	chmod +x $EMULATOR_RUN_SCRIPT
	while [[ true ]]; do
		test_num=$((test_num + 1))
		test_enabled $test_num
		res=$?
		if [[ $res -ne 0 ]] && [[ $res -ne 77 ]]; then
			break
		fi

		name=$(get_test_name $test_num)
		echo "echo -e '\n\n##########################################'" \
				>> $EMULATOR_RUN_SCRIPT
		echo "echo 'Test $test_num: $name'" >> $EMULATOR_RUN_SCRIPT

		if [[ $res == 77 ]]; then
			echo -e "echo Skipping\n" >> $EMULATOR_RUN_SCRIPT
			continue
		fi
		cmd=$(get_test_command $name)
		echo "$cmd"
		echo -e "$cmd\n" >> $EMULATOR_RUN_SCRIPT
	done
}

trap "sig_handler INT" INT
trap "sig_handler ERR" ERR
trap "sig_handler QUIT" QUIT
trap "sig_handler TERM" TERM
create_emulator_run_script
cleanup_mount_point
target_sync
create_dataplane_disk_image

test_exit 0 "SUCCESS: Created Emulator Script $EMULATOR_RUN_SCRIPT"
