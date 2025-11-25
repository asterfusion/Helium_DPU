#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SKIP_TARGET_SETUP=${SKIP_TARGET_SETUP:-n}
TARGET_BOARD=${TARGET_BOARD:-root@127.0.0.1}
REMOTE="ssh -o ServerAliveInterval=30 $TARGET_BOARD -n"
REMOTE_DIR=${REMOTE_DIR:-/tmp/dpdk}
PROJROOT=${PROJROOT:-$PWD}
BUILD_DIR=${BUILD_DIR:-$PWD/build}
TMO=10m

function test_init()
{
	$REMOTE 'sudo dmesg -c' 2>&1 > /dev/null
	$REMOTE 'uname -a'
}

function copy_files()
{
	perf_dir="$PROJROOT/marvell-ci/test/cnxk-tests/crypto_perf"
	# Create remote dir
	$REMOTE "rm -rf $REMOTE_DIR"
	$REMOTE "mkdir -p $REMOTE_DIR"

	echo "Copying files to $TARGET_BOARD"
	scp $BUILD_DIR/app/dpdk-test-crypto-perf $TARGET_BOARD:$REMOTE_DIR
	scp $perf_dir/crypto_perf_target.sh $TARGET_BOARD:$REMOTE_DIR
	$REMOTE "mkdir -p $REMOTE_DIR/marvell-ci/test/board"
	scp $PROJROOT/marvell-ci/test/board/oxk-devbind-basic.sh \
		$TARGET_BOARD:$REMOTE_DIR/marvell-ci/test/board
	echo "File copy done"
}

function target_setup()
{
	if [ $SKIP_TARGET_SETUP == "y" ]; then
		return
	fi

	$PROJROOT/marvell-ci/test/board/cnxk-target-setup.sh
}

function run_test()
{
	local name=$1
	local cmd
	local curtime
	local res

	echo "Start $name"
	cmd="cd $REMOTE_DIR && $REMOTE_DIR/crypto_perf_target.sh $REMOTE_DIR"
	echo "$cmd"

	curtime=$SECONDS
	timeout --foreground -k 30 -s 3 $TMO $REMOTE "$cmd"
	res=$?
	echo -e "\n$name completed in $((SECONDS - curtime)) seconds"

	return $res
}

test_init
copy_files
target_setup
run_test "crypto_perf"

exit 0
