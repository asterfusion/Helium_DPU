#!/bin/bash

# Copyright(C) 2021 Marvell.
# SPDX-License-Identifier: BSD-3-Clause

# Functions required to manipulate the test.list file.

TEST_LIST=$RUN_DIR/test.list

function clean_test_list()
{
	rm -f $TEST_LIST
}

function add_test()
{
	local name=$1
	local exec_bin=$2
	local dir=$3
	local args=$4
	local env=$5
	echo "$name#$exec_bin#$dir# $args# $env" >> $TEST_LIST
}

function get_test_name()
{
	local test_num=$1
	local num=1
	local info="LIST_END"
	while read -r testinfo; do
		if [[ $num == $test_num ]]; then
			info=$testinfo
			break
		fi
		num=$((num + 1))
	done <$TEST_LIST
	echo $info | awk -F'#' '{print $1}'
}

function get_test_info()
{
	local test_name=$1
	local name
	local info="LIST_END"
	while read -r testinfo; do
		name=$(echo $testinfo | awk -F'#' '{print $1}')
		if [[ $name == $test_name ]]; then
			info=$testinfo
			break
		fi
	done <$TEST_LIST
	echo $info
}

function get_test_exec_bin()
{
	local val
	val=$(get_test_info $1 | awk -F'#' '{print $2}')
	echo $val | sed "s#$BUILD_DIR#$TARGET_RUN_DIR#g"
}

function get_test_dir()
{
	local val
	val=$(get_test_info $1 | awk -F'#' '{print $3}')
	echo $val | sed "s#$BUILD_DIR#$TARGET_RUN_DIR#g"
}

function get_test_args()
{
	get_test_info $1 | awk -F'#' '{print $4}'
}

function get_test_extra_args()
{
	local tst=$1
	local args=

	tst="${tst%% }"
	IFS=$'\n'
	for t in ${CMD_EXTRA_ARGS:-}; do
		if [ "${t%,*}" == "$tst" ]; then
			args=${t#*,}
			break
		fi
	done
	echo $args
	IFS=' '
}

function get_test_env()
{
	get_test_info $1 | awk -F'#' '{print $5}'
}

function get_test_timeout()
{
	local tmo=${DEFAULT_CMD_TIMEOUT:-5m}
	local tst=$1

	for t in ${CMD_TIMEOUTS:-}; do
		if [ "${t%=*}" == "$tst" ]; then
			tmo=${t#*=}
			break
		fi
	done
	echo $tmo
}

function test_enabled()
{
	local test_num=$1
	local tst=$(get_test_name $test_num)

	if [[ $tst == LIST_END ]]; then
		return 1
	fi

	echo -e "\n\n#################### Test $test_num: $tst ########################"

	# Check the SKIP_TESTS and RUN_TESTS and make sure that test need indeed be run
	if [[ -n $RUN_TESTS ]]; then
		if ! (echo "$RUN_TESTS" | grep -q "$tst"); then
			echo "Skipping $tst as not on RUN_TESTS list !!"
			echo "$test_num: $tst [RUN_TESTS]" >> $RUN_DIR/skip.list
			return 77
		fi
	elif $(echo "$SKIP_TESTS" | grep -q "$tst"); then
		echo "Skipping $tst on SKIP_TESTS list !!"
		echo "$test_num: $tst [SKIP_TESTS]" >> $RUN_DIR/skip.list
		return 77
	fi

	if [[ $test_num -lt ${START_TEST_NUM} ]] || [[ $test_num -gt ${END_TEST_NUM} ]]; then
		echo "Skipping $tst as test num not within given test num range ($START_TEST_NUM-$END_TEST_NUM) !!"
		echo "$test_num: $tst [TEST_NUM_OUT_OF_RANGE $START_TEST_NUM-$END_TEST_NUM]" >> $RUN_DIR/skip.list
		return 77
	fi

	echo "$test_num: $tst" >> $RUN_DIR/run.list
	return 0
}

function test_info_print()
{
	local name=$1
	local exec_bin
	local args=
	local defargs
	local envs
	local tmo
	local cmd
	local test_dir
	local extra_args=

	exec_bin=$(get_test_exec_bin $name)
	test_dir=$(get_test_dir $name)
	defargs=$(get_test_args $name)
	envs=$(get_test_env $name)
	tmo=$(get_test_timeout $name)
	cmd=$(get_test_command $name)
	extra_args=$(get_test_extra_args $name)
	echo "Test Binary/script -> $exec_bin"
	echo "Test Timeout -> $tmo"
	echo "Test Environment -> $envs"
	echo "Test Directory -> $test_dir"

	# Remove unnecessary arguments from command line
	echo "Default arguments -> '$defargs'"
	eval set -- "$defargs"
	while [[ $# -gt 0 ]]; do
		case $1 in
			-l) shift; shift;;
			--no-huge) shift;;
			-m) shift; shift;;
			*) args="$args $1"; shift;;
		esac
	done
	echo "Modified arguments -> '$args $extra_args'"
	echo "Test Command -> $cmd"
}

function get_test_command()
{
	local name=$1
	local exec_bin
	local args=
	local extra_args=
	local defargs
	local envs
	local cmd
	local test_dir

	exec_bin=$(get_test_exec_bin $name)
	test_dir=$(get_test_dir $name)
	defargs=$(get_test_args $name)
	envs=$(get_test_env $name)
	extra_args=$(get_test_extra_args $name)

	# Remove unnecessary arguments from command line
	eval set -- "$defargs"
	while [[ $# -gt 0 ]]; do
		case $1 in
			-l) shift; shift;;
			--no-huge) shift;;
			-m) shift; shift;;
			*) args="$args $1"; shift;;
		esac
	done
	cmd="cd $test_dir && $TARGET_SUDO $envs $EXTRA_TARGET_ENV $exec_bin $args $extra_args"
	echo "$cmd"
}
