#!/bin/bash -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021, Marvell

# Environment variables:
# ASIM               - ASIM directory
# ASIM_TARGET_IMAGES - ASIM target images directory which has images like,
#                      cn10k-dataplane-disk.img.

function help()
{
	echo "Start the CN10K ASIM"
	echo ""
	echo "By default, without any arguments ASIM starts and gets the Linux console."
	echo "Usage: "
	echo "$SCRIPT_NAME [OPTION]..."
	echo ""
	echo "--cmd-mode |-c         : Start Linux in command mode to control from asim_cmd.py"
	echo "--kill-asim|-k         : Kill existing asim process on startup."
	echo "--timeout|-t TIMEOUT   : ASIM console timeout in secs."
	echo "--plat|-p PLATFORM     : Specify platform to use: cn10ka (default), cnf10ka, cnf10kb."
	echo "--debug-asim-start|-d  : Debug asim startup."
	echo "--help|-h              : Show this help."
}

function raise_asim_priority()
{
	ps -eLf | grep "asim -e" | grep -v SCREEN | grep -v grep | \
		awk '{print $4}' | xargs sudo renice -n -20 -p 2> /dev/null 1> /dev/null
}

function kill_pids()
{
	for i in $1
	do
		kill -9 $i || (( $? == 1)) >/dev/null
		sleep 0.5
	done
}

function kill_asim()
{
	pids=`lsof -t -i @localhost:2000 || (( $? == 1 ))`
	kill_pids $pids
	pids=`pgrep -x asim || (( $? == 1 ))`
	kill_pids $pids
	pids=`pgrep -x screen || (( $? == 1 ))`
	kill_pids $pids
}

function sig_handler()
{
	set +e
	echo "Received signal $2 executing $1 at line $3: ${@:4}"
	kill_asim

	exit 1
}

function asim_env_setup()
{
	if [[ $KILL -eq 1 ]]; then
		kill_asim
	else
		if pgrep -x asim >/dev/null; then
			echo "ASIM instance is running, please kill it"
			exit 1
		fi
	fi

	# Remove old asim trace and uart log
	sudo rm -f $TRACE_LOG_FILE
	sudo rm -f  $UART_LOG_FILE

	export LD_LIBRARY_PATH=$ASIM/lib:$LD_LIBRARY_PATH
	export ASIM_LIBRARY_PATH=$ASIM/lib
	export ASIM_MANUAL_PATH=$ASIM/man
	export CONFIGDIR=$ASIM/configs
	export BOOT_STRAP=0x100a
	export ASIM_95XX_CFG=
	export ASIM_DIMM_SIZE=1
	export ASIM_DIMM_PER_LMC=2
	export INST_ID=1
	export NIC0=asimnic0
	export NIC1=asimnic1
	export NIC2=asimnic2
	export NIC3=asimnic3
	export NIC4=asimnic4
	export NIC5=asimnic5
	export NIC6=asimnic6
	export NIC7=asimnic7
	export NIC8=asimnic8
	export NIC9=asimnic9

	trap 'sig_handler $0 INT $LINENO $BASH_COMMAND' INT
	trap 'sig_handler $0 ERR $LINENO $BASH_COMMAND' ERR

	#Drop buffer cache
	sudo bash -c "echo 1 > /proc/sys/vm/drop_caches"

	# Enable coredump
	ulimit -c unlimited

	# Print ASIM Version
	$ASIM/bin/asim -V
}

function asim_run()
{
	local asim_cfg=${ASIM_CFG:-"$PROJECT_ROOT/marvell-ci/test/asim/$PLAT.asim"}
	local status
	local ps1set_cmd

	if [[ $DEBUG_ASIM -eq 0 ]]; then
		screen -L -Logfile /tmp/asim_screen.log -d -m -S dp_asim $ASIM/bin/asim -e $asim_cfg
		# Increase priority of all ASIM threads
		raise_asim_priority
	else
		ASIM_UART_RAW=1 $ASIM/bin/asim -e $asim_cfg
		return 0
	fi

	echo "ASIM from                      : $ASIM"
	echo "ASIM DP Target images from     : $ASIM_TARGET_IMAGES"
	echo "To get asim screen             : screen -r dp_asim"
	echo "To exit from asim screen       : CTRL-a d"
	echo "To get asim uart log           : tail -f $UART_LOG_FILE"
	echo "To kill the asim instance      : pkill -9 asim"

	# Wait for ASIM and Linux to start
	if [[ $CMD_MODE -eq 0 ]]; then
		$(dirname "$0")/asim_cmd.py --timeout $CONSOLE_TIMEOUT --console
		status=$?
	else
		$(dirname "$0")/asim_cmd.py --timeout $CONSOLE_TIMEOUT --cmd 'uname -a' --console "ASIM_DP_.*"
		status=$?

		# Set the prompt to echo SUCCESS / SKIP / FAIL cases
		ps1set_cmd="export PS1='\$(r=\$?; if [ \$r == 0 ]; then echo ASIM_DP_success#; elif [ \$r == 77 ]; then echo ASIM_DP_skip#; else echo ASIM_DP_fail#; fi)'"

		$(dirname "$0")/asim_cmd.py --timeout $CONSOLE_TIMEOUT --cmd "$ps1set_cmd" --console "ASIM_DP_.*"

		# Once ASIM is up completely, make sure that newly created threads of
		# ASIM, if any,  have the same nice value
		raise_asim_priority
	fi
	return $status
}

PROJECT_ROOT=${PROJECT_ROOT:-$PWD}
KILL=0
CMD_MODE=0
DEBUG_ASIM=0
CONSOLE_TIMEOUT=${ASIM_CONSOLE_TIMEOUT:-200}
PLAT="cn10ka"
TRACE_LOG_FILE=/tmp/asim_trace.log
UART_LOG_FILE=/tmp/asim_cmd_uart.log
SCRIPT_NAME="$(basename "$0")"

if ! OPTS=$(getopt \
	-o "cdhkp:t:" \
	-l "cmd-mode,debug-asim-start,help,kill-asim,plat:,timeout:" \
	-n "$SCRIPT_NAME" -- "$@"); then
	exit 1
fi
eval set -- "$OPTS"
unset OPTS

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -k|--kill-asim) KILL=1 ;;
        -c|--cmd-mode) CMD_MODE=1 ;;
        -d|--debug-asim-start) DEBUG_ASIM=1 ;;
        -t|--timeout) shift; CONSOLE_TIMEOUT=$1 ;;
	-p|--plat) shift; PLAT=$1 ;;
	-h|--help) help; exit 0 ;;
	--) shift; break ;;
    esac
    shift
done

if [[ -z $ASIM_TARGET_IMAGES ]] || [[ -z $ASIM ]]; then
	echo "Please set ASIM_TARGET_IMAGES ans ASIM environment variables"
	exit 1
fi

if [[ ! -f $ASIM/bin/asim ]]; then
	echo "ASIM binary not found in $ASIM"
	exit 1
fi

if [[ ! -f $ASIM_TARGET_IMAGES/flash-$PLAT.img ]] ||
   [[ ! -f $ASIM_TARGET_IMAGES/scp_bl0.exe-cn10xx ]] ||
   [[ ! -f $ASIM_TARGET_IMAGES/cn10k-dataplane-disk.img ]]; then
	echo "Required images not present in $ASIM_TARGET_IMAGES !!"
	exit 1
fi

asim_env_setup
asim_run
