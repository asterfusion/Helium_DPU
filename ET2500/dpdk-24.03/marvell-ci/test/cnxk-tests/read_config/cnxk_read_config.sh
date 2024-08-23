#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

if [[ -f $CNXKTESTPATH/../../../app/dpdk-proc-info ]]; then
	# This is running from build directory
	TESTDPDK=$CNXKTESTPATH/../../../app/dpdk-proc-info
elif [[ -f $CNXKTESTPATH/../../../dpdk-proc-info ]]; then
	# This is running from install directory
	TESTDPDK=$CNXKTESTPATH/../../../dpdk-proc-info
else
	TESTDPDK=$(which dpdk-proc-info)
fi

if [[ -z $TESTDPDK ]]; then
	echo "dpdk-proc-info not found !!"
	exit 1
fi

PRFX="read-config"

PORT0="0002:01:00.1"
COREMASK="0xC"
OFF=0

PROC_CMD="$TESTDPDK -a $PORT0 --file-prefix $PRFX"
APP_LOG=proc_info.$PRFX.log
rm -f $APP_LOG
rm -f $APP_LOG-port0

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
	fi

	testpmd_quit $PRFX
	testpmd_cleanup $PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function run_app()
{
	eval "nohup $1 >> $APP_LOG 2>&1 &"

	# Wait until the process is completed
	while (ps -ef | grep dpdk-proc-info | grep -q $PRFX); do
		continue
	done
}

echo "Testpmd running with $PORT0, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0" \
	"--nb-cores=1 --rxq 1 --txq 1"

#Dump device information
testpmd_cmd $PRFX "show device info all"

#Dump Rx and Tx queue config information
testpmd_cmd $PRFX "show config rxtx"
#Rx and Tx queue information for port 0 and queue 0
testpmd_cmd $PRFX "show rxq info 0 0"
testpmd_cmd $PRFX "show txq info 0 0"

#Dump port information
testpmd_cmd $PRFX "show port info all"

#Dump supported port ptypes
testpmd_cmd $PRFX "show port 0 ptypes"

#Dump Flow control
testpmd_cmd $PRFX "show port 0 flow_ctrl"

#Dump RSS hash configuration
testpmd_cmd $PRFX "show port 0 rss-hash"

#Dump module information
testpmd_cmd $PRFX "show port 0 module_eeprom"


sleep 1
testpmd_log_off $PRFX $OFF

#Dump Register Info
run_app "$PROC_CMD -- --dump-regs=$APP_LOG"

sleep 1
testpmd_quit $PRFX
testpmd_cleanup $PRFX

val=`cat $APP_LOG | grep -a "successfully" || true`
if [ "$val" == "" ]
then
	echo "FAILURE: Registers dump is failed"
	exit 1
fi

echo "SUCCESS: testpmd read config test completed"
