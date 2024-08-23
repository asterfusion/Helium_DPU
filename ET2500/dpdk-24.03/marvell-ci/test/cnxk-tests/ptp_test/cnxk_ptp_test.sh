#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

GENERATOR_BOARD=${GENERATOR_BOARD:?}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env

if [[ -f $CNXKTESTPATH/../../../examples/dpdk-ptpclient ]]; then
	# This is running from build directory
	TESTPTP=$CNXKTESTPATH/../../../examples/dpdk-ptpclient
elif [[ -f $CNXKTESTPATH/../../../dpdk-ptpclient ]]; then
	# This is running from install directory
	TESTPTP=$CNXKTESTPATH/../../../dpdk-ptpclient
else
	TESTPTP=$(which dpdk-ptpclient)
fi

if [[ -z $TESTPTP ]]; then
	echo "dpdk-ptpclient not found !!"
	exit 1
fi

if [[ -d /sys/bus/pci/drivers/octeontx2-nicpf ]]; then
	NICPF="octeontx2-nicpf"
else
	NICPF="rvu_nicpf"
fi

if [ -f $1/marvell-ci/test/board/oxk-devbind-basic.sh ]
then
	VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
	if [[ -z $VFIO_DEVBIND ]]; then
		echo "oxk-devbind-basic.sh not found !!"
		exit 1
	fi
fi

PRFX="ptp-client"
PORT0="0002:02:00.0"
PORT1="0002:03:00.0"
COREMASK="0x1"
PORTMAST="0x3"
TIMESTAMP="0"
MEMCHANNEL="4"

PTPC_CMD="$TESTPTP -c $COREMASK -n $MEMCHANNEL \
	-a $PORT0 -a $PORT1 --file-prefix $PRFX \
	-- -p $PORTMAST -T $TIMESTAMP"

declare -a ptp_log_strings=(
	"T2 - Slave  Clock."
	"T1 - Master Clock."
	"T3 - Slave  Clock."
	"T4 - Master Clock."
)

SUDO="sudo"
REMOTE_SSH="${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -n "} $GENERATOR_BOARD"
SCAPY_SCRIPT=${SCAPY_SCRIPT:-ptp_sendrecv.py}
PTP_PCAP=${PTP_PCAP:-ptp.pcap}

#Log files
PTP_CLIENT_LOG=$PRFX.log
SCAPY_LOG=$PRFX-scapy.log
rm -f $PTP_CLIENT_LOG $SCAPY_LOG

if [[ -z "$GENERATOR_BOARD" ]]; then
	echo "Generator board details missing!!"
	echo "Cannot run PTP test with generator board!!"
	exit $status
fi

echo "Running with generator board $GENERATOR_BOARD"

#Bind PORT0 and PORT1 to vfio-pci
$VFIO_DEVBIND -b vfio-pci $PORT0 $PORT1

find_exec()
{
	local name=$1
	$REMOTE_SSH find $REMOTE_DIR -type f -iname $name
}

function run_scapy()
{
	echo "Running scapy script on generator board $GENERATOR_BOARD"

	VFIO_DEVBIND_R=`find_exec "oxk-devbind-basic.sh"`
	#Bind PORT0 to Kernel interface on Generator board
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -u $PORT0 $PORT1"
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -b $NICPF $PORT0 $PORT1"

	#Run Scapy PTP packets generator
	$REMOTE_SSH "cd $REMOTE_DIR; $SUDO python3 " \
		"$(find_exec $SCAPY_SCRIPT) -p $(find_exec $PTP_PCAP)" >>$SCAPY_LOG 2>&1

	#Bind PORT0 back to vfio-pci
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -u $PORT0 $PORT1"
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -b vfio-pci $PORT0 $PORT1"
}

function dump_scapylog()
{
	cat -v $SCAPY_LOG
}

function dump_ptplog()
{
	cat -v $PTP_CLIENT_LOG
}

function run_app()
{
	local unbuffer="stdbuf -o0"
	eval "$unbuffer $1 >> $PTP_CLIENT_LOG 2>&1 &"
	sleep 1
	val=`dump_ptplog | grep -a "Error"`
	if [ "$val" == "" ]; then
		echo 0
	else
		echo -1
	fi
}

function exit_app()
{
	killall dpdk-ptpclient
}

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
		# Dump error logs
		dump_ptplog
		dump_scapylog
		exit_app
	fi

	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

function find_time()
{
	val=`dump_ptplog | grep -a "$1" | awk -F "$2" '{print $1}' | awk '{print $NF}'`
	echo $val
}

function check_ptplog()
{
	sec=`find_time "$1" "s "`
	nsec=`find_time "$1" "ns"`
	if [ "$sec" == "" ]; then
		echo 0
		return
	fi

	if [ $sec -eq 0 ] && [ $nsec -eq 0 ]; then
		echo 0
	else
		echo 1
	fi
}

function validate_ptp()
{
	for i in "${ptp_log_strings[@]}";
	do
		valid=`check_ptplog "$i"`
		if [ $valid -eq 0 ]
		then
			echo 0
			return
		fi
	done
	echo 1
}

function validate_scapy()
{
	val=`dump_scapylog | grep -a "Traceback"`
	if [ "$val" != "" ]; then
		echo -1
		return
	fi

	val=`dump_scapylog | grep -a "PTP Delay Response packet"`
	if [ "$val" == "" ]; then
		echo 0
	else
		echo 1
	fi
}

#Run Dpdk PTP client example
echo "PTP client running with $PORT0 and $PORT1"
res=`run_app '$PTPC_CMD'`
if [ $res -eq -1 ]; then
	echo "FAILURE: PTP client application launch failed"
	exit 1
fi

#Run scapy script to generate PTP packets
run_scapy

#dump logs
echo "Scapy logs"
dump_scapylog

echo "PTP client logs"
dump_ptplog

exit_app

echo "Exit"
#Validate scapy log
res=`validate_scapy`
if [ $res -eq -1 ]; then
	echo "FAILURE: Scapy failed"
elif [ $res -eq 0 ]; then
	echo "FAILURE: No PTP Delay Response packet sent"
else
	echo "SUCCESS: PTP Delay Response packet sent"
fi

res=`validate_ptp`
if [ $res -eq 0 ]; then
	echo "FAILURE: PTP test"
else
	echo "SUCCESS: PTP test completed"
fi
