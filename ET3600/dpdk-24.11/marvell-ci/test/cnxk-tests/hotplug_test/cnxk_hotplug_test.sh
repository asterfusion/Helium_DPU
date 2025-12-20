#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env


if [[ -f $CNXKTESTPATH/../../../build/examples/dpdk-hotplug_mp ]]; then
        # This is running from build directory
	HOTPLUG=$CNXKTESTPATH/../../../build/examples/dpdk-hotplug_mp
elif [[ -f $CNXKTESTPATH/../../../examples/dpdk-hotplug_mp ]]; then
	# This is running from install directory
	HOTPLUG=$CNXKTESTPATH/../../../examples/dpdk-hotplug_mp
else
        HOTPLUG=$(command -v dpdk-hotplug_mp)
fi

if [[ -z $HOTPLUG ]]; then
	echo "dpdk-hotplug_mp not found !!"
	exit 1
fi

CAP_PRFX="dut"
PORT0="0002:01:00.1"
PORT2="0002:01:00.2"
PORT3="0002:01:00.3"
PORT4="0002:02:00.0"

out_prim=hotplug_out_primary.$CAP_PRFX
in_prim=hotplug_in_primary.$CAP_PRFX
out_sec=hotplug_out_secondary.$CAP_PRFX
in_sec=hotplug_in_secondary.$CAP_PRFX


if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

if [ -f $CNXKTESTPATH/../board/oxk-devbind-basic.sh ]
then
        VFIO_DEVBIND="$CNXKTESTPATH/../board/oxk-devbind-basic.sh"
else
        VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
        if [[ -z $VFIO_DEVBIND ]]; then
                echo "oxk-devbind-basic.sh not found !!"
                exit 1
        fi
fi

function hotplug_cmd()
{
	local prefix=$1
	local cmd=$2

	if [ "$cmd" = "list" ]; then
		echo "$cmd" >> $in_prim
		sleep 1
		echo "$cmd" >> $in_sec
	else
		echo "$cmd" >> $in_prim
	fi
}

function hotplug_exit()
{
	local prefix=$1
	local cmd=$2
	echo "$cmd" >> $in_prim
	echo "$cmd" >> $in_sec
}


function hotplug_launch()
{
	local eal_args=$1
	local l3fwd_args=$2
	local in_file=$?
	local out_file=$?
	local unbuffer="stdbuf -o0"

	if [ "$2" = "primary" ]; then
		in_file=$in_prim
		out_file=$out_prim
	fi
	if [ "$2" = "secondary" ]; then
		in_file=$in_sec
		out_file=$out_sec
	fi

	rm -f $out_file
	rm -f $in_file
	touch $in_file
	tail -f $in_file | $unbuffer $HOTPLUG $eal_args &>$out_file 2>&1 &
}

function cleanup_interface()
{
	$VFIO_DEVBIND -b $NICVF $PORT0
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
	fi

	hotplug_exit $CAP_PRFX "quit"
	cleanup_interface
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

echo "dpdk-hotplug_mp running with no ports"
sleep 1
hotplug_launch "--log-level=".*,7" -a 0002:11:22.1 --proc-type=auto" "primary"
sleep 2
hotplug_launch "--log-level=".*,7" -a 0002:11:22.1 --proc-type=auto" "secondary"

sleep 1
$VFIO_DEVBIND -b vfio-pci $PORT2
sleep 2
# Start capturing
hotplug_cmd $CAP_PRFX "attach $PORT2"
sleep 3
hotplug_cmd $CAP_PRFX "list"
sleep 2
hotplug_cmd $CAP_PRFX "detach $PORT2"
sleep 3
hotplug_cmd $CAP_PRFX "list"
sleep 2
hotplug_exit $CAP_PRFX "quit"
sleep 1
cleanup_interface
sleep 1

port_id_prim=`sed -n '/attach/,/detach/p' $out_prim | \
	grep -A 1 "list all etherdev" | tail -n1 | awk '{print $2}'`
port_id_sec=`cat $out_sec | grep "Probe PCI driver:" | tail -n 1 | awk '{print $8}'`

if [ "$port_id_prim" = "$port_id_sec" ]; then
	echo "Hotplug attach sccuess"
else
	echo "Hotplug attach failure"
	exit 1;
fi

port_id_primd=`sed -n '/detach/,/quit/p' $out_prim | \
	grep -A 1 "list all etherdev" | tail -n1 | awk '{print $2}'`
port_id_secd=`cat $out_sec | tail -n1 | awk '{print $2}'`


if [ "$port_id_primd" = "$port_id_secd" ]; then
	echo "Hotplug detach sccuess"
else
	echo "Hotplug detach failure"
	exit 1;
fi
