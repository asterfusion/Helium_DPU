#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 Marvell.

set -e

GENERATOR_BOARD=${GENERATOR_BOARD:?}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

PRFX_PF="port_repr_pf"
PRFX_VF1="port_repr_vf1"
PRFX_VF2="port_repr_vf2"

CMASK_PF="0x3"
CMASK_VF1="0xC"
CMASK_VF2="0x30"

NET_PF="0002:02:00.0"
VF1="0002:02:00.1"
VF2="0002:02:00.2"
ESW_PF=$(lspci | grep a0e0 | cut -d ' ' -f1)
NPKTS=1

REPR="[pf1vf[0,1]]"
TOKEN="b9d20911-e43f-4115-83f5-dfa0181277fb"

SUDO="sudo"
REMOTE_SSH="${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -n "} $GENERATOR_BOARD"
SCAPY_SCRIPT=${SCAPY_SCRIPT:-sndrcv_pkt.py}
PORT0="0002:02:00.0"
SCAPY_LOG="sndrcvpkt_scapy.log"

if [[ -d /sys/bus/pci/drivers/octeontx2-nicpf ]]; then
	NICPF="octeontx2-nicpf"
else
	NICPF="rvu_nicpf"
fi

VFIO_DEVBIND="$CNXKTESTPATH/../board/oxk-devbind-basic.sh"
if ! [[ -f $VFIO_DEVBIND ]]
then
VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
fi
echo "$VFIO_DEVBIND"


if [[ $ESW_PF == "" ]]; then
	echo -e "\tERROR: ESWITCH PF device not present"
	exit 1
fi

source $CNXKTESTPATH/common/testpmd/common.env

function print_logs()
{
	testpmd_log $PRFX_PF
	testpmd_log $PRFX_VF1
	testpmd_log $PRFX_VF2
}

function quit_testpmds()
{
	testpmd_quit $PRFX_VF2
	sleep 2
	testpmd_quit $PRFX_VF1
	sleep 2
	testpmd_quit $PRFX_PF
	sleep 2
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
		testpmd_cleanup $PRFX_VF2
		testpmd_cleanup $PRFX_VF1
		testpmd_cleanup $PRFX_PF
	fi

	# Disable SRIOV
	echo 0 > /sys/module/vfio_pci/parameters/enable_sriov

	exit $status
}

function init_dev()
{
	# Enable SRIOV
	echo 1 > /sys/module/vfio_pci/parameters/enable_sriov

	$VFIO_DEVBIND -b vfio-pci $ESW_PF

	$VFIO_DEVBIND -b vfio-pci $NET_PF
	echo 0 > /sys/bus/pci/devices/$NET_PF/sriov_numvfs
	echo 2 > /sys/bus/pci/devices/$NET_PF/sriov_numvfs
}

function run_testpmds()
{
echo "PF testpmd running with $NET_PF, Coremask=$CMASK_PF"
testpmd_launch $PRFX_PF \
		" -c $CMASK_PF -n 4 -a $NET_PF -a $ESW_PF,representor=$REPR --vfio-vf-token=$TOKEN"

echo "VF1 testpmd running with Coremask=$CMASK_VF1"
testpmd_launch $PRFX_VF1 \
		" -c $CMASK_VF1 -n 4 -a $VF1 --vfio-vf-token=$TOKEN"

echo "VF2 testpmd running with Coremask=$CMASK_VF2"
testpmd_launch $PRFX_VF2 \
		" -c $CMASK_VF2 -n 4 -a $VF2 --vfio-vf-token=$TOKEN"
}

find_exec()
{
	local name=$1
	$REMOTE_SSH find $REMOTE_DIR -type f -iname $name
}

function delete_scapy_logs()
{
	rm -f $SCAPY_LOG
}

function run_scapy()
{
	local p=${1:-0}
	echo "Running scapy script on generator board $GENERATOR_BOARD"

	VFIO_DEVBIND_R=`find_exec "oxk-devbind-basic.sh" | head -n 1`
	#Bind PORT0 to Kernel interface on Generator board
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -u $PORT0"
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -b $NICPF $PORT0"

	#Run Scapy packets generator
	$REMOTE_SSH "cd $REMOTE_DIR; $SUDO python3 " \
		"$(find_exec $SCAPY_SCRIPT) $p" >>$SCAPY_LOG 2>&1

	#Bind PORT0 back to vfio-pci
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -u $PORT0"
	$REMOTE_SSH "$SUDO $VFIO_DEVBIND_R -b vfio-pci $PORT0"
}

function check_stats()
{
	local prefix=$1
	local cnt=$2
	local out=testpmd.out.$prefix
	local ret

	COUNT=`cat $out | tail -n12 | grep "RX-packets:" | awk -e '{ print $2 }'`

	if [[ $COUNT -eq $cnt ]]; then
		ret=0
	else
		ret=1
	fi

	echo $ret
}

function check_xstats()
{
	local prefix=$1
	local cnt=$2
	local out=testpmd.out.$prefix
	local ret

	COUNT=`cat $out | tail -n12 | grep "rep_nb_rx:" | awk -e '{ print $2 }'`

	if [[ $COUNT -eq $cnt ]]; then
		ret=0
	else
		ret=1
	fi

	echo $ret
}

function check_tx_xstats()
{
	local prefix=$1
	local cnt=$2
	local out=testpmd.out.$prefix
	local ret

	COUNT=`cat $out | tail -n12 | grep "rep_nb_tx:" | awk -e '{ print $2 }'`

	if [[ $COUNT -eq $cnt ]]; then
		ret=0
	else
		ret=1
	fi

	echo $ret
}

function check_tx_stats()
{
	local prefix=$1
	local cnt=$2
	local out=testpmd.out.$prefix
	local ret

	COUNT=`cat $out | tail -n12 | grep "TX-packets:" | awk -e '{ print $2 }'`


	if [[ $COUNT -eq $cnt ]]; then
		ret=0
	else
		ret=1
	fi

	echo $ret
}

function check_scapy_logs()
{
	local out=$SCAPY_LOG
	local cnt=$1

	COUNT=`cat $out | tail -n2 | grep "Received" | awk -e '{ print $2 }'`

	if [[ $COUNT -eq $cnt ]]; then
		ret=0
	else
		ret=1
	fi

	echo $ret
}

function clear_stats()
{
	testpmd_cmd $PRFX_PF "clear port stats 0"
	testpmd_cmd $PRFX_VF1 "clear port stats 0"
	testpmd_cmd $PRFX_VF2 "clear port stats 0"
}

function clear_xstats()
{
	testpmd_cmd $PRFX_PF "clear port xstats 0"
	testpmd_cmd $PRFX_PF "clear port xstats 1"
	testpmd_cmd $PRFX_PF "clear port xstats 2"
}

function test_fwd_pf_to_vf1()
{
	testpmd_cmd $PRFX_PF "start"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	run_scapy
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_stats $PRFX_PF $NPKTS) -eq 1 ]]; then
		echo "Packets not received in PF"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF1 $NPKTS) -eq 1 ]]; then
		echo "Packets not received in VF1"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF2 0) -eq 1 ]]; then
		echo "Packets received in VF2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"

	echo "test_fwd_pf_to_vf1 passed"
}

function test_fwd_pf_to_vf2()
{
	testpmd_cmd $PRFX_PF "set portlist 0,2"
	testpmd_cmd $PRFX_PF "start"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	run_scapy
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_stats $PRFX_PF 1) -eq 1 ]]; then
		echo "Packets not received in PF"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF1 0) -eq 1 ]]; then
		echo "Packets received in VF1"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF2 1) -eq 1 ]]; then
		echo "Packets not received in VF2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	echo "test_fwd_pf_to_vf2 passed"
}

function test_fwd_vf1_to_vf2()
{
	local flow_str

	flow_str="flow create 0 transfer pattern represented_port ethdev_port_id is 1 / end "
	flow_str+="actions represented_port ethdev_port_id 2 / count / end"

	testpmd_cmd $PRFX_PF "set portlist 0,1"
	testpmd_cmd $PRFX_PF "$flow_str"
	testpmd_cmd $PRFX_PF "start"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "set fwd rxonly"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	run_scapy
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_stats $PRFX_PF 1) -eq 1 ]]; then
		echo "Packets not received in PF"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF1 1) -eq 1 ]]; then
		echo "Packets not received in VF1"
		exit -1
	fi
	if [[ $(check_tx_stats $PRFX_VF1 1) -eq 1 ]]; then
		echo "Packets not transmitted by VF1"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF2 1) -eq 1 ]]; then
		echo "Packets not received in VF2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	testpmd_cmd $PRFX_PF "flow flush 0"
	testpmd_cmd $PRFX_PF "flow list 0"
	echo "test_fwd_vf1_to_vf2 passed"
}

function test_fwd_wire_to_vf2()
{
	local flow_str

	flow_str="flow create 0 transfer pattern represented_port ethdev_port_id is 0 / end "
	flow_str+="actions represented_port ethdev_port_id 2 / count / end"

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_PF "$flow_str"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	run_scapy
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_stats $PRFX_PF 0) -eq 1 ]]; then
		echo "Packets received in PF"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF1 0) -eq 1 ]]; then
		echo "Packets received in VF1"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF2 1) -eq 1 ]]; then
		echo "Packets not received in VF2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	testpmd_cmd $PRFX_PF "flow flush 0"
	testpmd_cmd $PRFX_PF "flow list 0"
	echo "test_fwd_wire_to_vf2 passed"
}

function test_fwd_port_repr_2_to_vf1()
{
	local flow_str

	flow_str="flow create 0 transfer pattern port_representor port_id is 2 / end "
	flow_str+="actions represented_port ethdev_port_id 1 / count / end"

	testpmd_cmd $PRFX_PF "$flow_str"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	testpmd_cmd $PRFX_PF "start tx_first 1"
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_stats $PRFX_VF1 64) -eq 1 ]]; then
		echo "Packets not received in VF1"
		exit -1
	fi
	if [[ $(check_stats $PRFX_VF2 0) -eq 1 ]]; then
		echo "Packets received in VF2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	testpmd_cmd $PRFX_PF "flow flush 0"
	testpmd_cmd $PRFX_PF "flow list 0"
	echo "test_fwd_port_repr_2_to_vf1 passed"
}

function test_fwd_port_repr_1_port_repr_2_pair()
{
	local flow_str_1
	local flow_str_2

	flow_str_1="flow create 0 transfer pattern port_representor port_id is 2 / end "
	flow_str_1+="actions port_representor port_id 1 / count / end"

	flow_str_2="flow create 0 transfer pattern port_representor port_id is 1 / end "
	flow_str_2+="actions port_representor port_id 2 / count / end"

	testpmd_cmd $PRFX_PF "$flow_str_1"
	testpmd_cmd $PRFX_PF "$flow_str_2"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_xstats
	testpmd_cmd $PRFX_PF "start tx_first 1"
	testpmd_cmd $PRFX_PF "show port xstats 1"
	if [[ $(check_xstats $PRFX_PF 32) -eq 1 ]]; then
		echo "Packets not received in port representor with port id 1"
		exit -1
	fi
	if [[ $(check_tx_xstats $PRFX_PF 32) -eq 1 ]]; then
		echo "Packets not transmitted by port representor with port id 1"
		exit -1
	fi
	testpmd_cmd $PRFX_PF "show port xstats 2"
	if [[ $(check_xstats $PRFX_PF 32) -eq 1 ]]; then
		echo "Packets not received in port representor with port id 2"
		exit -1
	fi
	if [[ $(check_tx_xstats $PRFX_PF 64) -eq 1 ]]; then
		echo "Packets not transmitted by port representor with port id 2"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	testpmd_cmd $PRFX_PF "flow flush 0"
	testpmd_cmd $PRFX_PF "flow list 0"
	echo "test_fwd_port_repr_1_port_repr_2_pair passed"
}

function test_fwd_vf2_to_wire()
{
	local flow_str

	flow_str="flow create 0 transfer pattern represented_port ethdev_port_id is 2 / end "
	flow_str+="actions represented_port ethdev_port_id 0 / count / end"

	testpmd_cmd $PRFX_PF "set portlist 0,2"
	testpmd_cmd $PRFX_PF "$flow_str"
	testpmd_cmd $PRFX_PF "start"
	testpmd_cmd $PRFX_VF1 "start"
	testpmd_cmd $PRFX_VF2 "start"

	clear_stats
	run_scapy 1
	testpmd_cmd $PRFX_PF "show port stats 0"
	testpmd_cmd $PRFX_VF1 "show port stats 0"
	testpmd_cmd $PRFX_VF2 "show port stats 0"
	if [[ $(check_tx_stats $PRFX_VF2 1) -eq 1 ]]; then
		echo "Packets not transmitted by VF2"
		exit -1
	fi
	if [[ $(check_scapy_logs 1) -eq 1 ]]; then
		echo "Packets not received by interface on wire"
		exit -1
	fi

	testpmd_cmd $PRFX_PF "stop"
	testpmd_cmd $PRFX_VF1 "stop"
	testpmd_cmd $PRFX_VF2 "stop"
	testpmd_cmd $PRFX_PF "flow flush 0"
	testpmd_cmd $PRFX_PF "flow list 0"
	echo "test_fwd_vf2_to_wire passed"
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

init_dev
delete_scapy_logs
run_testpmds

#test_fwd_pf_to_vf1
#test_fwd_pf_to_vf2
#test_fwd_vf1_to_vf2
test_fwd_wire_to_vf2

quit_testpmds
run_testpmds

test_fwd_port_repr_2_to_vf1
test_fwd_port_repr_1_port_repr_2_pair
#test_fwd_vf2_to_wire

quit_testpmds
