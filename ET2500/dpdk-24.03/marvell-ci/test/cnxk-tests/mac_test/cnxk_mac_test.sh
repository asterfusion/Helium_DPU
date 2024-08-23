#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."
source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/pcap/pcap.env

MCAST_MAC_PCAP="mcast_in.pcap"
UCAST_MAC_PCAP="ucast_in.pcap"
MTU_64B_PCAP="mtu_64B_in.pcap"
MTU_1518B_PCAP="mtu_1518B_in.pcap"
MACFLTR_PORT="0002:02:00.0"
MACFLTR_PORT_INDEX=0
PRFX="macfltr"
COREMASK="0xC"
NUM_MAX_MAC=0
OFF=0

# Get list of MAC address from pcap. Tshark is not used to parse the pcap as it
# may not be by-default present in all distros.
MCAST_DMAC_ARR=$(pcap_packet_dmac $MCAST_MAC_PCAP)
UCAST_DMAC_ARR=$(pcap_packet_dmac $UCAST_MAC_PCAP)

IFS=$'\n' MCAST_DMAC_ARR=($(sort <<<"${MCAST_DMAC_ARR[*]}"))
MCAST_DMAC_PKT_CNT=${#MCAST_DMAC_ARR[@]}
MCAST_DMAC_ARR=($(uniq <<<"${MCAST_DMAC_ARR[*]}"))
unset IFS

IFS=$'\n' UCAST_DMAC_ARR=($(sort <<<"${UCAST_DMAC_ARR[*]}"))
UCAST_DMAC_PKT_CNT=${#UCAST_DMAC_ARR[@]}
UCAST_DMAC_ARR=($(uniq <<<"${UCAST_DMAC_ARR[*]}"))
unset IFS

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
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

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

if [[ $IS_CN10K -ne 0 ]]; then
	MAX_MTU=16350
else
	MAX_MTU=9182
fi

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
		testpmd_log_off $PRFX $OFF
	fi

	macfltr_cleanup
	#Bind interface back to kernel
	macfltr_cleanup_interface
	exit $status
}

function macfltr_cleanup_interface()
{
	$VFIO_DEVBIND -b $NICVF $MACFLTR_PORT
}

function macfltr_bind_interface()
{
	$VFIO_DEVBIND -b vfio-pci $MACFLTR_PORT
}

function macfltr_cleanup()
{
	testpmd_quit $PRFX
	testpmd_cleanup $PRFX
	sleep 2
}

function macfltr_launch()
{
	local opts
	local coremask="0x3"
	local port="0002:01:00.1"
	local pcapin=$macfltr_SCRIPT_PATH/../pcap/sample.pcap

	if ! opts=$(getopt \
	        -o "i:p:c:" \
		-l "in-pcap:,port:,coremask:" \
		-- "$@"); then
		echo "Failed to parse macfltr arguments"
		exit 1
	fi

	eval set -- "$opts"
	while [[ $# -gt 1 ]]; do
		case $1 in
			-i|--in-pcap) shift; pcapin=$1;;
			-p|--port) shift; port=$1;;
			-c|--coremask) shift; coremask=$1;;
			*) echo "Unknown macfltr argument"; exit 1;;
		esac
		shift
	done

	testpmd_launch $PRFX \
		"-c $coremask -a $port --vdev eth_pcap0,rx_pcap=$pcapin,tx_pcap=out.pcap" \
		"--port-topology=paired --portlist=0,1 --no-flush-rx --max-pkt-len=9200 --mbuf-size=4096"
}

function macfltr_pkt_test_verify()
{
	tx_count=`testpmd_port_tx_count $PRFX $MACFLTR_PORT_INDEX`
	#Wait until to read valid counters
	while ! [[ $tx_count =~ ^[-+]?[0-9]+$ ]]
	do
		sleep 1
		tx_count=`testpmd_port_tx_count $PRFX $MACFLTR_PORT_INDEX`
	done
	# Wait for receiving all packets
	start_ts=`date +%s`
	start_ts=$((start_ts + 60))
	while [[ $tx_count -lt $1 ]]
	do
		sleep 0.1
		tx_count=`testpmd_port_tx_count $PRFX $MACFLTR_PORT_INDEX`
		ts=`date +%s`
		if (( $ts > $start_ts ))
		then
			echo "Timeout unable to received $EXPECTED_CNT packets"
			cleanup_interface
			exit 1
		fi

	done

	rx_count=`testpmd_port_rx_count $PRFX $MACFLTR_PORT_INDEX`
	#Wait until to read valid counters
	sleep 5
	rx_count=`testpmd_port_rx_count $PRFX $MACFLTR_PORT_INDEX`

	# As the loopback is configured, packets egressing from the port 0 shall
	# be looped back to ingress from the same port. tx_count would be
	# incremented during egress and rx_count would be incremented for the
	# number of packets allowed in by the LMAC. The difference would give
	# the number of packets dropped.
	pkt_drop=`expr $tx_count - $rx_count`

	OFF=`testpmd_log_sz $PRFX`
	testpmd_cmd $PRFX "show port xstats $MACFLTR_PORT_INDEX"
	sleep 5
	# cgx_rx_dmac_filt_pkts is xstats counter which counts the number of
	# packets with MAC address are filtered and dropped. This is a hardware
	# counter.
	rx_filter_pkts_af=$(macfltr_dmac_filt_pkts $OFF)
	xstats_pkt_drop=`expr $rx_filter_pkts_af - $rx_filter_pkts`

	# pcap contains 2 packets of the configured mcast mac address.
	if [[ $xstats_pkt_drop -ne $pkt_drop ]]
	then
		echo "MAC filtering not working"
		exit 1
	fi
}
function check_port_status()
{
	# Wait for receiving all packets
	start_ts=`date +%s`
	start_ts=$((start_ts + 60))
	link_status=""
	while [[ "$link_status" != " up" ]]
	do
		OFF=`testpmd_log_sz $PRFX`
		testpmd_cmd $PRFX "show port info $1"
		sleep 3
		link_status=`testpmd_log_off $PRFX $OFF | \
			grep "Link status: " | cut --complement -f 1 -d ":"`
		ts=`date +%s`
		if (( $ts > $start_ts ))
		then
			echo "Timeout port is down"
			cleanup_interface
			exit 1
		fi
		echo "link status $link_status"
	done
}

function macfltr_pkt_test()
{
	testpmd_cmd_refresh $PRFX "port stop $1"
	testpmd_cmd_refresh $PRFX "port config $1 loopback 1"
	testpmd_cmd_refresh $PRFX "port start $1"
	check_port_status $1

	if [[ $3 == "mcast" ]]
	then
		testpmd_cmd_refresh $PRFX "mcast_addr add $1 $2"
		NUM_PKTS=$MCAST_DMAC_PKT_CNT
	else
		testpmd_cmd_refresh $PRFX "mac_addr add $1 $2"
		NUM_PKTS=$UCAST_DMAC_PKT_CNT
	fi

	testpmd_cmd_refresh $PRFX "clear port stats all"
	testpmd_cmd_refresh $PRFX "start"
	macfltr_pkt_test_verify $NUM_PKTS
}

function macfltr_dmac_filt_pkts()
{
	if [[ $IS_CN10K -ne 0 ]]; then
		cat /sys/kernel/debug/cn10k/rpm/rpm0/lmac0/mac_filter |\
			 grep -a "DMAC filter drop count" | cut --complement -f 1 -d ":"
	else
		testpmd_log_off $PRFX $1 |\
			grep -a "cgx_rx_dmac_filt_pkts: "|\
			cut --complement -f 1 -d ":"
	fi
}

function macfltr_mac_cnt()
{
	testpmd_log_off $PRFX $1 | \
		grep -a "Number of MAC address added: "| \
		cut --complement -f 1 -d ":"
}

function macfltr_mcast_mac_cnt()
{
	testpmd_log_off $PRFX $1 | \
		grep -a "Multicast MAC address added: "| \
		cut --complement -f 1 -d ":"
}

function xmit_pkts()
{
	testpmd_cmd_refresh $PRFX "port stop $1"
	testpmd_cmd_refresh $PRFX "port config $1 loopback 1"
	testpmd_cmd_refresh $PRFX "port start $1"
	check_port_status $1
	testpmd_cmd_refresh $PRFX "clear port stats all"
	testpmd_cmd_refresh $PRFX "start"
}

# Register signal handlers.
trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# Bind the port to vfio-pci
macfltr_bind_interface $MACFLTR_PORT

echo "Starting unicast macfltr with port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $UCAST_MAC_PCAP


# Get MAX number of MAC's supported by the port.
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port info $MACFLTR_PORT_INDEX"
sleep 1
NUM_MAX_MAC=`testpmd_log_off $PRFX $OFF | \
	grep "Maximum number of MAC addresses: " | cut --complement -f 1 -d ":"`
NUM_MAX_MAC=`expr $NUM_MAX_MAC - 1`

# Minimum number of MAC address from the unicast mac address list or the
# configured one shall be considered.
if [[ ${#UCAST_DMAC_ARR[@]} -le $NUM_MAX_MAC ]]
then
	NUM_MAX_UCAST_MAC=${#UCAST_DMAC_ARR[@]}
else
	NUM_MAX_UCAST_MAC=`expr $NUM_MAX_MAC + 1`
fi

# Minimum number of MAC address from the multicast mac address list or the
# configured one shall be considered.
if [[ ${#MCAST_DMAC_ARR[@]} -le $NUM_MAX_MAC ]]
then
	NUM_MAX_MCAST_MAC=${#MCAST_DMAC_ARR[@]}
else
	NUM_MAX_MCAST_MAC=`expr $NUM_MAX_MAC + 1`
fi

# Tailing and greping the strings for verifying number of MAC address configured
# depends on the number MAC address in list.
MAC_UCAST_TAIL_LINES=`expr $NUM_MAX_UCAST_MAC + 5`
MAC_MCAST_TAIL_LINES=`expr $NUM_MAX_MCAST_MAC + 5`

#Test-1: verify configuring default mac.
echo "**** Test-1 Verify configuring default MAC address. ****"
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show device info $MACFLTR_PORT"
sleep 1
DEF_MAC=`testpmd_log_off $PRFX $OFF | grep "MAC address: " | \
	cut --complement -f 1 -d ":"`

testpmd_cmd_refresh $PRFX "mac_addr set $MACFLTR_PORT_INDEX ${UCAST_DMAC_ARR[0]}"

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show device info $MACFLTR_PORT"
sleep 1
NEW_MAC=`testpmd_log_off $PRFX $OFF | grep "MAC address: " | \
	cut --complement -f 1 -d ":"`
# The MAC address in show command are in upper case and the MAC address in the
# MAC address list are in lower case. Hence to match it up nocasematch is used.
shopt -s nocasematch
if [[ "$NEW_MAC" == "${UCAST_DMAC_ARR[0]}" ]]
then
	echo "MAC address set successful"
else
	echo "MAC address set failure"
	exit 1
fi
shopt -u nocasematch
##


#Test-2: verify the packets after configuring default unicast mac address.
OFF=`testpmd_log_sz $PRFX`
echo "**** Test-2 Verify packets with unicast mac filter  ****"
testpmd_cmd $PRFX "show port xstats $MACFLTR_PORT_INDEX"
sleep 5
rx_filter_pkts=$(macfltr_dmac_filt_pkts $OFF)
macfltr_pkt_test $MACFLTR_PORT_INDEX ${UCAST_DMAC_ARR[0]} "unicast"
echo "$rx_count packets with configured unicast MAC address \
(${UCAST_DMAC_ARR[0]}) received successful."
##

#Set back original MAC
testpmd_cmd_refresh $PRFX "mac_addr set $MACFLTR_PORT_INDEX $DEF_MAC"
##


# Test completed. Quit testpmd.
echo "Stop testpmd and exit."
macfltr_cleanup

OFF=`testpmd_log_sz $PRFX`
echo "Starting unicast macfltr with port=$MACFLTR_PORT, poremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $UCAST_MAC_PCAP

#Test-3: verify adding unicast mac address.
echo "**** Test-3 Verify configuring max:$NUM_MAX_UCAST_MAC unicast MAC "\
	"address for LMAC ****"
mac=0
while [ $mac -lt $NUM_MAX_UCAST_MAC ]
do
	testpmd_cmd_refresh $PRFX \
		"mac_addr add $MACFLTR_PORT_INDEX ${UCAST_DMAC_ARR[$mac]}"
	let "mac+=1"
done

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port $MACFLTR_PORT_INDEX macs"
sleep 1
CNT=$(macfltr_mac_cnt $OFF)
if [[ $CNT -eq $NUM_MAX_UCAST_MAC ]] || \
	[[ $CNT -eq $(expr $NUM_MAX_UCAST_MAC - 1) ]]
then
	echo "Total $CNT unicast MAC addresses add successful"
else
	echo "Total $CNT unicast MAC addresses add failure"
	exit 1
fi
##


#Test-4: verify deleting unicast mac address.
echo "**** Test-4 Verify deleting unicast MAC address for LMAC configured "\
	"in Test-3 ****"
mac=0
while [ $mac -lt $NUM_MAX_UCAST_MAC ]
do
	testpmd_cmd_refresh $PRFX \
		"mac_addr remove $MACFLTR_PORT_INDEX ${UCAST_DMAC_ARR[$mac]}"
	let "mac+=1"
done

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port $MACFLTR_PORT_INDEX macs"
sleep 1
CNT=$(macfltr_mac_cnt $OFF)
if [[ $CNT -eq 1 ]]
then
	echo "Unicast MAC addresses remove successful"
else
	echo "Unicast MAC address remove failure"
	exit 1
fi
##


#Test-5: verify the packets after configuring unicast mac address.
echo "**** Test-5 Verify packets with unicast mac filter  ****"
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port xstats $MACFLTR_PORT_INDEX"
sleep 5
rx_filter_pkts=$(macfltr_dmac_filt_pkts $OFF)
macfltr_pkt_test $MACFLTR_PORT_INDEX ${UCAST_DMAC_ARR[1]} "unicast"
echo "$rx_count packets with configured unicast MAC address \
(${UCAST_DMAC_ARR[1]}) received successful."
##


# Unicast test completed. Stop testpmd.
echo "Stop testpmd and exit."
macfltr_cleanup

echo "Starting multicast macfltr with port=$MACFLTR_PORT, poremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MCAST_MAC_PCAP


#Test-6: verify configuring max multicast mac address.
echo "**** Test-6 Verify configuring max:$NUM_MAX_MCAST_MAC multicast MAC "\
	"address for LMAC ****"
mac=0
while [ $mac -lt $NUM_MAX_MCAST_MAC ]
do
	testpmd_cmd_refresh $PRFX \
		"mcast_addr add $MACFLTR_PORT_INDEX ${MCAST_DMAC_ARR[$mac]}"
	let "mac+=1"
done

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port $MACFLTR_PORT_INDEX mcast_macs"
sleep 1
CNT=$(macfltr_mcast_mac_cnt $OFF)
if [[ $CNT -eq $NUM_MAX_MAC ]] || [[ $CNT -eq $NUM_MAX_MCAST_MAC ]]
then
	echo "Total $CNT multicast MAC addresses add successful"
else
	echo "Total $CNT multicast MAC addresses add failure"
	exit 1
fi
##


#Test-7: verify deleting multicast mac address.
echo "**** Test-7 Verify configuring max multicast MAC address for LMAC ****"
mac=0
while [ $mac -lt $NUM_MAX_MCAST_MAC ]
do
	testpmd_cmd_refresh $PRFX \
		"mcast_addr remove $MACFLTR_PORT_INDEX ${MCAST_DMAC_ARR[$mac]}"
	let "mac+=1"
done

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port $MACFLTR_PORT_INDEX mcast_macs"
sleep 1
CNT=$(macfltr_mcast_mac_cnt $OFF)
if [[ $CNT -eq 0 ]]
then
	echo "Multicast MAC addresses remove successful"
else
	echo "Multicast MAC addresses remove failure"
	exit 1
fi
##


#Test-8: verify the packets after configuring multicast mac address.
echo "**** Test-8 Verify packets with mcast mac filter  ****"
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port xstats $MACFLTR_PORT_INDEX"
sleep 5
rx_filter_pkts=$(macfltr_dmac_filt_pkts $OFF)
macfltr_pkt_test $MACFLTR_PORT_INDEX ${MCAST_DMAC_ARR[0]} "mcast"
echo "$rx_count packets with configured mcast MAC address \
(${MCAST_DMAC_ARR[0]}) received successful."
##

macfltr_cleanup

#Test-9: verify MTU configuration lesser than minimum.
echo "Test-9: MTU lesser than min for port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MTU_64B_PCAP
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "port config mtu $MACFLTR_PORT_INDEX 10"
sleep 1

STRING=`testpmd_log_off $PRFX $OFF | grep "MTU (10) < device min MTU"`
if [[ $STRING != "MTU (10) < device min MTU (18) for port_id 0" ]]
then
	echo "Test-9: MTU configuration lesser than minimum failed"
	exit 1
fi

echo "Test-9: Successful"
macfltr_cleanup

#Test-10: verify MTU configuration equals to minimum.
echo "Test-10: MTU equals to minimum for port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MTU_64B_PCAP
testpmd_cmd $PRFX "port config mtu $MACFLTR_PORT_INDEX 64"
sleep 1

xmit_pkts $MACFLTR_PORT_INDEX
sleep 5

testpmd_cmd $PRFX "show port stats $MACFLTR_PORT_INDEX"
sleep 5

rx_count=`testpmd_port_rx_count $PRFX $MACFLTR_PORT_INDEX`
if [[ $rx_count != 2 ]]
then
	echo "Test-10: MTU-test 64 bytes failed"
	exit 1
fi

echo "Test-10: Successful"
macfltr_cleanup

#Test-11: verify MTU configuration between to minimum and maximum.
echo "Test-11: MTU between min & max for port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MTU_1518B_PCAP
testpmd_cmd $PRFX "port config mtu $MACFLTR_PORT_INDEX 1518"
sleep 1

xmit_pkts $MACFLTR_PORT_INDEX
sleep 5

testpmd_cmd $PRFX "show port stats $MACFLTR_PORT_INDEX"
sleep 5

rx_count=`testpmd_port_rx_count $PRFX $MACFLTR_PORT_INDEX`
if [[ $rx_count != 3 ]]
then
	echo "Test-11: MTU-test 1518 bytes failed"
	exit 1
fi

echo "Test-11: Successful"
macfltr_cleanup

#Test-12: verify MTU configuration equals to maximum.
echo "Test-12: MTU equals to max for port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MTU_1518B_PCAP

testpmd_cmd $PRFX "port stop all"
sleep 1

testpmd_cmd $PRFX "port config $MACFLTR_PORT_INDEX rx_offload scatter on"
sleep 1

testpmd_cmd $PRFX "port start all"
sleep 1

OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "show port info $MACFLTR_PORT_INDEX"
sleep 1

MAX_RX_LEN=`testpmd_log_off $PRFX $OFF | \
	grep "Maximum configurable length of RX packet: " |\
	cut --complement -f 1 -d ":"`

MAX_RX_LEN=`expr $MAX_RX_LEN - 26`

testpmd_cmd $PRFX "port config mtu $MACFLTR_PORT_INDEX $MAX_RX_LEN"
sleep 1

xmit_pkts $MACFLTR_PORT_INDEX
sleep 5

testpmd_cmd $PRFX "show port stats $MACFLTR_PORT_INDEX"
sleep 5

rx_count=`testpmd_port_rx_count $PRFX $MACFLTR_PORT_INDEX`
if [[ $rx_count != 3 ]]
then
	echo "Test-12: MTU-test $MAX_RX_LEN bytes failed"
	exit 1
fi

echo "Test-12: Successful"
macfltr_cleanup

#Test-13: verify MTU configuration greater than maximum.
echo "Test-13: MTU more than max for port=$MACFLTR_PORT, coremask=$COREMASK"
macfltr_launch -c $COREMASK -p $MACFLTR_PORT -i $MTU_1518B_PCAP
OFF=`testpmd_log_sz $PRFX`
testpmd_cmd $PRFX "port config mtu $MACFLTR_PORT_INDEX 20000"
sleep 1

STRING=`testpmd_log_off $PRFX $OFF | grep "MTU (20000) > device max MTU" | cut -f 1 -d "."`
if [[ $STRING != "MTU (20000) > device max MTU ($MAX_MTU) for port_id 0" ]]
then
	echo "Test-13: MTU configuration more than maximum failed"
	exit 1
fi

echo "Test-13: Successful"

macfltr_cleanup
macfltr_cleanup_interface

echo "SUCCESS: testpmd mac test completed"
