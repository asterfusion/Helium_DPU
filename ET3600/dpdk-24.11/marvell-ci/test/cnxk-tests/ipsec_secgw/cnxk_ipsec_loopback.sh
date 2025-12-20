#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
PREFIX="ipsec_dpdk"
PKTLOSS_ALLOWED_P=0
IPSEC_COREMASK="0xe"

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

# Find the dpdk-ipsec-secgw application
if [[ -f $SCRIPTPATH/../../../../examples/dpdk-ipsec-secgw ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../examples/dpdk-ipsec-secgw
elif [[ -f $SCRIPTPATH/../../dpdk-ipsec-secgw ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-ipsec-secgw
else
	DPDK_TEST_BIN=$(which dpdk-ipsec-secgw)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-ipsec-secgw not found !!"
		exit 1
	fi
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
		awk ' { print FILENAME": " $0 } ' $APP_FULL_LOG
		awk ' { print FILENAME": " $0 } ' $APP_LOG
		awk ' { print FILENAME": " $0 } ' $APP_RESULT
		awk ' { print FILENAME": " $0 } ' $PING_LOG
	fi
	ip netns exec vm0 ip xfrm state deleteall
	ip netns exec vm0 ip xfrm policy deleteall
	killall -9 dpdk-ipsec-secgw
	cleanup_interfaces
	exit $status
}

# Display results for ping test
function print_result()
{
	local na
	local passed
	local failed
	local partial

	if [[ "$1" == "0%" ]]; then
		echo -e "\tPASS: no packet loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\tNo packet loss ----- PASSED" >> $APP_RESULT
		passed=$((passed + 1))
		set +e
	elif [[ "$1" == "100%" ]]; then
		echo -e "\t$1"" ERROR: packets loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\t""$1"" packets loss ----- FAILED" >> $APP_RESULT
		failed=$((failed + 1))
	elif [[ -z "$1" ]]; then
		echo -e "\tERROR: Unable to capture Results"
		echo -e "\tcase "$2"\tunable to capture Results  ----- N/A" >> $APP_RESULT
		na=$((na + 1))
	else
		echo -e "\t$1"" packets loss"
		echo -e "\t case "$2"\tpacket-size "$3"Bytes\t""$1"" packets loss ----- PARTIAL PASSED" >> $APP_RESULT
		partial=$((partial + 1))
	fi
}

# Start ping packets from interfaces for all test cases.
# This would need reconfiguration of interfaces.
function start_ping_test()
{
	local errp

	echo -e "ping_pkts :-------updated ip: 192.168.$Y.2"
	while [ $Y -le $MAX_Y ]; do
		if [[ $1 == "1" ]]; then
			if [[ $Y -gt 4 && $Y -lt 8 ]]; then
				((++Y))
				((++X))
				continue
			fi
		fi
		if [[ $1 == "2" ]] || [[ $1 == "3" ]]; then
			if [[ $Y -gt 1 && $Y -lt 8 ]]; then
				((++Y))
				((++X))
				continue
			fi
		fi
		reconfigure_interfaces
	        ip netns exec vm0 ip xfrm state list
	        ip netns exec vm0 ip xfrm policy list
		for pkt_size in $PKT_LIST
		do
			local itr=0
			echo -e "ping_pkts :-------" "$pkt_size" "$Y"

			while [ $itr -le $PING_RETRY ]; do
				ip netns exec vm0 ping 192.168.$Y.2 \
					-i $PKT_GAP -c $PING_PKTS -s \
					$pkt_size $PING_ARGS | tee -a $PING_LOG

				RESULT=`tail -n 3 $PING_LOG | \
					grep -o "\w*\.\w*%\|\w*%"`

				print_result "$RESULT" "$Y" "$pkt_size"
				errp=$(echo $RESULT | cut -c 1)

				# Break if success
				check=$(echo "$errp <= $PKTLOSS_ALLOWED_P" | bc)
				if [ $check -eq 1 ]; then break; fi
				((++itr))
			done
			# Wait until the process is killed
#			while (ps -ef | grep ping); do
#				continue
#			done

			if (( $(echo "$errp > $PKTLOSS_ALLOWED_P" | bc) )); then
				echo -e "Test Failed as packets loss $RESULT > $PKTLOSS_ALLOWED_P%"
				killall dpdk-ipsec-secgw
				# Wait until the process is killed
				while (ps -ef | grep dpdk-ipsec-secgw | grep -q $PREFIX); do
					continue
				done
				interfaces_cleanup
				exit 1
			fi
		done
		interfaces_cleanup
		((++Y))
		((++X))
	done
}

function run_test()
{
	local cmd=$1
#	nohup $cmd >> $APP_LOG 2>&1 &
	eval "nohup $1 >> $APP_LOG 2>&1 &"
	PT1="IPSEC: entering main loop on lcore"
	PT2="IPSEC: Launching event mode worker"

	local itr=0
	while ! (cat $APP_LOG | grep -q -e "$PT1" -e "$PT2")
	do
		sleep 1
		((itr+=1))

		if [[ $itr -eq 100 ]]
		then
			echo "Timeout waiting for IPSEC main loop"
			exit 2
		fi

		if [[ $((itr%5)) -eq 0 ]]
		then echo "Waiting for IPSEC main loop"; fi
	done
	sleep 5

	echo "Starting ping test" | tee $PING_LOG
	start_ping_test $2

	killall dpdk-ipsec-secgw
	# Wait until the process is killed
	while (ps -ef | grep dpdk-ipsec-secgw | grep -q $PREFIX); do
		continue
	done

	rm -rf /var/run/dpdk/$PREFIX
	sync
	cat $APP_LOG >>$APP_FULL_LOG
	rm -rf $APP_LOG
}

function run_ipsec_secgw_cn9k()
{
	# DPDK IPSEC-SECGW App - lookaside none mode
	X=101
	Y=1
	echo -e "Lookaside none ipsec-secgw"
	echo -e "--------------------------"
	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_crypto_test.cfg --config="(0,0,1),(1,0,2)"' 0

	sleep 5
	# DPDK IPSEC-SECGW App - lookaside protocol mode
	X=101
	Y=1
	echo -e ""
	echo -e "Lookaside protocol ipsec-secgw"
	echo -e "------------------------------"
	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_lookaside_test.cfg --config="(0,0,1),(1,0,2)"' 1

	sleep 5
	# DPDK IPSEC-SECGW App - inline protocol event mode
	X=101
	Y=1
	echo -e ""
	echo -e "Inline protocol ipsec-secgw event mode"
	echo -e "---------------------------"
	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 -- -P -p 0x3 -u 0x1 -f ./ep1_inline_test.cfg --transfer-mode event --event-schedule-type parallel' 2
}

function run_ipsec_secgw_cn10k()
{
	# DPDK IPSEC-SECGW App - lookaside none mode
	X=101
	Y=1
#	echo -e "Lookaside none ipsec-secgw"
#	echo -e "--------------------------"
#	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_crypto_test.cfg --config="(0,0,1),(1,0,2)"' 0

	sleep 5
	# DPDK IPSEC-SECGW App - lookaside protocol mode
	X=101
	Y=1
#	echo -e ""
#	echo -e "Lookaside protocol ipsec-secgw"
#	echo -e "------------------------------"
#	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_lookaside_test.cfg --config="(0,0,1),(1,0,2)"' 1

	sleep 5
	# DPDK IPSEC-SECGW App - inline protocol event mode
	X=101
	Y=1
	echo -e ""
	echo -e "Inline protocol ipsec-secgw event mode"
	echo -e "---------------------------"
	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_inline_test.cfg --transfer-mode event --event-schedule-type parallel' 2

	sleep 5
	# DPDK IPSEC-SECGW App - inline protocol poll mode
	X=101
	Y=1
	echo -e ""
	echo -e "Inline protocol ipsec-secgw poll mode"
	echo -e "---------------------------"
	run_test '$DPDK_TEST_BIN -c $IPSEC_COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $LIF2,ipsec_in_max_spi=128 -a $LIF4,ipsec_in_max_spi=128 --file-prefix $PREFIX -- -P -p 0x3 -u 0x1 -f ./ep1_inline_test.cfg --transfer-mode poll --config="(0,0,1),(1,0,2)"' 3
}

#configure vm0
function configure_vm0()
{
	ip netns exec vm0 ip addr add 192.168.$X.2/24 dev $LBK1
	ip netns exec vm0 ip addr add 1.1.$Y.1/24 dev $LBK1:1
	ip netns exec vm0 ip link set $LBK1 up
	ip netns exec vm0 ip link set $LBK1 address $VM0_MAC
	ip netns exec vm0 ip route add 192.168.$Y.0/24 via 192.168.$X.1
	ip netns exec vm0 arp -s 192.168.$X.1 $VM0_MAC
	ip netns exec vm0 arp -s 1.1.$Y.2 $VM0_MAC
	ip netns exec vm0 ip xfrm state add src 1.1.$Y.1 dst 1.1.$Y.2 proto esp spi $Y reqid 0 mode tunnel ${CASE[$Y]}
	ip netns exec vm0 ip xfrm state add src 1.1.$Y.2 dst 1.1.$Y.1 proto esp spi $X reqid 0 mode tunnel ${CASE[$Y]}
	ip netns exec vm0 ip xfrm policy add src 192.168.$X.2 dst 192.168.$Y.2 dir out tmpl src 1.1.$Y.1 dst 1.1.$Y.2 proto esp spi $Y reqid 0 mode tunnel
	ip netns exec vm0 ip xfrm policy add src 192.168.$Y.2 dst 192.168.$X.2 dir in tmpl src 1.1.$Y.2 dst 1.1.$Y.1 proto esp spi $X reqid 0 mode tunnel
}

#configure vm2
function configure_vm2()
{
	ip netns exec vm2 ip addr add 192.168.$Y.2/24 dev $LBK3
	ip netns exec vm2 ip link set $LBK3 up
	ip netns exec vm2 ip link set lo up
	ip netns exec vm2 ip link set $LBK3 address $VM2_MAC
	ip netns exec vm2 ip route add 192.168.$X.0/24 via 192.168.$Y.1
	ip netns exec vm2 arp -s 192.168.$Y.1 $VM2_MAC
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "Create namespaces"
	ip netns add vm0
	ip netns add vm2

	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"
	$VFIO_DEVBIND -b $NICVF $LIF1
	#$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF3
	#$VFIO_DEVBIND -b $NICVF $LIF4

	echo -e "Bind LBK devices required to act as LBK pairs b/w DPDK and Linux"
	$VFIO_DEVBIND -b vfio-pci $LIF2
	$VFIO_DEVBIND -b vfio-pci $LIF4

	LBK1=`ls /sys/bus/pci/devices/$LIF1/net/`
	LBK3=`ls /sys/bus/pci/devices/$LIF3/net/`

	echo -e "Add devices in namespaces $LBK1 $LBK3"
	ip link set dev $LBK1 netns vm0
	ip link set dev $LBK3 netns vm2
}

function interfaces_cleanup()
{
	echo -e "\ninterfaces_cleanup"
	ip netns exec vm0 ip xfrm state deleteall
	ip netns exec vm0 ip xfrm policy deleteall
	ip netns exec vm0 arp -d 192.168.$X.1
	ip netns exec vm0 arp -d 1.1.$Y.2
	ip netns exec vm0 ip route del 192.168.$Y.0/24
	ip netns exec vm0 ip addr del 192.168.$X.2/24 dev $LBK1
	ip netns exec vm0 ip addr del 1.1.$Y.1/24 dev $LBK1:1
	ip netns exec vm0 ip link set $LBK1 down

	ip netns exec vm2 ip route del 192.168.$X.0/24
	ip netns exec vm2 arp -d 192.168.$Y.1
	ip netns exec vm2 ip addr del 192.168.$Y.2/24 dev $LBK3
	ip netns exec vm2 ip link set $LBK3 down
	ip netns exec vm2 ip link set lo down
}

function reconfigure_interfaces()
{
	echo -e "\nreconfigure_interfaces"

	# Configure vm0
	configure_vm0
	# Configure vm2
	configure_vm2
}

function cleanup_interfaces()
{
	ip netns del vm0
	ip netns del vm2

	# Bind the LIF2 device back to nicvf
	$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF4
}

function main()
{
	setup_interfaces
	if [[ $IS_CN10K -ne 0 ]]
	then
		run_ipsec_secgw_cn10k
	else
		run_ipsec_secgw_cn9k
	fi
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# script's starting point
CASE=(
	""
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth    sha1    0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth-trunc    sha256  0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth-trunc    sha256  0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"enc    cbc(aes)        0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth-trunc    sha256  0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"enc    rfc3686(ctr(aes))       0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth    sha1    0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
	"enc    rfc3686(ctr(aes))       0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth-trunc    sha256  0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"enc    cbc(des3_ede)   0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0      auth    sha1    0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
	"aead  rfc4106(gcm(aes))       0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"aead  rfc4106(gcm(aes))       0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
	"aead  rfc4106(gcm(aes))       0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0 128"
)

PING_RETRY=1
PING_PKTS=320
PKT_LIST="64 380 1410"
PKT_GAP="0.001"
PING_ARGS=""

#VM0_MAC and VM2_MAC are taken from hard coded destination MAC addresses of ipsec-secgw app
VM0_MAC=00:16:3e:7e:94:9a
VM2_MAC=00:16:3e:22:a1:d9

LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?
! $(cat /proc/device-tree/soc@0/runplatform | grep -q "ASIM_PLATFORM")
IS_ASIM=$?

if [[ $IS_ASIM -ne 0 ]]
then
	PING_PKTS=10
	PKT_GAP=1
	# Wait for more time in case of ASIM
	PING_ARGS="-W 3"
	PING_RETRY=5
fi

CDEV_PF=$(lspci -d :a0fd | head -1 | awk -e '{ print $1 }')
CDEV_VF=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
if [ -z "$CDEV_PF" ]
then
	CDEV_PF=$(lspci -d :a0f2 | head -1 | awk -e '{ print $1 }')
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	if [ -z "$CDEV_PF" ]
	then
		echo "Error: CPTPF not found"
		exit 1;
	fi
fi

INLINE_DEV=0002:1d:00.0
SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_VF=$SSO_DEV

LBK1=""
LBK3=""

APP_LOG=app.log
APP_FULL_LOG=app_full.log
APP_RESULT=app_result.log
PING_LOG=ping.log
VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
if ! [[ -f $VFIO_DEVBIND ]]
then
VFIO_DEVBIND=$(which oxk-devbind-basic.sh)
fi

rm -f $APP_LOG $APP_FULL_LOG $APP_RESULT $PING_LOG

MAX_X=110
MAX_Y=10

main
exit 0
