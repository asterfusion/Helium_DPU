#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )/.."

source $CNXKTESTPATH/common/testpmd/common.env
source $CNXKTESTPATH/common/pcap/pcap.env

PRFX="tx-chksum"
CAP_PRFX="tx-chksum-cap"
TMP_DIR=/tmp/dpdk-$PRFX

if [[ "$1" == "--mseg" ]]
then
	need_mseg=1
	TX_PCAP="$CNXKTESTPATH/tx_chksum/in_mseg.pcap"
	EXPECTED_PCAP="$CNXKTESTPATH/tx_chksum/out_mseg.pcap"
else
	need_mseg=0
	TX_PCAP="$CNXKTESTPATH/tx_chksum/in.pcap"
	EXPECTED_PCAP="$CNXKTESTPATH/tx_chksum/out.pcap"
fi

EXPECTED_NON_UDP_TUN_PCAP="$TMP_DIR/out_non_udp_tun.pcap"
RECV_PCAP="recv.pcap"
PORT0="0002:01:00.1"
PORT1="--vdev net_pcap0,rx_pcap=$TX_PCAP"
INLINE_DEV="0002:1d:00.0"
PORT2="-a $INLINE_DEV"
CAP_PORT0="0002:01:00.2"
CAP_PORT1="--vdev net_pcap0,tx_pcap=$TMP_DIR/for-$RECV_PCAP"
COREMASK="0x3"
CAP_COREMASK="0xc"
# UDP tunnel ports for VXLAN and GENEVE
UDP_TUNNEL_FILTER="not udp port 4789 and not udp port 6081"
OFF=0

rm -rf $TMP_DIR
mkdir -p $TMP_DIR

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
		testpmd_log_off $PRFX $OFF
	fi

	testpmd_cleanup $PRFX
	testpmd_cleanup $CAP_PRFX
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

tx_offloads=(
	"0x010000"  #None(Fast free)
	"0x01001e"  #L3L4CSUM_F
	"0x110080"  #OL3OL4CSUM_F
	"0x11009e"  #OL3OL4CSUM_F | L3L4CSUM_F
	"0x010001"  #VLAN_F
	"0x01001f"  #L3L4CSUM_F | VLAN_F
	"0x110081"  #OL3OL4CSUM_F | VLAN_F
	"0x11009f"  #OL3OL4CSUM_F | L3L4CSUM_F | VLAN_F
	"0x030000"  #SEC_F
	"0x03001e"  #SEC_F | L3L4CSUM_F
	"0x130080"  #SEC_F | OL3OL4CSUM_F
	"0x13009e"  #SEC_F | OL3OL4CSUM_F | L3L4CSUM_F
	"0x030001"  #SEC_F | VLAN_F
	"0x03001f"  #SEC_F | L3L4CSUM_F | VLAN_F
	"0x130081"  #SEC_F | OL3OL4CSUM_F | VLAN_F
	"0x13009f"  #SEC_F | OL3OL4CSUM_F | L3L4CSUM_F | VLAN_F
	"0x018000"  #MSEG_F
	"0x01801e"  #MSEG_F | L3L4CSUM_F
	"0x008000"  #MSEG_F | NO_FF
	"0x118080"  #MSEG | OL3OL4CSUM_F
	"0x11809e"  #MSEG | OL3OL4CSUM_F | L3L4CSUM_F
	"0x018001"  #MSEG | VLAN_F
	"0x01801f"  #MSEG | L3L4CSUM_F | VLAN_F
	"0x118081"  #MSEG | OL3OL4CSUM_F | VLAN_F
	"0x11809f"  #MSEG | OL3OL4CSUM_F | L3L4CSUM_F | VLAN_F
	"0x038000"  #MSEG | SEC_F
	"0x03801e"  #MSEG | SEC_F | L3L4CSUM_F
	"0x138080"  #MSEG | SEC_F | OL3OL4CSUM_F
	"0x13809e"  #MSEG | SEC_F | OL3OL4CSUM_F | L3L4CSUM_F
	"0x038001"  #MSEG | SEC_F | VLAN_F
	"0x03801f"  #MSEG | SEC_F | L3L4CSUM_F | VLAN_F
	"0x138081"  #MSEG | SEC_F | OL3OL4CSUM_F | VLAN_F
	"0x13809f"  #MSEG | SEC_F | OL3OL4CSUM_F | L3L4CSUM_F | VLAN_F
	"0x12809f"  #MSEG | SEC_F | OL3OL4CSUM_F | L3L4CSUM_F | VLAN_F | NO_FF
	)

max=${#tx_offloads[@]}
((--max))

i=0
skip_udp_tunnel=1
skip_tx_security=0

# Skip security if not in cn10k
PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$') || true
if [[ "$PARTNUM" == "0x0b1" ]] || [[ "$PARTNUM" == "0x0b2" ]]
then
	PORT2=""
	skip_tx_security=1
fi

function start_capture()
{
	rm -rf $TMP_DIR/for-$RECV_PCAP
	rm -rf $TMP_DIR/$RECV_PCAP
	testpmd_cmd $CAP_PRFX "port start all"
	testpmd_cmd $CAP_PRFX "start"
}

function capture_count()
{
	testpmd_cmd $CAP_PRFX "show port stats 1"
	val=`testpmd_log $CAP_PRFX | tail -7 | grep -ao "TX-packets: [0-9]*"| \
		cut -f 2 -d ":"`
	echo $val
}

function stop_capture()
{
	testpmd_cmd $CAP_PRFX "stop"
	testpmd_cmd $CAP_PRFX "port stop all"
	testpmd_cmd $CAP_PRFX "clear port stats all"

	cp $TMP_DIR/for-$RECV_PCAP $TMP_DIR/$RECV_PCAP
}

function setup_tx_offload()
{
	local tx_off=$1
	local idx=$2

	# Turn off everything first
	testpmd_cmd $PRFX "port config 0 tx_offload vlan_insert off"
	testpmd_cmd $PRFX "port config 0 tx_offload ipv4_cksum off"
	testpmd_cmd $PRFX "port config 0 tx_offload udp_cksum off"
	testpmd_cmd $PRFX "port config 0 tx_offload tcp_cksum off"
	testpmd_cmd $PRFX "port config 0 tx_offload sctp_cksum off"
	testpmd_cmd $PRFX "port config 0 tx_offload outer_ipv4_cksum off"
	testpmd_cmd $PRFX "port config 0 tx_offload multi_segs off"
	testpmd_cmd $PRFX "port config 0 tx_offload security off"
	testpmd_cmd $PRFX "csum set outer-udp sw 0"
	testpmd_cmd $PRFX "port config 0 rx_offload scatter off"
	testpmd_cmd $PRFX "port config mtu 0 1500"
	testpmd_cmd $PRFX "port config 0 tx_offload mbuf_fast_free off"

	# Skip UDP tunnel packets if outer udp checksum is not enabled
	skip_udp_tunnel=1

	if ((tx_off & 0x1))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload vlan_insert on"
	fi
	if ((tx_off & 0x2))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload ipv4_cksum on"
	fi
	if ((tx_off & 0x4))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload udp_cksum on"
	fi
	if ((tx_off & 0x8))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload tcp_cksum on"
	fi
	if ((tx_off & 0x10))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload sctp_cksum on"
	fi
	if ((tx_off & 0x80))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload outer_ipv4_cksum on"
	fi
	if ((tx_off & 0x8000))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload multi_segs on"
		testpmd_cmd $PRFX "port config 0 rx_offload scatter on"
		if [[ $need_mseg == 1 ]]
		then
			testpmd_cmd $PRFX "port config mtu 0 9000"
		fi
	fi
	if ((tx_off & 0x10000))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload mbuf_fast_free on"
	fi
	if ((tx_off & 0x20000))
	then
		testpmd_cmd $PRFX "port config 0 tx_offload security on"
	fi
	if ((tx_off & 0x100000))
	then
		# Outer udp checksum is not available via port config cmd
		testpmd_cmd $PRFX "csum set outer-udp hw 0"
		skip_udp_tunnel=0
	fi

	# Toggle burst size
	if (( idx & 0x1 ))
	then
		testpmd_cmd $PRFX "port config all burst 135"
	else
		testpmd_cmd $PRFX "port config all burst 63"
	fi

	# Show log till now
	testpmd_log_off $PRFX $OFF
	OFF=`testpmd_log_sz $PRFX`
}

tcpdump -nr $TX_PCAP -xvve -t >$TMP_DIR/sent.txt
tcpdump -nr $EXPECTED_PCAP -xvve -t >$TMP_DIR/expect.txt
tcpdump -nr $EXPECTED_PCAP -w $EXPECTED_NON_UDP_TUN_PCAP $UDP_TUNNEL_FILTER
tcpdump -nr $EXPECTED_NON_UDP_TUN_PCAP -xvve \
		-t  >$TMP_DIR/expect_non_udp_tun.txt

EXPECTED_CNT=$(pcap_packet_count $EXPECTED_PCAP)
EXPECTED_NON_UDP_TUN_CNT=$(pcap_packet_count $EXPECTED_NON_UDP_TUN_PCAP)

echo "Testpmd running with $PORT0, $PORT1, Coremask=$COREMASK"
testpmd_launch $PRFX \
	"-c $COREMASK -a $PORT0	$PORT1 $PORT2" \
	"--no-flush-rx --nb-cores=1 --forward-mode=csum --no-flush-rx"

testpmd_cmd $PRFX "port stop all"
testpmd_cmd $PRFX "set verbose 2"
testpmd_cmd $PRFX "mac_addr set 0 02:00:00:00:01:00"
testpmd_cmd $PRFX "port config all burst 63"
testpmd_cmd $PRFX "csum parse-tunnel on 0"

# Launch capture testpmd
testpmd_launch $CAP_PRFX \
	"-c $CAP_COREMASK -a $CAP_PORT0 $CAP_PORT1" \
        "--no-flush-rx --nb-cores=1 --forward-mode=io"
testpmd_cmd $CAP_PRFX "port stop all"
testpmd_cmd $CAP_PRFX "port config mtu 0 9000"

while [ $i -le $max ]
do
	echo -e "########################### ITERATION $i" \
		"(tx_offload=${tx_offloads[$i]})########################\n"

	if ((${tx_offloads[$i]} & 0x20000)) && [[ $skip_tx_security == 1 ]]
	then
		echo "Skipped security testcase"
		echo -e "############################################# " \
			"END of ITERATION $i #####################\n"
		((++i))
		continue
	fi

	set -x
	is_mseg=$((${tx_offloads[$i]} & 0x8000))
	if [[ $need_mseg == 1 ]] && [[ $is_mseg == 0 ]]
	then
		echo "Skipped non mseg testcase"
		echo -e "############################################# " \
			"END of ITERATION $i #####################\n"
		((++i))
	set +x
		continue
	fi
	set +x


	# Setup tx offloads
	setup_tx_offload ${tx_offloads[$i]} $i

	# Start capturing
	start_capture

	testpmd_cmd $PRFX "csum show 0"
	testpmd_cmd $PRFX "port start all"
	testpmd_cmd $PRFX "show txq info 0 0"

	# Show log till now
	testpmd_log_off $PRFX $OFF
	OFF=`testpmd_log_sz $PRFX`

	# Verify Tx offload config
	testpmd_cmd $PRFX "show config rxtx"
	testpmd_log_off $PRFX $OFF
	val=`testpmd_log_off $PRFX $OFF | head -5 \
		| grep -ao "Tx offloads=.*" | cut -d "=" -f 2`
	if (( $val != ${tx_offloads[$i]} ))
	then
		echo -e "Expected Tx offloads ${tx_offloads[$i]} " \
			"!= Configured Tx offloads $val"
		exit 1
	fi

	testpmd_cmd_refresh $PRFX "start"
	# Peek to start log as we don't want to see pkt logs now
	testpmd_log_off $PRFX $OFF | head -32

	# Wait for receiving all packets
	start_ts=`date +%s`
	start_ts=$((start_ts + 60))
	count=`capture_count`
	while [[ "$count" != "$EXPECTED_CNT" ]]
	do
		sleep 0.1
		count=`capture_count`
		ts=`date +%s`
		if (( $ts > $start_ts ))
		then
			echo "Timeout waiting for all packets"
			exit 1
		fi

	done
	# Stop capturing
	stop_capture

	if [ $skip_udp_tunnel -eq 0 ]
	then
		FL=""
		tcpdump -nr $TMP_DIR/$RECV_PCAP -xvve -t >$TMP_DIR/recv.txt

		# Compare received and expected
		diff -sqad $TMP_DIR/recv.txt $TMP_DIR/expect.txt
	else
		FL=$UDP_TUNNEL_FILTER
		tcpdump -nr $TMP_DIR/$RECV_PCAP -xvve \
			-t $FL >$TMP_DIR/recv_non_udp_tun.txt

		# Compare received and expected
		diff -sqad $TMP_DIR/recv_non_udp_tun.txt \
				$TMP_DIR/expect_non_udp_tun.txt
	fi

	# Skip Dump testpmd log containing pkts
	OFF=`testpmd_log_sz $PRFX`

	testpmd_cmd $PRFX "stop"
	testpmd_cmd $PRFX "port stop all"

	testpmd_cmd $PRFX "show port stats all"
	testpmd_cmd $PRFX "clear port stats all"

	# Dump testpmd log
	testpmd_log_off $PRFX $OFF
	OFF=`testpmd_log_sz $PRFX`

	echo -e "############################################# " \
		"END of ITERATION $i #####################\n"
	((++i))
done

echo "SUCCESS: testpmd tx checksum offload test completed"
