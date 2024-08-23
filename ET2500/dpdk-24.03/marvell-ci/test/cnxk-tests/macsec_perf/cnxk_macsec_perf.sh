#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

set -e

GENERATOR_BOARD=${GENERATOR_BOARD:-}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}
CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-"$1/deps/lib"}
PKT_LIST="64 380 1410"
NUM_CAPTURE=3
MAX_TRY_CNT=5
CORES=(1)
COREMASK="0x10"
TXWAIT=15
RXWAIT=5
WS=2
IS_RXPPS_TXTPMD=0
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"}
TARGET_SSH_CMD="$TARGET_SSH_CMD -n"
GENERATOR_SCRIPT=${GENERATOR_SCRIPT:-cnxk_macsec_perf_gen.sh}
WITH_GEN_BOARD=0

source $CNXKTESTPATH/../common/testpmd/pktgen.env
source $CNXKTESTPATH/../common/testpmd/lbk.env
source $CNXKTESTPATH/../common/testpmd/common.env

MACSEC_PREFIX="macsec_dpdk"
TPMD_RX_PREFIX="tpmd_rx"
TPMD_TX_PREFIX="tpmd_tx"

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_PPS_TABLE

! $(cat /proc/device-tree/compatible | grep -q "cn10kb")
IS_CN103=$?

if [[ $IS_CN103 -ne 0 ]]; then
	HW="103xx"
fi

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

# Find the dpdk-l2fwd-macsec application
if [[ -f $CNXKTESTPATH/../../../../examples/dpdk-l2fwd-macsec ]]; then
	# This is running from build directory
	L2FWD_MACSEC_BIN=$CNXKTESTPATH/../../../../examples/dpdk-l2fwd-macsec
elif [[ -f $CNXKTESTPATH/../../dpdk-l2fwd-macsec ]]; then
	# This is running from install directory
	L2FWD_MACSEC_BIN=$CNXKTESTPATH/../../dpdk-l2fwd-macsec
else
	L2FWD_MACSEC_BIN=$(which dpdk-l2fwd-macsec)
	if [[ -z $L2FWD_MACSEC_BIN ]]; then
		echo "dpdk-l2fwd-macsec not found !!"
		exit 1
	fi
fi

TYPE=(
	"ip"
)

TN=(
	"Inline Protocol: Poll Mode"
)

NB_TYPES=${#TYPE[@]}

function assert_arr_len()
{
	local name=$1
	local -n arr=$name
	local arr_len=${#arr[@]}

	if [[ $arr_len -ne $NB_TYPES ]]; then
		echo "'$name' array($arr_len) should be same length as 'TYPE' array($NB_TYPES)"
		exit 1
	fi
}

assert_arr_len TN

Failed_tests=""

LIF1=0002:01:00.5
LIF2=0002:01:00.6

# MACsec log file name for app will be as
# macsec_{1/2 for aes-cbc/aes-gcm}_{outb/inb}_{Test number}_{Trial number}.log
MACSEC_LOG=macsec_*.log
VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"

rm -f $MACSEC_LOG

if [[ -z "$GENERATOR_BOARD" ]]; then
	echo "Generator board details missing!!"
	WITH_GEN_BOARD=0
else
	echo "Found Generator board details $GENERATOR_BOARD"
	if [[ $IS_CN103 -ne 0 ]]; then
		WITH_GEN_BOARD=1
	fi
fi

if [[ $WITH_GEN_BOARD -eq 1 ]]
then
	IF0=0002:02:00.0
	IF1=0002:03:00.0
	echo "Inline Protocol tests will run with generator board"
else
	IF0=$LIF2
	IF1=$LIF3
	echo "All tests will run locally without generator board"
fi

function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local fp_cptclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
if [[ $IS_CN103 -ne 0 ]]; then
	fp_rclk="$sysclk_dir/coreclk/clk_rate"
else
	fp_rclk="$sysclk_dir/rclk/clk_rate"
	fp_cptclk="$sysclk_dir/cptclk/clk_rate"
fi
	fp_sclk="$sysclk_dir/sclk/clk_rate"

	if $SUDO test -f "$fp_rclk"; then
		RCLK=$(echo "`$SUDO cat $fp_rclk` / $div" | bc)
	else
		echo "$fp_rclk not available"
		exit 1
	fi

	if $SUDO test -f "$fp_sclk"; then
		SCLK=$(echo "`$SUDO cat $fp_sclk` / $div" | bc)
	else
		echo "$fp_sclk not available"
		exit 1
	fi

if [[ $IS_CN103 -ne 0 ]]; then
	echo "CORECLK:   $RCLK Mhz"
	echo "SCLK:      $SCLK Mhz"
	return
fi
	if $SUDO test -f "$fp_cptclk"; then
		CPTCLK=$(echo "`$SUDO cat $fp_cptclk` / $div" | bc)
	else
		echo "$fp_cptclk not available"
		exit 1
	fi

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
	echo "CPTCLK: $CPTCLK Mhz"
}

function is_inline_proto_test()
{
	local type=${TYPE[$Y]}
	local ip_tests=(ip)

	[[ " ${ip_tests[*]} " =~ " $type " ]]
}

function run_test()
{
	local cmd=$1
	touch $MACSEC_LOG
	echo $env
	echo $1
	eval "nohup $1 >> $MACSEC_LOG 2>&1 &"
	PT1="L2FWD: entering main loop on lcore"

	local itr=0
	sleep 1
	while ! (cat $MACSEC_LOG | grep -q -e "$PT1" )
	do
		sleep 1
		((itr+=1))

		if [[ $itr -eq 100 ]]
		then
			echo "Timeout waiting for MACSEC main loop"
			exit 2
		fi

		if [[ $((itr%5)) -eq 0 ]]
		then echo "Waiting for MACSEC main loop"; fi
	done
}

function run_l2fwd_macsec()
{
	echo "l2fwd-macsec outb"
	if [[ $IS_CN103 -ne 0 ]]; then
		local env="$L2FWD_MACSEC_BIN -c $COREMASK -a $IF0  --file-prefix $MACSEC_PREFIX -- -P -p 0x1"
		if is_inline_proto_test; then
			IS_RXPPS_TXTPMD=1
		fi
		case "${TYPE[$Y]}" in
			ip)
				# Inline Protocol Poll Mode
				run_test '$env --mcs-tx-portmask 0x1 --mcs-port-config="(0,02:03:04:05:06:07,01:02:03:04:05:06)"'
				;;
		esac
	fi
	echo "run_l2fwd_macsec 2"
	sleep $WS
}

function run_l2fwd_macsec_inb()
{
	echo "l2fwd-macsec inb"
	if [[ $IS_CN103 -ne 0 ]]; then
		local env="$L2FWD_MACSEC_BIN -c $COREMASK -a $IF0 --file-prefix $MACSEC_PREFIX -- -P -p 0x1"
		if is_inline_proto_test; then
			IS_RXPPS_TXTPMD=1
		fi
		case "${TYPE[$Y]}" in
			ip)
				# Inline Protocol Poll Mode
				run_test '$env --mcs-rx-portmask 0x1 --mcs-port-config="(0,02:03:04:05:06:07,01:02:03:04:05:06)"'
				;;
		esac
	fi
	sleep $WS
}

function macsec_exit()
{
	killall -q dpdk-l2fwd-macsec | echo "macsec_exit: killed dpdk-l2fwd-macsec"

	# Wait until the process is killed
	while (ps -ef | grep dpdk-l2fwd-macsec | grep -q $MACSEC_PREFIX); do
		continue
	done
	sleep 7
}

function sig_handler()
{
	local status=$?
	set +e
	trap - ERR
	trap - INT
	trap - QUIT
	trap - EXIT
	macsec_exit
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
		ps -ef
		# print all MACsec logs
		MACSEC_LOG=macsec_*.log
		awk ' { print FILENAME": " $0 } ' $MACSEC_LOG
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_TX_PREFIX
		awk ' { print FILENAME": " $0 } ' testpmd.out.$TPMD_RX_PREFIX
	fi
	cleanup_interfaces
	exit $status
}

find_exec()
{
	local dut=$1
	local test_name=$2

	$TARGET_SSH_CMD $dut find $REMOTE_DIR -type f -executable -iname $test_name
}

function exec_genboard_cleanup()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]]; then
		$TARGET_SSH_CMD $GENERATOR_BOARD "sudo pkill -f dpdk*;"
		echo "Gen board previous test processes cleanup up"
	fi
}

exec_testpmd_cmd_gen()
{
	$TARGET_SSH_CMD $GENERATOR_BOARD "cd $REMOTE_DIR;" \
		"sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH TESTPMD_OP=$1 $(find_exec $GENERATOR_BOARD $GENERATOR_SCRIPT) $2 $3"
}

function pmd_tx_launch()
{
	local pcap=$CNXKTESTPATH/pcap/port_0_plain_pkt_$2B.pcap
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		echo "pmd_tx_launch with Gen"
		exec_testpmd_cmd_gen "launch_tx_outb" $TPMD_TX_PREFIX $pcap
	fi
}

function pmd_tx_launch_for_inb()
{
	local pcap=$CNXKTESTPATH/pcap/port_0_enc_pkt_$2B.pcap
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "launch_tx_inb" $TPMD_TX_PREFIX $pcap
	fi
}

function pmd_rx_launch()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then :
		echo "pmd_rx_launch with Gen"
	fi
}

function pmd_rx_dry_run()
{
	local port="0"
	PREFIX=("$TPMD_RX_PREFIX" "$TPMD_TX_PREFIX")

	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		rxpps=$(exec_testpmd_cmd_gen "rx_pps" $TPMD_TX_PREFIX $port)
	fi
}

function rx_stats()
{
	local prefix=$1
	local port=$2
	local in=testpmd.in.$prefix
	local out=testpmd.out.$prefix

	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		rxpps=$(exec_testpmd_cmd_gen "rx_pps" $prefix $port)
		echo $rxpps
	fi
}

function capture_rx_pps()
{
	local stats
	if [[ $IS_RXPPS_TXTPMD -ne 0 ]]; then
		# Specific case of Inline Protocol Single-SA configuration.
		# Packets are routed back to originating port.
		stats=$(rx_stats $TPMD_TX_PREFIX "0")
	else
		stats=$(rx_stats $TPMD_RX_PREFIX "0")
	fi

	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		echo $stats
	fi
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"

	$VFIO_DEVBIND -b vfio-pci $LIF1
	$VFIO_DEVBIND -b vfio-pci $LIF2
	$VFIO_DEVBIND -b vfio-pci $LIF3
	$VFIO_DEVBIND -b vfio-pci $LIF4
}

function cleanup_interfaces()
{
	# Bind the vfio-pci binded devices back to nicvf
	$VFIO_DEVBIND -b $NICVF $LIF1
	$VFIO_DEVBIND -b $NICVF $LIF2
	$VFIO_DEVBIND -b $NICVF $LIF3
	$VFIO_DEVBIND -b $NICVF $LIF4
}

function start_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "start" $TPMD_TX_PREFIX
	fi
}

function stop_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "stop" $TPMD_TX_PREFIX
	fi
}

function quit_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		if [[ $1 == $TPMD_TX_PREFIX ]]; then
			exec_testpmd_cmd_gen "log" $1 >testpmd.out.$1
			exec_testpmd_cmd_gen "quit" $1
		fi
	fi
}

function outb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local algo
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		sleep $WS
		pmd_tx_launch $1 $pktsz

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart l2fwd-macsec
				macsec_exit
				echo "Restart l2fwd-macsec"
				MACSEC_LOG=macsec_outb_"$Y"_"$tcnt".log
				run_l2fwd_macsec
			fi
			start_testpmd
			pmd_rx_dry_run
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			echo $NUM_CAPTURE
			p=${PASS_PPS_TABLE[$rn,$2]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			Failed_tests="$Failed_tests \"${TN[$Y]} outbound $algo pktsize:$pktsz\""
		fi
		((++rn))
	done
}

function inb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local algo
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		sleep $WS
		pmd_tx_launch_for_inb $1 $pktsz

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart l2fwd-macsec
				macsec_exit
				echo "Restart l2fwd-macsec"
				MACSEC_LOG=macsec_inb_"$Y"_"$tcnt".log
				run_l2fwd_macsec_inb
			fi
			start_testpmd
			pmd_rx_dry_run
			# Wait for few seconds for traffic to stabilize
			sleep $TXWAIT
			while [ $i -le $NUM_CAPTURE ]; do
				rx_pps=$rx_pps+$(capture_rx_pps)
				((++i))
				sleep $RXWAIT
			done
			stop_testpmd
			avg_pps=$(echo "(($rx_pps) / $NUM_CAPTURE)" | bc)
			p=${PASS_PPS_TABLE[$rn,$2]}
			echo "pktsize: $pktsz avg_pps: $avg_pps"
			echo "pass_pps $p"
			if (( $(echo "$avg_pps < $p" | bc) )); then
				echo "$1:Low numbers for packet size $pktsz " \
					"($avg_pps < $p) for $3 cores">&2
			else
				echo "Test Passed"
				quit_testpmd "$TPMD_TX_PREFIX"
				break
			fi
			((++tcnt))
			sleep $WS
		done
		if [[ $tcnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			quit_testpmd "$TPMD_TX_PREFIX"
			Failed_tests="$Failed_tests \"${TN[$Y]} inbound $algo pktsize:$pktsz\""
		fi
		((++rn))
	done
}

function get_ref_mops()
{
	local ref_mops
	ref_mops=$(awk -v pat=$1 '$0~pat','/end/' \
			$FPATH.$3 | grep $2: | tr -s ' ')
	echo $ref_mops
}

function populate_pass_mops()
{
	local rn=0
	local cn

	for i in ${PKT_LIST[@]}
	do
		cn=0
		ref_mops=$(get_ref_mops $1 $i $2)
		for j in ${CORES[@]}
		do
			tmp=$(( $cn + 2 ))
			ref_n=$(echo "$ref_mops" | cut -d " " -f $tmp)
			PASS_PPS_TABLE[$rn,$cn]=$(echo "($ref_n * .97)" | bc)
			((++cn))
		done
		((++rn))
	done
}

function macsec_gcm_outb()
{
	local algo_str="macsec-gcm"
	local cn

	echo "Outbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb"

	cn=0
	for j in ${CORES[@]}
	do
		outb_perf $algo_str $cn $j
		((++cn))
	done
}

function macsec_gcm_inb()
{
	local algo_str="macsec-gcm"
	local cn

	echo "Inbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.inb"

	cn=0
	for j in ${CORES[@]}
	do
		inb_perf $algo_str $cn $j
		((++cn))
	done
}

get_system_info

if [[ $IS_CN103 -ne 0 ]]; then
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}
	FPATH="$CNXKTESTPATH/ref_numbers/cn10k/$FNAME"
else
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${HW}
	FPATH="$CNXKTESTPATH/ref_numbers/cn9k/$FNAME"
fi

function check_ref_files()
{
	local outb
	local inb

	for type in "${TYPE[@]}"; do
		if [[ $IS_CN103 -eq 0 ]] && ! supported_by_9k $type; then
			continue
		fi
		outb="$FPATH.$type.outb"
		if [[ ! -f $outb ]]; then
			echo "File $outb not present"
			exit 1
		fi

		inb="$FPATH.$type.inb"
		if [[ ! -f $inb ]]; then
			echo "File $inb not present"
			exit 1
		fi
	done
}

check_ref_files

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

setup_interfaces
exec_genboard_cleanup

function is_skip_test()
{
	local inline=$1
	if [[ $inline = "inline" ]]; then
		! is_inline_proto_test
	else
		is_inline_proto_test
	fi
}

Y=0

while [[ $Y -lt $NB_TYPES ]]; do
	echo ""
	echo "Test: ${TN[$Y]}"
	echo "----------------------"
	# Outbound
	sleep $WS

	MACSEC_LOG=macsec_outb_"$Y"_1.log
	run_l2fwd_macsec

	pmd_rx_launch
	macsec_gcm_outb
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	macsec_exit

	sleep $WS

	echo ""
	# Inbound
	MACSEC_LOG=macsec_inb_"$Y"_1.log
	run_l2fwd_macsec_inb
	pmd_rx_launch
	macsec_gcm_inb
	quit_testpmd "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	macsec_exit
	((++Y))
done

echo ""
if [[ -n $Failed_tests ]]; then
	echo "FAILURE: Test(s) [$Failed_tests] failed"
	exit 1
fi

exit 0
