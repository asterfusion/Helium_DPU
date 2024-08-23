#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

set -e

GENERATOR_BOARD=${GENERATOR_BOARD:-}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}
CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
LD_LIBRARY_PATH=${LD_LIBRARY_PATH:-"$1/deps/lib"}
PKT_LIST="64 380 1410"
NUM_CAPTURE=3
MAX_TRY_CNT=5
CORES=(1)
COREMASK="0x10000"
TXWAIT=15
RXWAIT=5
WS=2
IS_RXPPS_TXTPMD=0
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"}
TARGET_SSH_CMD="$TARGET_SSH_CMD -n"
GENERATOR_SCRIPT=${GENERATOR_SCRIPT:-cnxk_ipsec_perf_gen.sh}
WITH_GEN_BOARD=0

source $CNXKTESTPATH/../common/testpmd/pktgen.env
source $CNXKTESTPATH/../common/testpmd/lbk.env
source $CNXKTESTPATH/../common/testpmd/common.env

IPSEC_PREFIX="ipsec_dpdk"
TPMD_RX_PREFIX="tpmd_rx"
TPMD_TX_PREFIX="tpmd_tx"

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_PPS_TABLE

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

if [[ $IS_CN10K -ne 0 ]]; then
	HW="106xx"
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	INLINE_DEV=0002:1d:00.0
else
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		HW="98xx"
	else
		HW="96xx"
	fi
	CDEV_VF=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
fi

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

# Find the dpdk-ipsec-secgw application
if [[ -f $CNXKTESTPATH/../../../../examples/dpdk-ipsec-secgw ]]; then
	# This is running from build directory
	IPSECGW_BIN=$CNXKTESTPATH/../../../../examples/dpdk-ipsec-secgw
elif [[ -f $CNXKTESTPATH/../../dpdk-ipsec-secgw ]]; then
	# This is running from install directory
	IPSECGW_BIN=$CNXKTESTPATH/../../dpdk-ipsec-secgw
else
	IPSECGW_BIN=$(which dpdk-ipsec-secgw)
	if [[ -z $IPSECGW_BIN ]]; then
		echo "dpdk-ipsec-secgw not found !!"
		exit 1
	fi
fi

CFG=(
	# Lookaside protocol
	"ep0_lookaside_crypto.cfg"
	"ep0_lookaside_protocol.cfg"
	"ep0_lookaside_protocol.cfg"
	"ep0_lookaside_protocol.cfg"
	# Inline protocol Outbound config files
	"ep0_inline_protocol_ob_sp.cfg"
	"ep0_inline_protocol_ob_sp.cfg"
	"ep0_inline_protocol_ob_sp.cfg"
	"ep0_inline_protocol_ob_sp.cfg"
	"ep0_inline_protocol_ob_sp.cfg"
)

#Inline Protocol inbound specific config files
# Sequence is align with TYPE
IP_IB_CFG=(
	""
	""
	""
	""
	"ep0_inline_protocol_ib_sp.cfg"
	"ep0_inline_protocol_ib_sp.cfg"
	"ep0_inline_protocol_ib_sp.cfg"
	"ep0_inline_protocol_ib_sp.cfg"
	"ep0_inline_protocol_ib_sp.cfg"
)

# Dual Port Inbound configs for Inline protocol
IP_IB_CFG_DP=(
	""
	""
	""
	""
	"ep0_inline_protocol_ib_dp.cfg"
	"ep0_inline_protocol_ib_dp.cfg"
	"ep0_inline_protocol_ib_dp.cfg"
	"ep0_inline_protocol_ib_dp.cfg"
	"ep0_inline_protocol_ib_dp.cfg"
)

# Dual Port Outbound configs for Inline protocol
IP_OB_CFG_DP=(
	""
	""
	""
	""
	"ep0_inline_protocol_ob_dp.cfg"
	"ep0_inline_protocol_ob_dp.cfg"
	"ep0_inline_protocol_ob_dp.cfg"
	"ep0_inline_protocol_ob_dp.cfg"
	"ep0_inline_protocol_ob_dp.cfg"
)
# Specific config files for Perf cases with Inline Protocol Single-SA
IP_PERF_CFG=(
	# AES-CBC config for outbound
	"ep0_inline_protocol_ob_aescbc.cfg"
	# AES-GCM config for outbound
	"ep0_inline_protocol_ob_aesgcm.cfg"
)

TYPE=(
	"lc"
	"lp"
	"lp_e"
	"lp_ev"
	"ip"
	"ip_ev"
	"ip_p"
	"ip_ev_ss"
	"ip_p_ss"
)

TN=(
	"Lookaside Crypto"
	"Lookaside Protocol"
	"Lookaside Protocol: Event Basic Mode"
	"Lookaside Protocol: Event Vector Mode"
	"Inline Protocol: Event Basic Mode"
	"Inline Protocol: Event Vector Mode"
	"Inline Protocol: Poll Mode"
	"Inline Protocol: Event Vector Perf Mode (Single-SA)"
	"Inline Protocol: Poll Perf Mode (Single-SA)"
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

assert_arr_len CFG
assert_arr_len IP_IB_CFG
assert_arr_len IP_IB_CFG_DP
assert_arr_len IP_OB_CFG_DP
assert_arr_len TN

Failed_tests=""

LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

# IPsec log file name for app will be as
# ipsec_{1/2 for aes-cbc/aes-gcm}_{outb/inb}_{Test number}_{Trial number}.log
IPSEC_LOG=ipsec_*.log
VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"

rm -f $IPSEC_LOG

if [[ -z "$GENERATOR_BOARD" ]]; then
	echo "Generator board details missing!!"
	WITH_GEN_BOARD=0
else
	echo "Found Generator board details $GENERATOR_BOARD"
	if [[ $IS_CN10K -ne 0 ]]; then
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
if [[ $IS_CN10K -ne 0 ]]; then
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

if [[ $IS_CN10K -ne 0 ]]; then
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
	local ip_tests=(ip ip_ev ip_p ip_ev_ss ip_p_ss)

	[[ " ${ip_tests[*]} " =~ " $type " ]]
}

function is_single_sa_test()
{
	local type=${TYPE[$Y]}
	local sa_tests=(ip_ev_ss ip_p_ss)

	[[ " ${sa_tests[*]} " =~ " $type " ]]
}

function supported_by_9k()
{
	local type=$1
	local supported=(lc lp lp_e ip)

	[[ " ${supported[*]} " =~ " $type " ]]
}

function run_test()
{
	local cmd=$1
	touch $IPSEC_LOG
	eval "nohup $1 >> $IPSEC_LOG 2>&1 &"
	PT1="IPSEC: entering main loop on lcore"
	PT2="IPSEC: Launching event mode worker"

	local itr=0
	sleep 1
	while ! (cat $IPSEC_LOG | grep -q -e "$PT1" -e "$PT2")
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
}

function run_ipsec_secgw()
{
	local config="(0,0,16),(1,0,16)"
	local lookaside_env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX"
	local lookaside="$lookaside_env -- -P -p 0x3 -f ${CFG[$Y]} --config=$config"
	local lookaside_event="$lookaside_env -a $EVENT_VF -- -P -p 0x3 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel"
	local lookaside_event_vec="$lookaside_event --vector-size 64 --event-vector"

	echo "ipsec-secgw outb"
	if [[ $IS_CN10K -ne 0 ]]; then
		local env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $IF0,ipsec_in_max_spi=128 -a $IF1,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3"
		if is_inline_proto_test; then
			IS_RXPPS_TXTPMD=1
		fi
		case "${TYPE[$Y]}" in
			lc|lp)
				# Lookaside Crypto/Protocol
				run_test '$lookaside'
				;;
			lp_e)
				# Lookaside Protocol Event Mode
				run_test '$lookaside_event'
				;;
			lp_ev)
				# Lookaside Protocol Event Vector Mode
				run_test '$lookaside_event_vec'
				;;
			ip)
				# Inline Protocol Event Mode
				run_test '$env -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
				;;
			ip_ev)
				# Inline Protocol Event Vector Mode
				run_test '$env -f ${CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -e'
				;;
			ip_p)
				# Inline Protocol Poll Mode
				run_test '$env -f ${CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l'
				;;
			ip_ev_ss)
				# Inline Protocol Event Vector Perf Mode (Single-SA)
				run_test '$env -f ${IP_PERF_CFG[$perf_cfg]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 256 --event-vector --event-schedule-type parallel -e --single-sa 0'
				;;
			ip_p_ss)
				# Inline Protocol Poll Perf Mode (Single-SA)
				run_test '$env -f ${IP_PERF_CFG[$perf_cfg]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l --single-sa 0'
				;;
		esac
	else
		# 9K supported types
		case "${TYPE[$Y]}" in
			lc|lp)
				# Lookaside Crypto/Protocol
				run_test '$lookaside'
				;;
			lp_e)
				# Lookaside Protocol Event Mode
				run_test '$lookaside_event'
				;;
			lp_ev)
				# Lookaside Protocol Event Vector Mode
				run_test '$lookaside_event_vec'
				;;
			ip)
				# Inline Protocol Event Mode
				run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${IP_OB_CFG_DP[$Y]} --transfer-mode event --event-schedule-type parallel'
				;;
		esac
	fi
	sleep $WS
}

function run_ipsec_secgw_inb()
{
	local config="(0,0,16),(1,0,16)"
	local lookaside_env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX"
	local lookaside="$lookaside_env -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --config=$config"
	local lookaside_event="$lookaside_env -a $EVENT_VF -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel"
	local lookaside_event_vec="$lookaside_event --vector-size 64 --event-vector"

	echo "ipsec-secgw inb"
	if [[ $IS_CN10K -ne 0 ]]; then
		local env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $IF0,ipsec_in_max_spi=128 -a $IF1,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x3"
		if is_inline_proto_test; then
			IS_RXPPS_TXTPMD=1
		fi
		case "${TYPE[$Y]}" in
			lc|lp)
				# Lookaside Crypto/Protocol
				run_test '$lookaside'
				;;
			ip)
				# Inline Protocol Event Mode
				run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
				;;
			lp_e)
				# Lookaside Protocol Event Mode
				run_test '$lookaside_event'
				;;
			lp_ev)
				# Lookaside Protocol Event Vector Mode
				run_test '$lookaside_event_vec'
				;;
			ip_ev)
				# Inline Protocol Event Vector Mode
				run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -s 8192 --vector-pool-sz 8192'
				;;
			ip_p)
				# Inline Protocol Poll Mode
				run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l'
				;;
			ip_ev_ss)
				# Inline Protocol Event Vector Perf Mode (Single-SA)
				run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 256 --event-vector --event-schedule-type parallel -s 8192 --vector-pool-sz 8192 --single-sa 0'
				;;
			ip_p_ss)
				# Inline Protocol Poll Perf Mode (Single-SA)
				run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l --single-sa 0'
				;;
		esac
	else
		# 9K supported types
		case "${TYPE[$Y]}" in
			lc|lp)
				# Lookaside Crypto/Protocol
				run_test '$lookaside'
				;;
			lp_e)
				# Lookaside Protocol Event Mode
				run_test '$lookaside_event'
				;;
			lp_ev)
				# Lookaside Protocol Event Vector Mode
				run_test '$lookaside_event_vec'
				;;
			ip)
				# Inline Protocol Event Mode
				run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${IP_IB_CFG_DP[$Y]} --transfer-mode event --event-schedule-type parallel'
				;;
		esac
	fi
	sleep $WS
}

function ipsec_exit()
{
	killall -q dpdk-ipsec-secgw | echo "ipsec_exit: killed dpdk-ipsec-secgw"

	# Wait until the process is killed
	while (ps -ef | grep dpdk-ipsec-secgw | grep -q $IPSEC_PREFIX); do
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
	ipsec_exit
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	if [[ $status -ne 0 ]]; then
		echo "$1 Handler"
		ps -ef
		# print all IPsec logs
		IPSEC_LOG=ipsec_*.log
		awk ' { print FILENAME": " $0 } ' $IPSEC_LOG
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
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "launch_tx_outb" $TPMD_TX_PREFIX $X
	else
		testpmd_launch "$TPMD_TX_PREFIX" \
			"-c 0x3800 -a $LIF1" \
			"--nb-cores=2 --forward-mode=txonly --tx-ip=192.168.$X.1,192.168.$X.2"
		testpmd_cmd $TPMD_TX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "port start 0"
		# Ratelimit Tx to 50Gbps on LBK
		testpmd_cmd $TPMD_TX_PREFIX "set port 0 queue 0 rate 50000"
	fi
}

function pmd_tx_launch_for_inb()
{
	local pcap=$CNXKTESTPATH/pcap/enc_$1_$2.pcap
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "launch_tx_inb" $TPMD_TX_PREFIX $pcap
	else
		if is_single_sa_test; then
			testpmd_launch "$TPMD_TX_PREFIX" \
			"-c 0xF800 --vdev net_pcap0,rx_pcap=$pcap,rx_pcap=$pcap,rx_pcap=$pcap,rx_pcap=$pcap,infinite_rx=1 -a $LIF1" \
			"--nb-cores=4 --txq=4 --rxq=4 --no-flush-rx"
		else
			testpmd_launch "$TPMD_TX_PREFIX" \
			"-c 0x3800 --vdev net_pcap0,rx_pcap=$pcap,infinite_rx=1 -a $LIF1" \
			"--nb-cores=2 --no-flush-rx"
		fi
		testpmd_cmd $TPMD_TX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "port start 0"
		# Ratelimit Tx to 50Gbps on LBK
		testpmd_cmd $TPMD_TX_PREFIX "set port 0 queue 0 rate 50000"
	fi
}

function pmd_rx_launch()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then :
	else
		testpmd_launch "$TPMD_RX_PREFIX" \
			"-c 0x700 -a $LIF4" \
			"--nb-cores=2 --forward-mode=rxonly"
		testpmd_cmd $TPMD_RX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_RX_PREFIX "port start 0"
	fi
}

function pmd_rx_dry_run()
{
	local port="0"
	PREFIX=("$TPMD_RX_PREFIX" "$TPMD_TX_PREFIX")

	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		rxpps=$(exec_testpmd_cmd_gen "rx_pps" $TPMD_TX_PREFIX $port)
	else
		for prefix in "${PREFIX[@]}"
		do
			local in=testpmd.in.$prefix
			prev=$(testpmd_log_sz $prefix)
			curr=$prev
			echo "show port stats $port" >> $in

			while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $prefix); done
			testpmd_prompt $prefix
		done
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
	else
		prev=$(testpmd_log_sz $prefix)
		curr=$prev

		echo "show port stats $port" >> $in
		while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $prefix); done
		testpmd_prompt $prefix
		cat $out | tail -n4 | head -n1
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
	else
		echo $stats | awk '{print $2}'
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
	else
		testpmd_cmd "$TPMD_RX_PREFIX" "start"
		testpmd_cmd "$TPMD_TX_PREFIX" "start"
	fi
}

function stop_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "stop" $TPMD_TX_PREFIX
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "stop"
		testpmd_cmd "$TPMD_RX_PREFIX" "stop"
	fi
}

function set_pktsize_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		exec_testpmd_cmd_gen "pktsize" "$TPMD_TX_PREFIX" $1
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts $1"
	fi
}

function quit_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 ]] && is_inline_proto_test; then
		if [[ $1 == $TPMD_TX_PREFIX ]]; then
			exec_testpmd_cmd_gen "log" $1 >testpmd.out.$1
			exec_testpmd_cmd_gen "quit" $1
		fi
	else
		testpmd_quit $1
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

	[[ $X = 1 ]] && algo="aes-cbc_sha1-hmac" || algo="aes-gcm"

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		set_pktsize_testpmd $pktsz

		tcnt=1
		while [ $tcnt -le $MAX_TRY_CNT ]; do
			echo "Try $tcnt"
			i=1
			rx_pps=0
			if [[ $tcnt -gt 1 ]]; then
				# Restart ipsec-secgw
				ipsec_exit
				echo "Restart ipsec-secgw"
				IPSEC_LOG=ipsec_"$X"_outb_"$Y"_"$tcnt".log
				run_ipsec_secgw
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

	[[ $X = 1 ]] && algo="aes-cbc_sha1-hmac" || algo="aes-gcm"

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
				# Restart ipsec-secgw
				ipsec_exit
				echo "Restart ipsec-secgw"
				IPSEC_LOG=ipsec_"$X"_inb_"$Y"_"$tcnt".log
				run_ipsec_secgw_inb
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

function aes_cbc_sha1_hmac_outb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
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

function aes_cbc_sha1_hmac_inb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
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

function aes_gcm_outb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local cn

	echo "Outbound Perf Test: $algo_str"
	populate_pass_mops $algo_str "${TYPE[$Y]}.outb"

	cn=0
	for j in ${CORES[@]}
	do
		# Run ipsec-secgw application
		outb_perf $algo_str $cn $j
		((++cn))
	done
}

function aes_gcm_inb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
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

if [[ $IS_CN10K -ne 0 ]]; then
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
		if [[ $IS_CN10K -eq 0 ]] && ! supported_by_9k $type; then
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

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_VF=$SSO_DEV

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
	if is_skip_test $2; then
		((++Y))
		continue
	fi

	if [[ $IS_CN10K -eq 0 ]] && ! supported_by_9k ${TYPE[$Y]}; then
		((++Y))
		continue
	fi
	echo ""
	echo "Test: ${TN[$Y]}"
	echo "----------------------"
	# Outbound
	sleep $WS

	# aes-cbc sha1-hmac

	# Select perf config file for Inline protocol Single-SA perf tests
	if is_single_sa_test; then
		perf_cfg=0
	fi
	X=1
	IPSEC_LOG=ipsec_"$X"_outb_"$Y"_1.log
	run_ipsec_secgw

	pmd_rx_launch
	pmd_tx_launch
	aes_cbc_sha1_hmac_outb
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	# aes-gcm

	X=2
	if is_single_sa_test; then
		# Restart ipsec-secgw for Inline Protocol Single-SA tests with new config
		ipsec_exit
		echo "Restart ipsec-secgw"
		# Select perf config file for Inline protocol Single-SA perf tests
		perf_cfg=1
		IPSEC_LOG=ipsec_"$X"_outb_"$Y"_1.log
		run_ipsec_secgw
	fi
	pmd_rx_launch
	pmd_tx_launch
	aes_gcm_outb
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	ipsec_exit

	echo ""
	# Inbound
	X=1
	IPSEC_LOG=ipsec_"$X"_inb_"$Y"_1.log
	run_ipsec_secgw_inb
	pmd_rx_launch
	aes_cbc_sha1_hmac_inb
	quit_testpmd "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	X=2
	pmd_rx_launch
	aes_gcm_inb
	quit_testpmd "$TPMD_RX_PREFIX"
	ipsec_exit
	((++Y))
done

echo ""
if [[ -n $Failed_tests ]]; then
	echo "FAILURE: Test(s) [$Failed_tests] failed"
	exit 1
fi

exit 0
