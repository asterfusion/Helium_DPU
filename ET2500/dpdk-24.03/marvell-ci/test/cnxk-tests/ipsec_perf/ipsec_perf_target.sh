#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

set -e

GENERATOR_BOARD=${GENERATOR_BOARD:-}
REMOTE_DIR=${REMOTE_DIR:-$(pwd | cut -d/ -f 1-3)}
SUDO=${SUDO:-"sudo"}
SCRIPTPATH=$1
PKT_LIST="64 380 1410"
NUM_CAPTURE=3
MAX_TRY_CNT=5
CORES=(1)
COREMASK="0x10000"
NUM_MODES=7
TXWAIT=15
RXWAIT=5
WS=2
IS_RXPPS_TXTPMD=0
TARGET_SSH_CMD=${TARGET_SSH_CMD:-"ssh -o LogLevel=ERROR -o ServerAliveInterval=30 \
	-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"}
TARGET_SSH_CMD="$TARGET_SSH_CMD -n"
GENERATOR_SCRIPT=${GENERATOR_SCRIPT:-cnxk_ipsec_perf_gen.sh}
WITH_GEN_BOARD=0

source $SCRIPTPATH/marvell-ci/test/cnxk-tests/common/testpmd/pktgen.env
source $SCRIPTPATH/marvell-ci/test/cnxk-tests/common/testpmd/lbk.env
source $SCRIPTPATH/marvell-ci/test/cnxk-tests/common/testpmd/common.env

IPSEC_PREFIX="ipsec_dpdk"
TPMD_RX_PREFIX="tpmd_rx"
TPMD_TX_PREFIX="tpmd_tx"

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

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

LIF1=0002:01:00.5
LIF2=0002:01:00.6
LIF3=0002:01:00.7
LIF4=0002:01:01.0

SSO_DEV=${SSO_DEV:-$(lspci -d :a0f9 | tail -1 | awk -e '{ print $1 }')}
EVENT_VF=$SSO_DEV

IPSEC_LOG=ipsec.log
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

get_system_info

if [[ $IS_CN10K -ne 0 ]]; then
	HW="106xx"
	CDEV_VF=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	INLINE_DEV=0002:1d:00.0
	mkdir -p ref_numbers/cn10k
	FNAME="ref_numbers/cn10k/rclk"${RCLK}"_sclk"${SCLK}"."${HW}
else
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		HW="98xx"
	else
		HW="96xx"
	fi
	CDEV_VF=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
	mkdir -p ref_numbers/cn9k
	FNAME="ref_numbers/cn9k/rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${HW}
fi

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A ACT_PPS_TABLE

if [[ -d /sys/bus/pci/drivers/octeontx2-nicvf ]]; then
	NICVF="octeontx2-nicvf"
else
	NICVF="rvu_nicvf"
fi

# Find the dpdk-ipsec-secgw application
if [[ -f $SCRIPTPATH/dpdk-ipsec-secgw ]]; then
	# This is running from build directory
	IPSECGW_BIN=$SCRIPTPATH/dpdk-ipsec-secgw
else
	echo "dpdk-ipsec-secgw not found !!"
	exit 1
fi

CFG=(
	"ep0_lookaside_crypto.cfg"
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
	"ip"
	"ip_ev"
	"ip_p"
	"ip_ev_ss"
	"ip_p_ss"
)

TN=(
	"Lookaside Crypto"
	"Lookaside Protocol"
	"Inline Protocol: Event Basic Mode"
	"Inline Protocol: Event Vector Mode"
	"Inline Protocol: Poll Mode"
	"Inline Protocol: Event Vector Perf Mode (Single-SA)"
	"Inline Protocol: Poll Perf Mode (Single-SA)"
)

function run_test()
{
	local cmd=$1
	eval "nohup $1 >> $IPSEC_LOG 2>&1 &"
	PT1="IPSEC: entering main loop on lcore"
	PT2="IPSEC: Launching event mode worker"

	local itr=0
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

	echo "ipsec-secgw outb"
	if [[ $Y -ge 2 ]]; then
		if [[ $IS_CN10K -ne 0 ]]; then
			local env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $IF0,ipsec_in_max_spi=128 -a $IF1,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3"
			IS_RXPPS_TXTPMD=1
			case "$Y" in
				2)
					# Inline Protocol Event Mode
					run_test '$env -f ${CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
					;;
				3)
					# Inline Protocol Event Vector Mode
					run_test '$env -f ${CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -e'
					;;
				4)
					# Inline Protocol Poll Mode
					run_test '$env -f ${CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l'
					;;
				5)
					# Inline Protocol Event Vector Perf Mode (Single-SA)
					run_test '$env -f ${IP_PERF_CFG[$perf_cfg]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -e --single-sa 0'
					;;
				6)
					# Inline Protocol Poll Perf Mode (Single-SA)
					run_test '$env -f ${IP_PERF_CFG[$perf_cfg]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l --single-sa 0'
					;;
			esac
		else
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${IP_OB_CFG_DP[$Y]} --transfer-mode event --event-schedule-type parallel'
		fi
	else
		run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -f ${CFG[$Y]} --config=$config'
	fi
	sleep $WS
}

function run_ipsec_secgw_inb()
{
	local config="(0,0,16),(1,0,16)"

	echo "ipsec-secgw inb"

	if [[ $Y -ge 2 ]]; then
		if [[ $IS_CN10K -ne 0 ]]; then
			local env="$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $INLINE_DEV,ipsec_in_max_spi=128 -a $EVENT_VF -a $IF0,ipsec_in_max_spi=128 -a $IF1,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x3"
			IS_RXPPS_TXTPMD=1
			case "$Y" in
				2)
					# Inline Protocol Event Mode
					run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --event-schedule-type parallel'
					;;
				3)
					# Inline Protocol Event Vector Mode
					run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -s 8192 --vector-pool-sz 8192'
					;;
				4)
					# Inline Protocol Poll Mode
					run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l'
					;;
				5)
					# Inline Protocol Event Vector Perf Mode (Single-SA)
					run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode event --cryptodev_mask 0 -l --vector-size 64 --event-vector --event-schedule-type parallel -s 8192 --vector-pool-sz 8192 --single-sa 0'
					;;
				6)
					# Inline Protocol Poll Perf Mode (Single-SA)
					run_test '$env -f ${IP_IB_CFG[$Y]} --transfer-mode poll --config="(0,0,16)" --cryptodev_mask 0 -l --single-sa 0'
					;;
			esac
		else
			run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $EVENT_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${IP_IB_CFG_DP[$Y]} --transfer-mode event --event-schedule-type parallel'
		fi
	else
		run_test '$IPSECGW_BIN -c $COREMASK -a $CDEV_VF -a $LIF2,ipsec_in_max_spi=128 -a $LIF3,ipsec_in_max_spi=128 --file-prefix $IPSEC_PREFIX -- -P -p 0x3 -u 0x1 -f ${CFG[$Y]} --config=$config'
	fi
	sleep $WS
}

function ipsec_exit()
{
	killall dpdk-ipsec-secgw
	# Wait until the process is killed
	while (ps -ef | grep dpdk-ipsec-secgw | grep -q $IPSEC_PREFIX); do
		continue
	done
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
		ipsec_exit
		quit_testpmd "$TPMD_TX_PREFIX"
		quit_testpmd "$TPMD_RX_PREFIX"
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

exec_testpmd_cmd_gen()
{
	$TARGET_SSH_CMD $GENERATOR_BOARD "cd $REMOTE_DIR;" \
		"sudo TESTPMD_OP=$1 $(find_exec $GENERATOR_BOARD $GENERATOR_SCRIPT) $2 $3"
}

function pmd_tx_launch()
{
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
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
	local pcap=$SCRIPTPATH/pcap/enc_$1_$2.pcap
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "launch_tx_inb" $TPMD_TX_PREFIX $pcap
	else
		if [[ $Y -gt 4 ]]; then
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
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "launch_rx" $TPMD_RX_PREFIX
	else
		testpmd_launch "$TPMD_RX_PREFIX" \
			"-c 0x700 -a $LIF4" \
			"--nb-cores=2 --forward-mode=rxonly"
		testpmd_cmd $TPMD_TX_PREFIX "port stop 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl rx off 0"
		testpmd_cmd $TPMD_RX_PREFIX "set flow_ctrl tx off 0"
		testpmd_cmd $TPMD_TX_PREFIX "port start 0"
	fi
}

function pmd_rx_dry_run()
{
	local port="0"

	PREFIX=("$TPMD_RX_PREFIX" "$TPMD_TX_PREFIX")
	for prefix in "${PREFIX[@]}"
	do
		if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
			rxpps=$(exec_testpmd_cmd_gen "rx_pps" $prefix $port)
		else
			local in=testpmd.in.$prefix

			prev=$(testpmd_log_sz $prefix)
			curr=$prev
			echo "show port stats $port" >> $in
			while [ $prev -eq $curr ]; do sleep 0.1; curr=$(testpmd_log_sz $prefix); done
			testpmd_prompt $prefix
		fi
	done
}

function rx_stats()
{
	local prefix=$1
	local port=$2
	local in=testpmd.in.$prefix
	local out=testpmd.out.$prefix

	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
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
		stats=$(rx_stats "$TPMD_TX_PREFIX" "0")
	else
		stats=$(rx_stats "$TPMD_RX_PREFIX" "0")
	fi
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		echo $stats
	else
		echo $stats | awk '{print $2}'
	fi
}

# Configure interfaces
function setup_interfaces()
{
	echo -e "dev bind $LIF1 $LIF2 $LIF3 $LIF4"

	$SUDO $VFIO_DEVBIND -b vfio-pci $LIF1
	$SUDO $VFIO_DEVBIND -b vfio-pci $LIF2
	$SUDO $VFIO_DEVBIND -b vfio-pci $LIF3
	$SUDO $VFIO_DEVBIND -b vfio-pci $LIF4
}

function cleanup_interfaces()
{
	# Bind the vfio-pci binded devices back to nicvf
	$SUDO $VFIO_DEVBIND -b $NICVF $LIF1
	$SUDO $VFIO_DEVBIND -b $NICVF $LIF2
	$SUDO $VFIO_DEVBIND -b $NICVF $LIF3
	$SUDO $VFIO_DEVBIND -b $NICVF $LIF4
}

function start_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "start" $TPMD_RX_PREFIX
		exec_testpmd_cmd_gen "start" $TPMD_TX_PREFIX
	else
		testpmd_cmd "$TPMD_RX_PREFIX" "start"
		testpmd_cmd "$TPMD_TX_PREFIX" "start"
	fi
}

function stop_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "stop" $TPMD_TX_PREFIX
		exec_testpmd_cmd_gen "stop" $TPMD_RX_PREFIX
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "stop"
		testpmd_cmd "$TPMD_RX_PREFIX" "stop"
	fi
}

function set_pktsize_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "pktsize" "$TPMD_TX_PREFIX" $1
	else
		testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts $1"
	fi
}

function quit_testpmd()
{
	if [[ $WITH_GEN_BOARD -eq 1 && $Y -ge 2 ]]; then
		exec_testpmd_cmd_gen "log" $1 >testpmd.out.$1
		exec_testpmd_cmd_gen "quit" $1
	else
		testpmd_quit $1
	fi
}

function write_mops()
{
	local pktsz
	local rn=0
	local cn
	local fn

	fn=$FNAME".$2"
	echo $1 >> $fn
	for pktsz in ${PKT_LIST[@]}
	do
		cn=0
		str=$pktsz":"
		for j in ${CORES[@]}
		do
			str+=" ${ACT_PPS_TABLE[$rn,$cn]}"
			let cn=cn+1
		done
		echo $str >> $fn
		let rn=rn+1
	done
	echo "<end>" >> $fn
}

function outb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		testpmd_cmd "$TPMD_TX_PREFIX" "set txpkts $pktsz"

		i=1
		rx_pps=0
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
		ACT_PPS_TABLE[$rn,$2]=$avg_pps
		echo "pktsize: $pktsz avg_pps: $avg_pps"
		echo "Test Passed"
		sleep $WS
		((++rn))
	done
}

function inb_perf()
{
	local rx_pps
	local avg_pps
	local pktsz
	local tcnt
	local rn
	local i

	rn=0
	for pktsz in ${PKT_LIST[@]}
	do
		sleep $WS
		pmd_tx_launch_for_inb $1 $pktsz
		i=1
		rx_pps=0
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
		ACT_PPS_TABLE[$rn,$2]=$avg_pps
		echo "pktsize: $pktsz avg_pps: $avg_pps"
		echo "Test Passed"
		quit_testpmd "$TPMD_TX_PREFIX"
		sleep $WS
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

	cn=0
	for j in ${CORES[@]}
	do
		outb_perf $algo_str $cn $j
		((++cn))
	done
	write_mops $algo_str "${TYPE[$Y]}.outb"
}

function aes_cbc_sha1_hmac_inb()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"
	local cn

	echo "Inbound Perf Test: $algo_str"

	cn=0
	for j in ${CORES[@]}
	do
		inb_perf $algo_str $cn $j
		((++cn))
	done
	write_mops $algo_str "${TYPE[$Y]}.inb"
}

function aes_gcm_outb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local cn

	echo "Outbound Perf Test: $algo_str"

	cn=0
	for j in ${CORES[@]}
	do
		# Run ipsec-secgw application
		outb_perf $algo_str $cn $j
		((++cn))
	done
	write_mops $algo_str "${TYPE[$Y]}.outb"
}

function aes_gcm_inb()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}"
	local cn

	echo "Inbound Perf Test: $algo_str"

	cn=0
	for j in ${CORES[@]}
	do
		inb_perf $algo_str $cn $j
		((++cn))
	done
	write_mops $algo_str "${TYPE[$Y]}.inb"
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT


setup_interfaces

Y=0

while [ $Y -lt $NUM_MODES ]; do
	if [[ $IS_CN10K -eq 0 && $Y -gt 2 ]]; then
		exit 0
	fi
	echo ""
	echo "Test: ${TN[$Y]}"
	echo "----------------------"
	# Outbound
	sleep $WS

	# aes-cbc sha1-hmac

	# Select perf config file for Inline protocol Single-SA perf tests
	if [[ $Y -gt 4 ]]; then
		perf_cfg=0
	fi
	run_ipsec_secgw

	X=1
	pmd_rx_launch
	pmd_tx_launch
	aes_cbc_sha1_hmac_outb
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	# aes-gcm

	if [[ $Y -gt 4 ]]; then
		# Restart ipsec-secgw for Inline Protocol Single-SA tests with new config
		ipsec_exit
		sleep $WS
		echo "Restart ipsec-secgw"
		# Select perf config file for Inline protocol Single-SA perf tests
		perf_cfg=1
		run_ipsec_secgw
	fi
	X=2
	pmd_rx_launch
	pmd_tx_launch
	aes_gcm_outb
	quit_testpmd "$TPMD_TX_PREFIX"
	quit_testpmd "$TPMD_RX_PREFIX"
	ipsec_exit
	sleep $WS

	echo ""
	# Inbound
	run_ipsec_secgw_inb
	pmd_rx_launch
	aes_cbc_sha1_hmac_inb
	quit_testpmd "$TPMD_RX_PREFIX"

	sleep $WS

	echo ""
	pmd_rx_launch
	aes_gcm_inb
	quit_testpmd "$TPMD_RX_PREFIX"
	ipsec_exit
	((++Y))
done

exit 0
