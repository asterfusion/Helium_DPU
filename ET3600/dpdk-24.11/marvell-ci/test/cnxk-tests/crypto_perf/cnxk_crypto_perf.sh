#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -e

SUDO=${SUDO:-"sudo"}
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
CORES=(1 2 4)
COREMASK=("0x300" "0x700" "0x1f00")
BUFSIZE=(64 384 1504)
BUFFERSZ="64,384,1504"
PREFIX="cpt"
IN="cryptoperf.in.$PREFIX"
OUT="cryptoperf.out.$PREFIX"
BURSTSZ=32
POOLSZ=16384
NUMOPS=10000000
DL=","
MAX_TRY_CNT=10
PARTNUM_98XX=0x0b1
! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

! $(cat /proc/device-tree/compatible | grep -q "cn10kb")
IS_CN103=$?

if [[ $IS_CN10K -ne 0 ]]; then
	DEVTYPE="crypto_cn10k"
	CRYPTO_DEVICE=$(lspci -d :a0f3 | head -1 | awk -e '{ print $1 }')
	FEXT="106xx"
	HW="cn10k"
	PART_106B0=$(cat /proc/device-tree/soc\@0/chiprevision)
else
	DEVTYPE="crypto_cn9k"
	CRYPTO_DEVICE=$(lspci -d :a0fe | head -1 | awk -e '{ print $1 }')
	# Get CPU PART NUMBER
	PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | grep -o '0x0[a-b][0-3]$')
	if [[ $PARTNUM == $PARTNUM_98XX ]]; then
		FEXT="98xx"
		HW="cn9k"
	else
		FEXT="96xx"
		HW="cn9k"
	fi
fi

if [ -z "$CRYPTO_DEVICE" ]
then
	echo "Crypto device not found"
	exit 1
fi

EAL_ARGS="-a $CRYPTO_DEVICE"

# Error Patterns in cryptoperf run.
CPT_PERF_ERROR_PATTERNS=(
	"EAL: Error"
	"invalid option"
	"Test run constructor failed"
)

declare -i SCLK
declare -i RCLK
declare -i CPTCLK
declare -A PASS_MOPS_TABLE
declare -A ACT_MOPS_TABLE

# Find the dpdk-test-crypto-perf application
if [[ -f $SCRIPTPATH/../../../../app/dpdk-test-crypto-perf ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/dpdk-test-crypto-perf
elif [[ -f $SCRIPTPATH/../../dpdk-test-crypto-perf ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test-crypto-perf
else
	DPDK_TEST_BIN=$(which dpdk-test-crypto-perf)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test-crypto-perf not found !!"
		exit 1
	fi
fi

function remove_files()
{
	rm -f "$SCRIPTPATH/$OUT"
	rm -f "$SCRIPTPATH/$IN"
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
	remove_files
	exit $status
}

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

function get_ref_mops()
{
	local ref_mops
	ref_mops=$(awk -v pat=$1 '$0~pat','/end/' \
			$FPATH | grep $2: | tr -s ' ')
	echo $ref_mops
}

function cryptoperf_cleanup()
{
	# Issue kill
	ps -eo "pid,args" | grep dpdk-test-crypto-perf | grep $PREFIX | \
		awk '{print $2}' | xargs -I[] -n1 kill -9 [] 2>/dev/null || true

	# Wait until the process is killed
	while (ps -ef | grep dpdk-test-crypto-perf | grep -q $PREFIX); do
		continue
	done
}

function cryptoperf_run()
{
	local eal_args=$1
	local cryptoperf_args=$2
	local unbuffer="stdbuf -o0"

	cryptoperf_cleanup $PREFIX
	remove_files
	echo "$DPDK_TEST_BIN $eal_args --file-prefix $PREFIX -- $cryptoperf_args"
	sleep 1
	touch $IN
	tail -f $IN | \
		($unbuffer $DPDK_TEST_BIN $eal_args --file-prefix $PREFIX -- \
			$cryptoperf_args &>$OUT) &
	# Wait till out file is created
	while [[ ! -f $OUT ]]; do
		continue
	done
	# Wait until the process exits
	while (ps -ef | grep dpdk-test-crypto-perf | grep -q $PREFIX); do
		continue
	done
}

function check_mops()
{
	local mops=0
	local i=1
	local j

	while [ $i -le $1 ]; do
		j=$((i+8))
		mops=$mops+$(grep "$j$DL$2$DL$BURSTSZ$DL$NUMOPS" $OUT | \
			tr -s ' ' | cut -d "$DL" -f 8)
		let i=i+1
	done
	echo "$mops" | bc
}

function compare_pass_mops()
{
	local ret=0
	local rn=0
	local cn
	local i

	case $2 in
		1) cn=0;;
		2) cn=1;;
		4) cn=2;;
		*) echo "Core number $2 not supported">&2; exit 1;;
	esac

	for i in ${BUFSIZE[@]}
	do
		a=${ACT_MOPS_TABLE[$rn,$cn]}
		e=${PASS_MOPS_TABLE[$rn,$cn]}
		if (( $(echo "$a < $e" | bc) )); then
			echo "$1:Low numbers for buffer size $i ($a < $e) for $2 cores">&2
			ret=1
			break 2
		fi
		let rn=rn+1
	done

	echo "$ret"
}

function populate_pass_mops()
{
	local rn=0
	local cn
	local i
	local j

	for i in ${BUFSIZE[@]}
	do
		cn=0
		ref_mops=$(get_ref_mops $1 $i)
		for j in ${CORES[@]}
		do
			tmp=$(( $cn + 2 ))
			ref_n=$(echo "$ref_mops" | cut -d " " -f $tmp)
			PASS_MOPS_TABLE[$rn,$cn]=$(echo "($ref_n * .97)" | bc)
			let cn=cn+1
		done
		let rn=rn+1
	done
}

function populate_act_mops()
{
	local rn=0
	local cn
	local i

	case $1 in
		1) cn=0;;
		2) cn=1;;
		4) cn=2;;
		*) echo "Core number $1 not supported">&2; exit 1;;
	esac

	for i in ${BUFSIZE[@]}
	do
		ACT_MOPS_TABLE[$rn,$cn]=""
		ACT_MOPS_TABLE[$rn,$cn]=$(check_mops $1 $i)
		let rn=rn+1
	done
}

function check_errors()
{
	local ret=0
	local err

	for err in "${CPT_PERF_ERROR_PATTERNS[@]}"; do
		grep -i "$err" $OUT 2>/dev/null 1>/dev/null
		if [ $? -eq 0 ]; then
			echo "Error running crypto perf">&2
			ret=2
			break
		fi
	done

	echo "$ret"
}

function post_run()
{
	local ret

	ret=$(check_errors)
	if [ "$ret" != "2" ]; then
		populate_act_mops $2
		ret=$(compare_pass_mops $1 $2)
	fi
	echo "$ret"
}

function crypto_perf_common()
{
	local try_cnt
	local eargs
	local j=0
	local ret
	local i

	echo "Perf Test: $1"
	populate_pass_mops $1

	for i in ${COREMASK[@]}
	do
		try_cnt=1
		eargs=$EAL_ARGS" -c $i"
		while [ $try_cnt -le $MAX_TRY_CNT ]; do
			echo "Run $try_cnt"
			cryptoperf_run "$eargs" "$2"
			cat $OUT
			ret=$(post_run $1 ${CORES[$j]})
			if [ "$ret" == "0" ]; then
				echo "Test Passed"
				break
			fi
			let try_cnt=try_cnt+1
		done
		if [[ $try_cnt -gt $MAX_TRY_CNT ]]; then
			echo "Test Failed"
			exit 1
		fi
		let j=j+1
	done
}

function aes_cbc_perf()
{
	local cipher="aes-cbc-only"
	local cipharg="aes-cbc"

	crypto_perf_common "$cipher" "--devtype $DEVTYPE --ptest throughput --optype cipher-only --cipher-algo $cipharg --pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 32 --cipher-iv-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function aes_sha1_hmac_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype cipher-then-auth --cipher-algo $cipher --pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 32 --cipher-iv-sz 16 --auth-algo $auth --auth-op generate --auth-key-sz 64 --digest-sz 20 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function aead_perf()
{
	local cipher="aes-gcm"

	crypto_perf_common "$cipher" "--devtype $DEVTYPE --ptest throughput --optype aead --aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt --aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function aes_sha1_hmac_ipsec_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}-ipsec"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype ipsec --cipher-algo $cipher --pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 16 --cipher-iv-sz 16 --auth-algo $auth --auth-op generate --auth-key-sz 20 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function aead_ipsec_perf()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}-ipsec"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype ipsec --aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt --aead-key-sz 32 --aead-iv-sz 12 --aead-aad-sz 64 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function aes_sha1_hmac_tls12_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}-tls1.2"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype tls-record --cipher-algo $cipher --pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 16 --cipher-iv-sz 16 --auth-algo $auth --auth-op generate --auth-key-sz 20 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly --tls-version TLS1.2"
}

function aead_tls12_perf()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}-tls1.2"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype tls-record --aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt --aead-key-sz 32  --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly --tls-version TLS1.2"
}

function aes_sha1_hmac_dtls12_perf()
{
	local cipher="aes-cbc"
	local auth="sha1-hmac"
	local algo_str="${cipher}_${auth}-dtls1.2"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype tls-record --cipher-algo $cipher --pool-sz $POOLSZ --cipher-op encrypt --cipher-key-sz 16 --cipher-iv-sz 16 --auth-algo $auth --auth-op generate --auth-key-sz 20 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly --tls-version DTLS1.2"
}

function aead_dtls12_perf()
{
	local cipher="aes-gcm"
	local algo_str="${cipher}-dtls1.2"

	crypto_perf_common "$algo_str" "--devtype $DEVTYPE --ptest throughput --optype tls-record --aead-algo $cipher --pool-sz $POOLSZ --aead-op encrypt --aead-key-sz 32 --digest-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly --tls-version DTLS1.2"
}

function zuc_eia3_perf()
{
	local auth="zuc-eia3"

	crypto_perf_common "$auth" "--devtype $DEVTYPE --ptest throughput --optype auth-only --auth-algo $auth --pool-sz $POOLSZ --auth-op generate --auth-key-sz 16 --digest-sz 4 --auth-iv-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function zuc_eea3_perf()
{
	local cipher="zuc-eea3"

	crypto_perf_common "$cipher" "--devtype $DEVTYPE --ptest throughput --optype cipher-only --cipher-algo $cipher --pool-sz $POOLSZ --cipher-op decrypt --cipher-key-sz 16 --cipher-iv-sz 16 --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function ae_modex_perf()
{
	local optype="modex"

	crypto_perf_common "$optype" "--devtype $DEVTYPE --ptest throughput --optype $optype --pool-sz $POOLSZ --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --silent --csv-friendly"
}

function ae_ecdsa_perf()
{
	local optype="ecdsa_p256r1"
	local asymoptype="sign"
	local algostr="ecdsa-sign"
	BUFSIZE=(64)
	BUFFERSZ="64"
	NUMOPS=100000
	crypto_perf_common "$algostr" "--devtype $DEVTYPE --ptest throughput --optype $optype --pool-sz $POOLSZ --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --asym-op $asymoptype --silent --csv-friendly"
	BUFSIZE=(64 384 1504)
	BUFFERSZ="64,384,1504"
	NUMOPS=10000000
}

function ae_sm2_perf()
{
	local optype="sm2"
	local asymoptype="sign"
	local algostr="sm2-sign"
	BUFSIZE=(64)
	BUFFERSZ="64"
	NUMOPS=100000
	crypto_perf_common "$algostr" "--devtype $DEVTYPE --ptest throughput --optype $optype --pool-sz $POOLSZ --buffer-sz $BUFFERSZ --total-ops $NUMOPS --burst-sz $BURSTSZ --asym-op $asymoptype --silent --csv-friendly"
	BUFSIZE=(64 384 1504)
	BUFFERSZ="64,384,1504"
	NUMOPS=10000000
}

echo "Starting crypto perf application"

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

get_system_info
if [[ $IS_CN10K -ne 0 ]]; then
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${FEXT}
else
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"_cptclk"${CPTCLK}"."${FEXT}
fi

FPATH="$SCRIPTPATH/ref_numbers/$HW/$FNAME"

if [[ ! -f "$FPATH" ]]; then
	exit 1
fi

aes_cbc_perf
aes_sha1_hmac_perf
aead_perf
aes_sha1_hmac_ipsec_perf
aead_ipsec_perf
zuc_eia3_perf
zuc_eea3_perf
ae_modex_perf
ae_ecdsa_perf

if [[ $PART_106B0 == "B0" ]]; then
	ae_sm2_perf
fi

if [[ $IS_CN103 -ne 0 ]] || [[ $PART_106B0 == "B0" ]]; then
	aead_tls12_perf
	aes_sha1_hmac_tls12_perf
	aead_dtls12_perf
	aes_sha1_hmac_dtls12_perf
fi

echo "Crypto perf application completed"
exit 0
