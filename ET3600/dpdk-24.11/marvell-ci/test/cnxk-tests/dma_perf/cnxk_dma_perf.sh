#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2023 Marvell.

set -e

CNXKTESTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
CONFIG_PATH="$1/marvell-ci/test/cnxk-tests/dma_perf/"

declare -i num_tests
declare -a test_name
declare -a test_cmd
declare -a test_config
declare -a test_result
declare -a test_suffix

SUDO="sudo"
MAX_RETRY=${MAX_RETRY:-5}
TOLERANCE=${TOLERANCE:-6}

NUM_DPI=1
NUMVFS=1

! $(cat /proc/device-tree/compatible | grep -q "cn10k")
IS_CN10K=$?

# Find the dpdk-test-dma-perf application
if [[ -f $CNXKTESTPATH/../../../../app/dpdk-test-dma-perf ]]; then
	# This is running from build directory
	PATH="$CNXKTESTPATH/../../../../app:$PATH"
elif [[ -f $CNXKTESTPATH/../../dpdk-test-dma-perf ]]; then
	# This is running from install directory
	PATH="$CNXKTESTPATH/../..:$PATH"
else
	TESTDMA_BIN=$(which dpdk-test-dma-perf)
	if [[ -z $TESTDMA_BIN ]]; then
		echo "dpdk-test-dma-perf not found !!"
		exit 1
	fi
fi

function cleanup_dma_dev()
{
	echo "Cleaning up DMA and NPA device"
	DPIPF=$(lspci -d 177d:a080|awk '{print $1}' | head -${NUM_DPI})
	echo "###### DPI PFs ######"
	echo "$DPIPF"

	# bind only required NPA and DPI VFs to vfio-pci
	DPIVF=$(lspci -d 177d:a081|awk '{print $1}')
	echo -e "\n"
	echo "###### DPI VFs ######"
	echo "$DPIVF"

	NPAPF=$(lspci -d 177d:a0fb|awk '{print $1}'|head -1)
	echo -e "\n"
	echo "NPA PF $NPAPF ..."

	dpi_devs=(${DPIVF} $NPAPF)

	# unbind device to vfio-pci
	for DEV in ${dpi_devs[*]}; do
		$VFIO_DEVBIND -u $DEV
	done

	for PF in $DPIPF; do
		echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs
	done
}

function setup_dma_dev()
{
	DPIPF=$(lspci -d 177d:a080|awk '{print $1}' | head -${NUM_DPI})
	echo "###### DPI PFs ######"
	echo "$DPIPF"

	echo "Creating DPI VFs ..."
	for PF in $DPIPF
	do
		DPIVFS=$(cat /sys/bus/pci/devices/$PF/sriov_numvfs)
		echo "Current number of VFs under DPIPF $PF = $DPIVFS"
		if [ "x$DPIVFS" != x"$NUMVFS" ]; then
			echo "Creating $NUMVFS VFs for DPIPF $PF ..."
			echo 0 > /sys/bus/pci/devices/$PF/sriov_numvfs
			echo $NUMVFS > /sys/bus/pci/devices/$PF/sriov_numvfs
			if [ x"$?" != "x0" ]; then
				echo -n \
		"""Failed to enable $DPI DMA queues.
		""" >&2
			exit 1
		fi
		fi
	done

	# bind only required NPA and DPI VFs to vfio-pci
	DPIVF=$(lspci -d 177d:a081|awk '{print $1}')
	echo -e "\n"
	echo "###### DPI VFs ######"
	echo "$DPIVF"

	NPAPF=$(lspci -d 177d:a0fb|awk '{print $1}'|head -1)
	echo -e "\n"
	echo "Using NPA PF $NPAPF ..."

	dpi_devs=(${DPIVF} $NPAPF)

	# bind device to vfio-pci
	for DEV in ${dpi_devs[*]}; do
		$VFIO_DEVBIND -b vfio-pci $DEV
	done
}

function setup_test_config()
{
	i=4
	t=0
	DPIVF=$(lspci -d 177d:a081|awk '{print $1}' | head -${NUM_DPI})

	while [[ t -lt num_tests ]]
	do
		for VF in $DPIVF
		do
			printf "lcore_dma=lcore%d@%s" $i $VF >> ${test_config[$t]}
		done
		((t+=1))
		((i+=1))
	done
}

function cleanup_test_config()
{
	t=0

	while [[ t -lt num_tests ]]
	do
		sed -i '$ d' ${test_config[$t]}
		if [[ -f ${test_result[$t]} ]]; then
			rm ${test_result[$t]}
		fi
		((t+=1))
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
	fi

	pkill -9 dpdk-test-dma-perf
	cleanup_test_config
	cleanup_dma_dev
	exit $status
}

trap "sig_handler ERR" ERR
trap "sig_handler INT" INT
trap "sig_handler QUIT" QUIT
trap "sig_handler EXIT" EXIT

# Get CPU PART NUMBER
PARTNUM_106XX=0xd49
PARTNUM=$(grep -m 1 'CPU part' /proc/cpuinfo | awk -F': ' '{print $2}')
if [[ $PARTNUM == $PARTNUM_98XX ]]; then
	HW="cn98"
else
	if [[ $PARTNUM == $PARTNUM_106XX ]]; then
		HW="cn106"
		TOLERANCE=$(echo "$TOLERANCE - 3" | bc)
	else
		HW="cn96"
	fi
fi

# get chip number and RCLK
function get_system_info()
{
	local sysclk_dir
	local fp_rclk
	local fp_sclk
	local div=1000000

	sysclk_dir="/sys/kernel/debug/clk"
	if [[ $PARTNUM == $PARTNUM_106XX ]]; then
		fp_rclk="$sysclk_dir/coreclk/clk_rate"
	else
		fp_rclk="$sysclk_dir/rclk/clk_rate"
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

	echo "RCLK:   $RCLK Mhz"
	echo "SCLK:   $SCLK Mhz"
}

function register_dma_test()
{
        test_name[$num_tests]=$1
	test_cmd[$num_tests]=$2
        test_config[$num_tests]=$CONFIG_PATH$3
	test_result[$num_tests]=$CONFIG_PATH$4

	if [ ${test_name[$num_tests]} = "TESTDMA_MEM_TO_MEM" ]; then
		test_suffix[$num_tests]="m2m"
	elif [ ${test_name[$num_tests]} =  "TESTDMA_MEM_TO_DEV" ]; then
		test_suffix[$num_tests]="m2d"
	elif [ ${test_name[$num_tests]} =  "TESTDMA_DEV_TO_MEM" ]; then
		test_suffix[$num_tests]="d2m"
	fi

        ((num_tests+=1))
}

expected_mops()
{
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}"."${test_suffix[$1]}
	FPATH="$CNXKTESTPATH/ref_numbers/$FNAME"
	if [[ ! -f $FPATH ]]; then echo 'Err: ref file missing !!'; exit 1; fi

	mops_gold=$(grep "${test_name[$1]}" $FPATH \
			| tr -s ' ' | cut -d " " -f 2)
	echo "($mops_gold * (100 - $TOLERANCE)) / 100" | bc
}

ref_mops()
{
	FNAME="rclk"${RCLK}"_sclk"${SCLK}"."${HW}"."${test_suffix[$1]}
	FPATH="$CNXKTESTPATH/ref_numbers/$FNAME"
	if [[ ! -f $FPATH ]]; then echo 'Err: ref file missing !!'; exit 1; fi

	mops_gold=$(grep "${test_name[$1]}" $FPATH \
			| tr -s ' ' | cut -d " " -f 2)
	echo $mops_gold
}

dma_perf_result()
{
	local MOps=$(grep "Summary" ${test_result[$1]} | cut -d "," -f11 | bc)
	echo $MOps
}

check_mops()
{
	idx=$1
	pass_mops=$(expected_mops $idx)
	ref_mops=$(ref_mops $idx)
	local retry=1

	while [[ retry -ne 0 ]]
	do
		mops=$(dma_perf_result $idx)

		if [[ ${mops%.*} -lt ${pass_mops%.*} ]]; then
			echo -n "Low MOPS for ${test_name[$idx]} ($mops < $pass_mops)"
			echo " (Ref $ref_mops, tolerance $TOLERANCE%)"
		else
			echo -n "MOPS $mops as expected $pass_mops"
			echo " (Ref $ref_mops, tolerance $TOLERANCE%)"
			return 0
		fi

		sleep 1
		((retry-=1))
	done

	return 1
}

function run_dma_tests()
{
	get_system_info

	idx=0
	ret=0
	local retry_count=$MAX_RETRY
	while [[ idx -lt num_tests ]]; do
		${test_cmd[$idx]} --config ${test_config[$idx]} --result ${test_result[$idx]}
		sleep 3
		set +e
		check_mops $idx
		set -e
		((idx+=1))
	done

	exit $ret
}

num_tests=0

# Register dma performance tests.
# Format:              <test name>         <cmd>            <config>               <test result>

register_dma_test "TESTDMA_MEM_TO_MEM" "dpdk-test-dma-perf" "mem_to_mem_config.ini" "dma_perf_result1.csv"
#register_dma_test "TESTDMA_MEM_TO_DEV" "dpdk-test-dma-perf" "mem_to_dev_config.ini" "dma_perf_result2.csv"
#register_dma_test "TESTDMA_DEV_TO_MEM" "dpdk-test-dma-perf" "dev_to_mem_config.ini" "dma_perf_result3.csv"

setup_dma_dev
setup_test_config
run_dma_tests
cleanup_test_config
cleanup_dma_dev
