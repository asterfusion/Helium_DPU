#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2022 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1; pwd -P )"

if [[ -f $SCRIPTPATH/../../../../app/test/dpdk-test ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/test/dpdk-test
elif [[ -f $SCRIPTPATH/../../dpdk-test ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test
else
	DPDK_TEST_BIN=$(command -v dpdk-test)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test not found !!"
		exit 1
	fi
fi

if [[ -f $1/marvell-ci/test/board/oxk-devbind-basic.sh ]]; then
	VFIO_DEVBIND="$1/marvell-ci/test/board/oxk-devbind-basic.sh"
else
	VFIO_DEVBIND=$(command -v oxk-devbind-basic.sh)
fi
if [[ -z $VFIO_DEVBIND ]]; then
	echo "oxk-devbind-basic.sh not found !!"
	exit 1
fi

run_cnxk_gpio_test() {
	DPDK_TEST=rawdev_autotest $DPDK_TEST_BIN --vdev=cnxk_gpio,gpiochip="$1",allowlist="$2"
}

run_cn9k_gpio_test() {
	local gpios

	case $1 in
		CN98XX-CRB) gpios="[51]" ;;
		ebb9604p) gpios="[63]" ;;
		*) echo "$1 not supported"; exit 0 ;;
	esac

	run_cnxk_gpio_test "$2" "$gpios"
}

run_cn10k_gpio_test() {
	local gpios

	case $1 in
		ASIM-CN*) gpios="[1,2,3,4,5,6]" ;;
		*) echo "$1 not supported"; exit 0 ;;
	esac

	run_cnxk_gpio_test "$2" "$gpios"
}

run_gpio_test() {
	local gpiochip
	local model

	model=$(tr -d '\0' </proc/device-tree/octeontx_brd/BOARD-MODEL)
	# all setups have single gpiochip now
	gpiochip=$(ls /sys/class/gpio | grep gpiochip | grep -o '[[:digit:]]\+')

	case $PLAT in
		cn9*) run_cn9k_gpio_test "$model" "$gpiochip";;
		cn10*) run_cn10k_gpio_test "$model" "$gpiochip";;
	esac
}

# unbind BPHY from VFIO to make sure only gpio rawdev tests get executed
BPHY=$(lspci -d 177d:a089 | cut -d ' ' -f 1)
if [[ -n $BPHY ]]; then
	$VFIO_DEVBIND -u $BPHY
fi

run_gpio_test
