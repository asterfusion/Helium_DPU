#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2021 Marvell.

set -euo pipefail

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

CNXK_MEMPOOL_DEVICE=$(lspci -d :a0fb | tail -1 | awk -e '{ print $1 }')
CNXK_EAL_VDEV_OPENSSL="--vdev crypto_openssl"

NIX_INL_DEV=${NIX_INL_DEV:-$(lspci -d :a0f0 | tail -1 | awk -e '{ print $1 }')}
NIX_INL_DEVICE="$NIX_INL_DEV"

ETH_DEV=${ETH_DEV:-$(lspci -d :a0f8 | head -1 | awk -e '{ print $1 }')}
ETHERNET_DEVICE="$ETH_DEV"

CN10K_CRYPTO_DEVICE="0002:20:00.1"
CN10K_EAL_ARGS="-a $ETHERNET_DEVICE -a $NIX_INL_DEVICE,rx_inject_qp=1 -a $CN10K_CRYPTO_DEVICE,max_qps_limit=4,rx_inject_qp=1 -a $CNXK_MEMPOOL_DEVICE"
CN10K_EAL_ARGS+=" --log-level=7"

CN9K_CRYPTO_DEVICE="0002:10:00.1"
CN9K_EAL_ARGS="-a $CN9K_CRYPTO_DEVICE,max_qps_limit=4 -a $CNXK_MEMPOOL_DEVICE"
CN9K_EAL_ARGS+=" --log-level=7"

if [[ -f $SCRIPTPATH/../../../../app/test/dpdk-test ]]; then
	# This is running from build directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../../../app/test/dpdk-test
elif [[ -f $SCRIPTPATH/../../dpdk-test ]]; then
	# This is running from install directory
	DPDK_TEST_BIN=$SCRIPTPATH/../../dpdk-test
else
	DPDK_TEST_BIN=$(which dpdk-test)
	if [[ -z $DPDK_TEST_BIN ]]; then
		echo "dpdk-test not found !!"
		exit 1
	fi
fi

run_cn10k_crypto_autotest() {
	DPDK_TEST=cryptodev_cn10k_autotest $DPDK_TEST_BIN $CN10K_EAL_ARGS
	DPDK_TEST=cryptodev_cn10k_asym_autotest $DPDK_TEST_BIN $CN10K_EAL_ARGS
	DPDK_TEST=cryptodev_cn10k_raw_api_autotest $DPDK_TEST_BIN $CN10K_EAL_ARGS
	DPDK_TEST=cryptodev_crosscheck $DPDK_TEST_BIN $CN10K_EAL_ARGS $CNXK_EAL_VDEV_OPENSSL
}

run_cn9k_crypto_autotest() {
	DPDK_TEST=cryptodev_cn9k_autotest $DPDK_TEST_BIN $CN9K_EAL_ARGS
	DPDK_TEST=cryptodev_cn9k_asym_autotest $DPDK_TEST_BIN $CN9K_EAL_ARGS
	DPDK_TEST=cryptodev_crosscheck $DPDK_TEST_BIN $CN9K_EAL_ARGS $CNXK_EAL_VDEV_OPENSSL
}

run_crypto_autotest() {
	case $PLAT in
		cn9*) run_cn9k_crypto_autotest ;;
		cn10*) run_cn10k_crypto_autotest ;;
	esac
}

run_crypto_autotest
