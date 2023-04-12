#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause

# usage:  /bin/bash linux_test4.sh <ipsec_mode>
# for list of available modes please refer to run_test.sh.
# ipsec-secgw (IPv4 mode) functional test script.
#
# Note that for most of them you required appropriate crypto PMD/device
# to be avaialble.
# Also user has to setup properly the following environment variables:
#  SGW_PATH - path to the ipsec-secgw binary to test
#  REMOTE_HOST - ip/hostname of the DUT
#  REMOTE_IFACE - iface name for the test-port on DUT
#  ETH_DEV - ethernet device to be used on SUT by DPDK ('-w <pci-id>')
# Also user can optonally setup:
#  SGW_LCORE - lcore to run ipsec-secgw on (default value is 0)
#  CRYPTO_DEV - crypto device to be used ('-w <pci-id>')
#  if none specified appropriate vdevs will be created by the scrit
#  MULTI_SEG_TEST - ipsec-secgw option to enable reassembly support and
#  specify size of reassembly table (i.e. MULTI_SEG_TEST="--reassemble 128")
#
# The purpose of the script is to automate ipsec-secgw testing
# using another system running linux as a DUT.
# It expects that SUT and DUT are connected through at least 2 NICs.
# One NIC is expected to be managed by linux both machines,
# and will be used as a control path
# Make sure user from SUT can ssh to DUT without entering password.
# Second NIC (test-port) should be reserved for DPDK on SUT,
# and should be managed by linux on DUT.
# The script starts ipsec-secgw with 2 NIC devices: test-port and tap vdev.
# Then configures local tap iface and remote iface and ipsec policies
# in the following way:
# traffic going over test-port in both directions has to be
# protected by ipsec.
# raffic going over TAP in both directions doesn't have to be protected.
# I.E:
# DUT OS(NIC1)--(ipsec)-->(NIC1)ipsec-secgw(TAP)--(plain)-->(TAP)SUT OS
# SUT OS(TAP)--(plain)-->(TAP)psec-secgw(NIC1)--(ipsec)-->(NIC1)DUT OS
# Then tries to perorm some data transfer using the scheme decribed above.
#

DIR=`dirname $0`
MODE=$1

 . ${DIR}/common_defs.sh
 . ${DIR}/${MODE}_defs.sh

#make linux to generate fragmented packets
if [[ -n "${MULTI_SEG_TEST}" && -n "${SGW_CMD_XPRM}" ]]; then
	echo "multi-segment test is enabled"
	SGW_CMD_XPRM="${SGW_CMD_XPRM} ${MULTI_SEG_TEST}"
	PING_LEN=5000
	MTU_LEN=1500
else
	PING_LEN=${DEF_PING_LEN}
	MTU_LEN=${DEF_MTU_LEN}
fi

config_secgw

secgw_start

config_iface

config_remote_xfrm

 . ${DIR}/data_rxtx.sh

set_local_mtu ${MTU_LEN}
ping_test1 ${REMOTE_IPV4} 0 ${PING_LEN}
st=$?
if [[ $st -eq 0 ]]; then
	set_local_mtu ${DEF_MTU_LEN}
	scp_test1 ${REMOTE_IPV4}
	st=$?
fi

secgw_stop
exit $st
