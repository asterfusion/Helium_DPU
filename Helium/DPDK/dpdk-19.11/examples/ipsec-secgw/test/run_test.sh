#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause

# usage: /bin/bash run_test.sh [-46]
# Run all defined linux_test[4,6].sh test-cases one by one
# user has to setup properly the following environment variables:
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
# refer to linux_test[4,6].sh for more information


# All supported modes to test.
# naming convention:
# 'old' means that ipsec-secgw will run in legacy (non-librte_ipsec mode)
# 'tun/trs' refer to tunnel/transport mode respectively

usage()
{
	echo "Usage:"
	echo -e "\t$0 -[46p]"
	echo -e "\t\t-4 Perform Linux IPv4 network tests"
	echo -e "\t\t-6 Perform Linux IPv6 network tests"
	echo -e "\t\t-p Perform packet validation tests"
	echo -e "\t\t-h Display this help"
}

LINUX_TEST="tun_aescbc_sha1 \
tun_aescbc_sha1_esn \
tun_aescbc_sha1_esn_atom \
tun_aesgcm \
tun_aesgcm_esn \
tun_aesgcm_esn_atom \
trs_aescbc_sha1 \
trs_aescbc_sha1_esn \
trs_aescbc_sha1_esn_atom \
trs_aesgcm \
trs_aesgcm_esn \
trs_aesgcm_esn_atom \
tun_aescbc_sha1_old \
tun_aesgcm_old \
trs_aescbc_sha1_old \
trs_aesgcm_old \
tun_aesctr_sha1 \
tun_aesctr_sha1_old \
tun_aesctr_sha1_esn \
tun_aesctr_sha1_esn_atom \
trs_aesctr_sha1 \
trs_aesctr_sha1_old \
trs_aesctr_sha1_esn \
trs_aesctr_sha1_esn_atom \
tun_3descbc_sha1 \
tun_3descbc_sha1_old \
tun_3descbc_sha1_esn \
tun_3descbc_sha1_esn_atom \
trs_3descbc_sha1 \
trs_3descbc_sha1_old \
trs_3descbc_sha1_esn \
trs_3descbc_sha1_esn_atom"

PKT_TESTS="trs_ipv6opts \
tun_null_header_reconstruct"

DIR=$(dirname $0)

# get input options
run4=0
run6=0
runpkt=0
while getopts ":46ph" opt
do
	case $opt in
		4)
			run4=1
			;;
		6)
			run6=1
			;;
		p)
			runpkt=1
			;;
		h)
			usage
			exit 0
			;;
		?)
			echo "Invalid option"
			usage
			exit 127
			;;
	esac
done

# no test suite has been selected
if [[ ${run4} -eq 0 && ${run6} -eq 0 && ${runpkt} -eq 0 ]]; then
	usage
	exit 127
fi

# perform packet processing validation tests
st=0
if [ $runpkt -eq 1 ]; then
	echo "Performing packet validation tests"
	/bin/bash ${DIR}/pkttest.sh ${PKT_TESTS}
	st=$?

	echo "pkttests finished with status ${st}"
	if [[ ${st} -ne 0 ]]; then
		echo "ERROR pkttests FAILED"
		exit ${st}
	fi
fi

# perform network tests
if [[ ${run4} -eq 1 || ${run6} -eq 1 ]]; then
	for i in ${LINUX_TEST}; do

		echo "starting test ${i}"

		st4=0
		if [[ ${run4} -ne 0 ]]; then
			/bin/bash ${DIR}/linux_test4.sh ${i}
			st4=$?
			echo "test4 ${i} finished with status ${st4}"
		fi

		st6=0
		if [[ ${run6} -ne 0 ]]; then
			/bin/bash ${DIR}/linux_test6.sh ${i}
			st6=$?
			echo "test6 ${i} finished with status ${st6}"
		fi

		let "st = st4 + st6"
		if [[ $st -ne 0 ]]; then
			echo "ERROR test ${i} FAILED"
			exit $st
		fi
	done
fi
