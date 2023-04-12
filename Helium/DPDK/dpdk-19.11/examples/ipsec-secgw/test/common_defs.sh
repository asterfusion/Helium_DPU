#! /bin/bash
# SPDX-License-Identifier: BSD-3-Clause

#check ETH_DEV
if [[ -z "${ETH_DEV}" ]]; then
	echo "ETH_DEV is invalid"
	exit 127
fi
#check that REMOTE_HOST is reachable
ssh ${REMOTE_HOST} echo
st=$?
if [[ $st -ne 0 ]]; then
	echo "host ${REMOTE_HOST} is not reachable"
	exit $st
fi

#get ether addr of REMOTE_HOST
REMOTE_MAC=`ssh ${REMOTE_HOST} ip addr show dev ${REMOTE_IFACE}`
st=$?
REMOTE_MAC=`echo ${REMOTE_MAC} | sed -e 's/^.*ether //' -e 's/ brd.*$//'`
if [[ $st -ne 0 || -z "${REMOTE_MAC}" ]]; then
	echo "coouldn't retrieve ether addr from ${REMOTE_IFACE}"
	exit 127
fi

LOCAL_IFACE=dtap0

LOCAL_MAC="00:64:74:61:70:30"

REMOTE_IPV4=192.168.31.14
LOCAL_IPV4=192.168.31.92

REMOTE_IPV6=fd12:3456:789a:0031:0000:0000:0000:0014
LOCAL_IPV6=fd12:3456:789a:0031:0000:0000:0000:0092

DPDK_PATH=${RTE_SDK:-${PWD}}
DPDK_BUILD=${RTE_TARGET:-x86_64-native-linux-gcc}

# by default ipsec-secgw can't deal with multi-segment packets
# make sure our local/remote host wouldn't generate fragmented packets
# if reassmebly option is not enabled
DEF_MTU_LEN=1400
DEF_PING_LEN=1200

#setup mtu on local iface
set_local_mtu()
{
	mtu=$1
	ifconfig ${LOCAL_IFACE} mtu ${mtu}
	sysctl -w net.ipv6.conf.${LOCAL_IFACE}.mtu=${mtu}
}

# configure local host/ifaces
config_local_iface()
{
	ifconfig ${LOCAL_IFACE} ${LOCAL_IPV4}/24 up
	ifconfig ${LOCAL_IFACE}

	ip neigh flush dev ${LOCAL_IFACE}
	ip neigh add ${REMOTE_IPV4} dev ${LOCAL_IFACE} lladdr ${REMOTE_MAC}
	ip neigh show dev ${LOCAL_IFACE}
}

config6_local_iface()
{
	config_local_iface

	sysctl -w net.ipv6.conf.${LOCAL_IFACE}.disable_ipv6=0
	ip addr add  ${LOCAL_IPV6}/64 dev ${LOCAL_IFACE}

	ip -6 neigh add ${REMOTE_IPV6} dev ${LOCAL_IFACE} lladdr ${REMOTE_MAC}
	ip neigh show dev ${LOCAL_IFACE}
}

#configure remote host/iface
config_remote_iface()
{
	ssh ${REMOTE_HOST} ifconfig ${REMOTE_IFACE} down
	ssh ${REMOTE_HOST} ifconfig ${REMOTE_IFACE} ${REMOTE_IPV4}/24 up
	ssh ${REMOTE_HOST} ifconfig ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} ip neigh flush dev ${REMOTE_IFACE}

	# by some reason following ip neigh doesn't work for me here properly:
	#ssh ${REMOTE_HOST} ip neigh add ${LOCAL_IPV4} \
	#		dev ${REMOTE_IFACE} lladr ${LOCAL_MAC}
	# so used arp instead.
	ssh ${REMOTE_HOST} arp -i ${REMOTE_IFACE} -s ${LOCAL_IPV4} ${LOCAL_MAC}
	ssh ${REMOTE_HOST} ip neigh show dev ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} iptables --flush
}

config6_remote_iface()
{
	config_remote_iface

	ssh ${REMOTE_HOST} sysctl -w \
		net.ipv6.conf.${REMOTE_IFACE}.disable_ipv6=0
	ssh ${REMOTE_HOST} ip addr add  ${REMOTE_IPV6}/64 dev ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} ip -6 neigh add ${LOCAL_IPV6} \
		dev ${REMOTE_IFACE} lladdr ${LOCAL_MAC}
	ssh ${REMOTE_HOST} ip neigh show dev ${REMOTE_IFACE}

	ssh ${REMOTE_HOST} ip6tables --flush
}

#configure remote and local host/iface
config_iface()
{
	config_local_iface
	config_remote_iface
}

config6_iface()
{
	config6_local_iface
	config6_remote_iface
}

# secgw application parameters setup
SGW_PORT_CFG="--vdev=\"net_tap0,mac=fixed\" ${ETH_DEV}"
SGW_WAIT_DEV="${LOCAL_IFACE}"
. ${DIR}/common_defs_secgw.sh
