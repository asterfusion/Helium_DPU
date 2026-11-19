#!/bin/sh -e
echo 12 > /sys/bus/pci/devices/0002\:02\:00.0/sriov_numvfs
ifconfig eth1 up

ip link set eth1 vf 0 trust on
ip link set eth1 vf 1 trust on
ip link set eth1 vf 2 trust on
ip link set eth1 vf 3 trust on
ip link set eth1 vf 4 trust on
ip link set eth1 vf 5 trust on
ip link set eth1 vf 6 trust on
ip link set eth1 vf 7 trust on
ip link set eth1 vf 8 trust on
ip link set eth1 vf 9 trust on
ip link set eth1 vf 10 trust on
ip link set eth1 vf 11 trust on

ip link set eth1 vf 0  mac 10:11:22:33:44:11
ip link set eth1 vf 1  mac 10:11:22:33:44:22
ip link set eth1 vf 2  mac 10:11:22:33:44:33
ip link set eth1 vf 3  mac 00:11:22:33:44:44
ip link set eth1 vf 4  mac 00:11:22:33:44:55
ip link set eth1 vf 5  mac 00:11:22:33:44:66
ip link set eth1 vf 6  mac 00:11:22:33:44:77
ip link set eth1 vf 7  mac 00:11:22:33:44:88
ip link set eth1 vf 8  mac 00:11:22:33:44:99
ip link set eth1 vf 9  mac 00:11:22:33:44:aa
ip link set eth1 vf 10  mac 00:11:22:33:44:bb
ip link set eth1 vf 11  mac 00:11:22:33:44:cc

ip link set eth1 vf 0 vlan 1
ip link set eth1 vf 1 vlan 2
ip link set eth1 vf 2 vlan 3
ip link set eth1 vf 3 vlan 4
ip link set eth1 vf 4 vlan 5
ip link set eth1 vf 5 vlan 6
ip link set eth1 vf 6 vlan 7
ip link set eth1 vf 7 vlan 8
ip link set eth1 vf 8 vlan 9
ip link set eth1 vf 9 vlan 10
ip link set eth1 vf 10 vlan 11
ip link set eth1 vf 11 vlan 12

ifconfig eth4 down
/home/admin/dpdk-devbind.py -b vfio-pci 0002:02:00.{1,2,3,4,5,6,7} 0002:02:01.{0,1,2,3,4} 0002:03:00.0 0002:04:00.0

sysctl -w vm.nr_hugepages=10
mkdir -p /mnt/huge_2M
mount -t hugetlbfs none /mnt/huge_2M -o pagesize=2MB
echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
