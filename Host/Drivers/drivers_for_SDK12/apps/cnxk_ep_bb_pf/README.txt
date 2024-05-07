Introduction
============

The Physical Function (PF) Baseband Device (BBDEV) Application
(cnxk_ep_bb_pf) provides a means to use vfio-pci driver to create
VFs for usage with DPDK BBdev PMD.

Building the PF BBDEV Application
=================================

To build the application run make

Usage
=====

To run the application

#./cnxk_ep_bb_pf  [-h] -p <pf DBDF> -v <vfio_token>

* -h: Prints help
* -p: Specifies PCI DBDF of device to attach
* -v: vfio-token is UUID formatted VFIO VF token for vfio-pci

Load the vfio-pci driver with sriov capability enabled if not already loaded:

# modprobe vfio-pci enable_sriov=1  enable_unsafe_noiommu_mode=1

Bind the PF with the vfio-pci module:

#<Path to DPDK>/usertools/dpdk-devbind.py --bind=vfio-pci <PF DBDF>

# ./cnxk_ep_bb_pf -p 0000:02:00.0 -v 00112233-4455-6677-8899-aabbccddeeff

Note: replace 0000:02:00.0 with BBDEV PF

Create VF from the PF using the exposed sysfs interface:

# echo 1 | sudo tee /sys/bus/pci/devices/0000:02:00.0/sriov_numvfs

# <Path to DPDK>/usertools/dpdk-devbind.py --bind=vfio-pci <VF DBDF>

Test that the VF is functional on the device using bbdev-test:

# <Path to DPDK>/build/app/dpdk-test-bbdev -l 0-1 -a <VF DBDF> --vfio-vf-token=00112233-4455-6677-8899-aabbccddeeff -- -c validation -v ./ldpc_dec_default.data

Note:

UUID(Universally Unique Identifier) used in above example should be generated
using uuidgen instead of static uuid

VFIO VF token support is available only in Linux kernel version 5.7 or later.
