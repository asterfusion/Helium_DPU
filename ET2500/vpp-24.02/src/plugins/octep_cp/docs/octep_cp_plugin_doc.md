# OCTEON end point control plain plugin (OCTEP-CP) for VPP  {#octep_cp_plugin_doc}

## Overview
This plugin implements Marvell OCTEON PCIe end point control plane protocol.
Marvell OCTEON firmware provides convenience user library liboctep.so to
setup and interact with the host over mailbox. This octep_cp plugin uses
liboctep.so library to read/send control message from/to host over mailbox.

## Supported SoC
- OCTEON CN10KXX

## Usage
The following steps demonstrate how you may bring up VPP with octep_cp, on the
OCTEON connected to host.
1. Enable octep_cp plugin in VPP startup.conf file
2. octep_cp plugin initializes liboctep.so library which initializes SDP firmware.
3. If there are any messages from host firmware puts them into mailbox.
4. octep_cp plugin regularly calls liboctep.so API's to check mailbox.
5. octep_cp plugin applies configuration action requested by host and replies
   success or failure to host.

### Setup
1. OCTEON should be connected to host via SDP interface.
2. Determine SDP interface on OCTEON
   "lspci | grep SDP" OR "dmesg | grep sdp"
	 0002:1f:00.0 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Physical Function (rev 51)
	 0002:1f:00.1 Ethernet controller: Cavium, Inc. Octeon Tx2 SDP Virtual Function (rev 51)
3. Bind SDP VF to vfio-pci driver
   dpdk-devbind.py -b vfio-pci 0002:1f:00.1
4. Modify startup.conf
   - Enable octep_cp plugin
     plugins {
         plugin octep_cp_plugin.so { enable }
     }
	 - Add SDP VF device under `onp` section
     onp {
         dev 0002:1f:00.1
     }
5. Determine SDP interface on HOST side
   - lspci | grep Cavium
	   17:00.0 Network controller: Cavium, Inc. Device b900
	 - load OCTEON PF and VF driver, insmod octeon_ep.ko octeon_ep_vf.ko
	 - create required VF's with 'echo 1 > /sys/bus/pci/devices/0000\:17\:00.0/sriov_numvfs'

#### Configuration
This plugin uses /usr/bin/cn10kxx.cfg configuration file to configure
PCIe end point.
