# OCTEON native plugin (ONP) for VPP  {#onp_plugin_doc}

## Overview
This plugin provides native device support for Marvell OCTEON-10 family of SoCs.
This OCTEON native implementation optimizes the interface between hardware
and VPP fast-path data structures. It integrates the following hardware
accelerators into VPP:
- Network interface controller (aka NIX) for packet ingress and egress
- Cryptographic accelerator for IPsec

## Supported SoC
- OCTEON CN10KXX

## Known issues
- The DPDK plugin must be disabled from startup.conf, prior to launching ONP.
  ONP cannot co-exist with the DPDK plugin, at runtime.

## Usage
The following steps demonstrate how you may bring up VPP with ONP, on the
OCTEON platform.

### Setup

#### Configure NIX VF on OCTEON
-# Determine NIX PF on OCTEON
```
# lspci -d 177d::0200 | grep 'a063'
  0002:02:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
  0002:07:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
```

-# Create 1 VF each for 2 NIX PF
```
# echo 1 > /sys/bus/pci/devices/0002\:02\:00.0/sriov_numvfs
# echo 1 > /sys/bus/pci/devices/0002\:07\:00.0/sriov_numvfs
```

-# Bind NIX VF to vfio-pci driver
```
dpdk-devbind.py -b vfio-pci 0002:02:00.1 0002:07:00.1
```

#### Modify startup.conf
-# Disable the DPDK plugin and enable the ONP plugin
```
plugins {
    plugin dpdk_plugin.so { disable }
    plugin onp_plugin.so { enable }
}
```

-# Add NIX devices under the `onp` section
```
  onp {
      dev 0002:02:00.1
      dev 0002:07:00.1
  }
```

### Launch VPP
Launch VPP with startup.conf as modified above and confirm
that the ONP plugin has been loaded successfully.
```
# vpp -c /etc/vpp/startup.conf
# vppctl -s /run/vpp/cli.sock
      _______    _        _   _____  ___
   __/ __/ _ \  (_)__    | | / / _ \/ _ \
   _/ _// // / / / _ \   | |/ / ___/ ___/
   /_/ /____(_)_/\___/   |___/_/  /_/

   vpp# show version
   vpp v22.10-release built by root on 485d58387b9e at Mon Sep 18 23:27:03 UTC 2023
   vpp#
   vpp# sh onp version
   ONP plugin version:            2.1.0
```
