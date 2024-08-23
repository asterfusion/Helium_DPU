# Octeon device plugin for VPP  {#dev_octeon_doc}

## Overview
This plugin provides native device support for Marvell OCTEON-10 SoCs.
This OCTEON native implementation optimizes the interface between hardware
and VPP fast-path data structures. It integrates the following hardware
accelerators into VPP:
- Network interface controller (aka NIX) for packet ingress and egress

## Supported SoC
- OCTEON-10
- OCTEON-9


## Usage
The following steps demonstrate how you may bring up VPP with dev_octeon, on the
OCTEON platform.

### Setup

#### Configure NIX on OCTEON
-# Determine NIX PF on OCTEON
```
# lspci -d 177d::0200 | grep 'a063'
  0002:02:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
  0002:03:00.0 Ethernet controller: Cavium, Inc. Device a063 (rev 08)
```

-# Bind NIX VF to vfio-pci driver
```
echo 0002:03:00.0 > /sys/bus/pci/devices/0002:03:00.0/driver/unbind
echo 0002:02:00.0 > /sys/bus/pci/devices/0002:02:00.0/driver/unbind

echo 177d a063 > /sys/bus/pci/drivers/vfio-pci/new_id

echo 0002:02:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
echo 0002:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind

```

### Launch VPP
VPP device bringup with dev_octeon is possible either through vppctl commands or
startup conf.

#### Device bringup using vppctl
Launch VPP with startup conf.

```
# vpp -c /etc/vpp/startup.conf
# vppctl -s /run/vpp/cli.sock
      _______    _        _   _____  ___
   __/ __/ _ \  (_)__    | | / / _ \/ _ \
   _/ _// // / / / _ \   | |/ / ___/ ___/
   /_/ /____(_)_/\___/   |___/_/  /_/

   vpp# device attach pci/0002:02:00.0 driver octeon
   vpp# device create-interface pci/0002:02:00.0 port 0 num-rx-queues 4
   vpp# device attach pci/0002:03:00.0 driver octeon
   vpp# device create-interface pci/0002:03:00.0 port 0 num-rx-queues 4
```

#### Device bringup using startup.conf device section
```
devices {
   dev pci/0002:02:00.0
   {
     driver octeon
     port 0
      {
        name eth0
        num-rx-queues 4
        num-tx-queues 4
      }
   }

   dev pci/0002:03:00.0
   {
     driver octeon
     port 0
      {
        name eth1
        num-rx-queues 5
        num-tx-queues 5
      }
   }
}
```
