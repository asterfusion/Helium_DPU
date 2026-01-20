#!/usr/bin/python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2024 Marvell.

import sys
import argparse
import subprocess
from scapy.all import *

eth_ports = ["0002:02:00.0"]
interface_def="enP2p2s0"

if __name__ == "__main__":

    for port in eth_ports:
        cmd = ["""/usr/bin/grep PCI_SLOT_NAME /sys/class/net/*/device/uevent |
                /usr/bin/grep {} | /usr/bin/cut -f 5 -d /""" .format(port)]
        interface = subprocess.getoutput(cmd)

        if interface == "":
            interface = interface_def

        cmd = ["""sudo ip link set dev {} up""" .format(interface)]
        subprocess.run(cmd, shell=True)

        if sys.argv[1] == '1':
            print("SCAPY: Sending and receiving packets on interface " + interface)
            srp1(Ether(src="00:0F:B7:06:78:2F",
                dst="00:0F:B7:06:78:3F")/IP()/Raw(RandString(size=80)),iface=interface)
        else:
            print("SCAPY: Sending packets to interface " + interface)
            sendp(Ether(src="00:0F:B7:06:78:2F",
                dst="00:0F:B7:06:78:3F")/IP()/Raw(RandString(size=80)),iface=interface)

    sys.exit(0)
