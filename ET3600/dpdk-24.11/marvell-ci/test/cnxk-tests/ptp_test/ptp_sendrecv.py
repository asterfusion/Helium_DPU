#!/usr/bin/python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2022 Marvell.

import sys
import argparse
import subprocess
from scapy.all import *

eth_ports = ["0002:02:00.0", "0002:03:00.0"]
interface_def="enP2p2s0"

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
            "-p", "--pcap-file", help="Name of the pcap file", nargs="?",
            type=str, default="ptp.pcap")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    pkts = rdpcap(args.pcap_file)

    if len(pkts) == 0:
        print("SCAPY: Empty pcap file %s" % args.pcap_file)
        sys.exit(0)

    for port in eth_ports:
        cmd = ["""/usr/bin/grep PCI_SLOT_NAME /sys/class/net/*/device/uevent |
                /usr/bin/grep {} | /usr/bin/cut -f 5 -d /""" .format(port)]
        interface = subprocess.getoutput(cmd)

        if interface == "":
            interface = interface_def

        cmd = ["""sudo ip link set dev {} up""" .format(interface)]
        subprocess.run(cmd, shell=True)

        print("SCAPY: Sending %d packets to interface %s" %
            (len(pkts) - 1, interface))

        ptp_dreq = srp1(pkts[:3], promisc=True, iface=interface, timeout=1)

        if ptp_dreq and len(ptp_dreq) != 0:
            clockId = ptp_dreq[Raw].load[20:28]
            pkts[3][Raw].load = pkts[3][Raw].load[:44] + clockId +\
                                pkts[3][Raw].load[52:]
            sendp(pkts[3], iface=interface, count=1, loop=0, inter=0.01)
            print("SCAPY: Sent PTP Delay Response packet")
            sys.exit(0)
        else:
            print("SCAPY: No packets received")
    sys.exit(0)
