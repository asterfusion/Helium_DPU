#!/usr/bin/python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

import sys
import argparse
from scapy.all import *

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-l", "--length", help="Length of the packets", type=int,
                default=64)
	parser.add_argument(
		"-p", "--pcap-file", help="Name of the pcap file", nargs="?",
		type=str, default="out.pcap")
	parser.add_argument(
		"-t", "--packet-type", help="Type of packet", nargs="?",
		type=str, default="IP_RAW")
	parser.add_argument(
		"-a", "--append", help="Append to pcap file", default=False,
		action='store_true')
	return parser.parse_args()

def get_base_packet(packet_type):
	if packet_type == "IP_RAW":
		return Ether()/IP()
	if packet_type == "TCP":
		return Ether()/IP()/TCP()
	if packet_type == "UDP":
		return Ether()/IP()/UDP()
	if packet_type == "SCTP":
		return Ether()/IP()/SCTP()
	if packet_type == "IPv6_TCP":
		return Ether()/IPv6()/TCP()
	if packet_type == "IPv6_UDP":
		return Ether()/IPv6()/UDP()
	if packet_type == "IPv6_SCTP":
		return Ether()/IP()/IPv6()/SCTP()
	if packet_type == "VLAN_UDP":
		return Ether()/Dot1Q()/IP()/UDP()
	if packet_type == "TIMESYNC":
		return Ether(dst='FF:FF:FF:FF:FF:FF',type=0x88f7)/"\\x00\\x02"
	if packet_type == "ARP":
		return Ether(dst='FF:FF:FF:FF:FF:FF')/ARP()
	sys.exit(1)

if __name__ == "__main__":
	args = parse_args()
	packet = get_base_packet(args.packet_type)

	if args.length < 64:
		args.length = 64
		print("SCAPY: Resetting packet len to min value = %d"
			% args.length)

	if len(packet) < args.length:
		#"\x00" is a single zero byte
		pad = "\x00" * (args.length - len(packet))
		packet = packet / pad

	print("SCAPY: Writing (append=%s) packet of len=%d to file %s" %
		(str(args.append), len(packet), args.pcap_file))

	wrpcap(args.pcap_file, packet, append=args.append)

	pcap = rdpcap(args.pcap_file)
	pcap.nsummary()

