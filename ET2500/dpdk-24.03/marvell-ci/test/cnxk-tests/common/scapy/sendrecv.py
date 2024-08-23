#!/usr/bin/python
# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2021 Marvell.

import sys
import argparse
from scapy.all import Ether
from scapy.all import IP
from scapy.all import srploop

def parse_args():
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-c", "--count", help="Number of packets to send", type=int,
                default=1)
	parser.add_argument(
		"-i", "--interface", help="Interface to send the packets",
		nargs='?', type=str, default='lbk3')
	parser.add_argument(
		"-l", "--length", help="Length of the packets", type=int,
                default=64)
	parser.add_argument(
		"-t", "--timeout", help="Time to wait for each packet response",
		type=int, default=5)
	return parser.parse_args()

if __name__ == "__main__":
	args = parse_args()
	packet = Ether()/IP()

	if args.length < 64:
		args.length = 64
		print("SCAPY: Resetting packet len to min value = %d"
			% args.length)

	if len(packet) < args.length:
		#"\x00" is a single zero byte
		pad = "\x00" * (args.length - len(packet))
		packet = packet / pad

	print("SCAPY: Sending %d packets of len=%d to interface %s" %
		(args.count, len(packet), args.interface))

	ans,unans = srploop(packet, promisc=True, iface=args.interface,
			count=args.count, timeout=args.timeout)
	total_len = 0
	for elem in ans:
		total_len += len(elem[0])

	print("SCAPY: Total Received Packets: %d Length: %d"
		% (ans.__len__(), total_len))

	if total_len != len(packet) * args.count or ans.__len__() != args.count:
		print("SCAPY: Error in Received packets")
		sys.exit(1)



