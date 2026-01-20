#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Marvell.

PORT0_DMAC="DA:90:4F:9E:4F:33"
PORT1_DMAC="8A:87:2D:D2:EF:A1"
PORT2_DMAC="A6:68:22:58:94:7C"
PORT3_DMAC="5A:59:EA:EF:2E:3E"
PORT4_DMAC="92:06:36:41:05:B0"
PORT5_DMAC="46:68:D3:16:83:13"
PORT6_DMAC="12:D5:E4:C6:1B:04"
PORT7_DMAC="D2:7E:BD:7B:04:11"

PORT0_VLAN=
PORT1_VLAN=
PORT2_VLAN=
PORT3_VLAN=
PORT4_VLAN=
PORT5_VLAN=
PORT6_VLAN=
PORT7_VLAN=

if [ "$PORT0_VLAN" != "" ]; then PORT0_OPT="--vlan-id $PORT0_VLAN"; fi
if [ "$PORT1_VLAN" != "" ]; then PORT1_OPT="--vlan-id $PORT1_VLAN"; fi
if [ "$PORT2_VLAN" != "" ]; then PORT2_OPT="--vlan-id $PORT2_VLAN"; fi
if [ "$PORT3_VLAN" != "" ]; then PORT3_OPT="--vlan-id $PORT3_VLAN"; fi
if [ "$PORT4_VLAN" != "" ]; then PORT4_OPT="--vlan-id $PORT4_VLAN"; fi
if [ "$PORT5_VLAN" != "" ]; then PORT5_OPT="--vlan-id $PORT5_VLAN"; fi
if [ "$PORT6_VLAN" != "" ]; then PORT6_OPT="--vlan-id $PORT6_VLAN"; fi
if [ "$PORT7_VLAN" != "" ]; then PORT7_OPT="--vlan-id $PORT7_VLAN"; fi

./gentraffic.py  --spi 0x20000000 --name port0.pcap --dmac $PORT0_DMAC $PORT0_OPT
./gentraffic.py  --spi 0x10000000 --name port0_1.pcap --dmac $PORT0_DMAC $PORT0_OPT
./gentraffic.py  --spi 0x4000000 --name port0_2.pcap --dmac $PORT0_DMAC $PORT0_OPT
./gentraffic.py  --spi 0x6000000 --name port0_3.pcap --dmac $PORT0_DMAC $PORT0_OPT

./gentraffic.py  --spi 0x20000010 --name port1.pcap --dmac $PORT1_DMAC $PORT1_OPT
./gentraffic.py  --spi 0x10000010 --name port1_1.pcap --dmac $PORT1_DMAC $PORT1_OPT
./gentraffic.py  --spi 0x4000010 --name port1_2.pcap --dmac $PORT1_DMAC $PORT1_OPT
./gentraffic.py  --spi 0x6000010 --name port1_3.pcap --dmac $PORT1_DMAC $PORT1_OPT

./gentraffic.py  --spi 0x20000040 --name port2.pcap --dmac $PORT2_DMAC $PORT2_OPT
./gentraffic.py  --spi 0x10000040 --name port2_1.pcap --dmac $PORT2_DMAC $PORT2_OPT
./gentraffic.py  --spi 0x4000040 --name port2_2.pcap --dmac $PORT2_DMAC $PORT2_OPT
./gentraffic.py  --spi 0x6000040 --name port2_3.pcap --dmac $PORT2_DMAC $PORT2_OPT

./gentraffic.py  --spi 0x20000050 --name port3.pcap --dmac $PORT3_DMAC $PORT3_OPT
./gentraffic.py  --spi 0x10000050 --name port3_1.pcap --dmac $PORT3_DMAC $PORT3_OPT
./gentraffic.py  --spi 0x4000050 --name port3_2.pcap --dmac $PORT3_DMAC $PORT3_OPT
./gentraffic.py  --spi 0x6000050 --name port3_3.pcap --dmac $PORT3_DMAC $PORT3_OPT

./gentraffic.py  --spi 0x20000080 --name port4.pcap --dmac $PORT4_DMAC $PORT4_OPT
./gentraffic.py  --spi 0x10000080 --name port4_1.pcap --dmac $PORT4_DMAC $PORT4_OPT
./gentraffic.py  --spi 0x4000080 --name port4_2.pcap --dmac $PORT4_DMAC $PORT4_OPT
./gentraffic.py  --spi 0x6000080 --name port4_3.pcap --dmac $PORT4_DMAC $PORT4_OPT

./gentraffic.py  --spi 0x20000090 --name port5.pcap --dmac $PORT5_DMAC $PORT5_OPT
./gentraffic.py  --spi 0x10000090 --name port5_1.pcap --dmac $PORT5_DMAC $PORT5_OPT
./gentraffic.py  --spi 0x4000090 --name port5_2.pcap --dmac $PORT5_DMAC $PORT5_OPT
./gentraffic.py  --spi 0x6000090 --name port5_3.pcap --dmac $PORT5_DMAC $PORT5_OPT

./gentraffic.py  --spi 0x200000c0 --name port6.pcap --dmac $PORT6_DMAC $PORT6_OPT
./gentraffic.py  --spi 0x10000090 --name port6_1.pcap --dmac $PORT6_DMAC $PORT6_OPT
./gentraffic.py  --spi 0x40000c0 --name port6_2.pcap --dmac $PORT6_DMAC $PORT6_OPT
./gentraffic.py  --spi 0x60000c0 --name port6_3.pcap --dmac $PORT6_DMAC $PORT6_OPT

./gentraffic.py  --spi 0x200000d0 --name port7.pcap --dmac $PORT7_DMAC $PORT7_OPT
./gentraffic.py  --spi 0x100000d0 --name port7_1.pcap --dmac $PORT7_DMAC $PORT7_OPT
./gentraffic.py  --spi 0x40000d0 --name port7_2.pcap --dmac $PORT7_DMAC $PORT7_OPT
./gentraffic.py  --spi 0x60000d0 --name port7_3.pcap --dmac $PORT7_DMAC $PORT7_OPT
