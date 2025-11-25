Ipsec perf standalone application
=================================

The ipsec_perf_host.sh and ipsec_perf_target.sh can be
used by developers to generate ipsec performance numbers. The
dpdk-ipsec-secgw is used for ipsec functionality and dpdk-testpmd
application is used to generate and receive packets.

The ipsec_perf_host.sh runs on the host machine and does the following:

1. Prints system info about the target.

2. Creates the remote directory on target board(96xx/106xx), copies the required
   files like dpdk-ipsec-secgw application, dpdk-testpmd application, the
   ipsec_perf_target.sh script, ipsec config files, pcap files, oxk-devbind-basic.sh
   script and testpmd directory on the target board.
   By default the files will be copied in /tmp/dpdk directory on target board.
   This can be changed by exporting REMOTE_DIR variable.

3. Do the target setup by calling cnxk-target-setup.sh script. This can be skipped
   if the target is already setup once by exporting SKIP_TARGET_SETUP=y.

4. Then executes the ipsec_perf_target.sh script on the target board.


The ipsec_perf_target.sh script runs on the target board and executes the various
ipsec tests. The lookaside crypto, lookaside protocol and inline protocol mode is
supported. Both outbound and inbound tests are supported.

On the target board the dpdk-testpmd application in tx mode transmit the packets or
pcap(in inbound side). The ipsec-secgw receives the packet and does the encrypt or
decrypt. The dpdk-testpmd application in rx mode receives the processed packets. The
throughput is captured on the rx side.


How to run
==========
cd <dpdk_dir>
export PROJROOT=$PWD
export BUILD_DIR=$PWD/build
export REMOTE_DIR=<target dir> (optional)
export SKIP_TARGET_SETUP=y (optional)
export TARGET_BOARD=ci@<target ip>
(The ci user is present by default in linux used in Marvell's DPDK devel CI)
./marvell-ci/test/cnxk-tests/ipsec_perf/ipsec_perf_host.sh

Outbound Setup:
  ---------------------        -----------------------------------         ---------------------
  |  dpdk-testpmd(TX) |        |          dpdk-ipsec-secgw       |         |  dpdk-testpmd(RX) |
  |                   |        |                                 |         |                   |
  |      0002:01:00.5 | ------>| 0002:01:00.6       0002:01:00.7 | ------> | 0002:01:01.0      |
  |                   |  (PT)  |                                 |  (CT)   |                   |
  ---------------------        -----------------------------------         ---------------------

Inbound Setup:
  ---------------------        -----------------------------------         ---------------------
  |  dpdk-testpmd(TX) |        |          dpdk-ipsec-secgw       |         |  dpdk-testpmd(RX) |
  |                   |        |                                 |         |                   |
  |      0002:01:00.5 | ------>| 0002:01:00.6       0002:01:00.7 | ------> | 0002:01:01.0      |
  |                   |  (CT)  |                                 |  (PT)   |                   |
  ---------------------        -----------------------------------         ---------------------

Output File
===========

The throughput (in pps) is stored in the output files. The output files
are stored in ref_numbers/<cn9k or cn10k> directory on the target.

The output file is named according to following format:
rclk<rclk freq>_sclk<sclk freq>_cptclk<cptclk freq>.<HW>.<ipsec mode>.<dir>
where:
rclk freq - coreclk/rclk frequency in Mhz
sclk freq - sclk frequency in Mhz
cptclk freq - CPT clock frequency in Mhz
HW - 96xx or 106xx
ipsec mode - ip: inline protocol
             lc: lookaside crypto
             lp: lookaside protocol
dir - outb: outbound test
      inb:  inbound test

The following is the snippet of output file for aes-cbc_sha1-hmac algorithm.
aes-cbc_sha1-hmac
64: 2203558
380: 2237834
1410: 2098405
<end>

The 1st column (64, 380, 1410) is the packet size. The 2nd column shows the throughput (in pps)
for 1 core. Only 1 core is supported.
