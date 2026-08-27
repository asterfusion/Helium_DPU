#!/usr/bin/env python3
"""CoPP IPv4 punt protocol tests."""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    IP4_TRAPS,
    generate_trap_methods,
)


class TestLinuxCpCoppIp4(LinuxCpCoppTestCase):
    """IPv4 CoPP tests."""

    def test_ptp_udp_ports(self):
        """Both UDP/319 and UDP/320 hit the PTP(10) trap."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / UDP(sport=50000, dport=port)
            / Raw(b"ptp")
            for port in (319, 320)
        ]
        before = self._copp_counter("trap_hit", 10)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))

        self.assertEqual(self._copp_counter("trap_hit", 10), before + len(pkts))

    def test_bgp_sport_and_dport(self):
        """Both source and destination TCP/179 hit BGP(47)."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)
            / TCP(sport=port, dport=50000)
            / Raw(b"bgp")
            for port in (179, 179)
        ]
        # vary one packet to use source, the other destination
        pkts[0][TCP].sport = 179
        pkts[0][TCP].dport = 50000
        pkts[1][TCP].sport = 50000
        pkts[1][TCP].dport = 179

        before = self._copp_counter("trap_hit", 47)
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))
        self.assertEqual(self._copp_counter("trap_hit", 47), before + len(pkts))

    def test_ldp_udp_and_tcp(self):
        """Both UDP/646 and TCP/646 hit LDP(53)."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / UDP(sport=646, dport=50000)
            / Raw(b"ldp-udp"),
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / TCP(sport=646, dport=50000)
            / Raw(b"ldp-tcp"),
        ]
        before = self._copp_counter("trap_hit", 53)
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))
        self.assertEqual(self._copp_counter("trap_hit", 53), before + len(pkts))


generate_trap_methods(TestLinuxCpCoppIp4, IP4_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
