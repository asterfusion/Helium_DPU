#!/usr/bin/env python3
"""CoPP IPv6 punt protocol tests."""

from scapy.layers.inet import UDP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrDestOpt
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    IP6_TRAPS,
    generate_trap_methods,
)


class TestLinuxCpCoppIp6(LinuxCpCoppTestCase):
    """IPv6 CoPP tests."""

    def test_ptp_udp6_ports(self):
        """Both UDP/319 and UDP/320 over IPv6 hit the PTP(10) trap."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.egress.remote_ip6)
            / UDP(sport=50000, dport=port)
            / Raw(b"ptp6")
            for port in (319, 320)
        ]
        before = self._copp_counter("trap_hit", 10)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))

        self.assertEqual(self._copp_counter("trap_hit", 10), before + len(pkts))

    def test_bgpv6_sport_and_dport(self):
        """Both source and destination TCP/179 over IPv6 hit BGPV6(48)."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6)
            / TCP(sport=179, dport=50000)
            / Raw(b"bgpv6"),
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6)
            / TCP(sport=50000, dport=179)
            / Raw(b"bgpv6"),
        ]
        before = self._copp_counter("trap_hit", 48)
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))
        self.assertEqual(self._copp_counter("trap_hit", 48), before + len(pkts))

    def test_snmp_with_ipv6_extension_header(self):
        """IPv6 extension header does not prevent SNMP(46) classification."""
        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6)
            / IPv6ExtHdrDestOpt()
            / UDP(sport=50000, dport=161)
            / Raw(b"snmp6-ext")
        )
        before = self._copp_counter("trap_hit", 46)
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [pkt])
        self.host.get_capture(1)
        self.assertEqual(self._copp_counter("trap_hit", 46), before + 1)

    def test_ldp_udp_dport_and_tcp_either_port(self):
        """IPv6 LDP matches UDP destination 646 and either TCP port 646."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.egress.remote_ip6)
            / UDP(sport=50000, dport=646)
            / Raw(b"ldp6-udp"),
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.egress.remote_ip6)
            / TCP(sport=646, dport=50000)
            / Raw(b"ldp6-tcp-source"),
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.egress.remote_ip6)
            / TCP(sport=50000, dport=646)
            / Raw(b"ldp6-tcp-destination"),
        ]
        before = self._copp_counter("trap_hit", 53)

        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))

        self.assertEqual(self._copp_counter("trap_hit", 53), before + len(pkts))


generate_trap_methods(TestLinuxCpCoppIp6, IP6_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
