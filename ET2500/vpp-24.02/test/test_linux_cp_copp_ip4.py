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

    def test_dhcp_l3_broadcast_ports(self):
        """Limited and ingress subnet broadcasts use the L3 DHCP trap."""
        from ipaddress import IPv4Interface

        subnet = IPv4Interface(
            "%s/%s" % (self.phy.local_ip4, self.phy.local_ip4_prefix_len)
        ).network
        self.vapi.lcp_copp_trap_add(
            trap_id=24, action=3, priority=100, policer_index=0xFFFFFFFF
        )
        try:
            for dst in ("255.255.255.255", str(subnet.broadcast_address)):
                for src in ("0.0.0.0", self.phy.remote_ip4):
                    for sport, dport in (
                        (68, 67), (67, 68), (67, 67),
                        (67, 50000), (68, 50000),
                        (50000, 67), (50000, 68),
                    ):
                        pkt = (
                            Ether(src=self.phy.remote_mac, dst="ff:ff:ff:ff:ff:ff")
                            / IP(src=src, dst=dst)
                            / UDP(sport=sport, dport=dport)
                            / Raw(b"dhcp-broadcast")
                        )
                        before = self._copp_counter("trap_hit", 24)
                        l2_before = self._copp_counter("trap_hit", 12)
                        self._send_and_check(self.phy, pkt, 1, 0)
                        self.assertEqual(self._copp_counter("trap_hit", 24), before + 1)
                        self.assertEqual(self._copp_counter("trap_hit", 12), l2_before)
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=24)

    def test_transit_dhcp_ports_are_forwarded(self):
        """Transit UDP/67 and UDP/68 must not enter the DHCP trap."""
        for port in (67, 68):
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
                / UDP(sport=50000, dport=port)
                / Raw(b"transit-dhcp")
            )
            before = self._copp_counter("trap_hit", 24)
            self._send_and_check(self.phy, pkt, 0, 1)
            self.assertEqual(self._copp_counter("trap_hit", 24), before)

    def test_transit_bfd_ports_are_forwarded(self):
        """Transit BFD and BFD echo traffic must not enter CoPP."""
        for port in (3784, 4784, 3785):
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
                / UDP(sport=50000, dport=port)
                / Raw(b"transit-bfd")
            )
            before = self._copp_counter("trap_hit", 48)
            self._send_and_check(self.phy, pkt, 0, 1)
            self.assertEqual(self._copp_counter("trap_hit", 48), before)

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

    def test_ldp_udp_either_port(self):
        """IPv4 UDP source or destination port 646 enters LDP CoPP."""
        pkts = [
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / UDP(sport=646, dport=50000)
            / Raw(b"ldp-udp-source"),
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / UDP(sport=50000, dport=646)
            / Raw(b"ldp-udp-destination"),
        ]
        before = self._copp_counter("trap_hit", 52)
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, pkts)
        self.host.get_capture(len(pkts))
        self.assertEqual(self._copp_counter("trap_hit", 52), before + len(pkts))

    def test_transit_ldp_tcp_is_forwarded(self):
        """Transit TCP/646 must not enter CoPP."""
        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / TCP(sport=646, dport=50000)
            / Raw(b"ldp-tcp")
        )
        before = self._copp_counter("trap_hit", 52)
        self._send_and_check(self.phy, pkt, 0, 1)
        self.assertEqual(self._copp_counter("trap_hit", 52), before)


generate_trap_methods(TestLinuxCpCoppIp4, IP4_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
