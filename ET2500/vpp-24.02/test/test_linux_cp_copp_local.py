#!/usr/bin/env python3
"""CoPP host-bound (local context) tests."""

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    LOCAL_TRAPS,
    generate_trap_methods,
)
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw


class TestLinuxCpCoppLocal(LinuxCpCoppTestCase):
    """Host-bound CoPP classification tests."""

    def test_bfd_echo_port_is_not_bfd_trap(self):
        """Local UDP/3785 follows IP2ME and must not hit the BFD traps."""
        cases = (
            (48, IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)),
            (49, IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6)),
        )
        for trap_id, network in cases:
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / network
                / UDP(sport=50000, dport=3785)
                / Raw(b"bfd-echo")
            )
            before = self._copp_counter("trap_hit", trap_id)
            self._send_and_check(self.phy, pkt, 1, 0)
            self.assertEqual(self._copp_counter("trap_hit", trap_id), before)

    def test_ldp_tcp_destination_port_is_local_trap(self):
        """Local TCP destination port 646 is classified as LDP for v4/v6."""
        networks = (
            IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4),
            IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6),
        )
        for network in networks:
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / network
                / TCP(sport=50000, dport=646)
                / Raw(b"ldp-tcp-destination")
            )
            before = self._copp_counter("trap_hit", 52)
            self._send_and_check(self.phy, pkt, 1, 0)
            self.assertEqual(self._copp_counter("trap_hit", 52), before + 1)


generate_trap_methods(TestLinuxCpCoppLocal, LOCAL_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
