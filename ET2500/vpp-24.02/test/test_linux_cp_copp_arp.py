#!/usr/bin/env python3
"""CoPP ARP request/response tests."""

from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    ARP_TRAPS,
    generate_trap_methods,
)


class TestLinuxCpCoppArp(LinuxCpCoppTestCase):
    """ARP CoPP tests."""

    def test_arp_request_default_copy_continuation(self):
        """Default COPY punts the request and preserves ARP continuation."""
        self.vapi.lcp_copp_trap_del(trap_id=23)
        request = (
            Ether(src=self.phy.remote_mac, dst="ff:ff:ff:ff:ff:ff")
            / ARP(
                op="who-has",
                hwsrc=self.phy.remote_mac,
                psrc=self.phy.remote_ip4,
                hwdst="00:00:00:00:00:00",
                pdst=self.phy.local_ip4,
            )
        )

        before = self._copp_counter("trap_hit", 23)
        self.pg_send(self.phy, [request])
        self.host.get_capture(1)
        replies = self.phy.get_capture(1)

        self.assertEqual(replies[0][ARP].op, 2)
        self.assertEqual(replies[0][ARP].psrc, self.phy.local_ip4)
        self.assertEqual(self._copp_counter("trap_hit", 23), before + 1)

    def test_arp_parser_failure(self):
        """Short ARP packet triggers parser failure and error-drop."""
        short_arp = (
            Ether(src=self.phy.remote_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806)
            / Raw(
                b"\x00\x01\x08\x00\x06\x04\x00\x01"
                + bytes.fromhex(self.phy.remote_mac.replace(":", ""))
                + b"\xc0\x00\x02\x01"
            )
        )

        self.vapi.cli("clear trace")
        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [short_arp])
        self.host.assert_nothing_captured()
        self.assertIn("opcode: 0", self.vapi.cli("show trace"))
        self.vapi.cli("clear trace")

    def test_arp_host_bypass(self):
        """Host -> PHY ARP bypasses CoPP and is x-connected to the PHY."""
        host_arp = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self.host.remote_mac)
            / ARP(
                op="who-has",
                hwdst=self.phy.remote_mac,
                hwsrc=self.phy.local_mac,
                psrc=self.phy.local_ip4,
                pdst=self.phy.remote_ip4,
            )
        )

        self.pg_enable_capture([self.phy])
        self.pg_send(self.host, [host_arp])
        self.phy.get_capture(1)


generate_trap_methods(TestLinuxCpCoppArp, ARP_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
