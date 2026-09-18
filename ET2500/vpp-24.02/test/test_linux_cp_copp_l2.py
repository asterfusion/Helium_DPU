#!/usr/bin/env python3
"""CoPP L2-direct protocol tests: STP, LACP, LLDP, PTP, ISIS."""

from scapy.layers.l2 import Ether, LLC
from scapy.packet import Raw

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    L2_DIRECT_TRAPS,
    COPP_ACTION_DROP,
    generate_trap_methods,
)


class TestLinuxCpCoppL2(LinuxCpCoppTestCase):
    """L2 direct adapter CoPP tests."""

    def test_l2_host_bypass(self):
        """Host -> PHY traffic bypasses ingress CoPP even with DROP policy."""
        lacp = (
            Ether(src=self.host.remote_mac, dst=self.host.local_mac, type=0x8809)
            / Raw(b"\x01\x01" + b"\x00" * 108)
        )

        self.vapi.lcp_copp_trap_add(
            trap_id=3, action=COPP_ACTION_DROP, priority=100, policer_index=0xFFFFFFFF
        )
        try:
            self.pg_enable_capture([self.phy])
            self.pg_send(self.host, [lacp])
            self.phy.get_capture(1)
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=3)

    def test_l2_marker_not_lacp(self):
        """LACP marker (subtype 2) must not increment the LACP trap counter."""
        marker = (
            Ether(src=self.phy.remote_mac, dst="01:80:c2:00:00:02", type=0x8809)
            / Raw(b"\x02\x01" + b"\x00" * 108)
        )
        before = self._copp_counter("trap_hit", 3)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [marker])
        self.host.get_capture(1)

        self.assertEqual(self._copp_counter("trap_hit", 3), before)

    def test_l2_eapol_not_copp(self):
        """EAPOL must not enter CoPP or the shared direct-delivery adapter."""
        eapol = (
            Ether(src=self.phy.remote_mac, dst="01:80:c2:00:00:03", type=0x888E)
            / Raw(b"\x01\x00\x00\x00")
        )
        counters_before = {
            trap_id: self._copp_counter("trap_hit", trap_id)
            for trap_id in (2, 3, 4, 10, 43)
        }

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [eapol])
        self.host.assert_nothing_captured()

        for trap_id, before in counters_before.items():
            self.assertEqual(self._copp_counter("trap_hit", trap_id), before)


generate_trap_methods(TestLinuxCpCoppL2, L2_DIRECT_TRAPS)

if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
