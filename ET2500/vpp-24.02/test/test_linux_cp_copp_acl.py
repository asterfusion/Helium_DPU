#!/usr/bin/env python3
"""CoPP tests for the ACL punt adapter."""

from ipaddress import IPv4Network

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    COPP_ACTION_DROP,
    COPP_ACTION_FORWARD,
    COPP_ACTION_COPY,
    COPP_ACTION_TRAP,
    COPP_COUNTER_NAMES,
    LCP_TRAP,
)
from vpp_acl import AclRule, VppAcl, VppAclInterface


class TestLinuxCpCoppAcl(LinuxCpCoppTestCase):
    """CoPP tests for ACL-punted packets."""

    extra_vpp_plugin_config = [
        "plugin default { disable }",
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
        "plugin acl_plugin.so { enable }",
    ]

    def setUp(self):
        super().setUp()
        self.acl = None
        self.acl_if = None

    def tearDown(self):
        if self.acl_if is not None:
            self.acl_if.remove_vpp_config()
        if self.acl is not None:
            self.acl.remove_vpp_config()
        super().tearDown()

    def _install_acl_punt(self):
        """Install an inbound ACL on phy that punts matching UDP packets."""
        rule = AclRule(
            is_permit=4,  # ACL_ACTION_API_PUNT
            src_prefix=IPv4Network((self.phy.remote_ip4, 32)),
            dst_prefix=IPv4Network((self.egress.remote_ip4, 32)),
            proto=17,  # UDP
        )
        self.acl = VppAcl(self, [rule], tag="copp-acl-punt")
        self.acl.add_vpp_config()
        self.acl_if = VppAclInterface(
            self, sw_if_index=self.phy.sw_if_index, n_input=1, acls=[self.acl]
        )
        self.acl_if.add_vpp_config()

    def _make_acl_packet(self):
        return (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / UDP(sport=1234, dport=5678)
            / b"payload"
        )

    def _run_action(self, action, expected):
        trap_id = LCP_TRAP.LCP_TRAP_ACL
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))

        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}

        self.vapi.lcp_copp_trap_add(
            trap_id=trap_id,
            action=action,
            priority=100,
            policer_index=0xFFFFFFFF,
        )
        self.addCleanup(self.vapi.lcp_copp_trap_del, trap_id=trap_id)

        pkt = self._make_acl_packet()

        if action == COPP_ACTION_DROP:
            self._send_and_check(self.phy, pkt, False, False)
        elif action == COPP_ACTION_FORWARD:
            self._send_and_check(self.phy, pkt, False, True)
        elif action == COPP_ACTION_COPY:
            self._send_and_check(self.phy, pkt, True, True)
        else:  # TRAP
            self._send_and_check(self.phy, pkt, True, False)

        self._assert_stats_delta(trap_id, before, expected)
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)

    def test_copp_acl_drop(self):
        self._install_acl_punt()
        self._run_action(
            COPP_ACTION_DROP,
            {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 1,
                "delivery_drop": 0,
            },
        )

    def test_copp_acl_forward(self):
        self._install_acl_punt()
        self._run_action(
            COPP_ACTION_FORWARD,
            {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 0,
                "delivery_drop": 0,
            },
        )

    def test_copp_acl_copy(self):
        self._install_acl_punt()
        self._run_action(
            COPP_ACTION_COPY,
            {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            },
        )

    def test_copp_acl_trap(self):
        self._install_acl_punt()
        self._run_action(
            COPP_ACTION_TRAP,
            {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            },
        )

    def test_copp_acl_default(self):
        """ACL punt without a configured policy should default to trap."""
        trap_id = LCP_TRAP.LCP_TRAP_ACL
        self._install_acl_punt()
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))

        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}
        pkt = self._make_acl_packet()
        self._send_and_check(self.phy, pkt, True, False)
        self._assert_stats_delta(
            trap_id,
            before,
            {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            },
        )


if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner

    unittest.main(testRunner=VppTestRunner)
