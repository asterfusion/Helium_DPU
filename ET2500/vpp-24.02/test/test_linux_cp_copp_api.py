#!/usr/bin/env python3
"""CoPP API/CLI lifecycle, invalid inputs, and priority arbitration tests."""

import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    COPP_ACTION_TRAP,
    COPP_ACTION_DROP,
    LCP_TRAP,
)


class TestLinuxCpCoppApi(LinuxCpCoppTestCase):
    """CoPP policy API, CLI, and classification priority arbitration."""

    def test_copp_policy_api_lifecycle(self):
        """Add/update/delete/dump a CoPP policy."""
        trap_id = LCP_TRAP.LCP_TRAP_ICMP_ECHO
        priority = 0x01020304
        policer_index = 0x0A0B0C0D

        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))

        # add
        self.vapi.lcp_copp_trap_add(
            trap_id=trap_id,
            action=COPP_ACTION_TRAP,
            priority=priority,
            policer_index=policer_index,
        )
        self.addCleanup(self.vapi.lcp_copp_trap_del, trap_id=trap_id)
        p = self._policy(trap_id)
        self.assertIsNotNone(p)
        self.assertEqual(p.action, COPP_ACTION_TRAP)
        self.assertEqual(p.priority, priority)
        self.assertEqual(p.policer_index, policer_index)

        # duplicate add with different params must fail
        with self.vapi.assert_negative_api_retval():
            self.vapi.lcp_copp_trap_add(
                trap_id=trap_id, action=COPP_ACTION_DROP, priority=1, policer_index=9
            )

        # update
        self.vapi.lcp_copp_trap_update(
            trap_id=trap_id,
            action=COPP_ACTION_DROP,
            priority=priority,
            policer_index=0xFFFFFFFF,
        )
        p = self._policy(trap_id)
        self.assertEqual(p.action, COPP_ACTION_DROP)
        self.assertEqual(p.policer_index, 0xFFFFFFFF)

        # CLI dump matches API dump
        cli_rows = self.vapi.cli("show lcp copp traps").splitlines()
        trap_row = next(row for row in cli_rows if row.split()[0] == str(trap_id))
        self.assertEqual(
            trap_row.split(),
            [
                str(trap_id),
                "ICMP_ECHO",
                "yes",
                str(COPP_ACTION_DROP),
                "none",
                "900",
                str(priority),
            ],
        )

        # delete and idempotent delete
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)

        # update non-existent fails
        with self.vapi.assert_negative_api_retval():
            self.vapi.lcp_copp_trap_update(
                trap_id=trap_id, action=COPP_ACTION_TRAP, priority=100, policer_index=7
            )

    def test_copp_invalid_trap_ids(self):
        """Invalid trap IDs are rejected."""
        for trap_id in (0, LCP_TRAP.LCP_TRAP_N_TYPES, 255):
            with self.vapi.assert_negative_api_retval():
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=COPP_ACTION_TRAP,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )

    def test_copp_policy_cli_lifecycle(self):
        """CLI set/delete a CoPP trap policy mirrors the API."""
        trap_id = LCP_TRAP.LCP_TRAP_P4RT
        priority = 0x01020304

        self.vapi.lcp_copp_trap_del(trap_id=trap_id)

        self.vapi.cli(
            "set lcp copp trap trap_id %u action %u priority %u policer %u"
            % (trap_id, COPP_ACTION_TRAP, priority, 0xFFFFFFFF)
        )
        self.addCleanup(self.vapi.lcp_copp_trap_del, trap_id=trap_id)

        p = self._policy(trap_id)
        self.assertIsNotNone(p)
        self.assertEqual(p.action, COPP_ACTION_TRAP)
        self.assertEqual(p.priority, priority)
        self.assertEqual(p.policer_index, 0xFFFFFFFF)

        self.vapi.cli("delete lcp copp trap trap_id %u" % trap_id)
        self.assertIsNone(self._policy(trap_id))

    def test_copp_invalid_action(self):
        """Action values outside 0..3 are rejected."""
        with self.vapi.assert_negative_api_retval():
            self.vapi.lcp_copp_trap_add(
                trap_id=LCP_TRAP.LCP_TRAP_ICMP_ECHO,
                action=4,
                priority=100,
                policer_index=0xFFFFFFFF,
            )

    def test_copp_ptp_tx_event_action_matrix(self):
        """PTP TX completion supports only DROP and TRAP."""
        trap_id = LCP_TRAP.LCP_TRAP_PTP_TX_EVENT
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        for action in (1, 2):
            with self.vapi.assert_negative_api_retval():
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=action,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
            self.assertIsNone(self._policy(trap_id))

        for action in (COPP_ACTION_DROP, COPP_ACTION_TRAP):
            self.vapi.lcp_copp_trap_add(
                trap_id=trap_id,
                action=action,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
            self.assertEqual(self._policy(trap_id).action, action)
            self.vapi.lcp_copp_trap_del(trap_id=trap_id)

    def test_copp_matchers_dump(self):
        """Matchers dump contains expected IDs and no duplicates."""
        rows = self.vapi.cli("show lcp copp matchers").splitlines()[1:]
        ids = [int(row.split()[0]) for row in rows]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(
            {9, 11, 23, 27, 100, 104, 105, 210, 211, 216, 314, 315, 320}
            .issubset(set(ids))
        )

    def test_copp_match_arbitration_unit(self):
        """Rule evidence stays separate from policy/trap arbitration."""
        self.assertIn(
            "match arbitration passed",
            self.vapi.cli("test lcp copp match arbitration"),
        )
        self.assertIn(
            "legacy default actions passed",
            self.vapi.cli("test lcp copp legacy actions"),
        )

    def test_copp_l2_direct_parse_unit(self):
        """L2 direct parsing is independent of current offset and VLAN depth."""
        self.assertIn(
            "L2 direct parsing passed",
            self.vapi.cli("test lcp copp l2 parse"),
        )

    def test_copp_default_priority_bgp_over_ssh_v4(self):
        """Default priority makes TCP/179 match BGP(47), not SSH(45)."""
        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)
            / TCP(sport=179, dport=22)
            / Raw(b"bgp-over-ssh")
        )
        before_bgp = self._copp_counter("trap_hit", 47)
        before_ssh = self._copp_counter("trap_hit", 45)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [pkt])
        self.host.get_capture(1)

        self.assertEqual(self._copp_counter("trap_hit", 47), before_bgp + 1)
        self.assertEqual(self._copp_counter("trap_hit", 45), before_ssh)

    def test_copp_default_priority_bgpv6_over_ssh_v6(self):
        """Default priority makes TCP/179 match BGPV6(48), not SSH(45)."""
        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IPv6(src=self.phy.remote_ip6, dst=self.phy.local_ip6)
            / TCP(sport=179, dport=22)
            / Raw(b"bgpv6-over-ssh")
        )
        before_bgp = self._copp_counter("trap_hit", 48)
        before_ssh = self._copp_counter("trap_hit", 45)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [pkt])
        self.host.get_capture(1)

        self.assertEqual(self._copp_counter("trap_hit", 48), before_bgp + 1)
        self.assertEqual(self._copp_counter("trap_hit", 45), before_ssh)

    def test_copp_default_priority_snmp_over_ip2me_v4(self):
        """Default priority makes UDP/161 match SNMP(46), not IP2ME(44)."""
        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)
            / UDP(sport=50000, dport=161)
            / Raw(b"snmp-over-ip2me")
        )
        before_snmp = self._copp_counter("trap_hit", 46)
        before_ip2me = self._copp_counter("trap_hit", 44)

        self.pg_enable_capture([self.host])
        self.pg_send(self.phy, [pkt])
        self.host.get_capture(1)

        self.assertEqual(self._copp_counter("trap_hit", 46), before_snmp + 1)
        self.assertEqual(self._copp_counter("trap_hit", 44), before_ip2me)

    def test_copp_runtime_priority_override_v4(self):
        """Higher policy priority makes IP2ME(44) win over BGP(47)."""
        self.vapi.lcp_copp_trap_del(trap_id=44)
        self.vapi.lcp_copp_trap_del(trap_id=47)
        self.vapi.lcp_copp_trap_add(
            trap_id=44, action=COPP_ACTION_TRAP, priority=200, policer_index=0xFFFFFFFF
        )
        self.vapi.lcp_copp_trap_add(
            trap_id=47, action=COPP_ACTION_TRAP, priority=100, policer_index=0xFFFFFFFF
        )
        try:
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)
                / TCP(sport=50000, dport=179)
                / Raw(b"priority")
            )
            before_ip2me = self._copp_counter("trap_hit", 44)
            before_bgp = self._copp_counter("trap_hit", 47)

            self.pg_enable_capture([self.host])
            self.pg_send(self.phy, [pkt])
            self.host.get_capture(1)

            self.assertEqual(self._copp_counter("trap_hit", 44), before_ip2me + 1)
            self.assertEqual(self._copp_counter("trap_hit", 47), before_bgp)
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=44)
            self.vapi.lcp_copp_trap_del(trap_id=47)

    def test_copp_equal_priority_fallback_v4(self):
        """Equal policy priority falls back to smaller trap type (IP2ME)."""
        self.vapi.lcp_copp_trap_del(trap_id=44)
        self.vapi.lcp_copp_trap_del(trap_id=47)
        self.vapi.lcp_copp_trap_add(
            trap_id=44, action=COPP_ACTION_TRAP, priority=100, policer_index=0xFFFFFFFF
        )
        self.vapi.lcp_copp_trap_add(
            trap_id=47, action=COPP_ACTION_TRAP, priority=100, policer_index=0xFFFFFFFF
        )
        try:
            pkt = (
                Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
                / IP(src=self.phy.remote_ip4, dst=self.phy.local_ip4)
                / TCP(sport=50000, dport=179)
                / Raw(b"equal-priority")
            )
            before_ip2me = self._copp_counter("trap_hit", 44)
            before_bgp = self._copp_counter("trap_hit", 47)

            self.pg_enable_capture([self.host])
            self.pg_send(self.phy, [pkt])
            self.host.get_capture(1)

            self.assertEqual(self._copp_counter("trap_hit", 44), before_ip2me + 1)
            self.assertEqual(self._copp_counter("trap_hit", 47), before_bgp)
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=44)
            self.vapi.lcp_copp_trap_del(trap_id=47)


if __name__ == "__main__":
    from asfframework import VppTestRunner
    unittest.main(testRunner=VppTestRunner)
