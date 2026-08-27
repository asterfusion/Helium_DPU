#!/usr/bin/env python3
"""CoPP tests for NAT44-ED miss / hairpin events."""

import socket
import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from framework import VppTestCase
from linux_cp_copp_common import (
    LinuxCpCoppTestCase,
    COPP_ACTION_DROP,
    COPP_ACTION_TRAP,
    COPP_COUNTER_NAMES,
    LCP_TRAP,
)
from vpp_papi import VppEnum


class TestLinuxCpCoppNat(LinuxCpCoppTestCase):
    """CoPP tests for NAT44-ED events."""

    extra_vpp_plugin_config = [
        "plugin default { disable }",
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
        "plugin nat_plugin.so { enable }",
    ]

    def setUp(self):
        super().setUp()
        self.vapi.nat44_ed_plugin_enable_disable(sessions=1024, enable=1)

    def tearDown(self):
        if not self.vpp_dead:
            self.vapi.nat44_ed_plugin_enable_disable(enable=0)
        super().tearDown()

    def _copp_counter(self, name, trap_id):
        counters = self.statistics.get_counter("/lcp/copp/%s" % name)
        return sum(thread[trap_id] for thread in counters)

    def _policy(self, trap_id):
        for p in self.vapi.lcp_copp_trap_dump():
            if p.trap_id == trap_id:
                return p
        return None

    def _assert_stats_delta(self, trap_id, before, expected):
        for name, delta in expected.items():
            got = self._copp_counter(name, trap_id) - before[name]
            self.assertEqual(
                got,
                delta,
                "%s delta mismatch for trap %d (expected %d, got %d)"
                % (name, trap_id, delta, got),
            )

    def _send_and_check(self, ingress, pkt, host_count, egress_count):
        ifaces = [self.host]
        if self.egress is not None:
            ifaces.append(self.egress)
        self.pg_enable_capture(ifaces)
        self.pg_send(ingress, [pkt])

        if host_count:
            self.host.get_capture(host_count)
        else:
            self.host.assert_nothing_captured()

        if self.egress is not None:
            if egress_count:
                self.egress.get_capture(egress_count)
            else:
                self.egress.assert_nothing_captured()

    def _set_policy(self, trap_id, action):
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.vapi.lcp_copp_trap_add(
            trap_id=trap_id,
            action=action,
            priority=100,
            policer_index=0xFFFFFFFF,
        )
        self.addCleanup(self.vapi.lcp_copp_trap_del, trap_id=trap_id)

    def _expected(self, action):
        if action == COPP_ACTION_DROP:
            return {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 1,
                "delivery_drop": 0,
            }
        return {
            "trap_hit": 1,
            "punt_required": 1,
            "punt_pass": 1,
            "punt_drop": 0,
            "delivery_drop": 0,
        }

    def test_copp_snat_miss(self):
        """SNAT miss: inside packet with no available NAT address."""
        trap_id = LCP_TRAP.LCP_TRAP_SNAT_MISS
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.phy.sw_if_index, is_add=1
        )
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.phy.sw_if_index,
            flags=VppEnum.vl_api_nat_config_flags_t.NAT_IS_INSIDE,
            is_add=1,
        )
        self.vapi.nat44_ed_add_del_output_interface(
            sw_if_index=self.egress.sw_if_index, is_add=1
        )
        # No address range added -> dynamic allocation fails -> SNAT miss.

        self._set_policy(trap_id, COPP_ACTION_TRAP)
        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}

        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
            / TCP(sport=12345, dport=80, flags="S")
        )
        self._send_and_check(self.phy, pkt, True, False)
        self._assert_stats_delta(trap_id, before, self._expected(COPP_ACTION_TRAP))

    def test_copp_dnat_miss(self):
        """DNAT miss: outside packet with no matching static mapping.

        The packet must ingress on an interface that has an LCP host pair so
        the punted copy can be captured on the host side.  Configure phy as
        outside only so the packet goes straight to the out2in path and hits
        the DNAT miss.
        """
        trap_id = LCP_TRAP.LCP_TRAP_DNAT_MISS
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.phy.sw_if_index, is_add=1
        )
        self.vapi.nat44_ed_add_del_output_interface(
            sw_if_index=self.egress.sw_if_index, is_add=1
        )

        self._set_policy(trap_id, COPP_ACTION_TRAP)
        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}

        pkt = (
            Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
            / IP(src=self.phy.remote_ip4, dst="10.0.0.99")
            / TCP(sport=12345, dport=80, flags="S")
        )
        self._send_and_check(self.phy, pkt, True, False)
        self._assert_stats_delta(trap_id, before, self._expected(COPP_ACTION_TRAP))

    def test_copp_nat_hairpin(self):
        """NAT hairpin: inside host reaches another inside host via external addr."""
        trap_id = LCP_TRAP.LCP_TRAP_NAT_HAIRPIN
        nat_addr = "10.0.0.1"
        outside_addr = "10.0.0.11"
        self.phy.generate_remote_hosts(2)
        self.phy.configure_ipv4_neighbors()
        client = self.phy.remote_hosts[0]
        server = self.phy.remote_hosts[1]

        self.vapi.nat44_add_del_address_range(
            first_ip_address=nat_addr,
            last_ip_address=nat_addr,
            is_add=1,
        )
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.phy.sw_if_index,
            flags=VppEnum.vl_api_nat_config_flags_t.NAT_IS_INSIDE,
            is_add=1,
        )
        self.vapi.nat44_interface_add_del_feature(
            sw_if_index=self.egress.sw_if_index,
            flags=VppEnum.vl_api_nat_config_flags_t.NAT_IS_OUTSIDE,
            is_add=1,
        )
        self.vapi.nat44_add_del_static_mapping_v2(
            local_ip_address=server.ip4,
            external_ip_address=outside_addr,
            protocol=6,
            local_port=80,
            external_port=80,
            is_add=1,
        )

        self._set_policy(trap_id, COPP_ACTION_TRAP)
        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}

        pkt = (
            Ether(src=client.mac, dst=self.phy.local_mac)
            / IP(src=client.ip4, dst=outside_addr)
            / TCP(sport=12345, dport=80, flags="S")
        )
        self._send_and_check(self.phy, pkt, True, False)
        self._assert_stats_delta(trap_id, before, self._expected(COPP_ACTION_TRAP))


if __name__ == "__main__":
    import unittest
    from asfframework import VppTestRunner

    unittest.main(testRunner=VppTestRunner)
