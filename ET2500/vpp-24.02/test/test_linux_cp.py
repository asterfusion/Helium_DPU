#!/usr/bin/env python3

import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    Raw,
)
from scapy.layers.l2 import Ether, ARP

from util import reassemble4
from vpp_object import VppObject
from framework import VppTestCase
from asfframework import VppTestRunner
from vpp_ipip_tun_interface import VppIpIpTunInterface
from vpp_ip_route import VppIpMRoute, VppMRoutePath
from vpp_papi import VppEnum
from vpp_policer import PolicerAction, VppPolicer
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from template_ipsec import (
    TemplateIpsec,
    IpsecTun4,
)
from test_ipsec_tun_if_esp import TemplateIpsecItf4


class VppLcpPair(VppObject):
    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli("test lcp add phy %s host %s" % (self.phy, self.host))
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli("test lcp del phy %s host %s" % (self.phy, self.host))

    def object_id(self):
        return "lcp:%d:%d" % (self.phy.sw_if_index, self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = list(self._test.vapi.vpp.details_iter(self._test.vapi.lcp_itf_pair_get))

        for p in pairs:
            if (
                p.phy_sw_if_index == self.phy.sw_if_index
                and p.host_sw_if_index == self.host.sw_if_index
            ):
                return True
        return False


class TestLinuxCP(VppTestCase):
    """Linux Control Plane"""

    extra_vpp_plugin_config = [
        "plugin default { disable }",
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
    ]

    @classmethod
    def setUpClass(cls):
        super(TestLinuxCP, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestLinuxCP, cls).tearDownClass()

    def setUp(self):
        super(TestLinuxCP, self).setUp()

        # create 4 pg interfaces so we can create two pairs
        self.create_pg_interfaces(range(4))

        # create on ip4 and one ip6 pg tun
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(4, 5))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(5, 6))

        for i in self.pg_interfaces:
            i.admin_up()

    def tearDown(self):
        for i in self.pg_interfaces:
            i.admin_down()
        super(TestLinuxCP, self).tearDown()

    def _copp_policy_details(self, trap_id):
        for policy in self.vapi.lcp_copp_trap_dump():
            if policy.trap_id == trap_id:
                return policy
        return None

    def _copp_counter(self, name, trap_id):
        counters = self.statistics.get_counter("/lcp/copp/%s" % name)
        return sum(thread[trap_id] for thread in counters)

    def _assert_copp_counter_delta(
        self, name, trap_id, before, expected, packet_name
    ):
        actual = self._copp_counter(name, trap_id) - before
        if actual != expected:
            diagnostics = "packet=%s trap=%u\n%s\n%s" % (
                packet_name,
                trap_id,
                self.vapi.cli("show trace"),
                self.vapi.cli("show errors"),
            )
            self.assertEqual(actual, expected, diagnostics)

    def _node_next_names(self, node_name):
        output = self.vapi.cli("show node %s" % node_name)
        next_names = []
        in_next_nodes = False

        for line in output.splitlines():
            if "next nodes:" in line:
                in_next_nodes = True
                continue
            if not in_next_nodes:
                continue
            columns = line.split()
            if len(columns) >= 3 and columns[0].isdigit():
                next_names.append(columns[2])

        return next_names

    def _assert_copp_graph_and_feature_lifecycle(self):
        expected_fixed_nexts = {
            "linux-cp-ip4-punt": ["error-drop", "linux-cp-copp-punt"],
            "linux-cp-ip6-punt": ["error-drop", "linux-cp-copp-punt"],
            "linux-cp-local-punt": ["error-drop", "linux-cp-copp-punt"],
            "linux-cp-l2-punt": ["error-drop", "linux-cp-l2-delivery"],
            "linux-cp-l2-direct-adapter": [
                "error-drop",
                "linux-cp-l2-delivery",
                "interface-output",
            ],
            "linux-cp-arp-phy": [
                "error-drop",
                "linux-cp-arp-copp-delivery",
            ],
        }

        for node_name, fixed_nexts in expected_fixed_nexts.items():
            next_names = self._node_next_names(node_name)
            self.assertEqual(next_names[: len(fixed_nexts)], fixed_nexts)
            self.assertEqual(len(next_names), len(set(next_names)))

        host = self.pg0
        phy = self.pg1
        producer_names = (
            "linux-cp-ip4-punt",
            "linux-cp-ip6-punt",
            "linux-cp-l2-punt",
            "linux-cp-arp-phy",
        )
        old_vrrp_names = (
            "linux-cp-vrrp",
            "linux-cp-vrrp6",
            "linux-cp-l2-vrrp",
            "linux-cp-l2-vrrp6",
        )
        features = self.vapi.cli("show interface features %s" % phy)
        for node_name in producer_names + old_vrrp_names:
            self.assertNotIn(node_name, features)

        pair_added = False
        try:
            self.vapi.cli("test lcp add phy %s host %s" % (phy, host))
            pair_added = True
            features = self.vapi.cli("show interface features %s" % phy)
            for node_name in producer_names:
                self.assertIn(node_name, features)
            for node_name in old_vrrp_names:
                self.assertNotIn(node_name, features)
        finally:
            if pair_added:
                self.vapi.cli("test lcp del phy %s host %s" % (phy, host))

        features = self.vapi.cli("show interface features %s" % phy)
        for node_name in producer_names + old_vrrp_names:
            self.assertNotIn(node_name, features)

    def test_linux_cp_copp_policy_api(self):
        """Linux CP CoPP policy API"""

        self._assert_copp_graph_and_feature_lifecycle()

        trap_id = 22
        priority = 0x01020304
        policer_index = 0x0A0B0C0D
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._copp_policy_details(trap_id))

        for invalid_trap_id in (0, 255):
            with self.vapi.assert_negative_api_retval():
                self.vapi.lcp_copp_trap_add(
                    trap_id=invalid_trap_id,
                    action=1,
                    priority=priority,
                    policer_index=policer_index,
                )

        matcher_rows = self.vapi.cli("show lcp copp matchers").splitlines()[1:]
        rule_ids = [int(row.split()[0]) for row in matcher_rows]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        self.assertTrue({100, 210, 211, 314, 315}.issubset(rule_ids))

        try:
            self.vapi.lcp_copp_trap_add(
                trap_id=trap_id,
                action=1,
                priority=priority,
                policer_index=policer_index,
            )

            policy = self._copp_policy_details(trap_id)
            self.assertIsNotNone(policy)
            self.assertEqual(policy.action, 1)
            self.assertEqual(policy.priority, priority)
            self.assertEqual(policy.policer_index, policer_index)

            # Repeating the same add is idempotent.
            self.vapi.lcp_copp_trap_add(
                trap_id=trap_id,
                action=1,
                priority=priority,
                policer_index=policer_index,
            )

            # A different add must not silently replace the existing policy.
            with self.vapi.assert_negative_api_retval():
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id, action=2, priority=200, policer_index=9
                )

            self.vapi.lcp_copp_trap_update(
                trap_id=trap_id,
                action=2,
                priority=priority,
                policer_index=0xFFFFFFFF,
            )

            policy = self._copp_policy_details(trap_id)
            self.assertEqual(policy.action, 2)
            self.assertEqual(policy.priority, priority)
            self.assertEqual(policy.policer_index, 0xFFFFFFFF)

            cli_rows = self.vapi.cli("show lcp copp traps").splitlines()
            trap_row = next(
                row for row in cli_rows if row.split()[0] == str(trap_id)
            )
            self.assertEqual(
                trap_row.split(),
                [
                    str(trap_id),
                    "IPOE_FDB_MISS",
                    "yes",
                    "2",
                    "none",
                    "800",
                    str(priority),
                ],
            )
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=trap_id)

        self.assertIsNone(self._copp_policy_details(trap_id))

        with self.vapi.assert_negative_api_retval():
            self.vapi.lcp_copp_trap_update(
                trap_id=trap_id, action=1, priority=100, policer_index=7
            )

        # Delete is idempotent for retry and rollback paths.
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)

        with self.vapi.assert_negative_api_retval():
            self.vapi.lcp_copp_trap_add(
                trap_id=trap_id,
                action=4,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
        self.assertIsNone(self._copp_policy_details(trap_id))

    def test_linux_cp_copp_l2_actions(self):
        """Linux CP CoPP LLDP/LACP/PTP actions and host bypass"""

        host = self.pg0
        phy = self.pg1
        VppLcpPair(self, phy, host).add_vpp_config()

        lldp = (
            Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:0e", type=0x88CC)
            / Raw(b"\x02\x07test-lldp\x00\x00")
        )
        eapol = (
            Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:03", type=0x888E)
            / Raw(b"\x01\x00\x00\x00")
        )
        lacp = (
            Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:02", type=0x8809)
            / Raw(b"\x01\x01" + b"\x00" * 108)
        )
        marker = (
            Ether(src="02:00:00:00:00:01", dst="01:80:c2:00:00:02", type=0x8809)
            / Raw(b"\x02\x01" + b"\x00" * 108)
        )
        ptp = (
            Ether(src="02:00:00:00:00:01", dst="01:1b:19:00:00:00", type=0x88F7)
            / Raw(b"\x00\x02" + b"\x00" * 42)
        )

        try:
            for trap_id, packet in ((3, lacp), (4, lldp), (10, ptp)):
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
                # An unconfigured policy preserves the legacy TRAP behavior.
                self.send_and_expect_only(phy, [packet], host)
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=3,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_expect_only(phy, [packet], host)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=0,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_assert_no_replies(phy, [packet])

                # host -> PHY bypasses ingress CoPP even when action is DROP.
                self.send_and_expect_only(host, [packet], phy)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=2,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_expect_only(phy, [packet], host)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=1,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_assert_no_replies(phy, [packet])

            # The shared EtherType nodes must not misclassify adjacent protocols.
            self.send_and_expect_only(phy, [marker], host)

            # EAPOL has no approved trap type and must not enter CoPP or the
            # shared direct-delivery adapter.
            counters_before = {
                trap_id: self._copp_counter("trap_hit", trap_id)
                for trap_id in (3, 4, 10)
            }
            self.send_and_assert_no_replies(phy, [eapol])
            for trap_id, counter_before in counters_before.items():
                self.assertEqual(
                    self._copp_counter("trap_hit", trap_id), counter_before
                )
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=3)
            self.vapi.lcp_copp_trap_del(trap_id=4)
            self.vapi.lcp_copp_trap_del(trap_id=10)

    def test_linux_cp_copp_ospf_actions(self):
        """Linux CP CoPP OSPF actions and policer enforcement"""

        MRouteEntryFlags = VppEnum.vl_api_mfib_entry_flags_t
        MRouteItfFlags = VppEnum.vl_api_mfib_itf_flags_t
        host = self.pg0
        phy = self.pg1
        egress = self.pg2

        for interface in (phy, egress):
            interface.config_ip4()

        pair = VppLcpPair(self, phy, host).add_vpp_config()
        route = VppIpMRoute(
            self,
            "0.0.0.0",
            "232.1.1.1",
            32,
            MRouteEntryFlags.MFIB_API_ENTRY_FLAG_NONE,
            [
                VppMRoutePath(
                    phy.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_ACCEPT
                ),
                VppMRoutePath(
                    egress.sw_if_index, MRouteItfFlags.MFIB_API_ITF_FLAG_FORWARD
                ),
            ],
        ).add_vpp_config()

        ospf = (
            Ether(src=phy.remote_mac, dst="01:00:5e:01:01:01")
            / IP(src=phy.remote_ip4, dst="232.1.1.1", proto=89, ttl=2)
            / Raw(b"\x02\x01" + b"\x00" * 42)
        )
        QosAction = VppEnum.vl_api_sse2_qos_action_type_t
        transmit = PolicerAction(QosAction.SSE2_QOS_ACTION_API_TRANSMIT, 0)
        drop = PolicerAction(QosAction.SSE2_QOS_ACTION_API_DROP, 0)
        pass_policer = VppPolicer(
            self,
            "lcp-copp-pass",
            1000,
            0,
            1000,
            0,
            rate_type=1,
            conform_action=transmit,
            exceed_action=transmit,
            violate_action=transmit,
        ).add_vpp_config()
        drop_policer = VppPolicer(
            self,
            "lcp-copp-drop",
            1000,
            0,
            1000,
            0,
            rate_type=1,
            conform_action=drop,
            exceed_action=drop,
            violate_action=drop,
        ).add_vpp_config()
        counter_names = (
            "trap_hit",
            "punt_required",
            "punt_pass",
            "punt_drop",
            "delivery_drop",
        )
        counters_before = {
            name: self._copp_counter(name, 26) for name in counter_names
        }
        delivery_feature_enabled = False

        try:
            self.vapi.lcp_copp_trap_del(trap_id=26)
            self.vapi.lcp_copp_trap_add(
                trap_id=26,
                action=3,
                priority=100,
                policer_index=pass_policer.policer_index,
            )
            self.send_and_expect(phy, [ospf], host)

            # DROP does not enter the policer, even when one is attached.
            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=0,
                priority=100,
                policer_index=pass_policer.policer_index,
            )
            self.send_and_assert_no_replies(phy, [ospf])

            # FORWARD bypasses a policer whose result would be DROP.
            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=1,
                priority=100,
                policer_index=drop_policer.policer_index,
            )
            self.send_and_expect_only(phy, [ospf], egress)

            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=2,
                priority=100,
                policer_index=pass_policer.policer_index,
            )
            self.pg_send(phy, [ospf])
            host.get_capture(1)
            egress.get_capture(1)

            # COPY polices only the CPU clone; its original still forwards.
            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=2,
                priority=100,
                policer_index=drop_policer.policer_index,
            )
            self.send_and_expect_only(phy, [ospf], egress)

            # TRAP polices the original CPU-bound packet.
            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=3,
                priority=100,
                policer_index=drop_policer.policer_index,
            )
            self.send_and_assert_no_replies(phy, [ospf])

            # A CoPP packet that passes action/policer but has no LCP pair
            # fails in the dedicated delivery context.
            pair.remove_vpp_config()
            self.vapi.lcp_set_interface_punt_feature(
                sw_if_index=phy.sw_if_index, punt_on=True
            )
            delivery_feature_enabled = True
            self.vapi.lcp_copp_trap_update(
                trap_id=26,
                action=3,
                priority=100,
                policer_index=pass_policer.policer_index,
            )
            self.send_and_assert_no_replies(phy, [ospf])

            counters_after = {
            name: self._copp_counter(name, 26) for name in counter_names
            }
            counter_delta = {
                name: counters_after[name] - counters_before[name]
                for name in counter_names
            }
            self.assertEqual(
                counter_delta,
                {
                    "trap_hit": 7,
                    "punt_required": 5,
                    "punt_pass": 3,
                    "punt_drop": 3,
                    "delivery_drop": 1,
                },
            )
        finally:
            if delivery_feature_enabled:
                self.vapi.lcp_set_interface_punt_feature(
                    sw_if_index=phy.sw_if_index, punt_on=False
                )
            self.vapi.lcp_copp_trap_del(trap_id=26)
            route.remove_vpp_config()
            for interface in (phy, egress):
                interface.unconfig_ip4()

    def test_linux_cp_copp_arp_actions(self):
        """Linux CP CoPP ARP request/response actions and host bypass"""

        host = self.pg0
        phy = self.pg1
        phy.config_ip4()

        # Force the host adapter without creating an LCP pair. The packet must
        # take error-drop instead of dereferencing an absent pair.
        self.vapi.feature_enable_disable(
            enable=1,
            arc_name="arp",
            feature_name="linux-cp-arp-host",
            sw_if_index=host.sw_if_index,
        )
        try:
            missing_pair_arp = (
                Ether(src=host.remote_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=1,
                    hwsrc=host.remote_mac,
                    psrc="192.0.2.1",
                    hwdst="00:00:00:00:00:00",
                    pdst="192.0.2.2",
                )
            )
            self.send_and_assert_no_replies(host, [missing_pair_arp])
        finally:
            self.vapi.feature_enable_disable(
                enable=0,
                arc_name="arp",
                feature_name="linux-cp-arp-host",
                sw_if_index=host.sw_if_index,
            )

        VppLcpPair(self, phy, host).add_vpp_config()
        self.assertIn(
            "linux-cp-arp-host",
            self.vapi.cli("show interface features %s" % host),
        )
        packets = (
            (
                23,
                Ether(src=phy.remote_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(
                    op=1,
                    hwsrc=phy.remote_mac,
                    psrc=phy.remote_ip4,
                    hwdst="00:00:00:00:00:00",
                    pdst="198.51.100.1",
                ),
            ),
            (
                24,
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / ARP(
                    op=2,
                    hwsrc=phy.remote_mac,
                    psrc=phy.remote_ip4,
                    hwdst=phy.local_mac,
                    pdst="198.51.100.1",
                ),
            ),
        )
        short_arp = (
            Ether(src=phy.remote_mac, dst="ff:ff:ff:ff:ff:ff", type=0x0806)
            / Raw(
                b"\x00\x01\x08\x00\x06\x04\x00\x01"
                + bytes.fromhex(phy.remote_mac.replace(":", ""))
                + b"\xc0\x00\x02\x01"
            )
        )

        try:
            # Exercise the traced parser-failure path and verify the
            # zero-initialized ARP view used by trace formatting.
            self.vapi.cli("clear trace")
            self.send_and_assert_no_replies(phy, [short_arp])
            self.assertIn("opcode: 0", self.vapi.cli("show trace"))
            self.vapi.cli("clear trace")
            for trap_id, packet in packets:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=3,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_expect(phy, [packet], host)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=0,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_assert_no_replies(phy, [packet])

                # The host direction remains a plain LCP x-connect. Use the
                # established TAP-test packet shape for this direction.
                host_packet = (
                    Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_mac)
                    / ARP(
                        op="who-has",
                        hwdst=phy.remote_mac,
                        hwsrc=phy.local_mac,
                        psrc=phy.local_ip4,
                        pdst=phy.remote_ip4,
                    )
                )
                self.send_and_expect(host, [host_packet], phy)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=2,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_expect(phy, [packet], host)

                self.vapi.lcp_copp_trap_update(
                    trap_id=trap_id,
                    action=1,
                    priority=100,
                    policer_index=0xFFFFFFFF,
                )
                self.send_and_assert_no_replies(phy, [packet])
        finally:
            self.vapi.cli("clear trace")
            for trap_id, _ in packets:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
            phy.unconfig_ip4()

    def test_linux_cp_copp_ip4_punt_classifier(self):
        """Linux CP CoPP IPv4 punt classifier"""

        host = self.pg0
        phy = self.pg1
        phy.config_ip4()
        pair = VppLcpPair(self, phy, host).add_vpp_config()
        trap_ids = (44, 45, 46, 47)

        packets = (
            (47, TCP(sport=179, dport=50000)),
            (47, TCP(sport=50000, dport=179)),
            # Equal priorities use the smaller trap type (SSH=45 < BGP=47).
            (45, TCP(sport=179, dport=22)),
            (45, TCP(sport=50000, dport=22)),
            (46, UDP(sport=50000, dport=161)),
            (44, UDP(sport=50000, dport=162)),
        )
        counters_before = {
            trap_id: self._copp_counter("trap_hit", trap_id)
            for trap_id in trap_ids
        }

        try:
            for trap_id in trap_ids:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=3,
                    # Keep the IP2ME fallback below the protocol traps.
                    # Later assertions explicitly raise it to validate
                    # runtime priority and equal-priority tie-breaking.
                    priority=1 if trap_id == 44 else 100,
                    policer_index=0xFFFFFFFF,
                )

            for _, l4 in packets:
                packet = (
                    Ether(src=phy.remote_mac, dst=phy.local_mac)
                    / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                    / l4
                    / Raw(b"classifier")
                )
                self.send_and_expect(phy, [packet], host)

            expected_hits = {44: 1, 45: 2, 46: 1, 47: 2}
            for trap_id, expected in expected_hits.items():
                self.assertEqual(
                    self._copp_counter("trap_hit", trap_id)
                    - counters_before[trap_id],
                    expected,
                )

            # Runtime policy priority is the only business priority.
            bgp_before = self._copp_counter("trap_hit", 47)
            ip2me_before = self._copp_counter("trap_hit", 44)
            self.vapi.lcp_copp_trap_update(
                trap_id=44,
                action=3,
                priority=200,
                policer_index=0xFFFFFFFF,
            )
            priority_packet = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                / TCP(sport=50000, dport=179)
                / Raw(b"priority")
            )
            self.send_and_expect(phy, [priority_packet], host)
            self.assertEqual(self._copp_counter("trap_hit", 47), bgp_before)
            self.assertEqual(
                self._copp_counter("trap_hit", 44), ip2me_before + 1
            )

            # Equal policy priority falls back to the smaller trap type (IP2ME).
            self.vapi.lcp_copp_trap_update(
                trap_id=44,
                action=3,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
            self.send_and_expect(phy, [priority_packet], host)
            self.assertEqual(
                self._copp_counter("trap_hit", 44), ip2me_before + 2
            )
            self.assertEqual(self._copp_counter("trap_hit", 47), bgp_before)

            with self.subTest(packet="ipv4-options", expected_trap=47):
                options_before = self._copp_counter("trap_hit", 47)
                options_packet = (
                    Ether(src=phy.remote_mac, dst=phy.local_mac)
                    / IP(
                        src=phy.remote_ip4,
                        dst=phy.local_ip4,
                        options=b"\x01\x01\x01\x01",
                    )
                    / TCP(sport=50000, dport=179)
                    / Raw(b"ipv4-options")
                )
                self.send_and_expect(phy, [options_packet], host)
                self._assert_copp_counter_delta(
                    "trap_hit", 47, options_before, 1, "ipv4-options"
                )

            # The fallback remains subject to policy after classification.
            self.vapi.lcp_copp_trap_update(
                trap_id=44,
                action=0,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
            fallback = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                / UDP(sport=50000, dport=9999)
                / Raw(b"ip2me")
            )
            self.send_and_assert_no_replies(phy, [fallback])
        finally:
            for trap_id in trap_ids:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
            phy.unconfig_ip4()

    def test_linux_cp_copp_ip6_punt_classifier(self):
        """Linux CP CoPP IPv6 punt classifier"""

        host = self.pg0
        phy = self.pg1
        phy.config_ip6()
        pair = VppLcpPair(self, phy, host).add_vpp_config()
        trap_ids = (44, 45, 46, 48)

        packets = (
            (48, TCP(sport=179, dport=50000)),
            (48, TCP(sport=50000, dport=179)),
            # Equal priorities use the smaller trap type (SSH=45 < BGPV6=48).
            (45, TCP(sport=179, dport=22)),
            (45, TCP(sport=50000, dport=22)),
            (46, UDP(sport=50000, dport=161)),
            (44, UDP(sport=50000, dport=162)),
        )
        counters_before = {
            trap_id: self._copp_counter("trap_hit", trap_id)
            for trap_id in trap_ids
        }

        try:
            for trap_id in trap_ids:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
                self.vapi.lcp_copp_trap_add(
                    trap_id=trap_id,
                    action=3,
                    # Keep the IP2ME fallback below the protocol traps.
                    # Later assertions explicitly raise it to validate
                    # runtime priority and equal-priority tie-breaking.
                    priority=1 if trap_id == 44 else 100,
                    policer_index=0xFFFFFFFF,
                )

            # Run the in-process IPv6 extension header parser unit tests.
            self.assertIn(
                "passed",
                self.vapi.cli("test lcp copp ip6 ext"),
            )

            for _, l4 in packets:
                packet = (
                    Ether(src=phy.remote_mac, dst=phy.local_mac)
                    / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                    / l4
                    / Raw(b"classifier-v6")
                )
                self.send_and_expect(phy, [packet], host)

            expected_hits = {44: 1, 45: 2, 46: 1, 48: 2}
            for trap_id, expected in expected_hits.items():
                self.assertEqual(
                    self._copp_counter("trap_hit", trap_id)
                    - counters_before[trap_id],
                    expected,
                )

            # Extension header traversal: exercise hdr_chain.length,
            # eh[last].protocol, eh[last].offset and fragment_index handling.
            ext_packets = (
                # Plain IPv6 + UDP: hdr_chain.length == 1, last protocol UDP.
                ("plain-udp", 46, UDP(sport=50000, dport=161)),
                # Plain IPv6 + TCP: hdr_chain.length == 1, last protocol TCP.
                ("plain-tcp", 48, TCP(sport=50000, dport=179)),
                # IPv6 + Hop-by-Hop + UDP: chain walks HBH, last protocol UDP.
                (
                    "hop-by-hop-udp",
                    46,
                    IPv6ExtHdrHopByHop() / UDP(sport=50000, dport=161),
                ),
                # IPv6 + Routing + UDP: chain walks Routing, last protocol UDP.
                (
                    "routing-udp",
                    46,
                    IPv6ExtHdrRouting() / UDP(sport=50000, dport=161),
                ),
                # IPv6 + Destination Options + UDP: chain walks DestOpt,
                # last protocol UDP.
                (
                    "destination-options-udp",
                    46,
                    IPv6ExtHdrDestOpt() / UDP(sport=50000, dport=161),
                ),
                # IPv6 first fragment + UDP: fragment_index >= 0, offset == 0,
                # last protocol UDP, L4 ports parsed.
                (
                    "first-fragment-udp",
                    46,
                    IPv6ExtHdrFragment(offset=0, m=1, nh=17)
                    / UDP(sport=50000, dport=161),
                ),
            )

            for packet_name, expected_trap, l4 in ext_packets:
                with self.subTest(
                    packet=packet_name, expected_trap=expected_trap
                ):
                    before = self._copp_counter("trap_hit", expected_trap)
                    packet = (
                        Ether(src=phy.remote_mac, dst=phy.local_mac)
                        / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                        / l4
                        / Raw(b"ipv6-extension")
                    )
                    self.send_and_expect(phy, [packet], host)
                    self._assert_copp_counter_delta(
                        "trap_hit", expected_trap, before, 1, packet_name
                    )

            # Non-first fragment: fragment_index >= 0 and fragment offset != 0.
            # The fragment next header is UDP, but L4 ports are not available,
            # so the SNMP matcher must NOT match.  Host-bound fallback hits IP2ME.
            non_first = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                / IPv6ExtHdrFragment(offset=8, m=0, nh=17)
                / Raw(b"non-first-fragment")
            )
            with self.subTest(packet="non-first-fragment", expected_trap=44):
                ip2me_before = self._copp_counter("trap_hit", 44)
                snmp_before2 = self._copp_counter("trap_hit", 46)
                self.send_and_expect(phy, [non_first], host)
                self._assert_copp_counter_delta(
                    "trap_hit", 44, ip2me_before, 1, "non-first-fragment"
                )
                self._assert_copp_counter_delta(
                    "trap_hit", 46, snmp_before2, 0, "non-first-fragment"
                )

            self.vapi.lcp_copp_trap_update(
                trap_id=44,
                action=0,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
            fallback = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                / UDP(sport=50000, dport=9999)
                / Raw(b"ip2me-v6")
            )
            self.send_and_assert_no_replies(phy, [fallback])
        finally:
            for trap_id in trap_ids:
                self.vapi.lcp_copp_trap_del(trap_id=trap_id)
            phy.unconfig_ip6()

    def test_linux_cp_copp_ptp_udp_matchers(self):
        """Linux CP CoPP PTP IPv4/IPv6 UDP matcher paths"""

        host = self.pg0
        phy = self.pg1
        phy.config_ip4()
        phy.config_ip6()
        VppLcpPair(self, phy, host).add_vpp_config()
        counter_before = self._copp_counter("trap_hit", 10)

        try:
            self.vapi.lcp_copp_trap_del(trap_id=10)
            self.vapi.lcp_copp_trap_add(
                trap_id=10,
                action=3,
                priority=100,
                policer_index=0xFFFFFFFF,
            )
            packets = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                / UDP(sport=50000, dport=319)
                / Raw(b"ptp-ip4-event"),
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                / UDP(sport=50000, dport=320)
                / Raw(b"ptp-ip4-general"),
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                / UDP(sport=50000, dport=319)
                / Raw(b"ptp-ip6-event"),
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                / UDP(sport=50000, dport=320)
                / Raw(b"ptp-ip6-general"),
            )
            for packet in packets:
                self.send_and_expect(phy, [packet], host)
            near_packets = (
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IP(src=phy.remote_ip4, dst=phy.local_ip4)
                / UDP(sport=50000, dport=318)
                / Raw(b"not-ptp-ip4"),
                Ether(src=phy.remote_mac, dst=phy.local_mac)
                / IPv6(src=phy.remote_ip6, dst=phy.local_ip6)
                / UDP(sport=50000, dport=321)
                / Raw(b"not-ptp-ip6"),
            )
            for packet in near_packets:
                self.send_and_expect(phy, [packet], host)
            self.assertEqual(
                self._copp_counter("trap_hit", 10) - counter_before, 4
            )
        finally:
            self.vapi.lcp_copp_trap_del(trap_id=10)
            phy.unconfig_ip6()
            phy.unconfig_ip4()

    def test_linux_cp_tap(self):
        """Linux CP TAP"""

        #
        # Setup
        #

        arp_opts = {"who-has": 1, "is-at": 2}

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg0, self.pg1]
        phys = [self.pg2, self.pg3]
        N_HOSTS = 4

        for phy in phys:
            phy.config_ip4()
            self.addCleanup(phy.unconfig_ip4)
            phy.generate_remote_hosts(4)
            phy.configure_ipv4_neighbors()

        pair1 = VppLcpPair(self, phys[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, phys[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))

        #
        # Traffic Tests
        #

        # hosts to phys
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(src=phy.local_mac, dst=phy.remote_hosts[j].mac)
                    / IP(src=phy.local_ip4, dst=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs x-connect to phy
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="who-has",
                    hwdst=phy.remote_hosts[j].mac,
                    hwsrc=phy.local_mac,
                    psrc=phy.local_ip4,
                    pdst=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(host, [p], phy)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

        # phy to host
        for phy, host in zip(phys, hosts):
            for j in range(N_HOSTS):
                p = (
                    Ether(dst=phy.local_mac, src=phy.remote_hosts[j].mac)
                    / IP(dst=phy.local_ip4, src=phy.remote_hosts[j].ip4)
                    / UDP(sport=1234, dport=1234)
                    / Raw()
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

                # ARPs rx'd on the phy are sent to the host
                p = Ether(dst="ff:ff:ff:ff:ff:ff", src=phy.remote_hosts[j].mac) / ARP(
                    op="is-at",
                    hwsrc=phy.remote_hosts[j].mac,
                    hwdst=phy.local_mac,
                    pdst=phy.local_ip4,
                    psrc=phy.remote_hosts[j].ip4,
                )

                rxs = self.send_and_expect(phy, [p], host)

                # verify packet is unchanged
                for rx in rxs:
                    self.assertEqual(p.show2(True), rx.show2(True))

    def test_linux_cp_tun(self):
        """Linux CP TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # create two pairs, wihch a bunch of hots on the phys
        hosts = [self.pg4, self.pg5]
        phy = self.pg2

        phy.config_ip4()
        phy.config_ip6()
        # This test exercises LCP tunnel forwarding, not dynamic ARP/ND.
        # Preinstall the underlay neighbours so the minimal plugin profile
        # cannot turn the first tunnel packet into a resolution probe.
        phy.configure_ipv4_neighbors()
        phy.configure_ipv6_neighbors()

        tun4 = VppIpIpTunInterface(
            self, phy, phy.local_ip4, phy.remote_ip4
        ).add_vpp_config()
        tun6 = VppIpIpTunInterface(
            self, phy, phy.local_ip6, phy.remote_ip6
        ).add_vpp_config()
        tuns = [tun4, tun6]

        tun4.admin_up()
        tun4.config_ip4()
        tun6.admin_up()
        tun6.config_ip6()

        pair1 = VppLcpPair(self, tuns[0], hosts[0]).add_vpp_config()
        pair2 = VppLcpPair(self, tuns[1], hosts[1]).add_vpp_config()

        self.logger.info(self.vapi.cli("sh lcp adj verbose"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        p = IP(src=tun4.local_ip4, dst="2.2.2.2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg4, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[Ether].dst, phy.remote_mac)
            self.assertEqual(rx[IP].dst, phy.remote_ip4)
            self.assertEqual(rx[IP].src, phy.local_ip4)
            inner = IP(rx[IP].payload)
            self.assertEqual(inner.src, tun4.local_ip4)
            self.assertEqual(inner.dst, "2.2.2.2")

        # host to phy for v6
        p = IPv6(src=tun6.local_ip6, dst="2::2") / UDP(sport=1234, dport=1234) / Raw()

        rxs = self.send_and_expect(self.pg5, p * N_PKTS, phy)

        # verify inner packet is unchanged and has the tunnel encap
        for rx in rxs:
            self.assertEqual(rx[IPv6].dst, phy.remote_ip6)
            self.assertEqual(rx[IPv6].src, phy.local_ip6)
            inner = IPv6(rx[IPv6].payload)
            self.assertEqual(inner.src, tun6.local_ip6)
            self.assertEqual(inner.dst, "2::2")

        # phy to host v4
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IP(dst=phy.local_ip4, src=phy.remote_ip4)
            / IP(dst=tun4.local_ip4, src=tun4.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg4)
        for rx in rxs:
            rx = IP(rx)
            self.assertEqual(rx[IP].dst, tun4.local_ip4)
            self.assertEqual(rx[IP].src, tun4.remote_ip4)

        # phy to host v6
        p = (
            Ether(dst=phy.local_mac, src=phy.remote_mac)
            / IPv6(dst=phy.local_ip6, src=phy.remote_ip6)
            / IPv6(dst=tun6.local_ip6, src=tun6.remote_ip6)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(phy, p * N_PKTS, self.pg5)
        for rx in rxs:
            rx = IPv6(rx)
            self.assertEqual(rx[IPv6].dst, tun6.local_ip6)
            self.assertEqual(rx[IPv6].src, tun6.remote_ip6)

        # cleanup
        phy.unconfig_ip4()
        phy.unconfig_ip6()

        tun4.unconfig_ip4()
        tun6.unconfig_ip6()


class TestLinuxCPIpsec(TemplateIpsec, TemplateIpsecItf4, IpsecTun4):
    """IPsec Interface IPv4"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "linux_cp_unittest_plugin.so",
        "{",
        "enable",
        "}",
    ]

    def setUp(self):
        super(TestLinuxCPIpsec, self).setUp()

        self.tun_if = self.pg0
        self.pg_interfaces += self.create_pg_ip4_interfaces(range(3, 4))
        self.pg_interfaces += self.create_pg_ip6_interfaces(range(4, 5))

    def tearDown(self):
        super(TestLinuxCPIpsec, self).tearDown()

    def verify_encrypted(self, p, sa, rxs):
        decrypt_pkts = []
        for rx in rxs:
            if p.nat_header:
                self.assertEqual(rx[UDP].dport, 4500)
            self.assert_packet_checksums_valid(rx)
            self.assertEqual(len(rx) - len(Ether()), rx[IP].len)
            try:
                rx_ip = rx[IP]
                decrypt_pkt = p.vpp_tun_sa.decrypt(rx_ip)
                if not decrypt_pkt.haslayer(IP):
                    decrypt_pkt = IP(decrypt_pkt[Raw].load)
                if rx_ip.proto == socket.IPPROTO_ESP:
                    self.verify_esp_padding(sa, rx_ip[ESP].data, decrypt_pkt)
                decrypt_pkts.append(decrypt_pkt)
                self.assert_equal(decrypt_pkt.src, p.tun_if.local_ip4)
                self.assert_equal(decrypt_pkt.dst, p.tun_if.remote_ip4)
            except:
                self.logger.debug(ppp("Unexpected packet:", rx))
                try:
                    self.logger.debug(ppp("Decrypted packet:", decrypt_pkt))
                except:
                    pass
                raise
        pkts = reassemble4(decrypt_pkts)
        for pkt in pkts:
            self.assert_packet_checksums_valid(pkt)

    def verify_decrypted(self, p, rxs):
        for rx in rxs:
            rx = IP(rx)
            self.assert_equal(rx[IP].src, p.tun_if.remote_ip4)
            self.assert_equal(rx[IP].dst, p.tun_if.local_ip4)
            self.assert_packet_checksums_valid(rx)

    def gen_encrypt_pkts(self, p, sa, sw_intf, src, dst, count=1, payload_size=54):
        return [
            Ether(src=sw_intf.remote_mac, dst=sw_intf.local_mac)
            / sa.encrypt(
                IP(src=src, dst=dst)
                / UDP(sport=1111, dport=2222)
                / Raw(b"X" * payload_size)
            )
            for i in range(count)
        ]

    def test_linux_cp_ipsec4_tun(self):
        """Linux CP Ipsec TUN"""

        #
        # Setup
        #
        N_PKTS = 31

        # the pg that paris with the tunnel
        self.host = self.pg3

        # tunnel and protection setup
        p = self.ipv4_params

        self.config_network(p)
        self.config_sa_tun(p, self.pg0.local_ip4, self.pg0.remote_ip4)
        self.config_protect(p)

        pair = VppLcpPair(self, p.tun_if, self.host).add_vpp_config()

        self.logger.info(self.vapi.cli("sh int addr"))
        self.logger.info(self.vapi.cli("sh lcp"))
        self.logger.info(self.vapi.cli("sh ip punt redirect"))

        #
        # Traffic Tests
        #

        # host to phy for v4
        pkt = (
            IP(src=p.tun_if.local_ip4, dst=p.tun_if.remote_ip4)
            / UDP(sport=1234, dport=1234)
            / Raw()
        )

        rxs = self.send_and_expect(self.host, pkt * N_PKTS, self.tun_if)
        self.verify_encrypted(p, p.vpp_tun_sa, rxs)

        # phy to host for v4
        pkts = self.gen_encrypt_pkts(
            p,
            p.scapy_tun_sa,
            self.tun_if,
            src=p.tun_if.remote_ip4,
            dst=p.tun_if.local_ip4,
            count=N_PKTS,
        )
        rxs = self.send_and_expect(self.tun_if, pkts, self.host)
        self.verify_decrypted(p, rxs)

        # cleanup
        pair.remove_vpp_config()
        self.unconfig_protect(p)
        self.unconfig_sa(p)
        self.unconfig_network(p)


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
