#!/usr/bin/env python3
"""Shared base class and helpers for linux-cp CoPP full-coverage tests."""

import functools
import unittest
from enum import IntEnum

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrHopByHop,
    ICMPv6ND_RS,
    ICMPv6ND_RA,
    ICMPv6ND_Redirect,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6MLQuery,
    ICMPv6MLReport,
    ICMPv6MLDone,
    ICMPv6MLReport2,
    ICMPv6EchoRequest,
)
from scapy.layers.l2 import Ether, ARP, LLC
from scapy.packet import Raw
from scapy.contrib.igmp import IGMP
from scapy.layers.ppp import PPPoED, PPPoE, PPP

from framework import VppTestCase
from config import config
from util import ppc
from vpp_object import VppObject
from vpp_policer import PolicerAction, VppPolicer
from vpp_papi import VppEnum


COPP_ACTION_DROP = 0
COPP_ACTION_FORWARD = 1
COPP_ACTION_COPY = 2
COPP_ACTION_TRAP = 3


class LcpTrap(IntEnum):
    """CoPP trap IDs needed before plugin API enums are loaded."""

    LCP_TRAP_PTP_TX_EVENT = 11
    LCP_TRAP_ICMP_ECHO = 17
    LCP_TRAP_ACL = 18
    LCP_TRAP_SNAT_MISS = 38
    LCP_TRAP_DNAT_MISS = 39
    LCP_TRAP_NAT_HAIRPIN = 40
    LCP_TRAP_P4RT = 55
    LCP_TRAP_N_TYPES = 61


LCP_TRAP = LcpTrap

COPP_COUNTER_NAMES = (
    "trap_hit",
    "punt_required",
    "punt_pass",
    "punt_drop",
    "delivery_drop",
)


class VppLcpCoppPair(VppObject):
    """LCP itf pair helper, mirrors the one in test_linux_cp.py."""

    def __init__(self, test, phy, host):
        self._test = test
        self.phy = phy
        self.host = host

    def add_vpp_config(self):
        self._test.vapi.cli(
            "test lcp add phy %s host %s" % (self.phy, self.host)
        )
        self._test.registry.register(self, self._test.logger)
        return self

    def remove_vpp_config(self):
        self._test.vapi.cli(
            "test lcp del phy %s host %s" % (self.phy, self.host)
        )

    def object_id(self):
        return "lcp-copp:%d:%d" % (self.phy.sw_if_index, self.host.sw_if_index)

    def query_vpp_config(self):
        pairs = list(
            self._test.vapi.vpp.details_iter(self._test.vapi.lcp_itf_pair_get)
        )
        for p in pairs:
            if (
                p.phy_sw_if_index == self.phy.sw_if_index
                and p.host_sw_if_index == self.host.sw_if_index
            ):
                return True
        return False


class LinuxCpCoppTestCase(VppTestCase):
    """Base class for all linux-cp CoPP full-coverage tests."""

    extra_vpp_plugin_config = [
        "plugin default { disable }",
        "plugin linux_cp_plugin.so { enable }",
        "plugin linux_cp_unittest_plugin.so { enable }",
    ]

    def setUp(self):
        super().setUp()
        self.create_pg_interfaces(range(6))
        for i in self.pg_interfaces:
            i.admin_up()

        self.host = self.pg0
        self.phy = self.pg1
        self.egress = self.pg2
        self.l2_host = self.pg3
        self.l2_phy = self.pg4
        self.l2_egress = self.pg5

        self.phy.generate_remote_hosts(1)
        self.egress.generate_remote_hosts(1)
        self.l2_phy.generate_remote_hosts(1)
        self.l2_egress.generate_remote_hosts(1)

        self.phy.config_ip4()
        self.phy.config_ip6()
        self.egress.config_ip4()
        self.egress.config_ip6()

        self.phy.configure_ipv4_neighbors()
        self.phy.configure_ipv6_neighbors()
        self.egress.configure_ipv4_neighbors()
        self.egress.configure_ipv6_neighbors()

        VppLcpCoppPair(self, self.phy, self.host).add_vpp_config()
        VppLcpCoppPair(self, self.l2_phy, self.l2_host).add_vpp_config()

        self.vapi.bridge_domain_add_del_v2(
            bd_id=1, is_add=1, flood=1, uu_flood=1, forward=1, learn=1
        )
        for intf in (self.l2_phy, self.l2_egress):
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=intf.sw_if_index, bd_id=1
            )

    def tearDown(self):
        for intf in (self.l2_phy, self.l2_egress):
            self.vapi.sw_interface_set_l2_bridge(
                rx_sw_if_index=intf.sw_if_index, bd_id=1, enable=0
            )
        self.vapi.bridge_domain_add_del_v2(bd_id=1, is_add=0)
        self.phy.unconfig_ip4()
        self.phy.unconfig_ip6()
        self.egress.unconfig_ip4()
        self.egress.unconfig_ip6()
        for i in self.pg_interfaces:
            i.admin_down()
        super().tearDown()

    def pg_send(self, intf, pkts, worker=None, trace=True):
        if config.verbose >= 1:
            self.logger.info(ppc("Sending packets on %s:" % intf.name, pkts))
        return super().pg_send(intf, pkts, worker=worker, trace=trace)

    def _copp_counter(self, name, trap_id):
        counters = self.statistics.get_counter("/lcp/copp/%s" % name)
        return sum(thread[trap_id] for thread in counters)

    def _policy(self, trap_id):
        for p in self.vapi.lcp_copp_trap_dump():
            if p.trap_id == trap_id:
                return p
        return None

    def _make_policer(self, name, action):
        QosAction = VppEnum.vl_api_sse2_qos_action_type_t
        pol_action = PolicerAction(
            QosAction.SSE2_QOS_ACTION_API_TRANSMIT
            if action == "pass"
            else QosAction.SSE2_QOS_ACTION_API_DROP,
            0,
        )
        return VppPolicer(
            self,
            name,
            1000,
            0,
            1000,
            0,
            rate_type=1,
            conform_action=pol_action,
            exceed_action=pol_action,
            violate_action=pol_action,
        ).add_vpp_config()

    def _assert_stats_delta(self, trap_id, before, expected):
        for name, delta in expected.items():
            got = self._copp_counter(name, trap_id) - before[name]
            self.assertEqual(
                got,
                delta,
                "%s delta mismatch for trap %d (expected %d, got %d)"
                % (name, trap_id, delta, got),
            )

    def _send_and_check(
        self, ingress, pkt, host_count, egress_count, host=None, egress=None
    ):
        """Send one packet and verify captures on host/egress."""
        host = host or self.host
        if egress is None:
            egress = self.egress
        ifaces = [host]
        if egress is not None:
            ifaces.append(egress)
        self.pg_enable_capture(ifaces)
        self.pg_send(ingress, [pkt])

        if host_count:
            host.get_capture(host_count)
        else:
            host.assert_nothing_captured()

        if egress is not None:
            if egress_count:
                egress.get_capture(egress_count)
            else:
                egress.assert_nothing_captured()

    def _other_trap_counters(self, trap):
        return {
            trap_id: self._copp_counter("trap_hit", trap_id)
            for trap_id in trap.get("exclusive_with", ())
        }

    def _assert_other_traps_unchanged(self, before):
        for trap_id, count in before.items():
            self.assertEqual(
                self._copp_counter("trap_hit", trap_id),
                count,
                "packet was also classified as trap %d" % trap_id,
            )

    def _run_action(self, trap, action):
        """Run a single action test for a wired trap."""
        reason = trap.get("skip_reason")
        if reason:
            self.skipTest(reason)

        trap_id = trap["id"]
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))

        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}
        other_before = self._other_trap_counters(trap)

        self.vapi.lcp_copp_trap_add(
            trap_id=trap_id,
            action=action,
            priority=100,
            policer_index=0xFFFFFFFF,
        )
        self.addCleanup(self.vapi.lcp_copp_trap_del, trap_id=trap_id)

        pkt = trap["make_packet"](self)
        ingress = getattr(self, trap.get("ingress", "phy"))
        host = getattr(self, trap.get("host", "host"))
        egress_name = trap.get("egress", "egress")
        egress = getattr(self, egress_name) if egress_name else None
        has_egress = trap.get("has_egress", False)
        is_l2_direct = trap.get("is_l2_direct", False)
        original_host_count = trap.get("original_host_count", 0)
        original_egress_count = int(has_egress and not is_l2_direct)

        if action == COPP_ACTION_DROP:
            self._send_and_check(ingress, pkt, False, False, host, egress)
            expected = {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 1,
                "delivery_drop": 0,
            }
        elif action == COPP_ACTION_FORWARD:
            self._send_and_check(
                ingress, pkt, original_host_count, original_egress_count,
                host, egress
            )
            expected = {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 0,
                "delivery_drop": 0,
            }
        elif action == COPP_ACTION_COPY:
            self._send_and_check(
                ingress, pkt, original_host_count + 1, original_egress_count,
                host, egress
            )
            expected = {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            }
        else:  # TRAP
            self._send_and_check(ingress, pkt, True, False, host, egress)
            expected = {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            }

        self._assert_stats_delta(trap_id, before, expected)
        self._assert_other_traps_unchanged(other_before)
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)

    def _run_default(self, trap):
        """Test the producer's legacy default action when no policy is set."""
        reason = trap.get("skip_reason")
        if reason:
            self.skipTest(reason)

        trap_id = trap["id"]
        self.vapi.lcp_copp_trap_del(trap_id=trap_id)
        self.assertIsNone(self._policy(trap_id))

        before = {n: self._copp_counter(n, trap_id) for n in COPP_COUNTER_NAMES}
        other_before = self._other_trap_counters(trap)

        pkt = trap["make_packet"](self)
        ingress = getattr(self, trap.get("ingress", "phy"))
        host = getattr(self, trap.get("host", "host"))
        egress_name = trap.get("egress", "egress")
        egress = getattr(self, egress_name) if egress_name else None
        has_egress = trap.get("has_egress", False)
        default = trap["default_action"]

        if default == "copy":
            self._send_and_check(ingress, pkt, True, has_egress, host, egress)
            expected = {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            }
        elif default == "trap":
            self._send_and_check(ingress, pkt, True, False, host, egress)
            expected = {
                "trap_hit": 1,
                "punt_required": 1,
                "punt_pass": 1,
                "punt_drop": 0,
                "delivery_drop": 0,
            }
        else:  # drop
            self._send_and_check(ingress, pkt, False, False, host, egress)
            expected = {
                "trap_hit": 1,
                "punt_required": 0,
                "punt_pass": 0,
                "punt_drop": 1,
                "delivery_drop": 0,
            }

        self._assert_stats_delta(trap_id, before, expected)
        self._assert_other_traps_unchanged(other_before)


def _action_name(action):
    return {0: "drop", 1: "forward", 2: "copy", 3: "trap"}[action]


def make_action_test(trap, action):
    def test(self):
        self._run_action(trap, action)
    return test


def make_default_test(trap):
    def test(self):
        self._run_default(trap)
    return test


def generate_trap_methods(cls, traps):
    """Attach one default + four action test methods per wired trap.

    For traps marked with ``skip_reason`` only a single placeholder is
    generated to avoid burning time on repeated setUp cycles.
    """
    for trap in traps:
        tid = trap["id"]
        name = trap["name"].lower()
        reason = trap.get("skip_reason")

        if reason:
            placeholder_name = "test_copp_trap_%d_%s_placeholder" % (tid, name)
            setattr(
                cls,
                placeholder_name,
                unittest.skip(reason)(make_default_test(trap)),
            )
            continue

        default_name = "test_copp_trap_%d_%s_default" % (tid, name)
        setattr(cls, default_name, make_default_test(trap))

        for action in (
            COPP_ACTION_DROP,
            COPP_ACTION_FORWARD,
            COPP_ACTION_COPY,
            COPP_ACTION_TRAP,
        ):
            method_name = "test_copp_trap_%d_%s_%s" % (tid, name, _action_name(action))
            setattr(cls, method_name, make_action_test(trap, action))


# ---------------------------------------------------------------------------
# Packet factories
# ---------------------------------------------------------------------------


def _mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def make_stp(self):
    return (
        Ether(src=self.phy.remote_mac, dst="01:80:c2:00:00:00")
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / Raw(b"\x00\x00\x00\x00" + b"\x00" * 32)
    )


def make_lacp(self):
    return Ether(
        src=self.phy.remote_mac, dst="01:80:c2:00:00:02", type=0x8809
    ) / Raw(b"\x01\x01" + b"\x00" * 108)


def make_lldp(self):
    return Ether(
        src=self.phy.remote_mac, dst="01:80:c2:00:00:0e", type=0x88CC
    ) / Raw(b"\x02\x07lldp-tst")


def make_ptp_l2(self):
    return Ether(
        src=self.phy.remote_mac, dst="01:1b:19:00:00:00", type=0x88F7
    ) / Raw(b"\x00\x02" + b"\x00" * 42)


def make_isis(self):
    return (
        Ether(src=self.phy.remote_mac, dst="01:80:c2:00:00:14", type=11)
        / LLC(dsap=0x14, ssap=0x14, ctrl=3)
        / Raw(b"\x83\x08\x01\x00\x0f\x01\x00\x00")
    )


def make_snp(self):
    return (
        Ether(src=self.phy.remote_mac, dst="01:80:c2:00:00:15", type=11)
        / LLC(dsap=0xFE, ssap=0xFE, ctrl=3)
        / Raw(b"\x83\x08\x01\x00\x18\x01\x00\x00")
    )


# ARP


def make_arp_request(self):
    return (
        Ether(src=self.phy.remote_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=self.phy.remote_mac,
            psrc=self.phy.remote_ip4,
            hwdst="00:00:00:00:00:00",
            pdst="198.51.100.1",
        )
    )


def make_arp_response(self):
    return (
        Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
        / ARP(
            op=2,
            hwsrc=self.phy.remote_mac,
            psrc=self.phy.remote_ip4,
            hwdst=self.phy.local_mac,
            pdst=self.phy.local_ip4,
        )
    )


# IPv4 factories


def _ip4_base(self, dst_local=False, proto=None):
    dst = self.phy.local_ip4 if dst_local else self.egress.remote_ip4
    ip = IP(src=self.phy.remote_ip4, dst=dst)
    if proto is not None:
        ip.proto = proto
    return Ether(src=self.phy.remote_mac, dst=self.phy.local_mac) / ip


def make_igmp_query(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="01:00:5e:00:00:01")
        / IP(src=self.l2_phy.remote_ip4, dst="224.0.0.1", proto=2)
        / IGMP(type=0x11)
    )


def make_igmp_leave(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="01:00:5e:00:00:02")
        / IP(src=self.l2_phy.remote_ip4, dst="224.0.0.2", proto=2)
        / IGMP(type=0x17)
    )


def make_igmp_v1_report(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="01:00:5e:01:01:01")
        / IP(src=self.l2_phy.remote_ip4, dst="239.1.1.1", proto=2)
        / IGMP(type=0x12, gaddr="239.1.1.1")
    )


def make_igmp_v2_report(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="01:00:5e:01:01:01")
        / IP(src=self.l2_phy.remote_ip4, dst="239.1.1.1", proto=2)
        / IGMP(type=0x16, gaddr="239.1.1.1")
    )


def make_igmp_v3_report(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="01:00:5e:00:00:16")
        / IP(src=self.l2_phy.remote_ip4, dst="224.0.0.22", proto=2)
        / IGMP(type=0x22)
    )


def make_dhcp(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(dport=67) / Raw(b"dhcp")


def make_ospf(self, dst_local=False):
    return _ip4_base(self, dst_local, proto=89) / Raw(
        b"\x02\x01" + b"\x00" * 42
    )


def make_pim(self, dst_local=False):
    return _ip4_base(self, dst_local, proto=103) / Raw(b"pim")


def make_vrrp(self, dst_local=False):
    return _ip4_base(self, dst_local, proto=112) / Raw(b"vrrp")


def make_bfd(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(dport=3784) / Raw(b"bfd")


def make_ldp(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(sport=646) / Raw(b"ldp")


def make_bgp(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=179) / Raw(b"bgp")


def make_ssh(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=22) / Raw(b"ssh")


def make_snmp(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(dport=161) / Raw(b"snmp")


def make_ip2me_v4(self, dst_local=False):
    # IP2ME only makes sense with local destination
    return _ip4_base(self, True) / UDP(dport=9999) / Raw(b"ip2me")


def make_ptp_v4(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(dport=319) / Raw(b"ptp")


def make_bfd_micro(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(dport=6784) / Raw(b"bfd-micro")


def make_gnmi(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=9339) / Raw(b"gnmi")


def make_p4rt(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=9559) / Raw(b"p4rt")


def make_ntp_client(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(sport=123, dport=40000) / Raw(b"ntpc")


def make_ntp_server(self, dst_local=False):
    return _ip4_base(self, dst_local) / UDP(sport=40000, dport=123) / Raw(b"ntps")


def make_http_client(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(sport=80, dport=40000) / Raw(b"httpc")


def make_http_server(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(sport=40000, dport=80) / Raw(b"https")


def make_custom_iccp(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=8888) / Raw(b"iccp")


def make_custom_telnet(self, dst_local=False):
    return _ip4_base(self, dst_local) / TCP(dport=23) / Raw(b"telnet")


def make_custom_icmp_echo(self, dst_local=False):
    return _ip4_base(self, dst_local) / ICMP(type=8) / Raw(b"echo")


def make_dhcp_l2(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst=self.l2_egress.remote_mac)
        / IP(src=self.l2_phy.remote_ip4, dst=self.l2_egress.remote_ip4)
        / UDP(sport=68, dport=67)
        / Raw(b"dhcp-l2")
    )


def make_unknown_l3_mc(self, dst_local=False):
    return (
        Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
        / IP(src=self.phy.remote_ip4, dst="239.1.1.1")
        / UDP(dport=1234)
        / Raw(b"mc")
    )


# IPv6 factories


def _ip6_base(self, dst_local=False, nh=None):
    dst = self.phy.local_ip6 if dst_local else self.egress.remote_ip6
    ip = IPv6(src=self.phy.remote_ip6, dst=dst)
    if nh is not None:
        ip.nh = nh
    return Ether(src=self.phy.remote_mac, dst=self.phy.local_mac) / ip


def make_dhcpv6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=546) / Raw(b"dhcpv6")


def make_ospfv6(self, dst_local=False):
    return _ip6_base(self, dst_local, nh=89) / Raw(b"ospfv6")


def make_vrrpv6(self, dst_local=False):
    return _ip6_base(self, dst_local, nh=112) / Raw(b"vrrpv6")


def make_pim_v6(self, dst_local=False):
    return _ip6_base(self, dst_local, nh=103) / Raw(b"pim6")


def make_nd(self, dst_local=False):
    return _ip6_base(self, dst_local) / ICMPv6ND_RS()


def make_ns(self, dst_local=False):
    return _ip6_base(self, dst_local) / ICMPv6ND_NS()


def make_na(self, dst_local=False):
    return _ip6_base(self, dst_local) / ICMPv6ND_NA()


def make_mld_query(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="33:33:00:00:00:01")
        / IPv6(src=self.l2_phy.remote_ip6, dst="ff02::1")
        / ICMPv6MLQuery()
    )


def make_mld_v1_report(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="33:33:00:00:12:34")
        / IPv6(src=self.l2_phy.remote_ip6, dst="ff02::1234")
        / ICMPv6MLReport(mladdr="ff02::1234")
    )


def make_mld_v1_done(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="33:33:00:00:00:02")
        / IPv6(src=self.l2_phy.remote_ip6, dst="ff02::2")
        / ICMPv6MLDone(mladdr="ff02::1234")
    )


def make_mld_v2_report(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst="33:33:00:00:00:16")
        / IPv6(src=self.l2_phy.remote_ip6, dst="ff02::16")
        / ICMPv6MLReport2()
    )


def make_bfd_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=3784) / Raw(b"bfd6")


def make_ldp_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=646) / Raw(b"ldp6")


def make_bgp_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=179) / Raw(b"bgp6")


def make_ssh_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=22) / Raw(b"ssh6")


def make_snmp_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=161) / Raw(b"snmp6")


def make_ip2me_v6(self, dst_local=False):
    return _ip6_base(self, True) / UDP(dport=9999) / Raw(b"ip2me6")


def make_ptp_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=319) / Raw(b"ptp6")


def make_bfd_micro_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(dport=6784) / Raw(b"bfd-micro6")


def make_gnmi_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=9339) / Raw(b"gnmi6")


def make_p4rt_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=9559) / Raw(b"p4rt6")


def make_ntp_client_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(sport=123, dport=40000) / Raw(b"ntpc6")


def make_ntp_server_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / UDP(sport=40000, dport=123) / Raw(b"ntps6")


def make_http_client_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(sport=80, dport=40000) / Raw(b"httpc6")


def make_http_server_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(sport=40000, dport=80) / Raw(b"https6")


def make_custom_iccp_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=8888) / Raw(b"iccp6")


def make_custom_telnet_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / TCP(dport=23) / Raw(b"telnet6")


def make_custom_icmp_echo_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / ICMPv6EchoRequest() / Raw(b"echo6")


def make_dhcpv6_l2(self, dst_local=False):
    return (
        Ether(src=self.l2_phy.remote_mac, dst=self.l2_egress.remote_mac)
        / IPv6(src=self.l2_phy.remote_ip6, dst=self.l2_egress.remote_ip6)
        / UDP(sport=547, dport=546)
        / Raw(b"dhcpv6-l2")
    )


def make_redirect_v6(self, dst_local=False):
    return _ip6_base(self, dst_local) / ICMPv6ND_Redirect()


# ---------------------------------------------------------------------------
# Trap tables
# ---------------------------------------------------------------------------

L2_DIRECT_TRAPS = [
    dict(id=2, name="STP", make_packet=make_stp, default_action="trap",
         has_egress=False, is_l2_direct=True),
    dict(id=3, name="LACP", make_packet=make_lacp, default_action="trap",
         has_egress=False, is_l2_direct=True),
    dict(id=4, name="LLDP", make_packet=make_lldp, default_action="trap",
         has_egress=False, is_l2_direct=True),
    dict(id=10, name="PTP", make_packet=make_ptp_l2, default_action="trap",
         has_egress=False, is_l2_direct=True),
    dict(id=43, name="ISIS", make_packet=make_isis, default_action="trap",
         has_egress=False, is_l2_direct=True),
    dict(id=15, name="SNP", make_packet=make_snp, default_action="trap",
         has_egress=False, is_l2_direct=True),
]

ARP_TRAPS = [
    dict(id=23, name="ARP_REQUEST", make_packet=make_arp_request,
         default_action="copy", has_egress=False),
    dict(id=24, name="ARP_RESPONSE", make_packet=make_arp_response,
         default_action="copy", has_egress=False),
]

IP4_TRAPS = [
    dict(id=5, name="IGMP_QUERY", make_packet=make_igmp_query,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=6, name="IGMP_LEAVE", make_packet=make_igmp_leave,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=7, name="IGMP_V1_REPORT", make_packet=make_igmp_v1_report,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=8, name="IGMP_V2_REPORT", make_packet=make_igmp_v2_report,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=9, name="IGMP_V3_REPORT", make_packet=make_igmp_v3_report,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=25, name="DHCP", make_packet=make_dhcp,
         default_action="trap", has_egress=True, exclusive_with=(12,)),
    dict(id=26, name="OSPF", make_packet=make_ospf,
         default_action="trap", has_egress=True),
    dict(id=27, name="PIM", make_packet=make_pim,
         default_action="copy", has_egress=True),
    dict(id=28, name="VRRP", make_packet=make_vrrp,
         default_action="copy", has_egress=True),
    dict(id=49, name="BFD", make_packet=make_bfd,
         default_action="trap", has_egress=True),
    dict(id=53, name="LDP", make_packet=make_ldp,
         default_action="trap", has_egress=True),
    dict(id=10, name="PTP", make_packet=make_ptp_v4,
         default_action="trap", has_egress=True),
    dict(id=12, name="DHCP_L2", make_packet=make_dhcp_l2,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress", exclusive_with=(25,)),
    dict(id=37, name="UNKNOWN_L3_MULTICAST",
         make_packet=make_unknown_l3_mc,
         default_action="trap", has_egress=True,
         skip_reason="待 producer: UNKNOWN_L3_MULTICAST matcher"),
]

IP6_TRAPS = [
    dict(id=29, name="DHCPV6", make_packet=make_dhcpv6,
         default_action="trap", has_egress=True, exclusive_with=(13,)),
    dict(id=30, name="OSPFV6", make_packet=make_ospfv6,
         default_action="trap", has_egress=True),
    dict(id=31, name="VRRPV6", make_packet=make_vrrpv6,
         default_action="copy", has_egress=True),
    dict(id=32, name="IPV6_NEIGHBOR_DISCOVERY", make_packet=make_nd,
         default_action="copy", has_egress=True),
    dict(id=41, name="IPV6_NEIGHBOR_SOLICITATION", make_packet=make_ns,
         default_action="copy", has_egress=True),
    dict(id=42, name="IPV6_NEIGHBOR_ADVERTISEMENT", make_packet=make_na,
         default_action="copy", has_egress=True),
    dict(id=33, name="IPV6_MLD_V1_V2", make_packet=make_mld_query,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=34, name="IPV6_MLD_V1_REPORT", make_packet=make_mld_v1_report,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=35, name="IPV6_MLD_V1_DONE", make_packet=make_mld_v1_done,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=36, name="MLD_V2_REPORT", make_packet=make_mld_v2_report,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress"),
    dict(id=50, name="BFDV6", make_packet=make_bfd_v6,
         default_action="trap", has_egress=True),
    dict(id=53, name="LDP", make_packet=make_ldp_v6,
         default_action="trap", has_egress=True),
    dict(id=10, name="PTP", make_packet=make_ptp_v6,
         default_action="trap", has_egress=True),
    dict(id=27, name="PIM", make_packet=make_pim_v6,
         default_action="copy", has_egress=True),
    dict(id=13, name="DHCPV6_L2", make_packet=make_dhcpv6_l2,
         default_action="trap", has_egress=True, ingress="l2_phy",
         host="l2_host", egress="l2_egress", exclusive_with=(29,)),
]

# Local context: reuse factories with local destination.

def _local_wrap(factory):
    @functools.wraps(factory)
    def wrapped(self):
        return factory(self, dst_local=True)
    return wrapped

LOCAL_TRAPS = [
    dict(id=44, name="IP2ME", make_packet=_local_wrap(make_ip2me_v4),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=44, name="IP2ME_V6", make_packet=_local_wrap(make_ip2me_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=45, name="SSH", make_packet=_local_wrap(make_ssh),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=45, name="SSH_V6", make_packet=_local_wrap(make_ssh_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=46, name="SNMP", make_packet=_local_wrap(make_snmp),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=46, name="SNMP_V6", make_packet=_local_wrap(make_snmp_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=47, name="BGP", make_packet=_local_wrap(make_bgp),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=48, name="BGPV6", make_packet=_local_wrap(make_bgp_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=51, name="BFD_MICRO", make_packet=_local_wrap(make_bfd_micro),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=52, name="BFDV6_MICRO", make_packet=_local_wrap(make_bfd_micro_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=54, name="GNMI", make_packet=_local_wrap(make_gnmi),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=54, name="GNMI_V6", make_packet=_local_wrap(make_gnmi_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=55, name="P4RT", make_packet=_local_wrap(make_p4rt),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=55, name="P4RT_V6", make_packet=_local_wrap(make_p4rt_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=56, name="NTPCLIENT", make_packet=_local_wrap(make_ntp_client),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=56, name="NTPCLIENT_V6", make_packet=_local_wrap(make_ntp_client_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=57, name="NTPSERVER", make_packet=_local_wrap(make_ntp_server),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=57, name="NTPSERVER_V6", make_packet=_local_wrap(make_ntp_server_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=58, name="HTTPCLIENT", make_packet=_local_wrap(make_http_client),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=58, name="HTTPCLIENT_V6", make_packet=_local_wrap(make_http_client_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=59, name="HTTPSERVER", make_packet=_local_wrap(make_http_server),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=59, name="HTTPSERVER_V6", make_packet=_local_wrap(make_http_server_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=14, name="CUSTOM_ICCP", make_packet=_local_wrap(make_custom_iccp),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=14, name="CUSTOM_ICCP_V6", make_packet=_local_wrap(make_custom_iccp_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=16, name="CUSTOM_TELNET", make_packet=_local_wrap(make_custom_telnet),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=16, name="CUSTOM_TELNET_V6", make_packet=_local_wrap(make_custom_telnet_v6),
         default_action="trap", has_egress=False, original_host_count=1),
    dict(id=17, name="CUSTOM_ICMP_ECHO",
         make_packet=_local_wrap(make_custom_icmp_echo), default_action="trap",
         has_egress=False, original_host_count=1),
    dict(id=17, name="CUSTOM_ICMP_ECHO_V6",
         make_packet=_local_wrap(make_custom_icmp_echo_v6), default_action="trap",
         has_egress=False, original_host_count=1),
]


# Misc / placeholder traps.

def _make_misc(id_, name, default_action="trap", has_egress=False,
               skip_reason=None, make_packet=None, original_host_count=0):
    return dict(
        id=id_, name=name, default_action=default_action,
        has_egress=has_egress, skip_reason=skip_reason,
        original_host_count=original_host_count,
        make_packet=make_packet or (lambda self: None),
    )


def make_pppoe_discovery(self):
    return Ether(src=self.phy.remote_mac, dst=self.phy.local_mac) / PPPoED(
        sessionid=0
    ) / Raw(b"padi")


def make_pppoe_control(self):
    return (
        Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
        / PPPoE(sessionid=1)
        / PPP(proto=0xC021)
        / Raw(b"lcp")
    )


def make_pppoe_session_miss(self):
    return (
        Ether(src=self.phy.remote_mac, dst=self.phy.local_mac)
        / PPPoE(sessionid=0xFFFF)
        / PPP(proto=0x0021)
        / IP(src=self.phy.remote_ip4, dst=self.egress.remote_ip4)
        / Raw(b"ip")
    )


MISC_TRAPS = [
    _make_misc(0, "INVALID", default_action="trap",
               skip_reason="INVALID trap_id is rejected by API, no data path"),
    _make_misc(1, "DEFAULT", default_action="trap",
               skip_reason="DEFAULT has no producer; API only"),
    _make_misc(60, "STATIC_FDB_MOVE",
               skip_reason="待 producer: STATIC_FDB_MOVE"),
    _make_misc(19, "PPPOE_DISCOVERY", make_packet=make_pppoe_discovery,
               original_host_count=1),
    _make_misc(20, "PPPOE_CONTROL", make_packet=make_pppoe_control),
    _make_misc(21, "PPPOE_SESSION_MISS",
               make_packet=make_pppoe_session_miss),
    _make_misc(22, "IPOE_FDB_MISS", skip_reason="待 producer: IPOE_FDB_MISS"),
    _make_misc(11, "PTP_TX_EVENT", default_action="trap",
               skip_reason="待 producer: PTP TX completion adapter"),
    _make_misc(61, "N_TYPES", default_action="trap",
               skip_reason="N_TYPES is boundary, rejected by API"),
]
