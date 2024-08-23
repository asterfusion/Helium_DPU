import os
import time
import unittest
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.packet import Raw, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP, Dot1Q
from ipaddress import IPv4Address
from vpp_papi_provider import VppPapiProvider
from vpp_interface import VppInterface
from otx_igw import OtxIgw
from otx_test_configs import OtxTestCaseConfig
from otx_ipsec import OtxIpsecObj
from otx_debug import otx_intf_stats, otx_onp_stats
from otx_debug import otx_ipsec_sa_stats
from otx_framework import otxArchModel10xx, otxArchModel98xx
from otx_framework import otx_is_onp_profile
import otx_framework as otxFw
import otx_debug as otxDbg
from util import fragment_rfc791
from scapy.all import bytes_hex


@unittest.skip("test disabled due to itf counter issue")
@unittest.skipUnless(
    otxArchModel10xx, "Skip route mode using itf interface in non cn10x board"
)
class TestIpsecInboundRouteModeReassembly(VppTestCase):
    """TestIpsecInboundRouteModeReassembly Test Case - """ """IPsec inner packet fragment and reassembly """

    @classmethod
    def setUpConstants(self):
        """Set-up the test case class based on environment variables"""
        self.extra_vpp_plugin_config = ["plugin", "onp_plugin.so", "{", "enable", "}"]
        super(TestIpsecInboundRouteModeReassembly, self).setUpConstants()
        otxFw.otx_set_dut_profile(self)

    @classmethod
    def setUpClass(self):
        self.testConfig = OtxTestCaseConfig()
        self.testConfig.otx_read_config()
        otxFw.set_feature(self, otxFw.OtxFeature.ROUTE_MODE_WITH_IPSEC_ITF)
        super(TestIpsecInboundRouteModeReassembly, self).setUpClass()
        self.igw = OtxIgw(self)
        self.igw.launch()
        self.create_loopback_interfaces(2)

        self.ipsec_policy_match_errors = 0
        self.packet_count = 15
        self.packet_size = 1200
        self.spd = 1
        self.saId = 5
        self.spiId = 1000
        self.crypto_algo = "aes-gcm-128"
        self.integ_algo = None
        self.spd_2 = 2
        self.saId_2 = 20

    @classmethod
    def tearDownClass(cls):
        cls.igw.quit()
        super(TestIpsecInboundRouteModeReassembly, cls).tearDownClass()

    def setUp(self):
        if not otx_is_onp_profile(self):
            raise unittest.SkipTest("Skip test cases for non onp profile")

        self.logger.debug(
            "--- setUp() for %s.%s(%s) starts here ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        super(TestIpsecInboundRouteModeReassembly, self).setUp()
        self.reset_packet_infos()
        self.create_pg_interfaces(range(2))

        otxFw.otx_setup_routemode_configuration(self)
        self.igw.setup(self)
        self.logger.debug(self.vapi.cli("show int"))
        self.logger.debug(self.vapi.cli("show int address"))

        self.V_IN = []
        self.V_OUT = []
        self.input_vector = []
        self.expected_output = []
        self.result = []
        self.pkt_infos = []
        self.expected_count = 0

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show int addr"))
        self.logger.debug(self.vapi.cli("show hardware detail"))
        self.logger.debug(self.vapi.cli("show ipsec all"))
        self.logger.debug(self.vapi.cli("show ipsec protect"))
        self.logger.debug(self.vapi.cli("show ipsec tunnel"))
        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        self.igw.tearDown()
        otxFw.otx_tearDown_default_configuration(self)
        self.ip_table.remove_vpp_config()
        super(TestIpsecInboundRouteModeReassembly, self).tearDown()

    def ipsec_setup(self):
        srcIpStart = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 1)
        srcIpEnd = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, -1)
        dstIpStart = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 10)
        dstIpEnd = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 30)

        # Inbound SA
        self.ipsecObj = OtxIpsecObj(
            self,
            self.spd,
            self.saId,
            self.spiId,
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=False,
            uplink=False,
        )
        saInDut = self.ipsecObj.otx_create_sa()

        # dummy outbound SA (which is to be applied for tun protect)
        ipsecObj2 = OtxIpsecObj(
            self,
            self.spd_2,
            self.saId_2,
            self.spiId,
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
        )
        saOutDut = ipsecObj2.otx_create_sa()
        self.ipsecIntf.add_tun_protect(saOutDut, [saInDut])

        # Outbound SA
        igw = self.igw
        igw.ipsecObj = OtxIpsecObj(
            igw.tc_obj,
            self.spd,
            self.saId,
            self.spiId,
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
            uplink=False,
        )
        saOutIgw = igw.ipsecObj.otx_create_sa()
        self.igw.ipsecIntf.add_tun_protect(saOutIgw)

        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, self.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, ipsecObj2), True)
        self.assertEqual(
            otxFw.otx_verify_ipsec_tun_setup(self, ipsecObj2, self.ipsecObj), True
        )
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, igw.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_tun_setup(self.igw, igw.ipsecObj), True)

    def ipsec_reasm_set(self, sa_index=0):
        self.vapi.cli("set onp ipsec reassembly 0")

    def ipsec_inbound_create_fragments(self, packet_size=64):
        packets = []
        src_if = self.pg1
        dst_if = self.intf1

        # In range of 128 (0 - 127), keep same dst ip and 128 different src ips
        for i in range(0, self.packet_count):
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)

            src_index = i % 128

            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(
                    src=str(IPv4Address(self.output_ip) + src_index),
                    dst=str(IPv4Address(self.input_ip) + (i // 128)),
                )
                / UDP(sport=otxFw.OTX_DEF_UDP_SPORT, dport=otxFw.OTX_DEF_UDP_DPORT)
                / Raw(payload)
            )
            self.extend_packet(p, packet_size, " 0123456789ABCDEF")
            info.data = p
            packets.append(p)

        return packets

    def clear_stats(self):
        self.logger.debug(self.vapi.cli("show run"))
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        self.logger.debug(self.igw.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show trace"))
        self.logger.debug(self.vapi.cli("show ipsec all"))
        rep = self.vapi.cli("clear run")
        rep = self.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear errors")
        rep = self.vapi.cli("clear onp counters")
        rep = self.igw.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear trace")
        rep = self.vapi.cli("clear ipsec counters")

    def setup_ipsec_inb_routemode_reass(self):
        self.logger.debug(
            "--- ipsec_inbound_setup() for %s.%s starts here ---"
            % (self.__class__.__name__, self._testMethodName)
        )
        self.ipsec_setup()
        self.ipsec_reasm_set()

        self.clear_stats()
        rep = self.vapi.cli("trace add pg-input 10")
        rep = self.vapi.cli("trace add onp-pktio-input 10")

    def ipsec_inbound_run(self, rx_count=None):
        self.logger.debug(
            "--- ipsec_inbound_run() for %s.%s starts here ---"
            % (self.__class__.__name__, self._testMethodName)
        )

        if rx_count is None:
            rx_count = self.expected_rx_count

        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start(trace=False)
        self.capture = self.pg0.get_capture(rx_count, timeout=10)

    def verify_intf_stats(self):
        packet_count = len(self._packet_infos)
        otx_intf_stats(self, self.testConfig.lbk1_intf_name)
        self.assertEqual(self.expected_rx_count, self.intf_rx_packets)
        self.assertEqual(0, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

        otx_intf_stats(self, self.testConfig.lbk4_intf_name)
        self.assertEqual(0, self.intf_rx_packets)
        self.assertEqual(self.expected_tx_count, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

        otx_intf_stats(self, self.ipsecIntf.ipsec_intf.name)
        self.assertEqual(self.expected_sa_packet_count, self.intf_rx_packets)
        self.assertEqual(0, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

    def verify_onp_stats(self):
        if hasattr(self, "vpp_profile") and self.vpp_profile is not "onp":
            return

        otx_onp_stats(self)

    def verify_errors(self):
        self.assertEqual(self.statistics.set_errors(), {})

    def verify_sa_stats(self):
        otx_ipsec_sa_stats(self, self.saId)
        self.assertEqual(self.sa_stats_packets, self.expected_sa_packet_count)

    def verify_capture(self):
        info = None
        seen = set()
        for packet in self.capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                packet_info = self.payload_to_info(packet[Raw])
                packet_index = packet_info.index
                if packet_index in seen:
                    raise Exception("Duplicate packet received", packet)
                seen.add(packet_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data

                self.assertEqual(len(udp.payload), len(saved_packet[UDP].payload))
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                # self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error("Unexpected or invalid packet:", packet)
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def ipsec_inbound_validate_reass(self, capture=False):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )
        self.verify_intf_stats()
        if capture is True:
            self.verify_capture()
        self.verify_sa_stats()
        self.verify_errors()

    def send_ipsec_inb_routemode_reass_success(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos

        for index, info in packet_infos.items():
            p = info.data
            fragments_400 = fragment_rfc791(p, 400)
            self.pkt_infos.append((index, fragments_400))

        self.fragments_400 = [x for (_, frags) in self.pkt_infos for x in frags]
        self.expected_rx_count = self.packet_count
        self.expected_tx_count = len(self.fragments_400)
        self.expected_sa_packet_count = len(self.fragments_400)

        self.pg1.add_stream(self.fragments_400)
        self.ipsec_inbound_run()

        self.ipsec_inbound_validate_reass(capture=True)

    def send_ipsec_inb_routemode_reass_timeout(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        self.packet_count = 256
        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos

        for index, info in packet_infos.items():
            p = info.data
            fragments_400 = fragment_rfc791(p, 400)
            self.pkt_infos.append((index, fragments_400))

        self.fragments_400 = [
            x
            for (_, frags) in self.pkt_infos
            for x in frags[: -1 if len(frags) > 1 else None]
        ]
        self.fragments_leftover = [
            x
            for (_, frags) in self.pkt_infos
            for x in frags[-1 if len(frags) > 1 else None]
        ]
        self.expected_rx_count = len(self.fragments_400)
        self.expected_tx_count = len(self.fragments_400)
        self.expected_sa_packet_count = len(self.fragments_400)

        self.pg1.add_stream(self.fragments_400)

        # get capture adds delay
        self.ipsec_inbound_run()

        self.ipsec_inbound_validate_reass()
        self.clear_stats()

        # send leftover fragments.
        self.expected_rx_count = len(self.fragments_leftover)
        self.expected_tx_count = len(self.fragments_leftover)
        self.expected_sa_packet_count = len(self.fragments_leftover)
        self.pg1.add_stream(self.fragments_leftover)
        self.ipsec_inbound_run()
        self.ipsec_inbound_validate_reass()

    def send_ipsec_inb_routemode_reass_outOfOrder(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos

        for index, info in packet_infos.items():
            p = info.data
            fragments_400 = fragment_rfc791(p, 400)
            self.pkt_infos.append((index, fragments_400))

        self.fragments_400 = [x for (_, frags) in self.pkt_infos for x in frags]
        self.fragments_400.reverse()
        self.expected_rx_count = self.packet_count
        self.expected_tx_count = len(self.fragments_400)
        self.expected_sa_packet_count = len(self.fragments_400)

        self.pg1.add_stream(self.fragments_400)
        self.ipsec_inbound_run()

        self.ipsec_inbound_validate_reass()

    def send_ipsec_inb_routemode_reass_moreFragments(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos

        for index, info in packet_infos.items():
            p = info.data
            fragments_300 = fragment_rfc791(p, 300)
            self.pkt_infos.append((index, fragments_300))

        self.fragments_300 = [x for (_, frags) in self.pkt_infos for x in frags]
        self.expected_rx_count = len(self.fragments_300)
        self.expected_tx_count = len(self.fragments_300)
        self.expected_sa_packet_count = len(self.fragments_300)

        self.pg1.add_stream(self.fragments_300)
        self.ipsec_inbound_run()

        self.ipsec_inbound_validate_reass()
        # Sleep for 6 seconds, to clear out zombie entries
        time.sleep(6)

    def send_ipsec_inb_routemode_reass_evict(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        self.packet_size = 501
        self.packet_count = otxFw.ONP_MAX_HW_REASS_CONTEXTS + 1

        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos
        for index, info in packet_infos.items():
            p = info.data
            fragments_400 = fragment_rfc791(p, 400)
            self.pkt_infos.append((index, fragments_400))
        self.fragments_400 = [
            x
            for (_, frags) in self.pkt_infos
            for x in frags[: -1 if len(frags) > 1 else None]
        ]
        self.fragments_leftover = [
            x
            for (_, frags) in self.pkt_infos
            for x in frags[-1 if len(frags) > 1 else None]
        ]

        expected_count = len(self.fragments_400)

        self.expected_rx_count = 1
        self.expected_tx_count = len(self.fragments_400)
        self.expected_sa_packet_count = 1

        # Send packets part by part, since facing issue with pg
        # sending whole packets. So split them into batch of 500
        i = 0
        packet_parts = []
        last_fragment = []
        start_index = 0

        while start_index < len(self.fragments_400):
            start = start_index
            end = (
                (start_index + 500)
                if (start_index + 500 < len(self.fragments_400))
                else len(self.fragments_400)
            )
            packet_parts.append([])
            packet_parts[i] = [
                x
                for index, x in enumerate(self.fragments_400)
                if index >= start and index < end
            ]
            start_index = end
            i += 1

        i = 0
        start_index = 0
        while start_index < len(self.fragments_leftover):
            start = start_index
            end = (
                (start_index + 500)
                if (start_index + 500 < len(self.fragments_leftover))
                else len(self.fragments_leftover)
            )
            last_fragment.append([])
            last_fragment[i] = [
                x
                for index, x in enumerate(self.fragments_leftover)
                if index >= start and index < end
            ]
            start_index = end
            i += 1

        i = 0
        while i < len(packet_parts):
            self.pg1.add_stream(packet_parts[i])
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start(trace=False)
            i += 1

        self.ipsec_inbound_validate_reass()

        # ONP_MAX_HW_REASS_CONTEXTS packets will get last fragment.
        # And 1 packet will go as zombie
        i = 0
        while i < len(last_fragment):
            self.pg1.add_stream(last_fragment[i])
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start(trace=False)
            i += 1

    def send_ipsec_inb_routemode_reass_overlap(self):
        self.logger.debug(
            "--- (%s) for %s.%s starts here ---"
            % (otxDbg.otx_func_name, self.__class__.__name__, self._testMethodName)
        )

        self.packet_size = 500
        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        packet_infos = self._packet_infos

        for index, info in packet_infos.items():
            p = info.data
            fragments_400 = fragment_rfc791(p, 400)
            fragments_300 = fragment_rfc791(p, 300)
            fragments_200 = [x for f in fragments_400 for x in fragment_rfc791(f, 200)]
            self.pkt_infos.append((index, fragments_400, fragments_300, fragments_200))

        self.fragments_400 = [x for (_, frags, _, _) in self.pkt_infos for x in frags]
        self.fragments_300 = [x for (_, _, frags, _) in self.pkt_infos for x in frags]
        self.fragments_200 = [x for (_, _, _, frags) in self.pkt_infos for x in frags]

        fragments = []
        for _, _, frags_300, frags_200 in self.pkt_infos:
            if len(frags_300) == 1:
                fragments.extend(frags_300)
            else:
                for i, j in zip(frags_200, frags_300):
                    fragments.extend(i)
                    fragments.extend(j)

        self.expected_rx_count = len(fragments)
        self.expected_tx_count = len(fragments)
        self.expected_sa_packet_count = len(fragments)

        self.pg1.add_stream(fragments)
        self.ipsec_inbound_run()

        self.ipsec_inbound_validate_reass()

    def test_ipsec_inbound_reass_success(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_success()

    def test_ipsec_inbound_reass_timeout(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_timeout()

    def test_ipsec_inbound_reass_outOfOrder(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_outOfOrder()

    def test_ipsec_inbound_reass_moreFragments(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_moreFragments()

    def test_ipsec_inbound_reass_evict(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_evict()

    def test_ipsec_inbound_reass_overlap(self):
        self.setup_ipsec_inb_routemode_reass()
        self.send_ipsec_inb_routemode_reass_overlap()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
