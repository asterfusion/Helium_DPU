import unittest
import os
from framework import VppTestCase
from asfframework import VppTestRunner
from scapy.packet import Raw, bind_layers
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, ARP, Dot1Q
from vpp_papi_provider import VppPapiProvider
import copy
from otx_igw import OtxIgw
from otx_test_configs import OtxTestCaseConfig
from vpp_interface import VppInterface
from otx_ipsec import OtxIpsecObj
import otx_framework as otxFw
import otx_debug as otxDbg
from otx_debug import otx_intf_stats, otx_onp_stats
from ipaddress import IPv4Address
from otx_framework import otxArchModel96xx, otxArchModel98xx


@unittest.skipUnless(
    otxArchModel96xx or otxArchModel98xx, "Skip policy mode in non cn9x board"
)
class TestIpsecInboundEsn(VppTestCase):
    """TestIpsecInboundEsn Test Case - """ """packet forwarding via IPSEC inbound tunnel"""

    @classmethod
    def setUpConstants(self):
        """Set-up the test case class based on environment variables"""
        self.extra_vpp_plugin_config = ["plugin", "onp_plugin.so", "{", "enable", "}"]
        super(TestIpsecInboundEsn, self).setUpConstants()
        otxFw.otx_set_dut_profile(self)

    @classmethod
    def setUpClass(self):
        self.testConfig = OtxTestCaseConfig()
        self.testConfig.otx_read_config()
        super(TestIpsecInboundEsn, self).setUpClass()
        self.igw = OtxIgw(self)
        self.igw.launch()
        self.create_loopback_interfaces(2)

        self.ipsec_policy_match_errors = 0
        self.ipsec_esn_replay_errors = 0
        self.ipsec_esn_mac_errors = 0
        self.packet_count = 10
        self.packet_size = 101
        self.spd = 1
        self.saId = 10
        self.spiId = 1000
        self.crypto_algo = None
        self.integ_algo = None
        self.expected_count = 0

    @classmethod
    def tearDownClass(cls):
        cls.igw.quit()
        super(TestIpsecInboundEsn, cls).tearDownClass()

    def setUp(self):
        self.logger.debug(
            "--- setUp() for %s.%s(%s) starts here ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        super(TestIpsecInboundEsn, self).setUp()
        self.reset_packet_infos()
        self.create_pg_interfaces(range(2))

        otxFw.otx_setup_default_configuration(self)
        self.igw.setup(self)

        self.V_IN = []
        self.V_OUT = []
        self.input_vector = []
        self.expected_output = []
        self.result = []
        self.local_register_ipsec_objs = []
        self.update_ipsec_register = True
        self.antiReplay = True

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show ipsec all"))
        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        self.igw.tearDown()
        otxFw.otx_tearDown_default_configuration(self)
        self.ip_table.remove_vpp_config()
        super(TestIpsecInboundEsn, self).tearDown()

    def ipsec_setup(self):
        srcIpStart = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 1)
        srcIpEnd = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, -1)
        dstIpStart = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 10)
        dstIpEnd = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 30)

        ipsecObj = OtxIpsecObj(
            self,
            self.spd,
            self.saId,
            self.spiId,
            self.intf0,
            self.integ_algo,
            self.crypto_algo,
            outbound=False,
            uplink=False,
            esn=True,
            antiReplay=self.antiReplay,
        )
        ipsecObj.otx_create_sa()
        ipsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
        )
        self.ipsecObj = ipsecObj

        igw = self.igw
        igwIpsecObj = OtxIpsecObj(
            igw.tc_obj,
            self.spd,
            self.saId,
            self.spiId,
            igw.tc_obj.intf0,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
            uplink=False,
            esn=True,
            antiReplay=self.antiReplay,
        )
        igwIpsecObj.otx_create_sa()
        igwIpsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
        )
        igwIpsecObj.otx_create_spd(
            igwIpsecObj.tun_ip4_src,
            igwIpsecObj.tun_ip4_src,
            igwIpsecObj.tun_ip4_dst,
            igwIpsecObj.tun_ip4_dst,
        )

        if otxFw.otx_is_onp_profile(self):
            self.assertEqual(otxFw.otx_verify_ipsec_backend(self, "onp backend"), True)
        if not otxFw.otx_is_onp_profile(self.igw):
            self.assertEqual(
                otxFw.otx_verify_ipsec_backend(self.igw, "onp backend"), False
            )

        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self.igw, igwIpsecObj), True)

    def ipsec_terminate(self):
        otxFw.otx_cleanup_ipsec_setup(self)
        self.igw.cleanup_ipsec_register()

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
            self.extend_packet(p, packet_size)
            info.data = p
            packets.append(p)

        return packets

    def ipsec_inbound_setup(self):
        self.logger.debug(
            "--- ipsec_inbound_setup() for %s.%s starts here ---"
            % (self.__class__.__name__, self._testMethodName)
        )
        self.ipsec_setup()
        self.reset_stats()

    def reset_stats(self):
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show hardware"))
        self.logger.debug(self.vapi.cli("show ipsec all"))
        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        rep = self.vapi.cli("clear run")
        rep = self.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear errors")
        rep = self.vapi.cli("clear onp counters")
        rep = self.igw.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear trace")
        self.igw.reset_stats()
        self.reset_packet_infos()

    def verify_ipsec_sa_stats(self, total_packets):
        otxDbg.otx_ipsec_sa_stats(self, self.saId)
        self.assert_equal(self.sa_stats_packets, total_packets)

    def verify_ipsec_spd_stats(self, total_packets):
        otxDbg.otx_ipsec_spd_stats(self, self.spiId)
        self.assert_equal(self.spd_stats_packets, total_packets)

    def send_inbound(self):
        packets = self.ipsec_inbound_create_fragments(self.packet_size)
        self.pg1.add_stream(packets)
        # self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        time.sleep(1)
        # self.capture = self.pg0.get_capture(self.expected_count, timeout=20)
        time.sleep(1)

    def ipsec_inbound_run_mac_error_caseA(self):
        self.ipsec_inbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseA",
            "Set seq num to x in first subspace. send n packets from x",
        )
        self.packet_count = self.expected_count = total_packets = 10
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, otxFw.otx_get_ipsec_replay_window_size() + 40
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseA",
            "Set seq num to a value out of lower"
            "bound in first subspace. Expected to drop",
        )
        self.packet_count = 1
        self.expected_count = 0
        total_packets += self.packet_count
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0x00000014)
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        otxDbg.set_ipsec_esn_mac_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        otxDbg.verify_ipsec_esn_mac_errors(self)
        self.verify_intf_stats(
            self.testConfig.lbk1_intf_name, self.packet_count, 0, self.packet_count
        )
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, 0, self.packet_count)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_inbound_run_mac_error_caseB(self):
        self.ipsec_inbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq num to x in first subspace."
            " Send n packets. This is to move "
            "replay window forward, so to refer "
            "higher future sequence number",
        )
        self.packet_count = self.expected_count = total_packets = 10
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0x00000400)
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq num to a value almost end of first subspace",
        )
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0xFFFFFFF0)
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Move further close to end of first subspace",
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        total_packets += self.packet_count

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Move further close to end of first " "subspace and enter second subspace",
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        total_packets += self.packet_count

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq number to one from first subspace, "
            "and send n packets. And expect mac error",
        )
        self.packet_count = 1
        self.expected_count = 0
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, (0xFFFFFFFF - otxFw.otx_get_ipsec_replay_window_size() - 100)
        )
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        otxDbg.set_ipsec_esn_mac_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        otxDbg.verify_ipsec_esn_mac_errors(self)
        self.verify_intf_stats(
            self.testConfig.lbk1_intf_name, self.packet_count, 0, self.packet_count
        )
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, 0, self.packet_count)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_inbound_run_replay_error_caseA(self):
        self.ipsec_inbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_replay_error_caseA",
            "Set seq number to x in first subspace. " "And send n packets",
        )
        self.packet_count = self.expected_count = total_packets = 10
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, otxFw.otx_get_ipsec_replay_window_size() + 40
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_replay_error_caseA",
            "Set seq number to same x in first "
            "subspace. And send n packets. Expecting "
            "to drop due to replay error",
        )
        self.packet_count = 10
        self.expected_count = 0
        total_policy_match_packets = total_packets + self.packet_count
        total_packets += self.expected_count
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, otxFw.otx_get_ipsec_replay_window_size() + 40
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        otxDbg.set_ipsec_esn_replay_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        otxDbg.verify_ipsec_esn_replay_errors(self)
        self.verify_intf_stats(
            self.testConfig.lbk1_intf_name, self.packet_count, 0, self.packet_count
        )
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(0, 0, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_policy_match_packets)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_inbound_run_replay_error_caseB(self):
        self.ipsec_inbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq num to x in first subspace. "
            "Send n packets. This is to move replay "
            "window forward, so to refer higher "
            "future sequence number",
        )
        self.packet_count = self.expected_count = total_packets = 10
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0x00000400)
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq num to a value almost end of first subspace",
        )
        total_packets += self.packet_count
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0xFFFFFFF0)
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()
        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Move further close to end of first subspace",
        )
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Move further close to end of first " "subspace and enter second subspace",
        )
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq number to one which is already "
            "used and in current window, and send n "
            "packets. And expect replay error",
        )
        self.packet_count = 10
        self.expected_count = 0
        total_policy_match_packets = total_packets + self.packet_count
        total_packets += self.expected_count
        otxFw.otx_set_ipsec_sa_seq(self.igw, 10, 0x100000000)
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        otxDbg.set_ipsec_esn_replay_errors(self, self.packet_count)
        self.send_inbound()
        # Validation
        otxDbg.verify_ipsec_policy_match_errors(self)
        otxDbg.verify_ipsec_esn_replay_errors(self)
        self.verify_intf_stats(
            self.testConfig.lbk1_intf_name, self.packet_count, 0, self.packet_count
        )
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(0, 0, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_policy_match_packets)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_inbound_run_ar_off(self):
        self.antiReplay = False
        self.ipsec_inbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_ar_off",
            "Set seq number to x from first " "subspace. And send n packets.",
        )
        self.packet_count = total_packets = 10
        self.expected_count = 10
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, otxFw.otx_get_ipsec_replay_window_size() + 40
        )
        otxDbg.set_ipsec_policy_match_errors(self, self.packet_count)
        self.send_inbound()

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_inbound_run_mac_error_caseB",
            "Set seq number to same x from first "
            "subspace. And send n packets. These "
            "expects wont get dropped as anti replay is off",
        )
        self.packet_count = 10
        total_packets += self.packet_count
        self.expected_count = 10
        otxFw.otx_set_ipsec_sa_seq(
            self.igw, 10, otxFw.otx_get_ipsec_replay_window_size() + 40
        )
        otxDbg.set_ipsec_esn_replay_errors(self, 0)
        self.send_inbound()
        otxDbg.verify_ipsec_esn_replay_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, self.packet_count, 0, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, 0, self.packet_count, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(total_packets)
        self.verify_ipsec_spd_stats(total_packets)

        self.reset_stats()
        self.ipsec_terminate()

    def verify_intf_stats(self, intf, rx, tx, drops):
        otx_intf_stats(self, intf)
        self.assertEqual(rx, self.intf_rx_packets)
        self.assertEqual(tx, self.intf_tx_packets)
        self.assertEqual(drops, self.intf_drops)

    def verify_onp_stats(self, submitted, recieved, droped):
        if hasattr(self, "vpp_profile") and self.vpp_profile is not "onp":
            return

        otxDbg.otx_onp_stats(self)
        self.assertEqual(self.esp4_decrypt_pkts_submit_counters, submitted)
        self.assertEqual(self.esp4_decrypt_pkts_recv_counters, recieved)
        self.assertEqual(self.esp4_decrypt_result_fail_counters, droped)

    def verify_errors(self):
        otxDbg.verify_ipsec_policy_match_errors(self)

    def verify_capture(self):
        info = None
        seen = set()
        for packet in self.capture:
            try:
                ip = packet[IP]
                udp = packet[UDP]
                payload_info = self.payload_to_info(packet[Raw])
                packet_index = payload_info.index
                if packet_index in seen:
                    raise Exception("Duplicate packet received", packet)
                seen.add(packet_index)
                info = self._packet_infos[packet_index]
                self.assertTrue(info is not None)
                self.assertEqual(packet_index, info.index)
                saved_packet = info.data
                self.assertEqual(ip.src, saved_packet[IP].src)
                self.assertEqual(ip.dst, saved_packet[IP].dst)
                self.assertEqual(udp.payload, saved_packet[UDP].payload)
            except Exception:
                self.logger.error("Unexpected or invalid packet:", packet)
                raise
        for index in self._packet_infos:
            self.assertTrue(
                index in seen, "Packet with packet_index %d not received" % index
            )

    # aes_gcm
    def test_ipsec_ar_on_esn_on_aes_gcm_128(self):
        self.crypto_algo = "aes-gcm-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_gcm_192(self):
        self.crypto_algo = "aes-gcm-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_gcm_256(self):
        self.crypto_algo = "aes-gcm-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    # aes_ctr
    def test_ipsec_ar_on_esn_on_aes_ctr_128_sha1_96(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_128_sha_256_128(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_128_sha_384_192(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_128_sha_512_256(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_192_sha1_96(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_192_sha_256_128(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_192_sha_384_192(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_192_sha_512_256(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_256_sha1_96(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_256_sha_256_128(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_256_sha_384_192(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_ctr_256_sha_512_256(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    # aes_cbc

    def test_ipsec_ar_on_esn_on_aes_cbc_128_sha1_96(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_128_sha_256_128(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_128_sha_384_192(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_128_sha_512_256(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_192_sha1_96(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_192_sha_256_128(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_192_sha_384_192(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_192_sha_512_256(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_256_sha1_96(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha1-96"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_256_sha_256_128(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_256_sha_384_192(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-384-192"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()

    def test_ipsec_ar_on_esn_on_aes_cbc_256_sha_512_256(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-512-256"
        self.ipsec_inbound_run_mac_error_caseA()
        self.ipsec_inbound_run_mac_error_caseB()
        self.ipsec_inbound_run_replay_error_caseA()
        self.ipsec_inbound_run_replay_error_caseB()
        self.ipsec_inbound_run_ar_off()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
