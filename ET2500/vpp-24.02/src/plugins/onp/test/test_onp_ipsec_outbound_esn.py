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
class TestIpsecOutboundEsn(VppTestCase):
    """TestIpsecOutboundEsn Test Case - """ """packet forwarding via IPSEC outbound tunnel"""

    @classmethod
    def setUpConstants(self):
        """Set-up the test case class based on environment variables"""
        self.extra_vpp_plugin_config = ["plugin", "onp_plugin.so", "{", "enable", "}"]
        super(TestIpsecOutboundEsn, self).setUpConstants()
        otxFw.otx_set_dut_profile(self)

    @classmethod
    def setUpClass(self):
        self.testConfig = OtxTestCaseConfig()
        self.testConfig.otx_read_config()
        super(TestIpsecOutboundEsn, self).setUpClass()
        self.igw = OtxIgw(self)
        self.igw.launch()
        self.create_loopback_interfaces(2)

        self.ipsec_policy_bypass_errors = 0
        self.ipsec_policy_protect_errors = 0
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
        super(TestIpsecOutboundEsn, cls).tearDownClass()

    def setUp(self):
        self.logger.debug(
            "--- setUp() for %s.%s(%s) starts here ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        super(TestIpsecOutboundEsn, self).setUp()
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
        super(TestIpsecOutboundEsn, self).tearDown()

    def ipsec_setup(self):
        srcIpStart = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 1)
        srcIpEnd = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, -1)
        dstIpStart = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 10)
        dstIpEnd = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 30)

        ipsecObj = OtxIpsecObj(
            self,
            self.spd,
            self.saId,
            self.spiId,
            self.intf0,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
            esn=True,
            antiReplay=self.antiReplay,
        )
        ipsecObj.otx_create_sa()
        ipsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
        )
        ipsecObj.otx_create_spd(
            ipsecObj.tun_ip4_src,
            ipsecObj.tun_ip4_src,
            ipsecObj.tun_ip4_dst,
            ipsecObj.tun_ip4_dst,
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
            outbound=False,
            esn=True,
            antiReplay=self.antiReplay,
        )
        igwIpsecObj.otx_create_sa()
        igwIpsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
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

    def ipsec_outbound_create_fragments(self, packet_size=64):
        packets = []
        src_if = self.pg0
        dst_if = self.intf0

        # In range of 128 (0 - 127), keep same dst ip and 128 different src ips
        for i in range(0, self.loop_cnt):
            info = self.create_packet_info(src_if, dst_if)
            payload = self.info_to_payload(info)

            src_index = i % 128

            p = (
                Ether(dst=src_if.local_mac, src=src_if.remote_mac)
                / IP(
                    src=str(IPv4Address(self.input_ip) + src_index),
                    dst=str(IPv4Address(self.output_ip) + (i // 128)),
                )
                / UDP(sport=otxFw.OTX_DEF_UDP_SPORT, dport=otxFw.OTX_DEF_UDP_DPORT)
                / Raw(payload)
            )
            self.extend_packet(p, packet_size)
            info.data = p
            packets.append(p)

        return packets

    def ipsec_outbound_setup(self):
        self.logger.debug(
            "--- ipsec_outbound_setup() for %s.%s starts here ---"
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

    def verify_ipsec_sa_stats(self, saId, total_packets):
        otxDbg.otx_ipsec_sa_stats(self, saId)
        self.assert_equal(self.sa_stats_packets, total_packets)

    def verify_ipsec_spd_stats(self, spiId, total_packets, policyType="protect"):
        otxDbg.otx_ipsec_spd_stats(self, spiId, policyType)
        self.assert_equal(self.spd_stats_packets, total_packets)

    def verify_ipsec_sa_last_seq(self, saId, expected_seq):
        otxDbg.otx_ipsec_dump(self.igw, saId)
        self.assert_equal(self.igw.stats_ipsec_dump_last_seq, expected_seq)

    def send_outbound(self):
        left_over = self.packet_count
        while left_over > 0:
            if left_over <= 800:
                self.loop_cnt = left_over
            else:
                self.loop_cnt = 800
            left_over = left_over - self.loop_cnt

            packets = self.ipsec_outbound_create_fragments(self.packet_size)
            self.pg0.add_stream(packets)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.capture = self.pg1.get_capture(self.loop_cnt, timeout=20)
            time.sleep(3)

    def ipsec_outb_run_seq_num_update_check_first_window(self):
        self.ipsec_outbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_outb_run_seq_num_update_check_first_window",
            "send packets within first window",
        )
        start_seq = 0
        self.packet_count = (
            self.expected_count
        ) = total_packets = otxFw.otx_get_ipsec_replay_window_size()
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.send_outbound()

        # Validation
        otxDbg.verify_ipsec_policy_protect_errors(self)
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, 0, self.packet_count, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, self.packet_count, 0, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(self.saId, total_packets)
        self.verify_ipsec_spd_stats(self.spiId, total_packets)
        self.verify_ipsec_spd_stats(self.spiId, total_packets, "bypass")
        self.verify_ipsec_sa_last_seq(self.saId, self.expected_count + start_seq)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_outb_run_seq_num_update_check_first_subspace(self):
        self.ipsec_outbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_outb_run_seq_num_update_check_first_subspace",
            "send packets within first window",
        )
        start_seq = 0
        self.packet_count = (
            self.expected_count
        ) = total_packets = otxFw.otx_get_ipsec_replay_window_size()
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.send_outbound()
        # Validation
        otxDbg.verify_ipsec_policy_protect_errors(self)
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        self.verify_ipsec_sa_last_seq(self.saId, self.expected_count + start_seq)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_outb_run_seq_num_update_check_first_subspace",
            "send packets from second window",
        )
        start_seq = otxFw.otx_set_ipsec_sa_seq(
            self, self.saId, otxFw.otx_get_ipsec_replay_window_size() + 10
        )
        self.packet_count = self.expected_count = 10
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.send_outbound()
        # Validation
        otxDbg.verify_ipsec_policy_protect_errors(self)
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        self.verify_intf_stats(self.testConfig.lbk1_intf_name, 0, self.packet_count, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, self.packet_count, 0, 0)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(self.saId, total_packets)
        self.verify_ipsec_spd_stats(self.spiId, total_packets)
        self.verify_ipsec_spd_stats(self.spiId, total_packets, "bypass")
        self.verify_ipsec_sa_last_seq(self.saId, self.expected_count + start_seq)

        self.reset_stats()
        self.ipsec_terminate()

    def ipsec_outb_run_seq_num_update_check_first_and_second_subspace(self):
        self.ipsec_outbound_setup()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_outb_run_seq_num_update_check_" "first_and_second_subspace",
            "send packets from first window",
        )
        start_seq = 0
        self.packet_count = (
            self.expected_count
        ) = total_packets = otxFw.otx_get_ipsec_replay_window_size()
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.send_outbound()
        # Validation
        otxDbg.verify_ipsec_policy_protect_errors(self)
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        self.verify_ipsec_sa_last_seq(self.saId, self.expected_count + start_seq)

        self.reset_stats()

        otxFw.otx_log(
            self,
            "subtestcase",
            "ipsec_outb_run_seq_num_update_" "check_first_and_second_subspace",
            "send packets from end of first subspace",
        )
        start_seq = otxFw.otx_set_ipsec_sa_seq(
            self, self.saId, 0xFFFFFFFF - otxFw.otx_get_max_future_seq_number()
        )
        self.packet_count = self.expected_count = (
            otxFw.otx_get_max_future_seq_number() + 10
        )
        total_packets += self.packet_count
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.send_outbound()
        # Validation
        otxDbg.verify_ipsec_policy_protect_errors(self)
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        self.verify_ipsec_sa_last_seq(self.saId, 0x100000009)

        self.verify_intf_stats(self.testConfig.lbk1_intf_name, 0, self.packet_count, 0)
        self.verify_intf_stats(self.testConfig.lbk4_intf_name, self.packet_count, 0, 0)
        otxDbg.otx_onp_stats(self)
        self.verify_onp_stats(self.packet_count, self.packet_count, 0)
        self.verify_ipsec_sa_stats(self.saId, total_packets)
        self.verify_ipsec_spd_stats(self.saId, total_packets)
        self.verify_ipsec_spd_stats(self.saId, total_packets, "bypass")
        self.assert_equal(self.spd_stats_packets, total_packets)
        self.verify_ipsec_sa_last_seq(self.saId, self.expected_count + start_seq)

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
        self.assertEqual(self.esp4_encrypt_pkts_submit_counters, submitted)
        self.assertEqual(self.esp4_encrypt_pkts_recv_counters, recieved)
        self.assertEqual(self.esp4_encrypt_result_fail_counters, droped)
        self.assertEqual(self.sched_handoff_pkts_enq_counters, submitted)
        self.assertEqual(self.sched_handoff_pkts_recv_counters, recieved)

    def verify_sa_stats(self):
        otx_ipsec_sa_stats(self, self.saId)
        self.assertEqual(self.sa_stats_packets, self.packet_count)
        otx_ipsec_spd_stats(self, self.spiId)
        self.assertEqual(self.spd_stats_packets, self.packet_count)

    def verify_errors(self):
        self.assert_packet_counter_equal(
            "/err/ipsec4-output-feature/IPSec policy bypass",
            [self.ipsec_policy_bypass_errors],
        )
        self.assert_packet_counter_equal(
            "/err/ipsec4-output-feature/IPSec policy protect",
            [self.ipsec_policy_protect_errors],
        )

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
                index in seen or index in dropped_packet_indexes,
                "Packet with packet_index %d not received" % index,
            )

    def ipsec_outbound_validate(self):
        self.logger.debug(
            "--- ipsec_outbound_validate() for %s.%s starts here ---"
            % (self.__class__.__name__, self._testMethodName)
        )
        self.verify_intf_stats()
        self.verify_onp_stats()
        self.verify_sa_stats()
        self.verify_capture()
        self.verify_errors()

    # aes_gcm
    def test_ipsec_ar_on_aes_gcm_128_101B_c1(self):
        self.crypto_algo = "aes-gcm-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_gcm_192_101B_c1(self):
        self.crypto_algo = "aes-gcm-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_gcm_256_101B_c1(self):
        self.crypto_algo = "aes-gcm-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    # aes_ctr
    def test_ipsec_ar_on_aes_ctr_128_sha1_96_101B(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_128_sha_256_101B(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_128_sha_384_192_101B(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_128_sha_512_101B(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_192_sha1_96_101B(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_192_sha_256_101B(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_192_sha_384_192_101B(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_192_sha_512_101B(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_256_sha1_96_101B(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_256_sha_256_101B(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_256_sha_384_192_101B(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_ctr_256_sha_512_101B(self):
        self.crypto_algo = "aes-ctr-256"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    # aes_cbc
    def test_ipsec_ar_on_aes_cbc_128_sha1_96_101B(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_128_sha_256_101B(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_128_sha_384_192_101B(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_128_sha_512_101B(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_192_sha1_96_101B(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_192_sha_256_101B(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_192_sha_384_192_101B(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_192_sha_512_101B(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_256_sha1_96_101B(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha1-96"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_256_sha_256_101B(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_256_sha_384_192_101B(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-384-192"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()

    def test_ipsec_ar_on_aes_cbc_256_sha_512_101B(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-512-256"
        self.ipsec_outb_run_seq_num_update_check_first_window()
        self.ipsec_outb_run_seq_num_update_check_first_subspace()
        self.ipsec_outb_run_seq_num_update_check_first_and_second_subspace()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
