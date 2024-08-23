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
from otx_debug import otx_intf_stats, otx_onp_stats
from otx_debug import otx_ipsec_sa_stats, otx_ipsec_spd_stats
from ipaddress import IPv4Address
from otx_framework import otxArchModel96xx, otxArchModel98xx
import otx_debug as otxDbg


@unittest.skipUnless(
    otxArchModel96xx or otxArchModel98xx, "Skip policy mode in non cn9x board"
)
class TestIpsecOutbound(VppTestCase):
    """TestIpsecOutbound Test Case - """ """packet forwarding via IPSEC outbound tunnel"""

    @classmethod
    def setUpConstants(self):
        """Set-up the test case class based on environment variables"""
        self.extra_vpp_plugin_config = ["plugin", "onp_plugin.so", "{", "enable", "}"]
        super(TestIpsecOutbound, self).setUpConstants()
        otxFw.otx_set_dut_profile(self)

    @classmethod
    def setUpClass(self):
        self.testConfig = OtxTestCaseConfig()
        self.testConfig.otx_read_config()
        super(TestIpsecOutbound, self).setUpClass()
        self.igw = OtxIgw(self)
        self.igw.launch()
        self.create_loopback_interfaces(2)

        self.ipsec_policy_bypass_errors = 0
        self.ipsec_policy_protect_errors = 0
        self.packet_count = 256
        self.packet_size = 64
        self.spd = 1
        self.saId = 10
        self.spiId = 1000
        self.crypto_algo = None
        self.integ_algo = None

    @classmethod
    def tearDownClass(cls):
        cls.igw.quit()
        super(TestIpsecOutbound, cls).tearDownClass()

    def setUp(self):
        self.logger.debug(
            "--- setUp() for %s.%s(%s) starts here ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        super(TestIpsecOutbound, self).setUp()
        self.reset_packet_infos()
        self.create_pg_interfaces(range(2))

        otxFw.otx_setup_default_configuration(self)
        self.igw.setup(self)

        self.V_IN = []
        self.V_OUT = []
        self.input_vector = []
        self.expected_output = []
        self.result = []

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show ipsec all"))
        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        self.igw.tearDown()
        otxFw.otx_tearDown_default_configuration(self)
        self.ip_table.remove_vpp_config()
        super(TestIpsecOutbound, self).tearDown()

    def ipsec_setup(self):
        srcIpStart = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, 1)
        srcIpEnd = otxFw.otx_add_ip_addr_host_field(self.input_ip_prefix, -1)
        dstIpStart = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 10)
        dstIpEnd = otxFw.otx_add_ip_addr_host_field(self.output_ip_prefix, 30)

        self.ipsecObj = OtxIpsecObj(
            self,
            self.spd,
            self.saId,
            self.spiId,
            self.intf0,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
        )
        self.ipsecObj.otx_create_sa()
        self.ipsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
        )
        self.ipsecObj.otx_create_spd(
            self.ipsecObj.tun_ip4_src,
            self.ipsecObj.tun_ip4_src,
            self.ipsecObj.tun_ip4_dst,
            self.ipsecObj.tun_ip4_dst,
        )

        igw = self.igw
        igw.ipsecObj = OtxIpsecObj(
            igw.tc_obj,
            self.spd,
            self.saId,
            self.spiId,
            igw.tc_obj.intf0,
            self.integ_algo,
            self.crypto_algo,
            outbound=False,
        )
        igw.ipsecObj.otx_create_sa()
        igw.ipsecObj.otx_create_spd(
            srcIpStart, srcIpEnd, dstIpStart, dstIpEnd, policy="protect"
        )

        if otxFw.otx_is_onp_profile(self):
            self.assertEqual(otxFw.otx_verify_ipsec_backend(self, "onp backend"), True)
        if not otxFw.otx_is_onp_profile(self.igw):
            self.assertEqual(
                otxFw.otx_verify_ipsec_backend(self.igw, "onp backend"), False
            )

        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, self.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self.igw, igw.ipsecObj), True)

    def ipsec_outbound_create_fragments(self, packet_size=64):
        packets = []
        src_if = self.pg0
        dst_if = self.intf0

        # In range of 128 (0 - 127), keep same dst ip and 128 different src ips
        for i in range(0, self.packet_count):
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

        rep = self.vapi.cli("clear run")
        rep = self.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear errors")
        rep = self.vapi.cli("clear onp counters")
        rep = self.igw.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear trace")
        rep = self.vapi.cli("trace add pg-input 10")
        rep = self.vapi.cli("trace add onp-pktio-input 10")
        packets = self.ipsec_outbound_create_fragments(self.packet_size)
        self.pg0.add_stream(packets)

    def ipsec_outbound_run(self):
        self.logger.debug(
            "--- ipsec_outbound_run() for %s.%s starts here ---"
            % (self.__class__.__name__, self._testMethodName)
        )
        self.pg_enable_capture(self.pg_interfaces)
        otxDbg.set_ipsec_policy_protect_errors(self, self.packet_count)
        otxDbg.set_ipsec_policy_bypass_errors(self, self.packet_count)
        self.pg_start()
        self.capture = self.pg1.get_capture(self.packet_count, timeout=10)

    def verify_intf_stats(self):
        packet_count = len(self._packet_infos)

        otx_intf_stats(self, self.testConfig.lbk1_intf_name)
        self.assertEqual(0, self.intf_rx_packets)
        self.assertEqual(packet_count, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

        otx_intf_stats(self, self.testConfig.lbk4_intf_name)
        self.assertEqual(packet_count, self.intf_rx_packets)
        self.assertEqual(0, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

    def verify_onp_stats(self):
        if hasattr(self, "vpp_profile") and self.vpp_profile != "onp":
            return

        otx_onp_stats(self)
        self.assertEqual(self.esp4_encrypt_pkts_submit_counters, self.packet_count)
        self.assertEqual(self.esp4_encrypt_pkts_recv_counters, self.packet_count)
        self.assertEqual(self.esp4_encrypt_result_fail_counters, 0)
        self.assertEqual(self.sched_handoff_pkts_enq_counters, self.packet_count)
        self.assertEqual(self.sched_handoff_pkts_recv_counters, self.packet_count)

    def verify_sa_stats(self):
        otx_ipsec_sa_stats(self, self.saId)
        self.assertEqual(self.sa_stats_packets, self.packet_count)
        otx_ipsec_spd_stats(self, self.spiId)
        self.assertEqual(self.spd_stats_packets, self.packet_count)

    def verify_errors(self):
        otxDbg.verify_ipsec_policy_bypass_errors(self)
        otxDbg.verify_ipsec_policy_protect_errors(self)

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
    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_128_64B_c1(self):
        self.crypto_algo = "aes-gcm-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_192_64B_c1(self):
        self.crypto_algo = "aes-gcm-192"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_256_64B_c1(self):
        self.crypto_algo = "aes-gcm-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_128_101B_c1(self):
        self.crypto_algo = "aes-gcm-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_192_101B_c1(self):
        self.crypto_algo = "aes-gcm-192"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_256_101B_c1(self):
        self.crypto_algo = "aes-gcm-256"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_128_1400B_c1(self):
        self.crypto_algo = "aes-gcm-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_192_1400B_c1(self):
        self.crypto_algo = "aes-gcm-192"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_gcm_256_1400B_c1(self):
        self.crypto_algo = "aes-gcm-256"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    # aes_ctr
    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_128_sha_256_64B_c1(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_256_64B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_512_64B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_128_sha_256_101B_c1(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-256-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_256_101B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-256-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_512_101B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-512-256"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_128_sha_256_1400B_c1(self):
        self.crypto_algo = "aes-ctr-128"
        self.integ_algo = "sha-256-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_256_1400B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-256-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_ctr_192_sha_512_1400B_c1(self):
        self.crypto_algo = "aes-ctr-192"
        self.integ_algo = "sha-512-256"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    # aes_cbc
    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_256_64B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_512_64B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_256_64B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_512_64B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_256_64B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_512_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_512_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.packet_size = 101
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_256_1400B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_512_1400B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_256_1400B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_512_1400B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_ipsec_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_256_1400B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.packet_size = 1400
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
