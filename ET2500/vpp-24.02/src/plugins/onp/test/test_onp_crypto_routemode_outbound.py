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
from otx_debug import otx_ipsec_sa_stats
from otx_debug import otx_ipsec_spd_stats, otx_ipsec_tun_stats
from ipaddress import IPv4Address
from otx_framework import otxArchModel10xx, otxArchModel98xx


@unittest.skipUnless(
    otxArchModel10xx, "Skip route mode using itf interface in non cn10x board"
)
class TestCryptoOutboundRouteMode(VppTestCase):
    """TestCryptoOutboundRouteMode Test Case - """ """crypto outbound routemode"""

    @classmethod
    def setUpConstants(self):
        """Set-up the test case class based on environment variables"""
        self.extra_vpp_plugin_config = ["plugin", "onp_plugin.so", "{", "enable", "}"]
        super(TestCryptoOutboundRouteMode, self).setUpConstants()
        otxFw.otx_set_dut_profile(self)

    @classmethod
    def setUpClass(self):
        self.testConfig = OtxTestCaseConfig()
        self.testConfig.otx_read_config()
        otxFw.set_feature(self, otxFw.OtxFeature.ROUTE_MODE_WITH_IPSEC_ITF)

        super(TestCryptoOutboundRouteMode, self).setUpClass()
        self.igw = OtxIgw(self)
        self.igw.launch()
        self.create_loopback_interfaces(2)

        self.ipsec_tun_esp_packets = {}
        self.packet_count = 15
        self.packet_size = 101
        self.spd = 1
        self.saId = 10
        self.spiId = 1000
        self.crypto_algo = None
        self.integ_algo = None
        self.spd_2 = 2
        self.saId_2 = 20
        self.esn_status = otxFw.get_esn_status(self)

        otxFw.async_crypto_setup(self)

        if hasattr(self, "vpp_profile") and self.vpp_profile is not "onp":
            self.encrypt_tun_node = "esp4-encrypt-tun"
        else:
            self.encrypt_tun_node = "onp-esp4-encrypt-tun"

    @classmethod
    def tearDownClass(cls):
        cls.igw.quit()
        super(TestCryptoOutboundRouteMode, cls).tearDownClass()

    def setUp(self):
        self.logger.debug(
            "--- setUp() for %s.%s(%s) starts here ---"
            % (self.__class__.__name__, self._testMethodName, self._testMethodDoc)
        )
        super(TestCryptoOutboundRouteMode, self).setUp()
        self.reset_packet_infos()
        self.create_pg_interfaces(range(2))

        otxFw.otx_setup_routemode_configuration(self)
        self.igw.setup(self)

        self.V_IN = []
        self.V_OUT = []
        self.input_vector = []
        self.expected_output = []
        self.result = []

    def tearDown(self):
        self.logger.debug(self.vapi.cli("show interface"))
        self.logger.debug(self.vapi.cli("show int addr"))
        self.logger.debug(self.vapi.cli("show ipsec all"))
        self.logger.debug(self.vapi.cli("show ipsec protect"))
        self.logger.debug(self.vapi.cli("show ipsec tunnel"))

        self.logger.debug(self.vapi.cli("show errors"))
        self.logger.debug(self.vapi.cli("show onp counters"))
        self.igw.tearDown()
        otxFw.otx_tearDown_default_configuration(self)
        self.ip_table.remove_vpp_config()
        super(TestCryptoOutboundRouteMode, self).tearDown()

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
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
            esn=self.esn_status,
        )
        sa = self.ipsecObj.otx_create_sa()
        self.ipsecIntf.add_tun_protect(sa)

        # Inbound SA
        igw = self.igw
        igw.ipsecObj = OtxIpsecObj(
            igw.tc_obj,
            self.spd,
            self.saId,
            self.spiId,
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=False,
            esn=self.esn_status,
        )
        saInIgw = igw.ipsecObj.otx_create_sa()

        # dummy outbound SA (which is to be applied for tun protect)
        ipsecObj2 = OtxIpsecObj(
            igw.tc_obj,
            self.spd_2,
            self.saId_2,
            self.spiId,
            None,
            self.integ_algo,
            self.crypto_algo,
            outbound=True,
            esn=self.esn_status,
        )
        saOutIgw = ipsecObj2.otx_create_sa()
        self.igw.ipsecIntf.add_tun_protect(saOutIgw, [saInIgw])
        #
        #        if otxFw.otx_is_onp_profile(self):
        #            self.assertEqual(
        #                    otxFw.otx_verify_ipsec_backend(
        #                        self, 'onp backend'), True)
        #        if not otxFw.otx_is_onp_profile(self.igw):
        #            self.assertEqual(
        #                    otxFw.otx_verify_ipsec_backend(
        #                        self.igw, 'onp backend'), False)

        self.assertEqual(otxFw.otx_verify_ipsec_setup(self, self.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_tun_setup(self, self.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self.igw, igw.ipsecObj), True)
        self.assertEqual(otxFw.otx_verify_ipsec_setup(self.igw, ipsecObj2), True)
        self.assertEqual(
            otxFw.otx_verify_ipsec_tun_setup(self.igw, ipsecObj2, igw.ipsecObj), True
        )

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
        self.pg_start(trace=False)
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

        otx_intf_stats(self, self.ipsecIntf.ipsec_intf.name)
        self.assertEqual(0, self.intf_rx_packets)
        self.assertEqual(packet_count, self.intf_tx_packets)
        self.assertEqual(0, self.intf_drops)

    def verify_onp_stats(self):
        if hasattr(self, "vpp_profile") and self.vpp_profile is not "onp":
            return

        otx_onp_stats(self)
        # TODO: Verify the counter
        # self.assertEqual(self.esp4_encrypt_pkts_noop_counters, self.packet_count)

    def verify_sa_stats(self):
        otx_ipsec_sa_stats(self, self.saId)
        self.assertEqual(self.sa_stats_packets, self.packet_count)

    def verify_errors(self):
        self.assertEqual(self.statistics.set_errors(), {})

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
        # self.verify_errors()

    # aes_gcm
    def test_crypto_outbound_1tunnelsa_ar_on_aes_gcm_128_101B_c1(self):
        self.crypto_algo = "aes-gcm-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_gcm_192_101B_c1(self):
        self.crypto_algo = "aes-gcm-192"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_gcm_256_101B_c1(self):
        self.crypto_algo = "aes-gcm-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    # aes_cbc
    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_1_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha1-96"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_1_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha1-96"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_1_101B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha1-96"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_256_101B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-256-128"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_384_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-384-192"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_384_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-384-192"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_384_101B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-384-192"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_128_sha_512_101B_c1(self):
        self.crypto_algo = "aes-cbc-128"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_192_sha_512_101B_c1(self):
        self.crypto_algo = "aes-cbc-192"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()

    def test_crypto_outbound_1tunnelsa_ar_on_aes_cbc_256_sha_512_101B_c1(self):
        self.crypto_algo = "aes-cbc-256"
        self.integ_algo = "sha-512-256"
        self.ipsec_outbound_setup()
        self.ipsec_outbound_run()
        self.ipsec_outbound_validate()


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
