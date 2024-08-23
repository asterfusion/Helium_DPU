import os
import sys

if sys.version_info >= (3, 0):
    from configparser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser


class OtxTunnelParams:
    def __init__(self):
        pass


class OtxTestCaseConfig:
    def otx_read_config(self):
        parser = SafeConfigParser()
        pcie_parser = SafeConfigParser()
        path = os.getenv("TEST_DIR")
        parser.read("%s/configs/unittest.ini" % path)
        pcie_parser.read("%s/configs/pcie.ini" % path)
        self.lbk1_bdf = pcie_parser.get("default", "lbk1_bdf")
        self.lbk2_bdf = pcie_parser.get("default", "lbk2_bdf")
        self.lbk3_bdf = pcie_parser.get("default", "lbk3_bdf")
        self.lbk4_bdf = pcie_parser.get("default", "lbk4_bdf")
        self.inl1_bdf = pcie_parser.get("default", "inl1_bdf")
        self.crypto_bdf = pcie_parser.get("default", "crypto1_bdf")
        self.crypto_bdf_2 = pcie_parser.get("default", "crypto2_bdf")
        self.sched_bdf = pcie_parser.get("default", "event1_bdf")
        self.sched_bdf_2 = pcie_parser.get("default", "event2_bdf")
        self.lbk1_ip = parser.get("default", "lbk1_ip")
        self.lbk2_ip = parser.get("default", "lbk2_ip")
        self.lbk3_ip = parser.get("default", "lbk3_ip")
        self.lbk4_ip = parser.get("default", "lbk4_ip")
        self.lbk1_intf_name = parser.get("default", "lbk1_intf_name")
        self.lbk4_intf_name = parser.get("default", "lbk4_intf_name")
        dut_instance = parser.get("default", "dut_instance")
        igw_instance = parser.get("default", "igw_instance")

        self.dut_instance = os.getenv("DUT_INSTANCE", dut_instance)
        self.igw_instance = os.getenv("IGW_INSTANCE", igw_instance)

        self.aes_gcm_128_crypto_key = parser.get("default", "aes_gcm_128_crypto_key")

        # aes-gcm
        self.outbound.ipsec_aes_gcm_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_GCM_128_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_gcm_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_GCM_128_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_gcm_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_GCM_192_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_gcm_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_GCM_192_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_gcm_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_GCM_256_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_gcm_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_GCM_256_CRYPTO_KEY"
        )
        # aes-cbc
        self.outbound.ipsec_aes_cbc_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CBC_128_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_cbc_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CBC_128_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_cbc_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CBC_192_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_cbc_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CBC_192_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_cbc_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CBC_256_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_cbc_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CBC_256_CRYPTO_KEY"
        )
        # aes-ctr
        self.outbound.ipsec_aes_ctr_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CTR_128_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_ctr_128_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CTR_128_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_ctr_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CTR_192_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_ctr_192_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CTR_192_CRYPTO_KEY"
        )
        self.outbound.ipsec_aes_ctr_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_AES_CTR_256_CRYPTO_KEY"
        )
        self.inbound.ipsec_aes_ctr_256_crypto_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_AES_CTR_256_CRYPTO_KEY"
        )
        # sha1-96
        self.outbound.ipsec_sha1_96_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_SHA1_96_INTEG_KEY"
        )
        self.inbound.ipsec_sha1_96_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_SHA1_96_INTEG_KEY"
        )
        # sha-256-96
        self.outbound.ipsec_sha_256_96_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_SHA_256_96_INTEG_KEY"
        )
        self.inbound.ipsec_sha_256_96_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_SHA_256_96_INTEG_KEY"
        )
        # sha-256-128
        self.outbound.ipsec_sha_256_128_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_SHA_256_128_INTEG_KEY"
        )
        self.inbound.ipsec_sha_256_128_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_SHA_256_128_INTEG_KEY"
        )
        # sha-384-192
        self.outbound.ipsec_sha_384_192_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_SHA_384_192_INTEG_KEY"
        )
        self.inbound.ipsec_sha_384_192_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_SHA_384_192_INTEG_KEY"
        )
        # sha-512-256
        self.outbound.ipsec_sha_512_256_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_OUTBOUND_SHA_512_256_INTEG_KEY"
        )
        self.inbound.ipsec_sha_512_256_integ_key = parser.get(
            "ipsec", "DEF_IPSEC_INBOUND_SHA_512_256_INTEG_KEY"
        )

        self.tun_ip4_src = parser.get("ipsec", "DEF_IPSEC_TNL_LOCAL_IP4")
        self.tun_ip4_dst = parser.get("ipsec", "DEF_IPSEC_TNL_REMOTE_IP4")

    def __init__(self):
        self.outbound = OtxTunnelParams()
        self.inbound = OtxTunnelParams()
