from otx_framework import otx_add_ip_addr_host_field
from otx_framework import otx_update_local_register
from otx_framework import otx_update_ipsec_into_local_register
from vpp_ipsec import VppIpsecSpd, VppIpsecSA
from vpp_ipsec import VppIpsecSpdItfBinding
from vpp_ipsec import VppIpsecSpdEntry
from vpp_papi import VppEnum
from ipaddress import ip_address
from otx_test_configs import OtxTestCaseConfig
from otx_igw import otx_is_igw_instance
import binascii


class OtxIpsecObj:
    def __init__(
        self,
        test,
        spd,
        saId,
        spiId,
        intf=None,
        integAlg=None,
        cryptoAlg=None,
        outbound=True,
        tunnel=True,
        uplink=True,
        antiReplay=True,
        esn=False,
    ):
        testConfig = OtxTestCaseConfig()
        testConfig.otx_read_config()

        self.test = test
        self.spd = spd
        self.saId = saId
        self.spiId = spiId
        self.intf = intf
        self.proto = VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP
        self.is_outbound = outbound
        integ_alg = VppEnum.vl_api_ipsec_integ_alg_t
        self.integAlg = integ_alg.IPSEC_API_INTEG_ALG_NONE
        self.integKey = b""
        crypto_alg = VppEnum.vl_api_ipsec_crypto_alg_t
        self.cryptoAlg = crypto_alg.IPSEC_API_CRYPTO_ALG_NONE
        self.cryptoKey = b""
        self.flags = 0

        self.ipsec_sa = []
        self.ipsec_spd = {}

        self.cryptoAlg = self.otx_get_crypto_alg_api(cryptoAlg)
        self.integAlg = self.otx_get_integ_alg_api(integAlg)

        if (not otx_is_igw_instance(test) and outbound) or (
            otx_is_igw_instance(test) and not outbound
        ):
            self.cryptoKey = self.otx_get_crypto_key(cryptoAlg, testConfig.outbound)

        if (not otx_is_igw_instance(test) and not outbound) or (
            otx_is_igw_instance(test) and outbound
        ):
            self.cryptoKey = self.otx_get_crypto_key(cryptoAlg, testConfig.inbound)

        if (not otx_is_igw_instance(test) and outbound) or (
            otx_is_igw_instance(test) and not outbound
        ):
            self.integKey = self.otx_get_integ_key(integAlg, testConfig.outbound)

        if (not otx_is_igw_instance(test) and not outbound) or (
            otx_is_igw_instance(test) and outbound
        ):
            self.integKey = self.otx_get_integ_key(integAlg, testConfig.inbound)

        sad_flag = VppEnum.vl_api_ipsec_sad_flags_t
        if not otx_is_igw_instance(test):
            if not uplink:
                self.flags = sad_flag.IPSEC_API_SAD_FLAG_IS_INBOUND
        else:
            if uplink:
                self.flags = sad_flag.IPSEC_API_SAD_FLAG_IS_INBOUND

        if tunnel:
            if uplink:
                self.tun_ip4_src = testConfig.tun_ip4_src
                self.tun_ip4_dst = testConfig.tun_ip4_dst
            else:
                self.tun_ip4_src = testConfig.tun_ip4_dst
                self.tun_ip4_dst = testConfig.tun_ip4_src

        if antiReplay:
            self.flags |= sad_flag.IPSEC_API_SAD_FLAG_USE_ANTI_REPLAY
        if esn:
            self.flags |= sad_flag.IPSEC_API_SAD_FLAG_USE_ESN

        # Create spd object
        self.spdObj = VppIpsecSpd(test, self.spd)
        self.spdObj.add_vpp_config()
        # otx_update_local_register(test, self.spdObj)
        otx_update_ipsec_into_local_register(test, self.spdObj)

        # Bind spd object to interface
        if self.intf is not None:
            intfBind = VppIpsecSpdItfBinding(test, self.spdObj, self.intf)
            intfBind.add_vpp_config()
            # otx_update_local_register(test, intfBind)
            otx_update_ipsec_into_local_register(test, intfBind)

    def otx_create_sa(self):
        # create ipsec SA object. And update in local register
        sa = VppIpsecSA(
            self.test,
            self.saId,
            self.spiId,
            self.integAlg,
            self.integKey,
            self.cryptoAlg,
            self.cryptoKey,
            self.proto,
            self.tun_ip4_src,
            self.tun_ip4_dst,
            self.flags,
        )
        sa.add_vpp_config()
        # otx_update_local_register(self.test, sa)
        otx_update_ipsec_into_local_register(self.test, sa)
        self.ipsec_sa.append(sa)
        return sa

    def otx_create_spd(
        self, srcStartIp, srcEndIp, dstStartIp, dstEndIp, policy="bypass"
    ):
        # create ipsec SPD object. And update in local register
        spd_action = VppEnum.vl_api_ipsec_spd_action_t
        if policy == "protect":
            spd = VppIpsecSpdEntry(
                self.test,
                self.spdObj,
                self.saId,
                srcStartIp,
                srcEndIp,
                dstStartIp,
                dstEndIp,
                proto=0,
                policy=spd_action.IPSEC_API_SPD_ACTION_PROTECT,
                is_outbound=self.is_outbound,
            )
            spd.add_vpp_config()
            # otx_update_local_register(self.test, spd)
            otx_update_ipsec_into_local_register(self.test, spd)
            self.ipsec_spd["protect"] = spd
        elif policy == "bypass":
            spd = VppIpsecSpdEntry(
                self.test,
                self.spdObj,
                self.saId,
                srcStartIp,
                srcEndIp,
                dstStartIp,
                dstEndIp,
                proto=0,
                is_outbound=self.is_outbound,
            )
            spd.add_vpp_config()
            # otx_update_local_register(self.test, spd)
            otx_update_ipsec_into_local_register(self.test, spd)
            self.ipsec_spd["bypass"] = spd

    def otx_get_crypto_alg_api(self, cryptoAlg):
        crypto_alg = VppEnum.vl_api_ipsec_crypto_alg_t
        return {
            "aes-gcm-128": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_GCM_128,
            "aes-gcm-192": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_GCM_192,
            "aes-gcm-256": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_GCM_256,
            "aes-ctr-128": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CTR_128,
            "aes-ctr-192": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CTR_192,
            "aes-ctr-256": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CTR_256,
            "aes-cbc-128": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CBC_128,
            "aes-cbc-192": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CBC_192,
            "aes-cbc-256": crypto_alg.IPSEC_API_CRYPTO_ALG_AES_CBC_256,
            None: crypto_alg.IPSEC_API_CRYPTO_ALG_NONE,
        }[cryptoAlg]

    def otx_get_integ_alg_api(self, integAlg):
        integ_alg = VppEnum.vl_api_ipsec_integ_alg_t
        return {
            "sha1-96": integ_alg.IPSEC_API_INTEG_ALG_SHA1_96,
            "sha-256-96": integ_alg.IPSEC_API_INTEG_ALG_SHA_256_96,
            "sha-256-128": integ_alg.IPSEC_API_INTEG_ALG_SHA_256_128,
            "sha-384-192": integ_alg.IPSEC_API_INTEG_ALG_SHA_384_192,
            "sha-512-256": integ_alg.IPSEC_API_INTEG_ALG_SHA_512_256,
            None: integ_alg.IPSEC_API_INTEG_ALG_NONE,
        }[integAlg]

    def otx_get_crypto_key(self, cryptoAlg, config):
        return {
            "aes-gcm-128": config.ipsec_aes_gcm_128_crypto_key,
            "aes-gcm-192": config.ipsec_aes_gcm_192_crypto_key,
            "aes-gcm-256": config.ipsec_aes_gcm_256_crypto_key,
            "aes-ctr-128": config.ipsec_aes_ctr_128_crypto_key,
            "aes-ctr-192": config.ipsec_aes_ctr_192_crypto_key,
            "aes-ctr-256": config.ipsec_aes_ctr_256_crypto_key,
            "aes-cbc-128": config.ipsec_aes_cbc_128_crypto_key,
            "aes-cbc-192": config.ipsec_aes_cbc_192_crypto_key,
            "aes-cbc-256": config.ipsec_aes_cbc_256_crypto_key,
            None: "",
        }[cryptoAlg].encode("ascii")

    def otx_get_integ_key(self, integAlg, config):
        return {
            "sha1-96": config.ipsec_sha1_96_integ_key,
            "sha-256-96": config.ipsec_sha_256_96_integ_key,
            "sha-256-128": config.ipsec_sha_256_128_integ_key,
            "sha-384-192": config.ipsec_sha_384_192_integ_key,
            "sha-512-256": config.ipsec_sha_512_256_integ_key,
            None: "",
        }[integAlg].encode("ascii")
