import os
import time
import logging
import tempfile
from log import RED, GREEN, YELLOW
from log import double_line_delim, single_line_delim
from log import get_logger, colorize
from vpp_papi_provider import VppPapiProvider
from logging import FileHandler, DEBUG, Formatter
from threading import Thread, Event
from asfframework import pump_output
from framework import VppTestCase
from collections import deque
from vpp_object import VppObjectRegistry
import otx_framework as otxFw
from otx_interface import OtxInterface
from otx_object import otx_update_local_register
from vpp_ip_route import VppIpInterfaceAddress
from vpp_ip_route import VppIpTable, VppIpRoute
from vpp_ip_route import VppRoutePath, VppIpInterfaceBind
from vpp_neighbor import VppNeighbor
from vpp_ipsec import VppIpsecSpd, VppIpsecSpdItfBinding
from vpp_ipsec import VppIpsecSA, VppIpsecSpdEntry
from otx_ipsec_interface import OtxIpsecInterface
from vpp_papi import VppEnum

logger = logging.getLogger(__name__)


def otx_is_igw_instance(test):
    if hasattr(test, "otx_igw_instance") and test.otx_igw_instance is True:
        return True
    else:
        return False


class OtxIgw:
    def get_tempdir(cls):
        return tempfile.mkdtemp(prefix="vpp-unittest-%s-" % cls.__name__)

    def get_api_sock_path(cls):
        return "%s/api.sock" % cls.tempDir

    def setup(self, dut_vpp):
        self.dut_vpp_class = dut_vpp
        test = self.tc_obj

        lbk2_route_ip = otxFw.otx_add_ip_addr_host_field(
            self.dut_vpp_class.input_ip_prefix, 5
        )
        # lbk2 ip will be tunnel ip
        lbk2_ip = self.testConfig.lbk2_ip
        # lbk3 ip as x.x.x.5, where x is the same ip as dut vpp pg1(loop1)
        lbk3_ip = otxFw.otx_add_ip_addr_host_field(
            self.dut_vpp_class.output_ip_prefix, 5
        )

        # create intf0 object (lbk2)
        test.intf0 = OtxInterface(test)
        test.intf0.set_sw_if_index(self.sw_if0_index)
        test.intf0.admin_up()
        if_addr0 = VppIpInterfaceAddress(test, test.intf0, lbk2_ip, 24)
        if_addr0.add_vpp_config()
        otx_update_local_register(test, if_addr0)
        # create intf1 object (lbk3)
        test.intf1 = OtxInterface(test)
        test.intf1.set_sw_if_index(self.sw_if1_index)
        test.intf1.admin_up()
        if_addr1 = VppIpInterfaceAddress(test, test.intf1, lbk3_ip, 24)
        if_addr1.add_vpp_config()
        otx_update_local_register(test, if_addr1)

        if otxFw.is_feature_set(
            self.dut_vpp_class, otxFw.OtxFeature.ROUTE_MODE_WITH_IPSEC_ITF
        ):
            self.ipsecIntf = OtxIpsecInterface(test)
            self.ipsecIntf.set_unnumbered(self.sw_if0_index)
            self.ipsecIntf.add_route(lbk2_route_ip)
        else:
            route = VppIpRoute(
                test, lbk2_route_ip, 24, [VppRoutePath("0.0.0.0", self.sw_if0_index)]
            )
            route.add_vpp_config()
            otx_update_local_register(test, route)

        lbk2_neighbor_mac = otxFw.otx_get_mac(dut_vpp, dut_vpp.sw_if0_index)
        lbk3_neighbor_mac = otxFw.otx_get_mac(dut_vpp, dut_vpp.sw_if1_index)
        neighbor = VppNeighbor(
            test, self.sw_if0_index, lbk2_neighbor_mac, "192.168.1.1"
        )
        neighbor.add_vpp_config()
        otx_update_local_register(test, neighbor)
        # create vpp neighbors. Here we create neighbours from host 10 to 30.
        # And hence routable traffic destination could be between this range
        for i in range(10, 30):
            neighbor = VppNeighbor(
                test,
                self.sw_if1_index,
                lbk3_neighbor_mac,
                otxFw.otx_add_ip_addr_host_field(
                    self.dut_vpp_class.output_ip_prefix, i
                ),
            )
            neighbor.add_vpp_config()
            otx_update_local_register(test, neighbor)
            neighbor = VppNeighbor(
                test,
                self.sw_if0_index,
                lbk2_neighbor_mac,
                otxFw.otx_add_ip_addr_host_field(self.dut_vpp_class.input_ip_prefix, i),
            )
            neighbor.add_vpp_config()
            otx_update_local_register(test, neighbor)

        # Call vpp cmds to be applied on igw vpp
        for cmd in self.vpp_cmds:
            r = self.vapi.cli_return_response(cmd)
            if r.retval != 0:
                if hasattr(r, "reply"):
                    self.logger.info(cmd + " FAIL reply " + r.reply)
                else:
                    self.logger.info(cmd + " FAIL retval " + str(r.retval))

    def cleanup_ipsec_register(self):
        for obj in reversed(self.tc_obj.local_register_ipsec_objs):
            obj.remove_vpp_config()
        self.tc_obj.local_register_ipsec_objs = []

    def reset_stats(self):
        self.logger.info(self.vapi.ppcli("show run"))
        self.logger.info(self.vapi.ppcli("show interface"))
        self.logger.info(self.vapi.ppcli("show hardware"))
        self.logger.info(self.vapi.ppcli("show ipsec all"))
        self.logger.info(self.vapi.ppcli("show errors"))
        rep = self.vapi.cli("clear run")
        rep = self.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear errors")
        rep = self.vapi.cli("clear interfaces")
        rep = self.vapi.cli("clear trace")

    def tearDown(self):
        # TODO : add test case name for which teardown is called.
        self.logger.debug("--- tearDown() called ---")
        self.logger.debug(self.vapi.cli("show trace max 1000"))
        self.logger.info(self.vapi.ppcli("show run"))
        self.logger.info(self.vapi.ppcli("show interface"))
        self.logger.info(self.vapi.ppcli("show int feat eth0"))
        self.logger.info(self.vapi.ppcli("show int feat eth1"))
        self.logger.info(self.vapi.ppcli("show int address"))
        self.logger.info(self.vapi.ppcli("sh ip fib"))
        self.logger.info(self.vapi.ppcli("show hardware"))
        self.logger.info(self.vapi.ppcli("show ipsec all"))
        self.logger.info(self.vapi.ppcli("show errors"))
        self.cleanup_ipsec_register()
        for obj in reversed(self.tc_obj.local_register):
            obj.remove_vpp_config()
        self.tc_obj.local_register = []

    def quit(self):
        self.file_handler.close()
        self.pump_thread_stop_flag.set()
        os.write(self.pump_thread_wakeup_pipe[1], b"ding dong wake up")
        self.pump_thread.join()
        vpp_output = "".join(self.vpp_stdout_deque)
        with open(self.tempDir + "/vpp_stdout.txt", "w") as f:
            f.write(vpp_output)
        vpp_output = "".join(self.vpp_stderr_deque)
        with open(self.tempDir + "/vpp_stderr.txt", "w") as f:
            f.write(vpp_output)
        self.vpp.kill()

    def launch(self):
        self.vpp_bin = os.getenv("VPP_BIN", "vpp")
        c = os.getenv("CACHE_OUTPUT", "1")
        self.cache_vpp_output = False if c.lower() in ("n", "no", "0") else True
        self.igw_vpp_cmdline = [
            self.vpp_bin,
            "unix",
            "{",
            "nodaemon",
            "full-coredump",
            "runtime-dir",
            self.tempDir,
            "}",
            "api-trace",
            "{",
            "on",
            "}",
            "cpu",
            "{",
            "main-core",
            "0",
            "corelist-workers",
            "1",
            "}",
        ]
        api_fuzzing = "off"
        self.igw_vpp_cmdline.extend(
            [
                "physmem",
                "{",
                "max-size",
                self.physmem_max_size,
                "}",
                "socksvr",
                "{",
                "socket-name",
                self.get_api_sock_path(),
                "}",
                "node { ",
                "}",
            ]
        )

        self.igw_vpp_cmdline.extend(self.plugin_list)
        self.igw_vpp_cmdline.extend([""])

        self.igw_vpp_cmdline.extend(self.plugin_config)
        if hasattr(self, "buffer_size"):
            self.igw_vpp_cmdline.extend(
                ["buffers", "{", "default", "data-size", self.buffer_size, "}"]
            )

        self.vpp = subprocess.Popen(
            self.igw_vpp_cmdline, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        time.sleep(5)

        self.vpp_stdout_deque = deque()
        self.vpp_stderr_deque = deque()
        self.pump_thread_stop_flag = Event()
        self.pump_thread_wakeup_pipe = os.pipe()
        self.pump_thread = Thread(target=pump_output, args=(self,))
        self.pump_thread.daemon = True
        self.pump_thread.start()

        self.vapi = self.tc_obj.vapi = VppPapiProvider("igw_vpp", self, 5)
        self.vapi.connect()
        self.otx_prepare_igw_cmds()
        # Get interface index of lbk2 and lbk3.
        # To be used when creating interface object
        self.sw_if0_index = otxFw.otx_get_sw_if_index(self, "eth0")
        self.sw_if1_index = otxFw.otx_get_sw_if_index(self, "eth1")

    def otx_prepare_igw_cmds(self):
        self.vpp_cmds = ["trace add onp-pktio-input 1000"]

    def otx_set_native_crypto_igw_profile(self):
        self.native_crypto_plugin_list = [
            "plugins",
            "{",
            "plugin",
            "dpdk_plugin.so",
            "{",
            "disable",
            "}",
            "plugin",
            "onp_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "unittest_plugin.so",
            "{",
            "enable",
            "}",
            "}",
        ]
        self.native_crypto_plugin_config = [
            "onp",
            "{",
            "dev",
            self.testConfig.lbk2_bdf,
            "dev",
            self.testConfig.lbk3_bdf,
            "dev sched",
            self.testConfig.sched_bdf_2,
            "}",
        ]
        self.physmem_max_size = "4G"
        self.plugin_config = self.native_crypto_plugin_config
        self.plugin_list = self.native_crypto_plugin_list
        self.vpp_profile = "native_crypto"

    def otx_set_onp_igw_profile(self):
        self.onp_plugin_list = [
            "plugins",
            "{",
            "plugin",
            "dpdk_plugin.so",
            "{",
            "disable",
            "}",
            "plugin",
            "onp_plugin.so",
            "{",
            "enable",
            "}",
            "}",
        ]
        self.onp_plugin_config = [
            "onp",
            "{",
            "dev",
            self.testConfig.lbk2_bdf,
            "dev",
            self.testConfig.lbk3_bdf,
            "dev crypto",
            self.testConfig.crypto_bdf_2,
            "dev sched",
            self.testConfig.sched_bdf_2,
            "}",
        ]
        self.physmem_max_size = "4G"
        self.plugin_config = self.onp_plugin_config
        self.plugin_list = self.onp_plugin_list
        self.vpp_profile = "onp"

    def otx_set_dpdk_igw_profile(self):
        self.dpdk_plugin_list = [
            "plugins",
            "{",
            "plugin",
            "dpdk_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "rdma_plugin.so",
            "{",
            "disable",
            "}",
            "plugin",
            "lisp_unittest_plugin.so",
            "{",
            "enable",
            "}",
            "plugin",
            "unittest_plugin.so",
            "{",
            "enable",
            "}",
            "}",
        ]
        self.dpdk_plugin_config = [
            "dpdk",
            "{",
            "dev",
            self.testConfig.lbk2_bdf,
            "{",
            "name",
            "eth0",
            "}",
            "dev",
            self.testConfig.lbk3_bdf,
            "{",
            "name",
            "eth1",
            "}",
            "uio-driver",
            "vfio-pci",
            "}",
        ]

        self.physmem_max_size = "32m"
        self.plugin_config = self.dpdk_plugin_config
        self.plugin_list = self.dpdk_plugin_list
        self.vpp_profile = "dpdk"

    def otx_set_igw_profile(self, igw_instance):
        if igw_instance == "onp":
            self.otx_set_onp_igw_profile()
        elif igw_instance == "native_crypto":
            self.otx_set_native_crypto_igw_profile()
        else:
            self.otx_set_dpdk_igw_profile()

    def __init__(self, testClass):
        self.__name__ = "igw_vpp_%s" % testClass.__name__
        self.tempDir = self.get_tempdir()
        self.dut_vpp_class = testClass
        self.tc_obj = VppTestCase()
        self.otx_igw_instance = True
        self.tc_obj.registry = VppObjectRegistry()
        self.testConfig = testClass.testConfig
        self.logger = self.tc_obj.logger = get_logger("igw_vpp")

        self.file_handler = FileHandler("%s/log.txt" % self.tempDir)
        self.file_handler.setFormatter(
            Formatter(fmt="%(asctime)s,%(msecs)03d %(message)s", datefmt="%H:%M:%S")
        )
        self.file_handler.setLevel(DEBUG)
        self.logger.addHandler(self.file_handler)
        self.tc_obj.otx_igw_instance = True
        self.tc_obj.local_register = []
        self.tc_obj.local_register_ipsec_objs = []
        self.tc_obj.update_register = True
        self.tc_obj.update_ipsec_register = True

        self.otx_set_igw_profile(self.testConfig.igw_instance)
