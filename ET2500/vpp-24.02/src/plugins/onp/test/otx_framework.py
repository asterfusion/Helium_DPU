from vpp_interface import VppInterface
from otx_interface import OtxInterface
from vpp_ip_route import VppIpInterfaceAddress
from vpp_ip_route import VppIpTable, VppIpRoute
from vpp_ip_route import VppRoutePath, VppIpInterfaceBind
from vpp_neighbor import VppNeighbor
from ipaddress import IPv4Address, IPv4Network
from otx_ipsec_interface import OtxIpsecInterface
from otx_object import otx_update_local_register
from otx_object import otx_update_ipsec_into_local_register
from otx_debug import otx_ipsec_tun_stats
from vpp_papi import VppEnum
from enum import Enum, Flag


class OtxArch(Flag):
    _unknown = 0
    _96xx = 1
    _98xx = 2
    _10xx = 4


class OtxFeature(Flag):
    ROUTE_MODE_WITH_IPSEC_ITF = 1 << 0
    LOOKASIDE_IPSEC_MODE = 1 << 1
    INLINE_IPSEC_MODE = 1 << 2


ONP_MAX_HW_REASS_CONTEXTS = 2000
OTX_DEF_UDP_SPORT = 49152
OTX_DEF_UDP_DPORT = 49152


# TODO print system arch for each test case/suite
def findSystemArch():
    command = "cat /proc/cpuinfo"
    info = subprocess.check_output(command, shell=True).decode().strip()
    cpu_part = ""
    for line in info.split("\n"):
        if "CPU part" in line:
            cpu_part = re.sub(".*CPU part.*: ", "", line, 1)
            break
    if cpu_part == "0x0b2":
        return OtxArch._96xx
    if cpu_part == "0x0b1":
        return OtxArch._98xx
    if cpu_part == "0xd49":
        return OtxArch._10xx

    return OtxArch._unknown


def otx_arch(arch):
    sysArch = findSystemArch()
    if arch & sysArch:
        return True
    return False


otxArchModel96xx = otx_arch(OtxArch._96xx)
otxArchModel98xx = otx_arch(OtxArch._98xx)
otxArchModel10xx = otx_arch(OtxArch._10xx)


def otx_log(test, field1="", field2="", field3=""):
    string = " --- " + field1
    if len(field2):
        string += ":" + field2
    if len(field3):
        string += ":" + field3
    test.logger.info(string)


def set_feature(test, feature):
    if hasattr(test, "feature_list"):
        test.feature_list |= feature
    else:
        test.feature_list = feature


def is_feature_set(test, feature):
    if hasattr(test, "feature_list"):
        if test.feature_list & feature:
            return True
    return False


def get_esn_status(self):
    esn = os.getenv("ESN")
    if esn == "ON":
        return True
    else:
        return False


def async_crypto_setup(self):
    rep = self.vapi.cli("set ipsec async mode on")
    self.vapi.ipsec_select_backend(VppEnum.vl_api_ipsec_proto_t.IPSEC_API_PROTO_ESP, 0)


def otx_verify_ipsec_backend(test, backend):
    status = False
    rep = test.vapi.ipsec_backend_dump()
    for i in range(0, len(rep)):
        if rep[i].name == backend and rep[i].active is True:
            status = True
    return status


def otx_ipsec_compare(test, sa, ipsecObj):
    if sa.crypto_algorithm != ipsecObj.cryptoAlg:
        test.logger.info(
            "ERROR: ipsec setup compare: crypto algorithm "
            + str(sa.crypto_algorithm)
            + " differ from "
            + str(ipsecObj.cryptoAlg)
        )
        return False

    if sa.integrity_algorithm != ipsecObj.integAlg:
        test.logger.info(
            "ERROR: ipsec setup compare: integrity algorithm "
            + str(sa.integrity_algorithm)
            + " differ from "
            + str(ipsecObj.integAlg)
        )
        return False

    if not sa.flags & ipsecObj.flags:
        test.logger.info(
            "ERROR: ipsec setup compare: flag "
            + str(sa.flags)
            + " doesnt contain "
            + str(ipsecObj.flags)
        )
        return False

    if sa.crypto_key.data[: sa.crypto_key.length] != ipsecObj.cryptoKey:
        test.logger.info(
            "ERROR: ipsec setup compare: crypto key "
            + str(sa.crypto_key.data[: sa.crypto_key.length])
            + " differ from "
            + str(ipsecObj.cryptoKey)
        )
        return False

    if sa.integrity_key.data[: sa.integrity_key.length] != ipsecObj.integKey:
        test.logger.info(
            "ERROR: ipsec setup compare: integrity key "
            + str(sa.integrity_key.data[: sa.integrity_key.length])
            + " differ from "
            + str(ipsecObj.integKey)
        )
        return False

    return True


def otx_verify_ipsec_setup(test, ipsecObj):
    sa_list = test.vapi.ipsec_sa_dump()
    ret = False
    sa_found = False

    for sa in sa_list:
        if sa.entry.sad_id == ipsecObj.saId and sa.entry.spi == ipsecObj.spiId:
            sa_found = True
            ret = otx_ipsec_compare(test, sa.entry, ipsecObj)
            # TODO: break here.

    if not sa_found:
        test.logger.info(
            "ERROR: ipsec setup compare: "
            "Could not find saId %d and spiId %d from sa list"
            % (ipsecObj.saId, ipsecObj.spiId)
        )

    return ret


def otx_verify_ipsec_tun_setup(test, ipsecOutObj, ipsecInObj=None):
    out_tun_found = False
    in_tun_found = True
    # if ipsecObj is route mode using itf interface, verify if tun created.
    tun_list = otx_ipsec_tun_stats(test, test.ipsecIntf)
    for tun in tun_list:
        # if ipsecOutObj is outbound, verify if outbound tunnel is created.
        if ipsecOutObj.is_outbound is True:
            if tun.tun.sa_out == ipsecOutObj.saId:
                out_tun_found = True
                break

    if ipsecInObj is not None:
        in_tun_found = False

        for tun in tun_list:
            # if ipsecInObj is inbound, verify if inbound tunnel is created.
            if ipsecInObj.is_outbound is False:
                for in_tun in tun.tun.sa_in:
                    if in_tun == ipsecInObj.saId:
                        in_tun_found = True
                        break

    return in_tun_found and out_tun_found


def otx_get_ipsec_replay_window_size():
    # NOTE: Replay window in hardware and onp differ.
    # Hence keeping the bigger size among them for the test cases
    return 1024


def otx_get_max_future_seq_number():
    return 1024


def otx_set_ipsec_sa_seq(test, saId, seq):
    string = "test ipsec sa " + str(saId) + " seq " + str(hex(seq))
    test.vapi.cli(string)
    return seq


def otx_is_onp_profile(test):
    if hasattr(test, "vpp_profile") and test.vpp_profile == "onp":
        return True
    else:
        return False


def otx_is_native_crypto_profile(test):
    if hasattr(test, "vpp_profile") and test.vpp_profile is "native_crypto":
        return True
    else:
        return False


def otx_is_dpdk_profile(test):
    if hasattr(test, "vpp_profile") and test.vpp_profile is "dpdk":
        return True
    else:
        return False


def otx_add_ip_addr_host_field(ip4_prefix, host):
    return str(IPv4Network(ip4_prefix, strict=False)[host])


def otx_update_ipsec_into_local_register(tc_obj, vpp_obj):
    if (
        hasattr(tc_obj, "update_ipsec_register")
        and tc_obj.update_ipsec_register is True
    ):
        tc_obj.local_register_ipsec_objs.append(vpp_obj)


def otx_update_local_register(tc_obj, vpp_obj):
    if hasattr(tc_obj, "update_register") and tc_obj.update_register is True:
        tc_obj.local_register.append(vpp_obj)


def otx_get_sw_if_index(test, intfName):
    intfDump = test.vapi.sw_interface_dump(name_filter_valid=True, name_filter=intfName)
    return intfDump[0].sw_if_index


def otx_get_mac(test, sw_if_index):
    macAddr = test.vapi.api(
        test.vapi.sw_interface_get_mac_address, {"sw_if_index": sw_if_index}
    ).mac_address
    return macAddr


def otx_set_onp_profile(test):
    test.physmem_config = ["physmem", "{", "max-size", "4G", "}"]
    if otxArchModel10xx:
        if is_feature_set(test, OtxFeature.LOOKASIDE_IPSEC_MODE):
            test.onp_plugin_config = [
                "onp",
                "{",
                "dev",
                test.testConfig.lbk1_bdf,
                "dev",
                test.testConfig.lbk4_bdf,
                "dev crypto",
                test.testConfig.crypto_bdf,
                "dev sched",
                test.testConfig.sched_bdf,
                "ipsec",
                "{",
                "reassembly-wait-time",
                "5000",
                "}",
                "}",
            ]
        else:
            test.onp_plugin_config = [
                "onp",
                "{",
                "dev",
                test.testConfig.lbk1_bdf,
                "dev",
                test.testConfig.lbk4_bdf,
                "dev",
                test.testConfig.inl1_bdf,
                "dev crypto",
                test.testConfig.crypto_bdf,
                "dev sched",
                test.testConfig.sched_bdf,
                "ipsec",
                "{",
                "enable-inline-ipsec-outbound",
                "reassembly-wait-time",
                "5000",
                "}",
                "}",
            ]
    else:
        test.onp_plugin_config = [
            "onp",
            "{",
            "dev",
            test.testConfig.lbk1_bdf,
            "dev",
            test.testConfig.lbk4_bdf,
            "dev crypto",
            test.testConfig.crypto_bdf,
            "dev sched",
            test.testConfig.sched_bdf,
            "}",
        ]
    test.vpp_cmdline.extend(test.physmem_config)
    test.vpp_cmdline.extend(test.onp_plugin_config)
    test.vpp_profile = "onp"


def otx_set_native_crypto_profile(test):
    test.physmem_config = ["physmem", "{", "max-size", "4G", "}"]
    test.onp_plugin_config = [
        "onp",
        "{",
        "dev",
        test.testConfig.lbk1_bdf,
        "dev",
        test.testConfig.lbk4_bdf,
        "}",
    ]
    test.vpp_cmdline.extend(test.physmem_config)
    test.vpp_cmdline.extend(test.onp_plugin_config)
    test.vpp_profile = "native_crypto"


def otx_set_dut_profile(test):
    if test.testConfig.dut_instance == "onp":
        otx_set_onp_profile(test)
    else:
        otx_set_native_crypto_profile(test)
    test.logger.info("DUT VPP CMDLINE: %s" % test.vpp_cmdline)
    test.logger.info("DUT VPP PROFILE: %s" % test.vpp_profile)


def otx_setup_default_configuration(test):
    # create Ip Table 1
    test.ip_table = VppIpTable(test, table_id=1)
    test.ip_table.add_vpp_config()
    # configure loopback devices. Loop1 interface is set to tableId 1
    table_id = 0
    for i in test.lo_interfaces:
        i.admin_up()
        i.set_table_ip4(table_id)
        i.local_ip4_prefix_len = 24
        i.config_ip4()
        table_id += 1

    # get input and output ip, from loopback device ips.
    test.input_ip = otx_add_ip_addr_host_field(
        test.lo_interfaces[0].local_ip4_prefix, 10
    )
    test.output_ip = otx_add_ip_addr_host_field(
        test.lo_interfaces[1].local_ip4_prefix, 10
    )
    test.input_ip_prefix = test.lo_interfaces[0].local_ip4_prefix
    test.output_ip_prefix = test.lo_interfaces[1].local_ip4_prefix
    test.input_ip_prefix_len = test.lo_interfaces[0].local_ip4_prefix_len
    test.output_ip_prefix_len = test.lo_interfaces[1].local_ip4_prefix_len

    test.sw_if0_index = otx_get_sw_if_index(test, test.testConfig.lbk1_intf_name)
    test.sw_if1_index = otx_get_sw_if_index(test, test.testConfig.lbk4_intf_name)

    # create intf0 (eth0/lbk1)
    test.intf0 = OtxInterface(test)
    test.intf0.set_sw_if_index(test.sw_if0_index)
    test.intf0.admin_up()
    if_addr0 = VppIpInterfaceAddress(test, test.intf0, test.testConfig.lbk1_ip, 24)
    if_addr0.add_vpp_config()
    # create intf1 (eth1/lbk4). And bind intf1 to table id 1
    test.intf1 = OtxInterface(test)
    test.intf1.set_sw_if_index(test.sw_if1_index)
    test.intf1.admin_up()
    intf1_bind = VppIpInterfaceBind(test, test.intf1, test.ip_table)
    intf1_bind.add_vpp_config()
    if_addr1 = VppIpInterfaceAddress(
        test, test.intf1, test.testConfig.lbk4_ip, 24, bind=intf1_bind
    )
    if_addr1.add_vpp_config()

    # add route, to route test.output_ip/24 traffic
    # via intf0(lbk1) to igw instance
    route = VppIpRoute(
        test, test.output_ip, 24, [VppRoutePath("0.0.0.0", test.intf0.sw_if_index)]
    )
    route.add_vpp_config()

    # add route, to route test.input_ip/24 traffic
    # via intf1(lbk4) to igw instance
    route = VppIpRoute(
        test,
        test.input_ip,
        24,
        [VppRoutePath("0.0.0.0", test.intf1.sw_if_index)],
        table_id=1,
    )
    route.add_vpp_config()

    lbk1_neighbor_mac = otx_get_mac(test.igw, test.igw.sw_if0_index)
    lbk4_neighbor_mac = otx_get_mac(test.igw, test.igw.sw_if1_index)

    # set neighbor for tunnel dst ip (for ipsec packets).
    # To send packet towards igw, via intf0(eth0/lbk1)
    VppNeighbor(
        test, test.sw_if0_index, lbk1_neighbor_mac, test.testConfig.lbk2_ip
    ).add_vpp_config()
    # set neighbor for traffic dst ip (for plain packets).
    # To send packet towards igw, via intf1(eth1/lbk4)
    # prepare range of dst ips.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.sw_if0_index,
            lbk1_neighbor_mac,
            otx_add_ip_addr_host_field(test.output_ip_prefix, i),
        ).add_vpp_config()
        VppNeighbor(
            test,
            test.sw_if1_index,
            lbk4_neighbor_mac,
            otx_add_ip_addr_host_field(test.input_ip_prefix, i),
        ).add_vpp_config()

    # configure pg interfaces. Bind pg0 to loop0 and pg1 to loop1.
    # And add pg1 interface to table id 1
    test.pg0.admin_up()
    test.pg0.set_unnumbered(test.lo_interfaces[0].sw_if_index)
    test.pg1.admin_up()
    test.pg1.set_table_ip4(1)
    test.pg1.set_unnumbered(test.lo_interfaces[1].sw_if_index)

    # set neighbor for traffic dst ip.
    # To send packet out of dut vpp via pg1 interface.
    # This will help to receive packet in pg1 get_capture function.
    # the provided mac is invalid one.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.pg1.sw_if_index,
            "de:ad:00:00:00:08",
            otx_add_ip_addr_host_field(test.output_ip_prefix, i),
        ).add_vpp_config()

    # set neighbor for traffic dst ip.
    # To send packet out of dut vpp via pg0 interface.
    # This will help to receive packet in pg0 get_capture function.
    # the provided mac is invalid one.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.pg0.sw_if_index,
            "de:ad:00:00:00:09",
            otx_add_ip_addr_host_field(test.input_ip_prefix, i),
        ).add_vpp_config()


def otx_cleanup_ipsec_setup(test):
    for obj in reversed(test.local_register_ipsec_objs):
        obj.remove_vpp_config()
    test.local_register_ipsec_objs = []


def otx_tearDown_default_configuration(test):
    # if hasattr(test, 'ipsecIntf'):
    #    test.ipsecIntf.remove_vpp_config()

    # remove binding between pg0-loop0 and pg1-loop1
    test.pg1.unset_unnumbered(test.lo_interfaces[1].sw_if_index)
    test.pg0.unset_unnumbered(test.lo_interfaces[0].sw_if_index)

    for i in test.pg_interfaces:
        i.unconfig_ip4()
        i.set_table_ip4(0)
        i.admin_down()

    # remove loopback interface configuration
    for i in test.lo_interfaces:
        i.unconfig_ip4()
        i.set_table_ip4(0)
        i.admin_down()


def otx_setup_routemode_configuration(test):
    # create Ip Table 1
    test.ip_table = VppIpTable(test, table_id=1)
    test.ip_table.add_vpp_config()
    # configure loopback devices. Loop1 interface is set to tableId 1
    table_id = 0
    for i in test.lo_interfaces:
        i.admin_up()
        i.set_table_ip4(table_id)
        i.local_ip4_prefix_len = 24
        i.config_ip4()
        table_id += 1

    # get input and output ip, from loopback device ips.
    test.input_ip = otx_add_ip_addr_host_field(
        test.lo_interfaces[0].local_ip4_prefix, 10
    )
    test.output_ip = otx_add_ip_addr_host_field(
        test.lo_interfaces[1].local_ip4_prefix, 10
    )
    test.input_ip_prefix = test.lo_interfaces[0].local_ip4_prefix
    test.output_ip_prefix = test.lo_interfaces[1].local_ip4_prefix
    test.input_ip_prefix_len = test.lo_interfaces[0].local_ip4_prefix_len
    test.output_ip_prefix_len = test.lo_interfaces[1].local_ip4_prefix_len

    test.sw_if0_index = otx_get_sw_if_index(test, test.testConfig.lbk1_intf_name)
    test.sw_if1_index = otx_get_sw_if_index(test, test.testConfig.lbk4_intf_name)

    # create intf0 (eth0/lbk1)
    test.intf0 = OtxInterface(test)
    test.intf0.set_sw_if_index(test.sw_if0_index)
    test.intf0.admin_up()
    if_addr0 = VppIpInterfaceAddress(test, test.intf0, test.testConfig.lbk1_ip, 24)
    if_addr0.add_vpp_config()
    # create intf1 (eth1/lbk4). And bind intf1 to table id 1
    test.intf1 = OtxInterface(test)
    test.intf1.set_sw_if_index(test.sw_if1_index)
    test.intf1.admin_up()
    intf1_bind = VppIpInterfaceBind(test, test.intf1, test.ip_table)
    intf1_bind.add_vpp_config()
    if_addr1 = VppIpInterfaceAddress(
        test, test.intf1, test.testConfig.lbk4_ip, 24, bind=intf1_bind
    )
    if_addr1.add_vpp_config()

    test.ipsecIntf = OtxIpsecInterface(test)
    test.ipsecIntf.set_unnumbered(test.sw_if0_index)
    test.ipsecIntf.add_route(test.output_ip)

    # add route, to route test.input_ip/24 traffic
    # via intf1(lbk4) to igw instance
    route = VppIpRoute(
        test,
        test.input_ip,
        24,
        [VppRoutePath("0.0.0.0", test.intf1.sw_if_index)],
        table_id=1,
    )
    route.add_vpp_config()

    lbk1_neighbor_mac = otx_get_mac(test.igw, test.igw.sw_if0_index)
    lbk4_neighbor_mac = otx_get_mac(test.igw, test.igw.sw_if1_index)

    # set neighbor for tunnel dst ip (for ipsec packets).
    # To send packet towards igw, via intf0(eth0/lbk1)
    VppNeighbor(
        test, test.sw_if0_index, lbk1_neighbor_mac, test.testConfig.lbk2_ip
    ).add_vpp_config()

    # set neighbor for traffic dst ip (for plain packets).
    # To send packet towards igw, via intf1(eth1/lbk4)
    # prepare range of dst ips.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.sw_if1_index,
            lbk4_neighbor_mac,
            otx_add_ip_addr_host_field(test.input_ip_prefix, i),
        ).add_vpp_config()

    # configure pg interfaces. Bind pg0 to loop0 and pg1 to loop1.
    # And add pg1 interface to table id 1
    test.pg0.admin_up()
    test.pg0.set_unnumbered(test.lo_interfaces[0].sw_if_index)
    test.pg1.admin_up()
    test.pg1.set_table_ip4(1)
    test.pg1.set_unnumbered(test.lo_interfaces[1].sw_if_index)

    # set neighbor for traffic dst ip. To send
    # packet out of dut vpp via pg1 interface.
    # This will help to receive packet in pg1 get_capture function.
    # the provided mac is invalid one.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.pg1.sw_if_index,
            "de:ad:00:00:00:08",
            otx_add_ip_addr_host_field(test.output_ip_prefix, i),
        ).add_vpp_config()

    # set neighbor for traffic dst ip.
    # To send packet out of dut vpp via pg0 interface.
    # This will help to receive packet in pg0 get_capture function.
    # the provided mac is invalid one.
    for i in range(10, 30):
        VppNeighbor(
            test,
            test.pg0.sw_if_index,
            "de:ad:00:00:00:09",
            otx_add_ip_addr_host_field(test.input_ip_prefix, i),
        ).add_vpp_config()
