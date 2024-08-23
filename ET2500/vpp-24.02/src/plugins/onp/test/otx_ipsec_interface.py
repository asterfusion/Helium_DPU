from vpp_ipsec import VppIpsecTunProtect, VppIpsecInterface
from vpp_ip_route import VppIpRoute, VppRoutePath
from otx_object import otx_update_local_register
from otx_object import otx_update_ipsec_into_local_register


class OtxIpsecInterface:
    def __init__(self, test):
        self.ipsec_intf = VppIpsecInterface(test)
        self.ipsec_intf.add_vpp_config()
        otx_update_local_register(test, self.ipsec_intf)
        self.ipsec_intf.admin_up()
        self.test = test
        self.tun_protect = None

    def add_route(self, ip):
        self.ipsecRoute = VppIpRoute(
            self.test, ip, 24, [VppRoutePath("0.0.0.0", self.ipsec_intf.sw_if_index)]
        )
        self.ipsecRoute.add_vpp_config()
        otx_update_local_register(self.test, self.ipsecRoute)

    def add_tun_protect(self, saOut, saIn=[]):
        self.tun_protect = VppIpsecTunProtect(self.test, self.ipsec_intf, saOut, saIn)
        self.tun_protect.add_vpp_config()
        otx_update_ipsec_into_local_register(self.test, self.tun_protect)

    def set_unnumbered(self, sw_index):
        self.ipsec_intf.set_unnumbered(sw_index)

    def remove_tun_protect(self):
        # if self.tun_protect != None:
        #    self.tun_protect.remove_vpp_config()
        self.tun_protect.remove_vpp_config()

    def remove_ipsec_interface(self):
        self.ipsecRoute.remove_vpp_config()
        self.ipsec_intf.remove_vpp_config()

    def remove_vpp_config(self):
        self.remove_tun_protect()
        self.remove_ipsec_interface()
