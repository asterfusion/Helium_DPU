from trex.stl.trex_stl_hltapi import STLHltStream


class STLS1(object):
    '''
    Default Eth/802.1Q/IP/TCP stream without VM
    '''

    def get_streams (self, direction = 0, **kwargs):
        return STLHltStream(l2_encap = 'ethernet_ii_vlan',
                            l3_protocol = 'ipv4', l4_protocol = 'tcp',
                            direction = direction)

# dynamic load - used for trex console or simulator
def register():
    return STLS1()



