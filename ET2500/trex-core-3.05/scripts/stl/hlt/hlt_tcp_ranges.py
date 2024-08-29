from trex.stl.trex_stl_hltapi import STLHltStream


class STLS1(object):
    '''
    Eth/IP/TCP stream with VM to get 10 different TCP ports
    '''

    def get_streams (self, direction = 0, **kwargs):
        return STLHltStream(l3_protocol = 'ipv4',
                            l4_protocol = 'tcp',
                            tcp_src_port_mode = 'decrement',
                            tcp_src_port_count = 10,
                            tcp_src_port = 1234,
                            tcp_dst_port_mode = 'increment',
                            tcp_dst_port_count = 10,
                            tcp_dst_port = 1234,
                            name = 'test_tcp_ranges',
                            direction = direction,
                            rate_pps = 1,
                            )

# dynamic load - used for trex console or simulator
def register():
    return STLS1()



