from trex.stl.trex_stl_hltapi import STLHltStream


class STLS1(object):
    '''
    Two Eth/IP/UDP streams with VM to get different size of packet by l3_length
    '''

    def get_streams (self, direction = 0, **kwargs):
        return [STLHltStream(length_mode = 'increment',
                             l3_length_min = 100,
                             l3_length_max = 3000,
                             l3_protocol = 'ipv4',
                             l4_protocol = 'udp',
                             rate_bps = 1000000,
                             direction = direction,
                             ),
                STLHltStream(length_mode = 'decrement',
                             l3_length_min = 100,
                             l3_length_max = 3000,
                             l3_protocol = 'ipv4',
                             l4_protocol = 'udp',
                             rate_bps = 1000000,
                             direction = direction,
                             )
               ]
               

# dynamic load - used for trex console or simulator
def register():
    return STLS1()



