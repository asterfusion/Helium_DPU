"""
ICMP service implementation

Description:
    <FILL ME HERE>

How to use:
    <FILL ME HERE>

Author:
  Itay Marom 

"""
from .trex_service import Service, ServiceFilter
from ..trex_types import listify
from ..trex_exceptions import TRexError
from ..trex_vlan import VLAN

from scapy.layers.l2 import Ether, Dot1Q, Dot1AD
from scapy.layers.inet import IP, ICMP
from collections import defaultdict

import random

class ServiceFilterICMP(ServiceFilter):
    '''
        Service filter for ICMP services
    '''
    def __init__ (self):
        self.services = defaultdict(list)


    def add (self, service):
        # an ICMP service can be identified by src IP, identifier and seq
        self.services[(service.src_ip, service.id, service.seq, tuple(service.vlan))].append(service)
        
        
    def lookup (self, pkt):
        scapy_pkt = Ether(pkt)
        
        # not ICMP
        if 'ICMP' not in scapy_pkt:
            return []

        vlans = VLAN.extract(scapy_pkt)

        # ignore VLAN 0
        vlans = vlans if vlans != [0] else []
        
        src_ip = scapy_pkt['IP'].dst
        id     = scapy_pkt['ICMP'].id
        seq    = scapy_pkt['ICMP'].seq

        return self.services.get( (src_ip, id, seq, tuple(vlans)), [] )


    def get_bpf_filter (self):
        # a simple BPF pattern for ICMP (duplicate for QinQ)
        return 'icmp or (vlan and icmp) or (vlan and icmp)'


class ServiceICMP(Service):
    '''
        ICMP service - generate echo requests
    '''
    
    def __init__ (self, ctx, dst_ip, src_ip = None, pkt_size = 64, timeout_sec = 3, verbose_level = Service.ERROR, vlan = None):
        
        # init the base object
        super(ServiceICMP, self).__init__(verbose_level)
        
        if src_ip is None:
            src_ip = ctx.get_src_ipv4()
            if not src_ip:
                raise TRexError('PING: port {} does not have an IPv4 address. please manually provide source IPv4'.format(ctx.get_port_id()))

        self.src_ip      = src_ip
        self.dst_ip      = dst_ip
        self.vlan        = VLAN(vlan)
        
        self.pkt_size    = pkt_size
        self.timeout_sec = timeout_sec

        self.id  = random.getrandbits(16)
        self.seq = 0

        self.record = None


    def get_filter_type (self):
        return ServiceFilterICMP


    def run (self, pipe):
        '''
            Will execute ICMP echo request
        '''
        
        self.record = None
        
        self.log("ICMP: {:<15} ---> Pinging '{}'".format(self.src_ip, self.dst_ip))
        
        base_pkt = Ether()/IP(src = self.src_ip, dst = self.dst_ip)/ICMP(id = self.id, type = 8)
        self.vlan.embed(base_pkt)
        
        pad = max(0, self.pkt_size - len(base_pkt))
        pkt = base_pkt / ('x' * pad)
    
        # wait until packet was actually sent - to get the ts
        tx_info = yield pipe.async_tx_pkt(pkt)
        
        # wait for RX packet
        pkts = yield pipe.async_wait_for_pkt(time_sec = self.timeout_sec)
        if not pkts:
            # timeout - create an empty record
            self.record = self.PINGRecord()
            return
        
        # take the first one
        response = pkts[0]
        
        # parse record
        self.record = self.PINGRecord(Ether(response['pkt']), tx_info['ts'], response['ts'])

        # log and exit
        self.log('ICMP: {:<15} <--- {}'.format(self.src_ip, str(self.record)))
        return
                

    def get_record (self):
        return self.record


    class PINGRecord(object):
        TIMEOUT, UNREACHABLE, SUCCESS = range(3)

        ICMP_TYPE_ECHO_REPLY       = 0
        ICMP_TYPE_DEST_UNREACHABLE = 3
         
        def __init__ (self, scapy_pkt = None, tx_ts = None, rx_ts = None):
            
            # default values
            self.responder_ip = 'N/A'
            self.ttl          = 'N/A'
            self.rtt          = 'N/A'
            self.pkt_size     = 'N/A'
            self.state        = self.TIMEOUT

            if not scapy_pkt:
                return

            if scapy_pkt['ICMP'].type == self.ICMP_TYPE_ECHO_REPLY:
                self.responder_ip = scapy_pkt['IP'].src
                self.ttl          = scapy_pkt['IP'].ttl
                self.rtt          = (rx_ts - tx_ts) * 1000
                self.pkt_size     = len(scapy_pkt)
                self.state        = self.SUCCESS
                return


            if scapy_pkt['ICMP'].type == self.ICMP_TYPE_DEST_UNREACHABLE:
                self.responder_ip = scapy_pkt['IP'].src
                self.state        = self.ICMP_TYPE_DEST_UNREACBLE
                return


        def __str__ (self):

            if self.state == self.SUCCESS:
                return 'Reply from {0}: bytes={1}, time={2:.2f}ms, TTL={3}'.format(self.responder_ip, self.pkt_size, self.rtt, self.ttl)

            elif self.state == self.TIMEOUT:
                return 'Request timed out.'

            elif self.state == self.ICMP_TYPE_DEST_UNREACHABLE:
                return 'Reply from {0}: Destination host unreachable'.format(self.responder_ip)

            assert(0)

