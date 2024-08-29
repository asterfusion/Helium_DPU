from trex_stl_lib.api import *
import argparse


def generate_payload(length):
      word = ''
      alphabet_size = len(string.ascii_letters)
      for i in range(length):
          word += string.ascii_letters[(i % alphabet_size)]
      return word


class STLS1(object):

    def create_stream (self):
        fsize_no_fcs = 129
        base_pkt_a = Ether()/IP()/IPv6()/IP(dst="48.0.0.1",options=IPOption(b'\x01\x01\x01\x00'))/UDP(dport=12,sport=1025)

        vm1 = STLScVmRaw([
                          STLVmFlowVar(name="src",min_value="16.0.0.1",max_value="16.0.0.10",size=4,op="inc"),
                          STLVmWrFlowVar(fv_name="src",pkt_offset= "IP:1.src"),
                           # checksum
                          STLVmFixIpv4(offset = "IP:1")

                         ]
                         ) # split to cores base on the tuple generator

        #
        pkt_a = STLPktBuilder(pkt=base_pkt_a/generate_payload(fsize_no_fcs-len(base_pkt_a)), vm=vm1)


        return STLStream( packet = pkt_a ,
                          mode = STLTXCont() )

    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args = parser.parse_args(tunables)
        # create 1 stream 
        return [ self.create_stream() ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



