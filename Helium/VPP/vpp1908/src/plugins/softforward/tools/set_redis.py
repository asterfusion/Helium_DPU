from pathlib import Path

from optparse import Values
import redis
import os
import re
import argparse




def get_line(com):
    lines =os.popen(com).readlines()
    
    lines=[line.replace(" ","") for line in lines]
    lines=[line.strip() for line in lines]
    num=[]
    lines_new=[]
    for i in range(len(lines)):
    
        n = lines[i].find("dst-map")
   
        if n != -1:
            num.append(i)
    for i in num:
         lines_new.append(lines[i])
    return lines_new




def line_dst(lines):
    dst =[]
    i = 0
    for i  in range(len(lines)):
   
        str1 = re.split("dst|dst-map|forward|modify-src|\(hit\)",lines[i])
        
        dst.append(str1[1])
    
    return dst



def line_dst_map(lines):
    dst_map =[]
    i = 0
    for i  in range(len(lines)):
   
        str1 = re.split("dst|dst-map|forward|modify-src|\(hit\)",lines[i])
        
        dst_map.append(str1[2][4:])
    
    return dst_map


def line_eth(lines):
    eth=[]
    i = 0
    for i in range(len(lines)):
   
        str1 = re.split("dst|dst-map|forward|modify-src|\(hit\)",lines[i])
        str2 = "Ethernet{}".format(str1[3])
        eth.append(str2)
    
    return eth



def line_dst_map_init(lines):
    ip=[]

    for i in range(len(lines)):
        str1 = re.split("dst-map|forward|src-modify",lines[i]) 
        
        ip.append(str1[2])
    
    return ip


def line_eth_init(lines):
    eth=[]

    for i in range(len(lines)):
        str1 = re.split("dst-map|forward|src-modify",lines[i])
        str2 = "Ethernet{}".format(str1[3])
        eth.append(str2)
    
    return eth


def hgetRedis(key):
    value = myRedis.hgetall(key)
    
    return value


def searchEth(eth_input,eth_line,key,nexthop,vrf,i_vrf=None):
    num =0

    for i in range(len(eth_line)):
       
        if eth_input == eth_line[i]:
            if i_vrf == None:
                new_key="ROUTE_TABLE|default|{}/32".format(key[i])
                
            else:
                new_key="ROUTE_TABLE|{}|{}/32".format(i_vrf,key[i])
               
            myRedis.hmset(new_key,{"distance":"","bfd":"disable","nexthop":nexthop,"local_addr":"","multihop":"disable","vrf":vrf,"ifname":eth_line[i]})
            route = hgetRedis(new_key)
            print("Add successfully\n","key="+new_key+"\n","value="+str(route)+"\n")
            num +=1

    if num ==0:
        print ("No match,add unsuccessfully")





parser = argparse.ArgumentParser()
parser.add_argument("init",default=None,choices=["init","sync"],help="是否为初始化路由，选择init或者sync")
parser.add_argument("redis",help="redis地址")
parser.add_argument("nexthop",help="nexthop")
parser.add_argument("ifname",help="ifname")

parser.add_argument("-vrf",help="vrf",default="")
parser.add_argument("-i_vrf",help="ingress_vrf",default=None)

args = parser.parse_args()
is_init = args.init
redis_ip=args.redis
nexthop =args.nexthop
ifname = "Ethernet{}".format(args.ifname)
vrf = args.vrf
ingress_vrf = args.i_vrf




pool = redis.ConnectionPool(host=redis_ip, 
                            port=6379,
                            db=4,
                            decode_responses=True)
myRedis = redis.StrictRedis(connection_pool=pool)







if is_init=="init":
    lines=get_line("cat /etc/vpp/init_softforward.cmd")  
    dst_map_init=line_dst_map_init(lines)
    eth_init=line_eth_init(lines)
    searchEth(ifname,eth_init,dst_map_init,nexthop,vrf)
else:
    if ingress_vrf==None:
        print("缺少ingress_vrf")
    else:
        lines=get_line("vppctl softforward show mapping all hit")
        dst_map_sync= line_dst_map(lines)
        dst_sync=line_dst(lines)
        eth_sync= line_eth(lines)
        searchEth(ifname,eth_sync,dst_sync,nexthop,vrf,ingress_vrf)
        
    