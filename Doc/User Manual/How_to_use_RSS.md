## 1、configuration method

**The following configuration has been added to startup.conf to specify the RSS mode**

```
...

onp {
        dev default {
                num-rx-queues 22
                num-tx-queues 22
        }

        dev 0002:02:00.0

        dev 0002:03:00.0 {

                name C1
                rss src_ip

        }
        dev 0002:04:00.0 {
                name C2
                rss dst_ip
        }
}

...
```

the "rss src_ip" is a new addition, supporting any combination of src_ip, dst_ip, src_port, and dst_port. For example: rss src_ip dst_ip src_port dst_port

## 2、functional testing

### 2.1 networking

![image-20260529234302717](./rss_image/2_1_1)



### 2.2 Package distribution tool(python)

```
from scapy.all import Ether, IP, UDP, Dot1Q, sendp

src_mac = "00:10:94:00:00:06"
dst_mac = "60:eb:5a:01:6a:53"
src_ip = "88.1.1.1"
dst_ip = "99.1.1.1"
dscp_value = 20
src_port = 12345
dst_port = 54321
payload = "Hello VLAN UDP AAAAAAA"
for i in range(0, 20):
 for j in range(0, 10):
     payload += str(j)

pkt = Ether(src=src_mac, dst=dst_mac) / \
         IP(src=src_ip, dst=dst_ip, tos=(dscp_value << 2)) / \
         UDP(sport=src_port, dport=dst_port) / \
         payload

print("len = {0}".format(len(pkt)))
for x in range(0,10000):
 sendp(pkt, iface="eth2", verbose=False)
```



### 2.3 rss src_ip

Configure the RSS mode to src_ip, construct a packet, fix the dst_ip (99.1.1.1), src_port (12345), and dst_port (54321), and modify the src_ip

**src_ip 88.1.1.1**

![image-20260529234640097](.\rss_image\2_3_1)



**src_ip 89.1.1.1**

![image-20260529234835580](.\rss_image\2_3_2)



**src_ip 88.1.1.1,modify dst_ip,src_port,dst_port  ---always on vpp_wk_5**

**dst_ip 9.1.1.1**

![image-20260529235238190](.\rss_image\2_3_3)

**src_port 1234**

![image-20260529235441488](.\rss_image\2_3_4)

**dst_port 5432**

![image-20260529235612402](.\rss_image\2_3_5)



### 2.4 rss dst_ip

Configure the RSS mode to dst_ip, construct the packet, fix src_ip (88.1.1.1), src_port (12345), dst_port (54321), and modify dst_ip

**dst_ip 99.1.1.1**

![image-20260530000906575](.\rss_image\2_4_1)



**dst_ip 98.1.1.1**

![image-20260530001014551](.\rss_image\2_4_2)



dst_ip 99.1.1.1 modify src_ip, src_port, dst_port ----always on vpp_wk_4

![image-20260530000732463](.\rss_image\2_4_3)

### 2.5 rss src_port

Configure the RSS mode to src_port, construct a packet, fix the src_ip (88.1.1.1), dst_ip (99.1.1.1), and dst_port (54321), and modify the src_port

**src_port 12345**

![image-20260530001508226](.\rss_image\2_5_1)



**src_port 1234**

![image-20260530001732668](.\rss_image\2_5_2)



**src_port 12345, modify src_ip, dst_ip,dst_port  ---always on vpp_wk_7**

![image-20260530002018917](.\rss_image\2_5_3)



### 2.6 rss dst_port

Configure the RSS mode to dst_port, construct a packet, fix src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345), and modify dst_port

**dst_port 54321**

![image-20260530003312255](.\rss_image\2_6_1)



**dst_port 5432**

![image-20260530003443752](.\rss_image\2_6_2)



**dst_port 54321, modify src_ip, dst_ip,src_port  ---always on vpp_wk_2**

![image-20260530003645910](.\rss_image\2_6_3)



### 2.7 rss src_ip dst_ip src_port dst_port 

src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345)，dst_port(54321)

![image-20260530004024883](.\rss_image\2_7_1)

**modify src_ip**

![image-20260530004340649](.\rss_image\2_7_2)



**modify dst_ip**

![image-20260530004456023](.\rss_image\2_7_3)



**modify src_port**

![image-20260530004554539](.\rss_image\2_7_4)



**modify dst_port**

![image-20260530004647909](.\rss_image\2_7_5)



### 2.8 symmetric hash

src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345)，dst_port(54321)

![image-20260530004024883](.\rss_image\2_8_1)



Swap src_ip and dst_ip, swap src_port and dst_port, always on vpp_wk_20

![image-20260530005021250](.\rss_image\2_8_2)
