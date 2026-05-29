## 1、configuration method

**The following configuration has been added to startup.conf to specify the RSS mode**

...

onp {

​        dev default {
​                num-rx-queues 22
​                num-tx-queues 22
​        }

​        dev 0002:02:00.0

​        dev 0002:03:00.0 {

​                name C1

​                **rss src_ip**  ##rss src_ip dst_ip src_port dst_port

​        }
​        dev 0002:04:00.0 {
​                name C2
​                **rss dst_ip**   ##rss src_ip dst_ip src_port dst_port
​        }

}

...



## 2、functional testing

### 2.1 networking

![image-20260529234302717](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529234302717.png)



### 2.2 Package distribution tool(python)

> from scapy.all import Ether, IP, UDP, Dot1Q, sendp
>
> src_mac = "00:10:94:00:00:06"
> dst_mac = "60:eb:5a:01:6a:53"
> src_ip = "88.1.1.1"
> dst_ip = "99.1.1.1"
> dscp_value = 20
> src_port = 12345
> dst_port = 54321
> payload = "Hello VLAN UDP AAAAAAA"
> for i in range(0, 20):
>     for j in range(0, 10):
>         payload += str(j)
>
> pkt = Ether(src=src_mac, dst=dst_mac) / \
>             IP(src=src_ip, dst=dst_ip, tos=(dscp_value << 2)) / \
>             UDP(sport=src_port, dport=dst_port) / \
>             payload
>
> print("len = {0}".format(len(pkt)))
> for x in range(0,10000):
>     sendp(pkt, iface="eth2", verbose=False)

### 2.3 rss src_ip

Configure the RSS mode to src_ip, construct a packet, fix the dst_ip (99.1.1.1), src_port (12345), and dst_port (54321), and modify the src_ip

**src_ip 88.1.1.1**

![image-20260529234640097](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529234640097.png)



**src_ip 89.1.1.1**

![image-20260529234835580](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529234835580.png)



**src_ip 88.1.1.1,modify dst_ip,src_port,dst_port  ---always on vpp_wk_5**

**dst_ip 9.1.1.1**

![image-20260529235238190](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529235238190.png)

**src_port 1234**

![image-20260529235441488](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529235441488.png)

**dst_port 5432**

![image-20260529235612402](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260529235612402.png)



### 2.4 rss dst_ip

Configure the RSS mode to dst_ip, construct the packet, fix src_ip (88.1.1.1), src_port (12345), dst_port (54321), and modify dst_ip

**dst_ip 99.1.1.1**

![image-20260530000906575](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530000906575.png)



**dst_ip 98.1.1.1**

![image-20260530001014551](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530001014551.png)



dst_ip 99.1.1.1 modify src_ip, src_port, dst_port ----always on vpp_wk_4

![image-20260530000732463](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530000732463.png)

### 2.5 rss src_port

Configure the RSS mode to src_port, construct a packet, fix the src_ip (88.1.1.1), dst_ip (99.1.1.1), and dst_port (54321), and modify the src_port

**src_port 12345**

![image-20260530001508226](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530001508226.png)



**src_port 1234**

![image-20260530001732668](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530001732668.png)



**src_port 12345, modify src_ip, dst_ip,dst_port  ---always on vpp_wk_7**

![image-20260530002018917](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530002018917.png)



### 2.6 rss dst_port

Configure the RSS mode to dst_port, construct a packet, fix src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345), and modify dst_port

**dst_port 54321**

![image-20260530003312255](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530003312255.png)



**dst_port 5432**

![image-20260530003443752](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530003443752.png)



**dst_port 54321, modify src_ip, dst_ip,src_port  ---always on vpp_wk_2**

![image-20260530003645910](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530003645910.png)



### 2.7 rss src_ip dst_ip src_port dst_port 

src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345)，dst_port(54321)

![image-20260530004024883](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004024883.png)

**modify src_ip**

![image-20260530004340649](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004340649.png)



**modify dst_ip**

![image-20260530004456023](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004456023.png)



**modify src_port**

![image-20260530004554539](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004554539.png)



**modify dst_port**

![image-20260530004647909](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004647909.png)



### 2.8 symmetric hash

src_ip(88.1.1.1), dst_ip(99.1.1.1), src_port(12345)，dst_port(54321)

![image-20260530004024883](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530004024883.png)



Swap src_ip and dst_ip, swap src_port and dst_port, always on vpp_wk_20

![image-20260530005021250](C:\Users\cynth\AppData\Roaming\Typora\typora-user-images\image-20260530005021250.png)