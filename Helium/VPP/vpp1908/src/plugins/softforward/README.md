# 开发与使用手册
- [1. 文件结构](#文件结构) 
- [2. 编译](#编译) 
- [3. 快速使用](#快速使用) 
  - [3.1 命令行](#命令行) 
  - [3.2 配置文件](#配置文件)
  - [3.3 启动加载配置](#启动加载项)
  - [3.4 工具使用](#工具使用)
  - [3.5 整体使用：结合SONIC使用](#整体使用)


*此目录为softforward plugin源码目录*

---

## 文件结构

 - 基于AsterNOS-TWG的私有协议头处理
  > asic_priv.c    
  > asic_priv.h         
  > asic_priv_cli.c     
  > asic_priv_proc.c    

 - 基于软件转发相关处理
  > softforward.c       
  > softforward.h       
  > softforward_cli.c   
  > softforward_proc.c  

 - 基于其相关的配置文件和脚本工具
  > tools/set_redis.py
  > tools/startup.conf
  > tools/init_softforward.cmd

---

## 编译

### 使用已有的vpp代码

1. 将此目录放置在vpp源码目录src/plugin/路径下(src/plugin/softforward)
```bash
cp -r softforward  <VPP_PATH>/src/plugin/
```

2. 使用vpp提供的相关编译命令进行编译和打包
```bash
make build-release
make pkg-deb
##打包后目前在<VPP_PATH>/build-root路径下
```

3. 安装vpp
```bash
dpkg -i libvppinfa_*.deb
dpkg -i vpp_*.deb
dpkg -i vpp-dbg*.deb
dpkg -i vpp-plugin-core_*.deb
dpkg -i vpp-plugin-dpdk_*.deb
```

---
### 使用直接提供的vpp代码
**可以使用我们提供的docker镜像sy/vpp-compile-env:v1进行编译**

**如果不使用镜像，可自己搭建编译环境，此过程略** 

**以下为使用docker 镜像的编译步骤**

- Docker镜像安装与运行
```bash
##导入sy/vpp-compile-env:v1镜像
###解压sy-vpp-compile-env-img.tar.gz
tar zxvf sy-vpp-compile-env-img.tar.gz 
docker load < sy-vpp-compile-env-img.tar

##使用sy/vpp-compile-env:v1镜像创建docker实例vpp_compile
docker run -itd --name vpp_compile sy/vpp-compile-env:v1

##如果需要可以在docker实例中运行vpp+dpdk需在创建实例时额外添加以下参数：
docker run \
    -itd \
    --privileged \
    -v /sys/bus/pci/drivers:/sys/bus/pci/drivers \
    -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages \
    -v /sys/devices/system/node:/sys/devices/system/node \
    -v /dev:/dev \
    --name vpp_compile \
    --ulimit core=0:0 \
    sy/vpp-compile-env:v1

##将vpp原理上传到vpp_compile实例中
docker cp <VPP_PATH> vpp_compile:/root/

##进入vpp_compile实例中进行编译打包
docker exec -it vpp_compile bash
```

1. 编译安装vpp相关拓展依赖
```bash
cd <VPP_PATH>
make install-ext-deps
```

2. 使用vpp提供的相关编译命令进行编译和打包
```bash
make build-release
make pkg-deb
##打包后目前在<VPP_PATH>/build-root路径下
```

4. 安装vpp
```bash
##相关deb包在<VPP_PATH>/build-root路径下
dpkg -i libvppinfra_*.deb
dpkg -i vpp_*.deb
dpkg -i vpp-dbg*.deb
dpkg -i vpp-plugin-core_*.deb
dpkg -i vpp-plugin-dpdk_*.deb
```
---
## 快速使用
### 命令行
1. AsterNOS-TWG asic私有协议头处理
```bash
vppctl set interface asic-priv-proc  enable  <intfc>
vppctl set interface asic-priv-proc  disable <intfc>
#explain:
  # 1. intfc 为VPP中的interfaces
```

2. 软件转发相关处理
```bash
vppctl create softforward mapping name <name>
vppctl create softforward mapping name <name> del 

#explain:
 # 1. name 为mapping组的名称

vppctl show softforward mappings [detail]


vppctl softforward mapping name <name> add  dst <dst_ip> dst-map <dst-ip> forward <panel-ports>[ src-modify <src_ip>]
vppctl softforward mapping name <name> add dst <dst_ip> dst-map <dst-ip> forward <panel-ports> del

#explain:
  # 1. name 为mapping组的名称
  # 2. dst 为报文的原始目的IP地址
  # 3. dst-map 为报文映射后的目的IP地址
  # 4. forward 为实际设备的物理面板端口 (eg: 52 -> Ethernet52)
  # 5. 可选参数 src-modify 为报文映射后的源IP地址

vppctl softforward show mapping <name>
vppctl softforward show mapping all
vppctl softforward show mapping <name> hit
vppctl softforward show mapping all hit

vppctl softforward bind <intfc> mapping <name>
vppctl softforward bind <intfc> mapping <name> del
vppctl softforward show bind

#explain:
  # 1. intfc 为VPP中的interfaces
  # 2. name 为mapping组的名称
```

---
### 配置文件

参考tools/startup.conf

```file
unix {
  nodaemon
  log /var/log/vpp/vpp.log
  full-coredump
  cli-listen /run/vpp/cli.sock
  gid vpp
  exec /etc/vpp/init_softforward.cmd
}

api-trace {
  on
}

api-segment {
  gid vpp
}

socksvr {
  default
}

cpu {
        main-core 0
        corelist-workers 1
}

buffers {
        buffers-per-numa 524288
}

dpdk {
        dev default {
                num-rx-queues 1
                num-tx-queues 1
        }
        dev 0002:07:00.0 {
                name C1
        }
        dev 0002:02:00.0 {
                name C2
        }
        num-mbufs 262144
}

plugins {
    plugin default { disable }
        plugin dpdk_plugin.so { enable }
        plugin softforward_plugin.so { enable }
}
```

---
### 启动加载项

参考tools/init_softforward.cmd
使用时放置在/etc/vpp/目录下

```file
set interface state C1 up
set interface state C2 up

set interface promiscuous on C1
set interface promiscuous on C2

set interface asic-priv-proc enable C1
set interface asic-priv-proc enable C2

create softforward mapping name test1
softforward bind C1 mapping test1
softforward bind C2 mapping test1

softforward mapping name test1 add dst 1.2.3.1 dst-map 4.4.4.101 forward 52 src-modify 5.5.5.101
softforward mapping name test1 add dst 1.2.3.2 dst-map 4.4.4.102 forward 52 src-modify 5.5.5.102
softforward mapping name test1 add dst 1.2.3.3 dst-map 4.4.4.103 forward 52 src-modify 5.5.5.103
softforward mapping name test1 add dst 1.2.3.4 dst-map 4.4.4.104 forward 52 src-modify 5.5.5.104
softforward mapping name test1 add dst 1.2.3.5 dst-map 4.4.4.105 forward 52 src-modify 5.5.5.105
softforward mapping name test1 add dst 1.2.3.6 dst-map 4.4.4.106 forward 52 src-modify 5.5.5.106
softforward mapping name test1 add dst 1.2.3.7 dst-map 4.4.4.107 forward 52 src-modify 5.5.5.107
softforward mapping name test1 add dst 1.2.3.8 dst-map 4.4.4.108 forward 52 src-modify 5.5.5.108
softforward mapping name test1 add dst 1.2.3.9 dst-map 4.4.4.109 forward 52 src-modify 5.5.5.109
softforward mapping name test1 add dst 1.2.3.10 dst-map 4.4.4.110 forward 52 src-modify 5.5.5.110
```

---
### 工具使用

tools/set_redis.py

编译方式
```bash
pyinstaller -F set_redis.py
##编译后会在当前目录下生成dist目录
##最终文件为dist/set_redis
```

如何使用
```bash
./set_redis --help
usage: set_redis [-h] [-vrf VRF] [-i_vrf I_VRF]
                 {init,sync} redis nexthop ifname

positional arguments:
  {init,sync}   是否为初始化路由，选择init或者sync
  redis         redis地址
  nexthop       nexthop
  ifname        ifname

optional arguments:
  -h, --help    show this help message and exit
  -vrf VRF      vrf
  -i_vrf I_VRF  ingress_vrf

set_redis init <sonic ip> <nexthop ip> <ifname id> -v <vrf_name> -i_vrf <ingress_vrf>
#eg: ./set_redis init 192.168.100.100 4.4.4.10 52 -v Vnet100

./set_redis sync <sonic ip> <nexthop ip> <ifname id> -v <vrf_name> -i_vrf <ingress_vrf>
#eg: ./set_redis sync 192.168.100.100 4.4.4.10 52 -i_vrf Vnet100  -v Vnet100

```

---
### 整体使用

组网：
```
                                                |---------------|
                                                | GHC     vpp   |
                                                |---------------|
                                                     |      |
  |--------------------|             |---------------|------|------------|
  |  traffic-gen       |             |          Ethernet112 Ethernet116  |
  |                    |             |                                   |
  |dip 1.2.3.1-1.2.3.10|             |                                   |
  |               port1| <---------->| Ethernet48                        |
  |                    |             |                                   |
  |  (4.4.4.10/24)port2| <---------->| Ethernet52(4.4.4.100/24)          |
  |--------------------|             |-----------------------------------|
```


1. Sonic需要开放redis服务网段对设备内GHC扣卡使用

```bash
docker exec -it database bash
#修改配置文件中bind配置，添加192.168.100.100 GHC0 和 192.168.101.100 GHC1
vi /etc/redis/redis.conf
bind 192.168.100.100 192.168.101.100 127.0.0.1 ::1
:wq
exit
sudo reboot
```

2. 配置交换配置，让其没有命中路由策略的报文上送到GHC
```bash
sudo config vnet add Vnet100 --miss_data 100 
sudo config interface vnet bind Ethernet48  Vnet100     
sudo config interface vnet bind Ethernet52  Vnet100
sudo config ghcroute add Vnet100 0.0.0.0/0 1234 --reason vxlan
sudo config interface ghc Ethernet112 enable 
sudo config interface ghc Ethernet116 enable 
sudo config interface ip add Ethernet52 4.4.4.100/24

#explain:
  #  1. Ethernet48 和 Ethernet52为两个设备100G面板端口
  #  2. EThernet112 和 Ethernet116 为 GHC0扣卡和交换芯片连接的两个端口
  #  3. 给Ethernet52 配置ip地址，是其需要和对端邻居学习ip
  #  4. ghcroute 为默认上送GHC的路由规则策略, --reason 目前只支持nat和vxlan
```

3. GHC上使用启动VPP
```bash
echo 10 > /proc/sys/vm/nr_hugepages

./dpdk-devbind.py -b vfio-pci 0002:02:00.0 0002:07:00.0

vpp -c /etc/vpp/startup_softforward.conf &
```

4. GHC上使用tools/set_redis.py 初始化默认SONIC路由配置
```bash
./set_redis init 192.168.100.100 4.4.4.10 52 -v Vnet100
```

5. traffic-gen 发送目的ip为1.2.3.1-1.2.3.10的流量
```
流量没有路由的，上送GHC，GHC处理后，修改报文SIP和DIP后，返回给交换芯片，再根据默认的SONIC路由转发到Ethernet52端口
```

6. GHC是使用tools/set_redis.py 同步命中的映射规则到SONIC路由配置
```bash
./set_redis sync 192.168.100.100 4.4.4.10 52 -i_vrf Vnet100  -v Vnet100
```

7. traffic-gen 发送目的ip为1.2.3.1-1.2.3.10的流量
```
流量因为有了上一步同步的路由，直接转发到Ethernet52端口
```




