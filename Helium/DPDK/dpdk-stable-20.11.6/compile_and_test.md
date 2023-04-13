# 编译

1. 第一次编译需要安装一些依赖的库和工具

   apt install python3 -y

   apt install python3-pip -y

   pip3 install --upgrade pip

   pip3 install meson ninja

2. cd dpdk-20.11/dpdk-stable-20.11.6

3. meson  build   (meson -Dbuildtype=debug build 编译debug版本)

   如果要编译具体的某个examples，这一步指定，比如要编译l2fwd和l3fwd，命令为：

   meson --reconfigure -Dexamples=l2fwd,l3fwd build   (注意：每次重新编译，都需要指定--reconfigure参数)

4. cd build

5. ninja

6. 编译完成之后，生成的examples路径为：dpdk-20.11/dpdk-stable-20.11.6/build/examples/dpdk-xxxx

7. app(testpmd等)默认是编译的，生成的可执行文件路径为：dpdk-20.11/dpdk-stable-20.11.6/build/app/dpdk-xxxx



# 环境设置(基于ET3000A)

## 设置大页

sysctl vm.nr_hugepages=20

## 绑定cptdev

cptdev主要用于加解密，当需要使用硬件进行加解密时，就需要绑定cptdev，绑定cptdev需要固件的支持，把对应的固件cpt02-mc.tar、cpt9x-mc.tar放到目录/lib/firmware下。

固件位置： [Browse SpekFabric / SF5000 - Git Repositoy (asterfusion.com)](https://git.asterfusion.com/projects/SF/repos/sf5000/browse/build-pkg/dpdk-setup/nf2000?at=refs%2Fheads%2FNF2000_V3.2R1) 

绑定方法：

lspci | grep "f9" | cut -d ' ' -f 1

echo 0 > /sys/bus/pci/devices/0002\:05\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:06\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:07\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:08\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:09\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:0a\:00.0/limits/cpt 

echo 0 > /sys/bus/pci/devices/0002\:0e\:00.0/limits/cpt 

echo 0002:10:00.0 > /sys/bus/pci/drivers/octeontx2-cpt/unbind

echo 64 > /sys/bus/pci/devices/0002\:10\:00.0/limits/cpt

echo 0002:10:00.0 > /sys/bus/pci/drivers/octeontx2-cpt/bind

 

\# To enable 2 VF devices

echo 2 > /sys/bus/pci/drivers/octeontx2-cpt/0002\:10\:00.0/kvf_limits

\#bind 1 vf devices

echo 1 > /sys/bus/pci/drivers/octeontx2-cpt/0002\:10\:00.0/sriov_numvfs

\#bind 1 vf to the dpdk 

./dpdk-devbind.py -b vfio-pci 0002:10:00.1   (dpdk-devbind.py文件就在dpdk源码里面，自行获取)

## 设置sso

当使用eventdev的时候，需要设置sso

echo 0 > /sys/bus/pci/devices/0002:05:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:06:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:07:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:08:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:09:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:0a:00.0/limits/sso

echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/sso

 

echo 0 > /sys/bus/pci/devices/0002:05:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:06:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:07:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:08:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:09:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:0a:00.0/limits/ssow

echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/ssow

 

echo 0 > /sys/bus/pci/devices/0002:0e:00.0/limits/tim

echo 1 > /sys/bus/pci/devices/0002:0e:00.0/limits/npa

echo 16 > /sys/bus/pci/devices/0002:0e:00.0/limits/sso

echo 46 > /sys/bus/pci/devices/0002:0e:00.0/limits/ssow

./dpdk-devbind.py -b vfio-pci 0002:0e:00.0

## 绑定ethdev

./dpdk-devbind.py -b vfio-pci 0002:03:00.0

./dpdk-devbind.py -b vfio-pci 0002:04:00.0

# 运行test

## testpmd

1. 单核：./dpdk-testpmd -l 0,1 -n 3 -a 0002:03:00.0 -a 0002:04:00.0 -- -i --nb 1 --rxq=1 --txq=1 --rxd=4096 --txd=4096
2. 多核(双核)：./dpdk-testpmd -l 0,1-2 -n 3 -a 0002:03:00.0 -a 0002:04:00.0 -- -i --nb 2 --rxq=2 --txq=2 --rxd=4096 --txd=4096

## l2fwd

1. 单核：./dpdk-l2fwd -l 0-1 -n 4 -a 0002:03:00.0 -a 0002:04:00.0 -- -q 8 -p 0x3 -T 0
2. 多核：./dpdk-l2fwd -l 0-22 -n 4 -w 0002:03:00.0 -w 0002:04:00.0 -- -q 8 -p 0x3 -T 0

## l2fwd-event

1. atomic：./dpdk-l2fwd-event -l 0-11 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -n 3 -- -p 0x3 --eventq-sched=atomic -T 0
2. ordered：./dpdk-l2fwd-event -l 0-11 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -n 3 -- -p 0x3 --eventq-sched=ordered -T 0
3. parallel：./dpdk-l2fwd-event -l 0-11 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -n 3 -- -p 0x3 --eventq-sched=parallel -T 0

## l3fwd

1. 单核：./dpdk-l3fwd -l 1 -n 3 -w 0002:03:00.0 -- -p 0x1 -P --config="(0,0,1)"
2. 22个核：./dpdk-l3fwd -l 1-22 -n 3 -w 0002:03:00.0 -- -p 0x1 -P --config="(0,0,1),(0,1,2),(0,2,3),(0,3,4),(0,4,5),(0,5,6),(0,6,7),(0,7,8),(0,8,9),(0,9,10),(0,10,11),(0,11,12),(0,12,13),(0,13,14),(0,14,15),(0,15,16),(0,16,17),(0,17,18),(0,18,19),(0,19,20),(0,20,21),(0,21,22)"

## l3fwd-event

1. atomic：./dpdk-l3fwd -l 0-12 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -- -p 0x3 -P --mode="eventdev" --eventq-sched=atomic
2. ordered：./dpdk-l3fwd -l 0-12 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -- -p 0x3 -P --mode="eventdev" --eventq-sched=ordered
3. parallel：./dpdk-l3fwd -l 0-12 -a 0002:03:00.0 -a 0002:04:00.0 -a 0002:0e:00.0 -- -p 0x3 -P --mode="eventdev" --eventq-sched=parallel

## ipsec-secgw

1. atomic：./ipsec-secgw -l 1-22 -w 0002:03:00.0,ipsec_in_max_spi=128 -w 0002:04:00.0,ipsec_in_max_spi=128 -w 0002:10:00.1 -w 0002:0e:00.0 --socket-mem 1024 -- -p 0xf -P -u 0x2 -f ./inline_cbc.cfg --transfer-mode event --event-schedule-type=atomic
2. ordered：./ipsec-secgw -l 1-22 -w 0002:03:00.0,ipsec_in_max_spi=128 -w 0002:04:00.0,ipsec_in_max_spi=128 -w 0002:10:00.1 -w 0002:0e:00.0 --socket-mem 1024 -- -p 0xf -P -u 0x2 -f ./inline_cbc.cfg --transfer-mode event --event-schedule-type=ordered
3. parallel：./ipsec-secgw -l 1-22 -w 0002:03:00.0,ipsec_in_max_spi=128 -w 0002:04:00.0,ipsec_in_max_spi=128 -w 0002:10:00.1 -w 0002:0e:00.0 --socket-mem 1024 -- -p 0xf -P -u 0x2 -f ./inline_cbc.cfg --transfer-mode event --event-schedule-type=parallel