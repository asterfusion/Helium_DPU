# How to use ovs/dpdk

## 1. update DPU to sdk12
1. Refer to Appendix C of the User Manual.

2. Download URL of busybox

    http://pan.asterfusion.com/index.php?mod=shares&sid=ZktTZEE2QkFwMG1qMWdJUng4aHlyT1FyeWNMM3ZxcWM2eldJYnlJRA

3. Download URL of OS installation package

    http://pan.asterfusion.com/index.php?mod=shares&sid=ZktTZEE2QkFwMG1qMWcwVW01OTQ4dUY2a3Nhc3ZLeVd1R0tJYVNZTQ

## 2. get driver
1. Refer to 7.1 of the User Manual

2.  You can first use 
        lsmod | grep octeon 
to check whether the driver already exists on the host.
If it does, you need to run rmmod first, wait for the NIC to finish restarting, and then run insmod again

##3. compile ovs/dpdk on DPU
1. complie dpdk
#### get dpdk source 
        git clone https://github.com/asterfusion/Helium_DPU/tree/main/ET3600/dpdk-24.11
#### compile dpdk
        export DPDK_DIR=/home/admin/Helium_DPU-main/ET3600/dpdk-24.11
   
        export DPDK_BUILD=$DPDK_DIR/build
        meson build
        ninja -C build
        ninja -C build install
        ldconfig    
        pkg-config --modversion libdpdk   //make sure dpdk installed succssfully
2. complie ovs
#### download ovs-3.6.1
#### compile ovs with dpdk
        cd openvswitch-3.6.1
        ./configure --with-dpdk=shared
        make 
        make install
3. insmod ovs driver on DPU
#### get driver
    http://pan.asterfusion.com/index.php?mod=shares&sid=ZktTZEE2QkFwMG1qMWc0V21wNHItdVo3bEpLdDdfdVM3R2FKYXlNTQ
#### insmod drivers
        insmod nsh.ko
        insmod openvswitch.ko
4. start ovs
        export PATH=$PATH:/usr/local/share/openvswitch/scripts

        sysctl -w vm.nr_hugepages=32 
        ovs-vsctl set Open_vSwitch . other_config:dpdk-init=true
        ovs-vsctl set Open_vSwitch . other_config:dpdk-socket-mem="1024"
        ovs-vsctl set Open_vSwitch . other_config:dpdk-lcore-list="0,1"

        ovs-ctl restart
5. dpdk bind
        ./dpdk-devbind.py -b vfio-pci 0002:02:00.0 0002:03:00.0 0002:0f:00.2 0002:0f:00.3
