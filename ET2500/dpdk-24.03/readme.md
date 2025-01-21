# How to build in ET2500
## install build depence package, such as libnuma-dev
```shell
   apt-get install -y libnuma-dev
```
## build dpdk
```shell
   cd dpdk-24.03
   meson build -Dmax_lcores=8
   ninja -C build
```
## the dpdk-app is built in the build directory
If you want to install it, and compile other dpdk-app, such as pktgen/vpp, then exec
```shell
   ninja -C build install
```
