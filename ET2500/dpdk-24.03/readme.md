# How to build in ET2500
## install build depence package, such as libnuma-dev
```shell
   apt-get install -y libnuma-dev
```
## build dpdk
```shell
   cd dpdk
   meson build -Dmax_lcores=8
   ninja -C build
```
## the dpdk-app is built in the build directory
