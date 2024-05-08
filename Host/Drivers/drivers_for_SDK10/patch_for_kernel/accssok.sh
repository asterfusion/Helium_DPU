#!/bin/bash

######################################################
#  patch for centos8.5.2111 + 4.18.0-348.el8.x86_64  #
######################################################
#detect access_ok() with 2 or 3 params .
#for kernel version < 5.0  #define access_ok(type, addr, size) 
#for kernek version >=5.0  #define access_ok(addr, size) 
#centos8.5.2111 with kernel 4.18.0: access_ok is of version 5.0
OS_plat=`grep '^ID=' /etc/os-release | cut -f2- -d= | sed -e 's/\"//g'`
if [ "$OS_plat" != "centos" ];then 
    exit 0
fi
CENTOS_V=`cat /etc/redhat-release`
KERNEL_V=`uname -r`
if [[ "$CENTOS_V" =~ "8.5.2111" ]];then
  if [ "$KERNEL_V" != "4.18.0-348.el8.x86_64" ];then
    exit 0
  fi
else
  exit 0
fi


UACCESS=/lib/modules/$(uname -r)/source/include/asm-generic/uaccess.h 

if [ ! -e $UACCESS ]; then
    exit 0
fi

ACCESS_OK_P=`sed -n '/access_ok \?( \?[a-zA-Z]\+ \?, \?[a-zA-Z]\+ \?)/p' $UACCESS`

if [ "$ACCESS_OK_P"x == ""x ];then
  #may be have 3 or more params. so kernel version < 5.0
  ACCESS_PARAM_NUM=3
else
  #kernel version >= 5.0
  ACCESS_PARAM_NUM=2
  echo "P_ACCESS_OK_PARAM_2" >> ${PATCHDIRS}/${PATCH_FILE}
fi


