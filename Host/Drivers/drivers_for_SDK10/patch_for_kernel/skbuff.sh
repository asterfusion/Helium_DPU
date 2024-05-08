#!/bin/bash

######################################################
#  patch for centos8.5.2111 + 4.18.0-348.el8.x86_64  #
######################################################
#detect struct skbuff  .
#for kernel version < 5.0  skbuff->xmit_more  
#for kernek version >=5.0  skbuff->xmit_more or skbuff->rh_reserved_xmit_more
#centos8.5.2111 with kernel 4.18.0: skbuff is of version 5.0
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


SKBUFF=/lib/modules/$(uname -r)/source/include/linux/skbuff.h 
if [ ! -e $SKBUFF ]; then
    exit 0
fi

MAY_RENAME=`grep -rns rh_reserved_xmit_more $SKBUFF`

if [ "$MAY_RENAME"x == ""x ];then
  #kernel version < 5.0
  RENAME_XMIT_MORE=0
else
  #kernel version >= 5.0
  #may rename ---determined by marco __GENKSYMS__
  RENAME_XMIT_MORE=1
  echo "P_SKBUFF_XMIT_MORE_2" >> ${PATCHDIRS}/${PATCH_FILE}
fi





