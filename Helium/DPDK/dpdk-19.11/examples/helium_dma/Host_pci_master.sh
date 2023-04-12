#!/bin/bash

bdf=`lspci | grep b200 |  awk '{print $1}'`
setpci -s $bdf 4.w
setpci -s $bdf 4.w=$(printf %x $((0x$(setpci -s $bdf 4.w)|4)))
