#! /bin/bash
export CNNIC_ROOT=`pwd`

mkdir -p $CNNIC_ROOT/modules/driver/bin
sh sym-link.sh $*;
