#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: GPL-2.0

#! /bin/bash
export CNNIC_ROOT=`pwd`

mkdir -p $CNNIC_ROOT/modules/driver/bin
sh sym-link.sh $*;
