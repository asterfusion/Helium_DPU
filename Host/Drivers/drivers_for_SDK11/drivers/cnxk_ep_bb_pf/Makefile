# SPDX-License-Identifier: GPL-2.0

obj-m +=  cnxk_ep_bb_pf.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
