#Copyright (c) 2020 Marvell.
#SPDX-License-Identifier: GPL-2.0

MODULE_MAME = mgmt_net
PCIE_HOST ?= $(OCTEONTX_HOST_ROOT)/drivers/legacy/modules/driver/src/host/linux/kernel/drv
KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
 
SRCS = host_ethdev.c 
 
INCLUDE_DIR = -I$(src) -I$(PCIE_HOST)
 
ccflags-y := $(INCLUDE_DIR)
KBUILD_EXTRA_SYMBOLS := $(PCIE_HOST)/Module.symvers
 
OBJS =  $(SRCS:.c=.o)
 
obj-m += $(MODULE_MAME).o
$(MODULE_MAME)-y = $(OBJS)
 
 
all:
	make -C $(KERNEL_DIR) M=`pwd` modules
 
clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
	@rm -f host_ethdev.o.ur-safe
