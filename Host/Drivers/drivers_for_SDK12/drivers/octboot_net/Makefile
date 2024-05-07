# SPDX-License-Identifier: GPL-2.0
#
# Facility driver for Marvell's Octeon PCI Endpoint NIC
#
#
#
obj-m += octboot_net.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
