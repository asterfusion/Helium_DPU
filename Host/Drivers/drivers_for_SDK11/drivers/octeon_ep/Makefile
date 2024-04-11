# SPDX-License-Identifier: GPL-2.0
#
# Network driver for Marvell's Octeon PCI Endpoint NIC
#

CONFIG_MODULE_SIG=n

obj-$(CONFIG_OCTEON_EP) += octeon_ep.o

octeon_ep-y := octep_main.o octep_cn9k_pf.o octep_tx.o octep_rx.o \
	       octep_ethtool.o octep_ctrl_mbox.o octep_ctrl_net.o \
	       octep_pfvf_mbox.o octep_cnxk_pf.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
