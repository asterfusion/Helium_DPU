# SPDX-License-Identifier: GPL-2.0
#
# Network driver for Marvell's Octeon PCI Endpoint NIC VF
#

obj-$(CONFIG_OCTEON_EP_VF) += octeon_ep_vf.o

octeon_ep_vf-y := octep_vf_main.o octep_vf_cn9k.o octep_vf_tx.o octep_vf_rx.o \
	       octep_vf_ethtool.o octep_vf_mbox.o octep_vf_cnxk.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
all:
	make -C $(KERNEL_DIR) M=`pwd` modules

clean:
	make -C $(KERNEL_DIR) M=`pwd` clean
