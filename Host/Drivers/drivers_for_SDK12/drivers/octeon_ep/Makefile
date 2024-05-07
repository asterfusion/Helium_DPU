# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 Marvell.

KVER?=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

LINUX=/lib/modules/$(KVER)/build
ifeq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
  LINUXSRC=$(LINUX)
else
  LINUXSRC=/lib/modules/$(KVER)/source
endif

KDIR ?= $(srctree)
ifneq ($(KDIR),)
  LINUX=$(KDIR)
  LINUXSRC=$(LINUX)
endif

OCT_DRIVER := octeon_ep
OCT_INSTALL_DIR=/lib/modules/$(KVER)/updates/drivers/net/ethernet/marvell/$(OCT_DRIVER)

override EXTRA_CFLAGS += -Werror -Wno-error=unused-variable -Wno-error=unused-function -I$(shell pwd)/include

cflags-y += $(EXTRA_CFLAGS)

OCT_MODULE = $(OCT_DRIVER).ko

ifneq ($(KERNELRELEASE),)

obj-$(CONFIG_OCTEON_EP) += $(OCT_DRIVER).o
$(OCT_DRIVER)-y := octep_main.o octep_cn9k_pf.o octep_tx.o octep_rx.o \
		   octep_ethtool.o octep_ctrl_mbox.o octep_ctrl_net.o \
		   octep_pfvf_mbox.o octep_cnxk_pf.o

else

all:
	make -C $(LINUX) M=$(shell pwd) modules EXTRA_CFLAGS="$(EXTRA_CFLAGS)"

modules_install:
	$(MAKE) -C $(LINUXSRC) M=$(shell pwd) modules_install

endif

install: all
	@if [ "$(KDIR)" != "" ]; then \
	echo "Cannot use install with KDIR option"; exit 2;\
	fi
	mkdir -p $(PREFIX)$(OCT_INSTALL_DIR);
	install -m 444 $(OCT_MODULE) $(PREFIX)$(OCT_INSTALL_DIR);
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a ;\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONEY: all clean install

clean:
	-rm -f *.tar.gz *.ko *.o *.mod.c *.mod.o .*.*.cmd *.cmd *.markers *.order *.symvers
	-rm -rf .tmp_versions
