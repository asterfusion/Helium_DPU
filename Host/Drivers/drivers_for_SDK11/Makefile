# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 Marvell.

OCTEONTX_HOST_ROOT = $(shell pwd)
export OCTEONTX_HOST_ROOT
export CONFIG_OCTEON_EP=m
export CONFIG_OCTEON_EP_VF=m

ifneq (,$(findstring PORT_EXTENDER_ENABLED=1, $(OCTEONTX_BUILD_ENV)))
SUBDIRS=drivers/legacy/modules/driver/src
SUBDIRS+=drivers/mgmt_net
else
SUBDIRS=drivers/octeon_ep
SUBDIRS+=drivers/octeon_ep_vf
SUBDIRS+=drivers/cnxk_ep_bb_pf
SUBDIRS+=apps/cnxk_ep_bb_pf
endif

SUBDIRS+=drivers/phc
SUBDIRS+=drivers/octboot_net

all: $(SUBDIRS)
		for d in $(SUBDIRS); do \
				if test -d $$d; then $(OCTEONTX_BUILD_ENV) $(MAKE) -s -C $$d || exit 1; fi; \
		done

install :
	 /usr/bin/install -c -m 644 mod-service/helium_insmod.sh mod-service/helium_rmmod.sh '/usr/bin'
	 /usr/bin/install -c -m 644 mod-service/helium-mod.service '/etc/systemd/system'
	 systemctl daemon-reload
	 echo -e "octeon_ep_path=$(OCTEONTX_HOST_ROOT)/drivers/octeon_ep/octeon_ep.ko\nocteon_ep_vf_path=$(OCTEONTX_HOST_ROOT)/drivers/octeon_ep_vf/octeon_ep_vf.ko\nvf_num=4">/etc/helium_mod.conf
clean:
		for d in $(SUBDIRS); do \
				if test -d $$d; then $(OCTEONTX_BUILD_ENV) $(MAKE) -s -C $$d $@ || exit 1; fi; \
		done
