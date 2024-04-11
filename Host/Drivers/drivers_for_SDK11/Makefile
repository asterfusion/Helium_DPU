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
clean:
		for d in $(SUBDIRS); do \
				if test -d $$d; then $(OCTEONTX_BUILD_ENV) $(MAKE) -s -C $$d $@ || exit 1; fi; \
		done
