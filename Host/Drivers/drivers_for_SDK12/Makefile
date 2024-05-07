# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2020 Marvell.

KVER?=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

export CONFIG_OCTEON_EP=m
export CONFIG_OCTEON_EP_VF=m

SUBDIRS=drivers/octeon_ep
SUBDIRS+=drivers/octeon_ep_vf
SUBDIRS+=drivers/phc
SUBDIRS+=drivers/octboot_net
SUBDIRS+=drivers/cnxk_ep_bb_pf

SUBDIRS+=apps/cnxk_ep_bb_pf

all: $(SUBDIRS)
		for d in $(SUBDIRS); do \
				if test -d $$d; then $(MAKE) -s -C $$d KVER=$(KVER) || exit 1; fi; \
		done
clean:
		for d in $(SUBDIRS); do \
				if test -d $$d; then  $(MAKE) -s -C $$d $@ KVER=$(KVER) || exit 1; fi; \
		done
