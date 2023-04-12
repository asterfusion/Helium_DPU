# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.

# binary name
APP = otx2_ep_perf

# all source are stored in SRCS-y
SRCS-y += otx2_ep_perf.c
SRCS-y += otx2_ep_host.c

# Build using pkg-config variables if possible
ifeq ($(shell pkg-config --exists libdpdk && --exists librte_pmd_octeontx2_sdpep && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF=pkg-config --define-prefix

PC_FILE := $(shell $(PKGCONF) --path libdpdk librte_pmd_octeontx2_sdpep)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk librte_pmd_octeontx2_sdpep)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk librte_pmd_octeontx2_sdpep)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk librte_pmd_octeontx2_sdpep)

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true

else

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, detect a build directory, by looking for a path with a .config
RTE_TARGET ?= $(notdir $(abspath $(dir $(firstword $(wildcard $(RTE_SDK)/*/.config)))))

include $(RTE_SDK)/mk/rte.vars.mk

CFLAGS += -I$(RTE_SDK)/drivers/common/octeontx2 -I$(RTE_SDK)/drivers/raw/octeontx2_ep
CFLAGS += -I$(RTE_SDK)/drivers/raw/octeontx2_ep/base -I$(RTE_SDK)/drivers/mempool/octeontx2
CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk

endif
