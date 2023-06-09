# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2016 Intel Corporation

APP = ipsec-secgw

#
# all source are stored in SRCS-y
#
SRCS-y += parser.c
SRCS-y += ipsec.c
SRCS-y += esp.c
SRCS-y += sp4.c
SRCS-y += sp6.c
SRCS-y += sa.c
SRCS-y += rt.c
SRCS-y += ipsec_process.c
SRCS-y += ipsec-secgw.c
SRCS-y += ipsec_worker.c
SRCS-y += event_helper.c

CFLAGS += -gdwarf-2

# Build using pkg-config variables if possible
ifeq ($(shell pkg-config --exists libdpdk && echo 0),0)

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PKGCONF ?= pkg-config

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk)
LDFLAGS_STATIC = -Wl,-Bstatic $(shell $(PKGCONF) --static --libs libdpdk)

CFLAGS += -DALLOW_EXPERIMENTAL_API

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

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(CONFIG_RTE_LIBRTE_IPSEC),y)
$(error "RTE_LIBRTE_IPSEC is required to build ipsec-secgw")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += -O3 -gdwarf-2
CFLAGS += $(WERROR_FLAGS)
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS_sa.o += -diag-disable=vec
endif

ifeq ($(DEBUG),1)
CFLAGS += -DIPSEC_DEBUG -fstack-protector-all -O0
endif

include $(RTE_SDK)/mk/rte.extapp.mk

endif
