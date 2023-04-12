# SPDX-License-Identifier: BSD-3-Clause
# Copyright(C) 2019 Marvell International Ltd.
#

include $(RTE_SDK)/mk/rte.vars.mk

# Library name
LIB = librte_pmd_octeontx_ep.a

# Build flags
CFLAGS += -O3
CFLAGS += -DALLOW_EXPERIMENTAL_API
CFLAGS += $(WERROR_FLAGS)

CFLAGS += -I$(RTE_SDK)/drivers/common/octeontx/
CFLAGS += -I$(RTE_SDK)/drivers/common/octeontx2/
CFLAGS += -I$(RTE_SDK)/drivers/net/octeontx_ep/
CFLAGS += -DBUFPTR_ONLY_MODE

LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs -lrte_hash
LDLIBS += -lrte_bus_pci
LDLIBS += -lrte_common_octeontx -lrte_common_octeontx2

ifneq ($(CONFIG_RTE_ARCH_64),y)
CFLAGS += -Wno-int-to-pointer-cast
CFLAGS += -Wno-pointer-to-int-cast
ifeq ($(CONFIG_RTE_TOOLCHAIN_ICC),y)
CFLAGS += -diag-disable 2259
endif
endif

EXPORT_MAP := rte_pmd_octeontx_ep_version.map

#
# All source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_OCTEONTX_EP_PMD) += otx_ep_ethdev.c
SRCS-$(CONFIG_RTE_LIBRTE_OCTEONTX_EP_PMD) += otx_ep_rxtx.c
SRCS-$(CONFIG_RTE_LIBRTE_OCTEONTX_EP_PMD) += otx_ep_vf.c
SRCS-$(CONFIG_RTE_LIBRTE_OCTEONTX_EP_PMD) += otx2_ep_vf.c


include $(RTE_SDK)/mk/rte.lib.mk
